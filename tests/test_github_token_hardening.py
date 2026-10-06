# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for GitHub App token handling across long Cloud Run scans.

Covers re-minting mid-scan, the refresh margin override, recovery from a
token GitHub rejects with 401, the bounded mint retry, the Stage 1 find
checkpoint that precedes every post-find GitHub call, and the Stage 2 guard
that keeps a GitHub failure from skipping the worker's state upload.
"""

import datetime
import json
import os
import tempfile
import unittest
import unittest.mock

import requests

from codemender_agent import config as config_module
from codemender_agent import utils
from codemender_agent.config import OrchestratorConfig
from codemender_agent.config import call_with_github_token
from codemender_agent.runners import scan
from codemender_agent.runners import worker
from codemender_agent.vcs import github
from codemender_agent.vcs import github_app
from codemender_agent.vcs.github import GitHubUnauthorizedError
from codemender_agent.vcs.github_app import GitHubAppAuthError
from codemender_agent.vcs.github_app import GitHubAppCredentials
from codemender_agent.vcs.github_app import InstallationTokenProvider

_FAKE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\nunused\n-----END RSA PRIVATE KEY-----\n"
)


def _iso(epoch: float) -> str:
  return datetime.datetime.fromtimestamp(
      epoch, tz=datetime.timezone.utc
  ).strftime("%Y-%m-%dT%H:%M:%SZ")


class _Clock:
  """A fake clock; `sleep` advances it instead of blocking."""

  def __init__(self, now=1_900_000_000.0):
    self.now = now
    self.slept = []

  def __call__(self):
    return self.now

  def sleep(self, seconds):
    self.slept.append(seconds)
    self.now += seconds


class _FakeResponse:

  def __init__(self, status_code, body=None, headers=None):
    self.status_code = status_code
    self._body = body
    self.headers = headers or {}
    self.text = json.dumps(body) if body is not None else ""

  def json(self):
    if self._body is None:
      raise ValueError("no body")
    return self._body

  def raise_for_status(self):
    if self.status_code >= 400:
      raise requests.HTTPError(f"HTTP {self.status_code}", response=self)


class _FakeSession:
  """Replays queued responses for the GitHub App endpoints."""

  def __init__(self, responses):
    self.responses = list(responses)
    self.calls = []

  def request(self, method, url, headers=None, json=None, timeout=None):
    del headers, timeout
    self.calls.append({"method": method, "url": url, "json": json})
    if not self.responses:
      raise AssertionError(f"Unexpected request {method} {url}")
    response = self.responses.pop(0)
    if callable(response):
      response = response()
    if isinstance(response, Exception):
      raise response
    return response


class _ProviderTestBase(unittest.TestCase):
  """Builds providers with a fake clock and session; JWT signing is stubbed."""

  def setUp(self):
    self.clock = _Clock()
    jwt_patcher = unittest.mock.patch.object(
        github_app, "build_app_jwt", return_value="eyJ.fake.jwt"
    )
    jwt_patcher.start()
    self.addCleanup(jwt_patcher.stop)
    jitter_patcher = unittest.mock.patch.object(
        github_app.random, "uniform", return_value=1.0
    )
    jitter_patcher.start()
    self.addCleanup(jitter_patcher.stop)
    env_patcher = unittest.mock.patch.dict(os.environ)
    env_patcher.start()
    self.addCleanup(env_patcher.stop)
    os.environ.pop(github_app.REFRESH_MARGIN_ENV_VAR, None)
    github_app.reset_token_cache()
    self.addCleanup(github_app.reset_token_cache)

  def _token(self, token, lifetime=3600):
    return lambda: _FakeResponse(
        201, {"token": token, "expires_at": _iso(self.clock.now + lifetime)}
    )

  def _provider(self, responses, **kwargs):
    creds = GitHubAppCredentials.from_values("12345", _FAKE_KEY, "77")
    session = _FakeSession(responses)
    provider = InstallationTokenProvider(
        creds,
        "octo-org",
        "octo-repo",
        clock=self.clock,
        session=session,
        sleep=self.clock.sleep,
        **kwargs,
    )
    return provider, session


class TestRefreshMargin(_ProviderTestBase):

  def test_default_margin_is_ten_minutes(self):
    self.assertEqual(github_app.resolve_refresh_margin(), 600)

  def test_override_is_clamped_to_the_allowed_range(self):
    cases = {
        "900": 900,
        "3300": 3300,
        "300": 300,
        "299": 300,
        "0": 300,
        "-50": 300,
        "3301": 3300,
        "86400": 3300,
        " 1200 ": 1200,
        "": 600,
        "soon": 600,
        "nan": 600,
        "inf": 600,
    }
    for raw, expected in cases.items():
      with self.subTest(raw=raw):
        self.assertEqual(github_app.resolve_refresh_margin(raw), expected)

  def test_provider_reads_the_override_from_the_environment(self):
    os.environ[github_app.REFRESH_MARGIN_ENV_VAR] = "3300"
    provider, session = self._provider(
        [self._token("ghs_1"), self._token("ghs_2"), self._token("ghs_3")]
    )
    self.assertEqual(provider.refresh_margin, 3300)
    self.assertEqual(provider.get_token(), "ghs_1")
    # Four minutes in: 56 minutes left, above the 55-minute margin.
    self.clock.now += 4 * 60
    self.assertEqual(provider.get_token(), "ghs_1")
    # Six minutes in: inside the margin, so the token is re-minted. This is
    # what a live proof run relies on.
    self.clock.now += 2 * 60
    self.assertEqual(provider.get_token(), "ghs_2")
    self.assertEqual(len(session.calls), 2)


class TestReMintMidScan(_ProviderTestBase):

  def test_token_read_after_a_long_scan_is_freshly_minted(self):
    provider, session = self._provider(
        [self._token("ghs_start"), self._token("ghs_after_scan")]
    )
    self.assertEqual(provider.get_token(), "ghs_start")
    self.clock.now += 6 * 3600  # a six-hour `cm find`
    self.assertEqual(provider.get_token(), "ghs_after_scan")
    self.assertEqual(provider.expires_at, self.clock.now + 3600)
    self.assertEqual(len(session.calls), 2)
    self.assertEqual(self.clock.slept, [])


class TestInvalidate(_ProviderTestBase):

  def test_invalidate_forces_a_new_mint(self):
    provider, session = self._provider(
        [self._token("ghs_1"), self._token("ghs_2")]
    )
    self.assertEqual(provider.get_token(), "ghs_1")
    self.assertTrue(provider.invalidate("ghs_1"))
    self.assertEqual(provider.get_token(), "ghs_2")
    self.assertEqual(len(session.calls), 2)

  def test_invalidating_a_superseded_token_does_not_re_mint(self):
    provider, session = self._provider(
        [self._token("ghs_1"), self._token("ghs_2")]
    )
    provider.get_token()
    provider.invalidate("ghs_1")
    self.assertEqual(provider.get_token(), "ghs_2")
    # A second caller reports the same stale token: nothing is dropped.
    self.assertFalse(provider.invalidate("ghs_1"))
    self.assertEqual(provider.get_token(), "ghs_2")
    self.assertEqual(len(session.calls), 2)

  def test_invalidate_without_a_cached_token_is_a_no_op(self):
    provider, _ = self._provider([])
    self.assertFalse(provider.invalidate("ghs_1"))


class TestMintRetry(_ProviderTestBase):

  def test_persistent_server_errors_stop_at_the_retry_budget(self):
    provider, session = self._provider(
        [lambda: _FakeResponse(503, {"message": "Unavailable"})] * 50
    )
    started = self.clock.now
    with self.assertRaisesRegex(
        GitHubAppAuthError, r"octo-org/octo-repo after \d+ attempt"
    ):
      provider.get_token()
    elapsed = self.clock.now - started
    self.assertEqual(elapsed, github_app.MINT_RETRY_BUDGET_SECONDS)
    # 5, 10, 20, 40, 80, 120, 120, then the rest of the budget.
    self.assertEqual(self.clock.slept, [5, 10, 20, 40, 80, 120, 120, 85])
    self.assertEqual(len(session.calls), len(self.clock.slept) + 1)

  def test_after_an_exhausted_budget_reads_fail_fast_for_a_while(self):
    provider, session = self._provider(
        [lambda: _FakeResponse(503, {"message": "Unavailable"})] * 12
        + [self._token("ghs_1")]
    )
    with self.assertRaises(GitHubAppAuthError):
      provider.get_token()
    calls_after_budget = len(session.calls)
    slept_after_budget = list(self.clock.slept)

    # Inside the cooldown: one attempt, no backoff.
    with self.assertRaises(GitHubAppAuthError):
      provider.get_token()
    self.assertEqual(len(session.calls), calls_after_budget + 1)
    self.assertEqual(self.clock.slept, slept_after_budget)

    # After the cooldown the full budget applies again, and GitHub recovers.
    self.clock.now += github_app.MINT_RETRY_COOLDOWN_SECONDS
    self.assertEqual(provider.get_token(), "ghs_1")
    self.assertGreater(len(self.clock.slept), len(slept_after_budget))

  def test_retry_budget_is_configurable_per_provider(self):
    provider, session = self._provider(
        [lambda: _FakeResponse(502, {"message": "Bad Gateway"})] * 10,
        retry_budget=12,
    )
    with self.assertRaises(GitHubAppAuthError):
      provider.get_token()
    self.assertEqual(self.clock.slept, [5, 7])
    self.assertEqual(len(session.calls), 3)

  def test_outage_shorter_than_the_budget_recovers(self):
    provider, session = self._provider(
        [lambda: _FakeResponse(502, {"message": "Bad Gateway"})] * 4
        + [requests.ConnectionError("reset"), self._token("ghs_1")]
    )
    self.assertEqual(provider.get_token(), "ghs_1")
    self.assertEqual(len(session.calls), 6)
    self.assertEqual(self.clock.slept, [5, 10, 20, 40, 80])

  def test_secondary_rate_limit_403_is_retried_after_retry_after(self):
    provider, session = self._provider([
        _FakeResponse(
            403,
            {"message": "You have exceeded a secondary rate limit."},
            headers={"Retry-After": "60"},
        ),
        self._token("ghs_1"),
    ])
    self.assertEqual(provider.get_token(), "ghs_1")
    self.assertEqual(self.clock.slept, [60])
    self.assertEqual(len(session.calls), 2)

  def test_rate_limit_message_without_headers_is_retried(self):
    provider, _ = self._provider([
        _FakeResponse(403, {"message": "API rate limit exceeded"}),
        _FakeResponse(429, {"message": "Too Many Requests"}),
        self._token("ghs_1"),
    ])
    self.assertEqual(provider.get_token(), "ghs_1")
    self.assertEqual(self.clock.slept, [5, 10])

  def test_permission_403_is_not_retried(self):
    provider, session = self._provider([
        _FakeResponse(403, {"message": "Resource not accessible by integration"})
    ])
    with self.assertRaisesRegex(GitHubAppAuthError, "not accessible"):
      provider.get_token()
    self.assertEqual(len(session.calls), 1)
    self.assertEqual(self.clock.slept, [])

  def test_rejected_app_key_is_not_retried(self):
    provider, session = self._provider(
        [_FakeResponse(401, {"message": "A JSON web token could not be decoded"})]
    )
    with self.assertRaisesRegex(GitHubAppAuthError, "HTTP 401"):
      provider.get_token()
    self.assertEqual(len(session.calls), 1)
    self.assertEqual(self.clock.slept, [])

  def test_transient_installation_lookup_failure_is_retried(self):
    creds = GitHubAppCredentials.from_values("12345", _FAKE_KEY)
    session = _FakeSession([
        _FakeResponse(502, {"message": "Bad Gateway"}),
        _FakeResponse(200, {"id": 42}),
        self._token("ghs_1"),
    ])
    provider = InstallationTokenProvider(
        creds,
        "octo-org",
        "octo-repo",
        clock=self.clock,
        session=session,
        sleep=self.clock.sleep,
    )
    self.assertEqual(provider.get_token(), "ghs_1")
    self.assertEqual(
        [c["method"] for c in session.calls], ["GET", "GET", "POST"]
    )

  def test_usable_cached_token_is_not_held_up_by_retries(self):
    provider, session = self._provider([
        self._token("ghs_1"),
        _FakeResponse(503, {"message": "Unavailable"}),
    ])
    provider.get_token()
    self.clock.now += 55 * 60  # five minutes left: still usable
    self.assertEqual(provider.get_token(), "ghs_1")
    self.assertEqual(self.clock.slept, [])
    self.assertEqual(len(session.calls), 2)


class TestRetryDecoratorRetriesUnauthorized(unittest.TestCase):
  """401 keeps its short retry: GitHub can reject a just-minted token."""

  def setUp(self):
    sleep_patcher = unittest.mock.patch.object(utils.time, "sleep")
    self.mock_sleep = sleep_patcher.start()
    self.addCleanup(sleep_patcher.stop)

  def test_401_is_retried_then_raised(self):
    func = unittest.mock.Mock(
        side_effect=_FakeResponse(401).raise_for_status, __name__="f"
    )
    with self.assertRaises(requests.HTTPError) as ctx:
      utils.retry_on_exception(max_tries=3)(func)()
    self.assertTrue(utils.is_unauthorized_http_error(ctx.exception))
    self.assertEqual(func.call_count, 3)

  def test_401_that_clears_succeeds(self):
    func = unittest.mock.Mock(
        side_effect=[
            requests.HTTPError("HTTP 401", response=_FakeResponse(401)),
            "ok",
        ],
        __name__="f",
    )
    self.assertEqual(utils.retry_on_exception(max_tries=3)(func)(), "ok")
    self.assertEqual(func.call_count, 2)

  def test_server_errors_are_still_retried(self):
    func = unittest.mock.Mock(
        side_effect=_FakeResponse(502).raise_for_status, __name__="f"
    )
    with self.assertRaises(requests.HTTPError):
      utils.retry_on_exception(max_tries=3)(func)()
    self.assertEqual(func.call_count, 3)


class TestHelpersFailClosedOnUnauthorized(unittest.TestCase):

  def setUp(self):
    sleep_patcher = unittest.mock.patch.object(utils.time, "sleep")
    sleep_patcher.start()
    self.addCleanup(sleep_patcher.stop)
    dry_patcher = unittest.mock.patch.object(
        github, "is_dry_run", return_value=False
    )
    dry_patcher.start()
    self.addCleanup(dry_patcher.stop)

  def test_default_branch_is_not_assumed_on_401_when_strict(self):
    with unittest.mock.patch.object(
        github.requests, "get", return_value=_FakeResponse(401)
    ) as mock_get:
      with self.assertRaises(GitHubUnauthorizedError):
        github.get_default_branch(
            "ghs_stale", "org", "repo", fail_on_unauthorized=True
        )
    # Only the decorator's short retries; no "main" guess afterwards.
    self.assertEqual(mock_get.call_count, 3)

  def test_default_branch_keeps_its_fallback_for_other_callers(self):
    with unittest.mock.patch.object(
        github.requests, "get", return_value=_FakeResponse(401)
    ):
      self.assertEqual(github.get_default_branch("tok", "org", "repo"), "main")

  def test_default_branch_still_falls_back_on_other_errors(self):
    with unittest.mock.patch.object(
        github.requests, "get", return_value=_FakeResponse(502)
    ):
      self.assertEqual(github.get_default_branch("tok", "org", "repo"), "main")

  def test_duplicate_pr_check_fails_closed_on_401(self):
    with unittest.mock.patch.object(
        github.requests, "get", return_value=_FakeResponse(401)
    ):
      with self.assertRaises(GitHubUnauthorizedError):
        github.is_duplicate_pr(
            "https://github.com/org/repo.git",
            "ghs_stale",
            "app.py",
            "XSS",
            10,
            head_branch="codemender/fix",
        )

  def test_duplicate_pr_check_keeps_its_fallback_for_other_errors(self):
    with unittest.mock.patch.object(
        github.requests, "get", return_value=_FakeResponse(502)
    ), unittest.mock.patch.object(
        github.requests.Session, "get", return_value=_FakeResponse(502)
    ):
      self.assertFalse(
          github.is_duplicate_pr(
              "https://github.com/org/repo.git", "tok", "app.py", "XSS", 10
          )
      )

  def test_branch_check_does_not_retry_a_rejected_token_over_git(self):
    with unittest.mock.patch.object(
        github.requests, "get", return_value=_FakeResponse(401)
    ), unittest.mock.patch.object(github, "run_command") as mock_git:
      with self.assertRaises(GitHubUnauthorizedError):
        github.check_remote_branch_exists(
            "https://github.com/org/repo.git", "ghs_stale", "codemender/fix"
        )
    mock_git.assert_not_called()


class TestCallWithGitHubToken(_ProviderTestBase):
  """401 recovery through the real provider cache."""

  def _app_config(self):
    return OrchestratorConfig(
        repo_url="https://github.com/octo-org/octo-repo.git",
        github_app_id="12345",
        github_app_private_key=_FAKE_KEY,
        github_app_installation_id="77",
    )

  def _seed_provider(self, responses):
    provider, session = self._provider(responses)
    github_app._providers[("12345", 77, "octo-org", "octo-repo")] = provider
    return provider, session

  def test_401_invalidates_re_mints_once_and_retries(self):
    _, session = self._seed_provider(
        [self._token("ghs_1"), self._token("ghs_2")]
    )
    cfg = self._app_config()
    token = config_module.refresh_github_token(cfg, "")
    self.assertEqual(token, "ghs_1")
    seen = []

    def call(tok):
      seen.append(tok)
      if tok == "ghs_1":
        raise GitHubUnauthorizedError("401 Bad credentials")
      return "result"

    result, new_token = call_with_github_token(cfg, token, call)
    self.assertEqual((result, new_token), ("result", "ghs_2"))
    self.assertEqual(seen, ["ghs_1", "ghs_2"])
    self.assertEqual(len(session.calls), 2)
    # The replacement token is cached for later reads.
    self.assertEqual(config_module.refresh_github_token(cfg, "ghs_1"), "ghs_2")

  def test_second_401_fails_closed(self):
    _, session = self._seed_provider(
        [self._token("ghs_1"), self._token("ghs_2")]
    )
    cfg = self._app_config()
    token = config_module.refresh_github_token(cfg, "")
    call = unittest.mock.Mock(side_effect=GitHubUnauthorizedError("401"))
    with self.assertRaises(GitHubUnauthorizedError):
      call_with_github_token(cfg, token, call)
    self.assertEqual(call.call_count, 2)
    self.assertEqual(len(session.calls), 2)

  def test_failed_re_mint_propagates(self):
    self._seed_provider([
        self._token("ghs_1"),
        _FakeResponse(401, {"message": "A JSON web token could not be decoded"}),
    ])
    cfg = self._app_config()
    token = config_module.refresh_github_token(cfg, "")
    call = unittest.mock.Mock(side_effect=GitHubUnauthorizedError("401"))
    with self.assertRaises(GitHubAppAuthError):
      call_with_github_token(cfg, token, call)
    self.assertEqual(call.call_count, 1)

  def test_static_token_is_not_retried(self):
    cfg = OrchestratorConfig(
        repo_url="https://github.com/octo-org/octo-repo.git",
        github_token="ghp_static",
    )
    call = unittest.mock.Mock(side_effect=GitHubUnauthorizedError("401"))
    with self.assertRaises(GitHubUnauthorizedError):
      call_with_github_token(cfg, "ghp_static", call)
    self.assertEqual(call.call_count, 1)

  def test_success_needs_no_new_token(self):
    cfg = OrchestratorConfig(github_token="ghp_static")
    self.assertEqual(
        call_with_github_token(cfg, "ghp_static", lambda tok: tok + "!"),
        ("ghp_static!", "ghp_static"),
    )

  def test_retry_waits_until_the_new_token_has_settled(self):
    self._seed_provider([self._token("ghs_1"), self._token("ghs_2")])
    cfg = self._app_config()
    token = config_module.refresh_github_token(cfg, "")
    retried_at = []

    def call(tok):
      if tok == "ghs_1":
        raise GitHubUnauthorizedError("401 Bad credentials")
      retried_at.append(self.clock.now)
      return "ok"

    minted_at = self.clock.now
    call_with_github_token(cfg, token, call)
    self.assertEqual(self.clock.slept, [github_app.NEW_TOKEN_SETTLE_SECONDS])
    self.assertEqual(
        retried_at, [minted_at + github_app.NEW_TOKEN_SETTLE_SECONDS]
    )


class TestNewTokenSettle(_ProviderTestBase):

  def test_waits_only_for_a_just_minted_cached_token(self):
    provider, _ = self._provider([self._token("ghs_1")])
    provider.get_token()
    self.clock.now += 2
    self.assertEqual(provider.wait_until_settled("ghs_1"), 3)
    self.assertEqual(provider.wait_until_settled("ghs_1"), 0)
    self.assertEqual(provider.wait_until_settled("ghs_other"), 0)
    self.assertEqual(provider.wait_until_settled(""), 0)
    self.assertEqual(self.clock.slept, [3])


class TestReplicationLag(_ProviderTestBase):
  """GitHub answers 401 for a few seconds after a token is minted."""

  _LAG_SECONDS = 4

  def setUp(self):
    super().setUp()
    self.minted = {}
    sleep_patcher = unittest.mock.patch.object(
        utils.time, "sleep", side_effect=self.clock.sleep
    )
    sleep_patcher.start()
    self.addCleanup(sleep_patcher.stop)
    dry_patcher = unittest.mock.patch.object(
        github, "is_dry_run", return_value=False
    )
    dry_patcher.start()
    self.addCleanup(dry_patcher.stop)
    self.cfg = OrchestratorConfig(
        repo_url="https://github.com/octo-org/octo-repo.git",
        github_app_id="12345",
        github_app_private_key=_FAKE_KEY,
        github_app_installation_id="77",
    )

  def _minting(self, count):
    responses = []
    for i in range(1, count + 1):

      def mint(token=f"ghs_{i}"):
        self.minted[token] = self.clock.now
        return self._token(token)()

      responses.append(mint)
    provider, session = self._provider(responses)
    github_app._providers[("12345", 77, "octo-org", "octo-repo")] = provider
    return session

  def _lagging(self, ok_response):
    def get(url, headers=None, timeout=None, **_kwargs):
      del url, timeout
      token = headers["Authorization"].split()[-1]
      if self.clock.now - self.minted[token] < self._LAG_SECONDS:
        return _FakeResponse(401, {"message": "Bad credentials"})
      return ok_response

    return get

  def test_duplicate_check_right_after_a_mint_is_not_failed_closed(self):
    self._minting(3)
    token = config_module.refresh_github_token(self.cfg, "")
    ok = _FakeResponse(200, [])
    ok.links = {}
    get = self._lagging(ok)
    with unittest.mock.patch.object(
        github.requests, "get", side_effect=get
    ), unittest.mock.patch.object(
        github.requests.Session,
        "get",
        autospec=True,
        side_effect=lambda _self, *a, **k: get(*a, **k),
    ):
      result, _ = call_with_github_token(
          self.cfg,
          token,
          lambda tok: github.is_duplicate_pr(
              "https://github.com/octo-org/octo-repo.git",
              tok,
              "app.py",
              "XSS",
              10,
              head_branch="codemender/fix",
          ),
      )
    self.assertFalse(result)

  def test_default_branch_right_after_a_mint_is_read(self):
    self._minting(3)
    token = config_module.refresh_github_token(self.cfg, "")
    with unittest.mock.patch.object(
        github.requests,
        "get",
        side_effect=self._lagging(
            _FakeResponse(200, {"default_branch": "trunk"})
        ),
    ):
      branch, _ = config_module.read_default_branch(
          self.cfg, token, "octo-org", "octo-repo"
      )
    self.assertEqual(branch, "trunk")


class TestStage1(_ProviderTestBase):
  """Stage 1 ordering and token use around a long `cm find`."""

  _FINDINGS = [
      {
          "FindingID": "fid-1",
          "Status": "DETECTED",
          "VulnType": "XSS",
          "FilePath": "app.py",
          "StartLine": 10,
      },
      {
          "FindingID": "fid-2",
          "Status": "DETECTED",
          "VulnType": "SQL_INJECTION",
          "FilePath": "db.py",
          "StartLine": 20,
      },
  ]

  def setUp(self):
    super().setUp()
    self.temp_dir = tempfile.TemporaryDirectory()
    self.addCleanup(self.temp_dir.cleanup)
    self.workspace_dir = self.temp_dir.name
    for key in list(os.environ):
      if key.startswith(("GITHUB_", "GH_", "CODEMENDER_", "WIZ_")):
        del os.environ[key]
    os.environ.update({
        "HOME": self.workspace_dir,
        "WORKSPACE_DIR": self.workspace_dir,
        "CODEMENDER_SCAN_ID": "scan-1",
        "CODEMENDER_GCS_BUCKET": "bucket",
        "CODEMENDER_STORAGE_MODE": "gcs",
        "GITHUB_REPO_URL": "https://github.com/octo-org/octo-repo.git",
        "GITHUB_APP_ID": "12345",
        "GITHUB_APP_PRIVATE_KEY": _FAKE_KEY,
        "GITHUB_APP_INSTALLATION_ID": "77",
    })
    db_dir = os.path.join(self.workspace_dir, ".codemender")
    os.makedirs(db_dir)
    with open(os.path.join(db_dir, "state.db"), "wb") as f:
      f.write(b"SQLite format 3\x00")
    self.events = []
    self.uploads = {}
    self.state_saved = False

  def _run(self, responses, extra_patches=()):
    """Runs Stage 1 with a seeded provider; returns the upload map."""
    provider, session = self._provider(responses)
    github_app._providers[("12345", 77, "octo-org", "octo-repo")] = provider

    def scan_repository(*_args, **_kwargs):
      self.events.append("find")
      self.clock.now += 6 * 3600  # the scan outlives the first token
      return [dict(f) for f in self._FINDINGS], {}

    def upload(local, bucket, blob):
      del bucket
      self.events.append(f"upload:{blob}")
      if local.endswith(".json"):
        with open(local, "r", encoding="utf-8") as f:
          self.uploads[blob] = json.load(f)
      else:
        self.uploads[blob] = None
      return True

    def branch_exists(url, token, branch, cwd=None):
      del url, branch, cwd
      self.events.append(f"branch_check:{token}")
      return False

    def duplicate_pr(url, token, *args, **kwargs):
      del url, args, kwargs
      self.events.append(f"pr_check:{token}")
      return False

    real_refresh = scan.refresh_github_token

    def refresh(cfg, token):
      self.events.append("refresh")
      return real_refresh(cfg, token)

    patches = [
        unittest.mock.patch.object(
            scan, "_sync_repository", return_value="abc123"
        ),
        unittest.mock.patch.object(
            scan, "ensure_cm_updated", return_value="/bin/cm"
        ),
        unittest.mock.patch.object(scan, "log_cm_version", return_value="1"),
        unittest.mock.patch.object(scan, "_init_codemender"),
        unittest.mock.patch.object(
            scan, "_scan_repository", side_effect=scan_repository
        ),
        unittest.mock.patch.object(
            scan, "upload_file_to_gcs", side_effect=upload
        ),
        unittest.mock.patch.object(
            scan, "check_remote_branch_exists", side_effect=branch_exists
        ),
        unittest.mock.patch.object(
            scan, "is_duplicate_pr", side_effect=duplicate_pr
        ),
        unittest.mock.patch.object(
            scan, "refresh_github_token", side_effect=refresh
        ),
        unittest.mock.patch.object(scan, "post_commit_status"),
        unittest.mock.patch.object(
            scan,
            "_save_and_upload_state",
            side_effect=lambda *a, **k: setattr(self, "state_saved", True),
        ),
        unittest.mock.patch("shutil.which", return_value="/bin/cm"),
    ] + list(extra_patches)
    for p in patches:
      p.start()
    try:
      scan.run_scan_pipeline()
    finally:
      for p in reversed(patches):
        p.stop()
    return session

  def test_checkpoint_is_uploaded_before_any_post_find_github_call(self):
    self._run([self._token("ghs_start"), self._token("ghs_after_scan")])

    find_at = self.events.index("find")
    after_find = self.events[find_at + 1:]
    checkpoint_at = after_find.index("upload:scans/scan-1/checkpoint/findings.json")
    self.assertIn("upload:scans/scan-1/checkpoint/state.db", after_find)
    github_calls = [
        i
        for i, e in enumerate(after_find)
        if e == "refresh" or e.startswith(("branch_check:", "pr_check:"))
    ]
    self.assertTrue(github_calls)
    self.assertLess(checkpoint_at, min(github_calls))
    self.assertLess(
        after_find.index("upload:scans/scan-1/checkpoint/state.db"),
        min(github_calls),
    )
    saved = self.uploads["scans/scan-1/checkpoint/findings.json"]
    self.assertEqual(saved["findings_count"], 2)
    self.assertEqual(
        [f["FindingID"] for f in saved["findings"]], ["fid-1", "fid-2"]
    )
    self.assertEqual(saved["target_sha"], "abc123")

  def test_dedupe_after_a_six_hour_scan_uses_a_freshly_minted_token(self):
    session = self._run(
        [self._token("ghs_start"), self._token("ghs_after_scan")]
    )
    checks = [e for e in self.events if e.startswith(("branch_check:", "pr_check:"))]
    self.assertEqual(len(checks), 4)
    self.assertTrue(all(e.endswith(":ghs_after_scan") for e in checks))
    self.assertEqual(len(session.calls), 2)

  def test_mint_failure_after_the_scan_keeps_the_checkpoint(self):
    with self.assertLogs("codemender-orchestrator", level="CRITICAL") as logs:
      with self.assertRaises(GitHubAppAuthError):
        self._run(
            [self._token("ghs_start")]
            + [lambda: _FakeResponse(503, {"message": "Unavailable"})] * 50
        )
    self.assertIn("scans/scan-1/checkpoint/findings.json", self.uploads)
    self.assertIn("gs://bucket/scans/scan-1/checkpoint/", "\n".join(logs.output))
    self.assertFalse(
        [e for e in self.events if e.startswith(("branch_check:", "pr_check:"))]
    )
    # The retry used its whole budget before giving up.
    self.assertEqual(sum(self.clock.slept), github_app.MINT_RETRY_BUDGET_SECONDS)

  def test_401_during_dedupe_is_recovered_with_one_re_mint(self):
    rejected = []

    def duplicate_pr(url, token, *args, **kwargs):
      del url, args, kwargs
      self.events.append(f"pr_check:{token}")
      if token == "ghs_after_scan":
        rejected.append(token)
        raise GitHubUnauthorizedError("401 Bad credentials")
      return False

    session = self._run(
        [
            self._token("ghs_start"),
            self._token("ghs_after_scan"),
            self._token("ghs_replacement"),
        ],
        extra_patches=[
            unittest.mock.patch.object(
                scan, "is_duplicate_pr", side_effect=duplicate_pr
            )
        ],
    )
    self.assertEqual(rejected, ["ghs_after_scan"])
    pr_checks = [e for e in self.events if e.startswith("pr_check:")]
    self.assertEqual(
        pr_checks,
        [
            "pr_check:ghs_after_scan",
            "pr_check:ghs_replacement",
            "pr_check:ghs_replacement",
        ],
    )
    self.assertEqual(len(session.calls), 3)

  def test_repeated_401_during_dedupe_fails_the_stage(self):
    def duplicate_pr(*_args, **_kwargs):
      raise GitHubUnauthorizedError("401 Bad credentials")

    with self.assertRaises(GitHubUnauthorizedError):
      self._run(
          [
              self._token("ghs_start"),
              self._token("ghs_after_scan"),
              self._token("ghs_replacement"),
          ],
          extra_patches=[
              unittest.mock.patch.object(
                  scan, "is_duplicate_pr", side_effect=duplicate_pr
              ),
              unittest.mock.patch.object(scan, "_record_failure_marker"),
          ],
      )
    # The findings were saved before the failing GitHub phase.
    self.assertIn("scans/scan-1/checkpoint/findings.json", self.uploads)
    self.assertFalse(self.state_saved)


class TestWorkerGuards(unittest.TestCase):
  """A GitHub failure in Stage 2 must not skip the partition state upload."""

  def setUp(self):
    self.temp_dir = tempfile.TemporaryDirectory()
    self.addCleanup(self.temp_dir.cleanup)
    self.workspace_dir = self.temp_dir.name
    env_patcher = unittest.mock.patch.dict(
        os.environ,
        {
            "HOME": self.workspace_dir,
            "CODEMENDER_WORKER_INDEX": "0",
            "CODEMENDER_BASE_WORKSPACE_URL": "http://signed-url/base.tar.gz",
            "CODEMENDER_PARTITION_URLS": json.dumps(
                ["http://signed-url/partition_0.json"]
            ),
            "CODEMENDER_UPLOAD_URLS": json.dumps(["http://signed-url/upload_0.db"]),
            "CODEMENDER_METADATA_URLS": json.dumps(
                ["http://signed-url/metadata_0.json"]
            ),
            "WORKSPACE_DIR": self.workspace_dir,
            "GITHUB_REPO_URL": "https://github.com/owner/repo.git",
            "GITHUB_TOKEN": "fake-token",
            "CODEMENDER_TARGET_SHA": "abc123commitsha",
        },
    )
    env_patcher.start()
    self.addCleanup(env_patcher.stop)
    for key in ("GITHUB_APP_ID", "GITHUB_APP_PRIVATE_KEY", "CODEMENDER_DRY_RUN"):
      os.environ.pop(key, None)

    findings = [
        {
            "FindingID": fid,
            "Status": "DETECTED",
            "VulnType": "SQL_INJECTION",
            "FilePath": f"{fid}.py",
            "StartLine": 10,
        }
        for fid in ("fid-1", "fid-2")
    ]
    report = unittest.mock.MagicMock(returncode=0, stdout=json.dumps(findings))
    git_status = unittest.mock.MagicMock(returncode=0, stdout=" M db.py")
    default = unittest.mock.MagicMock(returncode=0, stdout="")

    def run_cmd(cmd, *_args, **_kwargs):
      cmd_str = " ".join(cmd)
      if "report" in cmd_str:
        return report
      if "status" in cmd_str:
        return git_status
      return default

    def download(url, dest_path):
      if "partition" in url:
        with open(dest_path, "w", encoding="utf-8") as f:
          json.dump({"partition_index": 0, "finding_ids": ["fid-1", "fid-2"]}, f)
        return True
      return "base.tar.gz" in url

    self.mocks = {}
    for name, kwargs in {
        "run_command": {"side_effect": run_cmd},
        "download_from_url": {"side_effect": download},
        "upload_to_url": {"return_value": True},
        "check_remote_branch_exists": {"return_value": False},
        "is_duplicate_pr": {"return_value": False},
        "push_branch_to_remote": {},
        "create_pull_request": {
            "return_value": "https://github.com/owner/repo/pull/7"
        },
        "is_finding_verified": {"return_value": True},
        "get_finding_status": {"return_value": "FIXED"},
        "get_default_branch": {"return_value": "main"},
        "_mark_pr_creation_failed": {},
        "_mark_fix_failed": {},
    }.items():
      patcher = unittest.mock.patch.object(worker, name, **kwargs)
      self.mocks[name] = patcher.start()
      self.addCleanup(patcher.stop)
    for target, kwargs in {
        "tarfile.open": {},
        "shutil.which": {"return_value": "/bin/cm"},
    }.items():
      patcher = unittest.mock.patch(target, **kwargs)
      patcher.start()
      self.addCleanup(patcher.stop)

  def _state_uploaded(self):
    return any(
        call.args[0].endswith("state.db")
        for call in self.mocks["upload_to_url"].call_args_list
    )

  def test_rejected_token_in_duplicate_check_fails_closed_and_uploads(self):
    def duplicate_pr(url, token, file_path, *args, **kwargs):
      del url, token, args, kwargs
      if file_path == "fid-1.py":
        raise GitHubUnauthorizedError("401 Bad credentials")
      return False

    self.mocks["is_duplicate_pr"].side_effect = duplicate_pr
    worker.run_worker_pipeline()

    self.mocks["_mark_pr_creation_failed"].assert_called_once()
    self.assertEqual(
        self.mocks["_mark_pr_creation_failed"].call_args.args[1], "fid-1"
    )
    # fid-1 is not remediated; fid-2 still is.
    self.assertEqual(self.mocks["create_pull_request"].call_count, 1)
    self.assertTrue(self._state_uploaded())

  def test_unexpected_duplicate_check_error_fails_closed_and_uploads(self):
    self.mocks["check_remote_branch_exists"].side_effect = (
        RuntimeError("git ls-remote failed")
    )
    worker.run_worker_pipeline()

    self.assertEqual(self.mocks["_mark_pr_creation_failed"].call_count, 2)
    self.mocks["create_pull_request"].assert_not_called()
    self.assertTrue(self._state_uploaded())

  def test_unexpected_error_in_one_finding_does_not_skip_the_upload(self):
    with unittest.mock.patch.object(
        worker,
        "_process_finding",
        side_effect=[RuntimeError("boom"), "https://github.com/o/r/pull/1"],
    ) as mock_process:
      worker.run_worker_pipeline()

    self.assertEqual(mock_process.call_count, 2)
    self.mocks["_mark_fix_failed"].assert_called_once()
    self.assertEqual(self.mocks["_mark_fix_failed"].call_args.args[1], "fid-1")
    self.assertTrue(self._state_uploaded())

  def test_token_refresh_outage_does_not_skip_the_upload(self):
    with unittest.mock.patch.object(
        worker,
        "refresh_github_token",
        side_effect=GitHubAppAuthError("Could not mint: HTTP 503"),
    ):
      worker.run_worker_pipeline()

    # Routing needs a fresh token, so nothing reaches GitHub, but the
    # partition state is still uploaded.
    self.mocks["push_branch_to_remote"].assert_not_called()
    self.mocks["create_pull_request"].assert_not_called()
    self.assertTrue(self._state_uploaded())


if __name__ == "__main__":
  unittest.main()
