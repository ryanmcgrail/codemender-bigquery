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

"""Unit tests for GitHub App installation token minting and refresh."""

import base64
import datetime
import json
import os
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

from google.auth import crypt as google_crypt
import requests

from codemender_agent import config as config_module
from codemender_agent.config import OrchestratorConfig
from codemender_agent.config import get_github_credentials
from codemender_agent.config import get_scrubbed_env
from codemender_agent.config import github_app_configured
from codemender_agent.config import refresh_github_token
from codemender_agent.runners import sequential
from codemender_agent.vcs import github_app
from codemender_agent.vcs.git import get_git_auth_header
from codemender_agent.vcs.github_app import GitHubAppAuthError
from codemender_agent.vcs.github_app import GitHubAppCredentials
from codemender_agent.vcs.github_app import InstallationTokenProvider

try:
  from cryptography.hazmat.primitives import serialization
  from cryptography.hazmat.primitives.asymmetric import rsa

  _HAVE_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover - exercised only without cryptography
  _HAVE_CRYPTOGRAPHY = False


def _generate_keys():
  """Returns (PKCS#1 private PEM, public PEM), like a GitHub App key."""
  key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
  private_pem = key.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.TraditionalOpenSSL,
      encryption_algorithm=serialization.NoEncryption(),
  ).decode("utf-8")
  public_pem = (
      key.public_key()
      .public_bytes(
          encoding=serialization.Encoding.PEM,
          format=serialization.PublicFormat.SubjectPublicKeyInfo,
      )
      .decode("utf-8")
  )
  return private_pem, public_pem


def _b64decode(segment: str) -> bytes:
  return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _iso(epoch: float) -> str:
  return datetime.datetime.fromtimestamp(
      epoch, tz=datetime.timezone.utc
  ).strftime("%Y-%m-%dT%H:%M:%SZ")


class _FakeResponse:

  def __init__(self, status_code, body=None):
    self.status_code = status_code
    self._body = body
    self.text = json.dumps(body) if body is not None else ""

  def json(self):
    if self._body is None:
      raise ValueError("no body")
    return self._body

  def raise_for_status(self):
    if self.status_code >= 400:
      raise requests.HTTPError(f"HTTP {self.status_code}")


class _FakeSession:
  """Records requests and replays queued responses."""

  def __init__(self, responses):
    self.responses = list(responses)
    self.calls = []

  def request(self, method, url, headers=None, json=None, timeout=None):
    self.calls.append(
        {"method": method, "url": url, "headers": headers, "json": json}
    )
    if not self.responses:
      raise AssertionError(f"Unexpected request {method} {url}")
    response = self.responses.pop(0)
    if callable(response):
      response = response()
    if isinstance(response, Exception):
      raise response
    return response


class _Clock:

  def __init__(self, now=1_900_000_000.0):
    self.now = now

  def __call__(self):
    return self.now


@unittest.skipUnless(
    _HAVE_CRYPTOGRAPHY, "cryptography is required to generate test keys"
)
class TestGitHubAppCredentials(unittest.TestCase):

  @classmethod
  def setUpClass(cls):
    cls.private_pem, cls.public_pem = _generate_keys()

  def test_valid_values_are_parsed(self):
    creds = GitHubAppCredentials.from_values(
        " 12345 ", self.private_pem, " 678 "
    )
    self.assertEqual(creds.app_id, "12345")
    self.assertEqual(creds.installation_id, 678)
    self.assertIn("BEGIN RSA PRIVATE KEY", creds.private_key)

  def test_installation_id_is_optional(self):
    creds = GitHubAppCredentials.from_values("12345", self.private_pem, None)
    self.assertIsNone(creds.installation_id)

  def test_repr_never_contains_the_private_key(self):
    creds = GitHubAppCredentials.from_values("12345", self.private_pem)
    self.assertNotIn("PRIVATE KEY", repr(creds))

  def test_escaped_newlines_are_restored(self):
    escaped = self.private_pem.strip().replace("\n", "\\n")
    creds = GitHubAppCredentials.from_values("12345", f'"{escaped}"')
    self.assertEqual(creds.private_key, self.private_pem)

  def test_missing_app_id_is_rejected(self):
    with self.assertRaisesRegex(GitHubAppAuthError, "GITHUB_APP_ID"):
      GitHubAppCredentials.from_values("", self.private_pem)

  def test_app_id_with_whitespace_is_rejected(self):
    with self.assertRaisesRegex(GitHubAppAuthError, "whitespace"):
      GitHubAppCredentials.from_values("12 345", self.private_pem)

  def test_missing_private_key_is_rejected(self):
    with self.assertRaisesRegex(GitHubAppAuthError, "GITHUB_APP_PRIVATE_KEY"):
      GitHubAppCredentials.from_values("12345", "  ")

  def test_non_pem_private_key_is_rejected(self):
    with self.assertRaisesRegex(GitHubAppAuthError, "PEM"):
      GitHubAppCredentials.from_values("12345", "ghp_notakey")

  def test_bad_installation_id_is_rejected(self):
    for bad in ("abc", "0", "-5", "1.5"):
      with self.subTest(bad=bad):
        with self.assertRaisesRegex(GitHubAppAuthError, "INSTALLATION_ID"):
          GitHubAppCredentials.from_values("12345", self.private_pem, bad)


@unittest.skipUnless(
    _HAVE_CRYPTOGRAPHY, "cryptography is required to generate test keys"
)
class TestBuildAppJwt(unittest.TestCase):

  @classmethod
  def setUpClass(cls):
    cls.private_pem, cls.public_pem = _generate_keys()

  def test_jwt_is_rs256_signed_with_bounded_lifetime(self):
    creds = GitHubAppCredentials.from_values("12345", self.private_pem)
    token = github_app.build_app_jwt(creds, now=1_900_000_000)

    header_b64, payload_b64, signature_b64 = token.split(".")
    header = json.loads(_b64decode(header_b64))
    payload = json.loads(_b64decode(payload_b64))
    self.assertEqual(header["alg"], "RS256")
    self.assertEqual(header["typ"], "JWT")
    self.assertEqual(payload["iss"], "12345")
    self.assertEqual(payload["iat"], 1_900_000_000 - 60)
    self.assertEqual(payload["exp"], 1_900_000_000 + 540)
    # GitHub rejects App JWTs that live longer than ten minutes.
    self.assertLessEqual(payload["exp"] - payload["iat"], 600)

    verifier = google_crypt.RSAVerifier.from_string(self.public_pem)
    self.assertTrue(
        verifier.verify(
            f"{header_b64}.{payload_b64}".encode("utf-8"),
            _b64decode(signature_b64),
        )
    )

  def test_unloadable_key_raises_without_echoing_key_material(self):
    bogus = (
        "-----BEGIN RSA PRIVATE KEY-----\nTk9UQUtFWVNFQ1JFVA==\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    creds = GitHubAppCredentials.from_values("12345", bogus)
    with self.assertRaises(GitHubAppAuthError) as ctx:
      github_app.build_app_jwt(creds)
    self.assertNotIn("Tk9UQUtFWVNFQ1JFVA", str(ctx.exception))
    self.assertIsNone(ctx.exception.__cause__)


@unittest.skipUnless(
    _HAVE_CRYPTOGRAPHY, "cryptography is required to generate test keys"
)
class TestInstallationTokenProvider(unittest.TestCase):

  @classmethod
  def setUpClass(cls):
    cls.private_pem, _ = _generate_keys()

  def setUp(self):
    self.clock = _Clock()
    sleep_patcher = unittest.mock.patch("codemender_agent.utils.time.sleep")
    self.mock_sleep = sleep_patcher.start()
    self.addCleanup(sleep_patcher.stop)

  def _token_response(self, token, lifetime=3600):
    return _FakeResponse(
        201, {"token": token, "expires_at": _iso(self.clock.now + lifetime)}
    )

  def _provider(self, responses, installation_id=None):
    creds = GitHubAppCredentials.from_values(
        "12345",
        self.private_pem,
        str(installation_id) if installation_id else None,
    )
    session = _FakeSession(responses)
    provider = InstallationTokenProvider(
        creds, "octo-org", "octo-repo", clock=self.clock, session=session
    )
    return provider, session

  def test_looks_up_installation_then_mints_repo_scoped_token(self):
    provider, session = self._provider(
        [
            _FakeResponse(200, {"id": 42}),
            self._token_response("ghs_first"),
        ]
    )

    self.assertEqual(provider.get_token(), "ghs_first")

    self.assertEqual(len(session.calls), 2)
    lookup, mint = session.calls
    self.assertEqual(lookup["method"], "GET")
    self.assertEqual(
        lookup["url"],
        "https://api.github.com/repos/octo-org/octo-repo/installation",
    )
    self.assertEqual(mint["method"], "POST")
    self.assertEqual(
        mint["url"],
        "https://api.github.com/app/installations/42/access_tokens",
    )
    self.assertEqual(mint["json"], {"repositories": ["octo-repo"]})
    # App endpoints are called with the App JWT, never a static token.
    self.assertTrue(mint["headers"]["Authorization"].startswith("Bearer ey"))
    self.assertEqual(provider.expires_at, self.clock.now + 3600)

  def test_explicit_installation_id_skips_lookup(self):
    provider, session = self._provider(
        [self._token_response("ghs_first")], installation_id=77
    )
    self.assertEqual(provider.get_token(), "ghs_first")
    self.assertEqual(len(session.calls), 1)
    self.assertIn(
        "/app/installations/77/access_tokens", session.calls[0]["url"]
    )

  def test_cached_token_is_reused_until_refresh_margin(self):
    provider, session = self._provider(
        [self._token_response("ghs_first"), self._token_response("ghs_second")],
        installation_id=77,
    )
    self.assertEqual(provider.get_token(), "ghs_first")

    # 49 minutes in: 11 minutes of lifetime left, above the 10-minute margin.
    self.clock.now += 49 * 60
    self.assertEqual(provider.get_token(), "ghs_first")
    self.assertEqual(len(session.calls), 1)

    # 51 minutes in: inside the margin, so a new token is minted.
    self.clock.now += 2 * 60
    self.assertEqual(provider.get_token(), "ghs_second")
    self.assertEqual(len(session.calls), 2)

  def test_token_is_refreshed_across_a_multi_hour_run(self):
    responses = [
        (lambda i=i: self._token_response(f"ghs_{i}")) for i in range(6)
    ]
    provider, session = self._provider(responses, installation_id=77)
    seen = []
    for _ in range(5 * 12):  # five hours in five-minute steps
      seen.append(provider.get_token())
      self.assertGreater(provider.expires_at - self.clock.now, 60)
      self.clock.now += 5 * 60
    # Every token is used for ~50 minutes, so six tokens cover five hours.
    self.assertEqual(len(set(seen)), 6)
    self.assertEqual(len(session.calls), 6)

  def test_installation_id_is_looked_up_only_once(self):
    provider, session = self._provider(
        [
            _FakeResponse(200, {"id": 42}),
            self._token_response("ghs_first"),
            self._token_response("ghs_second"),
        ]
    )
    provider.get_token()
    self.clock.now += 55 * 60
    self.assertEqual(provider.get_token(), "ghs_second")
    self.assertEqual(
        [c["method"] for c in session.calls], ["GET", "POST", "POST"]
    )

  def test_failed_refresh_reuses_a_still_valid_token(self):
    provider, session = self._provider(
        [
            self._token_response("ghs_first"),
            _FakeResponse(401, {"message": "Bad credentials"}),
        ],
        installation_id=77,
    )
    provider.get_token()
    self.clock.now += 55 * 60  # five minutes left
    with self.assertLogs("codemender-orchestrator", level="WARNING") as logs:
      self.assertEqual(provider.get_token(), "ghs_first")
    self.assertIn("reusing the cached token", "\n".join(logs.output))
    self.assertEqual(len(session.calls), 2)

  def test_failed_refresh_with_expired_token_raises(self):
    provider, _ = self._provider(
        [
            self._token_response("ghs_first"),
            _FakeResponse(401, {"message": "Bad credentials"}),
        ],
        installation_id=77,
    )
    provider.get_token()
    self.clock.now += 59.5 * 60  # 30 seconds left: too little to reuse
    with self.assertRaisesRegex(GitHubAppAuthError, "Bad credentials"):
      provider.get_token()

  def test_app_not_installed_fails_fast_with_guidance(self):
    provider, session = self._provider(
        [_FakeResponse(404, {"message": "Not Found"})]
    )
    with self.assertRaisesRegex(
        GitHubAppAuthError, "not appear to be installed on octo-org/octo-repo"
    ):
      provider.get_token()
    # A 4xx response is not retried.
    self.assertEqual(len(session.calls), 1)
    self.mock_sleep.assert_not_called()

  def test_server_errors_are_retried(self):
    provider, session = self._provider(
        [
            _FakeResponse(502, {"message": "Bad Gateway"}),
            requests.ConnectionError("reset"),
            self._token_response("ghs_first"),
        ],
        installation_id=77,
    )
    self.assertEqual(provider.get_token(), "ghs_first")
    self.assertEqual(len(session.calls), 3)
    self.assertEqual(self.mock_sleep.call_count, 2)

  def test_persistent_server_errors_raise_auth_error(self):
    # Retries back off until the retry budget is spent; the fake sleep
    # advances the clock so the budget runs out.
    self.mock_sleep.side_effect = lambda seconds: setattr(
        self.clock, "now", self.clock.now + seconds
    )
    started = self.clock.now
    provider, session = self._provider(
        [_FakeResponse(503, {"message": "Unavailable"})] * 50,
        installation_id=77,
    )
    with self.assertRaisesRegex(GitHubAppAuthError, "octo-org/octo-repo"):
      provider.get_token()
    self.assertGreater(len(session.calls), 3)
    self.assertAlmostEqual(
        self.clock.now - started, github_app.MINT_RETRY_BUDGET_SECONDS
    )

  def test_response_without_token_raises(self):
    provider, _ = self._provider(
        [_FakeResponse(201, {"expires_at": _iso(self.clock.now + 3600)})],
        installation_id=77,
    )
    with self.assertRaisesRegex(GitHubAppAuthError, "did not contain a token"):
      provider.get_token()

  def test_unparseable_expiry_uses_a_short_fallback_lifetime(self):
    provider, _ = self._provider(
        [_FakeResponse(201, {"token": "ghs_first", "expires_at": "soon"})],
        installation_id=77,
    )
    self.assertEqual(provider.get_token(), "ghs_first")
    self.assertEqual(provider.expires_at, self.clock.now + 30 * 60)


@unittest.skipUnless(
    _HAVE_CRYPTOGRAPHY, "cryptography is required to generate test keys"
)
class TestGetInstallationTokenCache(unittest.TestCase):

  @classmethod
  def setUpClass(cls):
    cls.private_pem, _ = _generate_keys()

  def setUp(self):
    github_app.reset_token_cache()
    self.addCleanup(github_app.reset_token_cache)

  def test_providers_are_cached_per_repository(self):
    creds = GitHubAppCredentials.from_values("12345", self.private_pem, "77")
    with unittest.mock.patch.object(
        InstallationTokenProvider, "get_token", autospec=True
    ) as mock_get_token:
      mock_get_token.side_effect = lambda provider: f"tok-{id(provider)}"
      first = github_app.get_installation_token(creds, "org", "repo-a")
      again = github_app.get_installation_token(creds, "org", "repo-a")
      other = github_app.get_installation_token(creds, "org", "repo-b")
    self.assertEqual(first, again)
    self.assertNotEqual(first, other)


@unittest.skipUnless(
    _HAVE_CRYPTOGRAPHY, "cryptography is required to generate test keys"
)
class TestConfigGitHubAppIntegration(unittest.TestCase):

  @classmethod
  def setUpClass(cls):
    cls.private_pem, _ = _generate_keys()

  def setUp(self):
    github_app.reset_token_cache()
    self.addCleanup(github_app.reset_token_cache)
    # Start every test from an environment without any GitHub credentials.
    cleared = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("GITHUB_", "GH_"))
    }
    env_patcher = unittest.mock.patch.dict(os.environ, cleared, clear=True)
    env_patcher.start()
    self.addCleanup(env_patcher.stop)
    mint_patcher = unittest.mock.patch.object(
        config_module, "get_installation_token", return_value="ghs_minted"
    )
    self.mock_mint = mint_patcher.start()
    self.addCleanup(mint_patcher.stop)

  def _set_app_env(self, installation_id="77"):
    os.environ["GITHUB_REPO_URL"] = "https://github.com/octo-org/octo-repo.git"
    os.environ["GITHUB_APP_ID"] = "12345"
    os.environ["GITHUB_APP_PRIVATE_KEY"] = self.private_pem
    if installation_id:
      os.environ["GITHUB_APP_INSTALLATION_ID"] = installation_id

  def test_from_env_reads_app_settings_and_hides_key_from_repr(self):
    self._set_app_env()
    cfg = OrchestratorConfig.from_env()
    self.assertEqual(cfg.github_app_id, "12345")
    self.assertEqual(cfg.github_app_installation_id, "77")
    self.assertIn("PRIVATE KEY", cfg.github_app_private_key)
    self.assertTrue(github_app_configured(cfg))
    self.assertNotIn("PRIVATE KEY", repr(cfg))

  def test_app_token_is_used_and_static_token_ignored(self):
    self._set_app_env()
    os.environ["GITHUB_APP_TOKEN"] = "ghp_personal"
    repo_url, token = get_github_credentials()
    self.assertEqual(repo_url, "https://github.com/octo-org/octo-repo.git")
    self.assertEqual(token, "ghs_minted")
    creds, owner, repo = self.mock_mint.call_args.args
    self.assertEqual((owner, repo), ("octo-org", "octo-repo"))
    self.assertEqual(creds.app_id, "12345")
    self.assertEqual(creds.installation_id, 77)

  def test_ssh_repo_url_resolves_owner_and_repo(self):
    self._set_app_env(installation_id=None)
    os.environ["GITHUB_REPO_URL"] = "git@github.com:octo-org/octo-repo.git"
    get_github_credentials()
    _, owner, repo = self.mock_mint.call_args.args
    self.assertEqual((owner, repo), ("octo-org", "octo-repo"))

  def test_partial_app_config_fails_instead_of_falling_back_to_pat(self):
    os.environ["GITHUB_REPO_URL"] = "https://github.com/octo-org/octo-repo.git"
    os.environ["GITHUB_APP_ID"] = "12345"
    os.environ["GITHUB_PAT"] = "ghp_personal"
    with self.assertRaisesRegex(GitHubAppAuthError, "GITHUB_APP_PRIVATE_KEY"):
      get_github_credentials()
    self.mock_mint.assert_not_called()

  def test_minting_failure_propagates_without_fallback(self):
    self._set_app_env()
    os.environ["GITHUB_TOKEN"] = "ghp_personal"
    self.mock_mint.side_effect = GitHubAppAuthError("revoked")
    with self.assertRaisesRegex(GitHubAppAuthError, "revoked"):
      get_github_credentials()

  def test_without_app_the_static_token_path_is_unchanged(self):
    os.environ["GITHUB_REPO_URL"] = "https://github.com/octo-org/octo-repo.git"
    os.environ["GITHUB_APP_TOKEN"] = " ghp_personal "
    cfg = OrchestratorConfig.from_env()
    self.assertFalse(github_app_configured(cfg))
    self.assertEqual(
        get_github_credentials(cfg),
        ("https://github.com/octo-org/octo-repo.git", "ghp_personal"),
    )
    self.assertEqual(refresh_github_token(cfg, "ghp_personal"), "ghp_personal")
    self.mock_mint.assert_not_called()

  def test_missing_credentials_error_mentions_app_option(self):
    os.environ["GITHUB_REPO_URL"] = "https://github.com/octo-org/octo-repo.git"
    with self.assertRaisesRegex(ValueError, "GITHUB_APP_ID"):
      get_github_credentials()

  def test_refresh_with_app_returns_the_current_minted_token(self):
    self._set_app_env()
    cfg = OrchestratorConfig.from_env()
    self.mock_mint.side_effect = ["ghs_one", "ghs_two"]
    self.assertEqual(refresh_github_token(cfg, "stale"), "ghs_one")
    self.assertEqual(refresh_github_token(cfg, "ghs_one"), "ghs_two")

  def test_refresh_without_app_does_not_need_a_repo_url(self):
    cfg = OrchestratorConfig(github_token="fake-token")
    self.assertEqual(refresh_github_token(cfg, "fake-token"), "fake-token")

  def test_scrubbed_env_drops_app_credentials(self):
    self._set_app_env()
    scrubbed = get_scrubbed_env()
    for name in (
        "GITHUB_APP_ID",
        "GITHUB_APP_PRIVATE_KEY",
        "GITHUB_APP_INSTALLATION_ID",
    ):
      self.assertNotIn(name, scrubbed)


class TestStaticTokenPathWithoutGoogleAuth(unittest.TestCase):
  """The static token path must not depend on google-auth being importable."""

  def test_static_token_works_when_google_auth_cannot_be_imported(self):
    script = (
        "import sys\n"
        "sys.modules['google.auth'] = None\n"
        "from codemender_agent.config import get_github_credentials\n"
        "print(get_github_credentials()[1])\n"
    )
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("GITHUB_", "GH_"))
    }
    env["GITHUB_REPO_URL"] = "https://github.com/octo-org/octo-repo.git"
    env["GITHUB_PAT"] = "ghp_personal"
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in (repo_root, env.get("PYTHONPATH")) if p
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=repo_root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertEqual(result.stdout.strip(), "ghp_personal")


class TestSequentialRunnerRefreshesGitHubAppToken(unittest.TestCase):
  """The sequential runner re-reads an App token per finding and before push."""

  def setUp(self):
    github_app.reset_token_cache()
    self.addCleanup(github_app.reset_token_cache)
    self.tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self.tmp.cleanup)
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("GITHUB_", "GH_", "CODEMENDER_"))
    }
    env.update(
        {
            "HOME": self.tmp.name,
            "WORKSPACE_DIR": self.tmp.name,
            "CODEMENDER_SKIP_VERIFY": "true",
            "GITHUB_REPO_URL": "https://github.com/o/r.git",
            "GITHUB_PAT": "ghp_personal",
            "GITHUB_APP_ID": "12345",
            "GITHUB_APP_PRIVATE_KEY": (
                "-----BEGIN RSA PRIVATE KEY-----\nunused\n"
                "-----END RSA PRIVATE KEY-----"
            ),
            "GITHUB_APP_INSTALLATION_ID": "77",
        }
    )
    env_patcher = unittest.mock.patch.dict(os.environ, env, clear=True)
    env_patcher.start()
    self.addCleanup(env_patcher.stop)

    minted = iter(f"ghs_token_{i}" for i in range(1, 10))
    mint_patcher = unittest.mock.patch.object(
        config_module,
        "get_installation_token",
        side_effect=lambda *_args: next(minted),
    )
    self.mock_mint = mint_patcher.start()
    self.addCleanup(mint_patcher.stop)

    self.mocks = {}
    for name in (
        "run_command",
        "get_scrubbed_env",
        "ensure_cm_updated",
        "log_cm_version",
        "get_cm_default_model",
        "inject_codemender_config",
        "setup_local_git_excludes",
        "check_remote_branch_exists",
        "is_duplicate_pr",
        "create_pull_request",
        "delete_remote_branch",
        "get_finding_status",
    ):
      patcher = unittest.mock.patch(
          f"codemender_agent.runners.sequential.{name}"
      )
      self.mocks[name] = patcher.start()
      self.addCleanup(patcher.stop)
    self.mocks["ensure_cm_updated"].return_value = "/bin/cm"
    self.mocks["get_cm_default_model"].return_value = None
    self.mocks["get_scrubbed_env"].return_value = {}
    self.mocks["get_finding_status"].return_value = "FIXED"
    self.mocks["check_remote_branch_exists"].return_value = False
    self.mocks["is_duplicate_pr"].return_value = False
    self.mocks["create_pull_request"].return_value = (
        "https://github.com/o/r/pull/1"
    )
    report = json.dumps(
        [
            {"FindingID": "fid-1", "VulnType": "XSS", "FilePath": "a.py"},
        ]
    )

    def run_cmd(cmd, *_args, **_kwargs):
      res = unittest.mock.MagicMock(returncode=0, stdout="", token_usage=None)
      joined = " ".join(cmd)
      if cmd[:3] == ["git", "branch", "--show-current"]:
        res.stdout = "main\n"
      elif "report" in joined and "json" in joined:
        res.stdout = report
      elif cmd[:2] == ["git", "status"]:
        res.stdout = " M a.py"
      return res

    self.mocks["run_command"].side_effect = run_cmd

  def _push_commands(self):
    return [
        c.args[0]
        for c in self.mocks["run_command"].call_args_list
        if "push" in c.args[0]
    ]

  def test_push_and_pull_request_use_the_token_read_after_the_fix(self):
    sequential.run_sequential_pipeline()

    # 1: start (clone), 2: before the finding, 3: right before the push.
    self.assertEqual(self.mock_mint.call_count, 3)
    self.assertEqual(
        self.mocks["check_remote_branch_exists"].call_args.args[1],
        "ghs_token_2",
    )
    pushes = self._push_commands()
    self.assertEqual(len(pushes), 1)
    self.assertIn(get_git_auth_header("ghs_token_3"), pushes[0])
    self.assertEqual(
        self.mocks["create_pull_request"].call_args.kwargs["token"],
        "ghs_token_3",
    )
    # The personal token is never used while an App is configured.
    for call in self.mocks["run_command"].call_args_list:
      self.assertNotIn(get_git_auth_header("ghp_personal"), call.args[0])

  def test_failed_refresh_before_push_skips_the_pull_request(self):
    self.mock_mint.side_effect = [
        "ghs_token_1",
        "ghs_token_2",
        GitHubAppAuthError("revoked"),
    ]
    sequential.run_sequential_pipeline()
    self.assertEqual(self._push_commands(), [])
    self.mocks["create_pull_request"].assert_not_called()


if __name__ == "__main__":
  unittest.main()
