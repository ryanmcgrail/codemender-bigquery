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

"""Unit tests for the fix commit author identity."""

import json
import os
import pathlib
import re
import subprocess
import tempfile
import unittest
import unittest.mock

import requests

from codemender_agent.runners import scan
from codemender_agent.runners import worker
from codemender_agent.vcs import git as git_module
from codemender_agent.vcs import github_app
from codemender_agent.vcs.git import DEFAULT_GIT_AUTHOR_EMAIL
from codemender_agent.vcs.git import DEFAULT_GIT_AUTHOR_NAME
from codemender_agent.vcs.git import configure_git_identity
from codemender_agent.vcs.git import resolve_git_identity
from codemender_agent.vcs.github_app import GitHubAppCredentials

try:
  from cryptography.hazmat.primitives import serialization
  from cryptography.hazmat.primitives.asymmetric import rsa

  _HAVE_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover - exercised only without cryptography
  _HAVE_CRYPTOGRAPHY = False

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_BOT = ("cm-fixer[bot]", "4242+cm-fixer[bot]@users.noreply.github.com")


def _private_key_pem() -> str:
  key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
  return key.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.TraditionalOpenSSL,
      encryption_algorithm=serialization.NoEncryption(),
  ).decode("utf-8")


class _FakeResponse:

  def __init__(self, status_code, body=None):
    self.status_code = status_code
    self._body = body
    self.text = json.dumps(body) if body is not None else ""
    self.headers = {}

  def json(self):
    if self._body is None:
      raise ValueError("no body")
    return self._body


class _FakeSession:
  """Records requests and replays queued responses."""

  def __init__(self, responses):
    self.responses = list(responses)
    self.calls = []

  def request(self, method, url, headers=None, json=None, timeout=None):  # pylint: disable=redefined-outer-name
    del json, timeout
    self.calls.append({"method": method, "url": url, "headers": headers})
    if not self.responses:
      raise AssertionError(f"Unexpected request {method} {url}")
    response = self.responses.pop(0)
    if isinstance(response, Exception):
      raise response
    return response


def _clean_env(**extra):
  env = {
      k: v
      for k, v in os.environ.items()
      if not k.startswith(("GITHUB_", "GH_", "CODEMENDER_"))
  }
  env.update(extra)
  return unittest.mock.patch.dict(os.environ, env, clear=True)


class TestResolveGitIdentity(unittest.TestCase):

  def setUp(self):
    github_app.reset_token_cache()
    self.addCleanup(github_app.reset_token_cache)

  def test_default_is_neutral_and_not_a_google_address(self):
    with _clean_env():
      name, email = resolve_git_identity("ghp_x")
    self.assertEqual((name, email), (DEFAULT_GIT_AUTHOR_NAME, DEFAULT_GIT_AUTHOR_EMAIL))
    self.assertEqual(email, "codemender-agent@noreply.invalid")
    self.assertNotIn("google", email.lower())

  def test_env_override_wins_and_skips_the_app_lookup(self):
    with _clean_env(
        CODEMENDER_GIT_AUTHOR_NAME="  Security Bot ",
        CODEMENDER_GIT_AUTHOR_EMAIL="secbot@example.com",
        GITHUB_APP_ID="1",
        GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----",
    ), unittest.mock.patch.object(github_app, "get_app_bot_identity") as lookup:
      self.assertEqual(
          resolve_git_identity("ghs_t"), ("Security Bot", "secbot@example.com")
      )
    lookup.assert_not_called()

  def test_app_bot_identity_is_the_default_with_an_app(self):
    with _clean_env(
        GITHUB_APP_ID="12345",
        GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----",
        GITHUB_APP_INSTALLATION_ID="77",
    ), unittest.mock.patch.object(
        github_app, "get_app_bot_identity", return_value=_BOT
    ) as lookup:
      self.assertEqual(resolve_git_identity("ghs_t"), _BOT)
    credentials, token = lookup.call_args.args
    self.assertEqual(credentials.app_id, "12345")
    self.assertEqual(credentials.installation_id, 77)
    self.assertEqual(token, "ghs_t")

  def test_configured_email_is_never_paired_with_the_bot_name(self):
    # GitHub attributes commits by email, so an email override decides the
    # identity alone: no App lookup, and the neutral name unless one is set.
    key = "-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----"
    with _clean_env(
        GITHUB_APP_ID="12345",
        GITHUB_APP_PRIVATE_KEY=key,
        CODEMENDER_GIT_AUTHOR_EMAIL="allowed@example.com",
    ), unittest.mock.patch.object(
        github_app, "get_app_bot_identity", return_value=_BOT
    ) as lookup:
      self.assertEqual(
          resolve_git_identity("ghs_t"),
          (DEFAULT_GIT_AUTHOR_NAME, "allowed@example.com"),
      )
    lookup.assert_not_called()

  def test_name_override_keeps_the_bot_email(self):
    key = "-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----"
    with _clean_env(
        GITHUB_APP_ID="12345",
        GITHUB_APP_PRIVATE_KEY=key,
        CODEMENDER_GIT_AUTHOR_NAME="Security Bot",
    ), unittest.mock.patch.object(
        github_app, "get_app_bot_identity", return_value=_BOT
    ):
      self.assertEqual(resolve_git_identity("ghs_t"), ("Security Bot", _BOT[1]))
    with _clean_env(CODEMENDER_GIT_AUTHOR_NAME="Only Name"):
      self.assertEqual(
          resolve_git_identity(), ("Only Name", DEFAULT_GIT_AUTHOR_EMAIL)
      )

  def test_invalid_email_override_falls_through_to_the_bot(self):
    key = "-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----"
    with _clean_env(
        GITHUB_APP_ID="12345",
        GITHUB_APP_PRIVATE_KEY=key,
        CODEMENDER_GIT_AUTHOR_EMAIL="not valid@example.com",
    ), unittest.mock.patch.object(
        github_app, "get_app_bot_identity", return_value=_BOT
    ), self.assertLogs("codemender-orchestrator", level="WARNING"):
      self.assertEqual(resolve_git_identity("ghs_t"), _BOT)

  def test_app_lookup_failure_falls_back_to_the_default(self):
    with _clean_env(
        GITHUB_APP_ID="12345",
        GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----",
    ), unittest.mock.patch.object(
        github_app, "get_app_bot_identity", return_value=None
    ):
      self.assertEqual(
          resolve_git_identity("ghs_t"),
          (DEFAULT_GIT_AUTHOR_NAME, DEFAULT_GIT_AUTHOR_EMAIL),
      )

  def test_unexpected_app_error_falls_back_to_the_default(self):
    with _clean_env(
        GITHUB_APP_ID="12345",
        GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----",
    ), unittest.mock.patch.object(
        github_app, "get_app_bot_identity", side_effect=RuntimeError("boom")
    ), self.assertLogs("codemender-orchestrator", level="WARNING"):
      self.assertEqual(
          resolve_git_identity("ghs_t"),
          (DEFAULT_GIT_AUTHOR_NAME, DEFAULT_GIT_AUTHOR_EMAIL),
      )

  def test_malformed_app_settings_fall_back_without_raising(self):
    # A broken key cannot be signed with; the scan itself reports that, so
    # the identity lookup must not raise on top of it.
    with _clean_env(
        GITHUB_APP_ID="12345",
        GITHUB_APP_PRIVATE_KEY="not a pem",
    ):
      self.assertEqual(
          resolve_git_identity("ghs_t"),
          (DEFAULT_GIT_AUTHOR_NAME, DEFAULT_GIT_AUTHOR_EMAIL),
      )

  def test_partial_app_settings_do_not_trigger_a_lookup(self):
    with _clean_env(GITHUB_APP_ID="12345"), unittest.mock.patch.object(
        github_app, "get_app_bot_identity"
    ) as lookup:
      self.assertEqual(
          resolve_git_identity(),
          (DEFAULT_GIT_AUTHOR_NAME, DEFAULT_GIT_AUTHOR_EMAIL),
      )
    lookup.assert_not_called()

  def test_overrides_git_cannot_store_are_ignored(self):
    for name, email in (
        ("Evil <x@y>", "ok@example.com"),
        ("Two\nLines", "ok@example.com"),
        ("Fine Name", "a b@example.com"),
        ("Fine Name", "<a@example.com>"),
    ):
      with self.subTest(name=name, email=email), _clean_env(
          CODEMENDER_GIT_AUTHOR_NAME=name, CODEMENDER_GIT_AUTHOR_EMAIL=email
      ), self.assertLogs("codemender-orchestrator", level="WARNING"):
        got_name, got_email = resolve_git_identity()
        self.assertNotIn("<", got_name + got_email)
        self.assertNotIn("\n", got_name)
        self.assertNotIn(" ", got_email)

  def test_blank_overrides_are_unset(self):
    with _clean_env(
        CODEMENDER_GIT_AUTHOR_NAME="   ", CODEMENDER_GIT_AUTHOR_EMAIL=""
    ):
      self.assertEqual(
          resolve_git_identity(),
          (DEFAULT_GIT_AUTHOR_NAME, DEFAULT_GIT_AUTHOR_EMAIL),
      )


@unittest.skipUnless(
    _HAVE_CRYPTOGRAPHY, "cryptography is required to generate test keys"
)
class TestGetAppBotIdentity(unittest.TestCase):

  @classmethod
  def setUpClass(cls):
    super().setUpClass()
    cls.private_pem = _private_key_pem()

  def setUp(self):
    github_app.reset_token_cache()
    self.addCleanup(github_app.reset_token_cache)
    self.credentials = GitHubAppCredentials.from_values(
        "12345", self.private_pem
    )

  def _ok_session(self):
    return _FakeSession([
        _FakeResponse(200, {"id": 12345, "slug": "cm-fixer"}),
        _FakeResponse(200, {"login": "cm-fixer[bot]", "id": 4242, "type": "Bot"}),
    ])

  def test_resolves_slug_and_bot_user_id(self):
    session = self._ok_session()
    identity = github_app.get_app_bot_identity(
        self.credentials, "ghs_install", session=session
    )
    self.assertEqual(identity, _BOT)
    app_call, user_call = session.calls
    self.assertEqual(app_call["url"], "https://api.github.com/app")
    # The /app call is signed with the App JWT, not the installation token.
    self.assertTrue(app_call["headers"]["Authorization"].startswith("Bearer ey"))
    self.assertNotIn("ghs_install", app_call["headers"]["Authorization"])
    self.assertEqual(
        user_call["url"], "https://api.github.com/users/cm-fixer%5Bbot%5D"
    )
    self.assertEqual(user_call["headers"]["Authorization"], "Bearer ghs_install")

  def test_users_call_is_unauthenticated_without_a_token(self):
    session = self._ok_session()
    self.assertEqual(
        github_app.get_app_bot_identity(self.credentials, session=session), _BOT
    )
    self.assertNotIn("Authorization", session.calls[1]["headers"])

  def test_result_is_cached_per_app(self):
    session = self._ok_session()
    github_app.get_app_bot_identity(self.credentials, "t", session=session)
    again = github_app.get_app_bot_identity(
        self.credentials, "t", session=_FakeSession([])
    )
    self.assertEqual(again, _BOT)
    self.assertEqual(len(session.calls), 2)

  def test_failures_return_none_and_are_cached(self):
    cases = {
        "app 401": [_FakeResponse(401, {"message": "Bad credentials"})],
        "app 500": [_FakeResponse(500, {"message": "oops"})],
        "network": [requests.ConnectionError("down")],
        "bad slug": [_FakeResponse(200, {"slug": "../x"})],
        "no slug": [_FakeResponse(200, {"id": 1})],
        "user 404": [
            _FakeResponse(200, {"slug": "cm-fixer"}),
            _FakeResponse(404, {"message": "Not Found"}),
        ],
        "not a bot": [
            _FakeResponse(200, {"slug": "cm-fixer"}),
            _FakeResponse(200, {"id": 7, "type": "User"}),
        ],
        "bad id": [
            _FakeResponse(200, {"slug": "cm-fixer"}),
            _FakeResponse(200, {"id": "7", "type": "Bot"}),
        ],
        "bool id": [
            _FakeResponse(200, {"slug": "cm-fixer"}),
            _FakeResponse(200, {"id": True, "type": "Bot"}),
        ],
        "no body": [
            _FakeResponse(200, {"slug": "cm-fixer"}),
            _FakeResponse(200, None),
        ],
    }
    for label, responses in cases.items():
      with self.subTest(label):
        github_app.reset_token_cache()
        session = _FakeSession(responses)
        with self.assertLogs("codemender-orchestrator", level="WARNING") as logs:
          self.assertIsNone(
              github_app.get_app_bot_identity(
                  self.credentials, "ghs_secret", session=session
              )
          )
        self.assertNotIn("ghs_secret", "\n".join(logs.output))
        # The failure is cached: no second attempt in the same process.
        self.assertIsNone(
            github_app.get_app_bot_identity(
                self.credentials, "ghs_secret", session=_FakeSession([])
            )
        )

  def test_resolve_git_identity_end_to_end_with_mocked_github(self):
    session = self._ok_session()
    with _clean_env(
        GITHUB_APP_ID="12345", GITHUB_APP_PRIVATE_KEY=self.private_pem
    ), unittest.mock.patch.object(github_app, "requests", session):
      self.assertEqual(resolve_git_identity("ghs_install"), _BOT)

  def test_resolve_git_identity_end_to_end_lookup_failure(self):
    session = _FakeSession([requests.Timeout("slow")])
    with _clean_env(
        GITHUB_APP_ID="12345", GITHUB_APP_PRIVATE_KEY=self.private_pem
    ), unittest.mock.patch.object(github_app, "requests", session):
      self.assertEqual(
          resolve_git_identity("ghs_install"),
          (DEFAULT_GIT_AUTHOR_NAME, DEFAULT_GIT_AUTHOR_EMAIL),
      )


class TestConfigureGitIdentity(unittest.TestCase):

  def setUp(self):
    github_app.reset_token_cache()
    self.addCleanup(github_app.reset_token_cache)

  def test_sets_local_config_in_a_real_repository(self):
    with tempfile.TemporaryDirectory() as tmp, _clean_env(
        CODEMENDER_GIT_AUTHOR_NAME="Sec Bot",
        CODEMENDER_GIT_AUTHOR_EMAIL="secbot@example.com",
    ):
      subprocess.run(["git", "init", "-q", tmp], check=True)
      self.assertEqual(
          configure_git_identity(tmp), ("Sec Bot", "secbot@example.com")
      )
      for key, expected in (
          ("user.name", "Sec Bot"),
          ("user.email", "secbot@example.com"),
      ):
        got = subprocess.run(
            ["git", "-C", tmp, "config", "--local", key],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.assertEqual(got, expected)

  def test_uses_the_callers_runner(self):
    run = unittest.mock.MagicMock()
    with _clean_env():
      configure_git_identity("/repo", "tok", run=run)
    self.assertEqual(
        [c.args[0] for c in run.call_args_list],
        [
            ["git", "config", "user.name", DEFAULT_GIT_AUTHOR_NAME],
            ["git", "config", "user.email", DEFAULT_GIT_AUTHOR_EMAIL],
        ],
    )
    for c in run.call_args_list:
      self.assertEqual(c.kwargs["cwd"], "/repo")


def _fake_run(cmd, *_args, **_kwargs):
  res = unittest.mock.MagicMock(returncode=0, stdout="")
  if cmd[:3] == ["git", "branch", "--show-current"]:
    res.stdout = "main\n"
  elif cmd[:2] == ["git", "rev-parse"]:
    res.stdout = "abc123\n"
  return res


def _identity_calls(mock_run):
  return [
      c.args[0][2:]
      for c in mock_run.call_args_list
      if c.args[0][:2] == ["git", "config"]
      and c.args[0][2] in ("user.name", "user.email")
  ]


class TestRunnersConfigureTheIdentity(unittest.TestCase):
  """The scan, worker and sequential clone paths use the shared helper."""

  def setUp(self):
    github_app.reset_token_cache()
    self.addCleanup(github_app.reset_token_cache)
    self.tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self.tmp.cleanup)
    patcher = _clean_env(
        CODEMENDER_GIT_AUTHOR_NAME="Sec Bot",
        CODEMENDER_GIT_AUTHOR_EMAIL="secbot@example.com",
    )
    patcher.start()
    self.addCleanup(patcher.stop)
    self.expected = [["user.name", "Sec Bot"], ["user.email", "secbot@example.com"]]

  def test_worker_clone(self):
    with unittest.mock.patch.object(
        worker, "run_command", side_effect=_fake_run
    ) as run, unittest.mock.patch.object(worker, "setup_local_git_excludes"):
      worker._setup_git_and_checkout(  # pylint: disable=protected-access
          "https://github.com/o/r.git",
          "tok",
          os.path.join(self.tmp.name, "r"),
          self.tmp.name,
          None,
          "o",
          "r",
      )
    self.assertEqual(_identity_calls(run), self.expected)

  def test_scan_sync(self):
    with unittest.mock.patch.object(
        scan, "run_command", side_effect=_fake_run
    ) as run, unittest.mock.patch.object(scan, "setup_local_git_excludes"):
      scan._sync_repository(  # pylint: disable=protected-access
          "https://github.com/o/r.git",
          "tok",
          os.path.join(self.tmp.name, "r"),
          self.tmp.name,
      )
    self.assertEqual(_identity_calls(run), self.expected)


class TestNoGoogleAddressInCode(unittest.TestCase):

  def test_no_google_commit_address_in_the_package(self):
    offenders = []
    for path in sorted((_REPO_ROOT / "codemender_agent").rglob("*.py")):
      text = path.read_text(encoding="utf-8")
      if re.search(r"[\w.+-]+@google\.com", text):
        offenders.append(str(path.relative_to(_REPO_ROOT)))
    self.assertEqual(offenders, [])
    self.assertNotIn("google", git_module.DEFAULT_GIT_AUTHOR_EMAIL)


if __name__ == "__main__":
  unittest.main()
