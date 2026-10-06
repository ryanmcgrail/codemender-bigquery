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

"""Tests for codemender-setup secrets (github-app, github-token, wiz)."""

import io
import unittest

import yaml

from tests.setup_helper_testlib import FakeRunner, TempDirMixin, fail, make_context, make_repo, ok

from codemender_setup import cli  # pylint: disable=g-bad-import-order
from codemender_setup import common
from codemender_setup import config_edit

PEM = "-----BEGIN RSA PRIVATE KEY-----\nfake-key-material-for-tests\n-----END RSA PRIVATE KEY-----\n"
TOKEN = "fake-token-value-123"
WIZ_SECRET = "fake-wiz-secret-456"
NOT_FOUND = fail("ERROR: (gcloud.secrets.describe) NOT_FOUND: Secret [x] not found or has no versions.")


class SecretsTestBase(TempDirMixin, unittest.TestCase):

  def setUp(self):
    super().setUp()
    self.root = make_repo(self.tmp)
    self.deployment = self.root / "terraform" / "gcp" / "deployment.yaml"
    self.deployment.write_text(config_edit.render_deployment("demo-proj-123", "us-east1", "cm-demo", None))
    self.runner = FakeRunner()
    self.prompts = []
    self.prompt_answer = TOKEN
    self.ctx = None

  def _prompt(self, text):
    self.prompts.append(text)
    if isinstance(self.prompt_answer, Exception):
      raise self.prompt_answer
    return self.prompt_answer

  def main(self, *argv, stdin=""):
    def factory(repo_root, **kw):
      self.ctx = make_context(repo_root, self.runner, stdin=stdin, secret_prompt=self._prompt, **kw)
      return self.ctx
    return cli.main(["--repo-root", str(self.root), *argv], context_factory=factory)

  def output(self):
    return self.ctx.out.getvalue() + self.ctx.err.getvalue()

  def assert_never_exposed(self, *values):
    """The values appear in no argv and no output; only on stdin of gcloud."""
    text = self.output()
    for value in values:
      self.assertNotIn(value, text)
      for call in self.runner.calls:
        self.assertFalse(any(value in a for a in call["args"]), call["args"])

  def secret_exists(self, name, versions=1):
    self.runner.on(["gcloud", "secrets", "describe", name], ok(f"projects/1/secrets/{name}\n"))
    self.runner.on(["gcloud", "secrets", "versions", "list", name],
                   ok("".join(f"{i + 1}\n" for i in range(versions))))

  def secret_missing(self, name):
    self.runner.on(["gcloud", "secrets", "describe", name], NOT_FOUND)

  def accept_writes(self):
    self.runner.on(["gcloud", "secrets", "create"], ok())
    self.runner.on(["gcloud", "secrets", "versions", "add"], ok())

  def writes(self):
    return [c for c in self.runner.calls
            if c["args"][1:3] == ["secrets", "create"] or c["args"][1:4] == ["secrets", "versions", "add"]]


class GitHubAppTest(SecretsTestBase):

  def setUp(self):
    super().setUp()
    self.key = self.tmp / "app.private-key.pem"
    self.key.write_text(PEM)

  def test_creates_secret_from_file_and_sets_deployment_keys(self):
    self.secret_missing("cm-demo-github-app-private-key")
    self.accept_writes()
    code = self.main("secrets", "github-app", "--app-id", "123456", "--installation-id", "42",
                     "--key-file", str(self.key), "--skip-validate", "--non-interactive")
    self.assertEqual(code, common.EXIT_OK, self.output())
    create, add = self.writes()
    self.assertEqual(create["args"][1:], ["secrets", "create", "cm-demo-github-app-private-key",
                                          "--project=demo-proj-123", "--replication-policy=automatic"])
    self.assertEqual(add["args"][-1], f"--data-file={self.key}")
    self.assertIsNone(add["input"])
    doc = yaml.safe_load(self.deployment.read_text())
    self.assertEqual(doc["github_app_id"], "123456")
    self.assertEqual(doc["github_app_installation_id"], "42")
    self.assertNotIn("github_app_private_key_secret_id", doc)
    self.assertIn("delete the local file", self.output())
    self.assert_never_exposed("fake-key-material-for-tests")

  def test_custom_secret_name_and_locations(self):
    self.secret_missing("my-key")
    self.accept_writes()
    code = self.main("secrets", "github-app", "--app-id", "Iv1.abc", "--key-file", str(self.key),
                     "--secret-id", "my-key", "--secret-locations", "us-east1,us-west1",
                     "--skip-validate", "--non-interactive")
    self.assertEqual(code, common.EXIT_OK, self.output())
    create = self.writes()[0]
    self.assertIn("--replication-policy=user-managed", create["args"])
    self.assertIn("--locations=us-east1,us-west1", create["args"])
    doc = yaml.safe_load(self.deployment.read_text())
    self.assertEqual(doc["github_app_private_key_secret_id"], "my-key")
    self.assertNotIn("github_app_installation_id", doc)

  def test_existing_versions_need_confirmation(self):
    self.secret_exists("cm-demo-github-app-private-key", versions=2)
    self.accept_writes()
    code = self.main("secrets", "github-app", "--app-id", "1", "--key-file", str(self.key),
                     "--skip-validate", "--non-interactive")
    self.assertEqual(code, common.EXIT_OK, self.output())
    self.assertEqual(self.writes(), [])
    self.assertIn("left unchanged", self.output())
    code = self.main("secrets", "github-app", "--app-id", "1", "--key-file", str(self.key),
                     "--skip-validate", "--non-interactive", "--yes")
    self.assertEqual(code, common.EXIT_OK, self.output())
    self.assertEqual(len(self.writes()), 1)  # a new version, no create

  def test_rejects_bad_input_before_calling_gcloud(self):
    bad_key = self.tmp / "not-a-key.txt"
    bad_key.write_text("hello\n")
    cases = [
        ["--app-id", "1", "--key-file", str(bad_key)],
        ["--app-id", "1", "--key-file", str(self.tmp / "missing.pem")],
        ["--app-id", "has space", "--key-file", str(self.key)],
        ["--app-id", "1", "--installation-id", "abc", "--key-file", str(self.key)],
        ["--key-file", str(self.key)],  # no App ID in non-interactive mode
    ]
    for extra in cases:
      with self.subTest(extra=extra):
        code = self.main("secrets", "github-app", *extra, "--non-interactive", "--skip-validate")
        self.assertEqual(code, common.EXIT_USAGE)
    self.assertEqual(self.runner.calls, [])

  def test_gcloud_failure_leaves_deployment_untouched(self):
    before = self.deployment.read_text()
    self.secret_missing("cm-demo-github-app-private-key")
    self.runner.on(["gcloud", "secrets", "create"], fail("PERMISSION_DENIED: secretmanager.secrets.create"))
    code = self.main("secrets", "github-app", "--app-id", "1", "--key-file", str(self.key),
                     "--non-interactive", "--skip-validate")
    self.assertEqual(code, common.EXIT_FAILED)
    self.assertIn("PERMISSION_DENIED", self.output())
    self.assertIn("Secret Manager Admin", self.output())
    self.assertEqual(self.deployment.read_text(), before)

  def test_dry_run_reads_but_writes_nothing(self):
    before = self.deployment.read_text()
    self.secret_missing("cm-demo-github-app-private-key")
    code = self.main("secrets", "github-app", "--app-id", "1", "--key-file", str(self.key),
                     "--non-interactive", "--dry-run")
    self.assertEqual(code, common.EXIT_OK, self.output())
    self.assertEqual(self.writes(), [])
    self.assertIn("would run: secrets create cm-demo-github-app-private-key", self.output())
    self.assertIn("+github_app_id: \"1\"", self.output())
    self.assertEqual(self.deployment.read_text(), before)


class GitHubTokenTest(SecretsTestBase):

  def test_prompts_without_echo_and_sends_on_stdin(self):
    self.secret_exists("cm-demo-github-token")
    self.accept_writes()
    code = self.main("secrets", "github-token")
    self.assertEqual(code, common.EXIT_OK, self.output())
    self.assertEqual(len(self.prompts), 1)
    (add,) = self.writes()
    self.assertEqual(add["args"][1:], ["secrets", "versions", "add", "cm-demo-github-token",
                                       "--project=demo-proj-123", "--data-file=-"])
    self.assertEqual(add["input"], TOKEN)
    self.assert_never_exposed(TOKEN)

  def test_reads_stdin_and_files(self):
    self.secret_exists("cm-demo-github-token")
    self.accept_writes()
    self.assertEqual(self.main("secrets", "github-token", "--token-file", "-", "--non-interactive",
                               stdin=TOKEN + "\n"), common.EXIT_OK)
    token_file = self.tmp / "token.txt"
    token_file.write_text("  " + TOKEN + "\n")
    self.assertEqual(self.main("secrets", "github-token", "--token-file", str(token_file),
                               "--non-interactive"), common.EXIT_OK)
    self.assertEqual([c["input"] for c in self.writes()], [TOKEN, TOKEN])
    self.assertEqual(self.prompts, [])
    self.assert_never_exposed(TOKEN)

  def test_missing_secret_explains_the_first_deployment(self):
    self.secret_missing("cm-demo-github-token")
    code = self.main("secrets", "github-token")
    self.assertEqual(code, common.EXIT_FAILED)
    self.assertIn("terraform/gcp creates it", self.output())
    self.assertEqual(self.prompts, [])  # never asked for the token
    self.assertEqual(self.writes(), [])

  def test_non_interactive_needs_a_source(self):
    self.secret_exists("cm-demo-github-token")
    self.assertEqual(self.main("secrets", "github-token", "--non-interactive"), common.EXIT_USAGE)
    self.assertIn("--token-file", self.output())

  def test_rejects_empty_and_multi_word_tokens(self):
    self.secret_exists("cm-demo-github-token")
    for answer in ("", "two words"):
      with self.subTest(answer=answer):
        self.prompt_answer = answer
        self.assertEqual(self.main("secrets", "github-token"), common.EXIT_USAGE)
    self.assertEqual(self.writes(), [])

  def test_eof_at_the_prompt_cancels(self):
    self.secret_exists("cm-demo-github-token")
    self.prompt_answer = EOFError()
    self.assertEqual(self.main("secrets", "github-token"), common.EXIT_CANCELLED)

  def test_warns_when_the_app_is_configured(self):
    self.deployment.write_text(self.deployment.read_text() + 'github_app_id: "9"\n')
    self.assertEqual(self.main("secrets", "github-token", "--non-interactive"), common.EXIT_CANCELLED)
    self.assertIn("do not mount cm-demo-github-token", self.output())
    self.assertEqual(self.runner.calls, [])

  def test_common_flags_after_the_kind(self):
    self.secret_exists("cm-demo-github-token")
    code = self.main("secrets", "github-token", "--dry-run", "--project", "other-proj-1")
    self.assertEqual(code, common.EXIT_OK, self.output())
    self.assertEqual(self.writes(), [])
    self.assertIn("would run: secrets versions add cm-demo-github-token --project=other-proj-1", self.output())
    self.assert_never_exposed(TOKEN)


class WizTest(SecretsTestBase):

  def test_creates_both_secrets(self):
    self.secret_missing("cm-demo-wiz-client-id")
    self.secret_missing("cm-demo-wiz-client-secret")
    self.accept_writes()
    self.prompt_answer = WIZ_SECRET
    code = self.main("secrets", "wiz", "--client-id", "wiz-client-1")
    self.assertEqual(code, common.EXIT_OK, self.output())
    names = [c["args"][3] if c["args"][2] == "create" else c["args"][4] for c in self.writes()]
    self.assertEqual(names, ["cm-demo-wiz-client-id", "cm-demo-wiz-client-id",
                             "cm-demo-wiz-client-secret", "cm-demo-wiz-client-secret"])
    inputs = [c["input"] for c in self.writes() if c["args"][2] == "versions"]
    self.assertEqual(inputs, ["wiz-client-1", WIZ_SECRET])
    self.assertIn("wiz:", self.output())
    self.assert_never_exposed(WIZ_SECRET)

  def test_uses_secret_names_from_deployment_yaml(self):
    self.deployment.write_text(self.deployment.read_text() +
                               'wiz_client_id_secret_id: "id-name"\nwiz_client_secret_secret_id: "secret-name"\n')
    self.secret_missing("id-name")
    self.secret_missing("secret-name")
    self.accept_writes()
    code = self.main("secrets", "wiz", "--client-id", "c", "--client-secret-file", "-", "--non-interactive",
                     stdin=WIZ_SECRET)
    self.assertEqual(code, common.EXIT_OK, self.output())
    self.assertEqual({c["args"][3] for c in self.writes() if c["args"][2] == "create"}, {"id-name", "secret-name"})

  def test_bad_locations(self):
    code = self.main("secrets", "wiz", "--client-id", "c", "--client-secret-file", "-", "--non-interactive",
                     "--secret-locations", "US", stdin=WIZ_SECRET)
    self.assertEqual(code, common.EXIT_USAGE)
    self.assertEqual(self.writes(), [])


class ReadSecretTest(TempDirMixin, unittest.TestCase):

  def test_sources(self):
    ctx = make_context(self.tmp, stdin="from-stdin\n", secret_prompt=lambda p: " typed \n")
    self.assertEqual(ctx.read_secret("X", "-"), "from-stdin")
    self.assertEqual(ctx.read_secret("X"), "typed")
    with self.assertRaises(common.UsageError):
      ctx.read_secret("X", str(self.tmp / "missing"), "--x-file")
    ctx = make_context(self.tmp, non_interactive=True)
    with self.assertRaises(common.UsageError):
      ctx.read_secret("X", None, "--x-file")

  def test_missing_deployment(self):
    root = make_repo(self.tmp)
    ctx = make_context(root)
    ctx.out = io.StringIO()
    with self.assertRaises(common.UsageError):
      config_edit.read_deployment(ctx)


if __name__ == "__main__":
  unittest.main()
