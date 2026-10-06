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

"""Tests for `codemender-setup check` with stub gcloud, terraform, git and gh."""

import io
import json
import unittest
import urllib.error

from tests.setup_helper_testlib import FakeRunner, TempDirMixin, make_context, make_repo, ok, fail

from codemender_setup import check  # pylint: disable=g-bad-import-order
from codemender_setup import common


class Args:

  def __init__(self, project=None, connection_project=None, github_repo=None):
    self.project = project
    self.connection_project = connection_project
    self.github_repo = github_repo


class FakeResponse(io.BytesIO):

  def __enter__(self):
    return self

  def __exit__(self, *exc):
    return False


def opener_granting(granted, invalid=(), status=None):
  """A urlopen stand-in for testIamPermissions."""
  calls = []

  def opener(req, timeout=None):
    body = json.loads(req.data.decode())
    calls.append((req.full_url, body["permissions"]))
    if status:
      raise urllib.error.HTTPError(req.full_url, status, "err", {}, io.BytesIO(b'{"error":{"message":"nope"}}'))
    if any(p in invalid for p in body["permissions"]):
      raise urllib.error.HTTPError(req.full_url, 400, "bad", {}, io.BytesIO(b'{"error":{"message":"invalid"}}'))
    return FakeResponse(json.dumps({"permissions": [p for p in body["permissions"] if p in granted]}).encode())

  opener.calls = calls
  return opener


def healthy_runner(visibility="private", actions="true", tf_version="1.11.4"):
  return (FakeRunner()
          .on(["terraform", "version", "-json"], ok(json.dumps({"terraform_version": tf_version})))
          .on(["gcloud", "--version"], ok("Google Cloud SDK 500.0.0\n"))
          .on(["git", "--version"], ok("git version 2.40.0\n"))
          .on(["git", "-C"], ok("git@github.com:acme/deploy.git\n"))
          .on(["gh", "auth", "status"], ok())
          .on(["gh", "api", "repos/acme/deploy", "--jq", ".visibility"], ok(visibility + "\n"))
          .on(["gh", "api", "repos/acme/deploy/actions/permissions"], ok(actions + "\n"))
          .on(["gcloud", "config", "get-value", "account"], ok("me@example.com\n"))
          .on(["gcloud", "config", "get-value", "project"], ok("from-gcloud-1\n"))
          .on(["gcloud", "auth", "application-default", "print-access-token"], ok("fake-access-token\n")))


class CheckTest(TempDirMixin, unittest.TestCase):

  def setUp(self):
    super().setUp()
    self.root = make_repo(self.tmp)

  def _run(self, runner, args=None, opener=None, **ctx_kwargs):
    ctx = make_context(self.root, runner, **ctx_kwargs)
    code = check.run(ctx, args or Args(), opener=opener or opener_granting(set(check.SETUP_PERMISSIONS)))
    return code, ctx.out.getvalue()

  def test_all_good(self):
    code, out = self._run(healthy_runner())
    self.assertEqual(code, common.EXIT_OK, out)
    self.assertIn("[OK  ] terraform: 1.11.4", out)
    self.assertIn("[OK  ] Visibility: private", out)
    self.assertIn("[OK  ] Setup permissions: all present", out)
    self.assertIn("from-gcloud-1 (from gcloud config)", out)

  def test_old_terraform_fails(self):
    code, out = self._run(healthy_runner(tf_version="1.9.8"))
    self.assertEqual(code, common.EXIT_FAILED)
    self.assertIn("1.11 or later is needed", out)

  def test_public_and_internal_repositories_fail(self):
    for visibility in ("public", "internal"):
      with self.subTest(visibility=visibility):
        code, out = self._run(healthy_runner(visibility=visibility))
        self.assertEqual(code, common.EXIT_FAILED)
        self.assertIn(f"[FAIL] Visibility: {visibility}", out)

  def test_actions_permission_403_is_unknown_not_failure(self):
    runner = healthy_runner()
    runner.rules.insert(0, (["gh", "api", "repos/acme/deploy/actions/permissions"], fail("HTTP 403")))
    code, out = self._run(runner)
    self.assertEqual(code, common.EXIT_OK, out)
    self.assertIn("GitHub Actions: unknown", out)

  def test_missing_permissions_named_by_role(self):
    granted = set(check.SETUP_PERMISSIONS) - {"iam.roles.create", "storage.buckets.create"}
    code, out = self._run(healthy_runner(), opener=opener_granting(granted))
    self.assertEqual(code, common.EXIT_FAILED)
    self.assertIn("missing Role Administrator, Storage Admin", out)

  def test_invalid_permission_name_is_tested_one_by_one(self):
    granted = set(check.SETUP_PERMISSIONS)
    opener = opener_granting(granted, invalid={"cloudbuild.connections.create"})
    code, out = self._run(healthy_runner(), opener=opener)
    self.assertEqual(code, common.EXIT_OK, out)
    self.assertIn("could not test cloudbuild.connections.create", out)
    self.assertGreater(len(opener.calls), 1)

  def test_permission_check_http_error_is_a_warning(self):
    code, out = self._run(healthy_runner(), opener=opener_granting(set(), status=403))
    self.assertEqual(code, common.EXIT_OK, out)
    self.assertIn("could not check (HTTP 403 nope)", out)

  def test_connection_project_is_checked_separately(self):
    opener = opener_granting(set(check.SETUP_PERMISSIONS) | set(check.CONNECTION_PERMISSIONS))
    code, out = self._run(healthy_runner(), args=Args(project="main-proj-1", connection_project="conn-proj-1"),
                          opener=opener)
    self.assertEqual(code, common.EXIT_OK, out)
    urls = [u for u, _ in opener.calls]
    self.assertTrue(any("projects/main-proj-1:" in u for u in urls))
    self.assertTrue(any("projects/conn-proj-1:" in u for u in urls))

  def test_expired_adc(self):
    runner = healthy_runner()
    runner.rules.insert(0, (["gcloud", "auth", "application-default"], fail("Reauthentication failed")))
    code, out = self._run(runner)
    self.assertEqual(code, common.EXIT_FAILED)
    self.assertIn("gcloud auth application-default login", out)
    self.assertIn("[SKIP] Setup permissions", out)

  def test_project_from_deployment_yaml(self):
    (self.root / "terraform" / "gcp" / "deployment.yaml").write_text('project_id: "dep-proj-1"\n')
    code, out = self._run(healthy_runner())
    self.assertEqual(code, common.EXIT_OK, out)
    self.assertIn("dep-proj-1 (from deployment.yaml)", out)

  def test_missing_tools_with_cloud_shell_hint(self):
    runner = healthy_runner()
    code, out = self._run(runner, tools={"gcloud": "/usr/bin/gcloud", "git": "/usr/bin/git"},
                          environ={"CLOUD_SHELL": "true"})
    self.assertEqual(code, common.EXIT_FAILED)
    self.assertIn("[FAIL] terraform: not found", out)
    self.assertIn("Cloud Shell's Terraform", out)
    self.assertIn("[WARN] gh: not found", out)
    self.assertIn("Environment: Cloud Shell", out)

  def test_codespaces_hint(self):
    code, out = self._run(healthy_runner(), tools={"gcloud": "/usr/bin/gcloud", "git": "/usr/bin/git"},
                          environ={"CODESPACES": "true"})
    self.assertIn(".devcontainer", out)

  def test_dependabot_and_workflows_warn(self):
    gh_dir = self.root / ".github" / "workflows"
    gh_dir.mkdir(parents=True)
    (self.root / ".github" / "dependabot.yml").write_text("version: 2\n")
    (gh_dir / "ci.yml").write_text("on: push\n")
    code, out = self._run(healthy_runner())
    self.assertEqual(code, common.EXIT_OK, out)
    self.assertIn("[WARN] Dependabot", out)
    self.assertIn("[WARN] GitHub Actions workflows: ci.yml", out)

  def test_ghe_remote_fails(self):
    runner = healthy_runner()
    runner.rules.insert(0, (["git", "-C"], ok("https://acme.ghe.com/acme/deploy.git\n")))
    code, out = self._run(runner)
    self.assertEqual(code, common.EXIT_FAILED)
    self.assertIn("github.com only", out)

  def test_check_never_runs_mutating_commands(self):
    runner = healthy_runner()
    self._run(runner)
    for cmd in runner.commands():
      joined = " ".join(cmd)
      for verb in (" create", " delete", " apply", " add-iam-policy-binding", " enable", " push"):
        self.assertNotIn(verb, joined)


if __name__ == "__main__":
  unittest.main()
