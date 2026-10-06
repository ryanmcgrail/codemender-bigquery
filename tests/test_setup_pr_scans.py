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

"""Tests for codemender-setup pr-scans (gcloud, gh and ghcr.io stubbed)."""

import io
import json
import unittest
import urllib.error
from unittest import mock

from tests.setup_helper_testlib import FakeRunner, TempDirMixin, fail, make_context, make_repo, ok

from codemender_setup import cli  # pylint: disable=g-bad-import-order
from codemender_setup import common
from codemender_setup import config_edit
from codemender_setup import pr_scans

PROJECT = "demo-proj-123"
IMAGE = "ghcr.io/acme/codemender-runner:latest"
PROVIDER = json.dumps({"oidc": {"issuerUri": pr_scans.GITHUB_ISSUER},
                       "attributeCondition": "assertion.repository_owner == 'acme'"})


class FakeResponse(io.BytesIO):

  def __enter__(self):
    return self

  def __exit__(self, *exc):
    self.close()


def http_error(url, code):
  return urllib.error.HTTPError(url, code, "error", {}, None)


class FakeGhcr:
  """Answers the anonymous token request and the manifest HEAD."""

  def __init__(self, manifest_code=200, token_code=200):
    self.manifest_code, self.token_code = manifest_code, token_code
    self.requests = []

  def __call__(self, req, timeout=None):
    self.requests.append(req)
    url = req.full_url
    if url.startswith("https://ghcr.io/token"):
      if self.token_code != 200:
        raise http_error(url, self.token_code)
      return FakeResponse(json.dumps({"token": "fake-anon-token"}).encode())
    if self.manifest_code != 200:
      raise http_error(url, self.manifest_code)
    return FakeResponse(b"")


class PrScansTest(TempDirMixin, unittest.TestCase):

  def setUp(self):
    super().setUp()
    self.root = make_repo(self.tmp)
    (self.root / config_edit.DEPLOYMENT).write_text(
        config_edit.render_deployment(PROJECT, "us-east1", "cm-demo", None))
    self.runner = FakeRunner()
    self.runner.on(["git", "-C", str(self.root), "remote", "get-url", "origin"],
                   ok("git@github.com:acme/svc-repo.git\n"))
    self.ghcr = FakeGhcr()
    self.ctx = None

  def wif(self, present=True):
    r = self.runner
    r.on(["gcloud", "iam", "workload-identity-pools", "providers", "describe"],
         ok(PROVIDER) if present else fail("NOT_FOUND"))
    r.on(["gcloud", "iam", "service-accounts", "describe"],
         ok(f"codemender-gha-sa@{PROJECT}.iam.gserviceaccount.com\n") if present else fail("NOT_FOUND"))
    r.on(["gcloud", "services", "list"], ok("aiplatform.googleapis.com\n") if present else ok(""))
    r.on(lambda base, cwd: base[:2] == ["gh", "api"] and "/actions/secrets/" in base[2],
         ok('{"name": "X"}') if present else fail("gh: Not Found (HTTP 404)"))

  def main(self, *argv, tools=None):
    def factory(repo_root, **kw):
      self.ctx = make_context(repo_root, self.runner, tools=tools, **kw)
      return self.ctx
    with mock.patch.object(pr_scans.urllib.request, "urlopen", self.ghcr):
      return cli.main(["--repo-root", str(self.root), "pr-scans", *argv], context_factory=factory)

  def output(self):
    return self.ctx.out.getvalue() + self.ctx.err.getvalue()

  def commands(self):
    return [" ".join(c[1:]) for c in self.runner.commands()]

  def test_placeholder_image_fails_and_points_to_the_generator(self):
    self.wif()
    code = self.main()
    out = self.output()
    self.assertEqual(code, common.EXIT_FAILED, out)
    self.assertIn(f"[FAIL] runner_image: {pr_scans.PLACEHOLDER_IMAGE} is the placeholder", out)
    self.assertEqual(self.ghcr.requests, [])
    self.assertIn("scripts/ci/init_codemender_workflow.py", out)
    self.assertIn("docs/guides/github_actions_presubmit_ci_cd.md", out)
    self.assertIn("[WARN] runner_type: not given", out)

  def test_public_ghcr_image_and_hosted_runner_pass(self):
    self.wif()
    code = self.main("--image", IMAGE, "--runner-type", "ubuntu-latest")
    out = self.output()
    self.assertEqual(code, common.EXIT_OK, out)
    self.assertIn(f"[OK  ] runner_image: {IMAGE} exists and is public", out)
    self.assertIn("[OK  ] Workload identity provider: codemender-gha-pool/codemender-gha-provider", out)
    self.assertIn("[OK  ] Actions secret GCP_WORKLOAD_IDENTITY_PROVIDER: set on acme/svc-repo", out)
    self.assertIn("[OK  ] Vertex AI API: enabled", out)
    self.assertIn("GitHub-hosted", out)
    self.assertNotIn("containerMode", out)  # only for self-hosted runners
    self.assertIn("aiplatform.googleapis.com", out)  # egress list
    manifest = self.ghcr.requests[1]
    self.assertEqual(manifest.get_method(), "HEAD")
    self.assertEqual(manifest.full_url, "https://ghcr.io/v2/acme/codemender-runner/manifests/latest")
    self.assertIn(f"--runner-image {IMAGE}", out)
    self.assertNotIn("add `runner_type:", out)  # ubuntu-latest is the workflow default
    # Read-only.
    self.assertFalse(any(" create" in c or " delete" in c or "-X" in c for c in self.commands()))

  def test_private_ghcr_image_warns_with_visibility(self):
    self.wif()
    self.ghcr.manifest_code = 401
    self.runner.on(["gh", "api", "orgs/acme/packages/container/codemender-runner"],
                   ok(json.dumps({"visibility": "private"})))
    code = self.main("--image", IMAGE, "--runner-type", "ubuntu-latest")
    out = self.output()
    self.assertEqual(code, common.EXIT_OK, out)
    self.assertIn(f"[WARN] runner_image: {IMAGE} is private", out)
    self.assertIn("Manage Actions access", out)

  def test_user_package_fallback(self):
    self.wif()
    self.ghcr.manifest_code = 404
    self.runner.on(["gh", "api", "orgs/acme/packages/container/codemender-runner"], fail("HTTP 404"))
    self.runner.on(["gh", "api", "users/acme/packages/container/codemender-runner"],
                   ok(json.dumps({"visibility": "internal"})))
    self.main("--image", IMAGE)
    self.assertIn("is internal", self.output())

  def test_missing_ghcr_image_fails(self):
    self.wif()
    self.ghcr.manifest_code = 404
    self.runner.on(["gh", "api"], fail("HTTP 404"))
    code = self.main("--image", IMAGE, "--runner-type", "ubuntu-latest")
    self.assertEqual(code, common.EXIT_FAILED)
    self.assertIn("not found, or not visible to you (HTTP 404)", self.output())

  def test_registry_outage_is_a_warning(self):
    self.wif()
    self.ghcr.token_code = 503
    self.runner.on(["gh", "api"], fail("HTTP 404"))
    code = self.main("--image", IMAGE, "--runner-type", "ubuntu-latest")
    self.assertEqual(code, common.EXIT_OK, self.output())
    self.assertIn("[WARN] runner_image: could not check", self.output())

  def test_mirror_image_is_info_only(self):
    self.wif()
    image = "artifactory.example.com/docker/codemender-runner:1.2"
    code = self.main("--image", image, "--runner-type", "ubuntu-latest")
    out = self.output()
    self.assertEqual(code, common.EXIT_OK, out)
    self.assertIn(f"[INFO] runner_image: {image} is on artifactory.example.com", out)
    self.assertEqual(self.ghcr.requests, [])

  def test_missing_wif_fails(self):
    self.wif(present=False)
    code = self.main("--image", IMAGE, "--runner-type", "ubuntu-latest")
    out = self.output()
    self.assertEqual(code, common.EXIT_FAILED, out)
    self.assertIn("codemender-gha-pool/codemender-gha-provider not found in demo-proj-123", out)
    self.assertIn(f"codemender-gha-sa@{PROJECT}.iam.gserviceaccount.com not found", out)
    self.assertIn("[FAIL] Vertex AI API: not enabled", out)
    self.assertIn("[WARN] Actions secret GCP_SERVICE_ACCOUNT: not set on acme/svc-repo", out)

  def test_wif_flags_override_defaults(self):
    self.wif()
    self.main("--image", IMAGE, "--wif-project", "other-proj-1", "--pool", "p", "--provider", "q",
              "--service-account", "sa@other-proj-1.iam.gserviceaccount.com")
    cmds = self.commands()
    self.assertIn("iam workload-identity-pools providers describe q --workload-identity-pool=p "
                  "--location=global --project=other-proj-1 --format=json", cmds)
    self.assertIn("iam service-accounts describe sa@other-proj-1.iam.gserviceaccount.com "
                  "--project=other-proj-1 --format=value(email)", cmds)

  def test_self_hosted_runners_with_arc_names(self):
    self.wif()
    runners = {"runners": [
        {"name": "arc-linux-runner-abcde", "status": "online", "labels": [{"name": "self-hosted"},
                                                                           {"name": "arc-linux"}]},
        {"name": "other", "status": "offline", "labels": [{"name": "gpu"}]}]}
    self.runner.on(["gh", "api", "repos/acme/svc-repo/actions/runners?per_page=100"], ok(json.dumps(runners)))
    code = self.main("--image", IMAGE, "--runner-type", "arc-linux")
    out = self.output()
    self.assertEqual(code, common.EXIT_OK, out)
    self.assertIn("[INFO] runner_type: arc-linux (self-hosted)", out)
    self.assertIn("1 registered, 1 online", out)
    self.assertIn("Actions Runner Controller scale sets", out)
    self.assertIn("containerMode dind", out)
    self.assertIn("sandbox_enabled: false", out)
    self.assertIn("Artifactory", out)
    self.assertIn("add `runner_type: arc-linux` there", out)

  def test_self_hosted_without_admin_access(self):
    self.wif()
    self.runner.on(["gh", "api", "repos/acme/svc-repo/actions/runners?per_page=100"], fail("HTTP 403"))
    self.runner.on(["gh", "api", "orgs/acme/actions/runners?per_page=100"], fail("HTTP 403"))
    code = self.main("--image", IMAGE, "--runner-type", "my-runners")
    out = self.output()
    self.assertEqual(code, common.EXIT_OK, out)
    self.assertIn("could not list runners", out)
    self.assertIn("containerMode kubernetes", out)

  def test_self_hosted_label_not_registered(self):
    self.wif()
    self.runner.on(["gh", "api", "repos/acme/svc-repo/actions/runners?per_page=100"],
                   ok(json.dumps({"runners": []})))
    self.main("--image", IMAGE, "--runner-type", "my-runners")
    self.assertIn("[WARN] Runners with that label: none registered right now", self.output())

  def test_github_enterprise_host_fails(self):
    self.wif()
    self.runner.rules.insert(0, (["git", "-C", str(self.root), "remote", "get-url", "origin"],
                                 ok("https://acme.ghe.com/acme/svc-repo.git\n")))
    code = self.main("--image", IMAGE, "--runner-type", "ubuntu-latest")
    self.assertEqual(code, common.EXIT_FAILED)
    self.assertIn("acme.ghe.com is not supported", self.output())

  def test_no_wif_skips_identity_checks(self):
    (self.root / config_edit.DEPLOYMENT).unlink()
    code = self.main("--image", IMAGE, "--runner-type", "arc-linux", "--no-wif")
    out = self.output()
    self.assertEqual(code, common.EXIT_OK, out)
    self.assertIn("[SKIP] Workload Identity Federation", out)
    self.assertIn("GKE Workload Identity", out)
    self.assertFalse(any(c.startswith("iam ") or c.startswith("services ") for c in self.commands()))

  def test_no_project(self):
    (self.root / config_edit.DEPLOYMENT).unlink()
    code = self.main("--image", IMAGE, "--runner-type", "ubuntu-latest")
    self.assertEqual(code, common.EXIT_FAILED)
    self.assertIn("Pass --wif-project", self.output())


class ParseImageTest(unittest.TestCase):

  def test_forms(self):
    self.assertEqual(pr_scans.parse_image("ghcr.io/o/n:1.0"), ("ghcr.io", "o/n", "1.0"))
    self.assertEqual(pr_scans.parse_image("ghcr.io/o/n"), ("ghcr.io", "o/n", "latest"))
    self.assertEqual(pr_scans.parse_image("ghcr.io/o/n@sha256:abc"), ("ghcr.io", "o/n", "@sha256:abc"))
    self.assertEqual(pr_scans.parse_image("ghcr.io/o/n:1.0@sha256:abc"), ("ghcr.io", "o/n", "@sha256:abc"))
    self.assertEqual(pr_scans.parse_image("registry.example.com:5000/a/b/c:t"),
                     ("registry.example.com:5000", "a/b/c", "t"))
    self.assertIsNone(pr_scans.parse_image("codemender-runner:latest"))
    self.assertIsNone(pr_scans.parse_image(""))

  def test_digest_manifest_url(self):
    ghcr = FakeGhcr()
    self.assertEqual(pr_scans.ghcr_anonymous_pull("o/n", "@sha256:abc", ghcr), (True, ""))
    self.assertEqual(ghcr.requests[1].full_url, "https://ghcr.io/v2/o/n/manifests/sha256:abc")


if __name__ == "__main__":
  unittest.main()
