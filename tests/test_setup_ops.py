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

"""Tests for codemender-setup doctor, first-image and teardown (gcloud stubbed)."""

import json
import unittest

from tests.setup_helper_testlib import FakeRunner, TempDirMixin, fail, make_context, make_repo, ok

from codemender_setup import cli  # pylint: disable=g-bad-import-order
from codemender_setup import common
from codemender_setup import config_edit
from codemender_setup import gcp
from codemender_setup import ops

PROJECT = "demo-proj-123"
REPO_NAME = f"projects/{PROJECT}/locations/us-east1/connections/github/repositories/svc-repo"
AGENT = "serviceAccount:service-123456789@gcp-sa-cloudbuild.iam.gserviceaccount.com"
BUCKET = f"cm-demo-tfstate-{PROJECT}"
REAL_IMAGE = f"us-east1-docker.pkg.dev/{PROJECT}/cm-demo/runner@sha256:abc"
REPOS = "repositories:\n  svc:\n    repo_url: https://github.com/acme/svc.git\n"


class OpsTestBase(TempDirMixin, unittest.TestCase):

  def setUp(self):
    super().setUp()
    self.root = make_repo(self.tmp)
    self.tfvars = self.root / config_edit.BOOTSTRAP_TFVARS
    self.tfvars.write_text(config_edit.render_bootstrap_tfvars(
        PROJECT, "us-east1", "cm-demo", "main", ["group:admins@example.com"], REPO_NAME))
    self.deployment = self.root / config_edit.DEPLOYMENT
    self.deployment.write_text(config_edit.render_deployment(PROJECT, "us-east1", "cm-demo", None))
    (self.root / config_edit.REPOS).write_text(REPOS)
    self.runner = FakeRunner()
    self.ctx = None

  def main(self, *argv, stdin="", tools=None):
    def factory(repo_root, **kw):
      self.ctx = make_context(repo_root, self.runner, tools=tools, stdin=stdin, **kw)
      return self.ctx
    return cli.main(["--repo-root", str(self.root), *argv], context_factory=factory)

  def output(self):
    return self.ctx.out.getvalue() + self.ctx.err.getvalue()

  def commands(self):
    return [" ".join(c[1:]) for c in self.runner.commands()]

  def jobs(self, image):
    self.runner.on(["gcloud", "run", "jobs", "describe"], ok(image + "\n") if image else fail("NOT_FOUND"))


class DoctorTest(OpsTestBase):

  def healthy(self):
    """Every check answers like a finished deployment."""
    r = self.runner
    r.on(["gcloud", "builds", "connections", "describe"],
         ok(json.dumps({"installationState": {"stage": "COMPLETE"}})))
    r.on(["gcloud", "projects", "describe"], ok("123456789\n"))
    r.on(["gcloud", "projects", "get-iam-policy"],
         ok(json.dumps({"bindings": [{"role": "roles/viewer", "members": [AGENT]}]})))
    r.on(["gcloud", "storage", "buckets", "describe"], ok(BUCKET + "\n"))
    r.on(["gcloud", "storage", "ls"], ok(f"gs://{BUCKET}/{gcp.STATE_BACKUP_OBJECT}\n"))
    r.on(["gcloud", "builds", "triggers", "list"],
         ok("".join(f"cm-demo-{s}\tid-{s}\n" for s in ops.TRIGGER_SUFFIXES) + "other-stack-image\tid-other\n"))
    r.on(["gcloud", "builds", "list"], ok(""))
    self.jobs(REAL_IMAGE)
    r.on(["gcloud", "secrets", "versions", "list"], ok("1\n2\n"))

  def test_healthy_deployment_passes_and_suggests_unpausing(self):
    self.healthy()
    code = self.main("doctor")
    out = self.output()
    self.assertEqual(code, common.EXIT_OK, out)
    self.assertNotIn("[FAIL", out)
    self.assertIn("Cloud Build connection: github is complete", out)
    self.assertIn(f"State bucket: {BUCKET}", out)
    self.assertIn("Bootstrap state backup: present", out)
    self.assertIn("Cloud Build triggers: all 4 present", out)
    self.assertIn(f"Runner image: {REAL_IMAGE}", out)
    self.assertIn("codemender-setup set scheduler_paused false --pr", out)
    self.assertIn("token in cm-demo-github-token", out)
    cmds = self.commands()
    self.assertIn("builds connections describe github --region=us-east1 "
                  f"--project={PROJECT} --format=json", cmds)
    self.assertIn(f"storage ls gs://{BUCKET}/{gcp.STATE_BACKUP_OBJECT}", cmds)
    # Read-only: nothing that creates, changes or deletes.
    for c in cmds:
      for verb in (" create", " delete", " add-", " remove-", "triggers run", " approve", " update", " enable"):
        self.assertNotIn(verb, " " + c + " ", c)

  def test_placeholder_image_says_first_image(self):
    self.healthy()
    self.runner.rules.insert(0, (["gcloud", "run", "jobs", "describe"], ok(ops.PLACEHOLDER_IMAGE + ":latest\n")))
    code = self.main("doctor")
    out = self.output()
    self.assertEqual(code, common.EXIT_OK, out)
    self.assertIn("[WARN] Runner image: the jobs still run the placeholder image", out)
    self.assertIn("codemender-setup first-image", out)
    self.assertNotIn("scheduler_paused false", out)

  def test_missing_jobs_and_triggers_fail(self):
    self.healthy()
    self.runner.rules.insert(0, (["gcloud", "run", "jobs", "describe"], fail("NOT_FOUND")))
    self.runner.rules.insert(0, (["gcloud", "builds", "triggers", "list"], ok("cm-demo-tf-plan\n")))
    code = self.main("doctor")
    out = self.output()
    self.assertEqual(code, common.EXIT_FAILED, out)
    self.assertIn("[FAIL] Cloud Run job cm-demo-runner: not found", out)
    self.assertIn("missing cm-demo-tf-apply, cm-demo-tf-apply-destroy, cm-demo-image", out)

  def test_leftover_agent_grant_and_pending_approval_warn(self):
    self.healthy()
    r = self.runner
    r.rules.insert(0, (["gcloud", "projects", "get-iam-policy"],
                       ok(json.dumps({"bindings": [{"role": gcp.SERVICE_AGENT_ROLE, "members": [AGENT]}]}))))
    r.rules.insert(0, (lambda base, cwd: base[:3] == ["gcloud", "builds", "list"]
                       and any(a.startswith("--filter=approval.state=PENDING") for a in base),
                       ok("build-1\nbuild-2\n")))
    code = self.main("doctor")
    out = self.output()
    self.assertEqual(code, common.EXIT_OK, out)
    self.assertIn(f"[WARN] Cloud Build service agent: still has {gcp.SERVICE_AGENT_ROLE}", out)
    self.assertIn(f"gcloud projects remove-iam-policy-binding {PROJECT} --member={AGENT}", out)
    self.assertIn("[WARN] Builds waiting for approval: 2", out)
    # `gcloud beta builds approve` has no --location flag.
    self.assertIn(f"gcloud alpha builds approve build-1 --location=us-east1 --project={PROJECT}", out)

  def test_build_checks_only_cover_this_deployments_triggers(self):
    self.healthy()
    self.main("doctor")
    builds = [c for c in self.commands() if c.startswith("builds list")]
    self.assertEqual(len(builds), 2, builds)
    ids = " OR ".join(sorted(f"id-{s}" for s in ops.TRIGGER_SUFFIXES))
    for c in builds:
      self.assertIn(f"buildTriggerId=({ids})", c)
      self.assertNotIn("id-other", c)

  def test_no_triggers_means_no_build_checks(self):
    self.healthy()
    self.runner.rules.insert(0, (["gcloud", "builds", "triggers", "list"], ok("other-stack-image\tid-other\n")))
    self.main("doctor")
    self.assertFalse([c for c in self.commands() if c.startswith("builds list")])

  def test_connection_not_complete_and_no_backup(self):
    self.healthy()
    r = self.runner
    r.rules.insert(0, (["gcloud", "builds", "connections", "describe"],
                       ok(json.dumps({"installationState": {"stage": "PENDING_INSTALL_APP"}}))))
    r.rules.insert(0, (["gcloud", "storage", "ls"], fail("matched no objects")))
    code = self.main("doctor")
    out = self.output()
    self.assertEqual(code, common.EXIT_FAILED, out)
    self.assertIn("github is PENDING_INSTALL_APP", out)
    self.assertIn("[WARN] Bootstrap state backup: missing", out)

  def test_unconnected_repository_fails(self):
    self.healthy()
    self.tfvars.write_text(config_edit.render_bootstrap_tfvars(
        PROJECT, "us-east1", "cm-demo", "main", ["group:admins@example.com"], ""))
    code = self.main("doctor")
    out = self.output()
    self.assertEqual(code, common.EXIT_FAILED, out)
    self.assertIn("cloudbuild_repository is not set", out)
    self.assertNotIn("connections describe", " ".join(self.commands()))

  def test_github_app_key_and_wiz_secrets(self):
    self.healthy()
    with self.deployment.open("a") as f:
      f.write('github_app_id: "12345"\nwiz_client_id_secret_id: my-wiz-id\n')
    (self.root / config_edit.REPOS).write_text(REPOS + "    wiz:\n      enabled: true\n")

    def versions(base, cwd):
      return ok("") if base[4] in ("cm-demo-github-app-private-key", "cm-demo-wiz-client-secret") else ok("1\n")
    self.runner.rules.insert(0, (["gcloud", "secrets", "versions", "list"], versions))
    code = self.main("doctor")
    out = self.output()
    self.assertEqual(code, common.EXIT_FAILED, out)
    self.assertIn("[FAIL] GitHub App private key: cm-demo-github-app-private-key is missing", out)
    self.assertIn("[OK  ] Wiz secret: my-wiz-id", out)
    self.assertIn("[FAIL] Wiz secret: cm-demo-wiz-client-secret is missing", out)
    self.assertNotIn("cm-demo-github-token", out)

  def test_wiz_flow_mapping_is_detected(self):
    self.healthy()
    (self.root / config_edit.REPOS).write_text(REPOS + '    wiz: {min_severity: HIGH, enabled: "true"}\n')
    self.runner.rules.insert(0, (["gcloud", "secrets", "versions", "list"], ok("")))
    self.main("doctor")
    self.assertIn("[FAIL] Wiz secret: cm-demo-wiz-client-id is missing", self.output())

  def test_commented_wiz_is_ignored(self):
    self.healthy()
    (self.root / config_edit.REPOS).write_text(REPOS + "    # wiz:\n    #   enabled: true\n")
    self.runner.rules.insert(0, (["gcloud", "secrets", "versions", "list"], ok("")))
    self.main("doctor")
    self.assertNotIn("Wiz secret", self.output())

  def test_token_placeholder_only_warns(self):
    self.healthy()
    self.runner.rules.insert(0, (["gcloud", "secrets", "versions", "list"], ok("1\n")))
    self.main("doctor")
    self.assertIn("may hold only Terraform's placeholder", self.output())

  def test_bad_config_and_missing_deployment(self):
    self.deployment.unlink()
    code = self.main("doctor")
    out = self.output()
    self.assertEqual(code, common.EXIT_FAILED, out)
    self.assertIn("terraform/gcp/deployment.yaml: missing", out)
    self.assertEqual(self.runner.calls, [])

  def test_no_gcloud(self):
    code = self.main("doctor", tools={"git": "/usr/bin/git"})
    self.assertEqual(code, common.EXIT_FAILED)
    self.assertIn("[FAIL] gcloud: not found", self.output())


class FirstImageTest(OpsTestBase):

  def test_job_missing(self):
    self.jobs(None)
    code = self.main("first-image", "--yes")
    self.assertEqual(code, common.EXIT_FAILED)
    self.assertIn("cm-demo-runner does not exist yet", self.output())
    self.assertFalse(any("triggers run" in c for c in self.commands()))

  def test_dry_run_prints_the_trigger_run(self):
    self.jobs(ops.PLACEHOLDER_IMAGE)
    code = self.main("first-image", "--dry-run")
    self.assertEqual(code, common.EXIT_OK, self.output())
    self.assertIn(f"would run: builds triggers run cm-demo-image --branch=main --region=us-east1 "
                  f"--project={PROJECT}", self.output())
    self.assertFalse(any("triggers run" in c for c in self.commands()))

  def test_runs_the_image_trigger(self):
    self.jobs(ops.PLACEHOLDER_IMAGE)
    self.runner.on(["gcloud", "builds", "triggers", "run"],
                   ok(json.dumps({"metadata": {"build": {"id": "b-42"}}})))
    code = self.main("first-image", "--yes")
    out = self.output()
    self.assertEqual(code, common.EXIT_OK, out)
    self.assertIn(f"builds triggers run cm-demo-image --branch=main --region=us-east1 --project={PROJECT} "
                  "--format=json", self.commands())
    self.assertIn("Started build b-42", out)
    self.assertIn("gcloud builds log --stream b-42", out)

  def test_real_image_asks_before_rebuilding(self):
    self.jobs(REAL_IMAGE)
    code = self.main("first-image", stdin="n\n")
    self.assertEqual(code, common.EXIT_OK, self.output())
    self.assertIn(f"already runs {REAL_IMAGE}", self.output())
    self.assertFalse(any("triggers run" in c for c in self.commands()))

  def test_trigger_failure(self):
    self.jobs(ops.PLACEHOLDER_IMAGE)
    self.runner.on(["gcloud", "builds", "triggers", "run"], fail("NOT_FOUND: trigger"))
    code = self.main("first-image", "--yes")
    self.assertEqual(code, common.EXIT_FAILED)
    self.assertIn("NOT_FOUND: trigger", self.output())


class TeardownTest(OpsTestBase):

  def test_requires_print(self):
    code = self.main("teardown")
    self.assertEqual(code, common.EXIT_USAGE)
    self.assertIn("pass --print", self.output())

  def test_prints_steps_and_runs_nothing(self):
    code = self.main("teardown", "--print")
    out = self.output()
    self.assertEqual(code, common.EXIT_OK, out)
    self.assertEqual(self.runner.calls, [])
    self.assertIn(f"TF_STATE_BUCKET={BUCKET} scripts/ci/tf_init.sh", out)
    self.assertIn(f"gs://{BUCKET}/{gcp.STATE_BACKUP_OBJECT}", out)
    self.assertIn(f"gcloud builds repositories delete svc-repo --connection=github --region=us-east1 "
                  f"--project={PROJECT}", out)
    self.assertIn(f"gcloud secrets delete cm-demo-github-app-private-key --project={PROJECT}", out)
    self.assertIn("cm-demo-coordinator", out)
    self.assertLess(out.index("scheduler_paused true"), out.index("terraform -chdir=terraform/gcp destroy"))
    self.assertLess(out.index("terraform/gcp destroy"), out.index("terraform/bootstrap destroy"))

  def test_destroy_prerequisites_are_stated_as_required(self):
    # With the defaults, terraform destroy fails on the deletion-protected
    # BigQuery tables and on the non-empty state bucket; the steps must say so
    # before the destroy commands rather than present them as optional.
    self.main("teardown", "--print")
    out = self.output()
    self.assertIn("the destroy stops with an error on them", out)
    self.assertIn("its deletion fails unless state_bucket_force_destroy = true", out)
    self.assertLess(out.index("bigquery_deletion_protection: false"),
                    out.index("terraform -chdir=terraform/gcp destroy"))
    self.assertLess(out.index("state_bucket_force_destroy"), out.index("terraform -chdir=terraform/bootstrap destroy"))

  def test_regional_secret_commands_use_the_regional_endpoint(self):
    # gcloud sends `secrets list/delete --location` to the global endpoint,
    # which rejects the regional name with INVALID_ARGUMENT; each command needs
    # the regional endpoint, set per command so step 6 (global secrets) still
    # works.
    self.main("teardown", "--print")
    lines = self.output().splitlines()
    override = "CLOUDSDK_API_ENDPOINT_OVERRIDES_SECRETMANAGER=https://secretmanager.us-east1.rep.googleapis.com/"
    regional = [line for line in lines if line.startswith(("gcloud secrets", override)) and "--location=" in line]
    self.assertEqual(len(regional), 2, lines)
    for line in regional:
      self.assertTrue(line.startswith(override + " gcloud secrets "), line)
      self.assertIn(f"--location=us-east1 --project={PROJECT}", line)
    self.assertFalse(any(line.startswith("export ") for line in lines))
    self.assertIn(f"gcloud secrets delete cm-demo-github-app-private-key --project={PROJECT}", lines)
    self.assertIn("rep.mtls.googleapis.com", self.output())

  def test_without_connection_uses_placeholders(self):
    self.tfvars.unlink()
    code = self.main("teardown", "--print")
    out = self.output()
    self.assertEqual(code, common.EXIT_OK, out)
    self.assertIn("--connection=CONNECTION", out)
    self.assertIn(f"TF_STATE_BUCKET={BUCKET}", out)


if __name__ == "__main__":
  unittest.main()
