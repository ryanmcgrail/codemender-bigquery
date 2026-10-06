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

"""Tests for codemender-setup connect and bootstrap (gcloud and terraform stubbed)."""

import json
import pathlib
import unittest
import uuid

import yaml

from tests.setup_helper_testlib import FakeRunner, TempDirMixin, fail, make_context, make_repo, ok

from codemender_setup import cli  # pylint: disable=g-bad-import-order
from codemender_setup import common
from codemender_setup import config_edit
from codemender_setup import gcp

PROJECT = "demo-proj-123"
REPO_NAME = f"projects/{PROJECT}/locations/us-east1/connections/github/repositories/svc-repo"
AGENT = "serviceAccount:service-123456789@gcp-sa-cloudbuild.iam.gserviceaccount.com"


def connection(stage, uri="https://github.com/apps/google-cloud-build/installations/new"):
  return json.dumps({"name": "projects/x/locations/us-east1/connections/github",
                     "githubConfig": {},
                     "installationState": {"stage": stage, "actionUri": uri, "message": f"stage {stage}"}})


class GcpTestBase(TempDirMixin, unittest.TestCase):

  def setUp(self):
    super().setUp()
    self.root = make_repo(self.tmp)
    self.tfvars = self.root / config_edit.BOOTSTRAP_TFVARS
    self.write_tfvars()
    self.deployment = self.root / config_edit.DEPLOYMENT
    self.deployment.write_text(config_edit.render_deployment(PROJECT, "us-east1", "cm-demo", None))
    self.runner = FakeRunner()
    self.ctx = None

  def write_tfvars(self, approvers=("group:admins@example.com",), repo=""):
    self.tfvars.write_text(config_edit.render_bootstrap_tfvars(
        PROJECT, "us-east1", "cm-demo", "main", list(approvers), repo))

  def main(self, *argv, stdin="", environ=None):
    def factory(repo_root, **kw):
      self.ctx = make_context(repo_root, self.runner, stdin=stdin, environ=environ, **kw)
      return self.ctx
    return cli.main(["--repo-root", str(self.root), *argv], context_factory=factory)

  def output(self):
    return self.ctx.out.getvalue() + self.ctx.err.getvalue()

  def commands(self):
    return [" ".join(c[1:]) for c in self.runner.commands()]


class ConnectTest(GcpTestBase):

  def setUp(self):
    super().setUp()
    self.runner.on(["git", "-C", str(self.root), "remote", "get-url", "origin"],
                   ok("git@github.com:acme/svc-repo.git\n"))
    self.runner.on(["gcloud", "projects", "describe"], ok("123456789\n"))
    self.runner.on(["gcloud", "services", "enable"], ok())
    self.runner.on(["gcloud", "projects", "add-iam-policy-binding"], ok())
    self.runner.on(["gcloud", "projects", "remove-iam-policy-binding"], ok())
    self.runner.on(["gcloud", "builds", "connections", "create"], ok())
    self.runner.on(["gcloud", "builds", "repositories", "create"], ok())

  def stages(self, *stages):
    """connections describe answers NOT_FOUND or the given stages in turn."""
    queue = list(stages)

    def answer(base, cwd):
      stage = queue.pop(0) if len(queue) > 1 else queue[0]
      if stage is None:
        return fail("ERROR: (gcloud.builds.connections.describe) NOT_FOUND: Requested entity was not found.")
      return ok(connection(stage))
    self.runner.on(["gcloud", "builds", "connections", "describe"], answer)

  def policy(self, has_role):
    bindings = [{"role": "roles/secretmanager.admin", "members": [AGENT]}] if has_role else [
        {"role": "roles/viewer", "members": [AGENT]}]
    self.runner.on(["gcloud", "projects", "get-iam-policy"], ok(json.dumps({"bindings": bindings})))

  def repos(self, *entries):
    self.runner.on(["gcloud", "builds", "repositories", "list"], ok(json.dumps(list(entries))))

  def test_new_connection_walks_through_browser_steps(self):
    self.stages(None, "PENDING_USER_OAUTH", "PENDING_INSTALL_APP", "COMPLETE")
    self.policy(has_role=False)
    self.repos()
    code = self.main("connect", "--yes", stdin="\n\n")
    self.assertEqual(code, common.EXIT_OK, self.output())
    cmds = self.commands()
    self.assertIn("services enable cloudbuild.googleapis.com secretmanager.googleapis.com "
                  f"--project={PROJECT}", cmds)
    self.assertIn(f"projects add-iam-policy-binding {PROJECT} --member={AGENT} "
                  "--role=roles/secretmanager.admin --condition=None --format=none", cmds)
    self.assertIn(f"builds connections create github github --region=us-east1 --project={PROJECT}", cmds)
    self.assertIn(f"projects remove-iam-policy-binding {PROJECT} --member={AGENT} "
                  "--role=roles/secretmanager.admin --condition=None --format=none", cmds)
    self.assertIn("builds repositories create svc-repo --remote-uri=https://github.com/acme/svc-repo.git "
                  f"--connection=github --region=us-east1 --project={PROJECT}", cmds)
    out = self.output()
    self.assertIn("Authorize Cloud Build", out)
    self.assertIn("Install the Cloud Build GitHub App", out)
    self.assertIn("https://github.com/apps/google-cloud-build/installations/new", out)
    self.assertEqual(config_edit.read_tfvar(self.tfvars.read_text(), "cloudbuild_repository"), REPO_NAME)

  def test_reuses_complete_connection_and_existing_link(self):
    self.stages("COMPLETE")
    console_name = f"projects/{PROJECT}/locations/us-east1/connections/github/repositories/acme-svc-repo"
    self.repos({"name": "projects/x/other", "remoteUri": "https://github.com/acme/other.git"},
               {"name": console_name, "remoteUri": "https://github.com/ACME/svc-repo"})
    code = self.main("connect", "--non-interactive")
    self.assertEqual(code, common.EXIT_OK, self.output())
    cmds = " | ".join(self.commands())
    for mutating in ("services enable", "add-iam-policy-binding", "connections create", "repositories create",
                     "remove-iam-policy-binding"):
      self.assertNotIn(mutating, cmds)
    self.assertEqual(config_edit.read_tfvar(self.tfvars.read_text(), "cloudbuild_repository"), console_name)

  def test_existing_grant_is_neither_added_nor_removed(self):
    self.stages(None, "COMPLETE")
    self.policy(has_role=True)
    self.repos()
    code = self.main("connect", "--yes")
    self.assertEqual(code, common.EXIT_OK, self.output())
    cmds = " | ".join(self.commands())
    self.assertNotIn("add-iam-policy-binding", cmds)
    self.assertNotIn("remove-iam-policy-binding", cmds)

  def test_non_interactive_pending_stops_with_the_link(self):
    before = self.tfvars.read_text()
    self.stages("PENDING_INSTALL_APP")
    code = self.main("connect", "--non-interactive")
    self.assertEqual(code, common.EXIT_FAILED)
    self.assertIn("installations/new", self.output())
    self.assertIn("run `codemender-setup connect` again", self.output())
    self.assertEqual(self.tfvars.read_text(), before)

  def test_eof_while_waiting_cancels(self):
    self.stages("PENDING_USER_OAUTH")
    self.assertEqual(self.main("connect"), common.EXIT_CANCELLED)

  def test_dry_run_changes_nothing(self):
    before = self.tfvars.read_text()
    self.stages(None)
    code = self.main("connect", "--dry-run")
    self.assertEqual(code, common.EXIT_OK, self.output())
    cmds = " | ".join(self.commands())
    for mutating in ("services enable", "add-iam-policy-binding", "connections create", "repositories create"):
      self.assertNotIn(mutating, cmds)
    self.assertIn("would run: builds connections create github github", self.output())
    self.assertEqual(self.tfvars.read_text(), before)

  def test_connection_region_wins(self):
    self.stages("COMPLETE")
    name = f"projects/{PROJECT}/locations/us-central1/connections/github/repositories/svc-repo"
    self.repos({"name": name, "remoteUri": "https://github.com/acme/svc-repo.git"})
    code = self.main("connect", "--region", "us-central1", "--non-interactive")
    self.assertEqual(code, common.EXIT_OK, self.output())
    text = self.tfvars.read_text()
    self.assertEqual(config_edit.read_tfvar(text, "cloudbuild_repository"), name)
    self.assertEqual(config_edit.read_tfvar(text, "region"), "us-central1")

  def test_rejects_other_hosts_and_unusable_connections(self):
    self.runner.rules.insert(0, (["git", "-C", str(self.root), "remote", "get-url", "origin"],
                                 ok("https://acme.ghe.com/acme/svc-repo.git\n")))
    self.assertEqual(self.main("connect", "--non-interactive"), common.EXIT_USAGE)
    self.assertIn("only github.com", self.output())
    self.runner.rules.pop(0)
    self.runner.on(["gcloud", "builds", "connections", "describe"],
                   ok(json.dumps({"name": "c", "disabled": True, "githubConfig": {}})))
    self.assertEqual(self.main("connect", "--non-interactive"), common.EXIT_FAILED)
    self.assertIn("disabled", self.output())

  def test_needs_init(self):
    self.tfvars.unlink()
    self.assertEqual(self.main("connect"), common.EXIT_USAGE)
    self.assertIn("run `init` first", self.output())

  def test_reuses_discovered_connection_when_flag_omitted(self):
    self.runner.on(["gcloud", "builds", "connections", "list"],
                   ok(json.dumps([{"name": f"projects/{PROJECT}/locations/us-east1/connections/corp-github",
                                   "githubConfig": {},
                                   "installationState": {"stage": "COMPLETE"}}])))
    self.runner.on(["gcloud", "builds", "connections", "describe"],
                   ok(json.dumps({"name": f"projects/{PROJECT}/locations/us-east1/connections/corp-github",
                                  "githubConfig": {},
                                  "installationState": {"stage": "COMPLETE"}})))
    self.repos()
    code = self.main("connect", stdin="\n")
    self.assertEqual(code, common.EXIT_OK, self.output())
    cmds = self.commands()
    self.assertIn("builds repositories create svc-repo --remote-uri=https://github.com/acme/svc-repo.git "
                  f"--connection=corp-github --region=us-east1 --project={PROJECT}", cmds)
    self.assertIn("Reuse existing connection 'corp-github'?", self.output())
    expected_repo = f"projects/{PROJECT}/locations/us-east1/connections/corp-github/repositories/svc-repo"
    self.assertEqual(config_edit.read_tfvar(self.tfvars.read_text(), "cloudbuild_repository"), expected_repo)

  def test_declining_discovered_connection_falls_back_to_github(self):
    self.runner.on(["gcloud", "builds", "connections", "list"],
                   ok(json.dumps([{"name": f"projects/{PROJECT}/locations/us-east1/connections/corp-github",
                                   "githubConfig": {},
                                   "installationState": {"stage": "COMPLETE"}}])))
    self.stages("COMPLETE")
    self.repos()
    code = self.main("connect", stdin="n\n")
    self.assertEqual(code, common.EXIT_OK, self.output())
    cmds = self.commands()
    self.assertIn("builds repositories create svc-repo --remote-uri=https://github.com/acme/svc-repo.git "
                  f"--connection=github --region=us-east1 --project={PROJECT}", cmds)
    self.assertEqual(config_edit.read_tfvar(self.tfvars.read_text(), "cloudbuild_repository"), REPO_NAME)

  def test_declining_discovered_github_connection_prompts_for_custom_name(self):
    self.runner.on(["gcloud", "builds", "connections", "list"],
                   ok(json.dumps([{"name": f"projects/{PROJECT}/locations/us-east1/connections/github",
                                   "githubConfig": {},
                                   "installationState": {"stage": "COMPLETE"}}])))
    self.stages("COMPLETE")
    self.repos()
    code = self.main("connect", stdin="n\ncustom-github-conn\n")
    self.assertEqual(code, common.EXIT_OK, self.output())
    cmds = self.commands()
    self.assertIn("builds repositories create svc-repo --remote-uri=https://github.com/acme/svc-repo.git "
                  f"--connection=custom-github-conn --region=us-east1 --project={PROJECT}", cmds)
    expected_repo = f"projects/{PROJECT}/locations/us-east1/connections/custom-github-conn/repositories/svc-repo"
    self.assertEqual(config_edit.read_tfvar(self.tfvars.read_text(), "cloudbuild_repository"), expected_repo)

  def test_explicit_connection_skips_discovery(self):
    self.runner.on(["gcloud", "builds", "connections", "list"],
                   ok(json.dumps([{"name": f"projects/{PROJECT}/locations/us-east1/connections/corp-github",
                                   "githubConfig": {},
                                   "installationState": {"stage": "COMPLETE"}}])))
    self.runner.on(["gcloud", "builds", "connections", "describe"],
                   ok(json.dumps({"name": f"projects/{PROJECT}/locations/us-east1/connections/my-custom-conn",
                                  "githubConfig": {},
                                  "installationState": {"stage": "COMPLETE"}})))
    self.repos()
    code = self.main("connect", "--connection=my-custom-conn", "--non-interactive")
    self.assertEqual(code, common.EXIT_OK, self.output())
    cmds = self.commands()
    self.assertNotIn("builds connections list", " | ".join(cmds))
    self.assertIn("builds repositories create svc-repo --remote-uri=https://github.com/acme/svc-repo.git "
                  f"--connection=my-custom-conn --region=us-east1 --project={PROJECT}", cmds)
    expected_repo = f"projects/{PROJECT}/locations/us-east1/connections/my-custom-conn/repositories/svc-repo"
    self.assertEqual(config_edit.read_tfvar(self.tfvars.read_text(), "cloudbuild_repository"), expected_repo)


class BootstrapTest(GcpTestBase):

  OUTPUTS = {
      "state_bucket": {"value": "cm-demo-tfstate-demo-proj-123"},
      "image_build_service_account": {"value": "cm-demo-image-build@demo-proj-123.iam.gserviceaccount.com"},
      "triggers": {"value": {"plan": "cm-demo-tf-plan", "apply": "cm-demo-tf-apply"}},
      "deployment_yaml_snippet": {"value": f"project_id: {PROJECT}\nregion: us-east1\nresource_prefix: cm-demo\n"},
  }

  def setUp(self):
    super().setUp()
    self.write_tfvars(repo=REPO_NAME)
    self.state = self.root / "terraform" / "bootstrap" / "terraform.tfstate"
    self.runner.on(["terraform", "version"], ok(json.dumps({"terraform_version": "1.13.3"})))
    self.runner.on(lambda b, cwd: b[0] == "terraform" and b[2] == "init", ok("Initialized"))
    self.runner.on(lambda b, cwd: b[0] == "terraform" and b[2] == "output", ok(json.dumps(self.OUTPUTS)))
    self.runner.on(["gcloud", "storage", "cp"], ok())

  def plan(self, code, text="Plan: 12 to add, 0 to change, 0 to destroy."):
    self.runner.on(lambda b, cwd: b[0] == "terraform" and b[2] == "plan", common.Result(code, text, ""))

  def apply(self, result=None):
    def answer(base, cwd):
      self.state.write_text("{}")
      return result or ok("Apply complete!")
    self.runner.on(lambda b, cwd: b[0] == "terraform" and b[2] == "apply", answer)

  def tf_calls(self):
    return [c for c in self.runner.calls if c["args"][0].endswith("terraform") and c["args"][1] != "version"]

  def test_plan_confirm_apply_backup(self):
    self.plan(2)
    self.apply()
    environ = {"PATH": "/usr/bin", "TF_VAR_project_id": "elsewhere", "TF_CLI_ARGS_plan": "-target=x"}
    code = self.main("bootstrap", "--yes", "--skip-validate", environ=environ)
    self.assertEqual(code, common.EXIT_OK, self.output())
    calls = self.tf_calls()
    self.assertEqual([c["args"][2] for c in calls], ["init", "plan", "apply", "output"])
    self.assertTrue(calls[0]["args"][1].startswith("-chdir=") and calls[0]["args"][1].endswith("terraform/bootstrap"))
    for c in calls:
      self.assertNotIn("TF_VAR_project_id", c["env"])
      self.assertNotIn("TF_CLI_ARGS_plan", c["env"])
    plan_out = next(a for a in calls[1]["args"] if a.startswith("-out="))[len("-out="):]
    self.assertEqual(calls[2]["args"][-1], plan_out)
    self.assertIn("storage cp " + str(self.state) +
                  " gs://cm-demo-tfstate-demo-proj-123/bootstrap-backup/terraform.tfstate", self.commands())
    self.assertIn("Plan: 12 to add", self.output())
    self.assertIn("cm-demo-tf-plan (demo-proj-123)", self.output())
    self.assertIn("Seeded initial empty Terraform state at "
                  "gs://cm-demo-tfstate-demo-proj-123/terraform/gcp/default.tfstate", self.output())

  def test_declining_the_plan_applies_nothing(self):
    self.plan(2)
    self.apply()
    self.assertEqual(self.main("bootstrap", "--non-interactive"), common.EXIT_CANCELLED)
    self.assertEqual([c["args"][2] for c in self.tf_calls()], ["init", "plan"])

  def test_dry_run_plans_only(self):
    self.plan(2)
    self.assertEqual(self.main("bootstrap", "--dry-run"), common.EXIT_OK)
    self.assertEqual([c["args"][2] for c in self.tf_calls()], ["init", "plan"])
    self.assertNotIn("storage cp", " | ".join(self.commands()))

  def test_no_changes_still_backs_up_and_reconciles(self):
    self.plan(0, "No changes.")
    self.state.write_text("{}")
    code = self.main("bootstrap", "--non-interactive", "--skip-validate")
    self.assertEqual(code, common.EXIT_OK, self.output())
    self.assertEqual([c["args"][2] for c in self.tf_calls()], ["init", "plan", "output"])
    self.assertIn("No changes to apply.", self.output())
    self.assertIn("Backed up", self.output())

  def test_plan_error(self):
    self.plan(1, "Error: bad")
    self.assertEqual(self.main("bootstrap", "--yes"), common.EXIT_FAILED)
    self.assertIn("Error: bad", self.output())
    self.assertEqual([c["args"][2] for c in self.tf_calls()], ["init", "plan"])

  def test_apply_error(self):
    self.plan(2)
    self.apply(fail("Error: permission denied"))
    self.assertEqual(self.main("bootstrap", "--yes"), common.EXIT_FAILED)
    self.assertIn("permission denied", self.output())
    self.assertIn("run `codemender-setup bootstrap` again", self.output())
    self.assertNotIn("storage cp", " | ".join(self.commands()))

  def test_restores_backup_when_local_state_is_missing(self):
    self.runner.on(["gcloud", "storage", "ls"], ok("gs://cm-demo-tfstate-demo-proj-123/bootstrap-backup/terraform.tfstate\n"))
    self.plan(0, "No changes.")
    code = self.main("bootstrap", "--non-interactive", "--skip-validate", "--skip-backup")
    self.assertEqual(code, common.EXIT_OK, self.output())
    cmds = self.commands()
    self.assertIn("storage cp gs://cm-demo-tfstate-demo-proj-123/bootstrap-backup/terraform.tfstate "
                  f"{self.state}", cmds)
    # Restored before terraform init.
    order = [c[0] if c[0] != "storage" else " ".join(c[:2]) for c in (x.split() for x in cmds)]
    self.assertLess(order.index("storage cp"), order.index("-chdir=" + str(self.root / "terraform" / "bootstrap")))
    self.assertIn("a backup exists", self.output())

  def test_no_restore_with_local_state_or_without_backup(self):
    self.state.write_text("{}")
    self.runner.on(["gcloud", "storage", "ls"], ok("gs://x\n"))
    self.plan(0, "No changes.")
    self.assertEqual(self.main("bootstrap", "--non-interactive", "--skip-validate", "--skip-backup"),
                     common.EXIT_OK)
    self.assertNotIn(f"storage ls gs://cm-demo-tfstate-demo-proj-123/{gcp.STATE_BACKUP_OBJECT}",
                     " | ".join(self.commands()))
    self.state.unlink()
    self.runner.rules.insert(0, (["gcloud", "storage", "ls"], fail("One or more URLs matched no objects.")))
    self.assertEqual(self.main("bootstrap", "--non-interactive", "--skip-validate", "--skip-backup"),
                     common.EXIT_OK)
    self.assertNotIn(f"storage cp gs://cm-demo-tfstate-demo-proj-123/{gcp.STATE_BACKUP_OBJECT}",
                     " | ".join(self.commands()))

  def test_state_bucket_name(self):
    self.assertEqual(gcp.state_bucket_name(self.tfvars.read_text()), "cm-demo-tfstate-demo-proj-123")
    self.assertEqual(gcp.state_bucket_name('state_bucket_name = "mine"\n'), "mine")

  def test_backup_failure_is_reported(self):
    self.plan(2)
    self.apply()
    self.runner.rules.insert(0, (["gcloud", "storage", "cp"], fail("AccessDenied")))
    self.assertEqual(self.main("bootstrap", "--yes", "--skip-validate"), common.EXIT_FAILED)
    self.assertIn("Keep terraform/bootstrap/terraform.tfstate safe", self.output())

  def test_adds_a_new_image_build_account(self):
    outputs = dict(self.OUTPUTS)
    outputs["image_build_service_account"] = {"value": "new-image-build@demo-proj-123.iam.gserviceaccount.com"}
    self.runner.rules.insert(0, (lambda b, cwd: b[0] == "terraform" and b[2] == "output", ok(json.dumps(outputs))))
    self.plan(0, "No changes.")
    code = self.main("bootstrap", "--non-interactive", "--skip-validate", "--skip-backup")
    self.assertEqual(code, common.EXIT_OK, self.output())
    doc = yaml.safe_load(self.deployment.read_text())
    self.assertEqual(doc["cloudbuild_service_account_emails"], [
        "cm-demo-image-build@demo-proj-123.iam.gserviceaccount.com",
        "new-image-build@demo-proj-123.iam.gserviceaccount.com"])
    self.assertNotIn(f"storage cp {self.state} gs://cm-demo-tfstate-demo-proj-123/{gcp.STATE_BACKUP_OBJECT}",
                     " | ".join(self.commands()))

  def test_seeds_initial_state_when_missing(self):
    uploaded_content = None

    def catch_cp(base, cwd):
      nonlocal uploaded_content
      src = base[3]
      if "default.tfstate" in base[-1]:
        uploaded_content = pathlib.Path(src).read_text(encoding="utf-8")
      return ok()

    self.runner.rules.insert(0, (lambda b, cwd: b[:3] == ["gcloud", "storage", "cp"] and b[-1].endswith("default.tfstate"), catch_cp))
    self.plan(0, "No changes.")
    self.state.write_text("{}")
    code = self.main("bootstrap", "--non-interactive", "--skip-validate")
    self.assertEqual(code, common.EXIT_OK, self.output())
    self.assertIn("Seeded initial empty Terraform state at "
                  "gs://cm-demo-tfstate-demo-proj-123/terraform/gcp/default.tfstate", self.output())
    self.assertIsNotNone(uploaded_content)
    data = json.loads(uploaded_content)
    self.assertEqual(data["version"], 4)
    self.assertEqual(data["terraform_version"], "1.13.3")
    self.assertEqual(data["serial"], 0)
    self.assertTrue(uuid.UUID(data["lineage"]))
    self.assertEqual(data["outputs"], {})
    self.assertEqual(data["resources"], [])

  def test_seeds_initial_state_with_custom_prefix_from_tfvars(self):
    self.write_tfvars(repo=REPO_NAME)
    self.tfvars.write_text(self.tfvars.read_text() + '\nstate_prefix = "custom/prefix"\n')
    self.plan(0, "No changes.")
    self.state.write_text("{}")
    code = self.main("bootstrap", "--non-interactive", "--skip-validate", "--skip-backup")
    self.assertEqual(code, common.EXIT_OK, self.output())
    self.assertIn("Seeded initial empty Terraform state at "
                  "gs://cm-demo-tfstate-demo-proj-123/custom/prefix/default.tfstate", self.output())
    self.assertTrue(any(len(c) > 3 and c[1:3] == ["storage", "cp"] and c[-1] == "gs://cm-demo-tfstate-demo-proj-123/custom/prefix/default.tfstate"
                        for c in self.runner.commands()))

  def test_skips_seeding_when_state_already_exists(self):
    self.runner.rules.insert(0, (lambda b, cwd: b[:3] == ["gcloud", "storage", "ls"] and b[-1].endswith("default.tfstate"),
                                 ok("gs://cm-demo-tfstate-demo-proj-123/terraform/gcp/default.tfstate\n")))
    self.plan(0, "No changes.")
    self.state.write_text("{}")
    code = self.main("bootstrap", "--non-interactive", "--skip-validate", "--skip-backup")
    self.assertEqual(code, common.EXIT_OK, self.output())
    self.assertNotIn("Seeded initial empty Terraform state", self.output())
    self.assertFalse(any(len(c) > 3 and c[1:3] == ["storage", "cp"] and c[-1].endswith("default.tfstate")
                         for c in self.runner.commands()))

  def test_seeding_failure_is_reported(self):
    self.plan(0, "No changes.")
    self.state.write_text("{}")
    self.runner.rules.insert(0, (lambda b, cwd: b[:3] == ["gcloud", "storage", "cp"] and b[-1].endswith("default.tfstate"),
                                 fail("AccessDenied")))
    self.assertEqual(self.main("bootstrap", "--non-interactive", "--skip-validate", "--skip-backup"),
                     common.EXIT_FAILED)
    self.assertIn("Could not seed initial empty Terraform state", self.output())

  def test_preconditions(self):
    self.write_tfvars(repo="")
    self.assertEqual(self.main("bootstrap"), common.EXIT_USAGE)
    self.assertIn("connect", self.output())
    self.write_tfvars(approvers=(), repo=REPO_NAME)
    self.assertEqual(self.main("bootstrap"), common.EXIT_USAGE)
    self.assertIn("approver", self.output())
    self.write_tfvars(repo=REPO_NAME)
    self.runner.rules.insert(0, (["terraform", "version"], ok(json.dumps({"terraform_version": "1.9.8"}))))
    self.assertEqual(self.main("bootstrap"), common.EXIT_USAGE)
    self.assertIn("too old", self.output())
    self.assertEqual(self.tf_calls(), [])


class ReconcileTest(unittest.TestCase):

  def test_warns_on_mismatch_and_keeps_present_account(self):
    text = config_edit.render_deployment(PROJECT, "us-west1", "cm-demo", None)
    new, warnings = gcp.reconcile_deployment(text, {
        "deployment_yaml_snippet": f"project_id: {PROJECT}\nregion: us-east1\nresource_prefix: cm-demo\n",
        "image_build_service_account": "cm-demo-image-build@demo-proj-123.iam.gserviceaccount.com"})
    self.assertEqual(new, text)
    self.assertEqual(len(warnings), 1)
    self.assertIn("region", warnings[0])

  def test_normalize_remote(self):
    self.assertEqual(gcp.normalize_remote("git@github.com:Acme/Repo.git"), "https://github.com/acme/repo.git")
    self.assertEqual(gcp.normalize_remote("https://github.com/acme/repo"), "https://github.com/acme/repo.git")


class StateSeedingTest(TempDirMixin, unittest.TestCase):

  def setUp(self):
    super().setUp()
    self.runner = FakeRunner()
    self.ctx = make_context(self.tmp, self.runner)

  def test_empty_tfstate_format(self):
    raw = gcp.empty_tfstate("1.13.3")
    data = json.loads(raw)
    self.assertEqual(data["version"], 4)
    self.assertEqual(data["terraform_version"], "1.13.3")
    self.assertEqual(data["serial"], 0)
    self.assertTrue(uuid.UUID(data["lineage"]))
    self.assertEqual(data["outputs"], {})
    self.assertEqual(data["resources"], [])

  def test_state_prefix(self):
    self.assertEqual(gcp.state_prefix(""), "terraform/gcp")
    self.assertEqual(gcp.state_prefix('state_prefix = "custom/prefix"\n'), "custom/prefix")
    self.assertEqual(gcp.state_prefix('state_prefix = "/custom/prefix/"\n'), "custom/prefix")

  def test_seed_initial_state_missing_gcloud(self):
    ctx = make_context(self.tmp, self.runner, tools={})
    self.assertFalse(gcp.seed_initial_state(ctx, "my-bucket", "terraform/gcp"))
    self.assertIn("Could not seed initial empty Terraform state: gcloud not found", ctx.out.getvalue())

  def test_seed_initial_state_dry_run(self):
    self.runner.on(["gcloud", "storage", "ls"], fail("not found"))
    self.ctx.dry_run = True
    self.assertTrue(gcp.seed_initial_state(self.ctx, "my-bucket", "terraform/gcp"))
    self.assertIn("would seed initial empty Terraform state at gs://my-bucket/terraform/gcp/default.tfstate",
                  self.ctx.out.getvalue())
    self.assertEqual([c for c in self.runner.commands() if len(c) > 2 and c[1:3] == ["storage", "cp"]], [])

  def test_seed_initial_state_already_exists(self):
    self.runner.on(["gcloud", "storage", "ls"], ok("gs://my-bucket/terraform/gcp/default.tfstate"))
    self.assertTrue(gcp.seed_initial_state(self.ctx, "my-bucket", "terraform/gcp"))
    self.assertEqual([c for c in self.runner.commands() if len(c) > 2 and c[1:3] == ["storage", "cp"]], [])

  def test_seed_initial_state_copies_valid_state(self):
    uploaded = None

    def catch_cp(base, cwd):
      nonlocal uploaded
      uploaded = pathlib.Path(base[3]).read_text(encoding="utf-8")
      return ok()

    self.runner.on(["gcloud", "storage", "ls"], fail("not found"))
    self.runner.on(["gcloud", "storage", "cp"], catch_cp)
    self.assertTrue(gcp.seed_initial_state(self.ctx, "my-bucket", "terraform/gcp", "1.13.3"))
    self.assertIn("Seeded initial empty Terraform state at gs://my-bucket/terraform/gcp/default.tfstate",
                  self.ctx.out.getvalue())
    self.assertIsNotNone(uploaded)
    data = json.loads(uploaded)
    self.assertEqual(data["version"], 4)
    self.assertEqual(data["terraform_version"], "1.13.3")

  def test_seed_initial_state_normalizes_bucket_with_gs_prefix(self):
    self.runner.on(["gcloud", "storage", "ls"], fail("not found"))
    self.runner.on(["gcloud", "storage", "cp"], ok())
    self.assertTrue(gcp.seed_initial_state(self.ctx, "gs://my-bucket/", "terraform/gcp"))
    self.assertIn("Seeded initial empty Terraform state at gs://my-bucket/terraform/gcp/default.tfstate",
                  self.ctx.out.getvalue())
    self.assertEqual([c for c in self.runner.commands() if len(c) > 2 and c[1:3] == ["storage", "cp"]][-1][-1],
                     "gs://my-bucket/terraform/gcp/default.tfstate")

  def test_seed_initial_state_cp_failure(self):
    self.runner.on(["gcloud", "storage", "ls"], fail("not found"))
    self.runner.on(["gcloud", "storage", "cp"], fail("Permission denied"))
    self.assertFalse(gcp.seed_initial_state(self.ctx, "my-bucket", "terraform/gcp"))
    self.assertIn("Could not seed initial empty Terraform state at gs://my-bucket/terraform/gcp/default.tfstate: Permission denied",
                  self.ctx.out.getvalue())

  def test_seed_initial_state_cp_failure_with_stdout(self):
    self.runner.on(["gcloud", "storage", "ls"], fail("not found"))
    self.runner.on(["gcloud", "storage", "cp"], common.Result(1, "Storage bucket not found", ""))
    self.assertFalse(gcp.seed_initial_state(self.ctx, "my-bucket", "terraform/gcp"))
    self.assertIn("Could not seed initial empty Terraform state at gs://my-bucket/terraform/gcp/default.tfstate: Storage bucket not found",
                  self.ctx.out.getvalue())

  def test_terraform_returns_path_string(self):
    self.runner.on(["terraform", "version", "-json"], ok(json.dumps({"terraform_version": "1.14.0"})))
    tf = gcp._terraform(self.ctx)
    self.assertIsInstance(tf, str)
    self.assertTrue(tf.endswith("terraform"))


if __name__ == "__main__":
  unittest.main()
