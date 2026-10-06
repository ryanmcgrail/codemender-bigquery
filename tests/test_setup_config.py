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

"""Tests for codemender-setup init, add-repo, remove-repo, set and --pr."""

import io
import os
import pathlib
import shutil
import stat
import subprocess
import unittest

import yaml

from tests.setup_helper_testlib import TempDirMixin, make_context, make_repo

from codemender_setup import common  # pylint: disable=g-bad-import-order
from codemender_setup import config_edit


class Args:
  """argparse.Namespace stand-in with the defaults of every edit command."""

  def __init__(self, **kw):
    self.project = None
    self.region = None
    self.prefix = None
    self.bigquery_dataset = None
    self.branch = None
    self.approver = []
    self.force = False
    self.pr = False
    self.skip_validate = True
    self.name = None
    self.url = None
    self.schedule = None
    self.target_branch = None
    self.scan_target = None
    self.build_command = None
    self.scan_dry_run = False
    self.key = None
    self.value = None
    self.__dict__.update(kw)


INIT_ARGS = dict(project="demo-proj-123", region="us-east1", prefix="cm-demo",
                 bigquery_dataset="cm_demo", branch="main", approver=["group:admins@example.com"])


class InitTest(TempDirMixin, unittest.TestCase):

  def setUp(self):
    super().setUp()
    self.root = make_repo(self.tmp)

  def _init(self, stdin="", **kw):
    ctx = make_context(self.root, stdin=stdin, non_interactive=not stdin)
    code = config_edit.run_init(ctx, Args(**{**INIT_ARGS, **kw}))
    return code, ctx

  def test_writes_the_three_files(self):
    code, ctx = self._init()
    self.assertEqual(code, common.EXIT_OK, ctx.out.getvalue())
    gcp = self.root / "terraform" / "gcp"
    deployment = yaml.safe_load((gcp / "deployment.yaml").read_text())
    self.assertEqual(deployment, {
        "project_id": "demo-proj-123",
        "region": "us-east1",
        "resource_prefix": "cm-demo",
        "scheduler_paused": True,
        "cloudbuild_service_account_emails": ["cm-demo-image-build@demo-proj-123.iam.gserviceaccount.com"],
        "bigquery_dataset_id": "cm_demo",
    })
    self.assertEqual(yaml.safe_load((gcp / "repos.yaml").read_text()), {"repositories": None})
    tfvars = (self.root / "terraform" / "bootstrap" / "terraform.tfvars").read_text()
    self.assertIn('approvers = ["group:admins@example.com"]', tfvars)
    self.assertIn('resource_prefix = "cm-demo"', tfvars)
    self.assertIn('cloudbuild_repository = ""', tfvars)

  def test_dataset_is_optional(self):
    code, _ = self._init(bigquery_dataset=None)
    self.assertEqual(code, common.EXIT_OK)
    text = (self.root / "terraform" / "gcp" / "deployment.yaml").read_text()
    self.assertNotIn("bigquery_dataset_id", text)

  def test_refuses_to_overwrite_without_force_and_keeps_connection(self):
    self._init()
    tfvars = self.root / "terraform" / "bootstrap" / "terraform.tfvars"
    conn = "projects/p/locations/us-east1/connections/c/repositories/r"
    tfvars.write_text(config_edit.set_tfvar(tfvars.read_text(), "cloudbuild_repository", f'"{conn}"'))
    code, ctx = self._init()
    self.assertEqual(code, common.EXIT_FAILED)
    self.assertIn("Already present", ctx.out.getvalue())
    code, _ = self._init(force=True, prefix="cm-two")
    self.assertEqual(code, common.EXIT_OK)
    self.assertIn(conn, tfvars.read_text())
    self.assertIn('"cm-two"', tfvars.read_text())

  def test_approver_is_required_non_interactive(self):
    ctx = make_context(self.root, non_interactive=True)
    with self.assertRaises(common.UsageError) as cm:
      config_edit.run_init(ctx, Args(**{**INIT_ARGS, "approver": []}))
    self.assertIn("--approver", str(cm.exception))

  def test_invalid_values_are_usage_errors(self):
    ctx = make_context(self.root, non_interactive=True)
    for bad in (dict(prefix="Bad"), dict(prefix="a" * 18), dict(project="X"),
                dict(approver=["admins@example.com"]), dict(bigquery_dataset="has-dash")):
      with self.subTest(bad=bad), self.assertRaises(common.UsageError):
        config_edit.run_init(ctx, Args(**{**INIT_ARGS, **bad}))

  def test_interactive_prompts_retry(self):
    answers = "\n".join(["demo-proj-123", "", "BAD", "cm-x", "", "", "nope", "user:me@example.com"]) + "\n"
    ctx = make_context(self.root, stdin=answers)
    code = config_edit.run_init(ctx, Args())
    self.assertEqual(code, common.EXIT_OK, ctx.out.getvalue())
    deployment = yaml.safe_load((self.root / "terraform" / "gcp" / "deployment.yaml").read_text())
    self.assertEqual(deployment["region"], "us-central1")
    self.assertEqual(deployment["resource_prefix"], "cm-x")
    self.assertIn('"user:me@example.com"', (self.root / "terraform" / "bootstrap" / "terraform.tfvars").read_text())

  def test_dry_run_writes_nothing(self):
    ctx = make_context(self.root, non_interactive=True, dry_run=True)
    code = config_edit.run_init(ctx, Args(**INIT_ARGS))
    self.assertEqual(code, common.EXIT_OK)
    self.assertFalse((self.root / "terraform" / "gcp" / "deployment.yaml").exists())
    self.assertIn("+project_id: \"demo-proj-123\"", ctx.out.getvalue())

  def test_hcl_values_are_escaped(self):
    text = config_edit.render_bootstrap_tfvars("p-123456", "us-east1", "cm", "fix/${x}",
                                               ["group:a%{b}@example.com"], "")
    self.assertIn('branch          = "fix/$${x}"', text)
    self.assertIn('"group:a%%{b}@example.com"', text)


class ReposEditTest(TempDirMixin, unittest.TestCase):

  def setUp(self):
    super().setUp()
    self.root = make_repo(self.tmp)
    self.repos = self.root / "terraform" / "gcp" / "repos.yaml"

  def _ctx(self, **kw):
    return make_context(self.root, non_interactive=True, **kw)

  def test_add_keeps_comments_and_quotes_values(self):
    self.repos.write_text(
        "# my header\n"
        "repositories:\n"
        "    # the first one\n"
        "    first:\n"
        "        repo_url: https://github.com/acme/first.git  # keep me\n"
        "\n"
        "# trailing comment\n")
    code = config_edit.run_add_repo(self._ctx(), Args(
        name="svc", url="https://github.com/acme/svc.git", schedule="0 3 * * 6",
        build_command='make && echo "${HOME}" # not a comment', scan_target="on", scan_dry_run=True))
    self.assertEqual(code, common.EXIT_OK)
    text = self.repos.read_text()
    self.assertIn("# keep me", text)
    self.assertIn("# trailing comment", text)
    self.assertIn("    svc:\n        repo_url:", text)  # follows the existing indent
    self.assertLess(text.index("    svc:"), text.index("# trailing comment"))
    doc = yaml.safe_load(text)
    self.assertEqual(doc["repositories"]["svc"], {
        "repo_url": "https://github.com/acme/svc.git",
        "schedule": "0 3 * * 6",
        "scan_target": "on",
        "build_command": 'make && echo "${HOME}" # not a comment',
        "dry_run": True,
    })
    self.assertEqual(doc["repositories"]["first"]["repo_url"], "https://github.com/acme/first.git")

  def test_add_before_a_following_top_level_key(self):
    self.repos.write_text("repositories:\n  a:\n    repo_url: https://github.com/o/a.git\n\n# other\nextra: 1\n")
    config_edit.run_add_repo(self._ctx(), Args(name="b", url="https://github.com/o/b.git"))
    doc = yaml.safe_load(self.repos.read_text())
    self.assertEqual(list(doc["repositories"]), ["a", "b"])
    self.assertEqual(doc["extra"], 1)

  def test_add_to_empty_and_flow_mapping(self):
    for start in (None, "repositories:\n", "repositories: {}\n"):
      with self.subTest(start=start):
        if start is None:
          if self.repos.exists():
            self.repos.unlink()
        else:
          self.repos.write_text(start)
        config_edit.run_add_repo(self._ctx(), Args(name="a", url="https://github.com/o/a.git"))
        config_edit.run_add_repo(self._ctx(), Args(name="b", url="https://github.com/o/b.git"))
        doc = yaml.safe_load(self.repos.read_text())
        self.assertEqual(list(doc["repositories"]), ["a", "b"])

  def test_add_rejects_duplicates_bad_names_and_urls(self):
    self.repos.write_text("repositories:\n  a:\n    repo_url: https://github.com/o/a.git\n")
    for kw in (dict(name="a", url="https://github.com/o/a.git"),
               dict(name="b c", url="https://github.com/o/b.git"),
               dict(name="b", url="https://acme.ghe.com/o/b.git"),
               dict(name="b", url="https://github.com/o/b.git", schedule="daily")):
      with self.subTest(kw=kw), self.assertRaises(common.UsageError):
        config_edit.run_add_repo(self._ctx(), Args(**kw))

  def test_remove_keeps_neighbours(self):
    self.repos.write_text(
        "repositories:\n"
        "  a:\n"
        "    repo_url: https://github.com/o/a.git\n"
        "    wiz:\n"
        "      enabled: true\n"
        "\n"
        "  # b is important\n"
        "  b:\n"
        "    repo_url: https://github.com/o/b.git\n"
        "other_key: 1\n")
    code = config_edit.run_remove_repo(self._ctx(yes=True), Args(name="a"))
    self.assertEqual(code, common.EXIT_OK)
    text = self.repos.read_text()
    self.assertIn("# b is important", text)
    self.assertEqual(yaml.safe_load(text), {"repositories": {"b": {"repo_url": "https://github.com/o/b.git"}},
                                            "other_key": 1})
    config_edit.run_remove_repo(self._ctx(yes=True), Args(name="b"))
    self.assertEqual(yaml.safe_load(self.repos.read_text()), {"repositories": None, "other_key": 1})

  def test_remove_unknown_and_declined(self):
    self.repos.write_text("repositories:\n  a:\n    repo_url: https://github.com/o/a.git\n")
    with self.assertRaises(common.UsageError):
      config_edit.run_remove_repo(self._ctx(yes=True), Args(name="zzz"))
    ctx = make_context(self.root, stdin="n\n")
    with self.assertRaises(common.Cancelled):
      config_edit.run_remove_repo(ctx, Args(name="a"))
    self.assertIn("a:", self.repos.read_text())


class SetTest(TempDirMixin, unittest.TestCase):

  def setUp(self):
    super().setUp()
    self.root = make_repo(self.tmp)
    self.path = self.root / "terraform" / "gcp" / "deployment.yaml"
    self.path.write_text(
        "project_id: p-123456\n"
        "scheduler_paused: true   # flip after the first image\n"
        "cloudbuild_service_account_emails:\n"
        "  - old@p.iam.gserviceaccount.com\n"
        "\n"
        "# telemetry\n"
        "enable_bigquery_telemetry: true\n")

  def _set(self, key, value, **kw):
    ctx = make_context(self.root, non_interactive=True, **kw)
    return config_edit.run_set(ctx, Args(key=key, value=value))

  def test_types_follow_config_tf(self):
    self._set("scheduler_paused", "False")
    self._set("vpc_connector_max_instances", "5")
    self._set("github_app_installation_id", "0123")
    self._set("github_app_id", "true")
    self._set("cloudbuild_service_account_emails", "a@p.iam.gserviceaccount.com, b@p.iam.gserviceaccount.com")
    text = self.path.read_text()
    doc = yaml.safe_load(text)
    self.assertIs(doc["scheduler_paused"], False)
    self.assertEqual(doc["vpc_connector_max_instances"], 5)
    self.assertEqual(doc["github_app_installation_id"], "0123")
    self.assertEqual(doc["github_app_id"], "true")
    self.assertEqual(doc["cloudbuild_service_account_emails"],
                     ["a@p.iam.gserviceaccount.com", "b@p.iam.gserviceaccount.com"])
    self.assertIn("# flip after the first image", text)
    self.assertIn("# telemetry\nenable_bigquery_telemetry: true", text)
    self.assertNotIn("old@p", text)

  def test_bad_values(self):
    for key, value in (("scheduler_paused", "maybe"), ("vpc_connector_max_instances", "x"),
                       ("not_a_key", "1"), ("resource_prefix", "Bad_Prefix")):
      with self.subTest(key=key), self.assertRaises(common.UsageError):
        self._set(key, value, yes=True)

  def test_identity_keys_need_confirmation(self):
    with self.assertRaises(common.Cancelled):
      self._set("project_id", "other-123")
    self.assertEqual(self._set("project_id", "other-123", yes=True), common.EXIT_OK)
    self.assertIn('project_id: "other-123"', self.path.read_text())

  def test_set_top_level_ignores_nested_keys(self):
    text = "a:\n  scheduler_paused: x\n"
    out = config_edit.set_top_level(text, "scheduler_paused", True)
    self.assertEqual(yaml.safe_load(out), {"a": {"scheduler_paused": "x"}, "scheduler_paused": True})


def _git(cwd, *args):
  return subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True, check=True).stdout


@unittest.skipUnless(shutil.which("git"), "git not available")
class PullRequestTest(TempDirMixin, unittest.TestCase):
  """--pr against a real local git repository, a bare origin and a stub gh."""

  def setUp(self):
    super().setUp()
    self.root = make_repo(self.tmp)
    remote = self.tmp / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
    _git(self.root, "init", "-q", "-b", "main")
    _git(self.root, "config", "user.email", "t@example.com")
    _git(self.root, "config", "user.name", "Test")
    _git(self.root, "config", "commit.gpgsign", "false")
    (self.root / ".gitignore").write_text("*.tfvars\n")
    (self.root / "notes.txt").write_text("local\n")
    _git(self.root, "add", "terraform", ".gitignore")
    _git(self.root, "commit", "-q", "-m", "base")
    _git(self.root, "remote", "add", "origin", str(remote))
    self.gh_log = self.tmp / "gh.log"
    gh = self.tmp / "gh"
    gh.write_text(f'#!/bin/sh\necho "$@" >> "{self.gh_log}"\necho https://github.com/o/r/pull/7\n')
    gh.chmod(gh.stat().st_mode | stat.S_IEXEC)
    self.gh = str(gh)

  def _ctx(self):
    tools = {"git": shutil.which("git"), "gh": self.gh}
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1")
    return common.Context(repo_root=self.root, out=io.StringIO(), err=io.StringIO(),
                          stdin=io.StringIO(), non_interactive=True, run=common.run_process,
                          which=tools.get, environ=env)

  def test_init_pr_commits_only_the_yaml_files(self):
    ctx = self._ctx()
    code = config_edit.run_init(ctx, Args(**INIT_ARGS, pr=True))
    self.assertEqual(code, common.EXIT_OK, ctx.out.getvalue())
    self.assertEqual(_git(self.root, "rev-parse", "--abbrev-ref", "HEAD").strip(), "main")
    branches = _git(self.root, "branch", "--list", "codemender-setup/*").split()
    self.assertEqual(len(branches), 1)
    branch = branches[0]
    files = _git(self.root, "show", "--name-only", "--format=", branch).split()
    self.assertEqual(sorted(files), ["terraform/gcp/deployment.yaml", "terraform/gcp/repos.yaml"])
    pushed = subprocess.run(["git", f"--git-dir={self.tmp / 'origin.git'}", "branch", "--list"],
                            check=True, capture_output=True, text=True).stdout
    self.assertIn(branch, pushed)
    log = self.gh_log.read_text()
    self.assertIn("pr create", log)
    self.assertIn(f"--head {branch}", log)
    self.assertIn("--base main", log)
    # Local-only files are untouched; the tfvars stays.
    self.assertTrue((self.root / "notes.txt").exists())
    self.assertTrue((self.root / "terraform" / "bootstrap" / "terraform.tfvars").exists())
    self.assertIn("pull/7", ctx.out.getvalue())

  def test_pr_refuses_staged_changes(self):
    (self.root / "notes.txt").write_text("x\n")
    _git(self.root, "add", "notes.txt")
    ctx = self._ctx()
    with self.assertRaises(common.UsageError):
      config_edit.run_init(ctx, Args(**INIT_ARGS, pr=True))

  def _pr_branch(self):
    branches = _git(self.root, "branch", "--list", "codemender-setup/*").split()
    self.assertEqual(len(branches), 1, branches)
    return branches[0]

  def _branch_files(self, branch):
    return sorted(_git(self.root, "show", "--name-only", "--format=", branch).split())

  def test_add_repo_pr_includes_uncommitted_deployment_yaml(self):
    # First setup: init without --pr leaves both YAML files untracked.
    config_edit.run_init(self._ctx(), Args(**INIT_ARGS))
    ctx = self._ctx()
    code = config_edit.run_add_repo(ctx, Args(name="app", url="https://github.com/o/app.git", pr=True))
    self.assertEqual(code, common.EXIT_OK, ctx.out.getvalue())
    branch = self._pr_branch()
    # The pull request must hold both files, or the merge deploys repos.yaml
    # without the deployment settings.
    self.assertEqual(self._branch_files(branch),
                     ["terraform/gcp/deployment.yaml", "terraform/gcp/repos.yaml"])
    repos = _git(self.root, "show", f"{branch}:terraform/gcp/repos.yaml")
    self.assertIn("https://github.com/o/app.git", repos)
    out = ctx.out.getvalue()
    self.assertIn("terraform/gcp/deployment.yaml", out)
    self.assertIn("git pull", out)
    self.assertEqual(_git(self.root, "rev-parse", "--abbrev-ref", "HEAD").strip(), "main")

  def test_set_pr_includes_uncommitted_repos_yaml(self):
    config_edit.run_init(self._ctx(), Args(**INIT_ARGS))
    ctx = self._ctx()
    code = config_edit.run_set(ctx, Args(key="scheduler_paused", value="false", pr=True))
    self.assertEqual(code, common.EXIT_OK, ctx.out.getvalue())
    self.assertEqual(self._branch_files(self._pr_branch()),
                     ["terraform/gcp/deployment.yaml", "terraform/gcp/repos.yaml"])

  def test_pr_with_committed_config_touches_only_the_changed_file(self):
    config_edit.run_init(self._ctx(), Args(**INIT_ARGS))
    _git(self.root, "add", "terraform/gcp/deployment.yaml", "terraform/gcp/repos.yaml")
    _git(self.root, "commit", "-q", "-m", "config")
    ctx = self._ctx()
    code = config_edit.run_add_repo(ctx, Args(name="app", url="https://github.com/o/app.git", pr=True))
    self.assertEqual(code, common.EXIT_OK, ctx.out.getvalue())
    self.assertEqual(self._branch_files(self._pr_branch()), ["terraform/gcp/repos.yaml"])
    # Back on main, both files are as committed: nothing is left untracked
    # that would block the `git pull` after the merge.
    self.assertEqual(_git(self.root, "status", "--porcelain", "--", "terraform/gcp"), "")
    self.assertTrue((self.root / "terraform" / "gcp" / "deployment.yaml").exists())
    self.assertNotIn("git pull", ctx.out.getvalue().split("Opened")[0])

  def test_first_setup_hint_points_to_the_last_edit(self):
    # Rerunning init or secrets with --pr would ship the files early, so the
    # hint must not suggest it while the YAML files are uncommitted.
    ctx = self._ctx()
    config_edit.run_init(ctx, Args(**INIT_ARGS))
    out = ctx.out.getvalue()
    self.assertNotIn("rerun with --pr", out)
    self.assertIn("terraform/gcp/deployment.yaml and terraform/gcp/repos.yaml together in one pull request", out)
    self.assertIn("add --pr to your last edit (typically add-repo)", out)

  def test_hint_after_config_is_committed_does_not_suggest_a_rerun(self):
    config_edit.run_init(self._ctx(), Args(**INIT_ARGS))
    _git(self.root, "add", "terraform/gcp/deployment.yaml", "terraform/gcp/repos.yaml")
    _git(self.root, "commit", "-q", "-m", "config")
    ctx = self._ctx()
    config_edit.run_set(ctx, Args(key="scheduler_paused", value="false"))
    out = ctx.out.getvalue()
    self.assertNotIn("rerun", out)
    self.assertIn("commit terraform/gcp/deployment.yaml in a pull request", out)
    self.assertIn("add --pr to the command", out)
    # A rerun finds the file already changed and opens nothing, so the hint
    # must not point to it.
    rerun = self._ctx()
    code = config_edit.run_set(rerun, Args(key="scheduler_paused", value="false", pr=True))
    self.assertEqual(code, common.EXIT_OK, rerun.out.getvalue())
    self.assertEqual(_git(self.root, "branch", "--list", "codemender-setup/*").strip(), "")

  def test_first_setup_hint_with_one_uncommitted_file(self):
    config_edit.run_init(self._ctx(), Args(**INIT_ARGS))
    _git(self.root, "add", "terraform/gcp/deployment.yaml")
    _git(self.root, "commit", "-q", "-m", "deployment")
    ctx = self._ctx()
    config_edit.run_add_repo(ctx, Args(name="app", url="https://github.com/o/app.git"))
    out = ctx.out.getvalue()
    self.assertIn("commit terraform/gcp/repos.yaml in a pull request, or add --pr to your last edit", out)
    self.assertNotIn("together", out)
    self.assertNotIn("puts both", out)

  def test_pr_body_names_the_added_config(self):
    config_edit.run_init(self._ctx(), Args(**INIT_ARGS))
    ctx = self._ctx()
    config_edit.run_add_repo(ctx, Args(name="app", url="https://github.com/o/app.git", pr=True))
    message = _git(self.root, "log", "-1", "--format=%B", self._pr_branch())
    self.assertIn("Also adds terraform/gcp/deployment.yaml, which was not committed yet.", message)
    self.assertIn("Also adds terraform/gcp/deployment.yaml", self.gh_log.read_text())

  def test_long_title_branch_has_no_double_hyphen(self):
    config_edit.run_init(self._ctx(), Args(**INIT_ARGS))
    _git(self.root, "add", "terraform/gcp/deployment.yaml", "terraform/gcp/repos.yaml")
    _git(self.root, "commit", "-q", "-m", "config")
    ctx = self._ctx()
    code = config_edit.run_set(ctx, Args(key="bigquery_delete_contents_on_destroy", value="true", pr=True))
    self.assertEqual(code, common.EXIT_OK, ctx.out.getvalue())
    branch = self._pr_branch()
    self.assertNotIn("--", branch)
    self.assertRegex(branch, r"^codemender-setup/[a-z0-9-]*[a-z0-9]-\d{8}-\d{6}$")


if __name__ == "__main__":
  unittest.main()
