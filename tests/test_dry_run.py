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

"""Tests for CODEMENDER_DRY_RUN: no GitHub writes, no remote duplicate checks."""

from contextlib import closing
import json
import os
import sqlite3
import tempfile
import unittest
from unittest import mock

import yaml

import orchestrator
from codemender_agent.config import OrchestratorConfig
from codemender_agent.config import PR_MODE_REVIEW_SUGGESTION
from codemender_agent.runners import scan
from codemender_agent.runners import sequential
from codemender_agent.runners import worker
from codemender_agent.utils import is_dry_run
from codemender_agent.vcs import git as vcs_git
from codemender_agent.vcs import github

# A token that is not the "fake-token" test sentinel, so the helpers' own mock
# short-circuits cannot hide a missing dry-run guard.
_TOKEN = "ghs_notarealtoken"
_DRY = {"CODEMENDER_DRY_RUN": "true"}


class IsDryRunTest(unittest.TestCase):

  def test_enabled_values(self):
    for value in ("true", "TRUE", " True ", "1", "yes", "on"):
      with self.subTest(value=value):
        with mock.patch.dict(os.environ, {"CODEMENDER_DRY_RUN": value}):
          self.assertTrue(is_dry_run())

  def test_disabled_values(self):
    for value in ("", " ", "false", "0", "no", "off", "maybe"):
      with self.subTest(value=value):
        with mock.patch.dict(os.environ, {"CODEMENDER_DRY_RUN": value}):
          self.assertFalse(is_dry_run())

  def test_unset_is_disabled(self):
    with mock.patch.dict(os.environ, {}, clear=True):
      self.assertFalse(is_dry_run())

  def test_config_mirrors_env(self):
    with mock.patch.dict(os.environ, {}, clear=True):
      self.assertFalse(OrchestratorConfig.from_env().dry_run)
    with mock.patch.dict(os.environ, _DRY, clear=True):
      self.assertTrue(OrchestratorConfig.from_env().dry_run)
    self.assertFalse(OrchestratorConfig().dry_run)


class GitHubHelpersDryRunTest(unittest.TestCase):
  """Every GitHub write or remote dedup lookup is skipped in a dry run."""

  def setUp(self):
    self.env = mock.patch.dict(os.environ, _DRY)
    self.env.start()
    self.addCleanup(self.env.stop)
    self.http = {}
    for verb in ("get", "post", "patch", "put", "delete"):
      patcher = mock.patch(f"requests.{verb}")
      self.http[verb] = patcher.start()
      self.addCleanup(patcher.stop)
    patcher = mock.patch("requests.Session")
    self.http["session"] = patcher.start()
    self.addCleanup(patcher.stop)
    patcher = mock.patch("codemender_agent.vcs.github.run_command")
    self.run_command = patcher.start()
    self.addCleanup(patcher.stop)

  def tearDown(self):
    for name, m in self.http.items():
      self.assertFalse(m.called, f"requests.{name} was called in a dry run")
    self.assertFalse(self.run_command.called, "git was called in a dry run")

  def test_create_pull_request(self):
    self.assertIsNone(
        github.create_pull_request(_TOKEN, "o", "r", "t", "b", "head", "main")
    )

  def test_create_pr_comment(self):
    self.assertIsNone(github.create_pr_comment(_TOKEN, "o", "r", 7, "body"))

  def test_post_commit_status(self):
    self.assertFalse(
        github.post_commit_status(_TOKEN, "o", "r", "a" * 40, "success", "d")
    )

  def test_suggestion_review(self):
    comment = github.build_review_comment("a.py", 1, 1, "x")
    self.assertIsNone(
        github.create_pr_review_with_suggestions(
            _TOKEN, "o", "r", 7, "sha", "body", [comment]
        )
    )

  def test_sticky_comment(self):
    self.assertIsNone(
        github.post_or_update_sticky_comment(_TOKEN, "o", "r", 7, "body")
    )

  def test_update_finding_in_sticky_comment(self):
    self.assertFalse(
        github.update_finding_in_sticky_comment(
            _TOKEN, "o", "r", 7, "fid12345", "FIXED"
        )
    )

  def test_resolve_sticky_comment_if_present(self):
    self.assertFalse(
        github.resolve_sticky_comment_if_present(_TOKEN, "o", "r", 7, "a" * 40)
    )

  def test_post_idempotent_inline_review(self):
    comment = github.build_review_comment("a.py", 1, 1, "x")
    self.assertFalse(
        github.post_idempotent_inline_review(
            _TOKEN, "o", "r", 7, "a" * 40, "fid12345", comment, "summary"
        )
    )

  def test_sarif_upload(self):
    with tempfile.NamedTemporaryFile("w", suffix=".sarif") as f:
      f.write('{"runs": []}')
      f.flush()
      self.assertIsNone(
          github.upload_sarif_to_code_scanning(
              _TOKEN, "o", "r", f.name, "a" * 40, "refs/heads/main"
          )
      )

  def test_delete_remote_branch(self):
    self.assertFalse(
        github.delete_remote_branch(
            "https://github.com/o/r.git", _TOKEN, "codemender/fix-x"
        )
    )

  def test_remote_duplicate_checks_are_skipped(self):
    url = "https://github.com/o/r.git"
    self.assertFalse(github.check_remote_branch_exists(url, _TOKEN, "b"))
    self.assertFalse(github.is_duplicate_pr(url, _TOKEN, "a.py", "XSS", 3))
    self.assertEqual(github.list_reviewed_finding_ids(_TOKEN, "o", "r", 7), set())


class GitHubHelpersWithoutDryRunTest(unittest.TestCase):
  """Unset or false CODEMENDER_DRY_RUN leaves the helpers untouched."""

  @mock.patch("requests.post")
  def test_create_pull_request_still_posts(self, mock_post):
    mock_post.return_value = mock.MagicMock(
        status_code=201, json=lambda: {"html_url": "https://x/pull/1"}
    )
    for env in ({}, {"CODEMENDER_DRY_RUN": "false"}):
      with self.subTest(env=env):
        mock_post.reset_mock()
        with mock.patch.dict(os.environ, env, clear=True):
          self.assertEqual(
              github.create_pull_request(_TOKEN, "o", "r", "t", "b", "h", "m"),
              "https://x/pull/1",
          )
        mock_post.assert_called_once()

  @mock.patch("codemender_agent.vcs.github._get_branch_via_api")
  def test_branch_check_still_queries(self, mock_api):
    mock_api.return_value = True
    with mock.patch.dict(os.environ, {}, clear=True):
      self.assertTrue(
          github.check_remote_branch_exists("https://github.com/o/r.git", _TOKEN, "b")
      )
    mock_api.assert_called_once()


class PushBranchDryRunTest(unittest.TestCase):

  @mock.patch("codemender_agent.utils.run_command")
  def test_push_is_skipped(self, mock_run):
    with mock.patch.dict(os.environ, _DRY):
      vcs_git.push_branch_to_remote("/tmp/repo", _TOKEN, "codemender/fix-x")
    mock_run.assert_not_called()

  @mock.patch("codemender_agent.utils.run_command")
  def test_push_runs_without_dry_run(self, mock_run):
    with mock.patch.dict(os.environ, {}, clear=True):
      vcs_git.push_branch_to_remote("/tmp/repo", _TOKEN, "codemender/fix-x")
    mock_run.assert_called_once()
    self.assertIn("push", mock_run.call_args[0][0])


class FilterFindingsDryRunTest(unittest.TestCase):

  _FINDINGS = [
      {"FindingID": "f1", "VulnType": "XSS", "FilePath": "a.py", "StartLine": 3},
      {"FindingID": "f2", "VulnType": "SQLI", "FilePath": "b.py", "StartLine": 9},
  ]

  @mock.patch("codemender_agent.runners.scan.delete_remote_branch")
  @mock.patch("codemender_agent.runners.scan.is_duplicate_pr")
  @mock.patch("codemender_agent.runners.scan.check_remote_branch_exists")
  def test_dry_run_keeps_every_open_finding(self, mock_branch, mock_pr, mock_del):
    mock_branch.return_value = True
    mock_pr.return_value = "https://github.com/o/r/pull/1"
    active, skipped, ignored = scan._filter_findings(
        [dict(f) for f in self._FINDINGS],
        "https://github.com/o/r.git",
        _TOKEN,
        "/tmp/repo",
        force_overwrite=False,
        dry_run=True,
    )
    self.assertEqual([f["FindingID"] for f in active], ["f1", "f2"])
    self.assertEqual((skipped, ignored), ([], []))
    mock_branch.assert_not_called()
    mock_pr.assert_not_called()
    mock_del.assert_not_called()

  @mock.patch("codemender_agent.runners.scan.delete_remote_branch")
  @mock.patch("codemender_agent.runners.scan.is_duplicate_pr")
  @mock.patch("codemender_agent.runners.scan.check_remote_branch_exists")
  def test_default_still_deduplicates(self, mock_branch, mock_pr, _mock_del):
    mock_branch.return_value = True
    mock_pr.return_value = "https://github.com/o/r/pull/1"
    active, skipped, _ = scan._filter_findings(
        [dict(f) for f in self._FINDINGS],
        "https://github.com/o/r.git",
        _TOKEN,
        "/tmp/repo",
        force_overwrite=False,
    )
    self.assertEqual(active, [])
    self.assertEqual(skipped, ["f1", "f2"])


class _WorkerCase(unittest.TestCase):
  """Runs _process_finding with every GitHub-facing helper mocked."""

  def setUp(self):
    self.tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self.tmp.cleanup)
    self.repo_dir = os.path.join(self.tmp.name, "repo")
    os.makedirs(self.repo_dir)
    self.db = os.path.join(self.tmp.name, "state.db")
    with closing(sqlite3.connect(self.db)) as conn:
      conn.execute(
          "CREATE TABLE findings (finding_id TEXT PRIMARY KEY, status TEXT,"
          " verified INTEGER, muted INTEGER, mute_reason TEXT)"
      )
      conn.execute("INSERT INTO findings VALUES ('fid-1', 'FIXED', 1, 0, NULL)")
      conn.execute(
          "CREATE TABLE patches (finding_id TEXT, edited_files TEXT,"
          " target_file TEXT, diff TEXT)"
      )
      conn.execute(
          "INSERT INTO patches VALUES ('fid-1', NULL, 'app.py', '--- a\n+++ b')"
      )
      conn.commit()
    self.mocks = {}
    for name in (
        "check_remote_branch_exists",
        "is_duplicate_pr",
        "push_branch_to_remote",
        "create_pull_request",
        "delete_remote_branch",
        "create_pr_comment",
        "create_pr_review_with_suggestions",
        "is_finding_verified",
        "get_finding_status",
        "run_command",
        "get_cm_default_model",
    ):
      patcher = mock.patch(f"codemender_agent.runners.worker.{name}")
      self.mocks[name] = patcher.start()
      self.addCleanup(patcher.stop)
    # Truthy duplicate answers: a dry run must not even ask.
    self.mocks["check_remote_branch_exists"].return_value = True
    self.mocks["is_duplicate_pr"].return_value = "https://github.com/o/r/pull/9"
    self.mocks["is_finding_verified"].return_value = True
    self.mocks["get_finding_status"].return_value = "FIXED"
    self.mocks["create_pull_request"].return_value = "https://github.com/o/r/pull/1"
    self.mocks["get_cm_default_model"].return_value = None

    def run_cmd(cmd, *_args, **_kwargs):
      res = mock.MagicMock(returncode=0, stdout="", token_usage=None)
      if cmd[:2] == ["git", "status"]:
        res.stdout = " M app.py"
      return res

    self.mocks["run_command"].side_effect = run_cmd

  def _process(self, **config_kwargs):
    config = OrchestratorConfig(
        workspace_dir=self.tmp.name,
        repo_url="https://github.com/o/r.git",
        github_token=_TOKEN,
        target_sha="abc123",
        skip_verify=False,
        **config_kwargs,
    )
    return worker._process_finding(
        finding_id="fid-1",
        finding={
            "FindingID": "fid-1",
            "VulnType": "XSS",
            "FilePath": "app.py",
            "StartLine": 4,
        },
        repo_dir=self.repo_dir,
        cm_binary="/bin/cm",
        scrubbed_env={},
        clean_repo_url="https://github.com/o/r.git",
        token=_TOKEN,
        owner="o",
        repo_name="r",
        default_branch="main",
        working_base_ref="abc123",
        state_db_path=self.db,
        worker_token_usage={},
        config=config,
    )

  def _commands(self):
    return [c[0][0] for c in self.mocks["run_command"].call_args_list]

  def _status(self):
    with closing(sqlite3.connect(self.db)) as conn:
      return conn.execute(
          "SELECT status FROM findings WHERE finding_id = 'fid-1'"
      ).fetchone()[0]


class WorkerDryRunTest(_WorkerCase):

  def _assert_no_github(self):
    for name in (
        "check_remote_branch_exists",
        "is_duplicate_pr",
        "push_branch_to_remote",
        "create_pull_request",
        "delete_remote_branch",
        "create_pr_comment",
        "create_pr_review_with_suggestions",
    ):
      self.mocks[name].assert_not_called()

  def test_nightly_scan_verifies_and_fixes_but_opens_nothing(self):
    self.assertIsNone(self._process(dry_run=True))
    self._assert_no_github()
    commands = [" ".join(c) for c in self._commands()]
    self.assertTrue(any(" verify " in f" {c} " for c in commands))
    self.assertTrue(any(" fix " in f" {c} " for c in commands))
    # The fix stays recorded as FIXED; a dry run is not a routing failure.
    self.assertEqual(self._status(), "FIXED")
    # The workspace is reset afterwards.
    self.assertEqual(self._commands()[-1][:3], ["git", "checkout", "-f"])

  def test_pr_suggestion_mode_posts_no_review(self):
    self.assertIsNone(
        self._process(
            dry_run=True,
            is_pr_scan=True,
            pr_number=7,
            pr_remediation_mode=PR_MODE_REVIEW_SUGGESTION,
        )
    )
    self._assert_no_github()

  def test_fork_pr_posts_no_comment(self):
    self.assertIsNone(
        self._process(dry_run=True, is_pr_scan=True, is_fork_pr=True, pr_number=7)
    )
    self._assert_no_github()

  def test_without_dry_run_duplicates_are_skipped(self):
    self.assertIsNone(self._process())
    self.mocks["check_remote_branch_exists"].assert_called_once()
    self.mocks["push_branch_to_remote"].assert_not_called()

  def test_without_dry_run_the_pr_is_opened(self):
    self.mocks["check_remote_branch_exists"].return_value = False
    self.mocks["is_duplicate_pr"].return_value = False
    self.assertEqual(self._process(), "https://github.com/o/r/pull/1")
    self.mocks["check_remote_branch_exists"].assert_called_once()
    self.mocks["push_branch_to_remote"].assert_called_once()
    self.mocks["create_pull_request"].assert_called_once()


class SequentialDryRunTest(unittest.TestCase):

  def setUp(self):
    self.tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self.tmp.cleanup)
    os.makedirs(os.path.join(self.tmp.name, "r", ".git"))
    self.env = mock.patch.dict(
        os.environ,
        {
            "HOME": self.tmp.name,
            "WORKSPACE_DIR": self.tmp.name,
            "CODEMENDER_SKIP_VERIFY": "true",
        },
    )
    self.env.start()
    self.addCleanup(self.env.stop)
    self.mocks = {}
    for name in (
        "run_command",
        "get_github_credentials",
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
      patcher = mock.patch(f"codemender_agent.runners.sequential.{name}")
      self.mocks[name] = patcher.start()
      self.addCleanup(patcher.stop)
    self.mocks["get_github_credentials"].return_value = (
        "https://github.com/o/r.git",
        _TOKEN,
    )
    self.mocks["ensure_cm_updated"].return_value = "/bin/cm"
    self.mocks["get_cm_default_model"].return_value = None
    self.mocks["get_scrubbed_env"].return_value = {}
    self.mocks["get_finding_status"].return_value = "FIXED"
    self.mocks["create_pull_request"].return_value = "https://github.com/o/r/pull/1"

    report = json.dumps([
        {"FindingID": "fid-1", "VulnType": "XSS", "FilePath": "a.py", "StartLine": 2}
    ])

    def run_cmd(cmd, *_args, **_kwargs):
      res = mock.MagicMock(returncode=0, stdout="", token_usage=None)
      joined = " ".join(cmd)
      if cmd[:3] == ["git", "branch", "--show-current"]:
        res.stdout = "main\n"
      elif "report" in joined and "json" in joined:
        res.stdout = report
      elif cmd[:2] == ["git", "status"]:
        res.stdout = " M a.py"
      return res

    self.mocks["run_command"].side_effect = run_cmd

  def _pushes(self):
    return [
        c[0][0]
        for c in self.mocks["run_command"].call_args_list
        if "push" in c[0][0]
    ]

  def test_dry_run_pushes_and_opens_nothing(self):
    with mock.patch.dict(os.environ, _DRY):
      sequential.run_sequential_pipeline()
    self.assertEqual(self._pushes(), [])
    for name in (
        "check_remote_branch_exists",
        "is_duplicate_pr",
        "create_pull_request",
        "delete_remote_branch",
    ):
      self.mocks[name].assert_not_called()

  def test_without_dry_run_pushes_and_opens_pr(self):
    self.mocks["check_remote_branch_exists"].return_value = False
    self.mocks["is_duplicate_pr"].return_value = False
    sequential.run_sequential_pipeline()
    self.assertEqual(len(self._pushes()), 1)
    self.mocks["create_pull_request"].assert_called_once()


class WorkflowDryRunTest(unittest.TestCase):
  """The Cloud Workflows definition forwards dry_run to every job it runs."""

  _WORKFLOW = os.path.join(
      os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
      "workflows",
      "gcp_parallel_workflow.yaml",
  )

  def setUp(self):
    with open(self._WORKFLOW, "r", encoding="utf-8") as f:
      self.workflow = yaml.safe_load(f)

  def _job_envs(self, node, found):
    """Collects the env list of every Cloud Run jobs.run call, recursively."""
    if isinstance(node, dict):
      if node.get("call") == "googleapis.run.v2.projects.locations.jobs.run":
        env = {}
        for override in node["args"]["body"]["overrides"]["containerOverrides"]:
          for entry in override.get("env", []):
            env[entry["name"]] = entry["value"]
        found.append(env)
      for value in node.values():
        self._job_envs(value, found)
    elif isinstance(node, list):
      for value in node:
        self._job_envs(value, found)
    return found

  def test_every_job_run_receives_dry_run(self):
    envs = self._job_envs(self.workflow["main"], [])
    # Stage 1, Stage 2, Stage 3 and the failure finalizer.
    self.assertEqual(len(envs), 4)
    for env in envs:
      with self.subTest(run_mode=env.get("CODEMENDER_RUN_MODE")):
        self.assertEqual(env.get("CODEMENDER_DRY_RUN"), "${string(dry_run)}")

  def test_every_job_run_receives_skip_verify(self):
    # Telemetry derives `verified` from skip_verify, so every stage that can
    # emit it (including the failure finalizer) must see the same value.
    envs = self._job_envs(self.workflow["main"], [])
    self.assertEqual(len(envs), 4)
    for env in envs:
      with self.subTest(run_mode=env.get("CODEMENDER_RUN_MODE"),
                        finalizer=env.get("CODEMENDER_WORKFLOW_FAILED")):
        self.assertEqual(
            env.get("CODEMENDER_SKIP_VERIFY"), "${string(skip_verify)}"
        )

  def test_dry_run_defaults_to_false(self):
    assigns = {}
    for entry in self.workflow["main"]["steps"][0]["init_variables"]["assign"]:
      assigns.update(entry)
    self.assertEqual(
        assigns["dry_run"], '${default(map.get(args, "dry_run"), false)}'
    )


class GitHubActionsWorkflowDryRunTest(unittest.TestCase):
  """The reusable Actions workflow forwards dry_run and gates its SARIF upload.

  The codeql upload-sarif action writes to GitHub outside the Python helpers,
  so CODEMENDER_DRY_RUN alone cannot stop it.
  """

  def setUp(self):
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        ".github",
        "workflows",
        "codemender_parallel.yml",
    )
    with open(path, "r", encoding="utf-8") as f:
      self.pipeline = yaml.safe_load(f)
    # PyYAML parses the bare `on:` key as boolean True.
    triggers = self.pipeline.get("on", self.pipeline.get(True))
    self.inputs = triggers["workflow_call"]["inputs"]

  def test_dry_run_input_defaults_to_false(self):
    self.assertEqual(self.inputs["dry_run"]["type"], "boolean")
    self.assertIs(self.inputs["dry_run"]["default"], False)

  def test_every_stage_receives_dry_run(self):
    stage_steps = [
        (job_name, step)
        for job_name, job in self.pipeline["jobs"].items()
        for step in job.get("steps", [])
        if (step.get("env") or {}).get("CODEMENDER_RUN_MODE")
    ]
    self.assertGreaterEqual(len(stage_steps), 3)
    for job_name, step in stage_steps:
      with self.subTest(job=job_name):
        self.assertEqual(
            step["env"].get("CODEMENDER_DRY_RUN"), "${{ inputs.dry_run }}"
        )

  def test_sarif_upload_steps_skip_in_dry_run(self):
    upload_steps = [
        step
        for job in self.pipeline["jobs"].values()
        for step in job.get("steps", [])
        if "upload-sarif" in str(step.get("uses", ""))
    ]
    self.assertEqual(len(upload_steps), 2)
    for step in upload_steps:
      with self.subTest(step=step["name"]):
        self.assertIn("!inputs.dry_run", step["if"])


class OrchestratorDryRunLogTest(unittest.TestCase):

  @mock.patch("orchestrator.run_scan_pipeline")
  def test_announces_dry_run(self, _mock_scan):
    with mock.patch.dict(os.environ, {"CODEMENDER_RUN_MODE": "scan", **_DRY}):
      with self.assertLogs(level="WARNING") as logs:
        orchestrator.main()
    self.assertTrue(any("CODEMENDER_DRY_RUN" in line for line in logs.output))

  @mock.patch("orchestrator.run_scan_pipeline")
  def test_silent_without_dry_run(self, _mock_scan):
    with mock.patch.dict(os.environ, {"CODEMENDER_RUN_MODE": "scan"}, clear=True):
      with mock.patch("orchestrator.logging.warning") as mock_warn:
        orchestrator.main()
    mock_warn.assert_not_called()


if __name__ == "__main__":
  unittest.main()
