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

"""Unit tests for Stage 2 Worker runner."""

from contextlib import closing
import json
import os
import sqlite3
import subprocess
import tempfile
import unittest
import unittest.mock

from codemender_agent.config import OrchestratorConfig
from codemender_agent.runners.worker import _process_finding
from codemender_agent.runners.worker import run_worker_pipeline


class TestWorkerRunner(unittest.TestCase):

  def setUp(self):
    self.temp_dir = tempfile.TemporaryDirectory()
    self.workspace_dir = self.temp_dir.name

    self.env_patcher = unittest.mock.patch.dict(
        os.environ,
        {
            "HOME": self.workspace_dir,
            "CODEMENDER_WORKER_INDEX": "0",
            "CODEMENDER_BASE_WORKSPACE_URL": "http://signed-url/base.tar.gz",
            "CODEMENDER_PARTITION_URLS": json.dumps(["http://signed-url/partition_0.json"]),
            "CODEMENDER_UPLOAD_URLS": json.dumps(["http://signed-url/upload_0.db"]),
            "CODEMENDER_METADATA_URLS": json.dumps(["http://signed-url/metadata_0.json"]),
            "WORKSPACE_DIR": self.workspace_dir,
            "GITHUB_REPO_URL": "https://github.com/owner/repo.git",
            "GITHUB_TOKEN": "fake-token",
            "CODEMENDER_TARGET_SHA": "abc123commitsha",
            "CODEMENDER_BUILD_COMMAND": "echo 'build'",
        },
    )
    self.env_patcher.start()

  def tearDown(self):
    self.env_patcher.stop()
    self.temp_dir.cleanup()

  @unittest.mock.patch("codemender_agent.runners.worker.run_command")
  @unittest.mock.patch("codemender_agent.runners.worker.download_from_url")
  @unittest.mock.patch("codemender_agent.runners.worker.upload_to_url")
  @unittest.mock.patch("codemender_agent.runners.worker.check_remote_branch_exists")
  @unittest.mock.patch("codemender_agent.runners.worker.push_branch_to_remote")
  @unittest.mock.patch("codemender_agent.runners.worker.create_pull_request")
  @unittest.mock.patch("codemender_agent.runners.worker.is_duplicate_pr")
  @unittest.mock.patch("codemender_agent.runners.worker.is_finding_verified")
  @unittest.mock.patch("codemender_agent.runners.worker.get_finding_status")
  @unittest.mock.patch("tarfile.open")
  @unittest.mock.patch("shutil.which")
  def test_worker_pipeline_success(
      self,
      mock_which,
      _mock_tarfile_open,
      mock_get_finding_status,
      mock_is_finding_verified,
      mock_is_duplicate_pr,
      mock_create_pr,
      mock_push_branch,
      mock_check_remote_branch_exists,
      mock_upload_to_url,
      mock_download_from_url,
      mock_run_cmd,
  ):
    mock_which.return_value = "/bin/cm"
    mock_check_remote_branch_exists.return_value = False
    mock_is_duplicate_pr.return_value = False
    mock_is_finding_verified.return_value = True
    mock_get_finding_status.return_value = "FIXED"
    mock_create_pr.return_value = "https://github.com/org/repo/pull/42"

    def download_side_effect(url, dest_path):
      if "partition" in url:
        with open(dest_path, "w") as f:
          json.dump({"partition_index": 0, "finding_ids": ["fid-1"]}, f)
        return True
      elif "base.tar.gz" in url:
        return True
      return False

    mock_download_from_url.side_effect = download_side_effect
    mock_upload_to_url.return_value = True

    mock_cm_report = unittest.mock.MagicMock()
    mock_cm_report.stdout = json.dumps([
        {
            "FindingID": "fid-1",
            "Status": "DETECTED",
            "VulnType": "SQL_INJECTION",
            "FilePath": "db.py",
            "Title": "SQL Injection in db.py",
            "Severity": "HIGH",
            "Analysis": "Fix it.",
        }
    ])
    mock_cm_report.returncode = 0

    mock_git_status = unittest.mock.MagicMock()
    mock_git_status.stdout = " M db.py"
    mock_git_status.returncode = 0

    mock_default = unittest.mock.MagicMock()
    mock_default.stdout = ""
    mock_default.returncode = 0

    def run_cmd_side_effect(cmd, *_args, **_kwargs):
      cmd_str = " ".join(cmd)
      if "report" in cmd_str:
        return mock_cm_report
      elif "status" in cmd_str:
        return mock_git_status
      else:
        return mock_default

    mock_run_cmd.side_effect = run_cmd_side_effect

    run_worker_pipeline()

    mock_download_from_url.assert_any_call("http://signed-url/base.tar.gz", os.path.join(self.workspace_dir, "workspace_base.tar.gz"))
    mock_download_from_url.assert_any_call("http://signed-url/partition_0.json", os.path.join(self.workspace_dir, "partition_0.json"))

    mock_run_cmd.assert_any_call(["git", "checkout", "-f", "abc123commitsha"], cwd=os.path.join(self.workspace_dir, "repo"))

    verify_called = False
    fix_called = False
    for call in mock_run_cmd.call_args_list:
      cmd = call[0][0]
      cmd_str = " ".join(cmd)
      if "verify" in cmd_str and "fid-1" in cmd_str:
        verify_called = True
      elif "fix" in cmd_str and "fid-1" in cmd_str:
        fix_called = True

    self.assertFalse(verify_called)
    self.assertTrue(fix_called)
    mock_create_pr.assert_called_once()
    mock_upload_to_url.assert_any_call(
        os.path.expanduser("~/.codemender/state.db"),
        "http://signed-url/upload_0.db"
    )
    mock_upload_to_url.assert_any_call(
        os.path.join(self.workspace_dir, "worker_0_metadata.json"),
        "http://signed-url/metadata_0.json",
        content_type="application/json",
    )

    # Verify worker metadata JSON contents
    meta_path = os.path.join(self.workspace_dir, "worker_0_metadata.json")
    with open(meta_path, "r", encoding="utf-8") as f:
      meta_data = json.load(f)
      self.assertEqual(meta_data["worker_index"], 0)
      self.assertIn("finding_prs", meta_data)
      self.assertEqual(
          meta_data["finding_prs"].get("fid-1"),
          "https://github.com/org/repo/pull/42",
      )

  @unittest.mock.patch("codemender_agent.runners.worker.run_command")
  @unittest.mock.patch("codemender_agent.runners.worker.download_from_url")
  @unittest.mock.patch("codemender_agent.runners.worker.upload_to_url")
  @unittest.mock.patch("codemender_agent.runners.worker.check_remote_branch_exists")
  @unittest.mock.patch("codemender_agent.runners.worker.push_branch_to_remote")
  @unittest.mock.patch("codemender_agent.runners.worker.create_pull_request")
  @unittest.mock.patch("codemender_agent.runners.worker.is_duplicate_pr")
  @unittest.mock.patch("codemender_agent.runners.worker.is_finding_verified")
  @unittest.mock.patch("codemender_agent.runners.worker.get_finding_status")
  @unittest.mock.patch("tarfile.open")
  @unittest.mock.patch("shutil.which")
  def test_worker_pipeline_with_verify_enabled(
      self,
      mock_which,
      _mock_tarfile_open,
      mock_get_finding_status,
      mock_is_finding_verified,
      mock_is_duplicate_pr,
      mock_create_pr,
      mock_push_branch,
      mock_check_remote_branch_exists,
      mock_upload_to_url,
      mock_download_from_url,
      mock_run_cmd,
  ):
    """Verify worker pipeline executes 'cm verify' when CODEMENDER_SKIP_VERIFY is false."""
    mock_which.return_value = "/bin/cm"
    mock_check_remote_branch_exists.return_value = False
    mock_is_duplicate_pr.return_value = False
    mock_is_finding_verified.return_value = True
    mock_get_finding_status.return_value = "FIXED"
    mock_create_pr.return_value = "https://github.com/org/repo/pull/42"

    def download_side_effect(url, dest_path):
      if "partition" in url:
        with open(dest_path, "w") as f:
          json.dump({"partition_index": 0, "finding_ids": ["fid-1"]}, f)
        return True
      elif "base.tar.gz" in url:
        return True
      return False

    mock_download_from_url.side_effect = download_side_effect
    mock_upload_to_url.return_value = True

    mock_cm_report = unittest.mock.MagicMock()
    mock_cm_report.stdout = json.dumps([
        {
            "FindingID": "fid-1",
            "Status": "DETECTED",
            "VulnType": "SQL_INJECTION",
            "FilePath": "db.py",
            "Title": "SQL Injection in db.py",
            "Severity": "HIGH",
            "Analysis": "Fix it.",
        }
    ])
    mock_cm_report.returncode = 0

    mock_git_status = unittest.mock.MagicMock()
    mock_git_status.stdout = " M db.py"
    mock_git_status.returncode = 0

    mock_default = unittest.mock.MagicMock()
    mock_default.stdout = ""
    mock_default.returncode = 0

    def run_cmd_side_effect(cmd, *_args, **_kwargs):
      cmd_str = " ".join(cmd)
      if "report" in cmd_str:
        return mock_cm_report
      elif "status" in cmd_str:
        return mock_git_status
      else:
        return mock_default

    mock_run_cmd.side_effect = run_cmd_side_effect

    with unittest.mock.patch.dict(
        os.environ, {"CODEMENDER_SKIP_VERIFY": "false"}
    ):
      run_worker_pipeline()

    verify_called = False
    fix_called = False
    for call in mock_run_cmd.call_args_list:
      cmd = call[0][0]
      cmd_str = " ".join(cmd)
      if "verify" in cmd_str and "fid-1" in cmd_str:
        verify_called = True
      elif "fix" in cmd_str and "fid-1" in cmd_str:
        fix_called = True

    self.assertTrue(verify_called)
    self.assertTrue(fix_called)
    mock_create_pr.assert_called_once()

  @unittest.mock.patch("codemender_agent.runners.worker.run_command")
  @unittest.mock.patch("codemender_agent.runners.worker.download_from_url")
  @unittest.mock.patch("codemender_agent.runners.worker.upload_to_url")
  @unittest.mock.patch("codemender_agent.runners.worker.check_remote_branch_exists")
  @unittest.mock.patch("codemender_agent.runners.worker.create_pull_request")
  @unittest.mock.patch("codemender_agent.runners.worker.is_duplicate_pr")
  @unittest.mock.patch("codemender_agent.runners.worker.is_finding_verified")
  @unittest.mock.patch("codemender_agent.runners.worker.get_finding_status")
  @unittest.mock.patch("tarfile.open")
  @unittest.mock.patch("shutil.which")
  def test_worker_pipeline_idempotency_skip(
      self,
      mock_which,
      _mock_tarfile_open,
      mock_get_finding_status,
      mock_is_finding_verified,
      mock_is_duplicate_pr,
      mock_create_pr,
      mock_check_remote_branch_exists,
      mock_upload_to_url,
      mock_download_from_url,
      mock_run_cmd,
  ):
    del mock_get_finding_status
    mock_which.return_value = "/bin/cm"
    mock_check_remote_branch_exists.return_value = True
    mock_is_duplicate_pr.return_value = False
    mock_is_finding_verified.return_value = False
    mock_create_pr.return_value = True

    def download_side_effect(url, dest_path):
      if "partition" in url:
        with open(dest_path, "w") as f:
          json.dump({"partition_index": 0, "finding_ids": ["fid-1"]}, f)
        return True
      elif "base.tar.gz" in url:
        return True
      return False

    mock_download_from_url.side_effect = download_side_effect
    mock_upload_to_url.return_value = True

    mock_cm_report = unittest.mock.MagicMock()
    mock_cm_report.stdout = json.dumps([
        {
            "FindingID": "fid-1",
            "Status": "DETECTED",
            "VulnType": "SQL_INJECTION",
            "FilePath": "db.py",
            "Title": "SQL Injection in db.py",
            "Severity": "HIGH",
            "Analysis": "Fix it.",
        }
    ])
    mock_cm_report.returncode = 0

    mock_default = unittest.mock.MagicMock()
    mock_default.stdout = ""
    mock_default.returncode = 0

    def run_cmd_side_effect(cmd, *_args, **_kwargs):
      cmd_str = " ".join(cmd)
      if "report" in cmd_str:
        return mock_cm_report
      else:
        return mock_default

    mock_run_cmd.side_effect = run_cmd_side_effect

    run_worker_pipeline()

    mock_check_remote_branch_exists.assert_called_once()
    
    checkout_remote_called = False
    for call in mock_run_cmd.call_args_list:
      cmd = call[0][0]
      if len(cmd) >= 3 and cmd[0] == "git" and cmd[1] == "checkout" and "codemender/fix-" in cmd[2]:
        checkout_remote_called = True
    self.assertFalse(checkout_remote_called)

    fix_called = False
    for call in mock_run_cmd.call_args_list:
      cmd = call[0][0]
      if "fix" in cmd:
        fix_called = True
    self.assertFalse(fix_called)

    mock_create_pr.assert_not_called()
    mock_upload_to_url.assert_any_call(
        os.path.expanduser("~/.codemender/state.db"),
        "http://signed-url/upload_0.db"
    )
    mock_upload_to_url.assert_any_call(
        os.path.join(self.workspace_dir, "worker_0_metadata.json"),
        "http://signed-url/metadata_0.json",
        content_type="application/json",
    )

  @unittest.mock.patch("codemender_agent.runners.worker.run_command")
  @unittest.mock.patch("codemender_agent.runners.worker.download_from_url")
  @unittest.mock.patch("codemender_agent.runners.worker.upload_to_url")
  @unittest.mock.patch("tarfile.open")
  def test_worker_pipeline_metadata_upload(
      self, mock_tarfile_open, mock_upload_to_url, mock_download_from_url, mock_run_command
  ):
    mock_download_from_url.return_value = True
    mock_upload_to_url.return_value = True
    mock_run_command.return_value.returncode = 0
    mock_run_command.return_value.stdout = ""

    # Set up empty partition file dict
    part_file = os.path.join(self.workspace_dir, "partition_0.json")
    with open(part_file, "w") as f:
      json.dump({"finding_ids": []}, f)

    def download_side_effect(url, dest):
      os.makedirs(os.path.dirname(dest), exist_ok=True)
      if dest.endswith(".json"):
        with open(dest, "w") as f:
          json.dump({"finding_ids": []}, f)
      return True

    mock_download_from_url.side_effect = download_side_effect

    with unittest.mock.patch.dict(
        os.environ,
        {
            "CODEMENDER_METADATA_URLS": json.dumps(["http://signed-url/metadata_0.json"]),
        },
    ):
      with self.assertRaises(SystemExit) as cm:
        run_worker_pipeline()
      self.assertEqual(cm.exception.code, 0)

    mock_upload_to_url.assert_any_call(
        os.path.join(self.workspace_dir, "worker_0_metadata.json"),
        "http://signed-url/metadata_0.json",
        content_type="application/json",
    )

  @unittest.mock.patch("codemender_agent.runners.worker.run_command")
  @unittest.mock.patch("codemender_agent.runners.worker.download_from_url")
  @unittest.mock.patch("codemender_agent.runners.worker.upload_to_url")
  @unittest.mock.patch("codemender_agent.runners.worker.check_remote_branch_exists")
  @unittest.mock.patch("codemender_agent.runners.worker.push_branch_to_remote")
  @unittest.mock.patch("codemender_agent.runners.worker.create_pull_request")
  @unittest.mock.patch("codemender_agent.runners.worker.create_pr_comment")
  @unittest.mock.patch("codemender_agent.runners.worker.is_duplicate_pr")
  @unittest.mock.patch("codemender_agent.runners.worker.is_finding_verified")
  @unittest.mock.patch("codemender_agent.runners.worker.get_finding_status")
  @unittest.mock.patch("tarfile.open")
  @unittest.mock.patch("shutil.which")
  def test_worker_pipeline_child_pr_and_fork_comment(
      self,
      mock_which,
      _mock_tarfile_open,
      mock_get_finding_status,
      mock_is_finding_verified,
      mock_is_duplicate_pr,
      mock_create_comment,
      mock_create_pr,
      mock_push_branch,
      mock_check_remote_branch_exists,
      mock_upload_to_url,
      mock_download_from_url,
      mock_run_cmd,
  ):
    """Verify Child PR creation targeting pr_head_ref on internal PRs and review comment on Fork PRs."""
    mock_which.return_value = "/bin/cm"
    mock_check_remote_branch_exists.return_value = False
    mock_is_duplicate_pr.return_value = False
    mock_is_finding_verified.return_value = True
    mock_get_finding_status.return_value = "FIXED"
    # Setup transit partition file
    with open(os.path.join(self.workspace_dir, "partition_0.json"), "w") as f:
      json.dump({"finding_ids": ["fid-1"]}, f)
    transit_shard = os.path.join(self.workspace_dir, ".codemender_transit", "base")
    os.makedirs(transit_shard, exist_ok=True)
    with open(os.path.join(transit_shard, "partition_0.json"), "w") as f:
      json.dump({"finding_ids": ["fid-1"]}, f)

    mock_cm_report = unittest.mock.MagicMock()
    mock_cm_report.stdout = json.dumps([
        {
            "FindingID": "fid-1",
            "Status": "DETECTED",
            "VulnType": "SQL_INJECTION",
            "FilePath": "db.py",
            "Title": "SQL Injection in db.py",
            "Severity": "HIGH",
            "Analysis": "Fix it.",
        }
    ])
    mock_cm_report.returncode = 0

    mock_git_status = unittest.mock.MagicMock()
    mock_git_status.stdout = " M db.py"
    mock_git_status.returncode = 0

    mock_default = unittest.mock.MagicMock()
    mock_default.stdout = ""
    mock_default.returncode = 0

    def run_cmd_side_effect(cmd, *_args, **_kwargs):
      cmd_str = " ".join(cmd)
      if "report" in cmd_str:
        return mock_cm_report
      elif "status" in cmd_str:
        return mock_git_status
      else:
        return mock_default

    mock_run_cmd.side_effect = run_cmd_side_effect

    # 1. Test Internal PR -> Child PR targeting pr_head_ref and linking to Parent PR
    mock_create_pr.return_value = "https://github.com/owner/repo/pull/101"
    with unittest.mock.patch.dict(
        os.environ,
        {
            "CODEMENDER_STORAGE_MODE": "github_actions",
            "CODEMENDER_IS_PR_SCAN": "true",
            "CODEMENDER_PR_HEAD_REF": "feature/payments",
            "CODEMENDER_PR_BASE_REF": "main",
            "CODEMENDER_PR_NUMBER": "42",
        },
    ):
      run_worker_pipeline()

    # Verify Child PR targeted feature/payments as base_branch and referenced Parent PR
    mock_create_pr.assert_called_with(
        token="fake-token",
        owner="owner",
        repo="repo",
        title="fix(security): resolve SQL_INJECTION vulnerability in db.py (Child PR for #42)",
        body=unittest.mock.ANY,
        head_branch=unittest.mock.ANY,
        base_branch="feature/payments",
    )
    self.assertIn(
        "**Parent PR**: #42 (Branch: `feature/payments`)",
        mock_create_pr.call_args.kwargs.get("body"),
    )

    # Verify notification comment posted to Parent PR #42 with Child PR #101 link
    mock_create_comment.assert_called_once()
    self.assertEqual(mock_create_comment.call_args.kwargs.get("pr_number"), 42)
    self.assertIn(
        "https://github.com/owner/repo/pull/101",
        mock_create_comment.call_args.kwargs.get("body"),
    )
    self.assertIn("#101", mock_create_comment.call_args.kwargs.get("body"))

    # 2. Test Fork PR -> Skip Child PR push and post PR comment
    mock_create_pr.reset_mock()
    mock_create_comment.reset_mock()
    with unittest.mock.patch.dict(
        os.environ,
        {
            "CODEMENDER_STORAGE_MODE": "github_actions",
            "CODEMENDER_IS_PR_SCAN": "true",
            "CODEMENDER_IS_FORK_PR": "true",
            "CODEMENDER_PR_NUMBER": "42",
        },
    ):
      run_worker_pipeline()

    mock_create_pr.assert_not_called()
    mock_create_comment.assert_called_once()
    self.assertEqual(mock_create_comment.call_args.kwargs.get("pr_number"), 42)

    # 3. Test Nightly/Mainline Scan (is_pr_scan=False) -> Standard PR without parent link or parent comment
    mock_create_pr.reset_mock()
    mock_create_comment.reset_mock()
    mock_create_pr.return_value = "https://github.com/owner/repo/pull/102"
    with unittest.mock.patch.dict(
        os.environ,
        {
            "CODEMENDER_STORAGE_MODE": "github_actions",
            "CODEMENDER_IS_PR_SCAN": "false",
        },
    ):
      run_worker_pipeline()

    mock_create_pr.assert_called_with(
        token="fake-token",
        owner="owner",
        repo="repo",
        title="fix(security): resolve SQL_INJECTION vulnerability in db.py",
        body=unittest.mock.ANY,
        head_branch=unittest.mock.ANY,
        base_branch="main",
    )
    self.assertNotIn("Parent PR", mock_create_pr.call_args.kwargs.get("body"))
    mock_create_comment.assert_not_called()

  @unittest.mock.patch("codemender_agent.runners.worker.delete_remote_branch")
  @unittest.mock.patch("codemender_agent.runners.worker.run_command")
  @unittest.mock.patch("codemender_agent.runners.worker.download_from_url")
  @unittest.mock.patch("codemender_agent.runners.worker.upload_to_url")
  @unittest.mock.patch("codemender_agent.runners.worker.check_remote_branch_exists")
  @unittest.mock.patch("codemender_agent.runners.worker.push_branch_to_remote")
  @unittest.mock.patch("codemender_agent.runners.worker.create_pull_request")
  @unittest.mock.patch("codemender_agent.runners.worker.is_duplicate_pr")
  @unittest.mock.patch("codemender_agent.runners.worker.is_finding_verified")
  @unittest.mock.patch("codemender_agent.runners.worker.get_finding_status")
  @unittest.mock.patch("tarfile.open")
  @unittest.mock.patch("shutil.which")
  def test_worker_pipeline_pr_creation_failure_rolls_back_branch(
      self,
      mock_which,
      _mock_tarfile_open,
      mock_get_finding_status,
      mock_is_finding_verified,
      mock_is_duplicate_pr,
      mock_create_pr,
      mock_push_branch,
      mock_check_remote_branch_exists,
      mock_upload_to_url,
      mock_download_from_url,
      mock_run_cmd,
      mock_delete_branch,
  ):
    """Verify that worker rolls back and deletes remote branch if PR creation throws or fails."""
    mock_which.return_value = "/bin/cm"
    mock_check_remote_branch_exists.return_value = False
    mock_is_duplicate_pr.return_value = False
    mock_is_finding_verified.return_value = True
    mock_get_finding_status.return_value = "FIXED"
    mock_create_pr.side_effect = RuntimeError("GitHub PR API 500 error")

    def download_side_effect(url, dest_path):
      if "partition" in url:
        with open(dest_path, "w") as f:
          json.dump({"partition_index": 0, "finding_ids": ["fid-1"]}, f)
        return True
      elif "base.tar.gz" in url:
        return True
      return False

    mock_download_from_url.side_effect = download_side_effect
    mock_upload_to_url.return_value = True

    mock_cm_report = unittest.mock.MagicMock()
    mock_cm_report.stdout = json.dumps([
        {
            "FindingID": "fid-1",
            "Status": "DETECTED",
            "VulnType": "SQL_INJECTION",
            "FilePath": "db.py",
            "StartLine": 10,
        }
    ])
    mock_cm_report.returncode = 0

    mock_git_status = unittest.mock.MagicMock()
    mock_git_status.stdout = " M db.py"
    mock_git_status.returncode = 0

    mock_default = unittest.mock.MagicMock()
    mock_default.stdout = ""
    mock_default.returncode = 0

    def run_cmd_side_effect(cmd, *_args, **_kwargs):
      cmd_str = " ".join(cmd)
      if "report" in cmd_str:
        return mock_cm_report
      elif "status" in cmd_str:
        return mock_git_status
      else:
        return mock_default

    mock_run_cmd.side_effect = run_cmd_side_effect

    run_worker_pipeline()

    mock_push_branch.assert_called_once()
    mock_create_pr.assert_called_once()
    mock_delete_branch.assert_called_once()

  @unittest.mock.patch("codemender_agent.runners.worker.run_command")
  @unittest.mock.patch("codemender_agent.runners.worker.check_remote_branch_exists")
  @unittest.mock.patch("codemender_agent.runners.worker.is_duplicate_pr")
  @unittest.mock.patch("codemender_agent.runners.worker.is_finding_verified")
  @unittest.mock.patch("codemender_agent.runners.worker.get_finding_status")
  @unittest.mock.patch("codemender_agent.runners.worker.create_pull_request")
  @unittest.mock.patch("codemender_agent.runners.worker.push_branch_to_remote")
  def test_worker_staging_filters_exploit_files(
      self,
      _mock_push,
      mock_create_pr,
      mock_get_finding_status,
      mock_is_verified,
      mock_is_dup_pr,
      mock_branch_exists,
      mock_run_cmd,
  ):
    """Verify that _process_finding excludes .exploit files and duplicates during git staging."""
    mock_branch_exists.return_value = False
    mock_is_dup_pr.return_value = False
    mock_is_verified.return_value = True
    mock_get_finding_status.return_value = "FIXED"
    mock_create_pr.return_value = "https://github.com/org/repo/pull/1"

    repo_dir = os.path.join(self.workspace_dir, "test_repo")
    os.makedirs(os.path.join(repo_dir, "routes"), exist_ok=True)
    valid_file = os.path.join(repo_dir, "routes", "userProfile.ts")
    with open(valid_file, "w") as f:
      f.write("console.log('fix');")

    exploit_dir = os.path.join(repo_dir, ".exploit")
    os.makedirs(exploit_dir, exist_ok=True)
    exploit_file = os.path.join(exploit_dir, "exploit.sh")
    with open(exploit_file, "w") as f:
      f.write("evil")

    state_db_path = os.path.join(self.workspace_dir, "state.db")
    with closing(sqlite3.connect(state_db_path)) as conn:
      conn.execute(
          "CREATE TABLE findings (finding_id TEXT PRIMARY KEY, status TEXT,"
          " verified INTEGER)"
      )
      conn.execute("INSERT INTO findings VALUES ('fid-1', 'FIXED', 1)")
      conn.execute(
          "CREATE TABLE patches (finding_id TEXT, edited_files TEXT,"
          " target_file TEXT, diff TEXT)"
      )
      edited_files_json = json.dumps([
          valid_file,
          valid_file,
          exploit_file,
          f"/__w/repo/repo/{valid_file}",
          f"/__w/repo/repo/.exploit/exploit.sh",
      ])
      conn.execute(
          "INSERT INTO patches VALUES ('fid-1', ?, 'routes/userProfile.ts',"
          " 'diff')",
          (edited_files_json,),
      )
      conn.commit()

    mock_git_status = unittest.mock.MagicMock()
    mock_git_status.stdout = " M routes/userProfile.ts"
    mock_git_status.returncode = 0

    mock_default = unittest.mock.MagicMock()
    mock_default.stdout = ""
    mock_default.returncode = 0

    def run_cmd_side_effect(cmd, *_args, **_kwargs):
      cmd_str = " ".join(cmd)
      if "status" in cmd_str:
        return mock_git_status
      return mock_default

    mock_run_cmd.side_effect = run_cmd_side_effect

    finding = {
        "FindingID": "fid-1",
        "Status": "DETECTED",
        "VulnType": "SQL_INJECTION",
        "FilePath": "routes/userProfile.ts",
    }
    config = OrchestratorConfig(
        workspace_dir=self.workspace_dir,
        repo_url="https://github.com/org/repo.git",
        github_token="fake-token",
        target_sha="abc123commitsha",
    )

    _process_finding(
        finding_id="fid-1",
        finding=finding,
        repo_dir=repo_dir,
        cm_binary="/bin/cm",
        scrubbed_env={},
        clean_repo_url="https://github.com/org/repo.git",
        token="fake-token",
        owner="org",
        repo_name="repo",
        default_branch="main",
        working_base_ref="abc123commitsha",
        state_db_path=state_db_path,
        worker_token_usage={},
        config=config,
    )

    # Verify git add was called with only routes/userProfile.ts (no duplicates, no .exploit)
    git_add_calls = [
        call[0][0]
        for call in mock_run_cmd.call_args_list
        if call[0][0][:2] == ["git", "add"]
    ]
    self.assertTrue(git_add_calls, "Expected git add call")
    for call in git_add_calls:
      for arg in call[2:]:
        self.assertNotIn(".exploit", arg)
    self.assertEqual(git_add_calls[0], ["git", "add", "routes/userProfile.ts"])

  @unittest.mock.patch("codemender_agent.runners.worker.run_command")
  @unittest.mock.patch("codemender_agent.runners.worker.check_remote_branch_exists")
  @unittest.mock.patch("codemender_agent.runners.worker.is_duplicate_pr")
  @unittest.mock.patch("codemender_agent.runners.worker.is_finding_verified")
  @unittest.mock.patch("codemender_agent.runners.worker.get_finding_status")
  @unittest.mock.patch("codemender_agent.runners.worker.create_pull_request")
  @unittest.mock.patch("codemender_agent.runners.worker.push_branch_to_remote")
  def test_worker_staging_fallback_on_error(
      self,
      _mock_push,
      mock_create_pr,
      mock_get_finding_status,
      mock_is_verified,
      mock_is_dup_pr,
      mock_branch_exists,
      mock_run_cmd,
  ):
    """Verify that staging gracefully falls back to Tier 2 / Tier 3 when Tier 1 throws."""
    mock_branch_exists.return_value = False
    mock_is_dup_pr.return_value = False
    mock_is_verified.return_value = True
    mock_get_finding_status.return_value = "FIXED"
    mock_create_pr.return_value = "https://github.com/org/repo/pull/2"

    repo_dir = os.path.join(self.workspace_dir, "test_repo_fallback")
    os.makedirs(repo_dir, exist_ok=True)
    target_file = os.path.join(repo_dir, "server.js")
    with open(target_file, "w") as f:
      f.write("console.log('server');")

    state_db_path = os.path.join(self.workspace_dir, "state_fallback.db")
    with closing(sqlite3.connect(state_db_path)) as conn:
      conn.execute(
          "CREATE TABLE findings (finding_id TEXT PRIMARY KEY, status TEXT,"
          " verified INTEGER)"
      )
      conn.execute("INSERT INTO findings VALUES ('fid-2', 'FIXED', 1)")
      conn.execute(
          "CREATE TABLE patches (finding_id TEXT, edited_files TEXT,"
          " target_file TEXT, diff TEXT)"
      )
      conn.execute(
          "INSERT INTO patches VALUES ('fid-2', ?, 'server.js', 'diff')",
          (json.dumps([target_file]),),
      )
      conn.commit()

    mock_git_status = unittest.mock.MagicMock()
    mock_git_status.stdout = " M server.js"
    mock_git_status.returncode = 0

    mock_default = unittest.mock.MagicMock()
    mock_default.stdout = ""
    mock_default.returncode = 0

    def run_cmd_side_effect(cmd, *_args, **_kwargs):
      cmd_str = " ".join(cmd)
      if cmd[:3] == ["git", "add", "server.js"] and not getattr(
          run_cmd_side_effect, "tier1_failed", False
      ):
        run_cmd_side_effect.tier1_failed = True
        raise subprocess.CalledProcessError(1, cmd, output="mock error")
      elif "status" in cmd_str:
        return mock_git_status
      return mock_default

    run_cmd_side_effect.tier1_failed = False
    mock_run_cmd.side_effect = run_cmd_side_effect

    finding = {
        "FindingID": "fid-2",
        "Status": "DETECTED",
        "VulnType": "XSS",
        "FilePath": "server.js",
    }
    config = OrchestratorConfig(
        workspace_dir=self.workspace_dir,
        repo_url="https://github.com/org/repo.git",
        github_token="fake-token",
        target_sha="abc123commitsha",
    )

    # Should not raise exception even when Tier 1 git add fails
    _process_finding(
        finding_id="fid-2",
        finding=finding,
        repo_dir=repo_dir,
        cm_binary="/bin/cm",
        scrubbed_env={},
        clean_repo_url="https://github.com/org/repo.git",
        token="fake-token",
        owner="org",
        repo_name="repo",
        default_branch="main",
        working_base_ref="abc123commitsha",
        state_db_path=state_db_path,
        worker_token_usage={},
        config=config,
    )

    mock_create_pr.assert_called_once()

  @unittest.mock.patch("codemender_agent.runners.worker.run_command")
  @unittest.mock.patch("codemender_agent.runners.worker.check_remote_branch_exists")
  @unittest.mock.patch("codemender_agent.runners.worker.is_duplicate_pr")
  @unittest.mock.patch("codemender_agent.runners.worker.is_finding_verified")
  @unittest.mock.patch("codemender_agent.runners.worker.get_finding_status")
  @unittest.mock.patch("codemender_agent.runners.worker.create_pull_request")
  @unittest.mock.patch("codemender_agent.runners.worker.push_branch_to_remote")
  def test_process_finding_skips_verify_when_configured(
      self,
      _mock_push,
      mock_create_pr,
      mock_get_finding_status,
      mock_is_verified,
      mock_is_dup_pr,
      mock_branch_exists,
      mock_run_cmd,
  ):
    """Verify _process_finding skips cm verify completely when skip_verify=True."""
    mock_branch_exists.return_value = False
    mock_is_dup_pr.return_value = False
    mock_is_verified.return_value = True
    mock_get_finding_status.return_value = "FIXED"
    mock_create_pr.return_value = "https://github.com/org/repo/pull/10"

    repo_dir = os.path.join(self.workspace_dir, "test_repo_skip_verify")
    os.makedirs(repo_dir, exist_ok=True)
    state_db_path = os.path.join(self.workspace_dir, "state_skip_verify.db")
    with closing(sqlite3.connect(state_db_path)) as conn:
      conn.execute(
          "CREATE TABLE findings (finding_id TEXT PRIMARY KEY, status TEXT, verified INTEGER)"
      )
      conn.execute("INSERT INTO findings VALUES ('fid-skip', 'FIXED', 0)")
      conn.execute(
          "CREATE TABLE patches (finding_id TEXT, edited_files TEXT, target_file TEXT, diff TEXT)"
      )
      conn.commit()

    mock_default = unittest.mock.MagicMock()
    mock_default.stdout = ""
    mock_default.returncode = 0
    mock_run_cmd.return_value = mock_default

    finding = {
        "FindingID": "fid-skip",
        "Status": "DETECTED",
        "VulnType": "XSS",
        "FilePath": "app.js",
    }
    config = OrchestratorConfig(
        workspace_dir=self.workspace_dir,
        repo_url="https://github.com/org/repo.git",
        github_token="fake-token",
        target_sha="abc123commitsha",
        skip_verify=True,
    )

    _process_finding(
        finding_id="fid-skip",
        finding=finding,
        repo_dir=repo_dir,
        cm_binary="/bin/cm",
        scrubbed_env={},
        clean_repo_url="https://github.com/org/repo.git",
        token="fake-token",
        owner="org",
        repo_name="repo",
        default_branch="main",
        working_base_ref="abc123commitsha",
        state_db_path=state_db_path,
        worker_token_usage={},
        config=config,
    )

    verify_calls = [
        call[0][0]
        for call in mock_run_cmd.call_args_list
        if "verify" in " ".join(call[0][0])
    ]
    self.assertEqual(len(verify_calls), 0)

  @unittest.mock.patch("codemender_agent.runners.worker.run_command")
  @unittest.mock.patch("codemender_agent.runners.worker.check_remote_branch_exists")
  @unittest.mock.patch("codemender_agent.runners.worker.is_duplicate_pr")
  @unittest.mock.patch("codemender_agent.runners.worker.is_finding_verified")
  @unittest.mock.patch("codemender_agent.runners.worker.get_finding_status")
  @unittest.mock.patch("codemender_agent.runners.worker.create_pull_request")
  @unittest.mock.patch("codemender_agent.runners.worker.push_branch_to_remote")
  def test_process_finding_runs_verify_when_skip_verify_false(
      self,
      _mock_push,
      mock_create_pr,
      mock_get_finding_status,
      mock_is_verified,
      mock_is_dup_pr,
      mock_branch_exists,
      mock_run_cmd,
  ):
    """Verify _process_finding executes cm verify when skip_verify=False."""
    mock_branch_exists.return_value = False
    mock_is_dup_pr.return_value = False
    mock_is_verified.return_value = True
    mock_get_finding_status.return_value = "FIXED"
    mock_create_pr.return_value = "https://github.com/org/repo/pull/11"

    repo_dir = os.path.join(self.workspace_dir, "test_repo_run_verify")
    os.makedirs(repo_dir, exist_ok=True)
    state_db_path = os.path.join(self.workspace_dir, "state_run_verify.db")
    with closing(sqlite3.connect(state_db_path)) as conn:
      conn.execute(
          "CREATE TABLE findings (finding_id TEXT PRIMARY KEY, status TEXT, verified INTEGER)"
      )
      conn.execute("INSERT INTO findings VALUES ('fid-run', 'FIXED', 1)")
      conn.execute(
          "CREATE TABLE patches (finding_id TEXT, edited_files TEXT, target_file TEXT, diff TEXT)"
      )
      conn.commit()

    mock_default = unittest.mock.MagicMock()
    mock_default.stdout = ""
    mock_default.returncode = 0
    mock_run_cmd.return_value = mock_default

    finding = {
        "FindingID": "fid-run",
        "Status": "DETECTED",
        "VulnType": "XSS",
        "FilePath": "app.js",
    }
    config = OrchestratorConfig(
        workspace_dir=self.workspace_dir,
        repo_url="https://github.com/org/repo.git",
        github_token="fake-token",
        target_sha="abc123commitsha",
        skip_verify=False,
    )

    _process_finding(
        finding_id="fid-run",
        finding=finding,
        repo_dir=repo_dir,
        cm_binary="/bin/cm",
        scrubbed_env={},
        clean_repo_url="https://github.com/org/repo.git",
        token="fake-token",
        owner="org",
        repo_name="repo",
        default_branch="main",
        working_base_ref="abc123commitsha",
        state_db_path=state_db_path,
        worker_token_usage={},
        config=config,
    )

    verify_calls = [
        call[0][0]
        for call in mock_run_cmd.call_args_list
        if "verify" in " ".join(call[0][0])
    ]
    self.assertGreater(len(verify_calls), 0)

  @unittest.mock.patch("codemender_agent.config.get_installation_token")
  @unittest.mock.patch("codemender_agent.runners.worker.get_default_branch")
  @unittest.mock.patch("codemender_agent.runners.worker.run_command")
  @unittest.mock.patch("codemender_agent.runners.worker.download_from_url")
  @unittest.mock.patch("codemender_agent.runners.worker.upload_to_url")
  @unittest.mock.patch("codemender_agent.runners.worker.check_remote_branch_exists")
  @unittest.mock.patch("codemender_agent.runners.worker.push_branch_to_remote")
  @unittest.mock.patch("codemender_agent.runners.worker.create_pull_request")
  @unittest.mock.patch("codemender_agent.runners.worker.is_duplicate_pr")
  @unittest.mock.patch("codemender_agent.runners.worker.is_finding_verified")
  @unittest.mock.patch("codemender_agent.runners.worker.get_finding_status")
  @unittest.mock.patch("tarfile.open")
  @unittest.mock.patch("shutil.which")
  def test_worker_pipeline_refreshes_github_app_token_before_routing(
      self,
      mock_which,
      _mock_tarfile_open,
      mock_get_finding_status,
      mock_is_finding_verified,
      mock_is_duplicate_pr,
      mock_create_pr,
      mock_push_branch,
      mock_check_remote_branch_exists,
      mock_upload_to_url,
      mock_download_from_url,
      mock_run_cmd,
      mock_get_default_branch,
      mock_mint,
  ):
    """With a GitHub App, push and PR creation use the token read after the fix."""
    os.environ.pop("GITHUB_TOKEN", None)
    os.environ["GITHUB_APP_ID"] = "12345"
    os.environ["GITHUB_APP_PRIVATE_KEY"] = (
        "-----BEGIN RSA PRIVATE KEY-----\nunused\n-----END RSA PRIVATE KEY-----"
    )
    os.environ["GITHUB_APP_INSTALLATION_ID"] = "77"
    minted = iter(f"ghs_token_{i}" for i in range(1, 10))
    mock_mint.side_effect = lambda *_args: next(minted)

    mock_which.return_value = "/bin/cm"
    mock_get_default_branch.return_value = "main"
    mock_check_remote_branch_exists.return_value = False
    mock_is_duplicate_pr.return_value = False
    mock_is_finding_verified.return_value = True
    mock_get_finding_status.return_value = "FIXED"
    mock_create_pr.return_value = "https://github.com/owner/repo/pull/7"

    def download_side_effect(url, dest_path):
      if "partition" in url:
        with open(dest_path, "w") as f:
          json.dump({"partition_index": 0, "finding_ids": ["fid-1"]}, f)
        return True
      return "base.tar.gz" in url

    mock_download_from_url.side_effect = download_side_effect
    mock_upload_to_url.return_value = True

    mock_cm_report = unittest.mock.MagicMock(returncode=0)
    mock_cm_report.stdout = json.dumps([{
        "FindingID": "fid-1",
        "Status": "DETECTED",
        "VulnType": "SQL_INJECTION",
        "FilePath": "db.py",
        "StartLine": 10,
    }])
    mock_git_status = unittest.mock.MagicMock(returncode=0, stdout=" M db.py")
    mock_default = unittest.mock.MagicMock(returncode=0, stdout="")

    def run_cmd_side_effect(cmd, *_args, **_kwargs):
      cmd_str = " ".join(cmd)
      if "report" in cmd_str:
        return mock_cm_report
      if "status" in cmd_str:
        return mock_git_status
      return mock_default

    mock_run_cmd.side_effect = run_cmd_side_effect

    run_worker_pipeline()

    # 1: container start (clone), 2: before the finding, 3: before routing.
    self.assertEqual(mock_mint.call_count, 3)
    _, owner, repo = mock_mint.call_args.args
    self.assertEqual((owner, repo), ("owner", "repo"))
    self.assertEqual(
        mock_check_remote_branch_exists.call_args.args[1], "ghs_token_2"
    )
    self.assertEqual(mock_push_branch.call_args.kwargs["token"], "ghs_token_3")
    self.assertEqual(mock_create_pr.call_args.kwargs["token"], "ghs_token_3")


if __name__ == "__main__":
  unittest.main()

