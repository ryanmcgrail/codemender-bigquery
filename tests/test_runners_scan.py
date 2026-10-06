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

"""Unit tests for Stage 1 Scan runner."""

import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from codemender_agent.runners.scan import (
    _render_zero_findings_summary,
    run_scan_pipeline,
)


class TestScanRunner(unittest.TestCase):

  def setUp(self):
    self.temp_dir = tempfile.TemporaryDirectory()
    self.workspace_dir = self.temp_dir.name

    # Setup common env vars
    self.env_patcher = patch.dict(
        os.environ,
        {
            "HOME": self.workspace_dir,
            "CODEMENDER_SCAN_ID": "test-scan-123",
            "CODEMENDER_GCS_BUCKET": "test-bucket",
            "WORKSPACE_DIR": self.workspace_dir,
            "GITHUB_REPO_URL": "https://github.com/owner/repo.git",
            "GITHUB_TOKEN": "fake-token",
            "CODEMENDER_SCAN_TARGET": ".",
            "CODEMENDER_BUILD_COMMAND": "echo 'build'",
        },
    )
    self.env_patcher.start()

  def tearDown(self):
    self.env_patcher.stop()
    self.temp_dir.cleanup()

  @patch("codemender_agent.runners.scan.generate_signed_url")
  @patch("codemender_agent.runners.scan.run_command")
  @patch("codemender_agent.runners.scan.upload_file_to_gcs")
  @patch("codemender_agent.runners.scan.is_duplicate_pr")
  @patch("codemender_agent.runners.scan.check_remote_branch_exists")
  @patch("codemender_agent.runners.scan.get_default_branch")
  @patch("codemender_agent.runners.scan.make_tarfile")
  @patch("shutil.which")
  def test_scan_pipeline_success(
      self,
      mock_which,
      _mock_make_tarfile,
      mock_get_default_branch,
      mock_check_remote_branch_exists,
      mock_is_duplicate_pr,
      mock_upload_gcs,
      mock_run_cmd,
      mock_generate_signed_url,
  ):
    mock_which.return_value = "/bin/cm"
    mock_get_default_branch.return_value = "main"
    mock_check_remote_branch_exists.return_value = False
    mock_is_duplicate_pr.return_value = False

    # Mock git rev-parse HEAD
    mock_git_rev = MagicMock()
    mock_git_rev.stdout = "abc123commitsha"

    # Mock cm report --format json
    mock_cm_report = MagicMock()
    mock_cm_report.stdout = json.dumps([
        {
            "FindingID": "fid-1",
            "Status": "DETECTED",
            "VulnType": "SQL_INJECTION",
            "FilePath": "db.py",
        },
        {
            "FindingID": "fid-2",
            "Status": "DETECTED",
            "VulnType": "XSS",
            "FilePath": "app.py",
        },
    ])

    # Mock other commands
    mock_default = MagicMock()
    mock_default.stdout = ""

    def run_cmd_side_effect(cmd, *_args, **_kwargs):
      cmd_str = " ".join(cmd)
      if "rev-parse" in cmd_str:
        return mock_git_rev
      elif "report" in cmd_str:
        return mock_cm_report
      else:
        return mock_default

    mock_generate_signed_url.side_effect = (
        lambda bucket, blob, method="GET", **kwargs: (
            f"http://signed-url/{blob}?method={method}"
        )
    )
    mock_run_cmd.side_effect = run_cmd_side_effect
    mock_upload_gcs.return_value = True

    run_scan_pipeline()

    # Verify manifest was uploaded
    manifest_uploaded = False
    partitions_uploaded = 0
    workspace_uploaded = False

    for call in mock_upload_gcs.call_args_list:
      local_path, bucket, dest_blob = call[0]
      self.assertEqual(bucket, "test-bucket")
      if "manifest.json" in dest_blob:
        manifest_uploaded = True
        with open(local_path, "r") as f:
          manifest_data = json.load(f)
          self.assertEqual(manifest_data["findings_count"], 2)
          self.assertEqual(manifest_data["target_sha"], "abc123commitsha")
          self.assertEqual(
              manifest_data["base_workspace_url"],
              "http://signed-url/scans/test-scan-123/workspace_base.tar.gz"
              "?method=GET",
          )
          self.assertEqual(
              manifest_data["partition_urls"],
              [
                  "http://signed-url/scans/test-scan-123/partition_0.json"
                  "?method=GET",
                  "http://signed-url/scans/test-scan-123/partition_1.json"
                  "?method=GET",
              ],
          )
          self.assertEqual(
              manifest_data["upload_urls"],
              [
                  "http://signed-url/scans/test-scan-123/worker_0_state.db"
                  "?method=PUT",
                  "http://signed-url/scans/test-scan-123/worker_1_state.db"
                  "?method=PUT",
              ],
          )
          self.assertEqual(
              manifest_data["metadata_urls"],
              [
                  "http://signed-url/scans/test-scan-123/worker_0_metadata.json"
                  "?method=PUT",
                  "http://signed-url/scans/test-scan-123/worker_1_metadata.json"
                  "?method=PUT",
              ],
          )
      elif "partition_" in dest_blob:
        partitions_uploaded += 1
        with open(local_path, "r") as f:
          part_data = json.load(f)
          self.assertIn("partition_index", part_data)
          self.assertIn("finding_ids", part_data)
      elif "workspace_base.tar.gz" in dest_blob:
        workspace_uploaded = True
      elif "scan_metadata.json" in dest_blob:
        with open(local_path, "r") as f:
          meta_data = json.load(f)
          self.assertIn("token_usage", meta_data)
          self.assertIsInstance(meta_data["token_usage"], dict)

    self.assertTrue(manifest_uploaded)
    self.assertTrue(workspace_uploaded)
    self.assertEqual(partitions_uploaded, 2)

  @patch("codemender_agent.runners.scan.run_command")
  @patch("codemender_agent.runners.scan.upload_file_to_gcs")
  @patch("codemender_agent.runners.scan.is_duplicate_pr")
  @patch("codemender_agent.runners.scan.get_default_branch")
  @patch("shutil.which")
  def test_scan_pipeline_zero_findings(
      self,
      mock_which,
      mock_get_default_branch,
      mock_is_duplicate_pr,
      mock_upload_gcs,
      mock_run_cmd,
  ):
    mock_which.return_value = "/bin/cm"
    mock_get_default_branch.return_value = "main"

    mock_git_rev = MagicMock()
    mock_git_rev.stdout = "abc123commitsha"

    mock_cm_report = MagicMock()
    mock_cm_report.stdout = "[]"

    mock_default = MagicMock()
    mock_default.stdout = ""

    def run_cmd_side_effect(cmd, *_args, **_kwargs):
      cmd_str = " ".join(cmd)
      if "rev-parse" in cmd_str:
        return mock_git_rev
      elif "report" in cmd_str:
        return mock_cm_report
      else:
        return mock_default

    mock_run_cmd.side_effect = run_cmd_side_effect
    mock_upload_gcs.return_value = True

    with self.assertRaises(SystemExit) as cm:
      run_scan_pipeline()

    self.assertEqual(cm.exception.code, 0)

    # Verify clean SARIF file was written to workspace
    sarif_file = os.path.join(self.workspace_dir, "report.sarif")
    self.assertTrue(os.path.exists(sarif_file))
    with open(sarif_file, "r", encoding="utf-8") as f:
      sarif_data = json.load(f)
      self.assertEqual(sarif_data["version"], "2.1.0")
      self.assertEqual(sarif_data["runs"][0]["results"], [])

    manifest_uploaded = False
    sarif_uploaded = False
    token_usage_uploaded = False
    for call in mock_upload_gcs.call_args_list:
      local_path, _, dest_blob = call[0]
      if "manifest.json" in dest_blob:
        manifest_uploaded = True
        with open(local_path, "r") as f:
          manifest_data = json.load(f)
          self.assertEqual(manifest_data["findings_count"], 0)
          self.assertEqual(manifest_data["target_sha"], "abc123commitsha")
      elif dest_blob.endswith("/report.sarif"):
        sarif_uploaded = True
      elif dest_blob.endswith("/token_usage.json"):
        token_usage_uploaded = True

    self.assertTrue(manifest_uploaded)
    self.assertTrue(sarif_uploaded)
    self.assertTrue(token_usage_uploaded)

    find_calls = [
        call for call in mock_run_cmd.call_args_list
        if len(call[0][0]) >= 2 and call[0][0][1] == "find"
    ]
    self.assertEqual(len(find_calls), 1)

  @patch("codemender_agent.runners.scan.generate_signed_url")
  @patch("codemender_agent.runners.scan.run_command")
  @patch("codemender_agent.runners.scan.upload_file_to_gcs")
  @patch("codemender_agent.runners.scan.is_duplicate_pr")
  @patch("codemender_agent.runners.scan.check_remote_branch_exists")
  @patch("codemender_agent.runners.scan.get_default_branch")
  @patch("codemender_agent.runners.scan.make_tarfile")
  @patch("shutil.which")
  def test_scan_pipeline_with_skipped_findings(
      self,
      mock_which,
      _mock_make_tarfile,
      mock_get_default_branch,
      mock_check_remote_branch_exists,
      mock_is_duplicate_pr,
      mock_upload_gcs,
      mock_run_cmd,
      mock_generate_signed_url,
  ):
    mock_which.return_value = "/bin/cm"
    mock_get_default_branch.return_value = "main"
    mock_check_remote_branch_exists.return_value = False
    
    # fid-1 will be skipped (db.py), fid-2 will be active (app.py)
    mock_is_duplicate_pr.side_effect = lambda r, t, f, v, s, **kw: f == "db.py"

    mock_git_rev = MagicMock()
    mock_git_rev.stdout = "abc123commitsha"

    mock_cm_report = MagicMock()
    mock_cm_report.stdout = json.dumps([
        {
            "FindingID": "fid-1",
            "Status": "DETECTED",
            "VulnType": "SQL_INJECTION",
            "FilePath": "db.py",
        },
        {
            "FindingID": "fid-2",
            "Status": "DETECTED",
            "VulnType": "XSS",
            "FilePath": "app.py",
        },
    ])

    mock_default = MagicMock()
    mock_default.stdout = ""

    def run_cmd_side_effect(cmd, *_args, **_kwargs):
      cmd_str = " ".join(cmd)
      if "rev-parse" in cmd_str:
        return mock_git_rev
      elif "report" in cmd_str:
        return mock_cm_report
      else:
        return mock_default

    mock_generate_signed_url.side_effect = lambda b, blob, **kw: f"url/{blob}"
    mock_run_cmd.side_effect = run_cmd_side_effect
    mock_upload_gcs.return_value = True

    # Setup fake local state.db
    import sqlite3
    db_dir = os.path.join(self.workspace_dir, ".codemender")
    os.makedirs(db_dir, exist_ok=True)
    db_path = os.path.join(db_dir, "state.db")
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE findings (finding_id TEXT, status TEXT, muted INTEGER, mute_reason TEXT, dismiss_reason TEXT)")
    conn.execute("INSERT INTO findings VALUES ('fid-1', 'OPEN', 0, '', '')")
    conn.execute("INSERT INTO findings VALUES ('fid-2', 'OPEN', 0, '', '')")
    conn.commit()
    conn.close()

    run_scan_pipeline()

    # Check local state.db mutation
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT finding_id, status, muted, mute_reason FROM findings ORDER BY finding_id")
    rows = cursor.fetchall()
    conn.close()

    self.assertEqual(rows[0][0], "fid-1")
    self.assertEqual(rows[0][1], "SKIPPED_DUPLICATE")
    self.assertEqual(rows[0][2], 1)
    self.assertTrue(len(rows[0][3]) > 0)
    
    self.assertEqual(rows[1][0], "fid-2")
    self.assertEqual(rows[1][1], "OPEN")
    self.assertEqual(rows[1][2], 0)

  @patch("codemender_agent.runners.scan.generate_signed_url")
  @patch("codemender_agent.runners.scan.run_command")
  @patch("codemender_agent.runners.scan.upload_file_to_gcs")
  @patch("codemender_agent.runners.scan.check_remote_branch_exists")
  @patch("codemender_agent.runners.scan.is_duplicate_pr")
  @patch("codemender_agent.runners.scan.get_default_branch")
  @patch("shutil.which")
  def test_scan_pipeline_relative_targets_normalized(
      self,
      mock_which,
      mock_get_default_branch,
      mock_is_duplicate_pr,
      mock_check_remote_branch,
      mock_upload_gcs,
      mock_run_cmd,
      mock_generate_signed_url,
  ):
    """Verify that relative scan targets are normalized to absolute paths for cm find."""
    mock_which.return_value = "/bin/cm"
    mock_get_default_branch.return_value = "main"
    mock_is_duplicate_pr.return_value = False
    mock_check_remote_branch.return_value = False
    mock_upload_gcs.return_value = True
    mock_generate_signed_url.side_effect = (
        lambda bucket, blob, method="GET", **kwargs: (
            f"http://signed-url/{blob}?method={method}"
        )
    )

    mock_git_rev = MagicMock()
    mock_git_rev.stdout = "abc123commitsha"

    mock_cm_report = MagicMock()
    mock_cm_report.stdout = json.dumps([
        {"FindingID": "fid-1", "Status": "DETECTED", "VulnType": "SQL_INJECTION", "FilePath": "routes/db.py"}
    ])

    mock_default = MagicMock()
    mock_default.stdout = ""

    def run_cmd_side_effect(cmd, *_args, **_kwargs):
      cmd_str = " ".join(cmd)
      if "rev-parse" in cmd_str:
        return mock_git_rev
      elif "report" in cmd_str:
        return mock_cm_report
      else:
        return mock_default

    mock_run_cmd.side_effect = run_cmd_side_effect

    with patch.dict(os.environ, {"CODEMENDER_SCAN_TARGET": "routes;services/api"}):
      run_scan_pipeline()

    # Verify cm find was called with absolute paths
    repo_dir = os.path.join(self.workspace_dir, "repo")
    expected_target1 = os.path.join(repo_dir, "routes")
    expected_target2 = os.path.join(repo_dir, "services/api")

    find_targets_passed = []
    for call in mock_run_cmd.call_args_list:
      cmd = call[0][0]
      if len(cmd) >= 2 and cmd[1] == "find":
        find_targets_passed.append(cmd[-1])

    self.assertIn(expected_target1, find_targets_passed)
    self.assertIn(expected_target2, find_targets_passed)
    for target in find_targets_passed:
      self.assertTrue(os.path.isabs(target), f"Target {target} is not absolute")

  @patch("codemender_agent.runners.scan.get_pr_changed_lines")
  @patch("codemender_agent.runners.scan.run_command")
  @patch("codemender_agent.runners.scan.check_remote_branch_exists")
  @patch("codemender_agent.runners.scan.is_duplicate_pr")
  @patch("codemender_agent.runners.scan.get_default_branch")
  @patch("shutil.which")
  def test_scan_pipeline_pr_differential_filtering(
      self,
      mock_which,
      mock_get_default_branch,
      mock_is_duplicate_pr,
      mock_check_remote_branch,
      mock_run_cmd,
      mock_get_pr_changed_lines,
  ):
    """Verify differential PR filtering marks untouched findings PRE_EXISTING_IGNORED and emits GHA outputs."""
    mock_which.return_value = "/bin/cm"
    mock_get_default_branch.return_value = "main"
    mock_is_duplicate_pr.return_value = False
    mock_check_remote_branch.return_value = False
    
    # Diff hunks: only modified lines 10-15 in app.py
    mock_get_pr_changed_lines.return_value = {"app.py": {10, 11, 12, 13, 14, 15}}

    mock_git_rev = MagicMock()
    mock_git_rev.stdout = "targetsha123"

    mock_cm_report = MagicMock()
    mock_cm_report.stdout = json.dumps([
        {"FindingID": "fid-modified", "Status": "DETECTED", "VulnType": "SQL_INJECTION", "FilePath": "app.py", "StartLine": 12, "EndLine": 12},
        {"FindingID": "fid-untouched", "Status": "DETECTED", "VulnType": "XSS", "FilePath": "legacy.py", "StartLine": 50, "EndLine": 55},
    ])

    mock_default = MagicMock()
    mock_default.stdout = ""

    def run_cmd_side_effect(cmd, *_args, **_kwargs):
      cmd_str = " ".join(cmd)
      if "rev-parse" in cmd_str:
        return mock_git_rev
      elif "report" in cmd_str:
        return mock_cm_report
      else:
        return mock_default

    mock_run_cmd.side_effect = run_cmd_side_effect

    # Setup fake local state.db
    import sqlite3
    db_dir = os.path.join(self.workspace_dir, ".codemender")
    os.makedirs(db_dir, exist_ok=True)
    db_path = os.path.join(db_dir, "state.db")
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE findings (finding_id TEXT, status TEXT, muted INTEGER, mute_reason TEXT, dismiss_reason TEXT)")
    conn.execute("INSERT INTO findings VALUES ('fid-modified', 'OPEN', 0, '', '')")
    conn.execute("INSERT INTO findings VALUES ('fid-untouched', 'OPEN', 0, '', '')")
    conn.commit()
    conn.close()

    output_file = os.path.join(self.workspace_dir, "github_output.txt")

    with patch.dict(
        os.environ,
        {
            "CODEMENDER_STORAGE_MODE": "github_actions",
            "CODEMENDER_IS_PR_SCAN": "true",
            "CODEMENDER_PR_BASE_REF": "main",
            "GITHUB_OUTPUT": output_file,
        },
    ):
      run_scan_pipeline()

    # Check local state.db mutations
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT finding_id, status FROM findings ORDER BY finding_id")
    rows = cursor.fetchall()
    conn.close()

    self.assertEqual(rows[0], ("fid-modified", "OPEN"))
    self.assertEqual(rows[1], ("fid-untouched", "PRE_EXISTING_IGNORED"))

    # Check GITHUB_OUTPUT file
    self.assertTrue(os.path.exists(output_file))
    with open(output_file, "r") as f:
      output_content = f.read()

    self.assertIn("matrix=[0]", output_content)
    self.assertIn("findings_count=1", output_content)
    self.assertIn("target_sha=targetsha123", output_content)

  def test_render_zero_findings_summary_pr_scan_hides_legacy_notes(self):
    """Verify that _render_zero_findings_summary omits pre-existing/legacy notes on PR scans."""
    summary_file = os.path.join(self.workspace_dir, "step_summary.md")
    with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": summary_file}):
      _render_zero_findings_summary(
          owner="example-org",
          repo_name="juice-shop-local",
          target_sha="1e677199",
          is_pr_scan=True,
          filtered_reasons="10 pre-existing findings and 0 duplicate branches/PRs dismissed.",
      )

    self.assertTrue(os.path.exists(summary_file))
    with open(summary_file, "r", encoding="utf-8") as f:
      content = f.read()

    self.assertIn("Pull Request Scan (Clean as You Code)", content)
    self.assertNotIn("pre-existing findings", content)
    self.assertNotIn("- **Note:**", content)

  def test_render_zero_findings_summary_with_token_totals(self):
    """Verify that _render_zero_findings_summary renders per-model token table."""
    summary_file = os.path.join(self.workspace_dir, "step_summary_tokens.md")
    with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": summary_file}):
      _render_zero_findings_summary(
          owner="example-org",
          repo_name="juice-shop-local",
          target_sha="1e677199",
          is_pr_scan=False,
          token_totals={"test-model-a": {"in_tokens": 1200, "out_tokens": 80, "total_tokens": 1280}},
      )

    self.assertTrue(os.path.exists(summary_file))
    with open(summary_file, "r", encoding="utf-8") as f:
      content = f.read()

    self.assertIn("### ⚡ LLM Token Usage Summary", content)
    self.assertIn("- **Grand Total Tokens:** 1,280", content)
    self.assertIn("| `test-model-a` | 1,200 | 80 | 1,280 |", content)

  @patch("codemender_agent.runners.scan.delete_remote_branch")
  @patch("codemender_agent.runners.scan.is_duplicate_pr")
  @patch("codemender_agent.runners.scan.check_remote_branch_exists")
  def test_filter_findings_dead_branch_pruned_and_retained(
      self, mock_check_branch, mock_is_dup_pr, mock_delete_branch
  ):
    """Verify that a remote branch without an open PR is pruned as a dead branch and retained as active."""
    from codemender_agent.runners.scan import _filter_findings

    mock_check_branch.return_value = True
    mock_is_dup_pr.return_value = False
    mock_delete_branch.return_value = True

    findings = [
        {
            "FindingID": "f-dead-1",
            "Status": "DETECTED",
            "VulnType": "SQL_INJECTION",
            "FilePath": "routes/search.ts",
            "StartLine": 25,
        }
    ]

    active, skipped, ignored = _filter_findings(
        findings=findings,
        repo_url="https://github.com/org/repo.git",
        token="token",
        repo_dir=self.workspace_dir,
        force_overwrite=False,
        is_pr_scan=False,
    )

    self.assertEqual(len(active), 1)
    self.assertEqual(active[0]["FindingID"], "f-dead-1")
    self.assertEqual(skipped, [])
    self.assertEqual(ignored, [])
    mock_delete_branch.assert_called_once()

  @patch("codemender_agent.runners.scan.is_duplicate_pr")
  @patch("codemender_agent.runners.scan.check_remote_branch_exists")
  def test_filter_findings_accepts_cm_070_snake_case_payload(
      self, mock_check_branch, mock_is_dup_pr
  ):
    """Verify cm 0.7.0 snake_case findings survive filtering end-to-end."""
    from codemender_agent.codemender.cli import parse_findings_json
    from codemender_agent.runners.scan import _filter_findings

    mock_check_branch.return_value = False
    mock_is_dup_pr.return_value = False

    # Verbatim `cm report --format json` payload emitted by cm version 0.7.0,
    # which switched to snake_case struct tags in cl/974628022. Before the
    # normalization shim this produced 11 parsed but 0 active findings.
    raw_json = """[
      {
        "finding_id": "a722cea6-dced-56fc-8b96-393c12834278",
        "title": "SQL Injection in User Authentication",
        "file_path": "/__w/juice-shop-local/juice-shop-local/juice-shop-local/routes/login.ts",
        "severity": "CRITICAL",
        "vuln_type": "SQL Injection",
        "vuln_id": "CWE-89",
        "status": "OPEN",
        "start_line": 34,
        "end_line": 35
      },
      {
        "finding_id": "d83ac117-0f0a-5c3c-8b1e-9a1f2c3d4e5f",
        "title": "Open Redirect",
        "file_path": "/__w/juice-shop-local/juice-shop-local/juice-shop-local/lib/insecurity.ts",
        "severity": "MEDIUM",
        "vuln_type": "Open Redirect",
        "vuln_id": "CWE-601",
        "status": "OPEN",
        "start_line": 133,
        "end_line": 139
      }
    ]"""

    active, skipped, ignored = _filter_findings(
        findings=parse_findings_json(raw_json),
        repo_url="https://github.com/org/repo.git",
        token="token",
        repo_dir=self.workspace_dir,
        force_overwrite=False,
        is_pr_scan=False,
    )

    self.assertEqual(len(active), 2)
    self.assertEqual(skipped, [])
    self.assertEqual(ignored, [])
    self.assertEqual(
        active[0]["FindingID"], "a722cea6-dced-56fc-8b96-393c12834278"
    )
    self.assertEqual(
        active[1]["FindingID"], "d83ac117-0f0a-5c3c-8b1e-9a1f2c3d4e5f"
    )

  @patch("codemender_agent.runners.scan.delete_remote_branch")
  @patch("codemender_agent.runners.scan.is_duplicate_pr")
  @patch("codemender_agent.runners.scan.check_remote_branch_exists")
  def test_filter_findings_live_branch_skipped(
      self, mock_check_branch, mock_is_dup_pr, mock_delete_branch
  ):
    """Verify that a remote branch WITH an open PR is recognized as live and skipped."""
    from codemender_agent.runners.scan import _filter_findings

    mock_check_branch.return_value = True
    mock_is_dup_pr.return_value = True

    findings = [
        {
            "FindingID": "f-live-1",
            "Status": "DETECTED",
            "VulnType": "SQL_INJECTION",
            "FilePath": "routes/search.ts",
            "StartLine": 25,
        }
    ]

    active, skipped, ignored = _filter_findings(
        findings=findings,
        repo_url="https://github.com/org/repo.git",
        token="token",
        repo_dir=self.workspace_dir,
        force_overwrite=False,
        is_pr_scan=False,
    )

    self.assertEqual(active, [])
    self.assertEqual(skipped, ["f-live-1"])
    self.assertEqual(ignored, [])
    mock_delete_branch.assert_not_called()

  @patch("codemender_agent.runners.scan.is_duplicate_pr")
  @patch("codemender_agent.runners.scan.check_remote_branch_exists")
  def test_filter_findings_skips_closed_statuses(
      self, mock_check_branch, mock_is_dup_pr
  ):
    """FIXED and DISMISSED (cm's closed statuses) never reach the workers."""
    from codemender_agent.runners.scan import _filter_findings

    mock_check_branch.return_value = False
    mock_is_dup_pr.return_value = False
    statuses = {
        "f-open": "OPEN",
        "f-reopened": "REOPENED",
        "f-detected": "DETECTED",
        "f-none": None,
        "f-fixed": "FIXED",
        "f-dismissed": "DISMISSED",
        "f-dismissed-lower": "dismissed",
        "f-false-positive": "FALSE_POSITIVE",
        "f-resolved": "RESOLVED",
    }
    findings = [
        {
            "FindingID": fid,
            "Status": status,
            "VulnType": "SQL Injection",
            "FilePath": "routes/search.ts",
            "StartLine": 25 + i,
        }
        for i, (fid, status) in enumerate(statuses.items())
    ]

    active, skipped, ignored = _filter_findings(
        findings=findings,
        repo_url="https://github.com/org/repo.git",
        token="token",
        repo_dir=self.workspace_dir,
        force_overwrite=False,
        is_pr_scan=False,
    )

    self.assertEqual(
        [f["FindingID"] for f in active],
        ["f-open", "f-reopened", "f-detected", "f-none"],
    )
    self.assertEqual(skipped, [])
    self.assertEqual(ignored, [])

  def test_write_clean_sarif_file_includes_automation_details_id(self):
    """Verify _write_clean_sarif_file embeds automationDetails.id and has_sarif_results returns False."""
    from codemender_agent.runners.aggregate import has_sarif_results
    from codemender_agent.runners.scan import _write_clean_sarif_file

    sarif_path = _write_clean_sarif_file(
        self.workspace_dir,
        self.workspace_dir,
        repository="org/repo",
        scan_target="litemall-core;litemall-db",
    )
    self.assertFalse(has_sarif_results(sarif_path))
    with open(sarif_path, "r", encoding="utf-8") as f:
      data = json.load(f)
    self.assertEqual(
        data["runs"][0]["automationDetails"]["id"],
        "codemender/org-repo/litemall-core-litemall-db/",
    )

  @patch("codemender_agent.runners.scan.post_commit_status")
  @patch("codemender_agent.runners.scan._run_scan_pipeline")
  def test_run_scan_pipeline_posts_error_status_on_stage1_crash(
      self, mock_inner_scan, mock_post_status
  ):
    """Verify run_scan_pipeline posts state='error' if Stage 1 fails after setting target_sha."""
    import sys
    from codemender_agent.runners.scan import run_scan_pipeline

    def crash_after_sync(ctx):
      ctx.repository = "org/repo"
      ctx.target_sha = "cafebabe12345678"
      sys.exit(1)

    mock_inner_scan.side_effect = crash_after_sync
    with patch.dict(
        os.environ,
        {
            "GITHUB_REPO_URL": "https://github.com/org/repo.git",
            "GITHUB_TOKEN": "ghp_test",
            "CODEMENDER_IS_PR_SCAN": "false",
        },
    ):
      with self.assertRaises(SystemExit) as cm:
        run_scan_pipeline()
      self.assertEqual(cm.exception.code, 1)

    mock_post_status.assert_called_once()
    kwargs = mock_post_status.call_args.kwargs
    self.assertEqual(kwargs["state"], "error")
    self.assertEqual(kwargs["sha"], "cafebabe12345678")

  @patch("codemender_agent.runners.scan.post_or_update_sticky_comment")
  @patch("codemender_agent.runners.scan.post_commit_status")
  @patch("codemender_agent.runners.scan.run_command")
  @patch("codemender_agent.runners.scan.upload_file_to_gcs")
  @patch("codemender_agent.runners.scan.get_default_branch")
  @patch("shutil.which")
  def test_scan_pipeline_pr_zero_findings_posts_security_gate_and_sticky_comment(
      self,
      mock_which,
      mock_get_default_branch,
      mock_upload_gcs,
      mock_run_cmd,
      mock_post_status,
      mock_sticky_comment,
  ):
    """Verify PR scan with 0 raw findings posts passing Security Gate commit status and sticky summary."""
    mock_which.return_value = "/bin/cm"
    mock_get_default_branch.return_value = "main"
    mock_upload_gcs.return_value = True

    mock_git_rev = MagicMock()
    mock_git_rev.stdout = "prheadsha999"

    mock_cm_report = MagicMock()
    mock_cm_report.stdout = "[]"

    mock_default = MagicMock()
    mock_default.stdout = ""

    def run_cmd_side_effect(cmd, *_args, **_kwargs):
      cmd_str = " ".join(cmd)
      if "rev-parse" in cmd_str:
        return mock_git_rev
      elif "report" in cmd_str:
        return mock_cm_report
      return mock_default

    mock_run_cmd.side_effect = run_cmd_side_effect
    output_file = os.path.join(self.workspace_dir, "github_output_pr_zero.txt")

    with patch.dict(
        os.environ,
        {
            "CODEMENDER_STORAGE_MODE": "github_actions",
            "CODEMENDER_IS_PR_SCAN": "true",
            "CODEMENDER_PR_BASE_REF": "main",
            "CODEMENDER_PR_NUMBER": "42",
            "GITHUB_OUTPUT": output_file,
        },
    ):
      with self.assertRaises(SystemExit) as cm:
        run_scan_pipeline()

    self.assertEqual(cm.exception.code, 0)

    # Verify CodeMender / Security Gate commit status was posted as success
    mock_post_status.assert_called_once()
    status_kwargs = mock_post_status.call_args.kwargs
    self.assertEqual(status_kwargs["state"], "success")
    self.assertEqual(status_kwargs["context"], "CodeMender / Security Gate")
    self.assertEqual(status_kwargs["sha"], "prheadsha999")
    self.assertIn("Security Gate PASSED", status_kwargs["description"])

    # Verify sticky PR comment was posted/updated with PASSED status
    mock_sticky_comment.assert_called_once()
    sticky_kwargs = mock_sticky_comment.call_args.kwargs
    self.assertEqual(sticky_kwargs["pr_number"], 42)
    self.assertIn("Security Gate Status: PASSED", sticky_kwargs["body"])

  @patch("codemender_agent.runners.scan.post_or_update_sticky_comment")
  @patch("codemender_agent.runners.scan.post_commit_status")
  @patch("codemender_agent.runners.scan.get_pr_changed_lines")
  @patch("codemender_agent.runners.scan.run_command")
  @patch("codemender_agent.runners.scan.check_remote_branch_exists")
  @patch("codemender_agent.runners.scan.is_duplicate_pr")
  @patch("codemender_agent.runners.scan.get_default_branch")
  @patch("shutil.which")
  def test_scan_pipeline_pr_all_findings_filtered_posts_security_gate_and_sticky_comment(
      self,
      mock_which,
      mock_get_default_branch,
      mock_is_duplicate_pr,
      mock_check_remote_branch,
      mock_run_cmd,
      mock_get_pr_changed_lines,
      mock_post_status,
      mock_sticky_comment,
  ):
    """Verify PR scan where all findings are filtered out posts passing Security Gate status and updates sticky summary."""
    mock_which.return_value = "/bin/cm"
    mock_get_default_branch.return_value = "main"
    mock_is_duplicate_pr.return_value = False
    mock_check_remote_branch.return_value = False

    # PR only touched app.py lines 10-15, while finding is in legacy.py lines 50-55
    mock_get_pr_changed_lines.return_value = {"app.py": {10, 11, 12, 13, 14, 15}}

    mock_git_rev = MagicMock()
    mock_git_rev.stdout = "cleanprsha777"

    mock_cm_report = MagicMock()
    mock_cm_report.stdout = json.dumps([
        {
            "FindingID": "fid-untouched",
            "Status": "DETECTED",
            "VulnType": "XSS",
            "FilePath": "legacy.py",
            "StartLine": 50,
            "EndLine": 55,
        },
    ])

    mock_default = MagicMock()
    mock_default.stdout = ""

    def run_cmd_side_effect(cmd, *_args, **_kwargs):
      cmd_str = " ".join(cmd)
      if "rev-parse" in cmd_str:
        return mock_git_rev
      elif "report" in cmd_str:
        return mock_cm_report
      return mock_default

    mock_run_cmd.side_effect = run_cmd_side_effect
    output_file = os.path.join(self.workspace_dir, "github_output_pr_filtered.txt")

    with patch.dict(
        os.environ,
        {
            "CODEMENDER_STORAGE_MODE": "github_actions",
            "CODEMENDER_IS_PR_SCAN": "true",
            "CODEMENDER_PR_BASE_REF": "main",
            "CODEMENDER_PR_NUMBER": "99",
            "GITHUB_OUTPUT": output_file,
        },
    ):
      with self.assertRaises(SystemExit) as cm:
        run_scan_pipeline()

    self.assertEqual(cm.exception.code, 0)

    # Verify GITHUB_OUTPUT emitted findings_count=0
    with open(output_file, "r", encoding="utf-8") as f:
      output_content = f.read()
    self.assertIn("findings_count=0", output_content)

    # Verify CodeMender / Security Gate commit status was posted as success
    mock_post_status.assert_called_once()
    status_kwargs = mock_post_status.call_args.kwargs
    self.assertEqual(status_kwargs["state"], "success")
    self.assertEqual(status_kwargs["context"], "CodeMender / Security Gate")
    self.assertEqual(status_kwargs["sha"], "cleanprsha777")
    self.assertIn("Security Gate PASSED", status_kwargs["description"])

    # Verify sticky PR comment was posted/updated with PASSED status
    mock_sticky_comment.assert_called_once()
    sticky_kwargs = mock_sticky_comment.call_args.kwargs
    self.assertEqual(sticky_kwargs["pr_number"], 99)
    self.assertIn("Security Gate Status: PASSED", sticky_kwargs["body"])


if __name__ == "__main__":
  unittest.main()


