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

"""Telemetry for Stage 1 runs whose findings were all filtered out.

When every finding already has an open pull request (or pre-dates the change
under review), Stage 1 exits without workers and Stage 3 never runs. The run
must still record those findings in `vulnerability_findings`, with the matched
pull request, and a `skipped_duplicate_count` that agrees with the rows.
"""

import json
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from codemender_agent.runners.scan import _filtered_findings_for_telemetry
from codemender_agent.runners.scan import run_scan_pipeline
from codemender_agent.telemetry import bigquery as bq

PR_URL = "https://github.com/owner/repo/pull/7"


def _make_state_db(path, rows):
  os.makedirs(os.path.dirname(path), exist_ok=True)
  with sqlite3.connect(path) as conn:
    conn.execute(
        "CREATE TABLE findings (finding_id TEXT, title TEXT, vuln_type TEXT,"
        " severity TEXT, file_path TEXT, start_line INTEGER, status TEXT,"
        " muted INTEGER, mute_reason TEXT, dismiss_reason TEXT)"
    )
    conn.executemany(
        "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, 0, '', '')", rows
    )


class TestFilteredFindingsForTelemetry(unittest.TestCase):

  def setUp(self):
    self.tmp = tempfile.TemporaryDirectory()
    self.db_path = os.path.join(self.tmp.name, "state.db")

  def tearDown(self):
    self.tmp.cleanup()

  def test_filtered_status_overrides_state_db(self):
    # The state.db update is best effort; if it did not land, the snapshot
    # still reports the status Stage 1 decided on.
    _make_state_db(self.db_path, [
        ("dup", "SQLi", "SQL Injection", "HIGH", "a.py", 3, "OPEN"),
        ("pre", "XSS", "XSS", "MEDIUM", "b.py", 9, "OPEN"),
    ])
    rows = _filtered_findings_for_telemetry([], ["dup"], ["pre"], self.db_path)
    by_id = {r["finding_id"]: r for r in rows}
    self.assertEqual(by_id["dup"]["status"], "SKIPPED_DUPLICATE")
    self.assertEqual(by_id["pre"]["status"], "PRE_EXISTING_IGNORED")
    self.assertEqual(by_id["dup"]["title"], "SQLi")

  def test_finding_missing_from_state_db_is_rebuilt_from_report(self):
    findings = [
        {"FindingID": "camel", "VulnType": "SSRF", "FilePath": "c.py",
         "StartLine": 4, "Severity": "HIGH", "Title": "SSRF in c"},
        {"finding_id": "snake", "vuln_type": "XXE", "file_path": "d.py",
         "start_line": 8},
        {"FindingID": "active", "VulnType": "RCE", "FilePath": "e.py"},
    ]
    rows = _filtered_findings_for_telemetry(
        findings, ["camel", "snake"], [], os.path.join(self.tmp.name, "none.db")
    )
    by_id = {r["finding_id"]: r for r in rows}
    self.assertEqual(set(by_id), {"camel", "snake"})
    self.assertEqual(by_id["camel"]["vuln_type"], "SSRF")
    self.assertEqual(by_id["camel"]["start_line"], 4)
    self.assertEqual(by_id["snake"]["file_path"], "d.py")
    self.assertTrue(all(r["status"] == "SKIPPED_DUPLICATE" for r in rows))

  def test_no_duplicate_rows_when_finding_is_in_both_sources(self):
    _make_state_db(self.db_path, [
        ("dup", "SQLi", "SQL Injection", "HIGH", "a.py", 3, "SKIPPED_DUPLICATE"),
    ])
    rows = _filtered_findings_for_telemetry(
        [{"FindingID": "dup", "VulnType": "SQL Injection"}], ["dup"], [],
        self.db_path,
    )
    self.assertEqual([r["finding_id"] for r in rows], ["dup"])

  def test_pre_existing_counts_as_skipped_in_remediation_summary(self):
    counts = bq.summarize_remediation([
        {"finding_id": "a", "status": "SKIPPED_DUPLICATE"},
        {"finding_id": "b", "status": "PRE_EXISTING_IGNORED"},
        {"finding_id": "c", "status": "OPEN"},
    ])
    self.assertEqual(counts["skipped_duplicate"], 2)

  def test_aggregate_counts_duplicates_like_stage_one(self):
    # A PR scan with one duplicate and one pre-existing finding: Stage 1 would
    # record 2 on the all-filtered path, so Stage 3 must record 2 as well.
    from codemender_agent.runners import aggregate

    snapshot = [
        {"finding_id": "a", "status": "SKIPPED_DUPLICATE"},
        {"finding_id": "b", "status": "PRE_EXISTING_IGNORED"},
        {"finding_id": "c", "status": "FIXED"},
    ]
    self.assertEqual(aggregate._skipped_count_for_telemetry(snapshot, {"a"}), 2)
    # Without a snapshot the SKIPPED_DUPLICATE IDs are the only signal left.
    self.assertEqual(aggregate._skipped_count_for_telemetry([], {"a", "x"}), 2)


class TestAllDuplicateScanEmitsFindingRows(unittest.TestCase):

  def setUp(self):
    self.tmp = tempfile.TemporaryDirectory()
    self.workspace_dir = self.tmp.name
    self.env = patch.dict(
        os.environ,
        {
            "HOME": self.workspace_dir,
            "CODEMENDER_SCAN_ID": "scan-dup-1",
            "CODEMENDER_GCS_BUCKET": "test-bucket",
            "WORKSPACE_DIR": self.workspace_dir,
            "GITHUB_REPO_URL": "https://github.com/owner/repo.git",
            "GITHUB_TOKEN": "fake-token",
            "CODEMENDER_SCAN_TARGET": ".",
            "CODEMENDER_BUILD_COMMAND": "echo build",
            bq.ENV_DATASET: "ds",
        },
    )
    self.env.start()
    self.client = MagicMock()
    self.client.insert_rows_json.return_value = []
    self.exporter = bq.BigQueryTelemetryExporter(
        dataset="ds", project="p", client=self.client
    )

  def tearDown(self):
    self.env.stop()
    self.tmp.cleanup()

  def _rows(self, table):
    out = []
    for call in self.client.insert_rows_json.call_args_list:
      if call.args[0].endswith("." + table):
        out.extend(call.args[1])
    return out

  @patch("codemender_agent.runners.scan.upload_sarif_to_code_scanning")
  @patch("codemender_agent.runners.scan.post_commit_status")
  @patch("codemender_agent.runners.scan.run_command")
  @patch("codemender_agent.runners.scan.upload_file_to_gcs")
  @patch("codemender_agent.runners.scan.is_duplicate_pr")
  @patch("codemender_agent.runners.scan.check_remote_branch_exists")
  @patch("codemender_agent.runners.scan.get_default_branch")
  @patch("shutil.which")
  def test_every_duplicate_is_recorded_with_its_pull_request(
      self,
      mock_which,
      mock_default_branch,
      mock_remote_branch,
      mock_dup_pr,
      mock_upload,
      mock_run,
      _mock_status,
      _mock_sarif,
  ):
    mock_which.return_value = "/bin/cm"
    mock_default_branch.return_value = "main"
    mock_remote_branch.return_value = False
    mock_dup_pr.return_value = PR_URL
    mock_upload.return_value = True

    report = MagicMock()
    report.stdout = json.dumps([
        {"FindingID": "fid-1", "Status": "DETECTED", "VulnType": "SQLI",
         "FilePath": "db.py", "StartLine": 10},
        {"FindingID": "fid-2", "Status": "DETECTED", "VulnType": "XSS",
         "FilePath": "app.py", "StartLine": 20},
    ])
    rev = MagicMock()
    rev.stdout = "abc123commitsha"
    other = MagicMock()
    other.stdout = ""

    def run_side_effect(cmd, *_a, **_kw):
      joined = " ".join(cmd)
      if "rev-parse" in joined:
        return rev
      if "report" in joined:
        return report
      return other

    mock_run.side_effect = run_side_effect
    # fid-1 is in state.db; fid-2 is only in the cm report.
    _make_state_db(
        os.path.join(self.workspace_dir, ".codemender", "state.db"),
        [("fid-1", "SQLi in db", "SQLI", "HIGH", "db.py", 10, "OPEN")],
    )

    with patch.object(bq, "BigQueryTelemetryExporter", return_value=self.exporter):
      with self.assertRaises(SystemExit) as cm:
        run_scan_pipeline()
    self.assertEqual(cm.exception.code, 0)

    runs = self._rows(bq.SCAN_RUNS_TABLE)
    self.assertEqual(len(runs), 1)
    run = runs[0]
    self.assertEqual(run["status"], "SUCCESS")
    self.assertEqual(run["total_findings_count"], 2)
    self.assertEqual(run["active_findings_count"], 0)
    self.assertEqual(run["skipped_duplicate_count"], 2)

    rows = self._rows(bq.VULNERABILITY_FINDINGS_TABLE)
    self.assertEqual(sorted(r["finding_id"] for r in rows), ["fid-1", "fid-2"])
    for row in rows:
      self.assertEqual(row["status"], "SKIPPED_DUPLICATE")
      self.assertEqual(row["fix_pr_url"], PR_URL)
      self.assertEqual(row["scan_id"], "scan-dup-1")
    skipped_rows = sum(1 for r in rows if r["status"] in bq.SKIPPED_STATUSES)
    self.assertEqual(skipped_rows, run["skipped_duplicate_count"])

  @patch("codemender_agent.runners.scan.upload_sarif_to_code_scanning")
  @patch("codemender_agent.runners.scan.post_commit_status")
  @patch("codemender_agent.runners.scan.run_command")
  @patch("codemender_agent.runners.scan.upload_file_to_gcs")
  @patch("codemender_agent.runners.scan.is_duplicate_pr")
  @patch("codemender_agent.runners.scan.check_remote_branch_exists")
  @patch("codemender_agent.runners.scan.get_default_branch")
  @patch("shutil.which")
  def test_nothing_is_read_or_sent_when_telemetry_is_off(
      self,
      mock_which,
      mock_default_branch,
      mock_remote_branch,
      mock_dup_pr,
      mock_upload,
      mock_run,
      _mock_status,
      _mock_sarif,
  ):
    os.environ.pop(bq.ENV_DATASET, None)
    mock_which.return_value = "/bin/cm"
    mock_default_branch.return_value = "main"
    mock_remote_branch.return_value = False
    mock_dup_pr.return_value = PR_URL
    mock_upload.return_value = True
    report = MagicMock()
    report.stdout = json.dumps([
        {"FindingID": "fid-1", "Status": "DETECTED", "VulnType": "SQLI",
         "FilePath": "db.py", "StartLine": 10},
    ])
    rev = MagicMock()
    rev.stdout = "abc123commitsha"
    other = MagicMock()
    other.stdout = ""
    mock_run.side_effect = lambda cmd, *_a, **_kw: (
        rev if "rev-parse" in " ".join(cmd)
        else report if "report" in " ".join(cmd) else other
    )
    with patch(
        "codemender_agent.runners.scan._filtered_findings_for_telemetry"
    ) as mock_snapshot:
      with self.assertRaises(SystemExit) as cm:
        run_scan_pipeline()
    self.assertEqual(cm.exception.code, 0)
    mock_snapshot.assert_not_called()
    self.client.insert_rows_json.assert_not_called()

  @patch("codemender_agent.runners.scan.upload_sarif_to_code_scanning")
  @patch("codemender_agent.runners.scan.post_commit_status")
  @patch("codemender_agent.runners.scan.run_command")
  @patch("codemender_agent.runners.scan.upload_file_to_gcs")
  @patch("codemender_agent.runners.scan.is_duplicate_pr")
  @patch("codemender_agent.runners.scan.check_remote_branch_exists")
  @patch("codemender_agent.runners.scan.get_default_branch")
  @patch("shutil.which")
  def test_snapshot_error_does_not_fail_the_scan(
      self,
      mock_which,
      mock_default_branch,
      mock_remote_branch,
      mock_dup_pr,
      mock_upload,
      mock_run,
      _mock_status,
      _mock_sarif,
  ):
    # The commit status and SARIF are already published by this point, so a
    # telemetry error must still end the run as a success.
    mock_which.return_value = "/bin/cm"
    mock_default_branch.return_value = "main"
    mock_remote_branch.return_value = False
    mock_dup_pr.return_value = PR_URL
    mock_upload.return_value = True
    report = MagicMock()
    report.stdout = json.dumps([
        {"FindingID": "fid-1", "Status": "DETECTED", "VulnType": "SQLI",
         "FilePath": "db.py", "StartLine": 10},
    ])
    rev = MagicMock()
    rev.stdout = "abc123commitsha"
    other = MagicMock()
    other.stdout = ""
    mock_run.side_effect = lambda cmd, *_a, **_kw: (
        rev if "rev-parse" in " ".join(cmd)
        else report if "report" in " ".join(cmd) else other
    )
    with patch.object(bq, "BigQueryTelemetryExporter", return_value=self.exporter):
      with patch(
          "codemender_agent.runners.scan._filtered_findings_for_telemetry",
          side_effect=RuntimeError("boom"),
      ):
        with self.assertRaises(SystemExit) as cm:
          run_scan_pipeline()
    self.assertEqual(cm.exception.code, 0)
    runs = self._rows(bq.SCAN_RUNS_TABLE)
    self.assertEqual(len(runs), 1)
    self.assertEqual(runs[0]["status"], "SUCCESS")
    self.assertEqual(runs[0]["skipped_duplicate_count"], 1)
    self.assertEqual(self._rows(bq.VULNERABILITY_FINDINGS_TABLE), [])


if __name__ == "__main__":
  unittest.main()
