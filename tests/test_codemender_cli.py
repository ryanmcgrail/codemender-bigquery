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

"""Unit tests for codemender_agent.codemender.cli module."""

import unittest
from unittest.mock import MagicMock, patch

from codemender_agent.codemender.cli import (
    extract_session_id,
    is_closed_finding_status,
    log_cm_version,
    parse_findings_json,
)


class TestCodeMenderCli(unittest.TestCase):

  def test_is_closed_finding_status(self):
    """cm's FIXED/DISMISSED and legacy closed statuses are closed."""
    for status in ("FIXED", "DISMISSED", "dismissed", " Fixed ",
                   "FALSE_POSITIVE", "RESOLVED"):
      with self.subTest(status=status):
        self.assertTrue(is_closed_finding_status(status))
    for status in ("OPEN", "REOPENED", "DETECTED", "", None):
      with self.subTest(status=status):
        self.assertFalse(is_closed_finding_status(status))

  def test_extract_session_id(self):
    """Verify regex extraction of Session UUID from cm find stdout."""
    find_output = """
        🚀 Starting FIND session (mode: SCAN)...
        Server: codemender_prod
        Session: 63198618-4ce9-41fa-b973-436e1451a3d0
        Operation: sessions/63198618-4ce9-41fa-b973-436e1451a3d0/operations/aeabc910
    """
    session_id = extract_session_id(find_output)
    self.assertEqual(session_id, "63198618-4ce9-41fa-b973-436e1451a3d0")

  def test_parse_findings_json_valid(self):
    """Verify parsing valid JSON findings output."""
    raw_json = """[
      {
        "FindingID": "f123",
        "VulnType": "SQL Injection",
        "FilePath": "app.py",
        "Status": "NEW"
      }
    ]"""
    findings = parse_findings_json(raw_json)
    self.assertEqual(len(findings), 1)
    self.assertEqual(findings[0]["FindingID"], "f123")
    self.assertEqual(findings[0]["VulnType"], "SQL Injection")

  def test_parse_findings_json_cm_070_snake_case(self):
    """Verify cm 0.7.0 snake_case output normalizes to canonical PascalCase."""
    # Verbatim `cm report --format json` payload emitted by cm version 0.7.0,
    # which switched to snake_case struct tags in cl/974628022.
    raw_json = """[
      {
        "finding_id": "a722cea6-dced-56fc-8b96-393c12834278",
        "session_id": "ChA5ODRmOWZiNDBhMTRmNDU0EAgaATAqBG1haW4",
        "title": "SQL Injection in User Authentication",
        "file_path": "/__w/juice-shop-local/juice-shop-local/juice-shop-local/routes/login.ts",
        "severity": "CRITICAL",
        "confidence": 100,
        "analysis": "### Data Flow Analysis\\n- **Source**: `req.body.email`",
        "snippet": "models.sequelize.query(...)",
        "vuln_type": "SQL Injection",
        "vuln_id": "CWE-89",
        "status": "OPEN",
        "start_line": 34,
        "end_line": 35
      },
      {
        "finding_id": "c0b70aa9-78b8-59f5-940a-6f3d9d3b6b6e",
        "session_id": "ChA5ODRmOWZiNDBhMTRmNDU0EAgaATAqBG1haW4",
        "title": "UNION SQL Injection in Product Search",
        "file_path": "/__w/juice-shop-local/juice-shop-local/juice-shop-local/routes/search.ts",
        "severity": "CRITICAL",
        "confidence": 100,
        "analysis": "### Data Flow Analysis\\n- **Source**: `req.query.q`",
        "snippet": "let criteria: any = req.query.q",
        "vuln_type": "SQL Injection",
        "vuln_id": "CWE-89",
        "status": "OPEN",
        "start_line": 21,
        "end_line": 24
      }
    ]"""
    findings = parse_findings_json(raw_json)
    self.assertEqual(len(findings), 2)
    first = findings[0]
    self.assertEqual(first["FindingID"], "a722cea6-dced-56fc-8b96-393c12834278")
    self.assertEqual(
        first["SessionID"], "ChA5ODRmOWZiNDBhMTRmNDU0EAgaATAqBG1haW4"
    )
    self.assertEqual(first["Title"], "SQL Injection in User Authentication")
    self.assertEqual(
        first["FilePath"],
        "/__w/juice-shop-local/juice-shop-local/juice-shop-local/routes/login.ts",
    )
    self.assertEqual(first["Severity"], "CRITICAL")
    self.assertEqual(first["Confidence"], 100)
    self.assertEqual(first["VulnType"], "SQL Injection")
    self.assertEqual(first["VulnID"], "CWE-89")
    self.assertEqual(first["Status"], "OPEN")
    self.assertEqual(first["StartLine"], 34)
    self.assertEqual(first["EndLine"], 35)
    # Original snake_case keys are retained for snake_case-aware consumers
    self.assertEqual(first["finding_id"], first["FindingID"])
    self.assertEqual(
        findings[1]["FindingID"], "c0b70aa9-78b8-59f5-940a-6f3d9d3b6b6e"
    )

  def test_parse_findings_json_pascal_case_wins_on_conflict(self):
    """Verify an explicit PascalCase key is never clobbered by its alias."""
    raw_json = """[
      {"FindingID": "pascal-wins", "finding_id": "snake-loses"}
    ]"""
    findings = parse_findings_json(raw_json)
    self.assertEqual(findings[0]["FindingID"], "pascal-wins")
    self.assertEqual(findings[0]["finding_id"], "snake-loses")

  @patch("codemender_agent.codemender.cli.run_command")
  def test_log_cm_version_success(self, mock_run_cmd):
    """Verify log_cm_version logs and returns version string on success."""
    mock_run_cmd.return_value = MagicMock(
        returncode=0,
        stdout="cm version v0.1.0-20260515-vMvg-916238397\n",
        stderr="",
    )
    version = log_cm_version("cm")
    self.assertEqual(version, "cm version v0.1.0-20260515-vMvg-916238397")
    mock_run_cmd.assert_called_once_with(
        ["cm", "--version"],
        cwd=None,
        env=None,
        check=False,
        capture_stderr=True,
    )

  @patch("codemender_agent.codemender.cli.run_command")
  def test_log_cm_version_failure(self, mock_run_cmd):
    """Verify log_cm_version handles command error gracefully."""
    mock_run_cmd.return_value = MagicMock(
        returncode=1,
        stdout="",
        stderr="command not found",
    )
    version = log_cm_version("cm")
    self.assertIsNone(version)

  @patch("codemender_agent.codemender.cli.run_command")
  def test_log_cm_version_exception(self, mock_run_cmd):
    """Verify log_cm_version handles execution exceptions gracefully."""
    mock_run_cmd.side_effect = RuntimeError("Execution failed")
    version = log_cm_version("cm")
    self.assertIsNone(version)


if __name__ == "__main__":
  unittest.main()

