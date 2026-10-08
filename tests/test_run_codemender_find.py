"""Unit tests for standalone run_codemender_find.py."""

import json
import os
import subprocess
import tempfile
import types
import unittest
from unittest.mock import MagicMock, patch

import step_2_cm_find as finder


class RunCodeMenderFindTests(unittest.TestCase):

  def test_is_ci_gate_exit_blocking(self):
    stdout = "CI Gate Failure: 2 blocking finding(s) detected."
    self.assertTrue(finder.is_ci_gate_exit(1, stdout))

  def test_is_ci_gate_exit_truncated(self):
    stdout = "CI Gate Failure: 2 blocking finding(s) detected. CI Gate Failure: Impact expansion truncated"
    self.assertFalse(finder.is_ci_gate_exit(1, stdout))

  def test_is_ci_gate_exit_success(self):
    stdout = "CI Gate Failure: 2 blocking finding"
    self.assertFalse(finder.is_ci_gate_exit(0, stdout))

  def test_redact_sensitive_arg(self):
    self.assertEqual(
        finder.redact_sensitive_arg("http.extraheader=AUTHORIZATION: secret"),
        "[REDACTED_SECRET]",
    )
    self.assertEqual(
        finder.redact_sensitive_arg("ghp_1234567890abcdef"),
        "[REDACTED_SECRET]",
    )
    self.assertEqual(finder.redact_sensitive_arg("--repo-dir=/app"), "--repo-dir=/app")

  def test_parse_token_metric(self):
    self.assertEqual(finder.parse_token_metric("1.5k"), 1500)
    self.assertEqual(finder.parse_token_metric("2m"), 2000000)
    self.assertEqual(finder.parse_token_metric("500"), 500)
    with self.assertRaises(ValueError):
      finder.parse_token_metric("")

  def test_build_cm_command_find(self):
    cmd = finder.build_cm_command(
        cm_binary="/usr/bin/cm",
        action="find",
        target_or_id="/tmp/repo",
        cli_version="preview",
    )
    self.assertEqual(cmd[0], "/usr/bin/cm")
    self.assertEqual(cmd[1], "find")
    self.assertIn("-y", cmd)
    self.assertEqual(cmd[-1], "/tmp/repo")

  def test_build_cm_command_requires_target(self):
    with self.assertRaises(ValueError):
      finder.build_cm_command(cm_binary="cm", action="find", target_or_id=None)

  def test_extract_json_from_output(self):
    raw = "Some log line before\n{\"findings\": [{\"FindingID\": \"1\"}]}\nSome log after"
    data = finder.extract_json_from_output(raw)
    self.assertEqual(data, {"findings": [{"FindingID": "1"}]})
    self.assertIsNone(finder.extract_json_from_output(""))
    self.assertIsNone(finder.extract_json_from_output("no json here"))

  def test_parse_findings_json(self):
    raw = json.dumps([{"finding_id": "f-1", "file_path": "a.py", "title": "SQLi"}])
    parsed = finder._parse_findings_json(raw)
    self.assertEqual(len(parsed), 1)
    self.assertIsInstance(parsed[0], finder.Finding)
    self.assertEqual(parsed[0].finding_id, "f-1")
    self.assertEqual(parsed[0].file_path, "a.py")
    self.assertEqual(parsed[0].title, "SQLi")
    self.assertEqual(parsed[0]["FindingID"], "f-1")
    self.assertEqual(parsed[0]["FilePath"], "a.py")
    self.assertEqual(parsed[0]["Title"], "SQLi")

  def test_write_import_payload(self):
    findings = [
        {
            "file_path": "src/main.py",
            "line": 10,
            "end_line": 12,
            "title": "Bug",
            "message": "Bad code",
            "severity": "HIGH",
            "vuln_type": "Injection",
            "snippet": "code()",
            "unexpected": "ignore",
        }
    ]
    with tempfile.TemporaryDirectory() as tmpdir:
      dest = os.path.join(tmpdir, "payload.json")
      written = finder.write_import_payload(findings, dest)
      self.assertEqual(written, dest)
      with open(dest, "r", encoding="utf-8") as f:
        loaded = json.load(f)
      self.assertEqual(len(loaded), 1)
      self.assertEqual(loaded[0]["file_path"], "src/main.py")
      self.assertNotIn("unexpected", loaded[0])

  def test_run_cm_find_success(self):
    proc = types.SimpleNamespace(returncode=0, stdout="All clear")
    with patch.object(finder, "run_command", return_value=proc) as mock_run:
      finder.run_cm_find("cm", "/tmp/repo", cli_version="preview")
    mock_run.assert_called_once()

  def test_run_cm_find_handles_ci_gate_exit(self):
    proc = types.SimpleNamespace(
        returncode=1,
        stdout="CI Gate Failure: 1 blocking finding",
    )
    with patch.object(finder, "run_command", return_value=proc):
      # Should not raise exception
      finder.run_cm_find("cm", "/tmp/repo", cli_version="preview")

  def test_run_cm_find_raises_on_fatal_error(self):
    proc = types.SimpleNamespace(returncode=2, stdout="Fatal execution error")
    with patch.object(finder, "run_command", return_value=proc):
      with self.assertRaises(RuntimeError):
        finder.run_cm_find("cm", "/tmp/repo", cli_version="preview")

  def test_match_cm_findings_to_source_rows(self):
    source_rows = [
        {
            "repository": "acme/repo",
            "finding_id": "bq-1",
            "file_path": "app.py",
            "start_line": 20,
            "title": "XSS",
            "vuln_type": "Cross-Site Scripting",
        }
    ]
    cm_findings = [
        {
            "FindingID": "cm-1",
            "FilePath": "app.py",
            "StartLine": 20,
            "Title": "XSS",
            "VulnType": "Cross-Site Scripting",
        }
    ]
    matches = finder._match_cm_findings_to_source_rows(
        source_rows, cm_findings, "/tmp/repo", required_cm_ids=["cm-1"]
    )
    self.assertEqual(matches, {"cm-1": "bq-1"})

  def test_read_findings(self):
    raw = json.dumps({"findings": [{"FindingID": "cm-99"}]})
    proc = types.SimpleNamespace(returncode=0, stdout=raw)
    with patch.object(finder, "run_command", return_value=proc):
      findings = finder.read_findings("cm", "/tmp/repo")
    self.assertEqual(len(findings), 1)
    self.assertEqual(findings[0]["FindingID"], "cm-99")

  def test_import_findings(self):
    before_raw = json.dumps({"findings": [{"FindingID": "cm-1"}]})
    after_raw = json.dumps({"findings": [{"FindingID": "cm-1"}, {"FindingID": "cm-2"}]})
    proc_before = types.SimpleNamespace(returncode=0, stdout=before_raw)
    proc_import = types.SimpleNamespace(returncode=0, stdout="Imported")
    proc_after = types.SimpleNamespace(returncode=0, stdout=after_raw)

    with tempfile.NamedTemporaryFile() as tmp:
      with patch.object(finder, "run_command", side_effect=[proc_before, proc_import, proc_after]):
        assigned, after = finder.import_findings("cm", tmp.name, "/tmp/repo")
      self.assertEqual(assigned, ["cm-2"])
      self.assertEqual(len(after), 2)


if __name__ == "__main__":
  unittest.main()

