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

  def test_read_findings(self):
    raw = json.dumps({"findings": [{"FindingID": "cm-99"}]})
    proc = types.SimpleNamespace(returncode=0, stdout=raw)
    with patch.object(finder, "run_command", return_value=proc):
      findings = finder.fetch_findings_from_cm_report("cm", "/tmp/repo")
    self.assertEqual(len(findings), 1)
    self.assertEqual(findings[0].finding_id, "cm-99")
    with self.assertRaises(TypeError):
      _ = findings[0]["FindingID"]

  def test_import_findings(self):
    before_raw = json.dumps({"findings": [{"FindingID": "cm-1"}]})
    after_raw = json.dumps({"findings": [{"FindingID": "cm-1"}, {"FindingID": "cm-2"}]})
    proc_before = types.SimpleNamespace(returncode=0, stdout=before_raw)
    proc_import = types.SimpleNamespace(returncode=0, stdout="Imported")
    proc_after = types.SimpleNamespace(returncode=0, stdout=after_raw)
    to_import = [finder.Finding(finding_id="f-2", file_path="src/main.py", title="Bug")]

    with patch.object(finder, "run_command", side_effect=[proc_before, proc_import, proc_after]) as mock_run:
      assigned, after = finder.import_findings("cm", to_import, "/tmp/repo")
    self.assertEqual(assigned, ["cm-2"])
    self.assertEqual(len(after), 2)
    import_cmd = mock_run.call_args_list[1].args[0]
    temp_file_path = import_cmd[import_cmd.index("-f") + 1]
    self.assertFalse(os.path.exists(temp_file_path))


if __name__ == "__main__":
  unittest.main()

