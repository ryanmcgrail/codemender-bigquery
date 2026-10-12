"""Unit tests for codemender.py."""

import json
import os
import tempfile
import types
import unittest
from unittest.mock import patch

import codemender
from codemender import CodeMender
from finding import Finding


class CodeMenderTests(unittest.TestCase):

  def test_is_ci_gate_exit_blocking(self):
    stdout = "CI Gate Failure: 2 blocking finding(s) detected."
    self.assertTrue(codemender.is_ci_gate_exit(1, stdout))

  def test_is_ci_gate_exit_truncated(self):
    stdout = "CI Gate Failure: 2 blocking finding(s) detected. CI Gate Failure: Impact expansion truncated"
    self.assertFalse(codemender.is_ci_gate_exit(1, stdout))

  def test_is_ci_gate_exit_success(self):
    stdout = "CI Gate Failure: 2 blocking finding"
    self.assertFalse(codemender.is_ci_gate_exit(0, stdout))

  def test_build_cm_command_find(self):
    cmd = codemender.build_cm_command(
        cm_binary="/usr/bin/cm",
        action="find",
        target_or_id="/tmp/repo",
    )
    self.assertEqual(cmd, ["/usr/bin/cm", "find", "/tmp/repo"])

  def test_build_cm_command_requires_target(self):
    with self.assertRaises(ValueError):
      codemender.build_cm_command(cm_binary="cm", action="find", target_or_id=None)

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
      written = codemender.write_import_payload(findings, dest)
      self.assertEqual(written, dest)
      with open(dest, "r", encoding="utf-8") as f:
        loaded = json.load(f)
      self.assertEqual(len(loaded), 1)
      self.assertEqual(loaded[0]["file_path"], "src/main.py")
      self.assertNotIn("unexpected", loaded[0])

  def test_init_defaults(self):
    cm = CodeMender()
    self.assertEqual(cm.cm_binary, "cm")
    self.assertEqual(cm.repo_dir, ".")
    self.assertIsNone(cm.env)

  def test_init_custom(self):
    cm = CodeMender(
        cm_binary="/custom/cm",
        repo_dir="/custom/repo",
        env={"CUSTOM_VAR": "val"},
    )
    self.assertEqual(cm.cm_binary, "/custom/cm")
    self.assertEqual(cm.repo_dir, "/custom/repo")
    self.assertEqual(cm.env, {"CUSTOM_VAR": "val"})

  def test_find_defaults_to_repo_dir(self):
    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo")
    proc = types.SimpleNamespace(returncode=0, stdout="Success")
    with patch("codemender.run_command", return_value=proc) as mock_run:
      res = cm.find()
      mock_run.assert_called_once()
      args, kwargs = mock_run.call_args
      cmd = args[0]
      self.assertEqual(cmd, ["cm", "find", "/tmp/test_repo"])
      self.assertEqual(kwargs.get("cwd"), "/tmp/test_repo")
      self.assertEqual(res, proc)

  def test_find_custom_target(self):
    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo")
    proc = types.SimpleNamespace(returncode=0, stdout="Success")
    with patch("codemender.run_command", return_value=proc) as mock_run:
      cm.find(target_or_id="/tmp/other_target")
      args, _ = mock_run.call_args
      cmd = args[0]
      self.assertEqual(cmd[-1], "/tmp/other_target")

  def test_find_handles_ci_gate_exit(self):
    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo")
    proc = types.SimpleNamespace(
        returncode=1,
        stdout="CI Gate Failure: 2 blocking finding(s) detected.",
    )
    with patch("codemender.run_command", return_value=proc):
      cm.find()

  def test_find_raises_on_fatal_error(self):
    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo")
    proc = types.SimpleNamespace(returncode=2, stdout="Fatal error")
    with patch("codemender.run_command", return_value=proc):
      with self.assertRaises(RuntimeError):
        cm.find()

  def test_list_findings(self):
    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo")
    raw = json.dumps([{"FindingID": "cm-99"}])
    proc = types.SimpleNamespace(returncode=0, stdout=raw)
    with patch("codemender.run_command", return_value=proc):
      findings = cm.list_findings()
    self.assertEqual(len(findings), 1)
    self.assertEqual(findings[0].finding_id, "cm-99")

  def test_import_findings(self):
    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo")
    before_raw = json.dumps([{"FindingID": "cm-1", "Fingerprint": "fp-1"}])
    after_raw = json.dumps([{"FindingID": "cm-1", "Fingerprint": "fp-1"}, {"FindingID": "cm-2", "Fingerprint": "fp-2"}])
    proc_before = types.SimpleNamespace(returncode=0, stdout=before_raw)
    proc_import = types.SimpleNamespace(returncode=0, stdout="Imported")
    proc_after = types.SimpleNamespace(returncode=0, stdout=after_raw)
    to_import = [Finding(finding_id="f-2", fingerprint="fp-2", file_path="src/main.py", title="Bug")]

    with patch("codemender.run_command", side_effect=[proc_before, proc_import, proc_after]) as mock_run:
      assigned, after = cm.import_findings(to_import)
    self.assertEqual(assigned, ["cm-2"])
    self.assertEqual(len(after), 2)
    import_cmd = mock_run.call_args_list[1].args[0]
    temp_file_path = import_cmd[import_cmd.index("-f") + 1]
    self.assertFalse(os.path.exists(temp_file_path))


if __name__ == "__main__":
  unittest.main()
