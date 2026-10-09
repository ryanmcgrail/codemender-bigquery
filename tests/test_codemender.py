"""Unit tests for codemender.py."""

import types
import unittest
from unittest.mock import patch

from codemender import CodeMender, run_cm_find
from finding import Finding


class CodeMenderTests(unittest.TestCase):

  def test_init_defaults(self):
    cm = CodeMender()
    self.assertEqual(cm.cm_binary, "cm")
    self.assertEqual(cm.repo_dir, ".")
    self.assertIsNone(cm.cli_version)
    self.assertIsNone(cm.env)

  def test_init_custom(self):
    cm = CodeMender(
        cm_binary="/custom/cm",
        repo_dir="/custom/repo",
        cli_version="preview",
        env={"CUSTOM_VAR": "val"},
    )
    self.assertEqual(cm.cm_binary, "/custom/cm")
    self.assertEqual(cm.repo_dir, "/custom/repo")
    self.assertEqual(cm.cli_version, "preview")
    self.assertEqual(cm.env, {"CUSTOM_VAR": "val"})

  def test_find_defaults_to_repo_dir(self):
    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo", cli_version="preview")
    proc = types.SimpleNamespace(returncode=0, stdout="Success")
    with patch("codemender.finder.run_command", return_value=proc) as mock_run:
      res = cm.find()
      mock_run.assert_called_once()
      args, kwargs = mock_run.call_args
      cmd = args[0]
      self.assertEqual(cmd[0], "cm")
      self.assertEqual(cmd[1], "find")
      self.assertEqual(cmd[-1], "/tmp/test_repo")
      self.assertEqual(kwargs.get("cwd"), "/tmp/test_repo")
      self.assertEqual(res, proc)

  def test_find_custom_target_and_extra_flags(self):
    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo", cli_version="preview")
    proc = types.SimpleNamespace(returncode=0, stdout="Success")
    with patch("codemender.finder.run_command", return_value=proc) as mock_run:
      cm.find(target_or_id="/tmp/other_target")
      args, kwargs = mock_run.call_args
      cmd = args[0]
      self.assertEqual(cmd[-1], "/tmp/other_target")

  def test_find_handles_ci_gate_exit(self):
    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo", cli_version="preview")
    proc = types.SimpleNamespace(
        returncode=1,
        stdout="CI Gate Failure: 2 blocking finding(s) detected.",
    )
    with patch("codemender.finder.run_command", return_value=proc):
      # Should not raise exception
      cm.find()

  def test_find_raises_on_fatal_error(self):
    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo", cli_version="preview")
    proc = types.SimpleNamespace(returncode=2, stdout="Fatal error")
    with patch("codemender.finder.run_command", return_value=proc):
      with self.assertRaises(RuntimeError):
        cm.find()

  def test_run_find_alias(self):
    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo")
    self.assertEqual(cm.run_find, cm.find)
    self.assertEqual(cm.run_cm_find, cm.find)

  def test_report(self):
    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo", cli_version="preview")
    mock_findings = [Finding(finding_id="f-1", title="Issue 1")]
    with patch("codemender.finder.fetch_findings_from_cm_report", return_value=mock_findings) as mock_report:
      res = cm.report()
      self.assertEqual(res, mock_findings)
      mock_report.assert_called_once_with(
          "cm", "/tmp/test_repo", env=None, cli_version="preview"
      )

  def test_import_findings(self):
    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo", cli_version="preview")
    mock_findings = [Finding(finding_id="f-1", title="Issue 1")]
    with patch("codemender.finder.import_findings", return_value=(["f-1"], mock_findings)) as mock_import:
      assigned, findings = cm.import_findings("/tmp/payload.json")
      self.assertEqual(assigned, ["f-1"])
      self.assertEqual(findings, mock_findings)
      mock_import.assert_called_once_with(
          "cm", "/tmp/payload.json", "/tmp/test_repo", env=None, cli_version="preview"
      )

  def test_actions(self):
    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo", cli_version="preview")
    with patch("codemender.finder.run_cm_action", return_value=0) as mock_action:
      self.assertEqual(cm.verify("f-1"), 0)
      mock_action.assert_called_with(
          "verify", "f-1", "cm", "/tmp/test_repo", cli_version="preview"
      )

      self.assertEqual(cm.fix("f-2"), 0)
      mock_action.assert_called_with(
          "fix", "f-2", "cm", "/tmp/test_repo", cli_version="preview"
      )

  def test_module_run_cm_find(self):
    proc = types.SimpleNamespace(returncode=0, stdout="OK")
    with patch("codemender.finder.run_command", return_value=proc) as mock_run:
      run_cm_find("cm", "/tmp/repo", cli_version="preview")
      mock_run.assert_called_once()


if __name__ == "__main__":
  unittest.main()

