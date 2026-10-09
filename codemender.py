"""CodeMender CLI wrapper class and helpers."""

import logging
import os
from typing import Any, Dict, List, Optional, Sequence, Tuple

from finding import Finding
import step_2_cm_find as finder

logger = logging.getLogger("codemender")


class CodeMender:
  """Encapsulates CodeMender CLI configuration and operations for a repository."""

  def __init__(
      self,
      cm_binary: str = "cm",
      repo_dir: str = ".",
      cli_version: Optional[str] = None,
      env: Optional[Dict[str, str]] = None,
  ) -> None:
    self.cm_binary = cm_binary
    self.repo_dir = repo_dir
    self.cli_version = cli_version
    self.env = env

  def find(
      self,
      target_or_id: Optional[str] = None,
      extra_flags: Optional[List[str]] = None,
      env: Optional[Dict[str, str]] = None,
  ) -> Any:
    """Runs the CodeMender find command on the target repository directory."""
    target = target_or_id if target_or_id is not None else self.repo_dir
    command = finder.build_cm_command(
        self.cm_binary,
        "find",
        target_or_id=target,
        cli_version=self.cli_version,
        extra_flags=extra_flags,
    )
    run_env = env if env is not None else self.env
    result = finder.run_command(command, cwd=self.repo_dir, env=run_env, check=False)
    returncode = getattr(result, "returncode", 0)
    stdout = getattr(result, "stdout", "")
    if returncode and not finder.is_ci_gate_exit(returncode, stdout or ""):
      raise RuntimeError(f"cm find failed with exit code {returncode}")
    return result

  run_find = find
  run_cm_find = find

  def report(
      self,
      env: Optional[Dict[str, str]] = None,
  ) -> List[Finding]:
    """Returns every finding currently in CodeMender state for this repo."""
    run_env = env if env is not None else self.env
    return finder.fetch_findings_from_cm_report(
        self.cm_binary,
        self.repo_dir,
        env=run_env,
        cli_version=self.cli_version,
    )

  fetch_findings = report
  read_findings = report

  def import_findings(
      self,
      import_file: str,
      env: Optional[Dict[str, str]] = None,
  ) -> Tuple[List[str], List[Finding]]:
    """Imports findings from a file into CodeMender."""
    run_env = env if env is not None else self.env
    return finder.import_findings(
        self.cm_binary,
        import_file,
        self.repo_dir,
        env=run_env,
        cli_version=self.cli_version,
    )

  def run_action(
      self,
      action: str,
      finding_id: str,
  ) -> int:
    """Runs an arbitrary CodeMender action (verify, fix, etc.) on a finding ID."""
    return finder.run_cm_action(
        action,
        finding_id,
        self.cm_binary,
        self.repo_dir,
        cli_version=self.cli_version,
    )

  def verify(self, finding_id: str) -> int:
    """Runs CodeMender verify on a finding ID."""
    return self.run_action("verify", finding_id)

  def fix(self, finding_id: str) -> int:
    """Runs CodeMender fix on a finding ID."""
    return self.run_action("fix", finding_id)


def run_cm_find(
    cm_binary: str, repo_dir: str, cli_version: Optional[str] = None
) -> None:
  """Runs the CodeMender find command on the target repository directory."""
  cm = CodeMender(cm_binary=cm_binary, repo_dir=repo_dir, cli_version=cli_version)
  cm.find()

