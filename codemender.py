"""CodeMender CLI wrapper class and helpers."""

import enum
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from typing import Any, Dict, Iterable, List, Optional

from finding import Finding

logger = logging.getLogger("codemender")

_CI_GATE_BLOCKING = re.compile(r"CI Gate Failure:\s*\d+ blocking finding")
_CI_GATE_TRUNCATED = re.compile(r"CI Gate Failure:\s*Impact expansion truncated")


class ScanMode(str, enum.Enum):
  SHALLOW = "shallow"
  DEEP = "deep"
  DIFF = "diff"


def is_ci_gate_exit(returncode: int, find_stdout: str) -> bool:
  """Whether cm find exited 1 only because CI gate found blocking findings."""
  text = find_stdout or ""
  return (
      returncode == 1
      and bool(_CI_GATE_BLOCKING.search(text))
      and not _CI_GATE_TRUNCATED.search(text)
  )


def build_cm_command(
    cm_binary: str,
    action: str,
    target_or_id: Optional[str] = None,
    extra_flags: Optional[List[str]] = None,
) -> List[str]:
  """Centralized command builder for CodeMender CLI invocations."""
  if action == "find" and not target_or_id:
    raise ValueError(f"Action '{action}' requires a valid target or finding ID.")

  if action == "find":
    cmd = [cm_binary, "find", target_or_id]
    if extra_flags:
      cmd.extend(extra_flags)
  elif action == "init":
    cmd = [cm_binary, "init"]
    if extra_flags:
      cmd.extend(extra_flags)
  else:
    cmd = [cm_binary, action]
    if extra_flags:
      cmd.extend(extra_flags)
  return cmd


def run_command(
    cmd: List[str],
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    check: bool = True,
    print_to_stdout: bool = False,
) -> subprocess.CompletedProcess:
  """Executes a subprocess command, streaming stdout/stderr in real-time."""
  logger.info("Executing comand: %s", " ".join(cmd))

  process = subprocess.Popen(
      cmd,
      cwd=cwd,
      env=env,
      stdin=subprocess.DEVNULL,
      stdout=subprocess.PIPE,
      stderr=subprocess.STDOUT if print_to_stdout else subprocess.DEVNULL,
      text=True,
      bufsize=1,
  )

  stdout_lines = []
  for line in process.stdout:
    stdout_lines.append(line)
    if print_to_stdout:
      sys.stdout.write(line)
      sys.stdout.flush()
  process.stdout.close()

  return_code = process.wait()

  logger.info(f"Command completed with exit code {return_code}")

  if check and return_code != 0:
    logger.error("Command failed with code %d", return_code)
    raise subprocess.CalledProcessError(return_code, cmd, stdout_lines, "")

  return subprocess.CompletedProcess(cmd, return_code, "".join(stdout_lines), "")


def write_import_payload(findings: Iterable[Finding], dest_path: str) -> str:
  """Writes a simple-JSON import payload, keeping only recognized fields."""
  payload = []
  for f in findings:
    payload.append(f.to_cm_import_record())
  os.makedirs(os.path.dirname(os.path.abspath(dest_path)), exist_ok=True)
  with open(dest_path, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2)
  return dest_path


class CodeMender:
  """Encapsulates CodeMender CLI configuration and operations for a repository."""

  def __init__(
      self,
      cm_binary: str = "cm",
      repo_dir: str = ".",
      env: Optional[Dict[str, str]] = None,
  ) -> None:
    self.cm_binary = cm_binary
    self.repo_dir = repo_dir
    self.env = env

  def find(
      self,
      target_or_id: Optional[str] = None,
      scan_mode: ScanMode = ScanMode.SHALLOW,
  ) -> Any:
    """Runs the CodeMender find command on the target repository directory."""
    target = target_or_id if target_or_id is not None else self.repo_dir
    extra_flags: List[str] = []
    if scan_mode == ScanMode.DEEP:
      extra_flags.append("--deep")
    elif scan_mode == ScanMode.DIFF:
      extra_flags.append("--diff")
    command = build_cm_command(
        self.cm_binary,
        "find",
        target_or_id=target,
        extra_flags=extra_flags,
    )
    result = run_command(command, cwd=self.repo_dir, env=self.env, check=False, print_to_stdout=True)
    returncode = getattr(result, "returncode", 0)
    stdout = getattr(result, "stdout", "")
    if returncode and not is_ci_gate_exit(returncode, stdout or ""):
      raise RuntimeError(f"cm find failed with exit code {returncode}")
    return result

  def list_findings(
      self,
  ) -> List[Finding]:
    """Returns every finding currently in CodeMender state for this repo."""
    report_cmd = build_cm_command(
        self.cm_binary,
        "report",
        extra_flags=["--format", "json"],
    )
    res = run_command(
        report_cmd,
        cwd=self.repo_dir,
        env=self.env,
        check=False,
    )
    if res.returncode != 0:
      raise RuntimeError(
          f"'cm report --format json' exited {res.returncode}"
      )

    if (res.stdout or "").strip() == "null":
      return []

    json_findings = json.JSONDecoder().decode(res.stdout)

    return [Finding.from_dict(json_finding) for json_finding in json_findings]

  def import_findings(
      self,
      findings: Iterable[Finding],
  ) -> List[Finding]:
    """Imports findings, ignoring the duplicates. Returns the list of newly imported findings."""
    before_findings = self.list_findings()
    before_fingerprints = set([f.fingerprint for f in before_findings])
    findings_not_already_in_cm = [f for f in findings if f.fingerprint not in before_fingerprints]
    if len(findings_not_already_in_cm) == 0:
      return []

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_file:
      import_file = tmp_file.name

    try:
      write_import_payload(findings_not_already_in_cm, import_file)
      import_cmd = build_cm_command(
          self.cm_binary,
          "report",
          extra_flags=["import", "-f", import_file, "-p", self.repo_dir],
      )
      import_res = run_command(import_cmd, cwd=self.repo_dir, env=self.env, check=False)
    finally:
      if os.path.exists(import_file):
        os.remove(import_file)

    if import_res.returncode != 0:
      raise RuntimeError(
          f"'cm report import' exited {import_res.returncode}"
      )

    return findings_not_already_in_cm