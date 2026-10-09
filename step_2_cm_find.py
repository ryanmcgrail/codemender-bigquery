import json
import logging
import os
import re
import shlex
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Sequence, Tuple

from finding import Finding

logger = logging.getLogger("run-codemender-find")

_CI_GATE_BLOCKING = re.compile(r"CI Gate Failure:\s*\d+ blocking finding")
_CI_GATE_TRUNCATED = re.compile(r"CI Gate Failure:\s*Impact expansion truncated")


def is_ci_gate_exit(returncode: int, find_stdout: str) -> bool:
  """Whether cm find exited 1 only because CI gate found blocking findings."""
  text = find_stdout or ""
  return (
      returncode == 1
      and bool(_CI_GATE_BLOCKING.search(text))
      and not _CI_GATE_TRUNCATED.search(text)
  )


def parse_token_metric(token_str: str) -> int:
  """Converts human-readable token metric strings with SI suffixes into integers."""
  token_str = token_str.strip()
  if not token_str:
    raise ValueError("Empty token metric string.")
  unit_multipliers = {
      "k": 1000,
      "m": 1000000,
      "g": 1000000000,
  }
  last_char = token_str[-1].lower()
  if last_char in unit_multipliers:
    val = float(token_str[:-1])
    return int(val * unit_multipliers[last_char])
  return int(float(token_str))


_HELP_FLAG_LINE = re.compile(
    r"^\s*(?:-(?P<short>[A-Za-z0-9]),\s+)?--(?P<long>[A-Za-z0-9][\w-]*)"
    r"(?P<value> (?![ -])\S+)?"
)
_SUPPORTED_FLAGS_CACHE: Dict[Tuple[str, str], Optional[Dict[str, bool]]] = {}
_RESERVED_FLAGS = frozenset({"--model", "--unrestricted"})
_BLOCKED_FLAGS = frozenset({"-h", "--help"})


def resolve_command_model(command_name: str) -> Optional[str]:
  """Implements model precedence hierarchy: CODEMENDER_<COMMAND>_MODEL > CODEMENDER_MODEL > None."""
  cmd_override = (
      os.environ.get(f"CODEMENDER_{command_name.upper()}_MODEL") or ""
  ).strip()
  if cmd_override:
    return cmd_override
  model = (os.environ.get("CODEMENDER_MODEL") or "").strip()
  return model or None


def parse_help_flags(help_text: str) -> Dict[str, bool]:
  """Parses `cm <action> --help` output into {flag: takes_value}."""
  flags: Dict[str, bool] = {}
  in_flags = False
  for line in (help_text or "").splitlines():
    stripped = line.strip()
    if stripped.endswith("Flags:"):
      in_flags = True
      continue
    if not in_flags or not stripped.startswith("-"):
      continue
    match = _HELP_FLAG_LINE.match(line)
    if not match:
      continue
    value = (match.group("value") or "").strip()
    takes_value = bool(value) and "[=" not in value
    flags[f"--{match.group('long')}"] = takes_value
    if match.group("short"):
      flags[f"-{match.group('short')}"] = takes_value
  return flags


def get_supported_cm_flags(
    cm_binary: str, action: str, env: Optional[Dict[str, str]] = None
) -> Optional[Dict[str, bool]]:
  """Returns the flags `cm <action>` accepts, or None when help is unavailable."""
  key = (cm_binary, action)
  if key in _SUPPORTED_FLAGS_CACHE:
    return _SUPPORTED_FLAGS_CACHE[key]
  flags: Optional[Dict[str, bool]] = None
  try:
    res = subprocess.run(
        [cm_binary, action, "--help"],
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    parsed = parse_help_flags((res.stdout or "") + "\n" + (res.stderr or ""))
    flags = parsed or None
  except (OSError, subprocess.SubprocessError) as e:
    logger.warning("Could not read '%s %s --help': %s", cm_binary, action, e)
  _SUPPORTED_FLAGS_CACHE[key] = flags
  return flags


def filter_supported_flags(
    flags: List[str], supported: Optional[Dict[str, bool]], action: str
) -> List[str]:
  """Drops configured flags that must not or cannot be passed to cm."""
  kept: List[str] = []
  i = 0
  while i < len(flags):
    token = flags[i]
    i += 1
    if not token.startswith("-"):
      continue
    name = token.split("=", 1)[0]
    takes_value = supported.get(name) if supported is not None else None
    if "=" in token or takes_value is False:
      has_separate_value = False
    elif takes_value:
      has_separate_value = i < len(flags)
      if not has_separate_value and name not in _RESERVED_FLAGS:
        continue
    else:
      has_separate_value = i < len(flags) and not flags[i].startswith("-")
    if name in _BLOCKED_FLAGS:
      if has_separate_value:
        i += 1
      continue
    if name in _RESERVED_FLAGS or (supported is not None and takes_value is None):
      if has_separate_value:
        i += 1
      continue
    kept.append(token)
    if has_separate_value:
      kept.append(flags[i])
      i += 1
  return kept


def resolve_command_flags(command_name: str) -> List[str]:
  """Extra cm flags configured for one command via CODEMENDER_<COMMAND>_FLAGS."""
  raw = (os.environ.get(f"CODEMENDER_{command_name.upper()}_FLAGS") or "").strip()
  if not raw:
    return []
  try:
    return shlex.split(raw)
  except ValueError:
    return []


def build_cm_command(
    cm_binary: str,
    action: str,
    target_or_id: Optional[str] = None,
    cli_version: Optional[str] = None,
    extra_flags: Optional[List[str]] = None,
) -> List[str]:
  """Centralized command builder for CodeMender CLI invocations."""
  if cli_version is None:
    cli_version = os.environ.get("CODEMENDER_CLI_VERSION", "preview").lower()
  else:
    cli_version = cli_version.lower()

  if action in ["find", "verify", "fix"] and not target_or_id:
    raise ValueError(f"Action '{action}' requires a valid target or finding ID.")

  if cli_version == "preview":
    model = resolve_command_model(action)
    model_flags = ["--model", model] if model else []
    unrestricted_flag = (
        ["--unrestricted"]
        if os.environ.get("CODEMENDER_SANDBOX_ENABLED", "true").strip().lower()
        in ("false", "0", "no", "off")
        else []
    )
    passthrough_flags: List[str] = []
    if action in ("find", "verify", "fix"):
      requested = list(extra_flags or []) + resolve_command_flags(action)
      if requested:
        passthrough_flags = filter_supported_flags(
            requested, get_supported_cm_flags(cm_binary, action), action
        )

    if action == "find":
      cmd = (
          [cm_binary, "find", "-y"]
          + model_flags
          + passthrough_flags
          + [target_or_id]
      )
    elif action == "verify":
      skip_flag = (
          ["--skip-exploit-verification"]
          if os.environ.get("CODEMENDER_SKIP_EXPLOIT_VERIFICATION", "").lower() == "true"
          else []
      )
      cmd = (
          [cm_binary, "verify", "-y", "--bypass-warning"]
          + unrestricted_flag
          + model_flags
          + skip_flag
          + passthrough_flags
          + [target_or_id]
      )
    elif action == "fix":
      cmd = (
          [cm_binary, "fix", "-y", "--bypass-warning"]
          + unrestricted_flag
          + model_flags
          + passthrough_flags
          + [target_or_id]
      )
    elif action == "init":
      cmd = [cm_binary, "init"]
      if extra_flags:
        cmd.extend(extra_flags)
    else:
      cmd = [cm_binary, action]
      if extra_flags:
        cmd.extend(extra_flags)
  else:
    if action == "find":
      cmd = [cm_binary, "find", target_or_id]
    elif action == "verify":
      cmd = [cm_binary, "find", "verify", target_or_id, "--yes"]
    elif action == "fix":
      cmd = [cm_binary, "fix", target_or_id, "--yes"]
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


class FindingImportError(RuntimeError):
  """Raised when the import round-trip cannot establish the assigned IDs."""


IMPORTED_FINDING_FIELDS = (
    "file_path",
    "line",
    "end_line",
    "title",
    "message",
    "severity",
    "vuln_type",
    "snippet",
)


def fetch_findings_from_cm_report(
    cm_binary: str,
    repo_dir: str,
    env: Optional[Dict[str, str]] = None,
    cli_version: Optional[str] = None,
) -> List[Finding]:
  """Returns every finding currently in the CodeMender state."""
  report_cmd = build_cm_command(
      cm_binary,
      "report",
      extra_flags=["--format", "json"],
      cli_version=cli_version,
  )
  res = run_command(
      report_cmd,
      cwd=repo_dir,
      env=env,
      check=False,
  )
  if res.returncode != 0:
    raise FindingImportError(
        f"'cm report --format json' exited {res.returncode}"
    )

  if (res.stdout or "").strip() == "null":
    return []

  json_findings = json.JSONDecoder().decode(res.stdout)

  return [Finding.from_dict(json_finding) for json_finding in json_findings]


def _ids(findings: Sequence[Any]) -> List[str]:
  res = []
  for f in findings:
    if isinstance(f, Finding):
      fid = f.finding_id
    elif hasattr(f, "get"):
      fid = str(f.get("FindingID") or f.get("finding_id") or "")
    else:
      fid = str(getattr(f, "finding_id", ""))
    if fid:
      res.append(fid)
  return res


def import_findings(
    cm_binary: str,
    findings: Sequence[Finding],
    repo_dir: str,
    env: Optional[Dict[str, str]] = None,
    cli_version: Optional[str] = None,
) -> Tuple[List[str], List[Finding]]:
  """Imports findings and returns the IDs cm assigned them."""
  before_findings = fetch_findings_from_cm_report(cm_binary, repo_dir, env, cli_version)
  before_ids = set(_ids(before_findings))

  before_fingerprints = set([f.fingerprint for f in before_findings])
  findings_not_already_in_cm = [f for f in findings if f.fingerprint not in before_fingerprints]
  if len(findings_not_already_in_cm) == 0:
    return [], [];

  with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_file:
    import_file = tmp_file.name

  try:
    write_import_payload(findings_not_already_in_cm, import_file)
    import_cmd = build_cm_command(
        cm_binary,
        "report",
        extra_flags=["import", "-f", import_file, "-p", repo_dir],
        cli_version=cli_version,
    )
    import_res = run_command(import_cmd, cwd=repo_dir, env=env, check=False)
  finally:
    if os.path.exists(import_file):
      os.remove(import_file)

  if import_res.returncode != 0:
    raise FindingImportError(
        f"'cm report import' exited {import_res.returncode}"
    )

  after_findings = fetch_findings_from_cm_report(cm_binary, repo_dir, env, cli_version)
  assigned = [fid for fid in _ids(after_findings) if fid not in before_ids]
  if not assigned:
    raise FindingImportError(
        "'cm report import' exited 0 but the finding set is unchanged, so no"
        " imported finding ID could be resolved"
    )
  logger.info("Import round-trip: cm assigned %d finding ID(s).", len(assigned))
  return assigned, after_findings


def write_import_payload(findings: Sequence[Any], dest_path: str) -> str:
  """Writes a simple-JSON import payload, keeping only recognized fields."""
  payload = []
  for f in findings:
    if isinstance(f, Finding):
      payload.append(f.to_cm_import_record())
    elif hasattr(f, "__getitem__"):
      payload.append({k: f[k] for k in IMPORTED_FINDING_FIELDS if k in f})
    else:
      payload.append({k: getattr(f, k) for k in IMPORTED_FINDING_FIELDS if hasattr(f, k)})
  os.makedirs(os.path.dirname(os.path.abspath(dest_path)), exist_ok=True)
  with open(dest_path, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2)
  return dest_path


def run_cm_find(
    cm_binary: str, repo_dir: str, cli_version: Optional[str] = None
) -> None:
  """Runs the CodeMender find command on the target repository directory."""
  command = build_cm_command(
      cm_binary, "find", target_or_id=repo_dir, cli_version=cli_version
  )
  result = run_command(command, cwd=repo_dir, check=False, print_to_stdout=True)
  returncode = getattr(result, "returncode", 0)
  stdout = getattr(result, "stdout", "")
  if returncode and not is_ci_gate_exit(returncode, stdout or ""):
    raise RuntimeError(f"cm find failed with exit code {returncode}")


_run_cm_find = run_cm_find


def run_cm_action(
    action: str,
    finding_id: str,
    cm_binary: str,
    repo_dir: str,
    cli_version: Optional[str] = None,
) -> int:
  """Runs an arbitrary CodeMender action (verify, fix, etc.) on a finding ID."""
  command = build_cm_command(
      cm_binary, action, target_or_id=finding_id, cli_version=cli_version
  )
  result = run_command(command, cwd=repo_dir, check=False)
  returncode = getattr(result, "returncode", 0)
  if returncode != 0:
    logger.warning("cm %s failed for finding %s (exit %s).", action, finding_id, returncode)
  return returncode


_run_cm_action = run_cm_action