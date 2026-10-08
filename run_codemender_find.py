"""Run CodeMender find and interact with CodeMender CLI.

This module provides standalone functionality to run CodeMender's `find`
command, read findings from the local CodeMender state, import findings,
and match findings between external sources and CodeMender findings.

Example usage:
  python run_codemender_find.py --repo-dir ~/juice-shop
"""

import argparse
import json
import logging
import os
from pprint import pprint
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from fetch_bigquery_findings import (
    _finding_id,
    _finding_value,
    _int_or_none,
    _is_repo_finding,
    _row_key,
    _text,
    normalize_repo_relative_path,
)

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


SECRET_PATTERNS = [
    re.compile(r"http\.extraheader=AUTHORIZATION:.*", re.IGNORECASE),
    re.compile(r"(ghp_|ghs_|github_pat_|bearer\s+)[a-zA-Z0-9_\-\.]+", re.IGNORECASE),
]


def redact_sensitive_arg(arg: str) -> str:
  """Redacts secret credentials from command argument strings for log safety."""
  for pattern in SECRET_PATTERNS:
    if pattern.search(arg):
      return pattern.sub("[REDACTED_SECRET]", arg)
  return arg


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
    capture_stderr: bool = True,
) -> subprocess.CompletedProcess:
  """Executes a subprocess command, streaming stdout/stderr in real-time."""
  log_cmd_parts = [redact_sensitive_arg(arg) for arg in cmd]
  cmd_str_short = " ".join(log_cmd_parts)
  if len(cmd_str_short) > 80:
    cmd_str_short = cmd_str_short[:77] + "..."

  logger.info("Executing command: %s", " ".join(log_cmd_parts))

  process = subprocess.Popen(
      cmd,
      cwd=cwd,
      env=env,
      stdin=subprocess.DEVNULL,
      stdout=subprocess.PIPE,
      stderr=subprocess.STDOUT if capture_stderr else sys.stderr,
      text=True,
      bufsize=1,
  )

  assert process.stdout is not None
  sys.stdout.write(f"\n>>> [SUBPROCESS START] {cmd_str_short} >>>\n")
  sys.stdout.flush()

  stdout_lines = []
  for line in process.stdout:
    sys.stdout.write(redact_sensitive_arg(line))
    sys.stdout.flush()
    stdout_lines.append(line)

  process.stdout.close()
  return_code = process.wait()
  full_stdout = "".join(stdout_lines)

  sys.stdout.write(
      f"<<< [SUBPROCESS END] {cmd_str_short} (EXIT: {return_code}) <<<\n\n"
  )
  sys.stdout.flush()

  if check and return_code != 0:
    logger.error("Command failed with code %d", return_code)
    raise subprocess.CalledProcessError(return_code, cmd, full_stdout, "")

  cli_version = os.environ.get("CODEMENDER_CLI_VERSION", "preview").lower()
  token_usage = None
  if cli_version == "preview":
    matches = re.findall(
        r"Tokens:\s*([0-9.kMgG]+)\s*in\s*/\s*([0-9.kMgG]+)\s*out\s*/\s*([0-9.kMgG]+)\s*total",
        full_stdout,
    )
    if matches:
      in_tokens = 0
      out_tokens = 0
      total_tokens = 0
      for m in matches:
        try:
          in_tokens += parse_token_metric(m[0])
          out_tokens += parse_token_metric(m[1])
          total_tokens += parse_token_metric(m[2])
        except ValueError:
          pass
      token_usage = {
          "in_tokens": in_tokens,
          "out_tokens": out_tokens,
          "total_tokens": total_tokens,
      }
    else:
      consumed = re.findall(
          r"Total tokens consumed:\s*([0-9.]+[kKmMgG]?)", full_stdout
      )
      total_tokens = 0
      if consumed:
        try:
          total_tokens = parse_token_metric(consumed[-1])
        except ValueError:
          total_tokens = 0
      token_usage = {"in_tokens": 0, "out_tokens": 0, "total_tokens": total_tokens}

  res = subprocess.CompletedProcess(cmd, return_code, full_stdout, "")
  setattr(res, "token_usage", token_usage)
  return res


_FINDING_KEY_ALIASES = {
    "finding_id": "FindingID",
    "session_id": "SessionID",
    "title": "Title",
    "file_path": "FilePath",
    "severity": "Severity",
    "confidence": "Confidence",
    "analysis": "Analysis",
    "snippet": "Snippet",
    "vuln_type": "VulnType",
    "vuln_id": "VulnID",
    "fingerprint": "Fingerprint",
    "status": "Status",
    "source_stage": "SourceStage",
    "finding_json": "FindingJSON",
    "updated_at": "UpdatedAt",
    "start_line": "StartLine",
    "end_line": "EndLine",
    "dismiss_reason": "DismissReason",
    "confidence_level": "ConfidenceLevel",
}


def extract_json_from_output(raw_str: Optional[str]) -> Optional[Any]:
  """Extracts and parses the first JSON object or array from a string."""
  if not raw_str:
    return None
  clean = raw_str.strip()
  if not clean:
    return None

  start_idx = -1
  for i, ch in enumerate(clean):
    if ch in ("{", "["):
      start_idx = i
      break

  if start_idx == -1:
    return None

  try:
    decoder = json.JSONDecoder()
    data, _ = decoder.raw_decode(clean, start_idx)
    return data
  except (json.JSONDecodeError, ValueError):
    return None


def parse_findings_json(json_str: str) -> List[Dict[str, Any]]:
  """Parses `cm report --format json` output normalizing keys to PascalCase."""
  data = extract_json_from_output(json_str)
  if data is None:
    logger.error("No valid JSON array or object found in report.")
    return []

  if isinstance(data, dict):
    findings = data.get("findings", data.get("items", []))
  elif isinstance(data, list):
    findings = data
  else:
    findings = []

  cleaned_findings = []
  for item in findings:
    if not isinstance(item, dict):
      continue
    cleaned = {}
    for k, v in item.items():
      if v == "":
        cleaned[k] = None
      else:
        cleaned[k] = v
      canonical = _FINDING_KEY_ALIASES.get(k)
      if canonical and canonical not in item:
        cleaned[canonical] = cleaned[k]
    cleaned_findings.append(cleaned)

  return cleaned_findings


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


def read_findings(
    cm_binary: str,
    repo_dir: str,
    env: Optional[Dict[str, str]] = None,
    cli_version: Optional[str] = None,
) -> List[Dict[str, Any]]:
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
      capture_stderr=False,
  )
  if res.returncode != 0:
    raise FindingImportError(
        f"'cm report --format json' exited {res.returncode}"
    )
  if (res.stdout or "").strip() == "null":
    return []
  if extract_json_from_output(res.stdout) is None:
    raise FindingImportError(
        "'cm report --format json' exited 0 but wrote no parseable JSON"
    )
  return parse_findings_json(res.stdout)


def _ids(findings: List[Dict[str, Any]]) -> List[str]:
  return [str(f["FindingID"]) for f in findings if f.get("FindingID")]


def import_findings(
    cm_binary: str,
    import_file: str,
    repo_dir: str,
    env: Optional[Dict[str, str]] = None,
    cli_version: Optional[str] = None,
) -> Tuple[List[str], List[Dict[str, Any]]]:
  """Imports findings from a file and returns the IDs cm assigned them."""
  if not os.path.isfile(import_file):
    raise FindingImportError("import payload file does not exist")

  before = set(_ids(read_findings(cm_binary, repo_dir, env, cli_version)))

  import_cmd = build_cm_command(
      cm_binary,
      "report",
      extra_flags=["import", "-f", import_file, "-p", repo_dir],
      cli_version=cli_version,
  )
  import_res = run_command(import_cmd, cwd=repo_dir, env=env, check=False)
  if import_res.returncode != 0:
    raise FindingImportError(
        f"'cm report import' exited {import_res.returncode}"
    )

  after_findings = read_findings(cm_binary, repo_dir, env, cli_version)
  assigned = [fid for fid in _ids(after_findings) if fid not in before]
  if not assigned:
    raise FindingImportError(
        "'cm report import' exited 0 but the finding set is unchanged, so no"
        " imported finding ID could be resolved"
    )
  logger.info("Import round-trip: cm assigned %d finding ID(s).", len(assigned))
  return assigned, after_findings


def write_import_payload(findings: List[Dict[str, Any]], dest_path: str) -> str:
  """Writes a simple-JSON import payload, keeping only recognized fields."""
  payload = [
      {k: f[k] for k in IMPORTED_FINDING_FIELDS if k in f} for f in findings
  ]
  os.makedirs(os.path.dirname(os.path.abspath(dest_path)), exist_ok=True)
  with open(dest_path, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2)
  return dest_path


def _match_cm_findings_to_source_rows(
    source_rows: Sequence[Mapping[str, Any]],
    cm_findings: Sequence[Mapping[str, Any]],
    repo_dir: str,
    required_cm_ids: Optional[Sequence[str]] = None,
) -> Dict[str, str]:
  """Maps cm IDs to BigQuery finding IDs using stable finding attributes."""
  required = set(required_cm_ids) if required_cm_ids is not None else None
  unmatched = list(source_rows)
  source_ids_by_cm_id: Dict[str, str] = {}

  for cm_finding in cm_findings:
    cm_id = _finding_id(cm_finding)
    if not cm_id or (required is not None and cm_id not in required):
      continue
    cm_path = normalize_repo_relative_path(
        str(_finding_value(cm_finding, "file_path", "FilePath") or ""), repo_dir
    )
    imported_line = _int_or_none(
        _finding_value(cm_finding, "start_line", "StartLine")
    )
    imported_title = _text(cm_finding, "title") or _text(cm_finding, "Title")
    imported_type = _text(cm_finding, "vuln_type") or _text(cm_finding, "VulnType")
    candidates = []
    for source in unmatched:
      source_path = normalize_repo_relative_path(_text(source, "file_path"), repo_dir)
      if source_path != cm_path:
        continue
      source_line = _int_or_none(source.get("start_line"))
      if imported_line is not None and source_line is not None and imported_line != source_line:
        continue
      score = 0
      if imported_title and imported_title == _text(source, "title"):
        score += 4
      if imported_type and imported_type == _text(source, "vuln_type"):
        score += 2
      if source.get("snippet") and source.get("snippet") == _finding_value(
          cm_finding, "snippet", "Snippet"
      ):
        score += 1
      candidates.append((score, source))

    if not candidates:
      if required is not None and cm_id in required:
        raise ValueError(f"Could not match imported finding {cm_id} to BigQuery source")
      continue
    best_score = max(score for score, _ in candidates)
    best = [source for score, source in candidates if score == best_score]
    if len(best) != 1:
      if required is not None and cm_id in required:
        raise ValueError(f"Imported finding {cm_id} ambiguously matches BigQuery rows")
      continue
    source = best[0]
    source_ids_by_cm_id[cm_id] = _row_key(source)[1]
    unmatched.remove(source)

  if required is not None:
    missing = required.difference(source_ids_by_cm_id)
    if missing:
      raise ValueError("CodeMender report omitted imported finding IDs: " + ", ".join(sorted(missing)))
  return source_ids_by_cm_id


def run_cm_find(
    cm_binary: str, repo_dir: str, cli_version: Optional[str] = None
) -> None:
  """Runs the CodeMender find command on the target repository directory."""
  command = build_cm_command(
      cm_binary, "find", target_or_id=repo_dir, cli_version=cli_version
  )
  result = run_command(command, cwd=repo_dir, check=False)
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


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
  parser = argparse.ArgumentParser(
      description="Run CodeMender find on a local repository."
  )
  parser.add_argument(
      "--repo-dir", default=os.getcwd(), help="Local repository checkout root"
  )
  parser.add_argument(
      "--cm-binary", default=shutil.which("cm") or "cm", help="Path to CodeMender CLI binary"
  )
  parser.add_argument(
      "--cli-version", default=os.environ.get("CODEMENDER_CLI_VERSION", "preview"),
      help="CodeMender CLI version"
  )
  parser.add_argument(
      "--output", default=None, help="Optional output JSON file path for findings"
  )
  return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
  logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
  args = _parse_args(argv)
  repo_dir = os.path.abspath(os.path.expanduser(args.repo_dir))
  try:
    run_cm_find(args.cm_binary, repo_dir, cli_version=args.cli_version)
    findings = read_findings(args.cm_binary, repo_dir, cli_version=args.cli_version)
    if args.output:
      with open(args.output, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)
      print(f"CodeMender find completed: {len(findings)} findings written to {args.output}")
    else:
      print(f"CodeMender find completed successfully: {len(findings)} findings discovered.")
    return 0
  except Exception as error:  # pylint: disable=broad-exception-caught
    logger.error("CodeMender find failed: %s", error)
    return 1


if __name__ == "__main__":
  sys.exit(main())

