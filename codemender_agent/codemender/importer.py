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

"""Round-trip import of externally discovered findings into CodeMender state.

``cm`` assigns its **own** finding ID on import. The identifier an external
tool used is not preserved and cannot be handed to ``cm verify`` or
``cm fix``; the only way to learn the assigned IDs is to ask ``cm`` afterwards:

    1. ``cm report --format json``           -- snapshot existing IDs
    2. ``cm report import -f <file> -p <repo>`` -- seed the new findings
    3. ``cm report --format json``           -- read back the new state
    4. diff (3) against (1)                  -- the assigned IDs

Snapshotting first matters because the state database normally already holds
the results of a ``cm find`` sweep, so "the only finding present" is not a
safe identification. The session ID and fingerprint of imported rows are not
relied on: neither is documented as stable across CLI versions.

``cm report import`` never de-duplicates; importing the same payload twice
creates duplicate rows. Callers are responsible for filtering out findings
that were already imported before calling :func:`import_findings`.

The simple-JSON payload fields understood by ``cm report import`` are:

    file_path, line, end_line, title, message, severity, vuln_type, snippet
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from codemender_agent.codemender.cli import parse_findings_json
from codemender_agent.utils import build_cm_command
from codemender_agent.utils import extract_json_from_output
from codemender_agent.utils import run_command

logger = logging.getLogger("codemender-orchestrator")

# The fields `cm report import` recognizes in the simple-JSON dialect.
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


class FindingImportError(RuntimeError):
  """Raised when the import round-trip cannot establish the assigned IDs."""


def read_findings(
    cm_binary: str,
    repo_dir: str,
    env: Optional[Dict[str, str]] = None,
    cli_version: Optional[str] = None,
) -> List[Dict[str, Any]]:
  """Returns every finding currently in the CodeMender state.

  Raises:
    FindingImportError: If the report cannot be read. An unreadable report is
      not an empty one; treating it as empty would make the before/after diff
      silently wrong in both directions.
  """
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
  # An empty state is reported as a bare JSON `null` (observed with cm 0.9),
  # which is a valid, empty report rather than an unreadable one.
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
  """Imports findings from a file and returns the IDs ``cm`` assigned them.

  Args:
    cm_binary: Path to (or name of) the CodeMender CLI binary.
    import_file: Absolute path to a simple-JSON finding array.
    repo_dir: Repository root; relative ``file_path`` values resolve against
      it (passed explicitly with ``-p`` so stored paths never depend on the
      process working directory).
    env: Environment for the subprocesses, normally the scrubbed environment.
    cli_version: "preview" or "legacy".

  Returns:
    A tuple of (newly assigned finding IDs in report order, the full
    post-import finding list).

  Raises:
    FindingImportError: If the import subprocess fails, if the state cannot be
      read before or after it, or if no new finding appears.
  """
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
