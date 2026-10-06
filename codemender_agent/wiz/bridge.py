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

"""Orchestrates the opt-in Wiz SAST bridge for one repository scan.

Flow: obtain a Wiz JSON result (run ``wizcli`` or read a bring-your-own
file) -> empty-output guard -> convert and threshold -> de-duplicate against
the current CodeMender state -> cap -> ``cm report import`` round-trip.

Every imported finding is returned in ``force_verify_ids``: the pipeline must
run ``cm verify`` on it even when verification is otherwise skipped, and only
findings that verify proceed to a fix and pull request.

:func:`run_wiz_bridge` never raises. A disabled bridge does no work at all; a
failing bridge reports ``status == "failed"`` and the scan continues with
CodeMender's own findings.
"""

import dataclasses
import logging
import os
import shutil
import tempfile
from typing import Any, Dict, List, Optional, Sequence

from codemender_agent.codemender.importer import import_findings
from codemender_agent.codemender.importer import read_findings
from codemender_agent.codemender.importer import write_import_payload
from codemender_agent.wiz.cli import run_wiz_sast_scan
from codemender_agent.wiz.converter import WizCandidate
from codemender_agent.wiz.converter import build_import_record
from codemender_agent.wiz.converter import carries_import_marker
from codemender_agent.wiz.converter import convert_findings
from codemender_agent.wiz.dedupe import dedupe_candidates
from codemender_agent.wiz.dedupe import finding_ref
from codemender_agent.wiz.dedupe import is_same_import
from codemender_agent.wiz.guard import guard_wiz_result
from codemender_agent.wiz.guard import load_wiz_json
from codemender_agent.wiz.settings import WizBridgeSettings
from codemender_agent.wiz.settings import WizCredentials
from codemender_agent.wiz.settings import severity_rank

logger = logging.getLogger("codemender-orchestrator")

STATUS_ENABLED = "enabled"
STATUS_NOT_ENABLED = "not_enabled"
STATUS_FAILED = "failed"

_DETAIL_MAX_CHARS = 300
_REDACTED = "[REDACTED]"


@dataclasses.dataclass
class WizBridgeResult:
  """Outcome of one bridge run, safe to persist and to log."""

  status: str
  detail: str = ""
  source: str = ""
  # Whether Wiz is set up in this deployment at all (credentials or a
  # bring-your-own results file). Decides whether a "not enabled" status is
  # worth showing in the human-readable report; telemetry always records it.
  configured: bool = False
  reported_count: int = 0
  eligible_count: int = 0
  below_threshold_count: int = 0
  duplicate_count: int = 0
  already_imported_count: int = 0
  capped_count: int = 0
  imported_ids: List[str] = dataclasses.field(default_factory=list)
  force_verify_ids: List[str] = dataclasses.field(default_factory=list)
  candidates: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
  findings: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
  min_severity: str = ""

  @property
  def imported_count(self) -> int:
    return len(self.imported_ids)

  def to_metadata(self) -> Dict[str, Any]:
    """The JSON block recorded in scan metadata and read by the aggregator."""
    return {
        "status": self.status,
        "detail": self.detail,
        "source": self.source,
        "configured": self.configured,
        "min_severity": self.min_severity,
        "reported_count": self.reported_count,
        "eligible_count": self.eligible_count,
        "below_threshold_count": self.below_threshold_count,
        "duplicate_count": self.duplicate_count,
        "already_imported_count": self.already_imported_count,
        "capped_count": self.capped_count,
        "imported_count": self.imported_count,
        "imported_ids": list(self.imported_ids),
        "force_verify_ids": list(self.force_verify_ids),
        "candidates": list(self.candidates),
    }


def redact(text: str, secrets: Sequence[str]) -> str:
  """Removes secret values from text and bounds its length."""
  out = str(text or "")
  for secret in secrets:
    if secret:
      out = out.replace(secret, _REDACTED)
  return out[:_DETAIL_MAX_CHARS]


def summary_line(wiz: Optional[Dict[str, Any]]) -> Optional[str]:
  """One line describing the bridge outcome, or None when there is nothing to say.

  A repository that is not enabled gets a line only when Wiz is configured in
  the deployment, so "not on Wiz" is never mistaken for "clean" there, while
  deployments that do not use Wiz keep their reports unchanged.
  """
  if not isinstance(wiz, dict):
    return None
  status = wiz.get("status")
  if status == STATUS_ENABLED:
    parts = [
        f"{wiz.get('reported_count', 0)} reported",
        f"{wiz.get('eligible_count', 0)} at or above"
        f" {wiz.get('min_severity') or 'the threshold'}",
        f"{wiz.get('duplicate_count', 0)} already found by CodeMender",
        f"{wiz.get('imported_count', 0)} imported for verification",
    ]
    if wiz.get("already_imported_count"):
      parts.append(f"{wiz['already_imported_count']} previously imported")
    if wiz.get("capped_count"):
      parts.append(f"{wiz['capped_count']} over the import cap")
    return "enabled: " + ", ".join(parts) + "."
  if status == STATUS_FAILED:
    detail = wiz.get("detail") or "unknown error"
    return f"failed ({detail}); CodeMender findings were processed normally."
  if status == STATUS_NOT_ENABLED and wiz.get("configured"):
    return (
        "not enabled for this repository; no Wiz results were imported, so"
        " this report covers CodeMender's own findings only."
    )
  return None


def _resolve_results_file(path: str, repo_dir: str) -> str:
  if os.path.isabs(path) or os.path.isfile(path):
    return os.path.abspath(path)
  return os.path.abspath(os.path.join(repo_dir, path))


def _import_order(cand: WizCandidate):
  return (-severity_rank(cand.severity), cand.file_path, cand.start_line)


def _marker_ids(findings: Sequence[Dict[str, Any]]) -> List[str]:
  """IDs of findings in state that still carry the bridge's import marker."""
  return [
      str(f["FindingID"])
      for f in findings
      if isinstance(f, dict) and f.get("FindingID") and carries_import_marker(f)
  ]


def _match_candidate(
    finding: Dict[str, Any], candidates: Sequence[WizCandidate], repo_dir: str
) -> Optional[WizCandidate]:
  ref = finding_ref(finding, repo_dir)
  if ref is None:
    return None
  # Same matcher as the idempotency check, so it survives cm rewriting the
  # stored vulnerability type.
  return next((c for c in candidates if is_same_import(c, ref)), None)


def _summaries(
    ids: Sequence[str],
    findings: Sequence[Dict[str, Any]],
    candidates: Sequence[WizCandidate],
    repo_dir: str,
    state: str,
) -> List[Dict[str, Any]]:
  by_id = {str(f.get("FindingID")): f for f in findings if f.get("FindingID")}
  out = []
  for fid in ids:
    cand = _match_candidate(by_id.get(fid, {}), candidates, repo_dir)
    summary = cand.summary() if cand else {}
    summary.update({"finding_id": fid, "state": state})
    out.append(summary)
  return out


def run_wiz_bridge(
    *,
    settings: WizBridgeSettings,
    creds: WizCredentials,
    repo_dir: str,
    cm_binary: str,
    cm_env: Optional[Dict[str, str]],
    existing_findings: List[Dict[str, Any]],
    cli_version: Optional[str] = None,
) -> WizBridgeResult:
  """Runs the bridge for one repository. Never raises."""
  configured = bool(creds.present or settings.results_file)
  if not settings.enabled:
    return WizBridgeResult(
        status=STATUS_NOT_ENABLED,
        configured=configured,
        findings=list(existing_findings),
    )

  result = WizBridgeResult(
      status=STATUS_FAILED,
      configured=configured,
      findings=list(existing_findings),
      min_severity=settings.min_severity,
  )
  existing_ids = {
      str(f.get("FindingID")) for f in existing_findings if f.get("FindingID")
  }
  scan_out_dir = None
  payload_dir = None
  import_attempted = False
  try:
    if settings.results_file:
      result.source = "results_file"
      doc_path = _resolve_results_file(settings.results_file, repo_dir)
    else:
      result.source = "wizcli"
      doc_path = run_wiz_sast_scan(settings, creds, repo_dir)
      scan_out_dir = os.path.dirname(doc_path)

    guarded = guard_wiz_result(load_wiz_json(doc_path))
    conversion = convert_findings(
        guarded.sast_findings, repo_dir, settings.min_severity
    )
    result.reported_count = conversion.reported_count
    result.below_threshold_count = conversion.below_threshold_count
    result.eligible_count = conversion.eligible_count

    dedupe = dedupe_candidates(
        conversion.candidates, existing_findings, repo_dir, settings.line_window
    )
    result.duplicate_count = len(dedupe.duplicates)
    result.already_imported_count = len(dedupe.already_imported)

    to_import = sorted(dedupe.new, key=_import_order)
    if len(to_import) > settings.max_imports:
      result.capped_count = len(to_import) - settings.max_imports
      to_import = to_import[: settings.max_imports]

    findings_after = list(existing_findings)
    if to_import:
      payload_dir = tempfile.mkdtemp(prefix="cm-wiz-import-")
      payload = write_import_payload(
          [build_import_record(c, repo_dir) for c in to_import],
          os.path.join(payload_dir, "wiz_import.json"),
      )
      import_attempted = True
      result.imported_ids, findings_after = import_findings(
          cm_binary, payload, repo_dir, env=cm_env, cli_version=cli_version
      )

    result.findings = findings_after
    # Earlier imports that no longer match a current candidate (for example
    # after the threshold changed, or Wiz stopped reporting them) are still
    # unverified external findings, so they are forced as well.
    result.force_verify_ids = list(
        dict.fromkeys(
            result.imported_ids
            + dedupe.already_imported_ids
            + _marker_ids(findings_after)
        )
    )
    all_candidates = list(to_import) + list(dedupe.already_imported)
    result.candidates = _summaries(
        result.imported_ids, findings_after, all_candidates, repo_dir, "imported"
    ) + _summaries(
        dedupe.already_imported_ids,
        findings_after,
        all_candidates,
        repo_dir,
        "already_imported",
    )
    result.status = STATUS_ENABLED
    logger.info(
        "Wiz SAST bridge: %d reported, %d below %s, %d eligible, %d duplicate"
        " of CodeMender, %d already imported, %d capped, %d imported.",
        result.reported_count,
        result.below_threshold_count,
        settings.min_severity,
        result.eligible_count,
        result.duplicate_count,
        result.already_imported_count,
        result.capped_count,
        result.imported_count,
    )
  except Exception as e:  # pylint: disable=broad-exception-caught
    result.status = STATUS_FAILED
    result.detail = redact(f"{type(e).__name__}: {e}", creds.secret_values())
    logger.warning(
        "Wiz SAST bridge failed; continuing with CodeMender findings only: %s",
        result.detail,
    )
    if import_attempted:
      _recover_partial_import(
          result, existing_ids, repo_dir, cm_binary, cm_env, cli_version
      )
    result.force_verify_ids = list(
        dict.fromkeys(result.force_verify_ids + _marker_ids(result.findings))
    )
  finally:
    for d in (scan_out_dir, payload_dir):
      if d:
        shutil.rmtree(d, ignore_errors=True)
  return result


def _recover_partial_import(
    result: WizBridgeResult,
    existing_ids: set,
    repo_dir: str,
    cm_binary: str,
    cm_env: Optional[Dict[str, str]],
    cli_version: Optional[str],
) -> None:
  """After a failed import, still route any rows it created to verification.

  If ``cm report import`` wrote rows but the read-back failed, those rows are
  in the state database. Leaving them out of the returned findings would let
  them surface in reports without ever being verified, so re-read once and
  treat any new rows as imported (and therefore force-verified).
  """
  try:
    after = read_findings(cm_binary, repo_dir, env=cm_env, cli_version=cli_version)
  except Exception:  # pylint: disable=broad-exception-caught
    result.detail = (result.detail + "; state could not be re-read")[
        :_DETAIL_MAX_CHARS
    ]
    return
  new_ids = [
      str(f["FindingID"])
      for f in after
      if f.get("FindingID") and str(f["FindingID"]) not in existing_ids
  ]
  if new_ids:
    result.findings = after
    result.imported_ids = new_ids
    result.force_verify_ids = list(new_ids)
