import dataclasses
import datetime
import logging
import re
from pprint import pprint
from typing import Any, Dict, Iterable, List, Mapping, Optional, Union
import uuid

from step_1_import_from_bq import _finding_value
from finding import Finding

logger = logging.getLogger("export-bigquery-findings")

_FIXED_STATUSES = frozenset({"FIXED", "REMEDIATED", "PATCHED"})
_FAILED_FIX_STATUSES = frozenset({"FIX_FAILED", "PR_CREATION_FAILED", "PATCH_FAILED"})
_VERIFIED_STATUSES = frozenset({"VERIFIED", "CONFIRMED"})
_VERIFY_PASSED_STATUSES = _VERIFIED_STATUSES | _FIXED_STATUSES | _FAILED_FIX_STATUSES
SKIPPED_STATUSES = frozenset({"SKIPPED_DUPLICATE", "PRE_EXISTING_IGNORED"})

_CWE_PATTERN = re.compile(r"(CWE-\d+)", re.IGNORECASE)
_TRUTHY = frozenset({"true", "1", "yes", "on"})


def _as_str(value: Any) -> Optional[str]:
  """Coerces a value to a non-empty string, or None."""
  if value is None:
    return None
  text = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
  text = text.strip()
  return text or None


def _as_int(value: Any) -> Optional[int]:
  """Coerces a value to int, returning None rather than raising."""
  if value is None or isinstance(value, bool):
    return int(value) if isinstance(value, bool) else None
  try:
    return int(value)
  except (TypeError, ValueError):
    return None


def _as_bool(value: Any) -> Optional[bool]:
  """Coerces a 0/1/'true' style value to bool, or None."""
  if value is None:
    return None
  if isinstance(value, bool):
    return value
  if isinstance(value, (int, float)):
    return bool(value)
  text = _as_str(value)
  if text is None:
    return None
  return text.lower() in _TRUTHY


def _utc_now_iso() -> str:
  """Returns the current UTC time as an RFC 3339 string BigQuery accepts."""
  return datetime.datetime.now(datetime.timezone.utc).isoformat()


def extract_cwe_id(*candidates: Optional[str]) -> Optional[str]:
  """Extracts a normalized `CWE-nnn` identifier from any of the given strings."""
  for candidate in candidates:
    if not candidate:
      continue
    match = _CWE_PATTERN.search(str(candidate))
    if match:
      return match.group(1).upper()
  return None


def _repo_relative_path(raw_path: Any, repo_dir: Optional[str] = None) -> Optional[str]:
  """Returns a finding's file path as-is."""
  return _as_str(raw_path)


def _row_verified(
    finding: Dict[str, Any], status: str, force_verified: bool,
    skip_verify: Optional[bool],
) -> Optional[bool]:
  """Whether verification confirmed this finding."""
  if _as_bool(finding.get("verified")):
    return True
  if status in _VERIFIED_STATUSES:
    return True
  if status in _VERIFY_PASSED_STATUSES and (force_verified or skip_verify is False):
    return True
  return _as_bool(finding.get("verified"))


@dataclasses.dataclass
class ScanRunContext:
  """Mutable accumulator for the facts that make up one scan run."""

  stage: str = "scan"
  scan_id: Optional[str] = None
  repository: Optional[str] = None
  target_branch: Optional[str] = None
  target_sha: Optional[str] = None
  scan_target: Optional[str] = None
  cm_version: Optional[str] = None
  find_model: Optional[str] = None
  verify_model: Optional[str] = None
  fix_model: Optional[str] = None
  total_findings_count: Optional[int] = None
  active_findings_count: Optional[int] = None
  skipped_duplicate_count: Optional[int] = None
  fixed_count: Optional[int] = None
  failed_fix_count: Optional[int] = None
  report_uri: Optional[str] = None
  execution_url: Optional[str] = None
  token_totals: Optional[Dict[str, Dict[str, Any]]] = None
  wiz_status: Optional[str] = None
  wiz_status_detail: Optional[str] = None
  wiz_reported_count: Optional[int] = None
  wiz_imported_count: Optional[int] = None
  wiz_imported_ids: Optional[List[str]] = None
  skip_verify: Optional[bool] = None
  repo_dir: Optional[str] = None


def build_finding_rows(
    ctx: ScanRunContext,
    findings: Iterable[Finding],
    scan_timestamp: Optional[str] = None,
    finding_prs: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
  """Maps findings onto BigQuery `findings` rows."""
  if not findings:
    return []

  timestamp = scan_timestamp or _utc_now_iso()
  scan_id = _as_str(ctx.scan_id) or "unknown"
  repository = _as_str(ctx.repository)
  prs = finding_prs or {}
  repo_dir = _as_str(ctx.repo_dir)
  wiz_ids = {str(i) for i in (ctx.wiz_imported_ids or [])}

  rows: List[Dict[str, Any]] = []
  for finding in findings:
    if not isinstance(finding, dict):
      continue
    finding_id = _as_str(finding.get("finding_id"))
    if not finding_id:
      continue

    title = _as_str(finding.get("title"))
    status = (_as_str(finding.get("status")) or "DETECTED").upper()
    vuln_type = _as_str(finding.get("vuln_type"))
    severity = _as_str(finding.get("severity"))
    confidence_level = _as_str(
        finding.get("confidence_level")
    ) or _as_str(finding.get("confidence"))

    row: Dict[str, Any] = {
        "scan_id": scan_id,
        "scan_timestamp": timestamp,
        "repository": repository,
        "title": title,
        "vuln_type": vuln_type,
        "cwe_id": extract_cwe_id(finding.get("vuln_id"), vuln_type, title),
        "severity": severity.upper() if severity else None,
        "confidence_level": confidence_level.upper() if confidence_level else None,
        "file_path": _repo_relative_path(finding.get("file_path"), repo_dir),
        "start_line": _as_int(finding.get("start_line")),
        "end_line": _as_int(finding.get("end_line")),
        "status": status,
        "source_stage": _as_str(finding.get("source_stage")),
        "verified": _row_verified(finding, status, finding_id in wiz_ids, ctx.skip_verify),
        "muted": _as_bool(finding.get("muted")),
        "mute_reason": _as_str(finding.get("mute_reason"))
        or _as_str(finding.get("dismiss_reason")),
        "fingerprint": _as_str(finding.get("fingerprint")),
        "fix_pr_url": _as_str(prs.get(finding_id)),
        "patch_status": _as_str(finding.get("patch_status")),
        "finding_source": "wiz" if finding_id in wiz_ids else "codemender",
        "analysis": _as_str(finding.get("analysis")),
        "snippet": _as_str(finding.get("snippet"))
    }

    rows.append(row)

  return rows


def _to_telemetry_finding(
    finding: Union[Finding],
) -> Dict[str, Any]:
  """Maps canonical or snake_case cm report output to the telemetry mapper."""
  field_names = (
      "title", "file_path", "severity", "confidence", "confidence_level",
      "analysis", "snippet", "vuln_type", "vuln_id", "verified", "muted",
      "mute_reason", "status", "source_stage", "start_line", "end_line",
      "dismiss_reason", "updated_at",
  )
  normalized = {
      "fingerprint": finding.fingerprint,
  }
  aliases = {
      "confidence_level": "ConfidenceLevel",
      "vuln_id": "VulnID",
  }
  for field in field_names:
    pascal = aliases.get(field, "".join(part.capitalize() for part in field.split("_")))
    value = _finding_value(finding, field, pascal)
    if value is not None:
      normalized[field] = value
  return normalized


def export_findings_to_bigquery(
    client: Any,
    table_id: str,
    findings: Iterable[Finding],
    repository: str,
    repo_dir: str,
    location: Optional[str] = None,
    scan_id: Optional[str] = None,
) -> int:
  """Transforms CodeMender findings to telemetry rows and uploads them to BigQuery."""
  context = ScanRunContext(
      stage="bigquery_roundtrip",
      scan_id=scan_id or str(uuid.uuid4()),
      repository=repository,
      repo_dir=repo_dir,
      skip_verify=False,
  )
  finding_rows = build_finding_rows(context, findings)
  if not finding_rows:
    return 0

  from google.cloud import bigquery  # pylint: disable=import-outside-toplevel

  try:
    target_table = client.get_table(table_id)
    schema = target_table.schema
  except Exception:
    schema = [
        bigquery.SchemaField("finding_id", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("scan_id", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("scan_timestamp", "TIMESTAMP", mode="REQUIRED"),
        bigquery.SchemaField("repository", "STRING"),
        bigquery.SchemaField("title", "STRING"),
        bigquery.SchemaField("vuln_type", "STRING"),
        bigquery.SchemaField("cwe_id", "STRING"),
        bigquery.SchemaField("severity", "STRING"),
        bigquery.SchemaField("confidence_level", "STRING"),
        bigquery.SchemaField("file_path", "STRING"),
        bigquery.SchemaField("start_line", "INTEGER"),
        bigquery.SchemaField("end_line", "INTEGER"),
        bigquery.SchemaField("status", "STRING"),
        bigquery.SchemaField("source_stage", "STRING"),
        bigquery.SchemaField("verified", "BOOLEAN"),
        bigquery.SchemaField("muted", "BOOLEAN"),
        bigquery.SchemaField("mute_reason", "STRING"),
        bigquery.SchemaField("fingerprint", "STRING"),
        bigquery.SchemaField("fix_pr_url", "STRING"),
        bigquery.SchemaField("patch_status", "STRING"),
        bigquery.SchemaField("analysis", "STRING"),
        bigquery.SchemaField("snippet", "STRING"),
        bigquery.SchemaField("finding_source", "STRING"),
    ]
    table = bigquery.Table(table_id, schema=schema)
    table.time_partitioning = bigquery.TimePartitioning(
        type_=bigquery.TimePartitioningType.DAY, field="scan_timestamp"
    )
    table.clustering_fields = ["repository", "severity", "vuln_type"]
    table.description = "One row per CodeMender vulnerability finding."
    try:
      client.create_table(table, exists_ok=True)
    except Exception:
      pass

  columns = [field.name for field in schema]
  rows_to_load = [
      {key: value for key, value in row.items() if key in columns}
      for row in finding_rows
  ]
  job_config = bigquery.LoadJobConfig(schema=schema)
  client.load_table_from_json(
      rows_to_load, table_id, job_config=job_config, location=location
  ).result()
  return len(rows_to_load)