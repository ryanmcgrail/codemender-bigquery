import argparse
import dataclasses
import datetime
import json
import logging
import os
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union
import uuid

from step_1_import_from_bq import (
    DEFAULT_TABLE,
    _finding_id,
    _finding_value,
    _int_or_none,
    _resolve_project,
    _table_id,
    compute_finding_fingerprint,
    deduplicate_rows_by_key,
    ensure_dataset,
    normalize_repo_relative_path,
    resolve_dataset,
)
from finding import Finding

logger = logging.getLogger("export-bigquery-findings")

_FIXED_STATUSES = frozenset({"FIXED", "REMEDIATED", "PATCHED"})
_FAILED_FIX_STATUSES = frozenset({"FIX_FAILED", "PR_CREATION_FAILED", "PATCH_FAILED"})
_VERIFIED_STATUSES = frozenset({"VERIFIED", "CONFIRMED"})
_VERIFY_PASSED_STATUSES = _VERIFIED_STATUSES | _FIXED_STATUSES | _FAILED_FIX_STATUSES
SKIPPED_STATUSES = frozenset({"SKIPPED_DUPLICATE", "PRE_EXISTING_IGNORED"})

_CWE_PATTERN = re.compile(r"(CWE-\d+)", re.IGNORECASE)
_REPEATED_SLASHES = re.compile(r"/{2,}")
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


def _repo_relative_path(raw_path: Any, repo_dir: Optional[str]) -> Optional[str]:
  """Coerces a finding's file path to a repository-relative path."""
  text = _as_str(raw_path)
  if text is None:
    return None
  try:
    normalized = normalize_repo_relative_path(text, repo_dir)
  except Exception:
    return text
  if not normalized:
    return text
  if text.startswith("/") and normalized == text.lstrip("/"):
    return text
  return _REPEATED_SLASHES.sub("/", normalized)


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
    findings: Optional[Iterable[Dict[str, Any]]],
    scan_timestamp: Optional[str] = None,
    finding_prs: Optional[Dict[str, str]] = None,
    with_snippets: Optional[bool] = None,
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
        "finding_id": finding_id,
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


def _fingerprint_for_cm_finding(
    finding: Mapping[str, Any], repo_dir: str,
) -> Optional[str]:
  """Derives a stable VCS fingerprint for a CodeMender finding."""
  fingerprint = _finding_value(finding, "fingerprint", "Fingerprint")
  if fingerprint:
    return str(fingerprint)
  file_path = _finding_value(finding, "file_path", "FilePath")
  vuln_type = _finding_value(finding, "vuln_type", "VulnType")
  start_line = _finding_value(finding, "start_line", "StartLine")
  if not file_path:
    return None
  path = normalize_repo_relative_path(str(file_path), repo_dir)
  return compute_finding_fingerprint(
      path, str(vuln_type or "vulnerability"), _int_or_none(start_line) or 0
  )


def _to_telemetry_finding(
    finding: Union[Finding, Mapping[str, Any]],
    repo_dir: str,
    source_finding_id: Optional[str] = None,
) -> Dict[str, Any]:
  """Maps canonical or snake_case cm report output to the telemetry mapper."""
  field_names = (
      "title", "file_path", "severity", "confidence", "confidence_level",
      "analysis", "snippet", "vuln_type", "vuln_id", "verified", "muted",
      "mute_reason", "status", "source_stage", "start_line", "end_line",
      "dismiss_reason", "updated_at",
  )
  normalized = {
      "finding_id": _finding_id(finding),
      "fingerprint": _fingerprint_for_cm_finding(finding, repo_dir),
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
  if source_finding_id:
    normalized["finding_id"] = source_finding_id
  return normalized


def merge_current_findings(
    client: Any,
    table_id: str,
    *args: Any,
    location: Optional[str] = None,
    **kwargs: Any,
) -> int:
  """MERGEs rows by repository/finding_id into the findings table."""
  if len(args) >= 2:
    source_table_id = table_id
    target_table_id = str(args[0])
    rows = args[1]
    if len(args) >= 3 and location is None:
      location = args[2]
  elif len(args) == 1:
    source_table_id = table_id
    target_table_id = table_id
    rows = args[0]
  else:
    source_table_id = table_id
    target_table_id = table_id
    rows = kwargs.get("rows", [])

  if not rows:
    return 0

  table_id = target_table_id

  if source_table_id != target_table_id:
    client.query(
        f"CREATE TABLE IF NOT EXISTS `{target_table_id}` "
        f"AS SELECT * FROM `{source_table_id}` WHERE FALSE",
        location=location,
    ).result()

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
  identity = {"repository", "finding_id"}
  missing_identity = identity.difference(columns)
  if missing_identity:
    raise ValueError(
        "Findings table is missing key columns: "
        + ", ".join(sorted(missing_identity))
    )

  unique_rows = deduplicate_rows_by_key(rows)
  staged_rows = [
      {key: value for key, value in row.items() if key in columns}
      for row in unique_rows
  ]
  stage_table_id = f"{table_id.rsplit('.', 1)[0]}._cm_stage_{uuid.uuid4().hex}"
  from google.cloud import bigquery  # pylint: disable=import-outside-toplevel

  try:
    job_config = bigquery.LoadJobConfig(
        schema=schema, write_disposition=bigquery.WriteDisposition.WRITE_TRUNCATE
    )
    client.load_table_from_json(
        staged_rows, stage_table_id, job_config=job_config, location=location
    ).result()

    columns_sql = ", ".join(f"`{column}`" for column in columns)
    updates_sql = ", ".join(
        f"T.`{column}` = S.`{column}`" for column in columns if column not in identity
    )
    values_sql = ", ".join(f"S.`{column}`" for column in columns)
    merge_sql = f"""
MERGE `{table_id}` AS T
USING `{stage_table_id}` AS S
ON T.repository = S.repository AND T.finding_id = S.finding_id
WHEN MATCHED THEN UPDATE SET {updates_sql}
WHEN NOT MATCHED THEN INSERT ({columns_sql}) VALUES ({values_sql})
"""
    client.query(merge_sql, location=location).result()
    return len(unique_rows)
  finally:
    client.delete_table(stage_table_id, not_found_ok=True)


def export_findings_to_bigquery(
    client: Any,
    table_id: str,
    findings: Iterable[Finding],
    repository: str,
    repo_dir: str,
    location: Optional[str] = None,
    source_ids_by_cm_id: Optional[Mapping[str, str]] = None,
    ids_to_process: Optional[Iterable[str]] = None,
    scan_id: Optional[str] = None,
    with_snippets: bool = False,
    merge_fn: Optional[Any] = None,
) -> int:
  """Transforms CodeMender findings to telemetry rows and merges them into BigQuery."""
  source_ids = source_ids_by_cm_id or {}
  allowed_ids = set(ids_to_process) if ids_to_process is not None else None

  finding_objs = [
      f if isinstance(f, Finding) else Finding.from_dict(f, repo_dir)
      for f in findings
  ]
  findings_for_upload = [
      _to_telemetry_finding(
          finding, repo_dir, source_ids.get(finding.finding_id)
      )
      for finding in finding_objs
      if allowed_ids is None or finding.finding_id in allowed_ids
  ]
  context = ScanRunContext(
      stage="bigquery_roundtrip",
      scan_id=scan_id or str(uuid.uuid4()),
      repository=repository,
      repo_dir=repo_dir,
      skip_verify=False,
  )
  finding_rows = build_finding_rows(
      context, findings_for_upload, with_snippets=with_snippets
  )
  merge = merge_fn or merge_current_findings
  return merge(
      client,
      table_id,
      table_id,
      finding_rows,
      location=location,
  )


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
  parser = argparse.ArgumentParser(
      description="Export CodeMender security findings to Google BigQuery."
  )
  parser.add_argument(
      "--findings-file", required=True, help="Path to JSON file containing CodeMender findings"
  )
  parser.add_argument(
      "--repository", required=True, help="BigQuery repository value, e.g. owner/name"
  )
  parser.add_argument(
      "--repo-dir", default=os.getcwd(), help="Local repository checkout root"
  )
  parser.add_argument(
      "--project", default=_resolve_project(), help="GCP project ID"
  )
  parser.add_argument(
      "--dataset", default=resolve_dataset(), help="BigQuery dataset name"
  )
  parser.add_argument(
      "--table", default=DEFAULT_TABLE, help="BigQuery destination table name"
  )
  parser.add_argument(
      "--location", default=os.environ.get("CODEMENDER_BQ_LOCATION"), help="BigQuery dataset location"
  )
  parser.add_argument(
      "--with-snippets", action="store_true", help="Include code snippets and analysis prose"
  )
  args = parser.parse_args(argv)
  if not args.project:
    parser.error("--project or CODEMENDER_BQ_PROJECT/GOOGLE_CLOUD_PROJECT is required")
  if not args.dataset:
    parser.error("--dataset or CODEMENDER_BQ_DATASET is required")
  return args


def main(argv: Optional[Sequence[str]] = None) -> int:
  logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
  args = _parse_args(argv)
  with open(args.findings_file, "r", encoding="utf-8") as f:
    raw_findings = json.load(f)

  if isinstance(raw_findings, dict) and "findings" in raw_findings:
    findings = raw_findings["findings"]
  elif isinstance(raw_findings, list):
    findings = raw_findings
  else:
    logger.error("Expected findings JSON to be a list or an object with 'findings' array")
    return 1

  from google.cloud import bigquery  # pylint: disable=import-outside-toplevel
  client = bigquery.Client(project=args.project)
  table_id = _table_id(args.project, args.dataset, args.table)
  ensure_dataset(client, args.project, args.dataset, location=args.location)

  repo_dir = os.path.abspath(os.path.expanduser(args.repo_dir))
  finding_objs = [
      Finding.from_dict(item, repo_dir=repo_dir) if isinstance(item, dict) else item
      for item in findings
  ]
  merged = export_findings_to_bigquery(
      client=client,
      table_id=table_id,
      findings=finding_objs,
      repository=args.repository,
      repo_dir=repo_dir,
      location=args.location,
      with_snippets=args.with_snippets,
  )
  print(f"Successfully merged {merged} findings into {table_id}")
  return 0


if __name__ == "__main__":
  import sys
  sys.exit(main())

