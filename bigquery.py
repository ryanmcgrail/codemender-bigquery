"""BigQuery wrapper class and helpers for CodeMender findings."""

import dataclasses
import datetime
import logging
import re
from typing import Any, Dict, Iterable, List, Optional
import uuid

from finding import Finding

logger = logging.getLogger("bigquery")


_DEFAULT_TABLE = "findings"
_TABLE_COMPONENT = re.compile(r"^[A-Za-z0-9_-]+$")

_FIXED_STATUSES = frozenset({"FIXED", "REMEDIATED", "PATCHED"})
_FAILED_FIX_STATUSES = frozenset({"FIX_FAILED", "PR_CREATION_FAILED", "PATCH_FAILED"})
_VERIFIED_STATUSES = frozenset({"VERIFIED", "CONFIRMED"})
_VERIFY_PASSED_STATUSES = _VERIFIED_STATUSES | _FIXED_STATUSES | _FAILED_FIX_STATUSES
SKIPPED_STATUSES = frozenset({"SKIPPED_DUPLICATE", "PRE_EXISTING_IGNORED"})


def _table_id(project: str, dataset: str, table: str) -> str:
  """Validates and constructs a fully-qualified BigQuery table ID."""
  for value in (project, dataset, table):
    if not _TABLE_COMPONENT.fullmatch(value):
      raise ValueError(f"Invalid BigQuery identifier component: {value!r}")
  return f"{project}.{dataset}.{table}"


def _as_str(value: Any) -> Optional[str]:
  """Coerces a value to a non-empty string, or None."""
  if value is None:
    return None
  text = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
  text = text.strip()
  return text or None


def _utc_now_iso() -> str:
  """Returns the current UTC time as an RFC 3339 string BigQuery accepts."""
  return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _row_verified(
    finding: Finding, status: str, force_verified: bool,
    skip_verify: Optional[bool],
) -> Optional[bool]:
  """Whether verification confirmed this finding."""
  if finding.verified:
    return True
  if status in _VERIFIED_STATUSES:
    return True
  if status in _VERIFY_PASSED_STATUSES and (force_verified or skip_verify is False):
    return True
  return finding.verified


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
) -> List[Dict[str, Any]]:
  """Maps findings onto BigQuery `findings` rows."""
  if not findings:
    return []

  timestamp = scan_timestamp or _utc_now_iso()
  scan_id = _as_str(ctx.scan_id) or "unknown"
  repository = _as_str(ctx.repository)
  wiz_ids = {str(i) for i in (ctx.wiz_imported_ids or [])}

  rows: List[Dict[str, Any]] = []
  for finding in findings:
    title = _as_str(finding.title)
    status = finding.status
    vuln_type = finding.vuln_type

    row: Dict[str, Any] = {
        "analysis": finding.analysis,
        "confidence_level": finding.confidence_level,
        "end_line": finding.end_line,
        "file_path": finding.file_path,
        "finding_id": finding.finding_id,
        "fingerprint": finding.fingerprint,
        "mute_reason": finding.mute_reason,
        "muted": finding.muted,
        "repository": repository,
        "scan_id": scan_id,
        "scan_timestamp": timestamp,
        "severity": finding.severity,
        "source_stage": finding.source_stage,
        "snippet": finding.snippet,
        "start_line": finding.start_line,
        "status": status,
        "title": title,
        "verified": _row_verified(finding, status, finding.finding_id in wiz_ids, ctx.skip_verify),
        "vuln_type": vuln_type,
    }

    rows.append(row)

  return rows


def _ensure_dataset(client: Any, project: str, dataset: str, location: Optional[str]) -> None:
    """Creates the configured BigQuery dataset if it does not already exist."""
    from google.cloud import bigquery as gcp_bigquery  # pylint: disable=import-outside-toplevel

    dataset_resource = gcp_bigquery.Dataset(f"{project}.{dataset}")
    if location:
      dataset_resource.location = location
    client.create_dataset(dataset_resource, exists_ok=True)


def _ensure_table(client: Any, table_id: str) -> List[Any]:
  """Ensures the BigQuery findings table exists and returns its schema."""
  from google.cloud import bigquery as gcp_bigquery  # pylint: disable=import-outside-toplevel

  try:
    target_table = client.get_table(table_id)
    return target_table.schema
  except Exception:
    schema = [
        gcp_bigquery.SchemaField("analysis", "STRING", mode="REQUIRED"),
        gcp_bigquery.SchemaField("confidence_level", "STRING"),
        gcp_bigquery.SchemaField("end_line", "INTEGER", mode="REQUIRED"),
        gcp_bigquery.SchemaField("finding_id", "STRING"),
        gcp_bigquery.SchemaField("fingerprint", "STRING", mode="REQUIRED"),
        gcp_bigquery.SchemaField("muted", "BOOLEAN"),
        gcp_bigquery.SchemaField("mute_reason", "STRING"),
        gcp_bigquery.SchemaField("repository", "STRING", mode="REQUIRED"),
        gcp_bigquery.SchemaField("severity", "STRING", mode="REQUIRED"),
        gcp_bigquery.SchemaField("title", "STRING", mode="REQUIRED"),
        gcp_bigquery.SchemaField("verified", "BOOLEAN"),
        gcp_bigquery.SchemaField("vuln_type", "STRING", mode="REQUIRED"),
        gcp_bigquery.SchemaField("file_path", "STRING", mode="REQUIRED"),
        gcp_bigquery.SchemaField("scan_id", "STRING"),
        gcp_bigquery.SchemaField("scan_timestamp", "TIMESTAMP"),
        gcp_bigquery.SchemaField("source_stage", "STRING"),
        gcp_bigquery.SchemaField("snippet", "STRING", mode="REQUIRED"),
        gcp_bigquery.SchemaField("start_line", "INTEGER", mode="REQUIRED"),
        gcp_bigquery.SchemaField("status", "STRING", mode="REQUIRED"),
    ]
    table = gcp_bigquery.Table(table_id, schema=schema)
    table.time_partitioning = gcp_bigquery.TimePartitioning(
        type_=gcp_bigquery.TimePartitioningType.DAY, field="scan_timestamp"
    )
    table.clustering_fields = ["repository", "status"]
    table.description = "One row per CodeMender vulnerability finding."
    try:
      client.create_table(table, exists_ok=True)
    except Exception:
      pass
    return schema


class BigQuery:
  """Encapsulates BigQuery configuration and finding operations for a table."""

  def __init__(
      self,
      project: str,
      dataset: str,
      table: Optional[str],
      location: Optional[str] = None,
      client: Any = None,
  ) -> None:
    self.project = project
    self.dataset = dataset
    self.table = table or _DEFAULT_TABLE
    self.location = location
    self.table_id = _table_id(project, dataset, self.table)

    if client is None:
      from google.cloud import bigquery as gcp_bigquery  # pylint: disable=import-outside-toplevel

      client = gcp_bigquery.Client(project=project)
    self.client = client

  def fetch_findings(self, repository: str) -> List[Finding]:
    """Loads actionable findings for a repository from BigQuery."""
    from google.cloud import bigquery as gcp_bigquery  # pylint: disable=import-outside-toplevel

    _ensure_dataset(self.client, self.project, self.dataset, self.location)

    try:
      config = gcp_bigquery.QueryJobConfig(
          query_parameters=[
              gcp_bigquery.ScalarQueryParameter("repository", "STRING", repository)
          ]
      )
      rows = self.client.query(
          f"""
SELECT *
FROM `{self.table_id}`
WHERE repository = @repository
  AND UPPER(COALESCE(status, '')) NOT IN (
    'FIXED', 'REMEDIATED', 'PATCHED', 'DISMISSED', 'FALSE_POSITIVE', 'RESOLVED'
  )
""",
          job_config=config,
          location=self.location,
      ).result()
      return [
          Finding.from_dict(dict(row.items()) if hasattr(row, "items") else row)
          for row in rows
      ]
    except Exception as error:  # pylint: disable=broad-exception-caught
      logger.warning("Query failed on table %s: %s", self.table_id, error)
      return []

  def upload_findings(
      self,
      findings: Iterable[Finding],
      repository: str,
      repo_dir: Optional[str] = None,
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

    from google.cloud import bigquery as gcp_bigquery  # pylint: disable=import-outside-toplevel

    schema = _ensure_table(self.client, self.table_id)

    columns = [field.name for field in schema]
    identity = {"repository", "fingerprint"}
    missing_identity = identity.difference(columns)
    if missing_identity:
      raise ValueError(
          "Findings table is missing key columns: "
          + ", ".join(sorted(missing_identity))
      )

    rows_to_load = [
        {key: value for key, value in row.items() if key in columns}
        for row in finding_rows
    ]
    stage_table_id = f"{self.table_id.rsplit('.', 1)[0]}._cm_stage_{uuid.uuid4().hex}"

    try:
      job_config = gcp_bigquery.LoadJobConfig(
          schema=schema,
          write_disposition=gcp_bigquery.WriteDisposition.WRITE_TRUNCATE,
      )
      self.client.load_table_from_json(
          rows_to_load, stage_table_id, job_config=job_config, location=self.location
      ).result()

      columns_sql = ", ".join(f"`{column}`" for column in columns)
      updates_sql = ", ".join(
          f"T.`{column}` = S.`{column}`" for column in columns if column not in identity
      )
      values_sql = ", ".join(f"S.`{column}`" for column in columns)
      merge_sql = f"""
MERGE `{self.table_id}` AS T
USING `{stage_table_id}` AS S
ON T.repository = S.repository AND T.fingerprint = S.fingerprint
WHEN MATCHED THEN UPDATE SET {updates_sql}
WHEN NOT MATCHED THEN INSERT ({columns_sql}) VALUES ({values_sql})
"""
      self.client.query(merge_sql, location=self.location).result()
      return len(rows_to_load)
    finally:
      self.client.delete_table(stage_table_id, not_found_ok=True)

