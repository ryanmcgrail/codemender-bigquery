"""BigQuery wrapper class and helpers for CodeMender findings."""

import datetime
import logging
import re
from typing import Any, Dict, Iterable, List, Optional
import uuid

from finding import Finding

logger = logging.getLogger("bigquery")


_DEFAULT_TABLE = "findings"
_TABLE_COMPONENT = re.compile(r"^[A-Za-z0-9_-]+$")


def _table_id(project: str, dataset: str, table: str) -> str:
  """Validates and constructs a fully-qualified BigQuery table ID."""
  for value in (project, dataset, table):
    if not _TABLE_COMPONENT.fullmatch(value):
      raise ValueError(f"Invalid BigQuery identifier component: {value!r}")
  return f"{project}.{dataset}.{table}"


def _utc_now_iso() -> str:
  """Returns the current UTC time as an RFC 3339 string BigQuery accepts."""
  return datetime.datetime.now(datetime.timezone.utc).isoformat()


def build_finding_rows(
    findings: Iterable[Finding],
    repository: str,
) -> List[Dict[str, Any]]:
  """Maps findings onto BigQuery `findings` rows."""
  if not findings:
    return []

  timestamp = _utc_now_iso()

  rows: List[Dict[str, Any]] = []
  for finding in findings:
    rows.append({
        "analysis": finding.analysis,
        "confidence_level": finding.confidence_level,
        "dismiss_reason": finding.dismiss_reason,
        "end_line": finding.end_line,
        "file_path": finding.file_path,
        "finding_id": finding.finding_id,
        "fingerprint": finding.fingerprint,
        "mute_reason": finding.mute_reason,
        "muted": finding.muted,
        "repository": repository,
        "scan_timestamp": timestamp,
        "session_id": finding.session_id,
        "severity": finding.severity,
        "source_stage": finding.source_stage,
        "snippet": finding.snippet,
        "start_line": finding.start_line,
        "status": finding.status,
        "title": finding.title,
        "verified": finding.verified,
        "vuln_id": finding.vuln_id,
        "vuln_type": finding.vuln_type,
    })

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
        gcp_bigquery.SchemaField("confidence", "INTEGER"),
        gcp_bigquery.SchemaField("confidence_level", "STRING"),
        gcp_bigquery.SchemaField("dismiss_reason", "STRING"),
        gcp_bigquery.SchemaField("end_line", "INTEGER", mode="REQUIRED"),
        gcp_bigquery.SchemaField("finding_id", "STRING"),
        gcp_bigquery.SchemaField("fingerprint", "STRING", mode="REQUIRED"),
        gcp_bigquery.SchemaField("muted", "BOOLEAN"),
        gcp_bigquery.SchemaField("mute_reason", "STRING"),
        gcp_bigquery.SchemaField("repository", "STRING", mode="REQUIRED"),
        gcp_bigquery.SchemaField("session_id", "STRING"),
        gcp_bigquery.SchemaField("severity", "STRING", mode="REQUIRED"),
        gcp_bigquery.SchemaField("title", "STRING", mode="REQUIRED"),
        gcp_bigquery.SchemaField("verified", "BOOLEAN"),
        gcp_bigquery.SchemaField("vuln_id", "STRING"),
        gcp_bigquery.SchemaField("vuln_type", "STRING", mode="REQUIRED"),
        gcp_bigquery.SchemaField("file_path", "STRING", mode="REQUIRED"),
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
  ) -> int:
    """Transforms CodeMender findings to telemetry rows and uploads them to BigQuery."""
    finding_rows = build_finding_rows(findings, repository=repository)
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

      self.client.query(f"""
MERGE `{self.table_id}` AS T
USING `{stage_table_id}` AS S
ON T.repository = S.repository AND T.fingerprint = S.fingerprint
WHEN MATCHED THEN UPDATE SET {updates_sql}
WHEN NOT MATCHED THEN INSERT ({columns_sql}) VALUES ({values_sql})
""", location=self.location).result()

      return len(rows_to_load)
    finally:
      self.client.delete_table(stage_table_id, not_found_ok=True)

