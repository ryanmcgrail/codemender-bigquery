import logging
import os
import re
import subprocess
from typing import Any, Dict, Iterable, List, Optional, Tuple

from finding import Finding

logger = logging.getLogger("fetch-bigquery-findings")

# --- Environment & Configuration Keys ---
ENV_DATASET = "CODEMENDER_BQ_DATASET"
ENV_PROJECT = "CODEMENDER_BQ_PROJECT"
ENV_LOCATION = "CODEMENDER_BQ_LOCATION"

_PROJECT_FALLBACK_ENV_KEYS = (
    "GOOGLE_CLOUD_PROJECT",
    "GOOGLE_CLOUD_PROJECT_ID",
    "GCLOUD_PROJECT",
)

DEFAULT_TABLE = "findings"
_TABLE_COMPONENT = re.compile(r"^[A-Za-z0-9_-]+$")


def resolve_dataset() -> Optional[str]:
  """Returns the configured BigQuery dataset name from environment, or None."""
  return (os.environ.get(ENV_DATASET) or "").strip() or None


def resolve_project() -> Optional[str]:
  """Returns the BigQuery project from environment variables, or None."""
  explicit = (os.environ.get(ENV_PROJECT) or "").strip()
  if explicit:
    return explicit
  for key in _PROJECT_FALLBACK_ENV_KEYS:
    value = (os.environ.get(key) or "").strip()
    if value:
      return value
  return None


def _resolve_project() -> Optional[str]:
  """Resolves the GCP project from environment or active gcloud configuration."""
  project = resolve_project()
  if project:
    return project
  try:
    result = subprocess.run(
        ["gcloud", "config", "get-value", "project"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
  except (OSError, subprocess.SubprocessError):
    return None
  project = (result.stdout or "").strip()
  return project if result.returncode == 0 and project and project != "(unset)" else None


def _table_id(project: str, dataset: str, table: str) -> str:
  """Validates and constructs a fully-qualified BigQuery table ID."""
  for value in (project, dataset, table):
    if not _TABLE_COMPONENT.fullmatch(value):
      raise ValueError(f"Invalid BigQuery identifier component: {value!r}")
  return f"{project}.{dataset}.{table}"


def ensure_dataset(
    client: Any, project: str, dataset: str, location: Optional[str] = None
) -> None:
  """Creates the configured BigQuery dataset if it does not already exist."""
  from google.cloud import bigquery  # pylint: disable=import-outside-toplevel

  dataset_resource = bigquery.Dataset(f"{project}.{dataset}")
  if location:
    dataset_resource.location = location
  client.create_dataset(dataset_resource, exists_ok=True)


def _text(row: Any, key: str) -> str:
  if isinstance(row, Finding):
    value = getattr(row, key, None)
  elif hasattr(row, "get"):
    value = row.get(key)
  else:
    value = getattr(row, key, None)
  return str(value).strip() if value is not None else ""


def _int_or_none(value: Any) -> Optional[int]:
  try:
    return int(value) if value is not None and str(value).strip() else None
  except (TypeError, ValueError):
    return None


def _finding_value(finding: Any, snake: str, pascal: str) -> Any:
  if isinstance(finding, Finding):
    val = getattr(finding, snake, None)
    return getattr(finding, pascal, None) if val is None else val
  value = finding.get(snake) if hasattr(finding, "get") else getattr(finding, snake, None)
  return (finding.get(pascal) if hasattr(finding, "get") else getattr(finding, pascal, None)) if value is None else value



def build_cm_import_record(row: Any) -> Dict[str, Any]:
  """Converts one telemetry row to the simple-JSON dialect accepted by CodeMender."""
  if isinstance(row, Finding):
    return row.to_cm_import_record()
  file_path = _text(row, "file_path")
  if not file_path:
    raise ValueError("A BigQuery finding without file_path cannot be imported")

  title = _text(row, "title") or _text(row, "vuln_type") or "CodeMender finding"
  record: Dict[str, Any] = {
      "file_path": file_path,
      "title": title,
      "message": _text(row, "analysis") or "Imported from CodeMender BigQuery findings.",
      "severity": _text(row, "severity") or "MEDIUM",
      "vuln_type": _text(row, "vuln_type") or _text(row, "cwe_id") or title,
  }
  for source, destination in (("start_line", "line"), ("end_line", "end_line")):
    line = _int_or_none(row.get(source))
    if line is not None:
      record[destination] = line
  snippet = _text(row, "snippet")
  if snippet:
    record["snippet"] = snippet
  return record


def _latest_findings_query(table_id: str) -> str:
  """Constructs the parameterized BigQuery query to fetch actionable findings."""
  return f"""
SELECT *
FROM `{table_id}`
WHERE repository = @repository
  AND NULLIF(TRIM(fingerprint), '') IS NOT NULL
  AND NULLIF(TRIM(file_path), '') IS NOT NULL
  AND UPPER(COALESCE(status, '')) NOT IN (
    'FIXED', 'REMEDIATED', 'PATCHED', 'DISMISSED', 'FALSE_POSITIVE', 'RESOLVED'
  )
"""


def fetch_findings_from_bigquery(
    client: Any,
    table_id: str,
    repository: str,
    location: Optional[str] = None,
) -> List[Finding]:
  """Loads one latest actionable source row per repository/fingerprint from BigQuery."""
  from google.cloud import bigquery  # pylint: disable=import-outside-toplevel

  try:
    config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("repository", "STRING", repository)
        ]
    )
    rows = client.query(
        _latest_findings_query(table_id), job_config=config, location=location
    ).result()
    return [
        Finding.from_dict(dict(row.items()) if hasattr(row, "items") else row)
        for row in rows
    ]
  except Exception as error:  # pylint: disable=broad-exception-caught
    logger.warning("Query failed on table %s: %s", table_id, error)
    return []