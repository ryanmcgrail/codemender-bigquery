"""Fetch actionable CodeMender security findings from Google BigQuery.

This script pulls the latest actionable findings for a repository from a
BigQuery dataset/table, filtering out closed/remediated findings.

It is completely standalone with no internal dependencies on `codemender_agent`.
Only `google-cloud-bigquery` is required.

Example usage:
  python fetch_bigquery_findings.py \
    --repository ryanmcgrail/juice-shop \
    --project test-project-502314 \
    --dataset codemender_juice_shop \
    --table findings
"""

import argparse
import datetime
import hashlib
import json
import logging
import os
from pprint import pprint
import re
import subprocess
import sys
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

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
_CLOSED_STATUSES = frozenset(
    {"FIXED", "REMEDIATED", "PATCHED", "DISMISSED", "FALSE_POSITIVE", "RESOLVED"}
)


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


def _text(row: Mapping[str, Any], key: str) -> str:
  value = row.get(key)
  return str(value).strip() if value is not None else ""


def _int_or_none(value: Any) -> Optional[int]:
  try:
    return int(value) if value is not None and str(value).strip() else None
  except (TypeError, ValueError):
    return None


def _row_key(row: Mapping[str, Any]) -> Tuple[str, str]:
  repository = _text(row, "repository")
  finding_id = _text(row, "finding_id")
  if not repository or not finding_id:
    raise ValueError("A unique finding must have repository and finding_id")
  return repository, finding_id


def deduplicate_rows_by_key(
    rows: Iterable[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
  """Keeps the last row for each (repository, finding_id) pair."""
  keyed: Dict[Tuple[str, str], Dict[str, Any]] = {}
  for row in rows:
    if isinstance(row, dict):
      keyed[_row_key(row)] = dict(row)
    elif hasattr(row, "items"):
      keyed[_row_key(row)] = dict(row.items())
    else:
      keyed[_row_key(row)] = dict(row)
  return list(keyed.values())


def _finding_value(finding: Mapping[str, Any], snake: str, pascal: str) -> Any:
  value = finding.get(snake)
  return finding.get(pascal) if value is None else value


def _finding_id(finding: Mapping[str, Any]) -> str:
  value = _finding_value(finding, "finding_id", "FindingID")
  return str(value) if value else ""


def _is_repo_finding(finding: Mapping[str, Any], repo_dir: str) -> bool:
  file_path = _finding_value(finding, "file_path", "FilePath")
  if not file_path:
    return False
  clean_repo = os.path.abspath(repo_dir).replace("\\", "/")
  raw = str(file_path).strip().replace("\\", "/")
  if os.path.isabs(raw):
    clean_path = os.path.abspath(raw).replace("\\", "/")
    return clean_path == clean_repo or clean_path.startswith(clean_repo + "/")
  return not raw.startswith("/")


def normalize_repo_relative_path(path: str, repo_dir: Optional[str] = None) -> str:
  """Normalizes a file path to be strictly repository-relative with forward slashes."""
  if not path:
    return ""
  p = path.strip().replace("\\", "/")
  if repo_dir:
    clean_repo_dir = os.path.abspath(repo_dir).replace("\\", "/")
    if p == clean_repo_dir:
      return ""
    if p.startswith(clean_repo_dir + "/"):
      p = p[len(clean_repo_dir) + 1 :]
    elif os.path.isabs(p):
      try:
        rel = os.path.relpath(p, clean_repo_dir).replace("\\", "/")
        if not rel.startswith("../") and rel != "..":
          p = rel
      except ValueError:
        pass

  # Strip leading CI runner mount patterns if present
  p = re.sub(r"^/?__w/[^/]+/[^/]+(?:/[^/]+)?/", "", p)
  p = re.sub(r"^/?github/workspace/", "", p)
  # Strip any leading slashes, dots, or relative traversal markers
  p = re.sub(r"^(\.\./)+", "", p)
  p = re.sub(r"^\.?/+", "", p)
  return p


def compute_finding_fingerprint(
    file_path: str, vuln_type: str, start_line: int
) -> str:
  """Computes a deterministic 8-character SHA256 fingerprint for a finding."""
  norm_path = normalize_repo_relative_path(file_path)
  norm_type = (vuln_type or "vulnerability").strip().lower()
  raw_hash_str = f"{norm_path}|{norm_type}|{start_line}"
  return hashlib.sha256(raw_hash_str.encode("utf-8")).hexdigest()[:8]


def build_cm_import_record(row: Mapping[str, Any]) -> Dict[str, Any]:
  """Converts one telemetry row to the simple-JSON dialect accepted by CodeMender."""
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
  """Constructs the parameterized BigQuery query to fetch the latest actionable findings."""
  return f"""
SELECT * FROM (
  SELECT *
  FROM `{table_id}`
  WHERE repository = @repository
    AND NULLIF(TRIM(finding_id), '') IS NOT NULL
    AND NULLIF(TRIM(file_path), '') IS NOT NULL
  QUALIFY ROW_NUMBER() OVER (
    PARTITION BY repository, finding_id
    ORDER BY scan_timestamp DESC, scan_id DESC
  ) = 1
)
WHERE UPPER(COALESCE(status, '')) NOT IN (
  'FIXED', 'REMEDIATED', 'PATCHED', 'DISMISSED', 'FALSE_POSITIVE', 'RESOLVED'
)
"""


def fetch_latest_findings(
    client: Any,
    table_id: str,
    repository: str,
    location: Optional[str] = None,
) -> List[Dict[str, Any]]:
  """Loads one latest actionable source row per repository/finding_id from BigQuery."""
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
    return [dict(row.items()) for row in rows]
  except Exception as error:  # pylint: disable=broad-exception-caught
    logger.warning("Query failed on table %s: %s", table_id, error)
    return []


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument(
      "--repository",
      required=True,
      help="BigQuery repository filter value, e.g. owner/name",
  )
  parser.add_argument(
      "--project",
      default=_resolve_project(),
      help="GCP project ID (defaults to CODEMENDER_BQ_PROJECT or active gcloud config)",
  )
  parser.add_argument(
      "--dataset",
      default=resolve_dataset(),
      help="BigQuery dataset name (defaults to CODEMENDER_BQ_DATASET)",
  )
  parser.add_argument(
      "--table",
      default=DEFAULT_TABLE,
      help=f"BigQuery table name (default: {DEFAULT_TABLE})",
  )
  parser.add_argument(
      "--location",
      default=os.environ.get(ENV_LOCATION),
      help="BigQuery dataset geographic location (optional)",
  )
  parser.add_argument(
      "--output",
      help="Optional file path to write findings JSON output",
  )
  parser.add_argument(
      "--format",
      choices=["json", "pretty", "table"],
      default="pretty",
      help="Output display format (default: pretty)",
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

  table_id = _table_id(args.project, args.dataset, args.table)
  from google.cloud import bigquery  # pylint: disable=import-outside-toplevel

  client = bigquery.Client(project=args.project)
  ensure_dataset(client, args.project, args.dataset, args.location)

  findings = fetch_latest_findings(
      client=client,
      table_id=table_id,
      repository=args.repository,
      location=args.location,
  )

  # Format output
  if args.output:
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
      json.dump(findings, f, default=str, indent=2)
    print(f"Wrote {len(findings)} finding(s) to {args.output}")
  elif args.format == "json":
    print(json.dumps(findings, default=str, indent=2))
  elif args.format == "pretty":
    print(f"Fetched {len(findings)} actionable finding(s) from {table_id} for {args.repository}:")
    pprint(findings, indent=2)
  elif args.format == "table":
    print(f"{'FINDING ID':<38} {'SEVERITY':<10} {'TYPE':<25} {'FILE PATH'}")
    print("-" * 100)
    for row in findings:
      fid = _text(row, "finding_id")
      sev = _text(row, "severity") or "UNKNOWN"
      vtype = _text(row, "vuln_type") or _text(row, "cwe_id") or "UNKNOWN"
      fpath = _text(row, "file_path")
      print(f"{fid:<38} {sev:<10} {vtype:<25} {fpath}")

  return 0


if __name__ == "__main__":
  sys.exit(main())

