"""Import BigQuery findings into CodeMender, verify/fix them, and sync state back.

Example:
  python codemender_bigquery_roundtrip.py \
    --repository acme/widgets --repo-dir /work/widgets \
    --project my-gcp-project --dataset codemender_telemetry

The historical ``vulnerability_findings`` table remains append-only. Results
are merged into ``current_findings_by_id`` using
``(repository, finding_id)`` as the logical key.
"""

import argparse
import json
import logging
import os
import re
import shutil
import sys
import subprocess
import tempfile
import uuid
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from codemender_agent.codemender.importer import import_findings
from codemender_agent.codemender.importer import read_findings
from codemender_agent.codemender.importer import write_import_payload
from codemender_agent.codemender.cli import is_ci_gate_exit
from codemender_agent.telemetry import bigquery as telemetry
from codemender_agent.utils import build_cm_command
from codemender_agent.utils import run_command
from codemender_agent.vcs.git import compute_finding_fingerprint
from codemender_agent.vcs.git import normalize_repo_relative_path

logger = logging.getLogger("codemender-bigquery-roundtrip")

DEFAULT_SOURCE_TABLE = "vulnerability_findings"
DEFAULT_TARGET_TABLE = "current_findings_by_id"
_TABLE_COMPONENT = re.compile(r"^[A-Za-z0-9_-]+$")

def _table_id(project: str, dataset: str, table: str) -> str:
  for value in (project, dataset, table):
    if not _TABLE_COMPONENT.fullmatch(value):
      raise ValueError(f"Invalid BigQuery identifier component: {value!r}")
  return f"{project}.{dataset}.{table}"


def ensure_dataset(
    client: Any, project: str, dataset: str, location: Optional[str] = None,
) -> None:
  """Creates the configured BigQuery dataset if it does not already exist."""
  from google.cloud import bigquery  # pylint: disable=import-outside-toplevel

  dataset_resource = bigquery.Dataset(f"{project}.{dataset}")
  if location:
    dataset_resource.location = location
  client.create_dataset(dataset_resource, exists_ok=True)


def ensure_vulnerability_findings_table(
    client: Any,
    project: str,
    dataset: str,
 ) -> None:
  """Creates the telemetry-compatible source findings table when absent."""
  from google.cloud import bigquery  # pylint: disable=import-outside-toplevel

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
  table = bigquery.Table(
      _table_id(project, dataset, DEFAULT_SOURCE_TABLE), schema=schema
  )
  table.time_partitioning = bigquery.TimePartitioning(
      type_=bigquery.TimePartitioningType.DAY, field="scan_timestamp"
  )
  table.clustering_fields = ["repository", "severity", "vuln_type"]
  table.description = "One row per CodeMender vulnerability finding."
  client.create_table(table, exists_ok=True)


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


def build_cm_import_record(row: Mapping[str, Any]) -> Dict[str, Any]:
  """Converts one telemetry row to the simple-JSON dialect accepted by cm."""
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


def deduplicate_rows_by_key(
    rows: Iterable[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
  """Keeps the last row for each repository/finding_id pair."""
  keyed: Dict[Tuple[str, str], Dict[str, Any]] = {}
  for row in rows:
    keyed[_row_key(row)] = dict(row)
  return list(keyed.values())


def _latest_findings_query(source_table_id: str) -> str:
  return f"""
SELECT * FROM (
  SELECT *
  FROM `{source_table_id}`
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
    source_table_id: str,
    repository: str,
    location: Optional[str] = None,
) -> List[Dict[str, Any]]:
  """Loads one latest actionable source row per repository/finding_id."""
  from google.cloud import bigquery  # pylint: disable=import-outside-toplevel

  config = bigquery.QueryJobConfig(
      query_parameters=[bigquery.ScalarQueryParameter("repository", "STRING", repository)]
  )
  rows = client.query(
      _latest_findings_query(source_table_id), job_config=config, location=location
  ).result()
  return [dict(row.items()) for row in rows]


def _finding_value(finding: Mapping[str, Any], snake: str, pascal: str) -> Any:
  value = finding.get(snake)
  return finding.get(pascal) if value is None else value


def _fingerprint_for_cm_finding(
    finding: Mapping[str, Any], repo_dir: str,
) -> Optional[str]:
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


if __name__ == "__main__":
  sys.exit(main())


def main(argv: Optional[Sequence[str]] = None) -> int:
  logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
  args = _parse_args(argv)
  try:
    summary = run_roundtrip(
        repository=args.repository,
        repo_dir=os.path.abspath(os.path.expanduser(args.repo_dir)),
        project=args.project,
        dataset=args.dataset,
        source_table=args.source_table,
        target_table=args.target_table,
        cm_binary=args.cm_binary,
        cli_version=args.cli_version,
        location=args.location,
    )
  except Exception as error:  # pylint: disable=broad-exception-caught
    logger.error("BigQuery CodeMender round-trip failed: %s", error)
    return 1
  print(json.dumps(summary, indent=2))
  return 0


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--repository", required=True, help="BigQuery repository value, e.g. owner/name")
  parser.add_argument("--repo-dir", required=True, help="Local CodeMender checkout to process")
  parser.add_argument("--project", default=_resolve_project())
  parser.add_argument("--dataset", default=telemetry.resolve_dataset())
  parser.add_argument("--source-table", default=DEFAULT_SOURCE_TABLE)
  parser.add_argument("--target-table", default=DEFAULT_TARGET_TABLE)
  parser.add_argument("--cm-binary", default=shutil.which("cm") or "cm")
  parser.add_argument("--cli-version", default=os.environ.get("CODEMENDER_CLI_VERSION", "preview"))
  parser.add_argument("--location", default=os.environ.get("CODEMENDER_BQ_LOCATION"))
  parser.add_argument("--dry-run", action="store_true", help="Show eligible import counts without changing CodeMender or BigQuery")
  args = parser.parse_args(argv)
  if not args.project:
    parser.error("--project or CODEMENDER_BQ_PROJECT/GOOGLE_CLOUD_PROJECT is required")
  if not args.dataset:
    parser.error("--dataset or CODEMENDER_BQ_DATASET is required")
  return args


def _resolve_project() -> Optional[str]:
  project = telemetry.resolve_project()
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


def run_roundtrip(
    *,
    repository: str,
    repo_dir: str,
    project: str,
    dataset: str,
    source_table: str = DEFAULT_SOURCE_TABLE,
    target_table: str = DEFAULT_TARGET_TABLE,
    cm_binary: Optional[str] = None,
    cli_version: Optional[str] = None,
    location: Optional[str] = None,
    client: Any = None,
) -> Dict[str, int]:
  """Runs the BigQuery -> cm import/verify/fix -> BigQuery round trip."""
  if not os.path.isdir(repo_dir):
    raise ValueError(f"Repository directory does not exist: {repo_dir}")
  if not repository.strip():
    raise ValueError("Repository name must not be empty")
  source_table_id = _table_id(project, dataset, source_table)
  target_table_id = _table_id(project, dataset, target_table)
  if source_table_id == target_table_id:
    raise ValueError("The current-state target must differ from the history source table")

  if client is None:
    from google.cloud import bigquery  # pylint: disable=import-outside-toplevel

    client = bigquery.Client(project=project)
  ensure_dataset(client, project, dataset, location)
  if source_table == DEFAULT_SOURCE_TABLE:
    ensure_vulnerability_findings_table(client, project, dataset)
  cm_binary = cm_binary or shutil.which("cm") or "cm"

  source_rows = fetch_latest_findings(
      client, source_table_id, repository, location=location
  )

  scanned_findings = 0
  if not source_rows:
    before_findings = read_findings(cm_binary, repo_dir, cli_version=cli_version)
    before_ids = {_finding_id(finding) for finding in before_findings}
    _run_cm_find(cm_binary, repo_dir, cli_version)
    post_import_findings = read_findings(
        cm_binary, repo_dir, cli_version=cli_version
    )
    new_findings = [
        finding
        for finding in post_import_findings
        if _finding_id(finding) and _finding_id(finding) not in before_ids
    ]
    repo_findings = [
        finding
        for finding in post_import_findings
        if _is_repo_finding(finding, repo_dir)
    ]
    candidate_findings = (
        [f for f in new_findings if _is_repo_finding(f, repo_dir)]
        if new_findings
        else repo_findings
    )
    source_ids_by_cm_id = {
        _finding_id(finding): _finding_id(finding)
        for finding in candidate_findings
        if _finding_id(finding)
    }
    import_rows: List[Mapping[str, Any]] = []
    import_records: List[Dict[str, Any]] = []
    scanned_findings = len(candidate_findings)
  else:
    before_findings = read_findings(cm_binary, repo_dir, cli_version=cli_version)
    source_ids_by_cm_id = _match_cm_findings_to_source_rows(
        source_rows, before_findings, repo_dir
    )
    already_present_source_ids = set(source_ids_by_cm_id.values())
    import_rows = [
        row
        for row in source_rows
        if _row_key(row)[1] not in already_present_source_ids
    ]
    import_records = [build_cm_import_record(row) for row in import_rows]
    post_import_findings = list(before_findings)

  imported_ids: List[str] = []
  imported_source_ids: Dict[str, str] = {}
  if import_records:
    with tempfile.TemporaryDirectory(prefix="cm-bq-roundtrip-") as temp_dir:
      payload_path = write_import_payload(
          import_records, os.path.join(temp_dir, "bigquery_findings.json")
      )
      imported_ids, post_import_findings = import_findings(
          cm_binary, payload_path, repo_dir, cli_version=cli_version
      )
    imported_source_ids = _match_cm_findings_to_source_rows(
        import_rows, post_import_findings, repo_dir, required_cm_ids=imported_ids
    )

  source_ids_by_cm_id.update(imported_source_ids)
  ids_to_process = set(source_ids_by_cm_id)

  findings_by_id = {_finding_id(row): row for row in post_import_findings}

  after_findings = (
      list(post_import_findings)
      if scan_only
      else read_findings(cm_binary, repo_dir, cli_version=cli_version)
  )
  final_findings_by_id = {_finding_id(row): row for row in after_findings}

  findings_for_upload = [
      _to_telemetry_finding(
          finding, repo_dir, source_ids_by_cm_id.get(_finding_id(finding))
      )
      for finding in after_findings
      if _finding_id(finding) in ids_to_process
  ]
  context = telemetry.ScanRunContext(
      stage="bigquery_roundtrip",
      scan_id=str(uuid.uuid4()),
      repository=repository,
      repo_dir=repo_dir,
      skip_verify=False,
  )
  finding_rows = telemetry.build_finding_rows(
      context, findings_for_upload, with_snippets=False
  )
  merged = merge_current_findings(
      client,
      source_table_id,
      target_table_id,
      finding_rows,
      location=location,
  )
  return {
      "source_findings": len(source_rows),
      "scanned_findings": scanned_findings,
      "already_in_code_mender": len(source_rows) - len(import_rows),
      "to_import": len(import_records),
      "imported": len(imported_ids),
      "merged": merged,
  }


def _run_cm_find(
    cm_binary: str, repo_dir: str, cli_version: Optional[str]
) -> None:
  command = build_cm_command(
      cm_binary, "find", target_or_id=repo_dir, cli_version=cli_version
  )
  result = run_command(command, cwd=repo_dir, check=False)
  returncode = getattr(result, "returncode", 0)
  stdout = getattr(result, "stdout", "")
  if returncode and not is_ci_gate_exit(returncode, stdout or ""):
    raise RuntimeError(f"cm find failed with exit code {returncode}")


def _to_telemetry_finding(
  finding: Mapping[str, Any], repo_dir: str, source_finding_id: Optional[str] = None,
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
    source_table_id: str,
    target_table_id: str,
    rows: Sequence[Mapping[str, Any]],
    location: Optional[str] = None,
) -> int:
  """MERGEs rows by repository/finding_id into a separate current-state table."""
  if not rows:
    return 0
  if source_table_id == target_table_id:
    raise ValueError("The current-state target must differ from the history source table")

  client.query(
      f"CREATE TABLE IF NOT EXISTS `{target_table_id}` "
      f"AS SELECT * FROM `{source_table_id}` WHERE FALSE",
      location=location,
  ).result()
  target_table = client.get_table(target_table_id)
  schema = target_table.schema
  columns = [field.name for field in schema]
  identity = {"repository", "finding_id"}
  missing_identity = identity.difference(columns)
  if missing_identity:
    raise ValueError(
        "Current-state table is missing key columns: "
        + ", ".join(sorted(missing_identity))
    )

  unique_rows = deduplicate_rows_by_key(rows)
  staged_rows = [
      {key: value for key, value in row.items() if key in columns}
      for row in unique_rows
  ]
  stage_table_id = f"{target_table_id.rsplit('.', 1)[0]}._cm_stage_{uuid.uuid4().hex}"
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
MERGE `{target_table_id}` AS T
USING `{stage_table_id}` AS S
ON T.repository = S.repository AND T.finding_id = S.finding_id
WHEN MATCHED THEN UPDATE SET {updates_sql}
WHEN NOT MATCHED THEN INSERT ({columns_sql}) VALUES ({values_sql})
"""
    client.query(merge_sql, location=location).result()
    return len(unique_rows)
  finally:
    client.delete_table(stage_table_id, not_found_ok=True)