"""Import BigQuery findings into CodeMender, verify/fix them, and sync state back.

Example:
  python codemender_bigquery_roundtrip.py \
    --repository acme/widgets --repo-dir /work/widgets \
    --project my-gcp-project --dataset codemender_telemetry

Findings are fetched from and merged into the ``findings`` table using
``(repository, finding_id)`` as the logical key.
"""

import argparse
import json
import logging
import os
from pprint import pprint
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple


from step_1_import_from_bq import (
    DEFAULT_TABLE,
    _finding_id,
    _latest_findings_query,
    _resolve_project,
    _row_key,
    _table_id,
    build_cm_import_record,
    deduplicate_rows_by_key,
    ensure_dataset,
    fetch_latest_findings,
    resolve_dataset,
    resolve_project,
)
from step_2_cm_find import (
    _run_cm_find,
    import_findings,
    read_findings,
    write_import_payload,
)
from step_3_export_to_bq import (
    ScanRunContext,
    _to_telemetry_finding,
    build_finding_rows,
    export_findings_to_bigquery,
    merge_current_findings,
)


import types
telemetry = types.SimpleNamespace(
    resolve_project=resolve_project,
    resolve_dataset=resolve_dataset,
    ScanRunContext=ScanRunContext,
    build_finding_rows=build_finding_rows,
)

logger = logging.getLogger("codemender-bigquery-roundtrip")


def _print_heading(title: str):
  print()
  print("#########################")
  print("## " + title)
  print("#########################")
  print()


def run_roundtrip(
    *,
    repository: str,
    repo_dir: str,
    project: str,
    dataset: str,
    table: str = DEFAULT_TABLE,
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
  table_id = _table_id(project, dataset, table)

  if client is None:
    from google.cloud import bigquery  # pylint: disable=import-outside-toplevel

    client = bigquery.Client(project=project)
  cm_binary = cm_binary or shutil.which("cm") or "cm"

  _print_heading("Fetching latest findings from BigQuery...")
  ensure_dataset(client, project, dataset, location)
  source_rows = fetch_latest_findings(
      client, table_id, repository, location=location
  )

  print("Previous findings:")
  pprint(source_rows, indent = 2)

  _print_heading("Running CodeMender find on repository...")
  scanned_findings = 0
  scan_only = not source_rows
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
    candidate_findings = new_findings if new_findings else post_import_findings
    source_ids_by_cm_id = {
        _finding_id(finding): _finding_id(finding)
        for finding in candidate_findings
        if _finding_id(finding)
    }
    import_rows: List[Mapping[str, Any]] = []
    import_records: List[Dict[str, Any]] = []
    scanned_findings = len(candidate_findings)
  else:
    _run_cm_find(cm_binary, repo_dir, cli_version)
    before_findings = read_findings(cm_binary, repo_dir, cli_version=cli_version)
    before_ids = {_finding_id(f) for f in before_findings if _finding_id(f)}
    source_ids_by_cm_id = {fid: fid for fid in before_ids}
    import_rows = [
        row
        for row in source_rows
        if _finding_id(row) not in before_ids
    ]
    import_records = [build_cm_import_record(row) for row in import_rows]
    post_import_findings = list(before_findings)
    scanned_findings = len(before_findings)

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
    imported_source_ids = {fid: fid for fid in imported_ids}

  source_ids_by_cm_id.update(imported_source_ids)
  ids_to_process = set(source_ids_by_cm_id)

  after_findings = (
      list(post_import_findings)
      if scan_only
      else read_findings(cm_binary, repo_dir, cli_version=cli_version)
  )

  _print_heading("Exporting findings to BigQuery...")
  merged = export_findings_to_bigquery(
      client=client,
      table_id=table_id,
      findings=after_findings,
      repository=repository,
      repo_dir=repo_dir,
      location=location,
      source_ids_by_cm_id=source_ids_by_cm_id,
      ids_to_process=ids_to_process,
      merge_fn=merge_current_findings,
  )
  return {
      "source_findings": len(source_rows),
      "scanned_findings": scanned_findings,
      "already_in_code_mender": len(source_rows) - len(import_rows),
      "to_import": len(import_records),
      "imported": len(imported_ids),
      "merged": merged,
  }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--repository", required=True, help="BigQuery repository value, e.g. owner/name")
  parser.add_argument("--repo-dir", required=True, help="Local CodeMender checkout to process")
  parser.add_argument("--project", default=_resolve_project())
  parser.add_argument("--dataset", default=resolve_dataset())
  parser.add_argument("--table", default=DEFAULT_TABLE)
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


def main(argv: Optional[Sequence[str]] = None) -> int:
  logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
  args = _parse_args(argv)
  try:
    summary = run_roundtrip(
        repository=args.repository,
        repo_dir=os.path.abspath(os.path.expanduser(args.repo_dir)),
        project=args.project,
        dataset=args.dataset,
        table=args.table,
        cm_binary=args.cm_binary,
        cli_version=args.cli_version,
        location=args.location,
    )
  except Exception as error:  # pylint: disable=broad-exception-caught
    logger.error("BigQuery CodeMender round-trip failed: %s", error)
    return 1
  print(json.dumps(summary, indent=2))
  return 0


if __name__ == "__main__":
  sys.exit(main())