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
import re
import shutil
import sys
import subprocess
import tempfile
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
import uuid

from run_codemender_find import (
    FindingImportError,
    IMPORTED_FINDING_FIELDS,
    SECRET_PATTERNS,
    _ids,
    _match_cm_findings_to_source_rows,
    _run_cm_action,
    _run_cm_find,
    build_cm_command,
    extract_json_from_output,
    filter_supported_flags,
    get_supported_cm_flags,
    import_findings,
    is_ci_gate_exit,
    parse_findings_json,
    parse_help_flags,
    parse_token_metric,
    read_findings,
    redact_sensitive_arg,
    resolve_command_flags,
    resolve_command_model,
    run_cm_action,
    run_cm_find,
    run_command,
    write_import_payload,
)


from export_bigquery_findings import (
    ScanRunContext,
    _fingerprint_for_cm_finding,
    _to_telemetry_finding,
    build_finding_rows,
    export_findings_to_bigquery,
    merge_current_findings,
)
from fetch_bigquery_findings import (
    DEFAULT_TABLE,
    _finding_id,
    _finding_value,
    _int_or_none,
    _is_repo_finding,
    _latest_findings_query,
    _resolve_project,
    _row_key,
    _table_id,
    _text,
    build_cm_import_record,
    compute_finding_fingerprint,
    deduplicate_rows_by_key,
    ensure_dataset,
    fetch_latest_findings,
    normalize_repo_relative_path,
    resolve_dataset,
    resolve_project,
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