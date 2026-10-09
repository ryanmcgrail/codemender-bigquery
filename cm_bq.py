"""Import BigQuery findings into CodeMender, verify/fix them, and sync state back.

Example:
  python codemender_bigquery_roundtrip.py \
    --repository acme/widgets --repo-dir /work/widgets \
    --project my-gcp-project --dataset codemender_telemetry

Findings are fetched from and merged into the ``findings`` table using
``(repository, fingerprint)`` as the logical key.
"""

import argparse
import json
import logging
import os
from pprint import pprint
import shutil
import sys
from typing import Any, Dict, Optional, Sequence

from codemender import CodeMender
from step_1_import_from_bq import (
    DEFAULT_TABLE,
    _resolve_project,
    _table_id,
    ensure_dataset,
    fetch_findings_from_bigquery,
    resolve_dataset,
    resolve_project,
)
from step_3_export_to_bq import (
    ScanRunContext,
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
):
  """Runs the BigQuery -> cm import/verify/fix -> BigQuery round trip."""
  if not os.path.isdir(repo_dir):
    raise ValueError(f"Repository directory does not exist: {repo_dir}")
  if not repository.strip():
    raise ValueError("Repository name must not be empty")
  table_id = _table_id(project, dataset, table)

  if client is None:
    from google.cloud import bigquery  # pylint: disable=import-outside-toplevel

    client = bigquery.Client(project=project)

  cm = CodeMender(
    cm_binary = cm_binary,
    repo_dir = repo_dir,
    cli_version = cli_version
  )

  _print_heading("Fetching latest findings from BigQuery...")

  ensure_dataset(client, project, dataset, location)
  bq_findings = fetch_findings_from_bigquery(
      client, table_id, repository, location=location
  )

  print("BigQuery findings:")
  pprint(bq_findings, indent = 2)
  print()

  imported_ids, after_find_findings = cm.import_findings(bq_findings)

  print(f"Imported {len(imported_ids)} findings into CodeMender.")

  _print_heading("Running CodeMender find on repository...")

  cm.find('routes/login.ts')

  _print_heading("Exporting findings to BigQuery...")
  cm_findings = cm.list_findings()
  merged = export_findings_to_bigquery(
      client=client,
      table_id=table_id,
      findings=cm_findings,
      repository=repository,
      repo_dir=repo_dir,
      location=location,
      merge_fn=merge_current_findings,
  )


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
  logging.basicConfig(level=logging.ERROR, format="%(levelname)s %(message)s")
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
  return 0


if __name__ == "__main__":
  sys.exit(main())