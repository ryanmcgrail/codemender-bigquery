import argparse
import logging
import os
import shutil
import subprocess
import sys
from typing import Any, Iterable, Optional, Sequence

from bigquery import BigQuery
from codemender import CodeMender
from finding import Finding

logger = logging.getLogger("codemender-bigquery-roundtrip")


def _resolve_project() -> Optional[str]:
  """Resolves the GCP project from environment or active gcloud configuration."""
  project = os.environ.get("GOOGLE_CLOUD_PROJECT")
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


def _print_heading(title: str):
  print()
  print("#########################")
  print("## " + title)
  print("#########################")
  print()


def _print_findings(findings: Iterable[Finding]):
  sorted_findings = sorted(findings, key=lambda finding: finding.fingerprint)
  for i in range(len(sorted_findings)):
    finding = sorted_findings[i]
    print(f"  {1+i}) [{finding.fingerprint}] {finding.title}")


def run_roundtrip(
    *,
    repository: str,
    repo_dir: str,
    project: str,
    dataset: str,
    table: Optional[str] = None,
    cm_binary: Optional[str] = None,
    location: Optional[str] = None,
    client: Any = None,
):
  """Runs the BigQuery -> cm import/find -> BigQuery round trip."""
  if not os.path.isdir(repo_dir):
    raise ValueError(f"Repository directory does not exist: {repo_dir}")
  if not repository.strip():
    raise ValueError("Repository name must not be empty")

  bq = BigQuery(
      project=project,
      dataset=dataset,
      table=table,
      location=location,
      client=client,
  )
  cm = CodeMender(
      cm_binary=cm_binary,
      repo_dir=repo_dir,
  )

  _print_heading("Fetching latest findings from BigQuery...")

  print("BigQuery findings:")
  bq_findings = bq.fetch_findings(repository)
  _print_findings(bq_findings)
  print()

  print("Existing CodeMender findings:")
  cm_findings = cm.list_findings()
  _print_findings(cm_findings)
  print()

  newly_imported_findings = cm.import_findings(bq_findings)

  print(f"Imported {len(newly_imported_findings)} findings into CodeMender.")

  _print_heading("Running CodeMender find on repository...")

  cm.find()

  _print_heading("Uploading findings to BigQuery...")
  cm_findings_after_find = cm.list_findings()
  bq.upload_findings(
      findings=cm_findings_after_find,
      repository=repository,
      repo_dir=repo_dir,
  )

  bq_findings_after_upload = bq.fetch_findings(repository)

  print("BigQuery findings after upload:")
  _print_findings(bq_findings_after_upload)


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--repository", required=True, help="BigQuery repository value, e.g. owner/name")
  parser.add_argument("--repo-dir", required=True, help="Local CodeMender checkout to process")
  parser.add_argument("--project", default=_resolve_project())
  parser.add_argument("--dataset", required=True)
  parser.add_argument("--table", default=None)
  parser.add_argument("--cm-binary", default=shutil.which("cm") or "cm")
  parser.add_argument("--location", default=None)
  parser.add_argument("--dry-run", action="store_true", help="Show eligible import counts without changing CodeMender or BigQuery")
  args = parser.parse_args(argv)
  if not args.project:
    parser.error("--project or GOOGLE_CLOUD_PROJECT is required")
  if not args.dataset:
    parser.error("--dataset is required")
  return args


def main(argv: Optional[Sequence[str]] = None) -> int:
  logging.basicConfig(level=logging.ERROR, format="%(levelname)s %(message)s")
  args = _parse_args(argv)
  try:
    run_roundtrip(
        repository=args.repository,
        repo_dir=os.path.abspath(os.path.expanduser(args.repo_dir)),
        project=args.project,
        dataset=args.dataset,
        table=args.table,
        cm_binary=args.cm_binary,
        location=args.location,
    )
  except Exception as error:  # pylint: disable=broad-exception-caught
    logger.error("BigQuery CodeMender round-trip failed: %s", error)
    return 1
  return 0


if __name__ == "__main__":
  sys.exit(main())