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
  sorted_findings = sorted(findings, key=lambda f: f.title.upper())

  if len(sorted_findings) == 0:
    print("  (None)")
    return

  for i in range(len(sorted_findings)):
    finding = sorted_findings[i]
    print(f"  {1+i}) [{finding.fingerprint}] {finding.title}")


def run_roundtrip(
    repository: str,
    repo_dir: str,
    project: str,
    dataset: str,
    table: Optional[str] = None,
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
      cm_binary=shutil.which("cm") or "cm",
      repo_dir=repo_dir,
  )

  _print_heading("Fetching latest findings from BigQuery...")

  print("BigQuery findings:")
  preexisting_bq_findings = bq.fetch_findings(repository)
  _print_findings(preexisting_bq_findings)
  print()

  print("Existing CodeMender findings:")
  cm_findings = cm.list_findings()
  _print_findings(cm_findings)
  print()

  newly_imported_findings = cm.import_findings(preexisting_bq_findings)
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

  print("BigQuery findings after upload:")
  bq_findings_after_upload = bq.fetch_findings(repository)
  _print_findings(bq_findings_after_upload)
  print()

  print("New BigQuery findings:")
  preexisting_bq_fingerprints = set([f.fingerprint for f in preexisting_bq_findings])
  _print_findings([f for f in bq_findings_after_upload if f not in preexisting_bq_fingerprints])


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--repository", required=True, help="Repository to associate findings with in BigQuery.")
  parser.add_argument("--repo-dir", required=True, help="Local repository directory to scan with CodeMender.")
  parser.add_argument("--project", default=_resolve_project(), help="Google Cloud project id.")
  parser.add_argument("--dataset", required=True, help="BigQuery dataset name to add findings to. Will be created if it does not exist.")
  parser.add_argument("--table", default=None, help="BigQuery table name to create under the dataset. ")
  parser.add_argument("--location", default=None, help="Location to store the dataset/table within.")
  args = parser.parse_args(argv)
  if not args.project:
    parser.error("--project or GOOGLE_CLOUD_PROJECT is required")
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
        location=args.location,
    )
  except Exception as error:  # pylint: disable=broad-exception-caught
    logger.error("cm_bq failed: %s", error)
    return 1
  return 0


if __name__ == "__main__":
  sys.exit(main())