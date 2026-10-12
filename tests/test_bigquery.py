"""Unit tests for BigQuery class and helpers in bigquery.py."""

import types
import unittest
from unittest.mock import MagicMock

from google.cloud import bigquery as gcp_bigquery

import bigquery
from bigquery import BigQuery
from finding import Finding


class _Job:
  def result(self):
    return []


class _MockClient:
  def __init__(self):
    self.queries = []
    self.loaded = None
    self.deleted = None

  def query(self, query, **kwargs):
    self.queries.append(query)
    return _Job()

  def get_table(self, table_id):
    return types.SimpleNamespace(
        schema=[
            gcp_bigquery.SchemaField("repository", "STRING"),
            gcp_bigquery.SchemaField("fingerprint", "STRING"),
            gcp_bigquery.SchemaField("finding_id", "STRING"),
            gcp_bigquery.SchemaField("scan_timestamp", "TIMESTAMP"),
        ]
    )

  def load_table_from_json(self, rows, table_id, **kwargs):
    self.loaded = (rows, table_id, kwargs)
    return _Job()

  def delete_table(self, table_id, **kwargs):
    self.deleted = table_id


class BigQueryTests(unittest.TestCase):
  def test_table_id_valid(self):
    bq = BigQuery(project="my-proj", dataset="my_ds", table="my_table", client=MagicMock())
    self.assertEqual(bq.table_id, "my-proj.my_ds.my_table")

  def test_table_id_invalid(self):
    with self.assertRaises(ValueError):
      BigQuery(project="my-proj;drop table", dataset="my_ds", table="my_table", client=MagicMock())

  def test_ensure_dataset_creates_idempotently_in_requested_location(self):
    client = MagicMock()
    bigquery._ensure_dataset(client, "project", "dataset", "us-central1")

    dataset_resource = client.create_dataset.call_args.args[0]
    self.assertEqual(dataset_resource.project, "project")
    self.assertEqual(dataset_resource.dataset_id, "dataset")
    self.assertEqual(dataset_resource.location, "us-central1")
    self.assertTrue(client.create_dataset.call_args.kwargs["exists_ok"])

  def test_fetch_findings_success(self):
    client = MagicMock()
    mock_job = MagicMock()
    mock_job.result.return_value = [
        {"finding_id": "f-1", "repository": "acme/repo", "title": "Issue 1"}
    ]
    client.query.return_value = mock_job
    bq = BigQuery(project="proj", dataset="ds", table="tbl", client=client)

    results = bq.fetch_findings("acme/repo")
    self.assertEqual(len(results), 1)
    self.assertIsInstance(results[0], Finding)
    self.assertEqual(results[0].finding_id, "f-1")

  def test_fetch_findings_handles_exception(self):
    client = MagicMock()
    client.query.side_effect = RuntimeError("BigQuery unavailable")
    bq = BigQuery(project="proj", dataset="ds", table="tbl", client=client)

    results = bq.fetch_findings("acme/repo")
    self.assertEqual(results, [])

  def test_build_finding_rows(self):
    findings = [
        Finding(
            finding_id="fid-1",
            title="SQL injection in query",
            vuln_type="CWE-89",
            severity="HIGH",
            file_path="src/db.py",
            start_line=15,
            end_line=20,
            status="VERIFIED",
            fingerprint="fp-1",
        )
    ]
    rows = bigquery.build_finding_rows(
        findings, repository="acme/widgets", scan_timestamp="2026-10-07T00:00:00Z"
    )
    self.assertEqual(len(rows), 1)
    row = rows[0]
    self.assertEqual(row["finding_id"], "fid-1")
    self.assertEqual(row["repository"], "acme/widgets")
    self.assertEqual(row["severity"], "HIGH")
    self.assertEqual(row["start_line"], 15)
    self.assertEqual(row["status"], "VERIFIED")
    self.assertEqual(row["fingerprint"], "fp-1")
    self.assertTrue(row["verified"])
    self.assertNotIn("scan_id", row)
    self.assertNotIn("cwe_id", row)
    self.assertNotIn("fix_pr_url", row)
    self.assertNotIn("patch_status", row)
    self.assertNotIn("finding_source", row)

  def test_upload_findings(self):
    client = _MockClient()
    bq = BigQuery(project="project", dataset="dataset", table="findings", client=client)
    findings = [
        Finding(
            finding_id="cm-1",
            fingerprint="fp-1",
            file_path="src/app.py",
            title="XSS",
            vuln_type="XSS",
            start_line=5,
            status="OPEN",
        )
    ]
    merged = bq.upload_findings(
        findings=findings,
        repository="acme/widgets",
        repo_dir="/tmp/repo",
    )
    self.assertEqual(merged, 1)
    self.assertIn(
        "ON T.repository = S.repository AND T.fingerprint = S.fingerprint",
        client.queries[-1],
    )
    self.assertTrue(client.deleted.startswith("project.dataset._cm_stage_"))


if __name__ == "__main__":
  unittest.main()
