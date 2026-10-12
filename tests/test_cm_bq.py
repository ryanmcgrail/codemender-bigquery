"""Tests for the standalone BigQuery/CodeMender round-trip script."""

import tempfile
import types
import unittest
from unittest.mock import MagicMock, patch

from google.cloud import bigquery

import cm_bq as roundtrip
from finding import Finding
import import_from_bq


class _Job:
  def result(self):
    return []


class _Client:
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
            bigquery.SchemaField("repository", "STRING"),
            bigquery.SchemaField("fingerprint", "STRING"),
            bigquery.SchemaField("finding_id", "STRING"),
            bigquery.SchemaField("scan_id", "STRING"),
            bigquery.SchemaField("scan_timestamp", "TIMESTAMP"),
        ]
    )

  def load_table_from_json(self, rows, table_id, **kwargs):
    self.loaded = (rows, table_id, kwargs)
    return _Job()

  def delete_table(self, table_id, **kwargs):
    self.deleted = table_id


class BigQueryRoundtripTests(unittest.TestCase):
  def test_import_record_maps_telemetry_fields_to_cm_schema(self):
    finding = Finding.from_dict({
        "repository": "acme/widgets",
        "fingerprint": "abc123",
        "file_path": "src/db.py",
        "title": "SQL injection",
        "analysis": "Untrusted input reaches a query.",
        "severity": "HIGH",
        "vuln_type": "SQL Injection",
        "start_line": "12",
        "end_line": 14,
        "snippet": "query(user_input)",
    })
    record = finding.to_cm_import_record()

    self.assertEqual(record["file_path"], "src/db.py")
    self.assertEqual(record["start_line"], 12)
    self.assertEqual(record["end_line"], 14)
    self.assertEqual(record["analysis"], "Untrusted input reaches a query.")
    self.assertEqual(record["snippet"], "query(user_input)")
    self.assertNotIn("fingerprint", record)

  def test_ensure_dataset_creates_idempotently_in_requested_location(self):
    client = unittest.mock.MagicMock()

    roundtrip.ensure_dataset(client, "project", "dataset", "us-central1")

    dataset_resource = client.create_dataset.call_args.args[0]
    self.assertEqual(dataset_resource.project, "project")
    self.assertEqual(dataset_resource.dataset_id, "dataset")
    self.assertEqual(dataset_resource.location, "us-central1")
    self.assertTrue(client.create_dataset.call_args.kwargs["exists_ok"])

  def test_project_falls_back_to_active_gcloud_configuration(self):
    result = types.SimpleNamespace(
        returncode=0, stdout="test-project-502314\n", stderr=""
    )
    with (
        patch.object(import_from_bq, "resolve_project", return_value=None),
        patch.object(import_from_bq.subprocess, "run", return_value=result) as run,
    ):
      project = roundtrip._resolve_project()

    self.assertEqual(project, "test-project-502314")
    self.assertEqual(
        run.call_args.args[0], ["gcloud", "config", "get-value", "project"]
    )

  def test_roundtrip_imports_scans_and_uploads_findings(self):
    source = Finding.from_dict({
        "repository": "acme/widgets",
        "finding_id": "source-finding-id",
        "fingerprint": "source-fingerprint",
        "file_path": "src/db.py",
        "title": "SQL injection",
        "vuln_type": "SQL Injection",
        "severity": "HIGH",
        "start_line": 12,
    })
    imported = Finding.from_dict({
        "FindingID": "source-finding-id",
        "Fingerprint": "source-fingerprint",
        "FilePath": "src/db.py",
        "Title": "SQL injection",
        "VulnType": "SQL Injection",
        "StartLine": 12,
        "Status": "OPEN",
    })

    mock_cm = MagicMock()
    mock_cm.list_findings.side_effect = [[], [imported]]
    mock_cm.import_findings.return_value = [source]

    with tempfile.TemporaryDirectory() as repo_dir:
      with (
          patch.object(
              roundtrip,
              "fetch_findings_from_bigquery",
              side_effect=[[source], [imported]],
          ),
          patch.object(roundtrip, "CodeMender", return_value=mock_cm),
          patch.object(
              roundtrip, "export_findings_to_bigquery", return_value=1
          ) as export_bq,
          patch.object(roundtrip, "ensure_dataset"),
      ):
        roundtrip.run_roundtrip(
            repository="acme/widgets",
            repo_dir=repo_dir,
            project="project",
            dataset="dataset",
            client=object(),
        )

    mock_cm.import_findings.assert_called_once_with([source])
    mock_cm.find.assert_called_once()
    export_bq.assert_called_once()
    self.assertEqual(export_bq.call_args.kwargs["findings"], [imported])

  def test_roundtrip_scans_and_uploads_when_source_empty(self):
    discovered = Finding.from_dict({
        "FindingID": "cm-new",
        "Fingerprint": "fp-new",
        "FilePath": "src/new.py",
        "Title": "New issue",
        "VulnType": "SQL Injection",
        "StartLine": 25,
        "Status": "OPEN",
    })

    mock_cm = MagicMock()
    mock_cm.list_findings.side_effect = [[], [discovered]]
    mock_cm.import_findings.return_value = []

    with tempfile.TemporaryDirectory() as repo_dir:
      with (
          patch.object(
              roundtrip,
              "fetch_findings_from_bigquery",
              side_effect=[[], [discovered]],
          ),
          patch.object(roundtrip, "CodeMender", return_value=mock_cm),
          patch.object(
              roundtrip, "export_findings_to_bigquery", return_value=1
          ) as export_bq,
          patch.object(roundtrip, "ensure_dataset"),
      ):
        roundtrip.run_roundtrip(
            repository="acme/widgets",
            repo_dir=repo_dir,
            project="project",
            dataset="dataset",
            client=object(),
        )

    mock_cm.find.assert_called_once()
    export_bq.assert_called_once()
    self.assertEqual(export_bq.call_args.kwargs["findings"], [discovered])

  def test_export_uses_composite_key_and_removes_staging_table(self):
    client = _Client()
    finding = Finding(
        finding_id="f-1",
        fingerprint="abc123",
        file_path="src/a.py",
        title="Issue",
        status="OPEN",
    )

    merged = roundtrip.export_findings_to_bigquery(
        client=client,
        table_id="project.dataset.findings",
        findings=[finding],
        repository="acme/widgets",
        repo_dir="/tmp/widgets",
    )

    self.assertEqual(merged, 1)
    self.assertIn(
        "ON T.repository = S.repository AND T.fingerprint = S.fingerprint",
        client.queries[-1],
    )
    self.assertTrue(client.deleted.startswith("project.dataset._cm_stage_"))


if __name__ == "__main__":
  unittest.main()