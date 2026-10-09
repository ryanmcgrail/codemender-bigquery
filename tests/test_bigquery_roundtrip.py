"""Tests for the standalone BigQuery/CodeMender round-trip script."""

import tempfile
import types
import unittest
from unittest.mock import patch

from google.cloud import bigquery

import cm_bq as roundtrip


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
    record = roundtrip.build_cm_import_record({
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

    self.assertEqual(record["file_path"], "src/db.py")
    self.assertEqual(record["line"], 12)
    self.assertEqual(record["end_line"], 14)
    self.assertEqual(record["message"], "Untrusted input reaches a query.")
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
        patch.object(roundtrip.telemetry, "resolve_project", return_value=None),
        patch.object(roundtrip.subprocess, "run", return_value=result) as run,
    ):
      project = roundtrip._resolve_project()

    self.assertEqual(project, "test-project-502314")
    self.assertEqual(
        run.call_args.args[0], ["gcloud", "config", "get-value", "project"]
    )

  def test_rows_deduplicate_by_repository_and_finding_id(self):
    rows = [
        {"repository": "acme/widgets", "finding_id": "same", "title": "old"},
        {"repository": "acme/widgets", "finding_id": "same", "title": "new"},
        {"repository": "acme/api", "finding_id": "same", "title": "other repo"},
    ]

    result = roundtrip.deduplicate_rows_by_key(rows)

    self.assertEqual(len(result), 2)
    self.assertEqual(result[0]["title"], "new")

  def test_telemetry_mapping_preserves_source_finding_id(self):
    finding = {
        "FindingID": "cm-a",
        "FilePath": "src/a.py",
        "VulnType": "SQL Injection",
        "StartLine": 10,
        "Status": "VERIFIED",
    }

    row = roundtrip._to_telemetry_finding(
      finding, "/tmp/widgets", "source-finding-id"
    )

    self.assertEqual(row["finding_id"], "source-finding-id")
    self.assertEqual(row["vuln_type"], "SQL Injection")

  def test_roundtrip_imports_verifies_fixes_and_uploads_source_key(self):
    source = {
        "repository": "acme/widgets",
      "finding_id": "source-finding-id",
        "fingerprint": "source-fingerprint",
        "file_path": "src/db.py",
        "title": "SQL injection",
        "vuln_type": "SQL Injection",
        "severity": "HIGH",
        "start_line": 12,
    }
    imported = {
        "FindingID": "source-finding-id",
        "FilePath": "src/db.py",
        "Title": "SQL injection",
        "VulnType": "SQL Injection",
        "StartLine": 12,
        "Status": "OPEN",
    }
    verified = {**imported, "Status": "VERIFIED"}
    fixed = {**verified, "Status": "FIXED"}

    with tempfile.TemporaryDirectory() as repo_dir:
      with (
          patch.object(roundtrip, "fetch_latest_findings", return_value=[source]),
          patch.object(
              roundtrip,
              "fetch_findings_from_cm_report",
              side_effect=[[], [imported]],
          ),
          patch.object(roundtrip, "_run_cm_find") as cm_find,
          patch.object(
              roundtrip,
              "import_findings",
              return_value=(["source-finding-id"], [imported]),
          ),
          patch.object(roundtrip, "merge_current_findings", return_value=1) as merge,
          patch.object(roundtrip, "ensure_dataset"),
      ):
        summary = roundtrip.run_roundtrip(
            repository="acme/widgets",
            repo_dir=repo_dir,
            project="project",
            dataset="dataset",
            client=object(),
        )

    cm_find.assert_called_once()
    self.assertEqual(
      merge.call_args.args[3][0]["finding_id"], "source-finding-id"
    )
    self.assertEqual(summary["imported"], 1)
    self.assertEqual(summary["merged"], 1)

  def test_roundtrip_scans_and_uploads_without_verify_or_fix_when_source_empty(self):
    discovered = {
        "FindingID": "cm-new",
        "FilePath": "src/new.py",
        "Title": "New issue",
        "VulnType": "SQL Injection",
        "StartLine": 25,
        "Status": "OPEN",
    }
    with tempfile.TemporaryDirectory() as repo_dir:
      with (
          patch.object(roundtrip, "fetch_latest_findings", return_value=[]),
          patch.object(
              roundtrip,
              "fetch_findings_from_cm_report",
              side_effect=[[], [discovered]],
          ),
          patch.object(roundtrip, "_run_cm_find") as cm_find,
          patch.object(roundtrip, "merge_current_findings", return_value=1) as merge,
          patch.object(roundtrip, "ensure_dataset"),
      ):
        summary = roundtrip.run_roundtrip(
            repository="acme/widgets",
            repo_dir=repo_dir,
            project="project",
            dataset="dataset",
            client=object(),
        )

    cm_find.assert_called_once()
    self.assertEqual(merge.call_args.args[3][0]["finding_id"], "cm-new")
    self.assertEqual(summary["source_findings"], 0)
    self.assertEqual(summary["scanned_findings"], 1)
    self.assertEqual(summary["merged"], 1)

  def test_latest_query_ranks_before_filtering_closed_status(self):
    query = roundtrip._latest_findings_query("project.dataset.history")

    self.assertIn("PARTITION BY repository, finding_id", query)
    self.assertLess(query.index("QUALIFY ROW_NUMBER"), query.index("WHERE UPPER"))
    self.assertIn("NULLIF(TRIM(finding_id), '') IS NOT NULL", query)

  def test_merge_uses_composite_key_and_removes_staging_table(self):
    client = _Client()
    row = {
        "repository": "acme/widgets",
        "fingerprint": "abc123",
        "finding_id": "f-1",
        "scan_id": "s-1",
        "scan_timestamp": "2026-10-06T00:00:00+00:00",
        "unexpected": "ignored by target schema",
    }

    merged = roundtrip.merge_current_findings(
      client,
      "project.dataset.findings",
      "project.dataset.findings",
      [row],
    )

    self.assertEqual(merged, 1)
    self.assertIn(
        "ON T.repository = S.repository AND T.finding_id = S.finding_id",
        client.queries[-1],
    )
    self.assertNotIn("unexpected", client.loaded[0][0])
    self.assertTrue(client.deleted.startswith("project.dataset._cm_stage_"))

  def test_roundtrip_uses_repo_findings_when_no_new_ids_assigned(self):
    existing = {
        "FindingID": "cm-existing",
        "FilePath": "src/existing.py",
        "Title": "Pre-existing issue",
        "VulnType": "XSS",
        "StartLine": 10,
        "Status": "OPEN",
    }
    with tempfile.TemporaryDirectory() as repo_dir:
      with (
          patch.object(roundtrip, "fetch_latest_findings", return_value=[]),
          patch.object(
              roundtrip,
              "fetch_findings_from_cm_report",
              side_effect=[[existing], [existing]],
          ),
          patch.object(roundtrip, "_run_cm_find") as cm_find,
          patch.object(roundtrip, "merge_current_findings", return_value=1) as merge,
          patch.object(roundtrip, "ensure_dataset"),
      ):
        summary = roundtrip.run_roundtrip(
            repository="acme/widgets",
            repo_dir=repo_dir,
            project="project",
            dataset="dataset",
            client=object(),
        )

    cm_find.assert_called_once()
    self.assertEqual(merge.call_args.args[3][0]["finding_id"], "cm-existing")
    self.assertEqual(summary["scanned_findings"], 1)
    self.assertEqual(summary["merged"], 1)


if __name__ == "__main__":
  unittest.main()