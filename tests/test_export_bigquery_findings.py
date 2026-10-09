"""Unit tests for standalone export_bigquery_findings.py."""

import types
import unittest
from unittest.mock import MagicMock, patch

from google.cloud import bigquery

import step_3_export_to_bq as exporter


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


class ExportBigQueryFindingsTests(unittest.TestCase):
  def test_extract_cwe_id(self):
    self.assertEqual(exporter.extract_cwe_id("CWE-79"), "CWE-79")
    self.assertEqual(exporter.extract_cwe_id("Some text CWE-89 in middle"), "CWE-89")
    self.assertEqual(exporter.extract_cwe_id(None, "no cwe", "CWE-352"), "CWE-352")
    self.assertIsNone(exporter.extract_cwe_id("no cwe here"))

  def test_repo_relative_path(self):
    self.assertEqual(
        exporter._repo_relative_path("/work/repo/src/app.py", "/work/repo"),
        "/work/repo/src/app.py",
    )
    self.assertEqual(
        exporter._repo_relative_path("src//app.py", "/work/repo"),
        "src//app.py",
    )
    self.assertIsNone(exporter._repo_relative_path(None, "/work/repo"))

  def test_to_telemetry_finding(self):
    cm_finding = {
        "finding_id": "f-123",
        "file_path": "/work/repo/src/main.py",
        "title": "SQL Injection",
        "vuln_type": "SQL Injection",
        "start_line": 10,
        "status": "OPEN",
        "fingerprint": "fp-123",
    }
    telemetry_finding = exporter._to_telemetry_finding(
        cm_finding, "/work/repo", source_finding_id="orig-id"
    )
    self.assertEqual(telemetry_finding["finding_id"], "orig-id")
    self.assertEqual(telemetry_finding["file_path"], "/work/repo/src/main.py")
    self.assertEqual(telemetry_finding.get("fingerprint"), "fp-123")

  def test_build_finding_rows(self):
    ctx = exporter.ScanRunContext(
        scan_id="scan-1",
        repository="acme/widgets",
        repo_dir="/tmp/repo",
    )
    findings = [
        {
            "finding_id": "fid-1",
            "title": "SQL injection in query",
            "vuln_type": "CWE-89",
            "severity": "HIGH",
            "file_path": "src/db.py",
            "start_line": 15,
            "end_line": 20,
            "status": "VERIFIED",
            "fingerprint": "fp-1",
        }
    ]
    rows = exporter.build_finding_rows(ctx, findings, scan_timestamp="2026-10-07T00:00:00Z")
    self.assertEqual(len(rows), 1)
    row = rows[0]
    self.assertEqual(row["finding_id"], "fid-1")
    self.assertEqual(row["scan_id"], "scan-1")
    self.assertEqual(row["repository"], "acme/widgets")
    self.assertEqual(row["cwe_id"], "CWE-89")
    self.assertEqual(row["severity"], "HIGH")
    self.assertEqual(row["start_line"], 15)
    self.assertEqual(row["status"], "VERIFIED")
    self.assertEqual(row["fingerprint"], "fp-1")
    self.assertTrue(row["verified"])
    self.assertEqual(row["finding_source"], "codemender")

  def test_merge_current_findings(self):
    client = _MockClient()
    rows = [
        {
            "repository": "acme/widgets",
            "finding_id": "f-1",
            "fingerprint": "fp-1",
            "scan_id": "s-1",
            "scan_timestamp": "2026-10-07T00:00:00Z",
        }
    ]
    merged = exporter.merge_current_findings(client, "project.dataset.findings", rows)
    self.assertEqual(merged, 1)
    self.assertTrue(client.deleted.startswith("project.dataset._cm_stage_"))

  def test_export_findings_to_bigquery(self):
    client = _MockClient()
    findings = [
        exporter.Finding(
            finding_id="cm-1",
            file_path="src/app.py",
            title="XSS",
            vuln_type="XSS",
            start_line=5,
            status="OPEN",
        )
    ]
    merged = exporter.export_findings_to_bigquery(
        client=client,
        table_id="project.dataset.findings",
        findings=findings,
        repository="acme/widgets",
        repo_dir="/tmp/repo",
    )
    self.assertEqual(merged, 1)

  def test_export_findings_to_bigquery_with_dicts(self):
    client = _MockClient()
    findings = [
        {
            "finding_id": "cm-1",
            "file_path": "src/app.py",
            "title": "XSS",
            "vuln_type": "XSS",
            "start_line": 5,
            "status": "OPEN",
        }
    ]
    merged = exporter.export_findings_to_bigquery(
        client=client,
        table_id="project.dataset.findings",
        findings=findings,
        repository="acme/widgets",
        repo_dir="/tmp/repo",
    )
    self.assertEqual(merged, 1)


if __name__ == "__main__":
  unittest.main()
