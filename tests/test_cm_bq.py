"""Tests for the standalone BigQuery/CodeMender round-trip script."""

import tempfile
import types
import unittest
from unittest.mock import MagicMock, patch

import bigquery
import cm_bq as roundtrip
from finding import Finding


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

  def test_project_falls_back_to_active_gcloud_configuration(self):
    result = types.SimpleNamespace(
        returncode=0, stdout="test-project-502314\n", stderr=""
    )
    with (
        patch.object(bigquery, "resolve_project", return_value=None),
        patch.object(bigquery.subprocess, "run", return_value=result) as run,
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
        "finding_id": "source-finding-id",
        "fingerprint": "source-fingerprint",
        "file_path": "src/db.py",
        "title": "SQL injection",
        "vuln_type": "SQL Injection",
        "start_line": 12,
        "status": "OPEN",
    })

    mock_bq = MagicMock()
    mock_bq.fetch_findings.side_effect = [[source], [imported]]

    mock_cm = MagicMock()
    mock_cm.list_findings.side_effect = [[], [imported]]
    mock_cm.import_findings.return_value = [source]

    with tempfile.TemporaryDirectory() as repo_dir:
      with (
          patch.object(roundtrip, "BigQuery", return_value=mock_bq),
          patch.object(roundtrip, "CodeMender", return_value=mock_cm),
      ):
        roundtrip.run_roundtrip(
            repository="acme/widgets",
            repo_dir=repo_dir,
            project="project",
            dataset="dataset",
            client=object(),
        )

    mock_bq.ensure_dataset.assert_called_once()
    mock_cm.import_findings.assert_called_once_with([source])
    mock_cm.find.assert_called_once()
    mock_bq.upload_findings.assert_called_once()
    self.assertEqual(mock_bq.upload_findings.call_args.kwargs["findings"], [imported])

  def test_roundtrip_scans_and_uploads_when_source_empty(self):
    discovered = Finding.from_dict({
        "finding_id": "cm-new",
        "fingerprint": "fp-new",
        "file_path": "src/new.py",
        "title": "New issue",
        "vuln_type": "SQL Injection",
        "start_line": 25,
        "status": "OPEN",
    })

    mock_bq = MagicMock()
    mock_bq.fetch_findings.side_effect = [[], [discovered]]

    mock_cm = MagicMock()
    mock_cm.list_findings.side_effect = [[], [discovered]]
    mock_cm.import_findings.return_value = []

    with tempfile.TemporaryDirectory() as repo_dir:
      with (
          patch.object(roundtrip, "BigQuery", return_value=mock_bq),
          patch.object(roundtrip, "CodeMender", return_value=mock_cm),
      ):
        roundtrip.run_roundtrip(
            repository="acme/widgets",
            repo_dir=repo_dir,
            project="project",
            dataset="dataset",
            client=object(),
        )

    mock_cm.find.assert_called_once()
    mock_bq.upload_findings.assert_called_once()
    self.assertEqual(mock_bq.upload_findings.call_args.kwargs["findings"], [discovered])


if __name__ == "__main__":
  unittest.main()