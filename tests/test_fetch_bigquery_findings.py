"""Unit tests for standalone fetch_bigquery_findings.py."""

import types
import unittest
from unittest.mock import patch, MagicMock

import step_1_import_from_bq as fetcher


class FetchBigQueryFindingsTests(unittest.TestCase):
  def test_table_id_valid(self):
    tid = fetcher._table_id("my-proj", "my_ds", "my_table")
    self.assertEqual(tid, "my-proj.my_ds.my_table")

  def test_table_id_invalid(self):
    with self.assertRaises(ValueError):
      fetcher._table_id("my-proj;drop table", "my_ds", "my_table")

  def test_latest_findings_query(self):
    query = fetcher._latest_findings_query("proj.ds.tbl")
    self.assertIn("FROM `proj.ds.tbl`", query)
    self.assertIn("WHERE repository = @repository", query)
    self.assertIn("PARTITION BY repository, fingerprint", query)
    self.assertIn("QUALIFY ROW_NUMBER() OVER", query)
    self.assertIn("ORDER BY scan_timestamp DESC, scan_id DESC", query)

  def test_deduplicate_rows_by_key(self):
    rows = [
        {"repository": "acme/repo", "fingerprint": "1", "title": "Old"},
        {"repository": "acme/repo", "fingerprint": "1", "title": "New"},
        {"repository": "acme/repo", "fingerprint": "2", "title": "Other"},
    ]
    deduped = fetcher.deduplicate_rows_by_key(rows)
    self.assertEqual(len(deduped), 2)
    self.assertEqual(deduped[0]["title"], "New")
    self.assertEqual(deduped[1]["title"], "Other")

  def test_build_cm_import_record(self):
    row = {
        "file_path": "src/main.py",
        "title": "SQLi",
        "analysis": "Unsanitized query",
        "severity": "HIGH",
        "start_line": 10,
        "end_line": 12,
        "snippet": "db.execute(q)",
    }
    record = fetcher.build_cm_import_record(row)
    self.assertEqual(record["file_path"], "src/main.py")
    self.assertEqual(record["title"], "SQLi")
    self.assertEqual(record["message"], "Unsanitized query")
    self.assertEqual(record["severity"], "HIGH")
    self.assertEqual(record["line"], 10)
    self.assertEqual(record["end_line"], 12)
    self.assertEqual(record["snippet"], "db.execute(q)")

  def test_fetch_latest_findings_success(self):
    client = MagicMock()
    mock_job = MagicMock()
    mock_job.result.return_value = [
        {"finding_id": "f-1", "repository": "acme/repo", "title": "Issue 1"}
    ]
    client.query.return_value = mock_job

    results = fetcher.fetch_findings_from_bigquery(client, "proj.ds.tbl", "acme/repo")
    self.assertEqual(len(results), 1)
    self.assertIsInstance(results[0], fetcher.Finding)
    self.assertEqual(results[0].finding_id, "f-1")

  def test_fetch_latest_findings_handles_exception(self):
    client = MagicMock()
    client.query.side_effect = RuntimeError("BigQuery unavailable")

    results = fetcher.fetch_findings_from_bigquery(client, "proj.ds.tbl", "acme/repo")
    self.assertEqual(results, [])


if __name__ == "__main__":
  unittest.main()

