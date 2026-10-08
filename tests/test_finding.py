"""Unit tests for Finding class in finding.py."""

import unittest

from finding import (
    Finding,
    extract_cwe_id,
    normalize_repo_relative_path,
)


class FindingTests(unittest.TestCase):

  def test_extract_cwe_id(self):
    self.assertEqual(extract_cwe_id("CWE-79: Cross-site Scripting"), "CWE-79")
    self.assertEqual(extract_cwe_id("Insecure code", "cwe-89"), "CWE-89")
    self.assertIsNone(extract_cwe_id("no cwe here"))
    self.assertIsNone(extract_cwe_id(None, ""))

  def test_normalize_repo_relative_path(self):
    self.assertEqual(normalize_repo_relative_path("src/index.js"), "src/index.js")
    self.assertEqual(normalize_repo_relative_path("./src/index.js"), "src/index.js")
    self.assertEqual(
        normalize_repo_relative_path("/app/src/index.js", repo_dir="/app"),
        "src/index.js",
    )
    self.assertEqual(
        normalize_repo_relative_path("github/workspace/src/index.js"),
        "src/index.js",
    )
    self.assertEqual(
        normalize_repo_relative_path("__w/owner/repo/index.js"),
        "index.js",
    )

  def test_from_dict_and_to_dict(self):
    data = {
        "finding_id": "f-123",
        "repository": "owner/repo",
        "file_path": "src/auth.py",
        "start_line": 15,
        "end_line": 20,
        "title": "Hardcoded Secret",
        "vuln_type": "CWE-798",
        "severity": "high",
        "status": "detected",
        "analysis": "Secret key found in source",
        "snippet": "SECRET = '123'",
        "fingerprint": "fp-123",
    }
    f = Finding.from_dict(data)
    self.assertEqual(f.finding_id, "f-123")
    self.assertEqual(f.repository, "owner/repo")
    self.assertEqual(f.file_path, "src/auth.py")
    self.assertEqual(f.start_line, 15)
    self.assertEqual(f.end_line, 20)
    self.assertEqual(f.title, "Hardcoded Secret")
    self.assertEqual(f.cwe_id, "CWE-798")
    self.assertEqual(f.severity, "HIGH")
    self.assertEqual(f.status, "DETECTED")
    self.assertEqual(f.analysis, "Secret key found in source")
    self.assertEqual(f.snippet, "SECRET = '123'")
    self.assertEqual(f.fingerprint, "fp-123")

    out = f.to_dict()
    self.assertEqual(out["finding_id"], "f-123")
    self.assertEqual(out["severity"], "HIGH")
    self.assertEqual(out["cwe_id"], "CWE-798")
    self.assertEqual(out["fingerprint"], "fp-123")

  def test_from_cm_json_and_to_cm_dict(self):
    cm_json = {
        "FindingID": "cm-001",
        "FilePath": "lib/server.ts",
        "Line": 100,
        "EndLine": 105,
        "Title": "Command Injection",
        "VulnType": "command-injection",
        "VulnID": "CWE-78",
        "Severity": "Critical",
        "ConfidenceLevel": "High",
        "Status": "DETECTED",
        "Message": "Untrusted input in exec()",
        "Snippet": "exec(cmd)",
    }
    f = Finding.from_cm_json(cm_json)
    self.assertEqual(f.finding_id, "cm-001")
    self.assertEqual(f.file_path, "lib/server.ts")
    self.assertEqual(f.start_line, 100)
    self.assertEqual(f.end_line, 105)
    self.assertEqual(f.title, "Command Injection")
    self.assertEqual(f.cwe_id, "CWE-78")
    self.assertEqual(f.severity, "CRITICAL")
    self.assertEqual(f.confidence_level, "HIGH")
    self.assertEqual(f.analysis, "Untrusted input in exec()")

    cm_dict = f.to_cm_dict()
    self.assertEqual(cm_dict["FindingID"], "cm-001")
    self.assertEqual(cm_dict["FilePath"], "lib/server.ts")
    self.assertEqual(cm_dict["Severity"], "CRITICAL")
    # Verify backward compatible snake_case aliases in cm_dict
    self.assertEqual(cm_dict["finding_id"], "cm-001")
    self.assertEqual(cm_dict["file_path"], "lib/server.ts")

  def test_to_cm_import_record(self):
    f = Finding(
        finding_id="f-1",
        file_path="src/main.py",
        start_line=10,
        title="XSS",
        severity="HIGH",
        analysis="XSS vulnerability",
    )
    rec = f.to_cm_import_record()
    self.assertEqual(rec["file_path"], "src/main.py")
    self.assertEqual(rec["line"], 10)
    self.assertEqual(rec["title"], "XSS")
    self.assertEqual(rec["severity"], "HIGH")
    self.assertEqual(rec["message"], "XSS vulnerability")

    empty_path_finding = Finding(finding_id="f-2", file_path="")
    with self.assertRaises(ValueError):
      empty_path_finding.to_cm_import_record()

  def test_to_bq_row(self):
    f = Finding(
        finding_id="f-bq-1",
        repository="org/repo",
        file_path="src/utils.py",
        start_line=50,
        title="Path Traversal",
        vuln_type="CWE-22",
        severity="MEDIUM",
        status="VERIFIED",
        analysis="Potential traversal",
        snippet="open(path)",
    )
    row = f.to_bq_row(
        scan_id="scan-xyz",
        scan_timestamp="2026-10-08T00:00:00Z",
        prs={"f-bq-1": "https://github.com/org/repo/pull/42"},
        wiz_ids=["f-bq-1"],
    )
    self.assertEqual(row["finding_id"], "f-bq-1")
    self.assertEqual(row["scan_id"], "scan-xyz")
    self.assertEqual(row["scan_timestamp"], "2026-10-08T00:00:00Z")
    self.assertEqual(row["fix_pr_url"], "https://github.com/org/repo/pull/42")
    self.assertEqual(row["finding_source"], "wiz")
    self.assertTrue(row["verified"])
    self.assertEqual(row["snippet"], "open(path)")

    # Without snippets
    row_no_snippet = f.to_bq_row(with_snippets=False)
    self.assertNotIn("snippet", row_no_snippet)
    self.assertNotIn("analysis", row_no_snippet)

  def test_row_key(self):
    f = Finding(finding_id="f-1", repository="owner/repo")
    self.assertEqual(f.row_key, ("owner/repo", "f-1"))

    f_no_repo = Finding(finding_id="f-1", repository="")
    with self.assertRaises(ValueError):
      _ = f_no_repo.row_key

  def test_is_closed_and_verified(self):
    f_open = Finding(finding_id="1", status="DETECTED")
    self.assertFalse(f_open.is_closed())

    f_fixed = Finding(finding_id="2", status="FIXED")
    self.assertTrue(f_fixed.is_closed())

    f_remediated = Finding(finding_id="3", status="REMEDIATED")
    self.assertTrue(f_remediated.is_closed())

    f_verified_status = Finding(finding_id="4", status="VERIFIED")
    self.assertTrue(f_verified_status.is_verified())

  def test_property_access_and_no_dict_protocol(self):
    f = Finding(
        finding_id="f-99",
        title="Test Finding",
        file_path="test.py",
        severity="LOW",
    )
    self.assertEqual(f.finding_id, "f-99")
    self.assertEqual(f.title, "Test Finding")
    self.assertEqual(f.file_path, "test.py")
    self.assertEqual(f.severity, "LOW")

    # Dict-like indexing should not work
    with self.assertRaises(TypeError):
      _ = f["finding_id"]
    self.assertFalse(hasattr(f, "get"))
    self.assertIs(f.to_bq_row(), f.raw)

  def test_match_findings(self):
    source = [
        {"finding_id": "bq-1", "file_path": "a.py", "start_line": 10, "title": "SQLi", "vuln_type": "sqli"},
        {"finding_id": "bq-2", "file_path": "b.py", "start_line": 20, "title": "XSS", "vuln_type": "xss"},
    ]
    cm = [
        {"FindingID": "cm-1", "FilePath": "a.py", "Line": 10, "Title": "SQLi", "VulnType": "sqli"},
        {"FindingID": "cm-2", "FilePath": "b.py", "Line": 20, "Title": "XSS", "VulnType": "xss"},
    ]
    matched = Finding.match_findings(source, cm, repo_dir="/tmp")
    self.assertEqual(matched, {"cm-1": "bq-1", "cm-2": "bq-2"})

  def test_deduplicate(self):
    findings = [
        {"finding_id": "1", "repository": "r1", "title": "First"},
        {"finding_id": "1", "repository": "r1", "title": "Updated"},
        {"finding_id": "2", "repository": "r1", "title": "Other"},
    ]
    deduped = Finding.deduplicate(findings)
    self.assertEqual(len(deduped), 2)
    by_id = {f.finding_id: f.title for f in deduped}
    self.assertEqual(by_id["1"], "Updated")
    self.assertEqual(by_id["2"], "Other")


if __name__ == "__main__":
  unittest.main()
