"""Unit tests for Finding class in finding.py."""

import unittest

from finding import (
    Finding,
    extract_cwe_id,
)


class FindingTests(unittest.TestCase):

  def test_extract_cwe_id(self):
    self.assertEqual(extract_cwe_id("CWE-79: Cross-site Scripting"), "CWE-79")
    self.assertEqual(extract_cwe_id("Insecure code", "cwe-89"), "CWE-89")
    self.assertIsNone(extract_cwe_id("no cwe here"))
    self.assertIsNone(extract_cwe_id(None, ""))

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

  def test_finding_equivalence_by_finding_id(self):
    f1 = Finding(finding_id="f-1", title="Title 1", file_path="a.py")
    f2 = Finding(finding_id="f-1", title="Different Title", file_path="b.py")
    f3 = Finding(finding_id="f-2", title="Title 1", file_path="a.py")

    self.assertEqual(f1, f2)
    self.assertNotEqual(f1, f3)
    self.assertEqual(hash(f1), hash(f2))
    self.assertNotEqual(f1, "not-a-finding")


if __name__ == "__main__":
  unittest.main()
