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
    f = Finding.from_dict({
        "finding_id": "f-123",
        "repository": "owner/repo",
        "file_path": "src/auth.py",
        "start_line": 15,
        "end_line": 20,
        "title": "Hardcoded Secret",
        "vuln_type": "CWE-798",
        "severity": "HIGH",
        "status": "DETECTED",
        "analysis": "Secret key found in source",
        "snippet": "SECRET = '123'",
        "fingerprint": "fp-123",
    })
    self.assertEqual(f.finding_id, "f-123")
    self.assertEqual(f.repository, "owner/repo")
    self.assertEqual(f.file_path, "src/auth.py")
    self.assertEqual(f.start_line, 15)
    self.assertEqual(f.end_line, 20)
    self.assertEqual(f.title, "Hardcoded Secret")
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
    self.assertIs(f.to_dict(), f.raw)

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
