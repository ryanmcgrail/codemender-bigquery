# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit tests for the opt-in Wiz SAST bridge (codemender_agent.wiz)."""

import copy
import json
import os
import shutil
import stat
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

from codemender_agent.codemender import importer
from codemender_agent.config import get_scrubbed_env
from codemender_agent.wiz import bridge
from codemender_agent.wiz import cli as wiz_cli
from codemender_agent.wiz import converter
from codemender_agent.wiz import dedupe
from codemender_agent.wiz import guard
from codemender_agent.wiz import settings as wiz_settings
from codemender_agent.wiz import taxonomy

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "wiz")
FAKE_ID = "fake-client-id-0123456789"
FAKE_SECRET = "fake-client-secret-abcdefghijklmnop"


def _fixture(name):
  with open(os.path.join(FIXTURES, name), "r", encoding="utf-8") as f:
    return json.load(f)


def _write(path, content):
  os.makedirs(os.path.dirname(path), exist_ok=True)
  with open(path, "w", encoding="utf-8") as f:
    f.write(content)


def _numbered_lines(n, prefix="line"):
  return "\n".join(f"{prefix} {i}" for i in range(1, n + 1)) + "\n"


def _sast(path, line, severity="HIGH", cwe="CWE-89", rule="R-1", end=None):
  return {
      "id": f".##{rule}##{path}##{line}##{end or line}##1##2",
      "name": f"rule {rule}",
      "description": "Short description.\n\nLonger text.",
      "filePath": path,
      "startLine": line,
      "endLine": end or line,
      "severity": severity,
      "rule": {"id": rule, "name": rule},
      "weaknesses": [{"id": cwe}] if cwe else [],
  }


def _doc(sast):
  return {
      "status": {"state": "SUCCESS", "verdict": "WARN_BY_POLICY"},
      "policies": [{"name": "Default SAST", "type": "SAST"}],
      "result": {"sast": sast, "failedPolicyMatches": []},
  }


FAKE_CM = textwrap.dedent("""\
    #!{python}
    import json, os, sys, uuid
    state = os.environ["FAKE_CM_STATE"]
    with open(state + ".env", "a") as log:
      log.write(json.dumps(sorted(k for k in os.environ if k.startswith("WIZ_"))) + "\\n")
    rows = json.load(open(state)) if os.path.exists(state) else []
    args = sys.argv[1:]
    if args[:2] == ["report", "import"]:
      if os.environ.get("FAKE_CM_IMPORT_FAIL"):
        sys.exit(3)
      payload = json.load(open(args[args.index("-f") + 1]))
      root = args[args.index("-p") + 1]
      if not os.environ.get("FAKE_CM_IMPORT_NOOP"):
        for rec in payload:
          vuln_type, title, analysis = rec["vuln_type"], rec["title"], rec["message"]
          # Newer cm releases normalize the stored type to CWE-N (or UPPER);
          # "rewrite" additionally simulates verify replacing title/analysis.
          mode = os.environ.get("FAKE_CM_NORMALIZE", "")
          if mode:
            import re
            m = re.search(r"CWE[-_ ]?(\\d+)", vuln_type, re.I)
            vuln_type = "CWE-%d" % int(m.group(1)) if m else vuln_type.upper()
          if mode == "rewrite":
            title, analysis = "Verified issue", "Verifier prose."
          rows.append({{
              "finding_id": str(uuid.uuid4()),
              "file_path": os.path.join(root, rec["file_path"]),
              "start_line": rec["line"],
              "end_line": rec.get("end_line", rec["line"]),
              "title": title,
              "vuln_type": vuln_type,
              "severity": rec["severity"],
              "analysis": analysis,
              "snippet": rec["snippet"],
              "status": "OPEN",
          }})
      json.dump(rows, open(state, "w"))
      print("Imported %d finding(s)" % len(payload))
      sys.exit(0)
    if args[:1] == ["report"] and "--format" in args:
      if os.environ.get("FAKE_CM_REPORT_FAIL") and os.path.exists(state + ".imported"):
        sys.exit(4)
      # cm 0.9 reports an empty state as a bare `null`.
      print(json.dumps(rows) if rows else "null")
      sys.exit(0)
    sys.exit(2)
""")


class _RepoTestCase(unittest.TestCase):
  """Creates a throw-away repository directory."""

  def setUp(self):
    super().setUp()
    self._tmp = tempfile.TemporaryDirectory()
    self.root = self._tmp.name
    self.repo = os.path.join(self.root, "repo")
    os.makedirs(self.repo)

  def tearDown(self):
    self._tmp.cleanup()
    super().tearDown()

  def make_fake_cm(self):
    path = os.path.join(self.root, "fake_cm")
    _write(path, FAKE_CM.format(python=sys.executable))
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
    self.cm_state = os.path.join(self.root, "cm_state.json")
    self.cm_env = {"PATH": os.environ.get("PATH", ""), "FAKE_CM_STATE": self.cm_state}
    return path

  def cm_rows(self):
    if not os.path.exists(self.cm_state):
      return []
    with open(self.cm_state, "r", encoding="utf-8") as f:
      return json.load(f)


# --- settings & credentials -------------------------------------------------


class SettingsTest(unittest.TestCase):

  def test_disabled_by_default_even_with_credentials(self):
    s = wiz_settings.WizBridgeSettings.from_env(
        {"WIZ_CLIENT_ID": FAKE_ID, "WIZ_CLIENT_SECRET": FAKE_SECRET}
    )
    self.assertFalse(s.enabled)

  def test_enabled_and_threshold(self):
    s = wiz_settings.WizBridgeSettings.from_env({
        "CODEMENDER_WIZ_ENABLED": "true",
        "CODEMENDER_WIZ_MIN_SEVERITY": "medium",
    })
    self.assertTrue(s.enabled)
    self.assertEqual(s.min_severity, "MEDIUM")

  def test_invalid_threshold_falls_back_to_high(self):
    s = wiz_settings.WizBridgeSettings.from_env(
        {"CODEMENDER_WIZ_MIN_SEVERITY": "urgent"}
    )
    self.assertEqual(s.min_severity, "HIGH")

  def test_custom_version_without_digest_is_unpinned(self):
    s = wiz_settings.WizBridgeSettings.from_env(
        {"CODEMENDER_WIZCLI_VERSION": "9.9.9"}
    )
    self.assertEqual(s.wizcli_sha256, "")

  def test_credentials_repr_never_reveals_values(self):
    creds = wiz_settings.WizCredentials(FAKE_ID, FAKE_SECRET)
    for text in (repr(creds), str(creds), f"{creds}"):
      self.assertNotIn(FAKE_ID, text)
      self.assertNotIn(FAKE_SECRET, text)
    self.assertTrue(creds.present)

  def test_take_credentials_scrubs_every_wiz_variable(self):
    env = {
        "WIZ_CLIENT_ID": FAKE_ID,
        "WIZ_CLIENT_SECRET": FAKE_SECRET,
        "WIZ_ENV": "x",
        "PATH": "/bin",
    }
    creds = wiz_settings.take_wiz_credentials(env)
    self.assertEqual(env, {"PATH": "/bin"})
    self.assertEqual(
        creds.as_env(),
        {"WIZ_CLIENT_ID": FAKE_ID, "WIZ_CLIENT_SECRET": FAKE_SECRET},
    )

  def test_scrubbed_env_drops_wiz_variables(self):
    with mock.patch.dict(
        os.environ,
        {"WIZ_CLIENT_ID": FAKE_ID, "WIZ_CLIENT_SECRET": FAKE_SECRET, "KEEP": "1"},
    ):
      env = get_scrubbed_env()
    self.assertNotIn("WIZ_CLIENT_ID", env)
    self.assertNotIn("WIZ_CLIENT_SECRET", env)
    self.assertEqual(env.get("KEEP"), "1")


# --- guard -------------------------------------------------------------------


class GuardTest(unittest.TestCase):

  def test_accepts_real_scan_shape(self):
    res = guard.guard_wiz_result(_fixture("java_sec_code_sast.json"))
    self.assertEqual(len(res.sast_findings), 30)
    self.assertIn("Default SAST policy (Wiz CI/CD scan)", res.sast_policy_names)

  def test_rejects_legacy_dir_scan_with_sast_policy_hit_but_no_results(self):
    with self.assertRaisesRegex(guard.WizGuardError, "SAST policy matched"):
      guard.guard_wiz_result(_fixture("legacy_dir_scan.json"))

  def test_rejects_non_success_state(self):
    doc = _doc([])
    doc["status"]["state"] = "FAILED"
    with self.assertRaisesRegex(guard.WizGuardError, "state"):
      guard.guard_wiz_result(doc)

  def test_rejects_scan_without_sast_policy(self):
    doc = _doc([_sast("a.py", 1)])
    doc["policies"] = [{"name": "Default secrets policy", "type": "SECRETS"}]
    with self.assertRaisesRegex(guard.WizGuardError, "no SAST policy"):
      guard.guard_wiz_result(doc)

  def test_accepts_clean_sast_scan(self):
    self.assertEqual(guard.guard_wiz_result(_doc([])).sast_findings, [])

  def test_rejects_non_object_and_bad_sast_type(self):
    with self.assertRaises(guard.WizGuardError):
      guard.guard_wiz_result([])
    doc = _doc([])
    doc["result"]["sast"] = {"oops": 1}
    with self.assertRaises(guard.WizGuardError):
      guard.guard_wiz_result(doc)

  def test_load_errors_do_not_echo_content(self):
    with tempfile.TemporaryDirectory() as d:
      bad = os.path.join(d, "bad.json")
      _write(bad, "{ not json " + FAKE_SECRET)
      with self.assertRaises(guard.WizGuardError) as ctx:
        guard.load_wiz_json(bad)
      self.assertNotIn(FAKE_SECRET, str(ctx.exception))
      with self.assertRaises(guard.WizGuardError):
        guard.load_wiz_json(os.path.join(d, "missing.json"))


# --- taxonomy ----------------------------------------------------------------


class TaxonomyTest(unittest.TestCase):

  def test_labels(self):
    self.assertEqual(taxonomy.weakness_label("CWE-89"), "SQL Injection (CWE-89)")
    self.assertEqual(taxonomy.weakness_label("89"), "SQL Injection (CWE-89)")
    self.assertEqual(taxonomy.weakness_label(None, "Custom rule"), "Custom rule")
    self.assertEqual(
        taxonomy.weakness_label("CWE-99999", "Thing"), "Thing (CWE-99999)"
    )

  def test_families_from_cwe_and_text(self):
    self.assertIn("sql_injection", taxonomy.families_for(["CWE-89"]))
    self.assertIn("sql_injection", taxonomy.families_for([], "SQL Injection"))
    self.assertIn("path_traversal", taxonomy.families_for(["CWE-23"]))
    # Short acronyms only match whole words.
    self.assertNotIn("xss", taxonomy.families_for([], "the xssfoo helper"))


# --- converter ---------------------------------------------------------------


class ConverterTest(_RepoTestCase):

  def test_threshold_grouping_and_labels_on_real_shape(self):
    doc = _fixture("java_sec_code_sast.json")
    for f in doc["result"]["sast"]:
      path = os.path.join(self.repo, f["filePath"])
      if not os.path.exists(path):
        _write(path, _numbered_lines(400, os.path.basename(path)))
    res = converter.convert_findings(doc["result"]["sast"], self.repo, "HIGH")
    self.assertEqual(res.reported_count, 30)
    self.assertEqual(res.below_threshold_count, 14)
    self.assertEqual(res.invalid_count, 0)
    self.assertEqual(len(res.candidates), 16)
    labels = {c.label for c in res.candidates}
    self.assertIn("SQL Injection (CWE-89)", labels)
    self.assertIn("OS Command Injection (CWE-78)", labels)
    for cand in res.candidates:
      self.assertEqual(cand.severity, "HIGH")
    # The same threshold, lowered, admits more.
    low = converter.convert_findings(doc["result"]["sast"], self.repo, "LOW")
    self.assertEqual(low.below_threshold_count, 0)
    self.assertGreater(len(low.candidates), len(res.candidates))

  def test_overlapping_same_cwe_findings_are_grouped(self):
    _write(os.path.join(self.repo, "routes/login.js"), _numbered_lines(20))
    doc = _fixture("small_sast.json")
    res = converter.convert_findings(doc["result"]["sast"], self.repo, "MEDIUM")
    self.assertEqual(len(res.candidates), 1)
    self.assertEqual(res.grouped_count, 2)
    cand = res.candidates[0]
    self.assertEqual(cand.severity, "HIGH")
    self.assertEqual(len(cand.rule_ids), len(set(cand.rule_ids)))
    # HIGH threshold keeps only the HIGH finding.
    res_high = converter.convert_findings(doc["result"]["sast"], self.repo, "HIGH")
    self.assertEqual(res_high.below_threshold_count, 2)
    self.assertEqual(len(res_high.candidates), 1)

  def test_different_cwe_on_same_line_is_not_grouped(self):
    _write(os.path.join(self.repo, "a.py"), _numbered_lines(5))
    res = converter.convert_findings(
        [_sast("a.py", 2, cwe="CWE-89"), _sast("a.py", 2, cwe="CWE-78")],
        self.repo,
        "HIGH",
    )
    self.assertEqual(len(res.candidates), 2)

  def test_vendored_identical_copies_collapse_to_shallowest(self):
    body = "a\nb\nvulnerable(call)\nd\n"
    _write(os.path.join(self.repo, "static/js/lib.js"), body)
    _write(os.path.join(self.repo, "static/admin/js/lib.js"), body)
    _write(os.path.join(self.repo, "other/lib.js"), "a\nb\ndifferent()\nd\n")
    res = converter.convert_findings(
        [
            _sast("static/admin/js/lib.js", 3, cwe="CWE-79"),
            _sast("static/js/lib.js", 3, cwe="CWE-79"),
            _sast("other/lib.js", 3, cwe="CWE-79"),
        ],
        self.repo,
        "HIGH",
    )
    paths = sorted(c.file_path for c in res.candidates)
    self.assertEqual(paths, ["other/lib.js", "static/js/lib.js"])
    self.assertEqual(res.vendored_copy_count, 1)
    kept = next(c for c in res.candidates if c.file_path == "static/js/lib.js")
    self.assertEqual(kept.duplicate_locations, ["static/admin/js/lib.js:3"])

  def test_unsafe_and_missing_paths_are_dropped(self):
    _write(os.path.join(self.root, "outside.py"), "x\n")
    res = converter.convert_findings(
        [
            _sast("/etc/passwd", 1),
            _sast("../outside.py", 1),
            _sast("missing.py", 1),
            {"filePath": "a.py", "severity": "BOGUS"},
            "not-a-dict",
        ],
        self.repo,
        "HIGH",
    )
    self.assertEqual(res.candidates, [])
    self.assertEqual(res.invalid_count, 4)
    self.assertEqual(res.outside_repo_count, 1)

  def test_symlink_escaping_repo_is_outside(self):
    _write(os.path.join(self.root, "secret.txt"), "x\n")
    os.symlink(
        os.path.join(self.root, "secret.txt"), os.path.join(self.repo, "link.txt")
    )
    res = converter.convert_findings([_sast("link.txt", 1)], self.repo, "HIGH")
    self.assertEqual(res.outside_repo_count, 1)

  def test_import_record_reads_snippet_from_disk(self):
    _write(os.path.join(self.repo, "a.py"), _numbered_lines(100))
    cand = converter.convert_findings(
        [_sast("a.py", 50, end=51)], self.repo, "HIGH"
    ).candidates[0]
    rec = converter.build_import_record(cand, self.repo)
    self.assertEqual(rec["file_path"], "a.py")
    self.assertEqual((rec["line"], rec["end_line"]), (50, 51))
    self.assertEqual(rec["title"], "SQL Injection (CWE-89)")
    self.assertEqual(rec["vuln_type"], rec["title"])
    self.assertEqual(rec["snippet"].splitlines()[0], "line 48")
    self.assertEqual(rec["snippet"].splitlines()[-1], "line 53")
    self.assertNotIn("REDACTED", rec["snippet"])
    self.assertIn("Wiz rule(s): R-1", rec["message"])
    self.assertNotIn("Longer text", rec["message"])


# --- dedupe ------------------------------------------------------------------


class DedupeTest(_RepoTestCase):

  def setUp(self):
    super().setUp()
    _write(os.path.join(self.repo, "src/SQLI.java"), _numbered_lines(200))
    self.cands = converter.convert_findings(
        [_sast("src/SQLI.java", 67), _sast("src/SQLI.java", 150)],
        self.repo,
        "HIGH",
    ).candidates

  def _cm(self, fid, start, end, vuln_type, **extra):
    row = {
        "FindingID": fid,
        "FilePath": os.path.join(self.repo, "src/SQLI.java"),
        "StartLine": start,
        "EndLine": end,
        "VulnType": vuln_type,
        "Status": "OPEN",
    }
    row.update(extra)
    return row

  def test_codemender_method_range_matches_by_family(self):
    res = dedupe.dedupe_candidates(
        self.cands, [self._cm("cm1", 51, 86, "SQL Injection")], self.repo, 3
    )
    self.assertEqual([c.start_line for c in res.duplicates], [67])
    self.assertEqual([c.start_line for c in res.new], [150])
    self.assertEqual(list(res.duplicate_of.values()), ["cm1"])

  def test_line_window_is_respected(self):
    # CodeMender range ends 3 lines before the Wiz line: inside window 3 only.
    rows = [self._cm("cm1", 140, 147, "SQL Injection")]
    self.assertEqual(
        len(dedupe.dedupe_candidates(self.cands, rows, self.repo, 3).duplicates), 1
    )
    self.assertEqual(
        len(dedupe.dedupe_candidates(self.cands, rows, self.repo, 2).duplicates), 0
    )

  def test_unrelated_weakness_is_not_a_duplicate(self):
    res = dedupe.dedupe_candidates(
        self.cands, [self._cm("cm1", 60, 70, "Cross-Site Scripting")], self.repo, 3
    )
    self.assertEqual(res.duplicates, [])

  def test_cwe_in_vuln_id_matches(self):
    res = dedupe.dedupe_candidates(
        self.cands, [self._cm("cm1", 67, 67, "Weird name", VulnID="CWE-89")],
        self.repo, 0,
    )
    self.assertEqual(len(res.duplicates), 1)

  def test_already_imported_detected_before_duplicate(self):
    rows = [self._cm("wiz-1", 67, 67, "SQL Injection (CWE-89)")]
    res = dedupe.dedupe_candidates(self.cands, rows, self.repo, 3)
    self.assertEqual([c.start_line for c in res.already_imported], [67])
    self.assertEqual(res.already_imported_ids, ["wiz-1"])
    self.assertEqual(res.duplicates, [])

  def test_dismissed_codemender_finding_does_not_suppress(self):
    rows = [self._cm("cm1", 51, 86, "SQL Injection", Status="FALSE_POSITIVE")]
    res = dedupe.dedupe_candidates(self.cands, rows, self.repo, 3)
    self.assertEqual(len(res.new), 2)

  def test_label_is_unchanged_by_normalization_handling(self):
    self.assertEqual(self.cands[0].label, "SQL Injection (CWE-89)")

  def test_already_imported_survives_cm_vuln_type_normalization(self):
    # Newer cm releases store vuln_type as CWE-N (or UPPERCASE) on import and
    # on verify; the earlier import must still be recognised.
    for stored in (
        "CWE-89",
        "cwe-89",
        "SQL INJECTION (CWE-89)",
        "SQL Injection (CWE-89)",
        "  sql   injection (cwe-89) ",
    ):
      with self.subTest(stored=stored):
        rows = [self._cm("wiz-1", 67, 67, stored)]
        res = dedupe.dedupe_candidates(self.cands, rows, self.repo, 3)
        self.assertEqual([c.start_line for c in res.already_imported], [67])
        self.assertEqual(res.already_imported_ids, ["wiz-1"])
        self.assertEqual(res.duplicates, [])
        self.assertEqual([c.start_line for c in res.new], [150])

  def test_already_imported_via_title_or_marker_when_type_rewritten(self):
    marker = converter.IMPORT_MARKER + " Wiz rule(s): R-1."
    for extra in (
        {"Title": "SQL Injection (CWE-89)"},
        {"Analysis": marker},
        {"analysis": marker.upper()},
    ):
      with self.subTest(extra=extra):
        rows = [self._cm("wiz-1", 67, 67, "SQL INJECTION", **extra)]
        res = dedupe.dedupe_candidates(self.cands, rows, self.repo, 3)
        self.assertEqual(res.already_imported_ids, ["wiz-1"])

  def test_import_trace_requires_the_candidate_cwe_when_present(self):
    rows = [self._cm("wiz-1", 67, 67, "CWE-79", Title="SQL Injection (CWE-89)")]
    res = dedupe.dedupe_candidates(self.cands, rows, self.repo, 0)
    # The title trace matches but the stored type names only CWE-89 (title)
    # and CWE-79 (type); CWE-89 is present, so this is the same import.
    self.assertEqual(res.already_imported_ids, ["wiz-1"])
    rows = [self._cm("wiz-2", 67, 67, "CWE-79", Analysis=converter.IMPORT_MARKER)]
    res = dedupe.dedupe_candidates(self.cands, rows, self.repo, 0)
    self.assertEqual(res.already_imported_ids, [])

  def test_normalized_import_on_other_line_is_not_already_imported(self):
    rows = [self._cm("wiz-1", 68, 68, "CWE-89")]
    res = dedupe.dedupe_candidates(self.cands, rows, self.repo, 3)
    self.assertEqual(res.already_imported, [])
    # It is still a nearby same-CWE finding, so it suppresses as a duplicate.
    self.assertEqual([c.start_line for c in res.duplicates], [67])

  def test_codemender_finding_on_same_line_stays_a_duplicate(self):
    # No bridge trace (own prose type/title), CWE only in the vuln ID.
    rows = [self._cm("cm1", 67, 80, "SQL injection in query builder",
                     Title="Unsanitised input reaches SQL", VulnID="CWE-89")]
    res = dedupe.dedupe_candidates(self.cands, rows, self.repo, 3)
    self.assertEqual(res.already_imported, [])
    self.assertEqual(list(res.duplicate_of.values()), ["cm1"])

  def test_candidate_without_cwe_matches_label_case_insensitively(self):
    _write(os.path.join(self.repo, "src/X.java"), _numbered_lines(20))
    doc = _sast("src/X.java", 5)
    doc["weaknesses"] = []
    doc["name"] = "Custom Rule Name"
    cands = converter.convert_findings([doc], self.repo, "HIGH").candidates
    self.assertEqual(len(cands), 1)
    self.assertIsNone(cands[0].cwe)
    row = {"FindingID": "wiz-9", "FilePath": "src/X.java", "StartLine": 5,
           "VulnType": cands[0].label.upper(), "Status": "OPEN"}
    res = dedupe.dedupe_candidates(cands, [row], self.repo, 0)
    self.assertEqual(res.already_imported_ids, ["wiz-9"])

  def test_every_row_of_a_repeated_import_is_reported(self):
    rows = [
        self._cm("wiz-1", 67, 67, "SQL Injection (CWE-89)"),
        self._cm("wiz-2", 67, 67, "CWE-89"),
    ]
    res = dedupe.dedupe_candidates(self.cands, rows, self.repo, 3)
    self.assertEqual([c.start_line for c in res.already_imported], [67])
    self.assertEqual(res.already_imported_ids, ["wiz-1", "wiz-2"])

  def test_import_marker_detection(self):
    marker = converter.IMPORT_MARKER + " Wiz rule(s): R-1."
    self.assertTrue(converter.carries_import_marker({"Analysis": marker}))
    self.assertTrue(
        converter.carries_import_marker({"analysis": "  " + marker.lower()})
    )
    self.assertFalse(converter.carries_import_marker({"Analysis": "Prose."}))
    self.assertFalse(converter.carries_import_marker(None))
    record = converter.build_import_record(self.cands[0], self.repo)
    self.assertTrue(converter.carries_import_marker({"Analysis": record["message"]}))


# --- importer ----------------------------------------------------------------


class ImporterTest(_RepoTestCase):

  def test_round_trip_returns_only_new_ids(self):
    cm = self.make_fake_cm()
    _write(self.cm_state, json.dumps([{"finding_id": "pre", "file_path": "x"}]))
    payload = importer.write_import_payload(
        [{"file_path": "a.py", "line": 1, "title": "t", "message": "m",
          "severity": "HIGH", "vuln_type": "t", "snippet": "s", "extra": 1}],
        os.path.join(self.root, "p", "payload.json"),
    )
    with open(payload, encoding="utf-8") as f:
      self.assertNotIn("extra", json.load(f)[0])
    ids, after = importer.import_findings(cm, payload, self.repo, env=self.cm_env)
    self.assertEqual(len(ids), 1)
    self.assertNotIn("pre", ids)
    self.assertEqual(len(after), 2)

  def test_unchanged_state_raises(self):
    cm = self.make_fake_cm()
    payload = importer.write_import_payload(
        [{"file_path": "a.py", "line": 1}], os.path.join(self.root, "p.json")
    )
    env = dict(self.cm_env, FAKE_CM_IMPORT_NOOP="1")
    with self.assertRaisesRegex(importer.FindingImportError, "unchanged"):
      importer.import_findings(cm, payload, self.repo, env=env)

  def test_failed_import_raises(self):
    cm = self.make_fake_cm()
    payload = importer.write_import_payload([], os.path.join(self.root, "p.json"))
    env = dict(self.cm_env, FAKE_CM_IMPORT_FAIL="1")
    with self.assertRaisesRegex(importer.FindingImportError, "exited 3"):
      importer.import_findings(cm, payload, self.repo, env=env)

  def test_missing_payload_raises(self):
    with self.assertRaises(importer.FindingImportError):
      importer.import_findings("cm", "/nonexistent.json", self.repo)


# --- wizcli runner -------------------------------------------------------------


FAKE_WIZCLI = textwrap.dedent("""\
    #!{python}
    import json, os, shutil, sys
    here = os.path.dirname(os.path.abspath(__file__))
    args = sys.argv[1:]
    if args[-1:] == ["--help"]:
      sys.stdout.write(open(os.path.join(here, "help.txt")).read())
      sys.exit(0)
    with open(os.path.join(here, "calls.jsonl"), "a") as log:
      log.write(json.dumps({{
          "argv": args,
          "cwd": os.getcwd(),
          "env_keys": sorted(os.environ),
          "home": os.environ.get("HOME"),
          "id_ok": os.environ.get("WIZ_CLIENT_ID") == {client_id!r},
      }}) + "\\n")
    # Noisy output that must never reach logs.
    print("debug: secret=" + os.environ.get("WIZ_CLIENT_SECRET", ""))
    os.makedirs(os.path.join(os.environ["HOME"], ".wiz"), exist_ok=True)
    open(os.path.join(os.environ["HOME"], ".wiz", "token"), "w").write("jwt")
    mode = open(os.path.join(here, "mode.txt")).read().strip()
    if mode == "nooutput":
      sys.exit(1)
    out = [a.split("=", 1)[1] for a in args if a.startswith("--json-output-file=")][0]
    shutil.copy(os.path.join(here, "result.json"), out)
    sys.exit(4 if mode == "policyfail" else 0)
""")

HELP_TEXT_PATH = os.path.join(FIXTURES, "wizcli_scan_dir_help.txt")


class WizCliTest(_RepoTestCase):

  def setUp(self):
    super().setUp()
    self.bin_dir = os.path.join(self.root, "bin")
    os.makedirs(self.bin_dir)
    self.wizcli = os.path.join(self.bin_dir, "wizcli")
    _write(self.wizcli, FAKE_WIZCLI.format(python=sys.executable, client_id=FAKE_ID))
    os.chmod(self.wizcli, 0o755)
    shutil.copy(HELP_TEXT_PATH, os.path.join(self.bin_dir, "help.txt"))
    _write(os.path.join(self.bin_dir, "mode.txt"), "policyfail")
    _write(
        os.path.join(self.bin_dir, "result.json"),
        json.dumps(_doc([_sast("a.py", 1)])),
    )
    self.settings = wiz_settings.WizBridgeSettings(
        enabled=True, wizcli_path=self.wizcli
    )
    self.creds = wiz_settings.WizCredentials(FAKE_ID, FAKE_SECRET)

  def calls(self):
    with open(os.path.join(self.bin_dir, "calls.jsonl"), encoding="utf-8") as f:
      return [json.loads(line) for line in f]

  def test_scan_command_is_sast_only_unpublished_and_unfiltered(self):
    with open(HELP_TEXT_PATH, encoding="utf-8") as f:
      cmd = wiz_cli.build_scan_command("wizcli", f.read(), "nm", "/o/w.json")
    self.assertEqual(cmd[:4], ["wizcli", "scan", "dir", "."])
    self.assertIn("--no-publish", cmd)
    self.assertIn("--by-policy-hits=DISABLED", cmd)
    self.assertIn("--json-output-file=/o/w.json", cmd)
    disabled = [a for a in cmd if a.startswith("--disabled-scanners=")][0]
    scanners = disabled.split("=", 1)[1].split(",")
    self.assertNotIn("SAST", scanners)
    self.assertIn("Vulnerability", scanners)
    self.assertIn("Malware", scanners)
    self.assertIn("--no-telemetry", cmd)
    self.assertFalse(any("token" in a for a in cmd))

  def test_missing_required_flag_fails_loudly(self):
    with open(HELP_TEXT_PATH, encoding="utf-8") as f:
      text = f.read().replace("--by-policy-hits", "--by-policy")
    with self.assertRaisesRegex(wiz_cli.WizCliError, "--by-policy-hits"):
      wiz_cli.build_scan_command("wizcli", text, "", "/o.json")

  def test_run_isolates_environment_and_output(self):
    with mock.patch.dict(
        os.environ, {"GITHUB_TOKEN": "ghs_shouldnotleak", "HOME": self.root}
    ), self.assertLogs("codemender-orchestrator", level="DEBUG") as logs:
      out = wiz_cli.run_wiz_sast_scan(self.settings, self.creds, self.repo)
    try:
      self.assertTrue(os.path.isfile(out))
      self.assertFalse(out.startswith(self.repo))
      call = self.calls()[0]
      self.assertEqual(os.path.realpath(call["cwd"]), os.path.realpath(self.repo))
      self.assertTrue(call["id_ok"])
      self.assertNotIn("GITHUB_TOKEN", call["env_keys"])
      self.assertNotEqual(call["home"], self.root)
      self.assertFalse(os.path.exists(call["home"]))  # isolated HOME removed
      self.assertFalse(os.path.exists(os.path.join(self.root, ".wiz")))
      joined = "\n".join(logs.output)
      self.assertNotIn(FAKE_SECRET, joined)
      self.assertNotIn(FAKE_ID, joined)
    finally:
      shutil.rmtree(os.path.dirname(out), ignore_errors=True)

  def test_no_output_is_an_error_and_cleans_up(self):
    _write(os.path.join(self.bin_dir, "mode.txt"), "nooutput")
    before = set(os.listdir(tempfile.gettempdir()))
    with self.assertRaisesRegex(wiz_cli.WizCliError, "without writing"):
      wiz_cli.run_wiz_sast_scan(self.settings, self.creds, self.repo)
    leaked = [
        d for d in set(os.listdir(tempfile.gettempdir())) - before
        if d.startswith("cm-wiz-")
    ]
    self.assertEqual(leaked, [])

  def test_missing_credentials(self):
    with self.assertRaisesRegex(wiz_cli.WizCliError, "not configured"):
      wiz_cli.run_wiz_sast_scan(
          self.settings, wiz_settings.WizCredentials("", ""), self.repo
      )

  def test_download_verifies_digest(self):
    payload = b"binary-bytes"

    class _Resp:

      def __enter__(self):
        return self

      def __exit__(self, *a):
        return False

      def raise_for_status(self):
        pass

      def iter_content(self, chunk_size):
        del chunk_size
        yield payload

    import hashlib  # pylint: disable=g-import-not-at-top

    good = wiz_settings.WizBridgeSettings(
        wizcli_sha256=hashlib.sha256(payload).hexdigest()
    )
    bad = wiz_settings.WizBridgeSettings(wizcli_sha256="0" * 64)
    unpinned = wiz_settings.WizBridgeSettings(wizcli_sha256="")
    with mock.patch.object(wiz_cli.platform, "system", return_value="Linux"), \
         mock.patch.object(wiz_cli.platform, "machine", return_value="x86_64"), \
         mock.patch.object(wiz_cli.shutil, "which", return_value=None):
      path = wiz_cli.locate_wizcli(good, self.root, fetch=lambda *a, **k: _Resp())
      self.assertTrue(os.access(path, os.X_OK))
      os.remove(path)
      with self.assertRaisesRegex(wiz_cli.WizCliError, "SHA-256"):
        wiz_cli.locate_wizcli(bad, self.root, fetch=lambda *a, **k: _Resp())
      self.assertFalse(os.path.exists(os.path.join(self.root, "wizcli")))
      with self.assertRaisesRegex(wiz_cli.WizCliError, "unpinned"):
        wiz_cli.locate_wizcli(unpinned, self.root, fetch=lambda *a, **k: _Resp())


# --- bridge orchestration ------------------------------------------------------


class BridgeTest(_RepoTestCase):

  def setUp(self):
    super().setUp()
    _write(os.path.join(self.repo, "src/SQLI.java"), _numbered_lines(200))
    _write(os.path.join(self.repo, "src/Rce.java"), _numbered_lines(200))
    self.results = os.path.join(self.root, "wiz.json")
    _write(
        self.results,
        json.dumps(_doc([
            _sast("src/SQLI.java", 67),
            _sast("src/SQLI.java", 150),
            _sast("src/Rce.java", 36, cwe="CWE-78", rule="R-2"),
            _sast("src/Rce.java", 90, severity="MEDIUM", cwe="CWE-78"),
        ])),
    )
    self.cm = self.make_fake_cm()
    self.creds = wiz_settings.WizCredentials(FAKE_ID, FAKE_SECRET)

  def settings(self, **kw):
    kw.setdefault("enabled", True)
    kw.setdefault("results_file", self.results)
    return wiz_settings.WizBridgeSettings(**kw)

  def run_bridge(self, existing, **kw):
    return bridge.run_wiz_bridge(
        settings=self.settings(**kw),
        creds=self.creds,
        repo_dir=self.repo,
        cm_binary=self.cm,
        cm_env=self.cm_env,
        existing_findings=existing,
    )

  def cm_finding(self):
    return {
        "FindingID": "cm-1",
        "FilePath": os.path.join(self.repo, "src/SQLI.java"),
        "StartLine": 51,
        "EndLine": 86,
        "VulnType": "SQL Injection",
        "Status": "OPEN",
    }

  def test_disabled_is_a_pure_no_op(self):
    existing = [self.cm_finding()]
    with mock.patch.object(bridge, "run_wiz_sast_scan") as scan, \
         mock.patch.object(bridge, "import_findings") as imp, \
         mock.patch.object(bridge, "load_wiz_json") as load, \
         mock.patch("subprocess.run") as sub_run, \
         mock.patch("subprocess.Popen") as popen:
      res = bridge.run_wiz_bridge(
          settings=wiz_settings.WizBridgeSettings(enabled=False),
          creds=self.creds,
          repo_dir=self.repo,
          cm_binary=self.cm,
          cm_env=self.cm_env,
          existing_findings=existing,
      )
    for m in (scan, imp, load, sub_run, popen):
      m.assert_not_called()
    self.assertEqual(res.status, bridge.STATUS_NOT_ENABLED)
    self.assertEqual(res.findings, existing)
    self.assertEqual(res.force_verify_ids, [])
    # Wiz is configured in this deployment (credentials present), so the
    # report says the repository is not on Wiz rather than staying silent.
    self.assertTrue(res.to_metadata()["configured"])
    self.assertIn("not enabled", bridge.summary_line(res.to_metadata()))

  def test_not_enabled_line_only_where_wiz_is_configured(self):
    res = bridge.run_wiz_bridge(
        settings=wiz_settings.WizBridgeSettings(enabled=False),
        creds=wiz_settings.WizCredentials("", ""),
        repo_dir=self.repo,
        cm_binary=self.cm,
        cm_env=self.cm_env,
        existing_findings=[],
    )
    meta = res.to_metadata()
    self.assertEqual(meta["status"], bridge.STATUS_NOT_ENABLED)
    self.assertFalse(meta["configured"])
    self.assertIsNone(bridge.summary_line(meta))
    self.assertIsNone(bridge.summary_line({"status": "not_enabled"}))

  def test_every_duplicate_import_row_is_force_verified(self):
    first = self.run_bridge([])
    self.assertEqual(first.imported_count, 3)
    rows = self.cm_rows()
    extra = dict(rows[0], finding_id="extra-row")
    _write(self.cm_state, json.dumps(rows + [extra]))
    existing = importer.read_findings(self.cm, self.repo, env=self.cm_env)
    second = self.run_bridge(existing)
    self.assertEqual(second.imported_count, 0)
    self.assertEqual(
        set(second.force_verify_ids), {r["finding_id"] for r in self.cm_rows()}
    )

  def test_earlier_imports_outside_current_candidates_stay_forced(self):
    # Imported at MEDIUM, then the threshold is raised: the MEDIUM import is
    # no longer a candidate but is still unverified and must stay forced.
    first = self.run_bridge([], min_severity="MEDIUM")
    self.assertEqual(first.imported_count, 4)
    existing = importer.read_findings(self.cm, self.repo, env=self.cm_env)
    second = self.run_bridge(existing, min_severity="HIGH")
    self.assertEqual(second.imported_count, 0)
    self.assertEqual(sorted(second.force_verify_ids), sorted(first.imported_ids))

  def test_failed_run_still_forces_earlier_imports(self):
    first = self.run_bridge([])
    existing = importer.read_findings(self.cm, self.repo, env=self.cm_env)
    shutil.copy(os.path.join(FIXTURES, "legacy_dir_scan.json"), self.results)
    second = self.run_bridge(existing)
    self.assertEqual(second.status, bridge.STATUS_FAILED)
    self.assertEqual(sorted(second.force_verify_ids), sorted(first.imported_ids))

  def test_eligible_count_is_raw_findings_before_grouping(self):
    _write(
        self.results,
        json.dumps(_doc([
            _sast("src/SQLI.java", 67, rule="R-1"),
            _sast("src/SQLI.java", 67, rule="R-9"),
            _sast("src/Rce.java", 90, severity="LOW", cwe="CWE-78"),
        ])),
    )
    res = self.run_bridge([])
    self.assertEqual(res.eligible_count, 2)
    self.assertEqual(res.imported_count, 1)

  def test_import_dedupe_threshold_and_idempotency(self):
    # CodeMender's own finding lives in the same state the import writes to.
    _write(self.cm_state, json.dumps([{
        "finding_id": "cm-1",
        "file_path": os.path.join(self.repo, "src/SQLI.java"),
        "start_line": 51,
        "end_line": 86,
        "vuln_type": "SQL Injection",
        "title": "SQL Injection in query builder",
        "status": "OPEN",
    }]))
    existing = importer.read_findings(self.cm, self.repo, env=self.cm_env)
    first = self.run_bridge(existing)
    self.assertEqual(first.status, bridge.STATUS_ENABLED, first.detail)
    self.assertEqual(first.reported_count, 4)
    self.assertEqual(first.below_threshold_count, 1)
    self.assertEqual(first.duplicate_count, 1)  # SQLI:67 vs CodeMender 51-86
    self.assertEqual(first.imported_count, 2)  # SQLI:150 and Rce:36
    self.assertEqual(sorted(first.force_verify_ids), sorted(first.imported_ids))
    rows = [r for r in self.cm_rows() if r["finding_id"] != "cm-1"]
    self.assertEqual(
        sorted((r["file_path"][len(self.repo) + 1:], r["start_line"]) for r in rows),
        [("src/Rce.java", 36), ("src/SQLI.java", 150)],
    )
    self.assertEqual(
        {r["vuln_type"] for r in rows},
        {"SQL Injection (CWE-89)", "OS Command Injection (CWE-78)"},
    )
    self.assertEqual({s["state"] for s in first.candidates}, {"imported"})
    self.assertTrue(all(s.get("label") for s in first.candidates))

    # Re-run against the post-import state: nothing is imported twice, and the
    # previously imported findings are still routed to mandatory verification.
    second = self.run_bridge(first.findings)
    self.assertEqual(second.status, bridge.STATUS_ENABLED, second.detail)
    self.assertEqual(second.imported_count, 0)
    self.assertEqual(second.already_imported_count, 2)
    self.assertEqual(second.duplicate_count, 1)
    self.assertEqual(sorted(second.force_verify_ids), sorted(first.imported_ids))
    self.assertEqual(len(self.cm_rows()), 3)
    line = bridge.summary_line(second.to_metadata())
    self.assertIn("2 previously imported", line)

  def test_idempotent_when_cm_normalizes_vuln_type(self):
    for mode in ("1", "rewrite"):
      with self.subTest(mode=mode):
        if os.path.exists(self.cm_state):
          os.remove(self.cm_state)
        self.cm_env["FAKE_CM_NORMALIZE"] = mode
        try:
          first = self.run_bridge([])
          self.assertEqual(first.status, bridge.STATUS_ENABLED, first.detail)
          self.assertEqual(first.imported_count, 3)
          self.assertEqual(
              {r["vuln_type"] for r in self.cm_rows()}, {"CWE-89", "CWE-78"}
          )
          # Candidate summaries still resolve for the normalized rows.
          self.assertTrue(all(s.get("label") for s in first.candidates))
          second = self.run_bridge(first.findings)
          self.assertEqual(second.imported_count, 0)
          self.assertEqual(second.already_imported_count, 3)
          self.assertEqual(
              sorted(second.force_verify_ids), sorted(first.imported_ids)
          )
          self.assertEqual(len(self.cm_rows()), 3)
        finally:
          del self.cm_env["FAKE_CM_NORMALIZE"]

  def test_threshold_is_configurable(self):
    res = self.run_bridge([self.cm_finding()], min_severity="MEDIUM")
    self.assertEqual(res.below_threshold_count, 0)
    self.assertEqual(res.imported_count, 3)

  def test_import_cap_prefers_highest_severity(self):
    res = self.run_bridge([], min_severity="MEDIUM", max_imports=2)
    self.assertEqual(res.imported_count, 2)
    self.assertEqual(res.capped_count, 2)
    self.assertEqual({r["severity"] for r in self.cm_rows()}, {"HIGH"})

  def test_guard_failure_is_isolated(self):
    shutil.copy(os.path.join(FIXTURES, "legacy_dir_scan.json"), self.results)
    existing = [self.cm_finding()]
    res = self.run_bridge(existing)
    self.assertEqual(res.status, bridge.STATUS_FAILED)
    self.assertIn("WizGuardError", res.detail)
    self.assertEqual(res.findings, existing)
    self.assertEqual(self.cm_rows(), [])
    self.assertIn("failed", bridge.summary_line(res.to_metadata()))

  def test_unexpected_exception_is_isolated_and_redacted(self):
    with mock.patch.object(
        bridge, "run_wiz_sast_scan",
        side_effect=RuntimeError(f"auth failed for {FAKE_ID}:{FAKE_SECRET}"),
    ):
      res = self.run_bridge([], results_file=None)
    self.assertEqual(res.status, bridge.STATUS_FAILED)
    self.assertNotIn(FAKE_ID, res.detail)
    self.assertNotIn(FAKE_SECRET, res.detail)
    self.assertIn("[REDACTED]", res.detail)
    self.assertNotIn(FAKE_SECRET, json.dumps(res.to_metadata()))

  def test_import_failure_is_isolated(self):
    self.cm_env["FAKE_CM_IMPORT_FAIL"] = "1"
    res = self.run_bridge([])
    self.assertEqual(res.status, bridge.STATUS_FAILED)
    self.assertIn("FindingImportError", res.detail)
    self.assertEqual(res.force_verify_ids, [])

  def test_partial_import_is_still_force_verified(self):
    # Import succeeds but the read-back fails once; recovery re-reads state.
    real = importer.import_findings

    def flaky(*a, **k):
      real(*a, **k)
      raise importer.FindingImportError("read-back failed")

    with mock.patch.object(bridge, "import_findings", side_effect=flaky):
      res = self.run_bridge([])
    self.assertEqual(res.status, bridge.STATUS_FAILED)
    self.assertEqual(len(res.force_verify_ids), 3)
    self.assertEqual(len(res.findings), 3)

  def test_cm_never_receives_wiz_credentials(self):
    with mock.patch.dict(
        os.environ, {"WIZ_CLIENT_ID": FAKE_ID, "WIZ_CLIENT_SECRET": FAKE_SECRET}
    ):
      creds = wiz_settings.take_wiz_credentials()
      env = dict(get_scrubbed_env(), FAKE_CM_STATE=self.cm_state)
      res = bridge.run_wiz_bridge(
          settings=self.settings(),
          creds=creds,
          repo_dir=self.repo,
          cm_binary=self.cm,
          cm_env=env,
          existing_findings=[],
      )
    self.assertEqual(res.status, bridge.STATUS_ENABLED, res.detail)
    with open(self.cm_state + ".env", encoding="utf-8") as f:
      for line in f:
        self.assertEqual(json.loads(line), [])

  def test_temp_payload_is_removed(self):
    before = set(os.listdir(tempfile.gettempdir()))
    self.run_bridge([])
    leaked = [
        d for d in set(os.listdir(tempfile.gettempdir())) - before
        if d.startswith("cm-wiz-")
    ]
    self.assertEqual(leaked, [])

  def test_relative_results_file_resolves_against_repo(self):
    shutil.copy(self.results, os.path.join(self.repo, "wiz-results.json"))
    cwd = os.getcwd()
    os.chdir(self.root)
    try:
      res = self.run_bridge([], results_file="wiz-results.json")
    finally:
      os.chdir(cwd)
    self.assertEqual(res.status, bridge.STATUS_ENABLED, res.detail)


@unittest.skipUnless(
    os.environ.get("CODEMENDER_TEST_REAL_CM"),
    "set CODEMENDER_TEST_REAL_CM=/path/to/cm to run against a real cm binary",
)
class RealCmImportTest(_RepoTestCase):
  """Idempotent import against a real ``cm`` binary in an isolated HOME."""

  def test_real_cm_round_trip_is_idempotent(self):
    import subprocess  # pylint: disable=g-import-not-at-top

    cm = os.environ["CODEMENDER_TEST_REAL_CM"]
    home = os.path.join(self.root, "home")
    os.makedirs(home)
    env = dict(os.environ, HOME=home)
    for k in [k for k in env if k.startswith("WIZ_")]:
      del env[k]
    _write(os.path.join(self.repo, "src/SQLI.java"), _numbered_lines(200))
    subprocess.run(["git", "init", "-q"], cwd=self.repo, check=True)
    subprocess.run([cm, "init"], cwd=self.repo, env=env, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    results = os.path.join(self.root, "wiz.json")
    _write(results, json.dumps(_doc([_sast("src/SQLI.java", 150)])))
    s = wiz_settings.WizBridgeSettings(enabled=True, results_file=results)
    creds = wiz_settings.WizCredentials("", "")
    first = bridge.run_wiz_bridge(settings=s, creds=creds, repo_dir=self.repo,
                                  cm_binary=cm, cm_env=env, existing_findings=[])
    self.assertEqual(first.status, bridge.STATUS_ENABLED, first.detail)
    self.assertEqual(first.imported_count, 1)
    imported = [f for f in first.findings if f.get("FindingID") in first.imported_ids]
    self.assertEqual(imported[0]["VulnType"], "SQL Injection (CWE-89)")
    self.assertEqual(int(imported[0]["StartLine"]), 150)
    second = bridge.run_wiz_bridge(settings=s, creds=creds, repo_dir=self.repo,
                                   cm_binary=cm, cm_env=env,
                                   existing_findings=first.findings)
    self.assertEqual(second.status, bridge.STATUS_ENABLED, second.detail)
    self.assertEqual(second.imported_count, 0)
    self.assertEqual(second.already_imported_count, 1)
    self.assertEqual(len(importer.read_findings(cm, self.repo, env)), 1)


if __name__ == "__main__":
  unittest.main()
