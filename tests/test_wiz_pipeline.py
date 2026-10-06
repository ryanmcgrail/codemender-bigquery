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

"""Pipeline integration tests for the opt-in Wiz SAST bridge."""

import json
import os
import tempfile
import unittest
from unittest import mock

from codemender_agent.config import OrchestratorConfig
from codemender_agent.runners import aggregate
from codemender_agent.runners import worker
from codemender_agent.runners.scan import _render_zero_findings_summary
from codemender_agent.runners.scan import run_scan_pipeline
from codemender_agent.telemetry import bigquery as bq
from codemender_agent.wiz import bridge

FAKE_ID = "fake-client-id-0123456789"
FAKE_SECRET = "fake-client-secret-abcdefghijklmnop"


# --- worker: forced verification ------------------------------------------------


class ForcedVerifyTest(unittest.TestCase):

  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.ws = self._tmp.name
    self.repo = os.path.join(self.ws, "repo")
    os.makedirs(self.repo)
    self.db = os.path.join(self.ws, ".codemender", "state.db")
    os.makedirs(os.path.dirname(self.db))
    patches = {
        "run_command": mock.MagicMock(
            return_value=mock.MagicMock(returncode=0, stdout="", token_usage=None)
        ),
        "check_remote_branch_exists": mock.MagicMock(return_value=False),
        "is_duplicate_pr": mock.MagicMock(return_value=False),
        "is_finding_verified": mock.MagicMock(return_value=False),
        "get_finding_status": mock.MagicMock(return_value="OPEN"),
        "create_pull_request": mock.MagicMock(return_value=None),
        "push_branch_to_remote": mock.MagicMock(),
        "get_cm_default_model": mock.MagicMock(return_value="m"),
    }
    self.mocks = {}
    for name, m in patches.items():
      p = mock.patch.object(worker, name, m)
      self.mocks[name] = p.start()
      self.addCleanup(p.stop)
    sleep = mock.patch.object(worker.time, "sleep")
    sleep.start()
    self.addCleanup(sleep.stop)
    self.addCleanup(self._tmp.cleanup)

  def _run(self, config, force_verify, env=None):
    finding = {
        "FindingID": "wiz-1",
        "VulnType": "SQL Injection (CWE-89)",
        "FilePath": "src/SQLI.java",
        "StartLine": 150,
    }
    with mock.patch.dict(os.environ, env or {}):
      return worker._process_finding(
          finding_id="wiz-1",
          finding=finding,
          repo_dir=self.repo,
          cm_binary="/bin/cm",
          scrubbed_env={},
          clean_repo_url="https://github.com/org/repo.git",
          token="t",
          owner="org",
          repo_name="repo",
          default_branch="main",
          working_base_ref="abc",
          state_db_path=self.db,
          worker_token_usage={},
          config=config,
          force_verify=force_verify,
      )

  def _cm_calls(self, verb):
    return [
        c[0][0] for c in self.mocks["run_command"].call_args_list
        if c[0][0][:2] == ["/bin/cm", verb]
    ]

  def test_forced_finding_is_verified_even_with_skip_verify(self):
    config = OrchestratorConfig(workspace_dir=self.ws, skip_verify=True)
    self._run(config, force_verify=True)
    self.assertEqual(len(self._cm_calls("verify")), 3)  # retried, never verified
    self.assertEqual(self._cm_calls("fix"), [])  # unverified => never fixed

  def test_forced_finding_verified_on_cloud_run_without_force_env(self):
    config = OrchestratorConfig(
        workspace_dir=self.ws, skip_verify=False, execution_url="https://x"
    )
    self._run(config, force_verify=True, env={"CODEMENDER_FORCE_VERIFY": "false"})
    self.assertTrue(self._cm_calls("verify"))
    self.assertEqual(self._cm_calls("fix"), [])

  def test_not_exploitable_verdict_stops_retrying(self):
    self.mocks["get_finding_status"].return_value = "DISMISSED"
    config = OrchestratorConfig(workspace_dir=self.ws, skip_verify=True)
    self._run(config, force_verify=True)
    self.assertEqual(len(self._cm_calls("verify")), 1)
    self.assertEqual(self._cm_calls("fix"), [])

  def test_verified_forced_finding_proceeds_to_fix(self):
    self.mocks["is_finding_verified"].return_value = True
    config = OrchestratorConfig(workspace_dir=self.ws, skip_verify=True)
    self._run(config, force_verify=True)
    self.assertEqual(len(self._cm_calls("verify")), 1)
    self.assertTrue(self._cm_calls("fix"))

  def test_unforced_finding_keeps_existing_skip_behaviour(self):
    config = OrchestratorConfig(workspace_dir=self.ws, skip_verify=True)
    self._run(config, force_verify=False)
    self.assertEqual(self._cm_calls("verify"), [])
    self.assertTrue(self._cm_calls("fix"))

  def test_explicit_skip_verify_false_is_honored_on_cloud_run(self):
    config = OrchestratorConfig(
        workspace_dir=self.ws, skip_verify=False, execution_url="https://x"
    )
    self._run(config, force_verify=False)
    self.assertTrue(self._cm_calls("verify"))
    self.assertEqual(self._cm_calls("fix"), [])  # unverified => never fixed

  def test_default_skip_verify_still_skips_on_cloud_run(self):
    config = OrchestratorConfig(
        workspace_dir=self.ws, skip_verify=True, execution_url="https://x"
    )
    self._run(config, force_verify=False)
    self.assertEqual(self._cm_calls("verify"), [])
    self.assertTrue(self._cm_calls("fix"))

  def test_partition_force_verify_ids(self):
    path = os.path.join(self.ws, "p.json")
    with open(path, "w") as f:
      json.dump({"finding_ids": ["a", "b"], "force_verify_ids": ["b"]}, f)
    self.assertEqual(worker._read_force_verify_ids(path), {"b"})
    with open(path, "w") as f:
      json.dump({"finding_ids": ["a"]}, f)
    self.assertEqual(worker._read_force_verify_ids(path), set())
    self.assertEqual(worker._read_force_verify_ids(os.path.join(self.ws, "x")), set())
    self.assertEqual(worker._read_force_verify_ids(None), set())

  def test_import_marker_forces_verify_without_partition_list(self):
    from codemender_agent.wiz import converter  # pylint: disable=g-import-not-at-top

    imported = {"Analysis": converter.IMPORT_MARKER + " Wiz rule(s): R-1."}
    own = {"Analysis": "CodeMender prose."}
    self.assertTrue(worker._must_force_verify("x", imported, set()))
    self.assertTrue(worker._must_force_verify("x", own, {"x"}))
    self.assertFalse(worker._must_force_verify("x", own, set()))
    self.assertFalse(worker._must_force_verify("x", None, set()))


# --- scan pipeline -------------------------------------------------------------


class ScanPipelineWizTest(unittest.TestCase):

  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.ws = self._tmp.name
    self.addCleanup(self._tmp.cleanup)
    self.base_env = {
        "HOME": self.ws,
        "CODEMENDER_SCAN_ID": "test-scan-123",
        "CODEMENDER_GCS_BUCKET": "test-bucket",
        "WORKSPACE_DIR": self.ws,
        "GITHUB_REPO_URL": "https://github.com/owner/repo.git",
        "GITHUB_TOKEN": "fake-token",
        "CODEMENDER_SCAN_TARGET": ".",
        "CODEMENDER_BUILD_COMMAND": "echo 'build'",
        "CODEMENDER_MAX_TASKS": "5",
        "WIZ_CLIENT_ID": FAKE_ID,
        "WIZ_CLIENT_SECRET": FAKE_SECRET,
    }
    self.uploads = {}
    self.run_envs = []

  def _run_pipeline(self, extra_env=None, bridge_patch=None):
    cm_report = mock.MagicMock(stdout=json.dumps([
        {"FindingID": "fid-1", "Status": "DETECTED", "VulnType": "XSS",
         "FilePath": "app.py"},
    ]), returncode=0, token_usage=None)
    default = mock.MagicMock(stdout="abc123commitsha", returncode=0, token_usage=None)

    def run_cmd(cmd, *a, **kw):
      self.run_envs.append(kw.get("env"))
      return cm_report if "report" in " ".join(cmd) else default

    def upload(local, bucket, blob):
      del bucket
      if not local.endswith(".json"):
        self.uploads[blob] = None
        return True
      with open(local, "r", encoding="utf-8", errors="replace") as f:
        try:
          self.uploads[blob] = json.load(f)
        except ValueError:
          self.uploads[blob] = None
      return True

    env = dict(self.base_env, **(extra_env or {}))
    patches = [
        mock.patch.dict(os.environ, env),
        mock.patch("codemender_agent.runners.scan.run_command", side_effect=run_cmd),
        mock.patch("codemender_agent.runners.scan.upload_file_to_gcs", side_effect=upload),
        mock.patch("codemender_agent.runners.scan.generate_signed_url",
                   side_effect=lambda b, blob, method="GET", **k: f"http://s/{blob}"),
        mock.patch("codemender_agent.runners.scan.is_duplicate_pr", return_value=False),
        mock.patch("codemender_agent.runners.scan.check_remote_branch_exists",
                   return_value=False),
        mock.patch("codemender_agent.runners.scan.get_default_branch", return_value="main"),
        mock.patch("codemender_agent.runners.scan.make_tarfile"),
        mock.patch("codemender_agent.runners.scan.post_commit_status"),
        mock.patch("shutil.which", return_value="/bin/cm"),
    ]
    if bridge_patch is not None:
      patches.append(
          mock.patch("codemender_agent.runners.scan.run_wiz_bridge",
                     side_effect=bridge_patch)
      )
    for p in patches:
      p.start()
    try:
      run_scan_pipeline()
      remaining = {k for k in os.environ if k.startswith("WIZ_")}
    finally:
      for p in reversed(patches):
        p.stop()
    return remaining

  def _partitions(self):
    return [v for k, v in self.uploads.items() if "/partition_" in k]

  def test_disabled_repo_is_a_no_op_and_credentials_are_dropped(self):
    with mock.patch.object(bridge, "run_wiz_sast_scan") as scan, \
         mock.patch.object(bridge, "import_findings") as imp:
      remaining = self._run_pipeline()
    scan.assert_not_called()
    imp.assert_not_called()
    self.assertEqual(remaining, set())
    for env in self.run_envs:
      if env:
        self.assertFalse([k for k in env if k.startswith("WIZ_")])
    meta = self.uploads["scans/test-scan-123/scan_metadata.json"]
    self.assertEqual(meta["wiz"]["status"], bridge.STATUS_NOT_ENABLED)
    # Credentials are mounted in this deployment, so the report can say the
    # repository is not on Wiz; the credentials themselves never persist.
    self.assertTrue(meta["wiz"]["configured"])
    self.assertIn("not enabled", bridge.summary_line(meta["wiz"]))
    self.assertNotIn(FAKE_SECRET, json.dumps(self.uploads))
    self.assertNotIn(FAKE_ID, json.dumps(self.uploads))
    for part in self._partitions():
      self.assertNotIn("force_verify_ids", part)

  def test_enabled_repo_routes_imports_to_forced_verification(self):
    def fake_bridge(**kw):
      self.assertTrue(kw["settings"].enabled)
      self.assertEqual(kw["settings"].min_severity, "CRITICAL")
      self.assertTrue(kw["creds"].present)
      self.assertFalse([k for k in (kw["cm_env"] or {}) if k.startswith("WIZ_")])
      findings = list(kw["existing_findings"]) + [{
          "FindingID": "wiz-1", "Status": "OPEN",
          "VulnType": "SQL Injection (CWE-89)", "FilePath": "db.py",
      }]
      return bridge.WizBridgeResult(
          status=bridge.STATUS_ENABLED, reported_count=4,
          imported_ids=["wiz-1"], force_verify_ids=["wiz-1"], findings=findings,
          min_severity="CRITICAL",
      )

    remaining = self._run_pipeline(
        {"CODEMENDER_WIZ_ENABLED": "true",
         "CODEMENDER_WIZ_MIN_SEVERITY": "CRITICAL"},
        bridge_patch=fake_bridge,
    )
    self.assertEqual(remaining, set())
    parts = self._partitions()
    all_ids = sorted(i for p in parts for i in p["finding_ids"])
    self.assertEqual(all_ids, ["fid-1", "wiz-1"])
    forced = [i for p in parts for i in p.get("force_verify_ids", [])]
    self.assertEqual(forced, ["wiz-1"])
    for p in parts:
      self.assertTrue(set(p.get("force_verify_ids", [])) <= set(p["finding_ids"]))
    meta = self.uploads["scans/test-scan-123/scan_metadata.json"]
    self.assertEqual(meta["wiz"]["status"], bridge.STATUS_ENABLED)
    self.assertEqual(meta["wiz"]["imported_ids"], ["wiz-1"])
    self.assertNotIn(FAKE_SECRET, json.dumps(self.uploads))

  def test_failing_bridge_does_not_fail_the_scan(self):
    self._run_pipeline({
        "CODEMENDER_WIZ_ENABLED": "true",
        "CODEMENDER_WIZ_RESULTS_FILE": os.path.join(self.ws, "missing.json"),
    })
    meta = self.uploads["scans/test-scan-123/scan_metadata.json"]
    self.assertEqual(meta["wiz"]["status"], bridge.STATUS_FAILED)
    self.assertIn("does not exist", meta["wiz"]["detail"])
    parts = self._partitions()
    self.assertEqual([i for p in parts for i in p["finding_ids"]], ["fid-1"])
    self.assertIn("scans/test-scan-123/manifest.json", self.uploads)


class ZeroFindingsSummaryTest(unittest.TestCase):

  def test_wiz_line_rendered_only_when_given(self):
    with tempfile.TemporaryDirectory() as d:
      path = os.path.join(d, "summary.md")
      cfg = OrchestratorConfig(github_step_summary=path)
      _render_zero_findings_summary("o", "r", "abc", False, config=cfg)
      _render_zero_findings_summary(
          "o", "r", "abc", False, config=cfg, wiz_note="failed (x)"
      )
      with open(path, encoding="utf-8") as f:
        text = f.read()
    self.assertEqual(text.count("**Wiz SAST:** failed (x)"), 1)


# --- telemetry -----------------------------------------------------------------


class TelemetryWizTest(unittest.TestCase):

  def test_scan_row_and_finding_source(self):
    ctx = bq.ScanRunContext(stage="aggregate", scan_id="s1")
    ctx.apply_wiz({
        "status": "enabled", "detail": "", "reported_count": 7,
        "imported_count": 2, "imported_ids": ["wiz-1", "wiz-2"],
        "force_verify_ids": ["wiz-1", "wiz-2"],
    })
    row = bq.build_scan_run_row(ctx, bq.STATUS_SUCCESS)
    self.assertEqual(row["wiz_status"], "enabled")
    self.assertIsNone(row["wiz_status_detail"])
    self.assertEqual(row["wiz_reported_count"], 7)
    self.assertEqual(row["wiz_imported_count"], 2)
    rows = bq.build_finding_rows(
        ctx, [{"finding_id": "wiz-1"}, {"finding_id": "c1"}], with_snippets=False
    )
    self.assertEqual(
        {r["finding_id"]: r["finding_source"] for r in rows},
        {"wiz-1": "wiz", "c1": "codemender"},
    )

  def test_defaults_are_null(self):
    row = bq.build_scan_run_row(bq.ScanRunContext(), bq.STATUS_FAILED)
    for col in ("wiz_status", "wiz_status_detail", "wiz_reported_count",
                "wiz_imported_count"):
      self.assertIsNone(row[col])

  def test_schema_declares_new_columns(self):
    schema = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "terraform", "gcp", "bigquery.tf",
    )
    with open(schema, encoding="utf-8") as f:
      text = f.read()
    for col in ("wiz_status", "wiz_status_detail", "wiz_reported_count",
                "wiz_imported_count", "finding_source"):
      self.assertIn(f'name        = "{col}"', text)


# --- aggregate -----------------------------------------------------------------


class AggregateWizTest(unittest.TestCase):

  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.ws = self._tmp.name
    self.addCleanup(self._tmp.cleanup)

  def test_load_wiz_metadata(self):
    self.assertEqual(
        aggregate._load_wiz_metadata(self.ws), {"status": "not_enabled"}
    )
    with open(os.path.join(self.ws, "scan_metadata.json"), "w") as f:
      json.dump({"token_usage": {}}, f)
    self.assertEqual(
        aggregate._load_wiz_metadata(self.ws), {"status": "not_enabled"}
    )
    with open(os.path.join(self.ws, "scan_metadata.json"), "w") as f:
      json.dump({"wiz": {"status": "failed", "detail": "boom"}}, f)
    self.assertEqual(aggregate._load_wiz_metadata(self.ws)["detail"], "boom")

  def test_html_banner_is_escaped_and_skipped_when_not_enabled(self):
    path = os.path.join(self.ws, "r.html")
    original = '<html><body><div class="cards">x</div></body></html>'
    with open(path, "w") as f:
      f.write(original)
    aggregate._inject_wiz_status_into_html(path, {"status": "not_enabled"})
    with open(path) as f:
      self.assertEqual(f.read(), original)
    aggregate._inject_wiz_status_into_html(
        path, {"status": "failed", "detail": "<script>x</script>"}
    )
    with open(path) as f:
      text = f.read()
    self.assertIn("codemender-wiz-banner", text)
    self.assertNotIn("<script>", text)
    self.assertLess(text.index("codemender-wiz-banner"), text.index('class="cards"'))

  def test_step_summary_marks_wiz_findings(self):
    import sqlite3  # pylint: disable=g-import-not-at-top

    db = os.path.join(self.ws, "state.db")
    with sqlite3.connect(db) as conn:
      conn.execute(
          "CREATE TABLE findings (finding_id TEXT, title TEXT, status TEXT,"
          " file_path TEXT, start_line INT, vuln_type TEXT, vuln_id TEXT,"
          " severity TEXT)"
      )
      conn.execute(
          "INSERT INTO findings VALUES ('wiz-1','SQL Injection (CWE-89)','VERIFIED',"
          "'a.java',3,'SQL Injection (CWE-89)','','HIGH')"
      )
      conn.execute(
          "INSERT INTO findings VALUES ('c1','XSS','FIXED','b.js',1,'XSS','','LOW')"
      )
    wiz = {"status": "enabled", "reported_count": 5, "eligible_count": 2,
           "min_severity": "HIGH", "duplicate_count": 1, "imported_count": 1,
           "force_verify_ids": ["wiz-1"]}
    md, _ = aggregate._render_step_summary(
        db, OrchestratorConfig(workspace_dir=self.ws), "o", "r", wiz=wiz
    )
    self.assertIn("**Wiz SAST:** enabled: 5 reported", md)
    w_line = next(l for l in md.splitlines() if "`wiz-1`" in l)
    c_line = next(l for l in md.splitlines() if "`c1`" in l)
    self.assertIn("(reported by Wiz)", w_line)
    self.assertNotIn("(reported by Wiz)", c_line)
    md2, _ = aggregate._render_step_summary(
        db, OrchestratorConfig(workspace_dir=self.ws), "o", "r",
        wiz={"status": "not_enabled"},
    )
    self.assertNotIn("Wiz", md2)


class WorkflowWizTest(unittest.TestCase):
  """The Cloud Workflows definition forwards the opt-in switch to Stage 1."""

  _WORKFLOW = os.path.join(
      os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
      "workflows",
      "gcp_parallel_workflow.yaml",
  )

  def setUp(self):
    import yaml  # pylint: disable=g-import-not-at-top

    with open(self._WORKFLOW, "r", encoding="utf-8") as f:
      self.steps = {}
      for step in yaml.safe_load(f)["main"]["steps"]:
        (name, body), = step.items()
        self.steps[name] = body

  def _env(self, name):
    body = self.steps[name]
    call_args = body.get("args") or body.get("try", {}).get("args")
    env = {}
    for override in call_args["body"]["overrides"]["containerOverrides"]:
      for entry in override.get("env", []):
        env[entry["name"]] = entry["value"]
    return env

  def test_stage1_receives_wiz_switch(self):
    env = self._env("run_stage1_scan")
    self.assertEqual(env["CODEMENDER_WIZ_ENABLED"], "${string(wiz_enabled)}")
    self.assertEqual(env["CODEMENDER_WIZ_MIN_SEVERITY"], "${wiz_min_severity}")

  def test_other_stages_do_not_receive_wiz_env(self):
    for name in ("run_stage2_workers", "run_stage3_aggregate"):
      with self.subTest(stage=name):
        self.assertFalse(
            [k for k in self._env(name) if "WIZ" in k],
            f"{name} must not carry Wiz settings",
        )

  def test_wiz_defaults_to_disabled(self):
    assigns = {}
    for entry in self.steps["init_variables"]["assign"]:
      assigns.update(entry)
    self.assertEqual(
        assigns["wiz"], '${default(map.get(args, "wiz"), default_empty_map)}'
    )
    self.assertEqual(
        assigns["wiz_enabled"], '${default(map.get(wiz, "enabled"), false)}'
    )
    self.assertEqual(
        assigns["wiz_min_severity"],
        '${default(map.get(wiz, "min_severity"), "HIGH")}',
    )
    names = list(assigns)
    self.assertLess(names.index("default_empty_map"), names.index("wiz"))
    self.assertLess(names.index("wiz"), names.index("wiz_enabled"))


if __name__ == "__main__":
  unittest.main()
