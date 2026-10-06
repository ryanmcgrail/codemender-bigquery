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

"""Worker verify/fix retries: quota backoff and the FIX_FAILED marker."""

from contextlib import closing
import os
import sqlite3
import tempfile
import unittest
from unittest import mock

from codemender_agent.config import OrchestratorConfig
from codemender_agent.runners import worker
from codemender_agent.telemetry import bigquery as bq

# Shape of the message cm prints when the per-project concurrency quota rejects
# a session (project number replaced).
QUOTA_OUTPUT = (
    "Error: starting session: StartSession failed: code 429, body"
    ' {"error":{"message":"Quota exceeded for quota metric'
    " 'aiplatform.googleapis.com/concurrent_interaction_generations' and limit"
    " 'Global concurrent interaction generations per project.' of service"
    " 'aiplatform.googleapis.com' for consumer 'project_number:1'.\","
    '"code":"too_many_requests"}}'
)


class QuotaDetectionTest(unittest.TestCase):

  def test_detects_quota_and_rate_limit_messages(self):
    for text in (
        QUOTA_OUTPUT,
        "SubmitToolResult failed: code 429, body {}",
        'StartSession failed: code 429, body {"error":{"message":"Resource has'
        ' been exhausted (e.g. check quota)."}}',
        "rpc error: code = ResourceExhausted desc = RESOURCE_EXHAUSTED",
        "HTTP 429 Too Many Requests",
    ):
      with self.subTest(text=text[:40]):
        self.assertTrue(worker._is_quota_error(text))

  def test_ignores_ordinary_failures_and_ids_containing_429(self):
    for text in (
        "",
        "Error: build failed: exit status 1",
        "Verifying finding 4a429b1c-0000-4000-8000-000000000429 ...",
        "line 429: unexpected token",
    ):
      with self.subTest(text=text[:40]):
        self.assertFalse(worker._is_quota_error(text))
    self.assertFalse(worker._is_quota_error(None))
    self.assertFalse(worker._is_quota_error(mock.MagicMock()))


class RetryDelayTest(unittest.TestCase):

  def test_ordinary_failure_keeps_short_fixed_delay(self):
    self.assertEqual(worker._retry_delay_seconds(1, "boom"), 5.0)
    self.assertEqual(worker._retry_delay_seconds(2, None), 5.0)

  def test_quota_failure_backs_off_exponentially_with_jitter(self):
    with mock.patch.dict(os.environ, {}, clear=False):
      os.environ.pop("CODEMENDER_QUOTA_BACKOFF_SECONDS", None)
      os.environ.pop("CODEMENDER_QUOTA_BACKOFF_MAX_SECONDS", None)
      for attempt, (lo, hi) in ((1, (30, 60)), (2, (60, 120)), (3, (120, 240))):
        for _ in range(20):
          delay = worker._retry_delay_seconds(attempt, QUOTA_OUTPUT)
          self.assertGreaterEqual(delay, lo)
          self.assertLessEqual(delay, hi)
      # Capped at the maximum however many attempts are configured.
      self.assertLessEqual(worker._retry_delay_seconds(12, QUOTA_OUTPUT), 600)
      self.assertGreaterEqual(worker._retry_delay_seconds(12, QUOTA_OUTPUT), 300)

  def test_quota_backoff_is_configurable_and_rejects_bad_values(self):
    with mock.patch.object(worker.random, "uniform", return_value=1.0):
      with mock.patch.dict(os.environ, {
          "CODEMENDER_QUOTA_BACKOFF_SECONDS": "10",
          "CODEMENDER_QUOTA_BACKOFF_MAX_SECONDS": "15",
      }):
        self.assertEqual(worker._retry_delay_seconds(1, QUOTA_OUTPUT), 10)
        self.assertEqual(worker._retry_delay_seconds(3, QUOTA_OUTPUT), 15)
      with mock.patch.dict(os.environ, {
          "CODEMENDER_QUOTA_BACKOFF_SECONDS": "not-a-number",
          "CODEMENDER_QUOTA_BACKOFF_MAX_SECONDS": "-1",
      }):
        self.assertEqual(worker._retry_delay_seconds(1, QUOTA_OUTPUT), 60)
        self.assertEqual(worker._retry_delay_seconds(5, QUOTA_OUTPUT), 600)


class ProcessFindingRetryTest(unittest.TestCase):
  """Drives _process_finding with cm verify/fix outcomes and a real state.db."""

  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self._tmp.cleanup)
    self.ws = self._tmp.name
    self.repo = os.path.join(self.ws, "repo")
    os.makedirs(self.repo)
    self.db = os.path.join(self.ws, ".codemender", "state.db")
    os.makedirs(os.path.dirname(self.db))
    with closing(sqlite3.connect(self.db)) as conn:
      conn.execute(
          "CREATE TABLE findings (finding_id TEXT PRIMARY KEY, status TEXT,"
          " muted INTEGER, mute_reason TEXT)"
      )
      conn.execute("INSERT INTO findings VALUES ('f1', 'OPEN', 0, NULL)")
      conn.execute("INSERT INTO findings VALUES ('f2', 'VERIFIED', 0, NULL)")
      conn.commit()

    self.cm_results = {"verify": [], "fix": []}
    self.status_after = {"verify": "VERIFIED", "fix": "VERIFIED"}
    self.current_status = "OPEN"

    def fake_run(cmd, **_kwargs):
      verb = cmd[1] if len(cmd) > 1 and cmd[0] == "/bin/cm" else None
      if verb in self.cm_results:
        self.current_status = self.status_after[verb]
        queue = self.cm_results[verb]
        rc, out = queue.pop(0) if queue else (1, "")
        return mock.MagicMock(returncode=rc, stdout=out, token_usage=None)
      return mock.MagicMock(returncode=0, stdout="", token_usage=None)

    patches = {
        "run_command": mock.MagicMock(side_effect=fake_run),
        "check_remote_branch_exists": mock.MagicMock(return_value=False),
        "is_duplicate_pr": mock.MagicMock(return_value=False),
        "is_finding_verified": mock.MagicMock(
            side_effect=lambda *_: self.current_status == "VERIFIED"
        ),
        "get_finding_status": mock.MagicMock(
            side_effect=lambda *_: self.current_status
        ),
        "create_pull_request": mock.MagicMock(return_value=None),
        "push_branch_to_remote": mock.MagicMock(),
        "get_cm_default_model": mock.MagicMock(return_value="m"),
        "clean_workspace": mock.MagicMock(),
        "sanitize_exploit_and_artifacts": mock.MagicMock(),
    }
    self.mocks = {}
    for name, m in patches.items():
      p = mock.patch.object(worker, name, m)
      self.mocks[name] = p.start()
      self.addCleanup(p.stop)
    p = mock.patch.object(worker.time, "sleep")
    self.sleep = p.start()
    self.addCleanup(p.stop)
    p = mock.patch.object(worker.random, "uniform", return_value=1.0)
    p.start()
    self.addCleanup(p.stop)
    env = mock.patch.dict(os.environ, {"CODEMENDER_DRY_RUN": "true"})
    env.start()
    self.addCleanup(env.stop)
    for name in ("CODEMENDER_QUOTA_BACKOFF_SECONDS",
                 "CODEMENDER_QUOTA_BACKOFF_MAX_SECONDS",
                 "CODEMENDER_MAX_VERIFY_ATTEMPTS"):
      os.environ.pop(name, None)

  def _run(self, skip_verify=False):
    config = OrchestratorConfig(
        workspace_dir=self.ws, skip_verify=skip_verify, dry_run=True
    )
    return worker._process_finding(
        finding_id="f1",
        finding={"FindingID": "f1", "VulnType": "XSS", "FilePath": "a.js"},
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
    )

  def _row(self, finding_id="f1"):
    with closing(sqlite3.connect(self.db)) as conn:
      conn.row_factory = sqlite3.Row
      return dict(conn.execute(
          "SELECT * FROM findings WHERE finding_id = ?", (finding_id,)
      ).fetchone())

  def _sleeps(self):
    return [c.args[0] for c in self.sleep.call_args_list]

  def test_fix_exhaustion_on_quota_backs_off_and_records_fix_failed(self):
    self.cm_results["verify"] = [(0, "ok")]
    self.cm_results["fix"] = [(1, QUOTA_OUTPUT)] * 3
    self._run()
    self.assertEqual(self._sleeps(), [60.0, 120.0])
    row = self._row()
    self.assertEqual(row["status"], worker.FIX_FAILED_STATUS)
    self.assertIn("cm fix failed after 3 attempts", row["mute_reason"])
    self.assertEqual(row["muted"], 0)  # a failure, not a suppression
    # The untouched, never-attempted VERIFIED finding stays as it was.
    self.assertEqual(self._row("f2")["status"], "VERIFIED")

  def test_telemetry_counts_the_marked_failure_but_not_the_unattempted(self):
    self.cm_results["verify"] = [(0, "ok")]
    self.cm_results["fix"] = [(1, "boom")] * 3
    self._run()
    counts = bq.summarize_remediation([self._row("f1"), self._row("f2")])
    self.assertEqual(counts["failed_fix"], 1)
    self.assertEqual(counts["fixed"], 0)

  def test_ordinary_fix_failures_keep_the_short_delay(self):
    self.cm_results["verify"] = [(0, "ok")]
    self.cm_results["fix"] = [(1, "build broke")] * 3
    self._run()
    self.assertEqual(self._sleeps(), [5.0, 5.0])
    self.assertEqual(self._row()["status"], worker.FIX_FAILED_STATUS)

  def test_verify_quota_failures_back_off_and_never_reach_fix(self):
    self.status_after["verify"] = "OPEN"
    self.cm_results["verify"] = [(1, QUOTA_OUTPUT)] * 3
    self._run()
    self.assertEqual(self._sleeps(), [60.0, 120.0])
    fix_calls = [c for c in self.mocks["run_command"].call_args_list
                 if c.args[0][:2] == ["/bin/cm", "fix"]]
    self.assertEqual(fix_calls, [])
    # Fix was never attempted, so the finding is not marked as a failed fix.
    self.assertEqual(self._row()["status"], "OPEN")

  def test_quota_then_success_retries_verify(self):
    self.cm_results["verify"] = [(1, QUOTA_OUTPUT), (0, "ok")]
    self.status_after["fix"] = "FIXED"
    self.cm_results["fix"] = [(0, "ok")]
    # First verify attempt leaves the finding OPEN, the second verifies it.
    statuses = iter(["OPEN", "VERIFIED"])
    original = self.mocks["run_command"].side_effect

    def run(cmd, **kwargs):
      result = original(cmd, **kwargs)
      if cmd[:2] == ["/bin/cm", "verify"]:
        self.current_status = next(statuses)
      return result

    self.mocks["run_command"].side_effect = run
    self._run()
    self.assertEqual(self._sleeps(), [60.0])
    self.assertNotEqual(self._row()["status"], worker.FIX_FAILED_STATUS)

  def test_not_exploitable_verdict_from_fix_is_not_overwritten(self):
    self.cm_results["verify"] = [(0, "ok")]
    self.status_after["fix"] = "DISMISSED"
    self.cm_results["fix"] = [(1, "")] * 3
    with closing(sqlite3.connect(self.db)) as conn:
      conn.execute("UPDATE findings SET status = 'DISMISSED' WHERE finding_id = 'f1'")
      conn.commit()
    self._run()
    self.assertEqual(self._row()["status"], "DISMISSED")

  def test_missing_state_db_is_tolerated(self):
    os.remove(self.db)
    self.cm_results["verify"] = [(0, "ok")]
    self.cm_results["fix"] = [(1, "")] * 3
    self._run()  # must not raise
    self.assertFalse(os.path.exists(self.db))


if __name__ == "__main__":
  unittest.main()
