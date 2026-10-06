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

"""Unit tests for scripts/ci/image_rollout.sh, run against a stub gcloud."""

import os
import pathlib
import shutil
import subprocess
import tempfile
import textwrap
import unittest

_SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "ci" / "image_rollout.sh"
_BASH = shutil.which("bash")

_DIGEST = "sha256:" + "a" * 64
_OTHER_DIGEST = "sha256:" + "b" * 64
_IMAGE = "us-central1-docker.pkg.dev/test-project/cm-runner/orchestrator"

# Records every call in $STUB_DIR/calls and answers from files in $STUB_DIR:
#   digest_<tag>        output of `artifacts docker images describe IMAGE:<tag>`
#   latest_switch       "<n> <digest>": :latest has <digest> once the workflow
#                       list has been called <n> times (a newer build pushed)
#   wf_<n> / wf_default active workflow executions for the n-th list call
#   wf_fail             present: the workflow list fails
#   jobs_<job>          output of `run jobs executions list --job=<job>`
_STUB = textwrap.dedent("""\
    #!/usr/bin/env bash
    set -u
    echo "$*" >> "$STUB_DIR/calls"
    case "$1 $2" in
      "artifacts docker")
        ref="$5"; tag="${ref##*:}"
        if [ "$tag" = "latest" ] && [ -f "$STUB_DIR/latest_switch" ]; then
          read -r after digest < "$STUB_DIR/latest_switch"
          if [ "$(cat "$STUB_DIR/wf_count" 2>/dev/null || echo 0)" -ge "$after" ]; then
            echo "$digest"; exit 0
          fi
        fi
        [ -f "$STUB_DIR/digest_$tag" ] || { echo "not found" >&2; exit 1; }
        cat "$STUB_DIR/digest_$tag" ;;
      "workflows executions")
        [ -f "$STUB_DIR/wf_fail" ] && { echo "denied" >&2; exit 1; }
        n=$(( $(cat "$STUB_DIR/wf_count" 2>/dev/null || echo 0) + 1 ))
        echo "$n" > "$STUB_DIR/wf_count"
        if [ -f "$STUB_DIR/wf_$n" ]; then cat "$STUB_DIR/wf_$n";
        elif [ -f "$STUB_DIR/wf_default" ]; then cat "$STUB_DIR/wf_default"; fi ;;
      "run jobs")
        if [ "$3" = "executions" ]; then
          job="${5#--job=}"
          [ -f "$STUB_DIR/jobs_$job" ] && cat "$STUB_DIR/jobs_$job"
        elif [ "$3" = "update" ]; then
          echo "$*" >> "$STUB_DIR/updates"
        fi ;;
      *) echo "unexpected gcloud call: $*" >&2; exit 3 ;;
    esac
    exit 0
    """)


@unittest.skipIf(_BASH is None, "bash is required")
class ImageRolloutTest(unittest.TestCase):

  def setUp(self):
    super().setUp()
    tmp = tempfile.TemporaryDirectory()
    self.addCleanup(tmp.cleanup)
    self.stub_dir = pathlib.Path(tmp.name)
    bin_dir = self.stub_dir / "bin"
    bin_dir.mkdir()
    gcloud = bin_dir / "gcloud"
    gcloud.write_text(_STUB)
    gcloud.chmod(0o755)
    self.env = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
        "STUB_DIR": str(self.stub_dir),
        "PROJECT_ID": "test-project",
        "REGION": "us-central1",
        "REPO_NAME": "cm-runner",
        "IMAGE_TAG": "abc1234",
        "UPDATE_JOBS": "true",
        "POLL_SECONDS": "0",
    }
    self._write("digest_abc1234", _DIGEST)
    self._write("digest_latest", _DIGEST)

  def _write(self, name, content):
    (self.stub_dir / name).write_text(content + ("\n" if content else ""))

  def _read(self, name):
    path = self.stub_dir / name
    return path.read_text() if path.exists() else ""

  def _run(self, **env):
    result = subprocess.run(
        [_BASH, str(_SCRIPT)],
        env={**self.env, **env},
        capture_output=True, text=True, timeout=60, check=False,
    )
    return result

  def test_update_jobs_false_changes_nothing(self):
    result = self._run(UPDATE_JOBS="false")
    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertIn("leaving the Cloud Run jobs unchanged", result.stdout)
    self.assertEqual(self._read("calls"), "")

  def test_idle_rolls_out_both_jobs_by_digest(self):
    result = self._run()
    self.assertEqual(result.returncode, 0, result.stderr)
    updates = self._read("updates").splitlines()
    self.assertEqual(len(updates), 2)
    self.assertIn(f"run jobs update cm-runner --image={_IMAGE}@{_DIGEST}", updates[0])
    self.assertIn(f"run jobs update cm-worker --image={_IMAGE}@{_DIGEST}", updates[1])
    for line in updates:
      self.assertIn("--project=test-project", line)
      self.assertIn("--region=us-central1", line)
      self.assertIn("--quiet", line)
    calls = self._read("calls")
    self.assertIn("workflows executions list cm-coordinator", calls)
    self.assertIn("--filter=state=ACTIVE", calls)
    self.assertIn("run jobs executions list --job=cm-runner", calls)
    self.assertIn("run jobs executions list --job=cm-worker", calls)

  def test_waits_for_active_scans_then_rolls_out(self):
    self._write("wf_1", "projects/p/locations/l/workflows/cm-coordinator/executions/e1")
    self._write("wf_2", "projects/p/locations/l/workflows/cm-coordinator/executions/e1")
    result = self._run(MAX_WAIT_SECONDS="3600")
    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertEqual(result.stdout.count("waiting for 1 active scan(s)"), 2)
    # 3 pre-update checks (2 active, 1 idle) + 1 post-update check.
    self.assertEqual(self._read("wf_count").strip(), "4")
    self.assertEqual(len(self._read("updates").splitlines()), 2)

  def test_warns_if_scan_starts_during_update(self):
    # wf_1 (pre-update) is idle, wf_2 (post-update) has an active execution.
    self._write("wf_2", "projects/p/locations/l/workflows/cm-coordinator/executions/e2")
    result = self._run(MAX_WAIT_SECONDS="3600")
    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertEqual(len(self._read("updates").splitlines()), 2)
    self.assertIn("WARNING: 1 active scan(s) detected immediately after updating", result.stderr)

  def test_cloudbuild_yaml_sets_60s_poll_interval(self):
    cb_yaml = (_SCRIPT.parents[2] / "cloudbuild.yaml").read_text()
    self.assertIn("POLL_SECONDS=60", cb_yaml)

  def test_gives_up_after_max_wait_without_changes(self):
    self._write("wf_default", "e1\ne2")
    result = self._run(MAX_WAIT_SECONDS="0")
    self.assertEqual(result.returncode, 1)
    self.assertIn("still waiting for 2 active scan(s)", result.stderr)
    self.assertIn("re-running is safe", result.stderr)
    self.assertEqual(self._read("updates"), "")

  def test_running_job_execution_counts_as_active(self):
    # A running execution has no completion time; completed ones do.
    self._write("jobs_cm-worker", "cm-worker-abc\t\ncm-worker-old\t2026-01-01T00:00:00Z")
    result = self._run(MAX_WAIT_SECONDS="0")
    self.assertEqual(result.returncode, 1)
    self.assertIn("1 active scan(s)", result.stderr)
    self.assertEqual(self._read("updates"), "")

  def test_running_job_execution_without_trailing_tab_counts(self):
    self._write("jobs_cm-runner", "cm-runner-abc")
    result = self._run(MAX_WAIT_SECONDS="0")
    self.assertEqual(result.returncode, 1)
    self.assertEqual(self._read("updates"), "")

  def test_completed_job_executions_do_not_block(self):
    self._write("jobs_cm-runner", "cm-runner-a\t2026-01-01T00:00:00Z\ncm-runner-b\t2026-01-02T00:00:00Z")
    result = self._run(MAX_WAIT_SECONDS="0")
    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertEqual(len(self._read("updates").splitlines()), 2)

  def test_unresolvable_digest_fails_without_changes(self):
    (self.stub_dir / "digest_abc1234").unlink()
    result = self._run()
    self.assertEqual(result.returncode, 1)
    self.assertIn("Could not resolve the digest", result.stderr)
    self.assertEqual(self._read("updates"), "")

  def test_malformed_digest_fails(self):
    self._write("digest_abc1234", "sha256:xyz")
    result = self._run()
    self.assertEqual(result.returncode, 1)
    self.assertEqual(self._read("updates"), "")

  def test_newer_latest_supersedes_this_build(self):
    self._write("digest_latest", _OTHER_DIGEST)
    result = self._run()
    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertIn("A newer image", result.stdout)
    self.assertEqual(self._read("updates"), "")

  def test_supersede_is_rechecked_while_waiting(self):
    self._write("wf_default", "e1")
    self._write("latest_switch", f"1 {_OTHER_DIGEST}")
    result = self._run(MAX_WAIT_SECONDS="3600")
    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertIn("waiting for 1 active scan(s)", result.stdout)
    self.assertIn("A newer image", result.stdout)
    self.assertEqual(self._read("updates"), "")

  def test_latest_tag_skips_supersede_check(self):
    self._write("digest_latest", _OTHER_DIGEST)
    result = self._run(IMAGE_TAG="latest")
    self.assertEqual(result.returncode, 0, result.stderr)
    updates = self._read("updates")
    self.assertIn(f"@{_OTHER_DIGEST}", updates)

  def test_listing_errors_fail_closed(self):
    self._write("wf_fail", "")
    result = self._run(MAX_WAIT_SECONDS="3600")
    self.assertEqual(result.returncode, 1)
    self.assertIn("attempt 3 of 3", result.stderr)
    self.assertIn("Not rolling out", result.stderr)
    self.assertEqual(self._read("updates"), "")

  def test_explicit_job_and_workflow_names(self):
    result = self._run(RUNNER_JOB="r-job", WORKER_JOB="w-job", WORKFLOW="wf")
    self.assertEqual(result.returncode, 0, result.stderr)
    calls = self._read("calls")
    self.assertIn("workflows executions list wf ", calls)
    updates = self._read("updates")
    self.assertIn("run jobs update r-job ", updates)
    self.assertIn("run jobs update w-job ", updates)

  def test_invalid_wait_settings_are_rejected(self):
    for env in ({"MAX_WAIT_HOURS": "twelve"}, {"MAX_WAIT_SECONDS": "-1"}, {"POLL_SECONDS": "5m"}):
      with self.subTest(env=env):
        result = self._run(**env)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self._read("updates"), "")

  def test_required_settings(self):
    for name in ("PROJECT_ID", "REGION", "REPO_NAME", "IMAGE_TAG"):
      with self.subTest(name=name):
        env = dict(self.env)
        del env[name]
        result = subprocess.run(
            [_BASH, str(_SCRIPT)], env=env, capture_output=True, text=True,
            timeout=60, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(name, result.stderr)


if __name__ == "__main__":
  unittest.main()
