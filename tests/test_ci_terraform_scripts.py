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

"""Unit tests for scripts/ci/tf_*.sh and pipeline_lock.py."""

import http.server
import importlib.util
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_CI_DIR = _REPO_ROOT / "scripts" / "ci"
_SH = shutil.which("sh")

_lock_spec = importlib.util.spec_from_file_location("pipeline_lock", _CI_DIR / "pipeline_lock.py")
pipeline_lock = importlib.util.module_from_spec(_lock_spec)
_lock_spec.loader.exec_module(pipeline_lock)

# Records each call (one line per call) in $STUB_DIR/calls. `plan -out=F`
# creates F in the -chdir directory; `show -json` prints $STUB_DIR/plan.json;
# $STUB_DIR/fail_<subcommand> makes that subcommand fail;
# $STUB_DIR/fail_once_<subcommand> makes that subcommand fail once with the
# file's contents on stderr and then removes the file.
_STUB = textwrap.dedent("""\
    #!/bin/sh
    echo "$*" >> "$STUB_DIR/calls"
    dir=.
    case "$1" in -chdir=*) dir="${1#-chdir=}"; shift ;; esac
    if [ -f "$STUB_DIR/fail_once_$1" ]; then
      cat "$STUB_DIR/fail_once_$1" >&2
      rm -f "$STUB_DIR/fail_once_$1"
      exit 1
    fi
    [ -f "$STUB_DIR/fail_$1" ] && { echo "terraform $1 failed" >&2; exit 1; }
    case "$1" in
      plan)
        for a in "$@"; do
          case "$a" in -out=*) : > "$dir/${a#-out=}" ;; esac
        done ;;
      show) cat "$STUB_DIR/plan.json" ;;
    esac
    exit 0
    """)


@unittest.skipIf(_SH is None, "sh is required")
class TerraformScriptsTest(unittest.TestCase):

  def setUp(self):
    super().setUp()
    tmp = tempfile.TemporaryDirectory()
    self.addCleanup(tmp.cleanup)
    self.root = pathlib.Path(tmp.name)
    self.stub_dir = self.root / "stub"
    bin_dir = self.stub_dir / "bin"
    bin_dir.mkdir(parents=True)
    tf = bin_dir / "terraform"
    tf.write_text(_STUB)
    tf.chmod(0o755)
    # python3 must resolve to this interpreter for the guard step.
    (bin_dir / "python3").symlink_to(sys.executable)
    self.tf_dir = self.root / "stack"
    self.tf_dir.mkdir()
    self.env = {
        "PATH": f"{bin_dir}{os.pathsep}/usr/bin:/bin",
        "STUB_DIR": str(self.stub_dir),
        "TF_STATE_BUCKET": "state-bucket",
        "TF_STATE_PREFIX": "cm/gcp",
        "TF_DIR": str(self.tf_dir),
        "TF_APPLY_RETRY_SECONDS": "0",
    }
    self._plan([])

  def _plan(self, changes):
    (self.stub_dir / "plan.json").write_text(json.dumps({"resource_changes": changes}))

  def _calls(self):
    path = self.stub_dir / "calls"
    return path.read_text().splitlines() if path.exists() else []

  def _run(self, script, *args, **env):
    return subprocess.run(
        [_SH, str(_CI_DIR / script), *args],
        env={**self.env, **env}, cwd=self.root,
        capture_output=True, text=True, timeout=60, check=False,
    )

  def test_init_adds_gcs_backend_and_configures_it(self):
    result = self._run("tf_init.sh")
    self.assertEqual(result.returncode, 0, result.stderr)
    override = (self.tf_dir / "gcs_backend_override.tf").read_text()
    self.assertIn('backend "gcs" {}', override)
    self.assertEqual(self._calls(), [
        f"-chdir={self.tf_dir} init -input=false -reconfigure "
        "-backend-config=bucket=state-bucket -backend-config=prefix=cm/gcp"
    ])

  def test_init_requires_the_bucket(self):
    env = dict(self.env)
    del env["TF_STATE_BUCKET"]
    result = subprocess.run(
        [_SH, str(_CI_DIR / "tf_init.sh")], env=env, cwd=self.root,
        capture_output=True, text=True, timeout=60, check=False,
    )
    self.assertNotEqual(result.returncode, 0)
    self.assertIn("TF_STATE_BUCKET", result.stderr)
    self.assertEqual(self._calls(), [])

  def test_init_rejects_a_missing_directory(self):
    result = self._run("tf_init.sh", TF_DIR=str(self.root / "nope"))
    self.assertEqual(result.returncode, 1)
    self.assertEqual(self._calls(), [])

  def test_plan_is_read_only(self):
    result = self._run("tf_plan.sh")
    self.assertEqual(result.returncode, 0, result.stderr)
    calls = self._calls()
    self.assertEqual(len(calls), 2)
    self.assertIn(" init ", calls[0])
    self.assertIn(" plan ", calls[1])
    self.assertIn("-lock=false", calls[1])
    self.assertNotIn("-out", calls[1])
    self.assertFalse(any(" apply" in c for c in calls))

  def test_failing_plan_fails_the_check(self):
    (self.stub_dir / "fail_plan").write_text("")
    result = self._run("tf_plan.sh")
    self.assertNotEqual(result.returncode, 0)

  def test_apply_all_applies_the_saved_plan(self):
    result = self._run("tf_apply.sh", "all")
    self.assertEqual(result.returncode, 0, result.stderr)
    calls = self._calls()
    self.assertIn("-out=tfplan", calls[1])
    self.assertIn("-lock-timeout=15m", calls[1])
    self.assertIn("show -json tfplan", calls[2])
    self.assertTrue(calls[3].endswith("apply -input=false -no-color -lock-timeout=15m tfplan"))
    self.assertTrue((self.tf_dir / "tfplan.json").exists())
    # Lock must be released on exit.
    self.assertFalse((self.tf_dir / ".pipeline_state" / "pipeline.lock").exists())

  def test_apply_all_stops_on_protected_deletion(self):
    self._plan([{
        "address": "google_storage_bucket.reports", "mode": "managed",
        "type": "google_storage_bucket", "change": {"actions": ["delete", "create"]},
    }])
    result = self._run("tf_apply.sh", "all", DESTROY_TRIGGER="cm-tf-apply-destroy")
    self.assertEqual(result.returncode, 1)
    self.assertIn("google_storage_bucket.reports", result.stdout)
    self.assertIn("cm-tf-apply-destroy", result.stderr)
    self.assertFalse(any(" apply " in c for c in self._calls()))
    # Destroy guard failure must not be retried (only 1 plan call).
    self.assertEqual(sum(1 for c in self._calls() if " plan " in c), 1)
    self.assertFalse((self.tf_dir / ".pipeline_state" / "pipeline.lock").exists())

  def test_apply_all_with_allow_destroy(self):
    self._plan([{
        "address": "google_storage_bucket.reports", "mode": "managed",
        "type": "google_storage_bucket", "change": {"actions": ["delete"]},
    }])
    result = self._run("tf_apply.sh", "all", ALLOW_DESTROY="true")
    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertTrue(self._calls()[-1].endswith("tfplan"))

  def test_apply_all_retries_on_stale_saved_plan(self):
    (self.stub_dir / "fail_once_apply").write_text(
        "Error: Saved plan is stale\n\n"
        "The given plan file can no longer be applied because the state was changed.\n"
    )
    result = self._run("tf_apply.sh", "all", TF_APPLY_RETRY_SECONDS="0")
    self.assertEqual(result.returncode, 0, result.stderr)
    calls = self._calls()
    self.assertEqual(sum(1 for c in calls if " plan " in c), 2)
    self.assertEqual(sum(1 for c in calls if " apply " in c), 2)
    self.assertIn("re-running plan, guard and apply", result.stderr)

  def test_apply_all_retries_on_transient_state_lock(self):
    (self.stub_dir / "fail_once_plan").write_text(
        "Error: Error acquiring the state lock\n"
        "Lock Info:\n  Path: state-bucket/cm/gcp/default.tflock\n"
        "googleapi: Error 412: At least one of the pre-conditions you specified did not hold., conditionNotMet\n"
    )
    result = self._run("tf_apply.sh", "all", TF_APPLY_RETRY_SECONDS="0")
    self.assertEqual(result.returncode, 0, result.stderr)
    calls = self._calls()
    self.assertEqual(sum(1 for c in calls if " plan " in c), 2)
    self.assertEqual(sum(1 for c in calls if " apply " in c), 1)

  def test_apply_all_skips_superseded_commit_via_cloudbuild_read_token(self):
    # Create a bare git repository with two commits on main.
    remote_repo = self.root / "remote.git"
    subprocess.run(["git", "init", "--bare", "-b", "main", str(remote_repo)], check=True, capture_output=True)
    work_repo = self.root / "work"
    subprocess.run(["git", "clone", str(remote_repo), str(work_repo)], check=True, capture_output=True)
    for idx in (1, 2):
      (work_repo / "file.txt").write_text(f"v{idx}\n")
      subprocess.run(["git", "-C", str(work_repo), "add", "file.txt"], check=True, capture_output=True)
      subprocess.run(
          ["git", "-C", str(work_repo), "-c", "user.name=t", "-c", "user.email=t@e", "commit", "-m", f"c{idx}"],
          check=True, capture_output=True,
      )
    subprocess.run(["git", "-C", str(work_repo), "push", "origin", "main"], check=True, capture_output=True)
    old_sha = subprocess.run(
        ["git", "-C", str(work_repo), "rev-parse", "HEAD~1"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    head_sha = subprocess.run(
        ["git", "-C", str(work_repo), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()

    secret_token = "ghs_super_secret_token_value_999"
    repo_uri = str(remote_repo)

    class _Handler(http.server.BaseHTTPRequestHandler):
      def do_POST(self):
        if self.path.endswith(":accessReadToken"):
          body = json.dumps({"token": secret_token}).encode()
          self.send_response(200)
          self.send_header("Content-Type", "application/json")
          self.end_headers()
          self.wfile.write(body)
        elif "/upload/storage/v1/b/" in self.path:
          body = json.dumps({"generation": "7"}).encode()
          self.send_response(200)
          self.send_header("Content-Type", "application/json")
          self.end_headers()
          self.wfile.write(body)
        else:
          self.send_response(404)
          self.end_headers()

      def do_GET(self):
        body = json.dumps({"remoteUri": repo_uri}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

      def do_DELETE(self):
        self.send_response(204)
        self.end_headers()

      def log_message(self, format, *args):
        return

    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    self.addCleanup(server.shutdown)
    api_base = f"http://127.0.0.1:{server.server_port}"
    cb_repo = "projects/p/locations/us-central1/connections/github/repositories/org-repo"

    # 1. Superseded commit (old_sha != head_sha) skips apply and exits 0.
    result = self._run(
        "tf_apply.sh", "all",
        TF_APPLY_ACCESS_TOKEN="test-gcp-token",
        TF_GCS_API_URL=api_base,
        CLOUDBUILD_API_URL=api_base,
        CLOUDBUILD_REPO=cb_repo,
        DEPLOY_BRANCH="main",
        COMMIT_SHA=old_sha,
    )
    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertIn("skipping apply", result.stdout + result.stderr)
    self.assertEqual(self._calls(), [])
    self.assertNotIn(secret_token, result.stdout)
    self.assertNotIn(secret_token, result.stderr)

    # 2. Current HEAD commit (head_sha == head_sha) proceeds with plan and apply.
    result2 = self._run(
        "tf_apply.sh", "all",
        TF_APPLY_ACCESS_TOKEN="test-gcp-token",
        TF_GCS_API_URL=api_base,
        CLOUDBUILD_API_URL=api_base,
        CLOUDBUILD_REPO=cb_repo,
        DEPLOY_BRANCH="main",
        COMMIT_SHA=head_sha,
    )
    self.assertEqual(result2.returncode, 0, result2.stderr)
    self.assertTrue(any(" apply " in c for c in self._calls()))
    self.assertNotIn(secret_token, result2.stdout)
    self.assertNotIn(secret_token, result2.stderr)

  def test_apply_all_skips_superseded_commit_via_fallback_marker(self):
    # Initialize self.root as a git repo so git log -1 --format=%ct works.
    subprocess.run(["git", "init", "-b", "main", str(self.root)], check=True, capture_output=True)
    (self.root / "a.txt").write_text("1\n")
    subprocess.run(["git", "-C", str(self.root), "add", "a.txt"], check=True, capture_output=True)
    env_git = {
        **os.environ,
        "GIT_AUTHOR_DATE": "1700000100 +0000",
        "GIT_COMMITTER_DATE": "1700000100 +0000",
    }
    subprocess.run(
        ["git", "-C", str(self.root), "-c", "user.name=t", "-c", "user.email=t@e", "commit", "-m", "old"],
        check=True, capture_output=True, env=env_git,
    )
    old_sha = subprocess.run(
        ["git", "-C", str(self.root), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()

    (self.root / "a.txt").write_text("2\n")
    subprocess.run(["git", "-C", str(self.root), "add", "a.txt"], check=True, capture_output=True)
    env_git2 = {
        **os.environ,
        "GIT_AUTHOR_DATE": "1700000200 +0000",
        "GIT_COMMITTER_DATE": "1700000200 +0000",
    }
    subprocess.run(
        ["git", "-C", str(self.root), "-c", "user.name=t", "-c", "user.email=t@e", "commit", "-m", "new"],
        check=True, capture_output=True, env=env_git2,
    )
    new_sha = subprocess.run(
        ["git", "-C", str(self.root), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()

    # Apply new_sha first: records last-applied.json.
    r1 = self._run("tf_apply.sh", "all", COMMIT_SHA=new_sha)
    self.assertEqual(r1.returncode, 0, r1.stderr)
    self.assertTrue((self.tf_dir / ".pipeline_state" / "last-applied.json").exists())

    # Now an out-of-order/retried build for old_sha must skip without running terraform.
    (self.stub_dir / "calls").unlink()
    r2 = self._run("tf_apply.sh", "all", COMMIT_SHA=old_sha)
    self.assertEqual(r2.returncode, 0, r2.stderr)
    self.assertIn("skipping apply", r2.stdout + r2.stderr)
    self.assertEqual(self._calls(), [])

  def test_steps_can_run_separately(self):
    for step in ("plan", "guard", "apply"):
      with self.subTest(step=step):
        result = self._run("tf_apply.sh", step)
        self.assertEqual(result.returncode, 0, result.stderr)
    self.assertTrue(self._calls()[-1].endswith("tfplan"))

  def test_apply_needs_a_saved_plan(self):
    result = self._run("tf_apply.sh", "apply")
    self.assertEqual(result.returncode, 1)
    self.assertIn("No saved plan", result.stderr)
    self.assertEqual(self._calls(), [])

  def test_plan_step_removes_a_stale_plan(self):
    (self.tf_dir / "tfplan").write_text("stale")
    (self.stub_dir / "fail_plan").write_text("")
    result = self._run("tf_apply.sh", "plan")
    self.assertNotEqual(result.returncode, 0)
    self.assertFalse((self.tf_dir / "tfplan").exists())

  def test_unknown_mode(self):
    for args in ((), ("destroy",)):
      with self.subTest(args=args):
        result = self._run("tf_apply.sh", *args)
        self.assertEqual(result.returncode, 2)


class PipelineLockGCSTest(unittest.TestCase):
  """Tests GCS lock acquisition, contention, stale TTL breaking, and release."""

  def setUp(self):
    super().setUp()
    tmp = tempfile.TemporaryDirectory()
    self.addCleanup(tmp.cleanup)
    self.state_dir = pathlib.Path(tmp.name)
    env = mock.patch.dict(os.environ, {
        "TF_STATE_BUCKET": "test-bucket",
        "TF_STATE_PREFIX": "terraform/gcp",
        "TF_DIR": str(self.state_dir),
        "TF_APPLY_ACCESS_TOKEN": "fake-token",
        "TF_LOCK_POLL_SECONDS": "0",
        "TF_LOCK_TTL_SECONDS": "60",
        "BUILD_ID": "build-2",
        "COMMIT_SHA": "sha-2",
    }, clear=False)
    env.start()
    self.addCleanup(env.stop)

  def test_gcs_lock_acquire_and_release_with_generation_match(self):
    calls = []

    def fake_http(method, url, token=None, body=None, headers=None):
      calls.append((method, url))
      if method == "POST" and "ifGenerationMatch=0" in url:
        return 200, {"generation": "42"}
      if method == "DELETE" and "ifGenerationMatch=42" in url:
        return 204, {}
      self.fail(f"Unexpected HTTP call: {method} {url}")

    with mock.patch.object(pipeline_lock, "_http_json", side_effect=fake_http):
      out, err = io.StringIO(), io.StringIO()
      with redirect_stdout(out), redirect_stderr(err):
        self.assertEqual(pipeline_lock.acquire_lock(), 0)
        self.assertEqual(pipeline_lock.release_lock(), 0)

    self.assertEqual(len(calls), 2)
    self.assertEqual(calls[0][0], "POST")
    self.assertIn("ifGenerationMatch=0", calls[0][1])
    self.assertEqual(calls[1][0], "DELETE")
    self.assertIn("ifGenerationMatch=42", calls[1][1])

  def test_gcs_lock_breaks_stale_lock_after_ttl(self):
    calls = []
    state = {"broken": False}

    def fake_http(method, url, token=None, body=None, headers=None):
      calls.append((method, url))
      if method == "POST" and "ifGenerationMatch=0" in url:
        if not state["broken"]:
          return 412, {"error": "conditionNotMet"}
        return 200, {"generation": "100"}
      if method == "GET" and "alt=media" not in url:
        return 200, {"generation": "99", "timeCreated": "2020-01-01T00:00:00Z"}
      if method == "GET" and "alt=media" in url:
        return 200, {"holder": "build-1", "commit_sha": "sha-1", "acquired_at": 1000.0, "ttl_seconds": 60}
      if method == "DELETE" and "ifGenerationMatch=99" in url:
        state["broken"] = True
        return 204, {}
      self.fail(f"Unexpected HTTP call: {method} {url}")

    with mock.patch.object(pipeline_lock, "_http_json", side_effect=fake_http):
      out, err = io.StringIO(), io.StringIO()
      with redirect_stdout(out), redirect_stderr(err):
        self.assertEqual(pipeline_lock.acquire_lock(), 0)
      self.assertIn("breaking stale lock", out.getvalue())
      self.assertTrue(state["broken"])

  def test_gcs_lock_waits_on_fresh_lock_contention(self):
    post_attempts = {"n": 0}

    def fake_http(method, url, token=None, body=None, headers=None):
      if method == "POST" and "ifGenerationMatch=0" in url:
        post_attempts["n"] += 1
        if post_attempts["n"] == 1:
          return 412, {"error": "conditionNotMet"}
        return 200, {"generation": "101"}
      if method == "GET" and "alt=media" not in url:
        return 200, {"generation": "99", "timeCreated": "2099-01-01T00:00:00Z"}
      if method == "GET" and "alt=media" in url:
        return 200, {"holder": "build-1", "commit_sha": "sha-1", "acquired_at": 9999999999.0, "ttl_seconds": 1800}
      self.fail(f"Unexpected HTTP call: {method} {url}")

    with mock.patch.object(pipeline_lock, "_http_json", side_effect=fake_http):
      out, err = io.StringIO(), io.StringIO()
      with redirect_stdout(out), redirect_stderr(err):
        self.assertEqual(pipeline_lock.acquire_lock(), 0)
      self.assertIn("waiting for gs://test-bucket/terraform/gcp/pipeline.lock", out.getvalue())
      self.assertEqual(post_attempts["n"], 2)

  def test_ls_remote_error_scrubs_token(self):
    secret = "ghs_secret_value_to_scrub_12345"
    fake_proc = subprocess.CompletedProcess(
        args=["git", "ls-remote"],
        returncode=128,
        stdout="",
        stderr=f"fatal: unable to access with {secret}\n",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
      with self.assertRaises(pipeline_lock.PipelineLockError) as ctx:
        pipeline_lock._ls_remote_head("https://github.com/org/repo.git", "main", secret)
      self.assertNotIn(secret, str(ctx.exception))
      self.assertIn("***", str(ctx.exception))

  def test_use_gcs_backend_defaults_to_true_when_state_bucket_is_set(self):
    clean_env = {"TF_STATE_BUCKET": "prod-tfstate-bucket"}
    with mock.patch.dict(os.environ, clean_env, clear=True):
      self.assertTrue(pipeline_lock._use_gcs_backend())

  def test_gcs_fallback_marker_roundtrip_and_supersede(self):
    stored = {}

    def fake_http(method, url, token=None, body=None, headers=None):
      if method == "POST" and "last-applied.json" in url:
        stored["marker"] = dict(body)
        return 200, {"generation": "5"}
      if method == "GET" and "last-applied.json" in url:
        if "marker" not in stored:
          return 404, {}
        return 200, dict(stored["marker"])
      self.fail(f"Unexpected HTTP call: {method} {url}")

    with mock.patch.object(pipeline_lock, "_http_json", side_effect=fake_http):
      with mock.patch.dict(os.environ, {
          "CLOUDBUILD_REPO": "",
          "COMMIT_SHA": "new-sha-2222222",
          "COMMIT_TIMESTAMP": "1700000200",
      }, clear=False):
        out = io.StringIO()
        with redirect_stdout(out):
          self.assertEqual(pipeline_lock.check_commit(), 0)
          self.assertEqual(pipeline_lock.record_applied(), 0)

      self.assertEqual(stored["marker"]["sha"], "new-sha-2222222")
      self.assertEqual(stored["marker"]["commit_timestamp"], 1700000200)

      with mock.patch.dict(os.environ, {
          "CLOUDBUILD_REPO": "",
          "COMMIT_SHA": "old-sha-1111111",
          "COMMIT_TIMESTAMP": "1700000100",
      }, clear=False):
        out = io.StringIO()
        with redirect_stdout(out):
          self.assertEqual(
              pipeline_lock.check_commit(),
              pipeline_lock.SUPERSEDED_EXIT_CODE,
          )
        self.assertIn("superseded by new-sha-2222222", out.getvalue())

  def test_compute_cloud_run_jobs_ignore_gcloud_client_drift(self):
    compute_tf = (_REPO_ROOT / "terraform" / "gcp" / "compute.tf").read_text(
        encoding="utf-8"
    )
    for job_name in ("runner", "worker"):
      header = f'resource "google_cloud_run_v2_job" "{job_name}"'
      start = compute_tf.find(header)
      self.assertNotEqual(start, -1, f"Missing {header} in compute.tf")
      next_resource = compute_tf.find('\nresource "', start + len(header))
      block = (
          compute_tf[start:]
          if next_resource == -1
          else compute_tf[start:next_resource]
      )
      match = re.search(
          r"ignore_changes\s*=\s*\[(.*?)\n\s*\]", block, re.DOTALL
      )
      self.assertIsNotNone(
          match, f"Missing lifecycle.ignore_changes on {job_name}"
      )
      entries = {
          line.split("#", 1)[0].strip().rstrip(",")
          for line in match.group(1).splitlines()
          if line.split("#", 1)[0].strip()
      }
      self.assertEqual(
          entries,
          {
              "client",
              "client_version",
              "template[0].template[0].containers[0].image",
          },
          f"Unexpected ignore_changes on {job_name}: {entries}",
      )


if __name__ == "__main__":
  unittest.main()


