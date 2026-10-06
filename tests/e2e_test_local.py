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

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile


def run_cmd(cmd, cwd, env=None):
  print(f"Running: {' '.join(cmd)} in {cwd}")
  run_env = os.environ.copy()
  if env:
    run_env.update(env)
  tests_dir = os.path.dirname(os.path.abspath(__file__))
  run_env["PATH"] = f"{tests_dir}:{run_env.get('PATH', '')}"

  res = subprocess.run(cmd, cwd=cwd, env=run_env, capture_output=True, text=True)
  if res.returncode != 0:
    print(f"Command failed with code {res.returncode}")
    print(f"Stdout:\n{res.stdout}")
    print(f"Stderr:\n{res.stderr}")
    raise Exception(f"Command failed: {cmd}")
  return res


def test_local_storage_flow(temp_dir, bare_repo_dir, target_sha, proj_root):
  """Tests standard local storage execution flow."""
  print("\n--- Testing Local Storage Flow ---")
  local_storage_dir = os.path.join(temp_dir, "local_storage")

  # 1. Run Stage 1: Scan
  scan_env = {
      "CODEMENDER_RUN_MODE": "scan",
      "CODEMENDER_STORAGE_MODE": "local",
      "CODEMENDER_LOCAL_STORAGE_DIR": local_storage_dir,
      "CODEMENDER_SCAN_ID": "e2e-scan",
      "CODEMENDER_GCS_BUCKET": "e2e-bucket",
      "WORKSPACE_DIR": temp_dir,
      "GITHUB_REPO_URL": bare_repo_dir,
      "GITHUB_TOKEN": "fake-token",
      "CODEMENDER_SCAN_TARGET": ".",
      "CODEMENDER_MAX_TASKS": "2",
      "CODEMENDER_BUILD_COMMAND": "echo 'build'",
  }

  run_cmd(["python3", "orchestrator.py"], cwd=proj_root, env=scan_env)

  manifest_local_path = os.path.join(local_storage_dir, "e2e-bucket", "scans", "e2e-scan", "manifest.json")
  if not os.path.exists(manifest_local_path):
    raise Exception("manifest.json not found in local storage!")

  with open(manifest_local_path, "r") as f:
    manifest = json.load(f)

  print(f"Manifest contents:\n{json.dumps(manifest, indent=2)}")
  assert manifest["findings_count"] == 2
  assert manifest["target_sha"] == target_sha
  assert "base_workspace_url" in manifest
  assert len(manifest["partition_urls"]) == 2
  assert len(manifest["upload_urls"]) == 2

  # 2. Run Stage 2: Workers
  for i in range(2):
    worker_workspace = os.path.join(temp_dir, f"worker_workspace_{i}")
    os.makedirs(worker_workspace, exist_ok=True)

    worker_env = {
        "CODEMENDER_RUN_MODE": "worker",
        "CODEMENDER_STORAGE_MODE": "local",
        "CODEMENDER_LOCAL_STORAGE_DIR": local_storage_dir,
        "CODEMENDER_SCAN_ID": "e2e-scan",
        "CODEMENDER_GCS_BUCKET": "e2e-bucket",
        "WORKSPACE_DIR": worker_workspace,
        "CODEMENDER_WORKER_INDEX": str(i),
        "GITHUB_REPO_URL": bare_repo_dir,
        "GITHUB_TOKEN": "fake-token",
        "CODEMENDER_TARGET_SHA": target_sha,
        "CODEMENDER_BASE_WORKSPACE_URL": manifest["base_workspace_url"],
        "CODEMENDER_PARTITION_URLS": json.dumps(manifest["partition_urls"]),
        "CODEMENDER_UPLOAD_URLS": json.dumps(manifest["upload_urls"]),
        "CODEMENDER_BUILD_COMMAND": "echo 'build'",
    }

    run_cmd(["python3", "orchestrator.py"], cwd=proj_root, env=worker_env)

    worker_db_local_path = os.path.join(local_storage_dir, "e2e-bucket", "scans", "e2e-scan", f"worker_{i}_state.db")
    if not os.path.exists(worker_db_local_path):
      raise Exception(f"worker_{i}_state.db not found in local storage!")

  # 3. Run Stage 3: Aggregate
  aggregate_workspace = os.path.join(temp_dir, "aggregate_workspace")
  os.makedirs(aggregate_workspace, exist_ok=True)

  codemender_home = os.path.expanduser("~/.codemender")
  if os.path.exists(codemender_home):
    shutil.rmtree(codemender_home)

  aggregate_env = {
      "CODEMENDER_RUN_MODE": "aggregate",
      "CODEMENDER_STORAGE_MODE": "local",
      "CODEMENDER_LOCAL_STORAGE_DIR": local_storage_dir,
      "CODEMENDER_SCAN_ID": "e2e-scan",
      "CODEMENDER_GCS_BUCKET": "e2e-bucket",
      "WORKSPACE_DIR": aggregate_workspace,
      "GITHUB_REPO_URL": bare_repo_dir,
      "GITHUB_TOKEN": "fake-token",
      "CODEMENDER_TOTAL_WORKERS": "2",
      "CODEMENDER_BUILD_COMMAND": "echo 'build'",
  }

  run_cmd(["python3", "orchestrator.py"], cwd=proj_root, env=aggregate_env)

  # Verifications on Aggregated State
  reports_dir = os.path.join(local_storage_dir, "e2e-bucket", "reports")
  report_found = False
  for root, _, files in os.walk(reports_dir):
    for file in files:
      if file.startswith("report_") and file.endswith(".html"):
        report_found = True
        report_path = os.path.join(root, file)
        print(f"Found consolidated report: {report_path}")
        with open(report_path, "r") as r_file:
          content = r_file.read()
          assert "CodeMender Consolidated Report" in content

  assert report_found, "Consolidated report not found in local storage!"


def test_github_actions_flow(temp_dir, bare_repo_dir, target_sha, proj_root):
  """Tests native GitHub Actions 3-stage execution flow with .codemender_transit/."""
  print("\n--- Testing GitHub Actions Native Flow ---")
  gha_workspace = os.path.join(temp_dir, "gha_workspace")
  os.makedirs(gha_workspace, exist_ok=True)

  github_output_file = os.path.join(gha_workspace, "github_output.txt")
  step_summary_file = os.path.join(gha_workspace, "step_summary.md")

  # 1. Stage 1: Scan
  scan_env = {
      "CODEMENDER_RUN_MODE": "scan",
      "CODEMENDER_STORAGE_MODE": "github_actions",
      "WORKSPACE_DIR": gha_workspace,
      "GITHUB_REPO_URL": bare_repo_dir,
      "GITHUB_TOKEN": "fake-token",
      "CODEMENDER_SCAN_TARGET": ".",
      "CODEMENDER_MAX_TASKS": "2",
      "CODEMENDER_BUILD_COMMAND": "echo 'build'",
      "GITHUB_OUTPUT": github_output_file,
  }

  run_cmd(["python3", "orchestrator.py"], cwd=proj_root, env=scan_env)

  # Verify .codemender_transit/base files created
  transit_base = os.path.join(gha_workspace, ".codemender_transit", "base")
  assert os.path.exists(os.path.join(transit_base, "workspace_base.tar.gz")), "workspace_base.tar.gz missing"
  assert os.path.exists(os.path.join(transit_base, "manifest.json")), "manifest.json missing"
  assert os.path.exists(os.path.join(transit_base, "partition_0.json")), "partition_0.json missing"

  # Verify GITHUB_OUTPUT contents
  with open(github_output_file, "r") as f:
    out_txt = f.read()
  print(f"GITHUB_OUTPUT from scan:\n{out_txt}")
  assert "matrix=" in out_txt
  assert "findings_count=2" in out_txt

  # 2. Stage 2: Workers
  for i in range(2):
    worker_env = {
        "CODEMENDER_RUN_MODE": "worker",
        "CODEMENDER_STORAGE_MODE": "github_actions",
        "WORKSPACE_DIR": gha_workspace,
        "CODEMENDER_WORKER_INDEX": str(i),
        "GITHUB_REPO_URL": bare_repo_dir,
        "GITHUB_TOKEN": "fake-token",
        "CODEMENDER_TARGET_SHA": target_sha,
        "CODEMENDER_BUILD_COMMAND": "echo 'build'",
    }

    run_cmd(["python3", "orchestrator.py"], cwd=proj_root, env=worker_env)

    shard_db = os.path.join(gha_workspace, ".codemender_transit", "shards", f"worker_{i}", f"worker_{i}_state.db")
    assert os.path.exists(shard_db), f"Worker shard DB {shard_db} missing!"

  # 3. Stage 3: Aggregate
  codemender_home = os.path.expanduser("~/.codemender")
  if os.path.exists(codemender_home):
    shutil.rmtree(codemender_home)

  aggregate_env = {
      "CODEMENDER_RUN_MODE": "aggregate",
      "CODEMENDER_STORAGE_MODE": "github_actions",
      "WORKSPACE_DIR": gha_workspace,
      "GITHUB_REPO_URL": bare_repo_dir,
      "GITHUB_TOKEN": "fake-token",
      "CODEMENDER_TOTAL_WORKERS": "2",
      "CODEMENDER_BUILD_COMMAND": "echo 'build'",
      "GITHUB_STEP_SUMMARY": step_summary_file,
  }

  run_cmd(["python3", "orchestrator.py"], cwd=proj_root, env=aggregate_env)

  # Verify Step Summary
  assert os.path.exists(step_summary_file), "GITHUB_STEP_SUMMARY missing!"
  with open(step_summary_file, "r") as f:
    summary_text = f.read()
  print(f"GITHUB_STEP_SUMMARY:\n{summary_text}")
  assert "# 🛡️ CodeMender Security Remediation Summary" in summary_text
  assert "FIXED" in summary_text

  # Verify Merged DB
  merged_db_path = os.path.join(codemender_home, "state.db")
  conn = sqlite3.connect(merged_db_path)
  cursor = conn.cursor()
  cursor.execute("SELECT finding_id, status, verified FROM findings")
  rows = cursor.fetchall()
  print("GHA Merged database findings:")
  for r in rows:
    print(f"  ID: {r[0]}, Status: {r[1]}, Verified: {r[2]}")
    assert r[1] == "FIXED"
  conn.close()


def main():
  tests_dir = os.path.dirname(os.path.abspath(__file__))
  temp_dir = tempfile.mkdtemp(prefix="cm_e2e_")
  os.environ["HOME"] = temp_dir
  print(f"Temporary workspace: {temp_dir}")

  try:
    # 1. Setup Dummy Git Repository
    repo_src_dir = os.path.join(temp_dir, "dummy_repo")
    os.makedirs(repo_src_dir, exist_ok=True)

    with open(os.path.join(repo_src_dir, "db.py"), "w") as f:
      f.write("# Database file\n")
    with open(os.path.join(repo_src_dir, "web.py"), "w") as f:
      f.write("# Web file\n")

    run_cmd(["git", "init"], cwd=repo_src_dir)
    run_cmd(["git", "config", "user.name", "Test User"], cwd=repo_src_dir)
    run_cmd(["git", "config", "user.email", "test@example.com"], cwd=repo_src_dir)
    run_cmd(["git", "add", "."], cwd=repo_src_dir)
    run_cmd(["git", "commit", "-m", "Initial commit"], cwd=repo_src_dir)
    target_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_src_dir, capture_output=True, text=True).stdout.strip()
    print(f"Dummy Repo Target SHA: {target_sha}")

    # Clone to bare repos to simulate GitHub remote (allows pushing)
    bare_repo_dir_local = os.path.join(temp_dir, "dummy_repo_local.git")
    run_cmd(["git", "clone", "--bare", repo_src_dir, bare_repo_dir_local], cwd=temp_dir)
    print(f"Bare Remote Repo (Local): {bare_repo_dir_local}")

    bare_repo_dir_gha = os.path.join(temp_dir, "dummy_repo_gha.git")
    run_cmd(["git", "clone", "--bare", repo_src_dir, bare_repo_dir_gha], cwd=temp_dir)
    print(f"Bare Remote Repo (GHA): {bare_repo_dir_gha}")

    proj_root = os.path.dirname(tests_dir)
    print(f"Project root: {proj_root}")

    # Run Local Storage Flow
    test_local_storage_flow(temp_dir, bare_repo_dir_local, target_sha, proj_root)

    # Run Native GitHub Actions Flow
    test_github_actions_flow(temp_dir, bare_repo_dir_gha, target_sha, proj_root)

    print("\n🎉 ALL LOCAL AND GHA E2E TESTS COMPLETED SUCCESSFULLY! 🎉")

  except Exception as e:
    print(f"\n❌ E2E TEST FAILED: {e}")
    sys.exit(1)
  finally:
    print(f"Cleaning up {temp_dir}...")
    shutil.rmtree(temp_dir)
    if os.path.exists(os.path.expanduser("~/.codemender")):
      shutil.rmtree(os.path.expanduser("~/.codemender"))


if __name__ == "__main__":
  main()
