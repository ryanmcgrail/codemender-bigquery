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

"""The cm project_paths scope each runner hands to find, verify and fix.

`cm find <target>` must stay scoped to its target, so project_paths is empty
while it runs. `cm verify` and `cm fix` resolve each finding's project root
from project_paths (falling back to the finding file's directory) and run the
build command there, so they must see the repository root.

These tests use the real inject_codemender_config and read
~/.codemender/config.yaml at the moment each cm command is launched.
"""

import json
import os
import tempfile
import unittest
from unittest import mock

import yaml

from codemender_agent.runners import scan
from codemender_agent.runners import sequential
from codemender_agent.runners.worker import run_worker_pipeline


def _project_paths(home):
  path = os.path.join(home, ".codemender", "config.yaml")
  if not os.path.exists(path):
    return None
  with open(path, "r", encoding="utf-8") as f:
    return (yaml.safe_load(f) or {}).get("project_paths")


def _cm_action(cmd):
  """Returns find/verify/fix when cmd is that cm invocation, else None."""
  if not cmd or not str(cmd[0]).endswith("cm") or len(cmd) < 2:
    return None
  return cmd[1] if cmd[1] in ("find", "verify", "fix") else None


class WorkerProjectPathsTest(unittest.TestCase):
  """The parallel worker runs only verify and fix."""

  def setUp(self):
    self.tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self.tmp.cleanup)
    self.home = self.tmp.name
    env = mock.patch.dict(
        os.environ,
        {
            "HOME": self.home,
            "CODEMENDER_WORKER_INDEX": "0",
            "CODEMENDER_BASE_WORKSPACE_URL": "http://signed-url/base.tar.gz",
            "CODEMENDER_PARTITION_URLS": json.dumps(
                ["http://signed-url/partition_0.json"]
            ),
            "CODEMENDER_UPLOAD_URLS": json.dumps(["http://signed-url/upload_0.db"]),
            "CODEMENDER_METADATA_URLS": json.dumps(
                ["http://signed-url/metadata_0.json"]
            ),
            "WORKSPACE_DIR": self.home,
            "GITHUB_REPO_URL": "https://github.com/owner/repo.git",
            "GITHUB_TOKEN": "fake-token",
            "CODEMENDER_TARGET_SHA": "abc123commitsha",
            "CODEMENDER_BUILD_COMMAND": "mvn -q -B -DskipTests compile",
            "CODEMENDER_DRY_RUN": "true",
        },
    )
    env.start()
    self.addCleanup(env.stop)
    # What the scan stage archives: find's empty scope.
    cm_home = os.path.join(self.home, ".codemender")
    os.makedirs(cm_home, exist_ok=True)
    with open(os.path.join(cm_home, "config.yaml"), "w", encoding="utf-8") as f:
      yaml.safe_dump({"project_paths": []}, f)

  def _run(self, extra_env):
    seen = []

    def download(url, dest_path):
      if "partition" in url:
        with open(dest_path, "w", encoding="utf-8") as f:
          json.dump({"partition_index": 0, "finding_ids": ["fid-1"]}, f)
      return "partition" in url or "base.tar.gz" in url

    report = mock.MagicMock(returncode=0, token_usage=None)
    report.stdout = json.dumps([{
        "FindingID": "fid-1",
        "Status": "DETECTED",
        "VulnType": "SQL_INJECTION",
        "FilePath": "src/main/java/app/Db.java",
        "Title": "SQLi",
        "Severity": "HIGH",
        "Analysis": "a",
    }])

    def run_cmd(cmd, *_args, **_kwargs):
      action = _cm_action(cmd)
      if action:
        seen.append((action, _project_paths(self.home)))
      res = mock.MagicMock(returncode=0, stdout="", token_usage=None)
      joined = " ".join(str(c) for c in cmd)
      if "report" in joined:
        return report
      if cmd[:2] == ["git", "status"]:
        res.stdout = " M src/main/java/app/Db.java"
      return res

    patches = {
        "run_command": mock.DEFAULT,
        "download_from_url": mock.DEFAULT,
        "upload_to_url": mock.DEFAULT,
        "is_finding_verified": mock.DEFAULT,
        "get_finding_status": mock.DEFAULT,
    }
    with mock.patch.dict(os.environ, extra_env), mock.patch.multiple(
        "codemender_agent.runners.worker", **patches
    ) as m, mock.patch("tarfile.open"), mock.patch(
        "shutil.which", return_value="/bin/cm"
    ):
      m["run_command"].side_effect = run_cmd
      m["download_from_url"].side_effect = download
      m["upload_to_url"].return_value = True
      m["is_finding_verified"].return_value = True
      m["get_finding_status"].return_value = "FIXED"
      run_worker_pipeline()
    return seen

  def test_fix_sees_repo_root(self):
    seen = self._run({"CODEMENDER_SKIP_VERIFY": "true"})
    repo_dir = os.path.abspath(os.path.join(self.home, "repo"))
    self.assertEqual([a for a, _ in seen], ["fix"])
    self.assertEqual(seen[0][1], [repo_dir])

  def test_verify_and_fix_see_repo_root(self):
    seen = self._run({"CODEMENDER_SKIP_VERIFY": "false"})
    repo_dir = os.path.abspath(os.path.join(self.home, "repo"))
    self.assertEqual([a for a, _ in seen], ["verify", "fix"])
    for _, paths in seen:
      self.assertEqual(paths, [repo_dir])


class ScanInitProjectPathsTest(unittest.TestCase):
  """The scan stage runs only find; its scope stays empty."""

  def test_find_scope_empty_even_if_cm_init_writes_repo_root(self):
    with tempfile.TemporaryDirectory() as home:
      repo_dir = os.path.join(home, "repo")
      os.makedirs(repo_dir)
      cm_home = os.path.join(home, ".codemender")

      def run_cmd(cmd, *_args, **_kwargs):
        # cm init writes the repository root into project_paths.
        if len(cmd) > 1 and cmd[1] == "init":
          os.makedirs(cm_home, exist_ok=True)
          with open(
              os.path.join(cm_home, "config.yaml"), "w", encoding="utf-8"
          ) as f:
            yaml.safe_dump({"project_paths": [repo_dir]}, f)
        return mock.MagicMock(returncode=0, stdout="")

      with mock.patch.dict(
          os.environ,
          {"HOME": home, "CODEMENDER_BUILD_COMMAND": "make"},
      ), mock.patch.object(scan, "run_command", side_effect=run_cmd):
        scan._init_codemender(repo_dir, {}, "/bin/cm")
      self.assertEqual(_project_paths(home), [])


class SequentialProjectPathsTest(unittest.TestCase):
  """Sequential mode runs find, then verify and fix, in one container."""

  def test_find_empty_then_verify_and_fix_repo_root(self):
    with tempfile.TemporaryDirectory() as home:
      repo_dir = os.path.join(home, "r")
      os.makedirs(os.path.join(repo_dir, ".git"))
      seen = []
      report = json.dumps([
          {"FindingID": "fid-1", "VulnType": "XSS", "FilePath": "web/a.py",
           "StartLine": 2}
      ])

      def run_cmd(cmd, *_args, **_kwargs):
        action = _cm_action(cmd)
        if action:
          seen.append((action, _project_paths(home)))
        res = mock.MagicMock(returncode=0, stdout="", token_usage=None)
        joined = " ".join(str(c) for c in cmd)
        if cmd[:3] == ["git", "branch", "--show-current"]:
          res.stdout = "main\n"
        elif "report" in joined and "json" in joined:
          res.stdout = report
        elif cmd[:2] == ["git", "status"]:
          res.stdout = " M web/a.py"
        return res

      env = {
          "HOME": home,
          "WORKSPACE_DIR": home,
          "CODEMENDER_SKIP_VERIFY": "false",
          "CODEMENDER_DRY_RUN": "true",
          "CODEMENDER_BUILD_COMMAND": "make",
      }
      with mock.patch.dict(os.environ, env), mock.patch.multiple(
          sequential,
          run_command=mock.DEFAULT,
          get_github_credentials=mock.DEFAULT,
          get_scrubbed_env=mock.DEFAULT,
          ensure_cm_updated=mock.DEFAULT,
          log_cm_version=mock.DEFAULT,
          get_cm_default_model=mock.DEFAULT,
          setup_local_git_excludes=mock.DEFAULT,
          get_finding_status=mock.DEFAULT,
      ) as m, mock.patch(
          "codemender_agent.runners.sequential.is_finding_verified",
          return_value=True,
          create=True,
      ):
        m["run_command"].side_effect = run_cmd
        m["get_github_credentials"].return_value = (
            "https://github.com/o/r.git", "t"
        )
        m["ensure_cm_updated"].return_value = "/bin/cm"
        m["get_cm_default_model"].return_value = None
        m["get_scrubbed_env"].return_value = {}
        m["get_finding_status"].return_value = "FIXED"
        sequential.run_sequential_pipeline()

      actions = [a for a, _ in seen]
      self.assertEqual(actions[0], "find")
      self.assertIn("fix", actions)
      self.assertEqual(seen[0][1], [])
      root = [os.path.abspath(repo_dir)]
      for action, paths in seen[1:]:
        self.assertIn(action, ("verify", "fix"))
        self.assertEqual(paths, root, action)


if __name__ == "__main__":
  unittest.main()
