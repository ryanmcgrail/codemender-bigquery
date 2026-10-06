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

"""Unit tests for scripts/ci/destroy_guard.py."""

import importlib.util
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

_SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "ci" / "destroy_guard.py"
_spec = importlib.util.spec_from_file_location("destroy_guard", _SCRIPT)
destroy_guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(destroy_guard)


def _change(address, rtype, actions, mode="managed"):
  return {
      "address": address,
      "mode": mode,
      "type": rtype,
      "change": {"actions": actions},
  }


class DestroyGuardTest(unittest.TestCase):

  def setUp(self):
    super().setUp()
    self._tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self._tmp.cleanup)
    env = mock.patch.dict(os.environ, {}, clear=False)
    env.start()
    self.addCleanup(env.stop)
    os.environ.pop("ALLOW_DESTROY", None)
    os.environ.pop("DESTROY_TRIGGER", None)
    os.environ.pop("RESOURCE_PREFIX", None)

  def _write_plan(self, changes):
    path = pathlib.Path(self._tmp.name) / "tfplan.json"
    path.write_text(json.dumps({"format_version": "1.2", "resource_changes": changes}))
    return str(path)

  def _run(self, *args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
      code = destroy_guard.main(list(args))
    return code, out.getvalue(), err.getvalue()

  def test_plan_without_deletions_passes(self):
    plan = self._write_plan([
        _change("google_storage_bucket.reports", "google_storage_bucket", ["update"]),
        _change("google_cloud_run_v2_job.runner", "google_cloud_run_v2_job", ["create"]),
        _change("google_bigquery_dataset.telemetry[0]", "google_bigquery_dataset", ["no-op"]),
    ])
    code, out, _ = self._run(plan)
    self.assertEqual(code, 0)
    self.assertIn("no protected resources", out)

  def test_deleting_a_protected_resource_fails(self):
    plan = self._write_plan([
        _change("google_storage_bucket.reports", "google_storage_bucket", ["delete"]),
    ])
    code, out, err = self._run(plan)
    self.assertEqual(code, 1)
    self.assertIn("google_storage_bucket.reports (delete)", out)
    self.assertIn("<prefix>-tf-apply-destroy", err)
    self.assertIn("verify that the build's commit", err)

  def test_destroy_trigger_name_from_environment(self):
    plan = self._write_plan([
        _change("google_storage_bucket.reports", "google_storage_bucket", ["delete"]),
    ])
    os.environ["RESOURCE_PREFIX"] = "cm-prod"
    code, _, err = self._run(plan)
    self.assertEqual(code, 1)
    self.assertIn("cm-prod-tf-apply-destroy", err)

    os.environ["DESTROY_TRIGGER"] = "custom-destroy-trigger"
    code, _, err = self._run(plan)
    self.assertEqual(code, 1)
    self.assertIn("custom-destroy-trigger", err)

  def test_replacing_a_protected_resource_fails(self):
    for actions in (["delete", "create"], ["create", "delete"]):
      with self.subTest(actions=actions):
        plan = self._write_plan([
            _change("google_bigquery_table.scan_runs[0]", "google_bigquery_table", actions),
        ])
        code, _, _ = self._run(plan)
        self.assertEqual(code, 1)

  def test_every_protected_type_is_guarded(self):
    for rtype in sorted(destroy_guard.PROTECTED_TYPES):
      with self.subTest(rtype=rtype):
        plan = self._write_plan([_change(f"{rtype}.x", rtype, ["delete"])])
        code, _, _ = self._run(plan)
        self.assertEqual(code, 1)

  def test_deleting_unprotected_resources_passes(self):
    plan = self._write_plan([
        _change("google_cloud_scheduler_job.repo_scans[\"svc\"]", "google_cloud_scheduler_job", ["delete"]),
        _change("google_project_iam_member.x", "google_project_iam_member", ["delete", "create"]),
    ])
    code, _, _ = self._run(plan)
    self.assertEqual(code, 0)

  def test_forgetting_a_protected_resource_passes(self):
    plan = self._write_plan([
        _change("google_storage_bucket.reports", "google_storage_bucket", ["forget"]),
    ])
    code, _, _ = self._run(plan)
    self.assertEqual(code, 0)

  def test_data_sources_are_ignored(self):
    plan = self._write_plan([
        _change("data.google_secret_manager_secret.x", "google_secret_manager_secret", ["delete"], mode="data"),
    ])
    code, _, _ = self._run(plan)
    self.assertEqual(code, 0)

  def test_allow_destroy_flag_lists_but_passes(self):
    plan = self._write_plan([
        _change("google_secret_manager_secret.github_app_token", "google_secret_manager_secret", ["delete"]),
    ])
    code, out, _ = self._run(plan, "--allow-destroy")
    self.assertEqual(code, 0)
    self.assertIn("google_secret_manager_secret.github_app_token", out)
    self.assertIn("allowed for this run", out)

  def test_allow_destroy_environment(self):
    plan = self._write_plan([
        _change("google_artifact_registry_repository.docker_repo", "google_artifact_registry_repository", ["delete"]),
    ])
    for value, expected in (("true", 0), ("TRUE", 0), ("1", 0), ("yes", 0), ("false", 1), ("", 1), ("0", 1)):
      with self.subTest(value=value):
        os.environ["ALLOW_DESTROY"] = value
        code, _, _ = self._run(plan)
        self.assertEqual(code, expected)

  def test_empty_plan_passes(self):
    for changes in ([], None):
      with self.subTest(changes=changes):
        path = pathlib.Path(self._tmp.name) / "empty.json"
        path.write_text(json.dumps({"resource_changes": changes}))
        code, _, _ = self._run(str(path))
        self.assertEqual(code, 0)

  def test_unreadable_plan_fails_closed(self):
    missing = str(pathlib.Path(self._tmp.name) / "missing.json")
    code, _, err = self._run(missing)
    self.assertEqual(code, 2)
    self.assertIn("cannot read", err)

    garbage = pathlib.Path(self._tmp.name) / "garbage.json"
    garbage.write_text("not json")
    code, _, _ = self._run(str(garbage))
    self.assertEqual(code, 2)

    not_a_plan = pathlib.Path(self._tmp.name) / "list.json"
    not_a_plan.write_text("[]")
    code, _, _ = self._run(str(not_a_plan))
    self.assertEqual(code, 2)

  def test_runs_as_a_script(self):
    plan = self._write_plan([
        _change("google_storage_bucket.reports", "google_storage_bucket", ["delete"]),
    ])
    env = {k: v for k, v in os.environ.items() if k != "ALLOW_DESTROY"}
    result = subprocess.run(
        [sys.executable, str(_SCRIPT), plan],
        capture_output=True, text=True, env=env, check=False,
    )
    self.assertEqual(result.returncode, 1)
    self.assertIn("google_storage_bucket.reports", result.stdout)


if __name__ == "__main__":
  unittest.main()
