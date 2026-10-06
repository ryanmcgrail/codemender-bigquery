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

import os
import unittest
from unittest.mock import patch

from codemender_agent.utils import accumulate_model_token_usage
from codemender_agent.utils import build_cm_command
from codemender_agent.utils import parse_token_metric
from codemender_agent.utils import render_token_usage_markdown
from codemender_agent.utils import resolve_command_model


class TestCommandBuilder(unittest.TestCase):

  def test_accumulate_model_token_usage(self):
    usage = {}
    accumulate_model_token_usage(usage, "test-model-flash", {"in_tokens": 100, "out_tokens": 20, "total_tokens": 120})
    self.assertEqual(usage, {"test-model-flash": {"in_tokens": 100, "out_tokens": 20, "total_tokens": 120}})

    accumulate_model_token_usage(usage, "test-model-flash", {"in_tokens": 50, "out_tokens": 10, "total_tokens": 60})
    self.assertEqual(usage, {"test-model-flash": {"in_tokens": 150, "out_tokens": 30, "total_tokens": 180}})

    accumulate_model_token_usage(usage, "test-model-pro", {"in_tokens": 200, "out_tokens": 40, "total_tokens": 240})
    self.assertEqual(len(usage), 2)
    self.assertEqual(usage["test-model-pro"], {"in_tokens": 200, "out_tokens": 40, "total_tokens": 240})

    # None or non-dict handling
    accumulate_model_token_usage(usage, "test-model-pro", None)
    self.assertEqual(usage["test-model-pro"]["total_tokens"], 240)

  def test_render_token_usage_markdown(self):
    # Empty / None handling
    self.assertEqual(render_token_usage_markdown(None), "")
    self.assertEqual(render_token_usage_markdown({}), "")

    # Multi-model markdown table formatting
    totals = {
        "test-model-a": {"in_tokens": 12000, "out_tokens": 500, "total_tokens": 12500},
        "test-model-b": {"in_tokens": 45000, "out_tokens": 3200, "total_tokens": 48200},
    }
    md = render_token_usage_markdown(totals)
    self.assertIn("### ⚡ LLM Token Usage Summary", md)
    self.assertIn("- **Input Tokens:** 57,000", md)
    self.assertIn("- **Output Tokens:** 3,700", md)
    self.assertIn("- **Grand Total Tokens:** 60,700", md)
    self.assertIn("| Model | Input Tokens | Output Tokens | Total Tokens |", md)
    self.assertIn("| `test-model-a` | 12,000 | 500 | 12,500 |", md)
    self.assertIn("| `test-model-b` | 45,000 | 3,200 | 48,200 |", md)

  def test_parse_token_metric(self):
    self.assertEqual(parse_token_metric("41k"), 41000)
    self.assertEqual(parse_token_metric("41.5k"), 41500)
    self.assertEqual(parse_token_metric("1.2M"), 1200000)
    self.assertEqual(parse_token_metric("1.5G"), 1500000000)
    self.assertEqual(parse_token_metric("561"), 561)
    with self.assertRaises(ValueError):
      parse_token_metric("")
    with self.assertRaises(ValueError):
      parse_token_metric("abc")

  @patch.dict(os.environ, {}, clear=True)
  def test_resolve_command_model(self):
    self.assertIsNone(resolve_command_model("find"))

    with patch.dict(os.environ, {"CODEMENDER_MODEL": "test-model-default"}):
      self.assertEqual(resolve_command_model("find"), "test-model-default")

    with patch.dict(
        os.environ,
        {
            "CODEMENDER_MODEL": "test-model-default",
            "CODEMENDER_FIND_MODEL": "test-model-find",
        },
    ):
      self.assertEqual(resolve_command_model("find"), "test-model-find")
      self.assertEqual(resolve_command_model("verify"), "test-model-default")

  def test_build_cm_command_validation(self):
    with self.assertRaises(ValueError):
      build_cm_command("cm", "find", target_or_id=None)
    with self.assertRaises(ValueError):
      build_cm_command("cm", "verify", target_or_id="")
    with self.assertRaises(ValueError):
      build_cm_command("cm", "fix", target_or_id=None)

  @patch.dict(os.environ, {"CODEMENDER_CLI_VERSION": "preview"}, clear=True)
  def test_build_cm_command_preview(self):
    # find
    cmd = build_cm_command("cm", "find", ".")
    self.assertEqual(cmd, ["cm", "find", "-y", "."])

    # find with model
    with patch.dict(os.environ, {"CODEMENDER_FIND_MODEL": "test-model-pro"}):
      cmd = build_cm_command("cm", "find", ".")
      self.assertEqual(cmd, ["cm", "find", "-y", "--model", "test-model-pro", "."])

    # verify
    cmd = build_cm_command("cm", "verify", "id-123")
    self.assertEqual(cmd, ["cm", "verify", "-y", "--bypass-warning", "id-123"])

    # verify with skip exploit verification
    with patch.dict(os.environ, {"CODEMENDER_SKIP_EXPLOIT_VERIFICATION": "true"}):
      cmd = build_cm_command("cm", "verify", "id-123")
      self.assertEqual(
          cmd,
          [
              "cm",
              "verify",
              "-y",
              "--bypass-warning",
              "--skip-exploit-verification",
              "id-123",
          ],
      )

    # fix
    cmd = build_cm_command("cm", "fix", "id-123")
    self.assertEqual(cmd, ["cm", "fix", "-y", "--bypass-warning", "id-123"])

    # report
    cmd = build_cm_command("cm", "report", extra_flags=["-f", "html"])
    self.assertEqual(cmd, ["cm", "report", "-f", "html"])

  @patch.dict(os.environ, {"CODEMENDER_CLI_VERSION": "legacy"}, clear=True)
  def test_build_cm_command_legacy(self):
    # find
    cmd = build_cm_command("cm", "find", ".")
    self.assertEqual(cmd, ["cm", "find", "."])

    # verify
    cmd = build_cm_command("cm", "verify", "id-123")
    self.assertEqual(cmd, ["cm", "find", "verify", "id-123", "--yes"])

    # fix
    cmd = build_cm_command("cm", "fix", "id-123")
    self.assertEqual(cmd, ["cm", "fix", "id-123", "--yes"])

  @patch.dict(
      os.environ,
      {"CODEMENDER_CLI_VERSION": "preview", "CODEMENDER_SANDBOX_ENABLED": "false"},
      clear=True,
  )
  def test_build_cm_command_sandbox_disabled(self):
    # find omits --unrestricted so allowedRoots stays scoped to target_or_id
    cmd_find = build_cm_command("cm", "find", "src/bokeh/server/views")
    self.assertEqual(cmd_find, ["cm", "find", "-y", "src/bokeh/server/views"])

    # verify and fix include --unrestricted
    cmd_verify = build_cm_command("cm", "verify", "id-123")
    self.assertEqual(
        cmd_verify,
        ["cm", "verify", "-y", "--bypass-warning", "--unrestricted", "id-123"],
    )
    cmd_fix = build_cm_command("cm", "fix", "id-123")
    self.assertEqual(
        cmd_fix,
        ["cm", "fix", "-y", "--bypass-warning", "--unrestricted", "id-123"],
    )

  def test_empty_model_env_does_not_pass_model_flag(self):
    """Verify empty CODEMENDER_MODEL='' and CODEMENDER_FIND_MODEL='' do not pass --model to cm."""
    from codemender_agent.config import OrchestratorConfig

    with patch.dict(
        os.environ,
        {
            "CODEMENDER_CLI_VERSION": "preview",
            "CODEMENDER_MODEL": "   ",
            "CODEMENDER_FIND_MODEL": "",
            "CODEMENDER_FIX_MODEL": "",
        },
        clear=True,
    ):
      self.assertIsNone(resolve_command_model("find"))
      self.assertIsNone(resolve_command_model("fix"))
      cfg = OrchestratorConfig.from_env()
      self.assertIsNone(cfg.model)
      self.assertIsNone(cfg.find_model)
      self.assertIsNone(cfg.fix_model)
      cmd = build_cm_command("cm", "find", ".")
      self.assertNotIn("--model", cmd)

  def test_get_cm_default_model_and_binary_staging(self):
    """Verify dynamic default model detection from `cm find --help` and binary staging/restoration."""
    import tempfile
    from codemender_agent.codemender.cli import (
        _CM_DEFAULT_MODEL_CACHE,
        get_cm_default_model,
        restore_staged_cm_binary,
        stage_cm_binary_for_archive,
    )

    _CM_DEFAULT_MODEL_CACHE.clear()
    with tempfile.TemporaryDirectory() as tmpdir:
      fake_cm = os.path.join(tmpdir, "cm")
      with open(fake_cm, "w", encoding="utf-8") as f:
        f.write(
            '#!/bin/sh\necho \'      --model string     LLM model to use (default "cm-cli-default-model")\'\n'
        )
      os.chmod(fake_cm, 0o755)

      detected = get_cm_default_model(fake_cm, cwd=os.path.join(tmpdir, "nonexistent_cwd"))
      self.assertEqual(detected, "cm-cli-default-model")

      cm_home = os.path.join(tmpdir, ".codemender")
      staged = stage_cm_binary_for_archive(cm_home, fake_cm)
      self.assertTrue(staged and os.path.isfile(staged))

      install_dest = os.path.join(tmpdir, "installed_bin", "cm")
      os.makedirs(os.path.dirname(install_dest), exist_ok=True)
      restored = restore_staged_cm_binary(cm_home, install_path=install_dest)
      self.assertEqual(restored, install_dest)
      self.assertTrue(os.path.isfile(install_dest))

  def test_ensure_cm_updated_default_false_and_opt_in(self):
    """Verify ensure_cm_updated defaults to false (backward-compatible) and runs `cm update` when enabled."""
    import tempfile
    from codemender_agent.codemender.cli import (
        _CM_DEFAULT_MODEL_CACHE,
        ensure_cm_updated,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
      fake_cm = os.path.join(tmpdir, "cm")
      marker_file = os.path.join(tmpdir, "updated.marker")
      with open(fake_cm, "w", encoding="utf-8") as f:
        f.write(
            f'#!/bin/sh\nif [ "$1" = "update" ]; then\n  echo "updated" > "{marker_file}"\n  echo "Updated to v0.9.0"\nfi\n'
        )
      os.chmod(fake_cm, 0o755)

      # 1. Default (unset or empty CODEMENDER_AUTO_UPDATE) -> does not run `cm update`
      with patch.dict(os.environ, {"CODEMENDER_AUTO_UPDATE": ""}, clear=True):
        res_path = ensure_cm_updated(fake_cm, cwd=tmpdir)
        self.assertEqual(res_path, fake_cm)
        self.assertFalse(os.path.exists(marker_file))

      # 2. Explicit CODEMENDER_AUTO_UPDATE=true via os.environ -> runs `cm update` and clears model cache
      _CM_DEFAULT_MODEL_CACHE[fake_cm] = "cached-model"
      with patch.dict(os.environ, {"CODEMENDER_AUTO_UPDATE": "true"}, clear=True):
        res_path = ensure_cm_updated(fake_cm, cwd=tmpdir)
        self.assertEqual(res_path, fake_cm)
        self.assertTrue(os.path.exists(marker_file))
        self.assertNotIn(fake_cm, _CM_DEFAULT_MODEL_CACHE)

      # 3. Explicit CODEMENDER_AUTO_UPDATE=true via env dict when os.environ is empty
      os.remove(marker_file)
      with patch.dict(os.environ, {"CODEMENDER_AUTO_UPDATE": ""}, clear=True):
        res_path = ensure_cm_updated(
            fake_cm, env={"CODEMENDER_AUTO_UPDATE": "true"}, cwd=tmpdir
        )
        self.assertEqual(res_path, fake_cm)
        self.assertTrue(os.path.exists(marker_file))

      # 4. Non-zero exit code during `cm update` falls back cleanly without raising
      fail_cm = os.path.join(tmpdir, "cm_fail")
      with open(fail_cm, "w", encoding="utf-8") as f:
        f.write('#!/bin/sh\necho "network unreachable" >&2\nexit 1\n')
      os.chmod(fail_cm, 0o755)
      with patch.dict(os.environ, {"CODEMENDER_AUTO_UPDATE": "1"}, clear=True):
        res_fail = ensure_cm_updated(fail_cm, cwd=tmpdir)
        self.assertEqual(res_fail, fail_cm)

  def test_parallel_scan_uses_dynamic_default_model(self):
    """Verify Stage 1 _scan_repository records token usage under get_cm_default_model when find_model is unset."""
    from unittest.mock import MagicMock
    from codemender_agent.config import OrchestratorConfig
    from codemender_agent.runners.scan import _scan_repository

    fake_find_res = MagicMock()
    fake_find_res.token_usage = {"in_tokens": 1000, "out_tokens": 200, "total_tokens": 1200}
    fake_report_res = MagicMock()
    fake_report_res.stdout = '[{"FindingID": "f-1", "FilePath": "app.py"}]'

    with patch.dict(os.environ, {"CODEMENDER_MODEL": "", "CODEMENDER_FIND_MODEL": ""}, clear=True):
      cfg = OrchestratorConfig.from_env()
      with patch("codemender_agent.runners.scan.get_cm_default_model", return_value="detected-default-model") as mock_default_model, \
           patch("codemender_agent.runners.scan.run_command", side_effect=[fake_find_res, fake_report_res]):
        findings, token_usage = _scan_repository(
            repo_dir="/tmp/repo",
            scrubbed_env={},
            cm_binary="/usr/local/bin/cm",
            targets=["/tmp/repo"],
            config=cfg,
        )
        mock_default_model.assert_called_once()
        self.assertEqual(len(findings), 1)
        self.assertIn("detected-default-model", token_usage)
        self.assertEqual(token_usage["detected-default-model"]["total_tokens"], 1200)

  def test_parallel_worker_and_aggregate_dynamic_models(self):
    """Verify Stage 2 _process_finding uses get_cm_default_model and Stage 3 HTML banner renders multi-model labels."""
    import tempfile
    from unittest.mock import MagicMock
    from codemender_agent.config import OrchestratorConfig
    from codemender_agent.runners.aggregate import _inject_token_metrics_into_html
    from codemender_agent.runners.worker import _process_finding

    fake_verify_res = MagicMock(returncode=0, stdout="", token_usage={"in_tokens": 300, "out_tokens": 50, "total_tokens": 350})
    fake_fix_res = MagicMock(returncode=0, stdout="", token_usage={"in_tokens": 700, "out_tokens": 150, "total_tokens": 850})
    fake_git_res = MagicMock(returncode=0, stdout="")

    def side_effect(cmd, *_args, **_kwargs):
      if "verify" in cmd:
        return fake_verify_res
      if "fix" in cmd:
        return fake_fix_res
      return fake_git_res

    worker_tokens = {}
    with tempfile.TemporaryDirectory() as tmpdir:
      with patch.dict(os.environ, {"CODEMENDER_SKIP_VERIFY": "false"}, clear=True):
        cfg = OrchestratorConfig.from_env()
        with patch("codemender_agent.runners.worker.get_cm_default_model", return_value="detected-worker-model") as mock_worker_model, \
             patch("codemender_agent.runners.worker.clean_workspace"), \
             patch("codemender_agent.runners.worker.sanitize_exploit_and_artifacts"), \
             patch("codemender_agent.runners.worker.check_remote_branch_exists", return_value=False), \
             patch("codemender_agent.runners.worker.is_duplicate_pr", return_value=False), \
             patch("codemender_agent.runners.worker.is_finding_verified", return_value=True), \
             patch("codemender_agent.runners.worker.get_finding_status", return_value="FIXED"), \
             patch("codemender_agent.runners.worker.run_command", side_effect=side_effect):
          _process_finding(
              finding_id="f-1",
              finding={"FindingID": "f-1", "FilePath": "app.py", "VulnType": "XSS"},
              repo_dir=tmpdir,
              cm_binary="/usr/local/bin/cm",
              scrubbed_env={},
              clean_repo_url="https://github.com/org/repo.git",
              token="fake-token",
              owner="org",
              repo_name="repo",
              default_branch="main",
              working_base_ref="main",
              state_db_path=os.path.join(tmpdir, "nonexistent.db"),
              worker_token_usage=worker_tokens,
              config=cfg,
          )
          mock_worker_model.assert_called_once()
          self.assertIn("detected-worker-model", worker_tokens)
          self.assertEqual(worker_tokens["detected-worker-model"]["total_tokens"], 1200)

      html_path = os.path.join(tmpdir, "report.html")
      with open(html_path, "w", encoding="utf-8") as f:
        f.write("<html><body><h1>CodeMender Security Report</h1></body></html>")
      _inject_token_metrics_into_html(
          html_path,
          {
              "stage-find-model": {"in_tokens": 1000, "out_tokens": 200, "total_tokens": 1200},
              "detected-worker-model": worker_tokens["detected-worker-model"],
          },
      )
      with open(html_path, "r", encoding="utf-8") as f:
        html_content = f.read()
      self.assertIn("(Models: <code>detected-worker-model</code>, <code>stage-find-model</code>)", html_content)


if __name__ == "__main__":
  unittest.main()

