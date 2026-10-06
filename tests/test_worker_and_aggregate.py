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

"""Unit tests for Phase 3: Stage 2 Worker Verification/Fix & Stage 3 Aggregator."""

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from codemender_agent.runners.aggregate import aggregate_and_update_security_gate
from codemender_agent.runners.worker import verify_and_fix_worker_shard


class TestWorkerAndAggregateGate(unittest.TestCase):
  """Tests for Stage 2 worker verify/fix/inline review and Stage 3 SARIF/auto-unblock."""

  def setUp(self) -> None:
    self.temp_dir = tempfile.TemporaryDirectory()
    self.workspace = Path(self.temp_dir.name) / "workspace"
    self.home_dir = Path(self.temp_dir.name) / "home"
    self.workspace.mkdir(parents=True, exist_ok=True)
    (self.home_dir / ".codemender").mkdir(parents=True, exist_ok=True)
    (self.workspace / ".codemender_transit" / "base").mkdir(
        parents=True, exist_ok=True
    )

  def tearDown(self) -> None:
    self.temp_dir.cleanup()

  def _write_partition(self, idx: int, items: list[dict]) -> None:
    base_dir = self.workspace / ".codemender_transit" / "base"
    (base_dir / f"partition_{idx}.json").write_text(
        json.dumps(items), encoding="utf-8"
    )
    (base_dir / "active_findings.json").write_text(
        json.dumps(items), encoding="utf-8"
    )

  @patch("codemender_agent.vcs.github.post_idempotent_inline_review")
  @patch("codemender_agent.vcs.github.update_finding_in_sticky_comment")
  @patch("subprocess.run")
  def test_01_worker_verify_fix_and_inline_review(
      self,
      mock_run: MagicMock,
      mock_sticky: MagicMock,
      mock_inline: MagicMock,
  ) -> None:
    items = [
        {
            "finding_id": "11112222-aaaa",
            "file_path": "src/app.py",
            "line_number": 10,
            "severity": "HIGH",
            "title": "Command Injection",
            "description": "Unsafe os.system",
        }
    ]
    self._write_partition(0, items)
    mock_inline.return_value = "https://github.com/org/repo/pull/1#pullrequestreview-10"

    def side_effect(cmd, **_kwargs):
      if cmd[:2] == ["cm", "verify"]:
        return subprocess.CompletedProcess(cmd, 0, stdout="CONFIRMED\n", stderr="")
      if cmd[:2] == ["cm", "fix"]:
        return subprocess.CompletedProcess(cmd, 0, stdout="Fixed\n", stderr="")
      if cmd[:2] == ["git", "diff"]:
        return subprocess.CompletedProcess(
            cmd, 0, stdout="@@ -10,1 +10,1 @@\n-os.system(x)\n+subprocess.run(['echo', x])\n", stderr=""
        )
      return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    mock_run.side_effect = side_effect
    results = verify_and_fix_worker_shard(
        workspace_dir=str(self.workspace),
        worker_index=0,
        token="ghs_token",
        owner="org",
        repo="repo",
        pr_number=1,
        target_sha="abcdef12",
    )
    self.assertEqual(results[0]["verified_status"], "CONFIRMED")
    self.assertIn("subprocess.run", results[0]["patch_diff"])
    self.assertTrue(mock_inline.called)
    self.assertEqual(mock_sticky.call_count, 3)

  @patch("codemender_agent.runners.aggregate.post_or_update_sticky_comment")
  @patch("codemender_agent.runners.aggregate.post_commit_status")
  @patch("codemender_agent.vcs.github.update_finding_in_sticky_comment")
  @patch("subprocess.run")
  def test_02_false_positive_dismissal_auto_unblocks_stage3_and_filters_sarif(
      self,
      mock_run: MagicMock,
      _mock_worker_sticky: MagicMock,
      mock_status: MagicMock,
      mock_agg_sticky: MagicMock,
  ) -> None:
    items = [
        {
            "finding_id": "4d395fe6-f3eb",
            "file_path": "src/fp.py",
            "line_number": 35,
            "severity": "HIGH",
            "title": "SQLi",
            "description": "Guarded by allowlist",
        }
    ]
    self._write_partition(0, items)
    raw_sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "SQLI",
                        "message": {"text": "Finding 4d395fe6-f3eb"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/fp.py"},
                                    "region": {"startLine": 35},
                                }
                            }
                        ],
                    }
                ]
            }
        ],
    }

    def side_effect(cmd, **_kwargs):
      if cmd[:2] == ["cm", "verify"]:
        return subprocess.CompletedProcess(
            cmd, 0, stdout="Verdict: FALSE_POSITIVE\n", stderr=""
        )
      if cmd[:2] == ["cm", "fix"]:
        raise AssertionError("cm fix must not run on DISMISSED_FALSE_POSITIVE")
      if cmd[:2] == ["cm", "report"] and "sarif" in cmd:
        return subprocess.CompletedProcess(
            cmd, 0, stdout=json.dumps(raw_sarif), stderr=""
        )
      return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    mock_run.side_effect = side_effect
    verify_and_fix_worker_shard(workspace_dir=str(self.workspace), worker_index=0)
    rc = aggregate_and_update_security_gate(
        workspace_dir=str(self.workspace),
        min_sev="MEDIUM",
        fail_on_findings=True,
        token="ghs_token",
        owner="org",
        repo="repo",
        pr_number=1,
        target_sha="abcdef12",
    )
    self.assertEqual(rc, 0)
    self.assertEqual(mock_status.call_args.kwargs["state"], "success")
    self.assertIn(
        "1 false positive(s) dismissed",
        mock_status.call_args.kwargs["description"],
    )
    self.assertIn(
        "✅ **PASSED (Auto-Unblocked)**",
        mock_agg_sticky.call_args.kwargs["body"],
    )
    sarif_doc = json.loads(
        (self.workspace / "report.sarif").read_text(encoding="utf-8")
    )
    self.assertEqual(len(sarif_doc["runs"][0]["results"]), 0)

  @patch("codemender_agent.runners.aggregate.post_or_update_sticky_comment")
  @patch("codemender_agent.runners.aggregate.post_commit_status")
  @patch("subprocess.run")
  def test_03_fail_closed_on_unverified_output_or_missing_worker_shard(
      self,
      mock_run: MagicMock,
      mock_status: MagicMock,
      _mock_agg_sticky: MagicMock,
  ) -> None:
    items = [
        {
            "finding_id": "77778888",
            "file_path": "src/eval.py",
            "line_number": 1,
            "severity": "HIGH",
            "title": "Eval",
            "description": "RCE",
        }
    ]
    self._write_partition(0, items)

    def side_effect(cmd, **_kwargs):
      if cmd[:2] == ["cm", "verify"]:
        return subprocess.CompletedProcess(
            cmd, 0, stdout="Result: UNVERIFIED (timeout)\n", stderr=""
        )
      return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    mock_run.side_effect = side_effect
    res = verify_and_fix_worker_shard(
        workspace_dir=str(self.workspace), worker_index=0
    )
    self.assertEqual(res[0]["verified_status"], "CONFIRMED")

    # Delete worker shard to simulate worker crash; Stage 3 must still fail closed via active_findings.json
    shard_file = (
        self.workspace
        / ".codemender_transit"
        / "shards"
        / "worker_0"
        / "results_worker_0.json"
    )
    shard_file.unlink()
    with self.assertRaises(SystemExit) as ctx:
      aggregate_and_update_security_gate(
          workspace_dir=str(self.workspace),
          min_sev="MEDIUM",
          fail_on_findings=True,
          token="ghs_token",
          owner="org",
          repo="repo",
          pr_number=1,
          target_sha="abcdef12",
      )
    self.assertEqual(ctx.exception.code, 1)
    self.assertEqual(mock_status.call_args.kwargs["state"], "failure")

  @patch("os.path.expanduser")
  @patch("subprocess.run")
  def test_04_sandbox_violation_unrestricted_retry_and_sqlite_patch_fallback(
      self, mock_run: MagicMock, mock_expanduser: MagicMock
  ) -> None:
    mock_expanduser.side_effect = lambda p: str(self.home_dir) + p[1:] if p.startswith("~") else p
    db_path = self.home_dir / ".codemender" / "state.db"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE patches (finding_id TEXT, diff TEXT)")
    conn.execute(
        "INSERT INTO patches VALUES (?, ?)",
        ("sbx-999", "@@ -1,1 +1,1 @@\n-bad()\n+good()\n"),
    )
    conn.commit()
    conn.close()

    items = [
        {
            "finding_id": "sbx-999",
            "file_path": "src/sbx.py",
            "line_number": 1,
            "severity": "HIGH",
            "title": "Sandbox Retry Test",
            "description": "Test",
        }
    ]
    self._write_partition(0, items)
    cmds_called = []

    def side_effect(cmd, **_kwargs):
      cmds_called.append(cmd)
      if cmd[:2] == ["cm", "verify"] and "--unrestricted" not in cmd:
        return subprocess.CompletedProcess(
            cmd, 1, stdout="Error: failed to create sandbox box: EPERM\n", stderr=""
        )
      if cmd[:2] == ["cm", "fix"] and "--unrestricted" not in cmd:
        return subprocess.CompletedProcess(
            cmd, 1, stdout="Error: failed to create sandbox box: EPERM\n", stderr=""
        )
      if cmd[:2] == ["git", "diff"]:
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
      return subprocess.CompletedProcess(cmd, 0, stdout="CONFIRMED\n", stderr="")

    mock_run.side_effect = side_effect
    res = verify_and_fix_worker_shard(
        workspace_dir=str(self.workspace),
        worker_index=0,
        allow_unsandboxed_fallback=True,
    )
    self.assertTrue(
        any(c[:2] == ["cm", "verify"] and "--unrestricted" in c for c in cmds_called)
    )
    self.assertTrue(
        any(c[:2] == ["cm", "fix"] and "--unrestricted" in c for c in cmds_called)
    )
    self.assertIn("+good()", res[0]["patch_diff"])
    self.assertEqual(res[0]["verified_status"], "CONFIRMED")
    self.assertTrue(res[0]["sandbox_unrestricted_rerun"])

  @patch("codemender_agent.vcs.github.post_idempotent_inline_review")
  @patch("codemender_agent.vcs.github.update_finding_in_sticky_comment")
  @patch("subprocess.run")
  def test_04b_sandbox_violations_never_trigger_unrestricted_rerun(
      self,
      mock_run: MagicMock,
      mock_sticky: MagicMock,
      mock_inline: MagicMock,
  ) -> None:
    """Blocked accesses are the sandbox working; the session result is used as is."""
    self._write_partition(
        0,
        [{
            "finding_id": "viol-123",
            "file_path": "src/v.py",
            "line_number": 1,
            "severity": "HIGH",
            "title": "T",
            "description": "D",
        }],
    )
    mock_inline.return_value = ""
    cmds_called = []

    def side_effect(cmd, **_kwargs):
      cmds_called.append(list(cmd))
      if cmd[:2] in (["cm", "verify"], ["cm", "fix"]):
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout="sandbox: denied /tmp/x\nSandbox violations detected\nDone\n",
            stderr="",
        )
      return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    mock_run.side_effect = side_effect
    # Even with the opt-in set, violations alone do not cause a rerun.
    res = verify_and_fix_worker_shard(
        workspace_dir=str(self.workspace),
        worker_index=0,
        allow_unsandboxed_fallback=True,
    )
    self.assertFalse(any("--unrestricted" in c for c in cmds_called))
    self.assertEqual(
        len([c for c in cmds_called if c[:2] == ["cm", "verify"]]), 1
    )
    self.assertEqual(res[0]["verified_status"], "CONFIRMED")
    self.assertNotIn("sandbox_unrestricted_rerun", res[0])
    self.assertNotIn(
        "without the sandbox", mock_sticky.call_args.kwargs["status_cell_md"]
    )

  @patch("codemender_agent.vcs.github.post_idempotent_inline_review")
  @patch("codemender_agent.vcs.github.update_finding_in_sticky_comment")
  @patch("subprocess.run")
  def test_04c_failed_verify_is_never_reported_as_confirmed(
      self,
      mock_run: MagicMock,
      mock_sticky: MagicMock,
      mock_inline: MagicMock,
  ) -> None:
    items = [{
        "finding_id": "fail-123",
        "file_path": "src/f.py",
        "line_number": 1,
        "severity": "HIGH",
        "title": "T",
        "description": "D",
    }]
    mock_inline.return_value = ""

    # Case A: cm verify exits non-zero (session failed): VERIFY_FAILED, fix still runs.
    self._write_partition(0, items)
    cmds_a = []

    def side_effect_a(cmd, **_kwargs):
      cmds_a.append(list(cmd))
      if cmd[:2] == ["cm", "verify"]:
        return subprocess.CompletedProcess(
            cmd, 1, stdout="Error: session failed: model error\n", stderr=""
        )
      if cmd[:2] == ["git", "diff"]:
        return subprocess.CompletedProcess(
            cmd, 0, stdout="@@ -1,1 +1,1 @@\n-a\n+b\n", stderr=""
        )
      return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    mock_run.side_effect = side_effect_a
    res = verify_and_fix_worker_shard(
        workspace_dir=str(self.workspace), worker_index=0
    )
    self.assertEqual(res[0]["verified_status"], "VERIFY_FAILED")
    self.assertTrue(any(c[:2] == ["cm", "fix"] for c in cmds_a))
    self.assertFalse(any("--unrestricted" in c for c in cmds_a))
    self.assertIn("Unverified", mock_sticky.call_args.kwargs["status_cell_md"])

    # Case B: sandbox cannot start and fallback not allowed: VERIFY_FAILED, no fix.
    shard = (
        self.workspace / ".codemender_transit" / "shards" / "worker_0"
        / "results_worker_0.json"
    )
    shard.unlink()
    self._write_partition(0, items)
    cmds_b = []

    def side_effect_b(cmd, **_kwargs):
      cmds_b.append(list(cmd))
      if cmd[:2] == ["cm", "verify"]:
        return subprocess.CompletedProcess(
            cmd,
            1,
            stdout="Error: failed to start worker in sandbox: EPERM\n",
            stderr="",
        )
      return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    mock_run.side_effect = side_effect_b
    res = verify_and_fix_worker_shard(
        workspace_dir=str(self.workspace), worker_index=0
    )
    self.assertEqual(res[0]["verified_status"], "VERIFY_FAILED")
    self.assertEqual(res[0]["verify_failure_reason"], "sandbox_unavailable")
    self.assertEqual(res[0]["patch_diff"], "")
    self.assertFalse(any(c[:2] == ["cm", "fix"] for c in cmds_b))
    self.assertFalse(any("--unrestricted" in c for c in cmds_b))
    self.assertIn(
        "sandbox unavailable", mock_sticky.call_args.kwargs["status_cell_md"]
    )

  @patch("codemender_agent.runners.aggregate.post_or_update_sticky_comment")
  @patch("codemender_agent.runners.aggregate.post_commit_status")
  @patch("codemender_agent.vcs.github.update_finding_in_sticky_comment")
  @patch("subprocess.run")
  def test_04d_unverified_finding_still_blocks_and_is_labelled(
      self,
      mock_run: MagicMock,
      _mock_worker_sticky: MagicMock,
      mock_status: MagicMock,
      mock_agg_sticky: MagicMock,
  ) -> None:
    self._write_partition(
        0,
        [{
            "finding_id": "unv-12345678",
            "file_path": "src/u.py",
            "line_number": 3,
            "severity": "HIGH",
            "title": "Unverified Thing",
            "description": "D",
        }],
    )

    def side_effect(cmd, **_kwargs):
      if cmd[:2] == ["cm", "verify"]:
        return subprocess.CompletedProcess(
            cmd, 1, stdout="Error: session failed\n", stderr=""
        )
      return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    mock_run.side_effect = side_effect
    verify_and_fix_worker_shard(workspace_dir=str(self.workspace), worker_index=0)
    with self.assertRaises(SystemExit) as ctx:
      aggregate_and_update_security_gate(
          workspace_dir=str(self.workspace),
          min_sev="MEDIUM",
          fail_on_findings=True,
          token="ghs_token",
          owner="org",
          repo="repo",
          pr_number=1,
          target_sha="abcdef12",
      )
    self.assertEqual(ctx.exception.code, 1)
    self.assertEqual(mock_status.call_args.kwargs["state"], "failure")
    self.assertIn("1 unverified", mock_status.call_args.kwargs["description"])
    self.assertIn("**Unverified**", mock_agg_sticky.call_args.kwargs["body"])

  @patch("codemender_agent.runners.aggregate.post_or_update_sticky_comment")
  @patch("codemender_agent.runners.aggregate.post_commit_status")
  @patch("codemender_agent.vcs.github.post_idempotent_inline_review")
  @patch("codemender_agent.vcs.github.update_finding_in_sticky_comment")
  @patch("os.path.expanduser")
  @patch("subprocess.run")
  def test_04e_fix_sandbox_unavailable_recovers_no_patch(
      self,
      mock_run: MagicMock,
      mock_expanduser: MagicMock,
      mock_sticky: MagicMock,
      mock_inline: MagicMock,
      _mock_status: MagicMock,
      mock_agg_sticky: MagicMock,
  ) -> None:
    """A `cm fix` that never started posts no patch, even if state.db holds one."""
    mock_expanduser.side_effect = (
        lambda p: str(self.home_dir) + p[1:] if p.startswith("~") else p
    )
    # A patch left behind by another finding's fix session.
    db_path = self.home_dir / ".codemender" / "state.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE patches (diff TEXT)")
    conn.execute("INSERT INTO patches VALUES ('--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b')")
    conn.commit()
    conn.close()
    self._write_partition(
        0,
        [{
            "finding_id": "fixsbx-1234",
            "file_path": "src/f.py",
            "line_number": 2,
            "severity": "HIGH",
            "title": "T",
            "description": "D",
        }],
    )
    cmds = []

    def side_effect(cmd, **_kwargs):
      cmds.append(list(cmd))
      if cmd[:2] == ["cm", "verify"]:
        return subprocess.CompletedProcess(cmd, 0, stdout="CONFIRMED\n", stderr="")
      if cmd[:2] == ["cm", "fix"]:
        return subprocess.CompletedProcess(
            cmd,
            1,
            stdout="",
            stderr="Error: creating dispatcher: failed to create sandbox box: EPERM\n",
        )
      return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    mock_run.side_effect = side_effect
    mock_inline.return_value = ""
    res = verify_and_fix_worker_shard(
        workspace_dir=str(self.workspace), worker_index=0
    )
    self.assertEqual(res[0]["verified_status"], "CONFIRMED")
    self.assertEqual(res[0]["patch_diff"], "")
    self.assertEqual(res[0]["fix_failure_reason"], "sandbox_unavailable")
    self.assertFalse(any("--unrestricted" in c for c in cmds))
    self.assertFalse(any(c[:2] == ["git", "diff"] for c in cmds))
    mock_inline.assert_not_called()
    self.assertIn(
        "sandbox unavailable", mock_sticky.call_args.kwargs["status_cell_md"]
    )

    aggregate_and_update_security_gate(
        workspace_dir=str(self.workspace),
        min_sev="MEDIUM",
        fail_on_findings=False,
        token="ghs_token",
        owner="org",
        repo="repo",
        pr_number=1,
        target_sha="abcdef12",
    )
    self.assertIn(
        "`cm fix` did not run (sandbox unavailable)",
        mock_agg_sticky.call_args.kwargs["body"],
    )

  @patch("codemender_agent.runners.aggregate.post_or_update_sticky_comment")
  @patch("codemender_agent.runners.aggregate.post_commit_status")
  @patch("subprocess.run")
  def test_05_secondary_cm_report_fp_and_tier2_report_patch_and_stage3_details_sections(
      self,
      mock_run: MagicMock,
      _mock_status: MagicMock,
      mock_agg_sticky: MagicMock,
  ) -> None:
    items = [
        {
            "finding_id": "fp-via-report-1",
            "file_path": "src/a.py",
            "line_number": 5,
            "severity": "HIGH",
            "title": "Report FP",
            "description": "Dismissed via cm report",
        },
        {
            "finding_id": "patch-via-report-2",
            "file_path": "src/b.py",
            "line_number": 12,
            "severity": "HIGH",
            "title": "Report Patch",
            "description": "Root cause analysis for b.py",
        },
    ]
    self._write_partition(0, items)

    def side_effect(cmd, **_kwargs):
      if cmd[:2] == ["cm", "verify"]:
        return subprocess.CompletedProcess(cmd, 0, stdout="Done\n", stderr="")
      if cmd[:2] == ["cm", "fix"]:
        return subprocess.CompletedProcess(cmd, 0, stdout="Fixed\n", stderr="")
      if cmd[:2] == ["git", "diff"]:
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
      if cmd[:4] == ["cm", "report", "--format", "json"]:
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout=json.dumps([
                {
                    "finding_id": "fp-via-report-1",
                    "verification_status": "FALSE_POSITIVE",
                },
                {
                    "finding_id": "patch-via-report-2",
                    "verification_status": "CONFIRMED",
                    "suggested_fix": "@@ -12,1 +12,1 @@\n-eval(y)\n+ast.literal_eval(y)\n",
                },
            ]),
            stderr="",
        )
      return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    mock_run.side_effect = side_effect
    res = verify_and_fix_worker_shard(
        workspace_dir=str(self.workspace), worker_index=0
    )
    self.assertEqual(res[0]["verified_status"], "DISMISSED_FALSE_POSITIVE")
    self.assertEqual(res[1]["verified_status"], "CONFIRMED")
    self.assertIn("+ast.literal_eval(y)", res[1]["patch_diff"])

    step_summary = self.workspace / "step_summary.md"
    with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(step_summary)}, clear=False):
      with self.assertRaises(SystemExit):
        aggregate_and_update_security_gate(
            workspace_dir=str(self.workspace),
            min_sev="MEDIUM",
            fail_on_findings=True,
            token="ghs_token",
            owner="org",
            repo="repo",
            pr_number=1,
            target_sha="abcdef12",
        )
    sticky_body = mock_agg_sticky.call_args.kwargs["body"]
    self.assertIn("### 🔧 One-Click Auto-Remediation Guide", sticky_body)
    self.assertIn("View Unified Diff Patch", sticky_body)
    self.assertIn("Vulnerability Descriptions & Root-Cause Analysis", sticky_body)
    self.assertTrue((self.workspace / "report.html").exists())
    self.assertIn("One-Click Auto-Remediation Guide", step_summary.read_text(encoding="utf-8"))

  @patch("codemender_agent.runners.aggregate.post_or_update_sticky_comment")
  @patch("codemender_agent.runners.aggregate.post_commit_status")
  @patch("codemender_agent.vcs.github.update_finding_in_sticky_comment")
  @patch("subprocess.run")
  def test_06_mixed_findings_partial_fp_and_line_scoped_verify_pragma(
      self,
      mock_run: MagicMock,
      _mock_worker_sticky: MagicMock,
      mock_status: MagicMock,
      mock_agg_sticky: MagicMock,
  ) -> None:
    src_file = self.workspace / "src" / "mixed.py"
    src_file.parent.mkdir(parents=True, exist_ok=True)
    # Line 2 is a confirmed HIGH finding; line 25 has a function-scoped # codemender: verify=false-positive pragma
    lines = [
        "import os, sqlite3",
        "def run_cmd(x): os.system(x)",
        *[f"# line {i}" for i in range(3, 24)],
        "def guarded_query(db, q):",
        "    # codemender: verify=false-positive",
        "    db.execute(f'SELECT * FROM t WHERE name = {q}')",
    ]
    src_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    items = [
        {
            "finding_id": "real-1111",
            "file_path": "src/mixed.py",
            "start_line": 2,
            "severity": "HIGH",
            "title": "Command Injection",
        },
        {
            "finding_id": "fp-2222",
            "file_path": "src/mixed.py",
            "start_line": 26,
            "severity": "CRITICAL",
            "title": "Guarded SQLi",
        },
    ]
    self._write_partition(0, items)
    raw_sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "CMD",
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/mixed.py"}, "region": {"startLine": 2}}}],
                    },
                    {
                        "ruleId": "SQLI",
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/mixed.py"}, "region": {"startLine": 26}}}],
                    },
                ]
            }
        ],
    }

    def side_effect(cmd, **_kwargs):
      if cmd[:2] == ["cm", "verify"]:
        return subprocess.CompletedProcess(cmd, 0, stdout="Done\n", stderr="")
      if cmd[:2] == ["cm", "fix"]:
        return subprocess.CompletedProcess(cmd, 0, stdout="Fixed\n", stderr="")
      if cmd[:2] == ["git", "diff"]:
        return subprocess.CompletedProcess(
            cmd, 0, stdout="@@ -2,1 +2,1 @@\n-os.system(x)\n+subprocess.run(['echo', x])\n", stderr=""
        )
      if cmd[:2] == ["cm", "report"] and "sarif" in cmd:
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(raw_sarif), stderr="")
      return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    mock_run.side_effect = side_effect
    res = verify_and_fix_worker_shard(workspace_dir=str(self.workspace), worker_index=0)
    by_id = {r["finding_id"]: r["verified_status"] for r in res}
    self.assertEqual(by_id["real-1111"], "CONFIRMED")
    self.assertEqual(by_id["fp-2222"], "DISMISSED_FALSE_POSITIVE")

    with self.assertRaises(SystemExit):
      aggregate_and_update_security_gate(
          workspace_dir=str(self.workspace),
          min_sev="MEDIUM",
          fail_on_findings=True,
          token="ghs_token",
          owner="org",
          repo="repo",
          pr_number=1,
          target_sha="abcdef12",
      )
    self.assertEqual(mock_status.call_args.kwargs["state"], "failure")
    self.assertIn("1 FP dismissed", mock_status.call_args.kwargs["description"])
    sarif_doc = json.loads((self.workspace / "report.sarif").read_text(encoding="utf-8"))
    self.assertEqual(len(sarif_doc["runs"][0]["results"]), 1)
    self.assertEqual(sarif_doc["runs"][0]["results"][0]["ruleId"], "CMD")

  @patch("subprocess.run")
  @patch("codemender_agent.vcs.github.update_finding_in_sticky_comment")
  def test_07_positional_fid_arguments_and_verify_false_positive_pragma(
      self, mock_sticky: MagicMock, mock_run: MagicMock
  ) -> None:
    src_file = self.workspace / "src" / "guarded.py"
    src_file.parent.mkdir(parents=True, exist_ok=True)
    src_file.write_text(
        "# codemender: verify=FALSE_POSITIVE\ncursor.execute(f'SELECT * FROM t WHERE x = {x}')\n",
        encoding="utf-8",
    )
    shard = {
        "partition_index": 0,
        "finding_ids": ["pos-fid-1111"],
        "findings": [
            {
                "finding_id": "pos-fid-1111",
                "file_path": "src/guarded.py",
                "line_number": 2,
                "severity": "HIGH",
                "title": "Guarded SQL Sink",
                "description": "Dismissed via pragma",
            }
        ],
    }
    base_dir = self.workspace / ".codemender_transit" / "base"
    base_dir.mkdir(parents=True, exist_ok=True)
    (base_dir / "partition_0.json").write_text(json.dumps(shard), encoding="utf-8")

    recorded_cmds = []

    def side_effect(cmd, **kwargs):
      recorded_cmds.append(cmd)
      return subprocess.CompletedProcess(cmd, 0, stdout="Done\n", stderr="")

    mock_run.side_effect = side_effect
    res = verify_and_fix_worker_shard(workspace_dir=str(self.workspace), worker_index=0)
    self.assertEqual(res[0]["verified_status"], "DISMISSED_FALSE_POSITIVE")
    verify_calls = [c for c in recorded_cmds if c[:2] == ["cm", "verify"]]
    self.assertEqual(len(verify_calls), 1)
    self.assertEqual(verify_calls[0][2], "pos-fid-1111")
    self.assertNotIn("--finding-id", verify_calls[0])

  @patch("codemender_agent.runners.aggregate.post_or_update_sticky_comment")
  @patch("codemender_agent.runners.aggregate.post_commit_status")
  @patch("subprocess.run")
  def test_08_advisory_only_finding_passes_stage3_with_patch_guide(
      self,
      mock_run: MagicMock,
      mock_status: MagicMock,
      mock_agg_sticky: MagicMock,
  ) -> None:
    items = [
        {
            "finding_id": "adv-12345678",
            "file_path": "src/low.py",
            "start_line": 7,
            "severity": "LOW",
            "title": "Minor Advisory",
            "description": "Low severity advisory",
            "verified_status": "CONFIRMED",
            "patch_diff": "@@ -7,1 +7,1 @@\n-old()\n+new()\n",
            "review_url": "https://github.com/org/repo/pull/1#pullrequestreview-7",
        }
    ]
    self._write_partition(0, items)
    shard_dir = self.workspace / ".codemender_transit" / "shards" / "worker_0"
    shard_dir.mkdir(parents=True, exist_ok=True)
    (shard_dir / "results_worker_0.json").write_text(json.dumps(items), encoding="utf-8")
    mock_run.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")

    rc = aggregate_and_update_security_gate(
        workspace_dir=str(self.workspace),
        min_sev="MEDIUM",
        fail_on_findings=True,
        token="ghs_token",
        owner="org",
        repo="repo",
        pr_number=1,
        target_sha="abcdef12",
    )
    self.assertEqual(rc, 0)
    self.assertEqual(mock_status.call_args.kwargs["state"], "success")
    self.assertIn("1 advisory finding(s)", mock_status.call_args.kwargs["description"])
    self.assertIn("✅ **PASSED** (`1` advisory finding(s))", mock_agg_sticky.call_args.kwargs["body"])
    self.assertIn("### 🔧 One-Click Auto-Remediation Guide", mock_agg_sticky.call_args.kwargs["body"])

  @patch("codemender_agent.runners.aggregate.post_or_update_sticky_comment")
  @patch("codemender_agent.runners.aggregate.post_commit_status")
  @patch("subprocess.run")
  def test_09_non_blocking_mode_passes_stage3_with_confirmed_findings_and_patches(
      self,
      mock_run: MagicMock,
      mock_status: MagicMock,
      mock_agg_sticky: MagicMock,
  ) -> None:
    """Verifies fail_on_findings=False keeps Stage 3 commit status green while still delivering verified patches."""
    items = [
        {
            "finding_id": "crit-nonblock-1",
            "file_path": "src/vuln.py",
            "start_line": 15,
            "severity": "CRITICAL",
            "title": "Confirmed Command Injection",
            "description": "Arbitrary shell execution",
            "verified_status": "CONFIRMED",
            "patch_diff": "@@ -15,1 +15,1 @@\n-os.system(cmd)\n+subprocess.run(cmd)\n",
            "review_url": "https://github.com/org/repo/pull/5#pullrequestreview-99",
        }
    ]
    self._write_partition(0, items)
    shard_dir = self.workspace / ".codemender_transit" / "shards" / "worker_0"
    shard_dir.mkdir(parents=True, exist_ok=True)
    (shard_dir / "results_worker_0.json").write_text(
        json.dumps(items), encoding="utf-8"
    )
    mock_run.return_value = subprocess.CompletedProcess(
        [], 0, stdout="", stderr=""
    )

    rc = aggregate_and_update_security_gate(
        workspace_dir=str(self.workspace),
        min_sev="MEDIUM",
        fail_on_findings=False,
        token="ghs_token",
        owner="org",
        repo="repo",
        pr_number=5,
        target_sha="abcdef12",
    )
    self.assertEqual(rc, 0)
    self.assertEqual(mock_status.call_args.kwargs["state"], "success")
    self.assertIn(
        "PASSED (Non-Blocking)", mock_status.call_args.kwargs["description"]
    )
    sticky_body = mock_agg_sticky.call_args.kwargs["body"]
    self.assertIn("PASSED (Non-Blocking Mode)", sticky_body)
    self.assertIn("⚠️ **Non-Blocking**", sticky_body)
    self.assertIn("Inline `Commit suggestion`", sticky_body)
    self.assertNotIn("❌ **BLOCKED**", sticky_body)


if __name__ == "__main__":
  unittest.main()
