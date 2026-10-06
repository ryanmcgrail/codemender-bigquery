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

"""Tests for deep-scan output parsing and CI-gate exits of `cm find`."""

import os
import unittest
from unittest.mock import MagicMock
from unittest.mock import patch

from codemender_agent.codemender.cli import is_ci_gate_exit
from codemender_agent.codemender.cli import parse_deep_scan_summary
from codemender_agent.config import OrchestratorConfig
from codemender_agent.runners.scan import _scan_repository
from codemender_agent.utils import run_command

# Output shapes printed by `cm find --deep`.
DEEP_NORMAL = """\
🔍 Deep Scan Sifter: 80 total files discovered
   Tier 0 Pruner: 2 safe files pruned (tests, docs, DTOs, generated, lockfiles) at 0 token cost
   Tier 1 Sifter: 78 candidate files in 40 batches to scan with 4 workers
2026/09/26 10:00:01 [INFO]  ✅ Completed 12 tool steps in 41s | Tokens: 41k in / 2.5k out / 43.5k total
[1/40 batches] 🚨 src/SQLI.java (41.0s) | 43.5k tok - 2 vulnerabilities
2026/09/26 10:00:09 [INFO]  ✅ Completed 3 tool steps in 8s | Tokens: 9k in / 500 out / 9.5k total
[2/40 batches] ❌ src/Big.java (8.0s): rpc error: code = Internal
────────────────────────────────────────────────────────────
📊 Deep Scan Sifter Complete: 80 files in 40 batches (2 pruned at Tier 0, 39 succeeded, 1 failed) in 12m31s
   Total tokens consumed: 43.5k
"""

DEEP_ALL_PRUNED = """\
🔍 Deep Scan Sifter: 3 total files discovered
   Tier 0 Pruner: 3 safe files pruned (tests, docs, DTOs, generated, lockfiles) at 0 token cost
────────────────────────────────────────────────────────────
📊 Deep Scan Sifter Complete: 3/3 files examined (3 pruned at Tier 0) in 0s
   No candidate source files required LLM evaluation.
"""

STANDARD = """\
2026/09/26 10:00:01 [INFO]  ✅ Completed 30 tool steps in 5m2s | Tokens: 1.2M in / 20k out / 1.2M total
Found 9 vulnerabilities.
"""


class ParseDeepScanSummaryTest(unittest.TestCase):

  def test_normal_summary(self):
    self.assertEqual(
        parse_deep_scan_summary(DEEP_NORMAL),
        {
            "files": 80,
            "batches": 40,
            "pruned": 2,
            "succeeded": 39,
            "failed": 1,
            "elapsed": "12m31s",
            "total_tokens": 43500,
        },
    )

  def test_all_pruned_summary(self):
    self.assertEqual(
        parse_deep_scan_summary(DEEP_ALL_PRUNED),
        {
            "files": 3,
            "batches": 0,
            "pruned": 3,
            "succeeded": 0,
            "failed": 0,
            "elapsed": "0s",
        },
    )

  def test_standard_scan_has_no_summary(self):
    self.assertIsNone(parse_deep_scan_summary(STANDARD))
    self.assertIsNone(parse_deep_scan_summary(""))
    self.assertIsNone(parse_deep_scan_summary(None))


class CiGateExitTest(unittest.TestCase):

  def test_blocking_findings_gate(self):
    out = "\n🚨 CI Gate Failure: 3 blocking finding(s) match --fail-on=CRITICAL,HIGH\n"
    self.assertTrue(is_ci_gate_exit(1, out))

  def test_other_failures_are_not_gate_exits(self):
    out = "\n🚨 CI Gate Failure: 3 blocking finding(s) match --fail-on=HIGH\n"
    self.assertFalse(is_ci_gate_exit(0, out))
    self.assertFalse(is_ci_gate_exit(2, out))
    self.assertFalse(is_ci_gate_exit(1, "rpc error: code = Internal"))
    truncated = (
        "🚨 CI Gate Failure: Impact expansion truncated (40 files identified,"
        " capped at 10).\n"
    )
    self.assertFalse(is_ci_gate_exit(1, truncated))

  def test_blocking_findings_with_truncation_is_not_success(self):
    # cm prints both gate messages when both conditions hold.
    out = (
        "\n🚨 CI Gate Failure: 2 blocking finding(s) match --fail-on=HIGH\n"
        "\n🚨 CI Gate Failure: Impact expansion truncated (40 files identified,"
        " capped at 10).\n"
    )
    self.assertFalse(is_ci_gate_exit(1, out))


class RunCommandTokenTest(unittest.TestCase):
  """Token accounting from real subprocess output."""

  def _run(self, text):
    with patch.dict(os.environ, {"CODEMENDER_CLI_VERSION": "preview"}):
      return run_command(["printf", "%s", text], check=False).token_usage

  def test_deep_sums_session_lines_without_adding_the_total(self):
    self.assertEqual(
        self._run(DEEP_NORMAL),
        {"in_tokens": 50000, "out_tokens": 3000, "total_tokens": 53000},
    )

  def test_total_line_used_when_no_session_lines(self):
    text = (
        "📊 Deep Scan Sifter Complete: 4 files in 2 batches (0 pruned at"
        " Tier 0, 2 succeeded, 0 failed) in 1m\n   Total tokens consumed: 1.5M\n"
    )
    self.assertEqual(
        self._run(text),
        {"in_tokens": 0, "out_tokens": 0, "total_tokens": 1500000},
    )

  def test_no_token_output(self):
    self.assertEqual(
        self._run("nothing here\n"),
        {"in_tokens": 0, "out_tokens": 0, "total_tokens": 0},
    )


class ScanRepositoryTest(unittest.TestCase):

  def _scan(self, find_res, deep_summaries=None):
    report = MagicMock(returncode=0, stdout='[{"FindingID": "f-1"}]')
    with patch.dict(os.environ, {"CODEMENDER_FIND_MODEL": "m"}, clear=True):
      cfg = OrchestratorConfig.from_env()
      with patch(
          "codemender_agent.runners.scan.run_command",
          side_effect=[find_res, report],
      ):
        return _scan_repository(
            repo_dir="/tmp/repo",
            scrubbed_env={},
            cm_binary="/bin/cm",
            targets=["/tmp/repo"],
            config=cfg,
            deep_summaries=deep_summaries,
        )

  def test_deep_summary_is_collected(self):
    res = MagicMock(returncode=0, stdout=DEEP_NORMAL, token_usage=None)
    summaries = []
    findings, _ = self._scan(res, summaries)
    self.assertEqual(len(findings), 1)
    self.assertEqual(len(summaries), 1)
    self.assertEqual(summaries[0]["target"], "/tmp/repo")
    self.assertEqual(summaries[0]["attempt"], 1)
    self.assertEqual(summaries[0]["failed"], 1)

  def test_ci_gate_exit_is_not_logged_as_find_error(self):
    res = MagicMock(
        returncode=1,
        stdout="🚨 CI Gate Failure: 1 blocking finding(s) match --fail-on=HIGH\n",
        token_usage=None,
    )
    with self.assertLogs("codemender-orchestrator", level="INFO") as logs:
      findings, _ = self._scan(res)
    self.assertEqual(len(findings), 1)
    self.assertTrue(any("CI gate" in m for m in logs.output))
    self.assertFalse(any("non-zero exit code" in m for m in logs.output))

  def test_real_failure_is_still_logged(self):
    res = MagicMock(returncode=1, stdout="rpc error", token_usage=None)
    with self.assertLogs("codemender-orchestrator", level="WARNING") as logs:
      self._scan(res)
    self.assertTrue(any("non-zero exit code" in m for m in logs.output))

  def test_non_string_stdout_is_tolerated(self):
    res = MagicMock(returncode=0, token_usage=None)  # stdout is a MagicMock
    summaries = []
    findings, _ = self._scan(res, summaries)
    self.assertEqual(len(findings), 1)
    self.assertEqual(summaries, [])


if __name__ == "__main__":
  unittest.main()
