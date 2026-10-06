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

"""Tests for passing configured cm flags through to find, verify and fix."""

import os
import shlex
import tempfile
import unittest
from unittest.mock import patch

from codemender_agent import utils
from codemender_agent.utils import build_cm_command
from codemender_agent.utils import filter_supported_flags
from codemender_agent.utils import parse_help_flags
from codemender_agent.utils import resolve_command_flags

_FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "cm")


def _fixture(name: str) -> str:
  with open(os.path.join(_FIXTURES, name), encoding="utf-8") as f:
    return f.read()


class ParseHelpFlagsTest(unittest.TestCase):

  def test_newer_find_help(self):
    flags = parse_help_flags(_fixture("find_help_0_10_0.txt"))
    self.assertIs(flags["--deep"], False)
    self.assertIs(flags["--deep-workers"], True)
    self.assertIs(flags["--context"], True)
    self.assertIs(flags["-c"], True)
    # Optional-value flag: only the --diff=<ref> form carries a value.
    self.assertIs(flags["--diff"], False)
    self.assertIs(flags["--fail-on-truncation"], False)
    self.assertIs(flags["-y"], False)

  def test_older_find_help_has_no_deep(self):
    flags = parse_help_flags(_fixture("find_help_0_9_0.txt"))
    self.assertNotIn("--deep", flags)
    self.assertNotIn("--deep-workers", flags)
    self.assertIn("--context", flags)

  def test_verify_and_fix_help(self):
    verify = parse_help_flags(_fixture("verify_help_0_10_0.txt"))
    self.assertIs(verify["--no-reset"], False)
    fix = parse_help_flags(_fixture("fix_help_0_9_0.txt"))
    self.assertIs(fix["--no-cache"], False)
    self.assertIs(fix["--export"], True)

  def test_ignores_text_before_flags_section(self):
    self.assertEqual(parse_help_flags("Usage:\n  --deep is great\n"), {})
    self.assertEqual(parse_help_flags(""), {})


class FilterSupportedFlagsTest(unittest.TestCase):

  def setUp(self):
    self.new = parse_help_flags(_fixture("find_help_0_10_0.txt"))
    self.old = parse_help_flags(_fixture("find_help_0_9_0.txt"))

  def test_keeps_supported_flags_and_values(self):
    flags = ["--deep", "--deep-workers", "4", "-c", "focus on auth"]
    self.assertEqual(filter_supported_flags(flags, self.new, "find"), flags)

  def test_equals_form(self):
    flags = ["--deep-workers=4", "--diff=origin/main"]
    self.assertEqual(filter_supported_flags(flags, self.new, "find"), flags)

  def test_older_binary_drops_unknown_flags_with_their_values(self):
    flags = ["--deep", "--deep-workers", "4", "-c", "ctx"]
    with self.assertLogs("codemender-orchestrator", level="WARNING") as logs:
      kept = filter_supported_flags(flags, self.old, "find")
    self.assertEqual(kept, ["-c", "ctx"])
    self.assertTrue(any("--deep-workers" in m for m in logs.output))

  def test_reserved_flags_are_dropped(self):
    flags = ["--model", "other", "--unrestricted", "--deep"]
    self.assertEqual(filter_supported_flags(flags, self.new, "find"), ["--deep"])
    # Also when the installed cm's help is unavailable.
    self.assertEqual(filter_supported_flags(flags, None, "find"), ["--deep"])
    self.assertEqual(
        filter_supported_flags(["--model=other"], None, "find"), []
    )

  def test_unknown_support_passes_through(self):
    flags = ["--deep", "--deep-workers", "4"]
    self.assertEqual(filter_supported_flags(flags, None, "find"), flags)

  def test_stray_positional_is_dropped(self):
    self.assertEqual(
        filter_supported_flags(["--deep", "extra"], self.new, "find"),
        ["--deep"],
    )
    self.assertEqual(filter_supported_flags(["extra"], None, "find"), [])

  def test_empty(self):
    self.assertEqual(filter_supported_flags([], self.new, "find"), [])

  def test_value_starting_with_dash_stays_with_its_flag(self):
    flags = ["-c", "--focus on auth", "--deep-workers", "-1", "--deep"]
    self.assertEqual(filter_supported_flags(flags, self.new, "find"), flags)

  def test_value_flag_without_value_is_dropped(self):
    # Kept bare, cm would take the scan target as the flag's value.
    with self.assertLogs("codemender-orchestrator", level="WARNING"):
      self.assertEqual(
          filter_supported_flags(["--deep", "--deep-workers"], self.new, "find"),
          ["--deep"],
      )

  def test_reserved_value_flag_consumes_dash_value(self):
    self.assertEqual(
        filter_supported_flags(["--model", "-x", "--deep"], self.new, "find"),
        ["--deep"],
    )

  def test_help_is_blocked(self):
    for supported in (self.new, None):
      with self.assertLogs("codemender-orchestrator", level="WARNING"):
        self.assertEqual(
            filter_supported_flags(["--deep", "--help", "-h"], supported, "find"),
            ["--deep"],
        )


class ResolveCommandFlagsTest(unittest.TestCase):

  @patch.dict(os.environ, {}, clear=True)
  def test_unset_and_blank(self):
    self.assertEqual(resolve_command_flags("find"), [])
    with patch.dict(os.environ, {"CODEMENDER_FIND_FLAGS": "   "}):
      self.assertEqual(resolve_command_flags("find"), [])

  @patch.dict(
      os.environ,
      {"CODEMENDER_FIND_FLAGS": "--deep -c 'two words'"},
      clear=True,
  )
  def test_shell_style_split_per_command(self):
    self.assertEqual(
        resolve_command_flags("find"), ["--deep", "-c", "two words"]
    )
    self.assertEqual(resolve_command_flags("verify"), [])

  @patch.dict(os.environ, {"CODEMENDER_FIX_FLAGS": "--no-cache 'open"}, clear=True)
  def test_unparseable_value_is_ignored(self):
    with self.assertLogs("codemender-orchestrator", level="WARNING"):
      self.assertEqual(resolve_command_flags("fix"), [])


class BuildCmCommandFlagsTest(unittest.TestCase):
  """End-to-end through build_cm_command with a fake cm binary."""

  def setUp(self):
    utils._SUPPORTED_FLAGS_CACHE.clear()
    self.addCleanup(utils._SUPPORTED_FLAGS_CACHE.clear)
    self._tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self._tmp.cleanup)

  def _fake_cm(self, version: str) -> str:
    path = os.path.join(self._tmp.name, f"cm_{version}")
    lines = ["#!/bin/sh"]
    for action in ("find", "verify", "fix"):
      help_path = os.path.join(_FIXTURES, f"{action}_help_{version}.txt")
      lines.append(
          f'if [ "$1" = "{action}" ] && [ "$2" = "--help" ]; then'
          f" cat {shlex.quote(help_path)}; exit 0; fi"
      )
    lines.append("exit 1")
    with open(path, "w", encoding="utf-8") as f:
      f.write("\n".join(lines) + "\n")
    os.chmod(path, 0o755)
    return path

  @patch.dict(
      os.environ,
      {
          "CODEMENDER_CLI_VERSION": "preview",
          "CODEMENDER_FIND_FLAGS": "--deep --deep-workers 4",
          "CODEMENDER_FIND_MODEL": "configured-model",
      },
      clear=True,
  )
  def test_find_flags_reach_newer_cm(self):
    cm = self._fake_cm("0_10_0")
    self.assertEqual(
        build_cm_command(cm, "find", "/repo"),
        [cm, "find", "-y", "--model", "configured-model",
         "--deep", "--deep-workers", "4", "/repo"],
    )

  @patch.dict(
      os.environ,
      {
          "CODEMENDER_CLI_VERSION": "preview",
          "CODEMENDER_FIND_FLAGS": "--deep --deep-workers 4",
      },
      clear=True,
  )
  def test_find_flags_dropped_on_older_cm(self):
    cm = self._fake_cm("0_9_0")
    with self.assertLogs("codemender-orchestrator", level="WARNING"):
      self.assertEqual(
          build_cm_command(cm, "find", "/repo"), [cm, "find", "-y", "/repo"]
      )

  @patch.dict(
      os.environ,
      {
          "CODEMENDER_CLI_VERSION": "preview",
          "CODEMENDER_SANDBOX_ENABLED": "false",
          "CODEMENDER_VERIFY_FLAGS": "--no-reset",
          "CODEMENDER_FIX_FLAGS": "--no-cache",
      },
      clear=True,
  )
  def test_verify_and_fix_flags(self):
    cm = self._fake_cm("0_9_0")
    self.assertEqual(
        build_cm_command(cm, "verify", "id-1"),
        [cm, "verify", "-y", "--bypass-warning", "--unrestricted",
         "--no-reset", "id-1"],
    )
    self.assertEqual(
        build_cm_command(cm, "fix", "id-1"),
        [cm, "fix", "-y", "--bypass-warning", "--unrestricted",
         "--no-cache", "id-1"],
    )

  @patch.dict(os.environ, {"CODEMENDER_CLI_VERSION": "preview"}, clear=True)
  def test_explicit_extra_flags_for_find(self):
    cm = self._fake_cm("0_10_0")
    self.assertEqual(
        build_cm_command(cm, "find", "/repo", extra_flags=["--deep"]),
        [cm, "find", "-y", "--deep", "/repo"],
    )

  @patch.dict(os.environ, {"CODEMENDER_CLI_VERSION": "preview"}, clear=True)
  def test_no_flags_means_no_help_lookup(self):
    with patch.object(utils.subprocess, "run") as run:
      self.assertEqual(
          build_cm_command("cm", "find", "."), ["cm", "find", "-y", "."]
      )
      run.assert_not_called()

  @patch.dict(
      os.environ,
      {"CODEMENDER_CLI_VERSION": "preview", "CODEMENDER_FIND_FLAGS": "--deep"},
      clear=True,
  )
  def test_missing_binary_passes_flags_through(self):
    missing = os.path.join(self._tmp.name, "does-not-exist")
    with self.assertLogs("codemender-orchestrator", level="WARNING"):
      self.assertEqual(
          build_cm_command(missing, "find", "."),
          [missing, "find", "-y", "--deep", "."],
      )

  @patch.dict(
      os.environ,
      {"CODEMENDER_CLI_VERSION": "preview", "CODEMENDER_FIND_FLAGS": "--deep"},
      clear=True,
  )
  def test_help_is_read_once_per_binary_and_action(self):
    cm = self._fake_cm("0_10_0")
    real_run = utils.subprocess.run
    with patch.object(utils.subprocess, "run", side_effect=real_run) as run:
      build_cm_command(cm, "find", ".")
      build_cm_command(cm, "find", ".")
      self.assertEqual(run.call_count, 1)

  @patch.dict(
      os.environ,
      {"CODEMENDER_CLI_VERSION": "preview", "CODEMENDER_FIND_FLAGS": "--deep"},
      clear=True,
  )
  def test_other_actions_ignore_command_flags(self):
    self.assertEqual(
        build_cm_command("cm", "report", extra_flags=["--format", "json"]),
        ["cm", "report", "--format", "json"],
    )
    self.assertEqual(build_cm_command("cm", "init"), ["cm", "init"])

  @patch.dict(
      os.environ,
      {"CODEMENDER_CLI_VERSION": "legacy", "CODEMENDER_FIND_FLAGS": "--deep"},
      clear=True,
  )
  def test_legacy_cli_is_unchanged(self):
    self.assertEqual(build_cm_command("cm", "find", "."), ["cm", "find", "."])


if __name__ == "__main__":
  unittest.main()
