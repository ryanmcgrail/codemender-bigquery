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

"""Shared fixtures for the scripts/setup (codemender-setup) tests."""

import io
import pathlib
import shutil
import sys
import tempfile
from typing import Callable, Dict, List, Optional

ROOT = pathlib.Path(__file__).resolve().parents[1]
SETUP_DIR = ROOT / "scripts" / "setup"
if str(SETUP_DIR) not in sys.path:
  sys.path.insert(0, str(SETUP_DIR))

from codemender_setup import common  # pylint: disable=g-import-not-at-top,wrong-import-position


class FakeRunner:
  """Records commands and answers them from a list of (matcher, Result)."""

  def __init__(self) -> None:
    self.calls: List[Dict] = []
    self.rules: List = []

  def on(self, prefix: List[str], result: common.Result) -> "FakeRunner":
    self.rules.append((prefix, result))
    return self

  def __call__(self, args, *, input_text=None, env=None, cwd=None, timeout=None) -> common.Result:
    args = [str(a) for a in args]
    self.calls.append({"args": args, "env": env, "cwd": cwd, "input": input_text})
    base = [pathlib.Path(args[0]).name] + args[1:]
    for prefix, result in self.rules:
      if callable(prefix):
        if prefix(base, cwd):
          return result(base, cwd) if callable(result) else result
      elif base[: len(prefix)] == prefix:
        return result(base, cwd) if callable(result) else result
    return common.Result(1, "", "unexpected command: " + " ".join(base))

  def commands(self) -> List[List[str]]:
    return [[pathlib.Path(c["args"][0]).name] + c["args"][1:] for c in self.calls]


def make_repo(tmp: pathlib.Path) -> pathlib.Path:
  """A minimal copy of the repository layout the helper needs."""
  root = tmp / "repo"
  (root / "terraform" / "gcp").mkdir(parents=True)
  for name in ("config.tf", "variables.tf", "deployment.example.yaml", "repos.example.yaml"):
    src = ROOT / "terraform" / "gcp" / name
    if src.exists():
      shutil.copy2(src, root / "terraform" / "gcp" / name)
  (root / "terraform" / "bootstrap").mkdir(parents=True)
  return root


def make_context(root: pathlib.Path, runner: Optional[FakeRunner] = None,
                 tools: Optional[Dict[str, str]] = None, environ: Optional[Dict[str, str]] = None,
                 stdin: str = "", **flags) -> common.Context:
  tools = {"gcloud": "/usr/bin/gcloud", "terraform": "/usr/bin/terraform", "git": "/usr/bin/git",
           "gh": "/usr/bin/gh"} if tools is None else tools
  return common.Context(
      repo_root=root,
      out=io.StringIO(),
      err=io.StringIO(),
      stdin=io.StringIO(stdin),
      run=runner or FakeRunner(),
      which=tools.get,
      environ=environ if environ is not None else {"PATH": "/usr/bin"},
      **flags,
  )


class TempDirMixin:
  """unittest mixin: self.tmp is a fresh directory per test."""

  def setUp(self) -> None:  # pylint: disable=invalid-name
    super().setUp()
    self._tmp = tempfile.TemporaryDirectory()
    self.tmp = pathlib.Path(self._tmp.name)

  def tearDown(self) -> None:  # pylint: disable=invalid-name
    self._tmp.cleanup()
    super().tearDown()


def ok(stdout: str = "") -> common.Result:
  return common.Result(0, stdout, "")


def fail(stderr: str = "error", code: int = 1) -> common.Result:
  return common.Result(code, "", stderr)


Matcher = Callable[[List[str], Optional[str]], bool]
