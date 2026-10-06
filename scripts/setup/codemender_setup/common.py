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

"""Shared plumbing: exit codes, process runner, prompts and the report."""

import argparse
import dataclasses
import getpass
import os
import pathlib
import re
import shutil
import subprocess
import sys
from typing import Callable, Dict, List, Mapping, Optional, Sequence, TextIO, Tuple

EXIT_OK = 0
EXIT_FAILED = 1  # a check failed, or a command could not finish
EXIT_USAGE = 2  # bad arguments, or input needed in non-interactive mode
EXIT_CANCELLED = 3  # the user said no

# Same rule as terraform/bootstrap and terraform/gcp: at most 17 characters,
# so the longest derived service account ID (<prefix>-image-build) fits in 30.
PREFIX_RE = re.compile(r"^[a-z]([a-z0-9-]{0,15}[a-z0-9])?$")
PROJECT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
MIN_TERRAFORM = (1, 11, 0)
MIN_PYTHON = (3, 9)

# Environment that would change what a local terraform run sees. TF_VAR_* and
# TF_CLI_ARGS* can inject values the pipeline would not have.
_TF_ENV_PREFIXES = ("TF_VAR_", "TF_CLI_ARGS")
_TF_ENV_NAMES = ("TF_WORKSPACE", "TF_DATA_DIR", "TF_CLI_CONFIG_FILE")
_GOOGLE_CRED_NAMES = (
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_CREDENTIALS",
    "GOOGLE_CLOUD_KEYFILE_JSON",
    "GCLOUD_KEYFILE_JSON",
    "GOOGLE_OAUTH_ACCESS_TOKEN",
    "GOOGLE_IMPERSONATE_SERVICE_ACCOUNT",
)


class UsageError(Exception):
  """Bad arguments, or a value is needed but there is no one to ask."""


class Cancelled(Exception):
  """The user declined a confirmation."""


@dataclasses.dataclass
class Result:
  returncode: int
  stdout: str = ""
  stderr: str = ""

  @property
  def ok(self) -> bool:
    return self.returncode == 0


Runner = Callable[..., Result]


def run_process(
    args: Sequence[str],
    *,
    input_text: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
    cwd: Optional[os.PathLike] = None,
    timeout: Optional[float] = 600,
) -> Result:
  """Runs a command and captures its output. A missing binary returns 127."""
  try:
    proc = subprocess.run(
        list(args),
        input=input_text,
        env=dict(env) if env is not None else None,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
  except FileNotFoundError:
    return Result(127, "", f"{args[0]}: command not found")
  except subprocess.TimeoutExpired:
    return Result(124, "", f"{args[0]}: timed out after {timeout} seconds")
  return Result(proc.returncode, proc.stdout or "", proc.stderr or "")


def version_tuple(text: str) -> Tuple[int, ...]:
  """'1.11.2' or 'v1.11.2-beta' -> (1, 11, 2). Unparseable -> ()."""
  m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", text or "")
  if not m:
    return ()
  return tuple(int(g) for g in m.groups(default="0"))


def tf_env(base: Optional[Mapping[str, str]] = None, *, offline: bool = False) -> Dict[str, str]:
  """Environment for terraform without TF_VAR_*, TF_CLI_ARGS* and friends.

  With offline=True, Google credential variables are removed too and
  GOOGLE_APPLICATION_CREDENTIALS points at a missing file, so nothing can
  reach a real project.
  """
  env = dict(os.environ if base is None else base)
  for name in list(env):
    if name.startswith(_TF_ENV_PREFIXES) or name in _TF_ENV_NAMES:
      del env[name]
    elif offline and (name in _GOOGLE_CRED_NAMES or name.startswith("CLOUDSDK_AUTH_")):
      del env[name]
  env["TF_IN_AUTOMATION"] = "1"
  env["TF_INPUT"] = "0"
  env["CHECKPOINT_DISABLE"] = "1"
  if offline:
    env["GOOGLE_APPLICATION_CREDENTIALS"] = "/nonexistent/codemender-setup"
  return env


def add_common_flags(parser, in_subcommand: bool) -> None:
  """Adds --repo-root, --yes, --non-interactive and --dry-run to a parser.

  The flags work before or after the command. In subcommand parsers they
  default to SUPPRESS so they do not overwrite a value given earlier.
  """
  extra = {"default": argparse.SUPPRESS} if in_subcommand else {}
  parser.add_argument("--repo-root", metavar="DIR",
                      help="root of your copy of this repository (default: found from the current directory)",
                      **extra)
  parser.add_argument("--yes", "-y", action="store_true",
                      help="answer yes to every confirmation", **extra)
  parser.add_argument("--non-interactive", action="store_true",
                      help="never prompt; fail if a value is missing", **extra)
  parser.add_argument("--dry-run", action="store_true",
                      help="show what would change without changing anything", **extra)


def find_repo_root(start: Optional[pathlib.Path] = None) -> Optional[pathlib.Path]:
  """The nearest directory at or above start that holds terraform/gcp/config.tf."""
  here = (start or pathlib.Path.cwd()).resolve()
  for d in (here, *here.parents):
    if (d / "terraform" / "gcp" / "config.tf").is_file():
      return d
  return None


_REMOTE_RES = (
    re.compile(r"^https://(?P<host>[^/@]+)/(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$"),
    re.compile(r"^(?:ssh://)?git@(?P<host>[^/:]+)[:/](?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$"),
)


def parse_github_remote(url: str) -> Optional[Tuple[str, str, str]]:
  """Returns (host, owner, repo) for an https or ssh Git remote URL."""
  url = (url or "").strip()
  for pattern in _REMOTE_RES:
    m = pattern.match(url)
    if m:
      return m.group("host").lower(), m.group("owner"), m.group("repo")
  return None


@dataclasses.dataclass
class Context:
  """What every command gets: the repository, flags, I/O and a runner."""

  repo_root: pathlib.Path
  yes: bool = False
  non_interactive: bool = False
  dry_run: bool = False
  out: TextIO = sys.stdout
  err: TextIO = sys.stderr
  stdin: TextIO = sys.stdin
  run: Runner = run_process
  which: Callable[[str], Optional[str]] = shutil.which
  environ: Mapping[str, str] = dataclasses.field(default_factory=lambda: dict(os.environ))
  # Reads a value without echoing it (getpass). Replaced in tests.
  secret_prompt: Callable[[str], str] = getpass.getpass

  def say(self, text: str = "") -> None:
    print(text, file=self.out)

  def warn(self, text: str) -> None:
    print(text, file=self.err)

  def ask(self, prompt: str, default: Optional[str] = None,
          check: Optional[Callable[[str], Optional[str]]] = None,
          flag: str = "") -> str:
    """Asks for a value. check returns an error message or None."""
    if self.non_interactive:
      if default is not None and (check is None or check(default) is None):
        return default
      hint = f" (pass {flag})" if flag else ""
      raise UsageError(f"{prompt}: no value given{hint}")
    while True:
      suffix = f" [{default}]" if default else ""
      self.out.write(f"{prompt}{suffix}: ")
      self.out.flush()
      line = self.stdin.readline()
      if not line:
        raise Cancelled(prompt)
      value = line.strip() or (default or "")
      problem = check(value) if check else (None if value else "a value is required")
      if problem is None:
        return value
      self.say(f"  {problem}")

  def read_secret(self, prompt: str, source: Optional[str] = None, flag: str = "") -> str:
    """Reads a secret value without echoing it.

    source is a file path, "-" for standard input, or None to prompt. The
    value is stripped of surrounding whitespace and never printed.
    """
    if source == "-":
      value = self.stdin.read()
    elif source:
      try:
        value = pathlib.Path(source).expanduser().read_text(encoding="utf-8")
      except OSError as e:
        raise UsageError(f"{flag or 'file'}: cannot read {source}: {e.strerror}") from None
    elif self.non_interactive:
      hint = f" (pass {flag} FILE, or {flag} - for standard input)" if flag else ""
      raise UsageError(f"{prompt}: no value given{hint}")
    else:
      try:
        value = self.secret_prompt(f"{prompt} (input hidden): ")
      except EOFError:
        raise Cancelled(prompt) from None
    value = value.strip()
    if not value:
      raise UsageError(f"{prompt}: the value is empty")
    return value

  def confirm(self, prompt: str, default: bool = False) -> bool:
    if self.yes:
      return True
    if self.non_interactive:
      return default
    self.out.write(f"{prompt} [{'Y/n' if default else 'y/N'}]: ")
    self.out.flush()
    line = self.stdin.readline()
    if not line:
      return False
    answer = line.strip().lower()
    if not answer:
      return default
    return answer in ("y", "yes")


# Report ---------------------------------------------------------------------

OK = "OK"
WARN = "WARN"
FAIL = "FAIL"
SKIP = "SKIP"
INFO = "INFO"


@dataclasses.dataclass
class Finding:
  status: str
  title: str
  detail: str = ""
  hint: str = ""


@dataclasses.dataclass
class Report:
  """Collects findings and prints them as they come."""

  ctx: Context
  findings: List[Finding] = dataclasses.field(default_factory=list)

  def add(self, status: str, title: str, detail: str = "", hint: str = "") -> Finding:
    finding = Finding(status, title, detail, hint)
    self.findings.append(finding)
    line = f"[{status:<4}] {title}"
    if detail:
      line += f": {detail}"
    self.ctx.say(line)
    if hint:
      for hint_line in hint.splitlines():
        self.ctx.say(f"       {hint_line}")
    return finding

  def section(self, title: str) -> None:
    self.ctx.say("")
    self.ctx.say(f"== {title}")

  def count(self, status: str) -> int:
    return sum(1 for f in self.findings if f.status == status)

  def summary(self) -> int:
    fails, warns = self.count(FAIL), self.count(WARN)
    self.ctx.say("")
    self.ctx.say(f"{fails} failed, {warns} warning(s), {self.count(OK)} passed.")
    return EXIT_FAILED if fails else EXIT_OK
