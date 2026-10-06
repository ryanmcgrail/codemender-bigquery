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

"""`init`, `add-repo`, `remove-repo` and `set`: edit the deployment files.

These commands write terraform/gcp/deployment.yaml and repos.yaml, which you
commit, and terraform/bootstrap/terraform.tfvars, which stays local. Edits keep
your comments and layout: they add, replace or remove only the lines they
own. With --pr, the committed files go to a new branch and a pull request.
"""

import datetime
import difflib
import pathlib
import re
from typing import Dict, List, Optional, Sequence, Tuple

from codemender_setup import common
from codemender_setup import validate
from codemender_setup import yamlio

REPO_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
APPROVER_RE = re.compile(r"^(user|group|serviceAccount|domain):\S+$")
DATASET_RE = re.compile(r"^[A-Za-z0-9_]{1,1024}$")
REGION_RE = re.compile(r"^[a-z]+-[a-z]+[0-9]+$")
CRON_RE = re.compile(r"^\S+(\s+\S+){4}$")
CONNECTION_REPO_RE = re.compile(
    r"^projects/[^/]+/locations/[^/]+/connections/[^/]+/repositories/[^/]+$")

DEPLOYMENT = pathlib.Path("terraform", "gcp", "deployment.yaml")
REPOS = pathlib.Path("terraform", "gcp", "repos.yaml")
BOOTSTRAP_TFVARS = pathlib.Path("terraform", "bootstrap", "terraform.tfvars")


# Shared helpers ---------------------------------------------------------------


def add_pr_argument(parser) -> None:
  parser.add_argument("--pr", action="store_true",
                      help="commit the change on a new branch, push it to origin and open a pull request")
  parser.add_argument("--skip-validate", action="store_true",
                      help="do not run `validate` after the change")


def image_build_account(prefix: str, project: str) -> str:
  """The image build service account terraform/bootstrap creates."""
  return f"{prefix}-image-build@{project}.iam.gserviceaccount.com"


def _check(pattern: "re.Pattern", message: str):
  return lambda v: None if pattern.match(v) else message


def check_prefix(value: str) -> Optional[str]:
  if common.PREFIX_RE.match(value):
    return None
  return ("1-17 characters: lowercase letters, digits and hyphens, starting with a letter "
          "and not ending with a hyphen")


def check_project(value: str) -> Optional[str]:
  return None if common.PROJECT_ID_RE.match(value) else "not a valid project ID"


def check_repo_url(value: str) -> Optional[str]:
  errors, warnings = validate.lint_repos(
      "repositories:\n  x:\n    repo_url: " + yamlio.scalar(value) + "\n")
  problems = errors + warnings
  return problems[0].split(": ", 1)[-1] if problems else None


def show_change(ctx: common.Context, path: pathlib.Path, old: str, new: str) -> None:
  rel = path.relative_to(ctx.repo_root) if path.is_absolute() else path
  diff = difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                              fromfile=f"a/{rel}", tofile=f"b/{rel}")
  text = "".join(diff)
  ctx.say(text.rstrip() if text else f"{rel}: no change")


def write_files(ctx: common.Context, changes: Dict[pathlib.Path, str]) -> List[pathlib.Path]:
  """Shows and (unless --dry-run) writes each changed file. Returns those changed."""
  changed = []
  for rel, new in changes.items():
    path = ctx.repo_root / rel
    old = path.read_text(encoding="utf-8") if path.exists() else ""
    if old == new:
      ctx.say(f"{rel}: no change")
      continue
    show_change(ctx, rel, old, new)
    changed.append(rel)
    if not ctx.dry_run:
      path.parent.mkdir(parents=True, exist_ok=True)
      path.write_text(new, encoding="utf-8")
  return changed


def after_change(ctx: common.Context, args, changed: List[pathlib.Path], title: str, body: str) -> int:
  """Validates and optionally opens a pull request for committed files."""
  if ctx.dry_run:
    ctx.say("\n--dry-run: nothing was written.")
    return common.EXIT_OK
  if not changed:
    return common.EXIT_OK
  code = common.EXIT_OK
  if not getattr(args, "skip_validate", False):
    ctx.say("\nValidating ...")

    class _Args:
      repos = None
      deployment = None
      skip_terraform = False

    code = validate.run(ctx, _Args())
    if code != common.EXIT_OK:
      ctx.say("Fix the problems above before you commit these files.")
      return code
  committed = [p for p in changed if p != BOOTSTRAP_TFVARS]
  if getattr(args, "pr", False) and committed:
    return open_pull_request(ctx, committed, title, body)
  if committed:
    uncommitted = _uncommitted_configs(ctx)
    if len(uncommitted) > 1:
      # First setup: rerunning this command with --pr would ship the files
      # early and take them out of the working tree (see open_pull_request).
      ctx.say("\nNext: commit " + " and ".join(p.as_posix() for p in uncommitted) +
              " together in one pull request, or add --pr to your last edit (typically add-repo);"
              " while either file is not committed, --pr puts both in the pull request.")
    elif uncommitted:
      ctx.say(f"\nNext: commit {uncommitted[0].as_posix()} in a pull request, or add --pr to your last edit"
              " (typically add-repo).")
    else:
      # Not "rerun with --pr": a rerun finds no change and opens nothing.
      ctx.say("\nNext: commit " + " and ".join(p.as_posix() for p in committed) +
              " in a pull request. Next time, add --pr to the command to have it open one.")
  return code


# Pull requests ----------------------------------------------------------------


def _git(ctx: common.Context, *args: str, check: bool = True) -> common.Result:
  git = ctx.which("git")
  if not git:
    raise common.UsageError("git not found")
  res = ctx.run([git, "-C", str(ctx.repo_root), *args], timeout=300)
  if check and not res.ok:
    raise RuntimeError(f"git {' '.join(args)} failed: {res.stderr.strip() or res.stdout.strip()}")
  return res


def _tracked(ctx: common.Context, path: pathlib.Path) -> bool:
  return _git(ctx, "cat-file", "-e", f"HEAD:{path.as_posix()}", check=False).ok


def _uncommitted_configs(ctx: common.Context) -> List[pathlib.Path]:
  """deployment.yaml/repos.yaml files that exist but are not committed at HEAD."""
  if not ctx.which("git"):
    return []
  return [p for p in (DEPLOYMENT, REPOS) if (ctx.repo_root / p).exists() and not _tracked(ctx, p)]


def open_pull_request(ctx: common.Context, files: Sequence[pathlib.Path], title: str, body: str) -> int:
  """Commits `files` on a new branch, pushes to origin and opens a PR.

  deployment.yaml and repos.yaml are deployed together, so one of them that
  is not committed yet (the first setup) goes into the pull request too.

  The current branch and any other local changes are left as they were;
  afterwards the files are back to their committed state on the current
  branch, and the change lives on the new branch until the pull request is
  merged. Files that were not committed before leave the working tree until
  the merge is pulled.
  """
  try:
    start = _git(ctx, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    if start == "HEAD":
      raise common.UsageError("--pr needs a checked-out branch, not a detached HEAD")
    staged = _git(ctx, "diff", "--cached", "--name-only").stdout.strip()
    if staged:
      raise common.UsageError("--pr needs an empty index; commit or unstage your staged changes first")
    files = list(files)
    for config in (DEPLOYMENT, REPOS):
      if config not in files and (ctx.repo_root / config).exists() and not _tracked(ctx, config):
        ctx.say(f"{config} is not committed yet; it goes into the pull request too.")
        files.append(config)
        body = f"{body}\n\nAlso adds {config.as_posix()}, which was not committed yet.".lstrip()
    new_files = [p for p in files if not _tracked(ctx, p)]
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower())[:40].strip("-")
    branch = f"codemender-setup/{slug}-{stamp}"
    paths = [p.as_posix() for p in files]
    _git(ctx, "switch", "-c", branch)
    try:
      _git(ctx, "add", "--", *paths)
      _git(ctx, "commit", "-m", f"{title}\n\n{body}", "--", *paths)
      push = _git(ctx, "push", "-u", "origin", branch, check=False)
      if not push.ok:
        ctx.say(f"git push failed: {push.stderr.strip()}")
        ctx.say(f"The commit is on local branch {branch}. Push it and open a pull request yourself.")
        return common.EXIT_FAILED
    finally:
      _git(ctx, "switch", start, check=False)
  except RuntimeError as e:
    ctx.say(str(e))
    return common.EXIT_FAILED

  if new_files:
    ctx.say(", ".join(p.as_posix() for p in new_files) + f" now exist only on {branch}. Commands that read "
            f"them fail until the pull request is merged and you `git pull` on {start}.")
  gh = ctx.which("gh")
  if gh:
    res = ctx.run([gh, "pr", "create", "--head", branch, "--base", start, "--title", title,
                   "--body", body], cwd=ctx.repo_root, timeout=300)
    if res.ok:
      ctx.say(f"Opened {res.stdout.strip().splitlines()[-1] if res.stdout.strip() else 'a pull request'}")
      ctx.say(f"You are back on {start}; the change is on {branch} until it is merged.")
      return common.EXIT_OK
    ctx.say(f"gh pr create failed: {res.stderr.strip()}")
  ctx.say(f"Pushed {branch}. Open a pull request from it into {start}.")
  return common.EXIT_OK


# deployment.yaml ----------------------------------------------------------------


DEPLOYMENT_DEFAULTS = {"region": "us-central1", "resource_prefix": "codemender"}


def read_deployment(ctx: common.Context, project: Optional[str] = None) -> Dict[str, str]:
  """Top-level scalar settings of deployment.yaml, with terraform/gcp's defaults.

  project overrides project_id. Raises UsageError without a project ID.
  """
  path = ctx.repo_root / DEPLOYMENT
  if not path.exists():
    raise common.UsageError("terraform/gcp/deployment.yaml does not exist; run `init` first")
  values = dict(DEPLOYMENT_DEFAULTS)
  values.update({k: v for k, v in yamlio.top_level_scalars(path.read_text(encoding="utf-8")).items() if v})
  if project:
    values["project_id"] = project
  if not values.get("project_id"):
    raise common.UsageError("deployment.yaml has no project_id; set it or pass --project")
  if check_project(values["project_id"]):
    raise common.UsageError(f"project_id {values['project_id']!r}: {check_project(values['project_id'])}")
  return values


def _config_key_lists(repo_root: pathlib.Path) -> Dict[str, List[str]]:
  """Reads the typed key lists from terraform/gcp/config.tf."""
  text = (repo_root / "terraform" / "gcp" / "config.tf").read_text(encoding="utf-8")
  out: Dict[str, List[str]] = {}
  for kind in ("string", "bool", "number", "list"):
    m = re.search(rf"deployment_{kind}_keys\s*=\s*\[(.*?)\]", text, re.S)
    out[kind] = re.findall(r'"([a-z0-9_]+)"', m.group(1)) if m else []
  return out


def typed_value(repo_root: pathlib.Path, key: str, raw: str):
  """Converts a command-line value to the type config.tf expects for key."""
  lists = _config_key_lists(repo_root)
  if key in lists["bool"]:
    if raw.lower() in ("true", "false"):
      return raw.lower() == "true"
    raise common.UsageError(f"{key} must be true or false")
  if key in lists["number"]:
    if re.match(r"^-?[0-9]+$", raw):
      return int(raw)
    raise common.UsageError(f"{key} must be a whole number")
  if key in lists["list"]:
    return [v.strip() for v in raw.split(",") if v.strip()]
  if key in lists["string"]:
    return raw
  known = sorted(sum(lists.values(), []))
  raise common.UsageError(f"unknown deployment.yaml key {key!r}; known keys: {', '.join(known)}")


def _format_setting(key: str, value) -> List[str]:
  if isinstance(value, list):
    return [f"{key}:"] + [f"  - {yamlio.scalar(v)}" for v in value]
  return [f"{key}: {yamlio.scalar(value)}"]


def set_top_level(text: str, key: str, value) -> str:
  """Sets a top-level key, replacing its lines (and nested lines) if present."""
  lines = text.splitlines()
  new_lines = _format_setting(key, value)
  start = None
  for entry in yamlio.scan(text):
    if not entry.path and entry.key == key:
      start = entry.line - 1
  if start is None:
    if lines and lines[-1].strip():
      return "\n".join(lines + new_lines) + "\n"
    return "\n".join(lines + new_lines).lstrip("\n") + "\n"
  end = start + 1
  while end < len(lines) and (not lines[end].strip() or lines[end].startswith((" ", "\t", "-"))):
    if not lines[end].strip():
      # A blank line ends the setting unless more nested lines follow.
      nxt = next((l for l in lines[end:] if l.strip()), "")
      if not nxt.startswith((" ", "\t", "-")):
        break
    end += 1
  # Keep a trailing comment on a replaced scalar line.
  original = lines[start]
  trailing = original[len(yamlio.strip_comment(original)):]
  if not isinstance(value, list) and trailing.strip().startswith("#"):
    new_lines[0] += trailing
  return "\n".join(lines[:start] + new_lines + lines[end:]) + "\n"


def render_deployment(project: str, region: str, prefix: str, dataset: Optional[str]) -> str:
  lines = [
      "# Non-secret deployment settings, read by terraform/gcp (config.tf).",
      "# Written by scripts/setup/codemender-setup init. deployment.example.yaml",
      "# lists every setting; change values with `codemender-setup set KEY VALUE`",
      "# or by hand, in a pull request.",
      "",
      f"project_id: {yamlio.scalar(project)}",
      f"region: {yamlio.scalar(region)}",
      "# Prefix for every resource name. Changing it replaces the whole deployment.",
      f"resource_prefix: {yamlio.scalar(prefix)}",
      "",
      "# Keep true until the first runner image has been rolled out",
      "# (codemender-setup doctor tells you when).",
      "scheduler_paused: true",
      "",
      "# The image build service account that terraform/bootstrap creates.",
      "cloudbuild_service_account_emails:",
      f"  - {yamlio.scalar(image_build_account(prefix, project))}",
  ]
  if dataset:
    lines += ["", "# BigQuery dataset for scan telemetry.",
              f"bigquery_dataset_id: {yamlio.scalar(dataset)}"]
  return "\n".join(lines) + "\n"


REPOS_HEADER = """\
# Repositories to scan, read by terraform/gcp (config.tf). repos.example.yaml
# lists every key. Add entries with `codemender-setup add-repo` or by hand, in a
# pull request. build_command runs in the scan jobs: review changes to this
# file like code.
repositories:
"""


def render_bootstrap_tfvars(project: str, region: str, prefix: str, branch: str,
                            approvers: Sequence[str], cloudbuild_repository: str) -> str:
  approver_list = ", ".join(yamlio.hcl_string(a) for a in approvers)
  return "\n".join([
      "# terraform/bootstrap settings. Written by codemender-setup init; not committed",
      "# (*.tfvars is in .gitignore). See terraform.tfvars.example and variables.tf.",
      "",
      f"project_id      = {yamlio.hcl_string(project)}",
      f"region          = {yamlio.hcl_string(region)}",
      f"resource_prefix = {yamlio.hcl_string(prefix)}",
      f"branch          = {yamlio.hcl_string(branch)}",
      "",
      "# Who may approve the destroy trigger (and gated builds).",
      f"approvers = [{approver_list}]",
      "",
      "# The repository as linked to the Cloud Build connection; `codemender-setup",
      "# connect` fills this in.",
      f"cloudbuild_repository = {yamlio.hcl_string(cloudbuild_repository)}",
      "",
  ])


def set_tfvar(text: str, name: str, hcl_value: str) -> str:
  """Replaces `name = ...` (single line) in a tfvars file, or appends it."""
  pattern = re.compile(rf"^(\s*{re.escape(name)}\s*=\s*).*$", re.M)
  if pattern.search(text):
    return pattern.sub(lambda m: m.group(1) + hcl_value, text, count=1)
  sep = "" if text.endswith("\n") or not text else "\n"
  return f"{text}{sep}{name} = {hcl_value}\n"


def read_tfvar(text: str, name: str) -> Optional[str]:
  m = re.search(rf'^\s*{re.escape(name)}\s*=\s*"((?:[^"\\]|\\.)*)"\s*$', text, re.M)
  return m.group(1) if m else None


# init -------------------------------------------------------------------------------


def add_init_arguments(parser) -> None:
  parser.add_argument("--project", help="Google Cloud project ID for the deployment")
  parser.add_argument("--region", help="region for the deployment and triggers (default: us-central1)")
  parser.add_argument("--prefix", help="resource_prefix, 1-17 characters (default: codemender)")
  parser.add_argument("--bigquery-dataset", metavar="ID",
                      help="BigQuery dataset for telemetry (default: codemender_telemetry)")
  parser.add_argument("--branch", help="deployed branch (default: main)")
  parser.add_argument("--approver", action="append", default=[], metavar="MEMBER",
                      help="IAM member who may approve the destroy trigger, e.g. group:admins@example.com "
                           "(repeatable; at least one is required)")
  parser.add_argument("--force", action="store_true", help="overwrite existing files")
  add_pr_argument(parser)


def run_init(ctx: common.Context, args) -> int:
  existing = [p for p in (DEPLOYMENT, REPOS, BOOTSTRAP_TFVARS) if (ctx.repo_root / p).exists()]
  if existing and not args.force:
    ctx.say("Already present: " + ", ".join(str(p) for p in existing))
    ctx.say("Use `set`, `add-repo` and `remove-repo` to change them, or --force to start over.")
    return common.EXIT_FAILED

  project = args.project or ctx.ask("Google Cloud project ID", check=check_project, flag="--project")
  if check_project(project):
    raise common.UsageError(f"--project {project!r}: {check_project(project)}")
  region = args.region or ctx.ask("Region", default="us-central1",
                                  check=_check(REGION_RE, "not a region name"), flag="--region")
  prefix = args.prefix or ctx.ask("Resource prefix", default="codemender", check=check_prefix, flag="--prefix")
  if check_prefix(prefix):
    raise common.UsageError(f"--prefix {prefix!r}: {check_prefix(prefix)}")
  dataset = args.bigquery_dataset
  if dataset is None and not ctx.non_interactive:
    dataset = ctx.ask("BigQuery dataset (empty for codemender_telemetry)", default="",
                      check=lambda v: None if not v or DATASET_RE.match(v) else "letters, digits and _ only")
  if dataset and not DATASET_RE.match(dataset):
    raise common.UsageError(f"--bigquery-dataset {dataset!r}: letters, digits and _ only")
  branch = args.branch or ctx.ask("Deployed branch", default="main", flag="--branch")
  approvers = list(args.approver)
  if not approvers:
    value = ctx.ask("Destroy-trigger approver (IAM member, e.g. group:admins@example.com)",
                    check=_check(APPROVER_RE, "must look like user:..., group:... or domain:..."),
                    flag="--approver")
    approvers = [value]
  bad = [a for a in approvers if not APPROVER_RE.match(a)]
  if bad:
    raise common.UsageError(f"--approver {bad[0]!r}: must look like user:..., group:... or domain:...")

  old_tfvars = ""
  if (ctx.repo_root / BOOTSTRAP_TFVARS).exists():
    old_tfvars = (ctx.repo_root / BOOTSTRAP_TFVARS).read_text(encoding="utf-8")
  connection_repo = read_tfvar(old_tfvars, "cloudbuild_repository") or ""
  changes = {
      DEPLOYMENT: render_deployment(project, region, prefix, dataset or None),
      REPOS: REPOS_HEADER,
      BOOTSTRAP_TFVARS: render_bootstrap_tfvars(project, region, prefix, branch, approvers, connection_repo),
  }
  changed = write_files(ctx, changes)
  if not ctx.dry_run:
    ctx.say("\nterraform/bootstrap/terraform.tfvars stays local (it is in .gitignore).")
    ctx.say("Next: `codemender-setup connect` to link this repository to Cloud Build.")
  return after_change(ctx, args, changed, "Configure the CodeMender deployment",
                      f"Initial deployment.yaml and repos.yaml for project {project}, prefix {prefix}.")


# repos.yaml ----------------------------------------------------------------------


def repo_entries(text: str) -> Dict[str, int]:
  """Repository name -> 1-based line of its key."""
  return {e.key: e.line for e in yamlio.scan(text) if e.path == ("repositories",)}


def _indent_of(line: str) -> int:
  return len(line) - len(line.lstrip(" "))


def _entry_indents(text: str) -> Tuple[int, int]:
  """(entry indent, extra indent of an entry's settings), following the file."""
  lines = text.splitlines()
  entries = [e for e in yamlio.scan(text) if e.path == ("repositories",)]
  if not entries:
    return 2, 2
  entry = _indent_of(lines[entries[0].line - 1])
  for e in yamlio.scan(text):
    if e.path == ("repositories", entries[0].key):
      child = _indent_of(lines[e.line - 1]) - entry
      if child > 0:
        return entry, child
      break
  return entry, 2


def add_repo_text(text: str, name: str, settings: List[Tuple[str, object]]) -> str:
  if not text.strip():
    text = REPOS_HEADER
  lines = text.splitlines()
  if not any(e.key == "repositories" and not e.path for e in yamlio.scan(text)):
    raise common.UsageError("repos.yaml has no top-level `repositories:` key")
  if re.search(r"^repositories:\s*\{\s*\}\s*(#.*)?$", text, re.M):
    lines = [re.sub(r"^repositories:\s*\{\s*\}", "repositories:", l) for l in lines]
  entry, child = _entry_indents(text)
  indent, inner = " " * entry, " " * (entry + child)
  block = [f"{indent}{name}:"] + [f"{inner}{k}: {yamlio.scalar(v)}" for k, v in settings]
  # Insert after the last indented line under `repositories:` (before the next
  # top-level key), so blank lines and column-0 comments that follow the block
  # stay after it.
  root_line = next(e.line for e in yamlio.scan(text) if e.key == "repositories" and not e.path)
  stop = len(lines)
  for i in range(root_line, len(lines)):
    l = lines[i]
    if l.strip() and not l.startswith((" ", "\t", "#")):
      stop = i
      break
  end = root_line
  for i in range(root_line, stop):
    if lines[i].strip() and lines[i].startswith((" ", "\t")):
      end = i + 1
  return "\n".join(lines[:end] + block + lines[end:]).rstrip("\n") + "\n"


def remove_repo_text(text: str, name: str) -> str:
  entries = repo_entries(text)
  if name not in entries:
    raise common.UsageError(f"repos.yaml has no repository named {name!r}")
  lines = text.splitlines()
  start = entries[name] - 1
  indent = len(lines[start]) - len(lines[start].lstrip(" "))
  end = start + 1
  while end < len(lines):
    l = lines[end]
    if l.strip() and (len(l) - len(l.lstrip(" "))) <= indent:
      break
    end += 1
  # Keep trailing blank lines and comments that belong to the next entry.
  while end > start + 1 and (not lines[end - 1].strip() or lines[end - 1].lstrip().startswith("#")):
    end -= 1
  return "\n".join(lines[:start] + lines[end:]) + "\n"


def add_repo_arguments(parser) -> None:
  parser.add_argument("name", help="entry name in repos.yaml (letters, digits, - and _)")
  parser.add_argument("--url", required=True, help="https://github.com/<owner>/<repo>.git")
  parser.add_argument("--schedule", help="cron schedule (default: scheduler_cron in deployment.yaml)")
  parser.add_argument("--branch", dest="target_branch", help="branch to scan (default: the repository's default)")
  parser.add_argument("--scan-target", help="directory or directories to scan")
  parser.add_argument("--build-command", help="build and test command for fix verification (runs in the scan jobs)")
  parser.add_argument("--scan-dry-run", action="store_true",
                      help="scan without opening pull requests or writing to GitHub (dry_run: true)")
  add_pr_argument(parser)


def run_add_repo(ctx: common.Context, args) -> int:
  if not REPO_NAME_RE.match(args.name):
    raise common.UsageError(f"{args.name!r}: use letters, digits, - and _ only")
  problem = check_repo_url(args.url)
  if problem:
    raise common.UsageError(f"--url: {problem}")
  if args.schedule and not CRON_RE.match(args.schedule.strip()):
    raise common.UsageError("--schedule must have five fields, e.g. \"0 3 * * 6\"")
  path = ctx.repo_root / REPOS
  text = path.read_text(encoding="utf-8") if path.exists() else REPOS_HEADER
  if args.name in repo_entries(text):
    raise common.UsageError(f"repos.yaml already has {args.name!r}")
  settings: List[Tuple[str, object]] = [("repo_url", args.url)]
  for key in ("schedule", "target_branch", "scan_target", "build_command"):
    value = getattr(args, key)
    if value:
      settings.append((key, value))
  if args.scan_dry_run:
    settings.append(("dry_run", True))
  changed = write_files(ctx, {REPOS: add_repo_text(text, args.name, settings)})
  if not ctx.dry_run:
    ctx.say("Make sure the GitHub App is installed on that repository (or that the token can access it).")
  return after_change(ctx, args, changed, f"Scan {args.name} with CodeMender",
                      f"Adds {args.url} to repos.yaml.")


def remove_repo_arguments(parser) -> None:
  parser.add_argument("name", help="entry name in repos.yaml")
  add_pr_argument(parser)


def run_remove_repo(ctx: common.Context, args) -> int:
  path = ctx.repo_root / REPOS
  if not path.exists():
    raise common.UsageError("terraform/gcp/repos.yaml does not exist")
  text = path.read_text(encoding="utf-8")
  new = remove_repo_text(text, args.name)
  if not ctx.confirm(f"Remove {args.name} from repos.yaml (its scheduler job is deleted after the merge)?",
                     default=True):
    raise common.Cancelled("remove-repo")
  changed = write_files(ctx, {REPOS: new})
  return after_change(ctx, args, changed, f"Stop scanning {args.name} with CodeMender",
                      f"Removes {args.name} from repos.yaml.")


# set --------------------------------------------------------------------------------


def set_arguments(parser) -> None:
  parser.add_argument("key", help="deployment.yaml key, e.g. scheduler_paused")
  parser.add_argument("value", help="new value; lists are comma-separated")
  add_pr_argument(parser)


def run_set(ctx: common.Context, args) -> int:
  value = typed_value(ctx.repo_root, args.key, args.value)
  if args.key == "resource_prefix" and check_prefix(str(value)):
    raise common.UsageError(f"resource_prefix: {check_prefix(str(value))}")
  path = ctx.repo_root / DEPLOYMENT
  if not path.exists():
    raise common.UsageError("terraform/gcp/deployment.yaml does not exist; run `init` first")
  if args.key in ("resource_prefix", "project_id", "region") and not ctx.confirm(
      f"Changing {args.key} replaces resources of the deployment. Continue?"):
    raise common.Cancelled("set")
  text = path.read_text(encoding="utf-8")
  changed = write_files(ctx, {DEPLOYMENT: set_top_level(text, args.key, value)})
  return after_change(ctx, args, changed, f"Set {args.key} in deployment.yaml",
                      f"Sets {args.key} to {yamlio.scalar(value) if not isinstance(value, list) else value}.")
