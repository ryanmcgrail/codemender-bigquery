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

"""`validate`: checks repos.yaml and deployment.yaml without touching a project.

Terraform's own checks in terraform/gcp/config.tf decide whether the files
are valid. They run with `terraform test` against mock providers in a
temporary copy of the module, so no credentials, state or network access to
Google Cloud are needed (only the provider download, unless the plugin cache
has it). A few lints that Terraform cannot do run first.
"""

import pathlib
import re
import shutil
import tempfile
from typing import List, Optional, Tuple

from codemender_setup import common
from codemender_setup import yamlio

_TEST_DIR = "setup_check"

# Terraform's mock providers satisfy every resource, so one plan run
# evaluates all the preconditions in config.tf.
_TEST_FILE = """\
# Written by codemender-setup validate. Plans terraform/gcp with mock
# providers so that config.tf checks repos.yaml and deployment.yaml.
mock_provider "google" {}
mock_provider "google-beta" {}
mock_provider "random" {}

variables {
  # Placeholder for a deployment.yaml without project_id; a value in
  # deployment.yaml wins over this.
  project_id = "setup-check-project"
}

run "config" {
  command = plan
}
"""

_GITHUB_URL_RE = re.compile(r"^https://github\.com/[A-Za-z0-9](?:[A-Za-z0-9-]*)/[A-Za-z0-9._-]+?(?:\.git)?/?$")
_ERROR_RE = re.compile(r"^(?:│\s*)?Error:\s*(.*)$")


def add_arguments(parser) -> None:
  parser.add_argument("--repos", metavar="FILE",
                      help="repos.yaml to check (default: terraform/gcp/repos.yaml)")
  parser.add_argument("--deployment", metavar="FILE",
                      help="deployment.yaml to check (default: terraform/gcp/deployment.yaml)")
  parser.add_argument("--skip-terraform", action="store_true",
                      help="only run the quick lints, not Terraform's checks")


def _default(ctx: common.Context, given: Optional[str], name: str) -> Optional[pathlib.Path]:
  if given:
    return pathlib.Path(given).expanduser().resolve()
  path = ctx.repo_root / "terraform" / "gcp" / name
  return path if path.is_file() else None


def lint_repos(text: str) -> Tuple[List[str], List[str]]:
  """Returns (errors, warnings) for repos.yaml text."""
  errors: List[str] = []
  warnings: List[str] = []
  for dup in yamlio.duplicate_keys(text):
    errors.append(f"duplicate key {dup}; YAML keeps only the last one")
  for entry in yamlio.scan(text):
    where = f"line {entry.line}"
    if entry.path[:1] == ("repositories",) and len(entry.path) == 2 and entry.key == "repo_url":
      url = yamlio.plain_value(entry.raw_value)
      host = re.sub(r"^https?://", "", url).split("/", 1)[0].lower()
      if host.endswith(".ghe.com"):
        errors.append(f"{where}: {url} is on GHE.com, which this deployment does not support")
      elif not _GITHUB_URL_RE.match(url):
        warnings.append(f"{where}: repo_url {url!r} is not of the form https://github.com/<owner>/<repo>.git")
    problem = yamlio.coercion_warning(entry.raw_value)
    if problem:
      warnings.append(f"{where}: {'.'.join(entry.path + (entry.key,))}: {problem}")
  return errors, warnings


def lint_deployment(text: str) -> Tuple[List[str], List[str]]:
  """Returns (errors, warnings) for deployment.yaml text."""
  errors: List[str] = []
  warnings: List[str] = []
  for dup in yamlio.duplicate_keys(text):
    errors.append(f"duplicate key {dup}; YAML keeps only the last one")
  settings = yamlio.top_level_scalars(text)
  prefix = settings.get("resource_prefix")
  if prefix is not None and not common.PREFIX_RE.match(prefix):
    errors.append(
        f"resource_prefix {prefix!r} must be 1-17 characters of lowercase letters, digits and "
        "hyphens, start with a letter and not end with a hyphen")
  project = settings.get("project_id")
  if project in ("your-project-id", ""):
    errors.append("project_id is still the example value")
  for entry in yamlio.scan(text):
    problem = yamlio.coercion_warning(entry.raw_value)
    if problem:
      warnings.append(f"line {entry.line}: {'.'.join(entry.path + (entry.key,))}: {problem}")
  return errors, warnings


def _copy_module(repo_root: pathlib.Path, work: pathlib.Path,
                 repos: Optional[pathlib.Path], deployment: Optional[pathlib.Path]) -> pathlib.Path:
  """Copies terraform/gcp (only *.tf and the lock file) and the workflow."""
  src = repo_root / "terraform" / "gcp"
  dst = work / "terraform" / "gcp"
  dst.mkdir(parents=True)
  for tf in sorted(src.glob("*.tf")):
    # *_override.tf files would change the module under test.
    if not tf.name.endswith("_override.tf") and tf.name != "override.tf":
      shutil.copy2(tf, dst / tf.name)
  lock = src / ".terraform.lock.hcl"
  if lock.is_file():
    shutil.copy2(lock, dst / lock.name)
  workflow = repo_root / "workflows" / "gcp_parallel_workflow.yaml"
  if workflow.is_file():
    (work / "workflows").mkdir()
    shutil.copy2(workflow, work / "workflows" / workflow.name)
  if repos:
    shutil.copy2(repos, dst / "repos.yaml")
  if deployment:
    shutil.copy2(deployment, dst / "deployment.yaml")
  (dst / _TEST_DIR).mkdir()
  (dst / _TEST_DIR / "config.tftest.hcl").write_text(_TEST_FILE, encoding="utf-8")
  return dst


def parse_terraform_errors(output: str) -> List[str]:
  """Extracts the `Error:` blocks of terraform output as readable text."""
  blocks: List[str] = []
  current: Optional[List[str]] = None
  for raw in output.splitlines():
    line = raw.replace("│", "").rstrip()
    if raw.lstrip().startswith("╵"):
      if current is not None:
        blocks.append(_tidy(current))
        current = None
      continue
    m = _ERROR_RE.match(line.strip())
    if m:
      if current is not None:
        blocks.append(_tidy(current))
      current = [m.group(1)]
    elif current is not None:
      current.append(line)
  if current is not None:
    blocks.append(_tidy(current))
  return [b for b in blocks if b]


def _tidy(lines: List[str]) -> str:
  # Drop the source excerpt Terraform prints under "on <file> line N".
  out: List[str] = []
  skipping = False
  for line in lines:
    text = line.strip()
    if text.startswith("on ") and " line " in text:
      skipping = True
      continue
    if skipping and (text.startswith(("├", "│", "─")) or re.match(r"^\d+:", text) or not text):
      continue
    skipping = False
    if text or (out and out[-1]):
      out.append(line.rstrip())
  return "\n".join(out).strip()


def run_terraform(ctx: common.Context, repos: Optional[pathlib.Path],
                  deployment: Optional[pathlib.Path], report: common.Report) -> None:
  terraform = ctx.which("terraform")
  if not terraform:
    report.add(common.FAIL, "Terraform checks", "terraform not found",
               "Install Terraform 1.11 or later; see scripts/setup/README.md.")
    return
  env = common.tf_env(ctx.environ, offline=True)
  with tempfile.TemporaryDirectory(prefix="codemender-setup-") as tmp:
    module = _copy_module(ctx.repo_root, pathlib.Path(tmp), repos, deployment)
    init = ctx.run([terraform, "init", "-backend=false", "-input=false", "-no-color",
                    f"-test-directory={_TEST_DIR}"], env=env, cwd=module)
    if not init.ok:
      errors = parse_terraform_errors(init.stdout + "\n" + init.stderr)
      report.add(common.FAIL, "Terraform checks", "terraform init failed",
                 "\n".join(errors) or (init.stderr.strip() or init.stdout.strip())[-2000:])
      return
    test = ctx.run([terraform, "test", "-no-color", f"-test-directory={_TEST_DIR}"],
                   env=env, cwd=module)
  if test.ok:
    report.add(common.OK, "Terraform checks", "config.tf accepts both files")
    return
  errors = parse_terraform_errors(test.stdout + "\n" + test.stderr)
  if not errors:
    errors = [(test.stdout.strip() + "\n" + test.stderr.strip()).strip()[-2000:]]
  for error in errors:
    title, _, rest = error.partition("\n")
    report.add(common.FAIL, "Terraform", title, rest.strip())


def run(ctx: common.Context, args) -> int:
  report = common.Report(ctx)
  repos = _default(ctx, args.repos, "repos.yaml")
  deployment = _default(ctx, args.deployment, "deployment.yaml")
  for label, path in (("repos.yaml", repos), ("deployment.yaml", deployment)):
    if path is not None and not path.is_file():
      raise common.UsageError(f"{label}: {path} does not exist")

  report.section("Files")
  report.add(common.INFO, "repos.yaml", str(repos) if repos else "none (no repositories)")
  report.add(common.INFO, "deployment.yaml", str(deployment) if deployment else "none")
  tfvars = ctx.repo_root / "terraform" / "gcp" / "terraform.tfvars"
  if tfvars.exists():
    report.add(common.WARN, "terraform/gcp/terraform.tfvars exists",
               "the pipeline never sees it",
               "Local values can hide a missing setting. Move settings to deployment.yaml.")

  report.section("Lints")
  for label, path, lint in (("repos.yaml", repos, lint_repos),
                            ("deployment.yaml", deployment, lint_deployment)):
    if path is None:
      continue
    errors, warnings = lint(path.read_text(encoding="utf-8"))
    for e in errors:
      report.add(common.FAIL, label, e)
    for w in warnings:
      report.add(common.WARN, label, w)
    if not errors and not warnings:
      report.add(common.OK, label, "no problems found")

  if not args.skip_terraform:
    report.section("Terraform checks (mock providers, no project access)")
    run_terraform(ctx, repos, deployment, report)
  return report.summary()
