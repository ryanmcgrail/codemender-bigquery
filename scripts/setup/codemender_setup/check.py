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

"""`check`: read-only prerequisites check before the first setup step.

Nothing here changes a project or a repository. Each finding says what to do
next.
"""

import json
import pathlib
import sys
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple

from codemender_setup import common
from codemender_setup import yamlio

# One representative permission per role the one-time setup needs (see
# "Before you start" in docs/guides/gitops_cloud_build.md).
SETUP_PERMISSIONS: Dict[str, str] = {
    "resourcemanager.projects.setIamPolicy": "Project IAM Admin",
    "iam.serviceAccounts.create": "Service Account Admin",
    "iam.serviceAccounts.actAs": "Service Account User",
    "serviceusage.services.enable": "Service Usage Admin",
    "storage.buckets.create": "Storage Admin",
    "iam.roles.create": "Role Administrator",
    "cloudbuild.builds.create": "Cloud Build Editor",
    "cloudbuild.connections.create": "Cloud Build Connection Admin",
}
CONNECTION_PERMISSIONS: Dict[str, str] = {
    "cloudbuild.connections.create": "Cloud Build Connection Admin",
    "cloudbuild.repositories.create": "Cloud Build Connection Admin",
}

_CRM = "https://cloudresourcemanager.googleapis.com/v1/projects/{project}:testIamPermissions"


def add_arguments(parser) -> None:
  parser.add_argument("--project", help="Google Cloud project ID (default: deployment.yaml, then gcloud config)")
  parser.add_argument("--connection-project",
                      help="project that holds the Cloud Build connection, if it is not --project")
  parser.add_argument("--github-repo", metavar="OWNER/NAME",
                      help="this repository on GitHub (default: from the origin remote)")


# Tools ----------------------------------------------------------------------


def _install_hint(ctx: common.Context, tool: str) -> str:
  env = ctx.environ
  if env.get("CODESPACES") == "true":
    return "Rebuild the codespace with this repository's .devcontainer, which installs it."
  if env.get("CLOUD_SHELL") == "true":
    if tool == "terraform":
      return ("Cloud Shell's Terraform may be older than 1.11. Install a newer one in your home "
              "directory: https://developer.hashicorp.com/terraform/install")
    return f"Install {tool} in your home directory; Cloud Shell keeps only $HOME between sessions."
  return {
      "gcloud": "Install the Google Cloud CLI: https://cloud.google.com/sdk/docs/install",
      "terraform": "Install Terraform 1.11 or later: https://developer.hashicorp.com/terraform/install",
      "git": "Install git from your package manager.",
      "gh": "Optional. Install the GitHub CLI (https://cli.github.com) and run `gh auth login`.",
  }.get(tool, "")


def check_tools(ctx: common.Context, report: common.Report) -> Dict[str, Optional[str]]:
  report.section("Tools")
  found: Dict[str, Optional[str]] = {}
  py = sys.version_info[:2]
  if py >= common.MIN_PYTHON:
    report.add(common.OK, "python3", ".".join(map(str, sys.version_info[:3])))
  else:
    report.add(common.FAIL, "python3", f"{py[0]}.{py[1]} is older than 3.9")

  for tool in ("gcloud", "terraform", "git", "gh"):
    path = ctx.which(tool)
    found[tool] = path
    if not path:
      status = common.WARN if tool == "gh" else common.FAIL
      report.add(status, tool, "not found", _install_hint(ctx, tool))
      continue
    if tool == "terraform":
      res = ctx.run([path, "version", "-json"], timeout=60)
      version = ""
      if res.ok:
        try:
          version = json.loads(res.stdout).get("terraform_version", "")
        except ValueError:
          version = res.stdout
      have = common.version_tuple(version)
      if have and have >= common.MIN_TERRAFORM:
        report.add(common.OK, "terraform", version)
      else:
        report.add(common.FAIL, "terraform", f"{version or 'unknown version'}; 1.11 or later is needed",
                   _install_hint(ctx, "terraform"))
    elif tool == "gh":
      res = ctx.run([path, "auth", "status", "--hostname", "github.com"], timeout=60)
      if res.ok:
        report.add(common.OK, "gh", "logged in to github.com")
      else:
        report.add(common.WARN, "gh", "not logged in",
                   "Run `gh auth login` to enable the repository checks and --pr.")
        found["gh"] = None
    else:
      res = ctx.run([path, "--version"], timeout=60)
      first = (res.stdout or res.stderr).strip().splitlines()[:1]
      report.add(common.OK, tool, first[0] if first else path)
  return found


# Google Cloud -----------------------------------------------------------------


def resolve_project(ctx: common.Context, given: Optional[str], gcloud: Optional[str]) -> Tuple[Optional[str], str]:
  if given:
    return given, "--project"
  deployment = ctx.repo_root / "terraform" / "gcp" / "deployment.yaml"
  if deployment.is_file():
    value = yamlio.top_level_scalars(deployment.read_text(encoding="utf-8")).get("project_id")
    if value and value != "your-project-id":
      return value, "deployment.yaml"
  if gcloud:
    res = ctx.run([gcloud, "config", "get-value", "project"], timeout=60)
    value = res.stdout.strip()
    if res.ok and value and value != "(unset)":
      return value, "gcloud config"
  return None, ""


def adc_token(ctx: common.Context, gcloud: Optional[str]) -> Optional[str]:
  if not gcloud:
    return None
  res = ctx.run([gcloud, "auth", "application-default", "print-access-token"], timeout=60)
  token = res.stdout.strip()
  return token if res.ok and token else None


def test_iam_permissions(project: str, token: str, permissions: List[str],
                         opener=urllib.request.urlopen) -> Tuple[Dict[str, Optional[bool]], str]:
  """Tests permissions on a project with testIamPermissions.

  Returns ({permission: granted}, error). A permission maps to None when it
  could not be tested; error is set when nothing could be tested.
  """
  body = json.dumps({"permissions": permissions}).encode()
  req = urllib.request.Request(
      _CRM.format(project=project), data=body, method="POST",
      headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
  try:
    with opener(req, timeout=30) as resp:
      data = json.loads(resp.read().decode() or "{}")
  except urllib.error.HTTPError as e:
    detail = ""
    try:
      detail = json.loads(e.read().decode()).get("error", {}).get("message", "")
    except (ValueError, AttributeError):
      pass
    if e.code == 400 and len(permissions) > 1:
      # One permission name is not valid here; test them one by one.
      result: Dict[str, Optional[bool]] = {}
      for perm in permissions:
        one, _ = test_iam_permissions(project, token, [perm], opener)
        result[perm] = one.get(perm)
      if all(v is None for v in result.values()):
        return result, f"HTTP {e.code} {detail}".strip()
      return result, ""
    return {p: None for p in permissions}, f"HTTP {e.code} {detail}".strip()
  except (urllib.error.URLError, OSError, ValueError) as e:
    return {p: None for p in permissions}, str(e)
  granted = set(data.get("permissions", []))
  return {p: p in granted for p in permissions}, ""


def check_gcloud(ctx: common.Context, report: common.Report, args, gcloud: Optional[str],
                 opener=urllib.request.urlopen) -> None:
  report.section("Google Cloud")
  if not gcloud:
    report.add(common.SKIP, "Google Cloud checks", "gcloud not found")
    return
  account = ctx.run([gcloud, "config", "get-value", "account"], timeout=60).stdout.strip()
  if account and account != "(unset)":
    report.add(common.OK, "gcloud account", account)
  else:
    report.add(common.FAIL, "gcloud account", "not logged in", "Run `gcloud auth login`.")

  token = adc_token(ctx, gcloud)
  if token:
    report.add(common.OK, "Application Default Credentials", "usable (Terraform uses these)")
  else:
    report.add(common.FAIL, "Application Default Credentials", "missing or expired",
               "Run `gcloud auth application-default login`.")

  project, source = resolve_project(ctx, args.project, gcloud)
  if not project:
    report.add(common.FAIL, "Project", "unknown", "Pass --project or set project_id in deployment.yaml.")
    return
  report.add(common.INFO, "Project", f"{project} (from {source})")
  if not token:
    report.add(common.SKIP, "Setup permissions", "no Application Default Credentials")
    return
  _report_permissions(report, "Setup permissions", project, token, SETUP_PERMISSIONS, opener)
  if args.connection_project and args.connection_project != project:
    _report_permissions(report, f"Connection permissions in {args.connection_project}",
                        args.connection_project, token, CONNECTION_PERMISSIONS, opener)


def _report_permissions(report: common.Report, title: str, project: str, token: str,
                        wanted: Dict[str, str], opener) -> None:
  result, error = test_iam_permissions(project, token, sorted(wanted), opener)
  if error:
    report.add(common.WARN, title, f"could not check ({error})",
               "Check that the project exists and that you can see it.")
    return
  missing = sorted({wanted[p] for p, ok in result.items() if ok is False})
  untested = sorted(p for p, ok in result.items() if ok is None)
  if missing:
    report.add(common.FAIL, title, "missing " + ", ".join(missing),
               "Ask a project owner for these roles, or for Owner for the one-time setup.")
  else:
    report.add(common.OK, title, "all present")
  if untested:
    report.add(common.WARN, title, "could not test " + ", ".join(untested))


# GitHub ---------------------------------------------------------------------


def resolve_github_repo(ctx: common.Context, given: Optional[str], git: Optional[str]) -> Tuple[Optional[str], str]:
  if given:
    return given.strip().strip("/"), ""
  if not git:
    return None, ""
  res = ctx.run([git, "-C", str(ctx.repo_root), "remote", "get-url", "origin"], timeout=60)
  parsed = common.parse_github_remote(res.stdout) if res.ok else None
  if not parsed:
    return None, ""
  host, owner, name = parsed
  return f"{owner}/{name}", host


def check_github(ctx: common.Context, report: common.Report, args, tools: Dict[str, Optional[str]]) -> None:
  report.section("GitHub repository")
  repo, host = resolve_github_repo(ctx, args.github_repo, tools.get("git"))
  if not repo:
    report.add(common.WARN, "Repository", "could not tell which GitHub repository this is",
               "Pass --github-repo OWNER/NAME.")
  elif host and host != "github.com":
    status = common.FAIL if host.endswith("ghe.com") else common.WARN
    report.add(status, "Repository host", host, "This deployment supports github.com only.")
  else:
    report.add(common.INFO, "Repository", repo)

  gh = tools.get("gh")
  if repo and gh:
    res = ctx.run([gh, "api", f"repos/{repo}", "--jq", ".visibility"], timeout=60)
    visibility = res.stdout.strip()
    if not res.ok:
      report.add(common.WARN, "Visibility", "could not read the repository with gh")
    elif visibility == "private":
      report.add(common.OK, "Visibility", "private")
    else:
      report.add(common.FAIL, "Visibility", visibility or "unknown",
                 "repos.yaml can run code in the scan jobs. Keep this repository private; an "
                 "internal repository is visible to the whole enterprise.")
    res = ctx.run([gh, "api", f"repos/{repo}/actions/permissions", "--jq", ".enabled"], timeout=60)
    if res.ok and res.stdout.strip() == "true":
      _check_actions_files(ctx, report, actions_enabled=True)
    elif res.ok:
      _check_actions_files(ctx, report, actions_enabled=False)
    else:
      report.add(common.INFO, "GitHub Actions", "unknown (needs repository admin access to read)")
      _check_actions_files(ctx, report, actions_enabled=None)
  else:
    if repo:
      report.add(common.SKIP, "Visibility", "gh is not available",
                 "Check by hand that the repository is private.")
    _check_actions_files(ctx, report, actions_enabled=None)


def _check_actions_files(ctx: common.Context, report: common.Report, actions_enabled: Optional[bool]) -> None:
  root = ctx.repo_root
  if (root / ".github" / "dependabot.yml").is_file():
    report.add(common.WARN, "Dependabot", ".github/dependabot.yml is present",
               "Merging any pull request into the deployed branch runs an apply. Turn off Dependabot "
               "version updates, or review its pull requests like any infrastructure change.")
  workflows = sorted(p.name for p in (root / ".github" / "workflows").glob("*.yml"))
  if workflows and actions_enabled is not False:
    report.add(common.WARN, "GitHub Actions workflows", ", ".join(workflows),
               "This copy does not need them for scheduled scans. Disable them if your organization "
               "does not provide the runners they expect.")


def run(ctx: common.Context, args, opener=urllib.request.urlopen) -> int:
  report = common.Report(ctx)
  ctx.say(f"Repository: {ctx.repo_root}")
  if ctx.environ.get("CLOUD_SHELL") == "true":
    ctx.say("Environment: Cloud Shell")
  elif ctx.environ.get("CODESPACES") == "true":
    ctx.say("Environment: GitHub Codespaces")
  tools = check_tools(ctx, report)
  check_gcloud(ctx, report, args, tools.get("gcloud"), opener)
  check_github(ctx, report, args, tools)
  tfvars = pathlib.Path(ctx.repo_root, "terraform", "gcp", "terraform.tfvars")
  if tfvars.exists():
    report.section("Local files")
    report.add(common.WARN, "terraform/gcp/terraform.tfvars", "exists; the pipeline never sees it",
               "Move its settings to deployment.yaml.")
  return report.summary()
