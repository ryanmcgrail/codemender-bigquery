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

"""`pr-scans`: checks the prerequisites for pull request scans (read-only).

Pull request scans run .github/workflows/codemender_parallel.yml on your
GitHub Actions runners, in the runner image, with a Google identity from
Workload Identity Federation (terraform/gha_wif). This command checks what
can be checked from here and lists what your platform team has to confirm.
It does not write workflows; scripts/ci/init_codemender_workflow.py does
that where your copy has it.
"""

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional, Tuple

from codemender_setup import check
from codemender_setup import common
from codemender_setup import yamlio

PLACEHOLDER_IMAGE = "ghcr.io/your-org/codemender-runner:latest"
GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
GITHUB_HOSTED_LABELS = re.compile(r"^(ubuntu|windows|macos)-")
MANIFEST_ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])

EGRESS = [
    "github.com, api.github.com, and the Actions endpoints (*.actions.githubusercontent.com and the "
    "artifact storage host)",
    "the image registry: ghcr.io and pkg-containers.githubusercontent.com, or your mirror",
    "sts.googleapis.com and iamcredentials.googleapis.com (Workload Identity Federation)",
    "aiplatform.googleapis.com (Vertex AI)",
    "artifactregistry.googleapis.com, if these runners also build the runner image (the CodeMender CLI "
    "download; build_runner_image.yml runs on ubuntu-latest)",
]


def add_arguments(parser) -> None:
  parser.add_argument("--image", help=f"runner image the workflow pulls (default: {PLACEHOLDER_IMAGE}, "
                                      "which must be replaced)")
  parser.add_argument("--runner-type", metavar="LABEL",
                      help="runs-on label of the runners that will run the scans, e.g. ubuntu-latest or "
                           "your self-hosted label")
  parser.add_argument("--github-repo", metavar="OWNER/NAME",
                      help="a repository that will run PR scans (default: this copy's origin)")
  parser.add_argument("--wif-project", help="project of terraform/gha_wif (default: project_id in deployment.yaml)")
  parser.add_argument("--pool", default="codemender-gha-pool", help="workload identity pool ID")
  parser.add_argument("--provider", default="codemender-gha-provider", help="workload identity provider ID")
  parser.add_argument("--service-account", help="service account the workflow impersonates "
                                                "(default: codemender-gha-sa@<project>.iam.gserviceaccount.com)")
  parser.add_argument("--no-wif", action="store_true",
                      help="the runners use their own Google identity (GKE Workload Identity); skip the "
                           "terraform/gha_wif checks")


def parse_image(ref: str) -> Optional[Tuple[str, str, str]]:
  """'ghcr.io/o/n:tag' -> ('ghcr.io', 'o/n', 'tag'). Digests keep '@sha256:...'."""
  m = re.match(r"^(?P<host>[a-z0-9.-]+(?::\d+)?)/(?P<path>[a-z0-9._/-]+?)(?P<ref>[:@].+)?$", ref.strip())
  if not m or "." not in m.group("host"):
    return None
  ref_part = m.group("ref") or ":latest"
  if "@" in ref_part:  # name:tag@sha256:... pulls by digest
    ref_part = ref_part[ref_part.index("@"):]
  return m.group("host"), m.group("path"), ref_part[1:] if ref_part.startswith(":") else ref_part


def ghcr_anonymous_pull(path: str, tag: str, opener=None) -> Tuple[Optional[bool], str]:
  """(True, '') if anyone can pull the image; (False, why) if not; (None, why) on errors."""
  opener = opener or urllib.request.urlopen
  token_url = "https://ghcr.io/token?" + urllib.parse.urlencode({"scope": f"repository:{path}:pull",
                                                                 "service": "ghcr.io"})
  try:
    with opener(urllib.request.Request(token_url), timeout=30) as resp:
      token = json.loads(resp.read().decode() or "{}").get("token", "")
  except urllib.error.HTTPError as e:
    return (False, f"token request: HTTP {e.code}") if e.code in (401, 403, 404) else (None, f"HTTP {e.code}")
  except (urllib.error.URLError, OSError, ValueError) as e:
    return None, str(e)
  ref = tag[1:] if tag.startswith("@") else tag
  req = urllib.request.Request(f"https://ghcr.io/v2/{path}/manifests/{ref}", method="HEAD",
                               headers={"Authorization": f"Bearer {token}", "Accept": MANIFEST_ACCEPT})
  try:
    with opener(req, timeout=30):
      return True, ""
  except urllib.error.HTTPError as e:
    if e.code in (401, 403, 404):
      return False, f"HTTP {e.code}"
    return None, f"HTTP {e.code}"
  except (urllib.error.URLError, OSError) as e:
    return None, str(e)


def _gh_json(ctx: common.Context, gh: Optional[str], path: str):
  if not gh:
    return None, "gh not available"
  res = ctx.run([gh, "api", path], timeout=60)
  if not res.ok:
    return None, (res.stderr.strip() or res.stdout.strip())[:200]
  try:
    return json.loads(res.stdout or "null"), ""
  except ValueError:
    return None, "unexpected output"


def _check_image(ctx: common.Context, report: common.Report, image: str, gh: Optional[str], opener) -> None:
  report.section("Runner image")
  if image == PLACEHOLDER_IMAGE or "/your-org/" in image:
    report.add(common.FAIL, "runner_image", f"{image} is the placeholder",
               "Publish the image (build_runner_image.yml publishes ghcr.io/<owner>/codemender-runner) and pass "
               "it as runner_image, or pass --image here.")
    return
  parsed = parse_image(image)
  if not parsed:
    report.add(common.FAIL, "runner_image", f"{image} is not a full image reference (registry/path:tag)")
    return
  host, path, tag = parsed
  if host != "ghcr.io":
    report.add(common.INFO, "runner_image", f"{image} is on {host}",
               "This cannot be checked from here. Make sure the runners can pull it, and that the jobs have "
               "credentials for that registry if it is private.")
    return
  public, why = ghcr_anonymous_pull(path, tag, opener)
  if public:
    report.add(common.OK, "runner_image", f"{image} exists and is public")
    return
  owner, name = path.split("/", 1) if "/" in path else (path, "")
  pkg = urllib.parse.quote(name, safe="")
  data, err = _gh_json(ctx, gh, f"orgs/{owner}/packages/container/{pkg}")
  if data is None:
    data, err = _gh_json(ctx, gh, f"users/{owner}/packages/container/{pkg}")
  if isinstance(data, dict) and data.get("visibility"):
    report.add(common.WARN, "runner_image", f"{image} is {data['visibility']}",
               "Grant each repository that runs scans read access (package settings > Manage Actions access). "
               "On github.com the runner pulls ghcr.io images with the job's GITHUB_TOKEN.")
  elif public is False:
    report.add(common.FAIL, "runner_image", f"{image} not found, or not visible to you ({why})",
               "Check the name and tag; `gh auth refresh -s read:packages` lets this check see private packages.")
  else:
    report.add(common.WARN, "runner_image", f"could not check {image}: {why or err}")


def _check_wif(ctx: common.Context, report: common.Report, args, project: str, gh: Optional[str],
               repo: Optional[str]) -> None:
  report.section("Google identity (terraform/gha_wif)")
  gcloud = ctx.which("gcloud")
  if not gcloud:
    report.add(common.SKIP, "Workload Identity Federation", "gcloud not found")
    return
  res = ctx.run([gcloud, "iam", "workload-identity-pools", "providers", "describe", args.provider,
                 f"--workload-identity-pool={args.pool}", "--location=global", f"--project={project}",
                 "--format=json"], timeout=120)
  if not res.ok:
    report.add(common.FAIL, "Workload identity provider", f"{args.pool}/{args.provider} not found in {project}",
               "Apply terraform/gha_wif (see its terraform.tfvars.example), or pass --pool and --provider.")
  else:
    try:
      provider = json.loads(res.stdout or "{}")
    except ValueError:
      provider = {}
    issuer = ((provider.get("oidc") or {}).get("issuerUri") or "")
    condition = provider.get("attributeCondition", "")
    if issuer and issuer != GITHUB_ISSUER:
      report.add(common.WARN, "Workload identity provider", f"issuer is {issuer}",
                 f"github.com uses {GITHUB_ISSUER}.")
    else:
      report.add(common.OK, "Workload identity provider", f"{args.pool}/{args.provider}")
    if repo and condition and repo.split("/")[0].lower() not in condition.lower():
      report.add(common.WARN, "Workload identity provider", f"its condition does not mention {repo.split('/')[0]}",
                 "Check github_owner and wif_allowed_repositories in terraform/gha_wif.")
  sa = args.service_account or f"codemender-gha-sa@{project}.iam.gserviceaccount.com"
  res = ctx.run([gcloud, "iam", "service-accounts", "describe", sa, f"--project={project}",
                 "--format=value(email)"], timeout=120)
  if res.ok:
    report.add(common.OK, "Workflow service account", sa)
  else:
    report.add(common.FAIL, "Workflow service account", f"{sa} not found", "Apply terraform/gha_wif.")
  res = ctx.run([gcloud, "services", "list", "--enabled", f"--project={project}",
                 "--filter=config.name=aiplatform.googleapis.com", "--format=value(config.name)"], timeout=120)
  if res.ok and "aiplatform.googleapis.com" in res.stdout:
    report.add(common.OK, "Vertex AI API", "enabled")
  elif res.ok:
    report.add(common.FAIL, "Vertex AI API", "not enabled", "terraform/gha_wif enables it.")
  if repo:
    for secret in ("GCP_WORKLOAD_IDENTITY_PROVIDER", "GCP_SERVICE_ACCOUNT"):
      data, err = _gh_json(ctx, gh, f"repos/{repo}/actions/secrets/{secret}")
      if data:
        report.add(common.OK, f"Actions secret {secret}", f"set on {repo}")
      elif "404" in err or "Not Found" in err:
        report.add(common.WARN, f"Actions secret {secret}", f"not set on {repo}",
                   "terraform/gha_wif sets it; an organization secret works too (not checked here).")
      else:
        report.add(common.INFO, f"Actions secret {secret}", f"could not check ({err})")


def _check_runners(ctx: common.Context, report: common.Report, label: Optional[str], gh: Optional[str],
                   repo: Optional[str]) -> bool:
  """Returns True when the label looks like a self-hosted runner."""
  report.section("Runners")
  if not label:
    report.add(common.WARN, "runner_type", "not given",
               "The workflow defaults to ubuntu-latest. If your organization only allows its own runners, "
               "pass their label as runner_type (and here with --runner-type).")
    return False
  if GITHUB_HOSTED_LABELS.match(label):
    report.add(common.OK, "runner_type", f"{label} (GitHub-hosted: container jobs and --privileged work)")
    return False
  report.add(common.INFO, "runner_type", f"{label} (self-hosted)")
  if not repo:
    return True
  data, err = _gh_json(ctx, gh, f"repos/{repo}/actions/runners?per_page=100")
  owner = repo.split("/")[0]
  if data is None:
    data, err = _gh_json(ctx, gh, f"orgs/{owner}/actions/runners?per_page=100")
  runners = (data or {}).get("runners", []) if isinstance(data, dict) else []
  if data is None:
    report.add(common.INFO, "Runners with that label", f"could not list runners ({err})",
               "Listing runners needs admin access to the repository or organization.")
    return True
  matching = [r for r in runners if label in {l.get("name") for l in r.get("labels", [])}]
  if not matching:
    report.add(common.WARN, "Runners with that label", "none registered right now",
               "Runner scale sets (Actions Runner Controller) may register runners only while jobs wait. "
               "Check the label with your platform team.")
  else:
    online = sum(1 for r in matching if r.get("status") == "online")
    report.add(common.OK, "Runners with that label", f"{len(matching)} registered, {online} online")
    if any("-runner-" in r.get("name", "") for r in matching):
      report.add(common.INFO, "Runner type", "the names look like Actions Runner Controller scale sets")
  return True


def _print_confirmations(ctx: common.Context, self_hosted: bool, no_wif: bool = False) -> None:
  ctx.say("")
  ctx.say("== Confirm with your platform team (cannot be checked from here)")
  items = []
  if self_hosted:
    items += [
        "Container jobs: the workflow runs every job in the runner image with `options: --privileged`. On "
        "Actions Runner Controller, the scale set needs containerMode dind (privileged Docker sidecar), or "
        "containerMode kubernetes with a hook pod template that sets securityContext.privileged: true. With "
        "no container mode, container jobs fail.",
        "If privileged containers are not allowed: the CodeMender sandbox needs them. The alternative is "
        "sandbox_enabled: false, which relies on the runner pod's isolation; your security team must accept "
        "that.",
        "Size: a scan job needs about 4 vCPU and 16 GiB of memory; pick the runner label accordingly.",
    ]
  if no_wif:
    items.append("Identity: the job containers get Google credentials from the runner (for example GKE "
                 "Workload Identity), for an identity with Vertex AI User. Leave GCP_WORKLOAD_IDENTITY_PROVIDER "
                 "and GCP_SERVICE_ACCOUNT unset so the workflow skips its login step.")
  items += [
      "Image pulls: the runners must reach the image registry. If pulls go through a mirror (for example "
      "Artifactory), pass the mirrored image as runner_image and give the jobs credentials for it.",
      "Egress from the runners (and a proxy, if any): " + "; ".join(EGRESS) + ".",
  ]
  for i, item in enumerate(items, 1):
    ctx.say(f"{i}. {item}")


def run(ctx: common.Context, args, opener=None) -> int:
  report = common.Report(ctx)
  gh = ctx.which("gh")
  repo, host = check.resolve_github_repo(ctx, args.github_repo, ctx.which("git"))
  if host and host != "github.com":
    report.add(common.FAIL, "GitHub", f"{host} is not supported; pull request scans need github.com")
  project = args.wif_project
  if not project:
    deployment = ctx.repo_root / "terraform" / "gcp" / "deployment.yaml"
    if deployment.exists():
      project = yamlio.top_level_scalars(deployment.read_text(encoding="utf-8")).get("project_id")
  _check_image(ctx, report, args.image or PLACEHOLDER_IMAGE, gh, opener)
  if args.no_wif:
    report.section("Google identity")
    report.add(common.SKIP, "Workload Identity Federation", "--no-wif: the runners use their own identity")
  elif project:
    _check_wif(ctx, report, args, project, gh, repo)
  else:
    report.add(common.FAIL, "Google identity", "no project", "Pass --wif-project, or --no-wif.")
  self_hosted = _check_runners(ctx, report, args.runner_type, gh, repo)
  _print_confirmations(ctx, self_hosted, args.no_wif)
  ctx.say("")
  ctx.say("== Next")
  ctx.say("Generate the caller workflow in each scanned repository "
          "with scripts/ci/init_codemender_workflow.py (see docs/guides/github_actions_presubmit_ci_cd.md) "
          "where your copy has them. It is non-blocking (advisory) by default; set repository variable "
          "CODEMENDER_BLOCK_PR_MERGE=true later to block merges. Give it the image with --runner-image"
          + (f" {args.image}" if args.image else "")
          + ". The workflow runs on ubuntu-latest unless the generated file sets runner_type under `with:`"
          + (f"; add `runner_type: {args.runner_type}` there." if args.runner_type and
             not GITHUB_HOSTED_LABELS.match(args.runner_type) else "."))
  return report.summary()
