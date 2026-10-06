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

"""`doctor`, `first-image` and `teardown --print`: after the bootstrap.

doctor       read-only health check of the deployed pipeline and deployment.
first-image  runs the image trigger once, so the jobs get a real image.
teardown     prints the teardown steps for this deployment; changes nothing.
"""

import json
import re
from typing import Dict, List, Optional

from codemender_setup import common
from codemender_setup import config_edit
from codemender_setup import gcp
from codemender_setup import validate

PLACEHOLDER_IMAGE = "us-docker.pkg.dev/cloudrun/container/job"
TRIGGER_SUFFIXES = ("tf-plan", "tf-apply", "tf-apply-destroy", "image")


class Target:
  """Where the deployment and its pipeline live, from the local files."""

  def __init__(self, ctx: common.Context, project: Optional[str] = None):
    self.deployment = config_edit.read_deployment(ctx, project)
    tfvars_path = ctx.repo_root / config_edit.BOOTSTRAP_TFVARS
    self.tfvars = tfvars_path.read_text(encoding="utf-8") if tfvars_path.exists() else ""
    self.project = self.deployment["project_id"]
    self.region = self.deployment["region"]
    self.prefix = self.deployment["resource_prefix"]
    # The pipeline (bootstrap) may use another prefix or region.
    self.pipeline_prefix = config_edit.read_tfvar(self.tfvars, "resource_prefix") or self.prefix
    self.pipeline_region = config_edit.read_tfvar(self.tfvars, "region") or self.region
    self.pipeline_project = config_edit.read_tfvar(self.tfvars, "project_id") or self.project
    self.branch = config_edit.read_tfvar(self.tfvars, "branch") or "main"
    self.repository = config_edit.read_tfvar(self.tfvars, "cloudbuild_repository") or ""
    self.state_bucket = gcp.state_bucket_name(self.tfvars) if self.tfvars else None

  def trigger(self, suffix: str) -> str:
    return f"{self.pipeline_prefix}-{suffix}"

  def connection(self) -> Optional[Dict[str, str]]:
    m = re.match(r"^projects/([^/]+)/locations/([^/]+)/connections/([^/]+)/repositories/([^/]+)$",
                 self.repository)
    if not m:
      return None
    return dict(zip(("project", "region", "connection", "repository"), m.groups()))


def _add_project_argument(parser) -> None:
  parser.add_argument("--project", help="project ID (default: project_id in deployment.yaml)")


def _gcloud(ctx: common.Context) -> str:
  gcloud = ctx.which("gcloud")
  if not gcloud:
    raise common.UsageError("gcloud not found; install the Google Cloud CLI (run `codemender-setup check`)")
  return gcloud


def _json_or_none(res: common.Result):
  if not res.ok:
    return None
  try:
    return json.loads(res.stdout or "null")
  except ValueError:
    return None


def _lines(res: common.Result) -> List[str]:
  return [l.strip() for l in res.stdout.splitlines() if l.strip()] if res.ok else []


# doctor -----------------------------------------------------------------------


def add_doctor_arguments(parser) -> None:
  _add_project_argument(parser)


def _doctor_config(ctx: common.Context, report: common.Report) -> None:
  report.section("Configuration")
  for rel, lint in ((config_edit.DEPLOYMENT, validate.lint_deployment), (config_edit.REPOS, validate.lint_repos)):
    path = ctx.repo_root / rel
    if not path.exists():
      report.add(common.FAIL if rel == config_edit.DEPLOYMENT else common.WARN, str(rel), "missing",
                 "Run `codemender-setup init`.")
      continue
    errors, warnings = lint(path.read_text(encoding="utf-8"))
    if errors:
      report.add(common.FAIL, str(rel), errors[0], "Run `codemender-setup validate` for details.")
    elif warnings:
      report.add(common.WARN, str(rel), warnings[0], "Run `codemender-setup validate` for details.")
    else:
      report.add(common.OK, str(rel), "lints pass")


def _doctor_pipeline(ctx: common.Context, report: common.Report, t: Target, gcloud: str) -> None:
  report.section("GitOps pipeline (terraform/bootstrap)")
  if not t.tfvars:
    report.add(common.WARN, "terraform/bootstrap/terraform.tfvars", "missing on this machine",
               "Run `codemender-setup init` (it keeps existing YAML files with --force only).")
  conn = t.connection()
  if not conn:
    report.add(common.FAIL, "Cloud Build connection", "cloudbuild_repository is not set",
               "Run `codemender-setup connect`.")
  else:
    res = ctx.run([gcloud, "builds", "connections", "describe", conn["connection"], f"--region={conn['region']}",
                   f"--project={conn['project']}", "--format=json"], timeout=120)
    data = _json_or_none(res)
    stage = ((data or {}).get("installationState") or {}).get("stage", "")
    if stage == "COMPLETE":
      report.add(common.OK, "Cloud Build connection", f"{conn['connection']} is complete")
    elif data is None:
      report.add(common.FAIL, "Cloud Build connection", f"cannot read {conn['connection']}: "
                 f"{res.stderr.strip()[:200]}", "Run `codemender-setup connect`.")
    else:
      report.add(common.FAIL, "Cloud Build connection", f"{conn['connection']} is {stage or 'not ready'}",
                 "Run `codemender-setup connect` to finish it.")
    _doctor_agent_grant(ctx, report, gcloud, conn["project"])

  if t.state_bucket:
    res = ctx.run([gcloud, "storage", "buckets", "describe", f"gs://{t.state_bucket}", "--format=value(name)"],
                  timeout=120)
    if res.ok:
      report.add(common.OK, "State bucket", t.state_bucket)
      backup = ctx.run([gcloud, "storage", "ls", f"gs://{t.state_bucket}/{gcp.STATE_BACKUP_OBJECT}"], timeout=120)
      if backup.ok:
        report.add(common.OK, "Bootstrap state backup", "present")
      else:
        report.add(common.WARN, "Bootstrap state backup", "missing",
                   "Run `codemender-setup bootstrap` again; it backs up the state after each run.")
    else:
      report.add(common.FAIL, "State bucket", f"{t.state_bucket} not found or not readable",
                 "Run `codemender-setup bootstrap`.")

  res = ctx.run([gcloud, "builds", "triggers", "list", f"--region={t.pipeline_region}",
                 f"--project={t.pipeline_project}", "--format=value(name,id)"], timeout=120)
  ours = {t.trigger(s) for s in TRIGGER_SUFFIXES}
  trigger_ids = []
  if res.ok:
    have = set()
    for line in _lines(res):
      fields = line.split()
      have.add(fields[0])
      if fields[0] in ours and len(fields) > 1:
        trigger_ids.append(fields[1])
    missing = [t.trigger(s) for s in TRIGGER_SUFFIXES if t.trigger(s) not in have]
    if missing:
      report.add(common.FAIL, "Cloud Build triggers", "missing " + ", ".join(missing),
                 "Run `codemender-setup bootstrap`.")
    else:
      report.add(common.OK, "Cloud Build triggers", f"all {len(TRIGGER_SUFFIXES)} present")
  else:
    report.add(common.WARN, "Cloud Build triggers", f"could not list: {res.stderr.strip()[:200]}")

  # Only this deployment's builds: the project may hold other deployments, or
  # builds from an earlier deployment that used the same trigger names.
  if not trigger_ids:
    return
  by_trigger = "buildTriggerId=(" + " OR ".join(sorted(trigger_ids)) + ")"
  res = ctx.run([gcloud, "builds", "list", f"--region={t.pipeline_region}", f"--project={t.pipeline_project}",
                 f"--filter=approval.state=PENDING AND {by_trigger}", "--format=value(id)", "--limit=20"],
                timeout=120)
  pending = _lines(res)
  if pending:
    # `gcloud beta builds approve` has no --location flag; alpha does.
    report.add(common.WARN, "Builds waiting for approval", str(len(pending)),
               f"Review them in the Cloud Build history, or: gcloud alpha builds approve {pending[0]} "
               f"--location={t.pipeline_region} --project={t.pipeline_project}")
  res = ctx.run([gcloud, "builds", "list", f"--region={t.pipeline_region}", f"--project={t.pipeline_project}",
                 f"--filter=status=(FAILURE OR TIMEOUT OR INTERNAL_ERROR) AND {by_trigger}",
                 "--sort-by=~createTime", "--format=value(id,createTime)", "--limit=3"], timeout=120)
  failed = _lines(res)
  if failed:
    report.add(common.INFO, "Recent failed builds", "; ".join(" ".join(f.split()[:2]) for f in failed),
               f"gcloud builds log BUILD_ID --region={t.pipeline_region} --project={t.pipeline_project}")


def _doctor_agent_grant(ctx: common.Context, report: common.Report, gcloud: str, project: str) -> None:
  res = ctx.run([gcloud, "projects", "describe", project, "--format=value(projectNumber)"], timeout=60)
  number = res.stdout.strip()
  if not res.ok or not number.isdigit():
    return
  member = f"serviceAccount:service-{number}@gcp-sa-cloudbuild.iam.gserviceaccount.com"
  policy = _json_or_none(ctx.run([gcloud, "projects", "get-iam-policy", project, "--format=json"], timeout=120))
  if not policy:
    return
  if any(b.get("role") == gcp.SERVICE_AGENT_ROLE and member in b.get("members", [])
         for b in policy.get("bindings", [])):
    report.add(common.WARN, "Cloud Build service agent", f"still has {gcp.SERVICE_AGENT_ROLE}",
               "It is only needed while a connection is set up. Remove it unless another connection "
               f"is being created:\ngcloud projects remove-iam-policy-binding {project} --member={member} "
               f"--role={gcp.SERVICE_AGENT_ROLE} --condition=None")


def _doctor_deployment(ctx: common.Context, report: common.Report, t: Target, gcloud: str) -> None:
  report.section("Deployment (terraform/gcp)")
  images = {}
  for job in ("runner", "worker"):
    name = f"{t.prefix}-{job}"
    res = ctx.run([gcloud, "run", "jobs", "describe", name, f"--region={t.region}", f"--project={t.project}",
                   "--format=value(spec.template.spec.template.spec.containers[0].image)"], timeout=120)
    if not res.ok:
      report.add(common.FAIL, f"Cloud Run job {name}", "not found",
                 "Merge the pull request with deployment.yaml and repos.yaml; the apply creates it.")
      continue
    images[job] = res.stdout.strip()
  if not images:
    return
  if any(i.startswith(PLACEHOLDER_IMAGE) for i in images.values()):
    report.add(common.WARN, "Runner image", "the jobs still run the placeholder image",
               "Run `codemender-setup first-image`.")
  else:
    report.add(common.OK, "Runner image", images.get("runner", ""))
    if len(set(images.values())) > 1:
      report.add(common.WARN, "Runner image", "runner and worker run different images",
                 "Run the image trigger again, or see Manual rollout in the GitOps guide.")
  paused = str(t.deployment.get("scheduler_paused", "")).lower()
  if paused == "true" and not any(i.startswith(PLACEHOLDER_IMAGE) for i in images.values()):
    report.add(common.INFO, "Scheduler", "paused, and a real image is rolled out",
               "Start the schedules: codemender-setup set scheduler_paused false --pr")


def _enabled_versions(ctx: common.Context, gcloud: str, project: str, name: str) -> Optional[int]:
  res = ctx.run([gcloud, "secrets", "versions", "list", name, f"--project={project}",
                 "--filter=state:ENABLED", "--format=value(name)"], timeout=120)
  return len(_lines(res)) if res.ok else None


def _wiz_enabled(repos_text: str) -> bool:
  """Whether any repository sets wiz.enabled to true (block or flow style).

  `enabled` is only a key under `wiz:` in repos.yaml (config.tf), and
  config.tf accepts true or "true".
  """
  for line in repos_text.splitlines():
    code = re.sub(r"\s#.*$", "", line) if not line.lstrip().startswith("#") else ""
    if re.search(r"(^\s+|[{,]\s*)enabled:\s*([\"']?)true\2\s*([,}]|$)", code, re.I):
      return True
  return False


def _doctor_secrets(ctx: common.Context, report: common.Report, t: Target, gcloud: str) -> None:
  report.section("Secrets")
  d = t.deployment
  if d.get("github_app_id"):
    name = d.get("github_app_private_key_secret_id") or f"{t.prefix}-github-app-private-key"
    count = _enabled_versions(ctx, gcloud, t.project, name)
    if count:
      report.add(common.OK, "GitHub App private key", f"{name}: {count} enabled version(s)")
    else:
      report.add(common.FAIL, "GitHub App private key", f"{name} is missing or has no enabled version",
                 "Run `codemender-setup secrets github-app`.")
  else:
    name = f"{t.prefix}-github-token"
    count = _enabled_versions(ctx, gcloud, t.project, name)
    if count is None:
      report.add(common.WARN, "GitHub credentials", f"no GitHub App, and {name} does not exist yet",
                 "Set up the GitHub App: `codemender-setup secrets github-app`.")
    elif count <= 1:
      report.add(common.WARN, "GitHub credentials", f"no GitHub App, and {name} may hold only Terraform's "
                 "placeholder", "Set up the GitHub App (`codemender-setup secrets github-app`), or store a "
                 "token with `codemender-setup secrets github-token`.")
    else:
      report.add(common.OK, "GitHub credentials", f"token in {name} (consider the GitHub App instead)")
  repos = ctx.repo_root / config_edit.REPOS
  if repos.exists() and _wiz_enabled(repos.read_text(encoding="utf-8")):
    for key, suffix in (("wiz_client_id_secret_id", "wiz-client-id"),
                        ("wiz_client_secret_secret_id", "wiz-client-secret")):
      name = d.get(key) or f"{t.prefix}-{suffix}"
      if _enabled_versions(ctx, gcloud, t.project, name):
        report.add(common.OK, "Wiz secret", name)
      else:
        report.add(common.FAIL, "Wiz secret", f"{name} is missing or has no enabled version",
                   "Run `codemender-setup secrets wiz`.")


def run_doctor(ctx: common.Context, args) -> int:
  report = common.Report(ctx)
  _doctor_config(ctx, report)
  try:
    t = Target(ctx, args.project)
  except common.UsageError as e:
    report.add(common.FAIL, "deployment.yaml", str(e))
    return report.summary()
  gcloud = ctx.which("gcloud")
  if not gcloud:
    report.add(common.FAIL, "gcloud", "not found", "Install the Google Cloud CLI.")
    return report.summary()
  _doctor_pipeline(ctx, report, t, gcloud)
  _doctor_deployment(ctx, report, t, gcloud)
  _doctor_secrets(ctx, report, t, gcloud)
  return report.summary()


# first-image ------------------------------------------------------------------


def add_first_image_arguments(parser) -> None:
  _add_project_argument(parser)


def run_first_image(ctx: common.Context, args) -> int:
  t = Target(ctx, args.project)
  gcloud = _gcloud(ctx)
  job = f"{t.prefix}-runner"
  res = ctx.run([gcloud, "run", "jobs", "describe", job, f"--region={t.region}", f"--project={t.project}",
                 "--format=value(spec.template.spec.template.spec.containers[0].image)"], timeout=120)
  if not res.ok:
    ctx.say(f"The Cloud Run job {job} does not exist yet. Merge the pull request with deployment.yaml and "
            "repos.yaml first; its apply creates the jobs.")
    return common.EXIT_FAILED
  if not res.stdout.strip().startswith(PLACEHOLDER_IMAGE):
    ctx.say(f"{job} already runs {res.stdout.strip()}.")
    if not ctx.confirm("Build and roll out a new image anyway?"):
      return common.EXIT_OK
  trigger = t.trigger("image")
  cmd = [gcloud, "builds", "triggers", "run", trigger, f"--branch={t.branch}", f"--region={t.pipeline_region}",
         f"--project={t.pipeline_project}", "--format=json"]
  if ctx.dry_run:
    ctx.say("would run: " + " ".join(cmd[1:-1]))
    return common.EXIT_OK
  if not ctx.confirm(f"Run {trigger} on {t.branch} now?", default=True):
    raise common.Cancelled("first-image")
  res = ctx.run(cmd, timeout=300)
  if not res.ok:
    ctx.say(f"gcloud builds triggers run failed: {res.stderr.strip()}")
    return common.EXIT_FAILED
  data = _json_or_none(res) or {}
  build = ((data.get("metadata") or {}).get("build") or {}).get("id") or data.get("id") or ""
  ctx.say(f"Started build {build or '(see the Cloud Build history)'}.")
  if build:
    ctx.say(f"Follow it: gcloud builds log --stream {build} --region={t.pipeline_region} "
            f"--project={t.pipeline_project}")
  ctx.say("If image_requires_approval is set, an approver must approve it first. Nothing is running yet, so it "
          "rolls out right after the build.")
  ctx.say("Then `codemender-setup doctor` tells you when to set scheduler_paused to false.")
  return common.EXIT_OK


# teardown ---------------------------------------------------------------------


def add_teardown_arguments(parser) -> None:
  _add_project_argument(parser)
  parser.add_argument("--print", dest="print_only", action="store_true",
                      help="print the teardown steps for this deployment (required; nothing is deleted)")


def teardown_steps(t: Target) -> List[str]:
  conn = t.connection() or {"project": t.pipeline_project, "region": t.pipeline_region,
                            "connection": "CONNECTION", "repository": "REPOSITORY"}
  bucket = t.state_bucket or f"{t.pipeline_prefix}-tfstate-{t.pipeline_project}"
  loc = f"--region={conn['region']} --project={conn['project']}"
  regional_endpoint = ("CLOUDSDK_API_ENDPOINT_OVERRIDES_SECRETMANAGER="
                       f"https://secretmanager.{conn['region']}.rep.googleapis.com/")
  return [
      "# Teardown of this deployment. Read each step; nothing here runs by itself.",
      "",
      "# 1. Stop new scans and wait until none is running:",
      "scripts/setup/codemender-setup set scheduler_paused true --pr   # merge it",
      f"gcloud workflows executions list {t.prefix}-coordinator --location={t.region} --project={t.project} "
      "--filter='state=ACTIVE'",
      "",
      "# 2. Destroy terraform/gcp with the shared state. The BigQuery tables are deletion-protected by",
      "#    default and the destroy stops with an error on them, so first merge (and let it apply)",
      "#    bigquery_deletion_protection: false and bigquery_delete_contents_on_destroy: true.",
      "#    Export the telemetry first if you want to keep it.",
      f"TF_STATE_BUCKET={bucket} scripts/ci/tf_init.sh",
      "terraform -chdir=terraform/gcp destroy",
      "",
      "# 3. Destroy terraform/bootstrap (its state is local; restore the backup if this machine lacks it).",
      "#    The state bucket still holds objects, so its deletion fails unless state_bucket_force_destroy = true",
      "#    is in terraform/bootstrap/terraform.tfvars and applied first (codemender-setup bootstrap).",
      f"gcloud storage cp gs://{bucket}/{gcp.STATE_BACKUP_OBJECT} terraform/bootstrap/   # if needed",
      "terraform -chdir=terraform/bootstrap destroy",
      "",
      "# 4. Delete the repository link and, if nothing else uses it, the connection:",
      f"gcloud builds repositories delete {conn['repository']} --connection={conn['connection']} {loc}",
      f"gcloud builds connections delete {conn['connection']} {loc}",
      "",
      "# 5. Delete the connection's regional OAuth token secret (<connection>-github-oauthtoken-*).",
      "#    Regional secrets need the regional endpoint (otherwise gcloud fails with INVALID_ARGUMENT); it is",
      "#    set per command so that step 6 still reaches the global secrets. With certificate-based access,",
      f"#    use https://secretmanager.{conn['region']}.rep.mtls.googleapis.com/ instead.",
      f"{regional_endpoint} gcloud secrets list --location={conn['region']} --project={conn['project']}",
      f"{regional_endpoint} gcloud secrets delete SECRET_NAME --location={conn['region']} --project={conn['project']}",
      "",
      "# 6. Delete the secrets Terraform only references (if you created them):",
      f"gcloud secrets delete {t.deployment.get('github_app_private_key_secret_id') or t.prefix + '-github-app-private-key'}"
      f" --project={t.project}",
      f"gcloud secrets delete {t.deployment.get('wiz_client_id_secret_id') or t.prefix + '-wiz-client-id'} "
      f"--project={t.project}",
      f"gcloud secrets delete {t.deployment.get('wiz_client_secret_secret_id') or t.prefix + '-wiz-client-secret'} "
      f"--project={t.project}",
      "",
      "# 7. Uninstall the Cloud Build GitHub App and your GitHub App in GitHub if nothing else uses them.",
  ]


def run_teardown(ctx: common.Context, args) -> int:
  if not args.print_only:
    raise common.UsageError("teardown only prints the steps (pass --print); it never deletes anything itself")
  t = Target(ctx, args.project)
  for line in teardown_steps(t):
    ctx.say(line)
  return common.EXIT_OK
