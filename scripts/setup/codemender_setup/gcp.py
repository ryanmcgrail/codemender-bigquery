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

"""`connect` and `bootstrap`: the one-time Google Cloud setup.

connect   links this repository to Cloud Build through a 2nd-gen GitHub
          connection (reusing a finished one), and writes the linked
          repository's resource name to terraform/bootstrap/terraform.tfvars.
bootstrap runs terraform/bootstrap (init, plan, confirm, apply), adds the
          image build service account to deployment.yaml, and copies the
          bootstrap state to the state bucket as a backup.
"""

import json
import pathlib
import re
import tempfile
from typing import Dict, List, Optional, Tuple
import uuid

EMPTY_TFSTATE_VERSION = "1.13.3"


def empty_tfstate(terraform_version: str = EMPTY_TFSTATE_VERSION) -> str:
  """Returns a minimal valid empty Terraform v4 state JSON string."""
  payload = {
      "version": 4,
      "terraform_version": terraform_version,
      "serial": 0,
      "lineage": str(uuid.uuid4()),
      "outputs": {},
      "resources": [],
  }
  return json.dumps(payload, indent=2) + "\n"

from codemender_setup import common
from codemender_setup import config_edit
from codemender_setup import yamlio

CONNECTION_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
LINK_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
SERVICE_AGENT_ROLE = "roles/secretmanager.admin"
BOOTSTRAP_DIR = pathlib.Path("terraform", "bootstrap")
STATE_BACKUP_OBJECT = "bootstrap-backup/terraform.tfstate"


def _gcloud(ctx: common.Context) -> str:
  gcloud = ctx.which("gcloud")
  if not gcloud:
    raise common.UsageError("gcloud not found; install the Google Cloud CLI (run `codemender-setup check`)")
  return gcloud


def _json(res: common.Result, what: str):
  if not res.ok:
    raise RuntimeError(f"{what} failed: {res.stderr.strip() or res.stdout.strip()}")
  try:
    return json.loads(res.stdout or "null")
  except ValueError:
    raise RuntimeError(f"{what}: unexpected output") from None


def _not_found(res: common.Result) -> bool:
  return not res.ok and ("NOT_FOUND" in res.stderr or "not found" in res.stderr.lower())


def normalize_remote(url: str) -> str:
  """Canonical https://github.com/<owner>/<repo>.git, lowercased, for comparing."""
  parsed = common.parse_github_remote(url)
  if not parsed:
    return url.strip().lower()
  host, owner, repo = parsed
  return f"https://{host}/{owner}/{repo}.git".lower()


def _bootstrap_tfvars(ctx: common.Context) -> Tuple[pathlib.Path, str]:
  path = ctx.repo_root / config_edit.BOOTSTRAP_TFVARS
  if not path.exists():
    raise common.UsageError(f"{config_edit.BOOTSTRAP_TFVARS} does not exist; run `init` first")
  return path, path.read_text(encoding="utf-8")


# connect ----------------------------------------------------------------------


def add_connect_arguments(parser) -> None:
  parser.add_argument("--project", help="project of the deployment (default: project_id in terraform.tfvars)")
  parser.add_argument("--connection-project",
                      help="project that holds the Cloud Build connection (default: --project)")
  parser.add_argument("--region", help="connection and trigger region (default: region in terraform.tfvars)")
  parser.add_argument("--connection", default=None,
                      help="name of the Cloud Build connection to create or reuse (default: discover existing or 'github')")
  parser.add_argument("--remote-uri",
                      help="https://github.com/<owner>/<repo>.git (default: the origin remote)")
  parser.add_argument("--link-name", help="name of the repository link in Cloud Build (default: the repository name)")


class _Connect:
  """State for one `connect` run."""

  def __init__(self, ctx: common.Context, gcloud: str, project: str, region: str, connection: str):
    self.ctx, self.gcloud = ctx, gcloud
    self.project, self.region, self.connection = project, region, connection
    self.loc = [f"--region={region}", f"--project={project}"]

  def run(self, *args: str, timeout: int = 300) -> common.Result:
    return self.ctx.run([self.gcloud, *args], timeout=timeout)

  def describe_connection(self) -> Optional[dict]:
    res = self.run("builds", "connections", "describe", self.connection, *self.loc, "--format=json")
    if _not_found(res):
      return None
    return _json(res, f"gcloud builds connections describe {self.connection}")

  def list_connections(self) -> List[dict]:
    res = self.run("builds", "connections", "list", *self.loc, "--format=json")
    if not res.ok:
      return []
    try:
      return _json(res, "gcloud builds connections list") or []
    except RuntimeError:
      return []

  def active_github_connections(self) -> List[Tuple[str, str]]:
    conns = self.list_connections()
    results = []
    for c in conns:
      if not isinstance(c, dict):
        continue
      if c.get("disabled") or "githubConfig" not in c or not c.get("name"):
        continue
      cid = c["name"].rstrip("/").split("/")[-1]
      stage = (c.get("installationState") or {}).get("stage", "unknown")
      results.append((cid, stage))
    return results

  def service_agent(self) -> str:
    res = self.run("projects", "describe", self.project, "--format=value(projectNumber)")
    number = res.stdout.strip()
    if not res.ok or not number.isdigit():
      raise RuntimeError(f"could not read the project number of {self.project}: {res.stderr.strip()}")
    return f"serviceAccount:service-{number}@gcp-sa-cloudbuild.iam.gserviceaccount.com"

  def agent_has_role(self, member: str) -> bool:
    res = self.run("projects", "get-iam-policy", self.project, "--format=json")
    policy = _json(res, f"gcloud projects get-iam-policy {self.project}") or {}
    return any(b.get("role") == SERVICE_AGENT_ROLE and member in b.get("members", [])
               for b in policy.get("bindings", []))

  def repositories(self) -> List[dict]:
    res = self.run("builds", "repositories", "list", f"--connection={self.connection}", *self.loc,
                   "--format=json")
    return _json(res, "gcloud builds repositories list") or []


def _wait_for_complete(ctx: common.Context, c: _Connect, conn: dict) -> bool:
  """Walks the user through the browser steps until the connection is COMPLETE."""
  while True:
    state = (conn or {}).get("installationState", {}) or {}
    stage = state.get("stage", "")
    if stage == "COMPLETE":
      return True
    ctx.say("")
    if stage == "PENDING_USER_OAUTH":
      ctx.say("Authorize Cloud Build to access GitHub on your behalf:")
    elif stage == "PENDING_INSTALL_APP":
      ctx.say("Install the Cloud Build GitHub App on this repository (only this one is enough):")
    else:
      ctx.say(f"The connection is not ready yet (stage {stage or 'unknown'}).")
    if state.get("message"):
      ctx.say(f"  {state['message']}")
    if state.get("actionUri"):
      ctx.say(f"  {state['actionUri']}")
    if ctx.non_interactive:
      ctx.say("\nFinish this in a browser, then run `codemender-setup connect` again.")
      return False
    ctx.out.write("Press Enter when you are done (Ctrl-C to stop): ")
    ctx.out.flush()
    if not ctx.stdin.readline():
      raise common.Cancelled("connect")
    conn = c.describe_connection()


def run_connect(ctx: common.Context, args) -> int:
  tfvars_path, tfvars = _bootstrap_tfvars(ctx)
  project = args.project or config_edit.read_tfvar(tfvars, "project_id")
  region = args.region or config_edit.read_tfvar(tfvars, "region") or "us-central1"
  if not project or config_edit.check_project(project):
    raise common.UsageError("no valid project ID; pass --project or run `init`")
  connection_project = args.connection_project or project
  if args.connection and not CONNECTION_NAME_RE.match(args.connection):
    raise common.UsageError("--connection: lowercase letters, digits and hyphens, starting with a letter")

  remote = args.remote_uri
  if not remote:
    git = ctx.which("git")
    res = ctx.run([git, "-C", str(ctx.repo_root), "remote", "get-url", "origin"], timeout=60) if git else None
    if not res or not res.ok:
      raise common.UsageError("could not read the origin remote; pass --remote-uri")
    remote = res.stdout.strip()
  parsed = common.parse_github_remote(remote)
  if not parsed or parsed[0] != "github.com":
    raise common.UsageError(f"{remote}: only github.com repositories are supported (not GHE.com or GHES)")
  _, owner, repo = parsed
  remote_uri = f"https://github.com/{owner}/{repo}.git"
  link_name = args.link_name or repo
  if not LINK_NAME_RE.match(link_name):
    raise common.UsageError(f"--link-name {link_name!r}: letters, digits, '.', '_' and '-' only")

  gcloud = _gcloud(ctx)
  connection = args.connection
  c = _Connect(ctx, gcloud, connection_project, region, connection or "")
  if not connection:
    active = c.active_github_connections()
    if active:
      ctx.say(f"Found {len(active)} existing Cloud Build GitHub connection(s) in {connection_project} ({region}):")
      for cid, stage in active:
        ctx.say(f"  - {cid} (stage: {stage})")
      complete = [cid for cid, stage in active if stage == "COMPLETE"]
      candidate = complete[0] if complete else active[0][0]
      if ctx.confirm(f"Reuse existing connection '{candidate}'?", default=True):
        connection = candidate
      elif candidate != "github":
        connection = "github"
      else:
        connection = ctx.ask("Connection name to use or create",
                             check=lambda v: None if CONNECTION_NAME_RE.match(v) else "--connection: lowercase letters, digits and hyphens, starting with a letter",
                             flag="--connection")
    else:
      connection = "github"
  c.connection = connection
  ctx.say(f"Connection {connection} in {connection_project} ({region}) for {remote_uri}")
  try:
    conn = c.describe_connection()
    granted_member = None
    if conn is None:
      apis = ["cloudbuild.googleapis.com", "secretmanager.googleapis.com"]
      member = None if ctx.dry_run else c.service_agent()
      if ctx.dry_run:
        ctx.say(f"would run: services enable {' '.join(apis)} --project={connection_project}")
        ctx.say(f"would grant {SERVICE_AGENT_ROLE} to the Cloud Build service agent (if it lacks it)")
        ctx.say(f"would run: builds connections create github {connection} {' '.join(c.loc)}")
        ctx.say(f"would link {remote_uri} as {link_name}")
        ctx.say(f"would set cloudbuild_repository in {config_edit.BOOTSTRAP_TFVARS}")
        return common.EXIT_OK
      res = c.run("services", "enable", *apis, f"--project={connection_project}", timeout=600)
      if not res.ok:
        raise RuntimeError(f"gcloud services enable failed: {res.stderr.strip()}")
      if not c.agent_has_role(member):
        ctx.say(f"The Cloud Build service agent needs {SERVICE_AGENT_ROLE} to store the connection's "
                "GitHub token. It can be removed once the connection is complete.")
        if not ctx.confirm(f"Grant {SERVICE_AGENT_ROLE} to {member.split(':', 1)[1]}?", default=True):
          raise common.Cancelled("connect")
        res = c.run("projects", "add-iam-policy-binding", connection_project, f"--member={member}",
                    f"--role={SERVICE_AGENT_ROLE}", "--condition=None", "--format=none")
        if not res.ok:
          raise RuntimeError(f"granting {SERVICE_AGENT_ROLE} failed: {res.stderr.strip()}")
        granted_member = member
      res = c.run("builds", "connections", "create", "github", connection, *c.loc)
      if not res.ok:
        raise RuntimeError(f"gcloud builds connections create failed: {res.stderr.strip()}")
      conn = c.describe_connection()
    elif conn.get("disabled"):
      raise RuntimeError(f"connection {connection} exists but is disabled; enable it or pick another name")
    elif "githubConfig" not in conn:
      raise RuntimeError(f"connection {connection} exists but is not a github.com connection; "
                         "pick another name with --connection")
    else:
      ctx.say(f"Reusing connection {connection}.")

    if not _wait_for_complete(ctx, c, conn):
      return common.EXIT_FAILED
    ctx.say("Connection is complete.")

    if granted_member and ctx.confirm(
        f"Remove {SERVICE_AGENT_ROLE} from the Cloud Build service agent again "
        "(it is only needed while a connection is set up)?", default=True):
      res = c.run("projects", "remove-iam-policy-binding", connection_project, f"--member={granted_member}",
                  f"--role={SERVICE_AGENT_ROLE}", "--condition=None", "--format=none")
      if res.ok:
        ctx.say("Removed.")
      else:
        ctx.say(f"Could not remove it ({res.stderr.strip()}); remove it by hand.")

    wanted = normalize_remote(remote_uri)
    linked = next((r for r in c.repositories() if normalize_remote(r.get("remoteUri", "")) == wanted), None)
    if linked:
      name = linked["name"]
      ctx.say(f"Repository already linked: {name}")
    else:
      if ctx.dry_run:
        ctx.say(f"would run: builds repositories create {link_name} --remote-uri={remote_uri} "
                f"--connection={connection} {' '.join(c.loc)}")
        name = (f"projects/{connection_project}/locations/{region}/connections/{connection}"
                f"/repositories/{link_name}")
      else:
        res = c.run("builds", "repositories", "create", link_name, f"--remote-uri={remote_uri}",
                    f"--connection={connection}", *c.loc)
        if not res.ok:
          raise RuntimeError(f"gcloud builds repositories create failed: {res.stderr.strip()}\n"
                             "Check that the Cloud Build GitHub App is installed on this repository.")
        name = (f"projects/{connection_project}/locations/{region}/connections/{connection}"
                f"/repositories/{link_name}")
        ctx.say(f"Linked {remote_uri} as {name}")
  except RuntimeError as e:
    ctx.say(str(e))
    return common.EXIT_FAILED

  # The trigger region must match the connection's region.
  name_region = re.match(r"^projects/[^/]+/locations/([^/]+)/", name)
  new = config_edit.set_tfvar(tfvars, "cloudbuild_repository", yamlio.hcl_string(name))
  if name_region and config_edit.read_tfvar(tfvars, "region") not in (None, name_region.group(1)):
    ctx.say(f"region in terraform.tfvars differs from the connection's region; setting it to {name_region.group(1)}.")
    new = config_edit.set_tfvar(new, "region", yamlio.hcl_string(name_region.group(1)))
  config_edit.write_files(ctx, {config_edit.BOOTSTRAP_TFVARS: new})
  if not ctx.dry_run:
    ctx.say("\nNext: `codemender-setup bootstrap` creates the state bucket, service accounts and triggers.")
  return common.EXIT_OK


# bootstrap --------------------------------------------------------------------


def add_bootstrap_arguments(parser) -> None:
  parser.add_argument("--skip-backup", action="store_true",
                      help="do not copy the bootstrap state to the state bucket afterwards")
  config_edit.add_pr_argument(parser)


def _terraform(ctx: common.Context) -> str:
  terraform = ctx.which("terraform")
  if not terraform:
    raise common.UsageError("terraform not found; install Terraform 1.11 or later (run `codemender-setup check`)")
  res = ctx.run([terraform, "version", "-json"], timeout=60)
  version = ""
  if res.ok:
    try:
      version = json.loads(res.stdout).get("terraform_version", "")
    except ValueError:
      version = res.stdout
  if not version:
    res = ctx.run([terraform, "version"], timeout=30)
    version = common.parse_terraform_version(res.stdout if res.ok else "")
  have = common.version_tuple(version)
  if not have or have < common.MIN_TERRAFORM:
    raise common.UsageError(f"terraform {version or '(unknown version)'} is too old; 1.11 or later is needed")
  return terraform


def _check_bootstrap_tfvars(text: str) -> None:
  repo = config_edit.read_tfvar(text, "cloudbuild_repository") or ""
  if not config_edit.CONNECTION_REPO_RE.match(repo):
    raise common.UsageError("cloudbuild_repository is not set in terraform/bootstrap/terraform.tfvars; "
                            "run `codemender-setup connect` first")
  approvers = re.search(r"^\s*approvers\s*=\s*\[(.*?)\]", text, re.M | re.S)
  if not approvers or not re.search(r'"[^"]+"', approvers.group(1)):
    raise common.UsageError("approvers is empty in terraform/bootstrap/terraform.tfvars; the destroy "
                            "trigger needs at least one approver")


def reconcile_deployment(text: str, outputs: Dict[str, object]) -> Tuple[str, List[str]]:
  """Adds the image build account to deployment.yaml. Returns (text, warnings)."""
  warnings = []
  scalars = yamlio.top_level_scalars(text)
  snippet = str(outputs.get("deployment_yaml_snippet", ""))
  for key in ("project_id", "region", "resource_prefix"):
    m = re.search(rf"^{key}:\s*(\S+)\s*$", snippet, re.M)
    if m and scalars.get(key) and scalars[key] != m.group(1):
      warnings.append(f"deployment.yaml has {key}: {scalars[key]}, the bootstrap expects {m.group(1)}")
  account = str(outputs.get("image_build_service_account", ""))
  if not account:
    return text, warnings
  current = [yamlio.plain_value(v) for v in _list_items(text, "cloudbuild_service_account_emails")]
  if account in current:
    return text, warnings
  return config_edit.set_top_level(text, "cloudbuild_service_account_emails", current + [account]), warnings


def _list_items(text: str, key: str) -> List[str]:
  lines = text.splitlines()
  out: List[str] = []
  inside = False
  for line in lines:
    if re.match(rf"^{re.escape(key)}:\s*(#.*)?$", line):
      inside = True
      continue
    if inside:
      m = re.match(r"^\s+-\s*(.*?)\s*(#.*)?$", line)
      if m:
        out.append(m.group(1))
      elif line.strip() and not line.lstrip().startswith("#"):
        break
  return out


def state_bucket_name(tfvars: str) -> Optional[str]:
  """The bootstrap's state bucket, as main.tf names it."""
  explicit = config_edit.read_tfvar(tfvars, "state_bucket_name")
  if explicit:
    return explicit
  project = config_edit.read_tfvar(tfvars, "project_id")
  prefix = config_edit.read_tfvar(tfvars, "resource_prefix") or "codemender"
  return f"{prefix}-tfstate-{project}" if project else None


def state_prefix(tfvars: str) -> str:
  """Object prefix of the deployment state inside the state bucket."""
  prefix = config_edit.read_tfvar(tfvars, "state_prefix")
  return prefix.strip().strip("/") if prefix else "terraform/gcp"


def _restore_state(ctx: common.Context, tfvars: str, state: pathlib.Path) -> None:
  """Offers to restore a backed-up bootstrap state when there is no local one."""
  if state.exists():
    return
  gcloud, bucket = ctx.which("gcloud"), state_bucket_name(tfvars)
  if not gcloud or not bucket:
    return
  source = f"gs://{bucket}/{STATE_BACKUP_OBJECT}"
  res = ctx.run([gcloud, "storage", "ls", source], timeout=120)
  if not res.ok:
    return  # first run, or no access: nothing to restore
  ctx.say(f"There is no local bootstrap state, but a backup exists at {source}.")
  ctx.say("Without it, Terraform would try to create the existing bucket, service accounts and triggers again.")
  if not ctx.confirm("Restore it before planning?", default=True):
    ctx.say("Continuing without the backup.")
    return
  if ctx.dry_run:
    ctx.say(f"would run: storage cp {source} {state}")
    return
  res = ctx.run([gcloud, "storage", "cp", source, str(state)], timeout=300)
  if not res.ok:
    raise RuntimeError(f"restoring {source} failed: {res.stderr.strip()}")
  ctx.say(f"Restored {state.relative_to(ctx.repo_root)}.")


def seed_initial_state(ctx: common.Context, bucket: str, prefix: str,
                       terraform_version: str = EMPTY_TFSTATE_VERSION) -> bool:
  """Seeds an empty Terraform state in GCS if none exists yet.

  Terraform's GCS backend requires default.tfstate to exist for read-only
  operations like `terraform plan -lock=false`. If missing, `terraform init`
  attempts to create it with a lock write, which fails under read-only PR checks.
  """
  gcloud = ctx.which("gcloud")
  if not gcloud:
    ctx.say("\nCould not seed initial empty Terraform state: gcloud not found.")
    return False

  clean_bucket = bucket.removeprefix("gs://").strip("/")
  clean_prefix = prefix.strip().strip("/")
  target = f"gs://{clean_bucket}/{clean_prefix}/default.tfstate" if clean_prefix else f"gs://{clean_bucket}/default.tfstate"
  res = ctx.run([gcloud, "storage", "ls", target], timeout=120)
  if res.ok:
    return True

  if ctx.dry_run:
    ctx.say(f"would seed initial empty Terraform state at {target}")
    return True

  tmp_path = None
  try:
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix="cm-empty-tfstate-",
                                    suffix=".tfstate", delete=False) as f:
      tmp_path = pathlib.Path(f.name)
      f.write(empty_tfstate(terraform_version))
    res = ctx.run([gcloud, "storage", "cp", str(tmp_path), target], timeout=300)
    if res.ok:
      ctx.say(f"\nSeeded initial empty Terraform state at {target} "
              "so first-time pull request plan checks can run read-only.")
      return True
    err = (res.stderr or res.stdout).strip()
    ctx.say(f"\nCould not seed initial empty Terraform state at {target}"
            f"{': ' + err if err else '.'}")
    return False
  finally:
    if tmp_path is not None:
      tmp_path.unlink(missing_ok=True)


def run_bootstrap(ctx: common.Context, args) -> int:
  tfvars_path, tfvars = _bootstrap_tfvars(ctx)
  _check_bootstrap_tfvars(tfvars)
  terraform = _terraform(ctx)
  workdir = ctx.repo_root / BOOTSTRAP_DIR
  env = common.tf_env(ctx.environ)

  def tf(*tf_args: str, timeout: int = 1800) -> common.Result:
    return ctx.run([terraform, f"-chdir={workdir}", *tf_args], env=env, cwd=ctx.repo_root, timeout=timeout)

  try:
    _restore_state(ctx, tfvars, workdir / "terraform.tfstate")
  except RuntimeError as e:
    ctx.say(str(e))
    return common.EXIT_FAILED

  ctx.say("terraform init ...")
  res = tf("init", "-input=false", "-no-color")
  if not res.ok:
    ctx.say(res.stdout + res.stderr)
    return common.EXIT_FAILED

  with tempfile.TemporaryDirectory(prefix="codemender-bootstrap-") as tmp:
    plan_file = pathlib.Path(tmp) / "bootstrap.tfplan"
    ctx.say("terraform plan ...")
    res = tf("plan", "-input=false", "-no-color", "-detailed-exitcode", f"-out={plan_file}")
    if res.returncode == 1:
      ctx.say(res.stdout + res.stderr)
      return common.EXIT_FAILED
    ctx.say(res.stdout.rstrip())
    changes = res.returncode == 2
    if ctx.dry_run:
      ctx.say("\n--dry-run: the plan was not applied.")
      return common.EXIT_OK
    if changes:
      if not ctx.confirm("Apply this plan?"):
        raise common.Cancelled("bootstrap")
      ctx.say("terraform apply ...")
      res = tf("apply", "-input=false", "-no-color", str(plan_file))
      ctx.say((res.stdout + ("\n" + res.stderr if res.stderr else "")).rstrip())
      if not res.ok:
        ctx.say("The apply failed. Fix the problem and run `codemender-setup bootstrap` again; "
                "Terraform continues from what was created.")
        return common.EXIT_FAILED
    else:
      ctx.say("No changes to apply.")

  res = tf("output", "-json", timeout=300)
  try:
    outputs = {k: v.get("value") for k, v in json.loads(res.stdout or "{}").items()} if res.ok else {}
  except (ValueError, AttributeError):
    outputs = {}

  code = common.EXIT_OK
  bucket = outputs.get("state_bucket") or state_bucket_name(tfvars)
  state = workdir / "terraform.tfstate"
  if bucket and state.exists() and not args.skip_backup:
    gcloud = ctx.which("gcloud")
    target = f"gs://{bucket}/{STATE_BACKUP_OBJECT}"
    res = ctx.run([gcloud, "storage", "cp", str(state), target], timeout=300) if gcloud else None
    if res and res.ok:
      ctx.say(f"\nBacked up the bootstrap state to {target} (the bucket keeps older versions).")
    else:
      ctx.say(f"\nCould not back up the bootstrap state to {target}"
              f"{': ' + res.stderr.strip() if res else ' (gcloud not found)'}.")
      ctx.say(f"Keep {state.relative_to(ctx.repo_root)} safe: you need it to change or remove the triggers.")
      code = common.EXIT_FAILED

  if bucket:
    prefix = state_prefix(tfvars)
    if not seed_initial_state(ctx, bucket, prefix):
      code = common.EXIT_FAILED

  deployment_path = ctx.repo_root / config_edit.DEPLOYMENT
  changed: List[pathlib.Path] = []
  if deployment_path.exists() and outputs:
    text = deployment_path.read_text(encoding="utf-8")
    new, warnings = reconcile_deployment(text, outputs)
    for w in warnings:
      ctx.say(f"WARNING: {w}")
    changed = config_edit.write_files(ctx, {config_edit.DEPLOYMENT: new})

  triggers = outputs.get("triggers") or {}
  if isinstance(triggers, dict) and triggers.get("plan"):
    project = config_edit.read_tfvar(tfvars, "project_id") or "<project>"
    ctx.say(f"\nMake the plan trigger's check a required status check on the deployed branch: "
            f"{triggers['plan']} ({project}). It shows up after the first pull request has run it.")
  if changed:
    after = config_edit.after_change(ctx, args, changed, "Let the image build account roll out images",
                                     "Adds the bootstrap's image build service account to "
                                     "cloudbuild_service_account_emails.")
    code = code or after
  return code
