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

"""`secrets`: store GitHub and Wiz credentials in Secret Manager.

Secret values are read without echo (or from a file or standard input) and
handed to gcloud on standard input or as a file path, never on the command
line, and are never printed. The values never enter Terraform state:
Terraform only references the App key and Wiz secrets, and token versions
added here are not managed by Terraform.

  secrets github-app    App private key -> <prefix>-github-app-private-key,
                        then github_app_id (and installation ID) in
                        deployment.yaml.
  secrets github-token  Personal access token fallback -> new version of
                        <prefix>-github-token (created by terraform/gcp).
  secrets wiz           Wiz client ID and secret -> <prefix>-wiz-client-id and
                        <prefix>-wiz-client-secret.
"""

import pathlib
import re
from typing import List, Optional, Sequence

from codemender_setup import common
from codemender_setup import config_edit

INSTALLATION_ID_RE = re.compile(r"^[1-9][0-9]*$")
LOCATION_RE = re.compile(r"^[a-z]+-[a-z]+[0-9]+$")


# Arguments ----------------------------------------------------------------------


def _add_target_arguments(parser) -> None:
  parser.add_argument("--project", help="project ID (default: project_id in deployment.yaml)")
  parser.add_argument("--secret-locations", metavar="REGIONS",
                      help="comma-separated regions for user-managed replication of new secrets "
                           "(default: automatic replication)")


def add_arguments(parser) -> None:
  sub = parser.add_subparsers(dest="secret_kind", metavar="KIND")
  sub.required = True

  p = sub.add_parser("github-app", help="store the GitHub App private key and turn the App on",
                     description="Stores the GitHub App private key in Secret Manager and sets "
                                 "github_app_id (and the installation ID) in deployment.yaml.")
  common.add_common_flags(p, in_subcommand=True)
  p.add_argument("--app-id", help="GitHub App ID (or client ID)")
  p.add_argument("--installation-id", help="installation ID (optional; looked up per repository when empty)")
  p.add_argument("--key-file", metavar="PEM", help="the App's private key file (.pem)")
  p.add_argument("--secret-id", help="secret name (default: <prefix>-github-app-private-key)")
  _add_target_arguments(p)
  config_edit.add_pr_argument(p)

  p = sub.add_parser("github-token", help="store a personal access token (fallback without a GitHub App)",
                     description="Adds a version to <prefix>-github-token, which terraform/gcp creates. "
                                 "Used only while github_app_id is not set.")
  common.add_common_flags(p, in_subcommand=True)
  p.add_argument("--token-file", metavar="FILE", help="read the token from FILE, or - for standard input "
                                                     "(default: prompt without echo)")
  _add_target_arguments(p)

  p = sub.add_parser("wiz", help="store the Wiz service account client ID and secret",
                     description="Creates or updates the two secrets the Wiz import reads.")
  common.add_common_flags(p, in_subcommand=True)
  p.add_argument("--client-id", help="Wiz service account client ID")
  p.add_argument("--client-secret-file", metavar="FILE",
                 help="read the client secret from FILE, or - for standard input (default: prompt without echo)")
  _add_target_arguments(p)


# gcloud helpers -----------------------------------------------------------------


def _gcloud(ctx: common.Context) -> str:
  gcloud = ctx.which("gcloud")
  if not gcloud:
    raise common.UsageError("gcloud not found; install the Google Cloud CLI (run `codemender-setup check`)")
  return gcloud


def _locations(args) -> List[str]:
  raw = getattr(args, "secret_locations", None) or ""
  locations = [l.strip() for l in raw.split(",") if l.strip()]
  bad = [l for l in locations if not LOCATION_RE.match(l)]
  if bad:
    raise common.UsageError(f"--secret-locations: {bad[0]!r} is not a region name")
  return locations


class SecretError(Exception):
  """A gcloud call failed; the message is safe to print."""


def enabled_versions(ctx: common.Context, gcloud: str, project: str, name: str) -> Optional[int]:
  """None if the secret does not exist, else its number of enabled versions."""
  res = ctx.run([gcloud, "secrets", "describe", name, f"--project={project}", "--format=value(name)"],
                timeout=120)
  if not res.ok:
    if "NOT_FOUND" in res.stderr or "not found" in res.stderr.lower():
      return None
    raise SecretError(f"gcloud secrets describe {name} failed: {res.stderr.strip()}")
  res = ctx.run([gcloud, "secrets", "versions", "list", name, f"--project={project}",
                 "--filter=state:ENABLED", "--format=value(name)"], timeout=120)
  if not res.ok:
    raise SecretError(f"gcloud secrets versions list {name} failed: {res.stderr.strip()}")
  return len([l for l in res.stdout.splitlines() if l.strip()])


def store(ctx: common.Context, gcloud: str, project: str, name: str, *,
          value: Optional[str] = None, data_file: Optional[pathlib.Path] = None,
          create: bool = True, ask_before_new_version: bool = True,
          locations: Sequence = ()) -> bool:
  """Creates the secret if needed and adds a version. Returns False if it did not.

  Exactly one of value (sent on standard input) and data_file (a path) is set.
  """
  assert (value is None) != (data_file is None)
  versions = enabled_versions(ctx, gcloud, project, name)
  if versions is None and not create:
    raise SecretError(f"secret {name} does not exist in {project}")
  if versions and ask_before_new_version and not ctx.confirm(
      f"{name} already has {versions} enabled version(s). Add a new version "
      "(the next job execution uses it)?"):
    ctx.say(f"{name}: left unchanged.")
    return False

  create_cmd = [gcloud, "secrets", "create", name, f"--project={project}"]
  if locations:
    create_cmd += ["--replication-policy=user-managed", f"--locations={','.join(locations)}"]
  else:
    create_cmd += ["--replication-policy=automatic"]
  add_cmd = [gcloud, "secrets", "versions", "add", name, f"--project={project}",
             f"--data-file={data_file if data_file is not None else '-'}"]

  if ctx.dry_run:
    if versions is None:
      ctx.say("would run: " + " ".join(create_cmd[1:]))
    source = f" ({'standard input' if value is not None else 'from the file'})"
    ctx.say("would run: " + " ".join(add_cmd[1:]) + source)
    return True

  if versions is None:
    res = ctx.run(create_cmd, timeout=120)
    if not res.ok:
      raise SecretError(f"gcloud secrets create {name} failed: {res.stderr.strip()}")
    ctx.say(f"Created secret {name}.")
  res = ctx.run(add_cmd, input_text=value, timeout=120)
  if not res.ok:
    raise SecretError(f"gcloud secrets versions add {name} failed: {res.stderr.strip()}")
  ctx.say(f"Added a new version to {name}.")
  return True


# Commands -----------------------------------------------------------------------


def _no_whitespace(value: str) -> Optional[str]:
  if not value:
    return "a value is required"
  return "must not contain whitespace" if re.search(r"\s", value) else None


def _check_key_file(value: str) -> Optional[str]:
  path = pathlib.Path(value).expanduser()
  if not path.is_file():
    return f"{value}: no such file"
  try:
    head = path.read_text(encoding="utf-8", errors="replace")
  except OSError as e:
    return f"{value}: {e.strerror}"
  if "-----BEGIN" not in head or "PRIVATE KEY-----" not in head:
    return f"{value}: not a PEM private key (expected a -----BEGIN ... PRIVATE KEY----- block)"
  return None


def run_github_app(ctx: common.Context, args) -> int:
  deployment = config_edit.read_deployment(ctx, args.project)
  project, prefix = deployment["project_id"], deployment["resource_prefix"]
  app_id = args.app_id or ctx.ask("GitHub App ID (or client ID)", check=_no_whitespace, flag="--app-id")
  if _no_whitespace(app_id):
    raise common.UsageError(f"--app-id: {_no_whitespace(app_id)}")
  installation_id = args.installation_id
  if installation_id is None and not ctx.non_interactive:
    installation_id = ctx.ask(
        "Installation ID (empty to look it up for each repository)", default="",
        check=lambda v: None if not v or INSTALLATION_ID_RE.match(v) else "must be a positive integer")
  if installation_id and not INSTALLATION_ID_RE.match(installation_id):
    raise common.UsageError("--installation-id must be a positive integer")
  key_file = args.key_file or ctx.ask("Path to the App's private key (.pem)", check=_check_key_file,
                                      flag="--key-file")
  if _check_key_file(key_file):
    raise common.UsageError(f"--key-file {_check_key_file(key_file)}")
  default_name = f"{prefix}-github-app-private-key"
  secret_id = args.secret_id or deployment.get("github_app_private_key_secret_id") or default_name

  gcloud = _gcloud(ctx)
  try:
    store(ctx, gcloud, project, secret_id, data_file=pathlib.Path(key_file).expanduser(),
          locations=_locations(args))
  except SecretError as e:
    ctx.say(str(e))
    ctx.say("Creating secrets needs Secret Manager Admin on the project.")
    return common.EXIT_FAILED

  path = ctx.repo_root / config_edit.DEPLOYMENT
  text = path.read_text(encoding="utf-8")
  new = config_edit.set_top_level(text, "github_app_id", app_id)
  if installation_id:
    new = config_edit.set_top_level(new, "github_app_installation_id", installation_id)
  if args.secret_id and args.secret_id != default_name:
    new = config_edit.set_top_level(new, "github_app_private_key_secret_id", args.secret_id)
  changed = config_edit.write_files(ctx, {config_edit.DEPLOYMENT: new})
  if not ctx.dry_run:
    ctx.say(f"\nOnce the key is stored, delete the local file: {key_file}")
    ctx.say("The jobs switch to the App when the deployment.yaml change is merged and applied.")
  return config_edit.after_change(
      ctx, args, changed, "Use the GitHub App for CodeMender scans",
      f"Sets github_app_id in deployment.yaml. The private key is in Secret Manager ({secret_id}).")


def run_github_token(ctx: common.Context, args) -> int:
  deployment = config_edit.read_deployment(ctx, args.project)
  project, prefix = deployment["project_id"], deployment["resource_prefix"]
  name = f"{prefix}-github-token"
  if deployment.get("github_app_id"):
    ctx.say(f"github_app_id is set in deployment.yaml, so the jobs use the GitHub App and do not mount {name}.")
    if not ctx.confirm("Store the token anyway?"):
      raise common.Cancelled("secrets github-token")
  gcloud = _gcloud(ctx)
  try:
    if enabled_versions(ctx, gcloud, project, name) is None:
      ctx.say(f"{name} does not exist yet. terraform/gcp creates it on the first deployment; "
              "run this again after that.")
      return common.EXIT_FAILED
    token = ctx.read_secret("GitHub token", args.token_file, "--token-file")
    if re.search(r"\s", token):
      raise common.UsageError("the token must be a single line without spaces")
    store(ctx, gcloud, project, name, value=token, create=False, ask_before_new_version=False)
  except SecretError as e:
    ctx.say(str(e))
    return common.EXIT_FAILED
  if not ctx.dry_run:
    ctx.say("The next job execution uses the new version.")
  return common.EXIT_OK


def run_wiz(ctx: common.Context, args) -> int:
  deployment = config_edit.read_deployment(ctx, args.project)
  project, prefix = deployment["project_id"], deployment["resource_prefix"]
  id_name = deployment.get("wiz_client_id_secret_id") or f"{prefix}-wiz-client-id"
  secret_name = deployment.get("wiz_client_secret_secret_id") or f"{prefix}-wiz-client-secret"
  client_id = args.client_id or ctx.ask("Wiz client ID", check=_no_whitespace, flag="--client-id")
  if _no_whitespace(client_id):
    raise common.UsageError(f"--client-id: {_no_whitespace(client_id)}")
  client_secret = ctx.read_secret("Wiz client secret", args.client_secret_file, "--client-secret-file")
  gcloud = _gcloud(ctx)
  locations = _locations(args)
  try:
    store(ctx, gcloud, project, id_name, value=client_id, locations=locations)
    store(ctx, gcloud, project, secret_name, value=client_secret, locations=locations)
  except SecretError as e:
    ctx.say(str(e))
    ctx.say("Creating secrets needs Secret Manager Admin on the project.")
    return common.EXIT_FAILED
  if not ctx.dry_run:
    ctx.say("\nTurn the import on per repository in repos.yaml (see repos.example.yaml):")
    ctx.say("    wiz:\n      enabled: true\n      min_severity: HIGH")
  return common.EXIT_OK


_RUNNERS = {"github-app": run_github_app, "github-token": run_github_token, "wiz": run_wiz}


def run(ctx: common.Context, args) -> int:
  return _RUNNERS[args.secret_kind](ctx, args)
