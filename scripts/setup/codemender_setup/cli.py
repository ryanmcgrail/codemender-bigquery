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

"""Command-line dispatcher for codemender-setup."""

import argparse
import pathlib
import sys
from typing import Callable, Dict, List, Optional

from codemender_setup import __version__
from codemender_setup import check
from codemender_setup import common
from codemender_setup import config_edit
from codemender_setup import gcp
from codemender_setup import ops
from codemender_setup import pr_scans
from codemender_setup import secret_store
from codemender_setup import validate

# name -> (help, add_arguments, run), in the order of a first setup.
COMMANDS: Dict[str, tuple] = {
    "check": ("check tools, credentials, permissions and the repository (read-only)",
              check.add_arguments, check.run),
    "init": ("write deployment.yaml, repos.yaml and the local bootstrap terraform.tfvars",
             config_edit.add_init_arguments, config_edit.run_init),
    "connect": ("link this repository to Cloud Build (2nd-gen GitHub connection)",
                gcp.add_connect_arguments, gcp.run_connect),
    "bootstrap": ("create the state bucket, service accounts and triggers (terraform/bootstrap)",
                  gcp.add_bootstrap_arguments, gcp.run_bootstrap),
    "secrets": ("store the GitHub App key, a GitHub token or Wiz credentials in Secret Manager",
                secret_store.add_arguments, secret_store.run),
    "first-image": ("run the image trigger once so the jobs get a real runner image",
                    ops.add_first_image_arguments, ops.run_first_image),
    "add-repo": ("add a repository to repos.yaml",
                 config_edit.add_repo_arguments, config_edit.run_add_repo),
    "remove-repo": ("remove a repository from repos.yaml",
                    config_edit.remove_repo_arguments, config_edit.run_remove_repo),
    "set": ("set one deployment.yaml setting",
            config_edit.set_arguments, config_edit.run_set),
    "validate": ("check repos.yaml and deployment.yaml with Terraform's own rules, offline",
                 validate.add_arguments, validate.run),
    "doctor": ("check the deployed pipeline, deployment and secrets (read-only)",
               ops.add_doctor_arguments, ops.run_doctor),
    "pr-scans": ("check the prerequisites for pull request scans on GitHub Actions (read-only)",
                 pr_scans.add_arguments, pr_scans.run),
    "teardown": ("print the teardown steps for this deployment (deletes nothing)",
                 ops.add_teardown_arguments, ops.run_teardown),
}


def build_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
      prog="codemender-setup",
      description="Sets up and checks a GitOps CodeMender deployment in your copy of this repository.",
      epilog="Exit codes: 0 ok, 1 a check failed, 2 usage error, 3 cancelled.")
  common.add_common_flags(parser, in_subcommand=False)
  parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
  sub = parser.add_subparsers(dest="command", metavar="COMMAND")
  for name, (help_text, add_arguments, _) in COMMANDS.items():
    p = sub.add_parser(name, help=help_text, description=help_text)
    common.add_common_flags(p, in_subcommand=True)
    add_arguments(p)
  return parser


def main(argv: Optional[List[str]] = None, *,
         context_factory: Optional[Callable[..., common.Context]] = None) -> int:
  parser = build_parser()
  try:
    args = parser.parse_args(argv)
  except SystemExit as e:  # argparse exits 2 on usage errors, 0 on --help
    return int(e.code or 0)
  if not args.command:
    parser.print_help()
    return common.EXIT_USAGE

  if args.repo_root:
    root = pathlib.Path(args.repo_root).expanduser().resolve()
    if not (root / "terraform" / "gcp" / "config.tf").is_file():
      print(f"codemender-setup: {root} is not a copy of this repository "
            "(no terraform/gcp/config.tf)", file=sys.stderr)
      return common.EXIT_USAGE
  else:
    root = common.find_repo_root()
    if root is None:
      print("codemender-setup: run this inside your copy of the repository, or pass --repo-root",
            file=sys.stderr)
      return common.EXIT_USAGE

  factory = context_factory or common.Context
  ctx = factory(repo_root=root, yes=args.yes, non_interactive=args.non_interactive,
                dry_run=args.dry_run)
  _, _, run = COMMANDS[args.command]
  try:
    return run(ctx, args)
  except common.UsageError as e:
    ctx.warn(f"codemender-setup: {e}")
    return common.EXIT_USAGE
  except (common.Cancelled, KeyboardInterrupt):
    ctx.warn("\ncodemender-setup: cancelled")
    return common.EXIT_CANCELLED
