#!/usr/bin/env python3
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
"""Stops an automatic apply that would delete data-holding resources.

Reads the JSON form of a saved plan (`terraform show -json tfplan`) and fails
when any protected resource would be deleted, including a replacement
(delete then create, or create then delete). Removing a resource from state
without destroying it ("forget") is allowed.

Pass --allow-destroy, or set ALLOW_DESTROY=true, to list the deletions but
let the apply go ahead. The pipeline only does that from a separate,
approval-gated trigger.

Standard library only, so it runs in any python3 image.
"""

import argparse
import json
import os
import sys

# Resource types whose deletion loses data or breaks running scans.
PROTECTED_TYPES = frozenset({
    "google_artifact_registry_repository",
    "google_bigquery_dataset",
    "google_bigquery_table",
    "google_secret_manager_secret",
    "google_secret_manager_secret_version",
    "google_storage_bucket",
})

_TRUE_VALUES = frozenset({"1", "true", "yes"})


def protected_deletions(plan):
  """Returns (address, actions) for each protected resource being deleted."""
  found = []
  for change in plan.get("resource_changes") or []:
    if change.get("mode") != "managed":
      continue
    if change.get("type") not in PROTECTED_TYPES:
      continue
    actions = (change.get("change") or {}).get("actions") or []
    if "delete" in actions:
      found.append((change.get("address", "?"), list(actions)))
  return found


def _env_allows_destroy():
  return os.environ.get("ALLOW_DESTROY", "").strip().lower() in _TRUE_VALUES


def _destroy_trigger_name():
  trigger = os.environ.get("DESTROY_TRIGGER", "").strip()
  if trigger:
    return trigger
  prefix = os.environ.get("RESOURCE_PREFIX", "").strip()
  if prefix:
    return f"{prefix}-tf-apply-destroy"
  return "<prefix>-tf-apply-destroy"


def main(argv=None):
  parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
  parser.add_argument("plan_json", help="output of `terraform show -json tfplan`")
  parser.add_argument(
      "--allow-destroy",
      action="store_true",
      help="report protected deletions but do not fail",
  )
  args = parser.parse_args(argv)

  try:
    with open(args.plan_json, encoding="utf-8") as f:
      plan = json.load(f)
  except (OSError, ValueError) as e:
    print(f"destroy guard: cannot read {args.plan_json}: {e}", file=sys.stderr)
    return 2
  if not isinstance(plan, dict):
    print(f"destroy guard: {args.plan_json} is not a Terraform plan", file=sys.stderr)
    return 2

  deletions = protected_deletions(plan)
  if not deletions:
    print("destroy guard: no protected resources are deleted or replaced.")
    return 0

  allow = args.allow_destroy or _env_allows_destroy()
  print("destroy guard: this plan deletes or replaces protected resources:")
  for address, actions in deletions:
    print(f"  - {address} ({', '.join(actions)})")

  if allow:
    print("destroy guard: allowed for this run (ALLOW_DESTROY is set).")
    return 0

  trigger_name = _destroy_trigger_name()
  print(
      "\ndestroy guard: stopping before apply. Nothing was changed.\n"
      f"If these deletions are intended, an approver can run the {trigger_name}\n"
      "trigger, which builds and applies the current tip of the deployed branch\n"
      "after a manual approval. Before approving, verify that the build's commit\n"
      "SHA is still the branch HEAD (if a newer commit has landed since the\n"
      "trigger was started, reject the pending build and run the trigger again).\n"
      "Otherwise, fix the change and merge again.",
      file=sys.stderr,
  )
  return 1


if __name__ == "__main__":
  sys.exit(main())
