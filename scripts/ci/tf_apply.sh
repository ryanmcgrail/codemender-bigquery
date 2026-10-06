#!/bin/sh
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

# Apply pipeline: plan to a file, check it with the destroy guard, then apply
# exactly that saved plan.
#
# Usage: tf_apply.sh plan | guard | apply | all
#
#   plan   init, `terraform plan -out=tfplan`, and write tfplan.json
#   guard  run destroy_guard.py on tfplan.json (needs python3)
#   apply  `terraform apply tfplan`
#   all    acquire the pipeline mutex, skip if COMMIT_SHA is superseded, then
#          run plan -> guard -> apply (retrying transient state-lock or
#          stale-plan races up to TF_APPLY_MAX_ATTEMPTS times)
#
# Environment: see tf_init.sh and pipeline_lock.py, plus
#   ALLOW_DESTROY          true to let the guard pass a plan that deletes
#                          protected resources (default: false)
#   DESTROY_TRIGGER        name of the manual destroy trigger for error messages
#   CLOUDBUILD_REPO        Cloud Build v2 repository resource name (optional)
#   DEPLOY_BRANCH          deployed branch name (default: main)
#   COMMIT_SHA             commit being built (default: HEAD)
#   TF_APPLY_MAX_ATTEMPTS  max attempts on transient lock/stale-plan errors (default: 3)
#   TF_APPLY_RETRY_SECONDS sleep between retries (default: 2)

set -eu

if [ -d /workspace/.terraform-bin ]; then
  PATH="/workspace/.terraform-bin:$PATH"
  export PATH
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TF_DIR="${TF_DIR:-terraform/gcp}"
export TF_DIR
export TF_IN_AUTOMATION="${TF_IN_AUTOMATION:-1}"

do_plan() {
  sh "$SCRIPT_DIR/tf_init.sh" &&
  rm -f "$TF_DIR/tfplan" "$TF_DIR/tfplan.json" &&
  # Wait for a concurrent apply rather than failing on the state lock.
  terraform -chdir="$TF_DIR" plan -input=false -no-color -lock-timeout=15m -out=tfplan &&
  terraform -chdir="$TF_DIR" show -json tfplan > "$TF_DIR/tfplan.json"
}

do_guard() {
  python3 "$SCRIPT_DIR/destroy_guard.py" "$TF_DIR/tfplan.json"
}

do_apply() {
  if [ ! -f "$TF_DIR/tfplan" ]; then
    echo "No saved plan at $TF_DIR/tfplan; run '$0 plan' first." >&2
    exit 1
  fi
  terraform -chdir="$TF_DIR" apply -input=false -no-color -lock-timeout=15m tfplan
}

run_logged() {
  _log="$1"
  shift
  _rc=0
  "$@" >"$_log.out" 2>"$_log.err" || _rc=$?
  cat "$_log.out"
  cat "$_log.err" >&2
  cat "$_log.out" "$_log.err" >>"$_log"
  rm -f "$_log.out" "$_log.err"
  return "$_rc"
}

is_transient_tf_error() {
  grep -E -i \
    'Saved plan is stale|Error acquiring the state lock|Failed to lock state|conditionNotMet|default\.tflock|storage: object doesn'\''t exist' \
    "$1" >/dev/null 2>&1
}

do_all() {
  trap 'python3 "$SCRIPT_DIR/pipeline_lock.py" release || true' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  python3 "$SCRIPT_DIR/pipeline_lock.py" acquire

  _max_attempts="${TF_APPLY_MAX_ATTEMPTS:-3}"
  _retry_sleep="${TF_APPLY_RETRY_SECONDS:-2}"
  _attempt=1
  _log_file="${TMPDIR:-/tmp}/tf_apply_$$.log"

  while :; do
    _check_rc=0
    python3 "$SCRIPT_DIR/pipeline_lock.py" check-commit || _check_rc=$?
    if [ "$_check_rc" -eq 10 ]; then
      rm -f "$_log_file"
      exit 0
    elif [ "$_check_rc" -ne 0 ]; then
      rm -f "$_log_file"
      exit "$_check_rc"
    fi

    rm -f "$_log_file"
    _step_rc=0
    run_logged "$_log_file" do_plan || _step_rc=$?
    if [ "$_step_rc" -eq 0 ]; then
      # Protected deletions or unreadable plans are never transient; stop right away.
      do_guard || {
        _guard_rc=$?
        rm -f "$_log_file"
        exit "$_guard_rc"
      }
      run_logged "$_log_file" do_apply || _step_rc=$?
    fi

    if [ "$_step_rc" -eq 0 ]; then
      rm -f "$_log_file"
      break
    fi

    if [ "$_attempt" -lt "$_max_attempts" ] && is_transient_tf_error "$_log_file"; then
      echo "tf_apply: transient state lock or stale plan error (attempt $_attempt of $_max_attempts); re-running plan, guard and apply..." >&2
      rm -f "$_log_file"
      _attempt=$(( _attempt + 1 ))
      sleep "$_retry_sleep"
      continue
    fi

    rm -f "$_log_file"
    exit "$_step_rc"
  done

  python3 "$SCRIPT_DIR/pipeline_lock.py" record-applied
}

case "${1:-}" in
  plan) do_plan ;;
  guard) do_guard ;;
  apply) do_apply ;;
  all) do_all ;;
  *)
    echo "Usage: $0 plan | guard | apply | all" >&2
    exit 2
    ;;
esac
