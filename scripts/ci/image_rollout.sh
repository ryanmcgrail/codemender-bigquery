#!/usr/bin/env bash
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

# Points the runner and worker Cloud Run jobs at a freshly pushed image, but
# only while no scan is running.
#
# Each stage of a scan starts a new Cloud Run job execution, and an execution
# always uses the job's image at the moment it starts. Switching the image in
# the middle of a scan would therefore run one scan's stages on different
# versions. So this script waits until the coordinator workflow has no active
# executions and neither job has a running execution, re-checking every
# POLL_SECONDS, and then updates both jobs to the image *digest* (not the
# tag), so later pushes to the tag cannot change what the jobs run.
#
# If the wait exceeds MAX_WAIT_HOURS the script fails without changing
# anything; re-running the build is safe.
#
# Environment:
#   PROJECT_ID, REGION, REPO_NAME, IMAGE_TAG   (required)
#   UPDATE_JOBS       only "true" updates the jobs (default: true)
#   IMAGE_NAME        image name in the repository (default: orchestrator)
#   RUNNER_JOB        default: REPO_NAME
#   WORKER_JOB        default: REPO_NAME with -runner replaced by -worker
#   WORKFLOW          default: REPO_NAME with -runner replaced by -coordinator
#   MAX_WAIT_HOURS    default: 12
#   MAX_WAIT_SECONDS  overrides MAX_WAIT_HOURS when set
#   POLL_SECONDS      default: 300

set -euo pipefail

: "${PROJECT_ID:?PROJECT_ID is required}"
: "${REGION:?REGION is required}"
: "${REPO_NAME:?REPO_NAME is required}"
: "${IMAGE_TAG:?IMAGE_TAG is required}"
UPDATE_JOBS="${UPDATE_JOBS:-true}"
IMAGE_NAME="${IMAGE_NAME:-orchestrator}"
RUNNER_JOB="${RUNNER_JOB:-${REPO_NAME}}"
WORKER_JOB="${WORKER_JOB:-${REPO_NAME/-runner/-worker}}"
WORKFLOW="${WORKFLOW:-${REPO_NAME/-runner/-coordinator}}"
MAX_WAIT_HOURS="${MAX_WAIT_HOURS:-12}"
POLL_SECONDS="${POLL_SECONDS:-300}"
MAX_ERRORS=3

if [[ "${UPDATE_JOBS}" != "true" ]]; then
  echo "UPDATE_JOBS=${UPDATE_JOBS}; leaving the Cloud Run jobs unchanged."
  exit 0
fi

if [[ -n "${MAX_WAIT_SECONDS:-}" ]]; then
  max_wait="${MAX_WAIT_SECONDS}"
elif [[ "${MAX_WAIT_HOURS}" =~ ^[0-9]+$ ]]; then
  max_wait=$(( MAX_WAIT_HOURS * 3600 ))
else
  echo "MAX_WAIT_HOURS must be a whole number of hours, got '${MAX_WAIT_HOURS}'." >&2
  exit 2
fi
if ! [[ "${max_wait}" =~ ^[0-9]+$ && "${POLL_SECONDS}" =~ ^[0-9]+$ ]]; then
  echo "MAX_WAIT_SECONDS and POLL_SECONDS must be whole numbers." >&2
  exit 2
fi

IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/${IMAGE_NAME}"

# Prints the digest (sha256:...) of IMAGE:$1, or nothing if it has none.
image_digest() {
  gcloud artifacts docker images describe "${IMAGE}:$1" \
    --project="${PROJECT_ID}" --format='value(image_summary.digest)' 2>/dev/null || true
}

digest="$(image_digest "${IMAGE_TAG}")"
if ! [[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "Could not resolve the digest of ${IMAGE}:${IMAGE_TAG} (got '${digest}')." >&2
  exit 1
fi
echo "Rolling out ${IMAGE}@${digest} (tag ${IMAGE_TAG})"
echo "  jobs: ${RUNNER_JOB}, ${WORKER_JOB}; workflow: ${WORKFLOW}; region: ${REGION}"

# Prints the number of active workflow executions plus running executions of
# either job. Fails (non-zero) if any of the lookups fails.
count_active() {
  local out n total=0
  out="$(gcloud workflows executions list "${WORKFLOW}" \
    --project="${PROJECT_ID}" --location="${REGION}" \
    --filter='state=ACTIVE' --format='value(name)')" || return 1
  n="$(printf '%s\n' "${out}" | grep -c . || true)"
  total=$(( total + n ))
  for job in "${RUNNER_JOB}" "${WORKER_JOB}"; do
    # A running execution has no completion time yet. Executions are listed
    # newest first, and a running one is always among the most recent.
    out="$(gcloud run jobs executions list --job="${job}" \
      --project="${PROJECT_ID}" --region="${REGION}" --limit=100 \
      --format='value(name,status.completionTime)')" || return 1
    n="$(printf '%s\n' "${out}" | awk -F'\t' 'NF > 0 && $1 != "" && $2 == ""' | grep -c . || true)"
    total=$(( total + n ))
  done
  echo "${total}"
}

start=${SECONDS}
errors=0
while true; do
  # A newer build that has already moved :latest owns the rollout from here.
  if [[ "${IMAGE_TAG}" != "latest" ]]; then
    latest="$(image_digest latest)"
    if [[ -n "${latest}" && "${latest}" != "${digest}" ]]; then
      echo "A newer image (${latest}) has been pushed as :latest since this build;"
      echo "leaving the rollout to that build. The jobs were not changed."
      exit 0
    fi
  fi

  if active="$(count_active)"; then
    errors=0
    if [[ "${active}" -eq 0 ]]; then
      break
    fi
    waited=$(( SECONDS - start ))
    if (( waited >= max_wait )); then
      echo "Gave up after ${waited}s: still waiting for ${active} active scan(s)." >&2
      echo "The Cloud Run jobs were not changed. Re-run this build once the scans" >&2
      echo "finish; re-running is safe." >&2
      exit 1
    fi
    echo "$(date -u +%FT%TZ) waiting for ${active} active scan(s) to finish before rolling out" \
      "(waited ${waited}s of ${max_wait}s; next check in ${POLL_SECONDS}s)"
  else
    errors=$(( errors + 1 ))
    echo "Could not check for running scans (attempt ${errors} of ${MAX_ERRORS})." >&2
    if (( errors >= MAX_ERRORS )); then
      echo "Not rolling out without knowing whether a scan is running. Check that the" >&2
      echo "build service account can list workflow and Cloud Run job executions," >&2
      echo "then re-run this build. The Cloud Run jobs were not changed." >&2
      exit 1
    fi
  fi
  sleep "${POLL_SECONDS}"
done

for job in "${RUNNER_JOB}" "${WORKER_JOB}"; do
  gcloud run jobs update "${job}" --image="${IMAGE}@${digest}" \
    --project="${PROJECT_ID}" --region="${REGION}" --quiet
done
echo "Rolled out ${IMAGE}@${digest} to ${RUNNER_JOB} and ${WORKER_JOB}."

if post_active="$(count_active 2>/dev/null)" && [[ "${post_active}" -gt 0 ]]; then
  echo "WARNING: ${post_active} active scan(s) detected immediately after updating the" >&2
  echo "Cloud Run jobs. A scan that started during the update window may run its" >&2
  echo "later stages on ${IMAGE}@${digest}; check the active workflow execution." >&2
fi

