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

# Stages the CodeMender CLI binary as ./cm for the runner image build
# (cloudbuild.yaml and .github/workflows/build_runner_image.yml).
#
# Environment:
#   CM_VERSION  Release to download. Empty (the default) means "stable", the
#               latest release.
#   CM_SHA256   Optional sha256 of the extracted cm binary. When set, the
#               binary must match it; use it with CM_VERSION to require one
#               exact binary. When empty, whatever release CM_VERSION names
#               is accepted.
#   CM_FETCH    "gcloud" (default): download with the caller's gcloud
#               credentials. "curl": anonymous download over the Artifact
#               Registry REST API, for CI systems without gcloud credentials.
#
# A ./cm that is already in the working directory is used as is (and still
# checked against CM_SHA256 when that is set). Otherwise two published
# checksums are verified:
#   - the SHA-256 Artifact Registry records for the downloaded zip, and
#   - the binary's SHA-256 in the release manifest (stable.json) published
#     with each release, the same check `cm update` makes. Releases published
#     without a manifest get the first check only.
# Both catch a truncated, corrupted or mixed-up download. They come from the
# same repository as the binary, so they do not protect against a compromised
# release; CM_SHA256 does.
set -euo pipefail

readonly PROJECT=cmoc-prod
readonly LOCATION=us
readonly REPOSITORY=codemender-cli-production
readonly PACKAGE=cm
readonly NAME=cm-linux-amd64.zip
readonly MANIFEST=stable.json
readonly PLATFORM=linux-amd64
readonly API=https://artifactregistry.googleapis.com
readonly REPO_PATH="projects/${PROJECT}/locations/${LOCATION}/repositories/${REPOSITORY}"

version="${CM_VERSION:-}"
version="${version:-stable}"
fetch="${CM_FETCH:-gcloud}"

if [[ ! "${version}" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "CM_VERSION '${version}' is not a valid release name." >&2
  exit 2
fi
if [[ "${fetch}" != gcloud && "${fetch}" != curl ]]; then
  echo "CM_FETCH must be gcloud or curl, not '${fetch}'." >&2
  exit 2
fi

# download NAME: fetches file NAME of the release into the working directory.
download() {
  local name="$1"
  if [[ "${fetch}" == gcloud ]]; then
    gcloud artifacts generic download \
      --project="${PROJECT}" --location="${LOCATION}" --repository="${REPOSITORY}" \
      --package="${PACKAGE}" --version="${version}" --name="${name}" --destination=./
  else
    local encoded="${PACKAGE}%3A${version}%3A${name}"
    curl -fsSL -o "${name}" "${API}/download/v1/${REPO_PATH}/files/${encoded}:download?alt=media"
  fi
}

# describe NAME OUT: writes Artifact Registry's metadata for file NAME to OUT.
describe() {
  local name="$1" out="$2"
  if [[ "${fetch}" == gcloud ]]; then
    gcloud artifacts files describe "${PACKAGE}:${version}:${name}" \
      --project="${PROJECT}" --location="${LOCATION}" --repository="${REPOSITORY}" \
      --format=json >"${out}"
  else
    curl -fsSL -o "${out}" "${API}/v1/${REPO_PATH}/files/${PACKAGE}%3A${version}%3A${name}"
  fi
}

if [[ -f ./cm ]]; then
  echo "Using the pre-staged ./cm binary."
else
  echo "Downloading CodeMender CLI release '${version}'."
  download "${NAME}"
  describe "${NAME}" cm-file.json
  manifest_arg=""
  if download "${MANIFEST}" 2>/dev/null; then
    manifest_arg="${MANIFEST}"
  else
    echo "Release '${version}' has no ${MANIFEST} manifest; checking the zip's published SHA-256 only."
  fi

  python3 - "${NAME}" cm-file.json "${PLATFORM}" ${manifest_arg:+"${manifest_arg}"} <<'PY'
import base64
import hashlib
import json
import string
import sys
import zipfile


def sha256(data):
  return hashlib.sha256(data).hexdigest()


def fail(message):
  sys.exit(message + " If the release changed during the download, run the build again.")


zip_path, meta_path, platform = sys.argv[1:4]
manifest_path = sys.argv[4] if len(sys.argv) > 4 else ""

# 1. The zip against the SHA-256 Artifact Registry records for it. gcloud
#    prints it as hex, the REST API as base64.
with open(meta_path, encoding="utf-8") as f:
  meta = json.load(f)
values = [h.get("value", "") for h in meta.get("hashes", []) if h.get("type") == "SHA256"]
if not values:
  sys.exit("Artifact Registry published no SHA-256 for " + zip_path + "; not using it.")
published = values[0]
if len(published) == 64 and all(c in string.hexdigits for c in published):
  expected_zip = published.lower()
else:
  try:
    expected_zip = base64.b64decode(published, validate=True).hex()
  except ValueError:
    sys.exit("Could not read the published SHA-256 " + repr(published) + ".")
with open(zip_path, "rb") as f:
  actual_zip = sha256(f.read())
if actual_zip != expected_zip:
  fail(zip_path + ": SHA-256 " + actual_zip + " does not match the published " + expected_zip + ".")
print(zip_path + ": matches the SHA-256 Artifact Registry publishes (" + expected_zip + ").")

# 2. The binary inside against the release manifest, as `cm update` does.
with zipfile.ZipFile(zip_path) as z:
  if "cm" not in z.namelist():
    sys.exit(zip_path + " does not contain a cm binary.")
  actual_bin = sha256(z.read("cm"))
if manifest_path:
  with open(manifest_path, encoding="utf-8") as f:
    manifest = json.load(f)
  expected_bin = str((manifest.get("platforms") or {}).get(platform, "")).lower()
  if not expected_bin:
    sys.exit(manifest_path + " lists no " + platform + " binary; not using the download.")
  if actual_bin != expected_bin:
    fail("cm: SHA-256 " + actual_bin + " does not match " + expected_bin + " in " + manifest_path + ".")
  print(
      "cm: matches the release manifest (version " + str(manifest.get("version", "?"))
      + ", " + expected_bin + ")."
  )
PY

  python3 -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extract("cm", ".")' "${NAME}"
  rm -f "${NAME}" cm-file.json "${MANIFEST}"
fi

chmod +x ./cm
if [[ -n "${CM_SHA256:-}" ]]; then
  echo "${CM_SHA256}  cm" | sha256sum -c -
fi
./cm --version
