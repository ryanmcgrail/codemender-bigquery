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

"""Unit tests for scripts/ci/stage_cm.sh, run against stub gcloud and curl."""

import base64
import hashlib
import io
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import textwrap
import unittest
import zipfile

import yaml

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "ci" / "stage_cm.sh"
_BASH = shutil.which("bash")

# Both stubs serve files from $STUB_DIR/files/<release>/<name> and log their
# arguments to $STUB_DIR/calls.
_GCLOUD = textwrap.dedent("""\
    #!/usr/bin/env bash
    echo "gcloud $*" >>"$STUB_DIR/calls"
    version=stable name="" dest=""
    for a in "$@"; do
      case "$a" in
        --version=*) version="${a#--version=}" ;;
        --name=*) name="${a#--name=}" ;;
        --destination=*) dest="${a#--destination=}" ;;
      esac
    done
    if [[ "$1 $2 $3" == "artifacts generic download" ]]; then
      src="$STUB_DIR/files/$version/$name"
      [[ -f "$src" ]] || { echo "not found: $src" >&2; exit 1; }
      cp "$src" "$dest/$name"
    elif [[ "$1 $2 $3" == "artifacts files describe" ]]; then
      IFS=: read -r _ version name <<<"$4"
      cat "$STUB_DIR/files/$version/$name.describe-hex.json"
    else
      exit 3
    fi
    """)
_CURL = textwrap.dedent("""\
    #!/usr/bin/env bash
    echo "curl $*" >>"$STUB_DIR/calls"
    out="" url=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        -o) out="$2"; shift 2 ;;
        -*) shift ;;
        *) url="$1"; shift ;;
      esac
    done
    id="${url##*/files/}"
    id="${id%%:download*}"
    id="${id//%3A/:}"
    IFS=: read -r _ version name <<<"$id"
    if [[ "$url" == *":download"* ]]; then
      src="$STUB_DIR/files/$version/$name"
    else
      src="$STUB_DIR/files/$version/$name.describe-b64.json"
    fi
    [[ -f "$src" ]] || { echo "curl: (22) 404" >&2; exit 22; }
    cp "$src" "$out"
    """)


def _cm_script(version: str) -> bytes:
  return f'#!/bin/sh\necho "cm version {version}"\n'.encode()


@unittest.skipUnless(_BASH and shutil.which("sha256sum"), "needs bash and sha256sum")
class StageCmTest(unittest.TestCase):

  def setUp(self):
    self.tmp = pathlib.Path(tempfile.mkdtemp())
    self.addCleanup(shutil.rmtree, self.tmp)
    self.stub = self.tmp / "stub"
    self.bin = self.tmp / "bin"
    self.work = self.tmp / "work"
    for d in (self.stub, self.bin, self.work):
      d.mkdir()
    for name, body in (("gcloud", _GCLOUD), ("curl", _CURL)):
      path = self.bin / name
      path.write_text(body)
      path.chmod(0o755)

  def publish(self, version, cm_version, *, manifest=True, zip_hash=None, bin_hash=None):
    """Publishes a fake release; returns the sha256 of its cm binary."""
    binary = _cm_script(cm_version)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
      z.writestr("cm", binary)
    data = buf.getvalue()
    d = self.stub / "files" / version
    d.mkdir(parents=True, exist_ok=True)
    (d / "cm-linux-amd64.zip").write_bytes(data)
    digest = hashlib.sha256(data).digest()
    hex_hash = zip_hash or digest.hex()
    b64_hash = base64.b64encode(bytes.fromhex(hex_hash)).decode()
    for kind, value in (("hex", hex_hash), ("b64", b64_hash)):
      (d / f"cm-linux-amd64.zip.describe-{kind}.json").write_text(json.dumps(
          {"hashes": [{"type": "SHA256", "value": value}, {"type": "MD5", "value": "x"}]}
      ))
    bin_sha = hashlib.sha256(binary).hexdigest()
    if manifest:
      (d / "stable.json").write_text(json.dumps(
          {"version": cm_version, "platforms": {"linux-amd64": bin_hash or bin_sha}}
      ))
    return bin_sha

  def run_script(self, **env):
    full_env = {
        "PATH": f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}",
        "STUB_DIR": str(self.stub),
        "HOME": str(self.tmp),
    }
    full_env.update(env)
    return subprocess.run(
        [_BASH, str(_SCRIPT)], cwd=self.work, env=full_env,
        capture_output=True, text=True, check=False,
    )

  def calls(self):
    path = self.stub / "calls"
    return path.read_text() if path.exists() else ""

  def test_default_is_the_latest_release_via_gcloud(self):
    self.publish("stable", "9.9.9")
    res = self.run_script()
    self.assertEqual(res.returncode, 0, res.stderr)
    self.assertIn("cm version 9.9.9", res.stdout)
    self.assertIn("--version=stable", self.calls())
    self.assertIn("matches the release manifest", res.stdout)
    # Only the binary is left behind for the Docker build context.
    self.assertEqual(sorted(p.name for p in self.work.iterdir()), ["cm"])
    self.assertTrue(os.access(self.work / "cm", os.X_OK))

  def test_curl_fetch_accepts_the_base64_hash(self):
    self.publish("stable", "9.9.9")
    res = self.run_script(CM_FETCH="curl")
    self.assertEqual(res.returncode, 0, res.stderr)
    self.assertIn("cm%3Astable%3Acm-linux-amd64.zip:download", self.calls())
    self.assertNotIn("gcloud", self.calls())

  def test_explicit_version_is_downloaded(self):
    self.publish("stable", "9.9.9")
    self.publish("1.2.3", "1.2.3")
    res = self.run_script(CM_VERSION="1.2.3")
    self.assertEqual(res.returncode, 0, res.stderr)
    self.assertIn("cm version 1.2.3", res.stdout)
    self.assertIn("--version=1.2.3", self.calls())

  def test_zip_hash_mismatch_fails(self):
    self.publish("stable", "9.9.9", zip_hash="0" * 64)
    for fetch in ("gcloud", "curl"):
      with self.subTest(fetch=fetch):
        res = self.run_script(CM_FETCH=fetch)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("does not match the published", res.stderr)
        self.assertFalse((self.work / "cm").exists())

  def test_manifest_mismatch_fails(self):
    self.publish("stable", "9.9.9", bin_hash="f" * 64)
    res = self.run_script()
    self.assertNotEqual(res.returncode, 0)
    self.assertIn("stable.json", res.stderr)
    self.assertFalse((self.work / "cm").exists())

  def test_release_without_manifest_still_checks_the_zip(self):
    self.publish("0.1.0", "0.1.0", manifest=False)
    res = self.run_script(CM_VERSION="0.1.0")
    self.assertEqual(res.returncode, 0, res.stderr)
    self.assertIn("has no stable.json manifest", res.stdout)
    self.assertIn("matches the SHA-256 Artifact Registry publishes", res.stdout)

  def test_exact_pin_matches_or_fails(self):
    bin_sha = self.publish("1.2.3", "1.2.3")
    ok = self.run_script(CM_VERSION="1.2.3", CM_SHA256=bin_sha)
    self.assertEqual(ok.returncode, 0, ok.stderr)
    (self.work / "cm").unlink()
    bad = self.run_script(CM_VERSION="1.2.3", CM_SHA256="a" * 64)
    self.assertNotEqual(bad.returncode, 0)

  def test_pre_staged_binary_is_used_without_download(self):
    staged = self.work / "cm"
    staged.write_bytes(_cm_script("0.0.1"))
    res = self.run_script()
    self.assertEqual(res.returncode, 0, res.stderr)
    self.assertIn("pre-staged", res.stdout)
    self.assertEqual(self.calls(), "")
    pinned = self.run_script(CM_SHA256="b" * 64)
    self.assertNotEqual(pinned.returncode, 0)

  def test_rejects_bad_inputs(self):
    self.assertEqual(self.run_script(CM_VERSION="../x").returncode, 2)
    self.assertEqual(self.run_script(CM_FETCH="wget").returncode, 2)
    self.assertEqual(self.calls(), "")

  def test_missing_release_fails(self):
    res = self.run_script(CM_VERSION="99.0.0")
    self.assertNotEqual(res.returncode, 0)


class NoPinnedCliVersionTest(unittest.TestCase):
  """Both image builds default to the latest CLI release."""

  def test_cloudbuild_defaults_to_latest(self):
    doc = yaml.safe_load((_ROOT / "cloudbuild.yaml").read_text())
    self.assertEqual(doc["substitutions"]["_CM_VERSION"], "")
    self.assertEqual(doc["substitutions"]["_CM_SHA256"], "")
    step = next(s for s in doc["steps"] if s["id"] == "stage-cm")
    self.assertEqual(step["args"], ["scripts/ci/stage_cm.sh"])
    self.assertIn("CM_VERSION=${_CM_VERSION}", step["env"])

  def test_github_actions_build_defaults_to_latest(self):
    doc = yaml.safe_load((_ROOT / ".github" / "workflows" / "build_runner_image.yml").read_text())
    # PyYAML reads the bare `on:` key as True.
    inputs = doc[True]["workflow_dispatch"]["inputs"]
    self.assertEqual(inputs["cm_version"]["default"], "")
    steps = doc["jobs"]["build-and-publish"]["steps"]
    resolve = next(s for s in steps if s["name"] == "Resolve CodeMender CLI Binary")
    self.assertIn("scripts/ci/stage_cm.sh", resolve["run"])
    self.assertEqual(resolve["env"]["CM_FETCH"], "curl")


if __name__ == "__main__":
  unittest.main()
