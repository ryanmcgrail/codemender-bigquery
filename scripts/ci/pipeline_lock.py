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
"""Pipeline mutex and commit-ordering checks for scripts/ci/tf_apply.sh.

Holds a GCS lock object (`gs://$TF_STATE_BUCKET/$TF_STATE_PREFIX/pipeline.lock`,
created with `ifGenerationMatch=0` and a stale-lock TTL) across the entire
plan -> destroy_guard -> apply sequence, and checks that the build's commit is
still the current tip of the deployed branch before planning or applying:

1. Primary check (`CLOUDBUILD_REPO` set): fetches a short-lived read token from
   the Cloud Build v2 repository (`POST /v2/{repo}:accessReadToken` using the
   build service account's token from the metadata server) and runs
   `git ls-remote` for `refs/heads/<branch>`. If the remote branch HEAD differs
   from `COMMIT_SHA`, exits with status 10 so `tf_apply.sh` skips the apply and
   exits 0.
2. Fallback check (`CLOUDBUILD_REPO` unset, e.g. GitHub Actions or manual runs):
   reads `gs://$TF_STATE_BUCKET/$TF_STATE_PREFIX/last-applied.json`
   (`{sha, commit_timestamp}`) and exits 10 if the current commit is older.
   After a successful apply, `record-applied` updates `last-applied.json`.

Standard library only, so it runs in any python3 environment.
"""

import argparse
import base64
import datetime
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SUPERSEDED_EXIT_CODE = 10

_DEFAULT_GCS_API_URL = "https://storage.googleapis.com"
_DEFAULT_CLOUDBUILD_API_URL = "https://cloudbuild.googleapis.com"
_DEFAULT_METADATA_URL = "http://metadata.google.internal"
_DEFAULT_LOCK_TTL_SECONDS = 1800
_DEFAULT_LOCK_TIMEOUT_SECONDS = 900
_DEFAULT_LOCK_POLL_SECONDS = 5.0
_LOCK_STATE_FILENAME = ".pipeline_lock_state.json"


class PipelineLockError(Exception):
  """Raised when acquiring the lock or checking commit ordering fails."""


def _env(name, default=""):
  return os.environ.get(name, default).strip()


def _state_prefix():
  prefix = _env("TF_STATE_PREFIX", "terraform/gcp").strip("/")
  return prefix


def _lock_object_name():
  prefix = _state_prefix()
  return f"{prefix}/pipeline.lock" if prefix else "pipeline.lock"


def _marker_object_name():
  prefix = _state_prefix()
  return f"{prefix}/last-applied.json" if prefix else "last-applied.json"


def _lock_state_file():
  tf_dir = _env("TF_DIR", "terraform/gcp")
  return os.path.join(tf_dir, _LOCK_STATE_FILENAME)


def _local_state_dir():
  explicit = _env("TF_LOCK_LOCAL_DIR")
  if explicit:
    return explicit
  tf_dir = _env("TF_DIR", "terraform/gcp")
  return os.path.join(tf_dir, ".pipeline_state")


def _use_gcs_backend():
  """Returns True when GCS HTTP locking should be used instead of local files."""
  mode = _env("TF_LOCK_BACKEND").lower()
  if mode == "local":
    return False
  if mode == "gcs":
    return True
  for var in (
      "TF_APPLY_ACCESS_TOKEN",
      "GOOGLE_OAUTH_ACCESS_TOKEN",
      "TF_GCS_API_URL",
      "CLOUDBUILD_REPO",
      "BUILD_ID",
  ):
    if _env(var):
      return True
  if _env("STUB_DIR"):
    return False
  if _env("TF_REQUIRE_GCS_LOCK").lower() in ("1", "true", "yes"):
    return True
  return bool(_env("TF_STATE_BUCKET"))


def get_access_token():
  """Fetches an OAuth2 access token without ever logging the token value."""
  for var in ("TF_APPLY_ACCESS_TOKEN", "GOOGLE_OAUTH_ACCESS_TOKEN"):
    tok = _env(var)
    if tok:
      return tok

  meta_base = _env("TF_METADATA_URL", _DEFAULT_METADATA_URL).rstrip("/")
  meta_url = (
      f"{meta_base}/computeMetadata/v1/instance/service-accounts/default/token"
  )
  req = urllib.request.Request(
      meta_url, headers={"Metadata-Flavor": "Google"}, method="GET"
  )
  try:
    with urllib.request.urlopen(req, timeout=5) as resp:
      payload = json.loads(resp.read().decode("utf-8"))
      tok = payload.get("access_token", "").strip()
      if tok:
        return tok
  except (OSError, ValueError, urllib.error.URLError):
    pass

  try:
    proc = subprocess.run(
        ["gcloud", "auth", "print-access-token"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if proc.returncode == 0 and proc.stdout.strip():
      return proc.stdout.strip()
  except OSError:
    pass

  gcs_url = _env("TF_GCS_API_URL")
  if gcs_url.startswith(("http://127.0.0.1", "http://localhost")):
    return "local-test-token"

  raise PipelineLockError(
      "could not obtain a Google Cloud access token from the metadata server "
      "or gcloud"
  )


def _http_json(method, url, token, body=None, headers=None):
  """Performs an HTTP request and returns (status_code, parsed_json_or_bytes)."""
  req_headers = {"Authorization": f"Bearer {token}"}
  if headers:
    req_headers.update(headers)
  data = None
  if body is not None:
    if isinstance(body, (dict, list)):
      data = json.dumps(body).encode("utf-8")
      req_headers.setdefault("Content-Type", "application/json")
    elif isinstance(body, str):
      data = body.encode("utf-8")
    else:
      data = body
  req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
  try:
    with urllib.request.urlopen(req, timeout=30) as resp:
      raw = resp.read()
      if not raw:
        return resp.status, {}
      try:
        return resp.status, json.loads(raw.decode("utf-8"))
      except ValueError:
        return resp.status, raw
  except urllib.error.HTTPError as e:
    raw = e.read() if e.fp else b""
    try:
      parsed = json.loads(raw.decode("utf-8")) if raw else {}
    except ValueError:
      parsed = {"error": raw.decode("utf-8", errors="replace")}
    return e.code, parsed
  except urllib.error.URLError as e:
    raise PipelineLockError(f"HTTP {method} {url} failed: {e.reason}") from e


def _parse_rfc3339(ts_str):
  if not ts_str:
    return None
  try:
    cleaned = re.sub(r"(Z|[+-]\d{2}:\d{2})$", "", ts_str.strip())
    if "." in cleaned:
      head, frac = cleaned.split(".", 1)
      cleaned = f"{head}.{frac[:6]}"
    dt = datetime.datetime.fromisoformat(cleaned).replace(
        tzinfo=datetime.timezone.utc
    )
    return dt.timestamp()
  except ValueError:
    return None


def _holder_id():
  build_id = _env("BUILD_ID")
  if build_id:
    return f"cloudbuild:{build_id}"
  run_id = _env("GITHUB_RUN_ID")
  if run_id:
    return f"gha:{run_id}"
  return f"{socket.gethostname()}:{os.getpid()}"


def _resolve_commit_sha(cwd=None):
  for var in ("COMMIT_SHA", "REVISION_ID", "GITHUB_SHA"):
    val = _env(var)
    if val:
      return val
  try:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if proc.returncode == 0 and proc.stdout.strip():
      return proc.stdout.strip()
  except OSError:
    pass
  return ""


def _resolve_commit_timestamp(commit_sha="", cwd=None):
  explicit = _env("COMMIT_TIMESTAMP")
  if explicit:
    try:
      return int(explicit)
    except ValueError as e:
      raise PipelineLockError(
          f"COMMIT_TIMESTAMP must be an integer unix timestamp, got {explicit!r}"
      ) from e
  ref = commit_sha or "HEAD"
  try:
    proc = subprocess.run(
        ["git", "log", "-1", "--format=%ct", ref],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if proc.returncode == 0 and proc.stdout.strip():
      return int(proc.stdout.strip())
  except (OSError, ValueError):
    pass
  return None


def _is_ancestor(older_sha, newer_sha, cwd=None):
  if not older_sha or not newer_sha:
    return False
  try:
    proc = subprocess.run(
        ["git", "merge-base", "--is-ancestor", older_sha, newer_sha],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return proc.returncode == 0
  except OSError:
    return False


def _save_lock_state(state):
  path = _lock_state_file()
  os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
  with open(path, "w", encoding="utf-8") as f:
    json.dump(state, f)


def _load_lock_state():
  path = _lock_state_file()
  if not os.path.exists(path):
    return None
  try:
    with open(path, encoding="utf-8") as f:
      return json.load(f)
  except (OSError, ValueError):
    return None


def _remove_lock_state():
  path = _lock_state_file()
  try:
    os.remove(path)
  except OSError:
    pass


# ---------------------------------------------------------------------------
# Mutex acquire / release
# ---------------------------------------------------------------------------


def acquire_lock():
  """Acquires the pipeline mutex (in GCS or local state directory)."""
  _remove_lock_state()
  ttl = float(_env("TF_LOCK_TTL_SECONDS", str(_DEFAULT_LOCK_TTL_SECONDS)))
  timeout = float(
      _env("TF_LOCK_TIMEOUT_SECONDS", str(_DEFAULT_LOCK_TIMEOUT_SECONDS))
  )
  poll = float(_env("TF_LOCK_POLL_SECONDS", str(_DEFAULT_LOCK_POLL_SECONDS)))
  holder = _holder_id()
  commit_sha = _resolve_commit_sha()

  if not _use_gcs_backend():
    return _acquire_local_lock(holder, commit_sha, ttl, timeout, poll)

  bucket = _env("TF_STATE_BUCKET")
  if not bucket:
    raise PipelineLockError("TF_STATE_BUCKET is required to acquire pipeline lock")
  obj_name = _lock_object_name()
  gcs_base = _env("TF_GCS_API_URL", _DEFAULT_GCS_API_URL).rstrip("/")

  q_bucket = urllib.parse.quote(bucket, safe="")
  q_obj = urllib.parse.quote(obj_name, safe="")
  create_url = (
      f"{gcs_base}/upload/storage/v1/b/{q_bucket}/o"
      f"?uploadType=media&name={q_obj}&ifGenerationMatch=0"
  )
  meta_url = f"{gcs_base}/storage/v1/b/{q_bucket}/o/{q_obj}"
  media_url = f"{meta_url}?alt=media"

  deadline = time.monotonic() + timeout
  while True:
    token = get_access_token()
    now = time.time()
    payload = {
        "holder": holder,
        "commit_sha": commit_sha,
        "acquired_at": now,
        "ttl_seconds": ttl,
    }
    status, resp = _http_json("POST", create_url, token, body=payload)
    if status in (200, 201) and isinstance(resp, dict):
      gen = str(resp.get("generation", "1"))
      _save_lock_state({
          "backend": "gcs",
          "bucket": bucket,
          "object_name": obj_name,
          "generation": gen,
          "holder": holder,
      })
      print(
          f"pipeline lock: acquired gs://{bucket}/{obj_name} "
          f"(generation={gen}, holder={holder})"
      )
      return 0

    if status != 412:
      raise PipelineLockError(
          f"failed to create lock gs://{bucket}/{obj_name} "
          f"(HTTP {status}): {resp}"
      )

    # Lock already exists; inspect its generation and age.
    m_status, meta = _http_json("GET", meta_url, token)
    if m_status == 404:
      # Released between our POST and GET; retry immediately.
      continue
    if m_status != 200 or not isinstance(meta, dict):
      raise PipelineLockError(
          f"failed to read lock metadata gs://{bucket}/{obj_name} "
          f"(HTTP {m_status}): {meta}"
      )

    existing_gen = str(meta.get("generation", ""))
    acquired_at = _parse_rfc3339(meta.get("timeCreated") or meta.get("updated"))
    existing_holder = "unknown"
    existing_ttl = ttl

    d_status, data = _http_json("GET", media_url, token)
    if d_status == 404:
      # Released between metadata GET and media GET; retry immediately.
      continue
    if d_status == 200 and isinstance(data, dict):
      existing_holder = data.get("holder", existing_holder)
      if isinstance(data.get("acquired_at"), (int, float)):
        acquired_at = float(data["acquired_at"])
      if isinstance(data.get("ttl_seconds"), (int, float)):
        existing_ttl = float(data["ttl_seconds"])

    age = (time.time() - acquired_at) if acquired_at is not None else 0.0
    effective_ttl = min(ttl, existing_ttl) if existing_ttl > 0 else ttl
    if acquired_at is not None and age >= effective_ttl and existing_gen:
      print(
          f"pipeline lock: breaking stale lock gs://{bucket}/{obj_name} "
          f"held by {existing_holder} (age={age:.1f}s >= ttl={effective_ttl:.1f}s, "
          f"generation={existing_gen})"
      )
      del_url = (
          f"{meta_url}?ifGenerationMatch="
          f"{urllib.parse.quote(existing_gen, safe='')}"
      )
      del_status, _ = _http_json("DELETE", del_url, token)
      if del_status in (200, 204, 404, 412):
        continue
      raise PipelineLockError(
          f"failed to delete stale lock gs://{bucket}/{obj_name} "
          f"(HTTP {del_status})"
      )

    if time.monotonic() >= deadline:
      raise PipelineLockError(
          f"timed out after {timeout:.0f}s waiting for pipeline lock "
          f"gs://{bucket}/{obj_name} (held by {existing_holder})"
      )

    print(
        f"pipeline lock: waiting for gs://{bucket}/{obj_name} "
        f"(held by {existing_holder}, age={age:.1f}s; next check in {poll:g}s)"
    )
    time.sleep(poll)


def _acquire_local_lock(holder, commit_sha, ttl, timeout, poll):
  state_dir = _local_state_dir()
  os.makedirs(state_dir, exist_ok=True)
  lock_path = os.path.join(state_dir, "pipeline.lock")
  deadline = time.monotonic() + timeout

  while True:
    now = time.time()
    gen = str(time.time_ns())
    payload = {
        "holder": holder,
        "commit_sha": commit_sha,
        "acquired_at": now,
        "ttl_seconds": ttl,
        "generation": gen,
    }
    try:
      fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
      with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(payload, f)
      _save_lock_state({
          "backend": "local",
          "lock_path": lock_path,
          "generation": gen,
          "holder": holder,
      })
      return 0
    except FileExistsError:
      pass

    try:
      with open(lock_path, encoding="utf-8") as f:
        existing = json.load(f)
    except FileNotFoundError:
      continue
    except (OSError, ValueError):
      existing = {}

    acquired_at = existing.get("acquired_at")
    if not isinstance(acquired_at, (int, float)):
      try:
        acquired_at = os.path.getmtime(lock_path)
      except OSError:
        continue
    existing_ttl = existing.get("ttl_seconds", ttl)
    effective_ttl = (
        min(ttl, float(existing_ttl))
        if isinstance(existing_ttl, (int, float)) and existing_ttl > 0
        else ttl
    )
    age = time.time() - float(acquired_at)
    if age >= effective_ttl:
      try:
        os.remove(lock_path)
      except OSError:
        pass
      continue

    if time.monotonic() >= deadline:
      raise PipelineLockError(
          f"timed out after {timeout:.0f}s waiting for local pipeline lock "
          f"{lock_path}"
      )
    time.sleep(poll)


def release_lock():
  """Releases the pipeline mutex if held by this process."""
  state = _load_lock_state()
  if not state:
    return 0

  backend = state.get("backend")
  try:
    if backend == "local":
      lock_path = state.get("lock_path", "")
      gen = state.get("generation", "")
      if lock_path and os.path.exists(lock_path):
        try:
          with open(lock_path, encoding="utf-8") as f:
            current = json.load(f)
        except (OSError, ValueError):
          current = {}
        if not gen or current.get("generation") == gen:
          try:
            os.remove(lock_path)
          except OSError:
            pass
      return 0

    if backend == "gcs":
      bucket = state.get("bucket", "")
      obj_name = state.get("object_name", "")
      gen = str(state.get("generation", ""))
      if not bucket or not obj_name or not gen:
        return 0
      gcs_base = _env("TF_GCS_API_URL", _DEFAULT_GCS_API_URL).rstrip("/")
      token = get_access_token()
      q_bucket = urllib.parse.quote(bucket, safe="")
      q_obj = urllib.parse.quote(obj_name, safe="")
      q_gen = urllib.parse.quote(gen, safe="")
      del_url = (
          f"{gcs_base}/storage/v1/b/{q_bucket}/o/{q_obj}"
          f"?ifGenerationMatch={q_gen}"
      )
      status, resp = _http_json("DELETE", del_url, token)
      if status in (200, 204):
        print(
            f"pipeline lock: released gs://{bucket}/{obj_name} "
            f"(generation={gen})"
        )
      elif status in (404, 412):
        print(
            f"pipeline lock: lock gs://{bucket}/{obj_name} "
            f"(generation={gen}) was already released or superseded "
            f"(HTTP {status})",
            file=sys.stderr,
        )
      else:
        print(
            f"pipeline lock: warning: could not delete gs://{bucket}/{obj_name} "
            f"(HTTP {status}): {resp}",
            file=sys.stderr,
        )
      return 0
  finally:
    _remove_lock_state()
  return 0


# ---------------------------------------------------------------------------
# Commit ordering check (Cloud Build accessReadToken + git ls-remote, and
# fallback last-applied.json marker)
# ---------------------------------------------------------------------------


def _normalize_https_remote(url):
  url = (url or "").strip()
  if not url:
    return ""
  ssh_match = re.match(r"^git@([^:]+):(.+)$", url)
  if ssh_match:
    host, path = ssh_match.group(1), ssh_match.group(2)
    return f"https://{host}/{path}"
  if url.startswith("ssh://git@"):
    rest = url[len("ssh://git@") :]
    return f"https://{rest}"
  return url


def _resolve_remote_url(cloudbuild_repo, gcp_token):
  explicit = _env("REMOTE_REPO_URL")
  if explicit:
    return _normalize_https_remote(explicit)

  cb_base = _env("CLOUDBUILD_API_URL", _DEFAULT_CLOUDBUILD_API_URL).rstrip("/")
  repo_url = f"{cb_base}/v2/{cloudbuild_repo.lstrip('/')}"
  status, data = _http_json("GET", repo_url, gcp_token)
  if status == 200 and isinstance(data, dict) and data.get("remoteUri"):
    return _normalize_https_remote(data["remoteUri"])

  try:
    proc = subprocess.run(
        ["git", "config", "--get", "remote.origin.url"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if proc.returncode == 0 and proc.stdout.strip():
      return _normalize_https_remote(proc.stdout.strip())
  except OSError:
    pass

  raise PipelineLockError(
      f"could not determine remote URI for Cloud Build repository "
      f"{cloudbuild_repo}"
  )


def _fetch_cloudbuild_read_token(cloudbuild_repo, gcp_token):
  """Fetches a short-lived GitHub read token from Cloud Build v2.

  Never prints or logs the returned token.
  """
  cb_base = _env("CLOUDBUILD_API_URL", _DEFAULT_CLOUDBUILD_API_URL).rstrip("/")
  url = f"{cb_base}/v2/{cloudbuild_repo.lstrip('/')}:accessReadToken"
  status, data = _http_json("POST", url, gcp_token, body={})
  if status != 200 or not isinstance(data, dict):
    raise PipelineLockError(
        f"Cloud Build accessReadToken for {cloudbuild_repo} failed "
        f"(HTTP {status})"
    )
  gh_token = (data.get("token") or "").strip()
  if not gh_token:
    raise PipelineLockError(
        f"Cloud Build accessReadToken for {cloudbuild_repo} returned an empty "
        "token"
    )
  return gh_token


def _ls_remote_head(remote_url, branch, gh_token):
  """Runs git ls-remote for refs/heads/<branch> without exposing gh_token."""
  basic = base64.b64encode(f"x-access-token:{gh_token}".encode("utf-8")).decode(
      "ascii"
  )
  env = dict(os.environ)
  env["GIT_TERMINAL_PROMPT"] = "0"
  env["GIT_CONFIG_COUNT"] = "1"
  env["GIT_CONFIG_KEY_0"] = "http.extraheader"
  env["GIT_CONFIG_VALUE_0"] = f"AUTHORIZATION: basic {basic}"

  clean_branch = re.sub(r"^refs/heads/", "", branch.strip())
  ref = f"refs/heads/{clean_branch}"
  proc = subprocess.run(
      ["git", "ls-remote", "--exit-code", remote_url, ref],
      env=env,
      capture_output=True,
      text=True,
      timeout=30,
      check=False,
  )
  if proc.returncode != 0:
    # Scrub any accidental token appearance before surfacing stderr.
    safe_err = (proc.stderr or "").replace(gh_token, "***").replace(basic, "***")
    raise PipelineLockError(
        f"git ls-remote {remote_url} {ref} failed "
        f"(exit {proc.returncode}): {safe_err.strip()}"
    )
  lines = (proc.stdout or "").strip().splitlines()
  if not lines:
    raise PipelineLockError(f"git ls-remote returned no ref for {ref}")
  remote_sha = ""
  for line in lines:
    parts = line.split()
    if len(parts) >= 2 and parts[1] == ref:
      remote_sha = parts[0].strip()
      break
  if not remote_sha:
    remote_sha = lines[0].split()[0].strip()
  if not remote_sha:
    raise PipelineLockError(f"git ls-remote returned an empty SHA for {ref}")
  return remote_sha


def _read_marker():
  if not _use_gcs_backend():
    path = os.path.join(_local_state_dir(), "last-applied.json")
    if not os.path.exists(path):
      return None
    try:
      with open(path, encoding="utf-8") as f:
        return json.load(f)
    except (OSError, ValueError):
      return None

  bucket = _env("TF_STATE_BUCKET")
  if not bucket:
    return None
  obj_name = _marker_object_name()
  gcs_base = _env("TF_GCS_API_URL", _DEFAULT_GCS_API_URL).rstrip("/")
  token = get_access_token()
  q_bucket = urllib.parse.quote(bucket, safe="")
  q_obj = urllib.parse.quote(obj_name, safe="")
  url = f"{gcs_base}/storage/v1/b/{q_bucket}/o/{q_obj}?alt=media"
  status, data = _http_json("GET", url, token)
  if status == 404:
    return None
  if status != 200 or not isinstance(data, dict):
    raise PipelineLockError(
        f"failed to read gs://{bucket}/{obj_name} (HTTP {status}): {data}"
    )
  return data


def _write_marker(marker):
  if not _use_gcs_backend():
    state_dir = _local_state_dir()
    os.makedirs(state_dir, exist_ok=True)
    path = os.path.join(state_dir, "last-applied.json")
    with open(path, "w", encoding="utf-8") as f:
      json.dump(marker, f)
    return

  bucket = _env("TF_STATE_BUCKET")
  if not bucket:
    raise PipelineLockError("TF_STATE_BUCKET is required to write last-applied.json")
  obj_name = _marker_object_name()
  gcs_base = _env("TF_GCS_API_URL", _DEFAULT_GCS_API_URL).rstrip("/")
  token = get_access_token()
  q_bucket = urllib.parse.quote(bucket, safe="")
  q_obj = urllib.parse.quote(obj_name, safe="")
  url = (
      f"{gcs_base}/upload/storage/v1/b/{q_bucket}/o"
      f"?uploadType=media&name={q_obj}"
  )
  status, resp = _http_json("POST", url, token, body=marker)
  if status not in (200, 201):
    raise PipelineLockError(
        f"failed to write gs://{bucket}/{obj_name} (HTTP {status}): {resp}"
    )


def _shas_match(sha_a, sha_b):
  if not sha_a or not sha_b:
    return False
  a, b = sha_a.lower(), sha_b.lower()
  if a == b:
    return True
  # Support short SHAs (at least 7 hex chars) when comparing.
  if len(a) >= 7 and len(b) >= 7 and (a.startswith(b) or b.startswith(a)):
    return True
  return False


def check_commit():
  """Verifies that COMMIT_SHA has not been superseded on the target branch.

  Returns 0 when the apply should proceed, or SUPERSEDED_EXIT_CODE (10) when a
  newer commit has superseded this build.
  """
  commit_sha = _resolve_commit_sha()
  if not commit_sha:
    return 0

  branch = (
      _env("DEPLOY_BRANCH")
      or _env("_BRANCH_NAME")
      or _env("BRANCH_NAME")
      or _env("GITHUB_REF_NAME")
      or "main"
  )
  cloudbuild_repo = _env("CLOUDBUILD_REPO")

  if cloudbuild_repo:
    gcp_token = get_access_token()
    gh_token = _fetch_cloudbuild_read_token(cloudbuild_repo, gcp_token)
    remote_url = _resolve_remote_url(cloudbuild_repo, gcp_token)
    remote_sha = _ls_remote_head(remote_url, branch, gh_token)
    if not _shas_match(commit_sha, remote_sha):
      ancestor_note = (
          " (ancestor of remote HEAD)"
          if _is_ancestor(commit_sha, remote_sha)
          else ""
      )
      print(
          f"pipeline lock: commit {commit_sha} is not the current tip of "
          f"refs/heads/{branch}{ancestor_note}; superseded by {remote_sha}; "
          "skipping apply."
      )
      return SUPERSEDED_EXIT_CODE
    print(
        f"pipeline lock: commit {commit_sha} is the current tip of "
        f"refs/heads/{branch}; proceeding with apply."
    )
    return 0

  # Fallback when CLOUDBUILD_REPO is not set: check last-applied.json marker.
  marker = _read_marker()
  if not marker or not isinstance(marker, dict):
    return 0

  marker_sha = (marker.get("sha") or "").strip()
  marker_ts = marker.get("commit_timestamp")
  if not marker_sha or _shas_match(commit_sha, marker_sha):
    return 0

  commit_ts = _resolve_commit_timestamp(commit_sha)
  if isinstance(marker_ts, (int, float)) and commit_ts is not None:
    if commit_ts < marker_ts:
      print(
          f"pipeline lock: commit {commit_sha} (timestamp {commit_ts}) is "
          f"older than last-applied commit {marker_sha} "
          f"(timestamp {int(marker_ts)}); superseded by {marker_sha}; "
          "skipping apply."
      )
      return SUPERSEDED_EXIT_CODE
    if commit_ts == marker_ts and _is_ancestor(commit_sha, marker_sha):
      print(
          f"pipeline lock: commit {commit_sha} is an ancestor of "
          f"last-applied commit {marker_sha}; superseded by {marker_sha}; "
          "skipping apply."
      )
      return SUPERSEDED_EXIT_CODE
  elif _is_ancestor(commit_sha, marker_sha):
    print(
        f"pipeline lock: commit {commit_sha} is an ancestor of "
        f"last-applied commit {marker_sha}; superseded by {marker_sha}; "
        "skipping apply."
    )
    return SUPERSEDED_EXIT_CODE

  return 0


def record_applied():
  """Writes the last-applied.json marker for the current commit."""
  commit_sha = _resolve_commit_sha()
  if not commit_sha:
    return 0
  commit_ts = _resolve_commit_timestamp(commit_sha)
  now_iso = datetime.datetime.now(datetime.timezone.utc).strftime(
      "%Y-%m-%dT%H:%M:%SZ"
  )
  marker = {
      "sha": commit_sha,
      "commit_timestamp": commit_ts,
      "applied_at": now_iso,
  }
  _write_marker(marker)
  print(f"pipeline lock: recorded last-applied commit {commit_sha}.")
  return 0


def main(argv=None):
  parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
  parser.add_argument(
      "action",
      choices=("acquire", "release", "check-commit", "record-applied"),
      help="pipeline lock action to run",
  )
  args = parser.parse_args(argv)

  try:
    if args.action == "acquire":
      return acquire_lock()
    if args.action == "release":
      return release_lock()
    if args.action == "check-commit":
      return check_commit()
    if args.action == "record-applied":
      return record_applied()
  except PipelineLockError as e:
    print(f"pipeline lock: {e}", file=sys.stderr)
    return 1
  return 2


if __name__ == "__main__":
  sys.exit(main())
