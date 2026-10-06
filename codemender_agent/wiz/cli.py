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

"""Runs a SAST-only ``wizcli scan dir`` with credential isolation.

Safety properties:

* ``wizcli`` runs with a minimal environment (no GitHub token, no cloud
  credentials) and an isolated, throw-away ``HOME`` so its cached token never
  lands in the runner's home directory or the archived CodeMender state.
* Its console output can contain scan details and, on some errors,
  authentication diagnostics, so it is written to a temporary file that is
  never logged and is deleted afterwards.
* Results are never published to the Wiz portal (``--no-publish``).
* The flags the scan depends on are checked against ``scan dir --help``
  before running, so an incompatible CLI fails loudly instead of producing a
  silently empty result.
"""

import hashlib
import logging
import os
import platform
import re
import shutil
import subprocess
import tempfile
from typing import Callable, Dict, List, Optional

from codemender_agent.wiz.settings import WIZCLI_URL_TEMPLATE
from codemender_agent.wiz.settings import WizBridgeSettings
from codemender_agent.wiz.settings import WizCredentials

logger = logging.getLogger("codemender-orchestrator")

# Flags without which the scan cannot be trusted or cannot be read.
REQUIRED_FLAGS = (
    "--json-output-file",
    "--no-publish",
    "--by-policy-hits",
    "--disabled-scanners",
)
OPTIONAL_QUIET_FLAGS = ("--no-color", "--no-style", "--no-telemetry")

# Used only when the help text does not list the supported scanners.
KNOWN_NON_SAST_SCANNERS = (
    "Vulnerability",
    "Secret",
    "SensitiveData",
    "Misconfiguration",
    "SoftwareSupplyChain",
    "AIModels",
    "Malware",
)

# Environment variables passed through to wizcli besides the credentials.
_PASSTHROUGH_ENV = (
    "PATH",
    "LANG",
    "LC_ALL",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "NO_PROXY",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
)

_HELP_TIMEOUT_SECONDS = 60
_DOWNLOAD_TIMEOUT_SECONDS = 120
_SUPPORTED_SCANNERS_RE = re.compile(
    r"--disabled-scanners.*?Supported:\s*([A-Za-z0-9_,\s]+?)\)", re.DOTALL
)


class WizCliError(RuntimeError):
  """A wizcli failure. Messages never include command output or secrets."""


def build_wizcli_env(
    creds: WizCredentials, home_dir: str, tmp_dir: str
) -> Dict[str, str]:
  """A minimal environment for wizcli: credentials plus basic plumbing."""
  env = {k: os.environ[k] for k in _PASSTHROUGH_ENV if os.environ.get(k)}
  env.setdefault("PATH", os.defpath)
  env["HOME"] = home_dir
  env["TMPDIR"] = tmp_dir
  env.update(creds.as_env())
  return env


def _download_wizcli(
    settings: WizBridgeSettings, dest_dir: str, fetch: Optional[Callable] = None
) -> str:
  """Downloads the pinned wizcli build and verifies its SHA-256 digest."""
  if platform.system() != "Linux" or platform.machine() not in (
      "x86_64",
      "amd64",
  ):
    raise WizCliError(
        "wizcli is not installed and automatic download supports linux/amd64"
        " only; set CODEMENDER_WIZCLI_PATH"
    )
  if not settings.wizcli_sha256:
    raise WizCliError(
        "refusing to download an unpinned wizcli build; set"
        " CODEMENDER_WIZCLI_SHA256 for the configured version"
    )
  url = settings.wizcli_url or WIZCLI_URL_TEMPLATE.format(
      version=settings.wizcli_version
  )
  if not url.startswith("https://"):
    raise WizCliError("wizcli download URL must use https")
  if fetch is None:
    import requests  # pylint: disable=g-import-not-at-top

    fetch = requests.get
  dest = os.path.join(dest_dir, "wizcli")
  digest = hashlib.sha256()
  try:
    with fetch(url, stream=True, timeout=_DOWNLOAD_TIMEOUT_SECONDS) as resp:
      resp.raise_for_status()
      with open(dest, "wb") as out:
        for chunk in resp.iter_content(chunk_size=1 << 20):
          if chunk:
            digest.update(chunk)
            out.write(chunk)
  except Exception as e:  # pylint: disable=broad-exception-caught
    raise WizCliError(f"wizcli download failed ({type(e).__name__})") from None
  if digest.hexdigest() != settings.wizcli_sha256.lower():
    os.remove(dest)
    raise WizCliError("downloaded wizcli does not match the pinned SHA-256")
  os.chmod(dest, 0o700)
  logger.info("Downloaded wizcli %s (digest verified).", settings.wizcli_version)
  return dest


def locate_wizcli(
    settings: WizBridgeSettings,
    download_dir: str,
    fetch: Optional[Callable] = None,
) -> str:
  """Finds wizcli: explicit path, then PATH, then a verified download."""
  if settings.wizcli_path:
    if os.path.isfile(settings.wizcli_path) and os.access(
        settings.wizcli_path, os.X_OK
    ):
      return settings.wizcli_path
    raise WizCliError("CODEMENDER_WIZCLI_PATH does not point to an executable")
  on_path = shutil.which("wizcli")
  if on_path:
    return on_path
  return _download_wizcli(settings, download_dir, fetch=fetch)


def _run_quiet(
    cmd: List[str], env: Dict[str, str], cwd: str, timeout: int, log_path: str
) -> int:
  """Runs a command with all output sent to a private file. Returns the rc."""
  with open(log_path, "wb") as log:
    try:
      proc = subprocess.run(
          cmd,
          cwd=cwd,
          env=env,
          stdin=subprocess.DEVNULL,
          stdout=log,
          stderr=subprocess.STDOUT,
          timeout=timeout,
          check=False,
      )
    except subprocess.TimeoutExpired:
      raise WizCliError(f"wizcli timed out after {timeout}s") from None
    except OSError as e:
      raise WizCliError(f"wizcli could not be started ({type(e).__name__})") from None
  return proc.returncode


def read_scan_help(
    wizcli: str, env: Dict[str, str], cwd: str, scratch_dir: str
) -> str:
  """Returns ``wizcli scan dir --help`` output (help text holds no secrets)."""
  help_path = os.path.join(scratch_dir, "help.txt")
  rc = _run_quiet(
      [wizcli, "scan", "dir", "--help"], env, cwd, _HELP_TIMEOUT_SECONDS, help_path
  )
  with open(help_path, "r", encoding="utf-8", errors="replace") as f:
    text = f.read()
  os.remove(help_path)
  if rc != 0 or "--json-output-file" not in text:
    raise WizCliError(
        "'wizcli scan dir --help' did not describe a compatible scan command"
        f" (exit {rc})"
    )
  return text


def _has_flag(help_text: str, flag: str) -> bool:
  return re.search(rf"(?<![\w-]){re.escape(flag)}(?![\w-])", help_text) is not None


def scanners_to_disable(help_text: str) -> List[str]:
  """Every supported scanner except SAST, read from the help text."""
  match = _SUPPORTED_SCANNERS_RE.search(help_text)
  if match:
    listed = [s.strip() for s in re.split(r"[,\s]+", match.group(1)) if s.strip()]
    others = [s for s in listed if s.upper() != "SAST"]
    if others and len(others) < len(listed):
      return others
  return list(KNOWN_NON_SAST_SCANNERS)


def build_scan_command(
    wizcli: str, help_text: str, scan_name: str, output_file: str
) -> List[str]:
  """Builds the SAST-only, unpublished, unfiltered scan command."""
  missing = [f for f in REQUIRED_FLAGS if not _has_flag(help_text, f)]
  if missing:
    raise WizCliError(
        "installed wizcli lacks required scan flag(s): " + ", ".join(missing)
    )
  cmd = [
      wizcli,
      "scan",
      "dir",
      ".",
      "--no-publish",
      # Without this, findings under audit-only policies are hidden and the
      # result can be empty even though SAST found issues.
      "--by-policy-hits=DISABLED",
      "--disabled-scanners=" + ",".join(scanners_to_disable(help_text)),
      "--json-output-file=" + output_file,
  ]
  if scan_name and _has_flag(help_text, "--name"):
    cmd.append("--name=" + scan_name)
  cmd.extend(f for f in OPTIONAL_QUIET_FLAGS if _has_flag(help_text, f))
  return cmd


def run_wiz_sast_scan(
    settings: WizBridgeSettings,
    creds: WizCredentials,
    repo_dir: str,
    fetch: Optional[Callable] = None,
) -> str:
  """Runs the scan and returns the path of a private copy of the JSON result.

  The returned file lives in a fresh temporary directory outside the
  repository; the caller owns it and must delete its parent directory.
  """
  if not creds.present:
    raise WizCliError(
        "Wiz is enabled for this repository but WIZ_CLIENT_ID /"
        " WIZ_CLIENT_SECRET are not configured"
    )
  out_dir = tempfile.mkdtemp(prefix="cm-wiz-out-")
  output_file = os.path.join(out_dir, "wiz.json")
  try:
    with tempfile.TemporaryDirectory(prefix="cm-wiz-run-") as scratch:
      home = os.path.join(scratch, "home")
      tmp = os.path.join(scratch, "tmp")
      os.makedirs(home, mode=0o700)
      os.makedirs(tmp, mode=0o700)
      env = build_wizcli_env(creds, home, tmp)
      wizcli = locate_wizcli(settings, scratch, fetch=fetch)
      help_text = read_scan_help(wizcli, env, repo_dir, scratch)
      cmd = build_scan_command(
          wizcli, help_text, settings.scan_name, output_file
      )
      logger.info("Running Wiz SAST scan (results are not published).")
      rc = _run_quiet(
          cmd,
          env,
          repo_dir,
          settings.scan_timeout_seconds,
          os.path.join(scratch, "scan.log"),
      )
    # wizcli exits non-zero when policies fail, which is normal for a scan
    # that found issues; the guard decides whether the JSON can be trusted.
    if not os.path.isfile(output_file) or os.path.getsize(output_file) == 0:
      raise WizCliError(f"wizcli exited {rc} without writing a JSON result")
  except BaseException:
    shutil.rmtree(out_dir, ignore_errors=True)
    raise
  logger.info("Wiz SAST scan finished (exit %d).", rc)
  return output_file
