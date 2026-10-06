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

"""Per-repository settings and credential handling for the Wiz SAST bridge.

The bridge is strictly opt-in per repository: it runs only when
``CODEMENDER_WIZ_ENABLED`` is true for the scan being executed. Having Wiz
credentials in the environment never turns it on by itself.
"""

import dataclasses
import logging
import os
from typing import Dict, Optional

logger = logging.getLogger("codemender-orchestrator")

# Environment switches (all optional; the bridge is a no-op unless enabled).
ENV_ENABLED = "CODEMENDER_WIZ_ENABLED"
ENV_MIN_SEVERITY = "CODEMENDER_WIZ_MIN_SEVERITY"
ENV_RESULTS_FILE = "CODEMENDER_WIZ_RESULTS_FILE"
ENV_SCAN_NAME = "CODEMENDER_WIZ_SCAN_NAME"
ENV_LINE_WINDOW = "CODEMENDER_WIZ_LINE_WINDOW"
ENV_MAX_IMPORTS = "CODEMENDER_WIZ_MAX_IMPORTS"
ENV_SCAN_TIMEOUT = "CODEMENDER_WIZ_SCAN_TIMEOUT_SECONDS"
ENV_WIZCLI_PATH = "CODEMENDER_WIZCLI_PATH"
ENV_WIZCLI_VERSION = "CODEMENDER_WIZCLI_VERSION"
ENV_WIZCLI_SHA256 = "CODEMENDER_WIZCLI_SHA256"
ENV_WIZCLI_URL = "CODEMENDER_WIZCLI_URL"

# Credentials read natively by `wizcli`. Never logged, printed or persisted.
ENV_CLIENT_ID = "WIZ_CLIENT_ID"
ENV_CLIENT_SECRET = "WIZ_CLIENT_SECRET"

# Every variable with this prefix is treated as Wiz-sensitive and scrubbed from
# the environment of CodeMender subprocesses.
WIZ_ENV_PREFIX = "WIZ_"

SEVERITY_ORDER = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
DEFAULT_MIN_SEVERITY = "HIGH"
DEFAULT_SCAN_NAME = "codemender-sast-bridge"
DEFAULT_LINE_WINDOW = 3
DEFAULT_MAX_IMPORTS = 50
DEFAULT_SCAN_TIMEOUT_SECONDS = 900

# Pinned default `wizcli` build, used only when no binary is on PATH and no
# explicit path is configured. Overridable per deployment so a CLI upgrade
# needs no code change.
DEFAULT_WIZCLI_VERSION = "1.75.0"
DEFAULT_WIZCLI_SHA256 = (
    "1ba377887ed9d0543fd24d9ba0db778e52dce0c54ad35dd194410f9f64cd609a"
)
WIZCLI_URL_TEMPLATE = (
    "https://downloads.wiz.io/v1/wizcli/{version}/wizcli-linux-amd64"
)

_TRUTHY = frozenset({"true", "1", "yes", "on"})


def _env_str(env: Dict[str, str], key: str) -> str:
  return (env.get(key) or "").strip()


def _env_int(env: Dict[str, str], key: str, default: int, minimum: int) -> int:
  raw = _env_str(env, key)
  if not raw:
    return default
  try:
    value = int(raw)
  except ValueError:
    logger.warning("Ignoring non-integer %s=%r; using %d.", key, raw, default)
    return default
  return max(minimum, value)


def normalize_severity(value: Optional[str]) -> Optional[str]:
  """Returns the canonical upper-case severity, or None when unrecognized."""
  sev = (value or "").strip().upper()
  if sev == "INFORMATIONAL":
    sev = "INFO"
  return sev if sev in SEVERITY_ORDER else None


def severity_rank(value: Optional[str]) -> int:
  """Ranks a severity for threshold comparisons (-1 when unrecognized)."""
  sev = normalize_severity(value)
  return SEVERITY_ORDER.index(sev) if sev else -1


@dataclasses.dataclass(frozen=True)
class WizBridgeSettings:
  """Resolved per-scan settings for the Wiz SAST bridge."""

  enabled: bool = False
  min_severity: str = DEFAULT_MIN_SEVERITY
  results_file: Optional[str] = None
  scan_name: str = DEFAULT_SCAN_NAME
  line_window: int = DEFAULT_LINE_WINDOW
  max_imports: int = DEFAULT_MAX_IMPORTS
  scan_timeout_seconds: int = DEFAULT_SCAN_TIMEOUT_SECONDS
  wizcli_path: Optional[str] = None
  wizcli_version: str = DEFAULT_WIZCLI_VERSION
  wizcli_sha256: str = DEFAULT_WIZCLI_SHA256
  wizcli_url: Optional[str] = None

  @classmethod
  def from_env(cls, env: Optional[Dict[str, str]] = None) -> "WizBridgeSettings":
    """Builds settings from the environment. Never raises."""
    env = dict(os.environ if env is None else env)
    enabled = _env_str(env, ENV_ENABLED).lower() in _TRUTHY

    raw_min = _env_str(env, ENV_MIN_SEVERITY)
    min_severity = normalize_severity(raw_min) or DEFAULT_MIN_SEVERITY
    if raw_min and normalize_severity(raw_min) is None:
      logger.warning(
          "Unrecognized %s=%r; falling back to %s.",
          ENV_MIN_SEVERITY,
          raw_min,
          DEFAULT_MIN_SEVERITY,
      )

    version = _env_str(env, ENV_WIZCLI_VERSION) or DEFAULT_WIZCLI_VERSION
    sha = _env_str(env, ENV_WIZCLI_SHA256).lower()
    if not sha:
      # A pinned digest only applies to the pinned version; a custom version
      # without its own digest cannot be verified and is refused at download.
      sha = DEFAULT_WIZCLI_SHA256 if version == DEFAULT_WIZCLI_VERSION else ""

    return cls(
        enabled=enabled,
        min_severity=min_severity,
        results_file=_env_str(env, ENV_RESULTS_FILE) or None,
        scan_name=_env_str(env, ENV_SCAN_NAME) or DEFAULT_SCAN_NAME,
        line_window=_env_int(env, ENV_LINE_WINDOW, DEFAULT_LINE_WINDOW, 0),
        max_imports=_env_int(env, ENV_MAX_IMPORTS, DEFAULT_MAX_IMPORTS, 1),
        scan_timeout_seconds=_env_int(
            env, ENV_SCAN_TIMEOUT, DEFAULT_SCAN_TIMEOUT_SECONDS, 30
        ),
        wizcli_path=_env_str(env, ENV_WIZCLI_PATH) or None,
        wizcli_version=version,
        wizcli_sha256=sha,
        wizcli_url=_env_str(env, ENV_WIZCLI_URL) or None,
    )


class WizCredentials:
  """Holds the Wiz service account in memory only.

  ``repr``/``str`` never reveal the values, so an accidental log line or
  exception message cannot leak them.
  """

  __slots__ = ("_client_id", "_client_secret")

  def __init__(self, client_id: str, client_secret: str):
    self._client_id = client_id or ""
    self._client_secret = client_secret or ""

  @property
  def present(self) -> bool:
    return bool(self._client_id and self._client_secret)

  def secret_values(self) -> tuple:
    """Values that must never appear in any output (for redaction)."""
    return tuple(v for v in (self._client_id, self._client_secret) if v)

  def as_env(self) -> Dict[str, str]:
    """The variables `wizcli` reads natively."""
    return {ENV_CLIENT_ID: self._client_id, ENV_CLIENT_SECRET: self._client_secret}

  def __repr__(self) -> str:
    return f"WizCredentials(present={self.present})"

  __str__ = __repr__


def take_wiz_credentials(env: Optional[dict] = None) -> WizCredentials:
  """Reads the Wiz credentials and removes every ``WIZ_*`` variable from ``env``.

  Called at the start of a stage, before any subprocess is spawned, so neither
  ``cm`` nor any other child process can inherit Wiz credentials even when it
  is launched without an explicitly scrubbed environment. Defaults to mutating
  ``os.environ``.
  """
  target = os.environ if env is None else env
  creds = WizCredentials(
      (target.get(ENV_CLIENT_ID) or "").strip(),
      (target.get(ENV_CLIENT_SECRET) or "").strip(),
  )
  for key in [k for k in target if k.upper().startswith(WIZ_ENV_PREFIX)]:
    del target[key]
  return creds
