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

"""BigQuery analytics export for CodeMender scan telemetry.

This module persists one `scan_runs` row per scan execution and one
`vulnerability_findings` row per finding into a native BigQuery dataset, so
security posture, remediation rates, and token spend remain queryable across
repositories long after the scan artifacts themselves have expired.

Design constraints this module is built around:

  1. **Hard no-op when unconfigured.** If `CODEMENDER_BQ_DATASET` is unset the
     module performs zero BigQuery calls and never even opens `state.db`.
     Telemetry is strictly opt-in so the agent stays deployable in
     environments that have no data warehouse at all.

  2. **Never fail a security scan.** Every public entry point swallows its own
     exceptions and logs them. A broken warehouse, a revoked IAM grant, or a
     missing client library must degrade telemetry only -- it must never
     change the exit status or findings of a scan.

  3. **Tolerant of upstream schema drift.** The `findings` and `patches`
     tables in `state.db` are created and owned by the external `cm` binary,
     not by this repository. Reads therefore use an explicit column allowlist
     (never `SELECT *`) intersected against the live `PRAGMA table_info`
     result, so a `cm` release that adds, removes, or reorders columns cannot
     break the export. The BigQuery schema is treated as additive-only for the
     same reason.

  4. **Repository-agnostic.** Nothing here is specific to any single customer,
     repository, or deployment.
"""

import contextlib
from contextlib import closing
import dataclasses
import datetime
import json
import logging
import os
import re
import sqlite3
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence

from codemender_agent.vcs.git import normalize_repo_relative_path

logger = logging.getLogger("codemender-orchestrator")

# --- Environment configuration keys -----------------------------------------

# Presence of a dataset name is the single master switch for the whole module.
ENV_DATASET = "CODEMENDER_BQ_DATASET"
ENV_PROJECT = "CODEMENDER_BQ_PROJECT"
ENV_LOCATION = "CODEMENDER_BQ_LOCATION"
ENV_INCLUDE_SNIPPETS = "CODEMENDER_BQ_INCLUDE_SNIPPETS"

# Fallback project sources, in precedence order, when ENV_PROJECT is unset.
_PROJECT_FALLBACK_ENV_KEYS = (
    "GOOGLE_CLOUD_PROJECT",
    "GOOGLE_CLOUD_PROJECT_ID",
    "GCLOUD_PROJECT",
)

# --- Table names ------------------------------------------------------------

SCAN_RUNS_TABLE = "scan_runs"
VULNERABILITY_FINDINGS_TABLE = "vulnerability_findings"

# --- Run status vocabulary --------------------------------------------------

STATUS_SUCCESS = "SUCCESS"
STATUS_FAILED = "FAILED"

# --- state.db read allowlists -----------------------------------------------
#
# These are the ONLY columns ever read out of the cm-owned SQLite schema.
# Columns absent from a given `cm` release are silently dropped; columns added
# by a future release are silently ignored.

FINDINGS_COLUMN_ALLOWLIST: Sequence[str] = (
    "finding_id",
    "title",
    "file_path",
    "severity",
    "confidence",
    "confidence_level",
    "analysis",
    "snippet",
    "vuln_type",
    "vuln_id",
    "verified",
    "muted",
    "mute_reason",
    "status",
    "source_stage",
    "start_line",
    "end_line",
    "fingerprint",
    "dismiss_reason",
    "created_at",
    "updated_at",
)

PATCHES_COLUMN_ALLOWLIST: Sequence[str] = (
    "finding_id",
    "status",
    "created_at",
)

# Columns that carry LLM-generated prose or verbatim source code. Withheld
# unless the operator explicitly opts in via CODEMENDER_BQ_INCLUDE_SNIPPETS.
SENSITIVE_FINDING_COLUMNS = ("analysis", "snippet")

# Finding statuses that count as successfully remediated / failed to remediate.
_FIXED_STATUSES = frozenset({"FIXED", "REMEDIATED", "PATCHED"})
_FAILED_FIX_STATUSES = frozenset({"FIX_FAILED", "PR_CREATION_FAILED", "PATCH_FAILED"})
# Statuses a finding can only hold after `cm verify` confirmed it. The worker's
# own verify gate is status-based, and cm does not reliably set a `verified`
# column, so these statuses also mark a row as verified.
_VERIFIED_STATUSES = frozenset({"VERIFIED", "CONFIRMED"})
_VERIFY_PASSED_STATUSES = _VERIFIED_STATUSES | _FIXED_STATUSES | _FAILED_FIX_STATUSES
# Statuses Stage 1 assigns to findings it filters out instead of remediating:
# an open pull request or branch already tracks them, or they pre-date the
# change under review. `scan_runs.skipped_duplicate_count` counts both.
SKIPPED_STATUSES = frozenset({"SKIPPED_DUPLICATE", "PRE_EXISTING_IGNORED"})

_CWE_PATTERN = re.compile(r"(CWE-\d+)", re.IGNORECASE)

# Matches a `cm --version` banner token that is *entirely* a dotted version
# number, optionally `v`-prefixed and optionally carrying a pre-release or
# build suffix. The banner text around the number is owned by the external
# `cm` binary and is free to change between releases, so nothing about the
# surrounding words is assumed; but the match is anchored to a whole token
# rather than searched for anywhere in the string, because a loose search
# happily picks a version out of the middle of an unrelated word (a toolchain
# stamp such as `go1.24.2` yields `24.2`) and silently records a number the
# scanner never had.
_VERSION_TOKEN_PATTERN = re.compile(
    r"^v?(\d+(?:\.\d+)+(?:[-+][0-9A-Za-z.\-+]*)?)$"
)

# Banners separate their parts with whitespace or a slash (`cm/1.2.3`).
_VERSION_SEPARATORS = re.compile(r"[\s/]+")

# Punctuation a version token may be wrapped in, e.g. `(1.2.3)` or `1.2.3,`.
_VERSION_TOKEN_PUNCTUATION = "()[]{}<>,;:.'\"`"

# Redundant path separators, which would otherwise split one file into two
# distinct values in the warehouse.
_REPEATED_SLASHES = re.compile(r"/{2,}")

_TRUTHY = frozenset({"true", "1", "yes", "on"})

# --- Streaming insert safety limits -----------------------------------------
#
# Telemetry is emitted at the very end of a scan, so anything that can block
# here blocks the scan itself. These bounds exist so a degraded warehouse
# degrades telemetry only.

# Hard wall-clock ceiling on a single insertAll request. Without this the
# client would wait on its default (effectively unbounded for a hung endpoint)
# while the scan sits idle at its final step.
INSERT_TIMEOUT_SECONDS = 30.0

# BigQuery's streaming API caps a single insertAll request at 50,000 rows and
# 10 MB of payload; it recommends batching at around 500 rows. A scan of a
# large repository can exceed both, especially with snippet export enabled, and
# an over-limit request fails wholesale -- losing every finding row rather than
# some. Chunking on both axes keeps a big scan exporting successfully.
MAX_ROWS_PER_REQUEST = 500
MAX_REQUEST_BYTES = 9 * 1024 * 1024


# --- Small coercion helpers -------------------------------------------------


def _as_str(value: Any) -> Optional[str]:
  """Coerces a SQLite value to a non-empty string, or None."""
  if value is None:
    return None
  text = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
  text = text.strip()
  return text or None


def _as_int(value: Any) -> Optional[int]:
  """Coerces a value to int, returning None rather than raising."""
  if value is None or isinstance(value, bool):
    return int(value) if isinstance(value, bool) else None
  try:
    return int(value)
  except (TypeError, ValueError):
    return None


def _as_bool(value: Any) -> Optional[bool]:
  """Coerces a SQLite 0/1/'true' style value to bool, or None."""
  if value is None:
    return None
  if isinstance(value, bool):
    return value
  if isinstance(value, (int, float)):
    return bool(value)
  text = _as_str(value)
  if text is None:
    return None
  return text.lower() in _TRUTHY


def _env_flag(key: str, default: bool = False) -> bool:
  """Reads a boolean environment flag."""
  raw = os.environ.get(key)
  if raw is None or not raw.strip():
    return default
  return raw.strip().lower() in _TRUTHY


def _utc_now_iso() -> str:
  """Returns the current UTC time as an RFC 3339 string BigQuery accepts."""
  return datetime.datetime.now(datetime.timezone.utc).isoformat()


def extract_cwe_id(*candidates: Optional[str]) -> Optional[str]:
  """Extracts a normalized `CWE-nnn` identifier from any of the given strings.

  Mirrors the CWE detection already used by the SARIF transformer so BigQuery
  and GitHub Code Scanning agree on the same identifier for a given finding.
  """
  for candidate in candidates:
    if not candidate:
      continue
    match = _CWE_PATTERN.search(str(candidate))
    if match:
      return match.group(1).upper()
  return None


def normalize_cm_version(raw_version: Optional[str]) -> Optional[str]:
  """Reduces a `cm --version` banner to the bare version number.

  The binary reports something like `cm version 1.2.3`, which groups badly in
  analytics: any future change to the surrounding banner text would fork one
  release into two distinct values. The first banner token that is *entirely*
  a version number is taken, so a version embedded in an unrelated word -- a
  toolchain stamp such as `go1.24.2` -- cannot be mistaken for the scanner's
  own.

  A banner carrying no recognisable version number is returned unchanged
  rather than discarded -- an unexpected string is still more useful for
  diagnosing a bad deployment than a NULL.
  """
  text = _as_str(raw_version)
  if text is None:
    return None
  for token in _VERSION_SEPARATORS.split(text):
    match = _VERSION_TOKEN_PATTERN.match(
        token.strip(_VERSION_TOKEN_PUNCTUATION)
    )
    if match:
      return match.group(1)
  return text


def repo_relative_path(
    raw_path: Any, repo_dir: Optional[str] = None
) -> Optional[str]:
  """Coerces a finding's file path to a repository-relative path.

  Findings come out of `state.db` with whatever path the scanner happened to
  see, which inside a container is an absolute path under the checkout mount
  (`/workspace/<repo>/src/...`). Such paths neither join across runs nor mean
  anything to a reader, so they are rewritten relative to the repository root.

  When the repository root is unknown -- or the path simply does not live
  under it -- the original value is preserved. Stripping only the filesystem
  root would yield a path that still joins with nothing while no longer being
  recognisably absolute, which is strictly worse than leaving it alone.
  """
  text = _as_str(raw_path)
  if text is None:
    return None
  try:
    normalized = normalize_repo_relative_path(text, repo_dir)
  except Exception:  # pylint: disable=broad-exception-caught
    # Path normalization is cosmetic; a surprising input must not cost the
    # row the rest of its fields.
    return text
  if not normalized:
    return text
  if text.startswith("/") and normalized == text.lstrip("/"):
    return text
  # A path that survived normalization may still carry redundant separators
  # (`src//a.py`), which would group as a distinct file from `src/a.py`.
  return _REPEATED_SLASHES.sub("/", normalized)


# --- Configuration resolution -----------------------------------------------


def resolve_dataset() -> Optional[str]:
  """Returns the configured BigQuery dataset name, or None if telemetry is off."""
  return (os.environ.get(ENV_DATASET) or "").strip() or None


def resolve_project() -> Optional[str]:
  """Returns the BigQuery project, falling back to the ambient GCP project."""
  explicit = (os.environ.get(ENV_PROJECT) or "").strip()
  if explicit:
    return explicit
  for key in _PROJECT_FALLBACK_ENV_KEYS:
    value = (os.environ.get(key) or "").strip()
    if value:
      return value
  return None


def include_snippets() -> bool:
  """Whether LLM analysis prose and raw source snippets may be exported.

  Defaults to False. These columns contain verbatim source code and
  vulnerability detail, which many regulated deployments are not permitted to
  replicate into a queryable warehouse.
  """
  return _env_flag(ENV_INCLUDE_SNIPPETS, default=False)


def telemetry_enabled() -> bool:
  """True only when a BigQuery dataset has been explicitly configured.

  Callers should gate *all* telemetry-only work (including reading `state.db`)
  behind this, so an unconfigured deployment pays no cost whatsoever.
  """
  return resolve_dataset() is not None


# --- Run context ------------------------------------------------------------


@dataclasses.dataclass
class ScanRunContext:
  """Mutable accumulator for the facts that make up one `scan_runs` row.

  A pipeline populates this progressively as information becomes available
  (repository is known early, token totals only at the very end). The failure
  guard reads whatever has been filled in at the moment the run dies, so even
  an early crash still produces an attributable row.
  """

  stage: str = "scan"
  scan_id: Optional[str] = None
  repository: Optional[str] = None
  target_branch: Optional[str] = None
  target_sha: Optional[str] = None
  scan_target: Optional[str] = None
  cm_version: Optional[str] = None
  find_model: Optional[str] = None
  verify_model: Optional[str] = None
  fix_model: Optional[str] = None
  total_findings_count: Optional[int] = None
  active_findings_count: Optional[int] = None
  skipped_duplicate_count: Optional[int] = None
  fixed_count: Optional[int] = None
  failed_fix_count: Optional[int] = None
  report_uri: Optional[str] = None
  execution_url: Optional[str] = None
  token_totals: Optional[Dict[str, Dict[str, Any]]] = None

  # Outcome of the opt-in Wiz SAST bridge for this repository: "enabled",
  # "not_enabled" or "failed" (NULL when the run died before it was decided).
  wiz_status: Optional[str] = None
  wiz_status_detail: Optional[str] = None
  wiz_reported_count: Optional[int] = None
  wiz_imported_count: Optional[int] = None
  # CodeMender IDs of findings imported from Wiz, used to label finding rows.
  wiz_imported_ids: Optional[List[str]] = None

  # Whether the worker ran with skip_verify. Only when it is explicitly False
  # does a FIXED / patch-failed status prove the finding passed `cm verify`
  # (with skip_verify the worker goes straight to fix).
  skip_verify: Optional[bool] = None

  # Absolute path of the checkout this run scanned. Not itself exported; it is
  # the reference point that turns the container-absolute paths recorded in
  # `state.db` into repository-relative paths that join across runs.
  repo_dir: Optional[str] = None

  # Wall-clock anchor for duration_seconds. Defaults to object construction,
  # which the runners perform as their very first statement.
  started_monotonic: float = dataclasses.field(default_factory=time.monotonic)
  started_at: str = dataclasses.field(default_factory=_utc_now_iso)

  # Findings captured earlier in the run, stashed here so that a failure after
  # the snapshot still exports them. Without this, a run that successfully
  # found and remediated vulnerabilities but then died during report upload
  # would contribute a FAILED row and no finding rows at all -- losing exactly
  # the data the scan had already done the expensive work to produce.
  pending_findings: Optional[List[Dict[str, Any]]] = None
  pending_finding_prs: Optional[Dict[str, str]] = None

  # Set once a row has been emitted, so the failure guard never double-writes.
  emitted: bool = False

  def elapsed_seconds(self) -> float:
    """Wall-clock seconds since this context was created."""
    return max(0.0, time.monotonic() - self.started_monotonic)

  def apply_config(self, config: Any) -> "ScanRunContext":
    """Copies the telemetry-relevant fields off an OrchestratorConfig."""
    if config is None:
      return self
    self.scan_id = self.scan_id or getattr(config, "scan_id", None)
    self.target_branch = self.target_branch or getattr(config, "target_branch", None)
    self.target_sha = self.target_sha or getattr(config, "target_sha", None)
    self.scan_target = self.scan_target or getattr(config, "scan_target", None)
    self.find_model = self.find_model or getattr(config, "find_model", None)
    self.verify_model = self.verify_model or getattr(config, "verify_model", None)
    self.fix_model = self.fix_model or getattr(config, "fix_model", None)
    self.execution_url = self.execution_url or getattr(config, "execution_url", None)
    if self.skip_verify is None:
      value = getattr(config, "skip_verify", None)
      self.skip_verify = value if isinstance(value, bool) else None
    return self

  def apply_default_model(self, default_model: Optional[str]) -> "ScanRunContext":
    """Backfills the model columns with the scanner's resolved default model.

    These columns answer "which model produced these findings?", so they have
    to record the model that actually ran. An explicit per-command or global
    override always wins; when none was set the run silently used whatever
    default the scanner binary resolved at startup, and leaving the columns
    NULL in that case makes every unoverridden run invisible to model
    comparisons -- which is the majority of runs.

    The default is supplied by the caller rather than resolved here so this
    module stays free of any knowledge of the scanner CLI, and so no
    subprocess is ever spawned on behalf of a disabled exporter.
    """
    resolved = (default_model or "").strip() or None
    if resolved is None:
      return self
    self.find_model = self.find_model or resolved
    self.verify_model = self.verify_model or resolved
    self.fix_model = self.fix_model or resolved
    return self

  def apply_wiz(self, wiz: Optional[Dict[str, Any]]) -> "ScanRunContext":
    """Copies the Wiz bridge outcome recorded in scan metadata."""
    if not isinstance(wiz, dict):
      return self
    self.wiz_status = _as_str(wiz.get("status")) or self.wiz_status
    self.wiz_status_detail = _as_str(wiz.get("detail")) or None
    self.wiz_reported_count = _as_int(wiz.get("reported_count"))
    self.wiz_imported_count = _as_int(wiz.get("imported_count"))
    ids = wiz.get("force_verify_ids") or wiz.get("imported_ids") or []
    self.wiz_imported_ids = [str(i) for i in ids] if isinstance(ids, list) else []
    return self


# --- Row builders -----------------------------------------------------------


def flatten_token_totals(
    token_totals: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
  """Flattens the per-model `token_totals` mapping into a REPEATED STRUCT.

  `token_usage.json` stores `{model: {in_tokens, out_tokens, total_tokens}}`.
  BigQuery cannot represent an open-ended map, so each model becomes one
  element of a repeated record keyed by an explicit `model` field. This keeps
  per-model cost attribution queryable with a simple UNNEST.
  """
  if not isinstance(token_totals, dict):
    return []

  rows: List[Dict[str, Any]] = []
  for model, usage in token_totals.items():
    model_name = _as_str(model) or "unknown"
    if isinstance(usage, dict):
      in_tokens = _as_int(usage.get("in_tokens")) or 0
      out_tokens = _as_int(usage.get("out_tokens")) or 0
      total_tokens = _as_int(usage.get("total_tokens"))
    elif isinstance(usage, (int, float)):
      # Degenerate shape emitted by some cm versions: a bare scalar total.
      in_tokens = 0
      out_tokens = 0
      total_tokens = _as_int(usage)
    else:
      continue

    if total_tokens is None:
      total_tokens = in_tokens + out_tokens

    rows.append({
        "model": model_name,
        "in_tokens": in_tokens,
        "out_tokens": out_tokens,
        "total_tokens": total_tokens,
    })

  rows.sort(key=lambda r: r["model"])
  return rows


def build_scan_run_row(
    ctx: ScanRunContext,
    status: str,
    scan_timestamp: Optional[str] = None,
    failure_reason: Optional[str] = None,
    duration_seconds: Optional[float] = None,
) -> Dict[str, Any]:
  """Builds the single `scan_runs` row for a terminated scan execution."""
  effective_duration = (
      duration_seconds if duration_seconds is not None else ctx.elapsed_seconds()
  )
  return {
      "scan_id": _as_str(ctx.scan_id) or "unknown",
      "scan_timestamp": scan_timestamp or _utc_now_iso(),
      "repository": _as_str(ctx.repository),
      "target_branch": _as_str(ctx.target_branch),
      "target_sha": _as_str(ctx.target_sha),
      "scan_target": _as_str(ctx.scan_target),
      "stage": _as_str(ctx.stage),
      "status": status,
      "failure_reason": _as_str(failure_reason),
      "duration_seconds": round(float(effective_duration), 3),
      "cm_version": normalize_cm_version(ctx.cm_version),
      "find_model": _as_str(ctx.find_model),
      "verify_model": _as_str(ctx.verify_model),
      "fix_model": _as_str(ctx.fix_model),
      "total_findings_count": ctx.total_findings_count,
      "active_findings_count": ctx.active_findings_count,
      "skipped_duplicate_count": ctx.skipped_duplicate_count,
      "fixed_count": ctx.fixed_count,
      "failed_fix_count": ctx.failed_fix_count,
      "report_uri": _as_str(ctx.report_uri),
      "execution_url": _as_str(ctx.execution_url),
      "token_totals": flatten_token_totals(ctx.token_totals),
      "wiz_status": _as_str(ctx.wiz_status),
      "wiz_status_detail": _as_str(ctx.wiz_status_detail),
      "wiz_reported_count": _as_int(ctx.wiz_reported_count),
      "wiz_imported_count": _as_int(ctx.wiz_imported_count),
  }


def build_finding_rows(
    ctx: ScanRunContext,
    findings: Optional[Iterable[Dict[str, Any]]],
    scan_timestamp: Optional[str] = None,
    finding_prs: Optional[Dict[str, str]] = None,
    with_snippets: Optional[bool] = None,
) -> List[Dict[str, Any]]:
  """Maps a `state.db` findings snapshot onto `vulnerability_findings` rows."""
  if not findings:
    return []

  timestamp = scan_timestamp or _utc_now_iso()
  scan_id = _as_str(ctx.scan_id) or "unknown"
  repository = _as_str(ctx.repository)
  prs = finding_prs or {}
  repo_dir = _as_str(ctx.repo_dir)
  emit_sensitive = (
      include_snippets() if with_snippets is None else bool(with_snippets)
  )
  wiz_ids = {str(i) for i in (ctx.wiz_imported_ids or [])}

  rows: List[Dict[str, Any]] = []
  for finding in findings:
    if not isinstance(finding, dict):
      continue
    finding_id = _as_str(finding.get("finding_id"))
    if not finding_id:
      # A row with no primary key is unjoinable and therefore worthless.
      continue

    title = _as_str(finding.get("title"))
    status = (_as_str(finding.get("status")) or "DETECTED").upper()
    vuln_type = _as_str(finding.get("vuln_type"))
    severity = _as_str(finding.get("severity"))
    confidence_level = _as_str(
        finding.get("confidence_level")
    ) or _as_str(finding.get("confidence"))

    row: Dict[str, Any] = {
        "finding_id": finding_id,
        "scan_id": scan_id,
        "scan_timestamp": timestamp,
        "repository": repository,
        "title": title,
        "vuln_type": vuln_type,
        "cwe_id": extract_cwe_id(finding.get("vuln_id"), vuln_type, title),
        "severity": severity.upper() if severity else None,
        "confidence_level": confidence_level.upper() if confidence_level else None,
        "file_path": repo_relative_path(finding.get("file_path"), repo_dir),
        "start_line": _as_int(finding.get("start_line")),
        "end_line": _as_int(finding.get("end_line")),
        "status": status,
        "source_stage": _as_str(finding.get("source_stage")),
        "verified": _row_verified(finding, status, finding_id in wiz_ids, ctx.skip_verify),
        "muted": _as_bool(finding.get("muted")),
        "mute_reason": _as_str(finding.get("mute_reason"))
        or _as_str(finding.get("dismiss_reason")),
        "fingerprint": _as_str(finding.get("fingerprint")),
        "fix_pr_url": _as_str(prs.get(finding_id)),
        "patch_status": _as_str(finding.get("patch_status")),
        "finding_source": "wiz" if finding_id in wiz_ids else "codemender",
    }

    # Compliance gate: prose and verbatim source never leave the scanner
    # unless the operator has explicitly opted in.
    if emit_sensitive:
      row["analysis"] = _as_str(finding.get("analysis"))
      row["snippet"] = _as_str(finding.get("snippet"))

    rows.append(row)

  return rows


def _row_verified(
    finding: Dict[str, Any], status: str, force_verified: bool,
    skip_verify: Optional[bool],
) -> Optional[bool]:
  """Whether `cm verify` confirmed this finding.

  cm's own `verified` column is honoured when truthy, but it is not reliably
  set, so the answer is also derived the way the worker gates fixes: a
  VERIFIED status can only come from `cm verify`, and when verification was
  mandatory (skip_verify explicitly off, or an imported finding that is always
  force-verified) a fixed or fix-failed status implies verification passed.
  """
  if _as_bool(finding.get("verified")):
    return True
  if status in _VERIFIED_STATUSES:
    return True
  if status in _VERIFY_PASSED_STATUSES and (force_verified or skip_verify is False):
    return True
  return _as_bool(finding.get("verified"))


def summarize_remediation(
    findings: Optional[Iterable[Dict[str, Any]]],
) -> Dict[str, int]:
  """Counts fixed / failed-fix / skipped-duplicate findings in a snapshot.

  Only an explicit failure status counts as a failed fix. The worker records
  FIX_FAILED when every `cm fix` attempt fails, so a finding that is still
  VERIFIED was never sent to fix (for example report-only remediation or a
  run that ended early) and is not counted as a failure.
  """
  counts = {"fixed": 0, "failed_fix": 0, "skipped_duplicate": 0, "total": 0}
  for finding in findings or []:
    if not isinstance(finding, dict):
      continue
    counts["total"] += 1
    status = (_as_str(finding.get("status")) or "").upper()
    patch_status = (_as_str(finding.get("patch_status")) or "").upper()
    if status in _FIXED_STATUSES or patch_status in _FIXED_STATUSES:
      counts["fixed"] += 1
    elif status in _FAILED_FIX_STATUSES or patch_status in _FAILED_FIX_STATUSES:
      counts["failed_fix"] += 1
    if status in SKIPPED_STATUSES:
      counts["skipped_duplicate"] += 1
  return counts


# --- state.db snapshot ------------------------------------------------------


def _table_exists(cursor: sqlite3.Cursor, table_name: str) -> bool:
  cursor.execute(
      "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
      (table_name,),
  )
  return cursor.fetchone() is not None


def _available_columns(
    cursor: sqlite3.Cursor, table_name: str, allowlist: Sequence[str]
) -> List[str]:
  """Intersects an allowlist with the columns the live schema actually has."""
  cursor.execute(f"PRAGMA table_info({table_name})")
  present = {row[1] for row in cursor.fetchall()}
  return [column for column in allowlist if column in present]


def _load_patch_statuses(cursor: sqlite3.Cursor) -> Dict[str, str]:
  """Returns the most recent patch status per finding, if a patches table exists."""
  if not _table_exists(cursor, "patches"):
    return {}
  columns = _available_columns(cursor, "patches", PATCHES_COLUMN_ALLOWLIST)
  if "finding_id" not in columns or "status" not in columns:
    return {}

  order_clause = " ORDER BY created_at" if "created_at" in columns else ""
  cursor.execute(f"SELECT {', '.join(columns)} FROM patches{order_clause}")
  statuses: Dict[str, str] = {}
  for row in cursor.fetchall():
    record = dict(zip(columns, row))
    finding_id = _as_str(record.get("finding_id"))
    status = _as_str(record.get("status"))
    if finding_id and status:
      # Later rows win, which with the ORDER BY means "latest patch attempt".
      statuses[finding_id] = status
  return statuses


def snapshot_state_db_findings(db_path: str) -> List[Dict[str, Any]]:
  """Reads a findings snapshot out of a cm-owned `state.db`.

  Uses an explicit column allowlist intersected against the live schema, so
  neither a missing column (older `cm`) nor an added column (newer `cm`) can
  break the read. Returns an empty list -- never raises -- on any failure.

  Callers on the aggregate path must invoke this *before* the scoped cleanup
  DELETE, since that DELETE permanently removes `DISMISSED` (and, on PR scans,
  `PRE_EXISTING_IGNORED` / `SKIPPED_DUPLICATE`) rows from the reporting DB.
  """
  if not db_path or not os.path.exists(db_path):
    return []

  try:
    with closing(sqlite3.connect(db_path)) as conn:
      cursor = conn.cursor()
      if not _table_exists(cursor, "findings"):
        logger.warning(
            "state.db at %s has no 'findings' table; skipping telemetry snapshot.",
            db_path,
        )
        return []

      columns = _available_columns(cursor, "findings", FINDINGS_COLUMN_ALLOWLIST)
      if "finding_id" not in columns:
        logger.warning(
            "state.db 'findings' table lacks a finding_id column; skipping"
            " telemetry snapshot."
        )
        return []

      missing = [c for c in FINDINGS_COLUMN_ALLOWLIST if c not in columns]
      if missing:
        logger.info(
            "state.db 'findings' table is missing %d expected column(s) (%s);"
            " exporting the remaining columns.",
            len(missing),
            ", ".join(missing),
        )

      patch_statuses = _load_patch_statuses(cursor)

      cursor.execute(
          f"SELECT {', '.join(columns)} FROM findings ORDER BY finding_id"
      )
      snapshot: List[Dict[str, Any]] = []
      for row in cursor.fetchall():
        record = dict(zip(columns, row))
        finding_id = _as_str(record.get("finding_id"))
        if finding_id and finding_id in patch_statuses:
          record["patch_status"] = patch_statuses[finding_id]
        snapshot.append(record)
      return snapshot
  except sqlite3.Error as e:
    logger.warning("Failed to snapshot findings from %s for telemetry: %s", db_path, e)
    return []
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.warning("Unexpected error snapshotting %s for telemetry: %s", db_path, e)
    return []


# --- BigQuery client --------------------------------------------------------


def _chunk_rows(
    rows: Sequence[Dict[str, Any]],
) -> Iterable[List[Dict[str, Any]]]:
  """Splits rows into batches that fit BigQuery's per-request insert limits.

  Yields batches bounded by both `MAX_ROWS_PER_REQUEST` and, approximately,
  `MAX_REQUEST_BYTES`. A single row that is itself over the byte budget is
  still yielded on its own rather than dropped: BigQuery may reject it, but
  that is a better outcome than silently discarding it here.
  """
  batch: List[Dict[str, Any]] = []
  batch_bytes = 0
  for row in rows:
    try:
      row_bytes = len(json.dumps(row, default=str).encode("utf-8"))
    except (TypeError, ValueError):
      # Unmeasurable rows are assumed small; the insert itself will decide.
      row_bytes = 0
    if batch and (
        len(batch) >= MAX_ROWS_PER_REQUEST
        or batch_bytes + row_bytes > MAX_REQUEST_BYTES
    ):
      yield batch
      batch = []
      batch_bytes = 0
    batch.append(row)
    batch_bytes += row_bytes
  if batch:
    yield batch


def _default_client_factory(project: Optional[str]):
  """Constructs a real BigQuery client, importing the library lazily.

  The import is deliberately deferred: `google-cloud-bigquery` is only needed
  when telemetry is switched on, so deployments that never set
  CODEMENDER_BQ_DATASET do not need the dependency installed at all.
  """
  from google.cloud import bigquery  # pylint: disable=import-outside-toplevel

  return bigquery.Client(project=project) if project else bigquery.Client()


class BigQueryTelemetryExporter:
  """Streams scan telemetry rows into native BigQuery tables.

  The exporter is inert unless a dataset is configured. It owns no retry or
  buffering logic on purpose: telemetry is best-effort, and a scan must never
  stall waiting on the warehouse.
  """

  def __init__(
      self,
      dataset: Optional[str] = None,
      project: Optional[str] = None,
      location: Optional[str] = None,
      client=None,
      client_factory=None,
  ):
    self._dataset = dataset if dataset is not None else resolve_dataset()
    self._project = project if project is not None else resolve_project()
    self._location = location if location is not None else (
        (os.environ.get(ENV_LOCATION) or "").strip() or None
    )
    self._client = client
    self._client_factory = client_factory or _default_client_factory

  @property
  def enabled(self) -> bool:
    """True only when a dataset has been configured."""
    return bool(self._dataset)

  @property
  def dataset(self) -> Optional[str]:
    return self._dataset

  def table_id(self, table_name: str) -> str:
    """Fully qualifies a table name for the configured project and dataset."""
    if self._project:
      return f"{self._project}.{self._dataset}.{table_name}"
    return f"{self._dataset}.{table_name}"

  def _get_client(self):
    if self._client is None:
      self._client = self._client_factory(self._project)
    return self._client

  def insert_rows(self, table_name: str, rows: Sequence[Dict[str, Any]]) -> bool:
    """Streams rows into one table. Returns True only on a fully clean insert.

    Rows are chunked to stay inside BigQuery's per-request row and byte caps,
    and each request is bounded by a timeout so a hung warehouse cannot stall
    the scan that is waiting on it.
    """
    if not self.enabled or not rows:
      return False
    client = self._get_client()
    table_id = self.table_id(table_name)

    ok = True
    inserted = 0
    for chunk in _chunk_rows(rows):
      errors = client.insert_rows_json(
          table_id,
          chunk,
          # Best-effort semantics. Without these, a single row that violates
          # the table schema -- or one extra column after a `cm` upgrade or a
          # Terraform/runtime snippet-flag mismatch -- rejects the entire
          # batch, turning a partial-data problem into a total-data-loss one.
          skip_invalid_rows=True,
          ignore_unknown_values=True,
          timeout=INSERT_TIMEOUT_SECONDS,
      )
      if errors:
        ok = False
        logger.warning(
            "BigQuery rejected %d of %d row(s) for table %s: %s",
            len(errors),
            len(chunk),
            table_name,
            errors,
        )
        inserted += max(0, len(chunk) - len(errors))
      else:
        inserted += len(chunk)

    logger.info(
        "Exported %d of %d telemetry row(s) to BigQuery table %s.",
        inserted,
        len(rows),
        table_id,
    )
    return ok


  def export(
      self,
      scan_run_row: Optional[Dict[str, Any]],
      finding_rows: Optional[Sequence[Dict[str, Any]]] = None,
  ) -> bool:
    """Writes the run row and its findings. Returns True if everything landed."""
    if not self.enabled:
      return False
    ok = True
    if scan_run_row:
      ok = self.insert_rows(SCAN_RUNS_TABLE, [scan_run_row]) and ok
    if finding_rows:
      ok = self.insert_rows(VULNERABILITY_FINDINGS_TABLE, finding_rows) and ok
    return ok


# --- Public entry points ----------------------------------------------------


def emit_scan_telemetry(
    ctx: ScanRunContext,
    status: str = STATUS_SUCCESS,
    findings: Optional[Iterable[Dict[str, Any]]] = None,
    finding_prs: Optional[Dict[str, str]] = None,
    failure_reason: Optional[str] = None,
    duration_seconds: Optional[float] = None,
    exporter: Optional[BigQueryTelemetryExporter] = None,
) -> bool:
  """Emits one `scan_runs` row plus its `vulnerability_findings` rows.

  This is the single entry point the runners call. It is a hard no-op when
  telemetry is unconfigured, and it never propagates an exception -- a
  telemetry failure must not change the outcome of a security scan.

  Returns True only if rows were actually accepted by BigQuery.
  """
  try:
    if ctx is None:
      return False

    active_exporter = exporter or BigQueryTelemetryExporter()
    if not active_exporter.enabled:
      # Hard no-op: no client construction, no network, no row building.
      return False

    # Guard against a success row and a guard-emitted failure row racing for
    # the same execution.
    if ctx.emitted:
      logger.debug("Telemetry already emitted for scan %s; skipping.", ctx.scan_id)
      return False
    ctx.emitted = True

    scan_timestamp = _utc_now_iso()
    finding_list = list(findings) if findings else []

    if finding_list:
      remediation = summarize_remediation(finding_list)
      if ctx.fixed_count is None:
        ctx.fixed_count = remediation["fixed"]
      if ctx.failed_fix_count is None:
        ctx.failed_fix_count = remediation["failed_fix"]
      if ctx.total_findings_count is None:
        ctx.total_findings_count = remediation["total"]
      if ctx.skipped_duplicate_count is None:
        ctx.skipped_duplicate_count = remediation["skipped_duplicate"]

    scan_run_row = build_scan_run_row(
        ctx,
        status=status,
        scan_timestamp=scan_timestamp,
        failure_reason=failure_reason,
        duration_seconds=duration_seconds,
    )
    finding_rows = build_finding_rows(
        ctx,
        finding_list,
        scan_timestamp=scan_timestamp,
        finding_prs=finding_prs,
    )
    return active_exporter.export(scan_run_row, finding_rows)
  except Exception as e:  # pylint: disable=broad-exception-caught
    # Deliberately broad: telemetry must never fail or block a security scan.
    logger.warning("BigQuery telemetry export failed (non-fatal): %s", e)
    return False


@contextlib.contextmanager
def telemetry_run_guard(ctx: ScanRunContext):
  """Guarantees a `scan_runs` row exists even when a pipeline dies.

  Without this, the ~dozen `sys.exit(1)` paths in the scan and aggregate
  runners would produce no telemetry at all, leaving "which repositories
  failed last night?" permanently unanswerable. Wrapping the pipeline body
  means a FAILED row is written for every abnormal termination, without having
  to thread a hook through each individual exit site.

  A pipeline that has already emitted its own row (the success and
  zero-finding paths) sets `ctx.emitted`, so this guard never double-writes.
  The original exception or exit code is always re-raised unchanged.

  Any findings the pipeline stashed in `ctx.pending_findings` before dying are
  exported alongside the FAILED row. This matters for late failures -- for
  example a report upload that aborts the aggregate stage after findings were
  already discovered, verified, and patched -- where the findings themselves
  are perfectly good data that would otherwise be thrown away.
  """
  try:
    yield ctx
  except SystemExit as exc:
    code = exc.code
    if code not in (0, None) and not ctx.emitted:
      emit_scan_telemetry(
          ctx,
          status=STATUS_FAILED,
          findings=ctx.pending_findings,
          finding_prs=ctx.pending_finding_prs,
          failure_reason=f"{ctx.stage} stage exited with code {code}",
      )
    raise
  except BaseException as exc:  # pylint: disable=broad-except
    if not ctx.emitted:
      emit_scan_telemetry(
          ctx,
          status=STATUS_FAILED,
          findings=ctx.pending_findings,
          finding_prs=ctx.pending_finding_prs,
          failure_reason=f"{type(exc).__name__}: {exc}",
      )
    raise
