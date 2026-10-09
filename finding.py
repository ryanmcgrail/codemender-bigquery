from __future__ import annotations

import datetime
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

# --- Constants & Pattern Definitions ---

_CWE_PATTERN = re.compile(r"(CWE-\d+)", re.IGNORECASE)
_TRUTHY = frozenset({"true", "1", "yes", "on"})

_FIXED_STATUSES = frozenset({"FIXED", "REMEDIATED", "PATCHED"})
_FAILED_FIX_STATUSES = frozenset({"FIX_FAILED", "PR_CREATION_FAILED", "PATCH_FAILED"})
_VERIFIED_STATUSES = frozenset({"VERIFIED", "CONFIRMED"})
_VERIFY_PASSED_STATUSES = _VERIFIED_STATUSES | _FIXED_STATUSES | _FAILED_FIX_STATUSES
SKIPPED_STATUSES = frozenset({"SKIPPED_DUPLICATE", "PRE_EXISTING_IGNORED"})
_CLOSED_STATUSES = frozenset(
    {"FIXED", "REMEDIATED", "PATCHED", "DISMISSED", "FALSE_POSITIVE", "RESOLVED"}
)

_FINDING_KEY_ALIASES = {
    "finding_id": "FindingID",
    "session_id": "SessionID",
    "title": "Title",
    "file_path": "FilePath",
    "severity": "Severity",
    "confidence": "Confidence",
    "analysis": "Analysis",
    "snippet": "Snippet",
    "vuln_type": "VulnType",
    "vuln_id": "VulnID",
    "fingerprint": "Fingerprint",
    "status": "Status",
    "source_stage": "SourceStage",
    "finding_json": "FindingJSON",
    "updated_at": "UpdatedAt",
    "start_line": "StartLine",
    "end_line": "EndLine",
    "dismiss_reason": "DismissReason",
    "confidence_level": "ConfidenceLevel",
}

# Reverse aliases: PascalCase -> snake_case
_PASCAL_TO_SNAKE = {v: k for k, v in _FINDING_KEY_ALIASES.items()}
_PASCAL_TO_SNAKE["Line"] = "start_line"
_PASCAL_TO_SNAKE["line"] = "start_line"
_PASCAL_TO_SNAKE["Message"] = "analysis"
_PASCAL_TO_SNAKE["message"] = "analysis"
_PASCAL_TO_SNAKE["confidence"] = "confidence_level"
_PASCAL_TO_SNAKE["Confidence"] = "confidence_level"

IMPORTED_FINDING_FIELDS = (
    "file_path",
    "line",
    "end_line",
    "title",
    "message",
    "severity",
    "vuln_type",
    "snippet",
)


# --- Helper Conversion Functions ---


def _as_str(value: Any) -> Optional[str]:
  """Coerces a value to a non-empty string, or None."""
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
  """Coerces a 0/1/'true' style value to bool, or None."""
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


def extract_cwe_id(*candidates: Optional[str]) -> Optional[str]:
  """Extracts a normalized `CWE-nnn` identifier from candidates."""
  for candidate in candidates:
    if not candidate:
      continue
    match = _CWE_PATTERN.search(str(candidate))
    if match:
      return match.group(1).upper()
  return None


# --- Main Finding Class ---


class Finding:
  """Unified representation of a security vulnerability finding wrapping a raw dict."""

  def __init__(
      self,
      raw: Optional[Mapping[str, Any]] = None,
      **kwargs: Any,
  ):
    self._raw: Dict[str, Any] = {}
    if raw:
      self._raw.update(dict(raw.items()) if hasattr(raw, "items") else dict(raw))
    if kwargs:
      self._raw.update(kwargs)

  def _get(self, *keys: str) -> Any:
    for k in keys:
      if k in self._raw and self._raw[k] is not None:
        return self._raw[k]
    return None

  # --- Properties ---

  @property
  def raw(self) -> Dict[str, Any]:
    return self._raw

  @property
  def raw_data(self) -> Dict[str, Any]:
    return self._raw

  @property
  def finding_id(self) -> str:
    val = self._get("finding_id", "FindingID", "id")
    return str(val).strip() if val is not None else ""

  @property
  def repository(self) -> Optional[str]:
    return _as_str(self._get("repository", "Repository"))

  @property
  def file_path(self) -> str:
    val = self._get("file_path", "FilePath", "path")
    if not val:
      return ""
    return str(val)

  @property
  def start_line(self) -> Optional[int]:
    return _as_int(self._get("start_line", "StartLine", "line", "Line"))

  @property
  def line(self) -> Optional[int]:
    return self.start_line

  @property
  def end_line(self) -> Optional[int]:
    return _as_int(self._get("end_line", "EndLine"))

  @property
  def title(self) -> str:
    return _as_str(self._get("title", "Title")) or ""

  @property
  def vuln_type(self) -> Optional[str]:
    return _as_str(self._get("vuln_type", "VulnType", "type"))

  @property
  def vuln_id(self) -> Optional[str]:
    return _as_str(self._get("vuln_id", "VulnID"))

  @property
  def cwe_id(self) -> Optional[str]:
    val = _as_str(self._get("cwe_id", "CweID"))
    if val:
      return val
    return extract_cwe_id(self.vuln_id, self.vuln_type, self.title)

  @property
  def severity(self) -> Optional[str]:
    val = _as_str(self._get("severity", "Severity"))
    return val.upper() if val else None

  @property
  def confidence_level(self) -> Optional[str]:
    val = _as_str(
        self._get("confidence_level", "ConfidenceLevel", "confidence", "Confidence")
    )
    return val.upper() if val else None

  @property
  def confidence(self) -> Optional[str]:
    return self.confidence_level

  @property
  def status(self) -> str:
    val = _as_str(self._get("status", "Status")) or "DETECTED"
    return val.upper()

  @property
  def source_stage(self) -> Optional[str]:
    return _as_str(self._get("source_stage", "SourceStage"))

  @property
  def verified(self) -> Optional[bool]:
    return _as_bool(self._get("verified", "Verified"))

  @property
  def muted(self) -> Optional[bool]:
    return _as_bool(self._get("muted", "Muted"))

  @property
  def mute_reason(self) -> Optional[str]:
    return _as_str(
        self._get("mute_reason", "MuteReason", "dismiss_reason", "DismissReason")
    )

  @property
  def fingerprint(self) -> Optional[str]:
    return _as_str(self._get("fingerprint", "Fingerprint"))

  @property
  def fix_pr_url(self) -> Optional[str]:
    return _as_str(self._get("fix_pr_url", "FixPrUrl", "fix_pr", "FixPr"))

  @property
  def patch_status(self) -> Optional[str]:
    return _as_str(self._get("patch_status", "PatchStatus"))

  @property
  def finding_source(self) -> Optional[str]:
    return _as_str(self._get("finding_source", "FindingSource")) or "codemender"

  @property
  def analysis(self) -> Optional[str]:
    return _as_str(self._get("analysis", "Analysis", "message", "Message"))

  @property
  def message(self) -> Optional[str]:
    return self.analysis

  @property
  def snippet(self) -> Optional[str]:
    return _as_str(self._get("snippet", "Snippet"))

  @property
  def scan_id(self) -> Optional[str]:
    return _as_str(self._get("scan_id", "ScanID"))

  @property
  def scan_timestamp(self) -> Optional[str]:
    return _as_str(self._get("scan_timestamp", "ScanTimestamp"))

  @property
  def session_id(self) -> Optional[str]:
    return _as_str(self._get("session_id", "SessionID"))

  @property
  def updated_at(self) -> Optional[str]:
    return _as_str(self._get("updated_at", "UpdatedAt"))

  # --- Factory Methods ---

  @classmethod
  def from_dict(
      cls,
      data: Mapping[str, Any],
  ) -> Finding:
    """Creates a Finding instance from a dictionary."""
    raw: Dict[str, Any] = dict(data.items()) if hasattr(data, "items") else dict(data)
    return cls(raw)

  # --- Serialization & Export Formats ---

  def to_cm_import_record(self) -> Dict[str, Any]:
    """Converts finding to simple-JSON record accepted by CodeMender import."""
    if not self.file_path:
      raise ValueError("A BigQuery finding without file_path cannot be imported")

    title = self.title or self.vuln_type or "CodeMender finding"
    record: Dict[str, Any] = {
        "file_path": self.file_path,
        "title": title,
        "message": self.analysis or "Imported from CodeMender BigQuery findings.",
        "severity": self.severity or "MEDIUM",
        "vuln_type": self.vuln_type or self.cwe_id or title,
    }
    if self.start_line is not None:
      record["line"] = self.start_line
    if self.end_line is not None:
      record["end_line"] = self.end_line
    if self.snippet:
      record["snippet"] = self.snippet
    return record

  def __repr__(self) -> str:
    return f"Finding(finding_id={self.finding_id!r}, file_path={self.file_path!r}, status={self.status!r})"

  def __eq__(self, other: Any) -> bool:
    if isinstance(other, Finding):
      return self.finding_id == other.finding_id
    return False

  def __hash__(self) -> int:
    return hash(self.finding_id)


Findings = Finding
