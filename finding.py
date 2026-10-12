from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

# --- Constants & Pattern Definitions ---

_TRUTHY = frozenset({"true", "1", "yes", "on"})

SKIPPED_STATUSES = frozenset({"SKIPPED_DUPLICATE", "PRE_EXISTING_IGNORED"})


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
  def finding_id(self) -> Optional[str]:
    return _as_str(self._get("finding_id"))

  @property
  def repository(self) -> Optional[str]:
    return _as_str(self._get("repository"))

  @property
  def file_path(self) -> Optional[str]:
    return _as_str(self._get("file_path"))

  @property
  def start_line(self) -> Optional[int]:
    return _as_int(self._get("start_line"))

  @property
  def end_line(self) -> Optional[int]:
    return _as_int(self._get("end_line"))

  @property
  def title(self) -> Optional[str]:
    return _as_str(self._get("title"))

  @property
  def vuln_type(self) -> Optional[str]:
    return _as_str(self._get("vuln_type"))

  @property
  def vuln_id(self) -> Optional[str]:
    return _as_str(self._get("vuln_id"))

  @property
  def severity(self) -> Optional[str]:
    val = _as_str(self._get("severity"))
    return val.upper() if val else None

  @property
  def confidence_level(self) -> Optional[str]:
    val = _as_str(self._get("confidence_level"))
    return val.upper() if val else None

  @property
  def confidence(self) -> Optional[str]:
    return _as_int(self._get("confidence"))

  @property
  def status(self) -> Optional[str]:
    val = _as_str(self._get("status"))
    return val.upper() if val else None

  @property
  def source_stage(self) -> Optional[str]:
    return _as_str(self._get("source_stage"))

  @property
  def verified(self) -> Optional[bool]:
    return _as_bool(self._get("verified"))

  @property
  def muted(self) -> Optional[bool]:
    return _as_bool(self._get("muted"))

  @property
  def dismiss_reason(self) -> Optional[str]:
    return _as_str(self._get("dismiss_reason"))

  @property
  def mute_reason(self) -> Optional[str]:
    return _as_str(self._get("mute_reason"))

  @property
  def fingerprint(self) -> Optional[str]:
    return _as_str(self._get("fingerprint"))

  @property
  def analysis(self) -> Optional[str]:
    return _as_str(self._get("analysis"))

  @property
  def snippet(self) -> Optional[str]:
    return _as_str(self._get("snippet"))

  @property
  def scan_timestamp(self) -> Optional[str]:
    return _as_str(self._get("scan_timestamp"))

  @property
  def session_id(self) -> Optional[str]:
    return _as_str(self._get("session_id"))

  @property
  def updated_at(self) -> Optional[str]:
    return _as_str(self._get("updated_at"))

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
    return {
        "analysis": self.analysis,
        "file_path": self.file_path,
        "end_line": self.end_line,
        "start_line": self.start_line,
        "severity": self.severity,
        "snippet": self.snippet,
        "title": self.title,
        "vuln_type": self.vuln_type,
    }

  def __repr__(self) -> str:
    return f"Finding(finding_id={self.finding_id!r}, file_path={self.file_path!r}, status={self.status!r})"

  def __eq__(self, other: Any) -> bool:
    if isinstance(other, Finding):
      return self.finding_id == other.finding_id
    return False

  def __hash__(self) -> int:
    return hash(self.finding_id)