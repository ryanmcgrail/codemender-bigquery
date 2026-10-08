"""Encapsulates finding data and domain logic across CodeMender BigQuery workflows.

This module provides the `Finding` class, unifying finding representation,
normalization, fingerprint generation, scoring/matching, and transformations
between CodeMender CLI formats and BigQuery telemetry formats.
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import os
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

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


def _utc_now_iso() -> str:
  """Returns current UTC time as an RFC 3339 string BigQuery accepts."""
  return datetime.datetime.now(datetime.timezone.utc).isoformat()


def extract_cwe_id(*candidates: Optional[str]) -> Optional[str]:
  """Extracts a normalized `CWE-nnn` identifier from candidates."""
  for candidate in candidates:
    if not candidate:
      continue
    match = _CWE_PATTERN.search(str(candidate))
    if match:
      return match.group(1).upper()
  return None


def normalize_repo_relative_path(path: str, repo_dir: Optional[str] = None) -> str:
  """Normalizes a file path to be strictly repository-relative with forward slashes."""
  if not path:
    return ""
  p = str(path).strip().replace("\\", "/")
  if repo_dir:
    clean_repo_dir = os.path.abspath(repo_dir).replace("\\", "/")
    if p == clean_repo_dir:
      return ""
    if p.startswith(clean_repo_dir + "/"):
      p = p[len(clean_repo_dir) + 1 :]
    elif os.path.isabs(p):
      try:
        rel = os.path.relpath(p, clean_repo_dir).replace("\\", "/")
        if not rel.startswith("../") and rel != "..":
          p = rel
      except ValueError:
        pass

  # Strip leading CI runner mount patterns if present
  p = re.sub(r"^/?__w/[^/]+/[^/]+(?:/[^/]+)?/", "", p)
  p = re.sub(r"^/?github/workspace/", "", p)
  # Strip any leading slashes, dots, or relative traversal markers
  p = re.sub(r"^(\.\./)+", "", p)
  p = re.sub(r"^\.?/+", "", p)
  return p


def compute_finding_fingerprint(
    file_path: str, vuln_type: str, start_line: int
) -> str:
  """Computes a deterministic 8-character SHA256 fingerprint for a finding."""
  norm_path = normalize_repo_relative_path(file_path)
  norm_type = (vuln_type or "vulnerability").strip().lower()
  raw_hash_str = f"{norm_path}|{norm_type}|{start_line}"
  return hashlib.sha256(raw_hash_str.encode("utf-8")).hexdigest()[:8]


# --- Main Finding Class ---


@dataclasses.dataclass
class Finding:
  """Unified representation of a security vulnerability finding."""

  finding_id: str = ""
  repository: Optional[str] = None
  file_path: str = ""
  start_line: Optional[int] = None
  end_line: Optional[int] = None
  title: str = ""
  vuln_type: Optional[str] = None
  vuln_id: Optional[str] = None
  cwe_id: Optional[str] = None
  severity: Optional[str] = None
  confidence_level: Optional[str] = None
  status: str = "DETECTED"
  source_stage: Optional[str] = None
  verified: Optional[bool] = None
  muted: Optional[bool] = None
  mute_reason: Optional[str] = None
  fingerprint: Optional[str] = None
  fix_pr_url: Optional[str] = None
  patch_status: Optional[str] = None
  finding_source: Optional[str] = "codemender"
  analysis: Optional[str] = None
  snippet: Optional[str] = None
  scan_id: Optional[str] = None
  scan_timestamp: Optional[str] = None
  session_id: Optional[str] = None
  updated_at: Optional[str] = None
  raw_data: Dict[str, Any] = dataclasses.field(default_factory=dict)

  def __post_init__(self):
    if self.finding_id is not None:
      self.finding_id = str(self.finding_id).strip()
    if self.file_path:
      self.file_path = normalize_repo_relative_path(str(self.file_path))
    if self.severity:
      self.severity = self.severity.upper()
    if self.status:
      self.status = self.status.upper()
    if not self.cwe_id and (self.vuln_id or self.vuln_type or self.title):
      self.cwe_id = extract_cwe_id(self.vuln_id, self.vuln_type, self.title)
    if not self.fingerprint and self.file_path and self.start_line is not None:
      self.fingerprint = compute_finding_fingerprint(
          self.file_path, self.vuln_type or "vulnerability", self.start_line
      )

  # --- Factory Methods ---

  @classmethod
  def from_dict(
      cls,
      data: Union[Mapping[str, Any], Finding],
      repo_dir: Optional[str] = None,
  ) -> Finding:
    """Creates a Finding instance from any dictionary or Finding object."""
    if isinstance(data, Finding):
      return data

    raw: Dict[str, Any] = dict(data.items()) if hasattr(data, "items") else dict(data)

    def _get(*keys: str) -> Any:
      for k in keys:
        if k in raw and raw[k] is not None:
          return raw[k]
      return None

    finding_id = str(_get("finding_id", "FindingID", "id") or "")
    repository = _as_str(_get("repository", "Repository"))
    raw_path = _get("file_path", "FilePath", "path") or ""
    file_path = normalize_repo_relative_path(str(raw_path), repo_dir)

    start_line = _as_int(_get("start_line", "StartLine", "line", "Line"))
    end_line = _as_int(_get("end_line", "EndLine"))

    title = _as_str(_get("title", "Title")) or ""
    vuln_type = _as_str(_get("vuln_type", "VulnType", "type"))
    vuln_id = _as_str(_get("vuln_id", "VulnID"))
    cwe_id = _as_str(_get("cwe_id", "CweID")) or extract_cwe_id(vuln_id, vuln_type, title)

    severity = _as_str(_get("severity", "Severity"))
    if severity:
      severity = severity.upper()

    confidence_level = _as_str(
        _get("confidence_level", "ConfidenceLevel", "confidence", "Confidence")
    )
    if confidence_level:
      confidence_level = confidence_level.upper()

    status = _as_str(_get("status", "Status")) or "DETECTED"
    status = status.upper()

    source_stage = _as_str(_get("source_stage", "SourceStage"))
    verified = _as_bool(_get("verified", "Verified"))
    muted = _as_bool(_get("muted", "Muted"))
    mute_reason = _as_str(
        _get("mute_reason", "MuteReason", "dismiss_reason", "DismissReason")
    )
    fingerprint = _as_str(_get("fingerprint", "Fingerprint"))

    fix_pr_url = _as_str(_get("fix_pr_url", "FixPrUrl", "fix_pr", "FixPr"))
    patch_status = _as_str(_get("patch_status", "PatchStatus"))
    finding_source = _as_str(_get("finding_source", "FindingSource")) or "codemender"

    analysis = _as_str(_get("analysis", "Analysis", "message", "Message"))
    snippet = _as_str(_get("snippet", "Snippet"))

    scan_id = _as_str(_get("scan_id", "ScanID"))
    scan_timestamp = _as_str(_get("scan_timestamp", "ScanTimestamp"))
    session_id = _as_str(_get("session_id", "SessionID"))
    updated_at = _as_str(_get("updated_at", "UpdatedAt"))

    return cls(
        finding_id=finding_id,
        repository=repository,
        file_path=file_path,
        start_line=start_line,
        end_line=end_line,
        title=title,
        vuln_type=vuln_type,
        vuln_id=vuln_id,
        cwe_id=cwe_id,
        severity=severity,
        confidence_level=confidence_level,
        status=status,
        source_stage=source_stage,
        verified=verified,
        muted=muted,
        mute_reason=mute_reason,
        fingerprint=fingerprint,
        fix_pr_url=fix_pr_url,
        patch_status=patch_status,
        finding_source=finding_source,
        analysis=analysis,
        snippet=snippet,
        scan_id=scan_id,
        scan_timestamp=scan_timestamp,
        session_id=session_id,
        updated_at=updated_at,
        raw_data=raw,
    )

  @classmethod
  def from_bq_row(
      cls, row: Mapping[str, Any], repo_dir: Optional[str] = None
  ) -> Finding:
    """Explicit factory for findings fetched from BigQuery."""
    return cls.from_dict(row, repo_dir=repo_dir)

  @classmethod
  def from_cm_json(
      cls, item: Mapping[str, Any], repo_dir: Optional[str] = None
  ) -> Finding:
    """Explicit factory for findings produced by CodeMender CLI."""
    return cls.from_dict(item, repo_dir=repo_dir)

  # --- Key & Fingerprint Properties ---

  @property
  def row_key(self) -> Tuple[str, str]:
    """Returns composite primary key (repository, finding_id)."""
    if not self.repository or not self.finding_id:
      raise ValueError("A unique finding must have repository and finding_id")
    return self.repository, self.finding_id

  def compute_fingerprint(self, repo_dir: Optional[str] = None) -> str:
    """Computes or retrieves deterministic SHA256 fingerprint."""
    if self.fingerprint:
      return self.fingerprint
    norm_path = normalize_repo_relative_path(self.file_path, repo_dir)
    fp = compute_finding_fingerprint(
        norm_path, self.vuln_type or "vulnerability", self.start_line or 0
    )
    self.fingerprint = fp
    return fp

  def is_repo_finding(self, repo_dir: str) -> bool:
    """Whether finding belongs to the target repo directory."""
    if not self.file_path:
      return False
    clean_repo = os.path.abspath(repo_dir).replace("\\", "/")
    raw = str(self.file_path).strip().replace("\\", "/")
    if os.path.isabs(raw):
      clean_path = os.path.abspath(raw).replace("\\", "/")
      return clean_path == clean_repo or clean_path.startswith(clean_repo + "/")
    return not raw.startswith("/")

  def is_closed(self) -> bool:
    """Whether finding status is closed/remediated."""
    return (self.status or "").upper() in _CLOSED_STATUSES

  def is_verified(
      self, force_verified: bool = False, skip_verify: Optional[bool] = None
  ) -> Optional[bool]:
    """Whether finding has been verified."""
    if self.verified is True:
      return True
    if self.status in _VERIFIED_STATUSES:
      return True
    if self.status in _VERIFY_PASSED_STATUSES and (force_verified or skip_verify is False):
      return True
    return self.verified

  # --- Serialization & Export Formats ---

  def to_dict(self) -> Dict[str, Any]:
    """Serializes finding into a standard snake_case dictionary."""
    return {
        "finding_id": self.finding_id,
        "repository": self.repository,
        "file_path": self.file_path,
        "start_line": self.start_line,
        "end_line": self.end_line,
        "title": self.title,
        "vuln_type": self.vuln_type,
        "vuln_id": self.vuln_id,
        "cwe_id": self.cwe_id,
        "severity": self.severity,
        "confidence_level": self.confidence_level,
        "status": self.status,
        "source_stage": self.source_stage,
        "verified": self.verified,
        "muted": self.muted,
        "mute_reason": self.mute_reason,
        "fingerprint": self.fingerprint,
        "fix_pr_url": self.fix_pr_url,
        "patch_status": self.patch_status,
        "finding_source": self.finding_source,
        "analysis": self.analysis,
        "snippet": self.snippet,
        "scan_id": self.scan_id,
        "scan_timestamp": self.scan_timestamp,
        "session_id": self.session_id,
        "updated_at": self.updated_at,
    }

  def to_cm_dict(self) -> Dict[str, Any]:
    """Serializes finding into CodeMender PascalCase dict with snake_case aliases."""
    d: Dict[str, Any] = {
        "FindingID": self.finding_id,
        "FilePath": self.file_path,
        "StartLine": self.start_line,
        "EndLine": self.end_line,
        "Title": self.title,
        "VulnType": self.vuln_type,
        "VulnID": self.vuln_id,
        "Severity": self.severity,
        "Confidence": self.confidence_level,
        "ConfidenceLevel": self.confidence_level,
        "Status": self.status,
        "SourceStage": self.source_stage,
        "Fingerprint": self.fingerprint,
        "Analysis": self.analysis,
        "Snippet": self.snippet,
        "DismissReason": self.mute_reason,
        "SessionID": self.session_id,
        "UpdatedAt": self.updated_at,
    }
    # Add snake_case aliases for compatibility
    for snake, pascal in _FINDING_KEY_ALIASES.items():
      if pascal in d and snake not in d:
        d[snake] = d[pascal]
    return d

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

  def to_bq_row(
      self,
      scan_id: Optional[str] = None,
      scan_timestamp: Optional[str] = None,
      repository: Optional[str] = None,
      prs: Optional[Mapping[str, str]] = None,
      wiz_ids: Optional[Iterable[str]] = None,
      skip_verify: Optional[bool] = None,
      with_snippets: bool = True,
  ) -> Dict[str, Any]:
    """Transforms finding into a BigQuery `findings` schema table row."""
    wiz_set = {str(i) for i in (wiz_ids or [])}
    force_verified = self.finding_id in wiz_set
    pr_map = prs or {}

    row: Dict[str, Any] = {
        "finding_id": self.finding_id,
        "scan_id": scan_id or self.scan_id or "unknown",
        "scan_timestamp": scan_timestamp or self.scan_timestamp or _utc_now_iso(),
        "repository": repository or self.repository or "",
        "title": self.title,
        "vuln_type": self.vuln_type,
        "cwe_id": self.cwe_id or extract_cwe_id(self.vuln_id, self.vuln_type, self.title),
        "severity": self.severity.upper() if self.severity else None,
        "confidence_level": self.confidence_level.upper() if self.confidence_level else None,
        "file_path": self.file_path,
        "start_line": self.start_line,
        "end_line": self.end_line,
        "status": self.status.upper() if self.status else "DETECTED",
        "source_stage": self.source_stage,
        "verified": self.is_verified(force_verified=force_verified, skip_verify=skip_verify),
        "muted": self.muted,
        "mute_reason": self.mute_reason,
        "fingerprint": self.fingerprint or self.compute_fingerprint(),
        "fix_pr_url": pr_map.get(self.finding_id) or self.fix_pr_url,
        "patch_status": self.patch_status,
        "finding_source": "wiz" if force_verified else (self.finding_source or "codemender"),
    }
    if with_snippets:
      row["analysis"] = self.analysis
      row["snippet"] = self.snippet
    return row

  def to_telemetry_dict(
      self, repo_dir: Optional[str] = None, source_finding_id: Optional[str] = None
  ) -> Dict[str, Any]:
    """Maps finding to normalized telemetry fields."""
    d = self.to_dict()
    if source_finding_id:
      d["finding_id"] = source_finding_id
    if repo_dir:
      d["file_path"] = normalize_repo_relative_path(self.file_path, repo_dir)
      d["fingerprint"] = self.compute_fingerprint(repo_dir)
    return d

  # --- Dictionary-like Protocol (Backwards Compatibility) ---

  def __getitem__(self, key: str) -> Any:
    norm_key = _PASCAL_TO_SNAKE.get(key, key)
    if hasattr(self, norm_key):
      val = getattr(self, norm_key)
      if val is not None:
        return val
    if key in self.raw_data:
      return self.raw_data[key]
    if hasattr(self, norm_key):
      return getattr(self, norm_key)
    raise KeyError(key)

  def __setitem__(self, key: str, value: Any) -> None:
    norm_key = _PASCAL_TO_SNAKE.get(key, key)
    if hasattr(self, norm_key):
      setattr(self, norm_key, value)
    self.raw_data[key] = value

  def __contains__(self, key: str) -> bool:
    norm_key = _PASCAL_TO_SNAKE.get(key, key)
    if hasattr(self, norm_key) and getattr(self, norm_key) is not None:
      return True
    return key in self.raw_data and self.raw_data[key] is not None

  def get(self, key: str, default: Any = None) -> Any:
    norm_key = _PASCAL_TO_SNAKE.get(key, key)
    if hasattr(self, norm_key):
      val = getattr(self, norm_key)
      return val if val is not None else default
    return self.raw_data.get(key, default)

  def keys(self):
    return self.to_dict().keys()

  def values(self):
    return self.to_dict().values()

  def items(self):
    return self.to_dict().items()

  def __len__(self) -> int:
    return len(self.to_dict())

  def __iter__(self):
    return iter(self.to_dict())

  # --- Matching & Deduplication Algorithms ---

  @staticmethod
  def match_findings(
      source_findings: Sequence[Union[Mapping[str, Any], Finding]],
      cm_findings: Sequence[Union[Mapping[str, Any], Finding]],
      repo_dir: str,
      required_cm_ids: Optional[Sequence[str]] = None,
  ) -> Dict[str, str]:
    """Maps cm IDs to BigQuery finding IDs using finding attributes."""
    required = set(required_cm_ids) if required_cm_ids is not None else None
    sources = [Finding.from_dict(s, repo_dir) for s in source_findings]
    unmatched = list(sources)
    source_ids_by_cm_id: Dict[str, str] = {}

    cms = [Finding.from_dict(c, repo_dir) for c in cm_findings]
    for cm in cms:
      cm_id = cm.finding_id
      if not cm_id or (required is not None and cm_id not in required):
        continue

      candidates: List[Tuple[int, Finding]] = []
      for source in unmatched:
        if source.file_path != cm.file_path:
          continue
        if (
            cm.start_line is not None
            and source.start_line is not None
            and cm.start_line != source.start_line
        ):
          continue
        score = 0
        if cm.title and cm.title == source.title:
          score += 4
        if cm.vuln_type and cm.vuln_type == source.vuln_type:
          score += 2
        if source.snippet and source.snippet == cm.snippet:
          score += 1
        candidates.append((score, source))

      if not candidates:
        if required is not None and cm_id in required:
          raise ValueError(f"Could not match imported finding {cm_id} to BigQuery source")
        continue

      best_score = max(score for score, _ in candidates)
      best = [source for score, source in candidates if score == best_score]
      if len(best) != 1:
        if required is not None and cm_id in required:
          raise ValueError(f"Imported finding {cm_id} ambiguously matches BigQuery rows")
        continue

      source = best[0]
      source_ids_by_cm_id[cm_id] = source.finding_id
      unmatched.remove(source)

    if required is not None:
      missing = required.difference(source_ids_by_cm_id)
      if missing:
        raise ValueError(
            "CodeMender report omitted imported finding IDs: "
            + ", ".join(sorted(missing))
        )
    return source_ids_by_cm_id

  @staticmethod
  def deduplicate(
      findings: Iterable[Union[Mapping[str, Any], Finding]],
  ) -> List[Finding]:
    """Deduplicates findings by (repository, finding_id), keeping the last."""
    keyed: Dict[Tuple[str, str], Finding] = {}
    for item in findings:
      finding = Finding.from_dict(item)
      keyed[finding.row_key] = finding
    return list(keyed.values())
