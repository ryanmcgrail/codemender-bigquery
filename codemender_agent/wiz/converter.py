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

"""Converts guarded Wiz SAST findings into ``cm report import`` records.

Only the documented simple-JSON import dialect is produced; Wiz SARIF is never
imported (every SAST rule in it is named "SAST Finding" and it carries no
CWEs). The conversion:

* keeps findings at or above the per-repository severity threshold;
* drops findings whose file is not inside the checked-out repository;
* groups findings on the same file, with overlapping lines and the same CWE,
  into one record (several Wiz rules often flag the same line);
* collapses byte-identical copies of the same code in different directories
  (vendored libraries copied into several folders) into one record;
* labels each record "<Weakness> (CWE-nnn)"; and
* reads the code snippet from disk, because Wiz redacts parts of it.
"""

import dataclasses
import hashlib
import logging
import os
import posixpath
from typing import Any, Dict, List, Optional, Sequence, Tuple

from codemender_agent.wiz.settings import normalize_severity
from codemender_agent.wiz.settings import severity_rank
from codemender_agent.wiz.taxonomy import families_for
from codemender_agent.wiz.taxonomy import normalize_cwe
from codemender_agent.wiz.taxonomy import weakness_label

logger = logging.getLogger("codemender-orchestrator")

SNIPPET_CONTEXT_LINES = 2
SNIPPET_MAX_LINES = 40
SNIPPET_MAX_CHARS = 4000
DESCRIPTION_MAX_CHARS = 1200


@dataclasses.dataclass
class WizCandidate:
  """One import-ready finding, possibly merged from several Wiz results."""

  file_path: str
  start_line: int
  end_line: int
  severity: str
  cwe: Optional[str]
  label: str
  rule_ids: List[str] = dataclasses.field(default_factory=list)
  rule_names: List[str] = dataclasses.field(default_factory=list)
  wiz_finding_ids: List[str] = dataclasses.field(default_factory=list)
  description: str = ""
  duplicate_locations: List[str] = dataclasses.field(default_factory=list)

  @property
  def families(self):
    return families_for([self.cwe] if self.cwe else [], self.label)

  def summary(self) -> Dict[str, Any]:
    """A persistence-safe summary (no snippet, no scanner identity)."""
    return {
        "file_path": self.file_path,
        "start_line": self.start_line,
        "end_line": self.end_line,
        "severity": self.severity,
        "cwe": self.cwe,
        "label": self.label,
        "rule_ids": list(self.rule_ids),
        "duplicate_locations": list(self.duplicate_locations),
    }


@dataclasses.dataclass
class ConversionResult:
  """Candidates plus counts explaining everything that was left out."""

  candidates: List[WizCandidate]
  reported_count: int = 0
  # Raw findings at or above the threshold inside the repository, before
  # grouping and vendored-copy collapsing.
  eligible_count: int = 0
  below_threshold_count: int = 0
  invalid_count: int = 0
  outside_repo_count: int = 0
  grouped_count: int = 0
  vendored_copy_count: int = 0


def _to_int(value: Any, default: int) -> int:
  try:
    return int(value)
  except (TypeError, ValueError):
    return default


def normalize_wiz_path(raw: Any) -> Optional[str]:
  """Returns a clean repository-relative POSIX path, or None if unsafe."""
  if not isinstance(raw, str) or not raw.strip():
    return None
  path = raw.strip().replace("\\", "/")
  while path.startswith("./"):
    path = path[2:]
  if path.startswith("/") or (len(path) > 1 and path[1] == ":"):
    return None
  norm = posixpath.normpath(path)
  if norm in (".", "") or norm == ".." or norm.startswith("../"):
    return None
  return norm


def _inside_repo(repo_dir: str, rel_path: str) -> bool:
  root = os.path.realpath(repo_dir)
  target = os.path.realpath(os.path.join(root, rel_path))
  return target.startswith(root + os.sep) and os.path.isfile(target)


def _read_lines(repo_dir: str, rel_path: str) -> List[str]:
  try:
    with open(
        os.path.join(repo_dir, rel_path), "r", encoding="utf-8", errors="replace"
    ) as f:
      return f.read().splitlines()
  except OSError:
    return []


def read_snippet(repo_dir: str, rel_path: str, start: int, end: int) -> str:
  """Reads the flagged lines plus a little context straight from disk."""
  lines = _read_lines(repo_dir, rel_path)
  if not lines:
    return ""
  lo = max(1, start - SNIPPET_CONTEXT_LINES)
  hi = min(len(lines), end + SNIPPET_CONTEXT_LINES, lo + SNIPPET_MAX_LINES - 1)
  snippet = "\n".join(lines[lo - 1 : hi])
  return snippet[:SNIPPET_MAX_CHARS]


def _content_digest(repo_dir: str, rel_path: str, start: int, end: int) -> str:
  lines = _read_lines(repo_dir, rel_path)[max(0, start - 1) : max(start, end)]
  normalized = "\n".join(" ".join(line.split()) for line in lines)
  return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _first_paragraph(text: Any) -> str:
  if not isinstance(text, str):
    return ""
  para = text.strip().split("\n\n", 1)[0]
  para = " ".join(para.split())
  return para[:DESCRIPTION_MAX_CHARS]


def _primary_cwe(finding: Dict[str, Any]) -> Optional[str]:
  weaknesses = finding.get("weaknesses")
  if isinstance(weaknesses, list):
    for weakness in weaknesses:
      if isinstance(weakness, dict):
        cwe = normalize_cwe(weakness.get("id"))
        if cwe:
          return cwe
  return None


def _parse(finding: Dict[str, Any]) -> Optional[WizCandidate]:
  path = normalize_wiz_path(finding.get("filePath"))
  severity = normalize_severity(finding.get("severity"))
  if not path or not severity:
    return None
  start = max(1, _to_int(finding.get("startLine"), 1))
  end = max(start, _to_int(finding.get("endLine"), start))
  rule = finding.get("rule") if isinstance(finding.get("rule"), dict) else {}
  rule_id = str(rule.get("id") or "").strip()
  name = " ".join(str(finding.get("name") or "").split())
  cwe = _primary_cwe(finding)
  finding_ref = str(finding.get("id") or "").strip()
  return WizCandidate(
      file_path=path,
      start_line=start,
      end_line=end,
      severity=severity,
      cwe=cwe,
      label=weakness_label(cwe, name),
      rule_ids=[rule_id] if rule_id else [],
      rule_names=[name] if name else [],
      wiz_finding_ids=[finding_ref] if finding_ref else [],
      description=_first_paragraph(finding.get("description")),
  )


def _merge_into(dst: WizCandidate, src: WizCandidate) -> None:
  dst.start_line = min(dst.start_line, src.start_line)
  dst.end_line = max(dst.end_line, src.end_line)
  if severity_rank(src.severity) > severity_rank(dst.severity):
    dst.severity = src.severity
  for attr in ("rule_ids", "rule_names", "wiz_finding_ids"):
    existing = getattr(dst, attr)
    existing.extend(v for v in getattr(src, attr) if v not in existing)
  if not dst.description:
    dst.description = src.description


def group_overlapping(
    candidates: Sequence[WizCandidate],
) -> Tuple[List[WizCandidate], int]:
  """Merges same-file, same-CWE candidates whose line ranges overlap."""
  ordered = sorted(
      candidates, key=lambda c: (c.file_path, c.cwe or c.label, c.start_line)
  )
  grouped: List[WizCandidate] = []
  merged = 0
  for cand in ordered:
    prev = grouped[-1] if grouped else None
    if (
        prev is not None
        and prev.file_path == cand.file_path
        and (prev.cwe or prev.label) == (cand.cwe or cand.label)
        and cand.start_line <= prev.end_line
    ):
      _merge_into(prev, cand)
      merged += 1
    else:
      grouped.append(dataclasses.replace(
          cand,
          rule_ids=list(cand.rule_ids),
          rule_names=list(cand.rule_names),
          wiz_finding_ids=list(cand.wiz_finding_ids),
          duplicate_locations=list(cand.duplicate_locations),
      ))
  return grouped, merged


def collapse_vendored_copies(
    candidates: Sequence[WizCandidate], repo_dir: str
) -> Tuple[List[WizCandidate], int]:
  """Keeps one record for identical code flagged in several directories."""
  kept: List[WizCandidate] = []
  by_key: Dict[Tuple[str, str, str], WizCandidate] = {}
  collapsed = 0
  # Shallowest path first, so the kept copy is the least-nested one.
  ordered = sorted(
      candidates, key=lambda c: (c.file_path.count("/"), c.file_path, c.start_line)
  )
  for cand in ordered:
    key = (
        posixpath.basename(cand.file_path),
        cand.cwe or cand.label,
        _content_digest(repo_dir, cand.file_path, cand.start_line, cand.end_line),
    )
    original = by_key.get(key)
    if original is not None and original.file_path != cand.file_path:
      original.duplicate_locations.append(f"{cand.file_path}:{cand.start_line}")
      if severity_rank(cand.severity) > severity_rank(original.severity):
        original.severity = cand.severity
      collapsed += 1
      continue
    by_key.setdefault(key, cand)
    kept.append(cand)
  kept.sort(key=lambda c: (c.file_path, c.start_line))
  return kept, collapsed


def convert_findings(
    sast_findings: Sequence[Dict[str, Any]],
    repo_dir: str,
    min_severity: str,
) -> ConversionResult:
  """Parses, filters, groups and collapses guarded Wiz SAST findings."""
  result = ConversionResult(candidates=[], reported_count=len(sast_findings))
  threshold = severity_rank(min_severity)
  parsed: List[WizCandidate] = []
  for raw in sast_findings:
    cand = _parse(raw) if isinstance(raw, dict) else None
    if cand is None:
      result.invalid_count += 1
      continue
    if severity_rank(cand.severity) < threshold:
      result.below_threshold_count += 1
      continue
    if not _inside_repo(repo_dir, cand.file_path):
      result.outside_repo_count += 1
      continue
    parsed.append(cand)

  result.eligible_count = len(parsed)
  grouped, result.grouped_count = group_overlapping(parsed)
  result.candidates, result.vendored_copy_count = collapse_vendored_copies(
      grouped, repo_dir
  )
  return result


# Opening sentence of every imported finding's description. It lets the
# idempotency check recognise an earlier import even if ``cm`` rewrites the
# stored vulnerability type, and lets the fix workers recognise an imported
# finding on their own (see :func:`carries_import_marker`).
IMPORT_MARKER = (
    "Reported by a Wiz SAST scan and imported for independent verification."
)
_NORM_IMPORT_MARKER = " ".join(IMPORT_MARKER.split()).upper()


def carries_import_marker(finding: Any) -> bool:
  """Whether a ``cm report`` finding still carries the bridge's import marker.

  The marker is written by this module, so the check does not depend on how
  any ``cm`` release stores or normalizes other fields. It holds until
  ``cm verify`` replaces the description, after which the finding's status
  records CodeMender's own verdict.
  """
  if not isinstance(finding, dict):
    return False
  for key in ("Analysis", "analysis", "Description", "description"):
    text = finding.get(key)
    if isinstance(text, str) and _NORM_IMPORT_MARKER in " ".join(
        text.split()
    ).upper():
      return True
  return False


def build_import_record(cand: WizCandidate, repo_dir: str) -> Dict[str, Any]:
  """Renders one candidate in the ``cm report import`` simple-JSON dialect."""
  rules = ", ".join(
      f"{rid} ({name})" if name and name != rid else rid
      for rid, name in zip(
          cand.rule_ids, cand.rule_names + [""] * len(cand.rule_ids)
      )
  ) or "unspecified"
  parts = [f"{IMPORT_MARKER} Wiz rule(s): {rules}."]
  if cand.description:
    parts.append(cand.description)
  if cand.duplicate_locations:
    parts.append(
        "The same code is also flagged at: "
        + ", ".join(cand.duplicate_locations[:10])
        + "."
    )
  return {
      "file_path": cand.file_path,
      "line": cand.start_line,
      "end_line": cand.end_line,
      "title": cand.label,
      "message": " ".join(parts),
      "severity": cand.severity,
      "vuln_type": cand.label,
      "snippet": read_snippet(
          repo_dir, cand.file_path, cand.start_line, cand.end_line
      ),
  }
