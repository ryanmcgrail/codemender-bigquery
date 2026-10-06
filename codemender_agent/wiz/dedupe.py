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

"""De-duplicates Wiz candidates against findings already in CodeMender state.

Two different questions are answered here, in this order:

1. **Already imported?** ``cm report import`` never de-duplicates: importing
   the same file twice creates two rows. A candidate is already imported when
   a finding exists on the same file and start line that bears a trace of
   the bridge (its stored type is the label in any case or the label's bare
   ``CWE-N``, its title is the label, or its description carries the import
   marker) and does not carry only other CWEs. Accepting the normalized forms
   keeps this stable when ``cm`` rewrites the stored type (for example to
   ``CWE-89``). This makes the bridge idempotent when it runs more than once
   against the same state.
2. **Duplicate of a CodeMender finding?** CodeMender and Wiz describe the same
   weakness differently (Wiz reports "CWE-89" on one line; CodeMender reports
   "SQL Injection" over a whole method). A candidate is a duplicate when a
   finding exists on the same file, its line range (widened by a small
   window) overlaps the finding's, and the two share a CWE or a weakness
   family.
"""

import dataclasses
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Sequence, Set

from codemender_agent.vcs.git import normalize_repo_relative_path
from codemender_agent.wiz.converter import IMPORT_MARKER
from codemender_agent.wiz.converter import WizCandidate
from codemender_agent.wiz.taxonomy import cwes_in_text
from codemender_agent.wiz.taxonomy import families_for
from codemender_agent.wiz.taxonomy import normalize_cwe

# Statuses of findings that no longer represent an open weakness. A closed
# CodeMender finding does not suppress a Wiz finding, but a closed import of
# the same Wiz finding still counts as "already imported".
_CLOSED_STATUSES = frozenset({"FALSE_POSITIVE", "DISMISSED"})


@dataclasses.dataclass(frozen=True)
class FindingRef:
  """The parts of a CodeMender finding the matcher needs."""

  finding_id: str
  file_path: str
  start_line: int
  end_line: int
  vuln_type: str
  status: str
  cwes: FrozenSet[str]
  families: FrozenSet[str]
  title: str = ""
  analysis: str = ""


def _to_int(value: Any, default: int) -> int:
  try:
    return int(value)
  except (TypeError, ValueError):
    return default


def finding_ref(finding: Dict[str, Any], repo_dir: str) -> Optional[FindingRef]:
  """Builds a FindingRef from a parsed ``cm report`` finding, or None."""
  if not isinstance(finding, dict):
    return None
  path = normalize_repo_relative_path(
      finding.get("FilePath") or finding.get("file_path") or "", repo_dir=repo_dir
  )
  if not path:
    return None
  start = _to_int(finding.get("StartLine") or finding.get("start_line"), 0)
  end = max(start, _to_int(finding.get("EndLine") or finding.get("end_line"), start))
  vuln_type = str(finding.get("VulnType") or finding.get("vuln_type") or "")
  title = str(finding.get("Title") or finding.get("title") or "")
  vuln_id = str(finding.get("VulnID") or finding.get("vuln_id") or "")
  cwes: Set[str] = set(cwes_in_text(vuln_id, vuln_type, title))
  for key in ("CWE", "cwe", "cwe_id", "CweID"):
    cwe = normalize_cwe(finding.get(key))
    if cwe:
      cwes.add(cwe)
  return FindingRef(
      finding_id=str(finding.get("FindingID") or finding.get("finding_id") or ""),
      file_path=path,
      start_line=start,
      end_line=end,
      vuln_type=vuln_type,
      status=str(finding.get("Status") or finding.get("status") or "").upper(),
      cwes=frozenset(cwes),
      families=families_for(cwes, vuln_type, title),
      title=title,
      analysis=str(
          finding.get("Analysis")
          or finding.get("analysis")
          or finding.get("Description")
          or finding.get("description")
          or ""
      ),
  )


@dataclasses.dataclass
class DedupeResult:
  """Candidates split by why they are, or are not, imported."""

  new: List[WizCandidate] = dataclasses.field(default_factory=list)
  already_imported: List[WizCandidate] = dataclasses.field(default_factory=list)
  duplicates: List[WizCandidate] = dataclasses.field(default_factory=list)
  # Candidate label/location -> the CodeMender finding it duplicated.
  duplicate_of: Dict[str, str] = dataclasses.field(default_factory=dict)
  # CodeMender finding IDs that correspond to already-imported candidates.
  already_imported_ids: List[str] = dataclasses.field(default_factory=list)


def _norm_text(value: str) -> str:
  """Case- and whitespace-insensitive form used for label comparisons."""
  return " ".join((value or "").split()).upper()


_NORM_IMPORT_MARKER = _norm_text(IMPORT_MARKER)


def _looks_imported(cand: WizCandidate, ref: FindingRef) -> bool:
  """Whether ``ref`` carries any trace of having been written by the bridge.

  Every form ``cm`` is known to store the bridge's label in counts: the label
  itself in any case, and the bare ``CWE-N`` that newer releases normalize a
  CWE-bearing type to. The title (written as the label) and the marker the
  bridge puts at the start of the imported description are also accepted, in
  case verification rewrites the stored type.
  """
  label = _norm_text(cand.label)
  shapes = {label}
  if cand.cwe:
    shapes.add(_norm_text(cand.cwe))
  return (
      _norm_text(ref.vuln_type) in shapes
      or _norm_text(ref.title) == label
      or _NORM_IMPORT_MARKER in _norm_text(ref.analysis)
  )


def is_same_import(cand: WizCandidate, ref: FindingRef) -> bool:
  """Whether ``ref`` is an earlier import of ``cand``.

  ``cm`` may rewrite the stored vulnerability type (newer releases normalize
  it to ``CWE-N`` when a CWE is present, otherwise to upper case, both on
  import and when verification updates a finding), so the label the bridge
  wrote cannot be relied on to round-trip verbatim. A finding is an earlier
  import when it is on the same file and start line, looks like it was
  written by the bridge (see ``_looks_imported``), and does not carry only
  other CWEs. Requiring a bridge trace keeps a CodeMender finding that merely
  starts on the same line classified as a duplicate rather than an import.
  """
  if ref.file_path != cand.file_path or ref.start_line != cand.start_line:
    return False
  if not _looks_imported(cand, ref):
    return False
  return not cand.cwe or not ref.cwes or cand.cwe in ref.cwes


def _is_codemender_duplicate(
    cand: WizCandidate, ref: FindingRef, line_window: int
) -> bool:
  if ref.file_path != cand.file_path or ref.status in _CLOSED_STATUSES:
    return False
  lo = cand.start_line - line_window
  hi = cand.end_line + line_window
  # A finding without a usable line range still matches anywhere in the file.
  if ref.start_line > 0 and (ref.end_line < lo or ref.start_line > hi):
    return False
  cand_cwes = {cand.cwe} if cand.cwe else set()
  return bool(cand_cwes & ref.cwes) or bool(cand.families & ref.families)


def _candidate_key(cand: WizCandidate) -> str:
  return f"{cand.file_path}:{cand.start_line}:{cand.label}"


def dedupe_candidates(
    candidates: Sequence[WizCandidate],
    existing_findings: Iterable[Dict[str, Any]],
    repo_dir: str,
    line_window: int,
) -> DedupeResult:
  """Splits candidates into new, already-imported and CodeMender duplicates."""
  refs = [r for r in (finding_ref(f, repo_dir) for f in existing_findings) if r]
  result = DedupeResult()
  for cand in candidates:
    # ``cm report import`` never de-duplicates, so a state can hold several
    # rows for the same earlier import. Every one of them must be routed to
    # mandatory verification, not only the first.
    imported = [r for r in refs if is_same_import(cand, r)]
    if imported:
      result.already_imported.append(cand)
      for ref in imported:
        if ref.finding_id and ref.finding_id not in result.already_imported_ids:
          result.already_imported_ids.append(ref.finding_id)
      continue
    dup = next(
        (r for r in refs if _is_codemender_duplicate(cand, r, line_window)), None
    )
    if dup is not None:
      result.duplicates.append(cand)
      result.duplicate_of[_candidate_key(cand)] = dup.finding_id
      continue
    result.new.append(cand)
  return result
