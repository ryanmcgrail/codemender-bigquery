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

"""Empty-output guard for Wiz CLI JSON results.

A Wiz directory scan can "succeed" while having silently produced no SAST
results: the legacy ``dir scan`` mode skips SAST entirely, and the default
``--by-policy-hits=BLOCK`` filter hides every finding under audit-only
policies. A bare ``len(findings) > 0`` check therefore never fires. The guard
instead requires positive evidence that SAST actually ran:

1. the document parses and has the expected shape;
2. ``status.state`` is ``SUCCESS``;
3. a SAST policy was evaluated; and
4. if a SAST policy matched, the SAST result list is not empty.

Both inputs (a scan the bridge ran itself, and bring-your-own JSON from a
customer's CI) must pass the same guard.
"""

import dataclasses
import json
from typing import Any, Dict, List, Optional


class WizGuardError(ValueError):
  """Raised when a Wiz result cannot be trusted as a complete SAST scan."""


_SAST_POLICY_PARAMS_TYPENAME = "cicdscanpolicyparamssast"


def _is_sast_policy(policy: Any) -> bool:
  if not isinstance(policy, dict):
    return False
  if str(policy.get("type") or "").upper() == "SAST":
    return True
  params = policy.get("params")
  return (
      isinstance(params, dict)
      and str(params.get("__typename") or "").lower()
      == _SAST_POLICY_PARAMS_TYPENAME
  )


@dataclasses.dataclass(frozen=True)
class GuardedResult:
  """The parts of a Wiz result the bridge is allowed to use."""

  sast_findings: List[Dict[str, Any]]
  sast_policy_names: List[str]
  verdict: Optional[str]


def load_wiz_json(path: str) -> Dict[str, Any]:
  """Reads a Wiz JSON file, raising WizGuardError on unreadable content."""
  try:
    with open(path, "r", encoding="utf-8") as f:
      data = json.load(f)
  except FileNotFoundError as e:
    raise WizGuardError("Wiz result file does not exist") from e
  except (OSError, ValueError) as e:
    raise WizGuardError(
        f"Wiz result file is not valid JSON ({type(e).__name__})"
    ) from e
  if not isinstance(data, dict):
    raise WizGuardError("Wiz result is not a JSON object")
  return data


def guard_wiz_result(doc: Any) -> GuardedResult:
  """Validates a parsed Wiz CLI JSON document.

  Returns:
    The SAST findings and a little provenance, stripped of everything else
    (notably ``createdBy``, which identifies the scanning identity).

  Raises:
    WizGuardError: If the document fails any guard condition. The message is
      safe to log: it never includes document content.
  """
  if not isinstance(doc, dict):
    raise WizGuardError("Wiz result is not a JSON object")

  status = doc.get("status")
  state = status.get("state") if isinstance(status, dict) else None
  if str(state or "").upper() != "SUCCESS":
    raise WizGuardError(f"Wiz scan state is {state!r}, expected 'SUCCESS'")

  policies = doc.get("policies")
  if not isinstance(policies, list):
    policies = []
  sast_policies = [p for p in policies if _is_sast_policy(p)]
  if not sast_policies:
    raise WizGuardError(
        "no SAST policy was evaluated; the scan did not run SAST (was it"
        " produced by the legacy 'dir scan' mode or with SAST disabled?)"
    )

  result = doc.get("result")
  if not isinstance(result, dict):
    raise WizGuardError("Wiz result has no 'result' object")

  sast = result.get("sast")
  if sast is None:
    sast = []
  if not isinstance(sast, list):
    raise WizGuardError("Wiz 'result.sast' is not a list")

  failed_matches = result.get("failedPolicyMatches")
  if not isinstance(failed_matches, list):
    failed_matches = []
  sast_policy_matched = any(
      isinstance(m, dict) and _is_sast_policy(m.get("policy"))
      for m in failed_matches
  )
  if sast_policy_matched and not sast:
    raise WizGuardError(
        "a SAST policy matched but no SAST findings were returned; the"
        " findings were filtered out (missing --by-policy-hits=DISABLED?) or"
        " SAST was skipped"
    )

  findings = [f for f in sast if isinstance(f, dict)]
  return GuardedResult(
      sast_findings=findings,
      sast_policy_names=[str(p.get("name") or "") for p in sast_policies],
      verdict=(status.get("verdict") if isinstance(status, dict) else None),
  )
