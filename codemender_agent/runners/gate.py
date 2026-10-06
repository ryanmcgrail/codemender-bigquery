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

"""Stage 1 Immediate Security Gate & Preflight Diff Target Runner."""

import logging
import os
import subprocess
from typing import Optional, Tuple

from codemender_agent.config import OrchestratorConfig
from codemender_agent.vcs.github import (
    post_commit_status,
    resolve_sticky_comment_if_present,
)

logger = logging.getLogger("codemender-orchestrator")

SOURCE_CODE_EXTENSIONS = {
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".rb",
    ".php",
    ".sh",
    ".bash",
    ".scala",
}


def _write_preflight_output(
    github_output: Optional[str], skip_scan: bool, resolved_target: str
) -> None:
  """Appends preflight skip_scan and resolved_target keys to GITHUB_OUTPUT."""
  if github_output:
    with open(github_output, "a", encoding="utf-8") as f:
      f.write(f"skip_scan={str(skip_scan).lower()}\n")
      f.write(f"resolved_target={resolved_target}\n")


def get_pr_modified_code_files(
    workspace_dir: str,
    base_ref: str,
    require_exists: bool = True,
) -> Tuple[list[str], list[str]]:
  """Returns (all_changed_files, source_code_files) between origin/<base_ref> and HEAD.

  Automatically fetches origin/<base_ref> if missing in a shallow clone.
  """
  if not base_ref:
    return [], []
  diff_cmd = [
      "git",
      "diff",
      "--name-only",
      "--diff-filter=ACMRT",
      f"origin/{base_ref}...HEAD",
  ]
  proc = subprocess.run(
      diff_cmd,
      cwd=workspace_dir,
      capture_output=True,
      text=True,
      check=False,
  )
  if proc.returncode != 0:
    subprocess.run(
        [
            "git",
            "fetch",
            "--no-tags",
            "origin",
            f"+refs/heads/{base_ref}:refs/remotes/origin/{base_ref}",
        ],
        cwd=workspace_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    proc = subprocess.run(
        diff_cmd,
        cwd=workspace_dir,
        capture_output=True,
        text=True,
        check=False,
    )
  changed_files = [
      line.strip() for line in proc.stdout.splitlines() if line.strip()
  ]
  code_files = [
      path
      for path in changed_files
      if not path.startswith(".github/")
      and os.path.splitext(path)[1].lower() in SOURCE_CODE_EXTENSIONS
      and (not require_exists or os.path.exists(os.path.join(workspace_dir, path)))
  ]
  return changed_files, code_files


def resolve_pr_diff_targets(
    workspace_dir: str,
    is_pr: bool,
    diff_scoped: bool,
    base_ref: str,
    default_scan_target: str = ".",
    github_output: Optional[str] = None,
) -> Tuple[bool, str]:
  """Resolves diff-scoped PR scan targets and fast-skips non-code PRs (<15s).

  Returns:
    Tuple of (skip_scan, resolved_target).
  """
  if not (is_pr and diff_scoped and base_ref):
    _write_preflight_output(github_output, False, default_scan_target)
    return False, default_scan_target

  changed_files, code_files = get_pr_modified_code_files(
      workspace_dir, base_ref, require_exists=True
  )
  if not code_files:
    logger.info(
        "No modified source code files in PR diff (total changed files: %d)."
        " Skipping cm find.",
        len(changed_files),
    )
    _write_preflight_output(github_output, True, "")
    return True, ""

  if len(code_files) <= 15:
    targets = code_files
  else:
    targets = sorted({os.path.dirname(p) or "." for p in code_files})

  resolved = ",".join(targets)
  logger.info(
      "Diff-scoped PR scan targets (%d modified code files): %s",
      len(code_files),
      resolved,
  )
  _write_preflight_output(github_output, False, resolved)
  return False, resolved


def run_security_gate_pipeline(
    cfg: Optional[OrchestratorConfig] = None,
) -> int:
  """Enforces the immediate Stage 1 Security Gate and publishes Commit Status.

  Returns:
    0 when the gate passes, 1 when blocked or when Stage 1 fails/cancels.
  """
  cfg = cfg or OrchestratorConfig.from_env()
  scan_result = os.environ.get("SCAN_RESULT", "success").strip().lower()
  findings_count = int(os.environ.get("FINDINGS_COUNT", "0") or "0")
  blocking_count = int(os.environ.get("BLOCKING_COUNT", "0") or "0")
  advisory_count = int(os.environ.get("ADVISORY_COUNT", "0") or "0")
  min_sev = cfg.min_blocking_severity
  fail_enabled = cfg.fail_on_findings
  pr_number = cfg.pr_number or 0
  repo_full = (
      os.environ.get("REPO_FULL_NAME")
      or os.environ.get("REPO_FULL")
      or os.environ.get("GITHUB_REPOSITORY")
      or ""
  ).strip()
  owner, repo = (repo_full.split("/", 1) + [""])[:2] if "/" in repo_full else ("", "")
  target_sha = (cfg.target_sha or "").strip()
  run_url = os.environ.get("RUN_URL", "").strip()
  token = (cfg.github_token or "").strip()
  step_summary = (cfg.github_step_summary or "").strip()

  if scan_result != "success":
    status_state = "error"
    status_desc = (
        f"CodeMender scan stage failed (result: {scan_result})."
        " Failing closed."
    )
    should_fail = True
  elif blocking_count > 0 and fail_enabled:
    status_state = "failure"
    status_desc = (
        f"BLOCKED: {blocking_count} vulnerability(ies) >= {min_sev} found by"
        " cm find (cm verify & cm fix running in background)."
    )
    should_fail = True
  elif blocking_count > 0 and not fail_enabled:
    status_state = "success"
    status_desc = (
        f"PASSED (Non-Blocking): {blocking_count} finding(s) >= {min_sev}"
        " detected (merge blocking disabled; cm verify & cm fix running)."
    )
    should_fail = False
  else:
    status_state = "success"
    adv_label = "Low/Info" if min_sev == "MEDIUM" else f"< {min_sev}"
    status_desc = (
        f"PASSED: 0 vulnerabilities >= {min_sev} in PR diff"
        f" ({advisory_count} {adv_label} advisory finding(s))."
    )
    should_fail = False

  if token and owner and repo and target_sha:
    post_commit_status(
        token=token,
        owner=owner,
        repo=repo,
        sha=target_sha,
        state=status_state,
        description=status_desc,
        context="CodeMender / Security Gate",
        target_url=run_url,
    )

  if not should_fail and findings_count == 0 and token and owner and repo and pr_number:
    resolve_sticky_comment_if_present(
        token=token,
        owner=owner,
        repo=repo,
        pr_number=pr_number,
        target_sha=target_sha,
        min_sev=min_sev,
    )

  if step_summary:
    icon = "❌ BLOCKED" if should_fail else "✅ PASSED"
    policy_desc = (
        f"Block PRs with `>= {min_sev}` vulnerabilities"
        if fail_enabled
        else "Non-blocking audit mode (merge blocking disabled)"
    )
    with open(step_summary, "a", encoding="utf-8") as sf:
      sf.write(f"## 🛡️ CodeMender Pre-Submit Security Gate: {icon}\n\n")
      sf.write(f"- **Gating Policy:** {policy_desc}\n")
      sf.write(f"- **Blocking Findings (`>= {min_sev}`):** `{blocking_count}`\n")
      sf.write(f"- **Advisory Findings (`< {min_sev}`):** `{advisory_count}`\n")
      sf.write(f"- **Status:** {status_desc}\n")

  if should_fail:
    raise SystemExit(1)
  return 0
