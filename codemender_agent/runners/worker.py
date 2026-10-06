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

"""Stage 2: Parallel Worker runner for CodeMender Agent."""

from contextlib import closing
import json
import logging
import os
import random
import re
import shutil
import sqlite3
import sys
import tarfile
import time
from typing import Optional

from codemender_agent.codemender.cli import get_cm_default_model
from codemender_agent.codemender.cli import log_cm_version
from codemender_agent.codemender.cli import parse_findings_json
from codemender_agent.codemender.cli import restore_staged_cm_binary
from codemender_agent.codemender.db import get_finding_status
from codemender_agent.codemender.db import is_finding_verified
from codemender_agent.config import OrchestratorConfig
from codemender_agent.config import PR_MODE_REVIEW_SUGGESTION
from codemender_agent.config import call_with_github_token
from codemender_agent.config import get_cleanup_ports
from codemender_agent.config import get_github_credentials
from codemender_agent.config import get_scrubbed_env
from codemender_agent.config import inject_codemender_config
from codemender_agent.config import is_presubmit_pipeline
from codemender_agent.config import refresh_github_token
from codemender_agent.config import resolve_pr_remediation_mode
from codemender_agent.storage import download_from_url
from codemender_agent.storage import get_storage_adapter
from codemender_agent.storage import upload_to_url
from codemender_agent.utils import accumulate_model_token_usage
from codemender_agent.utils import build_cm_command
from codemender_agent.utils import free_port
from codemender_agent.utils import resolve_command_model
from codemender_agent.utils import run_command
from codemender_agent.vcs.git import clean_workspace
from codemender_agent.vcs.git import configure_git_identity
from codemender_agent.vcs.git import filter_stageable_files
from codemender_agent.vcs.git import get_finding_branch_name
from codemender_agent.vcs.git import get_git_auth_header
from codemender_agent.vcs.git import normalize_repo_relative_path
from codemender_agent.vcs.git import parse_patch_to_suggestions
from codemender_agent.vcs.git import parse_repo_owner_and_name
from codemender_agent.vcs.git import push_branch_to_remote
from codemender_agent.vcs.git import sanitize_exploit_and_artifacts
from codemender_agent.vcs.git import sanitize_git_url
from codemender_agent.vcs.git import setup_local_git_excludes
from codemender_agent.vcs.github import MAX_COMMENT_BODY_CHARS
from codemender_agent.vcs.github import build_review_comment
from codemender_agent.vcs.github import check_remote_branch_exists
from codemender_agent.vcs.github import create_pr_comment
from codemender_agent.vcs.github import create_pr_review_with_suggestions
from codemender_agent.vcs.github import create_pull_request
from codemender_agent.vcs.github import delete_remote_branch
from codemender_agent.vcs.github import finding_marker
from codemender_agent.vcs.github import format_suggestion_body
from codemender_agent.vcs.github import get_default_branch
from codemender_agent.vcs.github import get_pr_diff_line_ranges
from codemender_agent.vcs.github import is_duplicate_pr
from codemender_agent.vcs.github import list_reviewed_finding_ids
from codemender_agent.wiz.converter import carries_import_marker
from codemender_agent.wiz.settings import take_wiz_credentials

logger = logging.getLogger("codemender-orchestrator")

# Verdicts after which re-running `cm verify` on an imported finding is pointless.
_NOT_EXPLOITABLE_STATUSES = frozenset({"DISMISSED", "FALSE_POSITIVE"})

# Status the worker records when every `cm fix` attempt failed. Without it the
# finding would keep its VERIFIED status and be indistinguishable from one for
# which a fix was never attempted.
FIX_FAILED_STATUS = "FIX_FAILED"

# Delay between ordinary verify/fix retries.
_RETRY_DELAY_SECONDS = 5.0
# Defaults for the backoff applied when cm failed on a model quota or rate limit
# (HTTP 429 / RESOURCE_EXHAUSTED). Per-project concurrency quotas free up only
# as other sessions finish, so a fixed 5 s pause just burns the retry budget.
_QUOTA_BACKOFF_BASE_SECONDS = 60.0
_QUOTA_BACKOFF_MAX_SECONDS = 600.0
_QUOTA_ERROR_PATTERN = re.compile(
    r"\bcode:?\s*429\b|\bHTTP\s*429\b|\b429\s+Too Many Requests\b"
    r"|RESOURCE_EXHAUSTED|Resource has been exhausted|Quota exceeded"
    r"|too_many_requests|rate limit exceeded",
    re.IGNORECASE,
)


def _is_quota_error(output: object) -> bool:
  """Whether cm output shows a model quota or rate-limit rejection."""
  return isinstance(output, str) and bool(_QUOTA_ERROR_PATTERN.search(output))


def _env_seconds(name: str, default: float) -> float:
  try:
    value = float(os.environ.get(name, default))
  except (TypeError, ValueError):
    return default
  return value if value >= 0 else default


def _retry_delay_seconds(attempt: int, output: object) -> float:
  """Seconds to wait before retrying after a failed verify/fix attempt.

  Ordinary failures keep the short fixed pause. Quota failures back off
  exponentially (base * 2^(attempt-1), capped) with jitter, so parallel workers
  that hit the same quota do not retry in lockstep.
  """
  if not _is_quota_error(output):
    return _RETRY_DELAY_SECONDS
  base = _env_seconds(
      "CODEMENDER_QUOTA_BACKOFF_SECONDS", _QUOTA_BACKOFF_BASE_SECONDS
  )
  cap = _env_seconds(
      "CODEMENDER_QUOTA_BACKOFF_MAX_SECONDS", _QUOTA_BACKOFF_MAX_SECONDS
  )
  delay = min(cap, base * (2 ** max(0, attempt - 1)))
  return delay * random.uniform(0.5, 1.0)


def _sleep_before_retry(
    stage: str, finding_id: str, attempt: int, output: object
) -> None:
  delay = _retry_delay_seconds(attempt, output)
  if _is_quota_error(output):
    logger.warning(
        "cm %s for finding %s hit a model quota or rate limit; backing off"
        " %.0f s before retrying.",
        stage,
        finding_id,
        delay,
    )
  time.sleep(delay)


def _mark_fix_failed(state_db_path: str, finding_id: str, reason: str) -> None:
  """Records in the worker state database that every fix attempt failed."""
  if not os.path.exists(state_db_path):
    return
  try:
    with closing(sqlite3.connect(state_db_path)) as conn:
      conn.execute(
          "UPDATE findings SET status = ?, mute_reason = ? WHERE finding_id = ?",
          (FIX_FAILED_STATUS, reason, finding_id),
      )
      conn.commit()
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.warning("Failed to set %s in worker state.db: %s", FIX_FAILED_STATUS, e)


def _mark_pr_creation_failed(
    state_db_path: str, finding_id: str, reason: str
) -> None:
  """Records in the worker state database that GitHub delivery failed."""
  if not os.path.exists(state_db_path):
    return
  try:
    with closing(sqlite3.connect(state_db_path)) as conn:
      conn.execute(
          "UPDATE findings SET status = 'PR_CREATION_FAILED', mute_reason = ?"
          " WHERE finding_id = ?",
          (reason, finding_id),
      )
      conn.commit()
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.warning(
        "Failed to set PR_CREATION_FAILED in worker state.db: %s", e
    )


def _read_force_verify_ids(partition_path: str) -> set[str]:
  """IDs in this partition that must be verified regardless of skip_verify.

  Stage 1 lists findings imported from an external scanner here. Older
  partition files have no such key, which yields an empty set.
  """
  try:
    with open(partition_path, "r", encoding="utf-8") as f:
      data = json.load(f)
  except (OSError, ValueError, TypeError):
    return set()
  ids = data.get("force_verify_ids") if isinstance(data, dict) else None
  return {str(i) for i in ids} if isinstance(ids, list) else set()


def _must_force_verify(
    finding_id: str, finding: Optional[dict], force_verify_ids: set[str]
) -> bool:
  """Whether a finding must be verified regardless of skip_verify.

  Stage 1's partition list is the primary signal. The import marker the
  bridge writes into every imported finding is a second, independent one, so
  a missing or stale partition list can never let an unverified external
  finding reach a fix.
  """
  return finding_id in force_verify_ids or carries_import_marker(finding)


def _setup_git_and_checkout(
    clean_repo_url: str,
    token: str,
    repo_dir: str,
    workspace_dir: str,
    target_sha: Optional[str],
    owner: str,
    repo_name: str,
    is_pr_scan: bool = False,
) -> tuple[str, str]:
  """Clones the repository and checkouts the working base ref (target SHA for PRs, default branch for Nightly).

  Returns:
    Tuple of (default_branch, working_base_ref).
  """
  logger.info("Cloning repository: %s", clean_repo_url)

  # 1. Clean workspace directory if previously populated
  if os.path.exists(repo_dir):
    shutil.rmtree(repo_dir)

  # 2. Clone repository from GitHub using authentication header (blobless partial clone with fallback)
  base_clone_cmd = [
      "git",
      "-c",
      get_git_auth_header(token),
      "clone",
  ]
  use_partial_clone = (
      os.environ.get("CODEMENDER_GIT_PARTIAL_CLONE", "true").strip().lower()
      in ("true", "1", "yes")
  )
  cloned = False
  if use_partial_clone:
    try:
      run_command(
          base_clone_cmd + ["--filter=blob:none", clean_repo_url, repo_dir],
          cwd=workspace_dir,
      )
      cloned = True
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.warning(
          "Blobless partial clone failed (%s); retrying with full clone.", e
      )
      if os.path.exists(repo_dir):
        shutil.rmtree(repo_dir, ignore_errors=True)
  if not cloned:
    run_command(base_clone_cmd + [clean_repo_url, repo_dir], cwd=workspace_dir)

  # 3. Determine the repository's target or default branch (e.g. main/master/branch-4.0)
  target_branch = (os.environ.get("CODEMENDER_TARGET_BRANCH") or "").strip()
  try:
    default_branch = target_branch or run_command(
        ["git", "branch", "--show-current"], cwd=repo_dir
    ).stdout.strip()
  except Exception:  # pylint: disable=broad-exception-caught
    default_branch = ""
  if not default_branch:
    default_branch = get_default_branch(token, owner, repo_name)

  # 4. Checkout the target commit SHA (for PRs) or default branch (for Nightly)
  working_base_ref = target_sha if (is_pr_scan and target_sha) else (target_sha or default_branch)
  if working_base_ref:
    logger.info("Checking out working base ref: %s", working_base_ref)
    if target_sha:
      # Fetch explicit target SHA from origin to support detached or unadvertised PR commits
      fetch_target_cmd = [
          "git",
          "-c",
          get_git_auth_header(token),
          "fetch",
          "origin",
          target_sha,
      ]
      run_command(fetch_target_cmd, cwd=repo_dir, check=False)
    run_command(["git", "checkout", "-f", working_base_ref], cwd=repo_dir)
  else:
    logger.info("Using default branch: %s", default_branch)
    run_command(["git", "checkout", "-f", default_branch], cwd=repo_dir)
    working_base_ref = default_branch

  # 5. Configure local Git identity and exclusion patterns
  configure_git_identity(repo_dir, token, run=run_command)
  setup_local_git_excludes(repo_dir)

  return default_branch, working_base_ref


def _restore_state(
    base_workspace_url: str,
    partition_url: str,
    workspace_dir: str,
    worker_index: int,
    codemender_home: str,
) -> tuple[str, list[str]]:
  """Downloads and extracts base workspace tarball and worker partition file."""
  # 1. Reset local ~/.codemender directory
  if os.path.exists(codemender_home):
    shutil.rmtree(codemender_home)
  os.makedirs(codemender_home, exist_ok=True)

  # 2. Download base workspace tarball (contains initialized SQLite state.db)
  tarball_path = os.path.join(workspace_dir, "workspace_base.tar.gz")
  if not os.path.exists(tarball_path):
    logger.info("Downloading base workspace from URL: %s", base_workspace_url)
    if not download_from_url(base_workspace_url, tarball_path):
      # Fallback to local transit directory if running in local/GitHub Actions mode
      transit_tarball = os.path.join(workspace_dir, ".codemender_transit", "base", "workspace_base.tar.gz")
      if os.path.exists(transit_tarball):
        shutil.copy2(transit_tarball, tarball_path)
      else:
        logger.critical("Failed to download base workspace.")
        sys.exit(1)

  # 3. Extract base workspace archive into user home directory
  logger.info(
      "Extracting base workspace to %s", os.path.dirname(codemender_home)
  )
  if os.path.exists(tarball_path):
    try:
      with tarfile.open(tarball_path, "r:gz") as tar:
        # Use safe data_filter on Python 3.12+ to prevent traversal vulnerabilities and deprecation warnings
        if hasattr(tarfile, "data_filter"):
          tar.extractall(path=os.path.dirname(codemender_home), filter="data")
        else:
          tar.extractall(path=os.path.dirname(codemender_home))
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.critical("Failed to extract base workspace tarball: %s", e)
      sys.exit(1)

  # 4. Download assigned worker partition JSON file
  partition_path = os.path.join(workspace_dir, f"partition_{worker_index}.json")
  if not os.path.exists(partition_path):
    logger.info("Downloading partition from URL: %s", partition_url)
    if not download_from_url(partition_url, partition_path):
      transit_part = os.path.join(workspace_dir, ".codemender_transit", "base", f"partition_{worker_index}.json")
      if os.path.exists(transit_part):
        shutil.copy2(transit_part, partition_path)
      else:
        logger.critical("Failed to download partition.")
        sys.exit(1)

  # 5. Parse partition slice to extract assigned Finding IDs
  with open(partition_path, "r", encoding="utf-8") as f:
    partition_data = json.load(f)
  # Extract list of finding IDs assigned to this worker shard
  finding_ids = partition_data.get("finding_ids", [])
  logger.info("Worker assigned findings: %s", finding_ids)

  # Return partition metadata tuple
  return partition_path, finding_ids


def _mark_skipped_duplicate(
    state_db_path: str, finding_id: str, reason: str
) -> None:
  """Mutes a finding in the worker state database as an already-handled duplicate."""
  if not os.path.exists(state_db_path):
    return
  try:
    with closing(sqlite3.connect(state_db_path)) as conn:
      conn.execute(
          "UPDATE findings SET status = 'SKIPPED_DUPLICATE', muted = 1,"
          " mute_reason = ? WHERE finding_id = ?",
          (reason, finding_id),
      )
      conn.commit()
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.warning("Failed to set SKIPPED_DUPLICATE in worker state.db: %s", e)


def _skip_if_duplicate_branch_or_pr(
    clean_repo_url: str,
    token: str,
    repo_dir: str,
    branch_name: str,
    file_path: str,
    vuln_type: str,
    start_line: int,
    finding_id: str,
    state_db_path: str,
) -> bool:
  """Reports whether a branch or PR already remediates this finding."""
  is_branch_dup = check_remote_branch_exists(
      clean_repo_url, token, branch_name, cwd=repo_dir
  )
  is_pr_dup = is_duplicate_pr(
      clean_repo_url,
      token,
      file_path,
      vuln_type,
      start_line,
      head_branch=branch_name,
  )
  if not (is_branch_dup or is_pr_dup):
    return False

  logger.info(
      "Finding %s skipped due to existing duplicate branch/PR.", finding_id
  )
  _mark_skipped_duplicate(
      state_db_path, finding_id, "Duplicate PR or branch already exists"
  )
  return True


# -----------------------------------------------------------------------------
# Fork Pull Request Patch Comment Construction
# -----------------------------------------------------------------------------
def _fit_fork_comment(
    header: str, diff_section: str, apply_section: str, footer: str
) -> str:
  """Assembles the fork patch comment, dropping sections that will not fit.

  The patch appears twice (once to read, once inside a `git apply` heredoc), so
  a large diff overflows GitHub's comment limit. Sections are dropped whole
  rather than letting the body be cut mid-patch: a truncated heredoc still
  renders as a complete-looking block, and pasting it yields a corrupt patch.
  """
  oversize_note = (
      "> [!WARNING]\n"
      "> The patch is too large to embed in a pull request comment. Download"
      " the `codemender-report` artifact from the workflow run for the full"
      " diff.\n\n"
  )
  candidates = (
      header + diff_section + apply_section + footer,
      header + diff_section + footer,
      header + oversize_note + footer,
  )
  for body in candidates:
    if len(body) <= MAX_COMMENT_BODY_CHARS:
      return body
  # Even the header alone is oversized; the API layer truncates as a last resort.
  return candidates[-1]


# -----------------------------------------------------------------------------
# GitHub Review Suggestion Construction
# -----------------------------------------------------------------------------
def _build_suggestion_comments(
    finding_id: str,
    finding_meta: dict[str, any],
    repo_dir: str,
    patch_diff: str,
    pr_diff_line_ranges: dict[str, set[int]],
) -> tuple[list[dict], Optional[str]]:
  """Converts a fix patch into inline suggestion comments, or reports a blocker.

  Remediation is offered as a suggestion only when the *entire* patch can be
  expressed as one-click suggestions. A patch that creates, renames or deletes
  files, or that touches a line GitHub will not render as part of the PR diff,
  is rejected wholesale so the caller can route it to a fallback instead of
  posting a partial fix the reviewer could mistake for a complete one.

  Returns:
    Tuple of (comments, blocker_reason). Exactly one is populated.
  """
  # 1. Translate the unified diff into anchorable replacement hunks
  hunks, blockers = parse_patch_to_suggestions(repo_dir, patch_diff)
  if blockers:
    return [], "; ".join(blockers)
  if not hunks:
    return [], "the fix produced no suggestable hunks"

  # 2. Reject the whole patch unless every anchor line is inside the PR diff
  for hunk in hunks:
    addressable = pr_diff_line_ranges.get(hunk.path)
    if not addressable:
      return [], f"`{hunk.path}` is not part of the reviewable pull request diff"
    outside = [
        line
        for line in range(hunk.start_line, hunk.end_line + 1)
        if line not in addressable
    ]
    if outside:
      return [], (
          f"`{hunk.path}` line(s) {outside[0]}-{outside[-1]} fall outside the"
          " pull request diff"
      )

  # 3. Render one suggestion comment per hunk, each carrying the dedup marker
  marker = finding_marker(finding_id)
  severity = finding_meta.get("severity") or "UNKNOWN"
  vuln_type = finding_meta.get("vuln_type") or "vulnerability"
  analysis = finding_meta.get("analysis") or ""
  total = len(hunks)

  comments: list[dict] = []
  for index, hunk in enumerate(hunks, start=1):
    if index == 1:
      preamble = (
          f"{marker}\n"
          f"### 🛡️ CodeMender: {severity} `{vuln_type}`\n\n"
          f"{analysis}\n\n"
          f"Commit the suggestion below to apply the fix"
          f"{f' (part 1 of {total})' if total > 1 else ''}."
      )
    else:
      preamble = (
          f"{marker}\n"
          f"🛡️ **CodeMender** — part {index} of {total} of the fix for"
          f" `{vuln_type}` in this pull request."
      )
    comments.append(
        build_review_comment(
            path=hunk.path,
            start_line=hunk.start_line,
            end_line=hunk.end_line,
            body=format_suggestion_body(hunk.replacement_lines, preamble=preamble),
        )
    )

  return comments, None


# -----------------------------------------------------------------------------
# Single Finding Remediation and PR Pipeline
# -----------------------------------------------------------------------------
def _process_finding(
    finding_id: str,
    finding: dict[str, any],
    repo_dir: str,
    cm_binary: str,
    scrubbed_env: dict[str, str],
    clean_repo_url: str,
    # Authentication credentials and repository metadata
    token: str,
    owner: str,
    repo_name: str,
    default_branch: str,
    working_base_ref: str,
    state_db_path: str,
    worker_token_usage: dict[str, dict[str, int]],
    config: OrchestratorConfig,
    pr_diff_line_ranges: Optional[dict[str, set[int]]] = None,
    already_suggested: Optional[set[str]] = None,
    force_verify: bool = False,
) -> Optional[str]:
  """Handles verification, surgical staging, and PR routing for a single finding.

  Args:
    force_verify: Run ``cm verify`` even when verification is otherwise
      skipped. Set for findings imported from an external scanner, which must
      never reach a fix or pull request without CodeMender's own verdict.

  Returns:
    The URL of the remediation that was delivered — an inline suggestion
    review, a fork patch comment, or a Child Pull Request — or None when the
    finding was skipped or no remediation could be routed.
  """
  # 1. Extract finding metadata, vulnerability type, and target file path
  cli_version = config.cli_version
  vuln_type = finding.get("VulnType") or "vulnerability"
  file_path = normalize_repo_relative_path(
      finding.get("FilePath") or "unknown_file", repo_dir=repo_dir
  )
  # Extract title, severity, and analysis details from finding record
  title = finding.get("Title") or f"Security Fix for {vuln_type}"
  severity = finding.get("Severity") or "UNKNOWN"
  analysis = finding.get("Analysis") or "Automated fix generated by CodeMender."
  # Resolve model overrides for verification and fix stages
  default_cm_model = get_cm_default_model(cm_binary, env=scrubbed_env, cwd=repo_dir)
  verify_model = config.verify_model or resolve_command_model("verify") or default_cm_model
  fix_model = config.fix_model or resolve_command_model("fix") or default_cm_model

  try:
    start_line = int(finding.get("StartLine") or 0)
  except ValueError:
    start_line = 0

  # 2. Compute canonical branch name for finding
  branch_name = get_finding_branch_name(file_path, vuln_type, start_line)

  # 3. Resolve the remediation route for this finding
  suggestion_mode = (
      config.is_pr_scan
      and bool(config.pr_number)
      and resolve_pr_remediation_mode(config) == PR_MODE_REVIEW_SUGGESTION
  )

  logger.info(
      "Processing finding %s (Branch: %s, Remediation: %s)",
      finding_id,
      branch_name,
      "review suggestion" if suggestion_mode else "pull request",
  )

  # 1. Enforce force_overwrite = False on all PR scans to avoid branch clobbering
  force_overwrite = config.force_overwrite and not config.is_pr_scan

  if suggestion_mode:
    # No branch or PR is created in suggestion mode, so remote-branch dedup
    # cannot apply. The marker embedded in a previously posted suggestion is
    # the equivalent idempotency signal across re-runs.
    if already_suggested and finding_id in already_suggested:
      logger.info(
          "Finding %s skipped; a suggestion was already posted on PR #%s.",
          finding_id,
          config.pr_number,
      )
      _mark_skipped_duplicate(
          state_db_path, finding_id, "Suggestion already posted on this PR"
      )
      return
  elif not force_overwrite and not config.dry_run:
    # A dry run skips remote duplicate checks so that repeated runs against
    # the same commit (for example the arms of an A/B comparison) all process
    # the same findings.
    try:
      is_duplicate, token = call_with_github_token(
          config,
          token,
          lambda tok: _skip_if_duplicate_branch_or_pr(
              clean_repo_url,
              tok,
              repo_dir,
              branch_name,
              file_path,
              vuln_type,
              start_line,
              finding_id,
              state_db_path,
          ),
      )
    except Exception as e:  # pylint: disable=broad-exception-caught
      # Fail closed: without a duplicate check, remediating could clobber an
      # existing fix branch or open a second pull request. Record the failure
      # and return, so the worker moves on and still uploads its state.
      logger.error(
          "Could not check GitHub for an existing branch or pull request for"
          " finding %s; not remediating it: %s",
          finding_id,
          e,
      )
      _mark_pr_creation_failed(
          state_db_path, finding_id, f"GitHub duplicate check failed: {e}"
      )
      return None
    if is_duplicate:
      return

  # 2. Verification Retry Loop (Executes 'cm verify' with port cleanup)
  # skip_verify defaults to true; an explicit skip_verify=false is honored on
  # every platform, including Cloud Run.
  effective_skip_verify = not force_verify and config.skip_verify
  if force_verify:
    logger.info(
        "Finding %s was imported from an external scanner; verification is"
        " mandatory.",
        finding_id,
    )
  if not effective_skip_verify:
    max_verify_attempts = int(
        os.environ.get("CODEMENDER_MAX_VERIFY_ATTEMPTS", "3")
    )
    verified = False

    for attempt in range(1, max_verify_attempts + 1):
      logger.info(
          "Verifying finding %s (Attempt %d/%d)...",
          finding_id,
          attempt,
          max_verify_attempts,
      )
      # Free configured development ports before running probers/exploit verification
      for port in get_cleanup_ports(config=config):
        free_port(port)

      # Reset repository workspace to clean state before running verify
      run_command(["git", "checkout", "-f", working_base_ref], cwd=repo_dir)
      clean_workspace(repo_dir)

      # Execute 'cm verify' command
      verify_cmd = build_cm_command(
          cm_binary, "verify", finding_id, cli_version=cli_version
      )
      verify_res = run_command(
          verify_cmd,
          cwd=repo_dir,
          env=scrubbed_env,
          check=False,
      )
      token_usage = getattr(verify_res, "token_usage", None)
      if isinstance(token_usage, dict):
        accumulate_model_token_usage(
            worker_token_usage, verify_model, token_usage
        )

      # Free cleanup ports after verification completes
      for port in get_cleanup_ports(config=config):
        free_port(port)

      # Check whether the verification succeeded and state.db reflects verification
      if verify_res.returncode == 0 and is_finding_verified(
          state_db_path, finding_id
      ):
        logger.info("Successfully verified finding %s.", finding_id)
        verified = True
        break
      elif force_verify and verify_res.returncode == 0 and (
          get_finding_status(state_db_path, finding_id)
          in _NOT_EXPLOITABLE_STATUSES
      ):
        # A definitive "not exploitable" verdict; retrying cannot change it.
        logger.info(
            "Imported finding %s was not confirmed by verification.",
            finding_id,
        )
        break
      else:
        logger.warning(
            "Attempt %d failed to verify finding %s.", attempt, finding_id
        )
        if attempt < max_verify_attempts:
          _sleep_before_retry(
              "verify", finding_id, attempt, getattr(verify_res, "stdout", None)
          )

    if not verified:
      logger.error(
          "Verification failed for finding %s. Skipping fix.", finding_id
      )
      sanitize_exploit_and_artifacts(
          repo_dir, codemender_home=os.path.dirname(state_db_path)
      )
      return

    # Sanitize any accidental package/build caches from .exploit before fix starts
    sanitize_exploit_and_artifacts(
        repo_dir, codemender_home=os.path.dirname(state_db_path)
    )
  else:
    logger.info(
        "Skipping 'cm verify' for finding %s (skip_verify=True). Proceeding"
        " directly to fix.",
        finding_id,
    )

  # 3. Apply Automated Fix (Executes 'cm fix' with up to 3 attempts)
  max_fix_attempts = 3
  fixed = False
  for attempt in range(1, max_fix_attempts + 1):
    logger.info(
        "Applying fix for finding %s (Attempt %d/%d)...",
        finding_id,
        attempt,
        max_fix_attempts,
    )
    # Ensure a clean workspace before each fix attempt
    run_command(["git", "checkout", "-f", working_base_ref], cwd=repo_dir)
    clean_workspace(repo_dir)
    for port in get_cleanup_ports(config=config):
      free_port(port)

    fix_cmd = build_cm_command(
        cm_binary, "fix", finding_id, cli_version=cli_version
    )
    fix_res = run_command(
        fix_cmd,
        cwd=repo_dir,
        env=scrubbed_env,
        check=False,
    )
    token_usage = getattr(fix_res, "token_usage", None)
    if isinstance(token_usage, dict):
      accumulate_model_token_usage(worker_token_usage, fix_model, token_usage)

    for port in get_cleanup_ports(config=config):
      free_port(port)

    finding_status = get_finding_status(state_db_path, finding_id)

    if fix_res.returncode == 0 and finding_status == "FIXED":
      logger.info("Successfully applied fix for finding %s.", finding_id)
      fixed = True
      break
    else:
      logger.warning(
          "Attempt %d failed to fix finding %s (status: %s, returncode: %d).",
          attempt,
          finding_id,
          finding_status,
          fix_res.returncode,
      )
      if attempt < max_fix_attempts:
        _sleep_before_retry(
            "fix", finding_id, attempt, getattr(fix_res, "stdout", None)
        )

  if not fixed:
    logger.warning(
        "Fix failed for finding %s (status: %s)", finding_id, finding_status
    )
    # Record the exhaustion so telemetry can tell a failed fix apart from a
    # verified finding that was never sent to fix. A not-exploitable verdict
    # reached during fix is kept as is.
    if str(finding_status or "").upper() not in _NOT_EXPLOITABLE_STATUSES:
      _mark_fix_failed(
          state_db_path,
          finding_id,
          f"cm fix failed after {max_fix_attempts} attempts (last status:"
          f" {finding_status}, returncode: {fix_res.returncode})",
      )
    return

  # 4. Surgical Git Staging 3-Tier Fallback
  # Extract patch metadata from local state.db patches table
  edited_files = []
  target_file = None
  patch_diff = ""
  try:
    with closing(sqlite3.connect(state_db_path)) as conn:
      cursor = conn.cursor()
      cursor.execute(
          "SELECT edited_files, target_file, diff FROM patches WHERE"
          " finding_id = ?",
          (finding_id,),
      )
      row = cursor.fetchone()
      if row:
        try:
          edited_files = json.loads(row[0]) if row[0] else []
        except Exception:
          edited_files = []
        target_file = row[1]
        patch_diff = row[2] or ""
  except Exception as e:
    logger.warning("Failed to query patches table for staging: %s", e)

  staged = False
  # Tier 1: Stage explicit edited_files recorded by the agent in patches table
  if edited_files and isinstance(edited_files, list):
    valid_files = filter_stageable_files(repo_dir, edited_files)
    if valid_files:
      try:
        run_command(["git", "add"] + valid_files, cwd=repo_dir)
        staged = True
        logger.info(
            "Surgical Git Staging (Tier 1 - edited_files): %s", valid_files
        )
      except Exception as e:
        logger.warning(
            "Failed to stage edited_files %s (falling back): %s", valid_files, e
        )

  # Tier 2: Stage target_file recorded in patches table
  if not staged and target_file:
    valid_targets = filter_stageable_files(repo_dir, [target_file])
    if valid_targets:
      try:
        run_command(["git", "add"] + valid_targets, cwd=repo_dir)
        staged = True
        logger.info(
            "Surgical Git Staging (Tier 2 - target_file): %s", valid_targets
        )
      except Exception as e:
        logger.warning(
            "Failed to stage target_file %s (falling back): %s", valid_targets, e
        )

  # Tier 3: Tracked staging + Finding FilePath fallback
  if not staged:
    try:
      run_command(["git", "add", "-u"], cwd=repo_dir, check=False)
      valid_fallbacks = (
          filter_stageable_files(repo_dir, [file_path]) if file_path else []
      )
      if valid_fallbacks:
        run_command(["git", "add"] + valid_fallbacks, cwd=repo_dir, check=False)
      staged = True
      logger.info(
          "Surgical Git Staging (Tier 3 - Fallback): git add -u + %s",
          valid_fallbacks,
      )
    except Exception as e:
      logger.warning("Failed during Tier 3 fallback staging: %s", e)

  # Check if any git modifications are staged
  status_res = run_command(["git", "status", "--porcelain"], cwd=repo_dir)
  if not status_res.stdout.strip():
    logger.warning("No changes detected after fix for finding %s", finding_id)
    return

  # Extract unified git diff if not captured in patches table
  if not patch_diff:
    diff_res = run_command(["git", "diff", "HEAD"], cwd=repo_dir, check=False)
    patch_diff = diff_res.stdout

  # 5. Route the remediation to the reviewer
  try:
    if config.dry_run:
      # Leave the finding's state as cm recorded it (FIXED, with its patch)
      # rather than marking a routing failure; the finally block below resets
      # the workspace.
      logger.info(
          "Dry run (CODEMENDER_DRY_RUN): fix for finding %s is ready; not"
          " creating a branch, pull request, review or comment on GitHub.",
          finding_id,
      )
      return None
    # Verification and fixing can take longer than a GitHub App installation
    # token lives, so re-read the token before routing. A static token is
    # returned unchanged.
    token = refresh_github_token(config, token)
    if suggestion_mode:
      fallback_route = "patch comment" if config.is_fork_pr else "Child PR"
      # Suggestions must be derived before committing: the parser reads the
      # pre-fix content from HEAD, which is still the pull request head commit.
      # Any failure here degrades to the fallback route rather than propagating
      # to the handler below, which would strand the finding with no fix at all.
      try:
        comments, blocker = _build_suggestion_comments(
            finding_id,
            {"severity": severity, "vuln_type": vuln_type, "analysis": analysis},
            repo_dir,
            patch_diff,
            pr_diff_line_ranges or {},
        )
      except Exception as e:  # pylint: disable=broad-exception-caught
        comments, blocker = [], f"suggestion construction failed: {e}"
      if blocker:
        logger.info(
            "Finding %s cannot be offered as a one-click suggestion (%s);"
            " falling back to %s.",
            finding_id,
            blocker,
            fallback_route,
        )
      else:
        review_body = (
            f"### 🛡️ CodeMender proposed a fix for a {severity} `{vuln_type}`\n\n"
            f"**{title}**\n\n"
            f"`{file_path}:{start_line}` · Finding `{finding_id}`\n\n"
            "Commit the inline suggestion(s) in this review to apply the fix"
            " directly to this pull request.\n\n"
            "---\n"
            "*Automatically generated by CodeMender Orchestrator.*"
        )
        review_url = create_pr_review_with_suggestions(
            token=token,
            owner=owner,
            repo=repo_name,
            pr_number=config.pr_number,
            commit_id=config.target_sha,
            body=review_body,
            comments=comments,
        )
        if review_url:
          return review_url
        logger.warning(
            "Suggestion review was rejected for finding %s; falling back to %s.",
            finding_id,
            fallback_route,
        )

    # The fallback and Child PR routes both build on a dedicated fix branch.
    if suggestion_mode and not config.is_fork_pr and not force_overwrite:
      # The upfront duplicate check was skipped because suggestion mode pushes
      # no branch. Falling back to the Child PR route does push one, so the
      # check has to happen now to avoid clobbering an earlier fallback's work.
      if _skip_if_duplicate_branch_or_pr(
          clean_repo_url,
          token,
          repo_dir,
          branch_name,
          file_path,
          vuln_type,
          start_line,
          finding_id,
          state_db_path,
      ):
        return None

    run_command(["git", "checkout", "-B", branch_name], cwd=repo_dir)
    commit_msg = f"fix(security): resolve {vuln_type} in {file_path}"
    run_command(["git", "commit", "-m", commit_msg], cwd=repo_dir)

    if config.is_fork_pr:
      # Fork PR Scan: Post Markdown review comment on the Fork PR instead of pushing
      logger.info(
          "Fork PR Scan: Posting review comment on PR #%s instead of pushing"
          " branch.",
          config.pr_number,
      )
      # Construct formatted Markdown review comment body with analysis, patch diff, and git apply instructions
      comment_header = (
          "### 🛡️ CodeMender Security Fix Suggestion\n\n"
          f"**Finding ID**: `{finding_id}`\n"
          f"**Title**: {title}\n"
          f"**Severity**: {severity}\n"
          f"**Vulnerability Type**: {vuln_type}\n"
          f"**File**: `{file_path}`\n"
          f"**Start Line**: {start_line}\n\n"
          f"#### Analysis\n{analysis}\n\n"
      )
      comment_body = _fit_fork_comment(
          header=comment_header,
          # Render code diff block with 4-backtick fence to prevent premature closure on embedded markdown/backticks
          diff_section=(
              f"#### Suggested Patch Diff\n````diff\n{patch_diff}\n````\n\n"
          ),
          # Render local git apply snippet with 4-backtick fence
          apply_section=(
              "#### How to Apply Locally\n````bash\ngit apply <<"
              f" 'EOF'\n{patch_diff}\nEOF\n````\n\n"
          ),
          footer="---\n*Automatically generated by CodeMender Orchestrator.*",
      )
      # Submit Markdown review comment to Fork PR via GitHub REST API
      if config.pr_number:
        return create_pr_comment(
            token=token,
            owner=owner,
            repo=repo_name,
            pr_number=config.pr_number,
            body=comment_body,
        )
      else:
        # Warn if PR number is missing on fork scan
        logger.warning(
            "Fork PR Scan: CODEMENDER_PR_NUMBER not set; cannot post comment."
        )
        return None
    else:
      # Internal Branch / Nightly Scan: Push fix branch to origin
      logger.info("Pushing branch %s...", branch_name)
      push_branch_to_remote(
          repo_dir=repo_dir,
          token=token,
          branch_name=branch_name,
          force=force_overwrite,
      )

      # Dual PR Routing: Child PR vs Mainline PR
      if config.is_pr_scan:
        base_branch = config.pr_head_ref or default_branch
        logger.info(
            "Internal PR Scan: Creating Child PR targeting feature branch"
            " '%s'...",
            base_branch,
        )
        # Add parent PR cross-reference to title and body for bidirectional linkage
        if config.pr_number:
          pr_title = (
              f"fix(security): resolve {vuln_type} vulnerability in {file_path}"
              f" (Child PR for #{config.pr_number})"
          )
          parent_pr_section = (
              f"**Parent PR**: #{config.pr_number} (Branch: `{base_branch}`)\n\n"
          )
        else:
          pr_title = (
              f"fix(security): resolve {vuln_type} vulnerability in {file_path}"
          )
          parent_pr_section = ""
      else:
        base_branch = default_branch
        logger.info(
            "Nightly/Standard Scan: Creating PR targeting default branch"
            " '%s'...",
            base_branch,
        )
        pr_title = (
            f"fix(security): resolve {vuln_type} vulnerability in {file_path}"
        )
        parent_pr_section = ""

      # Construct PR description with parent PR reference
      pr_body = (
          "### CodeMender Security Fix\n\n"
          f"{parent_pr_section}"
          f"**Finding ID**: `{finding_id}`\n"
          f"**Title**: {title}\n"
          f"**Severity**: {severity}\n"
          f"**Vulnerability Type**: {vuln_type}\n"
          f"**File Path**: `{file_path}`\n"
          f"**Start Line**: {start_line}\n\n"
          f"#### Analysis\n{analysis}\n\n"
          "---\n"
          "*Automatically generated by CodeMender Orchestrator.*"
      )

      # Create Pull Request on GitHub with transactional rollback on failure
      try:
        child_pr_url = create_pull_request(
            token=token,
            owner=owner,
            repo=repo_name,
            title=pr_title,
            body=pr_body,
            head_branch=branch_name,
            base_branch=base_branch,
        )
        if not child_pr_url or child_pr_url == "FAILED":
          raise RuntimeError(f"Failed to create Pull Request for {branch_name}")
      except Exception as pr_err:
        logger.error(
            "PR creation failed for branch %s (%s). Rolling back remote branch to prevent orphan ref...",
            branch_name,
            pr_err,
        )
        delete_remote_branch(clean_repo_url, token, branch_name, cwd=repo_dir)
        raise

      # Post notification comment on Parent PR linking to the generated Child PR
      if (
          config.is_pr_scan
          and config.pr_number
          and child_pr_url
          and child_pr_url != "EXISTING_PR"
      ):
        # Extract Child PR number from URL if available
        child_match = re.search(r"/pull/(\d+)", child_pr_url)
        child_ref = f"#{child_match.group(1)}" if child_match else child_pr_url
        parent_comment = (
            "### 🛡️ CodeMender Security Fix Created\n\n"
            f"CodeMender detected a **{severity}** `{vuln_type}` vulnerability"
            f" in `{file_path}:{start_line}` and generated a proposed fix in"
            f" {child_ref}.\n\n"
            f"- **Child PR**: {child_pr_url}\n"
            f"- **Target Branch**: `{base_branch}`\n"
            f"- **Fix Branch**: `{branch_name}`\n\n"
            "#### Recommended Action\n"
            f"Review and merge {child_ref} into your feature branch"
            f" `{base_branch}` to resolve this finding.\n\n"
            "---\n"
            "*Automatically generated by CodeMender Orchestrator.*"
        )
        logger.info(
            "Posting notification comment on Parent PR #%d linking to Child"
            " PR...",
            config.pr_number,
        )
        create_pr_comment(
            token=token,
            owner=owner,
            repo=repo_name,
            pr_number=config.pr_number,
            body=parent_comment,
        )
      return child_pr_url
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.error("Error creating branch/PR for finding %s: %s", finding_id, e)
    if os.path.exists(state_db_path):
      try:
        with closing(sqlite3.connect(state_db_path)) as conn:
          conn.execute(
              "UPDATE findings SET status = 'PR_CREATION_FAILED', mute_reason = ? WHERE finding_id = ?",
              (f"PR creation or git push failed: {e}", finding_id),
          )
          conn.commit()
      except Exception as db_err:
        logger.warning(
            "Failed to update status to PR_CREATION_FAILED in worker state.db: %s",
            db_err,
        )
    return None
  finally:
    # Always reset workspace back to clean working base ref
    run_command(["git", "checkout", "-f", working_base_ref], cwd=repo_dir)
    clean_workspace(repo_dir)


def _save_and_upload_worker_metadata(
    workspace_dir: str,
    worker_index: int,
    worker_token_usage: dict[str, dict[str, int]],
    metadata_url: Optional[str],
    finding_prs: Optional[dict[str, str]] = None,
) -> None:
  """Saves worker metadata JSON and uploads it to GCS or transit storage."""
  # 1. Validate that metadata destination URL is available
  if not metadata_url:
    logger.error(
        "Failed to resolve metadata signed URL for worker %d; token usage"
        " statistics will be incomplete!",
        worker_index,
    )
    return

  logger.info("Uploading worker %d metadata...", worker_index)
  # 2. Package worker telemetry and token usage dictionary
  worker_metadata = {
      "worker_index": worker_index,
      "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
      "token_usage": worker_token_usage,
      "finding_prs": finding_prs or {},
  }
  meta_path = os.path.join(
      workspace_dir, f"worker_{worker_index}_metadata.json"
  )
  try:
    # 3. Write metadata to local JSON file
    with open(meta_path, "w", encoding="utf-8") as f:
      json.dump(worker_metadata, f, indent=2)
    # 4. Upload worker metadata JSON via signed PUT URL or transit storage
    if not upload_to_url(
        meta_path, metadata_url, content_type="application/json"
    ):
      logger.error(
          "Failed to upload worker %d metadata; token usage statistics will be"
          " incomplete!",
          worker_index,
      )
    else:
      logger.info(
          "Successfully uploaded worker %d metadata.", worker_index
      )
  except Exception as e:  # pylint: disable=broad-exception-caught
    # Log error if saving or uploading worker telemetry fails
    logger.error(
        "Failed to save or upload worker %d metadata: %s", worker_index, e
    )


def run_worker_pipeline() -> None:
  """Executes Stage 2: Download state, run verify/fix on partition, upload mutated state."""
  # Workers never run Wiz; drop any Wiz credentials before a subprocess could
  # inherit them.
  take_wiz_credentials()
  config = OrchestratorConfig.from_env()
  worker_index = config.worker_index if config.worker_index is not None else 0
  if is_presubmit_pipeline():
    repo_full = (
        os.environ.get("REPO_FULL") or os.environ.get("GITHUB_REPOSITORY") or ""
    ).strip()
    owner, repo = (
        repo_full.split("/", 1) if "/" in repo_full else ("", repo_full)
    )
    verify_and_fix_worker_shard(
        workspace_dir=config.workspace_dir or os.getcwd(),
        worker_index=worker_index,
        min_sev=config.min_blocking_severity,
        sandbox_enabled=config.sandbox_enabled,
        skip_exploit_verification=config.skip_verify,
        verify_model=(config.verify_model or "").strip(),
        fix_model=(config.fix_model or "").strip(),
        token=(config.github_token or "").strip(),
        owner=owner,
        repo=repo,
        pr_number=config.pr_number or 0,
        target_sha=(config.target_sha or "").strip(),
        fail_on_findings=config.fail_on_findings,
        allow_unsandboxed_fallback=config.allow_unsandboxed_fallback,
    )
    return

  logger.info("Starting Worker %d", worker_index)

  # Initialize active storage adapter (GCS or GitHub Actions transit adapter)
  adapter = get_storage_adapter(config.storage_mode, config.gcs_bucket)

  # 1. Base Workspace URL Resolution:
  # In GitHub Actions matrix runs, regenerate local file:// URL to match the current worker workspace mount
  base_workspace_url = config.base_workspace_url
  if not base_workspace_url or (
      config.storage_mode == "github_actions"
      and base_workspace_url.startswith("file://")
  ):
    base_workspace_url = adapter.generate_signed_url(
        f"scans/{config.scan_id or 'default_scan'}/workspace_base.tar.gz"
    )

  # 2. Partition URL Resolution:
  # Extract assigned partition URL from list or regenerate via active transit adapter
  partition_url = None
  if config.partition_urls:
    try:
      p_urls = json.loads(config.partition_urls)
      if worker_index < len(p_urls):
        partition_url = p_urls[worker_index]
    except Exception:  # pylint: disable=broad-exception-caught
      pass
  if not partition_url or (
      config.storage_mode == "github_actions"
      and partition_url.startswith("file://")
  ):
    partition_url = adapter.generate_signed_url(
        f"scans/{config.scan_id or 'default_scan'}/partition_{worker_index}.json"
    )

  # 3. Worker Shard Database PUT URL Resolution:
  # Regenerate local transit shard path in GitHub Actions mode to avoid stale mount paths
  upload_url = None
  if config.upload_urls:
    try:
      u_urls = json.loads(config.upload_urls)
      if worker_index < len(u_urls):
        upload_url = u_urls[worker_index]
    except Exception:  # pylint: disable=broad-exception-caught
      pass
  if not upload_url or (
      config.storage_mode == "github_actions"
      and upload_url.startswith("file://")
  ):
    upload_url = adapter.generate_signed_url(
        f"scans/{config.scan_id or 'default_scan'}/worker_{worker_index}_state.db",
        method="PUT",
        content_type="application/octet-stream",
    )

  # 4. Worker Token Usage Metadata PUT URL Resolution:
  # Extract or regenerate signed PUT URL for worker token usage metadata upload
  metadata_url = None
  if config.metadata_urls:
    try:
      m_urls = json.loads(config.metadata_urls)
      if worker_index < len(m_urls):
        metadata_url = m_urls[worker_index]
    except Exception:  # pylint: disable=broad-exception-caught
      pass
  if not metadata_url or (
      config.storage_mode == "github_actions"
      and metadata_url.startswith("file://")
  ):
    metadata_url = adapter.generate_signed_url(
        f"scans/{config.scan_id or 'default_scan'}/worker_{worker_index}_metadata.json",
        method="PUT",
        content_type="application/json",
    )

  # Validate that all required transit signed URLs were resolved
  if not base_workspace_url or not partition_url or not upload_url:
    logger.critical(
        "Failed to resolve required URLs for worker %d.", worker_index
    )
    sys.exit(1)

  workspace_dir = config.workspace_dir or os.getcwd()
  repo_url, token = get_github_credentials(config=config)
  clean_repo_url = sanitize_git_url(repo_url)
  owner, repo_name = parse_repo_owner_and_name(clean_repo_url)
  repo_dir = os.path.join(workspace_dir, repo_name)

  # 5. Clone repository and setup target SHA / working base ref
  target_sha = config.target_sha
  default_branch, working_base_ref = _setup_git_and_checkout(
      clean_repo_url,
      token,
      repo_dir,
      workspace_dir,
      target_sha,
      owner,
      repo_name,
      is_pr_scan=config.is_pr_scan,
  )

  # 6. Initialize local sandbox cache environment
  scrubbed_env = get_scrubbed_env(repo_dir=repo_dir)

  # 7. Restore base workspace and download partition slice
  codemender_home = os.path.expanduser("~/.codemender")
  partition_path, finding_ids = _restore_state(
      base_workspace_url,
      partition_url,
      workspace_dir,
      worker_index,
      codemender_home,
  )
  force_verify_ids = _read_force_verify_ids(partition_path)
  if force_verify_ids:
    logger.info(
        "%d finding(s) in this partition require mandatory verification.",
        len(force_verify_ids),
    )

  state_db_path = os.path.join(codemender_home, "state.db")
  worker_token_usage: dict[str, dict[str, int]] = {}

  # 7. Handle case where partition slice contains zero findings
  if not finding_ids:
    logger.info("No findings in partition. Exiting.")
    if not upload_to_url(state_db_path, upload_url):
      logger.critical("Failed to upload unmodified database.")
      sys.exit(1)

    _save_and_upload_worker_metadata(
        workspace_dir, worker_index, worker_token_usage, metadata_url
    )
    sys.exit(0)

  # 8. Inject project configurations, restore staged cm binary from workspace_base.tar.gz, and verify CLI binary
  # The worker only runs 'cm verify' and 'cm fix', so project_paths is the repository root.
  inject_codemender_config(repo_dir, config=config, for_remediation=True)
  cm_binary = restore_staged_cm_binary(codemender_home)
  log_cm_version(cm_binary, env=scrubbed_env, cwd=repo_dir)
  cli_version = config.cli_version

  # 9. Query restored SQLite state.db for finding metadata
  try:
    report_cmd = build_cm_command(
        cm_binary,
        "report",
        extra_flags=["--format", "json"],
        cli_version=cli_version,
    )
    report_res = run_command(
        report_cmd,
        cwd=repo_dir,
        env=scrubbed_env,
        check=True,
        capture_stderr=False,
    )
    all_findings = parse_findings_json(report_res.stdout)
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.critical("Failed to run cm report in worker: %s", e)
    sys.exit(1)

  findings_dict = {f["FindingID"]: f for f in all_findings if "FindingID" in f}

  worker_finding_prs: dict[str, str] = {}

  # 10. Pre-fetch pull request review context shared by every assigned finding
  pr_diff_line_ranges: dict[str, set[int]] = {}
  already_suggested: set[str] = set()
  if (
      config.is_pr_scan
      and config.pr_number
      and resolve_pr_remediation_mode(config) == PR_MODE_REVIEW_SUGGESTION
  ):
    pr_diff_line_ranges = get_pr_diff_line_ranges(
        token, owner, repo_name, config.pr_number
    )
    already_suggested = list_reviewed_finding_ids(
        token, owner, repo_name, config.pr_number
    )
    logger.info(
        "Review suggestion mode: %d file(s) addressable in PR #%d, %d finding(s)"
        " already suggested.",
        len(pr_diff_line_ranges),
        config.pr_number,
        len(already_suggested),
    )

  # 11. Process each assigned finding sequentially (Verify -> Fix -> Stage -> Route)
  for finding_id in finding_ids:
    finding = findings_dict.get(finding_id)
    if not finding:
      logger.warning(
          "Finding %s not found in restored database, skipping.", finding_id
      )
      continue

    # Earlier findings may have taken longer than a GitHub App installation
    # token lives. A static token is returned unchanged. A failed refresh is
    # not fatal here: routing refreshes again and records a failure for the
    # finding, and the partition's state must still be uploaded.
    try:
      token = refresh_github_token(config, token)
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.error(
          "Could not refresh the GitHub token before finding %s: %s",
          finding_id,
          e,
      )

    # Execute verify, fix, staging, and remediation routing routine for finding.
    # One finding's unexpected failure must not stop the worker before it
    # uploads the partition state below.
    try:
      pr_url = _process_finding(
          finding_id,
          finding,
          repo_dir,
          cm_binary,
          scrubbed_env,
          clean_repo_url,
          token,
          owner,
          repo_name,
          default_branch,
          working_base_ref,
          state_db_path,
          worker_token_usage,
          config=config,
          pr_diff_line_ranges=pr_diff_line_ranges,
          already_suggested=already_suggested,
          force_verify=_must_force_verify(finding_id, finding, force_verify_ids),
      )
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.error(
          "Unexpected error while processing finding %s; continuing with the"
          " next finding: %s",
          finding_id,
          e,
      )
      _mark_fix_failed(state_db_path, finding_id, f"Unexpected error: {e}")
      try:
        run_command(
            ["git", "checkout", "-f", working_base_ref], cwd=repo_dir, check=False
        )
        clean_workspace(repo_dir)
      except Exception as reset_err:  # pylint: disable=broad-exception-caught
        logger.warning("Could not reset the workspace: %s", reset_err)
      pr_url = None
    # Track generated Pull Request URL for Step Summary linking
    if pr_url and isinstance(pr_url, str) and pr_url.startswith("http"):
      worker_finding_prs[finding_id] = pr_url

  # 12. Upload mutated worker state database shard and token telemetry
  logger.info("Uploading mutated database to transit storage...")
  if not upload_to_url(state_db_path, upload_url):
    logger.error("Failed to upload mutated database.")
    sys.exit(1)

  # Upload worker metadata with accumulated token metrics and finding PR links
  _save_and_upload_worker_metadata(
      workspace_dir,
      worker_index,
      worker_token_usage,
      metadata_url,
      finding_prs=worker_finding_prs,
  )

  # 13. Adjust file permissions on transit directory if running in local container
  transit_dir = os.path.join(workspace_dir, ".codemender_transit")
  if os.path.exists(transit_dir):
    try:
      for root, dirs, files in os.walk(transit_dir):
        for d in dirs:
          os.chmod(os.path.join(root, d), 0o777)
        for f in files:
          os.chmod(os.path.join(root, f), 0o666)
    except Exception:
      pass

  logger.info("Stage 2 (Worker) completed successfully.")


_FP_VERDICT_KEYWORDS = (
    "false_positive",
    "false positive",
    "not exploitable",
    "invalid",
    "dismissed",
)

# verified_status for a finding whose `cm verify` produced no verdict (error
# exit, or the sandbox could not start). It is not dismissed, so it still
# counts toward the gate, but it is never reported as confirmed.
VERIFY_FAILED = "VERIFY_FAILED"


def _is_false_positive_verdict(text: str) -> bool:
  """Returns True when verification output or status explicitly dismisses a finding as a false positive."""
  lowered = (text or "").lower()
  return "unverified" not in lowered and any(
      kw in lowered for kw in _FP_VERDICT_KEYWORDS
  )


def verify_and_fix_worker_shard(
    workspace_dir: str,
    worker_index: int = 0,
    min_sev: str = "MEDIUM",
    sandbox_enabled: bool = True,
    skip_exploit_verification: bool = False,
    verify_model: str = "",
    fix_model: str = "",
    token: str = "",
    owner: str = "",
    repo: str = "",
    pr_number: int = 0,
    target_sha: str = "",
    fail_on_findings: Optional[bool] = None,
    allow_unsandboxed_fallback: bool = False,
) -> list[dict]:
  """Runs Stage 2.1 (cm verify), Stage 2.2 (cm fix), and Stage 2.3 (inline suggestions) on a worker shard."""
  from codemender_agent.runners.scan import (
      log_cm_environment,
      restore_presubmit_transit_workspace,
      sandbox_workspace_access,
  )

  base_dir = os.path.join(workspace_dir, ".codemender_transit", "base")
  shard_dir = os.path.join(
      workspace_dir, ".codemender_transit", "shards", f"worker_{worker_index}"
  )
  os.makedirs(shard_dir, exist_ok=True)

  build_cmd = (OrchestratorConfig.from_env().build_command or "true").strip() or "true"
  restore_presubmit_transit_workspace(
      workspace_dir=workspace_dir,
      sandbox_enabled=sandbox_enabled,
      build_cmd=build_cmd,
  )

  results_file = os.path.join(shard_dir, f"results_worker_{worker_index}.json")
  part_file = os.path.join(base_dir, f"partition_{worker_index}.json")
  raw_loaded = []
  if os.path.exists(results_file):
    with open(results_file, "r", encoding="utf-8") as rf:
      raw_loaded = json.load(rf)
  elif os.path.exists(part_file):
    with open(part_file, "r", encoding="utf-8") as pf:
      raw_loaded = json.load(pf)

  if isinstance(raw_loaded, dict):
    findings = raw_loaded.get("findings", [])
  elif isinstance(raw_loaded, list):
    findings = raw_loaded
  else:
    findings = []

  cm_env = get_scrubbed_env(repo_dir=workspace_dir)
  log_cm_environment(cm_env, sandbox_enabled)
  sandbox_flags = [] if sandbox_enabled else ["--unrestricted"]
  existing_inline_urls: dict[str, str] = {}
  verify_re = re.compile(
      r"#\s*codemender:\s*verify=(?:FALSE[_-]POSITIVE|DISMISSED)",
      re.IGNORECASE,
  )

  with sandbox_workspace_access(workspace_dir, sandbox_enabled):
    for finding in findings:
      _verify_and_fix_one_finding(
          finding=finding,
          workspace_dir=workspace_dir,
          worker_index=worker_index,
          cm_env=cm_env,
          sandbox_enabled=sandbox_enabled,
          sandbox_flags=sandbox_flags,
          allow_unsandboxed_fallback=allow_unsandboxed_fallback,
          skip_exploit_verification=skip_exploit_verification,
          verify_model=verify_model,
          fix_model=fix_model,
          verify_re=verify_re,
          existing_inline_urls=existing_inline_urls,
          min_sev=min_sev,
          token=token,
          owner=owner,
          repo=repo,
          pr_number=pr_number,
          target_sha=target_sha,
          fail_on_findings=fail_on_findings,
      )

  with open(results_file, "w", encoding="utf-8") as rf:
    json.dump(findings, rf, indent=2)
  return findings


def _verify_and_fix_one_finding(
    *,
    finding: dict,
    workspace_dir: str,
    worker_index: int,
    cm_env: dict[str, str],
    sandbox_enabled: bool,
    sandbox_flags: list[str],
    allow_unsandboxed_fallback: bool,
    skip_exploit_verification: bool,
    verify_model: str,
    fix_model: str,
    verify_re: "re.Pattern[str]",
    existing_inline_urls: dict[str, str],
    min_sev: str,
    token: str,
    owner: str,
    repo: str,
    pr_number: int,
    target_sha: str,
    fail_on_findings: Optional[bool],
) -> None:
  """Runs Stage 2.1-2.3 for one finding and records the outcome on `finding`."""
  import subprocess
  from codemender_agent.runners.scan import run_cm_with_sandbox_fallback
  from codemender_agent.vcs.git import find_source_pragma
  from codemender_agent.vcs.github import (
      extract_finding_fields,
      post_idempotent_inline_review,
      update_finding_in_sticky_comment,
  )

  fields = extract_finding_fields(finding, repo_dir=workspace_dir)
  fid = fields["finding_id"]
  if not fid:
    return

  # Stage 2.1: Exploit Verification (cm verify)
  update_finding_in_sticky_comment(
      token=token,
      owner=owner,
      repo=repo,
      pr_number=pr_number,
      finding=finding,
      status_cell_md="⏳ **Verifying (`cm verify`)...**",
      min_sev=min_sev,
      fail_on_findings=fail_on_findings,
  )
  v_cmd = ["cm", "verify", fid, "--yes", "--bypass-warning", *sandbox_flags]
  if skip_exploit_verification:
    v_cmd.append("--skip-exploit-verification")
  if verify_model:
    v_cmd.extend(["--model", verify_model])

  print(f"=== [Worker {worker_index}] Running cm verify for {fid} ===", flush=True)
  v_res = run_cm_with_sandbox_fallback(
      v_cmd,
      workspace_dir=workspace_dir,
      cm_env=cm_env,
      sandbox_enabled=sandbox_enabled,
      print_output=True,
      allow_unsandboxed_fallback=allow_unsandboxed_fallback,
  )
  v_lower = v_res.output
  if v_res.unrestricted_rerun:
    finding["sandbox_unrestricted_rerun"] = True

  subprocess.run(
      ["git", "checkout", "HEAD", "--", "."], cwd=workspace_dir, check=False
  )

  # A session that never ran (sandbox unavailable) has no verdict to parse.
  sandbox_blocked = v_res.sandbox_failed and not v_res.unrestricted_rerun
  is_dismissed_fp = (not sandbox_blocked) and _is_false_positive_verdict(
      v_lower
  )

  if not is_dismissed_fp and not sandbox_blocked:
    rep_check = subprocess.run(
        ["cm", "report", "--format", "json", "--bypass-warning"],
        cwd=workspace_dir,
        env=cm_env,
        capture_output=True,
        text=True,
        check=False,
    )
    if rep_check.stdout and rep_check.stdout.strip():
      for r_item in parse_findings_json(rep_check.stdout):
        r_id = extract_finding_fields(r_item)["finding_id"]
        if r_id == fid or (fid and r_id.startswith(fid[:8])):
          r_stat = " ".join(
              str(r_item.get(k) or "")
              for k in (
                  "status",
                  "Status",
                  "verification_status",
                  "state",
                  "verdict",
              )
          )
          if _is_false_positive_verdict(r_stat):
            is_dismissed_fp = True

  if not is_dismissed_fp:
    if find_source_pragma(
        workspace_dir=workspace_dir,
        relpath=fields["file_path"],
        start_line=fields["line_number"],
        end_line=fields["end_line"],
        pattern=verify_re,
    ):
      is_dismissed_fp = True

  if is_dismissed_fp:
    finding["verified_status"] = "DISMISSED_FALSE_POSITIVE"
    update_finding_in_sticky_comment(
        token=token,
        owner=owner,
        repo=repo,
        pr_number=pr_number,
        finding=finding,
        status_cell_md="⚪ **Dismissed (False Positive)**",
        min_sev=min_sev,
        fail_on_findings=fail_on_findings,
    )
    finding["patch_diff"] = ""
    finding["review_url"] = ""
    return

  if sandbox_blocked:
    # Fail closed: the finding stays (and blocks, if its severity does), but
    # it is not shown as confirmed and no fix is attempted.
    finding["verified_status"] = VERIFY_FAILED
    finding["verify_failure_reason"] = "sandbox_unavailable"
    finding["patch_diff"] = ""
    finding["review_url"] = ""
    update_finding_in_sticky_comment(
        token=token,
        owner=owner,
        repo=repo,
        pr_number=pr_number,
        finding=finding,
        status_cell_md=(
            "⚠️ **Unverified** (`cm verify` did not run: sandbox"
            " unavailable)"
        ),
        min_sev=min_sev,
        fail_on_findings=fail_on_findings,
    )
    return

  if v_res.proc.returncode != 0:
    # `cm verify` exited with an error (for example a session failure):
    # there is no verdict, so do not call the finding confirmed.
    finding["verified_status"] = VERIFY_FAILED
    finding["verify_failure_reason"] = f"cm verify exit {v_res.proc.returncode}"
    fixing_md = "🔨 **Generating Fix (`cm fix`)...** (unverified)"
  else:
    finding["verified_status"] = "CONFIRMED"
    fixing_md = "🔨 **Generating Fix (`cm fix`)...**"
  update_finding_in_sticky_comment(
      token=token,
      owner=owner,
      repo=repo,
      pr_number=pr_number,
      finding=finding,
      status_cell_md=fixing_md,
      min_sev=min_sev,
      fail_on_findings=fail_on_findings,
  )

  # Stage 2.2: Patch Synthesis (cm fix)
  f_cmd = ["cm", "fix", fid, "--yes", "--bypass-warning", *sandbox_flags]
  if fix_model:
    f_cmd.extend(["--model", fix_model])
  print(f"=== [Worker {worker_index}] Running cm fix for {fid} ===", flush=True)
  f_res = run_cm_with_sandbox_fallback(
      f_cmd,
      workspace_dir=workspace_dir,
      cm_env=cm_env,
      sandbox_enabled=sandbox_enabled,
      print_output=True,
      allow_unsandboxed_fallback=allow_unsandboxed_fallback,
  )
  if f_res.unrestricted_rerun:
    finding["sandbox_unrestricted_rerun"] = True

  if f_res.sandbox_failed and not f_res.unrestricted_rerun:
    # `cm fix` never ran (sandbox unavailable, fallback not allowed). Do not
    # look for a patch: the state.db fallback below can return another
    # finding's patch.
    subprocess.run(
        ["git", "checkout", "HEAD", "--", "."], cwd=workspace_dir, check=False
    )
    finding["patch_diff"] = ""
    finding["review_url"] = ""
    finding["fix_failure_reason"] = "sandbox_unavailable"
    status_md = (
        "⚠️ **No fix** (`cm fix` did not run: sandbox unavailable)"
    )
    if finding.get("verified_status") == VERIFY_FAILED:
      status_md = "⚠️ **Unverified** (`cm verify` failed) — " + status_md
    update_finding_in_sticky_comment(
        token=token,
        owner=owner,
        repo=repo,
        pr_number=pr_number,
        finding=finding,
        status_cell_md=status_md,
        min_sev=min_sev,
        fail_on_findings=fail_on_findings,
    )
    return

  # Tier 1: git diff
  diff_res = subprocess.run(
      ["git", "diff"], cwd=workspace_dir, capture_output=True, text=True, check=False
  )
  patch_diff = (diff_res.stdout or "").strip()

  # Tier 2: cm report --format json fallback
  if not patch_diff:
    rep_fix = subprocess.run(
        ["cm", "report", "--format", "json", "--bypass-warning"],
        cwd=workspace_dir,
        env=cm_env,
        capture_output=True,
        text=True,
        check=False,
    )
    if rep_fix.stdout and rep_fix.stdout.strip():
      for r_item in parse_findings_json(rep_fix.stdout):
        r_id = extract_finding_fields(r_item)["finding_id"]
        if r_id == fid or (fid and r_id.startswith(fid[:8])):
          for k in (
              "patch",
              "diff",
              "patch_diff",
              "fix_diff",
              "suggested_fix",
          ):
            cand = str(r_item.get(k) or "").strip()
            if cand and ("---" in cand or "@@" in cand or "+" in cand):
              patch_diff = cand
              break

  # Tier 3: Dynamic SQLite state.db inspection across candidate tables/columns
  if not patch_diff:
    db_path = os.path.expanduser("~/.codemender/state.db")
    if os.path.exists(db_path):
      try:
        with closing(sqlite3.connect(db_path)) as conn:
          tables = [
              r[0]
              for r in conn.execute(
                  "SELECT name FROM sqlite_master WHERE type='table'"
              ).fetchall()
          ]
          for tbl in ("patches", "fixes", "remediations", "findings"):
            if tbl not in tables:
              continue
            cols = [
                r[1]
                for r in conn.execute(f"PRAGMA table_info({tbl})").fetchall()
            ]
            for dcol in (
                "diff",
                "patch",
                "patch_diff",
                "unified_diff",
                "fix_diff",
                "content",
            ):
              if dcol not in cols:
                continue
              if "finding_id" in cols:
                row = conn.execute(
                    f"SELECT {dcol} FROM {tbl} WHERE finding_id = ? AND"
                    f" {dcol} IS NOT NULL AND {dcol} != '' ORDER BY rowid"
                    " DESC LIMIT 1",
                    (fid,),
                ).fetchone()
              else:
                row = conn.execute(
                    f"SELECT {dcol} FROM {tbl} WHERE {dcol} IS NOT NULL AND"
                    f" {dcol} != '' ORDER BY rowid DESC LIMIT 1"
                ).fetchone()
              if row and row[0]:
                patch_diff = str(row[0]).strip()
                break
            if patch_diff:
              break
      except Exception:  # pylint: disable=broad-exception-caught
        pass

  subprocess.run(
      ["git", "checkout", "HEAD", "--", "."], cwd=workspace_dir, check=False
  )
  finding["patch_diff"] = patch_diff

  # Stage 2.3: Post Idempotent Inline PR Review Suggestions
  review_url = post_idempotent_inline_review(
      token=token,
      owner=owner,
      repo=repo,
      pr_number=pr_number,
      target_sha=target_sha,
      finding=finding,
      patch_diff=patch_diff,
      existing_inline_urls=existing_inline_urls,
      repo_dir=workspace_dir,
  )
  finding["review_url"] = review_url
  if patch_diff:
    link_md = (
        f"[Inline `Commit suggestion` posted]({review_url})"
        if review_url
        else "see inline `Commit suggestion` / diff below"
    )
    final_status_md = f"✅ **Patch Ready** ({link_md})"
  else:
    final_status_md = "⚠️ **Manual remediation required**"
  if finding.get("verified_status") == VERIFY_FAILED:
    final_status_md = (
        "⚠️ **Unverified** (`cm verify` failed) — " + final_status_md
    )
  if finding.get("sandbox_unrestricted_rerun"):
    final_status_md += " — ⚠️ ran without the sandbox"

  update_finding_in_sticky_comment(
      token=token,
      owner=owner,
      repo=repo,
      pr_number=pr_number,
      finding=finding,
      status_cell_md=final_status_md,
      min_sev=min_sev,
      fail_on_findings=fail_on_findings,
  )
