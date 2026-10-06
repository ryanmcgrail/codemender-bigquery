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

"""Stage 1: Scan & Dispatch runner for CodeMender Agent."""

import contextlib
import dataclasses
import json
import logging
import os
import shutil
import sqlite3
import sys
import tarfile
import time
from typing import Optional
import uuid

# CodeMender CLI JSON parser, version logging, and binary auto-update helpers
from codemender_agent.codemender.cli import ensure_cm_updated
from codemender_agent.codemender.cli import get_cm_default_model
from codemender_agent.codemender.cli import is_ci_gate_exit
from codemender_agent.codemender.cli import is_closed_finding_status
from codemender_agent.codemender.cli import log_cm_version
from codemender_agent.codemender.cli import parse_deep_scan_summary
from codemender_agent.codemender.cli import parse_findings_json
from codemender_agent.codemender.cli import stage_cm_binary_for_archive
from codemender_agent.runners.aggregate import _build_automation_details_id
from codemender_agent.runners.aggregate import _record_failure_marker
from codemender_agent.runners.aggregate import has_sarif_results
from codemender_agent.runners.aggregate import transform_json_to_sarif
# Configuration injection and credentials
from codemender_agent.config import OrchestratorConfig
from codemender_agent.config import call_with_github_token
from codemender_agent.config import get_github_credentials
from codemender_agent.config import get_scrubbed_env
from codemender_agent.config import github_app_configured
from codemender_agent.config import inject_codemender_config
from codemender_agent.config import is_presubmit_pipeline
from codemender_agent.config import read_default_branch
from codemender_agent.config import refresh_github_token
# Storage signed URL and upload utilities
from codemender_agent.storage import generate_signed_url
from codemender_agent.storage import upload_file_to_gcs
# BigQuery analytics telemetry (hard no-op unless CODEMENDER_BQ_DATASET is set)
from codemender_agent.telemetry import bigquery as bq_telemetry
from codemender_agent.utils import accumulate_model_token_usage
from codemender_agent.utils import build_cm_command
from codemender_agent.utils import render_token_usage_markdown
from codemender_agent.utils import resolve_command_model
from codemender_agent.utils import run_command
# Git branch derivation and diff hunk utilities
from codemender_agent.vcs.git import configure_git_identity
from codemender_agent.vcs.git import get_finding_branch_name
from codemender_agent.vcs.git import get_git_auth_header
from codemender_agent.vcs.git import get_pr_changed_lines
from codemender_agent.vcs.git import normalize_repo_relative_path
from codemender_agent.vcs.git import parse_repo_owner_and_name
from codemender_agent.vcs.git import sanitize_git_url
from codemender_agent.vcs.git import setup_local_git_excludes
# GitHub REST API check and deduplication helpers
from codemender_agent.vcs.github import STATUS_CONTEXT_PR
from codemender_agent.vcs.github import STATUS_CONTEXT_SCHEDULED
from codemender_agent.vcs.github import check_remote_branch_exists
from codemender_agent.vcs.github import delete_remote_branch
from codemender_agent.vcs.github import get_default_branch
from codemender_agent.vcs.github import is_duplicate_pr
from codemender_agent.vcs.github import post_commit_status
from codemender_agent.vcs.github import post_or_update_sticky_comment
from codemender_agent.vcs.github import upload_sarif_to_code_scanning
# Opt-in Wiz SAST bridge (hard no-op unless enabled for this repository)
from codemender_agent.wiz.bridge import STATUS_NOT_ENABLED as WIZ_NOT_ENABLED
from codemender_agent.wiz.bridge import run_wiz_bridge
from codemender_agent.wiz.bridge import summary_line as wiz_summary_line
from codemender_agent.wiz.settings import WizBridgeSettings
from codemender_agent.wiz.settings import take_wiz_credentials

logger = logging.getLogger("codemender-orchestrator")


EXCLUDED_TAR_PATTERNS = {
    ".git",
    "__pycache__",
    ".venv",
    "node_modules",
    ".pytest_cache",
    ".codemender_cache",
}


def tar_filter(tarinfo: tarfile.TarInfo) -> Optional[tarfile.TarInfo]:
  """Filters out heavy/unnecessary metadata directories during workspace archiving."""
  base_name = os.path.basename(tarinfo.name)
  if base_name in EXCLUDED_TAR_PATTERNS or tarinfo.name.endswith(".pyc"):
    return None
  return tarinfo


def make_tarfile(output_filename: str, source_dir: str) -> None:
  """Creates a tar.gz archive of a directory excluding heavy cache/VCS paths."""
  with tarfile.open(output_filename, "w:gz") as tar:
    tar.add(source_dir, arcname=os.path.basename(source_dir), filter=tar_filter)


def _emit_github_output(
    outputs: dict[str, str],
    config: Optional[OrchestratorConfig] = None,
) -> None:
  """Emits outputs to GITHUB_OUTPUT environment file if running in GitHub Actions."""
  # 1. Resolve active GITHUB_OUTPUT environment file path
  cfg = config or OrchestratorConfig.from_env()
  output_file = cfg.github_output or os.environ.get("GITHUB_OUTPUT")
  if output_file:
    try:
      # 2. Append key-value pairs to the environment file
      with open(output_file, "a", encoding="utf-8") as f:
        for k, v in outputs.items():
          f.write(f"{k}={v}\n")
      logger.info("Successfully emitted GITHUB_OUTPUT: %s", outputs)
    except Exception as e:  # pylint: disable=broad-exception-caught
      # Log warning if writing to output file fails
      logger.warning("Failed to write to GITHUB_OUTPUT: %s", e)


def _write_clean_sarif_file(
    repo_dir: Optional[str],
    workspace_dir: str,
    repository: str = "",
    scan_target: str = "",
) -> str:
  """Generates a valid empty SARIF report when zero findings are discovered."""
  automation_id = _build_automation_details_id(
      repository=repository, scan_target=scan_target
  )
  clean_sarif = {
      "$schema": (
          "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
      ),
      "version": "2.1.0",
      "runs": [
          {
              "automationDetails": {
                  "id": automation_id,
              },
              "tool": {
                  "driver": {
                      "name": "CodeMender",
                      "semanticVersion": "1.0.0",
                      "rules": [],
                  }
              },
              "results": [],
          }
      ],
  }
  content = json.dumps(clean_sarif, indent=2)
  # Write clean SARIF to both repo_dir and workspace_dir for workflow actions
  for dest_dir in [repo_dir, workspace_dir]:
    if dest_dir and os.path.exists(dest_dir):
      sarif_path = os.path.join(dest_dir, "report.sarif")
      try:
        with open(sarif_path, "w", encoding="utf-8") as f:
          f.write(content)
        logger.info("Wrote clean SARIF report to %s", sarif_path)
      except Exception as e:  # pylint: disable=broad-exception-caught
        logger.warning(
            "Failed to write clean SARIF report to %s: %s", sarif_path, e
        )
  return os.path.join(workspace_dir, "report.sarif")


def _render_zero_findings_summary(
    owner: str,
    repo_name: str,
    target_sha: str,
    is_pr_scan: bool,
    config: Optional[OrchestratorConfig] = None,
    filtered_reasons: Optional[str] = None,
    token_totals: Optional[dict[str, dict[str, int]]] = None,
    wiz_note: Optional[str] = None,
) -> str:
  """Renders a reassuring Step Summary when zero findings are detected or all are ignored.

  The summary is always rendered and returned, so PR scans can mirror it into
  the sticky PR comment; it is appended to GITHUB_STEP_SUMMARY only when a
  summary file is configured.
  """
  cfg = config or OrchestratorConfig.from_env()
  summary_file = cfg.github_step_summary or os.environ.get("GITHUB_STEP_SUMMARY")

  mode_desc = (
      "Pull Request Scan (Clean as You Code)"
      if is_pr_scan
      else "Nightly Repository Scan"
  )
  commit_desc = target_sha[:8] if target_sha else "HEAD"
  reason_note = (
      f"\n- **Note:** {filtered_reasons}"
      if filtered_reasons and not is_pr_scan
      else ""
  )
  gate_section = (
      "\n- **Security Gate:** ✅ **PASSED (Clean as You Code)**\n\n"
      "> [!NOTE]\n"
      "> **Security Gate Status: PASSED**\n"
      "> \n"
      "> No new actionable security vulnerabilities detected in the pull request diff."
      if is_pr_scan
      else ""
  )

  token_md = render_token_usage_markdown(token_totals)
  token_section = f"\n{token_md}" if token_md else ""
  wiz_line = f"\n- **Wiz SAST:** {wiz_note}" if wiz_note else ""

  summary_md = f"""# 🛡️ CodeMender Security Remediation Summary

- **Repository:** `{owner}/{repo_name}`
- **Target Commit:** `{commit_desc}`
- **Execution Mode:** `{mode_desc}`{reason_note}{wiz_line}{gate_section}

### 📊 Remediation Overview

| Total Discovered | Remediated (Fixed) | Verified (Exploitable) | Pre-Existing Ignored | Skipped Duplicates | Other / Unfixed |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 0 | 0 | 0 | 0 | 0 | 0 |

🎉 **No actionable security vulnerabilities detected.**
{token_section}"""
  if summary_file:
    try:
      with open(summary_file, "a", encoding="utf-8") as f:
        f.write(summary_md + "\n")
      logger.info("Wrote Zero-Findings Step Summary to %s", summary_file)
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.warning("Failed to write to GITHUB_STEP_SUMMARY (%s): %s", summary_file, e)
  return summary_md


def _post_zero_findings_pr_gate(
    config: OrchestratorConfig,
    token: Optional[str],
    owner: str,
    repo_name: str,
    target_sha: Optional[str],
    summary_md: Optional[str],
) -> None:
  """Passes the PR Security Gate and updates the sticky summary on a zero-finding PR scan.

  Stage 1 exits before Stage 3 when a PR scan has no active findings, so Stage
  3 never posts the gate status. Without this, a required
  "CodeMender / Security Gate" check stays pending and blocks the PR.
  """
  if not config.is_pr_scan:
    return
  target_commit_sha = config.target_sha or target_sha
  if target_commit_sha and token:
    logger.info(
        "✅ CodeMender Security Gate PASSED: Clean as You Code. Emitting '%s' commit status check.",
        STATUS_CONTEXT_PR,
    )
    post_commit_status(
        token=token,
        owner=owner,
        repo=repo_name,
        sha=target_commit_sha,
        state="success",
        description="Security Gate PASSED: Clean as You Code (0 active vulnerabilities).",
        context=STATUS_CONTEXT_PR,
        target_url=config.execution_url or None,
    )
  if config.pr_number and token and summary_md:
    post_or_update_sticky_comment(
        token=token,
        owner=owner,
        repo=repo_name,
        pr_number=config.pr_number,
        body=summary_md,
    )


def _sync_repository(
    repo_url: str,
    token: str,
    repo_dir: str,
    workspace_dir: str,
    target_sha: Optional[str] = None,
    is_pr_scan: bool = False,
    pr_base_ref: Optional[str] = None,
) -> str:
  """Syncs the repository (clones if not exists, fetches and resets if exists).

  Returns:
    The target SHA of the repository after sync.
  """
  clean_repo_url = sanitize_git_url(repo_url)
  owner, repo_name = parse_repo_owner_and_name(clean_repo_url)

  logger.info("Syncing repository for scanning: %s", clean_repo_url)

  # 1. Fresh clone if repository directory does not already exist
  if not os.path.exists(os.path.join(repo_dir, ".git")):
    # Clean stale or non-git directory if present to prevent clone destination errors
    if os.path.exists(repo_dir):
      shutil.rmtree(repo_dir)

    # Configure git clone command with authorization header
    target_branch = (os.environ.get("CODEMENDER_TARGET_BRANCH") or "").strip()
    clone_cmd = [
        "git",
        "-c",
        get_git_auth_header(token),
        "clone",
    ]
    # In Nightly scans without target SHA use shallow clone depth=1; otherwise preserve full history
    if not is_pr_scan and not target_sha:
      clone_cmd.extend(["--depth", "1"])
      if target_branch:
        clone_cmd.extend(["--branch", target_branch])
    clone_cmd.extend([clean_repo_url, repo_dir])
    run_command(clone_cmd, cwd=workspace_dir)

    # In PR scans, fetch the target PR base reference branch from remote origin
    if is_pr_scan and pr_base_ref:
      fetch_base_cmd = [
          "git",
          "-c",
          get_git_auth_header(token),
          "fetch",
          "origin",
          pr_base_ref,
      ]
      run_command(fetch_base_cmd, cwd=repo_dir, check=False)
  else:
    # 2. Existing workspace: fetch latest branch state and reset working tree
    logger.info("Repository directory exists, fetching latest state...")
    target_branch = (os.environ.get("CODEMENDER_TARGET_BRANCH") or "").strip()
    try:
      curr_branch = target_branch or run_command(
          ["git", "branch", "--show-current"], cwd=repo_dir
      ).stdout.strip()
    except Exception:  # pylint: disable=broad-exception-caught
      curr_branch = ""
    if not curr_branch:
      curr_branch = get_default_branch(token, owner, repo_name)

    # Fetch latest commits from remote origin for current branch
    fetch_cmd = [
        "git",
        "-c",
        get_git_auth_header(token),
        "fetch",
        "origin",
        curr_branch,
    ]
    run_command(fetch_cmd, cwd=repo_dir, check=False)

    # In PR scans, ensure PR base reference branch is also fetched
    if is_pr_scan and pr_base_ref:
      fetch_base_cmd = [
          "git",
          "-c",
          get_git_auth_header(token),
          "fetch",
          "origin",
          pr_base_ref,
      ]
      run_command(fetch_base_cmd, cwd=repo_dir, check=False)

    if not is_pr_scan and not target_sha:
      # Force checkout and hard reset to clean up any untracked or modified artifacts
      run_command(["git", "checkout", "-f", curr_branch], cwd=repo_dir, check=False)
      run_command(
          ["git", "reset", "--hard", f"origin/{curr_branch}"], cwd=repo_dir, check=False
      )

  # 3. Checkout specific target commit SHA if requested, or determine default branch
  if target_sha:
    logger.info("Checking out explicit target SHA: %s", target_sha)
    fetch_target_cmd = [
        "git",
        "-c",
        get_git_auth_header(token),
        "fetch",
        "origin",
        target_sha,
    ]
    run_command(fetch_target_cmd, cwd=repo_dir, check=False)
    run_command(["git", "checkout", "-f", target_sha], cwd=repo_dir)
  elif not is_pr_scan:
    target_branch = (os.environ.get("CODEMENDER_TARGET_BRANCH") or "").strip()
    try:
      default_branch = target_branch or run_command(
          ["git", "branch", "--show-current"], cwd=repo_dir
      ).stdout.strip()
    except Exception:  # pylint: disable=broad-exception-caught
      default_branch = ""
    if not default_branch:
      default_branch = get_default_branch(token, owner, repo_name)

    logger.info("Using target/default branch: %s", default_branch)
    run_command(["git", "checkout", "-f", default_branch], cwd=repo_dir)

  # 4. Record and return the immutable target Git commit SHA
  target_sha_res = run_command(
      ["git", "rev-parse", "HEAD"], cwd=repo_dir
  ).stdout.strip()
  logger.info("Recorded target Git SHA: %s", target_sha_res)

  # 5. Configure local Git identity and exclusion patterns (.gitignore overrides)
  configure_git_identity(repo_dir, token, run=run_command)
  setup_local_git_excludes(repo_dir)

  return target_sha_res


def _init_codemender(
    repo_dir: str,
    scrubbed_env: dict[str, str],
    cm_binary: str,
    config: Optional[OrchestratorConfig] = None,
) -> None:
  """Initializes CodeMender CLI in the repository."""
  cfg = config or OrchestratorConfig.from_env()
  cli_version = cfg.cli_version
  logger.info("Initializing CodeMender CLI...")
  try:
    # 1. Run basic init to create .cm_project metadata
    init_cmd = build_cm_command(cm_binary, "init", cli_version=cli_version)
    run_command(
        init_cmd,
        cwd=repo_dir,
        env=scrubbed_env,
        check=True,
    )

    # 2. Inject repository and environment configs into ~/.codemender/config.yaml
    inject_codemender_config(repo_dir, config=cfg)

    # 3. Verify the initialization (validates build command in container environment)
    verify_init_cmd = build_cm_command(
        cm_binary, "init", extra_flags=["--verify"], cli_version=cli_version
    )
    run_command(
        verify_init_cmd,
        cwd=repo_dir,
        env=scrubbed_env,
        check=True,
    )

    # 4. Re-apply config injection so cm init --verify does not overwrite project_paths or sandbox settings
    inject_codemender_config(repo_dir, config=cfg)
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.critical("CodeMender initialization failed: %s", e)
    sys.exit(1)


def _scan_repository(
    repo_dir: str,
    scrubbed_env: dict[str, str],
    cm_binary: str,
    targets: list[str],
    config: Optional[OrchestratorConfig] = None,
    deep_summaries: Optional[list[dict[str, any]]] = None,
) -> tuple[list[dict[str, any]], dict[str, dict[str, int]]]:
  """Runs scan on targets with retries if no findings are found.

  Args:
    deep_summaries: When given, receives one parsed `cm find --deep` summary
      per target that ran in deep mode (files, failed files, total tokens).
  """
  cfg = config or OrchestratorConfig.from_env()
  cli_version = cfg.cli_version
  max_scan_attempts = int(os.environ.get("CODEMENDER_MAX_SCAN_ATTEMPTS", "1"))
  findings = []
  scan_token_usage: dict[str, dict[str, int]] = {}
  find_model = (
      cfg.find_model
      or resolve_command_model("find")
      or get_cm_default_model(cm_binary, env=scrubbed_env, cwd=repo_dir)
  )

  # Retry loop to account for transient cold-start, gRPC stream cancellation, or API rate-limit delays
  for attempt in range(1, max_scan_attempts + 1):
    logger.info("Running scan attempt %d/%d...", attempt, max_scan_attempts)
    had_find_error = False
    # 1. Execute 'cm find' (using native --diff when supported on PR scans, else target list)
    if (
        cfg.is_pr_scan
        and cfg.diff_scoped_pr_scan
        and cfg.pr_base_ref
        and cm_supports_diff_flag(repo_dir, scrubbed_env, cm_binary)
    ):
      scan_jobs = [(".", [f"--diff=origin/{cfg.pr_base_ref}", "--fail-on="])]
    else:
      scan_jobs = [(t, None) for t in targets]

    for target, extra_flags in scan_jobs:
      try:
        find_cmd = build_cm_command(
            cm_binary,
            "find",
            target,
            extra_flags=extra_flags,
            cli_version=cli_version,
        )
        res = run_command(
            find_cmd,
            cwd=repo_dir,
            env=scrubbed_env,
            check=False,
        )
        token_usage = getattr(res, "token_usage", None)
        if isinstance(token_usage, dict):
          accumulate_model_token_usage(
              scan_token_usage, find_model, token_usage
          )
        find_stdout = getattr(res, "stdout", "")
        if not isinstance(find_stdout, str):
          find_stdout = ""
        deep_summary = parse_deep_scan_summary(find_stdout)
        if deep_summary:
          logger.info("Deep scan summary for %s: %s", target, deep_summary)
          if deep_summary.get("failed"):
            logger.warning(
                "Deep scan could not analyse %d of %d batches for %s; their"
                " files were not scanned.",
                deep_summary["failed"],
                deep_summary["batches"],
                target,
            )
          if deep_summaries is not None:
            deep_summaries.append(
                {"target": target, "attempt": attempt, **deep_summary}
            )
        rc = getattr(res, "returncode", 0)
        if isinstance(rc, int) and is_ci_gate_exit(rc, find_stdout):
          logger.info(
              "cm find exited 1 for target %s because its CI gate matched"
              " blocking findings; treating this as findings present, not as"
              " a failed scan.",
              target,
          )
        elif isinstance(rc, int) and rc != 0:
          had_find_error = True
          logger.warning(
              "cm find returned non-zero exit code (%d) for target %s on attempt %d; checking state.db via cm report for incrementally saved findings...",
              rc,
              target,
              attempt,
          )
      except Exception as e:  # pylint: disable=broad-exception-caught
        had_find_error = True
        logger.warning(
            "Scan subprocess raised exception for target %s on attempt %d (%s); checking state.db via cm report...",
            target,
            attempt,
            e,
        )

    # 2. Retrieve structured vulnerability findings report in JSON format (cm find saves findings incrementally to state.db)
    try:
      # Construct 'cm report' command to export discovered findings as JSON
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
      # Parse stdout JSON into structured Python dictionary list
      findings = parse_findings_json(report_res.stdout)
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.error("Failed to get report: %s", e)
      findings = []

    # 3. Exit retry loop early if findings were discovered or if scan completed cleanly with 0 findings
    if findings:
      logger.info("Found %d findings on attempt %d.", len(findings), attempt)
      break
    elif not had_find_error:
      logger.info("Scan completed cleanly with 0 findings on attempt %d.", attempt)
      break
    else:
      # Log retry status and delay before next attempt
      logger.warning(
          "No findings recovered after non-zero cm find exit on attempt %d/%d.",
          attempt,
          max_scan_attempts,
      )
      if attempt < max_scan_attempts:
        time.sleep(5)
      else:
        logger.error("All %d scan attempts failed with errors and 0 recovered findings.", max_scan_attempts)
        sys.exit(1)

  return findings, scan_token_usage


def _find_remote_duplicate(
    clean_repo_url: str,
    token: str,
    repo_dir: str,
    finding_id: str,
    branch_name: str,
    file_path: str,
    vuln_type: str,
    start_line: int,
) -> any:
  """Returns the open PR (URL or True) already covering a finding, else False.

  A remote fix branch without an open PR is a dead branch and is pruned so the
  finding can be remediated afresh.

  Raises:
    GitHubUnauthorizedError: GitHub rejected the token.
  """
  if check_remote_branch_exists(clean_repo_url, token, branch_name, cwd=repo_dir):
    has_active_pr = is_duplicate_pr(
        clean_repo_url,
        token,
        file_path,
        vuln_type,
        start_line,
        head_branch=branch_name,
    )
    if has_active_pr:
      logger.info(
          "Skipping finding %s as active PR exists for branch %s.",
          finding_id,
          branch_name,
      )
      return has_active_pr
    logger.info(
        "Dead branch detected: %s exists on remote but has no active open PR."
        " Pruning dead branch to allow fresh remediation.",
        branch_name,
    )
    delete_remote_branch(clean_repo_url, token, branch_name, cwd=repo_dir)
    return False

  dup_pr = is_duplicate_pr(
      clean_repo_url,
      token,
      file_path,
      vuln_type,
      start_line,
      head_branch=branch_name,
  )
  if dup_pr:
    logger.info(
        "An open PR covering %s in %s near line %d already exists. Skipping"
        " finding %s.",
        vuln_type,
        file_path,
        start_line,
        finding_id,
    )
  return dup_pr


def _filter_findings(
    findings: list[dict[str, any]],
    repo_url: str,
    token: str,
    repo_dir: str,
    force_overwrite: bool,
    is_pr_scan: bool = False,
    pr_base_ref: Optional[str] = None,
    dry_run: bool = False,
    config: Optional[OrchestratorConfig] = None,
) -> tuple[list[dict[str, any]], list[str], list[str]]:
  """Filters findings against PR modified hunks (if PR scan) and remote duplicates.

  A dry run skips the remote duplicate checks (and never prunes a dead remote
  branch), so every run against the same commit keeps the same findings.

  With `config`, the GitHub token is re-read before each finding's remote
  checks (a GitHub App token is re-minted when close to expiry), and a token
  GitHub rejects with 401 is replaced once. A second rejection raises
  `GitHubUnauthorizedError` rather than guessing that no duplicate exists.
  """
  active_findings = []
  skipped_finding_ids = []
  ignored_finding_ids = []
  clean_repo_url = sanitize_git_url(repo_url)

  changed_lines = None
  if is_pr_scan and pr_base_ref:
    changed_lines = get_pr_changed_lines(repo_dir, pr_base_ref)
    if changed_lines is None:
      logger.warning(
          "PR Diff Hunk Analysis: git diff failed across all candidate targets for base ref '%s'."
          " Failing-open: retaining all findings without differential hunk suppression.",
          pr_base_ref,
      )
    else:
      logger.info(
          "PR Diff Hunk Analysis: Extracted modified lines across %d files from"
          " origin/%s...HEAD",
          len(changed_lines),
          pr_base_ref,
      )

  for finding in findings:
    finding_id = finding.get("FindingID")
    if not finding_id:
      logger.warning(
          "Finding record missing 'FindingID' (available keys: %s). Skipping."
          " This may indicate an upstream `cm report --format json` schema"
          " change.",
          sorted(finding.keys()),
      )
      continue
    # Only process findings that are still open: never send FIXED, DISMISSED
    # (for example rejected by verification) or false-positive findings to
    # the fix workers.
    status = finding.get("Status")
    if is_closed_finding_status(status):
      logger.info(
          "Skipping finding %s because its status is %s.", finding_id, status
      )
      continue

    file_path = normalize_repo_relative_path(
        finding.get("FilePath") or "unknown_file", repo_dir=repo_dir
    )
    try:
      start_line = int(finding.get("StartLine") or 0)
    except ValueError:
      start_line = 0
    try:
      end_line = int(finding.get("EndLine") or start_line)
    except ValueError:
      end_line = start_line

    # 1. PR Scoped Filtering: Differential check against changed hunks
    if is_pr_scan and pr_base_ref and changed_lines is not None:
      file_changed_lines = changed_lines.get(file_path, set())
      # Evaluate line ranges against PR modified hunks (start_line <= 0 falls back to {0})
      finding_lines = (
          set(range(start_line, max(start_line, end_line) + 1))
          if start_line > 0
          else {0}
      )
      intersection = file_changed_lines & finding_lines
      if not intersection:
        logger.info(
            "PR Differential Scan: Finding %s in %s (lines %d-%d) is"
            " pre-existing legacy debt (not modified in PR). Marking"
            " PRE_EXISTING_IGNORED.",
            finding_id,
            file_path,
            start_line,
            end_line,
        )
        finding["Status"] = "PRE_EXISTING_IGNORED"
        finding["status"] = "PRE_EXISTING_IGNORED"
        ignored_finding_ids.append(finding_id)
        continue
      else:
        logger.info(
            "PR Differential Scan: Finding %s in %s (lines %d-%d) matches PR modified lines %s. Retaining as active.",
            finding_id,
            file_path,
            start_line,
            end_line,
            sorted(intersection),
        )

    # 2. Universal Deduplication: Check if remote branch or PR already exists
    vuln_type = finding.get("VulnType") or "vulnerability"
    branch_name = get_finding_branch_name(file_path, vuln_type, start_line)

    check_remote = not force_overwrite and not dry_run
    if check_remote:
      def find_duplicate(tok: str) -> any:
        return _find_remote_duplicate(
            clean_repo_url,
            tok,
            repo_dir,
            finding_id,
            branch_name,
            file_path,
            vuln_type,
            start_line,
        )

      if config is not None:
        token = refresh_github_token(config, token)
        dup_pr, token = call_with_github_token(config, token, find_duplicate)
      else:
        dup_pr = find_duplicate(token)
      if dup_pr:
        finding["Status"] = "SKIPPED_DUPLICATE"
        finding["status"] = "SKIPPED_DUPLICATE"
        if isinstance(dup_pr, str) and dup_pr.startswith("http"):
          finding["pr_url"] = dup_pr
        skipped_finding_ids.append(finding_id)
        continue

    # Log active finding retained for Stage 2 remediation
    logger.info(
        "Retaining finding %s (%s in %s near line %d) for remediation.",
        finding_id,
        vuln_type,
        file_path,
        start_line,
    )
    active_findings.append(finding)

  return active_findings, skipped_finding_ids, ignored_finding_ids


def _filtered_findings_for_telemetry(
    findings: list[dict[str, any]],
    skipped_finding_ids: list[str],
    ignored_finding_ids: list[str],
    state_db_path: str,
) -> list[dict[str, any]]:
  """Finding snapshot for telemetry when Stage 1 filtered out every finding.

  Stage 3 never runs on this path, so this is the only chance to record the
  findings. The snapshot comes from state.db, the same source Stage 3 uses.
  The filtered status is applied on top of it, because the state.db update is
  best effort, and a filtered finding missing from state.db is rebuilt from
  its `cm report` entry so it is still counted.
  """
  filtered_status = {str(fid): "SKIPPED_DUPLICATE" for fid in skipped_finding_ids}
  filtered_status.update(
      {str(fid): "PRE_EXISTING_IGNORED" for fid in ignored_finding_ids}
  )
  snapshot = bq_telemetry.snapshot_state_db_findings(state_db_path)
  seen = set()
  for row in snapshot:
    finding_id = str(row.get("finding_id") or "")
    seen.add(finding_id)
    if finding_id in filtered_status:
      row["status"] = filtered_status[finding_id]
  for finding in findings:
    if not isinstance(finding, dict):
      continue
    finding_id = str(finding.get("FindingID") or finding.get("finding_id") or "")
    if finding_id not in filtered_status or finding_id in seen:
      continue
    seen.add(finding_id)
    snapshot.append({
        "finding_id": finding_id,
        "title": _report_field(finding, "Title", "title"),
        "vuln_type": _report_field(finding, "VulnType", "vuln_type"),
        "severity": _report_field(finding, "Severity", "severity"),
        "file_path": _report_field(finding, "FilePath", "file_path"),
        "start_line": _report_field(finding, "StartLine", "start_line"),
        "end_line": _report_field(finding, "EndLine", "end_line"),
        "status": filtered_status[finding_id],
    })
  return snapshot


def _report_field(finding: dict[str, any], camel: str, snake: str) -> any:
  """Reads a `cm report` field in either its CamelCase or snake_case spelling."""
  value = finding.get(camel)
  return value if value not in (None, "") else finding.get(snake)


def _partition_findings(
    active_findings: list[dict[str, any]],
    max_tasks: int,
) -> list[list[str]]:
  """Partitions active finding IDs into N worker buckets."""
  active_findings_count = len(active_findings)
  effective_max_tasks = max(1, max_tasks)
  num_workers = min(active_findings_count, effective_max_tasks, 10000)
  if num_workers <= 0:
    return []

  logger.info(
      "Partitioning %d active findings into %d workers (max_tasks=%d)",
      active_findings_count,
      num_workers,
      max_tasks,
  )

  # 1. Sort findings by FilePath to group same directory/file findings together
  sorted_findings = sorted(
      active_findings, key=lambda f: f.get("FilePath") or ""
  )
  sorted_ids = [f["FindingID"] for f in sorted_findings]

  # 2. Calculate even partition sizes across available workers
  base_size = active_findings_count // num_workers
  remainder = active_findings_count % num_workers
  sizes = [base_size + (1 if i < remainder else 0) for i in range(num_workers)]

  # 3. Chunk the sorted findings into worker partitions
  partitions = []
  start = 0
  for size in sizes:
    # Append slice to partitions list
    partitions.append(sorted_ids[start : start + size])
    start += size

  return partitions


FIND_CHECKPOINT_DIR = "checkpoint"


def _upload_find_checkpoint(
    findings: list[dict[str, any]],
    workspace_dir: str,
    bucket_name: str,
    scan_id: str,
    target_sha: Optional[str],
    scan_token_usage: dict[str, dict[str, int]],
    wiz_metadata: Optional[dict] = None,
    deep_summaries: Optional[list[dict]] = None,
) -> bool:
  """Saves the raw find results to GCS before Stage 1 talks to GitHub again.

  After `cm find`, which can run for hours, Stage 1 needs a freshly minted
  GitHub token for duplicate checks and statuses. If minting or a GitHub call
  fails there, the stage exits before the normal state upload. This writes
  the unfiltered findings and the scanner's state.db to
  `scans/<scan_id>/checkpoint/` first so the scan's results are not lost.

  Best effort: a failure is logged and never fails the scan. The normal
  manifest and workspace upload later in the stage is unchanged.

  Returns:
    True if every checkpoint file was uploaded.
  """
  prefix = f"scans/{scan_id}/{FIND_CHECKPOINT_DIR}"
  try:
    findings_path = os.path.join(workspace_dir, "find_checkpoint.json")
    with open(findings_path, "w", encoding="utf-8") as f:
      json.dump(
          {
              "scan_id": scan_id,
              "target_sha": target_sha,
              "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "findings_count": len(findings),
              "token_usage": scan_token_usage or {},
              "wiz": wiz_metadata or {},
              "deep_scan": deep_summaries or [],
              "findings": findings,
          },
          f,
          indent=2,
          default=str,
      )
    saved = upload_file_to_gcs(
        findings_path, bucket_name, f"{prefix}/findings.json"
    )
    state_db_path = os.path.expanduser("~/.codemender/state.db")
    if os.path.exists(state_db_path):
      saved = (
          upload_file_to_gcs(state_db_path, bucket_name, f"{prefix}/state.db")
          and saved
      )
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.warning("Could not save the find checkpoint (non-fatal): %s", e)
    return False
  if saved:
    logger.info(
        "Saved %d finding(s) to gs://%s/%s/ before the GitHub phase.",
        len(findings),
        bucket_name,
        prefix,
    )
  else:
    logger.warning(
        "Could not upload the find checkpoint to gs://%s/%s/ (non-fatal).",
        bucket_name,
        prefix,
    )
  return bool(saved)


def _save_and_upload_state(
    partitions: list[list[str]],
    active_findings_count: int,
    target_sha: str,
    workspace_dir: str,
    bucket_name: str,
    scan_id: str,
    scan_token_usage: dict[str, dict[str, int]],
    skipped_duplicate_count: int,
    config: Optional[OrchestratorConfig] = None,
    cm_binary: Optional[str] = None,
    finding_prs: Optional[dict[str, str]] = None,
    started_at: Optional[str] = None,
    wiz_metadata: Optional[dict] = None,
    deep_summaries: Optional[list[dict]] = None,
) -> None:
  """Saves partitions and manifest, generates signed URLs, and uploads to GCS."""
  # Resolve active configuration instance
  cfg = config or OrchestratorConfig.from_env()

  # 1. Construct scan metadata dictionary with token telemetry and finding counts
  scan_metadata = {
      "scan_id": scan_id,
      "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
      "token_usage": scan_token_usage,
      "total_findings_count": active_findings_count + skipped_duplicate_count,
      "active_findings_count": active_findings_count,
      "skipped_duplicate_count": skipped_duplicate_count,
      "finding_prs": finding_prs or {},
  }
  # Stage 1 start time, so the aggregator can report true end-to-end duration
  # rather than just its own stage runtime.
  if started_at:
    scan_metadata["started_at"] = started_at
  # Wiz bridge outcome, read by the aggregator for the report and telemetry.
  if wiz_metadata:
    scan_metadata["wiz"] = wiz_metadata
  # Per-target deep-scan summaries (only present for `cm find --deep`).
  if deep_summaries:
    scan_metadata["deep_scan"] = deep_summaries
  force_verify = set((wiz_metadata or {}).get("force_verify_ids") or [])
  scan_meta_path = os.path.join(workspace_dir, "scan_metadata.json")
  with open(scan_meta_path, "w", encoding="utf-8") as f:
    json.dump(scan_metadata, f, indent=2)

  # 2. Upload scan_metadata.json to GCS bucket
  if not upload_file_to_gcs(
      scan_meta_path, bucket_name, f"scans/{scan_id}/scan_metadata.json"
  ):
    logger.critical("Failed to upload scan_metadata.json to GCS.")
    sys.exit(1)

  # 3. Stage active cm binary into ~/.codemender/bin/cm and archive ~/.codemender state directory
  codemender_home = os.path.expanduser("~/.codemender")
  stage_cm_binary_for_archive(codemender_home, cm_binary=cm_binary)
  tarball_path = os.path.join(workspace_dir, "workspace_base.tar.gz")
  logger.info("Archiving ~/.codemender to %s", tarball_path)
  make_tarfile(tarball_path, codemender_home)

  # 4. Upload workspace_base.tar.gz archive to GCS
  if not upload_file_to_gcs(
      tarball_path, bucket_name, f"scans/{scan_id}/workspace_base.tar.gz"
  ):
    logger.critical("Failed to upload base workspace archive to GCS.")
    sys.exit(1)

  # 5. Generate GET Signed URL for workers to download the base workspace
  base_workspace_blob = f"scans/{scan_id}/workspace_base.tar.gz"
  base_workspace_url = generate_signed_url(
      bucket_name,
      base_workspace_blob,
      expiration_days=cfg.intermediate_retention_days,
      method="GET",
  )

  partition_urls = []
  upload_urls = []
  metadata_urls = []

  # 6. Save each worker partition slice, upload it, and generate signed URLs
  for i, part_ids in enumerate(partitions):
    partition_data = {"partition_index": i, "finding_ids": part_ids}
    # Imported findings in this partition must be verified by the worker even
    # when verification is otherwise skipped.
    part_force_verify = [fid for fid in part_ids if fid in force_verify]
    if part_force_verify:
      partition_data["force_verify_ids"] = part_force_verify
    part_path = os.path.join(workspace_dir, f"partition_{i}.json")
    with open(part_path, "w", encoding="utf-8") as f:
      json.dump(partition_data, f, indent=2)

    part_blob = f"scans/{scan_id}/partition_{i}.json"
    if not upload_file_to_gcs(part_path, bucket_name, part_blob):
      logger.critical("Failed to upload partition file to GCS.")
      sys.exit(1)

    # Generate Signed URL for workers to download their partition
    part_url = generate_signed_url(
        bucket_name,
        part_blob,
        expiration_days=cfg.intermediate_retention_days,
        method="GET",
    )
    if not part_url:
      logger.critical("Failed to generate GET signed URL for partition %d.", i)
      sys.exit(1)
    partition_urls.append(part_url)

    # Generate Signed URL for workers to upload their mutated DB shard
    worker_db_blob = f"scans/{scan_id}/worker_{i}_state.db"
    upload_url = generate_signed_url(
        bucket_name,
        worker_db_blob,
        expiration_days=cfg.intermediate_retention_days,
        method="PUT",
        content_type="application/octet-stream",
    )
    if not upload_url:
      logger.critical("Failed to generate PUT signed URL for worker %d.", i)
      sys.exit(1)
    upload_urls.append(upload_url)

    # Generate Signed URL for workers to upload their token usage metadata JSON
    worker_meta_blob = f"scans/{scan_id}/worker_{i}_metadata.json"
    meta_put_url = generate_signed_url(
        bucket_name,
        worker_meta_blob,
        expiration_days=cfg.intermediate_retention_days,
        method="PUT",
        content_type="application/json",
    )
    if not meta_put_url:
      logger.critical(
          "Failed to generate PUT signed URL for worker %d metadata.", i
      )
      sys.exit(1)
    metadata_urls.append(meta_put_url)

  # 7. Construct manifest with all Signed URLs and upload to GCS
  manifest = {
      "findings_count": active_findings_count,
      "target_sha": target_sha,
      "base_workspace_url": base_workspace_url,
      "partition_urls": partition_urls,
      "upload_urls": upload_urls,
      "metadata_urls": metadata_urls,
  }
  manifest_path = os.path.join(workspace_dir, "manifest.json")
  with open(manifest_path, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)
  if not upload_file_to_gcs(
      manifest_path, bucket_name, f"scans/{scan_id}/manifest.json"
  ):
    logger.critical("Failed to upload manifest.json to GCS.")
    sys.exit(1)

  # 8. Emit GitHub Actions matrix outputs for dynamic matrix orchestration
  matrix_json = (
      json.dumps(list(range(len(partitions)))) if partitions else "[0]"
  )
  _emit_github_output(
      {
          "matrix": matrix_json,
          "findings_count": str(active_findings_count),
          "target_sha": str(target_sha),
          "scan_id": str(scan_id),
      },
      config=cfg,
  )


def run_scan_pipeline() -> None:
  """Executes Stage 1: Scan repository, filter, partition, and upload state.

  The real work lives in `_run_scan_pipeline`; this wrapper exists purely so
  that every terminal path -- including the ten `sys.exit(1)` failure sites
  inside the body -- still produces exactly one `scan_runs` telemetry row.
  Placing the guard here rather than at each exit site keeps the failure
  accounting complete without scattering hooks through the pipeline.

  The guard re-raises whatever it caught, so exit codes are unchanged, and it
  is a hard no-op when telemetry is not configured.
  """
  if is_presubmit_pipeline():
    execute_stage1_presubmit_scan()
    return

  ctx = bq_telemetry.ScanRunContext(stage="scan")
  with bq_telemetry.telemetry_run_guard(ctx):
    try:
      _run_scan_pipeline(ctx)
    except BaseException as exc:
      is_clean_exit = isinstance(exc, SystemExit) and exc.code in (0, None)
      if not is_clean_exit:
        try:
          cfg = OrchestratorConfig.from_env()
          _record_failure_marker(
              cfg.workspace_dir or os.getcwd(),
              cfg.gcs_bucket,
              ctx.scan_id or cfg.scan_id,
              "scan",
              ctx.target_sha or cfg.target_sha,
          )
          if (ctx.target_sha or cfg.target_sha) and ctx.repository and "/" in ctx.repository:
            # A configured GitHub App always wins over a static token.
            token = None if github_app_configured(cfg) else cfg.github_token
            if not token:
              try:
                _, token = get_github_credentials(config=cfg)
              except Exception:  # pylint: disable=broad-exception-caught
                token = None
            if token:
              owner_part, repo_part = ctx.repository.split("/", 1)
              gate_ctx = (
                  STATUS_CONTEXT_PR
                  if cfg.is_pr_scan
                  else STATUS_CONTEXT_SCHEDULED
              )
              post_commit_status(
                  token=token,
                  owner=owner_part,
                  repo=repo_part,
                  sha=ctx.target_sha or cfg.target_sha,
                  state="error",
                  description="Scan failed during Stage 1.",
                  context=gate_ctx,
                  target_url=cfg.execution_url or None,
              )
        except Exception as status_err:  # pylint: disable=broad-exception-caught
          logger.warning("Failed to post Stage 1 error commit status: %s", status_err)
      raise


def _run_scan_pipeline(ctx: "bq_telemetry.ScanRunContext") -> None:
  """Stage 1 implementation. See `run_scan_pipeline` for the telemetry wrapper."""
  # Take the Wiz credentials out of the process environment before anything
  # can spawn a subprocess, so only wizcli itself can ever receive them.
  wiz_creds = take_wiz_credentials()
  wiz_settings = WizBridgeSettings.from_env()
  if not wiz_settings.enabled:
    ctx.wiz_status = WIZ_NOT_ENABLED
  config = OrchestratorConfig.from_env()
  scan_id = config.scan_id or f"scan_{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
  bucket_name = config.gcs_bucket

  # Seed telemetry context as early as possible so even an immediate
  # configuration failure below still produces an attributable FAILED row.
  ctx.apply_config(config)
  ctx.scan_id = scan_id

  # 1. Validate storage configuration when running in GCS mode
  if config.storage_mode == "gcs" and (not config.scan_id or not bucket_name):
    logger.critical(
        "CODEMENDER_SCAN_ID and CODEMENDER_GCS_BUCKET must be set when storage_mode is 'gcs'."
    )
    sys.exit(1)

  if not bucket_name:
    bucket_name = "default_bucket"

  # 2. Extract repository credentials and working directory paths
  repo_url, token = get_github_credentials(config=config)
  workspace_dir = config.workspace_dir or os.getcwd()
  clean_repo_url = sanitize_git_url(repo_url)
  owner, repo_name = parse_repo_owner_and_name(clean_repo_url)
  repo_dir = os.path.join(workspace_dir, repo_name)
  ctx.repository = f"{owner}/{repo_name}"
  ctx.repo_dir = repo_dir

  # 3. Synchronize repository and record the target commit SHA
  target_sha = _sync_repository(
      repo_url,
      token,
      repo_dir,
      workspace_dir,
      target_sha=config.target_sha,
      is_pr_scan=config.is_pr_scan,
      pr_base_ref=config.pr_base_ref,
  )
  ctx.target_sha = target_sha or ctx.target_sha

  if not config.is_pr_scan and target_sha and token:
    post_commit_status(
        token=token,
        owner=owner,
        repo=repo_name,
        sha=target_sha,
        state="pending",
        description="CodeMender scan in progress...",
        context=STATUS_CONTEXT_SCHEDULED,
        target_url=config.execution_url or None,
    )

  # 4. Initialize CodeMender CLI environment, self-update binary, and configure local cache paths
  scrubbed_env = get_scrubbed_env(repo_dir=repo_dir)
  cm_binary = ensure_cm_updated(
      shutil.which("cm") or "cm", env=scrubbed_env, cwd=repo_dir
  )
  # Capture the resolved version so analytics can correlate finding rates
  # against scanner upgrades.
  ctx.cm_version = log_cm_version(cm_binary, env=scrubbed_env, cwd=repo_dir)
  # The model columns have to name the model that actually ran. With no
  # override configured the scan uses the scanner's own built-in default, so
  # it is resolved here rather than left NULL -- otherwise every unoverridden
  # run, which is most of them, drops out of model comparisons entirely. The
  # lookup is cached and is repeated by the scan itself below, so this costs
  # nothing beyond the first call; it is still gated on telemetry being
  # configured so the failure-guard path stays cheap, and guarded so telemetry
  # can never be the thing that fails a scan.
  if bq_telemetry.telemetry_enabled():
    try:
      ctx.apply_default_model(
          get_cm_default_model(cm_binary, env=scrubbed_env, cwd=repo_dir)
      )
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.warning("Could not resolve the default model for telemetry: %s", e)
  _init_codemender(repo_dir, scrubbed_env, cm_binary, config=config)

  # 5. Parse scan targets (normalized to absolute paths to prevent sandbox mount errors)
  scan_target_env = config.scan_target
  targets = []
  for part in scan_target_env.split(";"):
    for subpart in part.split(","):
      t = subpart.strip()
      if t:
        abs_t = (
            t if os.path.isabs(t) else os.path.abspath(os.path.join(repo_dir, t))
        )
        targets.append(abs_t)
  if not targets:
    targets = [os.path.abspath(repo_dir)]

  # 6. Execute repository scan and accumulate token usage metrics
  deep_summaries: list[dict] = []
  findings, scan_token_usage = _scan_repository(
      repo_dir,
      scrubbed_env,
      cm_binary,
      targets,
      config=config,
      deep_summaries=deep_summaries,
  )

  # 6b. Opt-in Wiz SAST bridge: import eligible Wiz findings for mandatory
  #     verification. Never raises; a failure leaves CodeMender's own findings.
  wiz_result = run_wiz_bridge(
      settings=wiz_settings,
      creds=wiz_creds,
      repo_dir=repo_dir,
      cm_binary=cm_binary,
      cm_env=scrubbed_env,
      existing_findings=findings,
      cli_version=config.cli_version,
  )
  findings = wiz_result.findings
  wiz_metadata = wiz_result.to_metadata()
  ctx.apply_wiz(wiz_metadata)
  wiz_note = wiz_summary_line(wiz_metadata)

  # Save the find results before any GitHub call. Everything from here on
  # needs a GitHub token re-read after a scan that may have run for hours; if
  # that or a later GitHub call fails, the findings are still in GCS.
  checkpoint_saved = False
  if findings and config.storage_mode == "gcs":
    checkpoint_saved = _upload_find_checkpoint(
        findings,
        workspace_dir,
        bucket_name,
        scan_id,
        target_sha,
        scan_token_usage,
        wiz_metadata=wiz_metadata,
        deep_summaries=deep_summaries,
    )

  # The scan can run for hours, longer than a GitHub App installation token
  # lives. Re-read the token before the GitHub calls below; a static token is
  # returned unchanged.
  try:
    token = refresh_github_token(config, token)
  except Exception:
    if checkpoint_saved:
      saved_note = (
          f"The find results were saved to gs://{bucket_name}/scans/"
          f"{scan_id}/{FIND_CHECKPOINT_DIR}/."
      )
    elif findings:
      saved_note = "The find results could not be saved."
    else:
      saved_note = "The scan found nothing, so no results are lost."
    logger.critical(
        "Could not obtain a GitHub token after the scan. %s", saved_note
    )
    raise

  # 7. Handle case where repository scan returns zero findings
  if not findings:
    logger.info("Zero findings confirmed after scanning. Exiting Stage 1.")
    # Generate schema-compliant clean SARIF for GitHub Code Scanning alert resolution
    sarif_path = _write_clean_sarif_file(
        repo_dir,
        workspace_dir,
        repository=f"{owner}/{repo_name}",
        scan_target=config.scan_target,
    )
    # Render clean Step Summary before exiting
    summary_md = _render_zero_findings_summary(
        owner,
        repo_name,
        target_sha,
        config.is_pr_scan,
        config=config,
        token_totals=scan_token_usage,
        wiz_note=wiz_note,
    )
    # Stage 3 does not run, so pass the PR Security Gate here
    _post_zero_findings_pr_gate(
        config, token, owner, repo_name, target_sha, summary_md
    )
    # Build minimal manifest with findings_count = 0
    manifest = {"findings_count": 0, "target_sha": target_sha}
    manifest_path = os.path.join(workspace_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
      json.dump(manifest, f, indent=2)
    # Upload zero findings manifest and clean SARIF / token usage to transit storage
    upload_file_to_gcs(
        manifest_path, bucket_name, f"scans/{scan_id}/manifest.json"
    )
    if sarif_path and os.path.exists(sarif_path):
      upload_file_to_gcs(
          sarif_path, bucket_name, f"scans/{scan_id}/report.sarif"
      )
    token_usage_path = os.path.join(workspace_dir, "token_usage.json")
    try:
      with open(token_usage_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "scan_id": scan_id,
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "token_totals": scan_token_usage or {},
            },
            f,
            indent=2,
        )
      upload_file_to_gcs(
          token_usage_path, bucket_name, f"scans/{scan_id}/token_usage.json"
      )
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.warning("Failed to upload zero-findings token_usage.json: %s", e)
    # Emit zero findings output variables to GitHub Actions environment
    _emit_github_output(
        {
            "matrix": "[0]",
            "findings_count": "0",
            "target_sha": str(target_sha),
            "scan_id": str(scan_id),
        },
        config=config,
    )
    if not config.is_pr_scan and target_sha and token:
      post_commit_status(
          token=token,
          owner=owner,
          repo=repo_name,
          sha=target_sha,
          state="success",
          description="Scan complete: no active findings.",
          context=STATUS_CONTEXT_SCHEDULED,
          target_url=config.execution_url or None,
      )
      if sarif_path and os.path.exists(sarif_path):
        if has_sarif_results(sarif_path) or config.upload_empty_sarif:
          if config.target_branch:
            scan_ref = f"refs/heads/{config.target_branch}"
          else:
            default_br, token = read_default_branch(
                config, token, owner, repo_name, lookup=get_default_branch
            )
            scan_ref = f"refs/heads/{default_br}" if default_br else None
          if scan_ref:
            upload_sarif_to_code_scanning(
                token=token,
                owner=owner,
                repo=repo_name,
                sarif_path=sarif_path,
                commit_sha=target_sha,
                ref=scan_ref,
            )
          else:
            logger.error(
                "Not uploading report.sarif: the target branch is unknown."
            )
        else:
          logger.info(
              "Skipping GitHub Code Scanning SARIF upload because report.sarif contains 0 results "
              "(set CODEMENDER_UPLOAD_EMPTY_SARIF=true to auto-resolve existing alerts on empty runs)."
          )
    # Clean-repo terminal path. On the GCP path the coordinating workflow
    # short-circuits to completion when findings_count == 0, so Stage 3 never
    # runs -- this is the only opportunity to record that the scan happened.
    # report_uri stays NULL here because no HTML report is produced.
    ctx.total_findings_count = 0
    ctx.active_findings_count = 0
    ctx.skipped_duplicate_count = 0
    ctx.fixed_count = 0
    ctx.failed_fix_count = 0
    ctx.token_totals = scan_token_usage
    bq_telemetry.emit_scan_telemetry(ctx, status=bq_telemetry.STATUS_SUCCESS)
    sys.exit(0)

  # 8. Filter findings against PR differential hunks and deduplicate against open branches/PRs
  force_overwrite = config.force_overwrite
  active_findings, skipped_finding_ids, ignored_finding_ids = _filter_findings(
      findings,
      repo_url,
      token,
      repo_dir,
      force_overwrite,
      is_pr_scan=config.is_pr_scan,
      pr_base_ref=config.pr_base_ref,
      dry_run=config.dry_run,
      config=config,
  )

  # 9. Soft-delete skipped & ignored findings in local state.db for telemetry before archiving
  if skipped_finding_ids or ignored_finding_ids:
    db_path = os.path.expanduser("~/.codemender/state.db")
    if os.path.exists(db_path):
      try:
        # Open SQLite connection to record soft-deleted finding statuses
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        # Mark skipped duplicate findings in SQLite database
        for fid in skipped_finding_ids:
          cursor.execute(
              "UPDATE findings SET status = 'SKIPPED_DUPLICATE', muted = 1,"
              " mute_reason = 'Duplicate PR or branch already exists' WHERE"
              " finding_id = ?",
              (fid,),
          )
        # Mark pre-existing ignored findings in SQLite database
        for fid in ignored_finding_ids:
          # Execute soft-delete update query in local findings table
          cursor.execute(
              "UPDATE findings SET status = 'PRE_EXISTING_IGNORED', muted = 1,"
              " mute_reason = 'Pre-existing finding not touched in PR' WHERE"
              " finding_id = ?",
              (fid,),
          )
        conn.commit()
        conn.close()
        logger.info(
            "Dismissed %d skipped and %d ignored findings in local state.db.",
            len(skipped_finding_ids),
            len(ignored_finding_ids),
        )
      except Exception as e:  # pylint: disable=broad-exception-caught
        # Log warning if updating SQLite findings fails
        logger.warning("Failed to update findings in state.db: %s", e)

  # Compute active findings count after filtering
  active_findings_count = len(active_findings)
  logger.info("Active findings after filtering: %d", active_findings_count)

  # Detect total silent finding loss, which indicates upstream schema drift
  if (
      findings
      and active_findings_count == 0
      and not skipped_finding_ids
      and not ignored_finding_ids
  ):
    logger.error(
        "Parsed %d findings but retained 0 active with 0 skipped and 0 ignored."
        " The `cm report --format json` schema is likely unrecognized.",
        len(findings),
    )

  skipped_finding_prs = {
      str(f.get("FindingID") or f.get("finding_id")): str(f.get("pr_url"))
      for f in findings
      if isinstance(f, dict)
      and (f.get("FindingID") or f.get("finding_id")) in skipped_finding_ids
      and f.get("pr_url")
  }

  # 10. Handle case where all findings were filtered out
  if active_findings_count == 0:
    logger.info("Zero active findings after filtering. Exiting Stage 1.")
    if not config.is_pr_scan and skipped_finding_ids:
      # Synthesize rich SARIF with underReview suppressions so existing open alerts stay tracked on GitHub
      sarif_data = transform_json_to_sarif(
          findings=findings,
          repo_dir=repo_dir,
          skipped_finding_ids=set(skipped_finding_ids),
          finding_prs=skipped_finding_prs,
          is_pr_scan=False,
          repository=f"{owner}/{repo_name}",
          scan_target=config.scan_target,
      )
      sarif_path = os.path.join(workspace_dir, "report.sarif")
      for dest_dir in [repo_dir, workspace_dir]:
        if dest_dir and os.path.exists(dest_dir):
          try:
            with open(os.path.join(dest_dir, "report.sarif"), "w", encoding="utf-8") as f:
              json.dump(sarif_data, f, indent=2)
          except Exception as e:  # pylint: disable=broad-exception-caught
            logger.warning("Failed to write suppressed SARIF to %s: %s", dest_dir, e)
    else:
      # Generate schema-compliant clean SARIF for GitHub Code Scanning alert resolution
      sarif_path = _write_clean_sarif_file(
          repo_dir,
          workspace_dir,
          repository=f"{owner}/{repo_name}",
          scan_target=config.scan_target,
      )
    filtered_reason = (
        None
        if config.is_pr_scan
        else (
            f"{len(ignored_finding_ids)} pre-existing findings and"
            f" {len(skipped_finding_ids)} duplicate branches/PRs dismissed."
        )
    )
    # Render clean Step Summary before exiting
    summary_md = _render_zero_findings_summary(
        owner,
        repo_name,
        target_sha,
        config.is_pr_scan,
        config=config,
        filtered_reasons=filtered_reason,
        token_totals=scan_token_usage,
        wiz_note=wiz_note,
    )
    # Stage 3 does not run, so pass the PR Security Gate here
    _post_zero_findings_pr_gate(
        config, token, owner, repo_name, target_sha, summary_md
    )
    # Build minimal manifest with findings_count = 0
    manifest = {"findings_count": 0, "target_sha": target_sha}
    manifest_path = os.path.join(workspace_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
      json.dump(manifest, f, indent=2)
    # Upload filtered zero findings manifest and reports to transit storage
    upload_file_to_gcs(
        manifest_path, bucket_name, f"scans/{scan_id}/manifest.json"
    )
    if sarif_path and os.path.exists(sarif_path):
      upload_file_to_gcs(
          sarif_path, bucket_name, f"scans/{scan_id}/report.sarif"
      )
    token_usage_path = os.path.join(workspace_dir, "token_usage.json")
    try:
      with open(token_usage_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "scan_id": scan_id,
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "token_totals": scan_token_usage or {},
            },
            f,
            indent=2,
        )
      upload_file_to_gcs(
          token_usage_path, bucket_name, f"scans/{scan_id}/token_usage.json"
      )
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.warning("Failed to upload filtered zero-findings token_usage.json: %s", e)
    # Emit zero findings output variables to GitHub Actions environment
    _emit_github_output(
        {
            "matrix": "[0]",
            "findings_count": "0",
            "target_sha": str(target_sha),
            "scan_id": str(scan_id),
        },
        config=config,
    )
    if not config.is_pr_scan and target_sha and token:
      post_commit_status(
          token=token,
          owner=owner,
          repo=repo_name,
          sha=target_sha,
          state="success",
          description="Scan complete: no active findings.",
          context=STATUS_CONTEXT_SCHEDULED,
          target_url=config.execution_url or None,
      )
      if sarif_path and os.path.exists(sarif_path):
        if has_sarif_results(sarif_path) or config.upload_empty_sarif:
          if config.target_branch:
            scan_ref = f"refs/heads/{config.target_branch}"
          else:
            default_br, token = read_default_branch(
                config, token, owner, repo_name, lookup=get_default_branch
            )
            scan_ref = f"refs/heads/{default_br}" if default_br else None
          if scan_ref:
            upload_sarif_to_code_scanning(
                token=token,
                owner=owner,
                repo=repo_name,
                sarif_path=sarif_path,
                commit_sha=target_sha,
                ref=scan_ref,
            )
          else:
            logger.error(
                "Not uploading report.sarif: the target branch is unknown."
            )
        else:
          logger.info(
              "Skipping GitHub Code Scanning SARIF upload because report.sarif contains 0 results "
              "(set CODEMENDER_UPLOAD_EMPTY_SARIF=true to auto-resolve existing alerts on empty runs)."
          )
    # All-findings-filtered terminal path (duplicates / pre-existing). Stage 3
    # is likewise skipped here, so record the run now. Keeping the raw and
    # active counts distinct is what lets analytics separate "genuinely clean"
    # from "everything was already tracked elsewhere".
    ctx.total_findings_count = len(findings)
    ctx.active_findings_count = 0
    ctx.skipped_duplicate_count = len(skipped_finding_ids) + len(ignored_finding_ids)
    ctx.fixed_count = 0
    ctx.failed_fix_count = 0
    ctx.token_totals = scan_token_usage
    # Write the filtered findings too, so the warehouse shows which findings
    # were already tracked (and by which pull request) rather than an empty run.
    # This runs after the success status and SARIF upload, outside the
    # exporter's own guard, so a failure here must not fail the scan.
    telemetry_findings = []
    if bq_telemetry.telemetry_enabled():
      try:
        telemetry_findings = _filtered_findings_for_telemetry(
            findings,
            skipped_finding_ids,
            ignored_finding_ids,
            os.path.expanduser("~/.codemender/state.db"),
        )
      except Exception as e:  # pylint: disable=broad-exception-caught
        logger.warning(
            "Could not build the filtered findings for telemetry (non-fatal): %s",
            e,
        )
        telemetry_findings = []
    bq_telemetry.emit_scan_telemetry(
        ctx,
        status=bq_telemetry.STATUS_SUCCESS,
        findings=telemetry_findings,
        finding_prs=skipped_finding_prs,
    )
    sys.exit(0)

  # 11. Partition findings into balanced worker buckets
  max_tasks = config.max_tasks
  partitions = _partition_findings(active_findings, max_tasks)

  # 11b. For PR scans, classify blocking vs advisory findings, save active_findings.json,
  # emit GITHUB_OUTPUT counts, and publish the immediate Stage 1 sticky PR report.
  if config.is_pr_scan:
    base_dir = os.path.join(workspace_dir, ".codemender_transit", "base")
    os.makedirs(base_dir, exist_ok=True)
    _, blocking_cnt, advisory_cnt = classify_and_report_stage1_findings(
        findings=active_findings,
        workspace_dir=repo_dir,
        modified_files=set(),
        min_sev=config.min_blocking_severity,
        base_dir=base_dir,
        token=token,
        owner=owner,
        repo=repo_name,
        pr_number=config.pr_number or 0,
        target_sha=target_sha,
        run_url=os.environ.get("RUN_URL", ""),
        fail_on_findings=config.fail_on_findings,
    )
    _emit_github_output(
        {
            "blocking_count": str(blocking_cnt),
            "advisory_count": str(advisory_cnt),
        },
        config=config,
    )

  # 12. Save partitioned manifests, archive workspace, generate signed URLs, and upload
  _save_and_upload_state(
      partitions,
      active_findings_count,
      target_sha,
      workspace_dir,
      bucket_name,
      scan_id,
      scan_token_usage,
      len(skipped_finding_ids) + len(ignored_finding_ids),
      config=config,
      cm_binary=cm_binary,
      finding_prs=skipped_finding_prs,
      started_at=ctx.started_at,
      wiz_metadata=wiz_metadata,
      deep_summaries=deep_summaries,
  )

  logger.info("Stage 1 (Scan) completed successfully.")


def cm_supports_diff_flag(
    workspace_dir: str,
    cm_env: Optional[dict[str, str]] = None,
    cm_binary: str = "cm",
) -> bool:
  """Returns True if the installed `cm find` CLI supports the native `--diff` flag."""
  import subprocess

  try:
    proc = subprocess.run(
        [cm_binary, "find", "--help"],
        cwd=workspace_dir,
        env=cm_env,
        capture_output=True,
        text=True,
        check=False,
    )
    help_text = f"{proc.stdout or ''}\n{proc.stderr or ''}"
    return "--diff" in help_text
  except Exception:  # pylint: disable=broad-exception-caught
    return False


# Messages `cm` prints when its sandbox could not be set up at all, so the
# session never ran. (A session that ran but listed "sandbox violations" did
# complete: those are accesses the sandbox blocked, which is the point.)
SANDBOX_STARTUP_FAILURE_MARKERS = (
    "failed to create sandbox box",
    "failed to start worker in sandbox",
    "sandbox configuration error",
    "worker process exited unexpectedly",
)


@dataclasses.dataclass
class CmRunResult:
  """Outcome of one `cm` session run by `run_cm_with_sandbox_fallback`."""

  proc: "subprocess.CompletedProcess"
  output: str  # Lower-cased stdout + stderr of the run whose result is used.
  sandbox_failed: bool = False  # The sandbox could not start (see markers).
  unrestricted_rerun: bool = False  # The result comes from an --unrestricted rerun.

  def __iter__(self):
    # Lets older call sites keep unpacking `proc, output = ...`.
    return iter((self.proc, self.output))


def is_sandbox_startup_failure(returncode: int, output: str) -> bool:
  """Whether a `cm` run failed because its sandbox could not start."""
  lowered = (output or "").lower()
  return returncode != 0 and any(
      m in lowered for m in SANDBOX_STARTUP_FAILURE_MARKERS
  )


def _append_step_summary(text: str) -> None:
  path = os.environ.get("GITHUB_STEP_SUMMARY", "").strip()
  if not path:
    return
  try:
    with open(path, "a", encoding="utf-8") as sf:
      sf.write(text.rstrip("\n") + "\n")
  except OSError:
    pass


def _cm_label(cmd: list[str]) -> str:
  return " ".join(cmd[:3]) if len(cmd) >= 3 else " ".join(cmd)


def _log_sandbox_denials(
    cmd: list[str], output: str, output_printed: bool = False
) -> None:
  denied_lines = [
      line.strip()
      for line in output.splitlines()
      if "sandbox: denied " in line.lower()
  ]
  denied = output.lower().count("sandbox: denied ")
  if denied:
    print(
        f"[sandbox] `{_cm_label(cmd)}` completed inside the sandbox;"
        f" {denied} access(es) outside the sandbox roots were blocked"
        f"{' (listed above)' if output_printed else ''}. No unrestricted"
        " rerun.",
        flush=True,
    )
    if not output_printed:
      for line in denied_lines[:20]:
        print(f"[sandbox]   {line}", flush=True)


def run_cm_with_sandbox_fallback(
    cmd: list[str],
    workspace_dir: str,
    cm_env: dict[str, str],
    sandbox_enabled: bool = True,
    print_output: bool = False,
    allow_unsandboxed_fallback: bool = False,
) -> CmRunResult:
  """Runs a `cm` session, keeping it inside the sandbox.

  The session is re-run with `--unrestricted` only when the sandbox could not
  start at all (`is_sandbox_startup_failure`) and the operator explicitly
  allowed it (`allow_unsandboxed_fallback`, workflow input
  `allow_unsandboxed_fallback` / CODEMENDER_ALLOW_UNSANDBOXED_FALLBACK).
  Sandbox violations reported by a session that completed never trigger a
  rerun, and neither does any other failure.
  """
  import subprocess

  proc = subprocess.run(
      cmd,
      cwd=workspace_dir,
      env=cm_env,
      capture_output=True,
      text=True,
      check=False,
  )
  raw_out = f"{proc.stdout or ''}\n{proc.stderr or ''}"
  if print_output:
    print(raw_out, flush=True)
  combined_out = raw_out.lower()
  result = CmRunResult(proc=proc, output=combined_out)
  if not sandbox_enabled or "--unrestricted" in cmd:
    return result

  if not is_sandbox_startup_failure(proc.returncode, combined_out):
    _log_sandbox_denials(cmd, raw_out, output_printed=print_output)
    return result

  result.sandbox_failed = True
  label = _cm_label(cmd)
  if not allow_unsandboxed_fallback:
    print(
        f"::error title=CodeMender sandbox unavailable::`{label}` could not"
        " start its sandbox, so it did not run. CodeMender will not run it"
        " unsandboxed unless the workflow input allow_unsandboxed_fallback is"
        " true (or CODEMENDER_ALLOW_UNSANDBOXED_FALLBACK=true). Fix the runner"
        " (the container needs user namespaces) or opt in knowingly.",
        flush=True,
    )
    _append_step_summary(
        f"- ❌ `{label}`: the CodeMender sandbox could not start; the session"
        " was not run unsandboxed (fallback not allowed)."
    )
    return result

  print(
      f"::warning title=CodeMender sandbox DISABLED::`{label}` could not start"
      " its sandbox and allow_unsandboxed_fallback is true, so it is being"
      " re-run with --unrestricted. LLM-generated code in this session runs"
      " with the job's full filesystem access.",
      flush=True,
  )
  _append_step_summary(
      f"- ⚠️ `{label}`: re-run WITHOUT the sandbox (--unrestricted) because"
      " the sandbox could not start and allow_unsandboxed_fallback is true."
  )
  retry_cmd = [f for f in cmd if f != "--unrestricted"] + ["--unrestricted"]
  proc = subprocess.run(
      retry_cmd,
      cwd=workspace_dir,
      env=cm_env,
      capture_output=True,
      text=True,
      check=False,
  )
  raw_out = f"{proc.stdout or ''}\n{proc.stderr or ''}"
  if print_output:
    print(raw_out, flush=True)
  return CmRunResult(
      proc=proc,
      output=raw_out.lower(),
      sandbox_failed=True,
      unrestricted_rerun=True,
  )


@contextlib.contextmanager
def sandbox_workspace_access(workspace_dir: str, sandbox_enabled: bool = True):
  """Lets sandboxed `cm` sessions create files in the workspace root.

  `cm`'s sandbox runs tools in a user namespace that maps only the current
  user. In a GitHub Actions container job the job runs as root, but the
  runner creates the workspace directory on the host as its own user (not
  root). Inside the namespace that owner is unmapped, so the directory
  looks like it belongs to `nobody` and root's usual override does not
  apply: the agent cannot create anything in the repository root (for
  example its `.exploit/` working directory). Files that the checkout
  created inside the container are owned by root and are not affected.

  When running as root and the workspace root belongs to another user, take
  ownership of that one directory for the duration of the `cm` sessions and
  restore the original owner afterwards.
  """
  restore = None
  if sandbox_enabled and workspace_dir and hasattr(os, "geteuid"):
    try:
      st = os.stat(workspace_dir)
      euid = os.geteuid()
      if st.st_uid != euid:
        if euid == 0:
          os.chown(workspace_dir, 0, st.st_gid)
          restore = (st.st_uid, st.st_gid)
          print(
              f"[sandbox] Workspace {workspace_dir} is owned by uid"
              f" {st.st_uid}, but `cm` runs as uid 0 and its sandbox maps only"
              " that uid. Taking ownership of the workspace directory for the"
              " `cm` sessions (restored afterwards).",
              flush=True,
          )
        else:
          print(
              f"::warning title=CodeMender sandbox::Workspace {workspace_dir}"
              f" is owned by uid {st.st_uid} but `cm` runs as uid {euid}."
              " Sandboxed sessions may be unable to create files in the"
              " repository root.",
              flush=True,
          )
    except OSError as e:
      logger.warning("Could not check workspace ownership: %s", e)
  try:
    yield
  finally:
    if restore is not None:
      try:
        os.chown(workspace_dir, *restore)
      except OSError as e:
        logger.warning("Could not restore workspace ownership: %s", e)


def log_cm_environment(cm_env: dict[str, str], sandbox_enabled: bool) -> None:
  """Prints which credential-like variable names (never values) reach `cm`."""
  from codemender_agent.config import credential_like_env_names

  names = credential_like_env_names(cm_env)
  print(
      f"[cm env] sandbox={'on' if sandbox_enabled else 'off'};"
      f" {len(cm_env)} variables passed to cm; credential-like names:"
      f" {', '.join(names) if names else '(none)'}",
      flush=True,
  )


def build_pr_diff_context_prompt(
    workspace_dir: str, base_ref: str
) -> tuple[set[str], str]:
  """Builds a source-code-scoped PR diff context prompt for `cm find . -c`."""
  import subprocess
  from codemender_agent.runners.gate import get_pr_modified_code_files

  if not base_ref:
    return set(), ""

  all_changed, code_files = get_pr_modified_code_files(
      workspace_dir, base_ref, require_exists=False
  )
  modified_files = set(code_files) or set(all_changed)

  diff_cmd = ["git", "diff", "-U3", f"origin/{base_ref}...HEAD"]
  if modified_files:
    diff_cmd.extend(["--", *sorted(modified_files)])
  diff_proc = subprocess.run(
      diff_cmd, cwd=workspace_dir, capture_output=True, text=True, check=False
  )
  diff_context = diff_proc.stdout[:12000]
  if not modified_files:
    return set(), ""

  files_bullet_list = "\n".join(f"  - {f}" for f in sorted(modified_files))
  context_prompt = (
      "You are analyzing a GitHub Pull Request.\n"
      "1. SCOPE OF VULNERABILITY CHECKS: Check ONLY the files and code paths"
      f" modified in this PR diff:\n{files_bullet_list}\n"
      "Do NOT perform a blind full-repository crawl or report pre-existing"
      " vulnerabilities in untouched files.\n"
      "2. FULL REPOSITORY CONTEXT: The entire repository is mounted at `.`."
      " You SHOULD read and grep across other files in the repository (callers,"
      " callees, imported helpers, sanitizers, auth middleware, type"
      " definitions) to trace cross-file dataflow and accurately determine"
      " whether changes in the PR introduce or expose a vulnerability.\n\n"
      f"--- PR GIT DIFF ---\n{diff_context}\n--- END GIT DIFF ---"
  )
  return modified_files, context_prompt


def write_presubmit_cm_config(
    workspace_dir: str,
    sandbox_enabled: bool = True,
    build_cmd: str = "true",
) -> str:
  """Writes ~/.codemender/config.yaml for pre-submit scan/worker/aggregate runs and returns cm_home."""
  cm_home = os.path.expanduser("~/.codemender")
  os.makedirs(cm_home, exist_ok=True)
  cfg_path = os.path.join(cm_home, "config.yaml")
  with open(cfg_path, "w", encoding="utf-8") as cf:
    cf.write(
        f'project_paths:\n  - "{workspace_dir}"\n'
        'vcs:\n  type: "git"\n  commands:\n    reset: "git checkout HEAD -- ."\n'
        f'build:\n  command: "{build_cmd}"\n'
        f"sandbox:\n  enabled: {str(sandbox_enabled).lower()}\n  mounts:\n"
        f'    target_dir: "{workspace_dir}"\n  network:\n'
        '    profile: "permissive-open"\n'
        "tools:\n  confirm_commands: false\n  confirm_writes: false\n"
    )
  return cm_home


def restore_presubmit_transit_workspace(
    workspace_dir: str,
    sandbox_enabled: bool = True,
    build_cmd: str = "true",
) -> str:
  """Restores ~/.codemender and .cm_project from .codemender_transit/base and writes config.yaml."""
  base_dir = os.path.join(workspace_dir, ".codemender_transit", "base")
  tar_path = os.path.join(base_dir, "codemender_home.tar.gz")
  if os.path.exists(tar_path):
    with tarfile.open(tar_path, "r:gz") as tar:
      if hasattr(tarfile, "data_filter"):
        tar.extractall(path=os.path.expanduser("~"), filter="data")
      else:
        tar.extractall(path=os.path.expanduser("~"))
  cm_proj_src = os.path.join(base_dir, ".cm_project")
  cm_proj_dst = os.path.join(workspace_dir, ".cm_project")
  if os.path.exists(cm_proj_src):
    shutil.copy2(cm_proj_src, cm_proj_dst)
  return write_presubmit_cm_config(
      workspace_dir=workspace_dir,
      sandbox_enabled=sandbox_enabled,
      build_cmd=build_cmd,
  )


def classify_and_report_stage1_findings(
    findings: list[dict],
    workspace_dir: str,
    modified_files: set[str],
    min_sev: str = "MEDIUM",
    base_dir: Optional[str] = None,
    token: str = "",
    owner: str = "",
    repo: str = "",
    pr_number: int = 0,
    target_sha: str = "",
    run_url: str = "",
    fail_on_findings: bool = True,
) -> tuple[list[dict], int, int]:
  """Filters PR findings, applies severity pragmas, emits annotations, and posts Stage 1 sticky report."""
  import re
  from codemender_agent.vcs.git import find_source_pragma
  from codemender_agent.vcs.github import (
      extract_finding_fields,
      is_blocking_severity,
      post_or_update_sticky_comment,
  )

  pragma_re = re.compile(
      r"#\s*codemender:\s*severity=(LOW|INFO|MEDIUM|HIGH|CRITICAL)",
      re.IGNORECASE,
  )
  active_findings = []
  for raw_f in findings:
    if not isinstance(raw_f, dict):
      continue
    fields = extract_finding_fields(raw_f, repo_dir=workspace_dir)
    fid = fields["finding_id"]
    fpath = fields["file_path"]
    if modified_files and fpath and fpath not in modified_files:
      continue

    line_no = fields["line_number"]
    end_line = fields["end_line"]
    sev = fields["severity"]
    m_pragma = find_source_pragma(
        workspace_dir=workspace_dir,
        relpath=fpath,
        start_line=line_no,
        end_line=end_line,
        pattern=pragma_re,
    )
    if m_pragma:
      sev = m_pragma.group(1).upper()

    title = fields["title"]
    desc = fields["description"]
    nf = {
        **raw_f,
        "finding_id": fid,
        "FindingID": fid,
        "file_path": fpath,
        "FilePath": fpath,
        "line_number": max(1, line_no),
        "start_line": max(1, line_no),
        "StartLine": max(1, line_no),
        "end_line": max(line_no, end_line),
        "EndLine": max(line_no, end_line),
        "severity": sev,
        "Severity": sev,
        "title": title,
        "Title": title,
        "description": desc,
        "Description": desc,
    }
    active_findings.append(nf)

  blocking_count = 0
  advisory_count = 0
  for item in active_findings:
    sev = item["severity"]
    is_block = is_blocking_severity(sev, min_sev)
    if is_block:
      blocking_count += 1
    else:
      advisory_count += 1
    level = "error" if (is_block and fail_on_findings) else "warning"
    clean_desc = item["description"].replace("\n", " ")[:240]
    print(
        f"::{level} file={item['file_path']},line={item['line_number']},"
        f"title=CodeMender [{sev}] {item['title']}::{clean_desc}"
    )

  if base_dir:
    os.makedirs(base_dir, exist_ok=True)
    with open(
        os.path.join(base_dir, "active_findings.json"), "w", encoding="utf-8"
    ) as af:
      json.dump(active_findings, af, indent=2)

  if active_findings and token and owner and repo and pr_number:
    rows = []
    for item in active_findings:
      fid_short = item["finding_id"][:8]
      sev = item["severity"]
      is_block = is_blocking_severity(sev, min_sev)
      if is_block:
        badge = "🚫 **BLOCKING**" if fail_on_findings else "⚠️ **Non-Blocking**"
      else:
        badge = "ℹ️ Advisory"
      rows.append(
          f"| `{sev}` | {badge} | **{item['title']}** (`{fid_short}`) |"
          f" `{item['file_path']}:{item['line_number']}` | ⏳ **Queued for `cm"
          f" verify`** | <!-- cm-row:{fid_short} -->"
      )
    if blocking_count > 0:
      if fail_on_findings:
        gate_banner = (
            f"❌ **BLOCKED** (`{blocking_count}` finding(s) `>= {min_sev}`)"
        )
      else:
        gate_banner = (
            f"⚠️ **PASSED (Non-Blocking Mode)** (`{blocking_count}` finding(s)"
            f" `>= {min_sev}` — merge not blocked)"
        )
    else:
      gate_banner = (
          f"✅ **PASSED** (`0` findings `>= {min_sev}`, `{advisory_count}`"
          " advisory)"
      )
    body = (
        "## 🛡️ CodeMender Pre-Submit Security Gate —"
        f" {gate_banner}\n"
        f"*⏳ **Stage 1 Complete: 0/{len(active_findings)} Findings Verified**"
        " (`cm verify` & `cm fix` running in background)*\n\n"
        f"**Commit:** `{target_sha[:8]}` | [View Workflow Run]({run_url})\n\n"
        "| Severity | Gate | Finding | Location | Status |\n"
        "| :--- | :--- | :--- | :--- | :--- |\n"
        + "\n".join(rows)
    )
    post_or_update_sticky_comment(
        token=token, owner=owner, repo=repo, pr_number=pr_number, body=body
    )

  return active_findings, blocking_count, advisory_count


def execute_stage1_presubmit_scan(
    cfg: Optional[OrchestratorConfig] = None,
) -> list[dict]:
  """Executes Stage 1 local/GitHub Actions pre-submit scan, partitioning, and sticky report."""
  import subprocess

  cfg = cfg or OrchestratorConfig.from_env()
  workspace_dir = cfg.workspace_dir
  scan_target = cfg.scan_target.strip() or "."
  is_pr = cfg.is_pr_scan
  diff_scoped = cfg.diff_scoped_pr_scan
  base_ref = (cfg.pr_base_ref or "").strip()
  min_sev = cfg.min_blocking_severity
  fail_on_findings = cfg.fail_on_findings
  max_tasks = cfg.max_tasks
  target_sha = (cfg.target_sha or "").strip()
  if not target_sha:
    sha_proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=workspace_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    target_sha = sha_proc.stdout.strip() or "HEAD"

  scan_id = cfg.scan_id or f"scan_{int(time.time())}"
  run_url = os.environ.get("RUN_URL", "")
  token = (cfg.github_token or "").strip()
  repo_full = (
      os.environ.get("REPO_FULL") or os.environ.get("GITHUB_REPOSITORY") or ""
  ).strip()
  owner, repo = (
      repo_full.split("/", 1) if "/" in repo_full else ("", repo_full)
  )
  pr_number = cfg.pr_number or 0

  base_dir = os.path.join(workspace_dir, ".codemender_transit", "base")
  os.makedirs(base_dir, exist_ok=True)

  # 1. Fast-path when preflight detected zero modified source files (no `cm` binary required)
  if scan_target == "__SKIP_NO_SOURCE_CHANGES__":
    _write_clean_sarif_file(None, workspace_dir)
    with open(
        os.path.join(base_dir, "active_findings.json"), "w", encoding="utf-8"
    ) as af:
      json.dump([], af)
    _emit_github_output({
        "matrix": "[0]",
        "findings_count": "0",
        "blocking_count": "0",
        "advisory_count": "0",
        "target_sha": target_sha,
        "scan_id": scan_id,
    })
    return []

  # 2. Initialize .cm_project & ~/.codemender/config.yaml
  sandbox_enabled = cfg.sandbox_enabled
  allow_fallback = cfg.allow_unsandboxed_fallback
  cm_env = get_scrubbed_env(repo_dir=workspace_dir)
  log_cm_environment(cm_env, sandbox_enabled)
  cm_proj = os.path.join(workspace_dir, ".cm_project")
  if not os.path.exists(cm_proj):
    subprocess.run(
        ["cm", "init", "--yes", "--bypass-warning"],
        cwd=workspace_dir,
        env=cm_env,
        check=False,
    )
  build_cmd = (cfg.build_command or "true").strip() or "true"
  cm_home = write_presubmit_cm_config(
      workspace_dir=workspace_dir,
      sandbox_enabled=sandbox_enabled,
      build_cmd=build_cmd,
  )

  # 3. Execute `cm find` (native --diff when supported, else diff-scoped -c prompt, or target list)
  modified_files: set[str] = set()
  used_native_diff = False
  raw_findings: list[dict] = []
  find_results: list[CmRunResult] = []
  sandbox_flags = [] if sandbox_enabled else ["--unrestricted"]
  find_model = (cfg.find_model or "").strip()
  model_flags = ["--model", find_model] if find_model else []

  if is_pr and diff_scoped and base_ref:
    modified_files, context_prompt = build_pr_diff_context_prompt(
        workspace_dir, base_ref
    )
    if modified_files:
      fallback_cmd = [
          "cm",
          "find",
          ".",
          "--yes",
          "--bypass-warning",
          *sandbox_flags,
          *model_flags,
          "-c",
          context_prompt,
      ]
      if cm_supports_diff_flag(workspace_dir, cm_env):
        used_native_diff = True
        cmd = [
            "cm",
            "find",
            ".",
            f"--diff=origin/{base_ref}",
            "--fail-on=",
            "--yes",
            "--bypass-warning",
            *sandbox_flags,
            *model_flags,
        ]
      else:
        cmd = fallback_cmd
      with sandbox_workspace_access(workspace_dir, sandbox_enabled):
        res = run_cm_with_sandbox_fallback(
            cmd,
            workspace_dir,
            cm_env,
            sandbox_enabled=sandbox_enabled,
            allow_unsandboxed_fallback=allow_fallback,
        )
        find_results.append(res)
        if used_native_diff and res.proc.returncode != 0 and (
            "unknown flag" in res.output or "invalid" in res.output
        ):
          used_native_diff = False
          find_results.append(
              run_cm_with_sandbox_fallback(
                  fallback_cmd,
                  workspace_dir,
                  cm_env,
                  sandbox_enabled=sandbox_enabled,
                  allow_unsandboxed_fallback=allow_fallback,
              )
          )
  else:
    targets = [
        t.strip()
        for part in scan_target.split(";")
        for t in part.split(",")
        if t.strip()
    ] or ["."]
    with sandbox_workspace_access(workspace_dir, sandbox_enabled):
      for t in targets:
        cmd = ["cm", "find", t, "--yes", "--bypass-warning", *sandbox_flags, *model_flags]
        find_results.append(
            run_cm_with_sandbox_fallback(
                cmd,
                workspace_dir,
                cm_env,
                sandbox_enabled=sandbox_enabled,
                allow_unsandboxed_fallback=allow_fallback,
            )
        )

  # Fail closed: a `cm find` that never ran (sandbox unavailable, fallback not
  # allowed) must not be reported as "0 findings".
  if any(r.sandbox_failed and not r.unrestricted_rerun for r in find_results):
    print(
        "::error title=CodeMender scan not run::`cm find` could not start its"
        " sandbox. Failing Stage 1 so the security gate fails closed.",
        flush=True,
    )
    sys.exit(1)

  # 4. Export JSON & SARIF reports
  rep = subprocess.run(
      ["cm", "report", "--format", "json", "--bypass-warning"],
      cwd=workspace_dir,
      env=cm_env,
      capture_output=True,
      text=True,
      check=False,
  )
  if rep.stdout.strip():
    raw_findings = parse_findings_json(rep.stdout)

  sarif_proc = subprocess.run(
      ["cm", "report", "--format", "sarif", "--bypass-warning"],
      cwd=workspace_dir,
      env=cm_env,
      capture_output=True,
      text=True,
      check=False,
  )
  sarif_valid = False
  if sarif_proc.returncode == 0 and sarif_proc.stdout.strip():
    try:
      json.loads(sarif_proc.stdout)
      with open(
          os.path.join(workspace_dir, "report.sarif"), "w", encoding="utf-8"
      ) as sf:
        sf.write(sarif_proc.stdout)
      sarif_valid = True
    except Exception:  # pylint: disable=broad-exception-caught
      sarif_valid = False
  if not sarif_valid:
    _write_clean_sarif_file(None, workspace_dir)

  # 5. Classify findings, emit annotations, save active_findings.json, post Stage 1 sticky comment
  active_findings, blocking_count, advisory_count = (
      classify_and_report_stage1_findings(
          findings=raw_findings,
          workspace_dir=workspace_dir,
          modified_files=set() if used_native_diff else modified_files,
          min_sev=min_sev,
          base_dir=base_dir,
          token=token,
          owner=owner,
          repo=repo,
          pr_number=pr_number,
          target_sha=target_sha,
          run_url=run_url,
          fail_on_findings=fail_on_findings,
      )
  )

  # 6. Partition active findings and archive ~/.codemender state for Stage 2 workers
  total = len(active_findings)
  if total > 0:
    num_workers = min(total, max(1, max_tasks))
    for i in range(num_workers):
      shard = active_findings[i::num_workers]
      with open(
          os.path.join(base_dir, f"partition_{i}.json"), "w", encoding="utf-8"
      ) as pf:
        json.dump(
            {
                "partition_index": i,
                "finding_ids": [s["finding_id"] for s in shard],
                "findings": shard,
            },
            pf,
            indent=2,
        )
    matrix_list = list(range(num_workers))
  else:
    matrix_list = [0]

  if os.path.exists(cm_proj):
    shutil.copy2(cm_proj, os.path.join(base_dir, ".cm_project"))
  if os.path.exists(cm_home):
    make_tarfile(os.path.join(base_dir, "codemender_home.tar.gz"), cm_home)

  _emit_github_output({
      "matrix": json.dumps(matrix_list),
      "findings_count": str(total),
      "blocking_count": str(blocking_count),
      "advisory_count": str(advisory_count),
      "target_sha": target_sha,
      "scan_id": scan_id,
  })
  return active_findings


