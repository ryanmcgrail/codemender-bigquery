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

"""Sequential single-task execution pipeline runner for CodeMender Agent."""

import hashlib
import logging
import os
import shutil
import sqlite3
import sys
import time

from codemender_agent.codemender.cli import ensure_cm_updated
from codemender_agent.codemender.cli import extract_session_id
from codemender_agent.codemender.cli import get_cm_default_model
from codemender_agent.codemender.cli import is_closed_finding_status
from codemender_agent.codemender.cli import log_cm_version
from codemender_agent.codemender.cli import parse_findings_json
from codemender_agent.codemender.db import get_finding_status
from codemender_agent.codemender.db import is_finding_verified
from codemender_agent.config import OrchestratorConfig
from codemender_agent.config import get_cleanup_ports
from codemender_agent.config import get_github_credentials
from codemender_agent.config import get_scrubbed_env
from codemender_agent.config import inject_codemender_config
from codemender_agent.config import refresh_github_token
from codemender_agent.runners.aggregate import _inject_token_metrics_into_html
from codemender_agent.storage import upload_and_sign_report
from codemender_agent.utils import accumulate_model_token_usage
from codemender_agent.utils import build_cm_command
from codemender_agent.utils import free_port
from codemender_agent.utils import is_dry_run
from codemender_agent.utils import resolve_command_model
from codemender_agent.utils import run_command
from codemender_agent.vcs.git import clean_workspace
from codemender_agent.vcs.git import configure_git_identity
from codemender_agent.vcs.git import generate_branch_name
from codemender_agent.vcs.git import get_git_auth_header
from codemender_agent.vcs.git import parse_repo_owner_and_name
from codemender_agent.vcs.git import sanitize_exploit_and_artifacts
from codemender_agent.vcs.git import sanitize_git_url
from codemender_agent.vcs.git import setup_local_git_excludes
from codemender_agent.vcs.github import check_remote_branch_exists
from codemender_agent.vcs.github import create_pull_request
from codemender_agent.vcs.github import delete_remote_branch
from codemender_agent.vcs.github import get_default_branch
from codemender_agent.vcs.github import is_duplicate_pr
from codemender_agent.wiz.converter import carries_import_marker
from codemender_agent.wiz.settings import WizBridgeSettings

logger = logging.getLogger("codemender-orchestrator")


def run_sequential_pipeline() -> None:
  """Executes the single-task sequential scan, verify, fix, and PR pipeline.

  TODO(sequential-mode BigQuery telemetry): The BigQuery analytics export
  currently instruments only the GCP three-stage path (`scan.py` ->
  `worker.py` -> `aggregate.py`). This sequential runner -- the path taken in
  GitHub Actions mode and for local single-task runs -- emits no `scan_runs`
  or `vulnerability_findings` rows at all, so runs executed this way are
  invisible in the warehouse.

  Wiring it up means: creating a `bq_telemetry.ScanRunContext(stage=
  "sequential")`, wrapping the body in `bq_telemetry.telemetry_run_guard` so
  the two `sys.exit(1)` paths below still record a FAILED row, snapshotting
  `state.db` via `bq_telemetry.snapshot_state_db_findings` *before* any
  cleanup, and calling `bq_telemetry.emit_scan_telemetry` on the terminal
  paths. See `codemender_agent/telemetry/bigquery.py`.
  """
  cli_version = os.environ.get("CODEMENDER_CLI_VERSION", "preview").lower()
  skip_verify = (
      os.environ.get("CODEMENDER_SKIP_VERIFY", "true").strip().lower()
      in ("true", "1", "yes")
  )
  token_usage: dict[str, dict[str, int]] = {}
  if WizBridgeSettings.from_env().enabled:
    logger.warning(
        "The Wiz SAST bridge only runs in the parallel (Cloud Run) pipeline;"
        " this sequential run scans with CodeMender alone and imports no Wiz"
        " results."
    )
  config = OrchestratorConfig.from_env()
  repo_url, token = get_github_credentials(config=config)
  clean_repo_url = sanitize_git_url(repo_url)
  owner, repo_name = parse_repo_owner_and_name(clean_repo_url)

  workspace_dir = os.environ.get("WORKSPACE_DIR", os.getcwd())

  # Step 1: Single-Sync Git Rule - clone repository if not present or pull latest
  logger.info("Syncing repository: %s", clean_repo_url)
  repo_dir = os.path.join(workspace_dir, repo_name)

  if not os.path.exists(os.path.join(repo_dir, ".git")):
    if os.path.exists(repo_dir):
      shutil.rmtree(repo_dir)
    clone_cmd = [
        "git",
        "-c",
        get_git_auth_header(token),
        "clone",
        "--depth",
        "1",
        clean_repo_url,
        repo_dir,
    ]
    run_command(clone_cmd, cwd=workspace_dir)
  else:
    logger.info("Repository directory exists, fetching latest state...")
    try:
      curr_branch = run_command(
          ["git", "branch", "--show-current"], cwd=repo_dir
      ).stdout.strip()
    except Exception:
      curr_branch = "main"
    if not curr_branch:
      curr_branch = "main"

    fetch_cmd = [
        "git",
        "-c",
        get_git_auth_header(token),
        "fetch",
        "origin",
        curr_branch,
    ]
    run_command(fetch_cmd, cwd=repo_dir)
    run_command(["git", "checkout", "-f", curr_branch], cwd=repo_dir)
    run_command(
        ["git", "reset", "--hard", f"origin/{curr_branch}"], cwd=repo_dir
    )

  scrubbed_env = get_scrubbed_env(repo_dir=repo_dir)

  try:
    default_branch = run_command(
        ["git", "branch", "--show-current"], cwd=repo_dir
    ).stdout.strip()
  except Exception:
    default_branch = ""
  if not default_branch:
    default_branch = get_default_branch(token, owner, repo_name)

  logger.info("Using default branch: %s", default_branch)
  run_command(["git", "checkout", "-f", default_branch], cwd=repo_dir)

  configure_git_identity(repo_dir, token, run=run_command)

  setup_local_git_excludes(repo_dir)

  # Step 2: Initialize CodeMender CLI
  logger.info("Initializing CodeMender CLI...")
  cm_binary = ensure_cm_updated(
      shutil.which("cm") or "cm", env=scrubbed_env, cwd=repo_dir
  )
  log_cm_version(cm_binary, env=scrubbed_env, cwd=repo_dir)
  default_cm_model = get_cm_default_model(cm_binary, env=scrubbed_env, cwd=repo_dir)

  try:
    init_cmd = build_cm_command(cm_binary, "init", cli_version=cli_version)
    run_command(
        init_cmd,
        cwd=repo_dir,
        env=scrubbed_env,
        check=True,
    )
    inject_codemender_config(repo_dir)

    verify_init_cmd = build_cm_command(
        cm_binary, "init", extra_flags=["--verify"], cli_version=cli_version
    )
    run_command(
        verify_init_cmd,
        cwd=repo_dir,
        env=scrubbed_env,
        check=True,
    )
  except Exception as e:
    logger.critical(
        "CodeMender initialization failed. Please check if the 'cm' binary is"
        " properly installed, credentials/config are correct, or the backend is"
        " reachable: %s",
        e,
    )
    sys.exit(1)

  # Step 3: Parse scan targets (normalized to absolute paths to prevent sandbox mount errors)
  scan_target_env = os.environ.get("CODEMENDER_SCAN_TARGET", ".")
  targets = []
  for part in scan_target_env.split(";"):
    for subpart in part.split(","):
      t = subpart.strip()
      if t:
        abs_t = t if os.path.isabs(t) else os.path.abspath(os.path.join(repo_dir, t))
        targets.append(abs_t)
  if not targets:
    targets = [os.path.abspath(repo_dir)]

  logger.info("Starting CodeMender scanning for targets: %s", targets)

  for target in targets:
    logger.info("Running scan for target: '%s'...", target)
    try:
      find_cmd = build_cm_command(cm_binary, "find", target, cli_version=cli_version)
      find_res = run_command(
          find_cmd,
          cwd=repo_dir,
          env=scrubbed_env,
          check=True,
      )
      find_model = resolve_command_model("find") or default_cm_model
      find_tokens = getattr(find_res, "token_usage", None)
      if isinstance(find_tokens, dict):
        accumulate_model_token_usage(token_usage, find_model, find_tokens)
      session_id = extract_session_id(find_res.stdout)
      if session_id:
        logger.info("Detected active scan session ID: %s for target '%s'", session_id, target)
      else:
        logger.warning("Could not extract active session ID from scan output for target '%s'.", target)
    except Exception as e:
      logger.critical(
          "CodeMender vulnerability scanning failed for target '%s'. Stopping pipeline: %s",
          target,
          e,
      )
      sys.exit(1)

  # Fetch all findings from local SQLite database across all target sessions
  report_cmd = build_cm_command(
      cm_binary, "report", extra_flags=["--format", "json"], cli_version=cli_version
  )

  report_res = run_command(
      report_cmd,
      cwd=repo_dir,
      env=scrubbed_env,
      check=True,
      capture_stderr=False,
  )
  findings = parse_findings_json(report_res.stdout)
  logger.info("Found %d vulnerability finding(s).", len(findings))

  # Step 4: Sequential Verify -> Fix -> Branch -> Push -> PR loop
  # Find is done; verify and fix resolve each finding's project root (where cm
  # runs the build command) from project_paths, so point it at the repository.
  inject_codemender_config(repo_dir, for_remediation=True)
  state_db_path = os.path.expanduser("~/.codemender/state.db")
  for idx, finding in enumerate(findings, start=1):
    finding_id = finding.get("FindingID")
    if not finding_id:
      logger.warning("Finding missing FindingID at index %d, skipping.", idx)
      continue

    status = finding.get("Status")
    if is_closed_finding_status(status):
      logger.info(
          "Skipping finding %s because status is %s.", finding_id, status
      )
      continue

    vuln_type = finding.get("VulnType") or "vulnerability"
    file_path = finding.get("FilePath") or "unknown_file"
    title = finding.get("Title") or f"Security Fix for {vuln_type}"
    severity = finding.get("Severity") or "UNKNOWN"
    analysis = (
        finding.get("Analysis") or "Automated fix generated by CodeMender."
    )

    try:
      start_line = int(finding.get("StartLine") or 0)
    except ValueError:
      start_line = 0

    # Create deterministic fingerprint to prevent PR spam from LLM snippet jitter
    raw_hash_str = f"{file_path}|{vuln_type}|{start_line}"
    stable_fingerprint = hashlib.sha256(raw_hash_str.encode("utf-8")).hexdigest()[:8]

    branch_name = generate_branch_name(vuln_type, stable_fingerprint)

    logger.info(
        "Processing finding %d/%d [ID: %s, VulnType: %s, Branch: %s]",
        idx,
        len(findings),
        finding_id,
        vuln_type,
        branch_name,
    )

    force_overwrite = (
        os.environ.get("CODEMENDER_FORCE_OVERWRITE", "false").lower() == "true"
    )
    dry_run = is_dry_run()
    # Earlier findings may have outlived a GitHub App installation token. A
    # static token is returned unchanged. A failed refresh is not fatal here;
    # the refresh before pushing records a failure for this finding instead.
    try:
      token = refresh_github_token(config, token)
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.error(
          "Could not refresh the GitHub token before finding %s: %s",
          finding_id,
          e,
      )
    # A dry run skips remote duplicate checks, like the parallel runners.
    if not force_overwrite and not dry_run:
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
      if is_branch_dup:
        if is_pr_dup:
          logger.info(
              "Active PR exists for branch %s. Skipping finding %s.",
              branch_name,
              finding_id,
          )
          if os.path.exists(state_db_path):
            try:
              conn = sqlite3.connect(state_db_path)
              conn.execute(
                  "UPDATE findings SET status = 'SKIPPED_DUPLICATE', muted = 1,"
                  " mute_reason = 'Duplicate PR or branch already exists' WHERE"
                  " finding_id = ?",
                  (finding_id,),
              )
              conn.commit()
              conn.close()
            except Exception as e:  # pylint: disable=broad-exception-caught
              logger.warning(
                  "Failed to update SKIPPED_DUPLICATE in sequential state.db: %s", e
              )
          continue
        else:
          logger.info(
              "Dead branch detected: %s exists on remote with no active open PR."
              " Pruning dead branch to allow fresh remediation.",
              branch_name,
          )
          delete_remote_branch(clean_repo_url, token, branch_name, cwd=repo_dir)
      elif is_pr_dup:
        logger.info(
            "An open PR covering %s in %s near line %d already exists. Skipping"
            " finding %s.",
            vuln_type,
            file_path,
            start_line,
            finding_id,
        )
        if os.path.exists(state_db_path):
          try:
            conn = sqlite3.connect(state_db_path)
            conn.execute(
                "UPDATE findings SET status = 'SKIPPED_DUPLICATE', muted = 1,"
                " mute_reason = 'Duplicate PR or branch already exists' WHERE"
                " finding_id = ?",
                (finding_id,),
            )
            conn.commit()
            conn.close()
          except Exception as e:  # pylint: disable=broad-exception-caught
            logger.warning(
                "Failed to update SKIPPED_DUPLICATE in sequential state.db: %s", e
            )
        continue

    # Findings imported from an external scanner are always verified before
    # any fix, even when verification is otherwise skipped.
    if not skip_verify or carries_import_marker(finding):
      max_verify_attempts = 3
      verified = False

      for attempt in range(1, max_verify_attempts + 1):
        logger.info(
            "Verifying finding %s (Attempt %d/%d)...",
            finding_id,
            attempt,
            max_verify_attempts,
        )

        for port in get_cleanup_ports():
          free_port(port)

        run_command(["git", "checkout", "-f", default_branch], cwd=repo_dir)
        clean_workspace(repo_dir)

        verify_cmd = build_cm_command(
            cm_binary, "verify", finding_id, cli_version=cli_version
        )
        verify_res = run_command(
            verify_cmd,
            cwd=repo_dir,
            env=scrubbed_env,
            check=False,
        )
        verify_model = resolve_command_model("verify") or default_cm_model
        verify_tokens = getattr(verify_res, "token_usage", None)
        if isinstance(verify_tokens, dict):
          accumulate_model_token_usage(token_usage, verify_model, verify_tokens)
        for port in get_cleanup_ports():
          free_port(port)

        if verify_res.returncode == 0 and is_finding_verified(
            state_db_path, finding_id
        ):
          logger.info(
              "Successfully verified finding %s on attempt %d.",
              finding_id,
              attempt,
          )
          verified = True
          break
        else:
          logger.warning(
              "Attempt %d/%d failed to verify finding %s.",
              attempt,
              max_verify_attempts,
              finding_id,
          )
          if attempt < max_verify_attempts:
            logger.info("Retrying verification in 5 seconds...")
            time.sleep(5)

      if not verified:
        logger.error(
            "Verification failed for finding %s after %d attempts. Skipping fix.",
            finding_id,
            max_verify_attempts,
        )
        sanitize_exploit_and_artifacts(
            repo_dir, codemender_home=os.path.dirname(state_db_path)
        )
        continue

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

    logger.info(
        "Applying fix for finding %s on %s branch...",
        finding_id,
        default_branch,
    )
    fix_cmd = build_cm_command(
        cm_binary, "fix", finding_id, cli_version=cli_version
    )
    fix_res = run_command(
        fix_cmd,
        cwd=repo_dir,
        env=scrubbed_env,
        check=False,
    )
    fix_model = resolve_command_model("fix") or default_cm_model
    fix_tokens = getattr(fix_res, "token_usage", None)
    if isinstance(fix_tokens, dict):
      accumulate_model_token_usage(token_usage, fix_model, fix_tokens)
    for port in get_cleanup_ports():
      free_port(port)

    finding_status = get_finding_status(state_db_path, finding_id)
    if fix_res.returncode != 0 or finding_status != "FIXED":
      logger.warning(
          "Fix failed to apply successfully for finding %s (code %d, status"
          " %s). Skipping.",
          finding_id,
          fix_res.returncode,
          finding_status,
      )
      run_command(["git", "checkout", "-f", default_branch], cwd=repo_dir)
      clean_workspace(repo_dir)
      continue

    status_res = run_command(["git", "status", "--porcelain"], cwd=repo_dir)
    if not status_res.stdout.strip():
      logger.warning(
          "Fix command executed but no file changes were detected for"
          " finding %s.",
          finding_id,
      )
      continue

    try:
      run_command(["git", "checkout", "-B", branch_name], cwd=repo_dir)
      run_command(["git", "add", "-u"], cwd=repo_dir)
      commit_msg = f"fix(security): resolve {vuln_type} in {file_path}"
      run_command(["git", "commit", "-m", commit_msg], cwd=repo_dir)

      if dry_run:
        logger.info(
            "Dry run (CODEMENDER_DRY_RUN): fix for finding %s is ready; not"
            " pushing %s or opening a pull request.",
            finding_id,
            branch_name,
        )
        continue

      logger.info("Pushing branch %s to remote...", branch_name)
      # Verification and fixing can outlive a GitHub App installation token.
      token = refresh_github_token(config, token)
      push_cmd = [
          "git",
          "-c",
          get_git_auth_header(token),
          "push",
      ]
      if force_overwrite:
        push_cmd.append("-f")
      push_cmd.extend(["origin", branch_name])

      run_command(push_cmd, cwd=repo_dir)

      pr_title = (
          f"fix(security): resolve {vuln_type} vulnerability in {file_path}"
      )
      pr_body = (
          "### CodeMender Security Fix\n\n"
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

      try:
        pr_url = create_pull_request(
            token=token,
            owner=owner,
            repo=repo_name,
            title=pr_title,
            body=pr_body,
            head_branch=branch_name,
            base_branch=default_branch,
        )
        if not pr_url or pr_url == "FAILED":
          raise RuntimeError(f"Failed to create Pull Request for {branch_name}")
      except Exception as pr_err:
        logger.error(
            "PR creation failed for branch %s (%s). Rolling back remote branch...",
            branch_name,
            pr_err,
        )
        delete_remote_branch(clean_repo_url, token, branch_name, cwd=repo_dir)
        raise

    except Exception as e:
      logger.error("Error creating branch/PR for finding %s: %s", finding_id, e)
    finally:
      run_command(["git", "checkout", "-f", default_branch], cwd=repo_dir)
      run_command(
          ["git", "clean", "-fd", "-e", ".cm_project", "-e", ".exploit"],
          cwd=repo_dir,
      )

  # Delete SKIPPED_DUPLICATE findings from local state.db before html report
  if os.path.exists(state_db_path):
    try:
      conn = sqlite3.connect(state_db_path)
      conn.execute("DELETE FROM findings WHERE status = 'SKIPPED_DUPLICATE'")
      conn.commit()
      conn.close()
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.warning("Failed to remove SKIPPED_DUPLICATE findings from state.db: %s", e)

  # Generate final HTML report
  logger.info("Generating final HTML summary report...")
  report_html_cmd = build_cm_command(
      cm_binary, "report", extra_flags=["-f", "html"], cli_version=cli_version
  )
  report_res = run_command(
      report_html_cmd,
      cwd=repo_dir,
      env=scrubbed_env,
      check=False,
  )
  if report_res.returncode == 0:
    local_report_path = os.path.expanduser("~/.codemender/reports/report.html")
    if cli_version == "preview" and token_usage:
      _inject_token_metrics_into_html(local_report_path, token_usage)
    report_bucket = os.environ.get("CODEMENDER_REPORT_BUCKET")
    if report_bucket:
      dest_blob = f"reports/{owner}_{repo_name}/report_{time.strftime('%Y%m%d-%H%M%S')}.html"
      signed_url = upload_and_sign_report(
          local_report_path, report_bucket, dest_blob
      )
      if signed_url:
        logger.info(
            "\n"
            "======================================================================\n"
            "📊 CODEMENDER SUMMARY REPORT GENERATED:\n"
            "👉 %s\n"
            "======================================================================\n",
            signed_url,
        )
      else:
        logger.error("Failed to generate signed URL for the GCS report.")
    else:
      logger.info(
          "Local HTML report generated at %s (CODEMENDER_REPORT_BUCKET not set,"
          " skipped GCS upload).",
          local_report_path,
      )
  else:
    logger.error(
        "Failed to execute 'cm report -f html' (code %d).",
        report_res.returncode,
    )

  logger.info("CodeMender Orchestration completed successfully.")
