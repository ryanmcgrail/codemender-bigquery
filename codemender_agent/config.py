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

"""Configuration injection and environment security module for CodeMender Agent."""

import json
import logging
import os
import sys
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple, TypeVar

import yaml

from codemender_agent.utils import is_dry_run
from codemender_agent.vcs.git import parse_repo_owner_and_name
from codemender_agent.vcs.git import sanitize_git_url
from codemender_agent.vcs.github import GitHubUnauthorizedError
from codemender_agent.vcs.github import get_default_branch
from codemender_agent.vcs.github_app import GitHubAppAuthError
from codemender_agent.vcs.github_app import GitHubAppCredentials
from codemender_agent.vcs.github_app import get_installation_token
from codemender_agent.vcs.github_app import invalidate_installation_token
from codemender_agent.vcs.github_app import wait_for_installation_token

logger = logging.getLogger("codemender-orchestrator")

T = TypeVar("T")

SENSITIVE_ENV_VARS = [
    "GITHUB_APP_TOKEN",
    "GITHUB_APP_ID",
    "GITHUB_APP_PRIVATE_KEY",
    "GITHUB_APP_INSTALLATION_ID",
    # Names used by the GitHub Actions pull request workflow and its callers.
    "GH_APP_ID",
    "GH_APP_KEY",
    "GH_APP_PRIVATE_KEY",
    "GITHUB_PAT",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITHUB_SECRET",
    "INPUT_GITHUB_TOKEN",
    "CUSTOM_GITHUB_TOKEN",
    "GCP_SA_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS_JSON",
    "GOOGLE_CREDENTIALS",
    # GitHub Actions runtime tokens. The OIDC request token lets a process
    # mint new identity tokens for the job; `cm` never needs them. (The
    # google-github-actions/auth credentials file embeds its own copy, which is
    # why the workflow moves that file outside the sandbox roots.)
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_RUNTIME_TOKEN",
]

# Every variable starting with one of these prefixes is removed as well.
SENSITIVE_ENV_PREFIXES = ("WIZ_", "GH_APP_", "GITHUB_APP_")

# Substrings that mark an environment variable name as credential-like. Only
# used to log which such *names* reach `cm` (never their values).
_CREDENTIAL_NAME_MARKERS = (
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PRIVATE",
    "CREDENTIAL",
    "_KEY",
)

# Pull Request remediation routing modes.
#   review_suggestion: Post inline GitHub ```suggestion review comments enabling
#                      one-click "Commit suggestion" application on the PR.
#   child_pr:          Push a remediation branch and open a Child Pull Request
#                      targeting the developer's feature branch.
PR_MODE_REVIEW_SUGGESTION = "review_suggestion"
PR_MODE_CHILD_PR = "child_pr"
VALID_PR_REMEDIATION_MODES = (PR_MODE_REVIEW_SUGGESTION, PR_MODE_CHILD_PR)


def is_presubmit_pipeline() -> bool:
  """Returns True when the 4-stage PR pre-submit pipeline is active."""
  return (
      os.environ.get("CODEMENDER_PRESUBMIT_PIPELINE", "").strip().lower()
      == "true"
  )


@dataclass(frozen=True)
class OrchestratorConfig:
  """Centralized immutable configuration for the CodeMender Orchestrator."""

  # CodeMender CLI Version & AI Models
  cli_version: str = "preview"
  model: Optional[str] = None
  find_model: Optional[str] = None
  verify_model: Optional[str] = None
  fix_model: Optional[str] = None
  skip_exploit_verification: bool = False
  skip_verify: bool = True

  # Workspace & Execution Environment
  workspace_dir: str = ""
  worker_index: Optional[int] = None
  total_workers: Optional[int] = None
  target_sha: Optional[str] = None
  github_output: Optional[str] = None
  github_step_summary: Optional[str] = None

  # Storage & Manifest Configuration
  scan_id: Optional[str] = None
  gcs_bucket: Optional[str] = None
  report_bucket: Optional[str] = None
  storage_mode: str = "gcs"
  base_workspace_url: Optional[str] = None
  partition_urls: Optional[str] = None
  upload_urls: Optional[str] = None
  metadata_urls: Optional[str] = None
  intermediate_retention_days: int = 3

  # VCS & GitHub Integration
  repo_url: Optional[str] = None
  github_token: Optional[str] = None
  # GitHub App authentication (GITHUB_APP_ID / GITHUB_APP_PRIVATE_KEY /
  # GITHUB_APP_INSTALLATION_ID). When any of these is set, the App is used and
  # `github_token` is ignored; see `get_github_credentials`.
  github_app_id: Optional[str] = None
  github_app_private_key: Optional[str] = field(default=None, repr=False)
  github_app_installation_id: Optional[str] = None
  build_command: Optional[str] = None
  scan_target: str = "."
  max_tasks: int = 20
  force_overwrite: bool = False
  # Dry run (CODEMENDER_DRY_RUN): no GitHub writes and no remote duplicate
  # checks. The GitHub helpers in `codemender_agent/vcs/` read the same
  # variable directly via `utils.is_dry_run()`, so the guarantee holds even
  # for a code path that is not handed this config.
  dry_run: bool = False

  # Pull Request Scoped Parameters
  is_pr_scan: bool = False
  pr_base_ref: Optional[str] = None
  pr_head_ref: Optional[str] = None
  is_fork_pr: bool = False
  pr_number: Optional[int] = None
  fail_on_findings: bool = False
  min_blocking_severity: str = "MEDIUM"
  diff_scoped_pr_scan: bool = True
  pr_remediation_mode: str = PR_MODE_REVIEW_SUGGESTION

  # Scheduled / Branch Scan Parameters
  target_branch: Optional[str] = None
  execution_url: Optional[str] = None
  upload_empty_sarif: bool = False

  # BigQuery Analytics Telemetry (opt-in; unset dataset disables export
  # entirely).
  #
  # NOTE: these fields mirror the environment for introspection and testing;
  # they are not the source of truth. `codemender_agent/telemetry/bigquery.py`
  # reads the same CODEMENDER_BQ_* variables directly, because it must stay
  # usable from the failure guard -- which has to work even when constructing
  # an OrchestratorConfig is itself what failed. Mutating these fields after
  # `from_env()` therefore does not change export behaviour.
  bq_dataset: Optional[str] = None
  bq_project: Optional[str] = None
  bq_include_snippets: bool = False

  # Sandbox & Security Settings
  sandbox_enabled: bool = True
  sandbox_network_profile: str = "permissive-open"
  # When the `cm` sandbox cannot start at all, re-run that session with
  # `--unrestricted` only if this is set (CODEMENDER_ALLOW_UNSANDBOXED_FALLBACK).
  allow_unsandboxed_fallback: bool = False
  cleanup_ports: List[int] = field(
      default_factory=lambda: [3000, 3001, 5000, 8000, 8080, 8081, 9000]
  )

  @classmethod
  def from_env(cls) -> "OrchestratorConfig":
    """Loads configuration from environment variables safely in one place."""
    # 1. Parse CLI Version and Model Hierarchies
    cli_version = os.environ.get("CODEMENDER_CLI_VERSION", "preview").lower()
    model = (os.environ.get("CODEMENDER_MODEL") or "").strip() or None
    find_model = (
        os.environ.get("CODEMENDER_FIND_MODEL")
        or os.environ.get("FIND_MODEL")
        or ""
    ).strip() or model
    verify_model = (
        os.environ.get("CODEMENDER_VERIFY_MODEL")
        or os.environ.get("VERIFY_MODEL")
        or ""
    ).strip() or model
    fix_model = (
        os.environ.get("CODEMENDER_FIX_MODEL")
        or os.environ.get("FIX_MODEL")
        or ""
    ).strip() or model
    skip_exploit = (
        os.environ.get("CODEMENDER_SKIP_EXPLOIT_VERIFICATION")
        or os.environ.get("SKIP_EXPLOIT_VERIFICATION")
        or "false"
    ).lower() == "true"
    skip_verify = (
        os.environ.get("CODEMENDER_SKIP_VERIFY", "true").strip().lower()
        in ("true", "1", "yes")
    )

    # 2. Parse Workspace Directories and Runner Step Outputs
    workspace_dir = (
        os.environ.get("WORKSPACE_DIR")
        or os.environ.get("GITHUB_WORKSPACE")
        or os.getcwd()
    )
    github_output = os.environ.get("GITHUB_OUTPUT")
    github_step_summary = os.environ.get("GITHUB_STEP_SUMMARY")

    # 3. Parse Storage Mode and Storage Identifiers
    scan_id = os.environ.get("CODEMENDER_SCAN_ID") or os.environ.get("SCAN_ID")
    gcs_bucket = os.environ.get("CODEMENDER_GCS_BUCKET")
    report_bucket = os.environ.get("CODEMENDER_REPORT_BUCKET") or gcs_bucket

    storage_mode_env = os.environ.get("CODEMENDER_STORAGE_MODE")
    if storage_mode_env:
      storage_mode = storage_mode_env.strip().lower()
    elif os.environ.get("GITHUB_ACTIONS", "").lower() == "true":
      storage_mode = "github_actions"
    else:
      storage_mode = "gcs"

    try:
      intermediate_retention_days = int(
          os.environ.get("CODEMENDER_INTERMEDIATE_RETENTION_DAYS", "3")
      )
    except ValueError:
      intermediate_retention_days = 3

    # 4. Parse Worker Task Identifiers and Manifest Signed URLs
    worker_idx_env = (
        os.environ.get("CODEMENDER_WORKER_INDEX")
        or os.environ.get("WORKER_INDEX")
        or os.environ.get("CLOUD_RUN_TASK_INDEX")
    )
    worker_index = int(worker_idx_env) if worker_idx_env is not None and str(worker_idx_env).isdigit() else None

    total_workers_env = os.environ.get("CODEMENDER_TOTAL_WORKERS") or os.environ.get(
        "CLOUD_RUN_TASK_COUNT"
    )
    total_workers = int(total_workers_env) if total_workers_env is not None and str(total_workers_env).isdigit() else None

    target_sha = (
        os.environ.get("CODEMENDER_TARGET_SHA")
        or os.environ.get("TARGET_SHA")
        or os.environ.get("GITHUB_SHA")
    )
    base_workspace_url = os.environ.get("CODEMENDER_BASE_WORKSPACE_URL")
    partition_urls = os.environ.get("CODEMENDER_PARTITION_URLS")
    upload_urls = os.environ.get("CODEMENDER_UPLOAD_URLS")
    metadata_urls = os.environ.get("CODEMENDER_METADATA_URLS")

    # 5. Parse Repository Metadata and Credentials
    repo_url = os.environ.get("GITHUB_REPO_URL")
    github_token = (
        os.environ.get("GITHUB_APP_TOKEN")
        or os.environ.get("GITHUB_PAT")
        or os.environ.get("GH_TOKEN")
        or os.environ.get("GITHUB_TOKEN")
    )
    github_app_id = (os.environ.get("GITHUB_APP_ID") or "").strip() or None
    github_app_private_key = (
        os.environ.get("GITHUB_APP_PRIVATE_KEY") or ""
    ).strip() or None
    github_app_installation_id = (
        os.environ.get("GITHUB_APP_INSTALLATION_ID") or ""
    ).strip() or None
    build_command = os.environ.get("CODEMENDER_BUILD_COMMAND") or os.environ.get(
        "BUILD_COMMAND"
    )
    scan_target = (
        os.environ.get("CODEMENDER_SCAN_TARGET")
        or os.environ.get("SCAN_TARGET")
        or os.environ.get("DEFAULT_SCAN_TARGET")
        or "."
    )
    try:
      max_tasks = int(
          os.environ.get("CODEMENDER_MAX_TASKS")
          or os.environ.get("MAX_TASKS")
          or "20"
      )
    except ValueError:
      max_tasks = 20

    force_overwrite = (
        os.environ.get("CODEMENDER_FORCE_OVERWRITE", "false").lower() == "true"
    )
    dry_run = is_dry_run()

    # 6. Parse Pull Request Detection Parameters
    is_pr_env = os.environ.get("CODEMENDER_IS_PR_SCAN") or os.environ.get("IS_PR")
    if is_pr_env is not None and is_pr_env.strip():
      is_pr_scan = is_pr_env.strip().lower() == "true"
    else:
      is_pr_scan = (
          os.environ.get("GITHUB_EVENT_NAME") == "pull_request"
          or bool(
              os.environ.get("CODEMENDER_PR_BASE_REF")
              or os.environ.get("BASE_REF")
              or os.environ.get("GITHUB_BASE_REF")
          )
      )
    pr_base_ref = (
        os.environ.get("CODEMENDER_PR_BASE_REF")
        or os.environ.get("BASE_REF")
        or os.environ.get("GITHUB_BASE_REF")
    )
    if pr_base_ref:
      pr_base_ref = pr_base_ref.strip()
    pr_head_ref = os.environ.get("CODEMENDER_PR_HEAD_REF") or os.environ.get("GITHUB_HEAD_REF")
    if pr_head_ref:
      pr_head_ref = pr_head_ref.strip()
    is_fork_pr = is_pr_scan and (
        os.environ.get("CODEMENDER_IS_FORK_PR", "").lower() == "true"
    )

    pr_num_env = (
        os.environ.get("CODEMENDER_PR_NUMBER")
        or os.environ.get("PR_NUMBER")
        or os.environ.get("GITHUB_PR_NUMBER")
    )
    pr_number = None
    if pr_num_env:
      try:
        pr_number = int(str(pr_num_env).strip())
      except ValueError:
        pr_number = None

    fail_on_findings_env = (
        os.environ.get("BLOCK_PR_MERGE")
        or os.environ.get("CODEMENDER_BLOCK_PR_MERGE")
        or os.environ.get("FAIL_ON_FINDINGS")
        or os.environ.get("CODEMENDER_FAIL_ON_FINDINGS")
    )
    if fail_on_findings_env is not None and fail_on_findings_env.strip():
      fail_on_findings = fail_on_findings_env.strip().lower() not in (
          "false",
          "0",
          "no",
          "off",
      )
    elif (
        is_pr_scan
        or bool(pr_number)
        or is_presubmit_pipeline()
        or os.environ.get("CODEMENDER_RUN_MODE", "").lower()
        in ("gate", "security_gate")
    ):
      # Default to True on PR scans (blocking security gate)
      fail_on_findings = True
    else:
      fail_on_findings = False

    min_blocking_severity = (
        os.environ.get("CODEMENDER_MIN_BLOCKING_SEVERITY")
        or os.environ.get("MIN_BLOCKING_SEVERITY")
        or os.environ.get("MIN_SEVERITY")
        or "MEDIUM"
    ).strip().upper()
    diff_scoped_env = (
        os.environ.get("CODEMENDER_DIFF_SCOPED_PR_SCAN")
        or os.environ.get("DIFF_SCOPED")
        or "true"
    ).strip().lower()
    diff_scoped_pr_scan = diff_scoped_env not in ("false", "0", "no", "off")

    # Parse PR remediation routing mode, falling back to the default when unset
    # or when an unrecognized value is supplied.
    mode_env = (os.environ.get("CODEMENDER_PR_REMEDIATION_MODE") or "").strip().lower()
    if mode_env and mode_env not in VALID_PR_REMEDIATION_MODES:
      logger.warning(
          "Unrecognized CODEMENDER_PR_REMEDIATION_MODE '%s' (expected one of %s)."
          " Falling back to '%s'.",
          mode_env,
          ", ".join(VALID_PR_REMEDIATION_MODES),
          PR_MODE_REVIEW_SUGGESTION,
      )
    pr_remediation_mode = (
        mode_env
        if mode_env in VALID_PR_REMEDIATION_MODES
        else PR_MODE_REVIEW_SUGGESTION
    )

    # 7. Parse Sandbox and Cleanup Port Configurations
    sandbox_env = os.environ.get("CODEMENDER_SANDBOX_ENABLED") or os.environ.get(
        "SANDBOX_ENABLED"
    )
    if sandbox_env is not None and sandbox_env.strip():
      sandbox_enabled = sandbox_env.strip().lower() not in (
          "false",
          "0",
          "no",
          "off",
      )
    elif (
        os.environ.get("GITHUB_ACTIONS", "").lower() == "true"
        or storage_mode == "github_actions"
    ):
      # Default to True when running with container capabilities or local
      sandbox_enabled = True
    else:
      sandbox_enabled = True

    sandbox_network_profile = os.environ.get(
        "CODEMENDER_SANDBOX_NETWORK_PROFILE", "permissive-open"
    )
    allow_unsandboxed_fallback = (
        os.environ.get("CODEMENDER_ALLOW_UNSANDBOXED_FALLBACK", "false")
        .strip()
        .lower()
        in ("true", "1", "yes")
    )

    ports_env = os.environ.get("CODEMENDER_CLEANUP_PORTS")
    if ports_env:
      try:
        cleanup_ports = [
            int(p.strip()) for p in ports_env.split(",") if p.strip()
        ]
      except ValueError:
        cleanup_ports = [3000, 3001, 5000, 8000, 8080, 8081, 9000]
    else:
      cleanup_ports = [3000, 3001, 5000, 8000, 8080, 8081, 9000]

    raw_target_branch = (
        os.environ.get("CODEMENDER_TARGET_BRANCH")
        or os.environ.get("CODEMENDER_SCAN_REF")
        or ""
    ).strip()
    if raw_target_branch.startswith("refs/heads/"):
      raw_target_branch = raw_target_branch[len("refs/heads/") :]
    target_branch = raw_target_branch or None
    execution_url = (
        os.environ.get("CODEMENDER_EXECUTION_URL") or ""
    ).strip() or None
    upload_empty_sarif = (
        os.environ.get("CODEMENDER_UPLOAD_EMPTY_SARIF", "false").strip().lower()
        in ("true", "1", "yes")
    )

    # 8. Parse BigQuery Analytics Telemetry configuration.
    # An empty/unset dataset is the master off-switch: the exporter performs
    # zero BigQuery calls in that case, so telemetry is strictly opt-in.
    bq_dataset = (os.environ.get("CODEMENDER_BQ_DATASET") or "").strip() or None
    bq_project = (
        (os.environ.get("CODEMENDER_BQ_PROJECT") or "").strip()
        or (os.environ.get("GOOGLE_CLOUD_PROJECT") or "").strip()
        or None
    )
    # Default OFF: `analysis` and `snippet` carry LLM prose and verbatim source
    # code, which many regulated deployments may not replicate into a warehouse.
    bq_include_snippets = (
        os.environ.get("CODEMENDER_BQ_INCLUDE_SNIPPETS", "false").strip().lower()
        in ("true", "1", "yes")
    )

    # Return immutable configuration dataclass instance populated from parsed environment
    return cls(
        # AI models and CLI versions
        cli_version=cli_version,
        model=model,
        find_model=find_model,
        verify_model=verify_model,
        fix_model=fix_model,
        skip_exploit_verification=skip_exploit,
        skip_verify=skip_verify,
        # Execution environment and worker coordinates
        workspace_dir=workspace_dir,
        worker_index=worker_index,
        total_workers=total_workers,
        target_sha=target_sha,
        github_output=github_output,
        github_step_summary=github_step_summary,
        # Storage identifiers and retention policies
        scan_id=scan_id,
        gcs_bucket=gcs_bucket,
        report_bucket=report_bucket,
        storage_mode=storage_mode,
        base_workspace_url=base_workspace_url,
        partition_urls=partition_urls,
        upload_urls=upload_urls,
        metadata_urls=metadata_urls,
        intermediate_retention_days=intermediate_retention_days,
        # Repository credentials and scan constraints
        repo_url=repo_url,
        github_token=github_token,
        github_app_id=github_app_id,
        github_app_private_key=github_app_private_key,
        github_app_installation_id=github_app_installation_id,
        build_command=build_command,
        scan_target=scan_target,
        max_tasks=max_tasks,
        force_overwrite=force_overwrite,
        dry_run=dry_run,
        # Pull request detection and routing coordinates
        is_pr_scan=is_pr_scan,
        pr_base_ref=pr_base_ref,
        pr_head_ref=pr_head_ref,
        is_fork_pr=is_fork_pr,
        pr_number=pr_number,
        fail_on_findings=fail_on_findings,
        min_blocking_severity=min_blocking_severity,
        diff_scoped_pr_scan=diff_scoped_pr_scan,
        pr_remediation_mode=pr_remediation_mode,
        # Scheduled / branch scan parameters
        target_branch=target_branch,
        execution_url=execution_url,
        upload_empty_sarif=upload_empty_sarif,
        # BigQuery analytics telemetry (opt-in)
        bq_dataset=bq_dataset,
        bq_project=bq_project,
        bq_include_snippets=bq_include_snippets,
        # Sandbox execution flags and network isolation profiles
        sandbox_enabled=sandbox_enabled,
        sandbox_network_profile=sandbox_network_profile,
        allow_unsandboxed_fallback=allow_unsandboxed_fallback,
        cleanup_ports=cleanup_ports,
    )


def resolve_pr_remediation_mode(config: "OrchestratorConfig") -> str:
  """Resolves the effective PR remediation mode for the current scan.

  Fork Pull Requests always use inline review suggestions: CodeMender cannot
  push remediation branches across the fork boundary (HTTP 403), so the
  `pr_remediation_mode` flag only governs internal Pull Requests.
  """
  if config.is_fork_pr:
    return PR_MODE_REVIEW_SUGGESTION
  return config.pr_remediation_mode


def get_scrubbed_env(repo_dir: Optional[str] = None) -> Dict[str, str]:
  """Returns a copy of environment variables with sensitive credentials removed and local sandbox cache paths configured.

  This prevents credential exfiltration during untrusted LLM code execution
  inside the child subprocesses and redirects tool cache directories into repo_dir.
  """
  env = dict(os.environ)
  for var in SENSITIVE_ENV_VARS:
    if var in env:
      del env[var]
  # Wiz credentials (and any other WIZ_* setting) are only ever handed to
  # wizcli itself, never to CodeMender or the code it executes. GitHub App
  # settings (GH_APP_*, GITHUB_APP_*) are only used by the orchestrator to
  # mint installation tokens.
  for var in [k for k in env if k.upper().startswith(SENSITIVE_ENV_PREFIXES)]:
    del env[var]

  sandbox_disabled = env.get(
      "CODEMENDER_SANDBOX_ENABLED", "true"
  ).strip().lower() in (
      "false",
      "0",
      "no",
      "off",
  )
  if sandbox_disabled:
    env["CM_DISABLE_SANDBOX"] = "true"

  if repo_dir:
    cache_dir = os.path.join(repo_dir, ".codemender_cache")
    tmp_dir = os.path.join(cache_dir, "tmp")
    npm_dir = os.path.join(cache_dir, "npm")
    pip_dir = os.path.join(cache_dir, "pip")
    try:
      os.makedirs(tmp_dir, exist_ok=True)
      os.makedirs(npm_dir, exist_ok=True)
      os.makedirs(pip_dir, exist_ok=True)
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.warning("Could not initialize .codemender_cache directory: %s", e)

    env["XDG_CACHE_HOME"] = cache_dir
    env["npm_config_cache"] = npm_dir
    env["TEMP"] = tmp_dir
    env["TMP"] = tmp_dir
    env["PIP_CACHE_DIR"] = pip_dir
    if sandbox_disabled:
      env["TMPDIR"] = tmp_dir
    else:
      # `cm` adds its own temporary directory (Go's os.TempDir(), i.e.
      # $TMPDIR or /tmp) to the sandbox's denied paths, and the sandboxed
      # tools inherit the same environment. Pointing TMPDIR at the workspace
      # scratch directory therefore made that directory unusable inside the
      # sandbox. Leave TMPDIR unset so only /tmp is denied (as `cm` intends);
      # Python, pip and Node fall back to TEMP/TMP above. The Go toolchain
      # only reads TMPDIR, so point its scratch directory there explicitly
      # (GOTMPDIR is not read by `cm` itself).
      env.pop("TMPDIR", None)
      env["GOTMPDIR"] = tmp_dir

  return env


def credential_like_env_names(env: Dict[str, str]) -> List[str]:
  """Returns the sorted names (never values) of credential-like variables in env.

  Used to log what reaches `cm` so operators can confirm that no GitHub token
  or App key is passed on. `GOOGLE_APPLICATION_CREDENTIALS` (and the gcloud
  override that points at the same file) is expected in GitHub Actions: it
  is how `cm` reaches Vertex AI.
  """
  return sorted(
      k for k in env if any(m in k.upper() for m in _CREDENTIAL_NAME_MARKERS)
  )


def github_app_configured(config: OrchestratorConfig) -> bool:
  """Whether any GitHub App setting is present.

  A partial configuration still counts, so that it fails loudly in
  `get_github_credentials` instead of silently falling back to a personal
  access token.
  """
  return bool(
      config.github_app_id
      or config.github_app_private_key
      or config.github_app_installation_id
  )


def _mint_github_app_token(config: OrchestratorConfig, repo_url: str) -> str:
  """Returns a GitHub App installation token for the configured repository."""
  credentials = GitHubAppCredentials.from_values(
      config.github_app_id,
      config.github_app_private_key,
      config.github_app_installation_id,
  )
  owner, repo = parse_repo_owner_and_name(sanitize_git_url(repo_url))
  return get_installation_token(credentials, owner, repo)


def get_github_credentials(
    config: Optional[OrchestratorConfig] = None,
) -> Tuple[str, str]:
  """Retrieves repo URL and GitHub access token from configuration or environment.

  When a GitHub App is configured (GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY,
  optionally GITHUB_APP_INSTALLATION_ID), the token is an installation token
  minted for the repository and cached for the process. Calling this again
  returns the cached token until it nears expiry, then a fresh one, so
  long-running stages should call it (or `refresh_github_token`) right before
  each batch of GitHub operations. Otherwise the static token from
  GITHUB_APP_TOKEN, GITHUB_PAT or GITHUB_TOKEN is returned unchanged.

  Raises:
    ValueError: The repository URL or every credential is missing.
    GitHubAppAuthError: A GitHub App is configured but no token could be
      minted. There is deliberately no fallback to a static token, so a
      broken App configuration cannot silently attribute changes to a
      personal account.
  """
  cfg = config or OrchestratorConfig.from_env()

  # 1. Validate repository URL
  repo_url = cfg.repo_url
  if not repo_url:
    logger.error("Environment variable GITHUB_REPO_URL is required.")
    raise ValueError("Environment variable GITHUB_REPO_URL is required.")

  # 2. GitHub App installation token (takes precedence over static tokens)
  if github_app_configured(cfg):
    if cfg.github_token:
      logger.debug(
          "GitHub App authentication is configured; ignoring the static"
          " GITHUB_APP_TOKEN/GITHUB_PAT/GITHUB_TOKEN value."
      )
    return repo_url.strip(), _mint_github_app_token(cfg, repo_url)

  # 3. Validate static GitHub authentication token
  token = cfg.github_token
  if not token:
    logger.error(
        "One of GITHUB_APP_TOKEN, GITHUB_PAT, or GITHUB_TOKEN environment"
        " variables (or GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY) is required."
    )
    # Raise configuration error if no GitHub credential token is present
    raise ValueError(
        "One of GITHUB_APP_TOKEN, GITHUB_PAT, or GITHUB_TOKEN environment"
        " variables (or GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY) is required."
    )

  # Return cleaned repository URL and authentication token
  return repo_url.strip(), token.strip()


def refresh_github_token(config: OrchestratorConfig, token: str) -> str:
  """Returns a token that is safe to use for the next batch of GitHub calls.

  With a GitHub App this returns the cached installation token, minting a new
  one if it is close to expiry. Without one the static `token` is returned
  unchanged, so call sites behave exactly as before.
  """
  if not github_app_configured(config):
    return token
  _, fresh_token = get_github_credentials(config=config)
  return fresh_token


def reset_github_token(
    config: OrchestratorConfig, rejected_token: str
) -> Optional[str]:
  """Discards an installation token GitHub rejected and returns a new one.

  Only the cached token equal to `rejected_token` is discarded, so several
  callers reporting the same stale token cause one re-mint. GitHub can reject
  a token for a few seconds after minting it, so this returns only once the
  new token is `NEW_TOKEN_SETTLE_SECONDS` old.

  Returns:
    A freshly minted installation token, or None when no GitHub App is
    configured (a static token cannot be replaced).

  Raises:
    GitHubAppAuthError: A new token could not be minted.
  """
  if not github_app_configured(config):
    return None
  credentials = GitHubAppCredentials.from_values(
      config.github_app_id,
      config.github_app_private_key,
      config.github_app_installation_id,
  )
  owner, repo = parse_repo_owner_and_name(
      sanitize_git_url((config.repo_url or "").strip())
  )
  invalidate_installation_token(credentials, owner, repo, rejected_token)
  fresh_token = refresh_github_token(config, rejected_token)
  wait_for_installation_token(credentials, owner, repo, fresh_token)
  return fresh_token


def call_with_github_token(
    config: OrchestratorConfig,
    token: str,
    call: Callable[[str], T],
) -> Tuple[T, str]:
  """Runs `call(token)`, recovering once from a token GitHub rejects.

  On `GitHubUnauthorizedError` (HTTP 401) the installation token is
  discarded, a new one is minted and `call` runs once more with it. A second
  401, a static token (which cannot be replaced) or a failed re-mint
  propagates, so the caller fails closed instead of acting on a guess.

  Returns:
    Tuple of (call result, token that produced it). Callers should keep
    using the returned token.
  """
  try:
    return call(token), token
  except GitHubUnauthorizedError as e:
    fresh_token = reset_github_token(config, token)
    if not fresh_token:
      raise
    logger.warning(
        "GitHub rejected the installation token (%s); retrying once with a"
        " newly minted token.",
        e,
    )
    return call(fresh_token), fresh_token


def read_default_branch(
    config: OrchestratorConfig,
    token: str,
    owner: str,
    repo: str,
    lookup: Callable[..., str] = get_default_branch,
) -> Tuple[Optional[str], str]:
  """Reads the default branch, replacing a rejected App token once.

  For uploads that must target the right branch (SARIF). When GitHub keeps
  rejecting the token, or a new token cannot be minted, the error is logged
  and None is returned so the caller skips the upload instead of guessing
  "main". Other API failures keep `get_default_branch`'s "main" fallback.

  Args:
    lookup: `get_default_branch`, or a stand-in with the same signature.

  Returns:
    Tuple of (branch or None, token to keep using).
  """
  try:
    return call_with_github_token(
        config,
        token,
        lambda tok: lookup(tok, owner, repo, fail_on_unauthorized=True),
    )
  except (GitHubUnauthorizedError, GitHubAppAuthError) as e:
    logger.error(
        "Could not read the default branch of %s/%s because GitHub rejected"
        " the token: %s",
        owner,
        repo,
        e,
    )
    return None, token


def detect_build_command(repo_dir: str) -> Optional[str]:
  """Auto-detects default build/test command from repository structure."""
  # 1. Node.js (package.json)
  pkg_json = os.path.join(repo_dir, "package.json")
  if os.path.exists(pkg_json):
    try:
      with open(pkg_json, "r", encoding="utf-8") as f:
        data = json.load(f)
      if "scripts" in data and "test" in data["scripts"]:
        return "npm test"
    except Exception:
      return "npm test"

  # 2. Python (pytest / pyproject.toml / setup.py / tox.ini / requirements.txt)
  if any(
      os.path.exists(os.path.join(repo_dir, f))
      for f in [
          "pytest.ini",
          "pyproject.toml",
          "setup.py",
          "tox.ini",
          "requirements.txt",
      ]
  ):
    return "pytest"

  # 3. Java (Maven / Gradle)
  if os.path.exists(os.path.join(repo_dir, "pom.xml")):
    return "mvn test"
  if any(
      os.path.exists(os.path.join(repo_dir, f))
      for f in ["build.gradle", "build.gradle.kts"]
  ):
    return (
        "./gradlew test"
        if os.path.exists(os.path.join(repo_dir, "gradlew"))
        else "gradle test"
    )

  # 4. Go (go.mod)
  if os.path.exists(os.path.join(repo_dir, "go.mod")):
    return "go test ./..."

  # 5. Rust (Cargo.toml)
  if os.path.exists(os.path.join(repo_dir, "Cargo.toml")):
    return "cargo test"

  return None


def inject_codemender_config(
    repo_dir: str,
    config: Optional[OrchestratorConfig] = None,
    *,
    for_remediation: bool = False,
) -> None:
  """Reads project-level and environment configs and merges them into ~/.codemender/config.yaml.

  Args:
    repo_dir: The checked-out repository the cm commands run in.
    config: The orchestrator configuration; read from the environment if None.
    for_remediation: Set when the following cm commands are `cm verify` and
      `cm fix` rather than `cm find`. The default `project_paths` then becomes
      the repository root instead of empty. cm derives each finding's project
      root from `project_paths`, falling back to the finding file's own
      directory when it is empty, and runs the configured build command,
      workspace reset, artifact restore and patch capture there. A build
      command such as `mvn ... compile` only works from the directory that
      holds the build file, which is normally the repository root. A
      `project_paths` set in the repository's own config file still wins.
  """
  cfg = config or OrchestratorConfig.from_env()
  home_dir = os.path.expanduser("~")
  global_config_path = os.path.join(home_dir, ".codemender", "config.yaml")

  # 1. Load global default config created by 'cm init'
  if os.path.exists(global_config_path):
    try:
      with open(global_config_path, "r", encoding="utf-8") as f:
        config_data = yaml.safe_load(f) or {}
    except Exception as e:
      logger.warning("Could not read global config.yaml: %s. Re-creating.", e)
      config_data = {}
  else:
    config_data = {}

  # Initialize top-level sections if missing to prevent KeyError during deep merge
  if "build" not in config_data or config_data["build"] is None:
    config_data["build"] = {}
  if "vcs" not in config_data or config_data["vcs"] is None:
    config_data["vcs"] = {}
  if (
      "commands" not in config_data["vcs"]
      or config_data["vcs"]["commands"] is None
  ):
    config_data["vcs"]["commands"] = {}

  # 2. Defaults (VCS is always git inside the orchestrator clone)
  config_data["vcs"]["type"] = "git"
  if "commands" not in config_data["vcs"] or config_data["vcs"]["commands"] is None:
    config_data["vcs"]["commands"] = {}
  if "reset" not in config_data["vcs"]["commands"]:
    config_data["vcs"]["commands"]["reset"] = "git checkout HEAD -- . && git clean -fd"

  # Leave project_paths empty by default so 'cm find <scanTarget>' scopes allowedRoots
  # strictly to [scanTarget] rather than the entire repository root written by 'cm init'.
  # Verify and fix instead get the repository root, so that cm resolves each
  # finding's project root (where it runs the build command) to the repository
  # rather than to the directory of the finding's file.
  config_data["project_paths"] = (
      [os.path.abspath(repo_dir)] if for_remediation else []
  )

  # 3. Read Repository-Level config (Config-as-Code - takes precedence over defaults)
  project_config = None
  for filename in [
      ".codemender.yaml",
      "codemender.yaml",
      ".codemender.yml",
      "codemender.yml",
  ]:
    local_path = os.path.join(repo_dir, filename)
    if os.path.exists(local_path):
      try:
        with open(local_path, "r", encoding="utf-8") as f:
          project_config = yaml.safe_load(f)
        logger.info("Found repository-level configuration: %s", filename)
        break
      except Exception as e:
        logger.warning("Failed to parse local config file %s: %s", filename, e)

  # Merge repository-level dictionary sections into global configuration
  if project_config and isinstance(project_config, dict):
    # Deep merge the 'build' section
    if "build" in project_config and isinstance(project_config["build"], dict):
      config_data["build"].update(project_config["build"])

    # Deep merge the 'vcs' section preserving specific commands
    if "vcs" in project_config and isinstance(project_config["vcs"], dict):
      if "commands" in project_config["vcs"] and isinstance(
          project_config["vcs"]["commands"], dict
      ):
        config_data["vcs"]["commands"].update(project_config["vcs"]["commands"])
      for k, v in project_config["vcs"].items():
        if k != "commands":
          config_data["vcs"][k] = v

    # Copy standard configured sections directly
    for key in ["scan", "project_paths", "output", "tools", "sandbox", "security", "model"]:
      if key in project_config:
        config_data[key] = project_config[key]

    # Re-normalize project_paths if overwritten by project_config to ensure absolute paths
    if "project_paths" in project_config and isinstance(project_config["project_paths"], list):
      config_data["project_paths"] = [
          p if os.path.isabs(p) else os.path.abspath(os.path.join(repo_dir, p))
          for p in project_config["project_paths"]
      ]

  # 4. Read Environment Variable configurations or auto-detect build command (Env Overrides take top precedence)
  effective_build_cmd = None
  if cfg.build_command and cfg.build_command.strip().strip("'\""):
    effective_build_cmd = cfg.build_command.strip().strip("'\"")
    logger.info(
        "Applying env override CODEMENDER_BUILD_COMMAND: %s", effective_build_cmd
    )
  elif not config_data["build"].get("command"):
    detected_cmd = detect_build_command(repo_dir)
    if detected_cmd:
      effective_build_cmd = detected_cmd
      logger.info(
          "Auto-detected project build/test command: %s", detected_cmd
      )

  if effective_build_cmd:
    config_data["build"]["command"] = effective_build_cmd

  has_repo_model = bool(
      project_config
      and isinstance(project_config, dict)
      and str(project_config.get("model") or "").strip()
  )
  if cfg.model:
    config_data["model"] = cfg.model.strip()
  elif not has_repo_model:
    config_data.pop("model", None)

  # 5. Sandbox Configuration (Enabled by default with absolute target mounts)
  if "sandbox" not in config_data or config_data["sandbox"] is None:
    config_data["sandbox"] = {}
  if "mounts" not in config_data["sandbox"] or config_data["sandbox"]["mounts"] is None:
    config_data["sandbox"]["mounts"] = {}
  if "network" not in config_data["sandbox"] or config_data["sandbox"]["network"] is None:
    config_data["sandbox"]["network"] = {}

  # Set sandbox enablement and network profile from central OrchestratorConfig
  config_data["sandbox"]["enabled"] = cfg.sandbox_enabled
  config_data["sandbox"]["mounts"]["target_dir"] = os.path.abspath(repo_dir)
  config_data["sandbox"]["network"]["profile"] = cfg.sandbox_network_profile

  # 6. Interactive Terminal Prompt Fallback (if no build command configured)
  if not config_data["build"].get("command"):
    if sys.stdin.isatty():
      try:
        prompt_cmd = input(
            "\n⚠️  No build command configured for this project.\nPlease enter"
            " the build/test command (e.g., 'npm test') or press Enter to"
            " skip: "
        ).strip()
        if prompt_cmd:
          config_data["build"]["command"] = prompt_cmd
      except (KeyboardInterrupt, EOFError):
        logger.warning("\nPrompt interrupted. Skipping build command.")
    else:
      logger.warning(
          "No build command configured (running in headless environment)."
          " Post-fix verification will be skipped."
      )

  # 7. Force disable confirmations for headless execution safety (AFTER repository config merge)
  if "tools" not in config_data or config_data["tools"] is None:
    config_data["tools"] = {}
  config_data["tools"]["confirm_commands"] = False
  config_data["tools"]["confirm_writes"] = False

  # 8. Save the merged configuration back to ~/.codemender/config.yaml using atomic rename
  try:
    os.makedirs(os.path.dirname(global_config_path), exist_ok=True)
    tmp_config_path = global_config_path + ".tmp"
    with open(tmp_config_path, "w", encoding="utf-8") as f:
      yaml.safe_dump(config_data, f, default_flow_style=False)
    os.replace(tmp_config_path, global_config_path)
    logger.info(
        "Successfully injected configurations into %s", global_config_path
    )
  except Exception as e:
    logger.error("Failed to write global config.yaml: %s", e)


def get_cleanup_ports(config: Optional[OrchestratorConfig] = None) -> List[int]:
  """Retrieves the list of ports to free before verification tasks."""
  cfg = config or OrchestratorConfig.from_env()
  return cfg.cleanup_ports


