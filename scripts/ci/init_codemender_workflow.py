#!/usr/bin/env python3
"""Bootstrap script to generate .github/workflows/codemender.yml for CI/CD onboarding.

Supports two execution modes:
1. `reusable` (default): Calls `.github/workflows/codemender_parallel.yml` from
   your organization's CodeMender repository (or a local copy when
   `--copy-reusable-workflow` is set).
2. `standalone`: Generates the 4-stage Pre-Submit Security Gate workflow
   (`scan`, `security-gate`, `worker`, `aggregate`) that checks out the
   orchestrator into `.codemender_agent` and runs `orchestrator.py` directly on
   standard GitHub-hosted Ubuntu runners.
"""

from __future__ import annotations

import argparse
import pathlib
import shutil
import subprocess
import sys
from typing import Optional

VALID_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
PARALLEL_WORKFLOW_SRC = REPO_ROOT / ".github" / "workflows" / "codemender_parallel.yml"
BLOCK_PR_MERGE_VAR = "CODEMENDER_BLOCK_PR_MERGE"
LEGACY_FAIL_ON_FINDINGS_VAR = "CODEMENDER_FAIL_ON_FINDINGS"


def block_pr_merge_selector(
    default_block: bool, *, include_legacy_var: bool = False
) -> str:
  """Returns a GitHub Actions expression that evaluates to 'true' or 'false'.

  Precedence, first match wins:
    1. `inputs.block_pr_merge` set to 'true'/'false' on a manual run (it is
       null on `pull_request` events and 'auto' when left at its default).
    2. Repository variable `CODEMENDER_BLOCK_PR_MERGE` set to 'true'/'false'.
    3. (standalone only) legacy repository variable
       `CODEMENDER_FAIL_ON_FINDINGS` set to 'true'/'false'.
    4. The literal default baked in at generation time.

  Each source contributes `src == 'true' && 'true' || src == 'false' &&
  'false'`. Both result strings are non-empty and therefore truthy, so a
  'false' match stops the `||` chain instead of falling through to the next
  source (the bug in the old `cond && value || fallback` form, where a false
  value fell through to the literal default). GitHub compares strings
  case-insensitively, so 'FALSE' and 'False' match too. Comparing a null or
  unset source to 'true'/'false' is false, so it is skipped.
  """
  sources = ["inputs.block_pr_merge", f"vars.{BLOCK_PR_MERGE_VAR}"]
  if include_legacy_var:
    sources.append(f"vars.{LEGACY_FAIL_ON_FINDINGS_VAR}")
  terms = []
  for src in sources:
    terms.append(f"{src} == 'true' && 'true'")
    terms.append(f"{src} == 'false' && 'false'")
  terms.append("'true'" if default_block else "'false'")
  return " || ".join(terms)


def _block_pr_merge_dispatch_input(default_block: bool) -> str:
  """Renders the `block_pr_merge` workflow_dispatch input (a 3-way choice).

  A boolean input always carries a value on manual runs, so it would hide the
  repository variable; 'auto' defers to the variable, then the default.
  """
  default_str = "true" if default_block else "false"
  return f"""      block_pr_merge:
        description: 'Block PR merge on findings >= min_blocking_severity. auto = use repository variable {BLOCK_PR_MERGE_VAR}, else the generated default ({default_str})'
        required: false
        default: 'auto'
        type: choice
        options:
          - 'auto'
          - 'true'
          - 'false'"""


def detect_build_command(target_dir: pathlib.Path) -> str:
  """Infers a default test/build command from common project manifest files."""
  if (target_dir / "package.json").is_file():
    return "npm test"
  if (target_dir / "pyproject.toml").is_file() or (
      target_dir / "pytest.ini"
  ).is_file() or (target_dir / "setup.py").is_file():
    return "pytest"
  if (target_dir / "go.mod").is_file():
    return "go test ./..."
  if (target_dir / "Cargo.toml").is_file():
    return "cargo test"
  if (target_dir / "pom.xml").is_file():
    return "mvn test"
  if (target_dir / "build.gradle").is_file() or (
      target_dir / "build.gradle.kts"
  ).is_file():
    return "./gradlew test"
  return ""


def render_reusable_caller_workflow(
    *,
    agent_repo: str,
    agent_ref: str,
    runner_image: str,
    scan_target: str,
    build_command: str,
    min_blocking_severity: str,
    block_pr_merge: bool,
    max_tasks: int,
    local_reusable_copy: bool = False,
) -> str:
  """Renders `.github/workflows/codemender.yml` calling `codemender_parallel.yml`."""
  uses_target = (
      "./.github/workflows/codemender_parallel.yml"
      if local_reusable_copy
      else f"{agent_repo}/.github/workflows/codemender_parallel.yml@{agent_ref}"
  )
  # fromJSON turns the selector's 'true'/'false' string into the boolean the
  # reusable workflow's `block_pr_merge` / `fail_on_findings` inputs expect.
  block_expr = f"fromJSON({block_pr_merge_selector(block_pr_merge)})"
  dispatch_input = _block_pr_merge_dispatch_input(block_pr_merge)
  return f"""name: CodeMender Pre-Submit Security Gate

on:
  pull_request:
    types: [opened, reopened, synchronize, labeled]
  workflow_dispatch:
    inputs:
      scan_target:
        description: 'Subdirectory or file path(s) to scan (default: {scan_target})'
        required: false
        default: '{scan_target}'
        type: string
      build_command:
        description: 'Custom build/test command executed by cm fix'
        required: false
        default: '{build_command}'
        type: string
      min_blocking_severity:
        description: 'Minimum vulnerability severity that blocks merging (CRITICAL, HIGH, MEDIUM, LOW)'
        required: false
        default: '{min_blocking_severity}'
        type: string
{dispatch_input}

permissions:
  id-token: write
  contents: write
  pull-requests: write
  security-events: write
  statuses: write
  actions: read
  packages: read

jobs:
  security-gate:
    if: >-
      github.event_name == 'workflow_dispatch' ||
      (github.event_name == 'pull_request' && (
        contains(github.event.pull_request.labels.*.name, 'codemender-scan') ||
        github.event.action == 'opened' ||
        github.event.action == 'reopened' ||
        github.event.action == 'synchronize'
      ))
    uses: {uses_target}
    with:
      runner_image: '{runner_image}'
      scan_target: ${{{{ inputs.scan_target || '{scan_target}' }}}}
      build_command: ${{{{ inputs.build_command || '{build_command}' }}}}
      max_tasks: {max_tasks}
      min_blocking_severity: ${{{{ inputs.min_blocking_severity || vars.CODEMENDER_MIN_BLOCKING_SEVERITY || '{min_blocking_severity}' }}}}
      block_pr_merge: ${{{{ {block_expr} }}}}
      fail_on_findings: ${{{{ {block_expr} }}}}
    secrets:
      gcp_workload_identity_provider: ${{{{ secrets.GCP_WORKLOAD_IDENTITY_PROVIDER }}}}
      gcp_service_account: ${{{{ secrets.GCP_SERVICE_ACCOUNT }}}}
      gcp_sa_key: ${{{{ secrets.GCP_SA_KEY }}}}
      github_app_id: ${{{{ secrets.GH_APP_ID }}}}
      github_app_private_key: ${{{{ secrets.GH_APP_PRIVATE_KEY }}}}
      custom_github_token: ${{{{ secrets.CUSTOM_GITHUB_TOKEN }}}}
"""


def render_standalone_caller_workflow(
    *,
    agent_repo: str,
    agent_ref: str,
    scan_target: str,
    build_command: str,
    min_blocking_severity: str,
    block_pr_merge: bool,
    max_tasks: int,
    vendor_ref: Optional[str] = None,
) -> str:
  """Renders the 4-stage standalone `.github/workflows/codemender.yml` calling `orchestrator.py`."""
  # Env values stay strings ('true'/'false'); config.py parses them.
  block_expr = block_pr_merge_selector(block_pr_merge, include_legacy_var=True)
  dispatch_input = _block_pr_merge_dispatch_input(block_pr_merge)
  build_env_line = (
      f'\n          CODEMENDER_BUILD_COMMAND: "{build_command}"'
      if build_command
      else ""
  )
  vendor_env_line = (
      f'\n  CODEMENDER_VENDOR_REF: "{vendor_ref}"' if vendor_ref else ""
  )
  checkout_orchestrator_script = """          pip install --quiet pyyaml requests
          if [ -n "$CUSTOM_TOKEN" ] && git clone --depth=1 --branch "${CODEMENDER_AGENT_REF}" "https://x-access-token:${CUSTOM_TOKEN}@github.com/${CODEMENDER_AGENT_REPO}.git" .codemender_agent 2>/dev/null; then
            echo "Checked out ${CODEMENDER_AGENT_REPO}@${CODEMENDER_AGENT_REF} via CUSTOM_GITHUB_TOKEN"
          elif [ -n "${CODEMENDER_VENDOR_REF:-}" ]; then
            git clone --depth=1 --branch "${CODEMENDER_VENDOR_REF}" "https://x-access-token:${DEFAULT_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" .codemender_agent
            echo "Checked out mirrored ${CODEMENDER_AGENT_REPO}@${CODEMENDER_AGENT_REF} from ${CODEMENDER_VENDOR_REF}"
          else
            git clone --depth=1 --branch "${CODEMENDER_AGENT_REF}" "https://x-access-token:${DEFAULT_TOKEN}@github.com/${CODEMENDER_AGENT_REPO}.git" .codemender_agent
          fi"""
  return f"""name: CodeMender Pre-Submit Security Gate

on:
  pull_request:
    branches: [ "main", "master", "release/*", "branch-*", "future" ]
    types: [opened, reopened, synchronize, labeled]
  workflow_dispatch:
    inputs:
      scan_target:
        description: 'Subdirectory or file path(s) to scan (default: diff-scoped on PR)'
        required: false
        default: '{scan_target}'
        type: string
      min_blocking_severity:
        description: 'Minimum vulnerability severity that blocks merging (CRITICAL, HIGH, MEDIUM, LOW)'
        required: false
        default: '{min_blocking_severity}'
        type: string
{dispatch_input}

permissions:
  id-token: write
  contents: write
  pull-requests: write
  security-events: write
  statuses: write
  actions: read

concurrency:
  group: ${{{{ github.workflow }}}}-${{{{ github.event.pull_request.number || github.ref }}}}
  cancel-in-progress: ${{{{ github.event_name == 'pull_request' }}}}

env:
  CODEMENDER_PRESUBMIT_PIPELINE: "true"
  CODEMENDER_AGENT_REPO: "{agent_repo}"
  CODEMENDER_AGENT_REF: "{agent_ref}"{vendor_env_line}
  MIN_BLOCKING_SEVERITY: ${{{{ inputs.min_blocking_severity || vars.CODEMENDER_MIN_BLOCKING_SEVERITY || '{min_blocking_severity}' }}}}
  BLOCK_PR_MERGE: ${{{{ {block_expr} }}}}
  FAIL_ON_FINDINGS: ${{{{ {block_expr} }}}}

jobs:
  # ============================================================================
  # STAGE 1: PREFLIGHT DIFF TARGET RESOLUTION & CM FIND
  # ============================================================================
  scan:
    name: "Stage 1: Scan & Partition (`cm find`)"
    runs-on: ubuntu-latest
    if: >-
      github.event_name != 'pull_request' ||
      github.event.action == 'opened' ||
      github.event.action == 'reopened' ||
      github.event.action == 'synchronize' ||
      (github.event.action == 'labeled' && github.event.label.name == 'codemender-scan')
    outputs:
      matrix: ${{{{ steps.scan_exec.outputs.matrix || '[0]' }}}}
      findings_count: ${{{{ steps.scan_exec.outputs.findings_count || '0' }}}}
      blocking_count: ${{{{ steps.scan_exec.outputs.blocking_count || '0' }}}}
      advisory_count: ${{{{ steps.scan_exec.outputs.advisory_count || '0' }}}}
      target_sha: ${{{{ steps.scan_exec.outputs.target_sha || github.event.pull_request.head.sha || github.sha }}}}
      scan_id: ${{{{ steps.scan_exec.outputs.scan_id || github.run_id }}}}
      skip_scan: ${{{{ steps.preflight.outputs.skip_scan || 'false' }}}}
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
        with:
          ref: ${{{{ github.event.pull_request.head.sha || github.sha }}}}
          fetch-depth: 0

      - name: Checkout CodeMender Orchestrator
        env:
          CUSTOM_TOKEN: ${{{{ secrets.CUSTOM_GITHUB_TOKEN }}}}
          DEFAULT_TOKEN: ${{{{ github.token }}}}
        run: |
{checkout_orchestrator_script}

      - name: Preflight PR Diff Scan Target Resolution
        id: preflight
        env:
          PYTHONPATH: .codemender_agent
          CODEMENDER_RUN_MODE: preflight
          IS_PR: ${{{{ github.event_name == 'pull_request' }}}}
          DIFF_SCOPED: "true"
          BASE_REF: ${{{{ github.event.pull_request.base.ref || 'main' }}}}
          DEFAULT_SCAN_TARGET: ${{{{ inputs.scan_target || '{scan_target}' }}}}
        run: python3 .codemender_agent/orchestrator.py

      - name: Authenticate to Google Cloud
        if: steps.preflight.outputs.skip_scan != 'true'
        uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: ${{{{ secrets.GCP_WORKLOAD_IDENTITY_PROVIDER }}}}
          service_account: ${{{{ secrets.GCP_SERVICE_ACCOUNT }}}}
          credentials_json: ${{{{ secrets.GCP_SA_KEY }}}}

      - name: Install CodeMender CLI (`cm`)
        if: steps.preflight.outputs.skip_scan != 'true'
        run: |
          set -euo pipefail
          pip install --quiet pyyaml requests
          sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 || true
          curl -fsSL -o /tmp/cm-linux-amd64.zip \\
            "https://artifactregistry.googleapis.com/download/v1/projects/cmoc-prod/locations/us/repositories/codemender-cli-production/files/cm%3Astable%3Acm-linux-amd64.zip:download?alt=media"
          unzip -q -o /tmp/cm-linux-amd64.zip -d /tmp/cm-bin
          chmod +x /tmp/cm-bin/cm
          sudo mv /tmp/cm-bin/cm /usr/local/bin/cm
          cm --version

      - name: Execute Stage 1 Pre-Submit Scan (`orchestrator.py`)
        id: scan_exec
        env:
          PYTHONPATH: .codemender_agent
          CODEMENDER_RUN_MODE: scan{build_env_line}
          SCAN_TARGET: ${{{{ steps.preflight.outputs.skip_scan == 'true' && '__SKIP_NO_SOURCE_CHANGES__' || steps.preflight.outputs.resolved_target || inputs.scan_target || '{scan_target}' }}}}
          IS_PR: ${{{{ github.event_name == 'pull_request' }}}}
          DIFF_SCOPED: "true"
          BASE_REF: ${{{{ github.event.pull_request.base.ref || 'main' }}}}
          TARGET_SHA: ${{{{ github.event.pull_request.head.sha || github.sha }}}}
          PR_NUMBER: ${{{{ github.event.pull_request.number || '0' }}}}
          REPO_FULL: ${{{{ github.repository }}}}
          GH_TOKEN: ${{{{ secrets.CUSTOM_GITHUB_TOKEN || github.token }}}}
          RUN_URL: ${{{{ github.server_url }}}}/${{{{ github.repository }}}}/actions/runs/${{{{ github.run_id }}}}
          MAX_TASKS: "{max_tasks}"
        run: python3 .codemender_agent/orchestrator.py

      - name: Upload Stage 1 Base Transit Artifact
        if: steps.scan_exec.outputs.findings_count != '0' && steps.scan_exec.outputs.findings_count != ''
        uses: actions/upload-artifact@v4
        with:
          name: codemender-base-${{{{ steps.scan_exec.outputs.scan_id }}}}
          path: .codemender_transit/base
          include-hidden-files: true
          retention-days: 2

      - name: Upload Clean SARIF Report (0 Findings Fast-Path)
        if: steps.scan_exec.outputs.findings_count == '0' && hashFiles('report.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: report.sarif
          category: codemender

  # ============================================================================
  # STAGE 1.5: IMMEDIATE PRE-SUBMIT SECURITY GATE
  # ============================================================================
  security-gate:
    name: "CodeMender Security Gate"
    needs: [scan]
    if: always() && needs.scan.result != 'skipped'
    runs-on: ubuntu-latest
    steps:
      - name: Checkout CodeMender Orchestrator
        env:
          CUSTOM_TOKEN: ${{{{ secrets.CUSTOM_GITHUB_TOKEN }}}}
          DEFAULT_TOKEN: ${{{{ github.token }}}}
        run: |
{checkout_orchestrator_script}

      - name: Enforce Immediate Pre-Submit Security Gate (`orchestrator.py`)
        env:
          PYTHONPATH: .codemender_agent
          CODEMENDER_RUN_MODE: gate
          SCAN_RESULT: ${{{{ needs.scan.result }}}}
          FINDINGS_COUNT: ${{{{ needs.scan.outputs.findings_count }}}}
          BLOCKING_COUNT: ${{{{ needs.scan.outputs.blocking_count }}}}
          ADVISORY_COUNT: ${{{{ needs.scan.outputs.advisory_count }}}}
          MIN_SEVERITY: ${{{{ env.MIN_BLOCKING_SEVERITY }}}}
          BLOCK_PR_MERGE: ${{{{ env.BLOCK_PR_MERGE }}}}
          FAIL_ON_FINDINGS: ${{{{ env.FAIL_ON_FINDINGS }}}}
          PR_NUMBER: ${{{{ github.event.pull_request.number || '0' }}}}
          REPO_FULL_NAME: ${{{{ github.repository }}}}
          TARGET_SHA: ${{{{ needs.scan.outputs.target_sha }}}}
          RUN_URL: ${{{{ github.server_url }}}}/${{{{ github.repository }}}}/actions/runs/${{{{ github.run_id }}}}
          GITHUB_TOKEN: ${{{{ secrets.CUSTOM_GITHUB_TOKEN || github.token }}}}
        run: python3 .codemender_agent/orchestrator.py

  # ============================================================================
  # STAGE 2: PARALLEL EXPLOIT VERIFICATION (`cm verify`) & FIX (`cm fix`)
  # ============================================================================
  worker:
    name: "Stage 2: Verify & Fix Worker (${{{{ matrix.worker_index }}}})"
    needs: [scan]
    if: >-
      needs.scan.result == 'success' &&
      needs.scan.outputs.findings_count != '0' &&
      needs.scan.outputs.findings_count != ''
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        worker_index: ${{{{ fromJson(needs.scan.outputs.matrix) }}}}
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
        with:
          ref: ${{{{ github.event.pull_request.head.sha || github.sha }}}}
          fetch-depth: 0

      - name: Checkout CodeMender Orchestrator
        env:
          CUSTOM_TOKEN: ${{{{ secrets.CUSTOM_GITHUB_TOKEN }}}}
          DEFAULT_TOKEN: ${{{{ github.token }}}}
        run: |
{checkout_orchestrator_script}

      - name: Download Stage 1 Base Transit Artifact
        uses: actions/download-artifact@v4
        with:
          name: codemender-base-${{{{ needs.scan.outputs.scan_id }}}}
          path: .codemender_transit/base

      - name: Authenticate to Google Cloud
        uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: ${{{{ secrets.GCP_WORKLOAD_IDENTITY_PROVIDER }}}}
          service_account: ${{{{ secrets.GCP_SERVICE_ACCOUNT }}}}
          credentials_json: ${{{{ secrets.GCP_SA_KEY }}}}

      - name: Install CodeMender CLI (`cm`)
        run: |
          set -euo pipefail
          pip install --quiet pyyaml requests
          sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 || true
          curl -fsSL -o /tmp/cm-linux-amd64.zip \\
            "https://artifactregistry.googleapis.com/download/v1/projects/cmoc-prod/locations/us/repositories/codemender-cli-production/files/cm%3Astable%3Acm-linux-amd64.zip:download?alt=media"
          unzip -q -o /tmp/cm-linux-amd64.zip -d /tmp/cm-bin
          chmod +x /tmp/cm-bin/cm
          sudo mv /tmp/cm-bin/cm /usr/local/bin/cm
          cm --version

      - name: Execute Stage 2 Worker (`cm verify`, `cm fix`, Inline Review)
        env:
          PYTHONPATH: .codemender_agent
          CODEMENDER_RUN_MODE: worker{build_env_line}
          WORKER_INDEX: ${{{{ matrix.worker_index }}}}
          TARGET_SHA: ${{{{ needs.scan.outputs.target_sha }}}}
          PR_NUMBER: ${{{{ github.event.pull_request.number || '0' }}}}
          REPO_FULL: ${{{{ github.repository }}}}
          BLOCK_PR_MERGE: ${{{{ env.BLOCK_PR_MERGE }}}}
          FAIL_ON_FINDINGS: ${{{{ env.FAIL_ON_FINDINGS }}}}
          GH_TOKEN: ${{{{ secrets.CUSTOM_GITHUB_TOKEN || github.token }}}}
        run: python3 .codemender_agent/orchestrator.py

      - name: Upload Worker Shard Results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: codemender-shard-${{{{ needs.scan.outputs.scan_id }}}}-${{{{ matrix.worker_index }}}}
          path: .codemender_transit/shards/worker_${{{{ matrix.worker_index }}}}
          include-hidden-files: true
          retention-days: 2

  # ============================================================================
  # STAGE 3: AGGREGATE VERIFIED SHARDS, SARIF FILTER & AUTO-UNBLOCK
  # ============================================================================
  aggregate:
    name: "Stage 3: Aggregate & Auto-Unblock (`report.sarif`)"
    needs: [scan, worker]
    if: >-
      always() &&
      needs.scan.result == 'success' &&
      needs.scan.outputs.findings_count != '0' &&
      needs.scan.outputs.findings_count != ''
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
        with:
          ref: ${{{{ github.event.pull_request.head.sha || github.sha }}}}
          fetch-depth: 0

      - name: Checkout CodeMender Orchestrator
        env:
          CUSTOM_TOKEN: ${{{{ secrets.CUSTOM_GITHUB_TOKEN }}}}
          DEFAULT_TOKEN: ${{{{ github.token }}}}
        run: |
{checkout_orchestrator_script}

      - name: Install CodeMender CLI (`cm`)
        run: |
          set -euo pipefail
          pip install --quiet pyyaml requests
          sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 || true
          curl -fsSL -o /tmp/cm-linux-amd64.zip \\
            "https://artifactregistry.googleapis.com/download/v1/projects/cmoc-prod/locations/us/repositories/codemender-cli-production/files/cm%3Astable%3Acm-linux-amd64.zip:download?alt=media"
          unzip -q -o /tmp/cm-linux-amd64.zip -d /tmp/cm-bin
          chmod +x /tmp/cm-bin/cm
          sudo mv /tmp/cm-bin/cm /usr/local/bin/cm
          cm --version

      - name: Download Stage 1 Base & Worker Shard Artifacts
        uses: actions/download-artifact@v4
        with:
          pattern: codemender-*-${{{{ needs.scan.outputs.scan_id }}}}*
          path: .codemender_transit_download

      - name: Reconstruct Transit Directory Structure
        run: |
          mkdir -p .codemender_transit/base .codemender_transit/shards
          cp -r .codemender_transit_download/codemender-base-${{{{ needs.scan.outputs.scan_id }}}}/* .codemender_transit/base/ 2>/dev/null || true
          for d in .codemender_transit_download/codemender-shard-${{{{ needs.scan.outputs.scan_id }}}}-*; do
            if [ -d "$d" ]; then
              idx="${{d##*-}}"
              mkdir -p ".codemender_transit/shards/worker_${{idx}}"
              cp -r "$d"/* ".codemender_transit/shards/worker_${{idx}}/" 2>/dev/null || true
            fi
          done

      - name: Execute Stage 3 Aggregation & Auto-Unblock (`orchestrator.py`)
        env:
          PYTHONPATH: .codemender_agent
          CODEMENDER_RUN_MODE: aggregate
          BLOCK_PR_MERGE: ${{{{ env.BLOCK_PR_MERGE }}}}
          FAIL_ON_FINDINGS: ${{{{ env.FAIL_ON_FINDINGS }}}}
          TARGET_SHA: ${{{{ needs.scan.outputs.target_sha }}}}
          PR_NUMBER: ${{{{ github.event.pull_request.number || '0' }}}}
          REPO_FULL: ${{{{ github.repository }}}}
          GH_TOKEN: ${{{{ secrets.CUSTOM_GITHUB_TOKEN || github.token }}}}
          RUN_URL: ${{{{ github.server_url }}}}/${{{{ github.repository }}}}/actions/runs/${{{{ github.run_id }}}}
        run: python3 .codemender_agent/orchestrator.py

      - name: Upload SARIF to GitHub Security Tab
        if: always() && hashFiles('report.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: report.sarif
          category: codemender
"""



def configure_github_repo(
    gh_repo: str,
    min_blocking_severity: str,
    block_pr_merge: bool,
) -> None:
  """Configures the `codemender-scan` label and repository variables via `gh` CLI.

  `CODEMENDER_BLOCK_PR_MERGE` is set to the chosen mode ('false' unless
  `--blocking`). The generated workflow reads it before its literal default,
  so later flips of the variable take effect without regenerating.
  """
  block_str = "true" if block_pr_merge else "false"
  subprocess.run(
      [
          "gh",
          "label",
          "create",
          "codemender-scan",
          "--repo",
          gh_repo,
          "--description",
          "Triggers CodeMender automated security scan and remediation",
          "--color",
          "0E8A16",
          "--force",
      ],
      check=True,
  )
  subprocess.run(
      [
          "gh",
          "variable",
          "set",
          "CODEMENDER_MIN_BLOCKING_SEVERITY",
          "--repo",
          gh_repo,
          "--body",
          min_blocking_severity,
      ],
      check=True,
  )
  subprocess.run(
      [
          "gh",
          "variable",
          "set",
          "CODEMENDER_BLOCK_PR_MERGE",
          "--repo",
          gh_repo,
          "--body",
          block_str,
      ],
      check=True,
  )


def generate_workflow_files(
    *,
    target_dir: pathlib.Path,
    mode: str = "reusable",
    agent_repo: str = "your-org/codemender-agent",
    agent_ref: str = "main",
    vendor_ref: Optional[str] = None,
    runner_image: Optional[str] = None,
    scan_target: str = ".",
    build_command: Optional[str] = None,
    min_blocking_severity: str = "MEDIUM",
    block_pr_merge: bool = False,
    max_tasks: int = 10,
    copy_reusable_workflow: bool = False,
    force: bool = False,
) -> pathlib.Path:
  """Generates `.github/workflows/codemender.yml` inside `target_dir`."""
  sev = min_blocking_severity.strip().upper()
  if sev not in VALID_SEVERITIES:
    raise ValueError(
        f"Invalid min_blocking_severity '{min_blocking_severity}'. Must be one of {VALID_SEVERITIES}."
    )
  if mode not in ("reusable", "standalone"):
    raise ValueError(f"Invalid mode '{mode}'. Must be 'reusable' or 'standalone'.")

  workflows_dir = target_dir / ".github" / "workflows"
  workflows_dir.mkdir(parents=True, exist_ok=True)
  target_file = workflows_dir / "codemender.yml"

  if target_file.exists() and not force:
    raise FileExistsError(
        f"{target_file} already exists. Pass --force to overwrite."
    )

  resolved_build_cmd = (
      build_command
      if build_command is not None
      else detect_build_command(target_dir)
  )
  owner = agent_repo.split("/")[0] if "/" in agent_repo else "your-org"
  resolved_runner_image = (
      runner_image or f"ghcr.io/{owner}/codemender-runner:latest"
  )

  if mode == "reusable":
    if copy_reusable_workflow:
      if not PARALLEL_WORKFLOW_SRC.is_file():
        raise FileNotFoundError(
            f"Reusable workflow template not found at {PARALLEL_WORKFLOW_SRC}"
        )
      dest_parallel = workflows_dir / "codemender_parallel.yml"
      if dest_parallel.resolve() != PARALLEL_WORKFLOW_SRC.resolve():
        shutil.copyfile(PARALLEL_WORKFLOW_SRC, dest_parallel)
    content = render_reusable_caller_workflow(
        agent_repo=agent_repo,
        agent_ref=agent_ref,
        runner_image=resolved_runner_image,
        scan_target=scan_target,
        build_command=resolved_build_cmd,
        min_blocking_severity=sev,
        block_pr_merge=block_pr_merge,
        max_tasks=max_tasks,
        local_reusable_copy=copy_reusable_workflow,
    )
  else:
    content = render_standalone_caller_workflow(
        agent_repo=agent_repo,
        agent_ref=agent_ref,
        scan_target=scan_target,
        build_command=resolved_build_cmd,
        min_blocking_severity=sev,
        block_pr_merge=block_pr_merge,
        max_tasks=max_tasks,
        vendor_ref=vendor_ref,
    )

  target_file.write_text(content, encoding="utf-8")
  return target_file


def build_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
      description=(
          "Generate .github/workflows/codemender.yml to onboard a repository to"
          " the CodeMender Pre-Submit Security Gate."
      )
  )
  parser.add_argument(
      "--target-dir",
      default=".",
      help="Path to the target repository root (default: current directory).",
  )
  parser.add_argument(
      "--mode",
      choices=("reusable", "standalone"),
      default="reusable",
      help=(
          "Workflow generation mode: 'reusable' calls codemender_parallel.yml;"
          " 'standalone' generates the 4-stage orchestrator.py caller workflow"
          " (default: reusable)."
      ),
  )
  parser.add_argument(
      "--agent-repo",
      default="your-org/codemender-agent",
      help="GitHub owner/repo hosting the CodeMender orchestrator.",
  )
  parser.add_argument(
      "--agent-ref",
      default="main",
      help="Git branch or tag of the CodeMender orchestrator repository (default: main).",
  )
  parser.add_argument(
      "--vendor-ref",
      default=None,
      help=(
          "Optional mirrored branch or tag in the caller repository to fall back"
          " to when cloning the orchestrator across private namespaces."
      ),
  )
  parser.add_argument(
      "--runner-image",
      default=None,
      help=(
          "Container runner image for reusable mode (default:"
          " ghcr.io/<agent-owner>/codemender-runner:latest)."
      ),
  )
  parser.add_argument(
      "--scan-target",
      default=".",
      help="Default directory or path(s) to scan (default: '.').",
  )
  parser.add_argument(
      "--build-command",
      default=None,
      help=(
          "Custom build/test verification command (auto-detected from project"
          " manifests if omitted)."
      ),
  )
  parser.add_argument(
      "--min-blocking-severity",
      choices=VALID_SEVERITIES,
      default="MEDIUM",
      help="Minimum severity that blocks PR merge (default: MEDIUM).",
  )
  blocking_group = parser.add_mutually_exclusive_group()
  blocking_group.add_argument(
      "--blocking",
      "--block-pr-merge",
      dest="block_pr_merge",
      action="store_true",
      help=(
          "Generate a blocking gate (literal default block_pr_merge: true)."
          " Repository variable CODEMENDER_BLOCK_PR_MERGE still overrides it."
      ),
  )
  blocking_group.add_argument(
      "--non-blocking",
      dest="block_pr_merge",
      action="store_false",
      help=(
          "Generate a non-blocking (advisory) gate. This is the default; the"
          " flag is kept for compatibility. Set repository variable"
          " CODEMENDER_BLOCK_PR_MERGE=true to block later without"
          " regenerating."
      ),
  )
  parser.set_defaults(block_pr_merge=False)
  parser.add_argument(
      "--max-tasks",
      type=int,
      default=10,
      help="Maximum parallel Stage 2 worker shards (default: 10).",
  )
  parser.add_argument(
      "--copy-reusable-workflow",
      action="store_true",
      help=(
          "In 'reusable' mode, also copy codemender_parallel.yml into the"
          " target repository's .github/workflows/ directory. Needed for"
          " public callers of a private agent repository, or when the agent"
          " repository's Settings > Actions > General > Access cannot be"
          " opened to the caller."
      ),
  )
  parser.add_argument(
      "--gh-repo",
      default=None,
      help=(
          "Optional GitHub 'owner/repo' to configure via the `gh` CLI (creates"
          " the `codemender-scan` label and sets repository variables"
          " CODEMENDER_BLOCK_PR_MERGE and CODEMENDER_MIN_BLOCKING_SEVERITY)."
      ),
  )
  parser.add_argument(
      "--force",
      action="store_true",
      help="Overwrite existing .github/workflows/codemender.yml if present.",
  )
  return parser


def main(argv: Optional[list[str]] = None) -> int:
  parser = build_parser()
  args = parser.parse_args(argv)
  target_dir = pathlib.Path(args.target_dir).resolve()

  try:
    out_path = generate_workflow_files(
        target_dir=target_dir,
        mode=args.mode,
        agent_repo=args.agent_repo,
        agent_ref=args.agent_ref,
        vendor_ref=args.vendor_ref,
        runner_image=args.runner_image,
        scan_target=args.scan_target,
        build_command=args.build_command,
        min_blocking_severity=args.min_blocking_severity,
        block_pr_merge=args.block_pr_merge,
        max_tasks=args.max_tasks,
        copy_reusable_workflow=args.copy_reusable_workflow,
        force=args.force,
    )
  except (FileExistsError, FileNotFoundError, ValueError) as exc:
    print(f"Error: {exc}", file=sys.stderr)
    return 1

  print(f"Generated CodeMender CI/CD workflow ({args.mode} mode): {out_path}")
  if args.block_pr_merge:
    print(
        "Gate default: blocking. Set repository variable"
        f" {BLOCK_PR_MERGE_VAR}=false to make it advisory."
    )
  else:
    print(
        "Gate default: non-blocking (advisory). Set repository variable"
        f" {BLOCK_PR_MERGE_VAR}=true to block merges on findings."
    )
  if args.copy_reusable_workflow and args.mode == "reusable":
    print(
        "Copied reusable workflow template:"
        f" {target_dir / '.github' / 'workflows' / 'codemender_parallel.yml'}"
    )

  if args.gh_repo:
    configure_github_repo(
        gh_repo=args.gh_repo,
        min_blocking_severity=args.min_blocking_severity,
        block_pr_merge=args.block_pr_merge,
    )
    print(
        f"Configured label 'codemender-scan' and repository variables on {args.gh_repo}."
    )

  return 0


if __name__ == "__main__":
  sys.exit(main())
