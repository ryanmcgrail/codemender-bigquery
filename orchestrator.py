#!/usr/bin/env python3
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

"""CodeMender Orchestrator Entrypoint.

Decentralized, automated orchestration script that runs within a team's secure
infrastructure (e.g., Cloud Run Job) to validate and fix security
vulnerabilities using the CodeMender CLI and open GitHub Pull Requests.
"""

import logging
import os
import sys

from codemender_agent.config import OrchestratorConfig
from codemender_agent.runners.aggregate import run_aggregate_pipeline
from codemender_agent.runners.gate import resolve_pr_diff_targets
from codemender_agent.runners.gate import run_security_gate_pipeline
from codemender_agent.runners.scan import run_scan_pipeline
from codemender_agent.runners.sequential import run_sequential_pipeline
from codemender_agent.runners.worker import run_worker_pipeline
from codemender_agent.utils import is_dry_run

# Configure global root logger for all package submodules
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)


def main() -> None:
  """Main execution entrypoint for CodeMender Orchestrator."""
  run_mode = os.environ.get("CODEMENDER_RUN_MODE", "sequential").lower()
  if is_dry_run():
    logging.warning(
        "CODEMENDER_DRY_RUN is set: this run makes no GitHub writes (no fix"
        " pull requests, branch pushes, SARIF upload or commit status) and"
        " skips remote duplicate checks."
    )

  if run_mode == "sequential":
    run_sequential_pipeline()
  elif run_mode == "preflight":
    cfg = OrchestratorConfig.from_env()
    resolve_pr_diff_targets(
        workspace_dir=cfg.workspace_dir,
        is_pr=cfg.is_pr_scan,
        diff_scoped=cfg.diff_scoped_pr_scan,
        base_ref=cfg.pr_base_ref or "",
        default_scan_target=cfg.scan_target,
        github_output=cfg.github_output or "",
    )
  elif run_mode == "scan":
    run_scan_pipeline()
  elif run_mode in ("gate", "security_gate"):
    run_security_gate_pipeline()
  elif run_mode == "worker":
    run_worker_pipeline()
  elif run_mode == "aggregate":
    run_aggregate_pipeline()
  else:
    logging.warning("Unknown run mode '%s', falling back to sequential.", run_mode)
    run_sequential_pipeline()


if __name__ == "__main__":
  main()
