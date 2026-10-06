#!/usr/bin/env bash
# Wrapper script to generate .github/workflows/codemender.yml for a target repository.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/init_codemender_workflow.py" "$@"
