#!/bin/sh
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

# Pull request check: a read-only `terraform plan` against the shared state.
#
# Runs with -lock=false because the plan identity can only read the state
# bucket; it never writes state and never saves a plan file. A failing plan
# (including a YAML precondition) fails the check.
#
# Environment: see tf_init.sh.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TF_DIR="${TF_DIR:-terraform/gcp}"
export TF_DIR
export TF_IN_AUTOMATION="${TF_IN_AUTOMATION:-1}"

sh "$SCRIPT_DIR/tf_init.sh"
terraform -chdir="$TF_DIR" plan -input=false -lock=false -no-color
