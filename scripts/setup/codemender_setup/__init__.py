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

"""Setup helper for a GitOps CodeMender deployment.

Run it through the scripts/setup/codemender-setup wrapper. It uses only the
Python standard library (3.9 or later) and calls gcloud, terraform, git and,
optionally, gh.
"""

__version__ = "0.1.0"
