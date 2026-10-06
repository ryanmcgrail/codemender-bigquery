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

resource "google_secret_manager_secret" "github_app_token" {
  secret_id = "${local.cfg.resource_prefix}-github-token"
  project   = local.cfg.project_id

  replication {
    auto {}
  }

  depends_on = [google_project_service.enabled_services]
}

resource "google_secret_manager_secret_version" "github_app_token_initial" {
  secret      = google_secret_manager_secret.github_app_token.id
  secret_data = "PLACEHOLDER"

  lifecycle {
    ignore_changes = [secret_data]
  }
}
