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

locals {
  # Normalize target repo list: use var.target_github_repositories if provided,
  # or fall back to var.wif_allowed_repositories if scope is 'repositories'
  raw_repo_list = length(var.target_github_repositories) > 0 ? var.target_github_repositories : (
    var.github_scope_type == "repositories" ? var.wif_allowed_repositories : []
  )

  # Extract pure repository name if formatted as "owner/repo"
  target_repos = toset([
    for r in local.raw_repo_list : element(reverse(split("/", r)), 0)
  ])
}

# 1. Create 'codemender-scan' label in target repositories
resource "github_issue_label" "codemender_scan" {
  for_each    = local.target_repos
  repository  = each.value
  name        = "codemender-scan"
  description = "Triggers CodeMender automated security scan and remediation"
  color       = "0E8A16"
}

# 2. Configure GCP_WORKLOAD_IDENTITY_PROVIDER secret in target repositories
resource "github_actions_secret" "wif_provider" {
  for_each    = local.target_repos
  repository  = each.value
  secret_name = "GCP_WORKLOAD_IDENTITY_PROVIDER"
  value       = google_iam_workload_identity_pool_provider.github_provider.name
}

# 3. Configure GCP_SERVICE_ACCOUNT secret in target repositories
resource "github_actions_secret" "runner_sa" {
  for_each    = local.target_repos
  repository  = each.value
  secret_name = "GCP_SERVICE_ACCOUNT"
  value       = google_service_account.runner_sa.email
}

# 4. Configure GH_APP_ID secret in target repositories (when provided)
resource "github_actions_secret" "app_id" {
  for_each    = var.github_app_id != "" ? local.target_repos : toset([])
  repository  = each.value
  secret_name = "GH_APP_ID"
  value       = var.github_app_id
}
