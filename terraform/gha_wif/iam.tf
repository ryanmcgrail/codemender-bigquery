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

# 1. Dedicated Service Account for CodeMender Runner in GitHub Actions
resource "google_service_account" "runner_sa" {
  project      = var.gcp_project_id
  account_id   = var.gcp_service_account_id
  display_name = "CodeMender GitHub Actions Runner SA"
  description  = "Assumed by GitHub Actions runners via Workload Identity Federation for Vertex AI Gemini LLM reasoning"
  depends_on   = [google_project_service.enabled_apis["iam.googleapis.com"]]
}

# 2. Grant Vertex AI User role for Gemini model inference
resource "google_project_iam_member" "vertex_ai_user" {
  project = var.gcp_project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.runner_sa.email}"
}

# 3. Workload Identity Pool for GitHub Actions
resource "google_iam_workload_identity_pool" "github_pool" {
  project                   = var.gcp_project_id
  workload_identity_pool_id = var.gcp_wif_pool_id
  display_name              = "GitHub Actions Pool"
  description               = "OIDC Identity Pool for CodeMender GitHub Actions workflows"
  depends_on                = [google_project_service.enabled_apis["iam.googleapis.com"]]
}

# 4. Workload Identity Pool OIDC Provider with Scoping Conditions
locals {
  # Build attribute condition based on selected scope type
  attribute_condition = (
    var.github_scope_type == "org" || var.github_scope_type == "user"
    ? "assertion.repository_owner == '${var.github_owner}'"
    : "assertion.repository in ${jsonencode(var.wif_allowed_repositories)}"
  )

  # Principal set for user or org wide scope
  owner_principal_set = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_pool.name}/attribute.repository_owner/${var.github_owner}"
}

resource "google_iam_workload_identity_pool_provider" "github_provider" {
  project                            = var.gcp_project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github_pool.workload_identity_pool_id
  workload_identity_pool_provider_id = var.gcp_wif_provider_id
  display_name                       = "GitHub Actions Provider"
  description                        = "OIDC Provider for GitHub Actions runners"

  attribute_mapping = {
    "google.subject"             = "assertion.sub"
    "attribute.actor"            = "assertion.actor"
    "attribute.repository"       = "assertion.repository"
    "attribute.repository_owner" = "assertion.repository_owner"
  }

  attribute_condition = local.attribute_condition

  oidc {
    issuer_uri = var.github_oidc_issuer_uri
  }
}

# 5a. Service Account Binding for Org / User Scope
resource "google_service_account_iam_member" "wif_user_org_binding" {
  count              = (var.github_scope_type == "org" || var.github_scope_type == "user") ? 1 : 0
  service_account_id = google_service_account.runner_sa.name
  role               = "roles/iam.workloadIdentityUser"
  member             = local.owner_principal_set
}

# 5b. Service Account Binding for Specific Repository List Scope
resource "google_service_account_iam_member" "wif_repo_binding" {
  for_each           = var.github_scope_type == "repositories" ? toset(var.wif_allowed_repositories) : toset([])
  service_account_id = google_service_account.runner_sa.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_pool.name}/attribute.repository/${each.value}"
}
