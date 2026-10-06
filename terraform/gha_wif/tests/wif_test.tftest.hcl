// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

# Unit tests for GCP Workload Identity Federation (WIF) and GitHub Secrets setup
mock_provider "google" {}
mock_provider "github" {}

variables {
  gcp_project_id             = "test-codemender-project"
  gcp_region                 = "global"
  github_owner               = "test-org"
  github_app_id              = "123456"
  target_github_repositories = ["repo-a", "test-org/repo-b"]
}

run "default_wif_and_github_resources_created_correctly" {
  command = plan

  assert {
    condition     = google_service_account.runner_sa.account_id == "codemender-gha-sa"
    error_message = "Runner Service Account ID does not match expected default."
  }

  assert {
    condition     = google_project_iam_member.vertex_ai_user.role == "roles/aiplatform.user"
    error_message = "Runner Service Account must be granted Vertex AI User role."
  }

  assert {
    condition     = google_iam_workload_identity_pool.github_pool.workload_identity_pool_id == "codemender-gha-pool"
    error_message = "Workload Identity Pool ID does not match expected default."
  }

  assert {
    condition     = google_iam_workload_identity_pool_provider.github_provider.workload_identity_pool_provider_id == "codemender-gha-provider"
    error_message = "Workload Identity Provider ID does not match expected default."
  }

  assert {
    condition     = google_iam_workload_identity_pool_provider.github_provider.attribute_condition == "assertion.repository_owner == 'test-org'"
    error_message = "Provider attribute condition does not match expected org scoping."
  }

  assert {
    condition     = length(google_service_account_iam_member.wif_user_org_binding) == 1
    error_message = "Org-scoped binding must be created."
  }

  assert {
    condition     = length(github_issue_label.codemender_scan) == 2
    error_message = "Label 'codemender-scan' must be created for both target repositories."
  }

  assert {
    condition     = length(github_actions_secret.wif_provider) == 2
    error_message = "GCP_WORKLOAD_IDENTITY_PROVIDER secret must be created for both target repositories."
  }

  assert {
    condition     = length(github_actions_secret.runner_sa) == 2
    error_message = "GCP_SERVICE_ACCOUNT secret must be created for both target repositories."
  }

  assert {
    condition     = length(github_actions_secret.app_id) == 2
    error_message = "GH_APP_ID secret must be created for both target repositories."
  }
}

run "repository_list_scoping" {
  command = plan

  variables {
    github_scope_type          = "repositories"
    wif_allowed_repositories   = ["test-org/repo-a", "test-org/repo-b"]
    target_github_repositories = []
  }

  assert {
    condition     = google_iam_workload_identity_pool_provider.github_provider.attribute_condition == "assertion.repository in [\"test-org/repo-a\",\"test-org/repo-b\"]"
    error_message = "Provider attribute condition does not match expected repository list scoping."
  }

  assert {
    condition     = length(google_service_account_iam_member.wif_repo_binding) == 2
    error_message = "Per-repository WIF IAM bindings must be created for each allowed repository."
  }

  assert {
    condition     = length(github_issue_label.codemender_scan) == 2
    error_message = "Labels must be created based on allowed_repositories fallback."
  }
}

run "default_oidc_issuer_is_github_com" {
  command = plan

  assert {
    condition     = google_iam_workload_identity_pool_provider.github_provider.oidc[0].issuer_uri == "https://token.actions.githubusercontent.com"
    error_message = "The default OIDC issuer must stay the github.com issuer."
  }
}

run "custom_oidc_issuer" {
  command = plan

  variables {
    github_oidc_issuer_uri = "https://token.actions.example.ghe.com"
  }

  assert {
    condition     = google_iam_workload_identity_pool_provider.github_provider.oidc[0].issuer_uri == "https://token.actions.example.ghe.com"
    error_message = "github_oidc_issuer_uri must reach the workload identity provider."
  }
}

run "non_https_oidc_issuer_rejected" {
  command = plan

  variables {
    github_oidc_issuer_uri = "http://token.actions.example.ghe.com"
  }

  expect_failures = [var.github_oidc_issuer_uri]
}
