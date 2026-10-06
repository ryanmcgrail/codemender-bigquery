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

# Unit tests for GCP IAM and Service Accounts
mock_provider "google" {}
mock_provider "google-beta" {}
mock_provider "random" {}

variables {
  # Keep the tests independent of any repos.yaml / deployment.yaml in the
  # module directory.
  repos_file      = ""
  deployment_file = ""

  project_id      = "test-project-123"
  region          = "us-central1"
  resource_prefix = "test-iam"
}

run "iam_resources_created_correctly" {
  command = plan

  assert {
    condition     = google_service_account.runner_sa.account_id == "test-iam-runner-sa"
    error_message = "Runner Service Account ID does not match expected prefix."
  }

  assert {
    condition     = google_service_account.workflow_sa.account_id == "test-iam-workflows-sa"
    error_message = "Workflow Service Account ID does not match expected prefix."
  }

  assert {
    condition     = google_service_account.scheduler_sa.account_id == "test-iam-scheduler-sa"
    error_message = "Scheduler Service Account ID does not match expected prefix."
  }

  assert {
    condition = (
      google_project_iam_member.workflow_jobs_executor.role == "roles/run.jobsExecutorWithOverrides" &&
      google_project_iam_member.workflow_run_viewer.role == "roles/run.viewer"
    )
    error_message = "The workflow service account must hold the predefined Cloud Run roles that replace the old custom role."
  }

  assert {
    condition     = google_project_iam_member.workflow_jobs_executor.project == "test-project-123" && google_project_iam_member.workflow_run_viewer.project == "test-project-123"
    error_message = "The Cloud Run role bindings must be in the deployment project."
  }
}

run "workflow_run_roles_target_the_workflow_service_account" {
  command = plan

  override_resource {
    target          = google_service_account.workflow_sa
    override_during = plan
    values = {
      email = "test-iam-workflows-sa@test-project-123.iam.gserviceaccount.com"
    }
  }

  assert {
    condition = (
      google_project_iam_member.workflow_jobs_executor.member == "serviceAccount:test-iam-workflows-sa@test-project-123.iam.gserviceaccount.com" &&
      google_project_iam_member.workflow_run_viewer.member == "serviceAccount:test-iam-workflows-sa@test-project-123.iam.gserviceaccount.com"
    )
    error_message = "The Cloud Run role bindings must target the workflow service account."
  }
}

run "cloudbuild_default_service_accounts" {
  command = plan

  assert {
    condition     = toset(keys(google_project_iam_member.cloudbuild_run_developer)) == toset(["legacy", "compute"])
    error_message = "By default the two default Cloud Build service accounts keep their existing keys."
  }

  assert {
    condition = (
      toset(keys(google_project_iam_member.cloudbuild_workflows_viewer)) == toset(["legacy", "compute"]) &&
      google_project_iam_member.cloudbuild_workflows_viewer["legacy"].role == "roles/workflows.viewer"
    )
    error_message = "The Cloud Build service accounts must be able to list workflow executions."
  }
}

run "cloudbuild_custom_service_accounts" {
  command = plan

  variables {
    cloudbuild_service_account_emails = ["test-iam-image-build@test-project-123.iam.gserviceaccount.com"]
  }

  assert {
    condition = (
      keys(google_project_iam_member.cloudbuild_run_developer) == ["test-iam-image-build@test-project-123.iam.gserviceaccount.com"] &&
      google_project_iam_member.cloudbuild_run_developer["test-iam-image-build@test-project-123.iam.gserviceaccount.com"].member == "serviceAccount:test-iam-image-build@test-project-123.iam.gserviceaccount.com"
    )
    error_message = "Configured Cloud Build service accounts replace the defaults."
  }

  assert {
    condition = (
      length(google_artifact_registry_repository_iam_member.cloudbuild_ar_writer) == 1 &&
      length(google_project_iam_member.cloudbuild_storage_viewer) == 1 &&
      length(google_project_iam_member.cloudbuild_log_writer) == 1 &&
      length(google_service_account_iam_member.cloudbuild_runner_sa_user) == 1 &&
      length(google_service_account_iam_member.cloudbuild_worker_sa_user) == 1 &&
      length(google_project_iam_member.cloudbuild_workflows_viewer) == 1
    )
    error_message = "Every Cloud Build grant must follow the configured service accounts."
  }
}

run "cloudbuild_empty_service_accounts" {
  command = plan

  variables {
    cloudbuild_service_account_emails = []
  }

  assert {
    condition     = length(google_project_iam_member.cloudbuild_run_developer) == 0
    error_message = "An empty list grants no Cloud Build service account anything."
  }
}

run "cloudbuild_service_account_with_prefix_rejected" {
  command = plan

  variables {
    cloudbuild_service_account_emails = ["serviceAccount:builder@test-project-123.iam.gserviceaccount.com"]
  }

  expect_failures = [terraform_data.config_checks]
}
