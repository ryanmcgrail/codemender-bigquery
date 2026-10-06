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

# Unit tests for GCP Storage and Artifact Registry
mock_provider "google" {}
mock_provider "google-beta" {}

variables {
  # Keep the tests independent of any repos.yaml / deployment.yaml in the
  # module directory.
  repos_file      = ""
  deployment_file = ""

  project_id      = "test-project-123"
  region          = "us-central1"
  resource_prefix = "test-storage"
}

run "storage_resources_default_names" {
  command = plan

  variables {
    reports_bucket_name = ""
  }

  assert {
    condition     = google_storage_bucket.reports.name == "test-storage-reports-test-project-123"
    error_message = "Reports bucket default name does not match expected prefix pattern."
  }

  assert {
    condition     = google_artifact_registry_repository.docker_repo.repository_id == "test-storage-runner"
    error_message = "Artifact Registry repository ID does not match expected prefix pattern."
  }
}

run "storage_resources_custom_names" {
  command = plan

  variables {
    reports_bucket_name = "custom-reports-123"
  }

  assert {
    condition     = google_storage_bucket.reports.name == "custom-reports-123"
    error_message = "Reports bucket should use provided variable when specified."
  }
}

run "storage_iam_bindings" {
  command = plan

  assert {
    condition     = length(google_project_iam_member.cloudbuild_run_developer) > 0
    error_message = "Cloud Build SAs must be granted run.developer role on the project."
  }

  assert {
    condition     = length(google_service_account_iam_member.cloudbuild_runner_sa_user) > 0
    error_message = "Cloud Build SAs must be granted iam.serviceAccountUser role on the runner SA."
  }
}
