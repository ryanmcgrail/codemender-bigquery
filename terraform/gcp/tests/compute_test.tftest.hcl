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

# Unit tests for GCP Compute resources (Cloud Run and Workflows)
mock_provider "google" {}
mock_provider "google-beta" {}

variables {
  # Keep the tests independent of any repos.yaml / deployment.yaml in the
  # module directory.
  repos_file      = ""
  deployment_file = ""

  project_id      = "test-project-123"
  region          = "us-central1"
  resource_prefix = "test-compute"
}

run "compute_resources_created_correctly" {
  command = plan

  assert {
    condition     = google_cloud_run_v2_job.runner.name == "test-compute-runner"
    error_message = "Cloud Run job name does not match the expected resource_prefix pattern."
  }

  assert {
    condition     = google_cloud_run_v2_job.runner.location == "us-central1"
    error_message = "Cloud Run job should be deployed to the specified region."
  }

  assert {
    condition     = google_cloud_run_v2_job.worker.name == "test-compute-worker" && google_cloud_run_v2_job.worker.location == "us-central1"
    error_message = "Worker Cloud Run job name and location must match the expected resource_prefix and region."
  }

  assert {
    condition = (
      google_cloud_run_v2_job.runner.client == null &&
      google_cloud_run_v2_job.runner.client_version == null &&
      google_cloud_run_v2_job.worker.client == null &&
      google_cloud_run_v2_job.worker.client_version == null
    )
    error_message = "Cloud Run jobs must not hardcode client/client_version so lifecycle.ignore_changes preserves out-of-band gcloud metadata."
  }

  assert {
    condition     = google_workflows_workflow.coordinator.name == "test-compute-coordinator"
    error_message = "Workflow name does not match the expected resource_prefix pattern."
  }

  assert {
    condition     = google_secret_manager_secret.github_app_token.secret_id == "test-compute-github-token"
    error_message = "Secret Manager secret ID does not match the expected resource_prefix pattern."
  }
}

# The runner job updates the CodeMender CLI when a scan starts unless the
# deployment turns it off.
run "cm_auto_update_defaults_to_on" {
  command = plan

  assert {
    condition     = [for e in google_cloud_run_v2_job.runner.template[0].template[0].containers[0].env : e.value if e.name == "CODEMENDER_AUTO_UPDATE"] == ["true"]
    error_message = "The runner job must set CODEMENDER_AUTO_UPDATE=true by default."
  }
}

run "cm_auto_update_can_be_turned_off_in_deployment_yaml" {
  command = plan

  variables {
    deployment_file = "tests/fixtures/deployment_cm_auto_update_off.yaml"
  }

  assert {
    condition     = [for e in google_cloud_run_v2_job.runner.template[0].template[0].containers[0].env : e.value if e.name == "CODEMENDER_AUTO_UPDATE"] == ["false"]
    error_message = "cm_auto_update: false in deployment.yaml must set CODEMENDER_AUTO_UPDATE=false."
  }
}

run "cm_auto_update_must_be_a_bool" {
  command = plan

  variables {
    deployment_file = "tests/fixtures/deployment_bad_cm_auto_update.yaml"
  }

  expect_failures = [terraform_data.config_checks]
}
