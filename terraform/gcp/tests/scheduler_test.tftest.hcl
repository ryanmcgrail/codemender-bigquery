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

# Unit tests for GCP Cloud Scheduler
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
  resource_prefix = "test-sched"
  scheduler_cron  = "0 3 * * *"
  target_repositories = {
    "default" = {
      repo_url = "https://github.com/org/repo.git"
    }
  }
}

run "scheduler_job_created_correctly" {
  command = plan

  assert {
    condition     = google_cloud_scheduler_job.repo_scans["default"].name == "test-sched-scan-default"
    error_message = "Cloud Scheduler job name does not match expected prefix pattern."
  }

  assert {
    condition     = google_cloud_scheduler_job.repo_scans["default"].schedule == "0 3 * * *"
    error_message = "Cloud Scheduler job schedule does not match input variable."
  }

  assert {
    condition     = google_cloud_scheduler_job.repo_scans["default"].paused == false
    error_message = "Cloud Scheduler job should be active (paused = false) by default."
  }

  assert {
    condition     = google_cloud_scheduler_job.repo_scans["default"].http_target[0].http_method == "POST"
    error_message = "Cloud Scheduler job HTTP target method must be POST."
  }
}
