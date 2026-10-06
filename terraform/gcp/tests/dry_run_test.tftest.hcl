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

# Unit tests for the per-repository dry-run switch in the scheduler payload.
mock_provider "google" {
  # Make the workflow ID known at plan time so the scheduler body can be
  # decoded and inspected.
  override_during = plan

  mock_resource "google_workflows_workflow" {
    defaults = {
      id = "projects/test-project-123/locations/us-central1/workflows/test-dry-coordinator"
    }
  }
}
mock_provider "google-beta" {}
mock_provider "random" {}

variables {
  # Keep the tests independent of any repos.yaml / deployment.yaml in the
  # module directory.
  repos_file      = ""
  deployment_file = ""

  project_id      = "test-project-123"
  region          = "us-central1"
  resource_prefix = "test-dry"
  target_repositories = {
    "plain" = {
      repo_url = "https://github.com/org/plain.git"
    }
    "off" = {
      repo_url = "https://github.com/org/off.git"
      dry_run  = false
    }
    "dry" = {
      repo_url = "https://github.com/org/dry.git"
      dry_run  = true
    }
  }
}

run "dry_run_only_emitted_when_enabled" {
  command = plan

  assert {
    condition     = !can(jsondecode(jsondecode(base64decode(google_cloud_scheduler_job.repo_scans["plain"].http_target[0].body)).argument).dry_run)
    error_message = "A repository without dry_run must not send dry_run to the workflow."
  }

  assert {
    condition     = !can(jsondecode(jsondecode(base64decode(google_cloud_scheduler_job.repo_scans["off"].http_target[0].body)).argument).dry_run)
    error_message = "dry_run = false must not send dry_run to the workflow."
  }

  assert {
    condition     = jsondecode(jsondecode(base64decode(google_cloud_scheduler_job.repo_scans["dry"].http_target[0].body)).argument).dry_run == true
    error_message = "dry_run = true must be forwarded to the workflow."
  }
}
