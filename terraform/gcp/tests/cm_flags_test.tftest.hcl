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

# Unit tests for per-repository cm flags in the scheduler payload.
mock_provider "google" {
  # Make the workflow ID known at plan time so the scheduler body can be
  # decoded and inspected.
  override_during = plan

  mock_resource "google_workflows_workflow" {
    defaults = {
      id = "projects/test-project-123/locations/us-central1/workflows/test-flags-coordinator"
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
  resource_prefix = "test-flags"
  target_repositories = {
    "plain" = {
      repo_url = "https://github.com/org/plain.git"
    }
    "blank" = {
      repo_url     = "https://github.com/org/blank.git"
      find_flags   = "   "
      verify_flags = ""
    }
    "deep" = {
      repo_url   = "https://github.com/org/deep.git"
      find_flags = " --deep --deep-workers 4 "
    }
    "all" = {
      repo_url     = "https://github.com/org/all.git"
      find_flags   = "--deep"
      verify_flags = "--no-reset"
      fix_flags    = "--no-cache"
    }
  }
}

run "flags_only_emitted_when_set" {
  command = plan

  assert {
    condition     = !can(jsondecode(jsondecode(base64decode(google_cloud_scheduler_job.repo_scans["plain"].http_target[0].body)).argument).cm_flags)
    error_message = "A repository without flags must not send cm_flags to the workflow."
  }

  assert {
    condition     = !can(jsondecode(jsondecode(base64decode(google_cloud_scheduler_job.repo_scans["blank"].http_target[0].body)).argument).cm_flags)
    error_message = "Blank flag strings must not send cm_flags to the workflow."
  }

  assert {
    condition     = jsondecode(jsondecode(base64decode(google_cloud_scheduler_job.repo_scans["deep"].http_target[0].body)).argument).cm_flags == { find = "--deep --deep-workers 4" }
    error_message = "find_flags must be forwarded trimmed, and only the commands that set flags may appear."
  }

  assert {
    condition     = jsondecode(jsondecode(base64decode(google_cloud_scheduler_job.repo_scans["all"].http_target[0].body)).argument).cm_flags == { find = "--deep", verify = "--no-reset", fix = "--no-cache" }
    error_message = "find, verify and fix flags must all be forwarded."
  }
}
