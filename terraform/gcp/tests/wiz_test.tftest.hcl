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

# Unit tests for the opt-in Wiz SAST bridge wiring.
mock_provider "google" {
  # Make the workflow ID known at plan time so the scheduler body can be
  # decoded and inspected.
  override_during = plan

  mock_resource "google_workflows_workflow" {
    defaults = {
      id = "projects/test-project-123/locations/us-central1/workflows/test-wiz-coordinator"
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
  resource_prefix = "test-wiz"
  target_repositories = {
    "plain" = {
      repo_url = "https://github.com/org/plain.git"
    }
  }
}

run "disabled_by_default_creates_nothing" {
  command = plan

  assert {
    condition     = length(data.google_secret_manager_secret.wiz_client_id) == 0 && length(data.google_secret_manager_secret.wiz_client_secret) == 0
    error_message = "Wiz secrets must not be read unless a repository enables the bridge."
  }

  assert {
    condition     = length(google_secret_manager_secret_iam_member.runner_wiz_client_id_accessor) == 0 && length(google_secret_manager_secret_iam_member.runner_wiz_client_secret_accessor) == 0
    error_message = "No Wiz IAM bindings may be created unless a repository enables the bridge."
  }

  assert {
    condition     = length([for e in google_cloud_run_v2_job.runner.template[0].template[0].containers[0].env : e.name if startswith(e.name, "WIZ_")]) == 0
    error_message = "The runner job must not receive Wiz credentials when the bridge is disabled."
  }

  assert {
    condition     = !can(jsondecode(jsondecode(base64decode(google_cloud_scheduler_job.repo_scans["plain"].http_target[0].body)).argument).wiz)
    error_message = "A repository without a wiz block must not send wiz settings to the workflow."
  }
}

run "explicitly_disabled_creates_nothing" {
  command = plan

  variables {
    target_repositories = {
      "plain" = {
        repo_url = "https://github.com/org/plain.git"
        wiz      = { enabled = false, min_severity = "LOW" }
      }
    }
  }

  assert {
    condition     = length(data.google_secret_manager_secret.wiz_client_id) == 0
    error_message = "wiz.enabled = false must not read the Wiz secrets."
  }

  assert {
    condition     = !can(jsondecode(jsondecode(base64decode(google_cloud_scheduler_job.repo_scans["plain"].http_target[0].body)).argument).wiz)
    error_message = "wiz.enabled = false must not send wiz settings to the workflow."
  }
}

run "enabled_mounts_secrets_on_runner_only" {
  command = plan

  variables {
    target_repositories = {
      "plain" = {
        repo_url = "https://github.com/org/plain.git"
      }
      "opted-in" = {
        repo_url = "https://github.com/org/opted-in.git"
        wiz      = { enabled = true }
      }
      "opted-in-medium" = {
        repo_url = "https://github.com/org/opted-in-medium.git"
        wiz      = { enabled = true, min_severity = "medium" }
      }
    }
  }

  assert {
    condition     = data.google_secret_manager_secret.wiz_client_id[0].secret_id == "test-wiz-wiz-client-id"
    error_message = "The client ID secret name must default to <resource_prefix>-wiz-client-id."
  }

  assert {
    condition     = data.google_secret_manager_secret.wiz_client_secret[0].secret_id == "test-wiz-wiz-client-secret"
    error_message = "The client secret name must default to <resource_prefix>-wiz-client-secret."
  }

  assert {
    condition     = google_secret_manager_secret_iam_member.runner_wiz_client_id_accessor[0].role == "roles/secretmanager.secretAccessor" && google_secret_manager_secret_iam_member.runner_wiz_client_secret_accessor[0].role == "roles/secretmanager.secretAccessor"
    error_message = "The runner service account must get secretAccessor on both Wiz secrets."
  }

  assert {
    condition = toset([
      for e in google_cloud_run_v2_job.runner.template[0].template[0].containers[0].env :
      "${e.name}=${e.value_source[0].secret_key_ref[0].secret}" if startswith(e.name, "WIZ_")
    ]) == toset(["WIZ_CLIENT_ID=test-wiz-wiz-client-id", "WIZ_CLIENT_SECRET=test-wiz-wiz-client-secret"])
    error_message = "The runner job must mount exactly WIZ_CLIENT_ID and WIZ_CLIENT_SECRET from the referenced secrets."
  }

  assert {
    condition     = length([for e in google_cloud_run_v2_job.worker.template[0].template[0].containers[0].env : e.name if startswith(e.name, "WIZ_")]) == 0
    error_message = "The worker job must never receive Wiz credentials."
  }

  assert {
    condition     = !can(jsondecode(jsondecode(base64decode(google_cloud_scheduler_job.repo_scans["plain"].http_target[0].body)).argument).wiz)
    error_message = "Repositories that did not opt in must not send wiz settings."
  }

  assert {
    condition     = jsondecode(jsondecode(base64decode(google_cloud_scheduler_job.repo_scans["opted-in"].http_target[0].body)).argument).wiz == { enabled = true, min_severity = "HIGH" }
    error_message = "An opted-in repository must send wiz.enabled = true with the HIGH default threshold."
  }

  assert {
    condition     = jsondecode(jsondecode(base64decode(google_cloud_scheduler_job.repo_scans["opted-in-medium"].http_target[0].body)).argument).wiz.min_severity == "MEDIUM"
    error_message = "A per-repository threshold must be forwarded upper-cased."
  }
}

run "custom_secret_names" {
  command = plan

  variables {
    wiz_client_id_secret_id     = "custom-id"
    wiz_client_secret_secret_id = "custom-secret"
    target_repositories = {
      "opted-in" = {
        repo_url = "https://github.com/org/opted-in.git"
        wiz      = { enabled = true }
      }
    }
  }

  assert {
    condition     = data.google_secret_manager_secret.wiz_client_id[0].secret_id == "custom-id" && data.google_secret_manager_secret.wiz_client_secret[0].secret_id == "custom-secret"
    error_message = "Secret name overrides must be honoured."
  }
}

run "invalid_min_severity_is_rejected" {
  command = plan

  variables {
    target_repositories = {
      "opted-in" = {
        repo_url = "https://github.com/org/opted-in.git"
        wiz      = { enabled = true, min_severity = "SEVERE" }
      }
    }
  }

  expect_failures = [var.target_repositories]
}
