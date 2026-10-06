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

# Unit tests for the optional fix commit author identity.
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
  resource_prefix = "test-author"
  target_repositories = {
    "plain" = {
      repo_url = "https://github.com/org/plain.git"
    }
  }
}

run "unset_adds_no_env" {
  command = plan

  assert {
    condition = length([
      for e in concat(
        tolist(google_cloud_run_v2_job.runner.template[0].template[0].containers[0].env),
        tolist(google_cloud_run_v2_job.worker.template[0].template[0].containers[0].env),
      ) : e.name if startswith(e.name, "CODEMENDER_GIT_AUTHOR_")
    ]) == 0
    error_message = "No commit identity variables may be set unless configured."
  }
}

run "tfvars_reach_both_jobs" {
  command = plan

  variables {
    git_author_name  = "Security Fixes"
    git_author_email = "secfix@example.com"
  }

  assert {
    condition = {
      for e in google_cloud_run_v2_job.runner.template[0].template[0].containers[0].env :
      e.name => e.value if startswith(e.name, "CODEMENDER_GIT_AUTHOR_")
      } == {
      CODEMENDER_GIT_AUTHOR_NAME  = "Security Fixes"
      CODEMENDER_GIT_AUTHOR_EMAIL = "secfix@example.com"
    }
    error_message = "The runner job must receive both commit identity variables."
  }

  assert {
    condition = {
      for e in google_cloud_run_v2_job.worker.template[0].template[0].containers[0].env :
      e.name => e.value if startswith(e.name, "CODEMENDER_GIT_AUTHOR_")
      } == {
      CODEMENDER_GIT_AUTHOR_NAME  = "Security Fixes"
      CODEMENDER_GIT_AUTHOR_EMAIL = "secfix@example.com"
    }
    error_message = "The worker job must receive both commit identity variables."
  }
}

run "email_only" {
  command = plan

  variables {
    git_author_email = "secfix@example.com"
  }

  assert {
    condition = [
      for e in google_cloud_run_v2_job.worker.template[0].template[0].containers[0].env :
      e.name if startswith(e.name, "CODEMENDER_GIT_AUTHOR_")
    ] == ["CODEMENDER_GIT_AUTHOR_EMAIL"]
    error_message = "Only the configured field may be set."
  }
}

run "deployment_yaml_keys" {
  command = plan

  variables {
    deployment_file = "tests/fixtures/deployment_git_author.yaml"
  }

  assert {
    condition = {
      for e in google_cloud_run_v2_job.worker.template[0].template[0].containers[0].env :
      e.name => e.value if startswith(e.name, "CODEMENDER_GIT_AUTHOR_")
      } == {
      CODEMENDER_GIT_AUTHOR_NAME  = "Security Fixes"
      CODEMENDER_GIT_AUTHOR_EMAIL = "secfix@example.com"
    }
    error_message = "git_author_name and git_author_email must be read from deployment.yaml."
  }
}

run "deployment_yaml_rejects_bracketed_email" {
  command = plan

  variables {
    deployment_file = "tests/fixtures/deployment_bad_git_author.yaml"
  }

  expect_failures = [terraform_data.config_checks]
}

run "tfvars_rejects_bad_values" {
  command = plan

  variables {
    git_author_name  = "Evil <x@example.com>"
    git_author_email = "two words@example.com"
  }

  expect_failures = [var.git_author_name, var.git_author_email]
}
