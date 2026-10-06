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

# Unit tests for the opt-in GitHub App authentication wiring.
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
  resource_prefix = "test-gha"
  target_repositories = {
    "plain" = {
      repo_url = "https://github.com/org/plain.git"
    }
  }
}

run "disabled_by_default_keeps_static_token" {
  command = plan

  assert {
    condition     = length(data.google_secret_manager_secret.github_app_private_key) == 0
    error_message = "The App private key secret must not be read unless github_app_id is set."
  }

  assert {
    condition     = length(google_secret_manager_secret_iam_member.runner_github_app_key_accessor) == 0 && length(google_secret_manager_secret_iam_member.worker_github_app_key_accessor) == 0
    error_message = "No App key IAM bindings may be created unless github_app_id is set."
  }

  assert {
    condition = [
      for e in google_cloud_run_v2_job.runner.template[0].template[0].containers[0].env :
      e.value_source[0].secret_key_ref[0].secret if e.name == "GITHUB_APP_TOKEN"
    ] == ["test-gha-github-token"]
    error_message = "The runner job must keep mounting the static token secret when no App is configured."
  }

  assert {
    condition = [
      for e in google_cloud_run_v2_job.worker.template[0].template[0].containers[0].env :
      e.value_source[0].secret_key_ref[0].secret if e.name == "GITHUB_APP_TOKEN"
    ] == ["test-gha-github-token"]
    error_message = "The worker job must keep mounting the static token secret when no App is configured."
  }

  assert {
    condition = length(concat(
      [for e in google_cloud_run_v2_job.runner.template[0].template[0].containers[0].env : e.name if startswith(e.name, "GITHUB_APP_") && e.name != "GITHUB_APP_TOKEN"],
      [for e in google_cloud_run_v2_job.worker.template[0].template[0].containers[0].env : e.name if startswith(e.name, "GITHUB_APP_") && e.name != "GITHUB_APP_TOKEN"],
    )) == 0
    error_message = "No GitHub App settings may be set on either job when the App is disabled."
  }

  assert {
    condition     = strcontains(output.secret_manager_notice, "gcloud secrets versions add test-gha-github-token") && !strcontains(output.secret_manager_notice, "private-key")
    error_message = "Without an App, the secret notice must keep the static token instructions."
  }
}

run "enabled_mounts_app_on_runner_and_worker" {
  command = plan

  variables {
    github_app_id = "123456"
  }

  assert {
    condition     = data.google_secret_manager_secret.github_app_private_key[0].secret_id == "test-gha-github-app-private-key"
    error_message = "The private key secret name must default to <resource_prefix>-github-app-private-key."
  }

  assert {
    condition     = google_secret_manager_secret_iam_member.runner_github_app_key_accessor[0].role == "roles/secretmanager.secretAccessor" && google_secret_manager_secret_iam_member.worker_github_app_key_accessor[0].role == "roles/secretmanager.secretAccessor"
    error_message = "Both job service accounts must get secretAccessor on the App private key."
  }

  assert {
    condition = toset([
      for e in google_cloud_run_v2_job.runner.template[0].template[0].containers[0].env :
      e.value if e.name == "GITHUB_APP_ID"
      ]) == toset(["123456"]) && toset([
      for e in google_cloud_run_v2_job.worker.template[0].template[0].containers[0].env :
      e.value if e.name == "GITHUB_APP_ID"
    ]) == toset(["123456"])
    error_message = "Both jobs must receive GITHUB_APP_ID."
  }

  assert {
    condition = [
      for e in google_cloud_run_v2_job.runner.template[0].template[0].containers[0].env :
      e.value_source[0].secret_key_ref[0].secret if e.name == "GITHUB_APP_PRIVATE_KEY"
      ] == ["test-gha-github-app-private-key"] && [
      for e in google_cloud_run_v2_job.worker.template[0].template[0].containers[0].env :
      e.value_source[0].secret_key_ref[0].secret if e.name == "GITHUB_APP_PRIVATE_KEY"
    ] == ["test-gha-github-app-private-key"]
    error_message = "Both jobs must mount GITHUB_APP_PRIVATE_KEY from the referenced secret."
  }

  assert {
    condition = length(concat(
      [for e in google_cloud_run_v2_job.runner.template[0].template[0].containers[0].env : e.name if contains(["GITHUB_APP_TOKEN", "GITHUB_APP_INSTALLATION_ID"], e.name)],
      [for e in google_cloud_run_v2_job.worker.template[0].template[0].containers[0].env : e.name if contains(["GITHUB_APP_TOKEN", "GITHUB_APP_INSTALLATION_ID"], e.name)],
    )) == 0
    error_message = "With an App configured, the static token must not be mounted, and no installation ID is set unless given."
  }

  assert {
    condition     = strcontains(output.secret_manager_notice, "gcloud secrets versions add test-gha-github-app-private-key") && !strcontains(output.secret_manager_notice, "placeholder data")
    error_message = "With an App configured, the secret notice must point at the App private key secret, not the static token."
  }
}

run "installation_id_and_custom_secret_name" {
  command = plan

  variables {
    github_app_id                    = "123456"
    github_app_installation_id       = "987654"
    github_app_private_key_secret_id = "custom-app-key"
  }

  assert {
    condition     = data.google_secret_manager_secret.github_app_private_key[0].secret_id == "custom-app-key"
    error_message = "The private key secret name override must be honoured."
  }

  assert {
    condition = [
      for e in google_cloud_run_v2_job.worker.template[0].template[0].containers[0].env :
      e.value if e.name == "GITHUB_APP_INSTALLATION_ID"
      ] == ["987654"] && [
      for e in google_cloud_run_v2_job.runner.template[0].template[0].containers[0].env :
      e.value if e.name == "GITHUB_APP_INSTALLATION_ID"
    ] == ["987654"]
    error_message = "Both jobs must receive GITHUB_APP_INSTALLATION_ID when it is set."
  }
}

run "invalid_installation_id_is_rejected" {
  command = plan

  variables {
    github_app_id              = "123456"
    github_app_installation_id = "abc"
  }

  expect_failures = [var.github_app_installation_id]
}

run "app_id_with_whitespace_is_rejected" {
  command = plan

  variables {
    github_app_id = "123 456"
  }

  expect_failures = [var.github_app_id]
}
