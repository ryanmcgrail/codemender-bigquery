# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Opt-in GitHub App authentication for scheduled scans.
#
# With var.github_app_id empty (the default) nothing in this file is created
# and both Cloud Run jobs keep reading the static token secret
# "<resource_prefix>-github-token" exactly as before.
#
# With var.github_app_id set, the runner and worker jobs receive the App ID
# (and optional installation ID) as plain environment variables and the App's
# private key from a pre-existing Secret Manager secret, and mint one-hour
# installation tokens at runtime, refreshing them during long scans. The
# private key secret is *referenced* through a data source rather than
# managed here, so the key never enters Terraform state and toggling the App
# can never create, replace or destroy it. The static token is then no longer
# mounted on either job, so a personal token cannot be used by accident; the
# static token secret itself is left in place so that unsetting
# var.github_app_id restores the previous behaviour.

locals {
  github_app_enabled = local.cfg.github_app_id != ""

  github_app_private_key_secret_id = (
    local.cfg.github_app_private_key_secret_id != ""
    ? local.cfg.github_app_private_key_secret_id
    : "${local.cfg.resource_prefix}-github-app-private-key"
  )

  # Environment variable name => value. Consumed by the runner and worker jobs.
  github_app_plain_env = local.github_app_enabled ? merge(
    { GITHUB_APP_ID = local.cfg.github_app_id },
    local.cfg.github_app_installation_id != "" ? { GITHUB_APP_INSTALLATION_ID = local.cfg.github_app_installation_id } : {},
  ) : {}

  # Environment variable name => secret. Consumed by the runner and worker jobs.
  github_app_secret_env = local.github_app_enabled ? {
    GITHUB_APP_PRIVATE_KEY = data.google_secret_manager_secret.github_app_private_key[0].secret_id
  } : {}

  # The static token is mounted only while no GitHub App is configured.
  github_static_token_env = local.github_app_enabled ? {} : {
    GITHUB_APP_TOKEN = google_secret_manager_secret.github_app_token.secret_id
  }

  # Replaces the static-token instructions in the secret_manager_notice output
  # while an App is configured.
  github_app_secret_notice = join("\n", [
    "GitHub App authentication is enabled (App ID ${local.cfg.github_app_id}). The runner and worker jobs",
    "read the App's private key from the existing secret '${local.github_app_private_key_secret_id}'",
    "and mint installation tokens at runtime; '${google_secret_manager_secret.github_app_token.secret_id}' is not mounted.",
    "To rotate the key, add a new version (used by the next job execution):",
    "  gcloud secrets versions add ${local.github_app_private_key_secret_id} --data-file=/path/to/app.private-key.pem --project=${local.cfg.project_id}",
    "",
  ])
}

data "google_secret_manager_secret" "github_app_private_key" {
  count     = local.github_app_enabled ? 1 : 0
  secret_id = local.github_app_private_key_secret_id
  project   = local.cfg.project_id
}

# Non-authoritative accessor bindings: both jobs talk to GitHub (the runner
# for scan, status and SARIF upload; the worker for fix branches and pull
# requests), so both service accounts need the key.
resource "google_secret_manager_secret_iam_member" "runner_github_app_key_accessor" {
  count     = local.github_app_enabled ? 1 : 0
  project   = local.cfg.project_id
  secret_id = data.google_secret_manager_secret.github_app_private_key[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runner_sa.email}"
}

resource "google_secret_manager_secret_iam_member" "worker_github_app_key_accessor" {
  count     = local.github_app_enabled ? 1 : 0
  project   = local.cfg.project_id
  secret_id = data.google_secret_manager_secret.github_app_private_key[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.worker_sa.email}"
}
