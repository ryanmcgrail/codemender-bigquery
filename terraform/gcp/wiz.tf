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

# Opt-in Wiz SAST bridge.
#
# Nothing in this file is created unless at least one repository (in
# repos.yaml or var.target_repositories) sets `wiz = { enabled = true }`. The
# Wiz service account credentials live in two pre-existing Secret Manager
# secrets that are
# *referenced* through data sources rather than managed here, so enabling or
# disabling the bridge can never create, replace, or destroy the secrets or
# their versions. The credentials are mounted on the runner job only (the
# stage that runs the scan); the worker job never receives them.
#
# Mounting the credentials does not enable the bridge on its own: the runtime
# only calls Wiz for a repository whose scheduler payload carries
# `wiz.enabled = true`, which the workflow forwards as CODEMENDER_WIZ_ENABLED.

locals {
  wiz_enabled_repositories = {
    for name, repo in local.target_repositories : name => repo
    if try(repo.wiz.enabled, false) == true
  }

  wiz_enabled = length(local.wiz_enabled_repositories) > 0

  wiz_client_id_secret_id = (
    local.cfg.wiz_client_id_secret_id != ""
    ? local.cfg.wiz_client_id_secret_id
    : "${local.cfg.resource_prefix}-wiz-client-id"
  )

  wiz_client_secret_secret_id = (
    local.cfg.wiz_client_secret_secret_id != ""
    ? local.cfg.wiz_client_secret_secret_id
    : "${local.cfg.resource_prefix}-wiz-client-secret"
  )

  # Environment variable name => referenced secret. Consumed by the runner job.
  wiz_secret_env = local.wiz_enabled ? {
    WIZ_CLIENT_ID     = data.google_secret_manager_secret.wiz_client_id[0].secret_id
    WIZ_CLIENT_SECRET = data.google_secret_manager_secret.wiz_client_secret[0].secret_id
  } : {}
}

data "google_secret_manager_secret" "wiz_client_id" {
  count     = local.wiz_enabled ? 1 : 0
  secret_id = local.wiz_client_id_secret_id
  project   = local.cfg.project_id
}

data "google_secret_manager_secret" "wiz_client_secret" {
  count     = local.wiz_enabled ? 1 : 0
  secret_id = local.wiz_client_secret_secret_id
  project   = local.cfg.project_id
}

# Non-authoritative accessor bindings for the runner service account only.
# `_iam_member` adds a single binding and leaves any other members of the
# secret's policy untouched.
resource "google_secret_manager_secret_iam_member" "runner_wiz_client_id_accessor" {
  count     = local.wiz_enabled ? 1 : 0
  project   = local.cfg.project_id
  secret_id = data.google_secret_manager_secret.wiz_client_id[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runner_sa.email}"
}

resource "google_secret_manager_secret_iam_member" "runner_wiz_client_secret_accessor" {
  count     = local.wiz_enabled ? 1 : 0
  project   = local.cfg.project_id
  secret_id = data.google_secret_manager_secret.wiz_client_secret[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runner_sa.email}"
}
