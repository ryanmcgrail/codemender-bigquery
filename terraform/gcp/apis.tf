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

locals {
  base_required_apis = [
    "cloudresourcemanager.googleapis.com",
    "run.googleapis.com",
    "workflows.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudscheduler.googleapis.com",
    "artifactregistry.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "storage.googleapis.com",
    "cloudbuild.googleapis.com",
    "aiplatform.googleapis.com",
  ]

  # BigQuery is only required when analytics telemetry is enabled. Folding it
  # into the same for_each map (rather than declaring a separate resource)
  # means bigquery.tf can depend on it by key, exactly like every other API.
  required_apis = concat(
    local.base_required_apis,
    local.cfg.enable_bigquery_telemetry ? ["bigquery.googleapis.com"] : [],
  )
}

resource "google_project_service" "enabled_services" {
  for_each           = toset(local.required_apis)
  project            = local.cfg.project_id
  service            = each.key
  disable_on_destroy = false
}

resource "google_project_service" "vpcaccess_api" {
  count              = local.cfg.create_vpc_and_nat ? 1 : 0
  project            = local.cfg.project_id
  service            = "vpcaccess.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "compute_api" {
  count              = local.cfg.create_vpc_and_nat ? 1 : 0
  project            = local.cfg.project_id
  service            = "compute.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service_identity" "workflows_sa" {
  provider   = google-beta
  project    = local.cfg.project_id
  service    = "workflows.googleapis.com"
  depends_on = [google_project_service.enabled_services["workflows.googleapis.com"]]
}
