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
  state_bucket_name          = coalesce(var.state_bucket_name, "${var.resource_prefix}-tfstate-${var.project_id}")
  deployment_resource_prefix = coalesce(var.deployment_resource_prefix, var.resource_prefix)
  deployment_region          = coalesce(var.deployment_region, var.region)

  # The project, region and connection segments of the linked repository's resource name.
  repository_project    = try(regex("^projects/([^/]+)/", var.cloudbuild_repository)[0], var.project_id)
  repository_region     = try(regex("^projects/[^/]+/locations/([^/]+)/", var.cloudbuild_repository)[0], "")
  repository_connection = try(regex("^projects/[^/]+/locations/[^/]+/connections/([^/]+)/", var.cloudbuild_repository)[0], "")

  # Trigger branch filters are RE2 patterns; match the branch name exactly.
  branch_pattern = "^${replace(var.branch, ".", "\\.")}$"

  required_apis = [
    "cloudbuild.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "serviceusage.googleapis.com",
    "storage.googleapis.com",
  ]
}

resource "google_project_service" "apis" {
  for_each           = toset(local.required_apis)
  project            = var.project_id
  service            = each.key
  disable_on_destroy = false
}

# Terraform state for terraform/gcp. Versioned, so an overwritten or deleted
# state can be restored from an older generation.
resource "google_storage_bucket" "state" {
  name                        = local.state_bucket_name
  project                     = var.project_id
  location                    = var.region
  force_destroy               = var.state_bucket_force_destroy
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  # Keep the 20 most recent superseded generations of each state file.
  lifecycle_rule {
    condition {
      num_newer_versions = 20
      with_state         = "ARCHIVED"
    }
    action {
      type = "Delete"
    }
  }

  lifecycle {
    precondition {
      condition     = length(local.state_bucket_name) >= 3 && length(local.state_bucket_name) <= 63
      error_message = "The state bucket name \"${local.state_bucket_name}\" must be 3-63 characters; set state_bucket_name."
    }
  }

  depends_on = [google_project_service.apis]
}
