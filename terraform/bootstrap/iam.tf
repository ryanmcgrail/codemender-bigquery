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

# Three identities, one per trigger kind. Cloud Build always runs a trigger's
# builds as the trigger's own service account, whatever the build file says,
# so a pull request cannot borrow the apply identity.

resource "google_service_account" "tf_plan" {
  account_id   = "${var.resource_prefix}-tf-plan"
  display_name = "CodeMender Terraform plan (${var.resource_prefix})"
  description  = "Runs terraform plan for pull requests. Read-only; cannot read secret values, BigQuery data or scan execution details."
  project      = var.project_id
  depends_on   = [google_project_service.apis]
}

resource "google_service_account" "tf_apply" {
  account_id   = "${var.resource_prefix}-tf-apply"
  display_name = "CodeMender Terraform apply (${var.resource_prefix})"
  description  = "Runs terraform apply for merged changes to the deployed branch."
  project      = var.project_id
  depends_on   = [google_project_service.apis]
}

resource "google_service_account" "image_build" {
  account_id   = "${var.resource_prefix}-image-build"
  display_name = "CodeMender runner image build (${var.resource_prefix})"
  description  = "Builds the runner image and rolls it out to the Cloud Run jobs. Its deployment permissions are granted by terraform/gcp (cloudbuild_service_account_emails)."
  project      = var.project_id
  depends_on   = [google_project_service.apis]
}

# ---------------------------------------------------------------------------
# Plan identity: read-only.
#
# The pull request plan runs code the pull request author controls, so this
# identity gets narrow read roles rather than roles/viewer. In particular it
# gets none of roles/viewer, roles/iam.securityReviewer, roles/run.viewer or
# roles/workflows.viewer: those can list Cloud Run and workflow executions,
# whose environment and arguments carry signed URLs for the scan workspace and
# reports. Terraform only needs to read the job and workflow definitions,
# which the custom role below grants.
# ---------------------------------------------------------------------------

locals {
  plan_member        = "serviceAccount:${google_service_account.tf_plan.email}"
  apply_member       = "serviceAccount:${google_service_account.tf_apply.email}"
  image_build_member = "serviceAccount:${google_service_account.image_build.email}"

  plan_project_roles = toset([
    "roles/bigquery.metadataViewer", # dataset/table metadata, not data
    "roles/browser",
    "roles/cloudscheduler.viewer",
    "roles/compute.networkViewer",
    "roles/iam.roleViewer",
    "roles/iam.serviceAccountViewer",
    "roles/logging.logWriter",
    "roles/secretmanager.viewer", # secret metadata, not payloads
    "roles/serviceusage.serviceUsageViewer",
    "roles/storage.bucketViewer",
    "roles/vpcaccess.viewer",
  ])

  plan_reader_permissions = [
    "artifactregistry.repositories.get",
    "artifactregistry.repositories.getIamPolicy",
    "run.jobs.get",
    "storage.buckets.getIamPolicy",
    "workflows.workflows.get",
  ]

  apply_project_roles = toset([
    "roles/artifactregistry.admin",
    "roles/bigquery.dataOwner",
    "roles/browser",
    "roles/cloudscheduler.admin",
    "roles/compute.networkAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/iam.serviceAccountUser",
    "roles/logging.logWriter",
    "roles/resourcemanager.projectIamAdmin",
    "roles/run.admin",
    "roles/secretmanager.admin",
    "roles/serviceusage.serviceUsageAdmin",
    "roles/storage.admin",
    "roles/vpcaccess.admin",
    "roles/workflows.admin",
  ])
}

# Custom roles stay in a 7-day soft-deleted state after deletion, so a random
# suffix lets the stack be destroyed and re-created without an ID conflict.
resource "random_id" "plan_reader_suffix" {
  byte_length = 3
  keepers = {
    resource_prefix = var.resource_prefix
  }
}

resource "google_project_iam_custom_role" "plan_reader" {
  project     = var.project_id
  role_id     = "${replace(var.resource_prefix, "-", "_")}_tf_plan_reader_${random_id.plan_reader_suffix.hex}"
  title       = "CodeMender Terraform plan reader (${var.resource_prefix})"
  description = "Reads the Cloud Run job, workflow, bucket and registry settings terraform plan refreshes, without access to executions."
  permissions = local.plan_reader_permissions
  depends_on  = [google_project_service.apis]
}

resource "google_project_iam_member" "plan_roles" {
  for_each = local.plan_project_roles
  project  = var.project_id
  role     = each.key
  member   = local.plan_member
}

resource "google_project_iam_member" "plan_reader" {
  project = var.project_id
  role    = google_project_iam_custom_role.plan_reader.id
  member  = local.plan_member
}

# The plan reads state but never writes it (it runs with -lock=false).
resource "google_storage_bucket_iam_member" "plan_state_reader" {
  bucket = google_storage_bucket.state.name
  role   = "roles/storage.objectViewer"
  member = local.plan_member
}

# ---------------------------------------------------------------------------
# Apply identity: manages everything terraform/gcp creates.
# ---------------------------------------------------------------------------

resource "google_project_iam_member" "apply_roles" {
  for_each = local.apply_project_roles
  project  = var.project_id
  role     = each.key
  member   = local.apply_member
}

# Used by scripts/ci/pipeline_lock.py to check the live remote branch HEAD via
# git ls-remote before applying, so an older or retried commit never overwrites
# a newer one.
resource "google_cloudbuildv2_connection_iam_member" "apply_read_token" {
  project  = local.repository_project
  location = var.region
  name     = local.repository_connection
  role     = "roles/cloudbuild.readTokenAccessor"
  member   = local.apply_member
}

# ---------------------------------------------------------------------------
# Image build identity. terraform/gcp grants it the registry, Cloud Run and
# workflow access the build and rollout need, once deployment.yaml lists it
# in cloudbuild_service_account_emails. Only build logging is granted here.
# ---------------------------------------------------------------------------

resource "google_project_iam_member" "image_build_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = local.image_build_member
}

# ---------------------------------------------------------------------------
# Approvers for gated builds.
# ---------------------------------------------------------------------------

resource "google_project_iam_member" "approvers" {
  for_each = toset(var.approvers)
  project  = var.project_id
  role     = "roles/cloudbuild.builds.approver"
  member   = each.key
}
