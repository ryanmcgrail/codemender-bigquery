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
  tf_substitutions = {
    _TF_STATE_BUCKET = google_storage_bucket.state.name
    _TF_STATE_PREFIX = var.state_prefix
    _TF_DIR          = var.terraform_dir
  }

  apply_substitutions = merge(local.tf_substitutions, {
    _CLOUDBUILD_REPO = var.cloudbuild_repository
    _DEPLOY_BRANCH   = var.branch
    _DESTROY_TRIGGER = "${var.resource_prefix}-tf-apply-destroy"
  })
}

# Every pull request into the deployed branch. No file filter, so the check
# always reports and can be made a required status check. Pull requests from
# people without write access wait for a maintainer's /gcbrun comment.
resource "google_cloudbuild_trigger" "tf_plan" {
  name               = "${var.resource_prefix}-tf-plan"
  project            = var.project_id
  location           = var.region
  description        = "terraform plan for pull requests into ${var.branch} (read-only)."
  service_account    = google_service_account.tf_plan.id
  filename           = "cloudbuild/terraform-plan.yaml"
  include_build_logs = "INCLUDE_BUILD_LOGS_WITH_STATUS"

  repository_event_config {
    repository = var.cloudbuild_repository
    pull_request {
      branch          = local.branch_pattern
      comment_control = "COMMENTS_ENABLED_FOR_EXTERNAL_CONTRIBUTORS_ONLY"
    }
  }

  substitutions = local.tf_substitutions

  lifecycle {
    precondition {
      condition     = local.repository_region == var.region
      error_message = "cloudbuild_repository is in region \"${local.repository_region}\", but region is \"${var.region}\". Triggers must be in the connection's region."
    }
  }

  depends_on = [
    google_project_iam_member.plan_roles,
    google_project_iam_member.plan_reader,
    google_storage_bucket_iam_member.plan_state_reader,
  ]
}

# Every push to the deployed branch: plan, destroy guard, apply.
resource "google_cloudbuild_trigger" "tf_apply" {
  name            = "${var.resource_prefix}-tf-apply"
  project         = var.project_id
  location        = var.region
  description     = "terraform apply for pushes to ${var.branch}. Stops before deleting protected resources."
  service_account = google_service_account.tf_apply.id
  filename        = "cloudbuild/terraform-apply.yaml"

  repository_event_config {
    repository = var.cloudbuild_repository
    push {
      branch = local.branch_pattern
    }
  }

  approval_config {
    approval_required = var.apply_requires_approval
  }

  substitutions = merge(local.apply_substitutions, { _ALLOW_DESTROY = "false" })

  depends_on = [
    google_project_iam_member.apply_roles,
    google_cloudbuildv2_connection_iam_member.apply_read_token,
  ]
}

# Manual only, always approval-gated: applies the deployed branch even when
# the plan deletes protected resources. Used after the destroy guard has
# stopped an apply whose deletions are intended.
resource "google_cloudbuild_trigger" "tf_apply_destroy" {
  name            = "${var.resource_prefix}-tf-apply-destroy"
  project         = var.project_id
  location        = var.region
  description     = "Manual terraform apply of ${var.branch} that may delete protected resources. Always needs approval."
  service_account = google_service_account.tf_apply.id

  source_to_build {
    repository = var.cloudbuild_repository
    ref        = "refs/heads/${var.branch}"
    repo_type  = "GITHUB"
  }

  git_file_source {
    path       = "cloudbuild/terraform-apply.yaml"
    repository = var.cloudbuild_repository
    revision   = "refs/heads/${var.branch}"
    repo_type  = "GITHUB"
  }

  approval_config {
    approval_required = true
  }

  substitutions = merge(local.apply_substitutions, { _ALLOW_DESTROY = "true" })

  depends_on = [
    google_project_iam_member.apply_roles,
    google_cloudbuildv2_connection_iam_member.apply_read_token,
  ]
}

# Pushes to the deployed branch that touch the runner image: build, push and
# roll out once no scan is running (cloudbuild.yaml).
resource "google_cloudbuild_trigger" "image" {
  name            = "${var.resource_prefix}-image"
  project         = var.project_id
  location        = var.region
  description     = "Builds the runner image for pushes to ${var.branch} and rolls it out when no scan is running."
  service_account = google_service_account.image_build.id
  filename        = "cloudbuild.yaml"
  included_files  = var.image_included_files

  repository_event_config {
    repository = var.cloudbuild_repository
    push {
      branch = local.branch_pattern
    }
  }

  approval_config {
    approval_required = var.image_requires_approval
  }

  # cloudbuild.yaml enables dynamic substitutions, so ${SHORT_SHA} expands to
  # the commit being built.
  substitutions = {
    _RESOURCE_PREFIX = local.deployment_resource_prefix
    _REGION          = local.deployment_region
    _IMAGE_TAG       = "$${SHORT_SHA}"
    _UPDATE_JOBS     = "true"
    _MAX_WAIT_HOURS  = tostring(var.image_max_wait_hours)
  }

  depends_on = [google_project_iam_member.image_build_log_writer]
}
