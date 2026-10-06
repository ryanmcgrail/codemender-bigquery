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

# Unit tests for the Cloud Build bootstrap stack. Mock providers, so no cloud
# credentials are needed.
mock_provider "google" {}
mock_provider "random" {}

variables {
  project_id            = "test-project-123"
  region                = "us-central1"
  resource_prefix       = "cmtest"
  cloudbuild_repository = "projects/test-project-123/locations/us-central1/connections/github/repositories/example-org-cm"
}

run "defaults" {
  command = plan

  assert {
    condition = (
      google_storage_bucket.state.name == "cmtest-tfstate-test-project-123" &&
      google_storage_bucket.state.location == "us-central1" &&
      google_storage_bucket.state.versioning[0].enabled &&
      google_storage_bucket.state.uniform_bucket_level_access &&
      google_storage_bucket.state.public_access_prevention == "enforced" &&
      google_storage_bucket.state.force_destroy == false
    )
    error_message = "The state bucket must be versioned, uniform-access, public-access-blocked and protected from force-destroy by default."
  }

  assert {
    condition = (
      google_service_account.tf_plan.account_id == "cmtest-tf-plan" &&
      google_service_account.tf_apply.account_id == "cmtest-tf-apply" &&
      google_service_account.image_build.account_id == "cmtest-image-build"
    )
    error_message = "Service account IDs must follow the prefix."
  }

  assert {
    condition = (
      google_cloudbuild_trigger.tf_plan.name == "cmtest-tf-plan" &&
      google_cloudbuild_trigger.tf_apply.name == "cmtest-tf-apply" &&
      google_cloudbuild_trigger.tf_apply_destroy.name == "cmtest-tf-apply-destroy" &&
      google_cloudbuild_trigger.image.name == "cmtest-image"
    )
    error_message = "Trigger names must follow the prefix."
  }

  assert {
    condition = alltrue([
      for t in [google_cloudbuild_trigger.tf_plan, google_cloudbuild_trigger.tf_apply, google_cloudbuild_trigger.tf_apply_destroy, google_cloudbuild_trigger.image] :
      t.location == "us-central1" && t.project == "test-project-123"
    ])
    error_message = "All triggers must be regional, in the connection's region."
  }
}

run "plan_trigger_runs_every_pull_request_read_only" {
  command = plan

  assert {
    condition = (
      google_cloudbuild_trigger.tf_plan.filename == "cloudbuild/terraform-plan.yaml" &&
      google_cloudbuild_trigger.tf_plan.repository_event_config[0].repository == var.cloudbuild_repository &&
      google_cloudbuild_trigger.tf_plan.repository_event_config[0].pull_request[0].branch == "^main$" &&
      google_cloudbuild_trigger.tf_plan.repository_event_config[0].pull_request[0].comment_control == "COMMENTS_ENABLED_FOR_EXTERNAL_CONTRIBUTORS_ONLY" &&
      length(google_cloudbuild_trigger.tf_plan.repository_event_config[0].push) == 0
    )
    error_message = "The plan trigger must run cloudbuild/terraform-plan.yaml for pull requests into main."
  }

  assert {
    condition     = google_cloudbuild_trigger.tf_plan.included_files == null || length(coalesce(google_cloudbuild_trigger.tf_plan.included_files, [])) == 0
    error_message = "The plan trigger must not filter files, or a required check could never report."
  }

  assert {
    condition = (
      google_cloudbuild_trigger.tf_plan.substitutions["_TF_STATE_PREFIX"] == "terraform/gcp" &&
      google_cloudbuild_trigger.tf_plan.substitutions["_TF_DIR"] == "terraform/gcp" &&
      !contains(keys(google_cloudbuild_trigger.tf_plan.substitutions), "_ALLOW_DESTROY")
    )
    error_message = "The plan trigger must pass the state location and nothing else."
  }
}

run "plan_identity_cannot_read_executions_or_data" {
  command = plan

  assert {
    condition = length(setintersection(toset(keys(google_project_iam_member.plan_roles)), toset([
      "roles/viewer",
      "roles/editor",
      "roles/owner",
      "roles/iam.securityReviewer",
      "roles/run.viewer",
      "roles/run.developer",
      "roles/workflows.viewer",
      "roles/bigquery.dataViewer",
      "roles/secretmanager.secretAccessor",
      "roles/storage.objectViewer",
    ]))) == 0
    error_message = "The plan identity must not get project roles that read executions, BigQuery data, secret payloads or objects."
  }

  assert {
    condition = length([
      for p in google_project_iam_custom_role.plan_reader.permissions : p
      if can(regex("^(run\\.executions\\.|workflows\\.executions\\.|bigquery\\.tables\\.getData|secretmanager\\.versions\\.access|storage\\.objects\\.)", p))
    ]) == 0
    error_message = "The plan reader role must not include execution, data, secret payload or object permissions."
  }

  assert {
    condition     = google_storage_bucket_iam_member.plan_state_reader.role == "roles/storage.objectViewer"
    error_message = "The plan identity reads the state bucket only."
  }
}

run "apply_trigger_auto_applies_with_guard" {
  command = plan

  assert {
    condition = (
      google_cloudbuild_trigger.tf_apply.filename == "cloudbuild/terraform-apply.yaml" &&
      google_cloudbuild_trigger.tf_apply.repository_event_config[0].push[0].branch == "^main$" &&
      google_cloudbuild_trigger.tf_apply.approval_config[0].approval_required == false &&
      google_cloudbuild_trigger.tf_apply.substitutions["_ALLOW_DESTROY"] == "false" &&
      google_cloudbuild_trigger.tf_apply.substitutions["_CLOUDBUILD_REPO"] == var.cloudbuild_repository &&
      google_cloudbuild_trigger.tf_apply.substitutions["_DEPLOY_BRANCH"] == "main" &&
      google_cloudbuild_trigger.tf_apply.substitutions["_DESTROY_TRIGGER"] == "cmtest-tf-apply-destroy"
    )
    error_message = "By default the apply trigger applies pushes to main without approval and with the destroy guard on."
  }

  assert {
    condition = (
      google_cloudbuildv2_connection_iam_member.apply_read_token.name == "github" &&
      google_cloudbuildv2_connection_iam_member.apply_read_token.location == "us-central1" &&
      google_cloudbuildv2_connection_iam_member.apply_read_token.role == "roles/cloudbuild.readTokenAccessor"
    )
    error_message = "The apply identity must get roles/cloudbuild.readTokenAccessor on the repository's Cloud Build connection."
  }

  assert {
    condition = (
      google_cloudbuild_trigger.tf_apply_destroy.approval_config[0].approval_required == true &&
      google_cloudbuild_trigger.tf_apply_destroy.substitutions["_ALLOW_DESTROY"] == "true" &&
      google_cloudbuild_trigger.tf_apply_destroy.substitutions["_CLOUDBUILD_REPO"] == var.cloudbuild_repository &&
      google_cloudbuild_trigger.tf_apply_destroy.substitutions["_DEPLOY_BRANCH"] == "main" &&
      google_cloudbuild_trigger.tf_apply_destroy.substitutions["_DESTROY_TRIGGER"] == "cmtest-tf-apply-destroy" &&
      google_cloudbuild_trigger.tf_apply_destroy.git_file_source[0].path == "cloudbuild/terraform-apply.yaml" &&
      google_cloudbuild_trigger.tf_apply_destroy.source_to_build[0].ref == "refs/heads/main" &&
      length(google_cloudbuild_trigger.tf_apply_destroy.repository_event_config) == 0
    )
    error_message = "The destroy trigger must be manual, always approval-gated, and the only one that allows destroys."
  }
}

run "image_trigger" {
  command = plan

  assert {
    condition = (
      google_cloudbuild_trigger.image.filename == "cloudbuild.yaml" &&
      contains(google_cloudbuild_trigger.image.included_files, "codemender_agent/**") &&
      contains(google_cloudbuild_trigger.image.included_files, "Dockerfile") &&
      google_cloudbuild_trigger.image.approval_config[0].approval_required == false
    )
    error_message = "The image trigger must build cloudbuild.yaml on code changes without approval by default."
  }

  assert {
    condition = (
      google_cloudbuild_trigger.image.substitutions["_RESOURCE_PREFIX"] == "cmtest" &&
      google_cloudbuild_trigger.image.substitutions["_REGION"] == "us-central1" &&
      google_cloudbuild_trigger.image.substitutions["_IMAGE_TAG"] == "$${SHORT_SHA}" &&
      google_cloudbuild_trigger.image.substitutions["_UPDATE_JOBS"] == "true" &&
      google_cloudbuild_trigger.image.substitutions["_MAX_WAIT_HOURS"] == "12"
    )
    error_message = "The image trigger must tag by commit and roll out with the configured wait."
  }
}

run "approvals_and_overrides" {
  command = plan

  variables {
    apply_requires_approval    = true
    image_requires_approval    = true
    approvers                  = ["group:platform-admins@example.com", "user:alice@example.com"]
    branch                     = "release.1"
    deployment_resource_prefix = "codemender"
    deployment_region          = "europe-west1"
    state_bucket_name          = "custom-state-bucket"
    state_prefix               = "cm/gcp"
    image_max_wait_hours       = 4
  }

  assert {
    condition = (
      google_cloudbuild_trigger.tf_apply.approval_config[0].approval_required &&
      google_cloudbuild_trigger.image.approval_config[0].approval_required
    )
    error_message = "The approval flags must gate the apply and image triggers."
  }

  assert {
    condition = (
      length(google_project_iam_member.approvers) == 2 &&
      google_project_iam_member.approvers["group:platform-admins@example.com"].role == "roles/cloudbuild.builds.approver"
    )
    error_message = "Each approver must get the Cloud Build approver role."
  }

  assert {
    condition = (
      google_cloudbuild_trigger.tf_apply.repository_event_config[0].push[0].branch == "^release\\.1$" &&
      google_cloudbuild_trigger.tf_apply.substitutions["_DEPLOY_BRANCH"] == "release.1" &&
      google_cloudbuild_trigger.tf_apply_destroy.source_to_build[0].ref == "refs/heads/release.1" &&
      google_cloudbuild_trigger.tf_apply_destroy.substitutions["_DEPLOY_BRANCH"] == "release.1"
    )
    error_message = "The branch must be matched literally."
  }

  assert {
    condition = (
      google_storage_bucket.state.name == "custom-state-bucket" &&
      google_cloudbuild_trigger.tf_apply.substitutions["_TF_STATE_PREFIX"] == "cm/gcp" &&
      google_cloudbuild_trigger.image.substitutions["_RESOURCE_PREFIX"] == "codemender" &&
      google_cloudbuild_trigger.image.substitutions["_REGION"] == "europe-west1" &&
      google_cloudbuild_trigger.image.substitutions["_MAX_WAIT_HOURS"] == "4"
    )
    error_message = "Overrides must reach the bucket and trigger substitutions."
  }
}

run "repository_in_another_region_is_rejected" {
  command = plan

  variables {
    cloudbuild_repository = "projects/test-project-123/locations/europe-west1/connections/github/repositories/example-org-cm"
  }

  expect_failures = [google_cloudbuild_trigger.tf_plan]
}

run "malformed_repository_is_rejected" {
  command = plan

  variables {
    cloudbuild_repository = "example-org/cm"
  }

  expect_failures = [var.cloudbuild_repository]
}

run "long_prefix_is_rejected" {
  command = plan

  variables {
    resource_prefix = "a-much-too-long-prefix"
  }

  expect_failures = [var.resource_prefix]
}

# 18 characters would pass the bootstrap's own service accounts, but
# terraform/gcp then builds <prefix>-workflows-sa (31 characters).
run "eighteen_character_prefix_is_rejected" {
  command = plan

  variables {
    resource_prefix = "abcdefghijklmnopqr"
  }

  expect_failures = [var.resource_prefix]
}

run "seventeen_character_prefix_is_accepted" {
  command = plan

  variables {
    resource_prefix = "abcdefghijklmnopq"
  }

  assert {
    condition     = google_service_account.image_build.account_id == "abcdefghijklmnopq-image-build"
    error_message = "A 17-character prefix must be accepted."
  }
}

run "wait_beyond_build_timeout_is_rejected" {
  command = plan

  variables {
    image_max_wait_hours = 13
  }

  expect_failures = [var.image_max_wait_hours]
}

run "bad_approver_is_rejected" {
  command = plan

  variables {
    approvers = ["alice@example.com"]
  }

  expect_failures = [var.approvers]
}
