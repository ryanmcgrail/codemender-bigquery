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

output "state_bucket" {
  description = "The Terraform state bucket for terraform/gcp."
  value       = google_storage_bucket.state.name
}

output "tf_plan_service_account" {
  description = "Service account of the pull request plan trigger."
  value       = google_service_account.tf_plan.email
}

output "tf_apply_service_account" {
  description = "Service account of the apply triggers."
  value       = google_service_account.tf_apply.email
}

output "image_build_service_account" {
  description = "Service account of the runner image trigger. List it in deployment.yaml (cloudbuild_service_account_emails)."
  value       = google_service_account.image_build.email
}

output "triggers" {
  description = "Cloud Build trigger names. Make the plan trigger's check (named after the trigger) a required status check on the deployed branch."
  value = {
    plan          = google_cloudbuild_trigger.tf_plan.name
    apply         = google_cloudbuild_trigger.tf_apply.name
    apply_destroy = google_cloudbuild_trigger.tf_apply_destroy.name
    image         = google_cloudbuild_trigger.image.name
  }
}

output "deployment_yaml_snippet" {
  description = "Settings to add to terraform/gcp/deployment.yaml so the image build service account can push and roll out images."
  value       = <<-EOT
    project_id: ${var.project_id}
    region: ${local.deployment_region}
    resource_prefix: ${local.deployment_resource_prefix}
    cloudbuild_service_account_emails:
      - ${google_service_account.image_build.email}
  EOT
}

output "local_init_command" {
  description = "Initialises terraform/gcp against the shared state from a workstation (run from the repository root)."
  value       = "TF_STATE_BUCKET=${google_storage_bucket.state.name} TF_STATE_PREFIX=${var.state_prefix} TF_DIR=${var.terraform_dir} scripts/ci/tf_init.sh"
}
