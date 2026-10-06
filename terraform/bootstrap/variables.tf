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

variable "project_id" {
  type        = string
  description = "Project that holds the Cloud Build triggers, the Terraform state bucket and the CodeMender deployment."
}

variable "region" {
  type        = string
  description = "Region of the Cloud Build triggers and the state bucket. Must be the region of the Cloud Build GitHub connection."
  default     = "us-central1"
}

variable "resource_prefix" {
  type        = string
  description = "Prefix for the service accounts, triggers and state bucket this stack creates. Use the same prefix as the CodeMender deployment unless you have a reason not to."
  default     = "codemender"

  validation {
    # 17 characters keeps the longest service account the deployment creates
    # with the same prefix, <prefix>-workflows-sa / <prefix>-scheduler-sa in
    # terraform/gcp, within the 30-character service account ID limit.
    condition     = can(regex("^[a-z]([a-z0-9-]{0,15}[a-z0-9])?$", var.resource_prefix))
    error_message = "resource_prefix must be 1-17 lowercase letters, digits or hyphens, start with a letter and not end with a hyphen."
  }
}

variable "cloudbuild_repository" {
  type        = string
  description = "The GitHub repository as linked to a Cloud Build 2nd-gen connection, in the form projects/<project>/locations/<region>/connections/<connection>/repositories/<repository>. Create the connection and link the repository once by hand (see the guide)."

  validation {
    condition     = can(regex("^projects/[^/]+/locations/[^/]+/connections/[^/]+/repositories/[^/]+$", var.cloudbuild_repository))
    error_message = "cloudbuild_repository must look like projects/<project>/locations/<region>/connections/<connection>/repositories/<repository>."
  }
}

variable "branch" {
  type        = string
  description = "The branch that is deployed. Pull requests into it are planned; pushes to it are applied."
  default     = "main"
}

variable "deployment_resource_prefix" {
  type        = string
  description = "resource_prefix of the CodeMender deployment (terraform/gcp), used to find its Artifact Registry repository and Cloud Run jobs. Defaults to resource_prefix."
  default     = null
}

variable "deployment_region" {
  type        = string
  description = "Region of the CodeMender deployment (terraform/gcp). Defaults to region."
  default     = null
}

variable "state_bucket_name" {
  type        = string
  description = "Name of the Terraform state bucket. Defaults to <resource_prefix>-tfstate-<project_id>."
  default     = null
}

variable "state_bucket_force_destroy" {
  type        = bool
  description = "Whether destroying this stack may delete the state bucket while it still holds state. Leave false outside throwaway test projects."
  default     = false
}

variable "state_prefix" {
  type        = string
  description = "Object prefix of the CodeMender deployment's state inside the state bucket."
  default     = "terraform/gcp"
}

variable "terraform_dir" {
  type        = string
  description = "Directory of the Terraform stack the pipeline plans and applies, relative to the repository root."
  default     = "terraform/gcp"
}

variable "apply_requires_approval" {
  type        = bool
  description = "Whether each apply after a merge waits for a manual approval in Cloud Build. By default merging the reviewed pull request is the approval."
  default     = false
}

variable "image_requires_approval" {
  type        = bool
  description = "Whether each runner image build after a merge waits for a manual approval in Cloud Build."
  default     = false
}

variable "approvers" {
  type        = list(string)
  description = "IAM members allowed to approve gated builds (the destroy trigger always; apply and image builds when their approval flag is set), for example [\"group:platform-admins@example.com\"]."
  default     = []

  validation {
    condition     = alltrue([for m in var.approvers : can(regex("^(user|group|serviceAccount|domain):[^\\s]+$", m))])
    error_message = "Each approver must be an IAM member such as user:alice@example.com or group:admins@example.com."
  }
}

variable "image_max_wait_hours" {
  type        = number
  description = "How long an image rollout waits for running scans to finish before giving up (whole hours, 0-12). cloudbuild.yaml's 13-hour build timeout caps it at 12."
  default     = 12

  validation {
    condition     = var.image_max_wait_hours >= 0 && var.image_max_wait_hours <= 12 && floor(var.image_max_wait_hours) == var.image_max_wait_hours
    error_message = "image_max_wait_hours must be a whole number from 0 to 12."
  }
}

variable "image_included_files" {
  type        = list(string)
  description = "Files whose change on the deployed branch rebuilds and rolls out the runner image (glob patterns)."
  default = [
    "Dockerfile",
    "cloudbuild.yaml",
    "codemender_agent/**",
    "orchestrator.py",
    "requirements.txt",
    "scripts/ci/image_rollout.sh",
    "scripts/ci/stage_cm.sh",
  ]
}
