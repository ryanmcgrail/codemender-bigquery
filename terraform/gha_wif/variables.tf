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

# --- GCP Infrastructure Variables ---

variable "gcp_project_id" {
  type        = string
  description = "The GCP Project ID hosting Vertex AI where Gemini LLM APIs will be queried."
}

variable "gcp_region" {
  type        = string
  default     = "global"
  description = "The GCP region for resource deployment."
}

variable "gcp_service_account_id" {
  type        = string
  default     = "codemender-gha-sa"
  description = "ID of the dedicated Service Account to create for CodeMender runner in GCP."
}

variable "gcp_wif_pool_id" {
  type        = string
  default     = "codemender-gha-pool"
  description = "ID of the Workload Identity Pool to create in GCP."
}

variable "gcp_wif_provider_id" {
  type        = string
  default     = "codemender-gha-provider"
  description = "ID of the Workload Identity Provider to create in GCP."
}

# --- Workload Identity Federation (WIF) Scoping ---

variable "github_scope_type" {
  type        = string
  default     = "org"
  description = "Scoping type for WIF authentication: 'org' (all repos in org), 'user' (all repos under user), or 'repositories' (specific repo allowlist)."

  validation {
    condition     = contains(["org", "user", "repositories"], var.github_scope_type)
    error_message = "github_scope_type must be one of: 'org', 'user', 'repositories'."
  }
}

variable "github_owner" {
  type        = string
  default     = ""
  description = "GitHub organization name (e.g. 'my-org') or username (e.g. 'octocat'). Required if github_scope_type is 'org' or 'user'."
}

variable "wif_allowed_repositories" {
  type        = list(string)
  default     = []
  description = "List of allowed GitHub repositories in 'owner/repo' format. Defines the GCP IAM security perimeter (REQUIRED ONLY if github_scope_type is 'repositories')."
}

variable "github_oidc_issuer_uri" {
  type        = string
  default     = "https://token.actions.githubusercontent.com"
  description = "OIDC issuer of the GitHub Actions tokens. The default is right for github.com; GitHub Enterprise Cloud with data residency (GHE.com) uses an enterprise-specific issuer, for example https://token.actions.<subdomain>.ghe.com."

  validation {
    condition     = can(regex("^https://[^\\s/]+(/[^\\s]*)?$", var.github_oidc_issuer_uri))
    error_message = "github_oidc_issuer_uri must be an https:// URL."
  }
}

# --- GitHub Platform Configuration ---

variable "target_github_repositories" {
  type        = list(string)
  default     = []
  description = "List of target repository names where GitHub Actions secrets and the 'codemender-scan' label should be configured (defaults to wif_allowed_repositories if left empty when github_scope_type is 'repositories')."
}

variable "github_app_id" {
  type        = string
  default     = ""
  description = "Numeric GitHub App ID to automatically populate as GH_APP_ID secret in target repositories."
}

variable "github_mgmt_token" {
  type        = string
  default     = null
  sensitive   = true
  description = "GitHub Personal Access Token with repository admin permissions (can also be provided via GITHUB_TOKEN environment variable)."
}
