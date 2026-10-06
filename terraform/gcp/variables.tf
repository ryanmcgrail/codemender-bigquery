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

# ---------------------------------------------------------------------------
# YAML configuration (see config.tf). Every setting below can also be set in
# deployment.yaml, which takes precedence over tfvars and -var values.
# ---------------------------------------------------------------------------

variable "repos_file" {
  type        = string
  description = "Path to the repository list YAML, relative to the Terraform working directory. Leave null to read repos.yaml in this directory when it exists; set to \"\" to ignore YAML and use target_repositories only. Any other value must name an existing file. See repos.example.yaml."
  default     = null
}

variable "deployment_file" {
  type        = string
  description = "Path to the deployment settings YAML, relative to the Terraform working directory. Leave null to read deployment.yaml in this directory when it exists; set to \"\" to ignore it. Any other value must name an existing file. See deployment.example.yaml."
  default     = null
}

variable "project_id" {
  type        = string
  description = "The GCP Project ID where resources will be deployed. Required here or in deployment.yaml."
  default     = ""
}

variable "region" {
  type        = string
  description = "The GCP region for resource deployment."
  default     = "us-central1"
}

variable "resource_prefix" {
  type        = string
  description = "Prefix used for naming provisioned GCP resources to prevent multi-deployment collisions."
  default     = "codemender"
}

variable "reports_bucket_name" {
  type        = string
  description = "Name of the GCS bucket for scan reports."
  default     = ""
}


variable "runner_cpu" {
  type        = string
  description = "CPU limit for Cloud Run Job worker tasks (e.g. '1', '2', '4', '8')."
  default     = "4"
}

variable "runner_memory" {
  type        = string
  description = "Memory limit for Cloud Run Job worker tasks (e.g. '2Gi', '4Gi', '8Gi', '16Gi')."
  default     = "16Gi"
}

variable "initial_runner_image" {
  type        = string
  description = "Container image the runner and worker Cloud Run jobs are created with. Terraform ignores later image changes (image rollouts happen through cloudbuild.yaml), so this only takes effect when a job is first created or replaced. Defaults to a public placeholder; set it to a known-good runner image digest so a replaced job comes back on a real image."
  default     = "us-docker.pkg.dev/cloudrun/container/job:latest"
}

variable "cm_auto_update" {
  type        = bool
  description = "Whether each scan updates the CodeMender CLI to the latest release before it starts (`cm update`, through CODEMENDER_AUTO_UPDATE on the runner job). Stage 1 updates once and hands the same binary to the worker and Stage 3, so every stage of a scan runs the same release. If the update cannot reach the CLI's download server (for example inside a VPC Service Controls perimeter), the scan continues with the release baked into the image. Set to false to run exactly the release in the image."
  default     = true
}

variable "cloudbuild_service_account_emails" {
  type        = list(string)
  description = "Service account emails that build the runner image (cloudbuild.yaml) and roll it out to the Cloud Run jobs. They get Artifact Registry write access, permission to update the jobs, and read access to workflow executions (to wait for running scans). Leave null to grant the project's default Cloud Build service accounts (<number>@cloudbuild.gserviceaccount.com and <number>-compute@developer.gserviceaccount.com). With the terraform/bootstrap pipeline, set it to the image-build service account; also list the default compute service account if you still run `gcloud builds submit` by hand."
  default     = null
}

variable "create_vpc_and_nat" {
  type        = bool
  description = "Whether to create a dedicated VPC network, subnet, connector, and Cloud NAT for private egress."
  default     = false
}

variable "existing_vpc_connector_id" {
  type        = string
  description = "ID of an existing Serverless VPC Access Connector if create_vpc_and_nat is false."
  default     = null
}

variable "vpc_connector_cidr" {
  type        = string
  description = "CIDR range (/28 or /26) for the Serverless VPC Access Connector."
  default     = "10.0.0.0/26"

  validation {
    condition     = can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$", var.vpc_connector_cidr))
    error_message = "vpc_connector_cidr must be a valid IPv4 CIDR string (e.g., 10.0.0.0/26)."
  }
}

variable "vpc_connector_min_instances" {
  type        = number
  description = "Minimum number of instances for the Serverless VPC Access Connector."
  default     = 2
}

variable "vpc_connector_max_instances" {
  type        = number
  description = "Maximum number of instances for the Serverless VPC Access Connector."
  default     = 3
}

variable "vpc_connector_machine_type" {
  type        = string
  description = "Machine type for the Serverless VPC Access Connector."
  default     = "e2-micro"
}

variable "scheduler_cron" {
  type        = string
  description = "Cron expression for the nightly trigger."
  default     = "0 2 * * *"
}

variable "scheduler_timezone" {
  type        = string
  description = "Time zone for Cloud Scheduler jobs."
  default     = "Etc/UTC"
}

variable "scheduler_paused" {
  type        = bool
  description = "Whether Cloud Scheduler jobs should be created in a paused state."
  default     = false
}

variable "target_repositories" {
  type = map(object({
    repo_url      = string
    scan_target   = optional(string, ".")
    target_branch = optional(string, "")
    build_command = optional(string, "")
    schedule      = optional(string)
    max_tasks     = optional(number, 8)
    skip_verify   = optional(bool, true)
    model         = optional(string, "")
    find_model    = optional(string, "")
    verify_model  = optional(string, "")
    fix_model     = optional(string, "")
    # Extra cm flags per command, as shell-style strings (for example
    # find_flags = "--deep --deep-workers 4"). Flags the installed cm does not
    # support are dropped at run time with a warning.
    find_flags   = optional(string, "")
    verify_flags = optional(string, "")
    fix_flags    = optional(string, "")
    # Dry run: the scan, verify and fix stages run as usual, but the run makes
    # no GitHub writes (no fix pull requests, branch pushes, SARIF upload or
    # commit status) and skips remote duplicate checks.
    dry_run = optional(bool, false)
    # Opt-in Wiz SAST bridge. Disabled unless `enabled = true` is set for the
    # repository; configuring the Wiz secrets alone never enables it.
    wiz = optional(object({
      enabled      = optional(bool, false)
      min_severity = optional(string, "HIGH")
    }))
  }))
  description = "Map of repositories to schedule for automated CodeMender security scans. Merged with the repositories in repos.yaml (see repos_file); a repository defined in both takes the repos.yaml definition."
  default     = {}

  validation {
    condition = alltrue([
      for repo in values(var.target_repositories) :
      contains(
        ["INFORMATIONAL", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        upper(coalesce(try(repo.wiz.min_severity, null), "HIGH"))
      )
    ])
    error_message = "target_repositories[*].wiz.min_severity must be one of INFORMATIONAL, INFO, LOW, MEDIUM, HIGH, or CRITICAL."
  }
}

# ---------------------------------------------------------------------------
# Wiz SAST bridge (opt-in per repository via target_repositories[*].wiz)
# ---------------------------------------------------------------------------

variable "wiz_client_id_secret_id" {
  type        = string
  description = "Existing Secret Manager secret ID holding the Wiz service account client ID. Only read when at least one repository enables the Wiz bridge. Defaults to \"<resource_prefix>-wiz-client-id\" when empty. The secret is referenced, not managed, by Terraform."
  default     = ""
}

variable "wiz_client_secret_secret_id" {
  type        = string
  description = "Existing Secret Manager secret ID holding the Wiz service account client secret. Only read when at least one repository enables the Wiz bridge. Defaults to \"<resource_prefix>-wiz-client-secret\" when empty. The secret is referenced, not managed, by Terraform."
  default     = ""
}

# ---------------------------------------------------------------------------
# GitHub App authentication for scheduled scans (opt-in)
# ---------------------------------------------------------------------------

variable "github_app_id" {
  type        = string
  description = "GitHub App ID (or client ID) used by scheduled scans. When set, the runner and worker jobs mint short-lived installation tokens from the App's private key instead of reading the static token secret, and branch pushes, pull requests, comments and statuses are attributed to the App's bot account. The deployed runner image must include GitHub App support, because the static token is no longer mounted. Leave empty to keep using the static token in \"<resource_prefix>-github-token\"."
  default     = ""

  validation {
    condition     = !can(regex("\\s", var.github_app_id))
    error_message = "github_app_id must not contain whitespace."
  }
}

variable "github_app_installation_id" {
  type        = string
  description = "Optional GitHub App installation ID. When empty, the installation is looked up from each scanned repository, which requires the App to be installed on it."
  default     = ""

  validation {
    condition     = var.github_app_installation_id == "" || can(regex("^[1-9][0-9]*$", var.github_app_installation_id))
    error_message = "github_app_installation_id must be empty or a positive integer."
  }
}

variable "github_app_private_key_secret_id" {
  type        = string
  description = "Existing Secret Manager secret ID holding the GitHub App's PEM private key. Only read when github_app_id is set. Defaults to \"<resource_prefix>-github-app-private-key\" when empty. The secret is referenced, not managed, by Terraform, so the key never enters Terraform state."
  default     = ""
}

# ---------------------------------------------------------------------------
# Fix commit author identity (optional)
# ---------------------------------------------------------------------------

variable "git_author_name" {
  type        = string
  description = "Optional author and committer name for fix commits. When empty, the name is \"CodeMender Agent\", except that scans with a GitHub App and no git_author_email use the App's bot account (\"<app-slug>[bot]\")."
  default     = ""

  validation {
    condition     = !can(regex("[<>\\r\\n]", var.git_author_name))
    error_message = "git_author_name must not contain '<', '>' or line breaks."
  }
}

variable "git_author_email" {
  type        = string
  description = "Optional author and committer email for fix commits, for example an address your GitHub commit email rules accept. When empty, scans with a GitHub App use the App's bot noreply address and other scans use \"codemender-agent@noreply.invalid\"."
  default     = ""

  validation {
    condition     = !can(regex("[<>\\s]", var.git_author_email))
    error_message = "git_author_email must not contain '<', '>' or whitespace."
  }
}

# ---------------------------------------------------------------------------
# BigQuery analytics telemetry
# ---------------------------------------------------------------------------

variable "enable_bigquery_telemetry" {
  type        = bool
  description = "Whether to provision the BigQuery telemetry dataset and tables, grant the runner service account write access, and enable the export at runtime. When false, no BigQuery resources are created and the orchestrator performs zero BigQuery calls."
  default     = true
}

variable "bigquery_dataset_id" {
  type        = string
  description = "BigQuery dataset ID for CodeMender scan telemetry."
  default     = "codemender_telemetry"

  validation {
    # NB: the character-class check and the length check are separate on
    # purpose. A single `^[A-Za-z0-9_]{1,1024}$` will not compile -- Go's RE2
    # engine caps repeat counts at 1000 -- so `can()` would return false and
    # reject even valid dataset IDs.
    condition = (
      can(regex("^[A-Za-z0-9_]+$", var.bigquery_dataset_id))
      && length(var.bigquery_dataset_id) <= 1024
    )
    error_message = "bigquery_dataset_id must be 1-1024 characters of letters, numbers, and underscores only."
  }
}

variable "bigquery_location" {
  type        = string
  description = "Location for the BigQuery telemetry dataset (e.g. 'US', 'EU', 'us-central1'). Defaults to var.region when empty. Note that a dataset's location is immutable after creation."
  default     = ""
}

variable "bigquery_include_snippets" {
  type        = bool
  description = "Whether to export the LLM-generated `analysis` prose and verbatim source `snippet` columns to BigQuery. Defaults to false: these columns replicate real application source code and vulnerability detail into a queryable warehouse, which many regulated environments must review before enabling."
  default     = false
}

variable "bigquery_deletion_protection" {
  type        = bool
  description = "Whether the BigQuery telemetry tables are protected against deletion by Terraform."
  default     = true
}

variable "bigquery_delete_contents_on_destroy" {
  type        = bool
  description = "Whether `terraform destroy` may delete the telemetry dataset along with all historical scan records. Defaults to false because this dataset is the only durable record of scan history: the GCS report artifacts are deleted after 90 days."
  default     = false
}



