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

output "nat_ip" {
  description = "Static IP address allocated for Cloud NAT (if VPC/NAT was created)."
  value       = local.cfg.create_vpc_and_nat ? google_compute_address.nat_ip[0].address : null
}

output "region" {
  description = "GCP Region for all resources."
  value       = local.cfg.region
}

output "reports_bucket_url" {
  description = "GCS bucket URL for scan reports."
  value       = google_storage_bucket.reports.url
}

output "reports_bucket_name" {
  description = "GCS bucket name for scan reports."
  value       = google_storage_bucket.reports.name
}


output "runner_job_name" {
  description = "Cloud Run Job name."
  value       = google_cloud_run_v2_job.runner.name
}

output "workflow_name" {
  description = "Cloud Workflows workflow name."
  value       = google_workflows_workflow.coordinator.name
}

output "scheduler_job_name" {
  description = "Primary Cloud Scheduler job name."
  value       = try(values(google_cloud_scheduler_job.repo_scans)[0].name, "")
}

output "scheduler_job_names" {
  description = "Map of repository keys to Cloud Scheduler job names."
  value       = { for k, v in google_cloud_scheduler_job.repo_scans : k => v.name }
}

output "artifact_registry_repository" {
  description = "Artifact Registry Docker repository path."
  value       = "${local.cfg.region}-docker.pkg.dev/${local.cfg.project_id}/${google_artifact_registry_repository.docker_repo.repository_id}"
}

output "container_build_command" {
  description = "Copy-paste Cloud Build command to build, push, and update the runner and worker Cloud Run Jobs."
  value       = "gcloud builds submit --config=cloudbuild.yaml --project=${local.cfg.project_id} --substitutions=_RESOURCE_PREFIX=${local.cfg.resource_prefix},_REGION=${local.cfg.region} ."
}

output "workflow_id" {
  description = "Cloud Workflows workflow ID."
  value       = google_workflows_workflow.coordinator.id
}

output "workflow_execution_url" {
  description = "API URL to trigger execution of the coordinator workflow."
  value       = "https://workflowexecutions.googleapis.com/v1/${google_workflows_workflow.coordinator.id}/executions"
}

output "bigquery_telemetry_dataset_id" {
  description = "BigQuery dataset ID holding CodeMender scan telemetry, or null when telemetry is disabled."
  value       = local.cfg.enable_bigquery_telemetry ? google_bigquery_dataset.telemetry[0].dataset_id : null
}

output "bigquery_telemetry_tables" {
  description = "Fully qualified BigQuery table IDs for scan telemetry."
  value = local.cfg.enable_bigquery_telemetry ? {
    scan_runs              = "${local.cfg.project_id}.${google_bigquery_dataset.telemetry[0].dataset_id}.${google_bigquery_table.scan_runs[0].table_id}"
    vulnerability_findings = "${local.cfg.project_id}.${google_bigquery_dataset.telemetry[0].dataset_id}.${google_bigquery_table.vulnerability_findings[0].table_id}"
  } : null
}

output "bigquery_telemetry_views" {
  description = "Fully qualified BigQuery view IDs for enriched scan analytics."
  value = local.cfg.enable_bigquery_telemetry ? {
    v_findings_enriched = "${local.cfg.project_id}.${google_bigquery_dataset.telemetry[0].dataset_id}.${google_bigquery_table.v_findings_enriched[0].table_id}"
    v_scan_runs_flat    = "${local.cfg.project_id}.${google_bigquery_dataset.telemetry[0].dataset_id}.${google_bigquery_table.v_scan_runs_flat[0].table_id}"
    v_token_usage       = "${local.cfg.project_id}.${google_bigquery_dataset.telemetry[0].dataset_id}.${google_bigquery_table.v_token_usage[0].table_id}"
  } : null
}

output "bigquery_console_url" {
  description = "Console link to the telemetry dataset, the entry point for Gemini Conversational Analytics and Data Canvas."
  value = local.cfg.enable_bigquery_telemetry ? format(
    "https://console.cloud.google.com/bigquery?project=%s&ws=!1m4!1m3!3m2!1s%s!2s%s",
    local.cfg.project_id,
    local.cfg.project_id,
    google_bigquery_dataset.telemetry[0].dataset_id,
  ) : null
}

output "bigquery_snippet_export_notice" {
  description = "Whether source code snippets and LLM analysis prose are being replicated into BigQuery."
  value = local.cfg.bigquery_include_snippets ? join("", [
    "WARNING: bigquery_include_snippets is TRUE. The `analysis` and `snippet` ",
    "columns are being exported, which replicates verbatim application source ",
    "code and vulnerability detail into a queryable warehouse. Confirm this is ",
    "permitted by the data-handling policy for every scanned repository.",
    ]) : join("", [
    "Snippet export is DISABLED (default). BigQuery receives vulnerability ",
    "metadata only -- no source code and no LLM analysis prose. Set ",
    "bigquery_include_snippets = true to enable richer narratives.",
  ])
}

output "secret_manager_notice" {
  description = "Instructions for updating the GitHub App Token secret (or the GitHub App private key when github_app_id is set)."
  value       = local.github_app_enabled ? local.github_app_secret_notice : <<EOT
The secret '${google_secret_manager_secret.github_app_token.secret_id}' has been created with placeholder data.
Please update it with your actual GitHub App Token before running scans:
  gcloud secrets versions add ${google_secret_manager_secret.github_app_token.secret_id} --data-file=/path/to/token.pem --project=${local.cfg.project_id}
EOT
}
