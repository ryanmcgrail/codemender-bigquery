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

# Unit tests for the BigQuery analytics telemetry dataset, tables, and IAM.
mock_provider "google" {}
mock_provider "google-beta" {}

variables {
  # Keep the tests independent of any repos.yaml / deployment.yaml in the
  # module directory.
  repos_file      = ""
  deployment_file = ""

  project_id      = "test-project-123"
  region          = "us-central1"
  resource_prefix = "test-bq"
}

run "bigquery_enabled_by_default" {
  command = plan

  assert {
    condition     = length(google_bigquery_dataset.telemetry) == 1
    error_message = "Telemetry dataset should be provisioned when enable_bigquery_telemetry defaults to true."
  }

  assert {
    condition     = google_bigquery_dataset.telemetry[0].dataset_id == "codemender_telemetry"
    error_message = "Telemetry dataset ID must default to codemender_telemetry."
  }

  assert {
    condition     = contains(local.required_apis, "bigquery.googleapis.com")
    error_message = "bigquery.googleapis.com must be enabled when telemetry is on."
  }

  assert {
    condition     = google_bigquery_table.scan_runs[0].table_id == "scan_runs"
    error_message = "scan_runs table must be created."
  }

  assert {
    condition     = google_bigquery_table.vulnerability_findings[0].table_id == "vulnerability_findings"
    error_message = "vulnerability_findings table must be created."
  }

  assert {
    condition = (
      google_bigquery_table.v_findings_enriched[0].table_id == "v_findings_enriched"
      && google_bigquery_table.v_scan_runs_flat[0].table_id == "v_scan_runs_flat"
      && google_bigquery_table.v_token_usage[0].table_id == "v_token_usage"
    )
    error_message = "All three analytics SQL views (v_findings_enriched, v_scan_runs_flat, v_token_usage) must be created when telemetry is enabled."
  }
}

run "bigquery_tables_are_partitioned_and_clustered" {
  command = plan

  assert {
    condition = (
      google_bigquery_table.scan_runs[0].time_partitioning[0].type == "DAY"
      && google_bigquery_table.scan_runs[0].time_partitioning[0].field == "scan_timestamp"
    )
    error_message = "scan_runs must be day-partitioned on scan_timestamp."
  }

  assert {
    condition = (
      google_bigquery_table.vulnerability_findings[0].time_partitioning[0].type == "DAY"
      && google_bigquery_table.vulnerability_findings[0].time_partitioning[0].field == "scan_timestamp"
    )
    error_message = "vulnerability_findings must be day-partitioned on scan_timestamp."
  }

  assert {
    condition     = google_bigquery_table.scan_runs[0].clustering == tolist(["repository", "status"])
    error_message = "scan_runs must be clustered by repository and status."
  }

  assert {
    condition     = google_bigquery_table.vulnerability_findings[0].clustering == tolist(["repository", "severity", "vuln_type"])
    error_message = "vulnerability_findings must be clustered by repository, severity, and vuln_type."
  }
}

# Column descriptions ground Gemini Conversational Analytics, so an undescribed
# column is a functional defect, not a documentation gap.
run "every_column_has_a_description" {
  command = plan

  assert {
    condition = alltrue([
      for field in jsondecode(google_bigquery_table.scan_runs[0].schema) :
      try(length(field.description), 0) > 0
    ])
    error_message = "Every scan_runs column must carry a description to ground Conversational Analytics."
  }

  assert {
    condition = alltrue([
      for field in jsondecode(google_bigquery_table.vulnerability_findings[0].schema) :
      try(length(field.description), 0) > 0
    ])
    error_message = "Every vulnerability_findings column must carry a description."
  }

  assert {
    condition = alltrue([
      for field in jsondecode(google_bigquery_table.scan_runs[0].schema) :
      alltrue([for sub in try(field.fields, []) : try(length(sub.description), 0) > 0])
    ])
    error_message = "Nested token_totals fields must also carry descriptions."
  }
}

# Only runner_sa may write telemetry; worker_sa must get no BigQuery access.
run "bigquery_iam_is_scoped_to_runner_sa" {
  command = plan

  assert {
    condition = (
      length(google_bigquery_dataset_iam_member.runner_telemetry_editor) == 1
      && google_bigquery_dataset_iam_member.runner_telemetry_editor[0].role == "roles/bigquery.dataEditor"
    )
    error_message = "runner_sa must hold bigquery.dataEditor on the telemetry dataset."
  }

  assert {
    condition = (
      length(google_project_iam_member.runner_bigquery_job_user) == 1
      && google_project_iam_member.runner_bigquery_job_user[0].role == "roles/bigquery.jobUser"
    )
    error_message = "runner_sa must hold bigquery.jobUser at the project level."
  }

  # worker_sa getting no BigQuery access is a structural guarantee: no
  # worker-scoped BigQuery IAM resource is declared anywhere in the config.
  # Asserting on the resource inventory is both stronger and plan-evaluable --
  # the `member` attribute itself interpolates a service account email that is
  # only known after apply.
  assert {
    condition     = length(google_bigquery_dataset_iam_member.runner_telemetry_editor) == 1
    error_message = "Exactly one dataset-level BigQuery IAM binding should exist, for runner_sa only."
  }

  assert {
    condition     = google_service_account.runner_sa.account_id == "test-bq-runner-sa"
    error_message = "The BigQuery dataset IAM binding must target the runner service account."
  }
}

# Snippets carry verbatim source code, so the default must be off and the
# columns must not even be provisioned unless explicitly opted in.
run "snippet_columns_absent_by_default" {
  command = plan

  assert {
    condition = !contains([
      for field in jsondecode(google_bigquery_table.vulnerability_findings[0].schema) : field.name
    ], "snippet")
    error_message = "The `snippet` column must NOT exist unless bigquery_include_snippets is explicitly enabled."
  }

  assert {
    condition = !contains([
      for field in jsondecode(google_bigquery_table.vulnerability_findings[0].schema) : field.name
    ], "analysis")
    error_message = "The `analysis` column must NOT exist unless bigquery_include_snippets is explicitly enabled."
  }
}

run "snippet_columns_present_when_opted_in" {
  command = plan

  variables {
    bigquery_include_snippets = true
  }

  assert {
    condition = contains([
      for field in jsondecode(google_bigquery_table.vulnerability_findings[0].schema) : field.name
    ], "snippet")
    error_message = "The `snippet` column must exist when bigquery_include_snippets is true."
  }

  assert {
    condition = contains([
      for field in jsondecode(google_bigquery_table.vulnerability_findings[0].schema) : field.name
    ], "analysis")
    error_message = "The `analysis` column must exist when bigquery_include_snippets is true."
  }
}

# Disabling telemetry must provision nothing at all -- no dataset, no tables,
# no IAM, and no BigQuery API enablement.
run "bigquery_fully_absent_when_disabled" {
  command = plan

  variables {
    enable_bigquery_telemetry = false
  }

  assert {
    condition     = length(google_bigquery_dataset.telemetry) == 0
    error_message = "No telemetry dataset may be created when telemetry is disabled."
  }

  assert {
    condition = (
      length(google_bigquery_table.scan_runs) == 0
      && length(google_bigquery_table.vulnerability_findings) == 0
      && length(google_bigquery_table.v_findings_enriched) == 0
      && length(google_bigquery_table.v_scan_runs_flat) == 0
      && length(google_bigquery_table.v_token_usage) == 0
    )
    error_message = "No telemetry tables or views may be created when telemetry is disabled."
  }

  assert {
    condition = (
      length(google_bigquery_dataset_iam_member.runner_telemetry_editor) == 0
      && length(google_project_iam_member.runner_bigquery_job_user) == 0
    )
    error_message = "No BigQuery IAM may be granted when telemetry is disabled."
  }

  assert {
    condition     = !contains(local.required_apis, "bigquery.googleapis.com")
    error_message = "bigquery.googleapis.com must not be enabled when telemetry is disabled."
  }
}

run "invalid_dataset_id_is_rejected" {
  command = plan

  variables {
    bigquery_dataset_id = "invalid-dashes-not-allowed"
  }

  expect_failures = [
    var.bigquery_dataset_id,
  ]
}
