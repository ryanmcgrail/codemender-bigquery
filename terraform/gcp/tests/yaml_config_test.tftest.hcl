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

# Unit tests for the repos.yaml / deployment.yaml loaders in config.tf.
mock_provider "google" {
  # Make the workflow ID known at plan time so the scheduler body can be
  # decoded and inspected.
  override_during = plan

  mock_resource "google_workflows_workflow" {
    defaults = {
      id = "projects/test-project-123/locations/us-central1/workflows/test-yaml-coordinator"
    }
  }
}
mock_provider "google-beta" {}
mock_provider "random" {}

variables {
  project_id      = "test-project-123"
  region          = "us-central1"
  resource_prefix = "test-yaml"
  scheduler_cron  = "0 2 * * *"
  repos_file      = ""
  deployment_file = ""
}

# ---------------------------------------------------------------------------
# repos.yaml
# ---------------------------------------------------------------------------

run "yaml_only_fills_the_same_defaults_as_tfvars" {
  command = plan

  variables {
    repos_file = "tests/fixtures/repos_valid.yaml"
  }

  assert {
    condition     = toset(keys(google_cloud_scheduler_job.repo_scans)) == toset(["svc-a", "svc_b"])
    error_message = "Each repos.yaml entry must become one scheduler job keyed by its name."
  }

  assert {
    condition     = google_cloud_scheduler_job.repo_scans["svc-a"].name == "test-yaml-scan-svc-a"
    error_message = "The scheduler job name must follow <resource_prefix>-scan-<name>."
  }

  assert {
    condition     = google_cloud_scheduler_job.repo_scans["svc-a"].schedule == "0 2 * * *"
    error_message = "A repository without a schedule must fall back to scheduler_cron."
  }

  assert {
    condition = jsondecode(jsondecode(base64decode(google_cloud_scheduler_job.repo_scans["svc-a"].http_target[0].body)).argument) == {
      job_name        = "test-yaml-runner"
      worker_job_name = "test-yaml-worker"
      gcs_bucket      = "test-yaml-reports-test-project-123"
      region          = "us-central1"
      repo_url        = "https://github.com/example-org/svc-a.git"
      scan_target     = "."
      target_branch   = ""
      build_command   = ""
      max_tasks       = 8
      skip_verify     = true
    }
    error_message = "A minimal repos.yaml entry must produce the default scheduler payload."
  }

  assert {
    condition     = google_cloud_scheduler_job.repo_scans["svc_b"].schedule == "30 4 * * 1"
    error_message = "A per-repository schedule must be used as is."
  }

  assert {
    condition = jsondecode(jsondecode(base64decode(google_cloud_scheduler_job.repo_scans["svc_b"].http_target[0].body)).argument) == {
      job_name        = "test-yaml-runner"
      worker_job_name = "test-yaml-worker"
      gcs_bucket      = "test-yaml-reports-test-project-123"
      region          = "us-central1"
      repo_url        = "https://github.com/example-org/svc-b.git"
      scan_target     = "src/;lib/"
      target_branch   = "develop"
      build_command   = "make test"
      max_tasks       = 4
      skip_verify     = false
      model           = "example-model"
      models = {
        find   = "example-find-model"
        verify = "example-verify-model"
        fix    = "example-fix-model"
      }
      wiz      = { enabled = true, min_severity = "MEDIUM" }
      cm_flags = { find = "--deep --deep-workers 4", fix = "--example-flag" }
      dry_run  = true
    }
    error_message = "Every repos.yaml setting must reach the scheduler payload."
  }

  assert {
    condition     = length(data.google_secret_manager_secret.wiz_client_id) == 1
    error_message = "A repos.yaml entry that enables Wiz must enable the Wiz bridge resources."
  }
}

run "tfvars_only_keeps_the_existing_addresses" {
  command = plan

  variables {
    target_repositories = {
      "legacy" = {
        repo_url = "https://github.com/example-org/legacy.git"
      }
    }
  }

  assert {
    condition     = keys(google_cloud_scheduler_job.repo_scans) == ["legacy"]
    error_message = "Without repos.yaml, target_repositories alone must define the scheduler jobs."
  }

  assert {
    condition     = google_cloud_scheduler_job.repo_scans["legacy"].name == "test-yaml-scan-legacy"
    error_message = "The scheduler job for a tfvars repository must keep its name."
  }
}

run "yaml_and_tfvars_are_merged_and_yaml_wins" {
  command = plan

  variables {
    repos_file = "tests/fixtures/repos_clash.yaml"
    target_repositories = {
      "shared" = {
        repo_url = "https://github.com/example-org/from-tfvars.git"
        schedule = "0 1 * * *"
      }
      "only-tfvars" = {
        repo_url = "https://github.com/example-org/only-tfvars.git"
      }
    }
  }

  assert {
    condition     = toset(keys(google_cloud_scheduler_job.repo_scans)) == toset(["shared", "only-tfvars"])
    error_message = "Repositories from both sources must be scheduled, once per name."
  }

  assert {
    condition     = jsondecode(jsondecode(base64decode(google_cloud_scheduler_job.repo_scans["shared"].http_target[0].body)).argument).repo_url == "https://github.com/example-org/from-yaml.git"
    error_message = "On a name clash the repos.yaml definition must win."
  }

  assert {
    condition     = google_cloud_scheduler_job.repo_scans["shared"].schedule == "0 5 * * *"
    error_message = "On a name clash the repos.yaml schedule must win."
  }
}

run "same_repository_gives_the_same_job_from_either_source" {
  command = plan

  variables {
    repos_file = "tests/fixtures/repos_equivalent.yaml"
    target_repositories = {
      "from-tfvars" = {
        repo_url   = "https://github.com/example-org/same.git"
        find_flags = "--deep"
      }
    }
  }

  assert {
    condition     = google_cloud_scheduler_job.repo_scans["from-yaml"].http_target[0].body == google_cloud_scheduler_job.repo_scans["from-tfvars"].http_target[0].body
    error_message = "A repository must produce an identical scheduler payload whether it is defined in repos.yaml or target_repositories."
  }

  assert {
    condition = (
      google_cloud_scheduler_job.repo_scans["from-yaml"].schedule == google_cloud_scheduler_job.repo_scans["from-tfvars"].schedule &&
      google_cloud_scheduler_job.repo_scans["from-yaml"].paused == google_cloud_scheduler_job.repo_scans["from-tfvars"].paused &&
      google_cloud_scheduler_job.repo_scans["from-yaml"].time_zone == google_cloud_scheduler_job.repo_scans["from-tfvars"].time_zone
    )
    error_message = "Schedule, pause state and time zone must not depend on the source."
  }
}

run "empty_repos_file_schedules_nothing" {
  command = plan

  variables {
    repos_file = "tests/fixtures/repos_empty.yaml"
  }

  assert {
    condition     = length(google_cloud_scheduler_job.repo_scans) == 0
    error_message = "An empty repos.yaml must not create scheduler jobs."
  }
}

run "typo_in_repository_key_is_rejected" {
  command = plan

  variables {
    repos_file = "tests/fixtures/repos_typo.yaml"
  }

  expect_failures = [terraform_data.config_checks]
}

run "missing_repo_url_is_rejected" {
  command = plan

  variables {
    repos_file = "tests/fixtures/repos_missing_url.yaml"
  }

  expect_failures = [terraform_data.config_checks]
}

run "malformed_cron_is_rejected" {
  command = plan

  variables {
    repos_file = "tests/fixtures/repos_bad_cron.yaml"
  }

  expect_failures = [terraform_data.config_checks]
}

run "empty_cron_is_rejected" {
  command = plan

  variables {
    repos_file = "tests/fixtures/repos_empty_cron.yaml"
  }

  expect_failures = [terraform_data.config_checks]
}

run "invalid_wiz_severity_is_rejected" {
  command = plan

  variables {
    repos_file = "tests/fixtures/repos_bad_severity.yaml"
  }

  expect_failures = [terraform_data.config_checks]
}

run "wrong_value_types_are_rejected" {
  command = plan

  variables {
    repos_file = "tests/fixtures/repos_bad_types.yaml"
  }

  expect_failures = [terraform_data.config_checks]
}

run "invalid_repository_name_is_rejected" {
  command = plan

  variables {
    repos_file = "tests/fixtures/repos_bad_name.yaml"
  }

  expect_failures = [terraform_data.config_checks]
}

run "wrong_top_level_key_is_rejected" {
  command = plan

  variables {
    repos_file = "tests/fixtures/repos_bad_root.yaml"
  }

  expect_failures = [terraform_data.config_checks]
}

run "missing_explicit_repos_file_is_rejected" {
  command = plan

  variables {
    repos_file = "tests/fixtures/does_not_exist.yaml"
  }

  expect_failures = [terraform_data.config_checks]
}

run "duplicate_repository_name_is_rejected" {
  command = plan

  variables {
    repos_file = "tests/fixtures/repos_duplicate.yaml"
  }

  expect_failures = [terraform_data.config_checks]
}

run "duplicate_detection_ignores_nested_keys" {
  command = plan

  variables {
    repos_file = "tests/fixtures/repos_valid.yaml"
  }

  assert {
    condition     = local.repos_entry_names == ["svc-a", "svc_b"] && length(local.repos_duplicate_errors) == 0
    error_message = "Only the entry names may count towards duplicates, not the keys inside each entry."
  }
}

run "duplicate_detection_handles_any_indent" {
  command = plan

  variables {
    repos_file = "tests/fixtures/repos_duplicate.yaml"
  }

  expect_failures = [terraform_data.config_checks]

  assert {
    condition     = local.repos_duplicate_errors == ["repositories.svc-a: listed more than once (only the last entry would be used)"]
    error_message = "A quoted and a plain spelling of the same name, indented by four spaces, must be reported once."
  }
}

# ---------------------------------------------------------------------------
# deployment.yaml
# ---------------------------------------------------------------------------

run "deployment_yaml_overrides_variables" {
  command = plan

  variables {
    project_id      = "tfvars-project"
    deployment_file = "tests/fixtures/deployment_valid.yaml"
    target_repositories = {
      "svc" = {
        repo_url = "https://github.com/example-org/svc.git"
      }
    }
  }

  assert {
    condition     = google_cloud_run_v2_job.runner.name == "yaml-prefix-runner" && google_cloud_run_v2_job.runner.location == "europe-west1" && google_cloud_run_v2_job.runner.project == "yaml-project"
    error_message = "resource_prefix, region and project_id from deployment.yaml must win over variables."
  }

  assert {
    condition     = google_cloud_run_v2_job.runner.template[0].template[0].containers[0].resources[0].limits.cpu == "2" && google_cloud_run_v2_job.worker.template[0].template[0].containers[0].resources[0].limits.memory == "8Gi"
    error_message = "A numeric runner_cpu in YAML must be converted to the string the variable expects."
  }

  assert {
    condition = (
      google_cloud_run_v2_job.runner.template[0].template[0].containers[0].image == "europe-west1-docker.pkg.dev/yaml-project/yaml-prefix-runner/orchestrator@sha256:0000000000000000000000000000000000000000000000000000000000000000" &&
      google_cloud_run_v2_job.worker.template[0].template[0].containers[0].image == google_cloud_run_v2_job.runner.template[0].template[0].containers[0].image
    )
    error_message = "initial_runner_image must be used for both jobs."
  }

  assert {
    condition     = google_cloud_scheduler_job.repo_scans["svc"].paused == true && google_cloud_scheduler_job.repo_scans["svc"].schedule == "15 1 * * *" && google_cloud_scheduler_job.repo_scans["svc"].region == "europe-west1"
    error_message = "scheduler_paused, scheduler_cron and region from deployment.yaml must reach the scheduler jobs."
  }

  assert {
    condition     = contains([for e in google_cloud_run_v2_job.runner.template[0].template[0].containers[0].env : "${e.name}=${e.value}" if e.name == "GITHUB_APP_ID"], "GITHUB_APP_ID=123456")
    error_message = "A numeric github_app_id in YAML must be converted to a string."
  }

  assert {
    condition     = length(google_bigquery_dataset.telemetry) == 0
    error_message = "enable_bigquery_telemetry = false in deployment.yaml must disable telemetry."
  }
}

run "initial_runner_image_defaults_to_the_placeholder" {
  command = plan

  assert {
    condition     = google_cloud_run_v2_job.runner.template[0].template[0].containers[0].image == "us-docker.pkg.dev/cloudrun/container/job:latest" && google_cloud_run_v2_job.worker.template[0].template[0].containers[0].image == "us-docker.pkg.dev/cloudrun/container/job:latest"
    error_message = "Without initial_runner_image the jobs must keep the public placeholder image."
  }
}

run "typo_in_deployment_key_is_rejected" {
  command = plan

  variables {
    deployment_file = "tests/fixtures/deployment_typo.yaml"
  }

  expect_failures = [terraform_data.config_checks]
}

run "wrong_deployment_value_types_are_rejected" {
  command = plan

  variables {
    deployment_file = "tests/fixtures/deployment_bad_types.yaml"
  }

  expect_failures = [terraform_data.config_checks]
}

run "invalid_deployment_values_are_rejected" {
  command = plan

  variables {
    deployment_file = "tests/fixtures/deployment_bad_values.yaml"
  }

  expect_failures = [terraform_data.config_checks]
}

run "deployment_file_must_be_a_mapping" {
  command = plan

  variables {
    deployment_file = "tests/fixtures/deployment_not_a_map.yaml"
  }

  expect_failures = [terraform_data.config_checks]
}

run "project_id_is_required_somewhere" {
  command = plan

  variables {
    project_id = ""
  }

  expect_failures = [terraform_data.config_checks]
}

run "deployment_yaml_sets_cloud_build_accounts" {
  command = plan

  variables {
    deployment_file = "tests/fixtures/deployment_build_accounts.yaml"
  }

  assert {
    condition = toset(keys(google_project_iam_member.cloudbuild_run_developer)) == toset([
      "image-build@yaml-project.iam.gserviceaccount.com",
      "123456789-compute@developer.gserviceaccount.com",
    ])
    error_message = "cloudbuild_service_account_emails from deployment.yaml must replace the default Cloud Build accounts."
  }
}

run "cloud_build_accounts_must_be_a_list" {
  command = plan

  variables {
    deployment_file = "tests/fixtures/deployment_build_accounts_scalar.yaml"
  }

  expect_failures = [terraform_data.config_checks]
}

# ---------------------------------------------------------------------------
# The committed examples must stay valid.
# ---------------------------------------------------------------------------

run "example_files_are_valid" {
  command = plan

  variables {
    repos_file      = "repos.example.yaml"
    deployment_file = "deployment.example.yaml"
  }

  assert {
    condition     = toset(keys(google_cloud_scheduler_job.repo_scans)) == toset(["example-service", "example-api"])
    error_message = "repos.example.yaml must plan cleanly and define its two example repositories."
  }

  assert {
    condition     = google_cloud_scheduler_job.repo_scans["example-api"].paused == true
    error_message = "deployment.example.yaml must start with the scheduler paused."
  }
}

# The provider rejects most bad prefixes itself (too long, upper case); a
# trailing hyphen gets past it, so it shows the precondition on its own.
run "prefix_ending_in_hyphen_is_rejected" {
  command = plan

  variables {
    resource_prefix = "test-yaml-"
  }

  expect_failures = [terraform_data.config_checks]
}
