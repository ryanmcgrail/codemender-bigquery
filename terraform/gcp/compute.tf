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
  # Optional fix commit author identity, read by both jobs (see
  # codemender_agent/vcs/git.py). Unset values are left out entirely, so the
  # plan is unchanged for deployments that do not set them.
  git_author_env = merge(
    local.cfg.git_author_name != "" ? { CODEMENDER_GIT_AUTHOR_NAME = local.cfg.git_author_name } : {},
    local.cfg.git_author_email != "" ? { CODEMENDER_GIT_AUTHOR_EMAIL = local.cfg.git_author_email } : {},
  )
}

resource "time_sleep" "wait_for_apis_and_iam" {
  create_duration = "60s"

  depends_on = [
    google_project_service.enabled_services,
    google_secret_manager_secret_iam_member.runner_secret_accessor,
    google_project_iam_member.workflow_jobs_executor,
    google_project_iam_member.workflow_run_viewer,
    google_service_account_iam_member.workflow_runner_sa_user,
    google_project_service_identity.workflows_sa
  ]
}

resource "google_cloud_run_v2_job" "runner" {
  name                = "${local.cfg.resource_prefix}-runner"
  location            = local.cfg.region
  project             = local.cfg.project_id
  deletion_protection = false

  template {
    template {
      service_account = google_service_account.runner_sa.email
      timeout         = "86400s"
      max_retries     = 0

      containers {
        # The image the job is created with (a public placeholder by default,
        # so Terraform can provision the job before Cloud Build runs). The
        # actual image is deployed out-of-band via Cloud Build (see
        # cloudbuild.yaml), which is why the image is in ignore_changes below.
        image = local.cfg.initial_runner_image

        resources {
          limits = {
            cpu    = local.cfg.runner_cpu
            memory = local.cfg.runner_memory
          }
        }

        env {
          name  = "GOOGLE_CLOUD_PROJECT"
          value = local.cfg.project_id
        }

        env {
          name  = "WORKSPACE_DIR"
          value = "/workspace"
        }

        env {
          name  = "CODEMENDER_SANDBOX_ENABLED"
          value = "false"
        }

        # Stage 1 runs `cm update` before scanning when this is true and hands
        # the updated binary to the worker and Stage 3 through the scan
        # workspace archive, so the worker job does not need the variable.
        env {
          name  = "CODEMENDER_AUTO_UPDATE"
          value = local.cfg.cm_auto_update ? "true" : "false"
        }

        # BigQuery analytics telemetry. Set on the base container rather than
        # in the workflow overrides: Cloud Run merges execution-time container
        # env overrides with the base env, so these survive into every stage
        # without having to be repeated in the workflow YAML.
        #
        # An empty CODEMENDER_BQ_DATASET is the master off-switch -- the
        # orchestrator then performs zero BigQuery calls.
        env {
          name  = "CODEMENDER_BQ_DATASET"
          value = local.cfg.enable_bigquery_telemetry ? local.cfg.bigquery_dataset_id : ""
        }

        env {
          name  = "CODEMENDER_BQ_PROJECT"
          value = local.cfg.enable_bigquery_telemetry ? local.cfg.project_id : ""
        }

        # Off by default: gates export of LLM analysis prose and verbatim
        # source snippets into the warehouse.
        env {
          name  = "CODEMENDER_BQ_INCLUDE_SNIPPETS"
          value = local.cfg.bigquery_include_snippets ? "true" : "false"
        }

        # Optional fix commit author identity (git_author_name/_email).
        dynamic "env" {
          for_each = local.git_author_env
          content {
            name  = env.key
            value = env.value
          }
        }

        # Static GitHub token, mounted only while no GitHub App is configured
        # (see github_app.tf). Kept first so the env list, and therefore the
        # plan, is unchanged for deployments that do not use an App.
        dynamic "env" {
          for_each = local.github_static_token_env
          content {
            name = env.key
            value_source {
              secret_key_ref {
                secret  = env.value
                version = "latest"
              }
            }
          }
        }

        # GitHub App identity and private key (opt-in, see github_app.tf).
        dynamic "env" {
          for_each = local.github_app_plain_env
          content {
            name  = env.key
            value = env.value
          }
        }

        dynamic "env" {
          for_each = local.github_app_secret_env
          content {
            name = env.key
            value_source {
              secret_key_ref {
                secret  = env.value
                version = "latest"
              }
            }
          }
        }

        # Wiz service account credentials for the opt-in Wiz SAST bridge.
        # Present only when at least one repository enables the bridge (see
        # wiz.tf); the runtime still requires the per-run
        # CODEMENDER_WIZ_ENABLED flag before calling Wiz.
        dynamic "env" {
          for_each = local.wiz_secret_env
          content {
            name = env.key
            value_source {
              secret_key_ref {
                secret  = env.value
                version = "latest"
              }
            }
          }
        }
      }

      dynamic "vpc_access" {
        for_each = local.use_vpc_access ? [1] : []
        content {
          connector = local.vpc_connector_id
          egress    = "ALL_TRAFFIC"
        }
      }
    }
  }

  lifecycle {
    # gcloud run jobs update (used by scripts/ci/image_rollout.sh) stamps
    # client = "gcloud" and client_version on the job alongside the new image.
    ignore_changes = [
      client,
      client_version,
      template[0].template[0].containers[0].image,
    ]
  }

  depends_on = [
    time_sleep.wait_for_apis_and_iam,
    google_secret_manager_secret_iam_member.runner_wiz_client_id_accessor,
    google_secret_manager_secret_iam_member.runner_wiz_client_secret_accessor,
    google_secret_manager_secret_iam_member.runner_github_app_key_accessor,
  ]
}

resource "google_cloud_run_v2_job" "worker" {
  name                = "${local.cfg.resource_prefix}-worker"
  location            = local.cfg.region
  project             = local.cfg.project_id
  deletion_protection = false

  template {
    template {
      service_account = google_service_account.worker_sa.email
      timeout         = "86400s"
      max_retries     = 0

      containers {
        # The image the job is created with (a public placeholder by default,
        # so Terraform can provision the job before Cloud Build runs). The
        # actual image is deployed out-of-band via Cloud Build (see
        # cloudbuild.yaml), which is why the image is in ignore_changes below.
        image = local.cfg.initial_runner_image

        resources {
          limits = {
            cpu    = local.cfg.runner_cpu
            memory = local.cfg.runner_memory
          }
        }

        env {
          name  = "GOOGLE_CLOUD_PROJECT"
          value = local.cfg.project_id
        }

        env {
          name  = "WORKSPACE_DIR"
          value = "/workspace"
        }

        env {
          name  = "CODEMENDER_SANDBOX_ENABLED"
          value = "false"
        }

        # Optional fix commit author identity (git_author_name/_email).
        dynamic "env" {
          for_each = local.git_author_env
          content {
            name  = env.key
            value = env.value
          }
        }

        # Static GitHub token, mounted only while no GitHub App is configured
        # (see github_app.tf).
        dynamic "env" {
          for_each = local.github_static_token_env
          content {
            name = env.key
            value_source {
              secret_key_ref {
                secret  = env.value
                version = "latest"
              }
            }
          }
        }

        # GitHub App identity and private key (opt-in, see github_app.tf).
        dynamic "env" {
          for_each = local.github_app_plain_env
          content {
            name  = env.key
            value = env.value
          }
        }

        dynamic "env" {
          for_each = local.github_app_secret_env
          content {
            name = env.key
            value_source {
              secret_key_ref {
                secret  = env.value
                version = "latest"
              }
            }
          }
        }
      }

      dynamic "vpc_access" {
        for_each = local.use_vpc_access ? [1] : []
        content {
          connector = local.vpc_connector_id
          egress    = "ALL_TRAFFIC"
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [
      client,
      client_version,
      template[0].template[0].containers[0].image,
    ]
  }

  depends_on = [
    time_sleep.wait_for_apis_and_iam,
    google_secret_manager_secret_iam_member.worker_github_app_key_accessor,
  ]
}

resource "google_workflows_workflow" "coordinator" {
  name                = "${local.cfg.resource_prefix}-coordinator"
  region              = local.cfg.region
  project             = local.cfg.project_id
  deletion_protection = false
  description         = "Coordinates parallel CodeMender security scan and fix executions"
  service_account     = google_service_account.workflow_sa.id
  source_contents     = file("${path.module}/../../workflows/gcp_parallel_workflow.yaml")

  depends_on = [
    time_sleep.wait_for_apis_and_iam
  ]
}
