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
  # Non-empty per-command cm flag strings for each repository. coalesce(v, " ")
  # maps both null and "" to a blank string that trimspace() then empties.
  repo_cm_flags = {
    for key, repo in local.target_repositories : key => {
      for cmd, flags in {
        find   = repo.find_flags
        verify = repo.verify_flags
        fix    = repo.fix_flags
      } : cmd => trimspace(coalesce(flags, " ")) if trimspace(coalesce(flags, " ")) != ""
    }
  }
}

resource "google_cloud_scheduler_job" "repo_scans" {
  for_each    = local.target_repositories
  name        = "${local.cfg.resource_prefix}-scan-${each.key}"
  description = "Scheduled CodeMender scan for ${each.value.repo_url}"
  schedule    = coalesce(each.value.schedule, local.cfg.scheduler_cron)
  time_zone   = local.cfg.scheduler_timezone
  paused      = local.cfg.scheduler_paused
  region      = local.cfg.region
  project     = local.cfg.project_id

  http_target {
    uri         = "https://workflowexecutions.googleapis.com/v1/${google_workflows_workflow.coordinator.id}/executions"
    http_method = "POST"

    body = base64encode(jsonencode({
      argument = jsonencode(merge(
        {
          job_name        = google_cloud_run_v2_job.runner.name
          worker_job_name = google_cloud_run_v2_job.worker.name
          gcs_bucket      = google_storage_bucket.reports.name
          region          = local.cfg.region
          repo_url        = each.value.repo_url
          scan_target     = (each.value.scan_target != null && each.value.scan_target != "") ? each.value.scan_target : "."
          target_branch   = each.value.target_branch != null ? each.value.target_branch : ""
          build_command   = each.value.build_command != null ? each.value.build_command : ""
          max_tasks       = each.value.max_tasks != null ? each.value.max_tasks : 8
          skip_verify     = each.value.skip_verify != null ? each.value.skip_verify : true
        },
        (each.value.model != null && each.value.model != "") ? { model = each.value.model } : {},
        (
          (each.value.find_model != null && each.value.find_model != "") ||
          (each.value.verify_model != null && each.value.verify_model != "") ||
          (each.value.fix_model != null && each.value.fix_model != "")
          ) ? {
          models = merge(
            (each.value.find_model != null && each.value.find_model != "") ? { find = each.value.find_model } : {},
            (each.value.verify_model != null && each.value.verify_model != "") ? { verify = each.value.verify_model } : {},
            (each.value.fix_model != null && each.value.fix_model != "") ? { fix = each.value.fix_model } : {}
          )
        } : {},
        # Opt-in Wiz SAST bridge: only emitted for repositories that enable
        # it, so every other repository's payload is unchanged.
        try(each.value.wiz.enabled, false) == true ? {
          wiz = {
            enabled      = true
            min_severity = upper(coalesce(try(each.value.wiz.min_severity, null), "HIGH"))
          }
        } : {},
        # Extra cm flags: only emitted for repositories that set any.
        length(local.repo_cm_flags[each.key]) > 0 ? {
          cm_flags = local.repo_cm_flags[each.key]
        } : {},
        # Dry run: only emitted for repositories that enable it.
        each.value.dry_run == true ? { dry_run = true } : {}
      ))
    }))

    headers = {
      "Content-Type" = "application/json"
    }

    oauth_token {
      service_account_email = google_service_account.scheduler_sa.email
    }
  }

  depends_on = [google_project_service.enabled_services]
}
