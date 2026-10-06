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

# YAML configuration files.
#
# Two optional, committed files can replace terraform.tfvars:
#
#   repos.yaml       the repositories to scan (merged with var.target_repositories)
#   deployment.yaml  non-secret deployment settings (one key per module variable)
#
# Both are read natively with yamldecode(), so a plain `terraform plan` sees
# exactly what a pipeline sees. A value in YAML wins over the same variable
# set in tfvars or on the command line; a repository defined in both places
# takes the YAML definition. Typos and malformed values fail the plan through
# the preconditions on terraform_data.config_checks at the end of this file.
# See repos.example.yaml and deployment.example.yaml.

locals {
  # ---------------------------------------------------------------------------
  # File locations. null (the default) means "<module>/<name>.yaml if it
  # exists"; "" turns the file off; any other value must name an existing file.
  # ---------------------------------------------------------------------------
  repos_file_path       = var.repos_file == null ? "${path.module}/repos.yaml" : var.repos_file
  repos_file_exists     = local.repos_file_path == "" ? false : fileexists(local.repos_file_path)
  repos_file_missing    = var.repos_file != null && var.repos_file != "" && !local.repos_file_exists
  deployment_file_path  = var.deployment_file == null ? "${path.module}/deployment.yaml" : var.deployment_file
  deployment_file_exist = local.deployment_file_path == "" ? false : fileexists(local.deployment_file_path)
  deployment_file_missing = (
    var.deployment_file != null && var.deployment_file != "" && !local.deployment_file_exist
  )

  # A file that is empty or holds only comments counts as no settings.
  # Anything that is not a mapping is reported by the preconditions and
  # otherwise treated as empty.
  repos_text         = local.repos_file_exists ? file(local.repos_file_path) : ""
  repos_raw          = trimspace(replace(local.repos_text, "/(?m)^\\s*#.*$/", "")) == "" ? null : yamldecode(local.repos_text)
  repos_doc_is_map   = local.repos_raw == null || can(keys(local.repos_raw))
  repos_doc          = { for k in(can(keys(local.repos_raw)) ? keys(local.repos_raw) : []) : k => local.repos_raw[k] }
  repos_section      = lookup(local.repos_doc, "repositories", null)
  repos_section_ok   = local.repos_section == null || can(keys(local.repos_section))
  repos_entries      = { for k in(can(keys(local.repos_section)) ? keys(local.repos_section) : []) : k => local.repos_section[k] }
  repos_unknown_root = setsubtract(keys(local.repos_doc), ["repositories"])

  deployment_text       = local.deployment_file_exist ? file(local.deployment_file_path) : ""
  deployment_raw        = trimspace(replace(local.deployment_text, "/(?m)^\\s*#.*$/", "")) == "" ? null : yamldecode(local.deployment_text)
  deployment_doc_is_map = local.deployment_raw == null || can(keys(local.deployment_raw))
  deployment_doc        = { for k in(can(keys(local.deployment_raw)) ? keys(local.deployment_raw) : []) : k => local.deployment_raw[k] }

  # ---------------------------------------------------------------------------
  # repos.yaml
  # ---------------------------------------------------------------------------
  repo_string_keys = [
    "repo_url", "scan_target", "target_branch", "build_command", "schedule",
    "model", "find_model", "verify_model", "fix_model",
    "find_flags", "verify_flags", "fix_flags",
  ]
  repo_number_keys = ["max_tasks"]
  repo_bool_keys   = ["skip_verify", "dry_run"]
  repo_known_keys  = concat(local.repo_string_keys, local.repo_number_keys, local.repo_bool_keys, ["wiz"])
  wiz_known_keys   = ["enabled", "min_severity"]

  # Every entry as a mapping; `name:` with no body becomes {} so that it is
  # reported as missing repo_url rather than failing to evaluate.
  repos_yaml = {
    for name, repo in local.repos_entries : name => { for k in(can(keys(repo)) ? keys(repo) : []) : k => repo[k] }
  }

  # yamldecode() keeps the last of two identical keys without an error, so a
  # repository listed twice would silently lose its first definition. Find
  # duplicates in the raw text instead: the entry names are the mapping keys
  # with the smallest indentation below the top-level `repositories:` key.
  # Quoted and plain spellings of a name count as the same name.
  repos_key_pattern = "^( +)(\"[^\"]*\"|'[^']*'|(?:[^\\s#'\"-]|-\\S)[^:#]*?)[ \\t]*:(?:\\s|$)"
  repos_key_lines = [
    for line in split("\n", replace(local.repos_text, "\r", "")) : regex(local.repos_key_pattern, line)
    if can(regex(local.repos_key_pattern, line))
  ]
  repos_entry_indent = length(local.repos_key_lines) == 0 ? 0 : min([for m in local.repos_key_lines : length(m[0])]...)
  repos_entry_names = [
    for m in local.repos_key_lines : trim(m[1], "\"'") if length(m[0]) == local.repos_entry_indent
  ]
  repos_duplicate_errors = [
    for name in distinct(local.repos_entry_names) :
    "repositories.${name}: listed more than once (only the last entry would be used)"
    if length([for n in local.repos_entry_names : n if n == name]) > 1
  ]

  repos_yaml_errors = concat(local.repos_duplicate_errors, flatten([
    for name, repo in local.repos_entries : concat(
      can(regex("^[A-Za-z0-9_-]+$", name)) ? [] : [
        "repositories.${name}: the name may only contain letters, digits, '-' and '_' (it becomes part of the Cloud Scheduler job name)",
      ],
      repo == null || can(keys(repo)) ? [] : ["repositories.${name}: must be a mapping of settings"],
      [
        for key in setsubtract(keys(local.repos_yaml[name]), local.repo_known_keys) :
        "repositories.${name}.${key}: unknown key (allowed: ${join(", ", local.repo_known_keys)})"
      ],
      try(trimspace(tostring(local.repos_yaml[name].repo_url)), "") != "" ? [] : [
        "repositories.${name}.repo_url: required",
      ],
      [
        for key in local.repo_string_keys : "repositories.${name}.${key}: must be a string"
        if lookup(local.repos_yaml[name], key, null) != null && !can(tostring(lookup(local.repos_yaml[name], key, null)))
      ],
      [
        for key in local.repo_number_keys : "repositories.${name}.${key}: must be a number"
        if lookup(local.repos_yaml[name], key, null) != null && !can(tonumber(lookup(local.repos_yaml[name], key, null)))
      ],
      [
        for key in local.repo_bool_keys : "repositories.${name}.${key}: must be true or false"
        if lookup(local.repos_yaml[name], key, null) != null && !can(tobool(lookup(local.repos_yaml[name], key, null)))
      ],
      # schedule is optional, but when present it must be a unix-cron
      # expression: five whitespace-separated fields.
      lookup(local.repos_yaml[name], "schedule", null) == null || can(regex(
        local.cron_pattern,
        trimspace(replace(try(tostring(local.repos_yaml[name].schedule), ""), "/\\s+/", " "))
      )) ? [] : ["repositories.${name}.schedule: must be a five-field cron expression, for example \"0 2 * * 1\""],
      lookup(local.repos_yaml[name], "wiz", null) == null ? [] : (
        can(keys(local.repos_yaml[name].wiz)) ? concat(
          [
            for key in setsubtract(keys(local.repos_yaml[name].wiz), local.wiz_known_keys) :
            "repositories.${name}.wiz.${key}: unknown key (allowed: ${join(", ", local.wiz_known_keys)})"
          ],
          lookup(local.repos_yaml[name].wiz, "enabled", null) == null || can(tobool(lookup(local.repos_yaml[name].wiz, "enabled", null))) ? [] : [
            "repositories.${name}.wiz.enabled: must be true or false",
          ],
          contains(local.wiz_severities, upper(try(tostring(coalesce(lookup(local.repos_yaml[name].wiz, "min_severity", null), "HIGH")), "?"))) ? [] : [
            "repositories.${name}.wiz.min_severity: must be one of ${join(", ", local.wiz_severities)}",
          ],
        ) : ["repositories.${name}.wiz: must be a mapping with enabled and min_severity"]
      ),
    )
  ]))

  wiz_severities = ["INFORMATIONAL", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

  # Five cron fields of digits, names, and the * , / - ? L W # operators.
  cron_pattern = "^[0-9A-Za-z*,/?#-]+( [0-9A-Za-z*,/?#-]+){4}$"

  # The YAML entries normalised to exactly the object type (and the same
  # optional-attribute defaults) as var.target_repositories, so a repository
  # produces the same scheduler payload whichever file defines it. Values
  # that fail to convert fall back to the default here and are reported by
  # repos_yaml_errors instead of aborting evaluation.
  repos_from_yaml = {
    for name, repo in local.repos_yaml : name => {
      repo_url      = try(tostring(repo.repo_url), null)
      scan_target   = try(tostring(repo.scan_target), null) == null ? "." : tostring(repo.scan_target)
      target_branch = try(tostring(repo.target_branch), null) == null ? "" : tostring(repo.target_branch)
      build_command = try(tostring(repo.build_command), null) == null ? "" : tostring(repo.build_command)
      schedule      = try(tostring(repo.schedule), null)
      max_tasks     = try(tonumber(repo.max_tasks), null) == null ? 8 : tonumber(repo.max_tasks)
      skip_verify   = try(tobool(repo.skip_verify), null) == null ? true : tobool(repo.skip_verify)
      model         = try(tostring(repo.model), null) == null ? "" : tostring(repo.model)
      find_model    = try(tostring(repo.find_model), null) == null ? "" : tostring(repo.find_model)
      verify_model  = try(tostring(repo.verify_model), null) == null ? "" : tostring(repo.verify_model)
      fix_model     = try(tostring(repo.fix_model), null) == null ? "" : tostring(repo.fix_model)
      find_flags    = try(tostring(repo.find_flags), null) == null ? "" : tostring(repo.find_flags)
      verify_flags  = try(tostring(repo.verify_flags), null) == null ? "" : tostring(repo.verify_flags)
      fix_flags     = try(tostring(repo.fix_flags), null) == null ? "" : tostring(repo.fix_flags)
      dry_run       = try(tobool(repo.dry_run), null) == null ? false : tobool(repo.dry_run)
      wiz = can(keys(repo.wiz)) ? {
        enabled      = try(tobool(repo.wiz.enabled), null) == null ? false : tobool(repo.wiz.enabled)
        min_severity = try(tostring(repo.wiz.min_severity), null) == null ? "HIGH" : tostring(repo.wiz.min_severity)
      } : null
    }
  }

  # The effective repository map used by scheduler.tf and wiz.tf. Keys are the
  # repository names from either source, so resource addresses such as
  # google_cloud_scheduler_job.repo_scans["<name>"] do not depend on which
  # file a repository is defined in. YAML wins on a name clash.
  #
  # While repos.yaml has errors none of its entries are used, so the plan
  # stops at the precondition that lists the errors instead of failing
  # somewhere else on a half-valid entry.
  repos_yaml_valid = (
    local.repos_doc_is_map && local.repos_section_ok &&
    length(local.repos_unknown_root) == 0 && length(local.repos_yaml_errors) == 0
  )
  target_repositories = merge(
    var.target_repositories,
    { for name, repo in local.repos_from_yaml : name => repo if local.repos_yaml_valid },
  )

  # ---------------------------------------------------------------------------
  # deployment.yaml
  # ---------------------------------------------------------------------------
  deployment_string_keys = [
    "project_id", "region", "resource_prefix", "reports_bucket_name",
    "runner_cpu", "runner_memory", "initial_runner_image",
    "existing_vpc_connector_id", "vpc_connector_cidr", "vpc_connector_machine_type",
    "scheduler_cron", "scheduler_timezone",
    "wiz_client_id_secret_id", "wiz_client_secret_secret_id",
    "github_app_id", "github_app_installation_id", "github_app_private_key_secret_id",
    "git_author_name", "git_author_email",
    "bigquery_dataset_id", "bigquery_location",
  ]
  deployment_bool_keys = [
    "create_vpc_and_nat", "scheduler_paused", "cm_auto_update",
    "enable_bigquery_telemetry", "bigquery_include_snippets",
    "bigquery_deletion_protection", "bigquery_delete_contents_on_destroy",
  ]
  deployment_number_keys = ["vpc_connector_min_instances", "vpc_connector_max_instances"]
  deployment_list_keys   = ["cloudbuild_service_account_emails"]
  deployment_known_keys = concat(
    local.deployment_string_keys, local.deployment_bool_keys, local.deployment_number_keys, local.deployment_list_keys,
  )

  dep_str = {
    for k in local.deployment_string_keys : k => tostring(local.deployment_doc[k])
    if can(tostring(lookup(local.deployment_doc, k, null))) && lookup(local.deployment_doc, k, null) != null
  }
  dep_bool = {
    for k in local.deployment_bool_keys : k => tobool(local.deployment_doc[k])
    if can(tobool(lookup(local.deployment_doc, k, null))) && lookup(local.deployment_doc, k, null) != null
  }
  dep_num = {
    for k in local.deployment_number_keys : k => tonumber(local.deployment_doc[k])
    if can(tonumber(lookup(local.deployment_doc, k, null))) && lookup(local.deployment_doc, k, null) != null
  }
  # A YAML sequence of strings. yamldecode() returns a tuple, so each element
  # is converted on its own; a scalar or mapping is rejected.
  dep_list = {
    for k in local.deployment_list_keys : k => [for v in local.deployment_doc[k] : tostring(v)]
    if lookup(local.deployment_doc, k, null) != null && can([for v in local.deployment_doc[k] : tostring(v)]) && !can(tostring(lookup(local.deployment_doc, k, null))) && !can(keys(lookup(local.deployment_doc, k, null)))
  }

  deployment_errors = concat(
    [
      for k in setsubtract(keys(local.deployment_doc), local.deployment_known_keys) :
      "${k}: unknown key (allowed: ${join(", ", sort(local.deployment_known_keys))})"
    ],
    [
      for k in local.deployment_string_keys : "${k}: must be a string"
      if lookup(local.deployment_doc, k, null) != null && !contains(keys(local.dep_str), k)
    ],
    [
      for k in local.deployment_bool_keys : "${k}: must be true or false"
      if lookup(local.deployment_doc, k, null) != null && !contains(keys(local.dep_bool), k)
    ],
    [
      for k in local.deployment_number_keys : "${k}: must be a number"
      if lookup(local.deployment_doc, k, null) != null && !contains(keys(local.dep_num), k)
    ],
    [
      for k in local.deployment_list_keys : "${k}: must be a list of strings"
      if lookup(local.deployment_doc, k, null) != null && !contains(keys(local.dep_list), k)
    ],
  )

  # Effective settings: deployment.yaml first, then the variable (tfvars,
  # -var, or its default). Every resource reads these instead of var.*.
  cfg = {
    project_id                          = lookup(local.dep_str, "project_id", var.project_id)
    region                              = lookup(local.dep_str, "region", var.region)
    resource_prefix                     = lookup(local.dep_str, "resource_prefix", var.resource_prefix)
    reports_bucket_name                 = lookup(local.dep_str, "reports_bucket_name", var.reports_bucket_name)
    runner_cpu                          = lookup(local.dep_str, "runner_cpu", var.runner_cpu)
    runner_memory                       = lookup(local.dep_str, "runner_memory", var.runner_memory)
    initial_runner_image                = lookup(local.dep_str, "initial_runner_image", var.initial_runner_image)
    cm_auto_update                      = lookup(local.dep_bool, "cm_auto_update", var.cm_auto_update)
    cloudbuild_service_account_emails   = lookup(local.dep_list, "cloudbuild_service_account_emails", var.cloudbuild_service_account_emails)
    create_vpc_and_nat                  = lookup(local.dep_bool, "create_vpc_and_nat", var.create_vpc_and_nat)
    existing_vpc_connector_id           = lookup(local.dep_str, "existing_vpc_connector_id", var.existing_vpc_connector_id)
    vpc_connector_cidr                  = lookup(local.dep_str, "vpc_connector_cidr", var.vpc_connector_cidr)
    vpc_connector_min_instances         = lookup(local.dep_num, "vpc_connector_min_instances", var.vpc_connector_min_instances)
    vpc_connector_max_instances         = lookup(local.dep_num, "vpc_connector_max_instances", var.vpc_connector_max_instances)
    vpc_connector_machine_type          = lookup(local.dep_str, "vpc_connector_machine_type", var.vpc_connector_machine_type)
    scheduler_cron                      = lookup(local.dep_str, "scheduler_cron", var.scheduler_cron)
    scheduler_timezone                  = lookup(local.dep_str, "scheduler_timezone", var.scheduler_timezone)
    scheduler_paused                    = lookup(local.dep_bool, "scheduler_paused", var.scheduler_paused)
    wiz_client_id_secret_id             = lookup(local.dep_str, "wiz_client_id_secret_id", var.wiz_client_id_secret_id)
    wiz_client_secret_secret_id         = lookup(local.dep_str, "wiz_client_secret_secret_id", var.wiz_client_secret_secret_id)
    github_app_id                       = lookup(local.dep_str, "github_app_id", var.github_app_id)
    github_app_installation_id          = lookup(local.dep_str, "github_app_installation_id", var.github_app_installation_id)
    github_app_private_key_secret_id    = lookup(local.dep_str, "github_app_private_key_secret_id", var.github_app_private_key_secret_id)
    git_author_name                     = trimspace(lookup(local.dep_str, "git_author_name", var.git_author_name))
    git_author_email                    = trimspace(lookup(local.dep_str, "git_author_email", var.git_author_email))
    enable_bigquery_telemetry           = lookup(local.dep_bool, "enable_bigquery_telemetry", var.enable_bigquery_telemetry)
    bigquery_dataset_id                 = lookup(local.dep_str, "bigquery_dataset_id", var.bigquery_dataset_id)
    bigquery_location                   = lookup(local.dep_str, "bigquery_location", var.bigquery_location)
    bigquery_include_snippets           = lookup(local.dep_bool, "bigquery_include_snippets", var.bigquery_include_snippets)
    bigquery_deletion_protection        = lookup(local.dep_bool, "bigquery_deletion_protection", var.bigquery_deletion_protection)
    bigquery_delete_contents_on_destroy = lookup(local.dep_bool, "bigquery_delete_contents_on_destroy", var.bigquery_delete_contents_on_destroy)
  }
}

# Fails the plan with a readable message when either YAML file is malformed.
# The variable validations in variables.tf only see tfvars and -var values, so
# the checks that matter for YAML-supplied values are repeated here against
# the effective settings.
resource "terraform_data" "config_checks" {
  lifecycle {
    precondition {
      condition     = !local.repos_file_missing
      error_message = "repos_file is set to \"${coalesce(var.repos_file, "-")}\", but that file does not exist."
    }

    precondition {
      condition     = !local.deployment_file_missing
      error_message = "deployment_file is set to \"${coalesce(var.deployment_file, "-")}\", but that file does not exist."
    }

    precondition {
      condition     = local.repos_doc_is_map && local.repos_section_ok && length(local.repos_unknown_root) == 0
      error_message = "${local.repos_file_path}: expected a mapping with a single top-level key, repositories, holding one entry per repository.${length(local.repos_unknown_root) > 0 ? " Unknown top-level keys: ${join(", ", local.repos_unknown_root)}." : ""}"
    }

    precondition {
      condition     = length(local.repos_yaml_errors) == 0
      error_message = "${local.repos_file_path} has errors:\n  - ${join("\n  - ", local.repos_yaml_errors)}"
    }

    precondition {
      condition     = local.deployment_doc_is_map
      error_message = "${local.deployment_file_path}: expected a mapping of setting names to values."
    }

    precondition {
      condition     = length(local.deployment_errors) == 0
      error_message = "${local.deployment_file_path} has errors:\n  - ${join("\n  - ", local.deployment_errors)}"
    }

    precondition {
      condition     = trimspace(local.cfg.project_id) != ""
      error_message = "project_id is required: set it in deployment.yaml or as a Terraform variable."
    }

    precondition {
      # <prefix>-workflows-sa and <prefix>-scheduler-sa must fit the
      # 30-character service account ID limit.
      condition     = can(regex("^[a-z]([a-z0-9-]{0,15}[a-z0-9])?$", local.cfg.resource_prefix))
      error_message = "resource_prefix must be 1-17 lowercase letters, digits or hyphens, start with a letter and not end with a hyphen."
    }

    precondition {
      condition     = can(regex(local.cron_pattern, trimspace(replace(local.cfg.scheduler_cron, "/\\s+/", " "))))
      error_message = "scheduler_cron must be a five-field cron expression, for example \"0 2 * * *\"."
    }

    precondition {
      condition     = can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$", local.cfg.vpc_connector_cidr))
      error_message = "vpc_connector_cidr must be a valid IPv4 CIDR string (e.g., 10.0.0.0/26)."
    }

    precondition {
      condition     = !can(regex("\\s", local.cfg.github_app_id))
      error_message = "github_app_id must not contain whitespace."
    }

    precondition {
      condition     = local.cfg.github_app_installation_id == "" || can(regex("^[1-9][0-9]*$", local.cfg.github_app_installation_id))
      error_message = "github_app_installation_id must be empty or a positive integer."
    }

    precondition {
      condition     = !can(regex("[<>\\r\\n]", local.cfg.git_author_name))
      error_message = "git_author_name must not contain '<', '>' or line breaks."
    }

    precondition {
      condition     = !can(regex("[<>\\s]", local.cfg.git_author_email))
      error_message = "git_author_email must not contain '<', '>' or whitespace."
    }

    precondition {
      condition     = can(regex("^[A-Za-z0-9_]+$", local.cfg.bigquery_dataset_id)) && length(local.cfg.bigquery_dataset_id) <= 1024
      error_message = "bigquery_dataset_id must be 1-1024 characters of letters, numbers, and underscores only."
    }

    precondition {
      condition = local.cfg.cloudbuild_service_account_emails == null ? true : alltrue([
        for e in local.cfg.cloudbuild_service_account_emails : can(regex("^[^@:\\s]+@[^@:\\s]+\\.[^@:\\s]+$", e))
      ]) && length(distinct(local.cfg.cloudbuild_service_account_emails)) == length(local.cfg.cloudbuild_service_account_emails)
      error_message = "cloudbuild_service_account_emails must be a list of distinct service account emails, without a \"serviceAccount:\" prefix."
    }
  }
}
