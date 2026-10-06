# How it works

This page describes the three flows, where the data lives, and the security
model. For setup, see the [GitOps guide](guides/gitops_cloud_build.md) and
[Operations](operations.md).

`<prefix>` is `resource_prefix` from `deployment.yaml` (default `codemender`).

## Scheduled scans (Google Cloud)

This is the main flow. Each entry in `repos.yaml` becomes a Cloud Scheduler job
that starts the `<prefix>-coordinator` workflow on the entry's schedule. The
workflow runs the scan in three stages on two Cloud Run jobs.

```mermaid
flowchart TD
  sched["Cloud Scheduler: one job per repos.yaml entry"] -->|"HTTP POST to the Workflows executions API"| wf["Cloud Workflows: prefix-coordinator"]
  wf -->|"runner job, 1 task, RUN_MODE=scan"| s1["Stage 1: clone, cm find, optional Wiz import, dedupe against open fix pull requests, partition"]
  s1 --> m[("Reports bucket: scans/scan-id/ manifest, workspace, partitions")]
  wf -->|"read manifest"| zero{"findings_count = 0?"}
  zero -- "yes" --> clean["Stage 1 already posted CodeMender / Nightly Scan and wrote BigQuery telemetry. SARIF uploaded only if it has results or the empty-SARIF option is on"]
  zero -- "no" --> s2["Stage 2: worker job, min(partitions, max_tasks) tasks: optional cm verify, cm fix, push branch, open fix pull request"]
  s2 -. "signed URLs only" .-> m
  s2 --> prs["GitHub: fix pull requests, GitHub App identity"]
  s2 -- "success or failure" --> s3["Stage 3: runner job, RUN_MODE=aggregate: merge shards, HTML, JSON and SARIF"]
  s3 --> gh["GitHub: SARIF to code scanning, status CodeMender / Nightly Scan"]
  s3 --> r[("Reports bucket: reports/owner_repo/scan-id/, 90-day lifecycle")]
  s3 --> bq[("BigQuery: scan_runs, vulnerability_findings, plus views")]
  wf -- "Stage 1 or 3 launch or run failure, or manifest read failure" --> fin["Failure finalizer: aggregate with CODEMENDER_WORKFLOW_FAILED=true"]
```

Step by step:

1.  **Trigger.** The scheduler job posts the entry's settings (repository URL,
    scan directories, branch, build command, `max_tasks`, `skip_verify`, and
    any model, `cm` flag, dry-run or Wiz settings) to the workflow, as the
    `<prefix>-scheduler-sa` service account.
2.  **Stage 1: scan** (`<prefix>-runner`, one task).
    *   Clones the repository and runs `cm find`.
    *   If Wiz import is enabled for the entry, imports Wiz findings at or
        above `min_severity`. Imported findings are always verified with
        `cm verify` before they are fixed, even when `skip_verify` is true.
    *   Skips findings that already have an open fix pull request or branch.
    *   Splits the remaining findings into partitions, and uploads the
        workspace and partitions to the reports bucket with a manifest.
    *   If nothing is left, it posts the status, writes telemetry and stops
        here. No HTML report is produced for a clean scan.
3.  **Stage 2: fix** (`<prefix>-worker`, one task per partition, at most
    `max_tasks`).
    *   Each task downloads its partition through signed URLs, optionally runs
        `cm verify`, runs `cm fix`, and pushes a branch and opens a pull
        request against the scanned branch for each fixed finding.
    *   If some tasks fail, the workflow still runs Stage 3 so the completed
        results are published.
4.  **Stage 3: publish** (`<prefix>-runner`, one task).
    *   Merges the workers' results into HTML, JSON and SARIF reports.
    *   Uploads the SARIF to GitHub code scanning (when it has results) and
        posts the `CodeMender / Nightly Scan` status on the scanned commit.
    *   Writes the HTML report to the reports bucket and a row per scan and per
        finding to BigQuery.
5.  **Failures.** If Stage 1 or Stage 3 fails, or the manifest cannot be read,
    the workflow runs a short finalizer so the GitHub status does not stay
    pending and the failure is recorded, then fails the execution.

`CodeMender / Nightly Scan` is informational: its state is `success` whenever
the scan completes, and its description gives the number of active findings.
It is not meant to block merges.

The Cloud Run jobs have a 24-hour timeout per stage. A `--deep` scan
(`find_flags` in `repos.yaml`) can take several hours.

## Pull request scans (GitHub Actions)

This flow is optional and set up separately from scheduled scans. It scans the
changes in each pull request, from GitHub Actions in the repository itself, and
reports only vulnerabilities that the pull request introduces or touches. The
setup steps are in
[Set up pull request scans on a repository](../README.md#set-up-pull-request-scans-on-a-repository);
the details of `.github/workflows/codemender.yml` generation
(`scripts/ci/init_codemender_workflow.py`) are in the
[GitHub Actions Pre-Submit CI/CD Onboarding Guide](guides/github_actions_presubmit_ci_cd.md).

```mermaid
flowchart TD
  pr["Pull request in an onboarded repository"] --> caller["Caller workflow in that repository (.github/workflows/codemender.yml)"]
  caller --> scan["Job scan (Stage 1): preflight diff check, cm find, sticky PR table & Checks annotations"]
  scan --> sgate["Job security-gate (Stage 1.5): post immediate CodeMender / Security Gate commit status & fail-closed check"]
  scan -- "findings > 0" --> worker["Job worker (Stage 2, matrix up to max_tasks): cm verify, cm fix, 1-click inline suggestion, live sticky row updates"]
  worker --> agg["Job aggregate (Stage 3): merge shards, filtered report.sarif, auto-unblock if all blocking findings are dismissed as false positives"]
  agg --> gate{"Confirmed findings >= min_blocking_severity and block_pr_merge?"}
  gate -- "yes" --> fail["CodeMender / Security Gate: failure"]
  gate -- "no" --> ok["CodeMender / Security Gate: success"]
  scan -. "Vertex AI through Workload Identity Federation" .-> gcp[("Your Google Cloud project")]
  worker -.-> gcp
```

How it fits together:

*   `.github/workflows/codemender_parallel.yml` in this repository is a
    reusable workflow (or `orchestrator.py` can be invoked directly in
    standalone mode). Each scanned repository adds
    `.github/workflows/codemender.yml` (generated via
    `python3 scripts/ci/init_codemender_workflow.py`) that decides when it runs
    and passes its inputs and secrets.
*   In reusable workflow mode, the jobs run in containers from a runner image
    that your organization hosts. Always set the `runner_image` input
    explicitly; `.github/workflows/build_runner_image.yml` can build and
    publish one (see
    [Build the runner image](operations.md#build-the-runner-image)).
*   The jobs reach Vertex AI in your project through Workload Identity
    Federation. `terraform/gha_wif/` creates the identity pool, a service
    account and the related repository secrets.
*   Intermediate files are passed between jobs as GitHub Actions artifacts. No
    Cloud Storage bucket is used.
*   The status check is `CodeMender / Security Gate`. Stage 1.5 posts an
    immediate status right after `cm find`, and Stage 3 automatically unblocks
    it to `success` if Stage 2 `cm verify` dismisses all blocking findings as
    false positives. It fails only when confirmed findings at or above
    `min_blocking_severity` (default `MEDIUM`) remain on the pull request's
    changes and `block_pr_merge` (or `fail_on_findings`) is `true`. Generated
    workflows default to `false` (advisory).
*   Wiz import is not used in this flow.

**Start in advisory mode.** A failing status only blocks merging if your
branch ruleset lists `CodeMender / Security Gate` as a required check. The
generated caller workflow is advisory by default (`block_pr_merge: false`).
Make it blocking once teams are used to the results: set repository variable
`CODEMENDER_BLOCK_PR_MERGE=true` and require the check. Setting the variable to
`false` turns blocking off again; neither change needs the workflow to be
regenerated.

## GitOps deployment changes (Cloud Build)

Your platform team changes the deployment through pull requests to your copy
of this repository. Nobody runs Terraform by hand after the one-time bootstrap.

```mermaid
flowchart LR
  edit["Edit repos.yaml, deployment.yaml or code"] --> pr["Pull request"]
  pr --> plan["tf-plan trigger: terraform plan, read-only service account"]
  plan --> review["Plan check and code owner review"]
  review --> merge["Merge to the deployed branch"]
  merge --> apply["tf-apply trigger: lock, check HEAD, plan, destroy guard, apply"]
  apply -- "would delete protected data" --> stop["Stops. An approver runs tf-apply-destroy"]
  merge -- "image files changed" --> img["image trigger: stage cm, build, push"]
  img --> wait{"Scan running?"}
  wait -- "yes: check again every 60s, up to 12 h" --> wait
  wait -- "no" --> roll["Point the runner and worker jobs at the new image digest"]
```

*   **Plan** runs on every pull request into the deployed branch, as the
    `<prefix>-tf-plan` service account, which can read but not change anything
    and cannot read secret values, BigQuery data or scan executions.
*   **Apply** runs on every push to the deployed branch, as
    `<prefix>-tf-apply`. It acquires a pipeline lock in the state bucket,
    verifies that its commit is still the tip of the deployed branch (skipping
    superseded commits), plans again, stops if the plan would delete or replace
    a bucket, BigQuery dataset or table, secret, or the image registry, and
    otherwise applies that plan.
*   **Image** runs when a merge changes the runner image or its rollout
    (`Dockerfile`, `codemender_agent/`, `orchestrator.py`, `requirements.txt`,
    `cloudbuild.yaml`, `scripts/ci/image_rollout.sh`, `scripts/ci/stage_cm.sh`).
    It downloads the latest CodeMender CLI release, builds and pushes the
    image, and waits until no scan is
    running (re-checking every 60 seconds) before it switches both jobs to the
    new image.

The [GitOps guide](guides/gitops_cloud_build.md) covers the bootstrap,
approvals, the destroy guard and manual rollback.

## Where data lives

| Data | Where | Retention |
| --- | --- | --- |
| Scan workspace, partitions, worker results, JSON and SARIF reports | Reports bucket, `scans/<scan-id>/` | Deleted after 90 days |
| HTML report | Reports bucket, `reports/<owner>_<repo>/<scan-id>/` | Deleted after 90 days |
| Scan history and findings | BigQuery dataset (`codemender_telemetry` by default; set via `bigquery_dataset_id`, not prefixed with `resource_prefix`) | Until you delete it |
| Findings | GitHub code scanning in each repository | GitHub's retention |
| Fixes | Branches and pull requests in each repository | Until closed or deleted |
| Logs | Cloud Logging for the jobs, the workflow and Cloud Build | Your Cloud Logging retention |
| Terraform state | `<prefix>-tfstate-<project>` bucket (versioned) | Kept |
| Pull request scan artifacts | GitHub Actions artifacts | 3 days (intermediate) and 90 days (reports) by default |

BigQuery does not store source code or the model's analysis text unless
`bigquery_include_snippets` is set to `true` in `deployment.yaml` (default
`false`).

## Security model

### Identities

| Service account | Used by | Can |
| --- | --- | --- |
| `<prefix>-scheduler-sa` | Cloud Scheduler | Start workflow executions |
| `<prefix>-workflows-sa` | The coordinator workflow | Run the two Cloud Run jobs with overrides, read Cloud Run state, read the reports bucket |
| `<prefix>-runner-sa` | Stages 1 and 3 | Read and write the reports bucket and sign URLs for it, use Vertex AI, read the GitHub App key, write its BigQuery dataset, read the Wiz credentials (if Wiz import is on) |
| `<prefix>-worker-sa` | Stage 2 | Use Vertex AI, read the GitHub App key. No access to the bucket (signed URLs only) and none to BigQuery |
| `<prefix>-tf-plan` | Pull request plans | Read-only; no secret values, BigQuery data, scan executions or objects outside the state bucket |
| `<prefix>-tf-apply` | Applies after merge | Manage everything the deployment creates, including project IAM |
| `<prefix>-image-build` | Image builds and rollouts | Push to the image registry and update the two Cloud Run jobs |

### GitHub access

*   The scheduled scans use a GitHub App that your organization creates and
    installs on the scanned repositories only. The jobs read the App's private
    key from Secret Manager and mint installation tokens scoped to the scanned
    repository. Tokens last one hour and are refreshed during long scans.
*   Pull requests, comments and statuses are attributed to the App's bot
    account.
*   The pull request flow authenticates with its own App credentials, stored as
    GitHub Actions secrets in the scanned repository.

### Secrets

*   Secrets are stored only in Secret Manager (or, for the pull request flow,
    GitHub Actions secrets). The YAML files only name them.
*   Terraform references the GitHub App key and Wiz secrets without managing
    them, so their values never enter Terraform state and a Terraform change
    cannot delete them.
*   Before it runs `cm`, the orchestrator removes GitHub tokens, the GitHub
    App settings (`GH_APP_*`, `GITHUB_APP_*`), Wiz credentials, service
    account key variables and the GitHub Actions runtime and OIDC request
    tokens from the environment. Each `cm` stage logs the names (never the
    values) of the credential-like variables that remain, on a `[cm env]`
    line. In GitHub Actions that is normally only
    `GOOGLE_APPLICATION_CREDENTIALS` and its gcloud equivalent, which `cm`
    needs for Vertex AI.
*   In GitHub Actions, `google-github-actions/auth` writes its credentials file
    into the workspace. The workflow moves it to the runner's temporary
    directory, outside the files the `cm` sandbox can reach, because a
    Workload Identity Federation credentials file also holds the job's OIDC
    request token.

### Code execution

*   `cm` builds and tests the scanned code, and runs the repository's
    `build_command`. That code runs inside the Cloud Run job with the job's
    service account, which can reach Vertex AI and read the GitHub App key.
    Only onboard repositories you trust, and require code owner review for
    `repos.yaml`.
*   On Cloud Run, the CodeMender CLI's own sandbox is turned off
    (`CODEMENDER_SANDBOX_ENABLED=false` on both jobs). The jobs rely on Cloud
    Run's container isolation, and each execution starts from a fresh
    container.
*   In the GitHub Actions pull request flow, the sandbox is on by default
    (`sandbox_enabled`), and the jobs run in privileged containers, which the
    sandbox needs. Accesses the sandbox blocks are logged and the session
    continues; they never cause an unsandboxed rerun. If the sandbox cannot
    start at all, the scan step fails (and so does the security gate), a
    verification is recorded as unverified, and a fix is not generated (the
    finding is labelled "`cm fix` did not run"). Setting
    `allow_unsandboxed_fallback: true` re-runs such a session with
    `--unrestricted` instead, with a warning on the run and in the job
    summary, and marks the finding "ran without the sandbox".

### Deployment changes

*   A pull request's build file cannot change which service account runs it:
    Cloud Build always runs a trigger's builds as the trigger's own account.
*   The plan account can read Terraform state, which can contain sensitive
    values. Treat pull request access to your copy as access to the state.
*   The apply account can grant project IAM roles. Protect the deployed branch
    so that every change goes through a reviewed pull request.
*   Because `<prefix>-tf-plan` and `<prefix>-tf-apply` hold project-wide roles,
    run each deployment in its own dedicated Google Cloud project.

### Not provided

*   No Cloud Monitoring alert policies are created.
*   A clean scheduled scan does not clear existing code scanning alerts (see
    [Where results show up](../README.md#where-results-show-up)).
