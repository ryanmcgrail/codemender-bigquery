# Operations

Day-to-day tasks for the team that runs the deployment. Every change below is
a pull request to your copy of this repository; see the
[GitOps guide](guides/gitops_cloud_build.md) for how plans and applies run.

The settings live in two committed files in `terraform/gcp/`:

*   `repos.yaml`: which repositories to scan, and how. Every key is documented
    in `repos.example.yaml`.
*   `deployment.yaml`: how the deployment is set up. Every key is documented in
    `deployment.example.yaml`, with the full descriptions in `variables.tf`.

An unknown key, a value of the wrong type, a missing `repo_url`, a malformed
schedule or a repository listed twice fails the pull request's plan with a
message that names the entry.
(When `repos.yaml` fails validation, Terraform prints planned deletions of the
YAML-defined scheduler jobs above the validation error; ignore those planned
deletions — a failed plan cannot be applied.)

In the commands below, set these first:

```bash
export PROJECT_ID=your-project-id
export REGION=us-central1      # region in deployment.yaml
export PREFIX=codemender       # resource_prefix in deployment.yaml
```

## Repositories

### Onboard a repository

1.  Install the GitHub App on the repository (see
    [GitHub credentials](#github-credentials)).
2.  Add an entry to `repos.yaml`:

    ```yaml
    repositories:
      example-service:
        repo_url: https://github.com/your-org/example-service.git
        # Optional:
        schedule: "0 3 * * 6"      # default: scheduler_cron in deployment.yaml
        scan_target: "src/"        # default: "." (whole repository)
        build_command: "make test" # default: none
    ```

    The entry name (`example-service`) becomes the scheduler job
    `<prefix>-scan-example-service`. It may contain letters, digits, `-` and
    `_`.
3.  Open the pull request, check that the plan adds one scheduler job, and
    merge.

For a first scan, set `dry_run: true` on the entry. The scan then runs `cm
find`, `cm verify` and `cm fix` but makes no GitHub writes: no branches, pull
requests, comments, statuses or SARIF uploads. The results are still in the
reports bucket, BigQuery and the job logs. Remove the key when you are happy
with the results.

### Change or remove a repository

*   **Change settings:** edit the entry. The scheduler job is updated in place.
*   **Rename an entry:** this replaces its scheduler job.
*   **Remove a repository:** delete the entry. Its scheduler job is deleted.
    Fix pull requests, code scanning alerts, reports and BigQuery rows from
    earlier scans are left as they are.

### Run a scan now

```bash
gcloud scheduler jobs run "${PREFIX}-scan-example-service" --location="${REGION}" --project="${PROJECT_ID}"
```

The scan uses the entry's current settings.

### Pause all scans

Set `scheduler_paused: true` in `deployment.yaml` and merge. Scans that are
already running finish. Set it back to `false` to resume.

## Deployment settings

The keys you are most likely to change in `deployment.yaml`:

| Key | Default | Meaning |
| --- | --- | --- |
| `project_id`, `region` | (required), `us-central1` | Where the deployment lives |
| `resource_prefix` | `codemender` | Prefix for every resource name: 1-17 lowercase letters, digits or hyphens. Changing it replaces the whole deployment |
| `scheduler_cron`, `scheduler_timezone` | `0 2 * * *`, `Etc/UTC` | Default schedule for entries without `schedule` |
| `scheduler_paused` | `false` (`true` in the example) | Pauses every scheduler job |
| `runner_cpu`, `runner_memory` | `4`, `16Gi` | Size of each Cloud Run task (both jobs) |
| `github_app_id`, `github_app_installation_id`, `github_app_private_key_secret_id` | unset | GitHub App authentication; see below |
| `git_author_name`, `git_author_email` | unset | Author of the fix commits; see [Fix commit author](#fix-commit-author) |
| `wiz_client_id_secret_id`, `wiz_client_secret_secret_id` | `<prefix>-wiz-client-id`, `<prefix>-wiz-client-secret` | Names of the Wiz credential secrets |
| `enable_bigquery_telemetry` | `true` | Write scan history and findings to BigQuery |
| `bigquery_dataset_id` | `codemender_telemetry` | BigQuery dataset ID (not prefixed with `resource_prefix`; override if another deployment shares the project) |
| `bigquery_include_snippets` | `false` | Also store source snippets and the model's analysis text in BigQuery |
| `create_vpc_and_nat`, `existing_vpc_connector_id` | `false`, unset | Send the jobs' traffic through a VPC connector and Cloud NAT (fixed egress IP) |
| `cloudbuild_service_account_emails` | the project's default Cloud Build accounts | Who may build and roll out the runner image; list the bootstrap's image build account |

## GitHub credentials

The scheduled scans authenticate to GitHub as a GitHub App. Set it up once,
before the first scan.

### 1. Create the GitHub App

In your GitHub organization, go to **Settings > Developer settings > GitHub
Apps > New GitHub App**. Webhooks can be turned off. Grant these repository
permissions:

| Permission | Access | Why |
| --- | --- | --- |
| Contents | Read and write | Clone, push fix branches, delete a fix branch if opening the pull request fails |
| Pull requests | Read and write | Open fix pull requests, find existing ones, comment |
| Commit statuses | Read and write | Post the `CodeMender / Nightly Scan` status |
| Code scanning alerts | Read and write | Upload SARIF |
| Metadata | Read-only | Required by GitHub |
| Workflows | Read and write | Only if fixes may change files under `.github/workflows/`; GitHub rejects those pushes otherwise |

Then:

1.  Install the App on your organization, limited to the repositories you
    scan. Add each newly onboarded repository to the installation.
2.  On the App's settings page, generate a private key (a `.pem` file) and note
    the App ID. Optionally note the installation ID (the number at the end of
    the installation's settings URL); if you leave it out, the jobs look it up
    for each repository.

### 2. Store the private key in Secret Manager

Someone with Secret Manager Admin on the project creates the secret. Terraform
only references it, so the key never enters Terraform state, and a Terraform
change cannot delete it.

```bash
gcloud secrets create "${PREFIX}-github-app-private-key" \
    --replication-policy=automatic --project="${PROJECT_ID}"
gcloud secrets versions add "${PREFIX}-github-app-private-key" \
    --data-file=path/to/app.private-key.pem --project="${PROJECT_ID}"
```

Then delete the local `.pem` file.

The secret must exist before the next step: the plan looks it up and fails if
it is missing.

### 3. Turn it on in `deployment.yaml`

```yaml
github_app_id: "123456"
# Optional; looked up from each repository when empty.
github_app_installation_id: ""
# Optional; only if you used a different secret name.
# github_app_private_key_secret_id: my-secret-name
```

Open a pull request and merge it. Both Cloud Run jobs then receive the App ID
and the key, and mint their own tokens at run time.

### Rotate the key

Generate a new key on the App's settings page and add it as a new secret
version:

```bash
gcloud secrets versions add "${PREFIX}-github-app-private-key" \
    --data-file=path/to/new.private-key.pem --project="${PROJECT_ID}"
```

The next job execution uses the new version. No deployment change is needed.
Once no scan that started before the rotation is still running, delete the
old key in GitHub and disable the old secret version.

### Personal access token fallback

Terraform also creates a `<prefix>-github-token` secret with placeholder data.
It is used only when `github_app_id` is not set, in which case the jobs read a
token from it. Use the GitHub App instead; with the App configured, this
secret is not mounted on either job.

### Fix commit author

The commits on fix branches are authored and committed as:

| Setup | Author |
| --- | --- |
| `git_author_name` / `git_author_email` set | The configured name and email |
| GitHub App | The App's bot account, `<app-slug>[bot]` with `<id>+<app-slug>[bot]@users.noreply.github.com`, so GitHub shows the commits as made by the App |
| Personal access token | `CodeMender Agent <codemender-agent@noreply.invalid>` |

The App's bot account is looked up once per job. If the lookup fails, the
scan continues and the commits use the personal access token row's identity.
GitHub links a commit to an account by its email address, so a configured
`git_author_email` is always used with `git_author_name`, or with
`CodeMender Agent` when no name is set, never with the App's name. A
`git_author_name` on its own only replaces the name and keeps the default
email.

If your organization only accepts commits from certain email addresses, set
an accepted address in `deployment.yaml`, either directly or with
`scripts/setup/codemender-setup set git_author_email ADDRESS`:

```yaml
git_author_name: "CodeMender"
git_author_email: "codemender@example.com"
```

## Wiz import (optional)

A repository can also import findings from your Wiz tenant during Stage 1.
Imported findings are always checked with `cm verify` before they are fixed,
and only findings that verify lead to a fix pull request. If the import fails,
the scan continues with CodeMender's own findings.

1.  Create the two secrets that hold your Wiz service account's client ID and
    client secret. Terraform only references them. Only the runner job (Stage
    1 and 3) can read them; the worker never gets them.

    ```bash
    # Prompts without echoing, so the values stay out of shell history.
    read -rs -p 'Wiz client ID: ' WIZ_CLIENT_ID; echo
    read -rs -p 'Wiz client secret: ' WIZ_CLIENT_SECRET; echo
    printf '%s' "${WIZ_CLIENT_ID}" | gcloud secrets create "${PREFIX}-wiz-client-id" \
        --replication-policy=automatic --data-file=- --project="${PROJECT_ID}"
    printf '%s' "${WIZ_CLIENT_SECRET}" | gcloud secrets create "${PREFIX}-wiz-client-secret" \
        --replication-policy=automatic --data-file=- --project="${PROJECT_ID}"
    unset WIZ_CLIENT_ID WIZ_CLIENT_SECRET
    ```

    If you use other names, set `wiz_client_id_secret_id` and
    `wiz_client_secret_secret_id` in `deployment.yaml`.
2.  Enable it per repository in `repos.yaml`:

    ```yaml
        wiz:
          enabled: true
          min_severity: HIGH   # INFORMATIONAL, INFO, LOW, MEDIUM, HIGH or CRITICAL
    ```

    See `repos.example.yaml`. The secrets must exist before this change is
    planned.

## Build the runner image

Pull request scans in reusable workflow mode (the generator's default) run every
job in a container image built from your copy: language toolchains, the
orchestrator, and the CodeMender CLI. (Scheduled scans use a separate image that
Cloud Build pushes to Artifact Registry.)
`.github/workflows/build_runner_image.yml` builds it on a GitHub-hosted
`ubuntu-latest` runner and publishes it to GitHub Container Registry.

1.  **Turn publishing on.** The workflow's job is skipped unless your copy has
    the repository variable `PUBLISH_RUNNER_IMAGE` set to `true` (**Settings >
    Secrets and variables > Actions > Variables**):

    ```bash
    gh variable set PUBLISH_RUNNER_IMAGE --body true --repo ORG/YOUR-COPY
    ```

2.  **Run it** from **Actions > Build & Publish CodeMender Runner Image > Run
    workflow**, or:

    ```bash
    gh workflow run build_runner_image.yml --repo ORG/YOUR-COPY
    ```

    Optional inputs: `cm_version` (a CLI release; empty means the latest) and
    `cm_sha256` (the build fails unless the extracted `cm` binary has this
    SHA-256).
3.  **Use the image.** It is published as
    `ghcr.io/<owner>/codemender-runner:latest` and
    `ghcr.io/<owner>/codemender-runner:<commit-sha>`, where `<owner>` owns your
    copy. Pass it as `runner_image` (`--runner-image` in the generator).
4.  **Give the scanning repositories access.** A new package is private. In the
    package's settings, under **Manage Actions access**, add each scanning
    repository with the **Read** role. The runner pulls `ghcr.io` images with
    the calling run's `GITHUB_TOKEN`, so the caller workflow needs
    `packages: read`, which the generated workflow already has.

The build reaches `artifactregistry.googleapis.com` to download the CLI. If
your organization does not allow GitHub-hosted runners, change `runs-on` in
your copy.

**When it rebuilds.** On pushes to `main` that change `Dockerfile`,
`codemender_agent/**`, `requirements.txt` or `scripts/ci/stage_cm.sh`; on `v*`
tags; every Monday (05:17 UTC); and when you run it by hand. Pull request scans
use the CLI in the image and do not update it, so the weekly build is how they
get new CLI releases. Callers on `:latest` pick up each build on their next
run. To change versions only when you choose, use the `:<commit-sha>` tag and
update it when you are ready.

**Mirror into your own registry.** If runners must pull from your registry (for
example Artifactory), copy the image there after each build and use the
mirrored name as `runner_image`. The reusable workflow passes no registry
credentials to its job containers, so your runners must be able to pull the
mirrored image without credentials from the workflow, or you add `credentials`
to the container jobs in your copy of `codemender_parallel.yml`.
`codemender-setup pr-scans` only lists images outside `ghcr.io`; it does not
check them.

**Add your own toolchains.** If a repository's `build_command` needs tools the
image does not have, build an image on top of it and use that as
`runner_image` for that repository:

```dockerfile
FROM ghcr.io/ORG/codemender-runner:latest
RUN apt-get update && apt-get install -y --no-install-recommends rustc cargo \
    && rm -rf /var/lib/apt/lists/*
```

Rebuild it after the base image changes, or it keeps the older CLI.

## Before pull request scans

Pull request scans run `.github/workflows/codemender_parallel.yml` on your
GitHub Actions runners rather than in Cloud Run. Agree on these with your
platform and security teams before the first workflow runs:

| Decision | Options |
| --- | --- |
| Runners (`runner_type`) | GitHub-hosted (`ubuntu-latest`, the default), or the label of your self-hosted runners. A scan job needs about 4 vCPU and 16 GiB of memory. |
| Container jobs | Every job runs in the runner image with `--privileged`. On Actions Runner Controller, use container mode `dind`, or `kubernetes` with a hook pod template that sets `securityContext.privileged: true`. Runners without a container mode cannot run the jobs. |
| Sandbox | The CodeMender sandbox needs the privileged container. If it cannot start, the scan fails rather than running `cm` unsandboxed; `allow_unsandboxed_fallback: true` allows that rerun (with a warning). If your runners cannot allow privileged containers, `sandbox_enabled: false` relies on the runner's own isolation; your security team must accept either choice. |
| Runner image (`runner_image`) | `build_runner_image.yml` publishes `ghcr.io/<owner>/codemender-runner`. Give each scanning repository read access to the package, or mirror the image into your own registry (for example Artifactory) and use the mirrored name. The workflow passes no registry credentials, so a mirror must be pullable by your runners without them. See [Build the runner image](#build-the-runner-image). |
| Google identity | `terraform/gha_wif` creates a Workload Identity Federation provider and service account and sets the `GCP_WORKLOAD_IDENTITY_PROVIDER` and `GCP_SERVICE_ACCOUNT` repository secrets. Self-hosted runners on GKE with Workload Identity can leave both secrets unset: the workflow then skips its login step and uses the runner's own identity (pass `--no-wif` to `pr-scans`). |
| Egress | `github.com`, `api.github.com` and the Actions endpoints; the image registry (`ghcr.io` and `pkg-containers.githubusercontent.com`, or your mirror); `sts.googleapis.com` and `iamcredentials.googleapis.com`; `aiplatform.googleapis.com`. `build_runner_image.yml` runs on `ubuntu-latest` and downloads the CodeMender CLI from `artifactregistry.googleapis.com`; if only your own runners are allowed, they need that endpoint too. Include any proxy in between. |

Then check what can be checked from your copy:

```bash
scripts/setup/codemender-setup pr-scans --image IMAGE --runner-type LABEL --github-repo ORG/REPO
```

It reports the image, the identity and the runners, and lists the items above
that only your platform team can confirm. Then generate the caller workflow in
each scanned repository and choose blocking or advisory mode; see
[Set up pull request scans on a repository](../README.md#set-up-pull-request-scans-on-a-repository)
and the
[GitHub Actions Pre-Submit CI/CD Onboarding Guide](guides/github_actions_presubmit_ci_cd.md).

## Reading results

| What | Where |
| --- | --- |
| Fix pull requests | The scanned repository's pull requests, opened by the GitHub App's bot account |
| Scan status | `CodeMender / Nightly Scan` on the scanned commit; its link opens the workflow execution |
| Findings | The repository's **Security > Code scanning** tab |
| HTML report | `gs://<prefix>-reports-<project>/reports/<owner>_<repo>/<scan-id>/` (scans with findings only) |
| Scan history | BigQuery, for example the `v_scan_runs_flat` view |
| Logs | Cloud Logging for the `<prefix>-runner` and `<prefix>-worker` jobs, and the `<prefix>-coordinator` executions |

List and download HTML reports:

```bash
gcloud storage ls "gs://${PREFIX}-reports-${PROJECT_ID}/reports/"
gcloud storage cp "gs://${PREFIX}-reports-${PROJECT_ID}/reports/your-org_example-service/<scan-id>/*.html" .
```

The signed report link printed in the job log expires after a few hours; the
object itself is kept for 90 days.

Recent scans in BigQuery:

```sql
SELECT scan_timestamp, repository, status, active_findings_count, fixed_count, report_uri, execution_url
FROM `your-project-id.codemender_telemetry.v_scan_runs_flat`
ORDER BY scan_timestamp DESC
LIMIT 20;
```

Remember the two known gaps: a clean scan does not clear older code scanning
alerts, and no alerts are set up for failed scans. List failed executions with:

```bash
gcloud workflows executions list "${PREFIX}-coordinator" --location="${REGION}" \
    --project="${PROJECT_ID}" --filter='state=FAILED' --limit=10
```

## CodeMender CLI version

By default you run the latest CodeMender CLI release:

-   Each image build downloads the latest release (`_CM_VERSION` in
    `cloudbuild.yaml` is empty). The build checks the download against the
    SHA-256 that the CLI's download repository publishes for it.
-   Each scheduled scan runs `cm update` when it starts (`cm_auto_update: true`
    in `deployment.yaml`), so a scan picks up a new release even if the image
    was built earlier. The update checks the new binary's SHA-256 before using
    it. If the update fails, the scan continues with the CLI in the image.

The download is public; no access request is needed. The image build and the
scan's update both reach `artifactregistry.googleapis.com`. If your project is
inside a VPC Service Controls perimeter, add an egress rule for it, or the scan
keeps using the CLI in the image.

**Hold a release.** To stay on one exact CLI binary, for example while you
evaluate a new release:

1.  Set `cm_auto_update: false` in `deployment.yaml`.
2.  Set `_CM_VERSION` and `_CM_SHA256` (the SHA-256 of the extracted `cm`
    binary) in `cloudbuild.yaml`.

Make both changes in one pull request. After the merge, the image trigger builds
the image with that binary and rolls it out once no scan is running. Revert the
pull request to go back to the latest release.

**Trial build.** Build an image with a given release without rolling it out.
This checks the download and leaves the scheduled scans untouched:

```bash
gcloud builds submit --config=cloudbuild.yaml --region="${REGION}" --project="${PROJECT_ID}" \
    --substitutions=_RESOURCE_PREFIX="${PREFIX}",_REGION="${REGION}",_CM_VERSION=<version>,_IMAGE_TAG=cm-<version>,_UPDATE_JOBS=false .
```

Running `gcloud builds submit` by hand needs a build account with the image
permissions; see step 3 of the
[GitOps guide](guides/gitops_cloud_build.md#step-3-commit-the-configuration).
To roll an image back by hand, see
[Manual rollout and rollback](guides/gitops_cloud_build.md#manual-rollout-and-rollback).

A new CLI release can change its output or state format. If a scan behaves
differently after a release, hold the previous release as described above and
run a scan with `dry_run: true` on one repository.

## Taking updates

Updates to this repository are delivered as new snapshots of the source
repository your Google team shared with you. Each snapshot is a single commit
whose parent is the previous snapshot, so you can merge it into your copy like
any other branch.

This works if your copy started from the snapshot history (for example, you
cloned the shared repository and pushed it to your private repository), not
from a copy of the files.

```bash
# Once per clone
git remote add google <shared-repository-url>

git fetch google
git checkout -b update-codemender origin/main
git merge google/main    # resolve conflicts; your repos.yaml and deployment.yaml are not in the snapshots
git push origin update-codemender
```

Open a pull request as usual. The plan shows what the update changes; code
changes build a new image after the merge.

In your private repository, turn off Dependabot version updates (or review them
like any infrastructure change, since merging any pull request into the deployed
branch triggers `<prefix>-tf-apply`), and disable GitHub Actions workflows if
your organization does not provide the runners they expect.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| A scheduler job never runs | `scheduler_paused` is `true`, or the entry's `schedule` is in a different time zone than you expect (`scheduler_timezone`). |
| The plan fails with a secret not found | The GitHub App key or Wiz secret named in `deployment.yaml` does not exist yet. Create it first. |
| A scan fails right away with a GitHub `401`, `403` or `404` | The GitHub App is not installed on the repository, lacks a permission from the table above, or `github_app_installation_id` points at another installation. |
| Status `CodeMender / Nightly Scan` stays pending | The execution is still running (deep scans take hours), or both the scan and the failure finalizer failed. Check the `<prefix>-coordinator` execution. |
| A scan finds issues but opens no pull requests | `dry_run` is `true`, an open pull request or branch already exists for the finding, or `cm fix` could not produce a fix that passes the build. See the worker job logs. |
| Findings stay in the Security tab after they are fixed | Expected after a clean scan; see the known gaps above. Dismiss them, or wait for a later scan with findings. |
| Build steps fail inside the scan | `build_command` needs tools that are not in the runner image, or network access your egress settings block. |
| A merged code change is not running yet | The image rollout waits until no scan is running; see [How a new image rolls out](guides/gitops_cloud_build.md#how-a-new-image-rolls-out). |
| The image build fails in step `stage-cm` | The build cannot reach `artifactregistry.googleapis.com` (egress or VPC Service Controls), `_CM_VERSION` names a release that does not exist, or the downloaded file does not match its published or pinned SHA-256. The step log names the cause. |
