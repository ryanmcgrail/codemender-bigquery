# codemender-setup

A helper for the team that runs a GitOps CodeMender deployment in its own copy
of this repository. It checks the prerequisites and the configuration files,
and tells you what to do next.

It needs Python 3.9 or later (standard library only) and calls `gcloud`,
`terraform` and `git`. The GitHub CLI (`gh`) is optional; with it, the helper
can also check the repository on GitHub.

```bash
scripts/setup/codemender-setup --help
scripts/setup/codemender-setup check
scripts/setup/codemender-setup validate
```

Run it from anywhere inside your copy, or pass `--repo-root`.

## Commands

| Command | What it does | Changes anything? |
| --- | --- | --- |
| `check` | Checks tools (Terraform 1.11 or later), gcloud login and Application Default Credentials, your permissions in the project, and that the repository is private. It also warns about Dependabot and GitHub Actions workflows in your copy. | No |
| `validate` | Checks `terraform/gcp/repos.yaml` and `deployment.yaml`: quick lints first (duplicate keys, unquoted values that are not read as text, GHE.com URLs, the prefix length), then Terraform's own checks from `config.tf`. | No |
| `init` | Asks for the project, region, prefix, BigQuery dataset, deployed branch and at least one destroy approver, then writes `terraform/gcp/deployment.yaml`, an empty `terraform/gcp/repos.yaml` and `terraform/bootstrap/terraform.tfvars`. Refuses to overwrite existing files without `--force`. | Local files |
| `connect` | Links this repository to Cloud Build through a 2nd-gen GitHub connection (discovers and reuses active connections or defaults to `github`), walks you through the browser steps, and writes the linked repository's name to `terraform/bootstrap/terraform.tfvars`. | Google Cloud, local file |
| `bootstrap` | Runs `terraform/bootstrap`: init, plan, asks, apply. Copies local bootstrap state to the state bucket, seeds the initial empty Terraform state if missing so first PR checks can run read-only, and makes sure `deployment.yaml` lists the image build service account. | Google Cloud, local file |
| `add-repo NAME --url URL` | Adds a repository to `repos.yaml`. Optional: `--schedule`, `--branch`, `--scan-target`, `--build-command`, `--scan-dry-run`. | Local file |
| `remove-repo NAME` | Removes a repository from `repos.yaml`. Its scheduler job is deleted when the change is deployed. | Local file |
| `set KEY VALUE` | Sets one top-level key in `deployment.yaml`. The value is typed from `terraform/gcp/config.tf` (true/false, whole numbers, comma-separated lists). Asks first for `project_id`, `region` and `resource_prefix`, which replace resources. | Local file |
| `secrets github-app` | Stores the GitHub App private key in Secret Manager (`<prefix>-github-app-private-key`, created if missing), then sets `github_app_id` and, optionally, `github_app_installation_id` in `deployment.yaml`. | Secret Manager, local file |
| `secrets github-token` | Adds a personal access token as a new version of `<prefix>-github-token`. Terraform creates that secret on the first deployment; it is used only while `github_app_id` is not set. | Secret Manager |
| `secrets wiz` | Creates or updates the Wiz client ID and client secret secrets (`<prefix>-wiz-client-id`, `<prefix>-wiz-client-secret`, or the names set in `deployment.yaml`). | Secret Manager |
| `first-image` | Runs the `<prefix>-image` trigger once on the deployed branch, after the first deployment created the Cloud Run jobs, so they get a real runner image. | Starts a build |
| `doctor` | Checks the deployed pipeline and deployment: configuration lints, the Cloud Build connection, a leftover Secret Manager Admin grant, the state bucket and its backup, the four triggers, builds waiting for approval, recent failed builds, the jobs' image and the secrets. Tells you when to start the schedules. | No |
| `pr-scans` | Checks the prerequisites for pull request scans on GitHub Actions: the runner image, Workload Identity Federation (`terraform/gha_wif`) and the runners. Lists what your platform team has to confirm. | No |
| `teardown --print` | Prints the teardown steps with this deployment's names. | No |

`validate` runs Terraform with mock providers in a temporary copy of
`terraform/gcp`. It needs no credentials or state and never contacts your
project. It ignores `TF_VAR_*`, `TF_CLI_ARGS*` and local `terraform.tfvars`, so
it sees what the pipeline sees. Terraform still downloads its providers unless
they are in its plugin cache. Use `--repos FILE` and `--deployment FILE` to
check other files, and `--skip-terraform` for the lints only.

### Editing the configuration

`init`, `add-repo`, `remove-repo` and `set` show a diff of every file they
change, then run `validate` (skip it with `--skip-validate`). They change only
the lines they own, so your comments and layout stay. Values are quoted where
YAML would otherwise read them as something other than text.

`deployment.yaml` and `repos.yaml` are committed and deployed through a pull
request like any other change. `terraform/bootstrap/terraform.tfvars` stays
local: it is in `.gitignore`.

With `--pr`, the helper commits the changed YAML files on a new branch named
`codemender-setup/...`, pushes it to `origin` and opens a pull request with
`gh` (or tells you to open it yourself without `gh`). It needs a checked-out
branch and nothing staged. You end up back on your branch with your other
local changes untouched; the change lives on the new branch until the pull
request is merged.

`deployment.yaml` and `repos.yaml` are deployed together, so while either is
not committed yet (a first setup), `--pr` puts both in the pull request. They
then leave your working tree until you merge the pull request and `git pull`,
so in a first setup use `--pr` only on the last edit, typically `add-repo`.

### Connecting and bootstrapping

`connect` follows Step 1 of the GitOps guide
([gitops_cloud_build.md](../../docs/guides/gitops_cloud_build.md)):

1.  It enables the Cloud Build and Secret Manager APIs.
2.  If the Cloud Build service agent lacks Secret Manager Admin, it asks before
    granting it. The agent needs that role to store the connection's GitHub
    token.
3.  It creates the connection and prints the links: authorize Cloud Build, then
    install the Cloud Build GitHub App on this repository.
4.  It waits until the connection is complete. If it granted the role in step 2,
    it offers to remove it again; Cloud Build needs it only while a connection
    is set up.
5.  It links the repository, or finds an existing link with the same URL, even
    one made in the Cloud Console under another name.

Use `--connection-project` if the connection lives in another project. When
`--connection` is not provided, `connect` lists existing Cloud Build GitHub
connections in the project and region and offers to reuse an active one rather
than creating a new connection. With `--non-interactive`, `connect` stops at the
browser step; run it again when you are done.

`bootstrap` needs the linked repository and at least one approver in
`terraform/bootstrap/terraform.tfvars`. It ignores `TF_VAR_*` and `TF_CLI_ARGS*`
and uses your Application Default Credentials. With `--dry-run` it plans only.

The bootstrap keeps its state in `terraform/bootstrap/terraform.tfstate`, on
your machine. After every run, `bootstrap` copies it to
`gs://<state bucket>/bootstrap-backup/terraform.tfstate`; the bucket keeps
older versions. You need that state to change or remove the triggers later.
When there is no local state but the backup exists (a new Cloud Shell session
or codespace, for example), `bootstrap` offers to restore it before it plans;
without it, Terraform would try to create the existing resources again. To
restore it by hand:

```bash
gcloud storage cp gs://STATE_BUCKET/bootstrap-backup/terraform.tfstate terraform/bootstrap/
```

After applying the bootstrap stack, `bootstrap` also checks if
`gs://<state bucket>/<state_prefix>/default.tfstate` exists. If not, it seeds
a minimal empty Terraform state so that the first pull request check can run
`terraform plan -lock=false` under the read-only plan identity without failing
on a missing remote state file.

### Secrets

`secrets` reads secret values without echoing them, or from a file
(`--token-file FILE`, `--client-secret-file FILE`, `-` for standard input). It
hands them to `gcloud` on standard input, or as the path of the key file, never
on the command line, and never prints them. The values never enter Terraform
state: Terraform only references the App key and Wiz secrets, and the token is
added as a version Terraform does not manage. Creating a secret needs Secret
Manager Admin on the project.

New secrets use automatic replication. If an organization policy restricts
locations, pass `--secret-locations us-east1,us-central1` for user-managed
replication. When a secret already has versions, the helper asks before it
adds a new one; the next job execution uses the new version. Delete the local
`.pem` file once `secrets github-app` has stored it. `secrets github-app` also
sets `github_app_id` in `deployment.yaml`; add `--pr` once that file is
committed.

```bash
scripts/setup/codemender-setup secrets github-app --app-id 123456 --key-file ~/app.private-key.pem
scripts/setup/codemender-setup secrets wiz --client-id "$WIZ_CLIENT_ID"
```

### After the first deployment

The first pull request with `deployment.yaml` and `repos.yaml` creates the
Cloud Run jobs with a placeholder image, and `init` keeps the schedules paused
(`scheduler_paused: true`). Then:

1.  `first-image` runs the image trigger once. If `image_requires_approval` is
    set, an approver approves the build first. Nothing runs yet, so the image
    rolls out right after the build.
2.  `doctor` reports the jobs' image. Once it is a real one, it tells you to
    start the schedules: `codemender-setup set scheduler_paused false --pr`.

Run `doctor` whenever something looks wrong. It only reads: it prints the
`gcloud` command for anything to fix (approving a waiting build, removing a
leftover role) instead of running it.

### Pull request scans

`pr-scans` checks what pull request scans on GitHub Actions need before the
first workflow runs, and changes nothing:

*   The runner image (`--image`): that it is not the workflow's placeholder,
    and, on `ghcr.io`, that it exists and who can pull it. Images on another
    registry, such as a mirror, are only listed.
*   Workload Identity Federation from `terraform/gha_wif`: the provider, the
    service account, the Vertex AI API and the two repository secrets the
    workflow reads. Use `--wif-project`, `--pool`, `--provider` and
    `--service-account` if you changed the defaults, or `--no-wif` if
    self-hosted runners bring their own identity (GKE Workload Identity).
*   The runners (`--runner-type LABEL`): GitHub-hosted or self-hosted, and, if
    you may list them, which runners carry the label.

It then lists what only your platform team can confirm: container mode and
privileged containers on self-hosted runners, image pulls through a mirror,
and egress. Generating the workflow itself is a separate step
(`scripts/ci/init_codemender_workflow.py`, where your copy has it).

```bash
scripts/setup/codemender-setup pr-scans --image ghcr.io/OWNER/codemender-runner:latest --runner-type LABEL
```

### Teardown

`teardown --print` prints the steps to remove the deployment, in order, with
its names filled in. It never deletes anything itself.

## Options for every command

| Option | Meaning |
| --- | --- |
| `--repo-root DIR` | Your copy of this repository (default: found from the current directory). |
| `--yes`, `-y` | Answer yes to every confirmation. |
| `--non-interactive` | Never prompt; fail with exit code 2 if a value is missing. |
| `--dry-run` | Show what would change without changing anything. |

Exit codes: `0` everything passed, `1` a check failed, `2` usage error, `3`
cancelled.

## Where to run it

**Cloud Shell** has `gcloud` and `git`, and is already logged in. Its Terraform
can be older than 1.11; `check` tells you. Cloud Shell keeps only your home
directory between sessions, so install a newer Terraform there.

**Your workstation** needs the same tools. Log in with both commands:

```bash
gcloud auth login
gcloud auth application-default login   # Terraform uses these credentials
```

**GitHub Codespaces** (or VS Code Dev Containers) uses `.devcontainer/`, which
installs Python, Terraform, the GitHub CLI and the Google Cloud CLI, and puts
`codemender-setup` on the `PATH`. Log in with the two commands above; use
`gcloud auth login --no-launch-browser` if the browser does not open. A
codespace is deleted after a period of inactivity, so keep the bootstrap
state backup (see above).
