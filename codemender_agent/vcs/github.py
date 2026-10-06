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

"""GitHub REST API integration for CodeMender Agent."""

import base64
import gzip
import logging
import random
import re
import time
from typing import Any, Dict, List, Optional, Set

import requests
from codemender_agent.utils import is_dry_run, is_unauthorized_http_error, retry_on_exception, run_command
from codemender_agent.vcs.git import (
    get_git_auth_header,
    normalize_repo_relative_path,
    parse_diff_hunks_to_review_comments,
    parse_repo_owner_and_name,
    sanitize_git_url,
)

logger = logging.getLogger("codemender-orchestrator")

STATUS_CONTEXT_PR = "CodeMender / Security Gate"
STATUS_CONTEXT_SCHEDULED = "CodeMender / Nightly Scan"


class GitHubUnauthorizedError(RuntimeError):
  """GitHub rejected the token with HTTP 401 (expired, revoked or invalid).

  Raised by the lookups whose fallback would otherwise silently produce a
  wrong answer (no duplicate pull request, a "main" default branch). Callers
  holding a GitHub App installation token can discard it, mint a new one and
  retry once; see `config.call_with_github_token`.
  """


def _skip_for_dry_run(action: str) -> bool:
  """Logs and returns True when CODEMENDER_DRY_RUN forbids this GitHub call.

  Every helper in this module that writes to GitHub, or that looks up remote
  branches and pull requests to deduplicate findings, checks this first, so a
  dry run makes no GitHub writes whichever runner calls it.
  """
  if not is_dry_run():
    return False
  logger.info("Dry run (CODEMENDER_DRY_RUN): skipping %s.", action)
  return True


@retry_on_exception(max_tries=3)
def _get_branch_via_api(
    owner: str, repo: str, branch_name: str, token: str
) -> Optional[bool]:
  """Triggers GitHub branch status checks with raise_for_status validation."""
  # 1. Return None for fake tokens in mock/unit testing environments
  if token == "fake-token":
    return None
  # 2. Build HTTP request headers with authorization bearer
  headers = {
      "Authorization": f"Bearer {token}",
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
  }
  api_url = (
      f"https://api.github.com/repos/{owner}/{repo}/branches/{branch_name}"
  )
  # 3. Query GitHub REST API endpoint for branch existence
  resp = requests.get(api_url, headers=headers, timeout=10)
  if resp.status_code == 200:
    return True
  elif resp.status_code == 404:
    return False
  # Trigger retry decorator on server error or rate limiting
  resp.raise_for_status()
  return None


def check_remote_branch_exists(
    repo_url: str, token: str, branch_name: str, cwd: Optional[str] = None
) -> bool:
  """Checks if a branch already exists on the remote repository.

  Always False in a dry run, which skips remote duplicate checks.

  Raises:
    GitHubUnauthorizedError: GitHub rejected the token. The git fallback
      would send the same token, so it is not attempted.
  """
  if _skip_for_dry_run(f"remote branch check for {branch_name}"):
    return False
  sanitized_url = sanitize_git_url(repo_url)
  # 1. Attempt O(1) branch existence check via GitHub REST API
  try:
    owner, repo = parse_repo_owner_and_name(sanitized_url)
    res = _get_branch_via_api(owner, repo, branch_name, token)
    if res is not None:
      return res
  except Exception as e:
    if is_unauthorized_http_error(e):
      raise GitHubUnauthorizedError(
          f"GitHub rejected the token while checking branch {branch_name}: {e}"
      ) from e
    logger.warning(
        "GitHub API branch check failed after retries (%s), falling back to"
        " git ls-remote",
        e,
    )

  # 2. Fallback to git ls-remote CLI command if API is inaccessible or rate-limited
  cmd = [
      "git",
      "-c",
      get_git_auth_header(token),
      "ls-remote",
      "--heads",
      sanitized_url,
      f"refs/heads/{branch_name}",
  ]
  res = run_command(cmd, cwd=cwd, check=True)
  return bool(res.stdout and branch_name in res.stdout)


@retry_on_exception(max_tries=3, initial_delay=2, backoff_factor=2)
def _delete_branch_via_api(
    owner: str, repo: str, branch_name: str, token: str
) -> bool:
  """Deletes a remote branch via GitHub REST API with raise_for_status validation."""
  if token == "fake-token":
    logger.info(
        "Mock GitHub token detected ('fake-token'), simulating branch deletion: %s",
        branch_name,
    )
    return True

  headers = {
      "Authorization": f"Bearer {token}",
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
  }
  # GitHub API endpoint to delete ref: DELETE /repos/{owner}/{repo}/git/refs/heads/{branch_name}
  api_url = f"https://api.github.com/repos/{owner}/{repo}/git/refs/heads/{branch_name}"
  resp = requests.delete(api_url, headers=headers, timeout=15)

  # Status 204: Successfully deleted
  if resp.status_code == 204:
    logger.info("Successfully deleted remote branch via API: %s", branch_name)
    return True
  # Status 404 / 422: Branch already does not exist (idempotent success)
  elif resp.status_code in (404, 422):
    logger.info(
        "Remote branch %s already deleted or does not exist (HTTP %d).",
        branch_name,
        resp.status_code,
    )
    return True

  if resp.status_code == 403 and any(
      msg in resp.text.lower() for msg in ["rate limit", "abuse detection"]
  ):
    resp.raise_for_status()

  resp.raise_for_status()
  return True


def delete_remote_branch(
    repo_url: str,
    token: str,
    branch_name: str,
    cwd: Optional[str] = None,
) -> bool:
  """Deletes a remote branch via GitHub REST API with Git CLI fallback.

  Enforces a strict security prefix check (branch_name must start with 'codemender/')
  to prevent deleting critical or protected branches (e.g., main, master).
  Does nothing and returns False in a dry run.
  """
  if _skip_for_dry_run(f"deletion of remote branch {branch_name}"):
    return False
  if not branch_name or not branch_name.startswith("codemender/"):
    logger.error(
        "Refusing to delete non-CodeMender branch '%s' for safety.", branch_name
    )
    return False

  sanitized_url = sanitize_git_url(repo_url)

  # 1. Attempt branch deletion via GitHub REST API
  try:
    owner, repo = parse_repo_owner_and_name(sanitized_url)
    if _delete_branch_via_api(owner, repo, branch_name, token):
      return True
  except Exception as e:
    logger.warning(
        "GitHub API branch deletion failed (%s), falling back to git push --delete.",
        e,
    )

  # 2. Fallback to git push origin --delete <branch_name> CLI command
  try:
    cmd = [
        "git",
        "-c",
        get_git_auth_header(token),
        "push",
        "origin",
        "--delete",
        branch_name,
    ]
    res = run_command(cmd, cwd=cwd, check=False)
    if res.returncode == 0:
      logger.info(
          "Successfully deleted remote branch via Git CLI: %s", branch_name
      )
      return True
    else:
      logger.warning(
          "Git CLI branch deletion returned non-zero code %d: %s",
          res.returncode,
          res.stderr,
      )
  except Exception as e:
    logger.warning("Git CLI branch deletion failed: %s", e)

  return False


@retry_on_exception(max_tries=3)
def _fetch_default_branch_via_api(token: str, owner: str, repo: str) -> str:
  """Queries repository metadata from GitHub with raise_for_status checks."""
  # 1. Fallback to main branch for mock token in test suites
  if token == "fake-token":
    return "main"
  # 2. Build GitHub API request headers
  headers = {
      "Authorization": f"Bearer {token}",
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
  }
  # 3. Query repository metadata endpoint to get repository default branch
  resp = requests.get(
      f"https://api.github.com/repos/{owner}/{repo}",
      headers=headers,
      timeout=10,
  )
  resp.raise_for_status()
  return resp.json().get("default_branch", "main")


def get_default_branch(
    token: str, owner: str, repo: str, fail_on_unauthorized: bool = False
) -> str:
  """Gets the default branch name for a repository via GitHub API or defaults to main.

  Args:
    fail_on_unauthorized: Raise instead of falling back to "main" when GitHub
      rejects the token, so the caller can replace the token and retry
      rather than silently target the wrong branch.

  Raises:
    GitHubUnauthorizedError: GitHub rejected the token and
      `fail_on_unauthorized` is set.
  """
  try:
    return _fetch_default_branch_via_api(token, owner, repo)
  except Exception as e:
    if fail_on_unauthorized and is_unauthorized_http_error(e):
      raise GitHubUnauthorizedError(
          f"GitHub rejected the token while reading the default branch of"
          f" {owner}/{repo}: {e}"
      ) from e
    logger.warning(
        "Could not determine default branch via API after retries: %s", e
    )
  return "main"


@retry_on_exception(max_tries=3)
def _check_duplicate_pr_api(
    repo_url: str,
    token: str,
    file_path: str,
    vuln_type: str,
    start_line: int,
    head_branch: Optional[str] = None,
) -> Any:
  """Checks GitHub API for existing duplicate PRs traversing pagination headers.

  Returns:
    The existing PR's html_url string (or True if html_url is absent) when a
    duplicate open PR is found, or False otherwise.
  """
  if token == "fake-token":
    return False
  sanitized_url = sanitize_git_url(repo_url)
  owner, repo = parse_repo_owner_and_name(sanitized_url)
  headers = {
      "Authorization": f"Bearer {token}",
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
  }

  # 1. If head_branch is specified, perform O(1) targeted search first
  if head_branch:
    target_url = f"https://api.github.com/repos/{owner}/{repo}/pulls?head={owner}:{head_branch}&state=open"
    resp = requests.get(target_url, headers=headers, timeout=15)
    if resp.status_code == 401 or (
        resp.status_code == 403
        and any(
            msg in resp.text.lower() for msg in ["rate limit", "abuse detection"]
        )
    ):
      resp.raise_for_status()
    # Check if a pull request exists matching this exact head branch
    if resp.status_code == 200:
      prs = resp.json()
      if isinstance(prs, list) and len(prs) > 0:
        pr_html_url = prs[0].get("html_url")
        logger.info(
            "Found existing open PR targeting head branch %s: %s",
            head_branch,
            pr_html_url,
        )
        return pr_html_url or True

  # 2. Paginate over open pull requests to check finding descriptions
  url: Optional[str] = (
      f"https://api.github.com/repos/{owner}/{repo}/pulls?state=open&per_page=100"
  )

  with requests.Session() as session:
    while url:
      # Fetch page of open pull requests
      resp = session.get(url, headers=headers, timeout=15)
      if resp.status_code == 403 and any(
          msg in resp.text.lower() for msg in ["rate limit", "abuse detection"]
      ):
        resp.raise_for_status()
      resp.raise_for_status()

      prs = resp.json()
      if not isinstance(prs, list):
        break

      # 3. Check each open PR for matching vulnerability signatures
      for pr in prs:
        if head_branch and pr.get("head", {}).get("ref") == head_branch:
          return pr.get("html_url") or True
        body = pr.get("body") or ""
        # Match PR body against vulnerability metadata and target file path
        if "CodeMender Security Fix" in body and file_path in body and vuln_type in body:
          match = re.search(r"\*\*Start Line\*\*:\s*(\d+)", body, re.IGNORECASE)
          if match:
            existing_line = int(match.group(1))
            # Match within 15 lines of original vulnerability location
            if abs(existing_line - start_line) <= 15:
              pr_html_url = pr.get("html_url")
              logger.info(
                  "Found existing PR (%s) covering %s in %s near line %d.",
                  pr_html_url,
                  vuln_type,
                  file_path,
                  start_line,
              )
              return pr_html_url or True

      # 4. Traverse next page link if present in Link header
      url = resp.links.get("next", {}).get("url")

  return False


def is_duplicate_pr(
    repo_url: str,
    token: str,
    file_path: str,
    vuln_type: str,
    start_line: int,
    head_branch: Optional[str] = None,
) -> Any:
  """Checks if an open PR already exists for the same vulnerability near the same line.

  Always False in a dry run, which skips remote duplicate checks.

  Raises:
    GitHubUnauthorizedError: GitHub rejected the token. Assuming "no
      duplicate" here could open a second pull request for the same finding.
  """
  if _skip_for_dry_run(f"open pull request check for {file_path}"):
    return False
  try:
    return _check_duplicate_pr_api(
        repo_url, token, file_path, vuln_type, start_line, head_branch=head_branch
    )
  except Exception as e:
    if is_unauthorized_http_error(e):
      raise GitHubUnauthorizedError(
          f"GitHub rejected the token while checking for an open pull request"
          f" covering {file_path}: {e}"
      ) from e
    logger.warning(
        "GitHub API check for duplicate PR failed after retries (%s), assuming no duplicate PR.",
        e,
    )
    return False


@retry_on_exception(max_tries=5, initial_delay=3, backoff_factor=2)
def create_pr_comment(
    token: str,
    owner: str,
    repo: str,
    pr_number: int,
    body: str,
) -> Optional[str]:
  """Posts a Markdown review comment on a Pull Request (or Issue)."""
  if _skip_for_dry_run(f"comment on pull request #{pr_number}"):
    return None
  # 1. Handle mock GitHub token in test environments
  if token == "fake-token":
    logger.info("Mock GitHub token detected ('fake-token'), simulating PR comment.")
    return f"https://github.com/{owner}/{repo}/issues/{pr_number}#issuecomment-1"

  # 2. Build comment API URL and authorization headers
  url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"
  headers = {
      "Authorization": f"Bearer {token}",
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
  }
  # The fork fallback comment embeds the patch diff twice (once to read, once
  # for `git apply`), so a large patch can exceed GitHub's body limit and lose
  # the remediation to a 422. Cap it here to cover every caller.
  payload = {"body": truncate_comment_body(body)}

  # 3. Post review comment payload to GitHub Issue/PR comments API
  resp = requests.post(url, headers=headers, json=payload, timeout=15)
  if resp.status_code == 403 and any(
      msg in resp.text.lower() for msg in ["rate limit", "abuse detection"]
  ):
    # Retry on rate limiting or abuse detection triggers
    resp.raise_for_status()
  # Validate response status code
  resp.raise_for_status()
  comment_url = resp.json().get("html_url")
  logger.info("Successfully posted comment on PR #%d: %s", pr_number, comment_url)
  return comment_url


@retry_on_exception(max_tries=5, initial_delay=3, backoff_factor=2)
def create_pull_request(
    token: str,
    owner: str,
    repo: str,
    title: str,
    body: str,
    head_branch: str,
    base_branch: str,
) -> Optional[str]:
  """Creates a Pull Request on GitHub using REST API."""
  if _skip_for_dry_run(f"pull request creation for {head_branch}"):
    return None
  # 1. Handle mock token in test suites
  if token == "fake-token":
    logger.info("Mock GitHub token detected ('fake-token'), simulating PR creation.")
    return f"https://github.com/{owner}/{repo}/pull/1"

  # 2. Prepare PR creation payload with title, body, head branch, and base branch
  url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
  headers = {
      "Authorization": f"Bearer {token}",
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
  }
  payload = {
      "title": title,
      "body": body,
      "head": head_branch,
      "base": base_branch,
  }
  # 3. Submit Pull Request creation request
  resp = requests.post(url, headers=headers, json=payload, timeout=15)

  # Gracefully intercept HTTP 422 "PR already exists" validation failure
  if resp.status_code == 422:
    try:
      resp_data = resp.json()
      errors = resp_data.get("errors") or []
      messages = [e.get("message") or "" for e in errors if isinstance(e, dict)]
      top_msg = resp_data.get("message") or ""
      if any(
          "already exists" in msg for msg in messages
      ) or "already exists" in top_msg:
        logger.info(
            "A Pull Request already exists on GitHub for branch %s. Skipping PR"
            " creation.",
            head_branch,
        )
        return "EXISTING_PR"
    except Exception:
      pass

  if resp.status_code == 403 and any(
      msg in resp.text.lower() for msg in ["rate limit", "abuse detection"]
  ):
    resp.raise_for_status()
  resp.raise_for_status()  # Throws HTTPError to trigger backoff retry decorator
  pr_url = resp.json().get("html_url")
  logger.info("Successfully created Pull Request: %s", pr_url)
  return pr_url


@retry_on_exception(max_tries=3, initial_delay=2, backoff_factor=2)
def _post_commit_status_api(
    token: str,
    owner: str,
    repo: str,
    sha: str,
    state: str,
    description: str,
    context: str = "CodeMender / Security Gate",
    target_url: Optional[str] = None,
) -> bool:
  """Posts a commit status check to GitHub REST API."""
  if _skip_for_dry_run(f"commit status '{context}' ({state})"):
    return False
  # 1. Handle mock token in test suites
  if token == "fake-token":
    logger.info("Mock GitHub token detected ('fake-token'), simulating commit status creation.")
    return True

  # 2. Prepare status payload with state, description, context, and optional target URL
  url = f"https://api.github.com/repos/{owner}/{repo}/statuses/{sha}"
  headers = {
      "Authorization": f"Bearer {token}",
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
  }
  # GitHub API limits status description to 140 characters
  clean_description = (description[:137] + "...") if len(description) > 140 else description
  payload = {
      "state": state,  # "error", "failure", "pending", "success"
      "description": clean_description,
      "context": context,
  }
  if target_url:
    payload["target_url"] = target_url

  # 3. Submit Commit Status request
  resp = requests.post(url, headers=headers, json=payload, timeout=15)
  if resp.status_code == 403 and any(
      msg in resp.text.lower() for msg in ["rate limit", "abuse detection"]
  ):
    # Retry on secondary rate limit / abuse detection triggers
    resp.raise_for_status()
  resp.raise_for_status()
  logger.info("Successfully posted commit status '%s' (%s) for SHA %s", context, state, sha[:8])
  return True


def post_commit_status(
    token: str,
    owner: str,
    repo: str,
    sha: str,
    state: str,
    description: str,
    context: str = "CodeMender / Security Gate",
    target_url: Optional[str] = None,
) -> bool:
  """Safely posts a commit status check on a commit SHA, logging warnings on failure without throwing."""
  try:
    return _post_commit_status_api(
        token=token,
        owner=owner,
        repo=repo,
        sha=sha,
        state=state,
        description=description,
        context=context,
        target_url=target_url,
    )
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.warning("Failed to post commit status check '%s' to GitHub: %s", context, e)
    return False


# HTML marker embedded in the single sticky summary comment posted by the
# aggregate stage, used to locate and update that comment on subsequent runs.
STICKY_SUMMARY_MARKER = "<!-- codemender-summary -->"

# Prefix of the HTML marker embedded in each inline suggestion comment, used to
# deduplicate findings across re-runs (suggestion mode pushes no branch, so the
# usual remote-branch dedup cannot apply).
FINDING_MARKER_PREFIX = "<!-- codemender-finding:"

# Matches a unified diff hunk header, capturing the RIGHT (new) side range.
_PR_HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def finding_marker(finding_id: str) -> str:
  """Builds the HTML comment marker identifying a finding's suggestion."""
  return f"{FINDING_MARKER_PREFIX}{finding_id} -->"


@retry_on_exception(max_tries=3, initial_delay=2, backoff_factor=2)
def _fetch_pr_files(
    token: str, owner: str, repo: str, pr_number: int
) -> List[Dict]:
  """Fetches the full paginated list of files changed in a Pull Request."""
  # 1. Handle mock token in test suites
  if token == "fake-token":
    return []

  # 2. Build headers and the first page URL
  headers = {
      "Authorization": f"Bearer {token}",
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
  }
  url: Optional[str] = (
      f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/files?per_page=100"
  )

  # 3. Traverse every page, accumulating file entries
  files: List[Dict] = []
  with requests.Session() as session:
    while url:
      resp = session.get(url, headers=headers, timeout=15)
      if resp.status_code == 403 and any(
          msg in resp.text.lower() for msg in ["rate limit", "abuse detection"]
      ):
        resp.raise_for_status()
      resp.raise_for_status()

      page = resp.json()
      if not isinstance(page, list):
        break
      files.extend(page)
      url = resp.links.get("next", {}).get("url")

  return files


def get_pr_diff_line_ranges(
    token: str, owner: str, repo: str, pr_number: int
) -> Dict[str, Set[int]]:
  """Maps each changed file to the RIGHT-side line numbers inside its diff hunks.

  GitHub rejects inline review comments that anchor outside a diff hunk with
  HTTP 422, so callers use this map to pre-validate suggestions before posting.
  Files served without a ``patch`` body (too large, or binary) are omitted so
  that they are treated as not addressable and force a fallback.
  """
  try:
    files = _fetch_pr_files(token, owner, repo, pr_number)
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.warning(
        "Failed to fetch changed files for PR #%d (%s); treating the whole diff"
        " as not suggestable.",
        pr_number,
        e,
    )
    return {}

  # 1. Parse each file's unified diff patch into a set of addressable lines
  ranges: Dict[str, Set[int]] = {}
  for entry in files:
    path = entry.get("filename")
    patch = entry.get("patch")
    if not path or not patch:
      # No patch body means GitHub cannot render an anchorable diff.
      continue

    lines: Set[int] = set()
    for line in patch.splitlines():
      match = _PR_HUNK_HEADER_RE.match(line)
      if not match:
        continue
      # 2. Expand the hunk header's new-side range into individual line numbers
      start = int(match.group(1))
      count = int(match.group(2)) if match.group(2) is not None else 1
      if count <= 0:
        continue
      lines.update(range(start, start + count))

    if lines:
      ranges[path] = lines

  return ranges


# Matches a Markdown code fence opener or closer at the start of a line.
_MD_FENCE_RE = re.compile(r"^(`{3,}|~{3,})(.*)$")


def _terminate_open_fence(text: str) -> str:
  """Appends a closing delimiter if `text` leaves a Markdown code fence open.

  Follows CommonMark fence pairing: a closing fence uses the same character as
  its opener, is at least as long, and carries no info string.
  """
  open_delim = ""
  for line in text.split("\n"):
    match = _MD_FENCE_RE.match(line)
    if not match:
      continue
    delim, info = match.group(1), match.group(2)
    if not open_delim:
      open_delim = delim
    elif (
        delim[0] == open_delim[0]
        and len(delim) >= len(open_delim)
        and not info.strip()
    ):
      open_delim = ""
  return f"{text}\n{open_delim}" if open_delim else text


# GitHub rejects issue and pull request comment bodies longer than this with
# HTTP 422 ("Body is too long (maximum is 65536 characters)").
MAX_COMMENT_BODY_CHARS = 65536

_TRUNCATION_NOTICE = (
    "\n\n---\n"
    "*⚠️ This comment was truncated because it exceeded GitHub's 65,536"
    " character limit. See the workflow run summary for the full report.*"
)

# Headroom for the closing fence that _terminate_open_fence may append when the
# cut lands inside a code block.
_TRUNCATION_SLACK = 16


def truncate_comment_body(body: str, reserved: int = 0) -> str:
  """Trims a comment body to GitHub's maximum length, appending a notice.

  Args:
    body: The rendered Markdown comment body.
    reserved: Characters the caller will prepend (e.g. a sticky marker), which
      count against the same budget.
  """
  limit = MAX_COMMENT_BODY_CHARS - reserved
  if len(body) <= limit:
    return body

  head = body[: limit - len(_TRUNCATION_NOTICE) - _TRUNCATION_SLACK]
  # Cut on a line boundary so a Markdown table row or list item is not split.
  last_newline = head.rfind("\n")
  if last_newline > 0:
    head = head[:last_newline]
  # The cut may have landed inside a fenced block; close it before appending.
  result = _terminate_open_fence(head) + _TRUNCATION_NOTICE
  # Belt and braces: a pathologically long fence delimiter could still overrun
  # the slack above, and exceeding the cap costs the whole comment to a 422.
  return result if len(result) <= limit else result[:limit]


def format_suggestion_body(replacement_lines: List[str], preamble: str = "") -> str:
  """Wraps replacement lines in a GitHub ```suggestion block, fence-safe.

  The replacement may itself contain backtick runs (e.g. Markdown or shell
  snippets), so the fence is widened past the longest run in the content.
  An empty replacement renders as an empty suggestion block, which GitHub
  interprets as "delete these lines".
  """
  # 1. Size the fence past the longest backtick run in the payload
  longest_run = 0
  for line in replacement_lines:
    for run in re.findall(r"`+", line):
      longest_run = max(longest_run, len(run))
  fence = "`" * max(3, longest_run + 1)

  # 2. Assemble the suggestion block
  if replacement_lines:
    block = f"{fence}suggestion\n" + "\n".join(replacement_lines) + f"\n{fence}"
  else:
    block = f"{fence}suggestion\n{fence}"

  if preamble:
    # The preamble embeds LLM-authored analysis, which may leave a code fence
    # unterminated. An open fence would absorb the suggestion block below and
    # GitHub would render it as inert text, so close it first.
    return f"{_terminate_open_fence(preamble)}\n\n{block}"
  return block


def build_review_comment(
    path: str, start_line: int, end_line: int, body: str
) -> Dict:
  """Builds a single inline review comment payload anchored on the RIGHT side."""
  comment: Dict = {
      "path": path,
      "line": end_line,
      "side": "RIGHT",
      "body": body,
  }
  # GitHub requires start_line to be strictly less than line; a single-line
  # anchor must omit it entirely.
  if start_line < end_line:
    comment["start_line"] = start_line
    comment["start_side"] = "RIGHT"
  return comment


@retry_on_exception(max_tries=3, initial_delay=3, backoff_factor=2)
def _create_pr_review_api(
    token: str,
    owner: str,
    repo: str,
    pr_number: int,
    commit_id: Optional[str],
    body: str,
    comments: List[Dict],
) -> Optional[str]:
  """Posts a Pull Request review carrying inline suggestion comments."""
  if _skip_for_dry_run(f"suggestion review on pull request #{pr_number}"):
    return None
  # 1. Handle mock token in test suites
  if token == "fake-token":
    logger.info("Mock GitHub token detected ('fake-token'), simulating PR review.")
    return f"https://github.com/{owner}/{repo}/pull/{pr_number}#pullrequestreview-1"

  # 2. Prepare the review payload
  url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/reviews"
  headers = {
      "Authorization": f"Bearer {token}",
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
  }
  payload = {
      "body": body,
      # COMMENT rather than REQUEST_CHANGES: the Security Gate commit status
      # posted by the aggregate stage is what blocks the merge.
      "event": "COMMENT",
      "comments": comments,
  }
  # Omitting commit_id lets GitHub anchor the review on the PR's latest commit.
  if commit_id:
    payload["commit_id"] = commit_id

  # 3. Submit the review
  resp = requests.post(url, headers=headers, json=payload, timeout=20)

  # A 422 means at least one comment anchors outside the PR diff. This is a
  # permanent failure for this payload, so surface it to the caller as None
  # rather than retrying or raising, allowing a fallback remediation route.
  if resp.status_code == 422:
    logger.warning(
        "GitHub rejected the suggestion review for PR #%d (422): %s",
        pr_number,
        resp.text[:500],
    )
    return None

  if resp.status_code == 403 and any(
      msg in resp.text.lower() for msg in ["rate limit", "abuse detection"]
  ):
    resp.raise_for_status()
  resp.raise_for_status()
  review_url = resp.json().get("html_url")
  logger.info(
      "Successfully posted suggestion review with %d comment(s) on PR #%d: %s",
      len(comments),
      pr_number,
      review_url,
  )
  return review_url


def create_pr_review_with_suggestions(
    token: str,
    owner: str,
    repo: str,
    pr_number: int,
    commit_id: Optional[str],
    body: str,
    comments: List[Dict],
) -> Optional[str]:
  """Safely posts a suggestion review, returning None so callers can fall back."""
  if not comments:
    return None
  try:
    return _create_pr_review_api(
        token=token,
        owner=owner,
        repo=repo,
        pr_number=pr_number,
        commit_id=commit_id,
        body=body,
        comments=comments,
    )
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.warning("Failed to post suggestion review on PR #%d: %s", pr_number, e)
    return None


@retry_on_exception(max_tries=3, initial_delay=3, backoff_factor=2)
def _post_or_update_sticky_comment_api(
    token: str, owner: str, repo: str, pr_number: int, body: str
) -> Optional[str]:
  """Creates or updates the single marker-tagged summary comment on a PR."""
  if _skip_for_dry_run(f"summary comment on pull request #{pr_number}"):
    return None
  # 1. Handle mock token in test suites
  if token == "fake-token":
    logger.info("Mock GitHub token detected ('fake-token'), simulating sticky comment.")
    return f"https://github.com/{owner}/{repo}/issues/{pr_number}#issuecomment-1"

  headers = {
      "Authorization": f"Bearer {token}",
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
  }
  # The marker must survive truncation, or the next run cannot find this
  # comment to update, so it is reserved out of the body's budget.
  marked_body = f"{STICKY_SUMMARY_MARKER}\n" + truncate_comment_body(
      body, reserved=len(STICKY_SUMMARY_MARKER) + 1
  )

  # 2. Search existing PR comments for the sticky marker
  existing_id: Optional[int] = None
  url: Optional[str] = (
      f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments?per_page=100"
  )
  with requests.Session() as session:
    while url and existing_id is None:
      resp = session.get(url, headers=headers, timeout=15)
      resp.raise_for_status()
      comments = resp.json()
      if not isinstance(comments, list):
        break
      for comment in comments:
        if STICKY_SUMMARY_MARKER in (comment.get("body") or ""):
          existing_id = comment.get("id")
          break
      url = resp.links.get("next", {}).get("url")

  # 3. Update the existing comment in place, or create a new one
  if existing_id is not None:
    patch_url = (
        f"https://api.github.com/repos/{owner}/{repo}/issues/comments/{existing_id}"
    )
    resp = requests.patch(
        patch_url, headers=headers, json={"body": marked_body}, timeout=15
    )
  else:
    post_url = (
        f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"
    )
    resp = requests.post(
        post_url, headers=headers, json={"body": marked_body}, timeout=15
    )

  if resp.status_code == 403 and any(
      msg in resp.text.lower() for msg in ["rate limit", "abuse detection"]
  ):
    resp.raise_for_status()
  resp.raise_for_status()
  comment_url = resp.json().get("html_url")
  logger.info(
      "Successfully %s sticky summary comment on PR #%d: %s",
      "updated" if existing_id is not None else "posted",
      pr_number,
      comment_url,
  )
  return comment_url


def post_or_update_sticky_comment(
    token: str, owner: str, repo: str, pr_number: int, body: str
) -> Optional[str]:
  """Safely posts or updates the sticky summary comment, never raising."""
  try:
    return _post_or_update_sticky_comment_api(token, owner, repo, pr_number, body)
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.warning(
        "Failed to post sticky summary comment on PR #%d: %s", pr_number, e
    )
    return None


def list_reviewed_finding_ids(
    token: str, owner: str, repo: str, pr_number: int
) -> Set[str]:
  """Collects finding IDs already carrying a posted inline suggestion.

  Suggestion mode pushes no remote branch, so the remote-branch duplicate check
  used by Child PR mode cannot apply. The marker embedded in each suggestion
  comment provides the equivalent idempotency signal across re-runs.
  Always empty in a dry run, which skips remote duplicate checks.
  """
  if _skip_for_dry_run(f"existing suggestion lookup on pull request #{pr_number}"):
    return set()
  if token == "fake-token":
    return set()

  headers = {
      "Authorization": f"Bearer {token}",
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
  }
  marker_re = re.compile(re.escape(FINDING_MARKER_PREFIX) + r"([^\s]+) -->")
  finding_ids: Set[str] = set()

  try:
    url: Optional[str] = (
        f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/comments?per_page=100"
    )
    with requests.Session() as session:
      while url:
        resp = session.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        comments = resp.json()
        if not isinstance(comments, list):
          break
        for comment in comments:
          for match in marker_re.finditer(comment.get("body") or ""):
            finding_ids.add(match.group(1))
        url = resp.links.get("next", {}).get("url")
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.warning(
        "Failed to list existing suggestion comments on PR #%d (%s); duplicate"
        " suggestions may be posted.",
        pr_number,
        e,
    )
    return set()

  return finding_ids


def _sarif_payload(
    sarif_path: str, commit_sha: str, ref: str
) -> Optional[Dict[str, Any]]:
  """Builds the gzip+base64 payload the GitHub Code Scanning API expects."""
  try:
    with open(sarif_path, "rb") as fh:
      raw = fh.read()
  except OSError as e:
    logger.warning("Could not read SARIF file %s: %s", sarif_path, e)
    return None

  encoded = base64.b64encode(gzip.compress(raw)).decode("ascii")
  return {
      "commit_sha": commit_sha,
      "ref": ref,
      "sarif": encoded,
      "tool_name": "CodeMender",
  }


def upload_sarif_to_code_scanning(
    token: str,
    owner: str,
    repo: str,
    sarif_path: str,
    commit_sha: str,
    ref: str,
    checkout_uri: Optional[str] = None,
) -> Optional[str]:
  """Uploads a SARIF report to GitHub Code Scanning."""
  if _skip_for_dry_run(f"SARIF upload for {owner}/{repo}"):
    return None
  if token == "fake-token":
    logger.info(
        "Mock GitHub token detected ('fake-token'), simulating SARIF upload."
    )
    return "mock-sarif-id"

  payload = _sarif_payload(sarif_path, commit_sha, ref)
  if payload is None:
    return None
  if checkout_uri:
    payload["checkout_uri"] = checkout_uri

  headers = {
      "Authorization": f"Bearer {token}",
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
  }
  url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/sarifs"
  try:
    resp = requests.post(url, headers=headers, json=payload, timeout=60)
    if resp.status_code == 202:
      sarif_id = ""
      try:
        sarif_id = (resp.json() or {}).get("id", "")
      except ValueError:
        pass
      logger.info(
          "Uploaded SARIF to GitHub code scanning for %s/%s @ %s (id=%s).",
          owner,
          repo,
          commit_sha[:8],
          sarif_id or "unknown",
      )
      return sarif_id or "accepted"
    logger.warning(
        "SARIF upload returned HTTP %d: %s",
        resp.status_code,
        (resp.text or "")[:300],
    )
    return None
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.warning("Failed to upload SARIF to GitHub code scanning: %s", e)
    return None


SEVERITY_RANK: Dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
    "INFORMATIONAL": 0,
}


def is_blocking_severity(severity: str, min_sev: str = "MEDIUM") -> bool:
  """Returns True when `severity` meets or exceeds `min_sev`."""
  return SEVERITY_RANK.get(str(severity or "MEDIUM").strip().upper(), 2) >= (
      SEVERITY_RANK.get(str(min_sev or "MEDIUM").strip().upper(), 2)
  )


def extract_finding_fields(
    finding: Dict[str, Any], repo_dir: str = ""
) -> Dict[str, Any]:
  """Extracts normalized finding fields across PascalCase and snake_case schemas."""
  fid = str(
      finding.get("finding_id")
      or finding.get("FindingID")
      or finding.get("id")
      or ""
  )
  sev = (
      str(finding.get("severity") or finding.get("Severity") or "MEDIUM")
      .strip()
      .upper()
  )
  title = str(
      finding.get("title")
      or finding.get("Title")
      or finding.get("VulnType")
      or finding.get("vulnerability_type")
      or fid
  )
  raw_path = str(finding.get("file_path") or finding.get("FilePath") or "")
  fpath = (
      normalize_repo_relative_path(raw_path, repo_dir=repo_dir)
      if repo_dir
      else normalize_repo_relative_path(raw_path)
  )
  line_no = int(
      finding.get("line_number")
      or finding.get("start_line")
      or finding.get("StartLine")
      or finding.get("line")
      or 1
  )
  end_line = int(
      finding.get("end_line") or finding.get("EndLine") or line_no
  )
  desc = str(
      finding.get("description")
      or finding.get("Description")
      or finding.get("Analysis")
      or finding.get("analysis")
      or ""
  )
  return {
      "finding_id": fid,
      "severity": sev,
      "title": title,
      "file_path": fpath,
      "line_number": max(1, line_no),
      "end_line": max(line_no, end_line),
      "description": desc,
  }


def _github_api_headers(token: str) -> Dict[str, str]:
  """Builds standard GitHub REST API request headers."""
  return {
      "Authorization": f"Bearer {token}",
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
  }


def _find_sticky_comment(
    token: str, owner: str, repo: str, pr_number: int
) -> Optional[Dict[str, Any]]:
  """Fetches the existing sticky summary comment on a PR if present."""
  list_url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments?per_page=100"
  resp = requests.get(list_url, headers=_github_api_headers(token), timeout=15)
  resp.raise_for_status()
  comments = resp.json()
  if not isinstance(comments, list):
    return None
  return next(
      (
          c
          for c in comments
          if isinstance(c, dict)
          and STICKY_SUMMARY_MARKER in str(c.get("body") or "")
      ),
      None,
  )


def update_finding_in_sticky_comment(
    token: str,
    owner: str,
    repo: str,
    pr_number: int,
    finding: Dict,
    status_cell_md: str,
    min_sev: str = "MEDIUM",
    max_retries: int = 5,
    fail_on_findings: Optional[bool] = None,
) -> bool:
  """Updates a single finding's row in the sticky PR comment with optimistic concurrency retries."""
  if _skip_for_dry_run(f"sticky comment row update on pull request #{pr_number}"):
    return False
  if not (token and owner and repo and pr_number):
    return False
  if token == "fake-token":
    return True

  fields = extract_finding_fields(finding)
  fid = fields["finding_id"][:8]
  if not fid:
    return False

  sev = fields["severity"]
  title = fields["title"]
  fpath = fields["file_path"]
  line_no = fields["line_number"]
  is_blocking = is_blocking_severity(sev, min_sev)
  headers = _github_api_headers(token)

  for attempt in range(max_retries):
    try:
      sticky = _find_sticky_comment(token, owner, repo, pr_number)
      if not sticky:
        return False

      comment_id = sticky["id"]
      get_url = f"https://api.github.com/repos/{owner}/{repo}/issues/comments/{comment_id}"
      c_resp = requests.get(get_url, headers=headers, timeout=15)
      c_resp.raise_for_status()
      body = str(c_resp.json().get("body") or "")

      row_pattern = re.compile(
          rf"^\|[^\n]*<!-- cm-row:{re.escape(fid)} -->\s*$", re.MULTILINE
      )
      match_row = row_pattern.search(body)
      if not match_row:
        return False

      effective_fail = fail_on_findings
      if effective_fail is None:
        effective_fail = (
            "PASSED (Non-Blocking Mode)" not in body
            and "⚠️ **Non-Blocking**" not in match_row.group(0)
        )
      blocking_label = (
          "🚫 **BLOCKING**" if effective_fail else "⚠️ **Non-Blocking**"
      )
      gate_badge = (
          "⚪ Dismissed (FP)"
          if "Dismissed" in status_cell_md
          else (blocking_label if is_blocking else "ℹ️ Advisory")
      )
      new_row = (
          f"| `{sev}` | {gate_badge} | **{title}** (`{fid}`) | `{fpath}:{line_no}`"
          f" | {status_cell_md} | <!-- cm-row:{fid} -->"
      )
      updated_body = row_pattern.sub(new_row, body)

      all_rows = re.findall(
          r"^\|[^\n]*<!-- cm-row:[a-zA-Z0-9_-]+ -->", updated_body, re.MULTILINE
      )
      total_f = len(all_rows)
      done_f = sum(
          1
          for r in all_rows
          if ("✅" in r or "⚪" in r or "⚠️" in r)
          and "⏳" not in r
          and "🔨" not in r
      )
      if total_f > 0:
        if done_f == total_f:
          updated_body = re.sub(
              r"\*(?:⏳|🔄|✅)\s*(?:\*\*)?Stage [12][^\n]*\*",
              f"*✅ **Stage 2 Complete: {done_f}/{total_f} Findings Processed** (`cm verify` + `cm fix` finished)*",
              updated_body,
          )
        else:
          updated_body = re.sub(
              r"\*(?:⏳|🔄|✅)\s*(?:\*\*)?Stage [12][^\n]*\*",
              f"*🔄 **Stage 2 In Progress: {done_f}/{total_f} Findings Processed** (`cm verify` & `cm fix` running in parallel)*",
              updated_body,
          )

      patch_resp = requests.patch(
          get_url, headers=headers, json={"body": updated_body}, timeout=15
      )
      patch_resp.raise_for_status()
      return True
    except Exception as exc:  # pylint: disable=broad-exception-caught
      logger.warning(
          "Retrying sticky comment update for %s (attempt %d/%d): %s",
          fid,
          attempt + 1,
          max_retries,
          exc,
      )
      time.sleep(0.2 * (attempt + 1) + random.uniform(0.05, 0.25))
  return False


def resolve_sticky_comment_if_present(
    token: str,
    owner: str,
    repo: str,
    pr_number: int,
    target_sha: str,
    min_sev: str = "MEDIUM",
) -> bool:
  """Transitions an existing sticky comment on the PR to All Findings Resolved when 0 active findings remain."""
  if _skip_for_dry_run(f"sticky comment resolution on pull request #{pr_number}"):
    return False
  if not (token and owner and repo and pr_number):
    return False
  if token == "fake-token":
    return True

  try:
    existing = _find_sticky_comment(token, owner, repo, pr_number)
    if not existing:
      return False
    existing_body = str(existing.get("body") or "")
    if "✅ **All Findings Resolved**" in existing_body and (
        not target_sha or target_sha[:8] in existing_body
    ):
      return True

    resolved_body = (
        f"{STICKY_SUMMARY_MARKER}\n"
        "## 🛡️ CodeMender Pre-Submit Security Gate — ✅ **All Findings Resolved**\n\n"
        f"**Gate Status:** ✅ **PASSED** (`0` active vulnerabilities `>= {min_sev}` in current PR diff at commit `{target_sha[:8]}`)\n\n"
        "All previously reported security findings in this Pull Request have been remediated or removed from the modified files.\n"
    )
    patch_url = f"https://api.github.com/repos/{owner}/{repo}/issues/comments/{existing['id']}"
    patch_resp = requests.patch(
        patch_url,
        headers=_github_api_headers(token),
        json={"body": resolved_body},
        timeout=15,
    )
    patch_resp.raise_for_status()
    return True
  except Exception as exc:  # pylint: disable=broad-exception-caught
    logger.warning(
        "Failed to resolve existing sticky comment on PR #%d: %s",
        pr_number,
        exc,
    )
    return False


def post_idempotent_inline_review(
    token: str,
    owner: str,
    repo: str,
    pr_number: int,
    target_sha: str,
    finding: Dict,
    patch_diff: str,
    existing_inline_urls: Optional[Dict[str, str]] = None,
    repo_dir: str = "",
) -> str:
  """Posts an idempotent inline GitHub PR review suggestion for a verified finding.

  Embeds `<!-- cm-inline:{fpath}:{line_no}:{title} -->` (plus `finding_marker`
  for compatibility with `list_reviewed_finding_ids`) and checks existing PR
  review comments before posting so subsequent commits never duplicate reviews.
  """
  if _skip_for_dry_run(f"inline suggestion review on pull request #{pr_number}"):
    return ""
  if not (token and owner and repo and pr_number):
    return ""

  fields = extract_finding_fields(finding)
  fid = fields["finding_id"]
  sev = fields["severity"]
  title = fields["title"]
  fpath = fields["file_path"]
  line_no = fields["line_number"]
  desc = fields["description"]
  if not fpath:
    return ""

  cache = existing_inline_urls if existing_inline_urls is not None else {}
  if not cache and token != "fake-token":
    try:
      c_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/comments?per_page=100"
      c_resp = requests.get(
          c_url, headers=_github_api_headers(token), timeout=15
      )
      if c_resp.status_code == 200 and isinstance(c_resp.json(), list):
        for rc in c_resp.json():
          rc_body = str(rc.get("body") or "")
          rc_url = str(rc.get("html_url") or "")
          for m in re.findall(
              r"<!-- (?:cm-inline|codemender-finding):[^>]+ -->", rc_body
          ):
            if not patch_diff or "```suggestion" in rc_body:
              cache[m] = rc_url
    except Exception:  # pylint: disable=broad-exception-caught
      pass

  inline_marker = f"<!-- cm-inline:{fpath}:{line_no}:{title} -->"
  f_marker = finding_marker(fid) if fid else ""
  if inline_marker in cache:
    return cache[inline_marker]
  if f_marker and f_marker in cache:
    return cache[f_marker]

  marker_prefix = (
      f"{inline_marker}\n{f_marker}\n" if f_marker else f"{inline_marker}\n"
  )
  header_md = (
      f"{marker_prefix}"
      f"### 🛡️ CodeMender Security Finding (`{sev}`)\n"
      f"**{title}** (`{fid[:8]}`)\n\n"
      f"{desc}"
  )
  review_comments = parse_diff_hunks_to_review_comments(
      patch_diff, fpath, header_md, fallback_line=line_no, repo_dir=repo_dir
  )
  review_body = (
      f"🛡️ **CodeMender Automated Remediation** generated an inline fix for"
      f" **{title}** (`{sev}`) in `{fpath}`."
  )
  review_url = create_pr_review_with_suggestions(
      token=token,
      owner=owner,
      repo=repo,
      pr_number=pr_number,
      commit_id=target_sha,
      body=review_body,
      comments=review_comments,
  ) or ""
  if review_url:
    cache[inline_marker] = review_url
    if f_marker:
      cache[f_marker] = review_url
  return review_url

