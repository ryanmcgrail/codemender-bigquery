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

"""Git URL and repository manipulation utilities for CodeMender Agent."""

import base64
from dataclasses import dataclass
import hashlib
import logging
import os
import re
import shutil
from typing import Any, Callable, List, Optional, Tuple

from codemender_agent.utils import is_dry_run, retry_on_exception

logger = logging.getLogger("codemender-orchestrator")


def normalize_repo_relative_path(path: str, repo_dir: Optional[str] = None) -> str:
  """Normalizes a file path to be strictly repository-relative with forward slashes and no leading './'."""
  if not path:
    return ""
  p = path.strip().replace("\\", "/")
  if repo_dir:
    clean_repo_dir = os.path.abspath(repo_dir).replace("\\", "/")
    if p == clean_repo_dir:
      return ""
    if p.startswith(clean_repo_dir + "/"):
      p = p[len(clean_repo_dir) + 1 :]
    elif os.path.isabs(p):
      try:
        rel = os.path.relpath(p, clean_repo_dir).replace("\\", "/")
        if not rel.startswith("../") and rel != "..":
          p = rel
      except ValueError:
        pass

  # Strip leading CI runner mount patterns if present (e.g. /__w/<owner>/<repo>/... or /github/workspace/...)
  p = re.sub(r"^/?__w/[^/]+/[^/]+(?:/[^/]+)?/", "", p)
  p = re.sub(r"^/?github/workspace/", "", p)

  # Strip any leading slashes, dots, or relative traversal markers
  p = re.sub(r"^(\.\./)+", "", p)
  p = re.sub(r"^\.?/+", "", p)
  return p


def compute_finding_fingerprint(
    file_path: str, vuln_type: str, start_line: int
) -> str:
  """Computes a deterministic 8-character SHA256 fingerprint for a finding."""
  norm_path = normalize_repo_relative_path(file_path)
  norm_type = (vuln_type or "vulnerability").strip().lower()
  raw_hash_str = f"{norm_path}|{norm_type}|{start_line}"
  return hashlib.sha256(raw_hash_str.encode("utf-8")).hexdigest()[:8]


def get_finding_branch_name(
    file_path: str, vuln_type: str, start_line: int
) -> str:
  """Generates a canonical branch name for a finding using its deterministic fingerprint."""
  fp = compute_finding_fingerprint(file_path, vuln_type, start_line)
  return generate_branch_name(vuln_type, fp)


def enforce_https_url(url: str) -> str:
  """Converts SSH git URLs to HTTPS format to support token-based authentication."""
  url = url.strip()
  if url.startswith("git@") or url.startswith("ssh://"):
    # Match git@host:owner/repo.git or ssh://git@host/owner/repo.git
    match = re.search(r"(?:ssh://)?git@([^:/]+)[:/](.+)$", url)
    if match:
      host = match.group(1)
      path = match.group(2)
      return f"https://{host}/{path}"
  return url


def sanitize_git_url(url: str) -> str:
  """Removes embedded credentials and query parameters from Git URLs."""
  # Enforce HTTPS format
  cleaned = enforce_https_url(url)
  # Strip username/password credentials
  cleaned = re.sub(r"(https?://)[^@]+@", r"\1", cleaned)
  # Strip query parameters or fragment identifiers (?branch=main or #readme)
  cleaned = cleaned.split("?")[0].split("#")[0].strip()
  return cleaned


def get_git_auth_header(token: str) -> str:
  """Generates a Basic authentication header value for GitHub Git transactions."""
  auth_str = f"x-access-token:{token}"
  auth_b64 = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
  return f"http.extraheader=AUTHORIZATION: Basic {auth_b64}"


def parse_repo_owner_and_name(repo_url: str) -> Tuple[str, str]:
  """Extracts (owner, repo_name) from a GitHub repository URL."""
  clean_url = sanitize_git_url(repo_url).rstrip("/")
  if clean_url.endswith(".git"):
    clean_url = clean_url[:-4]

  match = re.search(r"[:/]([^/]+)/([^/]+)$", clean_url)
  if match:
    return match.group(1), match.group(2)
  raise ValueError(f"Could not parse owner and repo name from URL: {repo_url}")


def generate_branch_name(vuln_type: str, fingerprint: str) -> str:
  """Generates a stable, idempotent Git branch name based on VulnType and Fingerprint hash."""
  vuln_clean = re.sub(
      r"[^a-zA-Z0-9\-_]", "-", (vuln_type or "vuln").strip().lower()
  )
  suffix = fingerprint[:8]
  return f"codemender/fix-{vuln_clean}-{suffix}"


# Commit author/committer identity for the fix commits.
#
# Resolution order:
#   1. CODEMENDER_GIT_AUTHOR_EMAIL, with CODEMENDER_GIT_AUTHOR_NAME or else
#      DEFAULT_GIT_AUTHOR_NAME. GitHub attributes a commit by its email alone,
#      so a configured email is never paired with the App bot's name.
#   2. With GitHub App authentication (GITHUB_APP_ID and
#      GITHUB_APP_PRIVATE_KEY), the App's bot account, so the commits show as
#      made by the App, like the pushes and pull requests.
#      CODEMENDER_GIT_AUTHOR_NAME, if set, still replaces the bot's name.
#   3. DEFAULT_GIT_AUTHOR_NAME / DEFAULT_GIT_AUTHOR_EMAIL, again with the name
#      override if set. The address uses the reserved `.invalid` top-level
#      domain (RFC 2606): nobody can verify it on GitHub, so the commits are
#      never linked to an unrelated account. A
#      `<name>@users.noreply.github.com` address would be, because GitHub still
#      attributes that older noreply form to the account called `<name>`.
GIT_AUTHOR_NAME_ENV_VAR = "CODEMENDER_GIT_AUTHOR_NAME"
GIT_AUTHOR_EMAIL_ENV_VAR = "CODEMENDER_GIT_AUTHOR_EMAIL"
DEFAULT_GIT_AUTHOR_NAME = "CodeMender Agent"
DEFAULT_GIT_AUTHOR_EMAIL = "codemender-agent@noreply.invalid"

# Characters git cannot store in an identity (it strips angle brackets and
# rejects line breaks), so such an override is ignored instead.
_INVALID_IDENTITY_CHARS = ("<", ">", "\n", "\r", "\0")


def _identity_override(var: str, is_email: bool = False) -> str:
  """Returns the env override for one identity field, or "" if unusable."""
  value = (os.environ.get(var) or "").strip()
  if value and (
      any(ch in value for ch in _INVALID_IDENTITY_CHARS)
      or (is_email and any(ch.isspace() for ch in value))
  ):
    logger.warning(
        "Ignoring %s: it must not contain '<', '>' or line breaks%s.",
        var,
        " (or any whitespace)" if is_email else "",
    )
    return ""
  return value


def resolve_git_identity(token: Optional[str] = None) -> Tuple[str, str]:
  """Returns the (name, email) to author and commit fixes with.

  See the resolution order above. Never raises: a GitHub App lookup failure
  falls back to the default identity.

  Args:
    token: The GitHub token in use, passed on to the App bot lookup.
  """
  name = _identity_override(GIT_AUTHOR_NAME_ENV_VAR)
  email = _identity_override(GIT_AUTHOR_EMAIL_ENV_VAR, is_email=True)
  if email:
    # GitHub links a commit to an account by its email alone, so a configured
    # email decides who the commit belongs to. Pairing it with the App bot's
    # name would mislabel the commit, and the lookup is not needed.
    return name or DEFAULT_GIT_AUTHOR_NAME, email

  default = (DEFAULT_GIT_AUTHOR_NAME, DEFAULT_GIT_AUTHOR_EMAIL)
  app_id = (os.environ.get("GITHUB_APP_ID") or "").strip()
  private_key = (os.environ.get("GITHUB_APP_PRIVATE_KEY") or "").strip()
  if app_id and private_key:
    # pylint: disable=g-import-not-at-top
    from codemender_agent.vcs import github_app
    # pylint: enable=g-import-not-at-top

    try:
      credentials = github_app.GitHubAppCredentials.from_values(
          app_id, private_key, os.environ.get("GITHUB_APP_INSTALLATION_ID")
      )
      default = github_app.get_app_bot_identity(credentials, token) or default
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.warning(
          "Could not resolve the GitHub App bot identity (%s); using the"
          " default git identity.",
          type(e).__name__,
      )
  return name or default[0], default[1]


def configure_git_identity(
    repo_dir: str,
    token: Optional[str] = None,
    run: Optional[Callable[..., Any]] = None,
) -> Tuple[str, str]:
  """Sets the repository-local user.name and user.email for fix commits.

  Args:
    repo_dir: The repository to configure.
    token: The GitHub token in use, passed on to the App bot lookup.
    run: The caller's `run_command`, so tests that patch it see both calls.

  Returns:
    The (name, email) that was configured.
  """
  if run is None:
    from codemender_agent.utils import run_command as run  # pylint: disable=g-import-not-at-top

  name, email = resolve_git_identity(token)
  run(["git", "config", "user.name", name], cwd=repo_dir)
  run(["git", "config", "user.email", email], cwd=repo_dir)
  logger.info("Fix commits are authored as: %s <%s>", name, email)
  return name, email




def clean_workspace(repo_dir: str, exclude_dirs: Optional[Tuple[str, ...]] = None) -> None:
  """Resets working directory and cleans untracked files while preserving CLI metadata directories."""
  if exclude_dirs is None:
    exclude_dirs = (".cm_project", ".exploit", ".codemender_cache")

  cmd = ["git", "clean", "-fd"]
  for ex in exclude_dirs:
    cmd.extend(["-e", ex])

  from codemender_agent.utils import run_command
  run_command(cmd, cwd=repo_dir, check=False)


def setup_local_git_excludes(repo_dir: str) -> None:
  """Appends CodeMender metadata paths to local git excludes to prevent staging them."""
  exclude_path = os.path.join(repo_dir, ".git", "info", "exclude")
  try:
    os.makedirs(os.path.dirname(exclude_path), exist_ok=True)
    # Read existing excludes to prevent duplicates
    existing_content = ""
    if os.path.exists(exclude_path):
      with open(exclude_path, "r") as f:
        existing_content = f.read()

    new_entries = []
    for entry in [".cm_project", ".exploit", ".codemender_cache"]:
      if entry not in existing_content:
        new_entries.append(entry)

    if new_entries:
      with open(exclude_path, "a") as f:
        if existing_content and not existing_content.endswith("\n"):
          f.write("\n")
        f.write("\n".join(new_entries) + "\n")
      logger.info("Successfully added local git excludes: %s", new_entries)
  except Exception as e:
    logger.warning("Failed to configure local git excludes: %s", e)


IGNORED_METADATA_DIRS = (
    ".cm_project",
    ".exploit",
    ".codemender_cache",
    ".codemender",
    ".git",
)


def filter_stageable_files(
    repo_dir: str,
    file_paths: Any,
) -> List[str]:
  """Filters, normalizes, deduplicates, and validates paths for git staging.

  Excludes non-existent files, internal CodeMender metadata paths (.exploit, .cm_project,
  .codemender_cache, .codemender, .git), and files ignored by .gitignore or git excludes.
  """
  if not file_paths:
    return []

  if isinstance(file_paths, str):
    raw_list = [file_paths]
  elif isinstance(file_paths, (list, tuple, set)):
    raw_list = list(file_paths)
  else:
    return []

  candidates: List[str] = []
  seen = set()

  for item in raw_list:
    if not item or not isinstance(item, str):
      continue
    # Normalize to strictly repo-relative forward-slash path
    norm_path = normalize_repo_relative_path(item, repo_dir=repo_dir)
    if not norm_path:
      continue

    # Exclude internal metadata directories
    parts = norm_path.split("/")
    if any(part in IGNORED_METADATA_DIRS for part in parts):
      continue

    # Ensure path exists in repository working tree
    full_path = os.path.join(repo_dir, norm_path)
    if not os.path.exists(full_path):
      continue

    if norm_path not in seen:
      seen.add(norm_path)
      candidates.append(norm_path)

  if not candidates:
    return []

  # Check against git ignore rules (.gitignore and .git/info/exclude)
  from codemender_agent.utils import run_command

  try:
    check_res = run_command(
        ["git", "check-ignore", "--"] + candidates,
        cwd=repo_dir,
        check=False,
    )
    if check_res.returncode == 0 and check_res.stdout:
      ignored_paths = set(check_res.stdout.splitlines())
      candidates = [p for p in candidates if p not in ignored_paths]
  except Exception as e:
    logger.warning("git check-ignore query failed: %s", e)

  return candidates


def sanitize_exploit_and_artifacts(
    repo_dir: str, codemender_home: Optional[str] = None
) -> None:
  """Prunes heavy non-reproduction build caches from .exploit/ and ~/.codemender/artifacts/."""
  junk_dirs = {
      ".cache",
      "node_modules",
      ".npm",
      ".node-gyp",
      ".tmp",
      "tmp",
      "venv",
      ".venv",
      "__pycache__",
      ".pytest_cache",
  }

  # 1. Clean repo_dir/.exploit/
  exploit_dir = os.path.join(repo_dir, ".exploit")
  if os.path.isdir(exploit_dir):
    try:
      for entry in os.listdir(exploit_dir):
        entry_path = os.path.join(exploit_dir, entry)
        if os.path.isdir(entry_path) and entry in junk_dirs:
          shutil.rmtree(entry_path, ignore_errors=True)
          logger.info("Sanitized junk build cache directory: %s", entry_path)
    except Exception as e:
      logger.warning("Failed to sanitize .exploit directory: %s", e)

  # 2. Clean ~/.codemender/artifacts/
  cm_home = codemender_home or os.path.expanduser("~/.codemender")
  artifacts_dir = os.path.join(cm_home, "artifacts")
  if os.path.isdir(artifacts_dir):
    try:
      for root, dirs, _ in os.walk(artifacts_dir, topdown=True):
        for d in list(dirs):
          if d in junk_dirs:
            target_path = os.path.join(root, d)
            shutil.rmtree(target_path, ignore_errors=True)
            dirs.remove(d)
            logger.info("Sanitized artifact build cache directory: %s", target_path)
    except Exception as e:
      logger.warning("Failed to sanitize artifacts directory: %s", e)



def get_pr_changed_lines(repo_dir: str, base_ref: str) -> Optional[dict[str, set[int]]]:
  """Parses Unified Diff hunks to extract modified line numbers per file.

  Runs 'git diff -U0 origin/<base_ref>...HEAD' (falling back to '<base_ref>...HEAD' or 'origin/<base_ref>')
  and parses the diff hunk headers (@@ -old_start,old_count +new_start,new_count @@).

  Returns:
    Dict mapping repository-relative file paths to sets of 1-based modified line numbers,
    or None if git diff execution failed across all candidate targets.
  """
  from codemender_agent.utils import run_command

  clean_base = base_ref.strip()
  if clean_base.startswith("refs/heads/"):
    clean_base = clean_base[11:]

  diff_targets = [
      f"origin/{clean_base}...HEAD",
      f"{clean_base}...HEAD",
      f"origin/{clean_base}",
      clean_base,
  ]
  diff_output: Optional[str] = None
  for target in diff_targets:
    try:
      res = run_command(
          ["git", "diff", "-U0", target], cwd=repo_dir, check=False
      )
      if res.returncode == 0:
        diff_output = res.stdout
        break
    except Exception:  # pylint: disable=broad-exception-caught
      pass

  if diff_output is None:
    return None

  changed_lines: dict[str, set[int]] = {}
  if not diff_output:
    return changed_lines

  current_file: Optional[str] = None
  for line in diff_output.splitlines():
    if line.startswith("+++ b/"):
      current_file = normalize_repo_relative_path(line[6:].strip())
      if current_file and current_file not in changed_lines:
        changed_lines[current_file] = set()
    elif line.startswith("+++ /dev/null"):
      current_file = None
    elif line.startswith("@@ ") and current_file:
      # Parse hunk header: @@ -old_start,old_count +new_start,new_count @@
      # or @@ -old_start +new_start @@
      match = re.search(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", line)
      if match:
        new_start = int(match.group(1))
        new_count = int(match.group(2)) if match.group(2) is not None else 1
        if new_count == 0:
          changed_lines[current_file].add(new_start)
        else:
          for l in range(new_start, new_start + new_count):
            changed_lines[current_file].add(l)

  return changed_lines


@dataclass(frozen=True)
class SuggestionHunk:
  """A contiguous RIGHT-side line range replaceable by a GitHub suggestion block."""

  path: str
  start_line: int
  end_line: int
  replacement_lines: List[str]


_HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_DIFF_GIT_RE = re.compile(r"^diff --git a/(.+?) b/(.+)$")


def _read_head_file_lines(repo_dir: str, path: str) -> Optional[List[str]]:
  """Reads a file's contents at HEAD (the PR head commit), bypassing the mutated working tree."""
  if not repo_dir:
    return None
  from codemender_agent.utils import run_command

  try:
    res = run_command(
        ["git", "show", f"HEAD:{path}"], cwd=repo_dir, check=False
    )
    if res.returncode != 0:
      return None
    lines = res.stdout.split("\n")
    # Drop the trailing empty element produced by a final newline
    if lines and lines[-1] == "":
      lines.pop()
    return lines
  except Exception:  # pylint: disable=broad-exception-caught
    return None


def _build_suggestion_hunk(
    repo_dir: str,
    path: str,
    old_start: int,
    old_count: int,
    body: List[str],
    head_cache: dict,
) -> Tuple[Optional[SuggestionHunk], Optional[str]]:
  """Converts one unified-diff hunk body into a suggestion anchor plus replacement text.

  Returns:
    (hunk, None) on success, (None, None) when the hunk contains no changes, or
    (None, reason) when the hunk cannot be expressed as a GitHub suggestion.
  """
  change_indices = [k for k, b in enumerate(body) if b[:1] in ("+", "-")]
  if not change_indices:
    # Context-only hunk: nothing to suggest.
    return None, None

  first, last = change_indices[0], change_indices[-1]
  window = body[first : last + 1]

  # Trim surrounding context so the anchor range stays as narrow as possible,
  # which maximizes the chance it falls inside the Pull Request's diff hunks.
  leading_old = sum(1 for b in body[:first] if b[:1] in (" ", "-"))
  consumed_old = sum(1 for b in window if b[:1] in (" ", "-"))
  replacement = [b[1:] for b in window if b[:1] in (" ", "+")]
  anchor_start = old_start + leading_old

  # Standard case: the hunk replaces one or more existing lines.
  if consumed_old > 0:
    return (
        SuggestionHunk(
            path=path,
            start_line=anchor_start,
            end_line=anchor_start + consumed_old - 1,
            replacement_lines=replacement,
        ),
        None,
    )

  # Pure insertion: no existing lines are consumed, so resolve which old line
  # the new content is inserted in front of. Git's zero-length range form
  # (`@@ -5,0 +6,2 @@`) anchors *after* line 5; a context-bearing hunk whose
  # change window is insert-only inserts *before* the computed anchor line.
  insert_before = (old_start + 1) if old_count == 0 else anchor_start

  if path not in head_cache:
    head_cache[path] = _read_head_file_lines(repo_dir, path)
  head_lines = head_cache[path]

  # Prefer anchoring on the preceding line so the insertion reads naturally.
  preceding = insert_before - 1
  if head_lines:
    if 1 <= preceding <= len(head_lines):
      return (
          SuggestionHunk(
              path=path,
              start_line=preceding,
              end_line=preceding,
              replacement_lines=[head_lines[preceding - 1]] + replacement,
          ),
          None,
      )

    # Insertion at the very top of the file: anchor the following line instead.
    if 1 <= insert_before <= len(head_lines):
      return (
          SuggestionHunk(
              path=path,
              start_line=insert_before,
              end_line=insert_before,
              replacement_lines=replacement + [head_lines[insert_before - 1]],
          ),
          None,
      )

    return None, f"cannot anchor an insertion in '{path}'"

  # Fallback when HEAD is unavailable (e.g. standalone diff with context lines):
  # extract the adjacent anchor line directly from the hunk's context lines so
  # pure insertions still preserve the existing line instead of overwriting it.
  if first > 0 and body[first - 1][:1] == " " and preceding >= 1:
    return (
        SuggestionHunk(
            path=path,
            start_line=preceding,
            end_line=preceding,
            replacement_lines=[body[first - 1][1:]] + replacement,
        ),
        None,
    )
  if (
      last + 1 < len(body)
      and body[last + 1][:1] == " "
      and insert_before >= 1
  ):
    return (
        SuggestionHunk(
            path=path,
            start_line=insert_before,
            end_line=insert_before,
            replacement_lines=replacement + [body[last + 1][1:]],
        ),
        None,
    )

  return None, f"cannot read '{path}' at HEAD to anchor an insertion"


def parse_patch_to_suggestions(
    repo_dir: str, patch_diff: str, default_relpath: str = ""
) -> Tuple[List[SuggestionHunk], List[str]]:
  """Converts a unified diff produced against HEAD into GitHub suggestion hunks.

  The patch is generated by `git diff HEAD` where HEAD is the Pull Request head
  commit, so the diff's OLD side corresponds to the RIGHT side of the Pull
  Request's own diff. Suggestion anchors are therefore derived from the old
  line numbers.

  Returns:
    A tuple of (hunks, blockers). A non-empty `blockers` list means the patch
    cannot be fully represented as suggestions and the caller must fall back.
  """
  hunks: List[SuggestionHunk] = []
  blockers: List[str] = []

  if not patch_diff or not patch_diff.strip():
    return hunks, ["patch is empty"]

  lines = patch_diff.splitlines()
  head_cache: dict = {}
  current_path: Optional[str] = (
      normalize_repo_relative_path(default_relpath)
      if default_relpath
      else None
  )
  file_blocked = False
  i = 0

  while i < len(lines):
    line = lines[i]

    # 1. File header: resolve the target path and reset per-file state
    file_match = _DIFF_GIT_RE.match(line)
    if file_match:
      old_path, new_path = file_match.group(1), file_match.group(2)
      current_path = normalize_repo_relative_path(new_path)
      file_blocked = False
      if old_path != new_path:
        blockers.append(f"renames '{old_path}' to '{new_path}'")
        file_blocked = True
      i += 1
      continue

    if line.startswith("+++ b/") and not file_blocked:
      current_path = normalize_repo_relative_path(line[6:]) or current_path
      i += 1
      continue

    # 2. Structural markers that cannot be expressed as a suggestion
    label = current_path or "unknown file"
    if line.startswith("new file mode"):
      blockers.append(f"creates a new file '{label}'")
      file_blocked = True
    elif line.startswith("deleted file mode") or line.startswith("+++ /dev/null"):
      blockers.append(f"deletes file '{label}'")
      file_blocked = True
    elif line.startswith("Binary files ") or line.startswith("GIT binary patch"):
      blockers.append(f"contains a binary change to '{label}'")
      file_blocked = True

    # 3. Hunk header: collect the body and convert it
    hunk_match = _HUNK_HEADER_RE.match(line)
    if not hunk_match:
      i += 1
      continue

    old_start = int(hunk_match.group(1))
    old_count = int(hunk_match.group(2)) if hunk_match.group(2) is not None else 1
    body: List[str] = []
    i += 1
    while i < len(lines):
      candidate = lines[i]
      if _HUNK_HEADER_RE.match(candidate) or candidate.startswith("diff --git "):
        break
      # Skip the "\ No newline at end of file" marker
      if candidate.startswith("\\"):
        i += 1
        continue
      if candidate == "":
        body.append(" ")
      elif candidate[0] in " +-":
        body.append(candidate)
      i += 1

    if file_blocked or not current_path:
      continue

    hunk, reason = _build_suggestion_hunk(
        repo_dir, current_path, old_start, old_count, body, head_cache
    )
    if reason:
      blockers.append(reason)
    elif hunk:
      hunks.append(hunk)

  if not hunks and not blockers:
    blockers.append("patch contains no applicable changes")

  return hunks, blockers


@retry_on_exception(max_tries=3, initial_delay=2, backoff_factor=2)
def push_branch_to_remote(
    repo_dir: str,
    token: str,
    branch_name: str,
    force: bool = False,
) -> None:
  """Pushes a local branch to origin with exponential backoff retries.

  Does nothing in a dry run (CODEMENDER_DRY_RUN).
  """
  if is_dry_run():
    logger.info(
        "Dry run (CODEMENDER_DRY_RUN): skipping push of branch %s.", branch_name
    )
    return
  push_cmd = ["git", "-c", get_git_auth_header(token), "push"]
  if force:
    push_cmd.append("-f")
  push_cmd.extend(["origin", branch_name])
  from codemender_agent.utils import run_command
  run_command(push_cmd, cwd=repo_dir, check=True)


def parse_diff_hunks_to_review_comments(
    diff_text: str,
    default_relpath: str,
    header_md: str,
    fallback_line: int = 1,
    repo_dir: str = "",
) -> List[dict]:
  """Parses a unified diff into GitHub PR review suggestion comments anchored on RIGHT.

  Delegates hunk parsing and pure-insertion anchoring to
  `parse_patch_to_suggestions()` and formats comments with
  `format_suggestion_body()` and `build_review_comment()`. Falls back to a raw
  diff block on `fallback_line` if no suggestion hunks can be constructed.
  """
  from codemender_agent.vcs.github import (
      build_review_comment,
      format_suggestion_body,
  )

  hunks, blockers = parse_patch_to_suggestions(
      repo_dir, diff_text or "", default_relpath=default_relpath
  )
  if hunks and not blockers:
    total = len(hunks)
    comments: List[dict] = []
    for index, hunk in enumerate(hunks, start=1):
      part_suffix = f" (part {index} of {total})" if total > 1 else ""
      prefix = f"{header_md}\n\n" if index == 1 else ""
      preamble = (
          f"{prefix}#### 💡 CodeMender One-Click Fix (`cm fix`)\n"
          "Click **Commit suggestion** below to apply this security fix"
          f" directly to the PR{part_suffix}:"
      )
      comments.append(
          build_review_comment(
              path=hunk.path or default_relpath,
              start_line=hunk.start_line,
              end_line=hunk.end_line,
              body=format_suggestion_body(
                  hunk.replacement_lines, preamble=preamble
              ),
          )
      )
    return comments

  body = header_md
  if diff_text and diff_text.strip():
    body += (
        "\n\n#### 💡 Proposed CodeMender Patch (`cm fix`)\n"
        f"```diff\n{diff_text[:4000]}\n```"
    )
  line = max(1, int(fallback_line or 1))
  return [
      build_review_comment(
          path=default_relpath,
          start_line=line,
          end_line=line,
          body=body,
      )
  ]


def find_source_pragma(
    workspace_dir: str,
    relpath: str,
    start_line: int,
    end_line: int,
    pattern: re.Pattern,
) -> Optional[re.Match]:
  """Searches the local line window around a finding and file header for a `# codemender:` pragma."""
  if not (workspace_dir and relpath):
    return None
  full_file = os.path.join(workspace_dir, relpath)
  if not os.path.exists(full_file):
    return None
  try:
    with open(full_file, "r", encoding="utf-8", errors="ignore") as sf:
      src_lines = sf.read().splitlines()
    win_start = max(0, start_line - 8)
    win_end = min(len(src_lines), max(start_line, end_line) + 2)
    match = pattern.search("\n".join(src_lines[win_start:win_end]))
    if match:
      return match
    header_lines = []
    for hl in src_lines[:5]:
      if hl.lstrip().startswith(("def ", "class ")):
        break
      header_lines.append(hl)
    return pattern.search("\n".join(header_lines))
  except Exception:  # pylint: disable=broad-exception-caught
    return None

