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

"""Unit tests for GitHub one-click review suggestion remediation."""

import os
import re
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from codemender_agent.config import (
    PR_MODE_CHILD_PR,
    PR_MODE_REVIEW_SUGGESTION,
    OrchestratorConfig,
    resolve_pr_remediation_mode,
)
from codemender_agent.runners.worker import (
    _build_suggestion_comments,
    _fit_fork_comment,
)
from codemender_agent.vcs.git import parse_patch_to_suggestions
from codemender_agent.vcs.github import (
    FINDING_MARKER_PREFIX,
    MAX_COMMENT_BODY_CHARS,
    STICKY_SUMMARY_MARKER,
    build_review_comment,
    create_pr_review_with_suggestions,
    finding_marker,
    format_suggestion_body,
    get_pr_diff_line_ranges,
    list_reviewed_finding_ids,
    post_or_update_sticky_comment,
    truncate_comment_body,
)


def _git(repo_dir, *args):
  """Runs a git command in the scratch repository."""
  subprocess.run(
      ["git"] + list(args),
      cwd=repo_dir,
      check=True,
      capture_output=True,
      text=True,
  )


def _suggestion_is_top_level(markdown: str) -> bool:
  """Reports whether a ```suggestion fence opens at the document's top level.

  Mirrors CommonMark fence pairing: a fence nested inside an already-open code
  block is inert, so GitHub would render it as text instead of a suggestion.
  """
  open_len = 0
  for line in markdown.split("\n"):
    match = re.match(r"^(`{3,})(.*)$", line)
    if not match:
      continue
    run, info = len(match.group(1)), match.group(2).strip()
    if open_len == 0:
      if info == "suggestion":
        return True
      open_len = run
    elif run >= open_len and not info:
      open_len = 0
  return False


def _fence_left_open(markdown: str) -> bool:
  """Reports whether `markdown` ends with an unterminated code fence."""
  open_len = 0
  for line in markdown.split("\n"):
    match = re.match(r"^(`{3,})(.*)$", line)
    if not match:
      continue
    run, info = len(match.group(1)), match.group(2).strip()
    if open_len == 0:
      open_len = run
    elif run >= open_len and not info:
      open_len = 0
  return open_len != 0




class TestRemediationModeConfig(unittest.TestCase):
  """Validates parsing and fork override of the pr_remediation_mode flag."""

  def test_defaults_to_review_suggestion(self):
    with patch.dict(os.environ, {}, clear=True):
      config = OrchestratorConfig.from_env()
    self.assertEqual(config.pr_remediation_mode, PR_MODE_REVIEW_SUGGESTION)

  def test_parses_child_pr(self):
    with patch.dict(
        os.environ, {"CODEMENDER_PR_REMEDIATION_MODE": "  Child_PR "}, clear=True
    ):
      config = OrchestratorConfig.from_env()
    self.assertEqual(config.pr_remediation_mode, PR_MODE_CHILD_PR)

  def test_unrecognized_value_falls_back_to_review_suggestion(self):
    with patch.dict(
        os.environ, {"CODEMENDER_PR_REMEDIATION_MODE": "carrier_pigeon"}, clear=True
    ):
      config = OrchestratorConfig.from_env()
    self.assertEqual(config.pr_remediation_mode, PR_MODE_REVIEW_SUGGESTION)

  def test_fork_pr_ignores_child_pr_mode(self):
    """Fork PRs cannot receive a pushed branch, so the flag must not apply."""
    config = OrchestratorConfig(
        pr_remediation_mode=PR_MODE_CHILD_PR, is_fork_pr=True
    )
    self.assertEqual(
        resolve_pr_remediation_mode(config), PR_MODE_REVIEW_SUGGESTION
    )

  def test_internal_pr_honors_child_pr_mode(self):
    config = OrchestratorConfig(
        pr_remediation_mode=PR_MODE_CHILD_PR, is_fork_pr=False
    )
    self.assertEqual(resolve_pr_remediation_mode(config), PR_MODE_CHILD_PR)


class TestSuggestionBodyFormatting(unittest.TestCase):
  """Validates fence sizing and anchor payload construction."""

  def test_wraps_replacement_in_suggestion_fence(self):
    body = format_suggestion_body(["  return escape(value)"])
    self.assertEqual(body, "```suggestion\n  return escape(value)\n```")

  def test_widens_fence_past_embedded_backticks(self):
    body = format_suggestion_body(['q = "```"'])
    self.assertTrue(body.startswith("````suggestion\n"))
    self.assertTrue(body.endswith("\n````"))

  def test_empty_replacement_renders_deletion_block(self):
    self.assertEqual(format_suggestion_body([]), "```suggestion\n```")

  def test_preamble_precedes_block(self):
    body = format_suggestion_body(["x = 1"], preamble="Heads up")
    self.assertEqual(body, "Heads up\n\n```suggestion\nx = 1\n```")

  def test_unterminated_preamble_fence_is_closed(self):
    """An open fence in the analysis would otherwise swallow the suggestion."""
    body = format_suggestion_body(
        ["safe(x)"], preamble="Vulnerable:\n```python\neval(user_input)"
    )
    self.assertTrue(_suggestion_is_top_level(body), body)

  def test_balanced_preamble_fence_is_left_alone(self):
    preamble = "Vulnerable:\n```python\neval(x)\n```\nUse literal_eval."
    body = format_suggestion_body(["safe(x)"], preamble=preamble)
    self.assertTrue(body.startswith(preamble + "\n\n"))
    self.assertTrue(_suggestion_is_top_level(body), body)


  def test_single_line_anchor_omits_start_line(self):
    comment = build_review_comment("a.py", 7, 7, "body")
    self.assertEqual(comment["line"], 7)
    self.assertEqual(comment["side"], "RIGHT")
    self.assertNotIn("start_line", comment)

  def test_multi_line_anchor_includes_start_line(self):
    comment = build_review_comment("a.py", 7, 9, "body")
    self.assertEqual(comment["start_line"], 7)
    self.assertEqual(comment["start_side"], "RIGHT")
    self.assertEqual(comment["line"], 9)


class TestPrDiffLineRanges(unittest.TestCase):
  """Validates discovery of the lines GitHub will accept as review anchors."""

  @patch("codemender_agent.vcs.github._fetch_pr_files")
  def test_expands_hunk_headers_into_line_numbers(self, mock_fetch):
    mock_fetch.return_value = [{
        "filename": "app/views.py",
        "patch": "@@ -1,3 +1,4 @@\n ctx\n+new\n@@ -20,0 +30,2 @@\n+a\n+b",
    }]
    ranges = get_pr_diff_line_ranges("t", "org", "repo", 7)
    self.assertEqual(ranges["app/views.py"], {1, 2, 3, 4, 30, 31})

  @patch("codemender_agent.vcs.github._fetch_pr_files")
  def test_file_without_patch_is_not_addressable(self, mock_fetch):
    """Binary or oversized files have no patch, so nothing can anchor to them."""
    mock_fetch.return_value = [{"filename": "logo.png", "status": "added"}]
    self.assertEqual(get_pr_diff_line_ranges("t", "org", "repo", 7), {})

  @patch("codemender_agent.vcs.github._fetch_pr_files")
  def test_fetch_failure_yields_empty_map(self, mock_fetch):
    mock_fetch.side_effect = RuntimeError("boom")
    self.assertEqual(get_pr_diff_line_ranges("t", "org", "repo", 7), {})


class TestCreateReviewWithSuggestions(unittest.TestCase):
  """Validates review submission and its fallback signalling."""

  @patch("requests.post")
  def test_posts_review_and_returns_url(self, mock_post):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "html_url": "https://github.com/org/repo/pull/7#pullrequestreview-99"
    }
    mock_post.return_value = resp

    url = create_pr_review_with_suggestions(
        token="t",
        owner="org",
        repo="repo",
        pr_number=7,
        commit_id="deadbeef",
        body="summary",
        comments=[build_review_comment("a.py", 3, 3, "body")],
    )
    self.assertEqual(
        url, "https://github.com/org/repo/pull/7#pullrequestreview-99"
    )
    payload = mock_post.call_args.kwargs["json"]
    self.assertEqual(payload["event"], "COMMENT")
    self.assertEqual(payload["commit_id"], "deadbeef")

  @patch("requests.post")
  def test_omits_commit_id_when_absent(self, mock_post):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"html_url": "https://example.com"}
    mock_post.return_value = resp

    create_pr_review_with_suggestions(
        token="t",
        owner="org",
        repo="repo",
        pr_number=7,
        commit_id=None,
        body="summary",
        comments=[build_review_comment("a.py", 3, 3, "body")],
    )
    self.assertNotIn("commit_id", mock_post.call_args.kwargs["json"])

  @patch("requests.post")
  def test_out_of_diff_rejection_returns_none_for_fallback(self, mock_post):
    resp = MagicMock()
    resp.status_code = 422
    resp.text = '{"message":"line must be part of the diff"}'
    mock_post.return_value = resp

    url = create_pr_review_with_suggestions(
        token="t",
        owner="org",
        repo="repo",
        pr_number=7,
        commit_id="deadbeef",
        body="summary",
        comments=[build_review_comment("a.py", 3, 3, "body")],
    )
    self.assertIsNone(url)
    # A 422 is permanent for this payload and must not be retried.
    self.assertEqual(mock_post.call_count, 1)

  def test_no_comments_short_circuits(self):
    self.assertIsNone(
        create_pr_review_with_suggestions(
            token="t",
            owner="org",
            repo="repo",
            pr_number=7,
            commit_id="sha",
            body="b",
            comments=[],
        )
    )


class TestCommentTruncation(unittest.TestCase):
  """Validates the GitHub 65,536 character comment body cap."""

  def test_short_body_passes_through_untouched(self):
    self.assertEqual(truncate_comment_body("all good"), "all good")

  def test_oversized_body_fits_within_the_cap(self):
    body = "\n".join(f"| finding-{i} | HIGH | XSS |" for i in range(6000))
    self.assertGreater(len(body), MAX_COMMENT_BODY_CHARS)

    result = truncate_comment_body(body)

    self.assertLessEqual(len(result), MAX_COMMENT_BODY_CHARS)
    self.assertIn("truncated", result)
    # The cut must land on a line boundary, never mid-row.
    self.assertTrue(result.split("\n\n---\n")[0].endswith("|"))

  def test_reserved_prefix_counts_against_the_budget(self):
    body = "x" * (MAX_COMMENT_BODY_CHARS + 10)
    result = truncate_comment_body(body, reserved=500)
    self.assertLessEqual(len(result) + 500, MAX_COMMENT_BODY_CHARS)

  def test_cut_inside_a_code_block_closes_the_fence(self):
    body = "intro\n```python\n" + "payload = 1\n" * 12000
    result = truncate_comment_body(body)
    self.assertLessEqual(len(result), MAX_COMMENT_BODY_CHARS)
    # An unclosed fence would swallow the truncation notice.
    self.assertFalse(_fence_left_open(result), result[-200:])

  @patch("requests.post")
  @patch("requests.Session")
  def test_sticky_comment_truncates_and_keeps_marker(
      self, mock_session, mock_post
  ):
    listing = MagicMock()
    listing.json.return_value = []
    listing.links = {}
    mock_session.return_value.__enter__.return_value.get.return_value = listing

    created = MagicMock()
    created.status_code = 201
    created.json.return_value = {"html_url": "https://example.com/c/1"}
    mock_post.return_value = created

    post_or_update_sticky_comment(
        "t", "org", "repo", 7, "y" * (MAX_COMMENT_BODY_CHARS + 1000)
    )

    posted = mock_post.call_args.kwargs["json"]["body"]
    self.assertLessEqual(len(posted), MAX_COMMENT_BODY_CHARS)
    # Losing the marker would orphan the comment on the next run.
    self.assertTrue(posted.startswith(STICKY_SUMMARY_MARKER))


class TestForkCommentFitting(unittest.TestCase):
  """Validates that the fork patch comment degrades by whole sections."""

  HEADER = "### Fix\n\n#### Analysis\nUnescaped input.\n\n"
  FOOTER = "---\n*Automatically generated by CodeMender Orchestrator.*"

  def _sections(self, patch):
    return {
        "header": self.HEADER,
        "diff_section": f"#### Suggested Patch Diff\n````diff\n{patch}\n````\n\n",
        "apply_section": (
            f"#### How to Apply Locally\n````bash\ngit apply <<"
            f" 'EOF'\n{patch}\nEOF\n````\n\n"
        ),
        "footer": self.FOOTER,
    }

  def test_small_patch_keeps_every_section(self):
    body = _fit_fork_comment(**self._sections("+ safe()"))
    self.assertIn("#### Suggested Patch Diff", body)
    self.assertIn("git apply <<", body)
    self.assertIn("\nEOF\n", body)

  def test_medium_patch_drops_only_the_apply_helper(self):
    # Fits once but not twice.
    patch = "\n".join(f"+ line_{i}" for i in range(3000))
    body = _fit_fork_comment(**self._sections(patch))

    self.assertLessEqual(len(body), MAX_COMMENT_BODY_CHARS)
    self.assertIn("#### Suggested Patch Diff", body)
    self.assertNotIn("git apply <<", body)

  def test_huge_patch_drops_the_diff_and_points_to_the_artifact(self):
    patch = "\n".join(f"+ line_{i}" for i in range(10000))
    body = _fit_fork_comment(**self._sections(patch))

    self.assertLessEqual(len(body), MAX_COMMENT_BODY_CHARS)
    self.assertNotIn("````diff", body)
    self.assertIn("codemender-report", body)

  def test_a_surviving_apply_block_is_never_partial(self):
    """A heredoc without its EOF looks complete but yields a corrupt patch."""
    for count in (10, 1000, 3000, 6000, 20000):
      patch = "\n".join(f"+ line_{i}" for i in range(count))
      body = _fit_fork_comment(**self._sections(patch))
      self.assertLessEqual(len(body), MAX_COMMENT_BODY_CHARS, count)
      if "git apply <<" in body:
        self.assertIn("\nEOF\n", body, f"truncated heredoc at {count} lines")



class TestStickyCommentAndDedup(unittest.TestCase):
  """Validates the single summary comment and cross-run finding dedup."""

  @patch("requests.post")
  @patch("requests.patch")
  @patch("requests.Session")
  def test_updates_existing_marked_comment(
      self, mock_session, mock_patch, mock_post
  ):
    listing = MagicMock()
    listing.json.return_value = [
        {"id": 1, "body": "unrelated"},
        {"id": 2, "body": f"{STICKY_SUMMARY_MARKER}\nold summary"},
    ]
    listing.links = {}
    mock_session.return_value.__enter__.return_value.get.return_value = listing

    updated = MagicMock()
    updated.status_code = 200
    updated.json.return_value = {"html_url": "https://example.com/c/2"}
    mock_patch.return_value = updated

    url = post_or_update_sticky_comment("t", "org", "repo", 7, "new summary")
    self.assertEqual(url, "https://example.com/c/2")
    mock_post.assert_not_called()
    self.assertIn("/issues/comments/2", mock_patch.call_args.args[0])

  @patch("requests.post")
  @patch("requests.Session")
  def test_creates_comment_when_marker_absent(self, mock_session, mock_post):
    listing = MagicMock()
    listing.json.return_value = [{"id": 1, "body": "unrelated"}]
    listing.links = {}
    mock_session.return_value.__enter__.return_value.get.return_value = listing

    created = MagicMock()
    created.status_code = 201
    created.json.return_value = {"html_url": "https://example.com/c/9"}
    mock_post.return_value = created

    url = post_or_update_sticky_comment("t", "org", "repo", 7, "summary")
    self.assertEqual(url, "https://example.com/c/9")
    self.assertTrue(
        mock_post.call_args.kwargs["json"]["body"].startswith(
            STICKY_SUMMARY_MARKER
        )
    )

  @patch("requests.Session")
  def test_extracts_finding_ids_from_markers(self, mock_session):
    listing = MagicMock()
    listing.json.return_value = [
        {"body": f"{FINDING_MARKER_PREFIX}CM-1 -->\nsuggestion"},
        {"body": "a human review comment"},
        {"body": finding_marker("CM-2")},
    ]
    listing.links = {}
    mock_session.return_value.__enter__.return_value.get.return_value = listing

    self.assertEqual(
        list_reviewed_finding_ids("t", "org", "repo", 7), {"CM-1", "CM-2"}
    )


class TestParsePatchToSuggestions(unittest.TestCase):
  """Validates translation of a real git patch into suggestion anchors."""

  def setUp(self):
    self.tmp = tempfile.TemporaryDirectory()
    self.repo = self.tmp.name
    _git(self.repo, "init", "-q")
    _git(self.repo, "config", "user.email", "t@example.com")
    _git(self.repo, "config", "user.name", "Test")
    self.addCleanup(self.tmp.cleanup)

  def _commit(self, path, content):
    full = os.path.join(self.repo, path)
    with open(full, "w", encoding="utf-8") as fh:
      fh.write(content)
    _git(self.repo, "add", path)
    _git(self.repo, "commit", "-qm", "seed")

  def _write(self, path, content):
    with open(os.path.join(self.repo, path), "w", encoding="utf-8") as fh:
      fh.write(content)

  def _diff(self):
    res = subprocess.run(
        ["git", "diff", "HEAD"],
        cwd=self.repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return res.stdout

  def test_single_line_replacement(self):
    self._commit("app.py", "a = 1\nb = 2\nc = 3\n")
    self._write("app.py", "a = 1\nb = 22\nc = 3\n")
    hunks, blockers = parse_patch_to_suggestions(self.repo, self._diff())
    self.assertEqual(blockers, [])
    self.assertEqual(len(hunks), 1)
    self.assertEqual(hunks[0].path, "app.py")
    self.assertEqual((hunks[0].start_line, hunks[0].end_line), (2, 2))
    self.assertEqual(hunks[0].replacement_lines, ["b = 22"])

  def test_insertion_at_top_of_file_anchors_on_first_line(self):
    self._commit("app.py", "line1\nline2\nline3\n")
    self._write("app.py", "import bleach\nline1\nline2\nline3\n")
    hunks, blockers = parse_patch_to_suggestions(self.repo, self._diff())
    self.assertEqual(blockers, [])
    self.assertEqual((hunks[0].start_line, hunks[0].end_line), (1, 1))
    self.assertEqual(hunks[0].replacement_lines, ["import bleach", "line1"])

  def test_line_deletion_yields_empty_replacement(self):
    self._commit("app.py", "keep1\ndrop\nkeep2\n")
    self._write("app.py", "keep1\nkeep2\n")
    hunks, blockers = parse_patch_to_suggestions(self.repo, self._diff())
    self.assertEqual(blockers, [])
    self.assertEqual((hunks[0].start_line, hunks[0].end_line), (2, 2))
    self.assertEqual(hunks[0].replacement_lines, [])

  def test_new_file_is_a_blocker(self):
    self._commit("app.py", "a = 1\n")
    self._write("helper.py", "def helper():\n  pass\n")
    _git(self.repo, "add", "helper.py")
    hunks, blockers = parse_patch_to_suggestions(self.repo, self._diff())
    self.assertEqual(hunks, [])
    self.assertTrue(blockers)

  def test_empty_patch_is_a_blocker(self):
    self._commit("app.py", "a = 1\n")
    hunks, blockers = parse_patch_to_suggestions(self.repo, "")
    self.assertEqual(hunks, [])
    self.assertTrue(blockers)


class TestBuildSuggestionComments(unittest.TestCase):
  """Validates the all-or-nothing in-diff gate applied before posting."""

  FINDING_META = {
      "severity": "HIGH",
      "vuln_type": "XSS",
      "analysis": "Unescaped user input.",
  }

  @patch("codemender_agent.runners.worker.parse_patch_to_suggestions")
  def test_in_diff_patch_produces_marked_comments(self, mock_parse):
    from codemender_agent.vcs.git import SuggestionHunk

    mock_parse.return_value = (
        [SuggestionHunk("app.py", 10, 11, ["safe = escape(x)", "return safe"])],
        [],
    )
    comments, blocker = _build_suggestion_comments(
        "CM-1", self.FINDING_META, "/repo", "patch", {"app.py": {9, 10, 11, 12}}
    )
    self.assertIsNone(blocker)
    self.assertEqual(len(comments), 1)
    self.assertEqual(comments[0]["start_line"], 10)
    self.assertEqual(comments[0]["line"], 11)
    self.assertIn(finding_marker("CM-1"), comments[0]["body"])
    self.assertIn("```suggestion", comments[0]["body"])

  @patch("codemender_agent.runners.worker.parse_patch_to_suggestions")
  def test_out_of_diff_line_blocks_whole_patch(self, mock_parse):
    from codemender_agent.vcs.git import SuggestionHunk

    mock_parse.return_value = (
        [SuggestionHunk("app.py", 10, 11, ["x"])],
        [],
    )
    comments, blocker = _build_suggestion_comments(
        "CM-1", self.FINDING_META, "/repo", "patch", {"app.py": {10}}
    )
    self.assertEqual(comments, [])
    self.assertIn("outside the pull request diff", blocker)

  @patch("codemender_agent.runners.worker.parse_patch_to_suggestions")
  def test_untouched_file_blocks_whole_patch(self, mock_parse):
    from codemender_agent.vcs.git import SuggestionHunk

    mock_parse.return_value = ([SuggestionHunk("other.py", 1, 1, ["x"])], [])
    comments, blocker = _build_suggestion_comments(
        "CM-1", self.FINDING_META, "/repo", "patch", {"app.py": {1}}
    )
    self.assertEqual(comments, [])
    self.assertIn("not part of the reviewable pull request diff", blocker)

  @patch("codemender_agent.runners.worker.parse_patch_to_suggestions")
  def test_one_bad_hunk_blocks_the_suggestable_ones(self, mock_parse):
    """Partial fixes must never be offered; remediation is all or nothing."""
    from codemender_agent.vcs.git import SuggestionHunk

    mock_parse.return_value = (
        [
            SuggestionHunk("app.py", 10, 10, ["good"]),
            SuggestionHunk("app.py", 99, 99, ["bad"]),
        ],
        [],
    )
    comments, blocker = _build_suggestion_comments(
        "CM-1", self.FINDING_META, "/repo", "patch", {"app.py": {10}}
    )
    self.assertEqual(comments, [])
    self.assertIsNotNone(blocker)

  @patch("codemender_agent.runners.worker.parse_patch_to_suggestions")
  def test_structural_blocker_is_propagated(self, mock_parse):
    mock_parse.return_value = ([], ["`helper.py` is a new file"])
    comments, blocker = _build_suggestion_comments(
        "CM-1", self.FINDING_META, "/repo", "patch", {}
    )
    self.assertEqual(comments, [])
    self.assertIn("new file", blocker)

  @patch("codemender_agent.runners.worker.parse_patch_to_suggestions")
  def test_multi_hunk_comments_are_numbered(self, mock_parse):
    from codemender_agent.vcs.git import SuggestionHunk

    mock_parse.return_value = (
        [
            SuggestionHunk("app.py", 10, 10, ["one"]),
            SuggestionHunk("app.py", 20, 20, ["two"]),
        ],
        [],
    )
    comments, blocker = _build_suggestion_comments(
        "CM-1", self.FINDING_META, "/repo", "patch", {"app.py": {10, 20}}
    )
    self.assertIsNone(blocker)
    self.assertEqual(len(comments), 2)
    self.assertIn("part 1 of 2", comments[0]["body"])
    self.assertIn("part 2 of 2", comments[1]["body"])
    # Every comment carries the marker so re-runs can detect the finding.
    for comment in comments:
      self.assertIn(finding_marker("CM-1"), comment["body"])


class TestProcessFindingRouting(unittest.TestCase):
  """Validates which remediation route _process_finding actually takes."""

  def setUp(self):
    self.tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self.tmp.cleanup)
    self.repo_dir = os.path.join(self.tmp.name, "repo")
    os.makedirs(self.repo_dir, exist_ok=True)

    self.state_db = os.path.join(self.tmp.name, "state.db")
    with sqlite3.connect(self.state_db) as conn:
      conn.execute(
          "CREATE TABLE findings (finding_id TEXT PRIMARY KEY, status TEXT,"
          " verified INTEGER, muted INTEGER, mute_reason TEXT)"
      )
      conn.execute(
          "INSERT INTO findings VALUES ('fid-1', 'FIXED', 1, 0, NULL)"
      )
      conn.execute(
          "CREATE TABLE patches (finding_id TEXT, edited_files TEXT,"
          " target_file TEXT, diff TEXT)"
      )
      conn.execute(
          "INSERT INTO patches VALUES ('fid-1', '[]', 'app.py', 'the-patch')"
      )

    self.finding = {
        "FindingID": "fid-1",
        "VulnType": "XSS",
        "FilePath": "app.py",
        "StartLine": 10,
        "Severity": "HIGH",
    }

  def _config(self, **overrides):
    params = {
        "workspace_dir": self.tmp.name,
        "repo_url": "https://github.com/org/repo.git",
        "github_token": "fake-token",
        "target_sha": "headsha",
        "is_pr_scan": True,
        "pr_number": 42,
        "pr_head_ref": "feature/x",
    }
    params.update(overrides)
    return OrchestratorConfig(**params)

  def _run(self, config, **kwargs):
    from codemender_agent.runners.worker import _process_finding

    return _process_finding(
        finding_id="fid-1",
        finding=self.finding,
        repo_dir=self.repo_dir,
        cm_binary="/bin/cm",
        scrubbed_env={},
        clean_repo_url="https://github.com/org/repo.git",
        token="fake-token",
        owner="org",
        repo_name="repo",
        default_branch="main",
        working_base_ref="headsha",
        state_db_path=self.state_db,
        worker_token_usage={},
        config=config,
        **kwargs,
    )


def _routing_patches(func):
  """Applies the mock stack shared by every routing test."""
  decorators = [
      patch("codemender_agent.runners.worker.run_command"),
      patch("codemender_agent.runners.worker.check_remote_branch_exists"),
      patch("codemender_agent.runners.worker.is_duplicate_pr"),
      patch("codemender_agent.runners.worker.is_finding_verified"),
      patch("codemender_agent.runners.worker.get_finding_status"),
      patch("codemender_agent.runners.worker.push_branch_to_remote"),
      patch("codemender_agent.runners.worker.create_pull_request"),
      patch("codemender_agent.runners.worker.create_pr_comment"),
      patch("codemender_agent.runners.worker.create_pr_review_with_suggestions"),
      patch("codemender_agent.runners.worker.parse_patch_to_suggestions"),
  ]
  for decorator in decorators:
    func = decorator(func)
  return func


class TestRoutingDecisions(TestProcessFindingRouting):
  """Exercises the full verify -> fix -> route path with the pipeline mocked."""

  def _prime(self, mocks):
    """Configures the shared mock stack for a successful fix."""
    mocks["run_command"].side_effect = lambda cmd, *a, **k: MagicMock(
        stdout=" M app.py" if "status" in " ".join(cmd) else "",
        returncode=0,
    )
    mocks["check_remote_branch_exists"].return_value = False
    mocks["is_duplicate_pr"].return_value = False
    mocks["is_finding_verified"].return_value = True
    mocks["get_finding_status"].return_value = "FIXED"

  @staticmethod
  def _unpack(args):
    """Maps injected mocks onto names (patch injects innermost decorator first)."""
    names = [
        "run_command",
        "check_remote_branch_exists",
        "is_duplicate_pr",
        "is_finding_verified",
        "get_finding_status",
        "push_branch_to_remote",
        "create_pull_request",
        "create_pr_comment",
        "create_pr_review_with_suggestions",
        "parse_patch_to_suggestions",
    ]
    return dict(zip(names, args))

  @_routing_patches
  def test_suggestable_patch_posts_review_and_pushes_nothing(self, *args):
    from codemender_agent.vcs.git import SuggestionHunk

    mocks = self._unpack(args)
    self._prime(mocks)
    mocks["parse_patch_to_suggestions"].return_value = (
        [SuggestionHunk("app.py", 10, 10, ["safe()"])],
        [],
    )
    mocks["create_pr_review_with_suggestions"].return_value = (
        "https://github.com/org/repo/pull/42#pullrequestreview-1"
    )

    url = self._run(self._config(), pr_diff_line_ranges={"app.py": {10}})

    self.assertEqual(
        url, "https://github.com/org/repo/pull/42#pullrequestreview-1"
    )
    mocks["push_branch_to_remote"].assert_not_called()
    mocks["create_pull_request"].assert_not_called()
    # No fix branch should ever be created in suggestion mode.
    checkouts = [
        call.args[0]
        for call in mocks["run_command"].call_args_list
        if call.args[0][:3] == ["git", "checkout", "-B"]
    ]
    self.assertEqual(checkouts, [])

  @_routing_patches
  def test_unsuggestable_patch_falls_back_to_child_pr(self, *args):
    mocks = self._unpack(args)
    self._prime(mocks)
    mocks["parse_patch_to_suggestions"].return_value = (
        [],
        ["`helper.py` is a new file"],
    )
    mocks["create_pull_request"].return_value = (
        "https://github.com/org/repo/pull/99"
    )

    url = self._run(self._config(), pr_diff_line_ranges={})

    self.assertEqual(url, "https://github.com/org/repo/pull/99")
    mocks["create_pr_review_with_suggestions"].assert_not_called()
    mocks["push_branch_to_remote"].assert_called_once()

  @_routing_patches
  def test_rejected_review_falls_back_to_child_pr(self, *args):
    """A 422 from GitHub must not strand the finding without a remediation."""
    from codemender_agent.vcs.git import SuggestionHunk

    mocks = self._unpack(args)
    self._prime(mocks)
    mocks["parse_patch_to_suggestions"].return_value = (
        [SuggestionHunk("app.py", 10, 10, ["safe()"])],
        [],
    )
    mocks["create_pr_review_with_suggestions"].return_value = None
    mocks["create_pull_request"].return_value = (
        "https://github.com/org/repo/pull/99"
    )

    url = self._run(self._config(), pr_diff_line_ranges={"app.py": {10}})

    self.assertEqual(url, "https://github.com/org/repo/pull/99")

  @_routing_patches
  def test_fork_pr_falls_back_to_patch_comment(self, *args):
    mocks = self._unpack(args)
    self._prime(mocks)
    mocks["parse_patch_to_suggestions"].return_value = (
        [],
        ["`helper.py` is a new file"],
    )
    mocks["create_pr_comment"].return_value = (
        "https://github.com/org/repo/pull/42#issuecomment-5"
    )

    url = self._run(
        self._config(is_fork_pr=True), pr_diff_line_ranges={}
    )

    self.assertEqual(url, "https://github.com/org/repo/pull/42#issuecomment-5")
    mocks["push_branch_to_remote"].assert_not_called()
    mocks["create_pull_request"].assert_not_called()

  @_routing_patches
  def test_child_pr_mode_skips_suggestions_entirely(self, *args):
    mocks = self._unpack(args)
    self._prime(mocks)
    mocks["create_pull_request"].return_value = (
        "https://github.com/org/repo/pull/99"
    )

    url = self._run(self._config(pr_remediation_mode=PR_MODE_CHILD_PR))

    self.assertEqual(url, "https://github.com/org/repo/pull/99")
    mocks["parse_patch_to_suggestions"].assert_not_called()
    mocks["create_pr_review_with_suggestions"].assert_not_called()

  @_routing_patches
  def test_fork_pr_ignores_child_pr_mode(self, *args):
    """Forks cannot receive a pushed branch, so the flag must not apply."""
    from codemender_agent.vcs.git import SuggestionHunk

    mocks = self._unpack(args)
    self._prime(mocks)
    mocks["parse_patch_to_suggestions"].return_value = (
        [SuggestionHunk("app.py", 10, 10, ["safe()"])],
        [],
    )
    mocks["create_pr_review_with_suggestions"].return_value = (
        "https://github.com/org/repo/pull/42#pullrequestreview-1"
    )

    url = self._run(
        self._config(is_fork_pr=True, pr_remediation_mode=PR_MODE_CHILD_PR),
        pr_diff_line_ranges={"app.py": {10}},
    )

    self.assertIn("pullrequestreview", url)
    mocks["create_pull_request"].assert_not_called()

  @_routing_patches
  def test_already_suggested_finding_is_skipped(self, *args):
    mocks = self._unpack(args)
    self._prime(mocks)

    url = self._run(self._config(), already_suggested={"fid-1"})

    self.assertIsNone(url)
    mocks["create_pr_review_with_suggestions"].assert_not_called()
    mocks["create_pull_request"].assert_not_called()

  @_routing_patches
  def test_child_pr_fallback_respects_existing_fix_branch(self, *args):
    """The upfront dedup check is skipped in suggestion mode, so it must run here."""
    mocks = self._unpack(args)
    self._prime(mocks)
    mocks["check_remote_branch_exists"].return_value = True
    mocks["parse_patch_to_suggestions"].return_value = (
        [],
        ["`helper.py` is a new file"],
    )

    url = self._run(self._config(), pr_diff_line_ranges={})

    self.assertIsNone(url)
    mocks["push_branch_to_remote"].assert_not_called()
    mocks["create_pull_request"].assert_not_called()

  @_routing_patches
  def test_suggestion_crash_falls_back_instead_of_stranding_finding(self, *args):
    """An unexpected error while building suggestions must not lose the fix."""
    mocks = self._unpack(args)
    self._prime(mocks)
    mocks["parse_patch_to_suggestions"].side_effect = IndexError(
        "malformed hunk"
    )
    mocks["create_pull_request"].return_value = (
        "https://github.com/org/repo/pull/99"
    )

    url = self._run(self._config(), pr_diff_line_ranges={"app.py": {10}})

    self.assertEqual(url, "https://github.com/org/repo/pull/99")
    with sqlite3.connect(self.state_db) as conn:
      status = conn.execute(
          "SELECT status FROM findings WHERE finding_id = 'fid-1'"
      ).fetchone()[0]
    self.assertNotEqual(status, "PR_CREATION_FAILED")



if __name__ == "__main__":
  unittest.main()
