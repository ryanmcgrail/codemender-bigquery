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

"""Unit tests for Phase 1: GitHub VCS & Diff Security Gate Primitives."""

import unittest
from unittest.mock import MagicMock, patch

from codemender_agent.vcs.git import parse_diff_hunks_to_review_comments
from codemender_agent.vcs.github import (
    STICKY_SUMMARY_MARKER,
    post_idempotent_inline_review,
    resolve_sticky_comment_if_present,
    update_finding_in_sticky_comment,
)


class TestVcsSecurityGatePrimitives(unittest.TestCase):
  """Tests for sticky comment optimistic concurrency, inline idempotency, and diff hunk parsing."""

  def test_parse_diff_hunks_trims_context_and_builds_suggestion(self) -> None:
    diff_text = (
        "diff --git a/src/bokeh/util/probe.py b/src/bokeh/util/probe.py\n"
        "--- a/src/bokeh/util/probe.py\n"
        "+++ b/src/bokeh/util/probe.py\n"
        "@@ -8,5 +8,5 @@\n"
        " def run_cmd(user_cmd):\n"
        "     # leading context\n"
        "-    os.system(user_cmd)\n"
        "-    return True\n"
        "+    subprocess.run(['echo', user_cmd], check=True)\n"
        "     # trailing context\n"
    )
    comments = parse_diff_hunks_to_review_comments(
        diff_text, "src/bokeh/util/probe.py", "### Header", fallback_line=10
    )
    self.assertEqual(len(comments), 1)
    c = comments[0]
    self.assertEqual(c["path"], "src/bokeh/util/probe.py")
    self.assertEqual(c["side"], "RIGHT")
    self.assertEqual(c["start_line"], 10)
    self.assertEqual(c["line"], 11)
    self.assertIn("```suggestion\n    subprocess.run(['echo', user_cmd], check=True)\n```", c["body"])

  def test_parse_diff_hunks_fallback_when_no_hunk_header(self) -> None:
    comments = parse_diff_hunks_to_review_comments(
        "raw non-hunk diff", "src/app.py", "### Header", fallback_line=25
    )
    self.assertEqual(len(comments), 1)
    self.assertEqual(comments[0]["line"], 25)
    self.assertIn("```diff\nraw non-hunk diff\n```", comments[0]["body"])

  @patch("codemender_agent.vcs.github.time.sleep")
  @patch("codemender_agent.vcs.github.requests")
  def test_update_finding_in_sticky_comment_optimistic_concurrency_retry(
      self, mock_requests: MagicMock, _mock_sleep: MagicMock
  ) -> None:
    initial_body = (
        f"{STICKY_SUMMARY_MARKER}\n"
        "## 🛡️ CodeMender Pre-Submit Security Gate — ❌ **BLOCKED**\n"
        "*⏳ Stage 1 Complete: 0/2 Findings Verified (`cm verify` & `cm fix` running)*\n\n"
        "| Severity | Gate | Finding | Location | Status |\n"
        "| :--- | :--- | :--- | :--- | :--- |\n"
        "| `HIGH` | 🚫 **BLOCKING** | **SQLi** (`11112222`) | `src/a.py:10` | ⏳ **Queued** | <!-- cm-row:11112222 -->\n"
        "| `HIGH` | 🚫 **BLOCKING** | **RCE** (`33334444`) | `src/b.py:20` | ✅ **Patch Ready** | <!-- cm-row:33334444 -->\n"
    )
    state = {"body": initial_body, "patch_calls": 0}

    def fake_get(url, **_kwargs):
      resp = MagicMock()
      resp.raise_for_status.return_value = None
      if url.endswith("/comments?per_page=100"):
        resp.json.return_value = [{"id": 99, "body": state["body"]}]
      else:
        resp.json.return_value = {"id": 99, "body": state["body"]}
      return resp

    def fake_patch(_url, json=None, **_kwargs):
      state["patch_calls"] += 1
      resp = MagicMock()
      if state["patch_calls"] == 1:
        resp.raise_for_status.side_effect = RuntimeError("HTTP 502 Concurrent PATCH collision")
        return resp
      resp.raise_for_status.return_value = None
      state["body"] = json["body"]
      return resp

    mock_requests.get.side_effect = fake_get
    mock_requests.patch.side_effect = fake_patch

    finding = {
        "finding_id": "11112222-aaaa-bbbb",
        "severity": "HIGH",
        "title": "SQLi",
        "file_path": "src/a.py",
        "line_number": 10,
    }
    ok = update_finding_in_sticky_comment(
        token="ghs_real_token",
        owner="org",
        repo="repo",
        pr_number=1,
        finding=finding,
        status_cell_md="✅ **Patch Ready**",
        min_sev="MEDIUM",
    )
    self.assertTrue(ok)
    self.assertEqual(state["patch_calls"], 2)
    self.assertIn("Stage 2 Complete: 2/2 Findings Processed", state["body"])
    self.assertIn("| `HIGH` | 🚫 **BLOCKING** | **SQLi** (`11112222`) | `src/a.py:10` | ✅ **Patch Ready** | <!-- cm-row:11112222 -->", state["body"])

  @patch("codemender_agent.vcs.github.requests")
  def test_resolve_sticky_comment_if_present(self, mock_requests: MagicMock) -> None:
    get_resp = MagicMock()
    get_resp.raise_for_status.return_value = None
    get_resp.json.return_value = [{"id": 77, "body": f"{STICKY_SUMMARY_MARKER}\n❌ **BLOCKED**"}]
    patch_resp = MagicMock()
    patch_resp.raise_for_status.return_value = None

    mock_requests.get.return_value = get_resp
    mock_requests.patch.return_value = patch_resp

    resolved = resolve_sticky_comment_if_present(
        token="ghs_real_token",
        owner="org",
        repo="repo",
        pr_number=5,
        target_sha="abcdef1234567890",
        min_sev="MEDIUM",
    )
    self.assertTrue(resolved)
    patched_body = mock_requests.patch.call_args.kwargs["json"]["body"]
    self.assertIn("✅ **All Findings Resolved**", patched_body)

  @patch("codemender_agent.vcs.github.create_pr_review_with_suggestions")
  @patch("codemender_agent.vcs.github.requests")
  def test_post_idempotent_inline_review_skips_duplicate(
      self, mock_requests: MagicMock, mock_create_review: MagicMock
  ) -> None:
    list_resp = MagicMock()
    list_resp.status_code = 200
    list_resp.json.return_value = []
    mock_requests.get.return_value = list_resp
    mock_create_review.return_value = "https://github.com/org/repo/pull/1#pullrequestreview-500"

    finding = {
        "finding_id": "abcd1234",
        "severity": "HIGH",
        "title": "Command Injection",
        "file_path": "src/app.py",
        "line_number": 12,
        "description": "Unsanitized shell execution.",
    }
    diff = "@@ -12,1 +12,1 @@\n-os.system(x)\n+subprocess.run(['echo', x])\n"
    cache: dict = {}

    url1 = post_idempotent_inline_review(
        "ghs_token", "org", "repo", 1, "sha123", finding, diff, cache
    )
    url2 = post_idempotent_inline_review(
        "ghs_token", "org", "repo", 1, "sha123", finding, diff, cache
    )
    self.assertEqual(url1, "https://github.com/org/repo/pull/1#pullrequestreview-500")
    self.assertEqual(url2, url1)
    self.assertEqual(mock_create_review.call_count, 1)

  @patch("codemender_agent.vcs.github.requests")
  def test_update_finding_in_sticky_comment_transitions_bold_stage_subtitles(
      self, mock_requests: MagicMock
  ) -> None:
    state = {
        "body": (
            f"{STICKY_SUMMARY_MARKER}\n"
            "## 🛡️ CodeMender Pre-Submit Security Gate — ❌ **BLOCKED**\n"
            "*⏳ **Stage 1 Complete: 0/2 Findings Verified** (`cm verify` & `cm fix` running in background)*\n\n"
            "| Severity | Gate | Finding | Location | Status |\n"
            "| :--- | :--- | :--- | :--- | :--- |\n"
            "| `HIGH` | 🚫 **BLOCKING** | **SQLi** (`11112222`) | `src/a.py:10` | ⏳ **Queued** | <!-- cm-row:11112222 -->\n"
            "| `HIGH` | 🚫 **BLOCKING** | **CmdInj** (`33334444`) | `src/a.py:20` | ⏳ **Queued** | <!-- cm-row:33334444 -->\n"
        )
    }

    def fake_get(url: str, **kwargs):
      resp = MagicMock()
      resp.raise_for_status.return_value = None
      if url.endswith("/comments?per_page=100"):
        resp.json.return_value = [{"id": 99, "body": state["body"]}]
      else:
        resp.json.return_value = {"id": 99, "body": state["body"]}
      return resp

    def fake_patch(url: str, **kwargs):
      state["body"] = kwargs["json"]["body"]
      resp = MagicMock()
      resp.raise_for_status.return_value = None
      return resp

    mock_requests.get.side_effect = fake_get
    mock_requests.patch.side_effect = fake_patch

    update_finding_in_sticky_comment(
        token="ghs_token",
        owner="org",
        repo="repo",
        pr_number=1,
        finding={"finding_id": "11112222", "severity": "HIGH", "title": "SQLi", "file_path": "src/a.py", "line_number": 10},
        status_cell_md="✅ **Patch Ready**",
        min_sev="MEDIUM",
    )
    self.assertIn("*🔄 **Stage 2 In Progress: 1/2 Findings Processed**", state["body"])

    update_finding_in_sticky_comment(
        token="ghs_token",
        owner="org",
        repo="repo",
        pr_number=1,
        finding={"finding_id": "33334444", "severity": "HIGH", "title": "CmdInj", "file_path": "src/a.py", "line_number": 20},
        status_cell_md="⚪ **Dismissed (False Positive)**",
        min_sev="MEDIUM",
    )
    self.assertIn("*✅ **Stage 2 Complete: 2/2 Findings Processed**", state["body"])

  @patch("codemender_agent.vcs.github.requests")
  def test_update_finding_in_sticky_comment_preserves_non_blocking_gate_badge(
      self, mock_requests: MagicMock
  ) -> None:
    state = {
        "body": (
            f"{STICKY_SUMMARY_MARKER}\n"
            "## 🛡️ CodeMender Pre-Submit Security Gate — ⚠️ **PASSED (Non-Blocking Mode)** (`1` finding(s) `>= MEDIUM` — merge not blocked)\n"
            "*⏳ **Stage 1 Complete: 0/1 Findings Verified** (`cm verify` & `cm fix` running in background)*\n\n"
            "| Severity | Gate | Finding | Location | Status |\n"
            "| :--- | :--- | :--- | :--- | :--- |\n"
            "| `CRITICAL` | ⚠️ **Non-Blocking** | **CmdInj** (`2e654391`) | `src/a.py:9` | ⏳ **Queued** | <!-- cm-row:2e654391 -->\n"
        )
    }

    def fake_get(url: str, **kwargs):
      resp = MagicMock()
      resp.raise_for_status.return_value = None
      if url.endswith("/comments?per_page=100"):
        resp.json.return_value = [{"id": 99, "body": state["body"]}]
      else:
        resp.json.return_value = {"id": 99, "body": state["body"]}
      return resp

    def fake_patch(url: str, **kwargs):
      state["body"] = kwargs["json"]["body"]
      resp = MagicMock()
      resp.raise_for_status.return_value = None
      return resp

    mock_requests.get.side_effect = fake_get
    mock_requests.patch.side_effect = fake_patch

    update_finding_in_sticky_comment(
        token="ghs_token",
        owner="org",
        repo="repo",
        pr_number=1,
        finding={
            "finding_id": "2e654391",
            "severity": "CRITICAL",
            "title": "CmdInj",
            "file_path": "src/a.py",
            "line_number": 9,
        },
        status_cell_md="⏳ **Verifying (`cm verify`)...**",
        min_sev="MEDIUM",
    )
    self.assertIn("| `CRITICAL` | ⚠️ **Non-Blocking** |", state["body"])
    self.assertNotIn("🚫 **BLOCKING**", state["body"])

    update_finding_in_sticky_comment(
        token="ghs_token",
        owner="org",
        repo="repo",
        pr_number=1,
        finding={
            "finding_id": "2e654391",
            "severity": "CRITICAL",
            "title": "CmdInj",
            "file_path": "src/a.py",
            "line_number": 9,
        },
        status_cell_md="✅ **Patch Ready**",
        min_sev="MEDIUM",
        fail_on_findings=False,
    )
    self.assertIn("| `CRITICAL` | ⚠️ **Non-Blocking** |", state["body"])
    self.assertNotIn("🚫 **BLOCKING**", state["body"])

  @patch("codemender_agent.vcs.github.requests")
  def test_resolve_sticky_comment_refreshes_target_sha_on_new_clean_commit(
      self, mock_requests: MagicMock
  ) -> None:
    existing_resolved = (
        f"{STICKY_SUMMARY_MARKER}\n"
        "## 🛡️ CodeMender Pre-Submit Security Gate — ✅ **All Findings Resolved**\n\n"
        "**Gate Status:** ✅ **PASSED** (`0` active vulnerabilities `>= MEDIUM` in current PR diff at commit `aaaa1111`)\n"
    )
    get_resp = MagicMock()
    get_resp.raise_for_status.return_value = None
    get_resp.json.return_value = [{"id": 77, "body": existing_resolved}]
    patch_resp = MagicMock()
    patch_resp.raise_for_status.return_value = None
    mock_requests.get.return_value = get_resp
    mock_requests.patch.return_value = patch_resp

    # Calling with same SHA skips PATCH
    self.assertTrue(
        resolve_sticky_comment_if_present("ghs_tok", "org", "repo", 5, "aaaa11119999", "MEDIUM")
    )
    mock_requests.patch.assert_not_called()

    # Calling with new SHA updates the sticky comment with the new commit SHA
    self.assertTrue(
        resolve_sticky_comment_if_present("ghs_tok", "org", "repo", 5, "bbbb22229999", "MEDIUM")
    )
    mock_requests.patch.assert_called_once()
    patched_body = mock_requests.patch.call_args.kwargs["json"]["body"]
    self.assertIn("at commit `bbbb2222`", patched_body)

  @patch("codemender_agent.vcs.github.create_pr_review_with_suggestions")
  @patch("codemender_agent.vcs.github.requests")
  def test_post_idempotent_inline_review_upgrades_comment_without_suggestion_block(
      self, mock_requests: MagicMock, mock_create_review: MagicMock
  ) -> None:
    marker = "<!-- cm-inline:src/app.py:12:Command Injection -->"
    list_resp = MagicMock()
    list_resp.status_code = 200
    # Existing comment has the marker but NO ```suggestion block
    list_resp.json.return_value = [
        {"body": f"{marker}\n### 🛡️ CodeMender Security Finding (`HIGH`)", "html_url": "https://old-review"}
    ]
    mock_requests.get.return_value = list_resp
    mock_create_review.return_value = "https://github.com/org/repo/pull/1#pullrequestreview-999"

    finding = {
        "finding_id": "abcd1234",
        "severity": "HIGH",
        "title": "Command Injection",
        "file_path": "src/app.py",
        "line_number": 12,
        "description": "Unsanitized shell execution.",
    }
    diff = "@@ -12,1 +12,1 @@\n-os.system(x)\n+subprocess.run(['echo', x])\n"
    url = post_idempotent_inline_review(
        "ghs_token", "org", "repo", 1, "sha123", finding, diff, None
    )
    self.assertEqual(url, "https://github.com/org/repo/pull/1#pullrequestreview-999")
    mock_create_review.assert_called_once()

  def test_parse_diff_hunks_single_line_omits_start_line_and_handles_multi_hunk(
      self,
  ) -> None:
    diff_text = (
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -1,2 +1,3 @@\n"
        " import os\n"
        "+import subprocess\n"
        " \n"
        "@@ -14,1 +15,1 @@\n"
        "-    os.system(cmd)\n"
        "+    subprocess.run(['echo', cmd], check=True)\n"
    )
    comments = parse_diff_hunks_to_review_comments(
        diff_text, "src/app.py", "### Finding Header", fallback_line=14
    )
    self.assertEqual(len(comments), 2)
    # First hunk is pure insertion after line 1: anchors on line 1 and includes
    # existing line 1 ("import os") in the suggestion block so it inserts rather
    # than overwriting line 2.
    self.assertEqual(comments[0]["line"], 1)
    self.assertNotIn("start_line", comments[0])
    self.assertIn("### Finding Header", comments[0]["body"])
    self.assertIn(
        "```suggestion\nimport os\nimport subprocess\n```",
        comments[0]["body"],
    )
    # Second hunk is single-line replacement at line 14: start_line omitted, header_md not duplicated
    self.assertEqual(comments[1]["line"], 14)
    self.assertNotIn("start_line", comments[1])
    self.assertNotIn("### Finding Header", comments[1]["body"])

  @patch("codemender_agent.vcs.github.create_pr_review_with_suggestions")
  @patch("codemender_agent.vcs.github.requests")
  def test_vcs_primitives_accept_snake_case_start_line(
      self, mock_requests: MagicMock, mock_create_review: MagicMock
  ) -> None:
    state = {
        "body": (
            f"{STICKY_SUMMARY_MARKER}\n"
            "| Severity | Gate | Finding | Location | Status |\n"
            "| :--- | :--- | :--- | :--- | :--- |\n"
            "| `HIGH` | 🚫 **BLOCKING** | **SQLi** (`99887766`) | `src/db.py:42` | ⏳ **Queued** | <!-- cm-row:99887766 -->\n"
        )
    }

    def fake_get(url: str, **_kwargs):
      resp = MagicMock()
      resp.status_code = 200
      resp.raise_for_status.return_value = None
      if url.endswith("/comments?per_page=100") and "/issues/" in url:
        resp.json.return_value = [{"id": 55, "body": state["body"]}]
      elif "/issues/comments/" in url:
        resp.json.return_value = {"id": 55, "body": state["body"]}
      else:
        resp.json.return_value = []
      return resp

    def fake_patch(_url: str, **kwargs):
      state["body"] = kwargs["json"]["body"]
      resp = MagicMock()
      resp.raise_for_status.return_value = None
      return resp

    mock_requests.get.side_effect = fake_get
    mock_requests.patch.side_effect = fake_patch
    mock_create_review.return_value = "https://github.com/org/repo/pull/1#pullrequestreview-42"

    raw_snake_finding = {
        "finding_id": "99887766-aaaa",
        "severity": "HIGH",
        "title": "SQLi",
        "file_path": "src/db.py",
        "start_line": 42,
    }
    self.assertTrue(
        update_finding_in_sticky_comment(
            "ghs_tok", "org", "repo", 1, raw_snake_finding, "✅ **Patch Ready**", "MEDIUM"
        )
    )
    self.assertIn("`src/db.py:42`", state["body"])

    cache: dict = {}
    post_idempotent_inline_review(
        "ghs_tok", "org", "repo", 1, "sha123", raw_snake_finding, "", cache
    )
    self.assertIn("<!-- cm-inline:src/db.py:42:SQLi -->", cache)

  def test_parse_diff_hunks_does_not_truncate_on_removed_sql_comment_or_increment(
      self,
  ) -> None:
    diff_text = (
        "diff --git a/src/query.sql b/src/query.sql\n"
        "--- a/src/query.sql\n"
        "+++ b/src/query.sql\n"
        "@@ -5,3 +5,3 @@\n"
        "--- a/legacy comment\n"
        "-SELECT * FROM users WHERE name = '$input';\n"
        "+++ b/updated comment\n"
        "+SELECT * FROM users WHERE name = :input;\n"
        " COMMIT;\n"
    )
    comments = parse_diff_hunks_to_review_comments(
        diff_text, "src/query.sql", "### SQLi Fix", fallback_line=5
    )
    self.assertEqual(len(comments), 1)
    self.assertEqual(comments[0]["start_line"], 5)
    self.assertEqual(comments[0]["line"], 6)
    self.assertIn(
        "```suggestion\n++ b/updated comment\nSELECT * FROM users WHERE name = :input;\n```",
        comments[0]["body"],
    )


if __name__ == "__main__":
  unittest.main()

