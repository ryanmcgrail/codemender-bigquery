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

"""Unit tests for codemender_agent.vcs.github module."""

import unittest
from unittest.mock import MagicMock, patch

from codemender_agent.vcs.github import check_remote_branch_exists, create_pull_request, get_default_branch


class TestVcsGithub(unittest.TestCase):

  @patch("codemender_agent.vcs.github._get_branch_via_api")
  def test_check_remote_branch_exists_true(self, mock_api):
    """Verify branch check returns True when GitHub API finds the branch."""
    mock_api.return_value = True
    exists = check_remote_branch_exists(
        "https://github.com/org/repo.git", "fake_token", "feature-branch"
    )
    self.assertTrue(exists)
    mock_api.assert_called_once_with(
        "org", "repo", "feature-branch", "fake_token"
    )

  @patch("requests.post")
  def test_create_pull_request_success(self, mock_post):
    """Verify successful Pull Request creation."""
    mock_resp = MagicMock()
    mock_resp.status_code = 201
    mock_resp.json.return_value = {
        "html_url": "https://github.com/org/repo/pull/42"
    }
    mock_post.return_value = mock_resp

    pr_url = create_pull_request(
        token="token",
        owner="org",
        repo="repo",
        title="Fix SQLi",
        body="Details",
        head_branch="codemender/fix-sqli",
        base_branch="main",
    )
    self.assertEqual(pr_url, "https://github.com/org/repo/pull/42")

  @patch("requests.get")
  def test_get_default_branch_api_success(self, mock_get):
    """Verify fetching default branch via GitHub REST API."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"default_branch": "development"}
    mock_get.return_value = mock_resp

    branch = get_default_branch("token", "org", "repo")
    self.assertEqual(branch, "development")

  @patch("requests.post")
  def test_create_pr_comment_success(self, mock_post):
    """Verify posting review comment on PRs."""
    from codemender_agent.vcs.github import create_pr_comment

    mock_resp = MagicMock()
    mock_resp.status_code = 201
    mock_resp.json.return_value = {
        "html_url": "https://github.com/org/repo/pull/42#issuecomment-1"
    }
    mock_post.return_value = mock_resp

    comment_url = create_pr_comment(
        token="valid-token",
        owner="org",
        repo="repo",
        pr_number=42,
        body="## Security Fix Proposal",
    )
    self.assertEqual(
        comment_url, "https://github.com/org/repo/pull/42#issuecomment-1"
    )
    mock_post.assert_called_once()

  @patch("requests.get")
  def test_is_duplicate_pr_with_head_branch(self, mock_get):
    """Verify targeted O(1) duplicate PR lookup with head_branch parameter."""
    from codemender_agent.vcs.github import is_duplicate_pr

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        {"title": "Fix SQL Injection", "state": "open"}
    ]
    mock_get.return_value = mock_resp

    is_dup = is_duplicate_pr(
        repo_url="https://github.com/org/repo.git",
        token="token",
        file_path="db.py",
        vuln_type="SQL_INJECTION",
        start_line=10,
        head_branch="codemender/fix-sql_injection-abc12345",
    )
    # No html_url in the API response falls back to a plain True.
    self.assertIs(is_dup, True)
    mock_get.assert_called_once()
    call_args = mock_get.call_args
    self.assertIn("head=org:codemender/fix-sql_injection-abc12345", call_args[0][0])

  @patch("requests.get")
  def test_is_duplicate_pr_with_head_branch_returns_pr_url(self, mock_get):
    """Verify targeted head_branch lookup returns the existing PR's html_url."""
    from codemender_agent.vcs.github import is_duplicate_pr

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [{
        "title": "Fix SQL Injection",
        "state": "open",
        "html_url": "https://github.com/org/repo/pull/7",
    }]
    mock_get.return_value = mock_resp

    result = is_duplicate_pr(
        repo_url="https://github.com/org/repo.git",
        token="token",
        file_path="db.py",
        vuln_type="SQL_INJECTION",
        start_line=10,
        head_branch="codemender/fix-sql_injection-abc12345",
    )
    self.assertEqual(result, "https://github.com/org/repo/pull/7")
    mock_get.assert_called_once()

  @patch("requests.Session")
  @patch("requests.get")
  def test_is_duplicate_pr_paginated_head_ref_returns_pr_url(
      self, mock_get, mock_session_cls
  ):
    """Verify paginated scan returns html_url when a PR head ref matches."""
    from codemender_agent.vcs.github import is_duplicate_pr

    # Targeted lookup finds nothing, forcing the paginated scan.
    targeted_resp = MagicMock()
    targeted_resp.status_code = 200
    targeted_resp.json.return_value = []
    mock_get.return_value = targeted_resp

    page_resp = MagicMock()
    page_resp.status_code = 200
    page_resp.json.return_value = [
        {
            "head": {"ref": "codemender/other-branch"},
            "body": "",
            "html_url": "https://github.com/org/repo/pull/1",
        },
        {
            "head": {"ref": "codemender/fix-sql_injection-abc12345"},
            "body": "",
            "html_url": "https://github.com/org/repo/pull/9",
        },
    ]
    page_resp.links = {}
    session = mock_session_cls.return_value.__enter__.return_value
    session.get.return_value = page_resp

    result = is_duplicate_pr(
        repo_url="https://github.com/org/repo.git",
        token="token",
        file_path="db.py",
        vuln_type="SQL_INJECTION",
        start_line=10,
        head_branch="codemender/fix-sql_injection-abc12345",
    )
    self.assertEqual(result, "https://github.com/org/repo/pull/9")

  @patch("requests.Session")
  def test_is_duplicate_pr_body_match_returns_pr_url_across_pages(
      self, mock_session_cls
  ):
    """Verify body signature match on a later page returns that PR's html_url."""
    from codemender_agent.vcs.github import is_duplicate_pr

    first_page = MagicMock()
    first_page.status_code = 200
    first_page.json.return_value = [{
        "head": {"ref": "feature/unrelated"},
        "body": "Unrelated change",
        "html_url": "https://github.com/org/repo/pull/2",
    }]
    first_page.links = {
        "next": {"url": "https://api.github.com/repos/org/repo/pulls?page=2"}
    }

    second_page = MagicMock()
    second_page.status_code = 200
    second_page.json.return_value = [{
        "head": {"ref": "codemender/fix-sql_injection-def67890"},
        "body": (
            "## CodeMender Security Fix\n"
            "**File**: db.py\n"
            "**Type**: SQL_INJECTION\n"
            "**Start Line**: 20\n"
        ),
        "html_url": "https://github.com/org/repo/pull/11",
    }]
    second_page.links = {}

    session = mock_session_cls.return_value.__enter__.return_value
    session.get.side_effect = [first_page, second_page]

    result = is_duplicate_pr(
        repo_url="https://github.com/org/repo.git",
        token="token",
        file_path="db.py",
        vuln_type="SQL_INJECTION",
        start_line=10,
    )
    self.assertEqual(result, "https://github.com/org/repo/pull/11")
    self.assertEqual(session.get.call_count, 2)
    self.assertIn("page=2", session.get.call_args_list[1][0][0])

  @patch("requests.Session")
  def test_is_duplicate_pr_no_match_returns_false(self, mock_session_cls):
    """Verify no URL is returned when no open PR matches within 15 lines."""
    from codemender_agent.vcs.github import is_duplicate_pr

    page_resp = MagicMock()
    page_resp.status_code = 200
    page_resp.json.return_value = [{
        "head": {"ref": "codemender/fix-sql_injection-def67890"},
        "body": (
            "## CodeMender Security Fix\n"
            "db.py SQL_INJECTION\n"
            "**Start Line**: 100\n"
        ),
        "html_url": "https://github.com/org/repo/pull/11",
    }]
    page_resp.links = {}
    session = mock_session_cls.return_value.__enter__.return_value
    session.get.return_value = page_resp

    result = is_duplicate_pr(
        repo_url="https://github.com/org/repo.git",
        token="token",
        file_path="db.py",
        vuln_type="SQL_INJECTION",
        start_line=10,
    )
    self.assertIs(result, False)

  def test_is_duplicate_pr_fake_token_returns_false(self):
    """Verify fake-token short-circuits without returning a URL."""
    from codemender_agent.vcs.github import is_duplicate_pr

    result = is_duplicate_pr(
        repo_url="https://github.com/org/repo.git",
        token="fake-token",
        file_path="db.py",
        vuln_type="SQL_INJECTION",
        start_line=10,
    )
    self.assertIs(result, False)

  @patch("codemender_agent.utils.time.sleep")
  @patch("requests.get")
  def test_is_duplicate_pr_api_error_returns_false(self, mock_get, _mock_sleep):
    """Verify API failures after retries return False rather than a URL."""
    import requests
    from codemender_agent.vcs.github import is_duplicate_pr

    mock_get.side_effect = requests.exceptions.ConnectionError("boom")

    result = is_duplicate_pr(
        repo_url="https://github.com/org/repo.git",
        token="token",
        file_path="db.py",
        vuln_type="SQL_INJECTION",
        start_line=10,
        head_branch="codemender/fix-sql_injection-abc12345",
    )
    self.assertIs(result, False)
    self.assertEqual(mock_get.call_count, 3)

  @patch("requests.post")
  def test_post_commit_status_success(self, mock_post):
    """Verify posting a commit status check on a PR commit SHA."""
    from codemender_agent.vcs.github import post_commit_status

    mock_resp = MagicMock()
    mock_resp.status_code = 201
    mock_resp.json.return_value = {"state": "failure"}
    mock_post.return_value = mock_resp

    success = post_commit_status(
        token="valid-token",
        owner="org",
        repo="repo",
        sha="abcdef123456",
        state="failure",
        description="Security Gate FAILED: 1 vulnerability detected",
        context="CodeMender / Security Gate",
        target_url="https://github.com/org/repo/pull/42",
    )
    self.assertTrue(success)
    mock_post.assert_called_once()
    url = mock_post.call_args[0][0]
    payload = mock_post.call_args[1]["json"]
    self.assertIn("/repos/org/repo/statuses/abcdef123456", url)
    self.assertEqual(payload["state"], "failure")
    self.assertEqual(payload["context"], "CodeMender / Security Gate")
    self.assertEqual(payload["target_url"], "https://github.com/org/repo/pull/42")

  def test_post_commit_status_fake_token(self):
    """Verify post_commit_status handles fake-token gracefully in unit tests."""
    from codemender_agent.vcs.github import post_commit_status

    success = post_commit_status(
        token="fake-token",
        owner="org",
        repo="repo",
        sha="abcdef123456",
        state="success",
        description="Security Gate PASSED",
    )
    self.assertTrue(success)

  @patch("requests.post")
  def test_post_commit_status_api_error_returns_false(self, mock_post):
    """Verify post_commit_status returns False on network error without throwing."""
    import requests
    from codemender_agent.vcs.github import post_commit_status

    mock_post.side_effect = requests.exceptions.RequestException("Connection error")

    success = post_commit_status(
        token="valid-token",
        owner="org",
        repo="repo",
        sha="abcdef123456",
        state="failure",
        description="Security Gate FAILED",
    )
    self.assertFalse(success)

  def test_delete_remote_branch_safety_guard_rejects_main(self):
    """Verify delete_remote_branch strictly rejects non-codemender branches."""
    from codemender_agent.vcs.github import delete_remote_branch

    # Refuse to delete protected or non-codemender branches
    self.assertFalse(
        delete_remote_branch("https://github.com/org/repo.git", "token", "main")
    )
    self.assertFalse(
        delete_remote_branch("https://github.com/org/repo.git", "token", "master")
    )
    self.assertFalse(
        delete_remote_branch("https://github.com/org/repo.git", "token", "feature/my-branch")
    )

  @patch("requests.delete")
  def test_delete_remote_branch_api_success(self, mock_delete):
    """Verify deleting branch via GitHub REST API with 204 status."""
    from codemender_agent.vcs.github import delete_remote_branch

    mock_resp = MagicMock()
    mock_resp.status_code = 204
    mock_delete.return_value = mock_resp

    success = delete_remote_branch(
        repo_url="https://github.com/org/repo.git",
        token="valid-token",
        branch_name="codemender/fix-sqli-abc12345",
    )
    self.assertTrue(success)
    mock_delete.assert_called_once()
    self.assertIn(
        "/repos/org/repo/git/refs/heads/codemender/fix-sqli-abc12345",
        mock_delete.call_args[0][0],
    )

  @patch("requests.delete")
  def test_delete_remote_branch_api_404_idempotent(self, mock_delete):
    """Verify deleting already-deleted branch returns True idempotently on 404/422."""
    from codemender_agent.vcs.github import delete_remote_branch

    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_delete.return_value = mock_resp

    success = delete_remote_branch(
        repo_url="https://github.com/org/repo.git",
        token="valid-token",
        branch_name="codemender/fix-sqli-abc12345",
    )
    self.assertTrue(success)

  @patch("codemender_agent.vcs.github.run_command")
  @patch("requests.delete")
  def test_delete_remote_branch_api_fail_falls_back_to_cli(
      self, mock_delete, mock_run_command
  ):
    """Verify falling back to Git CLI push --delete if REST API raises error."""
    import requests
    from codemender_agent.vcs.github import delete_remote_branch

    mock_delete.side_effect = requests.exceptions.RequestException("API error")
    mock_cli_res = MagicMock()
    mock_cli_res.returncode = 0
    mock_run_command.return_value = mock_cli_res

    success = delete_remote_branch(
        repo_url="https://github.com/org/repo.git",
        token="valid-token",
        branch_name="codemender/fix-sqli-abc12345",
    )
    self.assertTrue(success)
    mock_run_command.assert_called_once()
    cmd = mock_run_command.call_args[0][0]
    self.assertIn("--delete", cmd)
    self.assertIn("codemender/fix-sqli-abc12345", cmd)

  @patch("requests.post")
  def test_upload_sarif_to_code_scanning_success(self, mock_post):
    """Verify upload_sarif_to_code_scanning compresses and base64 encodes SARIF payload."""
    import tempfile
    from codemender_agent.vcs.github import upload_sarif_to_code_scanning

    mock_resp = MagicMock()
    mock_resp.status_code = 202
    mock_resp.json.return_value = {"id": "sarif-12345"}
    mock_post.return_value = mock_resp

    with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif") as tmp:
      tmp.write('{"version": "2.1.0", "runs": []}')
      tmp.flush()
      sarif_id = upload_sarif_to_code_scanning(
          token="valid-token",
          owner="example-org",
          repo="example-repo",
          sarif_path=tmp.name,
          commit_sha="abcdef1234567890",
          ref="refs/heads/branch-4.0",
      )
    self.assertEqual(sarif_id, "sarif-12345")
    mock_post.assert_called_once()
    payload = mock_post.call_args.kwargs["json"]
    self.assertEqual(payload["commit_sha"], "abcdef1234567890")
    self.assertEqual(payload["ref"], "refs/heads/branch-4.0")
    self.assertEqual(payload["tool_name"], "CodeMender")
    self.assertTrue(payload["sarif"])

  def test_upload_sarif_to_code_scanning_missing_file(self):
    """Verify upload_sarif_to_code_scanning returns None gracefully on missing file."""
    from codemender_agent.vcs.github import upload_sarif_to_code_scanning

    res = upload_sarif_to_code_scanning(
        token="valid-token",
        owner="example-org",
        repo="example-repo",
        sarif_path="/nonexistent/path/report.sarif",
        commit_sha="abcdef1234567890",
        ref="refs/heads/branch-4.0",
    )
    self.assertIsNone(res)


if __name__ == "__main__":
  unittest.main()
