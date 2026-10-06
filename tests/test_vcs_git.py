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

"""Unit tests for codemender_agent.vcs.git module."""

import base64
import os
import subprocess
import tempfile
import unittest

from codemender_agent.vcs.git import (
    enforce_https_url,
    filter_stageable_files,
    generate_branch_name,
    get_git_auth_header,
    normalize_repo_relative_path,
    parse_repo_owner_and_name,
    sanitize_git_url,
    setup_local_git_excludes,
)



class TestVcsGit(unittest.TestCase):

  def test_get_git_auth_header(self):
    """Verify the generation of HTTP Basic auth header for Git."""
    token = "fake_token"
    header = get_git_auth_header(token)
    expected_token_b64 = base64.b64encode(b"x-access-token:fake_token").decode(
        "utf-8"
    )
    self.assertEqual(
        header, f"http.extraheader=AUTHORIZATION: Basic {expected_token_b64}"
    )

  def test_enforce_https_url(self):
    """Verify SSH git repository URLs are correctly converted to HTTPS."""
    test_cases = [
        (
            "git@github.com:my-org/my-repo.git",
            "https://github.com/my-org/my-repo.git",
        ),
        (
            "ssh://git@github.com/my-org/my-repo.git",
            "https://github.com/my-org/my-repo.git",
        ),
        ("git@github.corp.com:org/repo", "https://github.corp.com/org/repo"),
        ("https://github.com/org/repo.git", "https://github.com/org/repo.git"),
    ]
    for url, expected in test_cases:
      with self.subTest(url=url):
        self.assertEqual(enforce_https_url(url), expected)

  def test_sanitize_git_url(self):
    """Verify embedded credentials and parameters are removed from Git URLs."""
    test_cases = [
        (
            "https://github.com/my-org/my-repo.git",
            "https://github.com/my-org/my-repo.git",
        ),
        (
            "https://x-access-token:token123@github.com/my-org/my-repo.git",
            "https://github.com/my-org/my-repo.git",
        ),
        (
            "http://user:pass@github.corp.com:8443/org/repo?branch=main#readme",
            "http://github.corp.com:8443/org/repo",
        ),
        ("git@github.com:org/repo.git", "https://github.com/org/repo.git"),
    ]
    for url, expected in test_cases:
      with self.subTest(url=url):
        self.assertEqual(sanitize_git_url(url), expected)

  def test_parse_repo_owner_and_name(self):
    """Verify parsing owner and repo name from GitHub URLs."""
    owner, repo = parse_repo_owner_and_name(
        "https://github.com/my-org/my-repo.git"
    )
    self.assertEqual(owner, "my-org")
    self.assertEqual(repo, "my-repo")

  def test_generate_branch_name(self):
    """Verify creation of idempotent branch names."""
    branch = generate_branch_name("SQL Injection", "abcdef1234567890")
    self.assertEqual(branch, "codemender/fix-sql-injection-abcdef12")



  def test_normalize_repo_relative_path(self):
    """Verify normalize_repo_relative_path strips leading CI runner mount patterns and paths."""
    test_cases = [
        (
            "/__w/juice-shop-local/juice-shop-local/juice-shop-local/routes/profileImageUrlUpload.ts",
            "/__w/juice-shop-local/juice-shop-local/juice-shop-local",
            "routes/profileImageUrlUpload.ts",
        ),
        (
            "/__w/juice-shop-local/juice-shop-local/juice-shop-local/routes/profileImageUrlUpload.ts",
            None,
            "routes/profileImageUrlUpload.ts",
        ),
        (
            "/workspace/juice-shop-local/routes/profileImageUrlUpload.ts",
            "/workspace/juice-shop-local",
            "routes/profileImageUrlUpload.ts",
        ),
        (
            "/github/workspace/routes/profileImageUrlUpload.ts",
            None,
            "routes/profileImageUrlUpload.ts",
        ),
        (
            "./routes/profileImageUrlUpload.ts",
            None,
            "routes/profileImageUrlUpload.ts",
        ),
        (
            "routes/profileImageUrlUpload.ts",
            None,
            "routes/profileImageUrlUpload.ts",
        ),
    ]
    for path, repo_dir, expected in test_cases:
      with self.subTest(path=path, repo_dir=repo_dir):
        self.assertEqual(normalize_repo_relative_path(path, repo_dir=repo_dir), expected)

  def test_setup_local_git_excludes(self):
    """Verify local git excludes are correctly appended without duplicates."""
    with tempfile.TemporaryDirectory() as repo_dir:
      git_info_dir = os.path.join(repo_dir, ".git", "info")
      os.makedirs(git_info_dir, exist_ok=True)
      exclude_path = os.path.join(git_info_dir, "exclude")

      setup_local_git_excludes(repo_dir)

      self.assertTrue(os.path.exists(exclude_path))
      with open(exclude_path, "r") as f:
        content = f.read()

      self.assertIn(".cm_project", content)
      self.assertIn(".exploit", content)
      self.assertIn(".codemender_cache", content)

  def test_sanitize_exploit_and_artifacts(self):
    """Verify sanitize_exploit_and_artifacts removes junk build caches while preserving exploit files."""
    from codemender_agent.vcs.git import sanitize_exploit_and_artifacts

    with tempfile.TemporaryDirectory() as repo_dir:
      with tempfile.TemporaryDirectory() as cm_home:
        # Create .exploit directory with valid files and junk build directories
        exploit_dir = os.path.join(repo_dir, ".exploit")
        os.makedirs(os.path.join(exploit_dir, ".cache", "node-gyp", "node"), exist_ok=True)
        os.makedirs(os.path.join(exploit_dir, "node_modules", "express"), exist_ok=True)
        os.makedirs(os.path.join(exploit_dir, "venv", "bin"), exist_ok=True)
        os.makedirs(os.path.join(exploit_dir, "__pycache__"), exist_ok=True)

        valid_poc = os.path.join(exploit_dir, "exploit.py")
        valid_payload = os.path.join(exploit_dir, "payload.json")
        with open(valid_poc, "w") as f:
          f.write("print('poc')")
        with open(valid_payload, "w") as f:
          f.write("{}")

        # Create artifacts directory with junk build cache
        artifacts_dir = os.path.join(cm_home, "artifacts", "finding_123")
        os.makedirs(os.path.join(artifacts_dir, ".cache"), exist_ok=True)
        os.makedirs(os.path.join(artifacts_dir, "node_modules"), exist_ok=True)
        valid_artifact_file = os.path.join(artifacts_dir, "exploit.py")
        with open(valid_artifact_file, "w") as f:
          f.write("print('poc')")

        sanitize_exploit_and_artifacts(repo_dir, codemender_home=cm_home)

        # Assert valid files are preserved
        self.assertTrue(os.path.exists(valid_poc))
        self.assertTrue(os.path.exists(valid_payload))
        self.assertTrue(os.path.exists(valid_artifact_file))

        # Assert junk directories are removed
        self.assertFalse(os.path.exists(os.path.join(exploit_dir, ".cache")))
        self.assertFalse(os.path.exists(os.path.join(exploit_dir, "node_modules")))
        self.assertFalse(os.path.exists(os.path.join(exploit_dir, "venv")))
        self.assertFalse(os.path.exists(os.path.join(exploit_dir, "__pycache__")))
        self.assertFalse(os.path.exists(os.path.join(artifacts_dir, ".cache")))
        self.assertFalse(os.path.exists(os.path.join(artifacts_dir, "node_modules")))

  def test_filter_stageable_files(self):
    """Verify filter_stageable_files normalizes, deduplicates, and excludes metadata and ignored files."""
    with tempfile.TemporaryDirectory() as repo_dir:
      # Initialize git repository
      subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
      setup_local_git_excludes(repo_dir)

      # Create user repository .gitignore
      with open(os.path.join(repo_dir, ".gitignore"), "w") as f:
        f.write("*.log\nnode_modules/\n")

      # Create valid source file and directories
      routes_dir = os.path.join(repo_dir, "routes")
      os.makedirs(routes_dir, exist_ok=True)
      valid_source = os.path.join(routes_dir, "userProfile.ts")
      with open(valid_source, "w") as f:
        f.write("console.log('profile');")

      # Create exploit directory and exploit script
      exploit_dir = os.path.join(repo_dir, ".exploit")
      os.makedirs(exploit_dir, exist_ok=True)
      exploit_file = os.path.join(exploit_dir, "exploit.sh")
      with open(exploit_file, "w") as f:
        f.write("#!/bin/bash\necho evil")

      # Create internal metadata directories and files
      cm_project_dir = os.path.join(repo_dir, ".cm_project")
      os.makedirs(cm_project_dir, exist_ok=True)
      with open(os.path.join(cm_project_dir, "state.json"), "w") as f:
        f.write("{}")

      # Create git-ignored log file
      with open(os.path.join(repo_dir, "debug.log"), "w") as f:
        f.write("debug")

      raw_edited_files = [
          # Duplicates of absolute path
          valid_source,
          valid_source,
          # CI runner mount path pattern
          f"/__w/juice-shop-local/juice-shop-local/juice-shop-local/routes/userProfile.ts",
          # Relative path with ./
          "./routes/userProfile.ts",
          # Exploit paths (MUST be excluded)
          exploit_file,
          f"/__w/juice-shop-local/juice-shop-local/juice-shop-local/.exploit/exploit.sh",
          ".exploit/exploit.sh",
          # Internal metadata paths (MUST be excluded)
          ".cm_project/state.json",
          ".codemender_cache/cache.dat",
          ".codemender/config.yaml",
          # Git-ignored file (*.log)
          "debug.log",
          # Non-existent file
          "routes/non_existent.ts",
          # Falsy / invalid items
          "",
          None,
      ]

      stageable = filter_stageable_files(repo_dir, raw_edited_files)

      # Should only contain 'routes/userProfile.ts' exactly once
      self.assertEqual(stageable, ["routes/userProfile.ts"])


if __name__ == "__main__":
  unittest.main()
