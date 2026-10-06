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

"""Unit tests for codemender_agent.config module."""

import os
import tempfile
import unittest
import unittest.mock

from codemender_agent.config import get_cleanup_ports
from codemender_agent.config import get_github_credentials
from codemender_agent.config import get_scrubbed_env
from codemender_agent.config import inject_codemender_config
import yaml




class TestConfig(unittest.TestCase):

  def test_credential_scrubbing(self):
    """Verify sensitive credentials are scrubbed from environment variables."""
    test_env = {
        "PATH": "/usr/bin",
        "GITHUB_APP_TOKEN": "secret_app_token",
        "GITHUB_PAT": "secret_pat",
        "GITHUB_TOKEN": "secret_token",
        "GH_TOKEN": "secret_gh_token",
        "GITHUB_SECRET": "secret_github",
        "CUSTOM_VAR": "keep_me",
    }
    with unittest.mock.patch.dict(os.environ, test_env, clear=True):
      scrubbed = get_scrubbed_env()
      self.assertIn("PATH", scrubbed)
      self.assertIn("CUSTOM_VAR", scrubbed)
      self.assertNotIn("GITHUB_APP_TOKEN", scrubbed)
      self.assertNotIn("GITHUB_PAT", scrubbed)
      self.assertNotIn("GITHUB_TOKEN", scrubbed)
      self.assertNotIn("GH_TOKEN", scrubbed)
      self.assertNotIn("GITHUB_SECRET", scrubbed)

  def test_credential_scrubbing_github_app_and_actions_tokens(self):
    """GitHub App settings and Actions runtime tokens never reach cm."""
    test_env = {
        "PATH": "/usr/bin",
        "GH_APP_ID": "12345",
        "GH_APP_KEY": "-----BEGIN PRIVATE KEY-----",
        "GH_APP_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----",
        "GH_APP_SOMETHING_NEW": "x",
        "GITHUB_APP_CLIENT_ID": "Iv1.abc",
        "CUSTOM_GITHUB_TOKEN": "ghp_x",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "oidc",
        "ACTIONS_ID_TOKEN_REQUEST_URL": "https://example.invalid/oidc",
        "ACTIONS_RUNTIME_TOKEN": "rt",
        "WIZ_CLIENT_SECRET": "w",
        "GOOGLE_APPLICATION_CREDENTIALS": "/runner/temp/creds.json",
        "GOOGLE_CLOUD_PROJECT": "proj",
    }
    with unittest.mock.patch.dict(os.environ, test_env, clear=True):
      scrubbed = get_scrubbed_env()
    for name in (
        "GH_APP_ID",
        "GH_APP_KEY",
        "GH_APP_PRIVATE_KEY",
        "GH_APP_SOMETHING_NEW",
        "GITHUB_APP_CLIENT_ID",
        "CUSTOM_GITHUB_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_RUNTIME_TOKEN",
        "WIZ_CLIENT_SECRET",
    ):
      self.assertNotIn(name, scrubbed)
    # cm needs these to reach Vertex AI.
    self.assertEqual(
        scrubbed["GOOGLE_APPLICATION_CREDENTIALS"], "/runner/temp/creds.json"
    )
    self.assertEqual(scrubbed["GOOGLE_CLOUD_PROJECT"], "proj")
    self.assertEqual(scrubbed["PATH"], "/usr/bin")

  def test_credential_like_env_names_lists_names_only(self):
    """credential_like_env_names returns sorted names and never values."""
    from codemender_agent.config import credential_like_env_names

    env = {
        "PATH": "/usr/bin",
        "GOOGLE_APPLICATION_CREDENTIALS": "/x.json",
        "SOME_API_KEY": "value-should-not-appear",
        "MY_TOKEN": "t",
        "HOME": "/root",
    }
    names = credential_like_env_names(env)
    self.assertEqual(
        names, ["GOOGLE_APPLICATION_CREDENTIALS", "MY_TOKEN", "SOME_API_KEY"]
    )
    self.assertNotIn("value-should-not-appear", " ".join(names))
    self.assertEqual(credential_like_env_names({"PATH": "/bin"}), [])

  def test_get_scrubbed_env_with_repo_dir(self):
    """Verify get_scrubbed_env creates and configures local .codemender_cache paths."""
    with tempfile.TemporaryDirectory() as repo_dir:
      with unittest.mock.patch.dict(
          os.environ, {"CODEMENDER_SANDBOX_ENABLED": "false"}, clear=True
      ):
        scrubbed = get_scrubbed_env(repo_dir=repo_dir)
      expected_cache = os.path.join(repo_dir, ".codemender_cache")
      self.assertEqual(scrubbed.get("XDG_CACHE_HOME"), expected_cache)
      self.assertEqual(scrubbed.get("npm_config_cache"), os.path.join(expected_cache, "npm"))
      self.assertEqual(scrubbed.get("TMPDIR"), os.path.join(expected_cache, "tmp"))
      self.assertEqual(scrubbed.get("PIP_CACHE_DIR"), os.path.join(expected_cache, "pip"))
      self.assertTrue(os.path.isdir(os.path.join(expected_cache, "tmp")))
      self.assertTrue(os.path.isdir(os.path.join(expected_cache, "npm")))
      self.assertTrue(os.path.isdir(os.path.join(expected_cache, "pip")))

  def test_get_scrubbed_env_with_repo_dir_sandbox_leaves_tmpdir_unset(self):
    """With the sandbox on, TMPDIR is not set: cm denies $TMPDIR inside the sandbox."""
    with tempfile.TemporaryDirectory() as repo_dir:
      with unittest.mock.patch.dict(
          os.environ,
          {"CODEMENDER_SANDBOX_ENABLED": "true", "TMPDIR": "/somewhere/tmp"},
          clear=True,
      ):
        scrubbed = get_scrubbed_env(repo_dir=repo_dir)
      tmp_dir = os.path.join(repo_dir, ".codemender_cache", "tmp")
      self.assertNotIn("TMPDIR", scrubbed)
      self.assertEqual(scrubbed.get("TEMP"), tmp_dir)
      self.assertEqual(scrubbed.get("TMP"), tmp_dir)
      self.assertEqual(scrubbed.get("GOTMPDIR"), tmp_dir)
      self.assertTrue(os.path.isdir(tmp_dir))
      # Default (variable unset) is sandbox on.
      with unittest.mock.patch.dict(os.environ, {}, clear=True):
        self.assertNotIn("TMPDIR", get_scrubbed_env(repo_dir=repo_dir))

  def test_orchestrator_config_allow_unsandboxed_fallback(self):
    """CODEMENDER_ALLOW_UNSANDBOXED_FALLBACK is opt-in and defaults to False."""
    from codemender_agent.config import OrchestratorConfig

    with unittest.mock.patch.dict(os.environ, {}, clear=True):
      self.assertFalse(OrchestratorConfig.from_env().allow_unsandboxed_fallback)
    for val in ("false", "0", "no", "", "maybe"):
      with unittest.mock.patch.dict(
          os.environ, {"CODEMENDER_ALLOW_UNSANDBOXED_FALLBACK": val}, clear=True
      ):
        self.assertFalse(
            OrchestratorConfig.from_env().allow_unsandboxed_fallback, val
        )
    for val in ("true", "TRUE", "1", "yes", " true "):
      with unittest.mock.patch.dict(
          os.environ, {"CODEMENDER_ALLOW_UNSANDBOXED_FALLBACK": val}, clear=True
      ):
        self.assertTrue(
            OrchestratorConfig.from_env().allow_unsandboxed_fallback, val
        )

  def test_get_github_credentials_success(self):
    """Verify credentials extraction from environment."""
    test_env = {
        "GITHUB_REPO_URL": "https://github.com/my-org/my-repo.git",
        "GITHUB_TOKEN": "valid_token",
    }
    with unittest.mock.patch.dict(os.environ, test_env, clear=True):
      repo_url, token = get_github_credentials()
      self.assertEqual(repo_url, "https://github.com/my-org/my-repo.git")
      self.assertEqual(token, "valid_token")

  def test_inject_codemender_config_repo_level(self):
    """Verify repository-level .codemender.yaml overrides build command."""
    with tempfile.TemporaryDirectory() as temp_home:
      with tempfile.TemporaryDirectory() as repo_dir:
        local_config = {
            "build": {"command": "npm run test:security"},
            "scan": {"paths": ["src/"]},
        }
        with open(os.path.join(repo_dir, ".codemender.yaml"), "w") as f:
          yaml.dump(local_config, f)

        with unittest.mock.patch("os.path.expanduser", return_value=temp_home):
          inject_codemender_config(repo_dir)

          out_config = os.path.join(temp_home, ".codemender", "config.yaml")
          self.assertTrue(os.path.exists(out_config))

          with open(out_config, "r") as f:
            data = yaml.safe_load(f)

          self.assertEqual(data["build"]["command"], "npm run test:security")
          self.assertFalse(data["tools"]["confirm_commands"])

  def test_get_cleanup_ports_default(self):
    """Verify get_cleanup_ports returns default list when env is unset."""
    with unittest.mock.patch.dict(os.environ, {}, clear=True):
      ports = get_cleanup_ports()
      self.assertEqual(ports, [3000, 3001, 5000, 8000, 8080, 8081, 9000])

  def test_get_cleanup_ports_override(self):
    """Verify get_cleanup_ports parses comma-separated override list."""
    test_env = {"CODEMENDER_CLEANUP_PORTS": "3000, 8080, 9999"}
    with unittest.mock.patch.dict(os.environ, test_env, clear=True):
      ports = get_cleanup_ports()
      self.assertEqual(ports, [3000, 8080, 9999])

  def test_get_cleanup_ports_invalid_fallback(self):
    """Verify get_cleanup_ports falls back to default on parse errors."""
    test_env = {"CODEMENDER_CLEANUP_PORTS": "3000, abc, 9999"}
    with unittest.mock.patch.dict(os.environ, test_env, clear=True):
      ports = get_cleanup_ports()
      self.assertEqual(ports, [3000, 3001, 5000, 8000, 8080, 8081, 9000])





  def test_inject_codemender_config_sandbox(self):
    """Verify sandbox settings and project_paths normalization in config.yaml."""
    with tempfile.TemporaryDirectory() as temp_home:
      with tempfile.TemporaryDirectory() as repo_dir:
        local_config = {
            "build": {"command": "npm test"},
            "project_paths": ["src", "routes", os.path.abspath("/custom/abs/path")],
        }
        with open(os.path.join(repo_dir, ".codemender.yaml"), "w") as f:
          yaml.dump(local_config, f)

        with unittest.mock.patch("os.path.expanduser", return_value=temp_home):
          inject_codemender_config(repo_dir)

          out_config = os.path.join(temp_home, ".codemender", "config.yaml")
          self.assertTrue(os.path.exists(out_config))

          with open(out_config, "r") as f:
            data = yaml.safe_load(f)

          # Verify sandbox defaults
          self.assertIn("sandbox", data)
          self.assertTrue(data["sandbox"]["enabled"])
          self.assertEqual(data["sandbox"]["mounts"]["target_dir"], os.path.abspath(repo_dir))
          self.assertEqual(data["sandbox"]["network"]["profile"], "permissive-open")

          # Verify project_paths are all absolute
          self.assertIn("project_paths", data)
          for p in data["project_paths"]:
            self.assertTrue(os.path.isabs(p), f"Path {p} is not absolute")
          self.assertIn(os.path.abspath(os.path.join(repo_dir, "src")), data["project_paths"])
          self.assertIn(os.path.abspath(os.path.join(repo_dir, "routes")), data["project_paths"])
          self.assertIn(os.path.abspath("/custom/abs/path"), data["project_paths"])

  def test_detect_build_command_nodejs(self):
    """Verify detect_build_command finds npm test in package.json."""
    from codemender_agent.config import detect_build_command
    with tempfile.TemporaryDirectory() as repo_dir:
      with open(os.path.join(repo_dir, "package.json"), "w") as f:
        f.write('{"name": "test-pkg", "scripts": {"test": "mocha"}}')
      self.assertEqual(detect_build_command(repo_dir), "npm test")

  def test_detect_build_command_python(self):
    """Verify detect_build_command finds pytest when pyproject.toml exists."""
    from codemender_agent.config import detect_build_command
    with tempfile.TemporaryDirectory() as repo_dir:
      with open(os.path.join(repo_dir, "pyproject.toml"), "w") as f:
        f.write("[tool.pytest]")
      self.assertEqual(detect_build_command(repo_dir), "pytest")

  def test_detect_build_command_go(self):
    """Verify detect_build_command finds go test when go.mod exists."""
    from codemender_agent.config import detect_build_command
    with tempfile.TemporaryDirectory() as repo_dir:
      with open(os.path.join(repo_dir, "go.mod"), "w") as f:
        f.write("module example.com/test")
      self.assertEqual(detect_build_command(repo_dir), "go test ./...")

  def test_inject_codemender_config_auto_detects_build_command(self):
    """Verify inject_codemender_config auto-detects build command if unset."""
    with tempfile.TemporaryDirectory() as temp_home:
      with tempfile.TemporaryDirectory() as repo_dir:
        with open(os.path.join(repo_dir, "package.json"), "w") as f:
          f.write('{"scripts": {"test": "jest"}}')
        with unittest.mock.patch("os.path.expanduser", return_value=temp_home):
          inject_codemender_config(repo_dir)
          out_config = os.path.join(temp_home, ".codemender", "config.yaml")
          with open(out_config, "r") as f:
            data = yaml.safe_load(f)
          self.assertEqual(data["build"]["command"], "npm test")

  def test_inject_codemender_config_env_override_takes_precedence(self):
    """Verify env override CODEMENDER_BUILD_COMMAND takes precedence over repo config."""
    from codemender_agent.config import OrchestratorConfig
    with tempfile.TemporaryDirectory() as temp_home:
      with tempfile.TemporaryDirectory() as repo_dir:
        local_config = {"build": {"command": "npm test"}}
        with open(os.path.join(repo_dir, ".codemender.yaml"), "w") as f:
          yaml.dump(local_config, f)
        test_env = {"CODEMENDER_BUILD_COMMAND": "npm run custom:test"}
        with unittest.mock.patch.dict(os.environ, test_env, clear=True):
          cfg = OrchestratorConfig.from_env()
          with unittest.mock.patch("os.path.expanduser", return_value=temp_home):
            inject_codemender_config(repo_dir, config=cfg)
            out_config = os.path.join(temp_home, ".codemender", "config.yaml")
            with open(out_config, "r") as f:
              data = yaml.safe_load(f)
            self.assertEqual(data["build"]["command"], "npm run custom:test")

  def test_inject_codemender_config_composite_build_command(self):
    """Verify composite build commands with ampersands are safely preserved."""
    from codemender_agent.config import OrchestratorConfig
    with tempfile.TemporaryDirectory() as temp_home:
      with tempfile.TemporaryDirectory() as repo_dir:
        test_env = {"CODEMENDER_BUILD_COMMAND": "npm install && npm test"}
        with unittest.mock.patch.dict(os.environ, test_env, clear=True):
          cfg = OrchestratorConfig.from_env()
          with unittest.mock.patch("os.path.expanduser", return_value=temp_home):
            inject_codemender_config(repo_dir, config=cfg)
            out_config = os.path.join(temp_home, ".codemender", "config.yaml")
            with open(out_config, "r") as f:
              data = yaml.safe_load(f)
            self.assertEqual(data["build"]["command"], "npm install && npm test")

  def test_orchestrator_config_skip_verify_default(self):
    """Verify skip_verify defaults to True when CODEMENDER_SKIP_VERIFY is unset."""
    from codemender_agent.config import OrchestratorConfig
    with unittest.mock.patch.dict(os.environ, {}, clear=True):
      cfg = OrchestratorConfig.from_env()
      self.assertTrue(cfg.skip_verify)

  def test_orchestrator_config_skip_verify_false(self):
    """Verify skip_verify is False when CODEMENDER_SKIP_VERIFY is false/0/no."""
    from codemender_agent.config import OrchestratorConfig
    for false_val in ("false", "0", "no"):
      with unittest.mock.patch.dict(
          os.environ, {"CODEMENDER_SKIP_VERIFY": false_val}, clear=True
      ):
        cfg = OrchestratorConfig.from_env()
        self.assertFalse(
            cfg.skip_verify,
            f"Expected False for CODEMENDER_SKIP_VERIFY={false_val}",
        )

  def test_orchestrator_config_skip_verify_true(self):
    """Verify skip_verify is True when CODEMENDER_SKIP_VERIFY is true/1/yes."""
    from codemender_agent.config import OrchestratorConfig
    for true_val in ("true", "1", "yes"):
      with unittest.mock.patch.dict(
          os.environ, {"CODEMENDER_SKIP_VERIFY": true_val}, clear=True
      ):
        cfg = OrchestratorConfig.from_env()
        self.assertTrue(
            cfg.skip_verify,
            f"Expected True for CODEMENDER_SKIP_VERIFY={true_val}",
        )

  def test_orchestrator_config_target_branch_and_execution_url(self):
    """Verify CODEMENDER_TARGET_BRANCH and CODEMENDER_EXECUTION_URL parsing."""
    from codemender_agent.config import OrchestratorConfig
    with unittest.mock.patch.dict(
        os.environ,
        {
            "CODEMENDER_TARGET_BRANCH": "refs/heads/release/v1.0",
            "CODEMENDER_EXECUTION_URL": "https://console.cloud.google.com/workflows",
        },
        clear=True,
    ):
      cfg = OrchestratorConfig.from_env()
      self.assertEqual(cfg.target_branch, "release/v1.0")
      self.assertEqual(
          cfg.execution_url, "https://console.cloud.google.com/workflows"
      )

  def test_get_scrubbed_env_cm_disable_sandbox(self):
    """Verify CM_DISABLE_SANDBOX is set when CODEMENDER_SANDBOX_ENABLED=false."""
    with unittest.mock.patch.dict(
        os.environ, {"CODEMENDER_SANDBOX_ENABLED": "false"}, clear=True
    ):
      scrubbed = get_scrubbed_env()
      self.assertEqual(scrubbed.get("CM_DISABLE_SANDBOX"), "true")

    with unittest.mock.patch.dict(
        os.environ, {"CODEMENDER_SANDBOX_ENABLED": "true"}, clear=True
    ):
      scrubbed = get_scrubbed_env()
      self.assertNotIn("CM_DISABLE_SANDBOX", scrubbed)

  def test_inject_codemender_config_default_empty_project_paths(self):
    """Verify inject_codemender_config clears project_paths written by cm init unless .codemender.yaml specifies them."""
    with tempfile.TemporaryDirectory() as temp_home:
      with tempfile.TemporaryDirectory() as repo_dir:
        with open(os.path.join(repo_dir, "pyproject.toml"), "w") as f:
          f.write("[tool.pytest]")
        cm_dir = os.path.join(temp_home, ".codemender")
        os.makedirs(cm_dir, exist_ok=True)
        with open(os.path.join(cm_dir, "config.yaml"), "w") as f:
          yaml.dump({"project_paths": [repo_dir]}, f)

        with unittest.mock.patch("os.path.expanduser", return_value=temp_home):
          inject_codemender_config(repo_dir)
          with open(os.path.join(cm_dir, "config.yaml"), "r") as f:
            data = yaml.safe_load(f)
          self.assertEqual(data["project_paths"], [])

  def _inject_and_read(self, temp_home, repo_dir, **kwargs):
    with unittest.mock.patch("os.path.expanduser", return_value=temp_home):
      inject_codemender_config(repo_dir, **kwargs)
    with open(
        os.path.join(temp_home, ".codemender", "config.yaml"), "r"
    ) as f:
      return yaml.safe_load(f)

  def test_inject_codemender_config_remediation_uses_repo_root(self):
    """Verify and fix get the repository root as their only project path."""
    with tempfile.TemporaryDirectory() as temp_home:
      with tempfile.TemporaryDirectory() as repo_dir:
        with open(os.path.join(repo_dir, "pom.xml"), "w") as f:
          f.write("<project/>")
        data = self._inject_and_read(temp_home, repo_dir, for_remediation=True)
        self.assertEqual(data["project_paths"], [os.path.abspath(repo_dir)])

  def test_inject_codemender_config_find_scope_unchanged_by_default(self):
    """Find (the default) still clears project_paths, even after a remediation injection."""
    with tempfile.TemporaryDirectory() as temp_home:
      with tempfile.TemporaryDirectory() as repo_dir:
        with open(os.path.join(repo_dir, "go.mod"), "w") as f:
          f.write("module example.com/x\n")
        # The config file is shared by every stage in a container, so the
        # scope has to follow the latest injection in both directions.
        data = self._inject_and_read(temp_home, repo_dir, for_remediation=True)
        self.assertEqual(data["project_paths"], [os.path.abspath(repo_dir)])
        data = self._inject_and_read(temp_home, repo_dir)
        self.assertEqual(data["project_paths"], [])
        data = self._inject_and_read(temp_home, repo_dir, for_remediation=False)
        self.assertEqual(data["project_paths"], [])

  def test_inject_codemender_config_remediation_normalizes_relative_repo_dir(self):
    """A relative repo_dir is written as an absolute path for cm."""
    with tempfile.TemporaryDirectory() as temp_home:
      with tempfile.TemporaryDirectory() as parent:
        repo_dir = os.path.join(parent, "repo")
        os.makedirs(repo_dir)
        with open(os.path.join(repo_dir, "Cargo.toml"), "w") as f:
          f.write("[package]\n")
        cwd = os.getcwd()
        os.chdir(parent)
        try:
          data = self._inject_and_read(temp_home, "repo", for_remediation=True)
        finally:
          os.chdir(cwd)
        self.assertEqual(data["project_paths"], [os.path.abspath(repo_dir)])

  def test_inject_codemender_config_remediation_repo_config_wins(self):
    """A project_paths set in the repository's config file overrides the remediation default."""
    with tempfile.TemporaryDirectory() as temp_home:
      with tempfile.TemporaryDirectory() as repo_dir:
        with open(os.path.join(repo_dir, ".codemender.yaml"), "w") as f:
          yaml.dump(
              {"build": {"command": "make"}, "project_paths": ["services/api"]},
              f,
          )
        expected = [os.path.abspath(os.path.join(repo_dir, "services/api"))]
        data = self._inject_and_read(temp_home, repo_dir, for_remediation=True)
        self.assertEqual(data["project_paths"], expected)
        data = self._inject_and_read(temp_home, repo_dir)
        self.assertEqual(data["project_paths"], expected)

  def test_inject_codemender_config_remediation_repo_config_empty_list_wins(self):
    """An explicit empty project_paths in the repository config is honored for remediation too."""
    with tempfile.TemporaryDirectory() as temp_home:
      with tempfile.TemporaryDirectory() as repo_dir:
        with open(os.path.join(repo_dir, ".codemender.yaml"), "w") as f:
          yaml.dump({"build": {"command": "make"}, "project_paths": []}, f)
        data = self._inject_and_read(temp_home, repo_dir, for_remediation=True)
        self.assertEqual(data["project_paths"], [])

  def test_inject_codemender_config_removes_stale_model_when_unset(self):
    """Verify inject_codemender_config strips stale model from ~/.codemender/config.yaml when CODEMENDER_MODEL is empty."""
    from codemender_agent.config import OrchestratorConfig
    with tempfile.TemporaryDirectory() as temp_home:
      with tempfile.TemporaryDirectory() as repo_dir:
        cm_dir = os.path.join(temp_home, ".codemender")
        os.makedirs(cm_dir, exist_ok=True)
        with open(os.path.join(cm_dir, "config.yaml"), "w") as f:
          yaml.dump({"model": "stale-configured-model"}, f)

        with unittest.mock.patch.dict(
            os.environ,
            {"CODEMENDER_MODEL": "", "CODEMENDER_BUILD_COMMAND": "pytest"},
            clear=True,
        ):
          cfg = OrchestratorConfig.from_env()
          with unittest.mock.patch("os.path.expanduser", return_value=temp_home):
            inject_codemender_config(repo_dir, config=cfg)
            with open(os.path.join(cm_dir, "config.yaml"), "r") as f:
              data = yaml.safe_load(f)
            self.assertNotIn("model", data)


if __name__ == "__main__":
  unittest.main()
