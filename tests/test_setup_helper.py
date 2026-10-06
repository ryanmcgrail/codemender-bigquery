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

"""Tests for the codemender-setup wrapper, CLI, YAML helpers and validate."""

import ast
import io
import os
import pathlib
import shutil
import subprocess
import sys
import unittest

from tests.setup_helper_testlib import FakeRunner, TempDirMixin, SETUP_DIR, ROOT, make_context, make_repo, ok, fail

from codemender_setup import cli  # pylint: disable=g-bad-import-order
from codemender_setup import common
from codemender_setup import validate
from codemender_setup import yamlio

WRAPPER = SETUP_DIR / "codemender-setup"


class Python39AndShellSyntaxTest(unittest.TestCase):

  def test_package_parses_as_python_3_9(self):
    files = sorted((SETUP_DIR / "codemender_setup").glob("*.py"))
    self.assertTrue(files)
    for path in files:
      with self.subTest(path=path.name):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path), feature_version=(3, 9))

  def test_package_uses_only_the_standard_library(self):
    allowed_third_party = set()
    stdlib = getattr(sys, "stdlib_module_names", None)
    if stdlib is None:
      self.skipTest("needs Python 3.10+ to list standard library modules")
    for path in sorted((SETUP_DIR / "codemender_setup").glob("*.py")):
      tree = ast.parse(path.read_text(encoding="utf-8"))
      for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.Import):
          names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
          names = [node.module]
        for name in names:
          top = name.split(".")[0]
          if top == "codemender_setup":
            continue
          with self.subTest(path=path.name, module=name):
            self.assertTrue(top in stdlib or top in allowed_third_party, name)

  def test_wrapper_is_posix_sh(self):
    sh = shutil.which("sh")
    if not sh:
      self.skipTest("sh not available")
    self.assertTrue(os.access(WRAPPER, os.X_OK), "wrapper must be executable")
    first = WRAPPER.read_text(encoding="utf-8").splitlines()[0]
    self.assertEqual(first, "#!/bin/sh")
    res = subprocess.run([sh, "-n", str(WRAPPER)], capture_output=True, text=True, check=False)
    self.assertEqual(res.returncode, 0, res.stderr)

  def test_wrapper_runs_the_package(self):
    sh = shutil.which("sh")
    if not sh:
      self.skipTest("sh not available")
    env = dict(os.environ, CODEMENDER_SETUP_PYTHON=sys.executable)
    res = subprocess.run([sh, str(WRAPPER), "--version"], capture_output=True, text=True,
                         check=False, env=env, cwd=str(ROOT))
    self.assertEqual(res.returncode, 0, res.stderr)
    self.assertIn("codemender-setup", res.stdout)

  def test_wrapper_rejects_old_python(self):
    sh = shutil.which("sh")
    if not sh:
      self.skipTest("sh not available")
    env = dict(os.environ, CODEMENDER_SETUP_PYTHON="false")
    res = subprocess.run([sh, str(WRAPPER), "--version"], capture_output=True, text=True,
                         check=False, env=env)
    self.assertEqual(res.returncode, 2)
    self.assertIn("too old", res.stderr)


class CliTest(TempDirMixin, unittest.TestCase):

  def _main(self, argv, root=None, **ctx_kwargs):
    contexts = []

    def factory(**kwargs):
      ctx = make_context(kwargs.pop("repo_root"), **ctx_kwargs, **kwargs)
      contexts.append(ctx)
      return ctx

    code = cli.main(argv, context_factory=factory)
    return code, (contexts[0] if contexts else None)

  def test_no_command_is_a_usage_error(self):
    root = make_repo(self.tmp)
    code, _ = self._main(["--repo-root", str(root)])
    self.assertEqual(code, common.EXIT_USAGE)

  def test_unknown_flag_is_a_usage_error(self):
    code, _ = self._main(["check", "--bogus"])
    self.assertEqual(code, common.EXIT_USAGE)

  def test_repo_root_must_be_a_copy(self):
    code, _ = self._main(["--repo-root", str(self.tmp), "validate"])
    self.assertEqual(code, common.EXIT_USAGE)

  def test_flags_work_before_and_after_the_command(self):
    root = make_repo(self.tmp)
    for argv in (["--yes", "--repo-root", str(root), "validate", "--skip-terraform"],
                 ["validate", "--repo-root", str(root), "--yes", "--skip-terraform"]):
      with self.subTest(argv=argv):
        code, ctx = self._main(argv)
        self.assertEqual(code, common.EXIT_OK, ctx.out.getvalue() if ctx else "")
        self.assertTrue(ctx.yes)
        self.assertFalse(ctx.non_interactive)

  def test_usage_error_from_a_command_exits_2(self):
    root = make_repo(self.tmp)
    code, ctx = self._main(["--repo-root", str(root), "validate", "--repos", str(self.tmp / "missing.yaml")])
    self.assertEqual(code, common.EXIT_USAGE)
    self.assertIn("does not exist", ctx.err.getvalue())


class ContextPromptTest(TempDirMixin, unittest.TestCase):

  def test_non_interactive_uses_default_or_fails(self):
    ctx = make_context(self.tmp, non_interactive=True)
    self.assertEqual(ctx.ask("Region", default="us-central1"), "us-central1")
    with self.assertRaises(common.UsageError) as cm:
      ctx.ask("Project", flag="--project")
    self.assertIn("--project", str(cm.exception))

  def test_non_interactive_rejects_invalid_default(self):
    ctx = make_context(self.tmp, non_interactive=True)
    with self.assertRaises(common.UsageError):
      ctx.ask("Prefix", default="BAD", check=lambda v: None if v.islower() else "lowercase")

  def test_prompt_retries_until_valid(self):
    ctx = make_context(self.tmp, stdin="BAD\ngood\n")
    value = ctx.ask("Prefix", check=lambda v: None if v.islower() else "use lowercase")
    self.assertEqual(value, "good")
    self.assertIn("use lowercase", ctx.out.getvalue())

  def test_eof_cancels(self):
    ctx = make_context(self.tmp, stdin="")
    with self.assertRaises(common.Cancelled):
      ctx.ask("Project")

  def test_confirm(self):
    self.assertTrue(make_context(self.tmp, yes=True).confirm("Go?"))
    self.assertFalse(make_context(self.tmp, non_interactive=True).confirm("Go?"))
    self.assertTrue(make_context(self.tmp, stdin="y\n").confirm("Go?"))
    self.assertFalse(make_context(self.tmp, stdin="\n").confirm("Go?"))
    self.assertTrue(make_context(self.tmp, stdin="\n").confirm("Go?", default=True))


class CommonTest(unittest.TestCase):

  def test_prefix_rule_matches_terraform(self):
    for good in ("a", "cm", "codemender", "a" * 17, "cm-gitops", "a1"):
      self.assertRegex(good, common.PREFIX_RE)
    for bad in ("", "a" * 18, "-cm", "cm-", "Cm", "1cm", "cm_x"):
      self.assertNotRegex(bad, common.PREFIX_RE)

  def test_parse_github_remote(self):
    cases = {
        "https://github.com/acme/repo.git": ("github.com", "acme", "repo"),
        "https://github.com/acme/repo": ("github.com", "acme", "repo"),
        "git@github.com:acme/repo.git": ("github.com", "acme", "repo"),
        "ssh://git@github.com/acme/repo.git": ("github.com", "acme", "repo"),
        "https://acme.ghe.com/acme/repo.git": ("acme.ghe.com", "acme", "repo"),
    }
    for url, want in cases.items():
      self.assertEqual(common.parse_github_remote(url), want, url)
    self.assertIsNone(common.parse_github_remote("not a url"))

  def test_version_tuple(self):
    self.assertEqual(common.version_tuple("1.11.0"), (1, 11, 0))
    self.assertEqual(common.version_tuple("Terraform v1.13.3"), (1, 13, 3))
    self.assertEqual(common.version_tuple("v1.9"), (1, 9, 0))
    self.assertEqual(common.version_tuple("none"), ())
    self.assertLess(common.version_tuple("1.9.8"), common.MIN_TERRAFORM)

  def test_tf_env_scrubs_injected_values(self):
    base = {
        "PATH": "/bin", "HOME": "/home/x", "TF_PLUGIN_CACHE_DIR": "/cache",
        "TF_VAR_project_id": "other", "TF_CLI_ARGS": "-var=x=y", "TF_CLI_ARGS_plan": "-x",
        "TF_WORKSPACE": "ws", "TF_DATA_DIR": "/d",
        "GOOGLE_APPLICATION_CREDENTIALS": "/key.json", "GOOGLE_CREDENTIALS": "{}",
        "GOOGLE_IMPERSONATE_SERVICE_ACCOUNT": "sa@x", "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE": "/t",
    }
    online = common.tf_env(base)
    for name in ("TF_VAR_project_id", "TF_CLI_ARGS", "TF_CLI_ARGS_plan", "TF_WORKSPACE", "TF_DATA_DIR"):
      self.assertNotIn(name, online)
    self.assertEqual(online["GOOGLE_APPLICATION_CREDENTIALS"], "/key.json")
    self.assertEqual(online["TF_PLUGIN_CACHE_DIR"], "/cache")
    offline = common.tf_env(base, offline=True)
    self.assertEqual(offline["GOOGLE_APPLICATION_CREDENTIALS"], "/nonexistent/codemender-setup")
    for name in ("GOOGLE_CREDENTIALS", "GOOGLE_IMPERSONATE_SERVICE_ACCOUNT", "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE"):
      self.assertNotIn(name, offline)
    self.assertEqual(offline["TF_INPUT"], "0")


class YamlTest(unittest.TestCase):

  def test_scan_paths_and_comments(self):
    text = (
        "# header\n"
        "repositories:\n"
        "  svc:   # the service\n"
        "    repo_url: \"https://github.com/a/b.git\"  # url\n"
        "    build_command: |\n"
        "      make: all\n"
        "      echo done\n"
        "    wiz:\n"
        "      enabled: true\n"
        "  'quoted key':\n"
        "    repo_url: x\n"
    )
    entries = [(e.path, e.key, e.raw_value) for e in yamlio.scan(text)]
    self.assertIn((("repositories", "svc"), "repo_url", '"https://github.com/a/b.git"'), entries)
    self.assertIn((("repositories", "svc", "wiz"), "enabled", "true"), entries)
    self.assertIn((("repositories",), "quoted key", ""), entries)
    # Lines inside the block scalar are not keys.
    self.assertNotIn("make", [e[1] for e in entries])

  def test_duplicate_keys_any_level(self):
    text = "a: 1\nb:\n  c: 1\n  c: 2\na: 3\nd:\n  c: 1\n"
    dups = yamlio.duplicate_keys(text)
    self.assertEqual(sorted(dups), ["a (lines 1, 5)", "b.c (lines 3, 4)"])

  def test_sequences_do_not_count_as_duplicates(self):
    text = ("emails:\n  - a@x\n  - b@x\nlist:\n  - name: one\n    size: 1\n  - name: two\n"
            "flat:\n- name: a\n- name: b\n")
    self.assertEqual(yamlio.duplicate_keys(text), [])

  def test_duplicates_inside_one_sequence_item(self):
    text = "list:\n  - name: one\n    name: again\n  - name: two\n"
    self.assertEqual(yamlio.duplicate_keys(text), ["list.[0].name (lines 2, 3)"])

  def test_coercion_warnings(self):
    self.assertIn("boolean true", yamlio.coercion_warning("on"))
    self.assertIn("boolean false", yamlio.coercion_warning("No"))
    self.assertIn("number 123", yamlio.coercion_warning("0123"))
    for fine in ('"on"', "'0123'", "true", "123", "0", "us-central1", "0 3 * * 6", "1:30", ""):
      self.assertIsNone(yamlio.coercion_warning(fine), fine)

  def test_scalar_round_trips_as_strings(self):
    self.assertEqual(yamlio.scalar("on"), '"on"')
    self.assertEqual(yamlio.scalar("0123"), '"0123"')
    self.assertEqual(yamlio.scalar('a "b" \\ c'), '"a \\"b\\" \\\\ c"')
    self.assertEqual(yamlio.scalar(True), "true")
    self.assertEqual(yamlio.scalar(5), "5")
    self.assertEqual(yamlio.scalar(None), "null")

  def test_hcl_string_escapes_templates(self):
    self.assertEqual(yamlio.hcl_string("a${b}%{c}"), '"a$${b}%%{c}"')
    self.assertEqual(yamlio.hcl_string('q"\n'), '"q\\"\\n"')

  def test_top_level_scalars(self):
    text = "project_id: \"my-proj\"  # c\nregion: us-east1\nnested:\n  project_id: other\n"
    self.assertEqual(yamlio.top_level_scalars(text), {"project_id": "my-proj", "region": "us-east1"})


class ValidateLintTest(unittest.TestCase):

  def test_repos_lints(self):
    text = (
        "repositories:\n"
        "  svc:\n"
        "    repo_url: https://github.com/acme/svc.git\n"
        "    dry_run: yes\n"
        "  svc:\n"
        "    repo_url: https://acme.ghe.com/acme/svc.git\n"
        "  odd:\n"
        "    repo_url: git@github.com:acme/odd.git\n"
    )
    errors, warnings = validate.lint_repos(text)
    self.assertTrue(any("duplicate key repositories.svc " in e for e in errors), errors)
    self.assertTrue(any("GHE.com" in e for e in errors), errors)
    self.assertTrue(any("boolean true" in w for w in warnings), warnings)
    self.assertTrue(any("odd.git" in w for w in warnings), warnings)

  def test_good_repos_have_no_findings(self):
    text = (ROOT / "terraform" / "gcp" / "repos.example.yaml").read_text(encoding="utf-8")
    self.assertEqual(validate.lint_repos(text), ([], []))

  def test_deployment_lints(self):
    errors, _ = validate.lint_deployment("project_id: your-project-id\nresource_prefix: a-very-long-prefix-x\n")
    self.assertEqual(len(errors), 2, errors)
    errors, warnings = validate.lint_deployment("project_id: p-123456\nresource_prefix: cm\nscheduler_paused: off\n")
    self.assertEqual(errors, [])
    self.assertEqual(len(warnings), 1)

  def test_example_deployment_only_flags_the_placeholder(self):
    text = (ROOT / "terraform" / "gcp" / "deployment.example.yaml").read_text(encoding="utf-8")
    errors, warnings = validate.lint_deployment(text)
    self.assertEqual(errors, ["project_id is still the example value"])
    self.assertEqual(warnings, [])

  def test_parse_terraform_errors(self):
    output = (
        "run \"config\"... fail\n"
        "╷\n"
        "│ Error: Resource precondition failed\n"
        "│ \n"
        "│   on config.tf line 299, in resource \"terraform_data\" \"config_checks\":\n"
        "│  299:       condition     = length(local.repos_yaml_errors) == 0\n"
        "│     ├────────────────\n"
        "│     │ local.repos_yaml_errors is tuple with 1 element\n"
        "│ \n"
        "│ ./repos.yaml has errors:\n"
        "│   - repositories.x.repo_url: required\n"
        "╵\n"
        "╷\n"
        "│ Error: Second\n"
        "╵\n"
    )
    errors = validate.parse_terraform_errors(output)
    self.assertEqual(len(errors), 2)
    self.assertTrue(errors[0].startswith("Resource precondition failed"))
    self.assertIn("repositories.x.repo_url: required", errors[0])
    self.assertNotIn("299:", errors[0])
    self.assertEqual(errors[1], "Second")


class ValidateRunTest(TempDirMixin, unittest.TestCase):
  """validate with a fake terraform: what it copies and how it runs it."""

  def _args(self, **kw):
    class Args:
      repos = kw.get("repos")
      deployment = kw.get("deployment")
      skip_terraform = kw.get("skip_terraform", False)
    return Args()

  def test_runs_terraform_offline_in_a_copy(self):
    root = make_repo(self.tmp)
    gcp = root / "terraform" / "gcp"
    (gcp / "terraform.tfvars").write_text('project_id = "local"\n')
    (gcp / "local_override.tf").write_text("# override\n")
    (gcp / "repos.yaml").write_text("repositories: {}\n")
    deployment = self.tmp / "d.yaml"
    deployment.write_text("project_id: p-123456\nresource_prefix: cm\n")
    seen = {}

    def on_test(base, cwd):
      module = pathlib.Path(cwd)
      seen["files"] = sorted(p.name for p in module.iterdir())
      seen["deployment"] = (module / "deployment.yaml").read_text()
      seen["test"] = (module / "setup_check" / "config.tftest.hcl").read_text()
      return ok("Success! 1 passed, 0 failed.")

    runner = FakeRunner().on(["terraform", "init"], ok()).on(["terraform", "test"], on_test)
    environ = {"PATH": "/usr/bin", "TF_VAR_project_id": "x", "GOOGLE_APPLICATION_CREDENTIALS": "/k.json"}
    ctx = make_context(root, runner, environ=environ)
    code = validate.run(ctx, self._args(deployment=str(deployment)))
    self.assertEqual(code, common.EXIT_OK, ctx.out.getvalue())
    self.assertIn("terraform.tfvars exists", ctx.out.getvalue())
    self.assertNotIn("terraform.tfvars", seen["files"])
    self.assertNotIn("local_override.tf", seen["files"])
    self.assertIn("repos.yaml", seen["files"])
    self.assertIn("config.tf", seen["files"])
    self.assertIn("resource_prefix: cm", seen["deployment"])
    self.assertIn('mock_provider "google"', seen["test"])
    for call in runner.calls:
      self.assertNotIn("TF_VAR_project_id", call["env"])
      self.assertEqual(call["env"]["GOOGLE_APPLICATION_CREDENTIALS"], "/nonexistent/codemender-setup")
      self.assertNotEqual(pathlib.Path(call["cwd"]).resolve(), gcp.resolve())
    self.assertIn("-test-directory=setup_check", runner.commands()[0])
    self.assertIn("-backend=false", runner.commands()[0])

  def test_terraform_failure_is_reported(self):
    root = make_repo(self.tmp)
    out = "╷\n│ Error: Resource precondition failed\n│ \n│ ./deployment.yaml has errors:\n│   - x: unknown key\n╵\n"
    runner = FakeRunner().on(["terraform", "init"], ok()).on(["terraform", "test"], fail(out))
    ctx = make_context(root, runner)
    code = validate.run(ctx, self._args())
    self.assertEqual(code, common.EXIT_FAILED)
    self.assertIn("x: unknown key", ctx.out.getvalue())

  def test_missing_terraform_fails_but_lints_run(self):
    root = make_repo(self.tmp)
    (root / "terraform" / "gcp" / "deployment.yaml").write_text("project_id: your-project-id\n")
    ctx = make_context(root, tools={})
    code = validate.run(ctx, self._args())
    self.assertEqual(code, common.EXIT_FAILED)
    out = ctx.out.getvalue()
    self.assertIn("terraform not found", out)
    self.assertIn("example value", out)


@unittest.skipUnless(shutil.which("terraform") and os.environ.get("CODEMENDER_SETUP_TF_TESTS") == "1",
                     "set CODEMENDER_SETUP_TF_TESTS=1 with terraform on PATH to run")
class ValidateRealTerraformTest(TempDirMixin, unittest.TestCase):
  """Runs the real terraform against the real module (needs provider download)."""

  def test_examples_pass_and_errors_fail(self):
    good = self.tmp / "d.yaml"
    good.write_text((ROOT / "terraform" / "gcp" / "deployment.example.yaml").read_text()
                    .replace("your-project-id", "demo-project-123"))
    out = io.StringIO()
    ctx = common.Context(repo_root=ROOT, out=out, err=io.StringIO())

    class Args:
      repos = str(ROOT / "terraform" / "gcp" / "repos.example.yaml")
      deployment = str(good)
      skip_terraform = False

    self.assertEqual(validate.run(ctx, Args()), common.EXIT_OK, out.getvalue())
    bad = self.tmp / "bad.yaml"
    bad.write_text("project_id: demo-project-123\nsheduler_cron: x\n")
    Args.deployment = str(bad)
    out2 = io.StringIO()
    ctx2 = common.Context(repo_root=ROOT, out=out2, err=io.StringIO())
    self.assertEqual(validate.run(ctx2, Args()), common.EXIT_FAILED)
    self.assertIn("sheduler_cron: unknown key", out2.getvalue())


if __name__ == "__main__":
  unittest.main()
