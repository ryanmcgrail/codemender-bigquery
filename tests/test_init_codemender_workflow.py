"""Unit tests for scripts/ci/init_codemender_workflow.py."""

import importlib.util
import json
import math
import pathlib
import re
import tempfile
import unittest
from unittest import mock
import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "ci" / "init_codemender_workflow.py"

spec = importlib.util.spec_from_file_location(
    "init_codemender_workflow", SCRIPT_PATH
)
assert spec and spec.loader
init_wf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(init_wf)


class TestInitCodemenderWorkflow(unittest.TestCase):

  def test_detect_build_command_by_manifest(self) -> None:
    cases = [
        ("package.json", "npm test"),
        ("pyproject.toml", "pytest"),
        ("go.mod", "go test ./..."),
        ("Cargo.toml", "cargo test"),
        ("pom.xml", "mvn test"),
        ("build.gradle", "./gradlew test"),
    ]
    for filename, expected in cases:
      with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        (root / filename).write_text("", encoding="utf-8")
        self.assertEqual(init_wf.detect_build_command(root), expected)

  def test_reusable_mode_default_and_non_blocking(self) -> None:
    with tempfile.TemporaryDirectory() as tmp:
      root = pathlib.Path(tmp)
      (root / "pyproject.toml").write_text("[project]\n", encoding="utf-8")

      out = init_wf.generate_workflow_files(
          target_dir=root,
          mode="reusable",
          agent_repo="example-org/codemender-agent",
          agent_ref="main",
          scan_target="src",
          min_blocking_severity="HIGH",
          block_pr_merge=False,
      )
      self.assertTrue(out.is_file())
      doc = yaml.safe_load(out.read_text(encoding="utf-8"))
      job = doc["jobs"]["security-gate"]
      self.assertEqual(
          job["uses"],
          "example-org/codemender-agent/.github/workflows/codemender_parallel.yml@main",
      )
      self.assertEqual(
          job["with"]["runner_image"],
          "ghcr.io/example-org/codemender-runner:latest",
      )
      self.assertIn("pytest", job["with"]["build_command"])
      self.assertIn("HIGH", job["with"]["min_blocking_severity"])
      # The expression always mentions 'false', so evaluate it rather than
      # substring-matching: on a pull_request with nothing set, it must
      # resolve to the generated (non-blocking) default.
      self.assertIs(
          eval_gha(
              job["with"]["block_pr_merge"],
              inputs={},
              vars_={},
              event_name="pull_request",
          ),
          False,
      )

  def test_reusable_mode_with_copy_reusable_workflow(self) -> None:
    with tempfile.TemporaryDirectory() as tmp:
      root = pathlib.Path(tmp)
      out = init_wf.generate_workflow_files(
          target_dir=root,
          mode="reusable",
          copy_reusable_workflow=True,
      )
      copied_parallel = root / ".github" / "workflows" / "codemender_parallel.yml"
      self.assertTrue(copied_parallel.is_file())
      doc = yaml.safe_load(out.read_text(encoding="utf-8"))
      self.assertEqual(
          doc["jobs"]["security-gate"]["uses"],
          "./.github/workflows/codemender_parallel.yml",
      )

  def test_standalone_mode_generates_four_stage_pipeline(self) -> None:
    with tempfile.TemporaryDirectory() as tmp:
      root = pathlib.Path(tmp)
      out = init_wf.generate_workflow_files(
          target_dir=root,
          mode="standalone",
          agent_repo="example-org/codemender-agent",
          agent_ref="main",
          vendor_ref="vendor/codemender-agent",
          scan_target="src/app",
          build_command="pytest -q",
          min_blocking_severity="CRITICAL",
          block_pr_merge=True,
      )
      raw = out.read_text(encoding="utf-8")
      doc = yaml.safe_load(raw)
      self.assertEqual(
          set(doc["jobs"].keys()),
          {"scan", "security-gate", "worker", "aggregate"},
      )
      self.assertEqual(doc["env"]["CODEMENDER_PRESUBMIT_PIPELINE"], "true")
      self.assertNotIn("CODEMENDER_PRESUBMIT_GATE", doc["env"])
      self.assertEqual(
          doc["env"]["CODEMENDER_AGENT_REPO"], "example-org/codemender-agent"
      )
      self.assertEqual(
          doc["env"]["CODEMENDER_VENDOR_REF"], "vendor/codemender-agent"
      )
      self.assertIn("__SKIP_NO_SOURCE_CHANGES__", raw)

  def test_refuses_to_overwrite_without_force(self) -> None:
    with tempfile.TemporaryDirectory() as tmp:
      root = pathlib.Path(tmp)
      init_wf.generate_workflow_files(target_dir=root)
      with self.assertRaises(FileExistsError):
        init_wf.generate_workflow_files(target_dir=root, force=False)
      init_wf.generate_workflow_files(target_dir=root, force=True)

  @mock.patch("subprocess.run")
  def test_cli_main_with_gh_repo_configuration(
      self, mock_run: mock.MagicMock
  ) -> None:
    with tempfile.TemporaryDirectory() as tmp:
      rc = init_wf.main(
          [
              "--target-dir",
              tmp,
              "--mode",
              "reusable",
              "--agent-repo",
              "example-org/codemender-agent",
              "--non-blocking",
              "--min-blocking-severity",
              "HIGH",
              "--gh-repo",
              "example-org/service-a",
          ]
      )
      self.assertEqual(rc, 0)
      self.assertEqual(mock_run.call_count, 3)


# ---------------------------------------------------------------------------
# Minimal GitHub Actions expression evaluator, enough for the generated
# block_pr_merge expressions. Semantics follow
# https://docs.github.com/en/actions/reference/workflows-and-actions/expressions:
#   * falsy values: false, 0, -0, '', null (and NaN);
#   * `a && b` returns a if a is falsy, else b; `a || b` returns a if a is
#     truthy, else b (operands, not coerced booleans) -- this is what makes
#     `cond && 'x' || 'y'` a ternary only when 'x' is truthy;
#   * `==` / `!=`: strings compare case-insensitively; mismatched types are
#     coerced to numbers (null -> 0, true -> 1, false -> 0, '' -> 0,
#     non-numeric string -> NaN, NaN never equal);
#   * precedence: `!` > `==`/`!=` > `&&` > `||`;
#   * property access on a missing key / null yields null;
#   * unset repository variables read as ''.
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(
    r"\s*(?:(?P<str>'(?:[^']|'')*')|(?P<op>==|!=|&&|\|\||[()!.,])"
    r"|(?P<num>-?\d+(?:\.\d+)?)|(?P<ident>[A-Za-z_][A-Za-z0-9_-]*))"
)


def _tokenize(expr: str) -> list[tuple[str, str]]:
  tokens, pos = [], 0
  expr = expr.strip()
  while pos < len(expr):
    m = _TOKEN_RE.match(expr, pos)
    if not m or m.end() == pos:
      raise ValueError(f"cannot tokenize at {pos}: {expr[pos:]!r}")
    pos = m.end()
    kind = m.lastgroup
    tokens.append((kind, m.group(kind)))
  return tokens


def _truthy(v) -> bool:
  if v is None or v is False or v == "":
    return False
  if isinstance(v, (int, float)) and not isinstance(v, bool):
    return not (v == 0 or math.isnan(v))
  return True


def _to_number(v) -> float:
  if v is None:
    return 0.0
  if isinstance(v, bool):
    return 1.0 if v else 0.0
  if isinstance(v, (int, float)):
    return float(v)
  if isinstance(v, str):
    s = v.strip()
    if s == "":
      return 0.0
    try:
      return float(s)
    except ValueError:
      return math.nan
  return math.nan


def _loose_eq(a, b) -> bool:
  if isinstance(a, str) and isinstance(b, str):
    return a.casefold() == b.casefold()
  if type(a) is type(b) and not isinstance(a, (dict, list)):
    return a == b
  if isinstance(a, (dict, list)) or isinstance(b, (dict, list)):
    return a is b
  x, y = _to_number(a), _to_number(b)
  return not (math.isnan(x) or math.isnan(y)) and x == y


class _Evaluator:

  def __init__(self, expr: str, contexts: dict):
    self.toks = _tokenize(expr)
    self.i = 0
    self.ctx = contexts

  def _peek(self):
    return self.toks[self.i] if self.i < len(self.toks) else (None, None)

  def _take(self, value=None):
    tok = self._peek()
    if value is not None and tok[1] != value:
      raise ValueError(f"expected {value!r}, got {tok!r}")
    self.i += 1
    return tok

  def run(self):
    v = self._or()
    if self.i != len(self.toks):
      raise ValueError(f"trailing tokens: {self.toks[self.i:]}")
    return v

  def _or(self):
    left = self._and()
    while self._peek()[1] == "||":
      self._take()
      right = self._and()
      left = left if _truthy(left) else right
    return left

  def _and(self):
    left = self._eq()
    while self._peek()[1] == "&&":
      self._take()
      right = self._eq()
      left = right if _truthy(left) else left
    return left

  def _eq(self):
    left = self._unary()
    while self._peek()[1] in ("==", "!="):
      op = self._take()[1]
      right = self._unary()
      eq = _loose_eq(left, right)
      left = eq if op == "==" else not eq
    return left

  def _unary(self):
    if self._peek()[1] == "!":
      self._take()
      return not _truthy(self._unary())
    return self._primary()

  def _primary(self):
    kind, val = self._take()
    if val == "(":
      v = self._or()
      self._take(")")
      return v
    if kind == "str":
      return val[1:-1].replace("''", "'")
    if kind == "num":
      return float(val)
    if kind != "ident":
      raise ValueError(f"unexpected token {val!r}")
    low = val.lower()
    if low in ("true", "false"):
      return low == "true"
    if low == "null":
      return None
    if self._peek()[1] == "(":
      self._take("(")
      arg = self._or()
      self._take(")")
      if low == "fromjson":
        return json.loads(arg)
      raise ValueError(f"unsupported function {val}")
    obj = self.ctx.get(val)
    while self._peek()[1] == ".":
      self._take()
      key = self._take()[1]
      obj = obj.get(key) if isinstance(obj, dict) else None
    return obj


def eval_gha(expr: str, *, inputs: dict, vars_: dict, event_name: str):
  """Evaluates `expr` (with or without the `${{ }}` wrapper)."""
  m = re.fullmatch(r"\s*\$\{\{(.*)\}\}\s*", expr, flags=re.S)
  body = m.group(1) if m else expr

  class _Vars(dict):

    def get(self, key, default=None):  # unset variables read as ''
      return super().get(key, "")

  contexts = {
      "inputs": inputs,
      "vars": _Vars(vars_),
      "github": {"event_name": event_name},
  }
  return _Evaluator(body, contexts).run()


# Input states: pull_request (inputs context empty -> null), manual run left at
# 'auto', manual run with explicit 'true'/'false'.
_INPUT_STATES = {
    "pr_null": ("pull_request", {}),
    "dispatch_auto": ("workflow_dispatch", {"block_pr_merge": "auto"}),
    "dispatch_true": ("workflow_dispatch", {"block_pr_merge": "true"}),
    "dispatch_false": ("workflow_dispatch", {"block_pr_merge": "false"}),
}
_VAR_STATES = {
    "unset": None,
    "true": "true",
    "false": "false",
    "TRUE": "TRUE",
    "False": "False",
    "garbage": "maybe",
}

# Expression from the previous generator (literal default true), kept to
# document the false-fallthrough bug this change fixes.
_OLD_REUSABLE_EXPR = (
    "inputs.block_pr_merge != null && inputs.block_pr_merge ||"
    " (vars.CODEMENDER_BLOCK_PR_MERGE != '' &&"
    " vars.CODEMENDER_BLOCK_PR_MERGE == 'true') || true"
)


def _expected(input_state: str, var_value, literal: bool) -> bool:
  explicit = {"dispatch_true": True, "dispatch_false": False}
  if input_state in explicit:
    return explicit[input_state]
  if var_value is not None and var_value.lower() in ("true", "false"):
    return var_value.lower() == "true"
  return literal


class TestBlockPrMergePrecedence(unittest.TestCase):

  def _render(self, mode: str, block: bool) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
      out = init_wf.generate_workflow_files(
          target_dir=pathlib.Path(tmp), mode=mode, block_pr_merge=block
      )
      return yaml.safe_load(out.read_text(encoding="utf-8"))

  def test_evaluator_reproduces_old_false_fallthrough(self) -> None:
    # Sanity check that the evaluator models GitHub's && / || semantics: the
    # old expression ignores an explicit false and a 'false' variable.
    self.assertIs(
        eval_gha(
            _OLD_REUSABLE_EXPR,
            inputs={"block_pr_merge": False},
            vars_={},
            event_name="workflow_dispatch",
        ),
        True,
    )
    self.assertIs(
        eval_gha(
            _OLD_REUSABLE_EXPR,
            inputs={},
            vars_={"CODEMENDER_BLOCK_PR_MERGE": "false"},
            event_name="pull_request",
        ),
        True,
    )
    # And the GitHub coercion trap that rules out `inputs.x == false`.
    self.assertIs(
        eval_gha("inputs.x == false", inputs={}, vars_={}, event_name="x"),
        True,
    )

  def test_selector_exact_strings(self) -> None:
    self.assertEqual(
        init_wf.block_pr_merge_selector(False),
        "inputs.block_pr_merge == 'true' && 'true' || "
        "inputs.block_pr_merge == 'false' && 'false' || "
        "vars.CODEMENDER_BLOCK_PR_MERGE == 'true' && 'true' || "
        "vars.CODEMENDER_BLOCK_PR_MERGE == 'false' && 'false' || "
        "'false'",
    )
    self.assertEqual(
        init_wf.block_pr_merge_selector(True, include_legacy_var=True),
        "inputs.block_pr_merge == 'true' && 'true' || "
        "inputs.block_pr_merge == 'false' && 'false' || "
        "vars.CODEMENDER_BLOCK_PR_MERGE == 'true' && 'true' || "
        "vars.CODEMENDER_BLOCK_PR_MERGE == 'false' && 'false' || "
        "vars.CODEMENDER_FAIL_ON_FINDINGS == 'true' && 'true' || "
        "vars.CODEMENDER_FAIL_ON_FINDINGS == 'false' && 'false' || "
        "'true'",
    )

  def test_reusable_truth_table(self) -> None:
    for literal in (False, True):
      doc = self._render("reusable", literal)
      with_block = doc["jobs"]["security-gate"]["with"]
      self.assertEqual(
          with_block["block_pr_merge"], with_block["fail_on_findings"]
      )
      expr = with_block["block_pr_merge"]
      for in_name, (event, inputs) in _INPUT_STATES.items():
        for var_name, var_value in _VAR_STATES.items():
          vars_ = {} if var_value is None else {
              "CODEMENDER_BLOCK_PR_MERGE": var_value
          }
          with self.subTest(literal=literal, input=in_name, var=var_name):
            got = eval_gha(expr, inputs=inputs, vars_=vars_, event_name=event)
            # Must be a real boolean for the reusable workflow's boolean input.
            self.assertIsInstance(got, bool)
            self.assertIs(got, _expected(in_name, var_value, literal))

  def test_reusable_ignores_legacy_fail_on_findings_var(self) -> None:
    doc = self._render("reusable", False)
    expr = doc["jobs"]["security-gate"]["with"]["block_pr_merge"]
    got = eval_gha(
        expr,
        inputs={},
        vars_={"CODEMENDER_FAIL_ON_FINDINGS": "true"},
        event_name="pull_request",
    )
    self.assertIs(got, False)

  def test_standalone_truth_table(self) -> None:
    for literal in (False, True):
      doc = self._render("standalone", literal)
      self.assertEqual(doc["env"]["BLOCK_PR_MERGE"], doc["env"]["FAIL_ON_FINDINGS"])
      expr = doc["env"]["BLOCK_PR_MERGE"]
      for in_name, (event, inputs) in _INPUT_STATES.items():
        for var_name, var_value in _VAR_STATES.items():
          vars_ = {} if var_value is None else {
              "CODEMENDER_BLOCK_PR_MERGE": var_value
          }
          with self.subTest(literal=literal, input=in_name, var=var_name):
            got = eval_gha(expr, inputs=inputs, vars_=vars_, event_name=event)
            want = "true" if _expected(in_name, var_value, literal) else "false"
            self.assertEqual(got, want)

  def test_standalone_legacy_fail_on_findings_var(self) -> None:
    for literal in (False, True):
      expr = self._render("standalone", literal)["env"]["BLOCK_PR_MERGE"]
      for legacy, want in (("true", "true"), ("false", "false")):
        with self.subTest(literal=literal, legacy=legacy):
          self.assertEqual(
              eval_gha(
                  expr,
                  inputs={},
                  vars_={"CODEMENDER_FAIL_ON_FINDINGS": legacy},
                  event_name="pull_request",
              ),
              want,
          )
      # CODEMENDER_BLOCK_PR_MERGE wins over the legacy variable.
      self.assertEqual(
          eval_gha(
              expr,
              inputs={},
              vars_={
                  "CODEMENDER_BLOCK_PR_MERGE": "false",
                  "CODEMENDER_FAIL_ON_FINDINGS": "true",
              },
              event_name="pull_request",
          ),
          "false",
      )

  def test_dispatch_input_is_auto_choice(self) -> None:
    for mode in ("reusable", "standalone"):
      doc = self._render(mode, False)
      on_block = doc.get("on") or doc.get(True)
      spec = on_block["workflow_dispatch"]["inputs"]["block_pr_merge"]
      with self.subTest(mode=mode):
        self.assertEqual(spec["type"], "choice")
        self.assertEqual(spec["default"], "auto")
        self.assertEqual(spec["options"], ["auto", "true", "false"])


class TestBlockingCliDefaults(unittest.TestCase):

  def _cli_doc(self, *flags: str) -> dict:
    with tempfile.TemporaryDirectory() as tmp, mock.patch("builtins.print"):
      rc = init_wf.main(["--target-dir", tmp, *flags])
      self.assertEqual(rc, 0)
      path = pathlib.Path(tmp) / ".github" / "workflows" / "codemender.yml"
      return yaml.safe_load(path.read_text(encoding="utf-8"))

  def _literal(self, doc: dict) -> bool:
    expr = doc["jobs"]["security-gate"]["with"]["block_pr_merge"]
    # Everything unset on a pull_request: only the literal default applies.
    return eval_gha(expr, inputs={}, vars_={}, event_name="pull_request")

  def test_default_is_non_blocking(self) -> None:
    self.assertIs(self._literal(self._cli_doc()), False)
    self.assertFalse(init_wf.build_parser().parse_args([]).block_pr_merge)

  def test_function_default_is_non_blocking(self) -> None:
    with tempfile.TemporaryDirectory() as tmp:
      out = init_wf.generate_workflow_files(target_dir=pathlib.Path(tmp))
      doc = yaml.safe_load(out.read_text(encoding="utf-8"))
    self.assertIs(self._literal(doc), False)

  def test_non_blocking_flag_still_accepted(self) -> None:
    self.assertIs(self._literal(self._cli_doc("--non-blocking")), False)

  def test_blocking_flags(self) -> None:
    for flag in ("--blocking", "--block-pr-merge"):
      with self.subTest(flag=flag):
        self.assertIs(self._literal(self._cli_doc(flag)), True)

  def test_blocking_and_non_blocking_are_exclusive(self) -> None:
    with mock.patch("sys.stderr"), self.assertRaises(SystemExit):
      init_wf.build_parser().parse_args(["--blocking", "--non-blocking"])

  @mock.patch("subprocess.run")
  def test_gh_repo_sets_variable_to_selected_mode(
      self, mock_run: mock.MagicMock
  ) -> None:
    for flags, want in (((), "false"), (("--blocking",), "true")):
      mock_run.reset_mock()
      with self.subTest(flags=flags), tempfile.TemporaryDirectory() as tmp:
        with mock.patch("builtins.print"):
          rc = init_wf.main(
              ["--target-dir", tmp, "--gh-repo", "example-org/svc", *flags]
          )
        self.assertEqual(rc, 0)
        var_calls = [
            c.args[0]
            for c in mock_run.call_args_list
            if "CODEMENDER_BLOCK_PR_MERGE" in c.args[0]
        ]
        self.assertEqual(len(var_calls), 1)
        self.assertEqual(var_calls[0][-1], want)


if __name__ == "__main__":
  unittest.main()
