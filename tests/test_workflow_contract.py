"""Unit tests for the CodeMender 4-Job Pre-Submit Security Gate workflow.

This test suite validates `.github/workflows/codemender_parallel.yml` and
executes the full `orchestrator.main()` pipeline across Stage 1 (`preflight`
and `scan`), Stage 1.5 (`security-gate`), Stage 2 (`worker` 2.1, 2.2, 2.3),
and Stage 3 (`aggregate`) against mocked `cm` CLI outputs and a mocked GitHub
REST API.
"""

from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

import yaml

_HERE = Path(__file__).resolve()
REPO_ROOT = _HERE.parents[3] if (_HERE.parents[3] / ".github" / "workflows" / "codemender_parallel.yml").exists() else _HERE.parents[1]
PARALLEL_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "codemender_parallel.yml"


class FakeGitHubServer:
    """In-memory mock of GitHub REST API endpoints for Statuses, Issue Comments, and PR Reviews."""

    def __init__(self) -> None:
        self.statuses: list[dict] = []
        self.issue_comments: list[dict] = []
        self.pr_reviews: list[dict] = []
        self._next_comment_id = 1000
        self._next_review_id = 5000

    def urlopen(self, req: urllib.request.Request, timeout: float = 15):
        url = req.full_url
        method = req.get_method()
        body_bytes = req.data or b""
        payload = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}

        # 1. Commit Statuses: POST /repos/{owner}/{repo}/statuses/{sha}
        if "/statuses/" in url and method == "POST":
            self.statuses.append(payload)
            return self._response(201, {"state": payload.get("state"), "description": payload.get("description")})

        # 2. List PR Issue Comments: GET /repos/{owner}/{repo}/issues/{pr}/comments
        if "/issues/" in url and "/comments" in url and method == "GET" and "/issues/comments/" not in url:
            return self._response(200, list(self.issue_comments))

        # 3. Get Single Issue Comment: GET /repos/{owner}/{repo}/issues/comments/{id}
        if "/issues/comments/" in url and method == "GET":
            cid = int(url.rsplit("/", 1)[1])
            for c in self.issue_comments:
                if c["id"] == cid:
                    return self._response(200, c)
            return self._response(404, {})

        # 4. Create Issue Comment: POST /repos/{owner}/{repo}/issues/{pr}/comments
        if "/issues/" in url and url.endswith("/comments") and method == "POST":
            cid = self._next_comment_id
            self._next_comment_id += 1
            comment = {"id": cid, "body": payload.get("body", "")}
            self.issue_comments.append(comment)
            return self._response(201, comment)

        # 5. Update Issue Comment: PATCH /repos/{owner}/{repo}/issues/comments/{id}
        if "/issues/comments/" in url and method == "PATCH":
            cid = int(url.rsplit("/", 1)[1])
            for c in self.issue_comments:
                if c["id"] == cid:
                    c["body"] = payload.get("body", "")
                    return self._response(200, c)
            return self._response(404, {})

        # 6. List PR Review Comments: GET /repos/{owner}/{repo}/pulls/{pr}/comments
        if "/pulls/" in url and "/comments" in url and method == "GET":
            flat_comments = []
            for rev in self.pr_reviews:
                for c in rev.get("comments", []):
                    flat_comments.append({**c, "html_url": rev.get("html_url", "")})
            return self._response(200, flat_comments)

        # 7. Create PR Review (Inline Suggestions): POST /repos/{owner}/{repo}/pulls/{pr}/reviews
        if "/pulls/" in url and url.endswith("/reviews") and method == "POST":
            rid = self._next_review_id
            self._next_review_id += 1
            review = {
                "id": rid,
                "html_url": f"https://github.com/test/repo/pull/1#pullrequestreview-{rid}",
                "body": payload.get("body", ""),
                "comments": payload.get("comments", []),
            }
            self.pr_reviews.append(review)
            return self._response(200, review)

        raise AssertionError(f"Unhandled mock GitHub API request: {method} {url}")

    @staticmethod
    def _response(status: int, data: object):
        raw = json.dumps(data).encode("utf-8")

        class _Resp(io.BytesIO):
            def __init__(self) -> None:
                super().__init__(raw)
                self.status = status

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.close()

        return _Resp()


    def requests_request(self, method: str, url: str, **kwargs):
        data = (
            json.dumps(kwargs["json"]).encode("utf-8")
            if "json" in kwargs and kwargs["json"] is not None
            else None
        )
        req = urllib.request.Request(url, data=data, method=method)
        try:
            raw_resp = self.urlopen(req)
            status = raw_resp.status
            body_bytes = raw_resp.read()
        except urllib.error.HTTPError as exc:
            status = exc.code
            body_bytes = b"{}"
        parsed = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        resp = mock.MagicMock()
        resp.status_code = status
        resp.json.return_value = parsed
        resp.text = body_bytes.decode("utf-8")
        resp.links = {}

        def _raise():
            if status >= 400:
                raise RuntimeError(f"HTTP {status}")

        resp.raise_for_status.side_effect = _raise
        return resp


class TestCodeMenderSecurityGate(unittest.TestCase):
    """Comprehensive unit tests for all CodeMender Security Gate scenarios and edge cases."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name) / "workspace"
        self.home_dir = Path(self.temp_dir.name) / "home"
        self.workspace.mkdir(parents=True, exist_ok=True)
        (self.home_dir / ".codemender").mkdir(parents=True, exist_ok=True)
        self.github_output = self.workspace / "github_output.txt"
        self.step_summary = self.workspace / "step_summary.md"
        self.github_output.write_text("", encoding="utf-8")
        self.step_summary.write_text("", encoding="utf-8")
        self.gh = FakeGitHubServer()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _run_step(self, job: str, step_substr: str, env_overrides: dict[str, str], subprocess_handler) -> int:
        """Executes a workflow stage via orchestrator.main() with isolated env, filesystem, and mocks."""
        import orchestrator
        from codemender_agent.vcs.github import post_idempotent_inline_review

        # Verify job exists in PARALLEL_WORKFLOW and delegates to orchestrator.py
        with open(PARALLEL_WORKFLOW, "r", encoding="utf-8") as f:
            wf_doc = yaml.safe_load(f)
        self.assertIn(job, wf_doc["jobs"])

        if job == "worker" and ("Initialize" in step_substr or "Stage 2.2" in step_substr):
            return 0

        run_mode_map = {
            ("scan", "Resolve PR Diff"): "preflight",
            ("scan", "Execute"): "scan",
            ("security-gate", "Enforce"): "gate",
            ("worker", "Stage 2.1"): "worker",
            ("aggregate", "Update"): "aggregate",
        }
        run_mode = ""
        for (j_key, s_key), mode_val in run_mode_map.items():
            if job == j_key and s_key in step_substr:
                run_mode = mode_val
                break

        base_env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(self.home_dir),
            "WORKSPACE_DIR": str(self.workspace),
            "GITHUB_WORKSPACE": str(self.workspace),
            "GITHUB_OUTPUT": str(self.github_output),
            "GITHUB_STEP_SUMMARY": str(self.step_summary),
            "CODEMENDER_PRESUBMIT_PIPELINE": "true",
            "CODEMENDER_RUN_MODE": run_mode,
            "REPO_FULL": "niteshtadepalli/bokeh",
            "REPO_FULL_NAME": "niteshtadepalli/bokeh",
            "GITHUB_REPOSITORY": "niteshtadepalli/bokeh",
            "PR_NUMBER": "1",
            "TARGET_SHA": "abcdef1234567890",
            "BASE_REF": "branch-4.0",
            "RUN_URL": "https://github.com/niteshtadepalli/bokeh/actions/runs/999",
            "GH_TOKEN": "ghs_test_token",
            "GITHUB_TOKEN": "ghs_test_token",
            "MIN_SEVERITY": "MEDIUM",
            "MIN_BLOCKING_SEVERITY": "MEDIUM",
            "FAIL_ON_FINDINGS": "true",
            "SANDBOX_ENABLED": "true",
            "MAX_TASKS": "10",
        }
        base_env.update(env_overrides)
        if "SCAN_TARGETS" in base_env and "SCAN_TARGET" not in env_overrides:
            base_env["SCAN_TARGET"] = base_env["SCAN_TARGETS"]
        if "MIN_SEVERITY" in env_overrides and "MIN_BLOCKING_SEVERITY" not in env_overrides:
            base_env["MIN_BLOCKING_SEVERITY"] = env_overrides["MIN_SEVERITY"]

        def fake_expanduser(p: str) -> str:
            if p.startswith("~"):
                return str(self.home_dir) + p[1:]
            return p

        mock_requests = mock.MagicMock()
        mock_requests.get.side_effect = lambda url, **kw: self.gh.requests_request("GET", url, **kw)
        mock_requests.post.side_effect = lambda url, **kw: self.gh.requests_request("POST", url, **kw)
        mock_requests.patch.side_effect = lambda url, **kw: self.gh.requests_request("PATCH", url, **kw)
        mock_session = mock.MagicMock()
        mock_session.get.side_effect = mock_requests.get
        mock_requests.Session.return_value.__enter__.return_value = mock_session

        exit_code = 0
        old_cwd = os.getcwd()
        try:
            os.chdir(self.workspace)
            with (
                mock.patch.dict(os.environ, base_env, clear=True),
                mock.patch("os.path.expanduser", side_effect=fake_expanduser),
                mock.patch("codemender_agent.vcs.github.requests", mock_requests),
                mock.patch("subprocess.run", side_effect=subprocess_handler),
                mock.patch("time.sleep", return_value=None),
            ):
                if job == "worker" and "Stage 2.3" in step_substr:
                    w_idx = base_env.get("WORKER_INDEX", "0")
                    res_file = self.workspace / ".codemender_transit" / "shards" / f"worker_{w_idx}" / f"results_worker_{w_idx}.json"
                    if res_file.exists():
                        for f_item in json.loads(res_file.read_text(encoding="utf-8")):
                            if f_item.get("verified_status") == "CONFIRMED":
                                post_idempotent_inline_review(
                                    token=base_env["GH_TOKEN"],
                                    owner="niteshtadepalli",
                                    repo="bokeh",
                                    pr_number=int(base_env["PR_NUMBER"]),
                                    target_sha=base_env["TARGET_SHA"],
                                    finding=f_item,
                                    patch_diff=f_item.get("patch_diff", ""),
                                    existing_inline_urls=None,
                                )
                    return 0
                try:
                    orchestrator.main()
                except SystemExit as exc:
                    exit_code = int(exc.code or 0)
        finally:
            os.chdir(old_cwd)
        return exit_code

    def _parse_github_output(self) -> dict[str, str]:
        out = {}
        for line in self.github_output.read_text(encoding="utf-8").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
        return out

    # -------------------------------------------------------------------------
    # Test 1: YAML Contract & Option A Orchestrator Delegation Verification
    # -------------------------------------------------------------------------
    def test_01_workflow_yaml_and_embedded_python_syntax(self) -> None:
        with open(PARALLEL_WORKFLOW, "r", encoding="utf-8") as f:
            parallel_doc = yaml.safe_load(f)
        self.assertEqual(set(parallel_doc["jobs"].keys()), {"scan", "security-gate", "worker", "aggregate"})
        self.assertEqual(parallel_doc.get("env", {}).get("CODEMENDER_PRESUBMIT_PIPELINE"), "true")

        found_modes = set()
        for job_name, job in parallel_doc["jobs"].items():
            for step in job.get("steps", []):
                run_cmd = str(step.get("run", ""))
                self.assertNotIn("python3 - <<'EOF'", run_cmd, f"Job {job_name} should delegate to orchestrator.py without inline heredocs")
                if "orchestrator.py" in run_cmd:
                    mode = step.get("env", {}).get("CODEMENDER_RUN_MODE")
                    if mode:
                        found_modes.add(mode)
        self.assertEqual(found_modes, {"preflight", "scan", "gate", "worker", "aggregate"})

    # -------------------------------------------------------------------------
    # Test 2: Diff Target Resolution (Code vs. Non-Code / Deleted Files)
    # -------------------------------------------------------------------------
    def test_02_diff_target_resolution_code_vs_non_code(self) -> None:
        # Case A: Only .github/ files (including .github/workflows/tests/*.py), .gitignore, or a deleted .py file -> skip_scan=true
        gh_test_file = self.workspace / ".github" / "workflows" / "tests" / "test_codemender_security_gate.py"
        gh_test_file.parent.mkdir(parents=True, exist_ok=True)
        gh_test_file.write_text("# workflow unit test\n", encoding="utf-8")

        def subproc_non_code(cmd, *args, **kwargs):
            if cmd[:2] == ["git", "diff"]:
                return subprocess.CompletedProcess(
                    cmd,
                    0,
                    stdout=".github/workflows/codemender.yml\n.github/workflows/tests/test_codemender_security_gate.py\n.gitignore\nsrc/deleted_file.py\n",
                    stderr="",
                )
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        rc = self._run_step(
            "scan",
            "Resolve PR Diff Scan Targets",
            {"IS_PR": "true", "DIFF_SCOPED": "true", "BASE_REF": "branch-4.0", "DEFAULT_SCAN_TARGET": "src/bokeh"},
            subproc_non_code,
        )
        self.assertEqual(rc, 0)
        outputs = self._parse_github_output()
        self.assertEqual(outputs.get("skip_scan"), "true")
        self.assertEqual(outputs.get("resolved_target"), "")

        # Case B: Existing .py file modified -> skip_scan=false and target resolved
        self.github_output.write_text("", encoding="utf-8")
        probe_file = self.workspace / "src" / "bokeh" / "probe.py"
        probe_file.parent.mkdir(parents=True, exist_ok=True)
        probe_file.write_text("print('hello')\n", encoding="utf-8")

        def subproc_with_code(cmd, *args, **kwargs):
            if cmd[:2] == ["git", "diff"]:
                return subprocess.CompletedProcess(cmd, 0, stdout="src/bokeh/probe.py\n.gitignore\n", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        rc = self._run_step(
            "scan",
            "Resolve PR Diff Scan Targets",
            {"IS_PR": "true", "DIFF_SCOPED": "true", "BASE_REF": "branch-4.0", "DEFAULT_SCAN_TARGET": "src/bokeh"},
            subproc_with_code,
        )
        self.assertEqual(rc, 0)
        outputs = self._parse_github_output()
        self.assertEqual(outputs.get("skip_scan"), "false")
        self.assertEqual(outputs.get("resolved_target"), "src/bokeh/probe.py")

    # -------------------------------------------------------------------------
    # Test 3: Stage 1 Immediate Block & Security Gate Status
    # -------------------------------------------------------------------------
    def test_03_stage1_and_security_gate_blocking_on_high_and_critical(self) -> None:
        probe_rel = "src/bokeh/util/probe.py"
        probe_abs = self.workspace / probe_rel
        probe_abs.parent.mkdir(parents=True, exist_ok=True)
        probe_abs.write_text("import os, pickle, sqlite3\n", encoding="utf-8")

        mock_findings = [
            {
                "FindingID": "11111111-aaaa-bbbb-cccc-000000000001",
                "FilePath": probe_rel,
                "StartLine": 10,
                "Severity": "CRITICAL",
                "Title": "OS Command Injection in run_report",
                "Description": "Untrusted shell input passed to subprocess.",
            },
            {
                "FindingID": "22222222-aaaa-bbbb-cccc-000000000002",
                "FilePath": probe_rel,
                "StartLine": 25,
                "Severity": "HIGH",
                "Title": "SQL Injection in lookup_theme",
                "Description": "Unparameterized SQL query string.",
            },
        ]

        def stage1_subproc(cmd, *args, **kwargs):
            if cmd[:2] == ["git", "diff"] and "--name-only" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=f"{probe_rel}\n", stderr="")
            if cmd[:2] == ["cm", "report"] and "json" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"findings": mock_findings}), stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        rc1 = self._run_step("scan", "Execute `cm find`", {"SCAN_TARGETS": probe_rel}, stage1_subproc)
        self.assertEqual(rc1, 0)
        outputs = self._parse_github_output()
        self.assertEqual(outputs["findings_count"], "2")
        self.assertEqual(outputs["blocking_count"], "2")
        self.assertEqual(outputs["advisory_count"], "0")
        self.assertEqual(json.loads(outputs["matrix"]), [0, 1])

        self.assertEqual(len(self.gh.issue_comments), 1)
        sticky_body = self.gh.issue_comments[0]["body"]
        self.assertIn("❌ **BLOCKED** (`2` finding(s) `>= MEDIUM`)", sticky_body)
        self.assertIn("<!-- cm-row:11111111 -->", sticky_body)
        self.assertIn("<!-- cm-row:22222222 -->", sticky_body)

        rc_gate = self._run_step(
            "security-gate",
            "Enforce Immediate Pre-Submit Security Gate",
            {
                "SCAN_RESULT": "success",
                "FINDINGS_COUNT": "2",
                "BLOCKING_COUNT": "2",
                "ADVISORY_COUNT": "0",
            },
            stage1_subproc,
        )
        self.assertEqual(rc_gate, 1)
        self.assertEqual(self.gh.statuses[-1]["state"], "failure")
        self.assertIn("BLOCKED: 2 vulnerability(ies) >= MEDIUM", self.gh.statuses[-1]["description"])
        self.assertIn("❌ BLOCKED", self.step_summary.read_text(encoding="utf-8"))

    # -------------------------------------------------------------------------
    # Test 4: Stage 2 Parallel Workers (2.1 -> 2.2 -> 2.3) & Stage 3 Shard Merge
    # -------------------------------------------------------------------------
    def test_04_stage2_parallel_workers_and_stage3_shard_merge(self) -> None:
        self.test_03_stage1_and_security_gate_blocking_on_high_and_critical()
        probe_rel = "src/bokeh/util/probe.py"
        sample_diff = (
            f"diff --git a/{probe_rel} b/{probe_rel}\n"
            f"--- a/{probe_rel}\n"
            f"+++ b/{probe_rel}\n"
            "@@ -10,1 +10,1 @@\n"
            "-    os.system(user_cmd)\n"
            "+    subprocess.run(['echo', user_cmd], check=True)\n"
        )

        def worker_subproc(cmd, *args, **kwargs):
            if cmd[:2] == ["cm", "verify"]:
                return subprocess.CompletedProcess(cmd, 0, stdout="Status: CONFIRMED EXPLOITABLE\n", stderr="")
            if cmd[:2] == ["cm", "fix"]:
                return subprocess.CompletedProcess(cmd, 0, stdout="Patch generated.\n", stderr="")
            if cmd[:2] == ["git", "diff"]:
                return subprocess.CompletedProcess(cmd, 0, stdout=sample_diff, stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        for w_idx in ("0", "1"):
            self._run_step("worker", "Initialize Worker Workspace", {"WORKER_INDEX": w_idx}, worker_subproc)
            self._run_step("worker", "Stage 2.1: Exploit Verification", {"WORKER_INDEX": w_idx}, worker_subproc)
            self._run_step("worker", "Stage 2.2: Patch Synthesis", {"WORKER_INDEX": w_idx}, worker_subproc)
            self._run_step("worker", "Stage 2.3: Post Inline PR Review Suggestions", {"WORKER_INDEX": w_idx}, worker_subproc)

        self.assertEqual(len(self.gh.pr_reviews), 2)
        self.assertIn("```suggestion", self.gh.pr_reviews[0]["comments"][0]["body"])
        self.assertIn("<!-- cm-inline:", self.gh.pr_reviews[0]["comments"][0]["body"])

        # Re-running Stage 2.3 on a subsequent commit/rerun must skip duplicate inline PR review suggestions
        self._run_step("worker", "Stage 2.3: Post Inline PR Review Suggestions", {"WORKER_INDEX": "0"}, worker_subproc)
        self.assertEqual(len(self.gh.pr_reviews), 2, "Idempotency check must prevent duplicate inline PR reviews")

        live_sticky = self.gh.issue_comments[0]["body"]
        self.assertIn("Stage 2 Complete: 2/2 Findings Processed", live_sticky)
        self.assertIn("✅ **Patch Ready**", live_sticky)

        rc_agg = self._run_step("aggregate", "Update Sticky PR Comment", {}, worker_subproc)
        self.assertEqual(rc_agg, 1)
        self.assertEqual(self.gh.statuses[-1]["state"], "failure")
        self.assertIn("2 auto-fix patch(es) ready", self.gh.statuses[-1]["description"])
        report_data = json.loads((self.workspace / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(len(report_data["findings"]), 2)

    # -------------------------------------------------------------------------
    # Test 5: Non-Blocking Advisory Finding (LOW < MEDIUM)
    # -------------------------------------------------------------------------
    def test_05_low_advisory_finding_passes_gate_and_preserves_banner(self) -> None:
        probe_rel = "src/bokeh/util/advisory.py"
        (self.workspace / "src" / "bokeh" / "util").mkdir(parents=True, exist_ok=True)
        (self.workspace / probe_rel).write_text("import hashlib\n", encoding="utf-8")

        low_finding = [
            {
                "FindingID": "33333333-aaaa-bbbb-cccc-000000000003",
                "FilePath": probe_rel,
                "StartLine": 5,
                "Severity": "LOW",
                "Title": "Weak MD5 hash used for cache key",
                "Description": "Use SHA-256 instead of MD5.",
            }
        ]

        def subproc(cmd, *args, **kwargs):
            if cmd[:2] == ["git", "diff"] and "--name-only" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=f"{probe_rel}\n", stderr="")
            if cmd[:2] == ["cm", "report"] and "json" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"findings": low_finding}), stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self._run_step("scan", "Execute `cm find`", {"SCAN_TARGETS": probe_rel}, subproc)
        outputs = self._parse_github_output()
        self.assertEqual(outputs["blocking_count"], "0")
        self.assertEqual(outputs["advisory_count"], "1")

        rc_gate = self._run_step(
            "security-gate",
            "Enforce Immediate Pre-Submit Security Gate",
            {"SCAN_RESULT": "success", "FINDINGS_COUNT": "1", "BLOCKING_COUNT": "0", "ADVISORY_COUNT": "1"},
            subproc,
        )
        self.assertEqual(rc_gate, 0)
        self.assertEqual(self.gh.statuses[-1]["state"], "success")
        self.assertIn("1 Low/Info advisory finding(s)", self.gh.statuses[-1]["description"])

        # Run Worker 0 + Stage 3 -> must exit 0 and preserve "(1 advisory finding(s))" in Stage 3 banner
        self._run_step("worker", "Initialize Worker Workspace", {"WORKER_INDEX": "0"}, subproc)
        self._run_step("worker", "Stage 2.1: Exploit Verification", {"WORKER_INDEX": "0"}, subproc)
        self._run_step("worker", "Stage 2.2: Patch Synthesis", {"WORKER_INDEX": "0"}, subproc)
        self._run_step("worker", "Stage 2.3: Post Inline PR Review Suggestions", {"WORKER_INDEX": "0"}, subproc)

        rc_agg = self._run_step("aggregate", "Update Sticky PR Comment", {}, subproc)
        self.assertEqual(rc_agg, 0)
        self.assertIn("(`1` advisory finding(s))", self.gh.issue_comments[0]["body"])
        self.assertIn("ℹ️ Advisory", self.gh.issue_comments[0]["body"])

    # -------------------------------------------------------------------------
    # Test 6: False-Positive Dismissal Auto-Unblocks Stage 3 & Filters SARIF
    # -------------------------------------------------------------------------
    def test_06_false_positive_dismissal_auto_unblocks_stage3_and_filters_sarif(self) -> None:
        probe_rel = "src/bokeh/util/fp_probe.py"
        (self.workspace / "src" / "bokeh" / "util").mkdir(parents=True, exist_ok=True)
        (self.workspace / probe_rel).write_text("def lookup(name): pass\n", encoding="utf-8")

        fp_finding = [
            {
                "FindingID": "4d395fe6-f3eb-5048-a6e7-327e97638e0e",
                "FilePath": probe_rel,
                "StartLine": 35,
                "Severity": "HIGH",
                "Title": "SQL Injection in lookup_theme_by_name",
                "Description": "Guarded by strict allowlist.",
            }
        ]
        raw_sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "CodeMender"}},
                    "results": [
                        {
                            "ruleId": "SQLI",
                            "message": {"text": "Finding 4d395fe6-f3eb-5048-a6e7-327e97638e0e"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": probe_rel},
                                        "region": {"startLine": 35},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        def subproc(cmd, *args, **kwargs):
            if cmd[:2] == ["git", "diff"] and "--name-only" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=f"{probe_rel}\n", stderr="")
            if cmd[:2] == ["cm", "report"] and "json" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"findings": fp_finding}), stderr="")
            if cmd[:2] == ["cm", "report"] and "sarif" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(raw_sarif), stderr="")
            if cmd[:2] == ["cm", "verify"]:
                return subprocess.CompletedProcess(cmd, 0, stdout="Verdict: FALSE_POSITIVE (not exploitable)\n", stderr="")
            if cmd[:2] == ["cm", "fix"]:
                raise AssertionError("cm fix should NOT be called for a DISMISSED_FALSE_POSITIVE finding!")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        # Stage 1 + security-gate blocks initially
        self._run_step("scan", "Execute `cm find`", {"SCAN_TARGETS": probe_rel}, subproc)
        self._run_step(
            "security-gate",
            "Enforce Immediate Pre-Submit Security Gate",
            {"SCAN_RESULT": "success", "FINDINGS_COUNT": "1", "BLOCKING_COUNT": "1", "ADVISORY_COUNT": "0"},
            subproc,
        )
        self.assertEqual(self.gh.statuses[-1]["state"], "failure")

        # Stage 2.1 dismisses finding as FALSE_POSITIVE; Stage 2.2 & 2.3 skip cm fix and inline review
        self._run_step("worker", "Initialize Worker Workspace", {"WORKER_INDEX": "0"}, subproc)
        self._run_step("worker", "Stage 2.1: Exploit Verification", {"WORKER_INDEX": "0"}, subproc)
        self._run_step("worker", "Stage 2.2: Patch Synthesis", {"WORKER_INDEX": "0"}, subproc)
        self._run_step("worker", "Stage 2.3: Post Inline PR Review Suggestions", {"WORKER_INDEX": "0"}, subproc)
        self.assertEqual(len(self.gh.pr_reviews), 0)

        # Stage 3 auto-unblocks Commit Status -> "success", updates sticky banner, and strips FP from report.sarif
        rc_agg = self._run_step("aggregate", "Update Sticky PR Comment", {}, subproc)
        self.assertEqual(rc_agg, 0)
        self.assertEqual(self.gh.statuses[-1]["state"], "success")
        self.assertIn("1 false positive(s) dismissed by cm verify", self.gh.statuses[-1]["description"])
        self.assertIn("✅ **PASSED (Auto-Unblocked)**", self.gh.issue_comments[0]["body"])
        self.assertIn("⚪ Dismissed (FP)", self.gh.issue_comments[0]["body"])

        filtered_sarif = json.loads((self.workspace / "report.sarif").read_text(encoding="utf-8"))
        self.assertEqual(len(filtered_sarif["runs"][0]["results"]), 0, "Dismissed FP must be stripped from report.sarif")

    # -------------------------------------------------------------------------
    # Test 7: Fail-Closed Hardening (Verify Error / "UNVERIFIED" / Missing Worker Shard)
    # -------------------------------------------------------------------------
    def test_07_fail_closed_on_verify_error_or_missing_worker_shard(self) -> None:
        probe_rel = "src/bokeh/util/fail_closed.py"
        (self.workspace / "src" / "bokeh" / "util").mkdir(parents=True, exist_ok=True)
        (self.workspace / probe_rel).write_text("eval(user_input)\n", encoding="utf-8")

        high_finding = [
            {
                "FindingID": "77777777-aaaa-bbbb-cccc-000000000007",
                "FilePath": probe_rel,
                "StartLine": 1,
                "Severity": "HIGH",
                "Title": "Code Injection via eval",
                "Description": "Arbitrary code execution.",
            }
        ]

        # Even if `cm verify` prints "UNVERIFIED" or exits non-zero, it MUST NOT dismiss the finding
        def subproc_unverified(cmd, *args, **kwargs):
            if cmd[:2] == ["git", "diff"] and "--name-only" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=f"{probe_rel}\n", stderr="")
            if cmd[:2] == ["cm", "report"] and "json" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"findings": high_finding}), stderr="")
            if cmd[:2] == ["cm", "verify"]:
                return subprocess.CompletedProcess(cmd, 0, stdout="Result: UNVERIFIED (timeout)\n", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self._run_step("scan", "Execute `cm find`", {"SCAN_TARGETS": probe_rel}, subproc_unverified)
        self._run_step("worker", "Initialize Worker Workspace", {"WORKER_INDEX": "0"}, subproc_unverified)
        self._run_step("worker", "Stage 2.1: Exploit Verification", {"WORKER_INDEX": "0"}, subproc_unverified)

        shard_path = self.workspace / ".codemender_transit" / "shards" / "worker_0" / "results_worker_0.json"
        shard_items = json.loads(shard_path.read_text(encoding="utf-8"))
        self.assertEqual(shard_items[0]["verified_status"], "CONFIRMED")

        # Now simulate a worker crash where `results_worker_0.json` was deleted/never uploaded:
        # Stage 3 (`aggregate`) must fall back to `active_findings.json` and still fail closed (exit 1)!
        shard_path.unlink()
        rc_agg = self._run_step("aggregate", "Update Sticky PR Comment", {}, subproc_unverified)
        self.assertEqual(rc_agg, 1, "Stage 3 must fail closed (exit 1) when a worker shard is missing")

    # -------------------------------------------------------------------------
    # Test 8: Sticky Comment Auto-Resolution on Clean Rescan / File Deletion (`skip_scan=true`)
    # -------------------------------------------------------------------------
    def test_08_sticky_comment_resolved_on_clean_rescan_or_skip_scan(self) -> None:
        # Seed an existing sticky comment from a previous blocked commit
        self.gh.issue_comments.append(
            {
                "id": 5800237576,
                "body": "<!-- codemender-summary -->\n### 🛡️ Old Blocked Report\n**Gate Status:** ❌ **BLOCKED**",
            }
        )

        # Run `security-gate` with FINDINGS_COUNT="" (simulating `skip_scan=true` after deleting the vulnerable file)
        rc_gate = self._run_step(
            "security-gate",
            "Enforce Immediate Pre-Submit Security Gate",
            {
                "SCAN_RESULT": "success",
                "FINDINGS_COUNT": "",
                "BLOCKING_COUNT": "0",
                "ADVISORY_COUNT": "0",
                "TARGET_SHA": "d55260c297555863",
            },
            lambda cmd, *a, **kw: subprocess.CompletedProcess(cmd, 0, stdout="", stderr=""),
        )
        self.assertEqual(rc_gate, 0)
        self.assertEqual(self.gh.statuses[-1]["state"], "success")
        updated_comment = self.gh.issue_comments[0]["body"]
        self.assertIn("✅ **All Findings Resolved**", updated_comment)
        self.assertIn("`d55260c2`", updated_comment)

    # -------------------------------------------------------------------------
    # Test 9: Stage 1 Infrastructure / Scan Crash Fails Closed (`SCAN_RESULT != "success"`)
    # -------------------------------------------------------------------------
    def test_09_scan_stage_crash_or_cancellation_fails_closed(self) -> None:
        for bad_result in ("failure", "cancelled", "timed_out"):
            self.gh.statuses.clear()
            rc_gate = self._run_step(
                "security-gate",
                "Enforce Immediate Pre-Submit Security Gate",
                {"SCAN_RESULT": bad_result, "FINDINGS_COUNT": "0", "BLOCKING_COUNT": "0", "ADVISORY_COUNT": "0"},
                lambda cmd, *a, **kw: subprocess.CompletedProcess(cmd, 0, stdout="", stderr=""),
            )
            self.assertEqual(rc_gate, 1, f"security-gate must exit 1 when SCAN_RESULT={bad_result!r}")
            self.assertEqual(self.gh.statuses[-1]["state"], "error")
            self.assertIn(f"CodeMender scan stage failed (result: {bad_result})", self.gh.statuses[-1]["description"])

    # -------------------------------------------------------------------------
    # Test 10: Mixed Verdicts in Stage 3 (Partial FP Dismissal & Partial SARIF Filter)
    # -------------------------------------------------------------------------
    def test_10_mixed_findings_partial_fp_dismissal_and_sarif_partial_filter(self) -> None:
        probe_rel = "src/bokeh/util/mixed.py"
        (self.workspace / "src" / "bokeh" / "util").mkdir(parents=True, exist_ok=True)
        (self.workspace / probe_rel).write_text("import os\n", encoding="utf-8")

        mixed_findings = [
            {
                "FindingID": "fp-11111111",
                "FilePath": probe_rel,
                "StartLine": 10,
                "Severity": "CRITICAL",
                "Title": "Dismissed Critical Finding",
                "Description": "False positive.",
            },
            {
                "FindingID": "real-22222222",
                "FilePath": probe_rel,
                "StartLine": 20,
                "Severity": "HIGH",
                "Title": "Confirmed High Finding",
                "Description": "Real vulnerability.",
            },
        ]
        raw_sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "CodeMender"}},
                    "results": [
                        {
                            "ruleId": "R1",
                            "message": {"text": "fp-11111111"},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": probe_rel}, "region": {"startLine": 10}}}],
                        },
                        {
                            "ruleId": "R2",
                            "message": {"text": "real-22222222"},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": probe_rel}, "region": {"startLine": 20}}}],
                        },
                    ],
                }
            ],
        }

        def subproc(cmd, *args, **kwargs):
            if cmd[:2] == ["git", "diff"] and "--name-only" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=f"{probe_rel}\n", stderr="")
            if cmd[:2] == ["cm", "report"] and "json" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"findings": mixed_findings}), stderr="")
            if cmd[:2] == ["cm", "report"] and "sarif" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(raw_sarif), stderr="")
            if cmd[:2] == ["cm", "verify"]:
                if "fp-11111111" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, stdout="Verdict: FALSE_POSITIVE\n", stderr="")
                return subprocess.CompletedProcess(cmd, 0, stdout="Verdict: CONFIRMED EXPLOITABLE\n", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self._run_step("scan", "Execute `cm find`", {"SCAN_TARGETS": probe_rel}, subproc)
        for w_idx in ("0", "1"):
            self._run_step("worker", "Initialize Worker Workspace", {"WORKER_INDEX": w_idx}, subproc)
            self._run_step("worker", "Stage 2.1: Exploit Verification", {"WORKER_INDEX": w_idx}, subproc)
            self._run_step("worker", "Stage 2.2: Patch Synthesis", {"WORKER_INDEX": w_idx}, subproc)
            self._run_step("worker", "Stage 2.3: Post Inline PR Review Suggestions", {"WORKER_INDEX": w_idx}, subproc)

        # Stage 3 must NOT auto-unblock because 1 confirmed HIGH finding remains!
        rc_agg = self._run_step("aggregate", "Update Sticky PR Comment", {}, subproc)
        self.assertEqual(rc_agg, 1)
        self.assertIn("❌ **BLOCKED** (`1` confirmed finding(s) `>= MEDIUM`)", self.gh.issue_comments[0]["body"])

        # SARIF must strip ONLY fp-11111111 while keeping real-22222222
        filtered_sarif = json.loads((self.workspace / "report.sarif").read_text(encoding="utf-8"))
        remaining_results = filtered_sarif["runs"][0]["results"]
        self.assertEqual(len(remaining_results), 1)
        self.assertEqual(remaining_results[0]["ruleId"], "R2")

    # -------------------------------------------------------------------------
    # Test 11: Sandbox startup failure: opt-in `--unrestricted` rerun & SQLite `state.db` Patch Fallback
    # -------------------------------------------------------------------------
    def test_11_sandbox_violation_unrestricted_retry_and_sqlite_patch_fallback(self) -> None:
        import sqlite3

        probe_rel = "src/bokeh/util/sandbox_retry.py"
        (self.workspace / "src" / "bokeh" / "util").mkdir(parents=True, exist_ok=True)
        (self.workspace / probe_rel).write_text("os.system(cmd)\n", encoding="utf-8")

        finding = [
            {
                "FindingID": "sbx-99999999",
                "FilePath": probe_rel,
                "StartLine": 1,
                "Severity": "HIGH",
                "Title": "Command Injection",
                "Description": "Test sandbox fallback and state.db patch recovery.",
            }
        ]
        verify_calls: list[list[str]] = []
        fix_calls: list[list[str]] = []
        startup_failure = "Error: failed to create sandbox box: operation not permitted\n"

        def subproc(cmd, *args, **kwargs):
            if cmd[:2] == ["git", "diff"] and "--name-only" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=f"{probe_rel}\n", stderr="")
            if cmd[:2] == ["cm", "report"] and "json" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"findings": finding}), stderr="")
            if cmd[:2] == ["cm", "verify"]:
                verify_calls.append(list(cmd))
                if "--unrestricted" not in cmd:
                    return subprocess.CompletedProcess(cmd, 1, stdout=startup_failure, stderr="")
                return subprocess.CompletedProcess(cmd, 0, stdout="Status: CONFIRMED\n", stderr="")
            if cmd[:2] == ["cm", "fix"]:
                fix_calls.append(list(cmd))
                if "--unrestricted" not in cmd:
                    return subprocess.CompletedProcess(cmd, 1, stdout=startup_failure, stderr="")
                # Simulate `cm fix` writing patch into `~/.codemender/state.db` while leaving working tree clean
                db_path = self.home_dir / ".codemender" / "state.db"
                conn = sqlite3.connect(str(db_path))
                conn.execute("CREATE TABLE IF NOT EXISTS patches (finding_id TEXT, diff TEXT, target_file TEXT)")
                conn.execute(
                    "INSERT INTO patches VALUES (?, ?, ?)",
                    (
                        "sbx-99999999",
                        f"--- a/{probe_rel}\n+++ b/{probe_rel}\n@@ -1,1 +1,1 @@\n-os.system(cmd)\n+subprocess.run([cmd], check=True)\n",
                        probe_rel,
                    ),
                )
                conn.commit()
                conn.close()
                return subprocess.CompletedProcess(cmd, 0, stdout="Saved patch to state.db\n", stderr="")
            # Return empty git diff so Stage 2.2 is forced to recover patch from SQLite state.db
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        opt_in = {"CODEMENDER_ALLOW_UNSANDBOXED_FALLBACK": "true"}
        self._run_step("scan", "Execute `cm find`", {"SCAN_TARGETS": probe_rel, **opt_in}, subproc)
        self._run_step("worker", "Initialize Worker Workspace", {"WORKER_INDEX": "0", **opt_in}, subproc)
        self._run_step("worker", "Stage 2.1: Exploit Verification", {"WORKER_INDEX": "0", **opt_in}, subproc)
        self._run_step("worker", "Stage 2.2: Patch Synthesis", {"WORKER_INDEX": "0", **opt_in}, subproc)
        self._run_step("worker", "Stage 2.3: Post Inline PR Review Suggestions", {"WORKER_INDEX": "0", **opt_in}, subproc)

        self.assertEqual(len(verify_calls), 2, "Expected initial sbox attempt + opt-in --unrestricted rerun for cm verify")
        self.assertIn("--unrestricted", verify_calls[1])
        self.assertEqual(len(fix_calls), 2, "Expected initial sbox attempt + opt-in --unrestricted rerun for cm fix")
        self.assertIn("--unrestricted", fix_calls[1])
        self.assertEqual(len(self.gh.pr_reviews), 1, "Expected patch recovered from SQLite state.db to be posted as PR review")
        self.assertIn("subprocess.run([cmd], check=True)", self.gh.pr_reviews[0]["comments"][0]["body"])
        summary = self.step_summary.read_text(encoding="utf-8")
        self.assertIn("WITHOUT the sandbox", summary)

    def test_11b_sandbox_violations_alone_never_rerun_unrestricted(self) -> None:
        probe_rel = "src/bokeh/util/sandbox_violation.py"
        (self.workspace / "src" / "bokeh" / "util").mkdir(parents=True, exist_ok=True)
        (self.workspace / probe_rel).write_text("os.system(cmd)\n", encoding="utf-8")
        finding = [
            {
                "FindingID": "viol-88888888",
                "FilePath": probe_rel,
                "StartLine": 1,
                "Severity": "HIGH",
                "Title": "Command Injection",
                "Description": "Violations only.",
            }
        ]
        cm_calls: list[list[str]] = []
        violations = "sandbox: denied /root/.local\nError: Sandbox violations detected in sbox\n"

        def subproc(cmd, *args, **kwargs):
            if cmd[:2] == ["git", "diff"] and "--name-only" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=f"{probe_rel}\n", stderr="")
            if cmd[:2] == ["cm", "report"] and "json" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"findings": finding}), stderr="")
            if cmd[:2] in (["cm", "find"], ["cm", "verify"], ["cm", "fix"]):
                cm_calls.append(list(cmd))
                return subprocess.CompletedProcess(cmd, 1, stdout=violations, stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        # Opt-in set on purpose: violations are not a startup failure, so still no rerun.
        opt_in = {"CODEMENDER_ALLOW_UNSANDBOXED_FALLBACK": "true"}
        self._run_step("scan", "Execute `cm find`", {"SCAN_TARGETS": probe_rel, **opt_in}, subproc)
        self._run_step("worker", "Stage 2.1: Exploit Verification", {"WORKER_INDEX": "0", **opt_in}, subproc)

        self.assertTrue(any(c[:2] == ["cm", "verify"] for c in cm_calls))
        self.assertFalse(any("--unrestricted" in c for c in cm_calls), cm_calls)
        res_file = self.workspace / ".codemender_transit" / "shards" / "worker_0" / "results_worker_0.json"
        results = json.loads(res_file.read_text(encoding="utf-8"))
        # cm verify exited 1 with no verdict: never reported as confirmed.
        self.assertEqual(results[0]["verified_status"], "VERIFY_FAILED")
        self.assertNotIn("sandbox_unrestricted_rerun", results[0])

    def test_11c_workflow_keeps_secrets_out_of_env_and_wires_sandbox_opt_in(self) -> None:
        with open(PARALLEL_WORKFLOW, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f)

        # No secret values at workflow level: every step (including the cm
        # steps) would inherit them.
        for name, value in (doc.get("env") or {}).items():
            self.assertFalse(name.startswith(("GH_APP_", "GITHUB_APP_")), name)
            self.assertNotIn(name, ("WIF_PROVIDER", "GCP_SA_KEY"))
            refs = re.findall(r"secrets\.\w+(\s*!=\s*'')?", str(value))
            for comparison in refs:
                self.assertTrue(
                    comparison,
                    f"workflow env {name} must only expose whether a secret is set",
                )

        # `on:` is parsed by PyYAML as True.
        on = doc.get("on", doc.get(True))
        inputs = on["workflow_call"]["inputs"]
        self.assertIn("allow_unsandboxed_fallback", inputs)
        self.assertEqual(inputs["allow_unsandboxed_fallback"]["type"], "boolean")
        self.assertIs(inputs["allow_unsandboxed_fallback"]["default"], False)

        wired = set()
        moved = set()
        for job_name, job in doc["jobs"].items():
            steps = job.get("steps", [])
            for idx, step in enumerate(steps):
                env = step.get("env") or {}
                run = str(step.get("run", ""))
                if "orchestrator.py" in run:
                    mode = env.get("CODEMENDER_RUN_MODE")
                    for leaked in ("GH_APP_ID", "GH_APP_KEY", "GH_APP_PRIVATE_KEY"):
                        self.assertNotIn(leaked, env, f"{job_name}/{mode}")
                    if env.get("CODEMENDER_ALLOW_UNSANDBOXED_FALLBACK") == "${{ inputs.allow_unsandboxed_fallback }}":
                        wired.add(mode)
                if "google-github-actions/auth" in str(step.get("uses", "")):
                    self.assertEqual(step.get("id"), "gcp-auth", job_name)
                    nxt = steps[idx + 1]
                    self.assertIn("credentials_file_path", str(nxt.get("if", "")))
                    nxt_run = str(nxt.get("run", ""))
                    self.assertIn("RUNNER_TEMP", nxt_run)
                    for var in ("GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_GHA_CREDS_PATH", "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"):
                        self.assertIn(f"{var}=$dest", nxt_run)
                    self.assertIn('rm -f "$CREDS_FILE"', nxt_run)
                    moved.add(job_name)
                if str(step.get("uses", "")).startswith("actions/create-github-app-token"):
                    self.assertIn("CODEMENDER_HAS_GITHUB_APP == 'true'", str(step.get("if", "")))
        self.assertEqual(wired, {"scan", "worker"})
        self.assertEqual(moved, {"scan", "worker", "aggregate"})

    # -------------------------------------------------------------------------
    # Test 12: Clean-as-You-Code Untouched File Filter & >15 Files Directory Grouping
    # -------------------------------------------------------------------------
    def test_12_untouched_file_filtering_and_large_pr_directory_grouping(self) -> None:
        # Subcase A: >15 modified code files collapses to deduplicated parent directories
        changed_20 = []
        for idx in range(20):
            rel = f"src/bokeh/subpkg_{idx % 3}/mod_{idx}.py"
            p = self.workspace / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("x = 1\n", encoding="utf-8")
            changed_20.append(rel)

        rc = self._run_step(
            "scan",
            "Resolve PR Diff Scan Targets",
            {"IS_PR": "true", "DIFF_SCOPED": "true", "BASE_REF": "branch-4.0", "DEFAULT_SCAN_TARGET": "src/bokeh"},
            lambda cmd, *a, **kw: subprocess.CompletedProcess(cmd, 0, stdout="\n".join(changed_20) + "\n", stderr=""),
        )
        self.assertEqual(rc, 0)
        outputs = self._parse_github_output()
        self.assertEqual(
            outputs["resolved_target"],
            "src/bokeh/subpkg_0,src/bokeh/subpkg_1,src/bokeh/subpkg_2",
        )

        # Subcase B: Pre-existing vulnerability in untouched file is excluded from active_findings
        self.github_output.write_text("", encoding="utf-8")
        report_with_untouched = [
            {
                "FindingID": "in-diff-1",
                "FilePath": "src/bokeh/subpkg_0/mod_0.py",
                "StartLine": 1,
                "Severity": "HIGH",
                "Title": "In-Diff Issue",
                "Description": "In PR diff.",
            },
            {
                "FindingID": "pre-existing-2",
                "FilePath": "src/bokeh/legacy/untouched_file.py",
                "StartLine": 99,
                "Severity": "CRITICAL",
                "Title": "Pre-Existing Legacy Issue",
                "Description": "Not in PR diff.",
            },
        ]

        def subproc_filter(cmd, *args, **kwargs):
            if cmd[:2] == ["git", "diff"] and "--name-only" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout="src/bokeh/subpkg_0/mod_0.py\n", stderr="")
            if cmd[:2] == ["cm", "report"] and "json" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"findings": report_with_untouched}), stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self._run_step("scan", "Execute `cm find`", {"SCAN_TARGETS": "src/bokeh/subpkg_0/mod_0.py"}, subproc_filter)
        outputs = self._parse_github_output()
        self.assertEqual(outputs["findings_count"], "1", "Untouched file finding must be filtered out")
        self.assertNotIn("Pre-Existing Legacy Issue", self.gh.issue_comments[0]["body"])

    # -------------------------------------------------------------------------
    # Test 13: Optimistic Concurrency Retry on Sticky Comment Collision
    # -------------------------------------------------------------------------
    def test_13_sticky_comment_optimistic_concurrency_retry_on_worker_collision(self) -> None:
        probe_rel = "src/bokeh/util/race.py"
        (self.workspace / "src" / "bokeh" / "util").mkdir(parents=True, exist_ok=True)
        (self.workspace / probe_rel).write_text("x = 1\n", encoding="utf-8")

        finding = [
            {
                "FindingID": "race-0001",
                "FilePath": probe_rel,
                "StartLine": 1,
                "Severity": "HIGH",
                "Title": "Race Test Finding",
                "Description": "Test concurrent PATCH collision recovery.",
            }
        ]

        def subproc(cmd, *args, **kwargs):
            if cmd[:2] == ["git", "diff"] and "--name-only" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=f"{probe_rel}\n", stderr="")
            if cmd[:2] == ["cm", "report"] and "json" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"findings": finding}), stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self._run_step("scan", "Execute `cm find`", {"SCAN_TARGETS": probe_rel}, subproc)
        self._run_step("worker", "Initialize Worker Workspace", {"WORKER_INDEX": "0"}, subproc)

        # Simulate another worker clobbering the first PATCH before the verification GET
        orig_urlopen = self.gh.urlopen
        patch_count = 0
        stale_body = self.gh.issue_comments[0]["body"]

        def colliding_urlopen(req, timeout=15):
            nonlocal patch_count
            if req.get_method() == "PATCH" and "/issues/comments/" in req.full_url:
                patch_count += 1
                if patch_count == 1:
                    raise urllib.error.HTTPError(req.full_url, 502, "Concurrent PATCH collision", {}, None)
            return orig_urlopen(req, timeout=timeout)

        with mock.patch.object(self.gh, "urlopen", side_effect=colliding_urlopen):
            self._run_step("worker", "Stage 2.1: Exploit Verification", {"WORKER_INDEX": "0"}, subproc)

        self.assertGreaterEqual(patch_count, 2, "Worker must detect failed PATCH and retry on attempt 2")
        self.assertIn("Stage 2 Complete: 1/1 Findings Processed", self.gh.issue_comments[0]["body"])

    # -------------------------------------------------------------------------
    # Test 14: End-to-End `orchestrator.main()` Pipeline (`preflight` -> `scan` -> `gate` -> `worker` -> `aggregate`)
    # -------------------------------------------------------------------------
    def test_14_orchestrator_presubmit_gate_end_to_end_pipeline(self) -> None:
        import orchestrator

        probe_rel = "src/bokeh/util/orch_probe.py"
        (self.workspace / "src" / "bokeh" / "util").mkdir(parents=True, exist_ok=True)
        (self.workspace / probe_rel).write_text("eval(x)\n", encoding="utf-8")

        finding = [
            {
                "finding_id": "orch-11112222",
                "file_path": probe_rel,
                "line_number": 1,
                "severity": "HIGH",
                "title": "Code Injection",
                "description": "Unsafe eval",
            }
        ]

        def subproc(cmd, *args, **kwargs):
            if "--name-only" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=f"{probe_rel}\n", stderr="")
            if "diff" in cmd and "-U3" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout="+eval(x)\n", stderr="")
            if cmd[:4] == ["cm", "report", "--format", "json"]:
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"findings": finding}), stderr="")
            if cmd[:4] == ["cm", "report", "--format", "sarif"]:
                return subprocess.CompletedProcess(cmd, 0, stdout='{"version":"2.1.0","runs":[]}', stderr="")
            if cmd[:2] == ["cm", "verify"]:
                return subprocess.CompletedProcess(cmd, 0, stdout="CONFIRMED\n", stderr="")
            if cmd[:2] == ["cm", "fix"]:
                return subprocess.CompletedProcess(cmd, 0, stdout="Fixed\n", stderr="")
            if cmd[:2] == ["git", "diff"]:
                return subprocess.CompletedProcess(
                    cmd, 0, stdout=f"@@ -1,1 +1,1 @@\n-eval(x)\n+ast.literal_eval(x)\n", stderr=""
                )
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        base_env = {
            "CODEMENDER_PRESUBMIT_PIPELINE": "true",
            "WORKSPACE_DIR": str(self.workspace),
            "GITHUB_WORKSPACE": str(self.workspace),
            "GITHUB_OUTPUT": str(self.github_output),
            "GITHUB_STEP_SUMMARY": str(self.step_summary),
            "IS_PR": "true",
            "DIFF_SCOPED": "true",
            "BASE_REF": "branch-4.0",
            "DEFAULT_SCAN_TARGET": "src/bokeh",
            "SCAN_TARGET": probe_rel,
            "MIN_BLOCKING_SEVERITY": "MEDIUM",
            "MIN_SEVERITY": "MEDIUM",
            "FAIL_ON_FINDINGS": "true",
            "GH_TOKEN": "ghs_test",
            "GITHUB_TOKEN": "ghs_test",
            "REPO_FULL": "niteshtadepalli/bokeh",
            "REPO_FULL_NAME": "niteshtadepalli/bokeh",
            "PR_NUMBER": "2",
            "TARGET_SHA": "abcdef123456",
            "SCAN_ID": "scan_orch_1",
        }

        sticky_bodies: list[str] = []
        inline_calls: list[dict] = []
        status_calls: list[dict] = []

        def fake_sticky(**kwargs):
            sticky_bodies.append(kwargs.get("body", ""))
            return True

        def fake_inline(**kwargs):
            inline_calls.append(kwargs)
            return "https://github.com/niteshtadepalli/bokeh/pull/2#pullrequestreview-1"

        def fake_status(**kwargs):
            status_calls.append(kwargs)
            return True

        with (
            mock.patch("subprocess.run", side_effect=subproc),
            mock.patch("codemender_agent.vcs.github.post_or_update_sticky_comment", side_effect=fake_sticky),
            mock.patch("codemender_agent.runners.aggregate.post_or_update_sticky_comment", side_effect=fake_sticky),
            mock.patch("codemender_agent.vcs.github.update_finding_in_sticky_comment", return_value=True),
            mock.patch("codemender_agent.vcs.github.post_idempotent_inline_review", side_effect=fake_inline),
            mock.patch("codemender_agent.runners.gate.post_commit_status", side_effect=fake_status),
            mock.patch("codemender_agent.runners.aggregate.post_commit_status", side_effect=fake_status),
        ):
            # 1. preflight
            with mock.patch.dict(os.environ, {**base_env, "CODEMENDER_RUN_MODE": "preflight"}, clear=False):
                orchestrator.main()
            self.assertEqual(self._parse_github_output().get("resolved_target"), probe_rel)

            # 2. scan
            with mock.patch.dict(os.environ, {**base_env, "CODEMENDER_RUN_MODE": "scan"}, clear=False):
                orchestrator.main()
            self.assertEqual(self._parse_github_output().get("blocking_count"), "1")

            # 3. gate
            with mock.patch.dict(
                os.environ,
                {
                    **base_env,
                    "CODEMENDER_RUN_MODE": "gate",
                    "SCAN_RESULT": "success",
                    "FINDINGS_COUNT": "1",
                    "BLOCKING_COUNT": "1",
                    "ADVISORY_COUNT": "0",
                },
                clear=False,
            ):
                with self.assertRaises(SystemExit) as g_ctx:
                    orchestrator.main()
                self.assertEqual(g_ctx.exception.code, 1)

            # 4. worker
            with mock.patch.dict(
                os.environ,
                {**base_env, "CODEMENDER_RUN_MODE": "worker", "WORKER_INDEX": "0"},
                clear=False,
            ):
                orchestrator.main()
            self.assertEqual(len(inline_calls), 1)

            # 5. aggregate
            with mock.patch.dict(os.environ, {**base_env, "CODEMENDER_RUN_MODE": "aggregate"}, clear=False):
                with self.assertRaises(SystemExit) as a_ctx:
                    orchestrator.main()
                self.assertEqual(a_ctx.exception.code, 1)
            self.assertTrue(any("Stage 3 Complete" in b for b in sticky_bodies))

    # -------------------------------------------------------------------------
    # Test 15: Configurable Non-Blocking Audit Mode (`block_pr_merge: false`)
    # -------------------------------------------------------------------------
    def test_15_non_blocking_mode_end_to_end_pipeline(self) -> None:
        with open(PARALLEL_WORKFLOW, "r", encoding="utf-8") as f:
            wf_doc = yaml.safe_load(f)
        on_block = wf_doc.get("on") or wf_doc.get(True)
        wf_inputs = on_block["workflow_call"]["inputs"]
        self.assertIn("block_pr_merge", wf_inputs)
        self.assertEqual(wf_inputs["block_pr_merge"]["default"], True)

        probe_rel = "src/bokeh/util/non_blocking_probe.py"
        (self.workspace / "src" / "bokeh" / "util").mkdir(parents=True, exist_ok=True)
        (self.workspace / probe_rel).write_text("eval(user_data)\n", encoding="utf-8")

        finding = [
            {
                "FindingID": "nb-88889999",
                "FilePath": probe_rel,
                "StartLine": 1,
                "Severity": "HIGH",
                "Title": "Code Injection in Non-Blocking Mode",
                "Description": "Arbitrary code execution.",
            }
        ]

        def subproc(cmd, *args, **kwargs):
            if cmd[:2] == ["git", "diff"] and "--name-only" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=f"{probe_rel}\n", stderr="")
            if cmd[:2] == ["git", "diff"] and "-U3" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout="+eval(user_data)\n", stderr="")
            if cmd[:2] == ["cm", "report"] and "json" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"findings": finding}), stderr="")
            if cmd[:2] == ["cm", "report"] and "sarif" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout='{"version":"2.1.0","runs":[]}', stderr="")
            if cmd[:2] == ["cm", "verify"]:
                return subprocess.CompletedProcess(cmd, 0, stdout="CONFIRMED\n", stderr="")
            if cmd[:2] == ["cm", "fix"]:
                return subprocess.CompletedProcess(cmd, 0, stdout="Fixed\n", stderr="")
            if cmd[:2] == ["git", "diff"]:
                return subprocess.CompletedProcess(
                    cmd, 0, stdout="@@ -1,1 +1,1 @@\n-eval(user_data)\n+ast.literal_eval(user_data)\n", stderr=""
                )
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        # Stage 1: scan in non-blocking mode
        rc_scan = self._run_step(
            "scan",
            "Execute `cm find`",
            {"SCAN_TARGETS": probe_rel, "BLOCK_PR_MERGE": "false"},
            subproc,
        )
        self.assertEqual(rc_scan, 0)
        self.assertIn("⚠️ **PASSED (Non-Blocking Mode)**", self.gh.issue_comments[0]["body"])
        self.assertIn("⚠️ **Non-Blocking**", self.gh.issue_comments[0]["body"])

        # Stage 1.5: security-gate exits 0 and posts state="success"
        rc_gate = self._run_step(
            "security-gate",
            "Enforce Immediate Pre-Submit Security Gate",
            {
                "SCAN_RESULT": "success",
                "FINDINGS_COUNT": "1",
                "BLOCKING_COUNT": "1",
                "ADVISORY_COUNT": "0",
                "BLOCK_PR_MERGE": "false",
            },
            subproc,
        )
        self.assertEqual(rc_gate, 0)
        self.assertEqual(self.gh.statuses[-1]["state"], "success")
        self.assertIn("PASSED (Non-Blocking):", self.gh.statuses[-1]["description"])

        # Stage 2: worker still verifies and posts 1-click inline PR review suggestion
        self._run_step("worker", "Stage 2.1: Exploit Verification", {"WORKER_INDEX": "0"}, subproc)
        self.assertEqual(len(self.gh.pr_reviews), 1)

        # Stage 3: aggregate exits 0, keeps Commit Status "success", and links the 1-click patch
        rc_agg = self._run_step(
            "aggregate",
            "Update Sticky PR Comment",
            {"BLOCK_PR_MERGE": "false"},
            subproc,
        )
        self.assertEqual(rc_agg, 0)
        self.assertEqual(self.gh.statuses[-1]["state"], "success")
        self.assertIn("PASSED (Non-Blocking):", self.gh.statuses[-1]["description"])
        self.assertIn("⚠️ **PASSED (Non-Blocking Mode)**", self.gh.issue_comments[0]["body"])
        self.assertIn("Inline `Commit suggestion`", self.gh.issue_comments[0]["body"])


if __name__ == "__main__":
    unittest.main()


