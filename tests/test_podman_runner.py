#!/usr/bin/env python3
"""Suite nonroot: Podman E2E runner contract, result semantics, and run ownership."""
import json
import os
import signal
import sys
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e.runner import (  # noqa: E402
    BLOCKED,
    FAIL,
    INCOMPLETE,
    PASS,
    SKIP,
    BudgetExhausted,
    Case,
    CaseResult,
    RunAborted,
    RunContext,
    Runner,
    overall_status,
)


class TestPodmanRunnerContract(unittest.TestCase):
    def context(self, budget_seconds: int = 60) -> RunContext:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        return RunContext("aio", Path(self.tmp.name), budget_seconds=budget_seconds, run_id="podman-aio-test-abcdef12")

    def test_passing_case_writes_json_and_junit(self):
        context = self.context()
        runner = Runner(context)
        runner.add(Case("AIO-SMOKE", "aio", lambda ctx: {"note": "ok"}))
        self.assertEqual(runner.execute(), 0)
        report = json.loads((context.artifact_dir / "result.json").read_text())
        self.assertEqual(report["overall"], PASS)
        self.assertEqual(report["cases"][0]["status"], PASS)
        self.assertEqual(report["cases"][0]["evidence"], {"note": "ok"})
        suite = ET.parse(context.artifact_dir / "junit.xml").getroot()
        self.assertEqual(suite.attrib["tests"], "1")
        self.assertEqual(suite.attrib["failures"], "0")

    def test_assertion_failure_is_never_green(self):
        context = self.context()

        def failing(ctx):
            raise AssertionError("AIO-DP-REALITY: payload mismatch")

        runner = Runner(context)
        runner.add(Case("AIO-DP-REALITY", "aio", failing))
        self.assertEqual(runner.execute(), 1)
        report = json.loads((context.artifact_dir / "result.json").read_text())
        self.assertEqual(report["overall"], FAIL)
        self.assertIn("payload mismatch", report["cases"][0]["message"])

    def test_declared_case_timeout_is_enforced(self):
        context = self.context()
        runner = Runner(context)
        runner.add(Case("AIO-SLOW", "aio", lambda ctx: time.sleep(5), timeout_seconds=1))
        started = time.monotonic()
        self.assertEqual(runner.execute(), 1)
        self.assertLess(time.monotonic() - started, 3.5)
        result = runner.results[0]
        self.assertEqual(result.status, FAIL)
        self.assertIn("timed out", result.message)

    def test_budget_overrun_marks_case_incomplete(self):
        context = self.context(budget_seconds=1)
        runner = Runner(context)
        runner.add(Case("AIO-SLOW", "aio", lambda ctx: time.sleep(5), timeout_seconds=30))
        self.assertEqual(runner.execute(), 1)
        self.assertEqual(runner.results[0].status, INCOMPLETE)
        self.assertIn("budget", runner.results[0].message)

    def test_unexecuted_cases_are_incomplete(self):
        context = self.context(budget_seconds=1)
        runner = Runner(context)
        runner.add(Case("AIO-SLOW", "aio", lambda ctx: time.sleep(5), timeout_seconds=30))
        runner.add(Case("AIO-NEVER", "aio", lambda ctx: None))
        self.assertEqual(runner.execute(), 1)
        self.assertEqual(runner.results[1].status, INCOMPLETE)
        self.assertIn("before the case ran", runner.results[1].message)

    def test_explicit_budget_exhaustion_is_incomplete(self):
        context = self.context()

        def exhausted(ctx):
            raise BudgetExhausted("no time left")

        runner = Runner(context)
        runner.add(Case("AIO-BUDGET", "aio", exhausted))
        self.assertEqual(runner.execute(), 1)
        self.assertEqual(runner.results[0].status, INCOMPLETE)

    def test_skip_never_passes_the_run(self):
        self.assertEqual(overall_status([CaseResult("X", "aio", SKIP)]), FAIL)
        self.assertEqual(overall_status([CaseResult("X", "aio", BLOCKED)]), BLOCKED)
        self.assertEqual(overall_status([]), INCOMPLETE)
        self.assertEqual(overall_status([CaseResult("X", "aio", PASS)]), PASS)

    def test_cleanup_failure_fails_the_run(self):
        context = self.context()
        context.add_cleanup(lambda: (_ for _ in ()).throw(RuntimeError("leftover network")))
        runner = Runner(context)
        runner.add(Case("AIO-OK", "aio", lambda ctx: None))
        self.assertEqual(runner.execute(), 1)
        cleanup = [result for result in runner.results if result.id == "CLEANUP"]
        self.assertEqual(len(cleanup), 1)
        self.assertEqual(cleanup[0].status, FAIL)
        self.assertIn("leftover network", cleanup[0].message)

    def test_abort_still_runs_cleanup_and_marks_remaining_incomplete(self):
        context = self.context()
        cleaned = []
        context.add_cleanup(lambda: cleaned.append("cleanup"))
        runner = Runner(context)
        runner.add(Case(
            "AIO-ABORT", "aio",
            lambda ctx: (_ for _ in ()).throw(RunAborted(signal.SIGTERM)),
        ))
        runner.add(Case("AIO-AFTER", "aio", lambda ctx: None))
        self.assertEqual(runner.execute(), 1)
        self.assertEqual([result.status for result in runner.results], [INCOMPLETE, INCOMPLETE])
        self.assertIn("SIGTERM", runner.results[0].message)
        self.assertIn("SIGTERM", runner.results[1].message)
        self.assertEqual(cleaned, ["cleanup"])
        self.assertTrue((context.artifact_dir / "result.json").exists())

    def test_sigterm_becomes_an_inband_abort(self):
        context = self.context()
        context.install_signal_handlers()
        try:
            with self.assertRaises(RunAborted):
                os.kill(os.getpid(), signal.SIGTERM)
                time.sleep(1)
        finally:
            context.restore_signal_handlers()


class TestPodmanRunOwnership(unittest.TestCase):
    def test_resource_names_and_labels_are_run_scoped(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = RunContext("aio", Path(tmp), budget_seconds=60, run_id="podman-aio-20260101T000000-aaaaaaaa")
            second = RunContext("aio", Path(tmp), budget_seconds=60, run_id="podman-aio-20260101T000000-bbbbbbbb")
            self.assertNotEqual(first.resource_name("panel"), second.resource_name("panel"))
            self.assertEqual(first.labels["gowave.e2e.run"], first.run_id)
            self.assertEqual(first.labels["gowave.e2e.topology"], "aio")

    def test_secret_files_are_private_outside_artifacts_and_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            context = RunContext("aio", Path(tmp), budget_seconds=60, run_id="podman-aio-secret-abcd1234")
            secret = "SuperSecretPassword12345"
            path = context.write_secret("admin-password", secret)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(str(context.artifact_dir), str(path))
            context.evidence_text("probe.txt", f"login used {secret}")
            self.assertNotIn(secret, (context.artifact_dir / "evidence" / "probe.txt").read_text())
            self.assertEqual(context.run_cleanup(), [])
            self.assertFalse(path.exists())

    def test_secret_name_must_be_a_plain_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            context = RunContext("aio", Path(tmp), budget_seconds=60)
            with self.assertRaises(ValueError):
                context.write_secret("../escape", "value")


if __name__ == "__main__":
    unittest.main()
