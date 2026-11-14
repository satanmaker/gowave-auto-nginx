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
    CaseBlocked,
    CaseIncomplete,
    CaseResult,
    RunAborted,
    RunContext,
    Runner,
    overall_status,
    repository_state,
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

    def test_each_case_names_the_evidence_files_it_wrote(self):
        # The inline evidence dict cannot be grepped from a shell, so a case also
        # carries the paths of the files it produced — and only its own.
        context = self.context()
        runner = Runner(context)

        def with_logs(ctx):
            ctx.evidence_text("aio-install.stdout.log", "install output")
            ctx.evidence_text("aio-install.stderr.log", "install warning")
            return {"note": "ok"}

        runner.add(Case("AIO-ONE", "aio", with_logs))
        runner.add(Case("AIO-TWO", "aio", lambda ctx: {}))
        self.assertEqual(runner.execute(), 0)
        report = json.loads((context.artifact_dir / "result.json").read_text())
        self.assertEqual(
            report["cases"][0]["evidence_files"],
            ["evidence/aio-install.stdout.log", "evidence/aio-install.stderr.log"],
        )
        self.assertEqual(report["cases"][1]["evidence_files"], [])
        for named in report["cases"][0]["evidence_files"]:
            self.assertTrue((context.artifact_dir / named).is_file(), named)
        suite = ET.parse(context.artifact_dir / "junit.xml").getroot()
        cases = suite.findall("testcase")
        self.assertEqual(
            cases[0].findtext("system-out"),
            "evidence/aio-install.stdout.log\nevidence/aio-install.stderr.log",
        )
        self.assertIsNone(cases[1].find("system-out"))

    def test_rewriting_one_evidence_file_references_it_once(self):
        context = self.context()
        runner = Runner(context)

        def rewritten(ctx):
            ctx.evidence_text("same.log", "first")
            ctx.evidence_text("same.log", "second")
            return {}

        runner.add(Case("AIO-ONE", "aio", rewritten))
        self.assertEqual(runner.execute(), 0)
        report = json.loads((context.artifact_dir / "result.json").read_text())
        self.assertEqual(report["cases"][0]["evidence_files"], ["evidence/same.log"])
        self.assertEqual((context.artifact_dir / "evidence" / "same.log").read_text(), "second")

    def test_the_result_names_the_commit_it_measured(self):
        # A run is evidence only for the revision it started on, so the artifact
        # carries that revision instead of leaving it to a timestamp argument.
        context = self.context()
        runner = Runner(context)
        runner.add(Case("AIO-SMOKE", "aio", lambda ctx: {}))
        self.assertEqual(runner.execute(), 0)
        report = json.loads((context.artifact_dir / "result.json").read_text())
        repository = report["environment"]["repository"]
        self.assertRegex(repository["commit"], r"^[0-9a-f]{40}$")
        self.assertIn(repository["tree"], ("clean", "dirty"))

    def test_a_missing_revision_is_reported_instead_of_failing_the_run(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            self.assertEqual(repository_state(Path(tmpdir)),
                             {"commit": "unknown", "tree": "unknown"})

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

    def test_a_case_without_its_prerequisite_is_blocked_not_failed(self):
        context = self.context()

        def blocked(ctx):
            raise CaseBlocked("AIO-INSTALL: this case needs the AIO install")

        runner = Runner(context)
        runner.add(Case("AIO-04", "aio", blocked))
        self.assertEqual(runner.execute(), 1)
        report = json.loads((context.artifact_dir / "result.json").read_text())
        self.assertEqual(report["cases"][0]["status"], BLOCKED)
        self.assertEqual(report["overall"], BLOCKED)

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

    def test_evidence_that_cannot_decide_the_question_is_incomplete_not_failed(self):
        # A refusal with no working control beside it says nothing about the
        # policy, so calling it a product failure would invent a defect.
        context = self.context()

        def ambiguous(ctx):
            raise CaseIncomplete("FW-02: the refusal is not attributable to a policy")

        runner = Runner(context)
        runner.add(Case("FW-02", "aio", ambiguous))
        self.assertEqual(runner.execute(), 1)
        report = json.loads((context.artifact_dir / "result.json").read_text())
        self.assertEqual(report["cases"][0]["status"], INCOMPLETE)
        self.assertEqual(report["overall"], INCOMPLETE)
        self.assertIn("not attributable", report["cases"][0]["message"])

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


class TestArtifactOwnership(unittest.TestCase):
    """A root run must leave artifacts the invoking operator can actually read."""

    def test_a_sudo_run_hands_the_evidence_back_to_the_invoking_user(self):
        from unittest import mock

        chowned = []
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {"SUDO_UID": "1000", "SUDO_GID": "1000"}), \
                mock.patch("os.geteuid", return_value=0), \
                mock.patch("os.chown",
                           side_effect=lambda path, uid, gid: chowned.append((Path(path), uid, gid))):
            context = RunContext("aio", Path(tmp), budget_seconds=60, run_id="podman-aio-owned-abcd1234")
            context.evidence_text("probe.txt", "evidence")
        targets = {path.name: (uid, gid) for path, uid, gid in chowned}
        self.assertEqual(targets[context.run_id], (1000, 1000))
        self.assertEqual(targets["probe.txt"], (1000, 1000))

    def test_a_non_root_run_never_touches_ownership(self):
        from unittest import mock

        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {"SUDO_UID": "1000", "SUDO_GID": "1000"}), \
                mock.patch("os.geteuid", return_value=1000), \
                mock.patch("os.chown") as chown:
            context = RunContext("aio", Path(tmp), budget_seconds=60, run_id="podman-aio-ownless-abcd1234")
            context.evidence_text("probe.txt", "evidence")
        chown.assert_not_called()

    def test_a_root_run_outside_sudo_still_hands_the_tree_to_its_owner(self):
        from unittest import mock

        chowned = []
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch("os.geteuid", return_value=0), \
                mock.patch("os.chown",
                           side_effect=lambda path, uid, gid: chowned.append((Path(path), uid, gid))), \
                mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SUDO_UID", None)
            os.environ.pop("SUDO_GID", None)
            owner = os.stat(tmp)
            context = RunContext("aio", Path(tmp), budget_seconds=60, run_id="podman-aio-nosudo-abcd1234")
            context.evidence_text("probe.txt", "evidence")
        self.assertTrue(chowned, "a root shell has no SUDO_UID, so the artifact owner is the only signal")
        self.assertEqual({(uid, gid) for _, uid, gid in chowned}, {(owner.st_uid, owner.st_gid)})

    def test_sudo_credentials_name_the_operator_before_any_stat(self):
        from unittest import mock

        from tools.podman_e2e.runner import operator_identity

        with mock.patch.dict(os.environ, {"SUDO_UID": "1234", "SUDO_GID": "5678"}):
            self.assertEqual(operator_identity(Path("/nonexistent")), (1234, 5678))

    def test_sudo_from_a_root_shell_falls_back_to_the_artifact_owner(self):
        from unittest import mock

        from tools.podman_e2e.runner import operator_identity

        # ``sudo`` run inside a root shell reports the invoker as root, which
        # would hand the evidence back to root and change nothing.
        artifact_root = mock.Mock()
        artifact_root.stat.return_value = mock.Mock(st_uid=1000, st_gid=1000)
        with mock.patch.dict(os.environ, {"SUDO_UID": "0", "SUDO_GID": "0"}):
            self.assertEqual(operator_identity(artifact_root), (1000, 1000))

    def test_an_artifact_root_owned_by_root_is_left_alone(self):
        from unittest import mock

        from tools.podman_e2e.runner import operator_identity

        root_owned = mock.Mock()
        root_owned.stat.return_value = mock.Mock(st_uid=0, st_gid=0)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SUDO_UID", None)
            os.environ.pop("SUDO_GID", None)
            self.assertIsNone(operator_identity(root_owned))


if __name__ == "__main__":
    unittest.main()
