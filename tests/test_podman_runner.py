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


class TestFailureDiagnosticsHook(unittest.TestCase):
    """A red case leaves a bundle, and the bundle never becomes the verdict."""

    def context(self, budget_seconds: int = 60) -> RunContext:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        return RunContext("aio", Path(self.tmp.name), budget_seconds=budget_seconds, run_id="podman-aio-test-abcdef12")

    def test_only_a_non_green_case_collects(self):
        context = self.context()
        seen = []
        runner = Runner(context)
        runner.on_failure(lambda result: seen.append((result.id, result.status)))
        runner.add(Case("AIO-FAILED", "aio", lambda ctx: (_ for _ in ()).throw(AssertionError("mismatch"))))
        runner.add(Case("AIO-BLOCKED", "aio", lambda ctx: (_ for _ in ()).throw(CaseBlocked("no install"))))
        runner.add(Case("AIO-OK", "aio", lambda ctx: {}))
        self.assertEqual(runner.execute(), 1)
        # The blocked case is a consequence of the failed one: probing again for
        # every case behind one broken install would only re-record the machine.
        self.assertEqual(seen, [("AIO-FAILED", FAIL)])

    def test_a_run_whose_only_red_case_is_blocked_still_collects(self):
        context = self.context()
        seen = []
        runner = Runner(context)
        runner.on_failure(lambda result: seen.append(result.id))
        runner.add(Case("AIO-BLOCKED", "aio", lambda ctx: (_ for _ in ()).throw(CaseBlocked("no install"))))
        self.assertEqual(runner.execute(), 1)
        self.assertEqual(seen, ["AIO-BLOCKED"])

    def test_a_broken_collector_cannot_change_the_verdict(self):
        context = self.context()

        def broken(result):
            raise RuntimeError("podman ps timed out")

        runner = Runner(context)
        runner.on_failure(broken)
        runner.add(Case("AIO-BAD", "aio", lambda ctx: (_ for _ in ()).throw(AssertionError("mismatch"))))
        self.assertEqual(runner.execute(), 1)
        report = json.loads((context.artifact_dir / "result.json").read_text())
        self.assertEqual(report["cases"][0]["status"], FAIL)
        self.assertIn("mismatch", report["cases"][0]["message"])
        self.assertIn("failure diagnostics: RuntimeError: podman ps timed out", report["cases"][0]["message"])
        self.assertEqual(report["overall"], FAIL)

    def test_the_bundle_is_named_by_the_case_that_failed(self):
        context = self.context()

        def collect(result):
            context.evidence_text(f"diagnostics/{result.id}/network.txt", "listeners: none")

        runner = Runner(context)
        runner.on_failure(collect)
        runner.add(Case("AIO-BAD", "aio", lambda ctx: (_ for _ in ()).throw(AssertionError("mismatch"))))
        runner.add(Case("AIO-AFTER", "aio", lambda ctx: {}))
        runner.execute()
        report = json.loads((context.artifact_dir / "result.json").read_text())
        self.assertEqual(report["cases"][0]["evidence_files"], ["evidence/diagnostics/AIO-BAD/network.txt"])
        self.assertEqual(report["cases"][1]["evidence_files"], [])

    def test_an_operator_abort_does_not_wait_for_diagnostics(self):
        context = self.context()
        called = []
        runner = Runner(context)
        runner.on_failure(lambda result: called.append(result.id))
        runner.add(Case(
            "AIO-ABORT", "aio",
            lambda ctx: (_ for _ in ()).throw(RunAborted(signal.SIGTERM)),
        ))
        runner.execute()
        self.assertEqual(called, [])

    def test_an_interrupt_during_the_bundle_stops_the_run(self):
        # A collector that swallowed the operator's interrupt would keep a run
        # alive that was asked to stop, so the case keeps its verdict and the
        # remaining cases are reported as never run.
        context = self.context()
        runner = Runner(context)
        runner.on_failure(lambda result: (_ for _ in ()).throw(RunAborted(signal.SIGINT)))
        runner.add(Case("AIO-BAD", "aio", lambda ctx: (_ for _ in ()).throw(AssertionError("mismatch"))))
        runner.add(Case("AIO-NEVER", "aio", lambda ctx: {}))
        self.assertEqual(runner.execute(), 1)
        report = json.loads((context.artifact_dir / "result.json").read_text())
        self.assertEqual([case["status"] for case in report["cases"]], [FAIL, INCOMPLETE])
        self.assertIn("mismatch", report["cases"][0]["message"])
        self.assertIn("SIGINT", report["cases"][1]["message"])


class FakePodman:
    """The two calls the collector makes, with the failures a real host produces."""

    def __init__(self, containers, output="probe output", raising=None, listing_error=None):
        self.containers = containers
        self.output = output
        self.raising = raising or {}
        self.listing_error = listing_error

    def run_containers(self):
        if self.listing_error:
            raise self.listing_error
        return list(self.containers)

    def exec_bash(self, name, script, check=False, timeout=0):
        import subprocess

        fault = self.raising.get(name)
        if fault is not None:
            raise fault
        return subprocess.CompletedProcess(
            args=["bash", "-lc", script], returncode=0,
            stdout=f"{self.output} on {name}", stderr="",
        )


class TestPodmanDiagnosticsBundle(unittest.TestCase):
    """The failure bundle names the eight areas and never hides a gap."""

    AREA_NAMES = {"operator", "service", "systemd", "network", "tls", "dns", "client", "endpoint"}

    def setUp(self):
        from tools.podman_e2e import diagnostics

        self.diagnostics = diagnostics
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.context = RunContext(
            "aio", Path(self.tmp.name), budget_seconds=60, run_id="podman-aio-diag-abcdef12",
        )
        self.result = CaseResult("AIO-05", "aio", FAIL, message="AIO-05: the panel route answered 502")

    def bundle(self, podman, **kwargs):
        return self.diagnostics.collect(self.context, podman, self.result, **kwargs)

    def read(self, relative):
        return (self.context.artifact_dir / relative).read_text()

    def test_every_area_of_the_ledger_is_written(self):
        self.assertEqual({area.name for area in self.diagnostics.AREAS}, self.AREA_NAMES)
        written = self.bundle(FakePodman([
            {"name": "aio-abcdef12", "state": "running", "status": "Up 4 minutes"},
            {"name": "worker-abcdef12", "state": "exited", "status": "Exited (1) 2 minutes ago"},
        ]))
        self.assertEqual(len(written), len(self.AREA_NAMES) + 1)
        for area in sorted(self.AREA_NAMES):
            path = f"evidence/diagnostics/AIO-05/{area}.txt"
            self.assertIn(path, written)
            text = self.read(path)
            self.assertIn("aio-abcdef12 (running)", text)
            self.assertIn("worker-abcdef12 (exited)", text)
            self.assertIn("[bundle complete: 2 container(s) probed]", text)
        index = self.read("evidence/diagnostics/AIO-05/index.txt")
        self.assertIn("AIO-05", index)
        self.assertIn("the panel route answered 502", index)
        self.assertIn("probes run: 16, not run: 0", index)

    def test_a_probe_that_cannot_run_is_reported_and_the_rest_still_runs(self):
        written = self.bundle(FakePodman(
            [{"name": "aio-abcdef12", "state": "running"},
             {"name": "echo-abcdef12", "state": "running"}],
            raising={"echo-abcdef12": TimeoutError("podman exec did not answer within 25s")},
        ))
        self.assertEqual(len(written), len(self.AREA_NAMES) + 1)
        text = self.read("evidence/diagnostics/AIO-05/network.txt")
        self.assertIn("[probe could not run: TimeoutError: podman exec did not answer within 25s]", text)
        self.assertIn("probe output on aio-abcdef12", text)

    def test_an_exhausted_budget_is_visible_in_every_file(self):
        written = self.bundle(FakePodman([{"name": "aio-abcdef12", "state": "running"}]), budget_seconds=0)
        self.assertEqual(len(written), len(self.AREA_NAMES) + 1)
        text = self.read("evidence/diagnostics/AIO-05/systemd.txt")
        self.assertIn("the diagnostic bundle ran out of time", text)
        self.assertIn("[bundle truncated: 1 probe(s) not run]", text)
        self.assertIn("probes run: 0, not run: 8", self.read("evidence/diagnostics/AIO-05/index.txt"))

    def test_the_bundle_is_redacted(self):
        secret = "SuperSecretPassword12345"
        self.context.write_secret("admin-password", secret)
        podman = FakePodman([{"name": "aio-abcdef12", "state": "running"}], output=f"password={secret}")
        self.bundle(podman)
        text = self.read("evidence/diagnostics/AIO-05/operator.txt")
        self.assertNotIn(secret, text)
        self.assertIn("password=", text)

    def test_no_container_still_leaves_an_index(self):
        written = self.bundle(FakePodman([]))
        self.assertEqual(len(written), len(self.AREA_NAMES) + 1)
        index = self.read("evidence/diagnostics/AIO-05/index.txt")
        self.assertIn("[none: the run owned no container when this case failed]", index)

    def test_a_listing_failure_is_reported_instead_of_raised(self):
        written = self.bundle(FakePodman([], listing_error=RuntimeError("podman is gone")))
        self.assertEqual(len(written), len(self.AREA_NAMES) + 1)
        self.assertIn("container listing failed: RuntimeError: podman is gone",
                      self.read("evidence/diagnostics/AIO-05/index.txt"))

    def test_an_awkward_case_id_cannot_escape_the_evidence_directory(self):
        self.result.id = "../../etc/passwd"
        written = self.bundle(FakePodman([]))
        for relative in written:
            self.assertNotIn("..", relative)
            self.assertTrue(relative.startswith("evidence/diagnostics/"))

    def test_an_interrupt_while_probing_is_not_recorded_as_a_failed_probe(self):
        podman = FakePodman(
            [{"name": "aio-abcdef12", "state": "running"}],
            raising={"aio-abcdef12": RunAborted(signal.SIGINT)},
        )
        with self.assertRaises(RunAborted):
            self.bundle(podman)


class TestPodmanContainerDiscovery(unittest.TestCase):
    def test_names_state_and_labels_come_from_the_run_label(self):
        from unittest import mock

        from tools.podman_e2e.podman import Podman

        podman = object.__new__(Podman)
        podman.context = mock.Mock(run_id="podman-aio-x-abcd1234", topology="aio")
        listed = mock.Mock(returncode=0, stdout=json.dumps([
            {"Names": ["worker-abcd1234"], "State": "exited", "Status": "Exited (1) 2 minutes ago"},
            {"Name": "aio-abcd1234", "State": "running", "Status": "Up 4 minutes"},
        ]), stderr="")
        with mock.patch.object(Podman, "_run", return_value=listed) as run:
            containers = podman.run_containers()
        self.assertEqual(
            containers,
            [
                {"name": "aio-abcd1234", "state": "running", "status": "Up 4 minutes"},
                {"name": "worker-abcd1234", "state": "exited", "status": "Exited (1) 2 minutes ago"},
            ],
        )
        argv = run.call_args[0][0]
        self.assertEqual(argv[:3], ["ps", "-a", "--format"])
        self.assertIn("label=gowave.e2e.run=podman-aio-x-abcd1234", argv)

    def test_an_unreadable_listing_yields_no_containers(self):
        from unittest import mock

        from tools.podman_e2e.podman import Podman

        podman = object.__new__(Podman)
        podman.context = mock.Mock(run_id="podman-aio-x-abcd1234", topology="aio")
        for listed in (
            mock.Mock(returncode=1, stdout="", stderr="no such label"),
            mock.Mock(returncode=0, stdout="not json", stderr=""),
        ):
            with mock.patch.object(Podman, "_run", return_value=listed):
                self.assertEqual(podman.run_containers(), [])


if __name__ == "__main__":
    unittest.main()
