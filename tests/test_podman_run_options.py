#!/usr/bin/env python3
"""Suite nonroot: the compact summary and the run's case-selection options.

Three things are held here, each read from the side the claim is about. The
summary is read out of the artifact directory a real ``Runner`` wrote, not from
the payload the writer was handed. ``--only`` is read from the ids that reached
the runner and from the exit status an unknown id produces, not from the parser's
help. ``--reuse`` is read from what it refuses and from the fact that a refusal
costs no container, because the flag exists to avoid an install and a fallback to
one would answer a question nobody asked.
"""
import contextlib
import io
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools import run_podman_e2e  # noqa: E402
from tools.podman_e2e.runner import (  # noqa: E402
    BLOCKED,
    FAIL,
    INCOMPLETE,
    PASS,
    SUMMARY_MESSAGE_LIMIT,
    Case,
    CaseBlocked,
    RunContext,
    Runner,
    write_summary,
)

PASSWORD = "SuperSecretPassword12345"


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class TestSummaryArtifact(unittest.TestCase):
    """``summary.json`` is the compact account a person or an agent reads first."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def context(self, **kwargs) -> RunContext:
        return RunContext(
            "aio", self.root, budget_seconds=60,
            run_id="podman-aio-options-abcdef12", **kwargs,
        )

    def summary(self, context: RunContext) -> dict:
        return read_json(context.artifact_dir / "summary.json")

    def test_it_sits_beside_the_result_and_is_world_readable(self):
        # The summary is what someone reads without root: a 0600 file would hide
        # the one artifact an unprivileged operator can use.
        context = self.context(distribution="debian-13")
        runner = Runner(context)
        runner.add(Case("AIO-ONE", "aio", lambda ctx: {"note": "ok"}))
        self.assertEqual(runner.execute(), 0)

        summary_path = context.artifact_dir / "summary.json"
        self.assertTrue((context.artifact_dir / "result.json").is_file())
        self.assertEqual(summary_path.stat().st_mode & 0o777, 0o644)
        self.assertEqual((context.artifact_dir / "result.json").stat().st_mode & 0o777, 0o600)

        summary = self.summary(context)
        self.assertEqual(summary["run_id"], context.run_id)
        self.assertEqual(summary["topology"], "aio")
        self.assertEqual(summary["distribution"], "debian-13")
        self.assertEqual(summary["overall"], PASS)
        self.assertEqual(summary["counts"], {PASS: 1})
        self.assertEqual(summary["executed"], ["AIO-ONE"])
        self.assertFalse(summary["reused"])
        self.assertEqual(summary["cases"], [])

    def test_it_lists_one_entry_per_non_pass_case_in_run_order(self):
        context = self.context()

        def failing(ctx):
            raise AssertionError("AIO-FAIL: the panel route answered 502")

        def blocked(ctx):
            raise CaseBlocked("AIO-BLOCKED: no certificate was issued")

        runner = Runner(context)
        runner.add(Case("AIO-PASS", "aio", lambda ctx: {}))
        runner.add(Case("AIO-FAIL", "aio", failing))
        runner.add(Case("AIO-BLOCKED", "aio", blocked))
        self.assertEqual(runner.execute(), 1)

        summary = self.summary(context)
        self.assertEqual(summary["overall"], FAIL)
        self.assertEqual(summary["counts"], {BLOCKED: 1, FAIL: 1, PASS: 1})
        self.assertEqual(
            [case["id"] for case in summary["cases"]], ["AIO-FAIL", "AIO-BLOCKED"],
        )
        self.assertEqual([case["status"] for case in summary["cases"]], [FAIL, BLOCKED])
        self.assertIn("answered 502", summary["cases"][0]["message"])
        self.assertIn("no certificate", summary["cases"][1]["message"])

    def test_a_long_message_is_bounded_while_the_result_keeps_it_whole(self):
        context = self.context()

        def failing(ctx):
            raise AssertionError("AIO-FAIL: " + "x" * (SUMMARY_MESSAGE_LIMIT * 2))

        runner = Runner(context)
        runner.add(Case("AIO-FAIL", "aio", failing))
        runner.execute()

        summary = self.summary(context)
        self.assertEqual(len(summary["cases"][0]["message"]), SUMMARY_MESSAGE_LIMIT)
        full = read_json(context.artifact_dir / "result.json")["cases"][0]["message"]
        self.assertEqual(len(full), len("AIO-FAIL: ") + SUMMARY_MESSAGE_LIMIT * 2)

    def test_a_case_the_deadline_left_unrun_is_not_reported_as_executed(self):
        # Both cases end up INCOMPLETE and only one of them ran. The summary has
        # to tell those apart, or a truncated run looks like a run that decided
        # nothing about every case.
        context = self.context()
        context.budget_seconds = 1
        runner = Runner(context)
        runner.add(Case("AIO-SLOW", "aio", lambda ctx: time.sleep(5), timeout_seconds=30))
        runner.add(Case("AIO-NEVER", "aio", lambda ctx: None))
        self.assertEqual(runner.execute(), 1)

        summary = self.summary(context)
        self.assertEqual(summary["executed"], ["AIO-SLOW"])
        self.assertEqual(summary["counts"], {INCOMPLETE: 2})
        self.assertEqual([case["id"] for case in summary["cases"]], ["AIO-SLOW", "AIO-NEVER"])
        self.assertIn("before the case ran", summary["cases"][1]["message"])

    def test_a_reused_run_says_which_run_it_borrowed_its_hosts_from(self):
        context = self.context(reused_from="podman-aio-earlier-12345678")
        runner = Runner(context)
        runner.add(Case("AIO-05", "aio", lambda ctx: {}))
        self.assertEqual(runner.execute(), 0)

        summary = self.summary(context)
        self.assertTrue(summary["reused"])
        self.assertEqual(summary["reused_from"], "podman-aio-earlier-12345678")
        self.assertEqual(
            read_json(context.artifact_dir / "result.json")["reused_from"],
            "podman-aio-earlier-12345678",
        )

    def test_a_run_without_a_distribution_does_not_invent_one(self):
        context = self.context()
        runner = Runner(context)
        runner.add(Case("AIO-ONE", "aio", lambda ctx: {}))
        self.assertEqual(runner.execute(), 0)
        self.assertNotIn("distribution", self.summary(context))

    def test_the_summary_is_redacted_and_reads_back_as_json(self):
        context = self.context()
        context.write_secret("admin-password", PASSWORD)
        runner = Runner(context)
        runner.add(Case(
            "AIO-AUTH", "aio",
            lambda ctx: (_ for _ in ()).throw(AssertionError(f"login failed with {PASSWORD}")),
        ))
        self.assertEqual(runner.execute(), 1)

        text = (context.artifact_dir / "summary.json").read_text(encoding="utf-8")
        self.assertNotIn(PASSWORD, text)
        summary = json.loads(text)
        self.assertIn("[REDACTED]", summary["cases"][0]["message"])

    def test_a_red_verdict_reaches_the_summary_written_last(self):
        # The verdict is written twice: once before the redaction audit and once
        # after it. What an offence adds must land in the summary the operator
        # reads, not only in the full record.
        context = self.context()
        context.write_secret("admin-password", PASSWORD)

        def leaky(ctx):
            (ctx.artifact_dir / "leak.txt").write_text(f"password={PASSWORD}\n")
            return {}

        runner = Runner(context)
        runner.add(Case("AIO-LEAKY", "aio", leaky))
        self.assertEqual(runner.execute(), 1)

        summary = self.summary(context)
        self.assertEqual(summary["overall"], FAIL)
        self.assertIn("REDACTION", [case["id"] for case in summary["cases"]])

    def test_a_payload_without_the_run_keys_still_yields_a_summary(self):
        # A report a probe builds by hand carries neither ``executed`` nor
        # ``reused_from``; the writer must not invent a selection from that.
        data = {
            "run_id": "podman-aio-handmade-00000000",
            "topology": "aio",
            "overall": PASS,
            "cases": [{"id": "AIO-ONE", "status": PASS, "message": ""}],
        }
        path = write_summary(self.root, data)
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)
        summary = read_json(path)
        self.assertEqual(summary["executed"], [])
        self.assertFalse(summary["reused"])
        self.assertEqual(summary["counts"], {PASS: 1})


class TestOnlySelection(unittest.TestCase):
    """``--only`` is the suite's declared order, narrowed to the named ids."""

    def suite(self):
        return [
            Case("AIO-INSTALL", "aio", lambda ctx: {}),
            Case("AIO-05", "aio", lambda ctx: {}),
            Case("AIO-04", "aio", lambda ctx: {}),
        ]

    def test_the_declared_order_wins_over_the_typed_order(self):
        selected = run_podman_e2e.select_cases(self.suite(), ["AIO-04", "AIO-INSTALL"])
        self.assertEqual([case.id for case in selected], ["AIO-INSTALL", "AIO-04"])

    def test_no_selection_is_the_whole_declared_suite(self):
        selected = run_podman_e2e.select_cases(self.suite(), None)
        self.assertEqual([case.id for case in selected], ["AIO-INSTALL", "AIO-05", "AIO-04"])

    def test_a_repeated_id_selects_once(self):
        selected = run_podman_e2e.select_cases(self.suite(), ["AIO-05", "AIO-05"])
        self.assertEqual([case.id for case in selected], ["AIO-05"])

    def test_an_unknown_id_is_named_in_the_refusal(self):
        with self.assertRaises(run_podman_e2e.CaseSelectionError) as caught:
            run_podman_e2e.select_cases(self.suite(), ["AIO-05", "AIO-NOPE"])
        self.assertIn("AIO-NOPE", str(caught.exception))
        self.assertIn("does not declare", str(caught.exception))

    def test_an_empty_selection_is_refused_rather_than_widened(self):
        with self.assertRaises(run_podman_e2e.CaseSelectionError) as caught:
            run_podman_e2e.select_cases(self.suite(), [])
        self.assertIn("no case", str(caught.exception))


class EntrypointCase:
    """Drive ``main`` with the suite, Podman and the runner replaced by recorders.

    A mixin rather than a ``TestCase``: it has no test of its own, and a test
    class without test methods fails the repository's completeness check.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cases = [
            Case("AIO-INSTALL", "aio", lambda ctx: {}),
            Case("AIO-05", "aio", lambda ctx: {}),
            Case("AIO-04", "aio", lambda ctx: {}),
        ]
        self.podmen = []
        self.runners = []

    def patchers(self, suite=None, containers=None):
        podmen, runners = self.podmen, self.runners
        suite_cases = list(self.cases if suite is None else suite)

        class RecordingPodman:
            def __init__(self, context):
                self.context = context
                self.calls = []
                podmen.append(self)

            def remove_stale_runs(self):
                self.calls.append("remove_stale_runs")
                return []

            def register_cleanup(self):
                self.calls.append("register_cleanup")

        class RecordingRunner:
            def __init__(self, context):
                self.context = context
                self.added = []
                self.executed_any = False
                runners.append(self)

            def require_group(self, group):
                pass

            def add(self, case):
                self.added.append(case.id)

            def on_failure(self, hook):
                pass

            def execute(self):
                self.executed_any = True
                return 0

        patchers = [
            mock.patch.object(run_podman_e2e, "Podman", RecordingPodman),
            mock.patch.object(run_podman_e2e, "Runner", RecordingRunner),
            mock.patch.object(run_podman_e2e, "build_suite", lambda *a, **k: list(suite_cases)),
            # The catalog is a separate artifact and has no row for a synthetic
            # id; the disagreement it guards is not what these tests are about.
            mock.patch.object(run_podman_e2e.catalog, "require_executable", lambda cases: None),
        ]
        if containers is not None:
            patchers.append(mock.patch.object(
                run_podman_e2e, "kept_containers", lambda run_id: list(containers),
            ))
        return patchers

    def _invoke(self, argv, suite, containers):
        patchers = self.patchers(suite, containers)
        for patcher in patchers:
            patcher.start()
        try:
            return run_podman_e2e.main([*argv, "--artifact-root", str(self.root)])
        finally:
            for patcher in reversed(patchers):
                patcher.stop()

    def run_main(self, argv, suite=None, containers=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = self._invoke(argv, suite, containers)
        return status, stdout.getvalue(), stderr.getvalue()

    def run_main_expecting_exit_2(self, argv, suite=None, containers=None):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                self._invoke(argv, suite, containers)
        self.assertEqual(caught.exception.code, 2)
        return stderr.getvalue()


class TestOnlyFromTheCommandLine(EntrypointCase, unittest.TestCase):
    """An unknown id costs an argument error, never an install."""

    def test_an_unknown_id_exits_2_and_names_it(self):
        message = self.run_main_expecting_exit_2(["--only", "AIO-05,AIO-NOPE"])
        self.assertIn("AIO-NOPE", message)
        self.assertIn("AIO-INSTALL", message)
        # No case is handed to the runner and nothing is executed: the runner
        # object itself exists because the suite needs the context to be built.
        self.assertEqual([runner.added for runner in self.runners], [[]])
        self.assertFalse(any(runner.executed_any for runner in self.runners))
        for podman in self.podmen:
            self.assertEqual(podman.calls, [], "a refused selection may not touch the host")
        self.assertEqual(list(self.root.iterdir()), [], "an argument error leaves no run behind")

    def test_an_empty_selection_exits_2(self):
        message = self.run_main_expecting_exit_2(["--only", ","])
        self.assertIn("no case", message)
        self.assertFalse(any(runner.executed_any for runner in self.runners))

    def test_an_empty_selection_is_refused_before_a_matrix_starts_four_runs(self):
        message = self.run_main_expecting_exit_2(["--only", ",", "--all-distributions"])
        self.assertIn("no case", message)
        self.assertFalse(self.podmen, "the matrix must not be started to learn this")

    def test_the_selected_cases_reach_the_runner_in_the_declared_order(self):
        status, _out, _err = self.run_main(["--only", "AIO-04,AIO-INSTALL"])
        self.assertEqual(status, 0)
        self.assertEqual(len(self.runners), 1)
        runner = self.runners[0]
        self.assertEqual(runner.added, ["AIO-INSTALL", "AIO-04"])
        self.assertTrue(runner.executed_any)

    def test_without_the_flag_the_whole_suite_is_added(self):
        status, _out, _err = self.run_main([])
        self.assertEqual(status, 0)
        self.assertEqual(
            self.runners[0].added, ["AIO-INSTALL", "AIO-05", "AIO-04"],
        )

    def test_the_run_records_the_distribution_it_installs(self):
        status, _out, _err = self.run_main(["--distribution", "ubuntu-24.04"])
        self.assertEqual(status, 0)
        self.assertEqual(self.podmen[0].context.distribution, "ubuntu-24.04")


class TestKeepFromTheCommandLine(EntrypointCase, unittest.TestCase):
    """``--keep`` leaves the hosts and says which run id names them."""

    def test_keep_does_not_register_the_cleanup(self):
        status, _out, _err = self.run_main(["--keep"])
        self.assertEqual(status, 0)
        podman = self.podmen[0]
        self.assertIn("remove_stale_runs", podman.calls)
        self.assertNotIn("register_cleanup", podman.calls)

    def test_without_keep_the_cleanup_is_registered(self):
        status, _out, _err = self.run_main([])
        self.assertEqual(status, 0)
        self.assertIn("register_cleanup", self.podmen[0].calls)

    def test_keep_prints_the_run_id_and_how_to_reuse_it(self):
        status, out, _err = self.run_main(["--keep"])
        self.assertEqual(status, 0)
        run_id = self.podmen[0].context.run_id
        self.assertIn(f"run id: {run_id}", out)
        reuse_lines = [line for line in out.splitlines() if "--reuse" in line]
        self.assertTrue(reuse_lines, out)
        self.assertIn(run_id, reuse_lines[0])
        self.assertIn("gowave.e2e.run=", out)


class TestReuseFromTheCommandLine(EntrypointCase, unittest.TestCase):
    """``--reuse`` resolves and validates an earlier run, then refuses."""

    SOURCE = "podman-aio-20260101T000000-abcdef12"

    def kept_run(self, run_id: str = SOURCE, result: bool = True) -> Path:
        directory = self.root / run_id
        directory.mkdir(parents=True)
        if result:
            (directory / "result.json").write_text(json.dumps({"overall": PASS}), encoding="utf-8")
        return directory

    def test_a_resolvable_run_with_live_containers_is_refused_not_reinstalled(self):
        directory = self.kept_run()
        message = self.run_main_expecting_exit_2(
            ["--reuse", self.SOURCE], containers=["aio-abcdef12", "dns-abcdef12"],
        )
        self.assertIn(self.SOURCE, message)
        self.assertIn(str(directory), message)
        self.assertIn("not implemented", message)
        # The whole point of the flag is not to install again; a silent fallback
        # would be the defect this assertion exists to keep out.
        self.assertIn("Refusing instead of installing a second time", message)
        self.assertFalse(self.podmen, "a refused reuse may not start Podman")
        self.assertFalse(self.runners, "a refused reuse may not run a case")

    def test_a_run_whose_containers_are_gone_is_refused(self):
        self.kept_run()
        message = self.run_main_expecting_exit_2(["--reuse", self.SOURCE], containers=[])
        self.assertIn("no container", message)
        self.assertIn(self.SOURCE, message)
        self.assertFalse(self.podmen)

    def test_a_missing_run_directory_is_refused_by_path(self):
        message = self.run_main_expecting_exit_2(["--reuse", self.SOURCE], containers=[])
        self.assertIn("no run directory", message)
        self.assertIn(str(self.root / self.SOURCE), message)

    def test_a_directory_that_is_not_a_run_is_refused(self):
        self.kept_run(result=False)
        message = self.run_main_expecting_exit_2(["--reuse", self.SOURCE], containers=[])
        self.assertIn("holds no result.json", message)

    def test_a_run_id_cannot_climb_out_of_the_artifact_root(self):
        message = self.run_main_expecting_exit_2(["--reuse", "../escape"], containers=[])
        self.assertIn("not a path", message)

    def test_reuse_and_the_four_distribution_matrix_are_refused(self):
        message = self.run_main_expecting_exit_2(
            ["--reuse", self.SOURCE, "--all-distributions"], containers=[],
        )
        self.assertIn("--all-distributions", message)

    def test_reuse_beside_keep_is_refused(self):
        self.kept_run()
        message = self.run_main_expecting_exit_2(
            ["--reuse", self.SOURCE, "--keep"], containers=["aio-abcdef12"],
        )
        self.assertIn("--keep", message)


class TestReuseResolution(unittest.TestCase):
    """The validation a later reuse will run, tested without a container."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.run_id = "podman-aio-20260101T000000-abcdef12"
        self.directory = self.root / self.run_id
        self.directory.mkdir()
        (self.directory / "result.json").write_text("{}", encoding="utf-8")

    def test_validation_reports_the_directory_and_the_live_containers(self):
        source = run_podman_e2e.validate_reuse(
            self.root, self.run_id, containers=["aio-abcdef12"],
        )
        self.assertEqual(source["run_id"], self.run_id)
        self.assertEqual(source["directory"], self.directory.resolve())
        self.assertEqual(source["containers"], ["aio-abcdef12"])

    def test_no_container_means_the_hosts_are_gone(self):
        with self.assertRaises(run_podman_e2e.ReuseRefused) as caught:
            run_podman_e2e.validate_reuse(self.root, self.run_id, containers=[])
        self.assertIn("no container", str(caught.exception))

    def test_the_container_list_is_read_through_the_runs_own_label(self):
        seen = {}

        def fake_podman(command, **kwargs):
            seen["command"] = list(command)
            seen["kwargs"] = kwargs
            listing = [
                {"Names": ["aio-abcdef12"], "State": "running"},
                {"Names": ["dns-abcdef12"], "State": "running"},
            ]
            return mock.Mock(returncode=0, stdout=json.dumps(listing), stderr="")

        with mock.patch.object(run_podman_e2e, "podman_binary", lambda: "/usr/bin/podman"):
            names = run_podman_e2e.kept_containers(self.run_id, run=fake_podman)
        self.assertEqual(names, ["aio-abcdef12", "dns-abcdef12"])
        self.assertEqual(seen["command"][:2], ["/usr/bin/podman", "ps"])
        self.assertIn(f"label=gowave.e2e.run={self.run_id}", seen["command"])
        self.assertIn("--format", seen["command"])
        self.assertEqual(seen["kwargs"], {
            "capture_output": True, "text": True, "check": False, "timeout": 60,
        })

    def test_a_single_name_and_an_empty_listing_are_both_understood(self):
        def listing(stdout):
            def run(command, **kwargs):
                return mock.Mock(returncode=0, stdout=stdout, stderr="")
            return run

        with mock.patch.object(run_podman_e2e, "podman_binary", lambda: "/usr/bin/podman"):
            single = run_podman_e2e.kept_containers(
                self.run_id, run=listing(json.dumps([{"Names": "aio-abcdef12"}])),
            )
            empty = run_podman_e2e.kept_containers(
                self.run_id, run=listing("[]"),
            )
        self.assertEqual(single, ["aio-abcdef12"])
        self.assertEqual(empty, [])

    def test_a_listing_that_is_not_json_is_a_refusal(self):
        def not_json(command, **kwargs):
            return mock.Mock(returncode=0, stdout="aio-abcdef12", stderr="")

        with mock.patch.object(run_podman_e2e, "podman_binary", lambda: "/usr/bin/podman"):
            with self.assertRaises(run_podman_e2e.ReuseRefused) as caught:
                run_podman_e2e.kept_containers(self.run_id, run=not_json)
        self.assertIn("did not answer JSON", str(caught.exception))

    def test_a_listing_that_fails_is_a_refusal_not_a_traceback(self):
        def failing_podman(command, **kwargs):
            return mock.Mock(returncode=125, stdout="", stderr="cannot connect to Podman")

        with mock.patch.object(run_podman_e2e, "podman_binary", lambda: "/usr/bin/podman"):
            with self.assertRaises(run_podman_e2e.ReuseRefused) as caught:
                run_podman_e2e.kept_containers(self.run_id, run=failing_podman)
        self.assertIn("exited 125", str(caught.exception))
        self.assertIn("cannot connect", str(caught.exception))

    def test_an_absent_podman_is_a_refusal(self):
        from tools.podman_e2e.podman import PodmanUnavailable

        def missing():
            raise PodmanUnavailable("Podman is not installed")

        with mock.patch.object(run_podman_e2e, "podman_binary", missing):
            with self.assertRaises(run_podman_e2e.ReuseRefused) as caught:
                run_podman_e2e.kept_containers(self.run_id)
        self.assertIn("Podman is not installed", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
