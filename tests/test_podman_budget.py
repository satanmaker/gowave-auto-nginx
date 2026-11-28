#!/usr/bin/env python3
"""Suite nonroot: the declared runtime budget is a deadline, not a suggestion.

8.15 asks three things of the budget declared in ``tests/cases/matrix.yaml``: the
run is bounded by it, a run that spends it reports ``INCOMPLETE`` naming the
cases it did not run instead of dropping them, and the pull-request checks are
backed by the same envelope. These tests read the declaration out of the
manifest, drive the entrypoint's argument handling with the container layer
replaced, and run the ``GATE-BUDGET`` case against fake contexts so each refusal
is held by the side it protects: a widened deadline is refused before anything
runs, and the probe's report is refused when any of the facts it demonstrates
goes missing.
"""
import contextlib
import copy
import inspect
import io
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools import run_podman_e2e  # noqa: E402
from tools.podman_e2e import budget, matrix, podman as podman_module  # noqa: E402
from tools.podman_e2e.runner import BudgetExhausted, RunContext  # noqa: E402


def declared_aio():
    """The AIO deadline the manifest declares, for a test that needs a number.

    The numbers are the manifest's, not this file's: restating one here would
    make a manifest edit pass while the copy stayed behind. The published copies
    in ``docs/PODMAN_E2E.md`` are checked against the same declaration in
    ``test_podman_docs``.
    """
    return matrix.runtime_budget_seconds(matrix.load(), "aio")


class TestDeclaredBudget(unittest.TestCase):
    """The manifest's numbers, read out of it rather than restated."""

    def setUp(self):
        self.data = matrix.load()

    def test_each_topology_declares_its_own_deadline(self):
        declared = {
            name: matrix.runtime_budget_seconds(self.data, name)
            for name in run_podman_e2e.TOPOLOGIES
        }
        for name, seconds in declared.items():
            with self.subTest(topology=name):
                self.assertIs(type(seconds), int)
                self.assertGreater(seconds, 0)
        # One topology's declaration is its own: raising it must not move the
        # deadline any other topology runs under.
        raised = copy.deepcopy(self.data)
        raised["topologies"]["aio"]["runtime_budget_seconds"] = declared["aio"] + 1
        self.assertEqual(matrix.runtime_budget_seconds(raised, "aio"), declared["aio"] + 1)
        for name in run_podman_e2e.TOPOLOGIES:
            if name != "aio":
                self.assertEqual(matrix.runtime_budget_seconds(raised, name), declared[name])

    def test_the_case_reads_the_same_declaration(self):
        for topology in run_podman_e2e.TOPOLOGIES:
            with self.subTest(topology=topology):
                self.assertEqual(
                    budget.declared(topology, self.data),
                    matrix.runtime_budget_seconds(self.data, topology),
                )

    def test_a_topology_without_a_budget_is_refused(self):
        doctored = {"topologies": {"aio": {"positive_case_counts": {}}}}
        with self.assertRaises(KeyError):
            matrix.runtime_budget_seconds(doctored, "aio")

    def test_the_tier_totals_are_read_from_the_same_block(self):
        for tier in ("pre_push", "pr", "nightly"):
            with self.subTest(tier=tier):
                self.assertEqual(
                    matrix.tier_budget_seconds(self.data, tier),
                    self.data["runtime_budget"][f"{tier}_total_seconds"],
                    "the tier is read from the block that declares it",
                )
        self.assertEqual(self.data["runtime_budget"]["on_exhaustion"], "INCOMPLETE")

    def test_the_pre_push_total_covers_every_gated_topology(self):
        gated = [
            name for name, entry in self.data["topologies"].items()
            if "pre-push" in (entry.get("gate") or [])
        ]
        spent = sum(matrix.runtime_budget_seconds(self.data, name) for name in gated)
        self.assertLessEqual(
            spent, matrix.tier_budget_seconds(self.data, "pre_push"),
            "a topology added to the pre-push gate without raising the total would "
            "make the tier promise a bound it cannot keep",
        )

    def test_a_tier_without_a_total_is_refused(self):
        with self.assertRaises(KeyError):
            matrix.tier_budget_seconds({"runtime_budget": {"pr_total_seconds": 10}}, "pre_push")


class TestBudgetCase(unittest.TestCase):
    """``GATE-BUDGET``: what it demonstrates and what it refuses to demonstrate away."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def context(self, budget_seconds):
        return RunContext(
            "aio", Path(self.tmp.name),
            budget_seconds=budget_seconds, run_id=f"podman-aio-budget-{budget_seconds:08d}",
        )

    def test_the_case_passes_inside_the_declared_envelope(self):
        declared = declared_aio()
        context = self.context(declared)
        evidence = budget.case_budget(context)
        self.assertEqual(evidence["declared_budget_seconds"], declared)
        self.assertEqual(evidence["enforced_budget_seconds"], declared)
        self.assertLessEqual(evidence["elapsed_seconds"], evidence["enforced_budget_seconds"])
        self.assertEqual(evidence["probe_overall"], "INCOMPLETE")
        self.assertNotEqual(evidence["probe_exit_status"], 0)
        self.assertIn(budget.UNEXECUTED_PHRASE, evidence["probe_case_message"])
        self.assertNotEqual(evidence["aggregate_of_incomplete"], "PASS")

    def test_the_case_refuses_a_run_that_already_spent_its_deadline(self):
        # The case closes the suite, so the clock it reads is the run's own: a run
        # that arrives past its deadline owes INCOMPLETE for what it lost, and its
        # final case must not hand it a pass instead.
        context = self.context(60)
        context.started -= 61
        with self.assertRaises(AssertionError) as caught:
            budget.case_budget(context)
        self.assertIn("after 61", str(caught.exception))
        self.assertIn("of a 60s deadline", str(caught.exception))
        self.assertIn("not a pass from this one", str(caught.exception))

    def test_a_tightened_deadline_is_allowed(self):
        self.assertEqual(
            budget.case_budget(self.context(60))["enforced_budget_seconds"], 60,
            "an operator may tighten the deadline for a quick local run",
        )

    def test_a_widened_deadline_fails_the_case(self):
        declared = declared_aio()
        with self.assertRaises(AssertionError) as caught:
            budget.case_budget(self.context(declared + 1))
        self.assertIn(f"outside the {declared}s", str(caught.exception))
        self.assertIn("cannot claim", str(caught.exception))

    def test_a_run_with_no_budget_cannot_pass_the_case(self):
        with self.assertRaises(AssertionError):
            budget.case_budget(self.context(0))

    def probe_with(self, **changes):
        observed = {
            "exit_status": 1, "overall": "INCOMPLETE", "case_status": "INCOMPLETE",
            "case_message": "Runtime budget exhausted before the case ran", "case_count": 1,
        }
        observed.update(changes)
        return observed

    def test_the_case_refuses_a_probe_that_exited_zero(self):
        with mock.patch.object(budget, "probe", return_value=self.probe_with(exit_status=0)):
            with self.assertRaises(AssertionError) as caught:
                budget.case_budget(self.context(declared_aio()))
        self.assertIn("must not exit 0", str(caught.exception))

    def test_the_case_refuses_a_probe_that_reported_pass(self):
        with mock.patch.object(budget, "probe", return_value=self.probe_with(overall="PASS")):
            with self.assertRaises(AssertionError) as caught:
                budget.case_budget(self.context(declared_aio()))
        self.assertIn("not 'INCOMPLETE'", str(caught.exception))

    def test_the_case_refuses_a_dropped_case(self):
        with mock.patch.object(budget, "probe", return_value=self.probe_with(case_count=0)):
            with self.assertRaises(AssertionError) as caught:
                budget.case_budget(self.context(declared_aio()))
        self.assertIn("truncated pass", str(caught.exception))

    def test_the_case_refuses_a_case_that_does_not_say_why_it_did_not_run(self):
        with mock.patch.object(budget, "probe", return_value=self.probe_with(case_message="")):
            with self.assertRaises(AssertionError) as caught:
                budget.case_budget(self.context(declared_aio()))
        self.assertIn("does not name why it did not run", str(caught.exception))


class TestEntrypointBudget(unittest.TestCase):
    """How the entrypoint turns the declaration into the deadline it runs with."""

    def main(self, argv):
        seen = {}

        class _Podman:
            def __init__(self, context):
                seen["budget_seconds"] = context.budget_seconds

            def remove_stale_runs(self):
                return []

            def register_cleanup(self):
                pass

        class _Runner:
            def __init__(self, context):
                pass

            def add(self, case):
                pass

            def on_failure(self, hook):
                pass

            def execute(self):
                return 0

        stdout, stderr = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(run_podman_e2e, "Podman", _Podman), \
                mock.patch.object(run_podman_e2e, "Runner", _Runner), \
                mock.patch.object(run_podman_e2e, "build_suite", lambda *a, **k: []), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = run_podman_e2e.main(
                [*argv, "--artifact-root", directory]
            )
        return status, stdout.getvalue(), stderr.getvalue(), seen

    def test_the_deadline_is_the_one_the_manifest_declares(self):
        for topology in ("aio", "multi-node"):
            with self.subTest(topology=topology):
                declared = matrix.runtime_budget_seconds(matrix.load(), topology)
                status, _out, _err, seen = self.main(["--topology", topology])
                self.assertEqual(status, 0)
                self.assertEqual(seen["budget_seconds"], declared)

    def test_a_widened_override_is_refused_before_anything_runs(self):
        with self.assertRaises(SystemExit) as caught:
            self.main(["--topology", "aio", "--budget-seconds", str(declared_aio() + 1)])
        self.assertEqual(caught.exception.code, 2)

    def test_a_tightened_override_reaches_the_run(self):
        status, _out, _err, seen = self.main(["--topology", "aio", "--budget-seconds", "60"])
        self.assertEqual(status, 0)
        self.assertLess(60, declared_aio(), "the tightened value has to be a tightening")
        self.assertEqual(seen["budget_seconds"], 60)


class TestOperationCeilings(unittest.TestCase):
    """The image pull and the image build are bounded by the work, not by a probe.

    ``podman-acceptance.yml`` run 45161440198 killed ``AIO-INSTALL`` at 311.2 s
    and ``PO-INSTALL`` at 306.8 s because both rode the 300-second probe default,
    so these tests hold the two sites that carry the install: each names its own
    ceiling, each ceiling is capped by what the run has left, and every other
    caller keeps the probe default.
    """

    DIGEST = "sha256:" + "a" * 64

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def context(self, budget_seconds=10 ** 6):
        context = RunContext(
            "aio", Path(self.tmp.name),
            budget_seconds=budget_seconds, run_id="podman-aio-ceilings-abcdef12",
        )
        self.addCleanup(context.run_cleanup)
        return context

    def podman(self, context):
        """A ``Podman`` with the binary lookup and the run identity stubbed out."""
        instance = podman_module.Podman.__new__(podman_module.Podman)
        instance.context = context
        instance.binary = "podman"
        instance._built_images = set()
        instance._started_epoch = 0
        return instance

    def recorder(self):
        """Every ``podman`` invocation with the timeout it was given."""
        calls = []
        pinned = f"docker.io/library/ubuntu@{self.DIGEST}"

        def run(argv, **kwargs):
            calls.append((list(argv), kwargs.get("timeout")))
            if list(argv)[1:2] == ["image"]:
                return subprocess.CompletedProcess(argv, 0, json.dumps([pinned]), "")
            return subprocess.CompletedProcess(argv, 0, "", "")

        return calls, run, pinned

    def test_the_pull_gets_its_own_ceiling(self):
        calls, run, pinned = self.recorder()
        with mock.patch.object(podman_module, "resolve", return_value=pinned), \
                mock.patch.object(podman_module.subprocess, "run", side_effect=run):
            self.podman(self.context()).ensure_image("ubuntu-2404")
        pull = [entry for entry in calls if entry[0][1:2] == ["pull"]]
        self.assertEqual(len(pull), 1, f"expected exactly one pull, saw {calls}")
        self.assertEqual(pull[0][1], podman_module.PULL_CEILING_SECONDS)
        # Task 4.2 measured it: the pull costs at most 11.2 s of the 311.2 s that a
        # 300 s build kill ended, and 1 s on a cold local store, so the kill that
        # reddened AIO-INSTALL belonged to the build and the pull is left on the
        # probe default it already had.
        self.assertEqual(podman_module.PULL_CEILING_SECONDS, podman_module.DEFAULT_COMMAND_TIMEOUT,
                         "the pull measures in seconds, so it keeps the probe default rather than a larger floor")
        self.assertGreater(podman_module.PULL_CEILING_SECONDS, 11.2)

    def test_the_build_gets_its_own_ceiling(self):
        calls, run, _pinned = self.recorder()
        instance = self.podman(self.context())
        with mock.patch.object(podman_module.Podman, "ensure_image",
                               lambda _self, alias: f"base@{self.DIGEST}"), \
                mock.patch.object(podman_module.subprocess, "run", side_effect=run):
            instance.build("target:test", "ubuntu-2404", Path("/tmp/Containerfile.target"),
                           Path("/tmp"))
        build = [entry for entry in calls if entry[0][1:2] == ["build"]]
        self.assertEqual(len(build), 1, f"expected exactly one build, saw {calls}")
        self.assertEqual(build[0][1], podman_module.BUILD_CEILING_SECONDS)
        self.assertGreater(podman_module.BUILD_CEILING_SECONDS, 311.2,
                           "a 14 s cold build still outlasted 300 s on the runner, so the floor stays above that")

    def test_a_ceiling_is_capped_by_what_the_run_has_left(self):
        context = self.context(budget_seconds=600)
        context.started -= 589.5
        timeout = podman_module.operation_timeout(context, podman_module.PULL_CEILING_SECONDS, "podman pull x")
        self.assertEqual(timeout, 10, "a run with ten seconds left hands the command ten seconds")
        self.assertLess(timeout, podman_module.PULL_CEILING_SECONDS)

    def test_a_spent_budget_refuses_before_the_command_starts(self):
        context = self.context(budget_seconds=60)
        context.started -= 61
        _calls, run, _pinned = self.recorder()
        with mock.patch.object(podman_module.subprocess, "run", side_effect=run) as started:
            with self.assertRaises(BudgetExhausted) as caught:
                podman_module.operation_timeout(context, podman_module.BUILD_CEILING_SECONDS, "podman build x")
        self.assertIn("podman build x", str(caught.exception))
        self.assertFalse(started.called, "a command that cannot finish must not be started")

    def test_every_other_caller_keeps_the_probe_default(self):
        for name in ("_run", "exec", "exec_bash"):
            with self.subTest(name=name):
                signature = inspect.signature(getattr(podman_module.Podman, name))
                self.assertEqual(signature.parameters["timeout"].default,
                                 podman_module.DEFAULT_COMMAND_TIMEOUT,
                                 f"{name} lost the probe default")
        self.assertEqual(podman_module.DEFAULT_COMMAND_TIMEOUT, 300)


if __name__ == "__main__":
    unittest.main()
