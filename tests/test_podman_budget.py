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
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools import run_podman_e2e  # noqa: E402
from tools.podman_e2e import budget, matrix  # noqa: E402
from tools.podman_e2e.runner import RunContext  # noqa: E402


class TestDeclaredBudget(unittest.TestCase):
    """The manifest's numbers, read out of it rather than restated."""

    def setUp(self):
        self.data = matrix.load()

    def test_each_topology_declares_its_own_deadline(self):
        self.assertEqual(matrix.runtime_budget_seconds(self.data, "aio"), 2700)
        self.assertEqual(matrix.runtime_budget_seconds(self.data, "multi-node"), 4500)

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
        self.assertEqual(matrix.tier_budget_seconds(self.data, "pre_push"), 7200)
        self.assertEqual(matrix.tier_budget_seconds(self.data, "pr"), 9000)
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
        context = self.context(budget.declared("aio"))
        evidence = budget.case_budget(context)
        self.assertEqual(evidence["declared_budget_seconds"], 2700)
        self.assertEqual(evidence["enforced_budget_seconds"], 2700)
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
        with self.assertRaises(AssertionError) as caught:
            budget.case_budget(self.context(2701))
        self.assertIn("outside the 2700s", str(caught.exception))
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
                budget.case_budget(self.context(2700))
        self.assertIn("must not exit 0", str(caught.exception))

    def test_the_case_refuses_a_probe_that_reported_pass(self):
        with mock.patch.object(budget, "probe", return_value=self.probe_with(overall="PASS")):
            with self.assertRaises(AssertionError) as caught:
                budget.case_budget(self.context(2700))
        self.assertIn("not 'INCOMPLETE'", str(caught.exception))

    def test_the_case_refuses_a_dropped_case(self):
        with mock.patch.object(budget, "probe", return_value=self.probe_with(case_count=0)):
            with self.assertRaises(AssertionError) as caught:
                budget.case_budget(self.context(2700))
        self.assertIn("truncated pass", str(caught.exception))

    def test_the_case_refuses_a_case_that_does_not_say_why_it_did_not_run(self):
        with mock.patch.object(budget, "probe", return_value=self.probe_with(case_message="")):
            with self.assertRaises(AssertionError) as caught:
                budget.case_budget(self.context(2700))
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
        for topology, declared in (("aio", 2700), ("multi-node", 4500)):
            with self.subTest(topology=topology):
                status, _out, _err, seen = self.main(["--topology", topology])
                self.assertEqual(status, 0)
                self.assertEqual(seen["budget_seconds"], declared)

    def test_a_widened_override_is_refused_before_anything_runs(self):
        with self.assertRaises(SystemExit) as caught:
            self.main(["--topology", "aio", "--budget-seconds", "7200"])
        self.assertEqual(caught.exception.code, 2)

    def test_a_tightened_override_reaches_the_run(self):
        status, _out, _err, seen = self.main(["--topology", "aio", "--budget-seconds", "60"])
        self.assertEqual(status, 0)
        self.assertEqual(seen["budget_seconds"], 60)


if __name__ == "__main__":
    unittest.main()
