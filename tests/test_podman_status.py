#!/usr/bin/env python3
"""Suite nonroot: the report an overall PASS is read from.

``GATE-STATUS`` produces runs of the real runner over the case ids the matrix
declares and reads ``result.json`` and ``junit.xml`` back. These tests drive the
case against both contours and then damage the report it just read, one fact at
a time, so each refusal is held by the side it protects: a green aggregate over a
lost case, a failing case the report does not name, a red run that exits zero, a
report missing a documented field, and a Data Plane nobody judged reported as a
pass.
"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import matrix, status  # noqa: E402
from tools.podman_e2e.runner import RunContext  # noqa: E402

TOPOLOGIES = ("aio", "multi-node")


class TestStatusCase(unittest.TestCase):
    """``GATE-STATUS``: what it demonstrates and what it refuses to demonstrate away."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def context(self, topology):
        return RunContext(
            topology, Path(self.tmp.name), budget_seconds=300,
            run_id=status.PROBE_RUN_ID.format(topology=topology),
        )

    def refuse(self, damage, topology="aio"):
        """Run the case with the probe's own report damaged, and return the refusal."""
        real = status.probe

        def patched(*args, **kwargs):
            observed = real(*args, **kwargs)
            damage(observed, *args, **kwargs)
            return observed

        with mock.patch.object(status, "probe", patched):
            with self.assertRaises(AssertionError) as caught:
                status.case_status_semantics(self.context(topology))
        return str(caught.exception)

    def test_the_case_holds_on_both_contours(self):
        for topology in TOPOLOGIES:
            with self.subTest(topology=topology):
                evidence = status.case_status_semantics(self.context(topology))
                self.assertEqual(
                    evidence["runtime_cases"],
                    matrix.positive_count(matrix.load(), topology),
                )
                self.assertEqual(evidence["two_failing_overall"], "FAIL")
                self.assertEqual(evidence["undecided_overall"], "INCOMPLETE")
                self.assertEqual(evidence["vision_failing_overall"], "FAIL")
                self.assertEqual(evidence["junit_child"], "failure")
                self.assertNotEqual(evidence["skip_aggregate"], "PASS")
                self.assertEqual(evidence["report_schema"], status.REPORT_SCHEMA)
                self.assertEqual(len(evidence["failing_named"].split(", ")), 2)

    def test_the_runtime_cases_are_the_ones_the_matrix_declares(self):
        data = matrix.load()
        self.assertEqual(
            len(status.runtime_case_ids("aio")),
            matrix.positive_count(data, "aio"),
        )
        self.assertEqual(
            len(status.runtime_case_ids("aio", vision=True)),
            matrix.positive_count(data, "aio", vision=True),
        )
        both = status.runtime_case_ids("multi-node", vision=True, worker_vision=True)
        self.assertEqual(len(both), matrix.positive_count(data, "multi-node", vision=True, worker_vision=True))
        self.assertEqual(len(set(both)), len(both), "two tuples share one case id")
        self.assertNotIn(matrix.VISION_INBOUND, "".join(status.runtime_case_ids("aio")))

    def test_the_probe_refuses_a_case_the_matrix_does_not_declare(self):
        with self.assertRaises(ValueError) as caught:
            status.probe("aio", failing=("AIO-DP-NOT-A-TUPLE",))
        self.assertIn("AIO-DP-NOT-A-TUPLE", str(caught.exception))

    def test_a_green_aggregate_over_a_lost_case_is_refused(self):
        refusal = self.refuse(lambda observed, *a, **k: observed.update(overall="PASS"))
        self.assertIn("not 'FAIL'", refusal)
        self.assertIn("survives a lost runtime case", refusal)

    def test_a_failing_case_the_report_does_not_name_is_refused(self):
        def forget_the_failure(observed, *a, **k):
            for case in observed["report"]["cases"]:
                if case["status"] == "FAIL":
                    case["status"] = "PASS"

        refusal = self.refuse(forget_the_failure)
        self.assertIn("identified only in aggregate is not identified", refusal)

    def test_a_red_run_that_exits_zero_is_refused(self):
        refusal = self.refuse(lambda observed, *a, **k: observed.update(exit_status=0))
        self.assertIn("hands the gate a pass", refusal)

    def test_a_report_missing_a_documented_field_is_refused(self):
        refusal = self.refuse(lambda observed, *a, **k: observed["report"].pop("budget_seconds"))
        self.assertIn("missing ['budget_seconds']", refusal)

    def test_a_case_entry_missing_a_documented_field_is_refused(self):
        def drop_one_case_field(observed, *a, **k):
            observed["report"]["cases"][0].pop("evidence")

        refusal = self.refuse(drop_one_case_field)
        self.assertIn("'evidence'", refusal)

    def test_a_report_without_its_revision_is_refused(self):
        refusal = self.refuse(
            lambda observed, *a, **k: observed["report"]["environment"].pop("repository"),
        )
        self.assertIn("evidence only", refusal)

    def test_a_run_that_decided_nothing_cannot_report_pass(self):
        def pass_the_undecided_run(observed, *args, **kwargs):
            if kwargs.get("incomplete"):
                observed["overall"] = "PASS"
                observed["report"]["overall"] = "PASS"

        refusal = self.refuse(pass_the_undecided_run)
        self.assertIn("not 'INCOMPLETE'", refusal)

    def test_a_skipped_case_cannot_aggregate_to_pass(self):
        with mock.patch.object(status, "overall_status", lambda _results: "PASS"):
            with self.assertRaises(AssertionError) as caught:
                status.case_status_semantics(self.context("aio"))
        self.assertIn("must not be the contour that rewards it", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
