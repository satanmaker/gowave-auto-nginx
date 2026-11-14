#!/usr/bin/env python3
"""Suite nonroot: the traceability table is an audit, not a document.

`tests/cases/traceability.yaml` claims that every scenario of the delta spec is
proved by a case or a test and runs in a named CI job. These tests hold the
claims to what exists: the spec's scenario list, the ids the two suites declare,
the test classes under `tests/`, the jobs the workflows declare, and the ledger's
open boxes. A row that cites a case nobody declares, a test nobody wrote, a job
no workflow has, or a task that is already closed must fail here rather than in
a review.
"""
import contextlib
import io
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import trace  # noqa: E402


class TestTraceabilityRules(unittest.TestCase):
    """Every rule the audit applies, driven by the real inputs it reads."""

    def setUp(self):
        self.spec = trace.parse_spec()
        self.declared = trace.declared_cases()
        self.jobs = trace.declared_jobs()
        self.tasks = trace.task_boxes()
        self.tests = trace.test_index()
        self.table = trace.load_table()

    def problems(self, table=None):
        return trace.validate(
            table if table is not None else self.table,
            self.spec, self.declared, self.jobs, self.tasks, self.tests,
        )

    def row_in(self, table, scenario):
        """The row as the table holds it; ``trace.rows`` returns copies."""
        for group in table.get("requirements") or []:
            for row in group.get("scenarios") or []:
                if row.get("scenario") == scenario:
                    return row
        raise AssertionError(f"no row for {scenario!r}")

    def test_the_checked_in_table_agrees_with_what_it_cites(self):
        self.assertEqual(
            self.problems(), [],
            "the audit that ships with the change must hold on its own tree",
        )

    def test_every_spec_scenario_has_exactly_one_row(self):
        self.assertEqual(len(self.spec), 45, "the delta spec states 45 scenarios")
        self.assertEqual(len(trace.rows(self.table)), 45)
        self.assertEqual(len({tuple(row) for row in self.spec}), 45)

    def test_every_declared_case_is_mapped_or_serves_a_requirement(self):
        mapped = {
            pair
            for row in trace.rows(self.table)
            for pair in trace.expand(row.get("cases") or [], self.declared)[0]
        }
        for entry in trace.unstated(self.table):
            mapped |= set(trace.expand(entry.get("cases") or [], self.declared)[0])
        for topology in trace.TOPOLOGIES:
            for case_id in self.declared[topology]:
                with self.subTest(case=case_id):
                    self.assertIn((topology, case_id), mapped)

    def test_a_missing_row_is_named(self):
        table = trace.load_table()
        first = table["requirements"][0]
        dropped = first["scenarios"].pop(0)["scenario"]
        problems = self.problems(table)
        self.assertTrue(
            any(dropped in problem and "no row" in problem for problem in problems),
            problems,
        )

    def test_a_scenario_the_spec_does_not_state_is_refused(self):
        table = trace.load_table()
        table["requirements"][0]["scenarios"][0]["scenario"] = "A Scenario Nobody Wrote"
        problems = self.problems(table)
        self.assertTrue(any("not a scenario" in problem for problem in problems), problems)

    def test_a_duplicated_scenario_is_refused(self):
        table = trace.load_table()
        row = dict(table["requirements"][0]["scenarios"][0])
        table["requirements"][0]["scenarios"].append(row)
        problems = self.problems(table)
        self.assertTrue(any("listed 2 times" in problem for problem in problems), problems)

    def test_a_case_no_suite_declares_is_refused(self):
        table = trace.load_table()
        table["requirements"][0]["scenarios"][0]["cases"].append("AIO-NOT-A-CASE")
        problems = self.problems(table)
        self.assertTrue(any("AIO-NOT-A-CASE" in problem for problem in problems), problems)

    def test_a_case_in_a_topology_the_row_does_not_name_is_refused(self):
        table = trace.load_table()
        row = self.row_in(table, "All-in-One repeated provisioning")
        row["topologies"] = ["multi-node"]
        problems = self.problems(table)
        self.assertTrue(
            any("AIO-IDEMPOTENT" in problem and "does not name" in problem for problem in problems),
            problems,
        )

    def test_a_test_nobody_wrote_is_refused(self):
        table = trace.load_table()
        row = self.row_in(table, "Secret redaction")
        row["tests"] = ["tests.test_podman_redaction.TestNotWritten"]
        problems = self.problems(table)
        self.assertTrue(
            any("no test class tests.test_podman_redaction.TestNotWritten" in problem
                for problem in problems),
            problems,
        )

    def test_a_test_method_nobody_wrote_is_refused(self):
        table = trace.load_table()
        row = self.row_in(table, "Secret redaction")
        row["tests"] = ["tests.test_podman_redaction.TestRedactionFilter.test_not_written"]
        problems = self.problems(table)
        self.assertTrue(any("no test method" in problem for problem in problems), problems)

    def test_a_job_no_workflow_declares_is_refused(self):
        table = trace.load_table()
        row = self.row_in(table, "Secret redaction")
        row["jobs"] = ["Imaginary Acceptance"]
        problems = self.problems(table)
        self.assertTrue(any("Imaginary Acceptance" in problem for problem in problems), problems)

    def test_a_row_with_evidence_but_no_job_is_refused(self):
        table = trace.load_table()
        row = self.row_in(table, "Secret redaction")
        row["jobs"] = []
        problems = self.problems(table)
        self.assertTrue(any("names no CI job" in problem for problem in problems), problems)

    def test_a_row_that_proves_nothing_is_refused(self):
        table = trace.load_table()
        row = self.row_in(table, "Secret redaction")
        row["tests"] = []
        problems = self.problems(table)
        self.assertTrue(any("proves nothing" in problem for problem in problems), problems)

    def test_a_gap_must_be_owned_by_an_open_task(self):
        table = trace.load_table()
        row = self.row_in(table, "Pre-push run blocks a regressed change")
        row["gap"] = "8.6 — closed long ago"
        problems = self.problems(table)
        self.assertTrue(any("already closed" in problem for problem in problems), problems)

    def test_a_gap_naming_no_task_is_refused(self):
        table = trace.load_table()
        row = self.row_in(table, "Pre-push run blocks a regressed change")
        row["gap"] = "99.9 — a task that is not in the ledger"
        problems = self.problems(table)
        self.assertTrue(any("no task of the ledger" in problem for problem in problems), problems)

    def test_a_case_serving_a_requirement_must_name_a_reason(self):
        table = trace.load_table()
        entry = table["cases_by_requirement"][0]
        entry["reason"] = "  "
        problems = self.problems(table)
        self.assertTrue(any("names no reason" in problem for problem in problems), problems)

    def test_a_case_serving_a_requirement_must_not_also_be_mapped_to_a_scenario(self):
        table = trace.load_table()
        table["cases_by_requirement"][0]["cases"] = ["AIO-INSTALL"]
        problems = self.problems(table)
        self.assertTrue(any("already mapped to a scenario" in problem for problem in problems), problems)

    def test_an_orphan_case_is_named(self):
        table = trace.load_table()
        entry = next(
            entry for entry in table["cases_by_requirement"]
            if entry["requirement"] == "Failure injection and recovery"
        )
        entry["cases"].remove("AIO-FAULT-DISK")
        problems = self.problems(table)
        self.assertTrue(
            any("orphan case: AIO-FAULT-DISK" in problem for problem in problems),
            problems,
        )

    def test_strict_refuses_the_gaps_the_table_still_has(self):
        gaps = trace.gaps(self.table)
        self.assertEqual(
            {gap.split()[0] for _requirement, _scenario, gap in gaps},
            {"8.14", "8.15", "8.16", "8.17"},
            "each open gap must name the ledger task that owns it",
        )

    def test_the_audit_entrypoint_reads_the_checked_in_table(self):
        with contextlib.redirect_stdout(io.StringIO()) as printed:
            self.assertEqual(trace.main(["--check"]), 0)
        self.assertIn("45 scenarios, 45 rows", printed.getvalue())
        with contextlib.redirect_stdout(io.StringIO()) as printed:
            self.assertEqual(trace.main(["--strict"]), 1)
        self.assertIn("--strict refuses", printed.getvalue())


if __name__ == "__main__":
    unittest.main()
