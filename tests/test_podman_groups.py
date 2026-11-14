#!/usr/bin/env python3
"""Suite nonroot: required case groups make coverage a verdict, not a count.

The full suite fails when a case fails, but a case deleted from ``cases()``
leaves a shorter run that still reports PASS. These tests hold the other half:
the group names real case ids, an empty or mistyped group is refused instead of
being vacuously green, and a run that requires one carries the promise and the
shortfall in its own artifact.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import aio, groups, multi_node  # noqa: E402
from tools.podman_e2e.runner import (  # noqa: E402
    FAIL,
    NOT_APPLICABLE,
    PASS,
    Case,
    CaseNotApplicable,
    CaseResult,
    RunContext,
    Runner,
)


class TestGroupDefinitions(unittest.TestCase):
    """A group must name cases the suite actually declares."""

    def context(self, topology: str) -> RunContext:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        return RunContext(
            topology, Path(self.tmp.name), budget_seconds=60,
            run_id=f"podman-{topology}-test-abcdef12",
        )

    def suite_ids(self, topology: str) -> set:
        podman = SimpleNamespace(context=self.context(topology))
        if topology == "aio":
            return {case.id for case in aio.cases(podman)}
        return {case.id for case in multi_node.cases(podman)}

    def test_every_recovery_id_is_declared_by_its_own_suite(self):
        for topology in ("aio", "multi-node"):
            with self.subTest(topology=topology):
                declared = self.suite_ids(topology)
                missing = [
                    case_id for case_id in groups.required_ids(groups.RECOVERY, topology)
                    if case_id not in declared
                ]
                self.assertEqual(
                    missing, [],
                    f"the recovery group names cases the {topology} suite does not declare",
                )

    def test_an_unknown_group_is_refused(self):
        with self.assertRaises(ValueError) as caught:
            groups.required_ids("nonsense", "aio")
        self.assertIn("unknown case group", str(caught.exception))

    def test_a_group_without_the_topology_is_refused(self):
        with self.assertRaises(ValueError) as caught:
            groups.required_ids(groups.RECOVERY, "live")
        self.assertIn("declares no cases for topology", str(caught.exception))

    def test_a_group_that_selects_nothing_is_refused(self):
        # A group required to prove nothing is the green-looking run this module
        # exists to refuse, so an empty definition is a configuration error.
        empty = {"recovery": {"aio": ()}}
        original = groups.GROUP_CASES
        groups.GROUP_CASES = empty
        try:
            with self.assertRaises(ValueError) as caught:
                groups.required_ids("recovery", "aio")
        finally:
            groups.GROUP_CASES = original
        self.assertIn("selects no cases", str(caught.exception))


class TestUnmet(unittest.TestCase):
    def test_absent_and_not_passing_are_named_apart(self):
        results = [
            CaseResult("AIO-RESTART", "aio", PASS),
            CaseResult("AIO-FAULT-XRAY", "aio", FAIL),
            CaseResult("AIO-REVOKE", "aio", NOT_APPLICABLE),
        ]
        problems = groups.unmet(
            ("AIO-RESTART", "AIO-FAULT-XRAY", "AIO-REVOKE", "AIO-IDEMPOTENT"),
            results,
            passing=PASS,
        )
        self.assertEqual(problems, [
            "AIO-FAULT-XRAY: FAIL",
            "AIO-REVOKE: NOT_APPLICABLE",
            "AIO-IDEMPOTENT: not declared in this run",
        ])

    def test_a_fully_passing_group_has_no_problems(self):
        results = [CaseResult(case_id, "aio", PASS) for case_id in ("A", "B")]
        self.assertEqual(groups.unmet(("A", "B"), results, passing=PASS), [])


class TestRequiredGroupRun(unittest.TestCase):
    """The declaration reaches result.json, JUnit and the exit status."""

    def context(self) -> RunContext:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        return RunContext(
            "aio", Path(self.tmp.name), budget_seconds=60,
            run_id="podman-aio-test-abcdef12",
        )

    def add_recovery_cases(self, runner: Runner, statuses=None) -> None:
        statuses = statuses or {}

        def behaviour(case_id):
            def run(_context):
                if statuses.get(case_id) == NOT_APPLICABLE:
                    raise CaseNotApplicable("no subject here")
                if statuses.get(case_id) == FAIL:
                    raise AssertionError("contradicted")
                return {"note": "ok"}
            return run

        for case_id in groups.required_ids(groups.RECOVERY, "aio"):
            runner.add(Case(case_id, "aio", behaviour(case_id)))

    def test_a_covered_group_is_green_and_the_audit_names_every_id(self):
        context = self.context()
        runner = Runner(context)
        runner.require_group(groups.RECOVERY)
        self.add_recovery_cases(runner)
        self.assertEqual(runner.execute(), 0)
        report = json.loads((context.artifact_dir / "result.json").read_text())
        self.assertEqual(report["overall"], PASS)
        audit = report["environment"]["required_groups"][groups.RECOVERY]
        self.assertEqual(audit["topology"], "aio")
        self.assertEqual(audit["unmet"], [])
        self.assertEqual(
            sorted(audit["required"]),
            sorted(groups.required_ids(groups.RECOVERY, "aio")),
        )

    def test_a_case_dropped_from_the_suite_fails_the_run(self):
        context = self.context()
        runner = Runner(context)
        runner.require_group(groups.RECOVERY)
        required = groups.required_ids(groups.RECOVERY, "aio")
        dropped = required[0]
        for case_id in required[1:]:
            runner.add(Case(case_id, "aio", lambda _ctx: {}))
        self.assertEqual(runner.execute(), 1)
        report = json.loads((context.artifact_dir / "result.json").read_text())
        self.assertEqual(report["overall"], FAIL)
        verdict = [case for case in report["cases"] if case["id"] == "REQUIRED-GROUP"]
        self.assertEqual(len(verdict), 1)
        self.assertIn(f"{dropped}: not declared in this run", verdict[0]["message"])
        self.assertEqual(
            report["environment"]["required_groups"][groups.RECOVERY]["unmet"],
            [f"{dropped}: not declared in this run"],
        )

    def test_a_not_applicable_recovery_case_does_not_satisfy_the_group(self):
        context = self.context()
        runner = Runner(context)
        runner.require_group(groups.RECOVERY)
        skipped = groups.required_ids(groups.RECOVERY, "aio")[-1]
        self.add_recovery_cases(runner, statuses={skipped: NOT_APPLICABLE})
        self.assertEqual(runner.execute(), 1)
        report = json.loads((context.artifact_dir / "result.json").read_text())
        verdict = [case for case in report["cases"] if case["id"] == "REQUIRED-GROUP"]
        self.assertIn(f"{skipped}: NOT_APPLICABLE", verdict[0]["message"])

    def test_the_declaration_is_refused_before_the_run_when_the_group_is_unknown(self):
        context = self.context()
        runner = Runner(context)
        with self.assertRaises(ValueError):
            runner.require_group("nonsense")


if __name__ == "__main__":
    unittest.main()
