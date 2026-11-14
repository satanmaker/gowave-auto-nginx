#!/usr/bin/env python3
"""Suite nonroot: the traceability table is an audit, not a document.

`tests/cases/traceability.yaml` claims that every scenario of the delta spec is
proved by a case or a test and runs in a named CI job. These tests hold the
claims to what exists: the spec's scenario list, the ids the two suites declare,
the test classes under `tests/`, the jobs the workflows declare, and the ledger's
open boxes. A row that cites a case nobody declares, a test nobody wrote, a job
no workflow has, or a task that is already closed must fail here rather than in
a review. The published report is judged the same way: it is what the table
renders to, or it is refused.
"""
import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import catalog, trace  # noqa: E402


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

    def test_the_published_report_is_the_table_rendered(self):
        self.assertEqual(
            trace.report_problems(self.table), [],
            "docs/PODMAN_E2E_TRACEABILITY.md must be the text the table renders to",
        )

    def test_a_report_that_drifts_from_the_table_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "PODMAN_E2E_TRACEABILITY.md"
            report.write_text("| Requirement | Scenario |\n| --- | --- |\n", encoding="utf-8")
            problems = trace.report_problems(self.table, report)
        self.assertTrue(
            any("not what the table renders to" in problem for problem in problems), problems
        )

    def test_a_missing_report_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            problems = trace.report_problems(self.table, Path(directory) / "absent.md")
        self.assertTrue(any("is missing" in problem for problem in problems), problems)

    def test_the_report_carries_every_scenario_and_the_gap_count(self):
        report = trace.render(self.table)
        for requirement, scenario in self.spec:
            with self.subTest(scenario=scenario):
                self.assertIn(f"| {requirement} | {scenario} |", report)
        self.assertIn(f"Open gaps: {len(trace.gaps(self.table))}.", report)
        self.assertIn("## Cases serving a requirement that states no scenario", report)
        for entry in trace.unstated(self.table):
            with self.subTest(requirement=entry["requirement"]):
                self.assertIn(entry["requirement"], report)

    def test_the_positive_case_counts_are_what_the_suites_declare(self):
        self.assertEqual(
            trace.positive_counts(), [],
            "the manifest's expected positive-case counts must be the ones the suites declare",
        )

    def test_a_manifest_count_the_suite_does_not_declare_is_refused(self):
        doctored = copy.deepcopy(catalog.load_catalog())
        doctored["expected_positive_case_counts"]["multi-node"]["vision_both"] = 21
        with mock.patch.object(catalog, "load_catalog", return_value=doctored):
            problems = trace.positive_counts()
        self.assertTrue(
            any("multi-node/vision_both" in problem and "21" in problem for problem in problems),
            problems,
        )

    def test_every_non_optional_matrix_row_is_named_by_a_scenario(self):
        self.assertEqual(trace.matrix_problems(self.table, self.declared), [])
        required = trace.required_matrix_rows()
        self.assertEqual(
            len(required), 24,
            "4 non-optional inbounds x 2 clients x (1 All-in-One + 2 Multi-Node nodes)",
        )
        self.assertEqual({row[0] for row in required}, {"aio", "multi-node"})

    def test_a_matrix_row_no_scenario_names_is_refused(self):
        table = copy.deepcopy(self.table)
        for row in table["requirements"]:
            for scenario_row in row["scenarios"]:
                scenario_row["cases"] = [
                    case for case in scenario_row.get("cases") or [] if case != "AIO-DP-*"
                ]
        problems = trace.matrix_problems(table, self.declared)
        self.assertTrue(
            any(
                "aio: no scenario names the matrix row REALITY/xray" in problem
                for problem in problems
            ),
            problems,
        )

    def test_a_case_id_naming_an_undeclared_inbound_is_refused(self):
        table = copy.deepcopy(self.table)
        row = self.row_in(table, "Fixture chain is trusted by Xray and Mihomo")
        row["cases"][0] = "AIO-DP-QUIC-xray"
        declared = dict(self.declared)
        declared["aio"] = [*self.declared["aio"], "AIO-DP-QUIC-xray"]
        problems = trace.matrix_problems(table, declared)
        self.assertTrue(
            any("names the inbound 'QUIC'" in problem for problem in problems), problems
        )

    def test_a_case_id_naming_an_undeclared_node_is_refused(self):
        table = copy.deepcopy(self.table)
        self.row_in(table, "Worker data-plane traffic cannot bypass Worker")["cases"] = [
            "MN-DP-edge-REALITY-xray"
        ]
        declared = dict(self.declared)
        declared["multi-node"] = [*self.declared["multi-node"], "MN-DP-edge-REALITY-xray"]
        problems = trace.matrix_problems(table, declared)
        self.assertTrue(any("names the node 'edge'" in problem for problem in problems), problems)

    def test_a_data_plane_id_without_a_client_is_refused(self):
        table = copy.deepcopy(self.table)
        self.row_in(table, "Worker data-plane traffic cannot bypass Worker")["cases"] = [
            "MN-DP-REALITY"
        ]
        declared = dict(self.declared)
        declared["multi-node"] = [*self.declared["multi-node"], "MN-DP-REALITY"]
        problems = trace.matrix_problems(table, declared)
        self.assertTrue(any("names no client" in problem for problem in problems), problems)

    def test_the_matrix_column_names_the_rows_the_case_ids_decode_to(self):
        report = trace.render(self.table)
        self.assertIn(
            "| Requirement | Scenario | Matrix rows | Cases | Tests | Job | Gap |", report
        )
        self.assertIn("8 of 8 aio rows, 16 of 16 multi-node rows", report)
        row = next(
            line for line in report.splitlines()
            if line.startswith("| Private test CA trust for both client engines |")
        )
        for label in ("XHTTP/xray", "WS/mihomo", "TROJAN-GRPC/xray"):
            with self.subTest(label=label):
                self.assertIn(f"`{label}`", row)
        multi_row = next(
            line for line in report.splitlines()
            if line.startswith("| Non-bypassable node egress attribution |")
        )
        self.assertIn("`worker/REALITY/xray`", multi_row)
        self.assertNotIn("`master/REALITY/xray`", multi_row)

    def make_run(self, directory, count=8, status="PASS", vision="disabled"):
        """A run directory with the shape ``result.json`` actually has."""
        ids = [case for case in self.declared["aio"] if "-DP-" in case][:count]
        result = {
            "schema": "gowave-podman-e2e-result/v1",
            "run_id": "podman-aio-stub",
            "topology": "aio",
            "environment": {"vision": vision},
            "cases": [{"id": case_id, "status": status} for case_id in ids],
            "overall": "PASS",
        }
        path = Path(directory) / "result.json"
        path.write_text(json.dumps(result), encoding="utf-8")
        return path

    def test_a_run_that_executed_every_positive_case_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            self.make_run(directory)
            self.assertEqual(trace.run_count_problems(directory), [])

    def test_a_run_short_of_the_manifest_count_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            self.make_run(directory, count=7)
            problems = trace.run_count_problems(directory)
        self.assertTrue(
            any("owes 8 positive cases for aio/disabled" in p and "executed 7" in p
                for p in problems),
            problems,
        )

    def test_a_positive_case_that_did_not_pass_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            self.make_run(directory, count=8, status="SKIP")
            problems = trace.run_count_problems(directory)
        self.assertTrue(any("is SKIP, so it is not a positive case" in p for p in problems), problems)

    def test_a_run_of_an_undeclared_vision_combination_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            self.make_run(directory, vision="sometimes")
            problems = trace.run_count_problems(directory)
        self.assertTrue(any("declares no count for" in p for p in problems), problems)

    def test_the_verify_run_entrypoint_reads_a_run_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            self.make_run(directory)
            with contextlib.redirect_stdout(io.StringIO()) as printed:
                self.assertEqual(trace.main(["--verify-run", directory]), 0)
            self.assertIn("executed every positive case it owes", printed.getvalue())
            self.make_run(directory, count=7)
            with contextlib.redirect_stdout(io.StringIO()) as printed:
                self.assertEqual(trace.main(["--verify-run", directory]), 1)
            self.assertIn("did not execute the positive cases", printed.getvalue())
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(trace.main(["--verify-run"]), 2)

    def test_an_artifact_root_is_judged_run_by_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, count in (("podman-aio-good", 8), ("podman-aio-short", 7)):
                (root / name).mkdir()
                self.make_run(root / name, count=count)
            problems = trace.run_count_problems(root)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("podman-aio-short", problems[0])
        self.assertIn("executed 7", problems[0])

    def test_a_root_with_no_finished_run_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            problems = trace.run_count_problems(directory)
        self.assertTrue(any("holds no finished run" in problem for problem in problems), problems)

    def test_the_audit_entrypoint_reads_the_checked_in_table(self):
        with contextlib.redirect_stdout(io.StringIO()) as printed:
            self.assertEqual(trace.main(["--check"]), 0)
        self.assertIn("45 scenarios, 45 rows", printed.getvalue())
        with contextlib.redirect_stdout(io.StringIO()) as printed:
            self.assertEqual(trace.main(["--strict"]), 1)
        self.assertIn("--strict refuses", printed.getvalue())

    def test_the_audit_entrypoint_refuses_a_drifted_report(self):
        with tempfile.TemporaryDirectory() as directory:
            drifted = Path(directory) / "PODMAN_E2E_TRACEABILITY.md"
            drifted.write_text("| Requirement | Scenario |\n", encoding="utf-8")
            with mock.patch.object(trace, "REPORT_PATH", drifted):
                with contextlib.redirect_stdout(io.StringIO()) as printed:
                    self.assertEqual(trace.main(["--check"]), 1)
        self.assertIn("is not what the table renders to", printed.getvalue())


class TestNamedBehaviours(unittest.TestCase):
    """The second view: one promise at a time, each quoting the manifest.

    `behaviours` publishes what a single behaviour rests on — the cases, the
    tests, the job — and quotes the `matrix.yaml` declaration it depends on, so
    a policy that moves in the manifest cannot leave the report describing the
    old one. These tests damage the block they read: a dropped behaviour, a
    changed value, a lost Vision combination, an obligation nobody meets.
    """

    def setUp(self):
        self.spec = trace.parse_spec()
        self.declared = trace.declared_cases()
        self.jobs = trace.declared_jobs()
        self.tests = trace.test_index()
        self.matrix = trace.load_matrix()
        self.table = trace.load_table()

    def problems(self, table=None):
        return trace.validate_behaviours(
            table if table is not None else self.table,
            self.spec, self.declared, self.jobs, self.tests, self.matrix,
        )

    def entry_in(self, table, behaviour):
        for entry in table.get("behaviours") or []:
            if entry.get("behaviour") == behaviour:
                return entry
        raise AssertionError(f"no behaviour {behaviour!r}")

    def test_the_checked_in_behaviours_agree_with_what_they_quote(self):
        self.assertEqual(self.problems(), [])
        cited = set()
        for entry in trace.behaviours(self.table):
            for _topology, case_id in trace.expand(entry["cases"], self.declared)[0]:
                cited.add(case_id)
        for case_id in (
            "SUB-SERVED", "SUB-UA-ABSENT", "SUB-UA-BLANK", "SUB-B64",
            "SUB-JSON-SHAPES", "PODNET-MASTER-ADDR", "MN-SSHKEY", "MN-VISION",
            "NGX-COVER-DERIVE", "NGX-COVER-UNRESOLVED", "DECOY-01",
            "NGX-COVER-SITE", "DNS-01",
        ):
            with self.subTest(case=case_id):
                self.assertIn(case_id, cited)
        dns = [
            entry for entry in trace.behaviours(self.table)
            if "DNS-01" in (entry.get("cases") or [])
        ]
        self.assertEqual(len(dns), 5, "each DNS behaviour is named on its own")

    def test_a_behaviour_that_stops_quoting_a_declaration_is_refused(self):
        table = trace.load_table()
        table["behaviours"] = [
            entry for entry in table["behaviours"]
            if entry["behaviour"] != "A subscription request without a User-Agent header is refused"
        ]
        self.assertIn("no behaviour names user_agent.absent", self.problems(table))

    def test_a_behaviour_quoting_a_value_the_manifest_does_not_state_is_refused(self):
        table = trace.load_table()
        self.entry_in(
            table, "A subscription request without a User-Agent header is refused"
        )["declares"]["value"] = 200
        problems = self.problems(table)
        self.assertTrue(
            any("user_agent.absent is 403 in the manifest" in problem for problem in problems),
            problems,
        )

    def test_a_vision_combination_no_behaviour_names_is_refused(self):
        table = trace.load_table()
        table["behaviours"] = [
            entry for entry in table["behaviours"]
            if entry["behaviour"] != "Vision runs on both nodes"
        ]
        problems = self.problems(table)
        self.assertTrue(
            any(
                "no behaviour names topologies.multi-node.vision_combinations = 'both'" in problem
                for problem in problems
            ),
            problems,
        )

    def test_a_behaviour_listed_twice_is_refused(self):
        table = trace.load_table()
        table["behaviours"].append(copy.deepcopy(table["behaviours"][0]))
        problems = self.problems(table)
        self.assertTrue(any("listed more than once" in problem for problem in problems), problems)

    def test_a_behaviour_serving_a_requirement_the_spec_does_not_state_is_refused(self):
        table = trace.load_table()
        table["behaviours"][0]["requirement"] = "A Requirement Nobody Wrote"
        problems = self.problems(table)
        self.assertTrue(
            any("no spec requirement 'A Requirement Nobody Wrote'" in problem
                for problem in problems),
            problems,
        )

    def test_a_behaviour_citing_a_case_no_suite_declares_is_refused(self):
        table = trace.load_table()
        table["behaviours"][0]["cases"] = ["SUB-NOT-A-CASE"]
        problems = self.problems(table)
        self.assertTrue(
            any("no suite declares the case 'SUB-NOT-A-CASE'" in problem for problem in problems),
            problems,
        )

    def test_a_behaviour_citing_a_job_no_workflow_declares_is_refused(self):
        table = trace.load_table()
        table["behaviours"][0]["jobs"] = ["A Job Nobody Runs"]
        problems = self.problems(table)
        self.assertTrue(
            any("no workflow declares the job 'A Job Nobody Runs'" in problem
                for problem in problems),
            problems,
        )

    def test_a_behaviour_citing_a_test_nobody_wrote_is_refused(self):
        table = trace.load_table()
        table["behaviours"][0]["tests"] = [
            "tests.test_podman_subscriptions.TestSubscriptionCases.test_nobody_wrote_this"
        ]
        problems = self.problems(table)
        self.assertTrue(any("no test method" in problem for problem in problems), problems)

    def test_a_behaviour_with_no_case_is_refused(self):
        table = trace.load_table()
        table["behaviours"][0]["cases"] = []
        problems = self.problems(table)
        self.assertTrue(
            any("names no case, so nothing proves it" in problem for problem in problems),
            problems,
        )

    def test_two_behaviours_claiming_one_declaration_are_refused(self):
        table = trace.load_table()
        self.entry_in(
            table, "A subscription request with a blank User-Agent header is refused"
        )["declares"] = {"path": "user_agent.absent", "value": 403}
        problems = self.problems(table)
        self.assertTrue(
            any("already claims user_agent.absent" in problem for problem in problems),
            problems,
        )

    def test_a_declaration_path_the_manifest_does_not_hold_is_refused(self):
        table = trace.load_table()
        table["behaviours"][0]["declares"]["path"] = "user_agent.sometimes"
        problems = self.problems(table)
        self.assertTrue(
            any("declares 'user_agent.sometimes', which the manifest does not hold" in problem
                for problem in problems),
            problems,
        )

    def test_a_list_declaration_that_names_no_value_is_refused(self):
        table = trace.load_table()
        del self.entry_in(table, "Vision runs on both nodes")["declares"]["value"]
        problems = self.problems(table)
        self.assertTrue(
            any("has to be quoted with the value the manifest states" in problem
                for problem in problems),
            problems,
        )

    def test_an_obligation_the_manifest_does_not_hold_is_refused(self):
        table = trace.load_table()
        table["behaviour_obligations"].append({"path": "user_agent.sometimes"})
        problems = self.problems(table)
        self.assertTrue(
            any("names a declaration the manifest does not hold" in problem
                for problem in problems),
            problems,
        )

    def test_an_obligation_on_a_single_value_cannot_ask_for_every_value(self):
        table = trace.load_table()
        table["behaviour_obligations"].append(
            {"path": "user_agent.absent", "every_value": True}
        )
        problems = self.problems(table)
        self.assertTrue(any("asks for every value" in problem for problem in problems), problems)

    def test_a_table_with_no_obligations_is_refused(self):
        table = trace.load_table()
        table["behaviour_obligations"] = []
        problems = self.problems(table)
        self.assertTrue(any("no behaviour obligation" in problem for problem in problems), problems)

    def test_the_report_publishes_every_named_behaviour(self):
        report = trace.render(self.table)
        self.assertIn("## Named behaviours", report)
        self.assertIn("| Behaviour | Requirement | Manifest | Cases | Tests | Job |", report)
        for entry in trace.behaviours(self.table):
            with self.subTest(behaviour=entry["behaviour"]):
                self.assertIn(f"| {entry['behaviour']} |", report)
        self.assertIn("`user_agent.absent` = `403`", report)
        self.assertIn("`topologies.multi-node.vision_combinations` holds `both`", report)


if __name__ == "__main__":
    unittest.main()
