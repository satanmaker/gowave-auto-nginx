#!/usr/bin/env python3
"""Suite nonroot: the shared contracts with the live capability are audited.

`openspec/specs/live-vps-e2e/spec.md` is the other acceptance capability's own
statement of what the product does. Six contracts are shared with it —
subscription policy, case counts, Vision independence, firewall evidence,
redaction, result semantics — and `tests/cases/traceability.yaml` maps each one
to the live requirement, the sentences it rests on and the catalog cases that
hold it here. These tests read both sides back: a live sentence that was
dropped, a case the container does not reproduce, and a count whose numbers
disagree are refusals, because a divergence is a defect here rather than a
container-only variant.
"""
import copy
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import catalog, trace  # noqa: E402

TABLE = trace.load_table()
LIVE_SPEC = trace.parse_live_spec()
CATALOGUE = catalog.load_catalog()
MATRIX = trace.load_matrix()
CASE_BY_ID = {case["id"]: case for case in CATALOGUE["cases"]}


def entry(table, contract_id):
    for item in table["shared_contracts"]:
        if item["id"] == contract_id:
            return item
    raise AssertionError(f"no shared contract {contract_id}")


class TestSharedContracts(unittest.TestCase):
    """Every refusal the contract audit makes, driven by the shipped mapping."""

    def problems(self, mutate=None):
        table = copy.deepcopy(TABLE)
        if mutate is not None:
            mutate(table)
        return trace.validate_contracts(table, LIVE_SPEC, CATALOGUE, MATRIX)

    def assert_refused(self, problems, message):
        self.assertIn(message, problems, f"the audit accepted what it must refuse: {message}")

    # --- the tree as it ships ------------------------------------------------

    def test_the_checked_in_mapping_holds(self):
        self.assertEqual(
            trace.validate_contracts(TABLE, LIVE_SPEC, CATALOGUE, MATRIX), [],
            "the audit that ships with the change must hold on its own tree",
        )

    def test_every_contract_the_ledger_names_is_recorded(self):
        self.assertEqual(
            [item["id"] for item in TABLE["shared_contracts"]],
            list(trace.SHARED_CONTRACTS),
        )

    def test_every_contract_rests_on_live_parity_cases_in_a_container(self):
        for item in TABLE["shared_contracts"]:
            with self.subTest(contract=item["id"]):
                self.assertTrue(item["cases"])
                for case_id in item["cases"]:
                    self.assertEqual(CASE_BY_ID[case_id]["state"], "live-parity")
                    self.assertEqual(CASE_BY_ID[case_id]["environment"], "container")

    def test_every_quoted_sentence_is_in_the_requirement_it_names(self):
        for item in TABLE["shared_contracts"]:
            body = LIVE_SPEC[item["live_requirement"]]
            with self.subTest(contract=item["id"]):
                for quote in item["live_asserts"]:
                    self.assertIn(trace._squash(quote), body)

    def test_the_report_publishes_the_mapping(self):
        report = trace.render(TABLE)
        self.assertIn("## Shared contracts with the live capability", report)
        for item in TABLE["shared_contracts"]:
            with self.subTest(contract=item["id"]):
                self.assertIn(f"| {item['id']} | {item['live_requirement']} ", report)
        self.assertEqual(trace.report_problems(TABLE), [])

    # --- the mapping is missing or malformed --------------------------------

    def test_a_table_without_the_mapping_is_refused(self):
        problems = self.problems(lambda table: table.pop("shared_contracts"))
        self.assert_refused(problems, "the table records no shared contract with the live capability")

    def test_a_contract_the_ledger_does_not_name_is_refused(self):
        problems = self.problems(
            lambda table: table["shared_contracts"].append(
                {"id": "telemetry", "live_requirement": "Result Status Semantics", "agreement": "x"}
            )
        )
        self.assert_refused(problems, "shared contract telemetry: not one of the contracts the ledger names")

    def test_a_contract_the_ledger_names_but_the_table_drops_is_refused(self):
        problems = self.problems(
            lambda table: table.__setitem__(
                "shared_contracts",
                [item for item in table["shared_contracts"] if item["id"] != "redaction"],
            )
        )
        self.assert_refused(problems, "shared contract redaction: not recorded")

    def test_a_contract_recorded_twice_is_refused(self):
        problems = self.problems(
            lambda table: table["shared_contracts"].append(copy.deepcopy(table["shared_contracts"][0]))
        )
        self.assert_refused(problems, f"shared contract {TABLE['shared_contracts'][0]['id']}: recorded more than once")

    def test_a_contract_that_states_no_observable_is_refused(self):
        def strip(table):
            entry(table, "redaction")["agreement"] = "  "

        self.assert_refused(self.problems(strip), "shared contract redaction: states no shared observable")

    def test_a_contract_with_no_case_is_refused(self):
        self.assert_refused(
            self.problems(lambda table: entry(table, "redaction").__setitem__("cases", [])),
            "shared contract redaction: names no case",
        )

    # --- the live side ------------------------------------------------------

    def test_an_unknown_live_requirement_is_named(self):
        def rename(table):
            entry(table, "case-counts")["live_requirement"] = "Data Plane Traffic"

        problems = self.problems(rename)
        self.assert_refused(problems, "shared contract case-counts: no live requirement 'Data Plane Traffic'")

    def test_a_live_sentence_that_was_reworded_is_named(self):
        def drift(table):
            entry(table, "firewall-evidence")["live_asserts"].append(
                "A timeout is sufficient evidence of UFW DROP"
            )

        problems = self.problems(drift)
        self.assert_refused(
            problems,
            "shared contract firewall-evidence: the live requirement no longer states "
            "'A timeout is sufficient evidence of UFW DROP'",
        )

    def test_a_count_sentence_that_was_reworded_is_named(self):
        def drift(table):
            entry(table, "result-semantics")["counts"][0]["live"] = "all thirty-two Data Plane runtime cases verified"

        problems = self.problems(drift)
        self.assert_refused(
            problems,
            "shared contract result-semantics: the live requirement no longer states the count "
            "'all thirty-two Data Plane runtime cases verified'",
        )

    # --- the container side -------------------------------------------------

    def test_an_unknown_case_is_named(self):
        problems = self.problems(lambda table: entry(table, "redaction")["cases"].append("NO-SUCH-CASE"))
        self.assert_refused(problems, "shared contract redaction: references unknown case NO-SUCH-CASE")

    def test_a_case_the_live_suite_does_not_share_is_refused(self):
        def substitute(table):
            incubated = next(
                case["id"] for case in CATALOGUE["cases"] if case["state"] == "incubating"
            )
            entry(table, "redaction")["cases"] = [incubated]
            self.incubated = incubated

        problems = self.problems(substitute)
        self.assert_refused(
            problems,
            f"shared contract redaction: case {self.incubated} is incubating, not live-parity",
        )

    def test_a_case_the_container_only_partly_reproduces_is_refused(self):
        partial = next(
            case["id"]
            for case in CATALOGUE["cases"]
            if case["state"] == "live-parity" and case["environment"] == "partial"
        )

        def substitute(table):
            entry(table, "firewall-evidence")["cases"] = [partial]

        problems = self.problems(substitute)
        self.assert_refused(
            problems,
            f"shared contract firewall-evidence: case {partial} runs in partial, "
            "so the container half does not assert it",
        )

    def test_a_case_serving_another_requirement_is_refused(self):
        def substitute(table):
            entry(table, "vision-independence")["cases"] = ["RES-01"]

        problems = self.problems(substitute)
        self.assert_refused(
            problems,
            "shared contract vision-independence: case RES-01 serves "
            "'Result Status Semantics', not the mapped requirement",
        )

    # --- the counts ---------------------------------------------------------

    def test_a_count_source_the_audit_cannot_read_is_refused(self):
        def substitute(table):
            entry(table, "case-counts")["counts"][0]["podman"] = "report:last-run"

        problems = self.problems(substitute)
        self.assert_refused(problems, "shared contract case-counts: unknown count source 'report:last-run'")

    def test_a_count_that_disagrees_with_the_manifest_is_named(self):
        def substitute(table):
            # A real sentence of the same requirement, stating a number the
            # matrix does not claim: the quote is in the live spec, so only the
            # comparison can catch it.
            entry(table, "subscription-policy")["counts"][0][
                "live"
            ] = "if that is 403, the runner records a pass"

        problems = self.problems(substitute)
        self.assert_refused(
            problems,
            "shared contract subscription-policy: proxy-capable outbounds per subscription "
            "is 403 on the live capability and 8/9/10 here",
        )

    def test_the_count_resolvers_read_what_they_name(self):
        self.assertEqual(trace.resolve_count("matrix:multi-node:positive-cases", CATALOGUE, MATRIX), [16, 18, 20])
        self.assertEqual(trace.resolve_count("matrix:aio:positive-cases", CATALOGUE, MATRIX), [8, 10])
        self.assertEqual(trace.resolve_count("matrix:product:node_api_port", CATALOGUE, MATRIX), [3002])
        self.assertEqual(trace.resolve_count("case:SUB-02:assertion", CATALOGUE, MATRIX), [8, 9, 10])


if __name__ == "__main__":
    unittest.main()
