#!/usr/bin/env python3
"""Suite nonroot: the fifteen-row fault matrix, and the witness of every row.

``NEG-01`` and ``NEG-04`` are conjunctions over a table the spec prints inside the
sentence: fifteen faults, the component each is injected into, and the boundary
the run has to stop at. Neither is a verdict a run can produce, so both cases
read three documents instead — the sentence itself, the live runner's
``run_neg_NN_*`` functions, and the case registry the catalog is generated from —
and this module drives them whole.

Each clause is then damaged on its own: a sentence that prints one row fewer, a
row whose component cell was rewritten, a live runner that lost a scenario, a
witness the suite does not build, a witness built only for the other contour, a
table reordered, and a ``NEG-04`` sentence that dropped its scope — so every
require is seen to fail at the document it protects rather than at a neighbour.
"""
import contextlib
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import catalog, negative_matrix  # noqa: E402

TOPOLOGIES = ("aio", "multi-node")

_REAL_REGISTRY = negative_matrix._registry

CASES = {
    negative_matrix.MATRIX_CASE_ID: negative_matrix.case_fifteen_rows_are_witnessed,
    negative_matrix.TEN_CASE_ID: negative_matrix.case_ten_rows_are_witnessed,
}

#: What each damage is meant to make its case say, so a probe that went red on an
#: unrelated assertion is not read as a held clause.
EXPECTED_REFUSALS = {
    ("NEG-01", "row-count"): "the sentence prints 14 matrix row(s) and this table names 15",
    ("NEG-01", "row-component"): "names a different component than this table does",
    ("NEG-01", "scenario-dropped"): "the live runner defines no scenario for NEG-05",
    ("NEG-01", "witness-missing"): "has no case that runs at its boundary",
    ("NEG-01", "witness-wrong-contour"): "built only for aio",
    ("NEG-01", "table-reordered"): "are not NEG-01..NEG-15 in order",
    ("NEG-04", "scope-dropped"): "no longer states the scope",
}


def _catalog_whose(case_id, mutate):
    """The catalog as the case reads it, with one sentence rewritten."""
    real = catalog.load_catalog

    def load():
        document = real()
        for case in document["cases"]:
            if case["id"] == case_id:
                case["assertion"] = mutate(case["assertion"])
        return document

    return load


def _unbolded_row(text):
    """One row printed without the marker the count and the cell read look for."""
    return text.replace("| **NEG-07**", "| NEG-07", 1)


def _row_naming_another_component(text):
    """One row whose component cell names a different component."""
    head, tail = text.split("| **NEG-07**", 1)
    return head + "| **NEG-07**" + tail.replace("Worker Node", "Worker Deploy", 1)


def _sentence_without_the_ten(text):
    """The NEG-04 sentence with its stated scope narrowed by one row."""
    return text.replace("NEG-01 through NEG-10", "NEG-01 through NEG-09", 1)


def _registry_without(case_id):
    registry = _REAL_REGISTRY()
    return {key: value for key, value in registry.items() if key != case_id}


def _registry_building(case_id, drivers):
    registry = dict(_REAL_REGISTRY())
    registry[case_id] = drivers
    return registry


def _reordered_table():
    """The same fifteen rows with the last two swapped."""
    rows = list(negative_matrix.MATRIX)
    rows[-2], rows[-1] = rows[-1], rows[-2]
    return tuple(rows)


@contextlib.contextmanager
def _runner_missing(scenario, workdir):
    """The live runner as a copy one ``run_neg_NN_*`` definition shorter."""
    source = negative_matrix.NEGATIVE_RUNNER.read_text(encoding="utf-8")
    number = scenario.split("-")[1]
    pattern = re.compile(
        rf"^def run_neg_{number}_[^\n]*\n.*?(?=^def |\Z)",
        re.MULTILINE | re.DOTALL,
    )
    trimmed, removed = pattern.subn("", source)
    assert removed == 1, f"{scenario} is defined {removed} time(s) in the live runner"
    target = Path(workdir) / "negative_without_a_scenario.py"
    target.write_text(trimmed, encoding="utf-8")
    with mock.patch.object(negative_matrix, "NEGATIVE_RUNNER", target):
        negative_matrix._runner_scenarios.cache_clear()
        try:
            yield
        finally:
            negative_matrix._runner_scenarios.cache_clear()


def _damages(workdir):
    return {
        "row-count": [
            mock.patch.object(negative_matrix.catalog, "load_catalog",
                              _catalog_whose("NEG-01", _unbolded_row)),
        ],
        "row-component": [
            mock.patch.object(negative_matrix.catalog, "load_catalog",
                              _catalog_whose("NEG-01", _row_naming_another_component)),
        ],
        "scenario-dropped": [_runner_missing("NEG-05", workdir)],
        "witness-missing": [
            mock.patch.object(negative_matrix, "_registry",
                              lambda: _registry_without("ACME-02")),
        ],
        "witness-wrong-contour": [
            mock.patch.object(
                negative_matrix, "_registry",
                lambda: _registry_building(
                    "MN-SSH-DOWN",
                    {"aio": _REAL_REGISTRY()["MN-SSH-DOWN"]["multi-node"]},
                )),
        ],
        "table-reordered": [
            mock.patch.object(negative_matrix, "MATRIX", _reordered_table()),
        ],
        "scope-dropped": [
            mock.patch.object(negative_matrix.catalog, "load_catalog",
                              _catalog_whose("NEG-04", _sentence_without_the_ten)),
        ],
    }


def run_case(case_id, damage=None, workdir=None):
    """Run one case, optionally with one damaged document; return (facts, refusal)."""
    patchers = _damages(workdir)[damage] if damage else []
    for patcher in patchers:
        patcher.__enter__()
    try:
        return CASES[case_id](object(), SimpleNamespace(topology="aio")), None
    except AssertionError as error:
        return None, str(error)
    finally:
        for patcher in reversed(patchers):
            patcher.__exit__(None, None, None)


class TestNegativeMatrixRegistration(unittest.TestCase):
    """Both ids are registered on both contours with their own callable."""

    def test_every_id_is_registered_on_both_contours(self):
        registry = catalog.driver_registry()
        for case_id, function in CASES.items():
            with self.subTest(case=case_id):
                self.assertIn(case_id, registry)
                self.assertEqual(set(registry[case_id]), set(TOPOLOGIES))
                for topology in TOPOLOGIES:
                    self.assertEqual(
                        registry[case_id][topology]["driver"],
                        f"negative_matrix:{function.__name__}",
                    )

    def test_every_catalog_entry_is_what_the_registry_derives(self):
        registry = catalog.driver_registry()
        entries = {entry["id"]: entry for entry in catalog.load_catalog()["cases"]}
        for case_id in CASES:
            with self.subTest(case=case_id):
                entry = entries[case_id]
                self.assertEqual(entry["driver_status"], "implemented")
                self.assertEqual(entry["drivers"], registry[case_id])
                self.assertEqual(sorted(entry["topology"]), sorted(TOPOLOGIES))


class TestNegativeMatrixCases(unittest.TestCase):
    """Both conjunctions hold, over the table the spec actually prints."""

    def test_every_case_holds_on_both_contours(self):
        for case_id in CASES:
            for topology in TOPOLOGIES:
                with self.subTest(case=case_id, topology=topology):
                    facts = CASES[case_id](object(), SimpleNamespace(topology=topology))
                    self.assertTrue(facts)

    def test_every_evidence_set_is_what_the_catalog_records(self):
        registry = catalog.driver_registry()
        for case_id in CASES:
            with self.subTest(case=case_id):
                facts, refusal = run_case(case_id)
                self.assertIsNone(refusal)
                self.assertEqual(sorted(facts), registry[case_id]["aio"]["evidence"])

    def test_the_fifteen_rows_are_each_witnessed_in_their_contour(self):
        facts, refusal = run_case(negative_matrix.MATRIX_CASE_ID)
        self.assertIsNone(refusal)
        self.assertEqual(facts["matrix_rows"], 15)
        self.assertEqual(facts["rows_in_sentence"], 15)
        self.assertEqual(facts["scenario_ids"].split(","),
                         [f"NEG-{index:02d}" for index in range(1, 16)])
        self.assertEqual(facts["live_scenarios_defined"], 15)
        self.assertEqual(facts["aio_rows"], 8)
        self.assertEqual(facts["multi_node_rows"], 7)
        self.assertEqual(facts["unwitnessed_rows"], 0)
        self.assertEqual(len(facts["witnesses"].split(",")), 15)
        self.assertEqual(len(facts["witnessed_contours"].split(",")), 15)

    def test_the_first_ten_rows_are_the_scope_the_sentence_states(self):
        facts, refusal = run_case(negative_matrix.TEN_CASE_ID)
        self.assertIsNone(refusal)
        self.assertEqual(facts["matrix_rows"], 10)
        self.assertEqual(facts["rows_in_sentence"], 10)
        self.assertEqual(facts["scenario_ids"].split(","),
                         [f"NEG-{index:02d}" for index in range(1, 11)])
        self.assertEqual(facts["aio_rows"], 6)
        self.assertEqual(facts["multi_node_rows"], 4)
        self.assertEqual(facts["unwitnessed_rows"], 0)

    def test_the_table_names_fifteen_distinct_faults(self):
        scenarios = [row.scenario for row in negative_matrix.MATRIX]
        self.assertEqual(len(set(scenarios)), 15)
        self.assertEqual({row.topology for row in negative_matrix.MATRIX},
                         set(TOPOLOGIES))
        self.assertTrue(all(row.case_id for row in negative_matrix.MATRIX))


class TestNegativeMatrixDamage(unittest.TestCase):
    """Each document is damaged on its own and its case refuses for that reason."""

    def setUp(self):
        self.workdir = Path(tempfile.mkdtemp(prefix="gowave-neg-matrix-"))
        self.addCleanup(shutil.rmtree, self.workdir, True)

    def assert_refused(self, case_id, damage):
        _, refusal = run_case(case_id, damage=damage, workdir=self.workdir)
        self.assertIsNotNone(refusal, f"{damage} did not make {case_id} refuse")
        self.assertIn(EXPECTED_REFUSALS[(case_id, damage)], refusal)

    def test_a_sentence_that_prints_one_row_fewer_is_refused(self):
        self.assert_refused(negative_matrix.MATRIX_CASE_ID, "row-count")

    def test_a_row_naming_another_component_is_refused(self):
        self.assert_refused(negative_matrix.MATRIX_CASE_ID, "row-component")

    def test_a_live_runner_that_lost_a_scenario_is_refused(self):
        self.assert_refused(negative_matrix.MATRIX_CASE_ID, "scenario-dropped")

    def test_a_row_whose_witness_the_suite_does_not_build_is_refused(self):
        self.assert_refused(negative_matrix.MATRIX_CASE_ID, "witness-missing")

    def test_a_witness_built_only_for_the_other_contour_is_refused(self):
        self.assert_refused(negative_matrix.MATRIX_CASE_ID, "witness-wrong-contour")

    def test_a_table_out_of_scenario_order_is_refused(self):
        self.assert_refused(negative_matrix.MATRIX_CASE_ID, "table-reordered")

    def test_a_narrower_scope_sentence_is_refused(self):
        self.assert_refused(negative_matrix.TEN_CASE_ID, "scope-dropped")


if __name__ == "__main__":
    unittest.main()
