#!/usr/bin/env python3
"""Suite nonroot: the behaviour inventory is an audit, not a summary.

`tests/cases/behaviors.yaml` says which behaviours the suite accepts and which
cases establish each of them, where they run and which tier blocks on them. A
summary can say anything; an inventory has to be a partition: every catalog case
is named by exactly one behaviour, every behaviour names at least one case that
exercises an error path, every area the delta spec lists carries a behaviour, and
a case no behaviour names is a guarantee nobody wrote down. These tests drive
every refusal the audit makes by damaging a copy of the inventory it just read,
so a later edit that widens the check fails here rather than passing quietly.
"""
import copy
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import catalog, matrix  # noqa: E402

CATALOG = catalog.load_catalog()
INVENTORY = catalog.load_behaviors()
TOPOLOGY_BY_CASE = {case["id"]: list(case.get("topology") or []) for case in CATALOG["cases"]}


def naming(inventory, case_id):
    """The behaviour of ``inventory`` that claims ``case_id``."""
    for entry in inventory["behaviors"]:
        if case_id in (entry.get("cases") or []) + (entry.get("error_paths") or []):
            return entry
    raise AssertionError(f"no behaviour names {case_id}")


def where(inventory, predicate):
    for entry in inventory["behaviors"]:
        if predicate(entry):
            return entry
    raise AssertionError("no behaviour matches")


def reaches(entry, key):
    """The topologies the behaviours' ``key`` cases run in."""
    return {
        topology
        for case_id in entry.get(key) or []
        for topology in TOPOLOGY_BY_CASE.get(case_id, [])
    }


class TestBehaviorInventory(unittest.TestCase):
    """Every rule the audit applies, driven by the inventory it ships with."""

    def audit(self, mutate=None, matrix=None):
        """Judge a damaged copy of the checked-in inventory.

        The copy goes through YAML on its way back in, so the test exercises the
        file the audit reads rather than the dictionary the mutation touched.
        """
        before = copy.deepcopy(INVENTORY)
        inventory = copy.deepcopy(INVENTORY)
        if mutate is not None:
            mutate(inventory)
        self.assertEqual(INVENTORY, before, "a test damaged the inventory the other tests read")
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "behaviors.yaml"
            path.write_text(yaml.safe_dump(inventory, sort_keys=False), encoding="utf-8")
            matrix_path = catalog.MATRIX_PATH
            if matrix is not None:
                matrix_path = Path(scratch) / "matrix.yaml"
                matrix_path.write_text(yaml.safe_dump(matrix, sort_keys=False), encoding="utf-8")
            return catalog.coverage_audit(CATALOG, behaviors_path=path, matrix_path=matrix_path)

    def assert_refused(self, errors, message):
        self.assertIn(message, errors, f"the audit accepted what it must refuse: {message}")

    # --- the tree as it ships ------------------------------------------------

    def test_the_checked_in_inventory_covers_the_catalog(self):
        self.assertEqual(
            catalog.coverage_audit(CATALOG), [],
            "the audit that ships with the change must hold on its own tree",
        )

    def test_the_checked_in_report_is_what_the_inventory_renders_to(self):
        self.assertEqual(catalog.report_problems(CATALOG), [])

    def test_the_inventory_is_a_partition_of_the_catalog(self):
        named = [
            case_id
            for entry in INVENTORY["behaviors"]
            for case_id in (entry.get("cases") or []) + (entry.get("error_paths") or [])
        ]
        self.assertEqual(len(named), len(set(named)), "a case is named twice in the checked-in inventory")
        self.assertEqual(set(named), set(TOPOLOGY_BY_CASE))
        self.assertEqual(INVENTORY["areas"], list(catalog.BEHAVIOR_AREAS))

    def test_every_area_the_requirement_names_carries_a_behaviour(self):
        areas = {entry["area"] for entry in INVENTORY["behaviors"]}
        self.assertEqual(sorted(areas), sorted(catalog.BEHAVIOR_AREAS))

    def test_every_behaviour_states_where_it_runs_and_what_blocks_on_it(self):
        manifest = matrix.load()
        for entry in INVENTORY["behaviors"]:
            with self.subTest(behaviour=entry["name"]):
                self.assertTrue(entry["topology"])
                self.assertEqual(
                    entry["gate"], catalog.case_gate(entry["topology"], manifest),
                    "a behaviour is gated at the earliest tier that runs every topology it names",
                )
                self.assertLessEqual(reaches(entry, "cases"), set(entry["topology"]))
                self.assertLessEqual(
                    set(entry["topology"]), reaches(entry, "cases") | reaches(entry, "error_paths")
                )

    def test_the_report_names_every_behaviour(self):
        report = Path(catalog.BEHAVIOR_REPORT_PATH).read_text(encoding="utf-8")
        for entry in INVENTORY["behaviors"]:
            with self.subTest(behaviour=entry["name"]):
                self.assertIn(entry["name"], report)
        self.assertIn(f"{len(CATALOG['cases'])} of {len(CATALOG['cases'])} catalog cases", report)

    def test_the_operator_guide_points_at_the_inventory(self):
        guide = (REPO_ROOT / "docs" / "PODMAN_E2E.md").read_text(encoding="utf-8")
        self.assertIn("PODMAN_E2E_BEHAVIORS.md", guide)
        self.assertIn("tests/cases/behaviors.yaml", guide)

    # --- a behaviour that promises nothing ----------------------------------

    def test_a_behavior_with_no_case_is_named(self):
        target = where(INVENTORY, lambda entry: len(entry["cases"]) > 1)
        dropped = target["cases"][0]
        errors = self.audit(lambda inventory: naming(inventory, dropped).__setitem__("cases", []))
        self.assert_refused(errors, f"Behavior has no case: {target['name']}")

    def test_a_behavior_covered_only_on_its_happy_path_is_named(self):
        target = where(INVENTORY, lambda entry: bool(entry["error_paths"]))
        errors = self.audit(
            lambda inventory: naming(inventory, target["error_paths"][0]).__setitem__("error_paths", [])
        )
        self.assert_refused(errors, f"Behavior has no error-path case: {target['name']}")

    def test_a_behavior_without_a_gate_is_named(self):
        target = where(INVENTORY, lambda entry: True)
        errors = self.audit(lambda inventory: naming(inventory, target["cases"][0]).__setitem__("gate", None))
        self.assert_refused(errors, f"Behavior {target['name']} declares no gate")

    def test_a_behavior_without_a_topology_is_named(self):
        target = where(INVENTORY, lambda entry: True)
        errors = self.audit(lambda inventory: naming(inventory, target["cases"][0]).__setitem__("topology", []))
        self.assert_refused(errors, f"Behavior {target['name']} declares no topology")

    def test_a_duplicate_behavior_name_is_refused(self):
        first = INVENTORY["behaviors"][0]["name"]
        errors = self.audit(
            lambda inventory: inventory["behaviors"].append(copy.deepcopy(inventory["behaviors"][0]))
        )
        self.assert_refused(errors, f"Duplicate behavior name: {first}")

    def test_a_behavior_naming_one_case_twice_is_refused(self):
        target = where(INVENTORY, lambda entry: len(entry["cases"]) > 1)
        twice = target["cases"][0]
        errors = self.audit(
            lambda inventory: naming(inventory, twice)["error_paths"].append(twice)
        )
        self.assert_refused(errors, f"Behavior {target['name']} names case {twice} more than once")

    # --- the partition ------------------------------------------------------

    def test_a_case_mapped_to_no_behavior_is_named(self):
        target = where(INVENTORY, lambda entry: len(entry["cases"]) > 1)
        orphan = target["cases"][0]
        errors = self.audit(lambda inventory: naming(inventory, orphan)["cases"].remove(orphan))
        self.assert_refused(errors, f"Case is mapped to no behavior: {orphan}")

    def test_a_case_two_behaviors_claim_is_named(self):
        first = where(INVENTORY, lambda entry: len(entry["cases"]) > 1)
        second = where(INVENTORY, lambda entry: entry is not first and bool(entry["error_paths"]))
        claimed = first["cases"][0]
        errors = self.audit(
            lambda inventory: naming(inventory, second["error_paths"][0])["error_paths"].append(claimed)
        )
        self.assert_refused(
            errors,
            f"Case is mapped by more than one behavior: {claimed} "
            f"({', '.join(sorted([first['name'], second['name']]))})",
        )

    def test_a_case_the_catalog_does_not_hold_is_refused(self):
        target = INVENTORY["behaviors"][0]
        errors = self.audit(lambda inventory: inventory["behaviors"][0]["cases"].append("NO-SUCH-CASE-99"))
        self.assert_refused(errors, f"Behavior {target['name']} references unknown case NO-SUCH-CASE-99")

    def test_a_case_named_as_a_non_string_is_refused(self):
        target = INVENTORY["behaviors"][0]
        errors = self.audit(lambda inventory: inventory["behaviors"][0]["cases"].append(99))
        self.assert_refused(errors, f"Behavior {target['name']} names a case that is not an id: 99")

    # --- areas --------------------------------------------------------------

    def test_an_area_with_no_behavior_is_named(self):
        target = where(INVENTORY, lambda entry: entry["area"] == "decoy")
        errors = self.audit(
            lambda inventory: inventory.__setitem__(
                "behaviors",
                [entry for entry in inventory["behaviors"] if entry["area"] != "decoy"],
            )
        )
        self.assert_refused(errors, "Area has no behavior: decoy")
        self.assert_refused(errors, f"Case is mapped to no behavior: {target['cases'][0]}")

    def test_an_area_the_inventory_does_not_declare_is_named(self):
        errors = self.audit(lambda inventory: inventory["areas"].remove("decoy"))
        self.assert_refused(errors, "Behavior inventory does not declare area decoy")

    def test_an_area_the_requirement_does_not_name_is_refused(self):
        errors = self.audit(lambda inventory: inventory["areas"].append("scheduling"))
        self.assert_refused(errors, "Behavior inventory declares unknown area 'scheduling'")

    def test_a_behavior_in_an_area_the_requirement_does_not_name_is_refused(self):
        target = where(INVENTORY, lambda entry: True)
        errors = self.audit(
            lambda inventory: naming(inventory, target["cases"][0]).__setitem__("area", "scheduling")
        )
        self.assert_refused(errors, f"Behavior {target['name']} declares unknown area 'scheduling'")

    # --- gate and topology --------------------------------------------------

    def test_a_gate_the_cases_are_not_gated_by_is_refused(self):
        target = where(INVENTORY, lambda entry: entry["gate"] == "pre-push")
        reported = target["cases"][0]
        errors = self.audit(lambda inventory: naming(inventory, reported).__setitem__("gate", "pr"))
        self.assert_refused(
            errors,
            f"Behavior {target['name']} declares gate pr but case {reported} is gated pre-push",
        )

    def test_a_topology_none_of_its_cases_runs_in_is_refused(self):
        target = where(INVENTORY, lambda entry: entry["topology"] == ["aio"])
        errors = self.audit(
            lambda inventory: naming(inventory, target["cases"][0])["topology"].append("multi-node")
        )
        self.assert_refused(
            errors,
            f"Behavior {target['name']} declares topology multi-node that none of its cases runs in",
        )

    def test_a_topology_the_matrix_does_not_hold_is_refused(self):
        target = INVENTORY["behaviors"][0]
        errors = self.audit(lambda inventory: inventory["behaviors"][0]["topology"].append("nightly"))
        self.assert_refused(errors, f"Behavior {target['name']} declares unknown topology nightly")

    def test_a_topology_declared_twice_is_refused(self):
        target = INVENTORY["behaviors"][0]
        errors = self.audit(
            lambda inventory: inventory["behaviors"][0]["topology"].append(
                inventory["behaviors"][0]["topology"][0]
            )
        )
        self.assert_refused(errors, f"Behavior {target['name']} declares a topology more than once")

    def test_a_case_established_in_a_topology_the_behavior_does_not_declare_is_refused(self):
        target = where(INVENTORY, lambda entry: reaches(entry, "cases") == {"aio", "multi-node"})
        errors = self.audit(
            lambda inventory: naming(inventory, target["cases"][0]).__setitem__("topology", ["multi-node"])
        )
        self.assert_refused(
            errors,
            f"Behavior {target['name']} does not declare topology aio where its cases are established",
        )

    def test_a_gate_the_matrix_does_not_block_on_is_refused(self):
        matrix = yaml.safe_load(catalog.MATRIX_PATH.read_text(encoding="utf-8"))
        for entry in matrix["topologies"].values():
            entry["gate"] = ["pr"]
        target = where(INVENTORY, lambda entry: entry["topology"] == ["aio"])
        errors = self.audit(matrix=matrix)
        declared = [
            error for error in errors
            if error.startswith(f"Behavior {target['name']} declares gate pre-push for aio, which ")
        ]
        self.assertEqual(len(declared), 1, errors)
        self.assertIn("does not gate that way", declared[0])

    # --- the file itself ----------------------------------------------------

    def test_a_missing_inventory_is_named(self):
        with tempfile.TemporaryDirectory() as scratch:
            errors = catalog.coverage_audit(CATALOG, behaviors_path=Path(scratch) / "absent.yaml")
        self.assertTrue(errors)
        self.assertTrue(errors[0].startswith("Behavior inventory is missing: "), errors[0])

    def test_the_schema_is_required(self):
        errors = self.audit(lambda inventory: inventory.__setitem__("schema", "gowave-podman-behaviors/v0"))
        self.assert_refused(
            errors,
            f"Behavior inventory schema is 'gowave-podman-behaviors/v0', expected {catalog.BEHAVIOR_SCHEMA!r}",
        )

    def test_an_inventory_that_is_not_a_mapping_is_refused(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "behaviors.yaml"
            path.write_text("- just\n- a list\n", encoding="utf-8")
            errors = catalog.coverage_audit(CATALOG, behaviors_path=path)
        self.assertEqual(errors, [f"Behavior inventory must be a mapping: {path}"])

    def test_an_inventory_that_is_not_yaml_is_refused(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "behaviors.yaml"
            path.write_text("behaviors: [\n", encoding="utf-8")
            errors = catalog.coverage_audit(CATALOG, behaviors_path=path)
        self.assertEqual(len(errors), 1)
        self.assertIn("is not valid YAML", errors[0])

    def test_an_inventory_with_no_behaviors_is_refused(self):
        errors = self.audit(lambda inventory: inventory.__setitem__("behaviors", []))
        self.assert_refused(errors, "Behavior inventory names no behavior")

    def test_a_missing_report_is_named(self):
        with tempfile.TemporaryDirectory() as scratch:
            errors = catalog.report_problems(CATALOG, report_path=Path(scratch) / "absent.md")
        self.assertEqual(len(errors), 1)
        self.assertIn("is missing: run `python3 -m tools.podman_e2e.catalog behaviors --write`", errors[0])

    def test_a_drifted_report_is_refused(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "behaviors.md"
            path.write_text(
                Path(catalog.BEHAVIOR_REPORT_PATH).read_text(encoding="utf-8") + "\n- a behaviour nobody wrote\n",
                encoding="utf-8",
            )
            errors = catalog.report_problems(CATALOG, report_path=path)
        self.assertEqual(len(errors), 1)
        self.assertIn("is not what the behaviour inventory renders to", errors[0])


if __name__ == "__main__":
    unittest.main()
