#!/usr/bin/env python3
"""Suite nonroot: the catalog states what the code runs, and the code is checked.

A case list lives in Python and the catalog is a separate artifact, so the two
drift silently: an entry can say ``planned`` while its case runs every night, a
driver can be renamed and leave the entry pointing at a callable nobody wraps,
and a recorded evidence key can disappear from the driver that used to emit it.
These tests read the drivers out of the source — the callable each ``Case``
wraps and the evidence keys its own body records — and hold the catalog to that,
in both directions.
"""
import copy
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import catalog  # noqa: E402
from tools.podman_e2e.runner import Case, RunContext  # noqa: E402


class TestImplementationRegistry(unittest.TestCase):
    """What the code runs and what the catalog claims are one set, not two."""

    def setUp(self):
        self.catalog = catalog.load_catalog()
        self.registry = catalog.driver_registry()
        self.by_id = {case["id"]: case for case in self.catalog["cases"]}
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name

    def suite_ids(self, topology, **kwargs):
        """The case ids the suite really builds, without a host or a container."""
        from tools import run_podman_e2e

        podman = SimpleNamespace(context=RunContext(topology, Path(self.tmp), budget_seconds=60))
        return [
            (case.id, case.topology)
            for case in run_podman_e2e.build_suite(podman, topology, "ubuntu-24.04", **kwargs)
        ]

    def problems(self, catalog_document):
        return catalog.validate_catalog(catalog_document)

    def doctored(self):
        return copy.deepcopy(self.catalog)

    def test_the_checked_in_catalog_obeys_every_rule_it_states(self):
        self.assertEqual(
            self.problems(self.catalog), [],
            "the catalog that ships with the change must hold on its own tree",
        )

    def test_every_case_the_suites_build_is_one_the_catalog_calls_implemented(self):
        for topology, kwargs in (
            ("aio", {}),
            ("aio", {"vision": True}),
            ("multi-node", {}),
            ("multi-node", {"vision": True, "worker_vision": True}),
        ):
            with self.subTest(topology=topology, **kwargs):
                built = self.suite_ids(topology, **kwargs)
                self.assertTrue(built, "the suite built no case at all")
                catalog.require_executable(built)

    def test_the_registry_names_the_driver_and_evidence_of_a_known_case(self):
        self.assertEqual(self.registry["AIO-04"]["aio"]["driver"], "aio:case_services")
        self.assertEqual(self.registry["AIO-04"]["aio"]["evidence"], ["listeners", "units"])
        self.assertEqual(
            self.registry["AIO-INSTALL"]["aio"]["driver"], "aio:AioProduct.install",
            "a method-backed case must be recorded by the method it wraps",
        )
        self.assertEqual(
            self.registry["GATE-BUDGET"]["aio"]["driver"], "budget:case_budget",
            "a case defined in a sibling module must name that module",
        )

    def test_a_matrix_driven_case_is_recorded_under_the_builder(self):
        self.assertEqual(
            self.registry["AIO-DP-REALITY-xray"]["aio"]["driver"], "aio:_data_plane_case",
        )
        for node in ("master", "worker"):
            with self.subTest(node=node):
                self.assertEqual(
                    self.registry[f"MN-DP-{node}-REALITY-xray"]["multi-node"]["driver"],
                    "multi_node:data_plane_case",
                )

    def test_every_implemented_entry_names_the_topologies_the_code_drives(self):
        implemented = [case for case in self.catalog["cases"]
                       if case.get("driver_status") == "implemented"]
        self.assertTrue(implemented, "no entry claims an implementation, so nothing is checked")
        for case in implemented:
            with self.subTest(case=case["id"]):
                self.assertEqual(
                    sorted(case["drivers"]), sorted(self.registry[case["id"]]),
                    f"{case['id']}: the catalog names different topologies than the code",
                )

    def test_an_implemented_entry_that_names_no_driver_is_refused(self):
        document = self.doctored()
        entry = next(case for case in document["cases"]
                     if case.get("driver_status") == "implemented")
        entry["drivers"] = {}
        problems = self.problems(document)
        self.assertTrue(
            any(entry["id"] in problem and "names no driver" in problem for problem in problems),
            problems,
        )

    def test_a_driver_the_code_does_not_wrap_is_refused(self):
        document = self.doctored()
        entry = self.by_id["AIO-04"]
        doctored_entry = next(case for case in document["cases"] if case["id"] == entry["id"])
        doctored_entry["drivers"]["aio"]["driver"] = "aio:no_such_function"
        problems = self.problems(document)
        self.assertTrue(
            any("AIO-04 / aio" in problem and "is not the one the code wraps" in problem
                for problem in problems),
            problems,
        )

    def test_a_case_the_code_runs_but_the_catalog_calls_planned_is_refused(self):
        document = self.doctored()
        doctored_entry = next(case for case in document["cases"] if case["id"] == "AIO-04")
        doctored_entry["driver_status"] = "planned"
        doctored_entry["drivers"] = {}
        problems = self.problems(document)
        self.assertTrue(
            any("AIO-04: the code runs it" in problem and "'planned'" in problem
                for problem in problems),
            problems,
        )

    def test_evidence_the_driver_stopped_recording_is_refused(self):
        document = self.doctored()
        doctored_entry = next(case for case in document["cases"] if case["id"] == "AIO-04")
        doctored_entry["drivers"]["aio"]["evidence"] = ["listeners", "retired_key"]
        problems = self.problems(document)
        self.assertTrue(
            any("AIO-04 / aio" in problem and "evidence keys differ" in problem
                for problem in problems),
            problems,
        )

    def test_a_topology_its_entry_does_not_list_is_refused(self):
        document = self.doctored()
        doctored_entry = next(case for case in document["cases"] if case["id"] == "SUB-SERVED")
        self.assertEqual(sorted(doctored_entry["drivers"]), ["aio", "multi-node"])
        doctored_entry["topology"] = ["aio"]
        problems = self.problems(document)
        self.assertTrue(
            any("SUB-SERVED: driven in multi-node" in problem for problem in problems),
            problems,
        )

    def test_a_case_no_catalog_entry_defines_is_refused(self):
        with self.assertRaises(catalog.CatalogError) as caught:
            catalog.require_executable([("AIO-NOT-A-CASE", "aio")])
        self.assertIn("AIO-NOT-A-CASE: no catalog entry", str(caught.exception))

    def test_a_case_the_catalog_calls_planned_is_refused_before_it_runs(self):
        planned = next(case["id"] for case in self.catalog["cases"]
                       if case.get("driver_status") == "planned")
        with self.assertRaises(catalog.CatalogError) as caught:
            catalog.require_executable([(planned, "aio")])
        self.assertIn(f"{planned}: the catalog says 'planned'", str(caught.exception))

    def test_a_topology_the_entry_does_not_drive_is_refused_before_it_runs(self):
        with self.assertRaises(catalog.CatalogError) as caught:
            catalog.require_executable([("AIO-04", "multi-node")])
        self.assertIn("AIO-04: the catalog names no multi-node driver", str(caught.exception))

    def test_an_undeclared_matrix_driven_builder_is_refused(self):
        with mock.patch.object(catalog, "MATRIX_DRIVEN_BUILDERS", frozenset()):
            with self.assertRaises(catalog.CatalogError) as caught:
                catalog.driver_registry()
        self.assertIn("mints ids this catalog cannot check", str(caught.exception))

    def test_a_declared_builder_the_source_lost_is_refused(self):
        declared = set(catalog.MATRIX_DRIVEN_BUILDERS) | {("aio", "case_no_such_builder")}
        with mock.patch.object(catalog, "MATRIX_DRIVEN_BUILDERS", frozenset(declared)):
            with self.assertRaises(catalog.CatalogError) as caught:
                catalog.driver_registry()
        self.assertIn("case_no_such_builder", str(caught.exception))
        self.assertIn("is gone", str(caught.exception))


class TestEntrypointRefusesAnUnknownSuite(unittest.TestCase):
    """A case the catalog cannot see must be refused before the install starts."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_the_entrypoint_refuses_a_suite_the_catalog_cannot_see(self):
        from tools import run_podman_e2e

        executed = {}

        class _Podman:
            def __init__(self, context):
                self.context = context

            def remove_stale_runs(self):
                return []

            def register_cleanup(self):
                pass

        class _Runner:
            def __init__(self, context):
                executed["created"] = True

            def require_group(self, group):
                pass

            def add(self, case):
                executed.setdefault("added", []).append(case.id)

            def on_failure(self, hook):
                pass

            def execute(self):
                executed["ran"] = True
                return 0

        def suite(podman, topology, distribution, vision=False, worker_vision=False):
            return [Case("AIO-NOT-A-CASE", "aio", lambda context: {})]

        patchers = [
            mock.patch.object(run_podman_e2e, name, value)
            for name, value in (("Podman", _Podman), ("Runner", _Runner), ("build_suite", suite))
        ]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

        argv = ["--topology", "aio", "--artifact-root", str(self.tmp.name)]
        with mock.patch("sys.stderr") as stderr:
            with self.assertRaises(SystemExit) as caught:
                run_podman_e2e.main(argv)

        self.assertEqual(caught.exception.code, 2, "a catalog disagreement is a usage error")
        message = " ".join(str(call.args[0]) for call in stderr.write.call_args_list if call.args)
        self.assertIn("AIO-NOT-A-CASE", message)
        self.assertIn("the case list does not match tests/cases/catalog.yaml", message)
        self.assertNotIn("added", executed, "the refused suite must not have been handed over")
        self.assertNotIn("ran", executed, "the install must not start on a refused suite")


if __name__ == "__main__":
    unittest.main()
