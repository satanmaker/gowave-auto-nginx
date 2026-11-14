#!/usr/bin/env python3
"""Suite nonroot: the catalog states what the code runs, and the code is checked.

A case list lives in Python and the catalog is a separate artifact, so the two
drift silently: an entry can say ``planned`` while its case runs every night, a
driver can be renamed and leave the entry pointing at a callable nobody wraps,
and a recorded evidence key can disappear from the driver that used to emit it.
These tests read the drivers out of the source — the callable each ``Case``
wraps and the evidence keys its own body records — and hold the catalog to that,
in both directions. The run's start sequence is read the same way, from the
topology's own ``create()``, because a per-case fixture list cannot be derived
from a driver at all.
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


class TestRunStarts(unittest.TestCase):
    """A run starts a fixed sequence of containers, and the catalog states it.

    A case cannot carry a fixture list: it consumes a fixture through an endpoint
    or a container it never names, and no syntactic marker separates the fixtures
    from the rest of the contour. What the source does prove is the sequence the
    topology's own ``create()`` performs, so that is what the catalog records.
    """

    def setUp(self):
        self.catalog = catalog.load_catalog()
        self.derived = catalog.run_starts()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

    def problems(self, document):
        return catalog.validate_catalog(document)

    def doctored(self):
        return copy.deepcopy(self.catalog)

    def test_the_recorded_sequence_is_the_one_the_topology_performs(self):
        self.assertEqual(
            self.catalog.get("run_starts"), self.derived,
            "the catalog's start inventory must be the sequence create() performs",
        )
        steps = [entry["step"] for entry in self.derived]
        self.assertEqual(steps, sorted(steps), "the inventory is recorded in a stable order")
        for entry in self.derived:
            self.assertEqual(entry["started_by"], "tools/podman_e2e/topology.py")
            self.assertEqual(entry["scope"], "run", "a start step belongs to the run, not to a case")

    def test_a_step_the_topology_performs_and_the_catalog_omits_is_refused(self):
        document = self.doctored()
        document["run_starts"] = [entry for entry in document["run_starts"] if entry["step"] != "echo"]
        self.assertTrue(
            any("start step 'echo' is performed by the topology and not recorded" in problem
                for problem in self.problems(document)),
            self.problems(document),
        )

    def test_a_step_the_catalog_invents_is_refused(self):
        document = self.doctored()
        document["run_starts"] = list(document["run_starts"]) + [{
            "step": "pebble", "started_by": "tools/podman_e2e/topology.py", "scope": "run",
            "fixture_image": False, "acme_module": True,
        }]
        self.assertTrue(
            any("start step 'pebble' is recorded, but no topology `create()` performs it" in problem
                for problem in self.problems(document)),
            self.problems(document),
        )

    def test_a_step_recorded_twice_is_refused(self):
        document = self.doctored()
        document["run_starts"] = list(document["run_starts"]) + [self.derived[0]]
        self.assertTrue(
            any("is recorded twice" in problem for problem in self.problems(document)),
            self.problems(document),
        )

    def test_a_changed_marker_is_refused(self):
        document = self.doctored()
        changed = next(entry for entry in document["run_starts"] if entry["step"] == "target")
        changed["fixture_image"] = True
        problems = self.problems(document)
        self.assertTrue(
            any("start step 'target': fixture_image is True, the topology says False" in problem
                for problem in problems),
            problems,
        )

    def test_a_per_case_fixtures_field_is_refused(self):
        document = self.doctored()
        document["cases"][0]["fixtures"] = ["dns"]
        problems = self.problems(document)
        self.assertTrue(
            any("the run-level sequence is `run_starts`" in problem for problem in problems),
            problems,
        )
        self.assertTrue(
            any(document["cases"][0]["id"] in problem for problem in problems),
            "the refusal must name the case that carries the field",
        )

    def test_the_inventory_follows_create_when_the_topology_changes(self):
        source = (REPO_ROOT / "tools" / "podman_e2e" / "topology.py").read_text(encoding="utf-8")
        block = (
            "        self._start_dns()\n"
            "        self._start_acme()\n"
            "        self._start_target()\n"
            "        self._start_echo()\n"
            "        self._start_client()\n"
        )
        self.assertIn(block, source, "the All-in-One create() sequence moved; re-anchor this test")
        anchor = "    def _start_dns(self) -> None:\n"
        self.assertIn(anchor, source)
        rewritten = source.replace(block, block + "        self._start_probe()\n", 1).replace(
            anchor, "    def _start_probe(self) -> None:\n        self.probe = None\n\n" + anchor, 1,
        )
        doctored_topology = self.tmp / "topology.py"
        doctored_topology.write_text(rewritten, encoding="utf-8")

        real = catalog.run_starts
        extended = {entry["step"]: entry for entry in real(doctored_topology)}
        self.assertIn("probe", extended, "a step create() performs must appear in the inventory")
        self.assertFalse(extended["probe"]["fixture_image"])
        self.assertFalse(extended["probe"]["acme_module"])

        def derive_from_the_copy():
            entries = real(doctored_topology)
            for entry in entries:
                entry["started_by"] = "tools/podman_e2e/topology.py"
            return entries

        with mock.patch.object(catalog, "run_starts", derive_from_the_copy):
            problems = self.problems(self.catalog)
        self.assertTrue(
            any("start step 'probe' is performed by the topology and not recorded" in problem
                for problem in problems),
            problems,
        )


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
