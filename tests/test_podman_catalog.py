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
import contextlib
import copy
import hashlib
import io
import json
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
        self.assertEqual(
            self.registry["AIO-04"]["aio"]["evidence"], ["listeners", "units", "update_helper"],
            "the in-panel update helper probe is its own evidence key, not a clause of `units`",
        )
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

    def test_every_implemented_entry_names_the_topologies_it_runs_in(self):
        """The catalog's driver map is what this repository runs, not what the text lists.

        A live scenario's `topology` is read from the spec and names the contours
        the sentence covers; the drivers say which of them a case actually
        executes here. The two are not the same field: `SUB-01` describes a
        subscription fetched from a panel, which both contours serve, but the
        User-Agent refusal is executed by the All-in-One suite only. Requiring
        equality would either hide that coverage gap or force the catalog to
        restate the spec, so the invariant is the one that can be checked: every
        declared driver belongs to a topology the entry lists, and the case named
        is one the code builds for that topology.
        """
        implemented = [case for case in self.catalog["cases"]
                       if case.get("driver_status") == "implemented"]
        self.assertTrue(implemented, "no entry claims an implementation, so nothing is checked")
        for case in implemented:
            observed = {topology: facts.get("case") or case["id"]
                        for topology, facts in case["drivers"].items()}
            with self.subTest(case=case["id"]):
                self.assertTrue(observed, f"{case['id']}: an implemented entry names no driver")
                self.assertTrue(
                    set(observed) <= set(case["topology"]),
                    f"{case['id']}: driven in {sorted(observed)}, which its topology list "
                    f"{case['topology']} does not name",
                )
                for topology, observer in observed.items():
                    self.assertIn(
                        topology, self.registry.get(observer, {}),
                        f"{case['id']} / {topology}: {observer} is not a case the code builds "
                        "for that topology",
                    )
                    self.assertEqual(
                        case["drivers"][topology]["driver"],
                        self.registry[observer][topology]["driver"],
                        f"{case['id']} / {topology}: the named driver is not the one {observer} wraps",
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
        # Every shipped entry is implemented now, so the state under test is
        # built instead of borrowed from a gap: a refusal that needed one would
        # stop being tested the moment the last entry landed.
        document = self.doctored()
        planned = next(case for case in document["cases"] if case["id"] == "AIO-04")
        planned["driver_status"] = "planned"
        planned["drivers"] = {}
        with mock.patch.object(catalog, "load_catalog", return_value=document):
            with self.assertRaises(catalog.CatalogError) as caught:
                catalog.require_executable([("AIO-04", "aio")])
        self.assertIn("AIO-04: the catalog says 'planned'", str(caught.exception))

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

    def test_a_live_scenario_is_observed_by_the_case_the_declaration_names(self):
        entry = self.by_id["DP-01"]
        self.assertEqual(entry["driver_status"], "implemented")
        self.assertEqual(entry["drivers"]["aio"]["case"], "AIO-MATRIX")
        self.assertEqual(entry["drivers"]["multi-node"]["case"], "MN-MATRIX")
        self.assertEqual(
            entry["drivers"]["aio"]["evidence"],
            self.registry["AIO-MATRIX"]["aio"]["evidence"],
            "the evidence of an observed entry is the observer's own, not a hand-written list",
        )
        self.assertEqual(
            entry["drivers"]["aio"]["driver"], "aio:case_matrix",
            "the recorded driver is the callable the observer case wraps",
        )

    def test_an_observer_the_code_does_not_build_is_refused(self):
        cases = [{"id": "DP-01", "driver_status": "planned", "drivers": {}}]
        with mock.patch.object(catalog, "LIVE_PARITY_OBSERVERS", {"DP-01": {"aio": "AIO-NOT-A-CASE"}}):
            with self.assertRaises(catalog.CatalogError) as caught:
                catalog.apply_implementations(cases, {})
        self.assertIn("AIO-NOT-A-CASE", str(caught.exception))
        self.assertIn("is not a Case the code builds", str(caught.exception))

    def test_a_scenario_an_observer_names_but_the_catalog_does_not_define_is_refused(self):
        with mock.patch.object(catalog, "LIVE_PARITY_OBSERVERS", {"DP-NOT-A-CASE": {"aio": "AIO-MATRIX"}}):
            with self.assertRaises(catalog.CatalogError) as caught:
                catalog.apply_implementations([{"id": "DP-01", "drivers": {}}], {})
        self.assertIn("DP-NOT-A-CASE", str(caught.exception))
        self.assertIn("does not define", str(caught.exception))

    def test_a_case_that_runs_and_is_also_mapped_is_refused(self):
        cases = [{"id": "DP-01", "driver_status": "planned", "drivers": {}}]
        registry = {"DP-01": {"aio": {"driver": "aio:case_x", "evidence": []}}}
        with mock.patch.object(catalog, "LIVE_PARITY_OBSERVERS", {"DP-01": {"aio": "AIO-MATRIX"}}):
            with self.assertRaises(catalog.CatalogError) as caught:
                catalog.apply_implementations(cases, registry)
        self.assertIn("is also mapped to the observer", str(caught.exception))

    def test_an_observer_changed_in_the_catalog_is_refused(self):
        document = self.doctored()
        entry = next(case for case in document["cases"] if case["id"] == "DP-01")
        entry["drivers"]["aio"]["case"] = "AIO-04"
        problems = self.problems(document)
        self.assertTrue(
            any("the observer is 'AIO-04', the declaration says 'AIO-MATRIX'" in problem
                for problem in problems),
            problems,
        )

    def test_evidence_the_observer_stopped_recording_is_refused(self):
        document = self.doctored()
        entry = next(case for case in document["cases"] if case["id"] == "DP-01")
        entry["drivers"]["aio"]["evidence"] = [
            key for key in entry["drivers"]["aio"]["evidence"] if key != "passed_cases"
        ]
        problems = self.problems(document)
        self.assertTrue(
            any("DP-01 / aio: the evidence keys differ" in problem for problem in problems),
            problems,
        )


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


class TestJustifiedExclusions(unittest.TestCase):
    """What a run leaves out is printed, and the catalog is what says why.

    Two live scenarios cannot be answered by a container, and a run that simply
    does not mention them reads as parity in a green artifact. The catalog
    carries the limitation, the run prints it, and `result.json` keeps it, so
    "not executed" and "not considered" are different claims.
    """

    def setUp(self):
        self.document = catalog.load_catalog()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name

    def exclusions(self, topology="aio", document=None):
        with mock.patch.object(
            catalog, "load_catalog", return_value=document or self.document,
        ):
            return catalog.justified_exclusions(topology)

    def entry(self, document, case_id):
        return next(case for case in document["cases"] if case["id"] == case_id)

    def test_the_two_live_only_entries_state_their_limitation(self):
        live_only = {
            case["id"]: case for case in self.document["cases"]
            if case["environment"] == "live-only"
        }
        self.assertEqual(sorted(live_only), ["LOCAL-02", "TD-06"])
        self.assertEqual(self.document["counts"]["live_only"], 2)
        for case_id, case in live_only.items():
            self.assertEqual(case["runs_in"], ["live"], case_id)
            self.assertEqual(case["state"], "live-only", case_id)
            self.assertEqual(case["driver_status"], "not-applicable", case_id)
            self.assertTrue(case["live_only_reason"].strip(), case_id)

    def test_a_run_reports_the_exclusions_that_apply_to_its_topology(self):
        one = self.exclusions("aio")
        both = self.exclusions("multi-node")
        self.assertEqual(sorted(entry["id"] for entry in one), ["TD-06"])
        self.assertEqual(sorted(entry["id"] for entry in both), ["LOCAL-02", "TD-06"])
        for entry in both:
            self.assertEqual(entry["environment"], "live-only")
            self.assertTrue(entry["requirement"])
            self.assertTrue(entry["reason"].strip())
            self.assertIn("multi-node", entry["topology"])

    def test_a_live_only_entry_with_no_reason_is_refused(self):
        document = copy.deepcopy(self.document)
        self.entry(document, "LOCAL-02")["live_only_reason"] = "   "
        with self.assertRaises(catalog.CatalogError) as caught:
            self.exclusions("multi-node", document)
        self.assertIn(
            "LOCAL-02: live-only case must state its reason", str(caught.exception)
        )

    def test_a_live_only_entry_that_also_runs_here_is_refused(self):
        document = copy.deepcopy(self.document)
        self.entry(document, "TD-06")["runs_in"] = ["live", "podman"]
        with self.assertRaises(catalog.CatalogError) as caught:
            self.exclusions("aio", document)
        self.assertIn(
            "TD-06: live-only case is listed as running in the Podman suite",
            str(caught.exception),
        )

    def test_an_unknown_topology_is_a_usage_error(self):
        with self.assertRaises(ValueError) as caught:
            self.exclusions("aio-and-a-half")
        self.assertIn("unsupported topology: 'aio-and-a-half'", str(caught.exception))

    def test_a_topology_the_matrix_declares_but_no_case_owns_leaves_nothing_out(self):
        # The catalog is not what decides whether a topology exists: the matrix
        # is. Reading the case list alone turned an empty suite into a usage
        # error naming a real mode. Panel-only owns cases now, so the document is
        # stripped to keep the property under test rather than leaning on a suite
        # that happens to be empty today.
        document = copy.deepcopy(self.document)
        document["cases"] = [
            case for case in document["cases"]
            if "panel-only" not in (case.get("topology") or [])
        ]
        self.assertEqual(self.exclusions("panel-only", document), [])

    def test_the_panel_only_topology_owns_cases_of_its_own(self):
        owned = {case["id"] for case in self.document["cases"]
                 if "panel-only" in (case.get("topology") or [])}
        self.assertEqual(
            owned, {"PO-INSTALL", "PO-HOST", "PO-API", "PO-SQUAD", "PO-SQUAD-REFUSED"},
        )

    def stub_run(self, argv, executed):
        """Drive `main` with a Podman and a Runner that touch nothing."""
        from tools import run_podman_e2e

        class _Podman:
            def __init__(self, context):
                executed["context"] = context
                self.context = context

            def remove_stale_runs(self):
                return []

            def register_cleanup(self):
                pass

        class _Runner:
            def __init__(self, context):
                executed["runner"] = context

            def require_group(self, group):
                pass

            def add(self, case):
                executed.setdefault("added", []).append(case.id)

            def on_failure(self, hook):
                pass

            def execute(self):
                return 0

        patchers = [
            mock.patch.object(run_podman_e2e, name, value)
            for name, value in (
                ("Podman", _Podman),
                ("Runner", _Runner),
                ("build_suite", lambda *a, **k: []),
            )
        ]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        return run_podman_e2e.main(argv)

    def test_the_entrypoint_prints_and_records_every_exclusion(self):
        executed = {}
        with contextlib.redirect_stdout(io.StringIO()) as printed:
            status = self.stub_run(
                ["--topology", "multi-node", "--artifact-root", self.tmp], executed,
            )
        self.assertEqual(status, 0)
        output = printed.getvalue()
        self.assertIn("justified exclusions (live-only, not executed here):", output)
        for case_id in ("TD-06", "LOCAL-02"):
            self.assertIn(case_id, output)
        recorded = executed["context"].environment["justified_exclusions"]
        self.assertEqual(sorted(entry["id"] for entry in recorded), ["LOCAL-02", "TD-06"])
        by_id = {case["id"]: case for case in self.document["cases"]}
        for entry in recorded:
            self.assertEqual(
                entry["reason"], by_id[entry["id"]]["live_only_reason"],
                "the run must print the catalog's own limitation, not a paraphrase",
            )

    def test_the_entrypoint_refuses_an_exclusion_it_cannot_justify(self):
        executed = {}
        patcher = mock.patch.object(
            catalog, "justified_exclusions",
            mock.Mock(side_effect=catalog.CatalogError(
                "the catalog cannot justify what this run leaves out: "
                "TD-06: live-only case must state its reason"
            )),
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        with mock.patch("sys.stderr") as stderr:
            with self.assertRaises(SystemExit) as caught:
                self.stub_run(
                    ["--topology", "aio", "--artifact-root", self.tmp], executed,
                )
        self.assertEqual(caught.exception.code, 2)
        message = " ".join(str(call.args[0]) for call in stderr.write.call_args_list if call.args)
        self.assertIn("TD-06: live-only case must state its reason", message)
        self.assertNotIn("runner", executed, "a refused run must not construct the runner")


class TestPodmanFirstPromotion(unittest.TestCase):
    """A Podman-first case is a promise to promote, and the promise names an owner.

    The catalog incubates 124 cases that no live scenario covers yet. Each one
    states the requirement it belongs to here and the live requirement it is
    being promoted into; both are read from the specs, so a renamed
    requirement orphans its cases loudly instead of leaving them pointing at a
    string no spec declares.
    """

    def setUp(self):
        self.document = catalog.load_catalog()
        self.extras = [
            case for case in self.document["cases"] if not case.get("live_scenario")
        ]

    def vocabulary(self):
        names = {scenario.requirement for scenario in catalog.parse_live_spec()}
        from tools.podman_e2e import trace

        names.update(requirement for requirement, _ in trace.parse_spec())
        # The lifecycle-management spec is the third authoritative vocabulary:
        # `trace.validate` already resolves gap rows against it, and a
        # Podman-first case owning a requirement from it (the ACME lineage
        # selection) is a name a spec states, not an invented one.
        names.update(trace.parse_lifecycle_spec())
        return names

    def problems(self, document=None):
        return catalog.validate_catalog(document or self.document)

    def entry(self, document, case_id):
        return next(case for case in document["cases"] if case["id"] == case_id)

    def test_every_podman_first_case_names_an_owner_and_a_target_the_specs_state(self):
        vocabulary = self.vocabulary()
        self.assertEqual(len(self.extras), self.document["counts"]["podman_first"])
        self.assertEqual(len(self.extras), 124)
        for case in self.extras:
            self.assertEqual(case["runs_in"], ["podman"], case["id"])
            self.assertEqual(case["state"], "incubating", case["id"])
            self.assertIn(case["requirement"], vocabulary, case["id"])
            self.assertIn(case["promotion_target"], vocabulary, case["id"])
        self.assertEqual(self.problems(), [])

    def test_an_owning_requirement_no_spec_states_is_refused(self):
        document = copy.deepcopy(self.document)
        self.entry(document, "MN-BACKUP")["requirement"] = "Backup and Restore Format v1"
        problems = self.problems(document)
        self.assertTrue(
            any("MN-BACKUP: Podman-first case names no owning requirement" in problem
                for problem in problems),
            problems,
        )

    def test_a_promotion_target_no_spec_states_is_refused(self):
        document = copy.deepcopy(self.document)
        self.entry(document, "AIO-INSTALL")["promotion_target"] = "Nowhere in particular"
        problems = self.problems(document)
        self.assertTrue(
            any("AIO-INSTALL: promotion target is not a requirement either spec states" in problem
                for problem in problems),
            problems,
        )

    def test_a_podman_first_case_without_a_target_is_refused(self):
        document = copy.deepcopy(self.document)
        self.entry(document, "AIO-INSTALL")["promotion_target"] = None
        problems = self.problems(document)
        self.assertTrue(
            any("AIO-INSTALL: Podman-first case requires a promotion target" in problem
                for problem in problems),
            problems,
        )


class TestScenarioClassification(unittest.TestCase):
    """A live scenario is answered where the checked table says, not by default.

    The table is the catalog's input, so a scenario the spec gains without a row
    stops the build instead of being called container-reproducible by the silence
    of a default. A live-only addition is exactly the case that default used to
    swallow.
    """

    def setUp(self):
        self.document = catalog.load_catalog()
        self.table = catalog.load_scenario_environments()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

    def test_every_live_scenario_is_classified_and_the_counts_agree(self):
        scenarios = catalog.parse_live_spec()
        self.assertEqual(len(scenarios), 125)
        self.assertEqual(len(self.table), 125)
        counted = {"container": 0, "partial": 0, "live-only": 0}
        for scenario in scenarios:
            environment, note = catalog.classify(scenario.requirement, scenario.title, self.table)
            counted[environment] += 1
            if environment == "partial":
                self.assertTrue(note, scenario.title)
            if environment == "live-only":
                self.assertTrue(note, scenario.title)
        self.assertEqual(counted, {
            "container": self.document["counts"]["container"],
            "partial": self.document["counts"]["partial"],
            "live-only": self.document["counts"]["live_only"],
        })

    def test_a_scenario_the_table_does_not_classify_is_refused(self):
        with self.assertRaises(ValueError) as caught:
            catalog.classify("Teardown Policy Enforcement", "A scenario nobody placed", self.table)
        self.assertIn(
            "Live scenario has no environment classification: "
            "Teardown Policy Enforcement / A scenario nobody placed",
            str(caught.exception),
        )

    def test_a_live_scenario_the_table_does_not_classify_fails_the_audit(self):
        spec = self.tmp / "spec.md"
        original = catalog.LIVE_SPEC.read_text(encoding="utf-8")
        addition = (
            "\n#### Scenario: A live-only sentence nobody classified\n\n"
            "- **WHEN** something happens\n- **THEN** it is observed\n"
        )
        marker = "### Requirement: Teardown Policy Enforcement"
        self.assertEqual(original.count(marker), 1)
        spec.write_text(
            original.replace(marker, marker + addition, 1), encoding="utf-8",
        )
        problems = catalog.validate_catalog(self.document, spec_path=spec)
        self.assertTrue(
            any("Live scenario has no environment classification: "
                "Teardown Policy Enforcement / A live-only sentence nobody classified" in problem
                for problem in problems),
            problems,
        )

    def test_a_classification_row_no_scenario_names_is_refused(self):
        extended = dict(self.table)
        extended[("Teardown Policy Enforcement", "A row nobody wrote")] = {
            "requirement": "Teardown Policy Enforcement",
            "scenario": "A row nobody wrote",
            "environment": "container",
        }
        with mock.patch.object(catalog, "load_scenario_environments", return_value=extended):
            problems = catalog.validate_catalog(self.document)
        self.assertTrue(
            any("Environment classification names no live scenario: "
                "Teardown Policy Enforcement / A row nobody wrote" in problem
                for problem in problems),
            problems,
        )

    def test_an_entry_whose_environment_drifted_from_the_table_is_refused(self):
        document = copy.deepcopy(self.document)
        entry = next(case for case in document["cases"] if case["id"] == "TD-06")
        entry["environment"] = "container"
        problems = catalog.validate_catalog(document)
        self.assertTrue(
            any("TD-06: environment 'container' is not the classification table's 'live-only'"
                in problem for problem in problems),
            problems,
        )


class TestPromotionPath(unittest.TestCase):
    """`incubating` → `podman-stable` → `live-parity`, and only that way round."""

    def setUp(self):
        self.document = catalog.load_catalog()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

    def register(self, promotions, criteria=None):
        path = self.tmp / "promotions.yaml"
        path.write_text(
            "schema: gowave-case-promotions/v1\n"
            f"criteria: {criteria or {'green_runs': 3, 'review': 'reviewed'}}\n"
            f"promotions: {promotions}\n",
            encoding="utf-8",
        )
        return path

    def problems(self, path, document=None):
        return catalog._promotion_errors(
            document or self.document, catalog.load_promotions(path),
        )

    def test_the_register_is_empty_and_every_podman_first_case_is_incubating(self):
        register = catalog.load_promotions()
        self.assertEqual(register["promoted"], {})
        self.assertEqual(register["criteria"]["green_runs"], 3)
        for case in self.document["cases"]:
            if case.get("live_scenario"):
                expected = (
                    "live-only" if case["environment"] == "live-only" else "live-parity"
                )
                self.assertEqual(case["state"], expected, case["id"])
            else:
                self.assertEqual(case["state"], "incubating", case["id"])
        self.assertEqual(self.problems(catalog.PROMOTIONS_PATH), [])

    def test_a_registered_case_becomes_podman_stable(self):
        path = self.register([
            {"id": "AIO-INSTALL", "state": "podman-stable", "green_runs": 3,
             "review": "PR #1234"},
        ])
        built = catalog.build_catalog(promotion_path=path)
        entry = next(case for case in built["cases"] if case["id"] == "AIO-INSTALL")
        self.assertEqual(entry["state"], "podman-stable")
        self.assertEqual(entry["promotion"]["green_runs"], 3)
        self.assertEqual(self.problems(path, built), [])

    def test_a_promotion_to_live_parity_is_refused(self):
        path = self.register([
            {"id": "AIO-INSTALL", "state": "live-parity", "green_runs": 3,
             "review": "PR #1234"},
        ])
        problems = self.problems(path)
        self.assertTrue(
            any("AIO-INSTALL: promotion state 'live-parity' is not reachable from the register"
                in problem for problem in problems),
            problems,
        )

    def test_a_promotion_with_too_few_green_runs_is_refused(self):
        path = self.register([
            {"id": "AIO-INSTALL", "state": "podman-stable", "green_runs": 1,
             "review": "PR #1234"},
        ])
        problems = self.problems(path)
        self.assertTrue(
            any("AIO-INSTALL: promotion rests on 1 green runs, the criteria require 3"
                in problem for problem in problems),
            problems,
        )

    def test_a_promotion_without_a_review_is_refused(self):
        path = self.register([
            {"id": "AIO-INSTALL", "state": "podman-stable", "green_runs": 3, "review": ""},
        ])
        problems = self.problems(path)
        self.assertTrue(
            any("AIO-INSTALL: promotion names no review" in problem for problem in problems),
            problems,
        )

    def test_a_promotion_of_a_case_that_is_already_live_parity_is_refused(self):
        path = self.register([
            {"id": "TD-06", "state": "podman-stable", "green_runs": 3, "review": "PR #1"},
        ])
        problems = self.problems(path)
        self.assertTrue(
            any("TD-06: already live-parity, and the promotion path runs one way" in problem
                for problem in problems),
            problems,
        )

    def test_a_promotion_of_an_unknown_case_is_refused(self):
        path = self.register([
            {"id": "AIO-NOPE", "state": "podman-stable", "green_runs": 3, "review": "PR #1"},
        ])
        problems = self.problems(path)
        self.assertTrue(
            any("AIO-NOPE: the promotion register names no such case" in problem
                for problem in problems),
            problems,
        )

    def test_a_state_the_register_does_not_grant_is_refused(self):
        document = copy.deepcopy(self.document)
        entry = next(case for case in document["cases"] if case["id"] == "AIO-INSTALL")
        entry["state"] = "podman-stable"
        problems = self.problems(catalog.PROMOTIONS_PATH, document)
        self.assertTrue(
            any("AIO-INSTALL: state 'podman-stable', but the promotion register does not list it"
                in problem for problem in problems),
            problems,
        )

    def test_a_register_without_criteria_is_refused(self):
        path = self.register([], criteria={"review": "reviewed"})
        problems = self.problems(path)
        self.assertTrue(
            any("promotion criteria must declare a positive green_runs" in problem
                for problem in problems),
            problems,
        )


class TestDivergenceGuard(unittest.TestCase):
    """A result proves which case ran; its digest proves what the case asserted."""

    def setUp(self):
        self.document = catalog.load_catalog()
        self.case = next(
            case for case in self.document["cases"] if case.get("state") == "live-parity"
        )
        self.case_id = self.case["id"]
        self.digest = self.case["assertion_sha256"]
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

    def result(self, name, digest=None):
        case = {"id": self.case_id, "status": "PASS"}
        if digest is not None:
            case["assertion_sha256"] = digest
        path = self.tmp / name
        path.write_text(
            json.dumps({"schema": "gowave-podman-e2e-result/v1", "cases": [case]}),
            encoding="utf-8",
        )
        return path

    def test_the_checked_in_tree_passes_the_guard(self):
        self.assertEqual(catalog.divergence_guard(), [])

    def test_a_result_recording_no_assertion_is_refused(self):
        problems = catalog.divergence_guard(podman_results=[self.result("silent.json")])
        self.assertTrue(
            any(f"{self.case_id}: the Podman result records no assertion text" in problem
                for problem in problems),
            problems,
        )

    def test_a_result_asserting_text_the_catalog_does_not_carry_is_refused(self):
        problems = catalog.divergence_guard(
            podman_results=[self.result("other.json", "f" * 64)]
        )
        self.assertTrue(
            any(f"{self.case_id}: the Podman result asserts text the catalog does not carry"
                in problem for problem in problems),
            problems,
        )

    def test_the_same_id_asserting_different_text_in_the_two_suites_is_refused(self):
        podman = self.result("podman.json", self.digest)
        live = self.result("live.json", "f" * 64)
        problems = catalog.divergence_guard(podman_results=[podman], live_results=[live])
        self.assertIn(
            f"{self.case_id}: the live result and the Podman result assert different text",
            problems,
        )
        self.assertTrue(
            any(f"{self.case_id}: the Live result asserts text the catalog does not carry"
                in problem for problem in problems),
            problems,
        )

    def test_both_suites_asserting_the_catalog_sentence_are_accepted(self):
        problems = catalog.divergence_guard(
            podman_results=[self.result("podman.json", self.digest)],
            live_results=[self.result("live.json", self.digest)],
        )
        self.assertEqual(problems, [])

    def test_the_recorder_publishes_the_digest_of_the_text_each_case_carries(self):
        digests = catalog.assertion_digests()
        self.assertEqual(digests[self.case_id], self.digest)
        for case in self.document["cases"]:
            if case.get("assertion_sha256"):
                self.assertEqual(
                    digests[case["id"]],
                    hashlib.sha256(case["assertion"].encode("utf-8")).hexdigest(),
                    case["id"],
                )


class TestParityInventory(unittest.TestCase):
    """The published inventory answers per scenario, and a stale copy is refused."""

    def setUp(self):
        self.document = catalog.load_catalog()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

    def live_cases(self):
        return [case for case in self.document["cases"] if case.get("live_scenario")]

    def rows(self, text):
        section = text.split("## Scenario inventory", 1)[1].split("## Partial splits", 1)[0]
        return [
            line for line in section.splitlines()
            if line.startswith("| ") and not line.startswith("| Case")
            and not line.startswith("|---")
        ]

    def test_the_rendered_inventory_has_one_row_per_live_scenario(self):
        rendered = catalog.render_parity(self.document)
        rows = self.rows(rendered)
        self.assertEqual(len(rows), self.document["counts"]["live_total"])
        self.assertEqual(len(rows), len(self.live_cases()))
        for case, row in zip(self.live_cases(), rows):
            cells = [cell.strip() for cell in row.strip("|").split("|")]
            self.assertEqual(cells[0], case["id"])
            self.assertEqual(cells[1], case["environment"])
            self.assertEqual(cells[2], case["gate"])
        self.assertEqual(catalog.parity_audit(self.document), [])

    def test_a_stale_inventory_is_refused(self):
        stale = self.tmp / "PARITY.md"
        stale.write_text(
            catalog.render_parity(self.document) + "- an entry nobody generated\n",
            encoding="utf-8",
        )
        problems = catalog.parity_audit(self.document, stale)
        self.assertTrue(
            any("is not what the catalog renders to" in problem for problem in problems),
            problems,
        )

    def test_a_missing_inventory_is_refused(self):
        problems = catalog.parity_audit(self.document, self.tmp / "absent.md")
        self.assertTrue(
            any("Parity inventory is missing" in problem for problem in problems),
            problems,
        )

    def test_a_row_without_a_gate_is_refused(self):
        damaged = copy.deepcopy(self.document)
        damaged["cases"][0]["gate"] = ""
        path = self.tmp / "PARITY.md"
        path.write_text(catalog.render_parity(damaged), encoding="utf-8")
        problems = catalog.parity_audit(damaged, path)
        self.assertTrue(
            any(f"{damaged['cases'][0]['id']}: parity row states no gate" in problem
                for problem in problems),
            problems,
        )

    def test_the_coverage_audit_reports_the_stale_inventory(self):
        stale = self.tmp / "PARITY.md"
        stale.write_text("not the catalog's text\n", encoding="utf-8")
        problems = catalog.coverage_audit(self.document, parity_path=stale)
        self.assertTrue(
            any("is not what the catalog renders to" in problem for problem in problems),
            problems,
        )


if __name__ == "__main__":
    unittest.main()
