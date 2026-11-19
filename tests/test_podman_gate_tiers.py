#!/usr/bin/env python3
"""Suite nonroot: the three gate cases decide something, and their guards are the product's.

`GATE-PREPUSH`, `GATE-COVERAGE` and `GATE-DIVERGENCE` are acceptance cases that
read the tree they ship with: the pre-push entrypoint, the behaviour inventory
and the catalog. A case that asserted "the gate works" would be a restatement;
these tests hold the two halves that make it evidence — the shipped tree is
accepted, and each named damage is refused with the sentence that names it —
and then damage the functions the case reads, to prove the case is listening to
the product rather than to its own assumptions.
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools import pre_push_e2e as pre_push  # noqa: E402
from tools.podman_e2e import catalog as catalog_data  # noqa: E402
from tools.podman_e2e import gate_tiers  # noqa: E402


class TestGateTiers(unittest.TestCase):
    """What the three gate cases prove, and what they refuse to prove."""

    def test_the_pre_push_gate_case_holds_on_the_shipped_manifest(self):
        evidence = gate_tiers.case_pre_push_gate(None, None)
        self.assertEqual(evidence["gated_topologies"], "aio,multi-node")
        self.assertEqual(evidence["blocked_exit"], "1")
        self.assertEqual(evidence["green_exit"], "0")
        self.assertEqual(evidence["nonroot_exit"], "2")
        self.assertEqual(evidence["overrun_exit"], "1")
        self.assertEqual(evidence["unrun_topology_started"], "False")
        self.assertEqual(evidence["suite_streams_captured"], "False")
        self.assertEqual(evidence["credential_tokens"], "0")
        self.assertEqual(evidence["host_tokens"], "0")
        self.assertIn("--topology aio", evidence["suite_arguments"])
        self.assertIn("--topology multi-node", evidence["suite_arguments"])
        self.assertNotIn("live", evidence["suite_arguments"].lower())

    def test_the_coverage_case_holds_on_the_shipped_inventory(self):
        evidence = gate_tiers.case_coverage_audit(None, None)
        self.assertEqual(evidence["baseline_errors"], "0")
        self.assertGreater(int(evidence["behaviors"]), 1)
        self.assertIn("Behavior has no case: ", evidence["no_case_message"])
        self.assertIn("Behavior has no error-path case: ", evidence["happy_path_only_message"])
        self.assertIn("Case is mapped to no behavior: ", evidence["orphan_message"])

    def test_the_divergence_case_holds_on_the_shipped_catalog(self):
        evidence = gate_tiers.case_divergence_guard(None, None)
        self.assertEqual(evidence["baseline_errors"], "0")
        self.assertEqual(evidence["control_errors"], "0")
        self.assertIn("Live scenario has no catalog entry: ", evidence["unlisted_scenario"])
        self.assertIn("live-parity case was not executed by the Podman suite: ",
                      evidence["one_suite_message"])
        self.assertIn("Positive case counts diverge between catalog and matrix for aio: ",
                      evidence["count_divergence"])

    # --- the gate must be listening to the product --------------------------

    def test_a_gate_that_gates_nothing_is_refused(self):
        empty = {"topologies": {"aio": {"gate": []}, "multi-node": {"gate": []}}}
        with mock.patch.object(pre_push, "load_matrix", return_value=empty):
            with self.assertRaises(AssertionError) as caught:
                gate_tiers.case_pre_push_gate(None, None)
        self.assertIn("not both topologies in the manifest's order", str(caught.exception))

    def test_a_suite_module_carrying_a_credential_word_is_refused(self):
        # The invocation is otherwise the pinned one, so the equality check
        # passes and the token check is the branch that has to refuse it.
        with mock.patch.object(pre_push, "SUITE_MODULE", "tools.secret_runner"):
            with self.assertRaises(AssertionError) as caught:
                gate_tiers.case_pre_push_gate(None, None)
        self.assertIn("'secret'", str(caught.exception))

    def test_a_suite_module_pointed_at_a_live_runner_is_refused(self):
        with mock.patch.object(pre_push, "SUITE_MODULE", "tools.live_runner"):
            with self.assertRaises(AssertionError) as caught:
                gate_tiers.case_pre_push_gate(None, None)
        self.assertIn("'live'", str(caught.exception))

    def test_a_topology_list_written_into_the_gate_is_refused(self):
        fixed = ["aio", "multi-node"]
        with mock.patch.object(pre_push, "pre_push_topologies", side_effect=[fixed, fixed, fixed]):
            with self.assertRaises(AssertionError) as caught:
                gate_tiers.case_pre_push_gate(None, None)
        self.assertIn("does not read the manifest's own gate list", str(caught.exception))

    def test_a_gate_that_swallows_a_failing_suite_is_refused(self):
        with mock.patch.object(pre_push, "main", return_value=0):
            with self.assertRaises(AssertionError) as caught:
                gate_tiers.case_pre_push_gate(None, None)
        self.assertIn("would continue", str(caught.exception))

    def test_a_hook_the_installer_does_not_mark_is_refused(self):
        with mock.patch.object(pre_push, "install_hook", create=True) as installer:
            installer.side_effect = self._bare_hook
            with self.assertRaises(AssertionError) as caught:
                gate_tiers.case_pre_push_gate(None, None)
        self.assertIn("without its own marker", str(caught.exception))

    @staticmethod
    def _bare_hook(directory):
        target = Path(directory) / "pre-push"
        target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        target.chmod(0o755)
        return target

    def test_a_coverage_audit_that_accepts_everything_is_refused(self):
        with mock.patch.object(catalog_data, "coverage_audit", return_value=[]):
            with self.assertRaises(AssertionError) as caught:
                gate_tiers.case_coverage_audit(None, None)
        self.assertIn("a behaviour that names no case was judged as []",
                      str(caught.exception))

    def test_a_divergence_guard_that_accepts_everything_is_refused(self):
        with mock.patch.object(catalog_data, "divergence_guard", return_value=[]):
            with self.assertRaises(AssertionError) as caught:
                gate_tiers.case_divergence_guard(None, None)
        self.assertIn("a live scenario with no catalog entry was judged as []",
                      str(caught.exception))

    def test_an_inventory_that_lost_its_error_paths_is_refused_before_the_damage(self):
        inventory = catalog_data.load_behaviors()
        stripped = {
            **inventory,
            "behaviors": [
                {**entry, "error_paths": []} if isinstance(entry, dict) else entry
                for entry in inventory.get("behaviors") or []
            ],
        }
        with mock.patch.object(catalog_data, "load_behaviors", return_value=stripped):
            with self.assertRaises(AssertionError) as caught:
                gate_tiers.case_coverage_audit(None, None)
        self.assertIn("fails its own audit", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
