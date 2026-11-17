#!/usr/bin/env python3
"""Suite nonroot: temporary access is revoked, or the run is not PASS.

``REV-01`` and ``REV-02`` are decided by ``tools/live_vps/operator.py``, so the
cases drive the product's own cleanup, its revoke pass, the summary sentence and
the report it writes. Every damage below rewrites one line of that module in a
temporary copy and loads the copy, so each assertion is seen to fail for the
reason it protects rather than for a mock that was never reached.
"""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import catalog, revocation  # noqa: E402

TOPOLOGIES = ("aio", "multi-node")

CASES = {
    revocation.REV_01: revocation.case_revocation_succeeds,
    revocation.REV_02: revocation.case_revocation_cannot_be_verified,
}

#: What each damage is meant to make a case say, so a probe that went red on an
#: unrelated assertion is not read as a held clause.
EXPECTED_REFUSALS = {
    ("REV-02", "cleanup-passes-with-the-key-present"):
        "a host still holding the marker was reported as clean",
    ("REV-02", "cleanup-ignores-the-timer"):
        "a host with an active expiry timer was reported as clean",
    ("REV-01", "cleanup-message-forgets-the-timer"):
        "the passing sentence reads",
    ("REV-02", "revoke-all-claims-success"):
        "reported overall success",
    ("REV-02", "revoke-all-skips-the-reverse"):
        "did not walk the targets in reverse order",
    ("REV-01", "report-is-world-readable"):
        "the operator report is mode",
    ("REV-01", "report-directory-is-open"):
        "the report directory is mode",
    ("REV-02", "refresh-keeps-the-overall-pass"):
        "after a failed cleanup",
    ("REV-02", "refresh-forgets-the-cleanup"):
        "the run state does not record the failed cleanup",
    ("REV-02", "summary-claims-removal-with-a-failure"):
        "a failing summary does not name the host that failed",
    ("REV-01", "revoke-script-never-ran"):
        "never ran the remote revoke script",
    ("REV-01", "marker-probe-ignores-the-marker"):
        "never probed authorized_keys for its marker",
    ("REV-02", "lost-connection-answered"):
        "a lost connection was answered instead of raised",
}

_REAL_OPERATOR = REPO_ROOT / "tools" / "live_vps" / "operator.py"


def _damaged_operator(workdir, old, new, expected, label):
    """``operator.py`` with exactly ``expected`` occurrences of ``old`` rewritten."""
    source = _REAL_OPERATOR.read_text(encoding="utf-8")
    assert source.count(old) == expected, f"{old!r} occurs {source.count(old)} times, not {expected}"
    path = Path(workdir) / f"operator_{label}.py"
    path.write_text(source.replace(old, new), encoding="utf-8")
    spec = importlib.util.spec_from_file_location(f"revocation_damaged_{label}", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _damages(workdir):
    return {
        "cleanup-passes-with-the-key-present": (
            'if not evidence["key_present"] and not evidence["timer_active"]:', "if True:", 1),
        "cleanup-ignores-the-timer": (' and not evidence["timer_active"]:', ":", 1),
        "cleanup-message-forgets-the-timer": (
            'return True, "temporary SSH key removed and expiry timer disabled", evidence',
            'return True, "temporary SSH key removed", evidence', 1),
        "revoke-all-claims-success": (
            'all(item["status"] == "PASS" for item in results.values())', "True", 1),
        "revoke-all-skips-the-reverse": ("for target in reversed(targets):",
                                         "for target in targets:", 1),
        "report-is-world-readable": ("tmp_file.chmod(0o600)", "tmp_file.chmod(0o644)", 1),
        "report-directory-is-open": ("artifact_dir.chmod(0o700)", "artifact_dir.chmod(0o755)", 1),
        "refresh-keeps-the-overall-pass": ('state["overall"] = "INCOMPLETE"',
                                           'state["overall"] = "PASS"', 1),
        "refresh-forgets-the-cleanup": (
            'state.setdefault("results", {})["operator_access_cleanup"] = entry',
            'state.setdefault("results", {})', 1),
        "summary-claims-removal-with-a-failure": ('if cleanup.get("status") == "PASS":',
                                                  "if True:", 1),
        "revoke-script-never-ran": (
            "ran = client.run(f\"/bin/sh '{script}' || true\", timeout=30)", "ran = present", 1),
        "marker-probe-ignores-the-marker": (
            "f\"grep -Fq -- '{marker}' /root/.ssh/authorized_keys 2>/dev/null\", timeout=30",
            "\"grep -Fq -- 'absent' /root/.ssh/authorized_keys 2>/dev/null\", timeout=30", 1),
        "lost-connection-answered": ("if 255 in (marker_check.returncode, timer_check.returncode):",
                                     "if False:", 1),
    }


def run_case(case_id, damage=None, workdir=None):
    """Run the case, optionally on a damaged product module; return (facts, refusal)."""
    patcher = None
    if damage:
        old, new, expected = _damages(workdir)[damage]
        patcher = mock.patch.object(
            revocation, "operator",
            _damaged_operator(workdir, old, new, expected, damage))
        patcher.start()
    try:
        return CASES[case_id](object(), SimpleNamespace(topology="aio")), None
    except AssertionError as error:
        return None, str(error)
    finally:
        if patcher is not None:
            patcher.stop()


class TestRevocationRegistration(unittest.TestCase):
    """Both ids are registered on both contours with their own callables."""

    def test_the_ids_are_registered_on_both_contours(self):
        registry = catalog.driver_registry()
        for case_id, function in CASES.items():
            with self.subTest(case=case_id):
                self.assertIn(case_id, registry)
                self.assertEqual(set(registry[case_id]), set(TOPOLOGIES))
                for topology in TOPOLOGIES:
                    self.assertEqual(
                        registry[case_id][topology]["driver"],
                        f"revocation:{function.__name__}",
                    )

    def test_the_catalog_entries_are_what_the_registry_derives(self):
        registry = catalog.driver_registry()
        entries = {entry["id"]: entry for entry in catalog.load_catalog()["cases"]}
        for case_id in CASES:
            with self.subTest(case=case_id):
                entry = entries[case_id]
                self.assertEqual(entry["driver_status"], "implemented")
                self.assertEqual(entry["drivers"], registry[case_id])
                self.assertEqual(sorted(entry["topology"]), sorted(TOPOLOGIES))


class TestRevocationCase(unittest.TestCase):
    """Each case holds on both contours and its evidence is what the catalog records."""

    def test_every_case_holds_on_both_contours(self):
        for case_id in CASES:
            for topology in TOPOLOGIES:
                with self.subTest(case=case_id, topology=topology):
                    facts = CASES[case_id](object(), SimpleNamespace(topology=topology))
                    self.assertTrue(facts)

    def test_the_evidence_sets_are_what_the_catalog_records(self):
        registry = catalog.driver_registry()
        for case_id in CASES:
            with self.subTest(case=case_id):
                facts, refusal = run_case(case_id)
                self.assertIsNone(refusal)
                self.assertEqual(sorted(facts), registry[case_id]["aio"]["evidence"])

    def test_a_clean_host_passes_and_the_key_never_leaves_the_control_machine(self):
        facts, refusal = run_case(revocation.REV_01)
        self.assertIsNone(refusal)
        self.assertTrue(facts["cleanup_reported_pass"])
        self.assertTrue(facts["revoke_script_ran"])
        self.assertTrue(facts["marker_probed"])
        self.assertTrue(facts["timer_probed"])
        self.assertFalse(facts["key_material_left_the_control_machine"])
        self.assertTrue(facts["client_keyed_on_the_control_machine_file"])
        self.assertEqual(facts["report_mode"], "0o600")
        self.assertEqual(facts["report_directory_mode"], "0o700")

    def test_every_unverified_state_is_incomplete_and_never_a_pass(self):
        facts, refusal = run_case(revocation.REV_02)
        self.assertIsNone(refusal)
        self.assertTrue(facts["key_only_reported_failure"])
        self.assertTrue(facts["timer_only_reported_failure"])
        self.assertTrue(facts["both_present_reported_failure"])
        self.assertTrue(facts["absent_script_reported_failure"])
        self.assertTrue(facts["unverifiable_connection_raised"])
        self.assertFalse(facts["revoke_all_overall"])
        self.assertEqual(facts["failed_target_status"], "INCOMPLETE")

    def test_a_failed_cleanup_turns_an_otherwise_pass_run_incomplete(self):
        facts, refusal = run_case(revocation.REV_02)
        self.assertIsNone(refusal)
        self.assertEqual(facts["overall_with_failed_cleanup"], "INCOMPLETE")
        self.assertEqual(facts["overall_with_passed_cleanup"], "PASS")
        self.assertEqual(facts["failed_run_records_the_cleanup"], "INCOMPLETE")

    def test_the_timer_is_recorded_as_still_armed_when_the_key_remains(self):
        facts, refusal = run_case(revocation.REV_02)
        self.assertIsNone(refusal)
        self.assertTrue(facts["timer_still_armed_recorded"])
        self.assertTrue(facts["both_present_names_both"])


class TestRevocationDamage(unittest.TestCase):
    """Each clause is damaged on its own and a case refuses for that reason."""

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory(prefix="gowave-rev-test-")
        self.addCleanup(self._directory.cleanup)
        self.workdir = Path(self._directory.name)

    def assert_refused(self, case_id, damage):
        _, refusal = run_case(case_id, damage=damage, workdir=self.workdir)
        self.assertIsNotNone(refusal, f"{damage} did not make {case_id} refuse")
        self.assertIn(EXPECTED_REFUSALS[(case_id, damage)], refusal)

    def test_a_cleanup_that_passes_with_the_key_present_is_refused(self):
        self.assert_refused("REV-02", "cleanup-passes-with-the-key-present")

    def test_a_cleanup_that_ignores_the_timer_is_refused(self):
        self.assert_refused("REV-02", "cleanup-ignores-the-timer")

    def test_a_passing_sentence_without_the_timer_is_refused(self):
        self.assert_refused("REV-01", "cleanup-message-forgets-the-timer")

    def test_a_revoke_pass_that_claims_success_is_refused(self):
        self.assert_refused("REV-02", "revoke-all-claims-success")

    def test_a_revoke_pass_without_the_reverse_walk_is_refused(self):
        self.assert_refused("REV-02", "revoke-all-skips-the-reverse")

    def test_a_world_readable_report_is_refused(self):
        self.assert_refused("REV-01", "report-is-world-readable")

    def test_an_open_report_directory_is_refused(self):
        self.assert_refused("REV-01", "report-directory-is-open")

    def test_a_run_kept_at_pass_after_a_failed_cleanup_is_refused(self):
        self.assert_refused("REV-02", "refresh-keeps-the-overall-pass")

    def test_a_run_state_without_the_cleanup_is_refused(self):
        self.assert_refused("REV-02", "refresh-forgets-the-cleanup")

    def test_a_summary_that_claims_removal_with_a_failure_is_refused(self):
        self.assert_refused("REV-02", "summary-claims-removal-with-a-failure")

    def test_a_cleanup_that_never_ran_the_script_is_refused(self):
        self.assert_refused("REV-01", "revoke-script-never-ran")

    def test_a_marker_probe_that_looks_for_the_wrong_string_is_refused(self):
        self.assert_refused("REV-01", "marker-probe-ignores-the-marker")

    def test_a_lost_connection_answered_instead_of_raised_is_refused(self):
        self.assert_refused("REV-02", "lost-connection-answered")


if __name__ == "__main__":
    unittest.main()
