#!/usr/bin/env python3
"""Suite nonroot: an interrupted mutation leaves a validated journal behind.

``TXN-02`` is decided by ``modules/recovery.py`` and by ``recover_boot_files`` in
``modules/recovery.sh``, so the case writes the journal with the product's own
atomic writer and runs the boot recovery in a temporary tree.

Each clause is damaged on its own — a recovery that does not take the mutation
lock, a missing snapshot reported as recovered, a snapshot outside the recovery
root rolled back anyway, a journal validated by nobody, a state left unrewritten,
a journal written world-readable, and a journal that forgets the snapshot it took
— so every assertion is seen to fail for the reason it protects.
"""
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from modules import recovery  # noqa: E402
from tools.podman_e2e import catalog, transaction_recovery  # noqa: E402

TOPOLOGIES = ("aio", "multi-node")

CASES = {
    transaction_recovery.CASE_ID:
        transaction_recovery.case_interrupted_mutation_leaves_a_validated_journal,
}

#: What each damage is meant to make the case say, so a probe that went red on an
#: unrelated assertion is not read as a held clause.
EXPECTED_REFUSALS = {
    "recovery-without-the-lock": "before it takes the mutation lock",
    "missing-snapshot-reported-recovered": "a journal naming an absent snapshot was reported as recovered",
    "outside-root-accepted": "a snapshot outside the recovery root was rolled back",
    "validation-skipped": "an invalid journal was accepted for automated rollback",
    "state-not-rewritten": "the recovered journal is left in",
    "journal-mode-loosened": "the journal is mode",
    "snapshot-field-dropped": "the journal does not name the snapshot it took",
}

_REAL_SH = transaction_recovery.REPO_ROOT / "modules" / "recovery.sh"
_REAL_WRITE = recovery.write_journal_atomically


def _rewritten_tree(workdir, old, new, expected):
    """A tree whose recovery.sh carries exactly ``expected`` rewritten lines."""
    tree = Path(workdir) / f"tree-{len(list(Path(workdir).glob('tree-*')))}"
    (tree / "modules").mkdir(parents=True)
    body = _REAL_SH.read_text(encoding="utf-8")
    assert body.count(old) == expected, f"{old!r} occurs {body.count(old)} times, not {expected}"
    (tree / "modules" / "recovery.sh").write_text(body.replace(old, new), encoding="utf-8")
    shutil.copy2(transaction_recovery.REPO_ROOT / "modules" / "recovery.py",
                 tree / "modules" / "recovery.py")
    return tree


def _writer_that_loosens_the_mode(journal_path, journal_data):
    _REAL_WRITE(journal_path, journal_data)
    Path(journal_path).chmod(0o644)


def _writer_that_drops_the_snapshot(journal_path, journal_data):
    """A writer that passes validation and then leaves the snapshot out of the file."""
    _REAL_WRITE(journal_path, journal_data)
    path = Path(journal_path)
    trimmed = {key: value for key, value in json.loads(path.read_text()).items()
               if key != "snapshot_dir"}
    path.write_text(json.dumps(trimmed, indent=2), encoding="utf-8")
    path.chmod(0o600)


def _damages(workdir):
    return {
        "recovery-without-the-lock": [
            mock.patch.object(
                transaction_recovery, "SCRIPT_ROOT",
                _rewritten_tree(workdir, "    acquire_mutation_lock || return 1\n", "    true\n", 3)),
        ],
        "missing-snapshot-reported-recovered": [
            mock.patch.object(
                transaction_recovery, "SCRIPT_ROOT",
                _rewritten_tree(
                    workdir,
                    'if [[ -z "$snap_dir" || ! -d "$snap_dir" ]]; then',
                    "if false; then", 1)),
        ],
        "outside-root-accepted": [
            mock.patch.object(
                transaction_recovery, "SCRIPT_ROOT",
                _rewritten_tree(workdir, "if snapshot == root or root not in snapshot.parents:",
                                "if False:", 1)),
        ],
        "validation-skipped": [
            mock.patch.object(
                transaction_recovery, "SCRIPT_ROOT",
                _rewritten_tree(
                    workdir,
                    'if ! python3 "$RECOVERY_PY" --validate-journal "$JOURNAL_FILE" 2>/dev/null; then',
                    "if false; then", 1)),
        ],
        "state-not-rewritten": [
            mock.patch.object(
                transaction_recovery, "SCRIPT_ROOT",
                _rewritten_tree(workdir, "data['state'] = 'ROLLED_BACK'",
                                "data['state'] = 'APPLYING'", 1)),
        ],
        "journal-mode-loosened": [
            mock.patch.object(recovery, "write_journal_atomically",
                              _writer_that_loosens_the_mode),
        ],
        "snapshot-field-dropped": [
            mock.patch.object(recovery, "write_journal_atomically",
                              _writer_that_drops_the_snapshot),
        ],
    }


def run_case(case_id, damage=None, workdir=None):
    """Run the case, optionally with one damaged behaviour; return (facts, refusal)."""
    patchers = _damages(workdir)[damage] if damage else []
    for patcher in patchers:
        patcher.start()
    try:
        return CASES[case_id](object(), SimpleNamespace(topology="aio")), None
    except AssertionError as error:
        return None, str(error)
    finally:
        for patcher in reversed(patchers):
            patcher.stop()


class TestTransactionRecoveryRegistration(unittest.TestCase):
    """The id is registered on both contours with its own callable."""

    def test_the_id_is_registered_on_both_contours(self):
        registry = catalog.driver_registry()
        for case_id, function in CASES.items():
            with self.subTest(case=case_id):
                self.assertIn(case_id, registry)
                self.assertEqual(set(registry[case_id]), set(TOPOLOGIES))
                for topology in TOPOLOGIES:
                    self.assertEqual(
                        registry[case_id][topology]["driver"],
                        f"transaction_recovery:{function.__name__}",
                    )

    def test_the_catalog_entry_is_what_the_registry_derives(self):
        registry = catalog.driver_registry()
        entries = {entry["id"]: entry for entry in catalog.load_catalog()["cases"]}
        for case_id in CASES:
            with self.subTest(case=case_id):
                entry = entries[case_id]
                self.assertEqual(entry["driver_status"], "implemented")
                self.assertEqual(entry["drivers"], registry[case_id])
                self.assertEqual(sorted(entry["topology"]), sorted(TOPOLOGIES))


class TestTransactionRecoveryCase(unittest.TestCase):
    """The case holds on both contours and its evidence is what the catalog records."""

    def test_every_case_holds_on_both_contours(self):
        for case_id in CASES:
            for topology in TOPOLOGIES:
                with self.subTest(case=case_id, topology=topology):
                    facts = CASES[case_id](object(), SimpleNamespace(topology=topology))
                    self.assertTrue(facts)

    def test_the_evidence_set_is_what_the_catalog_records(self):
        registry = catalog.driver_registry()
        for case_id in CASES:
            with self.subTest(case=case_id):
                facts, refusal = run_case(case_id)
                self.assertIsNone(refusal)
                self.assertEqual(sorted(facts), registry[case_id]["aio"]["evidence"])

    def test_the_journal_is_validated_named_and_private(self):
        facts, refusal = run_case(transaction_recovery.CASE_ID)
        self.assertIsNone(refusal)
        self.assertTrue(facts["mid_switch_journal_validated"])
        self.assertTrue(facts["journal_names_the_snapshot"])
        self.assertEqual(facts["journal_mode"], "0o600")
        self.assertTrue(facts["journal_write_leaves_no_temp"])

    def test_the_boot_recovery_rolls_the_named_snapshot_back(self):
        facts, refusal = run_case(transaction_recovery.CASE_ID)
        self.assertIsNone(refusal)
        self.assertEqual(facts["recovery_exit"], 0)
        self.assertEqual(facts["recovered_state"], "ROLLED_BACK")
        self.assertTrue(facts["recovery_names_the_state_it_found"])
        self.assertTrue(facts["rollback_delegate_called"])

    def test_every_unrecoverable_journal_is_refused_without_rewriting_it(self):
        facts, refusal = run_case(transaction_recovery.CASE_ID)
        self.assertIsNone(refusal)
        self.assertTrue(facts["missing_snapshot_refused"])
        self.assertEqual(facts["missing_snapshot_left_state"], "APPLYING")
        self.assertTrue(facts["outside_root_refused"])
        self.assertEqual(facts["outside_root_left_state"], "APPLYING")
        self.assertTrue(facts["invalid_journal_refused"])
        self.assertEqual(facts["invalid_journal_left_state"], "PROVISION_APPLYING")
        self.assertEqual(facts["absent_journal_exit"], 0)

    def test_the_recovery_holds_the_mutation_lock_before_it_reads(self):
        facts, refusal = run_case(transaction_recovery.CASE_ID)
        self.assertIsNone(refusal)
        self.assertTrue(facts["recovery_takes_the_mutation_lock"])
        self.assertTrue(facts["lock_precedes_validation"])


class TestTransactionRecoveryDamage(unittest.TestCase):
    """Each clause is damaged on its own and the case refuses for that reason."""

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory(prefix="gowave-txn-test-")
        self.addCleanup(self._directory.cleanup)
        self.workdir = Path(self._directory.name)

    def assert_refused(self, damage):
        _, refusal = run_case(transaction_recovery.CASE_ID, damage=damage, workdir=self.workdir)
        self.assertIsNotNone(refusal, f"{damage} did not make TXN-02 refuse")
        self.assertIn(EXPECTED_REFUSALS[damage], refusal)

    def test_a_recovery_that_skips_the_lock_is_refused(self):
        self.assert_refused("recovery-without-the-lock")

    def test_a_missing_snapshot_reported_as_recovered_is_refused(self):
        self.assert_refused("missing-snapshot-reported-recovered")

    def test_a_snapshot_outside_the_root_is_refused(self):
        self.assert_refused("outside-root-accepted")

    def test_a_journal_nobody_validated_is_refused(self):
        self.assert_refused("validation-skipped")

    def test_a_state_left_unrewritten_is_refused(self):
        self.assert_refused("state-not-rewritten")

    def test_a_world_readable_journal_is_refused(self):
        self.assert_refused("journal-mode-loosened")

    def test_a_journal_that_forgets_its_snapshot_is_refused(self):
        self.assert_refused("snapshot-field-dropped")


if __name__ == "__main__":
    unittest.main()
