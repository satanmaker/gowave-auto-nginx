#!/usr/bin/env python3
"""Suite nonroot: a failed node add is INCOMPLETE until both sides are verified.

``TXN-03`` is §Signal-Safe and Verifiable Transaction Compensation in
``openspec/changes/podman-full-e2e/specs/podman-e2e/spec.md``: when the Worker
compensation succeeds but the Panel API rollback fails, or the other way round,
Master retains both recovery records, reports the overall operation as
INCOMPLETE, and MUST NOT mark the transaction rolled back or committed until both
sides are verified.

The Master answers that with ``finalize_failed_node_add``, which asks each side
for its verdict and hands both to ``modules.recovery.record_rollback_sides``. The
order is the substance: the API rollback finalizes a clean rollback as
``NODE_ADD_ROLLED_BACK`` itself, so a Worker failure recorded afterwards would be
hidden behind that state unless the later writer is allowed to undo it.

The case drives the shipped finalizer over a scratch tree, with a stub Worker
script on one side and the product's own ``rollback_provisioning`` on the other.
Each clause is damaged on its own — a Worker side that is never asked, one asked
for a different transaction, an API side that is never asked, a writer that
marks the transaction rolled back regardless, one that records no sides, one that
drops the API's refusal, one that keeps no record at all, a finalizer that
reports nothing, one that reports success, one that reports no aggregate
refusal, and one that deletes the journal — so every assertion is seen to fail
for the reason it protects. The first of those damages is the defect this case
was written for: it is what the product did before the two-sided record existed.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from modules import recovery  # noqa: E402
from tools.podman_e2e import catalog, rollback_sides  # noqa: E402

TOPOLOGIES = ("aio", "multi-node")
DRIVER = rollback_sides.case_worker_and_api_rollback_are_both_required

#: What each damage is meant to make the case say, so a probe that went red on
#: an unrelated assertion is not read as a held clause.
EXPECTED_REFUSALS = {
    "finalizer-skips-the-worker-side":
        "a verified Panel API rollback over a failed Worker restore was not left INCOMPLETE",
    "finalizer-skips-the-api-side":
        "a verified Worker restore over a failed Panel API rollback was not left INCOMPLETE",
    "finalizer-reports-nothing":
        "the operation was not reported INCOMPLETE naming both sides",
    "finalizer-reports-success":
        "a verified Panel API rollback over a failed Worker restore was not left INCOMPLETE",
    "finalizer-drops-the-aggregate-refusal":
        "the aggregate refusal an operator reads was not reported",
    "finalizer-forgets-the-transaction":
        "the Worker rollback was asked to compensate a different transaction than the one "
        "the journal records",
    "finalizer-removes-the-journal":
        "the recovery record of the incomplete transaction was not retained",
    "writer-marks-rolled-back-anyway":
        "a verified Panel API rollback over a failed Worker restore was not left INCOMPLETE",
    "writer-drops-the-sides":
        "the journal does not record both compensation sides",
    "writer-drops-the-api-refusal":
        "the Panel API's own refusal was dropped when the outcome was recorded",
    "writer-keeps-no-record":
        "the journal does not record both compensation sides",
}

_SCRIPT_DAMAGES = (
    "finalizer-skips-the-worker-side",
    "finalizer-skips-the-api-side",
    "finalizer-reports-nothing",
    "finalizer-reports-success",
    "finalizer-drops-the-aggregate-refusal",
    "finalizer-forgets-the-transaction",
    "finalizer-removes-the-journal",
)
_MODULE_DAMAGES = (
    "writer-marks-rolled-back-anyway",
    "writer-drops-the-sides",
    "writer-drops-the-api-refusal",
    "writer-keeps-no-record",
)

_WORKER_ATTEMPT = """    if ACME_TX_ID="$acme_tx_id" PANEL_IP="$panel_ip" PANEL_IPV6="$panel_ipv6" NODE_PORT="$node_port" SSH_KNOWN_HOSTS="$known_hosts" \\
        VISION_DOMAIN="$vision_domain" \\
        GOWAVE_WORKER_LEASE_TOKEN="${GOWAVE_WORKER_LEASE_TOKEN:-}" \\
        "$SCRIPT_DIR/gowave-node-auto.sh" remote_rollback "$ip" "$ssh_port" "$worker_domain" "$reality_domain" "$ssh_user"; then
        worker_status="ROLLED_BACK"
    else
        echo "CRITICAL: Remote Worker host rollback failed; manual inspection required." >&2
    fi
"""

_API_ATTEMPT = """    if PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from modules.api_client import rollback_provisioning
import sys
sys.exit(0 if rollback_provisioning('$JOURNAL_FILE', '$STATE_FILE', '$CREDENTIALS_FILE') else 1)
"; then
        api_status="ROLLED_BACK"
    else
        echo "CRITICAL: API rollback incomplete; recovery journal requires operator attention." >&2
    fi
"""

_INCOMPLETE_LINE = (
    '        echo "CRITICAL: Node add \'$name\' is INCOMPLETE: Worker $worker_status, '
    'Panel API $api_status; both sides recorded in $JOURNAL_FILE." >&2\n'
)
_AGGREGATE_LINE = (
    '        echo "CRITICAL: Rollback failed for Worker \'$name\'; recovery journal retained." >&2\n'
)


def _rewritten(body: str, old: str, new: str, expected: int = 1) -> str:
    """The text with exactly ``expected`` occurrences rewritten."""
    assert body.count(old) == expected, f"{old!r} occurs {body.count(old)} times, not {expected}"
    return body.replace(old, new)


def run_case(damage=None, workdir=None):
    """Run the case, optionally with one clause of the product damaged."""
    patchers = []
    if damage in _SCRIPT_DAMAGES:
        broken = Path(workdir) / "gowave-auto-damaged.sh"
        broken.write_text(_damage_script(damage), encoding="utf-8")
        patchers.append(mock.patch.object(rollback_sides, "AUTO_SCRIPT", broken))
    elif damage in _MODULE_DAMAGES:
        package = _damaged_package(Path(workdir), damage)
        patchers.append(mock.patch.object(rollback_sides, "SCRIPT_ROOT", package))
    for patcher in patchers:
        patcher.start()
    try:
        return DRIVER(object(), object()), None
    except AssertionError as error:
        return None, str(error)
    finally:
        for patcher in reversed(patchers):
            patcher.stop()


def _damage_script(damage):
    """The finalizer with one clause rewritten."""
    body = rollback_sides.AUTO_SCRIPT.read_text(encoding="utf-8")

    if damage == "finalizer-skips-the-worker-side":
        return _rewritten(body, _WORKER_ATTEMPT, '    worker_status="ROLLED_BACK"\n')
    if damage == "finalizer-skips-the-api-side":
        return _rewritten(body, _API_ATTEMPT, '    api_status="ROLLED_BACK"\n')
    if damage == "finalizer-reports-nothing":
        return _rewritten(body, _INCOMPLETE_LINE, "")
    if damage == "finalizer-reports-success":
        return _rewritten(
            body, _AGGREGATE_LINE + "        return 1\n",
            _AGGREGATE_LINE + "        return 0\n")
    if damage == "finalizer-drops-the-aggregate-refusal":
        return _rewritten(body, _AGGREGATE_LINE, "")
    if damage == "finalizer-forgets-the-transaction":
        return _rewritten(
            body, '    if ACME_TX_ID="$acme_tx_id" PANEL_IP="$panel_ip"',
            '    if ACME_TX_ID="" PANEL_IP="$panel_ip"')
    if damage == "finalizer-removes-the-journal":
        return _rewritten(
            body, _INCOMPLETE_LINE, '        rm -f "$JOURNAL_FILE"\n' + _INCOMPLETE_LINE)
    raise AssertionError(f"unknown script damage {damage!r}")


def _damage_recovery(source, damage):
    if damage == "writer-marks-rolled-back-anyway":
        return _rewritten(
            source,
            '    verified = worker_status == "ROLLED_BACK" and api_status == "ROLLED_BACK"\n',
            "    verified = True\n")
    if damage == "writer-drops-the-sides":
        return _rewritten(
            source,
            '    data["rollback_sides"] = {"worker": worker_status, "api": api_status}\n',
            "")
    if damage == "writer-drops-the-api-refusal":
        return _rewritten(
            source,
            '    data["rollback_sides"] = {"worker": worker_status, "api": api_status}\n',
            '    data.pop("rollback_error", None)\n'
            '    data["rollback_sides"] = {"worker": worker_status, "api": api_status}\n')
    if damage == "writer-keeps-no-record":
        return _rewritten(
            source,
            "    write_journal_atomically(journal_path, data)\n    return verified\n",
            "    return verified\n")
    raise AssertionError(f"unknown module damage {damage!r}")


def _damaged_package(workdir, damage):
    """A modules package whose recovery or api_client is the damaged copy."""
    package = workdir / "pkg"
    (package / "modules").mkdir(parents=True)
    for name in ("recovery.py", "api_client.py"):
        source = (REPO_ROOT / "modules" / name).read_text(encoding="utf-8")
        if name == "recovery.py":
            source = _damage_recovery(source, damage)
        (package / "modules" / name).write_text(source, encoding="utf-8")
    return package


class TestRollbackSidesRegistration(unittest.TestCase):
    """The id is registered on both contours, each with the driver it runs."""

    def test_the_id_is_registered_on_both_contours(self):
        registry = catalog.driver_registry()
        self.assertIn(rollback_sides.CASE_ID, registry)
        self.assertEqual(set(registry[rollback_sides.CASE_ID]), set(TOPOLOGIES))
        for name in TOPOLOGIES:
            self.assertEqual(
                registry[rollback_sides.CASE_ID][name]["driver"],
                f"rollback_sides:{DRIVER.__name__}",
            )

    def test_the_catalog_entry_is_what_the_registry_derives(self):
        registry = catalog.driver_registry()
        entries = {entry["id"]: entry for entry in catalog.load_catalog()["cases"]}
        entry = entries[rollback_sides.CASE_ID]
        self.assertEqual(entry["driver_status"], "implemented")
        self.assertEqual(entry["drivers"], registry[rollback_sides.CASE_ID])
        self.assertEqual(sorted(entry["topology"]), sorted(TOPOLOGIES))


class TestRollbackSidesCase(unittest.TestCase):
    """The two-sided record holds on this tree and reports the facts it decides."""

    def test_the_two_sides_hold_on_both_contours(self):
        for name in TOPOLOGIES:
            with self.subTest(topology=name):
                facts, refusal = run_case()
                self.assertIsNone(refusal)
                self.assertEqual(len(facts), len(rollback_sides.EVIDENCE))
                self.assertTrue(all(facts.values()), facts)

    def test_the_evidence_set_is_what_the_catalog_records(self):
        registry = catalog.driver_registry()
        for name in TOPOLOGIES:
            with self.subTest(topology=name):
                facts, refusal = run_case()
                self.assertIsNone(refusal)
                self.assertEqual(
                    sorted(facts), registry[rollback_sides.CASE_ID][name]["evidence"])

    def test_both_failure_paths_go_through_one_finalizer(self):
        text = rollback_sides.AUTO_SCRIPT.read_text(encoding="utf-8")
        # The remote failure and the commit-record failure are the two ways a
        # node add can end after the Worker was dispatched, and neither may
        # compensate on its own: a second copy is a second place to forget a side.
        self.assertEqual(text.count('finalize_failed_node_add "'), 2)
        cmd_node = text[text.index("cmd_node() {"):text.index("\ncmd_domain_change() {")]
        self.assertEqual(cmd_node.count('finalize_failed_node_add "'), 2)
        # The registration failure runs before any Worker mutation, so it keeps
        # its own API-only rollback: the one inline call is that one, and it is
        # above the dispatch.
        dispatch = cmd_node.index("# 4. Dispatch remote deployment strictly via SSH stdin")
        call = "rollback_provisioning('$JOURNAL_FILE'"
        self.assertEqual(cmd_node.count(call), 1)
        self.assertLess(cmd_node.index(call), dispatch)
        self.assertEqual(cmd_node[dispatch:].count(call), 0)
        # The finalizer writes both verdicts with the product's own writer.
        self.assertEqual(rollback_sides.function_body().count("record_rollback_sides("), 1)


class TestRollbackSideRecord(unittest.TestCase):
    """The writer's own refusals, which no scenario of the case reaches."""

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory(prefix="gowave-txn-03-writer-")
        self.addCleanup(self._directory.cleanup)
        self.root = Path(self._directory.name)
        self.journal = self.root / "journal.json"

    def _write(self, state):
        recovery.write_journal_atomically(self.journal, {
            "transaction_id": "node_add_worker-1",
            "op": "node_add",
            "state": state,
            "node_name": "worker-1",
            "timestamp": "2026-11-18T00:00:00Z",
            "entities": [],
        })

    def test_a_committed_transaction_is_not_rewritten_as_a_rollback(self):
        self._write("NODE_ADD_COMMITTED")
        before = self.journal.read_text(encoding="utf-8")
        with self.assertRaises(recovery.JournalValidationError):
            recovery.record_rollback_sides(
                str(self.journal), "ROLLED_BACK", "ROLLED_BACK")
        self.assertEqual(self.journal.read_text(encoding="utf-8"), before)

    def test_an_unknown_side_status_is_refused(self):
        self._write("NODE_ADD_APPLYING")
        before = self.journal.read_text(encoding="utf-8")
        for worker, api in (("PARTIAL", "ROLLED_BACK"), ("ROLLED_BACK", "DONE")):
            with self.subTest(worker=worker, api=api):
                with self.assertRaises(recovery.JournalValidationError):
                    recovery.record_rollback_sides(str(self.journal), worker, api)
        self.assertEqual(self.journal.read_text(encoding="utf-8"), before)

    def test_both_verified_finalizes_and_one_side_does_not(self):
        self._write("NODE_ADD_APPLYING")
        self.assertFalse(recovery.record_rollback_sides(
            str(self.journal), "ROLLED_BACK", "INCOMPLETE"))
        self.assertEqual(
            json.loads(self.journal.read_text(encoding="utf-8"))["state"],
            "NODE_ADD_ROLLBACK_REQUIRED")
        self.assertTrue(recovery.record_rollback_sides(
            str(self.journal), "ROLLED_BACK", "ROLLED_BACK"))
        data = json.loads(self.journal.read_text(encoding="utf-8"))
        self.assertEqual(data["state"], "NODE_ADD_ROLLED_BACK")
        self.assertEqual(data["rollback_sides"], {"worker": "ROLLED_BACK", "api": "ROLLED_BACK"})


class TestRollbackSidesDamage(unittest.TestCase):
    """Each clause is damaged on its own and the case refuses for that reason."""

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory(prefix="gowave-txn-03-damage-")
        self.addCleanup(self._directory.cleanup)
        self.workdir = Path(self._directory.name)

    def assert_refused(self, damage):
        _, refusal = run_case(damage=damage, workdir=self.workdir)
        self.assertIsNotNone(refusal, f"{damage} did not make TXN-03 refuse")
        self.assertIn(EXPECTED_REFUSALS[damage], refusal)

    def test_a_finalizer_that_skips_the_worker_side_is_refused(self):
        self.assert_refused("finalizer-skips-the-worker-side")

    def test_a_finalizer_that_skips_the_api_side_is_refused(self):
        self.assert_refused("finalizer-skips-the-api-side")

    def test_a_finalizer_that_reports_nothing_is_refused(self):
        self.assert_refused("finalizer-reports-nothing")

    def test_a_finalizer_that_reports_success_is_refused(self):
        self.assert_refused("finalizer-reports-success")

    def test_a_finalizer_that_drops_the_aggregate_refusal_is_refused(self):
        self.assert_refused("finalizer-drops-the-aggregate-refusal")

    def test_a_finalizer_that_forgets_the_transaction_is_refused(self):
        self.assert_refused("finalizer-forgets-the-transaction")

    def test_a_finalizer_that_removes_the_journal_is_refused(self):
        self.assert_refused("finalizer-removes-the-journal")

    def test_a_writer_that_marks_the_rollback_anyway_is_refused(self):
        self.assert_refused("writer-marks-rolled-back-anyway")

    def test_a_writer_that_records_no_sides_is_refused(self):
        self.assert_refused("writer-drops-the-sides")

    def test_a_writer_that_drops_the_api_refusal_is_refused(self):
        self.assert_refused("writer-drops-the-api-refusal")

    def test_a_writer_that_keeps_no_record_is_refused(self):
        self.assert_refused("writer-keeps-no-record")


if __name__ == "__main__":
    unittest.main()
