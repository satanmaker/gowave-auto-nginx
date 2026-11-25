#!/usr/bin/env python3
"""Suite nonroot: an interrupted Worker install compensates once and says so.

``TXN-01`` is §Signal-Safe and Verifiable Transaction Compensation in
``openspec/specs/podman-e2e/spec.md``: a remote Worker
deployment that has mutated at least one resource and has not committed, on HUP,
INT or TERM, stops starting new mutations, persists interruption state, executes
compensation exactly once, verifies the result and exits nonzero — secret and
temp-file cleanup alone is not sufficient.

The payload answers that with the block its remote shell installs before the first
mutation: ``handle_signal`` for the three signals, ``handle_error`` for a failing
step, ``compensate_once`` in front of both, and the EXIT trap for the temp files
and the unset secrets. Compensation is ``compensate_remote_worker``: it records
the package residue, restores the inventoried paths from the transaction's own
before-image, verifies every restored file against the digest it recorded, and
reports the cleanup incomplete when it cannot.

The case runs that block as the shipped bytes over a scratch host root, so it
decides the handlers' verdict, the number of times the compensator runs, and the
bytes the restore leaves behind. Each clause is damaged on its own — a TERM, HUP
or INT handler that skips the compensator, a handler that bypasses the single
compensation, a signal that stops nothing, a journal that is never written, a
restore that skips pre-existing paths, one that writes a fixed mode, one that
trusts a write it did not read back, one that trusts a copy changed after it was
written, an interruption that exits zero, a cleanup that keeps the payload's temp
file, and a compensation that removes the journal — so every assertion is seen to
fail for the reason it protects.

Two clauses are decided by the same absence: a journal the compensation removed is
also a journal the interruption did not persist, and both sentences are true of
that host.
"""
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import catalog, signal_compensation  # noqa: E402
from tools.podman_e2e.runner import CaseBlocked  # noqa: E402

TOPOLOGIES = ("aio", "multi-node")
DRIVERS = {
    "aio": signal_compensation.case_panel_signal_is_compensated_once,
    "multi-node": signal_compensation.case_worker_signal_is_compensated_once,
}

#: The before-image block and the journal block are spliced into the payload
#: twice and into the rollback script once, so a damage rewrites every copy — and
#: the copies stay byte-identical.
BLOCK_COPIES = 3

#: What each damage is meant to make the case say, so a probe that went red on
#: an unrelated assertion is not read as a held clause.
EXPECTED_REFUSALS = {
    "term-handler-skips-compensation":
        "the TERM handler did not run the compensator exactly once",
    "hup-handler-skips-compensation":
        "the HUP handler did not run the compensator exactly once",
    "int-handler-skips-compensation":
        "the INT handler did not run the compensator exactly once",
    "handler-compensates-outside-the-guard":
        "the compensator ran more than once for one interruption",
    "signal-stops-nothing":
        "the interrupted run started another mutation after the signal",
    "journal-is-never-written":
        "the interrupted transaction left no journal naming the state it never committed",
    "restore-skips-pre-existing-paths":
        "the compensation left the mutated path as the interrupted run wrote it",
    "restore-writes-a-fixed-mode":
        "the compensation put the content back without the mode it recorded",
    "restore-trusts-a-write-it-did-not-read-back":
        "the compensation preserved a path its restore could have put back, so the "
        "restore was not verified",
    "restore-trusts-a-changed-copy":
        "the compensation claimed a restore it could not verify",
    "signal-exits-zero":
        "the interrupted run did not exit nonzero, or was still running after the signal",
    "cleanup-keeps-the-payload-temp-file": "the payload's temp file survived the interruption",
    "compensation-removes-the-journal":
        "a signal other than TERM did not leave the transaction's journal in place",
}

_TEMP_FILE = "/tmp/gowave-node-install-*.sh"


def _bash_driver(script, timeout=300):
    """Run the driver as the shipped bytes, with the three signals left trappable.

    A signal that is ignored when a process starts cannot be trapped, so a
    launcher that ignores one decides that scenario instead of the product's
    handler: a suite run with `&` hands its children SIGINT ignored, and one run
    under `nohup` hands them SIGHUP ignored. The dispositions are restored for the
    run and put back afterwards, so the suite's own handling of a Ctrl-C and of a
    terminal hangup is unchanged.
    """
    restored = {}
    for number in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        if signal.getsignal(number) is signal.SIG_IGN:
            signal.signal(number, signal.SIG_DFL)
            restored[number] = signal.SIG_IGN
    try:
        return subprocess.run(
            ["bash", "-s"], input=script, capture_output=True, text=True, timeout=timeout,
        )
    finally:
        for number, disposition in restored.items():
            signal.signal(number, disposition)


class _LocalHost:
    """The container's shell, answered by this machine: same script, same bash."""

    def host_script(self, script, timeout=300):
        return _bash_driver(script, timeout)


class _LocalPodman:
    def exec_bash(self, name, script, check=True, input_text=None, timeout=300):
        return _bash_driver(script, timeout)


class _LocalProduct:
    def __init__(self, worker=True):
        self.host_script = _LocalHost().host_script
        self.podman = _LocalPodman()
        self.topology = (
            type("Topology", (), {"worker_name": "worker-1"})() if worker else None
        )


def _rewritten(body: str, old: str, new: str, expected: int) -> str:
    """The text with exactly ``expected`` occurrences rewritten."""
    assert body.count(old) == expected, f"{old!r} occurs {body.count(old)} times, not {expected}"
    return body.replace(old, new)


def run_case(topology_name, damage=None, workdir=None):
    """Run one contour, optionally with one damaged clause of the product."""
    product = _LocalProduct(worker=topology_name == "multi-node")
    patchers = []
    if damage:
        broken = Path(workdir) / "gowave-node-auto-damaged.sh"
        broken.write_text(_damage_source(damage), encoding="utf-8")
        patchers.append(mock.patch.object(signal_compensation, "WORKER_INSTALLER", broken))
    for patcher in patchers:
        patcher.start()
    try:
        return DRIVERS[topology_name](product, object()), None
    except AssertionError as error:
        return None, str(error)
    finally:
        for patcher in reversed(patchers):
            patcher.stop()


def _damage_source(damage):
    """The product with one clause of the signal block rewritten."""
    body = signal_compensation.WORKER_INSTALLER.read_text(encoding="utf-8")

    if damage == "term-handler-skips-compensation":
        return _rewritten(
            body,
            "    trap 'handle_signal TERM' TERM\n",
            "    trap 'cleanup_temp_and_secrets' TERM\n",
            1,
        )
    if damage == "hup-handler-skips-compensation":
        return _rewritten(
            body,
            "    trap 'handle_signal HUP' HUP\n",
            "    trap 'cleanup_temp_and_secrets' HUP\n",
            1,
        )
    if damage == "int-handler-skips-compensation":
        return _rewritten(
            body,
            "    trap 'handle_signal INT' INT\n",
            "    trap 'cleanup_temp_and_secrets' INT\n",
            1,
        )
    if damage == "handler-compensates-outside-the-guard":
        return _rewritten(
            body,
            "        compensate_once 128\n",
            "        compensate_once 128\n"
            "        compensate_remote_worker 128\n",
            1,
        )
    if damage == "signal-stops-nothing":
        # Neither the handler nor the ERR trap halts the run, so the deployment
        # reaches the mutation that follows the step the signal interrupted. One
        # trap left in place would stop it: a returning HUP handler fails the
        # interrupted `wait`, and the ERR trap would then compensate and exit.
        broken = _rewritten(
            body,
            "    trap 'handle_signal HUP' HUP\n",
            "    trap ':' HUP\n",
            1,
        )
        return _rewritten(broken, '    trap \'handle_error "$?"\' ERR\n', "    trap ':' ERR\n", 1)
    if damage == "journal-is-never-written":
        return _rewritten(
            body,
            "def store(state):\n"
            "    # An installed transaction is closed: rewriting it as started would let a\n"
            "    # later run undo an install that already verified every path it wrote.\n",
            "def store(state):\n"
            "    return\n"
            "    # An installed transaction is closed: rewriting it as started would let a\n"
            "    # later run undo an install that already verified every path it wrote.\n",
            BLOCK_COPIES,
        )
    if damage == "restore-skips-pre-existing-paths":
        return _rewritten(
            body,
            'def restore_pre_existing(path, entry):\n'
            "    # A path that was here before: put back its recorded content and metadata.\n"
            '    state = entry.get("state")\n',
            'def restore_pre_existing(path, entry):\n'
            "    return\n"
            '    state = entry.get("state")\n',
            BLOCK_COPIES,
        )
    if damage == "restore-writes-a-fixed-mode":
        return _rewritten(
            body,
            '        write_atomic(path, payload, int(entry.get("mode") or 0o644))\n',
            "        write_atomic(path, payload, 0o644)\n",
            BLOCK_COPIES,
        )
    if damage == "restore-trusts-a-write-it-did-not-read-back":
        return _rewritten(
            body,
            '    if digest(path) != entry.get("sha256"):\n'
            '        keep(path, "the restored file does not read back as the before-image")\n',
            '    if True:\n'
            '        keep(path, "the restored file does not read back as the before-image")\n',
            BLOCK_COPIES,
        )
    if damage == "restore-trusts-a-changed-copy":
        # Two independent checks stand between a changed copy and a silent
        # restore: the copy is hashed before it is read, and the path is read
        # back after it is written. A damage that removes only one is repaired by
        # the other, so the clause is damaged in both.
        broken = _rewritten(
            body,
            '    if hashlib.sha256(payload).hexdigest() != entry.get("sha256"):\n'
            '        keep(path, "its before-image copy changed after it was written")\n'
            "        return\n",
            '    if False:\n'
            '        keep(path, "its before-image copy changed after it was written")\n'
            "        return\n",
            BLOCK_COPIES,
        )
        return _rewritten(
            broken,
            '    if digest(path) != entry.get("sha256"):\n'
            '        keep(path, "the restored file does not read back as the before-image")\n',
            '    if False:\n'
            '        keep(path, "the restored file does not read back as the before-image")\n',
            BLOCK_COPIES,
        )
    if damage == "signal-exits-zero":
        return _rewritten(body, "        exit 128\n", "        exit 0\n", 1)
    if damage == "cleanup-keeps-the-payload-temp-file":
        # Both copies remove the payload's temp file: the handler's own cleanup
        # and the compensator's step 8. A damage that left either in place would
        # be repaired by the other, so the clause is damaged in both.
        names = "rm -f /tmp/gowave-verify-node-mtls.py /tmp/gowave-managed-security.py"
        broken = _rewritten(
            body,
            names + " " + _TEMP_FILE + " /run/gowave-acme-test-ca.pem 2>/dev/null || true\n",
            names + " /run/gowave-acme-test-ca.pem 2>/dev/null || true\n",
            1,
        )
        return _rewritten(
            broken,
            names + " " + _TEMP_FILE + " /run/gowave-acme-test-ca.pem || rollback_failed=1\n",
            names + " /run/gowave-acme-test-ca.pem || rollback_failed=1\n",
            1,
        )
    if damage == "compensation-removes-the-journal":
        return _rewritten(
            body,
            '    record_worker_package_changes "$_ACME_TX_ID" "$state_root" ||\n',
            '    worker_journal_action remove "$(worker_transaction_journal "$state_root" '
            '"$_ACME_TX_ID")" "$_ACME_TX_ID" || true\n'
            '    record_worker_package_changes "$_ACME_TX_ID" "$state_root" ||\n',
            1,
        )
    raise AssertionError(f"unknown damage {damage!r}")


class TestSignalCompensationRegistration(unittest.TestCase):
    """The id is registered on both contours, each with the driver it runs."""

    def test_the_id_is_registered_on_both_contours(self):
        registry = catalog.driver_registry()
        self.assertIn(signal_compensation.CASE_ID, registry)
        self.assertEqual(set(registry[signal_compensation.CASE_ID]), set(TOPOLOGIES))
        for name, function in DRIVERS.items():
            self.assertEqual(
                registry[signal_compensation.CASE_ID][name]["driver"],
                f"signal_compensation:{function.__name__}",
            )

    def test_the_catalog_entry_is_what_the_registry_derives(self):
        registry = catalog.driver_registry()
        entries = {entry["id"]: entry for entry in catalog.load_catalog()["cases"]}
        entry = entries[signal_compensation.CASE_ID]
        self.assertEqual(entry["driver_status"], "implemented")
        self.assertEqual(entry["drivers"], registry[signal_compensation.CASE_ID])
        self.assertEqual(sorted(entry["topology"]), sorted(TOPOLOGIES))


class TestSignalCompensationCase(unittest.TestCase):
    """Both halves hold on this tree, and each reports the facts it decides."""

    def test_the_interruption_holds_on_both_contours(self):
        for name in TOPOLOGIES:
            with self.subTest(topology=name):
                facts, refusal = run_case(name)
                self.assertIsNone(refusal)
                self.assertEqual(len(facts), len(signal_compensation.EVIDENCE))
                self.assertTrue(all(facts.values()), facts)

    def test_the_evidence_set_is_what_the_catalog_records(self):
        registry = catalog.driver_registry()
        for name in TOPOLOGIES:
            with self.subTest(topology=name):
                facts, refusal = run_case(name)
                self.assertIsNone(refusal)
                self.assertEqual(
                    sorted(facts), registry[signal_compensation.CASE_ID][name]["evidence"])

    def test_the_handlers_share_one_compensation(self):
        preamble = signal_compensation.signal_preamble()
        # The preamble is the payload's block with its four spaces of nesting
        # removed, so the handlers' bodies sit four spaces in here.
        self.assertEqual(preamble.count("    compensate_once 128\n"), 1)
        self.assertEqual(preamble.count('    compensate_once "$exit_code"\n'), 1)
        self.assertEqual(preamble.count('[[ "${_COMPENSATED:-0}" -eq 0 ]] || return 0\n'), 1)
        self.assertEqual(preamble.count("    _COMPENSATED=1\n"), 1)
        # The compensator hands back the exit code it was given, so a call from
        # either handler that is not guarded would re-enter the ERR trap and roll
        # back twice over a host the first pass already put back.
        self.assertEqual(preamble.count("    trap - ERR\n"), 1)
        self.assertEqual(preamble.count('compensate_remote_worker "$exit_code" ||\n'), 1)

    def test_the_error_trap_routes_through_the_handler(self):
        preamble = signal_compensation.signal_preamble()
        for line in ("trap 'handle_signal HUP' HUP\n",
                     "trap 'handle_signal INT' INT\n",
                     "trap 'handle_signal TERM' TERM\n",
                     'trap \'handle_error "$?"\' ERR\n',
                     "trap 'cleanup_temp_and_secrets' EXIT\n"):
            with self.subTest(trap=line.strip()):
                self.assertIn(line, preamble)
        # The ERR trap names the handler, never the compensator: the handler is
        # the one place that knows a compensation may already have run.
        for line in preamble.splitlines():
            if line.startswith("trap "):
                self.assertNotIn("compensate_remote_worker", line)

    def test_the_library_renames_the_compensator_once(self):
        library = signal_compensation.library()
        self.assertEqual(library.count("shipped_compensate_remote_worker() {\n"), 1)
        self.assertEqual(
            [line for line in library.splitlines() if line.startswith("compensate_remote_worker")],
            [],
        )
        # The rename must not leave the shipped body behind a second time: the
        # first rendering of this module emitted it with no signature at all, and
        # its `local` lines then ran at top level.
        self.assertEqual(library.count('    local exit_code="${1:-1}"\n'), 1)

    def test_the_compensator_takes_the_two_roots_and_names_the_image(self):
        body = signal_compensation.compensation_body()
        self.assertIn('    local state_root="${WORKER_STATE_ROOT:-/var/lib/gowave-auto-nginx}"\n',
                      body)
        self.assertIn('    local host_root="${WORKER_HOST_ROOT:-/}"\n', body)
        # The image is named from this transaction, as the capture named it: the
        # ambient ACME_TX_ID is empty on a fresh install, so a default lookup
        # would read an image no transaction wrote.
        self.assertIn('restore_worker_targets_before_image \\\n'
                      '        "$host_root" "$(worker_targets_before_image "$state_root" '
                      '"$_ACME_TX_ID")" ||\n'
                      '        rollback_failed=1\n', body)

    def test_a_contour_without_a_worker_is_blocked_not_passed(self):
        product = _LocalProduct(worker=False)
        with self.assertRaises(CaseBlocked):
            DRIVERS["multi-node"](product, object())


class TestSignalCompensationDamage(unittest.TestCase):
    """Each clause is damaged on its own and the case refuses for that reason."""

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory(prefix="gowave-signal-damage-")
        self.addCleanup(self._directory.cleanup)
        self.workdir = Path(self._directory.name)

    def assert_refused(self, damage, topology_name="multi-node"):
        _, refusal = run_case(topology_name, damage=damage, workdir=self.workdir)
        self.assertIsNotNone(refusal, f"{damage} did not make TXN-01 refuse")
        self.assertIn(EXPECTED_REFUSALS[damage], refusal)

    def test_a_term_handler_that_skips_the_compensator_is_refused(self):
        self.assert_refused("term-handler-skips-compensation")

    def test_a_hup_handler_that_skips_the_compensator_is_refused(self):
        self.assert_refused("hup-handler-skips-compensation", "aio")

    def test_an_int_handler_that_skips_the_compensator_is_refused(self):
        self.assert_refused("int-handler-skips-compensation")

    def test_a_handler_that_compensates_outside_the_guard_is_refused(self):
        self.assert_refused("handler-compensates-outside-the-guard")

    def test_a_signal_that_stops_nothing_is_refused(self):
        self.assert_refused("signal-stops-nothing")

    def test_a_journal_that_is_never_written_is_refused(self):
        self.assert_refused("journal-is-never-written")

    def test_a_restore_that_skips_pre_existing_paths_is_refused(self):
        self.assert_refused("restore-skips-pre-existing-paths")

    def test_a_restore_that_writes_a_fixed_mode_is_refused(self):
        self.assert_refused("restore-writes-a-fixed-mode")

    def test_a_restore_that_trusts_a_write_it_did_not_read_back_is_refused(self):
        self.assert_refused("restore-trusts-a-write-it-did-not-read-back")

    def test_a_restore_that_trusts_a_changed_copy_is_refused(self):
        self.assert_refused("restore-trusts-a-changed-copy")

    def test_an_interruption_that_exits_zero_is_refused(self):
        self.assert_refused("signal-exits-zero")

    def test_a_cleanup_that_keeps_the_temp_file_is_refused(self):
        self.assert_refused("cleanup-keeps-the-payload-temp-file")

    def test_a_compensation_that_removes_the_journal_is_refused(self):
        self.assert_refused("compensation-removes-the-journal")


if __name__ == "__main__":
    unittest.main()
