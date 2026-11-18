#!/usr/bin/env python3
"""Suite nonroot: an interrupted Worker install is reconciled before the next one.

``HOOK-03`` is §Global Certbot Deploy Hook Ownership in
``openspec/changes/podman-full-e2e/specs/podman-e2e/spec.md``: a deployment
terminated by SIGKILL, a kernel panic or power loss after it wrote its
transaction journal is discovered by the next authenticated entrypoint, which
reconciles it before accepting a new mutation — and refuses the new operation,
retaining the journal, when the recovery cannot be verified.

The journal is ``worker_transaction_journal`` and ``worker_journal_action`` in
``gowave-node-auto.sh``, written by ``record_worker_transaction_journal`` before
the first mutation and closed by ``mark_worker_transaction_state installed``
after the install verified itself. ``reconcile_worker_transaction_journals`` is
the reader: it restores a ``started`` transaction from its own before-images and
releases its directory, and it retains anything it cannot verify.

The case drives those functions over a scratch root, so it decides their verdict
and the bytes they leave on disk. Each clause is damaged on its own — a journal
readable by every user, one that names no transaction, a mark that records
nothing, a reopen that is allowed, a reconcile that undoes a finalized install,
one that skips the Worker before-image, one that leaves the journal behind, one
that trusts an unreadable journal, one that preserves nothing, one that ignores
the firewall image, and one that reconciles the transaction it was invoked for —
so every assertion is seen to fail for the reason it protects.
"""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import catalog, worker_journal  # noqa: E402
from tools.podman_e2e.runner import CaseBlocked  # noqa: E402

TOPOLOGIES = ("aio", "multi-node")
DRIVERS = {
    "aio": worker_journal.case_panel_journal_is_reconciled,
    "multi-node": worker_journal.case_worker_journal_is_reconciled,
}

#: The journal block is spliced into the top-level library, the payload and the
#: rollback script, so a damage rewrites every copy — and the copies stay
#: byte-identical.
BLOCK_COPIES = 3

#: What each damage is meant to make the case say, so a probe that went red on
#: an unrelated assertion is not read as a held clause.
EXPECTED_REFUSALS = {
    "journal-names-no-transaction":
        "the transaction journal was not written in the transaction's own recovery directory",
    "journal-is-world-readable": "the transaction journal is readable by every user",
    "mark-records-nothing": "the verified end of the install did not mark the journal installed",
    "reopen-is-allowed": "a new install reopened a transaction that had already installed",
    "installed-journal-is-reconciled":
        "a journal that installed but was never finalized was released, or its install was undone",
    "reconcile-skips-the-worker-image":
        "the reconcile did not put back the bytes the interrupted transaction found",
    "reconcile-leaves-the-journal":
        "a reconciled transaction left its journal behind",
    "reconcile-preserves-nothing":
        "the reconcile removed a path no record proves the interrupted transaction wrote",
    "reconcile-trusts-an-unreadable-journal":
        "an unreadable journal was ignored instead of refusing the new install",
    "reconcile-ignores-the-firewall-image":
        "a firewall before-image that cannot be restored was ignored",
    "reconcile-reconciles-its-own-transaction":
        "the rollback entrypoint reconciled the transaction it was invoked for",
}


class _LocalHost:
    """The container's shell, answered by this machine: same script, same bash."""

    def host_script(self, script, timeout=180):
        return subprocess.run(
            ["bash", "-s"], input=script, capture_output=True, text=True, timeout=timeout,
        )


class _LocalPodman:
    def exec_bash(self, name, script, check=True, input_text=None, timeout=180):
        return subprocess.run(
            ["bash", "-s"], input=script, capture_output=True, text=True, timeout=timeout,
        )


class _LocalProduct:
    def __init__(self, worker=True):
        self.host_script = _LocalHost().host_script
        self.podman = _LocalPodman()
        self.topology = (
            type("Topology", (), {"worker_name": "worker-1"})() if worker else None
        )


def _rewritten(source: Path, old: str, new: str, expected: int) -> str:
    """The file's text with exactly ``expected`` occurrences rewritten."""
    body = source.read_text(encoding="utf-8")
    assert body.count(old) == expected, f"{old!r} occurs {body.count(old)} times, not {expected}"
    return body.replace(old, new)


def run_case(topology_name, damage=None, workdir=None):
    """Run one contour, optionally with one damaged clause of the product."""
    product = _LocalProduct(worker=topology_name == "multi-node")
    patchers = []
    if damage:
        broken = Path(workdir) / "gowave-node-auto-damaged.sh"
        broken.write_text(_damage_source(damage), encoding="utf-8")
        patchers.append(mock.patch.object(worker_journal, "WORKER_INSTALLER", broken))
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
    """The product with one clause of the journal functions rewritten."""
    source = worker_journal.WORKER_INSTALLER

    if damage == "journal-names-no-transaction":
        return _rewritten(
            source,
            '    printf \'%s\\n\' "${root%/}/recovery/${transaction}/transaction-journal.json"\n',
            '    printf \'%s\\n\' "${root%/}/recovery/transaction-journal.json"\n',
            BLOCK_COPIES,
        )
    if damage == "journal-is-world-readable":
        return _rewritten(
            source,
            "        os.fchmod(handle, 0o600)\n",
            "        os.fchmod(handle, 0o644)\n",
            BLOCK_COPIES,
        )
    if damage == "mark-records-nothing":
        return _rewritten(
            source,
            '    if not os.path.lexists(journal):\n        raise SystemExit(0)\n    read()\n    store(journal_state)\n',
            '    if not os.path.lexists(journal):\n        raise SystemExit(0)\n    read()\n',
            BLOCK_COPIES,
        )
    if damage == "reopen-is-allowed":
        return _rewritten(
            source,
            '    if state == "started" and os.path.lexists(journal) and read().get("state") == "installed":\n'
            '        refuse("Worker transaction journal " + journal + " is already installed; '
            'refusing to reopen it.")\n',
            '    if False:\n'
            '        refuse("Worker transaction journal " + journal + " is already installed; '
            'refusing to reopen it.")\n',
            BLOCK_COPIES,
        )
    if damage == "installed-journal-is-reconciled":
        return _rewritten(
            source,
            '        if [[ "$state" != "started" ]]; then\n',
            "        if false; then\n",
            BLOCK_COPIES,
        )
    if damage == "reconcile-skips-the-worker-image":
        return _rewritten(
            source,
            '        if [[ -d "$transaction_dir/worker-targets-before-image" ]] &&\n',
            "        if false &&\n",
            BLOCK_COPIES,
        )
    if damage == "reconcile-leaves-the-journal":
        return _rewritten(
            source,
            '        if ! worker_journal_action remove "$journal" "$transaction"; then\n',
            "        if false; then\n",
            BLOCK_COPIES,
        )
    if damage == "reconcile-preserves-nothing":
        return _rewritten(
            source,
            "    if preserved:\n",
            "    if False:\n",
            BLOCK_COPIES,
        )
    if damage == "reconcile-trusts-an-unreadable-journal":
        return _rewritten(
            source,
            '        refuse("Worker transaction journal " + journal + " is not readable JSON.")\n',
            '        return {"state": "started"}\n',
            BLOCK_COPIES,
        )
    if damage == "reconcile-ignores-the-firewall-image":
        return _rewritten(
            source,
            '        if [[ -d "$transaction_dir/firewall-before-image" ]] &&\n',
            "        if false &&\n",
            BLOCK_COPIES,
        )
    if damage == "reconcile-reconciles-its-own-transaction":
        return _rewritten(
            source,
            '        [[ -n "$skip" && "$transaction" == "$skip" ]] && continue\n',
            '        [[ -n "$skip" && "$transaction" == "$skip" ]] || true\n',
            BLOCK_COPIES,
        )
    raise AssertionError(f"unknown damage {damage!r}")


class TestWorkerJournalRegistration(unittest.TestCase):
    """The id is registered on both contours, each with the driver it runs."""

    def test_the_id_is_registered_on_both_contours(self):
        registry = catalog.driver_registry()
        self.assertIn(worker_journal.CASE_ID, registry)
        self.assertEqual(set(registry[worker_journal.CASE_ID]), set(TOPOLOGIES))
        for name, function in DRIVERS.items():
            self.assertEqual(
                registry[worker_journal.CASE_ID][name]["driver"],
                f"worker_journal:{function.__name__}",
            )

    def test_the_catalog_entry_is_what_the_registry_derives(self):
        registry = catalog.driver_registry()
        entries = {entry["id"]: entry for entry in catalog.load_catalog()["cases"]}
        entry = entries[worker_journal.CASE_ID]
        self.assertEqual(entry["driver_status"], "implemented")
        self.assertEqual(entry["drivers"], registry[worker_journal.CASE_ID])
        self.assertEqual(sorted(entry["topology"]), sorted(TOPOLOGIES))


class TestWorkerJournalCase(unittest.TestCase):
    """Both halves hold on this tree, and each reports the facts it decides."""

    def test_the_journal_holds_on_both_contours(self):
        for name in TOPOLOGIES:
            with self.subTest(topology=name):
                facts, refusal = run_case(name)
                self.assertIsNone(refusal)
                self.assertEqual(len(facts), len(worker_journal.EVIDENCE))
                self.assertTrue(all(facts.values()), facts)

    def test_the_evidence_set_is_what_the_catalog_records(self):
        registry = catalog.driver_registry()
        for name in TOPOLOGIES:
            with self.subTest(topology=name):
                facts, refusal = run_case(name)
                self.assertIsNone(refusal)
                self.assertEqual(
                    sorted(facts), registry[worker_journal.CASE_ID][name]["evidence"])

    def test_all_three_copies_of_the_block_agree(self):
        body = worker_journal.WORKER_INSTALLER.read_text(encoding="utf-8")
        self.assertEqual(body.count("<<'JOURNAL_PY'\n"), BLOCK_COPIES)
        reference = worker_journal.journal_block_body()
        self.assertIn("def store(state):", reference)
        self.assertIn("def remove():", reference)
        self.assertEqual(body.count(reference), BLOCK_COPIES)

    def test_the_journal_is_written_before_the_first_mutation(self):
        body = worker_journal.WORKER_INSTALLER.read_text(encoding="utf-8")
        self.assertEqual(body.count("    record_worker_transaction_journal \"$_ACME_TX_ID\" || return 1\n"), 1)
        written = body.index("    record_worker_transaction_journal \"$_ACME_TX_ID\" || return 1\n")
        captured = body.index('    record_worker_targets_before_image \\\n')
        # The journal names the image its reconcile restores from, so the image
        # comes first — and both come before the first path is touched.
        self.assertLess(captured, written)
        for later in ("    setup_system_prereqs </dev/null\n",
                      "    configure_host_security </dev/null\n",
                      "    configure_firewall </dev/null\n",
                      "    unpack_cover_reality </dev/null\n",
                      "    configure_edge_nginx </dev/null\n",
                      "    SECRET_KEY=\"$_NODE_SECRET_KEY\" run_upstream_node_installer </dev/null\n"):
            with self.subTest(mutation=later):
                self.assertLess(written, body.index(later))
        self.assertEqual(body.count("    reconcile_worker_transaction_journals || return 1\n"), 1)
        self.assertLess(
            body.index("    reconcile_worker_transaction_journals || return 1\n"),
            written,
        )

    def test_the_install_closes_its_journal_before_it_stops_compensating(self):
        body = worker_journal.WORKER_INSTALLER.read_text(encoding="utf-8")
        marked = '    mark_worker_transaction_state installed "$_ACME_TX_ID" || return 1\n'
        self.assertEqual(body.count(marked), 1)
        self.assertLess(
            body.index("    record_worker_mutation_targets\n"),
            body.index(marked),
        )
        self.assertLess(
            body.index(marked),
            body.index("    # Disable ERR compensation trap on verified success\n"),
        )

    def test_the_rollback_entrypoint_skips_its_own_transaction(self):
        body = worker_journal.WORKER_INSTALLER.read_text(encoding="utf-8")
        call = 'reconcile_worker_transaction_journals "${ACME_TX_ID:-}" || rollback_failed=1\n'
        self.assertEqual(body.count(call), 1)
        self.assertLess(body.index("rollback_failed=0\n"), body.index(call))
        # The rollback script reconciles before it restores, and it restores
        # unconditionally: the script is run on the host it rolls back, so it is
        # the one caller with no host root to carry.
        after = body.index(call)
        self.assertLess(
            after,
            body.index("restore_worker_targets_before_image || rollback_failed=1\n", after),
        )

    def test_a_run_that_captured_nothing_is_not_compensated(self):
        body = worker_journal.WORKER_INSTALLER.read_text(encoding="utf-8")
        self.assertEqual(body.count("No Worker before-image was captured; nothing to compensate."), 1)
        self.assertLess(
            body.index('    if [[ -z "${_ACME_TX_ID:-}" ]] ||\n'),
            body.index("    # 1. Stop and remove GoWave Node and Xray systemd services\n"),
        )

    def test_a_contour_without_a_worker_is_blocked_not_passed(self):
        product = _LocalProduct(worker=False)
        with self.assertRaises(CaseBlocked):
            DRIVERS["multi-node"](product, object())


class TestWorkerJournalDamage(unittest.TestCase):
    """Each clause is damaged on its own and the case refuses for that reason."""

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory(prefix="gowave-journal-damage-")
        self.addCleanup(self._directory.cleanup)
        self.workdir = Path(self._directory.name)

    def assert_refused(self, damage, topology_name="multi-node"):
        _, refusal = run_case(topology_name, damage=damage, workdir=self.workdir)
        self.assertIsNotNone(refusal, f"{damage} did not make HOOK-03 refuse")
        self.assertIn(EXPECTED_REFUSALS[damage], refusal)

    def test_a_journal_that_names_no_transaction_is_refused(self):
        self.assert_refused("journal-names-no-transaction")

    def test_a_journal_readable_by_every_user_is_refused(self):
        self.assert_refused("journal-is-world-readable", "aio")

    def test_a_mark_that_records_nothing_is_refused(self):
        self.assert_refused("mark-records-nothing")

    def test_a_reopen_of_an_installed_transaction_is_refused(self):
        self.assert_refused("reopen-is-allowed")

    def test_a_reconcile_that_undoes_a_finalized_install_is_refused(self):
        self.assert_refused("installed-journal-is-reconciled")

    def test_a_reconcile_that_skips_the_worker_image_is_refused(self):
        self.assert_refused("reconcile-skips-the-worker-image")

    def test_a_reconcile_that_leaves_the_journal_behind_is_refused(self):
        self.assert_refused("reconcile-leaves-the-journal")

    def test_a_reconcile_that_preserves_nothing_is_refused(self):
        self.assert_refused("reconcile-preserves-nothing")

    def test_a_reconcile_that_trusts_an_unreadable_journal_is_refused(self):
        self.assert_refused("reconcile-trusts-an-unreadable-journal")

    def test_a_reconcile_that_ignores_the_firewall_image_is_refused(self):
        self.assert_refused("reconcile-ignores-the-firewall-image")

    def test_a_reconcile_of_its_own_transaction_is_refused(self):
        self.assert_refused("reconcile-reconciles-its-own-transaction")


if __name__ == "__main__":
    unittest.main()
