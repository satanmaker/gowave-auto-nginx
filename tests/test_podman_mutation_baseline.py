#!/usr/bin/env python3
"""Suite nonroot: compensation restores every transaction-owned resource.

``OWN-04`` is the aggregate of §Complete Mutation-Target Baseline and Resource
Ownership: after a later deployment step fails, every path the transaction
created is removed only while it is still what the install wrote, every path
that was here before is put back with its recorded content and metadata, and
anything changed after the write — or that no record can prove — is preserved
with the cleanup reported as incomplete.

The before-image is ``worker_targets_image capture`` and the way back is
``worker_targets_image restore``, both in ``gowave-node-auto.sh``; the record the
restore compares a created path against is ``record_worker_mutation_targets``.
The case drives all of them over a scratch root, so it decides the functions'
verdict and the bytes they leave on disk. Each clause is damaged on its own — a
capture that forgets metadata, one that drops a link's target, one that calls a
pre-existing path absent, one readable by every user, one that overwrites an
existing image, a restore that removes a path changed after the write, one that
removes a path no record names, one that trusts a missing image, and one that
reports success while it preserved something — so every assertion is seen to
fail for the reason it protects.
"""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import catalog, mutation_baseline  # noqa: E402
from tools.podman_e2e.runner import CaseBlocked  # noqa: E402

TOPOLOGIES = ("aio", "multi-node")
DRIVERS = {
    "aio": mutation_baseline.case_panel_mutation_targets_are_restored,
    "multi-node": mutation_baseline.case_worker_mutation_targets_are_restored,
}

#: The block is spliced twice into the payload and once into the rollback
#: script, so a damage rewrites every copy — and the copies stay byte-identical.
BLOCK_COPIES = 3

#: What each damage is meant to make the case say, so a probe that went red on
#: an unrelated assertion is not read as a held clause.
EXPECTED_REFUSALS = {
    "capture-records-no-metadata":
        "the before-image does not record the mode and owner it restores",
    "capture-records-no-link-target":
        "the before-image does not record where the link it restores pointed",
    "capture-calls-a-pre-existing-path-absent":
        "a path that was here is recorded as absent",
    "capture-is-world-readable": "the Worker targets before-image is readable by every user",
    "capture-overwrites-an-existing-image":
        "a second capture overwrote the state the first one holds",
    "restore-removes-a-changed-path":
        "the restore removed a path that changed after this install wrote it",
    "restore-removes-an-unrecorded-path":
        "the restore removed a path no record proves this install wrote",
    "restore-trusts-a-missing-image":
        "a rollback with no before-image removed the paths this install wrote",
    "restore-reports-success-while-preserving":
        "the restore reported success while it preserved a path",
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
        patchers.append(mock.patch.object(mutation_baseline, "WORKER_INSTALLER", broken))
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
    """The product with one clause of the before-image functions rewritten."""
    source = mutation_baseline.WORKER_INSTALLER

    if damage == "capture-records-no-metadata":
        return _rewritten(
            source,
            '                "mode": state.st_mode & 0o7777,\n'
            '                "owner": [state.st_uid, state.st_gid],\n',
            "",
            BLOCK_COPIES,
        )
    if damage == "capture-records-no-link-target":
        return _rewritten(
            source,
            '                data["targets"][target] = {"state": "symlink", "target": os.readlink(path)}\n',
            '                data["targets"][target] = {"state": "symlink", "target": ""}\n',
            BLOCK_COPIES,
        )
    if damage == "capture-calls-a-pre-existing-path-absent":
        return _rewritten(
            source,
            '            if not os.path.lexists(path):\n                data["targets"][target] = {"state": "absent"}\n',
            '            if True:\n                data["targets"][target] = {"state": "absent"}\n                continue\n',
            BLOCK_COPIES,
        )
    if damage == "capture-is-world-readable":
        return _rewritten(
            source,
            "        write_atomic(MANIFEST, document, 0o600)\n",
            "        write_atomic(MANIFEST, document, 0o644)\n",
            BLOCK_COPIES,
        )
    if damage == "capture-overwrites-an-existing-image":
        return _rewritten(
            source,
            "    if os.path.lexists(image):\n"
            '        fail("Worker targets before-image " + image + " already exists; '
            'refusing to overwrite the state it holds.")\n',
            "    if False:\n"
            '        fail("Worker targets before-image " + image + " already exists; '
            'refusing to overwrite the state it holds.")\n',
            BLOCK_COPIES,
        )
    if damage == "restore-removes-a-changed-path":
        return _rewritten(
            source,
            '    if not isinstance(entry, dict) or entry != current:\n'
            '        keep(path, "it changed after this transaction wrote it")\n'
            "        return\n",
            '    if not isinstance(entry, dict):\n'
            '        keep(path, "it changed after this transaction wrote it")\n'
            "        return\n",
            BLOCK_COPIES,
        )
    if damage == "restore-removes-an-unrecorded-path":
        return _rewritten(
            source,
            "            if entries is None:\n",
            "            if False:\n",
            BLOCK_COPIES,
        )
    if damage == "restore-trusts-a-missing-image":
        return _rewritten(
            source,
            "    if not os.path.isfile(MANIFEST) or os.path.islink(MANIFEST):\n",
            "    if False:\n",
            BLOCK_COPIES,
        )
    if damage == "restore-reports-success-while-preserving":
        return _rewritten(
            source,
            "    if preserved:\n",
            "    if False:\n",
            BLOCK_COPIES,
        )
    raise AssertionError(f"unknown damage {damage!r}")


class TestMutationBaselineRegistration(unittest.TestCase):
    """The id is registered on both contours, each with the driver it runs."""

    def test_the_id_is_registered_on_both_contours(self):
        registry = catalog.driver_registry()
        self.assertIn(mutation_baseline.CASE_ID, registry)
        self.assertEqual(set(registry[mutation_baseline.CASE_ID]), set(TOPOLOGIES))
        for name, function in DRIVERS.items():
            self.assertEqual(
                registry[mutation_baseline.CASE_ID][name]["driver"],
                f"mutation_baseline:{function.__name__}",
            )

    def test_the_catalog_entry_is_what_the_registry_derives(self):
        registry = catalog.driver_registry()
        entries = {entry["id"]: entry for entry in catalog.load_catalog()["cases"]}
        entry = entries[mutation_baseline.CASE_ID]
        self.assertEqual(entry["driver_status"], "implemented")
        self.assertEqual(entry["drivers"], registry[mutation_baseline.CASE_ID])
        self.assertEqual(sorted(entry["topology"]), sorted(TOPOLOGIES))


class TestMutationBaselineCase(unittest.TestCase):
    """Both halves hold on this tree, and each reports the facts it decides."""

    def test_the_before_image_holds_on_both_contours(self):
        for name in TOPOLOGIES:
            with self.subTest(topology=name):
                facts, refusal = run_case(name)
                self.assertIsNone(refusal)
                self.assertEqual(len(facts), len(mutation_baseline.EVIDENCE))
                self.assertTrue(all(facts.values()), facts)

    def test_the_evidence_set_is_what_the_catalog_records(self):
        registry = catalog.driver_registry()
        for name in TOPOLOGIES:
            with self.subTest(topology=name):
                facts, refusal = run_case(name)
                self.assertIsNone(refusal)
                self.assertEqual(
                    sorted(facts), registry[mutation_baseline.CASE_ID][name]["evidence"])

    def test_all_three_copies_of_the_block_agree(self):
        body = mutation_baseline.WORKER_INSTALLER.read_text(encoding="utf-8")
        self.assertEqual(body.count("<<'WORKER_TARGETS_PY'\n"), BLOCK_COPIES)
        reference = mutation_baseline.block_body()
        self.assertIn("def capture():", reference)
        self.assertIn("def restore():", reference)
        self.assertEqual(body.count(reference), BLOCK_COPIES)

    def test_the_image_is_taken_before_the_first_mutation_and_used_by_both_rollbacks(self):
        body = mutation_baseline.WORKER_INSTALLER.read_text(encoding="utf-8")
        capture = body.index('    record_worker_targets_before_image \\\n')
        for later in ("    setup_system_prereqs </dev/null\n",
                      "    configure_host_security </dev/null\n",
                      "    configure_firewall </dev/null\n",
                      "    configure_edge_nginx \"$_WORKER_LIVE_DIR\" \"$_REALITY_LIVE_DIR\" \"${_VISION_LIVE_DIR:-}\" </dev/null\n",
                      "    SECRET_KEY=\"$_NODE_SECRET_KEY\" run_upstream_node_installer </dev/null\n"):
            with self.subTest(mutation=later):
                self.assertLess(capture, body.index(later))
        self.assertEqual(body.count("restore_worker_targets_before_image || rollback_failed=1\n"), 1)
        # The compensator restores into the host root the transaction described,
        # which is the host itself for a real run, and names the before-image
        # from that same transaction; the standalone rollback script keeps its
        # own unconditional call, so both rollbacks still restore.
        self.assertEqual(
            body.count('restore_worker_targets_before_image \\\n'
                       '        "$host_root" "$(worker_targets_before_image "$state_root" '
                       '"$_ACME_TX_ID")" ||\n'
                       '        rollback_failed=1\n'), 1)
        self.assertNotIn("rm -rf /opt/gowave-node", body)
        self.assertNotIn("rm -f /usr/local/bin/gowave-node", body)

    def test_the_image_is_named_by_the_transaction_it_belongs_to(self):
        body = mutation_baseline.WORKER_INSTALLER.read_text(encoding="utf-8")
        self.assertEqual(body.count("    record_worker_targets_before_image \\\n"), 1)
        self.assertIn(
            '        "/" "$(worker_targets_before_image "/var/lib/gowave-auto-nginx" '
            '"$_ACME_TX_ID")" || return 1\n',
            body,
        )
        # The record the restore compares a created path against is the one the
        # install writes after it has verified itself, so a path it never wrote
        # stays unproven and is preserved.
        self.assertEqual(body.count("    record_worker_mutation_targets\n"), 1)

    def test_a_contour_without_a_worker_is_blocked_not_passed(self):
        product = _LocalProduct(worker=False)
        with self.assertRaises(CaseBlocked):
            DRIVERS["multi-node"](product, object())


class TestMutationBaselineDamage(unittest.TestCase):
    """Each clause is damaged on its own and the case refuses for that reason."""

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory(prefix="gowave-targets-damage-")
        self.addCleanup(self._directory.cleanup)
        self.workdir = Path(self._directory.name)

    def assert_refused(self, damage, topology_name="multi-node"):
        _, refusal = run_case(topology_name, damage=damage, workdir=self.workdir)
        self.assertIsNotNone(refusal, f"{damage} did not make OWN-04 refuse")
        self.assertIn(EXPECTED_REFUSALS[damage], refusal)

    def test_a_capture_that_records_no_metadata_is_refused(self):
        self.assert_refused("capture-records-no-metadata")

    def test_a_capture_that_drops_a_link_target_is_refused(self):
        self.assert_refused("capture-records-no-link-target")

    def test_a_capture_that_calls_a_pre_existing_path_absent_is_refused(self):
        self.assert_refused("capture-calls-a-pre-existing-path-absent")

    def test_a_capture_readable_by_every_user_is_refused(self):
        self.assert_refused("capture-is-world-readable", "aio")

    def test_a_capture_that_overwrites_an_image_is_refused(self):
        self.assert_refused("capture-overwrites-an-existing-image")

    def test_a_restore_that_removes_a_changed_path_is_refused(self):
        self.assert_refused("restore-removes-a-changed-path")

    def test_a_restore_that_removes_an_unrecorded_path_is_refused(self):
        self.assert_refused("restore-removes-an-unrecorded-path")

    def test_a_restore_that_trusts_a_missing_image_is_refused(self):
        self.assert_refused("restore-trusts-a-missing-image")

    def test_a_restore_that_reports_success_while_preserving_is_refused(self):
        self.assert_refused("restore-reports-success-while-preserving")


if __name__ == "__main__":
    unittest.main()
