#!/usr/bin/env python3
"""Suite nonroot: a Worker path this install did not write is not its target.

``OWN-02`` is the container half of §Complete Mutation-Target Baseline and
Resource Ownership's sentence about pre-existing Worker unit, binary and
managed webroot paths: the runner rejects them unless a complete ownership
record proves the object belongs to this run. The guard lives in
``gowave-node-auto.sh`` as ``verify_worker_mutation_targets_preflight`` and its
writer as ``record_worker_mutation_targets``; the case drives both, sliced out
of the product, over a scratch root.

Each clause is damaged on its own — a guard that adopts a symlink, one that
ignores the digest, one that adopts a foreign directory, one that ignores the
target a recorded link points at, a refusal that does not name the path, a
record that forgets files, one that forgets links, a guard that trusts a record
claiming nothing, and a record readable by every user — so every assertion is
seen to fail for the reason it protects.
"""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import catalog, ownership_targets  # noqa: E402
from tools.podman_e2e.runner import CaseBlocked  # noqa: E402

TOPOLOGIES = ("aio", "multi-node")
DRIVERS = {
    "aio": ownership_targets.case_panel_mutation_targets_are_not_adopted,
    "multi-node": ownership_targets.case_worker_mutation_targets_are_not_adopted,
}

#: What each damage is meant to make the case say, so a probe that went red on
#: an unrelated assertion is not read as a held clause.
EXPECTED_REFUSALS = {
    "preflight-adopts-a-symlink": "a symlink at a managed path was adopted as the file",
    "preflight-ignores-the-digest": "a recorded file whose bytes changed was adopted anyway",
    "preflight-accepts-a-foreign-directory":
        "a pre-existing directory was adopted instead of refused",
    "preflight-names-no-path": "the refusal does not name the path it refused",
    "record-forgets-files": "the record this install wrote does not adopt its own file",
    "preflight-trusts-an-unclaimed-record":
        "a record that does not claim this product created anything was trusted",
    "record-is-world-readable": "the ownership record is readable by every user",
    "preflight-ignores-the-link-target":
        "a recorded symlink re-pointed elsewhere was adopted",
    "record-forgets-links": "a symlink this install wrote was refused as a foreign object",
}


class _LocalHost:
    """The container's shell, answered by this machine: same script, same bash."""

    def host_script(self, script, timeout=120):
        return subprocess.run(
            ["bash", "-s"], input=script, capture_output=True, text=True, timeout=timeout,
        )


class _LocalPodman:
    def exec_bash(self, name, script, check=True, input_text=None, timeout=120):
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
        patchers.append(mock.patch.object(ownership_targets, "WORKER_INSTALLER", broken))
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
    """The product with one clause of the guard or the writer rewritten."""
    source = ownership_targets.WORKER_INSTALLER

    if damage == "preflight-adopts-a-symlink":
        return _rewritten(
            source,
            "    if os.path.islink(path):\n"
            "        # The upstream installer links",
            "    if False:\n"
            "        # The upstream installer links",
            2,
        )
    if damage == "preflight-ignores-the-digest":
        return _rewritten(
            source,
            'entry.get("kind") == "file" and entry.get("sha256") == current',
            'entry.get("kind") == "file" and entry.get("sha256") is not None',
            2,
        )
    if damage == "preflight-accepts-a-foreign-directory":
        return _rewritten(
            source,
            '        if isinstance(entry, dict) and entry.get("kind") == "directory":\n'
            "            continue\n",
            "        if True:\n            continue\n",
            2,
        )
    if damage == "preflight-names-no-path":
        return _rewritten(
            source,
            '        "Error: Pre-existing unowned Worker " + what + " " + path + ". Refusing to "',
            '        "Error: Pre-existing unowned Worker " + what + ". Refusing to "',
            2,
        )
    if damage == "record-forgets-files":
        return _rewritten(
            source,
            "    elif os.path.isfile(path):\n"
            '        data["targets"][target] = {"kind": "file", "sha256": digest(path)}\n',
            "    elif False:\n"
            '        data["targets"][target] = {"kind": "file", "sha256": digest(path)}\n',
            2,
        )
    if damage == "preflight-trusts-an-unclaimed-record":
        return _rewritten(
            source,
            '    if not isinstance(data, dict) or data.get("created_by_tx") is not True:\n'
            "        print(\n"
            '            "Error: Worker ownership record " + record + " does not claim this product created anything.",',
            "    if False:\n"
            "        print(\n"
            '            "Error: Worker ownership record " + record + " does not claim this product created anything.",',
            2,
        )
    if damage == "record-is-world-readable":
        # Anchored on the record's own temporary sibling: the transaction journal
        # writes its file with the same fchmod, and a bare anchor would damage
        # both writers.
        return _rewritten(
            source,
            'handle, temporary = tempfile.mkstemp(dir=directory, prefix=".worker-ownership.", suffix=".tmp")\n'
            "try:\n"
            "    os.fchmod(handle, 0o600)\n",
            'handle, temporary = tempfile.mkstemp(dir=directory, prefix=".worker-ownership.", suffix=".tmp")\n'
            "try:\n"
            "    os.fchmod(handle, 0o644)\n",
            2,
        )
    if damage == "preflight-ignores-the-link-target":
        return _rewritten(
            source,
            'entry.get("kind") == "symlink" and entry.get("target") == os.readlink(path)',
            'entry.get("kind") == "symlink" and entry.get("target") is not None',
            2,
        )
    if damage == "record-forgets-links":
        return _rewritten(
            source,
            '        data["targets"][target] = {"kind": "symlink", "target": os.readlink(path)}\n',
            "        continue\n",
            2,
        )
    raise AssertionError(f"unknown damage {damage!r}")


class TestOwnershipTargetsRegistration(unittest.TestCase):
    """The id is registered on both contours, each with the driver it runs."""

    def test_the_id_is_registered_on_both_contours(self):
        registry = catalog.driver_registry()
        self.assertIn(ownership_targets.CASE_ID, registry)
        self.assertEqual(set(registry[ownership_targets.CASE_ID]), set(TOPOLOGIES))
        for name, function in DRIVERS.items():
            self.assertEqual(
                registry[ownership_targets.CASE_ID][name]["driver"],
                f"ownership_targets:{function.__name__}",
            )

    def test_the_catalog_entry_is_what_the_registry_derives(self):
        registry = catalog.driver_registry()
        entries = {entry["id"]: entry for entry in catalog.load_catalog()["cases"]}
        entry = entries[ownership_targets.CASE_ID]
        self.assertEqual(entry["driver_status"], "implemented")
        self.assertEqual(entry["drivers"], registry[ownership_targets.CASE_ID])
        self.assertEqual(sorted(entry["topology"]), sorted(TOPOLOGIES))


class TestOwnershipTargetsCase(unittest.TestCase):
    """Both halves hold on this tree, and each reports the facts it decides."""

    def test_the_guard_and_the_record_hold_on_both_contours(self):
        for name in TOPOLOGIES:
            with self.subTest(topology=name):
                facts, refusal = run_case(name)
                self.assertIsNone(refusal)
                self.assertEqual(len(facts), len(ownership_targets.EVIDENCE))
                self.assertTrue(all(facts.values()), facts)

    def test_the_evidence_set_is_what_the_catalog_records(self):
        registry = catalog.driver_registry()
        for name in TOPOLOGIES:
            with self.subTest(topology=name):
                facts, refusal = run_case(name)
                self.assertIsNone(refusal)
                self.assertEqual(
                    sorted(facts), registry[ownership_targets.CASE_ID][name]["evidence"])

    def test_the_guard_keeps_every_payload_copy_in_step(self):
        # Two copies in the payload, plus a third for each helper the standalone
        # rollback script calls: it is streamed on its own, so it cannot reach
        # the payload's definitions and has to carry its own.
        body = ownership_targets.WORKER_INSTALLER.read_text(encoding="utf-8")
        start = body.index("cat <<'ROLLBACK_REMOTE_SCRIPT'")
        rollback = body[start:body.index("\nROLLBACK_REMOTE_SCRIPT\n", start)]
        for signature in ownership_targets._FUNCTION_SIGNATURES:
            with self.subTest(function=signature):
                carried = rollback.count("\n" + signature)
                self.assertIn(carried, (0, 1), signature)
                self.assertEqual(body.count("\n" + signature), 2 + carried, signature)

    def test_the_guard_runs_before_the_first_managed_path(self):
        body = ownership_targets.WORKER_INSTALLER.read_text(encoding="utf-8")
        # The confirmed-migration branch calls the guard with the adopt override;
        # both the override call and the plain call sit before any mutation.
        guard = body.index("verify_worker_mutation_targets_preflight || return 1")
        record = body.index("    record_worker_mutation_targets\n")
        for later in ("setup_system_prereqs </dev/null", "configure_host_security </dev/null",
                      "configure_firewall </dev/null", "unpack_cover_reality </dev/null",
                      "configure_edge_nginx \"$_WORKER_LIVE_DIR\" \"$_REALITY_LIVE_DIR\" \"${_VISION_LIVE_DIR:-}\" </dev/null",
                      "run_upstream_node_installer </dev/null"):
            with self.subTest(mutation=later):
                self.assertLess(guard, body.index(later))
        self.assertLess(guard, record)
        # The disarm the install reaches on success, not whichever `trap - ERR`
        # the file happens to hold first: the signal block disarms its own.
        self.assertLess(record, body.index(
            "    # Disable ERR compensation trap on verified success\n"))

    def test_a_confirmed_migration_adopts_an_unowned_regular_file(self):
        # `node reapply` with GOWAVE_MIGRATE_EXISTING=yes forwards the adopt
        # flag: a regular file this install did not record (the legacy stream
        # map) is rewritten on the operator's word, while an unconfirmed run
        # still refuses it. Symlinks and directories stay refused either way.
        script = (
            "set -u\n"
            "work=$(mktemp -d)\n"
            "trap 'rm -rf \"$work\"' EXIT\n\n"
            + ownership_targets.guard_functions()
            + "\n"
            "root=\"$work/legacy\"\n"
            "mkdir -p \"$root/etc/nginx/stream-enabled\" \"$root/var/lib\"\n"
            "printf 'legacy map\\n' > \"$root/etc/nginx/stream-enabled/gowave-worker-stream.conf\"\n"
            "printf '%s\\n' '{\"created_by_tx\": true, \"targets\": {}}' > \"$root/var/lib/ownership.json\"\n"
            "verify_worker_mutation_targets_preflight \"$root\" \"$root/var/lib/ownership.json\" >/dev/null 2>&1; printf 'plain=%s\\n' \"$?\"\n"
            "GOWAVE_ADOPT_UNOWNED=1 verify_worker_mutation_targets_preflight \"$root\" \"$root/var/lib/ownership.json\" >/dev/null 2>&1; printf 'adopt=%s\\n' \"$?\"\n"
        )
        finished = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=120)
        self.assertEqual(finished.returncode, 0, finished.stderr)
        self.assertIn("plain=1", finished.stdout)
        self.assertIn("adopt=0", finished.stdout)

    def test_a_contour_without_a_worker_is_blocked_not_passed(self):
        product = _LocalProduct(worker=False)
        with self.assertRaises(CaseBlocked):
            DRIVERS["multi-node"](product, object())


class TestOwnershipTargetsDamage(unittest.TestCase):
    """Each clause is damaged on its own and the case refuses for that reason."""

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory(prefix="gowave-targets-damage-")
        self.addCleanup(self._directory.cleanup)
        self.workdir = Path(self._directory.name)

    def assert_refused(self, damage, topology_name="multi-node"):
        _, refusal = run_case(topology_name, damage=damage, workdir=self.workdir)
        self.assertIsNotNone(refusal, f"{damage} did not make OWN-02 refuse")
        self.assertIn(EXPECTED_REFUSALS[damage], refusal)

    def test_a_guard_that_adopts_a_symlink_is_refused(self):
        self.assert_refused("preflight-adopts-a-symlink")

    def test_a_guard_that_ignores_the_digest_is_refused(self):
        self.assert_refused("preflight-ignores-the-digest")

    def test_a_guard_that_adopts_a_foreign_directory_is_refused(self):
        self.assert_refused("preflight-accepts-a-foreign-directory")

    def test_a_refusal_that_does_not_name_the_path_is_refused(self):
        self.assert_refused("preflight-names-no-path")

    def test_a_record_that_forgets_files_is_refused(self):
        self.assert_refused("record-forgets-files")

    def test_a_guard_that_trusts_an_unclaimed_record_is_refused(self):
        self.assert_refused("preflight-trusts-an-unclaimed-record")

    def test_a_record_readable_by_every_user_is_refused(self):
        self.assert_refused("record-is-world-readable", "aio")

    def test_a_guard_that_ignores_the_link_target_is_refused(self):
        self.assert_refused("preflight-ignores-the-link-target")

    def test_a_record_that_forgets_links_is_refused(self):
        self.assert_refused("record-forgets-links")


if __name__ == "__main__":
    unittest.main()
