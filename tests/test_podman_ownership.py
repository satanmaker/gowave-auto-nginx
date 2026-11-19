#!/usr/bin/env python3
"""Suite nonroot: the sysctl file each role writes is only the one it created.

``OWN-01`` is the container half of §Complete Mutation-Target Baseline and
Resource Ownership's sentence about ``/etc/sysctl.d/99-gowave-node.conf``: a host
file the install did not write is never truncated and then treated as
transaction-created. Two writers can truncate such a file — the panel's
``configure_bbr_and_mtu`` and the worker's ``configure_host_security`` — so the
case runs the shipped function on the host that carries it and reads back the
bytes, the mode and the ownership flag it leaves.

Each clause is damaged on its own — a guard that adopts a symlink, one that
adopts an empty file, one that refuses the product's own file, a writer that
drops its marker, a refusal that does not name the path, a worker that forgets
it created the file, and a worker that marks a foreign file as its own — so
every assertion is seen to fail for the reason it protects.
"""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import catalog, ownership, topology  # noqa: E402
from tools.podman_e2e.runner import CaseBlocked  # noqa: E402

TOPOLOGIES = ("aio", "multi-node")
DRIVERS = {
    "aio": ownership.case_panel_sysctl_is_not_adopted,
    "multi-node": ownership.case_worker_sysctl_is_not_adopted,
}

#: What each damage is meant to make the case say, so a probe that went red on
#: an unrelated assertion is not read as a held clause.
EXPECTED_REFUSALS = {
    "panel-adopts-a-symlink": "a symlink at the managed path was adopted as the file",
    "panel-adopts-an-empty-file": "an empty file was adopted on the strength of being empty",
    "panel-refuses-its-own-file": "the product's own file was refused",
    "panel-writes-without-the-marker":
        "the file the product created does not carry its marker",
    "panel-refusal-does-not-name-the-path": "the refusal does not name the file it refused",
    "worker-forgets-the-created-flag": "the product did not record the file it created",
    "worker-marks-a-foreign-file-as-created":
        "the unmanaged file was recorded as created by this run",
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


def run_case(topology_name, workdir, damage=None):
    """Run one contour, optionally with one damaged clause of the product."""
    product = _LocalProduct(worker=topology_name == "multi-node")
    # The panel driver sources the module from the path the container holds it
    # at; on this machine the same module lives in this checkout.
    patchers = [mock.patch.object(topology, "REPO_IN_CONTAINER", str(REPO_ROOT))]
    if damage:
        patchers = _damages(workdir, damage)
    for patcher in patchers:
        patcher.start()
    try:
        return DRIVERS[topology_name](product, object()), None
    except AssertionError as error:
        return None, str(error)
    finally:
        for patcher in reversed(patchers):
            patcher.stop()


def _panel_copy(workdir, old, new, expected, suffix):
    """A temporary repository whose panel module carries one damaged clause.

    ``configure_bbr_and_mtu`` reaches ``modules.api_client`` through the module
    root it derives from its own path, so the copy keeps that import reachable.
    """
    repo = Path(workdir) / f"repo-{suffix}"
    (repo / "modules").mkdir(parents=True)
    (repo / "modules" / "api_client.py").symlink_to(
        ownership.PANEL_SECURITY.parent / "api_client.py")
    (repo / "modules" / "security.sh").write_text(
        _rewritten(ownership.PANEL_SECURITY, old, new, expected), encoding="utf-8")
    return repo


def _damages(workdir, damage):
    """One clause of one writer edited per probe."""
    guard_symlink = '        if [[ -L "$sysctl_conf" ]] ||\n'
    #: The whole condition, so a probe that removes it leaves a valid ``if``.
    guard_block = (
        '        if [[ -L "$sysctl_conf" ]] ||\n'
        "            ! grep -qxF '# Managed by GoWave Auto NGINX' \"$sysctl_conf\" ||\n"
        "            grep -qvxF -e '# Managed by GoWave Auto NGINX' \\\n"
        "                -e 'net.ipv4.tcp_mtu_probing = 1' \\\n"
        "                -e 'net.ipv4.tcp_congestion_control = bbr' \"$sysctl_conf\"; then\n"
    )
    guard_marker = "            ! grep -qxF '# Managed by GoWave Auto NGINX' \"$sysctl_conf\" ||\n"
    marker_echo = '        echo "# Managed by GoWave Auto NGINX"\n'
    refusal = ('            echo "Error: Pre-existing unmanaged sysctl configuration at '
               '$sysctl_conf. Refusing to overwrite unmanaged host resource." >&2\n')
    created_flag = "        _SYSCTL_CREATED_BY_US=1\n"
    foreign_flag = "            _SYSCTL_CREATED_BY_US=0\n"

    if damage == "panel-adopts-a-symlink":
        repo = _panel_copy(workdir, guard_symlink, "        if false ||\n", 1, "symlink")
        return [mock.patch.object(topology, "REPO_IN_CONTAINER", str(repo))]
    if damage == "panel-adopts-an-empty-file":
        repo = _panel_copy(workdir, guard_marker, "", 1, "empty")
        return [mock.patch.object(topology, "REPO_IN_CONTAINER", str(repo))]
    if damage == "panel-refuses-its-own-file":
        repo = _panel_copy(workdir, guard_block,
                           '        if true; then\n', 1, "own")
        return [mock.patch.object(topology, "REPO_IN_CONTAINER", str(repo))]
    if damage == "panel-writes-without-the-marker":
        repo = _panel_copy(workdir, marker_echo, "", 1, "marker")
        return [mock.patch.object(topology, "REPO_IN_CONTAINER", str(repo))]
    if damage == "panel-refusal-does-not-name-the-path":
        repo = _panel_copy(
            workdir, refusal,
            '            echo "Error: Pre-existing unmanaged sysctl configuration. '
            'Refusing to overwrite unmanaged host resource." >&2\n', 1, "path")
        return [mock.patch.object(topology, "REPO_IN_CONTAINER", str(repo))]
    if damage == "worker-forgets-the-created-flag":
        broken = Path(workdir) / "gowave-node-auto-forgot.sh"
        broken.write_text(
            _rewritten(ownership.WORKER_INSTALLER, created_flag,
                       "        _SYSCTL_CREATED_BY_US=0\n", 1), encoding="utf-8")
        return [mock.patch.object(ownership, "WORKER_INSTALLER", broken)]
    if damage == "worker-marks-a-foreign-file-as-created":
        broken = Path(workdir) / "gowave-node-auto-foreign.sh"
        broken.write_text(
            _rewritten(ownership.WORKER_INSTALLER, foreign_flag,
                       "            _SYSCTL_CREATED_BY_US=1\n", 1), encoding="utf-8")
        return [mock.patch.object(ownership, "WORKER_INSTALLER", broken)]
    raise AssertionError(f"unknown damage {damage!r}")


class TestOwnershipRegistration(unittest.TestCase):
    """The id is registered on both contours, each with the driver it runs."""

    def test_the_id_is_registered_on_both_contours(self):
        registry = catalog.driver_registry()
        self.assertIn(ownership.CASE_ID, registry)
        self.assertEqual(set(registry[ownership.CASE_ID]), set(TOPOLOGIES))
        for name, function in DRIVERS.items():
            self.assertEqual(
                registry[ownership.CASE_ID][name]["driver"],
                f"ownership:{function.__name__}",
            )

    def test_the_catalog_entry_is_what_the_registry_derives(self):
        registry = catalog.driver_registry()
        entries = {entry["id"]: entry for entry in catalog.load_catalog()["cases"]}
        entry = entries[ownership.CASE_ID]
        self.assertEqual(entry["driver_status"], "implemented")
        self.assertEqual(entry["drivers"], registry[ownership.CASE_ID])
        self.assertEqual(sorted(entry["topology"]), sorted(TOPOLOGIES))


class TestOwnershipCase(unittest.TestCase):
    """Both halves hold on this tree, and each reports the facts it decides."""

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory(prefix="gowave-own-test-")
        self.addCleanup(self._directory.cleanup)
        self.workdir = Path(self._directory.name)

    def test_the_panel_half_holds(self):
        facts, refusal = run_case("aio", self.workdir)
        self.assertIsNone(refusal)
        self.assertEqual(len(facts), 12)
        self.assertTrue(facts["foreign_refused"])
        self.assertTrue(facts["foreign_bytes_intact"])
        self.assertTrue(facts["symlink_refused"])
        self.assertTrue(facts["symlink_still_a_symlink"])
        self.assertTrue(facts["own_lines_adopted"])
        self.assertTrue(facts["absent_created"])

    def test_the_worker_half_holds(self):
        facts, refusal = run_case("multi-node", self.workdir)
        self.assertIsNone(refusal)
        self.assertEqual(len(facts), 15)
        self.assertTrue(facts["foreign_not_marked_created"])
        self.assertTrue(facts["absent_marked_created"])
        self.assertTrue(facts["absent_has_the_marker"])

    def test_the_evidence_set_is_what_the_catalog_records(self):
        registry = catalog.driver_registry()
        for name in TOPOLOGIES:
            with self.subTest(topology=name):
                facts, refusal = run_case(name, self.workdir)
                self.assertIsNone(refusal)
                self.assertEqual(sorted(facts), registry[ownership.CASE_ID][name]["evidence"])

    def test_a_contour_without_a_worker_is_blocked_not_passed(self):
        product = _LocalProduct(worker=False)
        with self.assertRaises(CaseBlocked):
            DRIVERS["multi-node"](product, object())


class TestOwnershipDamage(unittest.TestCase):
    """Each clause is damaged on its own and the case refuses for that reason."""

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory(prefix="gowave-own-damage-")
        self.addCleanup(self._directory.cleanup)
        self.workdir = Path(self._directory.name)

    def assert_refused(self, damage, topology_name):
        _, refusal = run_case(topology_name, self.workdir, damage=damage)
        self.assertIsNotNone(refusal, f"{damage} did not make OWN-01 refuse")
        self.assertIn(EXPECTED_REFUSALS[damage], refusal)

    def test_a_guard_that_adopts_a_symlink_is_refused(self):
        self.assert_refused("panel-adopts-a-symlink", "aio")

    def test_a_guard_that_adopts_an_empty_file_is_refused(self):
        self.assert_refused("panel-adopts-an-empty-file", "aio")

    def test_a_guard_that_refuses_the_products_own_file_is_refused(self):
        self.assert_refused("panel-refuses-its-own-file", "aio")

    def test_a_writer_that_drops_its_marker_is_refused(self):
        self.assert_refused("panel-writes-without-the-marker", "aio")

    def test_a_refusal_that_does_not_name_the_path_is_refused(self):
        self.assert_refused("panel-refusal-does-not-name-the-path", "aio")

    def test_a_worker_that_forgets_it_created_the_file_is_refused(self):
        self.assert_refused("worker-forgets-the-created-flag", "multi-node")

    def test_a_worker_that_marks_a_foreign_file_as_its_own_is_refused(self):
        self.assert_refused("worker-marks-a-foreign-file-as-created", "multi-node")


if __name__ == "__main__":
    unittest.main()
