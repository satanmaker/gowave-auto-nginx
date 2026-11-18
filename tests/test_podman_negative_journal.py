#!/usr/bin/env python3
"""Suite nonroot: a Worker whose transport never answered is not registered.

``NEG-03`` is §Negative Scenario and Fault Injection Tests in
``openspec/changes/podman-full-e2e/specs/podman-e2e/spec.md``: when the SSH
connection to a Worker is interrupted mid-installation, the recovery journal on
the Master is not ``COMMITTED``, the recorded rollback removes the partial Panel
entities and the Worker entry from ``state.json``, and the host mutation lock is
released.

The case runs the operator's own ``node add`` on the installed Master against an
address whose sshd never answers, and decides from what the Master wrote
afterwards: the journal, the two compensation sides, the state file against the
snapshot the case took, the Panel inventory and the lock. A container is not
available here, so the tests read the same report the container prints — one
file per clause is damaged, and every assertion is seen to fail for the sentence
it protects. The script's own structure is pinned separately: it pins the host
key before it dials, and it puts the Master back whether or not it got that far.
"""
import ast
import functools
import os
import re
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import catalog, negative_journal  # noqa: E402
from tools.podman_e2e.runner import CaseBlocked  # noqa: E402

TOPOLOGIES = ("aio", "multi-node")
DRIVER = negative_journal.case_partial_worker_install_leaves_no_committed_journal


@functools.lru_cache(maxsize=1)
def registry():
    """The driver registry, read once: building it walks both suites."""
    return catalog.driver_registry()


#: A cluster whose Master has one node and two published hosts; the multi-node
#: contour has two nodes and four, so a case that hardcoded either would fail.
INVENTORY = {"aio": (1, 1, 2), "multi-node": (2, 2, 4)}


def healthy_report(topology="aio"):
    """The report the container prints for a Master that recovered correctly."""
    nodes, profiles, hosts = INVENTORY[topology]
    return {
        "journal_preexisting": "1",
        "journal_set_aside": "1",
        "state_present": "1",
        "credentials_present": "1",
        "port_silent": "1",
        "panel_readable_before": "1",
        "before_nodes": str(nodes),
        "before_profiles": str(profiles),
        "before_hosts": str(hosts),
        "before_worker_listed": "0",
        "pin_reaches_the_product": "1",
        "add_returncode": "1",
        "journal_present": "1",
        "journal_state": "NODE_ADD_ROLLBACK_REQUIRED",
        "journal_is_this_transaction": "1",
        "journal_entries": "5",
        "journal_worker_side": "INCOMPLETE",
        "journal_api_side": "ROLLED_BACK",
        "operator_reads_incomplete": "1",
        "no_success_line": "1",
        "refusal_line": "ssh: connect to host 127.0.0.2 port 22: Connection refused",
        "state_snapshot_usable": "1",
        "state_matches_snapshot": "1",
        "state_nodes_before": str(nodes),
        "state_nodes_after": str(nodes),
        "node_absent_from_state": "1",
        "state_mode": "600",
        "mutation_lock_free": "1",
        "panel_readable_after": "1",
        "after_nodes": str(nodes),
        "after_profiles": str(profiles),
        "after_hosts": str(hosts),
        "after_worker_listed": "0",
        "host_left_as_found": "1",
    }


#: What each damage is meant to make the case say, so a probe that went red on an
#: unrelated sentence is not read as a held clause.
EXPECTED_REFUSALS = {
    "port-answered":
        "a listener answers on the Worker's SSH port",
    "pin-missing":
        "the pinned host key does not answer ssh-keygen -F",
    "panel-unreadable-before":
        "the Panel inventory could not be read before the attempt",
    "panel-unreadable-after":
        "the Panel inventory could not be read after the attempt",
    "never-registered":
        "the product never recorded a Worker transaction",
    "journal-from-another-transaction":
        "the journal the case read is not the transaction this command wrote",
    "journal-not-set-aside":
        "the interrupted node add probe reports a journal it neither set aside nor found absent",
    "no-transport-refusal":
        "no transport refusal appears in the product's own output",
    "printed-success":
        "the product printed its success line",
    "committed-journal":
        "the journal is committed for a Worker whose transport never answered",
    "applying-journal":
        "the journal is not left in a state that requires an operator",
    "no-action-ledger":
        "the journal kept no action ledger",
    "worker-side-verified":
        "the journal does not record both compensation sides",
    "silent-incomplete":
        "the product did not print the INCOMPLETE sentence",
    "panel-kept-the-node":
        "the recorded rollback did not remove the partial Panel entities",
    "panel-kept-a-host":
        "the recorded rollback did not remove the partial Panel entities",
    "state-drifted":
        "state.json does not match the pre-dispatch snapshot",
    "state-lists-the-worker":
        "the Worker is still an entry in state.json",
    "state-world-readable":
        "state.json is not left mode 0600",
    "lock-still-held":
        "the host mutation lock is still held",
    "host-left-dirty":
        "the case did not put the Master back the way it found it",
    "unusable-snapshot":
        "state.json does not match the pre-dispatch snapshot",
}

_DAMAGES = {
    "port-answered": {"port_silent": "0"},
    "pin-missing": {"pin_reaches_the_product": "0"},
    "panel-unreadable-before": {"panel_readable_before": "0"},
    "panel-unreadable-after": {"panel_readable_after": "0"},
    "never-registered": {"journal_present": "0", "journal_state": "absent"},
    "journal-from-another-transaction": {"journal_is_this_transaction": "0"},
    "journal-not-set-aside": {"journal_set_aside": "0"},
    "no-transport-refusal": {"refusal_line": "none"},
    "printed-success": {"no_success_line": "0"},
    "committed-journal": {"journal_state": "NODE_ADD_COMMITTED"},
    "applying-journal": {"journal_state": "NODE_ADD_APPLYING"},
    "no-action-ledger": {"journal_entries": "0"},
    "worker-side-verified": {"journal_worker_side": "ROLLED_BACK"},
    "silent-incomplete": {"operator_reads_incomplete": "0"},
    "panel-kept-the-node": {"after_worker_listed": "1"},
    "panel-kept-a-host": {"after_hosts": "9"},
    "state-drifted": {"state_matches_snapshot": "0"},
    "state-lists-the-worker": {"node_absent_from_state": "0"},
    "state-world-readable": {"state_mode": "644"},
    "lock-still-held": {"mutation_lock_free": "0"},
    "host-left-dirty": {"host_left_as_found": "0"},
    "unusable-snapshot": {"state_snapshot_usable": "0"},
}


class _FakeHost:
    """The product surface the case reaches for, answered from one report."""

    def __init__(self, stdout, returncode=0, stderr=""):
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr
        self.calls = []

    def host_script(self, script, timeout=0):
        self.calls.append({"script": script, "timeout": timeout})
        return types.SimpleNamespace(
            returncode=self.returncode, stdout=self.stdout, stderr=self.stderr)


class _FakePodman:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def exec_bash(self, name, script, check=False, input_text=None, timeout=0):
        self.calls.append({"name": name, "script": script, "timeout": timeout})
        return self.result


class _MultiNodeProduct:
    """Only the surface the case uses: the topology and the podman exec."""

    def __init__(self, result, target_name="e2e-master"):
        self.podman = _FakePodman(result)
        self.topology = types.SimpleNamespace(target_name=target_name)
        self.installed = True

    def require_installed(self):
        if not self.installed:
            raise CaseBlocked("MN-INSTALL: no install has run")
        return self.topology


def render(report, **overrides):
    data = dict(report)
    data.update(overrides)
    return "".join(f"{key}={value}\n" for key, value in data.items())


def run_case(damage=None, topology="aio"):
    """Run the case over one report, optionally with one clause damaged."""
    report = healthy_report(topology)
    if damage:
        report.update(_DAMAGES[damage])
    product = _FakeHost(render(report))
    try:
        return DRIVER(product, object()), None
    except (AssertionError, CaseBlocked) as error:
        return None, str(error)


class TestNegativeJournalRegistration(unittest.TestCase):
    """The id is registered on both contours, each with the driver it runs."""

    def test_the_id_is_registered_on_both_contours(self):
        driver_map = registry()
        self.assertIn(negative_journal.CASE_ID, driver_map)
        self.assertEqual(set(driver_map[negative_journal.CASE_ID]), set(TOPOLOGIES))
        for name in TOPOLOGIES:
            self.assertEqual(
                driver_map[negative_journal.CASE_ID][name]["driver"],
                f"negative_journal:{DRIVER.__name__}",
            )

    def test_the_catalog_entry_is_what_the_registry_derives(self):
        driver_map = registry()
        entries = {entry["id"]: entry for entry in catalog.load_catalog()["cases"]}
        entry = entries[negative_journal.CASE_ID]
        self.assertEqual(entry["driver_status"], "implemented")
        self.assertEqual(entry["drivers"], driver_map[negative_journal.CASE_ID])
        self.assertEqual(sorted(entry["topology"]), sorted(TOPOLOGIES))


class TestNegativeJournalScript(unittest.TestCase):
    """The script is the operator's command, and it runs on the Master."""

    def setUp(self):
        self.script = negative_journal.driver_script()

    def test_the_script_is_shell_and_python_valid(self):
        finished = subprocess.run(
            ["bash", "-n"], input=self.script, text=True, capture_output=True, check=False,
        )
        self.assertEqual(finished.returncode, 0, finished.stderr)
        blocks = re.findall(r"<<'PY'\n(.*?)\nPY\n", self.script, re.S)
        self.assertEqual(len(blocks), 2)
        for block in blocks:
            ast.parse(block)

    def test_the_script_runs_the_operator_command(self):
        self.assertIn(
            'bash "$AUTO" node add "$NAME" "$ADDRESS" "$WORKER_DOMAIN" '
            '"$REALITY_DOMAIN" root "$PORT"',
            self.script)
        self.assertIn(negative_journal.AUTO, self.script)
        self.assertIn(negative_journal.PANEL_SURFACE, self.script)

    def test_the_host_key_is_pinned_before_the_dispatch(self):
        pin = self.script.index('printf \'%s %s %s\\n\' "$HOST_KEY"')
        dispatch = self.script.index('bash "$AUTO" node add')
        self.assertLess(pin, dispatch)
        # The name pinned is the one the product looks up: a non-default port is
        # addressed as `[address]:port`, not as the bare address.
        self.assertIn('[[ "$PORT" != "22" ]] && HOST_KEY="[$ADDRESS]:$PORT"', self.script)

    def test_the_pin_is_a_known_hosts_entry_the_product_accepts(self):
        """The pin has to answer the gate the product uses: `ssh-keygen -F`.

        A bare public key appended to the file is not an entry, and the product
        then refuses the address before it registers anything, so this runs the
        script's own lines instead of trusting that they look right.
        """
        if shutil.which("ssh-keygen") is None:
            self.skipTest("ssh-keygen is not installed")
        block = self.script[
            self.script.index("# 2. Pin the host key"):
            self.script.index("report pin_reaches_the_product")
        ]
        report = 'report pin_reaches_the_product "$(ssh-keygen -F "$HOST_KEY" ' \
                 '-f "$KNOWN_HOSTS" >/dev/null 2>&1 && echo 1 || echo 0)"\n'
        with tempfile.TemporaryDirectory(prefix="gowave-neg03-pin-") as tmp:
            finished = subprocess.run(
                ["bash", "-c",
                 'report() { printf \'%s=%s\\n\' "$1" "$2"; }\n' + block + report],
                env={**os.environ, "work": tmp,
                     "ADDRESS": negative_journal.WORKER_ADDRESS,
                     "PORT": negative_journal.WORKER_SSH_PORT,
                     "HOST_KEY": f"[{negative_journal.WORKER_ADDRESS}]:"
                                 f"{negative_journal.WORKER_SSH_PORT}",
                     "KNOWN_HOSTS": str(Path(tmp) / ".ssh" / "known_hosts")},
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(finished.returncode, 0, finished.stderr)
            self.assertIn("pin_reaches_the_product=1", finished.stdout)
            # The entry is the one the product looks up for a non-default port.
            entry = Path(tmp) / ".ssh" / "known_hosts"
            self.assertTrue(
                entry.read_text(encoding="utf-8").startswith(
                    f"[{negative_journal.WORKER_ADDRESS}]:{negative_journal.WORKER_SSH_PORT} "),
                entry.read_text(encoding="utf-8")[:80])

    def test_a_journal_left_by_an_earlier_transaction_is_set_aside_before_the_dispatch(self):
        # It is not deleted: an earlier transaction's record is put back with its
        # own bytes, so the journal the case reads afterwards is this command's.
        aside = self.script.index('cp -a "$JOURNAL" "$work/journal-before.json"')
        dispatch = self.script.index('bash "$AUTO" node add')
        self.assertLess(aside, dispatch)

    def test_the_master_is_put_back_however_far_the_script_got(self):
        trap = self.script.index("trap 'restore_host; rm -rf \"$work\"' EXIT")
        restore = self.script.index("restore_host() {")
        self.assertLess(restore, trap)
        handler = self.script[restore:trap]
        # Every artefact the case created is undone by the handler: the state
        # file, the journal it wrote and the one it set aside, the pin and its
        # backup file.
        for undo in ('cp -a "$work/state-before.json" "$STATE"',
                     'rm -f "$JOURNAL" "$JOURNAL.tmp"',
                     'cp -a "$work/journal-before.json" "$JOURNAL"',
                     'cp -a "$work/known_hosts-before" "$KNOWN_HOSTS"',
                     'rm -f "$KNOWN_HOSTS"'):
            self.assertIn(undo, handler)

    def test_every_key_the_case_reads_is_a_key_the_script_prints(self):
        printed = set(re.findall(r'^report (\w+)', self.script, re.M))
        printed |= set(re.findall(r'report\("(\w+)"', self.script))
        families = set()
        for prefix in ("before", "after"):
            families |= {f"{prefix}_{suffix}"
                         for suffix in ("nodes", "profiles", "hosts", "worker_listed")}
        # The two surface families are printed by one helper, one call per
        # prefix, so the literal key never appears in the script.
        for key in negative_journal._REPORTED:
            with self.subTest(key=key):
                self.assertTrue(key in printed or key in families,
                                f"{key} is read by the case and printed by nothing")


class TestNegativeJournalCase(unittest.TestCase):
    """The case holds on both contours and reports the facts it decides."""

    def test_a_recovered_master_satisfies_the_case(self):
        for name in TOPOLOGIES:
            with self.subTest(topology=name):
                facts, refusal = run_case(topology=name)
                self.assertIsNone(refusal)
                self.assertEqual(facts["journal_state"], "NODE_ADD_ROLLBACK_REQUIRED")
                self.assertEqual(facts["journal_worker_side"], "INCOMPLETE")
                self.assertEqual(facts["journal_api_side"], "ROLLED_BACK")
                self.assertEqual(facts["panel_inventory_before"], facts["panel_inventory_after"])

    def test_the_evidence_set_is_what_the_catalog_records(self):
        driver_map = registry()
        for name in TOPOLOGIES:
            with self.subTest(topology=name):
                facts, refusal = run_case(topology=name)
                self.assertIsNone(refusal)
                self.assertEqual(
                    sorted(facts), driver_map[negative_journal.CASE_ID][name]["evidence"])

    def test_the_report_the_case_reads_is_complete(self):
        self.assertEqual(set(healthy_report()), set(negative_journal._REPORTED))

    def test_the_multi_node_contour_reaches_the_master_through_the_topology(self):
        product = _MultiNodeProduct(
            types.SimpleNamespace(
                returncode=0, stdout=render(healthy_report("multi-node")), stderr=""))
        facts = DRIVER(product, object())
        self.assertEqual(facts["panel_inventory_before"], "2/2/4")
        self.assertEqual(len(product.podman.calls), 1)
        self.assertEqual(product.podman.calls[0]["name"], "e2e-master")

    def test_an_uninstalled_master_blocks_the_case(self):
        product = _MultiNodeProduct(types.SimpleNamespace(returncode=0, stdout="", stderr=""))
        product.installed = False
        with self.assertRaises(Exception) as caught:
            DRIVER(product, object())
        self.assertIn("MN-INSTALL", str(caught.exception))

    def test_a_journal_that_cannot_be_set_aside_blocks_the_case(self):
        _, refusal = run_case()
        self.assertIsNone(refusal)
        product = _FakeHost(render(
            healthy_report(), bailed="1", journal_set_aside="0"))
        with self.assertRaises(Exception) as caught:
            DRIVER(product, object())
        self.assertIn("could not be prepared", str(caught.exception))

    def test_a_master_without_credentials_blocks_the_case(self):
        product = _FakeHost(render(healthy_report(), credentials_present="0"))
        with self.assertRaises(Exception) as caught:
            DRIVER(product, object())
        self.assertIn("no admin credentials", str(caught.exception))

    def test_a_probe_that_failed_is_refused_rather_than_read(self):
        product = _FakeHost("", returncode=1, stderr="bash: line 1: /repo/gowave-auto.sh: No such file")
        with self.assertRaises(AssertionError) as caught:
            DRIVER(product, object())
        self.assertIn("the interrupted node add probe exited 1", str(caught.exception))

    def test_a_report_that_omits_a_key_is_refused(self):
        report = healthy_report()
        report.pop("mutation_lock_free")
        product = _FakeHost(render(report))
        with self.assertRaises(AssertionError) as caught:
            DRIVER(product, object())
        self.assertIn("mutation_lock_free", str(caught.exception))


class TestNegativeJournalDamage(unittest.TestCase):
    """Each clause is damaged on its own and the case refuses for that reason."""

    def assert_refused(self, damage):
        _, refusal = run_case(damage=damage)
        self.assertIsNotNone(refusal, f"{damage} did not make NEG-03 refuse")
        self.assertIn(EXPECTED_REFUSALS[damage], refusal)

    def test_a_port_with_a_listener_is_refused(self):
        self.assert_refused("port-answered")

    def test_a_host_key_that_was_not_pinned_is_refused(self):
        self.assert_refused("pin-missing")

    def test_an_unreadable_panel_before_the_attempt_is_refused(self):
        self.assert_refused("panel-unreadable-before")

    def test_an_unreadable_panel_after_the_attempt_is_refused(self):
        self.assert_refused("panel-unreadable-after")

    def test_an_attempt_that_never_registered_is_refused(self):
        self.assert_refused("never-registered")

    def test_a_journal_from_another_transaction_is_refused(self):
        self.assert_refused("journal-from-another-transaction")

    def test_a_journal_neither_set_aside_nor_absent_is_refused(self):
        self.assert_refused("journal-not-set-aside")

    def test_a_dispatch_with_no_transport_refusal_is_refused(self):
        self.assert_refused("no-transport-refusal")

    def test_a_success_line_is_refused(self):
        self.assert_refused("printed-success")

    def test_a_committed_journal_is_refused(self):
        self.assert_refused("committed-journal")

    def test_a_journal_that_needs_no_operator_is_refused(self):
        self.assert_refused("applying-journal")

    def test_a_journal_without_an_action_ledger_is_refused(self):
        self.assert_refused("no-action-ledger")

    def test_a_worker_side_recorded_as_verified_is_refused(self):
        self.assert_refused("worker-side-verified")

    def test_a_silent_incomplete_is_refused(self):
        self.assert_refused("silent-incomplete")

    def test_a_panel_that_kept_the_node_is_refused(self):
        self.assert_refused("panel-kept-the-node")

    def test_a_panel_that_kept_a_host_is_refused(self):
        self.assert_refused("panel-kept-a-host")

    def test_a_state_file_that_drifted_is_refused(self):
        self.assert_refused("state-drifted")

    def test_a_state_file_that_lists_the_worker_is_refused(self):
        self.assert_refused("state-lists-the-worker")

    def test_a_world_readable_state_file_is_refused(self):
        self.assert_refused("state-world-readable")

    def test_a_lock_that_was_not_released_is_refused(self):
        self.assert_refused("lock-still-held")

    def test_a_master_left_dirty_is_refused(self):
        self.assert_refused("host-left-dirty")

    def test_an_unusable_snapshot_is_refused(self):
        self.assert_refused("unusable-snapshot")


if __name__ == "__main__":
    unittest.main()
