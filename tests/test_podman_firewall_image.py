#!/usr/bin/env python3
"""Suite nonroot: an existing firewall policy is restored, not partially deleted.

``OWN-03`` is the firewall half of §Complete Mutation-Target Baseline and
Resource Ownership: a host whose UFW is active, or holds operator rules and
default policies, must come back from an injected failure with every original
rule, every default policy and the enabled state — not with the four rules this
install adds deleted from whatever is left.

The before-image is ``firewall_image capture`` and the way back is
``firewall_image restore``, both in ``gowave-node-auto.sh``; the case drives
them over a scratch root whose ``ufw``, ``iptables-save`` and
``iptables-restore`` are shims that keep the state in files. Each clause is
damaged on its own — a capture that trusts a baseline it cannot restore, one
that records no default policies, one that forgets IPv6, one readable by every
user, one that overwrites an existing image, one that refuses a firewall that was
off, a restore that trusts a missing image, one that skips the enabled state, one
that never applies the dump, and one that compares the raw dump instead of the
rules —
so every assertion is seen to fail for the reason it protects.
"""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import catalog, firewall_image, trace  # noqa: E402
from tools.podman_e2e.runner import CaseBlocked  # noqa: E402

TOPOLOGIES = ("aio", "multi-node")
DRIVERS = {
    "aio": firewall_image.case_panel_firewall_policy_is_preserved,
    "multi-node": firewall_image.case_worker_firewall_policy_is_preserved,
}

#: The payload carries the image program twice and the rollback script once, so
#: a damage rewrites every copy — and the copies stay byte-identical.
IMAGE_COPIES = 3

#: What each damage is meant to make the case say, so a probe that went red on
#: an unrelated assertion is not read as a held clause.
EXPECTED_REFUSALS = {
    "capture-trusts-a-baseline-it-cannot-restore":
        "an install began on a firewall it could not write a restorable image of",
    "capture-records-no-default-policies":
        "the before-image does not record the three default policies it replaces",
    "capture-forgets-ipv6": "the before-image does not hold the IPv6 ruleset",
    "capture-is-world-readable": "the firewall before-image is readable by every user",
    "capture-overwrites-an-existing-image":
        "a second capture overwrote the state the first one holds",
    "capture-refuses-an-inactive-baseline":
        "a firewall that was off was refused instead of captured",
    "restore-trusts-a-missing-image":
        "a rollback with no before-image guessed which rules this install added",
    "restore-leaves-the-enabled-state":
        "the restore left UFW active on a host where it was inactive",
    "restore-never-applies-the-dump": "the restore lost a rule this install never wrote",
    "restore-compares-the-raw-dump":
        "the read-back compared the counters and the timestamp, not the rules",
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
        patchers.append(mock.patch.object(firewall_image, "WORKER_INSTALLER", broken))
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
    """The product with one clause of the image functions rewritten."""
    source = firewall_image.WORKER_INSTALLER

    if damage == "capture-trusts-a-baseline-it-cannot-restore":
        return _rewritten(
            source,
            "        code, text, error = run(argv)\n        if code != 0:\n",
            "        code, text, error = run(argv)\n        if False:\n",
            IMAGE_COPIES,
        )
    if damage == "capture-records-no-default-policies":
        return _rewritten(
            source,
            '                defaults[words[1].strip("()")] = words[0]\n',
            '                defaults[words[1].strip("()")] = "?"\n',
            IMAGE_COPIES,
        )
    if damage == "capture-forgets-ipv6":
        return _rewritten(
            source,
            '    for name, argv in (("iptables", ["iptables-save"]), ("ip6tables", ["ip6tables-save"])):\n',
            '    for name, argv in (("iptables", ["iptables-save"]),):\n',
            IMAGE_COPIES,
        )
    if damage == "capture-is-world-readable":
        return _rewritten(
            source,
            '(json.dumps(data, indent=1, sort_keys=True) + "\\n").encode("utf-8"), 0o600)',
            '(json.dumps(data, indent=1, sort_keys=True) + "\\n").encode("utf-8"), 0o644)',
            IMAGE_COPIES,
        )
    if damage == "capture-overwrites-an-existing-image":
        # The Worker-targets capture refuses an existing image with the same
        # line, so the anchor names the firewall's own sentence.
        return _rewritten(
            source,
            '    if os.path.lexists(image):\n'
            '        fail("Firewall before-image " + image + " already exists; refusing to overwrite the state it holds.")\n',
            '    if False:\n'
            '        fail("Firewall before-image " + image + " already exists; refusing to overwrite the state it holds.")\n',
            IMAGE_COPIES,
        )
    if damage == "capture-refuses-an-inactive-baseline":
        return _rewritten(
            source,
            '    if first == "Status: active" and set(defaults) != {"incoming", "outgoing", "routed"}:\n',
            '    if first != "Status: active" or set(defaults) != {"incoming", "outgoing", "routed"}:\n',
            IMAGE_COPIES,
        )
    if damage == "restore-trusts-a-missing-image":
        return _rewritten(
            source,
            "    if not os.path.isfile(MANIFEST):\n",
            "    if False:\n",
            IMAGE_COPIES,
        )
    if damage == "restore-leaves-the-enabled-state":
        return _rewritten(
            source,
            '    state = "enable" if data["enabled"] else "disable"\n',
            '    state = "enable"\n',
            IMAGE_COPIES,
        )
    if damage == "restore-compares-the-raw-dump":
        return _rewritten(
            source,
            '    if code != 0 or normalized(saved) != normalized(restored.get("iptables", "")):\n',
            '    if code != 0 or saved != restored.get("iptables", ""):\n',
            IMAGE_COPIES,
        )
    if damage == "restore-never-applies-the-dump":
        return _rewritten(
            source,
            "        code, _, error = run(argv, stdin_text=text)\n",
            '        code, _, error = 0, "", ""\n',
            IMAGE_COPIES,
        )
    raise AssertionError(f"unknown damage {damage!r}")


class TestFirewallImageRegistration(unittest.TestCase):
    """The id is registered on both contours, each with the driver it runs."""

    def test_the_id_is_registered_on_both_contours(self):
        registry = catalog.driver_registry()
        self.assertIn(firewall_image.CASE_ID, registry)
        self.assertEqual(set(registry[firewall_image.CASE_ID]), set(TOPOLOGIES))
        for name, function in DRIVERS.items():
            self.assertEqual(
                registry[firewall_image.CASE_ID][name]["driver"],
                f"firewall_image:{function.__name__}",
            )

    def test_the_catalog_entry_is_what_the_registry_derives(self):
        registry = catalog.driver_registry()
        entries = {entry["id"]: entry for entry in catalog.load_catalog()["cases"]}
        entry = entries[firewall_image.CASE_ID]
        self.assertEqual(entry["driver_status"], "implemented")
        self.assertEqual(entry["drivers"], registry[firewall_image.CASE_ID])
        self.assertEqual(sorted(entry["topology"]), sorted(TOPOLOGIES))


class TestFirewallImageCase(unittest.TestCase):
    """Both halves hold on this tree, and each reports the facts it decides."""

    def test_the_before_image_holds_on_both_contours(self):
        for name in TOPOLOGIES:
            with self.subTest(topology=name):
                facts, refusal = run_case(name)
                self.assertIsNone(refusal)
                self.assertEqual(len(facts), len(firewall_image.EVIDENCE))
                self.assertTrue(all(facts.values()), facts)

    def test_the_evidence_set_is_what_the_catalog_records(self):
        registry = catalog.driver_registry()
        for name in TOPOLOGIES:
            with self.subTest(topology=name):
                facts, refusal = run_case(name)
                self.assertIsNone(refusal)
                self.assertEqual(
                    sorted(facts), registry[firewall_image.CASE_ID][name]["evidence"])

    def test_all_three_copies_of_the_image_program_agree(self):
        body = firewall_image.WORKER_INSTALLER.read_text(encoding="utf-8")
        self.assertEqual(body.count("<<'FIREWALL_IMAGE_PY'\n"), 3)
        reference = firewall_image.image_body()
        self.assertIn("def capture():", reference)
        self.assertIn("def restore():", reference)
        self.assertEqual(body.count(reference), 3)

    def test_the_image_is_taken_before_the_first_rule_changes(self):
        body = firewall_image.WORKER_INSTALLER.read_text(encoding="utf-8")
        capture = body.index("    record_firewall_before_image || return 1\n")
        for later in ('    ufw default deny incoming\n',
                      '    ufw default allow outgoing\n',
                      '    ufw allow "$ssh_port/tcp" comment "SSH administration"\n',
                      '    ufw allow 80/tcp comment "HTTP ACME challenge"\n',
                      '    ufw --force enable\n'):
            with self.subTest(mutation=later):
                self.assertLess(capture, body.index(later))
        self.assertLess(capture, body.index("    _UFW_RULES_CONFIGURED=1\n"))

    def test_both_rollbacks_restore_the_image(self):
        body = firewall_image.WORKER_INSTALLER.read_text(encoding="utf-8")
        self.assertEqual(body.count("restore_firewall_before_image || rollback_failed=1\n"), 2)

    def test_a_contour_without_a_worker_is_blocked_not_passed(self):
        product = _LocalProduct(worker=False)
        with self.assertRaises(CaseBlocked):
            DRIVERS["multi-node"](product, object())


class TestFirewallImageTraceability(unittest.TestCase):
    """The row that cites OWN-03 states the number of facts the case reads."""

    def test_the_row_states_the_number_of_facts_the_case_reads(self):
        table = yaml.safe_load(
            (REPO_ROOT / "tests" / "cases" / "traceability.yaml").read_text(encoding="utf-8"))
        # A case that serves a requirement without a scenario of its own is filed
        # under `cases_by_requirement`, which is where this one lives.
        reasons = [
            " ".join((group.get("reason") or "").split())
            for group in table["cases_by_requirement"]
            if firewall_image.CASE_ID in (group.get("cases") or [])
        ]
        self.assertTrue(reasons, f"no traceability row cites {firewall_image.CASE_ID}")
        words = {count: word for word, count in trace.NUMBER_WORDS.items()}
        self.assertIn(
            f"reads back {words[len(firewall_image.EVIDENCE)]} facts", " ".join(reasons))


class TestFirewallImageDamage(unittest.TestCase):
    """Each clause is damaged on its own and the case refuses for that reason."""

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory(prefix="gowave-firewall-damage-")
        self.addCleanup(self._directory.cleanup)
        self.workdir = Path(self._directory.name)

    def assert_refused(self, damage, topology_name="multi-node"):
        _, refusal = run_case(topology_name, damage=damage, workdir=self.workdir)
        self.assertIsNotNone(refusal, f"{damage} did not make OWN-03 refuse")
        self.assertIn(EXPECTED_REFUSALS[damage], refusal)

    def test_a_capture_that_trusts_an_unrestorable_baseline_is_refused(self):
        self.assert_refused("capture-trusts-a-baseline-it-cannot-restore")

    def test_a_capture_that_records_no_default_policies_is_refused(self):
        self.assert_refused("capture-records-no-default-policies")

    def test_a_capture_that_forgets_ipv6_is_refused(self):
        self.assert_refused("capture-forgets-ipv6")

    def test_a_capture_readable_by_every_user_is_refused(self):
        self.assert_refused("capture-is-world-readable", "aio")

    def test_a_capture_that_overwrites_an_image_is_refused(self):
        self.assert_refused("capture-overwrites-an-existing-image")

    def test_a_capture_that_refuses_an_inactive_baseline_is_refused(self):
        self.assert_refused("capture-refuses-an-inactive-baseline")

    def test_a_restore_that_trusts_a_missing_image_is_refused(self):
        self.assert_refused("restore-trusts-a-missing-image")

    def test_a_restore_that_leaves_the_enabled_state_is_refused(self):
        self.assert_refused("restore-leaves-the-enabled-state")

    def test_a_read_back_that_compares_the_raw_dump_is_refused(self):
        self.assert_refused("restore-compares-the-raw-dump")

    def test_a_restore_that_never_applies_the_dump_is_refused(self):
        self.assert_refused("restore-never-applies-the-dump")


if __name__ == "__main__":
    unittest.main()
