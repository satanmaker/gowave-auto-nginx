#!/usr/bin/env python3
"""Suite nonroot: the run's own refusals, and what each case watches them refuse.

``PRE-01``/``PRE-02``/``PRE-03``/``PRE-05``/``PRE-06`` and ``ADDR-01``..``03``
decide what a live run trusts and what it calls its targets before it contacts a
VPS. The configuration, the ``known_hosts`` and the resolvers are real — the
product's own ``load_config``, ``check_ssh_trust``, ``verify_all_domains`` and
``evaluate_preflight_eligibility`` read bytes this suite writes and answers two
fixture resolvers put on the wire.

The four address cases need nothing but a temporary directory, so they run here.
The four DNS cases need ``tests/fixtures/dns_server.py`` on port 53, which an
unprivileged process cannot bind; each of those is therefore run in a child
process — directly when the suite is root, and otherwise inside a private
network namespace (``unshare -rn`` with loopback brought up), which is the only
way a runner without privileges can own :53. When neither is available the test
says so and skips rather than reporting a pass it did not observe.

Then each clause is damaged on its own — a trust check that accepts, a scan that
appends the key it was asked to verify, a preflight that accepts a duplicate
target, a resolver answer swallowed, a firewall record that reports ``PASS``
without an IPv6 target, a source order inverted — so every assertion is held by
the side it protects rather than by the case's own prose.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import yaml  # noqa: E402

from tools.podman_e2e import catalog, preflight_cases  # noqa: E402
from tools.podman_e2e.runner import RunContext  # noqa: E402

TOPOLOGIES = ("aio", "multi-node")

DNS_CASES = {
    preflight_cases.DNS_MISMATCH_CASE_ID: preflight_cases.case_dns_address_mismatch,
    preflight_cases.AAAA_WITHOUT_IPV6_CASE_ID: preflight_cases.case_aaaa_rejected_without_ipv6,
    preflight_cases.AAAA_WITH_IPV6_CASE_ID: preflight_cases.case_aaaa_verified_with_ipv6,
    preflight_cases.AAAA_BYPASS_CASE_ID: preflight_cases.case_aaaa_cannot_bypass,
}

LOCAL_CASES = {
    preflight_cases.SSH_TRUST_CASE_ID: preflight_cases.case_ssh_trust,
    preflight_cases.PRIVATE_ADDRESS_CASE_ID: preflight_cases.case_private_address_rejected,
    preflight_cases.DISTINCT_TARGETS_CASE_ID: preflight_cases.case_distinct_targets,
    preflight_cases.DISTINCT_DOMAINS_CASE_ID: preflight_cases.case_distinct_domains,
    preflight_cases.ROOT_IDENTITY_CASE_ID: preflight_cases.case_root_identity,
}

ALL_CASES = {**LOCAL_CASES, **DNS_CASES}

#: What each damage is meant to make a case say. The parent asserts the case
#: refused *for that reason*, not merely that it failed: a case that goes red on
#: an unrelated assertion holds nothing.
EXPECTED_REFUSALS = {
    ("PRE-01", "trust-accepts"): "accepted a known_hosts that pins another host's key",
    ("PRE-01", "trust-appends"): "the trust check rewrote known_hosts",
    ("PRE-01", "order-inverted"): "reads a remote baseline before it checks local host trust",
    ("PRE-02", "dns-accepts"): "was accepted while it resolved to",
    ("PRE-03", "dns-accepts"): "preflight accepted it while",
    ("PRE-04", "config-accepts"): "was accepted by configuration preflight",
    ("PRE-04", "validator-relaxed"): "so a caller could relax the global-address rule",
    ("PRE-04", "harness-private"): "are not global",
    ("PRE-04", "order-inverted"):
        "reaches its first bootstrap before it validates the target address",
    ("PRE-05", "dns-accepts"): "a domain with no AAAA record was answered with",
    ("PRE-06", "dns-accepts"): "preflight accepted it while ENABLE_IPV6=false",
    ("PRE-06", "firewall-passes"): "a firewall verification with no IPv6 target reported PASS",
    ("ADDR-01", "config-accepts"): "was accepted by configuration preflight",
    ("ADDR-01", "order-inverted"): "builds an SSH client before it validates",
    ("ADDR-01", "operator-order-inverted"):
        "calls _bootstrap_one before it validates the target identity",
    ("ADDR-02", "config-accepts"): "was accepted by configuration preflight",
    ("ADDR-02", "order-inverted"): "opens an SSH client before validating the names",
    ("ADDR-03", "config-accepts"): "was accepted by configuration preflight",
    ("ADDR-03", "order-inverted"): "takes the mutation lock before it validates the SSH identity",
}


def _accept_anything(_path):
    return mock.MagicMock(master_ssh_user="root", worker_ssh_user="root")


def _trust_that_accepts(_host, _port, _known_hosts):
    return True, None


def _trust_that_appends(host, _port, known_hosts):
    path = Path(known_hosts)
    path.write_text(path.read_text(encoding="utf-8") + f"{host} {preflight_cases.HOST_KEY}\n",
                    encoding="utf-8")
    return False, f"Host key for {host} is not pre-pinned in {path}"


def _descending(_path, *anchors):
    return list(range(len(anchors)))[::-1]


def _descending_for(name):
    """A source order that is ascending in every file but ``name``."""
    def order(path, *anchors):
        if Path(path).name == name:
            return list(range(len(anchors)))[::-1]
        return list(range(len(anchors)))
    return order


def _dns_that_accepts(*_args, **_kwargs):
    """Every name answered correctly, whatever the resolvers said."""
    names = {
        "MASTER_PANEL_DOMAIN": preflight_cases.PANEL_DOMAIN,
        "MASTER_REALITY_DOMAIN": preflight_cases.REALITY_DOMAIN,
        "WORKER_DOMAIN": preflight_cases.WORKER_DOMAIN,
        "WORKER_REALITY_DOMAIN": preflight_cases.WORKER_REALITY_DOMAIN,
        "MASTER_VISION_DOMAIN": preflight_cases.VISION_DOMAIN,
    }
    checks = {}
    for key, domain in names.items():
        checks[key] = SimpleNamespace(ok=True, error=None, domain=domain, resolved_ips=[])
        checks[f"{key}_AAAA"] = SimpleNamespace(ok=True, error=None, domain=domain, resolved_ips=[])
        checks[f"{key}_AAAA_ABSENT"] = SimpleNamespace(ok=True, error=None, domain=domain, resolved_ips=[])
    return checks


def _firewall_that_passes(*_args, **_kwargs):
    return {"status": "PASS"}


def _validator_that_could_relax(*_args, **_kwargs):
    return None


def _config_with_a_private_harness(root, name, **overrides):
    """The harness's own control configuration, answered with addresses it must refuse."""
    return SimpleNamespace(master_ip="10.89.0.2", worker_ip="10.89.0.3")


DAMAGES = {
    "trust-accepts": lambda: mock.patch.object(
        preflight_cases, "check_ssh_trust", _trust_that_accepts),
    "trust-appends": lambda: mock.patch.object(
        preflight_cases, "check_ssh_trust", _trust_that_appends),
    "config-accepts": lambda: mock.patch.object(
        preflight_cases, "load_config", _accept_anything),
    "dns-accepts": lambda: mock.patch.object(
        preflight_cases.live_dns, "verify_all_domains", _dns_that_accepts),
    "firewall-passes": lambda: mock.patch.object(
        preflight_cases.live_firewall, "verify_master_firewall", _firewall_that_passes),
    "validator-relaxed": lambda: mock.patch.object(
        preflight_cases, "validate_public_ip", _validator_that_could_relax),
    "harness-private": lambda: mock.patch.object(
        preflight_cases, "_config", _config_with_a_private_harness),
    "order-inverted": lambda: mock.patch.object(
        preflight_cases, "_source_order", _descending),
    "operator-order-inverted": lambda: mock.patch.object(
        preflight_cases, "_source_order", _descending_for("operator.py")),
}


def run_case(case_id, topology, damage=None):
    """Run one case, with one product behaviour damaged; return (facts, refusal)."""
    function = ALL_CASES[case_id]
    context = SimpleNamespace(topology=topology)
    if damage:
        with DAMAGES[damage]():
            try:
                return function(context), None
            except AssertionError as error:
                return None, str(error)
    try:
        return function(context), None
    except AssertionError as error:
        return None, str(error)


def _case_can_bind_53() -> bool:
    import socket
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind(("127.0.0.1", 53))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def _namespace_command(argv):
    """The argv that runs ``argv`` with a private loopback on port 53, or None."""
    if os.geteuid() == 0:
        return list(argv)
    unshare = shutil.which("unshare")
    if unshare is None:
        return None
    inner = "ip link set lo up && exec " + " ".join(
        subprocess.list2cmdline([argument]) for argument in argv
    )
    return [unshare, "-rn", "sh", "-c", inner]


class TestPreflightRegistration(unittest.TestCase):
    """The eight ids are registered, catalogued and mapped, from one source."""

    def test_every_id_is_registered_on_both_contours_with_its_own_callable(self):
        registry = catalog.driver_registry()
        for case_id, function in ALL_CASES.items():
            with self.subTest(case_id=case_id):
                self.assertIn(case_id, registry)
                self.assertEqual(set(registry[case_id]), set(TOPOLOGIES))
                for topology in TOPOLOGIES:
                    entry = registry[case_id][topology]
                    self.assertEqual(
                        entry["driver"], f"preflight_cases:{function.__name__}",
                        f"{case_id} / {topology} runs a different callable than the module exports",
                    )

    def test_the_catalog_entry_is_what_the_registry_derives(self):
        registry = catalog.driver_registry()
        entries = {entry["id"]: entry for entry in catalog.load_catalog()["cases"]}
        for case_id in ALL_CASES:
            with self.subTest(case_id=case_id):
                entry = entries[case_id]
                self.assertEqual(entry["driver_status"], "implemented")
                self.assertEqual(entry["drivers"], registry[case_id])

    def test_every_id_is_mapped_to_a_requirement(self):
        table = yaml.safe_load(
            (REPO_ROOT / "tests" / "cases" / "traceability.yaml").read_text(encoding="utf-8"))
        mapped = set()
        for row in table["requirements"]:
            for scenario in row["scenarios"]:
                mapped.update(scenario.get("cases") or [])
        for entry in table.get("cases_by_requirement") or []:
            mapped.update(entry.get("cases") or [])
        self.assertEqual(sorted(set(ALL_CASES) - mapped), [])


class TestPreflightLocalCases(unittest.TestCase):
    """The four cases that need no resolver answer for real, on both contours."""

    def test_the_cases_hold_on_both_contours(self):
        for topology in TOPOLOGIES:
            for case_id in LOCAL_CASES:
                with self.subTest(case_id=case_id, topology=topology):
                    facts, refusal = run_case(case_id, topology)
                    self.assertIsNone(refusal)
                    self.assertTrue(facts)

    def test_the_evidence_is_exactly_what_the_catalog_records(self):
        registry = catalog.driver_registry()
        for case_id in LOCAL_CASES:
            facts, _ = run_case(case_id, "aio")
            with self.subTest(case_id=case_id):
                self.assertEqual(sorted(facts), registry[case_id]["aio"]["evidence"])

    def test_a_trust_check_that_accepts_an_unpinned_host_is_refused(self):
        _, refusal = run_case("PRE-01", "aio", "trust-accepts")
        self.assertIn(EXPECTED_REFUSALS[("PRE-01", "trust-accepts")], refusal)

    def test_the_non_global_address_is_refused_and_the_harness_claims_no_exemption(self):
        facts, refusal = run_case(preflight_cases.PRIVATE_ADDRESS_CASE_ID, "aio")
        self.assertIsNone(refusal)
        self.assertEqual(facts["refused_classes"], 14)
        self.assertEqual(facts["refused_class_names"].split(","), [
            "broadcast", "documentation", "documentation-v6", "link-local", "link-local-v6",
            "loopback", "loopback-v6", "multicast", "multicast-v6", "rfc1918-10",
            "rfc1918-172", "rfc1918-192", "unique-local-v6", "unspecified",
        ])
        for key in ("loopback_refusal", "rfc1918_refusal", "multicast_refusal",
                    "documentation_refusal", "ipv6_refusal"):
            self.assertIn("not a public routable address", facts[key], key)
        self.assertEqual(facts["validator_parameters"], "val,key_name,allow_v6")
        self.assertTrue(facts["harness_addresses_global"])
        self.assertTrue(facts["validated_before_bootstrap"])

    def test_a_configuration_that_accepts_a_private_target_is_refused(self):
        _, refusal = run_case("PRE-04", "aio", "config-accepts")
        self.assertIn(EXPECTED_REFUSALS[("PRE-04", "config-accepts")], refusal)

    def test_a_validator_with_a_relaxing_switch_is_refused(self):
        _, refusal = run_case("PRE-04", "aio", "validator-relaxed")
        self.assertIn(EXPECTED_REFUSALS[("PRE-04", "validator-relaxed")], refusal)

    def test_a_harness_that_addresses_private_hosts_is_refused(self):
        _, refusal = run_case("PRE-04", "aio", "harness-private")
        self.assertIn(EXPECTED_REFUSALS[("PRE-04", "harness-private")], refusal)

    def test_an_operator_that_bootstraps_before_validating_the_address_is_refused(self):
        _, refusal = run_case("PRE-04", "aio", "order-inverted")
        self.assertIn(EXPECTED_REFUSALS[("PRE-04", "order-inverted")], refusal)

    def test_a_trust_check_that_appends_the_key_is_refused(self):
        _, refusal = run_case("PRE-01", "aio", "trust-appends")
        self.assertIn(EXPECTED_REFUSALS[("PRE-01", "trust-appends")], refusal)

    def test_a_runner_that_reads_the_host_before_trusting_the_key_is_refused(self):
        _, refusal = run_case("PRE-01", "aio", "order-inverted")
        self.assertIn(EXPECTED_REFUSALS[("PRE-01", "order-inverted")], refusal)

    def test_a_configuration_that_accepts_every_target_is_refused(self):
        for case_id in ("ADDR-01", "ADDR-02", "ADDR-03"):
            with self.subTest(case_id=case_id):
                _, refusal = run_case(case_id, "aio", "config-accepts")
                self.assertIn(EXPECTED_REFUSALS[(case_id, "config-accepts")], refusal)

    def test_a_runner_that_opens_a_client_before_validating_is_refused(self):
        _, refusal = run_case("ADDR-01", "aio", "order-inverted")
        self.assertIn(EXPECTED_REFUSALS[("ADDR-01", "order-inverted")], refusal)

    def test_an_operator_that_bootstraps_before_validating_is_refused(self):
        _, refusal = run_case("ADDR-01", "aio", "operator-order-inverted")
        self.assertIn(EXPECTED_REFUSALS[("ADDR-01", "operator-order-inverted")], refusal)

    def test_a_domain_check_that_opens_a_client_first_is_refused(self):
        _, refusal = run_case("ADDR-02", "aio", "order-inverted")
        self.assertIn(EXPECTED_REFUSALS[("ADDR-02", "order-inverted")], refusal)

    def test_an_identity_check_that_takes_the_lock_first_is_refused(self):
        _, refusal = run_case("ADDR-03", "aio", "order-inverted")
        self.assertIn(EXPECTED_REFUSALS[("ADDR-03", "order-inverted")], refusal)


class TestPreflightDnsCases(unittest.TestCase):
    """The four cases that need a resolver pair on :53, run where :53 is ours."""

    def run_in_child(self, case_id, topology="aio", damage=None):
        argv = _namespace_command([
            sys.executable, str(Path(__file__)),
            "--case", case_id, "--topology", topology,
        ] + (["--damage", damage] if damage else []))
        if argv is None:
            self.skipTest(
                "the resolver pair binds :53 and this runner is neither root nor able to "
                "create a network namespace (unshare is missing), so these four cases and "
                "their damage probes were not run"
            )
        completed = subprocess.run(
            argv, capture_output=True, text=True, timeout=600,
            env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
        )
        self.assertEqual(
            completed.returncode, 0,
            f"the child that runs {case_id} exited {completed.returncode}: "
            f"{completed.stderr.strip()[-2000:]}",
        )
        return json.loads(completed.stdout.strip().splitlines()[-1])

    def test_the_cases_hold_on_both_contours(self):
        for topology in TOPOLOGIES:
            for case_id in DNS_CASES:
                with self.subTest(case_id=case_id, topology=topology):
                    result = self.run_in_child(case_id, topology)
                    self.assertEqual(result["verdict"], "PASS", result.get("detail"))

    def test_the_evidence_is_exactly_what_the_catalog_records(self):
        registry = catalog.driver_registry()
        for case_id in DNS_CASES:
            result = self.run_in_child(case_id)
            with self.subTest(case_id=case_id):
                self.assertEqual(sorted(result["facts"]), registry[case_id]["aio"]["evidence"])

    def test_a_resolver_answer_swallowed_is_refused(self):
        for case_id in (preflight_cases.DNS_MISMATCH_CASE_ID,
                        preflight_cases.AAAA_WITHOUT_IPV6_CASE_ID,
                        preflight_cases.AAAA_WITH_IPV6_CASE_ID,
                        preflight_cases.AAAA_BYPASS_CASE_ID):
            with self.subTest(case_id=case_id):
                result = self.run_in_child(case_id, damage="dns-accepts")
                self.assertEqual(result["verdict"], "REFUSED")
                self.assertIn(EXPECTED_REFUSALS[(case_id, "dns-accepts")], result["detail"])

    def test_a_firewall_record_that_passes_without_an_ipv6_target_is_refused(self):
        result = self.run_in_child(
            preflight_cases.AAAA_BYPASS_CASE_ID, damage="firewall-passes")
        self.assertEqual(result["verdict"], "REFUSED")
        self.assertIn(
            EXPECTED_REFUSALS[(preflight_cases.AAAA_BYPASS_CASE_ID, "firewall-passes")],
            result["detail"],
        )


def _main(argv):
    """The child: one case, one optional damage, one JSON line on stdout."""
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--case", required=True)
    parser.add_argument("--topology", default="aio")
    parser.add_argument("--damage")
    arguments = parser.parse_args(argv)
    facts, refusal = run_case(arguments.case, arguments.topology, arguments.damage)
    print(json.dumps({
        "case": arguments.case,
        "topology": arguments.topology,
        "damage": arguments.damage,
        "verdict": "REFUSED" if refusal is not None else "PASS",
        "detail": refusal,
        "facts": facts or {},
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    if "--case" in sys.argv[1:]:
        sys.exit(_main(sys.argv[1:]))
    unittest.main()
