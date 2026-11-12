#!/usr/bin/env python3
"""Suite nonroot: FW-01/FW-02 denial evidence, parsing, and fail-closed cases."""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import denial, multi_node  # noqa: E402
from tools.podman_e2e.runner import CaseIncomplete  # noqa: E402

MASTER = "10.89.0.11"
WORKER = "10.89.0.22"
UNTRUSTED = "10.89.0.88"

Iptables = [
    "*filter",
    "-P INPUT DROP",
    "-A INPUT -i lo -j ACCEPT",
    f"-A INPUT -s {MASTER}/32 -p tcp -m tcp --dport {denial.NODE_PORT} -j ACCEPT",
    "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT",
    "-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT",
    "-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT",
]

Counters = [
    "    3     180 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0"
    f"  tcp dpt:{denial.NODE_PORT}",
]

Ufw = ["Status: active", "To                         Action      From",
       f"{denial.NODE_PORT}/tcp              ALLOW       {MASTER}"]


class TestDenialParsers(unittest.TestCase):
    def test_the_node_allowlist_is_read_with_its_source(self):
        parsed = denial.parse_worker_firewall({"iptables": Iptables, "counters": Counters, "ufw": Ufw})
        self.assertEqual(parsed["node_allow_sources"], [MASTER])
        self.assertEqual(parsed["unscoped_allows"], [])
        self.assertEqual(parsed["input_policy"], "DROP")
        self.assertTrue(parsed["active"])
        self.assertTrue(parsed["ssh_anywhere"])

    def test_an_unscoped_control_port_allow_is_named(self):
        rules = [f"-A INPUT -p tcp -m tcp --dport {denial.NODE_PORT} -j ACCEPT"]
        parsed = denial.parse_worker_firewall({"iptables": rules, "counters": [], "ufw": Ufw})
        self.assertEqual(parsed["node_allow_sources"], [])
        self.assertEqual(len(parsed["unscoped_allows"]), 1)

    def test_a_source_scoped_ssh_rule_is_not_reported_as_open_to_all(self):
        rules = [f"-A INPUT -s {MASTER}/32 -p tcp -m tcp --dport 22 -j ACCEPT"]
        parsed = denial.parse_ssh_rules(rules)
        self.assertFalse(parsed["anywhere"])
        self.assertEqual(parsed["scoped_sources"], [MASTER])

    def test_the_counters_carry_packets_and_the_rule_source(self):
        entries = denial.parse_counters(Counters)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["packets"], 3)
        self.assertEqual(entries[0]["target"], "ACCEPT")

    def test_the_probe_report_and_the_trusted_command_are_parsed(self):
        report = denial.parse_untrusted_probe(
            "noise\n"
            f"worker={UNTRUSTED}\n"
            "management=REFUSED\n"
            "management_detail=bash: connect: Connection refused\n"
            "ssh_outcome=REJECTED\n"
            "ssh_command_output=0\n"
            "ssh_returncode=255\n"
            "ssh_stderr=root@10.89.0.22: Permission denied (publickey).\n"
        )
        self.assertEqual(report["management"]["outcome"], "REFUSED")
        self.assertIn("Connection refused", report["management"]["detail"])
        self.assertEqual(report["ssh_login"]["outcome"], "REJECTED")
        self.assertEqual(report["ssh_login"]["returncode"], 255)
        self.assertFalse(report["ssh_login"]["command_output"])
        self.assertIn("Permission denied", report["ssh_login"]["stderr"])
        trusted = denial.parse_trusted_ssh(f"{denial.TRUSTED_MARKER}\n rc=0\n")
        self.assertTrue(trusted["marker"])
        self.assertEqual(trusted["returncode"], 0)

    def test_a_probe_that_printed_no_verdict_is_an_empty_report(self):
        self.assertEqual(denial.parse_untrusted_probe("bash: line 1: not found\n"), {})

    def test_the_ssh_observation_returns_the_worker_lines(self):
        lines = denial.parse_sshd_observation(
            '{"count": 1, "matches": ["Failed publickey for root from '
            f'{UNTRUSTED} port 40000 ssh2"]}}'
        )
        self.assertEqual(len(lines), 1)
        self.assertIn(UNTRUSTED, lines[0])

    def test_the_ssh_report_carries_the_daemon_tail_for_a_diagnosable_miss(self):
        # journalctl -o cat prints the message alone, so the query selects the
        # daemon and the report has to show what it logged when nothing matches.
        report = denial.parse_sshd_report(
            '{"count": 0, "matches": [], '
            '"tail": ["Server listening on 0.0.0.0 port 22.", '
            f'"Connection closed by {UNTRUSTED} port 40000"]}}'
        )
        self.assertEqual(report["matches"], [])
        self.assertEqual(len(report["tail"]), 2)
        self.assertIn(UNTRUSTED, report["tail"][-1])

    def test_the_probe_is_a_real_connection_and_a_real_login(self):
        script = denial.untrusted_probe_script("10.89.0.22")
        self.assertIn("/dev/tcp/$WORKER/$PORT", script)
        self.assertIn("StrictHostKeyChecking=no", script)
        self.assertIn("PreferredAuthentications=publickey", script)
        self.assertIn(denial.UNTRUSTED_MARKER, script)
        self.assertNotIn("python3", script, "the clean target image has no Python")

    def test_the_trusted_command_pins_the_host_key(self):
        command = denial.trusted_ssh_command(MASTER)
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("/root/.ssh/known_hosts", command)
        self.assertIn(denial.TRUSTED_MARKER, command)


class TestDenialClassification(unittest.TestCase):
    def classify(self, **overrides):
        arguments = {
            "management_outcome": "REFUSED",
            "positive_control": True,
            "worker_rule_scoped": True,
            "observed_source": UNTRUSTED,
            "allowed_source": MASTER,
        }
        arguments.update(overrides)
        return denial.classify_denial(**arguments)

    def test_a_supported_refusal_is_the_firewall(self):
        verdict, reason = self.classify()
        self.assertEqual(verdict, denial.FIREWALL)
        self.assertIn(UNTRUSTED, reason)
        self.assertIn(MASTER, reason)

    def test_an_accepted_connection_is_a_finding(self):
        verdict, reason = self.classify(management_outcome="CONNECTED")
        self.assertEqual(verdict, denial.ACCEPTED)
        self.assertIn("allowlist is not in force", reason)

    def test_a_refusal_without_a_working_control_is_ambiguous(self):
        verdict, reason = self.classify(positive_control=False)
        self.assertEqual(verdict, denial.AMBIGUOUS)
        self.assertIn("control plane was down", reason)

    def test_a_refusal_without_scoped_rules_is_ambiguous(self):
        verdict, reason = self.classify(worker_rule_scoped=False)
        self.assertEqual(verdict, denial.AMBIGUOUS)
        self.assertIn("not attributable to a policy", reason)

    def test_a_refusal_without_an_observed_source_is_ambiguous(self):
        verdict, reason = self.classify(observed_source="")
        self.assertEqual(verdict, denial.AMBIGUOUS)
        self.assertIn("unproven", reason)

    def test_a_probe_from_the_allowed_address_proves_nothing(self):
        verdict, reason = self.classify(observed_source=MASTER)
        self.assertEqual(verdict, denial.AMBIGUOUS)
        self.assertIn("not about this vantage", reason)

    def test_a_route_failure_is_ambiguous(self):
        verdict, _reason = self.classify(management_outcome="UNREACHABLE")
        self.assertEqual(verdict, denial.AMBIGUOUS)


class _DenialProduct:
    """A product stub: the memoized denial facts, nothing else."""

    def __init__(self, facts=None):
        self.facts = {
            "master_address": MASTER,
            "worker_address": WORKER,
            "untrusted_address": UNTRUSTED,
            "trusted_mtls": {
                "returncode": 0,
                "handshake_pass": True,
                "status_line": "HTTP/1.1 200 OK",
                "response": "health",
                "tail": "",
            },
            "trusted_ssh": {"marker": True, "returncode": 0, "stderr": ""},
            "untrusted": {
                "management": {"outcome": "REFUSED", "errno": 111},
                "ssh_login": {
                    "outcome": "REJECTED",
                    "returncode": 255,
                    "command_output": False,
                    "stderr": "root@10.89.0.22: Permission denied (publickey).",
                },
            },
            "observed_source": UNTRUSTED,
            "observed_lines": [
                f"Failed publickey for root from {UNTRUSTED} port 40000 ssh2"
            ],
            "journal_tail": [
                "Server listening on 0.0.0.0 port 22.",
                f"Connection closed by authenticating user root {UNTRUSTED} port 40000",
            ],
            "firewall": {
                "active": True,
                "input_policy": "DROP",
                "node_allow_sources": [MASTER],
                "node_blocks": [],
                "unscoped_allows": [],
                "ssh_anywhere": True,
                "ssh_scoped_sources": [],
                "counters": [{"packets": 4, "bytes": 240, "target": "ACCEPT", "source": MASTER}],
                "iptables_returncode": 0,
                "iptables_error": "",
            },
            "worker_name": "worker",
            "untrusted_name": "untrusted",
        }
        self.facts.update(facts or {})

    def denial_facts(self, case_id=multi_node.MANAGEMENT_DENIAL_CASE_ID):
        return self.facts


class TestManagementDenialCase(unittest.TestCase):
    """FW-01: accepted on the trusted path, refused from the untrusted one."""

    def run_case(self, product):
        return multi_node.case_management_denial(product)

    def test_a_supported_pair_is_accepted_with_its_evidence(self):
        facts = self.run_case(_DenialProduct())
        self.assertEqual(facts["untrusted_management"], "REFUSED")
        self.assertEqual(facts["untrusted_ssh"], "REJECTED")
        self.assertEqual(facts["worker_observed_source"], UNTRUSTED)
        self.assertEqual(facts["node_allow_sources"], MASTER)

    def test_an_accepted_management_connection_fails_the_case(self):
        product = _DenialProduct()
        product.facts["untrusted"] = {
            "management": {"outcome": "CONNECTED"},
            "ssh_login": product.facts["untrusted"]["ssh_login"],
        }
        with self.assertRaises(AssertionError) as caught:
            self.run_case(product)
        self.assertIn("allowlist is not in force", str(caught.exception))

    def test_a_dead_trusted_path_fails_the_case(self):
        product = _DenialProduct()
        product.facts["trusted_mtls"] = dict(product.facts["trusted_mtls"], handshake_pass=False)
        with self.assertRaises(AssertionError) as caught:
            self.run_case(product)
        self.assertIn("trusted management path is not working", str(caught.exception))

    def test_a_closed_ssh_port_fails_the_case(self):
        product = _DenialProduct()
        product.facts["firewall"] = dict(product.facts["firewall"], ssh_anywhere=False)
        with self.assertRaises(AssertionError) as caught:
            self.run_case(product)
        self.assertIn("not open to every source", str(caught.exception))

    def test_an_unscoped_control_port_fails_the_case(self):
        product = _DenialProduct()
        product.facts["firewall"] = dict(
            product.facts["firewall"],
            unscoped_allows=[{"line": f"--dport {denial.NODE_PORT} -j ACCEPT"}],
        )
        with self.assertRaises(AssertionError) as caught:
            self.run_case(product)
        self.assertIn("from every source", str(caught.exception))

    def test_a_refused_login_that_ran_a_command_fails_the_case(self):
        product = _DenialProduct()
        product.facts["untrusted"] = {
            "management": product.facts["untrusted"]["management"],
            "ssh_login": dict(product.facts["untrusted"]["ssh_login"], command_output=True),
        }
        with self.assertRaises(AssertionError) as caught:
            self.run_case(product)
        self.assertIn("executed a remote command", str(caught.exception))

    def test_a_login_refused_for_another_reason_fails_the_case(self):
        product = _DenialProduct()
        product.facts["untrusted"] = {
            "management": product.facts["untrusted"]["management"],
            "ssh_login": dict(product.facts["untrusted"]["ssh_login"],
                        stderr="ssh: connect to host 10.89.0.22 port 22: No route to host"),
        }
        with self.assertRaises(AssertionError) as caught:
            self.run_case(product)
        self.assertIn("permission denial", str(caught.exception))

    def test_an_observation_naming_no_source_is_incomplete(self):
        # The catalog calls a missing Worker-side observation INCOMPLETE: the
        # refusal was measured, but the vantage it came from is unproven.
        product = _DenialProduct({"observed_source": "", "observed_lines": []})
        with self.assertRaises(CaseIncomplete) as caught:
            self.run_case(product)
        self.assertIn("unproven", str(caught.exception))


class TestDenialClassificationCase(unittest.TestCase):
    """FW-02: the same evidence, classified rather than restated."""

    def test_a_supported_refusal_closes_the_case(self):
        facts = multi_node.case_denial_classification(_DenialProduct())
        self.assertEqual(facts["verdict"], denial.FIREWALL)
        self.assertEqual(facts["denied_source"], UNTRUSTED)

    def test_an_accepted_connection_fails_the_case(self):
        product = _DenialProduct()
        product.facts["untrusted"] = {
            "management": {"outcome": "CONNECTED"},
            "ssh_login": product.facts["untrusted"]["ssh_login"],
        }
        with self.assertRaises(AssertionError) as caught:
            multi_node.case_denial_classification(product)
        self.assertIn("allowlist is not in force", str(caught.exception))

    def test_missing_support_is_incomplete_not_a_pass(self):
        product = _DenialProduct({"observed_source": ""})
        with self.assertRaises(CaseIncomplete):
            multi_node.case_denial_classification(product)


class TestDenialFactsVantage(unittest.TestCase):
    """Both attempts must dial the Worker; the Master is only the allowed source."""

    def test_the_trusted_and_untrusted_attempts_are_made_against_the_worker(self):
        from types import SimpleNamespace
        from unittest import mock

        host = SimpleNamespace(
            plan=SimpleNamespace(
                target_ip=MASTER, worker_ip=WORKER, untrusted_ip=UNTRUSTED,
            ),
            target_name="master",
            worker_name="worker",
            untrusted_name="untrusted",
        )
        product = multi_node.MultiNodeProduct.__new__(multi_node.MultiNodeProduct)
        product.podman = mock.Mock()
        product.denial_facts_cache = None
        product.require_worker = lambda: host
        product.mtls_positive = lambda: {"returncode": 0, "tail": ""}

        calls = {}

        def trusted(podman, container, worker_ip):
            calls["trusted"] = (container, worker_ip)
            return {"marker": True, "returncode": 0}

        def probe(podman, container, worker_ip):
            calls["untrusted"] = (container, worker_ip)
            return {"management": {"outcome": "REFUSED"}, "ssh_login": {"outcome": "REJECTED"}}

        with mock.patch.object(denial, "run_trusted_ssh", side_effect=trusted), \
                mock.patch.object(denial, "run_untrusted_probe", side_effect=probe), \
                mock.patch.object(denial, "sshd_observation", return_value={
                    "matches": [f"Failed publickey from {UNTRUSTED}"],
                    "tail": [f"Connection closed by {UNTRUSTED} port 40000"],
                }), \
                mock.patch.object(denial, "worker_firewall", return_value={
                    "iptables_returncode": 0, "node_allow_sources": [MASTER],
                }):
            facts = multi_node.MultiNodeProduct.denial_facts(product, "FW-01")

        self.assertEqual(calls["trusted"], ("master", WORKER))
        self.assertEqual(calls["untrusted"], ("untrusted", WORKER))
        self.assertEqual(facts["master_address"], MASTER)
        self.assertEqual(facts["worker_address"], WORKER)
        self.assertEqual(facts["journal_tail"], [f"Connection closed by {UNTRUSTED} port 40000"])


if __name__ == "__main__":
    unittest.main()
