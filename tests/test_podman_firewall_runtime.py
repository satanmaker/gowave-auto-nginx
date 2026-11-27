"""The two reload/connection cases, driven through stubs.

`FW-07` and `FW-08` read a live host: one compares two rule-set snapshots around
a reload, the other keeps an SSH control session alive across a policy change.
Neither needs a container to be wrong or right about its own logic, so these
tests drive both with a stand-in Podman and assert the assertions themselves:
a changed rule set must fail even when every command exits zero, and a session
that answers while the transport underneath is dead must not pass.
"""

from __future__ import annotations

import subprocess
import unittest
from typing import Any, Dict, List, Optional

from tools.podman_e2e import firewall_runtime


class FakePodman:
    """Answers `exec_bash` from a scripted map, recording every call."""

    def __init__(self, answers: Dict[str, Any]):
        self.answers = answers
        self.calls: List[str] = []

    def exec_bash(self, name: str, script: str, check: bool = True,
                  input_text: Optional[str] = None, timeout: int = 60) -> Any:
        self.calls.append(script)
        for needle, answer in self.answers.items():
            if needle in script:
                if isinstance(answer, Exception):
                    raise answer
                if isinstance(answer, (list, tuple)):
                    answer = answer[min(sum(1 for c in self.calls if needle in c) - 1,
                                        len(answer) - 1)]
                return subprocess.CompletedProcess(
                    ["bash", "-lc", script], 0, answer, "",
                )
        return subprocess.CompletedProcess(["bash", "-lc", script], 0, "", "")


class FakeProduct:
    def __init__(self, podman: FakePodman, worker: bool = False):
        self.podman = podman
        self._worker = worker

    def require_installed(self) -> Any:
        return type("Host", (), {"target_name": "aio-cell"})()

    def require_worker(self) -> Any:
        if not self._worker:
            raise AssertionError("no Worker")
        return type("Host", (), {"target_name": "master-cell",
                                 "plan": type("Plan", (), {"worker_ip": "203.0.113.9"})})()


RULES = "*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n"
RULES_CHANGED = "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n"
LISTENERS = ("State Recv-Q Send-Q Local-Address:Port Peer-Address:Port Process\n"
             "LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:((\"nginx\",pid=1,fd=6))\n")


class TestFirewallRuntimeCases(unittest.TestCase):
    def test_a_reload_that_leaves_the_rules_alone_passes(self):
        podman = FakePodman({"iptables-save": RULES, "ip6tables-save": RULES,
                             "ss -ltn": LISTENERS})
        facts = firewall_runtime.case_rules_survive_reload(FakeProduct(podman))
        self.assertEqual(facts["rules"], "unchanged")
        self.assertTrue(any("ufw reload" in call for call in podman.calls))
        self.assertTrue(any("systemctl restart nginx" in call for call in podman.calls))

    def test_a_reload_that_changes_the_policy_fails_even_with_zero_exits(self):
        # The reload itself is green; the rule set is not the one it started
        # with. A suite that only checked exit codes would call this a pass.
        podman = FakePodman({"iptables-save": [RULES, RULES_CHANGED],
                             "ip6tables-save": RULES, "ss -ltn": LISTENERS})
        with self.assertRaisesRegex(AssertionError, "iptables-save changed"):
            firewall_runtime.case_rules_survive_reload(FakeProduct(podman))

    def test_an_unreadable_rule_set_is_refused_instead_of_compared(self):
        podman = FakePodman({"iptables-save": "", "ip6tables-save": RULES,
                             "ss -ltn": LISTENERS})
        with self.assertRaisesRegex(AssertionError, "answered nothing"):
            firewall_runtime.case_rules_survive_reload(FakeProduct(podman))

    def test_a_listener_that_disappears_across_the_restart_fails(self):
        podman = FakePodman({"iptables-save": RULES, "ip6tables-save": RULES,
                             "ss -ltn": [LISTENERS, LISTENERS.splitlines()[0] + "\n"]})
        with self.assertRaisesRegex(AssertionError, "listeners changed"):
            firewall_runtime.case_rules_survive_reload(FakeProduct(podman))

    def test_the_control_session_surviving_the_policy_change_passes(self):
        podman = FakePodman({
            "ControlMaster=yes": "Master running\n",
            "ufw allow": "active\n",
            "-O check": "Master running\nactive\n",
            "-O exit": "",
        })
        facts = firewall_runtime.case_ssh_survives_firewall(FakeProduct(podman, worker=True))
        self.assertEqual(facts["session"], "survived")

    def test_a_closed_session_fails(self):
        # The mutation ran, but the connection the operator held is gone: the
        # check must read the session, not the exit status of the mutation.
        podman = FakePodman({"ControlMaster=yes": "Master running\n",
                             "ufw allow": "active\n",
                             "-O check": "Control socket connect: No such file\n",
                             "-O exit": ""})
        with self.assertRaisesRegex(AssertionError, "the control session is gone"):
            firewall_runtime.case_ssh_survives_firewall(FakeProduct(podman, worker=True))

    def test_a_session_that_outlives_a_dead_transport_fails(self):
        podman = FakePodman({"ControlMaster=yes": "Master running\n",
                             "ufw allow": "active\n",
                             "-O check": "Master running\ninactive\n",
                             "-O exit": ""})
        with self.assertRaisesRegex(AssertionError, "ssh reports"):
            firewall_runtime.case_ssh_survives_firewall(FakeProduct(podman, worker=True))

    def test_a_mutation_that_dies_on_the_transport_fails(self):
        class Refused(Exception):
            pass

        podman = FakePodman({"ControlMaster=yes": "Master running\n", "-O exit": ""})
        podman.answers["ufw allow"] = subprocess.CompletedProcess([], 255, "", "Connection closed")
        podman.answers["ufw allow"] = Refused("Connection closed by remote host")
        with self.assertRaises(Refused):
            firewall_runtime.case_ssh_survives_firewall(FakeProduct(podman, worker=True))


if __name__ == "__main__":
    unittest.main()
