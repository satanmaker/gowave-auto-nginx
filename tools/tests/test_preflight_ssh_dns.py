#!/usr/bin/env python3
"""Unit tests for tools/live_vps/ssh.py, dns.py, and preflight.py."""
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

from live_vps.ssh import assert_no_secrets_in_argv
from live_vps.redaction import register_secret, clear_secrets
from live_vps.dns import verify_domain_dns, verify_domain_no_aaaa
from live_vps.firewall import verify_master_firewall, verify_worker_firewall
from live_vps.preflight import (
    check_disposable_gate,
    LocalLock,
    check_control_machine_tools,
)


class TestPreflightSSHDNS(unittest.TestCase):
    def tearDown(self):
        clear_secrets()

    def test_assert_no_secrets_in_argv(self):
        # 1. Normal safe arguments
        assert_no_secrets_in_argv(["ssh", "root@example.com", "systemctl status"])

        # 2. Argument containing registered secret
        register_secret("SuperSecretToken12345")
        with self.assertRaises(ValueError) as ctx:
            assert_no_secrets_in_argv(["ssh", "root@example.com", "echo SuperSecretToken12345"])
        self.assertIn("Zero-leak violation", str(ctx.exception))

        # 3. Prohibited credential parameter flag in argv
        with self.assertRaises(ValueError) as ctx2:
            assert_no_secrets_in_argv(["ssh", "root@example.com", "--admin_password=abc"])
        self.assertIn("Zero-leak violation", str(ctx2.exception))

    def test_dns_verification_mock(self):
        # Less than 2 resolvers raises ValueError
        with self.assertRaises(ValueError):
            verify_domain_dns("example.com", "93.184.216.34", resolvers=["1.1.1.1"])

    @patch("live_vps.dns.resolve_dig")
    def test_dns_requires_exactly_expected_ip_on_each_resolver(self, resolve):
        resolve.side_effect = [["203.0.113.10", "203.0.113.11"], ["203.0.113.10"]]
        result = verify_domain_dns(
            "panel.example.test", "203.0.113.10", "A", resolvers=["1.1.1.1", "8.8.8.8"]
        )
        self.assertFalse(result.ok)
        self.assertIn("exactly", result.error)

    @patch("live_vps.dns.subprocess.run")
    def test_dns_ipv6_disabled_requires_no_aaaa_answers(self, run):
        run.return_value = MagicMock(
            returncode=0,
            stdout=";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\\n",
        )
        result = verify_domain_no_aaaa("panel.example.test", resolvers=["1.1.1.1", "8.8.8.8"])
        self.assertTrue(result.ok)
        run.return_value = MagicMock(
            returncode=0,
            stdout=";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\\npanel.example.test. 60 IN AAAA 2001:db8::10\\n",
        )
        result = verify_domain_no_aaaa("panel.example.test", resolvers=["1.1.1.1", "8.8.8.8"])
        self.assertFalse(result.ok)
        self.assertIn("Unexpected AAAA", result.error)

    @patch("live_vps.firewall.probe_tcp_port", return_value=(False, "REFUSED"))
    def test_master_firewall_accepts_local_only_bind_not_generic_drop(self, probe):
        ssh = MagicMock()
        ssh.run.side_effect = [
            MagicMock(ok=True, stdout="CONNECTED"),  # loopback
            MagicMock(ok=True, stdout="LISTEN 0 4096 127.0.0.1:3002 *:*"),  # bind
            MagicMock(ok=True, stdout="Status: active"),  # UFW
            MagicMock(ok=True, stdout=""),  # iptables
        ]
        result = verify_master_firewall(ssh, "203.0.113.10")
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["local_only_bind"])

    @patch("live_vps.firewall.probe_tcp_port", return_value=(False, "TIMEOUT"))
    def test_master_firewall_does_not_accept_generic_default_drop(self, probe):
        ssh = MagicMock()
        ssh.run.side_effect = [
            MagicMock(ok=True, stdout="CONNECTED"),
            MagicMock(ok=True, stdout="LISTEN 0 4096 0.0.0.0:3002 *:*"),
            MagicMock(ok=True, stdout="Default: deny (incoming)"),
            MagicMock(ok=True, stdout="-P INPUT DROP"),
        ]
        result = verify_master_firewall(ssh, "203.0.113.10")
        self.assertEqual(result["status"], "INCOMPLETE")

    @patch("live_vps.firewall.probe_tcp_port", return_value=(False, "TIMEOUT"))
    @patch("live_vps.firewall.get_control_machine_public_ip", return_value="198.51.100.77")
    def test_worker_firewall_requires_source_specific_master_allow(self, cm_ip, probe):
        master = MagicMock()
        master.run.side_effect = [
            MagicMock(ok=True, stdout="203.0.113.10"),
            MagicMock(ok=True, stdout="CONNECTED"),
        ]
        worker = MagicMock()
        worker.run.side_effect = [
            MagicMock(ok=True, stdout="Status: active\\nDefault: deny (incoming)\\n3002/tcp ALLOW IN 203.0.113.10"),
            MagicMock(ok=True, stdout=""),
        ]
        result = verify_worker_firewall(master, worker, "203.0.113.20")
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["worker_allow_list_evidence"])

    def test_check_disposable_gate(self):
        # Clean baseline
        clean = {
            "existing_gowave_dirs": [],
            "running_services": ["cron.service", "ssh.service"],
            "listening_ports": [22],
        }
        ok, disqs = check_disposable_gate(clean)
        self.assertTrue(ok)
        self.assertEqual(disqs, [])

        # Dirty baseline: existing directory
        dirty_dir = {
            "existing_gowave_dirs": ["/opt/gowave"],
            "running_services": [],
            "listening_ports": [22],
        }
        ok1, disqs1 = check_disposable_gate(dirty_dir)
        self.assertFalse(ok1)
        self.assertTrue(any("Pre-existing GoWave directories" in d for d in disqs1))

        # Dirty baseline: occupied port 443
        dirty_port = {
            "existing_gowave_dirs": [],
            "running_services": [],
            "listening_ports": [22, 443],
        }
        ok2, disqs2 = check_disposable_gate(dirty_port)
        self.assertFalse(ok2)
        self.assertTrue(any("Port conflicts" in d for d in disqs2))

        # Dirty baseline: active gowave service
        dirty_svc = {
            "existing_gowave_dirs": [],
            "running_services": ["gowave.service"],
            "listening_ports": [22],
        }
        ok3, disqs3 = check_disposable_gate(dirty_svc)
        self.assertFalse(ok3)
        self.assertTrue(any("GoWave systemd service already active" in d for d in disqs3))

    def test_local_lock(self):
        lock1 = LocalLock("test-target-lock")
        lock2 = LocalLock("test-target-lock")

        self.assertTrue(lock1.acquire())
        # Second acquire for same target fails
        self.assertFalse(lock2.acquire())

        # Release first lock
        lock1.release()
        # Second can now acquire
        self.assertTrue(lock2.acquire())
        lock2.release()


if __name__ == "__main__":
    unittest.main()
