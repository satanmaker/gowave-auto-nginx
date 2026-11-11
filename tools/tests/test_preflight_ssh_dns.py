#!/usr/bin/env python3
"""Unit tests for tools/live_vps/ssh.py, dns.py, and preflight.py."""
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

from live_vps.ssh import assert_no_secrets_in_argv, SSHClient
from live_vps.redaction import register_secret, clear_secrets
from live_vps.dns import verify_domain_dns, verify_domain_no_aaaa
from live_vps.firewall import verify_master_firewall, verify_worker_firewall
from live_vps.preflight import (
    check_disposable_gate,
    check_private_key_file,
    check_ssh_trust,
    collect_remote_baseline,
    LocalLock,
    check_control_machine_tools,
)


class TestPreflightSSHDNS(unittest.TestCase):
    def setUp(self):
        clear_secrets()

    def tearDown(self):
        clear_secrets()

    def test_private_key_file_requires_runner_owned_private_regular_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            key = root / "id_ed25519"
            key.write_text("private-key-material")
            key.chmod(0o600)
            self.assertEqual(check_private_key_file(key), (True, None))

            key.chmod(0o644)
            ok, error = check_private_key_file(key)
            self.assertFalse(ok)
            self.assertIn("permissions are too broad", error)

            key.chmod(0o600)
            symlink = root / "key-link"
            symlink.symlink_to(key)
            ok, error = check_private_key_file(symlink)
            self.assertFalse(ok)
            self.assertIn("must not be a symlink", error)

            directory = root / "key-dir"
            directory.mkdir()
            ok, error = check_private_key_file(directory)
            self.assertFalse(ok)
            self.assertIn("regular file", error)

    @patch("live_vps.preflight.subprocess.run")
    def test_known_hosts_rejects_symlink_and_group_world_writable(self, run):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            kh = root / "known_hosts"
            kh.write_text("203.0.113.10 ssh-ed25519 AAAATEST")
            kh.chmod(0o600)
            run.return_value = MagicMock(returncode=0, stdout="pinned\n")
            self.assertEqual(check_ssh_trust("203.0.113.10", 22, kh), (True, None))

            symlink = root / "known_hosts-link"
            symlink.symlink_to(kh)
            ok, error = check_ssh_trust("203.0.113.10", 22, symlink)
            self.assertFalse(ok)
            self.assertIn("non-symlink", error)

            kh.chmod(0o666)
            ok, error = check_ssh_trust("203.0.113.10", 22, kh)
            self.assertFalse(ok)
            self.assertIn("group- or world-writable", error)

    def test_ssh_client_ignores_ambient_config_and_global_trust(self):
        client = SSHClient(
            host="203.0.113.10", port=2222, user="root",
            key_path="/tmp/master-key", known_hosts="/tmp/pinned-known-hosts",
        )
        ssh_cmd = client._build_ssh_cmd("true")
        for expected in (
            "/dev/null",
            "UserKnownHostsFile=/tmp/pinned-known-hosts",
            "GlobalKnownHostsFile=/dev/null",
            "StrictHostKeyChecking=yes",
            "IdentityAgent=none",
            "IdentitiesOnly=yes",
            "ProxyCommand=none",
            "ProxyJump=none",
            "ClearAllForwardings=yes",
            "UpdateHostKeys=no",
        ):
            self.assertIn(expected, ssh_cmd)
        self.assertEqual(ssh_cmd[ssh_cmd.index("-F") + 1], "/dev/null")
        self.assertIn("-i", ssh_cmd)

    def test_assert_no_secrets_in_argv(self):
        # 1. Normal safe arguments
        assert_no_secrets_in_argv(["ssh", "root@example.com", "systemctl status"])

        # 2. Argument containing registered secret
        register_secret("SuperSecretToken12345")
        with self.assertRaises(ValueError) as ctx:
            assert_no_secrets_in_argv(["ssh", "root@example.com", "echo SuperSecretToken12345"])
        self.assertIn("Zero-leak violation", str(ctx.exception))
        self.assertNotIn("SuperSecretToken12345", str(ctx.exception))
        self.assertNotIn("echo", str(ctx.exception))

        # 3. Prohibited credential parameter flag in argv
        with self.assertRaises(ValueError) as ctx2:
            assert_no_secrets_in_argv(["ssh", "root@example.com", "--admin_password=abc"])
        self.assertIn("Zero-leak violation", str(ctx2.exception))
        self.assertNotIn("abc", str(ctx2.exception))
        self.assertNotIn("--admin_password", str(ctx2.exception))

    def test_dns_verification_mock(self):
        # Less than 2 resolvers raises ValueError
        with self.assertRaises(ValueError):
            verify_domain_dns("example.com", "93.184.216.34", resolvers=["1.1.1.1"])

    def test_dns_requires_two_distinct_resolvers(self):
        for verifier in (verify_domain_dns, verify_domain_no_aaaa):
            with self.subTest(verifier=verifier.__name__):
                with self.assertRaisesRegex(ValueError, "two distinct independent resolvers"):
                    if verifier is verify_domain_dns:
                        verifier("panel.example.test", "203.0.113.10", resolvers=["1.1.1.1", "1.1.1.1"])
                    else:
                        verifier("panel.example.test", resolvers=["1.1.1.1", "1.1.1.1"])

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
            stdout=";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n",
        )
        result = verify_domain_no_aaaa("panel.example.test", resolvers=["1.1.1.1", "8.8.8.8"])
        self.assertTrue(result.ok)
        run.return_value = MagicMock(
            returncode=0,
            stdout=";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\npanel.example.test. 60 IN AAAA 2001:db8::10\n",
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
            MagicMock(ok=True, stdout="CONNECTED"),
            MagicMock(ok=True, stdout="203.0.113.10"),
        ]
        worker = MagicMock()
        worker.run.side_effect = [
            MagicMock(ok=True, stdout="Status: active\nDefault: deny (incoming)\n3002/tcp ALLOW IN 203.0.113.10"),
            MagicMock(ok=True, stdout=""),
        ]
        result = verify_worker_firewall(master, worker, "203.0.113.20")
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["worker_allow_list_evidence"])

    @patch("live_vps.firewall.probe_tcp_port", return_value=(False, "REFUSED"))
    @patch("live_vps.firewall.get_control_machine_public_ip", return_value="198.51.100.77")
    def test_worker_firewall_accepts_refused_external_probe_with_positive_controls(self, cm_ip, probe):
        master = MagicMock()
        master.run.side_effect = [
            MagicMock(ok=True, stdout="CONNECTED"),
            MagicMock(ok=True, stdout="203.0.113.10"),
        ]
        worker = MagicMock()
        worker.run.side_effect = [
            MagicMock(ok=True, stdout="Status: active\nDefault: deny (incoming)\n3002/tcp ALLOW IN 203.0.113.10"),
            MagicMock(ok=True, stdout=""),
        ]
        result = verify_worker_firewall(master, worker, "203.0.113.20")
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["control_machine_probe_reason"], "REFUSED")
        self.assertTrue(result["worker_allow_list_evidence"])

    def test_collect_remote_baseline_records_required_target_tools(self):
        ssh = MagicMock()
        ssh.run.return_value = MagicMock(ok=True, stdout="tcpdump=ok\ntimeout=missing\n")
        manifest = collect_remote_baseline(ssh)
        self.assertEqual(manifest["required_tools"], {"tcpdump": "ok", "timeout": "missing"})

        eligible, reasons = check_disposable_gate(manifest)
        self.assertFalse(eligible)
        self.assertTrue(any("timeout" in reason for reason in reasons))

    def test_check_disposable_gate(self):
        clean = {
            "existing_gowave_dirs": [],
            "running_services": ["cron.service", "ssh.service"],
            "listening_ports": [22],
            "required_tools": {"tcpdump": "ok", "timeout": "ok"},
        }
        eligible, reasons = check_disposable_gate(clean)
        self.assertTrue(eligible)
        self.assertEqual(reasons, [])

        occupied_baselines = (
            (
                "GoWave installation directory",
                {
                    "existing_gowave_dirs": ["/opt/gowave"],
                    "running_services": [],
                    "listening_ports": [22],
                },
                "Pre-existing GoWave directories",
            ),
            (
                "HTTPS listener",
                {
                    "existing_gowave_dirs": [],
                    "running_services": [],
                    "listening_ports": [22, 443],
                },
                "Port conflicts",
            ),
            (
                "GoWave service",
                {
                    "existing_gowave_dirs": [],
                    "running_services": ["gowave.service"],
                    "listening_ports": [22],
                },
                "GoWave systemd service already active",
            ),
            (
                "packet capture tool",
                {
                    "existing_gowave_dirs": [],
                    "running_services": [],
                    "listening_ports": [22],
                    "required_tools": {"tcpdump": "missing", "timeout": "ok"},
                },
                "Missing required target tools",
            ),
        )
        for label, baseline, expected_reason in occupied_baselines:
            with self.subTest(conflict=label):
                eligible, reasons = check_disposable_gate(baseline)
                self.assertFalse(eligible)
                self.assertTrue(any(expected_reason in reason for reason in reasons))

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
