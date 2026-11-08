#!/usr/bin/env python3
"""Unit tests for tools/live_vps/ssh.py, dns.py, and preflight.py."""
import tempfile
import unittest
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

from live_vps.ssh import assert_no_secrets_in_argv
from live_vps.redaction import register_secret, clear_secrets
from live_vps.dns import verify_domain_dns
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
