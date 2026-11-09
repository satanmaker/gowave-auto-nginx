#!/usr/bin/env python3
"""Unit tests for tools/live_vps/config.py."""
import os
import tempfile
import unittest
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

from live_vps.config import load_config, LiveVPSConfig


class TestLiveVPSConfig(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)
        self.valid_content = """
MASTER_IP=198.51.100.1
MASTER_PANEL_DOMAIN=panel.example.com
MASTER_REALITY_DOMAIN=reality.example.com
WORKER_IP=198.51.100.2
WORKER_DOMAIN=worker.example.com
WORKER_REALITY_DOMAIN=reality-worker.example.com
SSH_KEY_PATH=/tmp/id_rsa
SSH_KNOWN_HOSTS=/tmp/known_hosts
GOWAVE_PANEL_VERSION=0.4.0
GOWAVE_NODE_VERSION=0.4.0
GOWAVE_NODE_INSTALLER_COMMIT=7b3514d1ab8c674050597820d52d55525d4bece7
GOWAVE_NODE_INSTALLER_SHA256=9a524f1383d3a6a8be42ac370699b0ec6725678ece4abe5b5bc61e8c2af682d0
XRAY_SERVER_VERSION=25.10.15
XRAY_CLIENT_VERSION=25.10.15
MIHOMO_CLIENT_VERSION=1.19.1
ACME_MODE=staging
TEST_TEARDOWN_POLICY=PRESERVE
"""

    def tearDown(self):
        self.tmpdir.cleanup()

    def _write_config(self, content: str, mode: int = 0o600) -> Path:
        p = self.tmp / "test_config.env"
        p.write_text(content.strip() + "\n", encoding="utf-8")
        p.chmod(mode)
        return p

    def test_valid_config_loading(self):
        # Note: 198.51.100.1 is doc range, but let's test with public IP e.g. 1.1.1.1
        content = self.valid_content.replace("198.51.100.1", "93.184.216.34").replace("198.51.100.2", "93.184.216.35")
        p = self._write_config(content)
        cfg = load_config(p)
        self.assertEqual(cfg.MASTER_IP, "93.184.216.34")
        self.assertEqual(cfg.WORKER_IP, "93.184.216.35")
        self.assertEqual(cfg.MASTER_PANEL_DOMAIN, "panel.example.com")
        self.assertEqual(cfg.ACME_MODE, "staging")
        self.assertTrue(cfg.TEST_TRAFFIC_VERIFICATION)
        self.assertEqual(cfg.NODE_READY_TIMEOUT, 120)

    def test_lowercase_attributes_and_per_host_ssh_paths(self):
        content = self.valid_content.replace("198.51.100.1", "93.184.216.34").replace("198.51.100.2", "93.184.216.35")
        content += "\nMASTER_SSH_KEY_PATH=/tmp/master_key\nWORKER_SSH_KEY_PATH=/tmp/worker_key\n"
        content += "MASTER_KNOWN_HOSTS_PATH=/tmp/master_known\nWORKER_KNOWN_HOSTS_PATH=/tmp/worker_known\n"
        cfg = load_config(self._write_config(content))
        self.assertEqual(cfg.master_ip, "93.184.216.34")
        self.assertEqual(cfg.worker_ip, "93.184.216.35")
        self.assertEqual(cfg.master_ssh_key_path, "/tmp/master_key")
        self.assertEqual(cfg.worker_ssh_key_path, "/tmp/worker_key")
        self.assertEqual(cfg.master_known_hosts_path, "/tmp/master_known")
        self.assertEqual(cfg.worker_known_hosts_path, "/tmp/worker_known")

    def test_shared_ssh_paths_remain_backward_compatible(self):
        content = self.valid_content.replace("198.51.100.1", "93.184.216.34").replace("198.51.100.2", "93.184.216.35")
        cfg = load_config(self._write_config(content))
        self.assertEqual(cfg.master_ssh_key_path, "/tmp/id_rsa")
        self.assertEqual(cfg.worker_ssh_key_path, "/tmp/id_rsa")
        self.assertEqual(cfg.master_known_hosts_path, "/tmp/known_hosts")
        self.assertEqual(cfg.worker_known_hosts_path, "/tmp/known_hosts")

    def test_insecure_mode_rejected(self):
        content = self.valid_content.replace("198.51.100.1", "93.184.216.34").replace("198.51.100.2", "93.184.216.35")
        p = self._write_config(content, mode=0o644)
        with self.assertRaises(PermissionError) as ctx:
            load_config(p)
        self.assertIn("insecure permissions", str(ctx.exception))

    def test_unknown_key_rejected(self):
        content = self.valid_content + "\nUNKNOWN_VARIABLE=foo\n"
        content = content.replace("198.51.100.1", "93.184.216.34").replace("198.51.100.2", "93.184.216.35")
        p = self._write_config(content)
        with self.assertRaises(ValueError) as ctx:
            load_config(p)
        self.assertIn("Unknown configuration key", str(ctx.exception))

    def test_duplicate_key_rejected(self):
        content = self.valid_content + "\nMASTER_IP=93.184.216.34\n"
        content = content.replace("198.51.100.1", "93.184.216.34").replace("198.51.100.2", "93.184.216.35")
        p = self._write_config(content)
        with self.assertRaises(ValueError) as ctx:
            load_config(p)
        self.assertIn("Duplicate configuration key", str(ctx.exception))

    def test_private_or_doc_ip_rejected(self):
        # 192.168.1.1 (RFC-1918)
        c1 = self.valid_content.replace("198.51.100.1", "192.168.1.1")
        p1 = self._write_config(c1)
        with self.assertRaises(ValueError) as ctx1:
            load_config(p1)
        self.assertIn("not a public routable address", str(ctx1.exception))

        # 127.0.0.1 (Loopback)
        c2 = self.valid_content.replace("198.51.100.1", "127.0.0.1")
        p2 = self._write_config(c2)
        with self.assertRaises(ValueError) as ctx2:
            load_config(p2)
        self.assertIn("not a public routable address", str(ctx2.exception))

        # 203.0.113.1 (Documentation address)
        c3 = self.valid_content.replace("198.51.100.1", "203.0.113.1")
        p3 = self._write_config(c3)
        with self.assertRaises(ValueError) as ctx3:
            load_config(p3)
        self.assertIn("not a public routable address", str(ctx3.exception))

    def test_missing_mandatory_key_rejected(self):
        lines = [line for line in self.valid_content.splitlines() if not line.startswith("GOWAVE_PANEL_VERSION")]
        p = self._write_config("\n".join(lines).replace("198.51.100.1", "93.184.216.34").replace("198.51.100.2", "93.184.216.35"))
        with self.assertRaises(ValueError) as ctx:
            load_config(p)
        self.assertIn("Missing mandatory configuration keys", str(ctx.exception))

    def test_teardown_destroy_rejected(self):
        content = self.valid_content.replace("TEST_TEARDOWN_POLICY=PRESERVE", "TEST_TEARDOWN_POLICY=DESTROY")
        content = content.replace("198.51.100.1", "93.184.216.34").replace("198.51.100.2", "93.184.216.35")
        p = self._write_config(content)
        with self.assertRaises(ValueError) as ctx:
            load_config(p)
        self.assertIn("TEST_TEARDOWN_POLICY=DESTROY is unsupported in v1", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
