#!/usr/bin/env python3
"""Unit tests for tools/live_vps/config.py."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

from live_vps.config import load_config


class TestLiveVPSConfig(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)
        self.valid_content = """
MASTER_IP=93.184.216.34
MASTER_PANEL_DOMAIN=panel.example.com
MASTER_REALITY_DOMAIN=reality.example.com
WORKER_IP=93.184.216.35
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

    def _config_content(self, **overrides: str) -> str:
        """Build a valid baseline while keeping each test's mutation explicit."""
        values = dict(
            line.split("=", 1)
            for line in self.valid_content.strip().splitlines()
            if line.strip()
        )
        values.update({key: str(value) for key, value in overrides.items()})
        return "\n".join(f"{key}={value}" for key, value in values.items())

    def _write_config(self, content: str, mode: int = 0o600) -> Path:
        p = self.tmp / "test_config.env"
        p.write_text(content.strip() + "\n", encoding="utf-8")
        p.chmod(mode)
        return p

    def test_valid_config_loading(self):
        p = self._write_config(self.valid_content)
        cfg = load_config(p)
        self.assertEqual(cfg.MASTER_IP, "93.184.216.34")
        self.assertEqual(cfg.WORKER_IP, "93.184.216.35")
        self.assertEqual(cfg.MASTER_PANEL_DOMAIN, "panel.example.com")
        self.assertEqual(cfg.ACME_MODE, "staging")
        self.assertTrue(cfg.TEST_TRAFFIC_VERIFICATION)
        self.assertEqual(cfg.NODE_READY_TIMEOUT, 120)

    def test_lowercase_attributes_and_per_host_ssh_paths(self):
        content = self._config_content(
            MASTER_SSH_KEY_PATH="/tmp/master_key",
            WORKER_SSH_KEY_PATH="/tmp/worker_key",
            MASTER_KNOWN_HOSTS_PATH="/tmp/master_known",
            WORKER_KNOWN_HOSTS_PATH="/tmp/worker_known",
        )
        cfg = load_config(self._write_config(content))
        self.assertEqual(cfg.master_ip, "93.184.216.34")
        self.assertEqual(cfg.worker_ip, "93.184.216.35")
        self.assertEqual(cfg.master_ssh_key_path, "/tmp/master_key")
        self.assertEqual(cfg.worker_ssh_key_path, "/tmp/worker_key")
        self.assertEqual(cfg.master_known_hosts_path, "/tmp/master_known")
        self.assertEqual(cfg.worker_known_hosts_path, "/tmp/worker_known")

    def test_shared_ssh_paths_remain_backward_compatible(self):
        cfg = load_config(self._write_config(self.valid_content))
        self.assertEqual(cfg.master_ssh_key_path, "/tmp/id_rsa")
        self.assertEqual(cfg.worker_ssh_key_path, "/tmp/id_rsa")
        self.assertEqual(cfg.master_known_hosts_path, "/tmp/known_hosts")
        self.assertEqual(cfg.worker_known_hosts_path, "/tmp/known_hosts")

    def test_insecure_mode_rejected(self):
        p = self._write_config(self.valid_content, mode=0o644)
        with self.assertRaises(PermissionError) as ctx:
            load_config(p)
        self.assertIn("insecure permissions", str(ctx.exception))

    def test_owner_executable_config_mode_rejected(self):
        with self.assertRaises(PermissionError):
            load_config(self._write_config(self.valid_content, mode=0o700))

    def test_config_symlink_rejected(self):
        target = self._write_config(self.valid_content)
        link = self.tmp / "config-link.env"
        link.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "must not be a symlink"):
            load_config(link)

    def test_unknown_key_rejected(self):
        content = self.valid_content + "\nUNKNOWN_VARIABLE=foo\n"
        p = self._write_config(content)
        with self.assertRaises(ValueError) as ctx:
            load_config(p)
        self.assertIn("Unknown configuration key", str(ctx.exception))

    def test_duplicate_key_rejected(self):
        content = self.valid_content + "\nMASTER_IP=93.184.216.34\n"
        p = self._write_config(content)
        with self.assertRaises(ValueError) as ctx:
            load_config(p)
        self.assertIn("Duplicate configuration key", str(ctx.exception))

    def test_non_public_master_addresses_are_rejected(self):
        invalid_addresses = (
            "192.168.1.1",  # RFC 1918
            "127.0.0.1",    # loopback
            "203.0.113.1",  # documentation range
        )
        for address in invalid_addresses:
            with self.subTest(master_ip=address):
                with self.assertRaisesRegex(ValueError, "not a public routable address"):
                    load_config(
                        self._write_config(self._config_content(MASTER_IP=address))
                    )

    def test_missing_mandatory_key_rejected(self):
        lines = [line for line in self.valid_content.splitlines() if not line.startswith("GOWAVE_PANEL_VERSION")]
        p = self._write_config("\n".join(lines))
        with self.assertRaises(ValueError) as ctx:
            load_config(p)
        self.assertIn("Missing mandatory configuration keys", str(ctx.exception))

    def test_floating_component_versions_rejected(self):
        content = self._config_content(GOWAVE_PANEL_VERSION="latest")
        with self.assertRaisesRegex(ValueError, "explicit pinned version"):
            load_config(self._write_config(content))

    def test_per_host_ssh_credentials_without_shared_paths(self):
        content = self._config_content(
            SSH_KEY_PATH="",
            SSH_KNOWN_HOSTS="",
            MASTER_SSH_KEY_PATH="/tmp/master_key",
            WORKER_SSH_KEY_PATH="/tmp/worker_key",
            MASTER_KNOWN_HOSTS_PATH="/tmp/master_known",
            WORKER_KNOWN_HOSTS_PATH="/tmp/worker_known",
        )
        cfg = load_config(self._write_config(content))
        self.assertEqual(cfg.master_ssh_key_path, "/tmp/master_key")
        self.assertEqual(cfg.worker_ssh_key_path, "/tmp/worker_key")

    def test_same_master_and_worker_ip_rejected(self):
        content = self._config_content(WORKER_IP="93.184.216.34")
        with self.assertRaisesRegex(ValueError, "different VPS hosts"):
            load_config(self._write_config(content))

    def test_non_root_ssh_user_rejected(self):
        content = self._config_content(WORKER_SSH_USER="ubuntu")
        with self.assertRaisesRegex(ValueError, "requires MASTER_SSH_USER=root"):
            load_config(self._write_config(content))

    def test_master_only_vision_configuration_is_supported(self):
        content = self._config_content(MASTER_VISION_DOMAIN="vision-master.example.com")
        cfg = load_config(self._write_config(content))
        self.assertEqual(cfg.master_vision_domain, "vision-master.example.com")
        self.assertIsNone(cfg.worker_vision_domain)

    def test_worker_only_vision_configuration_is_supported(self):
        content = self._config_content(WORKER_VISION_DOMAIN="vision-worker.example.com")
        cfg = load_config(self._write_config(content))
        self.assertIsNone(cfg.master_vision_domain)
        self.assertEqual(cfg.worker_vision_domain, "vision-worker.example.com")

    def test_global_domain_collision_rejected(self):
        content = self._config_content(WORKER_DOMAIN="panel.example.com")
        with self.assertRaisesRegex(ValueError, "globally distinct"):
            load_config(self._write_config(content))

    def test_expected_egress_ip_must_be_public_ipv4(self):
        content = self._config_content(EXPECTED_WORKER_EGRESS_IP="192.168.1.10")
        with self.assertRaisesRegex(ValueError, "not a public routable address"):
            load_config(self._write_config(content))

    def test_teardown_destroy_rejected(self):
        content = self._config_content(TEST_TEARDOWN_POLICY="DESTROY")
        p = self._write_config(content)
        with self.assertRaises(ValueError) as ctx:
            load_config(p)
        self.assertIn("TEST_TEARDOWN_POLICY=DESTROY is unsupported in v1", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
