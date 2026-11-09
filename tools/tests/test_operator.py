#!/usr/bin/env python3
"""Unit tests for the interactive local VPS operator."""
from __future__ import annotations

import base64
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from live_vps.operator import _build_config, _fingerprint, _public_key_line, _remote_cleanup_script, _run_runner


class FakeKey:
    def get_name(self):
        return "ssh-ed25519"

    def asbytes(self):
        return b"public-key-material"


class TestLocalOperator(unittest.TestCase):
    def test_runner_child_is_interrupted_before_cleanup(self):
        class FakeProcess:
            def __init__(self):
                self.wait_calls = 0
                self.signals = []

            def wait(self, timeout=None):
                self.wait_calls += 1
                if self.wait_calls == 1:
                    raise KeyboardInterrupt()
                return 130

            def poll(self):
                return None

            def send_signal(self, signum):
                self.signals.append(signum)

        process = FakeProcess()
        with patch("live_vps.operator.subprocess.Popen", return_value=process):
            with self.assertRaises(KeyboardInterrupt):
                _run_runner(["python3", "test_live_vps.py"], Path("/tmp"))
        self.assertTrue(process.signals)

    def test_runner_child_escalates_termination_when_sigint_is_ignored(self):
        class FakeProcess:
            def __init__(self):
                self.wait_calls = 0
                self.signals = []

            def wait(self, timeout=None):
                self.wait_calls += 1
                if self.wait_calls == 1:
                    raise KeyboardInterrupt()
                if self.wait_calls in (2, 3):
                    raise subprocess.TimeoutExpired("runner", timeout)
                return 137

            def poll(self):
                return None

            def send_signal(self, signum):
                self.signals.append(("signal", signum))

            def terminate(self):
                self.signals.append(("terminate", None))

            def kill(self):
                self.signals.append(("kill", None))

        process = FakeProcess()
        with patch("live_vps.operator.subprocess.Popen", return_value=process):
            with self.assertRaises(KeyboardInterrupt):
                _run_runner(["python3", "test_live_vps.py"], Path("/tmp"))

        self.assertEqual(process.signals[0], ("signal", signal.SIGINT))
        self.assertEqual(process.signals[1:], [("terminate", None), ("kill", None)])
        self.assertEqual(process.wait_calls, 4)

    def test_runner_returns_child_exit_code(self):
        class FakeProcess:
            def wait(self):
                return 23

        with patch("live_vps.operator.subprocess.Popen", return_value=FakeProcess()):
            self.assertEqual(_run_runner(["python3", "test_live_vps.py"], Path("/tmp")), 23)

    def test_temporary_authorized_key_disables_forwarding_and_pty(self):
        line = _public_key_line(FakeKey(), "gowave-e2e:run:master:marker")
        self.assertTrue(line.startswith("restrict ssh-ed25519 "))
        self.assertTrue(line.endswith(" gowave-e2e:run:master:marker"))

    def test_fingerprint_is_openssh_sha256_format(self):
        import hashlib
        expected = "SHA256:" + base64.b64encode(
            hashlib.sha256(b"public-key-material").digest()
        ).decode("ascii").rstrip("=")
        self.assertEqual(_fingerprint(FakeKey()), expected)

    def test_expiry_script_removes_only_matching_authorized_key(self):
        script = _remote_cleanup_script(
            "run-20261109-abcd1234", "gowave-e2e:run-20261109-abcd1234:master:deadbeef",
            "MASTER", True, True, 0o600,
        )
        self.assertIn("awk -v marker=\"$MARKER\"", script)
        self.assertIn("index($0, marker) == 0", script)
        self.assertIn("gowave-e2e-key-expiry-run-20261109-abcd1234-master.timer", script)
        self.assertIn("chmod 0600", script)

    def test_config_builder_writes_mode_0600_and_master_only_vision(self):
        template = ROOT / "tools" / "live_vps_config.env.example"
        values = {
            "MASTER_IP": "93.184.216.34",
            "MASTER_PANEL_DOMAIN": "panel.example.net",
            "MASTER_REALITY_DOMAIN": "reality.example.net",
            "MASTER_VISION_DOMAIN": "vision.example.net",
            "MASTER_SSH_PORT": "2222",
            "MASTER_SSH_USER": "root",
            "WORKER_IP": "93.184.216.35",
            "WORKER_DOMAIN": "worker.example.org",
            "WORKER_REALITY_DOMAIN": "worker-reality.example.org",
            "WORKER_SSH_PORT": "22",
            "WORKER_SSH_USER": "root",
            "SSH_KEY_PATH": "/tmp/master-key",
            "SSH_KNOWN_HOSTS": "/tmp/master-known-hosts",
            "MASTER_SSH_KEY_PATH": "/tmp/master-key",
            "WORKER_SSH_KEY_PATH": "/tmp/worker-key",
            "MASTER_KNOWN_HOSTS_PATH": "/tmp/master-known-hosts",
            "WORKER_KNOWN_HOSTS_PATH": "/tmp/worker-known-hosts",
            "ACME_MODE": "staging",
            "ADMIN_EMAIL": "admin@example.net",
        }
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "config.env"
            _build_config(template, output, values)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            content = output.read_text(encoding="utf-8")
            self.assertIn("MASTER_VISION_DOMAIN=vision.example.net", content)
            self.assertNotIn("\nWORKER_VISION_DOMAIN=", content)
            self.assertNotIn("PASSWORD", content.upper())


if __name__ == "__main__":
    unittest.main()
