#!/usr/bin/env python3
"""Unit tests for the interactive local VPS operator."""
from __future__ import annotations

import base64
import json
import os
import signal
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from live_vps.operator import (
    _bootstrap_one,
    _build_config,
    _cleanup_access,
    _defer_termination_signals,
    _fingerprint,
    _public_key_line,
    _refresh_report,
    _remote_cleanup_script,
    _revoke_all,
    _run_runner,
)


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
            "WORKER_VISION_DOMAIN": "worker-vision.example.org",
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
            self.assertIn("WORKER_VISION_DOMAIN=worker-vision.example.org", content)
            self.assertNotIn("PASSWORD", content.upper())

    def test_runner_command_selects_preflight_mode(self):
        from live_vps.operator import _build_runner_command, TOOLS_DIR
        command = _build_runner_command(Path("/run/config.env"), "run-123", "preflight")
        self.assertEqual(command[-4:], ["--mode", "preflight", "--run-id", "run-123"])
        self.assertIn(str(TOOLS_DIR / "test_live_vps.py"), command)

    def test_runner_command_rejects_unsupported_mode(self):
        from live_vps.operator import _build_runner_command
        with self.assertRaises(ValueError):
            _build_runner_command(Path("/run/config.env"), "run-123", "install")


class TestOperatorSecurityLifecycle(unittest.TestCase):
    """Controller scenarios 3-8: confirmation, bootstrap, revocation, and its record."""

    @staticmethod
    def _target(label="MASTER", host="203.0.113.10"):
        return {
            "host": host, "port": 22, "user": "root",
            "key_path": "/tmp/key", "known_hosts": "/tmp/known_hosts",
            "marker": f"gowave-e2e:run-test:{label.lower()}:deadbeef",
            "timer": f"gowave-e2e-key-expiry-run-test-{label.lower()}",
            "expiry_deadline_utc": "2026-11-12 02:00:00 UTC",
            "timer_state_at_bootstrap": "active",
        }

    @staticmethod
    def _results(*codes):
        return [MagicMock(returncode=code, stdout="", stderr="") for code in codes]

    @patch("live_vps.operator.SSHClient")
    def test_cleanup_records_key_and_timer_evidence(self, client_cls):
        client_cls.return_value.run.side_effect = self._results(0, 0, 1, 1)
        ok, message, evidence = _cleanup_access(self._target())
        self.assertTrue(ok)
        self.assertIn("removed", message)
        self.assertTrue(evidence["revocation_script_present"])
        self.assertFalse(evidence["key_present"])
        self.assertFalse(evidence["timer_active"])
        self.assertEqual(evidence["timer_unit"], "gowave-e2e-key-expiry-run-test-master.timer")
        self.assertEqual(evidence["expiry_deadline_utc"], "2026-11-12 02:00:00 UTC")
        client_cls.return_value.close.assert_called_once()

    @patch("live_vps.operator.SSHClient")
    def test_cleanup_fails_when_the_key_survives(self, client_cls):
        client_cls.return_value.run.side_effect = self._results(0, 0, 0, 1)
        ok, message, evidence = _cleanup_access(self._target())
        self.assertFalse(ok)
        self.assertTrue(evidence["key_present"])
        self.assertIn("still present", message)

    @patch("live_vps.operator.SSHClient")
    def test_cleanup_fails_when_the_timer_survives(self, client_cls):
        client_cls.return_value.run.side_effect = self._results(0, 0, 1, 0)
        ok, message, evidence = _cleanup_access(self._target())
        self.assertFalse(ok)
        self.assertTrue(evidence["timer_active"])
        self.assertIn("still active", message)

    @patch("live_vps.operator.SSHClient")
    def test_cleanup_treats_a_lost_ssh_session_as_unverified(self, client_cls):
        client_cls.return_value.run.side_effect = self._results(255)
        with self.assertRaises(RuntimeError):
            _cleanup_access(self._target())

    @patch("live_vps.operator._cleanup_access")
    def test_revocation_continues_after_an_interrupt(self, cleanup):
        cleanup.side_effect = [
            KeyboardInterrupt(),
            (True, "temporary SSH key removed and expiry timer disabled", {"key_present": False}),
        ]
        results, ok = _revoke_all([
            self._target("MASTER"), self._target("WORKER", "203.0.113.20"),
        ])
        self.assertFalse(ok)
        self.assertEqual(cleanup.call_count, 2)
        self.assertEqual(set(results), {"root@203.0.113.10", "root@203.0.113.20"})
        self.assertEqual(results["root@203.0.113.20"]["status"], "INCOMPLETE")
        self.assertIn("interrupted", results["root@203.0.113.20"]["message"])
        self.assertEqual(results["root@203.0.113.10"]["status"], "PASS")

    def test_revocation_ignores_termination_signals(self):
        seen = {}

        def fake_cleanup(_target):
            seen["sigint"] = signal.getsignal(signal.SIGINT)
            seen["sigterm"] = signal.getsignal(signal.SIGTERM)
            seen["sighup"] = signal.getsignal(signal.SIGHUP)
            return True, "ok", {}

        previous = signal.getsignal(signal.SIGINT)
        with patch("live_vps.operator._cleanup_access", side_effect=fake_cleanup):
            _revoke_all([self._target()])
        for name, handler in seen.items():
            self.assertIs(handler, signal.SIG_IGN, name)
        self.assertEqual(signal.getsignal(signal.SIGINT), previous)

    def test_deferral_restores_handlers_after_an_error(self):
        previous = signal.getsignal(signal.SIGINT)
        with self.assertRaises(RuntimeError):
            with _defer_termination_signals():
                self.assertIs(signal.getsignal(signal.SIGINT), signal.SIG_IGN)
                raise RuntimeError("boom")
        self.assertEqual(signal.getsignal(signal.SIGINT), previous)

    def test_cleanup_record_is_written_without_runner_state(self):
        with tempfile.TemporaryDirectory() as td:
            with patch("live_vps.operator.REPO_ROOT", Path(td)):
                _refresh_report("run-test-abcd", {
                    "status": "PASS",
                    "targets": {"root@203.0.113.10": {"status": "PASS", "message": "removed"}},
                    "ttl_hours": 2,
                })
            artifact_dir = Path(td) / "artifacts" / "live-vps" / "run-test-abcd"
            report_path = artifact_dir / "operator-access.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["run_state"], "absent")
            self.assertEqual(report["operator_access_cleanup"]["status"], "PASS")
            self.assertEqual(report_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(artifact_dir.stat().st_mode & 0o777, 0o700)

    def test_cleanup_failure_reaches_the_run_report_and_junit(self):
        with tempfile.TemporaryDirectory() as td:
            artifact_dir = Path(td) / "artifacts" / "live-vps" / "run-test-abcd"
            artifact_dir.mkdir(parents=True)
            state_file = artifact_dir / "run-state.json"
            state_file.write_text(json.dumps({"overall": "PASS", "results": {}}), encoding="utf-8")
            state_file.chmod(0o600)
            with patch("live_vps.operator.REPO_ROOT", Path(td)):
                _refresh_report("run-test-abcd", {
                    "status": "INCOMPLETE",
                    "targets": {
                        "root@203.0.113.10": {
                            "status": "INCOMPLETE",
                            "message": "temporary SSH key is still present",
                        },
                    },
                    "ttl_hours": 2,
                })
            result = json.loads((artifact_dir / "result.json").read_text(encoding="utf-8"))
            self.assertEqual(result["overall"], "INCOMPLETE")
            entry = result["results"]["operator_access_cleanup"]
            self.assertIn("still present", entry["message"])
            junit = (artifact_dir / "junit.xml").read_text(encoding="utf-8")
            self.assertIn("still present", junit)

    def _bootstrap(self, td, transport, sftp, private_key, exec_side_effect, fingerprint,
                   run_calls=None):
        fake_paramiko = MagicMock()
        fake_paramiko.Transport.return_value = transport
        fake_paramiko.SFTPClient.from_transport.return_value = sftp

        class FakeEd25519Key:
            """Mirrors paramiko 3.5.x, which has no ``Ed25519Key.generate``."""

            @staticmethod
            def from_private_key_file(path):
                return private_key

        fake_paramiko.Ed25519Key = FakeEd25519Key

        def fake_run(cmd, **kwargs):
            if not cmd or cmd[0] != "ssh-keygen":
                raise AssertionError(f"unexpected subprocess invocation: {cmd}")
            if run_calls is not None:
                run_calls.append((list(cmd), kwargs))
            key_path = Path(cmd[cmd.index("-f") + 1])
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key_path.write_text("private-key-material", encoding="utf-8")
            Path(f"{key_path}.pub").write_text("ssh-ed25519 AAAA test", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with patch("live_vps.operator.paramiko", fake_paramiko), \
                patch("live_vps.operator.socket.create_connection", return_value=MagicMock()), \
                patch("live_vps.operator._exec", side_effect=exec_side_effect), \
                patch("live_vps.operator.subprocess.run", side_effect=fake_run), \
                patch("builtins.input", return_value=fingerprint), \
                patch("live_vps.operator.getpass.getpass", return_value="password"):
            return _bootstrap_one(
                label="MASTER", host="203.0.113.10", port=22, username="root",
                run_id="run-test-abcd", runtime_dir=Path(td),
            )

    def test_expiry_timer_is_armed_before_the_key_is_installed(self):
        writes = []

        class FakeSftp:
            def lstat(self, path):
                raise FileNotFoundError(path)

            def file(self, path, mode):
                class _Stream:
                    def __enter__(self_inner):
                        return self_inner

                    def __exit__(self_inner, *exc):
                        return False

                    def write(self_inner, content):
                        writes.append((path, content))

                    def flush(self_inner):
                        pass

                return _Stream()

            def chmod(self, path, mode):
                pass

            def close(self):
                pass

        class FakePrivateKey:
            def get_name(self):
                return "ssh-ed25519"

            def asbytes(self):
                return FakeKey().asbytes()

        transport = MagicMock()
        transport.get_remote_server_key.return_value = FakeKey()
        transport.is_authenticated.return_value = True

        def fake_exec(_transport, command, timeout=15):
            if command == "id -u":
                return 0, "0", ""
            if command.startswith("date -u"):
                return 0, "2026-11-12T00:00:00Z", ""
            if command.startswith("systemctl is-active"):
                return 0, "active\n", ""
            return 0, "", ""

        run_calls = []
        with tempfile.TemporaryDirectory() as td:
            target = self._bootstrap(
                td, transport, FakeSftp(), FakePrivateKey(), fake_exec,
                _fingerprint(FakeKey()), run_calls,
            )
            self.assertEqual(len(run_calls), 1, "the private key must be generated exactly once")
            keygen_cmd, keygen_kwargs = run_calls[0]
            self.assertEqual(keygen_cmd[:4], ["ssh-keygen", "-q", "-t", "ed25519"])
            self.assertEqual(keygen_cmd[keygen_cmd.index("-N") + 1], "")
            self.assertEqual(
                keygen_cmd[keygen_cmd.index("-C") + 1], target["marker"],
                "the key comment must carry the revocation marker",
            )
            key_path = Path(keygen_cmd[keygen_cmd.index("-f") + 1])
            self.assertTrue(key_path.exists(), "the private key file must be written by ssh-keygen")
            self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)
            self.assertFalse(
                Path(f"{key_path}.pub").exists(),
                "the public key half must not be left behind in the runtime directory",
            )
            self.assertIs(keygen_kwargs["shell"], False)
            self.assertIs(keygen_kwargs["check"], True)

        paths = [path for path, _ in writes]
        timer_index = next(i for i, path in enumerate(paths) if path.endswith(".timer"))
        auth_index = next(i for i, path in enumerate(paths) if path.endswith(".tmp"))
        self.assertLess(timer_index, auth_index, "the expiry timer must be armed before the key")

        timer_content = next(body for path, body in writes if path.endswith(".timer"))
        self.assertIn("OnActiveSec=2h", timer_content)
        self.assertIn("OnCalendar=2026-11-12 02:00:00 UTC", timer_content)
        self.assertIn("Persistent=true", timer_content)

        auth_content = next(body for path, body in writes if path.endswith(".tmp"))
        self.assertIn("restrict ssh-ed25519", auth_content)
        self.assertIn(target["marker"], auth_content)

        self.assertEqual(target["expiry_deadline_utc"], "2026-11-12 02:00:00 UTC")
        self.assertEqual(target["timer_state_at_bootstrap"], "active")
        self.assertEqual(target["timer"], "gowave-e2e-key-expiry-run-test-abcd-master")

    def test_unconfirmed_fingerprint_sends_no_password(self):
        transport = MagicMock()
        transport.get_remote_server_key.return_value = FakeKey()
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(RuntimeError):
                self._bootstrap(
                    td, transport, MagicMock(), MagicMock(),
                    lambda *args, **kwargs: (0, "", ""), "SHA256:not-the-real-one",
                )
        transport.auth_password.assert_not_called()


if __name__ == "__main__":
    unittest.main()
