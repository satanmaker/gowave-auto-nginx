#!/usr/bin/env python3
"""Unit tests for teardown module, restore hook failure modes, and reporting redaction."""
from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
import sys
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT))

from live_vps.teardown import validate_restore_hook, execute_teardown
from live_vps.reporting import write_result_json, write_junit_report, write_summary_txt
from live_vps.redaction import register_secret, clear_secrets


class TestTeardownAndReporting(unittest.TestCase):
    def setUp(self):
        clear_secrets()
        self.td = tempfile.TemporaryDirectory()
        self.td_path = Path(self.td.name)

    def tearDown(self):
        self.td.cleanup()
        clear_secrets()

    def test_validate_restore_hook_missing_or_relative(self):
        ok, err = validate_restore_hook("", "sha256")
        self.assertFalse(ok)
        self.assertTrue("empty" in str(err).lower())

        ok, err = validate_restore_hook("relative/hook.sh", "sha256")
        self.assertFalse(ok)
        self.assertTrue("absolute" in str(err).lower())

    def test_validate_restore_hook_rejects_symlinks(self):
        target = self.td_path / "restore-target.sh"
        target.write_text("#!/bin/sh\\nexit 0\\n")
        target.chmod(0o755)
        link = self.td_path / "restore-link.sh"
        link.symlink_to(target)

        ok, error = validate_restore_hook(str(link), hashlib.sha256(target.read_bytes()).hexdigest())

        self.assertFalse(ok)
        self.assertIn("must not be a symlink", error)

    def test_validate_restore_hook_permissions_and_sha256(self):
        hook = self.td_path / "restore.sh"
        hook.write_text("#!/bin/sh\necho '{\"status\":\"RESTORED\"}'\n")
        h_bytes = hook.read_bytes()
        valid_sha = hashlib.sha256(h_bytes).hexdigest()

        # Not executable yet
        hook.chmod(0o644)
        ok, err = validate_restore_hook(str(hook), valid_sha)
        self.assertFalse(ok)
        self.assertTrue("executable" in str(err).lower())

        # Group/world writable
        hook.chmod(0o777)
        ok, err = validate_restore_hook(str(hook), valid_sha)
        self.assertFalse(ok)
        self.assertTrue("writable" in str(err).lower())

        # Proper mode 0755 but wrong sha
        hook.chmod(0o755)
        ok, err = validate_restore_hook(str(hook), "wrong_sha256_hash")
        self.assertFalse(ok)
        self.assertTrue("mismatch" in str(err).lower())

        # Proper mode 0755 and matching sha
        ok, err = validate_restore_hook(str(hook), valid_sha)
        self.assertTrue(ok)
        self.assertIsNone(err)

    def test_execute_teardown_preserve(self):
        config = MagicMock()
        config.test_teardown_policy = "PRESERVE"
        res = execute_teardown(config, "run-123")
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["policy"], "PRESERVE")

    @patch("live_vps.teardown.subprocess.run")
    def test_execute_teardown_restore_snapshot_failures_before_hook(self, run_hook):
        config = SimpleNamespace(
            test_teardown_policy="RESTORE_SNAPSHOT",
            master_snapshot_id="",
            worker_snapshot_id="snap-worker",
            restore_hook_path="/nonexistent/hook.sh",
            restore_hook_sha256="123",
        )

        with self.subTest(reason="missing snapshot ID"):
            result = execute_teardown(config, "run-123")
            self.assertEqual(result["status"], "TEARDOWN_FAILED")
            self.assertIn("Missing master_snapshot_id", result["error"])
            run_hook.assert_not_called()

        config.master_snapshot_id = "snap-master"
        with self.subTest(reason="invalid hook"):
            result = execute_teardown(
                config, "run-123",
                master_ssh=MagicMock(), worker_ssh=MagicMock(),
                pre_baseline_master={}, pre_baseline_worker={},
            )
            self.assertEqual(result["status"], "TEARDOWN_FAILED")
            self.assertIn("Invalid restore hook", result["error"])
            run_hook.assert_not_called()

    @patch("live_vps.teardown.time.sleep")
    @patch("live_vps.teardown.check_disposable_gate", return_value=(True, []))
    @patch("live_vps.teardown.collect_remote_baseline")
    def test_execute_teardown_restore_snapshot_is_not_false_pass(
        self, collect_baseline, gate, sleep
    ):
        hook = self.td_path / "valid_hook.sh"
        hook_resp = {
            "status": "RESTORED",
            "master_snapshot_id": "snap-m-1",
            "worker_snapshot_id": "snap-w-1",
        }
        hook.write_text(f"#!/bin/sh\ncat >/dev/null\necho '{json.dumps(hook_resp)}'\n")
        hook.chmod(0o755)
        sha = hashlib.sha256(hook.read_bytes()).hexdigest()

        config = MagicMock()
        config.test_teardown_policy = "RESTORE_SNAPSHOT"
        config.master_ip = "198.51.100.1"
        config.worker_ip = "198.51.100.2"
        config.master_snapshot_id = "snap-m-1"
        config.worker_snapshot_id = "snap-w-1"
        config.restore_hook_path = str(hook)
        config.restore_hook_sha256 = sha
        config.restore_timeout = 10

        baseline = {
            "os_kernel": "Linux test 6.1",
            "running_services": ["ssh.service"],
            "tcp_listeners_raw": "LISTEN 0 4096 0.0.0.0:22",
            "listening_ports": [22],
            "existing_gowave_dirs": [],
            "firewall_status": "Status: active",
            "swap_info": "",
            "key_packages": "openssh-server=1",
        }
        collect_baseline.side_effect = [dict(baseline), dict(baseline)]
        res = execute_teardown(
            config, "run-123",
            master_ssh=MagicMock(), worker_ssh=MagicMock(),
            pre_baseline_master=baseline, pre_baseline_worker=baseline,
        )
        self.assertEqual(res["status"], "INCOMPLETE")
        self.assertEqual(res["policy"], "RESTORE_SNAPSHOT")
        self.assertEqual(res["captured_baseline_comparison"], "MATCHED")
        self.assertEqual(res["pair_lock_reacquisition"], "NOT_IMPLEMENTED")
        sleep.assert_called_once_with(5)
        self.assertEqual(collect_baseline.call_count, 2)
        self.assertEqual(gate.call_count, 2)

    @patch("live_vps.teardown.collect_remote_baseline")
    @patch("live_vps.teardown.subprocess.run")
    def test_restore_hook_failures_never_reconnect_or_report_success(
        self, run_hook, collect_baseline
    ):
        hook = self.td_path / "restore_contract.sh"
        hook.write_text("#!/bin/sh\\nexit 0\\n")
        hook.chmod(0o755)
        sha = hashlib.sha256(hook.read_bytes()).hexdigest()
        config = SimpleNamespace(
            test_teardown_policy="RESTORE_SNAPSHOT",
            master_snapshot_id="snap-master",
            worker_snapshot_id="snap-worker",
            restore_hook_path=str(hook),
            restore_hook_sha256=sha,
            master_ip="192.0.2.10",
            worker_ip="192.0.2.20",
            restore_timeout=10,
        )
        ssh = MagicMock()
        baseline = {"os_kernel": "Linux"}
        cases = (
            ("nonzero exit", subprocess.CompletedProcess([], 7, "", "hook failed"), "exited with code 7"),
            ("invalid JSON", subprocess.CompletedProcess([], 0, "not-json", ""), "non-JSON output"),
            ("wrong status", subprocess.CompletedProcess([], 0, json.dumps({"status": "FAILED"}), ""), "reported status"),
            (
                "snapshot ID mismatch",
                subprocess.CompletedProcess([], 0, json.dumps({
                    "status": "RESTORED",
                    "master_snapshot_id": "wrong-master",
                    "worker_snapshot_id": "snap-worker",
                }), ""),
                "snapshot IDs mismatch",
            ),
        )
        for label, response, expected_error in cases:
            with self.subTest(response=label):
                run_hook.reset_mock()
                collect_baseline.reset_mock()
                run_hook.return_value = response
                result = execute_teardown(
                    config, "run-restore-failure",
                    master_ssh=ssh, worker_ssh=ssh,
                    pre_baseline_master=baseline, pre_baseline_worker=baseline,
                )
                self.assertEqual(result["status"], "TEARDOWN_FAILED")
                self.assertIn(expected_error, result["error"])
                run_hook.assert_called_once()
                collect_baseline.assert_not_called()

    @patch("live_vps.teardown.collect_remote_baseline")
    @patch("live_vps.teardown.subprocess.run", side_effect=subprocess.TimeoutExpired("restore", 10))
    def test_restore_hook_timeout_fails_without_reconnecting(
        self, run_hook, collect_baseline
    ):
        hook = self.td_path / "restore_timeout.sh"
        hook.write_text("#!/bin/sh\\nexit 0\\n")
        hook.chmod(0o755)
        config = SimpleNamespace(
            test_teardown_policy="RESTORE_SNAPSHOT",
            master_snapshot_id="snap-master",
            worker_snapshot_id="snap-worker",
            restore_hook_path=str(hook),
            restore_hook_sha256=hashlib.sha256(hook.read_bytes()).hexdigest(),
            master_ip="192.0.2.10",
            worker_ip="192.0.2.20",
            restore_timeout=10,
        )
        baseline = {"os_kernel": "Linux"}
        result = execute_teardown(
            config, "run-restore-timeout",
            master_ssh=MagicMock(), worker_ssh=MagicMock(),
            pre_baseline_master=baseline, pre_baseline_worker=baseline,
        )
        self.assertEqual(result["status"], "TEARDOWN_FAILED")
        self.assertIn("timed out after 10s", result["error"])
        run_hook.assert_called_once()
        collect_baseline.assert_not_called()

    def test_execute_teardown_restore_requires_both_baselines_before_hook(self):
        config = MagicMock()
        config.test_teardown_policy = "RESTORE_SNAPSHOT"
        config.master_snapshot_id = "snap-m"
        config.worker_snapshot_id = "snap-w"
        config.restore_hook_path = "/not-invoked"
        config.restore_hook_sha256 = "0" * 64
        config.master_ip = "198.51.100.1"
        config.worker_ip = "198.51.100.2"
        config.restore_timeout = 10
        result = execute_teardown(config, "run-123", master_ssh=MagicMock(),
                                  worker_ssh=MagicMock(), pre_baseline_master={}, pre_baseline_worker=None)
        self.assertEqual(result["status"], "TEARDOWN_FAILED")
        self.assertIn("both SSH clients and both saved preflight baselines", result["error"])

    def test_junit_marks_incomplete_and_teardown_failed_as_errors(self):
        path = write_junit_report(self.td_path, [
            {"name": "missing-evidence", "classname": "acceptance", "status": "INCOMPLETE",
             "message": "packet evidence missing"},
            {"name": "restore", "classname": "teardown", "status": "TEARDOWN_FAILED",
             "message": "snapshot restoration failed"},
        ])
        content = path.read_text()
        self.assertIn('errors="2"', content)
        self.assertEqual(content.count("<error "), 2)

    def test_reporting_redaction_in_all_outputs(self):
        password = "SuperSecretAdminPassword"
        uuid = "SensitiveShortUuid999"
        jwt = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.jwtSignature"
        register_secret(password)
        register_secret(uuid)
        register_secret(jwt)

        data = {
            "test_run_id": password,
            "repository_commit": uuid,
            "overall": "PASS",
            "results": {
                "auth": {"token": jwt, "password": password},
                "subscription": {"uuid": uuid},
            },
        }

        json_path = write_result_json(self.td_path, data)
        json_content = json_path.read_text()
        junit_path = write_junit_report(self.td_path, [{
            "name": "redaction",
            "classname": "security",
            "status": "FAIL",
            "message": f"{password} {uuid} {jwt}",
            "details": f"{password} {uuid} {jwt}",
        }])
        junit_content = junit_path.read_text()
        summary_path = write_summary_txt(self.td_path, {
            **data,
            "control_machine": {"os": jwt},
            "trust": {"acme_mode": uuid},
        })
        summary_content = summary_path.read_text()

        for output_path, content in (
            (json_path, json_content),
            (junit_path, junit_content),
            (summary_path, summary_content),
        ):
            with self.subTest(output=output_path.name):
                for secret in (password, uuid, "jwtSignature", "eyJhbGciOiJIUzI1NiJ9"):
                    self.assertNotIn(secret, content)
                self.assertEqual(output_path.stat().st_mode & 0o777, 0o600)
                self.assertIn("[REDACTED]", content)

    def test_summary_reports_actual_production_acme_mode(self):
        txt_path = write_summary_txt(self.td_path, {
            "test_run_id": "run-production",
            "overall": "INCOMPLETE",
            "trust": {"acme_mode": "production"},
        })
        self.assertIn("ACME Mode:      production", txt_path.read_text())


if __name__ == "__main__":
    unittest.main()
