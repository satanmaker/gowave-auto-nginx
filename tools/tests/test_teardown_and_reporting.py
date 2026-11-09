#!/usr/bin/env python3
"""Unit tests for teardown module, restore hook failure modes, and reporting redaction."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
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

    def test_execute_teardown_restore_snapshot_failures(self):
        config = MagicMock()
        config.test_teardown_policy = "RESTORE_SNAPSHOT"
        config.master_snapshot_id = ""
        config.worker_snapshot_id = "w-snap"
        config.restore_hook_path = "/nonexistent/hook.sh"
        config.restore_hook_sha256 = "123"

        # Missing snapshot ID
        res = execute_teardown(config, "run-123")
        self.assertEqual(res["status"], "TEARDOWN_FAILED")

        # Invalid hook
        config.master_snapshot_id = "m-snap"
        res = execute_teardown(config, "run-123")
        self.assertEqual(res["status"], "TEARDOWN_FAILED")

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
        register_secret("SuperSecretAdminPassword")
        register_secret("SensitiveShortUuid999")
        register_secret("Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.jwtSignature")

        data = {
            "test_run_id": "run-test",
            "overall": "PASS",
            "results": {
                "auth": {
                    "token": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.jwtSignature",
                    "password": "SuperSecretAdminPassword",
                },
                "sub": {"uuid": "SensitiveShortUuid999"},
            },
        }

        # 1. Result JSON
        json_path = write_result_json(self.td_path, data)
        json_content = json_path.read_text()
        self.assertNotIn("SuperSecretAdminPassword", json_content)
        self.assertNotIn("SensitiveShortUuid999", json_content)
        self.assertNotIn("jwtSignature", json_content)

        # 2. JUnit XML
        cases = [
            {
                "name": "case_1",
                "classname": "suite",
                "status": "FAIL",
                "message": "Failed with SuperSecretAdminPassword and SensitiveShortUuid999",
            }
        ]
        xml_path = write_junit_report(self.td_path, cases)
        xml_content = xml_path.read_text()
        self.assertNotIn("SuperSecretAdminPassword", xml_content)
        self.assertNotIn("SensitiveShortUuid999", xml_content)

        # 3. Summary TXT
        txt_path = write_summary_txt(self.td_path, data)
        txt_content = txt_path.read_text()
        self.assertNotIn("SuperSecretAdminPassword", txt_content)


if __name__ == "__main__":
    unittest.main()
