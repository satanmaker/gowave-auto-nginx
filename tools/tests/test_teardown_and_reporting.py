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

    def test_execute_teardown_restore_snapshot_success(self):
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

        res = execute_teardown(config, "run-123", master_ssh=None, worker_ssh=None)
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["policy"], "RESTORE_SNAPSHOT")

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
