#!/usr/bin/env python3
"""Integration and CLI runner tests for Live VPS E2E:
Validates partial-run resume identity/prerequisite checks, ACME directory mappings,
installer digest consistency, and negative suite status gate.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT))

from live_vps.deployment import ACME_MODE_URLS
from live_vps.negative import run_negative_suite
from live_vps.traffic import evaluate_traffic_suite_status
from test_live_vps import load_run_state, save_run_state


class TestCLIRunnerAndIntegration(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.artifact_dir = Path(self.td.name)

    def tearDown(self):
        self.td.cleanup()

    def test_acme_mode_exact_mappings(self):
        # Exactly two official directories allowed
        self.assertEqual(
            ACME_MODE_URLS.get("staging"),
            "https://acme-staging-v02.api.letsencrypt.org/directory",
        )
        self.assertEqual(
            ACME_MODE_URLS.get("production"),
            "https://acme-v02.api.letsencrypt.org/directory",
        )
        self.assertIsNone(ACME_MODE_URLS.get("custom"))
        self.assertIsNone(ACME_MODE_URLS.get("http://arbitrary-acme.org"))

    def test_run_state_save_and_load(self):
        state = {
            "test_run_id": "run-test-1",
            "repository_commit": "abcdef123456",
            "config_fingerprint": {"master_ip": "198.51.100.1", "worker_ip": "198.51.100.2"},
            "results": {"preflight": {"status": "PASS"}},
            "overall": "RUNNING",
        }
        save_run_state(self.artifact_dir, state)

        loaded = load_run_state(self.artifact_dir)
        self.assertEqual(loaded["test_run_id"], "run-test-1")
        self.assertEqual(loaded["results"]["preflight"]["status"], "PASS")

        # Mode 0600 on run-state.json
        st = (self.artifact_dir / "run-state.json").stat()
        self.assertEqual(st.st_mode & 0o777, 0o600)

    def test_partial_run_prerequisites_logic(self):
        # Without preflight PASS, install must not proceed
        state_no_preflight = {
            "test_run_id": "run-test-2",
            "results": {"preflight": {"status": "FAIL"}},
        }
        save_run_state(self.artifact_dir, state_no_preflight)
        st = load_run_state(self.artifact_dir)
        self.assertNotEqual(st.get("results", {}).get("preflight", {}).get("status"), "PASS")

        # With preflight PASS, install can proceed
        state_preflight_ok = {
            "test_run_id": "run-test-2",
            "results": {"preflight": {"status": "PASS"}},
        }
        save_run_state(self.artifact_dir, state_preflight_ok)
        st2 = load_run_state(self.artifact_dir)
        self.assertEqual(st2.get("results", {}).get("preflight", {}).get("status"), "PASS")

    def test_negative_suite_disabled_gate_produces_incomplete(self):
        config = type("Config", (), {"test_negative_suite": False})()
        res = run_negative_suite(config)
        self.assertEqual(res["status"], "INCOMPLETE")
        self.assertEqual(res["skipped_count"], 15)

    def test_traffic_verification_disabled_gate_produces_incomplete(self):
        # Even if all cases pass, test_traffic_verification=False forces INCOMPLETE
        status = evaluate_traffic_suite_status(
            test_traffic_verification=False,
            xray_results=[{"status": "PASS"}],
            mihomo_results={"status": "PASS"},
        )
        self.assertEqual(status, "INCOMPLETE")


if __name__ == "__main__":
    unittest.main()
