#!/usr/bin/env python3
"""Unit tests for traffic module and traffic verification status gate."""
from __future__ import annotations

import unittest
from pathlib import Path
import sys
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT))

from live_vps.traffic import (
    evaluate_traffic_suite_status,
    get_server_rx_packets,
    run_mihomo_traffic_suite,
)


class TestTrafficModule(unittest.TestCase):
    def test_status_gate_when_traffic_verification_disabled(self):
        # TEST_TRAFFIC_VERIFICATION=false MUST force INCOMPLETE, never PASS
        status = evaluate_traffic_suite_status(
            test_traffic_verification=False,
            xray_results=[{"status": "PASS"}],
            mihomo_results={"status": "PASS"},
        )
        self.assertEqual(status, "INCOMPLETE")

    def test_status_gate_when_mihomo_incomplete(self):
        # When Mihomo suite is INCOMPLETE (e.g. skipped), overall traffic is INCOMPLETE
        status = evaluate_traffic_suite_status(
            test_traffic_verification=True,
            xray_results=[{"status": "PASS"}],
            mihomo_results={"status": "INCOMPLETE", "skipped": True},
        )
        self.assertEqual(status, "INCOMPLETE")

    def test_status_gate_when_case_fails(self):
        status = evaluate_traffic_suite_status(
            test_traffic_verification=True,
            xray_results=[{"status": "PASS"}, {"status": "FAIL"}],
            mihomo_results={"status": "PASS"},
        )
        self.assertEqual(status, "FAIL")

    def test_status_gate_when_all_pass(self):
        status = evaluate_traffic_suite_status(
            test_traffic_verification=True,
            xray_results=[{"status": "PASS"}, {"status": "PASS"}],
            mihomo_results={"status": "PASS"},
        )
        self.assertEqual(status, "PASS")

    def test_get_server_rx_packets_proc_net_dev(self):
        mock_ssh = MagicMock()
        mock_ssh.run.return_value = MagicMock(
            ok=True,
            stdout="1234567\n",
        )
        count = get_server_rx_packets(mock_ssh)
        self.assertEqual(count, 1234567)

    def test_mihomo_traffic_disabled_config_returns_incomplete(self):
        config = MagicMock()
        config.test_mihomo_traffic = False

        res = run_mihomo_traffic_suite(
            subscription_yaml_str="proxies: []",
            ca_bundle_path=Path("/tmp/ca.crt"),
            config=config,
            master_ssh=MagicMock(),
            worker_ssh=MagicMock(),
        )
        self.assertEqual(res["status"], "INCOMPLETE")
        self.assertTrue(res.get("skipped"))


if __name__ == "__main__":
    unittest.main()
