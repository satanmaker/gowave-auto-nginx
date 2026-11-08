#!/usr/bin/env python3
"""Unit tests for negative scenarios module and suite status gate."""
from __future__ import annotations

import unittest
from pathlib import Path
import sys
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT))

from live_vps.negative import (
    run_neg_01_ssh_host_key_absent,
    run_neg_02_ssh_port_unreachable,
    run_neg_03_dns_wrong_ip,
    run_neg_04_dns_missing_aaaa,
    run_negative_suite,
)


class TestNegativeScenarios(unittest.TestCase):
    def test_neg_01_host_key_absent(self):
        res = run_neg_01_ssh_host_key_absent()
        self.assertEqual(res["scenario"], "NEG-01")
        self.assertEqual(res["status"], "PASS")

    def test_neg_02_unreachable_port(self):
        res = run_neg_02_ssh_port_unreachable()
        self.assertEqual(res["scenario"], "NEG-02")
        self.assertEqual(res["status"], "PASS")

    def test_neg_03_dns_wrong_ip(self):
        res = run_neg_03_dns_wrong_ip()
        self.assertEqual(res["scenario"], "NEG-03")
        self.assertEqual(res["status"], "PASS")

    def test_neg_04_dns_missing_aaaa(self):
        res = run_neg_04_dns_missing_aaaa()
        self.assertEqual(res["scenario"], "NEG-04")
        self.assertEqual(res["status"], "PASS")

    def test_negative_suite_disabled_produces_incomplete(self):
        config = MagicMock()
        config.test_negative_suite = False

        res = run_negative_suite(config)
        self.assertEqual(res["status"], "INCOMPLETE")
        self.assertEqual(res["skipped_count"], 15)
        self.assertEqual(res["passed_count"], 0)
        self.assertEqual(res["failed_count"], 0)
        self.assertEqual(len(res["scenarios"]), 15)
        for s in res["scenarios"]:
            self.assertEqual(s["status"], "SKIP")


if __name__ == "__main__":
    unittest.main()
