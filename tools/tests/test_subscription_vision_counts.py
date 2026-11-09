#!/usr/bin/env python3
"""Regression tests for subscription endpoint counts with independent Vision domains."""
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from live_vps.subscriptions import expected_proxy_count


class TestSubscriptionVisionCounts(unittest.TestCase):
    def test_core_topology_has_eight_endpoints(self):
        self.assertEqual(expected_proxy_count(), 8)
        self.assertEqual(expected_proxy_count(vision_count=0), 8)

    def test_master_only_or_worker_only_vision_adds_one_endpoint(self):
        self.assertEqual(expected_proxy_count(vision_count=1), 9)

    def test_both_vision_domains_add_two_endpoints(self):
        self.assertEqual(expected_proxy_count(vision_count=2), 10)

    def test_legacy_boolean_contract_remains_compatible(self):
        self.assertEqual(expected_proxy_count(has_vision=False), 8)
        self.assertEqual(expected_proxy_count(has_vision=True), 10)

    def test_invalid_vision_count_is_rejected(self):
        for value in (-1, 3, True):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    expected_proxy_count(vision_count=value)


if __name__ == "__main__":
    unittest.main()
