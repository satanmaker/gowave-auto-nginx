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

from live_vps.dns import DNSCheckResult
from live_vps.negative import (
    run_neg_10_mtls_forged_certificate,
    run_negative_suite,
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

    @patch("live_vps.negative.verify_domain_dns")
    def test_neg_03_wrong_ip_with_two_resolver_answers_is_pass(self, verify_dns):
        verify_dns.return_value = DNSCheckResult(
            domain="dns.google", expected_ip="198.51.100.1", record_type="A",
            ok=False, resolved_ips=["8.8.8.8"],
            resolver_results={"1.1.1.1": ["8.8.8.8"], "8.8.8.8": ["8.8.8.8"]},
            error="mismatched IP",
        )
        self.assertEqual(run_neg_03_dns_wrong_ip()["status"], "PASS")

    @patch("live_vps.negative.verify_domain_dns")
    def test_neg_03_no_resolver_answers_is_incomplete(self, verify_dns):
        verify_dns.return_value = DNSCheckResult(
            domain="dns.google", expected_ip="198.51.100.1", record_type="A",
            ok=False, resolved_ips=[],
            resolver_results={"1.1.1.1": [], "8.8.8.8": []}, error="timeout",
        )
        self.assertEqual(run_neg_03_dns_wrong_ip()["status"], "INCOMPLETE")

    @patch("live_vps.negative.verify_domain_no_aaaa")
    @patch("live_vps.negative.verify_domain_dns")
    def test_neg_04_missing_aaaa_is_pass_only_with_nodata_proof(self, verify_dns, no_aaaa):
        no_aaaa.return_value = DNSCheckResult(
            domain="ipv4.google.com", expected_ip="NONE", record_type="AAAA",
            ok=True, resolved_ips=[], resolver_results={"1.1.1.1": [], "8.8.8.8": []},
        )
        verify_dns.return_value = DNSCheckResult(
            domain="ipv4.google.com", expected_ip="2001:db8::1", record_type="AAAA",
            ok=False, resolved_ips=[], resolver_results={"1.1.1.1": [], "8.8.8.8": []},
            error="no AAAA",
        )
        self.assertEqual(run_neg_04_dns_missing_aaaa()["status"], "PASS")

    @patch("live_vps.negative.verify_domain_no_aaaa")
    def test_neg_04_dns_failure_is_incomplete(self, no_aaaa):
        no_aaaa.return_value = DNSCheckResult(
            domain="ipv4.google.com", expected_ip="NONE", record_type="AAAA",
            ok=False, resolved_ips=[], resolver_results={"1.1.1.1": [], "8.8.8.8": []},
            error="resolver timeout",
        )
        self.assertEqual(run_neg_04_dns_missing_aaaa()["status"], "INCOMPLETE")

    def test_unimplemented_backup_and_journal_scenarios_are_not_pass(self):
        from live_vps.negative import (
            run_neg_11_backup_corrupted_tar,
            run_neg_12_backup_corrupted_sqlite,
            run_neg_13_worker_deploy_interrupted_journal,
        )
        ssh = MagicMock()
        self.assertEqual(run_neg_11_backup_corrupted_tar(ssh)["status"], "INCOMPLETE")
        self.assertEqual(run_neg_12_backup_corrupted_sqlite(ssh)["status"], "INCOMPLETE")
        self.assertEqual(run_neg_13_worker_deploy_interrupted_journal(ssh)["status"], "INCOMPLETE")

    @patch("live_vps.negative.run_mtls_negative_tests")
    def test_neg_10_uses_valid_sni_and_trusted_server_path(self, mtls_negative):
        mtls_negative.return_value = {
            "status": "FAIL",
            "untrusted_client_rejected": True,
            "wrong_sni_rejected": False,
        }
        result = run_neg_10_mtls_forged_certificate(MagicMock(), "203.0.113.20")
        self.assertEqual(result["status"], "PASS")
        mtls_negative.assert_called_once()

    @patch("live_vps.negative.run_neg_06_nginx_config_syntax_corruption")
    @patch("live_vps.negative.run_neg_05_acme_install_failure", return_value={"status": "INCOMPLETE"})
    @patch("live_vps.negative.run_neg_04_dns_missing_aaaa", return_value={"status": "PASS"})
    @patch("live_vps.negative.run_neg_03_dns_wrong_ip", return_value={"status": "PASS"})
    @patch("live_vps.negative.run_neg_02_ssh_port_unreachable", return_value={"status": "PASS"})
    @patch("live_vps.negative.run_neg_01_ssh_host_key_absent", return_value={"status": "PASS"})
    def test_failed_acme_negative_gate_stops_later_live_mutations(
        self, neg01, neg02, neg03, neg04, neg05, neg06
    ):
        config = MagicMock()
        config.test_negative_suite = True
        result = run_negative_suite(config, master_ssh=MagicMock())
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(result["scenarios"][4]["status"], "INCOMPLETE")
        self.assertTrue(all(item["status"] == "INCOMPLETE" for item in result["scenarios"][5:]))
        neg06.assert_not_called()

    def test_neg_10_unreachable_worker_is_incomplete(self):
        from types import SimpleNamespace
        from live_vps.negative import run_neg_10_mtls_forged_certificate
        ssh = MagicMock()
        ssh.run.return_value = SimpleNamespace(
            returncode=0, ok=True, stdout="CONNECT_INCOMPLETE:TimeoutError", stderr=""
        )
        self.assertEqual(run_neg_10_mtls_forged_certificate(ssh, "203.0.113.20")["status"], "INCOMPLETE")

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
