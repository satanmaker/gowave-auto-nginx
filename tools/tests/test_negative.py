#!/usr/bin/env python3
"""Unit tests for negative scenarios module and suite status gate."""
from __future__ import annotations

import json
import unittest
from pathlib import Path
import sys
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT))

from live_vps.dns import DNSCheckResult
from live_vps.ssh import SSHResult
from live_vps.negative import (
    run_neg_05_acme_install_failure,
    run_neg_10_mtls_forged_certificate,
    run_negative_suite,
    run_neg_01_ssh_host_key_absent,
    run_neg_02_ssh_port_unreachable,
    run_neg_03_dns_wrong_ip,
    run_neg_04_dns_missing_aaaa,
)


class FakeSSH:
    """Minimal SSH stand-in that answers by matching the remote command text."""

    def __init__(self, handler, holder_pids=("4242",)):
        self._handler = handler
        #: What the run's own lock holder published, in reading order; the last
        #: entry repeats once the list is exhausted. A scenario reads it twice:
        #: before its mutation and after it.
        self._holder_pids = list(holder_pids)
        self._holder_reads = 0
        self.calls = []
        self.inputs = []

    def run(self, remote_cmd, input_data=None, timeout=60):
        self.calls.append(remote_cmd)
        self.inputs.append((remote_cmd, input_data))
        if "['holder_pid']" in remote_cmd:
            if not self._holder_pids:
                return SSHResult(1, "", "")
            value = self._holder_pids[min(self._holder_reads, len(self._holder_pids) - 1)]
            self._holder_reads += 1
            return SSHResult(0, f"{value}\n", "")
        return self._handler(remote_cmd)


STALE_NODE_ADD_JOURNAL = {
    "op": "node_add",
    "state": "NODE_ADD_ROLLED_BACK",
    "node_name": "neg13-interrupt",
}


class TestNegativeScenarios(unittest.TestCase):
    def test_neg_01_host_key_absent(self):
        res = run_neg_01_ssh_host_key_absent()
        self.assertEqual(res["scenario"], "NEG-01")
        self.assertEqual(res["status"], "PASS")

    @patch("live_vps.negative.socket.create_connection", side_effect=ConnectionRefusedError)
    def test_neg_02_refused_connection_is_a_proven_rejection(self, create_connection):
        result = run_neg_02_ssh_port_unreachable()

        self.assertEqual(result["scenario"], "NEG-02")
        self.assertEqual(result["status"], "PASS")
        create_connection.assert_called_once_with(("127.0.0.1", 59998), timeout=0.5)

    @patch("live_vps.negative.socket.create_connection")
    def test_neg_02_open_port_is_a_negative_test_failure(self, create_connection):
        connection = MagicMock()
        create_connection.return_value.__enter__.return_value = connection

        result = run_neg_02_ssh_port_unreachable()

        self.assertEqual(result["scenario"], "NEG-02")
        self.assertEqual(result["status"], "FAIL")
        create_connection.assert_called_once_with(("127.0.0.1", 59998), timeout=0.5)

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

    def test_neg_11_rejects_corrupted_header_before_mutating(self):
        from live_vps.negative import run_neg_11_backup_corrupted_tar

        def handler(cmd):
            if "backup --type panel" in cmd:
                return SSHResult(0, "", "")
            if cmd.startswith("dd "):
                return SSHResult(0, "", "")
            if "sha256sum -- /opt/gowave/gowave.db" in cmd:
                return SSHResult(0, "dbhash  -\n", "")
            if "sha256sum -- /var/lib/gowave-auto-nginx/recovery/journal.json" in cmd:
                return SSHResult(0, "journalhash  -\n", "")
            if "systemctl is-active" in cmd:
                return SSHResult(0, "", "")
            if " restore " in cmd:
                return SSHResult(1, "", "Validation Error: truncated header")
            return SSHResult(0, "", "")

        result = run_neg_11_backup_corrupted_tar(FakeSSH(handler), MagicMock(restore_timeout=120))
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["journal_untouched"])
        self.assertTrue(result["service_kept_active"])

    def test_neg_11_successful_restore_is_fail(self):
        from live_vps.negative import run_neg_11_backup_corrupted_tar

        def handler(cmd):
            if "sha256sum -- /opt/gowave/gowave.db" in cmd:
                return SSHResult(0, "dbhash  -\n", "")
            if "sha256sum -- /var/lib/gowave-auto-nginx/recovery/journal.json" in cmd:
                return SSHResult(0, "journalhash  -\n", "")
            if " restore " in cmd:
                return SSHResult(0, "Restore completed", "")
            return SSHResult(0, "", "")

        result = run_neg_11_backup_corrupted_tar(FakeSSH(handler), MagicMock(restore_timeout=120))
        self.assertEqual(result["status"], "FAIL")

    def test_neg_12_rejects_corrupted_database_at_integrity_gate(self):
        from live_vps.negative import run_neg_12_backup_corrupted_sqlite

        def handler(cmd):
            if "sha256sum -- /opt/gowave/gowave.db" in cmd:
                return SSHResult(0, "dbhash  -\n", "")
            if "sha256sum -- /var/lib/gowave-auto-nginx/recovery/journal.json" in cmd:
                return SSHResult(0, "journalhash  -\n", "")
            if "systemctl is-active" in cmd:
                return SSHResult(0, "", "")
            if " restore " in cmd:
                return SSHResult(1, "", "Pre-restore check failed: staged database integrity check returned: corrupt")
            return SSHResult(0, "", "")

        result = run_neg_12_backup_corrupted_sqlite(FakeSSH(handler), MagicMock(restore_timeout=120))
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["rejected"])
        self.assertTrue(result["live_data_unchanged"])

    def test_neg_12_mutated_live_database_is_fail(self):
        from live_vps.negative import run_neg_12_backup_corrupted_sqlite

        hashes = iter(("before  -", "after  -"))

        def handler(cmd):
            if "sha256sum -- /opt/gowave/gowave.db" in cmd:
                return SSHResult(0, next(hashes, "after  -") + "\n", "")
            if "sha256sum -- /var/lib/gowave-auto-nginx/recovery/journal.json" in cmd:
                return SSHResult(0, "journalhash  -\n", "")
            if " restore " in cmd:
                return SSHResult(1, "", "Pre-restore check failed: staged database integrity check returned: corrupt")
            return SSHResult(0, "", "")

        result = run_neg_12_backup_corrupted_sqlite(FakeSSH(handler), MagicMock(restore_timeout=120))
        self.assertEqual(result["status"], "FAIL")

    def test_neg_13_interrupted_dispatch_leaves_journal_uncommitted(self):
        from live_vps.negative import run_neg_13_worker_deploy_interrupted_journal

        journal = {"op": "node_add", "state": "NODE_ADD_VERIFYING", "node_name": "neg13-interrupt"}
        journal_reads = []

        def handler(cmd):
            if "cat /var/lib/gowave-auto-nginx/state.json" in cmd:
                return SSHResult(0, json.dumps({"nodes": []}), "")
            if "nohup setsid" in cmd:
                return SSHResult(0, "PID:4242\n", "")
            if "cat /var/lib/gowave-auto-nginx/recovery/journal.json" in cmd:
                journal_reads.append(True)
                served = STALE_NODE_ADD_JOURNAL if len(journal_reads) == 1 else journal
                return SSHResult(0, json.dumps(served), "")
            if "kill -0 -4242" in cmd:
                return SSHResult(1, "", "")
            if "validate_journal" in cmd:
                return SSHResult(0, "", "")
            if "rollback_provisioning" in cmd:
                journal["state"] = "NODE_ADD_ROLLED_BACK"
                return SSHResult(0, "", "")
            return SSHResult(0, "", "")

        config = MagicMock(
            restore_timeout=120, worker_ssh_user="root", worker_ssh_port=22,
        )
        result = run_neg_13_worker_deploy_interrupted_journal(FakeSSH(handler), config)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["post_kill_journal_state"], "NODE_ADD_VERIFYING")
        self.assertTrue(result["state_restored"])
        self.assertTrue(result["lock_kept_by_the_run"])
        self.assertEqual(result["rollback_journal_state"], "NODE_ADD_ROLLED_BACK")

    def test_neg_13_dispatch_without_verifying_state_is_incomplete(self):
        from live_vps.negative import run_neg_13_worker_deploy_interrupted_journal

        journal = {"op": "node_add", "state": "NODE_ADD_COMMITTED", "node_name": "neg13-interrupt"}
        journal_reads = []

        def handler(cmd):
            if "cat /var/lib/gowave-auto-nginx/state.json" in cmd:
                return SSHResult(0, json.dumps({"nodes": []}), "")
            if "nohup setsid" in cmd:
                return SSHResult(0, "PID:4242\n", "")
            if "cat /var/lib/gowave-auto-nginx/recovery/journal.json" in cmd:
                journal_reads.append(True)
                served = STALE_NODE_ADD_JOURNAL if len(journal_reads) == 1 else journal
                return SSHResult(0, json.dumps(served), "")
            if "kill -0 4242" in cmd:
                return SSHResult(1, "", "")
            if "kill -0 -4242" in cmd:
                return SSHResult(1, "", "")
            return SSHResult(0, "", "")

        config = MagicMock(restore_timeout=120, worker_ssh_user="root", worker_ssh_port=22)
        result = run_neg_13_worker_deploy_interrupted_journal(FakeSSH(handler), config)
        self.assertEqual(result["status"], "INCOMPLETE")

    def test_neg_13_volatile_state_fields_do_not_mask_restoration(self):
        from live_vps.negative import run_neg_13_worker_deploy_interrupted_journal

        journal = {"op": "node_add", "state": "NODE_ADD_VERIFYING", "node_name": "neg13-interrupt"}
        state_reads = []
        journal_reads = []

        def handler(cmd):
            if "cat /var/lib/gowave-auto-nginx/state.json" in cmd:
                state_reads.append(True)
                stamp = "2026-11-11T20:00:00Z" if len(state_reads) == 1 else "2026-11-11T20:00:05Z"
                return SSHResult(0, json.dumps(
                    {"schemaVersion": 2, "lastUpdated": stamp, "nodes": []}
                ), "")
            if "nohup setsid" in cmd:
                return SSHResult(0, "PID:4242\n", "")
            if "cat /var/lib/gowave-auto-nginx/recovery/journal.json" in cmd:
                journal_reads.append(True)
                served = STALE_NODE_ADD_JOURNAL if len(journal_reads) == 1 else journal
                return SSHResult(0, json.dumps(served), "")
            if "kill -0 -4242" in cmd:
                return SSHResult(1, "", "")
            if "validate_journal" in cmd:
                return SSHResult(0, "", "")
            if "rollback_provisioning" in cmd:
                journal["state"] = "NODE_ADD_ROLLED_BACK"
                return SSHResult(0, "", "")
            return SSHResult(0, "", "")

        config = MagicMock(restore_timeout=120, worker_ssh_user="root", worker_ssh_port=22)
        result = run_neg_13_worker_deploy_interrupted_journal(FakeSSH(handler), config)
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["state_restored"])

    def test_neg_13_orphan_node_entry_is_not_restored(self):
        from live_vps.negative import run_neg_13_worker_deploy_interrupted_journal

        journal = {"op": "node_add", "state": "NODE_ADD_VERIFYING", "node_name": "neg13-interrupt"}
        state_reads = []
        journal_reads = []

        def handler(cmd):
            if "cat /var/lib/gowave-auto-nginx/state.json" in cmd:
                state_reads.append(True)
                nodes = [] if len(state_reads) == 1 else [{"name": "neg13-interrupt"}]
                return SSHResult(0, json.dumps({"nodes": nodes}), "")
            if "nohup setsid" in cmd:
                return SSHResult(0, "PID:4242\n", "")
            if "cat /var/lib/gowave-auto-nginx/recovery/journal.json" in cmd:
                journal_reads.append(True)
                served = STALE_NODE_ADD_JOURNAL if len(journal_reads) == 1 else journal
                return SSHResult(0, json.dumps(served), "")
            if "kill -0 -4242" in cmd:
                return SSHResult(1, "", "")
            if "validate_journal" in cmd:
                return SSHResult(0, "", "")
            if "rollback_provisioning" in cmd:
                journal["state"] = "NODE_ADD_ROLLED_BACK"
                return SSHResult(0, "", "")
            return SSHResult(0, "", "")

        config = MagicMock(restore_timeout=120, worker_ssh_user="root", worker_ssh_port=22)
        result = run_neg_13_worker_deploy_interrupted_journal(FakeSSH(handler), config)
        self.assertFalse(result["state_restored"])
        self.assertEqual(result["status"], "INCOMPLETE")

    def test_neg_13_a_dispatch_that_moves_the_runs_holder_is_incomplete(self):
        from live_vps.negative import run_neg_13_worker_deploy_interrupted_journal

        journal = {"op": "node_add", "state": "NODE_ADD_VERIFYING", "node_name": "neg13-interrupt"}
        journal_reads = []

        def handler(cmd):
            if "cat /var/lib/gowave-auto-nginx/state.json" in cmd:
                return SSHResult(0, json.dumps({"nodes": []}), "")
            if "nohup setsid" in cmd:
                return SSHResult(0, "PID:4242\n", "")
            if "cat /var/lib/gowave-auto-nginx/recovery/journal.json" in cmd:
                journal_reads.append(True)
                served = STALE_NODE_ADD_JOURNAL if len(journal_reads) == 1 else journal
                return SSHResult(0, json.dumps(served), "")
            if "kill -0 -4242" in cmd:
                return SSHResult(1, "", "")
            if "validate_journal" in cmd:
                return SSHResult(0, "", "")
            if "rollback_provisioning" in cmd:
                journal["state"] = "NODE_ADD_ROLLED_BACK"
                return SSHResult(0, "", "")
            return SSHResult(0, "", "")

        config = MagicMock(restore_timeout=120, worker_ssh_user="root", worker_ssh_port=22)
        result = run_neg_13_worker_deploy_interrupted_journal(
            FakeSSH(handler, holder_pids=("4242", "9999")), config
        )
        self.assertFalse(result["lock_kept_by_the_run"])
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertIn("changed the host mutation lock holder", result["message"])

    def test_neg_13_a_dispatch_that_leaves_the_runs_holder_passes(self):
        from live_vps.negative import run_neg_13_worker_deploy_interrupted_journal

        journal = {"op": "node_add", "state": "NODE_ADD_VERIFYING", "node_name": "neg13-interrupt"}
        journal_reads = []

        def handler(cmd):
            if "cat /var/lib/gowave-auto-nginx/state.json" in cmd:
                return SSHResult(0, json.dumps({"nodes": []}), "")
            if "nohup setsid" in cmd:
                return SSHResult(0, "PID:4242\n", "")
            if "cat /var/lib/gowave-auto-nginx/recovery/journal.json" in cmd:
                journal_reads.append(True)
                served = STALE_NODE_ADD_JOURNAL if len(journal_reads) == 1 else journal
                return SSHResult(0, json.dumps(served), "")
            if "kill -0 -4242" in cmd:
                return SSHResult(1, "", "")
            if "validate_journal" in cmd:
                return SSHResult(0, "", "")
            if "rollback_provisioning" in cmd:
                journal["state"] = "NODE_ADD_ROLLED_BACK"
                return SSHResult(0, "", "")
            return SSHResult(0, "", "")

        config = MagicMock(restore_timeout=120, worker_ssh_user="root", worker_ssh_port=22)
        result = run_neg_13_worker_deploy_interrupted_journal(FakeSSH(handler), config)
        self.assertTrue(result["lock_kept_by_the_run"])
        self.assertEqual(result["status"], "PASS")

    def test_neg_11_a_restore_the_lock_refuses_is_incomplete(self):
        from live_vps.negative import run_neg_11_backup_corrupted_tar

        def handler(cmd):
            if "sha256sum -- /opt/gowave/gowave.db" in cmd:
                return SSHResult(0, "dbhash  -\n", "")
            if "sha256sum -- /var/lib/gowave-auto-nginx/recovery/journal.json" in cmd:
                return SSHResult(0, "journalhash  -\n", "")
            if " restore " in cmd:
                return SSHResult(1, "", "Could not acquire host mutation lock")
            return SSHResult(0, "", "")

        fake = FakeSSH(handler)
        result = run_neg_11_backup_corrupted_tar(fake, MagicMock(restore_timeout=120))
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertFalse(result["lease_presented"])
        # The lock refusal is the product's answer to a restore it was handed,
        # not a reason to stop before handing it one.
        self.assertTrue(any(" restore " in call for call in fake.calls))

    def test_neg_13_committed_after_interruption_is_fail(self):
        from live_vps.negative import run_neg_13_worker_deploy_interrupted_journal

        reads = []

        def handler(cmd):
            if "cat /var/lib/gowave-auto-nginx/state.json" in cmd:
                return SSHResult(0, json.dumps({"nodes": []}), "")
            if "nohup setsid" in cmd:
                return SSHResult(0, "PID:4242\n", "")
            if "cat /var/lib/gowave-auto-nginx/recovery/journal.json" in cmd:
                reads.append(True)
                if len(reads) == 1:
                    served = STALE_NODE_ADD_JOURNAL
                else:
                    state = "NODE_ADD_VERIFYING" if len(reads) == 2 else "NODE_ADD_COMMITTED"
                    served = {"op": "node_add", "state": state, "node_name": "neg13-interrupt"}
                return SSHResult(0, json.dumps(served), "")
            if "kill -0 -4242" in cmd:
                return SSHResult(1, "", "")
            return SSHResult(0, "", "")

        config = MagicMock(restore_timeout=120, worker_ssh_user="root", worker_ssh_port=22)
        result = run_neg_13_worker_deploy_interrupted_journal(FakeSSH(handler), config)
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["post_kill_journal_state"], "NODE_ADD_COMMITTED")

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

    @patch("live_vps.negative.run_neg_06_nginx_syntax_corruption")
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

    @patch("live_vps.negative.run_mtls_negative_tests", return_value={"status": "INCOMPLETE", "untrusted_client_rejected": "INCOMPLETE"})
    def test_neg_10_unreachable_worker_is_incomplete(self, mtls_negative):
        result = run_neg_10_mtls_forged_certificate(MagicMock(), "203.0.113.20")
        self.assertEqual(result["status"], "INCOMPLETE")
        mtls_negative.assert_called_once()

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


class LeaseRecordingSSH:
    """Records the stdin handed to each remote command, which FakeSSH drops."""

    host = "198.51.100.10"

    def __init__(self, result):
        self._result = result
        self.calls = []

    def run(self, remote_cmd, input_data=None, timeout=60):
        self.calls.append({"cmd": remote_cmd, "input_data": input_data})
        return self._result


ACME_REFUSAL = SSHResult(
    returncode=1,
    stdout="",
    stderr=(
        "Error: Invalid GOWAVE_ACME_SERVER: "
        "'https://invalid-acme-directory.example.com/directory'. Only "
        "'https://acme-staging-v02.api.letsencrypt.org/directory' or "
        "'https://acme-v02.api.letsencrypt.org/directory' are supported.\n"
    ),
)

LOCK_REFUSAL = SSHResult(
    returncode=1,
    stdout="",
    stderr=(
        "Error: Another process currently holds the mutation lock "
        "(/run/lock/gowave-managed-mutation.lock).\n"
        "Refusing concurrent mutation without an authorized re-entrant lease.\n"
    ),
)


class TestNeg05PresentsTheRunsLease(unittest.TestCase):
    def test_the_probe_hands_the_runs_lease_to_the_install_over_stdin(self):
        ssh = LeaseRecordingSSH(ACME_REFUSAL)

        result = run_neg_05_acme_install_failure(
            ssh,
            lease_token="token-of-this-run",
            panel_domain="panel.gowave.test",
            reality_domain="reality.gowave.test",
        )

        self.assertEqual(len(ssh.calls), 1)
        self.assertEqual(ssh.calls[0]["input_data"], "GOWAVE_LEASE: token-of-this-run\n")
        self.assertIn("gowave-auto.sh install", ssh.calls[0]["cmd"])
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["lease_presented"])
        self.assertEqual(result["exit_code"], 1)

    def test_the_install_is_given_the_runs_own_domains_not_an_unresolvable_placeholder(self):
        ssh = LeaseRecordingSSH(ACME_REFUSAL)

        result = run_neg_05_acme_install_failure(
            ssh, panel_domain="panel.gowave.test", reality_domain="reality.gowave.test"
        )

        self.assertEqual(result["status"], "PASS")
        self.assertIn("install panel.gowave.test reality.gowave.test", ssh.calls[0]["cmd"])
        self.assertNotIn("invalid.example.com", ssh.calls[0]["cmd"])

    def test_a_lock_refusal_is_reported_as_a_failure_not_as_the_acme_rejection(self):
        ssh = LeaseRecordingSSH(LOCK_REFUSAL)

        result = run_neg_05_acme_install_failure(
            ssh, panel_domain="panel.gowave.test", reality_domain="reality.gowave.test"
        )

        self.assertIsNone(ssh.calls[0]["input_data"])
        self.assertEqual(result["status"], "FAIL")
        self.assertFalse(result["lease_presented"])
        self.assertIn("Another process currently holds the mutation lock", result["message"])

    @patch("live_vps.negative.run_neg_05_acme_install_failure", return_value={"status": "FAIL"})
    @patch("live_vps.negative.run_neg_04_dns_missing_aaaa", return_value={"status": "PASS"})
    @patch("live_vps.negative.run_neg_03_dns_wrong_ip", return_value={"status": "PASS"})
    @patch("live_vps.negative.run_neg_02_ssh_port_unreachable", return_value={"status": "PASS"})
    @patch("live_vps.negative.run_neg_01_ssh_host_key_absent", return_value={"status": "PASS"})
    def test_the_negative_suite_passes_the_masters_lease_to_the_acme_probe(
        self, neg01, neg02, neg03, neg04, neg05
    ):
        config = MagicMock()
        config.test_negative_suite = True
        config.master_panel_domain = "panel.gowave.test"
        config.master_reality_domain = "reality.gowave.test"
        master_ssh = MagicMock()

        run_negative_suite(
            config, master_ssh=master_ssh, master_lease_token="lease-of-this-run"
        )

        neg05.assert_called_once_with(
            master_ssh,
            lease_token="lease-of-this-run",
            panel_domain="panel.gowave.test",
            reality_domain="reality.gowave.test",
        )


class TestMutatingScenariosStageTheRunsLease(unittest.TestCase):
    """A mutating case runs under the run's own lock, so it hands that lease over."""

    TOKEN = "lease-of-this-run-8f3c"

    def assert_the_token_travelled_as_stdin_only(self, fake):
        self.assertNotIn(
            self.TOKEN,
            "\n".join(fake.calls),
            "the lease token must reach the host over stdin, not on a command line",
        )
        staged = [
            input_data
            for cmd, input_data in fake.inputs
            if cmd.startswith("umask 077 && cat > /run/gowave-negative-lease")
        ]
        self.assertEqual(staged, [f"{self.TOKEN}\n"])

    def test_neg_11_stages_the_lease_for_the_restore_and_removes_it(self):
        from live_vps.negative import run_neg_11_backup_corrupted_tar

        def handler(cmd):
            if "sha256sum -- /opt/gowave/gowave.db" in cmd:
                return SSHResult(0, "dbhash  -\n", "")
            if "sha256sum -- /var/lib/gowave-auto-nginx/recovery/journal.json" in cmd:
                return SSHResult(0, "journalhash  -\n", "")
            if "systemctl is-active" in cmd:
                return SSHResult(0, "", "")
            if " restore " in cmd:
                return SSHResult(1, "", "Validation Error: truncated header")
            return SSHResult(0, "", "")

        fake = FakeSSH(handler)
        result = run_neg_11_backup_corrupted_tar(
            fake, MagicMock(restore_timeout=120), lease_token=self.TOKEN
        )

        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["lease_presented"])
        self.assert_the_token_travelled_as_stdin_only(fake)
        restore = [call for call in fake.calls if " restore " in call]
        self.assertEqual(len(restore), 1)
        self.assertIn("printf 'GOWAVE_LEASE: %s\\n'", restore[0])
        self.assertIn("cat /run/gowave-negative-lease", restore[0])
        self.assertEqual(fake.calls[-1], "rm -f -- /run/gowave-negative-lease")

    def test_neg_14_stages_the_lease_for_the_duplicate_add(self):
        from live_vps.negative import run_neg_14_duplicate_worker_registration

        def handler(cmd):
            if cmd.startswith("sha256sum"):
                return SSHResult(0, "abc123  /var/lib/gowave-auto-nginx/state.json\n", "")
            if "node add" in cmd:
                return SSHResult(1, "", "Error: worker-1 is already registered in state.json\n")
            return SSHResult(0, "", "")

        fake = FakeSSH(handler)
        panel_client = MagicMock()
        for resource in ("get_nodes", "get_config_profiles", "get_internal_squads", "get_hosts"):
            getattr(panel_client, resource).return_value = []
        config = MagicMock(
            worker_ssh_user="root", worker_ssh_port=22,
            worker_domain="worker.example.com",
            worker_reality_domain="worker-reality.example.com",
        )

        result = run_neg_14_duplicate_worker_registration(
            fake, "203.0.113.30", config, panel_client, lease_token=self.TOKEN
        )

        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["lease_presented"])
        self.assert_the_token_travelled_as_stdin_only(fake)
        add = [call for call in fake.calls if "node add" in call]
        self.assertEqual(len(add), 1)
        self.assertIn("cat /run/gowave-negative-lease", add[0])
        self.assertIn("rm -f -- /run/gowave-negative-lease", fake.calls)


if __name__ == "__main__":
    unittest.main()
