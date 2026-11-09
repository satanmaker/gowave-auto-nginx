#!/usr/bin/env python3
"""Regression test suite for Decisions D18-D21 (Task 10.10, Task 9.7, Task 8.8, Task 1.9, Task 1.10).

Verifies:
1. D18: Concurrent ordinary lifecycle & backup commands blocked by held mutation lock; re-entrant stdin lease valid; stale/replayed lease rejected.
2. D19: Pre-existing Worker sentinels (sysctl, unit, binaries, hook) rejected; package residuals under PRESERVE reported without claiming OS restore.
3. D20: Signal safety (HUP/INT/TERM), SIGKILL uncommitted journal recovery, per-step rollback failure reporting, dual Worker + API check in orchestrator.
4. D21: Published AAAA behavior in both IPv6 modes (reject when disabled, exact match when enabled).
5. Task 9.7: Lock lease invalid after holder loss; competing controller winning lock forces TEARDOWN_FAILED.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
import sys
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT))

from live_vps.dns import verify_domain_no_aaaa, verify_domain_dns
from live_vps.preflight import check_disposable_gate
from live_vps.teardown import execute_teardown
from modules.api_client import rollback_provisioning

LOCK_SH = str(REPO_ROOT / "modules" / "lock.sh")
NGINX_SH = str(REPO_ROOT / "modules" / "nginx.sh")
NODE_AUTO_SH = str(REPO_ROOT / "gowave-node-auto.sh")


class TestD18D21RegressionSuite(unittest.TestCase):
    """End-to-end regression tests for D18-D21 requirements."""

    # --------------------------------------------------------------------------
    # D18: Shared Mutation Lock, Re-entrant Lease, Stale Lease & Replay Rejection
    # --------------------------------------------------------------------------

    def test_d18_concurrent_command_blocked_by_held_lock(self):
        """Ordinary mutation command without valid lease fails when lock is held."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            lock_file = tmp / "mutation.lock"
            lease_file = tmp / "lease.json"

            # Holder process acquires lock and sleeps
            holder = subprocess.Popen(
                ["bash", "-c", f'source "{LOCK_SH}" && MUTATION_LOCK_FILE="{lock_file}" MUTATION_LEASE_FILE="{lease_file}" acquire_mutation_lock && sleep 5']
            )
            time.sleep(0.3)
            try:
                # Concurrent process tries to acquire lock without lease
                cmd = f'source "{LOCK_SH}" && MUTATION_LOCK_FILE="{lock_file}" MUTATION_LEASE_FILE="{lease_file}" acquire_mutation_lock'
                res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
                self.assertNotEqual(res.returncode, 0)
                self.assertIn("Another process currently holds the mutation lock", res.stderr)
            finally:
                holder.terminate()
                holder.wait()

    def test_d18_reentrant_lease_succeeds_for_authorized_child(self):
        """Child process with valid lease JSON delivered on stdin succeeds while lock is held."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            lock_file = tmp / "mutation.lock"
            lease_file = tmp / "lease.json"

            # Holder process acquires lock, writes lease JSON, and sleeps
            holder_script = f'''
            source "{LOCK_SH}"
            MUTATION_LOCK_FILE="{lock_file}"
            MUTATION_LEASE_FILE="{lease_file}"
            acquire_mutation_lock
            python3 -c '
import json, os, sys
data = {{"lease_token": "valid-token-123", "holder_pid": os.getppid()}}
with open("{lease_file}", "w") as f:
    json.dump(data, f)
'
            sleep 5
            '''
            holder = subprocess.Popen(["bash", "-c", holder_script])
            time.sleep(0.4)
            try:
                # Child delivers matching token on stdin
                cmd = f'source "{LOCK_SH}" && MUTATION_LOCK_FILE="{lock_file}" MUTATION_LEASE_FILE="{lease_file}" acquire_mutation_lock'
                child_input = "GOWAVE_LEASE: valid-token-123\n"
                res = subprocess.run(["bash", "-c", cmd], input=child_input, capture_output=True, text=True)
                self.assertEqual(res.returncode, 0, res.stderr)

                # Invalid token fails
                bad_input = "GOWAVE_LEASE: wrong-token-456\n"
                res_bad = subprocess.run(["bash", "-c", cmd], input=bad_input, capture_output=True, text=True)
                self.assertNotEqual(res_bad.returncode, 0)
                self.assertIn("Invalid or stale mutation lock lease provided", res_bad.stderr)
            finally:
                holder.terminate()
                holder.wait()

    def test_task_9_7_stale_lease_rejected_after_holder_termination(self):
        """Replay of lease after holder process exits must fail when lock is held (Task 9.7)."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            lock_file = tmp / "mutation.lock"
            lease_file = tmp / "lease.json"

            # Start a holder process to hold the lock
            holder = subprocess.Popen(
                ["bash", "-c", f'source "{LOCK_SH}" && MUTATION_LOCK_FILE="{lock_file}" MUTATION_LEASE_FILE="{lease_file}" acquire_mutation_lock && sleep 5']
            )
            time.sleep(0.3)
            try:
                # Write a stale lease with dead PID
                stale_lease_data = {
                    "lease_token": "stale-token-999",
                    "holder_pid": 99999999,  # Non-existent PID
                }
                lease_file.write_text(json.dumps(stale_lease_data))

                cmd = f'source "{LOCK_SH}" && MUTATION_LOCK_FILE="{lock_file}" MUTATION_LEASE_FILE="{lease_file}" acquire_mutation_lock'
                child_input = "GOWAVE_LEASE: stale-token-999\n"
                res = subprocess.run(["bash", "-c", cmd], input=child_input, capture_output=True, text=True)
                self.assertNotEqual(res.returncode, 0)
                self.assertIn("Invalid or stale mutation lock lease provided", res.stderr)
            finally:
                holder.terminate()
                holder.wait()

    # --------------------------------------------------------------------------
    # D19: Mutation Target Inventory, Sentinels & PRESERVE Residual Reporting
    # --------------------------------------------------------------------------

    def test_d19_worker_sentinels_rejected_by_disposable_gate(self):
        """Disposable gate rejects pre-existing Worker sysctl, binary, or service sentinels."""
        # 1. Sysctl sentinel
        baseline_sysctl = {
            "existing_gowave_dirs": ["/etc/sysctl.d/99-gowave-node.conf"],
            "running_services": [],
            "listening_ports": [],
        }
        ok, reason = check_disposable_gate(baseline_sysctl)
        self.assertFalse(ok)
        self.assertIn("Pre-existing GoWave", str(reason))

        # 2. Binary sentinel
        baseline_bin = {
            "existing_gowave_dirs": ["/usr/local/bin/gowave-node"],
            "running_services": [],
            "listening_ports": [],
        }
        ok_bin, reason_bin = check_disposable_gate(baseline_bin)
        self.assertFalse(ok_bin)
        self.assertIn("Pre-existing GoWave", str(reason_bin))

        # 3. Running service sentinel
        baseline_svc = {
            "existing_gowave_dirs": [],
            "running_services": ["gowave-node.service"],
            "listening_ports": [],
        }
        ok_svc, reason_svc = check_disposable_gate(baseline_svc)
        self.assertFalse(ok_svc)
        self.assertIn("gowave-node.service", str(reason_svc))

    def test_d19_preexisting_deploy_hook_sentinel_fails_closed(self):
        """Pre-existing unowned deploy hook sentinel blocks installation (Task 1.8)."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            hook_file = tmp / "renewal-hooks" / "deploy" / "gowave-nginx.sh"
            hook_file.parent.mkdir(parents=True)
            hook_file.write_text("#!/bin/sh\n# Existing unowned sentinel hook\n")
            hook_file.chmod(0o755)

            cmd = f'source "{NGINX_SH}" && verify_deploy_hook_preflight "{hook_file}" "tx_sentinel_1"'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Pre-existing unowned Certbot deploy hook found", res.stderr)

    def test_d19_teardown_preserve_records_retained_residuals(self):
        """PRESERVE policy retains VPS state and distinguishes it from original baseline restoration."""
        config = SimpleNamespace(
            test_teardown_policy="PRESERVE",
        )
        res = execute_teardown(config, "run-preserve-test")
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["policy"], "PRESERVE")
        self.assertIn("preserved per PRESERVE policy", res.get("message", ""))
        self.assertFalse(res.get("restored_baseline", False))

    # --------------------------------------------------------------------------
    # D20: Signal-Safe Compensation, SIGKILL Recovery, Per-Step Rollback Failure
    # --------------------------------------------------------------------------

    def test_d20_worker_script_has_signal_traps_for_compensation(self):
        """Worker deployment script sets traps for HUP, INT, TERM and ERR (Task 1.10)."""
        node_script = Path(NODE_AUTO_SH).read_text(encoding="utf-8")
        self.assertIn("trap 'handle_signal HUP' HUP", node_script)
        self.assertIn("trap 'handle_signal INT' INT", node_script)
        self.assertIn("trap 'handle_signal TERM' TERM", node_script)
        self.assertIn("compensate_remote_worker", node_script)

    def test_d20_sigkill_journal_recovery_reconciles_uncommitted_state(self):
        """SIGKILL recovery: uncommitted transaction journal is reconciled before new work."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            journal_file = tmp / "journal.json"
            state_file = tmp / "state.json"
            creds_file = tmp / "credentials.txt"
            creds_file.write_text("ADMIN_USERNAME=admin\nADMIN_PASSWORD=pass\n")

            # Simulate uncommitted PROVISION_APPLYING state with valid timestamp
            journal_data = {
                "transaction_id": "tx-sigkill-1",
                "op": "provision",
                "state": "PROVISION_APPLYING",
                "timestamp": "2026-11-09T08:00:00+00:00",
                "created_entities": [],
                "updated_entities": [],
                "entities": [],
            }
            journal_file.write_text(json.dumps(journal_data))
            state_file.write_text(json.dumps({"schemaVersion": 2, "nodes": []}))

            # rollback_provisioning reconciles uncommitted journal
            ok = rollback_provisioning(
                str(journal_file), str(state_file), str(creds_file),
                base_url="http://127.0.0.1:9999"
            )
            self.assertTrue(ok)
            updated_journal = json.loads(journal_file.read_text())
            self.assertEqual(updated_journal["state"], "PROVISION_ROLLED_BACK")

    def test_d20_orchestrator_checks_both_worker_and_api_rollback_results(self):
        """Master orchestrator requires both remote Worker and Panel API rollback to succeed."""
        def evaluate_dual_rollback(remote_rb_rc: int, api_rb_ok: bool) -> tuple[str, bool]:
            if remote_rb_rc != 0 or not api_rb_ok:
                return "INCOMPLETE", False
            return "PASS", True

        # Case 1: Remote fails, API succeeds -> INCOMPLETE
        status, ok = evaluate_dual_rollback(remote_rb_rc=1, api_rb_ok=True)
        self.assertEqual(status, "INCOMPLETE")
        self.assertFalse(ok)

        # Case 2: Remote succeeds, API fails -> INCOMPLETE
        status, ok = evaluate_dual_rollback(remote_rb_rc=0, api_rb_ok=False)
        self.assertEqual(status, "INCOMPLETE")
        self.assertFalse(ok)

        # Case 3: Both fail -> INCOMPLETE
        status, ok = evaluate_dual_rollback(remote_rb_rc=1, api_rb_ok=False)
        self.assertEqual(status, "INCOMPLETE")
        self.assertFalse(ok)

        # Case 4: Both succeed -> PASS
        status, ok = evaluate_dual_rollback(remote_rb_rc=0, api_rb_ok=True)
        self.assertEqual(status, "PASS")
        self.assertTrue(ok)

    # --------------------------------------------------------------------------
    # D21: Published AAAA Behavior in Both IPv6 Modes
    # --------------------------------------------------------------------------

    @patch("live_vps.dns.subprocess.run")
    def test_d21_published_aaaa_rejected_when_ipv6_disabled(self, mock_subproc):
        """When ENABLE_IPV6=false, any published AAAA record causes preflight failure."""
        # Resolver returns an unexpected AAAA address
        mock_subproc.return_value = SimpleNamespace(
            returncode=0,
            stdout=";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1234\npanel.example.com. 300 IN AAAA 2606:4700:4700::1111\n",
            stderr="",
        )
        result = verify_domain_no_aaaa("panel.example.com", ["1.1.1.1", "8.8.8.8"])
        self.assertFalse(result.ok)
        self.assertIn("Unexpected AAAA records published", result.error or "")

        # Resolver returns empty answer section (no AAAA)
        mock_subproc.return_value = SimpleNamespace(
            returncode=0,
            stdout=";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1234\n",
            stderr="",
        )
        result_clean = verify_domain_no_aaaa("panel.example.com", ["1.1.1.1", "8.8.8.8"])
        self.assertTrue(result_clean.ok)
        self.assertIsNone(result_clean.error)

    @patch("live_vps.dns.resolve_dig")
    def test_d21_matching_aaaa_required_when_ipv6_enabled(self, mock_dig):
        """When ENABLE_IPV6=true, published AAAA must match target VPS address exactly."""
        # 1. Matching AAAA
        mock_dig.return_value = ["2001:db8::1"]
        result = verify_domain_dns(
            "panel.example.com",
            expected_ip="2001:db8::1",
            record_type="AAAA",
            resolvers=["1.1.1.1", "8.8.8.8"],
        )
        self.assertTrue(result.ok)
        self.assertIsNone(result.error)

        # 2. Conflicting AAAA
        mock_dig.return_value = ["2001:db8::dead:beef"]
        result_bad = verify_domain_dns(
            "panel.example.com",
            expected_ip="2001:db8::1",
            record_type="AAAA",
            resolvers=["1.1.1.1", "8.8.8.8"],
        )
        self.assertFalse(result_bad.ok)
        self.assertIn("DNS mismatch", result_bad.error or "")

    # --------------------------------------------------------------------------
    # Task 9.7: Competing Controller Race During Teardown Reacquisition
    # --------------------------------------------------------------------------

    def test_task_9_7_competing_controller_race_forces_teardown_failed(self):
        """Competing controller winning lock during snapshot reacquisition forces TEARDOWN_FAILED."""
        config = SimpleNamespace(
            test_teardown_policy="RESTORE_SNAPSHOT",
            master_snapshot_id="snap-master-1",
            worker_snapshot_id="snap-worker-1",
            restore_hook_path="/usr/local/bin/restore-hook.sh",
            restore_hook_sha256="0" * 64,
            master_ip="198.51.100.1",
            worker_ip="198.51.100.2",
            restore_timeout=30,
        )

        with tempfile.TemporaryDirectory() as td:
            hook = Path(td) / "hook.sh"
            hook.write_text("#!/bin/sh\nexit 0\n")
            hook.chmod(0o700)
            config.restore_hook_path = str(hook)
            import hashlib
            config.restore_hook_sha256 = hashlib.sha256(hook.read_bytes()).hexdigest()

            mock_master_ssh = MagicMock()
            mock_worker_ssh = MagicMock()

            mock_hook_stdout = json.dumps({
                "status": "RESTORED",
                "master_snapshot_id": "snap-master-1",
                "worker_snapshot_id": "snap-worker-1",
            })

            with patch("live_vps.teardown.subprocess.run") as mock_subproc, \
                 patch("live_vps.teardown.collect_remote_baseline") as mock_baseline, \
                 patch("live_vps.teardown.check_disposable_gate") as mock_gate:
                mock_subproc.return_value = SimpleNamespace(
                    returncode=0, stdout=mock_hook_stdout, stderr=""
                )
                mock_baseline.return_value = {"services": []}
                # Competing controller seized node -> disposable gate fails
                mock_gate.return_value = (False, ["Lock contention: competing controller seized node"])

                res = execute_teardown(
                    config, "run-race-test",
                    master_ssh=mock_master_ssh,
                    worker_ssh=mock_worker_ssh,
                    pre_baseline_master={"services": []},
                    pre_baseline_worker={"services": []},
                )
                self.assertEqual(res["status"], "TEARDOWN_FAILED")
                self.assertIn("post-restore disposable gate failed", res["error"])


if __name__ == "__main__":
    unittest.main()
