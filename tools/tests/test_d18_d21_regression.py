#!/usr/bin/env python3
"""Regression test suite for Decisions D18-D21 (Task 10.10, Task 9.7, Task 8.8, Task 1.9, Task 1.10).

Verifies:
1. D18: Concurrent mutation commands are blocked; authorized re-entrant leases work; stale leases are rejected.
2. D19: Pre-existing Worker sentinels and unowned deploy hooks are rejected; PRESERVE is not misreported as baseline restoration.
3. D20: Worker signal traps are present and uncommitted transaction journals can be reconciled.
4. D21: Published AAAA behavior is checked in both IPv6 modes.
5. Task 9.7: Dead-holder lease replay is rejected; a competing controller prevents false teardown success.
"""
from __future__ import annotations

import json
import shlex
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


def _wait_for_file(path: Path, process: subprocess.Popen, timeout: float = 5.0) -> None:
    """Wait for a child-process readiness marker without relying on scheduler sleeps."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            return
        return_code = process.poll()
        if return_code is not None:
            raise AssertionError(f"lock holder exited before readiness (exit={return_code})")
        time.sleep(0.01)
    try:
        process.terminate()
        process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        process.kill()
        process.wait()
    raise AssertionError(f"lock holder did not become ready within {timeout:.1f}s")


def _start_lock_holder(
    lock_file: Path,
    lease_file: Path,
    ready_file: Path,
    before_ready: str = "",
) -> subprocess.Popen:
    """Acquire the mutation lock, publish readiness, and clean up the sleeper on TERM."""
    setup = f"{before_ready} || exit; " if before_ready else ""
    script = (
        f"source {shlex.quote(LOCK_SH)} && "
        f"MUTATION_LOCK_FILE={shlex.quote(str(lock_file))} "
        f"MUTATION_LEASE_FILE={shlex.quote(str(lease_file))} "
        f"acquire_mutation_lock || exit; "
        f"{setup}"
        "sleep 30 & child=$!; "
        "trap 'kill \"$child\" 2>/dev/null || true; "
        "wait \"$child\" 2>/dev/null || true; exit 0' TERM INT; "
        f"touch {shlex.quote(str(ready_file))}; wait \"$child\""
    )
    process = subprocess.Popen(["bash", "-c", script])
    _wait_for_file(ready_file, process)
    return process


class TestD18D21RegressionSuite(unittest.TestCase):
    """Regression tests for D18-D21 lifecycle and safety requirements."""

    # --------------------------------------------------------------------------
    # D18: Shared Mutation Lock, Re-entrant Lease, Stale Lease & Replay Rejection
    # --------------------------------------------------------------------------

    def test_d18_concurrent_command_blocked_by_held_lock(self):
        """Ordinary mutation command without valid lease fails when lock is held."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            lock_file = tmp / "mutation.lock"
            lease_file = tmp / "lease.json"

            ready_file = tmp / "holder.ready"
            holder = _start_lock_holder(lock_file, lease_file, ready_file)
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

            # The holder writes the lease and readiness marker after lock acquisition.
            ready_file = tmp / "holder.ready"
            lease_writer = (
                "import json, os; "
                f"open({str(lease_file)!r}, 'w').write(json.dumps("
                "{'lease_token': 'valid-token-123', 'holder_pid': os.getppid()}))"
            )
            holder = _start_lock_holder(
                lock_file, lease_file, ready_file,
                before_ready=f"python3 -c {shlex.quote(lease_writer)}",
            )
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
        """A lease with a non-live holder PID is rejected while the lock is held (Task 9.7)."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            lock_file = tmp / "mutation.lock"
            lease_file = tmp / "lease.json"

            ready_file = tmp / "holder.ready"
            holder = _start_lock_holder(lock_file, lease_file, ready_file)
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
        """Each pre-existing GoWave-owned path or service blocks disposable eligibility."""
        sentinels = (
            (
                "sysctl configuration",
                {
                    "existing_gowave_dirs": ["/etc/sysctl.d/99-gowave-node.conf"],
                    "running_services": [],
                    "listening_ports": [],
                },
                "Pre-existing GoWave",
            ),
            (
                "worker binary",
                {
                    "existing_gowave_dirs": ["/usr/local/bin/gowave-node"],
                    "running_services": [],
                    "listening_ports": [],
                },
                "Pre-existing GoWave",
            ),
            (
                "worker service",
                {
                    "existing_gowave_dirs": [],
                    "running_services": ["gowave-node.service"],
                    "listening_ports": [],
                },
                "gowave-node.service",
            ),
        )
        for label, baseline, expected_reason in sentinels:
            with self.subTest(sentinel=label):
                eligible, reasons = check_disposable_gate(baseline)
                self.assertFalse(eligible)
                self.assertIn(expected_reason, str(reasons))

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
        self.assertIn(
            """trap 'exit_code=$?; compensate_remote_worker "$exit_code"; exit "$exit_code"' ERR""",
            node_script,
        )
        self.assertIn("trap 'cleanup_temp_and_secrets' EXIT", node_script)
        self.assertIn('if [[ "${_COMPENSATED:-0}" -eq 0 ]]; then', node_script)
        self.assertIn("compensate_remote_worker", node_script)

    def test_d20_uncommitted_journal_recovery_reconciles_state(self):
        """An uncommitted transaction journal is reconciled before new work."""

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            journal_file = tmp / "journal.json"
            state_file = tmp / "state.json"
            # Simulate uncommitted PROVISION_APPLYING state with valid timestamp
            journal_data = {
                "transaction_id": "tx-uncommitted-1",
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
                str(journal_file), str(state_file),
                base_url="http://127.0.0.1:9999"
            )
            self.assertTrue(ok)
            updated_journal = json.loads(journal_file.read_text())
            self.assertEqual(updated_journal["state"], "PROVISION_ROLLED_BACK")

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
