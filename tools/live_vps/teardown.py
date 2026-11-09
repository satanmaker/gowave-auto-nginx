"""Teardown policy execution and provider snapshot restoration.
Supports PRESERVE (retain VPS for triage) and RESTORE_SNAPSHOT (pin-verified hook).
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .config import LiveVPSConfig
from .ssh import SSHClient
from .preflight import collect_remote_baseline, check_disposable_gate


def validate_restore_hook(hook_path_str: str, expected_sha256: str) -> Tuple[bool, Optional[str]]:
    """Validate snapshot restore hook properties: absolute, non-symlink, executable,
    not group/world writable, and matching expected SHA-256.
    """
    if not hook_path_str:
        return False, "Restore hook path is empty"

    p = Path(hook_path_str)
    if not p.is_absolute():
        return False, f"Restore hook path must be absolute: {hook_path_str}"
    if p.is_symlink():
        return False, f"Restore hook must not be a symlink: {hook_path_str}"
    if not p.is_file():
        return False, f"Restore hook file does not exist: {hook_path_str}"

    st = p.stat()
    # Check executable by owner
    if not (st.st_mode & 0o100):
        return False, f"Restore hook is not executable by owner: {hook_path_str}"
    # Check non-group/world-writable
    if st.st_mode & 0o022:
        return False, f"Restore hook must not be group- or world-writable (mode {oct(st.st_mode)}): {hook_path_str}"

    # Verify SHA-256
    file_bytes = p.read_bytes()
    actual_sha = hashlib.sha256(file_bytes).hexdigest().lower()
    if actual_sha != expected_sha256.lower():
        return False, f"Restore hook SHA-256 mismatch: expected {expected_sha256}, got {actual_sha}"

    return True, None


BASELINE_COMPARISON_KEYS = (
    "os_kernel",
    "running_services",
    "tcp_listeners_raw",
    "listening_ports",
    "existing_gowave_dirs",
    "firewall_status",
    "swap_info",
    "key_packages",
)


def compare_captured_baseline(
    before: Dict[str, Any], after: Dict[str, Any]
) -> Tuple[bool, List[str], List[str]]:
    """Compare the stable fields currently captured by preflight."""
    missing = [key for key in BASELINE_COMPARISON_KEYS if key not in before or key not in after]
    changed = [
        key for key in BASELINE_COMPARISON_KEYS
        if key in before and key in after and before[key] != after[key]
    ]
    return not missing and not changed, missing, changed


def execute_teardown(
    config: LiveVPSConfig,
    run_id: str,
    master_ssh: Optional[SSHClient] = None,
    worker_ssh: Optional[SSHClient] = None,
    pre_baseline_master: Optional[Dict[str, Any]] = None,
    pre_baseline_worker: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Execute configured teardown policy (PRESERVE or RESTORE_SNAPSHOT)."""
    policy = config.test_teardown_policy.upper()

    if policy == "PRESERVE":
        return {
            "status": "PASS",
            "policy": "PRESERVE",
            "message": "Both VPS and state preserved per PRESERVE policy",
        }

    if policy != "RESTORE_SNAPSHOT":
        return {
            "status": "FAIL",
            "policy": policy,
            "error": f"Unsupported teardown policy: {policy}",
        }

    # RESTORE_SNAPSHOT validation
    if not config.master_snapshot_id or not config.worker_snapshot_id:
        return {
            "status": "TEARDOWN_FAILED",
            "policy": "RESTORE_SNAPSHOT",
            "error": "Missing master_snapshot_id or worker_snapshot_id for RESTORE_SNAPSHOT",
        }

    if (
        master_ssh is None or worker_ssh is None
        or not isinstance(pre_baseline_master, dict)
        or not isinstance(pre_baseline_worker, dict)
    ):
        return {
            "status": "TEARDOWN_FAILED",
            "policy": "RESTORE_SNAPSHOT",
            "error": "RESTORE_SNAPSHOT requires both SSH clients and both saved preflight baselines; refusing unverifiable restore",
        }

    hook_ok, hook_err = validate_restore_hook(config.restore_hook_path or "", config.restore_hook_sha256 or "")
    if not hook_ok:
        return {
            "status": "TEARDOWN_FAILED",
            "policy": "RESTORE_SNAPSHOT",
            "error": f"Invalid restore hook: {hook_err}",
        }

    # Prepare restore payload
    payload = {
        "version": "1.0",
        "run_id": run_id,
        "master_ip": config.master_ip,
        "master_snapshot_id": config.master_snapshot_id,
        "worker_ip": config.worker_ip,
        "worker_snapshot_id": config.worker_snapshot_id,
    }

    try:
        proc = subprocess.run(
            [config.restore_hook_path],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=config.restore_timeout,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "TEARDOWN_FAILED",
            "policy": "RESTORE_SNAPSHOT",
            "error": f"Restore hook timed out after {config.restore_timeout}s",
        }
    except Exception as e:
        return {
            "status": "TEARDOWN_FAILED",
            "policy": "RESTORE_SNAPSHOT",
            "error": f"Failed invoking restore hook: {e}",
        }

    if proc.returncode != 0:
        return {
            "status": "TEARDOWN_FAILED",
            "policy": "RESTORE_SNAPSHOT",
            "error": f"Restore hook exited with code {proc.returncode}: {proc.stderr}",
        }

    # Parse JSON output from hook
    try:
        hook_out = json.loads(proc.stdout)
    except Exception as e:
        return {
            "status": "TEARDOWN_FAILED",
            "policy": "RESTORE_SNAPSHOT",
            "error": f"Restore hook emitted non-JSON output: {proc.stdout[:200]}",
        }

    if hook_out.get("status") != "RESTORED":
        return {
            "status": "TEARDOWN_FAILED",
            "policy": "RESTORE_SNAPSHOT",
            "error": f"Hook reported status: {hook_out.get('status')}",
        }

    if (
        hook_out.get("master_snapshot_id") != config.master_snapshot_id
        or hook_out.get("worker_snapshot_id") != config.worker_snapshot_id
    ):
        return {
            "status": "TEARDOWN_FAILED",
            "policy": "RESTORE_SNAPSHOT",
            "error": "Restore hook snapshot IDs mismatch response",
        }

    # Reconnect and compare the captured pre/post state on both hosts. This is
    # deliberately not reported as PASS: D8 pair-lock reacquisition and the
    # complete D19 mutation-target inventory/ownership comparison are not yet
    # implemented, so the current partial manifest cannot prove full restoration.
    try:
        time.sleep(5)  # allow both snapshot instances to boot
        post_m = collect_remote_baseline(master_ssh)
        post_w = collect_remote_baseline(worker_ssh)
    except Exception as exc:
        return {
            "status": "TEARDOWN_FAILED",
            "policy": "RESTORE_SNAPSHOT",
            "error": f"Failed collecting both post-restore baselines: {type(exc).__name__}: {exc}",
        }

    for host_name, post in (("Master", post_m), ("Worker", post_w)):
        clean, disqualifications = check_disposable_gate(post)
        if not clean:
            return {
                "status": "TEARDOWN_FAILED",
                "policy": "RESTORE_SNAPSHOT",
                "error": f"{host_name} post-restore disposable gate failed: {disqualifications}",
            }

    matches_m, missing_m, changed_m = compare_captured_baseline(pre_baseline_master, post_m)
    matches_w, missing_w, changed_w = compare_captured_baseline(pre_baseline_worker, post_w)
    if not matches_m or not matches_w:
        return {
            "status": "TEARDOWN_FAILED",
            "policy": "RESTORE_SNAPSHOT",
            "error": "Captured pre/post snapshot baseline differs",
            "master": {"missing_fields": missing_m, "changed_fields": changed_m},
            "worker": {"missing_fields": missing_w, "changed_fields": changed_w},
        }

    return {
        "status": "INCOMPLETE",
        "policy": "RESTORE_SNAPSHOT",
        "hook_status": "RESTORED",
        "captured_baseline_comparison": "MATCHED",
        "pair_lock_reacquisition": "NOT_IMPLEMENTED",
        "complete_resource_ownership_comparison": "NOT_IMPLEMENTED",
        "message": (
            "The snapshot hook restored both snapshots and the currently captured baseline fields match. "
            "RESTORE_SNAPSHOT cannot be marked PASS until D8 pair-lock reacquisition and the complete D19 "
            "mutation-target/ownership baseline are implemented and verified."
        ),
    }
