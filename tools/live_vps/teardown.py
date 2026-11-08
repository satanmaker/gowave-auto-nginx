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

    # Reconnect and verify clean baseline
    if master_ssh and pre_baseline_master:
        time.sleep(5)  # allow snapshot boot
        try:
            post_m = collect_remote_baseline(master_ssh)
            disp_ok, disp_errs = check_disposable_gate(post_m)
            if not disp_ok:
                return {
                    "status": "TEARDOWN_FAILED",
                    "policy": "RESTORE_SNAPSHOT",
                    "error": f"Master baseline verification failed after snapshot restore: {disp_errs}",
                }
        except Exception as e:
            return {
                "status": "TEARDOWN_FAILED",
                "policy": "RESTORE_SNAPSHOT",
                "error": f"Failed verifying Master baseline after restore: {e}",
            }

    if worker_ssh and pre_baseline_worker:
        try:
            post_w = collect_remote_baseline(worker_ssh)
            disp_ok, disp_errs = check_disposable_gate(post_w)
            if not disp_ok:
                return {
                    "status": "TEARDOWN_FAILED",
                    "policy": "RESTORE_SNAPSHOT",
                    "error": f"Worker baseline verification failed after snapshot restore: {disp_errs}",
                }
        except Exception as e:
            return {
                "status": "TEARDOWN_FAILED",
                "policy": "RESTORE_SNAPSHOT",
                "error": f"Failed verifying Worker baseline after restore: {e}",
            }

    return {
        "status": "PASS",
        "policy": "RESTORE_SNAPSHOT",
        "message": "Snapshots successfully restored and baselines re-verified clean",
    }
