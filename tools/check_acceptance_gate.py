#!/usr/bin/env python3
"""Pre-Deployment Acceptance Gate Checker.
Validates points 1-4 of the Pre-Deployment Acceptance Gate (Task 10.11),
and inspects artifacts/live-vps/ for point 5 (verified live ACME staging PASS).
"""
import json
import os
from pathlib import Path
import subprocess
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent


def run_command(cmd: list[str], desc: str) -> tuple[bool, str]:
    print(f"--> [GATE CHECK] {desc}...")
    proc = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True)
    if proc.returncode != 0:
        print(f"    FAILED: {desc}\n{proc.stderr or proc.stdout}")
        return False, proc.stderr or proc.stdout
    print(f"    PASSED: {desc}")
    return True, proc.stdout


def verify_live_staging_run(artifacts_dir: Path | None = None) -> tuple[bool, str]:
    if artifacts_dir is None:
        artifacts_dir = REPO_ROOT / "artifacts" / "live-vps"
    if not artifacts_dir.exists():
        return False, "No artifacts/live-vps directory found; live VPS staging run has not been executed."

    valid_runs = []
    for run_dir in sorted(artifacts_dir.iterdir()):
        if not run_dir.is_dir():
            continue
        result_file = run_dir / "result.json"
        if not result_file.is_file():
            continue
        try:
            with open(result_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            overall = data.get("overall") or data.get("overall_status")
            acme_mode = (data.get("trust") or {}).get("acme_mode") or data.get("acme_mode")
            phases = data.get("results") or data.get("phases") or {}
            teardown = phases.get("teardown") or {}
            if overall == "PASS" and acme_mode == "staging" and teardown.get("status") == "PASS":
                valid_runs.append(data.get("test_run_id") or data.get("run_id") or run_dir.name)
        except Exception:
            continue

    if valid_runs:
        return True, f"Found verified live staging PASS run(s): {', '.join(valid_runs)}"
    return False, "No completed run in artifacts/live-vps/ with overall_status=PASS, acme_mode=staging, and teardown=PASS found."


def main():
    print("==================================================================")
    print("GoWave Auto NGINX: Pre-Deployment Acceptance Gate Validation")
    print("==================================================================")
    failures = []

    # 1. OpenSpec strict validation
    ok, out = run_command(["openspec", "validate", "--all", "--strict"], "OpenSpec strict validation")
    if not ok:
        failures.append("OpenSpec strict validation failed")

    # 2. CI Inventory completeness
    ok, out = run_command([sys.executable, "tests/run_ci.py", "--check-completeness"], "CI test inventory completeness")
    if not ok:
        failures.append("CI completeness check failed")

    # 3. Nonroot test suite
    ok, out = run_command([sys.executable, "tests/run_ci.py", "--suite", "nonroot"], "Nonroot CI test suite")
    if not ok:
        failures.append("Nonroot test suite failed")

    # 4. Runner unit & integration tests
    ok, out = run_command([sys.executable, "-m", "unittest", "discover", "-s", "tools/tests"], "Runner unit & integration tests")
    if not ok:
        failures.append("Runner tests failed")

    # 5. Live VPS Staging run check
    staging_ok, staging_msg = verify_live_staging_run()
    print(f"--> [GATE CHECK] Live VPS Staging Run: {staging_msg}")

    print("==================================================================")
    if failures:
        print(f"GATE FAILED: {len(failures)} automated check(s) failed:")
        for f in failures:
            print(f"  - {f}")
        return 1

    if not staging_ok:
        print("AUTOMATED CODE CHECKS PASSED.")
        print("NOTICE: Live VPS ACME Staging acceptance run is PENDING.")
        print("Per Task 10.11 requirement:")
        print("  Execute: python3 tools/test_live_vps.py --config tools/live_vps_config.env --mode full")
        print("  on disposable VPS before two-VPS production rollout.")
        return 0

    print("PRE-DEPLOYMENT ACCEPTANCE GATE: ALL CHECKS PASSED (INCLUDING LIVE VPS RUN)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
