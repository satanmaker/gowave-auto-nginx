"""Test report generation and diagnostics collection with redact-on-write security.
Generates result.json, JUnit XML, summary.txt, and sanitized SSH diagnostic dumps.
"""
from __future__ import annotations

import json
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional

from .redaction import redact
from .ssh import SSHClient


def write_result_json(artifact_dir: Path, data: Dict[str, Any]) -> Path:
    """Write sanitized result.json with redact-on-write filtering and mode 0600."""
    artifact_dir.mkdir(parents=True, exist_ok=True)
    raw_json = json.dumps(data, indent=2)
    sanitized_json = redact(raw_json)

    out_path = artifact_dir / "result.json"
    out_path.write_text(sanitized_json, encoding="utf-8")
    out_path.chmod(0o600)
    return out_path


def write_junit_report(
    artifact_dir: Path,
    test_cases: List[Dict[str, Any]],
    suite_name: str = "LiveVPSE2E",
) -> Path:
    """Generate standardized JUnit XML report with redact-on-write protection."""
    artifact_dir.mkdir(parents=True, exist_ok=True)

    total_tests = len(test_cases)
    failures = sum(1 for c in test_cases if c.get("status") == "FAIL")
    errors = sum(1 for c in test_cases if c.get("status") in ("ERROR", "INCOMPLETE", "TEARDOWN_FAILED", "UNKNOWN", "RUNNING"))
    skipped = sum(1 for c in test_cases if c.get("status") == "SKIP")

    root = ET.Element(
        "testsuite",
        attrib={
            "name": suite_name,
            "tests": str(total_tests),
            "failures": str(failures),
            "errors": str(errors),
            "skipped": str(skipped),
        },
    )

    for case in test_cases:
        c_name = redact(case.get("name", "unnamed_case"))
        c_class = redact(case.get("classname", "live_vps"))
        c_time = str(case.get("duration", "0.0"))

        tc = ET.SubElement(
            root,
            "testcase",
            attrib={"name": c_name, "classname": c_class, "time": c_time},
        )

        status = case.get("status", "PASS")
        if status == "FAIL":
            msg = redact(case.get("message", "assertion failed"))
            fail_el = ET.SubElement(tc, "failure", attrib={"message": msg})
            fail_el.text = redact(case.get("details", msg))
        elif status in ("ERROR", "INCOMPLETE", "TEARDOWN_FAILED", "UNKNOWN", "RUNNING"):
            # Incomplete evidence and failed cleanup must never appear as a pass.
            msg = redact(case.get("message", status.lower()))
            err_el = ET.SubElement(tc, "error", attrib={"message": msg})
            err_el.text = redact(case.get("details", msg))
        elif status == "SKIP":
            msg = redact(case.get("message", "skipped"))
            ET.SubElement(tc, "skipped", attrib={"message": msg})

    xml_bytes = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    sanitized_xml = redact(xml_bytes.decode("utf-8"))

    out_path = artifact_dir / "junit.xml"
    out_path.write_text(sanitized_xml, encoding="utf-8")
    out_path.chmod(0o600)
    return out_path


def write_summary_txt(artifact_dir: Path, data: Dict[str, Any]) -> Path:
    """Write human-readable summary.txt with test breakdown."""
    artifact_dir.mkdir(parents=True, exist_ok=True)

    overall = data.get("overall", "UNKNOWN")
    run_id = data.get("test_run_id", "unknown")

    lines = [
        "==================================================================",
        f" GoWave Auto NGINX Live VPS E2E Test Summary",
        "==================================================================",
        f" Run ID:    {run_id}",
        f" Status:    {overall}",
        f" Commit:    {data.get('repository_commit', 'unknown')}",
        "------------------------------------------------------------------",
        " Phases Breakdown:",
    ]

    results = data.get("results", {})
    for phase, res in results.items():
        p_status = res.get("status", "UNKNOWN") if isinstance(res, dict) else str(res)
        lines.append(f"   - {phase:<25} : {p_status}")

    lines.extend([
        "------------------------------------------------------------------",
        f" Control Machine: {data.get('control_machine', {}).get('os', 'Linux')}",
        f" ACME Mode:      {data.get('trust', {}).get('acme_mode', 'staging')}",
        "==================================================================",
    ])

    raw_text = "\n".join(lines) + "\n"
    sanitized = redact(raw_text)

    out_path = artifact_dir / "summary.txt"
    out_path.write_text(sanitized, encoding="utf-8")
    out_path.chmod(0o600)
    return out_path


def collect_diagnostics(
    artifact_dir: Path,
    master_ssh: Optional[SSHClient] = None,
    worker_ssh: Optional[SSHClient] = None,
) -> None:
    """Collect diagnostic dumps from Master and Worker VPS, redacting all sensitive output."""
    diag_dir = artifact_dir / "diagnostics"

    dump_cmds = {
        "uname.txt": "uname -a",
        "os-release.txt": "cat /etc/os-release",
        "systemd-status.txt": "systemctl status gowave gowave-node nginx fail2ban 2>/dev/null || true",
        "listeners.txt": "ss -tlnp",
        "nginx-test.txt": "nginx -t 2>&1 || true",
        "ufw-status.txt": "ufw status verbose 2>/dev/null || iptables -S 2>/dev/null || true",
        "cert-metadata.txt": "openssl x509 -in /etc/letsencrypt/live/*/fullchain.pem -noout -subject -issuer -dates 2>/dev/null || true",
    }

    if master_ssh:
        m_dir = diag_dir / "master"
        m_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        m_dir.chmod(0o700)
        for fname, cmd in dump_cmds.items():
            r = master_ssh.run(cmd)
            content = redact(r.stdout + ("\n" + r.stderr if r.stderr else ""))
            dump_path = m_dir / fname
            dump_path.write_text(content, encoding="utf-8")
            dump_path.chmod(0o600)

    if worker_ssh:
        w_dir = diag_dir / "worker"
        w_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        w_dir.chmod(0o700)
        for fname, cmd in dump_cmds.items():
            r = worker_ssh.run(cmd)
            content = redact(r.stdout + ("\n" + r.stderr if r.stderr else ""))
            dump_path = w_dir / fname
            dump_path.write_text(content, encoding="utf-8")
            dump_path.chmod(0o600)
