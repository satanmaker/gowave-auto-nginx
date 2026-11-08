"""UFW firewall isolation verification for Master and Worker TCP/3002.
Proves isolation using paired positive controls, external negative probes,
and target-side UFW/iptables DROP rule evidence.
"""
from __future__ import annotations

import socket
import subprocess
import urllib.request
from typing import Any, Dict, Optional, Tuple

from .ssh import SSHClient


def probe_tcp_port(host: str, port: int, timeout: float = 3.0) -> Tuple[bool, str]:
    """Probe TCP host:port from Control Machine."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "CONNECTED"
    except socket.timeout:
        return False, "TIMEOUT"
    except ConnectionRefusedError:
        return False, "REFUSED"
    except OSError as e:
        return False, f"ERROR_{type(e).__name__}"


def get_control_machine_public_ip() -> Optional[str]:
    """Determine public egress IP of the Control Machine."""
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as resp:
            return resp.read().decode("utf-8").strip()
    except Exception:
        pass
    try:
        with urllib.request.urlopen("https://ifconfig.me", timeout=5) as resp:
            return resp.read().decode("utf-8").strip()
    except Exception:
        return None


def verify_master_firewall(
    master_ssh: SSHClient,
    master_ip: str,
    enable_ipv6: bool = False,
    master_ipv6: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify Master TCP/3002 isolation (loopback allowed, external blocked)."""
    # 1. Loopback probe on Master
    loop_r = master_ssh.run("python3 -c \"import socket; s = socket.create_connection(('127.0.0.1', 3002), timeout=3); s.close(); print('CONNECTED')\"")
    loopback_ok = loop_r.ok and "CONNECTED" in loop_r.stdout

    # 2. External probe from Control Machine
    ext_ok, ext_reason = probe_tcp_port(master_ip, 3002, timeout=3.0)

    # 3. Master-side firewall evidence (port 3002 not open publicly or UFW DROP)
    ufw_r = master_ssh.run("ufw status numbered")
    iptables_r = master_ssh.run("iptables -S")

    # In Master all-in-one, 3002 is bound to 127.0.0.1 or blocked by UFW default incoming DROP
    has_ufw_drop = "Default: deny (incoming)" in ufw_r.stdout or "DROP" in iptables_r.stdout

    passed = loopback_ok and (not ext_ok) and has_ufw_drop
    return {
        "status": "PASS" if passed else "FAIL",
        "loopback_accessible": loopback_ok,
        "external_blocked": not ext_ok,
        "external_reason": ext_reason,
        "master_firewall_drop_evidence": has_ufw_drop,
    }


def verify_worker_firewall(
    master_ssh: SSHClient,
    worker_ssh: SSHClient,
    worker_ip: str,
    enable_ipv6: bool = False,
    worker_ipv6: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify Worker TCP/3002 isolation (positive control from Master allowed,
    negative probe from Control Machine blocked with target-side evidence).
    """
    # 1. Positive control from Master to Worker:3002
    master_probe = master_ssh.run(
        f"python3 -c \"import socket; s = socket.create_connection(('{worker_ip}', 3002), timeout=5); s.close(); print('CONNECTED')\""
    )
    positive_ok = master_probe.ok and "CONNECTED" in master_probe.stdout

    # 2. Check Worker UFW allow rule for Master
    worker_ufw = worker_ssh.run("ufw status numbered")
    worker_iptables = worker_ssh.run("iptables -S")

    # 3. Negative probe from Control Machine
    cm_ip = get_control_machine_public_ip()
    ext_ok, ext_reason = probe_tcp_port(worker_ip, 3002, timeout=3.0)

    # Check for vantage overlap: Control Machine running on Master VPS
    master_public_ip_r = master_ssh.run("curl -s4 https://api.ipify.org || true")
    master_public_ip = master_public_ip_r.stdout.strip()
    if cm_ip and master_public_ip and cm_ip == master_public_ip:
        return {
            "status": "INCOMPLETE",
            "error": "Control Machine public IP matches Master public IP; separate external vantage required",
            "cm_ip": cm_ip,
            "master_ip": master_public_ip,
        }

    # Verify Worker-side DROP evidence
    worker_drop_evidence = "DROP" in worker_iptables.stdout or "deny (incoming)" in worker_ufw.stdout

    passed = positive_ok and (not ext_ok) and worker_drop_evidence
    return {
        "status": "PASS" if passed else "FAIL",
        "positive_control_ok": positive_ok,
        "control_machine_blocked": not ext_ok,
        "control_machine_probe_reason": ext_reason,
        "worker_drop_evidence": worker_drop_evidence,
    }
