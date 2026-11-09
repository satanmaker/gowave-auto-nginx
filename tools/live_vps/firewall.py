"""UFW firewall isolation verification for Master and Worker TCP/3002.
Proves isolation using paired positive controls, external negative probes,
and target-side UFW/iptables DROP rule evidence.
"""
from __future__ import annotations

import socket
import re
import subprocess
import urllib.request
from typing import Any, Dict, Optional, Tuple

from .ssh import SSHClient


def probe_tcp_port(host: str, port: int, timeout: float = 3.0) -> Tuple[bool, str]:
    """Probe TCP host:port from Control Machine, validating actual traffic delivery to guard against SYN-spoofing middleboxes."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(min(timeout, 2.0))
        try:
            # Send small probe to verify whether connection reaches a real server application
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            data = s.recv(512)
            s.close()
            if data:
                return True, "CONNECTED"
            # If closed immediately with EOF without data
            return False, "REFUSED"
        except (socket.timeout, TimeoutError):
            # SYN was ACKed by local middlebox but no application packet answered
            s.close()
            return False, "TIMEOUT"
        except (ConnectionResetError, BrokenPipeError):
            s.close()
            return False, "REFUSED"
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
    """Verify local-only Master control listener and independent external denial."""
    loop_r = master_ssh.run(
        "python3 -c \"import socket; s = socket.create_connection(('127.0.0.1', 3002), timeout=3); s.close(); print('CONNECTED')\""
    )
    loopback_ok = loop_r.ok and "CONNECTED" in loop_r.stdout
    if not loopback_ok:
        return {
            "status": "FAIL",
            "loopback_accessible": False,
            "error": "Master TCP/3002 is not reachable through loopback",
        }

    # A local-only bind is direct evidence that the service is not listening on
    # the public interface. A generic default-DENY policy alone is insufficient.
    listeners = master_ssh.run("ss -ltnH 'sport = :3002'")
    listener_lines = [line.split() for line in listeners.stdout.splitlines() if line.split()]
    local_addresses = [parts[3] for parts in listener_lines if len(parts) >= 4]
    local_only_bind = bool(local_addresses) and all(
        address.startswith("127.") or address.startswith("[::1]:") or address.startswith("::1:")
        for address in local_addresses
    )

    ufw_r = master_ssh.run("ufw status numbered")
    iptables_r = master_ssh.run("iptables -S INPUT")
    explicit_deny = bool(
        re.search(r"\b3002/tcp\s+DENY IN\s+Anywhere", ufw_r.stdout, re.IGNORECASE)
        or re.search(r"--dport\s+3002.*-j\s+(DROP|REJECT)", iptables_r.stdout)
    )

    ext_ok, ext_reason = probe_tcp_port(master_ip, 3002, timeout=3.0)
    if enable_ipv6:
        if not master_ipv6:
            return {
                "status": "INCOMPLETE",
                "error": "ENABLE_IPV6=true but MASTER_IPV6 was not supplied to firewall verification",
                "loopback_accessible": True,
            }
        ipv6_ok, ipv6_reason = probe_tcp_port(master_ipv6, 3002, timeout=3.0)
        if ipv6_ok:
            return {"status": "FAIL", "error": "Master TCP/3002 is reachable over public IPv6",
                    "ipv6_probe_reason": ipv6_reason}
    else:
        ipv6_reason = "not enabled"

    if ext_ok:
        status = "FAIL"
    elif ext_reason not in ("TIMEOUT", "REFUSED"):
        status = "INCOMPLETE"
    elif enable_ipv6 and ipv6_reason not in ("TIMEOUT", "REFUSED"):
        status = "INCOMPLETE"
    elif not (local_only_bind or explicit_deny):
        status = "INCOMPLETE"
    else:
        status = "PASS"

    return {
        "status": status,
        "loopback_accessible": loopback_ok,
        "external_blocked": not ext_ok,
        "external_reason": ext_reason,
        "local_only_bind": local_only_bind,
        "explicit_port_3002_deny": explicit_deny,
        "ipv6_external_reason": ipv6_reason,
    }
def verify_worker_firewall(
    master_ssh: SSHClient,
    worker_ssh: SSHClient,
    worker_ip: str,
    enable_ipv6: bool = False,
    worker_ipv6: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify Master allow-list access and external TCP/3002 denial on Worker."""
    master_probe = master_ssh.run(
        f"python3 -c \"import socket; s = socket.create_connection(('{worker_ip}', 3002), timeout=5); s.close(); print('CONNECTED')\""
    )
    positive_ok = master_probe.ok and "CONNECTED" in master_probe.stdout
    if not positive_ok:
        return {
            "status": "FAIL",
            "positive_control_ok": False,
            "error": "Master could not connect to Worker TCP/3002",
        }

    master_public_ip_r = master_ssh.run("curl -fsS4 --connect-timeout 5 --max-time 10 https://api.ipify.org")
    master_public_ip = master_public_ip_r.stdout.strip() if master_public_ip_r.ok else ""
    if not master_public_ip:
        return {
            "status": "INCOMPLETE",
            "positive_control_ok": positive_ok,
            "error": "Could not determine Master public egress IP for Worker allow-list verification",
        }

    worker_ufw = worker_ssh.run("ufw status verbose")
    worker_iptables = worker_ssh.run("iptables -S")
    cm_ip = get_control_machine_public_ip()
    if not cm_ip:
        return {
            "status": "INCOMPLETE",
            "error": "Could not determine Control Machine public IP for external firewall probe",
        }
    if cm_ip == master_public_ip:
        return {
            "status": "INCOMPLETE",
            "error": "Control Machine public IP matches Master public IP; separate external vantage required",
            "cm_ip": cm_ip,
            "master_ip": master_public_ip,
        }

    # Require a source-specific allow rule for Master and a default-deny policy;
    # a generic DROP anywhere in the ruleset is not sufficient evidence.
    escaped_master = re.escape(master_public_ip)
    ufw_allow_master = bool(
        re.search(rf"3002/tcp\s+ALLOW IN\s+{escaped_master}(?:\s|$)", worker_ufw.stdout)
    )
    iptables_allow_master = bool(
        re.search(
            rf"-A\s+\S+\s+-s\s+{escaped_master}(?:/32)?\s+.*--dport\s+3002\s+.*-j\s+ACCEPT",
            worker_iptables.stdout,
        )
    )
    default_deny = "Default: deny (incoming)" in worker_ufw.stdout
    iptables_accept_3002 = [
        line for line in worker_iptables.stdout.splitlines()
        if "--dport 3002" in line and "-j ACCEPT" in line
    ]
    iptables_broad_allow = any(
        not re.search(rf"-s\s+{escaped_master}(?:/32)?(?:\s|$)", line)
        for line in iptables_accept_3002
    )
    broad_allow = bool(
        re.search(r"3002/tcp\s+ALLOW IN\s+Anywhere", worker_ufw.stdout, re.IGNORECASE)
        or iptables_broad_allow
    )
    allow_list_evidence = (ufw_allow_master or iptables_allow_master) and default_deny and not broad_allow

    ext_ok, ext_reason = probe_tcp_port(worker_ip, 3002, timeout=3.0)
    if ext_ok:
        return {
            "status": "FAIL",
            "positive_control_ok": True,
            "control_machine_blocked": False,
            "error": "Worker TCP/3002 is reachable from the external Control Machine",
        }
    if ext_reason != "TIMEOUT":
        status = "INCOMPLETE"
    elif not allow_list_evidence:
        status = "INCOMPLETE"
    else:
        status = "PASS"

    ipv6_reason = "not enabled"
    if enable_ipv6:
        if not worker_ipv6:
            status = "INCOMPLETE"
            ipv6_reason = "missing WORKER_IPV6"
        else:
            ipv6_ok, ipv6_reason = probe_tcp_port(worker_ipv6, 3002, timeout=3.0)
            if ipv6_ok:
                status = "FAIL"
            elif ipv6_reason != "TIMEOUT":
                # Refused/unreachable IPv6 does not prove a target firewall drop.
                status = "INCOMPLETE"

    return {
        "status": status,
        "positive_control_ok": positive_ok,
        "master_public_ip": master_public_ip,
        "control_machine_ip": cm_ip,
        "control_machine_blocked": not ext_ok,
        "control_machine_probe_reason": ext_reason,
        "worker_allow_list_evidence": allow_list_evidence,
        "ufw_allow_from_master": ufw_allow_master,
        "iptables_allow_from_master": iptables_allow_master,
        "ufw_default_deny": default_deny,
        "broad_allow_rule": broad_allow,
        "ipv6_external_reason": ipv6_reason,
    }
