"""Preflight verification, disposable baseline gate, and pair-wide run locking.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .ssh import SSHClient, SSHResult
from .redaction import redact

REQUIRED_PORTS_DEFAULT = [80, 443, 3000, 3001, 3002, 7443, 8443, 9443, 10001, 10002, 10003]
VISION_PORTS = [8444, 9444]


@dataclass
class ToolCheckResult:
    tool: str
    ok: bool
    version: Optional[str] = None
    error: Optional[str] = None


def check_tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def check_control_machine_tools(config: Any) -> Dict[str, ToolCheckResult]:
    """Interrogate Control Machine tool inventory and pinned versions."""
    results: Dict[str, ToolCheckResult] = {}

    # 1. python3 >= 3.10
    v = sys.version_info
    py_ok = v >= (3, 10)
    py_ver = f"{v.major}.{v.minor}.{v.micro}"
    results["python3"] = ToolCheckResult(
        tool="python3",
        ok=py_ok,
        version=py_ver,
        error=None if py_ok else f"Python 3.10+ required, got {py_ver}",
    )

    # 2. Standard CLI utilities
    standard_tools = ["ssh", "ssh-keygen", "openssl", "curl", "dig", "timeout"]
    for t in standard_tools:
        available = check_tool_available(t)
        results[t] = ToolCheckResult(
            tool=t,
            ok=available,
            error=None if available else f"Required CLI utility '{t}' not found in PATH",
        )

    # 3. Xray client binary version check
    if not check_tool_available("xray"):
        results["xray"] = ToolCheckResult(
            tool="xray",
            ok=False,
            error="Xray client binary not found in PATH on Control Machine",
        )
    else:
        try:
            proc = subprocess.run(["xray", "version"], capture_output=True, text=True, timeout=5)
            # Output like: Xray 25.10.15 (Xray, Penetrates Everything.)
            match = re.search(r"Xray\s+([0-9\.]+)", proc.stdout)
            ver = match.group(1) if match else proc.stdout.split()[1] if proc.stdout else "unknown"
            expected = getattr(config, "XRAY_CLIENT_VERSION", None)
            ver_ok = (expected is None) or (ver == expected)
            results["xray"] = ToolCheckResult(
                tool="xray",
                ok=ver_ok,
                version=ver,
                error=None if ver_ok else f"Xray client version mismatch: expected {expected}, got {ver}",
            )
        except Exception as e:
            results["xray"] = ToolCheckResult(tool="xray", ok=False, error=str(e))

    # 4. Mihomo client binary version check
    if not check_tool_available("mihomo"):
        results["mihomo"] = ToolCheckResult(
            tool="mihomo",
            ok=False,
            error="Mihomo client binary not found in PATH on Control Machine",
        )
    else:
        try:
            proc = subprocess.run(["mihomo", "-v"], capture_output=True, text=True, timeout=5)
            # Output like: Mihomo v1.19.1 linux amd64
            match = re.search(r"v([0-9\.]+)", proc.stdout)
            ver = match.group(1) if match else proc.stdout.strip()
            expected = getattr(config, "MIHOMO_CLIENT_VERSION", None)
            ver_ok = (expected is None) or (ver == expected)
            results["mihomo"] = ToolCheckResult(
                tool="mihomo",
                ok=ver_ok,
                version=ver,
                error=None if ver_ok else f"Mihomo client version mismatch: expected {expected}, got {ver}",
            )
        except Exception as e:
            results["mihomo"] = ToolCheckResult(tool="mihomo", ok=False, error=str(e))

    return results


def check_ssh_trust(host: str, port: int, known_hosts_path: str | Path) -> Tuple[bool, Optional[str]]:
    """Verify that SSH host key for host:port is pre-pinned in known_hosts."""
    kh = Path(known_hosts_path).resolve()
    if not kh.is_file() or kh.stat().st_size == 0:
        return False, f"SSH known_hosts file missing or empty: {kh}"

    host_pattern = host if port == 22 else f"[{host}]:{port}"
    cmd = ["ssh-keygen", "-F", host_pattern, "-f", str(kh)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if proc.returncode == 0 and proc.stdout.strip():
            return True, None
        return False, f"Host key for {host_pattern} is not pre-pinned in {kh}"
    except Exception as e:
        return False, f"ssh-keygen check failed: {e}"


def collect_remote_baseline(ssh: SSHClient) -> Dict[str, Any]:
    """Collect read-only system baseline manifest from remote VPS."""
    manifest: Dict[str, Any] = {}

    # 1. Host OS / kernel
    r = ssh.run("uname -a && cat /etc/os-release 2>/dev/null || true")
    manifest["os_kernel"] = r.stdout.strip()

    # 2. Running systemd services
    r = ssh.run("systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null || true")
    manifest["running_services"] = [line.split()[0] for line in r.stdout.splitlines() if line.strip()]

    # 3. Active TCP listeners
    r = ssh.run("ss -tlnH 2>/dev/null || netstat -tln 2>/dev/null || true")
    manifest["tcp_listeners_raw"] = r.stdout.strip()

    listening_ports = set()
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            # Look at local address column (usually 4th column in ss)
            addr = parts[3]
            if ":" in addr:
                port_str = addr.rsplit(":", 1)[-1]
                if port_str.isdigit():
                    listening_ports.add(int(port_str))
    manifest["listening_ports"] = sorted(listening_ports)

    # 4. Existing GoWave directories
    gowave_dirs = [
        "/opt/gowave",
        "/opt/gowave-node",
        "/opt/gowave-auto-nginx",
        "/var/www/gowave-auto-nginx",
        "/etc/nginx/stream-enabled",
    ]
    r = ssh.run(f"for d in {' '.join(gowave_dirs)}; do if [ -e \"$d\" ]; then echo \"$d\"; fi; done")
    existing_dirs = [d.strip() for d in r.stdout.splitlines() if d.strip()]
    manifest["existing_gowave_dirs"] = existing_dirs

    # 5. Firewall state
    r = ssh.run("ufw status verbose 2>/dev/null || iptables -L -n 2>/dev/null || true")
    manifest["firewall_status"] = r.stdout.strip()

    # 6. Swap state
    r = ssh.run("swapon --show 2>/dev/null || true")
    manifest["swap_info"] = r.stdout.strip()

    # 7. Filesystem usage
    r = ssh.run("df -h / 2>/dev/null || true")
    manifest["disk_usage"] = r.stdout.strip()

    # 8. Packages
    r = ssh.run("dpkg-query -W -f='${binary:Package}=${Version}\n' 2>/dev/null | grep -E '^(nginx|certbot|python3|ufw|fail2ban)' || true")
    manifest["key_packages"] = r.stdout.strip()

    return manifest


def check_disposable_gate(manifest: Dict[str, Any], vision_enabled: bool = False) -> Tuple[bool, List[str]]:
    """Evaluate whether VPS satisfies the clean disposable baseline gate."""
    disqualifications: List[str] = []

    # Check 1: No pre-existing GoWave directories
    existing_dirs = manifest.get("existing_gowave_dirs", [])
    if existing_dirs:
        disqualifications.append(f"Pre-existing GoWave directories detected: {existing_dirs}")

    # Check 2: No GoWave systemd services active
    services = manifest.get("running_services", [])
    for svc in services:
        if "gowave" in svc.lower():
            disqualifications.append(f"GoWave systemd service already active: {svc}")

    # Check 3: Port hygiene (none of the required ports may be listening)
    required = set(REQUIRED_PORTS_DEFAULT)
    if vision_enabled:
        required.update(VISION_PORTS)

    listening = set(manifest.get("listening_ports", []))
    conflicts = required.intersection(listening)
    if conflicts:
        disqualifications.append(f"Port conflicts detected; required ports already occupied: {sorted(conflicts)}")

    return len(disqualifications) == 0, disqualifications


class LocalLock:
    """Local process lock using fcntl.flock in private mode-0700 runtime dir."""

    def __init__(self, target_name: str):
        self.target_name = target_name
        self.lock_dir = Path.home() / ".cache" / "gowave-live-vps" / "locks"
        self.lock_file = self.lock_dir / f"{target_name}.lock"
        self._fd: Optional[int] = None

    def acquire(self) -> bool:
        self.lock_dir.mkdir(parents=True, exist_ok=True)
        self.lock_dir.chmod(0o700)

        # Open without following symlinks
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        self._fd = os.open(str(self.lock_file), flags, 0o600)
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except (BlockingIOError, OSError):
            os.close(self._fd)
            self._fd = None
            return False

    def release(self) -> None:
        if self._fd is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
                os.close(self._fd)
            except Exception:
                pass
            self._fd = None


class RemotePairLock:
    """Authoritative remote locks on Master and Worker held over dedicated SSH sessions.
    Acquires locks in deterministic host address order.
    """

    def __init__(self, master_ssh: SSHClient, worker_ssh: SSHClient):
        self.clients = [master_ssh, worker_ssh]
        # Sort in deterministic address order to avoid deadlocks
        self.clients.sort(key=lambda c: c.host)
        self._procs: List[subprocess.Popen] = []

    def acquire(self, timeout: int = 15) -> bool:
        lock_path = "/run/lock/gowave-live-vps.lock"
        for client in self.clients:
            cmd = client._build_ssh_cmd(
                f"mkdir -p /run/lock && exec flock -x -w 5 {lock_path} sleep 86400"
            )
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self._procs.append(proc)
                # Brief wait to ensure SSH connect and lock acquisition
                time.sleep(1.0)
                if proc.poll() is not None:
                    # Session exited immediately -> lock failed
                    self.release()
                    return False
            except Exception:
                self.release()
                return False
        return True

    def check_alive(self) -> bool:
        for p in self._procs:
            if p.poll() is not None:
                return False
        return True

    def release(self) -> None:
        for p in self._procs:
            try:
                p.terminate()
                p.wait(timeout=2)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        self._procs.clear()
