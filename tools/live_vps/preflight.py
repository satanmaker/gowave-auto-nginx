"""Preflight verification, disposable baseline gate, and pair-wide run locking.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import shutil
import stat
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


def check_private_key_file(key_path: str | Path) -> Tuple[bool, Optional[str]]:
    """Require a runner-owned, regular, non-symlink private key with safe permissions."""
    path = Path(key_path).expanduser()
    try:
        info = path.lstat()
    except OSError as exc:
        return False, f"SSH private key cannot be inspected: {path}: {type(exc).__name__}"
    if stat.S_ISLNK(info.st_mode):
        return False, f"SSH private key must not be a symlink: {path}"
    if not stat.S_ISREG(info.st_mode):
        return False, f"SSH private key must be a regular file: {path}"
    if info.st_uid != os.geteuid():
        return False, f"SSH private key must be owned by the runner user: {path}"
    if not (info.st_mode & stat.S_IRUSR):
        return False, f"SSH private key must be readable by the runner user: {path}"
    if stat.S_IMODE(info.st_mode) & 0o077:
        return False, f"SSH private key permissions are too broad; require 0600 or 0400: {path}"
    if info.st_size == 0:
        return False, f"SSH private key is empty: {path}"
    return True, None


def check_ssh_trust(host: str, port: int, known_hosts_path: str | Path) -> Tuple[bool, Optional[str]]:
    """Verify safe known_hosts metadata and a pre-pinned key for host:port."""
    kh = Path(known_hosts_path).expanduser()
    try:
        info = kh.lstat()
    except OSError as exc:
        return False, f"SSH known_hosts file cannot be inspected: {kh}: {type(exc).__name__}"
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return False, f"SSH known_hosts must be a regular non-symlink file: {kh}"
    if info.st_uid != os.geteuid():
        return False, f"SSH known_hosts must be owned by the runner user: {kh}"
    if stat.S_IMODE(info.st_mode) & 0o022:
        return False, f"SSH known_hosts must not be group- or world-writable: {kh}"
    if info.st_size == 0:
        return False, f"SSH known_hosts file is empty: {kh}"

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
    Acquires locks in deterministic host address order and generates re-entrant leases.
    """

    def __init__(self, master_ssh: SSHClient, worker_ssh: SSHClient, run_id: str = "live_vps_run"):
        self.clients = [master_ssh, worker_ssh]
        # Sort in deterministic address order to avoid deadlocks
        self.clients.sort(key=lambda c: c.host)
        self.run_id = run_id
        self._procs: List[subprocess.Popen] = []
        self.lease_tokens: Dict[str, str] = {}

    def acquire(self, timeout: int = 15) -> bool:
        lock_path = "/run/lock/gowave-managed-mutation.lock"
        lease_path = "/run/lock/gowave-mutation-lease.json"
        for client in self.clients:
            holder_py = (
                "import fcntl, json, os, secrets, sys, time; "
                "os.makedirs('/run/lock', exist_ok=True); "
                f"lock_path = '{lock_path}'; lease_path = '{lease_path}'; "
                "fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600); "
                "fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); "
                "tok = secrets.token_hex(32); "
                f"data = {{'run_id': '{self.run_id}', 'host': '{client.host}', 'holder_pid': os.getpid(), 'lease_token': tok}}; "
                "with open(lease_path, 'w', encoding='utf-8') as f: json.dump(data, f); "
                "os.chmod(lease_path, 0o600); "
                "print('LEASE_TOKEN:' + tok, flush=True); "
                "while True: time.sleep(1)"
            )
            cmd = client._build_ssh_cmd(f"python3 -c \"{holder_py}\"")
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self._procs.append(proc)
                # Read lease token line from holder stdout
                line = proc.stdout.readline().strip() if proc.stdout else ""
                if line.startswith("LEASE_TOKEN:"):
                    self.lease_tokens[client.host] = line.split(":", 1)[1]
                else:
                    # Session exited or failed to acquire lock
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
        self.lease_tokens.clear()
