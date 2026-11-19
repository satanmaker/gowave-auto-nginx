"""Runtime fingerprint captured once per Podman E2E run.

Reproducibility claims are only meaningful together with the host facts they
were produced on: kernel, cgroup generation, Podman/runtime versions, network
backend, and the exact image digests the run consumed. The fingerprint is
written next to ``result.json`` and embedded in the JSON report.
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from tools.live_vps.redaction import redact

from .images import entries, validate_lock
from .runner import RunContext

SCHEMA = "gowave-podman-environment/v1"


class EnvironmentError(RuntimeError):
    pass


def _run(argv: List[str], timeout: int = 30) -> str:
    binary = shutil.which(argv[0])
    if not binary:
        raise EnvironmentError(f"{argv[0]} is not installed")
    proc = subprocess.run(
        [binary, *argv[1:]], capture_output=True, text=True, timeout=timeout, check=False,
    )
    if proc.returncode != 0:
        raise EnvironmentError(f"{' '.join(argv)} failed: {(proc.stderr or proc.stdout).strip()}")
    return proc.stdout


def _podman_info() -> Dict[str, Any]:
    raw = _run(["podman", "info", "--format", "json"])
    try:
        return json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        raise EnvironmentError(f"podman info returned non-JSON output: {exc}") from exc


def _podman_version() -> Dict[str, Any]:
    raw = _run(["podman", "version", "--format", "json"])
    try:
        return json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        raise EnvironmentError(f"podman version returned non-JSON output: {exc}") from exc


def cgroup_version() -> str:
    stat = shutil.which("stat")
    if not stat:
        return "unknown"
    proc = subprocess.run(
        [stat, "-fc", "%T", "/sys/fs/cgroup"],
        capture_output=True, text=True, check=False, timeout=10,
    )
    if proc.returncode != 0:
        return "unknown"
    filesystem = proc.stdout.strip()
    if filesystem == "cgroup2fs":
        return "v2"
    if filesystem == "tmpfs":
        return "v1"
    return "unknown"


def hw_virtualization() -> str:
    path = Path("/sys/hypervisor/type")
    if path.exists():
        return path.read_text(encoding="utf-8").strip() or "unknown"
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        text = cpuinfo.read_text(encoding="utf-8", errors="replace")
        if "hypervisor" in text.split("\n\n", 1)[0]:
            return "virtualized"
    return "bare-metal"


def memory_bytes() -> int:
    meminfo = Path("/proc/meminfo")
    if not meminfo.exists():
        return 0
    for line in meminfo.read_text(encoding="utf-8").splitlines():
        if line.startswith("MemTotal:"):
            return int(line.split()[1]) * 1024
    return 0


def os_release() -> Dict[str, str]:
    data: Dict[str, str] = {}
    path = Path("/etc/os-release")
    if not path.exists():
        return data
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if not separator:
            continue
        data[key.strip()] = value.strip().strip('"')
    return data


def _image_inventory() -> Dict[str, Dict[str, str]]:
    errors = validate_lock()
    if errors:
        raise EnvironmentError("image lock is not usable: " + "; ".join(errors))
    return {
        alias: {"reference": entry.reference, "digest": entry.digest, "role": entry.role}
        for alias, entry in entries().items()
    }


def collect_environment(topology: str = "unknown", run_id: Optional[str] = None) -> Dict[str, Any]:
    info = _podman_info()
    version = _podman_version()
    host = info.get("host") or {}
    security = host.get("security") or {}
    oci_runtime = host.get("ociRuntime") or {}
    release = os_release()

    return {
        "schema": SCHEMA,
        "run_id": run_id or "",
        "topology": topology,
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": {
            "kernel": os.uname().release,
            "arch": platform.machine(),
            "os_release": release.get("PRETTY_NAME", "unknown"),
            "os_id": release.get("ID", "unknown"),
            "os_version_id": release.get("VERSION_ID", "unknown"),
            "cpu_count": os.cpu_count() or 0,
            "memory_bytes": memory_bytes(),
            "cgroup_version": cgroup_version(),
            "virtualization": hw_virtualization(),
            "python": platform.python_version(),
        },
        "podman": {
            "version": version.get("Client", {}).get("Version", ""),
            "api_version": version.get("Client", {}).get("APIVersion", ""),
            "go_version": version.get("Client", {}).get("GoVersion", ""),
            "rootless": security.get("rootless"),
            "selinux_enabled": security.get("selinuxEnabled"),
            "cgroup_version": host.get("cgroupVersion"),
            "cgroup_manager": host.get("cgroupManager"),
            "network_backend": host.get("networkBackend"),
            "oci_runtime": oci_runtime.get("name", ""),
            "oci_runtime_version": str(oci_runtime.get("version", "")).splitlines()[0] if oci_runtime.get("version") else "",
            "storage_driver": (info.get("store") or {}).get("graphDriverName", ""),
            "host_distribution": (host.get("distribution") or {}).get("distribution", ""),
            "host_kernel": host.get("kernel", ""),
        },
        "images": _image_inventory(),
    }


def write_environment(context: RunContext, environment: Optional[Dict[str, Any]] = None) -> Path:
    data = environment or collect_environment(context.topology, context.run_id)
    context.environment = data
    path = context.artifact_dir / "environment.json"
    tmp = context.artifact_dir / ".environment.json.tmp"
    tmp.write_text(redact(json.dumps(data, indent=2, sort_keys=True)), encoding="utf-8")
    tmp.chmod(0o600)
    os.replace(tmp, path)
    return path


def requirement_errors(environment: Dict[str, Any]) -> List[str]:
    """Fail-closed preconditions the gate depends on."""
    errors: List[str] = []
    podman = environment.get("podman") or {}
    host = environment.get("host") or {}
    if podman.get("rootless") is not False:
        errors.append("rootful Podman is required; rootless cannot verify INPUT firewall isolation")
    if host.get("cgroup_version") != "v2":
        errors.append(f"cgroup v2 is required for resource accounting, host reports {host.get('cgroup_version')!r}")
    if not podman.get("network_backend"):
        errors.append("Podman network backend could not be determined")
    for alias, image in (environment.get("images") or {}).items():
        if not str(image.get("digest", "")).startswith("sha256:"):
            errors.append(f"image {alias} is not pinned by digest")
    return errors


def main() -> int:
    try:
        data = collect_environment()
    except EnvironmentError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(data, indent=2, sort_keys=True))
    for error in requirement_errors(data):
        print(f"ERROR: {error}", file=sys.stderr)
    return 0 if not requirement_errors(data) else 1


if __name__ == "__main__":
    sys.exit(main())
