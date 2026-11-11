"""Deployment orchestration for Master VPS All-in-One installation and
Distributed Worker deployment with Master-side argv tracing.
"""
from __future__ import annotations

import ast
import json
import os
import re
import shlex
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .ssh import SSHClient, SSHResult
from .redaction import redact
from .config import LiveVPSConfig
from .tls import build_runtime_ca_bundle

ACME_MODE_URLS = {
    "staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "production": "https://acme-v02.api.letsencrypt.org/directory",
}


def output_matches_pinned_version(output: str, expected: str) -> bool:
    """Require the exact configured version token in a tool's version output."""
    normalized = str(expected).strip().lstrip("vV")
    if not normalized:
        return False
    pattern = rf"(?<![A-Za-z0-9])v?{re.escape(normalized)}(?![A-Za-z0-9])"
    return re.search(pattern, output or "", flags=re.IGNORECASE) is not None


def parse_strace_argv_output(trace_text: str, secrets: List[str]) -> Dict[str, Any]:
    """Parse strace execve/execveat trace text on Master.
    Inspects argv vectors only, discards envp, detects truncation and abbreviation markers.
    """
    exec_count = 0
    secret_found = False
    truncated = False
    abbreviated = False
    errors: List[str] = []

    for line in trace_text.splitlines():
        if "<unfinished" in line:
            errors.append("Unfinished syscall detected in strace output")
            continue
        if "resumed>" in line:
            continue

        m = re.search(r"(?:execve|execveat)\((.*)\)\s*=\s*(-?\d+)", line)
        if not m:
            continue

        exec_count += 1
        args_str = m.group(1)

        # Look for strace truncation or abbreviation markers
        if ", ...]" in args_str or "[..." in args_str:
            abbreviated = True
        if '"...' in args_str:
            truncated = True

        bracket_start = args_str.find("[")
        if bracket_start == -1:
            errors.append(f"No argv array found in exec record: {line[:60]}")
            continue

        # Parse bracket depth to extract argv
        depth = 0
        bracket_end = -1
        in_str = False
        escape = False
        for i, ch in enumerate(args_str[bracket_start:], start=bracket_start):
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_str = False
            else:
                if ch == '"':
                    in_str = True
                elif ch == "[":
                    depth += 1
                elif ch == "]":
                    depth -= 1
                    if depth == 0:
                        bracket_end = i
                        break

        if bracket_end == -1:
            errors.append("Unmatched bracket in argv vector")
            continue

        argv_raw = args_str[bracket_start : bracket_end + 1]

        for sec in secrets:
            if sec and sec in argv_raw:
                secret_found = True

        if '"]...' in argv_raw or '", ...' in argv_raw or '"...' in argv_raw:
            truncated = True

    status = "PASS"
    if secret_found:
        status = "FAIL"
    elif truncated or abbreviated or errors or exec_count == 0:
        status = "INCOMPLETE"

    return {
        "status": status,
        "exec_count": exec_count,
        "secret_found": secret_found,
        "truncated": truncated,
        "abbreviated": abbreviated,
        "errors": errors,
    }


def prepare_master_repository(master_ssh: SSHClient, local_repo: Path, target_dir: str = "/opt/gowave-auto-nginx") -> bool:
    """Stream git archive of HEAD to Master VPS and extract into target_dir."""
    # git archive defaults to an uncompressed tar stream. Use one matching
    # extractor: retrying tar -xf after tar -xzf has consumed stdin loses data.
    archive_cmd = ["git", "archive", "--format=tar", "HEAD"]
    proc = subprocess.Popen(archive_cmd, cwd=str(local_repo), stdout=subprocess.PIPE)
    tar_bytes, _ = proc.communicate()
    if proc.returncode != 0 or not tar_bytes:
        return False

    remote_dir = shlex.quote(target_dir)
    r = master_ssh.run(
        f"mkdir -p -- {remote_dir} && tar -xf - -C {remote_dir}",
        input_data=tar_bytes,
    )
    return r.ok


def ensure_strace_on_master(master_ssh: SSHClient) -> Tuple[bool, str]:
    """Ensure strace package is installed on Master and supports required flags."""
    r = master_ssh.run(
        "command -v strace >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y --no-install-recommends strace)"
    )
    if not r.ok:
        return False, f"Failed to install strace on Master: {r.stderr}"

    ver_r = master_ssh.run("strace -V")
    if not ver_r.ok:
        return False, "Failed to interrogate strace version on Master"

    check_cmd = "strace -f -v -s 100 -e trace=execve,execveat true 2>/dev/null"
    test_r = master_ssh.run(check_cmd)
    if not test_r.ok:
        return False, "Installed strace does not support required flags (-f, -v, -s, execve,execveat)"

    return True, ver_r.stdout.splitlines()[0] if ver_r.stdout else "strace installed"


def run_master_acceptance_fixtures(master_ssh: SSHClient) -> Tuple[bool, str]:
    """Execute acceptance fixtures on Master for execve and execveat:
    (a) sentinel after byte 32 of a long argument.
    (b) >= 128 argv elements with sentinel only in final element.
    Validates complete string capture and array non-abbreviation.
    """
    fixture_script = r"""
import os, sys, subprocess

limit = 32 * os.sysconf("SC_PAGE_SIZE")
sentinel_a = "SENTINEL_AFTER_BYTE_32_" + ("X" * 60)
long_arg = ("A" * 32) + sentinel_a
elements_b = [f"arg{i}" for i in range(127)] + ["SENTINEL_IN_FINAL_ELEMENT_128"]

# 1. Test fixture A with computed -s
cmd_a = ["strace", "-f", "-v", f"-s{limit}", "-e", "trace=execve,execveat", "python3", "-c", "import sys; sys.exit(0)", long_arg]
r_a = subprocess.run(cmd_a, capture_output=True, text=True)
if sentinel_a not in r_a.stderr:
    print(f"FAIL: Fixture A sentinel missing from strace output with -s{limit}")
    sys.exit(1)

# Prove default 32-byte limit truncates
cmd_a_default = ["strace", "-f", "-v", "-s32", "-e", "trace=execve,execveat", "python3", "-c", "import sys; sys.exit(0)", long_arg]
r_a_def = subprocess.run(cmd_a_default, capture_output=True, text=True)
if sentinel_a in r_a_def.stderr:
    print("FAIL: Sentinel A unexpectedly present with -s32")
    sys.exit(1)

# 2. Test fixture B with -v (>= 128 elements)
cmd_b = ["strace", "-f", "-v", f"-s{limit}", "-e", "trace=execve,execveat", "python3", "-c", "import sys; sys.exit(0)"] + elements_b
r_b = subprocess.run(cmd_b, capture_output=True, text=True)
if "SENTINEL_IN_FINAL_ELEMENT_128" not in r_b.stderr:
    print("FAIL: Fixture B sentinel missing from 128-element argv")
    sys.exit(1)

print("PASS")
sys.exit(0)
"""
    r = master_ssh.run("python3 -", input_data=fixture_script)
    if not r.ok or "PASS" not in r.stdout:
        return False, f"Acceptance fixtures failed on Master: {r.stderr or r.stdout}"
    return True, "Acceptance fixtures passed on Master"


def install_master(
    master_ssh: SSHClient,
    config: LiveVPSConfig,
    target_dir: str = "/opt/gowave-auto-nginx",
    lease_token: Optional[str] = None,
) -> Tuple[bool, Dict[str, Any]]:
    """Execute gowave-auto.sh install on Master and verify all invariants."""
    acme_server = ACME_MODE_URLS.get(config.acme_mode)
    if not acme_server:
        raise ValueError(f"Invalid ACME mode: {config.acme_mode}")

    # Stage the mode-specific CA bundle on Master under /run
    local_ca_bundle = build_runtime_ca_bundle(config.acme_mode)
    remote_ca_dir = "/run/live_vps_ca"
    remote_ca_file = f"{remote_ca_dir}/ca-bundle.crt"
    master_ssh.run(f"mkdir -p -m 0700 {remote_ca_dir}")
    master_ssh.copy_to_remote(local_ca_bundle, remote_ca_file)
    master_ssh.run(f"chmod 0600 {remote_ca_file}")

    # Pass immutable release versions and all non-secret arguments explicitly.
    env_values = {
        "GOWAVE_ACME_SERVER": acme_server,
        "GOWAVE_TLS_CA_FILE": remote_ca_file,
        "GOWAVE_NODE_REQUIRE_BUNDLED_INSTALLER": "1",
        "GOWAVE_NODE_INSTALLER_COMMIT": config.gowave_node_installer_commit,
        "GOWAVE_NODE_INSTALLER_SHA256": config.gowave_node_installer_sha256,
        "GOWAVE_PANEL_VERSION": config.gowave_panel_version,
        "GOWAVE_NODE_VERSION": config.gowave_node_version,
        "XRAY_SERVER_VERSION": config.xray_server_version,
        "GOWAVE_REALITY_FINGERPRINT": config.reality_fingerprint,
    }
    env_vars = "\n".join(
        f"export {key}={shlex.quote(str(value))}" for key, value in env_values.items()
    )

    args = [
        f"{target_dir}/gowave-auto.sh",
        "install",
        config.master_panel_domain,
        config.master_reality_domain,
        config.admin_email,
    ]
    if config.master_vision_domain:
        args.append(config.master_vision_domain)

    install_cmd = f"{env_vars}\nexec " + " ".join(shlex.quote(str(value)) for value in args)
    input_data = f"GOWAVE_LEASE: {lease_token}\n" if lease_token else None
    try:
        r = master_ssh.run(install_cmd, input_data=input_data, timeout=600)
    finally:
        master_ssh.run(f"rm -rf {remote_ca_dir}")
        if local_ca_bundle.exists():
            try:
                local_ca_bundle.unlink()
            except Exception:
                pass
    if not r.ok:
        return False, {"error": "gowave-auto.sh install exited non-zero", "stderr": r.stderr}

    # Verify services
    services = ["gowave.service", "gowave-node.service", "nginx.service", "fail2ban.service"]
    for svc in services:
        chk = master_ssh.run(f"systemctl is-active {svc}")
        if not chk.ok or chk.stdout.strip() != "active":
            return False, {"error": f"Required service {svc} is not active: {chk.stdout}"}

    # Verify listeners
    listeners_chk = master_ssh.run("ss -tlnp")
    listeners_out = listeners_chk.stdout
    if ":3000" not in listeners_out or ":3002" not in listeners_out or ":443" not in listeners_out:
        return False, {"error": "Required port listeners (3000, 3002, 443) missing on Master"}

    # Verify credentials file mode and ownership
    cred_chk = master_ssh.run("stat -c '%a %U %G' /root/gowave-credentials.txt")
    if not cred_chk.ok or cred_chk.stdout.strip() != "600 root root":
        return False, {"error": f"Invalid credentials permissions/owner: {cred_chk.stdout}"}

    # Verify credentials content has required keys
    cred_keys = master_ssh.run("grep -E '^(ADMIN_USERNAME|ADMIN_PASSWORD|SCOPED_API_TOKEN)=' /root/gowave-credentials.txt | wc -l")
    if not cred_keys.ok or int(cred_keys.stdout.strip() or "0") < 3:
        return False, {"error": "Credentials file missing required keys"}

    # Verify health
    health_chk = master_ssh.run(f"{target_dir}/gowave-auto.sh health")
    if not health_chk.ok or "HEALTHY" not in health_chk.stdout:
        return False, {"error": f"gowave-auto.sh health failed: {health_chk.stdout}"}

    # Interrogate exact Panel, Node and Node-managed Xray versions.
    panel_ver_r = master_ssh.run("/opt/gowave/gowave-server --version || /opt/gowave/gowave-server version")
    node_ver_r = master_ssh.run("/usr/local/bin/gowave-node --version || /usr/local/bin/gowave-node version")
    xray_ver_r = master_ssh.run("/opt/gowave-node/rw-core version")
    version_checks = {
        "panel": (panel_ver_r, config.gowave_panel_version),
        "node": (node_ver_r, config.gowave_node_version),
        "xray_server": (xray_ver_r, config.xray_server_version),
    }
    version_errors = []
    for component, (result, expected) in version_checks.items():
        observed = (result.stdout or "") + "\n" + (result.stderr or "")
        if not result.ok or not output_matches_pinned_version(observed, expected):
            version_errors.append({
                "component": component,
                "expected": expected,
                "observed": observed.strip()[:300],
            })
    if version_errors:
        return False, {"error": "Installed Master software does not match configured version pins",
                       "version_errors": version_errors}

    details = {
        "status": "PASS",
        "panel_version_output": panel_ver_r.stdout.strip(),
        "node_version_output": node_ver_r.stdout.strip(),
        "xray_server_version_output": xray_ver_r.stdout.strip(),
    }
    return True, details


def deploy_worker(
    master_ssh: SSHClient,
    worker_ssh: SSHClient,
    config: LiveVPSConfig,
    target_dir: str = "/opt/gowave-auto-nginx",
    lease_token: Optional[str] = None,
) -> Tuple[bool, Dict[str, Any]]:
    """Deploy Worker node from Master VPS under Master-side strace argv observer."""
    # Ensure strace on Master and run acceptance fixtures
    strace_ok, strace_msg = ensure_strace_on_master(master_ssh)
    if not strace_ok:
        return False, {"error": strace_msg, "status": "INCOMPLETE"}

    acc_ok, acc_msg = run_master_acceptance_fixtures(master_ssh)
    if not acc_ok:
        return False, {"error": acc_msg, "status": "INCOMPLETE"}

    acme_server = ACME_MODE_URLS.get(config.acme_mode)
    if not acme_server:
        raise ValueError(f"Invalid ACME mode: {config.acme_mode}")

    # Ensure Worker SSH credentials and known_hosts are staged on Master
    worker_key_path = Path(config.worker_ssh_key_path or config.ssh_key_path).expanduser()
    if worker_key_path.is_file():
        master_ssh.run(
            "mkdir -p -m 0700 /root/.ssh && cat > /root/.ssh/id_ed25519 && chmod 0600 /root/.ssh/id_ed25519",
            input_data=worker_key_path.read_text(encoding="utf-8"),
        )
    worker_kh_path = Path(config.worker_known_hosts_path or config.ssh_known_hosts).expanduser()
    if worker_kh_path.is_file():
        master_ssh.run(
            "mkdir -p -m 0700 /root/.ssh && cat > /root/.ssh/known_hosts && chmod 0600 /root/.ssh/known_hosts",
            input_data=worker_kh_path.read_text(encoding="utf-8"),
        )

    # Prepare private trace directory on Master
    master_ssh.run("mkdir -p -m 0700 /run/live_vps_strace && rm -f /run/live_vps_strace/worker_dispatch.trace")

    # Determine STRACE_LIMIT on Master
    limit_r = master_ssh.run('python3 -c "import os; print(32 * os.sysconf(\'SC_PAGE_SIZE\'))"')
    strace_limit = limit_r.stdout.strip() if limit_r.ok else "131072"

    # Command to run under strace on Master
    env_values = {
        "GOWAVE_ACME_SERVER": acme_server,
        "GOWAVE_NODE_REQUIRE_BUNDLED_INSTALLER": "1",
        "GOWAVE_NODE_INSTALLER_COMMIT": config.gowave_node_installer_commit,
        "GOWAVE_NODE_INSTALLER_SHA256": config.gowave_node_installer_sha256,
        "GOWAVE_NODE_VERSION": config.gowave_node_version,
        "XRAY_SERVER_VERSION": config.xray_server_version,
        "GOWAVE_REALITY_FINGERPRINT": config.reality_fingerprint,
    }
    env_vars = "\n".join(
        f"export {key}={shlex.quote(str(value))}" for key, value in env_values.items()
    )
    node_add_args = [
        f"{target_dir}/gowave-auto.sh", "node", "add",
    ]
    if config.worker_vision_domain:
        node_add_args.extend(["--vision-domain", config.worker_vision_domain])
    node_add_args.extend([
        "worker-1",
        config.worker_ip, config.worker_domain, config.worker_reality_domain,
        config.worker_ssh_user, str(config.worker_ssh_port),
    ])
    node_add_cmd = (
        f"{env_vars}\nstrace -f -v -s {shlex.quote(strace_limit)} "
        "-e trace=execve,execveat -o /run/live_vps_strace/worker_dispatch.trace "
        + " ".join(shlex.quote(str(value)) for value in node_add_args)
    )

    input_data = f"GOWAVE_LEASE: {lease_token}\n" if lease_token else None
    r = master_ssh.run(node_add_cmd, input_data=input_data, timeout=600)

    # Parse strace on Master VPS directly without exfiltrating envp
    parse_script = r"""
import json, os, re, sys

trace_path = "/run/live_vps_strace/worker_dispatch.trace"
if not os.path.exists(trace_path):
    print(json.dumps({"status": "INCOMPLETE", "error": "Trace file missing"}))
    sys.exit(0)

# Read secret key from rescue raw on Master to check for leakage
secret_key = sys.stdin.read().strip()

exec_count = 0
secret_found = False
truncated = False
abbreviated = False
errors = []

with open(trace_path, "r", errors="replace") as f:
    for line in f:
        if "resumed>" in line:
            continue
        m = re.search(r"(?:execve|execveat)\((.*)\)", line)
        if not m:
            continue
        exec_count += 1
        args_str = m.group(1)
        if ", ...]" in args_str or "[..." in args_str:
            abbreviated = True
        if '"...' in args_str:
            truncated = True

        bracket_start = args_str.find("[")
        if bracket_start == -1:
            if "<unfinished" not in line:
                errors.append("No argv array found")
            continue
        depth = 0
        bracket_end = -1
        in_str = False
        escape = False
        for i, ch in enumerate(args_str[bracket_start:], start=bracket_start):
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\\\":
                    escape = True
                elif ch == '"':
                    in_str = False
            else:
                if ch == '"':
                    in_str = True
                elif ch == "[":
                    depth += 1
                elif ch == "]":
                    depth -= 1
                    if depth == 0:
                        bracket_end = i
                        break
        if bracket_end != -1:
            argv_raw = args_str[bracket_start:bracket_end + 1]
            if secret_key and secret_key in argv_raw:
                secret_found = True
            if '"]...' in argv_raw or '", ...' in argv_raw or '"...' in argv_raw:
                truncated = True

# Securely remove trace file
try:
    os.remove(trace_path)
except Exception:
    pass

status = "PASS"
if secret_found:
    status = "FAIL"
elif truncated or abbreviated or errors or exec_count == 0:
    status = "INCOMPLETE"

print(json.dumps({
    "status": status,
    "exec_count": exec_count,
    "secret_found": secret_found,
    "truncated": truncated,
    "abbreviated": abbreviated,
    "errors": errors,
}))
"""
    # Fetch Master secret key for observer check via extract_secret_key
    sec_r = master_ssh.run(
        "(cd /opt/gowave && ./gowave-server rescue --print-secret-key-raw </dev/null 2>/dev/null) || "
        "/opt/gowave/gowave-server rescue --print-secret-key-raw </dev/null 2>/dev/null || true"
    )
    master_secret = sec_r.stdout.strip()

    if not sec_r.ok or not master_secret:
        observer_verdict: Dict[str, Any] = {
            "status": "INCOMPLETE", "error": "Could not obtain Master secret for argv observer"
        }
        parse_r = SSHResult(returncode=1, stdout="", stderr="secret extraction failed")
    else:
        # python - reads its program from stdin, so source and secret cannot
        # share that stream. Keep non-secret parser source in -c argv and send
        # only the secret through stdin.
        parse_cmd = "python3 -c " + shlex.quote(parse_script)
        parse_r = master_ssh.run(parse_cmd, input_data=master_secret)
        observer_verdict = {}
        if not parse_r.ok:
            observer_verdict = {"status": "INCOMPLETE", "error": "Remote argv observer process failed"}
        else:
            try:
                lines = parse_r.stdout.strip().splitlines()
                for ln in reversed(lines):
                    if ln.startswith("{") and ln.endswith("}"):
                        observer_verdict = json.loads(ln)
                        break
                if not observer_verdict:
                    observer_verdict = {"status": "INCOMPLETE", "error": "Observer emitted no JSON result"}
            except Exception as e:
                observer_verdict = {"status": "INCOMPLETE", "error": f"Failed to parse observer JSON: {e}"}

    # Audit Worker host state
    worker_state_ok = True
    worker_errors = []

    # gowave-node and nginx active on Worker
    for svc in ["gowave-node.service", "nginx.service"]:
        w_svc = worker_ssh.run(f"systemctl is-active {svc}")
        if not w_svc.ok or w_svc.stdout.strip() != "active":
            worker_state_ok = False
            worker_errors.append(f"Worker service {svc} not active")

    # Worker nginx -t
    w_ng = worker_ssh.run("nginx -t")
    if not w_ng.ok:
        worker_state_ok = False
        worker_errors.append("Worker nginx -t failed")

    # Deploy hook exists and executable
    w_hook = worker_ssh.run(
        "test -x /etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh || test -x /opt/gowave-node/deploy-hook.sh"
    )
    if not w_hook.ok:
        worker_state_ok = False
        worker_errors.append("Worker deploy-hook missing or not executable")

    # Cover reality assets exist
    w_cover = worker_ssh.run(
        "(test -d /var/www/gowave-auto-nginx/cover-reality && test -f /var/www/gowave-auto-nginx/cover-reality/index.html) || "
        "(test -d /opt/cover-reality && test -f /opt/cover-reality/index.html)"
    )
    if not w_cover.ok:
        worker_state_ok = False
        worker_errors.append("Worker cover-reality assets missing")

    worker_node_ver = worker_ssh.run(
        "/usr/local/bin/gowave-node version || /usr/local/bin/gowave-node --version || /opt/gowave-node/gowave-node version"
    )
    worker_xray_ver = worker_ssh.run("/opt/gowave-node/rw-core version")
    for component, result, expected in (
        ("node", worker_node_ver, config.gowave_node_version),
        ("xray_server", worker_xray_ver, config.xray_server_version),
    ):
        observed = (result.stdout or "") + "\n" + (result.stderr or "")
        if not result.ok or not output_matches_pinned_version(observed, expected):
            worker_state_ok = False
            worker_errors.append(
                f"Worker {component} version mismatch: expected {expected}, observed {observed.strip()[:200]}"
            )

    overall_ok = r.ok and observer_verdict.get("status") == "PASS" and worker_state_ok
    return overall_ok, {
        "dispatch_exit_code": r.returncode,
        "dispatch_stdout": (r.stdout or "").strip()[-1000:],
        "dispatch_stderr": (r.stderr or "").strip()[-1000:],
        "observer": observer_verdict,
        "worker_state_ok": worker_state_ok,
        "worker_errors": worker_errors,
    }
