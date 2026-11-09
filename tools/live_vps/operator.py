#!/usr/bin/env python3
"""Interactive local operator for the Live VPS E2E runner.

Passwords are read with getpass and used only for the first SSH bootstrap.
The test runner receives temporary Ed25519 keys and pinned known_hosts files.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import getpass
import os
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

try:
    import paramiko
except ImportError:
    paramiko = None

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = REPO_ROOT / "tools"
sys.path.insert(0, str(TOOLS_DIR))
sys.path.insert(0, str(REPO_ROOT))

from live_vps.ssh import SSHClient
from live_vps.config import load_config
from live_vps.preflight import check_control_machine_tools
from live_vps.dns import verify_all_domains
from live_vps.reporting import write_result_json, write_junit_report, write_summary_txt
from test_live_vps import build_test_cases_from_state, load_run_state, save_run_state

SSH_TIMEOUT = 15
TEMP_ACCESS_TTL_HOURS = 2


def _public_key_line(key: Any, marker: str) -> str:
    """Build an authorized_keys entry with forwarding, agent, X11, and PTY disabled."""
    encoded = base64.b64encode(key.asbytes()).decode("ascii")
    return f"restrict {key.get_name()} {encoded} {marker}"


def _fingerprint(key: Any) -> str:
    digest = __import__("hashlib").sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _exec(transport: Any, command: str, timeout: int = SSH_TIMEOUT) -> tuple[int, str, str]:
    channel = transport.open_session(timeout=timeout)
    stdout_chunks, stderr_chunks = [], []
    deadline = time.monotonic() + timeout
    try:
        channel.settimeout(0.5)
        channel.exec_command(command)
        channel.shutdown_write()
        while not channel.exit_status_ready():
            if time.monotonic() >= deadline:
                raise TimeoutError(f"remote bootstrap command exceeded {timeout} seconds")
            if channel.recv_ready():
                stdout_chunks.append(channel.recv(65536))
            if channel.recv_stderr_ready():
                stderr_chunks.append(channel.recv_stderr(65536))
            if not channel.recv_ready() and not channel.recv_stderr_ready():
                time.sleep(0.05)
        while channel.recv_ready():
            stdout_chunks.append(channel.recv(65536))
        while channel.recv_stderr_ready():
            stderr_chunks.append(channel.recv_stderr(65536))
        status = channel.recv_exit_status()
        return (
            status,
            b"".join(stdout_chunks).decode("utf-8", "replace"),
            b"".join(stderr_chunks).decode("utf-8", "replace"),
        )
    finally:
        channel.close()


def _sftp_write(sftp: Any, path: str, content: str, mode: int) -> None:
    with sftp.file(path, "w") as stream:
        stream.write(content)
        stream.flush()
    sftp.chmod(path, mode)


def _remote_cleanup_script(
    run_id: str, marker: str, label: str, auth_created: bool,
    ssh_dir_created: bool, auth_mode: int,
) -> str:
    timer = f"gowave-e2e-key-expiry-{run_id}-{label.lower()}"
    script = f"/usr/local/sbin/{timer}.sh"
    timer_unit = f"/etc/systemd/system/{timer}.timer"
    service_unit = f"/etc/systemd/system/{timer}.service"
    remove_created_auth = "1" if auth_created else "0"
    remove_created_ssh_dir = "1" if ssh_dir_created else "0"
    return f"""#!/bin/sh
set -eu
AK=/root/.ssh/authorized_keys
MARKER='{marker}'
if [ -f "$AK" ] && grep -Fq -- "$MARKER" "$AK"; then
  TMP="$(mktemp /root/.ssh/.authorized_keys.XXXXXX)"
  awk -v marker="$MARKER" 'index($0, marker) == 0' "$AK" > "$TMP"
  chown root:root "$TMP"
  chmod {auth_mode:04o} "$TMP"
  mv -f "$TMP" "$AK"
fi
if [ '{remove_created_auth}' = 1 ] && [ -f "$AK" ] && ! grep -q '[^[:space:]]' "$AK"; then
  rm -f "$AK"
fi
systemctl disable --now '{timer}.timer' >/dev/null 2>&1 || true
rm -f '{timer_unit}' '{service_unit}' '{script}' '/root/.ssh/.authorized_keys.{run_id}.tmp'
systemctl daemon-reload >/dev/null 2>&1 || true
if [ '{remove_created_ssh_dir}' = 1 ]; then rmdir /root/.ssh 2>/dev/null || true; fi
"""

def _bootstrap_one(
    *,
    label: str,
    host: str,
    port: int,
    username: str,
    run_id: str,
    runtime_dir: Path,
) -> dict[str, Any]:
    if username != "root":
        raise ValueError(
            f"{label}: this runner currently requires SSH login 'root'; "
            "a least-privilege sudo adapter is not implemented."
        )
    print(f"\n{label}: connecting to {host}:{port} to inspect the SSH host key…")
    sock = socket.create_connection((host, port), timeout=SSH_TIMEOUT)
    transport = paramiko.Transport(sock)
    transport.auth_timeout = SSH_TIMEOUT
    timer_files_created = False
    timer_armed = False
    key_installed = False
    private_key_path = runtime_dir / f"{label.lower()}_ephemeral_ed25519"
    known_hosts_path = runtime_dir / f"{label.lower()}_known_hosts"
    marker = f"gowave-e2e:{run_id}:{label.lower()}:{secrets.token_hex(8)}"
    timer = f"gowave-e2e-key-expiry-{run_id}-{label.lower()}"
    password: str | None = None
    try:
        transport.start_client(timeout=SSH_TIMEOUT)
        server_key = transport.get_remote_server_key()
        actual = _fingerprint(server_key)
        print(f"{label} SSH host-key fingerprint: {actual}")
        print("Compare this value with the fingerprint shown by your VPS provider console.")
        expected = input("Type the complete fingerprint to confirm this host: ").strip()
        if not secrets.compare_digest(expected, actual):
            raise RuntimeError(f"{label}: host-key fingerprint was not confirmed; no password was sent.")

        password = getpass.getpass(f"{label} root SSH password (hidden): ")
        if not password:
            raise ValueError(f"{label}: empty password is not accepted.")
        transport.auth_password(username=username, password=password)
        password = None
        if not transport.is_authenticated():
            raise PermissionError(f"{label}: SSH password authentication failed.")

        uid_status, uid_out, _ = _exec(transport, "id -u")
        if uid_status != 0 or uid_out.strip() != "0":
            raise PermissionError(f"{label}: authenticated account is not root.")

        private_key = paramiko.Ed25519Key.generate()
        private_key.write_private_key_file(str(private_key_path))
        os.chmod(private_key_path, 0o600)
        public_key = _public_key_line(private_key, marker)

        sftp = paramiko.SFTPClient.from_transport(transport)
        try:
            ssh_dir_created = False
            auth_created = False
            auth_mode = 0o600
            try:
                ssh_dir_attrs = sftp.lstat("/root/.ssh")
                if stat.S_ISLNK(ssh_dir_attrs.st_mode) or not stat.S_ISDIR(ssh_dir_attrs.st_mode):
                    raise RuntimeError(f"{label}: /root/.ssh must be a real directory.")
                if ssh_dir_attrs.st_uid != 0 or ssh_dir_attrs.st_gid != 0:
                    raise RuntimeError(f"{label}: /root/.ssh must be owned by root:root.")
                if ssh_dir_attrs.st_mode & 0o022:
                    raise RuntimeError(f"{label}: /root/.ssh is group/world writable; refusing to modify it.")
            except FileNotFoundError:
                ssh_dir_created = True

            auth_path = "/root/.ssh/authorized_keys"
            if not ssh_dir_created:
                try:
                    auth_attrs = sftp.lstat(auth_path)
                    if stat.S_ISLNK(auth_attrs.st_mode) or not stat.S_ISREG(auth_attrs.st_mode):
                        raise RuntimeError(f"{label}: authorized_keys is not a regular file.")
                    if auth_attrs.st_uid != 0 or auth_attrs.st_gid != 0:
                        raise RuntimeError(f"{label}: authorized_keys must be owned by root:root.")
                    auth_mode = stat.S_IMODE(auth_attrs.st_mode)
                    if auth_mode & 0o022:
                        raise RuntimeError(f"{label}: authorized_keys is group/world writable; refusing to modify it.")
                    with sftp.file(auth_path, "r") as stream:
                        existing = stream.read().decode("utf-8", "strict")
                except FileNotFoundError:
                    auth_created = True
                    existing = ""
            else:
                auth_created = True
                existing = ""

            if marker in existing:
                raise RuntimeError(f"{label}: temporary key marker collision.")

            # Arm a persistent server-side expiry BEFORE adding the privileged key.
            # A dropped connection at any later point therefore cannot strand access.
            cleanup_script = _remote_cleanup_script(
                run_id, marker, label, auth_created, ssh_dir_created, auth_mode
            )
            script_path = f"/usr/local/sbin/{timer}.sh"
            service_path = f"/etc/systemd/system/{timer}.service"
            timer_path = f"/etc/systemd/system/{timer}.timer"
            _sftp_write(sftp, script_path, cleanup_script, 0o700)
            timer_files_created = True
            _sftp_write(
                sftp, service_path,
                "[Unit]\nDescription=Expire temporary GoWave E2E SSH access\n"
                "[Service]\nType=oneshot\nExecStart=/bin/sh " + script_path + "\n",
                0o644,
            )
            time_status, remote_time_text, time_error = _exec(
                transport, "date -u +%Y-%m-%dT%H:%M:%SZ"
            )
            if time_status:
                raise RuntimeError(f"{label}: could not read VPS UTC clock for expiry scheduling: {time_error.strip()}")
            try:
                remote_now = dt.datetime.strptime(
                    remote_time_text.strip(), "%Y-%m-%dT%H:%M:%SZ"
                ).replace(tzinfo=dt.timezone.utc)
            except ValueError as exc:
                raise RuntimeError(f"{label}: VPS returned an invalid UTC clock value.") from exc
            expiry = remote_now + dt.timedelta(hours=TEMP_ACCESS_TTL_HOURS)
            calendar = expiry.strftime("%Y-%m-%d %H:%M:%S UTC")
            _sftp_write(
                sftp, timer_path,
                "[Unit]\nDescription=Expiry timer for temporary GoWave E2E SSH access\n"
                "[Timer]\nOnActiveSec=" + str(TEMP_ACCESS_TTL_HOURS) + "h\nOnCalendar=" + calendar + "\nPersistent=true\nUnit=" + timer + ".service\n"
                "[Install]\nWantedBy=timers.target\n",
                0o644,
            )
            status, _, stderr = _exec(
                transport,
                f"systemctl daemon-reload && systemctl enable --now '{timer}.timer'",
            )
            if status:
                raise RuntimeError(f"{label}: could not arm persistent SSH-key expiry timer: {stderr.strip()}")
            timer_armed = True

            if ssh_dir_created:
                status, _, stderr = _exec(transport, "install -d -o root -g root -m 0700 /root/.ssh")
                if status:
                    raise RuntimeError(f"{label}: cannot create /root/.ssh: {stderr.strip()}")

            tmp_auth = f"/root/.ssh/.authorized_keys.{run_id}.tmp"
            new_content = existing.rstrip("\n") + ("\n" if existing.strip() else "") + public_key + "\n"
            _sftp_write(sftp, tmp_auth, new_content, auth_mode)
            status, _, stderr = _exec(
                transport,
                f"chown root:root '{tmp_auth}' && chmod {auth_mode:04o} '{tmp_auth}' && mv -f '{tmp_auth}' '{auth_path}'",
            )
            if status:
                raise RuntimeError(f"{label}: could not atomically install temporary authorized_keys entry: {stderr.strip()}")
            key_installed = True
        finally:
            sftp.close()

        host_pattern = host if port == 22 else f"[{host}]:{port}"
        key_line = f"{host_pattern} {server_key.get_name()} {base64.b64encode(server_key.asbytes()).decode('ascii')}\n"
        known_hosts_path.write_text(key_line, encoding="utf-8")
        os.chmod(known_hosts_path, 0o600)
        return {
            "host": host, "port": port, "user": username,
            "key_path": private_key_path, "known_hosts": known_hosts_path,
            "marker": marker, "timer": timer,
        }
    except BaseException:
        if timer_files_created or timer_armed or key_installed:
            cleanup_verified = False
            try:
                script_path = f"/usr/local/sbin/{timer}.sh"
                timer_path = f"/etc/systemd/system/{timer}.timer"
                service_path = f"/etc/systemd/system/{timer}.service"
                rollback = (
                    f"if [ -x '{script_path}' ]; then /bin/sh '{script_path}'; "
                    f"else rm -f '{timer_path}' '{service_path}' '/usr/local/sbin/{timer}.sh'; "
                    "systemctl daemon-reload >/dev/null 2>&1 || true; fi"
                )
                cleanup_result = _exec(transport, rollback)
                cleanup_verified = cleanup_result[0] == 0
            except Exception:
                cleanup_verified = False
            if not cleanup_verified and (timer_armed or key_installed):
                print(f"WARNING: {label} bootstrap cleanup could not be verified; remote expiry timer is the fallback.", file=sys.stderr)
        raise
    finally:
        password = None
        transport.close()


def _cleanup_access(target: dict[str, Any]) -> tuple[bool, str]:
    client = SSHClient(
        host=target["host"], port=target["port"], user=target["user"],
        key_path=target["key_path"], known_hosts=target["known_hosts"],
    )
    script = f"/usr/local/sbin/{target['timer']}.sh"
    marker = target["marker"]
    timer = target["timer"]
    command = (
        f"if [ -x '{script}' ]; then /bin/sh '{script}' || true; fi; "
        f"if grep -Fq -- '{marker}' /root/.ssh/authorized_keys 2>/dev/null; then exit 1; fi; "
        f"! systemctl is-active --quiet '{timer}.timer'"
    )
    result = client.run(command, timeout=30)
    if result.ok:
        return True, "temporary SSH key removed and expiry timer disabled"
    return False, (
        "could not verify temporary SSH-key removal; persistent remote expiry timer "
        "was armed and will remove the key at its scheduled deadline"
    )


def _build_config(template: Path, output: Path, values: dict[str, str]) -> None:
    lines = template.read_text(encoding="utf-8").splitlines()
    keys = set(values)
    kept = []
    for line in lines:
        stripped = line.strip()
        if "=" in stripped and not stripped.startswith("#"):
            key = stripped.split("=", 1)[0].strip()
            if key in keys:
                continue
        kept.append(line)
    kept.extend(f"{key}={value}" for key, value in values.items())
    output.write_text("\n".join(kept) + "\n", encoding="utf-8")
    os.chmod(output, 0o600)


def _refresh_report(run_id: str, cleanup: dict[str, Any]) -> None:
    artifact_dir = REPO_ROOT / "artifacts" / "live-vps" / run_id
    state_file = artifact_dir / "run-state.json"
    if not state_file.is_file():
        return
    state = load_run_state(artifact_dir)
    state.setdefault("results", {})["operator_access_cleanup"] = cleanup
    if cleanup.get("status") != "PASS" and state.get("overall") == "PASS":
        state["overall"] = "INCOMPLETE"
    save_run_state(artifact_dir, state)
    write_result_json(artifact_dir, state)
    write_junit_report(artifact_dir, build_test_cases_from_state(state))
    write_summary_txt(artifact_dir, state)


def _handle_termination(signum: int, frame: Any) -> None:
    raise KeyboardInterrupt(f"received signal {signum}")


def _run_runner(command: list[str], cwd: Path) -> int:
    """Run the E2E child and stop it before access revocation on interruption."""
    process = subprocess.Popen(command, cwd=cwd)
    try:
        return process.wait()
    except BaseException:
        if process.poll() is None:
            try:
                process.send_signal(signal.SIGINT)
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        raise


def _build_runner_command(config_path: Path, run_id: str, mode: str) -> list[str]:
    if mode not in ("preflight", "full"):
        raise ValueError(f"Unsupported operator mode: {mode}")
    return [sys.executable, str(TOOLS_DIR / "test_live_vps.py"), "--config", str(config_path), "--mode", mode, "--run-id", run_id]


def run_interactive(acme_mode: str, mode: str = "full") -> int:
    signal.signal(signal.SIGTERM, _handle_termination)
    signal.signal(signal.SIGHUP, _handle_termination)
    if paramiko is None:
        print(
            "Missing dependency. Install it with: "
            "python3 -m pip install -r tools/requirements-live-vps.txt",
            file=sys.stderr,
        )
        return 1
    for tool in ("ssh-keygen", "dig", "openssl", "curl", "xray", "mihomo"):
        if shutil.which(tool) is None:
            print(f"Required local tool not found: {tool}", file=sys.stderr)
            return 1

    print(f"Live VPS E2E — local operator ({mode})")
    print("Only disposable VPS instances are accepted by the existing preflight gate.")
    if mode == "preflight":
        print("Preflight does not install GoWave or change its services; temporary SSH access is bootstrapped and revoked afterwards.")
    else:
        print("Full mode installs GoWave on both disposable VPS instances.")
    print("The SSH account must be root. Passwords are hidden and are not written to disk.")
    master_ip = input("Master public IPv4: ").strip()
    master_port = int(input("Master SSH port [22]: ").strip() or "22")
    master_user = input("Master SSH login [root]: ").strip() or "root"
    master_panel = input("Master Panel subdomain: ").strip()
    master_reality = input("Master REALITY subdomain: ").strip()
    master_vision = input("Master Vision domain (optional; Enter to disable): ").strip()
    worker_ip = input("Worker public IPv4: ").strip()
    worker_port = int(input("Worker SSH port [22]: ").strip() or "22")
    worker_user = input("Worker SSH login [root]: ").strip() or "root"
    worker_domain = input("Worker NGINX subdomain: ").strip()
    worker_reality = input("Worker REALITY subdomain: ").strip()
    worker_vision = input("Worker Vision domain (optional; Enter to disable): ").strip()
    admin_email = input("ACME registration email" + (" (required)" if mode == "full" else " (optional for preflight)") + ": ").strip()
    if mode == "full" and not admin_email:
        raise ValueError("A real ACME registration email is required for full deployment.")
    if mode == "full" and acme_mode == "production":
        confirmation = input("Production ACME can consume rate limits. Type PRODUCTION to continue: ").strip()
        if confirmation != "PRODUCTION":
            print("Production ACME was not confirmed; aborting before any VPS connection.")
            return 1

    run_id = "run-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
    targets: list[dict[str, Any]] = []
    cleanup_results: dict[str, Any] = {}
    result_code = 1
    runtime_base = os.environ.get("XDG_RUNTIME_DIR")
    if runtime_base:
        runtime_path = Path(runtime_base)
        try:
            runtime_stat = runtime_path.stat()
            if runtime_stat.st_uid != os.getuid() or stat.S_IMODE(runtime_stat.st_mode) & 0o077:
                runtime_base = None
        except OSError:
            runtime_base = None
    if not runtime_base and Path("/dev/shm").is_dir():
        runtime_base = "/dev/shm"
    with tempfile.TemporaryDirectory(prefix="gowave-live-vps-", dir=runtime_base) as tmp:
        runtime_dir = Path(tmp)
        os.chmod(runtime_dir, 0o700)
        try:
            # Validate addresses, domains, versions, and topology before opening either SSH connection.
            validation_path = runtime_dir / "validation.env"
            validation_values = {
                "MASTER_IP": master_ip, "MASTER_PANEL_DOMAIN": master_panel,
                "MASTER_REALITY_DOMAIN": master_reality,
                "MASTER_SSH_PORT": str(master_port), "MASTER_SSH_USER": master_user,
                "WORKER_IP": worker_ip, "WORKER_DOMAIN": worker_domain,
                "WORKER_REALITY_DOMAIN": worker_reality, "WORKER_SSH_PORT": str(worker_port),
                "WORKER_SSH_USER": worker_user, "SSH_KEY_PATH": "/tmp/not-used",
                "SSH_KNOWN_HOSTS": "/tmp/not-used", "ACME_MODE": acme_mode,
                "ADMIN_EMAIL": admin_email,
            }
            if master_vision:
                validation_values["MASTER_VISION_DOMAIN"] = master_vision
            if worker_vision:
                validation_values["WORKER_VISION_DOMAIN"] = worker_vision
            _build_config(TOOLS_DIR / "live_vps_config.env.example", validation_path, validation_values)
            validation_config = load_config(validation_path)
            tool_checks = check_control_machine_tools(validation_config)
            failed_tools = [f"{name}: {check.error}" for name, check in tool_checks.items() if not check.ok]
            if failed_tools:
                raise RuntimeError("Local tool/version preflight failed before SSH: " + "; ".join(failed_tools))
            dns_checks = verify_all_domains(validation_config)
            failed_dns = [f"{name}: {check.error}" for name, check in dns_checks.items() if not check.ok]
            if failed_dns:
                raise RuntimeError("DNS preflight failed before SSH: " + "; ".join(failed_dns))
            targets.append(_bootstrap_one(
                label="MASTER", host=master_ip, port=master_port, username=master_user,
                run_id=run_id, runtime_dir=runtime_dir,
            ))
            targets.append(_bootstrap_one(
                label="WORKER", host=worker_ip, port=worker_port, username=worker_user,
                run_id=run_id, runtime_dir=runtime_dir,
            ))

            template = TOOLS_DIR / "live_vps_config.env.example"
            config_path = runtime_dir / "live_vps_config.env"
            values = {
                "MASTER_IP": master_ip,
                "MASTER_PANEL_DOMAIN": master_panel,
                "MASTER_REALITY_DOMAIN": master_reality,
                "MASTER_SSH_PORT": str(master_port),
                "MASTER_SSH_USER": master_user,
                "WORKER_IP": worker_ip,
                "WORKER_DOMAIN": worker_domain,
                "WORKER_REALITY_DOMAIN": worker_reality,
                "WORKER_SSH_PORT": str(worker_port),
                "WORKER_SSH_USER": worker_user,
                "SSH_KEY_PATH": str(targets[0]["key_path"]),
                "SSH_KNOWN_HOSTS": str(targets[0]["known_hosts"]),
                "MASTER_SSH_KEY_PATH": str(targets[0]["key_path"]),
                "WORKER_SSH_KEY_PATH": str(targets[1]["key_path"]),
                "MASTER_KNOWN_HOSTS_PATH": str(targets[0]["known_hosts"]),
                "WORKER_KNOWN_HOSTS_PATH": str(targets[1]["known_hosts"]),
                "ACME_MODE": acme_mode,
                "ADMIN_EMAIL": admin_email,
            }
            if master_vision:
                values["MASTER_VISION_DOMAIN"] = master_vision
            if worker_vision:
                values["WORKER_VISION_DOMAIN"] = worker_vision
            _build_config(template, config_path, values)
            result_code = _run_runner(_build_runner_command(config_path, run_id, mode), cwd=REPO_ROOT)
        except KeyboardInterrupt:
            print("\nInterrupted. Attempting to revoke temporary SSH access…", file=sys.stderr)
            result_code = 130
        except Exception as exc:
            print(f"Operator setup failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            result_code = 1
        finally:
            for target in reversed(targets):
                try:
                    ok, message = _cleanup_access(target)
                except Exception as exc:
                    ok = False
                    message = f"cleanup could not be verified ({type(exc).__name__}); remote expiry timer remains the fallback"
                cleanup_results[target["user"] + "@" + target["host"]] = {
                    "status": "PASS" if ok else "INCOMPLETE",
                    "message": message,
                }
                print(f"{target['host']}: {message}")
            if targets:
                cleanup_ok = all(item["status"] == "PASS" for item in cleanup_results.values())
                try:
                    _refresh_report(run_id, {
                        "status": "PASS" if cleanup_ok else "INCOMPLETE",
                        "targets": cleanup_results,
                        "ttl_hours": TEMP_ACCESS_TTL_HOURS,
                    })
                except Exception as exc:
                    print(f"WARNING: could not update the final cleanup report ({type(exc).__name__}).", file=sys.stderr)
                    result_code = 2
                if not cleanup_ok and result_code == 0:
                    result_code = 2
    return result_code


def main() -> int:
    parser = argparse.ArgumentParser(description="Interactive local Live VPS E2E controller")
    parser.add_argument("--acme-mode", choices=("staging", "production"), default="staging")
    parser.add_argument("--mode", choices=("preflight", "full"), default="full",
                        help="preflight checks both disposable VPS without installing GoWave; full performs deployment")
    args = parser.parse_args()
    try:
        return run_interactive(args.acme_mode, args.mode)
    except (ValueError, OSError) as exc:
        print(f"Input/preflight error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
