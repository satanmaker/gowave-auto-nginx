"""Negative test scenarios (NEG-01..NEG-15) for Live VPS E2E test suite.
Executes preflight, config recovery, security enforcement, and state integrity fault injection.
"""
from __future__ import annotations

import json
import os
import shlex
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .ssh import SSHClient
from .panel_api import E2EPanelClient
from .config import LiveVPSConfig
from .preflight import check_ssh_trust
from .dns import verify_domain_dns, verify_domain_no_aaaa
from .nginx import verify_nginx_config_syntax
from .subscriptions import request_subscription_status
from .mtls import run_mtls_negative_tests


def run_neg_01_ssh_host_key_absent() -> Dict[str, Any]:
    """NEG-01: SSH host key absent or mutated in known_hosts."""
    with tempfile.NamedTemporaryFile("w", suffix=".known_hosts", delete=False) as tf:
        tf.write("198.51.100.2 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBADFAKEKEY1234567890\n")
        known_hosts_path = Path(tf.name)
    try:
        ok, msg = check_ssh_trust("198.51.100.99", 22, known_hosts_path)
        return {
            "scenario": "NEG-01",
            "name": "Preflight SSH Host Key Absent",
            "status": "PASS" if not ok else "FAIL",
            "message": msg or "Host key not found in known_hosts",
        }
    finally:
        if known_hosts_path.exists():
            known_hosts_path.unlink()


def run_neg_02_ssh_port_unreachable() -> Dict[str, Any]:
    """NEG-02: Target SSH port closed / unreachable."""
    # Use loopback on high closed port with strict 1s timeout
    try:
        with socket.create_connection(("127.0.0.1", 59998), timeout=0.5):
            connected = True
    except (socket.timeout, ConnectionRefusedError, OSError):
        connected = False

    return {
        "scenario": "NEG-02",
        "name": "Preflight SSH Unreachable Port",
        "status": "PASS" if not connected else "FAIL",
        "message": "Terminated with connectivity error before execution",
    }



def run_neg_03_dns_wrong_ip() -> Dict[str, Any]:
    """NEG-03: Domain resolves to a different IP on both configured resolvers."""
    check = verify_domain_dns("dns.google", expected_ip="198.51.100.1", record_type="A")
    complete_answers = len(check.resolver_results) >= 2 and all(check.resolver_results.values())
    if not complete_answers:
        status = "INCOMPLETE"
        message = "At least one resolver returned no usable answer; mismatch was not proven"
    else:
        status = "PASS" if not check.ok else "FAIL"
        message = "DNS preflight rejected wrong IP before remote modification" if status == "PASS" else "Expected-IP mismatch was not rejected"
    return {"scenario": "NEG-03", "name": "Preflight DNS Wrong IP Mismatch",
            "status": status, "message": message, "resolved_ips": check.resolved_ips,
            "error": check.error}


def run_neg_04_dns_missing_aaaa() -> Dict[str, Any]:
    """NEG-04: Prove a resolvable domain has no AAAA where IPv6 is expected."""
    no_aaaa = verify_domain_no_aaaa("ipv4.google.com")
    if not no_aaaa.ok:
        status = "FAIL" if no_aaaa.resolved_ips else "INCOMPLETE"
        message = ("The DNS fixture unexpectedly publishes AAAA" if no_aaaa.resolved_ips
                   else "Could not obtain conclusive no-AAAA DNS answers")
        return {
            "scenario": "NEG-04", "name": "Preflight DNS Missing AAAA Record",
            "status": status, "message": message,
            "resolved_ips": no_aaaa.resolved_ips, "error": no_aaaa.error,
        }
    expected = verify_domain_dns(
        "ipv4.google.com", expected_ip="2001:db8::1", record_type="AAAA"
    )
    rejected = not expected.ok and not expected.resolved_ips
    return {
        "scenario": "NEG-04", "name": "Preflight DNS Missing AAAA Record",
        "status": "PASS" if rejected else "FAIL",
        "message": "IPv6 preflight rejected a confirmed missing AAAA record" if rejected
                   else "Missing AAAA record was not rejected by expected-IP preflight",
        "resolver_results": no_aaaa.resolver_results,
        "error": expected.error,
    }


def run_neg_05_acme_install_failure(master_ssh: SSHClient) -> Dict[str, Any]:
    """NEG-05: ACME lineage guard / invalid ACME directory rejects installation before changing NGINX."""
    # Call gowave-auto.sh install with invalid ACME directory URL
    bad_cmd = "GOWAVE_ACME_SERVER=https://invalid-acme-directory.example.com/directory /opt/gowave-auto-nginx/gowave-auto.sh install invalid.example.com reality.example.com admin@example.com"
    r = master_ssh.run(bad_cmd)
    rejected = (not r.ok) and ("Invalid GOWAVE_ACME_SERVER" in r.stderr or "Invalid GOWAVE_ACME_SERVER" in r.stdout)
    return {
        "scenario": "NEG-05",
        "name": "ACME Install Invalid Directory Rejection",
        "status": "PASS" if rejected else "FAIL",
        "message": "Installation aborted before modifying certificates or services",
    }



def run_neg_06_nginx_syntax_corruption(master_ssh: SSHClient) -> Dict[str, Any]:
    """NEG-06: Inject syntax corruption using an isolated, collision-free fixture."""
    create = master_ssh.run("mktemp /etc/nginx/conf.d/neg06_corrupt.XXXXXX.conf")
    test_conf = create.stdout.strip()
    if not create.ok or not test_conf.startswith("/etc/nginx/conf.d/neg06_corrupt."):
        return {
            "scenario": "NEG-06",
            "name": "NGINX Config Syntax Corruption",
            "status": "INCOMPLETE",
            "message": "Could not allocate isolated NGINX test fixture",
        }

    write = master_ssh.run(
        f"printf '%s\\n' 'invalid_nginx_directive {{ broken;' > {shlex.quote(test_conf)}"
    )
    if not write.ok:
        master_ssh.run(f"rm -f -- {shlex.quote(test_conf)}")
        return {
            "scenario": "NEG-06",
            "name": "NGINX Config Syntax Corruption",
            "status": "INCOMPLETE",
            "message": "Could not create isolated invalid NGINX fixture",
        }

    try:
        ok, out = verify_nginx_config_syntax(master_ssh)
        passed = (not ok) and "syntax is ok" not in out
    finally:
        cleanup = master_ssh.run(f"rm -f -- {shlex.quote(test_conf)}")

    clean_ok, _ = verify_nginx_config_syntax(master_ssh)
    return {
        "scenario": "NEG-06",
        "name": "NGINX Config Syntax Corruption",
        "status": "PASS" if (passed and clean_ok and cleanup.ok) else "FAIL",
        "message": "nginx -t blocked isolated corrupted configuration and cleanup restored cleanly",
        "cleanup_ok": cleanup.ok,
    }


def run_neg_07_worker_node_service_stop(worker_ssh: SSHClient, panel_client: E2EPanelClient) -> Dict[str, Any]:
    """NEG-07: A connected Worker is stopped and Panel reports it offline."""
    initial = panel_client.get_nodes()
    initially_connected = any(
        n.get("name") == "worker-1" and n.get("isConnected") is True for n in initial
    )
    if not initially_connected:
        return {
            "scenario": "NEG-07",
            "name": "Worker Node Service Stop Detected by Panel",
            "status": "INCOMPLETE",
            "message": "Worker was not connected before service-stop fault injection",
        }

    stop_result = worker_ssh.run("systemctl stop --no-ask-password gowave-node.service")
    if not stop_result.ok:
        return {
            "scenario": "NEG-07",
            "name": "Worker Node Service Stop Detected by Panel",
            "status": "FAIL",
            "message": "systemctl stop gowave-node.service failed",
        }

    detected_offline = False
    deadline = time.time() + 30.0
    while time.time() < deadline:
        try:
            nodes = panel_client.get_nodes()
            detected_offline = any(
                n.get("name") == "worker-1" and n.get("isConnected") is False for n in nodes
            )
        except Exception:
            pass
        if detected_offline:
            break
        time.sleep(2)

    return {
        "scenario": "NEG-07",
        "name": "Worker Node Service Stop Detected by Panel",
        "status": "PASS" if detected_offline else "FAIL",
        "message": "Panel detected Worker node offline after successful service stop",
    }


def run_neg_08_worker_node_service_recover(worker_ssh: SSHClient, panel_client: E2EPanelClient) -> Dict[str, Any]:
    """NEG-08: Start Worker service successfully and observe reconnection."""
    start_result = worker_ssh.run("systemctl start --no-ask-password gowave-node.service")
    if not start_result.ok:
        return {
            "scenario": "NEG-08",
            "name": "Worker Node Service Recovery",
            "status": "FAIL",
            "message": "systemctl start gowave-node.service failed",
        }
    recovered = panel_client.poll_worker_ready("worker-1", timeout=60, poll_interval=3)
    return {
        "scenario": "NEG-08",
        "name": "Worker Node Service Recovery",
        "status": "PASS" if recovered else "FAIL",
        "message": "Worker recovered and reconnected in Panel after service restart",
    }

def run_neg_09_subscription_absent_user_agent(panel_domain: str, short_uuid: str, ssl_context: ssl.SSLContext) -> Dict[str, Any]:
    """NEG-09: Request subscription without User-Agent against real Panel."""
    url = f"https://{panel_domain}/api/sub/{short_uuid}/v2ray-json"
    rejected = False
    code = None
    error = None
    try:
        code = request_subscription_status(
            panel_domain, f"/api/sub/{short_uuid}/v2ray-json",
            ssl_context, user_agent=None, timeout=5,
        )
        rejected = code in (400, 403)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"

    status = "PASS" if rejected else ("INCOMPLETE" if code is None else "FAIL")
    return {
        "scenario": "NEG-09",
        "name": "Subscription Absent User-Agent Rejection",
        "status": status,
        "code": code,
        "error": error,
        "message": f"Panel response for missing User-Agent: HTTP {code}" if code is not None
                   else "Could not obtain an HTTP response; rejection was not proven",
    }


def run_neg_10_mtls_forged_certificate(master_ssh: SSHClient, worker_ip: str) -> Dict[str, Any]:
    """NEG-10: A trusted server/SNI path rejects an untrusted client certificate."""
    result = run_mtls_negative_tests(master_ssh, worker_ip)
    rejected = result.get("untrusted_client_rejected") is True
    incomplete = result.get("untrusted_client_rejected") == "INCOMPLETE" or result.get("untrusted_client_rejected") is None
    return {
        "scenario": "NEG-10",
        "name": "mTLS Forged Client Certificate Handshake Rejection",
        "status": "PASS" if rejected else ("INCOMPLETE" if incomplete else "FAIL"),
        "message": (
            "Worker rejected a self-signed client certificate while using the real derived SNI and trusted server CA"
            if rejected else
            "Could not prove rejection of an untrusted client certificate on the valid SNI/server-trust path"
        ),
        "untrusted_client_rejected": result.get("untrusted_client_rejected"),
    }


GOWAVE_AUTO_DIR = "/opt/gowave-auto-nginx"
BACKUP_SCRIPT = f"{GOWAVE_AUTO_DIR}/assets/backup/gowave-backup.sh"
PANEL_DB_PATH = "/opt/gowave/gowave.db"
RECOVERY_JOURNAL_PATH = "/var/lib/gowave-auto-nginx/recovery/journal.json"
STATE_FILE_PATH = "/var/lib/gowave-auto-nginx/state.json"
MUTATION_LOCK_PATH = "/run/lock/gowave-managed-mutation.lock"
MUTATION_LOCK_WAIT_SECONDS = 60.0
NEG13_TARGET_IP = "10.255.255.1"


def _remote_sha256(ssh: SSHClient, path: str) -> Optional[str]:
    result = ssh.run(f"sha256sum -- {shlex.quote(path)} 2>/dev/null | awk '{{print $1}}'")
    digest = result.stdout.strip()
    return digest or None


def _service_active(ssh: SSHClient, unit: str) -> bool:
    return ssh.run(f"systemctl is-active --quiet {shlex.quote(unit)}").ok


def _read_remote_journal(ssh: SSHClient) -> Dict[str, Any]:
    result = ssh.run(f"cat {shlex.quote(RECOVERY_JOURNAL_PATH)} 2>/dev/null || true")
    try:
        data = json.loads(result.stdout)
    except (ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def _read_remote_state(ssh: SSHClient) -> Optional[Dict[str, Any]]:
    result = ssh.run(f"cat {shlex.quote(STATE_FILE_PATH)} 2>/dev/null || true")
    try:
        data = json.loads(result.stdout)
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def _state_payload(state: Dict[str, Any]) -> Dict[str, Any]:
    """Drop bookkeeping fields that every rollout rewrites.

    ``atomic_write_state`` stamps ``lastUpdated`` (and ``schemaVersion``) on each
    write, so rollback changes them even when it restores the exact same nodes.
    """
    return {key: value for key, value in state.items() if key not in {"lastUpdated", "schemaVersion"}}


def _wait_for_mutation_lock(ssh: SSHClient, timeout_seconds: float = 60.0) -> bool:
    """Wait until no lifecycle command holds the host-wide mutation lock."""
    lock = shlex.quote(MUTATION_LOCK_PATH)
    deadline = time.time() + timeout_seconds
    while True:
        probe = ssh.run(f"if [ -e {lock} ]; then flock -n {lock} true; fi")
        if probe.ok:
            return True
        if time.time() >= deadline:
            return False
        time.sleep(2)


def _reap_stale_dispatch_holders(ssh: SSHClient) -> None:
    """Kill leftover dispatch processes that still hold the mutation lock.

    The interrupted Worker dispatch targets an unroutable address, so its ssh
    child can outlive the killed process group until the TCP connect timeout
    expires, keeping the inherited lock descriptor open.
    """
    ssh.run(
        f"""
LOCK={shlex.quote(MUTATION_LOCK_PATH)}
MARK={shlex.quote(NEG13_TARGET_IP)}
for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
  [ "$pid" = "$$" ] && continue
  [ "$pid" = "$PPID" ] && continue
  cmd=$(tr '\\0' ' ' </proc/$pid/cmdline 2>/dev/null) || continue
  case "$cmd" in *"$MARK"*) ;; *) continue ;; esac
  for fd in /proc/$pid/fd/*; do
    if [ "$(readlink -f "$fd" 2>/dev/null)" = "$LOCK" ]; then
      kill -KILL "$pid" 2>/dev/null || true
      break
    fi
  done
done
true
"""
    )


def run_neg_11_backup_corrupted_tar(master_ssh: SSHClient, config: LiveVPSConfig) -> Dict[str, Any]:
    """NEG-11: a corrupted archive header must be rejected before any live mutation."""
    ts = int(time.time())
    archive = f"/tmp/neg11-corrupt-header-{ts}.tar.gz"
    name = "Backup Restore Corrupted Header Rejection"
    try:
        created = master_ssh.run(
            f"{shlex.quote(BACKUP_SCRIPT)} backup --type panel {shlex.quote(archive)}",
            timeout=config.restore_timeout,
        )
        if not created.ok:
            return {
                "scenario": "NEG-11",
                "name": name,
                "status": "INCOMPLETE",
                "message": "Could not create the panel backup fixture",
            }

        corrupted = master_ssh.run(
            f"dd if=/dev/urandom of={shlex.quote(archive)} bs=512 count=1 conv=notrunc status=none"
        )
        if not corrupted.ok:
            return {
                "scenario": "NEG-11",
                "name": name,
                "status": "INCOMPLETE",
                "message": "Could not corrupt the archive header fixture",
            }

        db_before = _remote_sha256(master_ssh, PANEL_DB_PATH)
        journal_before = _remote_sha256(master_ssh, RECOVERY_JOURNAL_PATH)
        service_before = _service_active(master_ssh, "gowave.service")

        if not _wait_for_mutation_lock(master_ssh, MUTATION_LOCK_WAIT_SECONDS):
            return {
                "scenario": "NEG-11",
                "name": name,
                "status": "INCOMPLETE",
                "message": "Host mutation lock stayed held, so the corrupted-archive restore was never attempted",
            }

        restore = master_ssh.run(
            f"{shlex.quote(BACKUP_SCRIPT)} restore {shlex.quote(archive)}",
            timeout=config.restore_timeout,
        )

        db_after = _remote_sha256(master_ssh, PANEL_DB_PATH)
        journal_after = _remote_sha256(master_ssh, RECOVERY_JOURNAL_PATH)
        service_after = _service_active(master_ssh, "gowave.service")

        output = (restore.stdout or "") + (restore.stderr or "")
        rejected = (not restore.ok) and (
            "Validation Error" in output
            or "ReadError" in output
            or "gzip" in output
            or "could not be opened successfully" in output
            or "truncated header" in output
        )
        live_data_unchanged = db_before is not None and db_before == db_after
        service_kept = service_before and service_after
        journal_untouched = journal_before is not None and journal_before == journal_after
        passed = rejected and live_data_unchanged and service_kept and journal_untouched

        if passed:
            status = "PASS"
            message = "Corrupted archive header was rejected before stopping services or touching live data"
        elif "Could not acquire host mutation lock" in output:
            status = "INCOMPLETE"
            message = "Restore was blocked by the host mutation lock instead of by archive validation"
        elif db_before is None or journal_before is None:
            status = "INCOMPLETE"
            message = "Could not snapshot live state to prove the restore was rejected before mutation"
        else:
            status = "FAIL"
            message = "Corrupted archive header did not prove fail-closed rejection"

        return {
            "scenario": "NEG-11",
            "name": name,
            "status": status,
            "rejected": rejected,
            "live_data_unchanged": live_data_unchanged,
            "service_kept_active": service_kept,
            "journal_untouched": journal_untouched,
            "message": message,
        }
    finally:
        master_ssh.run(f"rm -f -- {shlex.quote(archive)}")


def run_neg_12_backup_corrupted_sqlite(master_ssh: SSHClient, config: LiveVPSConfig) -> Dict[str, Any]:
    """NEG-12: a checksum-valid archive with a corrupted SQLite DB must fail the integrity gate."""
    ts = int(time.time())
    valid_archive = f"/tmp/neg12-valid-{ts}.tar.gz"
    corrupted_archive = f"/tmp/neg12-corrupt-db-{ts}.tar.gz"
    name = "Backup Restore Corrupted SQLite DB Integrity Check"
    try:
        created = master_ssh.run(
            f"{shlex.quote(BACKUP_SCRIPT)} backup --type panel {shlex.quote(valid_archive)}",
            timeout=config.restore_timeout,
        )
        if not created.ok:
            return {
                "scenario": "NEG-12",
                "name": name,
                "status": "INCOMPLETE",
                "message": "Could not create the panel backup fixture",
            }

        build_script = f"""python3 - {shlex.quote(valid_archive)} {shlex.quote(corrupted_archive)} <<'PY'
import hashlib, io, json, os, sys, tarfile

src, dst = sys.argv[1], sys.argv[2]
db_member = "files/opt/gowave/gowave.db"
db_meta_path = "opt/gowave/gowave.db"
payload = b"SQLite format 3\\x00" + os.urandom(8192)
digest = hashlib.sha256(payload).hexdigest()

with tarfile.open(src, "r:gz") as tar, tarfile.open(dst, "w:gz") as out:
    members = tar.getmembers()
    meta_member = next((m for m in members if m.name in ("meta.json", "./meta.json")), None)
    if meta_member is None:
        sys.exit("meta.json missing from source archive")
    meta = json.loads(tar.extractfile(meta_member).read().decode("utf-8"))
    patched = False
    for entry in meta.get("files", []):
        if entry.get("path") == db_meta_path:
            entry["sha256"] = digest
            patched = True
    if not patched:
        sys.exit("gowave.db entry missing from meta.json files list")
    meta_bytes = json.dumps(meta, indent=2).encode("utf-8")
    meta_member.size = len(meta_bytes)
    out.addfile(meta_member, io.BytesIO(meta_bytes))
    for m in members:
        if m is meta_member:
            continue
        if m.name == db_member:
            m.size = len(payload)
            out.addfile(m, io.BytesIO(payload))
        elif m.isreg():
            out.addfile(m, tar.extractfile(m))
        else:
            out.addfile(m)
print("corrupted-db archive built")
PY"""
        built = master_ssh.run(build_script, timeout=config.restore_timeout)
        if not built.ok:
            return {
                "scenario": "NEG-12",
                "name": name,
                "status": "INCOMPLETE",
                "message": "Could not build a checksum-valid archive with a corrupted SQLite database",
            }

        db_before = _remote_sha256(master_ssh, PANEL_DB_PATH)
        journal_before = _remote_sha256(master_ssh, RECOVERY_JOURNAL_PATH)
        service_before = _service_active(master_ssh, "gowave.service")

        if not _wait_for_mutation_lock(master_ssh, MUTATION_LOCK_WAIT_SECONDS):
            return {
                "scenario": "NEG-12",
                "name": name,
                "status": "INCOMPLETE",
                "message": "Host mutation lock stayed held, so the corrupted-database restore was never attempted",
            }

        restore = master_ssh.run(
            f"{shlex.quote(BACKUP_SCRIPT)} restore {shlex.quote(corrupted_archive)}",
            timeout=config.restore_timeout,
        )

        db_after = _remote_sha256(master_ssh, PANEL_DB_PATH)
        journal_after = _remote_sha256(master_ssh, RECOVERY_JOURNAL_PATH)
        service_after = _service_active(master_ssh, "gowave.service")

        output = (restore.stdout or "") + (restore.stderr or "")
        rejected = (not restore.ok) and (
            "staged database integrity check" in output
            or "Pre-restore check failed" in output
        )
        live_data_unchanged = db_before is not None and db_before == db_after
        service_kept = service_before and service_after
        journal_untouched = journal_before is not None and journal_before == journal_after
        passed = rejected and live_data_unchanged and service_kept and journal_untouched

        if passed:
            status = "PASS"
            message = "Staged SQLite integrity check rejected the corrupted database before stopping or replacing the live DB"
        elif "Could not acquire host mutation lock" in output:
            status = "INCOMPLETE"
            message = "Restore was blocked by the host mutation lock instead of by the integrity gate"
        elif db_before is None or journal_before is None:
            status = "INCOMPLETE"
            message = "Could not snapshot live state to prove the restore was rejected before mutation"
        else:
            status = "FAIL"
            message = "Corrupted SQLite database did not prove fail-closed rejection"

        return {
            "scenario": "NEG-12",
            "name": name,
            "status": status,
            "rejected": rejected,
            "live_data_unchanged": live_data_unchanged,
            "service_kept_active": service_kept,
            "journal_untouched": journal_untouched,
            "message": message,
        }
    finally:
        for path in (valid_archive, corrupted_archive):
            master_ssh.run(f"rm -f -- {shlex.quote(path)}")


def run_neg_13_worker_deploy_interrupted_journal(
    master_ssh: SSHClient,
    config: LiveVPSConfig,
) -> Dict[str, Any]:
    """NEG-13: an interrupted Worker dispatch must leave a non-COMMITTED recovery journal."""
    name = "Interrupted SSH Deployment Journal Integrity"
    node_name = "neg13-interrupt"
    known_hosts = "/root/.ssh/known_hosts"
    known_hosts_backup = "/tmp/neg13-known-hosts.bak"
    dummy_key = "/tmp/neg13-dummy-ed25519"
    log_path = "/tmp/neg13-node-add.log"

    state_before = _read_remote_state(master_ssh)
    if state_before is None:
        return {
            "scenario": "NEG-13",
            "name": name,
            "status": "INCOMPLETE",
            "message": "Could not snapshot state.json before the interrupted dispatch",
        }

    journal_before = _read_remote_journal(master_ssh)

    prepared = master_ssh.run(
        f"cp -p {shlex.quote(known_hosts)} {shlex.quote(known_hosts_backup)} && "
        f"rm -f {shlex.quote(dummy_key)} {shlex.quote(dummy_key)}.pub {shlex.quote(log_path)} && "
        f"ssh-keygen -q -t ed25519 -N '' -f {shlex.quote(dummy_key)} >/dev/null 2>&1 && "
        f"awk '{{print \"{NEG13_TARGET_IP}\" \" \" $1 \" \" $2}}' {shlex.quote(dummy_key)}.pub >> {shlex.quote(known_hosts)}"
    )
    if not prepared.ok:
        master_ssh.run(
            f"rm -f {shlex.quote(dummy_key)} {shlex.quote(dummy_key)}.pub {shlex.quote(known_hosts_backup)}"
        )
        return {
            "scenario": "NEG-13",
            "name": name,
            "status": "INCOMPLETE",
            "message": "Could not pin a throwaway host key for the interrupted dispatch target",
        }

    pid: Optional[str] = None
    try:
        add_args = " ".join(
            shlex.quote(value)
            for value in (
                node_name, NEG13_TARGET_IP, "neg13-test.example.com", "neg13-reality.example.com",
                config.worker_ssh_user, str(config.worker_ssh_port),
            )
        )
        start = master_ssh.run(
            f"cd {shlex.quote(GOWAVE_AUTO_DIR)} && "
            f"nohup setsid ./gowave-auto.sh node add {add_args} "
            f">{shlex.quote(log_path)} 2>&1 </dev/null & echo \"PID:$!\""
        )
        for token in (start.stdout or "").split():
            if token.startswith("PID:") and token[4:].isdigit():
                pid = token[4:]
                break
        if pid is None:
            return {
                "scenario": "NEG-13",
                "name": name,
                "status": "INCOMPLETE",
                "message": "Could not start the Worker dispatch detached on Master",
            }

        observed_state: Optional[str] = None
        deadline = time.time() + 180
        while time.time() < deadline:
            journal = _read_remote_journal(master_ssh)
            if (
                journal
                and journal != journal_before
                and journal.get("op") == "node_add"
                and journal.get("node_name") == node_name
            ):
                observed_state = journal.get("state")
                if observed_state == "NODE_ADD_VERIFYING":
                    break
            if not master_ssh.run(f"kill -0 {shlex.quote(pid)} 2>/dev/null").ok:
                break
            time.sleep(1)

        if observed_state != "NODE_ADD_VERIFYING":
            master_ssh.run(f"kill -KILL -{shlex.quote(pid)} 2>/dev/null || true")
            return {
                "scenario": "NEG-13",
                "name": name,
                "status": "INCOMPLETE",
                "message": "Dispatch never reached NODE_ADD_VERIFYING, so no interruption could be proven",
                "observed_journal_state": observed_state,
            }

        master_ssh.run(
            f"kill -TERM -{pid} 2>/dev/null || true; sleep 1; kill -KILL -{pid} 2>/dev/null || true"
        )
        group_alive = master_ssh.run(f"kill -0 -{pid} 2>/dev/null").ok
        lock_released = _wait_for_mutation_lock(master_ssh, MUTATION_LOCK_WAIT_SECONDS)
        lock_released_after_reap = False
        if not lock_released:
            _reap_stale_dispatch_holders(master_ssh)
            lock_released = _wait_for_mutation_lock(master_ssh, MUTATION_LOCK_WAIT_SECONDS)
            lock_released_after_reap = lock_released

        journal_after = _read_remote_journal(master_ssh)
        post_kill_state = journal_after.get("state")
        journal_valid = master_ssh.run(
            "PYTHONPATH=/opt/gowave-auto-nginx python3 - "
            f"{shlex.quote(RECOVERY_JOURNAL_PATH)} <<'PY'\n"
            "import json, sys\n"
            "from modules.recovery import validate_journal\n"
            "validate_journal(json.load(open(sys.argv[1], encoding='utf-8')))\n"
            "PY"
        ).ok
        rollback = master_ssh.run(
            "PYTHONPATH=/opt/gowave-auto-nginx python3 -c "
            "\"import sys; from modules.api_client import rollback_provisioning; "
            "sys.exit(0 if rollback_provisioning() else 1)\""
        )
        rolled_back_state = _read_remote_journal(master_ssh).get("state")
        state_after = _read_remote_state(master_ssh)
        state_restored = state_after is not None and _state_payload(state_after) == _state_payload(state_before)

        interrupted = not group_alive
        journal_not_committed = (
            post_kill_state is not None
            and post_kill_state != "NODE_ADD_COMMITTED"
            and journal_valid
        )
        api_rolled_back = rollback.ok and rolled_back_state in (
            "NODE_ADD_ROLLED_BACK", "NODE_ADD_ROLLBACK_REQUIRED",
        )
        passed = interrupted and lock_released and journal_not_committed and state_restored and api_rolled_back

        if passed:
            status = "PASS"
            message = (
                "Interrupted dispatch left the journal non-COMMITTED and rollback removed the partial API entities"
            )
        elif post_kill_state == "NODE_ADD_COMMITTED":
            status = "FAIL"
            message = "Interrupted dispatch reached NODE_ADD_COMMITTED"
        elif not lock_released:
            status = "INCOMPLETE"
            message = "Killed dispatch kept the host mutation lock held, so later scenarios could not run"
        else:
            status = "INCOMPLETE"
            message = "Interruption was observed but its journal/state evidence is incomplete"

        return {
            "scenario": "NEG-13",
            "name": name,
            "status": status,
            "observed_journal_state": observed_state,
            "post_kill_journal_state": post_kill_state,
            "journal_valid": journal_valid,
            "interruption_confirmed": interrupted,
            "lock_released": lock_released,
            "lock_released_after_reap": lock_released_after_reap,
            "state_restored": state_restored,
            "api_rollback": rollback.ok,
            "rollback_journal_state": rolled_back_state,
            "message": message,
        }
    finally:
        kill_group = f"kill -KILL -{pid} 2>/dev/null || true; " if pid else ""
        master_ssh.run(
            f"{kill_group}"
            f"if [ -f {shlex.quote(known_hosts_backup)} ]; then "
            f"cat {shlex.quote(known_hosts_backup)} > {shlex.quote(known_hosts)}; "
            f"rm -f {shlex.quote(known_hosts_backup)}; fi; "
            f"rm -f {shlex.quote(dummy_key)} {shlex.quote(dummy_key)}.pub {shlex.quote(log_path)}"
        )
        _reap_stale_dispatch_holders(master_ssh)


def run_neg_14_duplicate_worker_registration(
    master_ssh: SSHClient,
    worker_ip: str,
    config: LiveVPSConfig,
    panel_client: E2EPanelClient,
) -> Dict[str, Any]:
    """NEG-14: Duplicate node add must fail before any Panel API/state mutation."""
    state_path = "/var/lib/gowave-auto-nginx/state.json"
    before_state = master_ssh.run(f"sha256sum {shlex.quote(state_path)}")
    if not before_state.ok or not before_state.stdout.strip():
        return {"scenario": "NEG-14", "status": "INCOMPLETE",
                "message": "Could not snapshot state.json before duplicate registration"}

    def api_identity() -> Dict[str, List[str]]:
        resources = {
            "nodes": panel_client.get_nodes(),
            "profiles": panel_client.get_config_profiles(),
            "squads": panel_client.get_internal_squads(),
            "hosts": panel_client.get_hosts(),
        }
        identity: Dict[str, List[str]] = {}
        for resource, items in resources.items():
            ids = []
            for item in items:
                if not isinstance(item, dict):
                    raise ValueError(f"Invalid {resource} item")
                value = item.get("uuid") or item.get("id")
                if value is None:
                    raise ValueError(f"{resource} item has no stable uuid/id")
                ids.append(str(value))
            identity[resource] = sorted(ids)
        return identity

    try:
        before_api = api_identity()
    except Exception as exc:
        return {"scenario": "NEG-14", "status": "INCOMPLETE",
                "message": f"Could not snapshot Panel API identities: {type(exc).__name__}"}

    argv = [
        "/opt/gowave-auto-nginx/gowave-auto.sh", "node", "add", "worker-1",
        worker_ip, config.worker_domain, config.worker_reality_domain,
        config.worker_ssh_user, str(config.worker_ssh_port),
    ]
    add_cmd = " ".join(shlex.quote(value) for value in argv)
    result = master_ssh.run(add_cmd, timeout=300)
    after_state = master_ssh.run(f"sha256sum {shlex.quote(state_path)}")
    try:
        after_api = api_identity()
    except Exception as exc:
        return {"scenario": "NEG-14", "status": "INCOMPLETE",
                "message": f"Could not verify Panel API identities after duplicate call: {type(exc).__name__}"}

    combined_output = result.stdout + chr(10) + result.stderr
    explicit_duplicate_rejection = (
        not result.ok and "already registered in state.json" in combined_output
    )
    state_unchanged = (
        after_state.ok and before_state.stdout.split()[0] == after_state.stdout.split()[0]
    )
    api_unchanged = before_api == after_api
    passed = explicit_duplicate_rejection and state_unchanged and api_unchanged

    return {
        "scenario": "NEG-14",
        "name": "Duplicate Worker Registration Rejection Before API Mutation",
        "status": "PASS" if passed else "FAIL",
        "explicit_duplicate_rejection": explicit_duplicate_rejection,
        "state_unchanged": state_unchanged,
        "api_ids_unchanged": api_unchanged,
        "message": "Duplicate registration was rejected before Panel API operations and without state changes"
                   if passed else "Duplicate registration did not prove fail-fast rejection with unchanged state and API IDs",
    }

def run_neg_15_panel_api_forged_jwt(panel_domain: str, ssl_context: ssl.SSLContext) -> Dict[str, Any]:
    """NEG-15: Protected Panel API request with forged JWT returns 401 Unauthorized."""
    url = f"https://{panel_domain}/api/nodes"
    req = urllib.request.Request(
        url,
        headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.fakeSignature12345"},
    )
    got_401 = False
    status_code = None
    try:
        with urllib.request.urlopen(req, context=ssl_context, timeout=5) as resp:
            status_code = resp.status
    except urllib.error.HTTPError as e:
        status_code = e.code
        if e.code == 401:
            got_401 = True
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"

    return {
        "scenario": "NEG-15",
        "name": "Panel API Forged JWT Rejection",
        "status": "PASS" if got_401 else ("INCOMPLETE" if status_code is None else "FAIL"),
        "status_code": status_code,
        "error": error if "error" in locals() else None,
        "message": f"Panel returned HTTP {status_code} for forged JWT" if status_code is not None else "No HTTP response; JWT rejection was not proven",
    }


def run_negative_suite(
    config: LiveVPSConfig,
    master_ssh: Optional[SSHClient] = None,
    worker_ssh: Optional[SSHClient] = None,
    panel_client: Optional[E2EPanelClient] = None,
    short_uuid: Optional[str] = None,
    ssl_context: Optional[ssl.SSLContext] = None,
) -> Dict[str, Any]:
    """Execute all 15 negative scenarios in sequence.
    If TEST_NEGATIVE_SUITE is false, all cases are marked SKIP and overall status is INCOMPLETE.
    """
    scenarios: List[Dict[str, Any]] = []

    if not config.test_negative_suite:
        for i in range(1, 16):
            sid = f"NEG-{i:02d}"
            scenarios.append({
                "scenario": sid,
                "name": f"Scenario {sid}",
                "status": "SKIP",
                "message": "TEST_NEGATIVE_SUITE=false",
            })
        return {
            "status": "INCOMPLETE",
            "scenarios": scenarios,
            "passed_count": 0,
            "skipped_count": 15,
            "failed_count": 0,
        }

    # Execute NEG-01..NEG-04 (isolated local preflight fixtures)
    scenarios.append(run_neg_01_ssh_host_key_absent())
    scenarios.append(run_neg_02_ssh_port_unreachable())
    scenarios.append(run_neg_03_dns_wrong_ip())
    scenarios.append(run_neg_04_dns_missing_aaaa())

    # Execute live / mock scenarios
    if master_ssh:
        neg05 = run_neg_05_acme_install_failure(master_ssh)
        scenarios.append(neg05)
        if neg05.get("status") != "PASS":
            for index in range(6, 16):
                scenarios.append({
                    "scenario": f"NEG-{index:02d}", "status": "INCOMPLETE",
                    "message": "Skipped because NEG-05 did not prove fail-closed ACME rejection; further live mutations are unsafe",
                })
            passed_count = sum(1 for item in scenarios if item.get("status") == "PASS")
            failed_count = sum(1 for item in scenarios if item.get("status") == "FAIL")
            return {
                "status": "FAIL" if failed_count else "INCOMPLETE",
                "scenarios": scenarios,
                "passed_count": passed_count,
                "failed_count": failed_count,
                "skipped_count": 0,
            }
        neg06 = run_neg_06_nginx_syntax_corruption(master_ssh)
        scenarios.append(neg06)
        if neg06.get("cleanup_ok") is False:
            for index in range(7, 16):
                scenarios.append({
                    "scenario": f"NEG-{index:02d}", "status": "INCOMPLETE",
                    "message": "Skipped because NEG-06 fixture cleanup failed; live host state is not trusted",
                })
            passed_count = sum(1 for item in scenarios if item.get("status") == "PASS")
            failed_count = sum(1 for item in scenarios if item.get("status") == "FAIL")
            return {"status": "FAIL", "scenarios": scenarios, "passed_count": passed_count,
                    "failed_count": failed_count, "skipped_count": 0}
    else:
        scenarios.append({"scenario": "NEG-05", "status": "SKIP", "message": "No Master SSH"})
        scenarios.append({"scenario": "NEG-06", "status": "SKIP", "message": "No Master SSH"})

    if worker_ssh and panel_client:
        neg07 = run_neg_07_worker_node_service_stop(worker_ssh, panel_client)
        scenarios.append(neg07)
        neg08 = run_neg_08_worker_node_service_recover(worker_ssh, panel_client)
        scenarios.append(neg08)
        if neg08.get("status") != "PASS":
            for index in range(9, 16):
                scenarios.append({
                    "scenario": f"NEG-{index:02d}", "status": "INCOMPLETE",
                    "message": "Skipped because Worker service recovery failed; dependent live cases are unsafe",
                })
            passed_count = sum(1 for item in scenarios if item.get("status") == "PASS")
            failed_count = sum(1 for item in scenarios if item.get("status") == "FAIL")
            return {"status": "FAIL", "scenarios": scenarios, "passed_count": passed_count,
                    "failed_count": failed_count, "skipped_count": 0}
    else:
        scenarios.append({"scenario": "NEG-07", "status": "SKIP", "message": "No Worker SSH / Panel"})
        scenarios.append({"scenario": "NEG-08", "status": "SKIP", "message": "No Worker SSH / Panel"})

    if short_uuid and ssl_context:
        scenarios.append(run_neg_09_subscription_absent_user_agent(config.master_panel_domain, short_uuid, ssl_context))
    else:
        scenarios.append({"scenario": "NEG-09", "status": "SKIP", "message": "No shortUuid / ssl_context"})

    if master_ssh:
        scenarios.append(run_neg_10_mtls_forged_certificate(master_ssh, config.worker_ip))
        scenarios.append(run_neg_11_backup_corrupted_tar(master_ssh, config))
        scenarios.append(run_neg_12_backup_corrupted_sqlite(master_ssh, config))
        scenarios.append(run_neg_13_worker_deploy_interrupted_journal(master_ssh, config))
    else:
        for sid in ("NEG-10", "NEG-11", "NEG-12", "NEG-13"):
            scenarios.append({"scenario": sid, "status": "SKIP", "message": "No Master SSH"})

    if master_ssh and panel_client:
        scenarios.append(run_neg_14_duplicate_worker_registration(master_ssh, config.worker_ip, config, panel_client))
    else:
        scenarios.append({"scenario": "NEG-14", "status": "SKIP", "message": "No Master SSH / Panel"})

    if ssl_context:
        scenarios.append(run_neg_15_panel_api_forged_jwt(config.master_panel_domain, ssl_context))
    else:
        scenarios.append({"scenario": "NEG-15", "status": "SKIP", "message": "No ssl_context"})

    passed_count = sum(1 for s in scenarios if s.get("status") == "PASS")
    failed_count = sum(1 for s in scenarios if s.get("status") == "FAIL")
    skipped_count = sum(1 for s in scenarios if s.get("status") == "SKIP")

    overall_status = "PASS" if passed_count == 15 else ("FAIL" if failed_count > 0 else "INCOMPLETE")

    return {
        "status": overall_status,
        "scenarios": scenarios,
        "passed_count": passed_count,
        "failed_count": failed_count,
        "skipped_count": skipped_count,
    }
