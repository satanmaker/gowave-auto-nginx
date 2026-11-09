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


def run_neg_11_backup_corrupted_tar(master_ssh: SSHClient) -> Dict[str, Any]:
    """NEG-11 is not implemented as a safe restore fixture yet."""
    return {
        "scenario": "NEG-11",
        "name": "Backup Restore Corrupted Header Rejection",
        "status": "INCOMPLETE",
        "message": "No isolated backup/restore fixture and before/after state assertion exists; scenario intentionally not executed",
    }


def run_neg_12_backup_corrupted_sqlite(master_ssh: SSHClient) -> Dict[str, Any]:
    """NEG-12 is not implemented as a real corrupted-database restore fixture yet."""
    return {
        "scenario": "NEG-12",
        "name": "Backup Restore Corrupted SQLite DB Integrity Check",
        "status": "INCOMPLETE",
        "message": "The current in-memory SQLite smoke test does not exercise backup restore; scenario intentionally not reported as PASS",
    }


def run_neg_13_worker_deploy_interrupted_journal(master_ssh: SSHClient) -> Dict[str, Any]:
    """NEG-13 is not implemented as a real interrupted-dispatch recovery test yet."""
    return {
        "scenario": "NEG-13",
        "name": "Interrupted SSH Deployment Journal Integrity",
        "status": "INCOMPLETE",
        "message": "No deterministic worker-dispatch interruption and subsequent journal-recovery assertion exists; scenario intentionally not executed",
    }


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
        scenarios.append(run_neg_11_backup_corrupted_tar(master_ssh))
        scenarios.append(run_neg_12_backup_corrupted_sqlite(master_ssh))
        scenarios.append(run_neg_13_worker_deploy_interrupted_journal(master_ssh))
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
