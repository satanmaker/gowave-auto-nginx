"""Data plane traffic testing with Xray and Mihomo clients.
Performs sequential endpoint verification, server-side ingress counters,
isolated local SOCKS5 proxy processes, and egress IP matching.
"""
from __future__ import annotations

import json
import os
import ipaddress
import re
import shlex
import socket
import subprocess
import tempfile
import time
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .ssh import SSHClient
from .config import LiveVPSConfig


def find_free_port() -> int:
    """Find an available local TCP port on loopback."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def get_control_egress_ip() -> Optional[str]:
    """Return the public IPv4 address visible to the target VPS."""
    try:
        result = subprocess.run(
            ["curl", "--noproxy", "*", "-4fsS", "--connect-timeout", "5",
             "--max-time", "10", "https://api.ipify.org"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        address = ipaddress.ip_address(result.stdout.strip())
        return str(address) if result.returncode == 0 and address.version == 4 else None
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def start_ingress_capture(ssh: SSHClient, source_ip: str, target_port: int) -> Optional[Dict[str, str]]:
    """Start header-only capture of inbound TCP packets from this test runner."""
    try:
        address = ipaddress.ip_address(source_ip)
    except ValueError:
        return None
    if address.version != 4 or not isinstance(target_port, int) or not 1 <= target_port <= 65535:
        return None
    if target_port == ssh.port:
        return None
    token = uuid.uuid4().hex
    base = "/run/gowave-e2e-ingress-" + token
    log_path, pid_path = base + ".log", base + ".pid"
    capture_filter = (
        "src host " + str(address) + " and tcp and dst port " + str(target_port)
        + " and not dst port " + str(ssh.port)
    )
    command = (
        "set -eu; umask 077; command -v tcpdump >/dev/null 2>&1 || exit 127; command -v timeout >/dev/null 2>&1 || exit 127; "
        "nohup timeout --signal=INT 45s tcpdump -nn -i any -Q in -l " + shlex.quote(capture_filter) +
        " > " + shlex.quote(log_path) + " 2>&1 </dev/null & "
        "echo $! > " + shlex.quote(pid_path) + "; "
        "for i in $(seq 1 30); do "
        "grep -q 'listening on' " + shlex.quote(log_path) + " 2>/dev/null && exit 0; "
        "kill -0 \"$(cat " + shlex.quote(pid_path) + ")\" 2>/dev/null || "
        "{ cat " + shlex.quote(log_path) + " 2>/dev/null || true; exit 1; }; "
        "sleep 0.1; done; cat " + shlex.quote(log_path) + " 2>/dev/null || true; exit 1"
    )
    result = ssh.run(command, timeout=10)
    if not result.ok:
        ssh.run(
            "if [ -f " + shlex.quote(pid_path) + " ]; then kill -INT \"$(cat " +
            shlex.quote(pid_path) + ")\" 2>/dev/null || true; fi; rm -f " +
            shlex.quote(log_path) + " " + shlex.quote(pid_path),
            timeout=5,
        )
        return None
    return {"log_path": log_path, "pid_path": pid_path}


def stop_ingress_capture(ssh: SSHClient, capture: Dict[str, str]) -> Optional[int]:
    """Stop capture and return tcpdump's summary count; absent summary is not evidence."""
    log_path, pid_path = shlex.quote(capture["log_path"]), shlex.quote(capture["pid_path"])
    command = (
        "set -eu; if [ -f " + pid_path + " ]; then kill -INT \"$(cat " + pid_path +
        ")\" 2>/dev/null || true; fi; "
        "for i in $(seq 1 50); do "
        "grep -q 'packets captured' " + log_path + " 2>/dev/null && break; "
        "sleep 0.1; done; "
        "cat " + log_path + " 2>/dev/null || true; rm -f " + log_path + " " + pid_path
    )
    result = ssh.run(command, timeout=10)
    if not result.ok:
        return None
    match = re.search(r"^(\d+) packets captured$", result.stdout, re.MULTILINE)
    return int(match.group(1)) if match else None


def capture_pair_ingress(
    master_ssh: SSHClient, worker_ssh: SSHClient, source_ip: str, target_port: int,
) -> Optional[Tuple[Dict[str, str], Dict[str, str]]]:
    """Start both target captures before one request to the exact proxy service port."""
    master_capture = start_ingress_capture(master_ssh, source_ip, target_port)
    if master_capture is None:
        return None
    worker_capture = start_ingress_capture(worker_ssh, source_ip, target_port)
    if worker_capture is None:
        stop_ingress_capture(master_ssh, master_capture)
        return None
    return master_capture, worker_capture


def finish_pair_ingress(
    master_ssh: SSHClient, worker_ssh: SSHClient,
    captures: Tuple[Dict[str, str], Dict[str, str]], is_worker_endpoint: bool,
) -> Optional[Dict[str, Any]]:
    master_packets = stop_ingress_capture(master_ssh, captures[0])
    worker_packets = stop_ingress_capture(worker_ssh, captures[1])
    if master_packets is None or worker_packets is None:
        return None
    target_packets = worker_packets if is_worker_endpoint else master_packets
    offload_packets = master_packets if is_worker_endpoint else worker_packets
    return {
        "master_packets": master_packets,
        "worker_packets": worker_packets,
        "target_packets": target_packets,
        "offload_packets": offload_packets,
        "target_ingress_ok": target_packets > 0,
        "offload_ok": offload_packets == 0,
        "evidence_method": "tcpdump inbound TCP filtered by control-machine public IPv4",
    }


def get_remote_egress_ip(ssh: SSHClient) -> Optional[str]:
    """Discover the VPS's actual IPv4 egress address (not its inbound target IP)."""
    result = ssh.run(
        "curl --noproxy '*' -4fsS --connect-timeout 5 --max-time 10 https://api.ipify.org "
        "|| curl --noproxy '*' -4fsS --connect-timeout 5 --max-time 10 https://ifconfig.me",
        timeout=15,
    )
    if not result.ok:
        return None
    value = result.stdout.strip()
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return None
    return value if parsed.version == 4 else None


def classify_xray_outbound(outbound: Dict[str, Any], config: LiveVPSConfig) -> Optional[bool]:
    """Return True for Worker, False for Master; unknown endpoints fail closed."""
    settings = outbound.get("settings") or {}
    servers = settings.get("vnext") or settings.get("servers") or []
    host = servers[0].get("address") if servers and isinstance(servers[0], dict) else None
    return classify_server_host(host, config)


def classify_server_host(host: Optional[str], config: LiveVPSConfig) -> Optional[bool]:
    if not isinstance(host, str) or not host:
        return None
    master_hosts = {
        config.master_ip, config.master_panel_domain, config.master_reality_domain,
        config.master_vision_domain, config.master_ipv6,
    }
    worker_hosts = {
        config.worker_ip, config.worker_domain, config.worker_reality_domain,
        config.worker_vision_domain, config.worker_ipv6,
    }
    if host in worker_hosts:
        return True
    if host in master_hosts:
        return False
    return None



def get_xray_server_port(outbound: Dict[str, Any]) -> Optional[int]:
    """Return the configured destination port for the first Xray server."""
    settings = outbound.get("settings") or {}
    if not isinstance(settings, dict):
        return None
    for key in ("vnext", "servers"):
        servers = settings.get(key) or []
        if isinstance(servers, list) and servers and isinstance(servers[0], dict):
            try:
                port = int(servers[0].get("port"))
            except (TypeError, ValueError):
                return None
            return port if 1 <= port <= 65535 else None
    return None


def run_xray_endpoint_test(
    outbound: Dict[str, Any],
    ca_bundle_path: Path,
    expected_egress_ip: str,
    master_ssh: SSHClient,
    worker_ssh: SSHClient,
    is_worker_endpoint: bool,
    timeout: int = 15,
    source_ip: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute a single tunnel test through Xray client for one active outbound."""
    socks_port = find_free_port()
    tag = outbound.get("tag", "proxy")

    full_config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "port": socks_port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            }
        ],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
    }

    # Write temporary mode-0600 config
    fd, tmp_config_path = tempfile.mkstemp(prefix="gowave-e2e-xray-", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(full_config, f)
    os.chmod(tmp_config_path, 0o600)

    env = os.environ.copy()
    env["SSL_CERT_FILE"] = str(ca_bundle_path)

    proc: Optional[subprocess.Popen] = None
    try:
        proc = subprocess.Popen(
            ["xray", "run", "-config", tmp_config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
        )

        # Wait for socks_port ready
        ready = False
        deadline = time.time() + 3.0
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", socks_port), timeout=0.2):
                    ready = True
                    break
            except Exception:
                time.sleep(0.05)

        if not ready:
            return {"status": "FAIL", "tag": tag, "error": "Xray client failed to bind SOCKS port"}

        if not source_ip:
            return {"status": "INCOMPLETE", "tag": tag,
                    "error": "Control-machine public IPv4 unavailable for per-case ingress capture"}
        server_port = get_xray_server_port(outbound) or 0
        captures = capture_pair_ingress(master_ssh, worker_ssh, source_ip, server_port)
        if captures is None:
            return {"status": "INCOMPLETE", "tag": tag,
                    "error": "Cannot start per-case tcpdump capture on both VPS"}

        # Execute exactly one request while both VPS captures are active.
        curl_cmd = [
            "curl",
            "-fsS",
            "--connect-timeout", "5",
            "--max-time", str(timeout),
            "-x", f"socks5h://127.0.0.1:{socks_port}",
            "--cacert", str(ca_bundle_path),
            "https://api.ipify.org",
        ]
        try:
            curl_res = subprocess.run(curl_cmd, capture_output=True, text=True)
        finally:
            ingress_evidence = finish_pair_ingress(
                master_ssh, worker_ssh, captures, is_worker_endpoint,
            )

        if curl_res.returncode != 0:
            return {
                "status": "FAIL",
                "tag": tag,
                "error": f"Tunnel request failed: {curl_res.stderr.strip()}",
            }

        observed_egress = curl_res.stdout.strip()
        egress_matches = observed_egress == expected_egress_ip

        if ingress_evidence is None:
            return {"status": "INCOMPLETE", "tag": tag,
                    "error": "Per-case tcpdump capture did not return packet summaries"}
        passed = (
            egress_matches
            and ingress_evidence["target_ingress_ok"]
            and ingress_evidence["offload_ok"]
        )
        return {
            "status": "PASS" if passed else "FAIL",
            "tag": tag,
            "observed_egress": observed_egress,
            "expected_egress": expected_egress_ip,
            "egress_matches": egress_matches,
            **ingress_evidence,
        }
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        if os.path.exists(tmp_config_path):
            try:
                os.remove(tmp_config_path)
            except Exception:
                pass


def run_mihomo_traffic_suite(
    subscription_yaml_str: str,
    ca_bundle_path: Path,
    config: LiveVPSConfig,
    master_ssh: SSHClient,
    worker_ssh: SSHClient,
    source_ip: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute Mihomo data plane verification across all subscription proxies."""
    if not config.test_mihomo_traffic:
        return {
            "status": "INCOMPLETE",
            "skipped": True,
            "reason": "TEST_MIHOMO_TRAFFIC=false",
            "results": [],
        }

    try:
        parsed_yaml = yaml.safe_load(subscription_yaml_str)
    except Exception as e:
        return {"status": "FAIL", "error": f"Malformed subscription YAML: {e}"}

    proxies = parsed_yaml.get("proxies", [])
    if not proxies:
        return {"status": "FAIL", "error": "No proxies in subscription YAML"}

    mixed_port = find_free_port()
    ctrl_port = find_free_port()

    # Re-bind all listeners to loopback only and assign free ports
    parsed_yaml["mixed-port"] = mixed_port
    parsed_yaml["allow-lan"] = False
    parsed_yaml["bind-address"] = "127.0.0.1"
    parsed_yaml["external-controller"] = f"127.0.0.1:{ctrl_port}"
    parsed_yaml["secret"] = ""

    # Preserve subscription proxy-groups and rules. Replacing them can break
    # rules that reference existing groups and no longer tests the real profile.
    groups = parsed_yaml.get("proxy-groups") or []
    global_group = next(
        (group for group in groups if isinstance(group, dict)
         and group.get("name") == "GLOBAL" and group.get("type") == "select"),
        None,
    )
    if global_group is None:
        return {
            "status": "INCOMPLETE",
            "error": "Subscription has no existing GLOBAL select group; refusing to rewrite proxy-groups/rules",
            "results": [],
        }
    group_members = global_group.get("proxies")
    if not isinstance(group_members, list):
        return {"status": "FAIL", "error": "GLOBAL proxy group has an invalid proxies list", "results": []}
    for proxy in proxies:
        proxy_name = proxy.get("name") if isinstance(proxy, dict) else None
        if not proxy_name:
            return {"status": "FAIL", "error": "Subscription contains a proxy without a name", "results": []}
        if proxy_name not in group_members:
            group_members.append(proxy_name)

    # Rebind enabled listeners to fresh loopback ports to avoid collisions.
    for listener_key in ("socks-port", "redir-port", "tproxy-port"):
        if parsed_yaml.get(listener_key):
            parsed_yaml[listener_key] = find_free_port()

    td = tempfile.TemporaryDirectory(prefix="gowave-e2e-mihomo-")
    tmp_config_path = Path(td.name) / "config.yaml"
    tmp_config_path.write_text(yaml.dump(parsed_yaml), encoding="utf-8")
    tmp_config_path.chmod(0o600)

    env = os.environ.copy()
    env["SSL_CERT_FILE"] = str(ca_bundle_path)

    proc: Optional[subprocess.Popen] = None
    case_results: List[Dict[str, Any]] = []

    try:
        proc = subprocess.Popen(
            ["mihomo", "-d", td.name, "-f", str(tmp_config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
        )

        # Wait for controller and mixed_port
        ready = False
        deadline = time.time() + 4.0
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", mixed_port), timeout=0.2):
                    ready = True
                    break
            except Exception:
                time.sleep(0.05)

        if not ready:
            return {"status": "FAIL", "error": "Mihomo client failed to start"}

        for p in proxies:
            p_name = p.get("name", "proxy")
            is_worker = classify_server_host(p.get("server"), config)
            if is_worker is None:
                case_results.append({
                    "status": "INCOMPLETE", "proxy": p_name,
                    "error": "Cannot identify Master/Worker endpoint from subscription server address",
                })
                continue
            expected_egress = (
                config.expected_worker_egress_ip or get_remote_egress_ip(worker_ssh)
                if is_worker else
                config.expected_master_egress_ip or get_remote_egress_ip(master_ssh)
            )
            if not expected_egress:
                case_results.append({
                    "status": "INCOMPLETE", "proxy": p_name,
                    "error": "Could not determine actual target VPS egress IP",
                })
                continue

            # Select proxy in Mihomo controller
            try:
                sel_req = urllib.request.Request(
                    f"http://127.0.0.1:{ctrl_port}/proxies/GLOBAL",
                    data=json.dumps({"name": p_name}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="PUT",
                )
                with urllib.request.urlopen(sel_req, timeout=3):
                    pass
            except Exception as e:
                case_results.append({"status": "FAIL", "proxy": p_name, "error": f"Failed selecting proxy: {e}"})
                continue

            if not source_ip:
                case_results.append({
                    "status": "INCOMPLETE", "proxy": p_name,
                    "error": "Control-machine public IPv4 unavailable for per-case ingress capture",
                })
                continue
            try:
                target_port = int(p.get("port"))
            except (TypeError, ValueError):
                target_port = 0
            captures = capture_pair_ingress(master_ssh, worker_ssh, source_ip, target_port)
            if captures is None:
                case_results.append({
                    "status": "INCOMPLETE", "proxy": p_name,
                    "error": "Cannot start per-case tcpdump capture on both VPS",
                })
                continue

            # Execute exactly one request while both VPS captures are active.
            curl_cmd = [
                "curl",
                "-fsS",
                "--connect-timeout", "5",
                "--max-time", "10",
                "-x", f"http://127.0.0.1:{mixed_port}",
                "--cacert", str(ca_bundle_path),
                "https://api.ipify.org",
            ]
            try:
                curl_res = subprocess.run(curl_cmd, capture_output=True, text=True)
            finally:
                ingress_evidence = finish_pair_ingress(
                    master_ssh, worker_ssh, captures, is_worker,
                )

            if curl_res.returncode != 0:
                case_results.append({
                    "status": "FAIL",
                    "proxy": p_name,
                    "error": f"Mihomo tunnel failed: {curl_res.stderr.strip()}",
                })
                continue

            observed_egress = curl_res.stdout.strip()
            egress_matches = observed_egress == expected_egress

            if ingress_evidence is None:
                case_results.append({
                    "status": "INCOMPLETE", "proxy": p_name,
                    "error": "Per-case tcpdump capture did not return packet summaries",
                })
                continue
            passed = (
                egress_matches
                and ingress_evidence["target_ingress_ok"]
                and ingress_evidence["offload_ok"]
            )
            case_results.append({
                "status": "PASS" if passed else "FAIL",
                "proxy": p_name,
                "observed_egress": observed_egress,
                "expected_egress": expected_egress,
                "egress_matches": egress_matches,
                **ingress_evidence,
            })

    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        td.cleanup()

    if any(case.get("status") == "FAIL" for case in case_results):
        suite_status = "FAIL"
    elif not case_results or any(case.get("status") in ("INCOMPLETE", "SKIP") for case in case_results):
        suite_status = "INCOMPLETE"
    else:
        suite_status = "PASS"
    return {
        "status": suite_status,
        "results": case_results,
    }


def evaluate_traffic_suite_status(
    test_traffic_verification: bool,
    xray_results: List[Dict[str, Any]],
    mihomo_results: Optional[Dict[str, Any]] = None,
    expected_case_count: Optional[int] = None,
) -> str:
    """Evaluate overall status for traffic suite.
    Enforces that disabling traffic verification or Mihomo traffic forces INCOMPLETE, not PASS.
    Enforces expected active case count (8 per client without Vision, 10 per client with Vision).
    """
    if not test_traffic_verification:
        return "INCOMPLETE"

    # A concrete failing case takes precedence over missing evidence in another case.
    mihomo_precheck_cases = mihomo_results.get("results", []) if isinstance(mihomo_results, dict) else []
    if (
        any(case.get("status") == "FAIL" for case in (xray_results or []))
        or (isinstance(mihomo_results, dict) and mihomo_results.get("status") == "FAIL")
        or (
            isinstance(mihomo_precheck_cases, list)
            and any(case.get("status") == "FAIL" for case in mihomo_precheck_cases)
        )
    ):
        return "FAIL"

    # Empty, missing, or explicitly incomplete results are not successful evidence.
    if not xray_results or mihomo_results is None:
        return "INCOMPLETE"
    if isinstance(mihomo_results, dict) and mihomo_results.get("status") == "INCOMPLETE":
        return "INCOMPLETE"

    if expected_case_count is not None:
        if len(xray_results) != expected_case_count:
            return "INCOMPLETE"
        mihomo_cases = mihomo_results.get("results", []) if isinstance(mihomo_results, dict) else []
        if len(mihomo_cases) != expected_case_count:
            return "INCOMPLETE"

    def case_evidence_status(result: Dict[str, Any]) -> str:
        if result.get("status") == "INCOMPLETE":
            return "INCOMPLETE"
        if result.get("status") != "PASS":
            return "FAIL"
        target_packets = result.get("target_packets")
        offload_packets = result.get("offload_packets")
        if not isinstance(target_packets, int) or target_packets <= 0:
            return "INCOMPLETE"
        if not isinstance(offload_packets, int):
            return "INCOMPLETE"
        if offload_packets != 0:
            return "FAIL"
        evidence_method = result.get("evidence_method")
        if not isinstance(evidence_method, str) or not evidence_method.startswith("tcpdump "):
            return "INCOMPLETE"
        return "PASS"

    for result in xray_results:
        evidence_status = case_evidence_status(result)
        if evidence_status != "PASS":
            return evidence_status

    if mihomo_results.get("status") == "INCOMPLETE":
        return "INCOMPLETE"
    if mihomo_results.get("status") != "PASS":
        return "FAIL"
    mihomo_cases = mihomo_results.get("results", [])
    if not isinstance(mihomo_cases, list) or not mihomo_cases:
        return "INCOMPLETE"
    for result in mihomo_cases:
        evidence_status = case_evidence_status(result)
        if evidence_status != "PASS":
            return evidence_status

    return "PASS"
