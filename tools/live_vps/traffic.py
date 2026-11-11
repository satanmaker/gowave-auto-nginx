"""Data plane traffic testing with Xray and Mihomo clients.
Performs sequential endpoint verification, server-side ingress counters,
isolated local SOCKS5 proxy processes, and egress IP matching.
"""
from __future__ import annotations

import json
import os
import ipaddress
import re
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .ssh import SSHClient
from .config import LiveVPSConfig
from .tls import verify_staging_roots


def find_free_port() -> int:
    """Find an available local TCP port on loopback."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def parse_proc_net_dev_rx_packets(output: str) -> Optional[int]:
    """Sum RX packet counters from /proc/net/dev, excluding loopback/container links."""
    total = 0
    interfaces_seen = 0
    for line in output.splitlines()[2:]:
        if ":" not in line:
            continue
        interface, counters = line.split(":", 1)
        interface = interface.strip()
        if not interface or interface.startswith(("lo", "docker", "veth")):
            continue
        fields = counters.split()
        # /proc/net/dev columns begin with RX bytes, RX packets, RX errors, ...
        if len(fields) < 2 or not fields[1].isdigit():
            continue
        total += int(fields[1])
        interfaces_seen += 1
    return total if interfaces_seen else None


def get_server_rx_packets(ssh: SSHClient) -> int:
    """Capture aggregate RX packets from non-loopback/non-container interfaces."""
    r = ssh.run("cat /proc/net/dev")
    if r.ok:
        parsed = parse_proc_net_dev_rx_packets(r.stdout)
        if parsed is not None:
            return parsed
    # Fallback to ip -s link; the second field after RX bytes is RX packets.
    r2 = ssh.run("ip -s link show | awk '/RX: bytes/{getline; sum += $2} END {print sum}'")
    if r2.ok and r2.stdout.strip().isdigit():
        return int(r2.stdout.strip())
    return 0



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


def apply_xray_trust_anchors(outbound: Dict[str, Any], acme_mode: str) -> Dict[str, Any]:
    """Declare Staging trust anchors inside Xray tlsSettings.

    Xray builds its certificate pool from a hardcoded system path list and ignores
    SSL_CERT_FILE, so a Staging leaf chain cannot be verified via the environment.
    tlsSettings.certificates with usage=verify is Xray's supported trust-anchor input.
    """
    if acme_mode.lower() != "staging":
        return outbound
    if (outbound.get("streamSettings") or {}).get("security") != "tls":
        return outbound

    anchors = [str(pem_path) for pem_path, _meta in verify_staging_roots()]
    if not anchors:
        return outbound

    result = json.loads(json.dumps(outbound))
    tls_settings = result.setdefault("streamSettings", {}).setdefault("tlsSettings", {})
    existing = tls_settings.get("certificates") or []
    tls_settings["certificates"] = existing + [
        {"usage": "verify", "certificateFile": path} for path in anchors
    ]
    return result


def run_xray_endpoint_test(
    outbound: Dict[str, Any],
    ca_bundle_path: Path,
    expected_egress_ip: str,
    master_ssh: SSHClient,
    worker_ssh: SSHClient,
    is_worker_endpoint: bool,
    timeout: int = 15,
    acme_mode: str = "production",
) -> Dict[str, Any]:
    """Execute a single tunnel test through Xray client for one active outbound."""
    socks_port = find_free_port()
    tag = outbound.get("tag", "proxy")
    full_outbound = apply_xray_trust_anchors(outbound, acme_mode)

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
        "outbounds": [full_outbound, {"protocol": "freedom", "tag": "direct"}],
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

        # Record ingress baselines
        m_base = get_server_rx_packets(master_ssh)
        w_base = get_server_rx_packets(worker_ssh)

        # Execute tunnel curl
        curl_cmd = [
            "curl",
            "-fsS",
            "--connect-timeout", "8",
            "--max-time", str(timeout),
            "-x", f"socks5h://127.0.0.1:{socks_port}",
            "https://api.ipify.org",
        ]
        curl_res = subprocess.run(curl_cmd, capture_output=True, text=True)

        m_post = get_server_rx_packets(master_ssh)
        w_post = get_server_rx_packets(worker_ssh)

        m_delta = m_post - m_base
        w_delta = w_post - w_base

        if curl_res.returncode != 0:
            return {
                "status": "FAIL",
                "tag": tag,
                "error": f"Tunnel request failed: {curl_res.stderr.strip()}",
            }

        observed_egress = curl_res.stdout.strip()
        egress_matches = observed_egress == expected_egress_ip

        # Server evidence verification
        if is_worker_endpoint:
            target_ingress_ok = w_delta > 0
            # Worker handles the data traffic; allow normal SSH/API background traffic on Master
            offload_ok = m_delta < w_delta
        else:
            target_ingress_ok = m_delta > 0
            offload_ok = True

        passed = egress_matches and target_ingress_ok and offload_ok
        status = "PASS" if passed else "FAIL"
        return {
            "status": status,
            "tag": tag,
            "observed_egress": observed_egress,
            "expected_egress": expected_egress_ip,
            "egress_matches": egress_matches,
            "target_ingress_ok": target_ingress_ok,
            "offload_ok": offload_ok,
            "m_delta": m_delta,
            "w_delta": w_delta,
            "evidence_confidence": "aggregate interface rx_packets; background traffic is not excluded",
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
    core_binary: str = "mihomo",
) -> Dict[str, Any]:
    """Execute Mihomo data plane verification across all subscription proxies.

    core_binary allows running the same suite with a mihomo-compatible fork
    (for example Prizrak-Core) without altering the subscription under test.
    """
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

    # Mihomo only keeps the X25519MLKEM768 key share while the proxy carries
    # reality-opts.support-x25519mlkem768; without it REALITY authentication
    # fails. This is a client-side requirement, not a server-side one.
    reality_without_hybrid = [
        proxy.get("name")
        for proxy in proxies
        if isinstance(proxy, dict)
        and isinstance(proxy.get("reality-opts"), dict)
        and proxy["reality-opts"].get("support-x25519mlkem768") is not True
    ]
    if reality_without_hybrid:
        return {
            "status": "FAIL",
            "error": (
                "REALITY proxies are missing reality-opts.support-x25519mlkem768; "
                "Xray >= 26.9.9 server cores reject non-hybrid ClientHellos"
            ),
            "proxies": reality_without_hybrid,
            "results": [],
        }

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
         and (group.get("name") in ("GLOBAL", "→ GoWave") or group.get("type") == "select")),
        None,
    )
    if global_group is None:
        return {
            "status": "INCOMPLETE",
            "error": "Subscription has no existing select group; refusing to rewrite proxy-groups/rules",
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
    mihomo_log = None
    mihomo_log_path = Path(td.name) / "mihomo.log"
    case_results: List[Dict[str, Any]] = []

    def mihomo_log_tail() -> str:
        try:
            return mihomo_log_path.read_text(encoding="utf-8", errors="replace")[-4000:].strip()
        except OSError:
            return ""

    try:
        mihomo_log = mihomo_log_path.open("w", encoding="utf-8")
        proc = subprocess.Popen(
            [core_binary, "-d", td.name, "-f", str(tmp_config_path)],
            stdout=mihomo_log,
            stderr=subprocess.STDOUT,
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
            return {
                "status": "FAIL",
                "error": "Mihomo client failed to start",
                "mihomo_log_tail": mihomo_log_tail(),
            }

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
            group_name = urllib.parse.quote(global_group.get("name", "GLOBAL"))
            try:
                # If running in mode: global and group is not GLOBAL, route GLOBAL to the group first
                if global_group.get("name") != "GLOBAL":
                    sel_global = urllib.request.Request(
                        f"http://127.0.0.1:{ctrl_port}/proxies/GLOBAL",
                        data=json.dumps({"name": global_group.get("name")}).encode("utf-8"),
                        headers={"Content-Type": "application/json"},
                        method="PUT",
                    )
                    with urllib.request.urlopen(sel_global, timeout=3):
                        pass

                sel_req = urllib.request.Request(
                    f"http://127.0.0.1:{ctrl_port}/proxies/{group_name}",
                    data=json.dumps({"name": p_name}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="PUT",
                )
                with urllib.request.urlopen(sel_req, timeout=3):
                    pass
            except Exception as e:
                case_results.append({
                    "status": "FAIL",
                    "proxy": p_name,
                    "error": f"Failed selecting proxy: {e}",
                    "mihomo_log_tail": mihomo_log_tail(),
                })
                continue

            # Ingress baselines
            m_base = get_server_rx_packets(master_ssh)
            w_base = get_server_rx_packets(worker_ssh)

            # Egress curl via Mihomo mixed-port
            curl_cmd = [
                "curl",
                "-fsS",
                "--connect-timeout", "5",
                "--max-time", "10",
                "-x", f"http://127.0.0.1:{mixed_port}",
                "https://api.ipify.org",
            ]
            curl_res = subprocess.run(curl_cmd, capture_output=True, text=True)

            m_post = get_server_rx_packets(master_ssh)
            w_post = get_server_rx_packets(worker_ssh)

            m_delta = m_post - m_base
            w_delta = w_post - w_base

            if curl_res.returncode != 0:
                case_results.append({
                    "status": "FAIL",
                    "proxy": p_name,
                    "error": f"Mihomo tunnel failed: {curl_res.stderr.strip()}",
                    "mihomo_log_tail": mihomo_log_tail(),
                })
                continue

            observed_egress = curl_res.stdout.strip()
            egress_matches = observed_egress == expected_egress

            passed = egress_matches and (w_delta > 0 if is_worker else m_delta > 0)
            case_status = "PASS" if passed else "FAIL"
            case_results.append({
                "status": case_status,
                "proxy": p_name,
                "observed_egress": observed_egress,
                "expected_egress": expected_egress,
                "egress_matches": egress_matches,
                "m_delta": m_delta,
                "w_delta": w_delta,
                "evidence_confidence": "aggregate interface rx_packets; background traffic is not excluded",
            })

    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        if mihomo_log:
            mihomo_log.close()
        td.cleanup()

    if any(case.get("status") == "FAIL" for case in case_results):
        suite_status = "FAIL"
    elif not case_results or any(case.get("status") in ("INCOMPLETE", "SKIP") for case in case_results):
        suite_status = "INCOMPLETE"
    else:
        suite_status = "PASS"
    return {
        "status": suite_status,
        "client": Path(core_binary).name,
        "results": case_results,
    }


def evaluate_traffic_suite_status(
    test_traffic_verification: bool,
    xray_results: List[Dict[str, Any]],
    mihomo_results: Optional[Dict[str, Any]] = None,
    expected_case_count: Optional[int] = None,
    mihomo_alt_results: Optional[Dict[str, Any]] = None,
) -> str:
    """Evaluate overall status for traffic suite.
    Enforces that disabling traffic verification or Mihomo traffic forces INCOMPLETE, not PASS.
    Enforces expected active case count (8 per client without Vision, 10 per client with Vision).
    """
    if not test_traffic_verification:
        return "INCOMPLETE"

    if mihomo_results and mihomo_results.get("status") == "INCOMPLETE":
        return "INCOMPLETE"

    # Empty or missing results are missing evidence, not a successful suite.
    if not xray_results or mihomo_results is None:
        return "INCOMPLETE"

    if expected_case_count is not None:
        if len(xray_results) != expected_case_count:
            return "INCOMPLETE"
        mihomo_cases = mihomo_results.get("results", []) if isinstance(mihomo_results, dict) else []
        if len(mihomo_cases) != expected_case_count:
            return "INCOMPLETE"

    for result in xray_results:
        if result.get("status") == "INCOMPLETE":
            return "INCOMPLETE"
        if result.get("status") != "PASS":
            return "FAIL"

    if mihomo_results.get("status") == "INCOMPLETE":
        return "INCOMPLETE"
    if mihomo_results.get("status") != "PASS":
        return "FAIL"

    # Optional second mihomo-compatible client is gated only when it actually ran.
    if mihomo_alt_results and not mihomo_alt_results.get("skipped"):
        alt_cases = mihomo_alt_results.get("results", [])
        if expected_case_count is not None and len(alt_cases) != expected_case_count:
            return "INCOMPLETE"
        if mihomo_alt_results.get("status") == "INCOMPLETE":
            return "INCOMPLETE"
        if mihomo_alt_results.get("status") != "PASS":
            return "FAIL"

    return "PASS"
