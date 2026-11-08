"""Data plane traffic testing with Xray and Mihomo clients.
Performs sequential endpoint verification, server-side ingress counters,
isolated local SOCKS5 proxy processes, and egress IP matching.
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import tempfile
import time
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


def get_server_rx_packets(ssh: SSHClient) -> int:
    """Capture incoming packet counter on the default public network interface."""
    r = ssh.run(
        "cat /proc/net/dev | awk -F'[: ]+' '$1 !~ /(lo|docker|veth)/ && $2 ~ /^[0-9]+$/ {sum += $3} END {print sum}'"
    )
    if r.ok and r.stdout.strip().isdigit():
        return int(r.stdout.strip())
    # Fallback to ip -s link
    r2 = ssh.run("ip -s link show | awk '/RX: bytes/{getline; sum += $2} END {print sum}'")
    if r2.ok and r2.stdout.strip().isdigit():
        return int(r2.stdout.strip())
    return 0


def run_xray_endpoint_test(
    outbound: Dict[str, Any],
    ca_bundle_path: Path,
    expected_egress_ip: str,
    master_ssh: SSHClient,
    worker_ssh: SSHClient,
    is_worker_endpoint: bool,
    timeout: int = 15,
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

        # Record ingress baselines
        m_base = get_server_rx_packets(master_ssh)
        w_base = get_server_rx_packets(worker_ssh)

        # Execute tunnel curl
        curl_cmd = [
            "curl",
            "-fsS",
            "--connect-timeout", "5",
            "--max-time", str(timeout),
            "-x", f"socks5h://127.0.0.1:{socks_port}",
            "--cacert", str(ca_bundle_path),
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
            offload_ok = m_delta <= 5  # Master should not handle data traffic
        else:
            target_ingress_ok = m_delta > 0
            offload_ok = True

        passed = egress_matches and target_ingress_ok and offload_ok
        return {
            "status": "PASS" if passed else "FAIL",
            "tag": tag,
            "observed_egress": observed_egress,
            "expected_egress": expected_egress_ip,
            "egress_matches": egress_matches,
            "target_ingress_ok": target_ingress_ok,
            "offload_ok": offload_ok,
            "m_delta": m_delta,
            "w_delta": w_delta,
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

    # Ensure proxy groups include GLOBAL selector
    parsed_yaml["proxy-groups"] = [
        {"name": "GLOBAL", "type": "select", "proxies": [p["name"] for p in proxies]}
    ]

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
            is_worker = "worker" in p_name.lower()
            expected_egress = config.expected_worker_egress_ip or config.worker_ip if is_worker else config.expected_master_egress_ip or config.master_ip

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
                "--cacert", str(ca_bundle_path),
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
                })
                continue

            observed_egress = curl_res.stdout.strip()
            egress_matches = observed_egress == expected_egress

            passed = egress_matches and (w_delta > 0 if is_worker else m_delta > 0)
            case_results.append({
                "status": "PASS" if passed else "FAIL",
                "proxy": p_name,
                "observed_egress": observed_egress,
                "expected_egress": expected_egress,
                "egress_matches": egress_matches,
                "m_delta": m_delta,
                "w_delta": w_delta,
            })

    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        td.cleanup()

    all_passed = bool(case_results) and all(c.get("status") == "PASS" for c in case_results)
    return {
        "status": "PASS" if all_passed else "FAIL",
        "results": case_results,
    }


def evaluate_traffic_suite_status(
    test_traffic_verification: bool,
    xray_results: List[Dict[str, Any]],
    mihomo_results: Optional[Dict[str, Any]] = None,
) -> str:
    """Evaluate overall status for traffic suite.
    Enforces that disabling traffic verification or Mihomo traffic forces INCOMPLETE, not PASS.
    """
    if not test_traffic_verification:
        return "INCOMPLETE"

    if mihomo_results and mihomo_results.get("status") == "INCOMPLETE":
        return "INCOMPLETE"

    # Check for any failures
    for r in xray_results:
        if r.get("status") != "PASS":
            return "FAIL"

    if mihomo_results:
        if mihomo_results.get("status") != "PASS":
            return "FAIL"

    return "PASS"
