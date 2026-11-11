"""Data plane traffic testing with Xray and Mihomo clients.
Performs sequential endpoint verification with simultaneous per-case tcpdump
captures on both VPS, isolated local proxy processes, and egress IP matching.
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
from .tls import verify_staging_roots

# A capture RPC must outlive its connection setup: the control channel stalls
# occasionally on VPN/carrier-NAT paths, and a budget equal to ConnectTimeout
# leaves no room for the kill/wait work that produces the packet summary.
CAPTURE_RPC_TIMEOUT = 20
CAPTURE_PATH_PREFIX = "/run/gowave-e2e-ingress-"


def find_free_port() -> int:
    """Find an available local TCP port on loopback."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def get_control_ingress_ip(ssh: SSHClient) -> Optional[str]:
    """Return the control machine's IPv4 as this target itself observes it.

    A public echo service is not authoritative: carrier-grade NAT pools hand out a
    different public address per destination, so a filter built from the address that
    api.ipify.org reports can match none of the packets that actually arrive here.
    """
    result = ssh.run('printf "%s\n%s\n" "$SSH_CONNECTION" "$SSH_CLIENT"', timeout=15)
    if not result.ok:
        return None
    for line in result.stdout.splitlines():
        fields = line.split()
        if not fields:
            continue
        try:
            address = ipaddress.ip_address(fields[0])
        except ValueError:
            continue
        if address.version == 4 and not address.is_loopback:
            return str(address)
    return None


def resolve_attribution_source(
    master_ssh: SSHClient, worker_ssh: SSHClient,
) -> Tuple[Optional[str], Optional[str]]:
    """Return the shared control IPv4 and, when unusable, the reason attribution failed."""
    master_ip = get_control_ingress_ip(master_ssh)
    worker_ip = get_control_ingress_ip(worker_ssh)
    if not master_ip or not worker_ip:
        return None, "Target VPS did not report the control machine's IPv4 address"
    if master_ip != worker_ip:
        return None, (
            "Control machine reaches Master and Worker from different public IPv4 "
            f"addresses ({master_ip} vs {worker_ip})"
        )
    return master_ip, None


def start_ingress_capture(ssh: SSHClient, target_port: int) -> Optional[Dict[str, str]]:
    """Start header-only capture of inbound TCP to the tested proxy service port.

    The filter deliberately does not name a source address: a VPN or carrier NAT can
    present a different public address per flow, and a filter built from any of them
    would silently capture nothing. Attribution happens after the fact from the
    addresses tcpdump actually saw.
    """
    if type(target_port) is not int or not 1 <= target_port <= 65535:
        return None
    if target_port == ssh.port:
        return None
    token = uuid.uuid4().hex
    base = CAPTURE_PATH_PREFIX + token
    log_path, pid_path = base + ".log", base + ".pid"
    capture_filter = "tcp and dst port " + str(target_port) + " and not dst port " + str(ssh.port)
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
    result = ssh.run(command, timeout=CAPTURE_RPC_TIMEOUT)
    if not result.ok:
        ssh.run(
            "if [ -f " + shlex.quote(pid_path) + " ]; then kill -INT \"$(cat " +
            shlex.quote(pid_path) + ")\" 2>/dev/null || true; fi; rm -f " +
            shlex.quote(log_path) + " " + shlex.quote(pid_path),
            timeout=10,
        )
        return None
    return {"log_path": log_path, "pid_path": pid_path}


def parse_ingress_evidence(output: str) -> Optional[Dict[str, Any]]:
    """Parse the stop-capture report into a total count and per-source packet counts."""
    summary = re.search(r"^SUMMARY (\d+) packets captured$", output, re.MULTILINE)
    if summary is None:
        return None
    sources: Dict[str, int] = {}
    for match in re.finditer(r"^SOURCE (\S+) (\d+)$", output, re.MULTILINE):
        count = int(match.group(2))
        if count > 0:
            sources[match.group(1)] = sources.get(match.group(1), 0) + count
    return {"captured": int(summary.group(1)), "sources": sources}


def stop_ingress_capture(ssh: SSHClient, capture: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """Stop capture and return its summary count plus per-source packet counts.

    An absent tcpdump summary is not evidence, so a capture that never completed is
    reported as missing rather than as zero traffic.
    """
    log_path, pid_path = shlex.quote(capture["log_path"]), shlex.quote(capture["pid_path"])
    command = (
        "set -eu; if [ -f " + pid_path + " ]; then kill -INT \"$(cat " + pid_path +
        ")\" 2>/dev/null || true; fi; "
        "for i in $(seq 1 50); do "
        "grep -q 'packets captured' " + log_path + " 2>/dev/null && break; "
        "sleep 0.1; done; "
        "summary=$(grep -E '^[0-9]+ packets captured$' " + log_path + " 2>/dev/null | tail -n 1 || true); "
        "printf 'SUMMARY %s\\n' \"${summary:-absent}\"; "
        "sed -n 's/.* IP6\\{0,1\\} \\([^ ]*\\) > .*/\\1/p' " + log_path + " 2>/dev/null "
        "| sed -E 's/\\.[0-9]+$//' | sort | uniq -c "
        "| sed -E 's/^ *([0-9]+) (.+)$/SOURCE \\2 \\1/' || true; "
        "rm -f " + log_path + " " + pid_path
    )
    result = ssh.run(command, timeout=CAPTURE_RPC_TIMEOUT)
    if not result.ok:
        return None
    return parse_ingress_evidence(result.stdout)


def sweep_stale_captures(ssh: SSHClient) -> None:
    """Remove capture logs and pid files an interrupted earlier case left behind.

    Only this suite's own prefix is touched; a leaked capture would otherwise keep
    recording later cases' packets and make any recovered summary ambiguous.
    """
    ssh.run(
        "rm -f " + CAPTURE_PATH_PREFIX + "*.log " + CAPTURE_PATH_PREFIX + "*.pid",
        timeout=10,
    )


def capture_pair_ingress(
    master_ssh: SSHClient, worker_ssh: SSHClient, target_port: int,
) -> Optional[Tuple[Dict[str, str], Dict[str, str]]]:
    """Start both target captures before one request to the exact proxy service port."""
    master_capture = start_ingress_capture(master_ssh, target_port)
    if master_capture is None:
        return None
    worker_capture = start_ingress_capture(worker_ssh, target_port)
    if worker_capture is None:
        stop_ingress_capture(master_ssh, master_capture)
        return None
    return master_capture, worker_capture


def finish_pair_ingress(
    master_ssh: SSHClient, worker_ssh: SSHClient,
    captures: Tuple[Dict[str, str], Dict[str, str]], is_worker_endpoint: bool,
    expected_source: str,
) -> Optional[Dict[str, Any]]:
    """Stop both captures and attribute matching packets to the control-machine address."""
    master = stop_ingress_capture(master_ssh, captures[0])
    worker = stop_ingress_capture(worker_ssh, captures[1])
    if master is None or worker is None:
        return None
    master_packets = master["sources"].get(expected_source, 0)
    worker_packets = worker["sources"].get(expected_source, 0)
    target_packets = worker_packets if is_worker_endpoint else master_packets
    offload_packets = master_packets if is_worker_endpoint else worker_packets
    foreign: Dict[str, int] = {}
    for side in (master, worker):
        for address, count in side["sources"].items():
            if address != expected_source:
                foreign[address] = foreign.get(address, 0) + count
    return {
        "master_packets": master_packets,
        "worker_packets": worker_packets,
        "master_captured": master["captured"],
        "worker_captured": worker["captured"],
        "observed_other_sources": dict(sorted(foreign.items(), key=lambda item: -item[1])[:5]),
        "expected_source_ip": expected_source,
        "target_packets": target_packets,
        "offload_packets": offload_packets,
        "target_ingress_ok": target_packets > 0,
        "offload_ok": offload_packets == 0,
        "evidence_method": "tcpdump inbound TCP by destination port, attributed to the control IPv4 the target reports",
    }


def classify_case_status(egress_matches: Any, ingress_evidence: Dict[str, Any]) -> str:
    """Decide one traffic case from egress and packet evidence, fail closed."""
    if egress_matches is not True:
        return "FAIL"
    if ingress_evidence["offload_ok"] is not True:
        return "FAIL"
    if ingress_evidence["target_ingress_ok"] is not True:
        # The tunnel demonstrably carried the request, so an empty capture on both hosts
        # means the filter missed the flow rather than that the connection leaked.
        return "INCOMPLETE"
    return "PASS"


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


def build_traffic_curl_cmd(proxy_url: str, timeout: int) -> List[str]:
    """Curl command for one tunneled egress request.

    The connect budget must survive one cold resolver stall: Go and Xray cache
    no DNS answers and a single dropped UDP query costs a full 5 seconds before
    the resolver falls through to the next server.
    """
    return [
        "curl",
        "-fsS",
        "--connect-timeout", str(max(10, timeout // 2)),
        "--max-time", str(timeout),
        "-x", proxy_url,
        "https://api.ipify.org",
    ]


def run_xray_endpoint_test(
    outbound: Dict[str, Any],
    ca_bundle_path: Path,
    expected_egress_ip: str,
    master_ssh: SSHClient,
    worker_ssh: SSHClient,
    is_worker_endpoint: bool,
    timeout: int = 30,
    acme_mode: str = "production",
    source_ip: Optional[str] = None,
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

        if not source_ip:
            return {"status": "INCOMPLETE", "tag": tag,
                    "error": "Target VPS did not report the control machine's IPv4 for per-case ingress capture"}
        server_port = get_xray_server_port(outbound) or 0
        captures = capture_pair_ingress(master_ssh, worker_ssh, server_port)
        if captures is None:
            return {"status": "INCOMPLETE", "tag": tag,
                    "error": "Cannot start per-case tcpdump capture on both VPS"}

        # Execute exactly one request while both VPS captures are active.
        curl_cmd = build_traffic_curl_cmd(f"socks5h://127.0.0.1:{socks_port}", timeout)
        try:
            curl_res = subprocess.run(curl_cmd, capture_output=True, text=True)
        finally:
            ingress_evidence = finish_pair_ingress(
                master_ssh, worker_ssh, captures, is_worker_endpoint, source_ip,
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
        return {
            "status": classify_case_status(egress_matches, ingress_evidence),
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
    timeout: int = 30,
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
            ["mihomo", "-d", td.name, "-f", str(tmp_config_path)],
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

            if not source_ip:
                case_results.append({
                    "status": "INCOMPLETE", "proxy": p_name,
                    "error": "Target VPS did not report the control machine's IPv4 for per-case ingress capture",
                })
                continue
            try:
                target_port = int(p.get("port"))
            except (TypeError, ValueError):
                target_port = 0
            captures = capture_pair_ingress(master_ssh, worker_ssh, target_port)
            if captures is None:
                case_results.append({
                    "status": "INCOMPLETE", "proxy": p_name,
                    "error": "Cannot start per-case tcpdump capture on both VPS",
                })
                continue

            # Execute exactly one request while both VPS captures are active.
            curl_cmd = build_traffic_curl_cmd(f"http://127.0.0.1:{mixed_port}", timeout)
            try:
                curl_res = subprocess.run(curl_cmd, capture_output=True, text=True)
            finally:
                ingress_evidence = finish_pair_ingress(
                    master_ssh, worker_ssh, captures, is_worker, source_ip,
                )

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

            if ingress_evidence is None:
                case_results.append({
                    "status": "INCOMPLETE", "proxy": p_name,
                    "error": "Per-case tcpdump capture did not return packet summaries",
                })
                continue
            case_results.append({
                "status": classify_case_status(egress_matches, ingress_evidence),
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
        "client": "mihomo",
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
    Enforces the expected active case count (8, 9, or 10 per client depending on the number of independently configured Vision domains).
    """
    if test_traffic_verification is not True:
        return "INCOMPLETE"
    if not isinstance(xray_results, list) or not isinstance(mihomo_results, dict):
        return "INCOMPLETE"
    if expected_case_count is not None and (
        type(expected_case_count) is not int or expected_case_count <= 0
    ):
        return "INCOMPLETE"

    mihomo_cases = mihomo_results.get("results")
    if not isinstance(mihomo_cases, list):
        mihomo_cases = []

    # A concrete failing case takes precedence over missing evidence in another case.
    all_cases = [*xray_results, *mihomo_cases]
    if (
        mihomo_results.get("status") == "FAIL"
        or any(isinstance(case, dict) and case.get("status") == "FAIL" for case in all_cases)
    ):
        return "FAIL"

    # A PASS requires a complete, well-formed case matrix from both clients.
    if not xray_results or not mihomo_cases:
        return "INCOMPLETE"
    if mihomo_results.get("status") != "PASS":
        return "INCOMPLETE"
    if expected_case_count is not None and (
        len(xray_results) != expected_case_count
        or len(mihomo_cases) != expected_case_count
    ):
        return "INCOMPLETE"

    def case_evidence_status(result: Dict[str, Any]) -> str:
        if not isinstance(result, dict):
            return "INCOMPLETE"
        if result.get("status") == "INCOMPLETE":
            return "INCOMPLETE"
        if result.get("status") == "FAIL":
            return "FAIL"
        if result.get("status") != "PASS":
            return "INCOMPLETE"

        # bool is a subclass of int in Python; packet counters must be actual integers.
        target_packets = result.get("target_packets")
        offload_packets = result.get("offload_packets")
        if type(target_packets) is not int or target_packets <= 0:
            return "INCOMPLETE"
        if type(offload_packets) is not int:
            return "INCOMPLETE"
        if offload_packets != 0:
            return "FAIL"

        # Do not trust a precomputed PASS status if its constituent evidence disagrees.
        if result.get("target_ingress_ok") is not True:
            return "INCOMPLETE"
        if result.get("offload_ok") is not True:
            return "FAIL" if result.get("offload_ok") is False else "INCOMPLETE"
        if result.get("egress_matches") is not True:
            return "FAIL" if result.get("egress_matches") is False else "INCOMPLETE"

        evidence_method = result.get("evidence_method")
        if not isinstance(evidence_method, str) or not evidence_method.startswith("tcpdump "):
            return "INCOMPLETE"
        return "PASS"

    for result in xray_results:
        evidence_status = case_evidence_status(result)
        if evidence_status != "PASS":
            return evidence_status

    for result in mihomo_cases:
        evidence_status = case_evidence_status(result)
        if evidence_status != "PASS":
            return evidence_status

    return "PASS"
