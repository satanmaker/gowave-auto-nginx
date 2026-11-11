#!/usr/bin/env python3
"""Live VPS E2E Test Runner CLI entrypoint.
Orchestrates end-to-end lifecycle, verification, and fault testing on live VPS pairs.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import subprocess
import sys
import re
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT))

from live_vps.config import load_config, LiveVPSConfig
from live_vps.tls import build_runtime_ca_bundle, create_ssl_context
from live_vps.redaction import register_secret, redact
from live_vps.ssh import SSHClient
from live_vps.dns import verify_all_domains
from live_vps.preflight import (
    check_control_machine_tools,
    check_private_key_file,
    check_ssh_trust,
    collect_remote_baseline,
    check_disposable_gate,
    LocalLock,
    RemotePairLock,
)
from live_vps.deployment import (
    prepare_master_repository,
    ensure_strace_on_master,
    install_master,
    deploy_worker,
)
from live_vps.panel_api import E2EPanelClient, read_master_credentials
from live_vps.mtls import verify_worker_mtls, run_mtls_negative_tests
from live_vps.subscriptions import (
    get_default_user_short_uuid,
    verify_user_agent_policy,
    fetch_and_validate_xray_subscription,
    fetch_and_validate_mihomo_subscription,
)
from live_vps.firewall import verify_master_firewall, verify_worker_firewall
from live_vps.nginx import (
    verify_nginx_config_syntax,
    verify_cover_reality_assets,
    verify_panel_https,
    verify_reality_decoy_fallback,
)
from live_vps.traffic import (
    run_xray_endpoint_test,
    run_mihomo_traffic_suite,
    evaluate_traffic_suite_status,
    get_remote_egress_ip,
    classify_xray_outbound,
)
from live_vps.negative import run_negative_suite
from live_vps.teardown import execute_teardown
from live_vps.reporting import (
    write_result_json,
    write_junit_report,
    write_summary_txt,
    collect_diagnostics,
)


def get_git_head_commit() -> str:
    """Return HEAD only when it represents the exact source archived to the VPS."""
    try:
        status = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=normal"],
            cwd=str(REPO_ROOT), capture_output=True, text=True,
        )
        if status.returncode != 0:
            return "unknown_commit"
        if status.stdout.strip():
            return "dirty_worktree"
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=str(REPO_ROOT), capture_output=True, text=True
        )
        if res.returncode == 0 and re.fullmatch(r"[0-9a-f]{40}", res.stdout.strip()):
            return res.stdout.strip()
    except Exception:
        pass
    return "unknown_commit"


def evaluate_preflight_eligibility(
    config: LiveVPSConfig,
    *,
    tools_ok: bool,
    master_trust_ok: bool,
    worker_trust_ok: bool,
    dns_ok: bool,
    master_root_ok: bool,
    worker_root_ok: bool,
    master_baseline: Dict[str, Any],
    worker_baseline: Dict[str, Any],
) -> Dict[str, Any]:
    """Evaluate read-only preflight and fail closed until safety gates are implemented."""
    vision_requested = bool(config.master_vision_domain and config.worker_vision_domain)
    master_gate_ok, master_errors = check_disposable_gate(
        master_baseline, vision_enabled=vision_requested
    )
    worker_gate_ok, worker_errors = check_disposable_gate(
        worker_baseline, vision_enabled=vision_requested
    )
    prerequisites_ok = all((
        tools_ok, master_trust_ok, worker_trust_ok, dns_ok,
        master_root_ok, worker_root_ok, master_gate_ok, worker_gate_ok,
    ))
    # Canonical mutation lock and re-entrant leases are active.
    remote_pair_lock_supported = True
    # D19/D20 host-resource before-images and verified two-sided compensation are active.
    transactional_restore_supported = True
    # Paired Master+Worker Vision setup and route verification are active.
    vision_supported = True
    blockers = (
        not remote_pair_lock_supported
        or not transactional_restore_supported
        or not vision_supported
    )
    status = "FAIL" if not prerequisites_ok else ("INCOMPLETE" if blockers else "PASS")
    return {
        "status": status,
        "vision_requested": vision_requested,
        "vision_supported": vision_supported,
        "remote_pair_lock_supported": remote_pair_lock_supported,
        "transactional_restore_supported": transactional_restore_supported,
        "tools_ok": tools_ok,
        "dns_ok": dns_ok,
        "master_root": master_root_ok,
        "worker_root": worker_root_ok,
        "master_gate_ok": master_gate_ok,
        "worker_gate_ok": worker_gate_ok,
        "master_gate_errors": master_errors,
        "worker_gate_errors": worker_errors,
        "master_baseline": master_baseline,
        "worker_baseline": worker_baseline,
    }


def build_config_fingerprint(config: LiveVPSConfig) -> str:
    """Hash every parsed non-secret configuration value for partial-run identity."""
    canonical = json.dumps(config.values, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_run_state(artifact_dir: Path) -> Dict[str, Any]:
    state_file = artifact_dir / "run-state.json"
    if state_file.is_symlink():
        raise ValueError("run-state.json must not be a symlink")
    if not state_file.is_file():
        raise FileNotFoundError(f"run-state.json not found in {artifact_dir}")
    if state_file.stat().st_mode & 0o077:
        raise PermissionError("run-state.json permissions must not grant group or other access")
    return json.loads(state_file.read_text(encoding="utf-8"))


def save_run_state(artifact_dir: Path, state: Dict[str, Any]) -> None:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    state_file = artifact_dir / "run-state.json"
    tmp_file = artifact_dir / "run-state.json.tmp"
    tmp_file.write_text(json.dumps(state, indent=2), encoding="utf-8")
    tmp_file.chmod(0o600)
    os.replace(tmp_file, state_file)


def build_test_cases_from_state(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build list of testcase dicts for JUnit reporting from state.
    Includes individual endpoints (16 or 20) and individual negative scenarios.
    """
    cases = []
    results = state.get("results", {})
    for phase_name, p_data in results.items():
        if isinstance(p_data, dict):
            status = p_data.get("status", "PASS")
            msg = p_data.get("error") or p_data.get("message") or ""
            cases.append({
                "name": f"phase_{phase_name}",
                "classname": f"live_vps.{phase_name}",
                "status": status,
                "message": msg,
                "duration": p_data.get("duration", "0.0"),
            })
            if phase_name == "traffic":
                for xc in p_data.get("xray_results", []):
                    cases.append({
                        "name": f"traffic_xray_{xc.get('tag', 'unknown')}",
                        "classname": "live_vps.traffic.xray",
                        "status": xc.get("status", "PASS"),
                        "message": xc.get("error") or xc.get("message") or "",
                        "duration": xc.get("duration", "0.0"),
                    })
                m_res = p_data.get("mihomo_results", {})
                m_cases = m_res.get("results", []) if isinstance(m_res, dict) else []
                for mc in m_cases:
                    cases.append({
                        "name": f"traffic_mihomo_{mc.get('name', 'unknown')}",
                        "classname": "live_vps.traffic.mihomo",
                        "status": mc.get("status", "PASS"),
                        "message": mc.get("error") or mc.get("message") or "",
                        "duration": mc.get("duration", "0.0"),
                    })
            elif phase_name == "negative":
                for sc in p_data.get("scenarios", []):
                    cases.append({
                        "name": f"negative_{sc.get('id', 'unknown')}",
                        "classname": "live_vps.negative",
                        "status": sc.get("status", "PASS"),
                        "message": sc.get("error") or sc.get("message") or "",
                        "duration": sc.get("duration", "0.0"),
                    })
        else:
            cases.append({
                "name": f"phase_{phase_name}",
                "classname": f"live_vps.{phase_name}",
                "status": "PASS" if p_data else "FAIL",
                "duration": "0.0",
            })
    return cases


def main() -> int:
    parser = argparse.ArgumentParser(description="Live VPS E2E Test Runner")
    parser.add_argument("--config", default="tools/live_vps_config.env", help="Path to config file")
    parser.add_argument(
        "--mode",
        choices=["preflight", "install", "verify", "traffic", "negative", "teardown", "full"],
        default="full",
        help="Execution mode (default: full)",
    )
    parser.add_argument("--run-id", help="Explicit test run ID (required for partial modes)")
    args = parser.parse_args()
    if args.mode not in ("full", "preflight") and not args.run_id:
        parser.error(f"--run-id is required when --mode={args.mode}")

    config_path = Path(args.config)
    if not config_path.is_file():
        print(f"Error: Config file not found: {config_path}", file=sys.stderr)
        return 1

    try:
        config = load_config(config_path)
    except Exception as e:
        print(f"Config parse error: {e}", file=sys.stderr)
        return 1

    head_commit = get_git_head_commit()
    if head_commit == "dirty_worktree":
        print(
            "Error: repository worktree is dirty; commit or discard local changes before E2E "
            "so the recorded commit matches the source archived to Master",
            file=sys.stderr,
        )
        return 1
    if head_commit == "unknown_commit":
        print("Error: cannot determine repository commit; refusing a resumable run", file=sys.stderr)
        return 1

    artifact_root = (REPO_ROOT / "artifacts" / "live-vps").resolve()
    artifact_root.mkdir(parents=True, exist_ok=True)

    def artifact_path_for(run_id_value: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", run_id_value) or run_id_value in (".", ".."):
            raise ValueError("run-id must match [A-Za-z0-9][A-Za-z0-9._-]{0,63} and must not be '.' or '..'")
        candidate = artifact_root / run_id_value
        if candidate.is_symlink():
            raise ValueError("run-id artifact path must not be a symlink")
        resolved = candidate.resolve(strict=False)
        if not resolved.is_relative_to(artifact_root):
            raise ValueError("run-id artifact path escapes artifacts/live-vps")
        return candidate

    is_fresh_run = args.mode in ("full", "preflight")
    if is_fresh_run:
        run_id = args.run_id or f"run-{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
        try:
            artifact_dir = artifact_path_for(run_id)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        if artifact_dir.exists():
            print(f"Error: Artifact directory {artifact_dir} already exists; refusing to reuse it", file=sys.stderr)
            return 1
        artifact_dir.mkdir(parents=True, mode=0o700)
        artifact_dir.chmod(0o700)
        state: Dict[str, Any] = {
            "test_run_id": run_id,
            "repository_commit": head_commit,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "config_fingerprint": build_config_fingerprint(config),
            "trust": {"acme_mode": config.acme_mode},
            "results": {},
            "overall": "RUNNING",
        }
        save_run_state(artifact_dir, state)
        if args.mode == "preflight":
            print(f"Initialized preflight run ID: {run_id}")
    else:
        if not args.run_id:
            print(f"Error: --run-id is required for mode '{args.mode}'", file=sys.stderr)
            return 1
        run_id = args.run_id
        try:
            artifact_dir = artifact_path_for(run_id)
            state = load_run_state(artifact_dir)
        except Exception as e:
            print(f"Error loading run state: {e}", file=sys.stderr)
            return 1

        if state.get("test_run_id") != run_id:
            print("Error: run-id does not match persisted state identity", file=sys.stderr)
            return 1
        if state.get("repository_commit") != head_commit:
            print(f"Error: State repository commit mismatch: {state.get('repository_commit')} != {head_commit}", file=sys.stderr)
            return 1

        cfg_fp = state.get("config_fingerprint", {})
        expected_fp = build_config_fingerprint(config)
        if cfg_fp != expected_fp:
            print("Error: Non-secret configuration identity mismatch with run state", file=sys.stderr)
            return 1
        if state.get("results", {}).get(args.mode, {}).get("status") in ("PASS", "FAIL", "INCOMPLETE", "TEARDOWN_FAILED"):
            print(f"Error: phase '{args.mode}' already has a terminal result; refusing implicit destructive rerun", file=sys.stderr)
            return 1

    # Initialize SSH clients
    master_ssh = SSHClient(
        host=config.master_ip,
        port=config.master_ssh_port,
        user=config.master_ssh_user,
        key_path=config.master_ssh_key_path,
        known_hosts=config.master_known_hosts_path,
    )
    worker_ssh = SSHClient(
        host=config.worker_ip,
        port=config.worker_ssh_port,
        user=config.worker_ssh_user,
        key_path=config.worker_ssh_key_path,
        known_hosts=config.worker_known_hosts_path,
    )

    # Scoped local process lock
    local_lock = LocalLock(f"gowave-live-vps-{config.master_ip}")
    if not local_lock.acquire():
        print("Error: Another runner is active on this Control Machine targeting Master", file=sys.stderr)
        return 2

    # Scoped CA bundle and SSL context
    try:
        ca_bundle = build_runtime_ca_bundle(config.acme_mode)
        ssl_ctx = create_ssl_context(ca_bundle)
    except Exception as e:
        print(f"Failed to prepare runtime CA bundle: {e}", file=sys.stderr)
        local_lock.release()
        return 1

    overall_status = "PASS"

    try:
        # Revalidate local SSH identity material on every invocation, including
        # resumed partial phases. The config fingerprint stores paths, not the
        # mutable file metadata or contents.
        ssh_preconditions = {
            "master_private_key": check_private_key_file(config.master_ssh_key_path),
            "worker_private_key": check_private_key_file(config.worker_ssh_key_path),
            "master_known_hosts": check_ssh_trust(
                config.master_ip, config.master_ssh_port, config.master_known_hosts_path
            ),
            "worker_known_hosts": check_ssh_trust(
                config.worker_ip, config.worker_ssh_port, config.worker_known_hosts_path
            ),
        }
        failed_ssh_preconditions = {
            name: error for name, (ok, error) in ssh_preconditions.items() if not ok
        }
        if failed_ssh_preconditions:
            state["results"]["ssh_precondition"] = {
                "status": "FAIL",
                "errors": failed_ssh_preconditions,
            }
            save_run_state(artifact_dir, state)
            print(
                "Local SSH credential/host-trust precondition failed; no VPS connection attempted.",
                file=sys.stderr,
            )
            return 1

        # Phase: Preflight
        if args.mode in ("full", "preflight"):
            tools_chk = check_control_machine_tools(config)
            tools_ok = all(t.ok for t in tools_chk.values())
            m_key_ok, m_key_error = check_private_key_file(config.master_ssh_key_path)
            w_key_ok, w_key_error = check_private_key_file(config.worker_ssh_key_path)
            m_trust_ok, m_trust_error = check_ssh_trust(config.master_ip, config.master_ssh_port, config.master_known_hosts_path)
            w_trust_ok, w_trust_error = check_ssh_trust(config.worker_ip, config.worker_ssh_port, config.worker_known_hosts_path)
            ssh_local_ok = m_key_ok and w_key_ok and m_trust_ok and w_trust_ok

            # Never contact either target unless both SSH credentials and both
            # pinned host identities passed local metadata/trust validation.
            if ssh_local_ok:
                m_base = collect_remote_baseline(master_ssh)
                w_base = collect_remote_baseline(worker_ssh)
                m_gate_ok, m_errs = check_disposable_gate(m_base)
                w_gate_ok, w_errs = check_disposable_gate(w_base)
                root_m_ok = master_ssh.run("test \"$(id -u)\" -eq 0").ok
                root_w_ok = worker_ssh.run("test \"$(id -u)\" -eq 0").ok
            else:
                m_base, w_base = {}, {}
                m_gate_ok = w_gate_ok = root_m_ok = root_w_ok = False
                m_errs = w_errs = ["Remote checks skipped: local SSH key/known_hosts validation failed"]

            dns_chk = verify_all_domains(config)

            dns_ok = bool(dns_chk) and all(result.ok for result in dns_chk.values())
            dns_details = {name: {"ok": result.ok, "expected_ip": result.expected_ip,
                                  "record_type": result.record_type, "resolved_ips": result.resolved_ips,
                                  "error": result.error} for name, result in dns_chk.items()}
            preflight_result = evaluate_preflight_eligibility(
                config,
                tools_ok=tools_ok,
                master_trust_ok=m_key_ok and m_trust_ok,
                worker_trust_ok=w_key_ok and w_trust_ok,
                dns_ok=dns_ok,
                master_root_ok=root_m_ok,
                worker_root_ok=root_w_ok,
                master_baseline=m_base,
                worker_baseline=w_base,
            )
            preflight_pass = preflight_result["status"] == "PASS"
            state["results"]["preflight"] = {
                **preflight_result,
                "master_ssh_key_ok": m_key_ok,
                "worker_ssh_key_ok": w_key_ok,
                "master_known_hosts_ok": m_trust_ok,
                "worker_known_hosts_ok": w_trust_ok,
                "ssh_local_errors": [value for value in (m_key_error, w_key_error, m_trust_error, w_trust_error) if value],
                "dns_details": dns_details,
            }
            save_run_state(artifact_dir, state)
            if not preflight_pass:
                print("Preflight failed. Halting.", file=sys.stderr)
                return 1

        # Phase: Install
        if args.mode in ("full", "install"):
            if state.get("results", {}).get("preflight", {}).get("status") != "PASS":
                print("Prerequisite preflight is not PASS", file=sys.stderr)
                return 1

            prep_ok = prepare_master_repository(master_ssh, REPO_ROOT)
            if not prep_ok:
                state["results"]["install"] = {"status": "FAIL", "error": "Failed copying repo to Master"}
                save_run_state(artifact_dir, state)
                return 1

            master_token = getattr(config, "_lease_token", None)
            inst_ok, inst_details = install_master(master_ssh, config, lease_token=master_token)
            if not inst_ok:
                state["results"]["install"] = {"status": "FAIL", "details": inst_details}
                save_run_state(artifact_dir, state)
                return 1

            worker_ok, worker_details = deploy_worker(master_ssh, worker_ssh, config, lease_token=master_token)
            state["results"]["install"] = {
                "status": "PASS" if worker_ok else "FAIL",
                "master_install": inst_details,
                "worker_deploy": worker_details,
            }
            save_run_state(artifact_dir, state)
            if not worker_ok:
                print("Worker deployment failed", file=sys.stderr)
                return 1

        # Panel client for verification phases
        panel_client = E2EPanelClient(
            panel_domain=config.master_panel_domain,
            ssl_context=ssl_ctx,
            timeout=config.api_timeout,
        )
        panel_credentials = None
        if args.mode in ("full", "verify", "traffic", "negative"):
            panel_credentials = read_master_credentials(master_ssh)
            register_secret(panel_credentials["ADMIN_PASSWORD"])
            register_secret(panel_credentials["SCOPED_API_TOKEN"])

        # Phase: Verify
        if args.mode in ("full", "verify"):
            if state.get("results", {}).get("install", {}).get("status") != "PASS":
                print("Prerequisite install is not PASS", file=sys.stderr)
                return 1

            # Login to Panel
            token = panel_client.login(panel_credentials["ADMIN_USERNAME"], panel_credentials["ADMIN_PASSWORD"])
            register_secret(token)

            # mTLS verification
            mtls_res = verify_worker_mtls(master_ssh, config.worker_ip, panel_client)
            mtls_negative_res = run_mtls_negative_tests(master_ssh, config.worker_ip)
            fw_m_res = verify_master_firewall(
                master_ssh, config.master_ip,
                enable_ipv6=config.enable_ipv6, master_ipv6=config.master_ipv6,
            )
            fw_w_res = verify_worker_firewall(
                master_ssh, worker_ssh, config.worker_ip,
                enable_ipv6=config.enable_ipv6, worker_ipv6=config.worker_ipv6,
            )
            ng_m_ok, _ = verify_nginx_config_syntax(master_ssh)
            ng_w_ok, _ = verify_nginx_config_syntax(worker_ssh)
            panel_https_res = verify_panel_https(config.master_panel_domain, ssl_ctx)
            reality_decoy_res = verify_reality_decoy_fallback(config.master_ip, config.master_reality_domain, ssl_ctx)

            short_uuid = get_default_user_short_uuid(panel_client)
            ua_res = verify_user_agent_policy(config.master_panel_domain, short_uuid, ssl_ctx)
            vision_enabled = bool(config.master_vision_domain and config.worker_vision_domain)
            xray_sub_ok, xray_sub_res = fetch_and_validate_xray_subscription(
                config.master_panel_domain, short_uuid, ssl_ctx,
                has_vision=vision_enabled, ca_bundle_path=ca_bundle,
                reality_fingerprint=config.reality_fingerprint,
            )
            mih_sub_ok, mih_sub_res = fetch_and_validate_mihomo_subscription(
                config.master_panel_domain, short_uuid, ssl_ctx,
                has_vision=vision_enabled, ca_bundle_path=ca_bundle,
                reality_fingerprint=config.reality_fingerprint,
            )

            verification_statuses = [
                mtls_res.get("status"),
                mtls_negative_res.get("status"),
                fw_m_res.get("status"),
                fw_w_res.get("status"),
                "PASS" if ng_m_ok else "FAIL",
                "PASS" if ng_w_ok else "FAIL",
                panel_https_res.get("status"),
                reality_decoy_res.get("status"),
                ua_res.get("status"),
                "PASS" if xray_sub_ok else "FAIL",
                "PASS" if mih_sub_ok else "FAIL",
            ]
            if any(value in ("FAIL", "ERROR") for value in verification_statuses):
                verification_status = "FAIL"
            elif any(value in ("INCOMPLETE", "SKIP", None) for value in verification_statuses):
                verification_status = "INCOMPLETE"
            else:
                verification_status = "PASS"
            verify_ok = verification_status == "PASS"

            state["results"]["verify"] = {
                "status": verification_status,
                "mtls": mtls_res,
                "mtls_negative": mtls_negative_res,
                "firewall_master": fw_m_res,
                "firewall_worker": fw_w_res,
                "nginx_master": ng_m_ok,
                "nginx_worker": ng_w_ok,
                "user_agent_policy": ua_res,
                "xray_subscription": xray_sub_res,
                "mihomo_subscription": mih_sub_res,
            }
            save_run_state(artifact_dir, state)

        # Phase: Traffic
        if args.mode in ("full", "traffic"):
            if state.get("results", {}).get("verify", {}).get("status") != "PASS":
                print("Prerequisite verify is not PASS", file=sys.stderr)
                return 1

            token = panel_client.login(panel_credentials["ADMIN_USERNAME"], panel_credentials["ADMIN_PASSWORD"])
            short_uuid = get_default_user_short_uuid(panel_client)

            # Fetch subscriptions
            _, xray_sub_res = fetch_and_validate_xray_subscription(config.master_panel_domain, short_uuid, ssl_ctx, ca_bundle_path=ca_bundle)
            mihomo_sub_url = f"https://{config.master_panel_domain}/api/sub/{short_uuid}/mihomo"
            req = urllib.request.Request(mihomo_sub_url, headers={"User-Agent": "mihomo"})
            with urllib.request.urlopen(req, context=ssl_ctx, timeout=10) as resp:
                mihomo_yaml_str = resp.read().decode("utf-8")

            # Sequential Xray cases
            xray_raw_outbounds = []
            try:
                sub_url = f"https://{config.master_panel_domain}/api/sub/{short_uuid}/v2ray-json"
                req_x = urllib.request.Request(sub_url, headers={"User-Agent": "v2rayNG/1.8.5"})
                with urllib.request.urlopen(req_x, context=ssl_ctx, timeout=10) as resp_x:
                    parsed_sub = json.loads(resp_x.read().decode("utf-8"))
                    if isinstance(parsed_sub, list):
                        for item in parsed_sub:
                            if isinstance(item, dict):
                                xray_raw_outbounds.extend(item.get("outbounds", []))
                    elif isinstance(parsed_sub, dict):
                        xray_raw_outbounds = parsed_sub.get("outbounds", [])
            except Exception:
                pass

            xray_case_results = []
            for ob in xray_raw_outbounds:
                if ob.get("protocol") in ("vless", "trojan", "vmess", "shadowsocks"):
                    is_worker = classify_xray_outbound(ob, config)
                    if is_worker is None:
                        xray_case_results.append({
                            "status": "INCOMPLETE", "tag": ob.get("tag"),
                            "error": "Cannot identify Master/Worker endpoint from Xray outbound server address",
                        })
                        continue
                    expected_egress = (
                        config.expected_worker_egress_ip or get_remote_egress_ip(worker_ssh)
                        if is_worker else
                        config.expected_master_egress_ip or get_remote_egress_ip(master_ssh)
                    )
                    if not expected_egress:
                        xray_case_results.append({
                            "status": "INCOMPLETE", "tag": ob.get("tag"),
                            "error": "Could not determine actual target VPS egress IP",
                        })
                        continue
                    res = run_xray_endpoint_test(
                        outbound=ob,
                        ca_bundle_path=ca_bundle,
                        expected_egress_ip=expected_egress,
                        master_ssh=master_ssh,
                        worker_ssh=worker_ssh,
                        is_worker_endpoint=is_worker,
                        acme_mode=config.acme_mode,
                    )
                    xray_case_results.append(res)

            mihomo_suite_res = run_mihomo_traffic_suite(
                subscription_yaml_str=mihomo_yaml_str,
                ca_bundle_path=ca_bundle,
                config=config,
                master_ssh=master_ssh,
                worker_ssh=worker_ssh,
            )

            expected_per_client = 10 if (config.master_vision_domain and config.worker_vision_domain) else 8
            alt_suite_res = None
            if config.alt_mihomo_core:
                alt_suite_res = run_mihomo_traffic_suite(
                    subscription_yaml_str=mihomo_yaml_str,
                    ca_bundle_path=ca_bundle,
                    config=config,
                    master_ssh=master_ssh,
                    worker_ssh=worker_ssh,
                    core_binary=config.alt_mihomo_core,
                )
            traffic_status = evaluate_traffic_suite_status(
                test_traffic_verification=config.test_traffic_verification,
                xray_results=xray_case_results,
                mihomo_results=mihomo_suite_res,
                expected_case_count=expected_per_client,
                mihomo_alt_results=alt_suite_res,
            )

            state["results"]["traffic"] = {
                "status": traffic_status,
                "xray_results": xray_case_results,
                "mihomo_results": mihomo_suite_res,
                "mihomo_alt_results": alt_suite_res,
            }
            save_run_state(artifact_dir, state)

        # Phase: Negative
        if args.mode in ("full", "negative"):
            if args.mode == "negative" and state.get("results", {}).get("install", {}).get("status") != "PASS":
                print("Prerequisite install is not PASS", file=sys.stderr)
                return 1
            token = panel_client.login(panel_credentials["ADMIN_USERNAME"], panel_credentials["ADMIN_PASSWORD"])
            short_uuid = get_default_user_short_uuid(panel_client)
            neg_res = run_negative_suite(
                config=config,
                master_ssh=master_ssh,
                worker_ssh=worker_ssh,
                panel_client=panel_client,
                short_uuid=short_uuid,
                ssl_context=ssl_ctx,
            )
            state["results"]["negative"] = neg_res
            save_run_state(artifact_dir, state)

        # Phase: Teardown
        if args.mode in ("full", "teardown"):
            if args.mode == "teardown" and (
                not state.get("results", {}).get("preflight", {}).get("master_baseline")
                or not state.get("results", {}).get("preflight", {}).get("worker_baseline")
            ):
                print("Prerequisite preflight baselines for both VPS are missing; refusing teardown", file=sys.stderr)
                return 1
            # Collect diagnostics before teardown
            collect_diagnostics(artifact_dir, master_ssh, worker_ssh)

            m_pre = state.get("results", {}).get("preflight", {}).get("master_baseline")
            w_pre = state.get("results", {}).get("preflight", {}).get("worker_baseline")

            teardown_res = execute_teardown(
                config=config,
                run_id=run_id,
                master_ssh=master_ssh,
                worker_ssh=worker_ssh,
                pre_baseline_master=m_pre,
                pre_baseline_worker=w_pre,
            )
            state["results"]["teardown"] = teardown_res
            save_run_state(artifact_dir, state)

        # Compute overall status
        phase_statuses = [p.get("status") for p in state.get("results", {}).values() if isinstance(p, dict)]
        if any(s in ("FAIL", "ERROR", "TEARDOWN_FAILED") for s in phase_statuses):
            overall_status = "FAIL"
        elif any(s in ("INCOMPLETE", "SKIP", "UNKNOWN", "RUNNING") for s in phase_statuses):
            overall_status = "INCOMPLETE"
        else:
            overall_status = "PASS"

        state["overall"] = overall_status
        save_run_state(artifact_dir, state)

        # Write reports
        test_cases = build_test_cases_from_state(state)
        write_result_json(artifact_dir, state)
        write_junit_report(artifact_dir, test_cases)
        write_summary_txt(artifact_dir, state)

    finally:
        # A full run with RESTORE_SNAPSHOT must not bypass the requested restore
        # merely because an earlier phase returned early. Preflight itself is
        # read-only; only proceed once both saved baselines exist.
        if (
            args.mode == "full"
            and config.test_teardown_policy == "RESTORE_SNAPSHOT"
            and "teardown" not in state.get("results", {})
            and state.get("results", {}).get("preflight", {}).get("status") == "PASS"
        ):
            try:
                if master_ssh and worker_ssh:
                    try:
                        collect_diagnostics(artifact_dir, master_ssh, worker_ssh)
                    except Exception as diagnostics_error:
                        print(
                            f"Pre-restore diagnostics incomplete: {type(diagnostics_error).__name__}",
                            file=sys.stderr,
                        )
                    state["results"]["teardown"] = execute_teardown(
                        config=config,
                        run_id=run_id,
                        master_ssh=master_ssh,
                        worker_ssh=worker_ssh,
                        pre_baseline_master=state["results"]["preflight"].get("master_baseline"),
                        pre_baseline_worker=state["results"]["preflight"].get("worker_baseline"),
                    )
                else:
                    state["results"]["teardown"] = {
                        "status": "TEARDOWN_FAILED",
                        "policy": "RESTORE_SNAPSHOT",
                        "error": "SSH sessions unavailable during early-failure snapshot teardown",
                    }
                save_run_state(artifact_dir, state)
            except Exception as teardown_error:
                state["results"]["teardown"] = {
                    "status": "TEARDOWN_FAILED",
                    "policy": "RESTORE_SNAPSHOT",
                    "error": f"Unexpected early-failure teardown error: {type(teardown_error).__name__}",
                }
                try:
                    save_run_state(artifact_dir, state)
                except Exception:
                    pass

        # Early phase returns and unexpected exceptions must still leave a
        # terminal, permission-restricted report instead of a RUNNING state.
        try:
            if state.get("overall") == "RUNNING":
                statuses = [p.get("status") for p in state.get("results", {}).values()
                            if isinstance(p, dict)]
                if any(value in ("FAIL", "ERROR", "TEARDOWN_FAILED") for value in statuses):
                    terminal = "FAIL"
                elif any(value in ("INCOMPLETE", "SKIP", "UNKNOWN", "RUNNING") for value in statuses):
                    terminal = "INCOMPLETE"
                else:
                    # Reaching finally without normal completion is never PASS.
                    terminal = "INCOMPLETE"
                state["overall"] = terminal
                save_run_state(artifact_dir, state)
                cases = build_test_cases_from_state(state)
                write_result_json(artifact_dir, state)
                write_junit_report(artifact_dir, cases)
                write_summary_txt(artifact_dir, state)
        except Exception as report_error:
            print(f"Failed to persist terminal E2E report: {type(report_error).__name__}", file=sys.stderr)
        finally:
            local_lock.release()

    print(f"E2E Run completed: {run_id}. Overall status: {overall_status}")
    if overall_status == "PASS":
        return 0
    elif overall_status == "INCOMPLETE":
        return 2
    else:
        return 1


if __name__ == "__main__":
    sys.exit(main())
