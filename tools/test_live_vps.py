#!/usr/bin/env python3
"""Live VPS E2E Test Runner CLI entrypoint.
Orchestrates end-to-end lifecycle, verification, and fault testing on live VPS pairs.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import subprocess
import sys
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
from live_vps.panel_api import E2EPanelClient
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
    """Get current git HEAD commit SHA."""
    try:
        res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(REPO_ROOT), capture_output=True, text=True)
        if res.returncode == 0:
            return res.stdout.strip()
    except Exception:
        pass
    return "unknown_commit"


def load_run_state(artifact_dir: Path) -> Dict[str, Any]:
    state_file = artifact_dir / "run-state.json"
    if not state_file.is_file():
        raise FileNotFoundError(f"run-state.json not found in {artifact_dir}")
    return json.loads(state_file.read_text(encoding="utf-8"))


def save_run_state(artifact_dir: Path, state: Dict[str, Any]) -> None:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    state_file = artifact_dir / "run-state.json"
    tmp_file = artifact_dir / "run-state.json.tmp"
    tmp_file.write_text(json.dumps(state, indent=2), encoding="utf-8")
    tmp_file.chmod(0o600)
    os.replace(tmp_file, state_file)


def build_test_cases_from_state(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build list of testcase dicts for JUnit reporting from state."""
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

    config_path = Path(args.config)
    if not config_path.is_file():
        print(f"Error: Config file not found: {config_path}", file=sys.stderr)
        return 1

    try:
        config = load_config(config_path)
    except Exception as e:
        print(f"Config parse error: {e}", file=sys.stderr)
        return 1

    # Register known secrets in redaction filter
    register_secret(config.admin_password)
    register_secret(config.scoped_api_token)
    register_secret(config.master_ssh_key_path)
    register_secret(config.worker_ssh_key_path)

    head_commit = get_git_head_commit()

    if args.mode == "full" or (args.mode == "preflight" and not args.run_id):
        run_id = args.run_id or f"run-{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
        artifact_dir = REPO_ROOT / "artifacts" / "live-vps" / run_id
        if artifact_dir.exists() and args.mode == "full":
            print(f"Error: Artifact directory {artifact_dir} already exists for full run", file=sys.stderr)
            return 1
        artifact_dir.mkdir(parents=True, exist_ok=True)
        state: Dict[str, Any] = {
            "test_run_id": run_id,
            "repository_commit": head_commit,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "config_fingerprint": {
                "master_ip": config.master_ip,
                "worker_ip": config.worker_ip,
                "acme_mode": config.acme_mode,
            },
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
        artifact_dir = REPO_ROOT / "artifacts" / "live-vps" / run_id
        try:
            state = load_run_state(artifact_dir)
        except Exception as e:
            print(f"Error loading run state: {e}", file=sys.stderr)
            return 1

        # Check repository commit & target address matching
        if state.get("repository_commit") != head_commit:
            print(f"Error: State repository commit mismatch: {state.get('repository_commit')} != {head_commit}", file=sys.stderr)
            return 1

        cfg_fp = state.get("config_fingerprint", {})
        if cfg_fp.get("master_ip") != config.master_ip or cfg_fp.get("worker_ip") != config.worker_ip:
            print("Error: Target IP address mismatch with run state", file=sys.stderr)
            return 1

    # Initialize SSH clients
    master_ssh = SSHClient(
        host=config.master_ip,
        port=config.master_ssh_port,
        user=config.master_ssh_user,
        key_path=config.master_ssh_key_path,
        known_hosts_path=config.master_known_hosts_path,
    )
    worker_ssh = SSHClient(
        host=config.worker_ip,
        port=config.worker_ssh_port,
        user=config.worker_ssh_user,
        key_path=config.worker_ssh_key_path,
        known_hosts_path=config.worker_known_hosts_path,
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
        # Phase: Preflight
        if args.mode in ("full", "preflight"):
            tools_chk = check_control_machine_tools(config)
            tools_ok = all(t.available for t in tools_chk.values())
            m_trust_ok, _ = check_ssh_trust(config.master_ip, config.master_ssh_port, config.master_known_hosts_path)
            w_trust_ok, _ = check_ssh_trust(config.worker_ip, config.worker_ssh_port, config.worker_known_hosts_path)
            dns_chk = verify_all_domains(config)

            # Baselines
            m_base = collect_remote_baseline(master_ssh)
            w_base = collect_remote_baseline(worker_ssh)
            m_gate_ok, m_errs = check_disposable_gate(m_base)
            w_gate_ok, w_errs = check_disposable_gate(w_base)

            preflight_pass = tools_ok and m_trust_ok and w_trust_ok and dns_chk.get("all_ok") and m_gate_ok and w_gate_ok
            state["results"]["preflight"] = {
                "status": "PASS" if preflight_pass else "FAIL",
                "tools_ok": tools_ok,
                "dns_ok": dns_chk.get("all_ok"),
                "master_gate_ok": m_gate_ok,
                "worker_gate_ok": w_gate_ok,
                "master_baseline": m_base,
                "worker_baseline": w_base,
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

            inst_ok, inst_details = install_master(master_ssh, config)
            if not inst_ok:
                state["results"]["install"] = {"status": "FAIL", "details": inst_details}
                save_run_state(artifact_dir, state)
                return 1

            worker_ok, worker_details = deploy_worker(master_ssh, worker_ssh, config)
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

        # Phase: Verify
        if args.mode in ("full", "verify"):
            if state.get("results", {}).get("install", {}).get("status") != "PASS":
                print("Prerequisite install is not PASS", file=sys.stderr)
                return 1

            # Login to Panel
            token = panel_client.login(config.admin_username, config.admin_password)
            register_secret(token)

            # mTLS verification
            mtls_res = verify_worker_mtls(master_ssh, config.worker_ip, panel_client)
            fw_m_res = verify_master_firewall(master_ssh, config.master_ip)
            fw_w_res = verify_worker_firewall(master_ssh, worker_ssh, config.worker_ip)
            ng_m_ok, _ = verify_nginx_config_syntax(master_ssh)
            ng_w_ok, _ = verify_nginx_config_syntax(worker_ssh)
            panel_https_res = verify_panel_https(config.master_panel_domain, ssl_ctx)
            reality_decoy_res = verify_reality_decoy_fallback(config.master_ip, config.master_reality_domain, ssl_ctx)

            short_uuid = get_default_user_short_uuid(panel_client)
            ua_res = verify_user_agent_policy(config.master_panel_domain, short_uuid, ssl_ctx)
            xray_sub_ok, xray_sub_res = fetch_and_validate_xray_subscription(config.master_panel_domain, short_uuid, ssl_ctx, ca_bundle_path=ca_bundle)
            mih_sub_ok, mih_sub_res = fetch_and_validate_mihomo_subscription(config.master_panel_domain, short_uuid, ssl_ctx, ca_bundle_path=ca_bundle)

            verify_ok = all([
                mtls_res.get("status") == "PASS",
                fw_m_res.get("status") == "PASS",
                fw_w_res.get("status") == "PASS",
                ng_m_ok, ng_w_ok,
                panel_https_res.get("status") == "PASS",
                reality_decoy_res.get("status") == "PASS",
                ua_res.get("status") == "PASS",
                xray_sub_ok, mih_sub_ok,
            ])

            state["results"]["verify"] = {
                "status": "PASS" if verify_ok else "FAIL",
                "mtls": mtls_res,
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

            token = panel_client.login(config.admin_username, config.admin_password)
            short_uuid = get_default_user_short_uuid(panel_client)

            # Fetch subscriptions
            _, xray_sub_res = fetch_and_validate_xray_subscription(config.master_panel_domain, short_uuid, ssl_ctx, ca_bundle_path=ca_bundle)
            mihomo_sub_url = f"https://{config.master_panel_domain}/api/sub/{short_uuid}/clash"
            req = urllib.request.Request(mihomo_sub_url, headers={"User-Agent": "clash.meta"})
            with urllib.request.urlopen(req, context=ssl_ctx, timeout=10) as resp:
                mihomo_yaml_str = resp.read().decode("utf-8")

            # Sequential Xray cases
            xray_raw_outbounds = []
            try:
                sub_url = f"https://{config.master_panel_domain}/api/sub/{short_uuid}/v2ray-json"
                req_x = urllib.request.Request(sub_url, headers={"User-Agent": "v2rayNG/1.8.5"})
                with urllib.request.urlopen(req_x, context=ssl_ctx, timeout=10) as resp_x:
                    xray_raw_outbounds = json.loads(resp_x.read().decode("utf-8")).get("outbounds", [])
            except Exception:
                pass

            xray_case_results = []
            for ob in xray_raw_outbounds:
                if ob.get("protocol") in ("vless", "trojan", "vmess"):
                    is_worker = "worker" in ob.get("tag", "").lower()
                    expected_egress = config.expected_worker_egress_ip or config.worker_ip if is_worker else config.expected_master_egress_ip or config.master_ip
                    res = run_xray_endpoint_test(
                        outbound=ob,
                        ca_bundle_path=ca_bundle,
                        expected_egress_ip=expected_egress,
                        master_ssh=master_ssh,
                        worker_ssh=worker_ssh,
                        is_worker_endpoint=is_worker,
                    )
                    xray_case_results.append(res)

            mihomo_suite_res = run_mihomo_traffic_suite(
                subscription_yaml_str=mihomo_yaml_str,
                ca_bundle_path=ca_bundle,
                config=config,
                master_ssh=master_ssh,
                worker_ssh=worker_ssh,
            )

            traffic_status = evaluate_traffic_suite_status(
                test_traffic_verification=config.test_traffic_verification,
                xray_results=xray_case_results,
                mihomo_results=mihomo_suite_res,
            )

            state["results"]["traffic"] = {
                "status": traffic_status,
                "xray_results": xray_case_results,
                "mihomo_results": mihomo_suite_res,
            }
            save_run_state(artifact_dir, state)

        # Phase: Negative
        if args.mode in ("full", "negative"):
            token = panel_client.login(config.admin_username, config.admin_password)
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
        if any(s == "FAIL" for s in phase_statuses):
            overall_status = "FAIL"
        elif any(s == "INCOMPLETE" for s in phase_statuses):
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
