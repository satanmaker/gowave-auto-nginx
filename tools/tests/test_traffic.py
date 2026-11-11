#!/usr/bin/env python3
"""Unit tests for traffic module and traffic verification status gate."""
from __future__ import annotations

import unittest
from pathlib import Path
import sys
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT))

from live_vps.traffic import (
    apply_xray_trust_anchors,
    build_traffic_curl_cmd,
    evaluate_traffic_suite_status,
    classify_case_status,
    classify_server_host,
    get_control_ingress_ip,
    parse_ingress_evidence,
    resolve_attribution_source,
    run_mihomo_traffic_suite,
    start_ingress_capture,
    stop_ingress_capture,
    finish_pair_ingress,
    get_xray_server_port,
    sweep_stale_captures,
    CAPTURE_RPC_TIMEOUT,
)


class TestTrafficCurlBudget(unittest.TestCase):
    def test_connect_budget_survives_one_cold_resolver_stall(self):
        # Go and Xray cache no DNS answers; one dropped UDP query costs 5s, so a
        # connect budget below that turns a resolvable host into a curl timeout.
        cmd = build_traffic_curl_cmd("socks5h://127.0.0.1:1080", 30)
        connect = int(cmd[cmd.index("--connect-timeout") + 1])
        self.assertGreater(connect, 5)
        self.assertLessEqual(connect, 30)
        self.assertEqual(cmd[cmd.index("--max-time") + 1], "30")
        self.assertEqual(cmd[cmd.index("-x") + 1], "socks5h://127.0.0.1:1080")

    def test_connect_budget_keeps_a_floor_for_short_timeouts(self):
        cmd = build_traffic_curl_cmd("http://127.0.0.1:7890", 4)
        self.assertEqual(int(cmd[cmd.index("--connect-timeout") + 1]), 10)
        self.assertEqual(cmd[cmd.index("--max-time") + 1], "4")


class TestXrayTrustAnchors(unittest.TestCase):
    def _tls_outbound(self):
        return {
            "tag": "proxy",
            "protocol": "vless",
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {"serverName": "dns.example.test", "fingerprint": "firefox"},
            },
        }

    def test_production_mode_leaves_outbound_untouched(self):
        outbound = self._tls_outbound()
        self.assertIs(apply_xray_trust_anchors(outbound, "production"), outbound)

    def test_staging_mode_injects_verified_roots_without_mutating_input(self):
        outbound = self._tls_outbound()
        roots = [(Path(f"/tmp/root-{i}.pem"), {}) for i in range(4)]
        with patch("live_vps.traffic.verify_staging_roots", return_value=roots):
            result = apply_xray_trust_anchors(outbound, "staging")

        certs = result["streamSettings"]["tlsSettings"]["certificates"]
        self.assertEqual(len(certs), 4)
        self.assertTrue(all(c["usage"] == "verify" for c in certs))
        self.assertEqual(
            [c["certificateFile"] for c in certs],
            [str(p) for p, _ in roots],
        )
        self.assertNotIn("certificates", outbound["streamSettings"]["tlsSettings"])

    def test_staging_mode_skips_reality_and_plaintext_outbounds(self):
        for security in ("reality", "none"):
            outbound = self._tls_outbound()
            outbound["streamSettings"]["security"] = security
            with patch("live_vps.traffic.verify_staging_roots") as roots:
                self.assertIs(apply_xray_trust_anchors(outbound, "staging"), outbound)
                roots.assert_not_called()


def _packet_evidence(**overrides):
    evidence = {
        "status": "PASS",
        "target_packets": 4,
        "offload_packets": 0,
        "target_ingress_ok": True,
        "offload_ok": True,
        "egress_matches": True,
        "evidence_method": "tcpdump inbound TCP by destination port, attributed to the control IPv4 the target reports",
    }
    evidence.update(overrides)
    return evidence


class TestTrafficModule(unittest.TestCase):
    def test_status_gate_when_traffic_verification_disabled(self):
        # TEST_TRAFFIC_VERIFICATION=false MUST force INCOMPLETE, never PASS
        status = evaluate_traffic_suite_status(
            test_traffic_verification=False,
            xray_results=[{"status": "PASS"}],
            mihomo_results={"status": "PASS"},
        )
        self.assertEqual(status, "INCOMPLETE")

    def test_status_gate_when_mihomo_incomplete(self):
        # When Mihomo suite is INCOMPLETE (e.g. skipped), overall traffic is INCOMPLETE
        status = evaluate_traffic_suite_status(
            test_traffic_verification=True,
            xray_results=[{"status": "PASS"}],
            mihomo_results={"status": "INCOMPLETE", "skipped": True},
        )
        self.assertEqual(status, "INCOMPLETE")

    def test_status_gate_when_case_fails(self):
        status = evaluate_traffic_suite_status(
            test_traffic_verification=True,
            xray_results=[{"status": "PASS"}, {"status": "FAIL"}],
            mihomo_results={"status": "PASS"},
        )
        self.assertEqual(status, "FAIL")

    def test_status_gate_when_all_pass(self):
        evidence = _packet_evidence()
        status = evaluate_traffic_suite_status(
            test_traffic_verification=True,
            xray_results=[dict(evidence), dict(evidence)],
            mihomo_results={"status": "PASS", "results": [dict(evidence)]},
        )
        self.assertEqual(status, "PASS")

    def test_status_gate_rejects_pass_without_per_case_ingress_evidence(self):
        status = evaluate_traffic_suite_status(
            test_traffic_verification=True,
            xray_results=[{"status": "PASS"}],
            mihomo_results={"status": "PASS", "results": [{"status": "PASS"}]},
        )
        self.assertEqual(status, "INCOMPLETE")

    def test_status_gate_fails_when_offload_host_received_test_source_packets(self):
        evidence = _packet_evidence(offload_packets=1, offload_ok=False)
        status = evaluate_traffic_suite_status(
            test_traffic_verification=True,
            xray_results=[evidence],
            mihomo_results={"status": "PASS", "results": [evidence]},
        )
        self.assertEqual(status, "FAIL")

    def test_observed_case_failure_dominates_incomplete_other_client(self):
        status = evaluate_traffic_suite_status(
            test_traffic_verification=True,
            xray_results=[{"status": "FAIL"}],
            mihomo_results={"status": "INCOMPLETE", "results": []},
        )
        self.assertEqual(status, "FAIL")


    def test_xray_server_port_is_extracted_and_validated(self):
        self.assertEqual(
            get_xray_server_port({"settings": {"vnext": [{"address": "proxy.test", "port": 443}]}}),
            443,
        )
        self.assertEqual(
            get_xray_server_port({"settings": {"servers": [{"address": "proxy.test", "port": "8443"}]}}),
            8443,
        )
        self.assertIsNone(get_xray_server_port({"settings": {"vnext": []}}))
        self.assertIsNone(get_xray_server_port({"settings": {"vnext": [{"port": 70000}]}}))
        self.assertIsNone(get_xray_server_port({"settings": None}))

    def test_start_ingress_capture_filters_by_port_only(self):
        ssh = MagicMock()
        ssh.port = 2222
        ssh.run.return_value = MagicMock(ok=True, stdout="", stderr="")
        capture = start_ingress_capture(ssh, 443)
        self.assertIsNotNone(capture)
        command = ssh.run.call_args.args[0]
        self.assertIn("timeout --signal=INT 45s tcpdump", command)
        self.assertIn("tcpdump -nn -i any -Q in -l", command)
        self.assertIn("'tcp and dst port 443 and not dst port 2222'", command)
        # A source address in the filter is the defect this replaced: VPN and carrier NAT
        # hand out a different public address per flow, so such a filter captures nothing.
        self.assertNotIn("src host", command)

    def test_start_ingress_capture_rejects_invalid_or_ssh_target_port(self):
        ssh = MagicMock()
        ssh.port = 2222
        self.assertIsNone(start_ingress_capture(ssh, 0))
        self.assertIsNone(start_ingress_capture(ssh, 2222))
        self.assertIsNone(start_ingress_capture(ssh, 70000))
        self.assertIsNone(start_ingress_capture(ssh, True))
        ssh.run.assert_not_called()

    def test_capture_rpc_budget_outlives_connection_setup(self):
        # A budget equal to ConnectTimeout left no room for the kill/wait work once a
        # connection setup stalled, turning a working tunnel into a missing summary.
        self.assertGreater(CAPTURE_RPC_TIMEOUT, 10)

    def test_sweep_stale_captures_touches_only_the_suite_prefix(self):
        ssh = MagicMock()
        ssh.run.return_value = MagicMock(ok=True, stdout="", stderr="")
        sweep_stale_captures(ssh)
        command = ssh.run.call_args.args[0]
        self.assertEqual(
            command,
            "rm -f /run/gowave-e2e-ingress-*.log /run/gowave-e2e-ingress-*.pid",
        )
        self.assertNotIn("/run/gowave", command.replace("/run/gowave-e2e-ingress-", ""))
        self.assertEqual(ssh.run.call_args.kwargs.get("timeout"), 10)

    def test_stop_ingress_capture_requires_tcpdump_summary(self):
        ssh = MagicMock()
        ssh.run.return_value = MagicMock(
            ok=True,
            stdout="SUMMARY 3 packets captured\nSOURCE 198.51.100.25 3\n",
            stderr="",
        )
        self.assertEqual(
            stop_ingress_capture(ssh, {"log_path": "/run/cap.log", "pid_path": "/run/cap.pid"}),
            {"captured": 3, "sources": {"198.51.100.25": 3}},
        )
        ssh.run.return_value = MagicMock(ok=True, stdout="SUMMARY absent\n", stderr="")
        self.assertIsNone(
            stop_ingress_capture(ssh, {"log_path": "/run/cap.log", "pid_path": "/run/cap.pid"}),
        )

    def test_observed_sources_are_parsed_from_the_capture_report(self):
        report = (
            "SUMMARY 12 packets captured\n"
            "SOURCE 92.62.60.71 9\n"
            "SOURCE 203.0.113.9 2\n"
            "SOURCE 2001:db8::1 1\n"
        )
        self.assertEqual(
            parse_ingress_evidence(report),
            {
                "captured": 12,
                "sources": {"92.62.60.71": 9, "203.0.113.9": 2, "2001:db8::1": 1},
            },
        )
        self.assertIsNone(parse_ingress_evidence("listening on any\n"))

    def test_finish_pair_ingress_proves_target_and_rejects_offload(self):
        master = MagicMock()
        worker = MagicMock()
        master.run.return_value = MagicMock(
            ok=True, stdout="SUMMARY 0 packets captured\n", stderr="",
        )
        worker.run.return_value = MagicMock(
            ok=True,
            stdout="SUMMARY 5 packets captured\nSOURCE 198.51.100.25 5\n",
            stderr="",
        )
        evidence = finish_pair_ingress(
            master, worker,
            ({"log_path": "/m.log", "pid_path": "/m.pid"},
             {"log_path": "/w.log", "pid_path": "/w.pid"}),
            True, "198.51.100.25",
        )
        self.assertEqual(evidence["target_packets"], 5)
        self.assertEqual(evidence["offload_packets"], 0)
        self.assertTrue(evidence["target_ingress_ok"])
        self.assertTrue(evidence["offload_ok"])
        self.assertEqual(evidence["observed_other_sources"], {})

    def test_finish_pair_ingress_reports_the_address_that_actually_arrived(self):
        # The VPN exit rotated: packets arrived, but from an address other than the one the
        # target reported for the SSH session. Evidence must name the address it saw.
        master = MagicMock()
        worker = MagicMock()
        master.run.return_value = MagicMock(
            ok=True, stdout="SUMMARY 0 packets captured\n", stderr="",
        )
        worker.run.return_value = MagicMock(
            ok=True,
            stdout="SUMMARY 6 packets captured\nSOURCE 195.154.10.20 6\n",
            stderr="",
        )
        evidence = finish_pair_ingress(
            master, worker,
            ({"log_path": "/m.log", "pid_path": "/m.pid"},
             {"log_path": "/w.log", "pid_path": "/w.pid"}),
            True, "198.51.100.25",
        )
        self.assertEqual(evidence["worker_captured"], 6)
        self.assertEqual(evidence["target_packets"], 0)
        self.assertEqual(evidence["observed_other_sources"], {"195.154.10.20": 6})
        self.assertEqual(classify_case_status(True, evidence), "INCOMPLETE")

    def test_control_ingress_ip_is_taken_from_the_target_ssh_session(self):
        ssh = MagicMock()
        ssh.run.return_value = MagicMock(
            ok=True,
            stdout="92.62.60.71 51944 203.0.113.5 22\n92.62.60.71 51944 22\n",
            stderr="",
        )
        self.assertEqual(get_control_ingress_ip(ssh), "92.62.60.71")
        # A public echo service answers from a different carrier-NAT address than the one
        # that reaches the VPS, so its value must never be requested for the capture filter.
        self.assertNotIn("ipify", ssh.run.call_args.args[0])

    def test_control_ingress_ip_ignores_unparseable_and_ipv6_answers(self):
        ssh = MagicMock()
        ssh.run.return_value = MagicMock(ok=True, stdout="\n2001:db8::1 4000 22\n", stderr="")
        self.assertIsNone(get_control_ingress_ip(ssh))
        ssh.run.return_value = MagicMock(ok=False, stdout="", stderr="ssh failed")
        self.assertIsNone(get_control_ingress_ip(ssh))

    def test_attribution_requires_both_targets_to_see_one_control_address(self):
        master, worker = MagicMock(), MagicMock()
        master.run.return_value = MagicMock(ok=True, stdout="92.62.60.71 5000 22\n", stderr="")
        worker.run.return_value = MagicMock(ok=True, stdout="92.62.60.71 5001 22\n", stderr="")
        self.assertEqual(resolve_attribution_source(master, worker), ("92.62.60.71", None))

        worker.run.return_value = MagicMock(ok=True, stdout="198.51.100.7 5001 22\n", stderr="")
        source, error = resolve_attribution_source(master, worker)
        self.assertIsNone(source)
        self.assertIn("different public IPv4", error)

        worker.run.return_value = MagicMock(ok=True, stdout="", stderr="")
        source, error = resolve_attribution_source(master, worker)
        self.assertIsNone(source)
        self.assertIn("did not report", error)

    def test_case_status_never_passes_without_proof_of_intended_ingress(self):
        empty = {
            "target_packets": 0, "offload_packets": 0,
            "target_ingress_ok": False, "offload_ok": True,
        }
        # The tunnel demonstrably worked, so an empty capture is missing evidence, not a leak.
        self.assertEqual(classify_case_status(True, empty), "INCOMPLETE")
        self.assertEqual(
            classify_case_status(
                False, dict(empty, target_packets=4, target_ingress_ok=True),
            ),
            "FAIL",
        )
        self.assertEqual(
            classify_case_status(
                True, dict(empty, offload_packets=2, offload_ok=False, target_ingress_ok=True),
            ),
            "FAIL",
        )
        self.assertEqual(
            classify_case_status(True, {"target_ingress_ok": True, "offload_ok": True}),
            "PASS",
        )
        self.assertEqual(
            classify_case_status(None, {"target_ingress_ok": True, "offload_ok": True}),
            "FAIL",
        )

    def test_empty_xray_evidence_is_incomplete(self):
        self.assertEqual(
            evaluate_traffic_suite_status(
                test_traffic_verification=True,
                xray_results=[],
                mihomo_results={"status": "PASS"},
            ),
            "INCOMPLETE",
        )

    def test_missing_mihomo_evidence_is_incomplete(self):
        self.assertEqual(
            evaluate_traffic_suite_status(
                test_traffic_verification=True,
                xray_results=[{"status": "PASS"}],
                mihomo_results=None,
            ),
            "INCOMPLETE",
        )

    def test_endpoint_classification_uses_server_address_not_tag(self):
        config = MagicMock()
        config.master_ip = "203.0.113.10"
        config.master_panel_domain = "panel.example.test"
        config.master_reality_domain = "decoy-master.example.test"
        config.master_vision_domain = None
        config.master_ipv6 = None
        config.worker_ip = "203.0.113.20"
        config.worker_domain = "worker.example.test"
        config.worker_reality_domain = "decoy-worker.example.test"
        config.worker_vision_domain = None
        config.worker_ipv6 = None
        self.assertIs(classify_server_host("203.0.113.20", config), True)
        self.assertIs(classify_server_host("203.0.113.10", config), False)
        self.assertIsNone(classify_server_host("proxy-name-contains-worker", config))

    def test_mihomo_traffic_disabled_config_returns_incomplete(self):
        config = MagicMock()
        config.test_mihomo_traffic = False

        res = run_mihomo_traffic_suite(
            subscription_yaml_str="proxies: []",
            ca_bundle_path=Path("/tmp/ca.crt"),
            config=config,
            master_ssh=MagicMock(),
            worker_ssh=MagicMock(),
        )
        self.assertEqual(res["status"], "INCOMPLETE")
        self.assertTrue(res.get("skipped"))


    def test_mihomo_traffic_rejects_reality_proxies_without_hybrid_key_share(self):
        config = MagicMock()
        config.test_mihomo_traffic = True
        subscription = (
            "proxies:\n"
            "  - name: reality-legacy\n"
            "    type: vless\n"
            "    servername: cdn.example.com\n"
            "    reality-opts:\n"
            "      public-key: pk\n"
            "      short-id: sid\n"
            "  - name: reality-hybrid\n"
            "    type: vless\n"
            "    servername: cdn.example.com\n"
            "    reality-opts:\n"
            "      public-key: pk\n"
            "      short-id: sid\n"
            "      support-x25519mlkem768: true\n"
        )

        res = run_mihomo_traffic_suite(
            subscription_yaml_str=subscription,
            ca_bundle_path=Path("/tmp/ca.crt"),
            config=config,
            master_ssh=MagicMock(),
            worker_ssh=MagicMock(),
        )
        self.assertEqual(res["status"], "FAIL")
        self.assertEqual(res["proxies"], ["reality-legacy"])
        self.assertIn("support-x25519mlkem768", res["error"])

    def test_status_gate_requires_complete_expected_case_matrix_for_both_clients(self):
        evidence = _packet_evidence()
        for count in (8, 9, 10):
            with self.subTest(expected_case_count=count):
                self.assertEqual(
                    evaluate_traffic_suite_status(
                        True, [dict(evidence)] * (count - 1),
                        {"status": "PASS", "results": [dict(evidence)] * count},
                        expected_case_count=count,
                    ),
                    "INCOMPLETE",
                )
                self.assertEqual(
                    evaluate_traffic_suite_status(
                        True, [dict(evidence)] * count,
                        {"status": "PASS", "results": [dict(evidence)] * (count - 1)},
                        expected_case_count=count,
                    ),
                    "INCOMPLETE",
                )
                self.assertEqual(
                    evaluate_traffic_suite_status(
                        True, [dict(evidence)] * count,
                        {"status": "PASS", "results": [dict(evidence)] * count},
                        expected_case_count=count,
                    ),
                    "PASS",
                )

    def test_status_gate_rejects_inconsistent_precomputed_pass_flags(self):
        base = _packet_evidence()
        for field, value, expected in (
            ("target_ingress_ok", False, "INCOMPLETE"),
            ("target_ingress_ok", None, "INCOMPLETE"),
            ("offload_ok", False, "FAIL"),
            ("offload_ok", None, "INCOMPLETE"),
            ("egress_matches", False, "FAIL"),
            ("egress_matches", None, "INCOMPLETE"),
        ):
            with self.subTest(field=field, value=value):
                broken = dict(base, **{field: value})
                self.assertEqual(
                    evaluate_traffic_suite_status(
                        True, [broken],
                        {"status": "PASS", "results": [dict(base)]},
                    ),
                    expected,
                )

    def test_status_gate_rejects_boolean_or_negative_packet_counters(self):
        base = _packet_evidence()
        for field, value, expected in (
            ("target_packets", True, "INCOMPLETE"),
            ("target_packets", -1, "INCOMPLETE"),
            ("offload_packets", False, "INCOMPLETE"),
            ("offload_packets", -1, "FAIL"),
        ):
            with self.subTest(field=field, value=value):
                broken = dict(base, **{field: value})
                self.assertEqual(
                    evaluate_traffic_suite_status(
                        True, [broken],
                        {"status": "PASS", "results": [dict(base)]},
                    ),
                    expected,
                )

    def test_status_gate_fails_closed_for_malformed_result_shapes(self):
        self.assertEqual(evaluate_traffic_suite_status(True, None, {"status": "PASS", "results": []}), "INCOMPLETE")
        self.assertEqual(evaluate_traffic_suite_status(True, [], []), "INCOMPLETE")
        self.assertEqual(
            evaluate_traffic_suite_status(
                True, ["PASS"], {"status": "PASS", "results": [{"status": "FAIL"}]}
            ),
            "FAIL",
        )
        self.assertEqual(
            evaluate_traffic_suite_status(
                True, [{"status": "PASS"}], {"status": "PASS", "results": [{"status": "PASS"}]}
            ),
            "INCOMPLETE",
        )

    def test_status_gate_rejects_invalid_expected_case_count(self):
        evidence = _packet_evidence()
        for count in (0, -1, True, 8.0):
            with self.subTest(count=count):
                self.assertEqual(
                    evaluate_traffic_suite_status(
                        True, [dict(evidence)], {"status": "PASS", "results": [dict(evidence)]},
                        expected_case_count=count,
                    ),
                    "INCOMPLETE",
                )


if __name__ == "__main__":
    unittest.main()
