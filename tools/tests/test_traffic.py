#!/usr/bin/env python3
"""Unit tests for traffic module and traffic verification status gate."""
from __future__ import annotations

import unittest
from pathlib import Path
import sys
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT))

from live_vps.traffic import (
    evaluate_traffic_suite_status,
    classify_server_host,
    run_mihomo_traffic_suite,
    start_ingress_capture,
    stop_ingress_capture,
    finish_pair_ingress,
    get_xray_server_port,
)


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
        evidence = {
            "status": "PASS", "target_packets": 4, "offload_packets": 0,
            "target_ingress_ok": True, "offload_ok": True, "egress_matches": True,
            "evidence_method": "tcpdump inbound TCP filtered by control-machine public IPv4",
        }
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
        evidence = {
            "status": "PASS", "target_packets": 4, "offload_packets": 1,
            "target_ingress_ok": True, "offload_ok": False, "egress_matches": True,
            "evidence_method": "tcpdump inbound TCP filtered by control-machine public IPv4",
        }
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

    def test_start_ingress_capture_uses_source_filter_and_excludes_ssh_port(self):
        ssh = MagicMock()
        ssh.port = 2222
        ssh.run.return_value = MagicMock(ok=True, stdout="", stderr="")
        capture = start_ingress_capture(ssh, "198.51.100.25", 443)
        self.assertIsNotNone(capture)
        command = ssh.run.call_args.args[0]
        self.assertIn("timeout --signal=INT 45s tcpdump", command)
        self.assertIn("tcpdump -nn -i any -Q in -l", command)
        self.assertIn("src host 198.51.100.25 and tcp and dst port 443 and not dst port 2222", command)


    def test_start_ingress_capture_rejects_invalid_or_ssh_target_port(self):
        ssh = MagicMock()
        ssh.port = 2222
        self.assertIsNone(start_ingress_capture(ssh, "198.51.100.25", 0))
        self.assertIsNone(start_ingress_capture(ssh, "198.51.100.25", 2222))
        self.assertIsNone(start_ingress_capture(ssh, "not-an-ip", 443))
        ssh.run.assert_not_called()

    def test_stop_ingress_capture_requires_tcpdump_summary(self):
        ssh = MagicMock()
        ssh.run.return_value = MagicMock(ok=True, stdout="3 packets captured\n", stderr="")
        self.assertEqual(
            stop_ingress_capture(ssh, {"log_path": "/run/cap.log", "pid_path": "/run/cap.pid"}),
            3,
        )
        ssh.run.return_value = MagicMock(ok=True, stdout="listening on any\n", stderr="")
        self.assertIsNone(
            stop_ingress_capture(ssh, {"log_path": "/run/cap.log", "pid_path": "/run/cap.pid"}),
        )

    def test_finish_pair_ingress_proves_target_and_rejects_offload(self):
        master = MagicMock()
        worker = MagicMock()
        master.run.return_value = MagicMock(ok=True, stdout="0 packets captured\n", stderr="")
        worker.run.return_value = MagicMock(ok=True, stdout="5 packets captured\n", stderr="")
        evidence = finish_pair_ingress(
            master, worker,
            ({"log_path": "/m.log", "pid_path": "/m.pid"},
             {"log_path": "/w.log", "pid_path": "/w.pid"}),
            True,
        )
        self.assertEqual(evidence["target_packets"], 5)
        self.assertEqual(evidence["offload_packets"], 0)
        self.assertTrue(evidence["target_ingress_ok"])
        self.assertTrue(evidence["offload_ok"])

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


    def test_status_gate_requires_complete_expected_case_matrix_for_both_clients(self):
        evidence = {
            "status": "PASS", "target_packets": 4, "offload_packets": 0,
            "target_ingress_ok": True, "offload_ok": True, "egress_matches": True,
            "evidence_method": "tcpdump inbound TCP filtered by control-machine public IPv4",
        }
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
        base = {
            "status": "PASS", "target_packets": 4, "offload_packets": 0,
            "target_ingress_ok": True, "offload_ok": True, "egress_matches": True,
            "evidence_method": "tcpdump inbound TCP filtered by control-machine public IPv4",
        }
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
        base = {
            "status": "PASS", "target_packets": 4, "offload_packets": 0,
            "target_ingress_ok": True, "offload_ok": True, "egress_matches": True,
            "evidence_method": "tcpdump inbound TCP filtered by control-machine public IPv4",
        }
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
        evidence = {
            "status": "PASS", "target_packets": 4, "offload_packets": 0,
            "target_ingress_ok": True, "offload_ok": True, "egress_matches": True,
            "evidence_method": "tcpdump inbound TCP filtered by control-machine public IPv4",
        }
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
