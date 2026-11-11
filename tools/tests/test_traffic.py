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
    evaluate_traffic_suite_status,
    get_server_rx_packets,
    parse_proc_net_dev_rx_packets,
    classify_server_host,
    run_mihomo_traffic_suite,
)


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
        status = evaluate_traffic_suite_status(
            test_traffic_verification=True,
            xray_results=[{"status": "PASS"}, {"status": "PASS"}],
            mihomo_results={"status": "PASS"},
        )
        self.assertEqual(status, "PASS")

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

    def test_parse_proc_net_dev_rx_packet_columns_and_interface_filter(self):
        sample = (
            "Inter-| Receive | Transmit\n"
            " face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n"
            "    lo: 100 999 0 0 0 0 0 0 100 999 0 0 0 0 0 0\n"
            "  ens3: 2000 7 0 0 0 0 0 0 3000 9 0 0 0 0 0 0\n"
            "docker0: 4000 100 0 0 0 0 0 0 5000 100 0 0 0 0 0 0\n"
            " enp1s0: 6000 11 0 0 0 0 0 0 7000 13 0 0 0 0 0 0\n"
        )
        self.assertEqual(parse_proc_net_dev_rx_packets(sample), 18)

    def test_get_server_rx_packets_reads_proc_net_dev(self):
        mock_ssh = MagicMock()
        mock_ssh.run.return_value = MagicMock(
            ok=True,
            stdout=(
                "Inter-| Receive | Transmit\n"
                " face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n"
                "  ens3: 2000 7 0 0 0 0 0 0 3000 9 0 0 0 0 0 0\n"
            ),
        )
        self.assertEqual(get_server_rx_packets(mock_ssh), 7)
        mock_ssh.run.assert_called_once_with("cat /proc/net/dev")

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


if __name__ == "__main__":
    unittest.main()
