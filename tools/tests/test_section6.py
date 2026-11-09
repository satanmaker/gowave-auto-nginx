#!/usr/bin/env python3
"""Unit tests for Section 6 modules: mtls, subscriptions, firewall, and nginx."""
from __future__ import annotations

import json
import ssl
import unittest
from pathlib import Path
import sys
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT))

from live_vps.subscriptions import (
    get_default_user_short_uuid,
    fetch_and_validate_xray_subscription,
    fetch_and_validate_mihomo_subscription,
)
from live_vps.firewall import probe_tcp_port, verify_master_firewall, verify_worker_firewall
from live_vps.nginx import verify_nginx_config_syntax, verify_reality_decoy_fallback
from live_vps.mtls import verify_worker_mtls


class TestSection6Modules(unittest.TestCase):
    def test_subscriptions_short_uuid_redaction(self):
        panel_client = MagicMock()
        panel_client.get_user_by_username.return_value = {"shortUuid": "secret-short-uuid-1234"}

        uuid = get_default_user_short_uuid(panel_client)
        self.assertEqual(uuid, "secret-short-uuid-1234")

        from live_vps.redaction import redact
        self.assertEqual(redact("User sub at https://panel.com/api/sub/secret-short-uuid-1234/clash"),
                         "User sub at https://panel.com/api/sub/[REDACTED]/clash")

    def test_xray_subscription_parsing(self):
        ctx = ssl.create_default_context()
        valid_xray_payload = {
            "outbounds": [
                {"tag": "proxy-1", "protocol": "vless", "streamSettings": {"realitySettings": {"fingerprint": "firefox"}}},
                {"tag": "proxy-2", "protocol": "vless", "streamSettings": {"tlsSettings": {"fingerprint": "firefox"}}},
                {"tag": "proxy-3", "protocol": "trojan", "streamSettings": {"tlsSettings": {"fingerprint": "firefox"}}},
                {"tag": "proxy-4", "protocol": "vmess", "streamSettings": {"tlsSettings": {"fingerprint": "firefox"}}},
                {"tag": "proxy-5", "protocol": "vless", "streamSettings": {"realitySettings": {"fingerprint": "firefox"}}},
                {"tag": "proxy-6", "protocol": "vless", "streamSettings": {"tlsSettings": {"fingerprint": "firefox"}}},
                {"tag": "proxy-7", "protocol": "trojan", "streamSettings": {"tlsSettings": {"fingerprint": "firefox"}}},
                {"tag": "proxy-8", "protocol": "vmess", "streamSettings": {"tlsSettings": {"fingerprint": "firefox"}}},
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"},
            ]
        }

        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.status = 200
        mock_resp.headers = {"Cache-Control": "no-store"}
        mock_resp.read.return_value = json.dumps(valid_xray_payload).encode("utf-8")

        with patch("urllib.request.urlopen", return_value=mock_resp), \
             patch("subprocess.run", return_value=MagicMock(returncode=0)):
            ok, res = fetch_and_validate_xray_subscription("panel.example.com", "uuid", ctx, has_vision=False)
            self.assertTrue(ok)
            self.assertEqual(res["proxy_outbounds_count"], 8)
            self.assertEqual(res["fingerprint"], "firefox")

    def test_mihomo_subscription_parsing(self):
        ctx = ssl.create_default_context()
        valid_yaml_text = """
proxies:
  - name: p1
    type: vless
    client-fingerprint: firefox
  - name: p2
    type: vless
    client-fingerprint: firefox
  - name: p3
    type: trojan
    client-fingerprint: firefox
  - name: p4
    type: vmess
    client-fingerprint: firefox
  - name: p5
    type: vless
    client-fingerprint: firefox
  - name: p6
    type: vless
    client-fingerprint: firefox
  - name: p7
    type: trojan
    client-fingerprint: firefox
  - name: p8
    type: vmess
    client-fingerprint: firefox
rules:
  - GEOIP,private,DIRECT,no-resolve
  - MATCH,DIRECT
"""
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.status = 200
        mock_resp.read.return_value = valid_yaml_text.encode("utf-8")

        with patch("urllib.request.urlopen", return_value=mock_resp), \
             patch("subprocess.run", return_value=MagicMock(returncode=0)):
            ok, res = fetch_and_validate_mihomo_subscription("panel.example.com", "uuid", ctx, has_vision=False)
            self.assertTrue(ok)
            self.assertEqual(res["proxies_count"], 8)
            self.assertTrue(res["has_geoip_rule"])

    def test_firewall_probe_tcp(self):
        # Probing an unassigned high port on 127.0.0.1 should refuse or timeout
        ok, reason = probe_tcp_port("127.0.0.1", 59999, timeout=0.1)
        self.assertFalse(ok)
        self.assertTrue("REFUSED" in reason or "TIMEOUT" in reason or "ERROR" in reason)

    def test_firewall_vantage_overlap_incomplete(self):
        master_ssh = MagicMock()
        worker_ssh = MagicMock()

        master_ssh.run.side_effect = [
            MagicMock(ok=True, stdout="CONNECTED\n"), # positive control
            MagicMock(ok=True, stdout="203.0.113.10\n"), # master ipify
        ]
        worker_ssh.run.side_effect = [
            MagicMock(ok=True, stdout="Rule 1\n"), # ufw
            MagicMock(ok=True, stdout="-A UFW-INPUT -j DROP\n"), # iptables
        ]

        # Patch Control Machine public IP to match Master IP
        with patch("live_vps.firewall.get_control_machine_public_ip", return_value="203.0.113.10"):
            with patch("live_vps.firewall.probe_tcp_port", return_value=(False, "TIMEOUT")):
                res = verify_worker_firewall(master_ssh, worker_ssh, "198.51.100.2")
                self.assertEqual(res["status"], "INCOMPLETE")
                self.assertTrue("separate external vantage required" in res["error"])

    def test_nginx_syntax_check(self):
        ssh = MagicMock()
        ssh.run.return_value = MagicMock(ok=True, stdout="nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\nnginx: configuration file /etc/nginx/nginx.conf test is successful\n", stderr="")
        ok, out = verify_nginx_config_syntax(ssh)
        self.assertTrue(ok)

    def test_nginx_reality_fallback_does_not_accept_arbitrary_http_200(self):
        with patch("socket.create_connection") as mock_conn:
            mock_tls = MagicMock()
            mock_tls.recv.side_effect = [
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\\\"ok\\\":true}",
                b"",
            ]
            ctx = MagicMock()
            ctx.wrap_socket.return_value = mock_tls
            result = verify_reality_decoy_fallback("192.0.2.20", "reality.example.com", ctx)
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("did not return decoy", result["error"])

    def test_nginx_reality_decoy_rejection_on_gowave_leak(self):
        # If the response contains GoWave Panel API strings, decoy check must FAIL
        with patch("socket.create_connection") as mock_conn:
            mock_tls = MagicMock()
            mock_tls.recv.side_effect = [b"HTTP/1.1 200 OK\r\n\r\n{\"gowave\": \"leak\", \"accessToken\": \"abc\"}", b""]
            ctx = MagicMock()
            ctx.wrap_socket.return_value = mock_tls

            res = verify_reality_decoy_fallback("198.51.100.2", "reality.example.com", ctx)
            self.assertEqual(res["status"], "FAIL")
            self.assertTrue("leaked GoWave Panel API" in res["error"])

    def test_mtls_output_parsing_and_401_distinction(self):
        master_ssh = MagicMock()
        # Mock extract_secret_key
        master_ssh.run.side_effect = [
            MagicMock(ok=True, stdout="dGVzdC1zZWNyZXQ=\n"), # rescue raw
            MagicMock(
                ok=True,
                stdout=(
                    "Payload cryptographic verification PASSED\n"
                    "Handshake SUCCESS: TLSv1.3 negotiated\n"
                    "Node response: HTTP/1.1 401 Unauthorized\n"
                ),
                returncode=0
            )
        ]
        res = verify_worker_mtls(master_ssh, "198.51.100.2", panel_client=None)
        self.assertTrue(res["payload_crypto_pass"])
        self.assertTrue(res["mtls_handshake_pass"])
        # 401 is NOT http health pass
        self.assertFalse(res["worker_http_health_pass"])
        self.assertEqual(res["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
