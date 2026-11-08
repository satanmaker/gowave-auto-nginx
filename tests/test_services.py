#!/usr/bin/env python3
"""Suite services: Userland daemon emulation, client handshakes, subscription delivery with User-Agent rules,
protocol template verification, proxy protocol constraints, and outbound SSRF blocking.
Must run with unprivileged user (os.geteuid() != 0).
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import socket
import sys
import threading
import time
import unittest
import urllib.request
import urllib.error

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from modules.api_client import GoWaveClient


class MockSubscriptionServer(BaseHTTPRequestHandler):
    """Emulates GoWave Panel /api/sub/ subscription endpoint with strict User-Agent validation."""
    
    def do_GET(self):
        user_agent = self.headers.get("User-Agent", "").strip()
        
        # GoWave Response Rule: Require non-empty User-Agent
        if not user_agent:
            self.close_connection = True
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Forbidden: Non-empty User-Agent header is required by GoWave Auto NGINX")
            return

        if self.path == "/api/sub/test-short-uuid/v2ray-json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.end_headers()
            sub_payload = {
                "outbounds": [
                    {
                        "protocol": "vless",
                        "settings": {"vnext": [{"address": "vpn.example.com", "port": 443}]},
                        "streamSettings": {"security": "reality", "realitySettings": {"serverName": "camou.example.com"}}
                    },
                    {
                        "protocol": "vless",
                        "settings": {"vnext": [{"address": "vpn.example.com", "port": 443}]},
                        "streamSettings": {"security": "tls", "network": "xhttp", "xhttpSettings": {"path": "/xhttp-down/"}}
                    },
                    {
                        "protocol": "vless",
                        "settings": {"vnext": [{"address": "vpn.example.com", "port": 443}]},
                        "streamSettings": {"security": "tls", "network": "ws", "wsSettings": {"path": "/ws"}}
                    },
                    {
                        "protocol": "trojan",
                        "settings": {"servers": [{"address": "vpn.example.com", "port": 443}]},
                        "streamSettings": {"security": "tls", "network": "grpc", "grpcSettings": {"serviceName": "trojan-grpc"}}
                    }
                ]
            }
            self.wfile.write(json.dumps(sub_payload).encode())

        elif self.path == "/api/sub/test-short-uuid/mihomo":
            self.send_response(200)
            self.send_header("Content-Type", "text/yaml; charset=utf-8")
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.end_headers()
            mihomo_yaml = """port: 7890
socks-port: 7891
allow-lan: false
mode: rule
log-level: info
proxies:
  - name: "VLESS-REALITY"
    type: vless
    server: vpn.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000001
    network: tcp
    reality-opts:
      public-key: test-pubkey
      short-id: test-shortid
    sni: camou.example.com
rules:
  - GEOIP,private,DIRECT,no-resolve
  - MATCH,DIRECT
"""
            self.wfile.write(mihomo_yaml.encode())
        else:
            self.close_connection = True
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


class TestServices(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), MockSubscriptionServer)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_euid_separation(self):
        """Services suite must run as unprivileged user."""
        self.assertNotEqual(os.geteuid(), 0, "Suite services must run with os.geteuid() != 0")

    def test_subscription_user_agent_positive_and_negative(self):
        """Subscription endpoints must require non-empty User-Agent and succeed with valid client UA."""
        # Negative test: Empty User-Agent
        req_empty_ua = urllib.request.Request(f"http://127.0.0.1:{self.port}/api/sub/test-short-uuid/v2ray-json")
        req_empty_ua.headers["User-Agent"] = ""
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req_empty_ua)
        self.assertEqual(ctx.exception.code, 403)

        # Positive test: Valid Xray User-Agent
        req_xray = urllib.request.Request(f"http://127.0.0.1:{self.port}/api/sub/test-short-uuid/v2ray-json")
        req_xray.headers["User-Agent"] = "v2rayN/6.0"
        with urllib.request.urlopen(req_xray) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("application/json", resp.headers.get("Content-Type", ""))
            data = json.loads(resp.read().decode())
            self.assertIn("outbounds", data)
            self.assertEqual(len(data["outbounds"]), 4)

        # Positive test: Valid Mihomo User-Agent
        req_mihomo = urllib.request.Request(f"http://127.0.0.1:{self.port}/api/sub/test-short-uuid/mihomo")
        req_mihomo.headers["User-Agent"] = "ClashMeta/1.19"
        with urllib.request.urlopen(req_mihomo) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("text/yaml", resp.headers.get("Content-Type", ""))
            yaml_content = resp.read().decode()
            self.assertIn("GEOIP,private,DIRECT,no-resolve", yaml_content)
            self.assertIn("VLESS-REALITY", yaml_content)

    def test_xray_template_proxy_protocol_isolation(self):
        """Only REALITY inbound (8443) must have acceptProxyProtocol: true; 10001-10003 must NOT."""
        templates_dir = REPO_ROOT / "assets" / "xray"

        reality_cfg = json.loads((templates_dir / "vless-reality.json").read_text())
        xhttp_cfg = json.loads((templates_dir / "vless-xhttp.json").read_text())
        ws_cfg = json.loads((templates_dir / "vless-ws.json").read_text())
        trojan_cfg = json.loads((templates_dir / "trojan-grpc.json").read_text())

        # REALITY on 8443 must have acceptProxyProtocol true in tcpSettings
        self.assertEqual(reality_cfg["port"], 8443)
        self.assertTrue(reality_cfg.get("streamSettings", {}).get("tcpSettings", {}).get("acceptProxyProtocol"))

        # Inbounds behind NGINX (10001-10003) must NOT have acceptProxyProtocol
        for cfg, expected_port in [(xhttp_cfg, 10001), (ws_cfg, 10002), (trojan_cfg, 10003)]:
            self.assertEqual(cfg["port"], expected_port)
            ss = cfg.get("streamSettings", {})
            self.assertFalse(ss.get("tcpSettings", {}).get("acceptProxyProtocol", False))
            self.assertFalse(ss.get("sockopt", {}).get("acceptProxyProtocol", False))

    def test_ssrf_outbound_routing_rules(self):
        """Outbound routing rules must block cloud metadata (169.254.0.0/16) and loopback ranges."""
        client = GoWaveClient("http://127.0.0.1:3000")
        raw_json = client.compile_config_profile("test-node", "camou.example.com", "dGVzdC1wcml2YXRlLWtleQ==")
        config = json.loads(raw_json)

        routing_rules = config.get("routing", {}).get("rules", [])
        self.assertTrue(len(routing_rules) >= 2, "Expected at least 2 routing rules")

        # Find block rule
        block_rule = None
        for r in routing_rules:
            if r.get("outboundTag", "").upper() == "BLOCK":
                block_rule = r
                break

        self.assertIsNotNone(block_rule, "No outbound rule with tag 'BLOCK' found")
        blocked_ips = block_rule.get("ip", [])
        self.assertTrue(any("169.254" in ip for ip in blocked_ips), "Expected 169.254 range in blocked IPs")
        self.assertTrue(any("127." in ip or ip == "geoip:private" for ip in blocked_ips),
                        "Expected loopback or geoip:private in blocked IPs")

    def test_userland_tcp_and_websocket_upgrade_simulation(self):
        """Simulate TCP connection and WebSocket upgrade header negotiation."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        srv_port = server_sock.getsockname()[1]

        def handle_conn():
            conn, _ = server_sock.accept()
            req = conn.recv(1024).decode()
            if "Upgrade: websocket" in req and "Connection: Upgrade" in req:
                conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
            conn.close()

        t = threading.Thread(target=handle_conn)
        t.start()

        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect(("127.0.0.1", srv_port))
        client_sock.sendall(b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        resp = client_sock.recv(1024).decode()
        client_sock.close()
        t.join()
        server_sock.close()

        self.assertIn("101 Switching Protocols", resp)
        self.assertIn("Upgrade: websocket", resp)


if __name__ == "__main__":
    unittest.main()
