#!/usr/bin/env python3
import http.server
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.parse

REPO_ROOT = Path(__file__).resolve().parent.parent
import sys
sys.path.insert(0, str(REPO_ROOT))
from modules.api_client import GoWaveClient, atomic_write_state, save_credentials


class MockGoWaveServer(http.server.BaseHTTPRequestHandler):
    registered_users = {}
    tokens = {}
    profiles = {}
    nodes = {}
    squads = {}
    hosts = {}
    users = {}

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}

        if self.path == "/api/auth/register":
            username = body["username"]
            self.registered_users[username] = body["password"]
            self.send_json(200, {"response": {"username": username}})
        elif self.path == "/api/auth/login":
            username = body["username"]
            if self.registered_users.get(username) == body["password"]:
                token = f"mock-token-for-{username}"
                self.send_json(200, {"response": {"accessToken": token}})
            else:
                self.send_json(401, {"error": "Invalid credentials"})
        elif self.path == "/api/config-profiles":
            uuid = f"profile-{len(self.profiles) + 1}"
            self.profiles[uuid] = body
            self.send_json(200, {"response": {"uuid": uuid, "name": body["name"]}})
        elif self.path == "/api/nodes":
            uuid = f"node-{len(self.nodes) + 1}"
            self.nodes[uuid] = body
            self.send_json(200, {"response": {"uuid": uuid, "name": body["name"]}})
        elif self.path == "/api/internal-squads":
            uuid = f"squad-{len(self.squads) + 1}"
            self.squads[uuid] = body
            self.send_json(200, {"response": {"uuid": uuid, "name": body["name"]}})
        elif self.path == "/api/hosts":
            uuid = f"host-{len(self.hosts) + 1}"
            self.hosts[uuid] = body
            self.send_json(200, {"response": {"uuid": uuid, "remark": body.get("remark")}})
        elif self.path == "/api/users":
            short_uuid = "suuid-12345"
            self.users[body["username"]] = {**body, "shortUuid": short_uuid}
            self.send_json(200, {"response": {"shortUuid": short_uuid, "username": body["username"]}})
        elif self.path == "/api/tokens":
            self.send_json(200, {"response": {"token": "gowave-scoped-api-token-xyz", "id": "token-1"}})
        else:
            self.send_json(404, {"error": "Not found"})

    def do_GET(self):
        if self.path == "/api/system/tools/x25519/generate":
            self.send_json(200, {"response": {"keypairs": [{"privateKey": "priv-key-base64", "publicKey": "pub-key-base64"}]}})
        elif self.path == "/api/config-profiles":
            self.send_json(200, {"response": {"configProfiles": [{"uuid": k, **v} for k, v in self.profiles.items()]}})
        elif self.path.startswith("/api/config-profiles/") and self.path.endswith("/computed-config"):
            uuid = self.path.split("/")[3]
            cfg_str = self.profiles.get(uuid, {}).get("config", "{}")
            self.send_json(200, {"response": {"uuid": uuid, "name": "profile", "config": cfg_str}})
        elif self.path.startswith("/api/config-profiles/") and self.path.endswith("/inbounds"):
            inbounds = [
                {"uuid": "inb-1", "tag": "vless-reality-local-node", "port": 8443, "protocol": "vless"},
                {"uuid": "inb-2", "tag": "vless-xhttp-local-node", "port": 10001, "protocol": "vless"},
                {"uuid": "inb-3", "tag": "vless-ws-local-node", "port": 10002, "protocol": "vless"},
                {"uuid": "inb-4", "tag": "trojan-grpc-local-node", "port": 10003, "protocol": "trojan"},
            ]
            self.send_json(200, {"response": inbounds})
        elif self.path == "/api/nodes":
            self.send_json(200, {"response": {"nodes": [{"uuid": k, **v} for k, v in self.nodes.items()]}})
        elif self.path == "/api/internal-squads":
            self.send_json(200, {"response": {"internalSquads": [{"uuid": k, **v} for k, v in self.squads.items()]}})
        elif self.path == "/api/hosts":
            self.send_json(200, {"response": {"hosts": [{"uuid": k, **v} for k, v in self.hosts.items()]}})
        elif self.path.startswith("/api/users/by-username/"):
            username = self.path.split("/")[-1]
            if username in self.users:
                self.send_json(200, {"response": self.users[username]})
            else:
                self.close_connection = True
                self.send_json(404, {"error": "User not found"})
        else:
            self.close_connection = True
            self.send_json(404, {"error": "Not found"})

    def do_PATCH(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
        self.send_json(200, {"response": {"status": "updated", **body}})

    def send_json(self, status, payload):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode("utf-8"))

    def log_message(self, format, *args):
        pass


class TestAPIClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), MockGoWaveServer)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.daemon = True
        cls.thread.start()
        cls.client = GoWaveClient(f"http://127.0.0.1:{cls.port}")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_save_credentials(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            creds_file = Path(tmpdir) / "gowave-credentials.txt"
            save_credentials("admin", "securepass1234567890", "https://panel.example.com", "token-xyz", str(creds_file))
            self.assertTrue(creds_file.exists())
            mode = oct(creds_file.stat().st_mode & 0o777)
            self.assertEqual(mode, "0o600")
            content = creds_file.read_text()
            self.assertIn("ADMIN_USERNAME=admin", content)
            self.assertIn("ADMIN_PASSWORD=securepass1234567890", content)
            self.assertIn("SCOPED_API_TOKEN=token-xyz", content)

    def test_atomic_write_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "state.json"
            data = {"installationMode": "all-in-one", "domain": "vpn.example.com"}
            atomic_write_state(data, str(state_file))
            self.assertTrue(state_file.exists())
            loaded = json.loads(state_file.read_text())
            self.assertEqual(loaded["schemaVersion"], 2)
            self.assertEqual(loaded["installationMode"], "all-in-one")

    def test_compile_config_profile(self):
        profile_json = self.client.compile_config_profile("local-node", "reality.example.com", "private-key-123")
        parsed = json.loads(profile_json)
        inbounds = parsed["inbounds"]
        self.assertEqual(len(inbounds), 4)

        # Check unique node-scoped tags
        tags = [inb["tag"] for inb in inbounds]
        self.assertIn("vless-reality-local-node", tags)
        self.assertIn("vless-xhttp-local-node", tags)
        self.assertIn("vless-ws-local-node", tags)
        self.assertIn("trojan-grpc-local-node", tags)

        # Check acceptProxyProtocol is ONLY on REALITY 8443
        for inb in inbounds:
            if inb["port"] == 8443:
                self.assertTrue(inb["streamSettings"]["tcpSettings"]["acceptProxyProtocol"])
            else:
                self.assertNotIn("acceptProxyProtocol", inb["streamSettings"])

        # Check SSRF blocking in routing rules
        rules = parsed["routing"]["rules"]
        blocked_ips = rules[0]["ip"]
        self.assertIn("127.0.0.0/8", blocked_ips)
        self.assertIn("169.254.0.0/16", blocked_ips)

    def test_full_api_provisioning_flow(self):
        # 1. Admin registration and login
        reg = self.client.register_initial_admin("admin", "admin-pass-12345")
        self.assertIsNotNone(reg)
        token = self.client.login("admin", "admin-pass-12345")
        self.assertEqual(token, "mock-token-for-admin")

        # 2. x25519 generation
        x25519 = self.client.generate_x25519()
        self.assertEqual(x25519["privateKey"], "priv-key-base64")

        # 3. Provision Config Profile
        raw_cfg = self.client.compile_config_profile("local-node", "cdn.example.com", x25519["privateKey"])
        profile_info = self.client.provision_config_profile("GoWave MVP Unified Profile - local-node", raw_cfg)
        prof_uuid = profile_info["profile_uuid"]
        inbounds = profile_info["inbounds"]
        self.assertEqual(len(inbounds), 4)

        # 4. Associate Node
        inb_uuids = [inb["uuid"] for inb in inbounds]
        node_uuid = self.client.associate_node("local-node", "127.0.0.1", 3002, prof_uuid, inb_uuids)
        self.assertIsNotNone(node_uuid)

        # 5. Provision Squad
        squad_uuid = self.client.provision_internal_squad("Default MVP Squad", inb_uuids)
        self.assertIsNotNone(squad_uuid)

        # 6. Provision Hosts
        hosts = self.client.provision_hosts(prof_uuid, inbounds, node_uuid, squad_uuid, "vpn.example.com", "cdn.example.com")
        self.assertEqual(len(hosts), 4)

        # 7. Provision User
        short_uuid = self.client.provision_user("default-user", squad_uuid)
        self.assertEqual(short_uuid, "suuid-12345")

        # 8. Issue API Token
        token_info = self.client.issue_api_token()
        self.assertEqual(token_info["token"], "gowave-scoped-api-token-xyz")


if __name__ == "__main__":
    unittest.main()
