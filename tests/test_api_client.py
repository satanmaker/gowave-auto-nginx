#!/usr/bin/env python3
import http.server
import io
import json
import os
import stat
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
import sys
sys.path.insert(0, str(REPO_ROOT))
from modules.api_client import GoWaveAPIError, GoWaveClient, atomic_write_state, save_credentials, rollback_provisioning, _extract_list
from modules.recovery import write_journal_atomically


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
            user_uuid = f"user-{len(self.users) + 1}"
            self.users[body["username"]] = {**body, "uuid": user_uuid, "shortUuid": short_uuid}
            self.send_json(200, {"response": {"uuid": user_uuid, "shortUuid": short_uuid, "username": body["username"]}})
        elif self.path == "/api/tokens":
            self.send_json(200, {"response": {"token": "gowave-scoped-api-token-xyz", "id": "token-1"}})
        else:
            self.send_json(404, {"error": "Not found"})

    def do_GET(self):
        if self.path == "/api/system/tools/x25519/generate":
            self.send_json(200, {"response": {"keypairs": [{"privateKey": "priv-key-base64", "publicKey": "pub-key-base64"}]}})
        elif self.path == "/api/config-profiles":
            self.send_json(200, {"response": {"configProfiles": [{"uuid": k, **v} for k, v in self.profiles.items()]}})
        elif self.path.startswith("/api/config-profiles/") and self.path.count("/") == 3:
            uuid = self.path.split("/")[3]
            profile = self.profiles.get(uuid)
            if profile is None:
                self.send_json(404, {"error": "Not found"})
            else:
                self.send_json(200, {"response": {"uuid": uuid, **profile}})
        elif self.path.startswith("/api/config-profiles/") and self.path.endswith("/computed-config"):
            uuid = self.path.split("/")[3]
            cfg_str = self.profiles.get(uuid, {}).get("config", "{}")
            self.send_json(200, {"response": {"uuid": uuid, "name": "profile", "config": cfg_str}})
        elif self.path.startswith("/api/config-profiles/") and self.path.endswith("/inbounds"):
            uuid = self.path.split("/")[3]
            cfg_raw = self.profiles.get(uuid, {}).get("config", "{}")
            cfg = json.loads(cfg_raw) if isinstance(cfg_raw, str) else cfg_raw
            cfg_inbs = cfg.get("inbounds", []) if isinstance(cfg, dict) else []
            if cfg_inbs:
                inbounds = [
                    {"uuid": f"inb-{uuid}-{i+1}", "tag": inb.get("tag", f"inb-{i+1}"), "port": inb.get("port", 8443), "protocol": inb.get("protocol", "vless")}
                    for i, inb in enumerate(cfg_inbs)
                ]
            else:
                inbounds = [
                    {"uuid": "inb-1", "tag": "vless-reality-local-node", "port": 8443, "protocol": "vless"},
                    {"uuid": "inb-2", "tag": "vless-vision-local-node", "port": 8444, "protocol": "vless"},
                    {"uuid": "inb-3", "tag": "vless-xhttp-local-node", "port": 10001, "protocol": "vless"},
                    {"uuid": "inb-4", "tag": "vless-ws-local-node", "port": 10002, "protocol": "vless"},
                    {"uuid": "inb-5", "tag": "trojan-grpc-local-node", "port": 10003, "protocol": "trojan"},
                ]
            self.send_json(200, {"response": inbounds})
        elif self.path == "/api/nodes":
            self.send_json(200, {"response": {"nodes": [{"uuid": k, **v} for k, v in self.nodes.items()]}})
        elif self.path == "/api/internal-squads":
            self.send_json(200, {"response": {"internalSquads": [{"uuid": k, **v} for k, v in self.squads.items()]}})
        elif self.path == "/api/hosts":
            self.send_json(200, {"response": {"hosts": [{"uuid": k, **v} for k, v in self.hosts.items()]}})
        elif self.path == "/api/tokens":
            self.send_json(200, {"response": {"tokens": []}})
        elif self.path == "/api/users":
            self.send_json(200, {"response": {"users": []}})
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
        if self.path.startswith("/api/hosts/") or self.path.startswith("/api/internal-squads/"):
            self.send_json(405, {"error": "Method Not Allowed"})
            return
        if self.path == "/api/internal-squads":
            s_uuid = body.get("uuid")
            if s_uuid and s_uuid in self.squads:
                self.squads[s_uuid].update(body)
        elif self.path == "/api/hosts":
            h_uuid = body.get("uuid")
            if h_uuid and h_uuid in self.hosts:
                self.hosts[h_uuid].update(body)
        elif self.path.startswith("/api/nodes/"):
            n_uuid = self.path.split("/")[-1]
            if n_uuid in self.nodes:
                self.nodes[n_uuid].update(body)
        self.send_json(200, {"response": {"status": "updated", **body}})

    def do_DELETE(self):
        if self.path.startswith("/api/tokens/"):
            token_id = self.path.split("/")[-1]
            self.send_json(200, {"response": {"status": "deleted", "id": token_id}})
        elif self.path.startswith("/api/users/"):
            uid = self.path.split("/")[-1]
            self.send_json(200, {"response": {"status": "deleted", "uuid": uid}})
        elif self.path.startswith("/api/hosts/"):
            hid = self.path.split("/")[-1]
            self.hosts.pop(hid, None)
            self.send_json(200, {"response": {"status": "deleted", "uuid": hid}})
        elif self.path.startswith("/api/internal-squads/"):
            sid = self.path.split("/")[-1]
            self.squads.pop(sid, None)
            self.send_json(200, {"response": {"status": "deleted", "uuid": sid}})
        elif self.path.startswith("/api/nodes/"):
            nid = self.path.split("/")[-1]
            self.nodes.pop(nid, None)
            self.send_json(200, {"response": {"status": "deleted", "uuid": nid}})
        elif self.path.startswith("/api/config-profiles/"):
            pid = self.path.split("/")[-1]
            self.profiles.pop(pid, None)
            self.send_json(200, {"response": {"status": "deleted", "uuid": pid}})
        else:
            self.send_json(404, {"error": "Not found"})

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
        cls.server.server_close()

    def test_post_network_failure_is_not_retried(self):
        client = GoWaveClient("http://panel.example.test")
        with mock.patch(
            "modules.api_client.urllib.request.urlopen",
            side_effect=urllib.error.URLError("response connection lost"),
        ) as urlopen:
            with self.assertRaises(Exception):
                client.request("POST", "/api/nodes", {"name": "worker"})
        self.assertEqual(urlopen.call_count, 1)

    def test_post_401_reauthenticates_once_then_retries_request(self):
        client = GoWaveClient("http://panel.example.test")
        client.username = "admin"
        client.password = "secure-password"
        unauthorized = urllib.error.HTTPError(
            "http://panel.example.test/api/nodes", 401, "Unauthorized", {}, io.BytesIO(b'{"error":"unauthorized"}')
        )
        login_response = mock.MagicMock()
        login_response.__enter__.return_value = login_response
        login_response.read.return_value = b'{"response": {"accessToken": "fresh-token"}}'
        login_response.headers.get.return_value = "application/json"
        mutation_response = mock.MagicMock()
        mutation_response.__enter__.return_value = mutation_response
        mutation_response.read.return_value = b'{"created": true}'
        mutation_response.headers.get.return_value = "application/json"
        with mock.patch(
            "modules.api_client.urllib.request.urlopen",
            side_effect=[unauthorized, login_response, mutation_response],
        ) as urlopen:
            self.assertEqual(client.request("POST", "/api/nodes", {"name": "worker"}), {"created": True})
        self.assertEqual(urlopen.call_count, 3)
        self.assertEqual(client.token, "fresh-token")

    def test_get_network_failure_is_retried(self):
        client = GoWaveClient("http://panel.example.test")
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b'{"ok": true}'
        response.headers.get.return_value = "application/json"
        with mock.patch(
            "modules.api_client.urllib.request.urlopen",
            side_effect=[urllib.error.URLError("temporary network failure"), response],
        ) as urlopen, mock.patch("modules.api_client.time.sleep"):
            self.assertEqual(client.request("GET", "/api/nodes"), {"ok": True})
        self.assertEqual(urlopen.call_count, 2)

    def test_recovery_journal_is_created_with_private_permissions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            journal_path = Path(tmpdir) / "journal.json"
            tmp_path = Path(f"{journal_path}.tmp")
            tmp_path.write_text("stale temporary data")
            tmp_path.chmod(0o644)
            write_journal_atomically(str(journal_path), {
                "transaction_id": "provision_private_journal",
                "op": "provision",
                "state": "PROVISION_PREPARED",
                "timestamp": "2026-11-08T00:00:00Z",
                "entities": {},
            })
            self.assertEqual(stat.S_IMODE(journal_path.stat().st_mode), 0o600)

    def test_recovery_journal_refuses_temporary_symlink(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            journal_path = Path(tmpdir) / "journal.json"
            target = Path(tmpdir) / "do-not-overwrite.txt"
            tmp_path = Path(f"{journal_path}.tmp")
            target.write_text("sentinel")
            tmp_path.symlink_to(target)
            with self.assertRaises(OSError):
                write_journal_atomically(str(journal_path), {
                    "transaction_id": "provision_symlink_journal",
                    "op": "provision",
                    "state": "PROVISION_PREPARED",
                    "timestamp": "2026-11-08T00:00:00Z",
                    "entities": {},
                })
            self.assertEqual(target.read_text(), "sentinel")
            self.assertTrue(tmp_path.is_symlink())

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

    def test_save_credentials_refuses_temporary_symlink(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            creds_file = Path(tmpdir) / "credentials.txt"
            target = Path(tmpdir) / "do-not-overwrite.txt"
            tmp_path = Path(f"{creds_file}.tmp")
            target.write_text("sentinel")
            tmp_path.symlink_to(target)
            with self.assertRaises(OSError):
                save_credentials("admin", "secret-password", "https://panel.example.com", creds_path=str(creds_file))
            self.assertEqual(target.read_text(), "sentinel")
            self.assertTrue(tmp_path.is_symlink())

    def test_atomic_write_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "state.json"
            data = {"installationMode": "all-in-one", "domain": "vpn.example.com"}
            atomic_write_state(data, str(state_file))
            self.assertTrue(state_file.exists())
            loaded = json.loads(state_file.read_text())
            self.assertEqual(loaded["schemaVersion"], 2)
            self.assertEqual(loaded["installationMode"], "all-in-one")

    def test_atomic_state_file_uses_private_permissions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "state.json"
            tmp_path = Path(f"{state_file}.tmp")
            tmp_path.write_text("stale temporary data")
            tmp_path.chmod(0o644)
            atomic_write_state({"nodes": []}, str(state_file))
            self.assertEqual(stat.S_IMODE(state_file.stat().st_mode), 0o600)

    def test_atomic_state_writer_refuses_temporary_symlink(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "state.json"
            target = Path(tmpdir) / "do-not-overwrite.txt"
            tmp_path = Path(f"{state_file}.tmp")
            target.write_text("sentinel")
            tmp_path.symlink_to(target)
            with self.assertRaises(OSError):
                atomic_write_state({"nodes": []}, str(state_file))
            self.assertEqual(target.read_text(), "sentinel")
            self.assertTrue(tmp_path.is_symlink())

    def test_compile_config_profile(self):
        # Case 1: Default mode without vision_domain (4 inbounds)
        profile_json = self.client.compile_config_profile("local-node", "reality.example.com", "private-key-123")
        parsed = json.loads(profile_json)
        inbounds = parsed["inbounds"]
        self.assertEqual(len(inbounds), 4)

        # Check unique node-scoped tags
        tags = [inb["tag"] for inb in inbounds]
        self.assertIn("vless-reality-local-node", tags)
        self.assertNotIn("vless-vision-local-node", tags)
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

        # Case 2: Optional mode with vision_domain (5 inbounds)
        profile_json5 = self.client.compile_config_profile(
            "local-node", "reality.example.com", "private-key-123", vision_domain="vision.example.com"
        )
        parsed5 = json.loads(profile_json5)
        inbounds5 = parsed5["inbounds"]
        self.assertEqual(len(inbounds5), 5)
        tags5 = [inb["tag"] for inb in inbounds5]
        self.assertIn("vless-vision-local-node", tags5)
        for inb in inbounds5:
            if inb["port"] in (8443, 8444):
                self.assertTrue(inb["streamSettings"]["tcpSettings"]["acceptProxyProtocol"])

    def test_full_api_provisioning_flow(self):
        # 1. Admin registration and login
        reg = self.client.register_initial_admin("admin", "admin-pass-12345")
        self.assertIsNotNone(reg)
        token = self.client.login("admin", "admin-pass-12345")
        self.assertEqual(token, "mock-token-for-admin")

        # 2. x25519 generation
        x25519 = self.client.generate_x25519()
        self.assertEqual(x25519["privateKey"], "priv-key-base64")

        # 3. Provision Config Profile (Default: 4 inbounds)
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

        # 6. Provision Hosts (Default: 4 hosts)
        hosts = self.client.provision_hosts(prof_uuid, inbounds, node_uuid, squad_uuid, "vpn.example.com", "cdn.example.com")
        self.assertEqual(len(hosts), 4)

        # Check that all hosts strictly use firefox fingerprint
        for h in MockGoWaveServer.hosts.values():
            self.assertEqual(h.get("fingerprint"), "firefox")

        # 7. Provision User
        short_uuid = self.client.provision_user("default-user", squad_uuid)
        self.assertEqual(short_uuid, "suuid-12345")

        # 8. Issue API Token
        token_info = self.client.issue_api_token()
        self.assertEqual(token_info["token"], "gowave-scoped-api-token-xyz")

    def test_optional_vision_provisioning_flow(self):
        """When vision_domain is provided, exactly 5 inbounds and 5 hosts are provisioned."""
        self.client.login("admin", "admin-pass-12345")
        x25519 = self.client.generate_x25519()

        raw_cfg = self.client.compile_config_profile(
            "vision-node", "cdn.example.com", x25519["privateKey"], vision_domain="vision.example.com"
        )
        profile_info = self.client.provision_config_profile("GoWave Vision Profile", raw_cfg)
        prof_uuid = profile_info["profile_uuid"]
        inbounds = profile_info["inbounds"]
        self.assertEqual(len(inbounds), 5)

        inb_uuids = [inb["uuid"] for inb in inbounds]
        node_uuid = self.client.associate_node("vision-node", "127.0.0.1", 3002, prof_uuid, inb_uuids)
        squad_uuid = self.client.provision_internal_squad("Vision Squad", inb_uuids)

        hosts = self.client.provision_hosts(
            prof_uuid, inbounds, node_uuid, squad_uuid, "vpn.example.com", "cdn.example.com",
            node_name="vision-node", vision_domain="vision.example.com"
        )
        self.assertEqual(len(hosts), 5)
        remarks = {MockGoWaveServer.hosts[h].get("remark") for h in hosts}
        self.assertIn("VLESS-Vision-TLS@vision-node", remarks)
        for h in hosts:
            self.assertEqual(MockGoWaveServer.hosts[h].get("fingerprint"), "firefox")

    def test_provision_hosts_idempotent_patch(self):
        """Re-provisioning existing hosts must execute PATCH /api/hosts with uuid in body without 405 error."""
        self.client.login("admin", "admin-pass-12345")
        x25519 = self.client.generate_x25519()
        raw_cfg = self.client.compile_config_profile("patch-test-node", "cdn.example.com", x25519["privateKey"])
        prof_info = self.client.provision_config_profile("GoWave MVP Unified Profile - patch-test", raw_cfg)
        prof_uuid = prof_info["profile_uuid"]
        inbounds = prof_info["inbounds"]

        # Initial creation (POST /api/hosts)
        hosts1 = self.client.provision_hosts(prof_uuid, inbounds, "node-patch-test", "squad-patch-test", "vpn.example.com", "cdn.example.com", "patch-test-node")
        self.assertEqual(len(hosts1), 4)

        # Re-provisioning with same remark (triggers PATCH /api/hosts with uuid in body)
        hosts2 = self.client.provision_hosts(prof_uuid, inbounds, "node-patch-test", "squad-patch-test", "vpn.example.com", "cdn.example.com", "patch-test-node")
        self.assertEqual(hosts1, hosts2)

    def test_panel_discovers_master_and_worker_nodes(self):
        """Test that Panel registers and discovers both master node and worker node via GET /api/nodes."""
        # 1. Login
        self.client.login("admin", "admin-pass-12345")

        # 2. Step A: Provision Master Node (local-node)
        x25519_master = self.client.generate_x25519()
        raw_master = self.client.compile_config_profile("local-node", "reality.example.com", x25519_master["privateKey"])
        master_prof = self.client.provision_config_profile("GoWave MVP Unified Profile - local-node", raw_master)
        master_prof_uuid = master_prof["profile_uuid"]
        master_inbounds = master_prof["inbounds"]
        master_inb_uuids = [inb["uuid"] for inb in master_inbounds]

        master_node_uuid = self.client.associate_node("local-node", "127.0.0.1", 3002, master_prof_uuid, master_inb_uuids)
        self.assertIsNotNone(master_node_uuid)

        squad_uuid = self.client.provision_internal_squad("Default MVP Squad", master_inb_uuids)
        master_hosts = self.client.provision_hosts(master_prof_uuid, master_inbounds, master_node_uuid, squad_uuid, "vpn.example.com", "reality.example.com", "local-node")
        self.assertEqual(len(master_hosts), 4)

        # 3. Step B: Provision Worker Node (worker-1) on separate address
        x25519_worker = self.client.generate_x25519()
        raw_worker = self.client.compile_config_profile("worker-1", "worker-reality.example.com", x25519_worker["privateKey"])
        worker_prof = self.client.provision_config_profile("GoWave Worker worker-1 Profile", raw_worker)
        worker_prof_uuid = worker_prof["profile_uuid"]
        worker_inbounds = worker_prof["inbounds"]
        worker_inb_uuids = [inb["uuid"] for inb in worker_inbounds]

        worker_node_uuid = self.client.associate_node("worker-1", "10.89.0.20", 3002, worker_prof_uuid, worker_inb_uuids)
        self.assertIsNotNone(worker_node_uuid)
        self.assertNotEqual(master_node_uuid, worker_node_uuid)

        # Link worker inbounds to squad
        updated_squad_uuid = self.client.provision_internal_squad("Default MVP Squad", worker_inb_uuids)
        self.assertEqual(squad_uuid, updated_squad_uuid)

        worker_hosts = self.client.provision_hosts(worker_prof_uuid, worker_inbounds, worker_node_uuid, squad_uuid, "worker.example.com", "worker-reality.example.com", "worker-1")
        self.assertEqual(len(worker_hosts), 4)

        # 4. Step C: Query GoWave Panel API GET /api/nodes and assert panel sees BOTH nodes
        nodes_res = self.client.request("GET", "/api/nodes")
        nodes_list = _extract_list(nodes_res, "nodes")
        self.assertGreaterEqual(len(nodes_list), 2)

        nodes_by_name = {n["name"]: n for n in nodes_list}
        self.assertIn("local-node", nodes_by_name)
        self.assertIn("worker-1", nodes_by_name)

        # Verify master node contracts
        node_local = nodes_by_name["local-node"]
        self.assertEqual(node_local["address"], "127.0.0.1")
        self.assertEqual(node_local["port"], 3002)
        self.assertEqual(node_local["configProfile"]["activeConfigProfileUuid"], master_prof_uuid)
        self.assertEqual(set(node_local["configProfile"]["activeInbounds"]), set(master_inb_uuids))

        # Verify worker node contracts
        node_worker = nodes_by_name["worker-1"]
        self.assertEqual(node_worker["address"], "10.89.0.20")
        self.assertEqual(node_worker["port"], 3002)
        self.assertEqual(node_worker["configProfile"]["activeConfigProfileUuid"], worker_prof_uuid)
        self.assertEqual(set(node_worker["configProfile"]["activeInbounds"]), set(worker_inb_uuids))

        # Verify Internal Squad contains inbounds from BOTH nodes
        squads_res = self.client.request("GET", "/api/internal-squads")
        squads_list = _extract_list(squads_res, "internalSquads")
        mvp_squad = next(s for s in squads_list if s.get("name") == "Default MVP Squad")
        squad_inbs = set(mvp_squad.get("inbounds", []))
        self.assertTrue(set(master_inb_uuids).issubset(squad_inbs))
        self.assertTrue(set(worker_inb_uuids).issubset(squad_inbs))

        # Verify Host entities in GET /api/hosts include both nodes
        hosts_res = self.client.request("GET", "/api/hosts")
        hosts_list = _extract_list(hosts_res, "hosts")
        master_host_remarks = {f"{p}@local-node" for p in ["VLESS-REALITY-Vision", "VLESS-XHTTP-TLS", "VLESS-WS-TLS", "Trojan-gRPC-TLS"]}
        worker_host_remarks = {f"{p}@worker-1" for p in ["VLESS-REALITY-Vision", "VLESS-XHTTP-TLS", "VLESS-WS-TLS", "Trojan-gRPC-TLS"]}
        all_remarks = {h.get("remark") for h in hosts_list}
        self.assertTrue(master_host_remarks.issubset(all_remarks))
        self.assertTrue(worker_host_remarks.issubset(all_remarks))

    def test_rollback_provisioning_flow(self):
        MockGoWaveServer.registered_users["admin"] = "securepass1234567890"
        with tempfile.TemporaryDirectory() as tmpdir:
            jfile = Path(tmpdir) / "journal.json"
            sfile = Path(tmpdir) / "state.json"
            cfile = Path(tmpdir) / "credentials.txt"

            save_credentials("admin", "securepass1234567890", "https://panel.example.com", "token-xyz", str(cfile))

            # Simulate uncommitted initial provisioning
            jdata = {
                "transaction_id": "provision_12345",
                "op": "provision",
                "state": "PROVISION_APPLYING",
                "timestamp": "2026-11-08T00:00:00Z",
                "entities": [
                    {"type": "token", "uuid": "token-1", "action": "created"},
                    {"type": "user", "uuid": "user-uuid-1", "action": "created"},
                    {"type": "host", "uuid": "host-1", "action": "created"},
                    {"type": "host", "uuid": "host-2", "action": "created"},
                    {"type": "squad", "uuid": "squad-1", "action": "created"},
                    {"type": "node", "uuid": "node-1", "action": "created"},
                    {"type": "profile", "uuid": "prof-1", "action": "created"},
                ]
            }
            jfile.write_text(json.dumps(jdata))
            sfile.write_text(json.dumps({"schemaVersion": 2, "squadUuid": "squad-1"}))

            res = rollback_provisioning(str(jfile), str(sfile), str(cfile), base_url=f"http://127.0.0.1:{self.port}")
            self.assertTrue(res)

            # Check journal state transitioned to PROVISION_ROLLED_BACK
            updated_jdata = json.loads(jfile.read_text())
            self.assertEqual(updated_jdata["state"], "PROVISION_ROLLED_BACK")

    def test_rollback_journal_parse_error_does_not_echo_file_contents(self):
        marker = "sensitive-journal-content-marker"
        with tempfile.TemporaryDirectory() as tmpdir:
            jfile = Path(tmpdir) / "journal.json"
            jfile.write_text(marker + " { invalid json")
            stderr = io.StringIO()
            with mock.patch("sys.stderr", stderr):
                result = rollback_provisioning(
                    str(jfile), str(Path(tmpdir) / "state.json"),
                    str(Path(tmpdir) / "missing-credentials.txt"),
                )
            self.assertFalse(result)
            self.assertNotIn(marker, stderr.getvalue())
            self.assertIn("JSONDecodeError", stderr.getvalue())

    def test_rollback_journal_validation_error_does_not_echo_field_values(self):
        marker = "sensitive-transaction-marker"
        with tempfile.TemporaryDirectory() as tmpdir:
            jfile = Path(tmpdir) / "journal.json"
            jfile.write_text(json.dumps({
                "transaction_id": marker,
                "op": "invalid-operation",
                "state": "PROVISION_APPLYING",
                "timestamp": "2026-11-08T00:00:00Z",
                "entities": [],
            }))
            stderr = io.StringIO()
            with mock.patch("sys.stderr", stderr):
                result = rollback_provisioning(
                    str(jfile), str(Path(tmpdir) / "state.json"),
                    str(Path(tmpdir) / "missing-credentials.txt"),
                )
            self.assertFalse(result)
            self.assertNotIn(marker, stderr.getvalue())
            self.assertIn("JournalValidationError", stderr.getvalue())

    def test_rollback_journal_does_not_persist_api_response_secrets(self):
        marker = "private-key-secret-marker"
        class FailingRollbackClient:
            def __init__(self, base_url):
                pass

            def login(self, username, password):
                return "mock-token"

            def delete_node(self, uuid):
                raise GoWaveAPIError(
                    f"API rejected request and echoed {marker}",
                    status_code=500,
                    response_body=f'{{"error":"{marker}"}}',
                )

        with tempfile.TemporaryDirectory() as tmpdir:
            jfile = Path(tmpdir) / "journal.json"
            cfile = Path(tmpdir) / "credentials.txt"
            save_credentials("admin", "securepass1234567890", "https://panel.example.com", creds_path=str(cfile))
            jfile.write_text(json.dumps({
                "transaction_id": "provision_redaction",
                "op": "provision",
                "state": "PROVISION_APPLYING",
                "timestamp": "2026-11-08T00:00:00Z",
                "entities": [{"type": "node", "uuid": "node-1", "action": "created"}],
            }))

            with mock.patch("modules.api_client.GoWaveClient", FailingRollbackClient):
                result = rollback_provisioning(
                    str(jfile), str(Path(tmpdir) / "state.json"), str(cfile)
                )

            self.assertFalse(result)
            journal_text = jfile.read_text()
            self.assertNotIn(marker, journal_text)
            journal = json.loads(journal_text)
            self.assertIn("GoWaveAPIError", journal["rollback_errors"][0])
            self.assertIn("HTTP 500", journal["rollback_errors"][0])

    def test_empty_prepared_journal_rolls_back_without_api_login(self):
        """A PREPARED journal with no recorded side effects is safe to close without credentials."""
        with tempfile.TemporaryDirectory() as tmpdir:
            jfile = Path(tmpdir) / "journal.json"
            jfile.write_text(json.dumps({
                "transaction_id": "provision_prepared",
                "op": "provision",
                "state": "PROVISION_PREPARED",
                "timestamp": "2026-11-08T00:00:00Z",
                "entities": {},
            }))
            res = rollback_provisioning(str(jfile), str(Path(tmpdir) / "state.json"),
                                        str(Path(tmpdir) / "missing-credentials.txt"),
                                        base_url=f"http://127.0.0.1:{self.port}")
            self.assertTrue(res)
            self.assertEqual(json.loads(jfile.read_text())["state"], "PROVISION_ROLLED_BACK")

    def test_rollback_node_add_flow(self):
        MockGoWaveServer.registered_users["admin"] = "securepass1234567890"
        with tempfile.TemporaryDirectory() as tmpdir:
            jfile = Path(tmpdir) / "journal.json"
            sfile = Path(tmpdir) / "state.json"
            cfile = Path(tmpdir) / "credentials.txt"

            save_credentials("admin", "securepass1234567890", "https://panel.example.com", "token-xyz", str(cfile))

            # Simulate uncommitted worker node addition
            jdata = {
                "transaction_id": "node_add_worker-1",
                "op": "node_add",
                "state": "NODE_ADD_APPLYING",
                "node_name": "worker-1",
                "timestamp": "2026-11-08T00:00:00Z",
                "entities": [
                    {"type": "host", "uuid": "host-w1", "action": "created"},
                    {"type": "node", "uuid": "node-w1", "action": "created"},
                    {"type": "profile", "uuid": "prof-w1", "action": "created"},
                ]
            }
            jfile.write_text(json.dumps(jdata))
            sfile.write_text(json.dumps({
                "schemaVersion": 2,
                "squadUuid": "squad-1",
                "nodes": [
                    {"name": "local-node", "uuid": "node-1"},
                    {"name": "worker-1", "uuid": "node-w1"}
                ]
            }))

            res = rollback_provisioning(str(jfile), str(sfile), str(cfile), base_url=f"http://127.0.0.1:{self.port}")
            self.assertTrue(res)

            # Check journal state transitioned to NODE_ADD_ROLLED_BACK
            updated_jdata = json.loads(jfile.read_text())
            self.assertEqual(updated_jdata["state"], "NODE_ADD_ROLLED_BACK")

            # Check worker-1 pruned from state.json nodes list
            updated_sdata = json.loads(sfile.read_text())
            self.assertEqual(len(updated_sdata["nodes"]), 1)
            self.assertEqual(updated_sdata["nodes"][0]["name"], "local-node")

    def test_node_add_rollback_does_not_report_success_when_local_state_is_corrupt(self):
        previous_admin = MockGoWaveServer.registered_users.get("admin")
        previous_node = MockGoWaveServer.nodes.get("node-corrupt-state")
        def restore_mock_state():
            if previous_admin is None:
                MockGoWaveServer.registered_users.pop("admin", None)
            else:
                MockGoWaveServer.registered_users["admin"] = previous_admin
            if previous_node is None:
                MockGoWaveServer.nodes.pop("node-corrupt-state", None)
            else:
                MockGoWaveServer.nodes["node-corrupt-state"] = previous_node
        self.addCleanup(restore_mock_state)
        """API entities may be compensated, but corrupt local state keeps the journal rollback-required."""
        MockGoWaveServer.registered_users["admin"] = "securepass1234567890"
        MockGoWaveServer.nodes["node-corrupt-state"] = {"name": "worker-corrupt", "uuid": "node-corrupt-state"}

        with tempfile.TemporaryDirectory() as tmpdir:
            jfile = Path(tmpdir) / "journal.json"
            sfile = Path(tmpdir) / "state.json"
            cfile = Path(tmpdir) / "credentials.txt"
            save_credentials("admin", "securepass1234567890", "https://panel.example.com", "token-xyz", str(cfile))
            jfile.write_text(json.dumps({
                "transaction_id": "node_add_worker-corrupt",
                "op": "node_add",
                "state": "NODE_ADD_APPLYING",
                "node_name": "worker-corrupt",
                "timestamp": "2026-11-08T00:00:00Z",
                "entities": [{"type": "node", "uuid": "node-corrupt-state", "action": "created"}],
            }))
            sfile.write_text("{not-json")

            result = rollback_provisioning(
                str(jfile), str(sfile), str(cfile), base_url=f"http://127.0.0.1:{self.port}"
            )

            self.assertFalse(result)
            self.assertNotIn("node-corrupt-state", MockGoWaveServer.nodes)
            journal = json.loads(jfile.read_text())
            self.assertEqual(journal["state"], "NODE_ADD_ROLLBACK_REQUIRED")
            self.assertTrue(journal["rollback_errors"])
            self.assertTrue(any("local state" in error for error in journal["rollback_errors"]))

    def test_node_add_rollback_recovers_from_valid_atomic_state_temp_file(self):
        previous_admin = MockGoWaveServer.registered_users.get("admin")
        previous_node = MockGoWaveServer.nodes.get("node-temp-state")
        def restore_mock_state():
            if previous_admin is None:
                MockGoWaveServer.registered_users.pop("admin", None)
            else:
                MockGoWaveServer.registered_users["admin"] = previous_admin
            if previous_node is None:
                MockGoWaveServer.nodes.pop("node-temp-state", None)
            else:
                MockGoWaveServer.nodes["node-temp-state"] = previous_node
        self.addCleanup(restore_mock_state)
        """A valid state.json.tmp is used when state.json is corrupt after an interrupted atomic write."""
        MockGoWaveServer.registered_users["admin"] = "securepass1234567890"
        MockGoWaveServer.nodes["node-temp-state"] = {"name": "worker-temp", "uuid": "node-temp-state"}

        with tempfile.TemporaryDirectory() as tmpdir:
            jfile = Path(tmpdir) / "journal.json"
            sfile = Path(tmpdir) / "state.json"
            tmp_state = Path(tmpdir) / "state.json.tmp"
            cfile = Path(tmpdir) / "credentials.txt"
            save_credentials("admin", "securepass1234567890", "https://panel.example.com", "token-xyz", str(cfile))
            jfile.write_text(json.dumps({
                "transaction_id": "node_add_worker-temp",
                "op": "node_add",
                "state": "NODE_ADD_APPLYING",
                "node_name": "worker-temp",
                "timestamp": "2026-11-08T00:00:00Z",
                "entities": [{"type": "node", "uuid": "node-temp-state", "action": "created"}],
            }))
            sfile.write_text("{interrupted")
            tmp_state.write_text(json.dumps({
                "schemaVersion": 2,
                "nodes": [{"name": "local-node", "uuid": "node-local"}, {"name": "worker-temp", "uuid": "node-temp-state"}],
            }))

            result = rollback_provisioning(
                str(jfile), str(sfile), str(cfile), base_url=f"http://127.0.0.1:{self.port}"
            )

            self.assertTrue(result)
            self.assertNotIn("node-temp-state", MockGoWaveServer.nodes)
            self.assertEqual(json.loads(sfile.read_text())["nodes"], [{"name": "local-node", "uuid": "node-local"}])
            self.assertEqual(json.loads(jfile.read_text())["state"], "NODE_ADD_ROLLED_BACK")

    def test_rollback_preserves_adopted_entities(self):
        """Rollback never deletes entities adopted from prior configurations (C-03)."""
        MockGoWaveServer.registered_users["admin"] = "securepass1234567890"
        MockGoWaveServer.squads["adopted-squad-uuid"] = {"name": "Default MVP Squad", "uuid": "adopted-squad-uuid"}
        MockGoWaveServer.profiles["adopted-prof-uuid"] = {"name": "GoWave MVP Unified Profile", "uuid": "adopted-prof-uuid"}
        MockGoWaveServer.hosts["created-host-uuid"] = {"remark": "VLESS_REALITY@local-node", "uuid": "created-host-uuid"}

        with tempfile.TemporaryDirectory() as tmpdir:
            jfile = Path(tmpdir) / "journal.json"
            sfile = Path(tmpdir) / "state.json"
            cfile = Path(tmpdir) / "credentials.txt"
            save_credentials("admin", "securepass1234567890", "https://panel.example.com", "token-xyz", str(cfile))

            jdata = {
                "transaction_id": "provision_test_c03",
                "op": "provision",
                "state": "PROVISION_APPLYING",
                "timestamp": "2026-11-08T00:00:00Z",
                "entities": [
                    {"type": "profile", "uuid": "adopted-prof-uuid", "action": "adopted"},
                    {"type": "squad", "uuid": "adopted-squad-uuid", "action": "adopted"},
                    {"type": "host", "uuid": "created-host-uuid", "action": "created"},
                ]
            }
            jfile.write_text(json.dumps(jdata))
            sfile.write_text(json.dumps({"schemaVersion": 2}))

            res = rollback_provisioning(str(jfile), str(sfile), str(cfile), base_url=f"http://127.0.0.1:{self.port}")
            self.assertTrue(res)

            # Verified: created host was deleted
            self.assertNotIn("created-host-uuid", MockGoWaveServer.hosts)
            # Verified: adopted entities were NOT deleted
            self.assertIn("adopted-squad-uuid", MockGoWaveServer.squads)
            self.assertIn("adopted-prof-uuid", MockGoWaveServer.profiles)

    def test_rollback_restores_updated_entities(self):
        """Rollback restores before state for updated entities (C-03)."""
        MockGoWaveServer.registered_users["admin"] = "securepass1234567890"
        MockGoWaveServer.squads["squad-target"] = {
            "name": "Default MVP Squad",
            "uuid": "squad-target",
            "inbounds": ["inb-1", "inb-2", "inb-3"]
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            jfile = Path(tmpdir) / "journal.json"
            sfile = Path(tmpdir) / "state.json"
            cfile = Path(tmpdir) / "credentials.txt"
            save_credentials("admin", "securepass1234567890", "https://panel.example.com", "token-xyz", str(cfile))

            jdata = {
                "transaction_id": "provision_test_restore",
                "op": "provision",
                "state": "PROVISION_APPLYING",
                "timestamp": "2026-11-08T00:00:00Z",
                "entities": [
                    {
                        "type": "squad",
                        "uuid": "squad-target",
                        "action": "updated",
                        "before": {"name": "Default MVP Squad", "inbounds": ["inb-1"]}
                    }
                ]
            }
            jfile.write_text(json.dumps(jdata))
            sfile.write_text(json.dumps({"schemaVersion": 2}))

            res = rollback_provisioning(str(jfile), str(sfile), str(cfile), base_url=f"http://127.0.0.1:{self.port}")
            self.assertTrue(res)

            # Verify squad inbounds were rolled back to before state
            self.assertEqual(MockGoWaveServer.squads["squad-target"]["inbounds"], ["inb-1"])

    def test_rollback_never_deletes_by_global_name_scan(self):
        """Entities sharing standard names are never deleted if they were not created in transaction (C-03)."""
        MockGoWaveServer.registered_users["admin"] = "securepass1234567890"
        MockGoWaveServer.profiles["unrelated-prof"] = {
            "name": "GoWave MVP Unified Profile",
            "uuid": "unrelated-prof"
        }
        MockGoWaveServer.nodes["unrelated-node"] = {
            "name": "local-node",
            "uuid": "unrelated-node"
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            jfile = Path(tmpdir) / "journal.json"
            sfile = Path(tmpdir) / "state.json"
            cfile = Path(tmpdir) / "credentials.txt"
            save_credentials("admin", "securepass1234567890", "https://panel.example.com", "token-xyz", str(cfile))

            jdata = {
                "transaction_id": "provision_test_namescan",
                "op": "provision",
                "state": "PROVISION_APPLYING",
                "timestamp": "2026-11-08T00:00:00Z",
                "entities": {
                    "token_id": "token-only"
                }
            }
            jfile.write_text(json.dumps(jdata))
            sfile.write_text(json.dumps({"schemaVersion": 2}))

            res = rollback_provisioning(str(jfile), str(sfile), str(cfile), base_url=f"http://127.0.0.1:{self.port}")
            self.assertFalse(res)

            # Legacy UUID-only journals do not prove transaction ownership.
            updated = json.loads(jfile.read_text())
            self.assertEqual(updated["state"], "PROVISION_ROLLBACK_REQUIRED")
            self.assertIn("rollback_error", updated)
            self.assertIn("unrelated-prof", MockGoWaveServer.profiles)
            self.assertIn("unrelated-node", MockGoWaveServer.nodes)


if __name__ == "__main__":
    unittest.main()
