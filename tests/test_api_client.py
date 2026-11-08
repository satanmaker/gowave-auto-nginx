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
from modules.api_client import GoWaveClient, atomic_write_state, save_credentials, rollback_provisioning, _extract_list


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
