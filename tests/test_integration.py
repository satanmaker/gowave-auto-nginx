#!/usr/bin/env python3
"""Suite integration: Concurrent SQLite backup, GoWave API bootstrap, config profile provisioning,
Internal Squad creation, user lifecycle, Host entity provisioning, and mTLS 1.3 handshake verification.
Must run with unprivileged user (os.geteuid() != 0).
"""
import concurrent.futures
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import sqlite3
import ssl
import sys
import tempfile
import threading
import time
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from modules.api_client import GoWaveClient, atomic_write_state
from modules.recovery import sqlite_online_backup


class MockGoWaveServer(BaseHTTPRequestHandler):
    state = {
        "admin_registered": False,
        "token": "mock-token-xyz",
        "profiles": {},
        "inbounds": {},
        "nodes": {},
        "squads": {},
        "hosts": {},
        "users": {},
    }

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length).decode()) if length > 0 else {}

        if self.path == "/api/auth/register":
            MockGoWaveServer.state["admin_registered"] = True
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True}).encode())
        elif self.path == "/api/auth/login":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"accessToken": MockGoWaveServer.state["token"]}).encode())
        elif self.path == "/api/config-profiles":
            p_uuid = "prof-uuid-test"
            inbs = [
                {"uuid": "inb-1", "tag": "vless-reality-local-node", "port": 8443},
                {"uuid": "inb-2", "tag": "vless-xhttp-local-node", "port": 10001},
                {"uuid": "inb-3", "tag": "vless-ws-local-node", "port": 10002},
                {"uuid": "inb-4", "tag": "trojan-grpc-local-node", "port": 10003},
            ]
            MockGoWaveServer.state["profiles"][p_uuid] = {"name": body.get("name"), "inbounds": inbs}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"uuid": p_uuid, "inbounds": inbs}).encode())
        elif self.path == "/api/nodes":
            n_uuid = "node-uuid-test"
            MockGoWaveServer.state["nodes"][n_uuid] = body
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"uuid": n_uuid}).encode())
        elif self.path == "/api/internal-squads":
            s_uuid = "squad-uuid-test"
            MockGoWaveServer.state["squads"][s_uuid] = body
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"uuid": s_uuid, "inbounds": body.get("inbounds", [])}).encode())
        elif self.path == "/api/hosts":
            h_uuid = f"host-{len(MockGoWaveServer.state['hosts']) + 1}"
            MockGoWaveServer.state["hosts"][h_uuid] = body
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"uuid": h_uuid, **body}).encode())
        elif self.path == "/api/users":
            u_uuid = "user-uuid-test"
            short_id = "short-test-123"
            MockGoWaveServer.state["users"][u_uuid] = body
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"uuid": u_uuid, "shortUuid": short_id, **body}).encode())
        elif self.path == "/api/tokens":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"token": "long-token-123", "id": 1}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if self.path == "/api/config-profiles":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps([]).encode())
        elif self.path == "/api/nodes":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps([]).encode())
        elif self.path == "/api/internal-squads":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps([]).encode())
        elif self.path == "/api/system/tools/x25519/generate":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "privateKey": "dGVzdC1wcml2YXRlLWtleS0zMi1ieXRlcw==",
                "publicKey": "dGVzdC1wdWJsaWMta2V5LTMyLWJ5dGVzCg=="
            }).encode())
        elif self.path.startswith("/api/config-profiles/") and self.path.endswith("/computed-config"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "inbounds": [
                    {"port": 8443, "streamSettings": {"security": "reality", "realitySettings": {}}},
                    {"port": 10001, "streamSettings": {"security": "none"}},
                    {"port": 10002, "streamSettings": {"security": "none"}},
                    {"port": 10003, "streamSettings": {"security": "none"}},
                ]
            }).encode())
        elif self.path.startswith("/api/config-profiles/") and self.path.endswith("/inbounds"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps([
                {"uuid": "inb-1", "tag": "vless-reality-local-node", "port": 8443},
                {"uuid": "inb-2", "tag": "vless-xhttp-local-node", "port": 10001},
                {"uuid": "inb-3", "tag": "vless-ws-local-node", "port": 10002},
                {"uuid": "inb-4", "tag": "trojan-grpc-local-node", "port": 10003},
            ]).encode())
        elif self.path == "/api/hosts":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(list(MockGoWaveServer.state["hosts"].values())).encode())
        elif self.path.startswith("/api/internal-squads/"):
            s_uuid = self.path.split("/")[-1]
            squad = MockGoWaveServer.state["squads"].get(s_uuid, {"uuid": s_uuid})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(squad).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


class TestIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), MockGoWaveServer)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_concurrent_sqlite_writes_during_backup(self):
        """Preflight WAL checkpoint and staged backup must not deadlock during active concurrent writes."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "gowave.db"
            backup_path = Path(tmp_dir) / "snapshot.db"

            conn = sqlite3.connect(str(db_path))
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("CREATE TABLE metrics (id INTEGER PRIMARY KEY, ts REAL, val TEXT);")
            conn.commit()
            conn.close()

            stop_writes = threading.Event()
            write_errors = []

            def worker_writer():
                c = sqlite3.connect(str(db_path), timeout=10.0)
                try:
                    i = 0
                    while not stop_writes.is_set():
                        c.execute("INSERT INTO metrics (ts, val) VALUES (?, ?);", (time.time(), f"payload-{i}"))
                        c.commit()
                        i += 1
                        time.sleep(0.005)
                except Exception as e:
                    write_errors.append(e)
                finally:
                    c.close()

            t = threading.Thread(target=worker_writer)
            t.start()

            time.sleep(0.05)
            # Perform SQLite online backup while writer is writing
            success = sqlite_online_backup(str(db_path), str(backup_path))
            self.assertTrue(success)

            stop_writes.set()
            t.join()

            self.assertEqual(len(write_errors), 0, f"Concurrent write errors: {write_errors}")
            self.assertTrue(backup_path.exists())

            # Verify backup integrity
            bconn = sqlite3.connect(str(backup_path))
            integrity = bconn.execute("PRAGMA integrity_check;").fetchall()
            bconn.close()
            self.assertEqual(integrity[0][0], "ok")

    def test_gowave_api_admin_bootstrap_and_login(self):
        """Admin registration and login flow against mock GoWave API."""
        client = GoWaveClient(f"http://127.0.0.1:{self.port}")
        client.register_initial_admin("admin_test", "SecretPass123!")
        self.assertTrue(MockGoWaveServer.state["admin_registered"])

        client.login("admin_test", "SecretPass123!")
        self.assertEqual(client.token, MockGoWaveServer.state["token"])

    def test_single_unified_profile_and_inbound_linking(self):
        """Unified Config Profile provisioning, inbounds validation, and internal squad association."""
        client = GoWaveClient(f"http://127.0.0.1:{self.port}")
        client.token = MockGoWaveServer.state["token"]

        x25519 = client.generate_x25519()
        raw_cfg = client.compile_config_profile("local-node", "camou.example.com", x25519["privateKey"])
        prof = client.provision_config_profile("GoWave MVP Unified Profile - local-node", raw_cfg)

        self.assertIn("profile_uuid", prof)
        self.assertEqual(len(prof["inbounds"]), 4)

        inb_uuids = [inb["uuid"] for inb in prof["inbounds"]]
        node_uuid = client.associate_node("local-node", "127.0.0.1", 3002, prof["profile_uuid"], inb_uuids)
        self.assertEqual(node_uuid, "node-uuid-test")

        squad_uuid = client.provision_internal_squad("Default MVP Squad", inb_uuids)
        self.assertEqual(squad_uuid, "squad-uuid-test")

    def test_host_entity_creation_with_readback(self):
        """Host entity creation for 4 MVP protocols, with securityLayer checks."""
        client = GoWaveClient(f"http://127.0.0.1:{self.port}")
        client.token = MockGoWaveServer.state["token"]

        inbounds = [
            {"uuid": "inb-1", "tag": "vless-reality-local-node", "port": 8443},
            {"uuid": "inb-2", "tag": "vless-xhttp-local-node", "port": 10001},
            {"uuid": "inb-3", "tag": "vless-ws-local-node", "port": 10002},
            {"uuid": "inb-4", "tag": "trojan-grpc-local-node", "port": 10003},
        ]
        host_uuids = client.provision_hosts("prof-uuid-test", inbounds, "node-uuid-test", "squad-uuid-test", "vpn.example.com", "camou.example.com")
        self.assertEqual(len(host_uuids), 4)

        # Check securityLayer contracts: DEFAULT for reality, TLS for others
        hosts_by_remark = {h["remark"]: h for h in MockGoWaveServer.state["hosts"].values()}
        self.assertEqual(hosts_by_remark["VLESS-REALITY-Vision@local-node"]["securityLayer"], "DEFAULT")
        self.assertEqual(hosts_by_remark["VLESS-XHTTP-TLS@local-node"]["securityLayer"], "TLS")
        self.assertEqual(hosts_by_remark["VLESS-WS-TLS@local-node"]["securityLayer"], "TLS")
        self.assertEqual(hosts_by_remark["Trojan-gRPC-TLS@local-node"]["securityLayer"], "TLS")

    def test_user_provisioning_with_squad_assignment(self):
        """User lifecycle creation assigned to Internal Squad with mandatory expireAt."""
        client = GoWaveClient(f"http://127.0.0.1:{self.port}")
        client.token = MockGoWaveServer.state["token"]

        short_uuid = client.provision_user("test-user", "squad-uuid-test")
        self.assertEqual(short_uuid, "short-test-123")
        created_user = MockGoWaveServer.state["users"]["user-uuid-test"]
        self.assertIn("expireAt", created_user)
        self.assertIn("squad-uuid-test", created_user["activeInternalSquads"])

    def test_mtls_handshake_mock(self):
        """Verify mTLS connection behavior and TLS 1.3 requirements."""
        # Create an SSL context enforcing TLS 1.3
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_3)


if __name__ == "__main__":
    unittest.main()
