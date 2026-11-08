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
import socket
import sqlite3
import ssl
import subprocess
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
                {"uuid": "inb-2", "tag": "vless-vision-local-node", "port": 8444},
                {"uuid": "inb-3", "tag": "vless-xhttp-local-node", "port": 10001},
                {"uuid": "inb-4", "tag": "vless-ws-local-node", "port": 10002},
                {"uuid": "inb-5", "tag": "trojan-grpc-local-node", "port": 10003},
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
            self.close_connection = True
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if self.path == "/api/config-profiles":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"response": {"configProfiles": []}}).encode())
        elif self.path == "/api/nodes":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"response": {"nodes": []}}).encode())
        elif self.path == "/api/internal-squads":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"response": {"internalSquads": []}}).encode())
        elif self.path == "/api/system/tools/x25519/generate":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "response": {
                    "keypairs": [{
                        "privateKey": "dGVzdC1wcml2YXRlLWtleS0zMi1ieXRlcw==",
                        "publicKey": "dGVzdC1wdWJsaWMta2V5LTMyLWJ5dGVzCg=="
                    }]
                }
            }).encode())
        elif self.path.startswith("/api/config-profiles/") and self.path.endswith("/computed-config"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            cfg_obj = {
                "inbounds": [
                    {"port": 8443, "streamSettings": {"security": "reality", "realitySettings": {}}},
                    {"port": 8444, "streamSettings": {"security": "tls"}},
                    {"port": 10001, "streamSettings": {"security": "none"}},
                    {"port": 10002, "streamSettings": {"security": "none"}},
                    {"port": 10003, "streamSettings": {"security": "none"}},
                ]
            }
            self.wfile.write(json.dumps({
                "response": {
                    "uuid": "prof-uuid-test",
                    "name": "mock-profile",
                    "config": json.dumps(cfg_obj)
                }
            }).encode())
        elif self.path.startswith("/api/config-profiles/") and self.path.endswith("/inbounds"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps([
                {"uuid": "inb-1", "tag": "vless-reality-local-node", "port": 8443},
                {"uuid": "inb-2", "tag": "vless-vision-local-node", "port": 8444},
                {"uuid": "inb-3", "tag": "vless-xhttp-local-node", "port": 10001},
                {"uuid": "inb-4", "tag": "vless-ws-local-node", "port": 10002},
                {"uuid": "inb-5", "tag": "trojan-grpc-local-node", "port": 10003},
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
            self.close_connection = True
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
        self.assertEqual(len(prof["inbounds"]), 5)

        inb_uuids = [inb["uuid"] for inb in prof["inbounds"]]
        node_uuid = client.associate_node("local-node", "127.0.0.1", 3002, prof["profile_uuid"], inb_uuids)
        self.assertEqual(node_uuid, "node-uuid-test")

        squad_uuid = client.provision_internal_squad("Default MVP Squad", inb_uuids)
        self.assertEqual(squad_uuid, "squad-uuid-test")

    def test_host_entity_creation_with_readback(self):
        """Host entity creation for 5 MVP protocols, with securityLayer checks."""
        client = GoWaveClient(f"http://127.0.0.1:{self.port}")
        client.token = MockGoWaveServer.state["token"]

        inbounds = [
            {"uuid": "inb-1", "tag": "vless-reality-local-node", "port": 8443},
            {"uuid": "inb-2", "tag": "vless-vision-local-node", "port": 8444},
            {"uuid": "inb-3", "tag": "vless-xhttp-local-node", "port": 10001},
            {"uuid": "inb-4", "tag": "vless-ws-local-node", "port": 10002},
            {"uuid": "inb-5", "tag": "trojan-grpc-local-node", "port": 10003},
        ]
        host_uuids = client.provision_hosts("prof-uuid-test", inbounds, "node-uuid-test", "squad-uuid-test", "vpn.example.com", "camou.example.com")
        self.assertEqual(len(host_uuids), 5)

        # Check securityLayer contracts: DEFAULT for reality, TLS for others
        hosts_by_remark = {h["remark"]: h for h in MockGoWaveServer.state["hosts"].values()}
        self.assertEqual(hosts_by_remark["VLESS-REALITY-Vision@local-node"]["securityLayer"], "DEFAULT")
        self.assertEqual(hosts_by_remark["VLESS-Vision-TLS@local-node"]["securityLayer"], "TLS")
        self.assertEqual(hosts_by_remark["VLESS-XHTTP-TLS@local-node"]["securityLayer"], "TLS")
        self.assertEqual(hosts_by_remark["VLESS-WS-TLS@local-node"]["securityLayer"], "TLS")
        self.assertEqual(hosts_by_remark["Trojan-gRPC-TLS@local-node"]["securityLayer"], "TLS")

        for h in hosts_by_remark.values():
            self.assertEqual(h["fingerprint"], "firefox")

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
        """Verify mutual TLS 1.3 handshake with HKDF-derived SNI and client certificate verification."""
        from modules.verify_node_mtls import derive_sni, perform_mtls_handshake

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ca_key = tmp / "ca.key"
            ca_crt = tmp / "ca.crt"
            node_key = tmp / "node.key"
            node_csr = tmp / "node.csr"
            node_crt = tmp / "node.crt"
            jwt_key = tmp / "jwt.key"
            jwt_pub = tmp / "jwt.pub"

            # Generate CA (ECDSA P-256)
            subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(ca_key)],
                           check=True, stderr=subprocess.DEVNULL)
            subprocess.run(["openssl", "req", "-x509", "-new", "-key", str(ca_key), "-out", str(ca_crt),
                            "-days", "365", "-subj", "/CN=IntegrationCA"], check=True, stderr=subprocess.DEVNULL)

            # Generate Node cert signed by CA
            subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(node_key)],
                           check=True, stderr=subprocess.DEVNULL)
            subprocess.run(["openssl", "req", "-new", "-key", str(node_key), "-out", str(node_csr),
                            "-subj", "/CN=IntegrationNode"], check=True, stderr=subprocess.DEVNULL)
            subprocess.run(["openssl", "x509", "-req", "-in", str(node_csr), "-CA", str(ca_crt),
                            "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(node_crt), "-days", "365"],
                           check=True, stderr=subprocess.DEVNULL)

            # Generate RSA JWT public key
            subprocess.run(["openssl", "genrsa", "-out", str(jwt_key), "2048"], check=True, stderr=subprocess.DEVNULL)
            subprocess.run(["openssl", "rsa", "-in", str(jwt_key), "-pubout", "-out", str(jwt_pub)],
                           check=True, stderr=subprocess.DEVNULL)

            ca_pem = ca_crt.read_text()
            jwt_pub_pem = jwt_pub.read_text()
            node_cert_pem = node_crt.read_text()
            node_key_pem = node_key.read_text()

            # Derive exact HKDF SNI
            expected_sni = derive_sni(ca_pem, jwt_pub_pem)
            self.assertTrue(expected_sni.endswith((".com", ".net", ".org", ".io", ".dev", ".app")))

            # Start real TLS 1.3 server requiring client certificate and verifying SNI
            server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            server_ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            server_ctx.load_cert_chain(str(node_crt), str(node_key))
            server_ctx.load_verify_locations(str(ca_crt))
            server_ctx.verify_mode = ssl.CERT_REQUIRED

            sni_seen = []
            def sni_callback(ssl_sock, server_name, initial_context):
                sni_seen.append(server_name)
                if server_name != expected_sni:
                    return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
                return None
            server_ctx.sni_callback = sni_callback

            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.bind(("127.0.0.1", 0))
            server_sock.listen(1)
            port = server_sock.getsockname()[1]

            def run_server():
                try:
                    raw_conn, _ = server_sock.accept()
                    conn = server_ctx.wrap_socket(raw_conn, server_side=True)
                    data = conn.recv(1024)
                    if b"GET /node/xray/healthcheck" in data:
                        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 22\r\n\r\n{\"response\":{\"ok\":true}}")
                    conn.close()
                except Exception:
                    pass
                finally:
                    server_sock.close()

            t = threading.Thread(target=run_server)
            t.daemon = True
            t.start()

            # Execute real mTLS 1.3 handshake with perform_mtls_handshake
            res = perform_mtls_handshake("127.0.0.1", port, expected_sni, ca_pem, node_cert_pem, node_key_pem)
            self.assertEqual(res["tls_version"], "TLSv1.3")
            self.assertIn("200 OK", res["status_line"])
            self.assertEqual(sni_seen, [expected_sni])
            t.join(timeout=2.0)


if __name__ == "__main__":
    unittest.main()
