#!/usr/bin/env python3
"""Unit tests for deployment observer parser and panel_api / api_client extensions."""
from __future__ import annotations

import http.server
import json
import os
import shlex
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
from unittest.mock import MagicMock, patch
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT))

from live_vps.deployment import parse_strace_argv_output, output_matches_pinned_version
from live_vps.panel_api import E2EPanelClient, read_master_credentials
from live_vps.mtls import run_mtls_negative_tests
from live_vps.nginx import verify_panel_https
from live_vps.subscriptions import verify_user_agent_policy
from live_vps.ssh import SSHResult
from modules.api_client import GoWaveClient, GoWaveAPIError
from live_vps.redaction import clear_secrets


class MockServerHandler(http.server.BaseHTTPRequestHandler):
    seen_subscription_user_agents = []

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8")
        if self.path == "/api/auth/login":
            data = json.loads(body)
            if data.get("username") == "admin" and data.get("password") == "correct":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"accessToken": "mock-jwt-token-12345"}).encode("utf-8"))
                return
            else:
                self.send_response(401)
                self.end_headers()
                return
        self.send_response(404)
        self.end_headers()

    def do_GET(self):
        if self.path.startswith("/api/sub/"):
            user_agent = self.headers.get("User-Agent")
            type(self).seen_subscription_user_agents.append(user_agent)
            self.send_response(403 if user_agent in (None, "") else 200)
            self.end_headers()
            return
        if self.path == "/api/slow":
            time.sleep(2)
            self.send_response(200)
            self.end_headers()
            return
        if self.path == "/api/nodes":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps([{"name": "worker-1", "isConnected": True}]).encode("utf-8"))
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        pass


class TestDeploymentAndPanelAPI(unittest.TestCase):
    def setUp(self):
        clear_secrets()

    def tearDown(self):
        clear_secrets()

    def test_bootstrap_acme_nginx_failures_trigger_lineage_rollback(self):
        """Bootstrap generation and activation failures must enter the ACME rollback path."""
        script = (REPO_ROOT / "gowave-auto.sh").read_text()
        install_start = script.index("cmd_install() {")
        install_end = script.index("\n}\n", install_start)
        install = script[install_start:install_end]

        generate_failure = install.index("if ! generate_bootstrap_acme_vhost")
        reload_failure = install.index("if ! reload_nginx_strict", generate_failure)
        certbot_step = install.index("if ! command -v certbot", reload_failure)
        bootstrap = install[generate_failure:certbot_step]

        self.assertIn("rollback_acme_lineages", bootstrap)
        self.assertIn("Failed to generate bootstrap ACME NGINX configuration", bootstrap)
        self.assertIn("Failed to activate bootstrap ACME NGINX configuration", bootstrap)
        self.assertIn("return 1", bootstrap)
        self.assertEqual(bootstrap.count("generate_bootstrap_acme_vhost"), 1)
        self.assertEqual(bootstrap.count("reload_nginx_strict"), 1)

    def test_pinned_version_match_requires_exact_token(self):
        self.assertTrue(output_matches_pinned_version("GoWave Server v0.4.0", "0.4.0"))
        self.assertTrue(output_matches_pinned_version("Xray 25.10.15 (Xray, Penetrates Everything.)", "25.10.15"))
        self.assertFalse(output_matches_pinned_version("GoWave Server v0.4.10", "0.4.1"))
        self.assertFalse(output_matches_pinned_version("version output unavailable", "0.4.0"))

    @classmethod
    def setUpClass(cls):
        # Generate temporary CA and server cert/key for localhost
        cls.td = tempfile.TemporaryDirectory()
        td_path = Path(cls.td.name)
        cls.ca_key = td_path / "ca.key"
        cls.ca_crt = td_path / "ca.crt"
        cls.srv_key = td_path / "srv.key"
        cls.srv_crt = td_path / "srv.crt"
        cls.untrusted_ca = td_path / "untrusted_ca.crt"

        # Generate CA with proper basicConstraints and keyUsage
        subprocess.run(
            ["openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(cls.ca_key), "-out", str(cls.ca_crt),
             "-days", "1", "-subj", "/CN=TestLiveVPSCA",
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
            capture_output=True, check=True
        )
        # Generate Untrusted CA
        subprocess.run(
            ["openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(td_path / "u.key"), "-out", str(cls.untrusted_ca),
             "-days", "1", "-subj", "/CN=UntrustedCA",
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
            capture_output=True, check=True
        )
        # Generate Server cert with SAN for localhost only
        csr = td_path / "srv.csr"
        ext_conf = td_path / "ext.cnf"
        ext_conf.write_text("subjectAltName=DNS:localhost\n")
        subprocess.run(
            ["openssl", "req", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(cls.srv_key), "-out", str(csr),
             "-subj", "/CN=localhost"],
            capture_output=True, check=True
        )
        subprocess.run(
            ["openssl", "x509", "-req", "-in", str(csr), "-CA", str(cls.ca_crt),
             "-CAkey", str(cls.ca_key), "-CAcreateserial", "-out", str(cls.srv_crt),
             "-days", "1", "-extfile", str(ext_conf)],
            capture_output=True, check=True
        )

        # Start HTTPS server
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), MockServerHandler)
        cls.port = cls.server.server_port
        ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_ctx.load_cert_chain(certfile=str(cls.srv_crt), keyfile=str(cls.srv_key))
        cls.server.socket = ssl_ctx.wrap_socket(cls.server.socket, server_side=True)

        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.td.cleanup()

    def test_parse_strace_argv_clean(self):
        trace = """
1000 execve("/usr/bin/ssh", ["ssh", "-p", "22", "root@198.51.100.2", "bash -s"], ["PATH=/usr/bin", "USER=root"]) = 0
1001 execveat(AT_FDCWD, "/usr/bin/curl", ["curl", "-fsSL", "https://example.com"], ["PATH=/usr/bin"]) = 0
"""
        res = parse_strace_argv_output(trace, secrets=["SecretKey123"])
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["exec_count"], 2)
        self.assertFalse(res["secret_found"])
        self.assertFalse(res["truncated"])
        self.assertFalse(res["abbreviated"])

    def test_parse_strace_argv_secret_detected(self):
        trace = """
1000 execve("/usr/bin/python3", ["python3", "-c", "SECRET_KEY='SuperSecretMasterKey'"], ["PATH=/usr/bin"]) = 0
"""
        res = parse_strace_argv_output(trace, secrets=["SuperSecretMasterKey"])
        self.assertEqual(res["status"], "FAIL")
        self.assertTrue(res["secret_found"])

    def test_parse_strace_argv_truncated_string_fixture(self):
        # Fixture (a): string truncated with '...' after byte 32
        sentinel = "SENTINEL_AFTER_BYTE_32_TEST_MARKER"
        long_arg = "A" * 32 + sentinel
        trace_truncated = f'1000 execve("/bin/test", ["test", "{"A"*32}"...], ["PATH=/bin"]) = 0\n'

        res = parse_strace_argv_output(trace_truncated, secrets=["SecretKey123"])
        self.assertEqual(res["status"], "INCOMPLETE")
        self.assertTrue(res["truncated"])

        # When complete with positive -s
        trace_complete = f'1000 execve("/bin/test", ["test", "{long_arg}"], ["PATH=/bin"]) = 0\n'
        res_complete = parse_strace_argv_output(trace_complete, secrets=["SecretKey123"])
        self.assertEqual(res_complete["status"], "PASS")
        self.assertFalse(res_complete["truncated"])

    def test_parse_strace_argv_execveat_truncated(self):
        trace_truncated = '1001 execveat(AT_FDCWD, "/bin/test", ["test", "arg"...], ["ENV=1"]) = 0\n'
        res = parse_strace_argv_output(trace_truncated, secrets=["SecretKey123"])
        self.assertEqual(res["status"], "INCOMPLETE")
        self.assertTrue(res["truncated"])

    def test_parse_strace_argv_128_elements_fixture(self):
        # Fixture (b): 128 elements, sentinel only in final element
        elements = [f'"arg{i}"' for i in range(127)] + ['"FINAL_SENTINEL_MARKER"']
        trace_complete = f'1000 execve("/bin/test", [{", ".join(elements)}], ["PATH=/bin"]) = 0\n'
        res = parse_strace_argv_output(trace_complete, secrets=["SecretKey123"])
        self.assertEqual(res["status"], "PASS")
        self.assertFalse(res["abbreviated"])

        # Abbreviated array: strace replaced later elements with '...'
        elements_abbrev = [f'"arg{i}"' for i in range(32)] + ["..."]
        trace_abbrev = f'1000 execve("/bin/test", [{", ".join(elements_abbrev)}], ["PATH=/bin"]) = 0\n'
        res_abbrev = parse_strace_argv_output(trace_abbrev, secrets=["SecretKey123"])
        self.assertEqual(res_abbrev["status"], "INCOMPLETE")
        self.assertTrue(res_abbrev["abbreviated"])

    def test_parse_strace_argv_envp_isolation(self):
        # If secret is in envp only, argv observer ignores it (envp discarded)
        trace_envp_only = '1000 execve("/bin/test", ["test", "--flag"], ["SECRET_KEY=OnlyInEnvp"]) = 0\n'
        res = parse_strace_argv_output(trace_envp_only, secrets=["OnlyInEnvp"])
        self.assertEqual(res["status"], "PASS")
        self.assertFalse(res["secret_found"])

    def test_master_credentials_are_read_through_stdin_safe_ssh_and_registered(self):
        ssh = MagicMock()
        ssh.run.return_value = SSHResult(
            returncode=0,
            stdout="\n".join([
                "ADMIN_USERNAME=admin",
                "ADMIN_PASSWORD=SensitivePassword123",
                "SCOPED_API_TOKEN=ScopedToken123",
            ]) + "\n",
            stderr="",
        )
        values = read_master_credentials(ssh)
        self.assertEqual(values["ADMIN_USERNAME"], "admin")
        self.assertEqual(values["ADMIN_PASSWORD"], "SensitivePassword123")
        command = ssh.run.call_args.args[0]
        self.assertIn("test ! -L", command)
        self.assertIn("regular file:600:0", command)
        self.assertNotIn("SensitivePassword123", command)

    def test_master_credentials_reject_bad_remote_file_metadata(self):
        ssh = MagicMock()
        ssh.run.return_value = SSHResult(returncode=1, stdout="", stderr="metadata mismatch")
        with self.assertRaises(GoWaveAPIError):
            read_master_credentials(ssh)
    @patch("live_vps.subscriptions.urllib.request.urlopen", side_effect=urllib.error.URLError("temporary transport failure"))
    @patch("live_vps.subscriptions.request_subscription_status", side_effect=[200, TimeoutError("blank UA probe timed out")])
    def test_user_agent_proven_policy_violation_beats_other_incomplete_probes(
        self, request_status, urlopen
    ):
        trusted_ctx = ssl.create_default_context(cafile=str(self.ca_crt))
        result = verify_user_agent_policy(
            f"localhost:{self.port}", "opaque-short-uuid", trusted_ctx
        )
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["absent_code"], 200)
        self.assertIsNone(result["blank_code"])
        self.assertIsNone(result["xray_code"])
        self.assertIsNone(result["mihomo_code"])

    @patch("live_vps.subscriptions.urllib.request.urlopen", side_effect=urllib.error.URLError("temporary transport failure"))
    @patch("live_vps.subscriptions.request_subscription_status", return_value=403)
    def test_user_agent_transport_uncertainty_is_incomplete_without_proven_violation(
        self, request_status, urlopen
    ):
        trusted_ctx = ssl.create_default_context(cafile=str(self.ca_crt))
        result = verify_user_agent_policy(
            f"localhost:{self.port}", "opaque-short-uuid", trusted_ctx
        )
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertTrue(result["absent_rejected"])
        self.assertTrue(result["blank_rejected"])
        self.assertIsNone(result["xray_code"])
        self.assertIsNone(result["mihomo_code"])

    def test_subscription_policy_sends_absent_and_blank_user_agent(self):
        trusted_ctx = ssl.create_default_context(cafile=str(self.ca_crt))
        MockServerHandler.seen_subscription_user_agents.clear()
        result = verify_user_agent_policy(
            f"localhost:{self.port}", "opaque-short-uuid", trusted_ctx
        )
        self.assertEqual(result["status"], "PASS")
        seen = MockServerHandler.seen_subscription_user_agents
        self.assertIn(None, seen)
        self.assertIn("", seen)
        self.assertIn("v2rayNG/1.8.5", seen)
        self.assertIn("clash.meta", seen)

    def test_panel_https_verifier_rejects_502(self):
        trusted_ctx = ssl.create_default_context(cafile=str(self.ca_crt))
        error = urllib.error.HTTPError(
            f"https://localhost:{self.port}/api/nodes", 502, "Bad Gateway", {}, None
        )
        with patch("live_vps.nginx.urllib.request.urlopen", side_effect=error):
            result = verify_panel_https(f"localhost:{self.port}", trusted_ctx)
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["http_status"], 502)

    def test_panel_https_verifier_accepts_panel_api(self):
        trusted_ctx = ssl.create_default_context(cafile=str(self.ca_crt))
        result = verify_panel_https(f"localhost:{self.port}", trusted_ctx)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["http_status"], 200)

    def test_mtls_negative_runner_sends_only_secret_on_stdin(self):
        ssh = MagicMock()
        secret = "base64-secret-payload"
        ssh.run.side_effect = [
            SSHResult(returncode=0, stdout=secret, stderr=""),
            SSHResult(
                returncode=0,
                stdout=json.dumps({
                    "untrusted_client_rejected": True,
                    "absent_client_rejected": True,
                    "mismatched_crypto_failed": True,
                    "untrusted_ca_rejected": True,
                    "wrong_sni_observation": {"outcome": "TLS_REJECTED", "error": "SSLError"},
                }),
                stderr="",
            ),
        ]

        result = run_mtls_negative_tests(ssh, "203.0.113.20")
        self.assertEqual(result["status"], "PASS")
        command = ssh.run.call_args.args[0]
        self.assertTrue(command.startswith("python3 -c "))
        # Compile the exact remote source after shell unquoting; import-time
        # tests cannot detect broken escaping inside the generated script.
        remote_argv = shlex.split(command)
        self.assertEqual(remote_argv[:2], ["python3", "-c"])
        compile(remote_argv[2], "<remote-mtls-negative-probe>", "exec")
        self.assertNotIn(secret, command)
        self.assertEqual(ssh.run.call_args.kwargs["input_data"], secret)

    def test_mtls_wrong_sni_http_routing_does_not_require_tls_alert(self):
        ssh = MagicMock()
        ssh.run.side_effect = [
            SSHResult(returncode=0, stdout="base64-secret", stderr=""),
            SSHResult(returncode=0, stdout=json.dumps({
                "untrusted_client_rejected": True,
                "absent_client_rejected": True,
                "mismatched_crypto_failed": True,
                "untrusted_ca_rejected": True,
                "wrong_sni_observation": {
                    "outcome": "HTTP_RESPONSE",
                    "version": "TLSv1.3",
                    "status_line": "HTTP/1.1 421 Misdirected Request",
                },
            }), stderr=""),
        ]
        result = run_mtls_negative_tests(ssh, "203.0.113.20")
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["wrong_sni_observation"]["outcome"], "HTTP_RESPONSE")

    def test_mtls_wrong_sni_tls_without_routing_response_is_incomplete(self):
        ssh = MagicMock()
        ssh.run.side_effect = [
            SSHResult(returncode=0, stdout="base64-secret", stderr=""),
            SSHResult(returncode=0, stdout=json.dumps({
                "untrusted_client_rejected": True,
                "absent_client_rejected": True,
                "mismatched_crypto_failed": True,
                "untrusted_ca_rejected": True,
                "wrong_sni_observation": {"outcome": "INCOMPLETE", "error": "no response"},
            }), stderr=""),
        ]
        result = run_mtls_negative_tests(ssh, "203.0.113.20")
        self.assertEqual(result["status"], "INCOMPLETE")

    def test_mtls_failed_required_check_cannot_be_overridden_by_wrong_sni(self):
        ssh = MagicMock()
        ssh.run.side_effect = [
            SSHResult(returncode=0, stdout="base64-secret", stderr=""),
            SSHResult(returncode=0, stdout=json.dumps({
                "untrusted_client_rejected": False,
                "absent_client_rejected": True,
                "mismatched_crypto_failed": True,
                "untrusted_ca_rejected": True,
                "wrong_sni_observation": {"outcome": "TLS_REJECTED"},
            }), stderr=""),
        ]
        result = run_mtls_negative_tests(ssh, "203.0.113.20")
        self.assertEqual(result["status"], "FAIL")

    def test_mtls_malformed_wrong_sni_result_is_incomplete(self):
        ssh = MagicMock()
        ssh.run.side_effect = [
            SSHResult(returncode=0, stdout="base64-secret", stderr=""),
            SSHResult(returncode=0, stdout=json.dumps({
                "untrusted_client_rejected": True,
                "absent_client_rejected": True,
                "mismatched_crypto_failed": True,
                "untrusted_ca_rejected": True,
                "wrong_sni_observation": None,
            }), stderr=""),
        ]
        result = run_mtls_negative_tests(ssh, "203.0.113.20")
        self.assertEqual(result["status"], "INCOMPLETE")

    def test_mtls_negative_transport_failure_is_incomplete(self):
        ssh = MagicMock()
        ssh.run.side_effect = [
            SSHResult(returncode=0, stdout="base64-secret", stderr=""),
            SSHResult(returncode=255, stdout="", stderr="Connection timed out"),
        ]
        result = run_mtls_negative_tests(ssh, "203.0.113.20")
        self.assertEqual(result["status"], "INCOMPLETE")

    def test_gowave_client_constructor_extensions(self):
        ctx = ssl.create_default_context()
        client = GoWaveClient(base_url="https://panel.example.com", ssl_context=ctx, timeout=42)
        self.assertEqual(client.base_url, "https://panel.example.com")
        self.assertEqual(client.ssl_context, ctx)
        self.assertEqual(client.timeout, 42)

    def test_panel_client_trusted_ca_success(self):
        trusted_ctx = ssl.create_default_context(cafile=str(self.ca_crt))
        panel_client = E2EPanelClient(panel_domain=f"localhost:{self.port}", ssl_context=trusted_ctx, timeout=5)
        token = panel_client.login("admin", "correct")
        self.assertEqual(token, "mock-jwt-token-12345")
        self.assertTrue(panel_client.poll_worker_ready("worker-1", timeout=5, poll_interval=1))

    def test_panel_client_worker_poll_returns_false_at_deadline(self):
        trusted_ctx = ssl.create_default_context(cafile=str(self.ca_crt))
        panel_client = E2EPanelClient(
            panel_domain=f"localhost:{self.port}",
            ssl_context=trusted_ctx,
            timeout=5,
        )
        with (
            patch.object(panel_client, "get_nodes", return_value=[
                {"name": "worker-1", "isConnected": False}
            ]) as get_nodes,
            patch("live_vps.panel_api.time.time", side_effect=[0.0, 1.0, 6.0]),
            patch("live_vps.panel_api.time.sleep") as sleep,
        ):
            self.assertFalse(
                panel_client.poll_worker_ready(
                    "worker-1", timeout=5, poll_interval=1
                )
            )

        get_nodes.assert_called_once_with()
        sleep.assert_called_once_with(1)

    def test_panel_client_untrusted_ca_rejection(self):
        untrusted_ctx = ssl.create_default_context(cafile=str(self.untrusted_ca))
        panel_client = E2EPanelClient(panel_domain=f"localhost:{self.port}", ssl_context=untrusted_ctx, timeout=5)
        with self.assertRaises(GoWaveAPIError) as cm:
            panel_client.login("admin", "correct")
        err_str = str(cm.exception).lower()
        self.assertIn("tls verification error", err_str)
        self.assertNotIn("certificate verify failed", err_str)

    def test_panel_client_hostname_verification(self):
        trusted_ctx = ssl.create_default_context(cafile=str(self.ca_crt))
        # Point to wrong hostname that is not in SAN (127.0.0.1 while SAN has localhost only)
        panel_client = E2EPanelClient(panel_domain=f"127.0.0.1:{self.port}", ssl_context=trusted_ctx, timeout=5)
        with self.assertRaises(GoWaveAPIError) as cm:
            panel_client.login("admin", "correct")
        err_str = str(cm.exception).lower()
        self.assertIn("tls verification error", err_str)
        self.assertNotIn("127.0.0.1", err_str)

    def test_panel_client_malformed_login_response_does_not_echo_payload(self):
        marker = "panel-login-secret-payload"
        panel_client = E2EPanelClient(
            panel_domain=f"localhost:{self.port}",
            ssl_context=ssl.create_default_context(cafile=str(self.ca_crt)),
            timeout=5,
        )
        with patch.object(panel_client.client, "request", return_value={"response": {"error": marker}}):
            with self.assertRaises(GoWaveAPIError) as ctx:
                panel_client.login("admin", "correct")
        self.assertNotIn(marker, str(ctx.exception))

    def test_panel_client_invalid_user_response_does_not_echo_payload(self):
        marker = "panel-user-secret-payload"
        panel_client = E2EPanelClient(
            panel_domain=f"localhost:{self.port}",
            ssl_context=ssl.create_default_context(cafile=str(self.ca_crt)),
            timeout=5,
        )
        with patch.object(panel_client.client, "request", return_value={"response": marker}):
            with self.assertRaises(GoWaveAPIError) as ctx:
                panel_client.get_user_by_username("admin")
        self.assertNotIn(marker, str(ctx.exception))

    def test_panel_client_timeout_propagation(self):
        trusted_ctx = ssl.create_default_context(cafile=str(self.ca_crt))
        panel_client = E2EPanelClient(panel_domain=f"localhost:{self.port}", ssl_context=trusted_ctx, timeout=1)
        with self.assertRaises(Exception):
            panel_client.client.request("GET", "/api/slow", authenticate=False)


if __name__ == "__main__":
    unittest.main()
