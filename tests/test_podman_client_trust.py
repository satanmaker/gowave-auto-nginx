#!/usr/bin/env python3
"""Suite nonroot: the fixture CA is trusted per client without global changes."""
import json
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import acme_fixture, client_trust  # noqa: E402

ECHO_SERVER = REPO_ROOT / "tests" / "fixtures" / "echo_server.py"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def tls_outbound(tag="proxy-tls"):
    return {
        "tag": tag,
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": "worker.testbed.internal",
                "port": 443,
                "users": [{"id": "4e1f6c62-0f6e-4f2b-9f0a-2b9f0f1d3c11", "encryption": "none"}],
            }],
        },
        "streamSettings": {"network": "ws", "security": "tls", "tlsSettings": {"serverName": "worker.testbed.internal"}},
    }


def reality_outbound(tag="proxy-reality"):
    return {
        "tag": tag,
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": "worker.testbed.internal",
                "port": 443,
                "users": [{"id": "4e1f6c62-0f6e-4f2b-9f0a-2b9f0f1d3c11", "encryption": "none", "flow": "xtls-rprx-vision"}],
            }],
        },
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {"serverName": "cover.testbed.internal", "publicKey": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"},
        },
    }


def sample_config():
    return {
        "inbounds": [{"tag": "socks", "port": 1080, "protocol": "socks"}],
        "outbounds": [
            tls_outbound("proxy-ws"),
            tls_outbound("proxy-xhttp"),
            reality_outbound(),
            {"tag": "direct", "protocol": "freedom"},
        ],
    }


class FixtureDirectory:
    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="gowave-client-trust-")
        self.root = Path(self._tmp.name)
        self.ca = acme_fixture.generate_fixture_ca(self.root)

    def cleanup(self) -> None:
        self._tmp.cleanup()


class TestPodmanClientTrust(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = FixtureDirectory()
        self.addCleanup(self.directory.cleanup)
        self.ca_file = self.directory.ca.root_cert

    def test_xray_anchor_is_a_verify_entry_with_inline_pem(self):
        anchor = client_trust.xray_verify_anchor(self.ca_file)
        self.assertEqual(anchor["usage"], "verify")
        self.assertEqual(len(anchor["certificate"]), 1)
        self.assertIn("BEGIN CERTIFICATE", anchor["certificate"][0])

    def test_every_tls_outbound_is_anchored_and_reality_is_untouched(self):
        config = sample_config()
        self.assertEqual(sorted(client_trust.unanchored_tls_outbounds(config)), ["proxy-ws", "proxy-xhttp"])
        anchored = client_trust.apply_xray_trust_anchors(config, self.ca_file)
        self.assertEqual(client_trust.unanchored_tls_outbounds(anchored), [])
        for outbound in client_trust.tls_outbounds(anchored):
            certificates = outbound["streamSettings"]["tlsSettings"]["certificates"]
            self.assertEqual([entry["usage"] for entry in certificates], ["verify"])
        reality = [outbound for outbound in anchored["outbounds"] if outbound["tag"] == "proxy-reality"][0]
        self.assertEqual(reality["streamSettings"]["security"], "reality")
        self.assertNotIn("tlsSettings", reality["streamSettings"])
        direct = [outbound for outbound in anchored["outbounds"] if outbound["tag"] == "direct"][0]
        self.assertNotIn("streamSettings", direct)

    def test_existing_certificates_are_preserved(self):
        config = sample_config()
        config["outbounds"][0]["streamSettings"]["tlsSettings"]["certificates"] = [
            {"usage": "verify", "certificateFile": "/etc/ssl/certs/other.pem"},
        ]
        anchored = client_trust.apply_xray_trust_anchors(config, self.ca_file)
        certificates = anchored["outbounds"][0]["streamSettings"]["tlsSettings"]["certificates"]
        self.assertEqual(len(certificates), 2)
        self.assertEqual(certificates[0]["certificateFile"], "/etc/ssl/certs/other.pem")
        self.assertEqual(certificates[1]["usage"], "verify")

    def test_anchoring_is_idempotent_and_non_mutating(self):
        config = sample_config()
        once = client_trust.apply_xray_trust_anchors(config, self.ca_file)
        twice = client_trust.apply_xray_trust_anchors(once, self.ca_file)
        self.assertEqual(once, twice)
        self.assertNotIn("certificates", config["outbounds"][0]["streamSettings"]["tlsSettings"])

    def test_missing_tls_outbound_fails_closed(self):
        with self.assertRaises(client_trust.ClientTrustError):
            client_trust.apply_xray_trust_anchors({"outbounds": [reality_outbound()]}, self.ca_file)
        with self.assertRaises(client_trust.ClientTrustError):
            client_trust.apply_xray_trust_anchors({"inbounds": []}, self.ca_file)

    def test_non_pem_input_is_rejected(self):
        not_a_certificate = self.directory.root / "not-a-cert.pem"
        not_a_certificate.write_text("hello\n", encoding="utf-8")
        with self.assertRaises(client_trust.ClientTrustError):
            client_trust.xray_verify_anchor(not_a_certificate)
        with self.assertRaises(client_trust.ClientTrustError):
            client_trust.xray_verify_anchor(self.directory.root / "absent.pem")

    def test_real_xray_accepts_the_anchored_config(self):
        xray = shutil.which("xray")
        if not xray:
            self.skipTest("xray is not installed")
        config = client_trust.apply_xray_trust_anchors(sample_config(), self.ca_file)
        path = self.directory.root / "xray-client.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        result = subprocess.run(
            [xray, "run", "-test", "-c", str(path)],
            capture_output=True, text=True, check=False, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_mihomo_anchor_is_embedded_because_the_key_takes_pem_documents(self):
        pem = client_trust.ca_pem(self.ca_file)
        config = client_trust.apply_mihomo_trust_anchors({"proxies": [], "rules": ["MATCH,DIRECT"]}, self.ca_file)
        self.assertEqual(config["tls"][client_trust.MIHOMO_CA_KEY], [pem])
        self.assertIn("BEGIN CERTIFICATE", config["tls"][client_trust.MIHOMO_CA_KEY][0])
        self.assertEqual(client_trust.CONTAINER_CA_FILE, "/fixtures/ca/fixture-ca.crt")
        with self.assertRaises(client_trust.ClientTrustError):
            client_trust.apply_mihomo_trust_anchors({"tls": "not-a-mapping"}, self.ca_file)
        with self.assertRaises(client_trust.ClientTrustError):
            client_trust.apply_mihomo_trust_anchors({}, "")
        with self.assertRaises(client_trust.ClientTrustError):
            client_trust.apply_mihomo_trust_anchors({"proxies": []}, "/fixtures/ca/absent.crt")

    def test_real_mihomo_accepts_the_trust_block(self):
        mihomo = shutil.which("mihomo")
        if not mihomo:
            self.skipTest("mihomo is not installed")
        config = client_trust.apply_mihomo_trust_anchors({
            "mixed-port": 17890,
            "proxies": [],
            "rules": ["MATCH,DIRECT"],
        }, str(self.ca_file))
        path = self.directory.root / "mihomo-config.yaml"
        anchor = "\n".join(
            f"      {line}" for line in config["tls"][client_trust.MIHOMO_CA_KEY][0].splitlines()
        )
        path.write_text(
            "\n".join([
                f"mixed-port: {config['mixed-port']}",
                "tls:",
                f"  {client_trust.MIHOMO_CA_KEY}:",
                "    - |",
                anchor,
                "proxies: []",
                "rules:",
                "  - MATCH,DIRECT",
                "",
            ]),
            encoding="utf-8",
        )
        result = subprocess.run(
            [mihomo, "-t", "-f", str(path)],
            capture_output=True, text=True, check=False, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_scoped_environment_and_curl_arguments(self):
        environment = client_trust.scoped_environment(self.ca_file)
        self.assertEqual(set(environment), {"CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE"})
        for value in environment.values():
            self.assertEqual(Path(value), self.ca_file)
        self.assertEqual(client_trust.curl_ca_arguments(self.ca_file), ["--cacert", str(self.ca_file)])

    def test_chain_failure_requires_a_real_chain_error(self):
        client_trust.verify_chain_failure(
            "ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
            "unable to get local issuer certificate (_ssl.c:1016)"
        )
        client_trust.verify_chain_failure("curl: (60) SSL certificate problem: self-signed certificate in certificate chain")
        for message in ("Connection refused", "timed out", ""):
            with self.assertRaises(client_trust.ClientTrustError):
                client_trust.verify_chain_failure(message)

    def test_python_client_trusts_the_anchor_and_fails_without_it(self):
        leaf = acme_fixture.generate_leaf(
            self.directory.root, "echo", ["DNS:echo.testbed.internal", "IP:127.0.0.1"],
        )
        port = free_port()
        control = self.directory.root / "echo-control.json"
        log = self.directory.root / "echo-log.jsonl"
        process = subprocess.Popen(
            [
                sys.executable, str(ECHO_SERVER),
                "--listen", "127.0.0.1", "--http-port", str(free_port()),
                "--https-port", str(port),
                "--cert", str(leaf["cert"]), "--key", str(leaf["key"]),
                "--control", str(control), "--log", str(log),
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.addCleanup(self._stop, process)
        self._wait_https(port)

        trusted = ssl.create_default_context(cafile=str(self.ca_file))
        with urllib.request.urlopen(f"https://127.0.0.1:{port}/anchored", timeout=5, context=trusted) as response:
            payload = json.loads(response.read())
        self.assertEqual(response.status, 200)
        self.assertEqual(payload["path"], "/anchored")
        self.assertTrue(payload["tls"]["version"].startswith("TLS"))

        untrusted = ssl.create_default_context()
        with self.assertRaises(urllib.error.URLError) as caught:
            urllib.request.urlopen(f"https://127.0.0.1:{port}/unanchored", timeout=5, context=untrusted)
        self.assertIsInstance(caught.exception.reason, ssl.SSLCertVerificationError)
        client_trust.verify_chain_failure(str(caught.exception.reason))

    def _wait_https(self, port: int) -> None:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("the HTTPS echo fixture did not start")

    @staticmethod
    def _stop(process: subprocess.Popen) -> None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        for stream in (process.stdout, process.stderr):
            if stream:
                stream.close()


if __name__ == "__main__":
    unittest.main()
