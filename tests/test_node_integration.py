#!/usr/bin/env python3
import base64
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
NODE_SH = REPO_ROOT / "modules" / "node.sh"


class TestNodeIntegration(unittest.TestCase):
    def test_extract_secret_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            mock_server = tmp / "gowave-server"
            fake_secret = base64.b64encode(b'{"caCertPem":"CA","jwtPublicKey":"JWT","nodeCertPem":"CERT","nodeKeyPem":"KEY"}').decode()
            mock_server.write_text(f'#!/bin/sh\nif [ "$1" = "rescue" ] && [ "$2" = "--print-secret-key-raw" ]; then echo "{fake_secret}"; fi\n')
            mock_server.chmod(0o755)

            cmd = f'source "{NODE_SH}" && extract_secret_key "{tmp}"'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)
            self.assertEqual(res.stdout, fake_secret)

    def test_configure_node_env(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            fake_secret = "c2VjcmV0LWtleS1kYXRh"
            cmd = f'source "{NODE_SH}" && configure_node_env "{tmp}" "{fake_secret}" 3002'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)

            env_file = tmp / ".env"
            self.assertTrue(env_file.exists())
            mode = oct(env_file.stat().st_mode & 0o777)
            self.assertEqual(mode, "0o600")

            content = env_file.read_text()
            self.assertIn(f"SECRET_KEY={fake_secret}", content)
            self.assertIn("NODE_PORT=3002", content)
            self.assertIn("SNI_VERIFICATION=true", content)

    def test_verify_node_mtls_payload(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ca_key = tmp / "ca.key"
            ca_crt = tmp / "ca.crt"
            node_key = tmp / "node.key"
            node_csr = tmp / "node.csr"
            node_crt = tmp / "node.crt"
            jwt_key = tmp / "jwt.key"
            jwt_pub = tmp / "jwt.pub"

            # 1. Generate real ECDSA P-256 CA
            subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(ca_key)],
                           check=True, stderr=subprocess.DEVNULL)
            subprocess.run(["openssl", "req", "-x509", "-new", "-key", str(ca_key), "-out", str(ca_crt),
                            "-days", "365", "-subj", "/CN=TestGoWaveCA"], check=True, stderr=subprocess.DEVNULL)

            # 2. Generate real ECDSA P-256 Node keypair signed by CA
            subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(node_key)],
                           check=True, stderr=subprocess.DEVNULL)
            subprocess.run(["openssl", "req", "-new", "-key", str(node_key), "-out", str(node_csr),
                            "-subj", "/CN=TestNode"], check=True, stderr=subprocess.DEVNULL)
            subprocess.run(["openssl", "x509", "-req", "-in", str(node_csr), "-CA", str(ca_crt),
                            "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(node_crt), "-days", "365"],
                           check=True, stderr=subprocess.DEVNULL)

            # 3. Generate real RSA 2048 JWT public key
            subprocess.run(["openssl", "genrsa", "-out", str(jwt_key), "2048"], check=True, stderr=subprocess.DEVNULL)
            subprocess.run(["openssl", "rsa", "-in", str(jwt_key), "-pubout", "-out", str(jwt_pub)],
                           check=True, stderr=subprocess.DEVNULL)

            valid_payload = {
                "caCertPem": ca_crt.read_text(),
                "jwtPublicKey": jwt_pub.read_text(),
                "nodeCertPem": node_crt.read_text(),
                "nodeKeyPem": node_key.read_text(),
            }
            valid_b64 = base64.b64encode(json.dumps(valid_payload).encode()).decode()

            # Test crypto-only verification passes with real keys and derives SNI
            cmd = f'source "{NODE_SH}" && verify_node_mtls_health "{valid_b64}" 3002 127.0.0.1 crypto-only'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("Derived HKDF SNI (rw-v1):", res.stdout)
            self.assertIn("Payload cryptographic verification PASSED", res.stdout)

            # Test incomplete payload rejection
            bad_payload = {"caCertPem": "CA"}
            bad_b64 = base64.b64encode(json.dumps(bad_payload).encode()).decode()
            cmd_bad = f'source "{NODE_SH}" && verify_node_mtls_health "{bad_b64}" 3002 127.0.0.1 crypto-only'
            res_bad = subprocess.run(["bash", "-c", cmd_bad], capture_output=True, text=True)
            self.assertNotEqual(res_bad.returncode, 0)
            self.assertIn("Missing or empty required cryptographic field", res_bad.stderr)

            # Test corrupted base64 rejection
            cmd_corrupt = f'source "{NODE_SH}" && verify_node_mtls_health "not-a-valid-base64!!!" 3002 127.0.0.1 crypto-only'
            res_corrupt = subprocess.run(["bash", "-c", cmd_corrupt], capture_output=True, text=True)
            self.assertNotEqual(res_corrupt.returncode, 0)
            self.assertIn("Failed to decode base64", res_corrupt.stderr)

            # Test mismatched certificate/key rejection
            other_key = tmp / "other.key"
            subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(other_key)],
                           check=True, stderr=subprocess.DEVNULL)
            mismatched_payload = dict(valid_payload)
            mismatched_payload["nodeKeyPem"] = other_key.read_text()
            mismatch_b64 = base64.b64encode(json.dumps(mismatched_payload).encode()).decode()
            cmd_mismatch = f'source "{NODE_SH}" && verify_node_mtls_health "{mismatch_b64}" 3002 127.0.0.1 crypto-only'
            res_mismatch = subprocess.run(["bash", "-c", cmd_mismatch], capture_output=True, text=True)
            self.assertNotEqual(res_mismatch.returncode, 0)
            self.assertIn("Cryptographic mismatch", res_mismatch.stderr)

    def test_deploy_node_systemd_dropins(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            cmd = f'source "{NODE_SH}" && deploy_node_systemd_dropins 3002 "{tmp}"'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)
            conf_file = tmp / "10-port.conf"
            self.assertTrue(conf_file.exists())
            content = conf_file.read_text()
            self.assertIn('Environment="NODE_PORT=3002"', content)
            self.assertIn("sport = :3002", content)
            self.assertNotIn("curl -k", content)

    def test_worker_payload_contains_automated_compensation(self):
        """Worker deployment must include automated compensating rollback on error."""
        worker_script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        self.assertIn("compensate_remote_worker", worker_script)
        self.assertIn("trap 'exit_code=$?; compensate_remote_worker \"$exit_code\"; exit \"$exit_code\"' ERR", worker_script)
        self.assertIn("systemctl stop gowave-node.service", worker_script)
        self.assertIn("rm -rf /etc/systemd/system/gowave-node.service.d", worker_script)
        self.assertIn("certbot delete --cert-name \"$WORKER_DOMAIN\"", worker_script)
        self.assertIn("swapoff /swapfile", worker_script)
        self.assertIn("ufw delete allow proto tcp from \"$PANEL_IP\"", worker_script)

    def test_worker_standalone_remote_rollback_defined(self):
        """gowave-node-auto.sh must provide standalone remote_rollback command."""
        worker_script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        self.assertIn("remote_rollback()", worker_script)
        self.assertIn("remote_rollback|rollback)", worker_script)
        self.assertIn("SSH host key for $host_key is not pre-pinned", worker_script)


if __name__ == "__main__":
    unittest.main()
