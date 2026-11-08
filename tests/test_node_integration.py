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
        payload = {
            "caCertPem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
            "jwtPublicKey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
            "nodeCertPem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
            "nodeKeyPem": "-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----"
        }
        b64 = base64.b64encode(json.dumps(payload).encode()).decode()

        cmd = f'source "{NODE_SH}" && verify_node_mtls_health "{b64}" 3002'
        res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("contains valid mTLS certificates", res.stdout)

        # Incomplete payload
        bad_payload = {"caCertPem": "CA"}
        bad_b64 = base64.b64encode(json.dumps(bad_payload).encode()).decode()
        cmd_bad = f'source "{NODE_SH}" && verify_node_mtls_health "{bad_b64}" 3002'
        res_bad = subprocess.run(["bash", "-c", cmd_bad], capture_output=True, text=True)
        self.assertNotEqual(res_bad.returncode, 0)
        self.assertIn("Missing jwtPublicKey", res_bad.stderr)


if __name__ == "__main__":
    unittest.main()
