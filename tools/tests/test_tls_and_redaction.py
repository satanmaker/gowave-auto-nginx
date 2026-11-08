#!/usr/bin/env python3
"""Unit tests for tools/live_vps/tls.py and tools/live_vps/redaction.py."""
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

from live_vps.tls import (
    find_system_ca_bundle,
    verify_staging_roots,
    build_runtime_ca_bundle,
    create_ssl_context,
    STAGING_CERTS_DIR,
)
from live_vps.redaction import (
    register_secret,
    clear_secrets,
    redact,
    write_redacted_text,
)


class TestTLSAndRedaction(unittest.TestCase):
    def test_find_system_ca_bundle(self):
        bundle = find_system_ca_bundle()
        self.assertTrue(bundle.is_file())
        self.assertGreater(bundle.stat().st_size, 0)

    def test_verify_staging_roots_production_manifest(self):
        verified = verify_staging_roots(STAGING_CERTS_DIR)
        self.assertEqual(len(verified), 4)
        cns = {item["subject_cn"] for _, item in verified}
        self.assertIn("(STAGING) Pretend Pear X1", cns)
        self.assertIn("(STAGING) Bogus Broccoli X2", cns)
        self.assertIn("(STAGING) Yearning Yucca Root YE", cns)
        self.assertIn("(STAGING) Yonder Yam Root YR", cns)

    def test_verify_staging_roots_tampered_digest_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            shutil.copytree(STAGING_CERTS_DIR, tmp / "staging")
            stg = tmp / "staging"
            pins_file = stg / "pins.json"
            data = json.loads(pins_file.read_text())
            # Mutate one digest
            data["roots"][0]["der_sha256"] = "0000000000000000000000000000000000000000000000000000000000000000"
            pins_file.write_text(json.dumps(data))

            with self.assertRaises(ValueError) as ctx:
                verify_staging_roots(stg)
            self.assertIn("Digest mismatch", str(ctx.exception))

    def test_verify_staging_roots_extra_file_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            shutil.copytree(STAGING_CERTS_DIR, tmp / "staging")
            stg = tmp / "staging"
            (stg / "extra-root.pem").write_text("dummy")

            with self.assertRaises(ValueError) as ctx:
                verify_staging_roots(stg)
            self.assertIn("Staging certificate file mismatch", str(ctx.exception))

    def test_build_runtime_ca_bundle_modes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)

            # Staging bundle
            stg_bundle = build_runtime_ca_bundle("staging", output_path=tmp / "staging.crt")
            self.assertTrue(stg_bundle.is_file())
            mode = oct(stg_bundle.stat().st_mode & 0o777)
            self.assertEqual(mode, "0o600")
            stg_content = stg_bundle.read_text()
            self.assertIn("Let's Encrypt Staging Roots", stg_content)
            self.assertIn("(STAGING) Pretend Pear X1", stg_content)

            # Production bundle
            prod_bundle = build_runtime_ca_bundle("production", output_path=tmp / "prod.crt")
            self.assertTrue(prod_bundle.is_file())
            prod_content = prod_bundle.read_text()
            self.assertNotIn("Let's Encrypt Staging Roots", prod_content)
            self.assertNotIn("(STAGING) Pretend Pear X1", prod_content)

            # SSL context creation
            ctx = create_ssl_context(stg_bundle)
            self.assertTrue(ctx.check_hostname)
            self.assertEqual(ctx.verify_mode, 2)  # CERT_REQUIRED

    def test_redaction_filters(self):
        clear_secrets()
        register_secret("SuperSecretAdminPassword123")
        register_secret("shortUuid-xyz-789")

        raw_log = "User admin with pass SuperSecretAdminPassword123 and sub shortUuid-xyz-789 logged in."
        cleaned = redact(raw_log)
        self.assertNotIn("SuperSecretAdminPassword123", cleaned)
        self.assertNotIn("shortUuid-xyz-789", cleaned)
        self.assertIn("User admin with pass [REDACTED] and sub [REDACTED] logged in.", cleaned)

        # JWT Redaction
        jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        cleaned_jwt = redact(f"Bearer {jwt_token}")
        self.assertNotIn(jwt_token, cleaned_jwt)
        self.assertIn("Bearer [REDACTED]", cleaned_jwt)

        # Private Key Redaction
        fake_key = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...\n-----END PRIVATE KEY-----"
        cleaned_key = redact(f"Dump:\n{fake_key}\nDone")
        self.assertNotIn("MIIEvgIBAD", cleaned_key)
        self.assertIn("[REDACTED]", cleaned_key)

        # File writing with enforced mode
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "diag.log"
            write_redacted_text(out_file, f"Secret: SuperSecretAdminPassword123")
            self.assertEqual(oct(out_file.stat().st_mode & 0o777), "0o600")
            self.assertEqual(out_file.read_text(), "Secret: [REDACTED]")


if __name__ == "__main__":
    unittest.main()
