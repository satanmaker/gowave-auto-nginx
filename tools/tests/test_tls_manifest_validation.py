#!/usr/bin/env python3
"""Regression tests for strict Let's Encrypt staging CA manifest validation."""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from live_vps.tls import STAGING_CERTS_DIR, verify_staging_roots


class TestStagingManifestValidation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.staging = Path(self.tmp.name) / "staging"
        shutil.copytree(STAGING_CERTS_DIR, self.staging)
        self.pins = self.staging / "pins.json"
        self.original = json.loads(self.pins.read_text(encoding="utf-8"))

    def tearDown(self):
        self.tmp.cleanup()

    def _write_manifest(self, value):
        self.pins.write_text(json.dumps(value), encoding="utf-8")

    def test_non_object_manifest_is_rejected(self):
        for value in ([], None, 42, "manifest"):
            with self.subTest(value=value):
                self._write_manifest(value)
                with self.assertRaisesRegex(ValueError, "root must be an object"):
                    verify_staging_roots(self.staging)

    def test_roots_must_be_a_list(self):
        for roots in ({}, None, "invalid", 4):
            with self.subTest(roots=roots):
                self._write_manifest({"roots": roots})
                with self.assertRaisesRegex(ValueError, "roots must be a list"):
                    verify_staging_roots(self.staging)

    def test_root_entries_must_have_required_typed_fields(self):
        malformed_entries = [
            None,
            "root.pem",
            {},
            {"file": "root.pem", "subject_cn": "Root", "der_sha256": 42},
            {"file": "root.pem", "subject_cn": [], "der_sha256": "a" * 64},
        ]
        for entry in malformed_entries:
            with self.subTest(entry=entry):
                value = json.loads(json.dumps(self.original))
                value["roots"][0] = entry
                self._write_manifest(value)
                with self.assertRaisesRegex(ValueError, "root entry 0"):
                    verify_staging_roots(self.staging)

    def test_certificate_filename_cannot_escape_staging_directory(self):
        for filename in ("../outside.pem", "/tmp/outside.pem", "nested/root.pem", ".."):
            with self.subTest(filename=filename):
                value = json.loads(json.dumps(self.original))
                value["roots"][0]["file"] = filename
                self._write_manifest(value)
                with self.assertRaisesRegex(ValueError, "invalid certificate filename"):
                    verify_staging_roots(self.staging)

    def test_duplicate_certificate_filenames_are_rejected(self):
        value = json.loads(json.dumps(self.original))
        value["roots"][1]["file"] = value["roots"][0]["file"]
        self._write_manifest(value)
        with self.assertRaisesRegex(ValueError, "duplicate certificate filename"):
            verify_staging_roots(self.staging)

    def test_symlinked_pinned_certificate_is_rejected(self):
        pem = self.staging / self.original["roots"][0]["file"]
        outside = Path(self.tmp.name) / "outside.pem"
        outside.write_bytes(pem.read_bytes())
        pem.unlink()
        pem.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "non-symlink regular file"):
            verify_staging_roots(self.staging)

    def test_symlinked_manifest_is_rejected(self):
        target = Path(self.tmp.name) / "manifest.json"
        target.write_text(json.dumps(self.original), encoding="utf-8")
        self.pins.unlink()
        self.pins.symlink_to(target)
        with self.assertRaisesRegex(FileNotFoundError, "non-symlink regular file"):
            verify_staging_roots(self.staging)


if __name__ == "__main__":
    unittest.main()
