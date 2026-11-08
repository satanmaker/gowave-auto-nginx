#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tarfile
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKUP_SH = REPO_ROOT / "assets" / "backup" / "gowave-backup.sh"


class TestBackupFormatV1(unittest.TestCase):
    def test_backup_and_validation_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            gowave_dir = tmp / "opt_gowave"
            gowave_dir.mkdir()
            db_file = gowave_dir / "gowave.db"

            # Create test SQLite db
            conn = sqlite3.connect(str(db_file))
            conn.execute("CREATE TABLE test (id INT);")
            conn.execute("INSERT INTO test VALUES (1);")
            conn.commit()
            conn.close()

            # Create test .env
            env_file = gowave_dir / ".env"
            env_file.write_text("APP_PORT=3000\nGOWAVE_PROXY=external\n")

            out_archive = tmp / "backup-panel.tar.gz"

            # Run backup
            cmd = f'"{BACKUP_SH}" backup --type panel "{out_archive}" "{gowave_dir}"'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)

            # Check archive mode 0600
            self.assertTrue(out_archive.exists())
            mode = oct(out_archive.stat().st_mode & 0o777)
            self.assertEqual(mode, "0o600")

            # Validate archive using 15-point validator
            cmd_verify = f'"{BACKUP_SH}" verify "{out_archive}" panel'
            res_verify = subprocess.run(["bash", "-c", cmd_verify], capture_output=True, text=True)
            self.assertEqual(res_verify.returncode, 0, res_verify.stderr)
            self.assertIn("15-point preflight archive validation PASSED", res_verify.stdout)

    def test_rejection_of_malicious_archives(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)

            # 1. Path traversal injection
            traversal_tar = tmp / "traversal.tar.gz"
            with tarfile.open(traversal_tar, "w:gz") as tar:
                meta = {"format_version": 1, "backup_type": "panel", "files": []}
                meta_bytes = json.dumps(meta).encode()
                ti_meta = tarfile.TarInfo("meta.json")
                ti_meta.size = len(meta_bytes)
                tar.addfile(ti_meta, fileobj=io_bytes(meta_bytes))

                payload = b"evil"
                ti_bad = tarfile.TarInfo("files/opt/gowave/../../etc/passwd")
                ti_bad.size = len(payload)
                tar.addfile(ti_bad, fileobj=io_bytes(payload))

            res = subprocess.run(["bash", "-c", f'"{BACKUP_SH}" verify "{traversal_tar}" panel'], capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Path traversal detected", res.stderr)

            # 2. Binary executable rejection
            bin_tar = tmp / "binary.tar.gz"
            with tarfile.open(bin_tar, "w:gz") as tar:
                meta = {"format_version": 1, "backup_type": "panel", "files": []}
                meta_bytes = json.dumps(meta).encode()
                ti_meta = tarfile.TarInfo("meta.json")
                ti_meta.size = len(meta_bytes)
                tar.addfile(ti_meta, fileobj=io_bytes(meta_bytes))

                payload = b"\x7fELFbin"
                ti_bad = tarfile.TarInfo("files/opt/gowave/gowave-server")
                ti_bad.size = len(payload)
                tar.addfile(ti_bad, fileobj=io_bytes(payload))

            res2 = subprocess.run(["bash", "-c", f'"{BACKUP_SH}" verify "{bin_tar}" panel'], capture_output=True, text=True)
            self.assertNotEqual(res2.returncode, 0)
            self.assertIn("Binary executable rejected", res2.stderr)

            # 3. Shell script rejection
            sh_tar = tmp / "script.tar.gz"
            with tarfile.open(sh_tar, "w:gz") as tar:
                meta = {"format_version": 1, "backup_type": "panel", "files": []}
                meta_bytes = json.dumps(meta).encode()
                ti_meta = tarfile.TarInfo("meta.json")
                ti_meta.size = len(meta_bytes)
                tar.addfile(ti_meta, fileobj=io_bytes(meta_bytes))

                payload = b"#!/bin/sh\nrm -rf /\n"
                ti_bad = tarfile.TarInfo("files/etc/nginx/conf.d/gowave-evil.sh")
                ti_bad.size = len(payload)
                tar.addfile(ti_bad, fileobj=io_bytes(payload))

            res3 = subprocess.run(["bash", "-c", f'"{BACKUP_SH}" verify "{sh_tar}" panel'], capture_output=True, text=True)
            self.assertNotEqual(res3.returncode, 0)
            self.assertIn("Forbidden executable or script extension", res3.stderr)


def io_bytes(b):
    import io
    return io.BytesIO(b)


if __name__ == "__main__":
    unittest.main()
