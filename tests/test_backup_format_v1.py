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

    def test_letsencrypt_relative_symlink_allowed(self):
        """Certbot relative symlinks (../../archive/domain/fullchain1.pem) are accepted (M-06)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            cert_tar = tmp / "cert_symlink.tar.gz"

            payload = b"CERTIFICATE DATA"
            sha = hashlib.sha256(payload).hexdigest()

            with tarfile.open(cert_tar, "w:gz") as tar:
                meta = {
                    "format_version": 1,
                    "backup_type": "panel",
                    "files": [
                        {"path": "etc/letsencrypt/archive/example.com/fullchain1.pem", "sha256": sha}
                    ]
                }
                meta_bytes = json.dumps(meta).encode()
                ti_meta = tarfile.TarInfo("meta.json")
                ti_meta.size = len(meta_bytes)
                tar.addfile(ti_meta, fileobj=io_bytes(meta_bytes))

                # Regular cert in archive/
                ti_reg = tarfile.TarInfo("files/etc/letsencrypt/archive/example.com/fullchain1.pem")
                ti_reg.size = len(payload)
                tar.addfile(ti_reg, fileobj=io_bytes(payload))

                # Relative symlink in live/ pointing to archive/
                ti_sym = tarfile.TarInfo("files/etc/letsencrypt/live/example.com/fullchain.pem")
                ti_sym.type = tarfile.SYMTYPE
                ti_sym.linkname = "../../archive/example.com/fullchain1.pem"
                tar.addfile(ti_sym)

            cmd_verify = f'"{BACKUP_SH}" verify "{cert_tar}" panel'
            res = subprocess.run(["bash", "-c", cmd_verify], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("15-point preflight archive validation PASSED", res.stdout)

    def test_letsencrypt_symlink_escape_rejected(self):
        """Relative symlinks escaping the archive files root are strictly rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            evil_tar = tmp / "cert_escape.tar.gz"

            with tarfile.open(evil_tar, "w:gz") as tar:
                meta = {"format_version": 1, "backup_type": "panel", "files": []}
                meta_bytes = json.dumps(meta).encode()
                ti_meta = tarfile.TarInfo("meta.json")
                ti_meta.size = len(meta_bytes)
                tar.addfile(ti_meta, fileobj=io_bytes(meta_bytes))

                ti_sym = tarfile.TarInfo("files/etc/letsencrypt/live/example.com/fullchain.pem")
                ti_sym.type = tarfile.SYMTYPE
                ti_sym.linkname = "../../../../../../etc/shadow"
                tar.addfile(ti_sym)

            cmd_verify = f'"{BACKUP_SH}" verify "{evil_tar}" panel'
            res = subprocess.run(["bash", "-c", cmd_verify], capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Symbolic link escape detected", res.stderr)

    def test_restore_corrupted_database_rejected(self):
        """Restore aborts before touching destination if database integrity fails (C-04)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            corrupt_tar = tmp / "corrupt_db.tar.gz"
            payload = b"this is not a valid sqlite database file"
            sha = hashlib.sha256(payload).hexdigest()

            with tarfile.open(corrupt_tar, "w:gz") as tar:
                meta = {
                    "format_version": 1,
                    "backup_type": "panel",
                    "files": [
                        {"path": "opt/gowave/gowave.db", "sha256": sha}
                    ]
                }
                meta_bytes = json.dumps(meta).encode()
                ti_meta = tarfile.TarInfo("meta.json")
                ti_meta.size = len(meta_bytes)
                tar.addfile(ti_meta, fileobj=io_bytes(meta_bytes))

                ti_db = tarfile.TarInfo("files/opt/gowave/gowave.db")
                ti_db.size = len(payload)
                tar.addfile(ti_db, fileobj=io_bytes(payload))

            gowave_dir = tmp / "live_gowave"
            gowave_dir.mkdir()
            (gowave_dir / "gowave.db").write_text("live-good-db")
            recovery_dir = tmp / "recovery"

            cmd_restore = f'GOWAVE_DIR="{gowave_dir}" RECOVERY_STORE="{recovery_dir}" "{BACKUP_SH}" restore "{corrupt_tar}" panel'
            res = subprocess.run(["bash", "-c", cmd_restore], capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("staged database integrity check returned", res.stderr)
            # Ensure live DB was untouched
            self.assertEqual((gowave_dir / "gowave.db").read_text(), "live-good-db")

    def test_restore_panel_transactional_roundtrip(self):
        """Full panel restore executes atomically with journal state transition to COMMITTED (C-04)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            gowave_dir = tmp / "opt_gowave"
            gowave_dir.mkdir()
            db_file = gowave_dir / "gowave.db"

            conn = sqlite3.connect(str(db_file))
            conn.execute("CREATE TABLE users (id INT, name TEXT);")
            conn.execute("INSERT INTO users VALUES (1, 'initial_user');")
            conn.commit()
            conn.close()

            env_file = gowave_dir / ".env"
            env_file.write_text("PANEL_PORT=3000\nINITIAL_SECRET=xyz\n")

            out_archive = tmp / "backup-roundtrip.tar.gz"
            cmd_backup = f'"{BACKUP_SH}" backup --type panel "{out_archive}" "{gowave_dir}"'
            subprocess.run(["bash", "-c", cmd_backup], check=True, capture_output=True)

            # Now modify live DB and .env to simulate state before restore
            conn = sqlite3.connect(str(db_file))
            conn.execute("UPDATE users SET name = 'corrupted_state' WHERE id = 1;")
            conn.commit()
            conn.close()
            env_file.write_text("PANEL_PORT=9999\n")

            # Execute restore
            recovery_dir = tmp / "recovery"
            cmd_restore = f'GOWAVE_DIR="{gowave_dir}" RECOVERY_STORE="{recovery_dir}" "{BACKUP_SH}" restore "{out_archive}" panel'
            res = subprocess.run(["bash", "-c", cmd_restore], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)

            # Check DB was restored
            conn = sqlite3.connect(str(db_file))
            cur = conn.cursor()
            val = cur.execute("SELECT name FROM users WHERE id = 1;").fetchone()[0]
            conn.close()
            self.assertEqual(val, "initial_user")

            # Check .env was restored
            self.assertIn("INITIAL_SECRET=xyz", env_file.read_text())

            # Check journal state COMMITTED
            journal_path = recovery_dir / "journal.json"
            self.assertTrue(journal_path.exists())
            jdata = json.loads(journal_path.read_text())
            self.assertEqual(jdata.get("op"), "restore")
            self.assertEqual(jdata.get("state"), "COMMITTED")

    def test_sqlite_preflight_runs_as_service_user_when_requested(self):
        """Root preflight must not open the service DB with O_CREAT (fs.protected_regular)."""
        import sys
        from unittest.mock import patch

        sys.path.insert(0, str(REPO_ROOT))
        from modules import recovery

        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch.object(recovery, "_service_user_exists", return_value=True), \
                patch.object(recovery.subprocess, "run", return_value=completed) as run_mock:
            recovery.sqlite_preflight_checkpoint(Path("/opt/gowave/gowave.db"), "gowave")

        argv = run_mock.call_args[0][0]
        self.assertEqual(argv[:5], ["runuser", "-u", "gowave", "--", "python3"])
        self.assertEqual(argv[5], "-c")
        self.assertIn("wal_checkpoint", argv[6])
        self.assertEqual(argv[7], "/opt/gowave/gowave.db")

    def test_sqlite_preflight_reports_service_user_failure(self):
        import sys
        from unittest.mock import patch

        sys.path.insert(0, str(REPO_ROOT))
        from modules import recovery

        failed = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="attempt to write a readonly database"
        )
        with patch.object(recovery, "_service_user_exists", return_value=True), \
                patch.object(recovery.subprocess, "run", return_value=failed):
            with self.assertRaises(ValueError) as ctx:
                recovery.sqlite_preflight_checkpoint(Path("/opt/gowave/gowave.db"), "gowave")
        self.assertIn("readonly", str(ctx.exception))


def io_bytes(b):
    import io
    return io.BytesIO(b)


if __name__ == "__main__":
    unittest.main()
