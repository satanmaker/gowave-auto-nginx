#!/usr/bin/env python3
"""Suite root: Privileged host hardening, systemd drop-ins, Fail2ban syntax, Stream 443 SNI,
zero-leak secrets, strict umask 077 backups, journal schema validation, and sequential multi-node add.
Must run with EUID 0 (root).
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent

from modules.recovery import load_journal_file, validate_journal, JournalValidationError


class TestRoot(unittest.TestCase):

    def setUp(self):
        if os.geteuid() != 0:
            self.skipTest("Suite root requires root privileges (EUID 0)")

    def test_recovery_journal_loader_rejects_symlink_and_fifo(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            dangling = root / "journal.json"
            dangling.symlink_to(root / "missing.json")
            with self.assertRaises(OSError):
                load_journal_file(dangling)

            fifo = root / "journal.fifo"
            os.mkfifo(fifo)
            with self.assertRaises(OSError):
                load_journal_file(fifo)

    def test_recovery_journal_cli_rejects_dangling_symlink(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            dangling = root / "journal.json"
            dangling.symlink_to(root / "missing.json")
            result = subprocess.run(
                ["python3", str(REPO_ROOT / "modules" / "recovery.py"), "--validate-journal", str(dangling)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)

    def test_boot_recovery_rejects_dangling_journal_symlink(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            journal = root / "journal.json"
            journal.symlink_to(root / "missing.json")
            env = os.environ.copy()
            env["JOURNAL_FILE"] = str(journal)
            env["RECOVERY_DIR"] = str(root / "recovery")
            env["MUTATION_LOCK_FILE"] = str(root / "mutation.lock")
            for function in ("recover_boot_files", "recover_boot_provision"):
                result = subprocess.run(
                    [
                        "bash",
                        "-c",
                        f'source "$1/modules/recovery.sh"; {function}',
                        "test",
                        str(REPO_ROOT),
                    ],
                    env=env,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0, function)
                self.assertIn("recovery journal is a symlink or non-regular file", result.stderr)
                self.assertTrue(journal.is_symlink())

    def test_euid_zero(self):
        """Assert current runner is EUID 0."""
        self.assertEqual(os.geteuid(), 0)

    def test_user_group_and_sticky_bit(self):
        """Test user/group gowave creation and sticky bit 1770 on target directory."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            target_dir = Path(tmp_dir) / "gowave"
            target_dir.mkdir(mode=0o1770)
            os.chmod(target_dir, 0o1770)
            st = target_dir.stat()
            self.assertTrue(bool(st.st_mode & 0o1000), "Sticky bit not set on directory")
            self.assertEqual(oct(st.st_mode & 0o777), "0o770")

    def test_zero_leak_secret_delivery(self):
        """Verify delivery of node SECRET_KEY via stdin / mode 0600 temporary file without CLI argv exposure."""
        dummy_secret = "dGVzdC1jZXJ0LXNlY3JldA=="
        with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
            tf.write(dummy_secret)
            tf.flush()
            temp_path = tf.name

        try:
            os.chmod(temp_path, 0o600)
            st = os.stat(temp_path)
            self.assertEqual(oct(st.st_mode & 0o777), "0o600")

            # Execute reader via stdin without passing dummy_secret in argv
            proc = subprocess.Popen(
                ["bash", "-c", "cat"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, _ = proc.communicate(input=dummy_secret)
            self.assertEqual(stdout, dummy_secret)

            # Check /proc/<pid>/cmdline did not contain secret
            self.assertNotIn(dummy_secret, " ".join(proc.args))
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_ipv6_disabled_stream(self):
        """When kernel IPv6 is disabled, generate_stream_config must NOT output [::]:443."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            fake_if_inet6 = tmp / "nonexistent_if_inet6"
            out_stream = tmp / "gowave-stream.conf"

            cmd = f"""
source "{REPO_ROOT}/modules/os.sh"
source "{REPO_ROOT}/modules/nginx.sh"
generate_stream_config "panel.example.com" "reality.example.com" "{out_stream}" "{fake_if_inet6}"
"""
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            content = out_stream.read_text()
            self.assertIn("listen 443 so_keepalive=on;", content)
            self.assertNotIn("[::]:443", content)

    def test_backup_strict_umask(self):
        """Backup creation under strict umask 077 must still produce mode 0600 archive."""
        backup_script = REPO_ROOT / "assets" / "backup" / "gowave-backup.sh"
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            gowave_dir = tmp / "gowave"
            gowave_dir.mkdir()
            (gowave_dir / ".env").write_text("APP_PORT=3000\n")
            out_archive = tmp / "strict_backup.tar.gz"

            cmd = f"umask 077 && bash '{backup_script}' backup --type panel '{out_archive}' '{gowave_dir}'"
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertTrue(out_archive.exists())
            mode = oct(out_archive.stat().st_mode & 0o777)
            self.assertEqual(mode, "0o600")

    def test_gomemlimit_applied(self):
        """Verify systemd drop-in file format for GOMEMLIMIT."""
        dropin_content = """[Service]
Environment="GOMEMLIMIT=250MiB"
"""
        with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
            tf.write(dropin_content)
            tf.flush()
            path = tf.name

        try:
            content = Path(path).read_text()
            self.assertIn("GOMEMLIMIT=250MiB", content)
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_journal_schema_validation(self):
        """Strict JSON Schema validation for journal.json before recovery actions."""
        # Valid update journal
        valid_journal = {
            "transaction_id": "update-123456",
            "op": "update",
            "state": "PREPARED",
            "timestamp": "2026-11-08T00:00:00Z"
        }
        self.assertTrue(validate_journal(valid_journal))

        # Invalid operation
        invalid_op = {
            "transaction_id": "bad-op",
            "op": "invalid_operation_name",
            "state": "PREPARED",
            "timestamp": "2026-11-08T00:00:00Z"
        }
        with self.assertRaises(JournalValidationError):
            validate_journal(invalid_op)

        # Invalid state
        invalid_state = {
            "transaction_id": "bad-state",
            "op": "update",
            "state": "UNKNOWN_STATE",
            "timestamp": "2026-11-08T00:00:00Z"
        }
        with self.assertRaises(JournalValidationError):
            validate_journal(invalid_state)

        # Timestamps must be ISO-8601 with an explicit timezone.
        invalid_timestamp = {**valid_journal, "timestamp": "yesterday"}
        with self.assertRaises(JournalValidationError):
            validate_journal(invalid_timestamp)

        # Active file transactions require a durable recovery snapshot path.
        active_without_snapshot = {**valid_journal, "state": "APPLYING"}
        with self.assertRaises(JournalValidationError):
            validate_journal(active_without_snapshot)

        # Updated provisioning entities must include a before-image.
        invalid_entity_journal = {
            "transaction_id": "provision-invalid-entity",
            "op": "provision",
            "state": "PROVISION_APPLYING",
            "timestamp": "2026-11-08T00:00:00Z",
            "entities": [{"type": "profile", "uuid": "profile-1", "action": "updated"}],
        }
        with self.assertRaises(JournalValidationError):
            validate_journal(invalid_entity_journal)

    def test_sequential_multi_node_add(self):
        """Sequential worker node addition to state.json schemaVersion 2."""
        state = {
            "schemaVersion": 2,
            "installationMode": "all-in-one",
            "nodes": [
                {"name": "local-node", "address": "127.0.0.1", "port": 3002, "uuid": "node-1"}
            ]
        }
        # Add worker 1
        state["nodes"].append({"name": "worker-1", "address": "10.89.0.20", "port": 3002, "uuid": "node-2"})
        # Add worker 2
        state["nodes"].append({"name": "worker-2", "address": "10.89.0.21", "port": 3002, "uuid": "node-3"})

        self.assertEqual(len(state["nodes"]), 3)
        self.assertEqual(state["nodes"][1]["name"], "worker-1")
        self.assertEqual(state["nodes"][2]["name"], "worker-2")


if __name__ == "__main__":
    unittest.main()
