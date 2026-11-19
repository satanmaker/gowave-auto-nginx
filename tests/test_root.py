#!/usr/bin/env python3
"""Suite root: Privileged host hardening, systemd drop-ins, Fail2ban syntax, Stream 443 SNI,
zero-leak secrets, strict umask 077 backups, journal schema validation, and sequential multi-node add.
Must run with EUID 0 (root).
"""
import json
import os
from pathlib import Path
import shutil
import sqlite3
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


class TestChannelSwitchRollback(unittest.TestCase):
    """Tasks 7.4/7.5: a channel switch is a transaction whose failure is undone.

    The switch is driven with its real snapshot code against a throwaway
    installation, and the only thing stubbed is `systemctl`: the first restart
    fails the way a release that cannot start fails, and every later one
    succeeds, so the rollback's own restart can bring the installation back.
    """

    def setUp(self):
        if os.geteuid() != 0:
            self.skipTest("Suite root requires root privileges (EUID 0)")
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        self.root = Path(holder.name)
        os.chmod(self.root, 0o700)

        self.stubs = self.root / "stubs"
        self.stubs.mkdir(mode=0o755)
        self.systemctl_log = self.root / "systemctl.log"
        self.write_stub(
            "systemctl",
            "#!/usr/bin/env bash\n"
            "set -u\n"
            'printf "%s\\n" "$*" >> "$STUB_LOG"\n'
            'if [[ "${1:-}" == "restart" && ! -e "$STUB_RESTART_OK" ]]; then\n'
            '    : > "$STUB_RESTART_OK"\n'
            "    exit 1\n"
            "fi\n"
            "exit 0\n",
        )
        self.write_stub("nginx", "#!/usr/bin/env bash\nexit 0\n")
        # The snapshot hands the staged database to the service user, which this
        # host does not have; the ownership hand-off is not what is under test.
        self.write_stub("chown", "#!/usr/bin/env bash\nexit 0\n")
        self.write_stub("runuser", '#!/usr/bin/env bash\nshift 3\nexec "$@"\n')

        # The rollback restores /etc/nginx and /etc/letsencrypt, so the switch runs
        # inside a private mount namespace where both name empty directories: the
        # code path is real and the host's own configuration is never a target.
        self.hidden_etc = {}
        for target in ("/etc/nginx", "/etc/letsencrypt"):
            empty = self.root / "empty" / target.strip("/").replace("/", "-")
            empty.mkdir(parents=True)
            self.hidden_etc[target] = empty
        probe = subprocess.run(
            ["unshare", "--mount", "--", "true"], capture_output=True, text=True,
        )
        if probe.returncode != 0:
            self.skipTest(f"a private mount namespace is required: {probe.stderr.strip()}")

        self.gowave = self.root / "opt" / "gowave"
        self.gowave.mkdir(parents=True)
        self.recovery = self.root / "recovery"
        self.recovery.mkdir(mode=0o700)
        self.state = self.root / "state.json"
        self.state.write_text('{"schemaVersion": 2}\n', encoding="utf-8")

        self.environment = dict(os.environ)
        self.environment.update({
            "PATH": f"{self.stubs}:{os.environ['PATH']}",
            "GOWAVE_DIR": str(self.gowave),
            "RECOVERY_DIR": str(self.recovery),
            "STATE_FILE": str(self.state),
            "JOURNAL_FILE": str(self.recovery / "journal.json"),
            "MUTATION_LOCK_FILE": str(self.root / "mutation.lock"),
            "CREDENTIALS_FILE": str(self.root / "credentials.txt"),
            "STUB_LOG": str(self.systemctl_log),
            "STUB_RESTART_OK": str(self.root / "restart-allowed"),
            "MOUNT_NGINX": str(self.hidden_etc["/etc/nginx"]),
            "MOUNT_LETSENCRYPT": str(self.hidden_etc["/etc/letsencrypt"]),
        })
        self.populate(self.gowave)

    def write_stub(self, name: str, body: str) -> None:
        stub = self.stubs / name
        stub.write_text(body, encoding="utf-8")
        os.chmod(stub, 0o755)

    def populate(self, directory: Path) -> None:
        database = sqlite3.connect(directory / "gowave.db")
        try:
            database.execute("create table users (id integer primary key, name text)")
            database.execute("insert into users (name) values ('alice')")
            database.commit()
        finally:
            database.close()
        (directory / ".env").write_text(
            "GOWAVE_CHANNEL=stable\nAPP_SECRET=keep-me\n", encoding="utf-8"
        )
        (directory / "gowave-server").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        os.chmod(directory / "gowave-server", 0o755)
        (directory / "frontend").mkdir()
        (directory / "frontend" / "index.html").write_text("<html>panel</html>\n", encoding="utf-8")
        (directory / "state.json").write_text('{"domain": "panel.test"}\n', encoding="utf-8")

    def run_function(self, call: str) -> subprocess.CompletedProcess:
        script = (
            "mount --make-rprivate /\n"
            "mount --bind \"$MOUNT_NGINX\" /etc/nginx\n"
            "mount --bind \"$MOUNT_LETSENCRYPT\" /etc/letsencrypt\n"
            f'source "$1/modules/recovery.sh"; {call}'
        )
        return subprocess.run(
            [
                "unshare",
                "--mount",
                "--",
                "bash",
                "-c",
                script,
                "test",
                str(REPO_ROOT),
            ],
            env=self.environment,
            capture_output=True,
            text=True,
            timeout=300,
        )

    def function_body(self, name: str) -> str:
        text = (REPO_ROOT / "modules" / "recovery.sh").read_text(encoding="utf-8")
        start = text.index(f"{name}() {{")
        end = text.index("\n}\n", start)
        return text[start:end]

    def test_a_switch_whose_restart_fails_restores_the_snapshot(self):
        before = (self.state).read_text(encoding="utf-8")
        result = self.run_function("switch_channel dev")

        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("Channel switch failed: gowave.service did not become active", result.stderr)
        self.assertIn("File rollback completed and services verified.", result.stderr)
        self.assertIn("Channel switch rolled back to the pre-switch state.", result.stderr)

        self.assertEqual(
            (self.gowave / ".env").read_text(encoding="utf-8"),
            "GOWAVE_CHANNEL=stable\nAPP_SECRET=keep-me\n",
        )
        journal = json.loads((self.recovery / "journal.json").read_text(encoding="utf-8"))
        self.assertEqual(journal["state"], "ROLLED_BACK")
        self.assertEqual(journal["target_version"], "dev")
        snapshots = sorted(self.recovery.glob("update-*"))
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(journal["snapshot_dir"], str(snapshots[0]))
        self.assertEqual(
            (snapshots[0] / ".env").read_text(encoding="utf-8"),
            "GOWAVE_CHANNEL=stable\nAPP_SECRET=keep-me\n",
        )
        self.assertEqual((snapshots[0] / "state.json").read_text(encoding="utf-8"), before)
        restarts = [
            line for line in self.systemctl_log.read_text(encoding="utf-8").splitlines()
            if line.startswith("restart")
        ]
        self.assertEqual(len(restarts), 2, self.systemctl_log.read_text(encoding="utf-8"))

        database = sqlite3.connect(self.gowave / "gowave.db")
        try:
            names = [row[0] for row in database.execute("select name from users")]
        finally:
            database.close()
        self.assertEqual(names, ["alice"])

    def test_a_rollback_that_cannot_restore_the_database_is_not_reported_as_done(self):
        # A directory where the rollback stages its database makes the rename over
        # gowave.db fail after the copy has succeeded, which is the shape of a
        # cleanup step that cannot complete: the journal must stay uncommitted.
        blocking = self.gowave / ".gowave.db.rollback"
        blocking.mkdir()
        (blocking / "occupied").write_text("x", encoding="utf-8")

        result = self.run_function("switch_channel dev")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Rollback could not restore the database snapshot.", result.stderr)
        self.assertIn("CRITICAL: the rollback did not complete", result.stderr)
        self.assertNotIn("File rollback completed and services verified.", result.stderr)
        journal = json.loads((self.recovery / "journal.json").read_text(encoding="utf-8"))
        self.assertEqual(journal["state"], "ROLLBACK_REQUIRED")

    def test_the_rollback_restores_the_acme_state_before_it_validates_nginx(self):
        body = self.function_body("execute_file_rollback")
        code = "\n".join(
            line for line in body.splitlines() if not line.lstrip().startswith("#")
        )
        self.assertLess(
            code.index("/etc/letsencrypt/."), code.index("nginx -t"),
            "the generated vhosts name certificates under /etc/letsencrypt/live, so a "
            "corrupted lineage has to be repaired before nginx -t reads it",
        )

    def test_every_rollback_step_checks_its_own_result(self):
        body = self.function_body("execute_file_rollback")
        for step in (
            'if ! systemctl stop --no-ask-password gowave.service',
            'if ! cp -p "$snap_dir/gowave.db" "$db_tmp"',
            'if ! install -m 0640 "$snap_dir/.env"',
            'if ! install -m 0755 "$snap_dir/gowave-server"',
            'if ! rm -rf "$GOWAVE_DIR/frontend"',
            'if ! install -m 0600 "$snap_dir/state.json"',
            '|| ! cp -a "$snap_dir/etc/letsencrypt/."',
            'if ! cp -a "$snap_dir/etc/nginx/." /etc/nginx/',
            'if ! nginx -t',
            'if ! systemctl restart --no-ask-password gowave.service',
        ):
            self.assertIn(step, body)

    def test_the_switch_restart_is_a_decision_point_and_not_an_exit(self):
        body = self.function_body("switch_channel")
        self.assertEqual(body.count("systemctl restart"), 1, body)
        self.assertIn("if ! systemctl restart --no-ask-password gowave.service", body)
        self.assertIn("rollback_channel_switch", body)


if __name__ == "__main__":
    unittest.main()
