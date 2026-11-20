#!/usr/bin/env python3
"""Suite nonroot: temporary-access bootstrap for worker onboarding.

The remote side is stubbed at the `ssh_bootstrap_exec` seam, so the test
observes the order of timer, key and revoke payloads without a network.
"""
import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SSH_BOOTSTRAP_SH = REPO_ROOT / "modules" / "ssh_bootstrap.sh"

SOURCE = f"source {shlex.quote(str(SSH_BOOTSTRAP_SH))}\n"


def bash(script, stdin="", env=None):
    merged = dict(os.environ)
    merged.pop("GOWAVE_SSH_PASSWORD_FILE", None)
    merged.pop("GOWAVE_SSH_FINGERPRINT", None)
    merged.update(env or {})
    return subprocess.run(
        ["bash", "-c", script],
        input=stdin,
        text=True,
        capture_output=True,
        env=merged,
        timeout=120,
    )


class TestFingerprintConfirmation(unittest.TestCase):
    def test_an_exact_fingerprint_matches_and_a_different_one_does_not(self):
        result = bash(
            SOURCE
            + "ssh_bootstrap_fingerprint_matches 'SHA256:abc' 'SHA256:abc' && echo SAME\n"
            "ssh_bootstrap_fingerprint_matches ' SHA256:abc ' 'SHA256:abc' && echo TRIMMED\n"
            "if ssh_bootstrap_fingerprint_matches 'SHA256:abc' 'SHA256:abd'; then echo BAD_ACCEPT;"
            " else echo DIFF; fi\n"
            "if ssh_bootstrap_fingerprint_matches '' 'SHA256:abc'; then echo BAD_ACCEPT; else echo EMPTY; fi\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["SAME", "TRIMMED", "DIFF", "EMPTY"])

    def test_a_mismatch_is_refused_with_a_named_reason(self):
        result = bash(
            SOURCE
            + "GOWAVE_SSH_FINGERPRINT='SHA256:typed'\n"
            "if ssh_bootstrap_confirm_fingerprint worker.example.com 'SHA256:scanned';"
            " then echo ACCEPTED; else echo REFUSED; fi\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("REFUSED", result.stdout)
        self.assertIn("worker.example.com", result.stderr)
        self.assertIn("does not match", result.stderr)

    def test_the_environment_fingerprint_is_used_without_a_prompt(self):
        result = bash(
            SOURCE
            + "GOWAVE_SSH_FINGERPRINT='SHA256:typed'\n"
            "ssh_bootstrap_confirm_fingerprint worker.example.com 'SHA256:typed' && echo ACCEPTED\n",
            stdin="",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "ACCEPTED")


class TestHostKeyScan(unittest.TestCase):
    """OpenSSH 9.x answers ssh-keyscan with a banner comment above the key line."""

    BANNER = "# 127.0.0.1:2222 SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20"

    def _scan(self, lines, tail=""):
        with tempfile.TemporaryDirectory() as directory:
            keyscan = Path(directory) / "ssh-keyscan"
            body = "".join(f"printf '%s\\n' {shlex.quote(line)}\n" for line in lines)
            keyscan.write_text("#!/bin/sh\n" + body, encoding="utf-8")
            keyscan.chmod(0o755)
            return bash(
                SOURCE + f"ssh_bootstrap_scan 127.0.0.1 2222{tail}\n",
                env={"PATH": f"{directory}:{os.environ['PATH']}"},
            )

    def test_the_banner_comment_is_not_mistaken_for_the_key(self):
        key_line = "[127.0.0.1]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITESTKEY"
        result = self._scan([self.BANNER, key_line])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, key_line)

    def test_a_comment_only_answer_is_refused(self):
        result = self._scan([self.BANNER])
        self.assertNotEqual(result.returncode, 0, "a banner is not a host key")
        self.assertEqual(result.stdout, "")

    def test_the_scanned_line_yields_a_fingerprint(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "id_ed25519"
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "verify", "-f", str(key)],
                check=True,
                timeout=60,
            )
            pubkey = Path(str(key) + ".pub").read_text(encoding="utf-8").strip()
        result = self._scan([self.BANNER, f"[127.0.0.1]:2222 {pubkey}"], tail=" | ssh_bootstrap_fingerprint")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout.strip(), r"^SHA256:[A-Za-z0-9+/=]+$")


class TestBootstrapPayloads(unittest.TestCase):
    def test_the_timer_is_installed_enabled_and_bounded_to_two_hours(self):
        result = bash(
            SOURCE
            + "ssh_bootstrap_render_timer_payload 'gowave-wizard-abc123' 'abc123'\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = result.stdout
        self.assertIn("OnActiveSec=115min", payload)
        self.assertIn("systemctl enable --now gowave-temp-key-abc123.timer", payload)
        self.assertIn("ExecStart=/usr/local/sbin/gowave-temp-key-revoke-abc123 gowave-wizard-abc123 abc123", payload)
        self.assertIn("grep -vF -- \"$marker\"", payload)
        self.assertNotIn("authorized_keys.XXXXXX", payload)
        self.assertNotIn("ssh-ed25519 AAAA", payload)

    def test_the_key_entry_carries_its_expiry_and_marker(self):
        result = bash(
            SOURCE
            + "ssh_bootstrap_key_entry 'ssh-ed25519 AAAATEST key' 'gowave-wizard-abc123' '202611191200'\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            'expiry-time="202611191200" ssh-ed25519 AAAATEST key gowave-wizard-abc123',
        )

    def test_the_key_payload_appends_atomically(self):
        entry = 'expiry-time="202611191200" ssh-ed25519 AAAATEST gowave-wizard-abc123'
        result = bash(SOURCE + f"ssh_bootstrap_render_key_payload {shlex.quote(entry)}\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = result.stdout
        self.assertIn(entry, payload)
        self.assertIn("mktemp /root/.ssh/authorized_keys.XXXXXX", payload)
        self.assertIn('mv "$tmp" /root/.ssh/authorized_keys', payload)
        self.assertIn("chmod 600 /root/.ssh/authorized_keys", payload)

    def test_the_revoke_payload_removes_the_marker_and_the_timer(self):
        result = bash(
            SOURCE
            + "ssh_bootstrap_render_revoke_payload 'gowave-wizard-abc123' 'abc123'\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = result.stdout
        self.assertIn("/usr/local/sbin/gowave-temp-key-revoke-abc123", payload)
        self.assertIn("'gowave-wizard-abc123' 'abc123'", payload)
        self.assertNotIn("mktemp /root/.ssh/authorized_keys", payload)

    def test_the_timer_id_is_derived_from_the_host(self):
        result = bash(
            SOURCE
            + "printf 'a=%s\\n' \"$(ssh_bootstrap_timer_id worker.example.com)\"\n"
            "printf 'b=%s\\n' \"$(ssh_bootstrap_timer_id worker.example.com)\"\n"
            "printf 'c=%s\\n' \"$(ssh_bootstrap_timer_id other.example.com)\"\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        first = lines[0].split("=", 1)[1]
        self.assertEqual(lines[1].split("=", 1)[1], first)
        self.assertNotEqual(lines[2].split("=", 1)[1], first)
        self.assertRegex(first, r"^[0-9a-f]{12}$")


class TestPasswordHandling(unittest.TestCase):
    def test_a_0600_password_file_is_used_as_is(self):
        with tempfile.TemporaryDirectory() as directory:
            password_file = Path(directory) / "password"
            password_file.write_text("s3cret\n", encoding="utf-8")
            password_file.chmod(0o600)
            result = bash(
                SOURCE
                + f"GOWAVE_SSH_TEMP_ROOT={shlex.quote(directory)}\n"
                + f"GOWAVE_SSH_PASSWORD_FILE={shlex.quote(str(password_file))}\n"
                "ssh_bootstrap_prepare_password worker.example.com\n",
                env={"GOWAVE_SSH_PASSWORD_FILE": str(password_file)},
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, str(password_file))

    def test_a_0644_password_file_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            password_file = Path(directory) / "password"
            password_file.write_text("s3cret\n", encoding="utf-8")
            password_file.chmod(0o644)
            result = bash(
                SOURCE
                + f"GOWAVE_SSH_TEMP_ROOT={shlex.quote(directory)}\n"
                + f"GOWAVE_SSH_PASSWORD_FILE={shlex.quote(str(password_file))}\n"
                "if ssh_bootstrap_prepare_password worker.example.com; then echo ACCEPTED;"
                " else echo REFUSED; fi\n",
                env={"GOWAVE_SSH_PASSWORD_FILE": str(password_file)},
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("REFUSED", result.stdout)
        self.assertIn("0600", result.stderr)

    def test_an_interactive_password_is_read_once_into_a_0600_file(self):
        with tempfile.TemporaryDirectory() as directory:
            result = bash(
                SOURCE
                + f"GOWAVE_SSH_TEMP_ROOT={shlex.quote(directory)}\n"
                "unset GOWAVE_SSH_PASSWORD_FILE\n"
                "ssh_bootstrap_prepare_password worker.example.com\n"
                "printf 'file_mode=%s\\n' \"$(stat -c '%a' \"$GOWAVE_SSH_TEMP_ROOT/password\")\"\n"
                "if [ -n \"${GOWAVE_SSH_PASSWORD:-}\" ]; then echo LEAKED_GLOBAL; else echo NO_GLOBAL; fi\n",
                stdin="s3cret\n",
            )
            stored = Path(directory) / "password"
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("file_mode=600", result.stdout)
            self.assertIn("NO_GLOBAL", result.stdout)
            self.assertEqual(stored.read_text(encoding="utf-8"), "s3cret")
        self.assertNotIn("s3cret", result.stdout)
        self.assertNotIn("s3cret", result.stderr)

    def test_the_askpass_helper_is_private_and_reads_the_file(self):
        with tempfile.TemporaryDirectory() as directory:
            password_file = Path(directory) / "password"
            password_file.write_text("s3cret\n", encoding="utf-8")
            password_file.chmod(0o600)
            result = bash(
                SOURCE
                + f"GOWAVE_SSH_TEMP_ROOT={shlex.quote(directory)}\n"
                + f"helper=$(ssh_bootstrap_askpass {shlex.quote(str(password_file))})\n"
                "printf 'helper=%s\\n' \"$helper\"\n"
                "printf 'mode=%s\\n' \"$(stat -c '%a' \"$helper\")\"\n"
                'cat "$helper"\n'
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("mode=700", result.stdout)
        self.assertIn(f"exec cat '{password_file}'", result.stdout)

    def test_the_spawned_ssh_command_line_never_carries_the_password(self):
        with tempfile.TemporaryDirectory() as directory:
            password_file = Path(directory) / "password"
            password_file.write_text("s3cret\n", encoding="utf-8")
            password_file.chmod(0o600)
            known_hosts = Path(directory) / "known_hosts"
            known_hosts.write_text("", encoding="utf-8")
            payload = Path(directory) / "payload.sh"
            payload.write_text("true\n", encoding="utf-8")
            shim_dir = Path(directory) / "bin"
            shim_dir.mkdir()
            shim = shim_dir / "ssh"
            shim.write_text(
                '#!/bin/sh\nprintf "%s\\n" "$@" > "$SSH_ARGV_LOG"\ncat > /dev/null\n',
                encoding="utf-8",
            )
            shim.chmod(0o755)
            argv_log = Path(directory) / "argv.log"
            result = bash(
                SOURCE
                + f"GOWAVE_SSH_TEMP_ROOT={shlex.quote(directory)}\n"
                + f"GOWAVE_SSH_KNOWN_HOSTS={shlex.quote(str(known_hosts))}\n"
                + f"ssh_bootstrap_exec worker.example.com 22 {shlex.quote(str(password_file))}"
                f" {shlex.quote(str(payload))}\n",
                env={
                    "PATH": f"{shim_dir}:{os.environ['PATH']}",
                    "SSH_ARGV_LOG": str(argv_log),
                    "GOWAVE_SSH_PASSWORD_FILE": str(password_file),
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            argv = argv_log.read_text(encoding="utf-8")
            self.assertIn("worker.example.com", argv)
            self.assertNotIn("s3cret", argv)
            self.assertNotIn(str(password_file), argv)


class TestTimerGate(unittest.TestCase):
    def test_a_failing_timer_aborts_before_any_key_is_authorised(self):
        with tempfile.TemporaryDirectory() as directory:
            password_file = Path(directory) / "password"
            password_file.write_text("s3cret\n", encoding="utf-8")
            password_file.chmod(0o600)
            log = Path(directory) / "remote.log"
            result = bash(
                SOURCE
                + f"GOWAVE_SSH_TEMP_ROOT={shlex.quote(directory)}\n"
                + f"GOWAVE_SSH_KEY={shlex.quote(str(Path(directory) / 'id_ed25519'))}\n"
                "printf 'ssh-ed25519 AAAATEST gowave-wizard\\n' > \"$GOWAVE_SSH_KEY.pub\"\n"
                "ssh_bootstrap_exec() { printf 'CALL\\n' >> \"$REMOTE_LOG\"; cat \"$4\" >> \"$REMOTE_LOG\";"
                " return 1; }\n"
                + f"if ssh_bootstrap_authorise worker.example.com 22 {shlex.quote(str(password_file))};"
                " then echo AUTHORISED; else echo REFUSED; fi\n"
                "printf 'calls=%s\\n' \"$(grep -c '^CALL$' \"$REMOTE_LOG\")\"\n"
                "if grep -q 'authorized_keys.XXXXXX' \"$REMOTE_LOG\"; then echo KEY_SENT; else echo NO_KEY; fi\n",
                env={"REMOTE_LOG": str(log)},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("REFUSED", result.stdout)
            self.assertIn("calls=1", result.stdout)
            self.assertIn("NO_KEY", result.stdout)
            self.assertIn("no key was authorised", result.stderr)


class TestOnboardingLifecycle(unittest.TestCase):
    STUB = (
        "ssh_bootstrap_prepare_key() { GOWAVE_SSH_TEMP_ROOT=$STUB_ROOT;"
        " GOWAVE_SSH_KEY=$STUB_ROOT/id; : > \"$GOWAVE_SSH_KEY.pub\";"
        " GOWAVE_SSH_KNOWN_HOSTS=$STUB_ROOT/known_hosts; : > \"$GOWAVE_SSH_KNOWN_HOSTS\"; }\n"
        "ssh_bootstrap_scan() { echo 'worker.example.com ssh-ed25519 AAAA'; }\n"
        "ssh_bootstrap_fingerprint() { echo 'SHA256:test'; }\n"
        "ssh_bootstrap_confirm_fingerprint() { return 0; }\n"
        "ssh_bootstrap_prepare_password() { echo \"$STUB_PASSWORD\"; }\n"
        "ssh_bootstrap_authorise() { printf 'AUTHORISE\\n' >> \"$STUB_LOG\"; return 0; }\n"
        "ssh_bootstrap_revoke() { printf 'REVOKE\\n' >> \"$STUB_LOG\"; return 0; }\n"
        "ssh_bootstrap_start_agent() { GOWAVE_SSH_AGENT_SOCK=stub; return 0; }\n"
        "ssh_bootstrap_stop_agent() { printf 'AGENT_STOP\\n' >> \"$STUB_LOG\"; }\n"
        "wizard_resolve_ipv4() { echo 203.0.113.7; }\n"
        "cmd_node() { printf 'NODE %s known_hosts=%s\\n' \"$*\" \"$SSH_KNOWN_HOSTS\" >> \"$STUB_LOG\";"
        " cat \"$GOWAVE_SSH_KNOWN_HOSTS\" >> \"$STUB_LOG\"; return \"${NODE_RC:-0}\"; }\n"
    )

    def _onboard(self, node_rc, vision="vision.example.com"):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "stub.log"
            password = Path(directory) / "password"
            password.write_text("s3cret\n", encoding="utf-8")
            password.chmod(0o600)
            vision_arg = f" {vision}" if vision else ""
            result = bash(
                SOURCE
                + self.STUB
                + "if ssh_bootstrap_onboard_one worker.example.com cdn.example.com"
                + vision_arg
                + "; then echo RESULT_OK; else echo RESULT_FAILED; fi\n",
                env={
                    "STUB_ROOT": directory,
                    "STUB_LOG": str(log),
                    "STUB_PASSWORD": str(password),
                    "NODE_RC": str(node_rc),
                },
            )
            return result, log.read_text(encoding="utf-8") if log.exists() else ""

    def test_a_successful_registration_revokes_the_temporary_access(self):
        result, log = self._onboard(0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("RESULT_OK", result.stdout)
        self.assertIn("AUTHORISE", log)
        self.assertIn(
            "NODE add --vision-domain vision.example.com worker.example.com 203.0.113.7"
            " worker.example.com cdn.example.com",
            log,
        )
        self.assertIn("REVOKE", log)
        self.assertIn("AGENT_STOP", log)
        self.assertLess(log.index("AUTHORISE"), log.index("NODE add"))
        self.assertLess(log.index("NODE add"), log.index("REVOKE"))
        self.assertIn("worker.example.com ssh-ed25519 AAAA", log)
        self.assertIn("203.0.113.7 ssh-ed25519 AAAA", log)

    def test_a_failed_registration_still_revokes_the_temporary_access(self):
        result, log = self._onboard(1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("RESULT_FAILED", result.stdout)
        self.assertIn("NODE add", log)
        self.assertIn("REVOKE", log)
        self.assertIn("AGENT_STOP", log)
        self.assertIn("registration failed", result.stderr)

    def test_without_vision_the_node_add_carries_no_vision_flag(self):
        result, log = self._onboard(0, vision="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("NODE add worker.example.com", log)
        self.assertNotIn("--vision-domain", log)


if __name__ == "__main__":
    unittest.main()
