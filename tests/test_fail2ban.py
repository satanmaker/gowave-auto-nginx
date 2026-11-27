#!/usr/bin/env python3
"""Suite nonroot: the Fail2ban jail is judged from the file it writes and reads back.

`configure_fail2ban` has one job the acceptance run cannot see cheaply: turn the
ports the host actually listens on into a jail whose settings are read back from
the running daemon, and undo its own file when that read-back fails. Every case
here runs a disposable host: a temporary root holding the jail file and
`/etc/os-release`, with the commands the helper calls answered by a recorder that
keeps the order. The daemon itself is not started here; a real active jail is
read inside the privileged container by `tests/test_root.py`.
"""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
MANAGED_PY = REPO_ROOT / "assets" / "security" / "managed.py"
JAIL = "etc/fail2ban/jail.d/90-gowave-auto-nginx.local"

STANDALONE_POLICY = "permitrootlogin yes\npasswordauthentication no\n"


def load_managed():
    spec = importlib.util.spec_from_file_location("managed_fail2ban", str(MANAGED_PY))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeHost:
    """Answers the helper's commands in order and remembers every call."""

    def __init__(self, ports=(22,), socket_ports=None, jail_present=True, password=False):
        self.ports = list(ports)
        self.socket_ports = socket_ports
        self.jail_present = jail_present
        self.password = password
        self.calls = []

    def names(self):
        return [args[0] for args in self.calls]

    def discovered_ports(self):
        return list(self.socket_ports) if self.socket_ports is not None else list(self.ports)

    def __call__(self, *args, check=True):
        self.calls.append(args)
        name, rest = args[0], args[1:]
        if name == "/usr/sbin/sshd":
            if rest == ("-t",):
                return ""
            policy = STANDALONE_POLICY.replace(
                "passwordauthentication no", "passwordauthentication yes"
            ) if self.password else STANDALONE_POLICY
            return "\n".join([f"port {port}" for port in self.ports]) + "\n" + policy
        if name == "apt-get":
            return ""
        if name == "systemctl":
            if rest[:2] == ("is-active", "ssh.socket"):
                return "active" if self.socket_ports is not None else "inactive"
            if rest[:2] == ("show", "ssh.socket"):
                return " ".join(f"0.0.0.0:{port} (Stream)" for port in self.socket_ports or [])
            if rest[:1] == ("is-active",):
                return "active"
            if rest[:1] == ("is-enabled",):
                return "enabled"
            return ""
        if name == "fail2ban-client":
            if rest == ("status", "sshd"):
                if not self.jail_present:
                    raise ValueError("Command failed (exit 255): fail2ban-client status sshd")
                return "Status for the jail: sshd"
            if rest[:2] == ("get", "sshd"):
                return {"maxretry": "5", "findtime": "1800", "bantime": "3600"}[rest[2]]
            if rest == ("-d",):
                ports = ",".join(str(port) for port in self.discovered_ports())
                return "\n".join([
                    f"                port = {ports}",
                    "              backend = systemd",
                    "           journalmatch = _SYSTEMD_UNIT=ssh.service + _COMM=sshd"
                    " + _COMM=sshd-session",
                ])
        raise AssertionError(f"unexpected command: {args}")


class TestFail2banJail(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / "etc").mkdir()
        (self.root / "etc/os-release").write_text(
            'ID=ubuntu\nVERSION_ID="24.04"\n', encoding="utf-8"
        )

    def jail(self):
        return (self.root / JAIL).read_text(encoding="utf-8")

    def configure(self, host):
        managed = load_managed()
        with mock.patch.object(managed, "command", host):
            with mock.patch.object(managed.time, "sleep", lambda _seconds: None):
                return managed.configure_fail2ban(root=self.root), host

    def test_the_jail_carries_the_discovered_standalone_ports_and_settings(self):
        result, host = self.configure(FakeHost(ports=(22, 2222)))
        self.assertEqual(result["status"], "configured")
        self.assertEqual(result["ports"], [22, 2222])
        jail = self.jail()
        self.assertTrue(jail.startswith(load_managed().MARKER))
        self.assertIn("port = 22,2222", jail)
        self.assertIn("backend = systemd", jail)
        self.assertIn("_SYSTEMD_UNIT=ssh.service", jail)
        self.assertIn("_COMM=sshd-session", jail)
        self.assertIn("findtime = 1800", jail)
        self.assertIn(("fail2ban-client", "get", "sshd", "maxretry"), host.calls)

    def test_a_socket_activated_port_is_the_one_the_jail_names(self):
        result, host = self.configure(
            FakeHost(ports=(22,), socket_ports=[2222]),
        )
        self.assertEqual(result["ports"], [2222])
        self.assertIn("port = 2222", self.jail())
        self.assertIn(("systemctl", "show", "ssh.socket", "-p", "Listen", "--value"),
                      host.calls)

    def test_a_verified_jail_is_left_in_place(self):
        result, _ = self.configure(FakeHost())
        self.assertEqual(result["status"], "configured")
        self.assertTrue((self.root / JAIL).is_file())

    def test_a_failed_readback_removes_the_jail_it_created(self):
        result, _ = self.configure(FakeHost(jail_present=False))
        self.assertEqual(result["status"], "failed_rolled_back")
        self.assertFalse((self.root / JAIL).exists())
        self.assertIn("status sshd", result["warnings"][0])

    def test_password_authentication_is_reported_and_not_rewritten(self):
        result, _ = self.configure(FakeHost(password=True))
        self.assertEqual(result["status"], "configured")
        self.assertIn("SSH PASSWORD AUTHENTICATION IS ENABLED", result["warnings"][0])
        self.assertNotIn("password", self.jail())

    def test_a_symlinked_jail_is_refused_before_the_daemon_is_touched(self):
        target = self.root / "elsewhere.conf"
        target.write_text("untouched\n", encoding="utf-8")
        (self.root / JAIL).parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, self.root / JAIL)
        host = FakeHost()
        with self.assertRaisesRegex(ValueError, "Unowned project configuration path"):
            self.configure(host)
        self.assertEqual(host.names().count("apt-get"), 0)
        self.assertEqual(target.read_text(encoding="utf-8"), "untouched\n")


if __name__ == "__main__":
    unittest.main()
