#!/usr/bin/env python3
"""Suite nonroot: unattended security updates are read back, not assumed.

`configure_apt` writes the project's APT policy and two timer drop-ins, restarts
the timers and then reads the effective package policy and timer schedule back.
Each case here runs a disposable host: a temporary root holding those files and
`/etc/os-release`, with the commands the helper calls answered by a recorder.
What the helper would read from the running package manager is the fake's
answer, so a timer that is not active, or a policy that re-enables reboots, is
proven to fail the step and undo the files it wrote.
"""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
MANAGED_PY = REPO_ROOT / "assets" / "security" / "managed.py"
POLICY = "etc/apt/apt.conf.d/zz-gowave-auto-nginx"
TIMERS = {
    "apt-daily.timer": "etc/systemd/system/apt-daily.timer.d/90-gowave-auto-nginx.conf",
    "apt-daily-upgrade.timer": "etc/systemd/system/apt-daily-upgrade.timer.d/90-gowave-auto-nginx.conf",
}

DUMP = """APT::Periodic::Enable "1";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Origins-Pattern:: "origin=Ubuntu,archive=${distro_codename}-security";
Unattended-Upgrade::Allowed-Origins:: "origin=Example,label=Extra";
"""


def load_managed():
    spec = importlib.util.spec_from_file_location("managed_apt", str(MANAGED_PY))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeHost:
    def __init__(self, dump=DUMP, timer_state=None):
        self.dump = dump
        self.timer_state = timer_state or {}
        self.calls = []

    def names(self):
        return [args[0] for args in self.calls]

    def __call__(self, *args, check=True):
        self.calls.append(args)
        name, rest = args[0], args[1:]
        if name == "apt-config":
            return self.dump
        if name == "apt-get":
            return ""
        if name == "systemctl":
            if rest[:1] == ("is-active",):
                state = self.timer_state.get(rest[-1], "active")
                if check and rest[:2] == ("is-active", "--quiet") and state != "active":
                    raise ValueError(f"Command failed (exit 3): systemctl is-active --quiet {rest[-1]}")
                return state
            if rest[:1] == ("is-enabled",):
                return "enabled"
            if rest[:1] == ("show",):
                hour = {"apt-daily.timer": "02:30", "apt-daily-upgrade.timer": "02:50"}.get(rest[1], "")
                return (f"TimersCalendar={{ OnCalendar=*-*-* {hour}:00 }}\n"
                        "RandomizedDelayUSec=0")
            return ""
        raise AssertionError(f"unexpected command: {args}")


class TestUnattendedUpdates(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / "etc").mkdir()
        (self.root / "etc/os-release").write_text('ID=ubuntu\nVERSION_ID="24.04"\n', encoding="utf-8")

    def configure(self, host):
        managed = load_managed()
        with mock.patch.object(managed, "command", host):
            return managed.configure_apt(root=self.root), host

    def test_the_package_policy_and_both_timers_are_applied_and_read_back(self):
        result, host = self.configure(FakeHost())
        self.assertEqual(result["status"], "configured", result)
        self.assertIn("unattended-upgrades", [arg for call in host.calls for arg in call])
        policy = (self.root / POLICY).read_text(encoding="utf-8")
        self.assertIn("Unattended-Upgrade::Automatic-Reboot \"false\";", policy)
        self.assertIn("origin=Ubuntu,archive=${distro_codename}-security", policy)
        self.assertIn("OnCalendar=*-*-* 02:30:00", (self.root / TIMERS["apt-daily.timer"]).read_text())
        self.assertIn("OnCalendar=*-*-* 02:50:00",
                      (self.root / TIMERS["apt-daily-upgrade.timer"]).read_text())
        for service in TIMERS:
            self.assertIn(("systemctl", "enable", service), host.calls)
            self.assertIn(("systemctl", "restart", service), host.calls)

    def test_an_inactive_timer_is_not_verified_and_the_files_are_undone(self):
        result, _ = self.configure(FakeHost(timer_state={"apt-daily.timer": "inactive"}))
        self.assertEqual(result["status"], "failed_rolled_back")
        self.assertIn("APT failed", result["warnings"][0])
        self.assertFalse((self.root / POLICY).exists())
        for path in TIMERS.values():
            self.assertFalse((self.root / path).exists())

    def test_an_automatic_reboot_policy_is_not_verified(self):
        result, _ = self.configure(
            FakeHost(dump=DUMP.replace('Automatic-Reboot "false"', 'Automatic-Reboot "true"')),
        )
        self.assertEqual(result["status"], "failed_rolled_back")
        self.assertIn("Automatic reboot", result["warnings"][0])

    def test_an_administrator_origin_stays_in_the_effective_policy(self):
        # The helper reads the host's origins before writing and refuses when
        # its own required origin disappears; the administrator's entry is not
        # in the project file and is never rewritten by this step.
        result, host = self.configure(FakeHost())
        self.assertEqual(result["status"], "configured")
        self.assertIn("origin=Example,label=Extra", host.dump)
        written = sorted(str(path.relative_to(self.root)) for path in self.root.rglob("*")
                         if path.is_file())
        self.assertEqual(written, ["etc/apt/apt.conf.d/zz-gowave-auto-nginx",
                                   "etc/os-release",
                                   *sorted(TIMERS.values())])

    def test_the_policy_file_sorts_after_a_disabling_drop_in(self):
        # APT reads apt.conf.d in byte order and a later file overrides an
        # earlier one. The official Ubuntu/Debian container images ship
        # `docker-disable-periodic-update`, which sets APT::Periodic::Enable "0";
        # its leading `d` sorts after `9`, so the old `99zz-…` name lost and the
        # effective policy stayed disabled. The managed file must sort last among
        # any entry that can disable the schedule, so its basename has to follow
        # `docker-…` (and the previous `99zz-…`) in byte order.
        managed = Path(POLICY).name
        for overriding in ("docker-disable-periodic-update", "99zz-gowave-auto-nginx"):
            self.assertGreater(managed, overriding,
                               f"{managed} must sort after {overriding} for APT to apply it last")

    def test_a_symlinked_policy_is_refused_before_a_package_is_touched(self):
        target = self.root / "elsewhere.conf"
        target.write_text("untouched\n", encoding="utf-8")
        (self.root / POLICY).parent.mkdir(parents=True)
        os.symlink(target, self.root / POLICY)
        host = FakeHost()
        with self.assertRaisesRegex(ValueError, "Unowned project configuration path"):
            self.configure(host)
        self.assertNotIn("apt-get", host.names())
        self.assertEqual(target.read_text(encoding="utf-8"), "untouched\n")

    def test_both_installers_run_the_shared_step(self):
        master = (REPO_ROOT / "gowave-auto.sh").read_text(encoding="utf-8")
        worker = (REPO_ROOT / "gowave-node-auto.sh").read_text(encoding="utf-8")
        self.assertIn("configure_unattended_upgrades", master)
        self.assertIn("--configure-apt", worker)
        self.assertIn("configure_worker_security_updates </dev/null", worker)


if __name__ == "__main__":
    unittest.main()
