#!/usr/bin/env python3
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANAGED_PY = REPO_ROOT / "assets" / "security" / "managed.py"
SECURITY_SH = REPO_ROOT / "modules" / "security.sh"


class TestSecurityModule(unittest.TestCase):
    def test_ssh_ports_parsing(self):
        # Import managed.py directly
        import importlib.util
        spec = importlib.util.spec_from_file_location("managed", str(MANAGED_PY))
        managed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(managed)

        # Standard sshd -T
        effective = "port 22\naddressfamily any\n"
        self.assertEqual(managed.ssh_ports(effective), [22])

        # Multiple ports
        effective_multi = "port 22\nport 2222\n"
        self.assertEqual(managed.ssh_ports(effective_multi), [22, 2222])

        # Socket activation listen
        socket_listen = "[::]:2200 (Stream) 0.0.0.0:2200 (Stream)"
        self.assertEqual(managed.ssh_ports(effective, socket_listen), [2200])

        # Invalid port
        with self.assertRaises(ValueError):
            managed.ssh_ports("port 70000\n")

    def test_password_warning(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("managed", str(MANAGED_PY))
        managed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(managed)

        self.assertTrue(managed.password_warning("passwordauthentication yes\n"))
        self.assertFalse(managed.password_warning("passwordauthentication no\nkbdinteractiveauthentication no\n"))

    def test_apt_config_automatic_reboot_false(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("managed", str(MANAGED_PY))
        managed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(managed)

        ubuntu_apt = managed.apt_config("ubuntu")
        self.assertIn('Unattended-Upgrade::Automatic-Reboot "false";', ubuntu_apt)
        self.assertIn('archive=${distro_codename}-security', ubuntu_apt)

        debian_apt = managed.apt_config("debian")
        self.assertIn('Unattended-Upgrade::Automatic-Reboot "false";', debian_apt)
        self.assertIn('origin=Debian,label=Debian-Security', debian_apt)

    def test_preflight_supported_os(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("managed", str(MANAGED_PY))
        managed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(managed)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "etc").mkdir()
            os_release = root / "etc" / "os-release"

            # Debian 12
            os_release.write_text('ID=debian\nVERSION_ID="12"\n')
            self.assertEqual(managed.preflight(root=root, files=(), services=()), "debian")

            # Debian 13
            os_release.write_text('ID=debian\nVERSION_ID="13"\n')
            self.assertEqual(managed.preflight(root=root, files=(), services=()), "debian")

            # Ubuntu 24.04
            os_release.write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
            self.assertEqual(managed.preflight(root=root, files=(), services=()), "ubuntu")

            # Ubuntu 26.04
            os_release.write_text('ID=ubuntu\nVERSION_ID="26.04"\n')
            self.assertEqual(managed.preflight(root=root, files=(), services=()), "ubuntu")

            # Unsupported
            os_release.write_text('ID=ubuntu\nVERSION_ID="22.04"\n')
            with self.assertRaises(ValueError):
                managed.preflight(root=root, files=(), services=())

    def test_dns_drop_in_directory_stays_readable_under_strict_umask(self):
        """systemd-resolved runs as systemd-resolve and cannot read a 0700 drop-in dir."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("managed", str(MANAGED_PY))
        managed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(managed)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "etc").mkdir()
            txn = managed.Transaction(root=root, services=(), files=())
            previous_umask = os.umask(0o077)
            try:
                txn.write("/etc/systemd/resolved.conf.d/90-gowave-auto-nginx.conf", managed.DOT)
            finally:
                os.umask(previous_umask)
                txn.temp.cleanup()

            drop_in_dir = root / "etc" / "systemd" / "resolved.conf.d"
            self.assertEqual(drop_in_dir.stat().st_mode & 0o777, 0o755)
            self.assertEqual(
                (drop_in_dir / "90-gowave-auto-nginx.conf").stat().st_mode & 0o777, 0o644
            )

    def test_bbr_and_mtu_configuration(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            sysctl_file = tmp / "99-gowave.conf"
            bbr_service = tmp / "bbr-load.service"
            state_file = tmp / "state.json"
            original_state = {
                "schemaVersion": 2,
                "nodes": [{"name": "worker-1", "uuid": "node-1"}],
                "squadUuid": "squad-1",
            }
            state_file.write_text(json.dumps(original_state))

            cmd = f'source "{SECURITY_SH}" && configure_bbr_and_mtu "{state_file}" "{sysctl_file}" "{bbr_service}"'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)

            # Check MTU probing directive
            sysctl_content = sysctl_file.read_text()
            self.assertIn("net.ipv4.tcp_mtu_probing = 1", sysctl_content)

            # Check systemd unit ordering Before=systemd-sysctl.service
            service_content = bbr_service.read_text()
            self.assertIn("Before=systemd-sysctl.service", service_content)
            self.assertIn("ConditionVirtualization=!container", service_content)

            # Check state.json records congestionControl and has mode 0600
            if state_file.exists():
                data = json.loads(state_file.read_text())
                self.assertIn(data.get("congestionControl"), ("bbr", "cubic"))
                self.assertEqual(data["nodes"], original_state["nodes"])
                self.assertEqual(data["squadUuid"], original_state["squadUuid"])
                self.assertEqual(oct(state_file.stat().st_mode & 0o777), "0o600")

    def test_bbr_state_update_refuses_corrupt_existing_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            state_file = tmp / "state.json"
            sysctl_file = tmp / "99-gowave.conf"
            bbr_service = tmp / "bbr-load.service"
            corrupt = "{broken state"
            state_file.write_text(corrupt)

            cmd = f'source "{SECURITY_SH}" && configure_bbr_and_mtu "{state_file}" "{sysctl_file}" "{bbr_service}"'
            result = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(state_file.read_text(), corrupt)

    def test_log_rotation_and_journal_cap(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            logrotate_file = tmp / "gowave-nginx"
            journal_file = tmp / "99-gowave.conf"

            cmd = f'source "{SECURITY_SH}" && configure_log_rotation "{logrotate_file}" "{journal_file}"'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)

            # Check logrotate content
            logrotate_content = logrotate_file.read_text()
            self.assertIn("daily", logrotate_content)
            self.assertIn("rotate 7", logrotate_content)
            self.assertIn("compress", logrotate_content)

            # Check journal cap SystemMaxUse=100M
            journal_content = journal_file.read_text()
            self.assertIn("SystemMaxUse=100M", journal_content)


if __name__ == "__main__":
    unittest.main()
