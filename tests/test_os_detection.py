#!/usr/bin/env python3
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent.parent / "modules" / "os.sh"
OPERATOR_PATH = Path(__file__).resolve().parent.parent / "gowave-auto.sh"


class TestOSDetection(unittest.TestCase):
    def run_bash_fn(self, fn_name, *args, env=None):
        cmd = f'source "{MODULE_PATH}" && {fn_name} ' + " ".join(f'"{a}"' for a in args)
        return subprocess.run(
            ["bash", "-c", cmd],
            capture_output=True,
            text=True,
            env=env or os.environ.copy(),
        )

    def test_check_os_supported_distributions(self):
        supported = [
            ("ubuntu", "24.04"),
            ("ubuntu", "26.04"),
            ("debian", "12"),
            ("debian", "13"),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            os_release = Path(tmpdir) / "os-release"
            for distro, ver in supported:
                for quote in ("", '"', "'"):
                    with self.subTest(distro=distro, version=ver, quote=quote):
                        os_release.write_text(f"ID={quote}{distro}{quote}\nVERSION_ID={quote}{ver}{quote}\n")
                        res = self.run_bash_fn("check_os", str(os_release))
                        self.assertEqual(res.returncode, 0, f"Expected 0 for {distro} {ver}, got: {res.stderr}")

    def test_check_os_unsupported_distributions(self):
        unsupported = [
            ("ubuntu", "22.04"),
            ("ubuntu", "20.04"),
            ("debian", "11"),
            ("debian", "10"),
            ("centos", "7"),
            ("fedora", "39"),
            ("arch", "rolling"),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            os_release = Path(tmpdir) / "os-release"
            for distro, ver in unsupported:
                with self.subTest(distro=distro, version=ver):
                    os_release.write_text(f'ID="{distro}"\nVERSION_ID="{ver}"\n')
                    res = self.run_bash_fn("check_os", str(os_release))
                    self.assertNotEqual(res.returncode, 0, f"Expected non-zero for {distro} {ver}")
                    self.assertIn("Unsupported OS", res.stderr)

    def test_check_os_missing_file_and_injection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            marker = Path(tmpdir) / "pwned"
            os_release = Path(tmpdir) / "os-release"
            os_release.write_text(f'ID=$(touch "{marker}")\nVERSION_ID="12"\n')

            res = self.run_bash_fn("check_os", str(os_release))
            self.assertNotEqual(res.returncode, 0)
            self.assertFalse(marker.exists(), "Command injection vulnerability detected in check_os!")

            # Missing file
            missing = Path(tmpdir) / "nonexistent"
            res = self.run_bash_fn("check_os", str(missing))
            self.assertNotEqual(res.returncode, 0)

    def test_nginx_http2_syntax_detection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_bin = Path(tmpdir) / "fake-nginx"

            # Test < 1.25.1 (e.g. 1.24.0, 1.22.1)
            for legacy_ver in ("1.24.0", "1.22.1", "1.20.0"):
                fake_bin.write_text(f'#!/bin/sh\necho "nginx version: nginx/{legacy_ver}" >&2\n')
                fake_bin.chmod(0o755)
                res = self.run_bash_fn("render_nginx_listen_ssl_http2", "127.0.0.1:7443", "proxy_protocol", str(fake_bin))
                self.assertEqual(res.returncode, 0)
                self.assertIn("listen 127.0.0.1:7443 ssl http2 proxy_protocol;", res.stdout)
                self.assertNotIn("http2 on;", res.stdout)

            # Test >= 1.25.1 (e.g. 1.25.1, 1.26.3, 1.27.0)
            for modern_ver in ("1.25.1", "1.26.3", "1.27.0"):
                fake_bin.write_text(f'#!/bin/sh\necho "nginx version: nginx/{modern_ver}" >&2\n')
                fake_bin.chmod(0o755)
                res = self.run_bash_fn("render_nginx_listen_ssl_http2", "127.0.0.1:7443", "proxy_protocol", str(fake_bin))
                self.assertEqual(res.returncode, 0)
                self.assertIn("listen 127.0.0.1:7443 ssl proxy_protocol;", res.stdout)
                self.assertIn("http2 on;", res.stdout)

    def test_check_kernel_ipv6(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            inet6_file = Path(tmpdir) / "if_inet6"

            # Present and non-empty
            inet6_file.write_text("00000000000000000000000000000001 01 80 10 80 lo\n")
            res = self.run_bash_fn("check_kernel_ipv6", str(inet6_file))
            self.assertEqual(res.returncode, 0)

            # Empty file
            inet6_file.write_text("")
            res = self.run_bash_fn("check_kernel_ipv6", str(inet6_file))
            self.assertNotEqual(res.returncode, 0)

            # Missing file
            res = self.run_bash_fn("check_kernel_ipv6", str(Path(tmpdir) / "no_file"))
            self.assertNotEqual(res.returncode, 0)

    def test_configure_debian_security_apt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            apt_dir = Path(tmpdir) / "apt.conf.d"
            os_release = Path(tmpdir) / "os-release"

            # Debian 12
            os_release.write_text('ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n')
            res = self.run_bash_fn("configure_debian_security_apt", str(apt_dir), str(os_release))
            self.assertEqual(res.returncode, 0)
            conf = (apt_dir / "99zz-gowave-auto-nginx").read_text()
            self.assertIn("origin=Debian,label=Debian-Security,codename=bookworm-security", conf)
            self.assertIn('Unattended-Upgrade::Automatic-Reboot "false";', conf)

            # Ubuntu 24.04
            os_release.write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
            res = self.run_bash_fn("configure_debian_security_apt", str(apt_dir), str(os_release))
            self.assertEqual(res.returncode, 0)
            conf = (apt_dir / "99zz-gowave-auto-nginx").read_text()
            self.assertIn('Unattended-Upgrade::Automatic-Reboot "false";', conf)

    def test_install_bootstraps_tools_before_validating_arguments(self):
        """cmd_install validates arguments and probes the cover apex before prerequisites."""
        script = OPERATOR_PATH.read_text(encoding="utf-8")
        start = script.index("cmd_install() {")
        body = script[start:start + 4000]
        bootstrap = body.index("bootstrap_early_tools || return 1")
        validator = body.index("python3 - \"$panel_domain\"")
        cover = body.index("server_ip=$(resolve_panel_ipv4)")
        self.assertLess(bootstrap, validator)
        self.assertLess(bootstrap, cover)

    def test_bootstrap_packages_are_part_of_the_prerequisite_inventory(self):
        required = set(self.run_bash_fn("get_required_packages").stdout.split())
        bootstrap = set(self.run_bash_fn("get_bootstrap_packages").stdout.split())
        self.assertTrue(bootstrap)
        self.assertLessEqual(bootstrap, required)
        self.assertIn("python3", bootstrap)
        self.assertIn("iproute2", bootstrap)

    def test_required_packages_inventory(self):
        res = self.run_bash_fn("get_required_packages")
        self.assertEqual(res.returncode, 0)
        pkgs = set(res.stdout.strip().splitlines())
        expected = {
            "nginx-full",
            "libnginx-mod-stream",
            "certbot",
            "python3",
            "python3-systemd",
            "sqlite3",
            "curl",
            "tar",
            "gzip",
            "openssl",
            "ufw",
            "fail2ban",
            "systemd-resolved",
            "iproute2",
            "ca-certificates",
            "openssh-client",
        }
        self.assertEqual(pkgs, expected)


if __name__ == "__main__":
    unittest.main()
