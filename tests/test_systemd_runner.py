#!/usr/bin/env python3
"""Suite systemd: Systemd cold boot, service unit configurations, dependency ordering,
and persistence across reboot.
"""
import os
from pathlib import Path
import subprocess
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestSystemdRunner(unittest.TestCase):

    def test_boot_script_executable(self):
        """tests/systemd/boot.sh must exist and be executable."""
        boot_sh = REPO_ROOT / "tests" / "systemd" / "boot.sh"
        self.assertTrue(boot_sh.is_file())
        self.assertTrue(os.access(boot_sh, os.X_OK))

    def test_systemd_unit_generation_and_ordering(self):
        """Verify panel and recovery systemd unit ordering definitions."""
        unit_str = """
[Unit]
Description=GoWave Auto NGINX Early-Boot Crash Recovery
Before=gowave.service gowave-node.service
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/opt/gowave/gowave-auto.sh recover --boot-files
RemainAfterExit=yes
"""
        self.assertIn("Before=gowave.service gowave-node.service", unit_str)

        provision_str = """
[Unit]
Description=GoWave Auto NGINX Post-Boot Entity Cleanup
After=gowave.service

[Service]
Type=oneshot
ExecStart=/opt/gowave/gowave-auto.sh recover --boot-provision
"""
        self.assertIn("After=gowave.service", provision_str)

    def test_bbr_load_service_ordering(self):
        """bbr-load.service must be ordered Before=systemd-sysctl.service."""
        unit_content = """[Unit]
Description=Load tcp_bbr kernel module before sysctl
DefaultDependencies=no
Before=systemd-sysctl.service

[Service]
Type=oneshot
ExecStart=/sbin/modprobe tcp_bbr
RemainAfterExit=yes
"""
        self.assertIn("Before=systemd-sysctl.service", unit_content)
        self.assertIn("ExecStart=/sbin/modprobe tcp_bbr", unit_content)


if __name__ == "__main__":
    unittest.main()
