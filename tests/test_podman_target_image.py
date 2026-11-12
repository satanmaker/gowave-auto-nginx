#!/usr/bin/env python3
"""Suite nonroot: the E2E target image is a clean, systemd-capable host."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import target_image  # noqa: E402


class FakePodman:
    def __init__(self, probe_output: str = "init=systemd\nsystemd=systemd 255 (255.4-1)\nsshd=active\n") -> None:
        self.builds = []
        self.execs = []
        self.probe_output = probe_output

    def build(self, tag, base_alias, containerfile, context_dir):
        self.builds.append({
            "tag": tag,
            "base_alias": base_alias,
            "containerfile": Path(containerfile),
            "context_dir": Path(context_dir),
        })
        return tag

    def exec(self, container, argv):
        self.execs.append((container, list(argv)))
        return subprocess.CompletedProcess(argv, 0, self.probe_output, "")


class TestPodmanTargetImage(unittest.TestCase):
    def test_target_distributions_match_the_supported_matrix(self):
        self.assertEqual(
            sorted(target_image.DISTRIBUTIONS),
            ["debian-12", "debian-13", "ubuntu-24.04", "ubuntu-26.04"],
        )
        for alias in target_image.DISTRIBUTIONS:
            self.assertEqual(target_image.tag(alias), f"gowave-e2e-target:{alias}")
        with self.assertRaises(target_image.TargetImageError):
            target_image.distribution("centos-9")
        with self.assertRaises(target_image.TargetImageError):
            target_image.tag("centos-9")

    def test_containerfile_boots_systemd_and_stays_clean(self):
        text = target_image.containerfile()
        self.assertIn("FROM ${BASE_IMAGE}", text)
        self.assertIn('CMD ["/sbin/init"]', text)
        self.assertIn("STOPSIGNAL SIGRTMIN+3", text)
        for package in target_image.PRODUCT_PACKAGES:
            self.assertNotIn(f" {package} ", text, f"{package} must be installed by the operator")

    def test_dirty_image_is_rejected(self):
        original = target_image.CONTAINERFILE
        with tempfile.TemporaryDirectory() as tmp:
            dirty = Path(tmp) / "Containerfile.target"
            dirty.write_text(
                target_image.containerfile().replace(
                    "        dbus \\\n", "        dbus \\\n        nginx-full \\\n",
                ),
                encoding="utf-8",
            )
            target_image.CONTAINERFILE = dirty
            try:
                with self.assertRaises(target_image.TargetImageError) as caught:
                    target_image.containerfile()
                self.assertIn("nginx-full", str(caught.exception))
            finally:
                target_image.CONTAINERFILE = original

    def test_missing_init_or_stop_signal_is_rejected(self):
        original = target_image.CONTAINERFILE
        with tempfile.TemporaryDirectory() as tmp:
            broken = Path(tmp) / "Containerfile.target"
            broken.write_text(
                target_image.containerfile().replace('CMD ["/sbin/init"]', 'CMD ["sleep", "infinity"]'),
                encoding="utf-8",
            )
            target_image.CONTAINERFILE = broken
            try:
                with self.assertRaises(target_image.TargetImageError):
                    target_image.containerfile()
            finally:
                target_image.CONTAINERFILE = original

    def test_build_uses_the_pinned_base_alias(self):
        podman = FakePodman()
        image_tag = target_image.build(podman, "debian-13")
        self.assertEqual(image_tag, "gowave-e2e-target:debian-13")
        self.assertEqual(podman.builds[0]["base_alias"], "debian-13")
        self.assertEqual(podman.builds[0]["tag"], image_tag)
        self.assertEqual(podman.builds[0]["containerfile"], REPO_ROOT / "tests" / "Containerfile.target")
        self.assertEqual(podman.builds[0]["context_dir"], REPO_ROOT / "tests")

    def test_probe_reports_every_product_package(self):
        probe = target_image.cleanliness_probe()
        for package in target_image.PRODUCT_PACKAGES:
            self.assertIn(package, probe)
        self.assertIn("ps -p 1", probe)
        self.assertIn("dpkg-query", probe)
        self.assertIn("systemctl is-active ssh.service", probe)

    def test_clean_target_passes_the_pre_install_check(self):
        podman = FakePodman()
        facts = target_image.assert_clean(podman, "aio-target")
        self.assertEqual(facts["init"], "systemd")
        self.assertEqual(facts["sshd"], "active")
        self.assertEqual(facts["installed"], [])
        self.assertEqual(podman.execs[0][0], "aio-target")
        self.assertEqual(podman.execs[0][1][:2], ["bash", "-lc"])

    def test_target_without_a_running_sshd_fails_the_check(self):
        podman = FakePodman("init=systemd\nsystemd=systemd 255\nsshd=inactive\n")
        with self.assertRaises(target_image.TargetImageError) as caught:
            target_image.assert_clean(podman, "no-sshd")
        self.assertIn("sshd", str(caught.exception))

    def test_preinstalled_product_package_fails_the_check(self):
        podman = FakePodman("init=systemd\nsystemd=systemd 255\nsshd=active\ninstalled=certbot\n")
        with self.assertRaises(target_image.TargetImageError) as caught:
            target_image.assert_clean(podman, "dirty")
        self.assertIn("certbot", str(caught.exception))

    def test_non_systemd_pid1_fails_the_check(self):
        podman = FakePodman("init=sleep\nsystemd=\n")
        with self.assertRaises(target_image.TargetImageError) as caught:
            target_image.assert_clean(podman, "broken")
        self.assertIn("systemd as PID 1", str(caught.exception))
        self.assertIn("sleep", str(caught.exception))

    def test_parse_probe_ignores_noise(self):
        facts = target_image.parse_probe("garbage\ninit=systemd\ninstalled=ufw\ninstalled=\n")
        self.assertEqual(
            facts, {"init": "systemd", "systemd": "", "sshd": "", "installed": ["ufw"]}
        )

    def test_evidence_records_distribution_and_image(self):
        record = target_image.evidence("ubuntu-26.04", "aio", {"init": "systemd", "systemd": "systemd 257", "installed": []})
        self.assertEqual(record["distribution"], "ubuntu")
        self.assertEqual(record["image_tag"], "gowave-e2e-target:ubuntu-26.04")
        self.assertEqual(record["pid1"], "systemd")
        self.assertEqual(record["preinstalled_product_packages"], [])


if __name__ == "__main__":
    unittest.main()
