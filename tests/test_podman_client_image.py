#!/usr/bin/env python3
"""Suite nonroot: the client-engine image is pinned, verified, and reproducible.

A subscription verdict is only meaningful when the engine that consumed the
payload is the pinned one. These tests hold the image to that contract offline:
the matrix pins version and digest, the build fails on a substituted download,
and the Containerfile installs nothing through a package manager.
"""
import gzip
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import install_client_artifact  # noqa: E402
from tools.podman_e2e import client_image  # noqa: E402

XRAY_BANNER = "Xray 26.11.9 (Xray, Penetrates Everything.)"
MIHOMO_BANNER = "v1.19.34 MetaCubeX mihomo linux/amd64"


class FakePodman:
    def __init__(self) -> None:
        self.builds = []

    def build(self, tag, base_alias, containerfile, context_dir, build_args=None):
        self.builds.append({
            "tag": tag,
            "base_alias": base_alias,
            "containerfile": Path(containerfile),
            "context_dir": Path(context_dir),
            "build_args": dict(build_args or {}),
        })
        return tag


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_script(directory: Path, name: str, banner: str) -> Path:
    script = directory / name
    script.write_text(f"#!/bin/sh\necho '{banner}'\n", encoding="utf-8")
    script.chmod(0o755)
    return script


def zip_artifact(path: Path, binary: Path, member: str) -> Path:
    with zipfile.ZipFile(path, "w") as bundle:
        bundle.writestr(member, binary.read_bytes())
    return path


def gz_artifact(path: Path, binary: Path) -> Path:
    with gzip.open(path, "wb") as bundle:
        bundle.write(binary.read_bytes())
    return path


class TestClientImageContract(unittest.TestCase):
    def test_matrix_pins_every_client_engine(self):
        self.assertEqual(client_image.versions(), {"xray": "26.11.9", "mihomo": "1.19.34"})
        self.assertEqual(client_image.BASE_ALIAS, "client-base")

    def test_build_arguments_carry_the_pinned_url_digest_and_banner(self):
        arguments = client_image.build_args()
        self.assertIn("26.11.9", arguments["XRAY_URL"])
        self.assertEqual(len(arguments["XRAY_SHA256"]), 64)
        self.assertIn("26.11.9", arguments["XRAY_EXPECT"])
        self.assertIn("1.19.34", arguments["MIHOMO_URL"])
        self.assertEqual(len(arguments["MIHOMO_SHA256"]), 64)
        self.assertIn("1.19.34", arguments["MIHOMO_EXPECT"])

    def test_tag_names_the_pinned_versions(self):
        self.assertEqual(client_image.tag(), "gowave-e2e-client:1.19.34-26.11.9")

    def test_engine_list_reports_how_each_engine_proves_its_version(self):
        engines = {engine["id"]: engine for engine in client_image.engine_list()}
        self.assertEqual(engines["xray"]["binary"], "xray")
        self.assertEqual(engines["xray"]["argument"], "version")
        self.assertEqual(engines["mihomo"]["argument"], "-v")
        self.assertIn("1.19.34", engines["mihomo"]["contains"])

    def test_containerfile_declares_pins_and_verifies_both_engines(self):
        text = client_image.containerfile()
        self.assertIn("ARG BASE_IMAGE=docker.io/library/", text)
        self.assertIn("FROM ${BASE_IMAGE}", text)
        self.assertIn('"${XRAY_SHA256}"', text)
        self.assertIn('"${MIHOMO_SHA256}"', text)
        for command in ("curl", "wget", "apt-get", "apk add"):
            self.assertNotIn(command, text, f"the client image must not use {command}")

    def test_containerfile_that_installs_through_a_package_manager_is_rejected(self):
        original = client_image.CONTAINERFILE
        with tempfile.TemporaryDirectory() as tmp:
            dirty = Path(tmp) / "Containerfile.client"
            dirty.write_text(
                client_image.containerfile().replace(
                    "COPY install_client_artifact.py",
                    "RUN apt-get install -y ca-certificates\nCOPY install_client_artifact.py",
                ),
                encoding="utf-8",
            )
            client_image.CONTAINERFILE = dirty
            try:
                with self.assertRaises(client_image.ClientImageError) as caught:
                    client_image.containerfile()
                self.assertIn("apt-get", str(caught.exception))
            finally:
                client_image.CONTAINERFILE = original

    def test_leading_dash_version_argument_must_use_the_equals_form(self):
        original = client_image.CONTAINERFILE
        with tempfile.TemporaryDirectory() as tmp:
            broken = Path(tmp) / "Containerfile.client"
            broken.write_text(
                client_image.containerfile().replace('--version-arg="-v"', "--version-arg -v"),
                encoding="utf-8",
            )
            client_image.CONTAINERFILE = broken
            try:
                with self.assertRaises(client_image.ClientImageError) as caught:
                    client_image.containerfile()
                self.assertIn("--version-arg=<arg>", str(caught.exception))
            finally:
                client_image.CONTAINERFILE = original

    def test_artifact_without_a_sha256_is_rejected(self):
        matrix = client_image.load_matrix()
        matrix["clients"][0]["artifact"]["sha256"] = "b651f7e1"
        with self.assertRaises(client_image.ClientImageError) as caught:
            client_image.build_args(matrix)
        self.assertIn("sha256", str(caught.exception))

    def test_artifact_url_without_the_pinned_version_is_rejected(self):
        matrix = client_image.load_matrix()
        matrix["clients"][1]["artifact"]["url"] = (
            "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/mihomo-linux-amd64-v1.19.33.gz"
        )
        with self.assertRaises(client_image.ClientImageError) as caught:
            client_image.build_args(matrix)
        self.assertIn("1.19.34", str(caught.exception))

    def test_unsupported_archive_kind_is_rejected(self):
        matrix = client_image.load_matrix()
        matrix["clients"][0]["artifact"]["archive"] = "tar.zst"
        with self.assertRaises(client_image.ClientImageError) as caught:
            client_image.build_args(matrix)
        self.assertIn("archive", str(caught.exception))

    def test_client_without_a_version_check_is_rejected(self):
        matrix = client_image.load_matrix()
        matrix["clients"][0]["version_check"] = {}
        with self.assertRaises(client_image.ClientImageError) as caught:
            client_image.build_args(matrix)
        self.assertIn("version_check", str(caught.exception))

    def test_build_uses_the_pinned_base_and_the_matrix_arguments(self):
        podman = FakePodman()
        image_tag = client_image.build(podman)
        self.assertEqual(image_tag, client_image.tag())
        build = podman.builds[0]
        self.assertEqual(build["base_alias"], "client-base")
        self.assertEqual(build["tag"], image_tag)
        self.assertEqual(build["containerfile"], REPO_ROOT / "tests" / "Containerfile.client")
        self.assertEqual(build["context_dir"], REPO_ROOT / "tests")
        self.assertEqual(build["build_args"], client_image.build_args())


class TestClientArtifactInstaller(unittest.TestCase):
    def test_zip_artifact_is_verified_and_installed_by_basename(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = write_script(root, "xray-source", XRAY_BANNER)
            archive = zip_artifact(root / "Xray-linux-64.zip", binary, "Xray-linux-64/xray")
            destination = root / "bin" / "xray"
            destination.parent.mkdir()
            facts = install_client_artifact.install(
                archive.as_uri(), sha256_of(archive), "zip", "xray",
                destination, "Xray 26.11.9", "version",
            )
            self.assertTrue(os.access(destination, os.X_OK))
            self.assertEqual(facts["sha256"], sha256_of(archive))
            self.assertIn("Xray 26.11.9", facts["version"])

    def test_gz_artifact_is_verified_and_installed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = write_script(root, "mihomo-source", MIHOMO_BANNER)
            archive = gz_artifact(root / "mihomo-linux-amd64.gz", binary)
            destination = root / "mihomo"
            facts = install_client_artifact.install(
                archive.as_uri(), sha256_of(archive), "gz", "",
                destination, "v1.19.34", "-v",
            )
            self.assertTrue(os.access(destination, os.X_OK))
            self.assertIn("v1.19.34", facts["version"])

    def test_digest_mismatch_refuses_to_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = write_script(root, "mihomo-source", MIHOMO_BANNER)
            archive = gz_artifact(root / "mihomo-linux-amd64.gz", binary)
            destination = root / "mihomo"
            with self.assertRaises(SystemExit) as caught:
                install_client_artifact.install(
                    archive.as_uri(), "0" * 64, "gz", "", destination, "v1.19.34", "-v",
                )
            self.assertIn("refusing to install", str(caught.exception))
            self.assertFalse(destination.exists())

    def test_archive_without_the_named_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = write_script(root, "xray-source", XRAY_BANNER)
            archive = zip_artifact(root / "Xray-linux-64.zip", binary, "Xray-linux-64/geoip.dat")
            with self.assertRaises(SystemExit) as caught:
                install_client_artifact.install(
                    archive.as_uri(), sha256_of(archive), "zip", "xray",
                    root / "xray", "Xray 26.11.9", "version",
                )
            self.assertIn("no 'xray' entry", str(caught.exception))

    def test_engine_that_reports_the_wrong_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = write_script(root, "xray-source", "Xray 25.1.1")
            archive = zip_artifact(root / "Xray-linux-64.zip", binary, "xray")
            with self.assertRaises(SystemExit) as caught:
                install_client_artifact.install(
                    archive.as_uri(), sha256_of(archive), "zip", "xray",
                    root / "xray", "Xray 26.11.9", "version",
                )
            self.assertIn("does not contain the pinned", str(caught.exception))

    def test_engine_that_refuses_to_report_its_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "xray-source"
            binary.write_text("#!/bin/sh\nexit 3\n", encoding="utf-8")
            binary.chmod(0o755)
            archive = zip_artifact(root / "Xray-linux-64.zip", binary, "xray")
            with self.assertRaises(SystemExit) as caught:
                install_client_artifact.install(
                    archive.as_uri(), sha256_of(archive), "zip", "xray",
                    root / "xray", "Xray 26.11.9", "version",
                )
            self.assertIn("failed with exit 3", str(caught.exception))

    def test_command_line_prints_the_installed_facts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = write_script(root, "xray-source", XRAY_BANNER)
            archive = zip_artifact(root / "Xray-linux-64.zip", binary, "xray")
            destination = root / "xray"
            stdout = io.StringIO()
            original = sys.stdout
            sys.stdout = stdout
            try:
                code = install_client_artifact.main([
                    "--url", archive.as_uri(),
                    "--sha256", sha256_of(archive),
                    "--archive", "zip",
                    "--member", "xray",
                    "--dest", str(destination),
                    "--expect", "Xray 26.11.9",
                    "--version-arg", "version",
                ])
            finally:
                sys.stdout = original
            self.assertEqual(code, 0)
            facts = json.loads(stdout.getvalue())
            self.assertEqual(facts["destination"], str(destination))
            self.assertEqual(facts["sha256"], sha256_of(archive))


if __name__ == "__main__":
    unittest.main()
