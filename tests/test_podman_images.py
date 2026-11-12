#!/usr/bin/env python3
"""Suite nonroot: image digest pinning and runtime fingerprint for the Podman E2E."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import environment, images  # noqa: E402
from tools.podman_e2e.podman import Podman, UnpinnedImageError  # noqa: E402
from tools.podman_e2e.runner import Runner, RunContext, Case  # noqa: E402

DIGEST = "sha256:" + "a" * 64


def synthetic_lock(**overrides):
    entry = {"reference": "docker.io/library/ubuntu:24.04", "digest": DIGEST, "role": "base"}
    references = {
        "ubuntu-24.04": "docker.io/library/ubuntu:24.04",
        "ubuntu-26.04": "docker.io/library/ubuntu:26.04",
        "debian-12": "docker.io/library/debian:12",
        "debian-13": "docker.io/library/debian:13",
        "acme-pebble": "ghcr.io/letsencrypt/pebble:2.10.3",
        "fixture-echo": "docker.io/library/python:3.12-slim",
    }
    lock = {
        "version": 1,
        "schema": images.SCHEMA,
        "images": {alias: dict(entry, reference=ref) for alias, ref in references.items()},
    }
    for image in lock["images"].values():
        image.update(overrides)
    return lock


class TestPodmanImagePinning(unittest.TestCase):
    def test_checked_in_lock_is_fully_pinned(self):
        errors = images.validate_lock()
        self.assertEqual(errors, [])
        for alias, entry in images.entries().items():
            self.assertRegex(entry.digest, r"^sha256:[0-9a-f]{64}$", alias)
            self.assertIn("@sha256:", images.resolve(alias), alias)

    def test_pinned_reference_drops_the_tag(self):
        pinned = images.resolve("ubuntu-24.04")
        self.assertEqual(pinned, f"docker.io/library/ubuntu@{images.entries()['ubuntu-24.04'].digest}")

    def test_resolution_fails_closed_for_unknown_alias(self):
        with self.assertRaises(images.ImageLockError):
            images.resolve("not-a-locked-image")

    def test_raw_digest_reference_is_not_an_alias(self):
        with self.assertRaises(images.ImageLockError):
            images.resolve("docker.io/library/ubuntu@sha256:" + "b" * 64)

    def test_floating_latest_tag_is_rejected(self):
        errors = images.validate_lock(synthetic_lock(reference="docker.io/library/ubuntu:latest"))
        self.assertTrue(any("latest" in error for error in errors), errors)

    def test_tagless_reference_is_rejected(self):
        lock = synthetic_lock()
        lock["images"]["ubuntu-24.04"]["reference"] = "docker.io/library/ubuntu"
        errors = images.validate_lock(lock)
        self.assertTrue(any("explicit tag" in error for error in errors), errors)

    def test_missing_digest_is_rejected(self):
        errors = images.validate_lock(synthetic_lock(digest=""))
        self.assertTrue(any("digest" in error for error in errors), errors)

    def test_missing_required_alias_is_rejected(self):
        lock = synthetic_lock()
        del lock["images"]["debian-13"]
        errors = images.validate_lock(lock)
        self.assertTrue(any("debian-13" in error for error in errors), errors)

    def test_podman_run_rejects_unpinned_reference_before_invocation(self):
        runner = object.__new__(Podman)
        runner._built_images = set()
        with self.assertRaises(UnpinnedImageError):
            runner.ensure_image("docker.io/library/ubuntu:24.04")

    def test_podman_run_rejects_unknown_alias(self):
        runner = object.__new__(Podman)
        runner._built_images = set()
        with self.assertRaises(UnpinnedImageError):
            runner.ensure_image("mystery-image")


class TestPodmanEnvironmentFingerprint(unittest.TestCase):
    def test_requirements_fail_closed_on_rootless_and_cgroup_v1(self):
        env = {
            "host": {"cgroup_version": "v1"},
            "podman": {"rootless": True, "network_backend": ""},
            "images": {"ubuntu-24.04": {"digest": ""}},
        }
        errors = environment.requirement_errors(env)
        self.assertTrue(any("rootful" in error for error in errors), errors)
        self.assertTrue(any("cgroup v2" in error for error in errors), errors)
        self.assertTrue(any("network backend" in error for error in errors), errors)
        self.assertTrue(any("not pinned" in error for error in errors), errors)

    def test_requirements_pass_for_a_pinned_rootful_cgroup2_host(self):
        env = {
            "host": {"cgroup_version": "v2"},
            "podman": {"rootless": False, "network_backend": "netavark"},
            "images": {"ubuntu-24.04": {"digest": DIGEST}},
        }
        self.assertEqual(environment.requirement_errors(env), [])

    def test_environment_is_written_into_the_run_artifacts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            context = RunContext("aio", Path(tmpdir), budget_seconds=60)
            path = environment.write_environment(context, {
                "schema": environment.SCHEMA,
                "host": {"kernel": "6.12.0-test", "cgroup_version": "v2"},
                "podman": {"rootless": False, "network_backend": "netavark"},
                "images": {"ubuntu-24.04": {"digest": DIGEST}},
            })
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(path.read_text())["podman"]["network_backend"], "netavark")

    def test_environment_is_embedded_in_the_result_report(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            context = RunContext("aio", Path(tmpdir), budget_seconds=60)
            context.environment = {"schema": environment.SCHEMA, "host": {"kernel": "6.12.0-test"}}
            runner = Runner(context)
            runner.add(Case("ENV-SMOKE", "aio", lambda ctx: {"note": "ok"}))
            self.assertEqual(runner.execute(), 0)
            report = json.loads((context.artifact_dir / "result.json").read_text())
            self.assertEqual(report["environment"]["host"]["kernel"], "6.12.0-test")


if __name__ == "__main__":
    unittest.main()
