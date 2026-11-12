#!/usr/bin/env python3
"""Suite nonroot: local Pebble ACME fixture and its scoped test CA."""
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import acme_fixture, images  # noqa: E402
from tools.podman_e2e.runner import RunContext  # noqa: E402

ENDPOINT_PATTERN = re.compile(r'^GOWAVE_ACME_TEST_ENDPOINT="(?P<url>[^"]+)"$', re.MULTILINE)


def openssl(*argv, timeout=60):
    proc = subprocess.run(
        ["openssl", *argv], capture_output=True, text=True, check=False, timeout=timeout,
    )
    return proc


class FakePodman:
    """Records container calls instead of talking to a Podman daemon."""

    def __init__(self, context):
        self.context = context
        self.runs = []
        self.commands = []
        self.waits = []

    def run(self, **kwargs):
        self.runs.append(kwargs)
        return kwargs["name"]

    def _run(self, args, check=True, timeout=300):
        self.commands.append(list(args))
        return subprocess.CompletedProcess(args, 0, "", "")

    def wait_tcp(self, name, host, port, timeout_seconds=60):
        self.waits.append((name, host, port, timeout_seconds))
        return True


class TestPodmanAcmeFixture(unittest.TestCase):
    def workdir(self) -> Path:
        directory = Path(tempfile.mkdtemp(prefix="gowave-acme-fixture-"))
        self.addCleanup(shutil.rmtree, directory, True)
        return directory

    def context(self, topology="aio") -> RunContext:
        context = RunContext(topology=topology, artifact_root=self.workdir(), budget_seconds=600)
        self.addCleanup(context.run_cleanup)
        return context

    def test_fixture_ca_signs_the_pebble_endpoint_leaf(self):
        ca = acme_fixture.generate_fixture_ca(self.workdir())
        verified = openssl("verify", "-CAfile", str(ca.root_cert), str(ca.directory / "pebble.crt"))
        self.assertEqual(verified.returncode, 0, verified.stderr + verified.stdout)
        subject = openssl("x509", "-in", str(ca.root_cert), "-noout", "-subject")
        self.assertIn(acme_fixture.FIXTURE_CA_COMMON_NAME, subject.stdout)
        constraints = openssl("x509", "-in", str(ca.root_cert), "-noout", "-text")
        self.assertIn("CA:TRUE", constraints.stdout)

    def test_pebble_leaf_covers_the_fixture_host_and_loopback(self):
        ca = acme_fixture.generate_fixture_ca(self.workdir())
        leaf = ca.directory / "pebble.crt"
        for san in ("DNS:pebble.testbed.internal", "DNS:localhost", "IP Address:127.0.0.1"):
            self.assertIn(san, openssl("x509", "-in", str(leaf), "-noout", "-text").stdout)
        host_match = openssl("x509", "-in", str(leaf), "-noout", "-checkhost", acme_fixture.FIXTURE_HOST)
        self.assertEqual(host_match.returncode, 0, host_match.stderr)
        self.assertIn("BEGIN CERTIFICATE", ca.root_pem)

    def test_issued_leafs_carry_key_identifiers(self):
        ca = acme_fixture.generate_fixture_ca(self.workdir())
        leaf_text = openssl("x509", "-in", str(ca.directory / "pebble.crt"), "-noout", "-text").stdout
        self.assertIn("Authority Key Identifier", leaf_text)
        self.assertIn("Subject Key Identifier", leaf_text)
        root_text = openssl("x509", "-in", str(ca.root_cert), "-noout", "-text").stdout
        self.assertIn("Subject Key Identifier", root_text)

    def test_private_keys_are_never_group_or_world_readable(self):
        ca = acme_fixture.generate_fixture_ca(self.workdir())
        self.assertEqual((ca.root_key.stat().st_mode & 0o777), 0o600)
        self.assertEqual(((ca.directory / "pebble.key").stat().st_mode & 0o777), 0o600)

    def test_pebble_config_matches_the_container_contract(self):
        pebble = acme_fixture.pebble_config()["pebble"]
        self.assertEqual(pebble["listenAddress"], "0.0.0.0:14000")
        self.assertEqual(pebble["managementListenAddress"], "0.0.0.0:15000")
        self.assertEqual(pebble["certificate"], "/fixtures/acme/pebble.crt")
        self.assertEqual(pebble["privateKey"], "/fixtures/acme/pebble.key")
        self.assertEqual(pebble["httpPort"], acme_fixture.CHALLENGE_HTTP_PORT)
        self.assertEqual(pebble["tlsPort"], acme_fixture.CHALLENGE_TLS_PORT)
        self.assertIs(pebble["externalAccountBindingRequired"], False)

    def test_pebble_config_drift_fails_closed(self):
        workdir = self.workdir()
        drifted = workdir / "pebble-config.json"
        drifted.write_text(json.dumps({"pebble": {"listenAddress": "0.0.0.0:14001"}}), encoding="utf-8")
        original = acme_fixture.PEBBLE_CONFIG_TEMPLATE
        acme_fixture.PEBBLE_CONFIG_TEMPLATE = drifted
        try:
            with self.assertRaises(acme_fixture.AcmeFixtureError):
                acme_fixture.pebble_config()
            with self.assertRaises(acme_fixture.AcmeFixtureError):
                acme_fixture.prepare_acme_directory(workdir / "acme")
        finally:
            acme_fixture.PEBBLE_CONFIG_TEMPLATE = original
        self.assertFalse((workdir / "acme" / "fixture-root.key").exists())

    def test_prepare_acme_directory_builds_a_private_mount(self):
        directory = self.workdir() / "acme"
        ca = acme_fixture.prepare_acme_directory(directory)
        self.assertEqual((directory.stat().st_mode & 0o777), 0o700)
        for name in ("pebble-config.json", "pebble.crt", "pebble.key", "fixture-root.crt", "fixture-root.key"):
            self.assertTrue((directory / name).is_file(), name)
        self.assertEqual((directory / "pebble-config.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual(ca.root_cert, directory / "fixture-root.crt")
        mounted = json.loads((directory / "pebble-config.json").read_text(encoding="utf-8"))["pebble"]
        self.assertEqual(mounted["certificate"], f"{acme_fixture.CONTAINER_FIXTURE_DIR}/pebble.crt")

    def test_ca_file_sha256_matches_the_installer_contract(self):
        ca = acme_fixture.generate_fixture_ca(self.workdir())
        digest = acme_fixture.ca_file_sha256(ca.root_cert)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        expected = subprocess.run(
            ["sha256sum", "--", str(ca.root_cert)], capture_output=True, text=True, check=True, timeout=30,
        ).stdout.split()[0]
        self.assertEqual(digest, expected)
        self.assertNotEqual(acme_fixture.ca_der_digest(ca.root_cert), "sha256:" + digest)

    def test_ca_der_digest_is_stable_and_prefixed(self):
        ca = acme_fixture.generate_fixture_ca(self.workdir())
        first = acme_fixture.ca_der_digest(ca.root_cert)
        self.assertRegex(first, r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(first, acme_fixture.ca_der_digest(ca.root_cert))

    def test_directory_url_is_the_pinned_installer_endpoint(self):
        self.assertEqual(acme_fixture.ACME_DIRECTORY_URL, "https://pebble.testbed.internal:14000/dir")
        for script in ("modules/nginx.sh", "gowave-node-auto.sh"):
            text = (REPO_ROOT / script).read_text(encoding="utf-8")
            endpoints = set(ENDPOINT_PATTERN.findall(text))
            self.assertTrue(endpoints, f"{script} does not pin an ACME test endpoint")
            self.assertEqual(endpoints, {acme_fixture.ACME_DIRECTORY_URL}, script)

    def test_trust_environment_is_limited_to_the_fixture_ca(self):
        ca = acme_fixture.generate_fixture_ca(self.workdir())
        environment = acme_fixture.trust_environment(ca.root_cert)
        self.assertEqual(
            set(environment),
            {"REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "CURL_CA_BUNDLE"},
        )
        for value in environment.values():
            self.assertEqual(Path(value), ca.root_cert)
        source = Path(acme_fixture.__file__).read_text(encoding="utf-8")
        self.assertNotIn("update-ca-certificates", source)

    def test_generate_leaf_requires_the_fixture_ca(self):
        with self.assertRaises(acme_fixture.AcmeFixtureError):
            acme_fixture.generate_leaf(self.workdir(), "echo", ["DNS:echo.testbed.internal"])

    def test_generate_leaf_is_signed_by_the_fixture_ca(self):
        directory = self.workdir()
        ca = acme_fixture.generate_fixture_ca(directory)
        leaf = acme_fixture.generate_leaf(directory, "echo", ["DNS:echo.testbed.internal", "IP:10.89.0.10"])
        verified = openssl("verify", "-CAfile", str(ca.root_cert), str(leaf["cert"]))
        self.assertEqual(verified.returncode, 0, verified.stderr + verified.stdout)
        text = openssl("x509", "-in", str(leaf["cert"]), "-noout", "-text").stdout
        self.assertIn("DNS:echo.testbed.internal", text)
        self.assertIn("IP Address:10.89.0.10", text)
        self.assertEqual(leaf["key"].stat().st_mode & 0o777, 0o600)

    def test_container_runs_the_pinned_image_from_the_secret_directory(self):
        context = self.context()
        podman = FakePodman(context)
        fixture = acme_fixture.AcmeFixture(podman, "gowave-e2e-net")
        with self.assertRaises(acme_fixture.AcmeFixtureError):
            fixture.ca_file()
        fixture.start()

        self.assertEqual(len(podman.runs), 1)
        run = podman.runs[0]
        self.assertEqual(run["image_alias"], "acme-pebble")
        self.assertEqual(run["network"], "gowave-e2e-net")
        self.assertFalse(run["privileged"])
        self.assertEqual(run["aliases"], (acme_fixture.FIXTURE_HOST,))
        self.assertEqual(run["systemd"], "false")
        self.assertEqual(run["command"], ("-config", "/fixtures/acme/pebble-config.json"))
        self.assertEqual(
            run["volumes"],
            (f"{context.secret_dir / 'acme'}:{acme_fixture.CONTAINER_FIXTURE_DIR}:ro,Z",),
        )
        self.assertTrue(str(fixture.directory).startswith(str(context.secret_dir)))
        self.assertTrue(fixture.ca_file().is_file())

        fixture.wait_ready(timeout_seconds=5)
        self.assertEqual(
            podman.waits,
            [(fixture.name, acme_fixture.FIXTURE_HOST, acme_fixture.ACME_PORT, 5)],
        )

        evidence = fixture.evidence()
        self.assertEqual(evidence["endpoint"], acme_fixture.ACME_DIRECTORY_URL)
        self.assertRegex(evidence["ca_file_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(evidence["ca_der_digest"], r"^sha256:[0-9a-f]{64}$")

        self.assertIn(fixture.stop, context.cleanup_actions)
        fixture.stop()
        self.assertEqual(podman.commands[-1], ["rm", "-f", fixture.name])

    def test_fixture_container_name_is_run_scoped(self):
        first = acme_fixture.AcmeFixture(FakePodman(self.context()), "net")
        second = acme_fixture.AcmeFixture(FakePodman(self.context()), "net")
        self.assertNotEqual(first.name, second.name)
        self.assertRegex(first.name, r"^acme-pebble-[0-9a-f]{8}$")

    def test_acme_image_is_pinned_in_the_checked_in_lock(self):
        entry = images.entries()["acme-pebble"]
        self.assertRegex(entry.digest, r"^sha256:[0-9a-f]{64}$")
        self.assertNotIn("latest", entry.reference)
        self.assertEqual(images.resolve("acme-pebble"), f"ghcr.io/letsencrypt/pebble@{entry.digest}")

    def test_issued_root_never_trusts_an_unverified_peer(self):
        ca = acme_fixture.generate_fixture_ca(self.workdir())
        with self.assertRaises(acme_fixture.AcmeFixtureError):
            acme_fixture.fetch_issued_root("127.0.0.1", ca.root_cert, timeout=2)


if __name__ == "__main__":
    unittest.main()
