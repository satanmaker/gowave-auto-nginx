#!/usr/bin/env python3
"""Suite nonroot: the fixtures never reach public DNS, ACME, or the live VPS."""
import ast
import inspect
import ipaddress
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from tools.podman_e2e import acme_fixture  # noqa: E402

HARNESS_DIR = REPO_ROOT / "tools" / "podman_e2e"
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures"

PUBLIC_DIRECTORIES = ("acme-v02.api.letsencrypt.org", "acme-staging-v02.api.letsencrypt.org")
IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")
GLOBAL_ANCHOR_WRITES = (
    "update-ca-certificates",
    "/usr/local/share/ca-certificates",
    "/etc/ssl/certs",
    "/etc/pki/ca-trust",
)


def executable_source(path: Path) -> str:
    """Module source with the module docstring removed, so prose cannot mask code."""
    source = path.read_text(encoding="utf-8")
    docstring = ast.get_docstring(ast.parse(source)) or ""
    return source.replace(docstring, "", 1)


def python_sources(directory: Path):
    return sorted(path for path in directory.rglob("*.py"))


def public_addresses(text: str):
    found = []
    for match in IPV4.finditer(text):
        try:
            address = ipaddress.ip_address(match.group(1))
        except ValueError:
            continue
        if address.is_global:
            found.append(match.group(1))
    return found


class StubContext:
    def __init__(self) -> None:
        self.secret_dir = Path(tempfile.gettempdir()) / "gowave-isolation-stub"
        self.cleaned = False

    def resource_name(self, prefix: str) -> str:
        return f"{prefix}-stub"

    def add_cleanup(self, action) -> None:
        self.cleaned = True


class StubPodman:
    def __init__(self) -> None:
        self.context = StubContext()


class TestPodmanFixtureIsolation(unittest.TestCase):
    def test_dns_fixture_has_no_upstream_resolver(self):
        code = executable_source(FIXTURE_DIR / "dns_server.py")
        for forbidden in ("/etc/resolv.conf", "forwarders", "8.8.8.8", "1.1.1.1", "dns.resolver", ".connect("):
            self.assertNotIn(forbidden, code)

    def test_dns_fixture_is_nxdomain_for_every_name_outside_the_zone(self):
        from test_fixture_dns import TYPE_A, DnsFixture

        fixture = DnsFixture({
            "ttl": 30,
            "records": {"panel.testbed.internal": {"A": ["10.89.0.10"]}},
            "behavior": {"mode": "answer"},
        })
        self.addCleanup(fixture.close)
        for name in ("example.com", "acme-v02.api.letsencrypt.org", "vps.invalid"):
            _, rcode, answers = fixture.query(name, TYPE_A, timeout=2)
            self.assertEqual(rcode, 3, name)
            self.assertEqual(answers, [], name)

    def test_echo_fixture_contains_no_outbound_client(self):
        code = executable_source(FIXTURE_DIR / "echo_server.py")
        for forbidden in ("http.client", "import requests", "socket.create_connection", "urllib.request", "subprocess"):
            self.assertNotIn(forbidden, code)
        self.assertIn("from urllib.parse import parse_qs, urlparse", code)

    def test_acme_endpoint_is_a_fixture_host_not_a_public_directory(self):
        parsed = urlparse(acme_fixture.ACME_DIRECTORY_URL)
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.hostname, acme_fixture.FIXTURE_HOST)
        self.assertTrue(parsed.hostname.endswith(".testbed.internal"))
        self.assertEqual(parsed.port, acme_fixture.ACME_PORT)
        source = (HARNESS_DIR / "acme_fixture.py").read_text(encoding="utf-8")
        for directory in PUBLIC_DIRECTORIES:
            self.assertNotIn(directory, source)

    def test_acme_fixture_cannot_be_pointed_at_another_server(self):
        code = executable_source(HARNESS_DIR / "acme_fixture.py")
        for forbidden in ("os.environ", "os.getenv", "getenv("):
            self.assertNotIn(forbidden, code)
        parameters = set(inspect.signature(acme_fixture.AcmeFixture.__init__).parameters)
        self.assertEqual(parameters, {"self", "podman", "network", "directory", "host_alias"})
        fixture = acme_fixture.AcmeFixture(StubPodman(), "net")
        self.assertEqual(fixture.directory_url(), acme_fixture.ACME_DIRECTORY_URL)

    def test_acme_fixture_only_fetches_from_the_fixture_host(self):
        code = executable_source(HARNESS_DIR / "acme_fixture.py")
        urls = set(re.findall(r"https://[^\s\"']+", code))
        self.assertEqual(
            urls,
            {"https://{host}:{MANAGEMENT_PORT}/roots/0", "https://{FIXTURE_HOST}:{ACME_PORT}/dir"},
        )
        for url in urls:
            self.assertNotIn("letsencrypt.org", url)
        self.assertEqual(acme_fixture.MANAGEMENT_PORT, 15000)

    def test_pebble_challenge_ports_never_claim_80_or_443(self):
        pebble = acme_fixture.pebble_config()["pebble"]
        for port in (pebble["httpPort"], pebble["tlsPort"]):
            self.assertNotIn(port, (80, 443, acme_fixture.ACME_PORT))

    def test_no_fixture_or_harness_module_installs_a_global_trust_anchor(self):
        for path in python_sources(HARNESS_DIR) + python_sources(FIXTURE_DIR):
            code = executable_source(path)
            for forbidden in GLOBAL_ANCHOR_WRITES:
                self.assertNotIn(forbidden, code, f"{path.name} must not modify global CA trust")

    def test_harness_binds_only_private_or_loopback_addresses(self):
        for path in python_sources(HARNESS_DIR) + python_sources(FIXTURE_DIR):
            self.assertEqual(public_addresses(path.read_text(encoding="utf-8")), [], path.name)

    def test_harness_never_reaches_a_remote_host_over_ssh(self):
        for path in python_sources(HARNESS_DIR):
            code = executable_source(path)
            self.assertNotIn("paramiko", code, path.name)
            self.assertIsNone(re.search(r"[\"']ssh[\"']", code), path.name)
            self.assertIsNone(re.search(r"[\"']scp[\"']", code), path.name)

    def test_fixture_zone_uses_only_testbed_names_and_private_addresses(self):
        from test_fixture_dns import BASE_ZONE

        for name, records in BASE_ZONE["records"].items():
            self.assertTrue(name.endswith(".testbed.internal"), name)
            for values in records.values():
                for value in values:
                    self.assertFalse(ipaddress.ip_address(value).is_global, f"{name} -> {value}")


if __name__ == "__main__":
    unittest.main()
