#!/usr/bin/env python3
"""Suite nonroot: the All-in-One suite installs once with the real operator."""
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import aio, catalog, target_image, topology  # noqa: E402
from tools.podman_e2e.runner import Case, CaseBlocked, RunContext  # noqa: E402

INSTALL_OUTPUT = (
    "Configured /opt/gowave/.env with mode 0640.\n"
    "GoWave Panel is healthy and listening on http://127.0.0.1:3000.\n"
    "GoWave Auto NGINX Installation Complete\n"
)


class FakePodman:
    def __init__(self, context, install_returncode=0, install_output=INSTALL_OUTPUT):
        self.context = context
        self.install_returncode = install_returncode
        self.install_output = install_output
        self.installs = []
        self.networks = []
        self.started = []
        self.waits = []

    def network_subnets(self):
        return []

    def network_create(self, name, subnet=None, disable_dns=False):
        self.networks.append((name, subnet, disable_dns))
        return name

    def build(self, tag, base_alias, containerfile, context_dir=None):
        return target_image.tag(base_alias)

    def run(self, **kwargs):
        self.started.append(kwargs["name"])
        return kwargs["name"]

    def wait_tcp(self, name, host, port, timeout_seconds=60):
        self.waits.append(("tcp", name, port))

    def wait_systemd(self, name, timeout_seconds=90):
        self.waits.append(("systemd", name))
        return "running"

    def exec(self, name, argv, check=True, input_text=None, timeout=300):
        if len(argv) == 3 and argv[2] == target_image.cleanliness_probe():
            return subprocess.CompletedProcess(
                argv, 0, "init=systemd\nsystemd=systemd 255\nsshd=active\n", ""
            )
        raise AssertionError(f"unexpected exec: {argv}")

    def exec_bash(self, name, script, check=True, input_text=None, timeout=300):
        self.installs.append((name, script))
        return subprocess.CompletedProcess(
            ["bash", "-lc", script], self.install_returncode, self.install_output, ""
        )


def fake_create(self):
    """Stand-in for the container setup; the topology itself has its own suite."""
    self.plan = topology.NetworkPlan("10.90.0.0/24")
    self.acme = None
    return self


def make_context() -> tuple[RunContext, tempfile.TemporaryDirectory]:
    tmp = tempfile.TemporaryDirectory()
    context = RunContext(
        topology="aio",
        artifact_root=Path(tmp.name),
        budget_seconds=600,
        run_id="podman-aio-test-00000000",
    )
    return context, tmp


class TestAioSuite(unittest.TestCase):
    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)
        patcher = mock.patch.object(topology.AioTopology, "create", fake_create)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_install_case_uses_the_real_operator_script(self):
        podman = FakePodman(self.context)
        product = aio.AioProduct(podman)
        evidence = product.install()
        self.assertEqual(len(podman.installs), 1)
        name, script = podman.installs[0]
        self.assertEqual(name, product.host.target_name)
        self.assertIn(f"bash /repo/gowave-auto.sh install '{product.host.panel_domain}'", script)
        self.assertIn(f"'{product.host.reality_domain}'", script)
        self.assertEqual(evidence["install_returncode"], 0)
        self.assertEqual(evidence["target_container"], name)
        self.assertTrue(evidence["install_command"].startswith("bash /repo/gowave-auto.sh install"))

    def test_install_evidence_names_the_operator_logs(self):
        podman = FakePodman(self.context)
        aio.AioProduct(podman).install()
        stdout = self.context.artifact_dir / "evidence" / "aio-install.stdout.log"
        stderr = self.context.artifact_dir / "evidence" / "aio-install.stderr.log"
        self.assertIn("GoWave Panel is healthy", stdout.read_text(encoding="utf-8"))
        self.assertEqual(stdout.stat().st_mode & 0o777, 0o600)
        self.assertTrue(stderr.is_file())

    def test_install_is_not_repeated_for_later_cases(self):
        podman = FakePodman(self.context)
        product = aio.AioProduct(podman)
        product.install()
        with self.assertRaises(AssertionError) as caught:
            product.install()
        self.assertIn("installed once per run", str(caught.exception))
        self.assertEqual(len(podman.installs), 1)
        self.assertIs(product.require_installed(), product.host)

    def test_later_cases_are_blocked_before_the_install(self):
        product = aio.AioProduct(FakePodman(self.context))
        with self.assertRaises(CaseBlocked) as caught:
            product.require_installed()
        self.assertIn(aio.INSTALL_CASE_ID, str(caught.exception))

    def test_failed_install_reports_the_operator_tail(self):
        podman = FakePodman(self.context, install_returncode=1, install_output="ACME acquisition failed\n")
        # Keep the artifact directory in a temporary root so the evidence is inspectable.
        product = aio.AioProduct(podman)
        with self.assertRaises(AssertionError) as caught:
            product.install()
        message = str(caught.exception)
        self.assertIn("exit 1", message)
        self.assertIn("ACME acquisition failed", message)

    def test_cases_after_a_failed_install_are_blocked(self):
        podman = FakePodman(self.context, install_returncode=1, install_output="ACME acquisition failed\n")
        product = aio.AioProduct(podman)
        with self.assertRaises(AssertionError):
            product.install()
        with self.assertRaises(CaseBlocked) as caught:
            product.require_installed()
        self.assertIn("had nothing to verify", str(caught.exception))

    def test_suite_declares_only_aio_cases_that_exist_in_the_catalog(self):
        podman = FakePodman(self.context)
        suite = aio.cases(podman)
        self.assertTrue(suite)
        ids = {case.id for case in suite}
        self.assertIn(aio.INSTALL_CASE_ID, ids)
        by_id = {case["id"]: case for case in catalog.load_catalog()["cases"]}
        for case_id in ids:
            self.assertIn(case_id, by_id, f"{case_id} must be in the shared case catalog")
        self.assertEqual(by_id[aio.INSTALL_CASE_ID]["state"], "incubating")
        self.assertEqual(by_id[aio.INSTALL_CASE_ID]["runs_in"], ["podman"])
        self.assertIn("aio", by_id[aio.INSTALL_CASE_ID]["topology"])

    def test_install_case_carries_a_bounded_timeout(self):
        case, = [item for item in aio.cases(FakePodman(self.context)) if item.id == aio.INSTALL_CASE_ID]
        self.assertIsInstance(case, Case)
        self.assertEqual(case.topology, "aio")
        self.assertGreater(case.timeout_seconds, 0)
        self.assertLessEqual(case.timeout_seconds, aio.INSTALL_TIMEOUT_SECONDS)


class ScriptedPodman:
    """Podman stub that returns prepared host-script results in order."""

    def __init__(self, context, results):
        self.context = context
        self.results = list(results)
        self.scripts = []

    def exec_bash(self, name, script, check=True, input_text=None, timeout=300):
        self.scripts.append(script)
        stdout, returncode = self.results.pop(0)
        return subprocess.CompletedProcess(["bash", "-lc", script], returncode, stdout, "")


class StubHost:
    """The installed host, without containers, for the per-case probes."""

    def __init__(self, target_name="aio-1", panel_domain=aio.PANEL_DOMAIN):
        self.target_name = target_name
        self.panel_domain = panel_domain
        self.reality_domain = aio.REALITY_DOMAIN
        self.client_reports = []

    def client_http(self, url, **kwargs):
        report = self.client_reports.pop(0)
        return report


def installed_product(context, results):
    podman = ScriptedPodman(context, results)
    product = aio.AioProduct(podman)
    product.host = StubHost()
    product.outcome = topology.InstallOutcome(0, "", "", 1.0, "install")
    return product, podman


SOCKET_LISTING = (
    "LISTEN 0 511 0.0.0.0:443 0.0.0.0:*\n"
    "LISTEN 0 511 127.0.0.1:3000 0.0.0.0:*\n"
    "LISTEN 0 511 127.0.0.1:3002 0.0.0.0:*\n"
)


class TestAioVerificationCases(unittest.TestCase):
    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def test_package_case_requires_every_harness_declared_prerequisite(self):
        installed = "".join(f"installed={name}\n" for name in aio.REQUIRED_PACKAGES)
        product, _ = installed_product(self.context, [(installed, 0)])
        evidence = aio.case_packages(product)
        self.assertEqual(evidence["missing_packages"], [])
        self.assertEqual(len(evidence["installed_packages"]), len(aio.REQUIRED_PACKAGES))

    def test_missing_prerequisite_fails_the_case(self):
        output = "".join(f"installed={name}\n" for name in aio.REQUIRED_PACKAGES if name != "fail2ban")
        product, _ = installed_product(self.context, [(output + "missing=fail2ban\n", 0)])
        with self.assertRaises(AssertionError) as caught:
            aio.case_packages(product)
        self.assertIn("fail2ban", str(caught.exception))

    def test_service_case_requires_active_units_and_correct_listeners(self):
        output = "active\nactive\nactive\nactive\n---\n" + SOCKET_LISTING
        product, _ = installed_product(self.context, [(output, 0)])
        evidence = aio.case_services(product)
        self.assertTrue(all(state == "active" for state in evidence["units"].values()))
        self.assertEqual(evidence["listeners"], sorted([
            "0.0.0.0:443", "127.0.0.1:3000", "127.0.0.1:3002",
        ]))

    def test_inactive_unit_fails_the_service_case(self):
        output = "active\nactive\ninactive\nactive\n---\n" + SOCKET_LISTING
        product, _ = installed_product(self.context, [(output, 0)])
        with self.assertRaises(AssertionError) as caught:
            aio.case_services(product)
        self.assertIn("nginx.service=inactive", str(caught.exception))

    def test_loopback_only_listener_is_not_a_public_443(self):
        listing = (
            "LISTEN 0 511 127.0.0.1:443 0.0.0.0:*\n"
            "LISTEN 0 511 127.0.0.1:3000 0.0.0.0:*\n"
            "LISTEN 0 511 127.0.0.1:3002 0.0.0.0:*\n"
        )
        output = "active\nactive\nactive\nactive\n---\n" + listing
        product, _ = installed_product(self.context, [(output, 0)])
        with self.assertRaises(AssertionError) as caught:
            aio.case_services(product)
        self.assertIn("publicly on 443", str(caught.exception))

    def test_credentials_case_rejects_a_world_readable_file(self):
        product, _ = installed_product(self.context, [("root 644 128\n1\n1\n1\n0\n", 0)])
        with self.assertRaises(AssertionError) as caught:
            aio.case_credentials(product)
        self.assertIn("mode", str(caught.exception))

    def test_credentials_case_never_returns_secret_values(self):
        product, _ = installed_product(self.context, [("root 600 128\n1\n1\n1\n0\n", 0)])
        evidence = aio.case_credentials(product)
        self.assertEqual(
            sorted(evidence),
            [
                "has_admin_password", "has_admin_username", "has_scoped_api_token",
                "has_short_uuid_key", "mode", "owner",
            ],
        )
        self.assertTrue(all(isinstance(value, (bool, str)) for value in evidence.values()))

    def test_panel_case_needs_an_authenticated_call_and_a_public_https_view(self):
        product, _ = installed_product(self.context, [("login=200 api=200 token_length=64\n", 0)])
        product.host.client_reports = [{
            "url": f"{aio.PUBLIC_PANEL}/",
            "returncode": 0,
            "stdout": "{}",
            "stderr": "",
            "probe": {"status": 200, "peer": {"tls_version": "TLSv1.3", "san": [aio.PANEL_DOMAIN]}},
        }]
        evidence = aio.case_panel_ready(product)
        self.assertEqual(evidence["loopback_api"], "200")
        self.assertEqual(evidence["public_status"], 200)

    def test_panel_case_fails_when_the_public_probe_is_not_trusted(self):
        product, _ = installed_product(self.context, [("login=200 api=200 token_length=64\n", 0)])
        product.host.client_reports = [{
            "url": f"{aio.PUBLIC_PANEL}/",
            "returncode": 1,
            "stdout": "{}",
            "stderr": "",
            "probe": {"error": "SSLCertVerificationError: certificate verify failed"},
        }]
        with self.assertRaises(AssertionError) as caught:
            aio.case_panel_ready(product)
        self.assertIn("certificate verify failed", str(caught.exception))

    def test_tls_case_rejects_a_lineage_that_does_not_verify(self):
        product, _ = installed_product(self.context, [("", 1), ("", 1)])
        with self.assertRaises(AssertionError) as caught:
            aio.case_tls_and_identity(product)
        self.assertIn(aio.PANEL_DOMAIN, str(caught.exception))

    def test_tls_case_reports_the_api_sourced_short_uuid(self):
        product, _ = installed_product(self.context, [
            ("panel.testbed.internal does match certificate\n", 0),
            ("reality.testbed.internal does match certificate\n", 0),
            ("short_uuid_length=12\nusername_present=True\n", 0),
            ("0\n", 0),
        ])
        evidence = aio.case_tls_and_identity(product)
        self.assertEqual(evidence["short_uuid_length"], "12")
        self.assertEqual(evidence["short_uuid_source"], "api")
        self.assertFalse(evidence["credentials_short_uuid_key"])

    def test_panel_probe_scripts_are_valid_bash(self):
        # The probes are generated shell; a quoting mistake would only surface
        # after a full install, so the syntax is checked without one.
        for script in (aio.panel_probe_script(), aio.identity_probe_script()):
            proc = subprocess.run(["bash", "-n", "-c", script], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertNotIn("Authorization: Bearer $token", script)

    def test_panel_probe_accepts_the_wrapped_token_shape(self):
        # The Panel answers {"response": {"accessToken": ...}}; a probe that only
        # looked at the top level would authenticate with an empty bearer token.
        script = aio.panel_probe_script()
        self.assertIn('nested.get(\'accessToken\')', script)

    def test_harness_package_list_matches_the_operator_prerequisites(self):
        operator = (REPO_ROOT / "modules" / "os.sh").read_text(encoding="utf-8")
        function = operator.split("get_required_packages() {", 1)[1]
        block = function.split("cat <<'EOF'", 1)[1].split("EOF", 1)[0]
        declared = [line.strip() for line in block.splitlines() if line.strip()]
        self.assertEqual(tuple(declared), tuple(aio.REQUIRED_PACKAGES))


if __name__ == "__main__":
    unittest.main()
