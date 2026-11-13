#!/usr/bin/env python3
"""Suite nonroot: the All-in-One suite installs once with the real operator."""
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional, Sequence
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import (  # noqa: E402
    acme_fixture,
    aio,
    catalog,
    matrix,
    panel_surface,
    target_image,
    topology,
)
from tools.podman_e2e.runner import Case, CaseBlocked, RunContext  # noqa: E402

MATRIX_INBOUNDS = len(matrix.inbounds(matrix.load(), vision=False))

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
        self.connects = []
        self.started = []
        self.waits = []

    def network_subnets(self):
        return []

    def network_create(self, name, subnet=None, disable_dns=False, internal=False):
        self.networks.append((name, subnet, disable_dns, internal))
        return name

    def network_connect(self, name, network, ip=None):
        self.connects.append((name, network, ip))
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
    self.plan = topology.NetworkPlan("203.0.114.0/24")
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

    def install_environment(self):
        return {"GOWAVE_ACME_TEST_CA_FILE": "/fixtures/ca/acme-trust.pem"}

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


def surface_facts(overrides=None):
    """Panel probe output for the happy path, with single facts replaceable."""
    inbound = {"uuid": "inbound-uuid", "tag": "VLESS-REALITY-Vision@node", "type": "vless", "port": 443}
    other = [
        {"uuid": "xhttp-uuid", "tag": "VLESS-XHTTP-TLS@node", "type": "vless", "port": 443},
        {"uuid": "ws-uuid", "tag": "VLESS-WS-TLS@node", "type": "vless", "port": 443},
        {"uuid": "trojan-uuid", "tag": "Trojan-gRPC-TLS@node", "type": "trojan", "port": 443},
    ]
    inbounds = [inbound, *other]
    identifiers = [entry["uuid"] for entry in inbounds]
    digests = panel_surface.digest(identifiers)
    facts = {
        "login": {"status": 200, "token_present": True, "token_length": 64},
        "surface": {
            "unauthenticated_nodes_status": 401,
            "nodes": {
                "status": 200, "count": 1, "connected_count": 1,
                "inbound_count": len(inbounds), "inbound_digest": digests,
                "inbound_types": ["trojan", "vless"], "inbound_ports": ["443"],
            },
            "profiles": {
                "status": 200, "count": 1, "inbound_count": len(inbounds),
                "inbound_digest": digests, "inbound_tags": sorted(i["tag"] for i in inbounds),
            },
            "squads": {
                "status": 200, "count": 1, "mvp_present": True,
                "mvp_inbound_count": len(inbounds), "mvp_inbound_digest": digests,
            },
            "hosts": {
                "status": 200, "count": len(inbounds), "inbound_digest": digests,
                "security_layers": ["DEFAULT"], "fingerprints": ["firefox"],
            },
            "default_user": {"status": 200, "short_uuid_length": 16, "status_field": "ACTIVE"},
        },
        "lifecycle": {
            "squad_requested": True, "create_status": 201, "created_id_present": True,
            "created_short_uuid_length": 16, "created_status_field": "ACTIVE",
            "readback_status": 200, "readback_username_matches": True,
            "readback_short_uuid_matches": True, "readback_squad_count": 1,
            "get_by_id_status": 200, "delete_status": 204, "after_delete_status": 404,
        },
    }
    for path, value in (overrides or {}).items():
        target = facts
        *parents, leaf = path.split(".")
        for name in parents:
            target = target[name]
        target[leaf] = value
    return json.dumps(facts)


def probe_product(context, facts, returncode=0):
    product, podman = installed_product(context, [(facts, returncode)])
    return product, podman


class TestNegativeCases(unittest.TestCase):
    """The negative cases: a refusal only counts against a working control."""

    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def policy_product(self, facts):
        product, _ = installed_product(self.context, [])
        product._subscriptions = {"xray-json": {}}
        product.host.prohibited_facts = lambda timeout=300: subprocess.CompletedProcess(
            ["python3", "traffic_probe.py"], 0, json.dumps(facts), "",
        )
        return product

    def test_prohibited_destination_requires_a_refusal_and_an_empty_record(self):
        product = self.policy_product({
            "engine": "xray", "network": "tcp", "control_delivered": True,
            "delivered": False, "status": 503, "reason": "HTTP 503 without an endpoint report",
            "endpoint_records": 6, "recorded_request_ids": 0,
        })
        evidence = aio.case_negative_destination(product)
        self.assertTrue(evidence["control_delivered"])
        self.assertFalse(evidence["delivered"])
        self.assertEqual(evidence["status"], 503)

    def test_a_prohibited_destination_that_was_delivered_fails_the_case(self):
        product = self.policy_product({
            "engine": "xray", "network": "tcp", "control_delivered": True,
            "delivered": True, "status": 200, "recorded_request_ids": 0,
        })
        with self.assertRaises(AssertionError) as caught:
            aio.case_negative_destination(product)
        self.assertIn("was delivered", str(caught.exception))

    def test_a_control_that_never_arrived_fails_before_the_denial_counts(self):
        product = self.policy_product({
            "engine": "xray", "network": "tcp", "control_delivered": False,
            "delivered": False, "recorded_request_ids": 0,
        })
        with self.assertRaises(AssertionError) as caught:
            aio.case_negative_destination(product)
        self.assertIn("would prove nothing", str(caught.exception))

    def test_port_case_requires_the_foreign_listener_to_be_a_conflict(self):
        output = "foreign=refused managed=accepted released=accepted port=9444\n"
        product, _ = installed_product(self.context, [(output, 0)])
        evidence = aio.case_foreign_listener(product)
        self.assertEqual(evidence["port"], 9444)
        self.assertEqual(evidence["managed_listener"], "accepted")

    def test_port_case_fails_when_a_foreign_listener_is_forgiven(self):
        output = "foreign=accepted managed=accepted released=accepted port=9444\n"
        product, _ = installed_product(self.context, [(output, 0)])
        with self.assertRaises(AssertionError) as caught:
            aio.case_foreign_listener(product)
        self.assertIn("was accepted as no conflict", str(caught.exception))

    def test_port_case_fails_when_the_product_is_its_own_conflict(self):
        output = "foreign=refused managed=refused released=accepted port=9444\n"
        product, _ = installed_product(self.context, [(output, 0)])
        with self.assertRaises(AssertionError) as caught:
            aio.case_foreign_listener(product)
        self.assertIn("own listener on 443", str(caught.exception))

    def test_acme_case_requires_both_directions_and_the_unchanged_default(self):
        output = (
            "fixture_without_optin=refused arbitrary_in_test_mode=refused "
            "unpinned_ca=refused letsencrypt_production=accepted\n"
        )
        product, _ = installed_product(self.context, [(output, 0)])
        evidence = aio.case_acme_fail_closed(product)
        self.assertEqual(evidence["unpinned_ca"], "refused")
        self.assertEqual(evidence["letsencrypt_production"], "accepted")

    def test_acme_case_fails_when_test_mode_widens_the_allowlist(self):
        output = (
            "fixture_without_optin=refused arbitrary_in_test_mode=accepted "
            "unpinned_ca=refused letsencrypt_production=accepted\n"
        )
        product, _ = installed_product(self.context, [(output, 0)])
        with self.assertRaises(AssertionError) as caught:
            aio.case_acme_fail_closed(product)
        self.assertIn("arbitrary ACME URL", str(caught.exception))

    def test_dependency_case_needs_the_public_surface_to_fail_and_recover(self):
        product, podman = installed_product(self.context, [
            ("inactive\n", 0),
            ("login=200 api=200 token_length=64\n", 0),
            ("active\n", 0),
        ])
        product.host.client_reports = [
            {"url": f"{aio.PUBLIC_PANEL}/", "returncode": 0, "stdout": "{}", "stderr": "",
             "probe": {"status": 200}},
            {"url": f"{aio.PUBLIC_PANEL}/", "returncode": 1, "stdout": "{}", "stderr": "",
             "probe": {"error": "ConnectionRefusedError: [Errno 111] Connection refused"}},
            {"url": f"{aio.PUBLIC_PANEL}/", "returncode": 0, "stdout": "{}", "stderr": "",
             "probe": {"status": 200}},
        ]
        evidence = aio.case_public_dependency(product)
        self.assertEqual(evidence["panel_loopback_login"], "200")
        self.assertEqual(evidence["public_before"], 200)
        self.assertIn("systemctl stop nginx", podman.scripts[0])
        self.assertIn("systemctl start nginx", podman.scripts[2])

    def test_dependency_case_fails_when_443_still_answers_without_nginx(self):
        product, _ = installed_product(self.context, [("inactive\n", 0)])
        product.host.client_reports = [
            {"url": f"{aio.PUBLIC_PANEL}/", "returncode": 0, "stdout": "{}", "stderr": "",
             "probe": {"status": 200}},
            {"url": f"{aio.PUBLIC_PANEL}/", "returncode": 0, "stdout": "{}", "stderr": "",
             "probe": {"status": 200}},
        ]
        with self.assertRaises(AssertionError) as caught:
            aio.case_public_dependency(product)
        self.assertIn("does not depend on it", str(caught.exception))

    def test_the_host_scripts_the_negative_cases_run_are_valid_bash(self):
        for script in (aio.FOREIGN_LISTENER_SCRIPT, aio.ACME_FAIL_CLOSED_SCRIPT):
            result = subprocess.run(["bash", "-n"], input=script, text=True,
                                    capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)


class TestPanelApiCases(unittest.TestCase):
    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def test_panel_surface_probe_is_valid_python(self):
        source = (REPO_ROOT / "tools" / "podman_e2e" / "panel_surface.py").read_text(encoding="utf-8")
        compile(source, "panel_surface.py", "exec")

    def test_inbound_digest_ignores_order_but_not_membership(self):
        self.assertEqual(panel_surface.digest(["b", "a"]), panel_surface.digest(["a", "b"]))
        self.assertNotEqual(panel_surface.digest(["a"]), panel_surface.digest(["a", "b"]))
        self.assertEqual(panel_surface.digest([]), "")

    def test_auth_case_reads_the_inventory_from_one_api_set(self):
        product, podman = probe_product(self.context, surface_facts())
        evidence = aio.case_panel_auth(product)
        self.assertEqual(evidence["login_status"], 200)
        self.assertEqual(evidence["unauthenticated_nodes_status"], 401)
        self.assertEqual(evidence["host_count"], MATRIX_INBOUNDS)
        self.assertEqual(podman.scripts[0], f"python3 {aio.PANEL_SURFACE_SCRIPT} --scope surface")

    def test_auth_case_rejects_an_unauthenticated_read_surface(self):
        product, _ = probe_product(
            self.context, surface_facts({"surface.unauthenticated_nodes_status": 200})
        )
        with self.assertRaises(AssertionError) as caught:
            aio.case_panel_auth(product)
        self.assertIn("anonymous /api/nodes", str(caught.exception))

    def test_auth_case_rejects_a_profile_that_diverges_from_the_node(self):
        product, _ = probe_product(
            self.context, surface_facts({"surface.profiles.inbound_digest": "0" * 64})
        )
        with self.assertRaises(AssertionError) as caught:
            aio.case_panel_auth(product)
        self.assertIn("disagree on which inbounds are active", str(caught.exception))

    def test_auth_case_rejects_a_squad_that_grants_nothing(self):
        product, _ = probe_product(self.context, surface_facts({"surface.squads.mvp_present": False}))
        with self.assertRaises(AssertionError) as caught:
            aio.case_panel_auth(product)
        self.assertIn("Default MVP Squad", str(caught.exception))

    def test_auth_case_rejects_a_missing_host_for_an_inbound(self):
        product, _ = probe_product(self.context, surface_facts({"surface.hosts.count": 3}))
        with self.assertRaises(AssertionError) as caught:
            aio.case_panel_auth(product)
        self.assertIn("one per inbound", str(caught.exception))

    def test_client_lifecycle_case_walks_create_read_delete(self):
        product, podman = probe_product(self.context, surface_facts())
        evidence = aio.case_client_lifecycle(product)
        self.assertEqual(evidence["create_status"], 201)
        self.assertEqual(evidence["delete_status"], 204)
        self.assertEqual(evidence["after_delete_status"], 404)
        self.assertEqual(podman.scripts[0], f"python3 {aio.PANEL_SURFACE_SCRIPT} --scope lifecycle")

    def test_client_lifecycle_case_fails_when_the_delete_does_not_take_effect(self):
        product, _ = probe_product(self.context, surface_facts({"lifecycle.after_delete_status": 200}))
        with self.assertRaises(AssertionError) as caught:
            aio.case_client_lifecycle(product)
        self.assertIn("still served by username", str(caught.exception))

    def test_client_lifecycle_case_fails_when_the_client_gets_no_squad(self):
        product, _ = probe_product(self.context, surface_facts({"lifecycle.squad_requested": False}))
        with self.assertRaises(AssertionError) as caught:
            aio.case_client_lifecycle(product)
        self.assertIn("Default MVP Squad", str(caught.exception))

    def test_probe_failure_is_reported_with_its_stderr(self):
        product, _ = probe_product(self.context, "", returncode=2)
        with self.assertRaises(AssertionError) as caught:
            aio.case_panel_auth(product)
        self.assertIn("Panel probe exited 2", str(caught.exception))

    def test_probe_output_that_is_not_json_fails_the_case(self):
        product, _ = probe_product(self.context, "login failed\n")
        with self.assertRaises(AssertionError) as caught:
            aio.case_panel_auth(product)
        self.assertIn("did not print JSON", str(caught.exception))


class TestPanelSurfaceProbe(unittest.TestCase):
    """The probe is exercised against a stub Panel: it must collect facts, not secrets."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.password = "pw-do-not-print"
        self.token = "token-do-not-print"
        self.credentials = Path(self.tmp.name) / "credentials"
        self.credentials.write_text(
            f"ADMIN_USERNAME=admin\nADMIN_PASSWORD={self.password}\n", encoding="utf-8"
        )
        self.credentials.chmod(0o600)
        inbounds = [
            {"uuid": f"inbound-{index}", "tag": f"tag-{index}", "type": "vless", "port": 443}
            for index in range(MATRIX_INBOUNDS)
        ]
        self.inbounds = inbounds
        self.server = self._start_stub(inbounds)
        self.addCleanup(self.server.shutdown)

    def _start_stub(self, inbounds):
        deleted = {"done": False}
        created = {"username": None, "short_uuid": "created-short-uuid"}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _authorised(self):
                return self.headers.get("Authorization") == f"Bearer {self.server.token}"

            def _send(self, status, body=None):
                self.send_response(status)
                if body is not None:
                    raw = json.dumps(body).encode()
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                else:
                    self.end_headers()

            def do_GET(self):
                path = self.path
                if path == "/api/nodes" and not self._authorised():
                    return self._send(401, {"error": "Unauthorized"})
                if not self._authorised():
                    return self._send(401, {"error": "Unauthorized"})
                if path == "/api/nodes":
                    node = {"uuid": "node-uuid", "isConnected": True,
                            "configProfile": {"activeInbounds": inbounds}}
                    return self._send(200, {"response": [node]})
                if path == "/api/config-profiles":
                    profile = {"uuid": "profile-uuid", "inbounds": inbounds}
                    return self._send(200, {"response": {"total": 1, "configProfiles": [profile]}})
                if path == "/api/internal-squads":
                    squad = {"uuid": "squad-uuid", "name": "Default MVP Squad",
                             "info": {"inboundsCount": len(inbounds)},
                             "inbounds": [{"uuid": item["uuid"]} for item in inbounds]}
                    return self._send(200, {"response": {"total": 1, "internalSquads": [squad]}})
                if path == "/api/hosts":
                    hosts = [{"uuid": f"host-{item['uuid']}", "securityLayer": "DEFAULT",
                              "fingerprint": "firefox",
                              "inbound": {"configProfileUuid": "profile-uuid",
                                          "configProfileInboundUuid": item["uuid"]}}
                             for item in inbounds]
                    return self._send(200, {"response": hosts})
                if path == "/api/users/by-username/default-user":
                    return self._send(200, {"response": {"username": "default-user",
                                                         "shortUuid": "default-short-uuid"}})
                if path == f"/api/users/by-username/{created['username']}":
                    if deleted["done"]:
                        return self._send(404, {"message": "User not found"})
                    return self._send(200, {"response": {
                        "username": created["username"], "shortUuid": created["short_uuid"],
                        "activeInternalSquads": [{"uuid": "squad-uuid"}],
                    }})
                if path == "/api/users/7":
                    return self._send(200, {"response": {"id": 7}})
                return self._send(404, {"message": "not found"})

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                if self.path == "/api/auth/login":
                    if body.get("password") != self.server.password:
                        return self._send(401, {"error": "Unauthorized"})
                    return self._send(200, {"response": {"accessToken": self.server.token,
                                                         "tokenType": "Bearer"}})
                if self.path == "/api/users" and self._authorised():
                    created["username"] = body.get("username")
                    return self._send(201, {"response": {
                        "id": 7, "username": body.get("username"), "status": "ACTIVE",
                        "shortUuid": created["short_uuid"],
                    }})
                return self._send(404, {"message": "not found"})

            def do_DELETE(self):
                if not self._authorised():
                    return self._send(401, {"error": "Unauthorized"})
                if self.path == "/api/users/7":
                    deleted["done"] = True
                    return self._send(204)
                return self._send(404, {"message": "not found"})

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.token = self.token
        server.password = self.password
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.port = server.server_address[1]
        return server

    def _run(self, scope):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = panel_surface.main([
                "--scope", scope,
                "--panel-url", f"http://127.0.0.1:{self.port}",
                "--credentials", str(self.credentials),
            ])
        self.assertEqual(code, 0)
        output = stdout.getvalue()
        self.assertNotIn(self.password, output)
        self.assertNotIn(self.token, output)
        return json.loads(output)

    def test_probe_reports_statuses_counts_and_digests_without_secrets(self):
        facts = self._run("all")
        self.assertEqual(facts["login"]["status"], 200)
        self.assertTrue(facts["login"]["token_present"])
        self.assertEqual(facts["login"]["token_length"], len(self.token))

        surface = facts["surface"]
        self.assertEqual(surface["unauthenticated_nodes_status"], 401)
        self.assertEqual(surface["nodes"]["count"], 1)
        self.assertEqual(surface["nodes"]["inbound_count"], MATRIX_INBOUNDS)
        self.assertEqual(surface["profiles"]["inbound_digest"], surface["nodes"]["inbound_digest"])
        self.assertEqual(surface["squads"]["mvp_inbound_digest"],
                         surface["profiles"]["inbound_digest"])
        self.assertEqual(surface["hosts"]["count"], MATRIX_INBOUNDS)
        self.assertEqual(surface["default_user"]["short_uuid_length"], len("default-short-uuid"))
        for uuid in (item["uuid"] for item in self.inbounds):
            self.assertNotIn(uuid, json.dumps(surface))

        lifecycle = facts["lifecycle"]
        self.assertTrue(lifecycle["squad_requested"])
        self.assertEqual(
            [lifecycle[key] for key in (
                "create_status", "readback_status", "get_by_id_status",
                "delete_status", "after_delete_status",
            )],
            [201, 200, 200, 204, 404],
        )
        self.assertTrue(lifecycle["readback_username_matches"])
        self.assertTrue(lifecycle["readback_short_uuid_matches"])
        self.assertEqual(lifecycle["readback_squad_count"], 1)

    def test_probe_scope_surface_does_not_create_anything(self):
        facts = self._run("surface")
        self.assertNotIn("lifecycle", facts)
        self.assertIn("surface", facts)

    def test_probe_fails_on_a_wrong_password_instead_of_printing_a_token(self):
        self.credentials.write_text(
            "ADMIN_USERNAME=admin\nADMIN_PASSWORD=wrong\n", encoding="utf-8"
        )
        facts = self._run("surface")
        self.assertEqual(facts["login"]["status"], 401)
        self.assertFalse(facts["login"]["token_present"])
        self.assertEqual(facts["surface"]["nodes"]["status"], 401)


PLAN = topology.NetworkPlan(subnet="203.0.114.0/24")


def transfer_facts():
    """The endpoint report shape the traffic probe returns for a healthy matrix."""
    transfers = [
        {
            "engine": engine,
            "tag": f"{engine}-{network}",
            "network": network,
            "security": security,
            "sni": sni,
            "request_id": f"{engine}-{network}-0123456789ab",
            "status": 200,
            "request_id_match": True,
            "body_match": True,
            "source_ip": PLAN.target_ip,
        }
        for engine in aio.TRAFFIC_ENGINES
        for network, security, sni in (
            ("tcp", "reality", topology.REALITY_DOMAIN),
            ("ws", "tls", topology.PANEL_DOMAIN),
            ("grpc", "tls", topology.PANEL_DOMAIN),
            ("xhttp", "tls", topology.PANEL_DOMAIN),
        )
    ]
    return {
        "transfers": transfers,
        "transfer_count": len(transfers),
        "source_ips": [PLAN.target_ip],
        "missing_request_ids": 0,
    }


def readiness_facts(delivered=True):
    """What the all-outbound readiness scope reports about the data plane."""
    return {
        "delivered": delivered,
        "engine": "xray",
        "network": "tcp",
        "status": 200 if delivered else None,
        "reason": "" if delivered else "HTTP 503 without an endpoint report",
        "recorded": delivered,
        "attempt_count": 1 if delivered else 2,
        "pending": [] if delivered else ["xray:xhttp/tls"],
    }


class TrafficHost(StubHost):
    """The installed host, extended with the engine-side traffic probe."""

    def __init__(self, facts=None, podman=None, readiness=None):
        super().__init__()
        self.plan = PLAN
        self.traffic = transfer_facts() if facts is None else facts
        self.readiness = readiness_facts() if readiness is None else readiness
        self.scopes = []
        self.podman = podman

    def traffic_facts(self, scope, timeout=900, payload_dir=None):
        self.scopes.append(scope)
        facts = self.readiness if scope == "warmup" else self.traffic
        return subprocess.CompletedProcess(
            ["python3", "traffic_probe.py"], 0, json.dumps(facts), "",
        )

    def reinstall(self):
        proc = self.podman.exec_bash(self.target_name, "reinstall", check=False, timeout=60)
        return topology.InstallOutcome(
            proc.returncode, proc.stdout, proc.stderr, 1.0, "reinstall",
        )


def surface_payload(counts=None, digest="digest-1"):
    counts = counts or {}
    return {
        "login": {"status": 200, "token_present": True},
        "surface": {
            "nodes": {"status": 200, "count": counts.get("nodes", 1), "inbound_digest": digest},
            "profiles": {"status": 200, "count": counts.get("profiles", 1), "inbound_digest": digest},
            "squads": {"status": 200, "count": counts.get("squads", 1), "mvp_inbound_digest": digest},
            "hosts": {"status": 200, "count": counts.get("hosts", 4), "inbound_digest": digest},
            "tokens": {"status": 200, "count": counts.get("tokens", 1), "name_digest": digest},
        },
    }


def subscription_payload(digest="credentials-1"):
    return {"subscriptions": {"credential_digest": digest, "representations": {}}}


def inventory_output(nginx="a" * 8, credentials="root 600", units=None):
    units = units or [
        "fail2ban.service enabled",
        "gowave-node.service enabled",
        "gowave.service enabled",
        "nginx.service enabled",
    ]
    return (
        "==units\n" + "\n".join(units) + "\n"
        "==unit-files\n/etc/systemd/system/gowave.service\n"
        "==nginx\n" + f"{nginx}  conf.d/gowave-panel.conf\n"
        "==credentials\n" + credentials + "\n"
    )


class TestRestartCase(unittest.TestCase):
    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def restart_product(self, results, facts=None, readiness=None):
        podman = ScriptedPodman(self.context, results)
        product = aio.AioProduct(podman)
        product.host = TrafficHost(facts, podman, readiness)
        product.outcome = topology.InstallOutcome(0, "", "", 1.0, "install")
        # The payloads were captured by an earlier case; this one only needs the
        # block to pass, not a second fetch that would consume a scripted result.
        product._subscriptions = {}
        return product, podman

    def poll_once(self):
        return lambda predicate, *args, **kwargs: predicate()

    def poll_until_the_tunnel(self):
        """Let the control-plane wait pass, then report the tunnel as never ready."""
        polls = []

        def wait(predicate, *args, **kwargs):
            polls.append(predicate())
            return len(polls) == 1

        return wait

    def test_the_case_restarts_the_units_and_exercises_the_data_plane(self):
        product, podman = self.restart_product([
            ("", 0),
            ("login=200 api=200 token_length=64 upstreams=2\n", 0),
            ("active\nactive\nactive\nactive\n", 0),
        ])
        with mock.patch.object(aio, "wait_until", self.poll_once()):
            evidence = aio.case_restart(product)
        self.assertIn("systemctl restart gowave.service gowave-node.service", podman.scripts[0])
        self.assertIn("8443", podman.scripts[1])
        self.assertEqual(evidence["loopback_login"], "200")
        self.assertEqual(evidence["readiness_network"], "tcp")
        self.assertEqual(evidence["transfer_count"], 8)
        self.assertEqual(product.host.scopes, ["warmup", "traffic"])

    def test_the_case_waits_for_a_tunnel_that_really_carries_a_payload(self):
        product, _ = self.restart_product([
            ("", 0),
            ("login=200 api=200 token_length=64 upstreams=2\n", 0),
            ("active\nactive\nactive\nactive\n", 0),
        ], readiness=readiness_facts(delivered=False))
        with mock.patch.object(aio, "wait_until", self.poll_until_the_tunnel()):
            with self.assertRaises(AssertionError) as caught:
                aio.case_restart(product)
        message = str(caught.exception)
        self.assertIn("not every served outbound carried a payload", message)
        self.assertIn("HTTP 503 without an endpoint report", message)

    def test_the_deadline_names_the_outbound_that_never_carried(self):
        # One warm transport is not the data plane: the case asserts the whole
        # matrix, so a transport that never carried has to be named before the
        # matrix runs rather than surfacing as a mid-matrix failure.
        product, _ = self.restart_product([
            ("", 0),
            ("login=200 api=200 token_length=64 upstreams=2\n", 0),
            ("active\nactive\nactive\nactive\n", 0),
        ], readiness=readiness_facts(delivered=False))
        with mock.patch.object(aio, "wait_until", self.poll_until_the_tunnel()):
            with self.assertRaises(AssertionError) as caught:
                aio.case_restart(product)
        self.assertIn("xray:xhttp/tls", str(caught.exception))

    def test_a_failed_restart_fails_the_case(self):
        product, _ = self.restart_product([("not permitted", 1)])
        with self.assertRaises(AssertionError) as caught:
            aio.case_restart(product)
        self.assertIn("systemctl restart", str(caught.exception))

    def test_a_panel_that_never_answers_fails_the_case_within_the_deadline(self):
        product, _ = self.restart_product([("", 0)])
        with mock.patch.object(aio, "wait_until", lambda *args, **kwargs: False):
            with self.assertRaises(AssertionError) as caught:
                aio.case_restart(product)
        self.assertIn("did not recover", str(caught.exception))

    def test_a_tunnel_upstream_that_never_binds_fails_the_case(self):
        product, _ = self.restart_product([
            ("", 0),
            ("login=200 api=200 token_length=64 upstreams=1\n", 0),
        ])
        with mock.patch.object(aio, "wait_until", self.poll_once()):
            with self.assertRaises(AssertionError) as caught:
                aio.case_restart(product)
        self.assertIn("'upstreams': '1'", str(caught.exception))

    def test_a_unit_that_stays_down_after_the_restart_fails_the_case(self):
        product, _ = self.restart_product([
            ("", 0),
            ("login=200 api=200 token_length=64 upstreams=2\n", 0),
            ("active\nactive\nfailed\nactive\n", 0),
        ])
        with mock.patch.object(aio, "wait_until", self.poll_once()):
            with self.assertRaises(AssertionError) as caught:
                aio.case_restart(product)
        self.assertIn("nginx.service=failed", str(caught.exception))

    def test_the_data_plane_must_still_transfer_after_the_restart(self):
        facts = transfer_facts()
        facts["transfer_count"] = 4
        product, _ = self.restart_product([
            ("", 0),
            ("login=200 api=200 token_length=64 upstreams=2\n", 0),
            ("active\nactive\nactive\nactive\n", 0),
        ], facts)
        with mock.patch.object(aio, "wait_until", self.poll_once()):
            with self.assertRaises(AssertionError) as caught:
                aio.case_restart(product)
        self.assertIn("after the restart 4 transports", str(caught.exception))


class TestIdempotentCase(unittest.TestCase):
    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def idempotent_product(self, results, facts=None):
        podman = ScriptedPodman(self.context, results)
        product = aio.AioProduct(podman)
        product.host = TrafficHost(facts, podman)
        product.outcome = topology.InstallOutcome(0, "", "", 1.0, "install")
        product._subscriptions = {}
        return product

    def scripted(self, before, after, nginx_before="a" * 8, nginx_after="a" * 8,
                 credentials_after="root 600", subscription_after="credentials-1"):
        return [
            (json.dumps(before), 0),
            (inventory_output(nginx=nginx_before), 0),
            (json.dumps(subscription_payload()), 0),
            ("reinstall finished\n", 0),
            (json.dumps(after), 0),
            (inventory_output(nginx=nginx_after, credentials=credentials_after), 0),
            (json.dumps(subscription_payload(subscription_after)), 0),
        ]

    def run_case(self, before=None, after=None, facts=None, **kwargs):
        product = self.idempotent_product(
            self.scripted(before or surface_payload(), after or surface_payload(), **kwargs), facts,
        )
        return aio.case_idempotent(product), product

    def reject(self, expected, **kwargs):
        with self.assertRaises(AssertionError) as caught:
            self.run_case(**kwargs)
        self.assertIn(expected, str(caught.exception))

    def test_an_unchanged_install_is_accepted(self):
        evidence, product = self.run_case()
        self.assertEqual(evidence["reinstall_returncode"], 0)
        self.assertEqual(evidence["credentials"], "root 600")
        self.assertFalse(evidence["credential_digest_changed"])
        self.assertEqual(evidence["transfer_count"], 8)
        self.assertIn("reinstall", product.podman.scripts[3])

    def test_a_duplicate_token_fails_the_case(self):
        self.reject("Panel inventory",
                    after=surface_payload(counts={"tokens": 2}))

    def test_a_duplicate_host_fails_the_case(self):
        self.reject("Panel inventory",
                    after=surface_payload(counts={"hosts": 8}))

    def test_a_rewritten_nginx_config_fails_the_case(self):
        self.reject("host resources: nginx", nginx_after="b" * 8)

    def test_a_world_readable_credentials_file_fails_the_case(self):
        self.reject("root-owned mode 600", credentials_after="root 644")

    def test_a_rotated_subscription_credential_fails_the_case(self):
        self.reject("rotated the credentials", subscription_after="credentials-2")

    def test_a_failed_repeated_install_fails_the_case(self):
        product = self.idempotent_product([
            (json.dumps(surface_payload()), 0),
            (inventory_output(), 0),
            (json.dumps(subscription_payload()), 0),
            ("registration refused", 1),
        ])
        with self.assertRaises(AssertionError) as caught:
            aio.case_idempotent(product)
        self.assertIn("repeated install failed", str(caught.exception))

    def test_traffic_that_stopped_working_fails_the_case(self):
        facts = transfer_facts()
        facts["transfer_count"] = 0
        self.reject("after the repeated install 0 transports", facts=facts)

    def test_the_inventory_is_split_into_sorted_sections(self):
        sections = aio.inventory_sections(inventory_output())
        self.assertEqual(sections["credentials"], ["root 600"])
        self.assertEqual(sections["nginx"], [f"{'a' * 8}  conf.d/gowave-panel.conf"])
        self.assertEqual(len(sections["units"]), 4)

    def test_the_cases_are_registered_with_their_own_budgets(self):
        cases = {case.id: case for case in aio.cases(ScriptedPodman(self.context, []))}
        self.assertEqual(cases["AIO-RESTART"].timeout_seconds,
                         aio.RESTART_TIMEOUT_SECONDS + aio.TUNNEL_READY_TIMEOUT_SECONDS
                         + aio.TRAFFIC_TIMEOUT_SECONDS)
        self.assertEqual(cases["AIO-IDEMPOTENT"].timeout_seconds,
                         aio.INSTALL_TIMEOUT_SECONDS + aio.TRAFFIC_TIMEOUT_SECONDS)


BROKEN_TAIL = (
    'nginx: [emerg] unknown directive "gowave_e2e_broken_probe" '
    f"in {aio.NGX_CONFIG_SNIPPET}:1\n"
    "nginx: configuration file /etc/nginx/nginx.conf test failed"
)


def nginx_probe(
    mode: str, *, test: int = 0, tail: str = "", hook: int = 0, active: str = "active",
    main_pid: str = "4242", before_workers: Sequence[str] = ("4243", "4244"),
    after_workers: Optional[Sequence[str]] = None, listeners: int = 1,
    after_listeners: Optional[int] = None, dump: Optional[dict] = None,
    present_before: bool = False, present: Optional[bool] = None,
    domain: str = aio.PANEL_DOMAIN,
) -> dict:
    """One phase's report, shaped exactly as the host probe prints it."""
    after = tuple(before_workers) if after_workers is None else tuple(after_workers)
    return {
        "mode": mode,
        "primary_domain": domain,
        "directive": aio.NGX_CONFIG_DIRECTIVE,
        "snippet": {
            "path": aio.NGX_CONFIG_SNIPPET,
            "present_before": present_before,
            "present": mode == "break" if present is None else present,
        },
        "config_files": ["/etc/nginx/conf.d/gowave-http.conf"],
        "test": {"returncode": test, "tail": tail},
        "dump": dump or {
            "returncode": 0, "bytes": 4096, "sha256": "a" * 64, "server_name_lines": 3,
            "ssl_preread": True, "primary_server_name": True, "tail": "",
        },
        "hook": {"present": True, "executable": True, "returncode": hook,
                 "stdout": "", "stderr": ""},
        "before_hook": {"active": active, "main_pid": main_pid,
                        "worker_pids": list(before_workers), "listeners_443": listeners},
        "after_hook": {"active": active, "main_pid": main_pid,
                       "worker_pids": list(after),
                       "listeners_443": listeners if after_listeners is None else after_listeners},
        "reload_waited_seconds": 0.5,
    }


class TestNginxConfigCase(unittest.TestCase):
    """NGX-05: a valid tree is reloaded, a broken one never reaches the master."""

    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def contract(self, *probes):
        product, podman = installed_product(
            self.context, [(json.dumps(probe), 0) for probe in probes],
        )
        return aio.case_nginx_config(product), podman

    def reject(self, expected: str, *probes):
        with self.assertRaises(AssertionError) as caught:
            self.contract(*probes)
        self.assertIn(expected, str(caught.exception))
        return caught

    def healthy_phases(self, **overrides):
        """The three phases of a passing run, with any phase's fields overridden."""
        return (
            nginx_probe("before", **overrides.get("before", {})),
            nginx_probe("break", test=1, tail=BROKEN_TAIL, present=True,
                        **overrides.get("broken", {})),
            nginx_probe("restore", after_workers=("5100", "5101"),
                        **overrides.get("restored", {})),
        )

    def test_the_case_refuses_a_broken_tree_and_reloads_the_restored_one(self):
        evidence, podman = self.contract(*self.healthy_phases())
        self.assertEqual(len(podman.scripts), 3)
        self.assertEqual(evidence["role"], "the All-in-One host")
        self.assertEqual(evidence["generated_config_files"], 1)
        self.assertEqual(evidence["invalid_configuration"]["nginx_test_returncode"], 1)
        self.assertIn(aio.NGX_CONFIG_DIRECTIVE, evidence["invalid_configuration"]["nginx_test_tail"])
        self.assertEqual(evidence["invalid_configuration"]["hook_returncode"], 0)
        self.assertEqual(evidence["invalid_configuration"]["worker_pids_before_hook"],
                         ["4243", "4244"])
        self.assertEqual(evidence["invalid_configuration"]["worker_pids"], ["4243", "4244"])
        self.assertEqual(evidence["restored_configuration"]["worker_pids_before"], ["4243", "4244"])
        self.assertEqual(evidence["restored_configuration"]["worker_pids_after"], ["5100", "5101"])

    def test_every_phase_carries_the_planted_snippet_and_the_guard_path(self):
        _evidence, podman = self.contract(*self.healthy_phases())
        for phase, script in zip(("before", "break", "restore"), podman.scripts):
            self.assertIn(phase, script)
            self.assertIn(aio.NGX_CONFIG_SNIPPET, script)
            self.assertIn(aio.NGX_CONFIG_HOOK, script)
            self.assertIn(aio.PANEL_DOMAIN, script)

    def run_probe(self, mode, *, nginx_test=0, hook_exit=0):
        """Run the real host probe body against stubbed binaries and a stub guard."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            bindir = root / "bin"
            bindir.mkdir()
            snippet = root / "zz-gowave-e2e-broken.conf"
            hook = root / "gowave-nginx.sh"
            marker = root / "hook-ran"
            hook.write_text(
                "#!/bin/sh\n" f"touch '{marker}'\n" f"exit {hook_exit}\n", encoding="utf-8",
            )
            hook.chmod(0o755)
            (bindir / "nginx").write_text(
                "#!/bin/sh\n"
                "case \"$1\" in\n"
                "  -t) printf '%s\\n' "
                f"'{aio.NGX_CONFIG_DIRECTIVE} is not allowed here' >&2; exit {nginx_test} ;;\n"
                "  -T) printf 'server_name %s;\\nssl_preread on;\\n' "
                f"'{aio.PANEL_DOMAIN}' ; exit 0 ;;\n"
                "esac\nexit 0\n",
                encoding="utf-8",
            )
            (bindir / "systemctl").write_text(
                "#!/bin/sh\n"
                "case \"$1 $2\" in\n"
                "  'is-active nginx') echo active ;;\n"
                "  'show -p') echo 4242 ;;\n"
                "esac\nexit 0\n",
                encoding="utf-8",
            )
            (bindir / "pgrep").write_text(
                "#!/bin/sh\necho 4243\necho 4244\n", encoding="utf-8",
            )
            (bindir / "ss").write_text(
                "#!/bin/sh\necho 'LISTEN 0 511 0.0.0.0:443 0.0.0.0:*'\n", encoding="utf-8",
            )
            for name in ("nginx", "systemctl", "pgrep", "ss"):
                (bindir / name).chmod(0o755)
            script = (
                aio.ngx_config_script(mode, aio.PANEL_DOMAIN)
                .replace(aio.NGX_CONFIG_SNIPPET, str(snippet))
                .replace(aio.NGX_CONFIG_HOOK, str(hook))
            )
            _, _, body = script.partition("<<'PY'\n")
            self.assertIn("import hashlib", body, "the probe script must carry a heredoc body")
            body = body.rsplit("\nPY\n", 1)[0]
            result = subprocess.run(
                [sys.executable, "-c", body, mode, aio.PANEL_DOMAIN],
                capture_output=True, text=True, check=False,
                env={**os.environ, "PATH": f"{bindir}:{os.environ.get('PATH', '')}"},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout), marker.exists()

    def test_the_baseline_phase_reports_the_guard_without_running_it(self):
        # Driving the guard on the untouched tree would reload the master, and the
        # workers that reload creates would then look like workers the break phase
        # gained.
        facts, ran = self.run_probe("before")
        self.assertTrue(facts["hook"]["present"])
        self.assertTrue(facts["hook"]["executable"])
        self.assertFalse(facts["hook"]["executed"])
        self.assertFalse(ran, "the baseline phase must not drive the deploy hook")

    def test_the_break_phase_drives_the_guard_and_reports_what_it_did(self):
        facts, ran = self.run_probe("break", nginx_test=1)
        self.assertTrue(facts["hook"]["executed"])
        self.assertTrue(ran, "the break phase has to drive the product's own guard")
        self.assertEqual(facts["hook"]["returncode"], 0)
        self.assertEqual(facts["before_hook"]["worker_pids"], ["4243", "4244"])
        self.assertEqual(facts["after_hook"]["worker_pids"], ["4243", "4244"])

    def test_a_reload_the_baseline_phase_saw_is_not_blamed_on_the_break_phase(self):
        # The break phase carries its own pre-guard reading, so a worker set that
        # differs from the earlier baseline phase is not evidence of anything.
        evidence, _podman = self.contract(
            nginx_probe("before", after_workers=("4300", "4301")),
            nginx_probe("break", test=1, tail=BROKEN_TAIL, present=True,
                        before_workers=("4300", "4301"), after_workers=("4300", "4301")),
            nginx_probe("restore", after_workers=("5100", "5101")),
        )
        self.assertEqual(evidence["invalid_configuration"]["worker_pids_before_hook"],
                         ["4300", "4301"])
        self.assertEqual(evidence["invalid_configuration"]["worker_pids"], ["4300", "4301"])

    def test_a_break_phase_that_read_no_worker_before_the_guard_fails_the_case(self):
        self.reject(
            "read no worker before driving the guard",
            nginx_probe("before"),
            nginx_probe("break", test=1, tail=BROKEN_TAIL, present=True,
                        before_workers=(), after_workers=("4300",)),
            nginx_probe("restore", after_workers=("5100",)),
        )

    def test_a_generated_tree_that_fails_nginx_t_fails_the_case(self):
        product, podman = installed_product(
            self.context, [(json.dumps(nginx_probe("before", test=1, tail="boom")), 0)],
        )
        with self.assertRaises(AssertionError) as caught:
            aio.case_nginx_config(product)
        self.assertIn("does not pass `nginx -t`", str(caught.exception))
        self.assertEqual(len(podman.scripts), 1, "nothing was planted, so nothing is restored")

    def test_a_dump_without_sni_routing_fails_the_case(self):
        dump = nginx_probe("before")["dump"]
        dump["ssl_preread"] = False
        self.reject("no ssl_preread SNI routing",
                    nginx_probe("before", dump=dump))

    def test_a_dump_without_the_deployments_own_server_name_fails_the_case(self):
        dump = nginx_probe("before")["dump"]
        dump["primary_server_name"] = False
        self.reject("no server_name for",
                    nginx_probe("before", dump=dump))

    def test_a_missing_deploy_hook_fails_the_case(self):
        probe = nginx_probe("before")
        probe["hook"] = {"present": False, "executable": False, "returncode": None,
                         "stdout": "", "stderr": ""}
        self.reject("deploy hook", probe)

    def test_a_snippet_nginx_never_validates_fails_the_case(self):
        self.reject(
            "left `nginx -t` succeeding",
            nginx_probe("before"),
            nginx_probe("break", test=0, present=True),
            nginx_probe("restore", after_workers=("5100",)),
        )

    def test_a_hook_that_reloads_a_broken_configuration_fails_the_case(self):
        self.reject(
            "reloaded NGINX with an invalid configuration",
            nginx_probe("before"),
            nginx_probe("break", test=1, tail=BROKEN_TAIL, present=True,
                        after_workers=("4300", "4301")),
            nginx_probe("restore", after_workers=("5100",)),
        )

    def test_a_hook_that_replaces_the_master_on_a_broken_configuration_fails_the_case(self):
        probe = nginx_probe("break", test=1, tail=BROKEN_TAIL, present=True)
        probe["after_hook"]["main_pid"] = "9001"
        self.reject(
            "replaced the NGINX master on an invalid configuration",
            nginx_probe("before"), probe,
        )

    def test_a_hook_that_fails_on_a_broken_configuration_fails_the_case(self):
        probe = nginx_probe("break", test=1, tail=BROKEN_TAIL, present=True, hook=1)
        probe["hook"]["stderr"] = "systemctl: Unit nginx.service not found."
        self.reject(
            "on an invalid configuration instead of leaving NGINX alone",
            nginx_probe("before"), probe,
        )

    def test_a_restore_that_never_reloads_fails_the_case(self):
        self.reject(
            "did not reload NGINX once the configuration was valid again",
            nginx_probe("before"),
            nginx_probe("break", test=1, tail=BROKEN_TAIL, present=True),
            nginx_probe("restore"),
        )

    def test_a_restore_that_restarts_the_master_fails_the_case(self):
        restored = nginx_probe("restore", after_workers=("5100",))
        restored["after_hook"]["main_pid"] = "9001"
        self.reject(
            "replaced the NGINX master instead of reloading it",
            nginx_probe("before"),
            nginx_probe("break", test=1, tail=BROKEN_TAIL, present=True),
            restored,
        )

    def test_a_restore_that_still_fails_nginx_t_fails_the_case(self):
        self.reject(
            "the restored configuration still fails `nginx -t`",
            nginx_probe("before"),
            nginx_probe("break", test=1, tail=BROKEN_TAIL, present=True),
            nginx_probe("restore", test=1, tail=BROKEN_TAIL, after_workers=("5100",)),
        )

    def test_the_snippet_is_removed_even_when_the_failing_probe_returns_nothing(self):
        product, podman = installed_product(self.context, [
            (json.dumps(nginx_probe("before")), 0),
            ("", 1),
            (json.dumps(nginx_probe("restore", after_workers=("5100",))), 0),
        ])
        with self.assertRaises(AssertionError) as caught:
            aio.case_nginx_config(product)
        self.assertIn("break probe", str(caught.exception))
        self.assertEqual(len(podman.scripts), 3, "the restore probe has to run from the finally block")
        self.assertIn("restore", podman.scripts[2])

    def test_a_restore_that_cannot_run_is_reported_instead_of_hiding_the_finding(self):
        product, podman = installed_product(self.context, [
            (json.dumps(nginx_probe("before")), 0),
            (json.dumps(nginx_probe("break", test=1, tail=BROKEN_TAIL, present=True)), 0),
            ("", 1),
        ])
        with self.assertRaises(AssertionError) as caught:
            aio.case_nginx_config(product)
        self.assertIn("the restore probe exited 1", str(caught.exception))
        self.assertEqual(len(podman.scripts), 3)

    def test_the_planted_directive_is_not_one_the_product_generates(self):
        for path in [*(REPO_ROOT / "modules").rglob("*.sh"),
                     REPO_ROOT / "gowave-auto.sh", REPO_ROOT / "gowave-node-auto.sh"]:
            self.assertNotIn(aio.NGX_CONFIG_DIRECTIVE, path.read_text(encoding="utf-8"), str(path))

    def test_the_case_is_registered_before_any_traffic_and_carries_a_bounded_budget(self):
        cases = {case.id: case for case in aio.cases(ScriptedPodman(self.context, []))}
        self.assertIn(aio.NGX_CONFIG_CASE_ID, cases)
        self.assertEqual(cases[aio.NGX_CONFIG_CASE_ID].timeout_seconds,
                         aio.NGX_CONFIG_TIMEOUT_SECONDS)
        self.assertEqual(cases[aio.NGX_CONFIG_CASE_ID].topology, "aio")
        ids = [case.id for case in aio.cases(ScriptedPodman(self.context, []))]
        self.assertLess(ids.index(aio.NGX_CONFIG_CASE_ID), ids.index("AIO-RESTART"))
        self.assertLess(ids.index(aio.NGX_CONFIG_CASE_ID), ids.index("AIO-REVOKE"))

    def test_the_case_is_catalogued_as_an_incubating_podman_first_case(self):
        entry = {case["id"]: case for case in catalog.load_catalog()["cases"]}
        self.assertIn(aio.NGX_CONFIG_CASE_ID, entry)
        record = entry[aio.NGX_CONFIG_CASE_ID]
        self.assertEqual(record["state"], "incubating")
        self.assertEqual(record["runs_in"], ["podman"])
        self.assertEqual(record["topology"], ["aio", "multi-node"])
        self.assertEqual(record["promotion_target"],
                         "NGINX SNI Routing and REALITY Decoy Verification")


def tls_policy(domain=aio.PANEL_DOMAIN, **overrides):
    """The host-side policy report for one HTTPS vhost, with a field overridden."""
    block = {
        "file": "/etc/nginx/conf.d/gowave-panel.conf",
        "server_names": [domain],
        "listen": ["127.0.0.1:7443 ssl proxy_protocol"],
        "ssl_protocols": ["TLSv1.2 TLSv1.3"],
        "ssl_certificate": [f"/etc/letsencrypt/live/{domain}/fullchain.pem"],
    }
    block.update(overrides)
    if block.pop("omit", False):
        return json.dumps({"domain": domain, "blocks": []})
    return json.dumps({"domain": domain, "blocks": [block]})


def acme_moment(seconds_ago: int = 0) -> int:
    return int(datetime.now(timezone.utc).timestamp()) - seconds_ago


def acme_certificate(
    path: str, serial: str, not_before_epoch: int, days: int = 90,
    domain: str = aio.PANEL_DOMAIN,
) -> dict:
    """One certificate as the host probe prints it, from the epoch it starts at."""
    starts = datetime.fromtimestamp(not_before_epoch, timezone.utc)
    return {
        "path": path,
        "present": True,
        "returncode": 0,
        "serial": serial,
        "subject": f"CN = {domain}",
        "issuer": "CN = Pebble Intermediate CA 123af5",
        "not_before": format_datetime(starts),
        "not_before_epoch": not_before_epoch,
        "not_after": format_datetime(starts + timedelta(days=days)),
        "not_after_epoch": not_before_epoch + days * 86400,
        "san": [domain],
    }


def acme_probe(
    mode: str, *, domain: str = aio.PANEL_DOMAIN,
    authenticator: str = "webroot", webroot_path: str = aio.ACME_WEBROOT,
    server: str = acme_fixture.ACME_DIRECTORY_URL,
    issued_epoch: Optional[int] = None, renewed_epoch: Optional[int] = None,
    installed_serial: str = "0A1B", renewed_serial: str = "0C2D",
    renewal_exit: int = 0, transcript: Optional[str] = None,
    workers_before: Sequence[str] = ("4243", "4244"),
    workers_after: Optional[Sequence[str]] = None,
    main_pid: str = "4242", listeners: int = 1, nginx_test: int = 0,
    lineage_present: bool = True,
) -> dict:
    """One phase's report, shaped exactly as the host probe prints it."""
    first = acme_moment(600) if issued_epoch is None else issued_epoch
    second = acme_moment(60) if renewed_epoch is None else renewed_epoch
    served = tuple(workers_before) if mode != "renew" else ("5100", "5101")
    after = served if workers_after is None else tuple(workers_after)
    live_path = f"{aio.ACME_LINEAGE_DIR}/{domain}/fullchain.pem"
    archive_path = f"{aio.ACME_ARCHIVE_DIR}/{domain}/cert1.pem"
    facts = {
        "mode": mode,
        "domain": domain,
        "webroot": webroot_path,
        "challenge_dir": f"{webroot_path}/.well-known/acme-challenge",
        "lineage": {
            "path": f"{aio.ACME_RENEWAL_DIR}/{domain}.conf",
            "present": lineage_present,
            "values": {
                "authenticator": authenticator,
                # Certbot serialises the webroot list with a trailing comma, so the
                # probe reports the raw value and the parsed list it means.
                "webroot_path": f"{webroot_path},",
                "webroot_paths": [webroot_path],
                "server": server,
            },
        },
        "live": acme_certificate(live_path, installed_serial, first),
        "archive": [acme_certificate(archive_path, installed_serial, first)],
        "service": {"active": "active", "main_pid": main_pid,
                    "worker_pids": list(workers_before), "listeners_443": listeners},
        "test": {"returncode": nginx_test, "tail": ""},
    }
    if mode != "renew":
        return facts
    text = transcript if transcript is not None else (
        f"http-01 challenge for {domain}\nSuccessfully received certificate"
    )
    facts.update({
        "renewal": {"returncode": renewal_exit, "stdout": text, "stderr": "",
                    "tail": text, "duration_seconds": 6.5},
        "certbot_log": text,
        "live_after": acme_certificate(live_path, renewed_serial, second),
        "archive_after": [
            acme_certificate(archive_path, installed_serial, first),
            acme_certificate(f"{aio.ACME_ARCHIVE_DIR}/{domain}/cert2.pem", renewed_serial, second),
        ],
        "service_after": {"active": "active", "main_pid": main_pid,
                          "worker_pids": list(after), "listeners_443": listeners},
        "test_after": {"returncode": nginx_test, "tail": ""},
        "reload_waited_seconds": 0.5,
    })
    return facts


def acme_route_report(status: int = 200, returncode: int = 0, body_length: int = 48) -> dict:
    """The independent client's fetch of a token from the product's port 80 vhost."""
    probe = {
        "url": f"http://{aio.PANEL_DOMAIN}/.well-known/acme-challenge/token",
        "status": status,
        "body_length": body_length,
        "body_sha256": "b" * 64,
    }
    return {"returncode": returncode, "probe": probe, "stdout": json.dumps(probe), "stderr": ""}


def acme_served_report(after: dict, **overrides) -> dict:
    """The handshake a client gets once the renewal reloaded NGINX."""
    renewed = (after.get("live_after") or {}).get("not_before_epoch")
    not_before = (
        format_datetime(datetime.fromtimestamp(renewed, timezone.utc))
        if isinstance(renewed, int) else certificate_day(-1)
    )
    return tls_report(not_before=not_before, not_after=certificate_day(60), **overrides)


class TestAcmeRenewalCase(unittest.TestCase):
    """ACME-01: the certificate is issued and renewed through the webroot route."""

    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def contract(self, before=None, after=None, route=None, served=None):
        before = acme_probe("before") if before is None else before
        after = acme_probe("renew") if after is None else after
        product, podman = installed_product(self.context, [
            (json.dumps(before), 0),
            ("", 0),
            ("", 0),
            (json.dumps(after), 0),
        ])
        product.host.client_reports = [
            acme_route_report() if route is None else route,
            acme_served_report(after) if served is None else served,
        ]
        return aio.case_acme_renewal(product), podman

    def reject(self, expected: str, **kwargs):
        with self.assertRaises(AssertionError) as caught:
            self.contract(**kwargs)
        self.assertIn(expected, str(caught.exception))
        return caught

    def test_the_case_walks_the_lineage_from_issuance_to_a_served_renewal(self):
        evidence, podman = self.contract()
        self.assertEqual(evidence["role"], "the All-in-One host")
        self.assertEqual(evidence["webroot"], aio.ACME_WEBROOT)
        self.assertEqual(evidence["lineage"]["authenticator"], "webroot")
        self.assertEqual(evidence["installed_certificate"]["serial"], "0A1B")
        self.assertEqual(evidence["challenge_route"]["status"], 200)
        self.assertEqual(evidence["renewal"]["serial_before"], "0A1B")
        self.assertEqual(evidence["renewal"]["serial_after"], "0C2D")
        self.assertEqual(evidence["renewal"]["installed_certificates_after"], 2)
        self.assertEqual(evidence["reload"]["worker_pids_after"], ["5100", "5101"])
        self.assertEqual(evidence["reload"]["master_pid"], "4242")
        self.assertEqual(len(podman.scripts), 4)
        self.assertTrue(podman.scripts[0].startswith("python3 - before "),
                        "the first phase only reads the lineage")
        self.assertIn(aio.ACME_WEBROOT, podman.scripts[0])
        self.assertTrue(podman.scripts[3].startswith("python3 - renew "))
        self.assertIn(aio.PANEL_DOMAIN, podman.scripts[3])

    def test_the_token_is_planted_in_the_products_own_webroot_and_removed_again(self):
        _evidence, podman = self.contract()
        self.assertIn(f"{aio.ACME_WEBROOT}/.well-known/acme-challenge/", podman.scripts[1])
        self.assertTrue(podman.scripts[2].startswith("rm -f "))

    def test_a_lineage_through_another_authenticator_fails_the_case(self):
        self.reject("authenticates as 'dns-01'",
                    before=acme_probe("before", authenticator="dns-01"))

    def test_a_renewal_that_writes_its_challenge_elsewhere_fails_the_case(self):
        self.reject("writes its challenge under ['/var/www/elsewhere']",
                    before=acme_probe("before", webroot_path="/var/www/elsewhere"))

    def test_a_lineage_against_another_acme_directory_fails_the_case(self):
        self.reject("instead of this run's ACME directory",
                    before=acme_probe("before", server="https://acme-v02.api.letsencrypt.org/directory"))

    def test_a_missing_renewal_lineage_fails_the_case(self):
        self.reject("keeps no renewal lineage",
                    before=acme_probe("before", lineage_present=False))

    def test_a_certificate_without_a_common_name_is_read_by_its_san(self):
        # Certbot 2.9.0 builds a SAN-only CSR, so the fixture CA signs a leaf with
        # an empty subject: the lineage is complete and readable all the same.
        without_cn = acme_probe("before")
        without_cn["live"].update({"subject": "", "san": [aio.PANEL_DOMAIN]})
        evidence, _podman = self.contract(before=without_cn)
        self.assertEqual(evidence["installed_certificate"]["serial"], "0A1B")

    def test_a_certificate_the_reader_cannot_parse_reports_the_readers_words(self):
        unreadable = acme_probe("before")
        unreadable["live"] = {
            "path": f"{aio.ACME_LINEAGE_DIR}/{aio.PANEL_DOMAIN}/fullchain.pem",
            "present": True,
            "returncode": 1,
            "error": "Could not read certificate from fullchain.pem",
        }
        caught = self.reject("`openssl x509` exited 1", before=unreadable)
        self.assertIn("Could not read certificate from fullchain.pem", str(caught.exception))

    def test_a_certificate_that_predates_the_run_is_refused_as_seeded(self):
        self.reject("it was seeded rather than obtained",
                    before=acme_probe("before", issued_epoch=acme_moment(3 * 86400)))

    def test_a_port_80_vhost_that_does_not_serve_the_token_fails_the_case(self):
        self.reject("instead of serving the token", route=acme_route_report(status=444))

    def test_a_route_the_client_cannot_reach_fails_the_case(self):
        self.reject("could not fetch http://",
                    route={"returncode": 1, "probe": {"url": "http://x/"},
                           "stdout": "", "stderr": "connection refused"})

    def test_a_renewal_that_never_performs_http01_fails_the_case(self):
        self.reject("did not perform an HTTP-01 challenge",
                    after=acme_probe("renew", transcript="dns-01 challenge for "
                                     f"{aio.PANEL_DOMAIN}\nSuccessfully received certificate"))

    def test_a_renewal_that_receives_no_certificate_fails_the_case(self):
        self.reject("exited 1", after=acme_probe("renew", renewal_exit=1))

    def test_a_renewal_that_reuses_the_serial_fails_the_case(self):
        self.reject("still reports certificate serial '0A1B'",
                    after=acme_probe("renew", renewed_serial="0A1B"))

    def test_a_renewal_that_keeps_the_same_archive_entry_fails_the_case(self):
        expired = acme_probe("renew")
        expired["archive_after"] = expired["archive"]
        self.reject("holds 1 certificate(s) after a forced renewal", after=expired)

    def test_a_renewal_that_never_reloads_nginx_fails_the_case(self):
        self.reject("did not reload NGINX after the renewal",
                    after=acme_probe("renew", workers_after=("4243", "4244")))

    def test_a_renewal_that_replaces_the_master_fails_the_case(self):
        replaced = acme_probe("renew")
        replaced["service_after"]["main_pid"] = "9001"
        self.reject("instead of reloading it", after=replaced)

    def test_a_leaf_the_client_still_receives_from_the_old_lineage_fails_the_case(self):
        self.reject("so NGINX is still serving the replaced lineage",
                    served=tls_report(not_before=certificate_day(-1)))

    def test_the_planted_token_is_removed_even_when_the_route_is_refused(self):
        product, podman = installed_product(self.context, [
            (json.dumps(acme_probe("before")), 0),
            ("", 0),
            ("", 0),
        ])
        product.host.client_reports = [acme_route_report(status=444)]
        with self.assertRaises(AssertionError) as caught:
            aio.case_acme_renewal(product)
        self.assertIn("instead of serving the token", str(caught.exception))
        self.assertEqual(len(podman.scripts), 3, "the token has to be removed from the finally block")
        self.assertTrue(podman.scripts[2].startswith("rm -f "))

    def test_a_host_that_refuses_the_token_write_fails_the_case_and_writes_nothing(self):
        product, podman = installed_product(self.context, [
            (json.dumps(acme_probe("before")), 0),
            ("", 1),
            ("", 0),
        ])
        product.host.client_reports = []
        with self.assertRaises(AssertionError) as caught:
            aio.case_acme_renewal(product)
        self.assertIn("could not write a challenge token", str(caught.exception))
        self.assertTrue(podman.scripts[2].startswith("rm -f "))

    def test_the_case_is_registered_before_any_traffic_and_carries_a_bounded_budget(self):
        cases = {case.id: case for case in aio.cases(ScriptedPodman(self.context, []))}
        self.assertIn(aio.ACME_CASE_ID, cases)
        self.assertEqual(cases[aio.ACME_CASE_ID].timeout_seconds, aio.ACME_TIMEOUT_SECONDS)
        self.assertEqual(cases[aio.ACME_CASE_ID].topology, "aio")
        ids = [case.id for case in aio.cases(ScriptedPodman(self.context, []))]
        self.assertLess(ids.index(aio.NGX_CONFIG_CASE_ID), ids.index(aio.ACME_CASE_ID))
        self.assertLess(ids.index(aio.ACME_CASE_ID), ids.index("SUB-SERVED"))
        self.assertLess(ids.index(aio.ACME_CASE_ID), ids.index("AIO-RESTART"))

    def test_the_case_is_catalogued_as_an_incubating_podman_first_case(self):
        entry = {case["id"]: case for case in catalog.load_catalog()["cases"]}
        self.assertIn(aio.ACME_CASE_ID, entry)
        record = entry[aio.ACME_CASE_ID]
        self.assertEqual(record["state"], "incubating")
        self.assertEqual(record["runs_in"], ["podman"])
        self.assertEqual(record["topology"], ["aio"])
        self.assertEqual(record["promotion_target"], "Global Certbot Deploy Hook Ownership")


class TestAcmeRenewalProbe(unittest.TestCase):
    """ACME-01's host probe: what it reads, and what it runs, on a real tree."""

    def build_target(self, tmpdir: Path, main_pid: str, domain: str = aio.PANEL_DOMAIN) -> dict:
        root = tmpdir
        renewal = root / "renewal"
        archive = root / "archive" / domain
        live_root = root / "live"
        live = live_root / domain
        webroot = root / "webroot"
        logs = root / "logs"
        for directory in (renewal, archive, live, webroot, logs):
            directory.mkdir(parents=True, exist_ok=True)
        (renewal / f"{domain}.conf").write_text(
            "# renew_before_expiry = 30 days\n"
            "version = 4.1.1\n"
            "archive_dir = /etc/letsencrypt/archive/" + domain + "\n"
            "cert = /etc/letsencrypt/live/" + domain + "/cert.pem\n"
            "privkey = /etc/letsencrypt/live/" + domain + "/privkey.pem\n"
            f"server = {acme_fixture.ACME_DIRECTORY_URL}\n"
            "authenticator = webroot\n"
            f"webroot_path = {aio.ACME_WEBROOT},\n"
            "[[webroot_map]]\n",
            encoding="utf-8",
        )
        (archive / "cert1.pem").write_text("old", encoding="utf-8")
        (live / "fullchain.pem").write_text("old", encoding="utf-8")

        bindir = root / "bin"
        bindir.mkdir()
        marker = root / "renewed"
        anchor = root / "anchor"

        def write(name: str, body: str) -> None:
            path = bindir / name
            path.write_text(body, encoding="utf-8")
            path.chmod(0o755)

        write("openssl", (
            "#!/bin/sh\n"
            'path=""\n'
            'while [ $# -gt 0 ]; do\n'
            '  if [ "$1" = "-in" ]; then shift; path="$1"; fi\n'
            "  shift\n"
            "done\n"
            'if [ -f "$path" ] && [ "$(cat "$path")" = "new" ]; then\n'
            f"  printf '%s' 'serial=0C2D\n"
            f"subject=CN = {domain}\n"
            "issuer=CN = Pebble Intermediate CA 123af5\n"
            "notBefore=Nov 13 10:30:00 2026 GMT\n"
            "notAfter=Feb 11 10:30:00 2027 GMT\n"
            "X509v3 Subject Alternative Name: \n"
            f"    DNS:{domain}\n'\n"
            "else\n"
            f"  printf '%s' 'serial=0A1B\n"
            f"subject=CN = {domain}\n"
            "issuer=CN = Pebble Intermediate CA 123af5\n"
            "notBefore=Nov 13 09:59:52 2026 GMT\n"
            "notAfter=Feb 11 09:59:51 2027 GMT\n"
            "X509v3 Subject Alternative Name: \n"
            f"    DNS:{domain}\n'\n"
            "fi\n"
            "exit 0\n"
        ))
        write("certbot", (
            "#!/bin/sh\n"
            'log_dir=""\n'
            'while [ $# -gt 0 ]; do\n'
            '  if [ "$1" = "--logs-dir" ]; then shift; log_dir="$1"; fi\n'
            "  shift\n"
            "done\n"
            'mkdir -p "$log_dir"\n'
            f"printf '%s\\n' 'http-01 challenge for {domain}' >> \"$log_dir/letsencrypt.log\"\n"
            "printf '%s\\n' 'Successfully received certificate' >> \"$log_dir/letsencrypt.log\"\n"
            'printf %s "$REQUESTS_CA_BUNDLE" > ' + str(anchor) + "\n"
            f"printf 'new' > {archive}/cert2.pem\n"
            f"printf 'new' > {live}/fullchain.pem\n"
            f"touch {marker}\n"
            f"printf '%s\\n' 'http-01 challenge for {domain}'\n"
            "printf '%s\\n' 'Successfully received certificate'\n"
            "exit 0\n"
        ))
        write("systemctl", (
            "#!/bin/sh\n"
            'case "$1 $2" in\n'
            '  "is-active nginx") echo active ;;\n'
            f'  "show -p") echo {main_pid} ;;\n'
            "esac\n"
            "exit 0\n"
        ))
        write("pgrep", (
            "#!/bin/sh\n"
            f'if [ -f {marker} ]; then echo 5100; echo 5101; else echo 4243; echo 4244; fi\n'
        ))
        write("ss", "#!/bin/sh\necho 'LISTEN 0 511 0.0.0.0:443 0.0.0.0:*'\n")
        write("nginx", "#!/bin/sh\nexit 0\n")
        return {
            "root": root, "bindir": bindir, "marker": marker, "anchor": anchor,
            "renewal": renewal, "archive_root": archive.parent, "archive": archive,
            "live_root": live_root, "live": live, "webroot": webroot, "logs": logs,
        }

    def run_probe(self, mode: str, layout: dict, main_pid: str) -> dict:
        domain = aio.PANEL_DOMAIN
        ca_file = "/fixtures/ca/acme-trust.pem"
        script = (
            aio.acme_renewal_script(mode, domain, ca_file)
            .replace(aio.ACME_RENEWAL_LOG_DIR, str(layout["logs"]))
            .replace(aio.ACME_RENEWAL_DIR, str(layout["renewal"]))
            .replace(aio.ACME_ARCHIVE_DIR, str(layout["archive_root"]))
            .replace(aio.ACME_LINEAGE_DIR, str(layout["live_root"]))
            .replace(aio.ACME_WEBROOT, str(layout["webroot"]))
        )
        _, _, body = script.partition("<<'PY'\n")
        self.assertIn("import calendar", body, "the probe script must carry a heredoc body")
        body = body.rsplit("\nPY\n", 1)[0]
        result = subprocess.run(
            [sys.executable, "-c", body, mode, domain, ca_file],
            capture_output=True, text=True, check=False,
            env={**os.environ, "PATH": f"{layout['bindir']}:{os.environ.get('PATH', '')}"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def spare_pid(self) -> str:
        """A PID no process holds, so the probe reads its workers from pgrep."""
        for candidate in range(30000, 40000):
            if not Path(f"/proc/{candidate}").exists():
                return str(candidate)
        self.skipTest("no free PID to stub the NGINX master with")

    def test_the_baseline_phase_reads_the_lineage_and_never_renews(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            main_pid = self.spare_pid()
            layout = self.build_target(Path(tmpdir), main_pid)
            facts = self.run_probe("before", layout, main_pid)
        self.assertEqual(facts["mode"], "before")
        self.assertEqual(facts["lineage"]["values"]["authenticator"], "webroot")
        # Certbot writes the webroot as a list, so the raw value keeps its trailing
        # comma and the parsed list is what the case compares.
        self.assertEqual(facts["lineage"]["values"]["webroot_path"], f"{aio.ACME_WEBROOT},")
        self.assertEqual(facts["lineage"]["values"]["webroot_paths"], [aio.ACME_WEBROOT])
        self.assertEqual(facts["live"]["serial"], "0A1B")
        self.assertEqual(len(facts["archive"]), 1)
        self.assertEqual(facts["service"]["worker_pids"], ["4243", "4244"])
        self.assertNotIn("renewal", facts)

    def test_the_renew_phase_renews_with_a_scoped_anchor_and_reads_the_new_leaf(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            main_pid = self.spare_pid()
            layout = self.build_target(Path(tmpdir), main_pid)
            facts = self.run_probe("renew", layout, main_pid)
            anchor = layout["anchor"].read_text(encoding="utf-8")
        self.assertEqual(facts["renewal"]["returncode"], 0)
        self.assertIn(f"http-01 challenge for {aio.PANEL_DOMAIN}", facts["certbot_log"])
        self.assertIn("Successfully received certificate", facts["certbot_log"])
        self.assertEqual(facts["live_after"]["serial"], "0C2D")
        self.assertEqual(len(facts["archive_after"]), 2)
        self.assertEqual([item["serial"] for item in facts["archive_after"]], ["0A1B", "0C2D"])
        self.assertGreater(facts["live_after"]["not_before_epoch"], facts["live"]["not_before_epoch"])
        self.assertEqual(facts["service"]["main_pid"], facts["service_after"]["main_pid"])
        self.assertEqual(facts["service_after"]["worker_pids"], ["5100", "5101"])
        self.assertEqual(anchor, "/fixtures/ca/acme-trust.pem",
                         "the renewal has to be handed the fixture CA the install used")

    def test_an_unreadable_certificate_keeps_the_readers_own_diagnostics(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            main_pid = self.spare_pid()
            layout = self.build_target(Path(tmpdir), main_pid)
            failing = layout["bindir"] / "openssl"
            failing.write_text(
                "#!/bin/sh\n"
                "echo 'Could not read certificate from fullchain.pem' >&2\n"
                "exit 1\n",
                encoding="utf-8",
            )
            failing.chmod(0o755)
            facts = self.run_probe("before", layout, main_pid)
        self.assertTrue(facts["live"]["present"])
        self.assertEqual(facts["live"]["returncode"], 1)
        self.assertIn("Could not read certificate", facts["live"]["error"])

    def test_the_renewal_uses_the_lineages_own_name_and_a_forced_reissue(self):
        script = aio.acme_renewal_script("renew", aio.PANEL_DOMAIN, "/ca.pem")
        self.assertIn('"certbot", "renew", "--cert-name"', script)
        self.assertIn("--force-renewal", script)
        self.assertIn("--non-interactive", script)
        self.assertIn("webroot", script)
        self.assertIn(aio.ACME_WEBROOT, script)


def acme_outage_report(mode: str, **overrides) -> dict:
    """One outage phase as the host probe reports it, with the effect that phase has."""
    report = {
        "mode": mode,
        "webroot": aio.ACME_WEBROOT,
        "webroot_mode": "0755",
        "resolution": f"172.30.0.9 {acme_fixture.FIXTURE_HOST}",
    }
    if mode == "challenge-block":
        report["webroot_mode_after"] = "0700"
    elif mode == "challenge-restore":
        report["webroot_mode_after"] = "0755"
    elif mode == "directory-block":
        report["resolution_after"] = f"127.0.0.1 {acme_fixture.FIXTURE_HOST}"
    elif mode == "directory-restore":
        report["resolution"] = f"127.0.0.1 {acme_fixture.FIXTURE_HOST}"
        report["resolution_after"] = f"172.30.0.9 {acme_fixture.FIXTURE_HOST}"
    report.update(overrides)
    return report


FAILED_CHALLENGE_TRANSCRIPT = (
    "http-01 challenge for {domain}\n"
    "Certbot failed to authenticate some domains (authenticator: webroot)\n"
    "Some challenges have failed."
)

FAILED_DIRECTORY_TRANSCRIPT = (
    "An unexpected error occurred:\n"
    "requests.exceptions.ConnectionError: HTTPSConnectionPool(host='{host}', port=14000): "
    "Max retries exceeded with url: /dir (Caused by NewConnectionError(... Connection refused))"
)


def acme_failed_attempt(kind: str = "challenge", **overrides) -> dict:
    """A forced renewal the outage denied: it reports the failure and saves nothing."""
    domain = overrides.pop("domain", aio.PANEL_DOMAIN)
    transcript = overrides.pop("transcript", None)
    if transcript is None:
        template = (FAILED_CHALLENGE_TRANSCRIPT if kind == "challenge"
                    else FAILED_DIRECTORY_TRANSCRIPT)
        transcript = template.format(domain=domain, host=acme_fixture.FIXTURE_HOST)
    facts = acme_probe(
        "renew", domain=domain, renewal_exit=1, transcript=transcript,
        installed_serial=overrides.pop("serial", "0A1B"), **overrides,
    )
    facts["live_after"] = dict(facts["live"])
    facts["archive_after"] = list(facts["archive"])
    facts["service_after"] = dict(facts["service"])
    return facts


class TestAcmeOutageCase(unittest.TestCase):
    """ACME-02: both ACME outages fail closed and leave the working lineage serving."""

    installed = acme_moment(900)
    first_renewal = acme_moment(600)
    second_renewal = acme_moment(60)

    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def phases(self) -> dict:
        return {
            "before": acme_probe("before", issued_epoch=self.installed),
            "challenge_block": acme_outage_report("challenge-block"),
            "challenge_attempt": acme_failed_attempt("challenge", issued_epoch=self.installed),
            "challenge_restore": acme_outage_report("challenge-restore"),
            "challenge_recovered": acme_probe(
                "renew", issued_epoch=self.installed, renewed_epoch=self.first_renewal,
            ),
            "directory_block": acme_outage_report("directory-block"),
            "directory_attempt": acme_failed_attempt(
                "directory", issued_epoch=self.first_renewal, serial="0C2D",
            ),
            "directory_restore": acme_outage_report("directory-restore"),
            "directory_renewed": acme_probe(
                "renew", issued_epoch=self.first_renewal, installed_serial="0C2D",
                renewed_epoch=self.second_renewal, renewed_serial="0E3F",
            ),
        }

    def contract(self, routes=None, served=None, **phases):
        """Run the case over the phases, the token routes, and the client handshakes."""
        plan = self.phases()
        plan.update(phases)
        scripts = [
            (json.dumps(plan["before"]), 0),
            (json.dumps(plan["challenge_block"]), 0),
            ("", 0), ("", 0),
            (json.dumps(plan["challenge_attempt"]), 0),
            (json.dumps(plan["challenge_restore"]), 0),
            ("", 0), ("", 0),
            (json.dumps(plan["challenge_recovered"]), 0),
            (json.dumps(plan["directory_block"]), 0),
            (json.dumps(plan["directory_attempt"]), 0),
            (json.dumps(plan["directory_restore"]), 0),
            (json.dumps(plan["directory_renewed"]), 0),
        ]
        product, podman = installed_product(self.context, scripts)
        if routes is None:
            routes = [acme_route_report(status=403), acme_route_report()]
        if served is None:
            served = [acme_served_report(plan[name]) for name in (
                "challenge_attempt", "challenge_recovered",
                "directory_attempt", "directory_renewed",
            )]
        # The case reads the route, then a handshake, then the route again, then
        # the three handshakes that follow each renewal.
        product.host.client_reports = [
            routes[0], served[0], routes[1], served[1], served[2], served[3],
        ]
        return aio.case_acme_outage(product), podman

    def reject(self, expected: str, **kwargs):
        with self.assertRaises(AssertionError) as caught:
            self.contract(**kwargs)
        self.assertIn(expected, str(caught.exception))
        return caught

    def test_each_outage_fails_closed_and_the_lineage_survives_both(self):
        evidence, podman = self.contract()
        self.assertEqual(evidence["role"], "the All-in-One host")
        self.assertEqual(evidence["installed_certificate"]["serial"], "0A1B")
        challenge = evidence["challenge_outage"]
        self.assertEqual(challenge["control"]["status"], 403, "the closed route refused the token")
        self.assertIn("Some challenges have failed", challenge["failure"]["reported"])
        self.assertEqual(challenge["lineage"]["serial"], "0A1B")
        self.assertEqual(challenge["lineage"]["archive"], 1)
        self.assertEqual(challenge["restored_mode"], "0755")
        self.assertEqual(challenge["route_after_restore"]["status"], 200)
        self.assertEqual(challenge["recovery"]["serial_after"], "0C2D")
        directory = evidence["directory_outage"]
        self.assertTrue(directory["control"]["loopback"])
        self.assertTrue(directory["failure"]["reported"])
        self.assertEqual(directory["lineage"]["serial"], "0C2D")
        self.assertTrue(directory["resolution_after_release"].startswith("172.30.0.9"))
        self.assertEqual(directory["recovery"]["serial_after"], "0E3F")
        self.assertEqual(len(podman.scripts), 13)
        self.assertTrue(podman.scripts[0].startswith("python3 - before "))
        self.assertTrue(podman.scripts[4].startswith("python3 - renew "))
        self.assertIn(aio.ACME_BLACKHOLE_MARKER, podman.scripts[9])
        self.assertIn(str(aio.ACME_OUTAGE_RELOAD_WAIT_SECONDS), podman.scripts[4])

    def test_the_failed_attempt_is_not_waited_for_like_a_reload(self):
        _evidence, podman = self.contract()
        self.assertIn(f"RELOAD_WAIT_SECONDS = {aio.ACME_OUTAGE_RELOAD_WAIT_SECONDS}",
                      podman.scripts[4])
        self.assertIn(f"RELOAD_WAIT_SECONDS = {aio.ACME_RENEWAL_WAIT_SECONDS}",
                      podman.scripts[8])

    def test_a_webroot_that_never_closed_fails_the_case(self):
        self.reject("so the validator's path was never closed",
                    challenge_block=acme_outage_report("challenge-block",
                                                       webroot_mode_after="0755"))

    def test_a_renewal_that_succeeds_during_the_challenge_outage_fails_the_case(self):
        self.reject("although the challenge was down",
                    challenge_attempt=acme_probe("renew", issued_epoch=self.installed))

    def test_a_failure_that_never_attempted_http01_fails_the_case(self):
        self.reject("never attempted an HTTP-01 challenge",
                    challenge_attempt=acme_failed_attempt(
                        "challenge", issued_epoch=self.installed,
                        transcript="Some challenges have failed.",
                    ))

    def test_a_failure_that_does_not_name_its_cause_fails_the_case(self):
        self.reject("failed without naming the challenge",
                    challenge_attempt=acme_failed_attempt(
                        "challenge", issued_epoch=self.installed,
                        transcript=f"http-01 challenge for {aio.PANEL_DOMAIN}\nunknown problem",
                    ))

    def test_a_failed_attempt_that_replaced_the_leaf_fails_the_case(self):
        attempt = acme_failed_attempt("challenge", issued_epoch=self.installed)
        attempt["live_after"] = acme_certificate(
            f"{aio.ACME_LINEAGE_DIR}/{aio.PANEL_DOMAIN}/fullchain.pem", "0E3F",
            self.first_renewal,
        )
        self.reject("changed the installed certificate", challenge_attempt=attempt)

    def test_a_failed_attempt_that_grew_the_archive_fails_the_case(self):
        attempt = acme_failed_attempt("challenge", issued_epoch=self.installed)
        attempt["archive_after"] = list(attempt["archive"]) + list(attempt["archive"])
        self.reject("added a certificate to the archive", challenge_attempt=attempt)

    def test_a_served_certificate_that_changed_after_the_failure_fails_the_case(self):
        plan = self.phases()
        self.reject(
            "disturbed the certificate the host was serving",
            served=[
                tls_report(not_before=certificate_day(-2)),
                acme_served_report(plan["challenge_recovered"]),
                acme_served_report(plan["directory_attempt"]),
                acme_served_report(plan["directory_renewed"]),
            ],
        )

    def test_a_webroot_left_closed_fails_the_case(self):
        self.reject("instead of '0755' after the outage was removed",
                    challenge_restore=acme_outage_report("challenge-restore",
                                                         webroot_mode_after="0700"))

    def test_a_recovery_that_reuses_the_serial_fails_the_case(self):
        self.reject("still reports certificate serial '0A1B'",
                    challenge_recovered=acme_probe(
                        "renew", issued_epoch=self.installed,
                        renewed_epoch=self.first_renewal, renewed_serial="0A1B",
                    ))

    def test_a_directory_that_stayed_reachable_fails_the_case(self):
        self.reject("when the directory was supposed to be unreachable",
                    directory_block=acme_outage_report("directory-block",
                                                       resolution_after=f"172.30.0.9 {acme_fixture.FIXTURE_HOST}"))

    def test_a_directory_left_unreachable_fails_the_case(self):
        self.reject("when the directory was supposed to be reachable",
                    directory_restore=acme_outage_report(
                        "directory-restore",
                        resolution_after=f"127.0.0.1 {acme_fixture.FIXTURE_HOST}",
                    ))

    def test_the_case_is_registered_before_any_traffic_and_carries_a_bounded_budget(self):
        cases = {case.id: case for case in aio.cases(ScriptedPodman(self.context, []))}
        self.assertIn(aio.ACME_OUTAGE_CASE_ID, cases)
        self.assertEqual(cases[aio.ACME_OUTAGE_CASE_ID].timeout_seconds,
                         aio.ACME_OUTAGE_TIMEOUT_SECONDS)
        self.assertEqual(cases[aio.ACME_OUTAGE_CASE_ID].topology, "aio")
        ids = [case.id for case in aio.cases(ScriptedPodman(self.context, []))]
        self.assertLess(ids.index(aio.ACME_CASE_ID), ids.index(aio.ACME_OUTAGE_CASE_ID))
        self.assertLess(ids.index(aio.ACME_OUTAGE_CASE_ID), ids.index("AIO-AUTH"))

    def test_the_case_is_catalogued_as_an_incubating_podman_first_case(self):
        entry = {case["id"]: case for case in catalog.load_catalog()["cases"]}
        self.assertIn(aio.ACME_OUTAGE_CASE_ID, entry)
        record = entry[aio.ACME_OUTAGE_CASE_ID]
        self.assertEqual(record["state"], "incubating")
        self.assertEqual(record["runs_in"], ["podman"])
        self.assertEqual(record["topology"], ["aio"])
        self.assertEqual(record["promotion_target"], "Global Certbot Deploy Hook Ownership")


class TestAcmeOutageProbe(unittest.TestCase):
    """ACME-02's outage probe: what it changes on a real tree, and what it puts back."""

    def build_target(self, tmpdir: Path) -> dict:
        webroot = tmpdir / "webroot"
        webroot.mkdir()
        webroot.chmod(0o755)
        hosts = tmpdir / "hosts"
        hosts.write_text("127.0.0.1 localhost\n172.30.0.9 pebble.testnet\n", encoding="utf-8")
        return {"webroot": webroot, "hosts": hosts}

    def run_probe(self, mode: str, layout: dict, original_mode: str = "") -> dict:
        script = (
            aio.acme_outage_script(mode, original_mode, str(layout["hosts"]))
            .replace(aio.ACME_WEBROOT, str(layout["webroot"]))
        )
        _, _, body = script.partition("<<'PY'\n")
        body = body.rsplit("\nPY\n", 1)[0]
        args = [mode, str(layout["webroot"]), original_mode, acme_fixture.FIXTURE_HOST,
                aio.ACME_BLACKHOLE_MARKER, str(layout["hosts"])]
        result = subprocess.run(
            [sys.executable, "-c", body, *args],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_closing_the_webroot_records_what_it_found_and_what_it_did(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            layout = self.build_target(Path(tmpdir))
            facts = self.run_probe("challenge-block", layout)
            after = layout["webroot"].stat().st_mode & 0o777
        self.assertEqual(facts["webroot_mode"], "0755")
        self.assertEqual(facts["webroot_mode_after"], "0700")
        self.assertEqual(after, 0o700)

    def test_restoring_puts_the_original_mode_back(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            layout = self.build_target(Path(tmpdir))
            layout["webroot"].chmod(0o750)
            self.run_probe("challenge-block", layout)
            facts = self.run_probe("challenge-restore", layout, "0750")
            after = layout["webroot"].stat().st_mode & 0o777
        self.assertEqual(facts["webroot_mode_after"], "0750")
        self.assertEqual(after, 0o750)

    def test_blackholing_the_directory_keeps_the_hosts_entry_and_leaves_the_rest(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            layout = self.build_target(Path(tmpdir))
            self.run_probe("directory-block", layout)
            lines = layout["hosts"].read_text(encoding="utf-8").splitlines()
            self.run_probe("directory-restore", layout)
            restored = layout["hosts"].read_text(encoding="utf-8").splitlines()
        self.assertIn(f"127.0.0.1 {acme_fixture.FIXTURE_HOST}  # {aio.ACME_BLACKHOLE_MARKER}", lines)
        self.assertIn("127.0.0.1 localhost", lines)
        self.assertFalse([line for line in restored if aio.ACME_BLACKHOLE_MARKER in line])
        self.assertEqual(restored, ["127.0.0.1 localhost", "172.30.0.9 pebble.testnet"])

    def test_a_second_block_does_not_duplicate_the_line(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            layout = self.build_target(Path(tmpdir))
            self.run_probe("directory-block", layout)
            self.run_probe("directory-block", layout)
            lines = layout["hosts"].read_text(encoding="utf-8").splitlines()
        self.assertEqual(len([line for line in lines if aio.ACME_BLACKHOLE_MARKER in line]), 1)


def certificate_day(days: float = 0) -> str:
    """A certificate time relative to now, in the form the peer report carries."""
    return format_datetime(datetime.now(timezone.utc) + timedelta(days=days))


def tls_report(
    domain=aio.PANEL_DOMAIN, status=200, san=None, version="TLSv1.3",
    not_before=None, not_after=None,
    issuer="CN=Pebble Intermediate CA", returncode=0, error="",
):
    """One independent-client handshake report, as the probe prints it."""
    peer = {
        "san": [domain] if san is None else san,
        "tls_version": version,
        "cipher": "TLS_AES_256_GCM_SHA384",
        "issuer": issuer,
        "not_before": certificate_day(-30) if not_before is None else not_before,
        "not_after": certificate_day(60) if not_after is None else not_after,
    }
    probe = {"url": f"https://{domain}/", "status": status, "peer": peer}
    if error:
        probe["error"] = error
    return {"returncode": returncode, "probe": probe, "stdout": json.dumps(probe), "stderr": ""}


def tls_refused(error):
    """A handshake the probe could not complete."""
    return {"returncode": 1, "probe": {"url": "https://x/", "error": error}, "stdout": "", "stderr": ""}


class TestTlsSurfaceCase(unittest.TestCase):
    """TLS-01: the certificate a client validates is the one this role serves."""

    CHAIN_ERROR = (
        "SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
        "unable to get local issuer certificate"
    )

    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def contract(self, policy=None, verified=None, tls12=None, legacy=None, untrusted=None):
        product, podman = installed_product(
            self.context, [((tls_policy() if policy is None else policy), 0)],
        )
        product.host.client_reports = [
            tls_report() if verified is None else verified,
            tls_report(version="TLSv1.2") if tls12 is None else tls12,
            tls_refused("SSLError: [SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure")
            if legacy is None else legacy,
            tls_refused(self.CHAIN_ERROR) if untrusted is None else untrusted,
        ]
        return aio.case_tls_surface(product), podman

    def reject(self, expected, **kwargs):
        with self.assertRaises(AssertionError) as caught:
            self.contract(**kwargs)
        self.assertIn(expected, str(caught.exception))
        return caught

    def test_a_healthy_host_reports_the_handshake_it_observed(self):
        evidence, podman = self.contract()
        self.assertEqual(evidence["role"], "the All-in-One host")
        self.assertEqual(evidence["domain"], aio.PANEL_DOMAIN)
        self.assertEqual(evidence["policy"]["ssl_protocols"], ["TLSv1.2", "TLSv1.3"])
        self.assertEqual(evidence["verified"]["san"], [aio.PANEL_DOMAIN])
        self.assertEqual(evidence["verified"]["tls_version"], "TLSv1.3")
        self.assertEqual(evidence["tls12_pinned"]["tls_version"], "TLSv1.2")
        self.assertTrue(evidence["legacy_refused"]["refused"])
        self.assertTrue(evidence["untrusted_refused"]["refused"])
        self.assertGreater(evidence["verified"]["remaining_seconds"],
                           aio.TLS_MINIMUM_REMAINING_SECONDS)
        self.assertEqual(len(podman.scripts), 1)
        self.assertIn(aio.PANEL_DOMAIN, podman.scripts[0])

    def test_a_vhost_that_inherits_its_protocol_policy_is_refused(self):
        self.reject("inherits its TLS protocol policy",
                    policy=tls_policy(ssl_protocols=[]))

    def test_a_vhost_that_allows_a_legacy_protocol_is_refused(self):
        self.reject("allows",
                    policy=tls_policy(ssl_protocols=["TLSv1 TLSv1.1 TLSv1.2 TLSv1.3"]))

    def test_a_vhost_serving_another_lineage_is_refused(self):
        self.reject("instead of the lineage",
                    policy=tls_policy(ssl_certificate=["/etc/letsencrypt/live/other.testbed.internal/fullchain.pem"]))

    def test_two_https_blocks_for_one_name_are_refused(self):
        self.reject("HTTPS server blocks claim",
                    policy=json.dumps({"domain": aio.PANEL_DOMAIN, "blocks": [
                        json.loads(tls_policy())["blocks"][0],
                        json.loads(tls_policy())["blocks"][0],
                    ]}))

    def test_a_missing_https_block_is_refused(self):
        self.reject("HTTPS server blocks claim", policy=tls_policy(omit=True))

    def test_a_certificate_covering_an_extra_name_is_refused(self):
        self.reject("covers",
                    verified=tls_report(san=[aio.PANEL_DOMAIN, aio.REALITY_DOMAIN]))

    def test_a_certificate_that_is_not_yet_valid_is_refused(self):
        self.reject("not valid yet",
                    verified=tls_report(not_before=certificate_day(1)))

    def test_an_expired_certificate_is_refused(self):
        self.reject("has expired",
                    verified=tls_report(not_after=certificate_day(-1)))

    def test_a_certificate_without_renewal_headroom_is_refused(self):
        self.reject("renewal path needs",
                    verified=tls_report(not_after=certificate_day(0.25)))

    def test_a_handshake_that_did_not_negotiate_tls13_is_refused(self):
        self.reject("instead of TLSv1.3", verified=tls_report(version="TLSv1.2"))

    def test_a_wrong_http_status_is_refused(self):
        self.reject("answered", verified=tls_report(status=502))

    def test_a_client_that_cannot_verify_the_chain_is_refused(self):
        self.reject("could not verify", verified=tls_refused(self.CHAIN_ERROR))

    def test_a_vhost_that_refuses_the_documented_version_is_refused(self):
        self.reject("although the generated vhost allows it",
                    tls12=tls_refused("SSLError: [SSL: UNSUPPORTED_PROTOCOL] unsupported protocol"))

    def test_a_tls12_pin_that_negotiated_another_version_is_refused(self):
        self.reject("negotiated", tls12=tls_report(version="TLSv1.3"))

    def test_a_legacy_protocol_that_completed_a_session_is_refused(self):
        self.reject("completed a session pinned to TLS 1.1",
                    legacy=tls_report(version="TLSv1.1", status=200))

    def test_a_chain_that_verifies_without_the_fixture_ca_is_refused(self):
        self.reject("verified without the fixture CA", untrusted=tls_report())

    def test_a_failure_that_is_not_a_chain_error_is_refused(self):
        self.reject("without a certificate-chain error",
                    untrusted=tls_refused("ConnectionRefusedError: [Errno 111] Connection refused"))

    def test_the_case_is_registered_against_the_public_surface_and_catalogued(self):
        cases = {case.id: case for case in aio.cases(ScriptedPodman(self.context, []))}
        self.assertIn(aio.TLS_CASE_ID, cases)
        self.assertEqual(cases[aio.TLS_CASE_ID].timeout_seconds, aio.TLS_TIMEOUT_SECONDS)
        self.assertEqual(cases[aio.TLS_CASE_ID].topology, "aio")
        ids = [case.id for case in aio.cases(ScriptedPodman(self.context, []))]
        self.assertLess(ids.index(aio.TLS_CASE_ID), ids.index("SUB-SERVED"))
        entry = {case["id"]: case for case in catalog.load_catalog()["cases"]}
        record = entry[aio.TLS_CASE_ID]
        self.assertEqual(record["state"], "incubating")
        self.assertEqual(record["runs_in"], ["podman"])
        self.assertEqual(record["topology"], ["aio", "multi-node"])


class TestTlsPolicyParse(unittest.TestCase):
    """The policy probe reads vhosts, not a file the harness thinks it knows."""

    CONF = """\
server {
    listen 80;
    server_name panel.testbed.internal;
    location /.well-known/acme-challenge/ { root /var/www/gowave-acme; }
}
server {
    listen 127.0.0.1:7443 ssl proxy_protocol;
    server_name panel.testbed.internal;
    ssl_certificate /etc/letsencrypt/live/panel.testbed.internal/fullchain.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    location / { return 404; }
}
server {
    listen 127.0.0.1:9443 ssl proxy_protocol;
    server_name reality.testbed.internal testbed.internal www.testbed.internal;
    ssl_protocols TLSv1.3;
}
"""

    def run_probe(self, conf, domain=aio.PANEL_DOMAIN):
        script = aio.TLS_POLICY_SCRIPT.replace(
            "DOMAIN_PLACEHOLDER", f"'{domain}'",
        )
        _, _, body = script.partition("<<'PY'\n")
        self.assertIn("import json", body, "the probe script must carry a heredoc body")
        body = body.rsplit("\nPY\n", 1)[0]
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir) / "conf.d"
            root.mkdir()
            (root / "panel.conf").write_text(conf, encoding="utf-8")
            runner = body.replace(
                'CONFIG_GLOBS = ("/etc/nginx/conf.d/*.conf", "/etc/nginx/sites-enabled/*")',
                f'CONFIG_GLOBS = ("{root}/*.conf",)',
            )
            return subprocess.run(
                [sys.executable, "-c", runner, str(domain)],
                capture_output=True, text=True, check=False,
            )

    def test_the_ssl_vhost_is_read_and_the_port_80_challenge_vhost_ignored(self):
        result = self.run_probe(self.CONF)
        self.assertEqual(result.returncode, 0, result.stderr)
        facts = json.loads(result.stdout)
        self.assertEqual(len(facts["blocks"]), 1)
        block = facts["blocks"][0]
        self.assertEqual(block["listen"], ["127.0.0.1:7443 ssl proxy_protocol"])
        self.assertEqual(block["ssl_protocols"], ["TLSv1.2 TLSv1.3"])
        self.assertEqual(block["ssl_certificate"],
                         ["/etc/letsencrypt/live/panel.testbed.internal/fullchain.pem"])

    def test_a_name_without_an_https_vhost_reports_no_block(self):
        result = self.run_probe(self.CONF, domain="absent.testbed.internal")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["blocks"], [])

    def test_the_cover_names_of_the_decoy_do_not_match_the_panel_contract(self):
        cover = self.run_probe(self.CONF, domain="testbed.internal")
        self.assertEqual(cover.returncode, 0, cover.stderr)
        blocks = json.loads(cover.stdout)["blocks"]
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0]["listen"], ["127.0.0.1:9443 ssl proxy_protocol"])
        # The decoy apex answers for its own names without claiming the Panel's
        # lineage, so the panel contract cannot be satisfied by that block.
        self.assertEqual(blocks[0]["ssl_certificate"], [])
        panel = self.run_probe(self.CONF)
        self.assertEqual(panel.returncode, 0, panel.stderr)
        panel_names = json.loads(panel.stdout)["blocks"][0]["server_names"]
        self.assertNotIn("testbed.internal", panel_names)


if __name__ == "__main__":
    unittest.main()
