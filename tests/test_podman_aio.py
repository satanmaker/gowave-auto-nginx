#!/usr/bin/env python3
"""Suite nonroot: the All-in-One suite installs once with the real operator."""
import hashlib
import io
import json
import os
import signal
import sqlite3
import ssl
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
    budget,
    catalog,
    ingress,
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
        if script == aio.INSTALLED_VERSION_SCRIPT:
            return subprocess.CompletedProcess(
                ["bash", "-lc", script], 0, json.dumps(installed_version_report()), ""
            )
        self.installs.append((name, script))
        return subprocess.CompletedProcess(
            ["bash", "-lc", script], self.install_returncode, self.install_output, ""
        )


def installed_version_report() -> dict:
    """The report the installed-version probe prints, from the matrix's own pins.

    Derived rather than written out: the install compares each component with the
    version the run configured, so a fake that answered with its own numbers would
    stay green while that comparison was broken.
    """
    pins = matrix.product(matrix.load())

    def reported(pin: str) -> str:
        return "1.0.0" if str(pin).strip().lower() in ("", "latest") else str(pin).lstrip("vV")

    panel, node, core = (
        reported(pins.get("panel_version", "")),
        reported(pins.get("node_version", "")),
        reported(pins.get("xray_version", "")),
    )
    return {
        "panel": {
            "binary": "/opt/gowave/gowave-server",
            "argv": "/opt/gowave/gowave-server --version",
            "returncode": 0,
            "stdout": f"GoWave Server v{panel}",
            "stderr": "",
        },
        "node": {
            "binary": "/opt/gowave-node/gowave-node",
            "argv": "/opt/gowave-node/gowave-node version",
            "returncode": 0,
            "stdout": f"gowave-node v{node}",
            "stderr": "",
        },
        "xray_server": {
            "binary": "/opt/gowave-node/rw-core",
            "argv": "/opt/gowave-node/rw-core version",
            "returncode": 0,
            "stdout": f"Xray {core} (Xray, Penetrates Everything.)",
            "stderr": "",
        },
    }


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

    def test_the_budget_case_is_declared_last(self):
        # It reports on the clock the whole run spent, so any case after it would
        # close the report on time it never saw — and a suite that spends its
        # deadline before the case runs loses it to INCOMPLETE, not to silence.
        suite = aio.cases(FakePodman(self.context))
        self.assertEqual(suite[-1].id, budget.BUDGET_CASE_ID)
        self.assertEqual(suite[-1].topology, "aio")


class ScriptedPodman:
    """Podman stub that returns prepared host-script results in order."""

    def __init__(self, context, results, panel_cluster=None):
        self.context = context
        self.results = list(results)
        #: The cluster scope's own document. It is matched on the script rather
        #: than queued, because the case asks the Panel exactly once whether the
        #: contour is enabled or not, and a queue would hand that ask whatever
        #: the contour leg happened to leave behind.
        self.panel_cluster = panel_cluster
        self.scripts = []
        self.execs = []
        # What a `find` for a persisted capture would print: nothing, because the
        # probe reports over the pipe it already holds.
        self.find_output = ""

    def exec_bash(self, name, script, check=True, input_text=None, timeout=300):
        self.scripts.append(script)
        if self.panel_cluster is not None and "--scope cluster" in script:
            return subprocess.CompletedProcess(
                ["bash", "-lc", script], 0, self.panel_cluster, "",
            )
        stdout, returncode = self.results.pop(0)
        return subprocess.CompletedProcess(["bash", "-lc", script], returncode, stdout, "")

    def exec(self, name, argv, check=True, input_text=None, timeout=300):
        self.execs.append((name, list(argv)))
        return subprocess.CompletedProcess(list(argv), 0, self.find_output, "")


class StubHost:
    """The installed host, without containers, for the per-case probes."""

    def __init__(self, target_name="aio-1", panel_domain=aio.PANEL_DOMAIN):
        self.target_name = target_name
        self.panel_domain = panel_domain
        self.reality_domain = aio.REALITY_DOMAIN
        self.vision_domain = None
        self.client_reports = []
        self.client_calls = []
        self.install_attempts = []
        self.install_reports = []

    def install_environment(self):
        return {"GOWAVE_ACME_TEST_CA_FILE": "/fixtures/ca/acme-trust.pem"}

    def install_vision_failure(self, vision_domain):
        """The install the Vision-failure case runs: same command, another name."""
        self.install_attempts.append(vision_domain)
        return self.install_reports.pop(0)

    def client_http(self, url, **kwargs):
        self.client_calls.append({"url": url, **kwargs})
        report = self.client_reports.pop(0)
        return report

    def engine_client(self):
        """The engine role's container, which every client case reuses."""
        return "aio-engines"


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


AUTH_NEGATIVE_VARIANTS = ("expired", "forged", "unsigned", "unknown-admin")


def auth_negative_facts(overrides=None):
    """`auth-negative` probe output for the happy path, with single facts replaceable."""
    facts = {
        "auth_negative": {
            "claims_present": True,
            "role": "ADMIN",
            "signing_key_present": True,
            "control_before": 200,
            "control_after": 200,
            "refusals": {
                name: {"status": 401, "error": "Unauthorized"}
                for name in AUTH_NEGATIVE_VARIANTS
            },
        }
    }
    for path, value in (overrides or {}).items():
        target = facts
        *parents, leaf = path.split(".")
        for name in parents:
            target = target[name]
        target[leaf] = value
    return json.dumps(facts)


def api_client_facts(overrides=None):
    """`api-client` probe output for the happy path, with single facts replaceable."""
    facts = {
        "api_client": {
            "verify_mode": "CERT_REQUIRED",
            "hostname_verification": True,
            "timeout_configured": aio.PANEL_API_CLIENT_TIMEOUT_SECONDS,
            "timeout_used": aio.PANEL_API_CLIENT_TIMEOUT_SECONDS,
            "bundle_login": "accepted",
            "nodes": 2,
            # The two refusals the case decides are reported as class names, so
            # the fixture uses two different ones: a case that compared the pair
            # to a single expected class would pass here only by accident.
            "empty_store_login": "GoWaveAPIError",
            "hostname_mismatch_login": "SSLCertVerificationError",
            "system_store_login": "GoWaveAPIError",
            "production_default_timeout": aio.PANEL_API_CLIENT_TIMEOUT_SECONDS,
            "production_default_context": True,
            "bypass_tokens": [],
        }
    }
    for path, value in (overrides or {}).items():
        target = facts
        *parents, leaf = path.split(".")
        for name in parents:
            target = target[name]
        target[leaf] = value
    return json.dumps(facts)


TLS_CA_DIGEST = "a" * 64
TLS_CA_CHAIN_ERROR = (
    "Error: The port 443 listener did not prove TLS for panel.testbed.internal.\n"
    "  Last attempt answered with: verification failed: unable to get local issuer certificate\n"
)
TLS_CA_REFUSAL_OUTPUT = f"Fatal: {aio.TLS_CA_REFUSAL}.\n"
TLS_CA_OTHER_FAILURE = (
    "Error: The port 443 listener did not prove TLS for panel.testbed.internal.\n"
    "  Last attempt answered with: no certificate was served\n"
)


def tls_ca_scripts(
    *, functions="1", stray="0", anchor=0, untrusted=1, untrusted_output=TLS_CA_CHAIN_ERROR,
    absent=1, absent_output=TLS_CA_REFUSAL_OUTPUT, symlink=1,
    symlink_output=TLS_CA_REFUSAL_OUTPUT, default=1, default_output=TLS_CA_CHAIN_ERROR,
    leftovers="0", removed="removed",
):
    """The eleven host scripts the case runs, in the order it runs them."""
    return [
        (f"{TLS_CA_DIGEST}\n{functions}\n{stray}\n", 0),
        ("9b2f foreign-root.pem\n", 0),
        ("", anchor),
        (untrusted_output, untrusted),
        (absent_output, absent),
        ("", 0),
        (symlink_output, symlink),
        (default_output, default),
        (f"{leftovers}\n", 0),
        ("", 0),
        (f"{removed}\n", 0),
    ]


class TestTlsCaBundleCase(unittest.TestCase):
    """AIO-02: the installer's probe trusts the per-run bundle and nothing else."""

    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def run_case(self, **overrides):
        product, podman = installed_product(self.context, tls_ca_scripts(**overrides))
        return aio.case_tls_ca_bundle(product), podman

    def test_the_probe_under_test_is_sliced_out_of_the_installers_own_script(self):
        _, podman = self.run_case()
        self.assertIn("sed -n '/^verify_public_tls_sni() {$/,/^acquire_lock() {$/p' /repo/gowave-auto.sh",
                      podman.scripts[0])
        self.assertIn("source /repo/modules/tempdir.sh", podman.scripts[0])
        legs = [script for script in podman.scripts if "verify_public_tls_sni " in script]
        self.assertEqual(len(legs), 5, f"five legs run the probe, got {len(legs)}")
        for script in legs:
            self.assertIn("127.0.0.1:443", script)
        bundled = [script for script in legs if script.startswith("GOWAVE_TLS_CA_FILE=")]
        self.assertEqual(len(bundled), 4, f"four legs supply a bundle, got {len(bundled)}")
        fallback = [script for script in legs if script.startswith("env -u GOWAVE_TLS_CA_FILE ")]
        self.assertEqual(len(fallback), 1, "exactly one leg runs with the bundle removed")

    def test_the_fallback_leg_removes_a_bundle_the_container_itself_carries(self):
        # The target is created with the install environment, so the variable is
        # part of the container's configuration and podman exec inherits it. A
        # fallback leg that merely left it out would re-run the anchored leg.
        _, podman = self.run_case()
        fallback = [script for script in podman.scripts
                    if "verify_public_tls_sni " in script
                    and script.startswith("env -u GOWAVE_TLS_CA_FILE ")]
        self.assertEqual(len(fallback), 1)
        self.assertNotIn("GOWAVE_TLS_CA_FILE=", fallback[0])

    def test_the_per_run_bundle_leg_records_what_each_bundle_decided(self):
        evidence, _ = self.run_case()
        self.assertEqual(evidence["install_ca_file"],
                         f"{topology.CA_MOUNT}/{topology.ISSUED_ROOT_NAME}")
        self.assertEqual(evidence["run_ca_status"], 0)
        self.assertEqual(evidence["foreign_ca_status"], 1)
        self.assertTrue(evidence["foreign_ca_is_a_chain_error"])
        self.assertEqual(evidence["absent_ca_status"], 1)
        self.assertEqual(evidence["symlink_ca_status"], 1)
        self.assertEqual(evidence["default_trust_status"], 1)
        self.assertFalse(evidence["default_trust_anchors_lineage"])
        self.assertEqual(evidence["scratch_leftovers"], "0")
        self.assertTrue(evidence["probe_removed"])
        self.assertEqual(evidence["installer_sha256"], TLS_CA_DIGEST)

    def test_a_foreign_root_that_is_accepted_fails_the_case(self):
        with self.assertRaises(AssertionError) as caught:
            self.run_case(untrusted=0, untrusted_output="")
        self.assertIn("accepted a certificate no foreign root issued", str(caught.exception))

    def test_a_failure_that_is_not_a_chain_error_fails_the_case(self):
        with self.assertRaises(AssertionError) as caught:
            self.run_case(untrusted_output=TLS_CA_OTHER_FAILURE)
        self.assertIn("reason other than the chain", str(caught.exception))

    def test_an_absent_bundle_that_is_read_fails_the_case(self):
        with self.assertRaises(AssertionError) as caught:
            self.run_case(absent=0, absent_output="")
        self.assertIn("does not exist was accepted", str(caught.exception))

    def test_a_symlinked_bundle_must_be_refused_as_one(self):
        with self.assertRaises(AssertionError) as caught:
            self.run_case(symlink_output=TLS_CA_OTHER_FAILURE)
        self.assertIn("not refused as such", str(caught.exception))

    def test_a_lineage_the_default_trust_path_anchors_fails_the_case(self):
        with self.assertRaises(AssertionError) as caught:
            self.run_case(default=0, default_output="")
        self.assertIn("without the per-run bundle", str(caught.exception))

    def test_a_default_path_failure_that_is_not_a_chain_error_fails_the_case(self):
        with self.assertRaises(AssertionError) as caught:
            self.run_case(default_output=TLS_CA_OTHER_FAILURE)
        self.assertIn("default trust path failed for a reason other than the chain",
                      str(caught.exception))

    def test_scratch_directories_left_behind_fail_the_case(self):
        with self.assertRaises(AssertionError) as caught:
            self.run_case(leftovers="2")
        self.assertIn("2 scratch directories", str(caught.exception))

    def test_a_slice_without_exactly_one_definition_fails_the_case(self):
        with self.assertRaises(AssertionError) as caught:
            self.run_case(functions="2")
        self.assertIn("not one", str(caught.exception))
        with self.assertRaises(AssertionError) as stray:
            self.run_case(stray="1")
        self.assertIn("ran past its end", str(stray.exception))

    def test_the_sliced_probe_is_removed_even_when_a_leg_fails(self):
        product, podman = installed_product(self.context, tls_ca_scripts(leftovers="2"))
        with self.assertRaises(AssertionError):
            aio.case_tls_ca_bundle(product)
        self.assertEqual(podman.scripts[-1], f"rm -rf {aio.TLS_CA_PROBE_DIR}",
                         "the finally leg runs after the failed check, not before it")


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

    def pin_output(self, **overrides):
        facts = {
            "floating_commit": "refused",
            "missing_digest": "refused",
            "short_digest": "refused",
            "pinned_pair": "accepted",
            "url_names_commit": "yes",
            "matching_bytes": "accepted",
            "mismatched_bytes": "refused",
            "scratch_carries_bundle": "no",
            "node_binary_present": "yes",
            "install_refused": "yes",
            "refusal_names_pin": "yes",
            "installer_untouched": "yes",
        }
        facts.update(overrides)
        body = " ".join(f"{key}={value}" for key, value in facts.items())
        return f"{body} refusal_text=Error:-GOWAVE_NODE_INSTALLER_COMMIT-must-be-a-40-character-hex-commit-SHA.\n"

    def test_pin_case_requires_every_refusal_and_the_accepted_pin(self):
        product, _ = installed_product(self.context, [(self.pin_output(), 0)])
        evidence = aio.case_installer_pin(product)
        self.assertEqual(evidence["pinned_pair"], "accepted")
        self.assertEqual(evidence["install_refused"], "yes")
        self.assertEqual(evidence["installer_untouched"], "yes")

    def test_pin_case_fails_when_a_floating_branch_is_accepted(self):
        product, _ = installed_product(self.context, [
            (self.pin_output(floating_commit="accepted"), 0),
        ])
        with self.assertRaises(AssertionError) as caught:
            aio.case_installer_pin(product)
        self.assertIn("floating installer branch", str(caught.exception))

    def test_pin_case_fails_when_the_digest_is_not_mandatory(self):
        product, _ = installed_product(self.context, [
            (self.pin_output(missing_digest="accepted"), 0),
        ])
        with self.assertRaises(AssertionError) as caught:
            aio.case_installer_pin(product)
        self.assertIn("without the mandatory installer digest", str(caught.exception))

    def test_pin_case_fails_when_the_url_does_not_name_the_commit(self):
        product, _ = installed_product(self.context, [
            (self.pin_output(url_names_commit="no"), 0),
        ])
        with self.assertRaises(AssertionError) as caught:
            aio.case_installer_pin(product)
        self.assertIn("does not name the pinned commit", str(caught.exception))

    def test_pin_case_fails_when_the_refusal_came_from_somewhere_else(self):
        product, _ = installed_product(self.context, [
            (self.pin_output(refusal_names_pin="no"), 0),
        ])
        with self.assertRaises(AssertionError) as caught:
            aio.case_installer_pin(product)
        self.assertIn("not by the installer pin", str(caught.exception))

    def test_pin_case_fails_when_an_installer_ran_anyway(self):
        product, _ = installed_product(self.context, [
            (self.pin_output(installer_untouched="no"), 0),
        ])
        with self.assertRaises(AssertionError) as caught:
            aio.case_installer_pin(product)
        self.assertIn("despite the refused pin", str(caught.exception))

    def test_pin_case_refuses_a_probe_that_ran_the_bundled_installer(self):
        product, _ = installed_product(self.context, [
            (self.pin_output(scratch_carries_bundle="yes"), 0),
        ])
        with self.assertRaises(AssertionError) as caught:
            aio.case_installer_pin(product)
        self.assertIn("bundled installer", str(caught.exception))

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
        for script in (aio.FOREIGN_LISTENER_SCRIPT, aio.ACME_FAIL_CLOSED_SCRIPT,
                       aio.INSTALLER_PIN_SCRIPT,
                       aio.vision_failure_inventory(StubHost(), aio.VISION_FAILURE_DOMAIN)):
            result = subprocess.run(["bash", "-n"], input=script, text=True,
                                    capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)


class TestVisionFailureCase(unittest.TestCase):
    """VIS-05: the failed Vision stage reports a rollback and leaves no side effect.

    The case compares two inventories of the same host around one install attempt,
    so each guard is proven by damaging exactly the field it reads: a lineage that
    changed, a hook that moved, a name that appeared in the tree, an attempt that
    reported success, and a report that called itself incomplete.
    """

    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def inventory(self, **overrides) -> str:
        facts = {
            "lineage_panel": "a" * 64,
            "lineage_reality": "b" * 64,
            "lineage_vision": "absent",
            "failed_lineage": "absent",
            "deploy_hook": "c" * 64,
            "ownership_record": "d" * 64,
            "stream_config": "e" * 64,
            "http_vhost": "f" * 64,
            "vision_fallback": "absent",
            "bootstrap_vhost": "absent",
            "failed_domain_mentions": "0",
            "nginx_active": "active",
            "nginx_test": "0",
        }
        facts.update(overrides)
        return "".join(f"{key}={value}\n" for key, value in facts.items())

    def surface(self, **overrides) -> str:
        counts = {"nodes": 1, "profiles": 1, "squads": 1, "hosts": 4}
        counts.update(overrides)
        return json.dumps({
            "login": {"status": 200},
            "surface": {area: {"count": count} for area, count in counts.items()},
        })

    def attempt(self, stdout=None, returncode=1) -> topology.InstallOutcome:
        if stdout is None:
            stdout = (
                f"Acquiring Let's Encrypt TLS certificate for VLESS Vision "
                f"({aio.VISION_FAILURE_DOMAIN})...\n"
                "ACME certificate lineage rollback completed successfully.\n"
            )
        return topology.InstallOutcome(returncode, stdout, "", 5.0, "install")

    def run_case(self, *, before=None, after=None, attempt=None,
                 surface_before=None, surface_after=None, client=None):
        product, _ = installed_product(self.context, [
            (self.inventory() if before is None else before, 0),
            (self.surface() if surface_before is None else surface_before, 0),
            (self.inventory() if after is None else after, 0),
            (self.surface() if surface_after is None else surface_after, 0),
            ("login=200 api=200\n", 0),
        ])
        product.host.install_reports = [self.attempt() if attempt is None else attempt]
        product.host.client_reports = [client or {
            "url": f"{aio.PUBLIC_PANEL}/", "returncode": 0, "stdout": "{}", "stderr": "",
            "probe": {"status": 200},
        }]
        return aio.case_vision_certificate_failure(product), product

    def damage(self, fragment: str, **kwargs) -> None:
        with self.assertRaises(AssertionError) as caught:
            self.run_case(**kwargs)
        self.assertIn(fragment, str(caught.exception))

    def test_the_stage_fails_and_the_host_is_left_as_it_was_found(self):
        evidence, product = self.run_case()
        self.assertEqual(evidence["attempt_returncode"], 1)
        self.assertEqual(evidence["vision_stage"], "reached")
        self.assertEqual(evidence["rollback"], "complete")
        self.assertEqual(evidence["failed_lineage"], "absent")
        self.assertTrue(evidence["lineage_panel"])
        self.assertTrue(evidence["lineage_reality"])
        self.assertTrue(evidence["deploy_hook"])
        self.assertEqual(evidence["failed_domain_mentions"], "0")
        self.assertEqual(evidence["bootstrap_vhost"], "absent")
        self.assertEqual(evidence["public_panel"], 200)
        self.assertEqual(product.host.install_attempts, [aio.VISION_FAILURE_DOMAIN])

    def test_the_case_fails_when_the_attempt_exits_zero(self):
        self.damage("exited 0", attempt=self.attempt(returncode=0))

    def test_the_case_fails_when_the_failure_came_from_another_stage(self):
        self.damage("never reached the Vision certificate stage", attempt=self.attempt(
            stdout="Error: Failed to activate bootstrap ACME NGINX configuration; "
                   "rolling back certificate lineages.\n"
                   "ACME certificate lineage rollback completed successfully.\n",
        ))

    def test_the_case_fails_when_the_rollback_is_not_reported_complete(self):
        self.damage("did not report a complete lineage rollback", attempt=self.attempt(
            stdout=f"Acquiring Let's Encrypt TLS certificate for VLESS Vision "
                   f"({aio.VISION_FAILURE_DOMAIN})...\n",
        ))

    def test_the_case_fails_when_the_report_calls_itself_incomplete(self):
        self.damage("reported an incomplete rollback", attempt=self.attempt(
            stdout=f"Acquiring Let's Encrypt TLS certificate for VLESS Vision "
                   f"({aio.VISION_FAILURE_DOMAIN})...\n"
                   "ACME certificate lineage rollback completed successfully.\n"
                   "CRITICAL: ACME rollback incomplete; certificate lineage or deploy-hook "
                   "restoration failed. Recovery snapshot retained for operator intervention.\n",
        ))

    def test_the_case_fails_when_the_host_had_no_lineage_to_preserve(self):
        self.damage("carries no Panel lineage",
                    before=self.inventory(lineage_panel="absent"))

    def test_the_case_fails_when_the_failed_name_already_has_a_lineage(self):
        self.damage("already has a lineage", before=self.inventory(failed_lineage="present"))

    def test_the_case_fails_when_the_host_had_no_deploy_hook(self):
        self.damage("owes nothing to restore", before=self.inventory(deploy_hook="absent"))

    def test_the_case_fails_when_nginx_was_not_active_before_the_attempt(self):
        self.damage("NGINX reports 'inactive' before the failed attempt",
                    before=self.inventory(nginx_active="inactive"))

    def test_the_case_fails_when_a_pre_existing_lineage_changed(self):
        self.damage("changed the pre-existing panel certificate lineage",
                    after=self.inventory(lineage_panel="1" * 64))

    def test_the_case_fails_when_the_reality_lineage_was_deleted(self):
        self.damage("changed the pre-existing reality certificate lineage",
                    after=self.inventory(lineage_reality="absent"))

    def test_the_case_fails_when_the_configured_vision_lineage_changed(self):
        self.damage("changed the pre-existing vision certificate lineage",
                    before=self.inventory(lineage_vision="2" * 64),
                    after=self.inventory(lineage_vision="3" * 64))

    def test_the_case_fails_when_the_failed_name_got_a_lineage(self):
        self.damage("left a certificate lineage for",
                    after=self.inventory(failed_lineage="present"))

    def test_the_case_fails_when_the_deploy_hook_changed(self):
        self.damage("changed or removed the managed deploy hook",
                    after=self.inventory(deploy_hook="4" * 64))

    def test_the_case_fails_when_the_ownership_record_was_rewritten(self):
        self.damage("rewrote the deploy-hook ownership record",
                    after=self.inventory(ownership_record="5" * 64))

    def test_the_case_fails_when_the_stream_map_was_rewritten(self):
        self.damage("rewrote the stream SNI map",
                    after=self.inventory(stream_config="6" * 64))

    def test_the_case_fails_when_the_http_vhost_was_rewritten(self):
        self.damage("rewrote the HTTP vhost", after=self.inventory(http_vhost="7" * 64))

    def test_the_case_fails_when_the_failed_name_appears_in_the_nginx_tree(self):
        self.damage("reference(s) to", after=self.inventory(failed_domain_mentions="2"))

    def test_the_case_fails_when_a_fallback_vhost_appeared(self):
        self.damage("created or removed the 9444 fallback vhost",
                    after=self.inventory(vision_fallback="present"))

    def test_the_case_fails_when_a_bootstrap_vhost_was_left_behind(self):
        self.damage("left a bootstrap ACME vhost behind",
                    after=self.inventory(bootstrap_vhost="present"))

    def test_the_case_fails_when_nginx_is_left_inactive(self):
        self.damage("NGINX reports 'inactive' after the failed attempt",
                    after=self.inventory(nginx_active="inactive"))

    def test_the_case_fails_when_the_configuration_no_longer_loads(self):
        self.damage("does not pass `nginx -t` after the failed attempt",
                    after=self.inventory(nginx_test="1"))

    def test_the_case_fails_when_the_panel_inventory_changed(self):
        self.damage("changed the Panel's hosts inventory",
                    surface_after=self.surface(hosts=5))

    def test_the_case_fails_when_the_public_surface_stopped_answering(self):
        self.damage("public surface stopped answering", client={
            "url": f"{aio.PUBLIC_PANEL}/", "returncode": 7, "stdout": "",
            "stderr": "connection refused", "probe": {"error": "connection refused"},
        })

    def test_the_case_fails_when_the_panel_api_stopped_answering(self):
        product_queue = [
            (self.inventory(), 0),
            (self.surface(), 0),
            (self.inventory(), 0),
            (self.surface(), 0),
            ("login=503 api=503\n", 0),
        ]
        product, _ = installed_product(self.context, product_queue)
        product.host.install_reports = [self.attempt()]
        product.host.client_reports = [{
            "url": f"{aio.PUBLIC_PANEL}/", "returncode": 0, "stdout": "{}", "stderr": "",
            "probe": {"status": 200},
        }]
        with self.assertRaises(AssertionError) as caught:
            aio.case_vision_certificate_failure(product)
        self.assertIn("Panel's own API stopped answering", str(caught.exception))


class TestInstalledVersionCases(unittest.TestCase):
    """VER-01/VER-03: each installed component is compared with the pin it was given.

    The install case reads three binaries inside the target and records all three
    against the versions this deployment configured. What a mistake in it costs is
    the whole version group's evidence — a comparison against the wrong pin, or
    one binary answering for two components — so each refusal is asserted here
    against a report that differs in exactly one place.
    """

    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def pins(self):
        return matrix.product(matrix.load())

    def report(self, **components):
        """The probe's own shape: one object per component, keyed by its binary."""
        defaults = {
            "panel": ("/opt/gowave/gowave-server", "GoWave Server v1.2.3\n"),
            "node": ("/opt/gowave-node/gowave-node", "gowave-node v1.2.3\n"),
            "xray_server": (
                "/opt/gowave-node/rw-core",
                f"Xray {self.pins()['xray_version']} (Xray, Penetrates Everything.)\n",
            ),
        }
        defaults.update(components)
        return {
            component: {
                "binary": binary, "argv": "version", "returncode": 0,
                "stdout": output, "stderr": "",
            }
            for component, (binary, output) in defaults.items()
        }

    def product_with(self, report):
        product, _ = installed_product(self.context, [(json.dumps(report), 0)])
        return product

    def test_the_three_components_are_recorded_against_their_pins(self):
        product = self.product_with(self.report())
        evidence = product.require_configured_versions()
        self.assertEqual(evidence["panel_version"], "1.2.3")
        self.assertEqual(evidence["node_version"], "1.2.3")
        self.assertEqual(evidence["xray_server_version"], self.pins()["xray_version"])
        self.assertEqual(evidence["xray_server_version_binary"], "/opt/gowave-node/rw-core")
        self.assertEqual(product.server_core_version, self.pins()["xray_version"])

    def test_a_core_that_differs_from_the_pin_fails_the_install(self):
        drifted = f"Xray {self.pins()['xray_version']}0 (Xray, Penetrates Everything.)\n"
        product = self.product_with(
            self.report(xray_server=("/opt/gowave-node/rw-core", drifted)),
        )
        with self.assertRaises(AssertionError) as caught:
            product.require_configured_versions()
        self.assertIn("this deployment configured", str(caught.exception))

    def test_two_components_read_through_one_binary_fail_the_install(self):
        product = self.product_with(
            self.report(node=("/opt/gowave/gowave-server", "gowave-node v1.2.3\n")),
        )
        with self.assertRaises(AssertionError) as caught:
            product.require_configured_versions()
        self.assertIn("two components were interrogated through one binary", str(caught.exception))

    def test_a_component_with_no_binary_fails_the_install(self):
        product = self.product_with(
            self.report(node=("", "gowave-node v1.2.3\n")),
        )
        with self.assertRaises(AssertionError) as caught:
            product.require_configured_versions()
        self.assertIn("installed at no documented path", str(caught.exception))

    def test_a_component_that_prints_no_version_fails_the_install(self):
        product = self.product_with(
            self.report(panel=("/opt/gowave/gowave-server", "version output unavailable\n")),
        )
        with self.assertRaises(AssertionError) as caught:
            product.require_configured_versions()
        self.assertIn("printed no version", str(caught.exception))

    def test_an_engine_that_reports_another_build_fails_the_tuple(self):
        product = self.product_with(self.report())
        product.podman.exec = lambda name, argv, check=True, input_text=None, timeout=0: (
            subprocess.CompletedProcess(list(argv), 0, f"{argv[0]} 0.0.1 (fixture)\n", "")
        )
        with self.assertRaises(AssertionError) as caught:
            product.engine_version("AIO-DP-REALITY-xray", "xray")
        self.assertIn("instead of the pinned", str(caught.exception))


class TestChannelCases(unittest.TestCase):
    """AIO-CHANNEL-NOOP / -DEV / -ROLLBACK / -INTERRUPT: what each case accepts as proof.

    The channel cases read the product's snapshot, journal and unit rather than
    the command's exit status alone, so what each one refuses matters as much as
    what it accepts. The probe itself is executed here against a real tree: a
    probe that only compiled would pass while its argv line was broken.
    """

    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def state(self, **overrides):
        state = {
            "environment": {"GOWAVE_CHANNEL": "stable"},
            "env_digest": "e" * 64,
            "binary": "b" * 64,
            "database": {"bytes": "d" * 64, "integrity": "ok", "logical": "l" * 64},
            "frontend": "f" * 64,
            "frontend_index": "i" * 64,
            "state": "s" * 64,
            "nginx": "n" * 64,
            "nginx_conf": "c" * 64,
            "letsencrypt": "a" * 64,
            "lineage_chain": "k" * 64,
            "journal": {
                "state": "COMMITTED",
                "snapshot_dir": f"{aio.CHANNEL_RECOVERY_ROOT}/update-1",
            },
            "snapshots": ["update-1"],
            "unit": {"ActiveState": "active", "MainPID": "42", "ActiveEnterTimestamp": "t"},
            "health": "200",
        }
        state.update(overrides)
        return state

    def test_the_noop_case_accepts_a_host_the_call_did_not_touch(self):
        product, _ = installed_product(self.context, [
            (json.dumps(self.state()), 0),
            ("GoWave is already on channel 'stable'.\n", 0),
            (json.dumps(self.state()), 0),
        ])
        evidence = aio.case_channel_noop(product)
        self.assertEqual(evidence["channel"], "stable")
        self.assertEqual(evidence["snapshots_after"], evidence["snapshots_before"])
        self.assertIn("already on channel", evidence["message"])

    def test_a_same_channel_call_that_restarted_the_panel_fails_the_noop_case(self):
        restarted = self.state()
        restarted["unit"] = dict(restarted["unit"], MainPID="43")
        product, _ = installed_product(self.context, [
            (json.dumps(self.state()), 0),
            ("GoWave is already on channel 'stable'.\n", 0),
            (json.dumps(restarted), 0),
        ])
        with self.assertRaises(AssertionError) as caught:
            aio.case_channel_noop(product)
        self.assertIn("MainPID", str(caught.exception))

    def test_a_same_channel_call_that_took_a_snapshot_fails_the_noop_case(self):
        snapshotted = self.state(snapshots=["update-1", "update-2"])
        product, _ = installed_product(self.context, [
            (json.dumps(self.state()), 0),
            ("GoWave is already on channel 'stable'.\n", 0),
            (json.dumps(snapshotted), 0),
        ])
        with self.assertRaises(AssertionError) as caught:
            aio.case_channel_noop(product)
        self.assertIn("snapshot", str(caught.exception))

    def test_the_dev_case_will_not_measure_a_host_that_is_not_on_stable(self):
        off_channel = self.state(environment={"GOWAVE_CHANNEL": "dev"})
        product, _ = installed_product(self.context, [(json.dumps(off_channel), 0)])
        with self.assertRaises(AssertionError) as caught:
            aio.case_channel_dev(product)
        self.assertIn("nothing to switch", str(caught.exception))

    def tree(self, directory):
        directory.mkdir(parents=True, exist_ok=True)
        database = sqlite3.connect(directory / "gowave.db")
        try:
            database.execute("create table users (id integer primary key, name text)")
            database.execute("insert into users (name) values ('alice')")
            database.commit()
        finally:
            database.close()
        (directory / ".env").write_text("GOWAVE_CHANNEL=stable\nAPP_SECRET=kept\n", encoding="utf-8")
        (directory / "gowave-server").write_bytes(b"#!/bin/sh\nexit 0\n")
        (directory / "frontend").mkdir(exist_ok=True)
        (directory / "frontend" / "index.html").write_text("<html>panel</html>\n", encoding="utf-8")
        (directory / "state.json").write_text('{"domain": "panel.test"}\n', encoding="utf-8")
        (directory / "etc" / "nginx" / "conf.d").mkdir(parents=True, exist_ok=True)
        (directory / "etc" / "nginx" / "nginx.conf").write_text("events {}\n", encoding="utf-8")
        lineage = directory / "etc" / "letsencrypt" / "live" / "panel.test"
        lineage.mkdir(parents=True, exist_ok=True)
        (lineage / "fullchain.pem").write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
        (lineage / "privkey.pem").write_text("-----BEGIN PRIVATE KEY-----\n", encoding="utf-8")
        return directory

    def probe(self, paths):
        result = subprocess.run(
            ["python3", "-", json.dumps(paths)], input=aio.CHANNEL_STATE_PROBE,
            text=True, capture_output=True, timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_the_state_probe_digests_a_snapshot_tree_and_its_database(self):
        snapshot = self.tree(Path(self.tmp.name) / "recovery" / "update-1")
        facts = self.probe(aio.channel_state_paths(str(snapshot)))
        self.assertEqual(facts["environment"]["GOWAVE_CHANNEL"], "stable")
        self.assertEqual(facts["database"]["integrity"], "ok")
        self.assertTrue(facts["database"]["logical"])
        self.assertEqual(facts["binary"], hashlib.sha256((snapshot / "gowave-server").read_bytes()).hexdigest())
        self.assertEqual(facts["frontend_index"], hashlib.sha256(b"<html>panel</html>\n").hexdigest())
        self.assertTrue(facts["nginx"] and facts["nginx_conf"] and facts["letsencrypt"])
        self.assertTrue(facts["lineage_chain"])
        # A snapshot names no journal and owns no recovery root, so the probe
        # must not mistake the live host's journal for part of the snapshot.
        self.assertEqual(facts["journal"], {})
        self.assertEqual(facts["snapshots"], [])

    def test_the_state_probe_counts_the_rows_of_every_table(self):
        snapshot = self.tree(Path(self.tmp.name) / "recovery" / "update-1")
        database = sqlite3.connect(snapshot / "gowave.db")
        try:
            database.execute("insert into users (name) values ('bob')")
            database.commit()
        finally:
            database.close()
        facts = self.probe(aio.channel_state_paths(str(snapshot)))
        self.assertEqual(facts["database"]["tables"], ["users"])
        self.assertEqual(facts["database"]["rows"], {"users": 2})

    def test_the_state_probe_reports_a_file_that_is_not_a_database(self):
        snapshot = self.tree(Path(self.tmp.name) / "recovery" / "update-1")
        (snapshot / "gowave.db").write_bytes(b"this is not a sqlite database\n")
        facts = self.probe(aio.channel_state_paths(str(snapshot)))
        self.assertTrue(facts["database"]["integrity"].startswith("error:"))
        self.assertNotIn("logical", facts["database"])

    def test_the_injected_switch_and_its_cleanup_are_valid_bash(self):
        for script in (aio.channel_rollback_script(), aio.channel_rollback_cleanup_script()):
            result = subprocess.run(["bash", "-n"], input=script, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        body = aio.channel_rollback_script()
        self.assertIn(aio.CHANNEL_RECOVERY_ROOT, body)
        # The repo path is baked in: the payload arrives on stdin alone, so a
        # positional argument would be empty and `set -u` would abort mid-switch.
        self.assertIn(f"repo={aio.topology.REPO_IN_CONTAINER}", body)
        self.assertIn('bash "$repo/gowave-auto.sh" channel dev', body)

    def surface(self, **overrides):
        facts = {
            "readback_status": 200,
            "short_uuid_length": 16,
            "inventory_status": 200,
            "users": 1,
            "users_captured": 1,
            "inventory_identical": True,
            "user_present": True,
            "representations": {
                name: {"status": 200, "bytes": 128} for name in aio.REPRESENTATIONS
            },
            "representations_identical": {name: True for name in aio.REPRESENTATIONS},
        }
        facts.update(overrides)
        return facts

    def switched_product(self, results):
        """A product whose data plane is the stub, so only host scripts are scripted."""
        podman = ScriptedPodman(self.context, results)
        product = aio.AioProduct(podman)
        product.host = TrafficHost(None, podman)
        product.outcome = topology.InstallOutcome(0, "", "", 1.0, "install")
        # The subscription payloads were captured by an earlier case in the suite.
        product._subscriptions = {}
        return product, podman

    def dev_results(self, after=None, surface=None):
        after = after or self.state(
            environment={"GOWAVE_CHANNEL": "dev"},
            snapshots=["update-1", "update-2"],
            journal={
                "state": "COMMITTED",
                "snapshot_dir": f"{aio.CHANNEL_RECOVERY_ROOT}/update-2",
                "target_version": "dev",
            },
        )
        surface = surface or self.surface()
        return after, [
            (json.dumps(self.state()), 0),
            (json.dumps({"channel": self.surface()}), 0),
            ("Snapshot captured.\nSwitched to channel 'dev' successfully.\n", 0),
            (json.dumps(after), 0),
            (json.dumps(self.state(journal={}, snapshots=[])), 0),
            (json.dumps({"channel": surface}), 0),
            ("200", 0),
            (
                "WARNING: Switching from Dev to Stable may involve irreversible "
                "database migrations.\nUse --force to confirm channel switch.\n",
                1,
            ),
            (json.dumps(after), 0),
        ]

    def test_the_dev_case_proves_a_committed_switch_on_the_same_client_surface(self):
        after, results = self.dev_results()
        product, podman = self.switched_product(results)
        with mock.patch.object(aio, "wait_until", lambda predicate, *a, **k: predicate()):
            evidence = aio.case_channel_dev(product)
        self.assertEqual(evidence["channel_after"], "dev")
        self.assertEqual(evidence["journal_state"], "COMMITTED")
        self.assertEqual(evidence["snapshot_target_version"], "dev")
        self.assertEqual(evidence["snapshot"], "update-2")
        self.assertEqual(evidence["clients_served"], 1)
        self.assertEqual(evidence["transfer_count"], 8)
        self.assertEqual(evidence["downgrade_refused"], 1)
        # The command is the product's own, run on the host and nowhere else.
        self.assertIn("gowave-auto.sh channel dev", podman.scripts[2])
        self.assertIn("gowave-auto.sh channel stable", podman.scripts[7])

    def test_a_switch_that_left_the_journal_uncommitted_fails_the_dev_case(self):
        after, results = self.dev_results(after=self.state(
            environment={"GOWAVE_CHANNEL": "dev"}, snapshots=["update-1", "update-2"],
        ))
        product, _ = self.switched_product(results)
        with mock.patch.object(aio, "wait_until", lambda predicate, *a, **k: predicate()):
            with self.assertRaises(AssertionError) as caught:
                aio.case_channel_dev(product)
        self.assertIn("instead of a COMMITTED dev transition", str(caught.exception))

    def test_a_switch_that_lost_the_client_fails_the_dev_case(self):
        _after, results = self.dev_results(surface=self.surface(
            inventory_identical=False, user_present=False, users=0,
        ))
        product, _ = self.switched_product(results)
        with mock.patch.object(aio, "wait_until", lambda predicate, *a, **k: predicate()):
            with self.assertRaises(AssertionError) as caught:
                aio.case_channel_dev(product)
        self.assertIn("changed the client inventory", str(caught.exception))

    def test_a_snapshot_that_kept_the_new_channel_fails_the_switch_case(self):
        product, _ = installed_product(self.context, [])
        before = self.state()
        snapshot = self.state(environment={"GOWAVE_CHANNEL": "dev"})
        with self.assertRaises(AssertionError) as caught:
            aio.require_channel_snapshot("AIO-CHANNEL-DEV", before, snapshot, "/recovery/update-2")
        self.assertIn("instead of the stable channel", str(caught.exception))

    def test_the_rollback_case_proves_every_area_came_back_from_the_snapshot(self):
        before = self.state()
        sabotage = {
            "snapshot": f"{aio.CHANNEL_RECOVERY_ROOT}/update-3",
            "targets": {
                "binary": "1" * 64, "database": "2" * 64, "frontend_index": "3" * 64,
                "environment": "4" * 64, "state": "5" * 64, "nginx_conf": "6" * 64,
                "lineage_chain": "7" * 64,
            },
        }
        switch = {
            "returncode": 1,
            "stdout": "",
            "stderr": "Channel switch failed: gowave.service did not become active\n"
                      "File rollback completed and services verified.\n"
                      "Channel switch rolled back to the pre-switch state.\n",
            "sabotage": sabotage,
            "journal": {
                "state": "ROLLED_BACK",
                "snapshot_dir": f"{aio.CHANNEL_RECOVERY_ROOT}/update-3",
                "target_version": "dev",
            },
            "unit": {"ActiveState": "active"},
            "health": 200,
        }
        product, podman = self.switched_product([
            (json.dumps(before), 0),
            (json.dumps({"channel": self.surface()}), 0),
            (json.dumps(switch), 0),
            (json.dumps(before), 0),
            (json.dumps(self.state(journal={}, snapshots=[])), 0),
            (json.dumps({"channel": self.surface()}), 0),
            ("200", 0),
            ("active\n", 0),
            (json.dumps(before), 0),
        ])
        with mock.patch.object(aio, "wait_until", lambda predicate, *a, **k: predicate()):
            evidence = aio.case_channel_rollback(product)
        self.assertEqual(evidence["journal_state"], "ROLLED_BACK")
        self.assertEqual(evidence["channel_after"], "stable")
        self.assertEqual(evidence["sabotaged_targets"],
                         "binary,database,environment,frontend_index,lineage_chain,nginx_conf,state")
        self.assertEqual(evidence["clients_served"], 1)
        self.assertEqual(evidence["representations_identical"], len(aio.REPRESENTATIONS))
        self.assertEqual(evidence["transfer_count"], 8)
        # The injected hook runs inside the switch, and the cleanup is the
        # product's own recovery command rather than a harness restore.
        self.assertIn("gowave-e2e-once-fail", podman.scripts[2])
        self.assertIn("gowave-auto.sh recover --boot-files", podman.scripts[7])

    def test_the_rollback_case_fails_when_the_injected_fault_never_fired(self):
        before = self.state()
        switch = {
            "returncode": 1, "stdout": "", "stderr": "boom",
            "sabotage": {}, "journal": {"state": "ROLLED_BACK"},
            "unit": {"ActiveState": "failed"}, "health": "URLError: refused",
        }
        product, _ = self.switched_product([
            (json.dumps(before), 0),
            (json.dumps({"channel": self.surface()}), 0),
            (json.dumps(switch), 0),
            ("active\n", 0),
            (json.dumps(before), 0),
        ])
        with self.assertRaises(AssertionError) as caught:
            aio.case_channel_rollback(product)
        self.assertIn("the injected start hook never ran", str(caught.exception))

    def test_the_start_hook_damages_files_outside_the_unit_sandbox(self):
        # systemd starts the injected hook with /dev/null on standard input and
        # inside the started unit's own sandbox, where measured root cannot
        # rewrite a gowave-owned database. So the hook hands the damage to a
        # transient unit and keeps a fallback for a manager that refuses one.
        script = aio.channel_rollback_script()
        self.assertIn(f"cat > {aio.CHANNEL_SABOTAGE_EXEC} <<'PY'", script)
        hook = script.split(f"cat > {aio.CHANNEL_ONCE_FAIL_EXEC} <<'ONCE'", 1)[1]
        hook = hook.split("\nONCE\n", 1)[0]
        self.assertNotIn("<<'PY'", hook)
        self.assertNotIn("python3 -", hook)
        self.assertIn("systemd-run --wait --collect --quiet --unit=gowave-e2e-sabotage", hook)
        self.assertIn(f"python3 {aio.CHANNEL_SABOTAGE_EXEC}", hook)
        self.assertLess(hook.index("systemd-run"), hook.index("exit 1"))
        self.assertIn(aio.CHANNEL_SABOTAGE_EXEC, aio.channel_rollback_cleanup_script())

    def test_the_sabotage_damages_the_chain_the_probe_reads(self):
        # Certbot keeps a README beside the lineages, so taking the first name
        # under live/ leaves the chain untouched while every other target is
        # damaged — the case then reports a restored chain it never broke. The
        # script is executed here, not pattern-matched: the digests it records
        # have to belong to the files it really wrote.
        tmp = Path(self.tmp.name)
        source = aio.channel_rollback_script()
        marker = f"cat > {aio.CHANNEL_SABOTAGE_EXEC} <<'PY'\n"
        body = source.split(marker, 1)[1].split("\nPY\n", 1)[0]
        for absolute in ("/var/lib/gowave-auto-nginx", "/etc/letsencrypt", "/etc/nginx",
                         "/opt/gowave"):
            body = body.replace(absolute, str(tmp / absolute.lstrip("/")))
        record_path = tmp / "sabotage.json"
        body = body.replace("/tmp/gowave-e2e-sabotage.json", str(record_path))

        (tmp / "var/lib/gowave-auto-nginx/recovery/update-1").mkdir(parents=True)
        (tmp / "var/lib/gowave-auto-nginx/state.json").write_text("{}\n", encoding="utf-8")
        live = tmp / "etc/letsencrypt/live"
        (live / "README").parent.mkdir(parents=True, exist_ok=True)
        (live / "README").write_text("certbot readme\n", encoding="utf-8")
        chains = {}
        for domain in ("panel.testbed.internal", "reality.testbed.internal"):
            (live / domain).mkdir(parents=True)
            chains[domain] = live / domain / "fullchain.pem"
            chains[domain].write_text(f"certificate for {domain}\n", encoding="utf-8")
        gowave = tmp / "opt/gowave"
        (gowave / "frontend").mkdir(parents=True)
        (gowave / "gowave-server").write_text("binary\n", encoding="utf-8")
        (gowave / "gowave.db").write_bytes(b"database\n")
        (gowave / "frontend/index.html").write_text("<html>panel</html>\n", encoding="utf-8")
        (gowave / ".env").write_text("GOWAVE_CHANNEL=stable\n", encoding="utf-8")
        (tmp / "etc/nginx").mkdir(parents=True)
        (tmp / "etc/nginx/nginx.conf").write_text("events {}\n", encoding="utf-8")

        script = tmp / "sabotage.py"
        script.write_text(body, encoding="utf-8")
        completed = subprocess.run(
            [sys.executable, str(script)], capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        record = json.loads(record_path.read_text(encoding="utf-8"))

        self.assertEqual(record["snapshot"], str(tmp / "var/lib/gowave-auto-nginx/recovery/update-1"))
        self.assertEqual(
            sorted(record["targets"]),
            ["binary", "database", "environment", "frontend_index", "lineage_chain",
             "nginx_conf", "state"],
        )
        # The probe reports the first lineage it finds under live/, skipping the
        # README because it carries no chain; the recorded digest has to be that
        # same file's, and no lineage may be left intact.
        served = chains["panel.testbed.internal"]
        self.assertEqual(record["targets"]["lineage_chain"],
                         hashlib.sha256(served.read_bytes()).hexdigest())
        for domain, path in chains.items():
            self.assertTrue(path.read_text(encoding="utf-8").endswith("# e2e sabotage\n"), domain)
        self.assertIn("E2E_CHANNEL_SABOTAGE=1", (gowave / ".env").read_text(encoding="utf-8"))

    def test_the_rollback_case_fails_when_an_area_the_hook_hit_stayed_damaged(self):
        before = self.state()
        sabotage = {
            "snapshot": f"{aio.CHANNEL_RECOVERY_ROOT}/update-3",
            "targets": {
                "binary": "1" * 64, "database": "2" * 64, "frontend_index": "3" * 64,
                "environment": "4" * 64, "state": "5" * 64, "nginx_conf": "6" * 64,
                "lineage_chain": "7" * 64,
            },
        }
        switch = {
            "returncode": 1, "stdout": "",
            "stderr": "File rollback completed and services verified.\n",
            "sabotage": sabotage,
            "journal": {"state": "ROLLED_BACK",
                        "snapshot_dir": f"{aio.CHANNEL_RECOVERY_ROOT}/update-3"},
            "unit": {"ActiveState": "active"}, "health": 200,
        }
        damaged = self.state(nginx_conf="0" * 64)
        product, _ = self.switched_product([
            (json.dumps(before), 0),
            (json.dumps({"channel": self.surface()}), 0),
            (json.dumps(switch), 0),
            (json.dumps(damaged), 0),
            ("active\n", 0),
            (json.dumps(damaged), 0),
        ])
        with self.assertRaises(AssertionError) as caught:
            aio.case_channel_rollback(product)
        self.assertIn("did not restore the NGINX configuration", str(caught.exception))

    # ------------------------------------------------ AIO-INTERRUPT (operator kill)
    def interrupted(self, **overrides):
        payload = {
            "operator_pid": 4242,
            "operator_alive": False,
            "operator_exit": -9,
            "hold_started": True,
            "waited_seconds": 3,
            "observed_journal_state": "APPLYING",
            "observed_channel": "dev",
            "configured": f"ExecStartPre=+{aio.CHANNEL_HOLD_EXEC}",
            "journal_at_kill": {
                "state": "APPLYING",
                "snapshot_dir": f"{aio.CHANNEL_RECOVERY_ROOT}/update-4",
                "target_version": "dev",
            },
            "journal_valid": True,
            "lock_free": True,
            "lease": {},
            "lease_holder_alive": None,
            "unit_at_kill": {"ActiveState": "activating", "SubState": "start-pre"},
            "switch_stdout": "Capturing pre-update persistent recovery snapshot...\n",
            "switch_stderr": "",
            "switch_reported_success": False,
            "recovery_returncode": 0,
            "recovery_output": "Interrupted transaction rolled back successfully.\n",
            "journal_after_recovery": {
                "state": "ROLLED_BACK",
                "snapshot_dir": f"{aio.CHANNEL_RECOVERY_ROOT}/update-4",
                "target_version": "dev",
            },
            "health": 200,
        }
        payload.update(overrides)
        return payload

    def interrupt_results(self, payload, before=None, after=None):
        """The host calls AIO-INTERRUPT makes, in the order it makes them."""
        before = before or self.state()
        after = after or self.state()
        return [
            (json.dumps(before), 0),                       # pre-interrupt state
            (json.dumps({"channel": self.surface()}), 0),  # client surface, capture
            (json.dumps(payload), 0),                      # interrupt + recovery payload
            (json.dumps(after), 0),                        # post-recovery state
            (json.dumps(before), 0),                       # the snapshot the journal names
            ("200", 0),                                    # Panel health
            (json.dumps({"channel": self.surface()}), 0),  # client surface, verify
            ("active\n", 0),                               # cleanup: is-active
            (json.dumps(after), 0),                        # cleanup: healed state
        ]

    def interrupt_failure_results(self, payload):
        """The host calls made when the case refuses before it reaches the recovery."""
        return [
            (json.dumps(self.state()), 0),
            (json.dumps({"channel": self.surface()}), 0),
            (json.dumps(payload), 0),
            ("active\n", 0),                  # cleanup: is-active
            (json.dumps(self.state()), 0),    # cleanup: healed state
        ]

    def test_the_interrupt_payload_holds_the_restart_and_kills_the_group(self):
        for script in (aio.channel_interrupt_script(), aio.channel_interrupt_cleanup_script()):
            result = subprocess.run(["bash", "-n"], input=script, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        body = aio.channel_interrupt_script()
        # The repo path is baked in: the payload arrives on stdin alone, so a
        # positional argument would be empty and `set -u` would abort mid-switch.
        self.assertIn(f"repo={aio.topology.REPO_IN_CONTAINER}", body)
        self.assertIn('bash "$repo/gowave-auto.sh" channel dev', body)
        self.assertIn(f"ExecStartPre=+{aio.CHANNEL_HOLD_EXEC}", body)
        # The hold is what makes the interruption land in APPLYING: without it the
        # restart commits in milliseconds and the kill measures a finished switch.
        self.assertIn("exec sleep", body)
        self.assertLess(body.index("99-e2e-hold.conf"), body.index("setsid"))
        # The whole group dies, not only the shell that leads it, and the product's
        # own recovery entrypoint is what the case then invokes.
        self.assertIn('kill -9 -- "-$operator"', body)
        self.assertIn("flock -n /run/lock/gowave-managed-mutation.lock", body)
        self.assertIn('bash "$repo/gowave-auto.sh" recover --boot-files', body)
        self.assertLess(body.index('kill -9 -- "-$operator"'), body.index("recover --boot-files"))
        cleanup = aio.channel_interrupt_cleanup_script()
        self.assertIn("gowave-auto.sh recover --boot-files", cleanup)
        self.assertIn(aio.CHANNEL_HOLD_UNIT, cleanup)

    def test_the_interrupt_case_proves_an_applying_journal_and_the_rollback_of_it(self):
        product, podman = self.switched_product(self.interrupt_results(self.interrupted()))
        with mock.patch.object(aio, "wait_until", lambda predicate, *a, **k: predicate()):
            evidence = aio.case_operator_interrupt(product)
        self.assertEqual(evidence["interrupted_state"], "APPLYING")
        self.assertEqual(evidence["journal_state_at_kill"], "APPLYING")
        self.assertEqual(evidence["journal_state"], "ROLLED_BACK")
        self.assertEqual(evidence["channel_after"], "stable")
        self.assertEqual(evidence["unit_state"], "active")
        self.assertEqual(evidence["mutation_lock_free"], True)
        self.assertEqual(evidence["snapshot"], "update-4")
        self.assertEqual(evidence["clients_served"], 1)
        self.assertEqual(evidence["transfer_count"], 8)
        # The kill runs the product's command in the host's own process group, and
        # the healing is the product's recovery entrypoint rather than a harness
        # restore: the same two facts, read from the scripts that were sent.
        self.assertIn("kill -9 --", podman.scripts[2])
        self.assertIn("recover --boot-files", podman.scripts[2])
        self.assertIn("gowave-auto.sh recover --boot-files", podman.scripts[7])
        # The artifact has to carry the observation, not only the verdict: a later
        # audit reads APPLYING and ROLLED_BACK out of the case's own evidence file.
        written = Path(self.context.artifact_dir) / "evidence" / "channel-interrupt.json"
        self.assertIn("evidence/channel-interrupt.json", self.context.evidence_files)
        recorded = json.loads(written.read_text(encoding="utf-8"))
        self.assertEqual(recorded["journal_at_kill"]["state"], "APPLYING")
        self.assertEqual(recorded["journal_after_recovery"]["state"], "ROLLED_BACK")
        self.assertEqual(recorded["interrupted"]["observed_journal_state"], "APPLYING")

    def test_a_switch_that_committed_before_the_kill_fails_the_interrupt_case(self):
        payload = self.interrupted(observed_journal_state="COMMITTED")
        product, _ = self.switched_product(self.interrupt_failure_results(payload))
        with mock.patch.object(aio, "wait_until", lambda predicate, *a, **k: predicate()):
            with self.assertRaises(AssertionError) as caught:
                aio.case_operator_interrupt(product)
        self.assertIn("was not interrupted after taking the snapshot", str(caught.exception))

    def test_a_lock_the_killed_operator_kept_fails_the_interrupt_case(self):
        product, _ = self.switched_product(
            self.interrupt_failure_results(self.interrupted(lock_free=False))
        )
        with mock.patch.object(aio, "wait_until", lambda predicate, *a, **k: predicate()):
            with self.assertRaises(AssertionError) as caught:
                aio.case_operator_interrupt(product)
        self.assertIn("mutation lock stayed held", str(caught.exception))

    def test_a_recovery_of_another_snapshot_fails_the_interrupt_case(self):
        payload = self.interrupted()
        payload["journal_after_recovery"] = {
            "state": "ROLLED_BACK",
            "snapshot_dir": f"{aio.CHANNEL_RECOVERY_ROOT}/update-9",
        }
        product, _ = self.switched_product(self.interrupt_failure_results(payload))
        with mock.patch.object(aio, "wait_until", lambda predicate, *a, **k: predicate()):
            with self.assertRaises(AssertionError) as caught:
                aio.case_operator_interrupt(product)
        self.assertIn("rolled back a different transaction", str(caught.exception))

    def test_the_interrupt_case_sits_between_the_failed_and_the_dev_switch(self):
        suite = aio.cases(ScriptedPodman(self.context, []))
        cases = {case.id: case for case in suite}
        self.assertIn(aio.CHANNEL_INTERRUPT_CASE_ID, cases)
        self.assertEqual(cases[aio.CHANNEL_INTERRUPT_CASE_ID].topology, "aio")
        self.assertEqual(
            cases[aio.CHANNEL_INTERRUPT_CASE_ID].timeout_seconds,
            aio.CHANNEL_TIMEOUT_SECONDS + aio.TUNNEL_READY_TIMEOUT_SECONDS
            + aio.TRAFFIC_TIMEOUT_SECONDS,
        )
        ids = [case.id for case in suite]
        self.assertLess(ids.index(aio.CHANNEL_ROLLBACK_CASE_ID),
                        ids.index(aio.CHANNEL_INTERRUPT_CASE_ID))
        self.assertLess(ids.index(aio.CHANNEL_INTERRUPT_CASE_ID), ids.index(aio.CHANNEL_DEV_CASE_ID))
        record = {
            case["id"]: case for case in catalog.load_catalog()["cases"]
        }[aio.CHANNEL_INTERRUPT_CASE_ID]
        self.assertEqual(record["requirement"], "Failure injection and recovery")
        self.assertEqual(record["state"], "incubating")
        self.assertEqual(record["runs_in"], ["podman"])
        self.assertEqual(record["topology"], ["aio"])


class TestBackupStoreFullCase(unittest.TestCase):
    """AIO-FAULT-DISK: what counts as "the failed backup damaged nothing".

    The Panel reads and writes its own rows while the operator's backup fails, so
    a whole-dump comparison across that window measures the Panel, not the
    backup. The case reads what a failure can destroy — the tables and rows the
    database held — and what a client can observe — the client list and the bytes
    of every representation.
    """

    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def state(self, **overrides):
        facts = {
            "database": {
                "integrity": "ok",
                "logical": "l" * 64,
                "tables": ["nodes", "users"],
                "rows": {"nodes": 1, "users": 1},
            },
            "env_digest": "e" * 64,
            "frontend": "f" * 64,
            "state": "s" * 64,
            "nginx": "n" * 64,
            "letsencrypt": "a" * 64,
            "unit": {"ActiveState": "active"},
            "health": 200,
        }
        facts.update(overrides)
        return facts

    def surface(self, **overrides):
        facts = {
            "readback_status": 200,
            "short_uuid_length": 16,
            "inventory_status": 200,
            "users": 1,
            "users_captured": 1,
            "inventory_identical": True,
            "user_present": True,
            "representations": {
                name: {"status": 200, "bytes": 128} for name in aio.REPRESENTATIONS
            },
            "representations_identical": {name: True for name in aio.REPRESENTATIONS},
        }
        facts.update(overrides)
        return facts

    def fault(self, **overrides):
        facts = {
            "free_kb": "12",
            "returncode": 1,
            "stdout": "",
            "stderr": "The backup store has 12 KiB free; nothing was published.\n",
            "files_during": ["filler"],
            "returncode_after": 0,
            "stderr_after": "",
            "archive": "gowave-backup-panel-20261114-000000.tar.gz",
            "archive_mode": "600",
            "archive_bytes": "78912",
            "verify_returncode": 0,
            "verify_output": "15-point preflight archive validation PASSED.\n",
            "unit": {"gowave.service": "active"},
            "health": 200,
        }
        facts.update(overrides)
        return facts

    def run_case(self, before=None, after=None, capture=None, verified=None, facts=None):
        product, _ = installed_product(self.context, [
            (json.dumps(before if before is not None else self.state()), 0),
            (json.dumps({"channel": capture if capture is not None else self.surface()}), 0),
            (json.dumps(facts if facts is not None else self.fault()), 0),
            (json.dumps(after if after is not None else self.state()), 0),
            (json.dumps({"channel": verified if verified is not None else self.surface()}), 0),
        ])
        return aio.case_backup_store_full(product)

    def test_the_case_keeps_every_row_the_panel_had_and_the_bytes_it_served(self):
        after = self.state(database={
            "integrity": "ok",
            "logical": "m" * 64,
            "tables": ["nodes", "users"],
            "rows": {"nodes": 3, "users": 1},
        })
        evidence = self.run_case(after=after)
        self.assertEqual(evidence["database_integrity"], "ok")
        self.assertEqual(evidence["database_tables"], 2)
        self.assertEqual(evidence["database_rows_before"], 2)
        self.assertEqual(evidence["database_rows_after"], 4)
        # The Panel wrote its own rows in this window: recorded, not refused.
        self.assertEqual(evidence["database_dump_digest_changed"], "true")
        self.assertEqual(evidence["representations_identical"], len(aio.REPRESENTATIONS))
        self.assertEqual(evidence["clients_served"], 1)
        self.assertEqual(evidence["seconds_fault"] >= 0, True)
        self.assertEqual(evidence["archive_mode"], "600")

    def test_a_failed_backup_that_lost_rows_fails_the_case(self):
        after = self.state(database={
            "integrity": "ok", "logical": "l" * 64,
            "tables": ["nodes", "users"], "rows": {"nodes": 1, "users": 0},
        })
        with self.assertRaises(AssertionError) as caught:
            self.run_case(after=after)
        self.assertIn("lost rows the Panel stored (before, after): {'users': [1, 0]}",
                      str(caught.exception))

    def test_a_failed_backup_that_lost_a_table_fails_the_case(self):
        after = self.state(database={
            "integrity": "ok", "logical": "l" * 64,
            "tables": ["nodes"], "rows": {"nodes": 1},
        })
        with self.assertRaises(AssertionError) as caught:
            self.run_case(after=after)
        self.assertIn("no longer holds ['users']", str(caught.exception))

    def test_a_failed_backup_that_changed_the_served_bytes_fails_the_case(self):
        changed = {name: True for name in aio.REPRESENTATIONS}
        changed["base64"] = False
        with self.assertRaises(AssertionError) as caught:
            self.run_case(verified=self.surface(representations_identical=changed))
        self.assertIn("changed the bytes the Panel serves its client", str(caught.exception))

    def test_a_failed_backup_that_lost_the_client_fails_the_case(self):
        with self.assertRaises(AssertionError) as caught:
            self.run_case(verified=self.surface(
                inventory_identical=False, user_present=False, users=0,
            ))
        self.assertIn("changed the client inventory", str(caught.exception))

    def test_the_case_will_not_measure_a_host_that_served_no_client_before_the_fault(self):
        with self.assertRaises(AssertionError) as caught:
            self.run_case(capture=self.surface(readback_status=500, short_uuid_length=0))
        self.assertIn("served no default client before the fault", str(caught.exception))


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


class TestPanelAuthNegativeCase(unittest.TestCase):
    """AIO-AUTH-NEG: four credentials the Panel did not issue, and one it did."""

    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def run_case(self, **overrides):
        product, podman = probe_product(self.context, auth_negative_facts(overrides))
        return aio.case_panel_auth_negative(product), podman

    def reject(self, *expected, **overrides):
        with self.assertRaises(AssertionError) as caught:
            self.run_case(**overrides)
        for fragment in expected:
            self.assertIn(fragment, str(caught.exception))

    def test_every_variant_is_refused_and_the_issued_token_still_reads(self):
        evidence, podman = self.run_case()
        self.assertEqual(len(podman.scripts), 1)
        self.assertIn("--scope auth-negative", podman.scripts[0])
        self.assertEqual(evidence["control_before"], 200)
        self.assertEqual(evidence["control_after"], 200)
        self.assertTrue(evidence["signing_key_present"])
        self.assertEqual(sorted(evidence["refusals"]), sorted(AUTH_NEGATIVE_VARIANTS))
        for name, entry in evidence["refusals"].items():
            self.assertEqual((entry["status"], entry["error"]), (401, "Unauthorized"), name)
            self.assertEqual(entry["verdict"], "PASS", name)

    def test_an_unreadable_issued_token_fails_before_anything_is_minted(self):
        self.reject("carries no readable claims", **{"auth_negative.claims_present": False})

    def test_a_non_administrator_token_cannot_be_copied_faithfully(self):
        self.reject("instead of ADMIN", **{"auth_negative.role": "USER"})

    def test_a_missing_or_short_signing_key_fails_the_expired_variant(self):
        self.reject("32-character floor", **{"auth_negative.signing_key_present": False})

    def test_a_control_that_fails_before_the_refusals_makes_them_prove_nothing(self):
        self.reject("before the refusals", **{"auth_negative.control_before": 401})

    def test_a_panel_that_stops_serving_the_issued_token_fails(self):
        self.reject("stopped serving the credential it issued",
                    **{"auth_negative.control_after": 500})

    def test_a_variant_the_panel_serves_fails_the_case(self):
        for name in AUTH_NEGATIVE_VARIANTS:
            with self.subTest(variant=name):
                self.reject(f"the {name} token read /api/nodes as 200 instead of being refused "
                            "with 401", **{f"auth_negative.refusals.{name}.status": 200})

    def test_a_variant_missing_from_the_probe_fails_the_case(self):
        for name in AUTH_NEGATIVE_VARIANTS:
            with self.subTest(variant=name):
                self.reject(f"the {name} token read /api/nodes as None",
                            **{f"auth_negative.refusals.{name}": {}})

    def test_a_refusal_with_another_body_fails_the_case(self):
        for name in AUTH_NEGATIVE_VARIANTS:
            with self.subTest(variant=name):
                self.reject("instead of the Panel's own Unauthorized body",
                            **{f"auth_negative.refusals.{name}.error": "Forbidden"})

    def test_a_probe_that_exits_nonzero_fails_the_case(self):
        product, _ = probe_product(self.context, '{"auth_negative": {}}', returncode=1)
        with self.assertRaises(AssertionError) as caught:
            aio.case_panel_auth_negative(product)
        self.assertIn("the Panel probe exited 1", str(caught.exception))

    def test_the_case_is_registered_beside_the_auth_case_and_before_any_traffic(self):
        cases = {case.id: case for case in aio.cases(ScriptedPodman(self.context, []))}
        self.assertIn(aio.AUTH_NEGATIVE_CASE_ID, cases)
        self.assertEqual(cases[aio.AUTH_NEGATIVE_CASE_ID].topology, "aio")
        self.assertEqual(cases[aio.AUTH_NEGATIVE_CASE_ID].timeout_seconds, 300)
        ids = [case.id for case in aio.cases(ScriptedPodman(self.context, []))]
        self.assertLess(ids.index("AIO-AUTH"), ids.index(aio.AUTH_NEGATIVE_CASE_ID))
        self.assertLess(ids.index(aio.AUTH_NEGATIVE_CASE_ID), ids.index("AIO-CLIENT"))


class TestPanelAuthNegativeProbe(unittest.TestCase):
    """The probe against a stub gate shaped like the Panel's three clauses."""

    SECRET = "4f1c" * 16
    ADMIN_UUID = "0b8f6f3c-9a1e-4f57-8a1c-2d5f0d6a1c11"
    PASSWORD = "pw-do-not-print"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        now = int(datetime.now(timezone.utc).timestamp())
        self.token = panel_surface._hs256_token(
            {"uuid": self.ADMIN_UUID, "username": "admin", "role": "ADMIN",
             "iat": now, "exp": now + 900},
            self.SECRET,
        )
        env = root / "gowave.env"
        env.write_text(f"APP_SECRET='{self.SECRET}'\n", encoding="utf-8")
        patcher = mock.patch.object(panel_surface, "PRODUCT_ENV_FILES", (str(env),))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.credentials = root / "credentials"
        self.credentials.write_text(
            f"ADMIN_USERNAME=admin\nADMIN_PASSWORD={self.PASSWORD}\n", encoding="utf-8"
        )
        self.credentials.chmod(0o600)
        self.server = self._start_stub()
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.server_close)

    def _start_stub(self):
        """A gate that refuses on the clause the probe's variant was built to break."""
        decisions = []
        admin_uuid, secret, password, token = (
            self.ADMIN_UUID, self.SECRET, self.PASSWORD, self.token,
        )

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, body):
                raw = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                if self.path != "/api/auth/login":
                    return self._send(404, {"message": "not found"})
                if body.get("password") != password:
                    decisions.append("login-refused")
                    return self._send(401, {"error": "Unauthorized"})
                decisions.append("login")
                return self._send(200, {"response": {"accessToken": token,
                                                     "tokenType": "Bearer"}})

            def do_GET(self):
                if self.path != "/api/nodes":
                    return self._send(404, {"message": "not found"})
                header = self.headers.get("Authorization") or ""
                presented = header[len("Bearer "):] if header.startswith("Bearer ") else ""
                clause = self._refusal(presented)
                decisions.append(clause)
                if clause:
                    return self._send(401, {"error": "Unauthorized"})
                return self._send(200, {"response": [{"uuid": "node-uuid", "isConnected": True}]})

            def _refusal(self, presented):
                parts = presented.split(".")
                if len(parts) != 3 or not parts[2]:
                    return "no-signature"
                claims = panel_surface.token_claims(presented)
                if not claims:
                    return "claims"
                if panel_surface._hs256_token(claims, secret) != presented:
                    return "signature"
                expiry = claims.get("exp")
                now = int(datetime.now(timezone.utc).timestamp())
                if not isinstance(expiry, (int, float)) or expiry <= now:
                    return "expiry"
                if str(claims.get("uuid") or "") != admin_uuid:
                    return "record"
                return ""

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.decisions = decisions
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server

    def run_probe(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = panel_surface.main([
                "--scope", "auth-negative",
                "--panel-url", f"http://127.0.0.1:{self.server.server_address[1]}",
                "--credentials", str(self.credentials),
            ])
        self.assertEqual(code, 0)
        output = stdout.getvalue()
        self.assertNotIn(self.PASSWORD, output)
        self.assertNotIn(self.token, output)
        self.assertNotIn(self.SECRET, output)
        return json.loads(output)

    def test_each_variant_dies_of_the_clause_it_was_built_to_break(self):
        facts = self.run_probe()["auth_negative"]
        self.assertEqual(self.server.decisions, [
            "login", "", "expiry", "signature", "no-signature", "record", "",
        ])
        self.assertEqual(facts["refusals"]["expired"]["status"], 401)
        self.assertEqual(facts["refusals"]["forged"]["status"], 401)
        self.assertEqual(facts["refusals"]["unsigned"]["status"], 401)
        self.assertEqual(facts["refusals"]["unknown-admin"]["status"], 401)
        self.assertEqual(
            [entry["error"] for entry in facts["refusals"].values()],
            ["Unauthorized"] * len(AUTH_NEGATIVE_VARIANTS),
        )

    def test_the_issued_token_reads_before_and_after_the_refusals(self):
        facts = self.run_probe()["auth_negative"]
        self.assertTrue(facts["claims_present"])
        self.assertEqual(facts["role"], "ADMIN")
        self.assertTrue(facts["signing_key_present"])
        self.assertEqual((facts["control_before"], facts["control_after"]), (200, 200))
        self.assertEqual(self.server.decisions[0], "login")
        self.assertEqual((self.server.decisions[1], self.server.decisions[-1]), ("", ""))

    def test_an_absent_secret_is_reported_rather_than_used(self):
        with mock.patch.object(panel_surface, "PRODUCT_ENV_FILES", ("/nonexistent.env",)):
            facts = self.run_probe()["auth_negative"]
        self.assertFalse(facts["signing_key_present"])
        # Every signed variant now dies of its signature instead of the clause it
        # was built to break, which is what the case's own `signing_key_present`
        # require is there to refuse before the refusals are believed.
        self.assertEqual(self.server.decisions.count("signature"), 3)
        self.assertNotIn("expiry", self.server.decisions)
        self.assertNotIn("record", self.server.decisions)


class TestPanelApiClientCase(unittest.TestCase):
    """APIC-01: the controller's client trusts the run bundle and nothing else."""

    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def run_case(self, **overrides):
        product, podman = probe_product(self.context, api_client_facts(overrides))
        return aio.case_panel_api_client_trust(product), podman

    def reject(self, *expected, **overrides):
        with self.assertRaises(AssertionError) as caught:
            self.run_case(**overrides)
        for fragment in expected:
            self.assertIn(fragment, str(caught.exception))

    def test_the_probe_is_driven_with_the_run_bundle_and_a_non_default_bound(self):
        evidence, podman = self.run_case()
        self.assertEqual(len(podman.scripts), 1)
        script = podman.scripts[0]
        self.assertIn("--scope api-client", script)
        self.assertIn(f"--edge-base https://{aio.PANEL_DOMAIN}", script)
        self.assertIn(f"{topology.CA_MOUNT}/{topology.ACME_CA_BUNDLE_NAME}", script)
        # The bound is neither the client's nor the parser's default, so a
        # literal left in place would disagree with it instead of agreeing.
        self.assertIn(f"API_TIMEOUT={aio.PANEL_API_CLIENT_TIMEOUT_SECONDS}", script)
        self.assertNotEqual(aio.PANEL_API_CLIENT_TIMEOUT_SECONDS, 15)
        self.assertEqual(evidence["verify_mode"], "CERT_REQUIRED")
        self.assertTrue(evidence["hostname_verification"])
        self.assertEqual(evidence["bundle_login"], "accepted")
        self.assertEqual(evidence["nodes"], 2)
        self.assertEqual(evidence["request_timeout_configured"],
                         aio.PANEL_API_CLIENT_TIMEOUT_SECONDS)
        self.assertEqual(evidence["request_timeout_used"],
                         aio.PANEL_API_CLIENT_TIMEOUT_SECONDS)
        self.assertEqual(evidence["production_default_timeout"],
                         aio.PANEL_API_CLIENT_TIMEOUT_SECONDS)
        self.assertTrue(evidence["production_default_context"])
        self.assertEqual(evidence["bypass_tokens"], 0)

    def test_a_context_that_does_not_verify_is_not_the_run_bundle(self):
        self.reject("verifies in 'CERT_NONE' instead of CERT_REQUIRED",
                    **{"api_client.verify_mode": "CERT_NONE"})

    def test_a_context_that_does_not_check_the_hostname_fails_the_case(self):
        self.reject("does not check the hostname", **{"api_client.hostname_verification": False})

    def test_a_client_that_cannot_log_in_through_the_bundle_fails_the_case(self):
        self.reject("could not log in through the run bundle", **{"api_client.bundle_login": "GoWaveAPIError"})

    def test_a_response_that_is_not_a_node_list_fails_the_case(self):
        self.reject("nodes instead of a list", **{"api_client.nodes": -1})

    def test_a_login_through_an_empty_store_makes_the_bundle_prove_nothing(self):
        self.reject("logged in through a context with no trust anchor",
                    **{"api_client.empty_store_login": "accepted"})

    def test_a_hostname_the_certificate_does_not_name_must_be_refused(self):
        self.reject("accepted a certificate that names a different host",
                    **{"api_client.hostname_mismatch_login": "accepted"})

    def test_a_client_with_its_own_literal_timeout_fails_the_case(self):
        self.reject("used a 15 second bound", **{"api_client.timeout_used": 15})

    def test_a_parser_that_ignores_api_timeout_fails_the_case(self):
        self.reject("API_TIMEOUT parsed as 15", **{"api_client.timeout_configured": 15})

    def test_a_default_caller_that_does_not_inherit_the_bound_fails_the_case(self):
        self.reject("did not inherit API_TIMEOUT",
                    **{"api_client.production_default_timeout": 15})

    def test_a_default_caller_that_supplies_its_own_context_fails_the_case(self):
        self.reject("did not get the default one", **{"api_client.production_default_context": False})

    def test_a_trust_bypass_in_either_source_fails_the_case(self):
        self.reject("a trust bypass reached the shipped sources",
                    **{"api_client.bypass_tokens": ["tools/live_vps/panel_api.py: verify=False"]})

    def test_a_probe_that_exits_nonzero_fails_the_case(self):
        product, _ = probe_product(self.context, '{"api_client": {}}', returncode=1)
        with self.assertRaises(AssertionError) as caught:
            aio.case_panel_api_client_trust(product)
        self.assertIn("the Panel API client probe exited 1", str(caught.exception))

    def test_the_case_runs_beside_the_refusal_case_on_a_healthy_panel(self):
        suite = aio.cases(ScriptedPodman(self.context, []))
        cases = {case.id: case for case in suite}
        self.assertIn(aio.PANEL_API_CLIENT_CASE_ID, cases)
        self.assertEqual(cases[aio.PANEL_API_CLIENT_CASE_ID].topology, "aio")
        self.assertEqual(cases[aio.PANEL_API_CLIENT_CASE_ID].timeout_seconds, 300)
        ids = [case.id for case in suite]
        self.assertLess(ids.index(aio.AUTH_NEGATIVE_CASE_ID),
                        ids.index(aio.PANEL_API_CLIENT_CASE_ID))
        self.assertLess(ids.index(aio.PANEL_API_CLIENT_CASE_ID), ids.index("AIO-CLIENT"))


class TestPanelApiClientProbe(unittest.TestCase):
    """The probe against a real TLS listener serving a certificate it must trust."""

    PASSWORD = "pw-do-not-print"
    TOKEN = "stub-token-not-a-secret-value"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ca = self.root / "ca.pem"
        key = self.root / "server.key"
        self._openssl(
            "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(self.ca), "-days", "1",
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost",
        )
        self.credentials = self.root / "credentials"
        self.credentials.write_text(
            f"ADMIN_USERNAME=admin\nADMIN_PASSWORD={self.PASSWORD}\n", encoding="utf-8"
        )
        self.credentials.chmod(0o600)
        self.server = self._start_stub(self.ca, key)
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.server_close)

    def _openssl(self, *arguments):
        result = subprocess.run(
            ["openssl", *arguments], capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def _start_stub(self, cert, key):
        """A Panel that answers login and ``/api/nodes`` once the caller is past TLS."""
        password, token = self.PASSWORD, self.TOKEN

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, body):
                raw = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                if self.path != "/api/auth/login":
                    return self._send(404, {"message": "not found"})
                if body.get("password") != password:
                    return self._send(401, {"error": "Unauthorized"})
                return self._send(200, {"response": {"accessToken": token}})

            def do_GET(self):
                if self.path != "/api/nodes":
                    return self._send(404, {"message": "not found"})
                if not (self.headers.get("Authorization") or "").startswith("Bearer "):
                    return self._send(401, {"error": "Unauthorized"})
                return self._send(200, {"response": [{"uuid": "node-uuid", "isConnected": True}]})

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server

    def edge_base(self, host="localhost"):
        return f"https://{host}:{self.server.server_address[1]}"

    def run_probe(self, edge_base=None, timeout=7):
        stdout = io.StringIO()
        argv = [
            "--scope", "api-client",
            "--edge-base", edge_base or self.edge_base(),
            "--ca", str(self.ca),
            "--credentials", str(self.credentials),
        ]
        with mock.patch.dict(os.environ, {"API_TIMEOUT": str(timeout)}), \
                redirect_stdout(stdout):
            code = panel_surface.main(argv)
        self.assertEqual(code, 0)
        output = stdout.getvalue()
        self.assertNotIn(self.PASSWORD, output)
        self.assertNotIn(self.TOKEN, output)
        return json.loads(output)

    def test_the_bundle_logs_in_and_an_anchorless_context_does_not(self):
        facts = self.run_probe()["api_client"]
        self.assertEqual(facts["verify_mode"], "CERT_REQUIRED")
        self.assertTrue(facts["hostname_verification"])
        self.assertEqual(facts["bundle_login"], "accepted")
        self.assertEqual(facts["nodes"], 1)
        self.assertNotEqual(facts["empty_store_login"], "accepted")

    def test_the_same_bundle_does_not_accept_an_address_the_certificate_omits(self):
        facts = self.run_probe()["api_client"]
        self.assertNotEqual(facts["hostname_mismatch_login"], "accepted")

    def test_an_empty_store_is_not_the_system_store_that_trusts_the_run_ca(self):
        # The live host may point its default store at the run's CA through
        # `SSL_CERT_FILE`, which the case names as the environment's property
        # rather than the client's. A probe that used `create_default_context`
        # where it promises a context with no anchor would then report that
        # trust as its own, so with the variable set the empty-store login must
        # still be refused while the system-store login is reported as accepted.
        with mock.patch.dict(os.environ, {"SSL_CERT_FILE": str(self.ca)}):
            facts = self.run_probe()["api_client"]
        self.assertEqual(facts["system_store_login"], "accepted")
        self.assertNotEqual(facts["empty_store_login"], "accepted")

    def test_the_configured_bound_reaches_the_client_and_the_default_one(self):
        facts = self.run_probe(timeout=7)["api_client"]
        self.assertEqual(facts["timeout_configured"], 7)
        self.assertEqual(facts["timeout_used"], 7)
        self.assertEqual(facts["production_default_timeout"], 7)
        self.assertTrue(facts["production_default_context"])

    def test_the_scope_does_not_log_in_to_the_loopback_api_first(self):
        # Every other scope starts with that fact; this one must not, or the
        # plaintext loopback answer would be read as the HTTPS client's trust.
        facts = self.run_probe()
        self.assertEqual(sorted(facts), ["api_client"])

    def test_a_plaintext_edge_base_is_refused_before_any_client_is_built(self):
        with self.assertRaises(SystemExit) as caught:
            self.run_probe(edge_base="http://localhost:3000")
        self.assertIn("must be an https URL naming the Panel", str(caught.exception))

    def test_the_shipped_tree_carries_no_bypass(self):
        from tools.podman_e2e import panel_surface as surface

        root = Path(__file__).resolve().parents[1]
        self.assertEqual(surface.api_client_bypass_tokens(root), [])

    def test_a_bypass_added_to_either_source_is_reported_by_name(self):
        from tools.podman_e2e import panel_surface as surface

        for relative in surface.API_CLIENT_SOURCES:
            with self.subTest(source=relative):
                for name in surface.API_CLIENT_SOURCES:
                    (self.root / name).parent.mkdir(parents=True, exist_ok=True)
                    (self.root / name).write_text("clean\n", encoding="utf-8")
                (self.root / relative).write_text(
                    "client = build(verify=False)\n", encoding="utf-8"
                )
                self.assertEqual(surface.api_client_bypass_tokens(self.root),
                                 [f"{relative}: verify=False"])


class TestPanelEnvValue(unittest.TestCase):
    """`APP_SECRET` is read from the product's own file, quotes and all."""

    def read(self, text, name="APP_SECRET"):
        with tempfile.TemporaryDirectory() as tmp:
            env = Path(tmp) / "gowave.env"
            env.write_text(text, encoding="utf-8")
            return panel_surface.env_value(name, str(env))

    def test_a_double_quoted_value_is_unwrapped(self):
        self.assertEqual(self.read('APP_SECRET="a-secret"\n'), "a-secret")

    def test_a_single_quoted_value_with_padding_is_unwrapped(self):
        self.assertEqual(self.read("  APP_SECRET = 'a-secret'  \n"), "a-secret")

    def test_a_missing_key_or_file_is_empty_rather_than_an_error(self):
        self.assertEqual(self.read("OTHER=1\n"), "")
        self.assertEqual(panel_surface.env_value("APP_SECRET", "/nonexistent.env"), "")

    def test_the_default_path_is_the_product_file_read_at_call_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = Path(tmp) / "gowave.env"
            env.write_text("APP_SECRET=a-secret\n", encoding="utf-8")
            with mock.patch.object(panel_surface, "PRODUCT_ENV_FILES", (str(env),)):
                self.assertEqual(panel_surface.env_value("APP_SECRET"), "a-secret")


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
        f"http-01 challenge for {domain}\n{aio.CERTBOT_RENEWAL_SUCCEEDED}: "
    )
    facts.update({
        "renewal": {"returncode": renewal_exit, "stdout": text, "stderr": "",
                    "tail": text, "duration_seconds": 6.5, "attempts": [
                        {"attempt": 1, "returncode": renewal_exit,
                         "challenged": f"http-01 challenge for {domain}" in text},
                    ]},
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
        self.reject("performed no HTTP-01 challenge",
                    after=acme_probe("renew", transcript="dns-01 challenge for "
                                     f"{aio.PANEL_DOMAIN}\n{aio.CERTBOT_RENEWAL_SUCCEEDED}: "))

    def test_a_renewal_the_ca_answered_without_a_challenge_names_the_reuse(self):
        # Pebble answers with an already-valid authorization one order in a hundred
        # even with reuse switched off, and such an order performs no challenge: the
        # log says so, the message counts the attempts, and the log is quoted.
        reused = acme_probe("renew", transcript=(
            f"Renewing an existing certificate for {aio.PANEL_DOMAIN}\n"
            f"{aio.CERTBOT_RENEWAL_SUCCEEDED}: "
        ))
        caught = self.reject("reuses a valid authorization", after=reused)
        self.assertIn("in 1 attempt(s)", str(caught.exception))
        self.assertIn(f"Renewing an existing certificate for {aio.PANEL_DOMAIN}",
                      str(caught.exception))

    def test_a_renewal_that_receives_no_certificate_fails_the_case(self):
        self.reject("exited 1", after=acme_probe("renew", renewal_exit=1))

    def test_a_certonly_success_line_does_not_stand_in_for_a_renewal(self):
        # `certbot renew` prints "Congratulations, all renewals succeeded";
        # "Successfully received certificate." belongs to certonly/run and can
        # never appear here, so demanding it read a real renewal as a failure.
        certonly = acme_probe("renew", transcript=(
            f"http-01 challenge for {aio.PANEL_DOMAIN}\nSuccessfully received certificate."
        ))
        caught = self.reject("without printing its completed-renewal summary", after=certonly)
        self.assertIn(aio.CERTBOT_RENEWAL_SUCCEEDED, str(caught.exception))

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
            f"printf '%s\\n' '{aio.CERTBOT_RENEWAL_SUCCEEDED}: ' >> \"$log_dir/letsencrypt.log\"\n"
            'printf %s "$REQUESTS_CA_BUNDLE" > ' + str(anchor) + "\n"
            f"printf 'new' > {archive}/cert2.pem\n"
            f"printf 'new' > {live}/fullchain.pem\n"
            f"touch {marker}\n"
            f"printf '%s\\n' 'http-01 challenge for {domain}'\n"
            f"printf '%s\\n' '{aio.CERTBOT_RENEWAL_SUCCEEDED}: '\n"
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
        self.assertIn(aio.CERTBOT_RENEWAL_SUCCEEDED, facts["certbot_log"])
        self.assertEqual(facts["live_after"]["serial"], "0C2D")
        self.assertEqual(len(facts["archive_after"]), 2)
        self.assertEqual([item["serial"] for item in facts["archive_after"]], ["0A1B", "0C2D"])
        self.assertGreater(facts["live_after"]["not_before_epoch"], facts["live"]["not_before_epoch"])
        self.assertEqual(facts["service"]["main_pid"], facts["service_after"]["main_pid"])
        self.assertEqual(facts["service_after"]["worker_pids"], ["5100", "5101"])
        self.assertEqual(anchor, "/fixtures/ca/acme-trust.pem",
                         "the renewal has to be handed the fixture CA the install used")

    def rewrite_certbot(self, layout: dict, prefix: str) -> Path:
        """The stub renewer with shell inserted ahead of its own body."""
        certbot = layout["bindir"] / "certbot"
        certbot.write_text(
            prefix + certbot.read_text(encoding="utf-8").split("\n", 1)[1],
            encoding="utf-8",
        )
        certbot.chmod(0o755)
        return certbot

    def test_a_renewal_the_ca_finished_without_a_challenge_is_asked_again(self):
        # Pebble reuses a valid authorization for one order in a hundred even with
        # PEBBLE_AUTHZREUSE=0, and a reused order performs no challenge at all: the
        # certificate is real and the route this phase exists to exercise was never
        # used. The fixture is the unreliable part — the product is asked the same
        # question either way — so the probe asks again instead of reporting a pass
        # for a challenge that never happened.
        with tempfile.TemporaryDirectory() as tmpdir:
            main_pid = self.spare_pid()
            layout = self.build_target(Path(tmpdir), main_pid)
            counter = layout["root"] / "certbot-calls"
            self.rewrite_certbot(layout, (
                "#!/bin/sh\n"
                f'calls=$(cat {counter} 2>/dev/null || echo 0)\n'
                f"printf '%s' $((calls + 1)) > {counter}\n"
                'if [ "$calls" = 0 ]; then\n'
                f'  printf "%s\\n" "Renewing an existing certificate for {aio.PANEL_DOMAIN}" >&2\n'
                "  exit 0\n"
                "fi\n"
            ))
            facts = self.run_probe("renew", layout, main_pid)
            calls = counter.read_text(encoding="utf-8")
        self.assertEqual(calls, "2", "the silent renewal must be asked again exactly once")
        self.assertEqual([item["challenged"] for item in facts["renewal"]["attempts"]],
                         [False, True])
        self.assertIn(f"http-01 challenge for {aio.PANEL_DOMAIN}", facts["certbot_log"])

    def test_a_refused_renewal_is_not_asked_again(self):
        # A refusal is the answer, not a fixture coin flip: retrying it would spend
        # the outage's evidence and could turn one refusal into a reported success.
        with tempfile.TemporaryDirectory() as tmpdir:
            main_pid = self.spare_pid()
            layout = self.build_target(Path(tmpdir), main_pid)
            counter = layout["root"] / "certbot-calls"
            self.rewrite_certbot(layout, (
                "#!/bin/sh\n"
                f'calls=$(cat {counter} 2>/dev/null || echo 0)\n'
                f"printf '%s' $((calls + 1)) > {counter}\n"
                'printf "%s\\n" "Some challenges have failed." >&2\n'
                "exit 1\n"
            ))
            facts = self.run_probe("renew", layout, main_pid)
            calls = counter.read_text(encoding="utf-8")
        self.assertEqual(calls, "1")
        self.assertEqual([item["returncode"] for item in facts["renewal"]["attempts"]], [1])

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

    def test_a_reused_authorization_during_the_outage_quotes_the_log(self):
        reused = acme_probe("renew", issued_epoch=self.installed, transcript=(
            f"Renewing an existing certificate for {aio.PANEL_DOMAIN}\n"
            f"{aio.CERTBOT_RENEWAL_SUCCEEDED}: "
        ))
        caught = self.reject("reuses a valid authorization", challenge_attempt=reused)
        self.assertIn("Renewing an existing certificate", str(caught.exception))

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
        # The rendered command is executed whole, heredoc and argv line included:
        # the invocation line is what the topology runs, so a substitution that
        # rewrites its own arguments has to fail here rather than in a live run.
        script = (
            aio.acme_outage_script(mode, original_mode, str(layout["hosts"]))
            .replace(aio.ACME_WEBROOT, str(layout["webroot"]))
        )
        result = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, check=False,
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


DECOY_INDEX_SHA = "a" * 64
DECOY_404_SHA = "b" * 64
DECOY_PANEL_SHA = "c" * 64


def decoy_report(
    url, status, sha, san=(), version="TLSv1.3", length=1024, peer=True,
    returncode=0, error="", snippet="",
):
    """One independent-client fetch, in the shape the probe prints it.

    A handshake read without a name pin reports no peer facts at all — Python
    returns an empty certificate dict once verification is off — so ``peer``
    decides whether the report carries any.
    """
    reported = {"san": list(san), "tls_version": version, "issuer": "CN=Pebble Intermediate CA"}
    probe = {
        "url": url,
        "status": status,
        "body_length": length,
        "body_sha256": sha,
        "body_snippet": snippet,
        "peer": reported if peer else {},
    }
    if error:
        probe["error"] = error
    return {"returncode": returncode, "probe": probe, "stdout": json.dumps(probe), "stderr": ""}


class TestDecoyCase(unittest.TestCase):
    """DECOY-01: the camouflage listener never answers as a management interface."""

    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def route_reports(self, name, san=(), site_sha=DECOY_INDEX_SHA, not_found_sha=DECOY_404_SHA):
        base = f"https://{name}"
        entries = [
            (f"{base}/", 200, site_sha),
            (f"{base}/index.html", 200, site_sha),
            (f"{base}{aio.DECOY_MISSING_PATH}", 404, not_found_sha),
            (f"{base}/404.html", 200, not_found_sha),
        ]
        entries += [(f"{base}{path}", 404, not_found_sha) for path in aio.DECOY_MANAGEMENT_PATHS]
        return [
            decoy_report(url, status, sha, san, peer=bool(san))
            for url, status, sha in entries
        ]

    def reports(self, replace=None):
        """The fetches the case makes, in order, with single answers replaceable."""
        cover = topology.COVER_APEX
        reports = []
        reports += self.route_reports(cover, san=[cover])
        reports += self.route_reports(f"www.{cover}", san=[f"www.{cover}"])
        reports += self.route_reports(aio.REALITY_DOMAIN, san=[aio.REALITY_DOMAIN])
        reports += self.route_reports(aio.DECOY_UNMAPPED_SNI)
        reports.append(decoy_report(
            f"{aio.PUBLIC_PANEL}/api/nodes", 401, DECOY_PANEL_SHA, [aio.PANEL_DOMAIN],
            snippet='{"message":"Unauthorized"}',
        ))
        for url, report in (replace or {}).items():
            for index, existing in enumerate(reports):
                if existing["probe"]["url"] == url:
                    reports[index] = report
                    break
            else:
                raise AssertionError(f"the case never asks for {url}")
        return reports

    def product(self, reports=None, loopback="login=200 api=200 token_length=64\n"):
        product, _podman = installed_product(self.context, [(loopback, 0)])
        product.host.client_reports = list(self.reports() if reports is None else reports)
        return product

    def reject(self, expected, reports=None, loopback="login=200 api=200 token_length=64\n"):
        with self.assertRaises(AssertionError) as caught:
            aio.case_decoy(self.product(reports, loopback))
        self.assertIn(expected, str(caught.exception))
        return caught

    def test_every_route_serves_the_site_and_refuses_every_management_path(self):
        evidence = aio.case_decoy(self.product())
        self.assertEqual(
            [route["sni"] for route in evidence["routes"].values()],
            [topology.COVER_APEX, f"www.{topology.COVER_APEX}",
             aio.REALITY_DOMAIN, aio.DECOY_UNMAPPED_SNI],
        )
        for route in evidence["routes"].values():
            self.assertEqual(route["status"], 200)
            self.assertEqual(route["site_sha256"], DECOY_INDEX_SHA)
            self.assertEqual(route["not_found_sha256"], DECOY_404_SHA)
            self.assertEqual(sorted(route["management"]), sorted(aio.DECOY_MANAGEMENT_PATHS))
            for observed in route["management"].values():
                self.assertEqual(observed, {"status": 404, "sha256": DECOY_404_SHA})
        self.assertEqual(evidence["management_paths"], list(aio.DECOY_MANAGEMENT_PATHS))
        self.assertEqual(evidence["missing_path"], aio.DECOY_MISSING_PATH)
        self.assertEqual(evidence["management"]["loopback_login"], "200")
        self.assertEqual(evidence["management"]["loopback_api"], "200")
        self.assertEqual(evidence["management"]["anonymous_api_status"], 401)

    def test_only_the_unmapped_route_is_read_without_verification(self):
        product = self.product()
        aio.case_decoy(product)
        calls = {call["url"]: call for call in product.host.client_calls}
        for name in (topology.COVER_APEX, f"www.{topology.COVER_APEX}", aio.REALITY_DOMAIN):
            self.assertFalse(calls[f"https://{name}/"].get("insecure", False))
        self.assertTrue(calls[f"https://{aio.DECOY_UNMAPPED_SNI}/"]["insecure"])
        self.assertFalse(calls[f"{aio.PUBLIC_PANEL}/api/nodes"].get("insecure", False))
        self.assertEqual(calls[f"https://{topology.COVER_APEX}/"]["expect_status"], 200)
        self.assertEqual(
            calls[f"https://{topology.COVER_APEX}/api/nodes"]["expect_status"], 404,
        )

    def test_a_management_path_that_answers_is_refused(self):
        url = f"https://{topology.COVER_APEX}/api/nodes"
        self.reject(
            "published a management interface",
            self.reports({url: decoy_report(
                url, 200, DECOY_PANEL_SHA, [topology.COVER_APEX],
                returncode=1, error="status 200 != 404", snippet='{"message":"Forbidden"}',
            )}),
        )

    def test_a_refusal_that_is_not_the_sites_own_page_is_refused(self):
        url = f"https://{topology.COVER_APEX}/api/"
        report = decoy_report(url, 404, "d" * 64, [topology.COVER_APEX],
                              snippet="<html><center>nginx</center></html>")
        self.reject("came from another listener", self.reports({url: report}))

    def test_a_route_serving_another_document_is_refused(self):
        cover = topology.COVER_APEX
        other = "e" * 64
        urls = [f"https://www.{cover}/", f"https://www.{cover}/index.html"]
        self.reject(
            "does not terminate on the camouflage site",
            self.reports({
                url: decoy_report(url, 200, other, [f"www.{cover}"]) for url in urls
            }),
        )

    def test_a_route_whose_certificate_does_not_name_it_is_refused(self):
        cover = topology.COVER_APEX
        report = decoy_report(f"https://www.{cover}/", 200, DECOY_INDEX_SHA, [cover])
        self.reject("which does not name", self.reports({f"https://www.{cover}/": report}))

    def test_a_route_that_negotiated_another_tls_version_is_refused(self):
        cover = topology.COVER_APEX
        report = decoy_report(f"https://{cover}/", 200, DECOY_INDEX_SHA, [cover], version="TLSv1.2")
        self.reject("instead of TLSv1.3", self.reports({f"https://{cover}/": report}))

    def test_a_route_that_cannot_be_reached_is_refused(self):
        cover = topology.COVER_APEX
        url = f"https://{cover}/"
        report = {"returncode": 1, "probe": {"url": url, "error": "ConnectionResetError: reset"},
                  "stdout": "", "stderr": ""}
        self.reject("did not answer as the camouflage site does", self.reports({url: report}))

    def test_a_404_page_that_is_the_front_page_is_refused(self):
        cover = topology.COVER_APEX
        url = f"https://{cover}/404.html"
        self.reject(
            "are the same document",
            self.reports({url: decoy_report(url, 200, DECOY_INDEX_SHA, [cover])}),
        )

    def test_an_unknown_path_answered_with_the_front_page_is_refused(self):
        cover = topology.COVER_APEX
        url = f"https://{cover}{aio.DECOY_MISSING_PATH}"
        report = decoy_report(url, 200, DECOY_INDEX_SHA, [cover], returncode=1,
                              error="status 200 != 404")
        self.reject("did not answer as the camouflage site does", self.reports({url: report}))

    def test_a_management_surface_that_stops_authenticating_fails_the_case(self):
        self.reject("the Panel login answered", loopback="login=502 api=502 token_length=0\n")

    def test_an_anonymous_management_read_that_is_answered_fails_the_case(self):
        url = f"{aio.PUBLIC_PANEL}/api/nodes"
        self.reject(
            "instead of being refused",
            self.reports({url: decoy_report(url, 200, DECOY_PANEL_SHA, [aio.PANEL_DOMAIN])}),
        )

    def test_a_panel_name_answered_by_the_decoy_fails_the_case(self):
        url = f"{aio.PUBLIC_PANEL}/api/nodes"
        self.reject(
            "the panel name is answered by the decoy",
            self.reports({url: decoy_report(url, 403, DECOY_404_SHA, [aio.PANEL_DOMAIN])}),
        )

    def test_the_measured_paths_are_the_ones_the_panel_vhost_serves(self):
        nginx = (REPO_ROOT / "modules" / "nginx.sh").read_text(encoding="utf-8")
        vhost = nginx.split("generate_panel_https_vhost() {", 1)[1].split("\n}\n", 1)[0]
        served = set()
        for line in vhost.splitlines():
            stripped = line.strip()
            if not stripped.startswith("location "):
                continue
            parts = stripped.split(None, 1)[1].rstrip("{").split()
            while parts and parts[0] in ("^~", "=", "~", "~*"):
                parts.pop(0)
            path = " ".join(parts)
            if path == "/":
                # The cover site's own front page is served there, and the case
                # measures that separately from the paths it must refuse.
                continue
            served.add(path)
        self.assertTrue(served)
        self.assertEqual(served - set(aio.DECOY_MANAGEMENT_PATHS), set())

    def test_the_unmapped_sni_is_resolved_by_the_run_zone(self):
        plan = topology.NetworkPlan("203.0.114.0/24")
        records = topology.zone(plan)["records"]
        self.assertEqual(records[aio.DECOY_UNMAPPED_SNI]["A"], [plan.target_ip])
        self.assertNotIn(aio.DECOY_UNMAPPED_SNI, {
            topology.PANEL_DOMAIN, topology.REALITY_DOMAIN, topology.VISION_DOMAIN,
            topology.COVER_APEX, f"www.{topology.COVER_APEX}",
        })

    def test_the_case_is_registered_before_any_traffic_and_catalogued(self):
        suite = aio.cases(ScriptedPodman(self.context, []))
        cases = {case.id: case for case in suite}
        self.assertIn(aio.DECOY_CASE_ID, cases)
        self.assertEqual(cases[aio.DECOY_CASE_ID].topology, "aio")
        self.assertEqual(cases[aio.DECOY_CASE_ID].timeout_seconds, aio.DECOY_TIMEOUT_SECONDS)
        ids = [case.id for case in suite]
        self.assertLess(ids.index(aio.DECOY_CASE_ID), ids.index("SUB-SERVED"))
        record = {case["id"]: case for case in catalog.load_catalog()["cases"]}[aio.DECOY_CASE_ID]
        self.assertEqual(record["state"], "incubating")
        self.assertEqual(record["runs_in"], ["podman"])
        self.assertEqual(record["topology"], ["aio"])


VISION_ROUTED_SHA = "d" * 64
VISION_OTHER_SHA = "e" * 64
VISION_ROOT = "/var/www/gowave-auto-nginx/cover-reality"


def vision_contour(
    domain=topology.VISION_DOMAIN, target=aio.VISION_MAP_TARGET, listen=1,
    bound=("127.0.0.1:8444", "127.0.0.1:9444"), root=VISION_ROOT, maps=1,
):
    """The contour probe's report, in the shape it prints it.

    ``target=None`` is a host installed without the delegated name: the map it
    runs carries no entry for it, and nothing listens on either Vision port.
    """
    routes = {"default": "127.0.0.1:8443"}
    if target:
        routes[domain] = target
    return json.dumps({
        "dump_returncode": 0,
        "dump_bytes": 8192,
        "stream_maps": maps,
        "routes": routes,
        "fallback_listen": listen,
        "fallback_root": root,
        "bound": {
            port: [address for address in bound if address.rsplit(":", 1)[-1] == port]
            for port in ("8444", "9444")
        },
    }, sort_keys=True) + "\n"


def vision_answer(status="HTTP/1.1 200 OK", sha=VISION_ROUTED_SHA):
    """One raw request answered by the fallback vhost, or refused by it."""
    return json.dumps(
        {"status": status, "bytes": 1024 if sha else 0, "sha256": sha, "error": ""},
        sort_keys=True,
    ) + "\n"


def panel_cluster_document(product) -> str:
    """The cluster scope's report for this product's own combination.

    One node record with one identifier per inbound, and one host publishing
    each of them: the endpoint total and the hosts that carry it are the same
    number the route is counted against, so the document is rendered from the
    product's own arithmetic rather than written out. A fixture with its own
    numbers would stay green while that arithmetic broke.
    """
    inbounds = [f"inbound-{index}" for index in range(product.inbound_count)]
    document = {
        "login": {"status": 200},
        "cluster": {
            "nodes": {"status": 200, "records": [
                {"name": "aio-1", "uuid": "master-uuid", "inbounds": inbounds},
            ]},
            "hosts": {"status": 200, "records": [
                {"inbound": value, "nodes": ["master-uuid"]} for value in inbounds
            ]},
        },
    }
    return json.dumps(document, sort_keys=True) + "\n"


class TestVisionRouteCase(unittest.TestCase):
    """NGX-04: the delegated name's own contour, and its absence when none is configured."""

    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def reports(self, replace=None):
        """The three fetches the case makes, with single answers replaceable."""
        domain = topology.VISION_DOMAIN
        reports = [
            decoy_report(f"https://{domain}/", 200, VISION_ROUTED_SHA, [domain]),
            decoy_report(f"https://{topology.COVER_APEX}/", 200, VISION_ROUTED_SHA,
                         [topology.COVER_APEX]),
            decoy_report(f"https://{domain}/api/nodes", 404, DECOY_404_SHA, [domain]),
        ]
        for url, report in (replace or {}).items():
            for index, existing in enumerate(reports):
                if existing["probe"]["url"] == url:
                    reports[index] = report
                    break
            else:
                raise AssertionError(f"the case never asks for {url}")
        return reports

    def product(self, contour=None, proxied=None, bare=None, reports=None, enabled=True):
        product, podman = installed_product(self.context, [
            (contour if contour is not None else vision_contour(), 0),
            (proxied if proxied is not None else vision_answer(), 0),
            (bare if bare is not None
             else vision_answer("HTTP/1.1 400 Bad Request", ""), 0),
        ])
        product.vision = enabled
        product.host.client_reports = list(self.reports() if reports is None else reports)
        podman.panel_cluster = panel_cluster_document(product)
        return product, podman

    def reject(self, expected, **kwargs):
        product, _podman = self.product(**kwargs)
        with self.assertRaises(AssertionError) as caught:
            aio.case_vision_route(product)
        self.assertIn(expected, str(caught.exception))
        return caught

    def test_the_contour_routes_the_name_and_the_fallback_needs_the_proxy_header(self):
        product, podman = self.product()
        evidence = aio.case_vision_route(product)
        self.assertEqual(evidence["combination"], "enabled")
        self.assertEqual(evidence["vision_domain"], topology.VISION_DOMAIN)
        self.assertEqual(evidence["routes"][topology.VISION_DOMAIN], aio.VISION_MAP_TARGET)
        self.assertEqual(evidence["bound"]["8444"], ["127.0.0.1:8444"])
        self.assertEqual(evidence["bound"]["9444"], ["127.0.0.1:9444"])
        self.assertEqual(evidence["fallback_listen"], 1)
        self.assertEqual(evidence["fallback_root"], VISION_ROOT)
        self.assertEqual(evidence["route_status"], 200)
        self.assertEqual(evidence["route_san"], [topology.VISION_DOMAIN])
        self.assertEqual(evidence["route_sha256"], VISION_ROUTED_SHA)
        self.assertEqual(evidence["proxied_status"], "HTTP/1.1 200 OK")
        self.assertEqual(evidence["proxied_sha256"], VISION_ROUTED_SHA)
        self.assertEqual(evidence["bare_status"], "HTTP/1.1 400 Bad Request")
        self.assertEqual(evidence["bare_sha256"], "")
        self.assertEqual(evidence["decoy_sha256"], VISION_ROUTED_SHA)
        self.assertEqual(evidence["management_status"], 404)
        self.assertEqual(len(podman.scripts), 4)
        self.assertIn(aio.VISION_FALLBACK_LISTEN, podman.scripts[0])
        self.assertIn("ss", podman.scripts[0])
        for script in podman.scripts[:3]:
            self.assertIn(topology.VISION_DOMAIN, script)
        self.assertIn("--scope cluster", podman.scripts[3])
        self.assertIn("PROXY TCP4", podman.scripts[1])
        self.assertEqual(
            podman.scripts[1].splitlines()[0],
            f"python3 - {topology.VISION_DOMAIN} 1 <<'PY'",
        )
        self.assertEqual(
            podman.scripts[2].splitlines()[0],
            f"python3 - {topology.VISION_DOMAIN} 0 <<'PY'",
        )

    def test_the_name_is_fetched_from_the_client_and_pinned_to_its_own_certificate(self):
        product, _podman = self.product()
        aio.case_vision_route(product)
        calls = {call["url"]: call for call in product.host.client_calls}
        route = calls[f"https://{topology.VISION_DOMAIN}/"]
        self.assertEqual(route["expect_status"], 200)
        self.assertNotIn("insecure", route)
        self.assertFalse(route.get("insecure", False))
        self.assertEqual(
            calls[f"https://{topology.VISION_DOMAIN}/api/nodes"]["expect_status"], 404,
        )

    def test_a_host_without_the_domain_owes_no_route_listener_or_vhost(self):
        product, _podman = self.product(
            contour=vision_contour(target=None, listen=0, bound=(), root=""), enabled=False,
        )
        evidence = aio.case_vision_route(product)
        self.assertEqual(evidence["combination"], "disabled")
        self.assertNotIn(topology.VISION_DOMAIN, evidence["routes"])
        self.assertEqual(evidence["bound"], {"8444": [], "9444": []})
        self.assertEqual(evidence["fallback_listen"], 0)
        self.assertEqual(product.host.client_calls, [])

    def test_a_disabled_contour_that_still_routes_the_name_is_refused(self):
        self.reject("still routes", contour=vision_contour(listen=0, bound=(), root=""),
                    enabled=False)

    def test_a_disabled_contour_that_still_listens_is_refused(self):
        self.reject("still listens on 8444", contour=vision_contour(target=None, listen=0),
                    enabled=False)

    def test_a_route_to_another_backend_is_refused(self):
        self.reject("does not reach the Vision inbound",
                    contour=vision_contour(target="127.0.0.1:8443"))

    def test_a_backend_bound_beyond_loopback_is_refused(self):
        self.reject(
            "instead of exactly 127.0.0.1:8444",
            contour=vision_contour(bound=("0.0.0.0:8444", "127.0.0.1:9444")),
        )

    def test_a_fallback_without_the_proxy_listener_is_refused(self):
        self.reject("the inbound hands over to", contour=vision_contour(listen=0, root=""))

    def test_a_fallback_that_answers_a_bare_request_is_refused(self):
        self.reject("is not enforced",
                    bare=vision_answer("HTTP/1.1 200 OK", VISION_ROUTED_SHA))

    def test_a_fallback_serving_another_document_is_refused(self):
        self.reject("do not hand out one document",
                    proxied=vision_answer(sha=VISION_OTHER_SHA))

    def test_a_certificate_that_does_not_name_the_name_is_refused(self):
        url = f"https://{topology.VISION_DOMAIN}/"
        self.reject(
            "does not name",
            reports=self.reports({url: decoy_report(
                url, 200, VISION_ROUTED_SHA, [topology.COVER_APEX],
            )}),
        )

    def test_a_route_that_does_not_serve_the_rendered_site_is_refused(self):
        url = f"https://{topology.COVER_APEX}/"
        self.reject(
            "does not hand out the camouflage site",
            reports=self.reports({url: decoy_report(
                url, 200, VISION_OTHER_SHA, [topology.COVER_APEX],
            )}),
        )

    def test_a_map_that_is_not_the_one_in_force_is_refused(self):
        self.reject("not the one deciding the traffic", contour=vision_contour(maps=2))

    def test_the_probe_reads_the_directive_argument_out_of_the_running_dump(self):
        # The dump keeps the directive's terminating semicolon, so a target read
        # verbatim is `127.0.0.1:8444;` — an address no contract can compare
        # against, and one a live run proved the contract could not. The rendered
        # script is run against a stand-in `nginx -T` so the reading is what is
        # tested, not the text of the heredoc.
        dump = (
            "stream {\n"
            "    map $ssl_preread_server_name $sni_backend {\n"
            f"        {topology.VISION_DOMAIN} 127.0.0.1:8444;\n"
            f"        {topology.COVER_APEX} 127.0.0.1:9443;\n"
            "        default 127.0.0.1:8443;\n"
            "    }\n"
            "}\n"
            "server {\n"
            f"    listen {aio.VISION_FALLBACK_LISTEN};\n"
            f"    root {VISION_ROOT};\n"
            "}\n"
        )
        sockets = (
            "LISTEN 0 511 127.0.0.1:8444 0.0.0.0:*\n"
            "LISTEN 0 511 127.0.0.1:9444 0.0.0.0:*\n"
            "LISTEN 0 511 0.0.0.0:443 0.0.0.0:*\n"
        )
        with tempfile.TemporaryDirectory() as bindir:
            for name, body in (("nginx", dump), ("ss", sockets)):
                path = Path(bindir) / name
                path.write_text(f"#!/bin/sh\ncat <<'OUT'\n{body}OUT\n", encoding="utf-8")
                path.chmod(0o755)
            script = aio.vision_contour_script(topology.VISION_DOMAIN)
            _, _, body = script.partition("<<'PY'\n")
            body = body.rsplit("\nPY\n", 1)[0]
            result = subprocess.run(
                [sys.executable, "-c", body, topology.VISION_DOMAIN],
                capture_output=True, text=True, check=False,
                env={**os.environ, "PATH": f"{bindir}:{os.environ.get('PATH', '')}"},
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        facts = json.loads(result.stdout)
        self.assertEqual(facts["routes"][topology.VISION_DOMAIN], aio.VISION_MAP_TARGET)
        self.assertEqual(facts["routes"]["default"], "127.0.0.1:8443")
        self.assertEqual(facts["stream_maps"], 1)
        self.assertEqual(facts["fallback_listen"], 1)
        self.assertEqual(facts["fallback_root"], VISION_ROOT)
        self.assertEqual(facts["bound"], {"8444": ["127.0.0.1:8444"], "9444": ["127.0.0.1:9444"]})

    def test_the_case_is_registered_before_the_reloads_and_catalogued(self):
        suite = aio.cases(ScriptedPodman(self.context, []))
        cases = {case.id: case for case in suite}
        self.assertIn(aio.VISION_ROUTE_CASE_ID, cases)
        self.assertEqual(cases[aio.VISION_ROUTE_CASE_ID].topology, "aio")
        self.assertEqual(cases[aio.VISION_ROUTE_CASE_ID].timeout_seconds,
                         aio.VISION_ROUTE_TIMEOUT_SECONDS)
        ids = [case.id for case in suite]
        self.assertLess(ids.index(aio.DECOY_CASE_ID), ids.index(aio.VISION_ROUTE_CASE_ID))
        self.assertLess(ids.index(aio.VISION_ROUTE_CASE_ID), ids.index(aio.ACME_CASE_ID))
        record = {case["id"]: case for case in catalog.load_catalog()["cases"]}[
            aio.VISION_ROUTE_CASE_ID
        ]
        self.assertEqual(record["state"], "live-parity")
        self.assertEqual(sorted(record["runs_in"]), ["live", "podman"])
        self.assertEqual(sorted(record["topology"]), ["aio", "multi-node"])
        self.assertEqual(record["driver_status"], "implemented")
        self.assertEqual(sorted(record["drivers"]), ["aio", "multi-node"])
        self.assertEqual(record["drivers"]["aio"]["driver"], "aio:case_vision_route")
        self.assertIn("proxied_sha256", record["drivers"]["aio"]["evidence"])
        self.assertEqual(record["drivers"]["multi-node"]["driver"],
                         "multi_node:case_vision_route")


class TestFaultCases(unittest.TestCase):
    """AIO-FAULT-PANEL / -XRAY / -LATENCY: the rendered probes, executed.

    Every one of these cases injects a fault on purpose, so the probe carries the
    destructive half of the case: what it reads decides whether the case may run
    at all, and what it puts back decides whether the next case measures a host
    someone broke. The commands are executed whole — heredoc and argv line
    included — because that is the line the topology runs.
    """

    UNIT_FIELDS = (
        "Id=gowave-node.service\n"
        "ActiveState=active\n"
        "SubState=running\n"
        "MainPID=411\n"
        "NRestarts=0\n"
        "ActiveEnterTimestamp=Sat 2026-11-14 01:00:00 UTC"
    )
    PANEL_STATE = {
        "env_digest": "sha256:env",
        "binary": "sha256:binary",
        "frontend": "sha256:frontend",
        "frontend_index": "sha256:index",
        "state": "sha256:state",
        "nginx": "sha256:nginx",
        "nginx_conf": "sha256:nginx.conf",
        "letsencrypt": "sha256:acme",
        "lineage_chain": "sha256:lineage",
        "database": {"integrity": "ok", "logical": "CREATE TABLE users(name TEXT);"},
        "unit": {"ActiveState": "active", "SubState": "running"},
        "health": 200,
    }

    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)
        self.workspace = Path(self.tmp.name)
        self.bin = self.workspace / "bin"
        self.bin.mkdir()
        self.log = self.workspace / "calls.log"
        self.env = dict(os.environ)
        self.env["PATH"] = f"{self.bin}:{self.env.get('PATH', '')}"

    # ------------------------------------------------------------ the helpers
    def write_shim(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        path.chmod(0o755)

    def run_script(self, script):
        return subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, env=self.env, check=False,
        )

    def calls(self):
        if not self.log.exists():
            return []
        return self.log.read_text(encoding="utf-8").splitlines()

    def systemctl_shim(self, units=()):
        listing = "".join(f"    printf '%s\\n' '{line}'\n" for line in units) or "    :\n"
        self.write_shim("systemctl", (
            f'printf "%s\\n" "$@" >> "{self.log}"\n'
            'case "$*" in\n'
            "  *list-units*)\n"
            + listing
            + "    ;;\n"
            "  *)\n"
            "    cat <<'EOF'\n"
            + self.UNIT_FIELDS
            + "\nEOF\n"
            "    ;;\n"
            "esac\n"
        ))

    def proc_tree(self, entries):
        root = self.workspace / "proc"
        root.mkdir()
        for pid, (comm, ppid, cgroup) in entries.items():
            directory = root / str(pid)
            directory.mkdir()
            (directory / "comm").write_text(comm + "\n", encoding="utf-8")
            (directory / "status").write_text(
                f"Name:\t{comm}\nPPid:\t{ppid}\n", encoding="utf-8",
            )
            (directory / "cgroup").write_text(f"0::{cgroup}\n", encoding="utf-8")
        (root / "loadavg").write_text("0.00 0.01 0.05\n", encoding="utf-8")
        return root

    def core_script(self, mode, root, timeout=0.0):
        return aio.core_fault_script(mode, timeout).replace('PROC = "/proc"', f'PROC = "{root}"')

    def core_process(self, seconds=30):
        """A process whose comm is rw-core, so the probe can find and signal it."""
        binary = self.workspace / "rw-core"
        binary.write_bytes(Path("/bin/sleep").read_bytes())
        binary.chmod(0o755)
        process = subprocess.Popen([str(binary), str(seconds)])
        self.addCleanup(lambda: (process.kill(), process.wait(10)))
        return process

    def network_tree(self, names=("eth0", "lo", "wlan0")):
        root = self.workspace / "net"
        root.mkdir()
        for name in names:
            (root / name).mkdir()
        return root

    def netem_shim(self, fail_on=""):
        failure = (
            f'if [ "$1 $2 $3 $4" = "qdisc replace dev {fail_on}" ]; then exit 1; fi\n'
            if fail_on else ""
        )
        self.write_shim("tc", (
            f'printf "%s\\n" "$*" >> "{self.log}"\n' + failure + "exit 0\n"
        ))

    # ------------------------------------------------------- the shared contract
    def test_configuration_compares_the_database_by_integrity_and_the_rest_byte_for_byte(self):
        before = dict(self.PANEL_STATE)
        moved = json.loads(json.dumps(before))
        moved["database"]["bytes"] = "sha256:checkpointed"
        aio.require_configuration_unchanged("AIO-FAULT-TEST", before, moved, "while it was down")
        moved["nginx_conf"] = "sha256:rewritten"
        with self.assertRaises(AssertionError) as caught:
            aio.require_configuration_unchanged(
                "AIO-FAULT-TEST", before, moved, "while it was down",
            )
        self.assertIn("changed the NGINX configuration", str(caught.exception))

    # ------------------------------------------------------------- core process
    def test_the_core_scan_reads_the_unit_from_the_cores_own_cgroup(self):
        self.systemctl_shim(units=(
            "xray-supervisor.service loaded active running Stray Xray",
        ))
        root = self.proc_tree({
            101: ("rw-core", 1, "/system.slice/gowave-node.service"),
            202: ("python3", 1, "/system.slice/gowave-node.service"),
            303: ("rw-core", 1, "/system.slice/other.service"),
        })
        result = self.run_script(self.core_script("scan", root))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual([item["pid"] for item in report["cores_before"]], [101, 303])
        self.assertEqual([item["in_unit"] for item in report["cores_before"]], [True, False])
        self.assertEqual(report["xray_units"], ["xray-supervisor.service"])
        self.assertEqual(report["unit_before"]["Id"], "gowave-node.service")
        self.assertIn("gowave-node.service", self.calls())

    def test_the_core_restart_signals_nothing_when_the_unit_owns_no_core(self):
        self.systemctl_shim()
        core = self.core_process()
        root = self.proc_tree({core.pid: ("rw-core", 1, "/system.slice/other.service")})
        result = self.run_script(self.core_script("restart", root, timeout=1.0))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertIn("expected exactly one core process inside gowave-node.service",
                      report["error"])
        self.assertNotIn("killed_pid", report)
        self.assertIsNone(core.poll(), "the probe signalled a core it does not supervise")

    def test_the_core_restart_kills_the_core_the_unit_owns_and_reports_what_replaced_it(self):
        self.systemctl_shim()
        core = self.core_process()
        root = self.proc_tree({core.pid: ("rw-core", 1, "/system.slice/gowave-node.service")})
        result = self.run_script(self.core_script("restart", root, timeout=1.0))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["killed_pid"], core.pid)
        self.assertEqual([item["pid"] for item in report["cores_after"]], [core.pid])
        self.assertGreaterEqual(report["restart_seconds"], 1.0)
        self.assertEqual(report["unit_after"]["NRestarts"], "0")
        # The probe is not the core's parent, so nothing can have collected it:
        # the exit is the one SIGKILL produces, against the pid the probe named.
        self.assertEqual(core.wait(timeout=10), -signal.SIGKILL)

    # ----------------------------------------------------------------- latency
    def test_the_latency_fault_delays_every_interface_but_loopback(self):
        self.netem_shim()
        root = self.network_tree()
        result = self.run_script(aio.latency_fault_apply_script().replace("/sys/class/net", str(root)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines()[0], "delayed: eth0 wlan0")
        self.assertEqual(self.calls(), [
            "qdisc replace dev eth0 root netem delay 300ms",
            "qdisc replace dev wlan0 root netem delay 300ms",
            "qdisc show",
        ])

    def test_a_latency_fault_that_fails_on_a_later_interface_removes_the_earlier_one(self):
        self.netem_shim(fail_on="wlan0")
        root = self.network_tree()
        result = self.run_script(aio.latency_fault_apply_script().replace("/sys/class/net", str(root)))
        self.assertEqual(result.returncode, 1)
        self.assertIn("latency could not be injected on wlan0", result.stderr)
        self.assertIn("qdisc del dev eth0 root", self.calls())

    def test_clearing_the_latency_leaves_no_qdisc_behind(self):
        self.netem_shim()
        root = self.network_tree()
        result = self.run_script(
            aio.LATENCY_FAULT_CLEAR_SCRIPT.strip().replace("/sys/class/net", str(root)),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines()[0], "cleared")
        self.assertEqual(self.calls(), [
            "qdisc del dev eth0 root",
            "qdisc del dev wlan0 root",
            "qdisc show",
        ])

    def test_timing_the_public_surface_reads_the_delay_the_client_feels(self):
        product, _ = installed_product(self.context, [])
        product.host.client_reports = [
            {"url": f"{aio.PUBLIC_PANEL}/", "returncode": 0, "stdout": "{}", "stderr": "",
             "probe": {"status": 200, "seconds": seconds}}
            for seconds in (0.12, 0.14, 0.13)
        ]
        samples = aio.public_latency(product, product.host, aio.LATENCY_FAULT_CASE_ID)
        self.assertEqual(samples, [0.12, 0.14, 0.13])
        self.assertEqual(len(product.host.client_calls), aio.LATENCY_FAULT_SAMPLES)

    def test_a_probe_that_reports_no_elapsed_time_cannot_time_the_fault(self):
        product, _ = installed_product(self.context, [])
        product.host.client_reports = [
            {"url": f"{aio.PUBLIC_PANEL}/", "returncode": 0, "stdout": "{}", "stderr": "",
             "probe": {"status": 200}},
        ]
        with self.assertRaises(AssertionError) as caught:
            aio.public_latency(product, product.host, aio.LATENCY_FAULT_CASE_ID)
        self.assertIn("reported no elapsed time", str(caught.exception))

    # -------------------------------------------------------------- the cases
    def test_the_panel_outage_case_fails_when_https_still_answers_with_the_unit_down(self):
        product, _ = installed_product(self.context, [
            ("inactive\n", 0),
            ("active\n", 0),
        ])
        down = json.loads(json.dumps(self.PANEL_STATE))
        down["unit"] = {"ActiveState": "inactive", "SubState": "dead"}
        down["health"] = "ConnectionRefusedError: [Errno 111] Connection refused"
        product.host.client_reports = [
            {"url": f"{aio.PUBLIC_PANEL}/", "returncode": 0, "stdout": "{}", "stderr": "",
             "probe": {"status": 200}},
        ]
        with mock.patch.object(aio, "channel_state", side_effect=[
            self.PANEL_STATE, down,
        ]), mock.patch.object(
            aio, "channel_client_surface",
            return_value={"readback_status": 200, "short_uuid_length": 4},
        ), mock.patch.object(product, "wait_tunnel_ready", return_value={}):
            with self.assertRaises(AssertionError) as caught:
                aio.case_panel_service_down(product)
        self.assertIn("expected NGINX's 502", str(caught.exception))
        self.assertIn(f"systemctl stop {aio.PANEL_SERVICE}", product.podman.scripts[0])
        # A fault case that fails half-way must still hand the host back with its
        # control plane running, or every case after it reads a dead Panel.
        self.assertIn(f"systemctl start {aio.PANEL_SERVICE}", product.podman.scripts[-1])

    def test_the_fault_cases_are_registered_before_the_idempotent_case_and_catalogued(self):
        suite = aio.cases(ScriptedPodman(self.context, []))
        cases = {case.id: case for case in suite}
        ids = [case.id for case in suite]
        for case_id, timeout in (
            (aio.PANEL_FAULT_CASE_ID, aio.PANEL_FAULT_TIMEOUT_SECONDS),
            (aio.CORE_FAULT_CASE_ID, aio.CORE_FAULT_TIMEOUT_SECONDS),
            (aio.LATENCY_FAULT_CASE_ID, aio.LATENCY_FAULT_TIMEOUT_SECONDS),
        ):
            self.assertIn(case_id, cases)
            self.assertEqual(cases[case_id].topology, "aio")
            self.assertEqual(cases[case_id].timeout_seconds, timeout)
            self.assertLess(ids.index(case_id), ids.index("AIO-IDEMPOTENT"))
        records = {case["id"]: case for case in catalog.load_catalog()["cases"]}
        for case_id in (
            aio.PANEL_FAULT_CASE_ID, aio.CORE_FAULT_CASE_ID, aio.LATENCY_FAULT_CASE_ID,
        ):
            self.assertEqual(records[case_id]["state"], "incubating")
            self.assertEqual(records[case_id]["runs_in"], ["podman"])
            self.assertEqual(records[case_id]["topology"], ["aio"])


CLIENT_ADDRESS = "198.51.100.7"
OTHER_SOURCE = "203.0.113.9"


def packet_summary(captured=3, source=CLIENT_ADDRESS, stopped_by="harness", drops=0):
    return {
        "captured": captured, "sources": {source: captured},
        "stopped_by": stopped_by, "drops": drops, "port": 443, "seconds": 4.0,
    }


class TestPacketEvidenceCase(unittest.TestCase):
    """AIO-PKT-02: each way the packet evidence is missing has to say INCOMPLETE.

    The bracket is `tests/test_podman_ingress.py`; what this class holds is the
    case built on it — that every degradation reaches the verdict through the
    real `evaluate`, that a missing attribution is never read off a count, and
    that a capture file left on the host is refused.
    """

    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def _measurement(self, request, inbound, *, identity_error="", captures=None,
                     capture_errors=None, client=CLIENT_ADDRESS, identity_engine=""):
        return ingress.Measurement(
            port=ingress.listener_port(inbound),
            intended="local",
            client="" if identity_error else client,
            captures=captures if captures is not None else {"local": packet_summary()},
            capture_errors=capture_errors or {},
            identity_error=identity_error,
            request=request(),
        )

    def _bracket(self, inbound, overrides=None):
        """The four degradations the case produces, keyed by how it asks for them."""

        def bracket(request, inbound, node="", window=ingress.CAPTURE_WINDOW_SECONDS, *,
                    intended="", identity_port=ingress.IDENTITY_PORT,
                    probe_script=ingress.PROBE_SCRIPT, identity_engine=""):
            key = "foreign_source_only" if identity_engine else ""
            if probe_script != ingress.PROBE_SCRIPT:
                key = "no_capture_tool"
            elif identity_port != ingress.IDENTITY_PORT:
                key = "no_identity"
            elif window != ingress.CAPTURE_WINDOW_SECONDS:
                key = "window_expired"
            if overrides and key in overrides:
                return overrides[key](request, inbound)
            shapes = {
                "no_capture_tool": dict(
                    captures={},
                    capture_errors={"local": "no_probe_summary: python3 exited at once"},
                ),
                "no_identity": dict(
                    identity_error="no_identity_connection",
                    captures={"local": packet_summary()},
                ),
                "window_expired": dict(
                    captures={"local": packet_summary(captured=5, stopped_by="window")},
                ),
                "foreign_source_only": dict(
                    captures={"local": packet_summary(captured=4, source=OTHER_SOURCE)},
                ),
            }
            return self._measurement(request, inbound, **shapes[key])

        return bracket

    def _product(self, findings="", overrides=None):
        product, podman = installed_product(self.context, [])
        inbound = matrix.inbound(matrix.load(), "REALITY")
        product.host.client_name = "aio-client"
        product.transfer_facts = lambda *args, **kwargs: {
            "status": 200, "source_ip": "10.0.0.2",
        }
        product.bracket_request = self._bracket(inbound, overrides)
        product.host.podman = podman
        podman.find_output = findings
        return product

    def test_every_degradation_is_incomplete_with_a_reason(self):
        evidence = aio.case_packet_evidence_incomplete(self._product())
        self.assertEqual(
            evidence["degradations"],
            "foreign_source_only,no_capture_tool,no_identity,window_expired",
        )
        self.assertEqual(evidence["verdicts"], ",".join(["INCOMPLETE"] * 4))
        for key in ("no_capture_tool_reason", "no_identity_reason",
                    "window_expired_reason", "foreign_source_reason"):
            self.assertTrue(evidence[key], f"{key} names nothing that was missing")

    def test_a_missing_tool_is_incomplete_with_no_count_to_fall_back_on(self):
        evidence = aio.case_packet_evidence_incomplete(self._product())
        self.assertEqual(evidence["tool_less_captured"], 0)
        self.assertEqual(evidence["persisted_files"], "")

    def test_a_tool_less_run_that_counted_is_refused(self):
        """The missing-tool branch is the case only when nothing was counted.

        A capture tool that is not there cannot count segments, so a run filed
        under that name which did count is some other run — and a case that
        accepted it would be reporting a degradation it never produced.
        """
        inbound = matrix.inbound(matrix.load(), "REALITY")

        def counted_anyway(request, inbound):
            return self._measurement(
                request, inbound,
                captures={"local": packet_summary(captured=4, drops=3)},
            )

        product = self._product(overrides={"no_capture_tool": counted_anyway})
        with self.assertRaises(AssertionError) as caught:
            aio.case_packet_evidence_incomplete(product)
        self.assertIn("the tool-missing run counted 4 segment(s)", str(caught.exception))

    def test_a_wrong_vantage_run_without_a_vantage_is_refused(self):
        """An address that differs means nothing unless the host reported one."""
        inbound = matrix.inbound(matrix.load(), "REALITY")

        def no_identity(request, inbound):
            return self._measurement(
                request, inbound, identity_error="no_identity_connection",
                captures={"local": packet_summary(captured=4, source=OTHER_SOURCE)},
            )

        product = self._product(overrides={"foreign_source_only": no_identity})
        with self.assertRaises(AssertionError) as caught:
            aio.case_packet_evidence_incomplete(product)
        self.assertIn("could not identify the client at all", str(caught.exception))

    def test_a_wrong_vantage_run_that_saw_no_foreign_address_is_refused(self):
        inbound = matrix.inbound(matrix.load(), "REALITY")

        def saw_only_the_client(request, inbound):
            return self._measurement(
                request, inbound, captures={"local": packet_summary(captured=3, drops=2)},
            )

        product = self._product(overrides={"foreign_source_only": saw_only_the_client})
        with self.assertRaises(AssertionError) as caught:
            aio.case_packet_evidence_incomplete(product)
        self.assertIn("recorded no non-matching source address", str(caught.exception))

    def test_an_incomplete_without_a_reason_is_refused(self):
        """INCOMPLETE has to name what was missing, or the verdict is a shrug."""
        shapeless = {
            "verdict": ingress.INCOMPLETE, "reason": "", "intended_captured": 0,
            "intended_matched": 0, "foreign": "",
        }
        with mock.patch.object(ingress, "evaluate", return_value=dict(shapeless)):
            with self.assertRaises(AssertionError) as caught:
                aio.case_packet_evidence_incomplete(self._product())
        self.assertIn("is INCOMPLETE without naming what was missing", str(caught.exception))

    def test_the_foreign_source_is_recorded_rather_than_assumed(self):
        evidence = aio.case_packet_evidence_incomplete(self._product())
        self.assertEqual(evidence["foreign_sources"], f"{OTHER_SOURCE}:4")

    def test_a_degradation_that_came_back_pass_is_refused(self):
        inbound = matrix.inbound(matrix.load(), "REALITY")
        pass_shape = lambda request, inbound: self._measurement(request, inbound)  # noqa: E731
        product = self._product(overrides={"no_identity": pass_shape})
        with self.assertRaises(AssertionError) as caught:
            aio.case_packet_evidence_incomplete(product)
        self.assertIn("the no_identity run came back PASS", str(caught.exception))

    def test_a_degradation_that_never_made_its_request_is_refused(self):
        inbound = matrix.inbound(matrix.load(), "REALITY")

        def no_request(request, inbound):
            measurement = self._measurement(request, inbound)
            measurement.request = None
            return measurement

        # A run that measured nothing would report the evidence it never armed as
        # the reason, which blames the instrument for a transfer that never ran.
        product = self._product(overrides={"window_expired": no_request})
        with self.assertRaises(AssertionError) as caught:
            aio.case_packet_evidence_incomplete(product)
        self.assertIn("the window_expired run never completed its request", str(caught.exception))

    def test_a_capture_file_left_on_the_host_is_refused(self):
        product = self._product(findings="/tmp/gowave-e2e-ingress.pcap\n")
        with self.assertRaises(AssertionError) as caught:
            aio.case_packet_evidence_incomplete(product)
        self.assertIn("packet evidence is reported, never persisted", str(caught.exception))

    def test_the_case_is_registered_after_the_matrix_case(self):
        suite = aio.cases(ScriptedPodman(self.context, []))
        cases = {case.id: case for case in suite}
        ids = [case.id for case in suite]
        self.assertIn(aio.PKT_INCOMPLETE_CASE_ID, cases)
        self.assertEqual(cases[aio.PKT_INCOMPLETE_CASE_ID].topology, "aio")
        self.assertEqual(
            cases[aio.PKT_INCOMPLETE_CASE_ID].timeout_seconds, aio.PKT_INCOMPLETE_TIMEOUT_SECONDS,
        )
        self.assertLess(ids.index("AIO-MATRIX"), ids.index(aio.PKT_INCOMPLETE_CASE_ID))



DUMP_PASSWORD = "e2e-admin-password-0123456789"
DUMP_TOKEN = "e2e-scoped-token-0123456789"
# The dump a careless diagnostic takes: the stat line the product's own hardening
# reads, then the file exactly as the installer wrote it. The field names come
# from the module under test, so this fixture cannot drift from the fields the
# case withholds.
CREDENTIALS_DUMP = (
    "mode=600\n"
    "owner=0\n"
    "type=regular file\n"
    "--file--\n"
    "# GoWave Auto NGINX Administrative Credentials\n"
    "# Generated at 2026-11-17T09:00:00Z\n"
    "PANEL_URL=https://panel.testbed.internal\n"
    f"{aio.CREDENTIAL_FIELDS[0]}=admin\n"
    f"{aio.CREDENTIAL_FIELDS[1]}={DUMP_PASSWORD}\n"
    f"{aio.CREDENTIAL_FIELDS[2]}={DUMP_TOKEN}\n"
)


class TestRedactedCredentialsCase(unittest.TestCase):
    """RED-01: the credentials file reaches an artifact as names, never values."""

    def setUp(self):
        from tools.live_vps.redaction import clear_secrets

        clear_secrets()
        self.addCleanup(clear_secrets)
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def run_case(self, dump=CREDENTIALS_DUMP, returncode=0):
        product, _ = installed_product(self.context, [(dump, returncode)])
        return aio.case_redacted_credentials(product)

    def reject(self, *expected, **kwargs):
        with self.assertRaises(AssertionError) as caught:
            self.run_case(**kwargs)
        message = str(caught.exception)
        # A refusal names the field or the file, never the value: a case that
        # quoted what it was withholding would leak it into result.json.
        self.assertNotIn(DUMP_PASSWORD, message)
        self.assertNotIn(DUMP_TOKEN, message)
        for fragment in expected:
            self.assertIn(fragment, message)

    def test_the_names_survive_and_both_values_are_redacted(self):
        evidence = self.run_case()
        self.assertEqual(evidence["file_mode"], "600")
        self.assertEqual(evidence["file_owner"], "0")
        self.assertEqual(evidence["file_type"], "regular file")
        self.assertEqual(evidence["credential_fields"], ",".join(aio.CREDENTIAL_FIELDS))
        self.assertEqual(evidence["redacted_markers"], 2)
        self.assertEqual(evidence["audit_offences"], 0)
        self.assertGreaterEqual(evidence["audited_files"], 1)
        written = (
            self.context.artifact_dir / "evidence" / "diagnostics" / aio.REDACTION_CASE_ID
            / "credentials.txt"
        ).read_text(encoding="utf-8")
        for name in aio.CREDENTIAL_FIELDS:
            self.assertIn(name, written)
        for secret in (DUMP_PASSWORD, DUMP_TOKEN):
            self.assertNotIn(secret, written)
        self.assertEqual(written.count("[REDACTED]"), 2)
        for secret in (DUMP_PASSWORD, DUMP_TOKEN):
            self.assertNotIn(secret, json.dumps(evidence))

    def test_a_file_anyone_could_read_fails_before_its_contents_are_withheld(self):
        self.reject("is mode '644', not 600", dump=CREDENTIALS_DUMP.replace("mode=600", "mode=644"))

    def test_a_symlink_is_not_the_file_the_installer_wrote(self):
        self.reject("'symbolic link', not a regular file",
                    dump=CREDENTIALS_DUMP.replace("type=regular file", "type=symbolic link"))

    def test_a_missing_field_is_named_and_its_value_is_not(self):
        dump = "".join(
            line for line in CREDENTIALS_DUMP.splitlines(True)
            if not line.startswith(f"{aio.CREDENTIAL_FIELDS[2]}=")
        )
        self.reject(f"does not name {aio.CREDENTIAL_FIELDS[2]}", dump=dump)

    def test_an_unreadable_file_fails_with_the_probe_code(self):
        self.reject("the credentials probe exited 3", dump="unreadable\n", returncode=3)

    def test_a_writer_that_does_not_redact_is_caught(self):
        class Unredacted:
            def __init__(self, artifact_dir):
                self.artifact_dir = artifact_dir

            def evidence_text(self, name, text):
                path = self.artifact_dir / "evidence" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
                return path

        product, _ = installed_product(self.context, [(CREDENTIALS_DUMP, 0)])
        product.context = Unredacted(self.context.artifact_dir)
        with self.assertRaises(AssertionError) as caught:
            aio.case_redacted_credentials(product)
        self.assertIn("kept the credentials text unchanged", str(caught.exception))

    def test_a_sibling_artifact_that_still_holds_the_password_fails_the_case(self):
        leak = self.context.artifact_dir / "evidence" / "leak.txt"
        leak.parent.mkdir(parents=True, exist_ok=True)
        leak.write_text(f"password={DUMP_PASSWORD}\n", encoding="utf-8")
        self.reject("artifacts that change when redacted: evidence/leak.txt")

    def test_both_halves_are_registered_before_the_channel_switch(self):
        suite = aio.cases(ScriptedPodman(self.context, []))
        cases = {case.id: case for case in suite}
        ids = [case.id for case in suite]
        self.assertEqual(cases[aio.REDACTION_CASE_ID].topology, "aio")
        self.assertEqual(cases[aio.DIAGNOSTICS_CASE_ID].topology, "aio")
        self.assertEqual(cases[aio.DIAGNOSTICS_CASE_ID].timeout_seconds,
                         aio.DIAGNOSTICS_TIMEOUT_SECONDS)
        self.assertLess(ids.index(aio.REDACTION_CASE_ID), ids.index(aio.DIAGNOSTICS_CASE_ID))
        self.assertLess(ids.index(aio.DIAGNOSTICS_CASE_ID), ids.index(aio.CHANNEL_NOOP_CASE_ID))


# What each area probe prints on a healthy host, keyed by a fragment of the probe
# that asks for it. Every value is the tool's own text, because the case asks for
# the words the tool prints rather than for words the harness could invent.
BUNDLE_AREA_OUTPUT = {
    "== operating system ==": (
        "Linux aio-1 6.8.0-45-generic #45-Ubuntu SMP x86_64 GNU/Linux\n"
        'NAME="Ubuntu"\nVERSION_ID="24.04"\nID=ubuntu\n'
        "nginx=1.24.0-2ubuntu7.3\nfail2ban=1.0.2-3ubuntu0.1\n"
    ),
    "is-active: ": "gowave\nis-active: active\nis-enabled: enabled\nActiveState=active\n",
    'journalctl -q -u "$unit"': (
        "2026-11-17T09:00:00+0000 aio-1 systemd[1]: Started GoWave Panel.\n"
    ),
    "ss -ltnup": (
        "LISTEN 0 511 0.0.0.0:443 0.0.0.0:*\n"
        "-P INPUT ACCEPT\nStatus: active\n"
    ),
    "openssl x509": (
        "subject=CN = panel.testbed.internal\nnotAfter=Feb 15 10:00:00 2027 GMT\n"
    ),
    "resolvectl status": "Link 2 (eth0): panel.testbed.internal\n",
    "== client engines ==": "xray 26.11.9\n",
    "nginx -t": (
        "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\n"
        "nginx: configuration file /etc/nginx/nginx.conf test is successful\n"
    ),
}


class BundlePodman:
    """Podman stub whose probes answer per area, so the bundle is a real bundle."""

    def __init__(self, context, override=None, raising=None):
        self.context = context
        self.override = override or {}
        self.raising = raising or {}
        self.scripts = []

    def run_containers(self):
        return [{"name": "aio-1", "state": "running"}]

    def exec_bash(self, name, script, check=False, timeout=0):
        self.scripts.append(script)
        if name in self.raising:
            raise self.raising[name]
        for marker, output in {**BUNDLE_AREA_OUTPUT, **self.override}.items():
            if marker in script:
                return subprocess.CompletedProcess(["bash", "-lc", script], 0, output, "")
        return subprocess.CompletedProcess(["bash", "-lc", script], 0, "unknown probe", "")


class TestDiagnosticArtifactsCase(unittest.TestCase):
    """RED-02: the bundle a failure leaves behind carries the fields it names."""

    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def run_case(self, **overrides):
        product = aio.AioProduct(BundlePodman(self.context, override=overrides))
        return aio.case_diagnostic_artifacts(product)

    def reject(self, *expected, **overrides):
        with self.assertRaises(AssertionError) as caught:
            self.run_case(**overrides)
        for fragment in expected:
            self.assertIn(fragment, str(caught.exception))

    def read(self, area):
        return (
            self.context.artifact_dir / "evidence" / "diagnostics" / aio.DIAGNOSTICS_CASE_ID
            / f"{area}.txt"
        ).read_text(encoding="utf-8")

    def test_every_area_carries_the_field_the_requirement_names(self):
        evidence = self.run_case()
        self.assertEqual(evidence["files"], len(aio.diagnostics.AREAS) + 1)
        self.assertEqual(evidence["required_fields"], len(aio.DIAGNOSTIC_REQUIRED_FIELDS))
        self.assertEqual(evidence["private_key_files"], 0)
        self.assertEqual(evidence["file_mode"], "0600")
        self.assertTrue(evidence["bundle_seconds"].endswith("s"))
        for area in (item.name for item in aio.diagnostics.AREAS):
            self.assertIn("[bundle complete: 1 container(s) probed]", self.read(area))

    def test_a_bundle_without_the_kernel_line_is_refused(self):
        self.reject("the operator file does not carry the kernel",
                    **{"== operating system ==": 'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\n'})

    def test_a_bundle_without_an_installed_package_version_is_refused(self):
        self.reject("the operator file does not carry the package version",
                    **{"== operating system ==": "Linux aio-1 6.8.0 x86_64\nID=ubuntu\n"
                                                   'VERSION_ID="24.04"\n'})

    def test_a_bundle_without_a_unit_state_is_refused(self):
        self.reject("the service file does not carry the unit state",
                    **{"is-active: ": "gowave\nunknown\n"})

    def test_a_bundle_without_a_firewall_verdict_is_refused(self):
        self.reject("the network file does not carry the firewall verdict",
                    **{"ss -ltnup": "LISTEN 0 511 0.0.0.0:443 0.0.0.0:*\n-P INPUT ACCEPT\n"})

    def test_a_bundle_without_certificate_metadata_is_refused(self):
        self.reject("the tls file does not carry the certificate subject",
                    **{"openssl x509": "notAfter=Feb 15 10:00:00 2027 GMT\n"})

    def test_a_bundle_without_the_vhost_test_verdict_is_refused(self):
        self.reject("the endpoint file does not carry the vhost test verdict",
                    **{"nginx -t": "nginx: the configuration file /etc/nginx/nginx.conf "
                                   "syntax is ok\n"})

    def test_private_key_material_in_the_bundle_fails_the_case(self):
        self.reject("tls.txt carries private key material",
                    **{"openssl x509": "-----BEGIN PRIVATE KEY-----\nMIIE\n"
                                       "subject=CN = panel.testbed.internal\n"
                                       "notAfter=Feb 15 10:00:00 2027 GMT\n"})

    def test_a_bundle_written_world_readable_fails_the_case(self):
        class WorldReadable:
            def __init__(self, inner):
                self.inner = inner
                self.artifact_dir = inner.artifact_dir
                self.topology = inner.topology

            def evidence_text(self, name, text):
                path = self.inner.evidence_text(name, text)
                path.chmod(0o644)
                return path

        product = aio.AioProduct(BundlePodman(self.context))
        product.context = WorldReadable(self.context)
        with self.assertRaises(AssertionError) as caught:
            aio.case_diagnostic_artifacts(product)
        self.assertIn("is mode 0o644, not 0o600", str(caught.exception))

    def test_a_probe_that_cannot_run_is_reported_rather_than_passing_empty(self):
        product = aio.AioProduct(BundlePodman(
            self.context, raising={"aio-1": TimeoutError("podman exec did not answer")},
        ))
        with self.assertRaises(AssertionError) as caught:
            aio.case_diagnostic_artifacts(product)
        self.assertIn("the operator file does not carry the kernel", str(caught.exception))
        self.assertIn("[probe could not run: TimeoutError", self.read("operator"))


if __name__ == "__main__":
    unittest.main()
