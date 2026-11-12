#!/usr/bin/env python3
"""Suite nonroot: the All-in-One suite installs once with the real operator."""
import io
import json
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import aio, catalog, panel_surface, target_image, topology  # noqa: E402
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
        self.assertEqual(evidence["host_count"], aio.CORE_INBOUNDS)
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
            for index in range(aio.CORE_INBOUNDS)
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
        self.assertEqual(surface["nodes"]["inbound_count"], aio.CORE_INBOUNDS)
        self.assertEqual(surface["profiles"]["inbound_digest"], surface["nodes"]["inbound_digest"])
        self.assertEqual(surface["squads"]["mvp_inbound_digest"],
                         surface["profiles"]["inbound_digest"])
        self.assertEqual(surface["hosts"]["count"], aio.CORE_INBOUNDS)
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


if __name__ == "__main__":
    unittest.main()
