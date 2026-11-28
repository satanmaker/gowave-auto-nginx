#!/usr/bin/env python3
"""Suite nonroot: the Panel-only suite installs once and proves the absent plane."""
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import (  # noqa: E402
    aio,
    catalog,
    matrix,
    panel_only,
    topology,
)
from tools.podman_e2e.runner import CaseBlocked, RunContext  # noqa: E402

SQUAD_UUID = "3f6c1d9a-7b2e-4c58-9f10-2a4d6e8b0c13"
STATE_SECTIONS = ("unit", "listeners", "processes", "binaries", "credentials", "lineages", "nginx")


def certificate_day(days: float = 0) -> str:
    """A certificate time relative to now, in the form the peer report carries."""
    return format_datetime(datetime.now(timezone.utc) + timedelta(days=days))


def tls_report(
    domain=topology.PANEL_DOMAIN, status=200, san=None, version="TLSv1.3",
    issuer="CN=Pebble Intermediate CA", returncode=0, error="",
):
    """One independent-client handshake report, as the probe prints it."""
    peer = {
        "san": [domain] if san is None else list(san),
        "tls_version": version,
        "cipher": "TLS_AES_256_GCM_SHA384",
        "issuer": issuer,
        "not_before": certificate_day(-30),
        "not_after": certificate_day(60),
    }
    probe = {"url": f"https://{domain}/", "status": status, "peer": peer}
    if error:
        probe["error"] = error
    return {"returncode": returncode, "probe": probe, "stdout": json.dumps(probe), "stderr": ""}


def decoy_report(
    url, status=200, san=(), snippet="<html><body>welcome</body></html>", returncode=0, error="",
):
    """One fetch of the static camouflage site, in the shape the probe prints it."""
    probe = {
        "url": url,
        "status": status,
        "body_length": len(snippet),
        "body_snippet": snippet,
        "peer": {"san": list(san), "tls_version": "TLSv1.3", "issuer": "CN=Pebble Intermediate CA"},
    }
    if error:
        probe["error"] = error
    return {"returncode": returncode, "probe": probe, "stdout": json.dumps(probe), "stderr": ""}


def host_shape_output(
    states="active active active", unit="0",
    listeners=("0.0.0.0:443", "127.0.0.1:3000"), processes="0", binaries=(),
    credentials=("600 root root", "3"), lineages=None,
    nginx=("nginx: configuration file /etc/nginx/nginx.conf test is successful", "nginx_t=0"),
):
    """The host-shape probe's own sections, with any single row replaceable."""
    if lineages is None:
        lineages = sorted([topology.PANEL_DOMAIN, topology.REALITY_DOMAIN])
    parts = [states]
    for name, rows in (
        ("unit", (unit,)),
        ("listeners", listeners),
        ("processes", (processes,)),
        ("binaries", binaries),
        ("credentials", credentials),
        ("lineages", lineages),
        ("nginx", nginx),
    ):
        parts.append(f"=={name}")
        parts.extend(rows)
    return "\n".join(parts) + "\n"


def installed_version_report(panel=None):
    """The installed-version probe, pinned to the version the matrix configures."""
    pin = str(matrix.product(matrix.load()).get("panel_version", ""))
    reported = "1.0.0" if pin.strip().lower() in ("", "latest") else pin.lstrip("vV")
    return json.dumps({
        "panel": {
            "binary": "/opt/gowave/gowave-server",
            "argv": "/opt/gowave/gowave-server --version",
            "returncode": 0,
            "stdout": f"GoWave Server v{reported if panel is None else panel}",
            "stderr": "",
        },
    })


def surface_facts(**overrides):
    """The Panel surface probe for a Panel-only install, with facts replaceable."""
    facts = {
        "login": {"status": 200, "token_present": True, "token_length": 64},
        "surface": {
            "hosts": {"status": 200, "count": 0},
            "nodes": {"status": 200, "count": 0},
            "profiles": {"status": 200, "count": 0},
            "squads": {"status": 200, "count": 0},
            "tokens": {"status": 200, "count": 1},
            "default_user": {"status": 200, "short_uuid_length": 16},
        },
    }
    for path, value in overrides.items():
        target = facts
        *parents, leaf = path.split(".")
        for name in parents:
            target = target[name]
        target[leaf] = value
    return json.dumps(facts)


def state_facts(**overrides):
    """What a Panel-only install leaves in ``state.json``, with keys replaceable."""
    facts = {
        "schema_version": 2,
        "installation_mode": "panel-only",
        "nodes_is_list": True,
        "node_count": 0,
        "local_node_keys": [],
        "state_keys": ["installationMode", "nodes", "schemaVersion"],
    }
    facts.update(overrides)
    return json.dumps(facts)


def squad_facts(**overrides):
    """The squad probe after the first registration, with facts replaceable."""
    facts = {
        "state_squad_present": True,
        "state_squad_length": len(SQUAD_UUID),
        "nodes_in_state": 1,
        "hosts_status": 200,
        "host_count": 1,
        "host_squad_entries": [1],
        "host_squad_modes": ["ALLOW_ONLY"],
        "hosts_with_null_squad": 0,
        "hosts_without_squad": 0,
        "hosts_naming_state_squad": 1,
        "squads_status": 200,
        "squad_count": 1,
        "mvp_squad_present": True,
        "mvp_squad_inbound_count": 4,
        "nodes_status": 200,
        "panel_node_count": 1,
        "panel_node_names": [topology.WORKER_NODE_NAME],
    }
    facts.update(overrides)
    return json.dumps(facts)


def refused_facts(**overrides):
    """The refusal probe, in the branch where the Panel refuses the null squad."""
    facts = {
        "squad_present": True,
        "hosts_before": 1,
        "control_status": 201,
        "control_created": True,
        "hosts_after_control": 2,
        "delete_status": 204,
        "hosts_after_delete": 1,
        "refused_status": 422,
        "refused_created": False,
        "refused_body_keys": ["message"],
        "hosts_after_refused": 1,
        "accepted_squad_entries": 0,
        "accepted_squad_nulls": 0,
        "accepted_naming_state_squad": 0,
        "refused_cleanup_status": None,
        "hosts_after_refused_cleanup": 1,
    }
    facts.update(overrides)
    return json.dumps(facts)


def make_context():
    tmp = tempfile.TemporaryDirectory()
    context = RunContext(
        topology="panel-only",
        artifact_root=Path(tmp.name),
        budget_seconds=900,
        run_id="podman-panel-only-test-00000000",
    )
    return context, tmp


class FakePodman:
    """Podman stub that returns prepared host-script results in order."""

    def __init__(self, context, results=(), version_report=None):
        self.context = context
        self.results = list(results)
        self.version_report = version_report
        self.scripts = []
        self.execs = []
        # Overrides the resolution the probe reports for the refusal case's
        # Panel name, so a test can take the case's premise out of force.
        self.resolution_report = None
        # A probe the container could not finish: there is no report to read, so
        # the case fails instead of judging a premise it never measured.
        self.probe_returncode = 0

    def exec_bash(self, name, script, check=True, input_text=None, timeout=300):
        self.scripts.append(script)
        if script == aio.INSTALLED_VERSION_SCRIPT:
            report = self.version_report or installed_version_report()
            return subprocess.CompletedProcess(["bash", "-lc", script], 0, report, "")
        if aio.ADD_NODE_REFUSED_PROBE_MARKER in script:
            return subprocess.CompletedProcess(
                ["bash", "-lc", script], self.probe_returncode,
                self.resolution_report or refused_resolution_report(), "",
            )
        stdout, returncode = self.results.pop(0)
        return subprocess.CompletedProcess(["bash", "-lc", script], returncode, stdout, "")

    def exec(self, name, argv, check=True, input_text=None, timeout=300):
        self.execs.append((name, list(argv)))
        return subprocess.CompletedProcess(list(argv), 0, "", "")


class PanelOnlyHost:
    """The disposable host, without containers, for the install and its probes."""

    def __init__(self, install_returncode=0, install_output="panel-only install ok\n"):
        self.target_name = "panel-only-1"
        self.panel_domain = topology.PANEL_DOMAIN
        self.reality_domain = topology.REALITY_DOMAIN
        self.install_returncode = install_returncode
        self.install_output = install_output
        self.install_attempts = 0
        self.trust_pins = 0
        self.node_add_attempts = 0
        self.node_add_returncode = 0
        self.client_reports = []
        self.client_calls = []

    def create(self):
        return self

    def require_roles(self):
        return None

    def install_script(self):
        return (
            f"bash /repo/gowave-auto.sh install --panel-only '{self.panel_domain}' "
            f"'{self.reality_domain}' 'e2e@testbed.internal'"
        )

    def install(self):
        self.install_attempts += 1
        return topology.InstallOutcome(
            self.install_returncode, self.install_output, "", 1.0, self.install_script(),
        )

    def reinstall(self):
        return self.install()

    def evidence(self, outcome):
        return {
            "installation_mode": "panel-only",
            "install_returncode": outcome.returncode,
            "install_command": outcome.command,
            "target_container": self.target_name,
        }

    def pin_worker_trust(self):
        self.trust_pins += 1
        return {"worker": topology.WORKER_NODE_NAME, "pinned": True}

    def node_add(self):
        self.node_add_attempts += 1
        return topology.InstallOutcome(
            self.node_add_returncode, "worker added\n", "", 2.0,
            f"bash /repo/gowave-auto.sh node add '{topology.WORKER_NODE_NAME}'",
        )

    def client_http(self, url, **kwargs):
        self.client_calls.append({"url": url, **kwargs})
        return self.client_reports.pop(0)


def installed(context, results=(), host=None):
    """A product whose install already succeeded, for the per-case probes."""
    host = host or PanelOnlyHost()
    product = panel_only.PanelOnlyProduct(FakePodman(context, results))
    product.host = host
    product.outcome = topology.InstallOutcome(0, "panel-only install ok\n", "", 1.0, host.install_script())
    product.node_add_outcome = None
    return product, host, product.podman


class TestPanelOnlySuite(unittest.TestCase):
    """The suite is the declaration: five ids, one install, one registration."""

    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def test_the_suite_declares_the_cases_in_run_order(self):
        suite = panel_only.cases(FakePodman(self.context))
        self.assertEqual(
            [case.id for case in suite],
            ["PO-INSTALL", "PO-HOST", "PO-FIREWALL", "PO-API", "PO-SQUAD",
             "PO-SQUAD-REFUSED", "MN-ADD-NODE-REFUSED"],
        )
        self.assertEqual({case.topology for case in suite}, {"panel-only"})
        self.assertEqual(
            [case.id for case in suite if case.id == panel_only.INSTALL_CASE_ID],
            [panel_only.INSTALL_CASE_ID],
            "the install case is declared once, and it is the host every later case reads",
        )

    def test_the_registration_is_declared_once_and_after_both_read_only_shapes(self):
        ids = [case.id for case in panel_only.cases(FakePodman(self.context))]
        self.assertEqual(ids.count(panel_only.SQUAD_CASE_ID), 1)
        self.assertLess(ids.index(panel_only.HOST_CASE_ID), ids.index(panel_only.SQUAD_CASE_ID))
        self.assertLess(ids.index(panel_only.API_CASE_ID), ids.index(panel_only.SQUAD_CASE_ID))
        self.assertLess(ids.index(panel_only.SQUAD_CASE_ID), ids.index(panel_only.SQUAD_REFUSED_CASE_ID))

    def test_the_registration_is_budgeted_at_least_as_much_as_the_install(self):
        by_id = {case.id: case for case in panel_only.cases(FakePodman(self.context))}
        self.assertEqual(by_id["PO-INSTALL"].timeout_seconds, panel_only.INSTALL_TIMEOUT_SECONDS)
        self.assertEqual(by_id["PO-SQUAD"].timeout_seconds, panel_only.REGISTRATION_TIMEOUT_SECONDS)
        self.assertGreaterEqual(
            by_id["PO-SQUAD"].timeout_seconds, panel_only.INSTALL_TIMEOUT_SECONDS,
            "a registration deploys a whole Worker over SSH and cannot be cheaper than the install",
        )

    def test_the_install_runs_the_operator_panel_only_command_once(self):
        host = PanelOnlyHost()
        with mock.patch.object(panel_only.topology, "PanelOnlyTopology", lambda *a, **k: host):
            product = panel_only.PanelOnlyProduct(FakePodman(self.context))
            record = product.install()
        self.assertEqual(host.install_attempts, 1)
        self.assertIn("install --panel-only", host.install_script())
        self.assertEqual(record["installation_mode"], "panel-only")
        self.assertEqual(record["install_returncode"], 0)
        self.assertEqual(record["panel_version"], "1.0.0")
        self.assertIs(product.require_installed(), host)
        with self.assertRaises(AssertionError) as caught:
            product.install()
        self.assertIn("installed once per run", str(caught.exception))
        self.assertEqual(host.install_attempts, 1)

    def test_a_failed_install_reports_the_operator_tail(self):
        host = PanelOnlyHost(install_returncode=1, install_output="ACME acquisition failed\n")
        with mock.patch.object(panel_only.topology, "PanelOnlyTopology", lambda *a, **k: host):
            product = panel_only.PanelOnlyProduct(FakePodman(self.context))
            with self.assertRaises(AssertionError) as caught:
                product.install()
        message = str(caught.exception)
        self.assertIn("exit 1", message)
        self.assertIn("ACME acquisition failed", message)

    def test_later_cases_are_blocked_before_the_install(self):
        product = panel_only.PanelOnlyProduct(FakePodman(self.context))
        with self.assertRaises(CaseBlocked) as caught:
            product.require_installed()
        self.assertIn(panel_only.INSTALL_CASE_ID, str(caught.exception))

    def test_every_declared_case_is_a_podman_first_catalog_entry(self):
        by_id = {case["id"]: case for case in catalog.load_catalog()["cases"]}
        for case in panel_only.cases(FakePodman(self.context)):
            entry = by_id.get(case.id)
            self.assertIsNotNone(entry, f"{case.id} must be in the shared case catalog")
            self.assertEqual(entry["runs_in"], ["podman"], case.id)
            self.assertIn("panel-only", entry["topology"], f"{case.id} must run in panel-only topology")
            self.assertEqual(entry["gate"], "pr", case.id)

    def test_every_section_the_host_case_parses_is_a_section_the_probe_prints(self):
        for name in STATE_SECTIONS:
            self.assertIn(f"=={name}", panel_only.HOST_SHAPE_SCRIPT, name)
        self.assertNotIn("==units\n", panel_only.HOST_SHAPE_SCRIPT,
                         "the unit states are the untagged prefix, not a section")


class TestPanelOnlyInstallCase(unittest.TestCase):
    """PO-INSTALL: the install stops after the Panel, and says which Panel it deployed."""

    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def test_the_install_records_the_panel_version_this_run_configured(self):
        product, host, _podman = installed(self.context)
        facts = product.require_panel_version()
        self.assertEqual(facts["panel_version"], "1.0.0")
        self.assertEqual(facts["panel_version_expected"], "latest")
        self.assertEqual(facts["panel_version_binary"], "/opt/gowave/gowave-server")
        self.assertEqual(host.install_attempts, 0, "the version probe must not install again")

    def test_a_panel_reporting_another_version_is_refused(self):
        product, _host, podman = installed(self.context)
        podman.version_report = installed_version_report(panel="9.9.9")
        product.matrix = dict(
            matrix.load(), product=dict(matrix.product(matrix.load()), panel_version="v2.6.0"),
        )
        with self.assertRaises(AssertionError) as caught:
            product.require_panel_version()
        self.assertIn("while this deployment", str(caught.exception))
        self.assertIn("2.6.0", str(caught.exception))

    def test_a_panel_binary_at_no_documented_path_is_refused(self):
        product, _host, podman = installed(self.context)
        podman.version_report = json.dumps({"panel": {"binary": "", "returncode": 0, "stdout": "v1"}})
        with self.assertRaises(AssertionError) as caught:
            product.require_panel_version()
        self.assertIn("at no documented path", str(caught.exception))

    def test_a_panel_that_prints_no_version_is_refused(self):
        product, _host, podman = installed(self.context)
        podman.version_report = json.dumps({
            "panel": {
                "binary": "/opt/gowave/gowave-server",
                "argv": "/opt/gowave/gowave-server --version",
                "returncode": 1,
                "stdout": "",
                "stderr": "illegal instruction",
            },
        })
        with self.assertRaises(AssertionError) as caught:
            product.require_panel_version()
        self.assertIn("printed no version", str(caught.exception))


class TestPanelOnlyHostCase(unittest.TestCase):
    """PO-HOST: the Panel and the decoy answer; nothing listens for a tunnel."""

    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def shape(self, output=None, reports=None, product=None):
        product, host, _podman = installed(self.context) if product is None else (product, None, None)
        product.podman.results = [(host_shape_output() if output is None else output, 0)]
        if host is None:
            host = product.host
        host.client_reports = list(reports if reports is not None else [
            tls_report(topology.PANEL_DOMAIN),
            decoy_report(f"https://{topology.REALITY_DOMAIN}/", san=[topology.REALITY_DOMAIN]),
        ])
        return panel_only.case_host_shape(product), host

    def test_a_panel_only_host_passes_every_shape_assertion(self):
        facts, host = self.shape()
        self.assertEqual(facts["units"], {
            "gowave.service": "active", "nginx.service": "active", "fail2ban.service": "active",
        })
        self.assertEqual(facts["node_unit_files"], "0")
        self.assertEqual(facts["traffic_listeners"], [])
        self.assertEqual(facts["traffic_processes"], "0")
        self.assertEqual(facts["traffic_binaries"], [])
        self.assertEqual(facts["credentials"], ["600 root root", "3"])
        self.assertEqual(facts["certificate_lineages"], [
            topology.PANEL_DOMAIN, topology.REALITY_DOMAIN,
        ])
        self.assertEqual(facts["public_panel"]["status"], 200)
        self.assertEqual(facts["public_decoy_san"], [topology.REALITY_DOMAIN])
        self.assertEqual([call["url"] for call in host.client_calls], [
            f"https://{topology.PANEL_DOMAIN}/", f"https://{topology.REALITY_DOMAIN}/",
        ], "the public surface is read on both names, and only those")

    def test_a_running_node_unit_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.shape(output=host_shape_output(unit="1"))
        self.assertIn("declares a gowave-node.service unit", str(caught.exception))

    def test_a_traffic_listener_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.shape(output=host_shape_output(
                listeners=("0.0.0.0:443", "127.0.0.1:3000", "127.0.0.1:8443"),
            ))
        self.assertIn("traffic-plane port", str(caught.exception))
        self.assertIn("8443", str(caught.exception))

    def test_a_missing_panel_listener_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.shape(output=host_shape_output(listeners=("0.0.0.0:443",)))
        self.assertIn("127.0.0.1:3000", str(caught.exception))

    def test_the_public_443_listener_is_required(self):
        with self.assertRaises(AssertionError) as caught:
            self.shape(output=host_shape_output(listeners=("127.0.0.1:443", "127.0.0.1:3000")))
        self.assertIn("publicly on 443", str(caught.exception))

    def test_a_traffic_process_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.shape(output=host_shape_output(processes="1"))
        self.assertIn("rw-core/xray process", str(caught.exception))

    def test_a_worker_binary_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.shape(output=host_shape_output(binaries=("/opt/gowave-node/rw-core",)))
        self.assertIn("/opt/gowave-node/rw-core", str(caught.exception))

    def test_a_failed_nginx_test_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.shape(output=host_shape_output(nginx=("nginx: [emerg] unknown directive", "nginx_t=1")))
        self.assertIn("nginx -t", str(caught.exception))

    def test_credentials_the_operator_left_readable_are_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.shape(output=host_shape_output(credentials=("644 root root", "3")))
        self.assertIn("600 root root", str(caught.exception))

    def test_a_credentials_file_missing_the_documented_keys_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.shape(output=host_shape_output(credentials=("600 root root", "1")))
        self.assertIn("three documented keys", str(caught.exception))

    def test_a_third_certificate_lineage_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.shape(output=host_shape_output(lineages=sorted([
                topology.PANEL_DOMAIN, topology.REALITY_DOMAIN, topology.VISION_DOMAIN,
            ])))
        self.assertIn("terminates no third name", str(caught.exception))

    def test_a_panel_certificate_covering_another_name_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.shape(reports=[
                tls_report(topology.PANEL_DOMAIN, san=[topology.PANEL_DOMAIN, topology.COVER_APEX]),
                decoy_report(f"https://{topology.REALITY_DOMAIN}/", san=[topology.REALITY_DOMAIN]),
            ])
        self.assertIn("is not the lineage", str(caught.exception))

    def test_a_camouflage_site_serving_product_content_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.shape(reports=[
                tls_report(topology.PANEL_DOMAIN),
                decoy_report(
                    f"https://{topology.REALITY_DOMAIN}/", san=[topology.REALITY_DOMAIN],
                    snippet='<html><body><a href="/api/">gowave</a></body></html>',
                ),
            ])
        self.assertIn("product content", str(caught.exception))

    def test_a_camouflage_name_that_does_not_answer_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.shape(reports=[
                tls_report(topology.PANEL_DOMAIN),
                decoy_report(
                    f"https://{topology.REALITY_DOMAIN}/", san=[topology.REALITY_DOMAIN],
                    returncode=1, error="connection refused",
                ),
            ])
        self.assertIn("does not serve the static site", str(caught.exception))


class TestPanelOnlyApiCase(unittest.TestCase):
    """PO-API: the install stops after the Panel's own bootstrap."""

    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def api(self, surface=None, state=None, product=None):
        product, _host, _podman = installed(self.context) if product is None else (product, None, None)
        product.podman.results = [
            (surface_facts() if surface is None else surface, 0),
            (state_facts() if state is None else state, 0),
        ]
        return panel_only.case_api_shape(product)

    def test_an_install_stops_before_the_first_host_record(self):
        facts = self.api()
        self.assertEqual(facts["login_status"], 200)
        for name in ("hosts", "nodes", "profiles", "squads"):
            self.assertEqual(facts[name]["count"], 0, name)
        self.assertGreaterEqual(facts["tokens"]["count"], 1)
        self.assertEqual(facts["state"]["installation_mode"], "panel-only")
        self.assertEqual(facts["state"]["node_count"], 0)

    def test_a_panel_that_left_a_config_profile_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.api(surface=surface_facts(**{"surface.profiles.count": 1}))
        self.assertIn("config profiles", str(caught.exception))

    def test_a_panel_without_a_scoped_token_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.api(surface=surface_facts(**{"surface.tokens.count": 0}))
        self.assertIn("scoped API token", str(caught.exception))

    def test_a_default_user_without_a_short_uuid_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.api(surface=surface_facts(**{"surface.default_user.short_uuid_length": 0}))
        self.assertIn("shortUuid", str(caught.exception))

    def test_a_state_file_naming_another_mode_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.api(state=state_facts(installation_mode="aio"))
        self.assertIn("'aio'", str(caught.exception))

    def test_a_state_file_carrying_local_node_fields_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.api(state=state_facts(local_node_keys=["localNodeUuid"]))
        self.assertIn("local-node fields", str(caught.exception))

    def test_a_state_file_whose_nodes_are_not_an_array_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.api(state=state_facts(nodes_is_list=False))
        self.assertIn("not an array", str(caught.exception))

    def test_a_state_file_listing_a_node_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.api(state=state_facts(node_count=1))
        self.assertIn("lists 1 nodes", str(caught.exception))


class TestPanelOnlySquadCase(unittest.TestCase):
    """PO-SQUAD: the first registration after a Panel-only install owns a real squad."""

    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def squad(self, output=None, host=None):
        product, host, _podman = installed(self.context, host=host)
        product.podman.results = [(squad_facts() if output is None else output, 0)]
        return panel_only.case_squad(product), host

    def test_the_first_registration_creates_the_squad_its_host_records_name(self):
        facts, host = self.squad()
        self.assertEqual(host.trust_pins, 1, "the Worker key is pinned before the add")
        self.assertEqual(host.node_add_attempts, 1)
        self.assertEqual(
            facts["node_add_command"],
            f"bash /repo/gowave-auto.sh node add '{topology.WORKER_NODE_NAME}'",
        )
        self.assertEqual(facts["worker_trust"]["worker"], topology.WORKER_NODE_NAME)
        self.assertEqual(facts["squad"]["hosts_naming_state_squad"], 1)
        self.assertEqual(facts["squad"]["host_squad_modes"], ["ALLOW_ONLY"])

    def test_a_state_file_that_kept_no_squad_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.squad(squad_facts(state_squad_present=False, state_squad_length=0))
        self.assertIn("stored no squad identifier", str(caught.exception))

    def test_a_host_record_with_a_null_squad_entry_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.squad(squad_facts(hosts_with_null_squad=1))
        self.assertIn("null squad entry", str(caught.exception))

    def test_a_host_record_without_a_squad_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.squad(squad_facts(hosts_without_squad=1))
        self.assertIn("no squad at all", str(caught.exception))

    def test_a_host_record_naming_another_squad_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.squad(squad_facts(hosts_naming_state_squad=0))
        self.assertIn("name the identifier state.json stored", str(caught.exception))

    def test_a_host_record_using_another_mode_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.squad(squad_facts(host_squad_modes=["ALLOW_ALL"]))
        self.assertIn("ALLOW_ALL", str(caught.exception))

    def test_a_squad_allowing_no_inbound_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.squad(squad_facts(mvp_squad_inbound_count=0))
        self.assertIn("allows no inbound", str(caught.exception))

    def test_a_panel_reporting_another_worker_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.squad(squad_facts(panel_node_names=["worker-2"]))
        self.assertIn("worker-1", str(caught.exception))

    def test_a_state_file_that_did_not_record_the_registration_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.squad(squad_facts(nodes_in_state=0))
        self.assertIn("after one registration", str(caught.exception))

    def test_a_failed_registration_reports_the_operator_tail(self):
        host = PanelOnlyHost()
        host.node_add_returncode = 1
        product, _host, _podman = installed(self.context, host=host)
        with self.assertRaises(AssertionError) as caught:
            panel_only.case_squad(product)
        self.assertIn("node add failed with exit 1", str(caught.exception))


class TestPanelOnlyRefusalProbe(unittest.TestCase):
    """PO-SQUAD-REFUSED: a null squad is never turned into a usable grant."""

    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def refused(self, output=None, outcome=None):
        product, host, _podman = installed(self.context)
        product.node_add_outcome = outcome or topology.InstallOutcome(
            0, "worker added\n", "", 2.0, "node add",
        )
        product.podman.results = [(refused_facts() if output is None else output, 0)]
        return panel_only.case_refused_payload(product), host

    def test_a_panel_that_refuses_the_payload_leaves_the_count_alone(self):
        facts, _host = self.refused()
        self.assertTrue(facts["panel_refuses_null_squad"])
        self.assertEqual(facts["hosts_after_refused"], facts["hosts_before"])

    def test_a_panel_that_takes_the_record_without_the_squad_passes(self):
        facts, _host = self.refused(refused_facts(
            refused_status=201, refused_created=True, hosts_after_refused=2,
            accepted_squad_entries=1, accepted_squad_nulls=1,
            accepted_naming_state_squad=0, refused_cleanup_status=204,
        ))
        self.assertFalse(facts["panel_refuses_null_squad"])
        self.assertEqual(facts["accepted_naming_state_squad"], 0)
        self.assertEqual(facts["hosts_after_refused_cleanup"], facts["hosts_before"])

    def test_a_panel_that_turns_the_null_entry_into_the_squad_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.refused(refused_facts(
                refused_status=201, refused_created=True, hosts_after_refused=2,
                accepted_squad_nulls=0, accepted_naming_state_squad=1,
                refused_cleanup_status=204,
            ))
        self.assertIn("broken registration", str(caught.exception))

    def test_an_acceptance_without_a_record_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.refused(refused_facts(refused_status=200, refused_created=False))
        self.assertIn("neither a refusal nor an acceptance", str(caught.exception))

    def test_a_control_the_panel_refuses_makes_the_result_unattributable(self):
        with self.assertRaises(AssertionError) as caught:
            self.refused(refused_facts(control_status=400, control_created=False, hosts_after_control=1))
        self.assertIn("cannot be attributed to the null squad", str(caught.exception))

    def test_a_control_whose_count_did_not_move_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.refused(refused_facts(hosts_after_control=1))
        self.assertIn("host count went", str(caught.exception))

    def test_a_control_that_was_not_removed_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.refused(refused_facts(delete_status=500))
        self.assertIn("not removed", str(caught.exception))

    def test_a_refused_payload_that_still_changed_the_count_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.refused(refused_facts(hosts_after_refused=2))
        self.assertIn("still changed the host count", str(caught.exception))

    def test_the_probe_does_not_run_a_second_registration(self):
        _facts, host = self.refused()
        self.assertEqual(host.node_add_attempts, 0,
                         "the negative replays the records the positive created")

    def test_a_failed_registration_blocks_the_replay(self):
        product, _host, _podman = installed(self.context)
        product.node_add_outcome = topology.InstallOutcome(1, "", "node add failed", 1.0, "node add")
        with self.assertRaises(CaseBlocked) as caught:
            panel_only.case_refused_payload(product)
        self.assertIn(panel_only.SQUAD_CASE_ID, str(caught.exception))

    def test_the_control_is_posted_before_the_null_payload(self):
        script = panel_only.REFUSED_PAYLOAD_SCRIPT
        control = script.index('"mode": "ALLOW_ONLY", "squads": [squad]')
        null = script.index('"mode": "ALLOW_ONLY", "squads": [None]')
        self.assertLess(control, null, "a control after the probe proves nothing")
        self.assertIn('"isDisabled": False', script)
        self.assertIn("refused_body_keys", script)


def node_surface(names=()):
    """The Panel surface read, reduced to the node list the refusal case compares."""
    return json.dumps({
        "surface": {
            "nodes": {"status": 200, "count": len(names), "names": list(names)},
        },
    })


def refused_resolution_report(resolution="", mode="remove"):
    """What the resolution probe prints for the refusal case's own name.

    The probe runs in ``remove`` mode: it drops any entry this case wrote into a
    container that is reused across cases, then reports what ``getent`` answers.
    The default is the premise the case needs — nothing answers the name — and a
    test overrides ``resolution`` to make the name reach something.
    """
    return json.dumps({
        "mode": mode,
        "host": aio.ADD_NODE_REFUSED_PANEL,
        "address": "",
        "resolution": resolution,
        "marker_count": 0,
        "request": None,
    })


def refusal_output(*, sentinel=False, verification=True):
    """What the shipped add-node wizard prints when the Panel cannot be verified.

    The sample is the one the live case produces: the local-Panel branch is
    skipped, the name is probed, no resolver answers it and the flow returns
    before any Worker prompt.
    """
    lines = ["No local Panel found on this host."]
    if verification:
        lines += [
            f"Verifying Panel API at {aio.ADD_NODE_REFUSED_PANEL}...",
            "Panel API unreachable.",
        ]
    if sentinel:
        lines.append("GOWAVE_CMD_NODE_CALLED")
    return "\n".join(lines) + "\n"


def wizard_script(podman):
    """The one script the case ran as the operator's add-node wizard."""
    matches = [script for script in podman.scripts if "wizard_add_node_to_panel" in script]
    if len(matches) != 1:
        raise AssertionError(f"the case ran {len(matches)} wizard scripts, not one")
    return matches[0]


class TestPanelOnlyAddNodeRefusedCase(unittest.TestCase):
    """PO-ADD-NODE-REFUSED (MN-ADD-NODE-REFUSED): refused before any Worker mutation."""

    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)

    def refused(self, *, before=("worker-1",), after=("worker-1",), wizard=None,
                wizard_returncode=1, resolution=None, probe_returncode=0):
        product, host, podman = installed(self.context)
        podman.results = [
            (node_surface(before), 0),
            (wizard if wizard is not None else refusal_output(), wizard_returncode),
            (node_surface(after), 0),
        ]
        podman.resolution_report = resolution
        podman.probe_returncode = probe_returncode
        return panel_only.case_add_node_refused(product), host, podman

    def test_a_refused_attempt_reports_verification_and_leaves_the_panel_alone(self):
        facts, host, podman = self.refused()
        self.assertEqual(facts.get("panel_address"), aio.ADD_NODE_REFUSED_PANEL)
        self.assertTrue(facts.get("verification_failure_reported"))
        self.assertEqual(facts.get("wizard_returncode"), 1)
        self.assertFalse(facts.get("mutation_boundary_reached"))
        self.assertTrue(facts.get("verification_step_reached"))
        self.assertEqual(facts.get("panel_node_names_before"), ["worker-1"])
        self.assertEqual(facts.get("panel_node_names_after"), ["worker-1"])
        self.assertEqual(host.node_add_attempts, 0, "the host ran a real node add")
        # The surface is read before and after the attempt; only the wizard in
        # between can have touched the Panel, and it is not a `node add`.
        self.assertNotIn("node add", wizard_script(podman))

    def test_the_case_asks_the_container_what_its_panel_name_resolves_to(self):
        _facts, _host, podman = self.refused()
        probes = [s for s in podman.scripts if aio.ADD_NODE_REFUSED_PROBE_MARKER in s]
        self.assertEqual(len(probes), 1, "the premise is read once, before the wizard")
        self.assertIn("MODE=remove", probes[0])
        self.assertIn(aio.ADD_NODE_REFUSED_PANEL, probes[0])
        self.assertLess(
            podman.scripts.index(probes[0]), podman.scripts.index(wizard_script(podman)),
            "a name that resolves has to fail the case before the wizard is pointed at it",
        )

    def test_the_case_drives_the_shipped_wizard_and_stubs_only_the_mutation(self):
        _facts, _host, podman = self.refused()
        script = wizard_script(podman)
        self.assertIn(aio.ADD_NODE_REFUSED_PANEL, script)
        self.assertIn("cmd_node() {", script)
        self.assertIn("detect_local_panel() { return 1; }", script)
        self.assertLess(
            script.index("cmd_node() {"),
            script.index("wizard_add_node_to_panel"),
            "the sentinel must be defined before the flow that could call it",
        )

    def test_a_reached_mutation_boundary_fails_the_case(self):
        with self.assertRaises(AssertionError) as caught:
            self.refused(wizard=refusal_output(sentinel=True))
        self.assertIn("mutation began", str(caught.exception))

    def test_a_refusal_without_a_verification_message_fails_the_case(self):
        with self.assertRaises(AssertionError) as caught:
            self.refused(wizard=refusal_output(verification=False))
        self.assertIn("verification failure", str(caught.exception))

    def test_a_changed_panel_node_list_fails_the_case(self):
        with self.assertRaises(AssertionError) as caught:
            self.refused(after=("worker-1", "worker-invalid"))
        self.assertIn("changed the Panel's node list", str(caught.exception))

    def test_a_panel_name_that_resolves_fails_the_case(self):
        with self.assertRaises(AssertionError) as caught:
            self.refused(resolution=refused_resolution_report(
                resolution=f"10.89.0.11 {aio.ADD_NODE_REFUSED_PANEL}",
            ))
        self.assertIn("resolves to", str(caught.exception))

    def test_a_probe_that_reports_the_name_still_steered_fails_the_case(self):
        with self.assertRaises(AssertionError) as caught:
            self.refused(resolution=refused_resolution_report(mode="install"))
        self.assertIn("may still", str(caught.exception))

    def test_a_resolution_the_container_could_not_measure_fails_the_case(self):
        # No report means no premise: the case must say so, not read an empty
        # document as a name that resolves nowhere.
        with self.assertRaises(AssertionError) as caught:
            self.refused(probe_returncode=9)
        self.assertIn("exited 9", str(caught.exception))

    def test_the_case_is_declared_in_the_suite(self):
        suite = panel_only.cases(FakePodman(self.context))
        ids = [case.id for case in suite]
        self.assertIn(panel_only.ADD_NODE_REFUSED_CASE_ID, ids)
        # The case runs after the refusal probe
        self.assertLess(ids.index(panel_only.SQUAD_REFUSED_CASE_ID), ids.index(panel_only.ADD_NODE_REFUSED_CASE_ID))


if __name__ == "__main__":
    unittest.main()
