#!/usr/bin/env python3
"""Suite nonroot: the Worker's state is read from the Worker.

WRK-05..06 run against the real Worker of a two-node install, so what a unit test
can hold is what the live run relies on being right: the probe reads the product's
own CLI and its own applied config without ever touching the Panel secret, and each
case refuses the disagreement it exists to catch instead of accepting a plausible
report.
"""
import ast
import json
import os
import subprocess
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(TESTS_DIR))

from tools.podman_e2e import matrix, multi_node, topology  # noqa: E402
from test_podman_cluster import healthy_cluster, inbound_specs  # noqa: E402

CORE_LINE = "Xray 26.11.9 (Xray, Penetrates Everything.)"

STATUS_TEMPLATE = (
    "\x1b[36m[STATUS]\x1b[0m Checking gowave-node service status...\n\n"
    "  \x1b[32m\u25cf\x1b[0m Daemon (Socket):   {daemon}\n"
    "  \x1b[32m\u25cf\x1b[0m Systemd Service:   active (gowave-node.service)\n"
    "  \x1b[32m\u25cf\x1b[0m Xray Core:         {core} (/opt/gowave-node/rw-core)\n"
    "  \x1b[36m\u25cf\x1b[0m Node Version:      v1.0.5\n\n"
)


def fixture_topology(vision=False, worker_vision=False):
    """The topology attributes the cases read, including the Worker's container."""
    return types.SimpleNamespace(
        plan=topology.allocate_plan([]),
        panel_domain=topology.PANEL_DOMAIN,
        worker_domain=topology.WORKER_DOMAIN,
        worker_vision_domain=topology.WORKER_VISION_DOMAIN if worker_vision else None,
        worker_name="worker-970db984",
    )


def worker_state(worker_vision=False, node="worker"):
    """The report a healthy Worker produces, in the probe's own shape."""
    return {
        "binary": {"path": "/opt/gowave-node/gowave-node", "executable": True},
        "version": {"returncode": 0, "stdout": "gowave-node v1.0.5\n", "stderr": ""},
        "status": {
            "returncode": 0,
            "stdout": STATUS_TEMPLATE.format(
                daemon="RUNNING (managed runtime socket)", core=CORE_LINE,
            ),
            "stderr": "",
        },
        "paths": {
            "runtime_dir": {"mode": "0o700"},
            "config": {"path": "/run/gowave-node/xray.json", "mode": "0o600"},
            "env": {"path": "/opt/gowave-node/.env", "mode": "0o600"},
            "core": {"path": "/opt/gowave-node/rw-core", "executable": True},
        },
        "options": {
            "NODE_PORT": str(multi_node.NODE_PORT),
            "GOWAVE_NODE_RUNTIME_DIR": "/run/gowave-node",
        },
        "applied": {
            "parsed": True,
            "inbounds": inbound_specs(node, worker_vision),
            "outbound_count": 2,
        },
    }


class _FakePodman:
    """The single call the Worker probe makes, answered from a prepared report."""

    def __init__(self, report, returncode=0, stdout=None):
        self.report = report
        self.returncode = returncode
        self.stdout = stdout
        self.calls = []

    def exec_bash(self, name, script, check=False, input_text=None, timeout=0):
        self.calls.append({"name": name, "script": script, "timeout": timeout})
        stdout = self.stdout if self.stdout is not None else json.dumps(self.report)
        return types.SimpleNamespace(returncode=self.returncode, stdout=stdout, stderr="")


class _WorkerProduct(multi_node.MultiNodeProduct):
    """The installed product, with the Panel and Worker surfaces prepared."""

    def __init__(self, cluster=None, report=None, vision=False, worker_vision=False):
        self.podman = _FakePodman(worker_state(worker_vision) if report is None else report)
        self.vision = vision
        self.worker_vision = worker_vision
        self.matrix = matrix.load()
        self.topology = fixture_topology(vision, worker_vision)
        self.node_add_outcome = types.SimpleNamespace(ok=True)
        self.master = types.SimpleNamespace(require_installed=lambda: None)
        self.worker_state_cache = None
        self.cluster = healthy_cluster(vision, worker_vision) if cluster is None else cluster
        # The report is stored by the node's first heartbeat; a unit test must
        # not wait for one, so the poll is compressed to a single pass.
        self.worker_report_timeout = 0.01
        self.worker_report_interval = 0.001

    def panel_cluster(self, case_id):
        return {"login": {"status": 200}, "cluster": self.cluster}


def run_case(case, cluster=None, report=None, **flags):
    product = _WorkerProduct(cluster, report, **flags)
    return case(product), product


def worker_record(cluster):
    return next(
        record for record in cluster["nodes"]["records"]
        if record["name"] == topology.WORKER_NODE_NAME
    )


class TestWorkerProbeParsing(unittest.TestCase):
    """The product's own command output is parsed, not assumed."""

    def test_the_cli_version_is_the_release_the_binary_reports(self):
        self.assertEqual(
            multi_node.parse_node_version("\x1b[32mgowave-node v1.0.5\x1b[0m\n"), "v1.0.5",
        )
        self.assertEqual(multi_node.parse_node_version("no version here"), "")

    def test_the_status_report_is_read_through_its_colours(self):
        status = multi_node.parse_node_status(
            STATUS_TEMPLATE.format(daemon="RUNNING (managed runtime socket)", core=CORE_LINE)
        )
        self.assertIs(status["daemon_running"], True)
        self.assertEqual(status["service"], "active")
        self.assertEqual(status["core"], f"{CORE_LINE} (/opt/gowave-node/rw-core)")
        self.assertEqual(status["version"], "v1.0.5")
        self.assertNotIn("\x1b", status["core"])

    def test_an_inactive_daemon_is_not_running(self):
        status = multi_node.parse_node_status(
            STATUS_TEMPLATE.format(daemon="INACTIVE / NOT RESPONDING", core="NOT FOUND")
        )
        self.assertIs(status["daemon_running"], False)

    def test_versions_compare_by_their_numbers(self):
        self.assertEqual(multi_node.version_number("v1.0.5 (Go)"), "1.0.5")
        self.assertEqual(multi_node.version_number(CORE_LINE), "26.11.9")
        self.assertEqual(multi_node.version_number("unknown"), "")

    def test_inbound_declarations_compare_on_normalised_fields(self):
        spec = inbound_specs("worker", False)[0]
        self.assertEqual(
            multi_node.inbound_key(dict(spec, security="REALITY", port=str(spec["port"]))),
            multi_node.inbound_key(spec),
        )
        self.assertNotEqual(
            multi_node.inbound_key(dict(spec, port=spec["port"] + 1)),
            multi_node.inbound_key(spec),
        )


class TestWorkerProbeContract(unittest.TestCase):
    """The probe reads the product's surfaces and nothing else."""

    def _embedded_python(self):
        script = multi_node.WORKER_STATE_SCRIPT
        start = script.index("<<'PY'") + len("<<'PY'")
        return script[start:script.index("\nPY", start)]

    def test_the_probe_is_shell_and_python_valid(self):
        script = multi_node.WORKER_STATE_SCRIPT
        finished = subprocess.run(
            ["bash", "-n"], input=script, text=True, capture_output=True, check=False,
        )
        self.assertEqual(finished.returncode, 0, finished.stderr)
        ast.parse(self._embedded_python())

    def test_the_probe_never_reads_the_panel_secret(self):
        script = multi_node.WORKER_STATE_SCRIPT
        self.assertNotIn("SECRET_KEY", script)
        self.assertIn("NODE_PORT", script)

    def test_the_report_is_collected_once_per_run(self):
        report = worker_state()
        product = _WorkerProduct(report=report)
        first = product.worker_state("WRK-05")
        second = product.worker_state("WRK-06")
        self.assertEqual(first, second)
        self.assertEqual(len(product.podman.calls), 1)
        self.assertEqual(product.podman.calls[0]["name"], product.topology.worker_name)
        self.assertEqual(product.podman.calls[0]["timeout"],
                         multi_node.WORKER_STATE_TIMEOUT_SECONDS)

    def test_a_probe_that_failed_is_refused_rather_than_read(self):
        product = _WorkerProduct(report={})
        product.podman.returncode = 1
        product.podman.stdout = ""
        with self.assertRaises(AssertionError) as caught:
            product.worker_state("WRK-05")
        self.assertIn("Worker state probe exited 1", str(caught.exception))

    def test_a_probe_that_printed_no_json_is_refused(self):
        product = _WorkerProduct(report={})
        product.podman.stdout = "not json"
        with self.assertRaises(AssertionError) as caught:
            product.worker_state("WRK-05")
        self.assertIn("did not print a JSON object", str(caught.exception))


class TestWorkerStateCase(unittest.TestCase):
    """WRK-05: the Panel's record of the Worker must be the Worker's own."""

    def test_the_healthy_worker_satisfies_the_case(self):
        evidence, _product = run_case(multi_node.case_worker_state)
        self.assertEqual(evidence["worker_version"], "v1.0.5")
        self.assertEqual(evidence["panel_node_version"], "v1.0.5 (Go)")
        self.assertEqual(evidence["panel_xray_version"], "v26.11.9")
        self.assertIn("26.11.9", evidence["core"])
        self.assertEqual(evidence["daemon"], "RUNNING (managed runtime socket)")

    def test_a_requested_release_that_the_binary_does_not_match_is_refused(self):
        with mock.patch.dict(os.environ, {"GOWAVE_NODE_VERSION": "v1.0.6"}):
            with self.assertRaises(AssertionError) as caught:
                run_case(multi_node.case_worker_state)
        self.assertIn("requested 'v1.0.6'", str(caught.exception))

    def test_a_requested_release_that_matches_is_accepted(self):
        with mock.patch.dict(os.environ, {"GOWAVE_NODE_VERSION": "v1.0.5"}):
            evidence, _product = run_case(multi_node.case_worker_state)
        self.assertEqual(evidence["requested_version"], "v1.0.5")

    def test_latest_is_resolved_to_whatever_the_binary_reports(self):
        with mock.patch.dict(os.environ, {"GOWAVE_NODE_VERSION": "latest"}):
            evidence, _product = run_case(multi_node.case_worker_state)
        self.assertEqual(evidence["requested_version"], "latest")

    def test_a_disabled_worker_is_refused(self):
        cluster = healthy_cluster()
        worker_record(cluster)["state"]["disabled"] = True
        with self.assertRaises(AssertionError) as caught:
            run_case(multi_node.case_worker_state, cluster)
        self.assertIn("holds the Worker disabled", str(caught.exception))

    def test_a_worker_that_never_connects_is_refused(self):
        cluster = healthy_cluster()
        worker_record(cluster)["connected"] = False
        with self.assertRaises(AssertionError) as caught:
            run_case(multi_node.case_worker_state, cluster)
        self.assertIn("not report", str(caught.exception))

    def test_a_worker_still_connecting_is_refused(self):
        cluster = healthy_cluster()
        worker_record(cluster)["state"]["connecting"] = True
        with self.assertRaises(AssertionError) as caught:
            run_case(multi_node.case_worker_state, cluster)
        self.assertIn("connecting", str(caught.exception))

    def test_a_config_the_node_rejected_is_refused(self):
        cluster = healthy_cluster()
        worker_record(cluster)["state"]["status_message"] = "invalid Xray configuration"
        with self.assertRaises(AssertionError) as caught:
            run_case(multi_node.case_worker_state, cluster)
        self.assertIn("refused to load", str(caught.exception))

    def test_a_node_of_the_other_implementation_is_refused(self):
        cluster = healthy_cluster()
        worker_record(cluster)["versions"]["node_type"] = "ts"
        with self.assertRaises(AssertionError) as caught:
            run_case(multi_node.case_worker_state, cluster)
        self.assertIn("'ts' node", str(caught.exception))

    def test_a_version_the_binary_does_not_report_is_refused(self):
        cluster = healthy_cluster()
        worker_record(cluster)["versions"]["node"] = "v2.0.0 (Go)"
        with self.assertRaises(AssertionError) as caught:
            run_case(multi_node.case_worker_state, cluster)
        self.assertIn("while the Panel records 'v2.0.0 (Go)'", str(caught.exception))

    def test_a_missing_node_binary_is_refused(self):
        report = worker_state()
        report["binary"]["executable"] = False
        with self.assertRaises(AssertionError) as caught:
            run_case(multi_node.case_worker_state, report=report)
        self.assertIn("no executable node binary", str(caught.exception))

    def test_a_version_command_that_failed_is_refused(self):
        report = worker_state()
        report["version"] = {"returncode": 1, "stdout": "", "stderr": "not found"}
        with self.assertRaises(AssertionError) as caught:
            run_case(multi_node.case_worker_state, report=report)
        self.assertIn("gowave-node version", str(caught.exception))

    def test_a_status_report_that_says_inactive_is_refused(self):
        report = worker_state()
        report["status"]["stdout"] = STATUS_TEMPLATE.format(
            daemon="INACTIVE / NOT RESPONDING", core=CORE_LINE,
        )
        with self.assertRaises(AssertionError) as caught:
            run_case(multi_node.case_worker_state, report=report)
        self.assertIn("INACTIVE", str(caught.exception))

    def test_a_worker_without_a_core_is_refused(self):
        report = worker_state()
        report["status"]["stdout"] = STATUS_TEMPLATE.format(
            daemon="RUNNING (managed runtime socket)", core="NOT FOUND",
        )
        with self.assertRaises(AssertionError) as caught:
            run_case(multi_node.case_worker_state, report=report)
        self.assertIn("no Xray core", str(caught.exception))

    def test_a_core_the_panel_does_not_record_is_refused(self):
        report = worker_state()
        report["status"]["stdout"] = STATUS_TEMPLATE.format(
            daemon="RUNNING (managed runtime socket)", core="Xray 26.10.0 (Xray)",
        )
        with self.assertRaises(AssertionError) as caught:
            run_case(multi_node.case_worker_state, report=report)
        self.assertIn("while the Panel records 'v26.11.9'", str(caught.exception))


class TestWorkerConfigCase(unittest.TestCase):
    """WRK-06: the loaded config is the assignment, field by field."""

    def test_the_healthy_worker_satisfies_the_case(self):
        evidence, _product = run_case(multi_node.case_worker_config)
        self.assertEqual(evidence["declared_inbound_count"], 4)
        self.assertEqual(evidence["worker_inbound_count"], 4)
        self.assertEqual(evidence["outbound_count"], 2)
        self.assertEqual(evidence["runtime_mode"], "0o700")
        self.assertEqual(evidence["config_mode"], "0o600")
        self.assertEqual(evidence["node_port"], str(multi_node.NODE_PORT))

    def test_both_nodes_running_vision_expect_five_inbounds_each(self):
        evidence, _product = run_case(
            multi_node.case_worker_config, vision=True, worker_vision=True,
        )
        self.assertEqual(evidence["worker_inbound_count"], 5)
        self.assertEqual(evidence["declared_inbound_count"], 5)

    def test_a_panel_that_declares_no_inbound_is_refused(self):
        cluster = healthy_cluster()
        worker_record(cluster)["inbound_specs"] = []
        with self.assertRaises(AssertionError) as caught:
            run_case(multi_node.case_worker_config, cluster)
        self.assertIn("declares no inbounds", str(caught.exception))

    def test_a_declaration_with_the_wrong_count_is_refused(self):
        cluster = healthy_cluster()
        worker_record(cluster)["inbound_specs"].pop()
        with self.assertRaises(AssertionError) as caught:
            run_case(multi_node.case_worker_config, cluster)
        self.assertIn("expected 4", str(caught.exception))

    def test_a_config_that_cannot_be_parsed_is_refused(self):
        report = worker_state()
        report["applied"]["parsed"] = False
        with self.assertRaises(AssertionError) as caught:
            run_case(multi_node.case_worker_config, report=report)
        self.assertIn("is not a JSON object", str(caught.exception))

    def test_a_config_with_the_wrong_inbound_count_is_refused(self):
        report = worker_state()
        report["applied"]["inbounds"].pop()
        with self.assertRaises(AssertionError) as caught:
            run_case(multi_node.case_worker_config, report=report)
        self.assertIn("while the Panel assigned it 4", str(caught.exception))

    def test_a_config_without_outbounds_is_refused(self):
        report = worker_state()
        report["applied"]["outbound_count"] = 0
        with self.assertRaises(AssertionError) as caught:
            run_case(multi_node.case_worker_config, report=report)
        self.assertIn("no outbounds", str(caught.exception))

    def test_an_inbound_the_panel_did_not_assign_is_refused(self):
        report = worker_state()
        stray = dict(report["applied"]["inbounds"][0], tag="vless-xhttp-stray")
        report["applied"]["inbounds"][0] = stray
        with self.assertRaises(AssertionError) as caught:
            run_case(multi_node.case_worker_config, report=report)
        self.assertIn("missing", str(caught.exception))
        self.assertIn("unexpected", str(caught.exception))

    def test_an_inbound_the_worker_does_not_load_is_refused(self):
        cluster = healthy_cluster()
        worker_record(cluster)["inbound_specs"][0]["port"] += 1
        with self.assertRaises(AssertionError) as caught:
            run_case(multi_node.case_worker_config, cluster)
        self.assertIn("differ from the Panel's assignment", str(caught.exception))

    def test_a_world_readable_runtime_directory_is_refused(self):
        report = worker_state()
        report["paths"]["runtime_dir"]["mode"] = "0o755"
        with self.assertRaises(AssertionError) as caught:
            run_case(multi_node.case_worker_config, report=report)
        self.assertIn("reachable by other local users", str(caught.exception))

    def test_a_world_readable_config_is_refused(self):
        report = worker_state()
        report["paths"]["config"]["mode"] = "0o644"
        with self.assertRaises(AssertionError) as caught:
            run_case(multi_node.case_worker_config, report=report)
        self.assertIn("REALITY key material", str(caught.exception))

    def test_a_world_readable_settings_file_is_refused(self):
        report = worker_state()
        report["paths"]["env"]["mode"] = "0o644"
        with self.assertRaises(AssertionError) as caught:
            run_case(multi_node.case_worker_config, report=report)
        self.assertIn("settings file", str(caught.exception))

    def test_a_worker_serving_another_port_than_the_panel_dials_is_refused(self):
        report = worker_state()
        report["options"]["NODE_PORT"] = "3003"
        with self.assertRaises(AssertionError) as caught:
            run_case(multi_node.case_worker_config, report=report)
        self.assertIn("serve port '3003'", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
