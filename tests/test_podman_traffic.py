#!/usr/bin/env python3
"""Suite nonroot: the data plane is proven by what the endpoint records.

The traffic probe is only as good as its evidence: a request id the endpoint
echoes, the digest of the body it received, and the source address it observed.
These tests hold the probe, the case that reads its facts, and the topology that
gives it somewhere to send the payload to.
"""
import hashlib
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import (  # noqa: E402
    acme_fixture,
    aio,
    client_trust,
    subscription_probe,
    target_image,
    topology,
    traffic_probe,
)
from tools.podman_e2e.runner import CaseBlocked, RunContext  # noqa: E402

PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
CLIENT_SECRET = "client-subscription-payload-do-not-print"

PLAN = topology.NetworkPlan(subnet="203.0.114.0/24")
CORE = (
    ("tcp", "reality", topology.REALITY_DOMAIN),
    ("ws", "tls", topology.PANEL_DOMAIN),
    ("grpc", "tls", topology.PANEL_DOMAIN),
    ("xhttp", "tls", topology.PANEL_DOMAIN),
)

XRAY_CONFIG = {
    "inbounds": [
        {"tag": "socks-in", "protocol": "socks", "port": 10808},
        {"tag": "http-in", "protocol": "http", "port": 10809},
    ],
    "outbounds": [
        {"tag": "proxy", "protocol": "vless", "streamSettings": {
            "network": "tcp", "security": "reality",
            "realitySettings": {"serverName": topology.REALITY_DOMAIN},
        }},
        {"tag": "direct", "protocol": "freedom"},
        {"tag": "block", "protocol": "blackhole"},
    ],
}

SERVED_MIHOMO = "\n".join([
    "mixed-port: 7890",
    "proxies:",
    "  - name: vless-reality",
    "    type: vless",
    "    network: tcp",
    "    servername: reality.testbed.internal",
    "    reality-opts:",
    "      public-key: public-key-value",
    "  - name: vless-ws",
    "    type: vless",
    "    network: ws",
    "    servername: panel.testbed.internal",
    "    tls: true",
    "proxy-groups:",
    "  - name: \u2192 GoWave",
    "    type: select",
    "    proxies:",
    "      - vless-reality",
    "rules:",
    "  - MATCH,\u2192 GoWave",
    "",
])


def traffic_transfers():
    transfers = []
    for engine in aio.TRAFFIC_ENGINES:
        for network, security, sni in CORE:
            transfers.append({
                "engine": engine,
                "tag": f"{engine}-{network}",
                "protocol": "vless",
                "network": network,
                "security": security,
                "sni": sni,
                "request_id": f"{engine}-{network}-0123456789ab",
                "status": 200,
                "request_id_match": True,
                "body_match": True,
                "source_ip": PLAN.target_ip,
            })
    return transfers


def traffic_facts():
    transfers = traffic_transfers()
    return {
        "transfers": transfers,
        "transfer_count": len(transfers),
        "engines": sorted({item["engine"] for item in transfers}),
        "networks": sorted({item["network"] for item in transfers}),
        "source_ips": [PLAN.target_ip],
        "direct_source_ip": PLAN.engine_client_ip,
        "echo_records": len(transfers),
        "missing_request_ids": 0,
    }


class TestTrafficProbeHelpers(unittest.TestCase):
    """What the probe reads out of a served profile, without a network."""

    def test_the_http_inbound_is_the_one_the_probe_can_drive(self):
        self.assertEqual(traffic_probe.http_proxy_port(XRAY_CONFIG), 10809)
        with self.assertRaises(SystemExit) as caught:
            traffic_probe.http_proxy_port({"inbounds": [{"protocol": "socks", "port": 10808}]})
        self.assertIn("no HTTP inbound", str(caught.exception))

    def test_the_proxy_outbound_is_not_the_direct_or_block_one(self):
        self.assertEqual(traffic_probe.proxy_outbound(XRAY_CONFIG)["tag"], "proxy")
        with self.assertRaises(SystemExit):
            traffic_probe.proxy_outbound({"outbounds": [{"tag": "direct", "protocol": "freedom"}]})
        with self.assertRaises(SystemExit):
            traffic_probe.proxy_outbound({"outbounds": {}})

    def test_the_xray_label_reads_the_transport_from_the_served_stream(self):
        label = traffic_probe.xray_label(XRAY_CONFIG)
        self.assertEqual(label["network"], "tcp")
        self.assertEqual(label["security"], "reality")
        self.assertEqual(label["sni"], topology.REALITY_DOMAIN)
        self.assertEqual(label["protocol"], "vless")

    def test_the_xray_label_falls_back_to_the_tls_and_tcp_defaults(self):
        config = {"outbounds": [{"tag": "proxy", "protocol": "trojan", "streamSettings": {
            "security": "tls", "tlsSettings": {"serverName": topology.PANEL_DOMAIN},
        }}]}
        label = traffic_probe.xray_label(config)
        self.assertEqual(label["network"], "tcp")
        self.assertEqual(label["security"], "tls")
        self.assertEqual(label["sni"], topology.PANEL_DOMAIN)

    def test_the_mihomo_label_marks_reality_by_key_presence(self):
        proxies = subscription_probe.scan_mihomo(SERVED_MIHOMO)["proxy_details"]
        self.assertEqual(len(proxies), 2)
        reality = traffic_probe.mihomo_label(proxies[0])
        self.assertEqual(reality["tag"], "vless-reality")
        self.assertEqual(reality["security"], "reality")
        self.assertEqual(reality["sni"], topology.REALITY_DOMAIN)
        plain = traffic_probe.mihomo_label(proxies[1])
        self.assertEqual(plain["network"], "ws")
        self.assertEqual(plain["security"], "tls")
        self.assertEqual(plain["sni"], topology.PANEL_DOMAIN)

    def test_the_fixture_anchor_is_appended_as_pem_without_editing_the_served_yaml(self):
        with tempfile.TemporaryDirectory(prefix="gowave-traffic-ca-") as directory:
            ca_file = Path(directory) / "issued-root.pem"
            ca_file.write_text(PEM, encoding="utf-8")
            config = traffic_probe.mihomo_config(SERVED_MIHOMO, str(ca_file))
            self.assertTrue(config.startswith(SERVED_MIHOMO.rstrip("\n") + "\n"))
            anchor = yaml.safe_load(config)["tls"][client_trust.MIHOMO_CA_KEY]
            self.assertEqual(len(anchor), 1)
            self.assertIn("BEGIN CERTIFICATE", anchor[0])
            self.assertEqual(anchor[0].strip(), PEM.strip())
            self.assertNotIn(str(ca_file), config, "the key takes PEM documents, not paths")

    def test_a_served_yaml_that_already_declares_tls_is_rejected_not_rewritten(self):
        with self.assertRaises(SystemExit) as caught:
            traffic_probe.mihomo_config("tls:\n  insecure: true\n", "/fixtures/ca/issued-root.pem")
        self.assertIn("already declares 'tls'", str(caught.exception))

    def test_the_matrix_reports_the_tuples_the_transfers_covered(self):
        transfers = traffic_transfers()
        matrix = traffic_probe.transfer_matrix(
            transfers,
            {"requests": [{"request_id": item["request_id"]} for item in transfers]},
            PLAN.engine_client_ip,
        )
        self.assertEqual(matrix["transfer_count"], 8)
        self.assertEqual(matrix["engines"], sorted(aio.TRAFFIC_ENGINES))
        self.assertEqual(matrix["networks"], sorted(aio.TRAFFIC_NETWORKS))
        self.assertEqual(matrix["source_ips"], [PLAN.target_ip])
        self.assertEqual(matrix["direct_source_ip"], PLAN.engine_client_ip)
        self.assertEqual(matrix["missing_request_ids"], 0)

    def test_the_matrix_names_the_request_ids_the_endpoint_never_saw(self):
        transfers = traffic_transfers()
        recorded = [{"request_id": item["request_id"]} for item in transfers[1:]]
        matrix = traffic_probe.transfer_matrix(transfers, {"requests": recorded}, PLAN.engine_client_ip)
        self.assertEqual(matrix["missing_request_ids"], 1)
        self.assertEqual(matrix["echo_records"], len(transfers) - 1)

    def test_the_probe_refuses_to_run_without_a_destination(self):
        with tempfile.TemporaryDirectory() as workdir:
            with self.assertRaises(SystemExit) as caught:
                traffic_probe.traffic("/secrets", "/fixtures/ca/root.pem", "", Path(workdir))
        self.assertIn("destination address is required", str(caught.exception))


class TestTrafficEngine(unittest.TestCase):
    """A supervised engine is started under a deadline and stopped under one."""

    def setUp(self):
        self.workdir = Path(tempfile.mkdtemp(prefix="gowave-traffic-engine-"))
        self.addCleanup(self._remove, self.workdir)
        self.log_path = self.workdir / "engine.log"
        self.pid_path = self.workdir / "engine.pid"

    def _remove(self, path):
        for pid_file in path.glob("*.pid"):
            pid_file.unlink(missing_ok=True)
        for item in sorted(path.rglob("*"), reverse=True):
            item.unlink(missing_ok=True)
        path.rmdir()

    def test_a_started_engine_is_recorded_and_stopped(self):
        pid = traffic_probe.launch_engine(["sleep", "30"], self.log_path, self.pid_path, "sleep")
        self.assertGreater(pid, 0)
        self.assertEqual(int(self.pid_path.read_text(encoding="utf-8").strip()), pid)
        self.assertTrue(traffic_probe.process_alive(pid))
        traffic_probe.wait_engine_exit(pid, 5, "sleep", self.log_path)
        self.assertFalse(traffic_probe.process_alive(pid))

    def test_the_engine_context_manager_cleans_up_its_pid_file(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        listener = (
            "import socket, time\n"
            "listener = socket.socket()\n"
            f"listener.bind(('127.0.0.1', {port}))\n"
            "listener.listen(1)\n"
            "time.sleep(60)\n"
        )
        with traffic_probe.Engine(
            [sys.executable, "-c", listener], self.log_path, self.pid_path, port, "the test listener",
        ) as engine:
            self.assertTrue(traffic_probe.process_alive(engine.pid))
            self.assertTrue(self.pid_path.exists())
        self.assertFalse(traffic_probe.process_alive(engine.pid))
        self.assertFalse(self.pid_path.exists())

    def test_an_engine_that_died_on_its_own_fails_the_case(self):
        pid = traffic_probe.launch_engine(["sleep", "0.05"], self.log_path, self.pid_path, "sleep")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and traffic_probe.process_alive(pid):
            time.sleep(0.05)
        with self.assertRaises(SystemExit) as caught:
            traffic_probe.wait_engine_exit(pid, 1, "sleep", self.log_path)
        self.assertIn("exited on its own", str(caught.exception))

    def test_an_engine_that_never_starts_fails_with_its_log(self):
        with self.assertRaises(SystemExit) as caught:
            traffic_probe.launch_engine(
                ["gowave-no-such-engine-binary"], self.log_path, self.pid_path, "the test engine",
            )
        self.assertIn("cannot start the test engine", str(caught.exception))
        self.assertIn("gowave-no-such-engine-binary", str(caught.exception))

    def test_stopping_a_process_that_is_gone_is_not_an_error(self):
        pid = traffic_probe.launch_engine(["sleep", "0.05"], self.log_path, self.pid_path, "sleep")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and traffic_probe.process_alive(pid):
            time.sleep(0.05)
        traffic_probe.stop_engine(pid)

    def test_readiness_is_bounded_when_nothing_listens(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        started = time.monotonic()
        with self.assertRaises(SystemExit) as caught:
            traffic_probe.wait_port(port, 0, "the test engine", self.log_path)
        self.assertIn("did not listen", str(caught.exception))
        self.assertLess(time.monotonic() - started, 5)

    def test_readiness_returns_when_the_listener_appears(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            traffic_probe.wait_port(port, 5, "the test engine", self.log_path)


class EchoStub(BaseHTTPRequestHandler):
    """A stand-in for the controlled endpoint: it reports what it received."""

    response = {"match": True}
    body = None
    received = []

    def do_POST(self):  # noqa: N802 - the standard library names it this way
        length = int(self.headers.get("Content-Length") or 0)
        payload = self.rfile.read(length)
        digest = hashlib.sha256(payload).hexdigest()
        type(self).received.append((self.path, self.headers.get("X-Request-Id")))
        recorded = {
            "request_id": self.headers.get("X-Request-Id"),
            "body_sha256": digest,
            "match": self.headers.get("X-Expect-SHA256") == digest,
            "source_ip": "203.0.114.10",
        }
        recorded.update(type(self).response)
        body = type(self).body if type(self).body is not None else json.dumps(recorded)
        self.send_response(200 if type(self).response.get("match", True) else 500)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body.encode("utf-8"))))
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, *_args):
        return


class TestTrafficProbeTransfer(unittest.TestCase):
    """One transfer proves itself with the endpoint's echo, not with a status."""

    def setUp(self):
        EchoStub.response = {"match": True}
        EchoStub.body = None
        EchoStub.received = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), EchoStub)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.destination = f"127.0.0.1:{self.server.server_address[1]}"
        self.label = {"tag": "vless-ws", "network": "ws"}

    def test_a_recorded_request_id_and_digest_is_what_proves_the_transfer(self):
        report = traffic_probe.transfer(None, self.destination, self.label, "xray")
        self.assertEqual(report["status"], 200)
        self.assertTrue(report["request_id_match"])
        self.assertTrue(report["body_match"])
        self.assertEqual(report["source_ip"], "203.0.114.10")
        self.assertEqual(report["engine"], "xray")
        self.assertEqual(report["network"], "ws")
        self.assertEqual(EchoStub.received, [("/traffic", report["request_id"])])

    def test_every_transfer_carries_its_own_request_id(self):
        first = traffic_probe.transfer(None, self.destination, self.label, "xray")
        second = traffic_probe.transfer(None, self.destination, self.label, "xray")
        self.assertNotEqual(first["request_id"], second["request_id"])

    def test_a_body_the_endpoint_did_not_receive_is_reported_as_a_mismatch(self):
        EchoStub.response = {"match": True, "body_sha256": "0" * 64}
        report = traffic_probe.transfer(None, self.destination, self.label, "xray")
        self.assertFalse(report["body_match"])

    def test_a_request_id_the_endpoint_did_not_echo_is_a_mismatch(self):
        EchoStub.response = {"match": True, "request_id": "someone-else"}
        report = traffic_probe.transfer(None, self.destination, self.label, "xray")
        self.assertFalse(report["request_id_match"])

    def test_a_response_without_an_endpoint_report_fails_the_case(self):
        EchoStub.body = "not json"
        with self.assertRaises(SystemExit) as caught:
            traffic_probe.transfer(None, self.destination, self.label, "xray")
        self.assertIn("without an endpoint report", str(caught.exception))

    def test_an_unreachable_endpoint_fails_the_case(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            closed = probe.getsockname()[1]
        with self.assertRaises(SystemExit) as caught:
            traffic_probe.transfer(None, f"127.0.0.1:{closed}", self.label, "xray")
        self.assertIn("did not reach the endpoint", str(caught.exception))

    def test_a_refused_transfer_is_a_result_when_refusal_is_expected(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            closed = probe.getsockname()[1]
        report = traffic_probe.transfer(
            None, f"127.0.0.1:{closed}", self.label, "xray", expect_refusal=True,
        )
        self.assertFalse(report["delivered"])
        self.assertIsNone(report["status"])
        self.assertEqual(report["engine"], "xray")
        self.assertTrue(report["reason"])
        self.assertEqual(EchoStub.received, [])

    def test_a_transfer_the_endpoint_answered_is_delivered_even_when_refusal_is_expected(self):
        report = traffic_probe.transfer(
            None, self.destination, self.label, "xray", expect_refusal=True,
        )
        self.assertTrue(report["delivered"])
        self.assertEqual(report["status"], 200)
        self.assertNotIn("reason", report)

    def test_a_refusal_never_claims_an_endpoint_report(self):
        report = traffic_probe.refusal("mihomo", self.label, "req-1", None, "ECONNREFUSED")
        self.assertEqual(report["delivered"], False)
        self.assertEqual(report["request_id"], "req-1")
        self.assertEqual(report["reason"], "ECONNREFUSED")


class TestTrafficProbeRevocation(unittest.TestCase):
    """The revoked scope retries propagation and never trusts an error message."""

    def refused(self, engine):
        return traffic_probe.refusal(
            engine, {"tag": f"{engine}-tcp", "network": "tcp"}, f"{engine}-req", None, "ECONNRESET",
        )

    def delivered(self, engine):
        return {
            "engine": engine, "tag": f"{engine}-tcp", "network": "tcp",
            "request_id": f"{engine}-req", "delivered": True, "status": 200,
            "request_id_match": True, "body_match": True, "source_ip": PLAN.target_ip,
        }

    def run_scope(self, rounds, diagnostics=None, monkey=None):
        queue = list(monkey) if monkey is not None else [
            [self.delivered("xray"), self.delivered("mihomo")],
            [self.refused("xray"), self.refused("mihomo")],
        ]

        def transfers(*_args, **_kwargs):
            return list(queue.pop(0)) if queue else [self.refused("xray")]

        with tempfile.TemporaryDirectory() as workdir:
            with mock.patch.object(traffic_probe, "xray_transfers", transfers), \
                    mock.patch.object(traffic_probe, "mihomo_transfers", lambda *a, **k: []), \
                    mock.patch.object(traffic_probe, "echo_diagnostics",
                                      lambda *a, **k: diagnostics or {"requests": []}), \
                    mock.patch.object(traffic_probe.time, "sleep") as sleep:
                facts = traffic_probe.revoked(
                    "/secrets/revoke", "/fixtures/ca/root.pem", "203.0.114.30:18080",
                    Path(workdir), rounds=rounds,
                )
        return facts, sleep

    def test_propagation_is_retried_until_every_transport_refuses(self):
        facts, sleep = self.run_scope(rounds=3)
        self.assertEqual(facts["rounds"], 2)
        self.assertEqual(facts["delivered"], 0)
        self.assertEqual(facts["refused"], 2)
        self.assertEqual(facts["attempt_count"], 2)
        self.assertEqual(facts["recorded_request_ids"], 0)
        sleep.assert_called_once_with(traffic_probe.REVOCATION_ROUND_PAUSE_SECONDS)

    def test_the_scope_fails_when_a_revoked_transport_still_delivers(self):
        with self.assertRaises(SystemExit) as caught:
            self.run_scope(rounds=2, monkey=[[self.delivered("xray")], [self.delivered("xray")]])
        self.assertIn("still reached the endpoint after 2 rounds", str(caught.exception))

    def test_the_scope_fails_when_the_endpoint_recorded_a_revoked_request(self):
        with self.assertRaises(SystemExit) as caught:
            self.run_scope(rounds=1, monkey=[[self.refused("xray")]],
                           diagnostics={"requests": [{"request_id": "xray-req"}]})
        self.assertIn("recorded a request from revoked access", str(caught.exception))

    def test_the_scope_fails_when_no_outbound_could_be_attempted(self):
        with self.assertRaises(SystemExit) as caught:
            self.run_scope(rounds=1, monkey=[[]])
        self.assertIn("no outbound was exercised", str(caught.exception))

    def test_the_scope_refuses_to_run_without_a_destination(self):
        with tempfile.TemporaryDirectory() as workdir:
            with self.assertRaises(SystemExit) as caught:
                traffic_probe.revoked("/secrets", "/fixtures/ca/root.pem", "", Path(workdir))
        self.assertIn("destination address is required", str(caught.exception))


class TestTrafficProbeProhibited(unittest.TestCase):
    """The policy scope: a denial counts only after the permitted control arrived."""

    PROHIBITED = "10.89.0.30:18080"
    PERMITTED = "203.0.114.30:18080"

    def delivered(self):
        return {
            "engine": "xray", "tag": "vless-reality-tcp", "network": "tcp",
            "request_id": "xray-control", "delivered": True, "status": 200,
            "request_id_match": True, "body_match": True, "source_ip": PLAN.data_target_ip,
        }

    def refused(self):
        return traffic_probe.refusal(
            "xray", {"tag": "vless-reality-tcp", "network": "tcp"},
            "xray-prohibited", None, "HTTP 503 without an endpoint report",
        )

    def run_scope(self, control, attempt, recorded=("xray-control",), destination=None):
        sequence = [control, attempt]
        with tempfile.TemporaryDirectory() as workdir:
            with mock.patch.object(traffic_probe, "xray_transfers",
                                   lambda *a, **k: list(sequence.pop(0))), \
                    mock.patch.object(
                        traffic_probe, "echo_diagnostics",
                        lambda *a, **k: {"requests": [{"request_id": rid} for rid in recorded]},
                    ):
                return traffic_probe.prohibited(
                    "/secrets", "/fixtures/ca/root.pem",
                    destination if destination is not None else self.PROHIBITED,
                    Path(workdir), report_destination=self.PERMITTED,
                )

    def test_a_refused_prohibited_destination_is_a_result_when_the_control_arrived(self):
        facts = self.run_scope([self.delivered()], [self.refused()])
        self.assertTrue(facts["control_delivered"])
        self.assertFalse(facts["delivered"])
        self.assertEqual(facts["recorded_request_ids"], 0)
        self.assertIn("503", facts["reason"])

    def test_a_control_that_never_reached_the_endpoint_proves_nothing(self):
        with self.assertRaises(SystemExit) as caught:
            self.run_scope([self.refused()], [self.refused()], recorded=())
        self.assertIn("would prove nothing", str(caught.exception))

    def test_the_scope_fails_when_the_endpoint_recorded_a_prohibited_request(self):
        with self.assertRaises(SystemExit) as caught:
            self.run_scope([self.delivered()], [self.refused()],
                           recorded=("xray-control", "xray-prohibited"))
        self.assertIn("recorded a payload sent to a destination", str(caught.exception))

    def test_the_scope_refuses_to_run_without_a_destination(self):
        with self.assertRaises(SystemExit) as caught:
            self.run_scope([self.delivered()], [self.refused()], destination="")
        self.assertIn("prohibited destination is required", str(caught.exception))


class TestTrafficProbeReadiness(unittest.TestCase):
    """The readiness scope: one tunnel, judged by what the endpoint recorded."""

    def run_scope(self, attempt, diagnostics=None, destination="203.0.114.30:18080"):
        calls = []

        def transfers(*_args, **kwargs):
            calls.append(kwargs.get("limit"))
            return [attempt]

        with tempfile.TemporaryDirectory() as workdir:
            with mock.patch.object(traffic_probe, "xray_transfers", transfers), \
                    mock.patch.object(traffic_probe, "echo_diagnostics",
                                      lambda *a, **k: diagnostics or {"requests": []}):
                facts = traffic_probe.warmup(
                    "/secrets", "/fixtures/ca/root.pem", destination, Path(workdir),
                )
        return facts, calls

    def delivered(self, request_id="xray-req"):
        return {
            "engine": "xray", "tag": "xray-tcp", "network": "tcp",
            "request_id": request_id, "delivered": True, "status": 200,
            "request_id_match": True, "body_match": True, "source_ip": PLAN.target_ip,
        }

    def test_one_profile_is_probed_and_the_endpoint_must_record_it(self):
        facts, calls = self.run_scope(
            self.delivered(), diagnostics={"requests": [{"request_id": "xray-req"}]},
        )
        self.assertTrue(facts["delivered"])
        self.assertEqual(facts["network"], "tcp")
        self.assertEqual(calls, [traffic_probe.WARMUP_PROFILES])

    def test_a_proxy_that_answers_without_carrying_the_payload_is_not_ready(self):
        facts, _ = self.run_scope(self.delivered(), diagnostics={"requests": []})
        self.assertFalse(facts["delivered"])
        self.assertFalse(facts["recorded"])

    def test_a_refusal_is_reported_as_not_ready_instead_of_an_error(self):
        refused = traffic_probe.refusal(
            "xray", {"tag": "xray-tcp", "network": "tcp"}, "xray-req", None,
            "HTTP 503 without an endpoint report",
        )
        facts, _ = self.run_scope(refused)
        self.assertFalse(facts["delivered"])
        self.assertIn("HTTP 503", facts["reason"])

    def test_the_scope_refuses_to_run_without_a_destination(self):
        with tempfile.TemporaryDirectory() as workdir:
            with self.assertRaises(SystemExit) as caught:
                traffic_probe.warmup("/secrets", "/fixtures/ca/root.pem", "", Path(workdir))
        self.assertIn("destination address is required", str(caught.exception))


class ScriptedPodman:
    """Podman stub that answers only the host-side subscription fetch."""

    def __init__(self, context, result=None):
        self.context = context
        self.scripts = []
        self.result = result or (json.dumps({"subscriptions": {}}), 0)

    def exec_bash(self, name, script, check=True, input_text=None, timeout=300):
        self.scripts.append(script)
        stdout, returncode = self.result
        return subprocess.CompletedProcess(["bash", "-lc", script], returncode, stdout, "")


class StubEngineHost:
    """The installed host, without containers, plus the engine-side probes."""

    def __init__(self, facts=None, returncode=0, stdout=None, bodies=None):
        self.target_name = "aio-1"
        self.panel_domain = aio.PANEL_DOMAIN
        self.reality_domain = aio.REALITY_DOMAIN
        self.vision_domain = None
        self.plan = PLAN
        self.scopes = []
        self.payload_dirs = []
        self.facts = facts
        self.returncode = returncode
        self.stdout = stdout
        self.bodies = bodies or {}

    def traffic_facts(self, scope, timeout=900, payload_dir=None):
        self.scopes.append(scope)
        self.payload_dirs.append(payload_dir)
        if scope in self.bodies:
            body, returncode = json.dumps(self.bodies[scope]), 0
        else:
            body = self.stdout if self.stdout is not None else json.dumps(self.facts or {})
            returncode = self.returncode
        return subprocess.CompletedProcess(
            ["python3", "traffic_probe.py"], returncode, body,
            "" if returncode == 0 else "the endpoint never answered",
        )


def installed_product(context, facts=None, returncode=0, stdout=None, bodies=None):
    podman = ScriptedPodman(context)
    product = aio.AioProduct(podman)
    product.host = StubEngineHost(facts=facts, returncode=returncode, stdout=stdout, bodies=bodies)
    product.outcome = topology.InstallOutcome(0, "", "", 1.0, "install")
    return product, podman


class TestTrafficCase(unittest.TestCase):
    """AIO-TRAFFIC accepts only what the endpoint recorded."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.context = RunContext(
            topology="aio",
            artifact_root=Path(self.tmp.name),
            budget_seconds=900,
            run_id="podman-traffic-test-000000",
        )
        self.addCleanup(self.context.run_cleanup)

    def reject(self, expected, mutate=None, facts=None):
        data = traffic_facts() if facts is None else facts
        if mutate is not None:
            mutate(data)
        product, _ = installed_product(self.context, facts=data)
        with self.assertRaises(AssertionError) as caught:
            aio.case_traffic(product)
        self.assertIn(expected, str(caught.exception))

    def test_the_case_accepts_a_matrix_every_recorded_transfer_supports(self):
        product, podman = installed_product(self.context, facts=traffic_facts())
        evidence = aio.case_traffic(product)
        self.assertEqual(evidence["transfer_count"], 8)
        self.assertEqual(evidence["engines"], "mihomo,xray")
        self.assertEqual(evidence["networks"], ",".join(sorted(aio.TRAFFIC_NETWORKS)))
        self.assertEqual(
            evidence["tuples"],
            "mihomo:tcp:reality,mihomo:ws:tls,mihomo:grpc:tls,mihomo:xhttp:tls,"
            "xray:tcp:reality,xray:ws:tls,xray:grpc:tls,xray:xhttp:tls",
        )
        self.assertEqual(evidence["source_ips"], PLAN.target_ip)
        self.assertEqual(evidence["direct_source_ip"], PLAN.engine_client_ip)
        self.assertEqual(evidence["echo_records"], 8)
        self.assertEqual(product.host.scopes, ["traffic"])
        self.assertIn("--scope subscriptions", podman.scripts[0])
        for value in evidence.values():
            self.assertIsInstance(
                value, (str, int, float, bool, type(None)),
                "evidence is flattened to strings by the runner, so it must hold primitives",
            )

    def test_the_case_fails_when_no_outbound_was_exercised(self):
        self.reject("no served outbound was exercised",
                    mutate=lambda data: data.update(transfers=[], transfer_count=0))

    def test_the_case_fails_when_a_payload_never_reached_the_endpoint(self):
        self.reject("never reached the controlled endpoint",
                    mutate=lambda data: data.update(missing_request_ids=1))

    def test_the_case_fails_when_the_endpoint_rejected_the_transfer(self):
        self.reject("instead of 200",
                    mutate=lambda data: data["transfers"][0].update(status=502))

    def test_the_case_fails_when_the_request_id_was_not_echoed(self):
        self.reject("did not echo the mihomo/tcp request id",
                    mutate=lambda data: data["transfers"][0].update(request_id_match=False))

    def test_the_case_fails_when_the_payload_digest_did_not_match(self):
        self.reject("did not receive the exact mihomo/tcp payload",
                    mutate=lambda data: data["transfers"][0].update(body_match=False))

    def test_the_case_fails_when_the_transfer_left_from_the_client(self):
        self.reject("did not traverse the product",
                    mutate=lambda data: data["transfers"][0].update(source_ip=PLAN.engine_client_ip))

    def test_the_case_fails_when_an_engine_missed_a_core_transport(self):
        self.reject("instead of every core transport",
                    mutate=lambda data: data.update(
                        transfers=[item for item in data["transfers"]
                                   if not (item["engine"] == "xray" and item["network"] == "ws")],
                    ))

    def test_the_case_fails_when_an_engine_exercised_more_than_one_reality_outbound(self):
        self.reject("expected exactly one",
                    mutate=lambda data: data["transfers"][1].update(
                        security="reality", sni=topology.PANEL_DOMAIN,
                    ))

    def test_the_case_fails_when_a_secured_outbound_carries_no_sni(self):
        self.reject("carries no SNI",
                    mutate=lambda data: data["transfers"][1].update(sni=""))

    def test_the_case_fails_when_the_control_request_came_from_the_product(self):
        self.reject("source attribution was not calibrated",
                    mutate=lambda data: data.update(direct_source_ip=PLAN.target_ip))

    def test_the_case_fails_when_the_endpoint_recorded_fewer_requests(self):
        self.reject("recorded",
                    mutate=lambda data: data.update(echo_records=1))

    def test_the_case_fails_when_the_probe_exits_non_zero(self):
        product, _ = installed_product(self.context, returncode=1)
        with self.assertRaises(AssertionError) as caught:
            aio.case_traffic(product)
        self.assertIn("traffic probe exited 1", str(caught.exception))
        self.assertIn("the endpoint never answered", str(caught.exception))

    def test_the_case_fails_when_the_probe_prints_no_json(self):
        product, _ = installed_product(self.context, stdout="transfers: 8")
        with self.assertRaises(AssertionError) as caught:
            aio.case_traffic(product)
        self.assertIn("did not print JSON", str(caught.exception))

    def test_the_case_is_blocked_when_the_payloads_were_never_fetched(self):
        product, podman = installed_product(self.context, facts=traffic_facts())
        product._subscription_error = "the subscription probe exited 1"
        with self.assertRaises(CaseBlocked) as caught:
            aio.case_traffic(product)
        self.assertIn("SUB-SERVED", str(caught.exception))
        self.assertEqual(podman.scripts, [])
        self.assertEqual(product.host.scopes, [])

    def test_the_case_is_part_of_the_aio_suite_with_its_own_budget(self):
        podman = ScriptedPodman(self.context)
        cases = {case.id: case for case in aio.cases(podman)}
        self.assertIn("AIO-TRAFFIC", cases)
        self.assertEqual(cases["AIO-TRAFFIC"].topology, "aio")
        self.assertEqual(cases["AIO-TRAFFIC"].timeout_seconds, aio.TRAFFIC_TIMEOUT_SECONDS)


class TestRevocationCase(unittest.TestCase):
    """AIO-REVOKE judges revocation by what the endpoint refused to record."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.context = RunContext(
            topology="aio",
            artifact_root=Path(self.tmp.name),
            budget_seconds=900,
            run_id="podman-revoke-test-000000",
        )
        self.addCleanup(self.context.run_cleanup)

    def issue(self):
        return {
            "squad_requested": True,
            "create_status": 201,
            "created_id_present": True,
            "created_short_uuid_length": 16,
            "patch_status": 200,
            "patch_visible": True,
            "representations": {name: {"status": 200, "bytes": 512} for name in aio.REPRESENTATIONS},
            "credential_digest": "a" * 64,
        }

    def applied(self):
        return {
            "revoke_status": 200,
            "revoked_at_present": True,
            "short_uuid_length": 16,
            "short_uuid_rotated": True,
            "status_field": "revoked",
            "readback_status": 200,
            "old_subscription_status": 404,
            "new_subscription_status": 200,
            "credential_digest": "b" * 64,
            "credential_digest_changed": True,
        }

    def cleanup_facts(self):
        return {"delete_status": 204, "after_delete_status": 404}

    def revoked_facts(self):
        attempts = [{"engine": engine, "tag": f"{engine}-tcp", "network": "tcp",
                     "request_id": f"{engine}-req", "delivered": False, "status": None,
                     "reason": "ConnectionRefusedError"}
                    for engine in aio.TRAFFIC_ENGINES for _ in range(aio.CORE_INBOUNDS)]
        return {
            "attempts": attempts,
            "attempt_count": len(attempts),
            "engines": sorted(aio.TRAFFIC_ENGINES),
            "networks": sorted(aio.TRAFFIC_NETWORKS),
            "refused": len(attempts),
            "delivered": 0,
            "rounds": 2,
            "endpoint_records": 0,
            "recorded_request_ids": 0,
        }

    def run_case(self, positive=None, negative=None, steps=None, calls=None, readiness=None):
        overrides = steps or {}
        bodies = {
            "warmup": readiness or {
                "delivered": True, "engine": "xray", "network": "tcp",
                "status": 200, "reason": "", "recorded": True,
            },
            "traffic": traffic_facts() if positive is None else positive,
            "revoked": self.revoked_facts() if negative is None else negative,
        }
        product, _ = installed_product(self.context, bodies=bodies)
        answers = {
            "issue": self.issue(),
            "apply": self.applied(),
            "cleanup": self.cleanup_facts(),
        }
        if calls is None:
            calls = []

        def probe(_product, _case_id, _scope, extra=""):
            step = extra.split("--step ")[1].split()[0]
            calls.append(step)
            return {"revocation": dict(answers[step], **overrides.get(step, {}))}

        with mock.patch.object(aio, "panel_probe", probe):
            return aio.case_revocation(product), calls, product

    def reject(self, expected, **kwargs):
        with self.assertRaises(AssertionError) as caught:
            self.run_case(**kwargs)
        self.assertIn(expected, str(caught.exception))

    def test_the_case_accepts_access_the_endpoint_refused_to_record(self):
        facts, calls, product = self.run_case()
        self.assertEqual(calls, ["issue", "apply", "cleanup"])
        self.assertEqual(product.host.scopes, ["warmup", "traffic", "revoked"])
        self.assertEqual(
            product.host.payload_dirs, [f"{topology.SECRETS_MOUNT}/revoke"] * 3,
            "every traffic scope replays the payload captured before the revocation, "
            "through the mount the engine client actually sees",
        )
        self.assertEqual(facts["revoke_status"], 200)
        self.assertEqual(facts["old_subscription_status"], 404)
        self.assertEqual(facts["revoked_delivered"], 0)
        self.assertEqual(facts["recorded_request_ids"], 0)
        self.assertTrue(facts["credential_digest_changed"])

    def test_the_case_waits_for_the_issued_client_before_transferring(self):
        readiness = {"delivered": False, "engine": "xray", "network": "tcp",
                     "status": None, "reason": "HTTP 503 without an endpoint report",
                     "recorded": False}
        with mock.patch.object(aio, "wait_until", lambda predicate, *args, **kwargs: predicate()):
            with self.assertRaises(AssertionError) as caught:
                self.run_case(readiness=readiness)
        message = str(caught.exception)
        self.assertIn("no served outbound carried a payload", message)
        self.assertIn("HTTP 503 without an endpoint report", message)

    def test_the_case_fails_when_the_client_could_not_be_created(self):
        self.reject("instead of 201", steps={"issue": {"create_status": 409}})

    def test_the_case_fails_when_the_client_got_no_squad(self):
        self.reject("no 'Default MVP Squad'", steps={"issue": {"squad_requested": False}})

    def test_the_case_fails_when_the_traffic_limit_was_not_updated(self):
        self.reject("PATCH /api/users/{id} returned 500", steps={"issue": {"patch_status": 500}})

    def test_the_case_fails_when_a_representation_was_not_served(self):
        representations = {name: {"status": 200} for name in aio.REPRESENTATIONS}
        representations["mihomo"] = {"status": 500}
        self.reject("not served: mihomo", steps={"issue": {"representations": representations}})

    def test_the_case_fails_when_the_issued_client_could_not_transfer(self):
        data = traffic_facts()
        data["transfer_count"] = 4
        self.reject("transferred through 4 transports", positive=data)

    def test_the_case_fails_when_the_issued_payload_left_from_the_client(self):
        data = traffic_facts()
        data["source_ips"] = [PLAN.engine_client_ip]
        self.reject("instead of the installed host", positive=data)

    def test_the_case_fails_when_the_revoke_action_was_refused(self):
        self.reject("actions/revoke returned 500", steps={"apply": {"revoke_status": 500}})

    def test_the_case_fails_when_no_revocation_was_recorded(self):
        self.reject("no subRevokedAt", steps={"apply": {"revoked_at_present": False}})

    def test_the_case_fails_when_the_old_subscription_still_answers(self):
        self.reject("still answers with 200", steps={"apply": {"old_subscription_status": 200}})

    def test_the_case_fails_when_the_credentials_were_not_rotated(self):
        self.reject("same credentials as before", steps={"apply": {"credential_digest_changed": False}})

    def test_the_case_fails_when_revoked_access_still_delivered(self):
        data = self.revoked_facts()
        data["delivered"] = 1
        data["refused"] = data["attempt_count"] - 1
        self.reject("still delivered a payload", negative=data)

    def test_the_case_fails_when_the_endpoint_recorded_a_revoked_request(self):
        data = self.revoked_facts()
        data["recorded_request_ids"] = 1
        self.reject("recorded a request sent with revoked access", negative=data)

    def test_the_case_fails_when_the_revoked_scope_attempted_fewer_transports(self):
        data = self.revoked_facts()
        data["attempt_count"] = 4
        data["refused"] = 4
        self.reject("exercised 4 transports", negative=data)

    def test_the_case_fails_when_the_client_was_not_deleted(self):
        self.reject("instead of 204", steps={"cleanup": {"delete_status": 500}})

    def test_the_client_is_deleted_even_when_the_positive_run_failed(self):
        data = traffic_facts()
        data["transfer_count"] = 0
        calls = []
        with self.assertRaises(AssertionError) as caught:
            self.run_case(positive=data, calls=calls)
        self.assertIn("transferred through 0 transports", str(caught.exception))
        self.assertEqual(calls, ["issue", "cleanup"],
                         "the failed run must still delete the client it created")

    def test_the_case_is_part_of_the_aio_suite_with_its_own_budget(self):
        podman = ScriptedPodman(self.context)
        cases = {case.id: case for case in aio.cases(podman)}
        self.assertIn("AIO-REVOKE", cases)
        self.assertEqual(cases["AIO-REVOKE"].topology, "aio")
        self.assertEqual(cases["AIO-REVOKE"].timeout_seconds,
                         aio.TUNNEL_READY_TIMEOUT_SECONDS + 2 * aio.TRAFFIC_TIMEOUT_SECONDS)


class RecordingPodman:
    """Podman stub for the topology wiring: no container is really created."""

    def __init__(self):
        self.artifacts = Path(tempfile.mkdtemp(prefix="gowave-traffic-topology-"))
        self.context = RunContext(topology="aio", artifact_root=self.artifacts, budget_seconds=3600)
        self.networks = []
        self.connects = []
        self.runs = []
        self.builds = []
        self.execs = []
        self.waits = []

    def network_subnets(self):
        return []

    def network_create(self, name, subnet=None, disable_dns=False, internal=False):
        self.networks.append((name, subnet, disable_dns, internal))
        return name

    def network_connect(self, name, network, ip=None):
        self.connects.append((name, network, ip))
        return name

    def run(self, **kwargs):
        self.runs.append(kwargs)
        return kwargs["name"]

    def build(self, tag, base_alias, containerfile, context_dir=None, build_args=None):
        self.builds.append({
            "tag": tag,
            "base_alias": base_alias,
            "containerfile": Path(containerfile),
            "context_dir": Path(context_dir),
            "build_args": dict(build_args or {}),
        })
        return tag

    def wait_tcp(self, name, host, port, timeout_seconds=60):
        self.waits.append((name, host, port))

    def wait_systemd(self, name, timeout_seconds=90):
        self.waits.append((name, "systemd"))
        return "running"

    def exec(self, name, argv, check=True, input_text=None, timeout=300):
        self.execs.append((name, list(argv)))
        if len(argv) == 3 and argv[2] == target_image.cleanliness_probe():
            return subprocess.CompletedProcess(
                argv, 0, "init=systemd\nsystemd=systemd 255\nsshd=active\n", ""
            )
        return subprocess.CompletedProcess(argv, 0, "{}", "")

    def exec_bash(self, name, script, check=True, input_text=None, timeout=300):
        return subprocess.CompletedProcess(["bash", "-lc", script], 0, "install ok", "")


def run_for(runs, name):
    for kwargs in runs:
        if kwargs["name"] == name:
            return kwargs
    raise AssertionError(f"{name} was not started: {[item['name'] for item in runs]}")


class TestTrafficTopology(unittest.TestCase):
    """The endpoint the payloads must reach, and the client that sends them."""

    def setUp(self):
        self.podman = RecordingPodman()
        self.addCleanup(self.podman.context.run_cleanup)
        self.instance = topology.AioTopology(self.podman, egress_resolvers=["192.0.2.53"])
        self.leaf_dir = Path(tempfile.mkdtemp(prefix="gowave-traffic-leaf-"))
        self.addCleanup(self._remove_leaf)
        leaf = {}
        for name in (topology.ECHO_CERT_NAME, topology.ECHO_KEY_NAME):
            path = self.leaf_dir / name
            path.write_text(f"leaf {name}", encoding="utf-8")
            leaf[name] = path
        self.leaf = {"cert": leaf[topology.ECHO_CERT_NAME], "key": leaf[topology.ECHO_KEY_NAME]}
        for target, value in (
            (acme_fixture.AcmeFixture, "issued_root"),
            (acme_fixture.AcmeFixture, "wait_ready"),
            (acme_fixture, "generate_leaf"),
        ):
            patcher = mock.patch.object(target, value, return_value=self._stub_value(value))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.instance.create()

    def _stub_value(self, name):
        if name == "issued_root":
            return PEM
        if name == "wait_ready":
            return None
        return self.leaf

    def _remove_leaf(self):
        for item in sorted(self.leaf_dir.rglob("*"), reverse=True):
            item.unlink(missing_ok=True)
        self.leaf_dir.rmdir()

    def test_the_endpoint_is_a_controlled_fixture_on_the_run_network(self):
        echo = run_for(self.podman.runs, self.instance.echo_name)
        self.assertEqual(echo["image_alias"], topology.FIXTURE_IMAGE)
        self.assertFalse(echo["privileged"])
        self.assertEqual(echo["systemd"], "false")
        self.assertEqual(echo["aliases"], (topology.ECHO_HOST,))
        self.assertIn(f"{self.instance._ca_dir}:{topology.CA_MOUNT}:ro,Z", echo["volumes"])
        self.assertIn(f"{self.instance.echo_dir}:{topology.ECHO_MOUNT}:Z", echo["volumes"])
        command = echo["command"]
        self.assertEqual(command[:2], ("python3", topology.ECHO_FIXTURE_SCRIPT))
        self.assertEqual(command[command.index("--http-port") + 1], str(topology.ECHO_HTTP_PORT))
        self.assertEqual(command[command.index("--https-port") + 1], str(topology.ECHO_HTTPS_PORT))
        self.assertEqual(command[command.index("--control") + 1], f"{topology.ECHO_MOUNT}/control.json")
        self.assertEqual(command[command.index("--log") + 1], f"{topology.ECHO_MOUNT}/requests.jsonl")
        self.assertEqual(command[command.index("--cert") + 1],
                         f"{topology.CA_MOUNT}/{topology.ECHO_CERT_NAME}")
        self.assertEqual(command[command.index("--key") + 1],
                         f"{topology.CA_MOUNT}/{topology.ECHO_KEY_NAME}")
        extra = echo["extra_args"]
        self.assertEqual(extra[extra.index("--ip") + 1], self.instance.plan.echo_ip)
        self.assertEqual(extra[extra.index("--dns") + 1], self.instance.plan.dns_ip)
        self.assertIn(
            (self.instance.echo_name, "127.0.0.1", topology.ECHO_HTTP_PORT),
            self.podman.waits,
        )

    def test_the_endpoint_leaf_is_issued_by_the_fixture_ca(self):
        for leaf_name, copied_name in (
            ("cert", topology.ECHO_CERT_NAME),
            ("key", topology.ECHO_KEY_NAME),
        ):
            path = self.instance._ca_dir / copied_name
            self.assertTrue(path.exists())
            self.assertEqual(path.read_text(encoding="utf-8"),
                             self.leaf[leaf_name].read_text(encoding="utf-8"))
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_the_endpoint_record_directory_is_run_scoped_and_private(self):
        self.assertEqual(self.instance.echo_dir.parent, self.instance.context.secret_dir)
        self.assertEqual(self.instance.echo_dir.stat().st_mode & 0o777, 0o700)
        self.assertNotIn(str(self.podman.artifacts), str(self.instance.echo_dir))

    def test_the_fixture_zone_answers_for_the_endpoint(self):
        records = topology.zone(self.instance.plan)["records"]
        self.assertEqual(records[topology.ECHO_HOST], {"A": [self.instance.plan.echo_ip]})

    def test_the_traffic_probe_reads_the_payloads_and_targets_the_endpoint(self):
        self.instance.traffic_facts("traffic")
        name, argv = self.podman.execs[-1]
        self.assertEqual(name, self.instance.engine_client_name)
        self.assertEqual(argv[:2], ["python3", topology.TRAFFIC_PROBE_SCRIPT])
        self.assertEqual(argv[argv.index("--scope") + 1], "traffic")
        self.assertEqual(argv[argv.index("--payload-dir") + 1], topology.SECRETS_MOUNT)
        self.assertEqual(argv[argv.index("--ca") + 1], f"{topology.CA_MOUNT}/{topology.ISSUED_ROOT_NAME}")
        self.assertEqual(argv[argv.index("--destination") + 1],
                         f"{self.instance.plan.data_echo_ip}:{topology.ECHO_HTTP_PORT}")
        self.assertNotIn(CLIENT_SECRET, " ".join(argv))

    def test_the_engine_client_reaches_both_the_control_plane_and_the_endpoint(self):
        self.instance.engine_client()
        self.assertIn(
            (self.instance.engine_client_name, self.instance.data_network,
             self.instance.plan.data_engine_client_ip),
            self.podman.connects,
            "the control transfer has to address the same literal the tunnel does",
        )

    def test_the_engine_client_pins_the_names_the_served_templates_resolve(self):
        self.instance.engine_client()
        engine = run_for(self.podman.runs, self.instance.engine_client_name)
        extra = list(engine["extra_args"])
        self.assertIn(f"{aio.PANEL_DOMAIN}:{self.instance.plan.target_ip}", extra)
        self.assertIn(f"{aio.REALITY_DOMAIN}:{self.instance.plan.target_ip}", extra)
        self.assertIn(self.instance.plan.engine_client_ip, extra)
        self.assertNotIn(self.instance.plan.echo_ip, extra)


if __name__ == "__main__":
    unittest.main()
