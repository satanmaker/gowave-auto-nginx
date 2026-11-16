#!/usr/bin/env python3
"""Suite nonroot: the packet bracket must decide, and must not persist anything.

A capture is only worth its verdict if three things hold: the port it filters on
is the port the product was installed on, the evidence it produces is a summary
the harness reads rather than a file it forgets to delete, and the branch that
turns the summary into PASS, FAIL or INCOMPLETE refuses to pass on evidence it
does not have. Each of those is held here.
"""
import ast
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import ingress, matrix  # noqa: E402
from tools.podman_e2e.ingress import Host, IngressUnavailable, Measurement  # noqa: E402
from tools.podman_e2e.runner import CaseIncomplete  # noqa: E402

PROBE = REPO_ROOT / "tools" / "podman_e2e" / "ingress_probe.py"
HARNESS = REPO_ROOT / "tools" / "podman_e2e" / "ingress.py"

CLIENT = "203.0.113.7"
OTHER = "198.51.100.9"


def summary(captured=3, sources=None, stopped_by="harness", drops=0):
    return {
        "captured": captured,
        "sources": sources if sources is not None else {CLIENT: captured},
        "stopped_by": stopped_by,
        "drops": drops,
    }


class FakeSession:
    """A probe that answers from a script instead of a socket."""

    def __init__(self, container, argv, backend):
        self.container = container
        self.role = container.removesuffix("-container")
        self.argv = list(argv)
        self.backend = backend
        self.messages = []
        self.released = False
        self.abandoned = False
        scope = self.argv[self.argv.index("--scope") + 1]
        if scope == "hold":
            for index, item in enumerate(self.argv):
                if item == "--peer":
                    role_name, _, _endpoint = self.argv[index + 1].partition("=")
                    self.messages.append({"held": role_name, "local_port": 40000 + len(role_name)})
        else:
            failure = backend.capture_errors.get(self.role)
            if failure:
                self.messages.append({"error": failure[0], "detail": failure[1]})
            else:
                self.messages.append({"ready": True, "scope": "packets", "port": 443})

    def message(self, timeout):
        return self.messages.pop(0) if self.messages else {}

    def release(self):
        self.released = True

    def finish(self, timeout=0):
        self.released = True
        if self.role in self.backend.summaries:
            return self.backend.summaries[self.role]
        return summary()

    def abandon(self):
        self.abandoned = True


class FakeBackend(ingress.Backend):
    """Stands in for `podman exec`, recording what would have been run."""

    def __init__(self, summaries=None, identity_error="", capture_errors=None):
        self.summaries = summaries or {}
        self.identity_error = identity_error
        self.capture_errors = capture_errors or {}
        self.sessions = []
        self.runs = []
        self.deadlines = []

    def spawn_probe(self, container, argv, timeout=ingress.SUMMARY_TIMEOUT_SECONDS):
        self.deadlines.append(float(timeout))
        session = FakeSession(container, argv, self)
        self.sessions.append(session)
        return session

    def run(self, container, argv, timeout=60):
        self.runs.append((container, list(argv)))
        if self.identity_error:
            payload = {"error": self.identity_error, "detail": "the client could not connect"}
        else:
            payload = {"peer": CLIENT, "family": "ipv4", "state": "ESTABLISHED"}
        return subprocess.CompletedProcess(list(argv), 0, json.dumps(payload), "")


def fake_hosts(*roles):
    return [Host(role=role, container=f"{role}-container", name=f"{role}.gowave.test") for role in roles]


class TestListenerPort(unittest.TestCase):
    """The filter names the port a client dials, or nothing at all."""

    def test_every_matrix_inbound_is_captured_on_the_port_its_host_record_publishes(self):
        candidates = matrix.load()["inbounds"]
        self.assertTrue(candidates)
        for candidate in candidates:
            published = int(candidate["host_record"]["port"])
            self.assertEqual(
                ingress.listener_port(candidate), published,
                f"{candidate.get('id')} publishes {candidate['host_record']['port']}",
            )
        self.assertEqual(
            {int(candidate["host_record"]["port"]) for candidate in candidates}, {443},
            "every Host record is dialled through NGINX on 443",
        )

    def test_the_published_port_clause_fails_when_the_internal_listener_is_read(self):
        # The damage this guard exists for: Vision's own listener is 8443 inside
        # the node, and a client reaches the tuple on 443 through the stream
        # demultiplexer. A capture on the internal port is empty for a request
        # that arrived, which is the account the evaluate() branch must refuse to
        # read as a pass — so the derivation is what keeps the verdict possible.
        vision = next(candidate for candidate in matrix.load()["inbounds"] if candidate["id"] == "VISION")
        internal = int(str(vision["listener"]).partition("/")[0])
        published = int(vision["host_record"]["port"])
        self.assertNotEqual(internal, published, "the Vision tuple binds the port a client dials")
        self.assertEqual(ingress.listener_port(vision), published)
        damaged = Measurement(
            port=internal,
            intended="local",
            client=CLIENT,
            addresses={"local": CLIENT},
            captures={"local": {"captured": 0, "sources": {}, "stopped_by": "harness", "drops": 0}},
        )
        facts = ingress.evaluate(damaged)
        self.assertEqual(facts["verdict"], ingress.INCOMPLETE)
        self.assertIn(f"captured nothing on port {internal}", facts["reason"])

    def test_a_listener_that_names_no_port_is_refused_rather_than_guessed(self):
        with self.assertRaises(IngressUnavailable) as caught:
            ingress.listener_port({"id": "X", "listener": "not-a-port"})
        self.assertEqual(caught.exception.code, "no_endpoint_port")

    def test_an_absent_listener_is_refused(self):
        with self.assertRaises(IngressUnavailable) as caught:
            ingress.listener_port({"id": "X"})
        self.assertEqual(caught.exception.code, "no_endpoint_port")

    def test_a_tuple_that_publishes_no_port_is_refused_instead_of_read_from_its_listener(self):
        with self.assertRaises(IngressUnavailable) as caught:
            ingress.listener_port({"id": "X", "listener": "8443/tcp", "host_record": {"port": None}})
        self.assertEqual(caught.exception.code, "no_endpoint_port")
        self.assertIn("publishes host_record.port None", str(caught.exception))
        self.assertIn("declares listener '8443/tcp'", str(caught.exception))


class TestProbePersistsNothing(unittest.TestCase):
    """What PKT-02 promises: no PCAP and no payload ever reaches a file.

    The claim is about the shipped code, so it is read from the shipped code: a
    probe that opened a capture file would pass every summary test in this file
    and still leave a PCAP on a host the requirement says must have none.
    """

    def setUp(self):
        self.tree = ast.parse(PROBE.read_text(encoding="utf-8"))

    def test_no_write_mode_is_opened(self):
        openings = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "open":
                openings.append(node)
        for call in openings:
            mode = ""
            if len(call.args) > 1 and isinstance(call.args[1], ast.Constant):
                mode = str(call.args[1].value)
            for keyword in call.keywords:
                if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
                    mode = str(keyword.value.value)
            self.assertFalse(
                set(mode) & set("wax+"),
                f"ingress_probe.py opens a file for writing at line {call.lineno} (mode {mode!r})",
            )

    def test_the_probe_starts_no_other_process(self):
        imported = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
        for forbidden in ("subprocess", "shutil", "tempfile"):
            self.assertNotIn(forbidden, imported)

    def test_the_kernel_drop_count_is_read(self):
        text = PROBE.read_text(encoding="utf-8")
        self.assertIn("PACKET_STATISTICS", text)
        self.assertIn("drops", text)

    def test_the_harness_never_asks_a_host_for_a_capture_file(self):
        text = HARNESS.read_text(encoding="utf-8")
        self.assertNotIn(".pcap", text)
        self.assertNotIn("gowave-e2e-ingress", text)


class TestMeasure(unittest.TestCase):
    """One request, every host's account of it, and nothing raised midway."""

    def test_the_request_runs_between_ready_and_stop(self):
        backend = FakeBackend()
        order = []
        backend.spawn_probe = lambda container, argv, timeout=0: order.append(f"spawn:{container}") or FakeSession(
            container, argv, backend
        )

        def request():
            order.append("request")
            return {"status": 200}

        measurement = ingress.measure(
            request, backend=backend, hosts=fake_hosts("master", "worker"),
            engine="client-container", port=443, intended="master",
        )
        self.assertEqual(measurement.request, {"status": 200})
        self.assertEqual(order[0], "spawn:client-container", "the identity connections come first")
        self.assertEqual(order[1:3], ["spawn:master-container", "spawn:worker-container"])
        self.assertEqual(order[3], "request")

    def test_a_capture_that_cannot_start_does_not_cancel_the_request(self):
        backend = FakeBackend(capture_errors={"worker": ("no_cap_net_raw", "no packet socket")})
        measured = []
        measurement = ingress.measure(
            lambda: measured.append(True),
            backend=backend, hosts=fake_hosts("master", "worker"),
            engine="client-container", port=443, intended="master",
        )
        self.assertEqual(measured, [True])
        self.assertIn("worker", measurement.capture_errors)
        self.assertIn("no_cap_net_raw", measurement.capture_errors["worker"])

    def test_no_host_is_refused(self):
        with self.assertRaises(IngressUnavailable) as caught:
            ingress.measure(lambda: None, backend=FakeBackend(), hosts=[],
                            engine="client-container", port=443)
        self.assertEqual(caught.exception.code, "no_ingress_host")

    def test_no_session_outlives_the_measurement(self):
        backend = FakeBackend()
        ingress.measure(lambda: None, backend=backend, hosts=fake_hosts("master"),
                        engine="client-container", port=443, intended="master")
        self.assertTrue(backend.sessions)
        for session in backend.sessions:
            self.assertTrue(
                session.released or session.abandoned,
                f"a {session.role} probe was left running",
            )

    def test_every_probe_is_started_with_a_deadline(self):
        """`Popen` has no timeout of its own, so the session carries it instead."""
        backend = FakeBackend()
        ingress.measure(lambda: None, backend=backend, hosts=fake_hosts("master", "worker"),
                        engine="client-container", port=443, intended="master")
        self.assertEqual(len(backend.deadlines), len(backend.sessions))
        for deadline in backend.deadlines:
            self.assertGreater(deadline, 0, "a probe was started without a deadline")

    def test_the_client_address_is_the_one_the_hosts_report(self):
        backend = FakeBackend()
        measurement = ingress.measure(lambda: None, backend=backend, hosts=fake_hosts("master"),
                                      engine="client-container", port=443, intended="master")
        self.assertEqual(measurement.client, CLIENT)
        self.assertEqual(measurement.addresses, {"master": CLIENT})
        peer_runs = [argv for _container, argv in backend.runs]
        self.assertTrue(peer_runs)
        for argv in peer_runs:
            self.assertIn("--scope", argv)
            self.assertNotIn(CLIENT, argv, "the host must not be told which address to report")

    def test_hosts_that_disagree_about_the_client_are_incomplete(self):
        backend = FakeBackend()
        answers = {"master-container": CLIENT, "worker-container": OTHER}
        backend.run = lambda container, argv, timeout=60: subprocess.CompletedProcess(
            list(argv), 0, json.dumps({"peer": answers[container]}), ""
        )
        measurement = ingress.measure(lambda: None, backend=backend,
                                      hosts=fake_hosts("master", "worker"),
                                      engine="client-container", port=443, intended="master")
        self.assertEqual(measurement.identity_error, "identity_disagreement")
        self.assertEqual(ingress.evaluate(measurement)["verdict"], ingress.INCOMPLETE)


class TestEvaluate(unittest.TestCase):
    """The five branches, driven through the real measurement path."""

    def measure(self, summaries=None, identity_error="", capture_errors=None, intended="master"):
        backend = FakeBackend(summaries or {}, identity_error=identity_error,
                              capture_errors=capture_errors)
        return ingress.measure(lambda: {"status": 200}, backend=backend,
                               hosts=fake_hosts("master", "worker"),
                               engine="client-container", port=443, intended=intended)

    def test_intended_host_alone_is_a_pass(self):
        facts = ingress.evaluate(self.measure({
            "master": summary(4, {CLIENT: 4}),
            "worker": summary(6, {OTHER: 6}),
        }))
        self.assertEqual(facts["verdict"], ingress.PASS, facts["reason"])
        self.assertEqual(facts["intended_matched"], 4)
        self.assertEqual(facts["other_matched"], 0)
        self.assertEqual(facts["foreign"], f"{OTHER}:6")
        self.assertEqual(facts["reason"], "")

    def test_the_other_host_capturing_the_client_is_a_fail_even_with_a_good_egress(self):
        facts = ingress.evaluate(self.measure({
            "master": summary(4, {CLIENT: 4}),
            "worker": summary(2, {CLIENT: 2}),
        }))
        self.assertEqual(facts["verdict"], ingress.FAIL)
        self.assertEqual(facts["other_matched"], 2)
        self.assertIn("worker", facts["reason"])

    def test_no_identity_is_incomplete(self):
        facts = ingress.evaluate(self.measure(identity_error="no_identity_connection"))
        self.assertEqual(facts["verdict"], ingress.INCOMPLETE)
        self.assertIn("identity", facts["reason"])

    def test_foreign_sources_only_is_incomplete_and_names_them(self):
        facts = ingress.evaluate(self.measure({
            "master": summary(5, {OTHER: 5}),
            "worker": summary(0, {}),
        }))
        self.assertEqual(facts["verdict"], ingress.INCOMPLETE)
        self.assertEqual(facts["intended_matched"], 0)
        self.assertEqual(facts["intended_captured"], 5)
        self.assertEqual(facts["foreign"], f"{OTHER}:5")
        self.assertIn("other than the client", facts["reason"])

    def test_an_empty_capture_on_both_hosts_is_incomplete_not_a_pass(self):
        facts = ingress.evaluate(self.measure({
            "master": summary(0, {}),
            "worker": summary(0, {}),
        }))
        self.assertEqual(facts["verdict"], ingress.INCOMPLETE)
        self.assertIn("decides nothing", facts["reason"])

    def test_a_capture_that_ran_out_its_window_is_incomplete(self):
        facts = ingress.evaluate(self.measure({
            "master": summary(3, {CLIENT: 3}, stopped_by="window"),
            "worker": summary(0, {}),
        }))
        self.assertEqual(facts["verdict"], ingress.INCOMPLETE)
        self.assertIn("window", facts["reason"])

    def test_kernel_drops_are_incomplete(self):
        facts = ingress.evaluate(self.measure({
            "master": summary(3, {CLIENT: 3}, drops=7),
            "worker": summary(0, {}),
        }))
        self.assertEqual(facts["verdict"], ingress.INCOMPLETE)
        self.assertIn("dropped 7", facts["reason"])

    def test_a_missing_capture_tool_is_incomplete(self):
        facts = ingress.evaluate(self.measure(
            {"worker": summary(0, {})},
            capture_errors={"master": ("no_probe_summary", "python3: can't open file")},
        ))
        self.assertEqual(facts["verdict"], ingress.INCOMPLETE)
        self.assertIn("no_probe_summary", facts["reason"])

    def test_aggregate_counters_are_not_a_fallback(self):
        """A capture that counted segments but attributed none decides nothing."""
        broken = {"captured": 9, "sources": {"unparseable": 0}, "stopped_by": "harness", "drops": 0}
        facts = ingress.evaluate(self.measure({
            "master": broken,
            "worker": summary(0, {}),
        }))
        self.assertEqual(facts["verdict"], ingress.INCOMPLETE)
        self.assertEqual(facts["intended_matched"], 0)


class TestEvidenceAndRequire(unittest.TestCase):
    """What reaches the run record, and what a non-PASS does to the case."""

    def test_evidence_is_a_flat_scalar_record(self):
        facts = ingress.evaluate(Measurement(
            port=443, intended="master", client=CLIENT,
            captures={"master": summary(3), "worker": summary(1, {OTHER: 1})},
        ))
        recorded = ingress.evidence(facts)
        self.assertEqual(len(recorded), 10)
        for key, value in recorded.items():
            self.assertTrue(key.startswith("ingress_"), key)
            self.assertIsInstance(value, (str, int, float, bool, type(None)), key)

    def test_evidence_names_both_hosts(self):
        facts = ingress.evaluate(Measurement(
            port=443, intended="master", client=CLIENT,
            captures={"master": summary(3), "worker": summary(1, {OTHER: 1})},
        ))
        recorded = ingress.evidence(facts)
        self.assertEqual(recorded["ingress_intended"], "master")
        self.assertEqual(recorded["ingress_other"], "worker")
        self.assertEqual(recorded["ingress_intended_matched"], 3)
        self.assertEqual(recorded["ingress_other_matched"], 0)

    def test_a_pass_is_allowed_through(self):
        ingress.require("DP-04", {"verdict": ingress.PASS, "reason": ""})

    def test_a_fail_raises_the_harness_assertion(self):
        with self.assertRaises(AssertionError):
            ingress.require("PKT-03", {"verdict": ingress.FAIL, "reason": "wrong host"})

    def test_incomplete_raises_the_case_incomplete_state(self):
        with self.assertRaises(CaseIncomplete):
            ingress.require("PKT-02", {"verdict": ingress.INCOMPLETE, "reason": "no identity"})


if __name__ == "__main__":
    unittest.main()
