#!/usr/bin/env python3
"""Suite nonroot: DNS answers read by the Podman E2E from both of its vantages."""
import argparse
import contextlib
import io
import json
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import aio, dns_probe, topology  # noqa: E402
from tools.podman_e2e.runner import RunContext  # noqa: E402

DNS_SERVER = REPO_ROOT / "tests" / "fixtures" / "dns_server.py"

TARGET_IP = "10.89.0.10"
CLIENT_IP = "10.89.0.40"
ECHO_IP = "10.89.0.30"
RESOLVER_IP = "10.89.0.53"
AAAA_ANSWER = "2001:db8::53"

BASE_ZONE = {
    "ttl": 30,
    "records": {
        "panel.testbed.internal": {"A": [TARGET_IP]},
        "reality.testbed.internal": {"A": [TARGET_IP]},
    },
    "behavior": {"mode": "answer", "delay_ms": 0},
}


def free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Fixture:
    """The real DNS fixture, started on loopback for the probe's own tests."""

    def __init__(self, zone=None, zone_path=None, log_path=None) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        if zone_path is None:
            self.zone_path = root / "zone.json"
            self.zone_path.write_text(json.dumps(zone or BASE_ZONE), encoding="utf-8")
        else:
            # A caller-owned zone file: a rewrite the caller makes is what this
            # fixture serves, which is what the case relies on in the run.
            self.zone_path = Path(zone_path)
            if not self.zone_path.is_file():
                raise RuntimeError(f"the zone file {self.zone_path} does not exist")
        self.log_path = Path(log_path) if log_path else root / "queries.jsonl"
        self.port = free_udp_port()
        self.process = subprocess.Popen(
            [
                sys.executable, str(DNS_SERVER),
                "--listen", "127.0.0.1",
                "--port", str(self.port),
                "--zone", str(self.zone_path),
                "--log", str(self.log_path),
            ],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True,
        )
        self._wait_ready()

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"the DNS fixture exited with {self.process.returncode}")
            report = dns_probe.direct_query(
                "127.0.0.1", self.port, "ready.testbed.internal", dns_probe.TYPE_A, 0.2,
            )
            if not report["error"]:
                return
            time.sleep(0.05)
        raise RuntimeError("the DNS fixture did not answer within 10s")

    def close(self) -> None:
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        self.tmp.cleanup()


class ZoneStore:
    """The zone the case rewrites, without the podman host around it."""

    dns_zone_file = topology.AioTopology.dns_zone_file
    dns_query_log = topology.AioTopology.dns_query_log
    write_dns_zone = topology.AioTopology.write_dns_zone
    dns_queries = topology.AioTopology.dns_queries

    def __init__(self, directory: Path) -> None:
        self.dns_dir = Path(directory)


class TestDnsProbe(unittest.TestCase):
    def fixture(self, zone=None) -> Fixture:
        fixture = Fixture(zone or BASE_ZONE)
        self.addCleanup(fixture.close)
        return fixture

    def test_direct_scope_reports_the_authoritative_answer_and_ttl(self):
        zone = {
            "ttl": 7,
            "records": {
                "a.testbed.internal": {"A": [TARGET_IP]},
                "aaaa.testbed.internal": {"AAAA": [AAAA_ANSWER]},
            },
        }
        fixture = self.fixture(zone)
        answer = dns_probe.direct_query(
            "127.0.0.1", fixture.port, "a.testbed.internal", dns_probe.TYPE_A, 2.0,
        )
        self.assertEqual(answer["rcode"], 0)
        self.assertEqual(answer["rcode_name"], "NOERROR")
        self.assertEqual(answer["answers"], [TARGET_IP])
        self.assertEqual(answer["ttl"], 7)
        self.assertEqual(answer["error"], "")

        family = dns_probe.direct_query(
            "127.0.0.1", fixture.port, "aaaa.testbed.internal", dns_probe.TYPE_AAAA, 2.0,
        )
        self.assertEqual(family["answers"], [AAAA_ANSWER])

        empty = dns_probe.direct_query(
            "127.0.0.1", fixture.port, "a.testbed.internal", dns_probe.TYPE_AAAA, 2.0,
        )
        self.assertEqual(empty["rcode"], 0)
        self.assertEqual(empty["answers"], [])

    def test_direct_scope_reports_nxdomain(self):
        fixture = self.fixture()
        answer = dns_probe.direct_query(
            "127.0.0.1", fixture.port, "absent.testbed.internal", dns_probe.TYPE_A, 2.0,
        )
        self.assertEqual(answer["rcode"], 3)
        self.assertEqual(answer["rcode_name"], "NXDOMAIN")
        self.assertEqual(answer["answers"], [])

    def test_unreachable_resolver_is_reported_not_raised(self):
        answer = dns_probe.direct_query(
            "127.0.0.1", free_udp_port(), "a.testbed.internal", dns_probe.TYPE_A, 0.3,
        )
        self.assertEqual(answer["rcode"], -1)
        self.assertTrue(answer["error"])
        self.assertEqual(answer["answers"], [])

    def test_system_scope_asks_both_families_separately(self):
        inet, inet_error = dns_probe.resolve("localhost", socket.AF_INET)
        self.assertIn("127.0.0.1", inet)
        self.assertEqual(inet_error, "")
        missing, error = dns_probe.resolve("dns-probe.invalid", socket.AF_INET)
        self.assertEqual(missing, [])
        self.assertTrue(error)

    def test_main_prints_one_json_document_per_scope(self):
        fixture = self.fixture()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = dns_probe.main([
                "--scope", "direct",
                "--server", "127.0.0.1",
                "--port", str(fixture.port),
                "--query", "panel.testbed.internal:A",
            ])
        self.assertEqual(code, 0)
        report = json.loads(buffer.getvalue())
        self.assertEqual(report["scope"], "direct")
        self.assertEqual(report["queries"][0]["answers"], [TARGET_IP])

    def test_query_spec_rejects_an_unknown_type(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            dns_probe.parse_query("panel.testbed.internal:MX")

    def test_resolver_config_reports_the_nameservers_in_use(self):
        config = dns_probe.resolver_config()
        self.assertEqual(config["path"], "/etc/resolv.conf")
        self.assertIsInstance(config["nameservers"], list)


class TestDnsZoneStore(unittest.TestCase):
    def store(self) -> ZoneStore:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return ZoneStore(Path(directory.name))

    def test_rewrite_replaces_the_zone_without_leaving_a_sibling(self):
        store = self.store()
        store.write_dns_zone(BASE_ZONE)
        store.write_dns_zone({**BASE_ZONE, "ttl": 5})
        self.assertEqual(sorted(path.name for path in store.dns_dir.iterdir()), ["zone.json"])
        self.assertEqual(json.loads(store.dns_zone_file().read_text(encoding="utf-8"))["ttl"], 5)

    def test_rewrite_changes_the_mtime_even_for_an_identical_size(self):
        store = self.store()
        store.write_dns_zone(BASE_ZONE)
        first = store.dns_zone_file().stat().st_mtime_ns
        store.write_dns_zone(BASE_ZONE)
        self.assertNotEqual(store.dns_zone_file().stat().st_mtime_ns, first)

    def test_queries_are_read_as_records_and_a_missing_log_is_empty(self):
        store = self.store()
        self.assertEqual(store.dns_queries(), [])
        event = {"qname": "panel.testbed.internal", "qtype": "A", "rcode": 0}
        store.dns_query_log().write_text(json.dumps(event) + "\n" + "not json\n", encoding="utf-8")
        self.assertEqual(store.dns_queries(), [event])

    def test_the_fixture_serves_a_rewritten_zone_without_a_restart(self):
        store = self.store()
        store.write_dns_zone(BASE_ZONE)
        fixture = Fixture(zone_path=store.dns_zone_file())
        self.addCleanup(fixture.close)

        before = dns_probe.direct_query(
            "127.0.0.1", fixture.port, "panel.testbed.internal", dns_probe.TYPE_A, 2.0,
        )
        self.assertEqual(before["answers"], [TARGET_IP])
        self.assertEqual(before["ttl"], 30)

        store.write_dns_zone({
            **BASE_ZONE,
            "ttl": 5,
            "records": {**BASE_ZONE["records"], "panel.testbed.internal": {"A": [CLIENT_IP]}},
        })
        after = dns_probe.direct_query(
            "127.0.0.1", fixture.port, "panel.testbed.internal", dns_probe.TYPE_A, 2.0,
        )
        self.assertEqual(after["answers"], [CLIENT_IP])
        self.assertEqual(after["ttl"], 5)
        self.assertIsNone(fixture.process.poll(), "the fixture was restarted to serve the rewrite")


class DnsHost:
    """The instantiated host's resolver face, without containers.

    It keeps the zone the case wrote and answers from it exactly as the fixture
    does — records, behaviour modes, overrides and TTLs included — and appends
    the query log the fixture would have written, so the case's phases run
    against real zone content instead of a scripted transcript.
    """

    dns_zone_file = topology.AioTopology.dns_zone_file
    dns_query_log = topology.AioTopology.dns_query_log
    dns_queries = topology.AioTopology.dns_queries
    write_dns_zone_atomically = topology.AioTopology.write_dns_zone

    def __init__(self, directory: Path, zone: dict, cache: bool = False) -> None:
        self.dns_dir = Path(directory)
        self.target_name = "aio-1"
        self.client_name = "client-1"
        self.plan = SimpleNamespace(
            target_ip=TARGET_IP, client_ip=CLIENT_IP, echo_ip=ECHO_IP, dns_ip=RESOLVER_IP,
        )
        self._base = json.loads(json.dumps(zone))
        self._zone = json.loads(json.dumps(zone))
        self.cache = cache
        self._cached = {}
        self.probes = []
        self.queries = []

    # ------------------------------------------------------------ host surface
    def zone(self):
        return json.loads(json.dumps(self._base))

    def write_dns_zone(self, data):
        self._zone = json.loads(json.dumps(data))
        self.write_dns_zone_atomically(data)

    def dns_probe(self, container, scope, queries=(), names=(), timeout=60):
        source = str(self.plan.target_ip) if container == self.target_name else str(self.plan.client_ip)
        self.probes.append({"container": container, "scope": scope,
                            "queries": list(queries), "names": list(names)})
        if scope == "direct":
            entries = []
            for spec in queries:
                name, _, qtype = spec.rpartition(":")
                entries.append(self._direct(name, qtype, source))
            report = {"scope": "direct", "server": str(self.plan.dns_ip), "port": 53,
                      "queries": entries}
        else:
            report = {"scope": "system", "resolver": {"path": "/etc/resolv.conf",
                                                      "nameservers": [str(self.plan.dns_ip)],
                                                      "symlink": "", "error": ""},
                      "names": [self._system(name, source) for name in names]}
        return subprocess.CompletedProcess(["python3"], 0, json.dumps(report), "")

    # ------------------------------------------------------------- resolution
    def _lookup(self, name, qtype):
        behavior = dict(self._zone.get("behavior") or {})
        mode = str(behavior.get("mode", "answer"))
        ttl = int(self._zone.get("ttl", 30))
        if mode == "nxdomain":
            return 3, [], ttl, mode
        records = dict(self._zone.get("records") or {})
        if mode in ("wrong", "stale"):
            records = {**records, **dict(behavior.get("overrides") or {})}
            if mode == "stale":
                ttl = int(behavior.get("ttl", 5))
        entry = records.get(name)
        if entry is None:
            return 3, [], ttl, mode
        return 0, list(entry.get(qtype) or []), ttl, mode

    def _record(self, name, qtype, source, rcode, values, ttl, mode):
        self.queries.append({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "client": f"{source}:43210",
            "qname": name,
            "qtype": qtype,
            "mode": mode,
            "path": "authoritative",
            "rcode": rcode,
            "answers": values,
            "ttl": ttl,
        })
        with self.dns_query_log().open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(self.queries[-1], sort_keys=True) + "\n")

    def _direct(self, name, qtype, source):
        rcode, values, ttl, mode = self._lookup(name, qtype)
        self._record(name, qtype, source, rcode, values, ttl, mode)
        return {
            "name": name, "type": qtype, "rcode": rcode,
            "rcode_name": dns_probe.RCODE_NAMES.get(rcode, str(rcode)),
            "answers": values,
            "records": [{"type": qtype, "ttl": ttl, "value": value} for value in values],
            "ttl": ttl if values else 0, "elapsed_ms": 1, "error": "",
        }

    def _system(self, name, source):
        entry = {"name": name, "inet": [], "inet6": [], "inet_error": "", "inet6_error": ""}
        for qtype, family in (("A", "inet"), ("AAAA", "inet6")):
            rcode, values, ttl, mode = self._lookup(name, qtype)
            self._record(name, qtype, source, rcode, values, ttl, mode)
            if self.cache:
                values = self._cached.setdefault((name, family), list(values))
            entry[family] = list(values)
            if rcode != 0:
                entry[f"{family}_error"] = "gaierror: Name or service not known"
        return entry


def make_context() -> tuple[RunContext, tempfile.TemporaryDirectory]:
    tmp = tempfile.TemporaryDirectory()
    context = RunContext(
        topology="aio",
        artifact_root=Path(tmp.name),
        budget_seconds=600,
        run_id="podman-aio-dns-00000000",
    )
    return context, tmp


class TestDnsCase(unittest.TestCase):
    """DNS-01: both vantages see the zone, and the zone is put back afterwards."""

    def setUp(self):
        self.context, self.tmp = make_context()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.context.run_cleanup)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.host = DnsHost(Path(directory.name), BASE_ZONE)
        self.product = aio.AioProduct(SimpleNamespace(context=self.context))
        self.product.host = self.host
        self.product.outcome = topology.InstallOutcome(0, "", "", 1.0, "install")

    def evidence(self):
        return aio.case_dns(self.product)

    def test_every_behaviour_is_read_from_both_vantages(self):
        evidence = self.evidence()
        self.assertEqual(sorted(evidence["selection"]), ["client", "target"])
        self.assertEqual(sorted(evidence["expiry"]), ["client", "target"])
        self.assertEqual(sorted(evidence["steered"]), ["client", "target"])
        self.assertEqual(sorted(evidence["restored"]), ["client", "target"])
        for role in ("target", "client"):
            selection = evidence["selection"][role]
            self.assertEqual(selection["a"]["answers"], [TARGET_IP])
            self.assertEqual(selection["aaaa"]["answers"], [AAAA_ANSWER])
            self.assertEqual(selection["nxdomain"]["rcode"], 3)
            self.assertEqual(evidence["expiry"][role]["before"], [TARGET_IP])
            self.assertEqual(evidence["expiry"][role]["after"], [CLIENT_IP])
            self.assertEqual(evidence["steered"][role]["wrong"]["answers"], [ECHO_IP])
            self.assertEqual(evidence["steered"][role]["stale"]["ttl"], aio.DNS_CASE_TTL)
            self.assertEqual(evidence["restored"][role]["panel_domain"], [TARGET_IP])
            self.assertEqual(evidence["restored"][role]["probe_name"], 3)

    def test_attribution_names_the_vantage_that_asked(self):
        evidence = self.evidence()
        self.assertEqual(evidence["attribution"]["target"]["source"], TARGET_IP)
        self.assertEqual(evidence["attribution"]["client"]["source"], CLIENT_IP)
        self.assertEqual(evidence["attribution"]["target"]["a"]["answers"], [TARGET_IP])
        self.assertEqual(evidence["attribution"]["client"]["ttl_after_change"]["answers"], [CLIENT_IP])
        self.assertEqual(evidence["attribution"]["client"]["resolver"], RESOLVER_IP)
        for probe in self.host.probes:
            self.assertIn(probe["scope"], ("direct", "system"))

    def test_the_install_zone_is_restored_before_the_case_returns(self):
        self.evidence()
        restored = json.loads(self.host.dns_zone_file().read_text(encoding="utf-8"))
        self.assertEqual(restored, BASE_ZONE)
        self.assertEqual(sorted(path.name for path in self.host.dns_dir.iterdir()),
                         ["queries.jsonl", "zone.json"])

    def test_a_family_answered_with_the_other_family_fails_the_case(self):
        original = self.host._lookup

        def crossed(name, qtype):
            rcode, values, ttl, mode = original(name, qtype)
            if name == aio.DNS_A_NAME and qtype == "AAAA":
                values = [AAAA_ANSWER]
            return rcode, values, ttl, mode

        self.host._lookup = crossed
        with self.assertRaises(AssertionError) as caught:
            self.evidence()
        self.assertIn("a different record set than the zone", str(caught.exception))
        self.assertEqual(json.loads(self.host.dns_zone_file().read_text(encoding="utf-8")), BASE_ZONE)

    def test_a_record_that_publishes_the_wrong_ttl_fails_the_case(self):
        original = self.host._lookup

        def long_lived(name, qtype):
            rcode, values, ttl, mode = original(name, qtype)
            return rcode, values, ttl + 300, mode

        self.host._lookup = long_lived
        with self.assertRaises(AssertionError) as caught:
            self.evidence()
        self.assertIn("a downstream cache would keep", str(caught.exception))
        self.assertEqual(json.loads(self.host.dns_zone_file().read_text(encoding="utf-8")), BASE_ZONE)

    def test_an_unknown_name_that_answers_fails_the_case(self):
        original = self.host._lookup

        def answered(name, qtype):
            rcode, values, ttl, mode = original(name, qtype)
            if name == aio.DNS_ABSENT_NAME:
                return 0, [], ttl, mode
            return rcode, values, ttl, mode

        self.host._lookup = answered
        with self.assertRaises(AssertionError) as caught:
            self.evidence()
        self.assertIn("instead of 3", str(caught.exception))

    def test_an_answer_the_fixture_never_logged_fails_attribution(self):
        original = self.host._record

        def silent(name, qtype, source, rcode, values, ttl, mode):
            if name == aio.DNS_A_NAME:
                return
            original(name, qtype, source, rcode, values, ttl, mode)

        self.host._record = silent
        with self.assertRaises(AssertionError) as caught:
            self.evidence()
        self.assertIn("the answer did not come from the fixture zone", str(caught.exception))

    def test_a_wrong_answer_that_is_repaired_fails_the_case(self):
        original = self.host._lookup

        def repaired(name, qtype):
            rcode, values, ttl, mode = original(name, qtype)
            if name == aio.DNS_WRONG_NAME:
                values = [TARGET_IP]
            return rcode, values, ttl, mode

        self.host._lookup = repaired
        with self.assertRaises(AssertionError) as caught:
            self.evidence()
        self.assertIn(ECHO_IP, str(caught.exception))

    def test_a_resolver_that_keeps_the_old_answer_past_the_ttl_fails_the_case(self):
        self.host.cache = True
        # The cached answer never expires, so the deadline has to be short enough
        # for the test to observe the failure instead of waiting for it.
        with mock.patch.object(aio, "DNS_EXPIRY_DEADLINE_SECONDS", 0.05):
            with mock.patch.object(aio, "DNS_EXPIRY_INTERVAL_SECONDS", 0.01):
                with self.assertRaises(AssertionError) as caught:
                    self.evidence()
        self.assertIn("never resolved to", str(caught.exception))
        self.assertEqual(json.loads(self.host.dns_zone_file().read_text(encoding="utf-8")), BASE_ZONE)


class TestDnsCaseWiring(unittest.TestCase):
    def test_the_case_is_registered_once_in_the_aio_suite(self):
        context, tmp = make_context()
        self.addCleanup(tmp.cleanup)
        self.addCleanup(context.run_cleanup)
        suite = aio.cases(SimpleNamespace(context=context))
        ids = [case.id for case in suite]
        self.assertEqual(ids.count(aio.DNS_CASE_ID), 1)
        case = suite[ids.index(aio.DNS_CASE_ID)]
        self.assertEqual(case.topology, "aio")
        self.assertEqual(case.timeout_seconds, aio.DNS_CASE_TIMEOUT_SECONDS)

    def test_the_probe_script_is_the_one_the_topology_runs(self):
        self.assertEqual(topology.DNS_PROBE_SCRIPT.split("/")[-1], "dns_probe.py")
        relative = topology.DNS_PROBE_SCRIPT[len(topology.REPO_IN_CONTAINER):].lstrip("/")
        self.assertTrue((REPO_ROOT / relative).is_file(), relative)

    def test_the_zone_names_sit_inside_the_fixture_suffix(self):
        for name in (aio.DNS_A_NAME, aio.DNS_AAAA_NAME, aio.DNS_BOTH_NAME, aio.DNS_TTL_NAME,
                     aio.DNS_ABSENT_NAME, aio.DNS_WRONG_NAME, aio.DNS_STALE_NAME):
            self.assertTrue(name.endswith(f".{topology.DNS_ZONE_SUFFIX}"), name)

    def test_the_case_zone_keeps_every_installed_name(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        host = DnsHost(Path(directory.name), BASE_ZONE)
        zone = aio.dns_case_zone(host)
        for name in BASE_ZONE["records"]:
            self.assertIn(name, zone["records"])
        zone = aio.dns_case_zone(host, ttl_address=CLIENT_IP)
        self.assertEqual(zone["ttl"], aio.DNS_CASE_TTL)
        self.assertEqual(zone["records"][aio.DNS_TTL_NAME], {"A": [CLIENT_IP]})


if __name__ == "__main__":
    unittest.main()
