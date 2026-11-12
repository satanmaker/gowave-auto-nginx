#!/usr/bin/env python3
"""Suite nonroot: controllable authoritative DNS fixture used by the Podman E2E."""
import json
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DNS_SERVER = REPO_ROOT / "tests" / "fixtures" / "dns_server.py"

TYPE_A = 1
TYPE_AAAA = 28


def build_query(name: str, qtype: int, transaction_id: int = 0x1234) -> bytes:
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
    return header + qname + struct.pack("!HH", qtype, 1)


def parse_response(data: bytes):
    transaction_id, flags, qdcount, ancount = struct.unpack("!HHHH", data[:8])
    rcode = flags & 0x000F
    offset = 12
    for _ in range(qdcount):
        while data[offset] != 0:
            offset += data[offset] + 1
        offset += 5
    answers = []
    for _ in range(ancount):
        offset += 2  # name compression pointer
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        offset += rdlength
        if rtype == TYPE_A:
            value = socket.inet_ntoa(rdata)
        elif rtype == TYPE_AAAA:
            value = socket.inet_ntop(socket.AF_INET6, rdata)
        else:
            value = rdata.hex()
        answers.append({"type": rtype, "ttl": ttl, "value": value})
    return transaction_id, rcode, answers


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class DnsFixture:
    def __init__(self, zone: dict) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.zone_path = root / "dns-zone.json"
        self.log_path = root / "dns-queries.jsonl"
        self.zone_path.write_text(json.dumps(zone), encoding="utf-8")
        self.port = free_port()
        self.process = subprocess.Popen(
            [
                sys.executable, str(DNS_SERVER),
                "--listen", "127.0.0.1",
                "--port", str(self.port),
                "--zone", str(self.zone_path),
                "--log", str(self.log_path),
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self._wait_ready()

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                self.query("ready.testbed.internal", TYPE_A, timeout=0.2)
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError(f"DNS fixture did not start: {self.process.stderr.read()[-2000:]}")

    def update(self, zone: dict) -> None:
        self.zone_path.write_text(json.dumps(zone), encoding="utf-8")
        time.sleep(0.02)

    def query(self, name: str, qtype: int = TYPE_A, timeout: float = 5.0):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(build_query(name, qtype), ("127.0.0.1", self.port))
            data, _ = sock.recvfrom(4096)
        return parse_response(data)

    def queries(self):
        if not self.log_path.exists():
            return []
        return [json.loads(line) for line in self.log_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def close(self) -> None:
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        if self.process.stdout:
            self.process.stdout.close()
        if self.process.stderr:
            self.process.stderr.close()
        self.tmp.cleanup()


BASE_ZONE = {
    "ttl": 300,
    "records": {
        "panel.testbed.internal": {"A": ["10.89.0.10"], "AAAA": ["fd00:dead::10"]},
        "worker.testbed.internal": {"A": ["10.89.0.11"]},
    },
    "behavior": {"mode": "answer", "delay_ms": 0},
}


class TestDnsFixture(unittest.TestCase):
    def fixture(self, zone=None) -> DnsFixture:
        fixture = DnsFixture(zone or BASE_ZONE)
        self.addCleanup(fixture.close)
        return fixture

    def test_answers_a_and_aaaa_with_configured_ttl(self):
        fixture = self.fixture()
        _, rcode, answers = fixture.query("panel.testbed.internal", TYPE_A)
        self.assertEqual(rcode, 0)
        self.assertEqual(answers, [{"type": TYPE_A, "ttl": 300, "value": "10.89.0.10"}])
        _, _, answers = fixture.query("panel.testbed.internal", TYPE_AAAA)
        self.assertEqual(answers[0]["value"], "fd00:dead::10")

    def test_nxdomain_mode_is_controllable(self):
        fixture = self.fixture()
        zone = dict(BASE_ZONE)
        zone["behavior"] = {"mode": "nxdomain", "delay_ms": 0}
        fixture.update(zone)
        _, rcode, answers = fixture.query("panel.testbed.internal")
        self.assertEqual(rcode, 3)
        self.assertEqual(answers, [])

    def test_wrong_answer_mode_returns_the_steered_address(self):
        fixture = self.fixture()
        zone = {
            **BASE_ZONE,
            "behavior": {
                "mode": "wrong",
                "overrides": {"panel.testbed.internal": {"A": ["10.89.0.66"]}},
            },
        }
        fixture.update(zone)
        _, rcode, answers = fixture.query("panel.testbed.internal")
        self.assertEqual(rcode, 0)
        self.assertEqual(answers[0]["value"], "10.89.0.66")

    def test_stale_mode_uses_the_short_ttl(self):
        fixture = self.fixture()
        zone = {
            **BASE_ZONE,
            "behavior": {
                "mode": "stale",
                "ttl": 1,
                "overrides": {"panel.testbed.internal": {"A": ["10.89.0.99"]}},
            },
        }
        fixture.update(zone)
        _, _, answers = fixture.query("panel.testbed.internal")
        self.assertEqual(answers[0]["ttl"], 1)
        self.assertEqual(answers[0]["value"], "10.89.0.99")

    def test_unknown_names_are_nxdomain_and_never_forwarded(self):
        fixture = self.fixture()
        _, rcode, answers = fixture.query("public.example.com")
        self.assertEqual(rcode, 3)
        self.assertEqual(answers, [])

    def test_diagnostics_record_every_query(self):
        fixture = self.fixture()
        fixture.query("worker.testbed.internal", TYPE_A)
        events = [event for event in fixture.queries() if event.get("qname") == "worker.testbed.internal"]
        self.assertTrue(events)
        self.assertEqual(events[-1]["rcode"], 0)
        self.assertEqual(events[-1]["answers"], ["10.89.0.11"])
        self.assertEqual(events[-1]["mode"], "answer")

    def test_latency_injection_is_applied(self):
        fixture = self.fixture()
        zone = {**BASE_ZONE, "behavior": {"mode": "answer", "delay_ms": 300}}
        fixture.update(zone)
        started = time.monotonic()
        _, rcode, _ = fixture.query("panel.testbed.internal")
        self.assertEqual(rcode, 0)
        self.assertGreaterEqual(time.monotonic() - started, 0.25)

    def test_zone_change_applies_without_a_restart(self):
        fixture = self.fixture()
        _, _, answers = fixture.query("worker.testbed.internal")
        self.assertEqual(answers[0]["value"], "10.89.0.11")
        fixture.update({
            "ttl": 60,
            "records": {"worker.testbed.internal": {"A": ["10.89.0.12"]}},
            "behavior": {"mode": "answer"},
        })
        _, _, answers = fixture.query("worker.testbed.internal")
        self.assertEqual(answers[0]["value"], "10.89.0.12")
        self.assertEqual(answers[0]["ttl"], 60)


if __name__ == "__main__":
    unittest.main()
