#!/usr/bin/env python3
"""Suite nonroot: HTTP/HTTPS echo and egress fixture for the Podman E2E."""
import hashlib
import json
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ECHO_SERVER = REPO_ROOT / "tests" / "fixtures" / "echo_server.py"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class EchoFixture:
    def __init__(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.control_path = root / "echo-control.json"
        self.log_path = root / "echo-requests.jsonl"
        self.port = free_port()
        self.process = subprocess.Popen(
            [
                sys.executable, str(ECHO_SERVER),
                "--listen", "127.0.0.1",
                "--http-port", str(self.port),
                "--control", str(self.control_path),
                "--log", str(self.log_path),
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self._wait_ready()

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                self.get("/healthz", timeout=0.2)
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError(f"echo fixture did not start: {self.process.stderr.read()[-2000:]}")

    def control(self, **values) -> None:
        current = {}
        if self.control_path.exists():
            current = json.loads(self.control_path.read_text(encoding="utf-8") or "{}")
        current.update(values)
        self.control_path.write_text(json.dumps(current), encoding="utf-8")
        time.sleep(0.02)

    def request(self, path="/probe", method="GET", body=None, headers=None, timeout=5):
        data = body.encode("utf-8") if isinstance(body, str) else body
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=data, method=method,
            headers=headers or {},
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, dict(response.headers), json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, dict(exc.headers or {}), json.loads(exc.read() or b"{}")
            finally:
                exc.close()

    def get(self, path, timeout=5, headers=None):
        return self.request(path, timeout=timeout, headers=headers)

    def events(self):
        if not self.log_path.exists():
            return []
        return [json.loads(line) for line in self.log_path.read_text().splitlines() if line.strip()]

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


class TestEchoFixture(unittest.TestCase):
    def fixture(self) -> EchoFixture:
        fixture = EchoFixture()
        self.addCleanup(fixture.close)
        return fixture

    def test_every_response_has_a_unique_request_id_and_source(self):
        fixture = self.fixture()
        first = fixture.get("/through/a")[2]
        second = fixture.get("/through/b")[2]
        self.assertNotEqual(first["request_id"], second["request_id"])
        self.assertEqual(first["method"], "GET")
        self.assertEqual(first["source_ip"], "127.0.0.1")
        self.assertEqual(first["path"], "/through/a")

    def test_caller_request_id_is_preserved(self):
        fixture = self.fixture()
        status, headers, payload = fixture.get("/probe", headers={"X-Request-Id": "case-123"})
        self.assertEqual(status, 200)
        self.assertEqual(payload["request_id"], "case-123")
        self.assertEqual(headers.get("X-Request-Id"), "case-123")

    def test_payload_digest_and_expectation_check(self):
        fixture = self.fixture()
        body = "payload-verified-through-the-tunnel"
        digest = hashlib.sha256(body.encode()).hexdigest()

        status, _, payload = fixture.request("/echo", method="POST", body=body, headers={"X-Expect-SHA256": digest})
        self.assertEqual(status, 200)
        self.assertTrue(payload["match"])
        self.assertEqual(payload["body_sha256"], digest)

        status, _, payload = fixture.request("/echo", method="POST", body=body, headers={"X-Expect-SHA256": "0" * 64})
        self.assertEqual(status, 409)
        self.assertFalse(payload["match"])
        self.assertEqual(payload["actual_sha256"], digest)

    def test_status_and_latency_fault_switches(self):
        fixture = self.fixture()
        fixture.control(status=503, delay_ms=250)
        started = time.monotonic()
        status, _, payload = fixture.request("/fault")
        self.assertEqual(status, 503)
        self.assertGreaterEqual(time.monotonic() - started, 0.2)
        self.assertIn("request_id", payload)

    def test_abrupt_close_fault_looks_like_unavailability(self):
        fixture = self.fixture()
        fixture.control(close=True)
        with self.assertRaises((urllib.error.URLError, ConnectionError, OSError)):
            fixture.request("/fault", timeout=3)

    def test_fault_switches_apply_without_a_restart(self):
        fixture = self.fixture()
        self.assertEqual(fixture.request("/flip")[0], 200)
        fixture.control(status=502)
        self.assertEqual(fixture.request("/flip")[0], 502)
        fixture.control(status=0)
        self.assertEqual(fixture.request("/flip")[0], 200)

    def test_diagnostics_exposes_recent_requests(self):
        fixture = self.fixture()
        fixture.get("/observed")
        status, _, payload = fixture.get("/diagnostics")
        self.assertEqual(status, 200)
        paths = [entry["path"] for entry in payload["requests"]]
        self.assertIn("/observed", paths)

    def test_request_log_records_source_path_and_digest(self):
        fixture = self.fixture()
        fixture.request("/logged", method="POST", body="abc")
        event = [entry for entry in fixture.events() if entry["path"] == "/logged"][-1]
        self.assertEqual(event["method"], "POST")
        self.assertEqual(event["body_sha256"], hashlib.sha256(b"abc").hexdigest())
        self.assertEqual(event["source_ip"], "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
