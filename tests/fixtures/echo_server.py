#!/usr/bin/env python3
"""HTTP/HTTPS echo and egress fixture for the Podman product E2E.

Every response carries a unique request id, the observed source address, and a
digest of the received payload, so a case can prove which path the traffic took
and that the bytes arrived unmodified. Fault switches (status, latency, abrupt
close, custom body) are read from a control file on each request, which lets a
case inject a failure without restarting the fixture.

    python3 tests/fixtures/echo_server.py --http-port 18080 --https-port 18443 \
        --cert /fixtures/tls/echo.crt --key /fixtures/tls/echo.key
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import socket
import ssl
import sys
import threading
import time
import uuid
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Deque, Dict, Optional, Sequence
from urllib.parse import parse_qs, urlparse

DEFAULT_CONTROL: Dict[str, Any] = {
    "status": 0,
    "delay_ms": 0,
    "close": False,
    "body": None,
}

RECENT: Deque[Dict[str, Any]] = deque(maxlen=1000)
RECENT_LOCK = threading.Lock()
CONTROL_PATH: Optional[Path] = None
LOG_PATH: Optional[Path] = None
SNI = threading.local()


def load_control(path: Optional[Path]) -> Dict[str, Any]:
    if path is None:
        return dict(DEFAULT_CONTROL)
    try:
        raw = json.loads(path.read_text(encoding="utf-8") or "{}")
    except (FileNotFoundError, json.JSONDecodeError):
        return dict(DEFAULT_CONTROL)
    return {**DEFAULT_CONTROL, **raw}


def log_event(event: Dict[str, Any]) -> None:
    with RECENT_LOCK:
        RECENT.append(event)
    if LOG_PATH is None:
        return
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


class EchoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        return  # fixture diagnostics go through the JSONL log, not stderr

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length > 0 else b""

    def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if payload.get("request_id"):
            self.send_header("X-Request-Id", str(payload["request_id"]))
        self.end_headers()
        self.wfile.write(body)

    def _handle(self, method: str) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            self._send_json(200, {"ok": True})
            return
        if parsed.path == "/diagnostics":
            with RECENT_LOCK:
                recent = list(RECENT)
            self._send_json(200, {"ok": True, "requests": recent, "control": load_control(CONTROL_PATH)})
            return

        control = load_control(CONTROL_PATH)
        if control.get("delay_ms"):
            time.sleep(min(int(control["delay_ms"]), 10000) / 1000.0)
        if control.get("close"):
            log_event({
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "request_id": self.headers.get("X-Request-Id") or "",
                "path": self.path,
                "fault": "close",
                "source_ip": self.client_address[0],
            })
            self.close_connection = True
            try:
                self.connection.close()
            except OSError:
                pass
            return

        body = self._read_body()
        request_id = self.headers.get("X-Request-Id") or uuid.uuid4().hex
        digest = hashlib.sha256(body).hexdigest()
        expected = self.headers.get("X-Expect-SHA256") or (parse_qs(parsed.query).get("expect") or [""])[0]
        tls_info = None
        if isinstance(self.connection, ssl.SSLSocket):
            tls_info = {
                "sni": getattr(SNI, "value", None),
                "version": self.connection.version(),
                "cipher": (self.connection.cipher() or ("",))[0],
            }

        event = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "request_id": request_id,
            "method": method,
            "path": parsed.path,
            "query": parsed.query,
            "source_ip": self.client_address[0],
            "source_port": self.client_address[1],
            "body_sha256": digest,
            "body_length": len(body),
            "expect_sha256": expected,
            "tls": tls_info,
        }
        log_event(event)

        if expected and expected != digest:
            self._send_json(409, {
                "request_id": request_id,
                "match": False,
                "expected_sha256": expected,
                "actual_sha256": digest,
                "body_length": len(body),
                "source_ip": self.client_address[0],
            })
            return

        status = int(control.get("status") or 200)
        payload: Dict[str, Any] = {
            **event,
            "match": True if expected else None,
            "headers": {key.lower(): value for key, value in self.headers.items()},
        }
        if control.get("body") is not None:
            payload["echo"] = control["body"]
        self._send_json(status, payload)

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def do_PUT(self) -> None:
        self._handle("PUT")


class DualStackServer:
    """HTTP server plus an optional TLS listener sharing the same handler."""

    def __init__(self, host: str, http_port: int, https_port: int, cert: Optional[Path], key: Optional[Path]) -> None:
        self.http = ThreadingHTTPServer((host, http_port), EchoHandler)
        self.https: Optional[ThreadingHTTPServer] = None
        if https_port and cert and key and cert.exists() and key.exists():
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=str(cert), keyfile=str(key))

            def remember_sni(ssl_socket, server_name, _context):
                SNI.value = server_name
                return None

            context.set_servername_callback(remember_sni)
            self.https = ThreadingHTTPServer((host, https_port), EchoHandler)
            self.https.socket = context.wrap_socket(self.https.socket, server_side=True)

    def start(self) -> None:
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        if self.https is not None:
            threading.Thread(target=self.https.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.http.shutdown()
        self.http.server_close()
        if self.https is not None:
            self.https.shutdown()
            self.https.server_close()


def main(argv: Optional[Sequence[str]] = None) -> int:
    global CONTROL_PATH, LOG_PATH
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--http-port", type=int, default=8080)
    parser.add_argument("--https-port", type=int, default=0)
    parser.add_argument("--control", type=Path, default=Path("/fixtures/echo-control.json"))
    parser.add_argument("--log", type=Path, default=Path("/fixtures/echo-requests.jsonl"))
    parser.add_argument("--cert", type=Path)
    parser.add_argument("--key", type=Path)
    args = parser.parse_args(argv)

    CONTROL_PATH = args.control
    LOG_PATH = args.log
    args.log.parent.mkdir(parents=True, exist_ok=True)

    server = DualStackServer(args.listen, args.http_port, args.https_port, args.cert, args.key)
    server.start()
    print(
        f"echo-fixture http={args.listen}:{args.http_port} "
        f"https={args.listen}:{args.https_port} control={args.control}",
        flush=True,
    )

    stop = threading.Event()

    def shutdown(signum, frame):
        stop.set()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    while not stop.is_set():
        time.sleep(0.2)
    server.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
