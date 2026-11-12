#!/usr/bin/env python3
"""Controllable authoritative DNS fixture for the Podman product E2E.

Answers A/AAAA from a JSON zone, with switchable failure behaviour and a JSONL
query log that doubles as the resolver diagnostics trail. The zone is re-read
when its mtime changes, so a case can flip NXDOMAIN, a wrong address, a stale
TTL, or a latency injection without restarting the fixture.

    python3 tests/fixtures/dns_server.py --port 5353 --zone /fixtures/dns-zone.json

This fixture never forwards to a public resolver and never reads /etc/resolv.conf.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

TYPE_A = 1
TYPE_AAAA = 28
QTYPE_NAMES = {TYPE_A: "A", TYPE_AAAA: "AAAA"}

RCODE_NOERROR = 0
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_REFUSED = 5

DEFAULT_SUFFIX = "testbed.internal"

DEFAULT_ZONE: Dict[str, object] = {
    "ttl": 300,
    "records": {},
    "behavior": {"mode": "answer", "delay_ms": 0},
}


def log_event(log_path: Optional[Path], event: Dict[str, object]) -> None:
    if log_path is None:
        return
    line = json.dumps(event, sort_keys=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
        handle.flush()
        os.fsync(handle.fileno())


class Zone:
    """Zone + behaviour, reloaded on mtime change so cases can steer answers."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._stamp: Tuple[float, int] = (-1.0, -1)
        self._data: Dict[str, object] = dict(DEFAULT_ZONE)
        self._lock = threading.Lock()
        self.reload()

    def reload(self) -> None:
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            self._data = dict(DEFAULT_ZONE)
            return
        stamp = (stat.st_mtime, stat.st_size)
        with self._lock:
            if stamp == self._stamp:
                return
            raw = json.loads(self.path.read_text(encoding="utf-8") or "{}")
            self._data = {**DEFAULT_ZONE, **raw}
            self._stamp = stamp

    @property
    def data(self) -> Dict[str, object]:
        self.reload()
        with self._lock:
            return dict(self._data)

    @property
    def behavior(self) -> Dict[str, object]:
        return dict(self.data.get("behavior") or {})

    @property
    def ttl(self) -> int:
        return int(self.data.get("ttl", 300))

    def lookup(self, name: str, qtype: int) -> Tuple[int, List[str], int]:
        """Return (rcode, answers, ttl) for a question under the current behaviour."""
        behaviour = self.behavior
        mode = str(behaviour.get("mode", "answer"))
        qtype_name = QTYPE_NAMES.get(qtype)

        if mode == "nxdomain":
            return RCODE_NXDOMAIN, [], self.ttl
        if mode == "servfail":
            return RCODE_SERVFAIL, [], self.ttl

        records = dict(self.data.get("records") or {})
        if mode in ("wrong", "stale"):
            overrides = dict(behaviour.get("overrides") or {})
            merged = {**records, **overrides}
            ttl = int(behaviour.get("ttl", 5)) if mode == "stale" else self.ttl
            records = merged
        else:
            ttl = self.ttl

        entry = records.get(name)
        if entry is None:
            return RCODE_NXDOMAIN, [], ttl
        if qtype_name is None:
            return RCODE_NOERROR, [], ttl
        values = entry.get(qtype_name) or []
        if isinstance(values, str):
            values = [values]
        return RCODE_NOERROR, [str(value) for value in values], ttl


def parse_question(data: bytes) -> Tuple[int, str, int, int, int, bytes]:
    if len(data) < 12:
        raise ValueError("truncated DNS header")
    transaction_id, flags, qdcount = struct.unpack("!HHH", data[:6])
    if qdcount != 1:
        raise ValueError(f"expected exactly one question, got {qdcount}")
    offset = 12
    labels: List[str] = []
    while True:
        if offset >= len(data):
            raise ValueError("truncated question name")
        length = data[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:
            raise ValueError("compressed question names are not supported")
        labels.append(data[offset:offset + length].decode("latin1"))
        offset += length
    if offset + 4 > len(data):
        raise ValueError("truncated question type")
    qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
    offset += 4
    return transaction_id, ".".join(labels).lower(), qtype, qclass, int(flags), data[12:offset]


def encode_answer(name_pointer: bytes, qtype: int, ttl: int, values: Sequence[str]) -> bytes:
    answers = b""
    for value in values:
        if qtype == TYPE_A:
            rdata = socket.inet_aton(value)
        elif qtype == TYPE_AAAA:
            rdata = socket.inet_pton(socket.AF_INET6, value)
        else:
            continue
        answers += name_pointer + struct.pack("!HHIH", qtype, 1, ttl, len(rdata)) + rdata
    return answers


def in_zone(name: str, suffixes: Sequence[str]) -> bool:
    return any(name == suffix or name.endswith("." + suffix) for suffix in suffixes)


def build_response(
    query: bytes,
    zone: Zone,
    client: str,
    log_path: Optional[Path],
    suffixes: Sequence[str] = (DEFAULT_SUFFIX,),
    out_of_zone: str = "nxdomain",
) -> bytes:
    transaction_id, name, qtype, qclass, flags, question = parse_question(query)
    behaviour = zone.behavior
    delay_ms = int(behaviour.get("delay_ms", 0) or 0)
    if delay_ms > 0:
        time.sleep(min(delay_ms, 5000) / 1000.0)

    if not in_zone(name, suffixes):
        # Out-of-zone names are never answered from here. REFUSED lets a resolver
        # list fall through to the real resolver the target needs for packages,
        # while a name inside the fixture zone can never be answered elsewhere.
        rcode = RCODE_REFUSED if out_of_zone == "refused" else RCODE_NXDOMAIN
        values: List[str] = []
        ttl = zone.ttl
        path = "out-of-zone-refused" if out_of_zone == "refused" else "out-of-zone-nxdomain"
    else:
        rcode, values, ttl = zone.lookup(name, qtype)
        path = "authoritative"
    answer_bytes = encode_answer(b"\xc0\x0c", qtype, ttl, values) if rcode == RCODE_NOERROR else b""
    answer_count = len(values) if rcode == RCODE_NOERROR else 0

    response_flags = 0x8000 | 0x0400 | (flags & 0x0100) | rcode
    header = struct.pack("!HHHHHH", transaction_id, response_flags, 1, answer_count, 0, 0)
    log_event(log_path, {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "client": client,
        "qname": name,
        "qtype": QTYPE_NAMES.get(qtype, str(qtype)),
        "qclass": qclass,
        "mode": str(behaviour.get("mode", "answer")),
        "path": path,
        "rcode": rcode,
        "answers": values,
        "ttl": ttl,
    })
    return header + question + answer_bytes


def serve_udp(
    sock: socket.socket,
    zone: Zone,
    log_path: Optional[Path],
    stop: threading.Event,
    suffixes: Sequence[str],
    out_of_zone: str,
) -> None:
    while not stop.is_set():
        try:
            data, address = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            return
        try:
            response = build_response(
                data, zone, f"{address[0]}:{address[1]}", log_path, suffixes, out_of_zone,
            )
        except (ValueError, struct.error) as exc:
            log_event(log_path, {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "client": f"{address[0]}:{address[1]}",
                "error": str(exc),
            })
            continue
        try:
            sock.sendto(response, address)
        except OSError:
            continue


def handle_tcp(
    conn: socket.socket,
    zone: Zone,
    log_path: Optional[Path],
    suffixes: Sequence[str],
    out_of_zone: str,
) -> None:
    with conn:
        conn.settimeout(5)
        try:
            length_data = conn.recv(2)
            if len(length_data) < 2:
                return
            length = struct.unpack("!H", length_data)[0]
            data = b""
            while len(data) < length:
                chunk = conn.recv(length - len(data))
                if not chunk:
                    return
                data += chunk
            response = build_response(
                data, zone, str(conn.getpeername()[0]), log_path, suffixes, out_of_zone,
            )
            conn.sendall(struct.pack("!H", len(response)) + response)
        except (OSError, ValueError, struct.error):
            return


def serve_tcp(
    sock: socket.socket,
    zone: Zone,
    log_path: Optional[Path],
    stop: threading.Event,
    suffixes: Sequence[str],
    out_of_zone: str,
) -> None:
    sock.settimeout(0.5)
    while not stop.is_set():
        try:
            conn, _ = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            return
        threading.Thread(target=handle_tcp, args=(conn, zone, log_path), daemon=True).start()


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5353)
    parser.add_argument("--zone", type=Path, default=Path("/fixtures/dns-zone.json"))
    parser.add_argument("--log", type=Path, default=Path("/fixtures/dns-queries.jsonl"))
    parser.add_argument("--no-tcp", action="store_true", help="Serve UDP only")
    parser.add_argument(
        "--suffix",
        action="append",
        default=None,
        help=f"Authoritative zone suffix (repeatable, default {DEFAULT_SUFFIX})",
    )
    parser.add_argument(
        "--out-of-zone",
        choices=("nxdomain", "refused"),
        default="nxdomain",
        help="Answer for names outside the authoritative suffixes",
    )
    args = parser.parse_args(argv)

    args.log.parent.mkdir(parents=True, exist_ok=True)
    suffixes = tuple(args.suffix or (DEFAULT_SUFFIX,))
    zone = Zone(args.zone)
    stop = threading.Event()

    def shutdown(signum, frame):
        stop.set()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind((args.listen, args.port))
    udp.settimeout(0.5)

    threads = [threading.Thread(
        target=serve_udp, args=(udp, zone, args.log, stop, suffixes, args.out_of_zone), daemon=True,
    )]
    if not args.no_tcp:
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind((args.listen, args.port))
        tcp.listen(8)
        threads.append(threading.Thread(
            target=serve_tcp, args=(tcp, zone, args.log, stop, suffixes, args.out_of_zone), daemon=True,
        ))

    for thread in threads:
        thread.start()
    print(f"dns-fixture listening on {args.listen}:{args.port} zone={args.zone}", flush=True)
    while not stop.is_set():
        time.sleep(0.2)
    udp.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
