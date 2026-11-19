#!/usr/bin/env python3
"""Standard-library DNS probe for the Podman product E2E.

Two scopes, because two different claims are being measured:

``direct``  sends its own UDP query to the named resolver. Nothing local can
            answer it, so the reply, its rcode, its records and its TTL are the
            authoritative ones the fixture zone published.
``system``  resolves through the host's own path, which is what a product step
            gets. Both families are asked separately and on purpose: a name that
            carries only an A record must not be answered with an AAAA. No
            ``AI_ADDRCONFIG`` is passed, so a host without IPv6 still reports
            the AAAA its resolver published instead of hiding it.

The probe reports facts and exits 0; the case decides what they mean.

    python3 tools/podman_e2e/dns_probe.py --scope direct --server 10.89.0.53 \\
        --query dns-a.testbed.internal:A --query dns-a.testbed.internal:AAAA
    python3 tools/podman_e2e/dns_probe.py --scope system \\
        --name dns-a.testbed.internal --name dns-aaaa.testbed.internal
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

TYPE_A = 1
TYPE_AAAA = 28
QTYPES = {"A": TYPE_A, "AAAA": TYPE_AAAA}
QTYPE_NAMES = {value: key for key, value in QTYPES.items()}

RCODE_NAMES = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}

DEFAULT_PORT = 53
DEFAULT_TIMEOUT_SECONDS = 3.0
# A question name has at most 127 labels and a response holds a bounded number
# of records; both loops are bounded so a malformed reply cannot spin.
MAX_LABELS = 128
RESOLV_CONF = Path("/etc/resolv.conf")


def encode_name(name: str) -> bytes:
    body = b""
    for label in name.rstrip(".").split("."):
        encoded = label.encode("idna")
        if not encoded or len(encoded) > 63:
            raise ValueError(f"invalid label in {name!r}")
        body += bytes([len(encoded)]) + encoded
    return body + b"\x00"


def query_packet(name: str, qtype: int, transaction_id: int) -> bytes:
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack("!HH", qtype, 1)


def skip_name(data: bytes, offset: int) -> int:
    for _ in range(MAX_LABELS):
        if offset >= len(data):
            raise ValueError("truncated name")
        length = data[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1
        if length == 0:
            return offset
        offset += length
    raise ValueError("name exceeds the label limit")


def decode_answers(data: bytes, offset: int, count: int) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for _ in range(count):
        offset = skip_name(data, offset)
        if offset + 10 > len(data):
            raise ValueError("truncated record header")
        rtype, _rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        offset += rdlength
        if rtype == TYPE_A and len(rdata) == 4:
            value = socket.inet_ntoa(rdata)
        elif rtype == TYPE_AAAA and len(rdata) == 16:
            value = socket.inet_ntop(socket.AF_INET6, rdata)
        else:
            value = ""
        records.append({"type": QTYPE_NAMES.get(rtype, str(rtype)), "ttl": ttl, "value": value})
    return records


def parse_response(data: bytes, transaction_id: int) -> Dict[str, Any]:
    if len(data) < 12:
        raise ValueError("truncated DNS header")
    answer_id, flags, qdcount, ancount = struct.unpack("!HHHH", data[:8])
    if answer_id != transaction_id:
        raise ValueError(f"answer for transaction {answer_id} instead of {transaction_id}")
    offset = 12
    for _ in range(qdcount):
        offset = skip_name(data, offset) + 4
    records = decode_answers(data, offset, ancount)
    rcode = flags & 0x000F
    return {
        "rcode": rcode,
        "rcode_name": RCODE_NAMES.get(rcode, str(rcode)),
        "records": records,
        "answers": [record["value"] for record in records],
    }


def direct_query(
    server: str, port: int, name: str, qtype: int, timeout: float,
) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "name": name,
        "type": QTYPE_NAMES[qtype],
        "rcode": -1,
        "rcode_name": "",
        "answers": [],
        "records": [],
        "ttl": 0,
        "elapsed_ms": 0,
        "error": "",
    }
    transaction_id = struct.unpack("!H", os.urandom(2))[0]
    started = time.monotonic()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(query_packet(name, qtype, transaction_id), (server, port))
            data, _address = sock.recvfrom(4096)
        report.update(parse_response(data, transaction_id))
        if report["records"]:
            report["ttl"] = min(record["ttl"] for record in report["records"])
    except (OSError, ValueError, struct.error) as error:
        report["error"] = f"{type(error).__name__}: {error}"
    report["elapsed_ms"] = int((time.monotonic() - started) * 1000)
    return report


def resolve(name: str, family: int) -> Tuple[List[str], str]:
    """The addresses the host's own path returns for one family, and its error."""
    try:
        infos = socket.getaddrinfo(name, None, family, socket.SOCK_STREAM, 0, 0)
    except socket.gaierror as error:
        return [], f"{type(error).__name__}: {error}"
    except OSError as error:
        return [], f"{type(error).__name__}: {error}"
    addresses: List[str] = []
    for _family, _type, _proto, _canonname, sockaddr in infos:
        address = str(sockaddr[0])
        if address not in addresses:
            addresses.append(address)
    return addresses, ""


def resolver_config() -> Dict[str, Any]:
    """Which resolver the system path will actually consult, as evidence."""
    config: Dict[str, Any] = {
        "path": str(RESOLV_CONF),
        "nameservers": [],
        "symlink": "",
        "error": "",
    }
    try:
        config["symlink"] = os.readlink(RESOLV_CONF) if RESOLV_CONF.is_symlink() else ""
        text = RESOLV_CONF.read_text(encoding="utf-8")
    except OSError as error:
        config["error"] = f"{type(error).__name__}: {error}"
        return config
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "nameserver":
            config["nameservers"].append(fields[1])
    return config


def parse_query(spec: str) -> Tuple[str, int]:
    name, _, qtype = spec.rpartition(":")
    if not name or qtype not in QTYPES:
        raise argparse.ArgumentTypeError(f"expected NAME:{'/'.join(QTYPES)}, got {spec!r}")
    return name.lower(), QTYPES[qtype]


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", choices=("direct", "system"), required=True)
    parser.add_argument("--server", default="", help="Resolver address for the direct scope")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--query", action="append", default=[], type=parse_query,
                        help="NAME:A or NAME:AAAA, repeatable (direct scope)")
    parser.add_argument("--name", action="append", default=[],
                        help="Name to resolve through the system path, repeatable (system scope)")
    args = parser.parse_args(argv)

    if args.scope == "direct":
        if not args.server:
            parser.error("the direct scope needs --server")
        if not args.query:
            parser.error("the direct scope needs at least one --query")
        report: Dict[str, Any] = {
            "scope": "direct",
            "server": args.server,
            "port": args.port,
            "queries": [
                direct_query(args.server, args.port, name, qtype, args.timeout)
                for name, qtype in args.query
            ],
        }
    else:
        if not args.name:
            parser.error("the system scope needs at least one --name")
        names: List[Dict[str, Any]] = []
        for name in args.name:
            inet, inet_error = resolve(name, socket.AF_INET)
            inet6, inet6_error = resolve(name, socket.AF_INET6)
            names.append({
                "name": name.lower(),
                "inet": inet,
                "inet6": inet6,
                "inet_error": inet_error,
                "inet6_error": inet6_error,
            })
        report = {"scope": "system", "resolver": resolver_config(), "names": names}

    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
