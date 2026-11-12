#!/usr/bin/env python3
"""Independent HTTPS probe used by the Podman product E2E client role.

Runs unchanged on the Control Machine and inside a disposable client container:
it depends on nothing but the standard library, so the result cannot be
explained by a helper that the product installed.

    python3 tools/podman_e2e/http_probe.py --url https://panel.testbed.internal/ \
        --ca /fixtures/ca/issued-root.pem --expect-status 200

The JSON report goes to stdout. The exit status is 0 only when every requested
expectation held, so a caller may use either signal and still get diagnostics.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import ssl
import sys
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urlsplit

DEFAULT_TIMEOUT = 20
SNIPPET_LIMIT = 300


class ProbeError(RuntimeError):
    pass


def build_context(ca_file: Optional[str], insecure: bool) -> ssl.SSLContext:
    if insecure:
        # Only for a case that is explicitly measuring a rejection: verification
        # is switched off so the alert itself becomes the observation.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    if ca_file:
        context = ssl.create_default_context(cafile=ca_file)
    else:
        context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def peer_report(sock: Any) -> Dict[str, Any]:
    if sock is None:
        return {}
    try:
        cert = sock.getpeercert()
    except (ValueError, OSError):
        return {}
    if not cert:
        return {}
    san = [value for key, value in cert.get("subjectAltName", ()) if key == "DNS"]
    subject = "".join(f"{key}={value}" for entry in (cert.get("subject") or ()) for key, value in entry)
    issuer = "".join(f"{key}={value}" for entry in (cert.get("issuer") or ()) for key, value in entry)
    return {
        "subject": subject,
        "issuer": issuer,
        "san": san,
        "not_after": cert.get("notAfter", ""),
        "tls_version": sock.version() if hasattr(sock, "version") else "",
        "cipher": (sock.cipher() or ("", "", 0))[0] if hasattr(sock, "cipher") else "",
    }


def fetch(
    url: str,
    ca_file: Optional[str] = None,
    insecure: bool = False,
    headers: Sequence[str] = (),
    method: str = "GET",
    body: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ProbeError(f"unsupported scheme in {url!r}")
    host = parts.hostname or ""
    if not host:
        raise ProbeError(f"no host in {url!r}")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    request_headers: Dict[str, str] = {}
    for header in headers:
        name, _, value = header.partition(":")
        if not name.strip():
            raise ProbeError(f"malformed header: {header!r}")
        request_headers[name.strip()] = value.strip()

    if parts.scheme == "https":
        context = build_context(ca_file, insecure)
        connection: http.client.HTTPConnection = http.client.HTTPSConnection(
            host, parts.port or 443, context=context, timeout=timeout,
        )
    else:
        connection = http.client.HTTPConnection(host, parts.port or 80, timeout=timeout)

    try:
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        payload = response.read()
        report: Dict[str, Any] = {
            "url": url,
            "method": method,
            "status": response.status,
            "headers": {key.lower(): value for key, value in response.getheaders()},
            "body_length": len(payload),
            "body_sha256": hashlib.sha256(payload).hexdigest(),
            "body_snippet": payload[:SNIPPET_LIMIT].decode("utf-8", "replace"),
            "peer": peer_report(getattr(connection, "sock", None)) if parts.scheme == "https" else {},
        }
        return report
    finally:
        connection.close()


def evaluate(report: Dict[str, Any], args: argparse.Namespace) -> List[str]:
    failures: List[str] = []
    if args.expect_status is not None and report["status"] != args.expect_status:
        failures.append(f"status {report['status']} != {args.expect_status}")
    if args.expect_body is not None and args.expect_body not in report["body_snippet"]:
        failures.append(f"body does not contain {args.expect_body!r}")
    if args.expect_absent is not None and args.expect_absent in report["body_snippet"]:
        failures.append(f"body unexpectedly contains {args.expect_absent!r}")
    peer = report.get("peer") or {}
    for san in args.expect_san or ():
        if san not in (peer.get("san") or []):
            failures.append(f"certificate SAN list {peer.get('san')} does not include {san!r}")
    if args.expect_tls and not str(peer.get("tls_version", "")).startswith(args.expect_tls):
        failures.append(f"TLS version {peer.get('tls_version')!r} does not start with {args.expect_tls!r}")
    return failures


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--ca", default=None, help="CA bundle the probe must trust")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable verification, for cases that measure the resulting rejection",
    )
    parser.add_argument("--header", action="append", default=[], help="Repeatable 'Name: value'")
    parser.add_argument("--method", default="GET")
    parser.add_argument("--body", default=None)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--expect-status", type=int, default=None)
    parser.add_argument("--expect-body", default=None)
    parser.add_argument("--expect-absent", default=None)
    parser.add_argument("--expect-san", action="append", default=None)
    parser.add_argument("--expect-tls", default=None, help="Required TLS version prefix, e.g. TLSv1.3")
    args = parser.parse_args(argv)

    try:
        report = fetch(
            args.url,
            ca_file=args.ca,
            insecure=args.insecure,
            headers=args.header,
            method=args.method,
            body=args.body,
            timeout=args.timeout,
        )
    except (ProbeError, OSError, ssl.SSLError) as exc:
        print(json.dumps({"url": args.url, "error": f"{type(exc).__name__}: {exc}"}, sort_keys=True))
        return 1

    failures = evaluate(report, args)
    report["failures"] = failures
    if failures:
        report["error"] = "; ".join(failures)
    print(json.dumps(report, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
