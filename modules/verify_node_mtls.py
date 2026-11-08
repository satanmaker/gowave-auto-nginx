#!/usr/bin/env python3
"""GoWave Node mTLS 1.3 and Cryptographic Health Verifier.
Validates the base64 SECRET_KEY payload, performs strict X.509 and RSA/EC
cryptographic verification, derives HKDF-SHA256 SNI ('rw-v1'), and executes
a mutual TLS 1.3 client handshake against the GoWave Node daemon.
Enforces AGENTS.md zero-leak standards by reading credentials from stdin.
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import tempfile


def derive_sni(ca_cert_pem: str, jwt_pub_key_pem: str) -> str:
    """Computes HKDF-SHA256 derived SNI matching upstream GoWave/gowave-node ('rw-v1')."""
    re_header = re.compile(r"-----[^-]+-----")
    re_non_b64 = re.compile(r"[^A-Za-z0-9+/=]")

    def canon(s: str) -> str:
        s = re_header.sub("", s)
        return re_non_b64.sub("", s)

    ikm = (canon(jwt_pub_key_pem) + canon(ca_cert_pem)).encode("utf-8")
    salt = bytes(32)  # RFC 5869 null salt = hash.Size zeros
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()

    okm = b""
    t = b""
    counter = 1
    while len(okm) < 22:
        t = hmac.new(prk, t + b"rw-v1" + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1

    okm = okm[:22]
    host = okm[:16].hex()
    sub = okm[16:21].hex()
    tlds = ["com", "net", "org", "io", "dev", "app"]
    tld = tlds[okm[21] % len(tlds)]
    return f"{host}.{sub}.{tld}"


def validate_payload_crypto(ca_pem: str, jwt_pub_pem: str, node_cert_pem: str, node_key_pem: str):
    """Performs strict cryptographic verification on the certificates and keys."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        ca_file = tmp / "ca.crt"
        cert_file = tmp / "node.crt"
        key_file = tmp / "node.key"
        jwt_file = tmp / "jwt.pub"

        ca_file.write_text(ca_pem)
        cert_file.write_text(node_cert_pem)
        key_file.write_text(node_key_pem)
        jwt_file.write_text(jwt_pub_pem)

        # 1. Verify node certificate public key matches node private key
        res_cert_pk = subprocess.run(["openssl", "x509", "-in", str(cert_file), "-noout", "-pubkey"],
                                     capture_output=True, text=True)
        if res_cert_pk.returncode != 0:
            raise ValueError(f"Failed parsing node certificate: {res_cert_pk.stderr.strip()}")

        res_key_pk = subprocess.run(["openssl", "pkey", "-in", str(key_file), "-pubout"],
                                    capture_output=True, text=True)
        if res_key_pk.returncode != 0:
            raise ValueError(f"Failed parsing node private key: {res_key_pk.stderr.strip()}")

        if res_cert_pk.stdout.strip() != res_key_pk.stdout.strip():
            raise ValueError("Cryptographic mismatch: node certificate public key does not match node private key")

        # 2. Verify node certificate was signed by CA certificate
        res_verify = subprocess.run(["openssl", "verify", "-CAfile", str(ca_file), str(cert_file)],
                                    capture_output=True, text=True)
        if res_verify.returncode != 0 or "OK" not in res_verify.stdout:
            raise ValueError(f"CA verification failed: node certificate is not signed by CA: {res_verify.stderr.strip()}")

        # 3. Verify JWT public key is valid RSA
        res_jwt = subprocess.run(["openssl", "rsa", "-pubin", "-in", str(jwt_file), "-noout"],
                                 capture_output=True, text=True)
        if res_jwt.returncode != 0:
            raise ValueError(f"Invalid JWT RSA public key: {res_jwt.stderr.strip()}")


def perform_mtls_handshake(host: str, port: int, sni: str, ca_pem: str, cert_pem: str, key_pem: str,
                           timeout: float = 10.0) -> dict:
    """Connects to GoWave Node, negotiates mTLS 1.3 with derived SNI, and queries health endpoint."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        ca_file = tmp / "ca.crt"
        cert_file = tmp / "node.crt"
        key_file = tmp / "node.key"

        ca_file.write_text(ca_pem)
        cert_file.write_text(cert_pem)
        key_file.write_text(key_pem)

        # Build TLS 1.3 client context
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(str(ca_file))
        ctx.load_cert_chain(str(cert_file), str(key_file))

        # Connect TCP socket
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        try:
            # Wrap socket with TLS 1.3 and SNI
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname=sni)
            try:
                actual_version = tls_sock.version()
                if actual_version != "TLSv1.3":
                    raise ssl.SSLError(f"Expected TLSv1.3 negotiation, got {actual_version}")

                # Send HTTP health check request
                http_req = (
                    f"GET /node/xray/healthcheck HTTP/1.1\r\n"
                    f"Host: {sni}\r\n"
                    f"User-Agent: gowave-auto-nginx/mtls-verifier\r\n"
                    f"Accept: application/json\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("utf-8")
                tls_sock.sendall(http_req)

                raw_resp = b""
                while True:
                    chunk = tls_sock.recv(4096)
                    if not chunk:
                        break
                    raw_resp += chunk
            finally:
                tls_sock.close()
        finally:
            raw_sock.close()

    resp_text = raw_resp.decode("utf-8", errors="replace")
    status_line = resp_text.splitlines()[0] if resp_text else ""
    return {
        "status_line": status_line,
        "tls_version": actual_version,
        "raw_response": resp_text,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="Target node host (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=3002, help="Target node port (default 3002)")
    parser.add_argument("--mode", choices=["full", "crypto-only"], default="full",
                        help="Verification mode: 'full' (crypto + live TLS 1.3 socket) or 'crypto-only'")
    parser.add_argument("--timeout", type=float, default=10.0, help="Socket connect and handshake timeout")
    args = parser.parse_args()

    # Read base64 secret payload strictly from standard input
    raw_input = sys.stdin.read().strip()
    if not raw_input:
        print("Error: Empty secret key payload provided on standard input", file=sys.stderr)
        return 1

    try:
        decoded_bytes = base64.b64decode(raw_input)
        payload = json.loads(decoded_bytes.decode("utf-8"))
    except Exception as e:
        print(f"Error: Failed to decode base64 JSON payload: {e}", file=sys.stderr)
        return 1

    required_keys = ("caCertPem", "jwtPublicKey", "nodeCertPem", "nodeKeyPem")
    for key in required_keys:
        if key not in payload or not str(payload[key]).strip():
            print(f"Error: Missing or empty required cryptographic field '{key}' in secret key", file=sys.stderr)
            return 1

    ca_pem = payload["caCertPem"]
    jwt_pub_pem = payload["jwtPublicKey"]
    node_cert_pem = payload["nodeCertPem"]
    node_key_pem = payload["nodeKeyPem"]

    # 1. Cryptographic validation of certificate chain and keys
    try:
        validate_payload_crypto(ca_pem, jwt_pub_pem, node_cert_pem, node_key_pem)
    except Exception as e:
        print(f"Error: Cryptographic payload validation failed: {e}", file=sys.stderr)
        return 1

    # 2. Derive HKDF SNI ('rw-v1')
    try:
        sni = derive_sni(ca_pem, jwt_pub_pem)
    except Exception as e:
        print(f"Error: Failed to compute HKDF-derived SNI: {e}", file=sys.stderr)
        return 1

    print(f"Derived HKDF SNI (rw-v1): {sni}")
    print("Payload cryptographic verification PASSED (CA signature, node EC keypair match, RSA JWT public key).")

    if args.mode == "crypto-only":
        print("Mode crypto-only: mTLS socket handshake skipped.")
        return 0

    # 3. Live mTLS 1.3 socket connection and healthcheck
    print(f"Initiating mutual TLS 1.3 handshake to https://{args.host}:{args.port} with SNI '{sni}'...")
    try:
        res = perform_mtls_handshake(args.host, args.port, sni, ca_pem, node_cert_pem, node_key_pem, timeout=args.timeout)
        print(f"Handshake SUCCESS: {res['tls_version']} negotiated.")
        print(f"Node response: {res['status_line']}")

        # Upstream go-node returns 200 OK (if token) or 401 Unauthorized (JWT required),
        # both proving that the mutual TLS 1.3 handshake and SNI check passed.
        if "200 OK" in res["status_line"] or "401 Unauthorized" in res["status_line"]:
            print("mTLS 1.3 control plane verification PASSED.")
            return 0
        else:
            print(f"Error: Unexpected HTTP response status from node: {res['status_line']}", file=sys.stderr)
            return 1
    except Exception as e:
        print(f"Error: mTLS 1.3 handshake failed: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
