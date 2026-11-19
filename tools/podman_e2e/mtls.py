"""MTLS-01..08: the product's own mTLS 1.3 verifier against the deployed Worker.

The Master is the vantage an operator has: `modules/node.sh:extract_secret_key`
reads the already-Base64-encoded payload there, and `verify_node_mtls.py`
consumes that value unchanged over stdin. Nothing here re-encodes the payload,
and the derived SNI is dropped before anything is recorded — both are what the
catalogue forbids.

The negative controls reuse the product's own `validate_payload_crypto()` for the
mismatched-pair case, so a local failure is proven to be local: the check must
fail with no socket opened at all.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

NODE_PORT = 3002

# The verifier's own socket timeout is 10s; the margin covers apt-free openssl
# work on a host that is already provisioned.
VERIFIER_TIMEOUT_SECONDS = 120
NEGATIVE_TIMEOUT_SECONDS = 180

PAYLOAD_MARKER = "Payload cryptographic verification PASSED"
SOCKET_MARKER = "Initiating mutual TLS 1.3 handshake"
HANDSHAKE_MARKER = "Handshake SUCCESS: TLSv1.3 negotiated"
RESPONSE_PREFIX = "Node response: "
SNI_PREFIX = "Derived HKDF SNI"

_POSITIVE_SCRIPT = """\
set -euo pipefail
# The product's own extractor and verifier, in the order an operator runs them.
# The payload stays inside this shell: it is never an argv entry and is never
# re-encoded here.
source /repo/modules/node.sh
secret="$(extract_secret_key)"
verify_node_mtls_health "$secret" __NODE_PORT__ __WORKER_IP__ full
"""

# Runs on the Master with the deployed payload in hand. Every negative control
# is classified by *who* refused, because "the handshake failed" alone cannot
# tell a Worker-side rejection from this side's own trust failure.
_NEGATIVE_SCRIPT = r'''
import base64, json, socket, ssl, subprocess, sys, tempfile

sys.path.insert(0, "/repo")
from modules.verify_node_mtls import derive_sni, validate_payload_crypto

worker_ip = "__WORKER_IP__"
port = __NODE_PORT__

extracted = subprocess.run(
    ["bash", "-lc", "source /repo/modules/node.sh && extract_secret_key"],
    capture_output=True, text=True,
)
if extracted.returncode != 0 or not extracted.stdout.strip():
    print(json.dumps({"error": "the Master could not extract the secret key"}))
    raise SystemExit(1)

payload = json.loads(base64.b64decode(extracted.stdout.strip()).decode("utf-8"))
ca_pem = payload["caCertPem"]
jwt_pub_pem = payload["jwtPublicKey"]
node_cert_pem = payload["nodeCertPem"]
node_key_pem = payload["nodeKeyPem"]
valid_sni = derive_sni(ca_pem, jwt_pub_pem)
results = {}


def attempt(context, server_name):
    """One client-auth attempt, classified by which side refused it."""
    try:
        with socket.create_connection((worker_ip, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=server_name) as tls:
                tls.sendall(
                    b"GET /node/xray/healthcheck HTTP/1.1\r\nHost: "
                    + server_name.encode() + b"\r\nConnection: close\r\n\r\n"
                )
                response = tls.recv(1024)
                if not response:
                    return {"outcome": "NO_RESPONSE", "version": tls.version()}
                return {
                    "outcome": "HTTP_RESPONSE",
                    "version": tls.version(),
                    "status_line": response.splitlines()[0].decode("ascii", errors="replace"),
                }
    except ssl.SSLCertVerificationError as exc:
        # This client refused the Worker's certificate: a trust failure on this
        # side, never evidence that the Worker rejected the client.
        return {"outcome": "SERVER_CERT_REJECTED", "error": type(exc).__name__}
    except ssl.SSLError as exc:
        return {"outcome": "TLS_REJECTED", "error": type(exc).__name__}
    except OSError as exc:
        return {"outcome": "INCOMPLETE", "error": type(exc).__name__}


with tempfile.TemporaryDirectory() as td:
    ca_file = td + "/ca.crt"
    cert_file = td + "/node.crt"
    key_file = td + "/node.key"
    untrusted_key = td + "/untrusted.key"
    untrusted_crt = td + "/untrusted.crt"
    with open(ca_file, "w") as handle:
        handle.write(ca_pem)
    with open(cert_file, "w") as handle:
        handle.write(node_cert_pem)
    with open(key_file, "w") as handle:
        handle.write(node_key_pem)
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", untrusted_key, "-out", untrusted_crt, "-days", "1",
         "-subj", "/CN=UntrustedClient"],
        capture_output=True, check=True,
    )

    def context(ca_path, cert=None, key=None, server_name=valid_sni):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(ca_path)
        if cert:
            ctx.load_cert_chain(cert, key)
        return ctx

    # MTLS-04: a self-signed client certificate the Worker's CA never signed.
    results["untrusted_client"] = attempt(context(ca_file, untrusted_crt, untrusted_key), valid_sni)

    # MTLS-05: no client certificate at all.
    results["absent_client"] = attempt(context(ca_file), valid_sni)

    # MTLS-06: the payload crypto path compares the certificate's public key with
    # the private key's, entirely locally. A socket opened while it runs would
    # mean the check is not local, so the transport is counted.
    opened = []
    real_socket = socket.socket

    def counting_socket(*args, **kwargs):
        opened.append(args)
        return real_socket(*args, **kwargs)

    with open(untrusted_key) as handle:
        mismatched_key = handle.read()
    socket.socket = counting_socket
    try:
        validate_payload_crypto(ca_pem, jwt_pub_pem, node_cert_pem, mismatched_key)
        results["mismatched_crypto_failed"] = False
    except ValueError:
        results["mismatched_crypto_failed"] = True
    finally:
        socket.socket = real_socket
    results["mismatched_socket_calls"] = len(opened)

    # MTLS-07: same SNI and client identity, only the server-trust store replaced.
    with open(td + "/untrusted-ca.crt", "w") as handle:
        handle.write(open(untrusted_crt).read())
    results["untrusted_ca"] = attempt(
        context(td + "/untrusted-ca.crt", cert_file, key_file), valid_sni,
    )

    # MTLS-08: a deliberately incorrect SNI, measured rather than assumed.
    results["wrong_sni"] = attempt(
        context(ca_file, cert_file, key_file), "wrong-sni.example.com",
    )

print(json.dumps(results))
'''


def positive_script(worker_ip: str, port: int = NODE_PORT) -> str:
    """The operator's own positive check, as `modules/node.sh` runs it."""
    return (
        _POSITIVE_SCRIPT
        .replace("__WORKER_IP__", worker_ip)
        .replace("__NODE_PORT__", str(port))
    )


def negative_script(worker_ip: str, port: int = NODE_PORT) -> str:
    """Every negative control in one process, so one payload decode serves all."""
    return (
        _NEGATIVE_SCRIPT
        .replace("__WORKER_IP__", worker_ip)
        .replace("__NODE_PORT__", str(port))
    )


def sanitized_lines(text: str) -> List[str]:
    """Every line except the derived SNI, which must never be recorded."""
    return [line for line in (text or "").splitlines() if SNI_PREFIX not in line]


def safe_tail(result: Any, limit: int = 1500) -> str:
    """The verifier's own words, minus the derived SNI, for a failure message."""
    lines = sanitized_lines(getattr(result, "stderr", "") or "")
    lines += sanitized_lines(getattr(result, "stdout", "") or "")
    return "\n".join(lines).strip()[-limit:]


def classify_response(status_line: str) -> str:
    """Health, unauthenticated, other, or nothing — never inferred from the handshake."""
    code: Optional[int] = None
    for field in status_line.split():
        if len(field) == 3 and field.isdigit():
            code = int(field)
            break
    if code is None:
        return "none"
    if code == 200:
        return "health"
    if code == 401:
        return "unauthenticated"
    return "other"


def parse_verifier_output(stdout: str) -> Dict[str, Any]:
    """The observations the catalogue names, in the order the verifier printed them.

    The payload proof must appear *before* the socket attempt: a handshake that
    succeeded against an unverified payload would still print a green line, and
    only the order tells the two apart.
    """
    lines = (stdout or "").splitlines()

    def index_of(marker: str) -> int:
        for index, line in enumerate(lines):
            if marker in line:
                return index
        return -1

    payload_at = index_of(PAYLOAD_MARKER)
    socket_at = index_of(SOCKET_MARKER)
    handshake_at = index_of(HANDSHAKE_MARKER)
    status_line = ""
    for line in lines:
        if line.startswith(RESPONSE_PREFIX):
            status_line = line[len(RESPONSE_PREFIX):].strip()
    return {
        "payload_crypto_pass": payload_at >= 0,
        "payload_verified_before_socket": 0 <= payload_at < socket_at,
        "handshake_pass": handshake_at >= 0,
        "handshake_line": lines[handshake_at].strip() if handshake_at >= 0 else "",
        "status_line": status_line,
        "response": classify_response(status_line),
    }


def parse_negative_report(stdout: str) -> Dict[str, Any]:
    """The JSON report the negative controls print, or an empty report."""
    for line in reversed((stdout or "").splitlines()):
        if not (line.startswith("{") and line.endswith("}")):
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return {}


def run_positive(
    podman: Any, container: str, worker_ip: str,
    timeout: int = VERIFIER_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """Run the product's verifier on the Master against the deployed Worker."""
    result = podman.exec_bash(container, positive_script(worker_ip), check=False, timeout=timeout)
    facts = parse_verifier_output(result.stdout or "")
    facts["returncode"] = result.returncode
    facts["tail"] = safe_tail(result)
    return facts


def run_negatives(
    podman: Any, container: str, worker_ip: str,
    timeout: int = NEGATIVE_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """Run every negative control on the Master; one payload decode serves all."""
    result = podman.exec(
        container, ["python3", "-c", negative_script(worker_ip)],
        check=False, timeout=timeout,
    )
    return {
        "returncode": result.returncode,
        "report": parse_negative_report(result.stdout or ""),
        "tail": safe_tail(result),
    }
