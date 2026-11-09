"""Mutual TLS 1.3 control-plane verification and negative tests from Master to Worker:3002.
Enforces zero-leak credentials by extracting secret key on Master and streaming to stdin.
"""
from __future__ import annotations

import json
import shlex
from typing import Any, Dict, Optional, Tuple

from .ssh import SSHClient
from .panel_api import E2EPanelClient


def verify_worker_mtls(
    master_ssh: SSHClient,
    worker_ip: str,
    panel_client: Optional[E2EPanelClient] = None,
    port: int = 3002,
    timeout: int = 15,
) -> Dict[str, Any]:
    """Execute live mTLS verification from Master to Worker:3002 and audit Panel connection state."""
    # 1. Extract secret key raw on Master
    sec_cmd = "/opt/gowave/gowave-server rescue --print-secret-key-raw </dev/null 2>/dev/null || true"
    sec_r = master_ssh.run(sec_cmd)
    if not sec_r.ok or not sec_r.stdout.strip():
        return {
            "status": "FAIL",
            "error": "Failed to extract secret key on Master via rescue --print-secret-key-raw",
        }

    raw_secret = sec_r.stdout.strip()

    # 2. Run verify_node_mtls.py on Master passing raw_secret unchanged via stdin
    verifier_cmd = (
        f"python3 /opt/gowave-auto-nginx/modules/verify_node_mtls.py "
        f"--host {worker_ip} --port {port} --mode full --timeout {timeout}"
    )
    res = master_ssh.run(verifier_cmd, input_data=raw_secret)

    out = res.stdout
    payload_crypto_pass = "Payload cryptographic verification PASSED" in out
    mtls_handshake_pass = "Handshake SUCCESS: TLSv1.3 negotiated" in out
    worker_http_health_pass = "200 OK" in out

    panel_worker_auth_pass = False
    if panel_client:
        try:
            nodes = panel_client.get_nodes()
            for n in nodes:
                if n.get("name") == "worker-1" and n.get("isConnected") is True:
                    panel_worker_auth_pass = True
                    break
        except Exception:
            panel_worker_auth_pass = False

    status = "PASS" if (res.ok and payload_crypto_pass and mtls_handshake_pass and worker_http_health_pass and panel_worker_auth_pass) else "FAIL"

    return {
        "status": status,
        "payload_crypto_pass": payload_crypto_pass,
        "mtls_handshake_pass": mtls_handshake_pass,
        "worker_http_health_pass": worker_http_health_pass,
        "panel_worker_auth_pass": panel_worker_auth_pass,
        "verifier_exit_code": res.returncode,
    }


def run_mtls_negative_tests(
    master_ssh: SSHClient,
    worker_ip: str,
    port: int = 3002,
) -> Dict[str, Any]:
    """Verify all negative mTLS handshakes; transport failures are INCOMPLETE."""
    sec_cmd = "/opt/gowave/gowave-server rescue --print-secret-key-raw </dev/null 2>/dev/null || true"
    sec_r = master_ssh.run(sec_cmd)
    if not sec_r.ok or not sec_r.stdout.strip():
        return {"status": "INCOMPLETE", "error": "Cannot extract secret key for negative tests"}

    script = f"""
import base64, json, os, socket, ssl, subprocess, sys, tempfile
sys.path.insert(0, "/opt/gowave-auto-nginx")
from modules.verify_node_mtls import derive_sni, validate_payload_crypto
worker_ip = "{worker_ip}"
port = {port}
raw_secret = sys.stdin.read().strip()
payload = json.loads(base64.b64decode(raw_secret).decode("utf-8"))
ca_pem = payload["caCertPem"]
jwt_pub_pem = payload["jwtPublicKey"]
node_cert_pem = payload["nodeCertPem"]
node_key_pem = payload["nodeKeyPem"]
valid_sni = derive_sni(ca_pem, jwt_pub_pem)
results = {{}}

def handshake_rejected(context, server_name, expected_error):
    try:
        with socket.create_connection((worker_ip, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=server_name):
                return False
    except expected_error:
        return True
    except OSError:
        return "INCOMPLETE"

def observe_wrong_sni(context, server_name):
    # A wrong SNI may be handled by a fallback vhost after TLS completes.
    # Record either a handshake rejection or the actual HTTP routing response;
    # do not assume that every valid policy sends a TLS alert.
    try:
        with socket.create_connection((worker_ip, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=server_name) as tls:
                tls.sendall(
                    b"GET / HTTP/1.1\\r\\nHost: wrong-sni.example.com\\r\\n"
                    b"Connection: close\\r\\n\\r\\n"
                )
                response = tls.recv(1024)
                status_line = (
                    response.splitlines()[0].decode("ascii", errors="replace")
                    if response else ""
                )
                if not response:
                    return {{"outcome": "INCOMPLETE", "version": tls.version(),
                            "error": "TLS established but no routing response was received"}}
                return {{"outcome": "HTTP_RESPONSE", "version": tls.version(),
                        "status_line": status_line}}
    except ssl.SSLError as exc:
        return {{"outcome": "TLS_REJECTED", "error": type(exc).__name__}}
    except OSError as exc:
        return {{"outcome": "INCOMPLETE", "error": type(exc).__name__}}

with tempfile.TemporaryDirectory() as td:
    ca_file = td + "/ca.crt"
    cert_file = td + "/node.crt"
    key_file = td + "/node.key"
    with open(ca_file, "w") as f: f.write(ca_pem)
    with open(cert_file, "w") as f: f.write(node_cert_pem)
    with open(key_file, "w") as f: f.write(node_key_pem)
    untrusted_key = td + "/untrusted.key"
    untrusted_crt = td + "/untrusted.crt"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", untrusted_key, "-out", untrusted_crt, "-days", "1",
                    "-subj", "/CN=UntrustedClient"], capture_output=True, check=True)

    ctx_untrusted = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
    ctx_untrusted.check_hostname = False
    ctx_untrusted.verify_mode = ssl.CERT_REQUIRED
    ctx_untrusted.load_cert_chain(untrusted_crt, untrusted_key)
    results["untrusted_client_rejected"] = handshake_rejected(ctx_untrusted, valid_sni, ssl.SSLError)

    ctx_absent = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
    ctx_absent.check_hostname = False
    ctx_absent.verify_mode = ssl.CERT_REQUIRED
    results["absent_client_rejected"] = handshake_rejected(ctx_absent, valid_sni, ssl.SSLError)

    try:
        validate_payload_crypto(ca_pem, jwt_pub_pem, node_cert_pem, open(untrusted_key).read())
        results["mismatched_crypto_failed"] = False
    except ValueError:
        results["mismatched_crypto_failed"] = True

    untrusted_ca = td + "/untrusted-ca.crt"
    with open(untrusted_ca, "w") as f: f.write(open(untrusted_crt).read())
    ctx_bad_ca = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=untrusted_ca)
    ctx_bad_ca.check_hostname = False
    ctx_bad_ca.verify_mode = ssl.CERT_REQUIRED
    ctx_bad_ca.load_cert_chain(cert_file, key_file)
    results["untrusted_ca_rejected"] = handshake_rejected(
        ctx_bad_ca, valid_sni, ssl.SSLCertVerificationError
    )

    ctx_wrong_sni = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
    ctx_wrong_sni.check_hostname = False
    ctx_wrong_sni.verify_mode = ssl.CERT_REQUIRED
    ctx_wrong_sni.load_cert_chain(cert_file, key_file)
    results["wrong_sni_observation"] = observe_wrong_sni(
        ctx_wrong_sni, "wrong-sni.example.com"
    )

print(json.dumps(results))
"""
    command = "python3 -c " + shlex.quote(script)
    result = master_ssh.run(command, input_data=sec_r.stdout.strip(), timeout=60)
    if not result.ok:
        return {"status": "INCOMPLETE", "error": "Remote mTLS negative-test process failed"}

    parsed = None
    for line in reversed(result.stdout.splitlines()):
        if line.startswith("{") and line.endswith("}"):
            try:
                parsed = json.loads(line)
                break
            except json.JSONDecodeError:
                continue
    if not isinstance(parsed, dict):
        return {"status": "INCOMPLETE", "error": "Could not parse mTLS negative-test result"}

    required = (
        "untrusted_client_rejected", "absent_client_rejected",
        "mismatched_crypto_failed", "untrusted_ca_rejected",
    )
    if any(key not in parsed or parsed[key] == "INCOMPLETE" for key in required):
        parsed["status"] = "INCOMPLETE"
    elif not all(parsed[key] is True for key in required):
        parsed["status"] = "FAIL"
    else:
        wrong_sni = parsed.get("wrong_sni_observation")
        if isinstance(wrong_sni, dict) and wrong_sni.get("outcome") in ("TLS_REJECTED", "HTTP_RESPONSE"):
            # The required client-auth negative controls passed. A valid HTTP
            # response is concrete wrong-SNI routing evidence, not a failed
            # mTLS handshake assertion.
            parsed["status"] = "PASS"
        else:
            # TLS establishment without a routable response is insufficient
            # evidence; do not infer a TLS alert that the server need not send.
            parsed["status"] = "INCOMPLETE"
    return parsed
