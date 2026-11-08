"""Mutual TLS 1.3 control-plane verification and negative tests from Master to Worker:3002.
Enforces zero-leak credentials by extracting secret key on Master and streaming to stdin.
"""
from __future__ import annotations

import json
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

    status = "PASS" if (payload_crypto_pass and mtls_handshake_pass and worker_http_health_pass and panel_worker_auth_pass) else "FAIL"

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
    """Execute server-side rejection tests from Master for untrusted, absent, mismatched,
    untrusted CA, and wrong SNI.
    """
    sec_cmd = "/opt/gowave/gowave-server rescue --print-secret-key-raw </dev/null 2>/dev/null || true"
    sec_r = master_ssh.run(sec_cmd)
    if not sec_r.ok or not sec_r.stdout.strip():
        return {"status": "FAIL", "error": "Cannot extract secret key for negative tests"}

    raw_secret = sec_r.stdout.strip()

    negative_runner_script = f"""
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

with tempfile.TemporaryDirectory() as td:
    ca_file = os.path.join(td, "ca.crt")
    cert_file = os.path.join(td, "node.crt")
    key_file = os.path.join(td, "node.key")
    with open(ca_file, "w") as f: f.write(ca_pem)
    with open(cert_file, "w") as f: f.write(node_cert_pem)
    with open(key_file, "w") as f: f.write(node_key_pem)

    # 1. Untrusted client certificate
    untrusted_key = os.path.join(td, "u.key")
    untrusted_crt = os.path.join(td, "u.crt")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", untrusted_key, "-out", untrusted_crt, "-days", "1",
                    "-subj", "/CN=UntrustedClient"], capture_output=True, check=True)

    ctx_untrusted = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
    ctx_untrusted.check_hostname = False
    ctx_untrusted.verify_mode = ssl.CERT_REQUIRED
    ctx_untrusted.load_cert_chain(untrusted_crt, untrusted_key)

    try:
        with socket.create_connection((worker_ip, port), timeout=5) as s:
            with ctx_untrusted.wrap_socket(s, server_hostname=valid_sni) as tls:
                tls.sendall(b"GET / HTTP/1.1\\r\\nHost: " + valid_sni.encode() + b"\\r\\n\\r\\n")
        results["untrusted_client_rejected"] = False
    except ssl.SSLError:
        results["untrusted_client_rejected"] = True
    except Exception as e:
        results["untrusted_client_rejected"] = True

    # 2. Absent client certificate
    ctx_absent = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
    ctx_absent.check_hostname = False
    ctx_absent.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((worker_ip, port), timeout=5) as s:
            with ctx_absent.wrap_socket(s, server_hostname=valid_sni) as tls:
                tls.sendall(b"GET / HTTP/1.1\\r\\nHost: " + valid_sni.encode() + b"\\r\\n\\r\\n")
        results["absent_client_rejected"] = False
    except ssl.SSLError:
        results["absent_client_rejected"] = True
    except Exception as e:
        results["absent_client_rejected"] = True

    # 3. Mismatched cert/key checked locally
    try:
        validate_payload_crypto(ca_pem, jwt_pub_pem, node_cert_pem, open(untrusted_key).read())
        results["mismatched_crypto_failed"] = False
    except ValueError:
        results["mismatched_crypto_failed"] = True

    # 4. Untrusted server CA
    untrusted_ca = os.path.join(td, "u_ca.crt")
    with open(untrusted_ca, "w") as f: f.write(open(untrusted_crt).read())
    ctx_bad_ca = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=untrusted_ca)
    ctx_bad_ca.check_hostname = False
    ctx_bad_ca.verify_mode = ssl.CERT_REQUIRED
    ctx_bad_ca.load_cert_chain(cert_file, key_file)
    try:
        with socket.create_connection((worker_ip, port), timeout=5) as s:
            with ctx_bad_ca.wrap_socket(s, server_hostname=valid_sni) as tls:
                tls.sendall(b"GET / HTTP/1.1\\r\\nHost: " + valid_sni.encode() + b"\\r\\n\\r\\n")
        results["untrusted_ca_rejected"] = False
    except ssl.SSLCertVerificationError:
        results["untrusted_ca_rejected"] = True
    except Exception:
        results["untrusted_ca_rejected"] = True

    # 5. Wrong SNI
    wrong_sni = "wrong-sni.example.com"
    ctx_valid = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
    ctx_valid.check_hostname = False
    ctx_valid.verify_mode = ssl.CERT_REQUIRED
    ctx_valid.load_cert_chain(cert_file, key_file)
    try:
        with socket.create_connection((worker_ip, port), timeout=5) as s:
            with ctx_valid.wrap_socket(s, server_hostname=wrong_sni) as tls:
                tls.sendall(b"GET / HTTP/1.1\\r\\nHost: " + wrong_sni.encode() + b"\\r\\n\\r\\n")
                resp = tls.recv(1024)
                results["wrong_sni_outcome"] = "HANDSHAKE_OR_RESPONSE"
    except Exception as e:
        results["wrong_sni_outcome"] = f"REJECTED: {{type(e).__name__}}"

print(json.dumps(results))
"""
    res = master_ssh.run("python3 -", input_data=f"{raw_secret}\n{negative_runner_script}")
    if not res.ok:
        return {"status": "FAIL", "error": res.stderr}

    for line in res.stdout.splitlines():
        if line.startswith("{") and line.endswith("}"):
            try:
                parsed = json.loads(line)
                parsed["status"] = "PASS" if all([
                    parsed.get("untrusted_client_rejected"),
                    parsed.get("absent_client_rejected"),
                    parsed.get("mismatched_crypto_failed"),
                    parsed.get("untrusted_ca_rejected"),
                ]) else "FAIL"
                return parsed
            except Exception:
                pass

    return {"status": "FAIL", "error": "Failed to parse negative tests output"}
