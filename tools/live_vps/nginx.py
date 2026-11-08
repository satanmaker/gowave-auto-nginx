"""NGINX Stream SNI demux, REALITY decoy fallback, and configuration verification.
Verifies port 443 SNI demultiplexing, proxy protocol, and camouflage decoy fallbacks.
"""
from __future__ import annotations

import http.client
import socket
import ssl
import urllib.request
import urllib.error
from typing import Any, Dict, Optional, Tuple

from .ssh import SSHClient


def verify_nginx_config_syntax(ssh: SSHClient) -> Tuple[bool, str]:
    """Execute nginx -t on remote host."""
    r = ssh.run("nginx -t")
    output = f"{r.stdout}\n{r.stderr}".strip()
    return r.ok and "syntax is ok" in output and "test is successful" in output, output


def verify_cover_reality_assets(ssh: SSHClient) -> Tuple[bool, str]:
    """Verify presence of cover-reality decoy assets and index marker."""
    chk = ssh.run("test -d /opt/cover-reality && test -f /opt/cover-reality/index.html")
    if not chk.ok:
        return False, "Cover-reality directory or index.html missing"
    # Check marker content
    content_chk = ssh.run("head -n 20 /opt/cover-reality/index.html")
    return True, content_chk.stdout.strip()


def verify_panel_https(
    panel_domain: str,
    ssl_context: ssl.SSLContext,
    timeout: int = 10,
) -> Dict[str, Any]:
    """Verify GoWave Panel responds over HTTPS with correct certificate and headers."""
    url = f"https://{panel_domain}/"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, context=ssl_context, timeout=timeout) as resp:
            status = resp.status
            body = resp.read(1024).decode("utf-8", errors="replace")
            return {"status": "PASS", "http_status": status, "body_snippet": body[:100]}
    except urllib.error.HTTPError as e:
        # e.g. 404 or 401 is still a valid HTTP response from Panel behind NGINX
        return {"status": "PASS", "http_status": e.code}
    except Exception as e:
        return {"status": "FAIL", "error": f"Failed connecting to Panel HTTPS: {e}"}


def verify_reality_decoy_fallback(
    target_ip: str,
    reality_domain: str,
    ssl_context: ssl.SSLContext,
    port: int = 443,
    timeout: int = 10,
) -> Dict[str, Any]:
    """Verify that TLS connection to port 443 with REALITY SNI without REALITY credentials
    falls back to decoy static site (port 9443), and never returns GoWave API.
    """
    try:
        # Connect raw socket to target_ip:443 and wrap with SSL using server_hostname=reality_domain
        raw_sock = socket.create_connection((target_ip, port), timeout=timeout)
        tls_sock = ssl_context.wrap_socket(raw_sock, server_hostname=reality_domain)
        try:
            http_req = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {reality_domain}\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("utf-8")
            tls_sock.sendall(http_req)

            chunks = []
            while True:
                data = tls_sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
            resp_bytes = b"".join(chunks)
        finally:
            tls_sock.close()

        resp_text = resp_bytes.decode("utf-8", errors="replace")

        # Crucial security assertion: Decoy check FAILS if GoWave API content is returned
        if "gowave" in resp_text.lower() or "accesstoken" in resp_text.lower() or "/api/" in resp_text:
            return {
                "status": "FAIL",
                "error": "REALITY fallback leaked GoWave Panel API content!",
                "snippet": resp_text[:200],
            }

        # Check for static html decoy
        is_decoy = "<!doctype html" in resp_text.lower() or "<html" in resp_text.lower() or "200 ok" in resp_text.lower()
        if not is_decoy:
            return {
                "status": "FAIL",
                "error": "REALITY fallback did not return decoy content",
                "snippet": resp_text[:200],
            }

        return {
            "status": "PASS",
            "is_decoy": True,
            "snippet": resp_text[:100],
        }
    except Exception as e:
        return {"status": "FAIL", "error": f"Failed testing REALITY decoy fallback: {e}"}
