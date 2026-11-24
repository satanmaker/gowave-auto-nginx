#!/usr/bin/env python3
"""Suite nonroot: subscription delivery is proven by the clients that consume it."""
import base64
import io
import json
import re
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import (  # noqa: E402
    acme_fixture,
    aio,
    catalog,
    client_image,
    matrix,
    panel_surface,
    subscription_probe,
    target_image,
    topology,
)
from tools.podman_e2e.runner import Case, CaseBlocked, RunContext  # noqa: E402

PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
SHORT_UUID = "e2eShortUuid0001"
CLIENT_UUID = "8f0d2c1a-4b3e-4f5a-9c7d-1e2f3a4b5c6d"
TROJAN_PASSWORD = "trojan-password-do-not-print"
REALITY_PUBLIC_KEY = "sB0fZx0RealityPublicKeyPlaceholder0000000000"

REALITY_LINK = (
    f"vless://{CLIENT_UUID}@panel.testbed.internal:443?type=tcp&security=reality"
    f"&sni=reality.testbed.internal&fp=firefox&pbk={REALITY_PUBLIC_KEY}&sid=ab12"
    "&flow=xtls-rprx-vision#vless-reality"
)
XHTTP_LINK = (
    f"vless://{CLIENT_UUID}@panel.testbed.internal:443?type=xhttp&security=tls"
    "&sni=panel.testbed.internal&fp=firefox&path=%2Fxhttp&mode=auto#vless-xhttp"
)
WS_LINK = (
    f"vless://{CLIENT_UUID}@panel.testbed.internal:443?type=ws&security=tls"
    "&sni=panel.testbed.internal&fp=firefox&path=%2Fws#vless-ws"
)
TROJAN_LINK = (
    f"trojan://{TROJAN_PASSWORD}@panel.testbed.internal:443?type=grpc&security=tls"
    "&sni=panel.testbed.internal&fp=firefox&serviceName=grpc#trojan-grpc"
)
LINKS = (REALITY_LINK, XHTTP_LINK, WS_LINK, TROJAN_LINK)
BASE64_BODY = base64.b64encode("\n".join(LINKS).encode("utf-8")).decode("ascii")

# The two local listeners every served Xray profile carries, taken from the
# Panel's default Xray JSON template.
INBOUNDS = (
    {"tag": "socks", "port": 10808, "listen": "127.0.0.1", "protocol": "socks",
     "settings": {"udp": True, "auth": "noauth"}},
    {"tag": "http", "port": 10809, "listen": "127.0.0.1", "protocol": "http",
     "settings": {"allowTransparent": False}},
)

REALITY_OUTBOUND = {
    "tag": "reality",
    "protocol": "vless",
    "settings": {"vnext": [{"address": "panel.testbed.internal", "port": 443, "users": [
        {"id": CLIENT_UUID, "encryption": "none", "flow": "xtls-rprx-vision"},
    ]}]},
    "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "tcpSettings": {"header": {"type": "none"}},
        "realitySettings": {
            "serverName": "reality.testbed.internal",
            "publicKey": REALITY_PUBLIC_KEY,
            "shortId": "ab12",
            "fingerprint": "firefox",
        },
    },
}
XHTTP_OUTBOUND = {
    "tag": "xhttp",
    "protocol": "vless",
    "settings": {"vnext": [{"address": "panel.testbed.internal", "port": 443, "users": [
        {"id": CLIENT_UUID, "encryption": "none", "flow": ""},
    ]}]},
    "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "xhttpSettings": {"mode": "auto", "host": "", "path": "/xhttp"},
        "tlsSettings": {"serverName": "panel.testbed.internal", "enableSessionResumption": False,
                        "fingerprint": "firefox"},
    },
}
WS_OUTBOUND = {
    "tag": "ws",
    "protocol": "vless",
    "settings": {"vnext": [{"address": "panel.testbed.internal", "port": 443, "users": [
        {"id": CLIENT_UUID, "encryption": "none", "flow": ""},
    ]}]},
    "streamSettings": {
        "network": "ws",
        "security": "tls",
        "wsSettings": {"path": "/ws", "host": "", "headers": {}},
        "tlsSettings": {"serverName": "panel.testbed.internal", "enableSessionResumption": False,
                        "fingerprint": "firefox"},
    },
}
TROJAN_OUTBOUND = {
    "tag": "trojan",
    "protocol": "trojan",
    "settings": {"servers": [{"address": "panel.testbed.internal", "port": 443,
                              "password": TROJAN_PASSWORD}]},
    "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "grpcSettings": {"serviceName": "grpc", "authority": "", "multiMode": False},
        "tlsSettings": {"serverName": "panel.testbed.internal", "enableSessionResumption": False,
                        "fingerprint": "firefox"},
    },
}


# What a client sees for the four inbounds below: the Host remark is the proxy
# name in both representations, and a proxy group repeats it. No country is
# confirmed in a Podman install, so these are the flagless forms.
SERVED_LABELS = {
    "reality": "VLESS · REALITY · Vision — local-node",
    "xhttp": "VLESS · XHTTP · TLS — local-node",
    "ws": "VLESS · WebSocket · TLS — local-node",
    "trojan": "Trojan · gRPC · TLS — local-node",
}


def profile(outbound):
    """One served profile: a complete config with the Panel's own outbound first."""
    return {
        "dns": {"servers": ["1.1.1.1"], "queryStrategy": "UseIP"},
        "routing": {"rules": [{"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"}],
                    "domainStrategy": "IPIfNonMatch"},
        "inbounds": json.loads(json.dumps(INBOUNDS)),
        "outbounds": [
            json.loads(json.dumps(outbound)),
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "remarks": SERVED_LABELS[outbound["tag"]],
    }


PROFILES = [profile(item) for item in (REALITY_OUTBOUND, XHTTP_OUTBOUND, WS_OUTBOUND, TROJAN_OUTBOUND)]
JSON_BODY = json.dumps(PROFILES, indent=2)
MIHOMO_YAML = """mode: global
mixed-port: 7890
dns:
  enable: true
  nameserver:
    - 1.1.1.1
proxies:
  - name: "VLESS · REALITY · Vision — local-node"
    type: vless
    server: panel.testbed.internal
    network: tcp
    tls: true
    servername: reality.testbed.internal
    reality-opts:
      public-key: Cb8_gedNWrtQ3bHsW8WBb1NugpsXIw-Tu-mu_Eyevjg
      short-id: 654854cb2af21ceb
    client-fingerprint: firefox
  - name: "VLESS · XHTTP · TLS — local-node"
    type: vless
    server: panel.testbed.internal
    network: xhttp
    tls: true
    alpn:
      - h2
      - http/1.1
    xhttp-opts:
      path: /xhttp-down/
      mode: stream-up
  - name: "VLESS · WebSocket · TLS — local-node"
    type: vless
    server: panel.testbed.internal
    network: ws
    tls: true
    alpn:
      - http/1.1
    ws-opts:
      path: /ws
      headers: {}
  - name: "Trojan · gRPC · TLS — local-node"
    type: trojan
    server: panel.testbed.internal
    alpn:
      - h2
    grpc-opts:
      grpc-service-name: trojan-grpc
proxy-groups:
  - name: GoWave
    type: select
    proxies:
      - "VLESS · REALITY · Vision — local-node"
      - "VLESS · XHTTP · TLS — local-node"
      - "VLESS · WebSocket · TLS — local-node"
      - "Trojan · gRPC · TLS — local-node"
rules:
  - MATCH,GoWave
"""
SINGBOX_BODY = json.dumps({"outbounds": [
    {"type": "vless", "tag": "reality"},
    {"type": "vless", "tag": "xhttp"},
    {"type": "trojan", "tag": "trojan"},
    {"type": "direct", "tag": "direct"},
]})
# The value the product's own vhost adds on /api/sub/ (modules/nginx.sh); a
# subscription a cache may keep would outlive the client it describes.
NO_STORE = "no-store, no-cache, must-revalidate, max-age=0"

BODIES = {
    "base64": (BASE64_BODY, "text/plain; charset=utf-8"),
    "xray-json": (JSON_BODY, "application/json"),
    "mihomo": (MIHOMO_YAML, "text/yaml"),
    "clash": (MIHOMO_YAML, "text/yaml"),
    "singbox": (SINGBOX_BODY, "application/json"),
}


def merge(base, overrides=None):
    data = json.loads(json.dumps(base))
    for path, value in (overrides or {}).items():
        target = data
        *parents, leaf = path.split(".")
        for name in parents:
            target = target[name]
        target[leaf] = value
    return data


def issue_edge_certificate(directory):
    """A self-signed certificate for the edge stub that doubles as its trust anchor."""
    key = Path(directory) / "edge.key"
    certificate = Path(directory) / "edge.crt"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(certificate), "-days", "1",
        "-subj", "/CN=panel.testbed.internal",
        "-addext", "subjectAltName=DNS:panel.testbed.internal,IP:127.0.0.1",
    ], check=True, stderr=subprocess.DEVNULL)
    return certificate


def served_facts(overrides=None):
    """Facts shaped like the real two vantages: the Panel process answers no header.

    ``cache_control`` is the loopback answer — the Panel itself — and
    ``edge_cache_control`` is the public vhost a client talks to. The product's
    Panel sends none of it and its vhost adds it, so a fixture that put the
    header on both would let a case pass while reading the wrong side.

    ``hosts`` is `GET /api/hosts` as the probe reduces it, and the four records
    are the ones the install posts for the four inbounds above — address, SNI and
    path are literals here so a projection edit turns this fixture red instead of
    moving with it. ``secret_needles`` is 2 because the probe reads the Panel's
    signing key and the administrator's password, and every ``secret_hits`` is 0
    because a served subscription carries neither.
    """
    return merge({
        "short_uuid_length": len(SHORT_UUID),
        "secret_needles": 2,
        "hosts": {
            "status": 200,
            "records": [
                {"remark": "VLESS · REALITY · Vision — local-node", "address": "panel.testbed.internal",
                 "port": "443", "sni": "reality.testbed.internal", "path": "",
                 "security_layer": "DEFAULT", "alpn": "h2,http/1.1", "disabled": False},
                {"remark": "VLESS · XHTTP · TLS — local-node", "address": "panel.testbed.internal",
                 "port": "443", "sni": "panel.testbed.internal", "path": "/xhttp",
                 "security_layer": "TLS", "alpn": "h2,http/1.1", "disabled": False},
                {"remark": "VLESS · WebSocket · TLS — local-node", "address": "panel.testbed.internal",
                 "port": "443", "sni": "panel.testbed.internal", "path": "/ws",
                 "security_layer": "TLS", "alpn": "http/1.1", "disabled": False},
                {"remark": "Trojan · gRPC · TLS — local-node", "address": "panel.testbed.internal",
                 "port": "443", "sni": "panel.testbed.internal", "path": "grpc",
                 "security_layer": "TLS", "alpn": "h2", "disabled": False},
            ],
        },
        "representations": {
            "base64": {"status": 200, "content_type": "text/plain", "bytes": len(BASE64_BODY),
                       "cache_control": "", "secret_hits": 0,
                       "edge_status": 200, "edge_cache_control": NO_STORE, "edge_identical": True,
                       "foreign_status": 200, "foreign_identical": True},
            "xray-json": {"status": 200, "content_type": "application/json", "bytes": len(JSON_BODY),
                          "cache_control": "", "secret_hits": 0,
                          "edge_status": 200, "edge_cache_control": NO_STORE, "edge_identical": True,
                          "foreign_status": 200, "foreign_identical": True},
            "mihomo": {"status": 200, "content_type": "text/yaml", "bytes": len(MIHOMO_YAML),
                       "cache_control": "", "secret_hits": 0,
                       "edge_status": 200, "edge_cache_control": NO_STORE, "edge_identical": True,
                       "foreign_status": 200, "foreign_identical": True},
            "clash": {"status": 200, "content_type": "text/yaml", "bytes": len(MIHOMO_YAML),
                      "cache_control": "", "secret_hits": 0,
                      "edge_status": 200, "edge_cache_control": NO_STORE, "edge_identical": True,
                      "foreign_status": 200, "foreign_identical": True},
            "singbox": {"status": 200, "content_type": "application/json", "bytes": len(SINGBOX_BODY),
                        "cache_control": "", "secret_hits": 0,
                        "edge_status": 200, "edge_cache_control": NO_STORE, "edge_identical": True,
                        "foreign_status": 200, "foreign_identical": True},
        },
    }, overrides)


def engine_representations(overrides=None):
    engine = {
        "base64": {"decoded": True, "decoded_bytes": 812, "link_count": 4,
                   "schemes": ["trojan", "vless"], "private_keys": 0},
        # The tuples and the fingerprint are what the probe reads back out of the
        # four served outbounds above, and what the matrix issues each inbound
        # for; they are literals here so a matrix edit turns this fixture red
        # instead of moving with it. ``dials`` is the same read with the fields a
        # Host record states kept, and every document carries no private key.
        "xray_json": {"shape": "list", "entries": 4, "wrapped": 0, "protocols": ["trojan", "vless"],
                      "transports": ["trojan/grpc/tls", "vless/tcp/reality",
                                     "vless/ws/tls", "vless/xhttp/tls"],
                      "fingerprints": ["firefox"], "sni_missing": 0,
                      "dials": [
                          {"tag": "reality", "protocol": "vless",
                           "address": "panel.testbed.internal", "port": "443",
                           "sni": "reality.testbed.internal", "path": "", "service_name": "",
                           "network": "tcp"},
                          {"tag": "xhttp", "protocol": "vless",
                           "address": "panel.testbed.internal", "port": "443",
                           "sni": "panel.testbed.internal", "path": "/xhttp", "service_name": "",
                           "network": "xhttp"},
                          {"tag": "ws", "protocol": "vless",
                           "address": "panel.testbed.internal", "port": "443",
                           "sni": "panel.testbed.internal", "path": "/ws", "service_name": "",
                           "network": "ws"},
                          {"tag": "trojan", "protocol": "trojan",
                           "address": "panel.testbed.internal", "port": "443",
                           "sni": "panel.testbed.internal", "path": "", "service_name": "grpc",
                           "network": "grpc"},
                      ],
                      "private_keys": 0},
        "mihomo": {"proxies": 4, "proxy_types": ["trojan", "vless"], "groups": 1, "rules": 1,
                   "match_rule": True, "exit": 0,
                   "rule_names": ["MATCH"], "duplicate_names": 0,
                   "group_members": 4, "missing_group_references": [],
                   "client_fingerprints": ["firefox"], "private_keys": 0,
                   "proxy_details": [
                       {"name": "VLESS · REALITY · Vision — local-node", "type": "vless",
                        "server": "panel.testbed.internal", "network": "tcp", "tls": "true",
                        "servername": "reality.testbed.internal"},
                       {"name": "VLESS · XHTTP · TLS — local-node", "type": "vless",
                        "server": "panel.testbed.internal", "network": "xhttp", "tls": "true"},
                       {"name": "VLESS · WebSocket · TLS — local-node", "type": "vless",
                        "server": "panel.testbed.internal", "network": "ws", "tls": "true"},
                       {"name": "Trojan · gRPC · TLS — local-node", "type": "trojan",
                        "server": "panel.testbed.internal", "network": "tcp", "tls": "true"},
                   ]},
        "clash": {"proxies": 1, "proxy_types": ["trojan"], "groups": 1, "rules": 1,
                  "match_rule": True, "exit": 0,
                  "rule_names": ["MATCH"], "duplicate_names": 0,
                  "client_fingerprints": ["firefox"], "private_keys": 0},
        "singbox": {"parsed": True, "outbounds": 4, "private_keys": 0},
    }
    return merge(engine, overrides)


def engine_share_links(overrides=None):
    return merge({
        "link_count": 4,
        "protocols": {"vless": 3, "trojan": 1},
        "hosts": ["panel.testbed.internal"],
        "snis": ["panel.testbed.internal", "reality.testbed.internal"],
        "sni_missing": 0,
        "fingerprints": ["firefox"],
        "fingerprint_missing": 0,
        "ports": ["443"],
        "networks": ["grpc", "tcp", "ws", "xhttp"],
        "credential_present": True,
        "xray_outbounds": 4,
        "cross_representation_matches": 4,
        "cross_representation_issued": 4,
        "json_body_links": 0,
    }, overrides)


def engine_json_shapes(overrides=None):
    return merge({
        "served_shape": "list",
        "served_entries": 4,
        "served_wrapped": 0,
        "alternate_shape": "object",
        "alternate_outbounds": 1,
        "alternate_wrapped": 1,
    }, overrides)


def policy_facts(policy, status=403):
    return {"policy": policy, "representations": {name: status for name in aio.REPRESENTATIONS}}


ROBOTS_TAG = "noindex, nofollow, noarchive, nosnippet"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def edge_answer(status=200, size=4096, cache_control=NO_STORE, x_robots_tag=ROBOTS_TAG,
                content_type="text/plain; charset=utf-8"):
    """One edge answer as `_answer()` reduces it: headers, length, digest."""
    return {
        "status": status,
        "content_type": content_type,
        "cache_control": cache_control,
        "x_robots_tag": x_robots_tag,
        "bytes": size,
        "sha256": EMPTY_SHA256 if size == 0 else "a" * 64,
    }


def edge_counters(before=7, after=None, control=None):
    """The Panel's two subscription counters around the crawler sweep.

    ``control`` is the loopback fetch that has to move them; ``after`` defaults
    to ``before`` because a sweep the edge answered itself moves nothing.
    """
    patterns = panel_surface.SUBSCRIPTION_ROUTE_PATTERNS
    after = before if after is None else after
    control = after + 1 if control is None else control
    return {
        "before": {"status": 200, "counts": {pattern: before for pattern in patterns}},
        "after": {"status": 200, "counts": {pattern: after for pattern in patterns}},
        "control": {"status": 200,
                    "counts": {patterns[0]: control, patterns[1]: after}},
        "control_status": 200,
    }


def edge_facts(overrides=None):
    """The edge-contract probe's block, with every family answering as shipped."""
    facts = {
        "short_uuid_length": len(SHORT_UUID),
        "loopback": edge_answer(),
        "served": edge_answer(),
        "served_identical_to_loopback": True,
        "foreign": edge_answer(),
        "foreign_identical": True,
        "absent": edge_answer(status=403, size=0, content_type="text/plain"),
        "previews": {
            agent: edge_answer(status=204, size=0)
            for agent in panel_surface.PREVIEW_USER_AGENTS
        },
        "refused": {
            "dot_segment": {"status": 0, "closed": True, "bytes": 0},
            "encoded_separator": {"status": 0, "closed": True, "bytes": 0},
        },
        "counters": edge_counters(),
    }
    return merge(facts, overrides)


def access_log_facts(overrides=None):
    """The access-log probe's answer: served lines none, refused lines recorded."""
    facts = {"present": True, "lines": 41, "served": 0,
             "refused_dot_segment": 1, "refused_encoded_separator": 1}
    facts.update(overrides or {})
    return facts


class StubPanel:
    """A Panel that answers the default-client lookup and every representation.

    ``secure`` makes it answer over HTTPS with a certificate that doubles as its
    own trust anchor, which is what lets a test read the same paths through a
    second, TLS-terminating vantage the way the public vhost is read.
    """

    def __init__(self, secure=False):
        self.password = "pw-do-not-print"
        self.token = "token-do-not-print"
        self.user = {"id": CLIENT_UUID, "username": "default-user", "shortUuid": SHORT_UUID}
        self.users = [{"id": CLIENT_UUID, "username": "default-user", "shortUuid": SHORT_UUID}]
        self.bodies = dict(BODIES)
        self.statuses = {}
        self.requests = []
        # `GET /api/hosts` as the Panel answers it: the document a client's config
        # is derived from, and the one the subscription has to agree with. The
        # four records are the install's own projection for the four inbounds.
        self.hosts = [
            {"remark": "VLESS · REALITY · Vision — local-node", "address": "panel.testbed.internal",
             "port": 443, "sni": "reality.testbed.internal", "path": None,
             "securityLayer": "DEFAULT", "alpn": "h2,http/1.1", "isDisabled": False},
            {"remark": "VLESS · XHTTP · TLS — local-node", "address": "panel.testbed.internal",
             "port": 443, "sni": "panel.testbed.internal", "path": "/xhttp",
             "securityLayer": "TLS", "alpn": "h2,http/1.1", "isDisabled": False},
            {"remark": "VLESS · WebSocket · TLS — local-node", "address": "panel.testbed.internal",
             "port": 443, "sni": "panel.testbed.internal", "path": "/ws",
             "securityLayer": "TLS", "alpn": "http/1.1", "isDisabled": False},
            {"remark": "Trojan · gRPC · TLS — local-node", "address": "panel.testbed.internal",
             "port": 443, "sni": "panel.testbed.internal", "path": "grpc",
             "securityLayer": "TLS", "alpn": "h2", "isDisabled": False},
        ]
        self.enforce_user_agent = False
        self.refuse_foreign_user_agent = False
        self.no_cache_control = False
        # `GET /api/system/stats/http` as the router answers it: a payload the
        # case reads beside the sweep, so a fake that never moved it cannot be
        # mistaken for a listener that never forwarded anything.
        self.route_counts = {"response": {"routes": [], "total": 0}}
        self.certificate = None
        directory = Path(tempfile.mkdtemp(prefix="gowave-subscription-panel-"))
        self.credentials = directory / "credentials"
        self.credentials.write_text(
            f"ADMIN_USERNAME=admin\nADMIN_PASSWORD={self.password}\n", encoding="utf-8"
        )
        self.credentials.chmod(0o600)
        self.server = self._start(secure, directory)

    def _start(self, secure=False, directory=None):
        panel = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, body, content_type="application/json"):
                raw = body.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                if not panel.no_cache_control:
                    self.send_header("Cache-Control", NO_STORE)
                self.send_header("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                agent = self.headers.get("User-Agent")
                panel.requests.append((self.path, agent))
                if "/../" in self.path or "%2F" in self.path or "%2f" in self.path:
                    # What the shipped vhost does to a raw target it refuses: the
                    # connection closes with no status, which is the answer the
                    # forgery case has to see.
                    self.close_connection = True
                    return
                if self.path == "/api/users/by-username/default-user":
                    return self._send(200, json.dumps({"response": panel.user}))
                if self.path == "/api/system/stats/http":
                    return self._send(200, json.dumps(panel.route_counts))
                if self.path == "/api/users":
                    return self._send(200, json.dumps({"response": {"users": panel.users}}))
                if self.path == "/api/hosts":
                    return self._send(200, json.dumps({"response": {"hosts": panel.hosts}}))
                name = panel.representation(self.path)
                if name is None:
                    return self._send(404, json.dumps({"message": "not found"}))
                if panel.enforce_user_agent and (agent is None or not agent.strip()):
                    return self._send(403, "forbidden", "text/plain")
                if panel.refuse_foreign_user_agent and agent == panel_surface.FOREIGN_USER_AGENT:
                    return self._send(403, "forbidden", "text/plain")
                status = panel.statuses.get(name, 200)
                body, content_type = panel.bodies[name]
                return self._send(status, body if status == 200 else "", content_type)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        if secure:
            certificate = issue_edge_certificate(directory)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(
                certfile=str(certificate), keyfile=str(certificate.with_suffix(".key")),
            )
            server.socket = context.wrap_socket(server.socket, server_side=True)
            self.certificate = certificate
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server

    @staticmethod
    def representation(path):
        prefix = f"/api/sub/{SHORT_UUID}"
        if not path.startswith(prefix):
            return None
        suffix = path[len(prefix):]
        return {
            "": "base64",
            "/v2ray-json": "xray-json",
            "/mihomo": "mihomo",
            "/clash": "clash",
            "/singbox": "singbox",
        }.get(suffix)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    @property
    def edge_url(self):
        scheme = "https" if self.certificate else "http"
        return f"{scheme}://127.0.0.1:{self.server.server_address[1]}"


def probe_output(panel, scope, payload_dir="", step="", edge_base="", ca=""):
    stdout = io.StringIO()
    argv = [
        "--scope", scope,
        "--panel-url", panel.url,
        "--credentials", str(panel.credentials),
    ]
    if payload_dir:
        argv.extend(["--payload-dir", payload_dir])
    if step:
        argv.extend(["--step", step])
    if edge_base:
        argv.extend(["--edge-base", edge_base])
    if ca:
        argv.extend(["--ca", str(ca)])
    with redirect_stdout(stdout):
        code = panel_surface.main(argv)
    if code != 0:
        raise AssertionError(f"panel_surface.main returned {code}")
    return json.loads(stdout.getvalue()), stdout.getvalue()


class TestPanelSubscriptionProbe(unittest.TestCase):
    """The host-side probe fetches payloads and reports facts, never payloads."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.payload_dir = Path(self.tmp.name) / "subscriptions"
        self.payload_dir.mkdir(mode=0o700)
        self.panel = StubPanel()
        self.addCleanup(self.panel.server.shutdown)
        self.addCleanup(self.panel.server.server_close)

    def test_subscriptions_writes_0600_payloads_and_reports_only_counts(self):
        facts, output = probe_output(self.panel, "subscriptions", str(self.payload_dir))
        self.assertEqual(facts["subscriptions"]["short_uuid_length"], len(SHORT_UUID))
        for name, (body, _content_type) in BODIES.items():
            record = facts["subscriptions"]["representations"][name]
            self.assertEqual(record["status"], 200)
            self.assertEqual(record["bytes"], len(body.encode("utf-8")))
            path = self.payload_dir / f"{name}.payload"
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.read_text(encoding="utf-8"), body)

        self.assertNotIn(self.panel.password, output)
        self.assertNotIn(self.panel.token, output)
        self.assertNotIn(SHORT_UUID, output)
        self.assertNotIn(CLIENT_UUID, output)
        self.assertNotIn(TROJAN_PASSWORD, output)
        self.assertNotIn("\"outbounds\"", output)

    def test_each_representation_is_fetched_with_its_client_user_agent(self):
        probe_output(self.panel, "subscriptions", str(self.payload_dir))
        agents = {}
        for path, agent in self.panel.requests:
            if "/api/sub/" in path:
                agents.setdefault(path, []).append(agent)
        self.assertIn(panel_surface.MOBILE_USER_AGENT, agents[f"/api/sub/{SHORT_UUID}"])
        self.assertIn(panel_surface.XRAY_USER_AGENT, agents[f"/api/sub/{SHORT_UUID}/v2ray-json"])
        self.assertIn(panel_surface.MIHOMO_USER_AGENT, agents[f"/api/sub/{SHORT_UUID}/mihomo"])
        self.assertIn(panel_surface.CLASH_USER_AGENT, agents[f"/api/sub/{SHORT_UUID}/clash"])
        self.assertIn(panel_surface.SINGBOX_USER_AGENT, agents[f"/api/sub/{SHORT_UUID}/singbox"])

    def test_the_probe_records_the_cache_control_header_it_received(self):
        facts, _ = probe_output(self.panel, "subscriptions", str(self.payload_dir))
        facts = facts["subscriptions"]
        for name in ("base64", "xray-json", "mihomo", "clash", "singbox"):
            with self.subTest(representation=name):
                self.assertIn("no-store", facts["representations"][name]["cache_control"])

    def test_a_panel_that_lets_the_subscription_be_cached_is_visible_to_the_probe(self):
        self.panel.no_cache_control = True
        facts, _ = probe_output(self.panel, "subscriptions", str(self.payload_dir))
        facts = facts["subscriptions"]
        for name in ("base64", "xray-json", "mihomo", "clash", "singbox"):
            with self.subTest(representation=name):
                self.assertEqual(facts["representations"][name]["cache_control"], "")

    def edge_panel(self):
        edge = StubPanel(secure=True)
        self.addCleanup(edge.server.shutdown)
        self.addCleanup(edge.server.server_close)
        return edge

    def test_the_probe_reads_the_public_edge_beside_the_panel_process(self):
        """Two vantages, two answers: the Panel sends no header, the edge sends it."""
        self.panel.no_cache_control = True
        edge = self.edge_panel()
        facts, output = probe_output(
            self.panel, "subscriptions", str(self.payload_dir),
            edge_base=edge.edge_url, ca=edge.certificate,
        )
        served = facts["subscriptions"]["representations"]
        for name, record in served.items():
            with self.subTest(representation=name):
                self.assertEqual(record["cache_control"], "",
                                 "the Panel process reported a header it does not send")
                self.assertEqual(record["edge_status"], 200)
                self.assertIn("no-store", record["edge_cache_control"])
                self.assertIs(record["edge_identical"], True)
        self.assertNotIn(SHORT_UUID, output)
        self.assertNotIn(TROJAN_PASSWORD, output)

    def test_an_edge_that_lets_the_subscription_be_cached_is_visible(self):
        self.panel.no_cache_control = True
        edge = self.edge_panel()
        edge.no_cache_control = True
        facts, _ = probe_output(
            self.panel, "subscriptions", str(self.payload_dir),
            edge_base=edge.edge_url, ca=edge.certificate,
        )
        for name, record in facts["subscriptions"]["representations"].items():
            with self.subTest(representation=name):
                self.assertEqual(record["edge_cache_control"], "")

    def test_an_edge_that_serves_other_bytes_is_reported_against_the_panel(self):
        self.panel.no_cache_control = True
        edge = self.edge_panel()
        edge.bodies["clash"] = (MIHOMO_YAML + "\n# another body\n", "text/yaml")
        facts, _ = probe_output(
            self.panel, "subscriptions", str(self.payload_dir),
            edge_base=edge.edge_url, ca=edge.certificate,
        )
        served = facts["subscriptions"]["representations"]
        self.assertIs(served["clash"]["edge_identical"], False)
        self.assertIs(served["mihomo"]["edge_identical"], True)

    def test_the_edge_fetch_trusts_only_the_ca_it_is_given(self):
        edge = self.edge_panel()
        path = f"/api/sub/{SHORT_UUID}"
        with self.assertRaises(ssl.SSLError):
            panel_surface.fetch(edge.edge_url, path, panel_surface.MOBILE_USER_AGENT)
        response = panel_surface.fetch(
            edge.edge_url, path, panel_surface.MOBILE_USER_AGENT, ca_file=str(edge.certificate),
        )
        self.assertEqual(response["status"], 200)
        self.assertIn("no-store", response["cache_control"])

    def test_the_edge_contract_scope_asks_the_edge_for_every_published_family(self):
        edge = self.edge_panel()
        facts, output = probe_output(
            self.panel, "edge-contract", edge_base=edge.edge_url, ca=edge.certificate,
        )
        block = facts["edge"]
        self.assertEqual(block["short_uuid_length"], len(SHORT_UUID))
        self.assertIs(block["served_identical_to_loopback"], True)
        self.assertEqual(set(block["previews"]), set(panel_surface.PREVIEW_USER_AGENTS))
        for agent, answer in block["previews"].items():
            with self.subTest(agent=agent):
                self.assertEqual(answer["status"], 200,
                                 "the stub serves every header; the probe must report what it saw")
                self.assertIn("no-store", answer["cache_control"])
                self.assertEqual(answer["x_robots_tag"], ROBOTS_TAG)
        self.assertNotIn(SHORT_UUID, output)
        self.assertNotIn(self.panel.password, output)
        self.assertNotIn(self.panel.token, output)

    def test_a_raw_target_that_closes_is_an_answer_with_no_status(self):
        edge = self.edge_panel()
        block = panel_surface.subscription_edge_contract(
            panel_surface.Panel(self.panel.url), edge.edge_url,
            ca_file=str(edge.certificate),
        )
        for label in ("dot_segment", "encoded_separator"):
            with self.subTest(target=label):
                self.assertIs(block["refused"][label]["closed"], True)
                self.assertEqual(block["refused"][label]["status"], 0)
                self.assertEqual(block["refused"][label]["bytes"], 0)

    def test_the_route_counter_reads_the_routers_own_route_names(self):
        self.panel.route_counts = {"response": {"total": 9, "routes": [
            {"method": "GET", "route": "/api/sub/{shortUuid}", "count": 3},
            {"method": "GET", "route": "/api/sub/{shortUuid}/{clientType}", "count": 1},
            {"method": "GET", "route": "/api/users", "count": 5},
        ]}}
        facts = panel_surface.http_route_counts(panel_surface.Panel(self.panel.url))
        self.assertEqual(facts["status"], 200)
        self.assertEqual(facts["counts"], {
            "GET /api/sub/{shortUuid}": 3,
            "GET /api/sub/{shortUuid}/{clientType}": 1,
        })

    def test_an_absent_user_agent_is_a_request_without_the_header(self):
        response = panel_surface.fetch(self.panel.url, f"/api/sub/{SHORT_UUID}", None)
        self.assertEqual(response["status"], 200)
        self.assertIsNone(self.panel.requests[-1][1])

    def test_a_blank_user_agent_is_an_empty_header_not_a_missing_one(self):
        response = panel_surface.fetch(self.panel.url, f"/api/sub/{SHORT_UUID}", "")
        self.assertEqual(response["status"], 200)
        self.assertEqual(self.panel.requests[-1][1], "")

    def test_the_accepted_header_names_no_client_family(self):
        families = {agent for _name, _template, agent in panel_surface.REPRESENTATIONS}
        self.assertNotIn(panel_surface.FOREIGN_USER_AGENT, families)
        for agent in families:
            with self.subTest(agent=agent):
                self.assertNotIn(agent.split("/")[0].lower(), panel_surface.FOREIGN_USER_AGENT.lower())

    def test_a_foreign_user_agent_is_served_the_same_bytes(self):
        self.panel.enforce_user_agent = True
        facts, output = probe_output(self.panel, "subscriptions", str(self.payload_dir))
        served = facts["subscriptions"]["representations"]
        self.assertEqual(sorted(served), sorted(aio.REPRESENTATIONS))
        for name, record in served.items():
            with self.subTest(representation=name):
                self.assertEqual(record["status"], 200)
                self.assertEqual(record["foreign_status"], 200)
                self.assertIs(record["foreign_identical"], True)
        asked = {path: agent for path, agent in self.panel.requests
                 if "/api/sub/" in path and agent == panel_surface.FOREIGN_USER_AGENT}
        self.assertEqual(len(asked), len(aio.REPRESENTATIONS),
                         "the probe did not ask every representation with the foreign header")
        self.assertNotIn(self.panel.password, output)

    def test_the_pinned_policy_refuses_both_kinds_of_missing_header(self):
        self.panel.enforce_user_agent = True
        for policy, agent in (("absent", None), ("blank", "")):
            with self.subTest(policy=policy):
                facts, output = probe_output(self.panel, f"ua-{policy}")
                self.assertEqual(facts["policy"]["policy"], policy)
                self.assertEqual(sorted(facts["policy"]["representations"]),
                                 sorted(aio.REPRESENTATIONS))
                self.assertEqual(set(facts["policy"]["representations"].values()), {403})
                self.assertNotIn(self.panel.password, output)

    def test_a_policy_probe_writes_no_payload(self):
        self.panel.enforce_user_agent = True
        probe_output(self.panel, "ua-absent")
        self.assertEqual(list(self.payload_dir.iterdir()), [])

    def test_a_refused_representation_is_reported_and_not_written(self):
        self.panel.statuses["mihomo"] = 404
        facts, _output = probe_output(self.panel, "subscriptions", str(self.payload_dir))
        self.assertEqual(facts["subscriptions"]["representations"]["mihomo"]["status"], 404)
        self.assertFalse((self.payload_dir / "mihomo.payload").exists())
        self.assertTrue((self.payload_dir / "clash.payload").is_file())

    def test_a_default_client_without_a_short_uuid_stops_the_probe(self):
        self.panel.user = {"username": "default-user"}
        with self.assertRaises(SystemExit) as caught:
            probe_output(self.panel, "subscriptions", str(self.payload_dir))
        self.assertIn("without a shortUuid", str(caught.exception))

    def test_write_payload_refuses_a_directory_that_is_not_mounted(self):
        with self.assertRaises(SystemExit) as caught:
            panel_surface.write_payload(Path(self.tmp.name) / "missing" / "base64.payload", b"x")
        self.assertIn("does not exist", str(caught.exception))

    def test_media_type_drops_the_parameters(self):
        self.assertEqual(panel_surface.media_type("Application/JSON; charset=utf-8"), "application/json")
        self.assertEqual(panel_surface.media_type(""), "")

    def test_the_probe_reports_the_host_records_the_subscription_must_agree_with(self):
        facts, output = probe_output(self.panel, "subscriptions", str(self.payload_dir))
        hosts = facts["subscriptions"]["hosts"]
        self.assertEqual(hosts["status"], 200)
        self.assertEqual([record["remark"] for record in hosts["records"]],
                         ["VLESS · REALITY · Vision — local-node", "VLESS · XHTTP · TLS — local-node",
                          "VLESS · WebSocket · TLS — local-node", "Trojan · gRPC · TLS — local-node"])
        self.assertEqual(hosts["records"][0]["sni"], "reality.testbed.internal")
        self.assertEqual(hosts["records"][0]["path"], "")
        self.assertEqual(hosts["records"][1]["path"], "/xhttp")
        self.assertEqual(hosts["records"][3]["path"], "grpc")
        self.assertEqual(hosts["records"][1]["security_layer"], "TLS")
        self.assertIs(hosts["records"][1]["disabled"], False)
        self.assertEqual(hosts["records"][1]["port"], "443")

    def test_the_host_fixture_is_the_projection_the_install_posts(self):
        """The four literals above are the client's own Host records, not a guess."""
        from modules.api_client import host_projection

        posted = host_projection("panel.testbed.internal", "reality.testbed.internal", "local-node")
        keys = ["vless-reality", "vless-xhttp", "vless-ws", "trojan-grpc"]
        labels = [posted[key]["remark"] for key in keys]
        self.assertEqual([record["remark"] for record in served_facts()["hosts"]["records"]], labels)
        self.assertEqual([record["remark"] for record in self.panel.hosts], labels)
        self.assertEqual([record["address"] for record in self.panel.hosts],
                         [posted[key]["address"] for key in keys])
        self.assertEqual([record["port"] for record in self.panel.hosts],
                         [posted[key]["port"] for key in keys])
        self.assertEqual([record["sni"] for record in self.panel.hosts],
                         [posted[key]["sni"] for key in keys])
        self.assertEqual([record["securityLayer"] for record in self.panel.hosts],
                         [posted[key]["securityLayer"] for key in keys])

    def test_the_served_bodies_carry_the_same_names_the_hosts_do(self):
        """A client resolves a group by name, so both representations agree."""
        facts = subscription_probe.scan_mihomo(MIHOMO_YAML)
        self.assertEqual(facts["duplicate_names"], 0)
        self.assertEqual(facts["group_members"], 4)
        self.assertEqual(facts["missing_group_references"], [])
        self.assertEqual([entry["name"] for entry in facts["proxy_details"]],
                         list(SERVED_LABELS.values()))
        self.assertEqual([entry["remarks"] for entry in json.loads(JSON_BODY)],
                         list(SERVED_LABELS.values()))

    def test_a_host_record_count_is_reported_and_no_value_is(self):
        """The hosts read is a fact, and the token that read it stays out of the output."""
        facts, output = probe_output(self.panel, "subscriptions", str(self.payload_dir))
        self.assertEqual(len(facts["subscriptions"]["hosts"]["records"]), 4)
        self.assertNotIn(self.panel.token, output)

    def test_server_secret_values_reads_both_product_keys_and_drops_short_values(self):
        """The Panel writes APP_SECRET, the Node SECRET_KEY; both are scanned."""
        panel_env = Path(self.tmp.name) / "gowave.env"
        panel_env.write_text(
            "APP_SECRET=an-example-signing-key-that-is-long\n"
            "GOWAVE_PROXY=external\n",
            encoding="utf-8",
        )
        node_env = Path(self.tmp.name) / "gowave-node.env"
        node_env.write_text(
            "SECRET_KEY=an-example-node-key-that-is-long\n",
            encoding="utf-8",
        )
        short_env = Path(self.tmp.name) / "short.env"
        short_env.write_text("SECRET_KEY=abc\n", encoding="utf-8")
        values = panel_surface.server_secret_values(
            "the-administrator-password",
            env_files=[str(panel_env), str(node_env), str(short_env)],
        )
        self.assertEqual(values, [
            "the-administrator-password",
            "an-example-signing-key-that-is-long",
            "an-example-node-key-that-is-long",
        ])

    def test_server_secret_values_tolerates_a_missing_environment_file(self):
        values = panel_surface.server_secret_values(
            "the-administrator-password",
            env_files=[str(Path(self.tmp.name) / "absent.env")],
        )
        self.assertEqual(values, ["the-administrator-password"])

    def test_the_scan_reads_the_files_and_keys_the_product_itself_writes(self):
        """A scan of the wrong file, or of a key the product no longer sets, proves nothing.

        The product writes its own environment files: the Panel's module into
        `/opt/gowave/.env` and the Node's into `/opt/gowave-node/.env`. This reads
        the two heredocs rather than trusting the probe's constants, so renaming a
        key in the product — or moving an install directory — fails here instead of
        silently making the secret scan look for a value that is nowhere on the host.
        """
        heredoc = re.compile(r'cat > "\$env_file" <<EOF\n(.*?)\nEOF', re.S)
        writers = {
            "modules/panel.sh": "GOWAVE_INSTALL_DIR",
            "modules/node.sh": "GOWAVE_NODE_INSTALL_DIR",
        }
        written_keys = set()
        for script, directory_variable in writers.items():
            source = (REPO_ROOT / script).read_text(encoding="utf-8")
            blocks = heredoc.findall(source)
            self.assertTrue(blocks, f"{script} no longer writes an environment file this reads")
            for block in blocks:
                for line in block.splitlines():
                    name, separator, _ = line.partition("=")
                    if separator and re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
                        written_keys.add(name)
            default = re.search(rf'^{directory_variable}="([^"]+)"', source, re.M)
            self.assertIsNotNone(
                default, f"{script} no longer declares {directory_variable}, so the scanned path is unproven",
            )
            self.assertIn(
                f"{default.group(1)}/.env", panel_surface.PRODUCT_ENV_FILES,
                f"the secret scan does not read {default.group(1)}/.env, which {script} writes",
            )
        secret_keys = {name for name in written_keys if "SECRET" in name or "KEY" in name}
        self.assertTrue(secret_keys, "neither module writes a key this scan is supposed to look for")
        self.assertEqual(
            sorted(secret_keys), sorted(panel_surface.SERVER_SECRET_KEYS),
            "the scanned key names are not the ones the product writes into its environment files",
        )

    def test_secret_forms_covers_every_encoding_a_leak_could_wear(self):
        value = "s3cr3t value/with+peculiar"
        forms = panel_surface.secret_forms(value)
        self.assertIn(value.encode("utf-8"), forms)
        self.assertIn(base64.b64encode(value.encode("utf-8")), forms)
        self.assertIn(base64.urlsafe_b64encode(value.encode("utf-8")).rstrip(b"="), forms)
        self.assertIn(b"s3cr3t%20value%2Fwith%2Bpeculiar", forms)

    def test_the_probe_scans_a_payload_for_the_administrators_password(self):
        self.panel.bodies["mihomo"] = (
            MIHOMO_YAML + f"\n# secret={self.panel.password}\n", "text/yaml",
        )
        facts, output = probe_output(self.panel, "subscriptions", str(self.payload_dir))
        served = facts["subscriptions"]["representations"]
        self.assertEqual(facts["subscriptions"]["secret_needles"], 1)
        self.assertEqual(served["mihomo"]["secret_hits"], 1)
        self.assertEqual(served["clash"]["secret_hits"], 0)
        self.assertNotIn(self.panel.password, output)

    def test_the_probe_scans_the_link_list_the_base64_body_stands_for(self):
        """A secret inside a link is base64 twice, so the body alone would hide it."""
        link = f"vless://{CLIENT_UUID}@panel.testbed.internal:443?remark={self.panel.password}#leak"
        body = base64.b64encode(link.encode("utf-8")).decode("ascii")
        self.assertNotIn(self.panel.password.encode("utf-8"), body.encode("ascii"))
        self.panel.bodies["base64"] = (body, "text/plain")
        facts, output = probe_output(self.panel, "subscriptions", str(self.payload_dir))
        self.assertEqual(facts["subscriptions"]["representations"]["base64"]["secret_hits"], 1)
        self.assertNotIn(self.panel.password, output)

    def test_the_representation_inventory_matches_the_pinned_matrix(self):
        matrix = yaml.safe_load(
            (REPO_ROOT / "tests" / "cases" / "matrix.yaml").read_text(encoding="utf-8")
        )
        self.assertEqual(sorted(matrix["representations"]), sorted(aio.REPRESENTATIONS))
        for name, template, _agent in panel_surface.REPRESENTATIONS:
            self.assertEqual(
                matrix["representations"][name].replace("{shortUuid}", "{short_uuid}"), template
            )


class TestChannelClientSurface(unittest.TestCase):
    """The channel scope states what a switch or a rollback left the client with.

    A channel switch restarts the Panel and a rollback restores its database, and
    the Panel writes to SQLite while it runs. The scope therefore compares the
    client list and the bytes each representation serves, and it keeps the
    captured payload digests in a 0600 state file rather than printing them.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.payload_dir = Path(self.tmp.name) / "payloads"
        self.payload_dir.mkdir(mode=0o700)
        self.panel = StubPanel()
        self.addCleanup(self.panel.server.shutdown)
        self.addCleanup(self.panel.server.server_close)

    def capture(self):
        facts, _output = probe_output(
            self.panel, "channel", str(self.payload_dir), step="capture",
        )
        return facts["channel"]

    def verify(self):
        facts, output = probe_output(
            self.panel, "channel", str(self.payload_dir), step="verify",
        )
        return facts["channel"], output

    def test_an_unchanged_panel_verifies_as_identical(self):
        captured = self.capture()
        self.assertEqual(captured["readback_status"], 200)
        self.assertEqual(captured["short_uuid_length"], len(SHORT_UUID))
        self.assertEqual(captured["users"], len(self.panel.users))

        state = self.payload_dir / "channel" / "state.json"
        self.assertEqual(state.stat().st_mode & 0o777, 0o600)

        verified, output = self.verify()
        self.assertTrue(verified["inventory_identical"])
        self.assertTrue(verified["user_present"])
        self.assertTrue(all(verified["representations_identical"].values()))
        self.assertEqual(
            sorted(verified["representations_identical"]),
            sorted(name for name, _template, _agent in panel_surface.REPRESENTATIONS),
        )
        for secret in (SHORT_UUID, CLIENT_UUID, TROJAN_PASSWORD, REALITY_PUBLIC_KEY):
            self.assertNotIn(secret, output)

    def test_a_client_the_switch_lost_is_not_an_identical_inventory(self):
        self.capture()
        self.panel.users = []
        verified, _output = self.verify()
        self.assertFalse(verified["inventory_identical"])
        self.assertFalse(verified["user_present"])
        self.assertEqual(verified["users"], 0)
        self.assertEqual(verified["users_captured"], 1)

    def test_a_representation_that_serves_different_bytes_is_reported(self):
        self.capture()
        self.panel.bodies["mihomo"] = ("changed: {}\n", "text/yaml")
        verified, _output = self.verify()
        self.assertFalse(verified["representations_identical"]["mihomo"])
        self.assertTrue(verified["representations_identical"]["base64"])
        self.assertEqual(verified["representations"]["mihomo"]["status"], 200)

    def test_a_scope_call_without_a_capture_asks_for_one(self):
        with self.assertRaises(SystemExit) as caught:
            self.verify()
        self.assertIn("run --step capture first", str(caught.exception))

    def test_the_scope_refuses_to_run_without_a_payload_directory(self):
        with self.assertRaises(SystemExit) as caught:
            probe_output(self.panel, "channel", step="capture")
        self.assertIn("--payload-dir", str(caught.exception))


class RecordingEngines:
    """Stand-in for the pinned binaries: records what they were asked to load."""

    def __init__(self):
        self.calls = []
        self.configs = []
        self.modes = []

    def __call__(self, argv, timeout=subscription_probe.COMMAND_TIMEOUT_SECONDS):
        argv = list(argv)
        self.calls.append(argv)
        for index, value in enumerate(argv):
            if value in ("-c", "-f") and index + 1 < len(argv):
                path = Path(argv[index + 1])
                if path.is_file():
                    self.modes.append(path.stat().st_mode & 0o777)
                    if path.suffix == ".json":
                        self.configs.append(json.loads(path.read_text(encoding="utf-8")))
        return 0


class TestSubscriptionClientProbe(unittest.TestCase):
    """The engine-side probe imports what the Panel served and prints no secret."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.payloads = Path(self.tmp.name) / "secrets"
        self.payloads.mkdir(mode=0o700)
        self.workdir = Path(self.tmp.name) / "work"
        self.workdir.mkdir(mode=0o700)
        self.ca = Path(self.tmp.name) / "issued-root.pem"
        self.ca.write_text(PEM, encoding="utf-8")
        self.write_payloads()
        self.engines = RecordingEngines()
        patcher = mock.patch.object(subscription_probe, "run_engine", self.engines)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write_payloads(self, xray_json=None):
        bodies = dict(BODIES)
        bodies["xray-json"] = (xray_json or JSON_BODY, "application/json")
        for name, (body, _content_type) in bodies.items():
            path = self.payloads / f"{name}.payload"
            path.write_text(body, encoding="utf-8")
            path.chmod(0o600)

    # ---------------------------------------------------------- share links
    def test_the_base64_list_decodes_and_a_json_body_does_not(self):
        decoded = subscription_probe.decode_share_list(BASE64_BODY)
        self.assertEqual(decoded, "\n".join(LINKS))
        self.assertEqual(len(subscription_probe.share_links(decoded)), 4)
        self.assertIsNone(subscription_probe.decode_share_list(JSON_BODY))
        self.assertEqual(subscription_probe.share_links(subscription_probe.decode_share_list(JSON_BODY)), [])
        self.assertIsNone(subscription_probe.decode_share_list(""))

    def test_an_unpadded_body_decodes(self):
        self.assertEqual(subscription_probe.decode_share_list("aGVsbG8"), "hello")

    def test_parse_link_reads_the_reality_parameters(self):
        link = subscription_probe.parse_link(REALITY_LINK)
        self.assertEqual(link["protocol"], "vless")
        self.assertEqual(link["host"], "panel.testbed.internal")
        self.assertEqual(link["port"], "443")
        self.assertEqual(link["sni"], "reality.testbed.internal")
        self.assertEqual(link["fingerprint"], "firefox")
        self.assertEqual(link["security"], "reality")
        self.assertEqual(link["network"], "tcp")
        self.assertEqual(link["flow"], "xtls-rprx-vision")
        self.assertEqual(link["reality_public_key"], REALITY_PUBLIC_KEY)
        self.assertEqual(link["reality_short_id"], "ab12")
        self.assertEqual(link["credential"], CLIENT_UUID)
        self.assertEqual(link["tag"], "vless-reality")

    def test_outbound_from_link_mirrors_the_panel_shapes(self):
        parsed = [subscription_probe.parse_link(link) for link in LINKS]

        reality = subscription_probe.outbound_from_link(parsed[0], "reality")
        self.assertEqual(reality["settings"]["vnext"][0]["users"][0],
                         {"id": CLIENT_UUID, "encryption": "none", "flow": "xtls-rprx-vision"})
        stream = reality["streamSettings"]
        self.assertEqual(stream["network"], "tcp")
        self.assertEqual(stream["security"], "reality")
        self.assertEqual(stream["tcpSettings"], {"header": {"type": "none"}})
        self.assertEqual(stream["realitySettings"], {
            "serverName": "reality.testbed.internal",
            "publicKey": REALITY_PUBLIC_KEY,
            "shortId": "ab12",
            "fingerprint": "firefox",
        })

        xhttp = subscription_probe.outbound_from_link(parsed[1], "xhttp")["streamSettings"]
        self.assertEqual(xhttp["xhttpSettings"], {"mode": "auto", "host": "", "path": "/xhttp"})
        self.assertEqual(xhttp["tlsSettings"], {
            "serverName": "panel.testbed.internal",
            "enableSessionResumption": False,
            "fingerprint": "firefox",
        })

        ws = subscription_probe.outbound_from_link(parsed[2], "ws")["streamSettings"]
        self.assertEqual(ws["wsSettings"], {"path": "/ws", "host": "", "headers": {}})

        trojan = subscription_probe.outbound_from_link(parsed[3], "trojan")
        self.assertEqual(trojan["protocol"], "trojan")
        self.assertEqual(trojan["settings"]["servers"][0],
                         {"address": "panel.testbed.internal", "port": 443, "password": TROJAN_PASSWORD})
        self.assertEqual(trojan["streamSettings"]["grpcSettings"],
                         {"serviceName": "grpc", "authority": "", "multiMode": False})

    def test_an_alpn_list_is_carried_into_the_tls_settings(self):
        parsed = dict(subscription_probe.parse_link(XHTTP_LINK), alpn="h2%2Chttp/1.1")
        stream = subscription_probe.outbound_from_link(parsed, "xhttp")["streamSettings"]
        self.assertEqual(stream["tlsSettings"]["alpn"], ["h2", "http/1.1"])

    def test_a_link_family_this_suite_cannot_import_is_rejected(self):
        parsed = subscription_probe.parse_link(REALITY_LINK)
        for override, expected in (
            ({"protocol": "ss"}, "protocol"),
            ({"network": "kcp"}, "network"),
            ({"security": "xtls"}, "security"),
        ):
            with self.subTest(**override):
                with self.assertRaises(SystemExit) as caught:
                    subscription_probe.outbound_from_link(dict(parsed, **override), "x")
                self.assertIn(expected, str(caught.exception))

    def test_link_and_outbound_identities_agree(self):
        for link in LINKS:
            with self.subTest(link=link.split("://")[0]):
                parsed = subscription_probe.parse_link(link)
                outbound = subscription_probe.outbound_from_link(parsed, "proxy")
                self.assertEqual(subscription_probe.outbound_identity(outbound),
                                 subscription_probe.link_identity(parsed))

    # ------------------------------------------------------------- configs
    def test_prepare_config_wraps_only_a_bare_object(self):
        bare = {"outbounds": [json.loads(json.dumps(REALITY_OUTBOUND))]}
        prepared, wrapped = subscription_probe.prepare_config(bare, str(self.ca))
        self.assertTrue(wrapped)
        self.assertEqual(prepared["inbounds"], [subscription_probe.SOCKS_INBOUND])
        self.assertNotIn("inbounds", bare)
        prepared["inbounds"][0]["port"] = 1
        self.assertEqual(subscription_probe.SOCKS_INBOUND["port"], 10808)

        prepared, wrapped = subscription_probe.prepare_config(PROFILES[1], str(self.ca))
        self.assertFalse(wrapped)
        self.assertEqual(prepared["inbounds"], PROFILES[1]["inbounds"])

    def test_prepare_config_anchors_only_tls_outbounds(self):
        config = {"outbounds": [
            json.loads(json.dumps(REALITY_OUTBOUND)),
            json.loads(json.dumps(XHTTP_OUTBOUND)),
        ]}
        prepared, _wrapped = subscription_probe.prepare_config(config, str(self.ca))
        reality, xhttp = prepared["outbounds"]
        self.assertNotIn("tlsSettings", reality["streamSettings"])
        self.assertEqual(xhttp["streamSettings"]["tlsSettings"]["certificates"],
                         [{"usage": "verify", "certificate": [PEM]}])
        self.assertNotIn("certificates", config["outbounds"][1]["streamSettings"]["tlsSettings"])

    def test_prepare_config_keeps_the_panel_outbound_unchanged(self):
        config = json.loads(json.dumps(PROFILES))
        served = [outbound for entry in config for outbound in entry["outbounds"]]
        prepared, _wrapped = subscription_probe.prepare_config({"outbounds": served}, str(self.ca))
        self.assertEqual(len(prepared["outbounds"]), len(served))
        for before, after in zip(served, prepared["outbounds"]):
            tls_settings = (after.get("streamSettings") or {}).get("tlsSettings")
            if tls_settings and "certificates" in tls_settings:
                self.assertEqual(tls_settings["certificates"],
                                 [{"usage": "verify", "certificate": [PEM]}])
                tls_settings.pop("certificates")
            self.assertEqual(after, before,
                             "the only change to a Panel-issued outbound is the trust anchor")

    def test_prepare_config_rejects_a_config_without_outbounds(self):
        for config in ({}, {"outbounds": []}):
            with self.subTest(config=config):
                with self.assertRaises(SystemExit) as caught:
                    subscription_probe.prepare_config(config, str(self.ca))
                self.assertIn("no outbounds list", str(caught.exception))

    def test_xray_test_removes_its_work_file_and_runs_the_pinned_command(self):
        wrapped = subscription_probe.xray_test(PROFILES[0], str(self.ca), self.workdir, "one")
        self.assertFalse(wrapped)
        self.assertEqual(list(self.workdir.iterdir()), [])
        self.assertEqual(self.engines.modes, [0o600])
        self.assertEqual(self.engines.calls[0][:4], ["xray", "run", "-test", "-c"])

    # --------------------------------------------------------------- yaml
    def test_scan_mihomo_counts_proxies_groups_and_the_match_rule(self):
        facts = subscription_probe.scan_mihomo(MIHOMO_YAML)
        self.assertEqual(facts["proxies"], 4)
        self.assertEqual(facts["proxy_types"], ["trojan", "vless"])
        self.assertEqual(facts["groups"], 1)
        self.assertEqual(facts["rules"], 1)
        self.assertTrue(facts["match_rule"])

    def test_scan_mihomo_ignores_nested_lists_and_group_members(self):
        # The shipped Panel emits ``alpn`` lists inside every proxy and repeats
        # the proxy names inside the group; both are nested, neither is a proxy.
        text = MIHOMO_YAML.replace("    alpn:\n      - h2\n      - http/1.1\n",
                                   "    alpn:\n      - h2\n      - http/1.1\n      - h3\n")
        facts = subscription_probe.scan_mihomo(text)
        self.assertEqual(facts["proxies"], 4)
        self.assertEqual(facts["groups"], 1)
        self.assertEqual(facts["rules"], 1)

    def test_scan_mihomo_reports_a_group_member_no_proxy_defines(self):
        text = MIHOMO_YAML.replace(
            '      - "Trojan · gRPC · TLS — local-node"',
            '      - "Trojan · gRPC · TLS — ams-99"',
        )
        facts = subscription_probe.scan_mihomo(text)
        self.assertEqual(facts["proxies"], 4)
        self.assertEqual(facts["group_members"], 4)
        self.assertEqual(facts["missing_group_references"], ["Trojan · gRPC · TLS — ams-99"])
        self.assertEqual(subscription_probe.scan_mihomo(MIHOMO_YAML)["missing_group_references"], [])

    def test_scan_mihomo_does_not_invent_a_match_rule(self):
        text = MIHOMO_YAML.replace("- MATCH,GoWave", "- DOMAIN-SUFFIX,testbed.internal,GoWave")
        facts = subscription_probe.scan_mihomo(text)
        self.assertEqual(facts["rules"], 1)
        self.assertFalse(facts["match_rule"])

    # ------------------------------------------------------------ profiles
    def test_load_profiles_accepts_both_documented_shapes(self):
        shape, entries = subscription_probe.load_profiles(JSON_BODY)
        self.assertEqual((shape, len(entries)), ("list", 4))
        shape, entries = subscription_probe.load_profiles(json.dumps(PROFILES[0]))
        self.assertEqual((shape, len(entries)), ("object", 1))

    def test_load_profiles_rejects_what_it_cannot_serve(self):
        for raw, expected in (
            ("not json", "not JSON"),
            ("[]", "empty profile list"),
            ("{}", "neither a config object nor a profile list"),
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(SystemExit) as caught:
                    subscription_probe.load_profiles(raw)
                self.assertIn(expected, str(caught.exception))

    def test_proxy_outbounds_skips_the_runtime_entries(self):
        outbounds = subscription_probe.proxy_outbounds(PROFILES)
        self.assertEqual(len(outbounds), 4)
        self.assertEqual([outbound["tag"] for outbound in outbounds],
                         ["reality", "xhttp", "ws", "trojan"])

    # -------------------------------------------------------------- scopes
    def test_representations_loads_every_representation(self):
        facts = subscription_probe.representations(str(self.payloads), str(self.ca), self.workdir)
        self.assertTrue(facts["base64"]["decoded"])
        self.assertEqual(facts["base64"]["link_count"], 4)
        self.assertEqual(facts["base64"]["schemes"], ["trojan", "vless"])
        self.assertEqual(facts["xray_json"],
                         {"shape": "list", "entries": 4, "wrapped": 0,
                          "protocols": ["trojan", "vless"],
                          "transports": ["trojan/grpc/tls", "vless/tcp/reality",
                                         "vless/ws/tls", "vless/xhttp/tls"],
                          "fingerprints": ["firefox"], "sni_missing": 0,
                          "dials": [
                              {"tag": "reality", "protocol": "vless",
                               "address": "panel.testbed.internal", "port": "443",
                               "sni": "reality.testbed.internal", "path": "",
                               "service_name": "", "network": "tcp"},
                              {"tag": "xhttp", "protocol": "vless",
                               "address": "panel.testbed.internal", "port": "443",
                               "sni": "panel.testbed.internal", "path": "/xhttp",
                               "service_name": "", "network": "xhttp"},
                              {"tag": "ws", "protocol": "vless",
                               "address": "panel.testbed.internal", "port": "443",
                               "sni": "panel.testbed.internal", "path": "/ws",
                               "service_name": "", "network": "ws"},
                              {"tag": "trojan", "protocol": "trojan",
                               "address": "panel.testbed.internal", "port": "443",
                               "sni": "panel.testbed.internal", "path": "",
                               "service_name": "grpc", "network": "grpc"},
                          ],
                          "private_keys": 0})
        for name in ("mihomo", "clash"):
            self.assertEqual(facts[name]["exit"], 0)
            self.assertEqual(facts[name]["proxies"], 4)
            self.assertTrue(facts[name]["match_rule"])
            self.assertEqual(facts[name]["rule_names"], ["MATCH"])
            self.assertEqual(facts[name]["duplicate_names"], 0)
            self.assertEqual(facts[name]["client_fingerprints"], ["firefox"])
            self.assertEqual(facts[name]["private_keys"], 0)
        self.assertEqual(facts["singbox"], {"parsed": True, "outbounds": 4, "private_keys": 0})
        self.assertEqual(facts["base64"]["private_keys"], 0)
        self.assertEqual([path.name for path in self.workdir.iterdir()
                          if path.suffix in (".json", ".yaml")], [])
        self.assertEqual(set(self.engines.modes), {0o600})
        self.assertEqual(len(self.engines.configs), 4)

    def test_the_probe_counts_a_server_side_private_key(self):
        """A counter that always reported zero would pass a document leaking a key."""
        leaked = json.loads(JSON_BODY)
        leaked[0]["outbounds"][0]["streamSettings"]["realitySettings"]["privateKey"] = "leak"
        self.write_payloads(xray_json=json.dumps(leaked))
        facts = subscription_probe.representations(str(self.payloads), str(self.ca), self.workdir)
        self.assertEqual(facts["xray_json"]["private_keys"], 1)

    def test_the_probe_counts_a_private_key_in_a_yaml_representation(self):
        self.write_payloads()
        (self.payloads / "mihomo.payload").write_text(
            MIHOMO_YAML + "  private-key: leak\n", encoding="utf-8",
        )
        facts = subscription_probe.representations(str(self.payloads), str(self.ca), self.workdir)
        self.assertEqual(facts["mihomo"]["private_keys"], 1)
        self.assertEqual(facts["clash"]["private_keys"], 0)

    def test_json_shapes_accepts_the_served_list_and_the_bare_object(self):
        facts = subscription_probe.json_shapes(str(self.payloads), str(self.ca), self.workdir)
        self.assertEqual(facts["served_shape"], "list")
        self.assertEqual(facts["served_entries"], 4)
        self.assertEqual(facts["served_wrapped"], 0)
        self.assertEqual(facts["alternate_shape"], "object")
        self.assertEqual(facts["alternate_outbounds"], 1)
        self.assertEqual(facts["alternate_wrapped"], 1)

        alternate = self.engines.configs[-1]
        self.assertEqual(alternate["inbounds"], [subscription_probe.SOCKS_INBOUND])
        first = subscription_probe.proxy_outbounds(PROFILES)[0]
        self.assertEqual(
            [subscription_probe.outbound_identity(item) for item in alternate["outbounds"]],
            [subscription_probe.outbound_identity(first)],
            "the alternate shape must carry the Panel's own outbound, not a rewritten one",
        )

    def test_json_shapes_does_not_merge_the_profiles_into_one_object(self):
        # The Panel tags the host outbound ``proxy`` in every profile, so one
        # object carrying all of them is a tag collision, not a shape.
        shared = json.loads(JSON_BODY)
        for entry in shared:
            entry["outbounds"][0]["tag"] = "proxy"
        self.write_payloads(json.dumps(shared))
        facts = subscription_probe.json_shapes(str(self.payloads), str(self.ca), self.workdir)
        self.assertEqual(
            (facts["alternate_outbounds"], facts["alternate_wrapped"]), (1, 1),
            "the alternate object must be one host's config, not every profile's outbound",
        )
        self.assertEqual([item["tag"] for item in self.engines.configs[-1]["outbounds"]], ["proxy"])

    def test_json_shapes_reads_a_served_complete_object(self):
        self.write_payloads(json.dumps(PROFILES[0]))
        facts = subscription_probe.json_shapes(str(self.payloads), str(self.ca), self.workdir)
        self.assertEqual((facts["served_shape"], facts["served_entries"]), ("object", 1))
        self.assertEqual(facts["served_wrapped"], 0)
        self.assertEqual((facts["alternate_shape"], facts["alternate_wrapped"]), ("list", 0))

    def test_share_link_facts_cross_checks_the_json_outbounds(self):
        facts = subscription_probe.share_link_facts(str(self.payloads), str(self.ca), self.workdir)
        self.assertEqual(facts["link_count"], 4)
        self.assertEqual(facts["protocols"], {"vless": 3, "trojan": 1})
        self.assertEqual(facts["hosts"], ["panel.testbed.internal"])
        self.assertEqual(facts["snis"], ["panel.testbed.internal", "reality.testbed.internal"])
        self.assertEqual(facts["sni_missing"], 0)
        self.assertEqual(facts["fingerprints"], ["firefox"])
        self.assertEqual(facts["fingerprint_missing"], 0)
        self.assertEqual(facts["ports"], ["443"])
        self.assertEqual(facts["networks"], ["grpc", "tcp", "ws", "xhttp"])
        self.assertTrue(facts["credential_present"])
        self.assertEqual(facts["xray_outbounds"], 4)
        self.assertEqual(facts["cross_representation_matches"], 4)
        self.assertEqual(facts["cross_representation_issued"], 4)
        self.assertEqual(facts["json_body_links"], 0)

    def test_share_link_facts_reports_a_drift_against_the_json_body(self):
        drifted = json.loads(JSON_BODY)
        drifted[1]["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"] = "other.testbed.internal"
        self.write_payloads(json.dumps(drifted))
        facts = subscription_probe.share_link_facts(str(self.payloads), str(self.ca), self.workdir)
        self.assertEqual(facts["cross_representation_matches"], 3)
        self.assertEqual(facts["cross_representation_issued"], 4)

    def test_share_link_facts_rejects_a_body_that_is_not_a_link_list(self):
        self.write_payloads()
        (self.payloads / "base64.payload").write_text(JSON_BODY, encoding="utf-8")
        with self.assertRaises(SystemExit) as caught:
            subscription_probe.share_link_facts(str(self.payloads), str(self.ca), self.workdir)
        self.assertIn("is not base64", str(caught.exception))

    def test_sanitize_redacts_client_identifiers(self):
        self.assertEqual(subscription_probe.sanitize(f"rejected {CLIENT_UUID}"),
                         "rejected <id>")
        self.assertEqual(len(subscription_probe.sanitize("x" * 1000, limit=10)), 10)

    def test_main_prints_facts_without_the_client_credentials(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = subscription_probe.main([
                "--scope", "share-links",
                "--payload-dir", str(self.payloads),
                "--ca", str(self.ca),
            ])
        self.assertEqual(code, 0)
        output = stdout.getvalue()
        self.assertNotIn(CLIENT_UUID, output)
        self.assertNotIn(TROJAN_PASSWORD, output)
        self.assertNotIn("vless://", output)
        self.assertEqual(json.loads(output)["link_count"], 4)


class ScriptedPodman:
    """Podman stub that returns prepared host-script results in order."""

    def __init__(self, context, scripts):
        self.context = context
        self.scripts = []
        self.execs = []
        self.results = list(scripts)

    def exec_bash(self, name, script, check=True, input_text=None, timeout=300):
        self.scripts.append(script)
        stdout, returncode = self.results.pop(0)
        return subprocess.CompletedProcess(["bash", "-lc", script], returncode, stdout, "")

    def exec(self, name, argv, check=True, input_text=None, timeout=300):
        """The engine container printing the version the matrix pinned for it.

        A data-plane case reads the version of the core that carried the payload,
        so the stub answers that read from the manifest: a moved client pin would
        otherwise leave a literal here naming a build the case no longer expects.
        """
        self.execs.append((name, list(argv)))
        binary = list(argv)[0]
        pinned = next(
            (item["contains"] for item in client_image.engine_list(matrix.load())
             if item["binary"] == binary),
            "",
        )
        return subprocess.CompletedProcess(list(argv), 0, f"{binary} {pinned} (fixture)\n", "")


class StubEngineHost:
    """The installed host, without containers, plus the engine-side probe."""

    def __init__(self, results=(), vision_domain=None):
        self.target_name = "aio-1"
        self.panel_domain = aio.PANEL_DOMAIN
        self.reality_domain = aio.REALITY_DOMAIN
        self.vision_domain = vision_domain
        self.scopes = []
        self.timeouts = []
        self.results = list(results)

    def subscription_facts(self, scope, timeout=300):
        self.scopes.append(scope)
        self.timeouts.append(timeout)
        return self.results.pop(0)

    def install_environment(self):
        return {"GOWAVE_ACME_TEST_CA_FILE": f"{topology.CA_MOUNT}/{topology.ACME_CA_BUNDLE_NAME}"}

    def engine_hosts(self):
        domains = [self.panel_domain, self.reality_domain]
        if self.vision_domain:
            domains.append(self.vision_domain)
        return {domain: self.target_name for domain in domains}

    def subscription_domains(self):
        required_hosts = {self.panel_domain}
        required_snis = {self.reality_domain}
        if self.vision_domain:
            required_hosts.add(self.vision_domain)
            required_snis.add(self.vision_domain)
        return {
            "allowed": set(self.engine_hosts()),
            "required_hosts": required_hosts,
            "required_snis": required_snis,
        }

    def engine_client(self):
        """The engine role's container, which a data-plane case reads a version from."""
        return "engine-client"


def panel_result(payload, returncode=0):
    body = payload if isinstance(payload, str) else json.dumps(payload)
    return (body, returncode)


def engine_result(payload, returncode=0):
    stdout = payload if isinstance(payload, str) else json.dumps(payload)
    return subprocess.CompletedProcess(
        ["python3", "subscription_probe.py"], returncode, stdout,
        "" if returncode == 0 else "engine rejected the config",
    )


def installed_product(context, host_scripts=(), engine_results=()):
    podman = ScriptedPodman(context, host_scripts)
    product = aio.AioProduct(podman)
    product.host = StubEngineHost(engine_results)
    product.outcome = topology.InstallOutcome(0, "", "", 1.0, "install")
    # What the install read out of `rw-core version`: a data-plane tuple compares
    # the client core with the core its node deployed, so the fake names that core.
    product.server_core_version = matrix.product(matrix.load()).get("xray_version", "")
    return product, podman


class TestSubscriptionCases(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.context = RunContext(
            topology="aio",
            artifact_root=Path(self.tmp.name),
            budget_seconds=600,
            run_id="podman-subscription-test-000000",
        )
        self.addCleanup(self.context.run_cleanup)

    def reject(self, expected, served=None, engine=None, engine_returncode=0):
        product, _ = installed_product(
            self.context,
            host_scripts=[panel_result({"subscriptions": served or served_facts()})],
            engine_results=[engine_result(engine or engine_representations(), engine_returncode)],
        )
        with self.assertRaises(AssertionError) as caught:
            aio.case_subscriptions(product)
        self.assertIn(expected, str(caught.exception))

    # ------------------------------------------------------------ SUB-SERVED
    def test_subscriptions_case_loads_every_representation(self):
        product, podman = installed_product(
            self.context,
            host_scripts=[panel_result({"subscriptions": served_facts()})],
            engine_results=[engine_result(engine_representations())],
        )
        evidence = aio.case_subscriptions(product)
        self.assertEqual(evidence["base64_status"], 200)
        self.assertEqual(evidence["xray_json_shape"], "list")
        self.assertEqual(evidence["xray_json_entries"], 4)
        self.assertEqual(evidence["xray_json_wrapped"], 0)
        self.assertEqual(evidence["mihomo_proxies"], 4)
        self.assertEqual(evidence["mihomo_proxy_types"], "trojan,vless")
        self.assertEqual(evidence["clash_proxies"], 1)
        self.assertEqual(evidence["clash_proxy_types"], "trojan")
        self.assertTrue(evidence["clash_match_rule"])
        self.assertEqual(evidence["singbox_outbounds"], 4)
        self.assertEqual(podman.scripts[0],
                         f"python3 {aio.PANEL_SURFACE_SCRIPT} --scope subscriptions "
                         f"--payload-dir {topology.PAYLOAD_MOUNT} "
                         f"--edge-base https://{aio.PANEL_DOMAIN} "
                         f"--ca {topology.CA_MOUNT}/{topology.ACME_CA_BUNDLE_NAME}")
        self.assertEqual(product.host.scopes, ["representations"])
        for value in evidence.values():
            self.assertIsInstance(
                value, (str, int, float, bool, type(None)),
                "evidence is flattened to strings by the runner, so it must hold primitives",
            )

    def test_subscriptions_case_rejects_a_representation_that_is_not_served(self):
        self.reject("instead of 200", served=served_facts({"representations.clash.status": 500}))

    def test_subscriptions_case_rejects_a_cachable_representation(self):
        self.reject("lets a cache serve a subscription",
                    served=served_facts(
                        {"representations.mihomo.edge_cache_control": "public, max-age=600"}))

    def test_subscriptions_case_rejects_a_representation_with_no_cache_control(self):
        self.reject("lets a cache serve a subscription",
                    served=served_facts({"representations.base64.edge_cache_control": ""}))

    def test_subscriptions_case_does_not_read_the_header_from_the_panel_process(self):
        """The loopback answer is never the one the case trusts.

        The Panel sends no Cache-Control; the vhost does. A case that asserted
        the loopback value would have failed against the real product while the
        header a client receives was present, which is what the first version of
        this case did.
        """
        product, _ = installed_product(
            self.context,
            host_scripts=[panel_result({"subscriptions": served_facts()})],
            engine_results=[engine_result(engine_representations())],
        )
        evidence = aio.case_subscriptions(product)
        self.assertEqual(evidence["base64_backend_cache_control"], "")
        self.assertEqual(evidence["base64_cache_control"], NO_STORE)

    def test_subscriptions_case_rejects_an_edge_response_from_another_body(self):
        self.reject("describes a body no engine consumed",
                    served=served_facts({"representations.clash.edge_identical": False}))

    def test_subscriptions_case_rejects_an_edge_that_refused_the_request(self):
        self.reject("the public edge answered",
                    served=served_facts({"representations.singbox.edge_status": 404}))

    def test_subscriptions_case_names_the_cache_control_it_received(self):
        product, _ = installed_product(
            self.context,
            host_scripts=[panel_result({"subscriptions": served_facts()})],
            engine_results=[engine_result(engine_representations())],
        )
        evidence = aio.case_subscriptions(product)
        for name in aio.REPRESENTATIONS:
            with self.subTest(representation=name):
                self.assertEqual(evidence[f"{name}_cache_control"], NO_STORE)

    def test_subscriptions_case_rejects_an_empty_representation(self):
        self.reject("is empty", served=served_facts({"representations.singbox.bytes": 0}))

    def test_subscriptions_case_rejects_a_missing_media_type(self):
        self.reject("as media type '' instead of 'text/yaml'",
                    served=served_facts({"representations.mihomo.content_type": ""}))

    def test_subscriptions_case_rejects_a_wrong_media_type(self):
        # A media type is a claim about which importer the bytes belong to, so a
        # well-formed but wrong one is the failure this require exists for.
        self.reject("as media type 'text/plain' instead of 'application/json'",
                    served=served_facts({"representations.xray-json.content_type": "text/plain"}))

    def test_subscriptions_case_names_the_media_type_each_representation_is_served_with(self):
        product, _ = installed_product(
            self.context,
            host_scripts=[panel_result({"subscriptions": served_facts()})],
            engine_results=[engine_result(engine_representations())],
        )
        evidence = aio.case_subscriptions(product)
        for name in aio.REPRESENTATIONS:
            with self.subTest(representation=name):
                self.assertEqual(evidence[f"{name}_content_type"],
                                 aio.REPRESENTATION_MEDIA_TYPES[name])

    def test_subscriptions_case_rejects_a_secret_scan_with_nothing_to_scan(self):
        self.reject("not evidence", served=served_facts({"secret_needles": 1}))

    def test_subscriptions_case_rejects_a_representation_carrying_a_server_secret(self):
        self.reject("server-side secret",
                    served=served_facts({"representations.mihomo.secret_hits": 1}))

    def test_subscriptions_case_rejects_a_host_list_it_could_not_read(self):
        self.reject("GET /api/hosts answered 500", served=served_facts({"hosts.status": 500}))

    def test_subscriptions_case_rejects_a_subscription_that_agrees_with_no_host(self):
        self.reject("returned no Host record", served=served_facts({"hosts.records": []}))

    def test_subscriptions_case_rejects_a_dial_address_no_host_record_names(self):
        # The REALITY record is the one whose address and SNI pair no other record
        # shares, so moving it leaves the dial with nothing to correspond to.
        records = [dict(record) for record in served_facts()["hosts"]["records"]]
        records[0]["address"] = "elsewhere.testbed.internal"
        self.reject("which no Host record names",
                    served=served_facts({"hosts.records": records}))

    def test_subscriptions_case_rejects_a_dial_path_no_host_record_names(self):
        # Three inbounds share ``panel.testbed.internal`` as both address and SNI,
        # so the path is the only field that tells them apart; a record naming a
        # different path is a different inbound.
        records = [dict(record) for record in served_facts()["hosts"]["records"]]
        records[1]["path"] = "/other"
        self.reject("which no Host record on that address and SNI names",
                    served=served_facts({"hosts.records": records}))

    def test_subscriptions_case_rejects_a_dial_set_that_is_not_one_per_inbound(self):
        dials = engine_representations()["xray_json"]["dials"][:3]
        self.reject("carry a dial tuple",
                    engine=engine_representations({"xray_json.dials": dials}))

    def test_subscriptions_case_rejects_a_private_key_in_a_representation(self):
        for name in ("base64", "xray_json", "mihomo", "clash", "singbox"):
            with self.subTest(representation=name):
                self.reject("server-side private key field",
                            engine=engine_representations({f"{name}.private_keys": 1}))

    def test_subscriptions_case_accepts_a_host_record_the_subscription_does_not_dial(self):
        """The require is "every dial is recorded", not "the two sets are equal".

        The Panel keeps records no client dials; an equality check would have
        called such a record a defect and pointed at the wrong document.
        """
        records = list(served_facts()["hosts"]["records"]) + [{
            "remark": "Panel@local-node", "address": "panel.testbed.internal", "port": "443",
            "sni": "panel.testbed.internal", "path": "/api", "security_layer": "TLS",
            "alpn": "http/1.1", "disabled": False,
        }]
        product, _ = installed_product(
            self.context,
            host_scripts=[panel_result({"subscriptions": served_facts({"hosts.records": records})})],
            engine_results=[engine_result(engine_representations())],
        )
        evidence = aio.case_subscriptions(product)
        self.assertEqual(evidence["host_records"], 5)
        self.assertEqual(evidence["host_record_mismatches"], 0)
        self.assertEqual(evidence["xray_json_dials"], 4)

    def test_subscriptions_case_rejects_a_panel_that_refuses_a_foreign_header(self):
        self.reject("names no client family",
                    served=served_facts({"representations.mihomo.foreign_status": 403}))

    def test_subscriptions_case_rejects_a_representation_selected_by_the_header(self):
        self.reject("selecting the representation",
                    served=served_facts({"representations.base64.foreign_identical": False}))

    def test_subscriptions_case_names_the_header_it_sent(self):
        product, _ = installed_product(
            self.context,
            host_scripts=[panel_result({"subscriptions": served_facts()})],
            engine_results=[engine_result(engine_representations())],
        )
        evidence = aio.case_subscriptions(product)
        self.assertEqual(evidence["ua_foreign"], panel_surface.FOREIGN_USER_AGENT)
        for name in aio.REPRESENTATIONS:
            with self.subTest(representation=name):
                self.assertEqual(evidence[f"{name}_foreign_status"], 200)
                self.assertIs(evidence[f"{name}_foreign_identical"], True)

    def test_subscriptions_case_rejects_a_default_client_without_a_short_uuid(self):
        self.reject("no shortUuid", served=served_facts({"short_uuid_length": 0}))

    def test_subscriptions_case_rejects_a_base64_body_that_does_not_decode(self):
        self.reject("did not decode", engine=engine_representations({"base64.decoded": False}))

    def test_subscriptions_case_rejects_a_link_list_that_lost_an_inbound(self):
        self.reject("one per inbound",
                    engine=engine_representations({"base64.link_count": 3}))

    def test_subscriptions_case_rejects_an_unknown_xray_shape(self):
        self.reject("neither a config object", engine=engine_representations({"xray_json.shape": "map"}))

    def test_subscriptions_case_rejects_a_profile_count_that_does_not_match_the_shape(self):
        self.reject("expected 1", engine=engine_representations({"xray_json.shape": "object"}))

    def test_subscriptions_case_rejects_a_profile_set_that_lost_a_protocol(self):
        self.reject("core vless and trojan set",
                    engine=engine_representations({"xray_json.protocols": ["vless"]}))

    def test_subscriptions_case_rejects_a_served_profile_that_needs_a_wrapper(self):
        self.reject("not a runnable config",
                    engine=engine_representations({"xray_json.wrapped": 1}))

    def test_subscriptions_case_rejects_a_yaml_the_engine_does_not_accept(self):
        self.reject("did not load the Panel YAML",
                    engine=engine_representations({"mihomo.exit": 1}))

    def test_subscriptions_case_rejects_a_yaml_with_a_missing_proxy(self):
        self.reject("(one per inbound)", engine=engine_representations({"mihomo.proxies": 3}))

    def test_subscriptions_case_rejects_a_clash_yaml_that_is_not_the_trojan_subset(self):
        self.reject("the trojan subset", engine=engine_representations({
            "clash.proxies": 4, "clash.proxy_types": ["trojan", "vless"],
        }))

    def test_subscriptions_case_rejects_a_yaml_with_an_unexpected_proxy_type(self):
        self.reject("proxy types", engine=engine_representations({"mihomo.proxy_types": ["vless"]}))

    def test_subscriptions_case_rejects_a_yaml_without_a_match_rule(self):
        self.reject("no MATCH and no GEOIP rule", engine=engine_representations({
            "clash.match_rule": False, "clash.rule_names": []}))

    def test_subscriptions_case_accepts_a_geoip_rule_family_without_match(self):
        """The pinned Panel routes by ``GEOIP,LAN,DIRECT`` and the live contract
        by ``GEOIP,private,DIRECT,no-resolve``; neither family ends in MATCH, so
        a rule that names GEOIP is enough to prove the client routes at all."""
        product, _ = installed_product(
            self.context,
            host_scripts=[panel_result({"subscriptions": served_facts()})],
            engine_results=[engine_result(engine_representations({
                "mihomo.match_rule": False, "mihomo.rule_names": ["GEOIP"]}))],
        )
        evidence = aio.case_subscriptions(product)
        self.assertEqual(evidence["mihomo_rule_names"], "GEOIP")

    def test_subscriptions_case_rejects_a_profile_dialling_a_foreign_transport(self):
        self.reject("transport", engine=engine_representations({
            "xray_json.transports": ["trojan/grpc/tls", "vless/tcp/tls",
                                     "vless/ws/tls", "vless/xhttp/tls"]}))

    def test_subscriptions_case_rejects_a_profile_with_the_wrong_fingerprint(self):
        self.reject("fingerprints", engine=engine_representations({
            "xray_json.fingerprints": ["chrome"]}))

    def test_subscriptions_case_rejects_a_profile_without_an_sni(self):
        self.reject("carry no SNI", engine=engine_representations({
            "xray_json.sni_missing": 1}))

    def test_subscriptions_case_rejects_a_yaml_with_duplicate_proxy_names(self):
        self.reject("duplicate proxy name", engine=engine_representations({
            "mihomo.duplicate_names": 1}))

    def test_subscriptions_case_rejects_a_mihomo_yaml_with_the_wrong_client_fingerprint(self):
        self.reject("client-fingerprint", engine=engine_representations({
            "mihomo.client_fingerprints": ["chrome"]}))

    def test_subscriptions_case_names_the_tuple_and_fingerprint_it_read(self):
        product, _ = installed_product(
            self.context,
            host_scripts=[panel_result({"subscriptions": served_facts()})],
            engine_results=[engine_result(engine_representations())],
        )
        evidence = aio.case_subscriptions(product)
        self.assertEqual(evidence["xray_json_transports"],
                         "trojan/grpc/tls,vless/tcp/reality,vless/ws/tls,vless/xhttp/tls")
        self.assertEqual(evidence["xray_json_expected_transports"],
                         "trojan/grpc/tls,vless/tcp/reality,vless/ws/tls,vless/xhttp/tls")
        self.assertEqual(evidence["xray_json_fingerprints"], "firefox")
        self.assertEqual(evidence["xray_json_sni_missing"], 0)
        self.assertEqual(evidence["mihomo_rule_names"], "MATCH")
        self.assertEqual(evidence["mihomo_duplicate_names"], 0)
        self.assertEqual(evidence["mihomo_client_fingerprints"], "firefox")

    def test_subscriptions_case_rejects_a_singbox_body_without_outbounds(self):
        self.reject("carries no outbounds", engine=engine_representations({"singbox.outbounds": 0}))

    def test_subscriptions_case_reports_a_probe_that_did_not_print_json(self):
        product, _ = installed_product(self.context, host_scripts=[("<html>502</html>\n", 0)])
        with self.assertRaises(AssertionError) as caught:
            aio.case_subscriptions(product)
        self.assertIn("did not print JSON", str(caught.exception))

    def test_subscriptions_case_reports_a_probe_that_failed(self):
        product, _ = installed_product(self.context, host_scripts=[("login failed\n", 2)])
        with self.assertRaises(AssertionError) as caught:
            aio.case_subscriptions(product)
        self.assertIn("subscription probe exited 2", str(caught.exception))

    # ------------------------------------------------------- SUB-UA-ABSENT
    def test_absent_user_agent_case_is_refused_for_every_representation(self):
        product, podman = installed_product(
            self.context, host_scripts=[panel_result({"policy": policy_facts("absent")})]
        )
        evidence = aio.case_user_agent_absent(product)
        self.assertEqual(evidence["policy"], "absent")
        self.assertEqual(evidence["representation_count"], len(aio.REPRESENTATIONS))
        self.assertEqual(evidence["statuses"],
                         ",".join(f"{name}=403" for name in aio.REPRESENTATIONS))
        self.assertIn("--scope ua-absent", podman.scripts[0])
        self.assertNotIn("--payload-dir", podman.scripts[0])

    def test_absent_user_agent_case_rejects_a_served_representation(self):
        facts = policy_facts("absent")
        facts["representations"]["base64"] = 200
        product, _ = installed_product(self.context, host_scripts=[panel_result({"policy": facts})])
        with self.assertRaises(AssertionError) as caught:
            aio.case_user_agent_absent(product)
        self.assertIn("served base64 with a absent User-Agent", str(caught.exception))

    def test_absent_user_agent_case_rejects_a_probe_that_sent_a_header(self):
        product, _ = installed_product(
            self.context, host_scripts=[panel_result({"policy": policy_facts("blank")})]
        )
        with self.assertRaises(AssertionError) as caught:
            aio.case_user_agent_absent(product)
        self.assertIn("instead of 'absent'", str(caught.exception))

    def test_absent_user_agent_case_rejects_a_partial_probe(self):
        facts = policy_facts("absent")
        del facts["representations"]["singbox"]
        product, _ = installed_product(self.context, host_scripts=[panel_result({"policy": facts})])
        with self.assertRaises(AssertionError) as caught:
            aio.case_user_agent_absent(product)
        self.assertIn("instead of every served representation", str(caught.exception))

    # -------------------------------------------------------- SUB-UA-BLANK
    def test_blank_user_agent_case_is_a_separate_result(self):
        product, podman = installed_product(
            self.context, host_scripts=[panel_result({"policy": policy_facts("blank")})]
        )
        evidence = aio.case_user_agent_blank(product)
        self.assertEqual(evidence["policy"], "blank")
        self.assertIn("--scope ua-blank", podman.scripts[0])

    def test_blank_user_agent_case_rejects_a_served_representation(self):
        facts = policy_facts("blank")
        facts["representations"]["mihomo"] = 200
        product, _ = installed_product(self.context, host_scripts=[panel_result({"policy": facts})])
        with self.assertRaises(AssertionError) as caught:
            aio.case_user_agent_blank(product)
        self.assertIn("served mihomo with a blank User-Agent", str(caught.exception))

    # ------------------------------------------------------------- SUB-B64
    def test_share_link_case_imports_the_decoded_list(self):
        product, _ = installed_product(
            self.context,
            host_scripts=[panel_result({"subscriptions": served_facts()})],
            engine_results=[engine_result(engine_share_links())],
        )
        evidence = aio.case_share_links(product)
        self.assertEqual(evidence["link_count"], 4)
        self.assertEqual(evidence["protocols"], "trojan=1,vless=3")
        self.assertEqual(evidence["fingerprints"], "firefox")
        self.assertEqual(evidence["ports"], "443")
        self.assertEqual(evidence["json_body_links"], 0)
        self.assertEqual(product.host.scopes, ["share-links"])

    def test_share_link_case_accepts_the_optional_vision_domain(self):
        product, _ = installed_product(
            self.context,
            host_scripts=[panel_result({"subscriptions": served_facts()})],
            engine_results=[engine_result(engine_share_links({
                "hosts": [aio.PANEL_DOMAIN, topology.REALITY_DOMAIN, topology.VISION_DOMAIN],
                "snis": [topology.REALITY_DOMAIN, topology.VISION_DOMAIN],
            }))],
        )
        product.host.vision_domain = topology.VISION_DOMAIN
        aio.case_share_links(product)

    def test_share_link_case_is_blocked_when_the_payloads_were_never_fetched(self):
        product, _ = installed_product(self.context, host_scripts=[("login failed\n", 2)])
        with self.assertRaises(AssertionError):
            aio.case_subscriptions(product)
        with self.assertRaises(CaseBlocked) as caught:
            aio.case_share_links(product)
        self.assertIn("SUB-SERVED", str(caught.exception))

    def test_share_link_case_reports_a_probe_that_failed(self):
        product, _ = installed_product(
            self.context,
            host_scripts=[panel_result({"subscriptions": served_facts()})],
            engine_results=[engine_result({}, 3)],
        )
        with self.assertRaises(AssertionError) as caught:
            aio.case_share_links(product)
        self.assertIn("client probe exited 3", str(caught.exception))

    def reject_links(self, overrides, expected):
        product, _ = installed_product(
            self.context,
            host_scripts=[panel_result({"subscriptions": served_facts()})],
            engine_results=[engine_result(engine_share_links(overrides))],
        )
        with self.assertRaises(AssertionError) as caught:
            aio.case_share_links(product)
        self.assertIn(expected, str(caught.exception))

    def test_share_link_case_rejects_a_list_that_lost_a_link(self):
        self.reject_links({"link_count": 3}, "one per inbound")

    def test_share_link_case_rejects_a_changed_protocol_set(self):
        self.reject_links({"protocols": {"vless": 4}},
                          "instead of the inbound set's own {'vless': 3, 'trojan': 1}")

    def test_share_link_case_rejects_a_link_that_left_the_public_listener(self):
        self.reject_links({"ports": ["8443"]}, "public 443 listener")

    def test_share_link_case_rejects_a_link_without_an_sni(self):
        self.reject_links({"sni_missing": 1}, "carry no SNI")

    def test_share_link_case_rejects_a_link_without_a_fingerprint(self):
        self.reject_links({"fingerprint_missing": 1}, "carry no uTLS fingerprint")

    def test_share_link_case_rejects_a_fingerprint_the_matrix_does_not_pin(self):
        self.reject_links({"fingerprints": ["chrome"]}, "'firefox'")

    def test_share_link_case_rejects_a_link_without_a_credential(self):
        self.reject_links({"credential_present": False}, "carries no client credential")

    def test_share_link_case_rejects_a_host_this_run_never_configured(self):
        self.reject_links({"hosts": ["evil.testbed.internal"]}, "never configured")

    def test_share_link_case_rejects_an_sni_this_run_never_configured(self):
        self.reject_links({"snis": ["evil.testbed.internal"]}, "name SNIs this run never configured")

    def test_share_link_case_rejects_a_link_list_the_importer_could_not_take(self):
        self.reject_links({"xray_outbounds": 0}, "outbounds from the link list")

    def test_share_link_case_rejects_a_drift_against_the_json_body(self):
        self.reject_links({"cross_representation_matches": 3},
                          "link entries match the Panel's own JSON")

    def test_share_link_case_rejects_a_json_body_that_is_a_link_list(self):
        self.reject_links({"json_body_links": 4}, "cannot be told apart")

    # ------------------------------------------------------ SUB-JSON-SHAPES
    def test_json_shape_case_loads_the_served_list_and_the_bare_object(self):
        product, _ = installed_product(
            self.context,
            host_scripts=[panel_result({"subscriptions": served_facts()})],
            engine_results=[engine_result(engine_json_shapes())],
        )
        evidence = aio.case_json_shapes(product)
        self.assertEqual(evidence["served_shape"], "list")
        self.assertEqual(evidence["served_wrapped"], 0)
        self.assertEqual(evidence["alternate_shape"], "object")
        self.assertEqual(evidence["alternate_wrapped"], 1)
        self.assertEqual(product.host.scopes, ["json-shapes"])

    def test_json_shape_case_accepts_the_reverse_served_shape(self):
        product, _ = installed_product(
            self.context,
            host_scripts=[panel_result({"subscriptions": served_facts()})],
            engine_results=[engine_result(engine_json_shapes({
                "served_shape": "object", "served_entries": 1, "served_wrapped": 0,
                "alternate_shape": "list", "alternate_wrapped": 0,
            }))],
        )
        evidence = aio.case_json_shapes(product)
        self.assertEqual((evidence["served_shape"], evidence["alternate_wrapped"]), ("object", 0))

    def reject_shapes(self, overrides, expected):
        product, _ = installed_product(
            self.context,
            host_scripts=[panel_result({"subscriptions": served_facts()})],
            engine_results=[engine_result(engine_json_shapes(overrides))],
        )
        with self.assertRaises(AssertionError) as caught:
            aio.case_json_shapes(product)
        self.assertIn(expected, str(caught.exception))

    def test_json_shape_case_rejects_an_undocumented_shape(self):
        self.reject_shapes({"served_shape": "map"}, "neither documented shape")

    def test_json_shape_case_rejects_an_empty_served_body(self):
        self.reject_shapes({"served_entries": 0}, "carries no profile")

    def test_json_shape_case_rejects_a_served_profile_that_needed_a_wrapper(self):
        self.reject_shapes({"served_wrapped": 1}, "needs no wrapper")

    def test_json_shape_case_rejects_an_alternate_that_repeats_the_served_shape(self):
        self.reject_shapes({"alternate_shape": "list"}, "instead of the one the served")

    def test_json_shape_case_rejects_an_alternate_that_lost_an_outbound(self):
        self.reject_shapes({"alternate_outbounds": 2}, "Panel outbounds")

    def test_json_shape_case_rejects_an_alternate_that_was_not_wrapped(self):
        self.reject_shapes({"alternate_wrapped": 0}, "expected 1")


class TestSubscriptionEdgeCases(unittest.TestCase):
    """SUB-EDGE / SUB-EDGE-BAD: what a pasted link answers through the edge.

    The two cases read one probe block and split the subject: the edge's answers
    to a client and to a link-preview crawler, and the refusal of a raw target a
    normalising client would never send. A fake that answered the probe but left
    either side out is what these tests exist to name.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.context = RunContext(
            topology="aio",
            artifact_root=Path(self.tmp.name),
            budget_seconds=600,
            run_id="podman-subscription-edge-0000",
        )
        self.addCleanup(self.context.run_cleanup)

    def edge_product(self, edge=None):
        product, _ = installed_product(
            self.context,
            host_scripts=[panel_result({"edge": edge_facts() if edge is None else edge})],
        )
        return product

    def reject_edge(self, expected, overrides=None, edge=None):
        product = self.edge_product(edge_facts(overrides) if edge is None else edge)
        with self.assertRaises(AssertionError) as caught:
            aio.case_subscription_edge(product)
        self.assertIn(expected, str(caught.exception))

    def forgery_product(self, edge=None, log=None):
        product, _ = installed_product(
            self.context,
            host_scripts=[
                panel_result({"edge": edge_facts() if edge is None else edge}),
                panel_result(access_log_facts(log)),
            ],
        )
        return product

    def reject_forgery(self, expected, edge=None, log=None):
        product = self.forgery_product(edge, log)
        with self.assertRaises(AssertionError) as caught:
            aio.case_subscription_edge_forgery(product)
        self.assertIn(expected, str(caught.exception))

    @staticmethod
    def mutate_preview(edge, agent, **answer):
        """One crawler's answer, changed after the fact.

        The preview keys are User-Agent strings and hold dots, so they cannot be
        addressed through the dotted merge the other fixtures use.
        """
        edge["previews"][agent] = {**edge["previews"][agent], **answer}
        return edge

    # ------------------------------------------------------------ SUB-EDGE
    def test_edge_case_names_what_the_client_and_the_crawlers_received(self):
        product, podman = installed_product(
            self.context, host_scripts=[panel_result({"edge": edge_facts()})]
        )
        evidence = aio.case_subscription_edge(product)
        self.assertEqual(evidence["served_status"], 200)
        self.assertIn("no-store", evidence["served_cache_control"])
        self.assertEqual(evidence["served_x_robots_tag"], ROBOTS_TAG)
        self.assertEqual(evidence["served_bytes"], 4096)
        self.assertEqual(evidence["foreign_status"], 200)
        self.assertEqual(evidence["absent_status"], 403)
        self.assertEqual(evidence["preview_count"], len(panel_surface.PREVIEW_USER_AGENTS))
        self.assertEqual(evidence["preview_statuses"], "204")
        self.assertEqual(evidence["preview_bytes"], 0)
        self.assertEqual(evidence["panel_requests_added_by_previews"], 0)
        self.assertEqual(evidence["panel_requests_added_by_control"], 1)
        self.assertEqual(
            podman.scripts[0],
            f"python3 {aio.PANEL_SURFACE_SCRIPT} --scope edge-contract "
            f"--edge-base https://{aio.PANEL_DOMAIN} "
            f"--ca {topology.CA_MOUNT}/{topology.ACME_CA_BUNDLE_NAME}",
        )
        for value in evidence.values():
            self.assertIsInstance(
                value, (str, int, float, bool, type(None)),
                "evidence is flattened to strings by the runner, so it must hold primitives",
            )
        self.assertNotIn(SHORT_UUID, json.dumps(evidence))

    def test_edge_case_rejects_a_cachable_subscription(self):
        self.reject_edge("would let a pasted link be cached",
                         {"served.cache_control": "public, max-age=600"})

    def test_edge_case_rejects_a_missing_robots_tag(self):
        self.reject_edge("instead of 'noindex, nofollow, noarchive, nosnippet'",
                         {"served.x_robots_tag": ""})

    def test_edge_case_rejects_bytes_the_panel_did_not_issue(self):
        self.reject_edge("did not hand the client the bytes",
                         {"served_identical_to_loopback": False})

    def test_edge_case_rejects_a_header_that_selects_a_representation(self):
        self.reject_edge("selecting a representation from the header",
                         {"foreign.status": 403})

    def test_edge_case_rejects_a_panel_refusal_that_lost_the_headers(self):
        self.reject_edge("lost the transport headers", {"absent.cache_control": ""})

    def test_edge_case_rejects_an_absent_header_that_was_served(self):
        self.reject_edge("instead of the Panel's own 403", {"absent.status": 200})

    def test_edge_case_rejects_a_crawler_that_was_served_the_payload(self):
        agent = panel_surface.PREVIEW_USER_AGENTS[0]
        self.reject_edge("instead of 204",
                         edge=self.mutate_preview(edge_facts(), agent, status=200))

    def test_edge_case_rejects_an_empty_answer_that_carried_a_body(self):
        agent = panel_surface.PREVIEW_USER_AGENTS[1]
        self.reject_edge("carried a body",
                         edge=self.mutate_preview(edge_facts(), agent, bytes=64))

    def test_edge_case_rejects_an_empty_answer_that_lost_the_robots_tag(self):
        agent = panel_surface.PREVIEW_USER_AGENTS[2]
        self.reject_edge("lost the transport headers",
                         edge=self.mutate_preview(edge_facts(), agent, x_robots_tag=""))

    def test_edge_case_rejects_a_sweep_that_reached_the_panel(self):
        self.reject_edge("the preview sweep reached the Panel", {
            "counters.after.counts.GET /api/sub/{shortUuid}": 8,
        })

    def test_edge_case_rejects_a_control_that_did_not_move_the_counter(self):
        self.reject_edge("moved the Panel's counter by 0", {
            "counters.control.counts.GET /api/sub/{shortUuid}": 7,
        })

    def test_edge_case_rejects_a_counter_read_that_was_refused(self):
        self.reject_edge("route counters answered 500", {"counters.before.status": 500})

    def test_edge_case_rejects_a_panel_without_a_default_client(self):
        self.reject_edge("served no default client", {"short_uuid_length": 0})

    # -------------------------------------------------------- SUB-EDGE-BAD
    def test_forgery_case_names_both_refusals_and_the_access_log(self):
        product, podman = installed_product(
            self.context,
            host_scripts=[panel_result({"edge": edge_facts()}),
                          panel_result(access_log_facts())],
        )
        evidence = aio.case_subscription_edge_forgery(product)
        self.assertEqual(evidence["refused_dot_segment"], "closed")
        self.assertEqual(evidence["refused_encoded_separator"], "closed")
        self.assertEqual(evidence["access_log_lines"], 41)
        self.assertEqual(evidence["access_log_served_lines"], 0)
        self.assertEqual(evidence["access_log_refused_lines"], 2)
        self.assertIn("--scope edge-contract", podman.scripts[0])
        self.assertIn("/var/log/nginx/access.log", podman.scripts[1])
        for value in evidence.values():
            self.assertIsInstance(
                value, (str, int, float, bool, type(None)),
                "evidence is flattened to strings by the runner, so it must hold primitives",
            )
        self.assertNotIn(SHORT_UUID, json.dumps(evidence))

    def test_forgery_case_rejects_a_target_the_listener_answered(self):
        edge = edge_facts()
        edge["refused"]["dot_segment"] = {"status": 444, "closed": False, "bytes": 0}
        self.reject_forgery("instead of a closed connection", edge=edge)

    def test_forgery_case_rejects_a_target_answered_with_bytes(self):
        edge = edge_facts()
        edge["refused"]["encoded_separator"] = {"status": 0, "closed": True, "bytes": 12}
        self.reject_forgery("instead of a closed connection", edge=edge)

    def test_forgery_case_rejects_an_absent_access_log(self):
        self.reject_forgery("absent or empty", log={"present": False})

    def test_forgery_case_rejects_an_empty_access_log(self):
        self.reject_forgery("absent or empty", log={"lines": 0})

    def test_forgery_case_rejects_a_log_that_recorded_a_served_line(self):
        self.reject_forgery("must leave none", log={"served": 1})

    def test_forgery_case_rejects_a_log_that_recorded_no_refusal(self):
        self.reject_forgery("did not record both refused targets",
                            log={"refused_encoded_separator": 0})


class RecordingPodman:
    """Podman stub for the topology wiring: no container is really created."""

    def __init__(self):
        self.artifacts = Path(tempfile.mkdtemp(prefix="gowave-subscription-topology-"))
        self.context = RunContext(topology="aio", artifact_root=self.artifacts, budget_seconds=3600)
        self.networks = []
        self.connects = []
        self.volumes = []
        self.runs = []
        self.builds = []
        self.execs = []
        self.waits = []

    def network_subnets(self):
        return []

    def network_create(self, name, subnet=None, disable_dns=False, internal=False):
        self.networks.append((name, subnet, disable_dns, internal))
        return name

    def network_connect(self, name, network, ip=None):
        self.connects.append((name, network, ip))
        return name

    def volume_create(self, name):
        self.volumes.append(name)
        return name

    def volume_mountpoint(self, name):
        mountpoint = self.context.secret_dir / "volumes" / name
        mountpoint.mkdir(parents=True, exist_ok=True)
        return mountpoint

    def run(self, **kwargs):
        self.runs.append(kwargs)
        return kwargs["name"]

    def build(self, tag, base_alias, containerfile, context_dir=None, build_args=None):
        self.builds.append({
            "tag": tag,
            "base_alias": base_alias,
            "containerfile": Path(containerfile),
            "context_dir": Path(context_dir),
            "build_args": dict(build_args or {}),
        })
        return tag

    def wait_tcp(self, name, host, port, timeout_seconds=60):
        self.waits.append((name, host, port))

    def wait_systemd(self, name, timeout_seconds=90):
        self.waits.append((name, "systemd"))
        return "running"

    def exec(self, name, argv, check=True, input_text=None, timeout=300):
        self.execs.append((name, list(argv)))
        if len(argv) == 3 and argv[2] == target_image.cleanliness_probe():
            return subprocess.CompletedProcess(
                argv, 0, "init=systemd\nsystemd=systemd 255\nsshd=active\n", ""
            )
        return subprocess.CompletedProcess(argv, 0, "{}", "")

    def exec_bash(self, name, script, check=True, input_text=None, timeout=300):
        return subprocess.CompletedProcess(["bash", "-lc", script], 0, "install ok", "")


def run_for(runs, name):
    for kwargs in runs:
        if kwargs["name"] == name:
            return kwargs
    raise AssertionError(f"{name} was not started: {[item['name'] for item in runs]}")


class TestSubscriptionTopology(unittest.TestCase):
    """The payloads travel from the loopback-only Panel to the engine container."""

    def setUp(self):
        self.podman = RecordingPodman()
        self.addCleanup(self.podman.context.run_cleanup)
        self.instance = topology.AioTopology(self.podman, egress_resolvers=["192.0.2.53"])
        patcher = mock.patch.object(acme_fixture.AcmeFixture, "issued_root", return_value=PEM)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(acme_fixture.AcmeFixture, "wait_ready", return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.instance.create()

    def test_the_payload_directory_is_run_scoped_and_private(self):
        self.assertEqual(self.instance.payload_dir.parent, self.podman.context.secret_dir)
        self.assertEqual(self.instance.payload_dir.stat().st_mode & 0o777, 0o700)
        self.assertNotIn(str(self.podman.artifacts), str(self.instance.payload_dir))

    def test_the_host_writes_the_payloads_it_fetched(self):
        target = run_for(self.podman.runs, self.instance.target_name)
        self.assertIn(f"{self.instance.payload_dir}:{topology.PAYLOAD_MOUNT}:Z", target["volumes"])

    def test_the_engine_client_reads_them_and_carries_no_product(self):
        self.instance.engine_client()
        engine = run_for(self.podman.runs, self.instance.engine_client_name)
        self.assertFalse(engine["privileged"])
        self.assertEqual(engine["systemd"], "false")
        self.assertIn(f"{self.instance.payload_dir}:{topology.SECRETS_MOUNT}:ro,Z", engine["volumes"])
        self.assertIn(f"{self.instance.context.secret_dir / 'client-ca'}:{topology.CA_MOUNT}:ro,Z",
                      engine["volumes"])
        extra = engine["extra_args"]
        self.assertEqual(extra[extra.index("--ip") + 1], self.instance.plan.engine_client_ip)
        self.assertEqual(extra[extra.index("--dns") + 1], self.instance.plan.dns_ip)

        built = [item for item in self.podman.builds
                 if item["base_alias"] == client_image.BASE_ALIAS]
        self.assertEqual(len(built), 1)
        self.assertEqual(built[0]["tag"], client_image.tag())
        self.assertIn("XRAY_SHA256", built[0]["build_args"])
        self.assertIn("MIHOMO_SHA256", built[0]["build_args"])

    def test_the_engine_client_is_started_once(self):
        self.instance.engine_client()
        self.instance.engine_client()
        started = [item for item in self.podman.runs
                   if item["name"] == self.instance.engine_client_name]
        self.assertEqual(len(started), 1)
        self.assertEqual(len([item for item in self.podman.builds
                              if item["base_alias"] == client_image.BASE_ALIAS]), 1)

    def test_the_probe_reads_the_mounted_payloads_and_the_issued_root(self):
        self.instance.subscription_facts("share-links")
        name, argv = self.podman.execs[-1]
        self.assertEqual(name, self.instance.engine_client_name)
        self.assertEqual(argv[:2], ["python3", topology.SUBSCRIPTION_PROBE_SCRIPT])
        self.assertEqual(argv[argv.index("--scope") + 1], "share-links")
        self.assertEqual(argv[argv.index("--payload-dir") + 1], topology.SECRETS_MOUNT)
        self.assertEqual(argv[argv.index("--ca") + 1],
                         f"{topology.CA_MOUNT}/{topology.ISSUED_ROOT_NAME}")
        for secret in (SHORT_UUID, CLIENT_UUID, TROJAN_PASSWORD):
            self.assertNotIn(secret, argv)


class TestSubscriptionWiring(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.context = RunContext(
            topology="aio",
            artifact_root=Path(self.tmp.name),
            budget_seconds=600,
            run_id="podman-subscription-wiring-0000",
        )
        self.addCleanup(self.context.run_cleanup)

    def test_suite_declares_the_subscription_cases(self):
        suite = {case.id: case for case in aio.cases(ScriptedPodman(self.context, []))}
        expected = {"SUB-SERVED", "SUB-UA-ABSENT", "SUB-UA-BLANK", "SUB-B64", "SUB-JSON-SHAPES",
                    "SUB-EDGE", "SUB-EDGE-BAD"}
        self.assertTrue(expected.issubset(suite))
        for case_id in expected:
            with self.subTest(case=case_id):
                self.assertIsInstance(suite[case_id], Case)
                self.assertEqual(suite[case_id].topology, "aio")
                self.assertGreater(suite[case_id].timeout_seconds, 0)
                self.assertLessEqual(suite[case_id].timeout_seconds, 600)

    def test_every_subscription_case_is_in_the_shared_catalog(self):
        by_id = {case["id"]: case for case in catalog.load_catalog()["cases"]}
        for case_id in ("SUB-SERVED", "SUB-UA-ABSENT", "SUB-UA-BLANK", "SUB-B64",
                        "SUB-JSON-SHAPES", "SUB-EDGE", "SUB-EDGE-BAD"):
            with self.subTest(case=case_id):
                case = by_id[case_id]
                self.assertEqual(case["runs_in"], ["podman"])
                self.assertEqual(case["state"], "incubating")
                self.assertIn("aio", case["topology"])
                self.assertTrue(case["promotion_target"])

    def test_the_probe_and_the_cases_agree_on_the_representation_inventory(self):
        self.assertEqual(list(aio.REPRESENTATIONS),
                         [name for name, _template, _agent in panel_surface.REPRESENTATIONS])
        self.assertEqual(set(aio.ENGINE_LOADED), set(aio.REPRESENTATIONS) - {"singbox"})
        matrix = yaml.safe_load(
            (REPO_ROOT / "tests" / "cases" / "matrix.yaml").read_text(encoding="utf-8")
        )
        self.assertEqual(matrix["user_agent"]["absent"], aio.UA_REFUSAL_STATUS)
        self.assertEqual(matrix["user_agent"]["blank"], aio.UA_REFUSAL_STATUS)
        self.assertEqual(matrix["product"]["reality_fingerprint"], aio.EXPECTED_FINGERPRINT)
        consumed = {representation for client in matrix["clients"] for representation in client["consumes"]}
        self.assertEqual(sorted(consumed), sorted(aio.ENGINE_LOADED))

    def test_the_probe_scripts_are_valid_python(self):
        for name in ("panel_surface.py", "subscription_probe.py"):
            with self.subTest(script=name):
                source = (REPO_ROOT / "tools" / "podman_e2e" / name).read_text(encoding="utf-8")
                compile(source, name, "exec")


if __name__ == "__main__":
    unittest.main()
