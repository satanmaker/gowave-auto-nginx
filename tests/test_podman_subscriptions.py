#!/usr/bin/env python3
"""Suite nonroot: subscription delivery is proven by the clients that consume it."""
import base64
import io
import json
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
        "remarks": outbound["tag"],
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
  - name: REALITY
    type: vless
    server: panel.testbed.internal
    network: tcp
    tls: true
    servername: reality.testbed.internal
    reality-opts:
      public-key: Cb8_gedNWrtQ3bHsW8WBb1NugpsXIw-Tu-mu_Eyevjg
      short-id: 654854cb2af21ceb
    client-fingerprint: firefox
  - name: XHTTP
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
  - name: WS
    type: vless
    server: panel.testbed.internal
    network: ws
    tls: true
    alpn:
      - http/1.1
    ws-opts:
      path: /ws
      headers: {}
  - name: TROJAN
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
      - REALITY
      - XHTTP
      - WS
      - TROJAN
rules:
  - MATCH,GoWave
"""
SINGBOX_BODY = json.dumps({"outbounds": [
    {"type": "vless", "tag": "reality"},
    {"type": "vless", "tag": "xhttp"},
    {"type": "trojan", "tag": "trojan"},
    {"type": "direct", "tag": "direct"},
]})
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


def served_facts(overrides=None):
    return merge({
        "short_uuid_length": len(SHORT_UUID),
        "representations": {
            "base64": {"status": 200, "content_type": "text/plain", "bytes": len(BASE64_BODY)},
            "xray-json": {"status": 200, "content_type": "application/json", "bytes": len(JSON_BODY)},
            "mihomo": {"status": 200, "content_type": "text/yaml", "bytes": len(MIHOMO_YAML)},
            "clash": {"status": 200, "content_type": "text/yaml", "bytes": len(MIHOMO_YAML)},
            "singbox": {"status": 200, "content_type": "application/json", "bytes": len(SINGBOX_BODY)},
        },
    }, overrides)


def engine_representations(overrides=None):
    engine = {
        "base64": {"decoded": True, "decoded_bytes": 812, "link_count": 4,
                   "schemes": ["trojan", "vless"]},
        "xray_json": {"shape": "list", "entries": 4, "wrapped": 0, "protocols": ["trojan", "vless"]},
        "mihomo": {"proxies": 4, "proxy_types": ["trojan", "vless"], "groups": 1, "rules": 1,
                   "match_rule": True, "exit": 0,
                   "proxy_details": [
                       {"name": "REALITY", "type": "vless", "server": "panel.testbed.internal",
                        "network": "tcp", "tls": "true",
                        "servername": "reality.testbed.internal"},
                       {"name": "XHTTP", "type": "vless", "server": "panel.testbed.internal",
                        "network": "xhttp", "tls": "true"},
                       {"name": "WS", "type": "vless", "server": "panel.testbed.internal",
                        "network": "ws", "tls": "true"},
                       {"name": "TROJAN", "type": "trojan", "server": "panel.testbed.internal",
                        "network": "tcp", "tls": "true"},
                   ]},
        "clash": {"proxies": 1, "proxy_types": ["trojan"], "groups": 1, "rules": 1,
                  "match_rule": True, "exit": 0},
        "singbox": {"parsed": True, "outbounds": 4},
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


class StubPanel:
    """A Panel that answers the default-client lookup and every representation."""

    def __init__(self):
        self.password = "pw-do-not-print"
        self.token = "token-do-not-print"
        self.user = {"username": "default-user", "shortUuid": SHORT_UUID}
        self.statuses = {}
        self.requests = []
        self.enforce_user_agent = False
        directory = Path(tempfile.mkdtemp(prefix="gowave-subscription-panel-"))
        self.credentials = directory / "credentials"
        self.credentials.write_text(
            f"ADMIN_USERNAME=admin\nADMIN_PASSWORD={self.password}\n", encoding="utf-8"
        )
        self.credentials.chmod(0o600)
        self.server = self._start()

    def _start(self):
        panel = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, body, content_type="application/json"):
                raw = body.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                agent = self.headers.get("User-Agent")
                panel.requests.append((self.path, agent))
                if self.path == "/api/users/by-username/default-user":
                    return self._send(200, json.dumps({"response": panel.user}))
                name = panel.representation(self.path)
                if name is None:
                    return self._send(404, json.dumps({"message": "not found"}))
                if panel.enforce_user_agent and (agent is None or not agent.strip()):
                    return self._send(403, "forbidden", "text/plain")
                status = panel.statuses.get(name, 200)
                body, content_type = BODIES[name]
                return self._send(status, body if status == 200 else "", content_type)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
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


def probe_output(panel, scope, payload_dir=""):
    stdout = io.StringIO()
    argv = [
        "--scope", scope,
        "--panel-url", panel.url,
        "--credentials", str(panel.credentials),
    ]
    if payload_dir:
        argv.extend(["--payload-dir", payload_dir])
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
        agents = {path: agent for path, agent in self.panel.requests if "/api/sub/" in path}
        self.assertEqual(agents[f"/api/sub/{SHORT_UUID}"], panel_surface.MOBILE_USER_AGENT)
        self.assertEqual(agents[f"/api/sub/{SHORT_UUID}/v2ray-json"], panel_surface.XRAY_USER_AGENT)
        self.assertEqual(agents[f"/api/sub/{SHORT_UUID}/mihomo"], panel_surface.MIHOMO_USER_AGENT)
        self.assertEqual(agents[f"/api/sub/{SHORT_UUID}/clash"], panel_surface.CLASH_USER_AGENT)
        self.assertEqual(agents[f"/api/sub/{SHORT_UUID}/singbox"], panel_surface.SINGBOX_USER_AGENT)

    def test_an_absent_user_agent_is_a_request_without_the_header(self):
        response = panel_surface.fetch(self.panel.url, f"/api/sub/{SHORT_UUID}", None)
        self.assertEqual(response["status"], 200)
        self.assertIsNone(self.panel.requests[-1][1])

    def test_a_blank_user_agent_is_an_empty_header_not_a_missing_one(self):
        response = panel_surface.fetch(self.panel.url, f"/api/sub/{SHORT_UUID}", "")
        self.assertEqual(response["status"], 200)
        self.assertEqual(self.panel.requests[-1][1], "")

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

    def test_the_representation_inventory_matches_the_pinned_matrix(self):
        matrix = yaml.safe_load(
            (REPO_ROOT / "tests" / "cases" / "matrix.yaml").read_text(encoding="utf-8")
        )
        self.assertEqual(sorted(matrix["representations"]), sorted(aio.REPRESENTATIONS))
        for name, template, _agent in panel_surface.REPRESENTATIONS:
            self.assertEqual(
                matrix["representations"][name].replace("{shortUuid}", "{short_uuid}"), template
            )


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
                          "protocols": ["trojan", "vless"]})
        for name in ("mihomo", "clash"):
            self.assertEqual(facts[name]["exit"], 0)
            self.assertEqual(facts[name]["proxies"], 4)
            self.assertTrue(facts[name]["match_rule"])
        self.assertEqual(facts["singbox"], {"parsed": True, "outbounds": 4})
        self.assertEqual([path.name for path in self.workdir.iterdir()
                          if path.suffix in (".json", ".yaml")], [])
        self.assertEqual(set(self.engines.modes), {0o600})
        self.assertEqual(len(self.engines.configs), 4)

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
        self.results = list(scripts)

    def exec_bash(self, name, script, check=True, input_text=None, timeout=300):
        self.scripts.append(script)
        stdout, returncode = self.results.pop(0)
        return subprocess.CompletedProcess(["bash", "-lc", script], returncode, stdout, "")


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
                         f"--payload-dir {topology.PAYLOAD_MOUNT}")
        self.assertEqual(product.host.scopes, ["representations"])
        for value in evidence.values():
            self.assertIsInstance(
                value, (str, int, float, bool, type(None)),
                "evidence is flattened to strings by the runner, so it must hold primitives",
            )

    def test_subscriptions_case_rejects_a_representation_that_is_not_served(self):
        self.reject("instead of 200", served=served_facts({"representations.clash.status": 500}))

    def test_subscriptions_case_rejects_an_empty_representation(self):
        self.reject("is empty", served=served_facts({"representations.singbox.bytes": 0}))

    def test_subscriptions_case_rejects_a_missing_media_type(self):
        self.reject("without a media type",
                    served=served_facts({"representations.mihomo.content_type": ""}))

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
        self.reject("no MATCH rule", engine=engine_representations({"clash.match_rule": False}))

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


class RecordingPodman:
    """Podman stub for the topology wiring: no container is really created."""

    def __init__(self):
        self.artifacts = Path(tempfile.mkdtemp(prefix="gowave-subscription-topology-"))
        self.context = RunContext(topology="aio", artifact_root=self.artifacts, budget_seconds=3600)
        self.networks = []
        self.connects = []
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

    def test_suite_declares_the_five_subscription_cases(self):
        suite = {case.id: case for case in aio.cases(ScriptedPodman(self.context, []))}
        expected = {"SUB-SERVED", "SUB-UA-ABSENT", "SUB-UA-BLANK", "SUB-B64", "SUB-JSON-SHAPES"}
        self.assertTrue(expected.issubset(suite))
        for case_id in expected:
            with self.subTest(case=case_id):
                self.assertIsInstance(suite[case_id], Case)
                self.assertEqual(suite[case_id].topology, "aio")
                self.assertGreater(suite[case_id].timeout_seconds, 0)
                self.assertLessEqual(suite[case_id].timeout_seconds, 600)

    def test_every_subscription_case_is_in_the_shared_catalog(self):
        by_id = {case["id"]: case for case in catalog.load_catalog()["cases"]}
        for case_id in ("SUB-SERVED", "SUB-UA-ABSENT", "SUB-UA-BLANK", "SUB-B64", "SUB-JSON-SHAPES"):
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
