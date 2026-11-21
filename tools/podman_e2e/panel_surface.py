"""Collect Panel API facts on the host under test and print them as JSON.

This script runs inside the disposable AIO host, next to the real Panel, because
the admin API is loopback-only by design. It only collects: every comparison
that turns a fact into an acceptance decision happens in the case driver, so a
defect is reported by the case that owns it rather than by a probe that decided
to be clever.

Nothing secret leaves the host. Credentials are read from the root-only file and
used in memory; the bearer token stays in this process; client and inbound
identifiers are reduced to SHA-256 digests. What is printed is a status, a count,
a boolean, a non-secret protocol/port name, or a digest.

Subscription payloads are secrets — they carry client identifiers, Trojan
passwords, and REALITY public keys — so they are written to the run's 0600
payload directory and never printed: the facts only report a status, a media
type, a byte count, and the transport header.

    python3 /repo/tools/podman_e2e/panel_surface.py --scope surface
    python3 /repo/tools/podman_e2e/panel_surface.py --scope cluster
    python3 /repo/tools/podman_e2e/panel_surface.py --scope subscriptions --payload-dir /payloads
    python3 /repo/tools/podman_e2e/panel_surface.py --scope subscriptions --payload-dir /payloads \
        --edge-base https://panel.testbed.internal --ca /fixtures/ca/acme-trust.pem
    python3 /repo/tools/podman_e2e/panel_surface.py --scope channel --step capture --payload-dir /payloads
    python3 /repo/tools/podman_e2e/panel_surface.py --scope auth-negative
    python3 /repo/tools/podman_e2e/panel_surface.py --scope api-client \
        --edge-base https://panel.testbed.internal --ca /fixtures/ca/acme-trust.pem
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set
from uuid import uuid4

CREDENTIALS_FILE = "/root/gowave-credentials.txt"
PANEL_URL = "http://127.0.0.1:3000"
REQUEST_TIMEOUT_SECONDS = 30
DEFAULT_USER = "default-user"
MVP_SQUAD = "Default MVP Squad"
CLIENT_PREFIX = "podman-e2e-"

# The server-side secrets a subscription must never carry. The Panel's signing
# key is the one that would be catastrophic to leak and the administrator's
# password the one that is already in this host's credentials file; both are
# read only to be compared, never printed. A subscription legitimately carries a
# user's own UUID and Trojan password, so the scan is a value scan, not a
# key-name scan — a key named `password` in a trojan outbound is what a client
# needs, and refusing it would refuse the product's own contract.
#
# The two products name their key differently: the Panel writes `APP_SECRET`
# (sources/gowave/backend-go/config/config.go reads it, modules/panel.sh writes
# it) and the Node writes `SECRET_KEY` (modules/node.sh). An All-in-One host
# carries both files and a subscription must carry neither value, so both files
# are read for both names.
PRODUCT_ENV_FILES = ("/opt/gowave/.env", "/opt/gowave-node/.env")
SERVER_SECRET_KEYS = ("APP_SECRET", "SECRET_KEY")
MIN_SCANNED_SECRET_LENGTH = 8

# The User-Agent strings name the client family that really imports each
# representation. The Panel's pinned policy only requires a non-empty header, but
# a case that sent an anonymous or invented header would not describe a client.
MOBILE_USER_AGENT = "v2rayNG/1.8.5"
XRAY_USER_AGENT = "Xray/26.11.9"
MIHOMO_USER_AGENT = "mihomo/1.19.34"
CLASH_USER_AGENT = "clash.meta/1.19.34"
SINGBOX_USER_AGENT = "sing-box/1.10.0"

# A header that names no client family at all. The Panel's rule is "non-empty
# header", not "a header naming this format", so this is what proves the suite
# encodes no allowlist the product does not have: every representation has to
# answer it with the same bytes it answers the family header.
FOREIGN_USER_AGENT = "curl/8.5.0"

# Every family the shipped vhost classifies as a link preview. The strings are
# the ones those clients send in the wild, because the map is anchored on the
# product name: an invented header would exercise no pattern and prove nothing.
# A real client whose name merely contains one of these words is the risk the
# list is short for, so adding a name here is a decision about who may be served.
PREVIEW_USER_AGENTS: Sequence[str] = (
    "TelegramBot (like TwitterBot)",
    "WhatsApp/2.23.20.0",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
    "Discordbot/2.0",
    "Twitterbot/1.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "Mozilla/5.0 (compatible; Applebot/0.1; +http://www.apple.com/go/applebot)",
    "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
    "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
)
SUBSCRIPTION_PREVIEW_STATUS = 204
# The Panel's own answer to a request with no User-Agent at all. The map's own
# branch is the client branch, so this comes from the product, not the vhost.
SUBSCRIPTION_ABSENT_HEADER_STATUS = 403
# The router patterns the Panel counts its subscription requests under. The base
# path and the per-client path are registered separately, so both are read.
SUBSCRIPTION_ROUTE_PATTERNS: Sequence[str] = (
    "GET /api/sub/{shortUuid}",
    "GET /api/sub/{shortUuid}/{clientType}",
)
# Every header the Panel consults for the client address, in the order it reads
# them (``internal/httpx.ClientIP``): the first non-empty one wins, so these are
# the addresses a client can choose for itself unless the listener replaces or
# removes them. Two are set from ``$remote_addr`` by the shipped vhost; the
# others are emptied there, and this split is what the render test compares the
# vhost with.
PANEL_CLIENT_IP_HEADERS: Sequence[str] = (
    "X-Remnawave-Real-IP",
    "X-Client-IP",
    "X-Forwarded-For",
    "CF-Connecting-IP",
    "Fastly-Client-Ip",
    "True-Client-Ip",
    "X-Real-IP",
    "X-Cluster-Client-IP",
    "X-Forwarded",
    "Forwarded-For",
)
PANEL_FORWARDED_CLIENT_IP_HEADERS: Sequence[str] = ("X-Forwarded-For", "X-Real-IP")
PANEL_CLEARED_CLIENT_IP_HEADERS: Sequence[str] = tuple(
    header for header in PANEL_CLIENT_IP_HEADERS
    if header not in PANEL_FORWARDED_CLIENT_IP_HEADERS
)
# An address no client in a run can hold, so a record that names it can only
# have come from the header that carried it.
FORGED_CLIENT_IP = "203.0.113.9"
# Paths no GoWave Panel route and no dashboard asset can occupy. The list is the
# shipped rule's own set (``modules/nginx.sh``), so probing another path would
# prove nothing about this build.
PANEL_SCANNER_PATHS: Sequence[str] = (
    "/.env",
    "/.git/config",
    "/.DS_Store",
    "/wp-login.php",
    "/wp-admin/",
    "/phpmyadmin/",
    "/server-status",
    "/actuator/health",
)
# The product surfaces the scanner rule must not shadow: a REST route, the
# subscription route, the login route, both inbound transports, the gRPC
# inbound, and the dashboard itself. Each is sent as a plain client would.
PANEL_PRODUCT_ROUTE_PROBES: Sequence[tuple[str, str, str]] = (
    ("rest-api", "/api/nodes", "GET"),
    ("login", "/api/auth/login", "POST"),
    ("web-ui", "/", "GET"),
    ("xhttp-down", "/xhttp-down/health", "GET"),
    ("websocket", "/ws", "GET"),
    ("trojan-grpc", "/trojan-grpc", "POST"),
)
# What a versioned build prints in its own ``Server`` header and in NGINX's
# error pages; ``server_tokens off`` removes the number and keeps the name.
NGINX_VERSION = re.compile(r"(?i)\b(?:nginx|openresty)/\d")

# name, path template, the client that consumes it. The order is the order the
# representation inventory is documented in.
REPRESENTATIONS: Sequence[tuple[str, str, str]] = (
    ("base64", "/api/sub/{short_uuid}", MOBILE_USER_AGENT),
    ("xray-json", "/api/sub/{short_uuid}/v2ray-json", XRAY_USER_AGENT),
    ("mihomo", "/api/sub/{short_uuid}/mihomo", MIHOMO_USER_AGENT),
    ("clash", "/api/sub/{short_uuid}/clash", CLASH_USER_AGENT),
    ("singbox", "/api/sub/{short_uuid}/singbox", SINGBOX_USER_AGENT),
)


def read_credentials(path: Path) -> tuple[str, str]:
    """Read the admin username and password without echoing either one."""
    values: Dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip()] = value.strip()
    missing = [name for name in ("ADMIN_USERNAME", "ADMIN_PASSWORD") if not values.get(name)]
    if missing:
        raise SystemExit(f"credentials file {path} is missing: {', '.join(missing)}")
    return values["ADMIN_USERNAME"], values["ADMIN_PASSWORD"]


def digest(identifiers: Sequence[Any]) -> str:
    """A stable fingerprint of an identifier set, so the set can be compared safely."""
    joined = "\n".join(sorted(str(value) for value in identifiers if value))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest() if joined else ""


IDENTIFIER_LENGTH = 16


def identifier(value: Any) -> str:
    """A short, one-way fingerprint of a single Panel identifier.

    Nodes, profiles, and inbounds are referenced by UUID across different
    payloads, and a case has to know when two references name the same object.
    Printing a digest keeps that comparison possible without writing internal
    identifiers into a report; 16 hex characters tell apart far more objects than
    one cluster holds.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:IDENTIFIER_LENGTH]


def payload(body: Any) -> Any:
    """The Panel wraps every payload in ``response``; some routes answer bare."""
    if isinstance(body, dict) and isinstance(body.get("response"), (dict, list)):
        return body["response"]
    return body


def items(body: Any, key: str) -> List[Any]:
    data = payload(body)
    if isinstance(data, dict):
        value = data.get(key)
        return value if isinstance(value, list) else []
    return data if isinstance(data, list) else []


def inbound_entries(entries: Any) -> List[Dict[str, Any]]:
    """Inbound references appear as objects in some payloads and as ids in others."""
    result: List[Dict[str, Any]] = []
    for entry in entries or []:
        if isinstance(entry, dict):
            result.append(entry)
        elif isinstance(entry, str):
            result.append({"uuid": entry})
    return result


def inbound_spec(entry: Dict[str, Any]) -> Dict[str, Any]:
    """The declaration a node's own applied config has to reproduce.

    Tag, protocol, port, transport, and security layer are read from the same
    template the node loads, so they are the fields a Worker-side config can be
    compared against field by field. ``rawInbound`` is deliberately absent: it
    carries the REALITY key material and the client credentials.
    """
    return {
        "tag": str(entry.get("tag") or ""),
        "type": str(entry.get("type") or ""),
        "port": entry.get("port"),
        "network": str(entry.get("network") or ""),
        "security": str(entry.get("security") or ""),
    }


def node_versions(value: Any) -> Dict[str, Any]:
    """What the node reported about itself, as the Panel stored it.

    The values arrive over the node's own heartbeat, so they are the Panel's
    record of the Worker's self-report rather than a value the Panel computed.
    """
    versions = value if isinstance(value, dict) else {}
    return {
        "node": str(versions.get("node") or ""),
        "xray": str(versions.get("xray") or ""),
        "node_type": str(versions.get("nodeType") or ""),
        "custom_core": versions.get("isCustom") is True,
    }


def node_state(node: Dict[str, Any]) -> Dict[str, Any]:
    """The health flags that say whether the node is serving the latest config."""
    return {
        "disabled": node.get("isDisabled") is True,
        "connecting": node.get("isConnecting") is True,
        "status_message": str(node.get("lastStatusMessage") or ""),
        "last_status_change": str(node.get("lastStatusChange") or ""),
    }


def _decode(raw: str) -> Any:
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"unparsed": True, "body_length": len(raw)}


class Panel:
    """Minimal authenticated client; the token never leaves this object."""

    def __init__(self, base_url: str = PANEL_URL, token: str = "") -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token

    def call(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        authenticated: bool = True,
        timeout: int = REQUEST_TIMEOUT_SECONDS,
    ) -> tuple[int, Any]:
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(self.base_url + path, data=data, method=method)
        request.add_header("Accept", "application/json")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        if authenticated and self.token:
            request.add_header("Authorization", "Bearer " + self.token)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, _decode(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                raw = exc.read().decode("utf-8", "replace")
            finally:
                exc.close()
            return exc.code, _decode(raw)


def login(panel: Panel, username: str, password: str) -> Dict[str, Any]:
    status, body = panel.call(
        "POST", "/api/auth/login", {"username": username, "password": password}, authenticated=False
    )
    nested = payload(body)
    token = ""
    if isinstance(body, dict):
        token = body.get("accessToken") or body.get("token") or ""
    if not token and isinstance(nested, dict):
        token = nested.get("accessToken") or nested.get("token") or ""
    panel.token = str(token)
    return {"status": status, "token_present": bool(token), "token_length": len(str(token))}


def surface(panel: Panel) -> Dict[str, Any]:
    """The authenticated read surface: cluster inventory and the default client."""
    facts: Dict[str, Any] = {}

    anonymous_status, _ = Panel(panel.base_url).call("GET", "/api/nodes", authenticated=False)
    facts["unauthenticated_nodes_status"] = anonymous_status

    status, body = panel.call("GET", "/api/nodes")
    nodes = [node for node in items(body, "nodes") if isinstance(node, dict)]
    node_inbounds: List[Dict[str, Any]] = []
    for node in nodes:
        profile = node.get("configProfile") if isinstance(node.get("configProfile"), dict) else {}
        node_inbounds.extend(inbound_entries(profile.get("activeInbounds")))
    facts["nodes"] = {
        "status": status,
        "count": len(nodes),
        "connected_count": sum(1 for node in nodes if node.get("isConnected") is True),
        "inbound_count": len(node_inbounds),
        "inbound_digest": digest([inbound.get("uuid") for inbound in node_inbounds]),
        "inbound_types": sorted({str(inbound.get("type", "")) for inbound in node_inbounds}),
        "inbound_ports": sorted({str(inbound.get("port", "")) for inbound in node_inbounds}),
        # Which node is which, and whether it is connected: a run with two nodes
        # cannot prove "the Worker is online" from a total count alone.
        "names": sorted(str(node.get("name", "")) for node in nodes),
        "endpoints": sorted(
            f"{node.get('address', '')}:{node.get('port', '')}" for node in nodes
        ),
        "connected": {
            str(node.get("name", "")): node.get("isConnected") is True for node in nodes
        },
    }

    status, body = panel.call("GET", "/api/config-profiles")
    profiles = [profile for profile in items(body, "configProfiles") if isinstance(profile, dict)]
    profile_inbounds = [
        inbound for profile in profiles for inbound in inbound_entries(profile.get("inbounds"))
    ]
    facts["profiles"] = {
        "status": status,
        "count": len(profiles),
        "inbound_count": len(profile_inbounds),
        "inbound_digest": digest([inbound.get("uuid") for inbound in profile_inbounds]),
        "inbound_tags": sorted({str(inbound.get("tag", "")) for inbound in profile_inbounds}),
    }

    status, body = panel.call("GET", "/api/internal-squads")
    squads = [squad for squad in items(body, "internalSquads") if isinstance(squad, dict)]
    mvp = next((squad for squad in squads if squad.get("name") == MVP_SQUAD), None)
    mvp_inbounds = inbound_entries(mvp.get("inbounds")) if mvp else []
    facts["squads"] = {
        "status": status,
        "count": len(squads),
        "mvp_present": mvp is not None,
        "mvp_inbound_count": len(mvp_inbounds),
        "mvp_inbound_digest": digest([inbound.get("uuid") for inbound in mvp_inbounds]),
    }

    status, body = panel.call("GET", "/api/hosts")
    hosts = [host for host in items(body, "hosts") if isinstance(host, dict)]
    host_inbound_ids = []
    for host in hosts:
        inbound = host.get("inbound") if isinstance(host.get("inbound"), dict) else {}
        host_inbound_ids.append(inbound.get("configProfileInboundUuid"))
    facts["hosts"] = {
        "status": status,
        "count": len(hosts),
        "inbound_digest": digest(host_inbound_ids),
        "security_layers": sorted({str(host.get("securityLayer", "")) for host in hosts}),
        "fingerprints": sorted({str(host.get("fingerprint", "")) for host in hosts}),
    }

    status, body = panel.call("GET", f"/api/users/by-username/{DEFAULT_USER}")
    user = payload(body)
    user = user if isinstance(user, dict) else {}
    facts["default_user"] = {
        "status": status,
        "short_uuid_length": len(str(user.get("shortUuid") or "")),
        "status_field": str(user.get("status", "")),
    }

    status, body = panel.call("GET", "/api/tokens")
    tokens = [token for token in items(body, "tokens") if isinstance(token, dict)]
    facts["tokens"] = {
        "status": status,
        "count": len(tokens),
        "name_digest": digest([token.get("name") for token in tokens]),
    }
    return facts


def computed_config(panel: Panel, profile_uuid: str) -> Dict[str, Any]:
    """The profile's computed Xray config, reduced to the shape a case can assert.

    The Panel expands the profile on read, so ``config`` is the object the node
    would run. Only its parseability and its inbound/outbound counts are
    reported: the config carries the client credentials a subscription would.
    """
    status, body = panel.call(
        "GET", f"/api/config-profiles/{profile_uuid}/computed-config"
    )
    profile = payload(body)
    raw = profile.get("config") if isinstance(profile, dict) else None
    config: Optional[Dict[str, Any]] = None
    if isinstance(raw, dict):
        config = raw
    elif isinstance(raw, str):
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError:
            decoded = None
        config = decoded if isinstance(decoded, dict) else None
    facts: Dict[str, Any] = {"status": status, "parsed": config is not None}
    if config is not None:
        inbounds = config.get("inbounds")
        outbounds = config.get("outbounds")
        facts["inbound_count"] = len(inbounds) if isinstance(inbounds, list) else -1
        facts["outbound_count"] = len(outbounds) if isinstance(outbounds, list) else -1
    return facts


def cluster(panel: Panel) -> Dict[str, Any]:
    """The cluster structure: which node owns which profile, inbounds, and hosts.

    The single-node ``surface`` scope counts the inventory; this scope keeps the
    per-object relations a two-node cluster has to prove — a host names exactly
    one node and one of that node's inbounds, a node runs one profile, and the
    profile expands into a config the node could load. Identifiers are reduced to
    digests, so the same object can be recognised across payloads without the
    report carrying it.
    """
    facts: Dict[str, Any] = {}

    status, body = panel.call("GET", "/api/nodes")
    nodes = [node for node in items(body, "nodes") if isinstance(node, dict)]
    node_records: List[Dict[str, Any]] = []
    for node in nodes:
        profile = node.get("configProfile") if isinstance(node.get("configProfile"), dict) else {}
        declared = inbound_entries(profile.get("activeInbounds"))
        inbounds = [
            identifier(inbound.get("uuid"))
            for inbound in declared
        ]
        node_records.append({
            "name": str(node.get("name") or ""),
            "address": str(node.get("address") or ""),
            "port": node.get("port"),
            "connected": node.get("isConnected") is True,
            "uuid": identifier(node.get("uuid")),
            "profile": identifier(profile.get("activeConfigProfileUuid")),
            "inbounds": [value for value in inbounds if value],
            "inbound_specs": [inbound_spec(entry) for entry in declared],
            "state": node_state(node),
            "versions": node_versions(node.get("versions")),
        })
    facts["nodes"] = {"status": status, "records": node_records}

    status, body = panel.call("GET", "/api/config-profiles")
    profiles = [profile for profile in items(body, "configProfiles") if isinstance(profile, dict)]
    profile_records: List[Dict[str, Any]] = []
    for profile in profiles:
        uuid = str(profile.get("uuid") or "")
        inbounds = [
            identifier(inbound.get("uuid"))
            for inbound in inbound_entries(profile.get("inbounds"))
        ]
        profile_records.append({
            "name": str(profile.get("name") or ""),
            "uuid": identifier(uuid),
            "inbounds": [value for value in inbounds if value],
            "computed": computed_config(panel, uuid) if uuid else {"status": 0, "parsed": False},
        })
    facts["profiles"] = {"status": status, "records": profile_records}

    status, body = panel.call("GET", "/api/hosts")
    hosts = [host for host in items(body, "hosts") if isinstance(host, dict)]
    host_records: List[Dict[str, Any]] = []
    for host in hosts:
        inbound = host.get("inbound") if isinstance(host.get("inbound"), dict) else {}
        references = host.get("nodes") if isinstance(host.get("nodes"), list) else []
        nodes_of_host = []
        for reference in references:
            value = reference.get("uuid") if isinstance(reference, dict) else reference
            nodes_of_host.append(identifier(value))
        host_records.append({
            "remark": str(host.get("remark") or ""),
            "address": str(host.get("address") or ""),
            "port": host.get("port"),
            "sni": str(host.get("sni") or ""),
            "fingerprint": str(host.get("fingerprint") or ""),
            "security_layer": str(host.get("securityLayer") or ""),
            "disabled": host.get("isDisabled") is True,
            "profile": identifier(inbound.get("configProfileUuid")),
            "inbound": identifier(inbound.get("configProfileInboundUuid")),
            "nodes": sorted(value for value in nodes_of_host if value),
        })
    facts["hosts"] = {"status": status, "records": host_records}

    status, body = panel.call("GET", "/api/internal-squads")
    squads = [squad for squad in items(body, "internalSquads") if isinstance(squad, dict)]
    mvp = next((squad for squad in squads if squad.get("name") == MVP_SQUAD), None)
    granted = [
        identifier(inbound.get("uuid"))
        for inbound in inbound_entries(mvp.get("inbounds") if mvp else None)
    ]
    facts["squad"] = {
        "status": status,
        "name": MVP_SQUAD,
        "mvp_present": mvp is not None,
        "inbounds": [value for value in granted if value],
    }
    return facts


def default_user_short_uuid(panel: Panel) -> str:
    """The default client's shortUuid, read from the API rather than a file."""
    status, body = panel.call("GET", f"/api/users/by-username/{DEFAULT_USER}")
    user = payload(body)
    user = user if isinstance(user, dict) else {}
    short_uuid = str(user.get("shortUuid") or "")
    if status != 200 or not short_uuid:
        raise SystemExit(
            f"GET /api/users/by-username/{DEFAULT_USER} returned {status} without a shortUuid"
        )
    return short_uuid


def fetch(
    base_url: str,
    path: str,
    user_agent: Optional[str],
    timeout: int = REQUEST_TIMEOUT_SECONDS,
    ca_file: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch one path with an explicit User-Agent, or with no header at all.

    ``urllib`` always adds a default User-Agent, so the absent-header request has
    to be written by hand: it is the only way to observe what the Panel does when
    a client sends no header. A ``user_agent`` of ``""`` sends an explicitly
    blank header, which is a different request from an absent one.

    ``ca_file`` is what lets the same function read the public edge: over HTTPS
    the certificate the fixture ACME directory issued is the only one that
    verifies, so a run cannot pass by trusting a store the product never used.
    """
    return request(base_url, path, user_agent, timeout=timeout, ca_file=ca_file)


def request(
    base_url: str,
    path: str,
    user_agent: Optional[str],
    timeout: int = REQUEST_TIMEOUT_SECONDS,
    ca_file: Optional[str] = None,
    tolerate_closed: bool = False,
    method: str = "GET",
    body: Optional[bytes] = None,
    headers: Sequence[tuple[str, str]] = (),
) -> Dict[str, Any]:
    """Send one request and read the answer, or notice that no answer was sent.

    ``path`` goes on the wire verbatim, which is what makes a traversal or an
    encoded separator observable: a client library that normalised it first
    would send a request the listener can no longer distinguish from a plain
    one. ``tolerate_closed`` is for the refusal that closes the connection
    without a response — a status of ``0`` with ``closed`` set is the honest
    record of it, not an exception in the caller. ``headers`` is how a caller
    carries a header the product reads and a well-behaved client would never
    send, which is the whole point of a forgery.
    """
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme == "https":
        context = ssl.create_default_context(cafile=ca_file or None)
        connection: http.client.HTTPConnection = http.client.HTTPSConnection(
            parsed.hostname, parsed.port or 443, context=context, timeout=timeout,
        )
    else:
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout)
    try:
        connection.putrequest(method, path, skip_accept_encoding=True)
        connection.putheader("Accept", "*/*")
        connection.putheader("Connection", "close")
        if user_agent is not None:
            connection.putheader("User-Agent", user_agent)
        for name, value in headers:
            connection.putheader(name, value)
        if body is not None:
            connection.putheader("Content-Length", str(len(body)))
        connection.endheaders(body)
        try:
            response = connection.getresponse()
            payload_bytes = response.read()
        except (http.client.RemoteDisconnected, http.client.BadStatusLine, ConnectionResetError):
            if not tolerate_closed:
                raise
            return {
                "status": 0,
                "closed": True,
                "server": "",
                "content_type": "",
                "cache_control": "",
                "x_robots_tag": "",
                "body": b"",
            }
        return {
            "status": response.status,
            "closed": False,
            "server": (response.getheader("Server") or ""),
            "content_type": (response.getheader("Content-Type") or ""),
            # What this vantage answered with. Read from both sides on purpose:
            # the Panel process answers none of it and the shipped vhost adds it,
            # so a case that only read the loopback URL would be asserting a
            # header no client ever sees.
            "cache_control": (response.getheader("Cache-Control") or ""),
            "x_robots_tag": (response.getheader("X-Robots-Tag") or ""),
            "body": payload_bytes,
        }
    finally:
        connection.close()


def media_type(value: str) -> str:
    """The bare media type, so parameter noise cannot hide a changed representation."""
    return (value or "").split(";", 1)[0].strip().lower()


def server_secret_values(
    password: str, env_files: Sequence[str] = PRODUCT_ENV_FILES
) -> List[str]:
    """The server-side values a subscription must never carry, read without echoing.

    The Panel's signing key, the Node's key and the administrator's password are
    what a leak would hand an attacker; a client needs none of them. They are
    read here only to be compared, and every fact this module reports about them
    is a count.
    """
    values: List[str] = [password] if password else []
    for env_file in env_files:
        path = Path(env_file)
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            name, separator, value = line.partition("=")
            if not separator or name.strip() not in SERVER_SECRET_KEYS:
                continue
            values.append(value.strip().strip("'\""))
    unique: List[str] = []
    for value in values:
        # A short value matches ordinary prose, so it could not distinguish a
        # leak from a coincidence; the floor is the one the redaction filter uses.
        if len(value) >= MIN_SCANNED_SECRET_LENGTH and value not in unique:
            unique.append(value)
    return unique


def secret_forms(value: str) -> List[bytes]:
    """The encodings a leak could wear: raw, base64, base64url and URL-quoted."""
    raw = value.encode("utf-8", "surrogateescape")
    standard = base64.b64encode(raw)
    url_safe = base64.urlsafe_b64encode(raw)
    forms = [raw, standard, standard.rstrip(b"="), url_safe, url_safe.rstrip(b"=")]
    quoted = urllib.parse.quote(value, safe="")
    if quoted != value:
        forms.append(quoted.encode("utf-8", "surrogateescape"))
    return forms


def scan_payload_for_secrets(payload: bytes, values: Sequence[str]) -> int:
    """How many of the server-side values this payload carries, in any encoding."""
    return sum(1 for value in values if any(form in payload for form in secret_forms(value)))


def decode_subscription_list(payload: bytes) -> bytes:
    """The link list a base64 body stands for, or nothing when it is not one."""
    try:
        text = payload.decode("ascii", "ignore").strip()
        padding = "=" * (-len(text) % 4)
        return base64.b64decode(text + padding, validate=False)
    except (ValueError, TypeError):
        return b""


def write_payload(path: Path, body: bytes) -> None:
    """Write a subscription payload as a 0600 file; it carries client secrets."""
    if not path.parent.is_dir():
        raise SystemExit(f"payload directory {path.parent} does not exist")
    handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "wb") as sink:
        sink.write(body)
    os.chmod(path, 0o600)


def subscriptions(
    panel: Panel,
    payload_dir: Optional[Path],
    edge_base: str = "",
    ca_file: Optional[str] = None,
    secrets_to_scan: Sequence[str] = (),
) -> Dict[str, Any]:
    """Fetch every served representation once and store its payload for the clients.

    Each representation is read twice. The loopback URL is the Panel process, and
    it is what the byte and User-Agent facts describe. ``edge_base`` is the public
    URL the shipped vhost answers on, and the same path is fetched through it with
    the same header, so the transport headers a real client receives are observed
    where a client receives them — the vhost adds ``Cache-Control`` and the Panel
    process does not, so a header read only on loopback would be a claim about a
    response nobody gets.

    ``secrets_to_scan`` are the server-side values this payload must not carry;
    each record reports how many of them it does, never which one or where. The
    base64 body stands for a link list, so its decoded text is scanned as well:
    a secret inside a link would be base64 twice and invisible in the body alone.
    """
    short_uuid = default_user_short_uuid(panel)
    facts: Dict[str, Any] = {
        "short_uuid_length": len(short_uuid),
        "representations": {},
        "secret_needles": len(secrets_to_scan),
    }
    for name, template, user_agent in REPRESENTATIONS:
        path = template.format(short_uuid=short_uuid)
        response = fetch(panel.base_url, path, user_agent)
        body = response["body"]
        # The payload is the Panel's own answer, so it is handed to the clients
        # before the transport read below. A probe that died on the edge used to
        # leave the payload directory empty, and every case that consumes those
        # payloads then reported a missing file as if the Panel had not issued one.
        if payload_dir is not None and response["status"] == 200 and body:
            write_payload(payload_dir / f"{name}.payload", body)
        # The same path again with a header that names no client family. The
        # Panel requires a non-empty header, so this must be served, and with
        # the same bytes: anything else would mean the path selected a
        # representation from the header and the family headers above were
        # carrying the assertion instead of identifying a client.
        foreign = fetch(panel.base_url, path, FOREIGN_USER_AGENT)
        record: Dict[str, Any] = {
            "status": response["status"],
            "content_type": media_type(response["content_type"]),
            "cache_control": response["cache_control"],
            "sha256": hashlib.sha256(body).hexdigest(),
            "bytes": len(body),
            "foreign_status": foreign["status"],
            "foreign_identical": foreign["body"] == body,
            "secret_hits": scan_payload_for_secrets(body, secrets_to_scan),
        }
        if name == "base64":
            record["secret_hits"] += scan_payload_for_secrets(
                decode_subscription_list(body), secrets_to_scan
            )
        if edge_base:
            edge = fetch(edge_base, path, user_agent, ca_file=ca_file)
            record.update({
                "edge_status": edge["status"],
                "edge_cache_control": edge["cache_control"],
                "edge_bytes": len(edge["body"]),
                # The edge has to hand a client the very bytes the Panel issued:
                # a header attached to a different body would describe a response
                # the engine-side probe never consumed.
                "edge_identical": edge["body"] == body,
            })
        facts["representations"][name] = record
        if name == "xray-json":
            # The credentials every engine derives from the same user, reduced to
            # a digest: a repeated install must not rotate them.
            facts["credential_digest"] = subscription_credentials(body)

    # The records the subscription has to agree with. A client dials whatever the
    # Host record it was issued for says, so the address and SNI it is served are
    # read from the same source the Panel hands a client's config — not from the
    # projection the installer posts, which would agree with itself.
    status, body = panel.call("GET", "/api/hosts")
    hosts = [host for host in items(body, "hosts") if isinstance(host, dict)]
    facts["hosts"] = {
        "status": status,
        "records": [
            {
                "remark": str(host.get("remark") or ""),
                "address": str(host.get("address") or ""),
                "port": str(host.get("port") or ""),
                "sni": str(host.get("sni") or ""),
                "path": str(host.get("path") or ""),
                "security_layer": str(host.get("securityLayer") or ""),
                "alpn": str(host.get("alpn") or ""),
                "disabled": host.get("isDisabled") is True,
            }
            for host in hosts
        ],
    }
    return facts


def user_agent_policy(
    panel: Panel,
    user_agent: Optional[str],
    policy: str,
) -> Dict[str, Any]:
    """Ask every representation for an answer while withholding or blanking the header."""
    short_uuid = default_user_short_uuid(panel)
    facts: Dict[str, Any] = {"policy": policy, "representations": {}}
    for name, template, _user_agent in REPRESENTATIONS:
        response = fetch(panel.base_url, template.format(short_uuid=short_uuid), user_agent)
        facts["representations"][name] = response["status"]
    return facts


def subscription_edge_contract(
    panel: Panel,
    edge_base: str,
    ca_file: Optional[str] = None,
) -> Dict[str, Any]:
    """Read the subscription surface the way a link-preview crawler and a client do.

    Three answers are read here and none of them is interchangeable. A client UA
    gets the payload through the public edge, and it has to be the bytes the
    Panel issued. A preview UA gets ``204`` with an empty body and the same
    transport headers, because a pasted link must not unfurl into a working
    subscription. A raw target with a dot segment or an encoded separator gets
    the connection closed, because the rule runs before normalisation and a
    listener that answered it would have proxied a path the Panel never saw.

    The Panel's own route counters bracket the preview sweep: the Panel is the
    process that would have served those requests, and it counts them whether or
    not its request log is enabled. A loopback fetch between the two reads is the
    control — it has to move the counter, or the sweep's silence proves nothing.
    """
    short_uuid = default_user_short_uuid(panel)
    path = f"/api/sub/{short_uuid}"
    loopback = fetch(panel.base_url, path, MOBILE_USER_AGENT)
    served = fetch(edge_base, path, MOBILE_USER_AGENT, ca_file=ca_file)
    foreign = fetch(edge_base, path, FOREIGN_USER_AGENT, ca_file=ca_file)
    absent = fetch(edge_base, path, None, ca_file=ca_file)

    facts: Dict[str, Any] = {
        "short_uuid_length": len(short_uuid),
        "loopback": _answer(loopback),
        "served": _answer(served),
        "served_identical_to_loopback": served["body"] == loopback["body"],
        "foreign": _answer(foreign),
        "foreign_identical": foreign["body"] == loopback["body"],
        "absent": _answer(absent),
        "previews": {},
        "refused": {},
        "counters": {},
    }

    before = http_route_counts(panel)
    for agent in PREVIEW_USER_AGENTS:
        facts["previews"][agent] = _answer(fetch(edge_base, path, agent, ca_file=ca_file))
    after = http_route_counts(panel)
    control = fetch(panel.base_url, path, MOBILE_USER_AGENT)
    facts["counters"] = {
        "before": before,
        "after": after,
        "control": http_route_counts(panel),
        "control_status": control["status"],
    }

    for label, target in (
        ("dot_segment", f"/api/sub/{short_uuid}/../x"),
        ("encoded_separator", f"/api/sub/{short_uuid}%2Fv2ray-json"),
    ):
        refused = request(
            edge_base, target, MOBILE_USER_AGENT, ca_file=ca_file, tolerate_closed=True,
        )
        facts["refused"][label] = {
            "status": refused["status"],
            "closed": refused["closed"],
            "bytes": len(refused["body"]),
        }
    return facts


def _user_record(panel: Panel, short_uuid: str) -> Dict[str, Any]:
    """The client the shortUuid names, read from the API rather than a file."""
    status, body = panel.call("GET", f"/api/users/by-short-uuid/{short_uuid}")
    user = payload(body)
    if status != 200 or not isinstance(user, dict) or not user.get("id"):
        raise SystemExit(
            f"GET /api/users/by-short-uuid/{short_uuid} returned {status} without a numeric id"
        )
    return user


def _subscription_history(panel: Panel, user_id: Any) -> List[Dict[str, Any]]:
    """The Panel's own record of who asked for a subscription, newest first."""
    status, body = panel.call("GET", f"/api/users/{user_id}/subscription-request-history")
    if status != 200:
        raise SystemExit(
            f"GET /api/users/{user_id}/subscription-request-history returned {status}"
        )
    rows = items(body, "records")
    if not rows:
        rows = items(body, "subscriptionRequestHistory")
    return [row for row in rows if isinstance(row, dict)]


def wait_for_new_history_row(
    panel: Panel,
    user_id: Any,
    seen: Set[Any],
    timeout: float = 5.0,
) -> Optional[Dict[str, Any]]:
    """Wait for the row a just-served request added, and name it.

    The Panel answers before its writer has inserted the row, so reading the
    history once right after the response would race the writer and report an
    empty address for a correct listener. The row's identity is what the wait is
    for: a previous row cannot be mistaken for this request's.
    """
    deadline = time.monotonic() + timeout
    result = None
    while time.monotonic() < deadline:
        fresh = [row for row in _subscription_history(panel, user_id) if row.get("id") not in seen]
        if fresh:
            result = max(fresh, key=lambda row: row.get("id") or 0)
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(0.1, remaining))
    return result


def local_source_address(base_url: str) -> str:
    """The source address this process's own request to ``base_url`` will carry.

    The probe runs on the Panel host — it needs the loopback API and the
    credentials file — so its edge request leaves from that host's own address
    rather than from the Control Machine's. Asking the kernel which source a
    connection to the edge would use is what makes "the Panel recorded the peer"
    a comparison against an observed address rather than against an assumed one.
    A connected UDP socket selects the route without sending a packet.
    """
    parsed = urllib.parse.urlsplit(base_url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.settimeout(5)
            probe.connect((host, port))
            return str(probe.getsockname()[0])
    except OSError:
        return ""


def panel_vhost_hygiene(
    panel: Panel,
    edge_base: str,
    ca_file: Optional[str] = None,
) -> Dict[str, Any]:
    """Read the panel vhost through the edge, from a client's side of it.

    Three things are read and none of them is the same question. A version in
    ``Server`` or in an error page is what an operator's scanner sorts hosts by,
    so the answer has to name the software without the build — once from a route
    the Panel answers and once from an error page NGINX writes itself, because
    the two are produced by different code. The address the Panel records for a
    request is the one it will rate-limit, log and notify about, so each header
    the Panel would *prefer* over the socket address is carried by a request
    that would never send it: the record has to name the peer, and the value a
    client chose has to appear nowhere. A path no product route can occupy is
    answered by a closed connection, and every product route is still proxied —
    the second half matters, because a rule that answers everything would pass
    the first one alone.
    """
    short_uuid = default_user_short_uuid(panel)
    user = _user_record(panel, short_uuid)
    facts: Dict[str, Any] = {
        "short_uuid_length": len(short_uuid),
        "server": {},
        "error_page": {},
        "client_ip": {},
        "scanner": {},
        "product_routes": {},
    }

    # A route the Panel answers itself, and a path it has no route for: the
    # second is answered by the Panel's own frontend through the proxy, so it is
    # a second producer of the answer rather than the listener's page — and a
    # path the vhost stopped proxying would come back as NGINX's 404 instead.
    for label, path in (("answered", "/api/system/health"), ("unmatched", "/api/no-such-route")):
        answer = request(edge_base, path, None, ca_file=ca_file)
        facts["server"][label] = {
            "status": answer["status"],
            "server": answer["server"],
        }
    # NGINX's own error page: a request line past the header buffer limit never
    # reaches a route, so whatever the answer says about the build was written by
    # the listener itself.
    oversized = request(
        edge_base, "/" + "a" * 16384, None, ca_file=ca_file, tolerate_closed=True,
    )
    body_text = oversized["body"].decode("utf-8", "replace")
    facts["error_page"] = {
        "status": oversized["status"],
        "server": oversized["server"],
        "version_in_body": bool(NGINX_VERSION.search(body_text)),
        "bytes": len(oversized["body"]),
    }

    # The peer the Panel sees, established by a request that carries no forged
    # header at all. Every later reading is compared with this, so the case does
    # not need to know the address the harness happens to allocate. The rows the
    # Panel already holds are read first: the writer may insert the control's own
    # row before this process manages to ask, and a row that was already there
    # would then be read as this request's. The source address this process's
    # request carries is read from the kernel, because the probe runs on the
    # Panel host and its own address is the peer that request will be recorded
    # under.
    facts["probe_source_ip"] = local_source_address(edge_base)
    seen = {row.get("id") for row in _subscription_history(panel, user["id"])}
    control = request(edge_base, f"/api/sub/{short_uuid}", MOBILE_USER_AGENT, ca_file=ca_file)
    peer = ""
    row = wait_for_new_history_row(panel, user["id"], seen) if control["status"] == 200 else None
    if row is not None:
        peer = str(row.get("requestIp") or "")
        seen.add(row.get("id"))
    facts["peer_recorded_ip"] = peer

    # Every header the Panel reads before the socket address, forged one at a
    # time so a listener that clears all but one is reported by name.
    for header in PANEL_CLIENT_IP_HEADERS:
        answer = request(
            edge_base, f"/api/sub/{short_uuid}", MOBILE_USER_AGENT,
            ca_file=ca_file, headers=((header, FORGED_CLIENT_IP),),
        )
        row = wait_for_new_history_row(panel, user["id"], seen) if answer["status"] == 200 else None
        recorded = ""
        if row is not None:
            recorded = str(row.get("requestIp") or "")
            seen.add(row.get("id"))
        facts["client_ip"][header] = {
            "status": answer["status"],
            "recorded_ip": recorded,
            "forged_was_recorded": recorded == FORGED_CLIENT_IP,
            "recorded_is_peer": bool(recorded) and recorded == peer,
        }

    # A path no route occupies: the answer is a closed connection with no bytes.
    # The control right after it is the same client on a proxied path, so "closed"
    # cannot be the listener refusing everything.
    for path in PANEL_SCANNER_PATHS:
        answer = request(edge_base, path, None, ca_file=ca_file, tolerate_closed=True)
        facts["scanner"][path] = {
            "status": answer["status"],
            "closed": answer["closed"],
            "bytes": len(answer["body"]),
        }
    control_route = request(edge_base, "/api/nodes", None, ca_file=ca_file, tolerate_closed=True)
    facts["scanner_control"] = {
        "status": control_route["status"],
        "closed": control_route["closed"],
    }

    # Every product surface the scanner rule must leave alone. A transport that
    # answers with its own protocol error still proves it was proxied: the rule
    # would have closed the connection instead.
    for label, path, method in PANEL_PRODUCT_ROUTE_PROBES:
        body = b"" if method != "POST" else b"{}"
        extra: List[tuple[str, str]] = []
        if label == "websocket":
            extra = [
                ("Upgrade", "websocket"),
                ("Sec-WebSocket-Version", "13"),
                ("Sec-WebSocket-Key", base64.b64encode(secrets.token_bytes(16)).decode()),
            ]
        elif label == "trojan-grpc":
            extra = [("Content-Type", "application/grpc")]
        answer = request(
            edge_base, path, MOBILE_USER_AGENT, ca_file=ca_file,
            tolerate_closed=True, method=method, body=body, headers=tuple(extra),
        )
        facts["product_routes"][label] = {
            "status": answer["status"],
            "closed": answer["closed"],
            "content_type": media_type(answer["content_type"]),
        }
    subscribed = request(
        edge_base, f"/api/sub/{short_uuid}", MOBILE_USER_AGENT,
        ca_file=ca_file, tolerate_closed=True,
    )
    facts["product_routes"]["subscription"] = {
        "status": subscribed["status"],
        "closed": subscribed["closed"],
        "content_type": media_type(subscribed["content_type"]),
    }
    return facts


def _answer(response: Dict[str, Any]) -> Dict[str, Any]:
    """What one answer is judged on, without the payload a client would keep."""
    return {
        "status": response["status"],
        "content_type": media_type(response["content_type"]),
        "cache_control": response["cache_control"],
        "x_robots_tag": response["x_robots_tag"],
        "bytes": len(response["body"]),
        "sha256": hashlib.sha256(response["body"]).hexdigest(),
    }


def http_route_counts(panel: Panel) -> Dict[str, Any]:
    """The Panel's own per-route counters for the two subscription routes.

    ``GET /api/system/stats/http`` is the product's answer to "how many requests
    did you serve", counted inside the router. It is read instead of a log
    because request logging is off by default, and an assertion about a log the
    product does not write would hold no matter what the listener did.
    """
    status, body = panel.call("GET", "/api/system/stats/http")
    response = payload(body) if isinstance(body, dict) else {}
    routes = (response or {}).get("routes") if isinstance(response, dict) else None
    counts = {pattern: 0 for pattern in SUBSCRIPTION_ROUTE_PATTERNS}
    for entry in routes or []:
        if not isinstance(entry, dict):
            continue
        key = f"{entry.get('method')} {entry.get('route')}"
        if key in counts:
            counts[key] = int(entry.get("count") or 0)
    return {"status": status, "counts": counts}


def lifecycle(panel: Panel) -> Dict[str, Any]:
    """Create, read back, and delete a client through the real API contracts."""
    facts: Dict[str, Any] = {}
    status, body = panel.call("GET", "/api/internal-squads")
    squads = [squad for squad in items(body, "internalSquads") if isinstance(squad, dict)]
    mvp = next((squad for squad in squads if squad.get("name") == MVP_SQUAD), None)
    squad_uuid = str((mvp or {}).get("uuid") or "")

    facts["squad_requested"] = bool(squad_uuid)
    username = f"{CLIENT_PREFIX}{secrets.token_hex(4)}"
    created: Dict[str, Any] = {}
    created_id = ""
    short_uuid = ""

    def cleanup() -> Optional[int]:
        if not created_id:
            return None
        status_code, _ = panel.call("DELETE", f"/api/users/{created_id}")
        return status_code

    try:
        payload_body: Dict[str, Any] = {
            "username": username,
            "status": "ACTIVE",
            "trafficLimitStrategy": "NO_RESET",
            "expireAt": "2099-01-01T00:00:00Z",
        }
        if squad_uuid:
            payload_body["activeInternalSquads"] = [squad_uuid]
        status, body = panel.call("POST", "/api/users", payload_body)
        created = payload(body) if isinstance(body, dict) else {}
        created = created if isinstance(created, dict) else {}
        created_id = str(created.get("id") or created.get("uuid") or "")
        short_uuid = str(created.get("shortUuid") or "")
        facts["create_status"] = status
        facts["created_id_present"] = bool(created_id)
        facts["created_short_uuid_length"] = len(short_uuid)
        facts["created_status_field"] = str(created.get("status", ""))

        status, body = panel.call("GET", f"/api/users/by-username/{username}")
        readback = payload(body)
        readback = readback if isinstance(readback, dict) else {}
        facts["readback_status"] = status
        facts["readback_username_matches"] = readback.get("username") == username
        facts["readback_short_uuid_matches"] = bool(short_uuid) and readback.get("shortUuid") == short_uuid
        facts["readback_squad_count"] = len(readback.get("activeInternalSquads") or [])

        if created_id:
            status, _ = panel.call("GET", f"/api/users/{created_id}")
            facts["get_by_id_status"] = status
    finally:
        facts["delete_status"] = cleanup()

    status, _ = panel.call("GET", f"/api/users/by-username/{username}")
    facts["after_delete_status"] = status
    return facts


# -------------------------------------------------------------- auth negative
# The Panel's gate is three clauses in one function: an HS256 signature over its
# own `APP_SECRET`, an expiry the middleware declares required, and the
# administrator record the claims name. A case that sent one broken token would
# only witness whichever clause the Panel happens to check first, so each
# variant below is a faithful copy of the real token that fails exactly one.
AUTH_EXPIRED_SECONDS = 3600


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def token_claims(token: str) -> Dict[str, Any]:
    """The payload a token carries, read without being trusted.

    The probe signs its own tokens, so it reads the Panel's one to learn which
    administrator the credential names; nothing from it is printed beyond a
    boolean, and no signature is ever taken as valid here.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        value = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _hs256_token(claims: Dict[str, Any], secret: str) -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header}.{body}".encode("ascii")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{header}.{body}.{_b64url(signature)}"


def _unsigned_token(claims: Dict[str, Any]) -> str:
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    return f"{header}.{body}."


def env_value(name: str, path: str | None = None) -> str:
    """One value from a product environment file, read and never echoed."""
    file = Path(path or PRODUCT_ENV_FILES[0])
    if not file.is_file():
        return ""
    for line in file.read_text(encoding="utf-8", errors="replace").splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip() == name:
            return value.strip().strip("'\"")
    return ""


def auth_negative(panel: Panel) -> Dict[str, Any]:
    """The four credentials the Panel must refuse, and the one it must still serve.

    ``expired`` carries the Panel's own signature and dies of its ``exp``,
    ``forged`` carries a future ``exp`` and dies of its signature, ``unsigned``
    declares ``alg: none``, and ``unknown-admin`` is signed and unexpired but
    names an administrator the database does not hold. The real token reads the
    same route before and after, so a Panel that refused everything would fail
    the control rather than pass the refusals.
    """
    facts: Dict[str, Any] = {}
    real = panel.token
    claims = token_claims(real)
    facts["claims_present"] = bool(claims)
    facts["role"] = str(claims.get("role") or "")
    secret = env_value("APP_SECRET")
    facts["signing_key_present"] = len(secret) >= 32
    now = int(time.time())
    faithful = {
        "uuid": str(claims.get("uuid") or ""),
        "username": str(claims.get("username") or ""),
        "role": "ADMIN",
    }
    variants = {
        "expired": _hs256_token(
            {**faithful, "iat": now - 2 * AUTH_EXPIRED_SECONDS, "exp": now - AUTH_EXPIRED_SECONDS},
            secret,
        ),
        "forged": _hs256_token(
            {**faithful, "iat": now, "exp": now + AUTH_EXPIRED_SECONDS},
            secrets.token_urlsafe(32),
        ),
        "unsigned": _unsigned_token(
            {**faithful, "iat": now, "exp": now + AUTH_EXPIRED_SECONDS},
        ),
        "unknown-admin": _hs256_token(
            {**faithful, "uuid": str(uuid4()), "iat": now, "exp": now + AUTH_EXPIRED_SECONDS},
            secret,
        ),
    }
    facts["control_before"] = Panel(panel.base_url, token=real).call("GET", "/api/nodes")[0]
    facts["refusals"] = {}
    for name, token in variants.items():
        status, body = Panel(panel.base_url, token=token).call("GET", "/api/nodes")
        error = payload(body)
        facts["refusals"][name] = {
            "status": status,
            "error": str(error.get("error") or "") if isinstance(error, dict) else "",
        }
    facts["control_after"] = Panel(panel.base_url, token=real).call("GET", "/api/nodes")[0]
    return facts


# ------------------------------------------------------------- Panel API client
# The two files that carry the controller's HTTP contract with the Panel: the
# client the live run drives, and the transport it is built on. A trust bypass
# added to either would make every other check here meaningless, so the probe
# reads them rather than trusting that nobody would.
API_CLIENT_SOURCES = ("tools/live_vps/panel_api.py", "modules/api_client.py")
API_CLIENT_BYPASS_TOKENS = (
    "allowInsecure",
    "verify=False",
    "_create_unverified_context",
    "check_hostname = False",
    "CERT_NONE",
)


def api_client_bypass_tokens(repo_root: Path) -> List[str]:
    """Every trust bypass that appears in the two files carrying the client.

    Read from ``repo_root`` rather than from the module's own location, so the
    caller decides which tree is the subject and a test can point at one that
    holds a bypass.
    """
    return [
        f"{relative}: {token}"
        for relative in API_CLIENT_SOURCES
        for token in API_CLIENT_BYPASS_TOKENS
        if token in (repo_root / relative).read_text(encoding="utf-8")
    ]


def api_client_trust(edge_base: str, ca_file: str, credentials: Path) -> Dict[str, Any]:
    """Drive the controller's own Panel client against the real Panel over HTTPS.

    The subject is ``tools/live_vps/panel_api.py``, so the probe imports that
    class and calls it the way the live controller does instead of re-encoding
    its behaviour: a build that stopped loading the run bundle, that turned
    hostname checking off, or that replaced the configured timeout with a
    literal moves the facts printed here.

    Trust is read from three sides. ``bundle_login`` proves the bundle is
    sufficient; ``empty_store_login`` proves a context with no anchor is not, so
    the success above came from the bundle rather than from an implicit store;
    ``system_store_login`` is reported but not decided here, because an image may
    legitimately point the default store at the run's CA through
    ``SSL_CERT_FILE`` and that is the environment's property, not the client's.
    ``hostname_mismatch_login`` asks the same bundle to accept an address the
    certificate does not name.

    Every value is a status, a count, a class name or a boolean. The username and
    the password are read from the root-only file and never printed; the
    refusals report the exception class, which the client has already reduced to
    "tls verification error" without the hostname or the certificate.
    """
    import sys

    parsed = urllib.parse.urlsplit(edge_base)
    domain = parsed.hostname or ""
    if parsed.scheme != "https" or not domain:
        raise SystemExit(f"--edge-base must be an https URL naming the Panel, got {edge_base!r}")
    # The client is given the authority, not the bare host: an edge base that
    # names a port has to be reached on that port, and dropping it would make
    # every refusal below a connection error instead of a trust decision.
    authority = f"{domain}:{parsed.port}" if parsed.port else domain
    other_address = f"127.0.0.1:{parsed.port}" if parsed.port else "127.0.0.1"
    tools_dir = Path(__file__).resolve().parents[1]
    if str(tools_dir) not in sys.path:
        sys.path.insert(0, str(tools_dir))
    from live_vps.panel_api import E2EPanelClient, configured_api_timeout

    username, password = read_credentials(credentials)
    bundle = ssl.create_default_context(cafile=ca_file)
    facts: Dict[str, Any] = {
        "verify_mode": bundle.verify_mode.name,
        "hostname_verification": bundle.check_hostname,
        "timeout_configured": configured_api_timeout(),
    }

    def refusal(client: Any) -> str:
        """The class of the refusal, or ``accepted`` when the client got through."""
        try:
            client.login(username, password)
            client.get_nodes()
        except Exception as error:  # noqa: BLE001 - the class is the fact
            return type(error).__name__
        return "accepted"

    trusted = E2EPanelClient(authority, bundle)
    facts["timeout_used"] = trusted.timeout
    facts["bundle_login"] = refusal(trusted)
    facts["nodes"] = len(trusted.get_nodes()) if facts["bundle_login"] == "accepted" else 0

    empty = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    facts["empty_store_login"] = refusal(E2EPanelClient(authority, empty))
    facts["hostname_mismatch_login"] = refusal(E2EPanelClient(other_address, bundle))
    facts["system_store_login"] = refusal(
        E2EPanelClient(authority, ssl.create_default_context())
    )

    # A caller that omits every optional argument: it must still construct, and
    # it must inherit the configured bound rather than a second literal.
    default_client = E2EPanelClient(authority)
    facts["production_default_timeout"] = default_client.timeout
    facts["production_default_context"] = default_client.ssl_context is None

    repo_root = Path(__file__).resolve().parents[2]
    facts["bypass_tokens"] = api_client_bypass_tokens(repo_root)
    return facts


# ------------------------------------------------------------------ revocation
REVOKE_DIRECTORY = "revoke"
REVOKE_STATE_NAME = "state.json"
REVOKE_PATCH_LIMIT_BYTES = 10 * 1024 * 1024 * 1024


def subscription_credentials(body: bytes) -> str:
    """A digest of the credentials a subscription payload carries, never the values.

    Revocation rotates the VLESS UUID and the Trojan password, so a digest that
    changes between the captured and the re-fetched subscription is how the case
    shows the Panel's change reached the client without printing a secret.
    """
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ""
    profiles = parsed if isinstance(parsed, list) else [parsed]
    credentials: List[Any] = []
    for profile in profiles:
        if not isinstance(profile, dict):
            continue
        for outbound in profile.get("outbounds") or []:
            settings = outbound.get("settings") if isinstance(outbound, dict) else None
            if not isinstance(settings, dict):
                continue
            for vnext in settings.get("vnext") or []:
                for user in (vnext or {}).get("users") or []:
                    credentials.append(str((user or {}).get("id") or ""))
                    credentials.append(str((user or {}).get("password") or ""))
            for server in settings.get("servers") or []:
                credentials.append(str((server or {}).get("password") or ""))
    return digest(credentials)


def _revocation_dir(payload_dir: Optional[Path]) -> Path:
    if payload_dir is None:
        raise SystemExit("the revoke scope needs --payload-dir: the captured subscription is a secret")
    directory = payload_dir / REVOKE_DIRECTORY
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    return directory


def write_state(path: Path, state: Dict[str, Any]) -> None:
    """Write the hand-off between steps as a 0600 file, next to the payloads."""
    handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "w", encoding="utf-8") as sink:
        json.dump(state, sink, sort_keys=True)
    os.chmod(path, 0o600)


def read_state(path: Path, hint: str = "issue") -> Dict[str, Any]:
    if not path.is_file():
        raise SystemExit(f"the state file {path} is missing: run --step {hint} first")
    state = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(state, dict) or not state.get("user_id"):
        raise SystemExit(f"the state file {path} holds no client id")
    return state


def revoke_issue(panel: Panel, directory: Path) -> Dict[str, Any]:
    """Create a client, capture its subscription, and update a documented field."""
    facts: Dict[str, Any] = {}
    status, body = panel.call("GET", "/api/internal-squads")
    squads = [squad for squad in items(body, "internalSquads") if isinstance(squad, dict)]
    mvp = next((squad for squad in squads if squad.get("name") == MVP_SQUAD), None)
    squad_uuid = str((mvp or {}).get("uuid") or "")
    facts["squad_requested"] = bool(squad_uuid)

    username = f"{CLIENT_PREFIX}revoke-{secrets.token_hex(4)}"
    request: Dict[str, Any] = {
        "username": username,
        "status": "ACTIVE",
        "trafficLimitStrategy": "NO_RESET",
        "expireAt": "2099-01-01T00:00:00Z",
    }
    if squad_uuid:
        request["activeInternalSquads"] = [squad_uuid]
    status, body = panel.call("POST", "/api/users", request)
    created = payload(body)
    created = created if isinstance(created, dict) else {}
    user_id = str(created.get("id") or created.get("uuid") or "")
    short_uuid = str(created.get("shortUuid") or "")
    facts["create_status"] = status
    facts["created_id_present"] = bool(user_id)
    facts["created_short_uuid_length"] = len(short_uuid)
    if not user_id or not short_uuid:
        return facts

    status, _ = panel.call(
        "PATCH", f"/api/users/{user_id}", {"trafficLimitBytes": REVOKE_PATCH_LIMIT_BYTES}
    )
    facts["patch_status"] = status
    status, body = panel.call("GET", f"/api/users/{user_id}")
    readback = payload(body)
    readback = readback if isinstance(readback, dict) else {}
    facts["patch_visible"] = readback.get("trafficLimitBytes") == REVOKE_PATCH_LIMIT_BYTES

    facts["representations"] = {}
    credential_digest = ""
    for name, template, user_agent in REPRESENTATIONS:
        response = fetch(panel.base_url, template.format(short_uuid=short_uuid), user_agent)
        body = response["body"]
        facts["representations"][name] = {
            "status": response["status"],
            "content_type": media_type(response["content_type"]),
            "cache_control": response["cache_control"],
            "bytes": len(body),
        }
        if response["status"] == 200 and body:
            write_payload(directory / f"{name}.payload", body)
            if name == "xray-json":
                credential_digest = subscription_credentials(body)
    facts["credential_digest"] = credential_digest

    write_state(directory / REVOKE_STATE_NAME, {
        "user_id": user_id,
        "username": username,
        "short_uuid": short_uuid,
        "short_uuid_length": len(short_uuid),
        "credential_digest": credential_digest,
    })
    return facts


def revoke_apply(panel: Panel, directory: Path) -> Dict[str, Any]:
    """Revoke the captured access and observe what the Panel and the route now say."""
    state = read_state(directory / REVOKE_STATE_NAME)
    user_id = state["user_id"]
    facts: Dict[str, Any] = {}

    status, body = panel.call("POST", f"/api/users/{user_id}/actions/revoke", {})
    revoked = payload(body)
    revoked = revoked if isinstance(revoked, dict) else {}
    facts["revoke_status"] = status
    facts["revoked_at_present"] = bool(revoked.get("subRevokedAt"))
    facts["short_uuid_length"] = len(str(revoked.get("shortUuid") or ""))
    facts["short_uuid_rotated"] = bool(revoked.get("shortUuid")) and \
        str(revoked.get("shortUuid")) != str(state.get("short_uuid") or "")

    status, body = panel.call("GET", f"/api/users/{user_id}")
    user = payload(body)
    user = user if isinstance(user, dict) else {}
    facts["status_field"] = str(user.get("status", ""))
    facts["readback_status"] = status

    # The payload the engines hold is what a client that never refreshed keeps
    # dialling, so the route it was served from is the one that has to stop
    # answering — not the new one.
    old_short_uuid = str(state.get("short_uuid") or "")
    if old_short_uuid:
        response = fetch(panel.base_url, f"/api/sub/{old_short_uuid}", MOBILE_USER_AGENT)
        facts["old_subscription_status"] = response["status"]

    new_short_uuid = str(user.get("shortUuid") or "")
    facts["new_subscription_status"] = 0
    facts["credential_digest"] = ""
    if new_short_uuid and new_short_uuid != old_short_uuid:
        response = fetch(
            panel.base_url, f"/api/sub/{new_short_uuid}/v2ray-json", XRAY_USER_AGENT
        )
        facts["new_subscription_status"] = response["status"]
        if response["status"] == 200:
            facts["credential_digest"] = subscription_credentials(response["body"])
    facts["credential_digest_changed"] = bool(facts["credential_digest"]) and \
        facts["credential_digest"] != state.get("credential_digest")
    return facts


def revoke_cleanup(panel: Panel, directory: Path) -> Dict[str, Any]:
    """Delete the client the run created, so the next run's inventory stays clean."""
    state = read_state(directory / REVOKE_STATE_NAME)
    facts: Dict[str, Any] = {}
    status, _ = panel.call("DELETE", f"/api/users/{state['user_id']}")
    facts["delete_status"] = status
    status, _ = panel.call("GET", f"/api/users/by-username/{state['username']}")
    facts["after_delete_status"] = status
    return facts


# ------------------------------------------------------------------- restore
RESTORE_DIRECTORY = "backup-restore"
RESTORE_STATE_NAME = "state.json"


def _restore_dir(payload_dir: Optional[Path]) -> Path:
    if payload_dir is None:
        raise SystemExit("the restore scope needs --payload-dir: the state carries a client identity")
    directory = payload_dir / RESTORE_DIRECTORY
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    return directory


def user_inventory(users: Sequence[Dict[str, Any]]) -> str:
    """One digest of the whole client list, so a restore is compared against it by value."""
    return digest(
        f"{user.get('id')}|{user.get('username')}|{user.get('shortUuid')}" for user in users
    )


def representation_digests(
    panel: Panel, short_uuid: str, directory: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    """Fetch every representation the clients consume and digest its body.

    A restore has to hand a client back exactly the payload it held, so the
    comparison is over the served bytes rather than over a count: the digest is
    kept, the payload is written 0600 where the probes expect it, and no value is
    printed.
    """
    facts: Dict[str, Dict[str, Any]] = {}
    for name, template, user_agent in REPRESENTATIONS:
        response = fetch(panel.base_url, template.format(short_uuid=short_uuid), user_agent)
        body = response["body"]
        facts[name] = {
            "status": response["status"],
            "content_type": media_type(response["content_type"]),
            "bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest() if body else "",
        }
        if directory is not None and response["status"] == 200 and body:
            write_payload(directory / f"{name}.payload", body)
    return facts


def restore_capture(panel: Panel, directory: Path) -> Dict[str, Any]:
    """Create a client, capture the Panel's inventory and every representation it is served."""
    facts: Dict[str, Any] = {}
    status, body = panel.call("GET", "/api/internal-squads")
    squads = [squad for squad in items(body, "internalSquads") if isinstance(squad, dict)]
    mvp = next((squad for squad in squads if squad.get("name") == MVP_SQUAD), None)
    squad_uuid = str((mvp or {}).get("uuid") or "")

    username = f"{CLIENT_PREFIX}restore-{secrets.token_hex(4)}"
    request: Dict[str, Any] = {
        "username": username,
        "status": "ACTIVE",
        "trafficLimitStrategy": "NO_RESET",
        "expireAt": "2099-01-01T00:00:00Z",
    }
    if squad_uuid:
        request["activeInternalSquads"] = [squad_uuid]
    status, body = panel.call("POST", "/api/users", request)
    created = payload(body)
    created = created if isinstance(created, dict) else {}
    user_id = str(created.get("id") or created.get("uuid") or "")
    short_uuid = str(created.get("shortUuid") or "")
    facts["create_status"] = status
    facts["created_short_uuid_length"] = len(short_uuid)
    if not user_id or not short_uuid:
        return facts

    status, body = panel.call("GET", f"/api/users/{user_id}")
    readback = payload(body)
    readback = readback if isinstance(readback, dict) else {}
    facts["readback_status"] = status
    facts["readback_username_matches"] = readback.get("username") == username

    # The inventory is the one the archive is about to capture, so it is read with
    # the client in place: a digest taken before the client existed could never be
    # reproduced by a restore of an archive that contains it.
    status, body = panel.call("GET", "/api/users")
    users = [user for user in items(body, "users") if isinstance(user, dict)]
    inventory = user_inventory(users)
    facts["inventory_status"] = status
    facts["users_in_archive"] = len(users)

    representations = representation_digests(panel, short_uuid, directory)
    facts["representations"] = {
        name: {"status": entry["status"], "bytes": entry["bytes"]}
        for name, entry in representations.items()
    }
    write_state(directory / RESTORE_STATE_NAME, {
        "user_id": user_id,
        "username": username,
        "short_uuid": short_uuid,
        "squad_uuid": squad_uuid,
        "inventory": inventory,
        "users_in_archive": len(users),
        "representations": representations,
    })
    return facts


def restore_mutate(panel: Panel, directory: Path) -> Dict[str, Any]:
    """Delete the captured client through the API so a restore has something to undo."""
    state = read_state(directory / RESTORE_STATE_NAME, "capture")
    user_id = state["user_id"]
    facts: Dict[str, Any] = {}

    status, _ = panel.call("DELETE", f"/api/users/{user_id}")
    facts["delete_status"] = status
    status, _ = panel.call("GET", f"/api/users/{user_id}")
    facts["after_delete_readback_status"] = status

    status, body = panel.call("GET", "/api/users")
    users = [user for user in items(body, "users") if isinstance(user, dict)]
    facts["users_after_delete"] = len(users)
    facts["user_present_after_delete"] = any(
        str(user.get("id") or "") == user_id for user in users
    )

    short_uuid = str(state.get("short_uuid") or "")
    response = fetch(panel.base_url, f"/api/sub/{short_uuid}", MOBILE_USER_AGENT)
    facts["subscription_after_delete_status"] = response["status"]
    return facts


def restore_verify(panel: Panel, directory: Path) -> Dict[str, Any]:
    """After the restore, the client and the bytes it was served have to be back."""
    state = read_state(directory / RESTORE_STATE_NAME, "capture")
    user_id = state["user_id"]
    facts: Dict[str, Any] = {}

    status, body = panel.call("GET", f"/api/users/{user_id}")
    user = payload(body)
    user = user if isinstance(user, dict) else {}
    facts["readback_status"] = status
    facts["username_restored"] = user.get("username") == state["username"]
    facts["short_uuid_restored"] = str(user.get("shortUuid") or "") == str(state["short_uuid"])

    status, body = panel.call("GET", "/api/users")
    users = [user for user in items(body, "users") if isinstance(user, dict)]
    facts["users_restored"] = len(users)
    facts["inventory_restored"] = user_inventory(users) == state.get("inventory")
    facts["user_present_after_restore"] = any(
        str(user.get("id") or "") == user_id for user in users
    )

    short_uuid = str(state.get("short_uuid") or "")
    captured = state.get("representations") or {}
    representations = representation_digests(panel, short_uuid, None)
    facts["representations"] = {
        name: {"status": entry["status"], "bytes": entry["bytes"]}
        for name, entry in representations.items()
    }
    facts["representations_identical"] = {
        name: bool(captured.get(name))
        and entry["status"] == captured[name]["status"]
        and entry["sha256"] == captured[name]["sha256"]
        for name, entry in representations.items()
    }
    return facts


# ------------------------------------------------------------------ channel
CHANNEL_DIRECTORY = "channel"
CHANNEL_STATE_NAME = "state.json"


def _channel_dir(payload_dir: Optional[Path]) -> Path:
    if payload_dir is None:
        raise SystemExit("the channel scope needs --payload-dir: the captured payloads are secrets")
    directory = payload_dir / CHANNEL_DIRECTORY
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    return directory


def channel_capture(panel: Panel, directory: Path) -> Dict[str, Any]:
    """Capture the client surface a channel switch or a rollback has to leave alone.

    The switch itself ships as a label plus a restart, and the rollback restores
    the database the Panel serves. Neither is allowed to take a client away or
    hand it different bytes, so what is captured is the digest of the whole
    client list together with the digest of every representation the default
    client is served. The database is compared through this surface rather than by
    its file bytes: the Panel keeps writing to SQLite while it runs, so the served
    content is the stable statement about what the switch did.
    """
    facts: Dict[str, Any] = {}
    status, body = panel.call("GET", f"/api/users/by-username/{DEFAULT_USER}")
    user = payload(body)
    user = user if isinstance(user, dict) else {}
    user_id = str(user.get("id") or user.get("uuid") or "")
    short_uuid = str(user.get("shortUuid") or "")
    facts["readback_status"] = status
    facts["short_uuid_length"] = len(short_uuid)
    if not user_id or not short_uuid:
        return facts

    status, body = panel.call("GET", "/api/users")
    users = [entry for entry in items(body, "users") if isinstance(entry, dict)]
    facts["inventory_status"] = status
    facts["users"] = len(users)
    representations = representation_digests(panel, short_uuid, directory)
    facts["representations"] = {
        name: {"status": entry["status"], "bytes": entry["bytes"]}
        for name, entry in representations.items()
    }
    write_state(directory / CHANNEL_STATE_NAME, {
        "user_id": user_id,
        "short_uuid": short_uuid,
        "inventory": user_inventory(users),
        "users": len(users),
        "representations": representations,
    })
    return facts


def channel_verify(panel: Panel, directory: Path) -> Dict[str, Any]:
    """Compare the client surface against the capture taken before the switch."""
    state = read_state(directory / CHANNEL_STATE_NAME, "capture")
    facts: Dict[str, Any] = {}

    status, body = panel.call("GET", "/api/users")
    users = [entry for entry in items(body, "users") if isinstance(entry, dict)]
    facts["inventory_status"] = status
    facts["users"] = len(users)
    facts["users_captured"] = state.get("users")
    facts["inventory_identical"] = user_inventory(users) == state.get("inventory")
    facts["user_present"] = any(
        str(entry.get("id") or entry.get("uuid") or "") == state["user_id"] for entry in users
    )

    captured = state.get("representations") or {}
    representations = representation_digests(panel, str(state.get("short_uuid") or ""), None)
    facts["representations"] = {
        name: {"status": entry["status"], "bytes": entry["bytes"]}
        for name, entry in representations.items()
    }
    facts["representations_identical"] = {
        name: bool(captured.get(name))
        and entry["status"] == captured[name]["status"]
        and entry["sha256"] == captured[name]["sha256"]
        for name, entry in representations.items()
    }
    return facts


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Collect Panel API facts without leaking secrets")
    parser.add_argument(
        "--scope",
        choices=(
            "surface", "cluster", "lifecycle", "subscriptions",
            "ua-absent", "ua-blank", "edge-contract", "vhost-hygiene", "revoke", "restore", "channel",
            "auth-negative", "api-client", "all",
        ),
        default="all",
    )
    parser.add_argument("--panel-url", default=PANEL_URL)
    parser.add_argument("--credentials", default=CREDENTIALS_FILE)
    parser.add_argument(
        "--step",
        choices=("issue", "apply", "cleanup", "capture", "mutate", "verify"),
        help="Which revocation or restore step to run; each step hands its state to the next one",
    )
    parser.add_argument(
        "--payload-dir",
        default="",
        help="Directory the subscription payloads are written to (0600); never printed",
    )
    parser.add_argument(
        "--edge-base",
        default="",
        help=(
            "Public base URL the shipped vhost answers on, e.g. "
            "https://panel.testbed.internal. The same paths are fetched through it "
            "so transport headers are read where a client reads them."
        ),
    )
    parser.add_argument(
        "--ca",
        default="",
        help="CA bundle the edge certificate chains to; over HTTPS no other store is trusted",
    )
    args = parser.parse_args(argv)

    if args.scope == "api-client":
        # This scope asks about the controller's HTTPS client, which builds its
        # own contexts and reads the same credentials file, so the loopback
        # ``login`` fact every other scope starts with would be a second subject
        # answering for the first one's trust.
        facts: Dict[str, Any] = {
            "api_client": api_client_trust(args.edge_base, args.ca, Path(args.credentials)),
        }
        print(json.dumps(facts, sort_keys=True))
        return 0

    username, password = read_credentials(Path(args.credentials))
    panel = Panel(args.panel_url)
    facts = {"login": login(panel, username, password)}
    if args.scope in ("surface", "all"):
        facts["surface"] = surface(panel)
    if args.scope == "cluster":
        facts["cluster"] = cluster(panel)
    if args.scope in ("lifecycle", "all"):
        facts["lifecycle"] = lifecycle(panel)
    if args.scope in ("subscriptions", "all"):
        payload_dir = Path(args.payload_dir) if args.payload_dir else None
        facts["subscriptions"] = subscriptions(
            panel, payload_dir, edge_base=args.edge_base, ca_file=args.ca or None,
            secrets_to_scan=server_secret_values(password),
        )
    if args.scope == "ua-absent":
        facts["policy"] = user_agent_policy(panel, None, "absent")
    if args.scope == "ua-blank":
        facts["policy"] = user_agent_policy(panel, "", "blank")
    if args.scope == "edge-contract":
        if not args.edge_base:
            raise SystemExit("the edge-contract scope reads the shipped vhost and needs --edge-base")
        facts["edge"] = subscription_edge_contract(panel, args.edge_base, ca_file=args.ca or None)
    if args.scope == "vhost-hygiene":
        if not args.edge_base:
            raise SystemExit("the vhost-hygiene scope reads the shipped vhost and needs --edge-base")
        facts["hygiene"] = panel_vhost_hygiene(panel, args.edge_base, ca_file=args.ca or None)
    if args.scope == "revoke":
        directory = _revocation_dir(Path(args.payload_dir) if args.payload_dir else None)
        steps = {
            "issue": revoke_issue,
            "apply": revoke_apply,
            "cleanup": revoke_cleanup,
        }
        if args.step not in steps:
            raise SystemExit("the revoke scope needs --step issue, --step apply, or --step cleanup")
        facts["revocation"] = steps[args.step](panel, directory)
    if args.scope == "restore":
        directory = _restore_dir(Path(args.payload_dir) if args.payload_dir else None)
        steps = {
            "capture": restore_capture,
            "mutate": restore_mutate,
            "verify": restore_verify,
        }
        if args.step not in steps:
            raise SystemExit(
                "the restore scope needs --step capture, --step mutate, or --step verify"
            )
        facts["restore"] = steps[args.step](panel, directory)
    if args.scope == "channel":
        directory = _channel_dir(Path(args.payload_dir) if args.payload_dir else None)
        steps = {"capture": channel_capture, "verify": channel_verify}
        if args.step not in steps:
            raise SystemExit("the channel scope needs --step capture or --step verify")
        facts["channel"] = steps[args.step](panel, directory)
    if args.scope == "auth-negative":
        facts["auth_negative"] = auth_negative(panel)
    print(json.dumps(facts, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
