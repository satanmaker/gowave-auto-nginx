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
type, and a byte count.

    python3 /repo/tools/podman_e2e/panel_surface.py --scope surface
    python3 /repo/tools/podman_e2e/panel_surface.py --scope cluster
    python3 /repo/tools/podman_e2e/panel_surface.py --scope subscriptions --payload-dir /payloads
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import secrets
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

CREDENTIALS_FILE = "/root/gowave-credentials.txt"
PANEL_URL = "http://127.0.0.1:3000"
REQUEST_TIMEOUT_SECONDS = 30
DEFAULT_USER = "default-user"
MVP_SQUAD = "Default MVP Squad"
CLIENT_PREFIX = "podman-e2e-"

# The User-Agent strings name the client family that really imports each
# representation. The Panel's pinned policy only requires a non-empty header, but
# a case that sent an anonymous or invented header would not describe a client.
MOBILE_USER_AGENT = "v2rayNG/1.8.5"
XRAY_USER_AGENT = "Xray/26.11.9"
MIHOMO_USER_AGENT = "mihomo/1.19.34"
CLASH_USER_AGENT = "clash.meta/1.19.34"
SINGBOX_USER_AGENT = "sing-box/1.10.0"

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
        inbounds = [
            identifier(inbound.get("uuid"))
            for inbound in inbound_entries(profile.get("activeInbounds"))
        ]
        node_records.append({
            "name": str(node.get("name") or ""),
            "address": str(node.get("address") or ""),
            "port": node.get("port"),
            "connected": node.get("isConnected") is True,
            "uuid": identifier(node.get("uuid")),
            "profile": identifier(profile.get("activeConfigProfileUuid")),
            "inbounds": [value for value in inbounds if value],
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
) -> Dict[str, Any]:
    """Fetch one path with an explicit User-Agent, or with no header at all.

    ``urllib`` always adds a default User-Agent, so the absent-header request has
    to be written by hand: it is the only way to observe what the Panel does when
    a client sends no header. A ``user_agent`` of ``""`` sends an explicitly
    blank header, which is a different request from an absent one.
    """
    parsed = urllib.parse.urlsplit(base_url)
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout)
    try:
        connection.putrequest("GET", path, skip_accept_encoding=True)
        connection.putheader("Accept", "*/*")
        connection.putheader("Connection", "close")
        if user_agent is not None:
            connection.putheader("User-Agent", user_agent)
        connection.endheaders()
        response = connection.getresponse()
        body = response.read()
        return {
            "status": response.status,
            "content_type": (response.getheader("Content-Type") or ""),
            "body": body,
        }
    finally:
        connection.close()


def media_type(value: str) -> str:
    """The bare media type, so parameter noise cannot hide a changed representation."""
    return (value or "").split(";", 1)[0].strip().lower()


def write_payload(path: Path, body: bytes) -> None:
    """Write a subscription payload as a 0600 file; it carries client secrets."""
    if not path.parent.is_dir():
        raise SystemExit(f"payload directory {path.parent} does not exist")
    handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "wb") as sink:
        sink.write(body)
    os.chmod(path, 0o600)


def subscriptions(panel: Panel, payload_dir: Optional[Path]) -> Dict[str, Any]:
    """Fetch every served representation once and store its payload for the clients."""
    short_uuid = default_user_short_uuid(panel)
    facts: Dict[str, Any] = {"short_uuid_length": len(short_uuid), "representations": {}}
    for name, template, user_agent in REPRESENTATIONS:
        response = fetch(panel.base_url, template.format(short_uuid=short_uuid), user_agent)
        body = response["body"]
        facts["representations"][name] = {
            "status": response["status"],
            "content_type": media_type(response["content_type"]),
            "bytes": len(body),
        }
        if name == "xray-json":
            # The credentials every engine derives from the same user, reduced to
            # a digest: a repeated install must not rotate them.
            facts["credential_digest"] = subscription_credentials(body)
        if payload_dir is not None and response["status"] == 200 and body:
            write_payload(payload_dir / f"{name}.payload", body)
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


def read_state(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        raise SystemExit(f"the revocation state file {path} is missing: run --step issue first")
    state = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(state, dict) or not state.get("user_id"):
        raise SystemExit(f"the revocation state file {path} holds no client id")
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


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Collect Panel API facts without leaking secrets")
    parser.add_argument(
        "--scope",
        choices=(
            "surface", "cluster", "lifecycle", "subscriptions",
            "ua-absent", "ua-blank", "revoke", "all",
        ),
        default="all",
    )
    parser.add_argument("--panel-url", default=PANEL_URL)
    parser.add_argument("--credentials", default=CREDENTIALS_FILE)
    parser.add_argument(
        "--step",
        choices=("issue", "apply", "cleanup"),
        help="Which revocation step to run; each step hands its state to the next one",
    )
    parser.add_argument(
        "--payload-dir",
        default="",
        help="Directory the subscription payloads are written to (0600); never printed",
    )
    args = parser.parse_args(argv)

    username, password = read_credentials(Path(args.credentials))
    panel = Panel(args.panel_url)
    facts: Dict[str, Any] = {"login": login(panel, username, password)}
    if args.scope in ("surface", "all"):
        facts["surface"] = surface(panel)
    if args.scope == "cluster":
        facts["cluster"] = cluster(panel)
    if args.scope in ("lifecycle", "all"):
        facts["lifecycle"] = lifecycle(panel)
    if args.scope in ("subscriptions", "all"):
        payload_dir = Path(args.payload_dir) if args.payload_dir else None
        facts["subscriptions"] = subscriptions(panel, payload_dir)
    if args.scope == "ua-absent":
        facts["policy"] = user_agent_policy(panel, None, "absent")
    if args.scope == "ua-blank":
        facts["policy"] = user_agent_policy(panel, "", "blank")
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
    print(json.dumps(facts, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
