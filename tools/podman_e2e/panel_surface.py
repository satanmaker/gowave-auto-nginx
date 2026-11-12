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

    python3 /repo/tools/podman_e2e/panel_surface.py --scope surface
"""
from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

CREDENTIALS_FILE = "/root/gowave-credentials.txt"
PANEL_URL = "http://127.0.0.1:3000"
REQUEST_TIMEOUT_SECONDS = 30
DEFAULT_USER = "default-user"
MVP_SQUAD = "Default MVP Squad"
CLIENT_PREFIX = "podman-e2e-"


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


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Collect Panel API facts without leaking secrets")
    parser.add_argument("--scope", choices=("surface", "lifecycle", "all"), default="all")
    parser.add_argument("--panel-url", default=PANEL_URL)
    parser.add_argument("--credentials", default=CREDENTIALS_FILE)
    args = parser.parse_args(argv)

    username, password = read_credentials(Path(args.credentials))
    panel = Panel(args.panel_url)
    facts: Dict[str, Any] = {"login": login(panel, username, password)}
    if args.scope in ("surface", "all"):
        facts["surface"] = surface(panel)
    if args.scope in ("lifecycle", "all"):
        facts["lifecycle"] = lifecycle(panel)
    print(json.dumps(facts, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
