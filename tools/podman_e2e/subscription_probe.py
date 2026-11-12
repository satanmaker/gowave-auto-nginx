"""Consume the Panel-issued subscriptions with the pinned client engines.

This runs inside the Control Machine's engine container, which holds the real
``xray`` and ``mihomo`` binaries and nothing from the product. The payloads were
fetched by the host-side probe and mounted read-only, because the Panel's
subscription routes are loopback-only.

Two rules shape the code:

* the Panel-issued outbound is never replaced. A subscription config is anchored
  with the fixture CA and, if the Panel served a bare object instead of a
  complete profile, given the minimal local inbound it needs to be a runnable
  core config — nothing else is rewritten;
* nothing secret is printed. Share links carry client identifiers and Trojan
  passwords, so only counts, families, and non-secret endpoint names appear in
  the facts. Engine diagnostics are redacted before they are reported.

    python3 /repo/tools/podman_e2e/subscription_probe.py \
        --scope representations --payload-dir /secrets --ca /fixtures/ca/issued-root.pem
"""
from __future__ import annotations

import argparse
import base64
import binascii
import copy
import json
import re
import string
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import client_trust  # noqa: E402

XRAY_BINARY = "xray"
MIHOMO_BINARY = "mihomo"
COMMAND_TIMEOUT_SECONDS = 180
SOCKS_PORT = 10808
SHARE_LINK_SCHEMES = ("vless", "trojan")
BASE64_ALPHABET = set(string.ascii_letters + string.digits + "+/=")

# The minimal runtime listener a bare outbound object needs to become a config.
SOCKS_INBOUND: Dict[str, Any] = {
    "tag": "socks",
    "listen": "127.0.0.1",
    "port": SOCKS_PORT,
    "protocol": "socks",
    "settings": {"udp": True, "auth": "noauth"},
}

UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE
)


def sanitize(text: str, limit: int = 800) -> str:
    """Redact client identifiers from engine diagnostics before they are reported."""
    return UUID_RE.sub("<id>", (text or "").strip())[-limit:]


def read_payload(directory: str, name: str) -> str:
    path = Path(directory) / f"{name}.payload"
    if not path.is_file():
        raise SystemExit(f"the {name} payload is missing from {directory}")
    return path.read_text(encoding="utf-8", errors="replace")


# ------------------------------------------------------------------ share links
def decode_share_list(text: str) -> Optional[str]:
    """Decode a share-link subscription, or report that the body is not one.

    A JSON config is not base64: its braces and quotes are outside the alphabet,
    so an importer that expects a share-link list decodes nothing at all. That is
    the property asserted when a JSON body is offered to an Xray-family client.
    """
    compact = "".join(text.split())
    if not compact:
        return None
    candidate = compact.replace("-", "+").replace("_", "/")
    if set(candidate) - BASE64_ALPHABET:
        return None
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        return base64.b64decode(padded, validate=True).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return None


def share_links(decoded: Optional[str]) -> List[str]:
    if not decoded:
        return []
    return [line.strip() for line in decoded.splitlines() if "://" in line]


def parse_link(link: str) -> Dict[str, str]:
    parsed = urllib.parse.urlsplit(link)
    query = {
        key: values[-1]
        for key, values in urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items()
    }
    return {
        "protocol": parsed.scheme.lower(),
        "host": parsed.hostname or "",
        "port": str(parsed.port or ""),
        "sni": query.get("sni", ""),
        "fingerprint": query.get("fp", ""),
        "security": query.get("security", ""),
        "network": query.get("type", ""),
        "path": query.get("path", ""),
        "flow": query.get("flow", ""),
        "service_name": query.get("serviceName", ""),
        "mode": query.get("mode", ""),
        "alpn": query.get("alpn", ""),
        "reality_public_key": query.get("pbk", ""),
        "reality_short_id": query.get("sid", ""),
        "credential": parsed.username or "",
        "tag": urllib.parse.unquote(parsed.fragment or ""),
    }


def _alpn(value: str) -> List[str]:
    if not value:
        return []
    return [entry for entry in urllib.parse.unquote(value).split(",") if entry]


def outbound_from_link(link: Dict[str, str], tag: str) -> Dict[str, Any]:
    """Translate one share link into the outbound the Panel's own JSON would carry."""
    protocol = link["protocol"]
    if protocol not in SHARE_LINK_SCHEMES:
        raise SystemExit(f"share link protocol {protocol!r} is not one this suite can import")
    port = int(link["port"] or 0)
    network = link["network"] or "tcp"
    security = link["security"] or "none"

    if protocol == "vless":
        settings: Dict[str, Any] = {
            "vnext": [{
                "address": link["host"],
                "port": port,
                "users": [{
                    "id": link["credential"],
                    "encryption": "none",
                    "flow": link["flow"] or "",
                }],
            }],
        }
    else:
        settings = {"servers": [{
            "address": link["host"],
            "port": port,
            "password": link["credential"],
        }]}

    stream: Dict[str, Any] = {"network": network}
    if network == "tcp":
        stream["tcpSettings"] = {"header": {"type": "none"}}
    elif network == "ws":
        stream["wsSettings"] = {"path": link["path"] or "/", "host": "", "headers": {}}
    elif network == "xhttp":
        stream["xhttpSettings"] = {"mode": link["mode"] or "auto", "host": "", "path": link["path"] or "/"}
    elif network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": link["service_name"],
            "authority": "",
            "multiMode": link["mode"] == "multi",
        }
    else:
        raise SystemExit(f"share link network {network!r} is not one this suite can import")

    if security == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName": link["sni"],
            "publicKey": link["reality_public_key"],
            "shortId": link["reality_short_id"],
            "fingerprint": link["fingerprint"],
        }
    elif security == "tls":
        stream["security"] = "tls"
        tls_settings: Dict[str, Any] = {
            "serverName": link["sni"],
            "enableSessionResumption": False,
            "fingerprint": link["fingerprint"],
        }
        alpn = _alpn(link["alpn"])
        if alpn:
            tls_settings["alpn"] = alpn
        stream["tlsSettings"] = tls_settings
    elif security != "none":
        raise SystemExit(f"share link security {security!r} is not one this suite can import")

    return {"tag": tag, "protocol": protocol, "settings": settings, "streamSettings": stream}


def link_identity(link: Dict[str, str]) -> Tuple[str, ...]:
    return (
        link["protocol"], link["host"], link["port"], link["sni"], link["fingerprint"],
        link["security"], link["network"], link["path"], link["service_name"],
    )


def outbound_identity(outbound: Dict[str, Any]) -> Optional[Tuple[str, ...]]:
    """The same tuple, read back from a Panel-issued Xray outbound."""
    protocol = str(outbound.get("protocol") or "")
    if protocol not in SHARE_LINK_SCHEMES:
        return None
    settings = outbound.get("settings") or {}
    stream = outbound.get("streamSettings") or {}
    if protocol == "vless":
        servers = settings.get("vnext") or [{}]
        host = str(servers[0].get("address") or "")
        port = str(servers[0].get("port") or "")
    else:
        servers = settings.get("servers") or [{}]
        host = str(servers[0].get("address") or "")
        port = str(servers[0].get("port") or "")
    tls_settings = stream.get("tlsSettings") or {}
    reality_settings = stream.get("realitySettings") or {}
    sni = str(tls_settings.get("serverName") or reality_settings.get("serverName") or "")
    fingerprint = str(tls_settings.get("fingerprint") or reality_settings.get("fingerprint") or "")
    network = str(stream.get("network") or "")
    path = ""
    service_name = ""
    if network == "ws":
        path = str((stream.get("wsSettings") or {}).get("path") or "")
    elif network == "xhttp":
        path = str((stream.get("xhttpSettings") or {}).get("path") or "")
    elif network == "grpc":
        service_name = str((stream.get("grpcSettings") or {}).get("serviceName") or "")
    return (
        protocol, host, port, sni, fingerprint,
        str(stream.get("security") or ""), network, path, service_name,
    )


# ---------------------------------------------------------------------- engines
def run_engine(argv: Sequence[str], timeout: int = COMMAND_TIMEOUT_SECONDS) -> int:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise SystemExit(f"{argv[0]} did not finish within {timeout}s")
    except OSError as exc:
        raise SystemExit(f"cannot run {argv[0]}: {exc}")
    if proc.returncode != 0:
        detail = sanitize(proc.stderr or proc.stdout)
        raise SystemExit(f"{argv[0]} rejected the Panel-issued configuration: {detail}")
    return proc.returncode


def prepare_config(config: Dict[str, Any], ca_file: str) -> Tuple[Dict[str, Any], bool]:
    """Make a Panel-issued config runnable without replacing what the Panel issued.

    Returns the prepared config and whether the minimal runtime wrapper was
    needed: a bare outbound object is not a core config, a complete profile is.
    """
    result = copy.deepcopy(config)
    outbounds = result.get("outbounds")
    if not isinstance(outbounds, list) or not outbounds:
        raise SystemExit("the Panel-issued Xray config has no outbounds list")
    if client_trust.tls_outbounds(result):
        result = client_trust.apply_xray_trust_anchors(result, ca_file)
    wrapped = False
    if not result.get("inbounds"):
        # A bare object is not a core config; the wrapper adds only the local
        # listener, exactly as the documented runtime shape requires.
        result["inbounds"] = [copy.deepcopy(SOCKS_INBOUND)]
        wrapped = True
    return result, wrapped


def xray_test(config: Dict[str, Any], ca_file: str, workdir: Path, label: str) -> bool:
    """Validate one config with the pinned Xray binary; report whether it was wrapped."""
    prepared, wrapped = prepare_config(config, ca_file)
    path = workdir / f"{label}.json"
    path.write_text(json.dumps(prepared), encoding="utf-8")
    path.chmod(0o600)
    run_engine([XRAY_BINARY, "run", "-test", "-c", str(path)])
    path.unlink()
    return wrapped


def mihomo_test(text: str, workdir: Path, label: str) -> int:
    path = workdir / f"{label}.yaml"
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)
    home = workdir / f"{label}-home"
    home.mkdir(exist_ok=True, mode=0o700)
    code = run_engine([MIHOMO_BINARY, "-t", "-f", str(path), "-d", str(home)])
    path.unlink()
    return code


def scan_mihomo(text: str) -> Dict[str, Any]:
    """Structural facts from the served YAML; Mihomo itself is the validity authority.

    Items are counted only at the indentation their own top-level section uses. A
    proxy carries nested lists of its own (``alpn``, ``reality-opts`` …) and a
    proxy-group repeats the names of the proxies it selects, so treating every
    ``- `` line as an item would count the same proxy twice and report a YAML
    Mihomo happily loads as the wrong size.
    """
    proxies: List[Dict[str, str]] = []
    groups = 0
    rules = 0
    match_rule = False
    section = ""
    item_prefix: Optional[str] = None
    key_prefix: Optional[str] = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        prefix = line[: len(line) - len(line.lstrip())]
        stripped = line.strip()
        if not prefix:
            section = line.partition(":")[0].strip()
            item_prefix = None
            key_prefix = None
            continue
        if section not in ("proxies", "proxy-groups", "rules"):
            continue
        if stripped.startswith("- "):
            if item_prefix is None:
                item_prefix = prefix
            if prefix != item_prefix:
                continue
            header = stripped[2:].strip()
            if section == "proxies":
                key, _, value = header.partition(":")
                proxies.append({key.strip(): value.strip().strip("'\"")})
            elif section == "proxy-groups":
                if header.partition(":")[0].strip() == "name":
                    groups += 1
            else:
                rules += 1
                match_rule = match_rule or header.partition(",")[0].strip().upper() == "MATCH"
            continue
        if section != "proxies" or not proxies:
            continue
        if key_prefix is None:
            key_prefix = prefix
        if prefix != key_prefix:
            continue
        key, _, value = stripped.partition(":")
        proxies[-1][key.strip()] = value.strip().strip("'\"")
    return {
        "proxies": len(proxies),
        "proxy_types": sorted({entry.get("type", "") for entry in proxies if entry.get("type")}),
        "groups": groups,
        "rules": rules,
        "match_rule": match_rule,
    }


# ----------------------------------------------------------------------- scopes
def representations(payload_dir: str, ca_file: str, workdir: Path) -> Dict[str, Any]:
    """Load every representation into the client that consumes it."""
    facts: Dict[str, Any] = {}

    link_text = read_payload(payload_dir, "base64")
    decoded = decode_share_list(link_text)
    links = share_links(decoded)
    parsed = [parse_link(link) for link in links]
    facts["base64"] = {
        "decoded": decoded is not None,
        "decoded_bytes": len(decoded or ""),
        "link_count": len(links),
        "schemes": sorted({entry["protocol"] for entry in parsed if entry["protocol"]}),
    }

    raw = read_payload(payload_dir, "xray-json")
    shape, entries = load_profiles(raw)

    protocols = set()
    wrapped = 0
    for index, entry in enumerate(entries):
        if not isinstance(entry.get("outbounds"), list):
            raise SystemExit(f"Xray profile {index} has no outbounds list")
        for outbound in entry["outbounds"]:
            protocol = str((outbound or {}).get("protocol") or "")
            if protocol not in ("freedom", "blackhole", ""):
                protocols.add(protocol)
        if xray_test(entry, ca_file, workdir, f"xray-json-{index}"):
            wrapped += 1

    facts["xray_json"] = {
        "shape": shape,
        "entries": len(entries),
        "wrapped": wrapped,
        "protocols": sorted(protocols),
    }

    for name in ("mihomo", "clash"):
        text = read_payload(payload_dir, name)
        scan = scan_mihomo(text)
        scan["exit"] = mihomo_test(text, workdir, name)
        facts[name] = scan

    singbox = read_payload(payload_dir, "singbox")
    try:
        parsed_singbox = json.loads(singbox)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"the Panel's sing-box JSON is not JSON: {exc}")
    outbounds = parsed_singbox.get("outbounds") if isinstance(parsed_singbox, dict) else None
    facts["singbox"] = {
        "parsed": outbounds is not None,
        "outbounds": len(outbounds or []),
    }
    return facts


def load_profiles(raw: str) -> Tuple[str, List[Dict[str, Any]]]:
    """The Panel serves `/v2ray-json` as one config object or as a profile list."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"the Panel's Xray JSON is not JSON: {exc}")
    if isinstance(data, list):
        entries = [entry for entry in data if isinstance(entry, dict)]
        if not entries:
            raise SystemExit("the Panel's Xray JSON is an empty profile list")
        return "list", entries
    if isinstance(data, dict) and isinstance(data.get("outbounds"), list):
        return "object", [data]
    raise SystemExit("the Panel's Xray JSON is neither a config object nor a profile list")


def proxy_outbounds(profiles: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The Panel-issued proxy outbounds, without the runtime freedom/blackhole entries."""
    result: List[Dict[str, Any]] = []
    for profile in profiles:
        for outbound in profile.get("outbounds") or []:
            protocol = str((outbound or {}).get("protocol") or "")
            if protocol and protocol not in ("freedom", "blackhole"):
                result.append(outbound)
    return result


def json_shapes(payload_dir: str, ca_file: str, workdir: Path) -> Dict[str, Any]:
    """Validate the served shape and the other documented shape of `/v2ray-json`.

    The Panel emits one config document per host and tags the host outbound
    ``proxy`` in every one of them, so a single object carrying all profiles'
    outbounds would collide on that tag — and no client is ever handed such an
    object. A config object is per-host by construction, so the alternate shape
    carries one Panel-issued outbound, taken exactly as it was served, and the
    wrapper count proves how the two shapes differ: a bare object needs the local
    inbound added, a complete profile does not.
    """
    shape, entries = load_profiles(read_payload(payload_dir, "xray-json"))
    served_wrapped = 0
    for index, entry in enumerate(entries):
        if not isinstance(entry.get("outbounds"), list):
            raise SystemExit(f"Xray profile {index} has no outbounds list")
        if xray_test(entry, ca_file, workdir, f"served-{index}"):
            served_wrapped += 1

    outbounds = proxy_outbounds(entries)
    if not outbounds:
        raise SystemExit("the Panel's Xray JSON carries no proxy outbound")
    alternate: Dict[str, Any] = {"outbounds": [copy.deepcopy(outbounds[0])]}
    alternate_shape = "object" if shape == "list" else "list"
    if alternate_shape == "list":
        alternate["inbounds"] = [copy.deepcopy(SOCKS_INBOUND)]
    alternate_wrapped = 1 if xray_test(alternate, ca_file, workdir, "alternate") else 0

    return {
        "served_shape": shape,
        "served_entries": len(entries),
        "served_wrapped": served_wrapped,
        "alternate_shape": alternate_shape,
        "alternate_outbounds": len(alternate["outbounds"]),
        "alternate_wrapped": alternate_wrapped,
    }


def share_link_facts(payload_dir: str, ca_file: str, workdir: Path) -> Dict[str, Any]:
    """Import the base64 list with Xray and cross-check it against the JSON profiles."""
    link_text = read_payload(payload_dir, "base64")
    decoded = decode_share_list(link_text)
    if decoded is None:
        raise SystemExit("the base64 subscription is not base64")
    links = share_links(decoded)
    if not links:
        raise SystemExit("the decoded base64 subscription carries no share links")

    parsed = [parse_link(link) for link in links]
    credentials_present = all(entry["credential"] for entry in parsed)
    outbounds = [
        outbound_from_link(entry, f"link-{index}-{entry['protocol']}")
        for index, entry in enumerate(parsed)
    ]
    xray_test({"outbounds": outbounds}, ca_file, workdir, "share-links")

    raw = read_payload(payload_dir, "xray-json")
    json_links = share_links(decode_share_list(raw))
    _shape, profiles = load_profiles(raw)
    issued = set()
    for outbound in proxy_outbounds(profiles):
        identity = outbound_identity(outbound)
        if identity is not None:
            issued.add(identity)
    imported = {link_identity(entry) for entry in parsed}

    counts: Dict[str, int] = {}
    for entry in parsed:
        counts[entry["protocol"]] = counts.get(entry["protocol"], 0) + 1

    return {
        "link_count": len(links),
        "protocols": counts,
        "hosts": sorted({entry["host"] for entry in parsed}),
        "snis": sorted({entry["sni"] for entry in parsed if entry["sni"]}),
        "sni_missing": sum(1 for entry in parsed if not entry["sni"]),
        "fingerprints": sorted({entry["fingerprint"] for entry in parsed if entry["fingerprint"]}),
        "fingerprint_missing": sum(1 for entry in parsed if not entry["fingerprint"]),
        "ports": sorted({entry["port"] for entry in parsed}),
        "networks": sorted({entry["network"] for entry in parsed}),
        "credential_present": credentials_present,
        "xray_outbounds": len(outbounds),
        "cross_representation_matches": len(imported & issued),
        "cross_representation_issued": len(issued),
        "json_body_links": len(json_links),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Consume Panel-issued subscriptions with the real engines")
    parser.add_argument(
        "--scope",
        choices=("representations", "json-shapes", "share-links"),
        default="representations",
    )
    parser.add_argument("--payload-dir", default="/secrets")
    parser.add_argument("--ca", required=True, help="Fixture CA the Xray outbounds are anchored to")
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory(prefix="subscription-") as tmp:
        workdir = Path(tmp)
        if args.scope == "representations":
            facts = representations(args.payload_dir, args.ca, workdir)
        elif args.scope == "json-shapes":
            facts = json_shapes(args.payload_dir, args.ca, workdir)
        else:
            facts = share_link_facts(args.payload_dir, args.ca, workdir)
    print(json.dumps(facts, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
