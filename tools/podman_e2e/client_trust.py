"""Client-side trust for the fixture CA, with no global trust changes.

Two client engines consume the fixture CA differently, and both deviations are
deliberate:

* Xray builds its certificate pool from a hardcoded system path list and ignores
  ``SSL_CERT_FILE``, so the anchor must be declared inside the outbound as
  ``tlsSettings.certificates`` with ``usage: verify``;
* Mihomo reads the extra anchor from ``tls.custom-certifactes`` (the upstream key
  really is spelled that way), and that key takes PEM documents rather than
  paths, so the anchor is embedded in the generated config.

curl and the Python clients honour the scoped ``CURL_CA_BUNDLE`` /
``REQUESTS_CA_BUNDLE`` / ``SSL_CERT_FILE`` environment, so nothing outside the
case's environment is ever touched.

Every helper fails closed when it cannot place the anchor: a config that is
returned unchanged would run a case that proves nothing.
"""
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Dict, List, Union

SCHEMA = "gowave-podman-client-trust/v1"

# Clients run inside the topology network, so the CA is mounted at a fixed path
# instead of being read from the host run directory.
CONTAINER_CA_DIR = "/fixtures/ca"
CONTAINER_CA_FILE = f"{CONTAINER_CA_DIR}/fixture-ca.crt"

MIHOMO_CA_KEY = "custom-certifactes"

CHAIN_ERROR_MARKERS = (
    "certificate signed by unknown authority",
    "unable to get local issuer certificate",
    "unable to get issuer certificate",
    "CERTIFICATE_VERIFY_FAILED",
    "certificate verify failed",
    "failed to verify certificate",
    "self-signed certificate in certificate chain",
)


class ClientTrustError(RuntimeError):
    pass


def _text(path: Union[str, Path]) -> str:
    path = Path(path)
    if not path.is_file():
        raise ClientTrustError(f"CA file does not exist: {path}")
    return path.read_text(encoding="utf-8")


def ca_pem(ca_file: Union[str, Path]) -> str:
    pem = _text(ca_file)
    if "BEGIN CERTIFICATE" not in pem or "END CERTIFICATE" not in pem:
        raise ClientTrustError(f"{ca_file} is not a PEM certificate")
    return pem.strip() + "\n"


def xray_verify_anchor(ca_file: Union[str, Path]) -> Dict[str, Any]:
    """The tlsSettings.certificates entry Xray accepts as a trust anchor."""
    return {"usage": "verify", "certificate": [ca_pem(ca_file)]}


def tls_outbounds(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    outbounds = config.get("outbounds")
    if not isinstance(outbounds, list):
        raise ClientTrustError("Xray config has no outbounds list")
    return [
        outbound for outbound in outbounds
        if isinstance(outbound, dict)
        and (outbound.get("streamSettings") or {}).get("security") == "tls"
    ]


def apply_xray_trust_anchors(config: Dict[str, Any], ca_file: Union[str, Path]) -> Dict[str, Any]:
    """Add the fixture anchor to every TLS outbound and return a new config.

    REALITY outbounds are left alone: REALITY authenticates the server with its
    public key, not with a PKI chain, so an extra anchor would be inert noise.
    """
    anchor = xray_verify_anchor(ca_file)
    result = copy.deepcopy(config)
    targeted = tls_outbounds(result)
    if not targeted:
        raise ClientTrustError("Xray config has no TLS outbound to anchor; the case would prove nothing")
    for outbound in targeted:
        tls_settings = outbound.setdefault("streamSettings", {}).setdefault("tlsSettings", {})
        existing = list(tls_settings.get("certificates") or [])
        if anchor not in existing:
            existing.append(copy.deepcopy(anchor))
        tls_settings["certificates"] = existing
    return result


def unanchored_tls_outbounds(config: Dict[str, Any]) -> List[str]:
    """Tags of TLS outbounds that would fall back to the system pool."""
    unanchored = []
    for outbound in tls_outbounds(config):
        certificates = ((outbound.get("streamSettings") or {}).get("tlsSettings") or {}).get("certificates") or []
        if not any(entry.get("usage") == "verify" and entry.get("certificate") for entry in certificates if isinstance(entry, dict)):
            unanchored.append(str(outbound.get("tag") or ""))
    return unanchored


def apply_mihomo_trust_anchors(config: Dict[str, Any], ca_file: Union[str, Path] = CONTAINER_CA_FILE) -> Dict[str, Any]:
    """Put the fixture anchor where Mihomo actually reads one.

    ``tls.custom-certifactes`` is a list of PEM *documents*, not of paths: Mihomo
    feeds each entry straight to ``AppendCertsFromPEM``, so a mounted path is
    rejected with a warning and every TLS outbound silently stays on the system
    pool. The anchor is therefore embedded, which is why this helper reads the
    file instead of naming it.
    """
    pem = ca_pem(ca_file)
    result = copy.deepcopy(config)
    tls_block = result.setdefault("tls", {})
    if not isinstance(tls_block, dict):
        raise ClientTrustError("Mihomo config 'tls' must be a mapping")
    tls_block[MIHOMO_CA_KEY] = [pem]
    return result


def scoped_environment(ca_path: Union[str, Path]) -> Dict[str, str]:
    """Environment bundle for curl, requests, and every OpenSSL-based client."""
    return {
        "CURL_CA_BUNDLE": str(ca_path),
        "REQUESTS_CA_BUNDLE": str(ca_path),
        "SSL_CERT_FILE": str(ca_path),
    }


def curl_ca_arguments(ca_path: Union[str, Path]) -> List[str]:
    """Explicit curl anchor, for cases that must not depend on the environment."""
    if not str(ca_path):
        raise ClientTrustError("curl CA path must not be empty")
    return ["--cacert", str(ca_path)]


def verify_chain_failure(message: str) -> None:
    """Fail the case unless the observed failure really is a trust-chain error.

    A refusal without a chain error (a closed port, a timeout, an HTTP 502) would
    otherwise be recorded as a successful "untrusted anchor" negative.
    """
    if not message:
        raise ClientTrustError("trust failure produced no diagnostic message")
    lowered = message.lower()
    if not any(marker.lower() in lowered for marker in CHAIN_ERROR_MARKERS):
        raise ClientTrustError(f"failure is not a certificate-chain error: {message.strip()[:400]}")


def evidence(ca_file: Union[str, Path], config: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema": SCHEMA,
        "ca_file": str(ca_file),
        "container_ca_file": CONTAINER_CA_FILE,
        "xray_anchored_tags": [
            str(outbound.get("tag") or "")
            for outbound in tls_outbounds(config)
            if str(outbound.get("tag") or "") not in unanchored_tls_outbounds(config)
        ],
        "mihomo_ca_key": MIHOMO_CA_KEY,
    }
