"""``TLS-VERIFY-ANCHORS``: every Xray TLS outbound carries the fixture CA.

Xray builds its certificate pool from a hardcoded list of system paths and
ignores ``SSL_CERT_FILE``, so the fixture CA has to travel inside the outbound
as a ``tlsSettings.certificates`` entry with ``usage: verify``. This case drives
the helper that places it — ``tools/podman_e2e/client_trust.py``, the module the
data-plane cases call — over a config with two TLS outbounds and one REALITY
outbound, and reads the three things the sentence names:

* every TLS outbound carries the anchor, embedded as a PEM document rather than
  named as a path, and REALITY is left alone;
* the anchor is what makes the chain valid: ``openssl`` accepts a leaf signed by
  the fixture CA when that CA is the only trusted store, and rejects it under a
  CA it has never seen;
* removing the anchor leaves the outbound on the system pool, which is the
  chain-verification failure the case exists to detect — and the helper refuses
  a failure that is not a certificate-chain error, so a closed port cannot be
  read as a trust result.

What is real: the helper, the anchor shape, and ``openssl``'s verdict. What is
not: the CA is minted here because the run's own fixture CA is issued by Pebble
inside the topology, and no Xray engine is started — the case decides what the
config carries and what that anchor trusts, not that Xray dials with it. That
half is the data-plane cases'.
"""
from __future__ import annotations

import copy
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Tuple

from tools.podman_e2e import client_trust
from tools.podman_e2e.runner import require

CASE_ID = "TLS-VERIFY-ANCHORS"

TLS_TAGS = ("vmess-tls", "trojan-tls")
REALITY_TAG = "vless-reality"


def _openssl(*arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(["openssl", *arguments], capture_output=True, text=True,
                          timeout=120, check=False)


def _mint_chain(directory: Path) -> Tuple[Path, Path, Path]:
    """A signing CA, a leaf it issued, and a CA that never saw the leaf."""
    ca_key = directory / "fixture-ca.key"
    ca = directory / "fixture-ca.crt"
    leaf_key = directory / "server.key"
    request = directory / "server.csr"
    leaf = directory / "server.crt"
    unrelated_key = directory / "unrelated.key"
    unrelated = directory / "unrelated.crt"
    steps = (
        ("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key),
         "-out", str(ca), "-days", "2", "-subj", "/CN=probe-fixture-authority",
         "-addext", "basicConstraints=critical,CA:TRUE"),
        ("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(leaf_key),
         "-out", str(request), "-subj", "/CN=panel.testbed.internal"),
        ("x509", "-req", "-in", str(request), "-CA", str(ca), "-CAkey", str(ca_key),
         "-CAcreateserial", "-out", str(leaf), "-days", "1"),
        ("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(unrelated_key),
         "-out", str(unrelated), "-days", "2", "-subj", "/CN=probe-unrelated-authority",
         "-addext", "basicConstraints=critical,CA:TRUE"),
    )
    for step in steps:
        completed = _openssl(*step)
        require(
            CASE_ID,
            completed.returncode == 0,
            f"the probe could not mint its chain at step {step[0]}: {completed.stderr[-400:]!r}",
        )
    return ca, leaf, unrelated


def _verify(ca: Path, leaf: Path) -> Tuple[bool, str]:
    completed = _openssl("verify", "-CAfile", str(ca), str(leaf))
    detail = ((completed.stdout or "") + (completed.stderr or "")).strip()
    return completed.returncode == 0, detail


def _config() -> Dict[str, Any]:
    return {
        "outbounds": [
            {"tag": TLS_TAGS[0], "protocol": "vmess",
             "streamSettings": {"network": "tcp", "security": "tls"}},
            {"tag": REALITY_TAG, "protocol": "vless",
             "streamSettings": {"network": "tcp", "security": "reality",
                                "realitySettings": {"serverName": "www.example.com"}}},
            {"tag": TLS_TAGS[1], "protocol": "trojan",
             "streamSettings": {"network": "ws", "security": "tls"}},
        ]
    }


def case_every_tls_outbound_carries_the_fixture_ca(product: Any, context: Any) -> Dict[str, Any]:
    """``TLS-VERIFY-ANCHORS``: the anchor is present, embedded, and load-bearing."""
    original = _config()
    with tempfile.TemporaryDirectory(prefix="gowave-tls-anchors-") as directory:
        root = Path(directory)
        ca, leaf, unrelated = _mint_chain(root)
        anchored = client_trust.apply_xray_trust_anchors(original, ca)

        require(
            CASE_ID,
            original == _config(),
            "applying the anchors mutated the config it was handed, so a second outbound would "
            "inherit the first one's entries",
        )

        entries = {}
        for outbound in client_trust.tls_outbounds(anchored):
            tag = str(outbound.get("tag") or "")
            certificates = ((outbound.get("streamSettings") or {}).get("tlsSettings") or {}).get(
                "certificates") or []
            entries[tag] = certificates

        require(
            CASE_ID,
            sorted(entries) == sorted(TLS_TAGS),
            f"the anchored config carries TLS outbounds {sorted(entries)}, so the case would not "
            f"read the two tags it names ({sorted(TLS_TAGS)})",
        )
        for tag, certificates in entries.items():
            require(
                CASE_ID,
                len(certificates) == 1,
                f"{tag} carries {len(certificates)} certificate entr(ies), not the one anchor the "
                "fixture CA needs",
            )
            anchor = certificates[0]
            require(
                CASE_ID,
                anchor.get("usage") == "verify",
                f"{tag}'s anchor has usage {anchor.get('usage')!r}; an entry Xray does not treat "
                "as a verify anchor leaves the outbound on the system pool",
            )
            certificate = anchor.get("certificate")
            require(
                CASE_ID,
                isinstance(certificate, list) and len(certificate) == 1
                and "BEGIN CERTIFICATE" in certificate[0],
                f"{tag}'s anchor is not an embedded PEM document ({type(certificate).__name__}), "
                "and Xray reads neither SSL_CERT_FILE nor a path in this entry",
            )
            require(
                CASE_ID,
                "certificateFile" not in anchor,
                f"{tag}'s anchor names a file instead of carrying the certificate, which Xray "
                "never reads",
            )

        reality = next(
            outbound for outbound in anchored["outbounds"] if outbound.get("tag") == REALITY_TAG
        )
        require(
            CASE_ID,
            "certificates" not in ((reality.get("streamSettings") or {}).get("tlsSettings") or {}),
            "the REALITY outbound was given a CA anchor; REALITY authenticates the server with its "
            "public key, so the entry is inert and hides a TLS outbound that lost its own",
        )
        require(
            CASE_ID,
            client_trust.unanchored_tls_outbounds(anchored) == [],
            f"after anchoring, the TLS outbounds {client_trust.unanchored_tls_outbounds(anchored)} "
            "still fall back to the system pool",
        )
        require(
            CASE_ID,
            sorted(client_trust.unanchored_tls_outbounds(original)) == sorted(TLS_TAGS),
            "an unanchored config was reported as anchored, so the check cannot tell the two apart",
        )

        trusted, trusted_detail = _verify(ca, leaf)
        require(
            CASE_ID,
            trusted,
            f"the fixture CA does not trust the leaf it issued ({trusted_detail!r}), so the anchor "
            "would be added to every outbound and mean nothing",
        )
        rejected, rejected_detail = _verify(unrelated, leaf)
        require(
            CASE_ID,
            not rejected,
            "a CA that never saw the leaf reported it as trusted, so the verification below would "
            "pass for any anchor",
        )

        try:
            client_trust.verify_chain_failure(rejected_detail)
            chain_error_accepted = "True"
        except client_trust.ClientTrustError as error:
            raise AssertionError(
                f"the failure openssl reports is not read as a certificate-chain error: {error}"
            ) from error
        try:
            client_trust.verify_chain_failure("dial tcp 10.0.0.1:443: connect: connection refused")
        except client_trust.ClientTrustError:
            non_chain_refused = "True"
        else:
            raise AssertionError(
                "a closed port was accepted as an untrusted-anchor result, so the negative half of "
                "this case could pass without a chain ever being verified"
            )

        stripped = copy.deepcopy(anchored)
        for outbound in client_trust.tls_outbounds(stripped):
            tls_settings = ((outbound.get("streamSettings") or {}).get("tlsSettings") or {})
            tls_settings.pop("certificates", None)
        unanchored = client_trust.unanchored_tls_outbounds(stripped)
        require(
            CASE_ID,
            sorted(unanchored) == sorted(TLS_TAGS),
            f"removing the anchors left {unanchored} still reported as anchored, so the case "
            "cannot show that the anchor is what makes the chain valid",
        )
        without_anchor, without_anchor_detail = _verify(unrelated, leaf)
        require(
            CASE_ID,
            not without_anchor,
            "the leaf verified without the fixture CA, so removing the anchor would not be a "
            "chain-verification failure",
        )

    return {
        "anchored_tags": ",".join(sorted(entries)),
        "anchor_usage": ",".join(
            str(certificates[0].get("usage")) for _tag, certificates in sorted(entries.items())
        ),
        "anchors_embedded": "True",
        "anchors_named_by_path": "0",
        "verify_anchors_per_outbound": ",".join(
            str(len(certificates)) for _tag, certificates in sorted(entries.items())
        ),
        "reality_untouched": "True",
        "input_unchanged": "True",
        "unanchored_tags": ",".join(sorted(unanchored)),
        "fixture_ca_trusts_leaf": str(trusted),
        "unrelated_ca_rejects_leaf": str(rejected),
        "without_anchor_error": without_anchor_detail,
        "chain_error_accepted": chain_error_accepted,
        "non_chain_failure_refused": non_chain_refused,
        "container_ca_file": client_trust.CONTAINER_CA_FILE,
    }
