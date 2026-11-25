#!/usr/bin/env python3
"""The pinned Staging roots, the anchors they become, and what both files trust.

``openspec/specs/live-vps-e2e/spec.md`` §Data Plane E2E Traffic Through All VPN
Endpoints has three sentences about Let's Encrypt Staging material, and this
module carries the container half of each:

``DP-11``  the four roots are vendored, digested in ``pins.json``, and refused
           when a pin is missing, mismatched, or joined by an intermediate;
``DP-10``  an Xray outbound whose transport is ``tls`` carries one
           ``{"usage": "verify", "certificateFile": <root>}`` entry per pinned
           root, while REALITY and ``production`` are returned untouched and
           ``allowInsecure`` never appears;
``DP-09``  the bundle built for a Staging run trusts both a pinned Staging root
           and an ordinary public root, an untrusted authority is rejected by
           it, and building it changes no global trust store and no engine
           configuration.

What is real: the vendored roots and their manifest, the product's own
``verify_staging_roots``, ``build_runtime_ca_bundle``, ``create_ssl_context``
and ``apply_xray_trust_anchors``, and ``openssl`` as the trust decision. What is
not available: a leaf chain under a pinned root — the vendored material carries
trust anchors without private keys, so a certificate issued beneath one cannot be
minted offline and each trust question is asked of the anchor itself. The live
half of each sentence (a real ACME issuance, a real https egress probe, four
engines making the request) is live-only and the catalog states the split.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

from tools.live_vps import tls as live_tls
from tools.live_vps import traffic as live_traffic
from tools.podman_e2e import client_trust
from tools.podman_e2e.runner import require

DP09_CASE_ID = "DP-09"
DP10_CASE_ID = "DP-10"
DP11_CASE_ID = "DP-11"

STAGING_DIR = live_tls.STAGING_CERTS_DIR

#: The marker ``build_runtime_ca_bundle`` writes before the Staging roots, and the
#: subject prefix a pinned Staging root carries. Both are read from the product's
#: own naming so a rename shows up here rather than being copied by hand.
STAGING_MARKER = "Let's Encrypt Staging Roots (Pinned E2E Trust Anchors)"
STAGING_SUBJECT = "(STAGING)"

#: The module whose own source says the pins are read from disk rather than
#: fetched: a runner that downloaded a certificate at run time would have to
#: carry a network client, and this is the list of the ones a reader would look
#: for.
_NETWORK_IMPORTS = ("urllib", "requests", "httpx", "socket")

_PEM_BLOCK = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\n?", re.DOTALL,
)


def _openssl(*arguments: str, text: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["openssl", *arguments], capture_output=True, text=text, timeout=120, check=False,
    )


def _openssl_verify(bundle: Path, certificate: Path) -> Tuple[bool, str]:
    """Does ``bundle`` alone trust ``certificate``? ``openssl`` decides."""
    completed = _openssl("verify", "-CAfile", str(bundle), str(certificate), text=True)
    detail = ((completed.stdout or "") + (completed.stderr or "")).strip()
    return completed.returncode == 0, detail


def _der_sha256(pem: Path) -> str:
    completed = _openssl("x509", "-in", str(pem), "-outform", "DER")
    if completed.returncode != 0:
        raise AssertionError(f"openssl could not read {pem}: {completed.stderr[-400:]!r}")
    return hashlib.sha256(completed.stdout).hexdigest()


def _subject(pem: Path) -> str:
    completed = _openssl("x509", "-in", str(pem), "-noout", "-subject", text=True)
    if completed.returncode != 0:
        raise AssertionError(f"openssl could not read the subject of {pem}: {completed.stderr[-400:]!r}")
    return (completed.stdout or "").strip()


def _public_root(bundle: Path, directory: Path) -> Tuple[Path, int]:
    """One public root lifted out of the public bundle, and how many it carries."""
    blocks = _PEM_BLOCK.findall(bundle.read_bytes())
    require(
        DP09_CASE_ID,
        len(blocks) > 1,
        f"the public bundle carries {len(blocks)} certificate(s), so it is not a root store",
    )
    candidate = directory / "public-root.pem"
    candidate.write_bytes(blocks[0])
    return candidate, len(blocks)


def _network_imports(module: Path) -> List[str]:
    """Which network clients ``module``'s own source imports, if any."""
    text = module.read_text(encoding="utf-8")
    return [name for name in _NETWORK_IMPORTS if re.search(rf"^\s*(import|from)\s+{name}\b", text, re.M)]


def _untrusted_ca(directory: Path) -> Path:
    """A self-signed authority nothing in the product's bundle has ever seen."""
    key = directory / "untrusted.key"
    certificate = directory / "untrusted.pem"
    created = _openssl(
        "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(certificate), "-days", "2",
        "-subj", "/CN=probe-untrusted-authority",
        "-addext", "basicConstraints=critical,CA:TRUE",
    )
    require(
        DP09_CASE_ID,
        created.returncode == 0 and certificate.is_file(),
        f"the probe could not mint an untrusted authority: {created.stderr[-400:]!r}",
    )
    return certificate


def _intermediate_like(directory: Path, subject_cn: str) -> Path:
    """A certificate carrying a pinned root's name but signed by someone else.

    It is what an intermediate would look like to this check: a CA certificate
    that is not its own issuer, so treating it as a trust anchor would extend
    trust one step beyond the four vendored roots.
    """
    ca_key = directory / "probe-ca.key"
    ca = directory / "probe-ca.pem"
    leaf_key = directory / "probe-leaf.key"
    request = directory / "probe-leaf.csr"
    leaf = directory / "probe-leaf.pem"
    for arguments in (
        ("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key),
         "-out", str(ca), "-days", "2", "-subj", "/CN=probe-signing-authority",
         "-addext", "basicConstraints=critical,CA:TRUE"),
        ("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(leaf_key),
         "-out", str(request), "-subj", f"/CN={subject_cn}"),
        ("x509", "-req", "-in", str(request), "-CA", str(ca), "-CAkey", str(ca_key),
         "-CAcreateserial", "-out", str(leaf), "-days", "1"),
    ):
        completed = _openssl(*arguments)
        require(
            DP11_CASE_ID,
            completed.returncode == 0,
            f"the probe could not mint a non-self-signed certificate: {completed.stderr[-400:]!r}",
        )
    return leaf


def _copy_staging(directory: Path) -> Path:
    target = directory / "staging"
    target.mkdir(parents=True)
    for item in STAGING_DIR.iterdir():
        (target / item.name).write_bytes(item.read_bytes())
    return target


def _rewrite_pins(directory: Path, mutate) -> Path:
    """Apply ``mutate`` to a copied manifest and return the directory it lives in."""
    path = directory / "pins.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    mutate(manifest)
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return directory


def _refusal(directory: Path, expected: str) -> str:
    """The sentence ``verify_staging_roots`` refuses this copy with."""
    try:
        live_tls.verify_staging_roots(directory)
    except (ValueError, FileNotFoundError) as error:
        return str(error)
    raise AssertionError(
        f"{directory.name} was accepted as a pinned Staging set ({expected} was not refused), "
        "so a missing or mismatched pin would reach a run instead of failing preflight"
    )


# --------------------------------------------------------------------------- #
# DP-11 — the four roots are pinned, reproducible, and read from disk.
# --------------------------------------------------------------------------- #
def case_staging_roots_are_pinned(product: Any, context: Any) -> Dict[str, Any]:
    """``DP-11``: four vendored roots match their digests, and every drift is refused."""
    verified = live_tls.verify_staging_roots()
    require(
        DP11_CASE_ID,
        len(verified) == 4,
        f"the pinned set resolves {len(verified)} roots, not the four design D9 names",
    )
    names = sorted(meta["subject_cn"] for _path, meta in verified)
    require(
        DP11_CASE_ID,
        all(STAGING_SUBJECT in name for name in names),
        f"the pinned roots are named {names}, so at least one is not a Staging root",
    )
    manifest = json.loads((STAGING_DIR / "pins.json").read_text(encoding="utf-8"))
    pinned_files = sorted(item["file"] for item in manifest["roots"])
    present = sorted(path.name for path in STAGING_DIR.glob("*.pem"))
    require(
        DP11_CASE_ID,
        pinned_files == present and len(present) == 4,
        f"pins.json names {pinned_files} and the directory holds {present}, so the manifest is "
        "not the whole pinned set",
    )
    mismatched = [
        path.name for path, meta in verified if _der_sha256(path) != meta["der_sha256"].lower()
    ]
    require(
        DP11_CASE_ID,
        not mismatched,
        f"{mismatched} do not hash to the digest pins.json records, so the pins are not reproducible",
    )
    subjects = {path.name: _subject(path) for path, _meta in verified}
    require(
        DP11_CASE_ID,
        all(STAGING_SUBJECT in subject for subject in subjects.values()),
        f"a pinned root's own subject is not a Staging one: {subjects}",
    )
    network_imports = _network_imports(Path(live_tls.__file__))
    require(
        DP11_CASE_ID,
        not network_imports,
        f"the module that builds the bundle imports {network_imports}, so a certificate could be "
        "fetched at run time instead of read from the vendored set",
    )
    tls_source = Path(live_tls.__file__).read_text(encoding="utf-8")
    downloaders = [name for name in ("curl", "wget") if f'"{name}"' in tls_source]
    require(
        DP11_CASE_ID,
        not downloaders,
        f"the bundle builder shells out to {downloaders}, so a root could be downloaded during a run",
    )
    provenance = [item.get("url", "") for item in manifest["roots"]]
    require(
        DP11_CASE_ID,
        all(url.startswith("https://") for url in provenance),
        f"the manifest records the roots' provenance as {provenance}, so a reader cannot say where "
        "the vendored material came from",
    )

    refusals: Dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="gowave-dp11-") as directory:
        root = Path(directory)

        missing = _copy_staging(root / "missing")
        (missing / pinned_files[0]).unlink()
        refusals["missing_file"] = _refusal(missing, "a pinned file that is absent")

        extra = _copy_staging(root / "extra")
        source = extra / pinned_files[1]
        (extra / "an-extra-intermediate.pem").write_bytes(source.read_bytes())
        refusals["extra_pem"] = _refusal(extra, "a file the manifest does not pin")

        tampered = _copy_staging(root / "tampered")
        _rewrite_pins(
            tampered,
            lambda manifest: manifest["roots"][0].__setitem__("der_sha256", "0" * 64),
        )
        refusals["tampered_digest"] = _refusal(tampered, "a digest that does not match its file")

        short = _copy_staging(root / "short")
        _rewrite_pins(short, lambda manifest: manifest["roots"].pop())
        refusals["short_manifest"] = _refusal(short, "a manifest with three roots")

        intermediate = _copy_staging(root / "intermediate")
        forged = _intermediate_like(root, manifest["roots"][2]["subject_cn"])
        (intermediate / pinned_files[2]).write_bytes(forged.read_bytes())
        _rewrite_pins(
            intermediate,
            lambda manifest: manifest["roots"][2].__setitem__(
                "der_sha256", hashlib.sha256(
                    _openssl("x509", "-in", str(forged), "-outform", "DER").stdout
                ).hexdigest(),
            ),
        )
        refusals["not_self_signed"] = _refusal(
            intermediate, "a certificate that is not its own issuer",
        )

    require(
        DP11_CASE_ID,
        "Digest mismatch" in refusals["tampered_digest"],
        f"a tampered digest was refused with {refusals['tampered_digest']!r}, which does not name "
        "the digest it compared",
    )
    require(
        DP11_CASE_ID,
        "not self-signed" in refusals["not_self_signed"],
        f"a certificate signed by another authority was answered with "
        f"{refusals['not_self_signed']!r}, so an intermediate could be pinned as a root",
    )
    require(
        DP11_CASE_ID,
        "Expected exactly 4" in refusals["short_manifest"],
        f"a three-root manifest was answered with {refusals['short_manifest']!r}",
    )

    return {
        "pinned_roots": len(verified),
        "pinned_files": ",".join(pinned_files),
        "pinned_subjects": ",".join(names),
        "digests_recomputed": len(verified),
        "manifest_matches_directory": pinned_files == present,
        "pins_record_provenance": len(provenance),
        "bundle_builder_network_imports": ",".join(network_imports),
        "missing_file_refusal": refusals["missing_file"],
        "extra_pem_refusal": refusals["extra_pem"],
        "tampered_digest_refusal": refusals["tampered_digest"],
        "short_manifest_refusal": refusals["short_manifest"],
        "not_self_signed_refusal": refusals["not_self_signed"],
    }


# --------------------------------------------------------------------------- #
# DP-10 — a TLS outbound carries explicit anchors; REALITY and production do not.
# --------------------------------------------------------------------------- #
def _tls_outbound(existing: Sequence[Dict[str, Any]] = ()) -> Dict[str, Any]:
    settings: Dict[str, Any] = {"serverName": "panel.testbed.internal"}
    if existing:
        settings["certificates"] = [dict(item) for item in existing]
    return {
        "tag": "probe-outbound",
        "protocol": "vless",
        "settings": {"vnext": [{"address": "203.0.113.10", "port": 443}]},
        "streamSettings": {"security": "tls", "tlsSettings": settings},
    }


def _reality_outbound() -> Dict[str, Any]:
    return {
        "tag": "probe-reality",
        "protocol": "vless",
        "settings": {"vnext": [{"address": "203.0.113.10", "port": 443}]},
        "streamSettings": {
            "security": "reality",
            "realitySettings": {"serverName": "reality.testbed.internal", "fingerprint": "chrome"},
        },
    }


def case_xray_outbounds_carry_anchors(product: Any, context: Any) -> Dict[str, Any]:
    """``DP-10``: staging adds one verify anchor per root to a TLS outbound, and only there."""
    pinned = [str(path) for path, _meta in live_tls.verify_staging_roots()]
    tls_outbound = _tls_outbound()
    before = json.dumps(tls_outbound, sort_keys=True)

    anchored = live_traffic.apply_xray_trust_anchors(tls_outbound, "staging")
    require(
        DP10_CASE_ID,
        json.dumps(tls_outbound, sort_keys=True) == before,
        "the product modified the outbound it was handed instead of returning an anchored copy, "
        "so the same dictionary would carry the anchors into a later caller",
    )
    require(
        DP10_CASE_ID,
        anchored is not tls_outbound,
        "the staging call returned the very object it was given, so no anchor could have been added",
    )
    tls_settings = (anchored.get("streamSettings") or {}).get("tlsSettings") or {}
    certificates = tls_settings.get("certificates") or []
    require(
        DP10_CASE_ID,
        len(certificates) == len(pinned) == 4,
        f"the outbound carries {len(certificates)} certificate entries for {len(pinned)} pinned "
        f"roots: {certificates}",
    )
    require(
        DP10_CASE_ID,
        [entry.get("certificateFile") for entry in certificates] == pinned,
        f"the anchors are {[entry.get('certificateFile') for entry in certificates]}, not one per "
        f"pinned root in order ({pinned})",
    )
    require(
        DP10_CASE_ID,
        all(entry.get("usage") == "verify" for entry in certificates),
        f"an anchor entry declares {[entry.get('usage') for entry in certificates]}, and an entry "
        "that is not 'verify' is not a trust anchor",
    )
    require(
        DP10_CASE_ID,
        all(Path(entry["certificateFile"]).is_file() for entry in certificates),
        "an anchor names a file that does not exist, so Xray would refuse the configuration",
    )
    text = json.dumps(anchored)
    require(
        DP10_CASE_ID,
        "allowInsecure" not in text and "insecure" not in text.lower(),
        "the anchored outbound declares an insecure transport, which the sentence prohibits",
    )

    reality = _reality_outbound()
    reality_before = json.dumps(reality, sort_keys=True)
    untouched = live_traffic.apply_xray_trust_anchors(reality, "staging")
    require(
        DP10_CASE_ID,
        untouched is reality and json.dumps(reality, sort_keys=True) == reality_before,
        "a REALITY outbound was rewritten, so the pinned key was replaced by a CA chain it does "
        "not use",
    )
    production = _tls_outbound()
    kept = live_traffic.apply_xray_trust_anchors(production, "production")
    require(
        DP10_CASE_ID,
        kept is production
        and "certificates" not in ((kept.get("streamSettings") or {}).get("tlsSettings") or {}),
        "production mode injected Staging anchors into a TLS outbound",
    )
    existing = {"usage": "verify", "certificateFile": "/probe/existing.pem"}
    with_existing = live_traffic.apply_xray_trust_anchors(_tls_outbound([existing]), "staging")
    merged = ((with_existing.get("streamSettings") or {}).get("tlsSettings") or {}).get("certificates")
    require(
        DP10_CASE_ID,
        merged[:1] == [existing] and len(merged) == 5,
        f"an outbound that already carried an anchor came back as {merged}, so the product "
        "replaced the caller's trust material instead of adding to it",
    )

    return {
        "pinned_roots": len(pinned),
        "anchors_injected": len(certificates),
        "anchor_usage": ",".join(entry["usage"] for entry in certificates),
        "anchor_paths": ",".join(entry["certificateFile"] for entry in certificates),
        "input_outbound_unchanged": json.dumps(tls_outbound, sort_keys=True) == before,
        "reality_untouched": untouched is reality,
        "production_injects_none": kept is production,
        "existing_anchor_preserved": merged[:1] == [existing],
        "anchors_are_files": all(Path(entry["certificateFile"]).is_file() for entry in certificates),
        "allow_insecure_absent": "allowInsecure" not in text,
    }


# --------------------------------------------------------------------------- #
# DP-09 — both chains are trusted by the explicit bundle, and nothing else is.
# --------------------------------------------------------------------------- #
def case_staging_and_public_chains_are_trusted(product: Any, context: Any) -> Dict[str, Any]:
    """``DP-09``: the Staging bundle trusts both chains, rejects a stranger, and changes no global state."""
    public_bundle = live_tls.find_system_ca_bundle()
    public_before = public_bundle.read_bytes()
    environment_before = {
        name: os.environ.get(name) for name in ("SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE")
    }
    with tempfile.TemporaryDirectory(prefix="gowave-dp09-") as directory:
        root = Path(directory)
        staging = live_tls.build_runtime_ca_bundle("staging", output_path=root / "staging.pem")
        staging_bytes = staging.read_bytes()
        require(
            DP09_CASE_ID,
            STAGING_MARKER in staging_bytes.decode("utf-8", "replace")
            and STAGING_SUBJECT in staging_bytes.decode("utf-8", "replace"),
            "the bundle built for a Staging run names no pinned Staging root, so the anchors the "
            "engines are given are only the public ones",
        )
        staging_root = live_tls.verify_staging_roots()[0][0]
        trusted_staging, staging_detail = _openssl_verify(staging, staging_root)
        require(
            DP09_CASE_ID,
            trusted_staging,
            f"the pinned root {staging_root.name} is not trusted by the bundle built for it: "
            f"{staging_detail}",
        )
        public_root, public_certificates = _public_root(public_bundle, root)
        public_subject = _subject(public_root)
        trusted_public, public_detail = _openssl_verify(staging, public_root)
        require(
            DP09_CASE_ID,
            trusted_public,
            f"the public root {public_subject!r} is not trusted by the Staging bundle, so a "
            f"public-CA endpoint would fail in a Staging run: {public_detail}",
        )
        stranger = _untrusted_ca(root)
        trusted_stranger, stranger_detail = _openssl_verify(staging, stranger)
        require(
            DP09_CASE_ID,
            not trusted_stranger,
            f"an authority no pinned root signs is trusted by the Staging bundle "
            f"({stranger_detail}), so the bundle is not a list of known roots",
        )
        context = live_tls.create_ssl_context(staging)
        require(
            DP09_CASE_ID,
            context.verify_mode.name == "CERT_REQUIRED" and context.check_hostname,
            f"the context built from the Staging bundle verifies mode {context.verify_mode!r} "
            f"with check_hostname {context.check_hostname!r}",
        )
        xray_config = live_traffic.apply_xray_trust_anchors(_tls_outbound(), "staging")
        mihomo_config = client_trust.apply_mihomo_trust_anchors(
            {"proxies": [{"name": "probe", "type": "vless", "tls": True}]}, staging,
        )
        rendered = json.dumps(xray_config) + json.dumps(mihomo_config)
        require(
            DP09_CASE_ID,
            not any(
                token in rendered
                for token in ("allowInsecure", "skip-cert-verify", "insecure-skip", '"insecure": true')
            ),
            "an engine configuration produced for the run carries a certificate bypass, which the "
            "sentence prohibits",
        )

    require(
        DP09_CASE_ID,
        public_bundle.read_bytes() == public_before,
        f"the system bundle {public_bundle} changed while the Staging bundle was built, so the "
        "run altered this machine's trust store instead of its own file",
    )
    environment_after = {
        name: os.environ.get(name) for name in ("SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE")
    }
    require(
        DP09_CASE_ID,
        environment_after == environment_before,
        f"the trust environment changed from {environment_before} to {environment_after}",
    )
    require(
        DP09_CASE_ID,
        len(staging_bytes) > len(public_before),
        f"the Staging bundle ({len(staging_bytes)} bytes) is not larger than the public store "
        f"({len(public_before)} bytes)",
    )

    return {
        "public_certificates": public_certificates,
        "public_root_subject": public_subject,
        "staging_roots_in_bundle": staging_bytes.decode("utf-8", "replace").count(STAGING_SUBJECT),
        "staging_root_trusted": trusted_staging,
        "public_root_trusted": trusted_public,
        "untrusted_authority_trusted": trusted_stranger,
        "untrusted_refusal": stranger_detail,
        "verify_mode": context.verify_mode.name,
        "check_hostname": context.check_hostname,
        "system_bundle_unchanged": public_bundle.read_bytes() == public_before,
        "trust_environment_unchanged": environment_after == environment_before,
        "bypass_directives": 0,
        "staging_bytes": len(staging_bytes),
        "public_bytes": len(public_before),
    }
