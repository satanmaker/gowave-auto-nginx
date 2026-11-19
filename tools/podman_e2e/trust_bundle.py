#!/usr/bin/env python3
"""The mode-specific CA bundle, and what each mode is allowed to trust.

``openspec/specs/podman-e2e/spec.md`` §Data Plane E2E
Traffic Through All VPN Endpoints says that under ``ACME_MODE=production`` the
runner's bundle carries the complete public roots and no Let's Encrypt Staging
root, that a chain terminating in a Staging root stays untrusted, and that
ordinary public-CA endpoints keep validating. The bundle is built by the
product's own ``tools/live_vps/tls.py::build_runtime_ca_bundle``; the questions
are answered by ``openssl verify`` with that file as the only trust source.

What is real here is the whole of the file: the public half is the Control
Machine's own system bundle, the Staging half is the four vendored roots with
their pinned DER digests, and ``openssl`` decides trust. What is not available is
a leaf chain: the vendored material is trust anchors without their private keys,
so a certificate issued under one cannot be minted offline. The target of the
verification is therefore the pinned root itself, which answers exactly the
question the bundle decides — is this issuer a trust anchor in this file? — and
the case records that substitution in its own evidence.
"""
from __future__ import annotations

import re
import ssl
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Tuple

from tools.live_vps.tls import (
    build_runtime_ca_bundle,
    create_ssl_context,
    find_system_ca_bundle,
    verify_staging_roots,
)
from tools.podman_e2e.runner import require

DP12_CASE_ID = "DP-12"

#: The name the production bundle must carry, and the one a reader can check
#: without trusting this case: the ISRG Root X1 is the public root Let's Encrypt
#: production certificates chain to. If the Control Machine's bundle names no
#: such root, the first root in the file is used instead and recorded.
PUBLIC_ROOT_NAME = "ISRG Root X1"

#: The marker ``build_runtime_ca_bundle`` writes before the Staging roots, and the
#: subject prefix every pinned Staging root carries.
STAGING_MARKER = "Let's Encrypt Staging Roots (Pinned E2E Trust Anchors)"
STAGING_SUBJECT = "(STAGING)"

_PEM_BLOCK = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\n?", re.DOTALL,
)


def _openssl_verify(bundle: Path, certificate: Path) -> Tuple[bool, str]:
    """Does ``bundle`` alone trust ``certificate``? ``openssl`` decides."""
    completed = subprocess.run(
        ["openssl", "verify", "-CAfile", str(bundle), str(certificate)],
        capture_output=True, text=True, timeout=60,
    )
    detail = (completed.stdout + completed.stderr).strip()
    return completed.returncode == 0, detail


def _subject(certificate: Path) -> str:
    completed = subprocess.run(
        ["openssl", "x509", "-in", str(certificate), "-noout", "-subject"],
        capture_output=True, text=True, check=True, timeout=60,
    )
    return completed.stdout.strip()


def _public_root(bundle: Path, directory: Path) -> Tuple[Path, str]:
    """One public root lifted out of the production bundle, with its subject.

    A root the bundle carries is a certificate the bundle can verify: lifting it
    out and asking ``openssl verify`` against the same file proves the root is
    present as a trust anchor rather than merely mentioned in its bytes.
    """
    blocks = _PEM_BLOCK.findall(bundle.read_bytes())
    require(
        DP12_CASE_ID,
        len(blocks) > 1,
        f"the production bundle carries {len(blocks)} certificate(s), so it is not the "
        "complete public root set",
    )
    fallback: Tuple[Path, str] = (Path(), "")
    for index, block in enumerate(blocks):
        candidate = directory / f"public-root-{index}.pem"
        candidate.write_bytes(block)
        subject = _subject(candidate)
        if fallback[1] == "":
            fallback = (candidate, subject)
        if PUBLIC_ROOT_NAME in subject:
            return candidate, subject
    return fallback


def case_production_bundle_excludes_staging(product: Any, context: Any) -> Dict[str, Any]:
    """``DP-12``: production trust is the public roots, and Staging stays outside it."""
    with tempfile.TemporaryDirectory(prefix="gowave-dp12-") as directory:
        root = Path(directory)
        production = build_runtime_ca_bundle("production", output_path=root / "production.pem")
        staging = build_runtime_ca_bundle("staging", output_path=root / "staging.pem")

        public_bundle = find_system_ca_bundle()
        production_bytes = production.read_bytes()
        staging_bytes = staging.read_bytes()
        require(
            DP12_CASE_ID,
            production_bytes == public_bundle.read_bytes(),
            f"the production bundle is not the Control Machine's own public bundle "
            f"({len(production_bytes)} vs {public_bundle.stat().st_size} bytes), so 'the complete "
            "public CA roots' is not what the file contains",
        )
        require(
            DP12_CASE_ID,
            (production.stat().st_mode & 0o777) == 0o600,
            f"the production bundle is mode {oct(production.stat().st_mode & 0o777)}, not 0600",
        )
        production_text = production_bytes.decode("utf-8", errors="replace")
        require(
            DP12_CASE_ID,
            STAGING_MARKER not in production_text and STAGING_SUBJECT not in production_text,
            "the production bundle carries a Let's Encrypt Staging marker, so a Staging root "
            "could have been added without the marker being the only trace of it",
        )

        # The control: the same builder does add them under the other mode, so the
        # absence above is a decision and not an inability.
        verified = verify_staging_roots()
        staging_text = staging_bytes.decode("utf-8", errors="replace")
        require(
            DP12_CASE_ID,
            len(verified) == 4 and STAGING_MARKER in staging_text,
            f"the staging bundle names {len(verified)} pinned roots and "
            f"{'carries' if STAGING_MARKER in staging_text else 'omits'} the marker",
        )
        absent = [meta["subject_cn"] for _path, meta in verified if meta["subject_cn"] not in production_text]
        require(
            DP12_CASE_ID,
            len(absent) == len(verified),
            f"the production bundle names {sorted(set(meta['subject_cn'] for _p, meta in verified) - set(absent))}, "
            "so a pinned Staging root is a trust anchor in production mode",
        )
        require(
            DP12_CASE_ID,
            len(staging_bytes) > len(production_bytes),
            f"the staging bundle ({len(staging_bytes)} bytes) is not the production bundle plus "
            f"the pinned roots ({len(production_bytes)} bytes)",
        )

        # A chain that terminates in a pinned Staging root: the root is the target
        # because the vendored material carries no private key to sign a leaf.
        staging_root = verified[0][0]
        trusted_by_staging, staging_detail = _openssl_verify(staging, staging_root)
        trusted_by_production, production_detail = _openssl_verify(production, staging_root)
        require(
            DP12_CASE_ID,
            trusted_by_staging,
            f"{staging_root.name} is not trusted by the bundle that carries it: {staging_detail}",
        )
        require(
            DP12_CASE_ID,
            not trusted_by_production,
            f"{staging_root.name} is trusted by the production bundle ({production_detail}), so "
            "a chain terminating in a Staging root would validate in production mode",
        )

        # An ordinary public-CA endpoint keeps validating: a public root the
        # production bundle carries, verified against that same file.
        public_root, public_subject = _public_root(production, root)
        trusted_public, public_detail = _openssl_verify(production, public_root)
        require(
            DP12_CASE_ID,
            trusted_public,
            f"the public root {public_subject!r} is not trusted by the production bundle: "
            f"{public_detail}",
        )
        context = create_ssl_context(production)
        require(
            DP12_CASE_ID,
            context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname,
            f"the context built from the production bundle verifies mode "
            f"{context.verify_mode!r} with check_hostname {context.check_hostname!r}",
        )
        refused = ""
        try:
            build_runtime_ca_bundle("staging-and-production", output_path=root / "bogus.pem")
        except ValueError as error:
            refused = str(error)
        require(
            DP12_CASE_ID,
            "staging-and-production" in refused,
            f"an unknown ACME mode was answered with {refused!r}, so the two modes are not the "
            "decision this case reads",
        )
        pinned_names = sorted(meta["subject_cn"] for _path, meta in verified)

    return {
        "production_bytes": len(production_bytes),
        "staging_bytes": len(staging_bytes),
        "public_bundle": public_bundle.name,
        "staging_marker_in_production": STAGING_MARKER in production_text,
        "pinned_roots": len(verified),
        "pinned_root_names": ",".join(pinned_names),
        "staging_root": staging_root.name,
        "staging_root_trusted_by_staging": trusted_by_staging,
        "staging_root_trusted_by_production": trusted_by_production,
        "staging_refusal": production_detail,
        "public_root_subject": public_subject,
        "public_root_trusted": trusted_public,
        "verify_mode": context.verify_mode.name,
        "check_hostname": context.check_hostname,
        "unknown_mode_refusal": refused,
    }
