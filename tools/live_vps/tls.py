"""TLS trust store and scoped CA bundle manager for Live VPS E2E testing.
Manages mode-specific CA bundles with reproducible Let's Encrypt Staging CA pinning.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

STAGING_CERTS_DIR = Path(__file__).resolve().parent.parent / "certs" / "letsencrypt-staging"


def find_system_ca_bundle() -> Path:
    """Resolve the Control Machine's complete default public CA bundle."""
    candidates: List[Path] = []
    verify_paths = ssl.get_default_verify_paths()
    if verify_paths.cafile:
        candidates.append(Path(verify_paths.cafile))

    candidates.extend([
        Path("/etc/ssl/certs/ca-certificates.crt"),
        Path("/etc/pki/tls/certs/ca-bundle.crt"),
        Path("/etc/ssl/cert.pem"),
        Path("/etc/ssl/ca-bundle.pem"),
    ])

    for p in candidates:
        if p.is_file() and p.stat().st_size > 0:
            return p.resolve()

    raise FileNotFoundError(
        "Control Machine public CA bundle could not be found. Verified paths: "
        + ", ".join(str(c) for c in candidates)
    )


def verify_staging_roots(staging_dir: Path = STAGING_CERTS_DIR) -> List[Tuple[Path, Dict[str, Any]]]:
    """Verify all vendored Let's Encrypt Staging roots against pins.json.
    Enforces exactly 4 unique roots, CA:TRUE, self-signature, validity window, and DER SHA-256.
    """
    staging_dir = Path(staging_dir)
    if staging_dir.is_symlink() or not staging_dir.is_dir():
        raise FileNotFoundError(f"Staging certificates directory must be a non-symlink directory: {staging_dir}")
    staging_root = staging_dir.resolve()

    pins_file = staging_dir / "pins.json"
    if pins_file.is_symlink() or not pins_file.is_file():
        raise FileNotFoundError(f"Pins manifest must be a non-symlink regular file: {pins_file}")

    try:
        manifest = json.loads(pins_file.read_text(encoding="utf-8"))
    except Exception as e:
        raise ValueError(f"Malformed pins.json: {e}")

    if not isinstance(manifest, dict):
        raise ValueError("Malformed pins.json: root must be an object")
    roots = manifest.get("roots")
    if not isinstance(roots, list):
        raise ValueError("Malformed pins.json: roots must be a list")
    if len(roots) != 4:
        raise ValueError(f"Expected exactly 4 Staging roots in pins.json, found {len(roots)}")

    required_fields = {"file", "subject_cn", "der_sha256"}
    pinned_files = []
    seen_names = set()
    for index, item in enumerate(roots):
        if not isinstance(item, dict) or not required_fields.issubset(item):
            raise ValueError(f"Malformed pins.json: root entry {index} must contain file, subject_cn, and der_sha256")
        file_name = item["file"]
        subject_cn = item["subject_cn"]
        digest = item["der_sha256"]
        if (
            not isinstance(file_name, str)
            or not file_name.endswith(".pem")
            or Path(file_name).name != file_name
            or file_name in (".pem", ".", "..")
        ):
            raise ValueError(f"Malformed pins.json: invalid certificate filename at root entry {index}")
        if file_name in seen_names:
            raise ValueError(f"Malformed pins.json: duplicate certificate filename '{file_name}'")
        seen_names.add(file_name)
        if not isinstance(subject_cn, str) or not subject_cn.strip():
            raise ValueError(f"Malformed pins.json: invalid subject_cn at root entry {index}")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-fA-F]{64}", digest) is None:
            raise ValueError(f"Malformed pins.json: invalid DER SHA-256 at root entry {index}")
        pinned_files.append(file_name)

    # Verify no extra .pem files exist in staging_dir.
    actual_pem_files = sorted(p.name for p in staging_dir.glob("*.pem"))
    if actual_pem_files != sorted(pinned_files):
        raise ValueError(
            f"Staging certificate file mismatch: actual {actual_pem_files} != pinned {sorted(pinned_files)}"
        )

    verified: List[Tuple[Path, Dict[str, Any]]] = []
    seen_digests = set()

    for item in roots:
        file_name = item["file"]
        expected_cn = item["subject_cn"]
        expected_sha = item["der_sha256"].lower()

        pem_path = staging_dir / file_name
        if pem_path.is_symlink() or not pem_path.is_file() or pem_path.resolve().parent != staging_root:
            raise ValueError(f"Pinned root PEM must be a non-symlink regular file inside staging directory: {pem_path}")

        # Check DER SHA-256
        res_der = subprocess.run(
            ["openssl", "x509", "-in", str(pem_path), "-outform", "DER"],
            capture_output=True,
            check=True,
        )
        der_bytes = res_der.stdout
        actual_sha = hashlib.sha256(der_bytes).hexdigest().lower()
        if actual_sha != expected_sha:
            raise ValueError(
                f"Digest mismatch for {file_name}: expected {expected_sha}, got {actual_sha}"
            )
        if actual_sha in seen_digests:
            raise ValueError(f"Duplicate certificate digest found in pins.json: {actual_sha}")
        seen_digests.add(actual_sha)

        # Subject check
        res_subj = subprocess.run(
            ["openssl", "x509", "-in", str(pem_path), "-noout", "-subject"],
            capture_output=True,
            text=True,
            check=True,
        )
        if expected_cn not in res_subj.stdout:
            raise ValueError(
                f"Subject mismatch for {file_name}: expected CN '{expected_cn}' in '{res_subj.stdout.strip()}'"
            )

        # Self-signature check (issuer must equal subject)
        res_issuer = subprocess.run(
            ["openssl", "x509", "-in", str(pem_path), "-noout", "-issuer"],
            capture_output=True,
            text=True,
            check=True,
        )
        if res_subj.stdout.replace("subject=", "").strip() != res_issuer.stdout.replace("issuer=", "").strip():
            raise ValueError(f"Root certificate {file_name} is not self-signed")

        # Validity window check
        res_valid = subprocess.run(
            ["openssl", "x509", "-in", str(pem_path), "-noout", "-checkend", "0"],
            capture_output=True,
        )
        if res_valid.returncode != 0:
            raise ValueError(f"Root certificate {file_name} is expired or not valid yet")

        # CA constraints check (must have CA:TRUE)
        res_text = subprocess.run(
            ["openssl", "x509", "-in", str(pem_path), "-noout", "-text"],
            capture_output=True,
            text=True,
            check=True,
        )
        if "CA:TRUE" not in res_text.stdout:
            raise ValueError(f"Certificate {file_name} lacks basicConstraints CA:TRUE")

        verified.append((pem_path, item))

    return verified


def build_runtime_ca_bundle(
    acme_mode: str,
    output_path: Path | None = None,
    staging_dir: Path = STAGING_CERTS_DIR,
) -> Path:
    """Build a private mode-0600 combined CA bundle for the current test run.
    - If acme_mode is 'staging', combines system public roots with the 4 verified Staging roots.
    - If acme_mode is 'production', contains system public roots only (staging roots are never added).
    """
    public_bundle = find_system_ca_bundle()
    public_bytes = public_bundle.read_bytes()

    if output_path is None:
        fd, tmp_file = tempfile.mkstemp(prefix="gowave-e2e-ca-bundle-", suffix=".crt")
        os.close(fd)
        target_path = Path(tmp_file)
    else:
        target_path = Path(output_path)
        target_path.parent.mkdir(parents=True, exist_ok=True)

    mode = acme_mode.lower()
    if mode == "staging":
        verified_roots = verify_staging_roots(staging_dir)
        staging_blocks = []
        for pem_path, meta in verified_roots:
            staging_blocks.append(f"# {meta['subject_cn']}\n".encode("utf-8") + pem_path.read_bytes())
        staging_bytes = b"\n".join(staging_blocks)
        bundle_content = public_bytes + b"\n\n# Let's Encrypt Staging Roots (Pinned E2E Trust Anchors)\n" + staging_bytes
    elif mode == "production":
        bundle_content = public_bytes
    else:
        raise ValueError(f"Invalid acme_mode: '{acme_mode}'. Must be 'staging' or 'production'.")

    target_path.write_bytes(bundle_content)
    target_path.chmod(0o600)
    return target_path


def create_ssl_context(ca_bundle_path: Path | str) -> ssl.SSLContext:
    """Create a strict SSLContext using the specified CA bundle with hostname verification."""
    ctx = ssl.create_default_context(cafile=str(ca_bundle_path))
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx
