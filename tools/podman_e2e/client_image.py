"""Pinned client-engine image for the Podman acceptance suite.

The Control Machine role needs real client engines, because "the Panel served a
subscription" is only meaningful when the engine that consumes it is the pinned
one. Both engines are baked into an image built from a digest-pinned base, with
the release artifact pinned by SHA-256 and its reported version re-checked at
build time: a wrong or substituted download fails the build instead of producing
a verdict about the product.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from . import images

REPO_ROOT = images.REPO_ROOT
CONTAINERFILE = REPO_ROOT / "tests" / "Containerfile.client"
INSTALLER = REPO_ROOT / "tests" / "install_client_artifact.py"
MATRIX_PATH = REPO_ROOT / "tests" / "cases" / "matrix.yaml"

BASE_ALIAS = "client-base"
TAG_PREFIX = "gowave-e2e-client"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ARCHIVES = ("zip", "gz")


class ClientImageError(RuntimeError):
    pass


def load_matrix(path: Path = MATRIX_PATH) -> Dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError as exc:
        raise ClientImageError(f"{path.relative_to(REPO_ROOT)} is missing") from exc
    if not isinstance(data, dict):
        raise ClientImageError(f"{path.relative_to(REPO_ROOT)} must contain a mapping")
    return data


def versions(matrix: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    data = matrix if matrix is not None else load_matrix()
    product = data.get("product") or {}
    result: Dict[str, str] = {}
    for client in data.get("clients") or []:
        key = client.get("version_key")
        version = str(product.get(key) or "")
        if not version:
            raise ClientImageError(f"{client.get('id')}: product.{key} must pin the client version")
        result[str(client.get("id"))] = version
    return result


def build_args(matrix: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Build arguments for the Containerfile, derived from the pinned matrix."""
    data = matrix if matrix is not None else load_matrix()
    pinned = versions(data)
    arguments: Dict[str, str] = {}
    for client in data.get("clients") or []:
        client_id = str(client.get("id"))
        artifact = client.get("artifact") or {}
        check = client.get("version_check") or {}
        url = str(artifact.get("url") or "")
        digest = str(artifact.get("sha256") or "")
        archive = str(artifact.get("archive") or "")
        contains = str(check.get("contains") or "")
        if not url or not digest:
            raise ClientImageError(f"{client_id}: artifact url and sha256 are required")
        if not SHA256_RE.match(digest):
            raise ClientImageError(f"{client_id}: artifact sha256 {digest!r} is not a sha256 digest")
        if archive not in ARCHIVES:
            raise ClientImageError(f"{client_id}: archive must be one of {', '.join(ARCHIVES)}")
        version = pinned[client_id]
        if version not in url:
            raise ClientImageError(
                f"{client_id}: artifact url does not carry the pinned version {version!r}: {url}"
            )
        if not contains:
            raise ClientImageError(f"{client_id}: version_check.contains is required")
        prefix = client_id.upper()
        arguments[f"{prefix}_URL"] = url
        arguments[f"{prefix}_SHA256"] = digest
        arguments[f"{prefix}_EXPECT"] = contains
    return arguments


def tag(matrix: Optional[Dict[str, Any]] = None) -> str:
    pinned = versions(matrix)
    return f"{TAG_PREFIX}:{'-'.join(sorted(pinned.values()))}"


def containerfile() -> str:
    """The client Containerfile, validated against the pinning contract."""
    if not CONTAINERFILE.is_file():
        raise ClientImageError(f"{CONTAINERFILE.relative_to(REPO_ROOT)} is missing")
    if not INSTALLER.is_file():
        raise ClientImageError(f"{INSTALLER.relative_to(REPO_ROOT)} is missing")
    text = CONTAINERFILE.read_text(encoding="utf-8")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    if "ARG BASE_IMAGE=docker.io/library/" not in code:
        raise ClientImageError("the client image must declare a pinned BASE_IMAGE build argument")
    if "FROM ${BASE_IMAGE}" not in code:
        raise ClientImageError("the client image must build from ${BASE_IMAGE}")
    if "install_client_artifact.py" not in code:
        raise ClientImageError("the client image must install its engines through the verifying installer")
    for argument in ("XRAY_SHA256", "MIHOMO_SHA256"):
        if f'"${{{argument}}}"' not in code:
            raise ClientImageError(f"the client image must verify {argument}")
    for command in ("curl", "wget", "apt-get", "apk add"):
        if command in code:
            raise ClientImageError(
                f"the client image must not use {command!r}: the base image ships python3 and "
                "the installer verifies every byte"
            )
    if re.search(r'--version-arg\s+"?-', code):
        # argparse claims a bare '-v' as its own flag, so the build fails on the
        # engine whose banner is requested with a leading dash.
        raise ClientImageError(
            "the client image must pass a leading-dash version argument as "
            "--version-arg=<arg>; a space-separated '-v' is consumed by argparse"
        )
    return text


def build(podman: Any, context_dir: Optional[Path] = None) -> str:
    """Build the client image once per run and return its local tag."""
    containerfile()
    matrix = load_matrix()
    image_tag = tag(matrix)
    podman.build(
        tag=image_tag,
        base_alias=BASE_ALIAS,
        containerfile=CONTAINERFILE,
        context_dir=Path(context_dir) if context_dir else CONTAINERFILE.parent,
        build_args=build_args(matrix),
    )
    return image_tag


def engine_list(matrix: Optional[Dict[str, Any]] = None) -> List[Dict[str, str]]:
    """The engines a case may run, as ``{id, binary, argument, contains}``."""
    data = matrix if matrix is not None else load_matrix()
    engines: List[Dict[str, str]] = []
    for client in data.get("clients") or []:
        check = client.get("version_check") or {}
        engines.append({
            "id": str(client.get("id")),
            "binary": str(client.get("binary") or client.get("id")),
            "argument": str(check.get("argument") or "version"),
            "contains": str(check.get("contains") or ""),
        })
    return engines
