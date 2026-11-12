"""Immutable image pinning for the Podman product E2E.

Every image the suite starts is referenced through an alias in
``tests/cases/images.lock.yaml`` and resolved to ``repository@sha256:<digest>``.
A tag-only reference is rejected before Podman is invoked, so a mutable upstream
tag can never silently change what the gate validated.

    python3 -m tools.podman_e2e.images check
    python3 -m tools.podman_e2e.images refresh [alias ...]
    python3 -m tools.podman_e2e.images verify
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
LOCK_PATH = REPO_ROOT / "tests" / "cases" / "images.lock.yaml"

SCHEMA = "gowave-podman-images/v1"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REFERENCE_RE = re.compile(
    r"^(?P<registry>[A-Za-z0-9._-]+(?::[0-9]+)?)/"
    r"(?P<repository>[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*)"
    r"(?::(?P<tag>[A-Za-z0-9_][A-Za-z0-9._-]{0,127}))?$"
)

# Aliases the suite cannot run without. Derived from the supported distro list in
# modules/os.sh, the ACME fixture, and the external echo/egress fixture.
REQUIRED_ALIASES: Sequence[str] = (
    "ubuntu-24.04",
    "ubuntu-26.04",
    "debian-12",
    "debian-13",
    "acme-pebble",
    "fixture-echo",
    "client-base",
)

MANIFEST_ACCEPT = ", ".join((
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
))


class ImageLockError(RuntimeError):
    """Raised when an image cannot be resolved to an immutable pinned digest."""


@dataclass(frozen=True)
class ImageEntry:
    alias: str
    reference: str
    digest: str
    role: str

    @property
    def pinned(self) -> str:
        repository = self.reference.rsplit(":", 1)[0] if ":" in self.reference.rsplit("/", 1)[-1] else self.reference
        return f"{repository}@{self.digest}"


def load_lock(path: Path = LOCK_PATH) -> Dict[str, Any]:
    if not path.exists():
        raise ImageLockError(f"{path.relative_to(REPO_ROOT)} is missing; run 'python3 -m tools.podman_e2e.images refresh'")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ImageLockError(f"{path.relative_to(REPO_ROOT)} must contain a mapping")
    return data


def entries(lock: Optional[Dict[str, Any]] = None) -> Dict[str, ImageEntry]:
    data = lock if lock is not None else load_lock()
    result: Dict[str, ImageEntry] = {}
    for alias, raw in (data.get("images") or {}).items():
        if not isinstance(raw, dict):
            raise ImageLockError(f"image alias {alias!r} must be a mapping")
        result[alias] = ImageEntry(
            alias=alias,
            reference=str(raw.get("reference", "")),
            digest=str(raw.get("digest", "")),
            role=str(raw.get("role", "")),
        )
    return result


def validate_lock(lock: Optional[Dict[str, Any]] = None) -> List[str]:
    data = lock if lock is not None else load_lock()
    errors: List[str] = []
    if data.get("schema") != SCHEMA:
        errors.append(f"schema must be {SCHEMA}")
    if data.get("version") != 1:
        errors.append("version must be 1")

    images = data.get("images")
    if not isinstance(images, dict) or not images:
        return errors + ["images must be a non-empty mapping"]

    for alias in REQUIRED_ALIASES:
        if alias not in images:
            errors.append(f"required image alias missing: {alias}")

    for alias, raw in images.items():
        entry = entries({**data, "images": {alias: raw}})[alias]
        if not REFERENCE_RE.match(entry.reference):
            errors.append(f"{alias}: reference {entry.reference!r} is not a fully qualified registry reference")
            continue
        match = REFERENCE_RE.match(entry.reference)
        assert match is not None
        tag = match.group("tag")
        if not tag:
            errors.append(f"{alias}: reference must carry an explicit tag, not just a digest")
        elif tag == "latest":
            errors.append(f"{alias}: floating tag 'latest' is not acceptable; pin a version tag")
        if not DIGEST_RE.match(entry.digest):
            errors.append(f"{alias}: digest {entry.digest!r} is not a sha256 digest")
        if not entry.role:
            errors.append(f"{alias}: role is required")
    return errors


def resolve(alias: str, lock: Optional[Dict[str, Any]] = None) -> str:
    """Return the immutable ``repository@sha256:...`` reference for an alias."""
    if "@" in alias:
        raise ImageLockError(f"pass a lock alias, not a raw reference: {alias}")
    data = entries(lock)
    if alias not in data:
        raise ImageLockError(f"image alias {alias!r} is not pinned in {LOCK_PATH.relative_to(REPO_ROOT)}")
    entry = data[alias]
    if not DIGEST_RE.match(entry.digest):
        raise ImageLockError(f"image alias {alias!r} has no immutable digest")
    return entry.pinned


def resolve_all(aliases: Iterable[str], lock: Optional[Dict[str, Any]] = None) -> List[str]:
    return [resolve(alias, lock) for alias in aliases]


# --------------------------------------------------------------------------- #
# Registry digest resolution (only used by refresh/verify, never by the gate)
# --------------------------------------------------------------------------- #

def split_reference(reference: str) -> Tuple[str, str, str]:
    match = REFERENCE_RE.match(reference)
    if not match:
        raise ImageLockError(f"cannot parse image reference {reference!r}")
    registry = match.group("registry")
    repository = match.group("repository")
    tag = match.group("tag") or ""
    if registry in ("docker.io", "index.docker.io") and "/" not in repository:
        repository = f"library/{repository}"
    return registry, repository, tag


def _http(url: str, headers: Dict[str, str], method: str = "GET") -> Tuple[int, bytes, Dict[str, str]]:
    request = urllib.request.Request(url, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers or {})


def _header(headers: Dict[str, str], name: str) -> str:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return ""


def _registry_token(challenge: str, repository: str) -> str:
    scheme, _, params = challenge.partition(" ")
    if scheme.lower() != "bearer":
        raise ImageLockError(f"unsupported registry auth challenge: {challenge!r}")
    fields = dict(re.findall(r'(\w+)="([^"]*)"', params))
    realm = fields.get("realm")
    if not realm:
        raise ImageLockError("registry auth challenge has no realm")
    query = {"scope": fields.get("scope") or f"repository:{repository}:pull"}
    if fields.get("service"):
        query["service"] = fields["service"]
    status, body, _ = _http(f"{realm}?{urllib.parse.urlencode(query)}", {"Accept": "application/json"})
    if status != 200:
        raise ImageLockError(f"token endpoint returned HTTP {status}")
    payload = json.loads(body.decode("utf-8") or "{}")
    token = payload.get("token") or payload.get("access_token")
    if not token:
        raise ImageLockError("token endpoint returned no token")
    return token


def registry_digest(reference: str) -> str:
    """Resolve a ``registry/repo:tag`` to the manifest digest the tag points at."""
    registry, repository, tag = split_reference(reference)
    if not tag:
        raise ImageLockError(f"{reference!r} has no tag to resolve")
    host = "registry-1.docker.io" if registry in ("docker.io", "index.docker.io") else registry
    url = f"https://{host}/v2/{repository}/manifests/{tag}"
    headers = {"Accept": MANIFEST_ACCEPT}

    status, body, response_headers = _http(url, headers, method="HEAD")
    if status == 401:
        token = _registry_token(_header(response_headers, "WWW-Authenticate"), repository)
        headers["Authorization"] = f"Bearer {token}"
        status, body, response_headers = _http(url, headers, method="HEAD")
    if status == 405:
        status, body, response_headers = _http(url, headers, method="GET")

    if status != 200:
        raise ImageLockError(f"{reference}: registry returned HTTP {status}")
    digest = _header(response_headers, "Docker-Content-Digest")
    if not DIGEST_RE.match(digest):
        digest = f"sha256:{hashlib.sha256(body).hexdigest()}"
    return digest


def resolve_tag(reference: str) -> str:
    return registry_digest(reference)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _write_lock(data: Dict[str, Any], path: Path = LOCK_PATH) -> None:
    text = "# Pinned Podman E2E images. Regenerate with:\n"
    text += "#   python3 -m tools.podman_e2e.images refresh\n"
    text += "# Digests are registry manifest digests; never replace one by hand with a tag.\n"
    text += yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".lock.yaml.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.chmod(0o644)
    tmp.replace(path)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check", help="Validate the lock file offline (no network)")
    refresh = sub.add_parser("refresh", help="Re-resolve digests from upstream registries and rewrite the lock")
    refresh.add_argument("aliases", nargs="*", help="Limit the refresh to these aliases")
    refresh.add_argument("--dry-run", action="store_true", help="Print resolved digests without writing")
    sub.add_parser("verify", help="Fail when an upstream tag no longer matches the locked digest")
    args = parser.parse_args(argv)

    if args.command == "check":
        errors = validate_lock()
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        if errors:
            return 1
        print("IMAGES: PASS")
        return 0

    lock = load_lock()
    if args.command == "refresh":
        targets = args.aliases or list((lock.get("images") or {}).keys())
        unknown = [alias for alias in targets if alias not in (lock.get("images") or {})]
        if unknown:
            print(f"ERROR: unknown aliases: {', '.join(unknown)}", file=sys.stderr)
            return 2
        for alias in targets:
            reference = lock["images"][alias]["reference"]
            try:
                digest = resolve_tag(reference)
            except (ImageLockError, urllib.error.URLError, OSError) as exc:
                print(f"ERROR: {alias} ({reference}): {exc}", file=sys.stderr)
                return 1
            lock["images"][alias]["digest"] = digest
            print(f"{alias}: {reference} -> {digest}")
        if args.dry_run:
            if not validate_lock(lock):
                print("IMAGES: DRY-RUN PASS")
            return 0
        _write_lock(lock)
        errors = validate_lock(load_lock())
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 0 if not errors else 1

    drift: List[str] = []
    for alias, entry in entries(lock).items():
        try:
            actual = resolve_tag(entry.reference)
        except (ImageLockError, urllib.error.URLError, OSError) as exc:
            print(f"ERROR: {alias} ({entry.reference}): {exc}", file=sys.stderr)
            return 1
        if actual != entry.digest:
            drift.append(f"{alias}: locked {entry.digest} but upstream {entry.reference} now resolves to {actual}")
    for item in drift:
        print(f"DRIFT: {item}", file=sys.stderr)
    if drift:
        return 1
    print("IMAGES: PASS (no upstream drift)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
