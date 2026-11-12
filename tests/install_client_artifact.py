#!/usr/bin/env python3
"""Download, verify and install one pinned client-engine artifact at build time.

The client engines in the acceptance testbed must be exactly the versions the
case matrix pins, and the bytes must be the ones whose SHA-256 was recorded.
This script is build-time tooling for ``tests/Containerfile.client``: it is not
product code and it never runs inside a case, so a broken download cannot turn
an acceptance result into a failure that says nothing about GoWave.

    python3 install_client_artifact.py \
        --url https://.../Xray-linux-64.zip --sha256 <hex> --archive zip \
        --member xray --dest /usr/local/bin/xray --version-arg version --expect "Xray 26.11.9"
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Optional, Sequence

CHUNK = 1 << 20
DOWNLOAD_TIMEOUT_SECONDS = 180


def download(url: str, destination: Path) -> None:
    with urllib.request.urlopen(url, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:
        with destination.open("wb") as handle:
            shutil.copyfileobj(response, handle, CHUNK)


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def extract(archive: Path, kind: str, member: str, destination: Path) -> None:
    if kind == "zip":
        with zipfile.ZipFile(archive) as bundle:
            names = bundle.namelist()
            match = member if member in names else next(
                (name for name in names if name.rsplit("/", 1)[-1] == member), None
            )
            if match is None:
                raise SystemExit(
                    f"{archive.name} carries no {member!r} entry; entries: {', '.join(sorted(names)[:10])}"
                )
            with bundle.open(match) as source, destination.open("wb") as target:
                shutil.copyfileobj(source, target, CHUNK)
    elif kind == "gz":
        with gzip.open(archive, "rb") as source, destination.open("wb") as target:
            shutil.copyfileobj(source, target, CHUNK)
    else:
        raise SystemExit(f"unsupported archive kind: {kind!r}")
    os.chmod(destination, 0o755)


def reported_version(binary: Path, argument: str) -> str:
    proc = subprocess.run([str(binary), argument], capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise SystemExit(
            f"{binary.name} {argument} failed with exit {proc.returncode}: "
            f"{(proc.stderr or proc.stdout).strip()[:400]}"
        )
    return (proc.stdout or proc.stderr).strip()


def install(
    url: str,
    expected_sha256: str,
    archive: str,
    member: str,
    destination: Path,
    expect: str,
    version_argument: str,
) -> dict:
    with tempfile.TemporaryDirectory(prefix="client-artifact-") as tmp:
        local = Path(tmp) / "download"
        download(url, local)
        actual = sha256_of(local)
        if actual != expected_sha256.lower():
            raise SystemExit(
                f"{url} has SHA-256 {actual}, but the matrix pins {expected_sha256}; refusing to install it"
            )
        extract(local, archive, member, destination)

    version = reported_version(destination, version_argument)
    if expect not in version:
        raise SystemExit(
            f"{destination} reports {version!r}, which does not contain the pinned {expect!r}"
        )
    return {
        "url": url,
        "sha256": actual,
        "destination": str(destination),
        "version": version.splitlines()[0] if version else "",
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Install one pinned client-engine artifact")
    parser.add_argument("--url", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--archive", choices=("zip", "gz"), required=True)
    parser.add_argument("--member", default="")
    parser.add_argument("--dest", required=True, type=Path)
    parser.add_argument("--expect", required=True)
    parser.add_argument("--version-arg", default="version")
    args = parser.parse_args(argv)
    facts = install(
        args.url, args.sha256, args.archive, args.member, args.dest, args.expect, args.version_arg
    )
    print(json.dumps(facts, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
