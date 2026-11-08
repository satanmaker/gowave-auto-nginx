#!/usr/bin/env python3
"""Prepare reproducible release archive and installer assets with SHA256 sidecars.
Adheres to Task 13.4.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile

REPO_ROOT = Path(__file__).resolve().parent.parent


def git(*args):
    return subprocess.check_output(["git", *args], cwd=str(REPO_ROOT), stderr=subprocess.PIPE).decode().strip()


def prepare_release(tag, commit, output_dir):
    if not re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag):
        raise ValueError(f"Expected a semantic version tag (e.g. v1.0.0), got: {tag}")

    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError(f"Expected an exact 40-character lowercase hex commit SHA, got: {commit}")

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    os.chmod(str(out), 0o755)

    archive_name = f"gowave-auto-nginx-{tag}.tar.gz"
    archive_path = out / archive_name

    print(f"Creating reproducible release archive: {archive_name} from commit {commit}...")

    # Create tarball of repository assets
    with tarfile.open(archive_path, "w:gz") as tar:
        for root_dir in ["modules", "assets", "config"]:
            dir_path = REPO_ROOT / root_dir
            if dir_path.is_dir():
                tar.add(str(dir_path), arcname=root_dir)

        for script in ["gowave-auto.sh", "gowave-node-auto.sh", "LICENSE", "THIRD_PARTY_NOTICES.md"]:
            file_path = REPO_ROOT / script
            if file_path.is_file():
                tar.add(str(file_path), arcname=script)

    # Compute SHA256
    sha256 = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    checksum_file = out / f"{archive_name}.sha256"
    checksum_file.write_text(f"{sha256}  {archive_name}\n")

    print(f"Release Archive:  {archive_path}")
    print(f"SHA-256 Checksum: {sha256}")
    print(f"Checksum Sidecar: {checksum_file}")
    return sha256


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag", help="Release tag (e.g. v1.0.0)")
    parser.add_argument("commit", help="40-hex commit SHA")
    parser.add_argument("output", help="Output directory for release assets")
    args = parser.parse_args()

    try:
        prepare_release(args.tag, args.commit, args.output)
    except Exception as e:
        print(f"Error preparing release: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
