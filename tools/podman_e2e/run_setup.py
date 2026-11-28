"""The per-run setup record that makes a kept cell adoptable.

A run allocates its network plan, creates its fixture directories, mints the
per-run CA material and names its containers. All of that lived in the memory of
the process that performed it, so ``--reuse`` could resolve a kept run and prove
its containers alive and still had no way to attach to them: the addresses, the
fixture paths and the secret directory were gone. This module owns the file that
carries those facts out of the process.

The record is written by the topology at the moment it creates its hosts, and
read back only by an adopting run. It is not evidence about the product: it
describes the harness machinery a later invocation must rebuild before it can
run a case. It therefore holds paths, addresses, names and image references —
never a credential, a key or a token.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

# The schema is versioned because an adopting process reads a file written by an
# earlier revision of the suite, and a record it cannot interpret must be
# refused instead of half-understood.
SETUP_SCHEMA = "gowave-podman-e2e-run-setup/v1"
SETUP_FILE_NAME = "run-setup.json"

# Every key an adopting run reads. A record missing one is not adoptable and
# says which key it lacks, rather than failing later with a KeyError inside a
# case that has already spent product time.
REQUIRED_KEYS: Sequence[str] = (
    "schema",
    "run_id",
    "topology",
    "distribution",
    "vision",
    "artifact_root",
    "secret_dir",
    "fixtures",
    "network",
    "addresses",
    "containers",
    "started",
    "images",
    "domains",
    "admin_email",
    "egress_resolvers",
    "ipv6",
    "backup_volumes",
    "acme",
    "pre_install",
    "pre_install_worker",
)

REQUIRED_SECTIONS: Dict[str, Sequence[str]] = {
    "vision": ("enabled", "worker_enabled", "combination"),
    "fixtures": ("dns", "echo", "acme", "client_ca", "payloads"),
    "network": ("control", "data"),
    "addresses": (
        "dns", "target", "target_data", "pebble", "echo", "echo_data", "client",
        "engine_client", "engine_client_data", "worker", "worker_data",
        "second_node", "untrusted",
    ),
    "containers": ("dns", "target", "echo", "client", "engine_client", "acme"),
    "images": ("target", "client", "fixture", "acme", "resolved"),
    "domains": (
        "panel", "reality", "vision", "worker", "worker_reality", "worker_vision",
        "cover_apex", "dns_zone",
    ),
    "ipv6": ("enabled", "address"),
    "acme": ("management_host_port",),
}

# The sections whose values are paths the adopting process must still find.
FIXTURE_KEYS: Sequence[str] = ("dns", "echo", "acme", "client_ca", "payloads")

# The facts without which nothing can be rebuilt: each is a non-empty string.
STRING_KEYS: Sequence[str] = (
    "run_id", "topology", "distribution", "artifact_root", "secret_dir", "admin_email",
)


class RunSetupError(RuntimeError):
    """The named run left no usable setup record, so it cannot be adopted."""


def write_setup(directory: Path, payload: Dict[str, Any], name: str = SETUP_FILE_NAME) -> Path:
    """Write the record atomically, mode 0600, and fsync the directory entry.

    A record half-written by a killed run would name paths that do not exist; the
    temporary sibling and the rename make the file appear whole or not at all,
    exactly as ``result.json`` is written.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / name
    tmp = directory / f".{name}.tmp"
    text = json.dumps(payload, indent=2, sort_keys=True)
    with tmp.open("w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    tmp.chmod(0o600)
    os.replace(tmp, path)
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return path


def setup_path(run_dir: Path) -> Path:
    return Path(run_dir) / SETUP_FILE_NAME


def read_setup(run_dir: Path) -> Dict[str, Any]:
    """Read and structurally validate a run's setup record.

    Raises ``RunSetupError`` naming the file and the first thing wrong with it.
    Structural only: whether the files and containers it names still exist is a
    question for the caller, which has Podman.
    """
    path = setup_path(run_dir)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise RunSetupError(
            f"{path} is missing: the run recorded no setup record, so the network plan, "
            "fixture directories and secret directory it used cannot be rebuilt"
        ) from None
    except OSError as exc:
        raise RunSetupError(f"{path} could not be read: {exc}") from exc
    try:
        record = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RunSetupError(f"{path} is not JSON: {exc}") from exc
    problems = validate_setup(record)
    if problems:
        raise RunSetupError(f"{path} is not an adoptable setup record: " + "; ".join(problems))
    return record


def validate_setup(record: Any) -> List[str]:
    """Structural problems with a record, as sentences an operator can act on."""
    if not isinstance(record, dict):
        return ["the record is not a JSON object"]
    problems: List[str] = []
    schema = record.get("schema")
    if schema != SETUP_SCHEMA:
        problems.append(f"schema is {schema!r}, not {SETUP_SCHEMA!r}")
    for key in REQUIRED_KEYS:
        if key not in record:
            problems.append(f"{key} is missing")
    for key in STRING_KEYS:
        value = record.get(key)
        if key in record and not (isinstance(value, str) and value.strip()):
            problems.append(f"{key} must be a non-empty string")
    for section, keys in REQUIRED_SECTIONS.items():
        value = record.get(section)
        if section not in record:
            continue
        if not isinstance(value, dict):
            problems.append(f"{section} must be an object")
            continue
        for key in keys:
            if key not in value:
                problems.append(f"{section}.{key} is missing")
    network = record.get("network")
    if isinstance(network, dict):
        for side in ("control", "data"):
            block = network.get(side)
            if not isinstance(block, dict):
                problems.append(f"network.{side} must be an object")
                continue
            for key in ("name", "subnet"):
                if not isinstance(block.get(key), str) or not block.get(key):
                    problems.append(f"network.{side}.{key} must be a non-empty string")
    containers = record.get("containers")
    if isinstance(containers, dict):
        for key in REQUIRED_SECTIONS["containers"]:
            value = containers.get(key)
            if key in containers and not isinstance(value, str):
                problems.append(f"containers.{key} must be a string")
    started = record.get("started")
    if "started" in record and not (
        isinstance(started, list) and all(isinstance(name, str) for name in started)
    ):
        problems.append("started must be a list of container names")
    resolvers = record.get("egress_resolvers")
    if "egress_resolvers" in record and not (
        isinstance(resolvers, list) and all(isinstance(entry, str) for entry in resolvers)
    ):
        problems.append("egress_resolvers must be a list of addresses")
    return problems


def required_paths(record: Dict[str, Any]) -> List[Tuple[str, Path]]:
    """Every path the adoption must still find, labelled as the refusal names it.

    The secret directory and each fixture directory are listed separately rather
    than by the secret directory alone: a fixture that was pruned while its
    parent survived is exactly the incomplete cell the refusal has to name.
    """
    fixtures = record.get("fixtures") or {}
    entries: List[Tuple[str, Path]] = []
    secret = str(record.get("secret_dir") or "")
    if secret:
        entries.append(("secret directory", Path(secret)))
    labels = {
        "dns": "fixture resolver directory",
        "echo": "echo fixture directory",
        "acme": "ACME fixture directory",
        "client_ca": "client CA directory",
        "payloads": "payload directory",
    }
    for key in FIXTURE_KEYS:
        value = fixtures.get(key)
        if isinstance(value, str) and value:
            entries.append((labels[key], Path(value)))
    return entries
