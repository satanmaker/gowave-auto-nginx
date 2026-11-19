"""Privilege scopes for the Podman E2E gate.

Two scopes exist and they are not interchangeable:

* ``rootful`` — the product gate. Everything that installs GoWave, starts
  systemd services, binds 80/443, or proves INPUT firewall isolation.
* ``rootless`` — harness self-checks only (catalog parity, image pinning,
  matrix schema, runner contracts). It never claims product acceptance,
  because rootless Podman cannot manipulate host nftables or bind low ports.

A rootless invocation must therefore run the self-check entrypoint, not the
product suite; asking for the product scope without root privileges fails
closed instead of silently degrading.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

from .podman import PodmanUnavailable, require_rootful


@dataclass(frozen=True)
class Scope:
    name: str
    rootful: bool
    checks: Tuple[str, ...]
    reason: str


ROOTLESS_CHECKS: Tuple[str, ...] = (
    "catalog-parity",
    "image-lock",
    "matrix-schema",
    "harness-contracts",
)

ROOTFUL_ONLY_REASONS: Tuple[str, ...] = (
    "privileged systemd container boot",
    "host firewall (UFW/nftables) INPUT isolation",
    "listener binding on 80/443",
    "Worker mTLS control plane and port 3002 isolation",
    "Panel and NGINX service supervision",
)

SCOPES: Dict[str, Scope] = {
    "rootless": Scope(
        name="rootless",
        rootful=False,
        checks=ROOTLESS_CHECKS,
        reason="Static contract self-checks only; product acceptance is not claimed.",
    ),
    "rootful": Scope(
        name="rootful",
        rootful=True,
        checks=("product-suite",),
        reason="Full product acceptance; requires rootful Podman with cgroup v2.",
    ),
}


def scope(name: str) -> Scope:
    try:
        return SCOPES[name]
    except KeyError as exc:
        raise ValueError(f"unknown privilege scope {name!r}; expected one of {sorted(SCOPES)}") from exc


def assert_scope_available(name: str) -> Scope:
    """Fail closed when the requested scope cannot be honestly executed."""
    selected = scope(name)
    if selected.rootful:
        try:
            require_rootful()
        except PodmanUnavailable as exc:
            raise PodmanUnavailable(
                f"scope {name!r} requires rootful Podman: {exc}. "
                f"Use the rootless self-check scope ({', '.join(ROOTLESS_CHECKS)}) instead."
            ) from exc
    return selected


def describe() -> List[str]:
    lines = []
    for name in sorted(SCOPES):
        selected = SCOPES[name]
        lines.append(f"{name}: {'rootful' if selected.rootful else 'rootless'} — {selected.reason}")
    return lines
