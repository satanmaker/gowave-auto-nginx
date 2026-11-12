"""All-in-One product acceptance cases.

Every case here runs against one real operator install in one disposable host.
The install is performed once, by the install case, and later cases reuse that
host: a second install would prove something the product never promises, and
re-provisioning per case would hide whether repeated installs are safe.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import topology
from .runner import Case, require

INSTALL_CASE_ID = "AIO-INSTALL"

# The real install downloads releases, resolves packages, and issues three
# certificates; the ceiling is a hang guard, not an expectation.
INSTALL_TIMEOUT_SECONDS = 5400


class AioProduct:
    """One disposable AIO host, installed once by the real operator."""

    def __init__(self, podman: Any, distribution: str = "ubuntu-24.04") -> None:
        self.podman = podman
        self.context = podman.context
        self.distribution = distribution
        self.host: Optional[topology.AioTopology] = None
        self.outcome: Optional[topology.InstallOutcome] = None

    def install(self) -> Dict[str, Any]:
        """Create the disposable host and run the operator install exactly once."""
        if self.host is not None:
            raise AssertionError(
                f"{INSTALL_CASE_ID}: the AIO host is installed once per run and reused by later cases"
            )
        host = topology.AioTopology(self.podman, distribution=self.distribution)
        host.create()
        self.host = host
        self.outcome = host.install()
        require(
            INSTALL_CASE_ID,
            self.outcome.ok,
            f"the operator full install failed with exit {self.outcome.returncode}:\n"
            f"{self.outcome.tail(6000)}",
        )
        return host.evidence(self.outcome)

    def require_installed(self) -> topology.AioTopology:
        """The installed host, for cases that must not provision anything themselves."""
        if self.host is None or self.outcome is None:
            raise AssertionError(
                f"{INSTALL_CASE_ID}: this case needs the AIO install, and no install has run in this suite"
            )
        return self.host


def cases(podman: Any, distribution: str = "ubuntu-24.04") -> List[Case]:
    """The AIO suite: the install case plus every case that reuses its host."""
    product = AioProduct(podman, distribution)
    return [
        Case(
            INSTALL_CASE_ID,
            "aio",
            lambda context: product.install(),
            timeout_seconds=INSTALL_TIMEOUT_SECONDS,
        ),
    ]
