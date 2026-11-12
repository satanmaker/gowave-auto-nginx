#!/usr/bin/env python3
"""Entrypoint for the full product Podman E2E.

Runs real operator installs inside disposable systemd hosts, with a local
resolver and a local ACME directory pinned for the run, and reports every case
as a structured result. No live credential, live host, or public DNS name is
involved.

    python3 -m tools.run_podman_e2e --topology aio

The exit status is 0 only when every declared case passed.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import aio, target_image  # noqa: E402
from tools.podman_e2e.podman import Podman  # noqa: E402
from tools.podman_e2e.runner import Case, RunContext, Runner  # noqa: E402

TOPOLOGIES = ("aio",)

# The install downloads releases and issues certificates; the budget is spent
# across the whole suite, so it must cover a slow network without being open.
DEFAULT_BUDGET_SECONDS = 7200


def build_suite(podman: Podman, topology: str, distribution: str, vision: bool = False) -> List[Case]:
    if topology == "aio":
        return aio.cases(podman, distribution, vision=vision)
    raise ValueError(f"unsupported topology: {topology!r}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--topology", choices=TOPOLOGIES, default="aio")
    parser.add_argument(
        "--distribution",
        choices=sorted(target_image.DISTRIBUTIONS),
        default="ubuntu-24.04",
        help="Target distribution alias from tests/cases/images.lock.yaml",
    )
    parser.add_argument(
        "--vision",
        action="store_true",
        help="Install the optional VLESS Vision inbound, which makes the matrix 10 cases instead of 8",
    )
    parser.add_argument(
        "--artifact-root",
        type=Path,
        default=REPO_ROOT / "artifacts" / "podman-e2e",
    )
    parser.add_argument("--budget-seconds", type=int, default=DEFAULT_BUDGET_SECONDS)
    args = parser.parse_args(argv)

    context = RunContext(
        topology=args.topology,
        artifact_root=args.artifact_root,
        budget_seconds=args.budget_seconds,
    )
    # The selected Vision configuration is part of the run's identity: the
    # matrix owes 8 or 10 positive cases depending on it.
    context.environment["vision"] = "enabled" if args.vision else "disabled"
    podman = Podman(context)
    # Containers, the network, and run images belong to the run, not the shell.
    podman.register_cleanup()
    runner = Runner(context)
    for case in build_suite(podman, args.topology, args.distribution, vision=args.vision):
        runner.add(case)
    status = runner.execute()
    print(f"artifacts: {context.artifact_dir}")
    return status


if __name__ == "__main__":
    sys.exit(main())
