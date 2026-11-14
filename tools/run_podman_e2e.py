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

from tools.podman_e2e import aio, diagnostics, groups, multi_node, target_image  # noqa: E402
from tools.podman_e2e.podman import Podman  # noqa: E402
from tools.podman_e2e.runner import Case, RunContext, Runner  # noqa: E402

TOPOLOGIES = ("aio", "multi-node")

# The install downloads releases and issues certificates; the budget is spent
# across the whole suite, so it must cover a slow network without being open.
# The Multi-Node suite provisions two hosts and moves real traffic through both,
# so its default budget is larger than the single-host one.
DEFAULT_BUDGET_SECONDS = 7200
MULTI_NODE_BUDGET_SECONDS = 10800


def build_suite(
    podman: Podman, topology: str, distribution: str,
    vision: bool = False, worker_vision: bool = False,
) -> List[Case]:
    if topology == "aio":
        return aio.cases(podman, distribution, vision=vision)
    if topology == "multi-node":
        return multi_node.cases(
            podman, distribution, vision=vision, worker_vision=worker_vision,
        )
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
        help=(
            "Install the optional VLESS Vision inbound; the matrix is then 10 cases instead of 8, "
            "or for multi-node 18/20 instead of 16"
        ),
    )
    parser.add_argument(
        "--worker-vision",
        action="store_true",
        help="Configure the optional VLESS Vision inbound on the Multi-Node Worker as well",
    )
    parser.add_argument(
        "--artifact-root",
        type=Path,
        default=REPO_ROOT / "artifacts" / "podman-e2e",
    )
    parser.add_argument("--budget-seconds", type=int, default=None)
    parser.add_argument(
        "--require-group",
        choices=groups.GROUPS,
        default=None,
        help=(
            "Fail the run unless every case id in this group was declared and passed; "
            "a case deleted from the suite would otherwise leave a shorter green run"
        ),
    )
    args = parser.parse_args(argv)

    if args.worker_vision and args.topology != "multi-node":
        parser.error("--worker-vision configures a Worker, and the AIO topology has none")
    if args.require_group:
        try:
            groups.required_ids(args.require_group, args.topology)
        except ValueError as exc:
            parser.error(str(exc))

    budget = args.budget_seconds
    if budget is None:
        budget = MULTI_NODE_BUDGET_SECONDS if args.topology == "multi-node" else DEFAULT_BUDGET_SECONDS

    context = RunContext(
        topology=args.topology,
        artifact_root=args.artifact_root,
        budget_seconds=budget,
    )
    # The selected Vision configuration is part of the run's identity: the
    # matrix owes 8 or 10 positive cases (AIO) or 16/18/20 (Multi-Node).
    context.environment["vision"] = "enabled" if args.vision else "disabled"
    if args.topology == "multi-node":
        context.environment["worker_vision"] = "enabled" if args.worker_vision else "disabled"
    podman = Podman(context)
    # Containers, the network, and run images belong to the run, not the shell.
    podman.register_cleanup()
    runner = Runner(context)
    if args.require_group:
        runner.require_group(args.require_group)
    # A failed case names a contradiction, not its cause, so every non-green case
    # also leaves the state of the run's own containers. The hook reads state and
    # cannot change a verdict, and it runs before the cleanup that removes them.
    runner.on_failure(lambda result: diagnostics.collect(context, podman, result))
    for case in build_suite(
        podman, args.topology, args.distribution,
        vision=args.vision, worker_vision=args.worker_vision,
    ):
        runner.add(case)
    status = runner.execute()
    print(f"artifacts: {context.artifact_dir}")
    return status


if __name__ == "__main__":
    sys.exit(main())
