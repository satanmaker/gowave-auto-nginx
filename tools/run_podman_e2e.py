#!/usr/bin/env python3
"""Entrypoint for the full product Podman E2E.

Runs real operator installs inside disposable systemd hosts, with a local
resolver and a local ACME directory pinned for the run, and reports every case
as a structured result. No live credential, live host, or public DNS name is
involved.

    python3 -m tools.run_podman_e2e --topology aio

The exit status is 0 only when every declared case passed. The wall-clock
deadline is the ``runtime_budget_seconds`` the matrix declares for the topology:
an override may tighten it, never widen it, and cases the deadline consumed are
reported ``INCOMPLETE`` instead of being dropped from the report.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4
from typing import List, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import (  # noqa: E402
    aio, catalog, diagnostics, groups, matrix, multi_node, panel_only, target_image,
)
from tools.podman_e2e.podman import Podman  # noqa: E402
from tools.podman_e2e.runner import Case, RunContext, Runner  # noqa: E402

TOPOLOGIES = ("aio", "multi-node", "panel-only")

# The row every CI job installs on. Named here rather than inline because
# `docs/PODMAN_E2E_DISCOVERY.md` §The OS matrix states which row executes, and a
# test reads this constant back against that page and against the workflows.
DEFAULT_DISTRIBUTION = "debian-13"


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
    if topology == "panel-only":
        return panel_only.cases(podman, distribution)
    raise ValueError(f"unsupported topology: {topology!r}")


def run_distribution_matrix(args: argparse.Namespace, budget: int) -> int:
    root = args.artifact_root / f"matrix-{uuid4().hex}"
    options = ["--topology", args.topology, "--budget-seconds", str(budget)]
    if args.vision:
        options.append("--vision")
    if args.worker_vision:
        options.append("--worker-vision")
    if args.require_group:
        options.extend(["--require-group", args.require_group])

    def run(distribution: str) -> bool:
        artifact_root = root / distribution
        command = [sys.executable, str(Path(__file__).resolve()), *options,
                   "--distribution", distribution, "--artifact-root", str(artifact_root)]
        try:
            status = subprocess.run(command, check=False, timeout=budget + 600).returncode
            records = list(artifact_root.glob("*/result.json"))
            passed = status == 0 and len(records) == 1 and json.loads(
                records[0].read_text(encoding="utf-8")
            )["overall"] == "PASS"
        except (OSError, subprocess.TimeoutExpired, ValueError, KeyError) as exc:
            print(f"{distribution}: {exc}", file=sys.stderr, flush=True)
            passed = False
        print(f"{distribution}: {'PASS' if passed else 'NOT PASS'} ({artifact_root})", flush=True)
        return passed

    with ThreadPoolExecutor(max_workers=len(target_image.DISTRIBUTIONS)) as executor:
        results = list(executor.map(run, sorted(target_image.DISTRIBUTIONS)))
    return 0 if all(results) else 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--topology", choices=TOPOLOGIES, default="aio")
    distributions = parser.add_mutually_exclusive_group()
    distributions.add_argument(
        "--distribution",
        choices=sorted(target_image.DISTRIBUTIONS),
        default=DEFAULT_DISTRIBUTION,
        help="Target distribution alias from tests/cases/images.lock.yaml",
    )
    distributions.add_argument(
        "--all-distributions", action="store_true",
        help="Run the selected suite concurrently on all four pinned distributions",
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
        parser.error(
            f"--worker-vision configures a Worker, and the {args.topology} topology has none"
        )
    if args.vision and args.topology == "panel-only":
        parser.error(
            "--vision installs the optional inbound on a traffic plane, and the panel-only "
            "topology has none"
        )
    if args.require_group:
        try:
            groups.required_ids(args.require_group, args.topology)
        except ValueError as exc:
            parser.error(str(exc))

    # The matrix states the deadline, and the run reports INCOMPLETE rather than
    # a shorter green when it is spent. An override may only tighten it: a run
    # outside the declared envelope has not met the tier the manifest describes,
    # so it must not be able to claim it by asking for more time.
    try:
        ceiling = matrix.runtime_budget_seconds(matrix.load(), args.topology)
    except KeyError as exc:
        parser.error(str(exc))
    budget = args.budget_seconds if args.budget_seconds is not None else ceiling
    if budget > ceiling:
        parser.error(
            f"--budget-seconds {budget} exceeds the {ceiling}s tests/cases/matrix.yaml "
            f"declares for {args.topology}: an override may only tighten the deadline"
        )

    if args.all_distributions:
        return run_distribution_matrix(args, budget)

    context = RunContext(
        topology=args.topology,
        artifact_root=args.artifact_root,
        budget_seconds=budget,
    )
    # The selected Vision configuration is part of the run's identity: the
    # matrix owes 8 or 10 positive cases (AIO) or 16/18/20 (Multi-Node). The label
    # is the matrix's own combination key, because All-in-One has two
    # configurations and Multi-Node has four: recording ``enabled``/``disabled``
    # for a Multi-Node run would hide which node carried Vision.
    context.environment["vision"] = matrix.combination(
        args.topology, args.vision, args.worker_vision
    )
    if args.topology == "multi-node":
        context.environment["worker_vision"] = "enabled" if args.worker_vision else "disabled"
    # What this run does not execute is part of what it claims. A live-only
    # scenario left unmentioned reads as parity in a green artifact, so every run
    # states each omission with the limitation that justifies it, and the block
    # travels into `result.json` as `environment.justified_exclusions`.
    try:
        exclusions = catalog.justified_exclusions(args.topology)
    except catalog.CatalogError as exc:
        parser.error(str(exc))
    context.environment["justified_exclusions"] = exclusions
    if exclusions:
        print("justified exclusions (live-only, not executed here):")
        for exclusion in exclusions:
            print(f"  {exclusion['id']} — {exclusion['reason']}")
    podman = Podman(context)
    # A run killed with SIGKILL cannot clean up after itself, so the next
    # invocation reclaims what a run of this suite older than
    # STALE_AFTER_SECONDS left behind. The filter is this suite's own label plus
    # that age: a young run, another tool's container, or an unlabelled one is
    # never touched.
    reclaimed = podman.remove_stale_runs()
    if reclaimed:
        print("reclaimed from stale runs: " + ", ".join(reclaimed))
    # Containers, the network, and run images belong to the run, not the shell.
    podman.register_cleanup()
    runner = Runner(context)
    if args.require_group:
        runner.require_group(args.require_group)
    # A failed case names a contradiction, not its cause, so every non-green case
    # also leaves the state of the run's own containers. The hook reads state and
    # cannot change a verdict, and it runs before the cleanup that removes them.
    runner.on_failure(lambda result: diagnostics.collect(context, podman, result))
    # The suite is built from Python objects while the catalog is a separate
    # artifact, so a case could run under an id no audit knows. Refusing the
    # disagreement here costs no product time: the install has not started.
    suite = build_suite(
        podman, args.topology, args.distribution,
        vision=args.vision, worker_vision=args.worker_vision,
    )
    try:
        catalog.require_executable([(case.id, case.topology) for case in suite])
    except catalog.CatalogError as exc:
        parser.error(str(exc))
    for case in suite:
        runner.add(case)
    status = runner.execute()
    print(f"artifacts: {context.artifact_dir}")
    return status


if __name__ == "__main__":
    sys.exit(main())
