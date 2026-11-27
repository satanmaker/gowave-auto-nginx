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

Two operator paths narrow what a run costs. ``--only`` runs a named subset in
the suite's own order, so a fix can be checked by the cases that judge it. A
``--keep`` run leaves its hosts alive so that a later ``--reuse RUN_ID`` can run
other cases against them without installing again; that flag currently resolves
the earlier run, proves its containers still exist, and then refuses, because
adopting the hosts it names is not implemented yet.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4
from typing import Callable, Dict, List, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import (  # noqa: E402
    aio, catalog, diagnostics, groups, matrix, multi_node, panel_only, target_image,
)
from tools.podman_e2e.podman import Podman, PodmanUnavailable, podman_binary  # noqa: E402
from tools.podman_e2e.runner import Case, RunContext, Runner  # noqa: E402

TOPOLOGIES = ("aio", "multi-node", "panel-only")

# The row every CI job installs on. Named here rather than inline because
# `docs/PODMAN_E2E_DISCOVERY.md` §The OS matrix states which row executes, and a
# test reads this constant back against that page and against the workflows.
DEFAULT_DISTRIBUTION = "debian-13"


class CaseSelectionError(ValueError):
    """``--only`` names a case the suite does not declare, or selects nothing."""


class ReuseRefused(RuntimeError):
    """``--reuse`` cannot adopt the named run, and the run will not install instead.

    The flag exists to avoid a second install, so every failure here is a
    refusal: falling back to a fresh install would answer a question the operator
    did not ask and would spend the instance that ``--keep`` was paying for.
    """


# What ``--reuse`` would have to rebuild, and therefore refuses for now. The
# install case creates the host, its fixtures and the per-run secrets and keeps
# them as Python objects; the containers are all that survives the process, so a
# reuse run that ran before the install case would have no host to attach to and
# one that ran the install case would install a second time under the name
# "reuse". Implementing the flag needs the run's plan, fixture directories and
# secret files written to the artifact root and re-read here, which is a change
# to the product lifecycle rather than to this argument parser.
REUSE_LIFECYCLE_GAP = (
    "--reuse {run_id}: {directory} and its {count} kept container(s) are resolvable, but "
    "adopting them is not implemented. The network plan, fixture resolver and CA directories, "
    "per-run secret files and the installed host object live only in the memory of the process "
    "that created them, so this run could not attach to the kept hosts without installing again. "
    "Refusing instead of installing a second time under the name 'reuse'."
)


def select_cases(cases: Sequence[Case], only: Optional[Sequence[str]] = None) -> List[Case]:
    """The suite narrowed to the ids ``--only`` names, in the suite's declared order.

    The declared order is kept rather than the order the ids were typed: the
    cases are ordered because a later one reads what an earlier one left, and a
    selection reorders that at the operator's fingertips. ``None`` means the flag
    was not given; an empty list means it selected nothing, which is a refusal
    rather than a full run — a run that demonstrates nothing must not be asked
    for by accident.
    """
    declared = list(cases)
    if only is None:
        return declared
    known = {case.id for case in declared}
    unknown = [case_id for case_id in dict.fromkeys(only) if case_id not in known]
    if unknown:
        # The declared ids are listed because a mistyped id is the common cause,
        # bounded because a full suite is over a hundred ids long and the message
        # is read in a terminal.
        listing = ", ".join(case.id for case in declared[:12])
        if len(declared) > 12:
            listing += f", and {len(declared) - 12} more"
        raise CaseSelectionError(
            "--only names case ids this suite does not declare: " + ", ".join(unknown)
            + " (declared: " + listing + ")"
        )
    wanted = set(only)
    selected = [case for case in declared if case.id in wanted]
    if not selected:
        raise CaseSelectionError(
            "--only selected no case; the run would demonstrate nothing"
        )
    return selected


def resolve_kept_run(artifact_root: Path, run_id: str) -> Path:
    """The artifact directory of an earlier run, proven to be one of this suite's runs."""
    if not run_id or "/" in run_id or run_id in (".", ".."):
        raise ReuseRefused(
            f"--reuse {run_id!r}: a run id is the artifact directory name of an earlier run, "
            "not a path"
        )
    root = artifact_root.resolve()
    directory = (artifact_root / run_id).resolve()
    if root not in directory.parents:
        raise ReuseRefused(
            f"--reuse {run_id}: {directory} is not below the artifact root {root}, so it is not "
            "a run this invocation may adopt"
        )
    if not directory.is_dir():
        raise ReuseRefused(
            f"--reuse {run_id}: no run directory at {directory}; the id is the directory name an "
            f"earlier --keep run printed, and its artifacts are looked up under {root}"
        )
    if not (directory / "result.json").is_file():
        raise ReuseRefused(
            f"--reuse {run_id}: {directory} holds no result.json, so it is not a finished run of "
            "this suite and its containers are not evidence of one"
        )
    return directory


def kept_containers(
    run_id: str,
    run: Optional[Callable[..., subprocess.CompletedProcess]] = None,
) -> List[str]:
    """The containers an earlier run left behind, read from Podman's own label index.

    The label is the same run id the kept run labelled its resources with, so the
    answer is that run's containers and never another tool's. ``run`` is the
    subprocess seam a unit test injects; production passes nothing. The listing
    is JSON rather than a format string because a container's ``Names`` is a list
    of its name and its aliases, and a template would flatten that into one
    string that is not a container name.
    """
    try:
        binary = podman_binary()
    except PodmanUnavailable as exc:
        raise ReuseRefused(f"--reuse {run_id}: {exc}") from exc
    command = [
        binary, "ps", "-a", "--format", "json",
        "--filter", f"label=gowave.e2e.run={run_id}",
    ]
    runner = run or subprocess.run
    try:
        completed = runner(command, capture_output=True, text=True, check=False, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReuseRefused(f"--reuse {run_id}: {' '.join(command)} could not run: {exc}") from exc
    if completed.returncode != 0:
        raise ReuseRefused(
            f"--reuse {run_id}: {' '.join(command)} exited {completed.returncode}: "
            f"{(completed.stderr or completed.stdout or '').strip()}"
        )
    try:
        items = json.loads(completed.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise ReuseRefused(
            f"--reuse {run_id}: {' '.join(command)} did not answer JSON: {exc}"
        ) from exc
    names: List[str] = []
    for item in items if isinstance(items, list) else []:
        name = item.get("Names") if isinstance(item, dict) else None
        if isinstance(name, list):
            name = name[0] if name else ""
        if name:
            names.append(str(name))
    return names


def validate_reuse(
    artifact_root: Path,
    run_id: str,
    containers: Optional[Sequence[str]] = None,
) -> Dict[str, object]:
    """Prove the named run and its hosts still exist, and say what was proven.

    Nothing is adopted and no container is started: the caller refuses after
    this returns, so the result is "this run is real and its containers are
    alive", never "this run has begun".
    """
    directory = resolve_kept_run(artifact_root, run_id)
    names = list(containers) if containers is not None else kept_containers(run_id)
    if not names:
        raise ReuseRefused(
            f"--reuse {run_id}: {directory} recorded the run, but Podman holds no container "
            f"labelled gowave.e2e.run={run_id}; the hosts are gone, so the cases cannot run "
            "against them"
        )
    return {"run_id": run_id, "directory": directory, "containers": names}


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


def run_distribution_matrix(
    args: argparse.Namespace, budget: int, only: Optional[Sequence[str]] = None,
) -> int:
    root = args.artifact_root / f"matrix-{uuid4().hex}"
    options = ["--topology", args.topology, "--budget-seconds", str(budget)]
    if args.vision:
        options.append("--vision")
    if args.worker_vision:
        options.append("--worker-vision")
    if args.require_group:
        options.extend(["--require-group", args.require_group])
    if only is not None:
        # Every cell runs the same subset; the selection is part of the question,
        # not of one cell's answer.
        options.extend(["--only", ",".join(only)])
    if args.keep:
        options.append("--keep")

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
        "--only",
        metavar="CASE[,CASE...]",
        action="append",
        default=None,
        help=(
            "Run exactly these case ids, in the order the suite declares them, instead of the "
            "whole suite; an id this suite does not declare exits 2 before any host is created"
        ),
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help=(
            "Leave this run's containers and network alive after the verdict and print its run "
            "id; the containers are not cleaned up here, so the stale-run sweep of a later "
            "invocation reclaims them once they are older than its age limit"
        ),
    )
    parser.add_argument(
        "--reuse",
        metavar="RUN_ID",
        default=None,
        help=(
            "Run the selected cases against the hosts of an earlier --keep run (the artifact "
            "directory name it printed) instead of installing again; resolution and validation "
            "are implemented, adopting the hosts is not and is refused rather than reinstalled"
        ),
    )
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

    # ``--only`` is parsed into a list of ids before anything runs: the ids are
    # what the suite has to declare, and the selection is part of the question a
    # run answers, so it travels to every child of a distribution matrix too.
    only: Optional[List[str]] = None
    if args.only is not None:
        only = [
            case_id.strip()
            for group in args.only
            for case_id in group.split(",")
            if case_id.strip()
        ]
    if only is not None and not only:
        # Refused here rather than in each child, because an empty selection that
        # reaches the matrix would start four runs to discover it four times.
        parser.error("--only selected no case; the run would demonstrate nothing")

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

    if args.reuse is not None:
        # A kept run is one cell's worth of hosts, so it cannot stand behind a
        # four-cell matrix, and keeping a second set that no run installed would
        # leave two claims on the same artifact root.
        if args.all_distributions:
            parser.error(
                "--reuse adopts the hosts of one kept run; --all-distributions starts four runs "
                "of its own and has no single run to adopt"
            )
        if args.keep:
            parser.error(
                "--reuse runs against hosts that are already kept; --keep would leave a second "
                "set behind that no install produced"
            )
        try:
            source = validate_reuse(args.artifact_root, args.reuse)
        except ReuseRefused as exc:
            parser.error(str(exc))
        parser.error(REUSE_LIFECYCLE_GAP.format(
            run_id=source["run_id"],
            directory=source["directory"],
            count=len(source["containers"]),
        ))

    if args.all_distributions:
        return run_distribution_matrix(args, budget, only)

    context = RunContext(
        topology=args.topology,
        artifact_root=args.artifact_root,
        budget_seconds=budget,
        distribution=args.distribution,
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
    # The selection is applied after the declared suite is built and audited, and
    # before a single case runs: a mistyped id costs an argument error, never an
    # install, and the cases that do run keep the order their dependencies assume.
    try:
        selected = select_cases(suite, only)
    except CaseSelectionError as exc:
        # The context opened this run's artifact directory before the suite
        # existed. An argument error leaves no run behind, so the empty directory
        # and the run's scratch space go with it rather than sit in the artifact
        # root looking like a cell that has just started.
        context.run_cleanup()
        shutil.rmtree(context.artifact_dir, ignore_errors=True)
        parser.error(str(exc))
    # A run killed with SIGKILL cannot clean up after itself, so the next
    # invocation reclaims what a run of this suite older than
    # STALE_AFTER_SECONDS left behind. The filter is this suite's own label plus
    # that age: a young run, another tool's container, or an unlabelled one is
    # never touched. It runs only once the selection is known to be valid, so a
    # mistyped case id does not cost a sweep.
    reclaimed = podman.remove_stale_runs()
    if reclaimed:
        print("reclaimed from stale runs: " + ", ".join(reclaimed))
    # Containers, the network, and run images belong to the run, not the shell.
    # ``--keep`` gives up that cleanup whole: a kept host is attached to the run's
    # network and volumes, so leaving the containers and removing the network
    # would keep a host nothing can reach. The stale-run sweep above is what
    # reclaims a kept run once it is older than the suite's age limit.
    if not args.keep:
        podman.register_cleanup()
    else:
        print(f"keeping containers: podman ps -a --filter label=gowave.e2e.run={context.run_id}")
    for case in selected:
        runner.add(case)
    status = runner.execute()
    print(f"artifacts: {context.artifact_dir}")
    if args.keep:
        print(f"run id: {context.run_id}")
        print(reuse_command(args, context.run_id))
    return status


def reuse_command(args: argparse.Namespace, run_id: str) -> str:
    """The command that names this kept run back to the suite, ready to paste.

    Printed with the limitation the flag currently has: ``--reuse`` resolves and
    validates the named run and then refuses, so an operator who pastes the line
    learns the state of the flag instead of guessing why nothing ran.
    """
    parts = [
        "sudo", sys.executable, str(Path(__file__).resolve()),
        "--reuse", run_id,
        "--topology", args.topology,
        "--distribution", args.distribution,
        "--artifact-root", str(args.artifact_root),
    ]
    return (
        "how to reuse it: " + " ".join(parts)
        + " (that validates this run and its containers, then refuses: adopting another "
        "run's hosts is not implemented)"
    )


if __name__ == "__main__":
    sys.exit(main())
