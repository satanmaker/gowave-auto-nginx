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
``--keep`` run leaves its hosts, its image tags and its secret directory alive so
that a later ``--reuse RUN_ID`` can run other cases against them without
installing again. Reuse reads the ``run-setup.json`` the kept run wrote beside
its result — the network plan, the fixture and secret directories, the container
names and the images — proves every recorded resource still exists, and attaches
to the hosts it finds. A reuse that cannot do that refuses; it never falls back
to an install under the name of reuse.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4
from typing import Any, Callable, Dict, List, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import (  # noqa: E402
    aio, catalog, diagnostics, groups, matrix, multi_node, panel_only, run_setup,
    target_image,
)
from tools.podman_e2e import topology as topology_module  # noqa: E402
from tools.podman_e2e.podman import Podman, PodmanUnavailable, podman_binary  # noqa: E402
from tools.podman_e2e.runner import Case, RunContext, Runner  # noqa: E402

TOPOLOGIES = ("aio", "multi-node", "panel-only")

# The row every CI job installs on. Named here rather than inline because
# `docs/PODMAN_E2E_DISCOVERY.md` §The OS matrix states which row executes, and a
# test reads this constant back against that page and against the workflows.
DEFAULT_DISTRIBUTION = "debian-13"

# The cases that provision hosts. An adopting run cannot execute them: each one
# creates the cell the flag exists to reuse. The ids are read from the modules
# that declare them, so a rename cannot leave this list naming a case that no
# longer exists.
SETUP_CASES: Dict[str, Dict[str, str]] = {
    "aio": {"install": aio.INSTALL_CASE_ID},
    "multi-node": {
        "install": multi_node.INSTALL_CASE_ID,
        "worker": multi_node.NODE_ADD_CASE_ID,
    },
    "panel-only": {
        "install": panel_only.INSTALL_CASE_ID,
        "worker": panel_only.SQUAD_CASE_ID,
    },
}


class CaseSelectionError(ValueError):
    """``--only`` names a case the suite does not declare, or selects nothing."""


class ReuseRefused(RuntimeError):
    """``--reuse`` cannot adopt the named run, and the run will not install instead.

    The flag exists to avoid a second install, so every failure here is a
    refusal: falling back to a fresh install would answer a question the operator
    did not ask and would spend the instance that ``--keep`` was paying for.
    """


@dataclass(frozen=True)
class Adoption:
    """A kept run proven adoptable: what to attach to and what the record said."""

    run_id: str
    directory: Path
    record: Dict[str, Any] = field(repr=False)
    install_case: str
    worker_registered: bool
    containers: List[str]


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
    return [entry["name"] for entry in owned_containers(run_id, run=run)]


def _podman_json(
    run_id: str,
    arguments: Sequence[str],
    run: Optional[Callable[..., subprocess.CompletedProcess]] = None,
) -> Any:
    """Run one Podman query and return its JSON, refusing rather than raising OSError.

    ``run_id`` names the run whose adoption is being proven, because every
    refusal this file raises has to say which cell was being adopted.
    """
    try:
        binary = podman_binary()
    except PodmanUnavailable as exc:
        raise ReuseRefused(f"--reuse {run_id}: {exc}") from exc
    command = [binary, *arguments]
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
        return json.loads(completed.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise ReuseRefused(
            f"--reuse {run_id}: {' '.join(command)} did not answer JSON: {exc}"
        ) from exc


def owned_containers(
    run_id: str,
    run: Optional[Callable[..., subprocess.CompletedProcess]] = None,
) -> List[Dict[str, str]]:
    """The named run's containers, each with the state Podman reports for it."""
    items = _podman_json(
        run_id,
        ["ps", "-a", "--format", "json", "--filter", f"label=gowave.e2e.run={run_id}"],
        run=run,
    )
    entries: List[Dict[str, str]] = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        name = item.get("Names")
        if isinstance(name, list):
            name = name[0] if name else ""
        if not name:
            continue
        entries.append({"name": str(name), "state": str(item.get("State") or "")})
    return entries


def network_facts(
    name: str, run_id: str = "",
    run: Optional[Callable[..., subprocess.CompletedProcess]] = None,
) -> Optional[Dict[str, Any]]:
    """What Podman reports for one network, or ``None`` when it holds no such network."""
    try:
        binary = podman_binary()
    except PodmanUnavailable as exc:
        raise ReuseRefused(f"--reuse {run_id}: {exc}") from exc
    command = [binary, "network", "inspect", name]
    runner = run or subprocess.run
    try:
        completed = runner(command, capture_output=True, text=True, check=False, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReuseRefused(f"--reuse {run_id}: {' '.join(command)} could not run: {exc}") from exc
    if completed.returncode != 0:
        return None
    try:
        listing = json.loads(completed.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise ReuseRefused(
            f"--reuse {run_id}: {' '.join(command)} did not answer JSON: {exc}"
        ) from exc
    for network in listing if isinstance(listing, list) else []:
        if not isinstance(network, dict):
            continue
        subnets = [
            str(entry.get("subnet"))
            for entry in (network.get("subnets") or [])
            if isinstance(entry, dict) and entry.get("subnet")
        ]
        return {"name": str(network.get("name") or name), "subnets": subnets}
    return None


def image_present(
    reference: str,
    run_id: str = "",
    run: Optional[Callable[..., subprocess.CompletedProcess]] = None,
) -> bool:
    """Whether this Podman still holds the named image reference."""
    try:
        binary = podman_binary()
    except PodmanUnavailable as exc:
        raise ReuseRefused(f"--reuse {run_id}: {exc}") from exc
    command = [binary, "image", "exists", reference]
    runner = run or subprocess.run
    try:
        completed = runner(command, capture_output=True, text=True, check=False, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReuseRefused(f"--reuse {run_id}: {' '.join(command)} could not run: {exc}") from exc
    return completed.returncode == 0


def validate_reuse(
    artifact_root: Path,
    run_id: str,
    containers: Optional[Sequence[str]] = None,
) -> Dict[str, object]:
    """Prove the named run and its hosts still exist, and say what was proven.

    This is the cheap existence proof ``--reuse`` has always made: the directory
    is one of this suite's finished runs and Podman still holds containers under
    its label. What the record names is checked separately by
    :func:`verify_adoption`, because that needs the record and this does not.
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


def verify_adoption(record: Dict[str, Any]) -> List[str]:
    """Prove every resource the setup record names still exists and is usable.

    The first missing resource is the refusal, because it is the one an operator
    can act on: a container, a network, a directory or an image. Nothing is
    created, started or pulled here — a kept cell that needs any of that is not
    the cell the flag promises, and provisioning it would be the second install
    the flag exists to avoid.
    """
    run_id = str(record["run_id"])
    containers = record.get("containers") or {}
    for role in topology_module.SETUP_CONTAINER_ROLES.get(str(record["topology"]), ()):
        if not str(containers.get(role) or ""):
            raise ReuseRefused(
                f"--reuse {run_id}: its setup record names no {role} container, so the "
                f"{record['topology']} cell it describes was never created whole and is not "
                "adoptable"
            )
    entries = {entry["name"]: entry for entry in owned_containers(run_id)}
    started = set(record.get("started") or [])
    for role in ("dns", "target", "echo", "client", "engine_client", "worker", "untrusted", "acme"):
        name = str(containers.get(role) or "")
        # A role the kept run never started is not a missing resource: the engine
        # client is started on demand, and a cell that never needed it is still
        # the cell the flag promises.
        if not name or name not in started:
            continue
        found = entries.get(name)
        if found is None:
            raise ReuseRefused(
                f"--reuse {run_id}: the run recorded the {role} container {name}, but Podman "
                f"holds no container with that name labelled gowave.e2e.run={run_id}; the first "
                "missing resource is that container, so the cell is not adoptable"
            )
        if found["state"] != "running":
            raise ReuseRefused(
                f"--reuse {run_id}: the recorded {role} container {name} is "
                f"{found['state'] or 'not running'}; adopting it would run cases against a host "
                "that is not serving, and --reuse does not start containers"
            )
    for side in ("control", "data"):
        block = (record.get("network") or {}).get(side) or {}
        name = str(block.get("name") or "")
        subnet = str(block.get("subnet") or "")
        if not name:
            continue
        facts = network_facts(name, run_id=run_id)
        if facts is None:
            raise ReuseRefused(
                f"--reuse {run_id}: the run recorded the {side} network {name}, but Podman holds "
                "no such network; the first missing resource is that network, and its containers' "
                "addresses cannot be reached without it"
            )
        if subnet and subnet not in facts.get("subnets", []):
            raise ReuseRefused(
                f"--reuse {run_id}: the {side} network {name} carries "
                f"{', '.join(facts.get('subnets') or []) or 'no subnet'}, while the run recorded "
                f"{subnet}; the kept containers hold addresses the recorded plan no longer matches"
            )
    for label, path in run_setup.required_paths(record):
        if not path.is_dir():
            raise ReuseRefused(
                f"--reuse {run_id}: the run recorded its {label} as {path}, which is not a "
                "directory any more; the first missing resource is that directory, and the "
                "containers that mount it cannot be served without it"
            )
    client_ca = Path(str((record.get("fixtures") or {}).get("client_ca") or ""))
    issued = client_ca / topology_module.ISSUED_ROOT_NAME
    if not issued.is_file():
        raise ReuseRefused(
            f"--reuse {run_id}: the run recorded its client CA directory as {client_ca}, but "
            f"{issued.name} is not there; the trust anchor its clients verified cannot be rebuilt"
        )
    images = record.get("images") or {}
    for role in ("target", "client"):
        reference = str(images.get(role) or "")
        if not reference:
            continue
        if not image_present(reference, run_id=run_id):
            raise ReuseRefused(
                f"--reuse {run_id}: the run recorded the {role} image {reference}, which this "
                "Podman no longer has; the first missing resource is that image"
            )
    return sorted(entries)


def reuse_result_facts(directory: Path, record: Dict[str, Any]) -> Dict[str, Any]:
    """What the kept run's own result says about the hosts being adopted.

    Adoption attaches to an installed host, so the source run has to record that
    its install passed. The Worker registration is read the same way: a cell that
    never registered one is still adoptable, but the cases that need a Worker are
    blocked instead of being told a registration happened.
    """
    run_id = str(record["run_id"])
    result_path = directory / "result.json"
    try:
        result = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ReuseRefused(f"--reuse {run_id}: {result_path} could not be read: {exc}") from exc
    statuses = {
        str(case.get("id")): str(case.get("status"))
        for case in result.get("cases") or []
        if isinstance(case, dict)
    }
    setup = SETUP_CASES.get(str(record["topology"]))
    if setup is None:
        raise ReuseRefused(
            f"--reuse {run_id}: the setup record names topology {record['topology']!r}, which "
            "this suite does not have"
        )
    install = setup["install"]
    status = statuses.get(install, "")
    if status != "PASS":
        raise ReuseRefused(
            f"--reuse {run_id}: its result.json records {install} as {status or 'not run'}; "
            "there is no installed host to adopt, and --reuse does not install one"
        )
    worker_case = setup.get("worker", "")
    return {
        "install_case": install,
        "worker_case": worker_case,
        "worker_registered": bool(worker_case) and statuses.get(worker_case) == "PASS",
    }


def apply_reuse_record(args: argparse.Namespace, record: Dict[str, Any]) -> None:
    """Make the kept run's record the authority for the run that adopts it.

    The record describes hosts that exist; a command line describes hosts someone
    intends to build. Where the two disagree the command is refused rather than
    silently overridden, because the suite's case ids and its matrix tuples are
    decided by the topology, the distribution and the Vision combination, and a
    suite built from the wrong ones would run cases the kept cell cannot answer.
    """
    run_id = str(record["run_id"])
    kind = str(record["topology"])
    if kind not in TOPOLOGIES:
        raise ReuseRefused(
            f"--reuse {run_id}: the setup record names topology {kind!r}, which this suite does "
            f"not have (known: {', '.join(TOPOLOGIES)})"
        )
    if args.topology is not None and args.topology != kind:
        raise ReuseRefused(
            f"--reuse {run_id}: the kept run is a {kind} cell, and --topology {args.topology} "
            "describes a different one"
        )
    distribution = str(record["distribution"])
    if args.distribution is not None and args.distribution != distribution:
        raise ReuseRefused(
            f"--reuse {run_id}: the kept run installed on {distribution}, and --distribution "
            f"{args.distribution} names another row"
        )
    vision = record.get("vision") or {}
    if args.vision and not vision.get("enabled"):
        raise ReuseRefused(
            f"--reuse {run_id}: the kept run was installed without the Vision inbound, so "
            "--vision would build a suite whose cases it cannot answer"
        )
    if args.worker_vision and not vision.get("worker_enabled"):
        raise ReuseRefused(
            f"--reuse {run_id}: the kept run was installed without Worker Vision, so "
            "--worker-vision would build a suite whose cases it cannot answer"
        )
    args.topology = kind
    args.distribution = distribution
    args.vision = bool(vision.get("enabled"))
    args.worker_vision = bool(vision.get("worker_enabled"))


def plan_adoption(args: argparse.Namespace, source: Dict[str, object]) -> Adoption:
    """Read the kept run's setup record and prove the cell it describes adoptable."""
    run_id = str(source["run_id"])
    directory = Path(str(source["directory"]))
    try:
        record = run_setup.read_setup(directory)
    except run_setup.RunSetupError as exc:
        raise ReuseRefused(f"--reuse {run_id}: {exc}") from exc
    if str(record["run_id"]) != run_id:
        raise ReuseRefused(
            f"--reuse {run_id}: the setup record in {directory} names run {record['run_id']!r}; "
            "the directory and the record describe different cells"
        )
    recorded_root = Path(str(record["artifact_root"])).resolve()
    if recorded_root != directory.resolve().parent:
        raise ReuseRefused(
            f"--reuse {run_id}: the setup record names artifact root {recorded_root}, but {directory} "
            "is not in it; a copy of a run directory is not the run its containers belong to"
        )
    apply_reuse_record(args, record)
    facts = reuse_result_facts(directory, record)
    containers = verify_adoption(record)
    return Adoption(
        run_id=run_id,
        directory=directory,
        record=record,
        install_case=str(facts["install_case"]),
        worker_registered=bool(facts["worker_registered"]),
        containers=containers,
    )


def build_suite(
    podman: Podman, topology: str, distribution: str,
    vision: bool = False, worker_vision: bool = False,
    adopted: Optional[Any] = None, source_run_id: str = "",
    worker_registered: bool = False,
) -> List[Case]:
    if topology == "aio":
        return aio.cases(
            podman, distribution, vision=vision,
            adopted=adopted, source_run_id=source_run_id,
        )
    if topology == "multi-node":
        return multi_node.cases(
            podman, distribution, vision=vision, worker_vision=worker_vision,
            adopted=adopted, source_run_id=source_run_id,
            worker_registered=worker_registered,
        )
    if topology == "panel-only":
        return panel_only.cases(
            podman, distribution, adopted=adopted, source_run_id=source_run_id,
            worker_registered=worker_registered,
        )
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
    # The topology, the distribution and both Vision switches default to ``None``
    # rather than to the value a fresh install would use. ``--reuse`` has to know
    # whether the operator stated a fact or accepted a default: a stated fact that
    # contradicts the kept run's own record is a refusal, while an unstated one is
    # simply taken from the record.
    parser.add_argument(
        "--topology", choices=TOPOLOGIES, default=None,
        help="Topology to install or adopt (default: aio, or the kept run's own for --reuse)",
    )
    distributions = parser.add_mutually_exclusive_group()
    distributions.add_argument(
        "--distribution",
        choices=sorted(target_image.DISTRIBUTIONS),
        default=None,
        help=(
            "Target distribution alias from tests/cases/images.lock.yaml "
            f"(default: {DEFAULT_DISTRIBUTION}, or the kept run's own for --reuse)"
        ),
    )
    distributions.add_argument(
        "--all-distributions", action="store_true",
        help="Run the selected suite concurrently on all four pinned distributions",
    )
    parser.add_argument(
        "--vision",
        action="store_true",
        default=None,
        help=(
            "Install the optional VLESS Vision inbound; the matrix is then 10 cases instead of 8, "
            "or for multi-node 18/20 instead of 16. For --reuse the kept run's configuration is "
            "used, and asking for one it does not have is refused"
        ),
    )
    parser.add_argument(
        "--worker-vision",
        action="store_true",
        default=None,
        help=(
            "Configure the optional VLESS Vision inbound on the Multi-Node Worker as well; for "
            "--reuse the kept run's configuration is used"
        ),
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
            "Leave this run's containers, networks, image tags and secret directory alive after "
            "the verdict and print its run id; the containers are not cleaned up here, so the "
            "stale-run sweep of a later invocation reclaims them once they are older than its "
            "age limit"
        ),
    )
    parser.add_argument(
        "--reuse",
        metavar="RUN_ID",
        default=None,
        help=(
            "Run the selected cases against the hosts of an earlier --keep run (the artifact "
            "directory name it printed) instead of installing again. The kept run's "
            "run-setup.json supplies its network plan, fixture and secret directories and "
            "container names; every one of them is proven to exist before a case runs, and a "
            "cell whose setup is incomplete or gone is refused rather than reinstalled"
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

    # What the command line stated is still visible here: the defaults below are
    # filled in only after ``--reuse`` has compared the stated values against the
    # kept run's record. A stated value that contradicts the kept cell is refused;
    # an unstated one is taken from the record.
    adoption: Optional[Adoption] = None
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
            adoption = plan_adoption(args, source)
        except ReuseRefused as exc:
            # Every failure here is a refusal, never a fallback to an install:
            # the flag exists to spend no second install on the same cell.
            parser.error(str(exc))

    if args.topology is None:
        args.topology = "aio"
    if args.distribution is None:
        args.distribution = DEFAULT_DISTRIBUTION
    args.vision = bool(args.vision)
    args.worker_vision = bool(args.worker_vision)

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
        return run_distribution_matrix(args, budget, only)

    context = RunContext(
        topology=args.topology,
        artifact_root=args.artifact_root,
        budget_seconds=budget,
        distribution=args.distribution,
        reused_from=adoption.run_id if adoption is not None else None,
        # ``--keep`` and an adopted run both leave their resources for a later
        # invocation: the first so it can be adopted, the second because the cell
        # it borrowed is not its to remove. An adopted run is handed the kept
        # run's secret directory because the running containers mount it.
        keep=bool(args.keep or adoption is not None),
        secret_dir=Path(str(adoption.record["secret_dir"])) if adoption is not None else None,
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
    # disagreement here costs no product time: the install has not started. An
    # adopted run hands the product the host it rebuilt from the kept run's
    # record, so every later case addresses hosts that already exist.
    # An adoption that cannot rebuild the topology is still a refusal, not a
    # traceback: the flag never installs, so the run directory it opened must go
    # rather than look like a cell that started and crashed.
    try:
        adopted_host = (
            topology_module.adopt_topology(podman, adoption.record)
            if adoption is not None else None
        )
    except topology_module.TopologyError as exc:
        context.run_cleanup()
        shutil.rmtree(context.artifact_dir, ignore_errors=True)
        parser.error(f"--reuse {adoption.run_id}: {exc}")
    suite = build_suite(
        podman, args.topology, args.distribution,
        vision=args.vision, worker_vision=args.worker_vision,
        adopted=adopted_host,
        source_run_id=adoption.run_id if adoption is not None else "",
        worker_registered=bool(adoption and adoption.worker_registered),
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
    if adoption is not None:
        # The provisioning cases stay declared — the suite is the same suite — but
        # an adopting run cannot execute one: each creates the cell the flag
        # exists to avoid creating again. A named one is refused; an unstated
        # selection simply omits them, so the default reuse run is "everything
        # this cell can still answer for".
        setup_ids = set(SETUP_CASES[args.topology].values())
        named = [case.id for case in selected if case.id in setup_ids]
        if only is not None and named:
            context.run_cleanup()
            shutil.rmtree(context.artifact_dir, ignore_errors=True)
            parser.error(
                "--reuse adopts hosts that are already provisioned, so the cases that provision "
                "them cannot run again: " + ", ".join(named)
            )
        selected = [case for case in selected if case.id not in setup_ids]
    # A run killed with SIGKILL cannot clean up after itself, so the next
    # invocation reclaims what a run of this suite older than
    # STALE_AFTER_SECONDS left behind. The filter is this suite's own label plus
    # that age: a young run, another tool's container, or an unlabelled one is
    # never touched. It runs only once the selection is known to be valid, so a
    # mistyped case id does not cost a sweep. An adopting run skips it: the kept
    # run it borrowed from is an older run by definition, and reclaiming it would
    # delete the hosts the cases are about to run against.
    if adoption is None:
        reclaimed = podman.remove_stale_runs()
        if reclaimed:
            print("reclaimed from stale runs: " + ", ".join(reclaimed))
    # Containers, the network, and run images belong to the run, not the shell.
    # ``--keep`` gives up that cleanup whole: a kept host is attached to the run's
    # network and volumes, so leaving the containers and removing the network
    # would keep a host nothing can reach. The stale-run sweep above is what
    # reclaims a kept run once it is older than the suite's age limit. An adopted
    # run gives it up for the same reason and one more: the hosts are another
    # run's, and removing them would delete the cell instead of measuring it.
    if not (args.keep or adoption is not None):
        podman.register_cleanup()
    else:
        print(
            "keeping containers: podman ps -a --filter "
            f"label=gowave.e2e.run={adoption.run_id if adoption is not None else context.run_id}"
        )
    for case in selected:
        runner.add(case)
    status = runner.execute()
    print(f"artifacts: {context.artifact_dir}")
    if adoption is not None:
        print(
            f"reused {adoption.run_id}: {len(adoption.containers)} container(s), install "
            f"{adoption.install_case} PASS in its result.json"
        )
    if args.keep:
        print(f"run id: {context.run_id}")
        print(reuse_command(args, context.run_id))
    return status


def reuse_command(args: argparse.Namespace, run_id: str) -> str:
    """The command that names this kept run back to the suite, ready to paste.

    The flags are the kept run's own topology, distribution and artifact root, so
    the line adopts the cell it names instead of describing another one. The
    Vision configuration is deliberately absent: ``--reuse`` takes it from the
    kept run's record, and stating it here could only contradict the record.
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
        + " [--only CASE,...] (that adopts this run's hosts from its run-setup.json instead of "
        "installing, and refuses if any recorded resource is gone)"
    )


if __name__ == "__main__":
    sys.exit(main())
