"""The read-only status of the Podman acceptance suite: one line per cell.

    PYTHONPATH=. python3 -m tools.podman_e2e.live_status [--artifact-root DIR] [--json]

A rootful cell's containers live in the root's store, so an unprivileged
``podman ps`` shows none of them and a live acceptance run looks like an idle
machine. The runner and the ``podman exec`` it is blocked on are ordinary
processes, and their command lines name the cell and the step it is on, so the
report is read from ``/proc`` and from the artifact root: which cells are
running, for how long, on which step, how many cases left diagnostics, and what
the runs that have finished decided. Nothing is started, nothing is signalled,
and no container engine is asked.

The whole decision is :func:`report`, which takes the process list and the
artifact directory as arguments, so the formatting and the liveness rule are
held by tests without a rootful container in sight. It is the command the
``podman-run`` runbook points at when someone asks whether a cell is alive; the
``GATE-STATUS`` case in :mod:`tools.podman_e2e.status` is a different question
about a different document and keeps its own module.
"""
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from tools.podman_e2e import target_image


#: Where the runner writes its runs and where this command reads them when
#: ``--artifact-root`` names nothing else. ``tools/run_podman_e2e.py`` declares
#: the same root, and a test reads it back from that file so the two cannot
#: drift apart.
ARTIFACT_ROOT = Path(__file__).resolve().parents[2] / "artifacts" / "podman-e2e"

#: How long a finished run stays in the report. A reader watching a batch of
#: cells needs the cells that ended while the batch was running, not the whole
#: history of the artifact root, and a verdict from six hours ago is history.
FINISHED_WINDOW_SECONDS = 6 * 3600

#: The width of the child command a line carries. The step names the case being
#: installed, so its head is the informative part and its tail is script noise.
STEP_WIDTH = 60

#: How much earlier than its own process a run directory may look. The runner
#: creates the directory after the interpreter starts, so a directory older than
#: this belongs to a different run, which is what keeps two cells sharing one
#: artifact root apart.
START_GRACE_SECONDS = 60

#: The distribution a runner is invoked with when its command line names none.
#: ``tools/run_podman_e2e.py`` declares the same default, and a test reads it
#: back from that file.
DEFAULT_DISTRIBUTION = "debian-13"

#: The topologies a run id can name. Read from the run directory name when the
#: report it writes cannot be opened, because ``multi-node`` carries a dash and
#: a naive split would report a topology called ``multi``.
RUN_TOPOLOGIES = ("aio", "multi-node", "panel-only")


def option(arguments: Sequence[str], name: str) -> Optional[str]:
    """The value of ``--name`` on a command line, in either of its spellings."""
    flag = f"--{name}"
    for index, argument in enumerate(arguments):
        if argument == flag:
            return arguments[index + 1] if index + 1 < len(arguments) else ""
        if argument.startswith(f"{flag}="):
            return argument.split("=", 1)[1]
    return None


def read_processes(proc_root: Path = Path("/proc")) -> List[Dict[str, Any]]:
    """Every process this user can see: pid, parent, command line, and age.

    ``/proc`` rather than ``podman ps``: a rootful cell's containers live in the
    root's store and an unprivileged reader sees none of them, while the runner
    and the ``podman exec`` it is blocked on are ordinary processes whose command
    lines name the run and the step it is on. Nothing here needs privilege or a
    container engine, and a process that exits mid-scan is skipped rather than
    reported as a cell of its own.
    """
    uptime = 0.0
    try:
        uptime = float((proc_root / "uptime").read_text(encoding="utf-8").split()[0])
    except (OSError, ValueError, IndexError):
        uptime = 0.0
    ticks = float(os.sysconf("SC_CLK_TCK"))
    processes: List[Dict[str, Any]] = []
    try:
        entries = sorted(proc_root.iterdir(), key=lambda path: path.name)
    except OSError:
        return processes
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            arguments = [
                item.decode("utf-8", "replace")
                for item in (entry / "cmdline").read_bytes().split(b"\0")
                if item
            ]
            stat = (entry / "stat").read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not arguments:
            continue
        # ``comm`` is parenthesised and may itself contain spaces and brackets,
        # so the fields are counted from the last ``)`` rather than from the
        # start of the line: ``ppid`` is the second of them and ``starttime``
        # the nineteenth, in clock ticks since boot.
        fields = stat[stat.rfind(")") + 2:].split()
        try:
            processes.append({
                "pid": int(entry.name),
                "ppid": int(fields[1]),
                "cmdline": arguments,
                "elapsed": max(0.0, uptime - int(fields[19]) / ticks),
            })
        except (IndexError, ValueError):
            continue
    return processes


def runner_cell(process: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The cell a process is, or ``None`` when the process is not a runner.

    A cell is an invocation that names a topology and a run root. The
    ``--all-distributions`` parent names a topology but spawns one child per
    distribution instead of installing anything, so it is not a cell; a runner
    invoked without ``--distribution`` is one all the same, on the default
    distribution its own entrypoint declares.
    """
    arguments = [str(argument) for argument in process.get("cmdline") or []]
    if not any("run_podman_e2e" in argument for argument in arguments):
        return None
    topology = option(arguments, "topology")
    if not topology:
        return None
    if option(arguments, "all-distributions") is not None:
        return None
    distribution = option(arguments, "distribution") or DEFAULT_DISTRIBUTION
    root = option(arguments, "artifact-root") or str(ARTIFACT_ROOT)
    return {
        "topology": topology,
        "distribution": distribution,
        "artifact_root": Path(root),
        "elapsed": float(process.get("elapsed") or 0.0),
    }


def ancestors(processes: Sequence[Dict[str, Any]], pid: int) -> Set[int]:
    """Every pid above ``pid``, up to the one that has no parent."""
    parents = {
        int(process.get("pid") or 0): int(process.get("ppid") or 0)
        for process in processes
    }
    found: Set[int] = set()
    current = parents.get(int(pid), 0)
    while current and current not in found:
        found.add(current)
        current = parents.get(current, 0)
    return found


def descendants(
    processes: Sequence[Dict[str, Any]], pid: int,
) -> List[Tuple[int, Dict[str, Any]]]:
    """``(depth, process)`` for every process below ``pid``, breadth first."""
    children: Dict[int, List[Dict[str, Any]]] = {}
    for process in processes:
        children.setdefault(int(process.get("ppid") or 0), []).append(process)
    found: List[Tuple[int, Dict[str, Any]]] = []
    frontier = [(0, int(pid))]
    seen = {int(pid)}
    while frontier:
        depth, current = frontier.pop()
        for child in children.get(current, []):
            child_pid = int(child.get("pid") or 0)
            if child_pid in seen:
                continue
            seen.add(child_pid)
            found.append((depth + 1, child))
            frontier.append((depth + 1, child_pid))
    return found


def trim(text: str, width: int = STEP_WIDTH) -> str:
    """One line of at most ``width`` characters, whitespace collapsed."""
    collapsed = " ".join(str(text).split())
    return collapsed if len(collapsed) <= width else collapsed[: width - 3] + "..."


def current_step(processes: Sequence[Dict[str, Any]], pid: int) -> Optional[str]:
    """The command the runner is waiting on: its deepest ``podman`` child.

    ``podman exec …`` names the step because the in-container command is on its
    command line — the case id, the installer stage it is in, the readback it is
    blocked on — which is the only place that name exists on this side of the
    container. A ``podman exec`` is preferred over another subcommand at the same
    depth, the deepest process wins over its parent, and the newest wins over an
    older sibling, because that is the one the runner is blocked on.
    """
    candidates: List[Tuple[int, int, float, List[str]]] = []
    for depth, process in descendants(processes, pid):
        arguments = [str(argument) for argument in process.get("cmdline") or []]
        if not arguments or Path(arguments[0]).name != "podman":
            continue
        candidates.append((
            1 if "exec" in arguments else 0,
            depth,
            -float(process.get("elapsed") or 0.0),
            arguments,
        ))
    if not candidates:
        return None
    best = max(candidates, key=lambda candidate: candidate[:3])
    return trim(" ".join(best[3]))


def duration(seconds: float) -> str:
    """An elapsed time a person reads at a glance: ``9s``, ``12m34s``, ``1h02m``."""
    total = int(max(0.0, float(seconds)))
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}h{minutes:02d}m"
    if minutes:
        return f"{minutes}m{secs:02d}s"
    return f"{secs}s"


def diagnostics(run_dir: Optional[Path]) -> Optional[int]:
    """How many cases left diagnostics under ``evidence/diagnostics``.

    ``None`` — printed as ``?`` — when the directory could not be read. A rootful
    run writes its evidence as root, and a count nobody could take is not a
    count of zero.
    """
    if run_dir is None:
        return None
    directory = run_dir / "evidence" / "diagnostics"
    try:
        return sum(1 for path in directory.iterdir() if path.is_dir())
    except FileNotFoundError:
        return 0
    except OSError:
        return None


def modification(path: Path) -> float:
    """``path``'s timestamp, or ``0.0`` when it cannot be read."""
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def run_directories(root: Path) -> List[Path]:
    """Every ``podman-*`` run directory under ``root``, matrix layout included.

    A single run writes ``podman-<topology>-<stamp>-<runid>`` straight into the
    artifact root; ``--all-distributions`` writes
    ``matrix-<uuid>/<distribution>/podman-<topology>-…``, one level deeper, and
    that level is also the only place the distribution of such a run is written
    down.
    """
    found: List[Path] = []
    try:
        matrices = sorted(root.glob("matrix-*"))
    except OSError:
        matrices = []
    for parent, pattern in [(root, "podman-*"), *((m, "*/podman-*") for m in matrices)]:
        try:
            candidates = sorted(parent.glob(pattern))
        except OSError:
            continue
        found.extend(path for path in candidates if path.is_dir())
    unique: List[Path] = []
    for path in found:
        if path not in unique:
            unique.append(path)
    return unique


def run_directory(root: Path, topology: str, started_at: float) -> Optional[Path]:
    """The run directory a live cell of ``topology`` created at ``started_at``.

    The run's own name carries no case id and no distribution, so the cell is
    matched by the two facts that are written down: the topology its id starts
    with, and the moment the runner began, which is the moment the directory
    appeared. Two cells sharing one artifact root are therefore kept apart, and a
    directory older than ``START_GRACE_SECONDS`` than the process is someone
    else's.
    """
    prefix = f"podman-{topology}-"
    candidates = [
        path for path in run_directories(root) if path.name.startswith(prefix)
    ]
    if not candidates:
        return None
    best = min(candidates, key=lambda path: abs(modification(path) - started_at))
    return best if modification(best) >= started_at - START_GRACE_SECONDS else None


def read_json(path: Path) -> Optional[Dict[str, Any]]:
    """A JSON object, or ``None`` when the file is missing, unreadable or not one."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return document if isinstance(document, dict) else None


def run_topology(run_dir: Path) -> str:
    """The topology a run directory name declares, or ``""`` when it declares none."""
    for topology in RUN_TOPOLOGIES:
        if run_dir.name.startswith(f"podman-{topology}-"):
            return topology
    return ""


def run_distribution(run_dir: Path, report_: Dict[str, Any]) -> str:
    """The distribution a finished run installed on.

    ``summary.json`` names it outright, and that document is a projection of the
    run's own report, so it wins. The matrix layout names it in the directory
    above the run, and a single run records only the images it resolved, where
    the one target alias among them is the distribution it installed on. A run
    that says none of those is reported as ``unknown`` rather than guessed.
    """
    declared = str(report_.get("distribution") or "")
    if declared in target_image.DISTRIBUTIONS:
        return declared
    parent = run_dir.parent.name
    if parent in target_image.DISTRIBUTIONS:
        return parent
    resolved = (report_.get("environment") or {}).get("images_resolved") or {}
    aliases = [name for name in target_image.DISTRIBUTIONS if name in resolved]
    return aliases[0] if len(aliases) == 1 else "unknown"


def finished_run(
    run_dir: Path, now: float, window: int = FINISHED_WINDOW_SECONDS,
) -> Optional[Dict[str, Any]]:
    """The entry a finished run leaves, or ``None`` while it has not finished.

    ``result.json`` is written when the run stops, which is what its own age
    measures, and ``summary.json`` — the document a batch writes over a cell — is
    read first when it exists. A run directory this user may not open still has a
    readable timestamp, so it is reported with neither residue count nor verdict
    rather than dropped: a rootful cell's artifacts are root-only, and hiding the
    run would read as a cell that never ran.
    """
    result = run_dir / "result.json"
    try:
        age = now - result.stat().st_mtime
    except PermissionError:
        if now - modification(run_dir) > window:
            return None
        return {
            "topology": run_topology(run_dir),
            "distribution": run_distribution(run_dir, {}),
            "up": None,
            "step": None,
            "diag": diagnostics(run_dir),
            "verdict": None,
        }
    except OSError:
        return None
    if age > window:
        return None
    recorded = read_json(result) or {}
    summary = read_json(run_dir / "summary.json") or {}
    overall = str(summary.get("overall") or recorded.get("overall") or "") or None
    topology = str(summary.get("topology") or recorded.get("topology") or "") or ""
    return {
        "topology": topology or run_topology(run_dir),
        "distribution": run_distribution(run_dir, {**recorded, **summary}),
        "up": None,
        "step": None,
        "diag": diagnostics(run_dir),
        "verdict": overall,
    }


def report(
    processes: Sequence[Dict[str, Any]],
    artifact_root: Path = ARTIFACT_ROOT,
    now: Optional[float] = None,
    window: int = FINISHED_WINDOW_SECONDS,
) -> List[Dict[str, Any]]:
    """One entry per live cell, then per run that finished inside ``window``.

    ``processes`` is what :func:`read_processes` returns — pid, parent, command
    line and the seconds it has been alive — so the whole decision is made from
    a list instead of from a machine, and a cell with no visible container is a
    fixture. A runner that is itself the child of another runner is not reported:
    a wrapper shell and the interpreter it launched are one cell, not two.
    """
    moment = time.time() if now is None else float(now)
    listed = list(processes or [])
    cells: List[Tuple[int, Dict[str, Any]]] = []
    for process in listed:
        cell = runner_cell(process)
        if cell is not None:
            cells.append((int(process.get("pid") or 0), cell))
    cell_pids = {pid for pid, _ in cells}
    entries: List[Dict[str, Any]] = []
    claimed: Set[Path] = set()
    for pid, cell in cells:
        if ancestors(listed, pid) & cell_pids:
            continue
        run = run_directory(
            Path(cell["artifact_root"]), cell["topology"], moment - cell["elapsed"],
        )
        if run is not None:
            claimed.add(run)
        entries.append({
            "topology": cell["topology"],
            "distribution": cell["distribution"],
            "up": round(cell["elapsed"], 1),
            "step": current_step(listed, pid),
            "diag": diagnostics(run),
            "verdict": "none",
        })
    entries.sort(key=lambda entry: (entry["topology"], entry["distribution"], entry["up"]))
    finished: List[Tuple[str, Dict[str, Any]]] = []
    for run in run_directories(Path(artifact_root)):
        if run in claimed:
            continue
        facts = finished_run(run, moment, window)
        if facts is not None:
            finished.append((run.name, facts))
    # A finished run has no elapsed time to order by, and its name is the run's
    # own timestamp and id, so the newest finisher is the first line.
    finished.sort(key=lambda pair: pair[0], reverse=True)
    return entries + [facts for _, facts in finished]


def line(entry: Dict[str, Any]) -> str:
    """One report line: the cell, its age, its step, its residue, its verdict."""
    up = "-" if entry.get("up") is None else duration(entry["up"])
    step = "-" if not entry.get("step") else trim(entry["step"])
    diag = "?" if entry.get("diag") is None else str(entry["diag"])
    verdict = entry.get("verdict") or "?"
    return (
        f"{entry.get('topology')} {entry.get('distribution')} up={up} "
        f"step={step} diag={diag} verdict={verdict}"
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Print the status of every live or recently finished cell.

    Exit status 0 when something was reported and 3 when nothing was, which is
    the difference between "no cell is running" and "the command could not tell".
    Nothing is started, nothing is signalled, and no container engine is asked:
    the report is read from ``/proc`` and from the artifact root this user may
    read.
    """
    parser = argparse.ArgumentParser(
        prog="python3 -m tools.podman_e2e.status",
        description=(
            "Report every live or recently finished Podman acceptance cell from "
            "/proc and the artifact root. A rootful cell's containers are invisible "
            "to podman ps; its runner and its podman exec are not."
        ),
    )
    parser.add_argument(
        "--artifact-root",
        type=Path,
        default=ARTIFACT_ROOT,
        help="Directory the runs were written to (default: artifacts/podman-e2e)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help=(
            "Print the same report as a JSON list of objects with fields "
            "topology, distribution, up, step, diag and verdict"
        ),
    )
    arguments = parser.parse_args(argv)
    entries = report(read_processes(), arguments.artifact_root)
    if arguments.json:
        print(json.dumps(entries, indent=2, sort_keys=True))
    else:
        for entry in entries:
            print(line(entry), flush=True)
    return 0 if entries else 3


if __name__ == "__main__":
    raise SystemExit(main())
