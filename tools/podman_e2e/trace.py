"""Requirement -> scenario -> case/test -> CI job traceability for this change.

The delta spec states 45 scenarios; the suites declare 43 All-in-One and 57
Multi-Node cases; five workflows declare the jobs that run them. Nothing ties
those three inventories together, so a scenario can lose its case, a case can
lose its scenario, and a row can cite a test or a job that does not exist —
all while every suite stays green. This module is that tie, and it is checked
rather than described:

``tests/cases/traceability.yaml`` holds one row per spec scenario. A row names
the case ids the suites declare, the ``unittest`` ids that pin the same
behaviour, and the CI jobs that run them. ``validate`` refuses a row that the
spec does not have, a spec scenario without a row, an id no suite declares, a
test that is not there, a job no workflow declares, a duplicate scenario, and a
declared Podman case that neither a row nor a ``cases_by_requirement`` entry
accounts for.

A row may instead carry ``gap``: the task id that owns the missing work. That
is not a way to pass — ``--strict`` reports every gap as a failure, and the
ledger keeps the audit open until the gap list is empty. ``--check`` stays
usable while the gaps exist so the mapping can be reviewed as it is filled in.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SPEC_PATH = (
    REPO_ROOT / "openspec" / "changes" / "podman-full-e2e" / "specs"
    / "podman-e2e" / "spec.md"
)
TABLE_PATH = REPO_ROOT / "tests" / "cases" / "traceability.yaml"
TASKS_PATH = REPO_ROOT / "openspec" / "changes" / "podman-full-e2e" / "tasks.md"
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
TESTS_DIR = REPO_ROOT / "tests"

TOPOLOGIES: Tuple[str, ...] = ("aio", "multi-node")

REQUIREMENT_RE = re.compile(r"^### Requirement:\s*(.+?)\s*$")
SCENARIO_RE = re.compile(r"^#### Scenario:\s*(.+?)\s*$")
TASK_RE = re.compile(r"^- \[(?P<box>[ xX])\] (?P<id>\d+(?:\.\d+)?) ")


def parse_spec(path: Path = SPEC_PATH) -> List[Tuple[str, str]]:
    """Every (requirement, scenario) pair the delta spec states, in order.

    The table is keyed by these two strings, so a scenario renamed in the spec
    turns its row into an unknown one and the audit says so instead of quietly
    keeping the old name.
    """
    pairs: List[Tuple[str, str]] = []
    requirement: Optional[str] = None
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        match = REQUIREMENT_RE.match(line)
        if match:
            requirement = match.group(1)
            continue
        match = SCENARIO_RE.match(line)
        if match:
            if requirement is None:
                raise ValueError(f"scenario before any requirement: {match.group(1)!r}")
            pairs.append((requirement, match.group(1)))
    return pairs


def load_table(path: Path = TABLE_PATH) -> Dict[str, Any]:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def rows(table: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flatten the requirement groups into rows that keep their requirement."""
    flat: List[Dict[str, Any]] = []
    for group in table.get("requirements") or []:
        requirement = group.get("requirement")
        for row in group.get("scenarios") or []:
            flat.append({**row, "requirement": requirement})
    return flat


def unstated(table: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Cases that serve a requirement the delta spec states without a scenario.

    A requirement can be broader than the scenarios that illustrate it — the
    failure-injection requirement names dependency, network, service,
    filesystem and process faults while the spec states two scenarios. These
    entries keep such a case in the audit instead of leaving it an orphan, and
    each has to name the requirement it serves and why no scenario fits.
    """
    return list(table.get("cases_by_requirement") or [])


def declared_cases() -> Dict[str, List[str]]:
    """The case ids each suite actually declares, in declaration order."""
    from types import SimpleNamespace

    from tools.podman_e2e import aio, multi_node
    from tools.podman_e2e.runner import RunContext

    declared: Dict[str, List[str]] = {}
    for topology, module in (("aio", aio), ("multi-node", multi_node)):
        context = RunContext(topology, REPO_ROOT / "artifacts" / "traceability",
                             budget_seconds=60, run_id=f"podman-{topology}-trace-00000000")
        podman = SimpleNamespace(context=context)
        declared[topology] = [case.id for case in module.cases(podman)]
    return declared


def declared_jobs(directory: Path = WORKFLOWS) -> Dict[str, str]:
    """Every job name the workflows declare, mapped to its workflow file."""
    names: Dict[str, str] = {}
    for path in sorted(Path(directory).glob("*.yml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for key, job in (document.get("jobs") or {}).items():
            name = (job or {}).get("name") or key
            names[name] = path.name
    return names


def task_boxes(path: Path = TASKS_PATH) -> Dict[str, bool]:
    """Task id -> whether its box is still open."""
    boxes: Dict[str, bool] = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        match = TASK_RE.match(line)
        if match:
            boxes[match.group("id")] = match.group("box") == " "
    return boxes


def test_index(directory: Path = TESTS_DIR) -> Dict[str, Set[str]]:
    """``tests.<module>.<Class>`` -> the ``test_*`` methods it defines."""
    index: Dict[str, Set[str]] = {}
    for path in sorted(Path(directory).glob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            methods = {
                child.name for child in node.body
                if isinstance(child, ast.FunctionDef) and child.name.startswith("test_")
            }
            index[f"tests.{path.stem}.{node.name}"] = methods
    return index


def expand(patterns: Iterable[str], declared: Dict[str, List[str]]) -> Tuple[List[Tuple[str, str]], List[str]]:
    """Resolve row case ids, expanding a trailing ``*`` against the suites.

    Returns the (topology, id) pairs and the patterns that matched nothing. A
    wildcard is accepted only at the end of an id: anywhere else it would hide
    which ids a row is claiming.
    """
    every = [(topology, case_id) for topology in TOPOLOGIES for case_id in declared.get(topology, [])]
    pairs: List[Tuple[str, str]] = []
    empty: List[str] = []
    for pattern in patterns:
        pattern = str(pattern)
        if pattern.endswith("*") and pattern.count("*") == 1:
            prefix = pattern[:-1]
            matched = [pair for pair in every if pair[1].startswith(prefix)]
            if not matched:
                empty.append(pattern)
            pairs.extend(matched)
        elif "*" in pattern:
            empty.append(pattern)
        else:
            hit = [pair for pair in every if pair[1] == pattern]
            if not hit:
                empty.append(pattern)
            pairs.extend(hit)
    return pairs, empty


def validate(
    table: Dict[str, Any],
    spec: Sequence[Tuple[str, str]],
    declared: Dict[str, List[str]],
    jobs: Dict[str, str],
    tasks: Dict[str, bool],
    tests: Dict[str, Set[str]],
) -> List[str]:
    """Every way the table can disagree with the spec, the suites and CI."""
    problems: List[str] = []
    stated = list(spec)
    known = set(stated)

    seen: Dict[Tuple[str, str], int] = {}
    named: Set[Tuple[str, str]] = set()
    for row in rows(table):
        requirement = row.get("requirement")
        scenario = row.get("scenario")
        key = (requirement, scenario)
        if key not in known:
            problems.append(f"not a scenario of the delta spec: {requirement} / {scenario}")
        seen[key] = seen.get(key, 0) + 1
        named.add(key)
        label = f"{requirement} / {scenario}"

        patterns = row.get("cases") or []
        pairs, empty = expand(patterns, declared)
        for pattern in empty:
            problems.append(f"{label}: no suite declares the case {pattern!r}")
        topologies = row.get("topologies")
        if patterns and topologies is None:
            problems.append(f"{label}: names cases but not the topologies they run in")
        for topology in topologies or []:
            if topology not in TOPOLOGIES:
                problems.append(f"{label}: unknown topology {topology!r}")
        # A shared id such as TLS-01 is declared by both suites; the row only has
        # to name one suite that declares it, and a shared id may run in both.
        if topologies is not None:
            for pattern in patterns:
                matched = [pair for pair in expand([pattern], declared)[0]]
                if matched and not any(pair[0] in topologies for pair in matched):
                    problems.append(
                        f"{label}: the case {pattern} is declared only by "
                        f"{sorted({pair[0] for pair in matched})}, which the row does not name"
                    )

        test_ids = row.get("tests") or []
        for test_id in test_ids:
            parts = str(test_id).split(".")
            if len(parts) not in (3, 4) or parts[0] != "tests":
                problems.append(f"{label}: malformed test id {test_id!r}")
                continue
            class_id = ".".join(parts[:3])
            if class_id not in tests:
                problems.append(f"{label}: no test class {class_id}")
                continue
            if len(parts) == 4 and parts[3] not in tests[class_id]:
                problems.append(f"{label}: no test method {test_id}")

        job_ids = row.get("jobs") or []
        for job in job_ids:
            if job not in jobs:
                problems.append(f"{label}: no workflow declares the job {job!r}")
        if (patterns or test_ids) and not job_ids:
            problems.append(f"{label}: names no CI job, so nothing runs what it claims")

        gap = row.get("gap")
        if gap is not None:
            task_id = str(gap).split()[0] if str(gap).strip() else ""
            if task_id not in tasks:
                problems.append(f"{label}: the gap names no task of the ledger: {gap!r}")
            elif not tasks[task_id]:
                problems.append(f"{label}: the gap is owned by {task_id}, whose box is already closed")
        elif not patterns and not test_ids:
            problems.append(f"{label}: has no case, no test, and no gap — it proves nothing")

    for key, count in seen.items():
        if count > 1:
            problems.append(f"scenario listed {count} times: {key[0]} / {key[1]}")
    for key in stated:
        if key not in named:
            problems.append(f"no row for the scenario: {key[0]} / {key[1]}")

    requirements = {requirement for requirement, _scenario in stated}
    mapped = {pair for row in rows(table) for pair in expand(row.get("cases") or [], declared)[0]}
    for entry in unstated(table):
        requirement = entry.get("requirement")
        if requirement not in requirements:
            problems.append(f"a requirement no spec sentence states: {requirement!r}")
        if not str(entry.get("reason") or "").strip():
            problems.append(f"{requirement}: a case serving the requirement names no reason")
        pairs, empty = expand(entry.get("cases") or [], declared)
        for case_id in empty:
            problems.append(f"{requirement}: no suite declares the case {case_id!r}")
        for pair in pairs:
            if pair in mapped:
                problems.append(
                    f"{requirement}: the case {pair[1]} is already mapped to a scenario"
                )
            mapped.add(pair)
    for topology in TOPOLOGIES:
        for case_id in declared.get(topology, []):
            if (topology, case_id) not in mapped:
                problems.append(
                    f"orphan case: {case_id} ({topology}) is mapped to no scenario and no requirement"
                )
    return problems


def gaps(table: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    """The (requirement, scenario, gap) rows whose work is still open."""
    return [
        (row["requirement"], row["scenario"], str(row["gap"]))
        for row in rows(table)
        if row.get("gap")
    ]


def audited() -> Tuple[Dict[str, Any], List[str]]:
    """Load the checked-in table and every input it is judged against."""
    table = load_table()
    problems = validate(table, parse_spec(), declared_cases(), declared_jobs(), task_boxes(), test_index())
    return table, problems


def main(argv: Optional[Sequence[str]] = None) -> int:
    import sys

    arguments = list(sys.argv[1:] if argv is None else argv)
    strict = "--strict" in arguments
    table, problems = audited()
    open_gaps = gaps(table)
    if problems:
        print("traceability: the mapping disagrees with what it cites")
        for problem in problems:
            print(f"  - {problem}")
    print(
        f"traceability: {len(parse_spec())} scenarios, {len(rows(table))} rows, "
        f"{len(open_gaps)} gaps"
    )
    for requirement, scenario, gap in open_gaps:
        print(f"  gap: {requirement} / {scenario} -> {gap}")
    if problems:
        return 1
    if strict and open_gaps:
        print("traceability: --strict refuses a mapping that still has gaps")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
