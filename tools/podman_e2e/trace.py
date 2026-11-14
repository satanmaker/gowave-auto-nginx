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

``behaviours`` is the second view: one entry per promise too narrow to be a
scenario — a missing User-Agent header, one Vision combination, one kind of DNS
answer. Each quotes the ``matrix.yaml`` declaration it rests on, so the report
cannot describe a policy the manifest has dropped, and ``behaviour_obligations``
names what the view has to cover, including every value of a list such as the
four Vision combinations.

``docs/PODMAN_E2E_TRACEABILITY.md`` is the same table for a reader who will not
open the YAML. It is generated (``--markdown``) and it is a fixed point: the
audit re-renders the table and refuses a report that is not that text, so the
published page cannot describe a mapping the table no longer holds.
``--verify-run`` reads a finished run back the other way: ``overall: PASS`` is
an aggregate, so the command counts the data-plane cases that run wrote and
refuses one that executed fewer than the manifest owes, or one whose positive
case did not pass.
"""
from __future__ import annotations

import ast
import json
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
REPORT_PATH = REPO_ROOT / "docs" / "PODMAN_E2E_TRACEABILITY.md"
MATRIX_PATH = REPO_ROOT / "tests" / "cases" / "matrix.yaml"

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


def _case_problems(
    label: str,
    patterns: Sequence[str],
    topologies: Optional[Sequence[str]],
    declared: Dict[str, List[str]],
) -> List[str]:
    """Why the case ids a row names do not resolve against the suites.

    A shared id such as ``TLS-01`` is declared by both suites; the row only has
    to name one suite that declares it, and a shared id may run in both.
    """
    problems: List[str] = []
    _pairs, empty = expand(patterns, declared)
    for pattern in empty:
        problems.append(f"{label}: no suite declares the case {pattern!r}")
    if patterns and topologies is None:
        problems.append(f"{label}: names cases but not the topologies they run in")
    for topology in topologies or []:
        if topology not in TOPOLOGIES:
            problems.append(f"{label}: unknown topology {topology!r}")
    if topologies is not None:
        for pattern in patterns:
            matched = expand([pattern], declared)[0]
            if matched and not any(pair[0] in topologies for pair in matched):
                problems.append(
                    f"{label}: the case {pattern} is declared only by "
                    f"{sorted({pair[0] for pair in matched})}, which the row does not name"
                )
    return problems


def _test_problems(label: str, test_ids: Sequence[str], tests: Dict[str, Set[str]]) -> List[str]:
    """Why a ``tests.<module>.<Class>[.<method>]`` id names nothing under ``tests/``."""
    problems: List[str] = []
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
    return problems


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
        problems.extend(_case_problems(label, patterns, row.get("topologies"), declared))

        test_ids = row.get("tests") or []
        problems.extend(_test_problems(label, test_ids, tests))

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


def behaviours(table: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The single promises the report publishes beside the scenario rows.

    A scenario row answers "which case proves this sentence of the spec"; a
    behaviour answers "what does this one promise rest on" — a missing
    User-Agent, one Vision combination, one kind of DNS answer. Several
    behaviours share a row and a case, which is why they are a second view and
    not a second mapping: they add no coverage the row-level audit would
    otherwise miss, and each one quotes a declaration the manifest states so
    the report cannot claim a policy the matrix has moved away from.
    """
    return list(table.get("behaviours") or [])


def resolve_declaration(path: str, matrix: Dict[str, Any]) -> Tuple[Any, bool]:
    """The manifest value a dotted path names, and whether it is there."""
    node: Any = matrix
    for key in str(path).split("."):
        if not isinstance(node, dict) or key not in node:
            return None, False
        node = node[key]
    return node, True


def declaration_text(entry: Dict[str, Any], matrix: Dict[str, Any]) -> str:
    """How the report quotes a behaviour's declaration.

    A scalar declaration is an equality and a list declaration is one element
    of it, which is the difference the reader needs to see: the Vision
    combinations live in one list, and a row that names ``both`` has not
    restated the other three.
    """
    declares = entry.get("declares") or {}
    path = str(declares.get("path") or "")
    if not path:
        return "—"
    if "value" not in declares:
        return f"`{path}`"
    value, found = resolve_declaration(path, matrix)
    if found and isinstance(value, list):
        return f"`{path}` holds `{declares['value']}`"
    return f"`{path}` = `{declares['value']}`"


def _claim_key(value: Any) -> str:
    """A value's identity as a claim: ``both`` and ``403`` never collide."""
    return json.dumps(value, sort_keys=True)


def _declaration_problems(
    label: str,
    declares: Dict[str, Any],
    matrix: Dict[str, Any],
    claims: Dict[Tuple[str, str], str],
) -> List[str]:
    """Why a behaviour does not quote the manifest exactly as it stands.

    A declaration is either a scalar the behaviour repeats or a list it names
    one element of, so a Vision combination can be quoted without restating the
    whole list. Both forms are read from the manifest rather than trusted.
    """
    path = str(declares.get("path") or "")
    if not path:
        return [f"{label}: declares no manifest path"]
    value, found = resolve_declaration(path, matrix)
    if not found:
        return [f"{label}: declares {path!r}, which the manifest does not hold"]
    if "value" not in declares:
        return [f"{label}: {path} has to be quoted with the value the manifest states"]
    claimed = declares["value"]
    if isinstance(value, list):
        if claimed not in value:
            return [f"{label}: {path} does not hold {claimed!r}"]
    elif claimed != value:
        return [
            f"{label}: {path} is {value!r} in the manifest, the behaviour claims {claimed!r}"
        ]
    key = (path, _claim_key(claimed))
    if key in claims:
        return [f"{label}: {claims[key]} already claims {path} = {claimed!r}"]
    claims[key] = label
    return []


def validate_behaviours(
    table: Dict[str, Any],
    spec: Sequence[Tuple[str, str]],
    declared: Dict[str, List[str]],
    jobs: Dict[str, str],
    tests: Dict[str, Set[str]],
    matrix: Dict[str, Any],
) -> List[str]:
    """Every way the named behaviours can disagree with what they quote.

    The obligations are what keep the block from shrinking: a declaration the
    table says the report covers has to be claimed by a behaviour, and an
    ``every_value`` obligation makes each element of the manifest's list one
    obligation of its own, so a new Vision combination is red until a behaviour
    names it.
    """
    problems: List[str] = []
    requirements = {requirement for requirement, _scenario in spec}
    entries = behaviours(table)
    seen: Set[str] = set()
    claims: Dict[Tuple[str, str], str] = {}
    for entry in entries:
        name = str(entry.get("behaviour") or "").strip()
        label = f"behaviour {name!r}" if name else "behaviour with no name"
        if not name:
            problems.append(f"{label}: has no text")
        if name in seen:
            problems.append(f"behaviour listed more than once: {name!r}")
        seen.add(name)
        requirement = entry.get("requirement")
        if requirement not in requirements:
            problems.append(f"{label}: no spec requirement {requirement!r}")
        cases = entry.get("cases") or []
        if not cases:
            problems.append(f"{label}: names no case, so nothing proves it")
        problems.extend(_case_problems(label, cases, entry.get("topologies"), declared))
        problems.extend(_test_problems(label, entry.get("tests") or [], tests))
        job_ids = entry.get("jobs") or []
        if not job_ids:
            problems.append(f"{label}: names no CI job, so nothing runs what it claims")
        for job in job_ids:
            if job not in jobs:
                problems.append(f"{label}: no workflow declares the job {job!r}")
        declares = entry.get("declares")
        if declares is not None:
            problems.extend(
                _declaration_problems(label, declares if isinstance(declares, dict) else {},
                                      matrix, claims)
            )

    obligations = list(table.get("behaviour_obligations") or [])
    if not obligations:
        problems.append(
            "no behaviour obligation: the table names nothing the behaviours have to cover"
        )
    claimed_paths = {path for path, _key in claims}
    for obligation in obligations:
        if not isinstance(obligation, dict):
            problems.append(f"behaviour obligation is not a mapping: {obligation!r}")
            continue
        path = str(obligation.get("path") or "")
        value, found = resolve_declaration(path, matrix)
        if not found:
            problems.append(
                f"behaviour obligation {path!r} names a declaration the manifest does not hold"
            )
            continue
        if obligation.get("every_value"):
            if not isinstance(value, list):
                problems.append(
                    f"behaviour obligation {path} asks for every value, but the manifest "
                    "states a single one"
                )
                continue
            for element in value:
                if (path, _claim_key(element)) not in claims:
                    problems.append(f"no behaviour names {path} = {element!r}")
        elif path not in claimed_paths:
            problems.append(f"no behaviour names {path}")
    return problems


def gaps(table: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    """The (requirement, scenario, gap) rows whose work is still open."""
    return [
        (row["requirement"], row["scenario"], str(row["gap"]))
        for row in rows(table)
        if row.get("gap")
    ]


def render(table: Dict[str, Any]) -> str:
    """The published report, generated from the table and nothing else.

    A hand-written report drifts from the audit that judges it, so the report
    is a function of the table and ``--check`` compares the two. The row order
    is the spec's order, which is why it can be read beside the spec.
    """
    lines = [
        "# Podman E2E traceability",
        "",
        "<!-- Generated by `python3 -m tools.podman_e2e.trace --markdown`. -->",
        "<!-- Edited by hand, it drifts: the audit refuses a report that is not this text. -->",
        "",
        "One row per scenario of",
        "`openspec/changes/podman-full-e2e/specs/podman-e2e/spec.md`.",
        "`matrix` is the `tests/cases/matrix.yaml` row each case id decodes to —",
        "`inbound/client`, or `node/inbound/client` on Multi-Node, where both",
        "nodes run the same pair — so the protocol and the client a scenario",
        "covers is readable without opening the suites.",
        "`cases` are the ids the All-in-One and Multi-Node suites declare, `tests`",
        "are the `unittest` ids that pin the same behaviour, and `job` is what runs",
        "them on CI. A `gap` row names the ledger task that still owns the work.",
        "",
        "| Requirement | Scenario | Matrix rows | Cases | Tests | Job | Gap |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    declared = declared_cases()
    for row in rows(table):
        matrix = ", ".join(f"`{entry}`" for entry in matrix_rows_of(row, declared)) or "—"
        cases = ", ".join(f"`{case}`" for case in row.get("cases") or []) or "—"
        # Only the ``tests.`` prefix is dropped: the module stays, because
        # ``TestMatrixCase`` exists in both ``test_podman_traffic`` and
        # ``test_podman_multi_node``.
        tests = ", ".join(
            f"`{'.'.join(test.split('.')[1:])}`" for test in row.get("tests") or []
        ) or "—"
        jobs = ", ".join(row.get("jobs") or []) or "—"
        gap = str(row.get("gap") or "—")
        lines.append(
            f"| {row['requirement']} | {row['scenario']} | {matrix} | {cases} "
            f"| {tests} | {jobs} | {gap} |"
        )
    entries = unstated_cases(table)
    if entries:
        lines += [
            "",
            "## Cases serving a requirement that states no scenario",
            "",
            "| Requirement | Cases |",
            "| --- | --- |",
        ]
        for entry in entries:
            cases = ", ".join(f"`{case}`" for case in entry["cases"])
            lines.append(f"| {entry['requirement']} | {cases} |")
    named_behaviours = behaviours(table)
    if named_behaviours:
        lines += [
            "",
            "## Named behaviours",
            "",
            "The promises this change names one by one, with the `tests/cases/matrix.yaml`",
            "declaration each one quotes, the cases that run it, the tests that pin it",
            "and the job that runs them. Several behaviours share a scenario: this view",
            "answers what one promise rests on, not which scenario owns it.",
            "",
            "| Behaviour | Requirement | Manifest | Cases | Tests | Job |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        matrix = load_matrix()
        for entry in named_behaviours:
            cases = ", ".join(f"`{case}`" for case in entry.get("cases") or []) or "—"
            tests = ", ".join(
                f"`{'.'.join(test.split('.')[1:])}`" for test in entry.get("tests") or []
            ) or "—"
            jobs = ", ".join(entry.get("jobs") or []) or "—"
            lines.append(
                f"| {entry['behaviour']} | {entry['requirement']} "
                f"| {declaration_text(entry, matrix)} | {cases} | {tests} | {jobs} |"
            )
    lines += ["", f"Open gaps: {len(gaps(table))}.", ""]
    named = named_matrix_rows(table, declared)
    required = required_matrix_rows()
    lines.append(
        "Matrix rows named: "
        + ", ".join(
            f"{sum(1 for row in named if row[0] == topology)} of "
            f"{sum(1 for row in required if row[0] == topology)} {topology} rows"
            for topology in TOPOLOGIES
        )
        + "."
    )
    lines.append("")
    return "\n".join(lines)


def unstated_cases(table: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(table.get("cases_by_requirement") or [])


def positive_counts() -> List[str]:
    """The expected positive-case counts, read from the manifest, not a run.

    A green aggregate says nothing about how many data-plane cases ran, so the
    count each topology may report is checked against the checked-in catalog and
    against the cases the suites actually declare for every Vision combination.
    """
    from types import SimpleNamespace

    from tools.podman_e2e import aio, catalog, multi_node
    from tools.podman_e2e.runner import RunContext

    def declared(topology: str, module: Any, **vision: bool) -> int:
        context = RunContext(topology, REPO_ROOT / "artifacts" / "traceability",
                             budget_seconds=60, run_id=f"podman-{topology}-counts-00000000")
        prefix = "AIO-DP-" if topology == "aio" else "MN-DP-"
        return sum(
            1 for case in module.cases(SimpleNamespace(context=context), **vision)
            if case.id.startswith(prefix)
        )

    expected = catalog.load_catalog()["expected_positive_case_counts"]
    observed = {
        "aio": {
            "vision_disabled": declared("aio", aio),
            "vision_enabled": declared("aio", aio, vision=True),
        },
        "multi-node": {
            "vision_neither": declared("multi-node", multi_node),
            "vision_one_node": declared("multi-node", multi_node, vision=True),
            "vision_both": declared("multi-node", multi_node, vision=True, worker_vision=True),
        },
    }
    problems: List[str] = []
    for topology, variants in expected.items():
        for variant, count in variants.items():
            if observed[topology][variant] != count:
                problems.append(
                    f"{topology}/{variant}: the manifest declares {count} positive cases, "
                    f"the suite declares {observed[topology][variant]}"
                )
    return problems


def load_matrix(path: Path = MATRIX_PATH) -> Dict[str, Any]:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def decode_matrix_case(case_id: str, matrix: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Split a ``AIO-DP-<inbound>-<client>`` / ``MN-DP-<node>-<inbound>-<client>`` id.

    The id is the only place a run says which matrix row it executed, so the
    report reads it back instead of trusting a second column to stay in step.
    An id that carries no client comes back with an empty client, so the audit
    can name it instead of treating it as a case that has no matrix row.
    """
    clients = sorted(
        (str(client["id"]) for client in matrix.get("clients") or []),
        key=len, reverse=True,
    )
    for prefix, topology in (("AIO-DP-", "aio"), ("MN-DP-", "multi-node")):
        if not case_id.startswith(prefix):
            continue
        rest = case_id[len(prefix):]
        node: Optional[str] = None
        if topology == "multi-node":
            node, _, rest = rest.partition("-")
        for client in clients:
            suffix = f"-{client}"
            if rest.endswith(suffix):
                return {
                    "topology": topology,
                    "node": node,
                    "inbound": rest[: -len(suffix)],
                    "client": client,
                }
        return {"topology": topology, "node": node, "inbound": rest, "client": ""}
    return None


def matrix_rows_of(row: Dict[str, Any], declared: Dict[str, List[str]]) -> List[str]:
    """The matrix rows a scenario row names, as ``inbound/client`` or ``node/inbound/client``."""
    matrix = load_matrix()
    named: List[str] = []
    for _topology, case_id in expand(row.get("cases") or [], declared)[0]:
        decoded = decode_matrix_case(case_id, matrix)
        if decoded is None or not decoded["client"]:
            continue
        if decoded["node"]:
            label = f"{decoded['node']}/{decoded['inbound']}/{decoded['client']}"
        else:
            label = f"{decoded['inbound']}/{decoded['client']}"
        if label not in named:
            named.append(label)
    return named


def required_matrix_rows() -> List[Tuple[str, str, str, str]]:
    """Every (topology, node, inbound, client) row the manifest calls non-optional.

    A Multi-Node row is counted once per node: ``master/REALITY/xray`` and
    ``worker/REALITY/xray`` are two cases, and a scenario that names only one of
    them has not claimed the other. All-in-One rows carry an empty node.
    """
    matrix = load_matrix()
    clients = [str(client["id"]) for client in matrix.get("clients") or []]
    nodes = [
        str(node)
        for node in (matrix.get("topologies") or {}).get("multi-node", {}).get("nodes") or []
    ]
    rows_: List[Tuple[str, str, str, str]] = []
    for inbound in matrix.get("inbounds") or []:
        if inbound.get("optional"):
            continue
        for client in clients:
            rows_.append(("aio", "", str(inbound["id"]), client))
            for node in nodes:
                rows_.append(("multi-node", node, str(inbound["id"]), client))
    return rows_


def named_matrix_rows(
    table: Dict[str, Any], declared: Dict[str, List[str]]
) -> Set[Tuple[str, str, str, str]]:
    """The (topology, node, inbound, client) rows every matrix case id in the table names."""
    matrix = load_matrix()
    pairs: Set[Tuple[str, str, str, str]] = set()
    for row in rows(table):
        for _topology, case_id in expand(row.get("cases") or [], declared)[0]:
            decoded = decode_matrix_case(case_id, matrix)
            if decoded is None or not decoded["client"]:
                continue
            pairs.add(
                (decoded["topology"], decoded["node"] or "", decoded["inbound"], decoded["client"])
            )
    return pairs


def matrix_problems(table: Dict[str, Any], declared: Dict[str, List[str]]) -> List[str]:
    """Every matrix row the suites execute has to be named by a scenario.

    The manifest says how many data-plane cases a topology runs; it does not say
    a scenario claims them. This holds the two sides together in both directions:
    an id that decodes to an inbound, a node or a client the matrix does not
    declare is refused, and a non-optional ``node × inbound × client`` row no
    scenario names is refused. Optional inbounds — Vision's 8443 listener — are
    exempt because they run only when that combination is switched on.
    """
    matrix = load_matrix()
    problems: List[str] = []
    inbounds = [str(inbound["id"]) for inbound in matrix.get("inbounds") or []]
    clients = [str(client["id"]) for client in matrix.get("clients") or []]
    nodes = [
        str(node)
        for node in (matrix.get("topologies") or {}).get("multi-node", {}).get("nodes") or []
    ]
    for row in rows(table):
        label = f"{row['requirement']} / {row['scenario']}"
        for _topology, case_id in expand(row.get("cases") or [], declared)[0]:
            decoded = decode_matrix_case(case_id, matrix)
            if decoded is None:
                continue
            if not decoded["client"]:
                problems.append(f"{label}: {case_id} names no client of the matrix {clients}")
                continue
            if decoded["inbound"] not in inbounds:
                problems.append(
                    f"{label}: {case_id} names the inbound {decoded['inbound']!r}, "
                    "which the matrix does not declare"
                )
            if decoded["node"] is not None and decoded["node"] not in nodes:
                problems.append(
                    f"{label}: {case_id} names the node {decoded['node']!r}, "
                    "which the matrix does not declare"
                )
    covered = named_matrix_rows(table, declared)
    for topology, node, inbound, client in required_matrix_rows():
        if (topology, node, inbound, client) not in covered:
            where = f"{node}/{inbound}/{client}" if node else f"{inbound}/{client}"
            problems.append(f"{topology}: no scenario names the matrix row {where}")
    return problems


def run_directories(path: Path) -> List[Path]:
    """The finished runs at ``path``: the directory itself, or every child with one."""
    path = Path(path)
    if (path / "result.json").exists():
        return [path]
    if path.is_dir():
        return sorted(child for child in path.iterdir() if (child / "result.json").exists())
    return []


def run_count_problems(path: Path) -> List[str]:
    """Read finished runs back: did the positive cases the manifest owes run?

    ``overall: PASS`` is an aggregate; it does not say how many data-plane cases
    contributed. This reads ``result.json`` on the side the claim is about — the
    case list a run wrote — and compares it with the count the manifest states
    for that run's Vision combination. A case that did not pass is a problem even
    if the count is right, because a positive case that skipped is not a positive
    case that ran. Pointed at the artifact root, it judges every run in it.
    """
    runs = run_directories(path)
    if not runs:
        return [f"{Path(path)}: holds no finished run (no result.json)"]
    problems: List[str] = []
    for run in runs:
        problems.extend(_run_count_problems(run))
    return problems


def _run_count_problems(directory: Path) -> List[str]:
    from tools.podman_e2e import catalog

    result = Path(directory) / "result.json"
    try:
        data = json.loads(result.read_text(encoding="utf-8"))
    except OSError as error:
        return [f"{result}: cannot be read back ({error.strerror or error})"]
    except json.JSONDecodeError as error:
        return [f"{result}: is not JSON ({error})"]
    topology = str(data.get("topology") or "")
    # ``environment.vision`` is the matrix's own combination key (``disabled``,
    # ``neither``, ``master-only``, …), so the manifest is read with it directly
    # rather than through a second translation table that could fall behind.
    combination = str((data.get("environment") or {}).get("vision") or "")
    counts = (
        (load_matrix().get("topologies") or {}).get(topology, {}).get("positive_case_counts")
        or {}
    )
    expected = counts.get(combination)
    if expected is None:
        return [
            f"{result}: records the topology {topology!r} and the Vision combination "
            f"{combination!r}, which the manifest declares no count for"
        ]
    # The catalog states the same counts under its own key names; a divergence
    # here would make the audit and a run disagree about what "enough" means.
    declared = catalog.load_catalog().get("expected_positive_case_counts", {})
    if set((declared.get(topology) or {}).values()) != set(counts.values()):
        return [
            f"{result}: the catalog and the matrix disagree about the positive-case "
            f"counts for {topology}"
        ]
    executed = [case for case in data.get("cases") or [] if "-DP-" in str(case.get("id"))]
    failures = [
        f"{result}: {case.get('id')} is {case.get('status')}, so it is not a positive case"
        for case in executed
        if case.get("status") != "PASS"
    ]
    if len(executed) != expected:
        failures.insert(
            0,
            f"{result}: the manifest owes {expected} positive cases for "
            f"{topology}/{combination}, the run executed {len(executed)}",
        )
    return failures


def report_problems(table: Dict[str, Any], path: Optional[Path] = None) -> List[str]:
    """Why the published report is not the text the table renders to.

    The path is resolved here rather than bound as a default, so a caller that
    points the published report somewhere else — a test, a dry run — is judged
    on the file it named.
    """
    path = Path(REPORT_PATH if path is None else path)
    try:
        label = str(path.relative_to(REPO_ROOT))
    except ValueError:
        label = str(path)
    if not path.exists():
        return [f"{label} is missing: run `--markdown` to write it"]
    if path.read_text(encoding="utf-8") != render(table):
        return [
            f"{label} is not what the table renders to: run `--markdown` and commit the result"
        ]
    return []


def audited(include_report: bool = True) -> Tuple[Dict[str, Any], List[str]]:
    """Load the checked-in table and every input it is judged against."""
    table = load_table()
    declared = declared_cases()
    spec = parse_spec()
    jobs = declared_jobs()
    tests = test_index()
    problems = validate(table, spec, declared, jobs, task_boxes(), tests)
    problems.extend(validate_behaviours(table, spec, declared, jobs, tests, load_matrix()))
    problems.extend(positive_counts())
    problems.extend(matrix_problems(table, declared))
    if include_report:
        problems.extend(report_problems(table))
    return table, problems


def main(argv: Optional[Sequence[str]] = None) -> int:
    import sys

    arguments = list(sys.argv[1:] if argv is None else argv)
    strict = "--strict" in arguments
    markdown = "--markdown" in arguments
    if "--verify-run" in arguments:
        position = arguments.index("--verify-run")
        if position + 1 >= len(arguments):
            print("traceability: --verify-run needs a run directory", file=sys.stderr)
            return 2
        target = Path(arguments[position + 1])
        runs = run_directories(target)
        problems = run_count_problems(target)
        if problems:
            print("traceability: the run did not execute the positive cases the manifest owes")
            for problem in problems:
                print(f"  - {problem}")
            return 1
        for run in runs:
            print(f"traceability: {run} executed every positive case it owes")
        return 0
    # ``--markdown`` regenerates the report it is about to judge, so the report
    # check runs after the write and not before it; every other mode judges the
    # published page as it stands, because a report nobody re-renders is a page
    # that has already drifted.
    table, problems = audited(include_report=not markdown)
    if markdown and problems:
        print("traceability: refusing to publish a report over a table that disagrees")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    if markdown:
        REPORT_PATH.write_text(render(table), encoding="utf-8")
        print(f"traceability: wrote {REPORT_PATH.relative_to(REPO_ROOT)}")
        problems = report_problems(table)
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
