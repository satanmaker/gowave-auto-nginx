"""The report an overall PASS is read from: every case named, and the schema.

``openspec/specs/live-vps-e2e/spec.md`` §Result Status Semantics says three
things about the machine-readable result rather than about a host: an overall
``PASS`` requires every active Data Plane runtime case, a case that did not run
is not passing, and each failing case is identified individually in
``result.json``. A report is the one product surface this suite can produce with
no VPS at all, so ``GATE-STATUS`` produces one instead of restating the rule.

The run it reads is made by the real ``Runner`` over the case ids the matrix
declares — sixteen with Vision off, eighteen or twenty with it configured — with
the outcomes chosen by raising the runner's own exceptions. No container is
started, and the ``result.json`` and ``junit.xml`` it reads back are written by
the same ``write_result`` and ``write_junit`` that write an acceptance run's own
report, which is what makes the case evidence rather than a second copy of the
aggregation.
"""
from __future__ import annotations

import json
import re
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from tools.podman_e2e import matrix
from tools.podman_e2e.runner import (
    BLOCKED,
    FAIL,
    INCOMPLETE,
    NOT_APPLICABLE,
    PASS,
    SKIP,
    Case,
    CaseIncomplete,
    CaseResult,
    RunContext,
    Runner,
    overall_status,
)

STATUS_CASE_ID = "GATE-STATUS"
PROBE_RUN_ID = "podman-{topology}-status-00000000"
REPORT_SCHEMA = "gowave-podman-e2e-result/v1"

#: The statuses a report of this suite may carry. The live runner's vocabulary is
#: ``PASS``, ``FAIL``, ``SKIP``, ``NOT_RUN``, ``PARTIAL``, ``INCOMPLETE`` and
#: ``TEARDOWN_FAILED``; this suite reports ``BLOCKED`` for a case whose
#: prerequisite failed and ``NOT_APPLICABLE`` for a case whose subject the
#: environment does not contain, and has no partial or teardown phase to name.
#: ``docs/PODMAN_E2E_DISCOVERY.md`` records that mapping.
VOCABULARY = (PASS, FAIL, BLOCKED, SKIP, NOT_APPLICABLE, INCOMPLETE)

#: The fields a report must carry, and the fields every case in it must carry.
REQUIRED_REPORT_KEYS = (
    "schema", "run_id", "topology", "started", "duration",
    "budget_seconds", "environment", "cases", "overall",
)
REQUIRED_CASE_KEYS = (
    "id", "topology", "status", "duration", "message", "evidence", "evidence_files",
)

#: ``started`` is what ``finished_at`` is derived from: the report records the
#: start and the duration, so a reader has both ends of the window.
STARTED_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

_EXCEPTIONS: Dict[str, type] = {
    FAIL: AssertionError,
    INCOMPLETE: CaseIncomplete,
}
_MESSAGES: Dict[str, str] = {
    FAIL: "the tuple carried no request this host saw",
    INCOMPLETE: "the capture named no source for the request",
}


def runtime_case_ids(
    topology: str, vision: bool = False, worker_vision: bool = False,
) -> List[str]:
    """The Data Plane case ids the matrix declares for one configuration.

    The ids come from ``tests/cases/matrix.yaml`` rather than from a list kept
    here, so a probe that counted its own cases would notice a matrix that grew
    a tuple. The Multi-Node contour contributes both nodes, because a Worker
    tuple is a case of its own.
    """
    data = matrix.load()
    if topology == matrix.MULTI_NODE:
        nodes = (("master", vision), ("worker", worker_vision))
    elif topology == matrix.AIO:
        nodes = (("", vision),)
    else:
        raise KeyError(f"no Data Plane case pattern is declared for {topology!r}")
    ids: List[str] = []
    for node, node_vision in nodes:
        for inbound, client in matrix.tuples(data, node_vision):
            ids.append(matrix.case_id(
                data, topology, str(inbound["id"]), client, node=node,
            ))
    return ids


def _outcome(case_id: str, status: str) -> Callable[[RunContext], Optional[Dict[str, Any]]]:
    """A case body that reaches ``status`` through the runner's own exception."""

    def run(_context: RunContext) -> Optional[Dict[str, Any]]:
        if status == PASS:
            return {}
        raise _EXCEPTIONS[status](f"{case_id}: {_MESSAGES[status]}")

    return run


def _junit_outcomes(path: Path) -> Dict[str, str]:
    """The child element each test case carried: ``failure``, ``error``, ``skipped`` or none."""
    outcomes: Dict[str, str] = {}
    for element in ET.parse(path).getroot().findall("testcase"):
        child = ""
        for tag in ("failure", "error", "skipped"):
            if element.find(tag) is not None:
                child = tag
                break
        outcomes[str(element.get("name") or "")] = child
    return outcomes


def probe(
    topology: str,
    failing: Sequence[str] = (),
    incomplete: Sequence[str] = (),
    vision: bool = False,
    worker_vision: bool = False,
) -> Dict[str, Any]:
    """Run the real runner over the matrix's own case ids and read the report back.

    A named outcome that the matrix does not declare is refused rather than
    silently dropped: a probe measuring a case it invented would report on a
    suite nobody runs.
    """
    ids = runtime_case_ids(topology, vision=vision, worker_vision=worker_vision)
    chosen: Dict[str, str] = {}
    for case_id in ids:
        if case_id in failing:
            chosen[case_id] = FAIL
        elif case_id in incomplete:
            chosen[case_id] = INCOMPLETE
        else:
            chosen[case_id] = PASS
    unknown = sorted((set(failing) | set(incomplete)) - set(ids))
    if unknown:
        raise ValueError(
            "the probe was told to fail cases the matrix does not declare: "
            + ", ".join(unknown)
        )

    with tempfile.TemporaryDirectory(prefix=f"gowave-status-{topology}-") as directory:
        context = RunContext(
            topology, Path(directory), budget_seconds=300,
            run_id=PROBE_RUN_ID.format(topology=topology),
        )
        runner = Runner(context)
        for case_id, status in chosen.items():
            runner.add(Case(case_id, topology, _outcome(case_id, status), timeout_seconds=30))
        exit_status = runner.execute()
        report = json.loads((context.artifact_dir / "result.json").read_text(encoding="utf-8"))
        junit = _junit_outcomes(context.artifact_dir / "junit.xml")
    return {
        "exit_status": exit_status,
        "overall": report.get("overall"),
        "report": report,
        "junit": junit,
        "cases": {str(case.get("id")): case for case in report.get("cases") or []},
    }


def _failing(report: Dict[str, Any]) -> List[str]:
    return [
        str(case.get("id"))
        for case in report.get("cases") or []
        if case.get("status") == FAIL
    ]


def case_status_semantics(context: RunContext) -> Dict[str, Any]:
    """``GATE-STATUS``: what an overall PASS requires, and what a red run must say."""
    data = matrix.load()
    topology = context.topology
    runtime = runtime_case_ids(topology)
    declared = matrix.positive_count(data, topology)
    assert len(runtime) == declared, (
        f"the matrix declares {declared} runtime cases for {topology} and the probe "
        f"built {len(runtime)}: a tuple the suite runs but this count does not see "
        "is a case an overall PASS would not require"
    )
    assert len(set(runtime)) == len(runtime), (
        "two tuples share one case id: the report would name a failure the reader "
        "cannot tell apart from its twin"
    )

    # Two of the runtime cases fail and the rest pass, so the verdict cannot come
    # from anything but them. The live sentence's own example is fourteen of
    # sixteen passing on a cluster, which is this shape at the matrix's count.
    two = runtime[:2]
    red = probe(topology, failing=two)
    assert red["exit_status"] != 0, (
        f"a run with two failing runtime cases exited {red['exit_status']}: a red "
        "report that exits zero hands the gate a pass"
    )
    assert red["overall"] == FAIL, (
        f"{declared - 2} passing cases and two failing ones report overall "
        f"{red['overall']!r}, not {FAIL!r}: an overall PASS that survives a lost "
        "runtime case is the sentence's whole subject"
    )
    assert _failing(red["report"]) == two, (
        f"the report names {_failing(red['report'])} as failing, not {two}: a failing "
        "case identified only in aggregate is not identified"
    )
    for case_id in two:
        assert case_id in str(red["cases"][case_id].get("message") or ""), (
            f"{case_id} failed with the message {red['cases'][case_id].get('message')!r}, "
            "which does not name the case that failed"
        )
    assert len(red["cases"]) == declared, (
        f"the report carries {len(red['cases'])} cases of {declared}: a case dropped "
        "from the report is the truncated pass this case refuses"
    )

    # One failing runtime case is enough, and the run that has not decided is told
    # apart from the run that failed: the eight INCOMPLETE tuples of the All-in-One
    # run on 15 November reported INCOMPLETE, never FAIL, because a capture that
    # decided nothing is not a product that refused anything.
    undone = probe(topology, incomplete=runtime)
    assert undone["overall"] == INCOMPLETE, (
        f"a run whose {declared} runtime cases all came back {INCOMPLETE} reports "
        f"{undone['overall']!r}, not {INCOMPLETE!r}"
    )
    assert not _failing(undone["report"]), (
        f"a run that decided nothing names {_failing(undone['report'])} as failing: a "
        "capture that saw nothing is not a product failure"
    )
    for case in undone["report"]["cases"]:
        assert case["status"] == INCOMPLETE, (
            f"{case['id']} reports {case['status']!r} in a run whose runtime cases "
            f"were all {INCOMPLETE}"
        )

    # The same question with Vision configured, which is where the count is
    # eighteen or twenty, and where the report and JUnit both have to name the
    # failing case rather than only the aggregate.
    both_nodes = topology == matrix.MULTI_NODE
    vision_ids = runtime_case_ids(topology, vision=True, worker_vision=both_nodes)
    expected = matrix.positive_count(data, topology, vision=True, worker_vision=both_nodes)
    assert len(vision_ids) == expected, (
        f"with Vision configured the matrix owes {expected} runtime cases for "
        f"{topology} and the probe built {len(vision_ids)}"
    )
    vision_id = next(
        (case_id for case_id in vision_ids if matrix.VISION_INBOUND in case_id), "",
    )
    assert vision_id, (
        f"no case id of {vision_ids} names the {matrix.VISION_INBOUND} inbound: a "
        "Vision-enabled run that cannot name its Vision case cannot report on it"
    )
    core_id = next(case_id for case_id in vision_ids if case_id != vision_id)
    vision_red = probe(
        topology, failing=(core_id, vision_id), vision=True, worker_vision=both_nodes,
    )
    assert vision_red["overall"] == FAIL, (
        f"a Vision-enabled run with {core_id} and {vision_id} failing reports "
        f"{vision_red['overall']!r}, not {FAIL!r}"
    )
    for case_id in (core_id, vision_id):
        assert case_id in _failing(vision_red["report"]), (
            f"{case_id} failed and result.json does not name it: {_failing(vision_red['report'])}"
        )
        assert vision_red["junit"].get(case_id) == "failure", (
            f"{case_id} carries the JUnit child {vision_red['junit'].get(case_id)!r}, "
            "not 'failure': a CI reader sees only what JUnit says"
        )

    # A case the run declared and did not execute is not passing, and a pass
    # beside it does not soften that: this suite has no switch that disables the
    # Data Plane — the Data Plane is its subject — so the live sentence's
    # `TEST_TRAFFIC_VERIFICATION=false` has no counterpart here beyond the
    # aggregate refusing a skipped case. `docs/PODMAN_E2E_DISCOVERY.md` records
    # that, and that the live runner calls the same outcome INCOMPLETE where this
    # suite calls it FAIL.
    skipped = overall_status([CaseResult("EXECUTED", topology, PASS),
                              CaseResult("SKIPPED", topology, SKIP)])
    assert skipped != PASS, (
        f"a declared case recorded {SKIP} beside a passing one aggregates to "
        f"{skipped!r}: the live sentence calls a skip non-passing, and this suite "
        "must not be the contour that rewards it"
    )

    # The schema of the report the three sentences above are read from.
    report = red["report"]
    missing = [key for key in REQUIRED_REPORT_KEYS if key not in report]
    assert not missing, (
        f"result.json is missing {missing}: a report without these fields cannot be "
        "the document the status is read from"
    )
    assert report["schema"] == REPORT_SCHEMA, (
        f"the report declares the schema {report['schema']!r}, not {REPORT_SCHEMA!r}"
    )
    assert report["run_id"] == PROBE_RUN_ID.format(topology=topology), (
        f"the report names the run {report['run_id']!r}"
    )
    assert report["topology"] == topology, (
        f"the report names the topology {report['topology']!r}"
    )
    assert STARTED_RE.match(str(report["started"])), (
        f"started reads {report['started']!r}, which is not a timestamp a reader can "
        "subtract the duration from"
    )
    assert isinstance(report["duration"], (int, float)) and report["duration"] >= 0, (
        f"duration reads {report['duration']!r}: without it the window has a start "
        "and no end"
    )
    assert report["overall"] in VOCABULARY, (
        f"overall reads {report['overall']!r}, outside the vocabulary {VOCABULARY}"
    )
    repository = (report.get("environment") or {}).get("repository") or {}
    assert set(repository) == {"commit", "tree"}, (
        f"the report records the revision as {repository!r}: a run is evidence only "
        "for the commit it started on"
    )
    for case in report["cases"]:
        absent = [key for key in REQUIRED_CASE_KEYS if key not in case]
        assert not absent, (
            f"the case {case.get('id')!r} is missing {absent} in result.json"
        )
        assert case["status"] in VOCABULARY, (
            f"the case {case.get('id')!r} reports {case['status']!r}, outside the "
            f"vocabulary {VOCABULARY}"
        )

    return {
        "runtime_cases": declared,
        "vision_runtime_cases": expected,
        "failing_named": ", ".join(two),
        "vision_failing_named": f"{core_id}, {vision_id}",
        "two_failing_overall": red["overall"],
        "vision_failing_overall": vision_red["overall"],
        "junit_child": vision_red["junit"].get(vision_id, ""),
        "undecided_overall": undone["overall"],
        "skip_aggregate": skipped,
        "report_schema": report["schema"],
        "report_keys": len(REQUIRED_REPORT_KEYS),
    }
