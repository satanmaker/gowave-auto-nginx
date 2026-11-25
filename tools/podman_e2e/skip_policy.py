#!/usr/bin/env python3
"""What a run that did not test the Data Plane is allowed to report.

``openspec/specs/podman-e2e/spec.md`` §Data Plane E2E
Traffic Through All VPN Endpoints says that with ``TEST_TRAFFIC_VERIFICATION``
off — or with Mihomo runtime testing disabled — the remaining phases still run,
the skipped cases are recorded as ``SKIP``, and the overall status is
``INCOMPLETE``, never ``PASS``.

Three product functions decide that, and all three are driven here: the traffic
suite's own verdict (``tools/live_vps/traffic.py::evaluate_traffic_suite_status``),
the JUnit document a CI reader sees (``tools/live_vps/reporting.py``), and the
runner's phase aggregation, which is read from its source because it is inline in
``run_e2e`` and therefore has no callable seam. The container contour answers the
same question with its own vocabulary: ``tools/podman_e2e/runner.py::overall_status``
turns a declared-but-skipped case into ``FAIL`` where the live runner says
``INCOMPLETE``, and this case records both verdicts rather than pretending they
are one.

The case is a harness-side sentence, so it starts no container and reads no host.
"""
from __future__ import annotations

import json
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List

from tools.live_vps.reporting import write_junit_report, write_result_json
from tools.live_vps.traffic import evaluate_traffic_suite_status
from tools.podman_e2e import preflight_cases
from tools.podman_e2e.runner import PASS, SKIP, CaseResult, overall_status, require

DP14_CASE_ID = "DP-14"

RUNNER = Path(__file__).resolve().parent.parent / "test_live_vps.py"

#: The per-client case count of a run with no optional Vision inbound. The switch
#: does not depend on it, so the same question is asked at both ends of the range.
CASE_COUNTS = (8, 10)

#: A case the suite calls PASS, with the evidence that verdict is read from. A
#: fabricated PASS without these fields is INCOMPLETE, which is why they are
#: spelled rather than implied.
_PASSING_EVIDENCE: Dict[str, Any] = {
    "status": "PASS",
    "target_packets": 12,
    "offload_packets": 0,
    "target_ingress_ok": True,
    "offload_ok": True,
    "egress_matches": True,
    "evidence_method": "tcpdump -i any -c 20",
}


def _passing(count: int) -> List[Dict[str, Any]]:
    return [
        {"tag": f"xray-{index}", "proxy": f"proxy-{index}", **_PASSING_EVIDENCE}
        for index in range(count)
    ]


def _skipped(count: int) -> List[Dict[str, Any]]:
    cases = _passing(count)
    cases[-1] = {
        "tag": cases[-1]["tag"],
        "proxy": cases[-1]["proxy"],
        "status": "SKIP",
        "error": "TEST_TRAFFIC_VERIFICATION=false",
    }
    return cases


def _mihomo(cases: List[Dict[str, Any]], status: str) -> Dict[str, Any]:
    return {"status": status, "client": "mihomo", "results": cases}


def _junit(path: Path) -> Dict[str, Any]:
    """What a CI reader sees in the document the suite wrote."""
    tree = ET.parse(path)
    suite = tree.getroot()
    children: Dict[str, str] = {}
    for case in suite.findall("testcase"):
        child = "passed"
        for tag in ("failure", "error", "skipped"):
            if case.find(tag) is not None:
                child = tag
                break
        children[case.get("name", "")] = child
    return {
        "tests": suite.get("tests"),
        "failures": suite.get("failures"),
        "errors": suite.get("errors"),
        "skipped": suite.get("skipped"),
        "children": children,
    }


def case_skipped_traffic_is_never_pass(product: Any, context: Any) -> Dict[str, Any]:
    """``DP-14``: a switch that skips the Data Plane reports INCOMPLETE, never PASS."""
    statuses: Dict[str, str] = {}
    for count in CASE_COUNTS:
        statuses[f"off-{count}"] = evaluate_traffic_suite_status(
            test_traffic_verification=False,
            xray_results=_passing(count),
            mihomo_results=_mihomo(_passing(count), "PASS"),
            expected_case_count=count,
        )
        statuses[f"on-{count}"] = evaluate_traffic_suite_status(
            test_traffic_verification=True,
            xray_results=_passing(count),
            mihomo_results=_mihomo(_passing(count), "PASS"),
            expected_case_count=count,
        )
        statuses[f"skip-{count}"] = evaluate_traffic_suite_status(
            test_traffic_verification=True,
            xray_results=_skipped(count),
            mihomo_results=_mihomo(_passing(count), "PASS"),
            expected_case_count=count,
        )
    for count in CASE_COUNTS:
        require(
            DP14_CASE_ID,
            statuses[f"off-{count}"] == "INCOMPLETE",
            f"a run with {count} passing cases per client and the switch off reported "
            f"{statuses[f'off-{count}']!r}, so skipping the Data Plane could end in a verdict "
            "the sentence forbids",
        )
        require(
            DP14_CASE_ID,
            statuses[f"on-{count}"] == "PASS",
            f"the same {count} passing cases with the switch on reported "
            f"{statuses[f'on-{count}']!r}, so the INCOMPLETE above is not attributable to the "
            "switch",
        )
        require(
            DP14_CASE_ID,
            statuses[f"skip-{count}"] == "INCOMPLETE",
            f"one case recorded SKIP among {count} passing ones reported "
            f"{statuses[f'skip-{count}']!r}, so a skipped case could ride a green suite",
        )

    with tempfile.TemporaryDirectory(prefix="gowave-dp14-") as directory:
        artifacts = Path(directory)
        state = {
            "test_run_id": "dp14-case",
            "overall": statuses["off-8"],
            "results": {
                "traffic": {
                    "status": statuses["off-8"],
                    "xray_results": _skipped(8),
                    "mihomo_results": _mihomo(_passing(8), "PASS"),
                },
            },
        }
        from tools import test_live_vps

        cases = test_live_vps.build_test_cases_from_state(state)
        junit_path = write_junit_report(artifacts, cases)
        result_path = write_result_json(artifacts, state)
        document = _junit(junit_path)
        require(
            DP14_CASE_ID,
            document["skipped"] == "1" and document["failures"] == "0",
            f"the JUnit document reports {document['skipped']} skipped and "
            f"{document['failures']} failures for one SKIP case, so a CI reader would not see "
            "the case the sentence names",
        )
        skipped_name = "traffic_xray_xray-7"
        require(
            DP14_CASE_ID,
            document["children"].get(skipped_name) == "skipped",
            f"{skipped_name} carries the JUnit child {document['children'].get(skipped_name)!r}, "
            "not 'skipped'",
        )
        require(
            DP14_CASE_ID,
            document["children"].get("phase_traffic") == "error",
            "the traffic phase itself is not an error in JUnit, so a run whose Data Plane was "
            f"skipped would read as a suite without a verdict: {document['children'].get('phase_traffic')!r}",
        )
        require(
            DP14_CASE_ID,
            result_path.stat().st_mode & 0o777 == 0o600,
            f"result.json is mode {oct(result_path.stat().st_mode & 0o777)}, not 0600",
        )
        recorded = json.loads(result_path.read_text(encoding="utf-8"))
        require(
            DP14_CASE_ID,
            recorded["overall"] == "INCOMPLETE"
            and recorded["results"]["traffic"]["xray_results"][-1]["status"] == "SKIP",
            f"result.json records overall {recorded['overall']!r} with the last case "
            f"{recorded['results']['traffic']['xray_results'][-1]['status']!r}",
        )

    container = overall_status([
        CaseResult("EXECUTED", context.topology, PASS),
        CaseResult("SKIPPED", context.topology, SKIP),
    ])
    require(
        DP14_CASE_ID,
        container != PASS,
        f"a declared case recorded SKIP beside a passing one aggregates to {container!r} in "
        "this suite, so the container contour would reward the skip the live sentence refuses",
    )

    # The runner's phase aggregation is inline in ``run_e2e``, so its shape is
    # read from its own source: SKIP has to reach INCOMPLETE, and PASS has to be
    # the branch nothing else claimed. The quote is the decision, not a comment
    # near it.
    text = RUNNER.read_text(encoding="utf-8")
    decision = (
        'elif any(s in ("INCOMPLETE", "SKIP", "UNKNOWN", "RUNNING") for s in phase_statuses):\n'
        '            overall_status = "INCOMPLETE"\n'
        "        else:\n"
        '            overall_status = "PASS"'
    )
    require(
        DP14_CASE_ID,
        decision in text,
        "the runner no longer aggregates a SKIP phase into INCOMPLETE with PASS as the "
        "remaining branch, so a run that skipped the Data Plane could report PASS",
    )
    gate_at, = preflight_cases._source_order(
        RUNNER, "test_traffic_verification=config.test_traffic_verification",
    )
    require(
        DP14_CASE_ID,
        gate_at > 0,
        "the runner does not pass its own TEST_TRAFFIC_VERIFICATION to the traffic gate, so the "
        "switch the sentence names would be read from somewhere else",
    )

    return {
        "switch_off_status": statuses["off-8"],
        "switch_on_status": statuses["on-8"],
        "skip_case_status": statuses["skip-8"],
        "case_counts": ",".join(str(count) for count in CASE_COUNTS),
        "junit_skipped": document["skipped"],
        "junit_failures": document["failures"],
        "junit_phase_child": document["children"].get("phase_traffic"),
        "junit_case_child": document["children"].get(skipped_name),
        "result_overall": recorded["overall"],
        "container_skip_aggregate": container,
        "runner_skip_branch_quoted": decision in text,
        "runner_reads_its_own_switch": gate_at > 0,
    }
