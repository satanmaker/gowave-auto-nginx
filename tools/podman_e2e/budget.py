"""The declared runtime budget: enforced as a deadline, demonstrated as INCOMPLETE.

``tests/cases/matrix.yaml`` states one ``runtime_budget_seconds`` per topology
and one total per gate tier. This module is the seam where those numbers stop
being documentation:

* the entrypoint takes the topology's budget as the deadline and refuses a
  ``--budget-seconds`` that would widen it, so a suite cannot quietly spend more
  wall clock than the matrix promised;
* the suites declare the ``GATE-BUDGET`` case last, which asserts that the
  enforced deadline is the declared one and that the run reaching it stayed
  inside that deadline, and then produces an exhausted run of the real runner
  with no containers at all and reads its report back: the unexecuted case is
  named, ``overall`` is ``INCOMPLETE``, the process exits non-zero, and the
  aggregation refuses to turn that into ``PASS``.

Producing the overrun instead of asserting it is what makes the case evidence
rather than a restatement: the report it reads is written by the same code that
writes the acceptance run's own ``result.json``.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

from tools.podman_e2e import matrix
from tools.podman_e2e.runner import (
    INCOMPLETE, PASS, Case, CaseResult, RunContext, Runner, overall_status,
)

BUDGET_CASE_ID = "GATE-BUDGET"
PROBE_CASE_ID = "GATE-BUDGET-PROBE"
PROBE_RUN_ID = "podman-{topology}-budget-00000000"

# The probe proves the naming, which the runner writes for a case the budget
# consumed before it started. Asserting the phrase keeps a rewording of that
# message from silently emptying the demonstration.
UNEXECUTED_PHRASE = "before the case ran"


def declared(topology: str, data: Optional[Dict[str, Any]] = None) -> int:
    """The deadline the manifest declares for this topology's suite."""
    return matrix.runtime_budget_seconds(data if data is not None else matrix.load(), topology)


def probe(topology: str) -> Dict[str, Any]:
    """Run one case with no budget and read the report back.

    The probe spends no container: the deadline is already gone when the runner
    looks at its first case, which is the same branch a slow install reaches, so
    the outcome comes from the runner instead of from a simulated status.
    """
    with tempfile.TemporaryDirectory(prefix=f"gowave-budget-{topology}-") as directory:
        context = RunContext(
            topology, Path(directory), budget_seconds=0,
            run_id=PROBE_RUN_ID.format(topology=topology),
        )
        runner = Runner(context)
        runner.add(Case(PROBE_CASE_ID, topology, lambda _context: {}))
        status = runner.execute()
        report = json.loads((context.artifact_dir / "result.json").read_text(encoding="utf-8"))
        cases = report.get("cases") or [{}]
        return {
            "exit_status": status,
            "overall": report.get("overall"),
            "case_status": cases[0].get("status"),
            "case_message": cases[0].get("message") or "",
            "case_count": len(cases),
        }


def case_budget(context: RunContext) -> Dict[str, Any]:
    """``GATE-BUDGET``: the declared deadline, the run that stayed inside it, and an overrun that is not a pass."""
    ceiling = declared(context.topology)
    assert 0 < context.budget_seconds <= ceiling, (
        f"{context.topology} runs with a {context.budget_seconds}s budget, outside the "
        f"{ceiling}s tests/cases/matrix.yaml declares: a run that may spend more wall "
        "clock than the manifest promises cannot claim the pre-push or pull-request tier"
    )
    # The case is declared last in both suites, so this clock is the run's own. A
    # suite that spent the deadline before reaching it never runs it — the runner
    # marks the rest of the tail INCOMPLETE — so this assertion covers the run that
    # arrives with seconds left and must still close as the run it reports on.
    elapsed = context.elapsed()
    assert elapsed <= context.budget_seconds, (
        f"the run reached {BUDGET_CASE_ID} after {elapsed:.1f}s of a "
        f"{context.budget_seconds}s deadline: a suite past its deadline owes "
        f"{INCOMPLETE} for the cases it lost, not a pass from this one"
    )
    observed = probe(context.topology)
    assert observed["exit_status"] != 0, (
        f"the exhausted probe exited {observed['exit_status']}: a run that lost its "
        "cases to the budget must not exit 0"
    )
    assert observed["overall"] == INCOMPLETE, (
        f"the exhausted probe reports overall {observed['overall']!r}, not {INCOMPLETE!r}"
    )
    assert observed["case_status"] == INCOMPLETE, (
        f"the unexecuted case reports {observed['case_status']!r}, not {INCOMPLETE!r}"
    )
    assert observed["case_count"] == 1, (
        f"the exhausted probe reported {observed['case_count']} cases: a case dropped "
        "from the report is the truncated pass this case exists to refuse"
    )
    assert UNEXECUTED_PHRASE in observed["case_message"], (
        f"the unexecuted case says {observed['case_message']!r}, which does not name "
        "why it did not run"
    )
    aggregated = overall_status([CaseResult(PROBE_CASE_ID, context.topology, INCOMPLETE)])
    assert aggregated != PASS, (
        f"an {INCOMPLETE} case aggregates to {aggregated!r}: the run could pass with "
        "cases it never executed"
    )
    return {
        "declared_budget_seconds": ceiling,
        "enforced_budget_seconds": context.budget_seconds,
        "elapsed_seconds": round(elapsed, 3),
        "probe_overall": observed["overall"],
        "probe_exit_status": observed["exit_status"],
        "probe_case_message": observed["case_message"],
        "aggregate_of_incomplete": aggregated,
    }
