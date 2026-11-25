"""Named groups of cases a run can be required to contain and pass.

The suite already fails when a case reports a failing state, so a group is not a
second verdict on the same cases. It answers the other question: did the cases
exist at all? A recovery case deleted from ``cases()`` leaves a shorter suite
that still reports PASS, and nothing in ``result.json`` says the coverage was
withdrawn. A required group turns that promise into part of the artifact and of
the exit status.

A group is deliberately checked by case id rather than by a tag on ``Case``: the
ids are what CI and the traceability report name, and a group that drifted from
the suite is a defect the run should name, not a tag nobody reads.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence, Tuple

RECOVERY = "recovery"

# The cases that take a role down on purpose — or replay the operator's own
# lifecycle against an installed host — and require the product to come back.
# A case that only reads a healthy install is not here.
GROUP_CASES: Dict[str, Dict[str, Tuple[str, ...]]] = {
    RECOVERY: {
        "aio": (
            "AIO-RESTART",
            "AIO-REVOKE",
            "AIO-IDEMPOTENT",
            "AIO-FAULT-DISK",
            "AIO-FAULT-PANEL",
            "AIO-FAULT-XRAY",
            "AIO-FAULT-LATENCY",
            "ACME-02",
            "AIO-CHANNEL-NOOP",
            "AIO-CHANNEL-ROLLBACK",
            "AIO-INTERRUPT",
            "AIO-CHANNEL-DEV",
        ),
        "multi-node": (
            "MN-SSH-DOWN",
            "MN-REVOKE",
            "MN-OUTAGE",
            "MN-RESTART",
            "MN-RESTORE",
            "MN-BACKUP-BAD",
            "NGX-WORKER-ACME80",
        ),
    },
}

GROUPS: Tuple[str, ...] = tuple(sorted(GROUP_CASES))


def required_ids(group: str, topology: str) -> Tuple[str, ...]:
    """The case ids a run of ``topology`` must contain and pass for ``group``.

    An unknown group, an unknown topology, or a group that selects nothing is a
    configuration error: a run that requires an empty set is required to prove
    nothing, which is exactly the green-looking outcome this module exists to
    refuse.
    """
    if group not in GROUP_CASES:
        raise ValueError(f"unknown case group: {group!r}")
    cases = GROUP_CASES[group]
    if topology not in cases:
        raise ValueError(f"group {group!r} declares no cases for topology {topology!r}")
    ids = cases[topology]
    if not ids:
        raise ValueError(f"group {group!r} selects no cases for topology {topology!r}")
    return ids


def unmet(
    required: Sequence[str], results: Iterable[Any], passing: str = "PASS",
) -> List[str]:
    """Name every required case that is absent or did not pass.

    Absent and not-passing are reported differently: the first says the run
    never declared the case, the second says the product or the host contradicted
    it. Both make the group unmet, and the message keeps them apart.
    """
    seen = {result.id: result.status for result in results}
    problems: List[str] = []
    for case_id in required:
        status = seen.get(case_id)
        if status is None:
            problems.append(f"{case_id}: not declared in this run")
        elif status != passing:
            problems.append(f"{case_id}: {status}")
    return problems
