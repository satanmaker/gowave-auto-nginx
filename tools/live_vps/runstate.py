"""Durable run state: what a phase may do, and what the run records when it may not.

The runner keeps one mode-0600 ``run-state.json`` per run and resumes partial
modes from it. Two decisions belong to that record rather than to the phase code:
whether the pair-wide lock is still held, and what a phase that was refused for
lack of it leaves behind. Both are answered here so a refusal is a value a case
can read instead of a branch buried in the CLI.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Protocol


#: The phases that change a host. A lost lock stops every one of them; a
#: read-only phase may still report what it sees.
MUTATING_PHASES = ("install", "traffic", "negative", "teardown")


class LockHolder(Protocol):
    """What a phase gate needs from the pair-wide remote lock."""

    def check_alive(self) -> bool:
        """Both lock-holder sessions are still running."""
        ...


@dataclass(frozen=True)
class PhaseGate:
    """A gate's verdict, in the shape the run state stores for the phase."""

    ok: bool
    status: str
    error: str = ""

    def record(self) -> Dict[str, Any]:
        record: Dict[str, Any] = {"status": self.status}
        if self.error:
            record["error"] = self.error
        return record


def pair_lock_gate(lock: LockHolder, phase: str) -> PhaseGate:
    """A mutating phase starts only while both lock-holder sessions are alive.

    The kernel releases a host's lock the moment its holder dies, so a lost SSH
    session is not a warning to log and continue past: the next mutating phase
    would run with no exclusivity at all, and a second runner could hold the same
    host while this one changed it. The verdict is INCOMPLETE rather than FAIL
    because the run did not observe the host disagree with it — it lost the right
    to speak for the host, and may only resume after reacquiring both locks and
    revalidating the saved run state.
    """
    if phase not in MUTATING_PHASES:
        return PhaseGate(ok=True, status="")
    if lock.check_alive():
        return PhaseGate(ok=True, status="")
    return PhaseGate(
        ok=False,
        status="INCOMPLETE",
        error=(
            f"the pair-wide mutation lock was lost before {phase} started: at least one "
            "SSH lock-holder session is gone, so this runner no longer holds the host "
            "exclusively; the phase was not started"
        ),
    )
