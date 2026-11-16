"""Durable run state: what a phase may do, and what the run records when it may not.

The runner keeps one mode-0600 ``run-state.json`` per run and resumes partial
modes from it. The decisions that belong to that record rather than to the phase
code live here: whether the pair-wide lock is still held, what a phase that was
refused for lack of it leaves behind, which run id may name an artifact
directory, whether a partial phase may resume a stored run, and whether the
disposable baseline still looks the way preflight recorded it. Each is answered
as a value a case can read instead of a branch buried in the CLI.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Protocol, Tuple

from .preflight import REQUIRED_PORTS_DEFAULT, VISION_PORTS, check_disposable_gate


#: The phases that change a host. A lost lock stops every one of them; a
#: read-only phase may still report what it sees.
MUTATING_PHASES = ("install", "traffic", "negative", "teardown")

#: What a phase needs to have happened before it may touch a host. A partial
#: mode that is missing its prerequisite is refused rather than started: the
#: phase's own record is the only evidence that the host is in the state it
#: assumes, and `full` is the mode that runs the chain in order.
PHASE_PREREQUISITES: Dict[str, Tuple[str, ...]] = {
    "install": ("preflight",),
    "verify": ("install",),
    "traffic": ("verify",),
    "negative": ("install",),
}

#: A phase status that means this phase already ran and reported. Repeating it
#: implicitly would re-run a destructive phase over its own result.
TERMINAL_STATUSES = ("PASS", "FAIL", "INCOMPLETE", "TEARDOWN_FAILED")

#: An artifact directory is named by a run id and nothing else: no separator, no
#: dot-only name, no NUL, and at most 64 characters.
RUN_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
RUN_ID_RULE = (
    "run-id must match [A-Za-z0-9][A-Za-z0-9._-]{0,63} and must not be '.' or '..'"
)


class RunIdRejected(ValueError):
    """A run id that may not name a directory below the artifact root."""


def validate_run_id(value: str) -> str:
    """The run id, or the sentence saying why it cannot name a directory.

    A NUL is refused before the pattern because a NUL truncates a path in the
    syscall layer while leaving the string that carried it intact, so a name that
    validated with one could still open a different directory than it names.
    """
    if "\x00" in value:
        raise RunIdRejected("run-id must not contain a NUL byte")
    if not RUN_ID_PATTERN.fullmatch(value) or value in (".", ".."):
        raise RunIdRejected(RUN_ID_RULE)
    return value


def artifact_path(artifact_root: Path, run_id: str) -> Path:
    """The directory a run id names, proved to stay below the artifact root.

    The id is validated first, then the path it would name: a component of the
    root may itself be a link, and a resolved candidate outside the root would
    let a run write wherever the link pointed. Nothing is created here — the
    caller creates the directory only after this answered.
    """
    validate_run_id(run_id)
    candidate = artifact_root / run_id
    if candidate.is_symlink():
        raise RunIdRejected("run-id artifact path must not be a symlink")
    root = artifact_root.resolve(strict=False)
    resolved = candidate.resolve(strict=False)
    if not resolved.is_relative_to(root):
        raise RunIdRejected("run-id artifact path escapes artifacts/live-vps")
    return candidate


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


@dataclass(frozen=True)
class ResumeVerdict:
    """Whether a partial phase may act on the state it was handed."""

    ok: bool
    error: str = ""


def resume_gate(
    state: Dict[str, Any],
    *,
    run_id: str,
    commit: str,
    config_fingerprint: str,
    phase: str,
) -> ResumeVerdict:
    """A partial phase resumes only the run that produced this record.

    The record names a run, a commit and a non-secret configuration identity;
    a phase invoked with any of those different is acting on somebody else's
    host state, so it is refused before the first remote command. A phase that
    already reported is refused too — a second implicit run would repeat a
    destructive phase over its own result — and so is a phase whose prerequisite
    has not reported PASS. `teardown` is the exception to the status chain: what
    it needs is both saved baselines, because the restore is what it compares
    against.
    """
    if state.get("test_run_id") != run_id:
        return ResumeVerdict(False, "run-id does not match persisted state identity")
    if state.get("repository_commit") != commit:
        return ResumeVerdict(
            False,
            f"State repository commit mismatch: {state.get('repository_commit')} != {commit}",
        )
    if state.get("config_fingerprint", {}) != config_fingerprint:
        return ResumeVerdict(False, "Non-secret configuration identity mismatch with run state")
    results = state.get("results", {})
    if not isinstance(results, dict):
        return ResumeVerdict(False, "run state carries no phase results to resume from")
    if results.get(phase, {}).get("status") in TERMINAL_STATUSES:
        return ResumeVerdict(
            False,
            f"phase '{phase}' already has a terminal result; refusing implicit destructive rerun",
        )
    for prerequisite in PHASE_PREREQUISITES.get(phase, ()):
        if results.get(prerequisite, {}).get("status") != "PASS":
            return ResumeVerdict(False, f"Prerequisite {prerequisite} is not PASS")
    if phase == "teardown":
        preflight = results.get("preflight", {})
        if not preflight.get("master_baseline") or not preflight.get("worker_baseline"):
            return ResumeVerdict(
                False,
                "Prerequisite preflight baselines for both VPS are missing; refusing teardown",
            )
    return ResumeVerdict(True)


def _gate_facts(manifest: Dict[str, Any], vision_enabled: bool) -> Dict[str, Any]:
    """The parts of a baseline the disposable gate decides on, and only those.

    `os_kernel`, `disk_usage`, `tcp_listeners_raw` and `swap_info` move on any
    host between two reads and say nothing about whether it is disposable;
    comparing them would turn every install into a drift refusal.
    """
    required = set(REQUIRED_PORTS_DEFAULT)
    if vision_enabled:
        required.update(VISION_PORTS)
    return {
        "existing_gowave_dirs": sorted(manifest.get("existing_gowave_dirs") or []),
        "gowave_services": sorted(
            name for name in (manifest.get("running_services") or [])
            if "gowave" in str(name).lower()
        ),
        "required_ports": sorted(required.intersection(manifest.get("listening_ports") or [])),
        "required_tools": dict(manifest.get("required_tools") or {}),
    }


def baseline_drift(
    preflight: Dict[str, Any],
    master_now: Dict[str, Any],
    worker_now: Dict[str, Any],
    *,
    vision_enabled: bool = False,
) -> str:
    """Why a fresh baseline is not the snapshot preflight approved, or ``""``.

    `install` re-collects both baselines after it holds both locks, because the
    preflight snapshot was taken before the locks and another actor could have
    touched a host in between. The comparison is the gate's own view of the
    manifest, and a fresh baseline that no longer passes the gate is a drift even
    when every recorded field matches.
    """
    for role, now in (("master", master_now), ("worker", worker_now)):
        stored = preflight.get(f"{role}_baseline") or {}
        if not stored:
            return f"the preflight snapshot has no {role} baseline to compare against"
        before = _gate_facts(stored, vision_enabled)
        after = _gate_facts(now, vision_enabled)
        for field in ("existing_gowave_dirs", "gowave_services", "required_ports", "required_tools"):
            if before[field] != after[field]:
                return (
                    f"the disposable baseline on the {role} drifted since preflight: "
                    f"{field} was {before[field]!r}, now {after[field]!r}"
                )
        passed, errors = check_disposable_gate(now, vision_enabled=vision_enabled)
        if not passed:
            return (
                f"the disposable baseline on the {role} no longer passes the gate: "
                + "; ".join(errors)
            )
    return ""
