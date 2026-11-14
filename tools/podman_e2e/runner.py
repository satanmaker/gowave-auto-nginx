"""Shared result model and runner for the full product Podman E2E.

Result states are distinct and never collapsed: PASS, FAIL, BLOCKED, SKIP,
NOT_APPLICABLE, INCOMPLETE. An unexpected SKIP/BLOCKED or budget exhaustion is
a suite failure, never a green result.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import traceback
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

from tools.live_vps.redaction import redact, register_secret

PASS = "PASS"
FAIL = "FAIL"
BLOCKED = "BLOCKED"
SKIP = "SKIP"
NOT_APPLICABLE = "NOT_APPLICABLE"
INCOMPLETE = "INCOMPLETE"

FAILING_STATES = {FAIL, BLOCKED, INCOMPLETE}


def repository_state(checkout: Optional[Path] = None) -> Dict[str, str]:
    """The commit and tree state the run is measuring, recorded with its result.

    A run is only evidence for the code it started on, and a run started before a
    fix cannot contain it. Recording the revision makes that comparison a fact in
    the artifact instead of a timestamp argument — the checkout is declared safe
    because ``sudo`` runs the suite as root inside an operator-owned tree, and a
    missing git is reported as an unknown revision rather than failing the run.
    """
    root = checkout or Path(__file__).resolve().parent.parent.parent

    def git(*args: str) -> str:
        try:
            completed = subprocess.run(
                ["git", "-c", f"safe.directory={root}", "-C", str(root), *args],
                capture_output=True, text=True, check=False, timeout=60,
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        return completed.stdout.strip() if completed.returncode == 0 else ""

    commit = git("rev-parse", "HEAD")
    if not commit:
        return {"commit": "unknown", "tree": "unknown"}
    dirty = bool(git("status", "--porcelain", "--untracked-files=no"))
    return {"commit": commit, "tree": "dirty" if dirty else "clean"}


def operator_identity(artifact_root: Path) -> Optional[tuple[int, int]]:
    """The uid and gid the run's artifacts belong to.

    ``SUDO_UID``/``SUDO_GID`` are absent when the suite is started from a root
    login shell instead of ``sudo <command>``, which is how the second
    Multi-Node run came out root-owned. The owner of the artifact root is the
    same operator in that case, and when that owner is root itself the run
    leaves ownership alone.

    ``sudo`` invoked from a root shell reports ``SUDO_UID=0``: there the
    credentials name root, handing the tree back to root would change nothing,
    so they are ignored exactly like absent ones.
    """
    uid = os.environ.get("SUDO_UID")
    gid = os.environ.get("SUDO_GID")
    if uid and gid and int(uid) != 0:
        return int(uid), int(gid)
    try:
        owned = artifact_root.stat()
    except OSError:
        return None
    if owned.st_uid == 0:
        return None
    return owned.st_uid, owned.st_gid


def hand_back_artifacts(path: Path, operator: Optional[tuple[int, int]]) -> None:
    """Give the operator who invoked the suite the artifacts a root run produced.

    Root is needed for Podman, but the run's output is a developer artifact: a
    0700 tree owned by root would leave the person who asked for the evidence
    unable to read it, which is exactly what happened to the first Multi-Node
    run. Outside ``sudo`` the function is a no-op and ownership never changes.
    """
    if os.geteuid() != 0 or operator is None:
        return
    uid, gid = operator
    targets = [path, *path.rglob("*")] if path.is_dir() else [path]
    for target in targets:
        try:
            os.chown(target, uid, gid)
        except OSError:
            continue


@dataclass
class CaseResult:
    id: str
    topology: str
    status: str
    duration: float = 0.0
    message: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    evidence_files: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "topology": self.topology,
            "status": self.status,
            "duration": round(self.duration, 3),
            "message": redact(self.message),
            "evidence": {key: redact(str(value)) for key, value in self.evidence.items()},
            "evidence_files": list(self.evidence_files),
        }


@dataclass
class Case:
    id: str
    topology: str
    run: Callable[["RunContext"], Optional[Dict[str, Any]]]
    timeout_seconds: int = 300


class BudgetExhausted(Exception):
    pass


class CaseBlocked(Exception):
    """The case could not observe the product because its prerequisite failed.

    Reported as BLOCKED rather than FAIL: collapsing the two would turn one real
    defect (say, a failed install) into six invented ones.
    """


class CaseIncomplete(Exception):
    """The case observed something that cannot decide the question either way.

    Reported as INCOMPLETE rather than FAIL: a refusal with no working control
    beside it is not evidence that a policy denied anything, and calling it a
    product failure would invent a defect the evidence does not name.
    """


class CaseTimeout(Exception):
    pass


class CaseNotApplicable(Exception):
    """The environment does not contain the subject the case would judge.

    Distinct from INCOMPLETE (the subject was observed, but what was seen cannot
    decide the question) and from SKIP (a declared case that was not executed):
    here there is nothing to observe, and saying so is not a failure of the
    product. A run made only of these proves nothing and is not green either.
    """


class RunAborted(Exception):
    def __init__(self, signum: int) -> None:
        super().__init__(f"run aborted by {signal.Signals(signum).name}")
        self.signum = signum


def _raise_case_timeout(signum: int, frame: Any) -> None:
    raise CaseTimeout("case exceeded its declared timeout")


def _raise_run_aborted(signum: int, frame: Any) -> None:
    raise RunAborted(signum)


class RunContext:
    """Run-scoped identity, artifact directory, and evidence helpers."""

    def __init__(
        self,
        topology: str,
        artifact_root: Path,
        budget_seconds: int,
        run_id: Optional[str] = None,
        labels: Optional[Dict[str, str]] = None,
    ) -> None:
        self.topology = topology
        self.run_id = run_id or f"podman-{topology}-{time.strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:8]}"
        self.artifact_dir = artifact_root / self.run_id
        self.artifact_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.operator = operator_identity(artifact_root)
        # The tree is readable as it is produced, not only when the run ends:
        # an operator watching a long run needs the evidence before the verdict.
        hand_back_artifacts(self.artifact_dir, self.operator)
        self.budget_seconds = budget_seconds
        self.started = time.monotonic()
        self.labels = {"gowave.e2e.run": self.run_id, "gowave.e2e.topology": topology}
        self.labels.update(labels or {})
        self.cleanup_actions: List[Callable[[], None]] = []
        self.environment: Dict[str, Any] = {}
        # Every evidence file is listed here as it is written, so a case result can
        # name the files it produced instead of only inlining their content.
        self.evidence_files: List[str] = []
        # Secrets never live under artifact_dir: artifacts are retained and shared.
        self.secret_dir = Path(tempfile.mkdtemp(prefix=f"gowave-e2e-{self.run_id}-"))
        self.secret_dir.chmod(0o700)
        self.add_cleanup(lambda: shutil.rmtree(self.secret_dir, ignore_errors=True))
        self._previous_signal_handlers: Dict[int, Any] = {}

    def install_signal_handlers(self) -> None:
        """Turn SIGINT/SIGTERM into an in-band abort so cleanup and reporting still run."""
        if not self._main_thread():
            return
        for signum in (signal.SIGINT, signal.SIGTERM):
            if signum in self._previous_signal_handlers:
                continue
            self._previous_signal_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, _raise_run_aborted)

    def restore_signal_handlers(self) -> None:
        for signum, handler in self._previous_signal_handlers.items():
            signal.signal(signum, handler)
        self._previous_signal_handlers.clear()

    @staticmethod
    def _main_thread() -> bool:
        return threading.current_thread() is threading.main_thread()

    def elapsed(self) -> float:
        return time.monotonic() - self.started

    def remaining(self) -> float:
        return self.budget_seconds - self.elapsed()

    def add_cleanup(self, action: Callable[[], None]) -> None:
        self.cleanup_actions.append(action)

    def resource_name(self, prefix: str) -> str:
        """Run-scoped resource name so parallel runs and stale runs never collide."""
        return f"{prefix}-{self.run_id.rsplit('-', 1)[-1]}"

    def write_secret(self, name: str, value: str) -> Path:
        """Materialize a secret as a 0600 file owned by the run and registered for redaction."""
        if "/" in name or name.startswith("."):
            raise ValueError(f"secret name must be a plain file name: {name!r}")
        path = self.secret_dir / name
        tmp = path.with_name(f".{name}.tmp")
        tmp.write_text(value, encoding="utf-8")
        tmp.chmod(0o600)
        os.replace(tmp, path)
        register_secret(value)
        return path

    def evidence_text(self, name: str, text: str) -> Path:
        path = self.artifact_dir / "evidence" / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text(redact(text), encoding="utf-8")
        path.chmod(0o600)
        hand_back_artifacts(path, self.operator)
        relative = str(path.relative_to(self.artifact_dir))
        if relative not in self.evidence_files:
            self.evidence_files.append(relative)
        return path

    def run_cleanup(self) -> List[str]:
        failures = []
        for action in reversed(self.cleanup_actions):
            try:
                action()
            except Exception as exc:  # cleanup failure must be visible
                failures.append(f"{type(exc).__name__}: {exc}")
        return failures


class Runner:
    def __init__(self, context: RunContext) -> None:
        self.context = context
        self.cases: List[Case] = []
        self.results: List[CaseResult] = []
        # Failure collectors are registered by the entrypoint instead of the
        # runner: collection needs Podman, while the runner stays a result
        # machine a unit test can drive without one.
        self.failure_hooks: List[Callable[[CaseResult], None]] = []
        self._diagnosed = False
        self._pending_abort = ""

    def add(self, case: Case) -> None:
        self.cases.append(case)

    def on_failure(self, hook: Callable[[CaseResult], None]) -> None:
        """Register a collector that runs for every non-green case, before cleanup."""
        self.failure_hooks.append(hook)

    def execute(self) -> int:
        self.context.install_signal_handlers()
        unexecuted: List[Case] = []
        abort_message = ""
        try:
            for index, case in enumerate(self.cases):
                if self.context.remaining() <= 0:
                    unexecuted = list(self.cases[index:])
                    break
                started = time.monotonic()
                evidence_before = len(self.context.evidence_files)
                timeout, capped_by_budget = self._case_timeout(case)
                try:
                    self._arm_timeout(timeout)
                    try:
                        evidence = case.run(self.context) or {}
                    finally:
                        self._disarm_timeout()
                    result = CaseResult(case.id, case.topology, PASS, evidence=evidence)
                except RunAborted as exc:
                    abort_message = str(exc)
                    unexecuted = list(self.cases[index + 1:])
                    result = CaseResult(case.id, case.topology, INCOMPLETE, message=abort_message)
                    # No diagnostics here: the operator asked the run to stop, so
                    # probe time is the one thing this path must not spend. The
                    # containers are removed immediately afterwards anyway.
                    self.results.append(self._finish(result, started, evidence_before))
                    break
                except CaseTimeout:
                    status = INCOMPLETE if capped_by_budget else FAIL
                    reason = "runtime budget exhausted" if capped_by_budget else "case timed out"
                    result = CaseResult(case.id, case.topology, status, message=f"{reason} after {timeout:.0f}s")
                except AssertionError as exc:
                    result = CaseResult(case.id, case.topology, FAIL, message=str(exc))
                except CaseBlocked as exc:
                    result = CaseResult(case.id, case.topology, BLOCKED, message=str(exc))
                except CaseNotApplicable as exc:
                    result = CaseResult(case.id, case.topology, NOT_APPLICABLE, message=str(exc))
                except CaseIncomplete as exc:
                    result = CaseResult(case.id, case.topology, INCOMPLETE, message=str(exc))
                except BudgetExhausted as exc:
                    result = CaseResult(case.id, case.topology, INCOMPLETE, message=str(exc))
                except Exception as exc:  # unexpected harness error is never PASS
                    result = CaseResult(
                        case.id,
                        case.topology,
                        FAIL,
                        message=f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}",
                    )
                self.results.append(self._finish_result(result, started, evidence_before))
                if self._pending_abort:
                    abort_message = self._pending_abort
                    unexecuted = list(self.cases[index + 1:])
                    break
        finally:
            # Cleanup must survive every exit path, so signal handlers are restored
            # before running it; a second SIGINT then behaves like an operator abort.
            self.context.restore_signal_handlers()

        for case in unexecuted:
            message = abort_message or "Runtime budget exhausted before the case ran"
            self.results.append(CaseResult(case.id, case.topology, INCOMPLETE, message=message))
        cleanup_failures = self.context.run_cleanup()

        if cleanup_failures:
            self.results.append(
                CaseResult("CLEANUP", self.context.topology, FAIL, message="; ".join(cleanup_failures))
            )
        return self.report()

    def _case_timeout(self, case: Case) -> tuple[float, bool]:
        remaining = max(self.context.remaining(), 0.0)
        declared = case.timeout_seconds if case.timeout_seconds > 0 else remaining
        if declared > remaining:
            return remaining, True
        return declared, False

    def _finish_result(self, result: CaseResult, started: float, evidence_before: int) -> CaseResult:
        """Stamp the case, collecting the failure bundle while its hosts still exist."""
        if self._should_diagnose(result.status):
            self._diagnosed = True
            self._collect_failure_diagnostics(result)
        return self._finish(result, started, evidence_before)

    def _should_diagnose(self, status: str) -> bool:
        """Which non-green outcomes owe a bundle.

        A blocked case is a consequence, not the failure: the case that blocked it
        already collected the state, and probing again for each of the fifty cases
        behind one failed install would spend minutes re-recording the same
        machine. A red run in which no case actually failed still gets one
        bundle, because then the blocked case is the only account of the run.
        """
        return status in (FAIL, INCOMPLETE) or (status == BLOCKED and not self._diagnosed)

    def _collect_failure_diagnostics(self, result: CaseResult) -> None:
        """Run the registered collectors for a non-green case.

        A collector that breaks must not change the verdict: the case already has
        one, and losing the bundle is a smaller loss than reporting a different
        outcome. The breakage is appended to the message so the gap is visible in
        result.json rather than silently absent.
        """
        for hook in self.failure_hooks:
            try:
                hook(result)
            except RunAborted as exc:
                # The operator interrupted while the bundle was being read. The
                # case keeps the verdict it earned; the run stops after it rather
                # than spending the rest of the budget on the next cases.
                self._pending_abort = str(exc)
                return
            except Exception as exc:
                result.message = (
                    f"{result.message}\n[failure diagnostics: {type(exc).__name__}: {exc}]"
                )

    def _finish(self, result: CaseResult, started: float, evidence_before: int) -> CaseResult:
        """Stamp the duration and the evidence files this case produced."""
        result.duration = time.monotonic() - started
        result.evidence_files = self.context.evidence_files[evidence_before:]
        return result

    def _arm_timeout(self, seconds: float) -> None:
        self._armed = False
        if seconds <= 0 or not hasattr(signal, "SIGALRM") or not self._main_thread():
            return
        self._previous_handler = signal.signal(signal.SIGALRM, _raise_case_timeout)
        signal.setitimer(signal.ITIMER_REAL, seconds)
        self._armed = True

    def _disarm_timeout(self) -> None:
        if not getattr(self, "_armed", False):
            return
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, self._previous_handler)
        self._previous_handler = None
        self._armed = False

    @staticmethod
    def _main_thread() -> bool:
        return threading.current_thread() is threading.main_thread()

    def report(self) -> int:
        def payload() -> Dict[str, Any]:
            return {
                "schema": "gowave-podman-e2e-result/v1",
                "run_id": self.context.run_id,
                "topology": self.context.topology,
                "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - self.context.elapsed())),
                "duration": round(self.context.elapsed(), 3),
                "budget_seconds": self.context.budget_seconds,
                "environment": {**self.context.environment, "repository": repository_state()},
                "cases": [result.to_dict() for result in self.results],
            }

        data = payload()
        data["overall"] = overall_status(self.results)
        write_result(self.context.artifact_dir, data)

        audit = redaction_audit(self.context.artifact_dir)
        self.context.environment["redaction_audit"] = audit
        if audit["offences"]:
            # A file that changes when redacted is holding something the policy
            # forbids in a retained artifact. Scrub it, then fail the run rather
            # than ship a credential behind a green verdict.
            scrubbed: List[str] = []
            unscrubbable: List[str] = []
            for name in audit["offences"]:
                done, error = scrub_artifact(self.context.artifact_dir, name)
                (scrubbed if done else unscrubbable).append(done or error)
            message = "retained artifacts held secrets and were scrubbed: " + ", ".join(scrubbed)
            if unscrubbable:
                message += "; could not scrub: " + "; ".join(unscrubbable)
            self.results.append(
                CaseResult("REDACTION", self.context.topology, FAIL, message=message)
            )

        # The second write is what puts the audit itself into the artifact: a green
        # run then carries the file count it read, so "no offences" can be told
        # apart from "nothing was audited".
        data = payload()
        data["overall"] = overall_status(self.results)
        write_result(self.context.artifact_dir, data)

        hand_back_artifacts(self.context.artifact_dir, self.context.operator)
        return 0 if data["overall"] == PASS else 1


def redaction_audit(artifact_dir: Path) -> Dict[str, Any]:
    """Read the artifact tree back and find files that are not a fixed point of ``redact``.

    Every writer in the suite passes its text through ``redact()`` before it
    reaches a retained artifact, and this is what makes that promise checkable
    instead of assumed: a writer that forgets the filter, or a secret registered
    after a file was already written, shows up as content that changes when it is
    redacted. Files that are not UTF-8 text cannot be audited this way and are
    named rather than silently passed.
    """
    offences: List[str] = []
    skipped: List[str] = []
    files = 0
    for path in sorted(artifact_dir.rglob("*")):
        if not path.is_file():
            continue
        files += 1
        relative = str(path.relative_to(artifact_dir))
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            skipped.append(relative)
            continue
        if redact(text) != text:
            offences.append(relative)
    return {"files": files, "offences": offences, "skipped_non_utf8": skipped}


def scrub_artifact(artifact_dir: Path, relative: str) -> tuple[str, str]:
    """Redact one offending artifact in place, keeping its mode."""
    path = artifact_dir / relative
    try:
        text = path.read_text(encoding="utf-8")
        path.write_text(redact(text), encoding="utf-8")
    except (UnicodeDecodeError, OSError) as exc:
        return "", f"{relative}: {type(exc).__name__}: {exc}"
    return relative, ""


def overall_status(results: Iterable[CaseResult]) -> str:
    statuses = [result.status for result in results]
    if not statuses:
        return INCOMPLETE
    if any(status in FAILING_STATES for status in statuses):
        if any(status == FAIL for status in statuses):
            return FAIL
        if any(status == INCOMPLETE for status in statuses):
            return INCOMPLETE
        return BLOCKED
    # A declared case that did not run is not a green result.
    if any(status == SKIP for status in statuses):
        return FAIL
    # Reaching here means only PASS and NOT_APPLICABLE remain. A run in which
    # nothing was applicable demonstrated nothing, and calling that green would
    # reward an empty suite.
    if not any(status == PASS for status in statuses):
        return INCOMPLETE
    return PASS


def write_result(artifact_dir: Path, data: Dict[str, Any]) -> Path:
    artifact_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = artifact_dir / "result.json"
    tmp = artifact_dir / ".result.json.tmp"
    tmp.write_text(redact(json.dumps(data, indent=2)), encoding="utf-8")
    tmp.chmod(0o600)
    os.replace(tmp, path)
    write_junit(artifact_dir, data)
    return path


def write_junit(artifact_dir: Path, data: Dict[str, Any]) -> Path:
    cases = data.get("cases", [])
    root = ET.Element("testsuite", attrib={
        "name": f"PodmanE2E.{data.get('topology', 'unknown')}",
        "tests": str(len(cases)),
        "failures": str(sum(1 for c in cases if c.get("status") == FAIL)),
        "errors": str(sum(1 for c in cases if c.get("status") in (BLOCKED, INCOMPLETE))),
        # JUnit has no "not applicable" concept, so both outcomes that did not
        # judge the product are counted here and told apart by their message.
        "skipped": str(sum(1 for c in cases if c.get("status") in (SKIP, NOT_APPLICABLE))),
    })
    for case in cases:
        element = ET.SubElement(root, "testcase", attrib={
            "name": case.get("id", "unknown"),
            "classname": f"podman.{data.get('topology', 'unknown')}",
            "time": str(case.get("duration", 0)),
        })
        status = case.get("status")
        if status == FAIL:
            ET.SubElement(element, "failure", attrib={"message": case.get("message", "failed")})
        elif status in (BLOCKED, INCOMPLETE):
            ET.SubElement(element, "error", attrib={"message": case.get("message", "incomplete")})
        elif status in (SKIP, NOT_APPLICABLE):
            ET.SubElement(element, "skipped", attrib={
                "message": f"{status}: {case.get('message', '')}".rstrip(),
            })
        evidence_files = case.get("evidence_files") or []
        if evidence_files:
            # JUnit has no evidence field, so the references travel in system-out.
            ET.SubElement(element, "system-out").text = "\n".join(evidence_files)
    path = artifact_dir / "junit.xml"
    path.write_text(redact(ET.tostring(root, encoding="unicode")), encoding="utf-8")
    path.chmod(0o600)
    return path


def require(case_id: str, condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(f"{case_id}: {message}")
