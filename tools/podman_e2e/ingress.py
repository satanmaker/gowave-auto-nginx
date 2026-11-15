#!/usr/bin/env python3
"""Bracket one proxy request with packet captures on every host that could take it.

The live controller brackets each request with ``tcpdump`` on both VPS and keeps,
per host, the source addresses the capture saw. This is the same measurement
taken from inside the two containers, with the same three facts and the same
verdicts:

* a capture names the proxy's destination port and nothing else, so a client
  whose visible address is not the expected one is discovered rather than
  silently filtered out;
* each host reports the client's address itself, over a connection the run holds
  to its SSH port, so the address a capture is attributed against is the host's
  answer and not the harness's constant;
* the intended host has to show at least one segment from that address, the
  other host has to show none, and evidence that is missing or ambiguous is
  INCOMPLETE while traffic at the wrong host is FAIL.

Nothing is persisted: the probe prints a summary of counts per source address,
the harness reads it, and there is no file to delete — which is a property of the
shipped code rather than of this docstring, held by
``tests/test_podman_ingress.py``.
"""
from __future__ import annotations

import json
import os
import select
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

PROBE_SCRIPT = "/repo/tools/podman_e2e/ingress_probe.py"

# The live controller gives each capture 45 s; a transfer's own budget is 30 s,
# so this outlives the request it brackets without outliving a hung case.
CAPTURE_WINDOW_SECONDS = 45
# How long a probe may take to print its readiness line. A container that has to
# start a Python interpreter is the slow case; a missing script exits at once.
READY_TIMEOUT_SECONDS = 20
SUMMARY_TIMEOUT_SECONDS = 20
IDENTITY_TIMEOUT_SECONDS = 20
# The host's own sshd: the live controller reads the client's address off its SSH
# session, and this is the connection a container host makes on its behalf. The
# request's destination port is excluded from it by construction — the capture
# names the proxy port, the identity connection names 22.
IDENTITY_PORT = 22
# How many foreign sources a summary keeps. Enough to name what the capture saw
# instead of the client, small enough to stay a fact rather than a transcript.
MAX_FOREIGN_RECORDED = 5

PASS = "PASS"
FAIL = "FAIL"
INCOMPLETE = "INCOMPLETE"


class IngressUnavailable(Exception):
    """Evidence the harness could not obtain, named so the case can call it INCOMPLETE."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Host:
    """One host a proxy request could arrive at."""

    role: str
    container: str
    name: str


def listener_port(inbound: Dict[str, Any]) -> int:
    """The public port the inbound's listener is declared on, from the matrix.

    The matrix is where a tuple's transport is stated, so the port the capture
    filters on is read from the same declaration the product was installed from:
    a manifest that moves an inbound to another port moves the filter with it
    instead of leaving the filter pointing at a port nothing uses.
    """
    declared = str(inbound.get("listener") or "")
    port = declared.partition("/")[0].strip()
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise IngressUnavailable(
            "no_endpoint_port",
            f"the inbound {inbound.get('id')!r} declares listener {declared!r}, so the capture "
            "has no destination port to filter on",
        )
    return int(port)


class Session:
    """One probe process inside a container, spoken to over a pipe.

    Readiness, evidence and the stop request all travel as JSON lines, so the
    capture never needs a file: a summary that arrives on the pipe is the whole
    record of what the host saw.
    """

    def __init__(self, label: str, process: "subprocess.Popen[bytes]",
                 timeout: float = SUMMARY_TIMEOUT_SECONDS) -> None:
        self.label = label
        self.process = process
        self.timeout = timeout
        self._buffer = b""
        self._closed = False

    def message(self, timeout: float) -> Dict[str, Any]:
        """The next JSON object the probe printed, or a named failure."""
        deadline = time.monotonic() + timeout
        while b"\n" not in self._buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.abandon()
                raise IngressUnavailable(
                    "no_probe_summary",
                    f"{self.label}: the probe printed no summary line within {timeout}s",
                )
            assert self.process.stdout is not None
            ready, _, _ = select.select([self.process.stdout], [], [], remaining)
            if not ready:
                continue
            chunk = os.read(self.process.stdout.fileno(), 65536)
            if not chunk:
                self.abandon()
                raise IngressUnavailable(
                    "no_probe_summary",
                    f"{self.label}: the probe exited before printing a summary "
                    f"({self._trace()})",
                )
            self._buffer += chunk
        line, _, self._buffer = self._buffer.partition(b"\n")
        text = line.decode("utf-8", "replace").strip()
        if not text:
            return {}
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            self.abandon()
            raise IngressUnavailable(
                "no_probe_summary",
                f"{self.label}: the probe printed {text[:400]!r} instead of a summary",
            ) from None
        return payload if isinstance(payload, dict) else {}

    def release(self) -> None:
        """Ask the probe to stop; its answer is the evidence."""
        if self._closed:
            return
        self._closed = True
        try:
            assert self.process.stdin is not None
            self.process.stdin.write(b"stop\n")
            self.process.stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            pass

    def finish(self, timeout: Optional[float] = None) -> Dict[str, Any]:
        """Stop the probe and read the summary it owes.

        ``timeout`` defaults to the deadline the session was started with, so a
        summary the probe never prints cannot hold the case open past it.
        """
        timeout = self.timeout if timeout is None else timeout
        if self._closed:
            message = self.message(timeout)
        else:
            self.release()
            message = self.message(timeout)
        self._await_exit()
        return message

    def abandon(self) -> None:
        """Leave nothing running: a capture that outlives its case is a leak."""
        self._closed = True
        try:
            if self.process.poll() is None:
                self.process.kill()
            self.process.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            pass
        for handle in (self.process.stdin, self.process.stdout):
            try:
                if handle is not None:
                    handle.close()
            except OSError:
                pass

    def _await_exit(self) -> None:
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.abandon()
            raise IngressUnavailable(
                "no_probe_summary",
                f"{self.label}: the probe printed a summary but did not exit",
            ) from None
        for handle in (self.process.stdin, self.process.stdout):
            try:
                if handle is not None:
                    handle.close()
            except OSError:
                pass

    def _trace(self) -> str:
        """Whatever the probe printed before it died, for the failure message."""
        text = self._buffer.decode("utf-8", "replace").strip()
        return text[-400:] if text else f"exit {self.process.poll()}"


class Backend:
    """How probes are started inside a run's containers."""

    def spawn_probe(self, container: str, argv: Sequence[str],
                    timeout: float = SUMMARY_TIMEOUT_SECONDS) -> Session:
        raise NotImplementedError

    def run(self, container: str, argv: Sequence[str], timeout: int = 60) -> subprocess.CompletedProcess:
        raise NotImplementedError


class PodmanBackend(Backend):
    """The real one: one ``podman exec`` per probe, pipes both ways."""

    def __init__(self, podman: Any) -> None:
        self.podman = podman

    def spawn_probe(self, container: str, argv: Sequence[str],
                    timeout: float = SUMMARY_TIMEOUT_SECONDS) -> Session:
        """Start one probe with the deadline its session cannot outlive.

        ``subprocess.Popen`` takes no ``timeout`` of its own — it returns as soon
        as the child exists — so the bound has to be named here and carried by
        the session: it is how long ``finish`` waits for the summary, and the
        process is killed when that passes. The readiness audit requires this
        helper to be the only ``Popen`` in the package and to declare the
        deadline it enforces, because elsewhere the same call would be a process
        with no bound at all.
        """
        process = subprocess.Popen(
            [self.podman.binary, "exec", "-i", container, *argv],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0,
        )
        return Session(f"{container} {' '.join(argv[1:3])}", process, timeout=timeout)

    def run(self, container: str, argv: Sequence[str], timeout: int = 60) -> subprocess.CompletedProcess:
        return self.podman.exec(container, list(argv), check=False, timeout=timeout)


def _probe_argv(*arguments: str) -> List[str]:
    return ["python3", "-u", PROBE_SCRIPT, *arguments]


def _hold(backend: Backend, engine: str, hosts: Sequence[Host],
          identity_port: int) -> Tuple[Optional[Session], Dict[str, int]]:
    """Hold one connection per host and learn the local port of each."""
    peers = [item for host in hosts for item in ("--peer", f"{host.role}={host.name}:{identity_port}")]
    argv = _probe_argv("--scope", "hold", "--timeout", str(IDENTITY_TIMEOUT_SECONDS), *peers)
    session = backend.spawn_probe(engine, argv, timeout=IDENTITY_TIMEOUT_SECONDS + SUMMARY_TIMEOUT_SECONDS)
    ports: Dict[str, int] = {}
    try:
        for _host in hosts:
            message = session.message(READY_TIMEOUT_SECONDS)
            if message.get("error"):
                raise IngressUnavailable(
                    str(message.get("error")), str(message.get("detail") or ""),
                )
            role = str(message.get("held") or "")
            port = message.get("local_port")
            if not role or not isinstance(port, int):
                raise IngressUnavailable(
                    "no_identity_connection",
                    f"the client reported {message!r} instead of a held connection",
                )
            ports[role] = port
    except IngressUnavailable:
        session.abandon()
        raise
    return session, ports


def _peer(backend: Backend, host: Host, identity_port: int, remote_port: int) -> str:
    """Ask one host who it sees on that connection."""
    result = backend.run(
        host.container,
        _probe_argv("--scope", "peer", "--port", str(identity_port),
                    "--remote-port", str(remote_port)),
        timeout=IDENTITY_TIMEOUT_SECONDS,
    )
    try:
        message = json.loads(result.stdout or "")
    except json.JSONDecodeError:
        raise IngressUnavailable(
            "no_identity_connection",
            f"{host.role}: the host printed {(result.stdout or result.stderr or '').strip()[:300]!r} "
            "instead of the client's address",
        ) from None
    if not isinstance(message, dict) or message.get("error") or not message.get("peer"):
        detail = message.get("detail") if isinstance(message, dict) else ""
        raise IngressUnavailable(
            str((message or {}).get("error") or "no_identity_connection"),
            f"{host.role}: {detail or 'the host did not report the client address'}",
        )
    return str(message["peer"])


def _capture(backend: Backend, host: Host, port: int, window: int,
             probe_script: str = PROBE_SCRIPT) -> Session:
    session = backend.spawn_probe(
        host.container,
        ["python3", "-u", probe_script, "--scope", "packets",
         "--port", str(port), "--window", str(window)],
        timeout=SUMMARY_TIMEOUT_SECONDS,
    )
    message = session.message(READY_TIMEOUT_SECONDS)
    if message.get("error"):
        session.abandon()
        raise IngressUnavailable(str(message.get("error")), str(message.get("detail") or ""))
    if message.get("ready") is not True:
        session.abandon()
        raise IngressUnavailable(
            "no_probe_summary",
            f"{host.role}: the capture printed {message!r} instead of its readiness line",
        )
    return session


@dataclass
class Measurement:
    """What every host said about one request, and what the request itself said."""

    port: int
    intended: str
    client: str = ""
    addresses: Dict[str, str] = field(default_factory=dict)
    captures: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    identity_error: str = ""
    identity_detail: str = ""
    capture_errors: Dict[str, str] = field(default_factory=dict)
    request: Any = None


def measure(
    request: Any,
    *,
    backend: Backend,
    hosts: Sequence[Host],
    engine: str,
    port: int,
    intended: str = "",
    window: int = CAPTURE_WINDOW_SECONDS,
    identity_port: int = IDENTITY_PORT,
    probe_script: str = PROBE_SCRIPT,
    identity_engine: str = "",
) -> Measurement:
    """Run one request with every host's capture and identity report around it.

    ``request`` is called exactly once, between the captures being ready and the
    captures being stopped: a request that ran outside that window would make the
    evidence a statement about some other traffic. A capture that could not start
    does not stop the request — the case still has to say what the endpoint saw —
    and every failure is carried into the measurement rather than raised, because
    the verdict belongs to one place.

    ``identity_port``, ``probe_script`` and ``identity_engine`` exist so the ways
    the evidence can be unavailable are reachable without damaging the run: an
    address nothing listens on, a capture tool that is not there, and a client
    whose identity connection does not travel the path the request takes.
    """
    if not hosts:
        raise IngressUnavailable("no_ingress_host", "no host was named to capture on")
    roles = [host.role for host in hosts]
    measurement = Measurement(port=port, intended=intended or roles[0])

    holder: Optional[Session] = None
    sessions: Dict[str, Session] = {}
    try:
        try:
            holder, ports = _hold(backend, identity_engine or engine, hosts, identity_port)
            for host in hosts:
                measurement.addresses[host.role] = _peer(
                    backend, host, identity_port, ports[host.role],
                )
            reported = sorted(set(measurement.addresses.values()))
            if len(reported) == 1:
                measurement.client = reported[0]
            else:
                measurement.identity_error = "identity_disagreement"
                measurement.identity_detail = (
                    "the hosts report different addresses for the same client: "
                    + ", ".join(f"{role}={address}" for role, address in sorted(measurement.addresses.items()))
                )
        except IngressUnavailable as error:
            measurement.identity_error = error.code
            measurement.identity_detail = error.detail

        for host in hosts:
            try:
                sessions[host.role] = _capture(backend, host, port, window, probe_script)
            except IngressUnavailable as error:
                measurement.capture_errors[host.role] = f"{error.code}: {error.detail}"

        measurement.request = request()

        for role, session in sessions.items():
            try:
                measurement.captures[role] = session.finish()
            except IngressUnavailable as error:
                measurement.capture_errors[role] = f"{error.code}: {error.detail}"
    finally:
        for session in sessions.values():
            session.abandon()
        if holder is not None:
            try:
                holder.finish()
            except IngressUnavailable:
                holder.abandon()
    return measurement


def _summary_facts(summary: Dict[str, Any]) -> Tuple[int, Dict[str, int], str]:
    """The captured count, the per-source counts, and why the summary is unusable."""
    captured = summary.get("captured")
    sources = summary.get("sources")
    if not isinstance(captured, int) or not isinstance(sources, dict):
        return 0, {}, "the capture printed no counts"
    if summary.get("stopped_by") != "harness":
        return captured, {}, (
            "the capture ended on its own window instead of being stopped by the harness, so it "
            "may have closed before the request"
        )
    if int(summary.get("drops") or 0) > 0:
        return captured, {}, (
            f"the kernel dropped {summary.get('drops')} segment(s) before the capture read them, "
            "so the account is incomplete"
        )
    counts = {str(address): int(count) for address, count in sources.items() if int(count) > 0}
    return captured, counts, ""


def evaluate(measurement: Measurement) -> Dict[str, Any]:
    """Decide one request from the hosts' own accounts, failing closed.

    PASS needs all four facts the live requirement names: a capture on the
    intended host, at least one segment from the address that host itself
    reported, no such segment at any other host, and a capture the harness
    stopped rather than one that timed out. Anything missing is INCOMPLETE with
    the foreign addresses recorded; a segment at the other host is FAIL even when
    everything else looked right, because that is traffic reaching the wrong
    place and no counter may excuse it.
    """
    # The union, because a capture that never started still owes a verdict: it is
    # the host whose account would have decided, so dropping it from the roles
    # would let the other host's empty capture answer for both.
    roles = sorted(set(measurement.captures) | set(measurement.capture_errors))
    others = [role for role in roles if role != measurement.intended]
    captured: Dict[str, int] = {}
    foreign: Dict[str, int] = {}
    reasons: List[str] = []
    matched: Dict[str, int] = {}

    for role in roles:
        if role in measurement.capture_errors:
            reasons.append(f"{role}: {measurement.capture_errors[role]}")
            captured[role] = 0
            matched[role] = 0
            continue
        count, sources, unusable = _summary_facts(measurement.captures[role])
        captured[role] = count
        matched[role] = sources.get(measurement.client, 0) if measurement.client else 0
        if unusable:
            reasons.append(f"{role}: {unusable}")
        for address, packets in sources.items():
            if address != measurement.client:
                foreign[address] = foreign.get(address, 0) + packets

    recorded_foreign = ", ".join(
        f"{address}:{packets}"
        for address, packets in sorted(foreign.items(), key=lambda item: (-item[1], item[0]))[
            :MAX_FOREIGN_RECORDED
        ]
    )
    other = others[0] if others else ""
    other_matched = max((matched.get(role, 0) for role in others), default=0)
    intended_matched = matched.get(measurement.intended, 0)
    intended_captured = captured.get(measurement.intended, 0)

    verdict = PASS
    if measurement.identity_error:
        verdict = INCOMPLETE
        reasons.insert(0, f"no target-reported client identity: {measurement.identity_detail}")
    elif reasons:
        verdict = INCOMPLETE
    elif other_matched > 0:
        verdict = FAIL
        reasons.append(
            f"the {other} host captured {other_matched} segment(s) from the client during a "
            f"request the {measurement.intended} host was supposed to carry"
        )
    elif intended_matched == 0:
        verdict = INCOMPLETE
        if intended_captured:
            reasons.append(
                f"every one of the {intended_captured} segment(s) the {measurement.intended} host "
                "captured came from an address other than the client's"
            )
        else:
            reasons.append(
                f"the {measurement.intended} host captured nothing on port {measurement.port}, so "
                "an empty capture on every host decides nothing"
            )

    return {
        "verdict": verdict,
        "reason": "; ".join(reasons),
        "client": measurement.client,
        "intended": measurement.intended,
        "other": other,
        "intended_captured": intended_captured,
        "intended_matched": intended_matched,
        "other_captured": captured.get(other, 0) if other else 0,
        "other_matched": other_matched,
        "foreign": recorded_foreign,
        "port": measurement.port,
    }


def evidence(facts: Dict[str, Any]) -> Dict[str, Any]:
    """The measurement as flat scalars, which is what the runner can record."""
    return {
        "ingress_port": facts["port"],
        "ingress_client": facts["client"],
        "ingress_intended": facts["intended"],
        "ingress_intended_captured": facts["intended_captured"],
        "ingress_intended_matched": facts["intended_matched"],
        "ingress_other": facts["other"],
        "ingress_other_captured": facts["other_captured"],
        "ingress_other_matched": facts["other_matched"],
        "ingress_foreign": facts["foreign"],
        "ingress_reason": facts["reason"],
    }


def require(case_id: str, facts: Dict[str, Any]) -> None:
    """Refuse a request whose packet evidence does not decide in the product's favour."""
    if facts["verdict"] == PASS:
        return
    from tools.podman_e2e.runner import CaseIncomplete, require as demand

    if facts["verdict"] == FAIL:
        demand(case_id, False, f"ingress: {facts['reason']}")
        return
    raise CaseIncomplete(f"{case_id}: ingress evidence is incomplete — {facts['reason']}")
