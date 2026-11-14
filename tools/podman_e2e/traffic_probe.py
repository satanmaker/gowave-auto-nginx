#!/usr/bin/env python3
"""Send a unique payload through every served outbound with the pinned engines.

This probe runs inside the engine client, so every byte it sends leaves from a
machine that carries no product code, and it reports only what the controlled
endpoint recorded: a request id, a payload digest, and the source address the
endpoint observed.

Two things prove that a transfer is real, and neither is a client exit status:

* the endpoint echoes the request id and the SHA-256 of the body it received, so
  a request that never reached it cannot produce a match;
* the endpoint records the source address, so a transfer that left from the
  client itself instead of the product under test is visible as a wrong source.

The Panel issues a complete config per host, so each profile is run as served;
the only addition is the fixture trust anchor (Xray cannot read SSL_CERT_FILE,
and Mihomo takes its extra anchor from ``tls``). The proxy server names are
resolved through the container's own pinned names, which is the testbed's stand
in for public DNS; the destination is an address literal so the served DNS
policy of the templates is never edited. That literal must be global unicast:
the node blocks private and loopback destinations, and the engine's freedom
outbound silently blackholes documentation, benchmarking and reserved ranges,
so either mistake would hide the egress instead of proving it (see the
topology notes on its candidate blocks).

    python3 tools/podman_e2e/traffic_probe.py --scope traffic \
        --payload-dir /secrets --ca /fixtures/ca/issued-root.pem \
        --destination <public-address>:18080
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import shlex
import signal
import socket
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import client_trust  # noqa: E402
from tools.podman_e2e import subscription_probe  # noqa: E402

XRAY_BINARY = "xray"
MIHOMO_BINARY = "mihomo"

ECHO_HTTP_PORT = 18080
ECHO_HTTPS_PORT = 18443

MIHOMO_GLOBAL_GROUP = "GLOBAL"

STARTUP_SECONDS = 60
REQUEST_TIMEOUT_SECONDS = 30
SHUTDOWN_SECONDS = 10
# A prohibited destination is answered by the node's block outbound, which closes
# the connection immediately; the budget only has to cover a policy that drops
# the packets silently instead, and must not turn a denial into a hung probe.
PROHIBITED_TIMEOUT_SECONDS = 15

TRANSFER_PATH = "/traffic"

# A resolver that stalls once must not fail an otherwise healthy endpoint, so the
# handshake gets its own budget instead of sharing the exchange's. The live
# runner divides its traffic timeout the same way; here the per-request budget is
# what is divided.
MIN_CONNECT_BUDGET_SECONDS = 10

# Mihomo's control surfaces. Each one names an interface the engine listens on, so
# each one has to be loopback before the engine is launched.
MIHOMO_CONTROL_KEYS: Sequence[str] = (
    "bind-address",
    "external-controller",
    "external-ui",
    "internal-controller",
)
MIHOMO_LOOPBACK_HOSTS: Sequence[str] = ("127.0.0.1", "::1", "localhost")
# Listeners the served document may declare. They are re-bound to fresh ports,
# never added: a listener the Panel did not issue is not this run's to invent.
MIHOMO_REBOUND_KEYS: Sequence[str] = ("socks-port", "redir-port", "tproxy-port")

# What the launched Mihomo document contributes to a transfer, so a case reads
# what the engine was given instead of only that it carried a payload.
MIHOMO_FACT_KEYS: Sequence[str] = (
    "mihomo_mixed_port",
    "mihomo_socks_port",
    "mihomo_redir_port",
    "mihomo_tproxy_port",
    "mihomo_controller",
    "mihomo_allow_lan",
    "mihomo_bind_address",
    "mihomo_control_endpoints",
    "mihomo_proxies",
    "mihomo_rules",
    "mihomo_preserved",
)

PROXY_PROTOCOLS = ("freedom", "blackhole")


def sanitize(text: str, limit: int = 800) -> str:
    """Engine diagnostics, with client identifiers removed before they are reported."""
    return subscription_probe.sanitize(text, limit)


def engine_log(path: Path) -> str:
    """The tail of an engine log, scrubbed: the engines print the config they loaded."""
    try:
        return sanitize(path.read_text(encoding="utf-8", errors="replace"))
    except FileNotFoundError:
        return ""


def engine_detail(log_path: Optional[Path]) -> str:
    """The engine's own account of a failed transfer, appended to the verdict."""
    if log_path is None:
        return ""
    tail = engine_log(log_path)
    return f"\nengine: {tail}" if tail else ""


def write_private(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    return path


def wait_port(port: int, seconds: int, label: str, log_path: Path) -> None:
    """Bounded readiness: a listener that never appears fails the case, it is never waited out."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(1.0)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.2)
    raise SystemExit(f"{label} did not listen on 127.0.0.1:{port} within {seconds}s: {engine_log(log_path)}")


@dataclass(frozen=True)
class EngineProcess:
    """A launched engine: its pid together with the start tick that makes it ours.

    A pid is not an identity. Once a process is reaped the kernel hands its
    number out again, and a full acceptance run forks enough for an unrelated
    process to own a stopped engine's number before the shutdown wait looks at
    it: the engine then reads as alive, so the case that expects "exited on its
    own" waits out the deadline and reports nothing. Field 22 of
    ``/proc/<pid>/stat`` is fixed for the life of a process, so the pair tells a
    recycled number from the engine that was actually launched.
    """

    pid: int
    started: Optional[str]


def process_started(pid: int) -> Optional[str]:
    """Field 22 of ``/proc/<pid>/stat``: the tick the process started, or None."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as handle:
            fields = handle.read().rsplit(b")", 1)[-1].split()
    except (OSError, IndexError):
        return None
    if len(fields) <= 19:
        return None
    return fields[19].decode("ascii", "replace")


def process_alive(process: EngineProcess) -> bool:
    """Whether the engine this probe launched still runs. A zombie has exited.

    The container's PID 1 is not a reaper, so a stopped engine stays visible to
    ``os.kill(pid, 0)`` until the container goes away; the process state is what
    tells the shutdown wait that it is over. A pid whose start tick has moved on
    is a different process that inherited the number, so the engine it used to
    name has exited and must not be signalled.
    """
    try:
        os.kill(process.pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # A process this probe may not signal is not the engine it forked.
        pass
    try:
        with open(f"/proc/{process.pid}/stat", "rb") as handle:
            fields = handle.read().rsplit(b")", 1)[-1].split()
    except FileNotFoundError:
        return False
    except (OSError, IndexError):
        return True
    if not fields or fields[0] == b"Z":
        return False
    if process.started is None or len(fields) <= 19:
        return True
    return fields[19].decode("ascii", "replace") == process.started


def launch_engine(argv: Sequence[str], log_path: Path, pid_path: Path, label: str) -> EngineProcess:
    """Start an engine that outlives this call, and record the pid to signal.

    A supervised child handle is a wait this probe would hold without a deadline,
    so the engine is launched detached and its pid is recorded instead: every
    wait the probe then performs is bounded, readiness by ``wait_port`` and
    shutdown by ``wait_engine_exit``. The start tick is read here, while the
    engine is known to be the process that number names.
    """
    pid_path.unlink(missing_ok=True)
    binary = shlex.quote(str(argv[0]))
    command = " ".join(shlex.quote(str(part)) for part in argv)
    # The engine is forked, so a binary that is not there cannot fail this call by
    # itself: the shell reports success and the pid of a child that never exec'd
    # would only surface later as a readiness timeout. Check the binary first so a
    # missing engine names itself instead of hiding behind that timeout.
    script = (
        f"if ! command -v {binary} >/dev/null 2>&1; then "
        f"echo 'no executable: ' {binary} >&2; exit 127; fi; "
        f"{command} & echo $! > {shlex.quote(str(pid_path))}"
    )
    descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as log:
        try:
            completed = subprocess.run(
                ["sh", "-c", script],
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=STARTUP_SECONDS,
                check=False,
            )
        except OSError as exc:
            raise SystemExit(f"cannot run {argv[0]}: {exc}")
    if completed.returncode != 0:
        raise SystemExit(f"cannot start {label}: {engine_log(log_path)}")
    try:
        pid = int(pid_path.read_text(encoding="utf-8").strip())
    except (FileNotFoundError, ValueError):
        raise SystemExit(f"cannot start {label}: the launched process recorded no pid")
    process = EngineProcess(pid, process_started(pid))
    if not process_alive(process):
        raise SystemExit(f"cannot start {label}: {engine_log(log_path)}")
    return process


def stop_engine(process: EngineProcess) -> None:
    """Last resort for a start that never became ready: nothing is left running."""
    if not process_alive(process):
        return
    try:
        os.kill(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def wait_engine_exit(process: EngineProcess, seconds: int, label: str, log_path: Path) -> None:
    """Signal the engine and wait, bounded, for its pid to disappear."""
    if not process_alive(process):
        raise SystemExit(f"{label} exited on its own while the transfers ran: {engine_log(log_path)}")
    try:
        os.kill(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        raise SystemExit(f"{label} exited on its own while the transfers ran: {engine_log(log_path)}")
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not process_alive(process):
            return
        time.sleep(0.2)
    stop_engine(process)
    raise SystemExit(f"{label} ignored SIGTERM for {seconds}s: {engine_log(log_path)}")


class Engine:
    """One engine process, started for the transfers and stopped afterwards."""

    def __init__(self, argv: Sequence[str], log_path: Path, pid_path: Path, port: int, label: str) -> None:
        self.argv = list(argv)
        self.log_path = log_path
        self.pid_path = pid_path
        self.port = port
        self.label = label
        self.process: Optional[EngineProcess] = None

    def __enter__(self) -> "Engine":
        self.process = launch_engine(self.argv, self.log_path, self.pid_path, self.label)
        try:
            wait_port(self.port, STARTUP_SECONDS, self.label, self.log_path)
        except SystemExit:
            stop_engine(self.process)
            raise
        return self

    def __exit__(self, *_exc: Any) -> None:
        if self.process is None:
            return
        try:
            wait_engine_exit(self.process, SHUTDOWN_SECONDS, self.label, self.log_path)
        finally:
            self.pid_path.unlink(missing_ok=True)


def http_proxy_port(config: Dict[str, Any]) -> int:
    """The local HTTP proxy inbound the served profile declares.

    A SOCKS listener would need a SOCKS client, and this probe deliberately uses
    only the standard library; the served template declares both, so the HTTP one
    is used as issued rather than added.
    """
    for inbound in config.get("inbounds") or []:
        if not isinstance(inbound, dict):
            continue
        if str(inbound.get("protocol")) == "http" and inbound.get("port"):
            return int(inbound["port"])
    raise SystemExit(
        "the Panel-issued Xray profile has no HTTP inbound, so a payload cannot be sent through it "
        "without rewriting the config"
    )


def proxy_outbound(config: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(config.get("outbounds"), list):
        raise SystemExit("the Panel-issued Xray profile has no outbounds list")
    for outbound in config["outbounds"]:
        if not isinstance(outbound, dict):
            continue
        protocol = str(outbound.get("protocol") or "")
        if protocol and protocol not in PROXY_PROTOCOLS:
            return outbound
    raise SystemExit("the Panel-issued Xray profile carries no proxy outbound")


def outbound_address(outbound: Dict[str, Any]) -> str:
    """The host an Xray outbound dials, whichever shape the protocol declares it in."""
    settings = outbound.get("settings") or {}
    servers = settings.get("vnext") or settings.get("servers") or [{}]
    server = servers[0] if isinstance(servers[0], dict) else {}
    return str(server.get("address") or "")


def xray_label(config: Dict[str, Any]) -> Dict[str, str]:
    outbound = proxy_outbound(config)
    stream = outbound.get("streamSettings") or {}
    settings = stream.get("realitySettings") or stream.get("tlsSettings") or {}
    return {
        "tag": str(outbound.get("tag") or ""),
        "protocol": str(outbound.get("protocol") or ""),
        "server": outbound_address(outbound),
        "network": str(stream.get("network") or "tcp"),
        "security": str(stream.get("security") or "none"),
        "sni": str(settings.get("serverName") or ""),
    }


def mihomo_label(proxy: Dict[str, str]) -> Dict[str, str]:
    """The transport a served Mihomo proxy uses, as the YAML declares it.

    ``reality-opts`` is declared as a nested block, so the scan records the key
    with an empty value: presence, not truthiness, is what marks REALITY.
    """
    return {
        "tag": str(proxy.get("name") or ""),
        "protocol": str(proxy.get("type") or ""),
        "server": str(proxy.get("server") or ""),
        "network": str(proxy.get("network") or "tcp"),
        "security": (
            "reality" if "reality-opts" in proxy else ("tls" if proxy.get("tls") == "true" else "none")
        ),
        "sni": str(proxy.get("servername") or proxy.get("sni") or ""),
    }


def connect_budget_seconds(transfer_seconds: int = REQUEST_TIMEOUT_SECONDS) -> int:
    """The part of a request's budget the handshake may spend.

    Half the transfer budget, and never below the floor: the point of the split
    is that one slow resolver answer costs the handshake its own time instead of
    the exchange's, so an endpoint that is healthy once the name resolves still
    has room to answer.
    """
    return max(MIN_CONNECT_BUDGET_SECONDS, transfer_seconds // 2)


def dial(host: str, port: int, timeout: int = REQUEST_TIMEOUT_SECONDS) -> http.client.HTTPConnection:
    """A connection whose name resolution and TCP handshake have their own budget.

    ``http.client`` applies one timeout to every socket operation, so a request
    that passes it would give the resolver and the exchange the same allowance
    and a stall in the first would read as a dead endpoint. The handshake runs
    under ``connect_budget_seconds`` here, and only the established socket is
    left on the transfer budget.
    """
    connection = http.client.HTTPConnection(host, port, timeout=connect_budget_seconds(timeout))
    connection.connect()
    if connection.sock is not None:
        connection.sock.settimeout(timeout)
    return connection


def transfer(
    proxy_port: Optional[int],
    destination: str,
    label: Dict[str, str],
    engine: str,
    log_path: Optional[Path] = None,
    expect_refusal: bool = False,
    timeout: int = REQUEST_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """POST one unique body through a local proxy, or directly when none is given.

    A direct transfer is the control for source attribution: it leaves from the
    client itself, so an endpoint that recorded the product's address for the
    tunnelled transfers has recorded something the client could not fake.

    ``expect_refusal`` inverts the verdict: the access being revoked is only
    proven revoked when this attempt cannot make the endpoint report it, so a
    refusal is the result and a delivered payload fails the case.
    """
    token = "".join(character if character.isalnum() else "-" for character in label["tag"])[:40]
    request_id = f"{engine}-{token}-{uuid.uuid4().hex[:12]}"
    body = (
        f"gowave-podman-e2e {request_id} {uuid.uuid4().hex}\n"
        f"payload for the {engine} client through {label['network']}\n"
    ).encode("utf-8")
    digest = hashlib.sha256(body).hexdigest()
    host, _, port = destination.partition(":")
    if proxy_port is None:
        dial_host, dial_port = host, int(port or ECHO_HTTP_PORT)
        target = TRANSFER_PATH
    else:
        dial_host, dial_port = "127.0.0.1", proxy_port
        target = f"http://{destination}{TRANSFER_PATH}"
    budgets = {
        "connect_budget_seconds": connect_budget_seconds(timeout),
        "transfer_budget_seconds": timeout,
    }
    connection: Optional[http.client.HTTPConnection] = None
    try:
        # The handshake is part of what a refusal is observed on: an endpoint
        # that refuses the connection is a result here, not a crash.
        connection = dial(dial_host, dial_port, timeout)
        connection.request(
            "POST",
            target,
            body=body,
            headers={
                "X-Request-Id": request_id,
                "X-Expect-SHA256": digest,
                "Content-Type": "text/plain",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        status = response.status
        raw = response.read(65536)
    except (OSError, http.client.HTTPException) as exc:
        if expect_refusal:
            return refusal(
                engine, label, request_id, status=None,
                reason=f"{type(exc).__name__}: {sanitize(str(exc), 200)}", extra=budgets,
            )
        raise SystemExit(
            f"the {engine} transfer through {label['network']} did not reach the endpoint: "
            f"{type(exc).__name__}: {sanitize(str(exc), 300)}{engine_detail(log_path)}"
        )
    finally:
        if connection is not None:
            connection.close()

    try:
        recorded = json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        if expect_refusal:
            return refusal(
                engine, label, request_id, status=status,
                reason=f"HTTP {status} without an endpoint report", extra=budgets,
            )
        raise SystemExit(
            f"the {engine} transfer through {label['network']} returned HTTP {status} without an "
            f"endpoint report: {sanitize(raw.decode('utf-8', errors='replace'), 300)}"
            f"{engine_detail(log_path)}"
        )
    if status != 200 or recorded.get("error"):
        # The endpoint answered but refused the payload — an unaccepted source,
        # or a destination it will not serve. That is a refusal, not a delivery:
        # a caller that treated the answer as proof would count a body the
        # endpoint never logged as a transfer.
        return refusal(
            engine, label, request_id, status=status,
            reason=f"HTTP {status} {recorded.get('error') or ''}".strip(),
            source_ip=str(recorded.get("source_ip") or ""),
            extra=budgets,
        )
    if expect_refusal:
        # A delivered payload is a fact for the case to judge, not a crash: the
        # Panel has to push the revocation and the node has to apply it, so a
        # round that still delivers is a propagation lag the scope retries.
        return {
            "engine": engine,
            **label,
            **budgets,
            "request_id": request_id,
            "delivered": True,
            "status": status,
            "request_id_match": recorded.get("request_id") == request_id,
            "body_match": recorded.get("body_sha256") == digest and recorded.get("match") is True,
            "source_ip": str(recorded.get("source_ip") or ""),
        }
    return {
        "engine": engine,
        **label,
        **budgets,
        "request_id": request_id,
        "delivered": True,
        "status": status,
        "request_id_match": recorded.get("request_id") == request_id,
        "body_match": recorded.get("body_sha256") == digest and recorded.get("match") is True,
        "source_ip": str(recorded.get("source_ip") or ""),
    }


def refusal(
    engine: str,
    label: Dict[str, str],
    request_id: str,
    status: Optional[int],
    reason: str,
    source_ip: str = "",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """A transfer the tunnel refused: no endpoint report came back for it."""
    return {
        "engine": engine,
        **label,
        **(extra or {}),
        "request_id": request_id,
        "delivered": False,
        "status": status,
        "reason": reason,
        "source_ip": source_ip,
    }


def echo_diagnostics(destination: str, timeout: int = REQUEST_TIMEOUT_SECONDS) -> Dict[str, Any]:
    """Read the endpoint's own record of what it received, without going through a proxy."""
    host, _, port = destination.partition(":")
    connection = http.client.HTTPConnection(host, int(port or ECHO_HTTP_PORT), timeout=timeout)
    try:
        connection.request("GET", "/diagnostics", headers={"Connection": "close"})
        response = connection.getresponse()
        raw = response.read(1 << 20)
        status = response.status
    except (OSError, http.client.HTTPException) as exc:
        raise SystemExit(f"cannot read the endpoint diagnostics from {destination}: {exc}")
    finally:
        connection.close()
    if status != 200:
        raise SystemExit(f"the endpoint diagnostics returned HTTP {status}")
    try:
        return json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"the endpoint diagnostics are not JSON: {exc}")


def transfer_matrix(
    transfers: Sequence[Dict[str, Any]],
    diagnostics: Dict[str, Any],
    direct_source_ip: str,
) -> Dict[str, Any]:
    """Cross-check every transfer against the endpoint's own log."""
    recorded = {
        str(event.get("request_id") or ""): event
        for event in diagnostics.get("requests") or []
        if isinstance(event, dict)
    }
    missing = [item["request_id"] for item in transfers if item["request_id"] not in recorded]
    return {
        "transfers": list(transfers),
        "transfer_count": len(transfers),
        "engines": sorted({str(item["engine"]) for item in transfers}),
        "networks": sorted({str(item["network"]) for item in transfers}),
        "source_ips": sorted({item["source_ip"] for item in transfers if item["source_ip"]}),
        "direct_source_ip": direct_source_ip,
        "echo_records": len(recorded),
        "missing_request_ids": len(missing),
    }


def matches_tuple(label: Dict[str, str], network: str, security: str) -> bool:
    """Whether a served outbound is the one matrix tuple names.

    The matrix identifies an inbound by its transport and security layer, which
    is what separates the five inbounds: tcp/reality is REALITY, xhttp/tls, ws/tls
    and grpc/tls are the three TLS transports, and tcp/tls is Vision.
    """
    return str(label.get("network")) == network and str(label.get("security")) == security


def xray_transfers(
    payload_dir: str,
    ca_file: str,
    destination: str,
    workdir: Path,
    expect_refusal: bool = False,
    timeout: int = REQUEST_TIMEOUT_SECONDS,
    limit: Optional[int] = None,
    match: Optional[Callable[[Dict[str, str]], bool]] = None,
) -> List[Dict[str, Any]]:
    """Run every served Xray profile and send a payload through each.

    ``limit`` runs only the first profiles, which the readiness scope uses to
    probe one tunnel instead of the whole matrix. ``match`` selects profiles by
    their served label, so a matrix case runs exactly the tuple it names while
    every profile stays a complete config.
    """
    raw = subscription_probe.read_payload(payload_dir, "xray-json")
    shape, profiles = subscription_probe.load_profiles(raw)
    transfers: List[Dict[str, Any]] = []
    matched = 0
    for index, profile in enumerate(profiles):
        prepared, wrapped = subscription_probe.prepare_config(profile, ca_file)
        label = xray_label(prepared)
        if match is not None and not match(label):
            continue
        if limit is not None and matched >= limit:
            break
        matched += 1
        if wrapped:
            raise SystemExit(
                f"the served Xray {shape} profile {index} is not a complete config: it needed a "
                "runtime wrapper before Xray would accept it"
            )
        path = workdir / f"traffic-xray-{index}.json"
        write_private(path, json.dumps(prepared))
        try:
            with Engine(
                [XRAY_BINARY, "run", "-c", str(path)],
                workdir / f"traffic-xray-{index}.log",
                workdir / f"traffic-xray-{index}.pid",
                http_proxy_port(prepared),
                f"xray profile {index}",
            ):
                transfers.append(transfer(
                    http_proxy_port(prepared), destination, label, "xray",
                    workdir / f"traffic-xray-{index}.log",
                    expect_refusal=expect_refusal, timeout=timeout,
                ))
        finally:
            path.unlink(missing_ok=True)
    return transfers


def top_level_scalars(text: str) -> Dict[str, str]:
    """Every unindented ``key: value`` the document states, as it states it.

    Only scalars are read: a section header (``dns:`` with nothing after it) is
    a mapping this probe must not touch, and a top-level list item carries no
    colon in the position a key would. The reader is deliberately this small
    because the probe runs inside the client container, where the only YAML
    library available is the one in this repository.
    """
    values: Dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line[0].isspace() or line.lstrip().startswith("#"):
            continue
        key, separator, value = line.partition(":")
        value = value.strip()
        if not separator or not value or value.startswith(("#", "|", ">")):
            continue
        values[key.strip()] = value.strip("'\"")
    return values


def assign_top_level(text: str, values: Dict[str, str]) -> str:
    """The same document with the named top-level keys set to the given scalars.

    A key the document already carries is rewritten in place, because a second
    top-level copy is a duplicate the engine refuses to load. A key it does not
    carry is inserted ahead of the first section, after any header comment, so
    nothing below it is renamed by the insertion. Every other line — proxies,
    proxy-groups, rules, the DNS block — is copied through untouched: this is
    the Panel's document, not a template of ours.
    """
    remaining = dict(values)
    lines: List[str] = []
    for raw in text.rstrip("\n").splitlines():
        line = raw.rstrip()
        key = ""
        if line and not line[0].isspace():
            key = line.partition(":")[0].strip()
        if key and key in remaining:
            lines.append(f"{key}: {remaining.pop(key)}")
            continue
        lines.append(line)
    if remaining:
        insert_at = 0
        for index, line in enumerate(lines):
            if line and not line[0].isspace() and not line.lstrip().startswith("#"):
                insert_at = index
                break
        lines[insert_at:insert_at] = [f"{key}: {value}" for key, value in remaining.items()]
    return "\n".join(lines) + "\n"


def free_loopback_port(taken: Set[int]) -> int:
    """A port nothing is listening on, distinct from the ones already assigned."""
    for _attempt in range(64):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = int(probe.getsockname()[1])
        if port not in taken:
            return port
    raise SystemExit("no free loopback port was found for the Mihomo listeners")


def mihomo_config(text: str, ca_file: str) -> Tuple[str, Dict[str, Any]]:
    """The served YAML as this run will launch it, together with what it says.

    Two things are added to what the Panel issued. The fixture trust anchor goes
    into ``tls.custom-certifactes`` (the upstream key is spelled that way), a
    list of PEM documents rather than of file names: Mihomo hands each entry to
    ``AppendCertsFromPEM``, so naming the mounted path would leave every TLS
    outbound on the system pool and fail verification instead of proving the
    transfer. A serving document that already declares ``tls`` is refused
    rather than merged, because a second top-level key is a different document.
    And every listener is re-bound to a free loopback port, with ``allow-lan``
    off and the controller pinned to ``127.0.0.1``: the Panel's document names
    7890/7891/7892/9090, and two runs on one machine would collide on all four.
    Listener keys the document does not declare are not invented — a profile
    under test is not a place to add surfaces the Panel never issued.
    """
    if any(line.startswith("tls:") for line in text.splitlines()):
        raise SystemExit(
            "the served Mihomo YAML already declares 'tls', so the fixture anchor cannot be added "
            "without editing what the Panel issued"
        )
    served = subscription_probe.scan_mihomo(text)
    if not served["proxies"]:
        raise SystemExit("the served Mihomo YAML declares no proxy, so there is nothing to launch")
    declared = top_level_scalars(text)
    taken: Set[int] = set()
    mixed_port = free_loopback_port(taken)
    taken.add(mixed_port)
    controller_port = free_loopback_port(taken)
    taken.add(controller_port)
    assigned = {
        "mixed-port": str(mixed_port),
        "allow-lan": "false",
        "bind-address": "127.0.0.1",
        "external-controller": f"127.0.0.1:{controller_port}",
        "secret": '""',
    }
    rebounded: Dict[str, int] = {}
    for key in MIHOMO_REBOUND_KEYS:
        if key not in declared:
            continue
        port = free_loopback_port(taken)
        taken.add(port)
        assigned[key] = str(port)
        rebounded[key] = port
    lines = [line for line in client_trust.ca_pem(ca_file).splitlines() if line.strip()]
    anchor = "\n".join(f"      {line}" for line in lines)
    prepared = assign_top_level(text, assigned).rstrip("\n")
    prepared += f"\ntls:\n  {client_trust.MIHOMO_CA_KEY}:\n    - |\n{anchor}\n"
    return prepared, {
        "mixed_port": mixed_port,
        "controller_port": controller_port,
        "socks_port": rebounded.get("socks-port"),
        "redir_port": rebounded.get("redir-port"),
        "tproxy_port": rebounded.get("tproxy-port"),
        "proxies": served["proxies"],
        "groups": served["groups"],
        "rules": served["rules"],
    }


def control_endpoints(text: str) -> Dict[str, str]:
    """Every control surface the document declares, as ``key -> host[:port]``."""
    scalars = top_level_scalars(text)
    return {key: scalars[key] for key in MIHOMO_CONTROL_KEYS if key in scalars}


def endpoint_host(value: str) -> str:
    """The host part of ``host:port``, ``[v6]:port`` and a bare host."""
    value = value.strip()
    if value.startswith("["):
        return value[1:].partition("]")[0].strip()
    host, _, port = value.rpartition(":")
    if host and port.isdigit():
        return host.strip()
    return value


def read_mihomo_config(path: Path, served: Dict[str, Any]) -> Dict[str, Any]:
    """Read the launched file back and state what it actually binds and keeps.

    The claim DP-05 makes is about the document Mihomo loads, not about what the
    preparation intended, so every fact here is parsed from the bytes on disk.
    A control surface bound anywhere but loopback stops the run before the
    engine starts.
    """
    text = path.read_text(encoding="utf-8")
    scalars = top_level_scalars(text)
    endpoints = control_endpoints(text)
    off_loopback = {
        key: value for key, value in endpoints.items()
        if endpoint_host(value) not in MIHOMO_LOOPBACK_HOSTS
    }
    if off_loopback:
        raise SystemExit(
            "refusing to launch Mihomo: a control endpoint would bind outside loopback: "
            + ", ".join(f"{key}={value}" for key, value in sorted(off_loopback.items()))
        )
    prepared = subscription_probe.scan_mihomo(text)
    listeners = {
        key: int(scalars[key]) for key in ("mixed-port", *MIHOMO_REBOUND_KEYS)
        if key in scalars and scalars[key].isdigit()
    }
    if len(set(listeners.values())) != len(listeners):
        raise SystemExit(
            "the prepared Mihomo config assigns one port to two listeners: "
            + ", ".join(f"{key}={port}" for key, port in sorted(listeners.items()))
        )
    controller = endpoints.get("external-controller", "")
    return {
        "mixed_port": listeners.get("mixed-port"),
        "socks_port": listeners.get("socks-port"),
        "redir_port": listeners.get("redir-port"),
        "tproxy_port": listeners.get("tproxy-port"),
        "controller": controller,
        "controller_port": int(controller.rpartition(":")[2] or 0),
        "allow_lan": scalars.get("allow-lan"),
        "bind_address": endpoints.get("bind-address", ""),
        "control_endpoints": ",".join(
            f"{key}={value}" for key, value in sorted(endpoints.items())
        ),
        "proxies": prepared["proxies"],
        "rules": prepared["rules"],
        "preserved": (
            prepared["proxies"] == served.get("proxies")
            and prepared["rules"] == served.get("rules")
            and prepared["groups"] == served.get("groups")
            and [entry.get("name") for entry in prepared["proxy_details"]]
            == [entry.get("name") for entry in served.get("proxy_details") or []]
        ),
    }


def select_mihomo_proxy(
    name: str, controller_port: int, timeout: int = REQUEST_TIMEOUT_SECONDS,
) -> None:
    """Select one proxy in Mihomo's global selector, the way a client UI does."""
    connection = http.client.HTTPConnection("127.0.0.1", controller_port, timeout=timeout)
    body = json.dumps({"name": name})
    try:
        connection.request(
            "PUT",
            f"/proxies/{MIHOMO_GLOBAL_GROUP}",
            body=body,
            headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
        )
        response = connection.getresponse()
        response.read()
        if response.status not in (200, 204):
            raise SystemExit(
                f"Mihomo refused to select {name!r} in {MIHOMO_GLOBAL_GROUP}: HTTP {response.status}"
            )
    except (OSError, http.client.HTTPException) as exc:
        raise SystemExit(f"cannot reach the Mihomo controller: {exc}")
    finally:
        connection.close()


def mihomo_transfers(
    payload_dir: str,
    ca_file: str,
    destination: str,
    workdir: Path,
    expect_refusal: bool = False,
    timeout: int = REQUEST_TIMEOUT_SECONDS,
    match: Optional[Callable[[Dict[str, str]], bool]] = None,
) -> List[Dict[str, Any]]:
    """Load the served Mihomo YAML and send a payload through every proxy it declares.

    ``match`` selects the proxies a matrix tuple names; the YAML is still loaded
    as served, so the selection never rewrites what the Panel issued.
    """
    text = subscription_probe.read_payload(payload_dir, "mihomo")
    served = subscription_probe.scan_mihomo(text)
    proxies = served.get("proxy_details") or []
    if not proxies:
        raise SystemExit("the served Mihomo YAML declares no proxy to send a payload through")
    if match is not None:
        proxies = [proxy for proxy in proxies if match(mihomo_label(proxy))]
        if not proxies:
            return []
    config = workdir / "traffic-mihomo.yaml"
    prepared, planned = mihomo_config(text, ca_file)
    write_private(config, prepared)
    bound = read_mihomo_config(config, served)
    facts = {
        "mihomo_mixed_port": bound["mixed_port"],
        "mihomo_socks_port": bound["socks_port"],
        "mihomo_redir_port": bound["redir_port"],
        "mihomo_tproxy_port": bound["tproxy_port"],
        "mihomo_controller": bound["controller"],
        "mihomo_allow_lan": bound["allow_lan"] == "false",
        "mihomo_bind_address": bound["bind_address"],
        "mihomo_control_endpoints": bound["control_endpoints"],
        "mihomo_proxies": bound["proxies"],
        "mihomo_rules": bound["rules"],
        "mihomo_preserved": bound["preserved"],
    }
    if (bound["mixed_port"], bound["controller_port"]) != (
            planned["mixed_port"], planned["controller_port"]):
        raise SystemExit(
            f"the launched Mihomo config binds {bound['mixed_port']}/{bound['controller']} where the "
            f"preparation assigned {planned['mixed_port']}/127.0.0.1:{planned['controller_port']}"
        )
    home = workdir / "traffic-mihomo-home"
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    mixed_port = int(bound["mixed_port"] or 0)
    controller_port = int(bound["controller_port"] or 0)
    transfers: List[Dict[str, Any]] = []
    try:
        with Engine(
            [MIHOMO_BINARY, "-f", str(config), "-d", str(home)],
            workdir / "traffic-mihomo.log",
            workdir / "traffic-mihomo.pid",
            mixed_port,
            "mihomo",
        ):
            wait_port(
                controller_port, STARTUP_SECONDS, "the Mihomo controller",
                workdir / "traffic-mihomo.log",
            )
            for proxy in proxies:
                label = mihomo_label(proxy)
                if not label["tag"]:
                    raise SystemExit("the served Mihomo YAML declares a proxy without a name")
                select_mihomo_proxy(label["tag"], controller_port)
                transfers.append({
                    **transfer(
                        mixed_port, destination, label, "mihomo",
                        workdir / "traffic-mihomo.log",
                        expect_refusal=expect_refusal, timeout=timeout,
                    ),
                    **facts,
                })
    finally:
        config.unlink(missing_ok=True)
    return transfers


# ----------------------------------------------------------------------- scopes
REVOCATION_ROUNDS = 6
REVOCATION_ROUND_PAUSE_SECONDS = 5
REVOCATION_TIMEOUT_SECONDS = 10


def wait_revocation_propagation(seconds: int = REVOCATION_ROUND_PAUSE_SECONDS) -> None:
    """Pause between rounds: the Panel pushes a revocation and the node applies it asynchronously."""
    time.sleep(seconds)


def warmup(payload_dir: str, ca_file: str, destination: str, workdir: Path) -> Dict[str, Any]:
    """Send one payload through every served outbound and say whether each arrived.

    This is a readiness scope, not an acceptance one: the Panel hands a new user
    to the node and the node applies it asynchronously, so the first transfer of a
    freshly issued payload can legitimately be refused. A refusal is therefore a
    reported result the caller waits on rather than an error, and the verdict
    comes from the endpoint's own log, because a proxy that answers without
    carrying the payload must not look ready.

    Every served outbound of both engines is exercised, per transport and per
    client: the cases that follow assert the whole matrix, so one warm tunnel
    says nothing about the transport that goes through NGINX's HTTP location or
    about the other client engine.
    """
    if not destination:
        raise SystemExit("a destination address is required: the payload needs somewhere to go")

    attempts = xray_transfers(
        payload_dir, ca_file, destination, workdir,
        expect_refusal=True, timeout=REVOCATION_TIMEOUT_SECONDS,
    )
    attempts += mihomo_transfers(
        payload_dir, ca_file, destination, workdir,
        expect_refusal=True, timeout=REVOCATION_TIMEOUT_SECONDS,
    )
    if not attempts:
        raise SystemExit("the served payload declares no outbound to warm up")
    diagnostics = echo_diagnostics(destination)
    recorded = {
        str(event.get("request_id") or "")
        for event in diagnostics.get("requests") or []
        if isinstance(event, dict)
    }
    tuples = [
        {
            "engine": str(item["engine"]),
            "network": str(item.get("network") or ""),
            "security": str(item.get("security") or ""),
            "tag": str(item.get("tag") or ""),
            "status": item.get("status"),
            "recorded": item["request_id"] in recorded,
            "delivered": bool(item.get("delivered")) and item["request_id"] in recorded,
            "reason": str(item.get("reason") or ""),
        }
        for item in attempts
    ]
    pending = [
        f"{item['engine']}:{item['network']}/{item['security']}"
        for item in tuples if not item["delivered"]
    ]
    first = tuples[0]
    unsatisfied = [item for item in tuples if not item["delivered"]]
    return {
        "delivered": not pending,
        "engine": first["engine"],
        "network": first["network"],
        "status": first["status"],
        "reason": unsatisfied[0]["reason"] if unsatisfied else first["reason"],
        "recorded": first["recorded"],
        "attempt_count": len(tuples),
        "pending": pending,
        "tuples": tuples,
    }


def traffic(payload_dir: str, ca_file: str, destination: str, workdir: Path) -> Dict[str, Any]:
    """Send a unique payload through every served outbound, with both engines."""
    if not destination:
        raise SystemExit("a destination address is required: the payload needs somewhere to go")

    transfers = xray_transfers(payload_dir, ca_file, destination, workdir)
    transfers += mihomo_transfers(payload_dir, ca_file, destination, workdir)
    if not transfers:
        raise SystemExit("no outbound was exercised, so nothing about the data plane was proven")

    direct = transfer(None, destination, {"tag": "control", "network": "direct"}, "control")
    return transfer_matrix(transfers, echo_diagnostics(destination), direct["source_ip"])


def revoked(
    payload_dir: str,
    ca_file: str,
    destination: str,
    workdir: Path,
    rounds: int = REVOCATION_ROUNDS,
) -> Dict[str, Any]:
    """Prove that access which was revoked cannot make the endpoint record a payload.

    Every attempt is a fresh engine started from the subscription payload that was
    captured while the access still worked, so this is what a client that kept the
    old subscription would experience — not an existing session.

    A revocation is not instantaneous: the Panel pushes the change and the node
    applies it. Each round therefore retries, and only a round in which every
    transport refused ends the wait. The verdict rests on two independent
    observations, because a refusal message alone would also describe a broken
    network: no attempt may receive an endpoint report, and the endpoint's own log
    may not contain a single one of the attempted request ids.
    """
    if not destination:
        raise SystemExit("a destination address is required: the payload needs somewhere to go")

    attempts: List[Dict[str, Any]] = []
    delivered: List[Dict[str, Any]] = []
    completed = 0
    for round_index in range(1, rounds + 1):
        attempts = xray_transfers(
            payload_dir, ca_file, destination, workdir,
            expect_refusal=True, timeout=REVOCATION_TIMEOUT_SECONDS,
        )
        attempts += mihomo_transfers(
            payload_dir, ca_file, destination, workdir,
            expect_refusal=True, timeout=REVOCATION_TIMEOUT_SECONDS,
        )
        if not attempts:
            raise SystemExit("no outbound was exercised, so nothing about the revocation was proven")
        delivered = [item for item in attempts if item.get("delivered")]
        completed = round_index
        if not delivered:
            break
        if round_index < rounds:
            wait_revocation_propagation()

    if delivered:
        raise SystemExit(
            f"access revoked in the Panel still reached the endpoint after {completed} rounds: "
            + ", ".join(f"{item['engine']}:{item['network']}" for item in delivered)
        )

    diagnostics = echo_diagnostics(destination)
    recorded = {
        str(event.get("request_id") or "")
        for event in diagnostics.get("requests") or []
        if isinstance(event, dict)
    }
    leaked = sorted(item["request_id"] for item in attempts if item["request_id"] in recorded)
    if leaked:
        raise SystemExit(
            f"the endpoint recorded a request from revoked access: {', '.join(leaked)}"
        )
    return {
        "attempts": attempts,
        "attempt_count": len(attempts),
        "engines": sorted({str(item["engine"]) for item in attempts}),
        "networks": sorted({str(item["network"]) for item in attempts}),
        "refused": sum(1 for item in attempts if not item.get("delivered")),
        "delivered": len(delivered),
        "rounds": completed,
        "endpoint_records": len(recorded),
        "recorded_request_ids": len(leaked),
    }


def prohibited(
    payload_dir: str,
    ca_file: str,
    destination: str,
    workdir: Path,
    report_destination: str = "",
) -> Dict[str, Any]:
    """Prove the node's egress policy drops a destination the product excludes.

    The permitted control comes first, through the same served outbound and the
    same engine: without it, a refusal of the prohibited attempt would describe a
    tunnel that is merely broken. The endpoint is then asked directly, not
    through the tunnel, which request ids it recorded, so a payload that reached
    it cannot hide behind a refused connection.

    The two addresses are separate because the product blocks private and
    loopback destinations by routing rule: the prohibited one is the fixture's
    private face, and the permitted one is the same fixture on its public face.
    """
    if not destination:
        raise SystemExit("a prohibited destination is required: the policy needs somewhere to deny")
    report = report_destination or destination

    control = xray_transfers(
        payload_dir, ca_file, report, workdir, timeout=PROHIBITED_TIMEOUT_SECONDS, limit=1,
    )
    if not control:
        raise SystemExit("the served Xray payload declares no outbound to test the policy with")
    permitted = control[0]
    recorded = _recorded_request_ids(report)
    if not permitted.get("delivered") or permitted["request_id"] not in recorded:
        raise SystemExit(
            "the control transfer to the permitted destination did not reach the endpoint, so a "
            f"refusal of the prohibited one would prove nothing: {permitted.get('reason', '')}"
        )

    attempts = xray_transfers(
        payload_dir, ca_file, destination, workdir,
        expect_refusal=True, timeout=PROHIBITED_TIMEOUT_SECONDS, limit=1,
    )
    if not attempts:
        raise SystemExit("the served Xray payload declares no outbound to test the policy with")
    attempt = attempts[0]
    received = _received_request_ids(report)
    leaked = attempt["request_id"] in received
    if leaked:
        raise SystemExit(
            "the endpoint recorded a payload sent to a destination the product's policy excludes"
        )
    return {
        "engine": attempt.get("engine"),
        "network": attempt.get("network"),
        "control_delivered": True,
        "delivered": bool(attempt.get("delivered")),
        "status": attempt.get("status"),
        "reason": attempt.get("reason", ""),
        "endpoint_records": len(received),
        "recorded_request_ids": 0,
    }


def direct(
    destination: str,
    timeout: int = REQUEST_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """Try to deliver a payload straight at the endpoint, without traversing a node.

    The endpoint accepts a payload only from a node's egress identity, so this
    attempt has to be refused: a delivery here would mean a client could
    manufacture the very evidence the data-plane cases rest on. The endpoint is
    then asked what it recorded, because a refusal that still logged the body
    would be a denial only in the response.
    """
    if not destination:
        raise SystemExit("a destination address is required: the endpoint is the target")
    attempt = transfer(
        None, destination, {"tag": "direct", "network": "direct"}, "direct",
        expect_refusal=True, timeout=timeout,
    )
    diagnostics = echo_diagnostics(destination)
    recorded = {
        str(event.get("request_id") or ""): event
        for event in diagnostics.get("requests") or []
        if isinstance(event, dict)
    }
    denied = {
        str(event.get("request_id") or ""): event
        for event in diagnostics.get("denied") or []
        if isinstance(event, dict)
    }
    request_id = str(attempt.get("request_id") or "")
    accepted = (
        bool(attempt.get("delivered"))
        and attempt.get("status") == 200
        and bool(attempt.get("request_id_match"))
        and bool(attempt.get("body_match"))
    )
    return {
        "endpoint": destination,
        "accepted": accepted,
        "status": attempt.get("status"),
        "reason": attempt.get("reason", ""),
        "source_ip": str(attempt.get("source_ip") or ""),
        "recorded": request_id in recorded,
        "denied_recorded": request_id in denied,
        "denied_source_ip": str((denied.get(request_id) or {}).get("source_ip") or ""),
        "denied_sources": sorted({
            str(event.get("source_ip") or "")
            for event in denied.values()
            if event.get("source_ip")
        }),
        "payload_sources": sorted({
            str(event.get("source_ip") or "")
            for event in recorded.values()
            if event.get("source_ip")
        }),
        "allowed_sources": [str(address) for address in diagnostics.get("allowed_sources") or []],
    }


def _recorded_request_ids(destination: str) -> set:
    """The request ids the endpoint itself says it received."""
    diagnostics = echo_diagnostics(destination)
    return {
        str(event.get("request_id") or "")
        for event in diagnostics.get("requests") or []
        if isinstance(event, dict)
    }


def _received_request_ids(destination: str) -> set:
    """Every request id the endpoint saw, whether it accepted or refused the source.

    A payload the product was supposed to block that arrives at the endpoint is a
    leak even when the fixture refuses its source by policy: the fixture's own
    allowlist must never stand in for the product's routing rule.
    """
    diagnostics = echo_diagnostics(destination)
    received = set()
    for key in ("requests", "denied"):
        received.update(
            str(event.get("request_id") or "")
            for event in diagnostics.get(key) or []
            if isinstance(event, dict)
        )
    return received


def transfer_one(
    payload_dir: str,
    ca_file: str,
    destination: str,
    workdir: Path,
    engine: str,
    network: str,
    security: str,
    host: str = "",
    expect_refusal: bool = False,
) -> Dict[str, Any]:
    """Send one payload through exactly the matrix tuple the arguments name.

    The matrix identifies an inbound by its transport and security layer, and one
    client by its engine. A tuple that resolves to no outbound, or to more than
    one, is a matrix/representation disagreement and fails here instead of being
    papered over by running whatever happened to be first: an unexplained extra
    case and a missing one are both count drift.

    ``host`` narrows the tuple to one node. A cluster serves the same transport
    and security layer on both nodes, so without it a Worker tuple would match
    the Master's outbound and prove the wrong node. The verdict stays with the
    caller — this returns what the endpoint recorded.

    ``expect_refusal`` reports a refused connection as the result instead of
    exiting: a node that was taken down is a state the caller wants to observe,
    and only the caller can tell that apart from a probe that could not run.
    """
    if not destination:
        raise SystemExit("a destination address is required: the payload needs somewhere to go")
    if engine not in ("xray", "mihomo"):
        raise SystemExit(f"unknown matrix client {engine!r}: the probe runs the pinned engines only")

    def selected(label: Dict[str, str]) -> bool:
        if not matches_tuple(label, network, security):
            return False
        return not host or str(label.get("server")) == host

    if engine == "xray":
        found = xray_transfers(payload_dir, ca_file, destination, workdir, match=selected,
                               expect_refusal=expect_refusal)
    else:
        found = mihomo_transfers(payload_dir, ca_file, destination, workdir, match=selected,
                                 expect_refusal=expect_refusal)
    if len(found) != 1:
        where = f" on {host}" if host else ""
        raise SystemExit(
            f"the served {engine} representation declares {len(found)} {network}/{security} "
            f"outbound(s){where} for the matrix tuple, expected exactly one"
        )
    item = found[0]
    facts = {
        "outbounds": len(found),
        "engine": item.get("engine"),
        "tag": item.get("tag"),
        "server": item.get("server"),
        "network": item.get("network"),
        "security": item.get("security"),
        "sni": item.get("sni"),
        "status": item.get("status"),
        "delivered": bool(item.get("delivered")),
        "request_id_match": bool(item.get("request_id_match")),
        "body_match": bool(item.get("body_match")),
        "source_ip": item.get("source_ip") or "",
        "reason": item.get("reason", ""),
        "connect_budget_seconds": item.get("connect_budget_seconds"),
        "transfer_budget_seconds": item.get("transfer_budget_seconds"),
    }
    for key in MIHOMO_FACT_KEYS:
        if key in item:
            facts[key] = item[key]
    return facts


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Send payloads through the Panel-issued outbounds")
    parser.add_argument("--scope", required=True,
                        choices=("traffic", "revoked", "warmup", "prohibited", "transfer", "direct"))
    parser.add_argument("--payload-dir", default="/secrets")
    parser.add_argument("--ca", required=True)
    parser.add_argument("--destination", default="")
    parser.add_argument(
        "--report-destination", default="",
        help="Where the prohibited scope reads the endpoint's own record, when it is not "
             "reachable at the prohibited destination",
    )
    parser.add_argument(
        "--engine", default="",
        help="The matrix client of the transfer scope: xray or mihomo",
    )
    parser.add_argument("--network", default="", help="The matrix transport of the transfer scope")
    parser.add_argument("--security", default="", help="The matrix security layer of the transfer scope")
    parser.add_argument(
        "--host", default="",
        help="The node's dial name, when the topology has more than one",
    )
    parser.add_argument(
        "--expect-refusal", action="store_true",
        help="Report a refused connection as the transfer result, the way the revoked "
             "scope does, so a node that is down can be observed rather than crash the probe",
    )
    parser.add_argument("--workdir", default="")
    args = parser.parse_args(argv)

    workdir = Path(args.workdir) if args.workdir else Path("/tmp")
    if args.scope == "prohibited":
        facts = prohibited(
            args.payload_dir, args.ca, args.destination, workdir,
            report_destination=args.report_destination,
        )
    elif args.scope == "transfer":
        facts = transfer_one(
            args.payload_dir, args.ca, args.destination, workdir,
            args.engine, args.network, args.security, host=args.host,
            expect_refusal=args.expect_refusal,
        )
    elif args.scope == "direct":
        facts = direct(args.destination)
    else:
        scopes = {
            "traffic": traffic,
            "revoked": revoked,
            "warmup": warmup,
        }
        facts = scopes[args.scope](args.payload_dir, args.ca, args.destination, workdir)
    print(json.dumps(facts, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
