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
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import client_trust  # noqa: E402
from tools.podman_e2e import subscription_probe  # noqa: E402

XRAY_BINARY = "xray"
MIHOMO_BINARY = "mihomo"

ECHO_HTTP_PORT = 18080
ECHO_HTTPS_PORT = 18443

MIHOMO_MIXED_PORT = 7890
MIHOMO_CONTROLLER_PORT = 9090
MIHOMO_GLOBAL_GROUP = "GLOBAL"

STARTUP_SECONDS = 60
REQUEST_TIMEOUT_SECONDS = 30
SHUTDOWN_SECONDS = 10
# A prohibited destination is answered by the node's block outbound, which closes
# the connection immediately; the budget only has to cover a policy that drops
# the packets silently instead, and must not turn a denial into a hung probe.
PROHIBITED_TIMEOUT_SECONDS = 15

TRANSFER_PATH = "/traffic"

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


def process_alive(pid: int) -> bool:
    """Whether the recorded pid still runs. A zombie has already exited.

    The container's PID 1 is not a reaper, so a stopped engine stays visible to
    ``os.kill(pid, 0)`` until the container goes away; the process state is what
    tells the shutdown wait that it is over.
    """
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        with open(f"/proc/{pid}/stat", "rb") as handle:
            return handle.read().rsplit(b")", 1)[-1].split()[0] != b"Z"
    except FileNotFoundError:
        return False
    except (OSError, IndexError):
        return True


def launch_engine(argv: Sequence[str], log_path: Path, pid_path: Path, label: str) -> int:
    """Start an engine that outlives this call, and record the pid to signal.

    A supervised child handle is a wait this probe would hold without a deadline,
    so the engine is launched detached and its pid is recorded instead: every
    wait the probe then performs is bounded, readiness by ``wait_port`` and
    shutdown by ``wait_engine_exit``.
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
    if not process_alive(pid):
        raise SystemExit(f"cannot start {label}: {engine_log(log_path)}")
    return pid


def stop_engine(pid: int) -> None:
    """Last resort for a start that never became ready: nothing is left running."""
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def wait_engine_exit(pid: int, seconds: int, label: str, log_path: Path) -> None:
    """Signal the engine and wait, bounded, for its pid to disappear."""
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        raise SystemExit(f"{label} exited on its own while the transfers ran: {engine_log(log_path)}")
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not process_alive(pid):
            return
        time.sleep(0.2)
    stop_engine(pid)
    raise SystemExit(f"{label} ignored SIGTERM for {seconds}s: {engine_log(log_path)}")


class Engine:
    """One engine process, started for the transfers and stopped afterwards."""

    def __init__(self, argv: Sequence[str], log_path: Path, pid_path: Path, port: int, label: str) -> None:
        self.argv = list(argv)
        self.log_path = log_path
        self.pid_path = pid_path
        self.port = port
        self.label = label
        self.pid: Optional[int] = None

    def __enter__(self) -> "Engine":
        self.pid = launch_engine(self.argv, self.log_path, self.pid_path, self.label)
        try:
            wait_port(self.port, STARTUP_SECONDS, self.label, self.log_path)
        except SystemExit:
            stop_engine(self.pid)
            raise
        return self

    def __exit__(self, *_exc: Any) -> None:
        if self.pid is None:
            return
        try:
            wait_engine_exit(self.pid, SHUTDOWN_SECONDS, self.label, self.log_path)
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


def xray_label(config: Dict[str, Any]) -> Dict[str, str]:
    outbound = proxy_outbound(config)
    stream = outbound.get("streamSettings") or {}
    settings = stream.get("realitySettings") or stream.get("tlsSettings") or {}
    return {
        "tag": str(outbound.get("tag") or ""),
        "protocol": str(outbound.get("protocol") or ""),
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
        "network": str(proxy.get("network") or "tcp"),
        "security": (
            "reality" if "reality-opts" in proxy else ("tls" if proxy.get("tls") == "true" else "none")
        ),
        "sni": str(proxy.get("servername") or proxy.get("sni") or ""),
    }


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
        connection = http.client.HTTPConnection(host, int(port or ECHO_HTTP_PORT), timeout=timeout)
        target = TRANSFER_PATH
    else:
        connection = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=timeout)
        target = f"http://{destination}{TRANSFER_PATH}"
    try:
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
            return refusal(engine, label, request_id, status=None, reason=f"{type(exc).__name__}: {sanitize(str(exc), 200)}")
        raise SystemExit(
            f"the {engine} transfer through {label['network']} did not reach the endpoint: "
            f"{type(exc).__name__}: {sanitize(str(exc), 300)}{engine_detail(log_path)}"
        )
    finally:
        connection.close()

    try:
        recorded = json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        if expect_refusal:
            return refusal(engine, label, request_id, status=status, reason=f"HTTP {status} without an endpoint report")
        raise SystemExit(
            f"the {engine} transfer through {label['network']} returned HTTP {status} without an "
            f"endpoint report: {sanitize(raw.decode('utf-8', errors='replace'), 300)}"
            f"{engine_detail(log_path)}"
        )
    if expect_refusal:
        # A delivered payload is a fact for the case to judge, not a crash: the
        # Panel has to push the revocation and the node has to apply it, so a
        # round that still delivers is a propagation lag the scope retries.
        return {
            "engine": engine,
            **label,
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
) -> Dict[str, Any]:
    """A transfer the tunnel refused: no endpoint report came back for it."""
    return {
        "engine": engine,
        **label,
        "request_id": request_id,
        "delivered": False,
        "status": status,
        "reason": reason,
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


def mihomo_config(text: str, ca_file: str) -> str:
    """The served YAML plus the fixture trust anchor.

    Mihomo reads its extra anchor from ``tls.custom-certifactes`` (the upstream
    key is spelled that way), and that key is a list of PEM documents rather than
    of file names: Mihomo hands each entry to ``AppendCertsFromPEM``, so naming
    the mounted path would leave every TLS outbound on the system pool and fail
    verification instead of proving the transfer. The block is appended only when
    the served YAML does not declare ``tls`` itself: a second top-level ``tls``
    key would be a different document, so failing closed is the only honest
    option.
    """
    if any(line.startswith("tls:") for line in text.splitlines()):
        raise SystemExit(
            "the served Mihomo YAML already declares 'tls', so the fixture anchor cannot be added "
            "without editing what the Panel issued"
        )
    lines = [line for line in client_trust.ca_pem(ca_file).splitlines() if line.strip()]
    anchor = "\n".join(f"      {line}" for line in lines)
    return (
        text.rstrip("\n")
        + "\n"
        + f"tls:\n  {client_trust.MIHOMO_CA_KEY}:\n    - |\n{anchor}\n"
    )


def select_mihomo_proxy(name: str, timeout: int = REQUEST_TIMEOUT_SECONDS) -> None:
    """Select one proxy in Mihomo's global selector, the way a client UI does."""
    connection = http.client.HTTPConnection("127.0.0.1", MIHOMO_CONTROLLER_PORT, timeout=timeout)
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
    write_private(config, mihomo_config(text, ca_file))
    home = workdir / "traffic-mihomo-home"
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    transfers: List[Dict[str, Any]] = []
    try:
        with Engine(
            [MIHOMO_BINARY, "-f", str(config), "-d", str(home)],
            workdir / "traffic-mihomo.log",
            workdir / "traffic-mihomo.pid",
            MIHOMO_MIXED_PORT,
            "mihomo",
        ):
            wait_port(MIHOMO_CONTROLLER_PORT, STARTUP_SECONDS, "the Mihomo controller",
                      workdir / "traffic-mihomo.log")
            for proxy in proxies:
                label = mihomo_label(proxy)
                if not label["tag"]:
                    raise SystemExit("the served Mihomo YAML declares a proxy without a name")
                select_mihomo_proxy(label["tag"])
                transfers.append(transfer(
                    MIHOMO_MIXED_PORT, destination, label, "mihomo", workdir / "traffic-mihomo.log",
                    expect_refusal=expect_refusal, timeout=timeout,
                ))
    finally:
        config.unlink(missing_ok=True)
    return transfers


# ----------------------------------------------------------------------- scopes
WARMUP_PROFILES = 1
REVOCATION_ROUNDS = 6
REVOCATION_ROUND_PAUSE_SECONDS = 5
REVOCATION_TIMEOUT_SECONDS = 10


def wait_revocation_propagation(seconds: int = REVOCATION_ROUND_PAUSE_SECONDS) -> None:
    """Pause between rounds: the Panel pushes a revocation and the node applies it asynchronously."""
    time.sleep(seconds)


def warmup(payload_dir: str, ca_file: str, destination: str, workdir: Path) -> Dict[str, Any]:
    """Send one payload through the first served outbound and say whether it arrived.

    This is a readiness scope, not an acceptance one: the Panel hands a new user
    to the node and the node applies it asynchronously, so the first transfer of a
    freshly issued payload can legitimately be refused. A refusal is therefore a
    reported result the caller waits on rather than an error, and the verdict
    comes from the endpoint's own log, because a proxy that answers without
    carrying the payload must not look ready.
    """
    if not destination:
        raise SystemExit("a destination address is required: the payload needs somewhere to go")

    attempts = xray_transfers(
        payload_dir, ca_file, destination, workdir,
        expect_refusal=True, timeout=REVOCATION_TIMEOUT_SECONDS, limit=WARMUP_PROFILES,
    )
    if not attempts:
        raise SystemExit("the served Xray payload declares no outbound to warm up")
    attempt = attempts[0]
    diagnostics = echo_diagnostics(destination)
    recorded = {
        str(event.get("request_id") or "")
        for event in diagnostics.get("requests") or []
        if isinstance(event, dict)
    }
    return {
        "delivered": bool(attempt.get("delivered")) and attempt["request_id"] in recorded,
        "engine": attempt.get("engine"),
        "network": attempt.get("network"),
        "status": attempt.get("status"),
        "reason": attempt.get("reason", ""),
        "recorded": attempt["request_id"] in recorded,
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
    recorded = _recorded_request_ids(report)
    leaked = attempt["request_id"] in recorded
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
        "endpoint_records": len(recorded),
        "recorded_request_ids": 0,
    }


def _recorded_request_ids(destination: str) -> set:
    """The request ids the endpoint itself says it received."""
    diagnostics = echo_diagnostics(destination)
    return {
        str(event.get("request_id") or "")
        for event in diagnostics.get("requests") or []
        if isinstance(event, dict)
    }


def transfer_one(
    payload_dir: str,
    ca_file: str,
    destination: str,
    workdir: Path,
    engine: str,
    network: str,
    security: str,
) -> Dict[str, Any]:
    """Send one payload through exactly the matrix tuple the arguments name.

    The matrix identifies an inbound by its transport and security layer, and one
    client by its engine. A tuple that resolves to no outbound, or to more than
    one, is a matrix/representation disagreement and fails here instead of being
    papered over by running whatever happened to be first: an unexplained extra
    case and a missing one are both count drift.

    The verdict stays with the caller — this returns what the endpoint recorded.
    A connection failure still raises, because that names the engine's own log,
    which is the only place the reason a tunnel did not accept a payload exists.
    """
    if not destination:
        raise SystemExit("a destination address is required: the payload needs somewhere to go")
    if engine not in ("xray", "mihomo"):
        raise SystemExit(f"unknown matrix client {engine!r}: the probe runs the pinned engines only")

    def selected(label: Dict[str, str]) -> bool:
        return matches_tuple(label, network, security)

    if engine == "xray":
        found = xray_transfers(payload_dir, ca_file, destination, workdir, match=selected)
    else:
        found = mihomo_transfers(payload_dir, ca_file, destination, workdir, match=selected)
    if len(found) != 1:
        raise SystemExit(
            f"the served {engine} representation declares {len(found)} {network}/{security} outbound(s) "
            "for the matrix tuple, expected exactly one"
        )
    item = found[0]
    return {
        "outbounds": len(found),
        "engine": item.get("engine"),
        "tag": item.get("tag"),
        "network": item.get("network"),
        "security": item.get("security"),
        "sni": item.get("sni"),
        "status": item.get("status"),
        "delivered": bool(item.get("delivered")),
        "request_id_match": bool(item.get("request_id_match")),
        "body_match": bool(item.get("body_match")),
        "source_ip": item.get("source_ip") or "",
        "reason": item.get("reason", ""),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Send payloads through the Panel-issued outbounds")
    parser.add_argument("--scope", required=True,
                        choices=("traffic", "revoked", "warmup", "prohibited", "transfer"))
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
            args.engine, args.network, args.security,
        )
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
