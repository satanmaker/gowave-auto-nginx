#!/usr/bin/env python3
"""The run's own refusals before it may touch a VPS.

``openspec/specs/live-vps-e2e/spec.md`` §Preflight SSH Trust and DNS
Verification and §Target Address, Domain, and SSH Identity Safety describe what
a run must refuse and in which order. This module decides both with the
product's own functions: ``load_config`` reads a real mode-0600 configuration,
``check_ssh_trust`` reads a real ``known_hosts``, ``verify_all_domains`` asks
real resolvers with ``dig``, ``verify_master_firewall`` decides a firewall
record, and ``evaluate_preflight_eligibility`` turns those answers into the
status the run reports.

What is real here is the whole of every clause: the configuration is bytes on
disk that the product parses, the resolver is ``tests/fixtures/dns_server.py``
answering a zone this case writes, and the question is the one ``dig`` puts on
the wire. What is not real is a VPS: the two hosts are addressed in the block
the harness already uses for addresses that ``ipaddress`` calls global, and
nothing here opens a connection to them. The firewall clause therefore supplies
the host's own command output rather than reading it, and says so in the case's
docstring; the decision it feeds is the product's.

Two fixture resolvers answer on loopback, because preflight refuses fewer than
two independent resolvers and a single server cannot be two. They are separate
processes with separate zone files, so one may publish an answer the other does
not — which is exactly the conflicting-answer clause the spec names.

The suite runs as root, and a fixture binds :53 on ``127.0.0.1`` and
``127.0.0.2``; a host already serving those addresses makes the case report the
bind failure instead of a verdict about the product.
"""
from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List

from tools.live_vps import dns as live_dns
from tools.live_vps import firewall as live_firewall
from tools.live_vps.config import load_config, validate_public_ip
from tools.live_vps.preflight import check_ssh_trust
from tools.podman_e2e import topology
from tools.podman_e2e.runner import RunContext

REPO = Path(__file__).resolve().parents[2]
TOOLS = REPO / "tools"
RUNNER = TOOLS / "test_live_vps.py"
OPERATOR = TOOLS / "live_vps" / "operator.py"
DNS_FIXTURE = REPO / "tests" / "fixtures" / "dns_server.py"

SSH_TRUST_CASE_ID = "PRE-01"
DNS_MISMATCH_CASE_ID = "PRE-02"
AAAA_WITHOUT_IPV6_CASE_ID = "PRE-03"
PRIVATE_ADDRESS_CASE_ID = "PRE-04"
AAAA_WITH_IPV6_CASE_ID = "PRE-05"
AAAA_BYPASS_CASE_ID = "PRE-06"
DISTINCT_TARGETS_CASE_ID = "ADDR-01"
DISTINCT_DOMAINS_CASE_ID = "ADDR-02"
ROOT_IDENTITY_CASE_ID = "ADDR-03"

#: The harness spells one block of addresses that ``ipaddress`` calls global and
#: that no provider owns, so a configuration can pass preflight without naming a
#: real host. The case never binds or contacts either address.
_ADDRESS_BLOCK = topology.DATA_PREFIX_CANDIDATES[0].rsplit(".", 1)[0]
MASTER_ADDRESS = f"{_ADDRESS_BLOCK}.{topology.TARGET_OFFSET}"
WORKER_ADDRESS = f"{_ADDRESS_BLOCK}.{topology.WORKER_OFFSET}"
#: The configuration refuses an IPv6 target that is not globally routable, and
#: the harness names no public IPv6 block. This literal is compared with the
#: answer a fixture publishes and is never contacted; it is the Cloudflare
#: resolver address, chosen because it is global and therefore parses the way a
#: real VPS's address does.
MASTER_IPV6 = "2606:4700:4700::1111"
WORKER_IPV6 = "2606:4700:4700::1001"

RESOLVER_A = "127.0.0.1"
RESOLVER_B = "127.0.0.2"
DNS_PORT = 53
DNS_SUFFIX = "testbed.internal"
#: How long one fixture resolver may take to bind and announce itself. A host
#: that already serves :53 answers sooner than this with the bind error instead.
RESOLVER_START_TIMEOUT_SECONDS = 15

PANEL_DOMAIN = f"panel.preflight.{DNS_SUFFIX}"
REALITY_DOMAIN = f"reality.preflight.{DNS_SUFFIX}"
WORKER_DOMAIN = f"worker.preflight.{DNS_SUFFIX}"
WORKER_REALITY_DOMAIN = f"worker-reality.preflight.{DNS_SUFFIX}"
VISION_DOMAIN = f"vision.preflight.{DNS_SUFFIX}"

#: A host key line the pin check can find. ``ssh-keygen -F`` matches the host
#: pattern and does not verify the blob, so this is a real line with a real
#: prefix rather than a key the case minted.
HOST_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL9XWkzN4lOo7m2cQ0pJ1sVd8fF3tGh5yUq6bR1eS0aE "
    "preflight-case"
)
OTHER_HOST = f"{_ADDRESS_BLOCK}.250"

#: What ``check_disposable_gate`` calls a clean host: the two tools preflight
#: wants, no GoWave directory, an active firewall and none of the eleven ports.
CLEAN_BASELINE: Dict[str, Any] = {
    "os_kernel": "Linux disposable 6.8.0-45-generic #45-Ubuntu SMP",
    "running_services": ["ssh.service", "systemd-journald.service"],
    "tcp_listeners_raw": "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*",
    "listening_ports": [22],
    "existing_gowave_dirs": [],
    "firewall_status": "Status: active",
    "swap_info": "",
    "key_packages": "openssh-server=1:9.6p1-3ubuntu13",
    "required_tools": {"tcpdump": "ok", "timeout": "ok"},
}


def _values(directory: Path, **overrides: str) -> Dict[str, str]:
    """A complete configuration for two hosts, with the caller's lines applied."""
    key = directory / "id_ed25519"
    key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n", encoding="utf-8")
    key.chmod(0o600)
    known = directory / "known_hosts"
    known.write_text(f"{MASTER_ADDRESS} {HOST_KEY}\n{WORKER_ADDRESS} {HOST_KEY}\n", encoding="utf-8")
    known.chmod(0o600)
    values = {
        "MASTER_IP": MASTER_ADDRESS,
        "WORKER_IP": WORKER_ADDRESS,
        "MASTER_PANEL_DOMAIN": PANEL_DOMAIN,
        "MASTER_REALITY_DOMAIN": REALITY_DOMAIN,
        "WORKER_DOMAIN": WORKER_DOMAIN,
        "WORKER_REALITY_DOMAIN": WORKER_REALITY_DOMAIN,
        "MASTER_SSH_KEY_PATH": str(key),
        "WORKER_SSH_KEY_PATH": str(key),
        "MASTER_KNOWN_HOSTS_PATH": str(known),
        "WORKER_KNOWN_HOSTS_PATH": str(known),
        "GOWAVE_PANEL_VERSION": "latest",
        "GOWAVE_NODE_VERSION": "latest",
        "XRAY_SERVER_VERSION": "latest",
        "XRAY_CLIENT_VERSION": "latest",
        "MIHOMO_CLIENT_VERSION": "latest",
        "GOWAVE_NODE_INSTALLER_COMMIT": "0" * 40,
        "GOWAVE_NODE_INSTALLER_SHA256": "0" * 64,
    }
    values.update(overrides)
    return values


def _write(directory: Path, name: str, values: Dict[str, str]) -> Path:
    path = directory / name
    path.write_text(
        "".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8",
    )
    path.chmod(0o600)
    return path


def _refused(path: Path) -> str:
    """The message preflight refuses ``path`` with; a failure if it accepts it."""
    try:
        load_config(path)
    except (ValueError, PermissionError, FileNotFoundError) as error:
        return str(error)
    raise AssertionError(
        f"{path.name} was accepted by configuration preflight: a target identity, a domain or "
        "an SSH account the sentence refuses reached the run instead of failing it"
    )


def _config(directory: Path, name: str, **overrides: str):
    return load_config(_write(directory, name, _values(directory, **overrides)))


def _zone(records: Dict[str, Dict[str, List[str]]]) -> Dict[str, Any]:
    return {"ttl": 30, "records": records, "behavior": {"mode": "answer", "delay_ms": 0}}


def _correct(record_type: str = "A") -> Dict[str, Dict[str, List[str]]]:
    """Every mandatory name answered with the address its role carries."""
    records: Dict[str, Dict[str, List[str]]] = {
        PANEL_DOMAIN: {"A": [MASTER_ADDRESS]},
        REALITY_DOMAIN: {"A": [MASTER_ADDRESS]},
        WORKER_DOMAIN: {"A": [WORKER_ADDRESS]},
        WORKER_REALITY_DOMAIN: {"A": [WORKER_ADDRESS]},
    }
    if record_type == "AAAA":
        for name, address in (
            (PANEL_DOMAIN, MASTER_IPV6),
            (REALITY_DOMAIN, MASTER_IPV6),
            (WORKER_DOMAIN, WORKER_IPV6),
            (WORKER_REALITY_DOMAIN, WORKER_IPV6),
        ):
            records[name]["AAAA"] = [address]
    return records


def _publish(path: Path, zone: Dict[str, Any]) -> None:
    """Rewrite the zone and move its mtime forward so the fixture reloads it."""
    path.write_text(json.dumps(zone), encoding="utf-8")
    info = path.stat()
    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 2_000_000_000))


def wait_for_listener(process: subprocess.Popen, log: Path, timeout: float) -> None:
    """Block until the fixture says it is listening, or fail naming what it said."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        text = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
        if "listening on" in text:
            return
        if process.poll() is not None:
            raise AssertionError(
                f"the DNS fixture exited {process.returncode} before it answered, so this case "
                f"observed no resolver: {text.strip()[-800:]}"
            )
        time.sleep(0.1)
    raise AssertionError(
        f"the DNS fixture did not start within {timeout:g} s: "
        f"{log.read_text(encoding='utf-8', errors='replace')[-800:]}"
    )


def spawn_resolver(
    address: str,
    port: int,
    zone_path: Path,
    log_path: Path,
    queries_path: Path,
    timeout: float,
):
    """Start one fixture resolver and wait, within ``timeout``, until it listens.

    A resolver that cannot bind its address — a host already serving :53 — is
    killed here and reported with what it said, so a case on such a host reports
    the host's state rather than a verdict about the product.
    """
    handle = log_path.open("w", encoding="utf-8")
    process = subprocess.Popen(
        [
            sys.executable, str(DNS_FIXTURE),
            "--listen", address, "--port", str(port),
            "--zone", str(zone_path),
            "--log", str(queries_path),
            "--suffix", DNS_SUFFIX, "--out-of-zone", "nxdomain",
        ],
        stdout=handle, stderr=subprocess.STDOUT,
    )
    try:
        wait_for_listener(process, log_path, timeout)
    except BaseException:
        process.kill()
        process.wait(timeout=10)
        handle.close()
        raise
    return process, handle


@contextmanager
def _resolvers(directory: Path, *zones: Dict[str, Any]) -> Iterator[List[str]]:
    """Two independent resolvers answering ``zones`` from loopback :53.

    Preflight refuses fewer than two distinct resolvers, and one server cannot be
    two, so the pair is two processes. Each takes its own zone file, which is how
    a case publishes an answer only one of them carries.
    """
    processes: List[subprocess.Popen] = []
    handles: List[Any] = []
    try:
        for index, zone in enumerate(zones):
            zone_path = directory / f"zone-{index + 1}.json"
            zone_path.write_text(json.dumps(zone), encoding="utf-8")
            process, handle = spawn_resolver(
                f"127.0.0.{index + 1}", DNS_PORT, zone_path,
                directory / f"resolver-{index + 1}.log",
                directory / f"queries-{index + 1}.jsonl",
                RESOLVER_START_TIMEOUT_SECONDS,
            )
            processes.append(process)
            handles.append(handle)
        yield [f"127.0.0.{index + 1}" for index in range(len(zones))]
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        for handle in handles:
            handle.close()


def _eligibility(config, dns_ok: bool) -> Dict[str, Any]:
    """The status the run reports for these preflight answers."""
    from tools import test_live_vps

    return test_live_vps.evaluate_preflight_eligibility(
        config,
        tools_ok=True,
        master_trust_ok=True,
        worker_trust_ok=True,
        dns_ok=dns_ok,
        master_root_ok=True,
        worker_root_ok=True,
        master_baseline=CLEAN_BASELINE,
        worker_baseline=CLEAN_BASELINE,
    )


def _failed(checks: Dict[str, Any]) -> List[str]:
    return sorted(name for name, result in checks.items() if not result.ok)


def _source_order(path: Path, *anchors: str) -> List[int]:
    """Where each anchor first appears in ``path``; a failure if one is absent."""
    text = path.read_text(encoding="utf-8")
    positions: List[int] = []
    for anchor in anchors:
        if anchor not in text:
            raise AssertionError(f"{path.name} no longer contains {anchor!r}, so the order it states cannot be read")
        positions.append(text.index(anchor))
    return positions


class _StubSSH:
    """A host's own command output, supplied because the case runs no VPS."""

    def __init__(self, replies: Dict[str, Any]) -> None:
        self.replies = replies
        self.commands: List[str] = []

    def run(self, command: str, **_kwargs: Any) -> Any:
        self.commands.append(command)
        for prefix, reply in self.replies.items():
            if command.startswith(prefix):
                return _Reply(*reply)
        return _Reply(True, "")


class _Reply:
    def __init__(self, ok: bool, stdout: str) -> None:
        self.ok = ok
        self.stdout = stdout
        self.stderr = ""
        self.returncode = 0 if ok else 1


def case_ssh_trust(context: RunContext) -> Dict[str, Any]:
    """``PRE-01``: an unpinned host key stops the run before any remote command."""
    with tempfile.TemporaryDirectory(prefix=f"gowave-pre-{context.topology}-") as directory:
        root = Path(directory)
        # A key is pinned, but for another host: this is the VPS whose key is
        # absent from known_hosts, not a known_hosts the runner may not read.
        pinned = root / "pinned"
        pinned.write_text(f"{OTHER_HOST} {HOST_KEY}\n", encoding="utf-8")
        pinned.chmod(0o600)
        before = pinned.read_bytes()
        ok, message = check_ssh_trust(MASTER_ADDRESS, 22, pinned)
        assert ok is False, (
            "check_ssh_trust accepted a known_hosts that pins another host's key, so a run "
            "would have trusted a key nobody verified"
        )
        assert MASTER_ADDRESS in message, (
            f"the refusal {message!r} does not name the host whose key is missing"
        )
        assert str(pinned) in message, f"the refusal {message!r} does not name the file it read"
        assert "not pre-pinned" in message, (
            f"the refusal {message!r} does not say the key has to be pinned before use"
        )
        # The refusal is a read: nothing scanned the host and appended its key.
        assert pinned.read_bytes() == before, (
            "the trust check rewrote known_hosts, so the runner trusted the host it was "
            "asked to verify"
        )

        empty = root / "empty"
        empty.write_text("", encoding="utf-8")
        empty.chmod(0o600)
        empty_ok, empty_message = check_ssh_trust(MASTER_ADDRESS, 22, empty)
        assert empty_ok is False and "empty" in empty_message, (
            f"an empty known_hosts was answered with {empty_message!r}"
        )

        # The same check accepts the host's own key, so the refusal above is the
        # pin and not a check that fails whenever it is asked.
        good = root / "good"
        good.write_text(f"{MASTER_ADDRESS} {HOST_KEY}\n", encoding="utf-8")
        good.chmod(0o600)
        good_ok, good_message = check_ssh_trust(MASTER_ADDRESS, 22, good)
        assert good_ok is True and good_message is None, (
            f"a pre-pinned key was refused with {good_message!r}"
        )

        trust_at, baseline_at, run_at = _source_order(
            RUNNER, "check_ssh_trust(", "collect_remote_baseline(", "master_ssh.run(",
        )
        assert trust_at < baseline_at < run_at, (
            "the runner reads a remote baseline before it checks local host trust, so an "
            "unpinned key would have been used before it was refused"
        )

    return {
        "refusal": message,
        "host_named": MASTER_ADDRESS,
        "known_hosts_named": str(pinned),
        "known_hosts_unchanged": len(before),
        "empty_refusal": empty_message,
        "accepted_pinned_key": good_message is None,
        "trust_before_remote_read": trust_at < baseline_at,
    }


def case_dns_address_mismatch(context: RunContext) -> Dict[str, Any]:
    """``PRE-02``: a name answering another address fails preflight and is reported."""
    with tempfile.TemporaryDirectory(prefix=f"gowave-pre-{context.topology}-") as directory:
        root = Path(directory)
        wrong = f"{_ADDRESS_BLOCK}.99"
        records = _correct()
        records[PANEL_DOMAIN] = {"A": [wrong]}
        with _resolvers(root, _zone(records), _zone(records)) as resolvers:
            config = _config(root, "mismatch.conf")
            checks = live_dns.verify_all_domains(config, resolvers)
            panel = checks["MASTER_PANEL_DOMAIN"]
            assert panel.ok is False, (
                f"{PANEL_DOMAIN} was accepted while it resolved to {panel.resolved_ips} instead "
                f"of {MASTER_ADDRESS}"
            )
            assert "DNS mismatch" in panel.error, (
                f"the failure was recorded as {panel.error!r}, which does not name the "
                "mismatch the report is read for"
            )
            for fragment in (PANEL_DOMAIN, MASTER_ADDRESS, wrong, RESOLVER_A, RESOLVER_B):
                assert fragment in panel.error, (
                    f"the recorded mismatch {panel.error!r} does not name {fragment!r}: an "
                    "operator reading the report could not tell which answer was wrong or "
                    "which resolver gave it"
                )
            failed = _failed(checks)
            assert failed == ["MASTER_PANEL_DOMAIN"], (
                f"only the panel name publishes a wrong answer, but the run failed {failed}"
            )

            failed_status = _eligibility(config, dns_ok=bool(checks) and all(r.ok for r in checks.values()))
            assert failed_status["status"] == "FAIL", (
                f"preflight reported {failed_status['status']!r} with a DNS mismatch recorded, "
                "so the run would have continued to a VPS"
            )
            passed_status = _eligibility(config, dns_ok=True)
            assert passed_status["status"] == "PASS", (
                f"preflight reported {passed_status['status']!r} with every answer correct, so "
                "the FAIL above is not attributable to DNS"
            )

        # The same name, published correctly on both resolvers, is accepted: the
        # refusal above is the wrong address and not the presence of a check.
        with _resolvers(root, _zone(_correct()), _zone(_correct())) as resolvers:
            checks = live_dns.verify_all_domains(_config(root, "correct.conf"), resolvers)
            assert checks["MASTER_PANEL_DOMAIN"].ok is True, (
                f"a correct A record was refused with {checks['MASTER_PANEL_DOMAIN'].error!r}"
            )

    return {
        "mismatch_domain": PANEL_DOMAIN,
        "mismatch_expected": MASTER_ADDRESS,
        "mismatch_published": wrong,
        "mismatch_resolvers": f"{RESOLVER_A},{RESOLVER_B}",
        "mismatch_error": panel.error,
        "failed_checks": ",".join(failed),
        "preflight_status": failed_status["status"],
        "correct_status": passed_status["status"],
    }


def case_aaaa_rejected_without_ipv6(context: RunContext) -> Dict[str, Any]:
    """``PRE-03``: a published AAAA fails preflight while IPv6 testing is off."""
    with tempfile.TemporaryDirectory(prefix=f"gowave-pre-{context.topology}-") as directory:
        root = Path(directory)
        records = _correct()
        records[PANEL_DOMAIN]["AAAA"] = [MASTER_IPV6]
        with _resolvers(root, _zone(records), _zone(records)) as resolvers:
            config = _config(root, "aaaa.conf", ENABLE_IPV6="false")
            rejected_checks = live_dns.verify_all_domains(config, resolvers)
            absent = rejected_checks["MASTER_PANEL_DOMAIN_AAAA_ABSENT"]
            assert absent.ok is False, (
                f"{PANEL_DOMAIN} publishes an AAAA and preflight accepted it while "
                "ENABLE_IPV6=false, so an untested IPv6 path would ship"
            )
            assert MASTER_IPV6 in absent.error, (
                f"the refusal {absent.error!r} does not name the published address"
            )
            rejected_failed = _failed(rejected_checks)
            assert rejected_failed == ["MASTER_PANEL_DOMAIN_AAAA_ABSENT"], (
                f"only one name publishes an AAAA, but the run failed {rejected_failed}"
            )
            rejected_status = _eligibility(config, dns_ok=all(r.ok for r in rejected_checks.values()))
            assert rejected_status["status"] == "FAIL", (
                f"preflight reported {rejected_status['status']!r} with an unexpected AAAA published"
            )

        # The same names with the AAAA gone are accepted: the FAIL above is the
        # published address and not the absence of a check.
        with _resolvers(root, _zone(_correct()), _zone(_correct())) as resolvers:
            accepted_checks = live_dns.verify_all_domains(
                _config(root, "no-aaaa.conf", ENABLE_IPV6="false"), resolvers,
            )
            assert not _failed(accepted_checks), (
                "names that publish no AAAA were refused with "
                f"{[(name, accepted_checks[name].error) for name in _failed(accepted_checks)]}"
            )

    return {
        "published_address": MASTER_IPV6,
        "refusal": absent.error,
        "failed_checks": ",".join(rejected_failed),
        "rejected_status": rejected_status["status"],
        "accepted_without_aaaa": all(r.ok for r in accepted_checks.values()),
        "accepted_domains": len(accepted_checks),
    }


def case_aaaa_verified_with_ipv6(context: RunContext) -> Dict[str, Any]:
    """``PRE-05``: with IPv6 enabled every name's AAAA must be the configured one."""
    with tempfile.TemporaryDirectory(prefix=f"gowave-pre-{context.topology}-") as directory:
        root = Path(directory)
        zone_paths = [root / "zone-1.json", root / "zone-2.json"]
        correct = _zone(_correct("AAAA"))
        with _resolvers(root, correct, correct) as resolvers:
            config = _config(
                root, "ipv6.conf",
                ENABLE_IPV6="true", MASTER_IPV6=MASTER_IPV6, WORKER_IPV6=WORKER_IPV6,
            )
            checks = live_dns.verify_all_domains(config, resolvers)
            assert not _failed(checks), (
                "every name publishes the configured AAAA, but preflight failed "
                f"{[(name, checks[name].error) for name in _failed(checks)]}"
            )
            accepted_domains = len(checks)

            # A name that publishes only its A record leaves the AAAA question
            # unanswered, which is a missing record rather than a correct one.
            missing = _correct("AAAA")
            missing[WORKER_DOMAIN] = {"A": [WORKER_ADDRESS]}
            for path in zone_paths:
                _publish(path, _zone(missing))
            missing_checks = live_dns.verify_all_domains(config, resolvers)
            absent = missing_checks["WORKER_DOMAIN_AAAA"]
            assert absent.ok is False and WORKER_DOMAIN in absent.error, (
                f"a domain with no AAAA record was answered with {absent.error!r}"
            )

            # A name that publishes another address is a wrong answer, and the
            # refusal names what was published.
            wrong_address = "2606:4700:4700::9999"
            drifted = _correct("AAAA")
            drifted[WORKER_REALITY_DOMAIN]["AAAA"] = [wrong_address]
            for path in zone_paths:
                _publish(path, _zone(drifted))
            drifted_checks = live_dns.verify_all_domains(config, resolvers)
            drifted_result = drifted_checks["WORKER_REALITY_DOMAIN_AAAA"]
            assert drifted_result.ok is False and wrong_address in drifted_result.error, (
                f"a wrong AAAA was answered with {drifted_result.error!r}"
            )
            status = _eligibility(config, dns_ok=all(r.ok for r in drifted_checks.values()))
            assert status["status"] == "FAIL", (
                f"preflight reported {status['status']!r} with a wrong AAAA published"
            )

    return {
        "accepted_domains": accepted_domains,
        "missing_refusal": absent.error,
        "wrong_address": wrong_address,
        "wrong_refusal": drifted_result.error,
        "wrong_status": status["status"],
        "configured_master_ipv6": MASTER_IPV6,
        "configured_worker_ipv6": WORKER_IPV6,
    }


def case_aaaa_cannot_bypass(context: RunContext) -> Dict[str, Any]:
    """``PRE-06``: a Vision name's AAAA cannot skip the IPv6 decision either."""
    with tempfile.TemporaryDirectory(prefix=f"gowave-pre-{context.topology}-") as directory:
        root = Path(directory)
        zone_paths = [root / "zone-1.json", root / "zone-2.json"]
        vision_aaaa = "2606:4700:4700::2222"
        records = _correct()
        records[VISION_DOMAIN] = {"A": [MASTER_ADDRESS], "AAAA": [vision_aaaa]}
        with _resolvers(root, _zone(records), _zone(records)) as resolvers:
            disabled = _config(root, "vision-disabled.conf", MASTER_VISION_DOMAIN=VISION_DOMAIN)
            checks = live_dns.verify_all_domains(disabled, resolvers)
            absent = checks["MASTER_VISION_DOMAIN_AAAA_ABSENT"]
            assert absent.ok is False, (
                f"the Vision name {VISION_DOMAIN} publishes an AAAA and preflight accepted it "
                "while ENABLE_IPV6=false"
            )
            assert vision_aaaa in absent.error, (
                f"the refusal {absent.error!r} does not name the published Vision address"
            )

            enabled = _config(
                root, "vision-enabled.conf",
                MASTER_VISION_DOMAIN=VISION_DOMAIN,
                ENABLE_IPV6="true", MASTER_IPV6=MASTER_IPV6, WORKER_IPV6=WORKER_IPV6,
            )
            # One resolver publishes the configured Vision AAAA; the other adds an
            # address the configuration never named. Both answer NOERROR, so the
            # only thing that can fail the run is the conflicting answer.
            agreeing = _correct("AAAA")
            agreeing[VISION_DOMAIN] = {"A": [MASTER_ADDRESS], "AAAA": [MASTER_IPV6]}
            conflicting = _correct("AAAA")
            conflicting[VISION_DOMAIN] = {"A": [MASTER_ADDRESS], "AAAA": [MASTER_IPV6, "2606:4700:4700::3333"]}
            _publish(zone_paths[0], _zone(agreeing))
            _publish(zone_paths[1], _zone(conflicting))
            checks = live_dns.verify_all_domains(enabled, resolvers)
            vision = checks["MASTER_VISION_DOMAIN_AAAA"]
            assert vision.ok is False, (
                f"two resolvers disagreed about {VISION_DOMAIN}'s AAAA and preflight accepted "
                "the run with the union of their answers"
            )
            assert "2606:4700:4700::3333" in vision.error, (
                f"the refusal {vision.error!r} does not name the extra address beside the "
                "configured one"
            )
            assert _failed(checks) == ["MASTER_VISION_DOMAIN_AAAA"], (
                f"only the Vision name answers differently, but the run failed {_failed(checks)}"
            )
            status = _eligibility(enabled, dns_ok=all(r.ok for r in checks.values()))
            assert status["status"] == "FAIL", (
                f"preflight reported {status['status']!r} with conflicting AAAA answers"
            )

        # With IPv6 enabled the listener and firewall checks are mandatory: a
        # firewall verification that has no IPv6 target cannot report PASS.
        host = _StubSSH({
            "python3 -c": (True, "CONNECTED\n"),
            "ss -ltnH": (True, "LISTEN 0 128 127.0.0.1:3002 0.0.0.0:*\n"),
            "ufw status numbered": (True, "3002/tcp DENY IN Anywhere\n"),
            "iptables -S INPUT": (True, ""),
        })
        without_target = live_firewall.verify_master_firewall(
            host, "192.0.2.10", enable_ipv6=True, master_ipv6=None,
        )
        assert without_target["status"] != "PASS", (
            "a firewall verification with no IPv6 target reported PASS while ENABLE_IPV6=true, "
            "so the IPv6 listener policy was never checked"
        )
        assert "MASTER_IPV6" in without_target.get("error", ""), (
            f"the refusal {without_target.get('error')!r} does not name the missing IPv6 target"
        )

    return {
        "vision_domain": VISION_DOMAIN,
        "vision_published_aaaa": vision_aaaa,
        "disabled_refusal": absent.error,
        "conflicting_address": "2606:4700:4700::3333",
        "enabled_refusal": vision.error,
        "failed_checks": ",".join(_failed(checks)),
        "enabled_status": status["status"],
        "firewall_without_ipv6_status": without_target["status"],
        "firewall_commands": len(host.commands),
    }


def case_distinct_targets(context: RunContext) -> Dict[str, Any]:
    """``ADDR-01``: one address cannot stand in for two VPS hosts."""
    with tempfile.TemporaryDirectory(prefix=f"gowave-addr-{context.topology}-") as directory:
        root = Path(directory)
        same = _refused(_write(root, "same.conf", _values(root, WORKER_IP=MASTER_ADDRESS)))
        assert "different VPS hosts" in same, (
            f"two roles on one address were refused with {same!r}, which does not say the "
            "targets have to differ"
        )
        # The ports differ, which is exactly the shape the clause says is not two
        # hosts: the runner may not read it as two independently verified VPS.
        same_with_port = _refused(_write(root, "same-port.conf", _values(
            root, WORKER_IP=MASTER_ADDRESS, WORKER_SSH_PORT="2222",
        )))
        assert "different VPS hosts" in same_with_port, (
            "two roles on one address with another SSH port were accepted, so two ports on "
            "one public address were read as two VPS"
        )
        # Distinct addresses are accepted, so the refusal is the duplicate.
        accepted = _config(root, "distinct.conf")

        config_at, client_at, lock_at = _source_order(
            RUNNER, "config = load_config(config_path)", "SSHClient(", "LocalLock(",
        )
        assert config_at < client_at, (
            "the runner builds an SSH client before it validates the target identity, so a "
            "refusal would arrive after a host had already been addressed"
        )
        assert config_at < lock_at, (
            "the runner takes the local lock before it validates the target identity, so a "
            "refusal would arrive while a lock was held"
        )
        validation_at, bootstrap_at = _source_order(
            OPERATOR, "validation_config = load_config(", "targets.append(_bootstrap_one(",
        )
        assert validation_at < bootstrap_at, (
            "the operator calls _bootstrap_one before it validates the target identity, so a "
            "host would be contacted with two roles on one address"
        )

    return {
        "duplicate_refusal": same,
        "duplicate_with_port_refusal": same_with_port,
        "accepted_worker": accepted.worker_ip,
        "validated_before_ssh_client": config_at < client_at,
        "validated_before_lock": config_at < lock_at,
        "operator_validated_before_bootstrap": validation_at < bootstrap_at,
    }


def case_distinct_domains(context: RunContext) -> Dict[str, Any]:
    """``ADDR-02``: the four mandatory names are pairwise unique."""
    with tempfile.TemporaryDirectory(prefix=f"gowave-addr-{context.topology}-") as directory:
        root = Path(directory)
        refusals = {
            "master panel equals master reality": (
                _refused(_write(root, "master.conf", _values(root, MASTER_REALITY_DOMAIN=PANEL_DOMAIN))),
                "must be different",
            ),
            "worker domain equals worker reality": (
                _refused(_write(root, "worker.conf", _values(root, WORKER_REALITY_DOMAIN=WORKER_DOMAIN))),
                "must be different",
            ),
            "master panel equals worker domain": (
                _refused(_write(root, "cross.conf", _values(root, WORKER_DOMAIN=PANEL_DOMAIN))),
                "globally distinct",
            ),
            "vision repeats a mandatory name": (
                _refused(_write(root, "vision.conf", _values(root, MASTER_VISION_DOMAIN=PANEL_DOMAIN))),
                "must differ from",
            ),
        }
        for label, (message, fragment) in refusals.items():
            assert fragment in message, (
                f"{label} was refused with {message!r}, which does not name the rule it broke"
            )
        # Case folding is what makes two spellings one name.
        folded = _refused(_write(root, "folded.conf", _values(root, WORKER_DOMAIN=PANEL_DOMAIN.upper())))
        assert "globally distinct" in folded, (
            f"a name differing only in case was refused with {folded!r}, so two spellings of "
            "one domain would have been configured as two"
        )
        accepted = _config(root, "unique.conf")
        names = sorted({
            accepted.master_panel_domain, accepted.master_reality_domain,
            accepted.worker_domain, accepted.worker_reality_domain,
        })
        config_at, client_at = _source_order(RUNNER, "config = load_config(config_path)", "SSHClient(")
        assert config_at < client_at, "the runner opens an SSH client before validating the names"

    return {
        "refusals": len(refusals),
        "master_pair_refusal": refusals["master panel equals master reality"][0],
        "cross_role_refusal": refusals["master panel equals worker domain"][0],
        "vision_refusal": refusals["vision repeats a mandatory name"][0],
        "case_folded_refusal": folded,
        "accepted_domains": ",".join(names),
        "validated_before_ssh_client": config_at < client_at,
    }


def case_root_identity(context: RunContext) -> Dict[str, Any]:
    """``ADDR-03``: a non-root SSH account is refused, with no sudo fallback."""
    with tempfile.TemporaryDirectory(prefix=f"gowave-addr-{context.topology}-") as directory:
        root = Path(directory)
        master = _refused(_write(root, "master-user.conf", _values(root, MASTER_SSH_USER="ubuntu")))
        worker = _refused(_write(root, "worker-user.conf", _values(root, WORKER_SSH_USER="admin")))
        for label, message in (("MASTER_SSH_USER", master), ("WORKER_SSH_USER", worker)):
            assert label in message, f"the refusal {message!r} does not name {label}"
            assert "root" in message and "sudo" in message, (
                f"the refusal {message!r} does not say the account must be root and that no "
                "sudo path exists"
            )
        # The default account is root, so an operator who names no account is not
        # refused; the refusal above is the value that was supplied.
        defaulted = _config(root, "default-user.conf")
        assert defaulted.master_ssh_user == "root" and defaulted.worker_ssh_user == "root", (
            "the default SSH account is not root: "
            f"{defaulted.master_ssh_user!r}/{defaulted.worker_ssh_user!r}"
        )
        config_at, lock_at = _source_order(RUNNER, "config = load_config(config_path)", "LocalLock(")
        assert config_at < lock_at, (
            "the runner takes the mutation lock before it validates the SSH identity, so a "
            "refusal would arrive while a lock was held"
        )

    return {
        "master_refusal": master,
        "worker_refusal": worker,
        "default_master_user": defaulted.master_ssh_user,
        "default_worker_user": defaulted.worker_ssh_user,
        "refused_before_lock": config_at < lock_at,
    }


#: The address classes the sentence names, each with the value that carries it.
#: The values are literals: nothing here contacts the address, and a class the
#: product stopped refusing is a line this table would no longer be able to read
#: back from a refusal.
_REFUSED_ADDRESSES = (
    ("loopback", "127.0.0.1"),
    ("rfc1918-10", "10.0.0.5"),
    ("rfc1918-172", "172.16.3.4"),
    ("rfc1918-192", "192.168.1.7"),
    ("link-local", "169.254.10.20"),
    ("multicast", "239.1.2.3"),
    ("documentation", "203.0.113.10"),
    ("unspecified", "0.0.0.0"),
    ("broadcast", "255.255.255.255"),
)

#: The same classes in the family of a key that declares it carries IPv6.
_REFUSED_IPV6 = (
    ("loopback-v6", "::1"),
    ("unique-local-v6", "fc00::1"),
    ("link-local-v6", "fe80::1"),
    ("multicast-v6", "ff02::1"),
    ("documentation-v6", "2001:db8::1"),
)


def case_private_address_rejected(context: RunContext) -> Dict[str, Any]:
    """``PRE-04``: a non-global target is refused, and the harness claims no exemption.

    The container contour addresses its two hosts in the one block this harness
    reserves for addresses ``ipaddress`` calls global, because a plan's own
    container addresses (``10.89.0.x``) are exactly what the product refuses. The
    exemption is therefore not a list of allowed private addresses inside the
    parser — it is the harness's choice of a global block, and this case proves
    that block is global so the choice fails closed if it ever is not.
    """
    refusals: Dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix=f"gowave-pre-{context.topology}-") as directory:
        root = Path(directory)
        for label, address in _REFUSED_ADDRESSES:
            message = _refused(_write(root, f"{label}.conf", _values(root, MASTER_IP=address)))
            assert "MASTER_IP" in message, f"{label} was refused with {message!r}, which names no key"
            assert address in message, (
                f"{label} was refused with {message!r}, which does not identify the address it "
                "rejected"
            )
            assert "not a public routable address" in message, (
                f"{label} was refused with {message!r}, which does not name the rule"
            )
            refusals[label] = message
        for label, address in _REFUSED_IPV6:
            message = _refused(_write(
                root, f"{label}.conf",
                _values(
                    root, MASTER_IPV6=address, WORKER_IPV6=WORKER_IPV6, ENABLE_IPV6="true",
                ),
            ))
            assert "MASTER_IPV6" in message and address in message, (
                f"{label} was refused with {message!r}, which does not name the IPv6 key and value"
            )
            refusals[label] = message

        # The control: the addresses this harness does spell are accepted, so the
        # refusals above are the class and not the configuration.
        accepted = _config(root, "global.conf")
        harness_addresses = {
            "MASTER_IP": accepted.master_ip,
            "WORKER_IP": accepted.worker_ip,
        }
        non_global = [
            name for name, address in harness_addresses.items()
            if not ipaddress.ip_address(address).is_global
        ]
        assert not non_global, (
            f"the harness addresses {harness_addresses}, and {non_global} are not global: every "
            "document it feeds the parser would be refused, or an exemption would have to exist"
        )

    # The parser carries no switch that could relax the rule: the exemption lives
    # in what the harness writes, not in the product.
    import inspect

    parameters = list(inspect.signature(validate_public_ip).parameters)
    assert parameters == ["val", "key_name", "allow_v6"], (
        f"validate_public_ip takes {parameters}, so a caller could relax the global-address rule"
    )

    config_at, bootstrap_at = _source_order(
        OPERATOR, "validation_config = load_config(", "targets.append(_bootstrap_one(",
    )
    assert config_at < bootstrap_at, (
        "the operator reaches its first bootstrap before it validates the target address, so a "
        "private address would reach a socket before it reached the refusal"
    )

    return {
        "refused_classes": len(refusals),
        "refused_class_names": ",".join(sorted(refusals)),
        "loopback_refusal": refusals["loopback"],
        "rfc1918_refusal": refusals["rfc1918-10"],
        "multicast_refusal": refusals["multicast"],
        "documentation_refusal": refusals["documentation"],
        "ipv6_refusal": refusals["unique-local-v6"],
        "harness_master_ip": harness_addresses["MASTER_IP"],
        "harness_worker_ip": harness_addresses["WORKER_IP"],
        "harness_addresses_global": True,
        "validator_parameters": ",".join(parameters),
        "validated_before_bootstrap": config_at < bootstrap_at,
    }
