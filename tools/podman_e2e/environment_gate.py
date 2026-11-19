#!/usr/bin/env python3
"""The disposable-environment gate, decided on a host rather than on a literal.

``openspec/specs/podman-e2e/spec.md`` §Disposable
Environment Gate says a clean target passes the baseline gate with its manifest
recorded, and that a contaminated one is refused before anything is modified,
with the rejection reason carried into ``result.json``. Both sentences are
decided by the product's own functions: ``collect_remote_baseline`` reads a host
over SSH, ``check_disposable_gate`` turns that manifest into a verdict, and
``tools/test_live_vps.py::evaluate_preflight_eligibility`` reports it.

The host is a second container built from the same clean target image the
install case uses, started for one case and removed with it. It is not a VPS,
and three differences are stated rather than hidden:

* The two target-side tools the gate requires are installed by the case. That is
  what the gate's own refusal asks for — "install them before the run" — and a
  real VPS at that point has them. ``iproute2`` is installed beside ``tcpdump``
  for the same reason: without ``ss`` the port clause reads an empty listener
  table and passes because nothing could be seen, not because nothing listened.
  The clean-target image deliberately ships no product package, so this step is
  the operator's, not the image's.
* The host the run installs is not this host. "Installation proceeds" is carried
  by the run's own install case, which the clean case asserts as the outcome the
  run already recorded, and by the runner's source order: the preflight verdict
  halts the run before the first remote write.
* The image tag, the network and the resolver come from the run's own topology,
  so the container is built from the same pinned digest as the installed host.
"""
from __future__ import annotations

import contextlib
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

from tools.live_vps.preflight import (
    REQUIRED_PORTS_DEFAULT,
    check_disposable_gate,
    collect_remote_baseline,
)
from tools.live_vps.ssh import SSHClient
from tools.podman_e2e import preflight_cases, target_image
from tools.podman_e2e.podman import wait_until
from tools.podman_e2e.runner import CaseBlocked, require

CLEAN_CASE_ID = "ENV-01"
CONTAMINATED_CASE_ID = "ENV-02"

#: One case boots systemd, installs the two target tools and reads the host up to
#: four times. The deadline is a hang guard, not an expectation.
GATE_CASE_TIMEOUT_SECONDS = 900
SSH_TIMEOUT_SECONDS = 120
TOOLS_TIMEOUT_SECONDS = 600
PORT_REACHABLE_TIMEOUT_SECONDS = 30

RUNNER = Path(__file__).resolve().parent.parent / "test_live_vps.py"

#: The manifest ``collect_remote_baseline`` promises, in its own order.
MANIFEST_KEYS = (
    "os_kernel",
    "running_services",
    "tcp_listeners_raw",
    "listening_ports",
    "existing_gowave_dirs",
    "firewall_status",
    "swap_info",
    "disk_usage",
    "key_packages",
    "required_tools",
)

#: The eleven ports the gate refuses to find occupied. The product's own list is
#: the one the gate reads, so a second copy cannot drift from the sentence.
REQUIRED_PORTS = tuple(REQUIRED_PORTS_DEFAULT)

#: The packages the gate's own refusal asks the operator to install.
GATE_TOOLS = ("tcpdump", "iproute2")

#: What those packages put on ``$PATH``. ``iproute2`` is a package name, not a
#: command, so a probe over the install list reports it missing however well the
#: install went and the tool clause is never reached.
GATE_COMMANDS = ("tcpdump", "ss")

#: What the case installs, and the one sentence the gate itself asks for.
_INSTALL_TOOLS = (
    "export DEBIAN_FRONTEND=noninteractive; "
    "apt-get update -qq && "
    "apt-get install -y -qq --no-install-recommends " + " ".join(GATE_TOOLS)
)

_PROBE_UNIT = "gowave-gate-probe.service"
_PROBE_UNIT_PATH = f"/etc/systemd/system/{_PROBE_UNIT}"
_PROBE_PORT = 443
_PROBE_DIR = "/opt/gowave"
_SENTINEL = "/etc/gowave-gate-sentinel"

#: The clause each contamination step has to produce, in the gate's own words.
_DIRECTORY_CLAUSE = "Pre-existing GoWave directories detected"
_SERVICE_CLAUSE = "GoWave systemd service already active"
_PORT_CLAUSE = "Port conflicts detected; required ports already occupied"
_TOOL_CLAUSE = "Missing required target tools (install them before the run)"


class _VisionFlags:
    """The two attributes ``evaluate_preflight_eligibility`` reads from a config.

    Neither Vision domain is configured here, so the gate asked for is the
    eleven-port one. The stub is deliberate: a function that starts reading
    another field fails here, loudly, instead of being answered by a fixture that
    quietly grew the field.
    """

    master_vision_domain = ""
    worker_vision_domain = ""


class _GateHost:
    """One throwaway container, the address it was given and a root SSH client."""

    def __init__(
        self, name: str, address: str, ssh: SSHClient, podman: Any, distribution: str,
    ) -> None:
        self.name = name
        self.address = address
        self.ssh = ssh
        self.podman = podman
        self.distribution = distribution


def _host_of(product: Any, case_id: str) -> Any:
    """The run's own topology: image tag, network, resolver and secret directory."""
    for attribute in ("topology", "host"):
        host = getattr(product, attribute, None)
        if host is not None:
            return host
    raise CaseBlocked(
        f"{case_id}: this case starts a host from the run's image and network, and no "
        "topology has been created yet"
    )


def _install_outcome(product: Any) -> Any:
    """The install the run performed, whichever product owns it."""
    outcome = getattr(product, "outcome", None)
    if outcome is None and getattr(product, "master", None) is not None:
        outcome = getattr(product.master, "outcome", None)
    return outcome


@contextlib.contextmanager
def _gate_host(product: Any, case_id: str, label: str) -> Iterator[_GateHost]:
    """One clean container from the run's own image, removed with the case."""
    host = _host_of(product, case_id)
    podman = host.podman
    name = host.context.resource_name(f"gate-{label}")
    # The install's own host built this tag; a second call is a cached build, and
    # it is also what registers the tag with ``Podman.run``. The base digest is the
    # one the run locked, so this container cannot be a different distribution.
    target_image.build(podman, host.distribution)
    extra = ["--dns", str(host.plan.dns_ip)]
    for resolver in host.egress_resolvers or ():
        extra += ["--dns", str(resolver)]
    podman.run(
        name=name,
        image_alias=target_image.tag(host.distribution),
        network=host.network,
        privileged=True,
        systemd="always",
        extra_args=tuple(extra),
    )
    try:
        podman.wait_systemd(name, timeout_seconds=180)
        address = podman.address(name, host.network)
        with tempfile.TemporaryDirectory(prefix=f"gowave-gate-{label}-") as directory:
            root = Path(directory)
            key = root / "id_ed25519"
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                check=True, capture_output=True, timeout=60,
            )
            key.chmod(0o600)
            public = Path(f"{key}.pub").read_text(encoding="utf-8").strip()
            podman.exec_bash(
                name,
                "umask 077; mkdir -p /root/.ssh; chmod 0700 /root/.ssh; "
                "systemctl is-active --quiet ssh.service || "
                "{ ssh-keygen -A >/dev/null 2>&1; systemctl start ssh.service; }",
                timeout=SSH_TIMEOUT_SECONDS,
            )
            podman.exec_bash(
                name,
                "umask 077; cat >> /root/.ssh/authorized_keys; "
                "chmod 0600 /root/.ssh/authorized_keys",
                input_text=public + "\n",
                timeout=SSH_TIMEOUT_SECONDS,
            )
            # The host key is read from the host's own filesystem, which is the
            # trusted local control plane in this contour; nothing is learned from
            # an unauthenticated ``ssh-keyscan``.
            host_key = podman.exec(
                name, ["cat", "/etc/ssh/ssh_host_ed25519_key.pub"],
                timeout=SSH_TIMEOUT_SECONDS,
            ).stdout.strip()
            require(
                case_id,
                host_key.startswith("ssh-ed25519 "),
                f"{name} published no ed25519 host key ({host_key!r}), so no SSH session "
                "could be authenticated at all",
            )
            known_hosts = root / "known_hosts"
            known_hosts.write_text(f"{address} {host_key}\n", encoding="utf-8")
            known_hosts.chmod(0o600)
            ssh = SSHClient(
                host=address, port=22, user="root",
                key_path=key, known_hosts=known_hosts, multiplex=False,
            )
            try:
                yield _GateHost(
                    name=name, address=address, ssh=ssh, podman=podman,
                    distribution=host.distribution,
                )
            finally:
                ssh.close()
    finally:
        podman._run(["rm", "-f", name], check=False)


def _install_gate_tools(host: _GateHost, case_id: str) -> Dict[str, str]:
    """Install the two target-side packages and report what the host now answers."""
    host.podman.exec_bash(host.name, _INSTALL_TOOLS, timeout=TOOLS_TIMEOUT_SECONDS)
    probe = host.podman.exec(
        host.name,
        ["bash", "-c",
         "for t in " + " ".join(GATE_COMMANDS) + "; do "
         'if command -v "$t" >/dev/null 2>&1; then echo "$t=ok"; else echo "$t=missing"; fi; '
         "done"],
        timeout=SSH_TIMEOUT_SECONDS,
    )
    tools = dict(
        line.split("=", 1) for line in (probe.stdout or "").splitlines() if "=" in line
    )
    require(
        case_id,
        all(tools.get(command) == "ok" for command in GATE_COMMANDS),
        f"the case could not put {GATE_COMMANDS} on the host after installing "
        f"{GATE_TOOLS} ({tools}), so neither sentence about the gate could be decided",
    )
    return tools


def _write_sentinel(host: _GateHost) -> Dict[str, str]:
    """A file and a package count that a baseline read must not change."""
    host.podman.exec_bash(
        host.name,
        f"umask 027; printf '%s\\n' gowave-gate-sentinel > {_SENTINEL}; "
        f"chmod 0640 {_SENTINEL}",
        timeout=SSH_TIMEOUT_SECONDS,
    )
    return _read_sentinel(host)


def _read_sentinel(host: _GateHost) -> Dict[str, str]:
    digest = host.podman.exec(
        host.name, ["sha256sum", _SENTINEL], timeout=SSH_TIMEOUT_SECONDS,
    ).stdout.split()[0]
    mtime = host.podman.exec(
        host.name, ["stat", "-c", "%Y", _SENTINEL], timeout=SSH_TIMEOUT_SECONDS,
    ).stdout.strip()
    packages = host.podman.exec(
        host.name, ["bash", "-c", "dpkg-query -W -f='${binary:Package}\\n' | wc -l"],
        timeout=SSH_TIMEOUT_SECONDS,
    ).stdout.strip()
    return {"sha256": digest, "mtime": mtime, "packages": packages}


def _eligibility(manifest: Dict[str, Any]) -> Dict[str, Any]:
    """What the run reports when both hosts answer with this manifest."""
    from tools import test_live_vps

    return test_live_vps.evaluate_preflight_eligibility(
        _VisionFlags(),
        tools_ok=True,
        master_trust_ok=True,
        worker_trust_ok=True,
        dns_ok=True,
        master_root_ok=True,
        worker_root_ok=True,
        master_baseline=manifest,
        worker_baseline=manifest,
    )


def _refusals(host: _GateHost, case_id: str) -> Tuple[Dict[str, Any], List[str]]:
    """Read the host and require the gate to refuse it."""
    manifest = collect_remote_baseline(host.ssh)
    cleared, disqualifications = check_disposable_gate(manifest)
    require(
        case_id,
        not cleared,
        f"the gate accepted a host it has to refuse: {sorted(manifest)}",
    )
    return manifest, disqualifications


def case_clean_baseline_passes_gate(product: Any, context: Any) -> Dict[str, Any]:
    """``ENV-01``: a clean host passes the gate, and its manifest is what the run records."""
    with _gate_host(product, CLEAN_CASE_ID, "clean") as host:
        _install_gate_tools(host, CLEAN_CASE_ID)
        before = _write_sentinel(host)
        manifest = collect_remote_baseline(host.ssh)
        missing = [key for key in MANIFEST_KEYS if key not in manifest]
        require(
            CLEAN_CASE_ID,
            not missing,
            f"the baseline manifest has no {missing}, so the record the run keeps is not the "
            f"one the sentence names: {sorted(manifest)}",
        )
        require(
            CLEAN_CASE_ID,
            manifest["required_tools"] == {"tcpdump": "ok", "timeout": "ok"},
            f"a host the case just gave both target tools reports "
            f"{manifest['required_tools']!r}, so the gate would refuse it for the tool clause "
            "and no sentence about the other clauses could be read",
        )
        require(
            CLEAN_CASE_ID,
            manifest["existing_gowave_dirs"] == [],
            f"the container image already carries GoWave directories "
            f"({manifest['existing_gowave_dirs']}), so it is not the clean target the install "
            "case is measured on",
        )
        active = [name for name in manifest["running_services"] if "gowave" in name.lower()]
        require(
            CLEAN_CASE_ID,
            not active,
            f"a fresh container reports GoWave services {active}, so the clean baseline is "
            "not clean",
        )
        # An empty listener table would make the port clause pass because nothing
        # could be read, so the table has to name the one listener a fresh target
        # has: sshd.
        require(
            CLEAN_CASE_ID,
            manifest["listening_ports"],
            "the host reports no listening port at all: ``ss`` answered nothing, so an "
            "occupied required port would have been invisible rather than absent",
        )
        occupied = sorted(set(REQUIRED_PORTS) & set(manifest["listening_ports"]))
        require(
            CLEAN_CASE_ID,
            not occupied,
            f"a fresh container already listens on the required ports {occupied}, so the "
            "image is not the disposable target the run installs onto",
        )
        cleared, disqualifications = check_disposable_gate(manifest)
        require(
            CLEAN_CASE_ID,
            cleared and disqualifications == [],
            f"the gate refused a clean host: {disqualifications}",
        )
        cleared_vision, vision_disqualifications = check_disposable_gate(
            manifest, vision_enabled=True,
        )
        require(
            CLEAN_CASE_ID,
            cleared_vision,
            f"the gate refused a clean host once the Vision ports joined the list: "
            f"{vision_disqualifications}",
        )
        status = _eligibility(manifest)
        require(
            CLEAN_CASE_ID,
            status["status"] == "PASS",
            f"preflight reported {status['status']!r} for a clean host "
            f"(master errors {status['master_gate_errors']})",
        )
        require(
            CLEAN_CASE_ID,
            status["master_baseline"] is manifest and status["worker_baseline"] is manifest,
            "the verdict does not carry the manifest it was read from, so the run would "
            "record a status without the baseline the sentence names beside it",
        )
        outcome = _install_outcome(product)
        require(
            CLEAN_CASE_ID,
            outcome is not None and outcome.ok,
            "the run's own install case has not succeeded, so nothing shows that a run which "
            "passes this gate proceeds to an installation",
        )
        after = _read_sentinel(host)
        require(
            CLEAN_CASE_ID,
            after == before,
            f"reading the baseline changed the host: {before} before, {after} after, so the "
            "inspection is not the read-only pass the sentence describes",
        )

    return {
        "distribution": host.distribution,
        "address": host.address,
        "manifest_keys": ",".join(MANIFEST_KEYS),
        "required_tools": ",".join(
            f"{tool}={state}" for tool, state in manifest["required_tools"].items()),
        "listening_ports": ",".join(str(port) for port in manifest["listening_ports"]),
        "occupied_required_ports": ",".join(str(port) for port in occupied),
        "gate_disqualifications": len(disqualifications),
        "vision_gate_disqualifications": len(vision_disqualifications),
        "preflight_status": status["status"],
        "installation_proceeded": bool(outcome.ok),
        "baseline_read_is_read_only": after == before,
    }


def _listening_on_443(host: _GateHost) -> bool:
    listing = host.podman.exec(
        host.name, ["bash", "-c", "ss -tlnH 2>/dev/null | grep -c ':" + str(_PROBE_PORT) + " '"],
        check=False, timeout=SSH_TIMEOUT_SECONDS,
    )
    return (listing.stdout or "").strip() not in ("", "0")


def _objects_after_refusal(host: _GateHost) -> Dict[str, bool]:
    """The contaminated objects, read again: a refused run repaired nothing."""
    directory = host.podman.exec_bash(
        host.name, f"test -d {_PROBE_DIR} && echo present || echo absent", check=False,
        timeout=SSH_TIMEOUT_SECONDS,
    ).stdout.strip()
    service = host.podman.exec_bash(
        host.name, f"systemctl is-active --quiet {_PROBE_UNIT} && echo active || echo inactive",
        check=False, timeout=SSH_TIMEOUT_SECONDS,
    ).stdout.strip()
    tools = host.podman.exec_bash(
        host.name, "command -v tcpdump >/dev/null 2>&1 && echo present || echo hidden",
        check=False, timeout=SSH_TIMEOUT_SECONDS,
    ).stdout.strip()
    return {
        "directory_present": directory == "present",
        "probe_service_active": service == "active",
        "probe_port_listening": _listening_on_443(host),
        "tcpdump_hidden": tools == "hidden",
    }


def case_contaminated_host_is_refused(product: Any, context: Any) -> Dict[str, Any]:
    """``ENV-02``: each contamination is refused by name, before anything is modified."""
    with _gate_host(product, CONTAMINATED_CASE_ID, "contaminated") as host:
        _install_gate_tools(host, CONTAMINATED_CASE_ID)
        before = _write_sentinel(host)
        clean_manifest = collect_remote_baseline(host.ssh)
        clean_ok, clean_disqualifications = check_disposable_gate(clean_manifest)
        require(
            CONTAMINATED_CASE_ID,
            clean_ok and clean_disqualifications == [],
            f"the control read of an uncontaminated host was refused: {clean_disqualifications}",
        )
        require(
            CONTAMINATED_CASE_ID,
            _read_sentinel(host) == before,
            "reading the control baseline changed the host, so the refusal below could not be "
            "attributed to the contamination",
        )

        # One clause at a time, cumulatively: the refusal that arrives with the
        # second step must still name the first, because a gate that reported only
        # its newest reason would let the operator fix one thing and be refused for
        # the next without ever seeing the whole list.
        host.podman.exec_bash(
            host.name, f"mkdir -p {_PROBE_DIR}", timeout=SSH_TIMEOUT_SECONDS,
        )
        _manifest, directory_refusals = _refusals(host, CONTAMINATED_CASE_ID)
        require(
            CONTAMINATED_CASE_ID,
            len(directory_refusals) == 1
            and _DIRECTORY_CLAUSE in directory_refusals[0]
            and _PROBE_DIR in directory_refusals[0],
            f"an existing {_PROBE_DIR} was answered with {directory_refusals}, which does not "
            "name the directory clause and the directory it found",
        )

        host.podman.exec_bash(
            host.name,
            f"printf '%s\\n' '[Unit]' 'Description=gate probe' '[Service]' "
            f"'ExecStart=/bin/sleep 600' > {_PROBE_UNIT_PATH}; "
            "systemctl daemon-reload; "
            f"systemctl start {_PROBE_UNIT}",
            timeout=SSH_TIMEOUT_SECONDS,
        )
        _manifest, service_refusals = _refusals(host, CONTAMINATED_CASE_ID)
        require(
            CONTAMINATED_CASE_ID,
            len(service_refusals) == 2
            and _SERVICE_CLAUSE in service_refusals[1]
            and _PROBE_UNIT in service_refusals[1]
            and directory_refusals[0] in service_refusals,
            f"a running {_PROBE_UNIT} was answered with {service_refusals}, which does not "
            "name the service clause beside the directory it already found",
        )

        # A listener on a required port, made by the host's own sshd: the port
        # clause is about a socket, not about a process the case invented.
        host.podman.exec_bash(
            host.name,
            f"/usr/sbin/sshd -p {_PROBE_PORT} -o PidFile=/run/gowave-gate-{_PROBE_PORT}.pid",
            timeout=SSH_TIMEOUT_SECONDS,
        )
        listening = wait_until(
            lambda: _listening_on_443(host),
            PORT_REACHABLE_TIMEOUT_SECONDS,
            f"a listener on {_PROBE_PORT} inside {host.name}",
        )
        require(
            CONTAMINATED_CASE_ID,
            listening,
            f"no listener appeared on {_PROBE_PORT} within {PORT_REACHABLE_TIMEOUT_SECONDS} s, "
            "so the port clause could not be read",
        )
        _manifest, port_refusals = _refusals(host, CONTAMINATED_CASE_ID)
        require(
            CONTAMINATED_CASE_ID,
            len(port_refusals) == 3
            and _PORT_CLAUSE in port_refusals[2]
            and str(_PROBE_PORT) in port_refusals[2],
            f"a listener on {_PROBE_PORT} was answered with {port_refusals}, which does not "
            "name the port clause and the port it found occupied",
        )

        host.podman.exec_bash(
            host.name,
            'tool="$(command -v tcpdump)"; test -n "$tool"; '
            'mv "$tool" "$tool.hidden"; '
            "command -v tcpdump >/dev/null 2>&1 && echo STILL-VISIBLE || echo HIDDEN",
            timeout=SSH_TIMEOUT_SECONDS,
        )
        manifest, tool_refusals = _refusals(host, CONTAMINATED_CASE_ID)
        require(
            CONTAMINATED_CASE_ID,
            len(tool_refusals) == 4
            and _TOOL_CLAUSE in tool_refusals[3]
            and "tcpdump" in tool_refusals[3],
            f"a host without tcpdump was answered with {tool_refusals}, which does not name "
            "the tool clause and the tool it could not find",
        )
        require(
            CONTAMINATED_CASE_ID,
            manifest["required_tools"].get("tcpdump") != "ok",
            f"the manifest still reports {manifest['required_tools']!r} after tcpdump was "
            "hidden, so the clause above was not read from this host",
        )

        status = _eligibility(manifest)
        require(
            CONTAMINATED_CASE_ID,
            status["status"] == "FAIL",
            f"preflight reported {status['status']!r} for a contaminated host, so the run "
            "would have continued to a VPS it must not touch",
        )
        require(
            CONTAMINATED_CASE_ID,
            status["master_gate_errors"] == tool_refusals
            and status["worker_gate_errors"] == tool_refusals,
            f"the recorded rejection reason is {status['master_gate_errors']!r}, not the "
            f"refusal the gate produced ({tool_refusals!r})",
        )
        require(
            CONTAMINATED_CASE_ID,
            status["master_baseline"] is manifest,
            "the rejected verdict does not carry the manifest it was read from, so result.json "
            "would record a rejection reason without the host it describes",
        )

        after = _read_sentinel(host)
        require(
            CONTAMINATED_CASE_ID,
            after == before,
            f"the refused run modified the host: {before} before, {after} after",
        )
        preserved = _objects_after_refusal(host)
        require(
            CONTAMINATED_CASE_ID,
            all(preserved.values()),
            f"the refused run changed the objects it refused for: {preserved}",
        )

        # The same reader PRE-01 uses, and the same seam its damage probe patches:
        # each anchor is a call site, because a module-level import would satisfy
        # the order without a line ever running in it.
        baseline_at, gate_at, halt_at, write_at = preflight_cases._source_order(
            RUNNER,
            "m_base = collect_remote_baseline(master_ssh)",
            "m_gate_ok, m_errs = check_disposable_gate(m_base)",
            '"Preflight failed. Halting."',
            "prep_ok = prepare_master_repository(master_ssh, REPO_ROOT)",
        )
        require(
            CONTAMINATED_CASE_ID,
            baseline_at < gate_at < halt_at < write_at,
            "the runner does not read the baseline, decide the gate, halt on the verdict and "
            "only then write to the host, so a contaminated target would be modified before it "
            "was refused",
        )
        stored_at, written_at = preflight_cases._source_order(
            RUNNER,
            'state["results"]["preflight"] = {',
            "write_result_json(artifact_dir, state)",
        )
        require(
            CONTAMINATED_CASE_ID,
            stored_at < written_at,
            "the runner writes result.json before it stores the preflight verdict, so the "
            "rejection reason would not be in the document the sentence names",
        )

    return {
        "distribution": host.distribution,
        "address": host.address,
        "control_disqualifications": len(clean_disqualifications),
        "directory_refusal": directory_refusals[0],
        "service_refusal": service_refusals[1],
        "port_refusal": port_refusals[2],
        "tool_refusal": tool_refusals[3],
        "refusal_count": len(tool_refusals),
        "preflight_status": status["status"],
        "recorded_gate_errors": len(status["master_gate_errors"]),
        "contamination_preserved": all(preserved.values()),
        "baseline_read_is_read_only": after == before,
        "halts_before_first_write": baseline_at < gate_at < halt_at < write_at,
    }
