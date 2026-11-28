"""FW-05/FW-06/PO-FIREWALL: the Node API's ingress, per role, port and family.

FW-01 and FW-03 already prove that an *untrusted attempt is denied* on the
installed host. This module asks the narrower question that a denial cannot
answer: what the rule set says about the Node API port itself, on every role the
product installs, for the port the product uses and for a port it does not, over
both address families, and again after the reload a reboot performs.

Four facts are read, none of them inferred from another:

* The role's own **applied** rules, parsed from the host's ``iptables -S``. On an
  All-in-One or Worker host the Node API port carries a source-independent deny
  and no public allow; a Worker names exactly its Master as the one source that
  may reach it; a Panel-only host carries neither rule nor listener, because it
  has no Node at all.
* The **declared** policy the shipped ``managed.py`` renders for the same host,
  asked for the installed port *and* for a port the install never used. The
  answer may differ in the port number and in nothing else, so an operator who
  registers a Worker on a non-default port gets the protection the default port
  gets. On a Panel-only host both answers must name no node port at all.
* The **SSH ports** the helper discovers on that host, each of which stays
  reachable from every source: the Node API's isolation must not be paid for
  with the operator's own access.
* The **same applied rules after** ``systemctl restart ufw.service``, the unit a
  boot runs, with the unit still enabled. A rule set that only exists in the
  running kernel is lost at the first reboot.

The two halves cannot be merged into one claim. ``installed`` is what this
container currently enforces; ``declared`` is what the shipped renderer says for
a port this run did not install. Evidence names them apart for that reason, and
the All-in-One half reads only the port it installs: ``install_local_node``
hardwires 3002, so a non-default port there has no installed counterpart and
the case says so instead of inventing one.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from . import denial
from .runner import CaseBlocked, require

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
HELPER = REPO_ROOT / "assets" / "security" / "managed.py"

AIO_CASE_ID = "FW-05"
WORKER_CASE_ID = "FW-06"
PANEL_ONLY_CASE_ID = "PO-FIREWALL"
CASE_IDS: Dict[str, str] = {
    "aio": AIO_CASE_ID,
    "multi-node": WORKER_CASE_ID,
    "panel-only": PANEL_ONLY_CASE_ID,
}
# Three installs write a rule set: the All-in-One host, a Worker, and a
# Panel-only host. They are roles, not topologies — the Multi-Node contour reads
# an All-in-One Master and a Worker in one case.
ROLES = ("aio", "worker", "panel-only")

DEFAULT_NODE_PORT = denial.NODE_PORT
# The port the product never installs. Only the declared half can answer for it,
# which is exactly the question a Worker registered off the default asks.
NON_DEFAULT_NODE_PORT = 3302

VERDICTS = {
    "aio": "denied-to-every-source",
    "worker": "allowed-only-from-the-master",
    "panel-only": "no-rule-and-no-listener",
}

POLICY_TIMEOUT_SECONDS = 120
RELOAD_TIMEOUT_SECONDS = 120
FACTS_TIMEOUT_SECONDS = denial.WORKER_REPORT_TIMEOUT_SECONDS

# `ufw.service` is the unit a boot runs to re-apply /etc/ufw/*.rules. Restarting
# it re-reads the files the product wrote, so the second reading below is the one
# a reboot would produce; keeping the unit enabled is what makes that true.
RELOAD_SCRIPT = (
    "systemctl restart ufw.service\n"
    "systemctl is-enabled ufw.service 2>&1\n"
    "systemctl is-active ufw.service 2>&1\n"
)

KERNEL_IPV6_SCRIPT = (
    "if grep -q '[^[:space:]]' /proc/net/if_inet6 2>/dev/null"
    " && [ \"$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 0)\" != 1 ]; then\n"
    "    echo true\n"
    "else\n"
    "    echo false\n"
    "fi\n"
)

# The shipped renderer, executed inside the host under test. The product
# delivers the same file over SSH stdin to a Worker, so a payload on stdin is
# the delivery shape it already trusts; nothing is written to the target's disk.
# `inspect_ssh_ports()` therefore reads *that* host's sshd, not this machine's.
_POLICY_PROGRAM = r"""import io, json, sys
source = sys.stdin.read()
request = json.loads(sys.argv[1])
sys.argv = ["managed.py", "--firewall-policy"]
sys.stdin = io.StringIO(json.dumps(request))
exec(compile(source, "managed.py", "exec"), {"__name__": "__main__", "__file__": "managed.py"})
"""


# --------------------------------------------------------------- rule reading
def _rules(family: Optional[Dict[str, Any]], port: int, key: str) -> List[Dict[str, Any]]:
    return list(((family or {}).get(key) or {}).get(int(port)) or [])


def _sources(entries: Sequence[Dict[str, Any]]) -> List[str]:
    return sorted({str(entry.get("source") or "") for entry in entries})


def _public(entries: Sequence[Dict[str, Any]]) -> bool:
    """Whether at least one rule names no source, so the port is open to all."""
    return any(not str(entry.get("source") or "") for entry in entries)


def _source_grants(commands: Sequence[Sequence[str]], port: int) -> List[List[str]]:
    return [list(command) for command in commands
            if list(command[:2]) == ["allow", "proto"] and list(command[-1:]) == [str(port)]]


def _worker_allow(source: str, port: int) -> List[str]:
    return ["allow", "proto", "tcp", "from", source, "to", "any", "port", str(port)]


def _without_port(commands: Sequence[Sequence[str]], port: int) -> List[List[str]]:
    """The declaration with its own port number replaced by a fixed placeholder."""
    normalized: List[List[str]] = []
    for command in commands:
        tokens: List[str] = []
        for token in command:
            if token == str(port):
                tokens.append("PORT")
            elif token == f"{port}/tcp":
                tokens.append("PORT/tcp")
            else:
                tokens.append(token)
        normalized.append(tokens)
    return normalized


def ipv6_gaps(
    role: str,
    node_port: int,
    facts: Dict[str, Any],
    ssh_ports: Sequence[int],
    master_sources: Sequence[str] = (),
) -> List[str]:
    """What the v6 half must say whenever the kernel it read has an address.

    The product chooses the branch from the kernel, so a host that offers IPv6
    and is left at ``IPV6=no`` has an unfiltered second stack — not a disabled
    family. When the branch is enabled, the same port decisions are required on
    ``ip6tables`` as on ``iptables``: a v4-only rule set leaves the same port
    reachable over the other family.
    """
    ipv6 = facts.get("ipv6") or {}
    offers = bool(ipv6.get("kernel_addresses")) and not ipv6.get("kernel_disabled")
    if not offers:
        return []
    declared = str(ipv6.get("declared") or "").lower()
    if declared != "yes":
        return [
            f"the kernel holds {len(ipv6.get('kernel_addresses') or [])} IPv6 address(es) "
            f"but /etc/default/ufw says IPV6={declared or 'nothing'}, so the v6 stack has no rule set"
        ]
    gaps: List[str] = []
    if not ipv6.get("active"):
        gaps.append("IPV6=yes is declared but no ip6tables chain was written")
    allows = _rules(ipv6, node_port, "allows")
    blocks = _rules(ipv6, node_port, "blocks")
    expected = sorted({str(source) for source in master_sources})
    if role == "panel-only":
        if _sources(allows):
            gaps.append(f"a Panel-only host allows {node_port}/tcp over IPv6 for {_sources(allows)}")
        listening = sorted(
            address for address in (ipv6.get("listens") or {})
            if str(address).endswith(f":{node_port}")
        )
        if listening:
            gaps.append(f"a Panel-only host publishes {node_port} over IPv6 at {listening}")
    else:
        if _public(allows):
            gaps.append(f"{node_port}/tcp is allowed to every source over IPv6")
        if not _public(blocks):
            gaps.append(f"{node_port}/tcp has no source-independent IPv6 deny rule")
        if role == "aio" and _sources(allows):
            gaps.append(f"the All-in-One grants {node_port}/tcp over IPv6 to {_sources(allows)}")
        if role == "worker" and _sources(allows) != expected:
            gaps.append(
                f"the Worker allows {_sources(allows)} on {node_port}/tcp over IPv6, "
                f"the Master's registered address is {expected}"
            )
    for port in ssh_ports:
        if not _public(_rules(ipv6, int(port), "allows")):
            gaps.append(
                f"SSH port {port} is not reachable from every source over IPv6, "
                "although this host offers one"
            )
    return gaps


def node_api_gaps(
    role: str,
    node_port: int,
    facts: Dict[str, Any],
    ssh_ports: Sequence[int],
    master_sources: Sequence[str] = (),
) -> List[str]:
    """Every way one host's applied IPv4 rules can fail the Node API contract."""
    if role not in ROLES:
        raise ValueError(f"unknown role: {role}")
    node_port = int(node_port)
    gaps: List[str] = []
    if facts.get("error"):
        gaps.append(f"the IPv4 rule set could not be read: {facts['error']}")
    if facts.get("chain_returncode") not in (0, None):
        gaps.append(
            f"`iptables -S` exited {facts['chain_returncode']}, so nothing below was decided"
        )
    if not facts.get("active"):
        gaps.append("UFW is not active, so no rule in this set decides a packet")
    allows = _rules(facts, node_port, "allows")
    blocks = _rules(facts, node_port, "blocks")
    allow_sources = _sources(allows)
    expected = sorted({str(source) for source in master_sources})
    if role == "panel-only":
        if allow_sources:
            gaps.append(
                f"a Panel-only host has no Node, yet {node_port}/tcp is allowed for {allow_sources}"
            )
        listening = [
            address
            for address in (facts.get("listeners") or {}).get(node_port, [])
            if address
        ]
        if listening:
            gaps.append(
                f"a Panel-only host listens on {node_port} at {listening}, "
                "so something other than the Panel was installed"
            )
    else:
        if _public(allows):
            gaps.append(
                f"{node_port}/tcp is allowed to every source, which publishes the Node API"
            )
        if not any(not str(entry.get("source") or "") for entry in blocks):
            gaps.append(f"{node_port}/tcp has no source-independent deny rule")
        if role == "aio":
            if allow_sources:
                gaps.append(
                    f"the All-in-One Panel reaches its Node over loopback, yet {node_port}/tcp "
                    f"is allowed for {allow_sources}"
                )
        elif not expected:
            gaps.append(
                "the Worker case has no Master address to compare against, "
                "so a source-restricted rule cannot be judged"
            )
        elif allow_sources != expected:
            gaps.append(
                f"the Worker allows {allow_sources} on {node_port}/tcp, "
                f"the Master's registered address is {expected}"
            )
    for port in ssh_ports:
        if not _public(_rules(facts, int(port), "allows")):
            gaps.append(
                f"SSH port {port} is no longer reachable from every source, "
                "so the operator's own access was traded for the Node API's"
            )
    gaps.extend(ipv6_gaps(role, node_port, facts, ssh_ports, master_sources))
    return gaps


def declared_policy_gaps(
    role: str,
    policies: Dict[int, Dict[str, Any]],
    master_sources: Sequence[str] = (),
) -> List[str]:
    """What the shipped renderer must answer for every port it is asked about.

    Two properties are checked together: each answer states the role's own
    decision for the port it was asked about, and the answers are identical once
    their port numbers are replaced — so the protection is a property of the
    role, not of the value 3002.
    """
    if role not in ROLES:
        raise ValueError(f"unknown role: {role}")
    normalized_policies = {int(port): policy for port, policy in policies.items()}
    if not normalized_policies:
        return ["no declared policy was read"]
    expected = sorted({str(source) for source in master_sources})
    gaps: List[str] = []
    baseline: Optional[List[List[str]]] = None
    baseline_port: Optional[int] = None
    ssh_baseline: Optional[List[int]] = None
    for port in sorted(normalized_policies):
        policy = normalized_policies[port]
        if not isinstance(policy, dict) or not policy:
            gaps.append(f"the declaration for {port} is empty")
            continue
        if policy.get("role") != role:
            gaps.append(
                f"the declaration for {port} answers for role {policy.get('role')!r}, not {role!r}"
            )
        if role == "panel-only":
            if policy.get("node_port") is not None:
                gaps.append(
                    f"a Panel-only declaration names node port {policy.get('node_port')!r} "
                    "instead of none"
                )
        elif policy.get("node_port") != port:
            gaps.append(
                f"the declaration asked for {port} answers with node port "
                f"{policy.get('node_port')!r}"
            )
        commands = [list(command) for command in policy.get("commands") or []]
        ssh = sorted({int(item) for item in policy.get("ssh_ports") or []})
        if ssh_baseline is None:
            ssh_baseline = ssh
        elif ssh != ssh_baseline:
            gaps.append(
                f"the declaration for {port} discovers SSH ports {ssh} "
                f"where the earlier one discovered {ssh_baseline}"
            )
        for service_port in ssh:
            if ["allow", f"{service_port}/tcp"] not in commands:
                gaps.append(
                    f"the declaration for {port} does not keep SSH port {service_port} reachable"
                )
        if role == "panel-only":
            for other in (DEFAULT_NODE_PORT, NON_DEFAULT_NODE_PORT):
                if ["deny", f"{other}/tcp"] in commands or _source_grants(commands, other):
                    gaps.append(
                        f"a Panel-only declaration for {port} carries a Node API rule for {other}"
                    )
        else:
            deny = ["deny", f"{port}/tcp"]
            if deny not in commands:
                gaps.append(f"the declaration for {port} carries no deny for that port")
            if role == "worker":
                wanted = [_worker_allow(source, port) for source in expected]
                missing = [entry for entry in wanted if entry not in commands]
                if missing:
                    gaps.append(
                        f"the declaration for {port} does not grant the Master's address "
                        f"{expected} on that port"
                    )
                grants = _source_grants(commands, port)
                if len(grants) != len(expected):
                    gaps.append(
                        f"the declaration for {port} carries {len(grants)} source-scoped grants "
                        f"for {len(expected)} Master address(es)"
                    )
                if wanted and deny in commands and commands.index(wanted[0]) > commands.index(deny):
                    gaps.append(
                        f"the declaration for {port} places the deny before the Master's allow, "
                        "so the deny wins for the one source that may connect"
                    )
            elif _source_grants(commands, port):
                gaps.append(
                    f"an All-in-One Panel reaches its Node over loopback, yet the declaration "
                    f"for {port} grants {_source_grants(commands, port)}"
                )
        normalized = _without_port(commands, port)
        if baseline is None:
            baseline, baseline_port = normalized, port
        elif normalized != baseline:
            gaps.append(
                f"the declaration for {port} differs from the one for {baseline_port} "
                f"beyond the port number: {normalized} vs {baseline}"
            )
    return gaps


def decision_shape(facts: Dict[str, Any], ports: Sequence[int]) -> Dict[str, Any]:
    """The decisions of one reading, with counters and timestamps left out.

    A reload may legitimately reset packet counters and reassign rule handles;
    what it may not change is who is admitted, what is dropped and what is bound.
    """
    ipv6 = facts.get("ipv6") or {}
    return {
        "active": bool(facts.get("active")),
        "default_incoming": facts.get("default_incoming") or "",
        "ipv6_declared": str(ipv6.get("declared") or ""),
        "ports": {
            str(int(port)): {
                "allows": _sources(_rules(facts, port, "allows")),
                "blocked": bool(_rules(facts, port, "blocks")),
                "listen": sorted(
                    address
                    for address in (facts.get("listeners") or {}).get(int(port), [])
                    if address
                ),
                "ipv6_allows": _sources(_rules(ipv6, port, "allows")),
                "ipv6_blocked": bool(_rules(ipv6, port, "blocks")),
            }
            for port in ports
        },
    }


def reload_gaps(
    before: Dict[str, Any],
    after: Dict[str, Any],
    ports: Sequence[int],
) -> List[str]:
    """What a reload that lost the rule set would leave behind, and must not."""
    gaps: List[str] = []
    unit = after.get("unit")
    if not isinstance(unit, dict) or not unit:
        gaps.append("the reload reported no ufw.service state, so persistence was not observed")
    else:
        if str(unit.get("enabled") or "") != "enabled":
            gaps.append(
                f"ufw.service is {unit.get('enabled')!r} after the reload, "
                "so a reboot would not re-apply the rule set"
            )
        if str(unit.get("active") or "") != "active":
            gaps.append(
                f"ufw.service is {unit.get('active')!r} after the reload: "
                f"{unit.get('detail') or 'no output'}"
            )
    if not after.get("active"):
        gaps.append("UFW is not active after the reload")
    shape_before = decision_shape(before, ports)
    shape_after = decision_shape(after, ports)
    for key in ("default_incoming", "ipv6_declared"):
        if shape_after.get(key) != shape_before.get(key):
            gaps.append(
                f"after the reload {key} reads {shape_after.get(key)!r}, "
                f"the installed set read {shape_before.get(key)!r}"
            )
    for port in sorted({int(port) for port in ports}):
        left = shape_before["ports"][str(port)]
        right = shape_after["ports"][str(port)]
        for field in ("allows", "blocked", "listen", "ipv6_allows", "ipv6_blocked"):
            if left.get(field) != right.get(field):
                gaps.append(
                    f"after the reload {port}/tcp {field} reads {right.get(field)!r}, "
                    f"the installed set read {left.get(field)!r}"
                )
    return gaps


# ------------------------------------------------------------------- the driver
def case_ingress_matrix(
    case_id: str,
    role: str,
    node_port: int,
    collect: Callable[[Sequence[int]], Dict[str, Any]],
    reload: Callable[[Sequence[int]], Dict[str, Any]],
    ssh_ports: Sequence[int],
    master_sources: Sequence[str] = (),
    declared: Optional[Dict[int, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Judge one host from two readings taken around the reload a reboot performs.

    ``collect`` and ``reload`` return the same parser's facts; the driver owns the
    question, so a contour only has to say how to reach its host. Every gap is
    gathered before the first assertion, because one reading names all of the
    failures instead of the first one the code happened to check.
    """
    if role not in ROLES:
        raise ValueError(f"unknown role: {role}")
    ssh = sorted({int(port) for port in ssh_ports})
    ports = sorted({int(node_port), *ssh})
    before = collect(ports)
    require(case_id, bool(before), "the host returned no firewall facts")
    gaps = node_api_gaps(role, node_port, before, ssh, master_sources)
    if declared is not None:
        gaps.extend(declared_policy_gaps(role, declared, master_sources))
    after = reload(ports)
    gaps.extend(reload_gaps(before, after, ports))
    require(case_id, not gaps, "; ".join(gaps))
    evidence = {
        "role": role,
        "node_port": int(node_port),
        "ssh_ports": ssh,
        "master_sources": sorted({str(source) for source in master_sources}),
        "verdict": VERDICTS[role],
        "installed": decision_shape(before, ports),
        "after_reload": decision_shape(after, ports),
        "declared_ports": sorted(int(port) for port in (declared or {})),
        "unit": dict(after.get("unit") or {}),
    }
    return evidence


# ------------------------------------------------------------- host-side reads
def _json_object(output: str) -> Dict[str, Any]:
    for line in reversed((output or "").splitlines()):
        stripped = line.strip()
        if not (stripped.startswith("{") and stripped.endswith("}")):
            continue
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return {}


def kernel_ipv6(podman: Any, container: str, timeout: int = FACTS_TIMEOUT_SECONDS) -> bool:
    """Whether the host's kernel offers IPv6, read the way the product reads it."""
    result = podman.exec_bash(container, KERNEL_IPV6_SCRIPT, check=False, timeout=timeout)
    lines = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
    return bool(lines) and lines[-1] == "true"


def helper_source() -> str:
    return HELPER.read_text(encoding="utf-8")


def read_policy(
    podman: Any,
    container: str,
    role: str,
    node_port: int,
    master_sources: Sequence[str],
    ipv6: bool,
    timeout: int = POLICY_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """The policy the shipped helper renders, asked inside the host under test."""
    request = {
        "role": role,
        "node_port": int(node_port),
        "master_sources": sorted({str(source) for source in master_sources}),
        "ipv6": bool(ipv6),
    }
    result = podman.exec(
        container,
        ["python3", "-c", _POLICY_PROGRAM, json.dumps(request, sort_keys=True)],
        check=False,
        input_text=helper_source(),
        timeout=timeout,
    )
    report = _json_object(result.stdout or "")
    if report.get("status") != "success" or not isinstance(report.get("policy"), dict):
        raise CaseBlocked(
            f"the shipped helper rendered no policy for {role} port {node_port} "
            f"(exit {result.returncode}): "
            f"{report.get('error') or (result.stderr or '').strip()[-300:] or 'no output'}"
        )
    return report["policy"]


def restart_ufw(podman: Any, container: str, timeout: int = RELOAD_TIMEOUT_SECONDS) -> Dict[str, str]:
    """Restart the unit a boot runs and read back whether it is still enabled."""
    result = podman.exec_bash(container, RELOAD_SCRIPT, check=False, timeout=timeout)
    lines = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
    return {
        "enabled": lines[0] if lines else "",
        "active": lines[1] if len(lines) > 1 else "",
        "detail": (result.stderr or "").strip()[-300:],
    }


def _host_evidence(
    case_id: str,
    role: str,
    podman: Any,
    container: str,
    node_ports: Sequence[int],
    master_sources: Sequence[str] = (),
) -> Dict[str, Any]:
    """One host: the policy it declares per port, then the rules it applies twice."""
    ipv6 = kernel_ipv6(podman, container)
    declared = {
        int(port): read_policy(podman, container, role, int(port), master_sources, ipv6)
        for port in node_ports
    }
    ssh_ports = sorted({
        int(port)
        for policy in declared.values()
        for port in policy.get("ssh_ports") or []
    })
    require(
        case_id,
        bool(ssh_ports),
        "the shipped helper discovered no SSH port on this host, "
        "so nothing could confirm the operator's own access survived",
    )

    def collect(ports: Sequence[int]) -> Dict[str, Any]:
        return denial.host_firewall(
            podman, container, ports, timeout=FACTS_TIMEOUT_SECONDS,
        )

    def reload(ports: Sequence[int]) -> Dict[str, Any]:
        unit = restart_ufw(podman, container)
        facts = denial.host_firewall(
            podman, container, ports, timeout=FACTS_TIMEOUT_SECONDS,
        )
        facts["unit"] = unit
        return facts

    evidence = case_ingress_matrix(
        case_id, role, int(node_ports[0]), collect, reload, ssh_ports, master_sources, declared,
    )
    evidence["container"] = container
    evidence["kernel_ipv6"] = ipv6
    return evidence


def case_aio_ingress(product: Any, context: Any) -> Dict[str, Any]:
    """FW-05: the All-in-One host's own Node API port, read and reloaded.

    The local Node is installed on 3002 by ``install_local_node`` and nothing in
    the product lets an All-in-One operator choose another number, so this half
    reads one installed port. The port-agnostic half is the declaration below,
    and the AIO's *non-default* port is reported as not applicable instead of
    being rendered and then described as installed.
    """
    host = product.require_installed()
    evidence = _host_evidence(
        CASE_IDS["aio"], "aio", product.podman, host.target_name,
        (DEFAULT_NODE_PORT,), (),
    )
    evidence["non_default_port"] = {
        "status": "NOT_APPLICABLE",
        "reason": (
            "install_local_node hardwires 3002 for the local Node, so this contour has no "
            "installed rule set on a non-default port; the Worker half (FW-06) carries that "
            "question, where `node add` really takes a port"
        ),
    }
    return evidence


def case_worker_ingress(product: Any, context: Any) -> Dict[str, Any]:
    """FW-06: both hosts of the pair — the Master denies, the Worker scopes.

    One case because the two rule sets answer one question between them: who may
    reach a Node API. Running them apart would let a change that opens the
    Master and another that mis-scopes the Worker pass as two green cases.
    """
    host = product.require_worker()
    master_sources = [host.plan.target_ip]
    master = _host_evidence(
        CASE_IDS["multi-node"], "aio", product.podman, host.target_name,
        (DEFAULT_NODE_PORT,), (),
    )
    worker = _host_evidence(
        CASE_IDS["multi-node"], "worker", product.podman, host.worker_name,
        (DEFAULT_NODE_PORT, NON_DEFAULT_NODE_PORT), master_sources,
    )
    evidence = {"master": master, "worker": worker}
    return evidence


def case_panel_only_ingress(product: Any, context: Any) -> Dict[str, Any]:
    """PO-FIREWALL: a Panel-only host has no Node API to expose, on any port."""
    host = product.require_installed()
    evidence = _host_evidence(
        CASE_IDS["panel-only"], "panel-only", product.podman, host.target_name,
        (DEFAULT_NODE_PORT, NON_DEFAULT_NODE_PORT), (),
    )
    return evidence
