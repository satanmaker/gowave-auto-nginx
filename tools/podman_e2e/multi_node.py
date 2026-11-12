"""Multi-Node product E2E: one Master, one Worker, real clients, no mocks.

The Master is the All-in-One host the operator installs in the single-node
suite; the Worker is a separate clean systemd host, provisioned only through
``gowave-auto.sh node add`` from the Master. Nothing here reproduces a product
installation or registration step: the harness creates disposable hosts, pins
the SSH identity an operator would establish out of band, and then observes.

The cases are split the way the product operations are: the install provisions
the Master, ``node add`` registers and deploys the Worker, and everything after
them only observes. A case that would need to provision something itself blocks
instead, because a second provisioning path would stop being the product the
operator ships.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from typing import Any, Dict, List, Optional, Sequence

from tools.podman_e2e import aio, matrix as matrix_data, mtls, topology
from tools.podman_e2e.podman import wait_until
from tools.podman_e2e.runner import Case, CaseBlocked, require

INSTALL_CASE_ID = "MN-INSTALL"
NODE_ADD_CASE_ID = "WRK-04"
WORKER_STATE_CASE_ID = "WRK-05"
WORKER_CONFIG_CASE_ID = "WRK-06"
MASTER_ADDRESS_CASE_ID = "PODNET-MASTER-ADDR"
MTLS_TIMEOUT_SECONDS = 300
CLUSTER_TIMEOUT_SECONDS = 300
WORKER_STATE_TIMEOUT_SECONDS = 300
WORKER_REPORT_TIMEOUT_SECONDS = 120

# The name the installer gives the node the Panel runs on. Without it, a cluster
# audit could be satisfied by any two nodes rather than the ones the product
# provisions.
LOCAL_NODE_NAME = "local-node"

NODE_ADD_TIMEOUT_SECONDS = topology.NODE_ADD_TIMEOUT_SECONDS
NODE_HEALTH_TIMEOUT_SECONDS = 600
NODE_HEALTH_INTERVAL_SECONDS = 5

NODE_PORT = 3002

# The node prepends its own stats/traffic API to whatever the Panel assigned it
# (gowave-node internal/xray/config.go), so the config it loads carries exactly
# one inbound the Panel never declares, and it must be a unix-socket listener
# rather than a port the outside world can reach.
NODE_API_INBOUND_TAG = "GOWAVE_NODE_API_INBOUND"

# Everything the Worker can say about the Master it was told to trust. The
# address arrives in the Worker's own firewall rule and in the peer of the live
# control-plane connection, so the proof does not depend on a value the harness
# passed to itself.
WORKER_CONTROL_SCRIPT = r"""
printf '== node service ==\n'
systemctl is-active gowave-node.service 2>/dev/null || true
printf '== listeners ==\n'
ss -Hltn 2>/dev/null | awk '{ print $4 }' | grep -F 'NODE_PORT_PLACEHOLDER' || true
printf '== established peers ==\n'
ss -Htn state established 2>/dev/null || true
printf '== firewall ==\n'
ufw status 2>/dev/null || true
"""


def worker_control_script() -> str:
    return WORKER_CONTROL_SCRIPT.replace("NODE_PORT_PLACEHOLDER", f":{NODE_PORT}")


# What the Worker says about itself, read through the product's own surfaces: the
# CLI's version and status commands, the config the node actually loaded, and the
# settings file it was installed with. Nothing here is written by the harness, and
# the Panel secret in `/opt/gowave-node/.env` is never read out.
WORKER_STATE_SCRIPT = r"""
python3 - <<'PY'
import json
import os
import subprocess

BINARY = "/opt/gowave-node/gowave-node"
CORE = "/opt/gowave-node/rw-core"
ENV_FILE = "/opt/gowave-node/.env"
RUNTIME = "/run/gowave-node"
CONFIG = os.path.join(RUNTIME, "xray.json")


def text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def mode(path):
    try:
        return oct(os.stat(path).st_mode & 0o777)
    except OSError:
        return ""


def run(*arguments):
    try:
        result = subprocess.run(arguments, capture_output=True, text=True, timeout=90)
    except (OSError, subprocess.SubprocessError) as error:
        return {"returncode": None, "stdout": "", "stderr": str(error)}
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def options(path):
    # The settings that describe the Worker's own serving identity. Everything
    # else in this file, the Panel secret above all, stays unread.
    wanted = {"NODE_PORT", "GOWAVE_NODE_RUNTIME_DIR"}
    found = {}
    for line in text(path).splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key in wanted:
            found[key] = value.strip().strip('"').strip("'")
    return found


def applied(path):
    raw = text(path)
    try:
        config = json.loads(raw) if raw.strip() else None
    except json.JSONDecodeError:
        return {"parsed": False, "inbounds": [], "outbound_count": 0, "api": {}}
    if not isinstance(config, dict):
        return {"parsed": False, "inbounds": [], "outbound_count": 0, "api": {}}
    inbounds = []
    for entry in config.get("inbounds") or []:
        if not isinstance(entry, dict):
            continue
        stream = entry.get("streamSettings")
        stream = stream if isinstance(stream, dict) else {}
        inbounds.append({
            "tag": str(entry.get("tag") or ""),
            "type": str(entry.get("protocol") or ""),
            "port": entry.get("port"),
            "listen": str(entry.get("listen") or ""),
            "network": str(stream.get("network") or "tcp"),
            "security": str(stream.get("security") or "none"),
        })
    outbounds = config.get("outbounds")
    api = config.get("api")
    api = api if isinstance(api, dict) else {}
    services = api.get("services")
    return {
        "parsed": True,
        "inbounds": inbounds,
        "outbound_count": len(outbounds) if isinstance(outbounds, list) else 0,
        "api": {
            "tag": str(api.get("tag") or ""),
            "listen": str(api.get("listen") or ""),
            "services": [str(service) for service in services] if isinstance(services, list) else [],
        },
    }


print(json.dumps({
    "binary": {"path": BINARY, "executable": os.access(BINARY, os.X_OK)},
    "version": run(BINARY, "version"),
    "status": run(BINARY, "status"),
    "paths": {
        "runtime_dir": {"mode": mode(RUNTIME)},
        "config": {"path": CONFIG, "mode": mode(CONFIG)},
        "env": {"path": ENV_FILE, "mode": mode(ENV_FILE)},
        "core": {"path": CORE, "executable": os.access(CORE, os.X_OK)},
    },
    "options": options(ENV_FILE),
    "applied": applied(CONFIG),
}, sort_keys=True))
PY
"""

ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")
VERSION_PATTERN = re.compile(r"\d+\.\d+(?:\.\d+)?")


def strip_ansi(text: str) -> str:
    """Drop the colours the product's status CLI writes even into a pipe."""
    return ANSI_PATTERN.sub("", text or "")


def version_number(text: str) -> str:
    """The numeric part of a version string, so ``v1.0.5 (Go)`` meets ``1.0.5``."""
    match = VERSION_PATTERN.search(str(text or ""))
    return match.group(0) if match else ""


def parse_node_version(output: str) -> str:
    """``gowave-node version`` prints one line: ``gowave-node v1.0.5``."""
    for line in strip_ansi(output).splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0].startswith("gowave-node"):
            return fields[1]
    return ""


def parse_node_status(output: str) -> Dict[str, Any]:
    """The self-report ``gowave-node status`` prints, label by label.

    The CLI is the product's own runtime check, so its verdict — not the unit's
    active state and not a socket the harness opened — is what the case reads.
    """
    labels: Dict[str, str] = {}
    for line in strip_ansi(output).splitlines():
        stripped = line.strip().lstrip("\u25cf\u25cb").strip()
        label, separator, value = stripped.partition(":")
        if not separator or not value.strip():
            continue
        key = label.strip().lower()
        if key.startswith("daemon"):
            labels["daemon"] = value.strip()
        elif key.startswith("systemd"):
            labels["service"] = value.split("(")[0].strip()
        elif key.startswith("xray core"):
            labels["core"] = value.strip()
        elif key.startswith("node version"):
            labels["version"] = value.strip()
    return {
        "daemon_running": labels.get("daemon", "").upper().startswith("RUNNING"),
        "daemon": labels.get("daemon", ""),
        "service": labels.get("service", ""),
        "core": labels.get("core", ""),
        "version": labels.get("version", ""),
    }


def inbound_key(spec: Dict[str, Any]) -> tuple:
    """One inbound declaration reduced to the fields both sides must agree on."""
    port = spec.get("port")
    return (
        str(spec.get("tag") or ""),
        str(spec.get("type") or "").lower(),
        "" if port in (None, "") else str(port),
        str(spec.get("network") or "").lower(),
        str(spec.get("security") or "").lower(),
    )


def node_api_inbounds(inbounds: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The node's own stats/traffic listener, which the Panel never declares."""
    return [entry for entry in inbounds if entry.get("tag") == NODE_API_INBOUND_TAG]


def serving_inbounds(inbounds: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The inbounds that serve clients, i.e. the ones the Panel assigns."""
    return [entry for entry in inbounds if entry.get("tag") != NODE_API_INBOUND_TAG]


def has_unix_api(api: Dict[str, Any]) -> bool:
    """Whether the node's own API listens on a unix socket, as the node decides it.

    ``gowave-node`` prepends the API inbound only for a unix API socket, so the
    expectation has to come from the config's own ``api`` object rather than from
    the harness assuming the default path.
    """
    listen = str(api.get("listen") or "")
    return ":" not in listen or listen.startswith("unix:")


def panel_node(cluster: Dict[str, Any], name: str, case_id: str) -> Dict[str, Any]:
    """The registry record for one node, refused by name when it is absent."""
    records = (cluster.get("nodes") or {}).get("records") or []
    node = next((record for record in records if record.get("name") == name), None)
    require(
        case_id,
        node is not None,
        f"the Panel registry lists no node named {name!r}; observed "
        f"{sorted(str(record.get('name') or '') for record in records)}",
    )
    return node


def normalize_peer_host(host: str) -> str:
    """The peer's address as plain IPv4 when the kernel reported a mapped socket.

    ``ss`` prints a dual-stack connection as ``[::ffff:10.89.0.10]:port``: the node
    binds ``::`` and accepts IPv4, so a Master-to-Worker control connection is an
    IPv6 socket whose peer is the Master's IPv4 address in mapped form. Comparing
    that text to the plan's ``10.89.0.10`` would fail on notation rather than on
    routing, so the mapped address is unwrapped before anything compares it.
    """
    candidate = host.strip("[]")
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return host
    mapped = getattr(address, "ipv4_mapped", None)
    return str(mapped) if mapped is not None else candidate


def parse_worker_control(output: str) -> Dict[str, Any]:
    """Split the Worker's report into the sections the cases assert on."""
    sections: Dict[str, List[str]] = {}
    current = ""
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("==") and stripped.endswith("=="):
            current = stripped.strip("= ").strip()
            sections[current] = []
            continue
        if current and line.strip():
            sections[current].append(line.strip())
    peers: List[str] = []
    for line in sections.get("established peers", []):
        # ss -tn columns: Recv-Q Send-Q Local:Port Peer:Port. The node port is the
        # local end; the peer carries an ephemeral port, so matching on the peer
        # suffix would never match a control-plane connection.
        fields = line.split()
        if len(fields) < 4:
            continue
        local, peer = fields[2], fields[3]
        if not local.endswith(f":{NODE_PORT}"):
            continue
        host = normalize_peer_host(peer.rsplit(":", 1)[0])
        if host not in peers:
            peers.append(host)
    return {
        "node_service": " ".join(sections.get("node service", [])).strip(),
        "listeners": sections.get("listeners", []),
        "peers": peers,
        "firewall": sections.get("firewall", []),
    }


def firewall_master_sources(rules: Sequence[str]) -> List[str]:
    """The addresses the Worker's own firewall allows to reach the node port.

    ``ufw status`` prints the rule as a table — port, verdict, source, comment —
    so the source is the token after the verdict, and the port is the one the
    verdict belongs to. A rule that allows *Anywhere* has no source and is not
    reported here at all.
    """
    sources: List[str] = []
    for line in rules:
        if "GoWave Control Plane" not in line:
            continue
        fields = line.split()
        for index, field in enumerate(fields):
            if field not in ("ALLOW", "LIMIT"):
                continue
            if index == 0 or index + 1 >= len(fields):
                break
            port = fields[index - 1].split("/")[0]
            if port != str(NODE_PORT):
                break
            source = fields[index + 1]
            if source != "Anywhere" and source not in sources:
                sources.append(source)
            break
    return sources


class MultiNodeProduct:
    """The Master install, the Worker provisioning, and the probes over both."""

    def __init__(
        self, podman: Any, distribution: str = "ubuntu-24.04",
        vision: bool = False, worker_vision: bool = False,
    ) -> None:
        self.podman = podman
        self.context = podman.context
        self.distribution = distribution
        # The optional Vision inbound is configured per node, which is what makes
        # the Multi-Node matrix 16, 18 or 20 positive cases.
        self.vision = vision
        self.worker_vision = worker_vision
        self.matrix = matrix_data.load()
        self.master = aio.AioProduct(
            podman, distribution, vision=vision, install_case_id=INSTALL_CASE_ID,
        )
        self.topology: Optional[topology.MultiNodeTopology] = None
        self.node_add_outcome: Optional[topology.InstallOutcome] = None
        self.mtls_positive_facts: Optional[Dict[str, Any]] = None
        self.mtls_negative_facts: Optional[Dict[str, Any]] = None
        self.worker_state_cache: Optional[Dict[str, Any]] = None
        self.worker_report_timeout = WORKER_REPORT_TIMEOUT_SECONDS
        self.worker_report_interval = NODE_HEALTH_INTERVAL_SECONDS
        self.trust: Dict[str, Any] = {}
        self.declared_data_plane: List[str] = []
        self.data_plane_results: Dict[str, str] = {}

    # ------------------------------------------------------------- identities
    @property
    def combination(self) -> str:
        """The matrix key that names this run's per-node Vision configuration."""
        return matrix_data.combination(
            matrix_data.MULTI_NODE, self.vision, self.worker_vision,
        )

    @property
    def positive_case_count(self) -> int:
        return matrix_data.positive_count(
            self.matrix, matrix_data.MULTI_NODE, self.vision, self.worker_vision,
        )

    @property
    def expected_inbound_total(self) -> int:
        """Inbounds the Panel should report across its nodes.

        Each node is issued its own profile, and the optional Vision inbound is
        configured per node, so one node can carry five inbounds while the other
        carries four.
        """
        return self.master_inbound_count + self.worker_inbound_count

    @property
    def master_inbound_count(self) -> int:
        return len(matrix_data.inbounds(self.matrix, vision=self.vision))

    @property
    def worker_inbound_count(self) -> int:
        return len(matrix_data.inbounds(self.matrix, vision=self.worker_vision))

    def declare_data_plane(self, case_ids: Sequence[str]) -> None:
        self.declared_data_plane = list(case_ids)

    def record_data_plane(self, case_id: str, status: str) -> None:
        self.data_plane_results[case_id] = status

    # ------------------------------------------------------------------ setup
    def install(self) -> Dict[str, Any]:
        """Create every role and install the Master through the real operator."""
        host = topology.MultiNodeTopology(
            self.podman,
            distribution=self.distribution,
            vision_domain=topology.VISION_DOMAIN if self.vision else None,
            worker_vision_domain=topology.WORKER_VISION_DOMAIN if self.worker_vision else None,
        )
        host.create()
        # Every role the run declares must exist before the install is asked to
        # succeed: a missing vantage would turn later denials and probes into
        # evidence about nothing.
        host.require_roles()
        evidence = self.master.install(host=host)
        self.topology = host
        self.trust = host.pin_worker_trust()
        evidence.update({
            "worker_trust": self.trust,
            "vision_combination": self.combination,
            "expected_positive_cases": self.positive_case_count,
        })
        return evidence

    def require_installed(self) -> topology.MultiNodeTopology:
        if self.topology is None:
            raise CaseBlocked(
                f"{INSTALL_CASE_ID}: this case needs the Multi-Node install, and no install has run"
            )
        self.master.require_installed()
        return self.topology

    def require_worker(self) -> topology.MultiNodeTopology:
        host = self.require_installed()
        if self.node_add_outcome is None:
            raise CaseBlocked(
                f"{NODE_ADD_CASE_ID}: this case needs the Worker the operator registered"
            )
        if not self.node_add_outcome.ok:
            raise CaseBlocked(
                f"{NODE_ADD_CASE_ID}: the Worker provisioning failed with exit "
                f"{self.node_add_outcome.returncode}, so this case had nothing to verify"
            )
        return host

    # --------------------------------------------------------------- node add
    def add_worker(self) -> Dict[str, Any]:
        """Register and deploy the Worker through the operator's own command."""
        host = self.require_installed()
        outcome = host.node_add()
        self.node_add_outcome = outcome
        require(
            NODE_ADD_CASE_ID,
            outcome.ok,
            f"the operator node add failed with exit {outcome.returncode}:\n{outcome.tail(6000)}",
        )
        return {
            "node_add_returncode": outcome.returncode,
            "node_add_duration_seconds": round(outcome.duration, 1),
            "node_add_command": outcome.command,
            "worker_ip": host.plan.worker_ip,
            "worker_domain": host.worker_domain,
            "worker_reality_domain": host.worker_reality_domain,
        }

    # ---------------------------------------------------------------- probes
    def panel_surface(self, case_id: str) -> Dict[str, Any]:
        return aio.panel_probe(self.master, case_id, "surface")

    def panel_cluster(self, case_id: str) -> Dict[str, Any]:
        return aio.panel_probe(self.master, case_id, "cluster")

    def cluster_facts(self, case_id: str) -> Dict[str, Any]:
        """The Panel's cluster structure, refused by name when the probe returned none."""
        facts = self.panel_cluster(case_id)
        cluster = facts.get("cluster")
        if not isinstance(cluster, dict):
            raise CaseBlocked(
                f"{case_id}: the Panel probe returned no cluster structure; "
                f"observed {sorted(facts)}"
            )
        return cluster

    def worker_state(self, case_id: str) -> Dict[str, Any]:
        """What the Worker says about itself, collected once per run.

        The report is read from the product's own CLI and its own applied config,
        so no case here can be satisfied by a value the harness wrote.
        """
        host = self.require_worker()
        if self.worker_state_cache is None:
            result = self.podman.exec_bash(
                host.worker_name, WORKER_STATE_SCRIPT, check=False,
                timeout=WORKER_STATE_TIMEOUT_SECONDS,
            )
            require(
                case_id,
                result.returncode == 0,
                f"the Worker state probe exited {result.returncode}: "
                f"{(result.stderr or result.stdout or '').strip()[-2000:]}",
            )
            parsed: Optional[Dict[str, Any]] = None
            try:
                candidate = json.loads(result.stdout or "")
            except json.JSONDecodeError:
                candidate = None
            if isinstance(candidate, dict):
                parsed = candidate
            require(
                case_id,
                parsed is not None,
                f"the Worker state probe did not print a JSON object: "
                f"{(result.stdout or '')[:400]}",
            )
            self.worker_state_cache = parsed
        return self.worker_state_cache

    def worker_control_facts(self, case_id: str, timeout: int = 120) -> Dict[str, Any]:
        host = self.require_installed()
        result = self.podman.exec_bash(host.worker_name, worker_control_script(), check=False,
                                       timeout=timeout)
        require(
            case_id,
            result.returncode == 0,
            f"the Worker control probe exited {result.returncode}: "
            f"{(result.stderr or result.stdout or '').strip()[-2000:]}",
        )
        return parse_worker_control(result.stdout or "")

    def wait_for_nodes(self, case_id: str, expected: int) -> Dict[str, Any]:
        """Wait until the Panel reports every node it owns as connected.

        Registration and connection are separate events: the Panel stores the
        node first and only calls it connected once the node answers on its own
        control port. Polling is bounded, so a node that never connects fails the
        case instead of hanging the suite.
        """
        observed: Dict[str, Any] = {}

        def connected() -> bool:
            facts = self.panel_surface(case_id)
            surface = facts.get("surface") or {}
            nodes = surface.get("nodes") or {}
            observed["nodes"] = {
                key: nodes.get(key)
                for key in ("count", "connected_count", "inbound_count", "inbound_types")
            }
            return (
                nodes.get("count") == expected
                and nodes.get("connected_count") == expected
            )

        ready = wait_until(
            connected,
            NODE_HEALTH_TIMEOUT_SECONDS,
            f"{case_id} node health",
            interval_seconds=NODE_HEALTH_INTERVAL_SECONDS,
        )
        require(
            case_id,
            ready,
            f"the Panel never reported {expected} connected nodes within "
            f"{NODE_HEALTH_TIMEOUT_SECONDS}s: {observed}",
        )
        return observed

    def wait_for_worker_report(self, case_id: str) -> Dict[str, Any]:
        """Wait until the Panel holds a version report from the Worker.

        A node's versions are stored by the heartbeat that first reaches the
        Panel, so a read taken between registration and that heartbeat finds the
        connection flag without the self-report behind it.
        """
        observed: Dict[str, Any] = {}

        def reported() -> bool:
            record = panel_node(self.cluster_facts(case_id), topology.WORKER_NODE_NAME, case_id)
            observed.clear()
            observed.update(record)
            versions = record.get("versions") or {}
            return bool(versions.get("node"))

        ready = wait_until(
            reported, self.worker_report_timeout, f"{case_id} Worker self-report",
            interval_seconds=self.worker_report_interval,
        )
        require(
            case_id,
            ready,
            f"the Panel never recorded a node version for {topology.WORKER_NODE_NAME!r} "
            f"within {self.worker_report_timeout}s; last record {observed.get('versions')}",
        )
        return observed

    # ------------------------------------------------------------------- mTLS
    def mtls_positive(self) -> Dict[str, Any]:
        """The product's own verifier, run on the Master against the Worker.

        One run answers MTLS-01 and MTLS-02, but neither case may lean on the
        other's conclusion: the handshake and the HTTP outcome are separate
        observations, and a 401 is a successful handshake with no health answer.
        """
        host = self.require_worker()
        if self.mtls_positive_facts is None:
            self.mtls_positive_facts = mtls.run_positive(
                self.podman, host.target_name, host.plan.worker_ip,
            )
        return self.mtls_positive_facts

    def mtls_negatives(self) -> Dict[str, Any]:
        """Every negative mTLS control, run once on the Master and shared."""
        host = self.require_worker()
        if self.mtls_negative_facts is None:
            self.mtls_negative_facts = mtls.run_negatives(
                self.podman, host.target_name, host.plan.worker_ip,
            )
        return self.mtls_negative_facts

    def mtls_negative_report(self, case_id: str) -> Dict[str, Any]:
        """The negative controls' report, or a block when they produced none.

        A probe that could not run says nothing about the product, so it blocks
        instead of inventing one failure per case that reads it.
        """
        facts = self.mtls_negatives()
        if facts["returncode"] != 0 or not facts["report"]:
            raise CaseBlocked(
                f"{case_id}: the negative mTLS controls produced no report "
                f"(exit {facts['returncode']}): {facts['tail'] or 'no output'}"
            )
        return facts["report"]

    def mtls_negative_outcome(self, case_id: str, key: str) -> Dict[str, Any]:
        """One negative control's outcome, refused by name when it is missing."""
        report = self.mtls_negative_report(case_id)
        outcome = report.get(key)
        require(
            case_id,
            isinstance(outcome, dict),
            f"the negative controls reported nothing for {key!r}; observed {sorted(report)}",
        )
        return outcome

    def worker_address_facts(self, case_id: str) -> Dict[str, Any]:
        """What the Worker itself says about the Master address it was given."""
        host = self.require_installed()
        facts = self.worker_control_facts(case_id)
        sources = firewall_master_sources(facts["firewall"])
        master_address = host.plan.target_ip
        require(
            case_id,
            facts["node_service"] == "active",
            f"gowave-node.service on the Worker reports {facts['node_service']!r} instead of active",
        )
        require(
            case_id,
            facts["listeners"],
            f"the Worker listens on no control port; expected :{NODE_PORT}",
        )
        require(
            case_id,
            sources == [master_address],
            f"the Worker's firewall allows {sources or 'nobody'} to reach :{NODE_PORT} "
            f"instead of only the Master's run address {master_address}",
        )
        require(
            case_id,
            master_address in facts["peers"],
            f"no live Master-to-Worker connection arrives from {master_address}; "
            f"observed peers {facts['peers'] or 'none'}",
        )
        require(
            case_id,
            all(peer.startswith("10.") for peer in facts["peers"]),
            f"the Worker saw a control-plane peer outside the run network: {facts['peers']}",
        )
        return {
            "master_address": master_address,
            "firewall_sources": sources,
            "peers": facts["peers"],
            "listeners": facts["listeners"],
            "node_service": facts["node_service"],
        }


def case_worker_registration(product: MultiNodeProduct) -> Dict[str, Any]:
    """WRK-04: the operator's node add registers and deploys the Worker.

    A total node count cannot tell a registered Worker from a second copy of the
    Master, so the case names both nodes and their endpoints, and it reads the
    Worker's own connection state from the Panel rather than inferring it.
    """
    host = product.require_installed()
    evidence = product.add_worker()
    observed = product.wait_for_nodes(NODE_ADD_CASE_ID, expected=2)
    facts = product.panel_surface(NODE_ADD_CASE_ID)
    surface = facts.get("surface") or {}
    hosts = surface.get("hosts") or {}
    nodes = surface.get("nodes") or {}
    names = nodes.get("names") or []
    endpoints = nodes.get("endpoints") or []
    connected = nodes.get("connected") or {}
    worker_endpoint = f"{host.plan.worker_ip}:{NODE_PORT}"
    require(
        NODE_ADD_CASE_ID,
        topology.WORKER_NODE_NAME in names,
        f"the Panel reports nodes {names or 'none'}, and none of them is the "
        f"registered Worker {topology.WORKER_NODE_NAME!r}",
    )
    require(
        NODE_ADD_CASE_ID,
        worker_endpoint in endpoints,
        f"the Panel reports endpoints {endpoints or 'none'} instead of registering the "
        f"Worker at {worker_endpoint}",
    )
    require(
        NODE_ADD_CASE_ID,
        connected.get(topology.WORKER_NODE_NAME) is True,
        f"the Panel reports the Worker as {connected.get(topology.WORKER_NODE_NAME)!r} "
        f"rather than connected; observed {connected}",
    )
    require(
        NODE_ADD_CASE_ID,
        nodes.get("inbound_count") == product.expected_inbound_total,
        f"the two nodes expose {nodes.get('inbound_count')!r} active inbounds in total, "
        f"expected {product.expected_inbound_total} for the {product.combination} Vision configuration",
    )
    require(
        NODE_ADD_CASE_ID,
        hosts.get("count", 0) >= 2,
        f"the Panel publishes {hosts.get('count')!r} hosts instead of one per node",
    )
    evidence.update({
        "panel_nodes": observed.get("nodes", {}),
        "panel_node_names": names,
        "panel_node_endpoints": endpoints,
        "panel_node_connected": connected,
        "worker_endpoint": worker_endpoint,
        "panel_hosts": {
            "count": hosts.get("count"),
            "security_layers": hosts.get("security_layers"),
            "fingerprints": hosts.get("fingerprints"),
        },
        "unauthenticated_nodes_status": surface.get("unauthenticated_nodes_status"),
    })
    return evidence


def case_master_address(product: MultiNodeProduct) -> Dict[str, Any]:
    """PODNET-MASTER-ADDR: the Worker's control plane runs over the Master's run address.

    The product discovers the Master's public address through an IP echo service
    on a real VPS. Inside the disposable topology that address is not what the
    Worker can reach, so the installer's narrow Podman override supplies the
    Master's address on the run network. This case proves the Worker *observed*
    that address — in its own firewall rule and in the live connection's peer —
    rather than trusting the value the harness passed in.
    """
    product.require_worker()
    return product.worker_address_facts(MASTER_ADDRESS_CASE_ID)


def case_mtls_verifier(product: MultiNodeProduct) -> Dict[str, Any]:
    """MTLS-01: the product's verifier proves the payload and then the handshake.

    The order is the assertion: the payload check must be printed before the
    socket attempt, because a handshake against an unverified payload would also
    succeed. The recorded facts are the verifier's own markers and the Worker's
    status line — never the payload or the HKDF-derived SNI.
    """
    facts = product.mtls_positive()
    require(
        "MTLS-01",
        facts["returncode"] == 0,
        f"the product's mTLS verifier exited {facts['returncode']}: "
        f"{facts['tail'] or 'no output'}",
    )
    require(
        "MTLS-01",
        facts["payload_crypto_pass"],
        f"the verifier never reported its payload cryptographic verification: "
        f"{facts['tail'] or 'no output'}",
    )
    require(
        "MTLS-01",
        facts["payload_verified_before_socket"],
        "the verifier reported the payload result after the socket attempt, so a "
        "handshake would have run against an unverified payload",
    )
    require(
        "MTLS-01",
        facts["handshake_pass"],
        f"the mTLS handshake did not negotiate TLS 1.3: {facts['tail'] or 'no output'}",
    )
    require(
        "MTLS-01",
        facts["status_line"],
        "the verified handshake produced no Node status line",
    )
    return {
        "payload_crypto_pass": True,
        "payload_verified_before_socket": True,
        "handshake_line": facts["handshake_line"],
        "node_response": facts["status_line"],
    }


def case_mtls_http_classification(product: MultiNodeProduct) -> Dict[str, Any]:
    """MTLS-02: a successful handshake is not yet an authenticated control plane.

    HTTP 200 means the Node answered the health endpoint over mutual TLS. HTTP
    401 means the handshake passed but the request carried no accepted token, so
    the health and authenticated-control-plane flags must stay clear.
    """
    facts = product.mtls_positive()
    require(
        "MTLS-02",
        facts["handshake_pass"],
        "the TLS 1.3 handshake never succeeded, so the HTTP outcome says nothing "
        "about authentication",
    )
    require(
        "MTLS-02",
        facts["response"] != "none",
        "the Worker returned no status line after the handshake",
    )
    require(
        "MTLS-02",
        facts["response"] in ("health", "unauthenticated"),
        f"the Worker answered {facts['status_line']!r} instead of a health or "
        f"authentication outcome",
    )
    require(
        "MTLS-02",
        facts["response"] == "health",
        f"the mTLS handshake passed but the Worker answered {facts['status_line']!r}: "
        "MTLS_HANDSHAKE_PASS is set, WORKER_HTTP_HEALTH_PASS is not, and the "
        "authenticated control plane the Panel relies on was not proven",
    )
    return {
        "mtls_handshake_pass": True,
        "worker_http_health_pass": True,
        "node_response": facts["status_line"],
    }


def case_mtls_panel_auth(product: MultiNodeProduct) -> Dict[str, Any]:
    """MTLS-03: the Panel's own connection state, not a local 401, proves authentication.

    A local client that happens to receive 401 has proven the handshake, not
    that the Panel authenticates to the Worker. Only the Panel's node registry
    can say that.
    """
    product.require_worker()
    facts = product.panel_surface("MTLS-03")
    surface = facts.get("surface") or {}
    nodes = surface.get("nodes") or {}
    connected = nodes.get("connected") or {}
    state = connected.get(topology.WORKER_NODE_NAME)
    require(
        "MTLS-03",
        state is True,
        f"the Panel reports {topology.WORKER_NODE_NAME!r} as {state!r}; a local "
        f"handshake outcome cannot stand in for the Panel's authenticated "
        f"connection, and the Panel registry is the only proof of it",
    )
    return {
        "panel_worker_auth_pass": True,
        "panel_node_connected": connected,
        "unauthenticated_nodes_status": surface.get("unauthenticated_nodes_status"),
    }


def case_mtls_untrusted_client(product: MultiNodeProduct) -> Dict[str, Any]:
    """MTLS-04: a client certificate the Worker's CA never issued is refused."""
    outcome = product.mtls_negative_outcome("MTLS-04", "untrusted_client")
    require(
        "MTLS-04",
        outcome["outcome"] == "TLS_REJECTED",
        f"a self-signed client certificate produced {outcome['outcome']} "
        f"({outcome.get('error') or outcome.get('status_line') or 'no detail'}) "
        f"instead of a TLS rejection during the handshake",
    )
    return {"untrusted_client": outcome}


def case_mtls_absent_client(product: MultiNodeProduct) -> Dict[str, Any]:
    """MTLS-05: no client certificate at all is refused before any handler."""
    outcome = product.mtls_negative_outcome("MTLS-05", "absent_client")
    require(
        "MTLS-05",
        outcome["outcome"] == "TLS_REJECTED",
        f"a client that presents no certificate produced {outcome['outcome']} "
        f"({outcome.get('error') or outcome.get('status_line') or 'no detail'}) "
        f"instead of a TLS rejection during the handshake",
    )
    return {"absent_client": outcome}


def case_mtls_mismatched_pair(product: MultiNodeProduct) -> Dict[str, Any]:
    """MTLS-06: a mismatched certificate and key fails locally, before any socket.

    A remote rejection would be a different finding: it would mean the verifier
    shipped the broken pair to the Worker. The socket counter is what separates
    the two.
    """
    report = product.mtls_negative_report("MTLS-06")
    require(
        "MTLS-06",
        report.get("mismatched_crypto_failed") is True,
        "the payload crypto validation accepted a certificate whose public key "
        "does not match the private key",
    )
    require(
        "MTLS-06",
        report.get("mismatched_socket_calls") == 0,
        f"the mismatched-pair validation opened {report.get('mismatched_socket_calls')!r} "
        f"sockets, so the failure was not local",
    )
    return {
        "mismatched_crypto_failed": True,
        "sockets_opened": 0,
        "classification": "client-side validation failure",
    }


def case_mtls_untrusted_ca(product: MultiNodeProduct) -> Dict[str, Any]:
    """MTLS-07: an untrusted Worker CA is this side's trust failure, not a rejection."""
    outcome = product.mtls_negative_outcome("MTLS-07", "untrusted_ca")
    require(
        "MTLS-07",
        outcome["outcome"] == "SERVER_CERT_REJECTED",
        f"with the GoWave CA removed from the trust store the outcome was "
        f"{outcome['outcome']} ({outcome.get('error') or outcome.get('status_line') or 'no detail'}); "
        f"only a client-side certificate verification failure isolates the trust "
        f"store without changing the SNI or the client identity",
    )
    return {"untrusted_ca": outcome, "classification": "client-side server verification failure"}


def case_mtls_wrong_sni(product: MultiNodeProduct) -> Dict[str, Any]:
    """MTLS-08: a wrong SNI is measured, not assumed to raise a TLS alert.

    A fallback vhost may complete TLS and answer over the default route, which
    is routing evidence rather than a handshake failure. Either observation is
    recorded as it arrived; only "TLS established, nothing answered" is refused.
    """
    outcome = product.mtls_negative_outcome("MTLS-08", "wrong_sni")
    require(
        "MTLS-08",
        outcome["outcome"] in ("TLS_REJECTED", "HTTP_RESPONSE"),
        f"the wrong-SNI attempt produced {outcome['outcome']} "
        f"({outcome.get('error') or 'no detail'}); TLS that is established but "
        f"unanswered is not evidence of routing either way",
    )
    return {"wrong_sni": outcome}


def case_cluster_hosts(product: MultiNodeProduct) -> Dict[str, Any]:
    """CLUS-01: every Host names one node, one of its inbounds, and the pinned fingerprint.

    The Host records are what a client is told to dial, so a host total proves
    nothing: a host can exist, carry a fingerprint, and still name another
    node's inbound. Each record must therefore name exactly one node, publish an
    inbound that node's profile actually carries, and keep the uTLS fingerprint
    the product pins for both the REALITY and TLS transports.
    """
    product.require_worker()
    cluster = product.cluster_facts("CLUS-01")
    hosts = cluster.get("hosts") or {}
    require(
        "CLUS-01",
        hosts.get("status") == 200,
        f"GET /api/hosts returned {hosts.get('status')!r}",
    )
    records = hosts.get("records") or []
    nodes = {
        record.get("uuid"): record
        for record in (cluster.get("nodes") or {}).get("records") or []
    }
    expected = product.expected_inbound_total
    require(
        "CLUS-01",
        len(records) == expected,
        f"the Panel publishes {len(records)} hosts, expected {expected} for the "
        f"{product.combination} Vision configuration",
    )
    per_node: Dict[str, int] = {}
    for record in records:
        remark = record.get("remark")
        references = record.get("nodes") or []
        require(
            "CLUS-01",
            len(references) == 1,
            f"host {remark!r} references {len(references)} nodes instead of exactly one",
        )
        node = nodes.get(references[0])
        require(
            "CLUS-01",
            node is not None,
            f"host {remark!r} references a node that GET /api/nodes does not list",
        )
        require(
            "CLUS-01",
            record.get("inbound") in (node.get("inbounds") or []),
            f"host {remark!r} publishes an inbound that is not among the inbounds "
            f"{node.get('name')!r} runs, so its clients would be dialled at a "
            f"transport that node does not serve",
        )
        require(
            "CLUS-01",
            record.get("profile") == node.get("profile"),
            f"host {remark!r} belongs to a profile its node {node.get('name')!r} "
            f"does not run",
        )
        name = str(node.get("name") or "")
        per_node[name] = per_node.get(name, 0) + 1

    require(
        "CLUS-01",
        set(per_node) == {LOCAL_NODE_NAME, topology.WORKER_NODE_NAME},
        f"the published hosts cover {sorted(per_node)} instead of both nodes",
    )
    for name, expected_count in (
        (LOCAL_NODE_NAME, product.master_inbound_count),
        (topology.WORKER_NODE_NAME, product.worker_inbound_count),
    ):
        require(
            "CLUS-01",
            per_node.get(name) == expected_count,
            f"{per_node.get(name)!r} hosts reference {name!r}, expected one per "
            f"active inbound ({expected_count})",
        )

    fingerprints = sorted({str(record.get("fingerprint") or "") for record in records})
    require(
        "CLUS-01",
        fingerprints == [aio.EXPECTED_FINGERPRINT],
        f"the published hosts carry fingerprints {fingerprints} instead of the "
        f"pinned {aio.EXPECTED_FINGERPRINT!r}",
    )
    layers = sorted({str(record.get("security_layer") or "") for record in records})
    require(
        "CLUS-01",
        {"DEFAULT", "TLS"}.issubset(set(layers)),
        f"the published hosts carry security layers {layers}; the REALITY and TLS "
        f"hosts must both exist for the pinned fingerprint to cover both classes",
    )
    return {
        "host_count": len(records),
        "hosts_per_node": per_node,
        "fingerprints": fingerprints,
        "security_layers": layers,
    }


def case_cluster_squad(product: MultiNodeProduct) -> Dict[str, Any]:
    """CLUS-02: the MVP squad grants exactly the inbounds the two nodes carry.

    A squad that omits an inbound hands a client a subscription that cannot
    reach that transport; a squad that repeats one hands out a duplicate entry.
    Only set equality against the node records catches both, and the comparison
    is against the Panel's own node inventory rather than the matrix, so a
    provisioning defect cannot be signed off by the plan that caused it.
    """
    product.require_worker()
    cluster = product.cluster_facts("CLUS-02")
    squad = cluster.get("squad") or {}
    require(
        "CLUS-02",
        squad.get("status") == 200,
        f"GET /api/internal-squads returned {squad.get('status')!r}",
    )
    require(
        "CLUS-02",
        squad.get("mvp_present"),
        f"the Panel lists no {squad.get('name')!r} squad, so no client could be granted "
        f"the provisioned inbounds through it",
    )
    nodes = (cluster.get("nodes") or {}).get("records") or []
    require(
        "CLUS-02",
        len(nodes) == 2,
        f"the squad comparison needs both nodes and the Panel reports {len(nodes)}",
    )
    expected = sorted({value for node in nodes for value in node.get("inbounds") or []})
    granted = squad.get("inbounds") or []
    duplicates = sorted({
        value for value in granted if granted.count(value) > 1
    })
    require(
        "CLUS-02",
        not duplicates,
        f"the squad grants {len(duplicates)} inbound(s) more than once "
        f"({duplicates}), so a client would receive duplicate proxy entries",
    )
    require(
        "CLUS-02",
        sorted(granted) == expected,
        f"the squad's inbound set differs from the inbounds the two nodes run: "
        f"missing {sorted(set(expected) - set(granted))}, "
        f"extra {sorted(set(granted) - set(expected))}",
    )
    require(
        "CLUS-02",
        len(granted) == product.expected_inbound_total,
        f"the squad grants {len(granted)} inbounds, expected "
        f"{product.expected_inbound_total} for the {product.combination} Vision "
        f"configuration",
    )
    return {
        "squad": squad.get("name"),
        "granted_inbound_count": len(granted),
        "unique_granted_inbound_count": len(set(granted)),
        "node_inbound_count": len(expected),
    }


def case_cluster_nodes(product: MultiNodeProduct) -> Dict[str, Any]:
    """CLUS-03: two nodes, each on its own profile and its own dial address.

    The Worker exists for clients to be pointed at it, so the case separates the
    two addresses the product maintains: the Panel reaches the Worker on its Node
    API address (the run-network IP), while a client dials it on the Worker's own
    VPN domain. Two profiles have to expand into loadable configs, because a node
    attached to an unexpandable profile is registered but unusable.
    """
    host = product.require_worker()
    cluster = product.cluster_facts("CLUS-03")

    nodes_section = cluster.get("nodes") or {}
    require(
        "CLUS-03",
        nodes_section.get("status") == 200,
        f"GET /api/nodes returned {nodes_section.get('status')!r}",
    )
    records = nodes_section.get("records") or []
    require(
        "CLUS-03",
        len(records) == 2,
        f"the Panel reports {len(records)} nodes instead of the Master and the Worker",
    )
    by_name = {str(record.get("name") or ""): record for record in records}
    require(
        "CLUS-03",
        set(by_name) == {LOCAL_NODE_NAME, topology.WORKER_NODE_NAME},
        f"the Panel reports nodes {sorted(by_name)} instead of "
        f"{sorted({LOCAL_NODE_NAME, topology.WORKER_NODE_NAME})}",
    )
    local = by_name[LOCAL_NODE_NAME]
    worker = by_name[topology.WORKER_NODE_NAME]
    require(
        "CLUS-03",
        (local.get("address"), local.get("port")) == ("127.0.0.1", NODE_PORT),
        f"the Master node is registered at {local.get('address')!r}:{local.get('port')!r} "
        f"instead of 127.0.0.1:{NODE_PORT}",
    )
    require(
        "CLUS-03",
        (worker.get("address"), worker.get("port")) == (host.plan.worker_ip, NODE_PORT),
        f"the Worker's Node API address is {worker.get('address')!r}:{worker.get('port')!r} "
        f"instead of {host.plan.worker_ip}:{NODE_PORT}",
    )
    for record, expected_count in (
        (local, product.master_inbound_count),
        (worker, product.worker_inbound_count),
    ):
        inbounds = record.get("inbounds") or []
        require(
            "CLUS-03",
            len(inbounds) == expected_count,
            f"{record.get('name')!r} runs {len(inbounds)} active inbounds, expected "
            f"{expected_count}",
        )
        require(
            "CLUS-03",
            len(set(inbounds)) == len(inbounds),
            f"{record.get('name')!r} lists the same inbound UUID more than once",
        )
    require(
        "CLUS-03",
        not set(local.get("inbounds") or []) & set(worker.get("inbounds") or []),
        "the two nodes share an inbound UUID, so a host cannot be attributed to one of them",
    )

    profiles_section = cluster.get("profiles") or {}
    require(
        "CLUS-03",
        profiles_section.get("status") == 200,
        f"GET /api/config-profiles returned {profiles_section.get('status')!r}",
    )
    profiles = profiles_section.get("records") or []
    require(
        "CLUS-03",
        len(profiles) == 2,
        f"the Panel reports {len(profiles)} config profiles instead of one per node",
    )
    require(
        "CLUS-03",
        len({profile.get("uuid") for profile in profiles}) == 2,
        "the two nodes are not attached to two distinct config profiles",
    )
    for record in (local, worker):
        profile = next(
            (candidate for candidate in profiles
             if candidate.get("uuid") == record.get("profile")),
            None,
        )
        require(
            "CLUS-03",
            profile is not None,
            f"node {record.get('name')!r} runs a profile GET /api/config-profiles does not list",
        )
        require(
            "CLUS-03",
            sorted(profile.get("inbounds") or []) == sorted(record.get("inbounds") or []),
            f"the profile of {record.get('name')!r} declares different inbounds than the "
            f"node runs, so the node would serve a different set than the Panel publishes",
        )
        computed = profile.get("computed") or {}
        require(
            "CLUS-03",
            computed.get("status") == 200,
            f"the computed config of {record.get('name')!r}'s profile returned "
            f"{computed.get('status')!r}",
        )
        require(
            "CLUS-03",
            computed.get("parsed") is True,
            f"the computed config of {record.get('name')!r}'s profile is not valid JSON",
        )
        require(
            "CLUS-03",
            computed.get("inbound_count") == len(profile.get("inbounds") or []),
            f"the computed config of {record.get('name')!r}'s profile expands "
            f"{computed.get('inbound_count')!r} inbounds for "
            f"{len(profile.get('inbounds') or [])} declared ones",
        )
        require(
            "CLUS-03",
            int(computed.get("outbound_count") or 0) > 0,
            f"the computed config of {record.get('name')!r}'s profile carries no outbounds",
        )

    hosts = (cluster.get("hosts") or {}).get("records") or []
    worker_hosts = [
        record for record in hosts if worker.get("uuid") in (record.get("nodes") or [])
    ]
    require(
        "CLUS-03",
        worker_hosts,
        "no published host references the Worker, so no client could be pointed at it",
    )
    vpn_addresses = {host.worker_domain}
    if product.worker_vision:
        vpn_addresses.add(host.worker_vision_domain)
    stray = sorted({
        str(record.get("address") or "")
        for record in worker_hosts
        if record.get("address") not in vpn_addresses
    })
    require(
        "CLUS-03",
        not stray,
        f"the Worker's hosts dial {stray} instead of the Worker's own VPN address "
        f"{sorted(vpn_addresses)}",
    )
    reality = [
        record for record in worker_hosts
        if record.get("security_layer") == "DEFAULT"
    ]
    require(
        "CLUS-03",
        reality,
        "the Worker publishes no REALITY host, so its VPN client address cannot be checked",
    )
    require(
        "CLUS-03",
        all(record.get("address") == host.worker_domain for record in reality),
        f"the Worker's REALITY host does not dial {host.worker_domain!r}; observed "
        f"{sorted({str(record.get('address') or '') for record in reality})}",
    )
    return {
        "nodes": sorted(by_name),
        "node_addresses": {
            name: f"{record.get('address')}:{record.get('port')}"
            for name, record in by_name.items()
        },
        "inbounds_per_node": {
            name: len(record.get("inbounds") or []) for name, record in by_name.items()
        },
        "profile_count": len(profiles),
        "worker_vpn_addresses": sorted(vpn_addresses),
        "worker_host_count": len(worker_hosts),
    }


def case_worker_state(product: MultiNodeProduct) -> Dict[str, Any]:
    """WRK-05: the Worker's own health report is what the Panel records about it.

    The Panel does not invent a node's version strings; they arrive over that
    node's heartbeat. Reading the same binary and the same core on the Worker is
    what turns the registry entry into a fact. And a connected node whose latest
    config was rejected is not healthy, which is exactly what the registry's
    status message says and a connection count cannot.
    """
    product.require_worker()
    record = product.wait_for_worker_report(WORKER_STATE_CASE_ID)
    state = record.get("state") or {}
    versions = record.get("versions") or {}
    require(
        WORKER_STATE_CASE_ID,
        record.get("connected") is True,
        f"the Panel does not report {topology.WORKER_NODE_NAME!r} as connected",
    )
    require(
        WORKER_STATE_CASE_ID,
        state.get("disabled") is not True,
        "the Panel holds the Worker disabled, so it is registered but not serving",
    )
    require(
        WORKER_STATE_CASE_ID,
        state.get("connecting") is not True,
        f"the Panel still reports the Worker as connecting after {NODE_ADD_CASE_ID}",
    )
    require(
        WORKER_STATE_CASE_ID,
        not state.get("status_message"),
        f"the Panel records a node status message {state.get('status_message')!r}, "
        f"which is how it reports a config the node refused to load",
    )
    require(
        WORKER_STATE_CASE_ID,
        str(versions.get("node_type") or "").lower() == "go",
        f"the Panel records the Worker as a {versions.get('node_type')!r} node",
    )

    facts = product.worker_state(WORKER_STATE_CASE_ID)
    binary = facts.get("binary") or {}
    require(
        WORKER_STATE_CASE_ID,
        binary.get("executable") is True,
        f"the Worker has no executable node binary at {binary.get('path') or 'the node path'}",
    )
    version_command = facts.get("version") or {}
    version = parse_node_version(version_command.get("stdout") or "")
    require(
        WORKER_STATE_CASE_ID,
        version_command.get("returncode") == 0 and bool(version),
        f"`gowave-node version` on the Worker exited {version_command.get('returncode')} "
        f"and printed {(version_command.get('stdout') or '').strip()[:200]!r}",
    )
    require(
        WORKER_STATE_CASE_ID,
        version_number(version) == version_number(versions.get("node")),
        f"the Worker binary reports {version!r} while the Panel records "
        f"{versions.get('node')!r}",
    )
    requested = (os.environ.get("GOWAVE_NODE_VERSION") or "").strip()
    if requested and requested.lower() != "latest":
        require(
            WORKER_STATE_CASE_ID,
            version_number(version) == version_number(requested),
            f"the Worker runs {version!r} although this deployment requested {requested!r}",
        )

    status_command = facts.get("status") or {}
    status = parse_node_status(status_command.get("stdout") or "")
    require(
        WORKER_STATE_CASE_ID,
        status_command.get("returncode") == 0 and status["daemon_running"],
        f"`gowave-node status` on the Worker reports "
        f"{status.get('daemon') or 'no daemon line'!r}; exit {status_command.get('returncode')}",
    )
    core = status.get("core") or ""
    require(
        WORKER_STATE_CASE_ID,
        bool(core) and "NOT FOUND" not in core.upper(),
        f"`gowave-node status` on the Worker reports no Xray core: {core!r}",
    )
    panel_xray = versions.get("xray") or ""
    require(
        WORKER_STATE_CASE_ID,
        bool(panel_xray) and version_number(core) == version_number(panel_xray),
        f"the Worker's core reports {core!r} while the Panel records {panel_xray!r}",
    )
    return {
        "worker_version": version,
        "requested_version": requested or "latest",
        "panel_node_version": versions.get("node"),
        "panel_xray_version": panel_xray,
        "core": core,
        "daemon": status.get("daemon"),
        "service": status.get("service"),
        "last_status_change": state.get("last_status_change"),
    }


def case_worker_config(product: MultiNodeProduct) -> Dict[str, Any]:
    """WRK-06: the config the Worker loaded is the one the Panel assigned to it.

    An active-inbound count cannot tell a node serving its own assignment from a
    node serving another's, and it cannot tell whether the latest config was
    applied. So the Worker's applied config — the product's own output — is
    compared to the Panel's declaration field by field, and the permissions that
    keep the REALITY keys and client credentials private are checked with it.
    """
    product.require_worker()
    record = panel_node(
        product.cluster_facts(WORKER_CONFIG_CASE_ID),
        topology.WORKER_NODE_NAME, WORKER_CONFIG_CASE_ID,
    )
    declared = [spec for spec in record.get("inbound_specs") or [] if isinstance(spec, dict)]
    require(
        WORKER_CONFIG_CASE_ID,
        bool(declared),
        f"the Panel declares no inbounds for {topology.WORKER_NODE_NAME!r}",
    )
    require(
        WORKER_CONFIG_CASE_ID,
        len(declared) == product.worker_inbound_count,
        f"the Panel declares {len(declared)} inbounds for the Worker, expected "
        f"{product.worker_inbound_count}",
    )

    facts = product.worker_state(WORKER_CONFIG_CASE_ID)
    paths = facts.get("paths") or {}
    config_path = (paths.get("config") or {}).get("path") or "/run/gowave-node/xray.json"
    applied = facts.get("applied") or {}
    require(
        WORKER_CONFIG_CASE_ID,
        applied.get("parsed") is True,
        f"the config the Worker applied at {config_path} is not a JSON object",
    )
    inbounds = [entry for entry in applied.get("inbounds") or [] if isinstance(entry, dict)]
    api_config = applied.get("api") or {}
    api = node_api_inbounds(inbounds)
    if has_unix_api(api_config):
        require(
            WORKER_CONFIG_CASE_ID,
            len(api) == 1,
            f"the Worker's config carries {len(api)} {NODE_API_INBOUND_TAG} inbounds "
            f"while its API listens on a unix socket, expected exactly one: the stats "
            f"service the Panel's traffic accounting queries",
        )
        require(
            WORKER_CONFIG_CASE_ID,
            api[0].get("type") == "tunnel"
            and str(api[0].get("listen") or "").startswith(("/", "@")),
            f"the Worker's {NODE_API_INBOUND_TAG} inbound is not a local unix listener: "
            f"protocol {api[0].get('type')!r}, listen {api[0].get('listen')!r}",
        )
    require(
        WORKER_CONFIG_CASE_ID,
        "StatsService" in (api_config.get("services") or []),
        f"the Worker's config exposes no StatsService, so the traffic the Panel bills "
        f"cannot be accounted: {api_config.get('services')!r}",
    )
    serving = serving_inbounds(inbounds)
    require(
        WORKER_CONFIG_CASE_ID,
        len(serving) == len(declared),
        f"the Worker serves {len(serving)} inbounds while the Panel assigned it "
        f"{len(declared)}",
    )
    require(
        WORKER_CONFIG_CASE_ID,
        applied.get("outbound_count", 0) > 0,
        "the config the Worker loaded declares no outbounds",
    )
    expected = {inbound_key(spec) for spec in declared}
    actual = {inbound_key(spec) for spec in serving}
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    require(
        WORKER_CONFIG_CASE_ID,
        not missing and not extra,
        f"the inbounds the Worker loaded differ from the Panel's assignment: "
        f"missing {missing}, unexpected {extra}",
    )

    runtime_mode = (paths.get("runtime_dir") or {}).get("mode")
    config_mode = (paths.get("config") or {}).get("mode")
    env_mode = (paths.get("env") or {}).get("mode")
    require(
        WORKER_CONFIG_CASE_ID,
        runtime_mode == "0o700",
        f"the Worker's runtime directory is {runtime_mode!r} instead of 0700, so the "
        f"config inside it is reachable by other local users",
    )
    require(
        WORKER_CONFIG_CASE_ID,
        config_mode == "0o600",
        f"the applied config is {config_mode!r} instead of 0600 although it carries the "
        f"REALITY key material and client credentials",
    )
    require(
        WORKER_CONFIG_CASE_ID,
        env_mode == "0o600",
        f"the Worker's settings file is {env_mode!r} instead of 0600",
    )

    options = facts.get("options") or {}
    require(
        WORKER_CONFIG_CASE_ID,
        str(options.get("NODE_PORT")) == str(record.get("port")),
        f"the Worker's settings serve port {options.get('NODE_PORT')!r} while the Panel "
        f"reaches it on {record.get('port')!r}",
    )
    return {
        "declared_inbound_count": len(declared),
        "worker_inbound_count": len(serving),
        "applied_inbound_count": len(inbounds),
        "api_inbound": {
            "tag": api[0].get("tag"),
            "type": api[0].get("type"),
            "listen": api[0].get("listen"),
        } if api else {"tag": "", "type": "", "listen": ""},
        "api_services": list(api_config.get("services") or []),
        "inbound_ports": sorted({str(entry.get("port")) for entry in serving}),
        "inbound_tags": sorted(str(entry.get("tag") or "") for entry in serving),
        "outbound_count": applied.get("outbound_count"),
        "node_port": options.get("NODE_PORT"),
        "runtime_mode": runtime_mode,
        "config_mode": config_mode,
        "env_mode": env_mode,
    }


def cases(
    podman: Any, distribution: str = "ubuntu-24.04",
    vision: bool = False, worker_vision: bool = False,
) -> List[Case]:
    """The Multi-Node suite: install, Worker provisioning, then observation."""
    product = MultiNodeProduct(
        podman, distribution, vision=vision, worker_vision=worker_vision,
    )
    return [
        Case(INSTALL_CASE_ID, "multi-node", lambda context: product.install(),
             timeout_seconds=aio.INSTALL_TIMEOUT_SECONDS),
        Case(NODE_ADD_CASE_ID, "multi-node", lambda context: case_worker_registration(product),
             timeout_seconds=NODE_ADD_TIMEOUT_SECONDS + NODE_HEALTH_TIMEOUT_SECONDS),
        Case(MASTER_ADDRESS_CASE_ID, "multi-node", lambda context: case_master_address(product),
             timeout_seconds=300),
        Case("MTLS-01", "multi-node", lambda context: case_mtls_verifier(product),
             timeout_seconds=MTLS_TIMEOUT_SECONDS),
        Case("MTLS-02", "multi-node", lambda context: case_mtls_http_classification(product),
             timeout_seconds=MTLS_TIMEOUT_SECONDS),
        Case("MTLS-03", "multi-node", lambda context: case_mtls_panel_auth(product),
             timeout_seconds=MTLS_TIMEOUT_SECONDS),
        Case("MTLS-04", "multi-node", lambda context: case_mtls_untrusted_client(product),
             timeout_seconds=MTLS_TIMEOUT_SECONDS),
        Case("MTLS-05", "multi-node", lambda context: case_mtls_absent_client(product),
             timeout_seconds=MTLS_TIMEOUT_SECONDS),
        Case("MTLS-06", "multi-node", lambda context: case_mtls_mismatched_pair(product),
             timeout_seconds=MTLS_TIMEOUT_SECONDS),
        Case("MTLS-07", "multi-node", lambda context: case_mtls_untrusted_ca(product),
             timeout_seconds=MTLS_TIMEOUT_SECONDS),
        Case("MTLS-08", "multi-node", lambda context: case_mtls_wrong_sni(product),
             timeout_seconds=MTLS_TIMEOUT_SECONDS),
        Case("CLUS-01", "multi-node", lambda context: case_cluster_hosts(product),
             timeout_seconds=CLUSTER_TIMEOUT_SECONDS),
        Case("CLUS-02", "multi-node", lambda context: case_cluster_squad(product),
             timeout_seconds=CLUSTER_TIMEOUT_SECONDS),
        Case("CLUS-03", "multi-node", lambda context: case_cluster_nodes(product),
             timeout_seconds=CLUSTER_TIMEOUT_SECONDS),
        Case(WORKER_STATE_CASE_ID, "multi-node", lambda context: case_worker_state(product),
             timeout_seconds=WORKER_STATE_TIMEOUT_SECONDS),
        Case(WORKER_CONFIG_CASE_ID, "multi-node", lambda context: case_worker_config(product),
             timeout_seconds=WORKER_STATE_TIMEOUT_SECONDS),
    ]
