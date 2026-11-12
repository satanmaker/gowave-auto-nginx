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

from typing import Any, Dict, List, Optional, Sequence

from tools.podman_e2e import aio, matrix as matrix_data, topology
from tools.podman_e2e.podman import wait_until
from tools.podman_e2e.runner import Case, CaseBlocked, require

INSTALL_CASE_ID = "MN-INSTALL"
NODE_ADD_CASE_ID = "WRK-04"
MASTER_ADDRESS_CASE_ID = "PODNET-MASTER-ADDR"

NODE_ADD_TIMEOUT_SECONDS = topology.NODE_ADD_TIMEOUT_SECONDS
NODE_HEALTH_TIMEOUT_SECONDS = 600
NODE_HEALTH_INTERVAL_SECONDS = 5

NODE_PORT = 3002

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
        host = peer.rsplit(":", 1)[0]
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
        core = len(matrix_data.inbounds(self.matrix, vision=False))
        extra = len(matrix_data.inbounds(self.matrix, vision=True)) - core
        return 2 * core + (extra if self.vision else 0) + (extra if self.worker_vision else 0)

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
        evidence = self.master.install(host=host)
        self.topology = host
        self.trust = host.pin_worker_trust()
        evidence.update({
            "roles": {
                "control": host.client_name,
                "master": host.target_name,
                "worker": host.worker_name,
                "untrusted": host.untrusted_name,
            },
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
    ]
