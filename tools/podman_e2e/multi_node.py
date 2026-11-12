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
from typing import Any, Dict, List, Optional, Sequence

from tools.podman_e2e import aio, matrix as matrix_data, mtls, topology
from tools.podman_e2e.podman import wait_until
from tools.podman_e2e.runner import Case, CaseBlocked, require

INSTALL_CASE_ID = "MN-INSTALL"
NODE_ADD_CASE_ID = "WRK-04"
MASTER_ADDRESS_CASE_ID = "PODNET-MASTER-ADDR"
MTLS_TIMEOUT_SECONDS = 300

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
    ]
