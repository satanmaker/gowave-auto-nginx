"""Disposable Podman topology for the All-in-One product E2E.

The host, its resolver, and its ACME directory are all run-scoped containers on
a private control network. The operator under test sees an ordinary fresh VPS:
it installs its own packages, manages its own systemd units, and requests a
certificate from the pinned fixture endpoint. Nothing on the workstation (or on
any real host) is touched.

A second, internal network carries the addresses the product is asked to reach
as if they were on the public internet, because it forwards only destinations it
reads as public (see the notes on ``DATA_PREFIX_CANDIDATES``). Both subnets are
allocated at run time instead of hard-coded: ``podman network create`` fails
when a candidate /24 overlaps a network the workstation already has (a previous
suite run, a developer network, a VPN), so the plan walks a fixed candidate
range per network and picks the first free block. Addresses inside each block
are fixed offsets, so a case can still assert which node answered a connection,
and on which of its two addresses. The private-address override handed to the
operator is the same narrow, test-only path the installer already validates.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

from tools.podman_e2e import acme_fixture, client_image, target_image

# Two networks, because one block cannot satisfy both ends of the run.
#
# The control network is private: the product resolves its own address through a
# test-only override that refuses anything but a private address (so an operator
# can never pass a public IP off as a NAT-ed host), and every fixture, both
# probes, and the ACME directory live on it.
CONTROL_PREFIX_CANDIDATES = ("10.89.0.0/24", "10.90.0.0/24", "10.91.0.0/24")

# The data network must carry real public addresses, because two independent
# guards otherwise swallow the payload before it can prove egress:
#   * the node's routing sends private and loopback destinations to its block
#     outbound, so a payload addressed into 10/8 returns 503 and never leaves;
#   * the engine's freedom outbound applies an implicit final rule for
#     vless/trojan/shadowsocks inbounds that blackholes every destination the
#     IANA special-purpose registry lists (RFC 5737 documentation blocks,
#     198.18.0.0/15 benchmarking, 240.0.0.0/4 reserved, multicast), and a
#     blackholed stream is drained until the block duration expires, so the
#     client hangs instead of failing fast. Pinning this against Xray 26.11.9
#     cost a full debugging pass: proxy/freedom getDefaultFinalRule returns
#     defaultBlockPrivateRule -> geodata.GetPrivateIPMatcher.
# Candidates are therefore global unicast space, which both guards forward. The
# data network is created internal, so it is a bridge with a connected route and
# no gateway: the node's dial is delivered locally and there is no route by which
# a packet addressed into the block could leave the workstation, even though the
# bytes look routable. Each candidate sits next to a documentation block so it is
# easy to recognise in an evidence file, and the allocator skips any block the
# workstation or another Podman network already claims.
DATA_PREFIX_CANDIDATES = ("203.0.114.0/24", "198.51.101.0/24", "192.0.3.0/24")

DNS_OFFSET = 53
TARGET_OFFSET = 10
PEBBLE_OFFSET = 20
ECHO_OFFSET = 30
CLIENT_OFFSET = 40
# The engine client runs the real xray/mihomo binaries; it is a second, distinct
# role from the standard-library Control Machine above.
ENGINE_CLIENT_OFFSET = 41
# Multi-Node roles. The Worker is a second installed node, so it needs its own
# control and data-plane addresses: sharing the Master's would make the run
# unable to tell which node a payload actually left from.
WORKER_OFFSET = 11
UNTRUSTED_OFFSET = 44

DNS_PORT = 53
DNS_ZONE_TTL = 30
DNS_ZONE_SUFFIX = "testbed.internal"
HOST_RESOLV_CONF = Path("/etc/resolv.conf")
# Where a stub-listener host keeps the servers it forwards to. Only consulted
# when /etc/resolv.conf itself yields nothing usable.
SYSTEMD_UPSTREAM_RESOLV_CONFS = (
    Path("/run/systemd/resolve/resolv.conf"),
    Path("/run/resolvconf/resolv.conf"),
)

FIXTURE_IMAGE = "fixture-echo"
DNS_FIXTURE_SCRIPT = "/repo/tests/fixtures/dns_server.py"
ECHO_FIXTURE_SCRIPT = "/repo/tests/fixtures/echo_server.py"
DNS_QUERY_LOG_NAME = "queries.jsonl"
DNS_ZONE_NAME = "zone.json"
REPO_IN_CONTAINER = "/repo"
CA_MOUNT = "/fixtures/ca"
CA_FILE_NAME = "fixture-ca.crt"
ISSUED_ROOT_NAME = "issued-root.pem"
# The product uses one pinned CA file for both jobs: trusting the ACME endpoint
# itself and verifying that an existing lineage is its own. Pebble serves its
# HTTPS endpoint under the fixture root while it issues certificates under its
# own root, so a single root would fail one of the two on the second install.
ACME_CA_BUNDLE_NAME = "acme-trust.pem"
ECHO_MOUNT = "/fixtures/echo"
ECHO_HTTP_PORT = 18080
ECHO_HTTPS_PORT = 18443
ECHO_CERT_NAME = "echo.crt"
ECHO_KEY_NAME = "echo.key"

PANEL_DOMAIN = "panel.testbed.internal"
REALITY_DOMAIN = "reality.testbed.internal"
VISION_DOMAIN = "vision.testbed.internal"
COVER_APEX = "testbed.internal"
# A name the run resolves into the host but the product was never configured
# with. Probing it is what a scan of the address looks like: the stream map has
# no entry for it, so it is answered by the REALITY fallback rather than by any
# vhost the operator asked for.
PROBE_UNMAPPED_SNI = "probe.testbed.internal"
ECHO_HOST = "echo.testbed.internal"
CLIENT_HOST = "client.testbed.internal"
# The Worker owns its names as well: the operator is asked for a Worker domain
# and a REALITY domain per node, and the matrix identifies a Multi-Node tuple by
# the node whose SNI it dials.
WORKER_DOMAIN = "worker.testbed.internal"
WORKER_REALITY_DOMAIN = "worker-reality.testbed.internal"
WORKER_VISION_DOMAIN = "worker-vision.testbed.internal"
# The node name the operator registers the Worker under; the Panel reports it
# back, so the cases match the registered node instead of counting nodes.
WORKER_NODE_NAME = "worker-1"

# The product reads the kernel, not a flag, to decide whether it publishes IPv6
# listeners and mirrors its firewall rules onto ip6tables. A run that has to
# exercise the enabled branch therefore has to hand one host an IPv6 stack: the
# kernel restores its own ::1 on loopback as soon as the interface's IPv6 is
# switched back on, and the clean image ships neither ``ip`` nor ``sysctl``, so
# the switch is written straight to /proc/sys with a shell builtin.
IPV6_HOST_ADDRESS = "::1"
ENABLE_IPV6_SCRIPT = """
set -eu
echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6
echo 0 > /proc/sys/net/ipv6/conf/lo/disable_ipv6
readarray -t addresses < /proc/net/if_inet6
[ "${#addresses[@]}" -gt 0 ]
"""
DISABLE_IPV6_SCRIPT = """
set -eu
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
echo 1 > /proc/sys/net/ipv6/conf/lo/disable_ipv6
"""

# The probe the client role runs: standard library only, so its verdict cannot
# depend on anything the product installed.
HTTP_PROBE_SCRIPT = f"{REPO_IN_CONTAINER}/tools/podman_e2e/http_probe.py"
# The probe the engine role runs: it consumes the Panel payloads with the pinned
# client binaries and reports facts only.
SUBSCRIPTION_PROBE_SCRIPT = f"{REPO_IN_CONTAINER}/tools/podman_e2e/subscription_probe.py"
# The probe that sends payloads through the served outbounds with the same
# binaries, from the same role.
TRAFFIC_PROBE_SCRIPT = f"{REPO_IN_CONTAINER}/tools/podman_e2e/traffic_probe.py"
# The probe that reads DNS answers either from the fixture itself or through the
# role's own resolution path, so both vantages are measured with the same code.
DNS_PROBE_SCRIPT = f"{REPO_IN_CONTAINER}/tools/podman_e2e/dns_probe.py"
DNS_PROBE_TIMEOUT_SECONDS = 60
# Payloads are fetched on the host (the subscription routes are loopback-only)
# and mounted into the engine container; they are never printed or copied into
# the artifact directory.
PAYLOAD_MOUNT = "/payloads"
SECRETS_MOUNT = "/secrets"
# Where the product keeps its unencrypted archives: a run-owned volume, removed
# by the same label the rest of the run's resources are removed by.
BACKUP_STORE = "/var/backups/gowave"

INSTALL_TIMEOUT_SECONDS = 5400


class TopologyError(RuntimeError):
    pass


@dataclass(frozen=True)
class NetworkPlan:
    """Two /24s with the fixed host offsets the fixtures occupy inside them.

    ``subnet`` reaches the product and every fixture; ``data_subnet`` carries the
    public address the data plane is asked to reach, so the two roles that touch
    it (the installed host and the endpoint, plus the engine client that
    calibrates the source attribution) need that block and nothing else.
    """

    subnet: str
    data_subnet: str = DATA_PREFIX_CANDIDATES[0]

    def _address(self, host: int, network_block: str = "") -> str:
        network = ipaddress.ip_network(network_block or self.subnet, strict=False)
        return str(network.network_address + host)

    @property
    def dns_ip(self) -> str:
        return self._address(DNS_OFFSET)

    @property
    def target_ip(self) -> str:
        return self._address(TARGET_OFFSET)

    @property
    def pebble_ip(self) -> str:
        return self._address(PEBBLE_OFFSET)

    @property
    def echo_ip(self) -> str:
        return self._address(ECHO_OFFSET)

    @property
    def client_ip(self) -> str:
        return self._address(CLIENT_OFFSET)

    @property
    def engine_client_ip(self) -> str:
        return self._address(ENGINE_CLIENT_OFFSET)

    @property
    def data_target_ip(self) -> str:
        return self._address(TARGET_OFFSET, self.data_subnet)

    @property
    def worker_ip(self) -> str:
        return self._address(WORKER_OFFSET)

    @property
    def data_worker_ip(self) -> str:
        return self._address(WORKER_OFFSET, self.data_subnet)

    @property
    def untrusted_ip(self) -> str:
        return self._address(UNTRUSTED_OFFSET)

    @property
    def data_echo_ip(self) -> str:
        return self._address(ECHO_OFFSET, self.data_subnet)

    @property
    def data_engine_client_ip(self) -> str:
        return self._address(ENGINE_CLIENT_OFFSET, self.data_subnet)


def _overlaps(candidate: ipaddress.IPv4Network, used: Sequence[str]) -> bool:
    for entry in used:
        try:
            network = ipaddress.ip_network(str(entry), strict=False)
        except ValueError:
            continue
        if candidate.version == network.version and candidate.overlaps(network):
            return True
    return False


def _first_free(candidates: Sequence[str], used_subnets: Sequence[str], role: str) -> str:
    for candidate in candidates:
        network = ipaddress.ip_network(candidate, strict=False)
        if not _overlaps(network, used_subnets):
            return str(network)
    raise TopologyError(
        f"no free /24 left in {', '.join(candidates)} for the {role} network"
    )


def allocate_plan(used_subnets: Sequence[str]) -> NetworkPlan:
    """Pick one free /24 per network, avoiding what the host already claims."""
    return NetworkPlan(
        subnet=_first_free(CONTROL_PREFIX_CANDIDATES, used_subnets, "control"),
        data_subnet=_first_free(DATA_PREFIX_CANDIDATES, used_subnets, "data"),
    )


def egress_resolvers(
    resolv_conf: Path = HOST_RESOLV_CONF,
    upstreams: Sequence[Path] = SYSTEMD_UPSTREAM_RESOLV_CONFS,
) -> List[str]:
    """Real resolvers the disposable host may use for names outside the fixture zone.

    The fixture answers its own zone authoritatively and refuses everything else,
    so the target falls through to these servers for package mirrors and release
    downloads exactly like a fresh VPS. Loopback entries are dropped: a stub
    listener such as systemd-resolved's 127.0.0.53 exists on the host and not
    inside the container, so handing it over would leave the target unable to
    resolve anything. A host that answers with nothing but stubs is therefore
    followed to the upstream list kept beside them (`upstreams`); the file the
    caller named is still read first, so a real address there wins.
    """
    for candidate in (resolv_conf, *upstreams):
        try:
            text = candidate.read_text(encoding="utf-8")
        except OSError:
            continue
        resolvers: List[str] = []
        for line in text.splitlines():
            fields = line.split()
            if len(fields) >= 2 and fields[0] == "nameserver":
                address = fields[1]
                if address.startswith("127.") or address.startswith("169.254.") or address == "::1":
                    continue
                if address not in resolvers:
                    resolvers.append(address)
        if resolvers:
            return resolvers
    return []


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def zone(plan: NetworkPlan) -> Dict[str, Any]:
    """Authoritative zone: every name the operator may resolve points into the run."""
    return {
        "ttl": DNS_ZONE_TTL,
        "records": {
            PANEL_DOMAIN: {"A": [plan.target_ip]},
            REALITY_DOMAIN: {"A": [plan.target_ip]},
            VISION_DOMAIN: {"A": [plan.target_ip]},
            COVER_APEX: {"A": [plan.target_ip]},
            f"www.{COVER_APEX}": {"A": [plan.target_ip]},
            PROBE_UNMAPPED_SNI: {"A": [plan.target_ip]},
            acme_fixture.FIXTURE_HOST: {"A": [plan.pebble_ip]},
            ECHO_HOST: {"A": [plan.echo_ip]},
            CLIENT_HOST: {"A": [plan.client_ip]},
        },
        "behavior": {"mode": "answer", "delay_ms": 0},
    }


def dns_command(zone_path: str, log_path: str, out_of_zone: str = "refused") -> Sequence[str]:
    return (
        "python3", DNS_FIXTURE_SCRIPT,
        "--listen", "0.0.0.0",
        "--port", str(DNS_PORT),
        "--zone", zone_path,
        "--log", log_path,
        "--suffix", DNS_ZONE_SUFFIX,
        "--out-of-zone", out_of_zone,
    )


@dataclass
class InstallOutcome:
    returncode: int
    stdout: str
    stderr: str
    duration: float
    command: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def tail(self, limit: int = 4000) -> str:
        combined = (self.stdout + "\n" + self.stderr).strip()
        return combined[-limit:]


@dataclass
class AioTopology:
    """One disposable AIO host plus its resolver and ACME fixtures."""

    podman: Any
    distribution: str = "ubuntu-24.04"
    panel_domain: str = PANEL_DOMAIN
    reality_domain: str = REALITY_DOMAIN
    vision_domain: Optional[str] = None
    admin_email: str = "e2e@testbed.internal"
    plan: Optional[NetworkPlan] = None
    egress_resolvers: Optional[List[str]] = None
    started: List[str] = field(default_factory=list)
    acme: Optional[acme_fixture.AcmeFixture] = None
    _ca_dir: Optional[Path] = None
    _issued_root: str = ""
    _clean_facts: Dict[str, Any] = field(default_factory=dict)
    echo_dir: Optional[Path] = None
    dns_dir: Optional[Path] = None
    # Whether the disposable host stands in for a dual-stack VPS. Off by
    # default, because a plain IPv4 host is what most of the run measures; the
    # IPv6 case turns it on for the role it has to prove.
    ipv6_host: bool = False
    ipv6_address: str = field(default="", init=False)
    # The name the installed host's archive volume is recorded under.
    target_role: str = "aio"
    # The role's archive volume: the archives carry install-time secrets, so they
    # are kept on a run-owned volume the cleanup removes by its own label rather
    # than in the container layer or anywhere an artifact could reach them.
    backup_volumes: Dict[str, Dict[str, str]] = field(default_factory=dict)

    def _backup_volume(self, role: str) -> str:
        name = self.context.resource_name(f"backups-{role}")
        self.podman.volume_create(name)
        mountpoint = self.podman.volume_mountpoint(name)
        # Podman leaves a fresh volume world-readable; the archives are not
        # encrypted, so the volume itself is closed to everyone but root.
        os.chmod(mountpoint, 0o700)
        self.backup_volumes[role] = {"name": name, "mountpoint": str(mountpoint)}
        return name

    def __post_init__(self) -> None:
        target_image.distribution(self.distribution)
        self.context = self.podman.context
        self.network = self.context.resource_name("e2e-net")
        self.data_network = self.context.resource_name("e2e-data")
        self.dns_name = self.context.resource_name("dns")
        self.target_name = self.context.resource_name("aio")
        self.echo_name = self.context.resource_name("echo")
        self.client_name = self.context.resource_name("client")
        self.engine_client_name = self.context.resource_name("engines")
        self.payload_dir = self.context.secret_dir / "subscriptions"
        self._engine_image = ""
        if self.plan is None:
            self.plan = allocate_plan(self.podman.network_subnets())
        if self.egress_resolvers is None:
            self.egress_resolvers = egress_resolvers()

    # ------------------------------------------------------------------ setup
    def zone(self) -> Dict[str, Any]:
        """The fixture zone for every name this topology installs."""
        return zone(self.plan)

    def create(self) -> "AioTopology":
        if not self.egress_resolvers:
            consulted = ", ".join(
                str(path) for path in (HOST_RESOLV_CONF, *SYSTEMD_UPSTREAM_RESOLV_CONFS)
            )
            raise TopologyError(
                f"no egress resolver found in {consulted}; the disposable host could not install packages"
            )
        self.payload_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.podman.network_create(self.network, self.plan.subnet, disable_dns=True)
        self.podman.network_create(
            self.data_network, self.plan.data_subnet, disable_dns=True, internal=True,
        )
        self._start_dns()
        self._start_acme()
        self._start_target()
        self._start_echo()
        self._start_client()
        return self

    def _start_dns(self) -> None:
        directory = self.context.secret_dir / "dns"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.dns_dir = directory
        zone_path = directory / DNS_ZONE_NAME
        zone_path.write_text(json.dumps(self.zone(), sort_keys=True), encoding="utf-8")
        self.podman.run(
            name=self.dns_name,
            image_alias=FIXTURE_IMAGE,
            network=self.network,
            aliases=("dns.testbed.internal",),
            privileged=False,
            # Writable: cases rewrite the zone to steer answers and the fixture
            # appends its query log there.
            volumes=(f"{directory}:/fixtures/dns:Z",),
            command=dns_command(f"/fixtures/dns/{DNS_ZONE_NAME}", f"/fixtures/dns/{DNS_QUERY_LOG_NAME}"),
            systemd="false",
            extra_args=("--ip", self.plan.dns_ip),
        )
        self.started.append(self.dns_name)
        self.podman.wait_tcp(self.dns_name, "127.0.0.1", DNS_PORT, timeout_seconds=60)

    def dns_zone_file(self) -> Path:
        """The zone the fixture serves; rewriting it steers the next answer."""
        if self.dns_dir is None:
            raise TopologyError("the resolver fixture has not been started")
        return self.dns_dir / DNS_ZONE_NAME

    def dns_query_log(self) -> Path:
        """The fixture's own query log, which names the vantage each answer went to."""
        if self.dns_dir is None:
            raise TopologyError("the resolver fixture has not been started")
        return self.dns_dir / DNS_QUERY_LOG_NAME

    def write_dns_zone(self, data: Dict[str, Any]) -> None:
        """Replace the zone atomically; a query never reads a half-written file.

        The fixture reloads when the zone's mtime changes, so the replacement is
        given a fresh timestamp: a rewrite of the same size inside one clock tick
        would otherwise be served from the fixture's previous copy.
        """
        path = self.dns_zone_file()
        temporary = path.with_name(path.name + ".tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            handle.write(json.dumps(data, sort_keys=True))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        stamp = time.time_ns()
        os.utime(path, ns=(stamp, stamp))
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def dns_queries(self) -> List[Dict[str, Any]]:
        """Every query the fixture has recorded, newest last."""
        try:
            text = self.dns_query_log().read_text(encoding="utf-8")
        except FileNotFoundError:
            return []
        events: List[Dict[str, Any]] = []
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events

    def dns_probe(
        self, container: str, scope: str, queries: Sequence[str] = (), names: Sequence[str] = (),
        timeout: int = DNS_PROBE_TIMEOUT_SECONDS,
    ) -> Any:
        """Run the DNS probe inside one role and return the completed process."""
        argv = ["python3", DNS_PROBE_SCRIPT, "--scope", scope]
        if scope == "direct":
            argv += ["--server", str(self.plan.dns_ip), "--port", str(DNS_PORT)]
        for query in queries:
            argv += ["--query", query]
        for name in names:
            argv += ["--name", name]
        return self.podman.exec(container, argv, check=False, timeout=timeout)

    def _start_acme(self) -> None:
        self.acme = acme_fixture.AcmeFixture(
            self.podman,
            self.network,
            extra_args=("--ip", self.plan.pebble_ip, "--dns", self.plan.dns_ip),
            management_host_port=free_loopback_port(),
        )
        self.acme.start()
        self.started.append(self.acme.name)
        self.acme.wait_ready(timeout_seconds=120)

    def _start_target(self) -> None:
        image_tag = target_image.build(self.podman, self.distribution)
        self._ca_dir = self.context.secret_dir / "client-ca"
        self._ca_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        ca_file = self._ca_dir / CA_FILE_NAME
        ca_file.write_text(self.acme.ca_file().read_text(encoding="utf-8"), encoding="utf-8")
        ca_file.chmod(0o644)
        self._issued_root = self.acme.issued_root()
        issued = self._ca_dir / ISSUED_ROOT_NAME
        issued.write_text(self._issued_root, encoding="utf-8")
        issued.chmod(0o644)
        bundle = self._ca_dir / ACME_CA_BUNDLE_NAME
        bundle.write_text(
            ca_file.read_text(encoding="utf-8").rstrip("\n") + "\n" + self._issued_root.strip() + "\n",
            encoding="utf-8",
        )
        bundle.chmod(0o644)

        self.podman.run(
            name=self.target_name,
            image_alias=image_tag,
            network=self.network,
            aliases=(self.panel_domain,),
            privileged=True,
            volumes=(
                f"{self._ca_dir}:{CA_MOUNT}:ro,Z",
                # The subscription routes are loopback-only, so the payloads are
                # fetched on the host and handed to the engine client from here.
                f"{self.payload_dir}:{PAYLOAD_MOUNT}:Z",
                # The product writes its archives here; a run-owned volume keeps
                # them out of the container layer and out of every artifact.
                f"{self._backup_volume(self.target_role)}:{BACKUP_STORE}:Z",
            ),
            environment=self.install_environment(),
            systemd="always",
            extra_args=(
                "--ip", self.plan.target_ip,
                "--dns", self.plan.dns_ip,
                *[option for resolver in self.egress_resolvers for option in ("--dns", resolver)],
            ),
        )
        self.started.append(self.target_name)
        self.podman.wait_systemd(self.target_name, timeout_seconds=180)
        # The public address the data plane dials out from, added after start so
        # the container keeps the private default route it installs packages over.
        self.podman.network_connect(self.target_name, self.data_network, ip=self.plan.data_target_ip)
        self._clean_facts = target_image.assert_clean(self.podman, self.target_name)
        if self.ipv6_host:
            self._enable_ipv6(self.target_name)
            self.ipv6_address = IPV6_HOST_ADDRESS

    def _enable_ipv6(self, container: str) -> None:
        """Turn one role's IPv6 stack back on, before its install runs.

        The product decides from ``/proc/net/if_inet6`` and the kernel's own
        ``disable_ipv6`` switch whether it publishes ``[::]`` listeners and
        mirrors its firewall decisions onto ip6tables, so the enabled branch is
        only reachable if the role has IPv6 before the operator installs. The
        kernel restores ``::1`` on loopback by itself; nothing is added to the
        run network, and the products that are published are proven by their
        wildcard ``[::]`` bind rather than by this address.
        """
        self.podman.exec_bash(container, ENABLE_IPV6_SCRIPT, timeout=120)
        proc = self.podman.exec(
            container, ["cat", "/proc/net/if_inet6"], check=False, timeout=60,
        )
        addresses = [line.split()[0] for line in (proc.stdout or "").splitlines() if line.strip()]
        if not addresses:
            raise TopologyError(
                f"{container} reports no IPv6 address after enabling it, so the product would "
                "still take its IPv4-only branch"
            )
        expected = ipaddress.ip_address(IPV6_HOST_ADDRESS).exploded.replace(":", "")
        if expected not in [address.lower() for address in addresses]:
            raise TopologyError(
                f"{container} did not keep {IPV6_HOST_ADDRESS}: it reports {addresses}"
            )

    def _start_echo(self) -> None:
        """The controlled endpoint the data plane has to reach.

        It is on the run network with its own address, so what it records about a
        request — the request id, the body digest, and the source address — is the
        only evidence that a payload actually travelled: a client that never
        connected cannot make it record anything.
        """
        if self._ca_dir is None or self.acme is None or self.acme.ca is None:
            raise TopologyError("the echo fixture needs the fixture CA, which the target start creates")
        leaf = acme_fixture.generate_leaf(
            self.acme.ca.directory, "echo", ("DNS:" + ECHO_HOST,),
        )
        for source, name in ((leaf["cert"], ECHO_CERT_NAME), (leaf["key"], ECHO_KEY_NAME)):
            destination = self._ca_dir / name
            destination.write_bytes(source.read_bytes())
            destination.chmod(0o644)
        directory = self.context.secret_dir / "echo"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.echo_dir = directory
        self.podman.run(
            name=self.echo_name,
            image_alias=FIXTURE_IMAGE,
            network=self.network,
            aliases=(ECHO_HOST,),
            privileged=False,
            volumes=(
                f"{self._ca_dir}:{CA_MOUNT}:ro,Z",
                f"{directory}:{ECHO_MOUNT}:Z",
            ),
            command=(
                "python3", ECHO_FIXTURE_SCRIPT,
                "--http-port", str(ECHO_HTTP_PORT),
                "--https-port", str(ECHO_HTTPS_PORT),
                "--control", f"{ECHO_MOUNT}/control.json",
                "--log", f"{ECHO_MOUNT}/requests.jsonl",
                "--cert", f"{CA_MOUNT}/{ECHO_CERT_NAME}",
                "--key", f"{CA_MOUNT}/{ECHO_KEY_NAME}",
                *[
                    option
                    for source in self.echo_allow_sources()
                    for option in ("--allow-source", source)
                ],
            ),
            systemd="false",
            extra_args=(
                "--ip", self.plan.echo_ip,
                "--dns", self.plan.dns_ip,
            ),
        )
        self.started.append(self.echo_name)
        # Both faces: the private one the fixtures resolve, and the public one the
        # installed node is asked to reach through the tunnel it was issued.
        self.podman.network_connect(self.echo_name, self.data_network, ip=self.plan.data_echo_ip)
        self.podman.wait_tcp(self.echo_name, "127.0.0.1", ECHO_HTTP_PORT, timeout_seconds=60)

    def _start_client(self) -> None:
        """The Control Machine role: independent of the host it probes.

        It shares the run network so it can reach the host by name, but it has no
        product code, no product packages, and no product configuration: whatever
        it reports about the host comes from its own standard-library client.
        """
        self.podman.run(
            name=self.client_name,
            image_alias=FIXTURE_IMAGE,
            network=self.network,
            aliases=(CLIENT_HOST,),
            privileged=False,
            volumes=(f"{self._ca_dir}:{CA_MOUNT}:ro,Z",),
            command=("sleep", "infinity"),
            systemd="false",
            extra_args=(
                "--ip", self.plan.client_ip,
                "--dns", self.plan.dns_ip,
            ),
        )
        self.started.append(self.client_name)

    # ------------------------------------------------------------------ client
    def engine_client(self) -> str:
        """The engine role, started once per run and reused by every client case."""
        if not self._engine_image:
            self._start_engine_client()
        return self.engine_client_name

    def engine_hosts(self) -> Dict[str, str]:
        """The names the engines resolve, and the address each one has to reach.

        The served Mihomo template resolves proxy servers through public
        nameservers, which cannot answer for the run's private zone, so the names
        the Panel issued are pinned in the client container's hosts file. That is
        client-side name resolution in place of public DNS, not a rewrite of what
        the Panel served.
        """
        domains = [self.panel_domain, self.reality_domain]
        if self.vision_domain:
            domains.append(self.vision_domain)
        return {domain: str(self.plan.target_ip) for domain in domains}

    def subscription_domains(self) -> Dict[str, Set[str]]:
        """The names a client's subscription may address, and the ones it must.

        A share link dials one name and presents another: the TLS-carrying
        inbounds are addressed by the node's own public name, while a REALITY
        inbound is addressed by the same name and presents its own SNI. The
        Vision inbound is the exception that carries its own name in both, so a
        node is fully published only when every configured name appears on the
        side it belongs to.
        """
        allowed = set(self.engine_hosts())
        required_hosts = {self.panel_domain}
        required_snis = {self.reality_domain}
        if self.vision_domain:
            required_hosts.add(self.vision_domain)
            required_snis.add(self.vision_domain)
        return {"allowed": allowed, "required_hosts": required_hosts, "required_snis": required_snis}

    def node_names(self, node: str = "") -> Dict[str, str]:
        """The names one node is dialled by, and the SNI its REALITY inbound presents.

        A cluster serves the same transport/security pairs on both nodes, so a
        data-plane case has to say which node it means. The All-in-One topology
        is a single node, which the empty name and the explicit ``local`` both
        select.
        """
        if node not in ("", "local"):
            raise TopologyError(f"the All-in-One topology has one node, not {node!r}")
        return {
            "dial": self.panel_domain,
            "reality": self.reality_domain,
            "vision": self.vision_domain or "",
        }

    def node_data_ip(self, node: str = "") -> str:
        """The source address traffic through this node's inbounds has to leave from."""
        if node not in ("", "local"):
            raise TopologyError(f"the All-in-One topology has one node, not {node!r}")
        return str(self.plan.data_target_ip)

    def echo_allow_sources(self) -> List[str]:
        """The only node identities the endpoint accepts a payload from.

        The endpoint sits outside the product, so the source address it records
        is the one piece of evidence a client cannot supply: the harness reads it
        back to attribute a transfer to a node. Accepting a payload from anyone
        else would make a direct client connection indistinguishable from product
        traffic, so the fixture refuses every other source by name.
        """
        return [str(self.plan.data_target_ip)]

    def _start_engine_client(self) -> None:
        """Start the pinned client engines, with no product code in the container.

        The payload directory is mounted read-only: the Panel's subscription
        routes are loopback-only, so the host fetches them and the engines
        consume exactly the bytes the Panel served.

        The Panel's own names are pinned in the container's hosts file because the
        served Mihomo template resolves proxy servers through public nameservers,
        which cannot answer for the run's private zone. That is client-side name
        resolution in place of public DNS, not a rewrite of what the Panel issued:
        the outbound fields stay exactly as served.
        """
        self._engine_image = client_image.build(self.podman)
        self.podman.run(
            name=self.engine_client_name,
            image_alias=self._engine_image,
            network=self.network,
            privileged=False,
            volumes=(
                f"{self.payload_dir}:{SECRETS_MOUNT}:ro,Z",
                f"{self._ca_dir}:{CA_MOUNT}:ro,Z",
            ),
            command=("sleep", "infinity"),
            systemd="false",
            extra_args=(
                "--ip", self.plan.engine_client_ip,
                "--dns", self.plan.dns_ip,
                *[
                    option
                    for name, address in self.engine_hosts().items()
                    for option in ("--add-host", f"{name}:{address}")
                ],
            ),
        )
        self.started.append(self.engine_client_name)
        # The control transfer has to address the same literal the tunnel does, so
        # the source each one leaves behind is a like-for-like comparison.
        self.podman.network_connect(
            self.engine_client_name, self.data_network, ip=self.plan.data_engine_client_ip,
        )

    def subscription_facts(self, scope: str, timeout: int = 300) -> Any:
        """Run the engine-side subscription probe and return the completed process."""
        self.engine_client()
        return self.podman.exec(
            self.engine_client_name,
            [
                "python3", SUBSCRIPTION_PROBE_SCRIPT,
                "--scope", scope,
                "--payload-dir", SECRETS_MOUNT,
                "--ca", f"{CA_MOUNT}/{ISSUED_ROOT_NAME}",
            ],
            check=False,
            timeout=timeout,
        )

    def traffic_facts(
        self, scope: str, timeout: int = 900, payload_dir: Optional[str] = None,
    ) -> Any:
        """Run the engine-side traffic probe against the controlled endpoint.

        The destination is the endpoint's public address, not the private one the
        fixtures resolve: both of the product's guards pass a global destination
        and would drop or blackhole a private one.

        ``payload_dir`` selects which captured subscription the engines consume;
        the revoked-access case replays a payload the Panel issued before the
        revocation, which is not the current one.
        """
        self.engine_client()
        return self.podman.exec(
            self.engine_client_name,
            [
                "python3", TRAFFIC_PROBE_SCRIPT,
                "--scope", scope,
                "--payload-dir", payload_dir or SECRETS_MOUNT,
                "--ca", f"{CA_MOUNT}/{ISSUED_ROOT_NAME}",
                "--destination", f"{self.plan.data_echo_ip}:{ECHO_HTTP_PORT}",
            ],
            check=False,
            timeout=timeout,
        )

    def transfer_facts(
        self, engine: str, network: str, security: str, timeout: int = 300, host: str = "",
        expect_refusal: bool = False,
    ) -> Any:
        """Run one matrix tuple: one client through one inbound, to the endpoint.

        The tuple is named by the transport and security layer the matrix
        declares, not by an outbound tag: the Panel tags every host outbound
        ``proxy``, so only the transport pair identifies the inbound the client
        was issued.

        ``host`` names the node the tuple belongs to. A cluster serves the same
        transport/security pair on both nodes, so without it the probe would run
        the Master's outbound and call it the Worker's.

        ``expect_refusal`` turns a refused connection into the returned result,
        which is how a case observes a node that was deliberately taken down.
        """
        self.engine_client()
        return self.podman.exec(
            self.engine_client_name,
            [
                "python3", TRAFFIC_PROBE_SCRIPT,
                "--scope", "transfer",
                "--payload-dir", SECRETS_MOUNT,
                "--ca", f"{CA_MOUNT}/{ISSUED_ROOT_NAME}",
                "--destination", f"{self.plan.data_echo_ip}:{ECHO_HTTP_PORT}",
                "--engine", engine,
                "--network", network,
                "--security", security,
                *(["--host", host] if host else []),
                *(["--expect-refusal"] if expect_refusal else []),
            ],
            check=False,
            timeout=timeout,
        )

    def direct_egress_facts(self, vantage: str, timeout: int = 300) -> Any:
        """Send one payload straight at the endpoint from a client role.

        ``vantage`` names the container the attempt leaves from — the Control
        Machine or the pinned-engine client. Neither owns a node identity, so the
        endpoint has to refuse the payload by source; the probe reports the
        refusal, the recorded denials and the sources of the payloads the
        endpoint did accept.
        """
        if vantage == "control":
            container = self.client_name
        elif vantage == "engine":
            container = self.engine_client()
        else:
            raise TopologyError(f"the topology has no client vantage {vantage!r}")
        return self.podman.exec(
            container,
            [
                "python3", TRAFFIC_PROBE_SCRIPT,
                "--scope", "direct",
                "--ca", f"{CA_MOUNT}/{ISSUED_ROOT_NAME}",
                "--destination", f"{self.plan.echo_ip}:{ECHO_HTTP_PORT}",
            ],
            check=False,
            timeout=timeout,
        )

    def prohibited_facts(self, timeout: int = 300) -> Any:
        """Run the policy probe: a permitted control, then a destination the product denies.

        The prohibited destination is the endpoint's private face, which the
        product's own routing sends to its block outbound, and the record is read
        from the public face, which the client reaches directly. A destination
        the product excludes can therefore only be proven denied by asking the
        endpoint what it did not receive.
        """
        self.engine_client()
        return self.podman.exec(
            self.engine_client_name,
            [
                "python3", TRAFFIC_PROBE_SCRIPT,
                "--scope", "prohibited",
                "--payload-dir", SECRETS_MOUNT,
                "--ca", f"{CA_MOUNT}/{ISSUED_ROOT_NAME}",
                "--destination", f"{self.plan.echo_ip}:{ECHO_HTTP_PORT}",
                "--report-destination", f"{self.plan.data_echo_ip}:{ECHO_HTTP_PORT}",
            ],
            check=False,
            timeout=timeout,
        )

    def client_http(
        self,
        url: str,
        expect_status: Optional[int] = None,
        expect_body: Optional[str] = None,
        expect_absent: Optional[str] = None,
        expect_san: Sequence[str] = (),
        headers: Sequence[str] = (),
        method: str = "GET",
        body: Optional[str] = None,
        insecure: bool = False,
        timeout: int = 30,
        min_tls: str = "",
        max_tls: str = "",
        anchor: bool = True,
    ) -> Dict[str, Any]:
        """Fetch a URL from the Control Machine role and return the probe report.

        The probe trusts the run CA only, so a certificate the product obtained
        from the fixture directory is the only one that can pass. ``anchor=False``
        withholds that CA, which is how a case proves the anchor is what made the
        handshake succeed rather than the client's own store.
        """
        argv = [
            "python3", HTTP_PROBE_SCRIPT,
            "--url", url,
            "--timeout", str(timeout),
            "--method", method,
        ]
        if insecure:
            argv.append("--insecure")
        elif anchor:
            argv += ["--ca", f"{CA_MOUNT}/{ISSUED_ROOT_NAME}"]
        if min_tls:
            argv += ["--min-tls", min_tls]
        if max_tls:
            argv += ["--max-tls", max_tls]
        if expect_status is not None:
            argv += ["--expect-status", str(expect_status)]
        if expect_body is not None:
            argv += ["--expect-body", expect_body]
        if expect_absent is not None:
            argv += ["--expect-absent", expect_absent]
        for san in expect_san:
            argv += ["--expect-san", san]
        for header in headers:
            argv += ["--header", header]
        if body is not None:
            argv += ["--body", body]
        proc = self.podman.exec(self.client_name, argv, check=False, timeout=timeout + 30)
        report: Dict[str, Any] = {
            "url": url,
            "returncode": proc.returncode,
            "stdout": (proc.stdout or "").strip(),
            "stderr": (proc.stderr or "").strip(),
        }
        try:
            parsed = json.loads(report["stdout"]) if report["stdout"] else {}
        except json.JSONDecodeError:
            parsed = {}
        report["probe"] = parsed
        return report

    # ----------------------------------------------------------------- install
    def install_environment(self) -> Dict[str, str]:
        ca_file = f"{CA_MOUNT}/{ACME_CA_BUNDLE_NAME}"
        bundle = self._ca_dir / ACME_CA_BUNDLE_NAME if self._ca_dir else None
        return {
            "GOWAVE_ACME_SERVER": acme_fixture.ACME_DIRECTORY_URL,
            "GOWAVE_ACME_TEST_MODE": "1",
            "GOWAVE_ACME_TEST_CA_FILE": ca_file,
            "GOWAVE_ACME_TEST_CA_SHA256": (
                acme_fixture.ca_file_sha256(bundle) if bundle is not None and bundle.is_file() else ""
            ),
            "GOWAVE_TLS_CA_FILE": f"{CA_MOUNT}/{ISSUED_ROOT_NAME}",
            "GOWAVE_PODMAN_TEST_MODE": "1",
            "GOWAVE_PODMAN_MASTER_ADDRESS": self.plan.target_ip,
            "GOWAVE_PODMAN_NETWORK_CIDR": self.plan.subnet,
            "DEBIAN_FRONTEND": "noninteractive",
        }

    def install_script(self) -> str:
        arguments = [self.panel_domain, self.reality_domain, self.admin_email]
        if self.vision_domain:
            arguments.append(self.vision_domain)
        quoted = " ".join(f"'{value}'" for value in arguments)
        return f"bash {REPO_IN_CONTAINER}/gowave-auto.sh install {quoted}"

    def install(self) -> InstallOutcome:
        """Run the real operator install, unmodified, inside the target."""
        return self._install("aio-install")

    def reinstall(self) -> InstallOutcome:
        """Run the same operator command again against the already installed host.

        The product documents installation as repeatable, so this is the operator's
        own command rather than a second entry point. The two runs keep separate
        evidence files so the second cannot overwrite what the first recorded.
        """
        return self._install("aio-reinstall")

    def _install(self, evidence_prefix: str) -> InstallOutcome:
        script = self.install_script()
        started = time.monotonic()
        proc = self.podman.exec_bash(
            self.target_name, script, check=False, timeout=INSTALL_TIMEOUT_SECONDS,
        )
        outcome = InstallOutcome(
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            duration=time.monotonic() - started,
            command=script,
        )
        self.context.evidence_text(f"{evidence_prefix}.stdout.log", outcome.stdout)
        self.context.evidence_text(f"{evidence_prefix}.stderr.log", outcome.stderr)
        return outcome

    def install_must_succeed(self) -> InstallOutcome:
        outcome = self.install()
        if not outcome.ok:
            raise TopologyError(
                f"the operator full install failed with exit {outcome.returncode} after "
                f"{outcome.duration:.0f}s:\n{outcome.tail()}"
            )
        return outcome

    # ---------------------------------------------------------------- evidence
    def evidence(self, outcome: Optional[InstallOutcome] = None) -> Dict[str, Any]:
        record: Dict[str, Any] = {
            "distribution": self.distribution,
            "network": self.network,
            "subnet": self.plan.subnet,
            "target_ip": self.plan.target_ip,
            "target_container": self.target_name,
            "data_network": self.data_network,
            "data_subnet": self.plan.data_subnet,
            "data_target_ip": self.plan.data_target_ip,
            "data_echo_ip": self.plan.data_echo_ip,
            "client_ip": self.plan.client_ip,
            "client_container": self.client_name,
            "panel_domain": self.panel_domain,
            "reality_domain": self.reality_domain,
            "vision_domain": self.vision_domain or "",
            "acme_endpoint": acme_fixture.ACME_DIRECTORY_URL,
            "acme_fixture": self.acme.evidence() if self.acme else {},
            "resolvers": {
                "fixture": self.plan.dns_ip,
                "fixture_zone": DNS_ZONE_SUFFIX,
                "egress": list(self.egress_resolvers or []),
            },
            "pre_install": self._clean_facts,
            "images_resolved": dict(self.context.environment.get("images_resolved") or {}),
        }
        if outcome is not None:
            record.update({
                "install_returncode": outcome.returncode,
                "install_duration_seconds": round(outcome.duration, 1),
                "install_command": outcome.command,
            })
        return record


NODE_ADD_TIMEOUT_SECONDS = 5400
WORKER_SSH_SETUP_SCRIPT = r"""
set -eu
umask 077
mkdir -p /root/.ssh
chmod 0700 /root/.ssh
# A shared test image is built once, so its host keys are identical in every
# container it starts. Real VPS hosts are not, and the trust cases depend on
# telling one node's key from another's.
rm -f /etc/ssh/ssh_host_*
ssh-keygen -A >/dev/null
systemctl restart ssh.service
"""


@dataclass
class MultiNodeTopology(AioTopology):
    """One Master, one Worker, the Control Machine, and an untrusted client.

    The Master is the All-in-One host: the operator installs Panel, the local
    GoWave Node, NGINX and Xray there through the same command the All-in-One
    suite uses. The Worker is a *separate* clean systemd host, provisioned only
    through the operator's real ``gowave-auto.sh node add`` path, so nothing in
    the harness reproduces a product installation step.
    """

    worker_domain: str = WORKER_DOMAIN
    worker_reality_domain: str = WORKER_REALITY_DOMAIN
    worker_vision_domain: Optional[str] = None
    # The Master runs with its IPv6 stack switched on and the Worker without one,
    # so a single run covers both branches the product can take. The split is
    # declared here rather than inherited from whatever the container runtime
    # happens to enable.
    ipv6_host: bool = True
    target_role: str = "master"

    def __post_init__(self) -> None:
        super().__post_init__()
        self.worker_name = self.context.resource_name("worker")
        self.untrusted_name = self.context.resource_name("untrusted")

    def zone(self) -> Dict[str, Any]:
        """The base zone plus the Worker's own names, which only this topology has."""
        data = zone(self.plan)
        records = data["records"]
        records[self.worker_domain] = {"A": [self.plan.worker_ip]}
        records[self.worker_reality_domain] = {"A": [self.plan.worker_ip]}
        if self.worker_vision_domain:
            records[self.worker_vision_domain] = {"A": [self.plan.worker_ip]}
        return data

    def worker_domains(self) -> Set[str]:
        """The names the Worker is published under, if the run configured them."""
        return {
            domain for domain in (
                self.worker_domain, self.worker_reality_domain, self.worker_vision_domain,
            )
            if domain
        }

    def engine_hosts(self) -> Dict[str, str]:
        """The Master's names plus the Worker's, each pinned to the node serving it."""
        hosts = super().engine_hosts()
        for domain in self.worker_domains():
            hosts[domain] = str(self.plan.worker_ip)
        return hosts

    def subscription_domains(self) -> Dict[str, Set[str]]:
        """A subscription for this cluster has to publish the Worker, not just the Master."""
        domains = super().subscription_domains()
        domains["required_hosts"] = set(domains["required_hosts"]) | {self.worker_domain}
        domains["required_snis"] = set(domains["required_snis"]) | {self.worker_reality_domain}
        if self.worker_vision_domain:
            domains["required_hosts"].add(self.worker_vision_domain)
            domains["required_snis"].add(self.worker_vision_domain)
        return domains

    def node_names(self, node: str = "") -> Dict[str, str]:
        """The names the named node is dialled by, and the SNI its REALITY inbound presents.

        Both nodes carry the same inbounds, so the names are what tell their
        tuples apart: a Worker case that dialled the Master's name would prove
        the Master.
        """
        if node in ("", "master"):
            return super().node_names()
        if node == "worker":
            return {
                "dial": self.worker_domain,
                "reality": self.worker_reality_domain,
                "vision": self.worker_vision_domain or "",
            }
        raise TopologyError(f"the Multi-Node topology has a Master and a Worker, not {node!r}")

    def node_data_ip(self, node: str = "") -> str:
        """The source address the named node's inbounds have to leave from."""
        if node in ("", "master"):
            return super().node_data_ip()
        if node == "worker":
            return str(self.plan.data_worker_ip)
        raise TopologyError(f"the Multi-Node topology has a Master and a Worker, not {node!r}")

    def echo_allow_sources(self) -> List[str]:
        """Both node identities, and only those: the endpoint has two egress peers."""
        return [str(self.plan.data_target_ip), str(self.plan.data_worker_ip)]

    def create(self) -> "MultiNodeTopology":
        super().create()
        self._start_worker()
        self._start_untrusted_client()
        return self

    # ------------------------------------------------------------------ roles
    def roles(self) -> List[Dict[str, Any]]:
        """The roles this run creates, and what each of them is there for.

        The inventory is declared rather than inferred: a case that runs from the
        wrong vantage would otherwise pass for the wrong reason, and a denial that
        was really a missing role would read as a firewall success.
        """
        return [
            {
                "role": "control",
                "container": self.client_name,
                "addresses": [self.plan.client_ip],
                "product_installed": False,
                "trust_anchor": True,
                "on_demand": False,
                "purpose": "Independent Control Machine: standard-library probes, no product code.",
            },
            {
                "role": "master",
                "container": self.target_name,
                "addresses": [self.plan.target_ip, self.plan.data_target_ip],
                "product_installed": True,
                "trust_anchor": True,
                "on_demand": False,
                "purpose": "Master/Panel host the operator installs: Panel, local Node, NGINX, Xray.",
            },
            {
                "role": "worker",
                "container": self.worker_name,
                "addresses": [self.plan.worker_ip, self.plan.data_worker_ip],
                "product_installed": True,
                "trust_anchor": False,
                "on_demand": False,
                "purpose": "Separate clean host the operator provisions only through node add.",
            },
            {
                "role": "trusted-client",
                "container": self.engine_client_name,
                "addresses": [self.plan.engine_client_ip],
                "product_installed": False,
                "trust_anchor": True,
                # Started by the first case that consumes a Panel payload, so the
                # install and registration stages do not pay for it.
                "on_demand": True,
                "purpose": "Pinned Xray and Mihomo engines that consume what the Panel served.",
            },
            {
                "role": "untrusted-client",
                "container": self.untrusted_name,
                "addresses": [self.plan.untrusted_ip],
                "product_installed": False,
                "trust_anchor": False,
                "on_demand": False,
                "purpose": "Holds no product credential or node identity; every denial case runs here.",
            },
            {
                "role": "external-service",
                "container": self.echo_name,
                "addresses": [self.plan.echo_ip, self.plan.data_echo_ip],
                "product_installed": False,
                "trust_anchor": True,
                "on_demand": False,
                "purpose": "Controlled endpoint outside the nodes that records what actually reached it.",
            },
        ]

    def require_roles(self) -> List[Dict[str, Any]]:
        """The inventory, refusing to continue if a declared role never started."""
        inventory = self.roles()
        missing = [
            role["container"] for role in inventory
            if not role["on_demand"] and role["container"] not in self.started
        ]
        if missing:
            raise TopologyError(f"the run declares roles that never started: {', '.join(missing)}")
        return inventory

    def _start_worker(self) -> None:
        image_tag = target_image.build(self.podman, self.distribution)
        self.podman.run(
            name=self.worker_name,
            image_alias=image_tag,
            network=self.network,
            aliases=(self.worker_domain,),
            privileged=True,
            # The Worker's archives are as secret-bearing as the Master's, so they
            # get their own run-owned volume and the same closed directory.
            volumes=(f"{self._backup_volume('worker')}:{BACKUP_STORE}:Z",),
            # The Worker installs its own packages and manages its own units, so
            # it needs the same egress resolver path the Master has.
            environment={"DEBIAN_FRONTEND": "noninteractive"},
            systemd="always",
            extra_args=(
                "--ip", self.plan.worker_ip,
                "--dns", self.plan.dns_ip,
                *[option for resolver in self.egress_resolvers for option in ("--dns", resolver)],
            ),
        )
        self.started.append(self.worker_name)
        self.podman.wait_systemd(self.worker_name, timeout_seconds=180)
        # The Worker is the run's IPv4-only host: the product has to take its
        # disabled branch there no matter what the container runtime defaults to.
        self.podman.exec_bash(self.worker_name, DISABLE_IPV6_SCRIPT, timeout=120)
        self.podman.exec_bash(self.worker_name, WORKER_SSH_SETUP_SCRIPT, timeout=120)
        # The Worker's public address, for the egress-attribution cases: the
        # endpoint must see Worker traffic leave from Worker, not from Master.
        self.podman.network_connect(self.worker_name, self.data_network, ip=self.plan.data_worker_ip)
        self.worker_clean_facts = target_image.assert_clean(self.podman, self.worker_name)

    def _start_untrusted_client(self) -> None:
        """A client role with the run CA and nothing else.

        It shares the control network with the fixtures, so it can reach every
        management endpoint by address; every case that must be *denied* runs
        from here rather than from the Control Machine, which owns the topology.

        The clean target image carries an SSH client, which the denial cases need
        to attempt a real login against the Worker's open SSH port; the fixture
        image has none. It still holds no product package, credential, or node
        identity, so the vantage stays untrusted. ``target_image.build`` has
        already tagged it for this run, so ``Podman.ensure_image`` resolves it
        without another build.
        """
        self.podman.run(
            name=self.untrusted_name,
            image_alias=target_image.tag(self.distribution),
            network=self.network,
            privileged=False,
            volumes=(f"{self._ca_dir}:{CA_MOUNT}:ro,Z",),
            command=("sleep", "infinity"),
            systemd="false",
            extra_args=(
                "--ip", self.plan.untrusted_ip,
                "--dns", self.plan.dns_ip,
            ),
        )
        self.started.append(self.untrusted_name)

    # ------------------------------------------------------------------- trust
    def pin_worker_trust(self) -> Dict[str, Any]:
        """Give the Master key access to the Worker and pin the Worker's host key.

        The operator refuses an unpinned host key on purpose, so the run pins one:
        the key is read from the Worker's own filesystem, which is the trusted
        local control plane here, exactly as an operator would verify it out of
        band before adding the node. Nothing is learned from an unauthenticated
        ``ssh-keyscan``.
        """
        self.podman.exec_bash(
            self.target_name,
            "umask 077; mkdir -p /root/.ssh; chmod 0700 /root/.ssh; "
            "test -f /root/.ssh/id_ed25519 || "
            "ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/id_ed25519 >/dev/null",
            timeout=120,
        )
        public_key = self.podman.exec(
            self.target_name, ["cat", "/root/.ssh/id_ed25519.pub"],
        ).stdout.strip()
        if not public_key:
            raise TopologyError("the Master did not produce an SSH identity for the Worker")
        # The key travels over stdin: an argv copy would be visible in the
        # container's process list for as long as the exec lasts.
        self.podman.exec(
            self.worker_name,
            ["bash", "-c",
             "umask 077; mkdir -p /root/.ssh; chmod 0700 /root/.ssh; "
             "cat >> /root/.ssh/authorized_keys; chmod 0600 /root/.ssh/authorized_keys"],
            input_text=public_key + "\n",
            timeout=120,
        )
        # A write that never arrived exits 0 and leaves an empty file, so the
        # pin is proven by reading it back: an unverified pin would surface much
        # later as the product's own "host key is not pre-pinned" refusal.
        authorized = self.podman.exec(
            self.worker_name, ["cat", "/root/.ssh/authorized_keys"], check=False,
        ).stdout
        if self._key_blob(public_key) not in authorized:
            raise TopologyError(
                f"the Master key did not land in {self.worker_name}:/root/.ssh/authorized_keys"
            )
        worker_host_key = self.podman.exec(
            self.worker_name, ["cat", "/etc/ssh/ssh_host_ed25519_key.pub"],
        ).stdout.strip()
        if not worker_host_key.startswith("ssh-ed25519 "):
            raise TopologyError("the Worker has no ed25519 host key to pin")
        known_hosts = f"{self.plan.worker_ip} {worker_host_key}\n"
        self.podman.exec(
            self.target_name,
            ["bash", "-c", "umask 077; mkdir -p /root/.ssh; cat >> /root/.ssh/known_hosts"],
            input_text=known_hosts,
            timeout=120,
        )
        pinned = self.podman.exec(
            self.target_name, ["cat", "/root/.ssh/known_hosts"], check=False,
        ).stdout
        if self._key_blob(worker_host_key) not in pinned:
            raise TopologyError(
                f"the Worker host key did not land in {self.target_name}:/root/.ssh/known_hosts"
            )
        self._worker_host_key = worker_host_key
        self._worker_public_key = public_key
        return {
            "worker_host_key": worker_host_key.split()[0] + " " + worker_host_key.split()[1][:16] + "…",
            "known_hosts_entry": f"{self.plan.worker_ip}",
            "master_key_fingerprint": self._key_fingerprint(public_key),
        }

    @staticmethod
    def _key_fingerprint(public_key: str) -> str:
        """The SHA256 fingerprint of an OpenSSH public key, computed without a key file."""
        fields = public_key.split()
        if len(fields) < 2:
            return ""
        blob = base64.b64decode(fields[1])
        digest = hashlib.sha256(blob).digest()
        return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")

    @staticmethod
    def _key_blob(public_key: str) -> str:
        """The base64 key material of a public key line, for substring proof of a pin."""
        fields = public_key.split()
        return fields[1] if len(fields) > 1 else ""

    # --------------------------------------------------------------- node add
    # The Panel registers the Worker under this name; the container that runs
    # the Worker image is named separately, so a later command that addresses
    # the registered node must not be handed the container's name.
    worker_node_name = WORKER_NODE_NAME

    def node_add_script(self, name: str = WORKER_NODE_NAME) -> str:
        arguments = [
            f"'{name}'",
            f"'{self.plan.worker_ip}'",
            f"'{self.worker_domain}'",
            f"'{self.worker_reality_domain}'",
        ]
        vision = f"--vision-domain '{self.worker_vision_domain}' " if self.worker_vision_domain else ""
        return f"bash {REPO_IN_CONTAINER}/gowave-auto.sh node add {vision}{' '.join(arguments)}"

    def node_add(self, name: str = WORKER_NODE_NAME) -> InstallOutcome:
        """Provision the Worker through the operator's real ``node add`` path.

        The command runs on the Master, over the same SSH transport and Panel API
        registration an operator uses; the harness only supplies the trusted
        host-key pin and the SSH identity the operator would establish first.
        """
        script = self.node_add_script(name)
        started = time.monotonic()
        proc = self.podman.exec_bash(
            self.target_name, script, check=False, timeout=NODE_ADD_TIMEOUT_SECONDS,
        )
        outcome = InstallOutcome(
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            duration=time.monotonic() - started,
            command=script,
        )
        self.context.evidence_text("mn-node-add.stdout.log", outcome.stdout)
        self.context.evidence_text("mn-node-add.stderr.log", outcome.stderr)
        return outcome

    def evidence(self, outcome: Optional[InstallOutcome] = None) -> Dict[str, Any]:
        record = super().evidence(outcome)
        record.update({
            "worker_ip": self.plan.worker_ip,
            "worker_container": self.worker_name,
            "worker_domain": self.worker_domain,
            "worker_reality_domain": self.worker_reality_domain,
            "worker_vision_domain": self.worker_vision_domain or "",
            "data_worker_ip": self.plan.data_worker_ip,
            "untrusted_ip": self.plan.untrusted_ip,
            "untrusted_container": self.untrusted_name,
            "role_inventory": self.roles(),
            "roles_started": list(self.started),
            "pre_install_worker": getattr(self, "worker_clean_facts", {}),
        })
        return record
