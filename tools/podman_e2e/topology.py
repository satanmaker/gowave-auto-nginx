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

import ipaddress
import json
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

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

DNS_PORT = 53
DNS_ZONE_TTL = 30
DNS_ZONE_SUFFIX = "testbed.internal"
HOST_RESOLV_CONF = Path("/etc/resolv.conf")

FIXTURE_IMAGE = "fixture-echo"
DNS_FIXTURE_SCRIPT = "/repo/tests/fixtures/dns_server.py"
ECHO_FIXTURE_SCRIPT = "/repo/tests/fixtures/echo_server.py"
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
ECHO_HOST = "echo.testbed.internal"
CLIENT_HOST = "client.testbed.internal"

# The probe the client role runs: standard library only, so its verdict cannot
# depend on anything the product installed.
HTTP_PROBE_SCRIPT = f"{REPO_IN_CONTAINER}/tools/podman_e2e/http_probe.py"
# The probe the engine role runs: it consumes the Panel payloads with the pinned
# client binaries and reports facts only.
SUBSCRIPTION_PROBE_SCRIPT = f"{REPO_IN_CONTAINER}/tools/podman_e2e/subscription_probe.py"
# The probe that sends payloads through the served outbounds with the same
# binaries, from the same role.
TRAFFIC_PROBE_SCRIPT = f"{REPO_IN_CONTAINER}/tools/podman_e2e/traffic_probe.py"
# Payloads are fetched on the host (the subscription routes are loopback-only)
# and mounted into the engine container; they are never printed or copied into
# the artifact directory.
PAYLOAD_MOUNT = "/payloads"
SECRETS_MOUNT = "/secrets"

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


def egress_resolvers(resolv_conf: Path = HOST_RESOLV_CONF) -> List[str]:
    """Real resolvers the disposable host may use for names outside the fixture zone.

    The fixture answers its own zone authoritatively and refuses everything else,
    so the target falls through to these servers for package mirrors and release
    downloads exactly like a fresh VPS. Loopback entries are dropped: they point
    at the workstation's stub resolver, which does not exist in the container.
    """
    try:
        text = resolv_conf.read_text(encoding="utf-8")
    except OSError:
        return []
    resolvers: List[str] = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "nameserver":
            address = fields[1]
            if address.startswith("127.") or address.startswith("169.254.") or address == "::1":
                continue
            if address not in resolvers:
                resolvers.append(address)
    return resolvers


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
    def create(self) -> "AioTopology":
        if not self.egress_resolvers:
            raise TopologyError(
                f"no egress resolver found in {HOST_RESOLV_CONF}; the disposable host could not install packages"
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
        zone_path = directory / "zone.json"
        zone_path.write_text(json.dumps(zone(self.plan), sort_keys=True), encoding="utf-8")
        self.podman.run(
            name=self.dns_name,
            image_alias=FIXTURE_IMAGE,
            network=self.network,
            aliases=("dns.testbed.internal",),
            privileged=False,
            # Writable: cases rewrite the zone to steer answers and the fixture
            # appends its query log there.
            volumes=(f"{directory}:/fixtures/dns:Z",),
            command=dns_command("/fixtures/dns/zone.json", "/fixtures/dns/queries.jsonl"),
            systemd="false",
            extra_args=("--ip", self.plan.dns_ip),
        )
        self.started.append(self.dns_name)
        self.podman.wait_tcp(self.dns_name, "127.0.0.1", DNS_PORT, timeout_seconds=60)

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
        domains = [self.panel_domain, self.reality_domain]
        if self.vision_domain:
            domains.append(self.vision_domain)
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
                    for name in domains
                    for option in ("--add-host", f"{name}:{self.plan.target_ip}")
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
    ) -> Dict[str, Any]:
        """Fetch a URL from the Control Machine role and return the probe report.

        The probe trusts the run CA only, so a certificate the product obtained
        from the fixture directory is the only one that can pass.
        """
        argv = [
            "python3", HTTP_PROBE_SCRIPT,
            "--url", url,
            "--timeout", str(timeout),
            "--method", method,
        ]
        if insecure:
            argv.append("--insecure")
        else:
            argv += ["--ca", f"{CA_MOUNT}/{ISSUED_ROOT_NAME}"]
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
