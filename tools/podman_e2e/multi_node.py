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
import shlex
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.podman_e2e import (
    acme_fixture, aio, denial, matrix as matrix_data, mtls, topology,
)
from tools.podman_e2e.podman import wait_until
from tools.podman_e2e.runner import Case, CaseBlocked, CaseIncomplete, require

INSTALL_CASE_ID = "MN-INSTALL"
NODE_ADD_CASE_ID = "WRK-04"
WORKER_STATE_CASE_ID = "WRK-05"
WORKER_CONFIG_CASE_ID = "WRK-06"
MASTER_ADDRESS_CASE_ID = "PODNET-MASTER-ADDR"
MANAGEMENT_DENIAL_CASE_ID = "FW-01"
DENIAL_CLASSIFICATION_CASE_ID = "FW-02"
REVOCATION_CASE_ID = "MN-REVOKE"
OUTAGE_CASE_ID = "MN-OUTAGE"
RESTART_CASE_ID = "MN-RESTART"
VISION_CASE_ID = "MN-VISION"
SSH_KEY_CASE_ID = "MN-SSHKEY"
MATRIX_CASE_ID = "MN-MATRIX"
EGRESS_CASE_ID = "MN-EGRESS"
MTLS_TIMEOUT_SECONDS = 300
MATRIX_TIMEOUT_SECONDS = 120
EGRESS_TIMEOUT_SECONDS = 300
DENIAL_TIMEOUT_SECONDS = 300
CLUSTER_TIMEOUT_SECONDS = 300
WORKER_STATE_TIMEOUT_SECONDS = 300
VISION_PROBE_TIMEOUT_SECONDS = 120
SSH_TRUST_TIMEOUT_SECONDS = 240
# The transaction id only has to satisfy the product's own format; it names a
# leftover snapshot the case plants on the Worker to observe a remote effect.
SSH_ROTATION_TX_ID = "worker_install_sshkey_rotation"
WORKER_REPORT_TIMEOUT_SECONDS = 120
# A stopped node is only reported offline once the Panel's own heartbeat window
# has expired, and a node that starts again has to re-register and re-apply its
# users before it carries a payload, so both waits are bounded but generous.
OUTAGE_TIMEOUT_SECONDS = 420
RESTART_TIMEOUT_SECONDS = 420
RECOVERY_INTERVAL_SECONDS = 5
WORKER_UNIT = "gowave-node.service"
# A stop waits for the unit's own TimeoutStopSec before the cgroup is killed, so
# the action's own budget is wider than the readiness windows above.
WORKER_SERVICE_TIMEOUT_SECONDS = 300
# The lifecycle cases drive one real tuple rather than the whole matrix: the
# engine is the one whose single-transfer path the probe already reports on.
LIFECYCLE_CLIENT = "xray"
# Each lifecycle case pays for the Panel's two connection windows, the Master's
# control dial and a baseline/recovery transfer besides the bounded waits above;
# the case budget has to cover all of them or a slow engine start would read as a
# product failure.
OUTAGE_CASE_TIMEOUT_SECONDS = (
    2 * OUTAGE_TIMEOUT_SECONDS + 3 * aio.DATA_PLANE_TIMEOUT_SECONDS
)
RESTART_CASE_TIMEOUT_SECONDS = (
    2 * RESTART_TIMEOUT_SECONDS + 3 * aio.DATA_PLANE_TIMEOUT_SECONDS
)
# The subscription cases build the engine image on first use, fetch five
# representations from the Panel, and run Xray and Mihomo over each of them.
SUB_SERVED_TIMEOUT_SECONDS = 900
SUB_SHARE_LINK_TIMEOUT_SECONDS = 600

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

# What one node provisioned for one Vision domain, read from that node itself:
# the certificate lineage the product asked the ACME fixture for, the NGINX
# stream route and vhost that carry the domain's name, and the config the node
# loaded. The probe is handed the domain it must report on, including when the
# run did not configure it, so an unconfigured node is proven to have no
# endpoint under that name rather than merely having no endpoint at all.
NODE_VISION_SCRIPT = r"""python3 - VISION_DOMAIN_PLACEHOLDER VISION_PORT_PLACEHOLDER <<'PY'
import glob
import json
import os
import subprocess
import sys

domain = sys.argv[1]
port = int(sys.argv[2])
LIVE = "/etc/letsencrypt/live"
RENEWAL = "/etc/letsencrypt/renewal"
CONFIG = "/run/gowave-node/xray.json"
NGINX_STREAM = "/etc/nginx/stream-enabled"
NGINX_CONF = "/etc/nginx/conf.d"


def openssl(*arguments):
    try:
        result = subprocess.run(
            ("openssl",) + arguments, capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return False, ""
    return result.returncode == 0, result.stdout


def certificate():
    lineage = os.path.join(LIVE, domain)
    cert = os.path.join(lineage, "cert.pem")
    key = os.path.join(lineage, "privkey.pem")
    present = os.path.isfile(cert) and os.path.isfile(key)
    facts = {
        "lineage": lineage,
        "present": present,
        "host_ok": False,
        "valid": False,
        "issuer": "",
        "renewal_server": "",
    }
    if present:
        host_ok, _ = openssl("x509", "-in", cert, "-noout", "-checkhost", domain)
        valid, _ = openssl("x509", "-in", cert, "-noout", "-checkend", "86400")
        issued, issuer = openssl("x509", "-in", cert, "-noout", "-issuer")
        facts["host_ok"] = host_ok
        facts["valid"] = valid
        facts["issuer"] = " ".join(issuer.split()) if issued else ""
    renewal = os.path.join(RENEWAL, domain + ".conf")
    if os.path.isfile(renewal):
        with open(renewal, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                name, separator, value = line.partition("=")
                if separator and name.strip() == "server":
                    facts["renewal_server"] = value.strip()
                    break
    return facts


def read(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.readlines()
    except OSError:
        return []


def nginx():
    routes = []
    targets = []
    for path in sorted(glob.glob(os.path.join(NGINX_STREAM, "*.conf"))):
        for line in read(path):
            fields = line.split()
            if len(fields) < 2:
                continue
            if fields[0] == domain:
                routes.append({"file": os.path.basename(path), "target": fields[1]})
            if fields[1] == "127.0.0.1:%d;" % port:
                targets.append(os.path.basename(path))
    vhosts = []
    for path in sorted(glob.glob(os.path.join(NGINX_CONF, "*.conf"))):
        for line in read(path):
            stripped = line.strip()
            if not stripped.startswith("server_name "):
                continue
            names = [name.rstrip(";") for name in stripped.split()[1:]]
            if domain in names:
                vhosts.append(os.path.basename(path))
                break
    return {
        "stream_routes": routes,
        "stream_vision_targets": sorted(set(targets)),
        "vhost_files": vhosts,
        "vision_named_files": [
            os.path.basename(path)
            for path in sorted(glob.glob(os.path.join(NGINX_CONF, "*vision*")))
        ],
    }


def applied():
    try:
        with open(CONFIG, "r", encoding="utf-8") as handle:
            config = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {"parsed": False, "inbounds": []}
    if not isinstance(config, dict):
        return {"parsed": False, "inbounds": []}
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
    return {"parsed": True, "inbounds": inbounds}


print(json.dumps({
    "domain": domain,
    "port": port,
    "certificate": certificate(),
    "nginx": nginx(),
    "applied": applied(),
}, sort_keys=True))
PY
"""


def node_vision_script(domain: str, port: int) -> str:
    """The probe for one node and one Vision name, with both values quoted."""
    return (
        NODE_VISION_SCRIPT
        .replace("VISION_DOMAIN_PLACEHOLDER", shlex.quote(domain))
        .replace("VISION_PORT_PLACEHOLDER", str(int(port)))
    )


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


def vision_identity(data: Dict[str, Any]) -> Dict[str, Any]:
    """The Vision inbound's identity, taken from the matrix and its shipped template.

    The inbound is identified by the fields the node loads — protocol, internal
    port, transport and security layer — not by its tag. The Panel names the tag
    after the node it provisions, so a case that matched the tag would accept a
    node carrying another node's inbound.
    """
    entry = matrix_data.inbound(data, matrix_data.VISION_INBOUND)
    template = json.loads(
        (matrix_data.REPO_ROOT / str(entry["template"])).read_text(encoding="utf-8")
    )
    stream = template.get("streamSettings")
    stream = stream if isinstance(stream, dict) else {}
    return {
        "id": str(entry.get("id") or ""),
        "type": str(template.get("protocol") or "").lower(),
        "port": int(template.get("port")),
        "network": str(stream.get("network") or "tcp").lower(),
        "security": str(stream.get("security") or "none").lower(),
    }


def vision_matches(spec: Dict[str, Any], identity: Dict[str, Any]) -> bool:
    """Whether one inbound declaration is the Vision inbound of this matrix."""
    port = spec.get("port")
    return (
        str(spec.get("type") or "").lower(),
        "" if port in (None, "") else str(port),
        str(spec.get("network") or "").lower(),
        str(spec.get("security") or "").lower(),
    ) == (
        identity["type"], str(identity["port"]), identity["network"], identity["security"],
    )


def describe_inbounds(specs: Sequence[Dict[str, Any]]) -> str:
    """A compact, credential-free inbound listing for a failure message."""
    described = [
        "{tag}({type}/{network}/{security}@{port})".format(
            tag=spec.get("tag") or "untagged",
            type=spec.get("type") or "?",
            network=spec.get("network") or "?",
            security=spec.get("security") or "?",
            port=spec.get("port") or "?",
        )
        for spec in specs
    ]
    return ", ".join(described) or "none"


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
        # The data-plane body is shared with the All-in-One suite, but its case ids
        # belong to this topology: a cluster case names its node, because both
        # nodes serve the same transport/security pairs.
        self.master.case_topology = matrix_data.MULTI_NODE
        # The default client's subscription carries every node in its squad, so
        # the Panel publishes both nodes' inbounds, not only the Master's.
        self.master.subscription_inbounds_override = (
            matrix_data.inbounds(self.matrix, vision=vision)
            + matrix_data.inbounds(self.matrix, vision=worker_vision)
        )
        self.topology: Optional[topology.MultiNodeTopology] = None
        self.node_add_outcome: Optional[topology.InstallOutcome] = None
        self.mtls_positive_facts: Optional[Dict[str, Any]] = None
        self.mtls_negative_facts: Optional[Dict[str, Any]] = None
        self.denial_facts_cache: Optional[Dict[str, Any]] = None
        self.worker_state_cache: Optional[Dict[str, Any]] = None
        self._data_plane_sources: Dict[str, str] = {}
        self.worker_report_timeout = WORKER_REPORT_TIMEOUT_SECONDS
        self.worker_report_interval = NODE_HEALTH_INTERVAL_SECONDS
        self.trust: Dict[str, Any] = {}

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

    def expected_egress_sources(self) -> List[str]:
        """The node addresses this cluster's served payloads have to leave from.

        A subscription issued by a cluster names both nodes, so a transfer set
        that lost one of them would otherwise pass while only the other node was
        proven — the same reason the revocation case counts what the Panel served
        rather than one install's own inbounds.
        """
        host = self.require_worker()
        return [host.plan.data_target_ip, str(host.plan.data_worker_ip)]

    def declare_data_plane(self, case_ids: Sequence[str]) -> None:
        """Record the declared matrix cases; the registry lives on the Master product.

        The shared data-plane body runs against that product, so keeping one
        registry means the count case reads exactly what the cases recorded.
        """
        self.master.declare_data_plane(case_ids)

    def record_data_plane(self, case_id: str, status: str) -> None:
        self.master.record_data_plane(case_id, status)

    def record_data_plane_source(self, case_id: str, source_ip: str) -> None:
        """Record the address a matrix case's payload actually left from.

        The count case says the tuples ran; this registry says where each one
        left from, so a cluster cannot attribute a Worker tuple to the Master.
        """
        self.data_plane_sources[case_id] = source_ip

    @property
    def declared_data_plane(self) -> List[str]:
        return self.master.declared_data_plane

    @property
    def data_plane_results(self) -> Dict[str, str]:
        return self.master.data_plane_results

    @property
    def data_plane_sources(self) -> Dict[str, str]:
        return self._data_plane_sources

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

    def node_vision_facts(
        self, case_id: str, node: str, domain: str, port: int,
    ) -> Dict[str, Any]:
        """Read one node's certificate, NGINX routing and applied config for a Vision name.

        The probe runs inside the node's own container and reads only files the
        product wrote, so what it reports is the deployment rather than what the
        installer intended to deploy.
        """
        host = self.require_worker() if node == "worker" else self.require_installed()
        container = host.worker_name if node == "worker" else host.target_name
        result = self.podman.exec_bash(
            container, node_vision_script(domain, port), check=False,
            timeout=VISION_PROBE_TIMEOUT_SECONDS,
        )
        require(
            case_id,
            result.returncode == 0,
            f"the {node} Vision probe exited {result.returncode}: "
            f"{(result.stderr or result.stdout or '').strip()[-2000:]}",
        )
        try:
            facts = json.loads(result.stdout or "")
        except json.JSONDecodeError:
            facts = None
        require(
            case_id,
            isinstance(facts, dict),
            f"the {node} Vision probe did not print a JSON object: "
            f"{(result.stdout or '')[:400]}",
        )
        return facts

    def remote_finalize(
        self, known_hosts: str, transaction: str,
        timeout: int = SSH_TRUST_TIMEOUT_SECONDS,
    ) -> Any:
        """Run the product's own remote-finalize SSH operation on the Worker.

        ``remote_finalize`` is the controller's documented Worker operation: it
        requires a pinned host key, connects with ``StrictHostKeyChecking=yes``
        against exactly that file, and deletes the named ACME recovery snapshot.
        Because the deletion is observable on the Worker, its presence or absence
        tells an executed remote command from a refused connection.
        """
        host = self.require_installed()
        script = (
            f"ACME_TX_ID={shlex.quote(transaction)} "
            f"SSH_KNOWN_HOSTS={shlex.quote(known_hosts)} "
            f"bash {topology.REPO_IN_CONTAINER}/gowave-node-auto.sh remote_finalize "
            f"{shlex.quote(host.plan.worker_ip)} 22 root"
        )
        return self.podman.exec_bash(
            host.target_name, script, check=False, timeout=timeout,
        )

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

    def direct_egress_facts(
        self, vantage: str, timeout: int = EGRESS_TIMEOUT_SECONDS,
    ) -> Dict[str, Any]:
        """Try to deliver a payload straight at the endpoint from one client role.

        Neither the Control Machine nor the pinned-engine client owns a node
        identity, so the endpoint has to refuse the payload by source. Running the
        same attempt from both roles is what separates "the product's egress is
        attributable" from "one container happens to sit outside the allowlist".
        """
        host = self.require_worker()
        return aio.probe_json(
            EGRESS_CASE_ID,
            f"the {vantage} direct-egress probe",
            host.direct_egress_facts(vantage, timeout=timeout),
        )

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

    # --------------------------------------------------------------- denial
    def denial_facts(self, case_id: str = MANAGEMENT_DENIAL_CASE_ID) -> Dict[str, Any]:
        """The untrusted and trusted management paths, measured once.

        FW-01 and FW-02 read the same observations — the Master's working path,
        the untrusted attempts, and what the Worker recorded about them — so a
        second collection would let the two cases describe different instants.
        A failed probe blocks instead of reporting a refusal, because "the probe
        could not run" and "the Worker said no" are not the same finding.
        """
        host = self.require_worker()
        if self.denial_facts_cache is not None:
            return self.denial_facts_cache

        master_address = host.plan.target_ip
        untrusted_address = host.plan.untrusted_ip
        # Both attempts dial the Worker, not the Master: the trust material the
        # operator set up names the Worker's run address, and the control port
        # the firewall scopes is the Worker's.
        worker_address = host.plan.worker_ip
        require(
            case_id,
            master_address != untrusted_address,
            f"the untrusted role runs at {untrusted_address}, the same address the Master "
            f"uses ({master_address}); a denial from that vantage would prove nothing",
        )

        positive = self.mtls_positive()
        require(
            case_id,
            positive.get("returncode") == 0,
            f"the Master's own mTLS verifier exited {positive.get('returncode')}, so a "
            f"refusal seen from the untrusted role could not be told from a control plane "
            f"that was down: {positive.get('tail') or 'no output'}",
        )
        trusted = denial.run_trusted_ssh(self.podman, host.target_name, worker_address)
        probe = denial.run_untrusted_probe(self.podman, host.untrusted_name, worker_address)
        if not probe.get("management"):
            raise CaseBlocked(
                f"{case_id}: the untrusted probe produced no report (exit "
                f"{probe.get('returncode')}): {probe.get('detail') or 'no output'}"
            )
        observed: List[str] = []
        journal_tail: List[str] = []

        def logged() -> bool:
            # sshd writes the refusal when the connection ends, so the line can
            # trail the probe by a moment; the deadline is what makes that a poll
            # rather than an assumption.
            report = denial.sshd_observation(
                self.podman, host.worker_name, untrusted_address,
            )
            observed[:] = report["matches"]
            journal_tail[:] = report["tail"]
            return bool(observed)

        wait_until(
            logged, denial.SSHD_OBSERVATION_TIMEOUT_SECONDS,
            f"{case_id} Worker sshd observation", interval_seconds=2,
        )
        firewall = denial.worker_firewall(self.podman, host.worker_name)
        require(
            case_id,
            firewall.get("iptables_returncode") == 0,
            f"the Worker's firewall rules could not be read (exit "
            f"{firewall.get('iptables_returncode')}): "
            f"{firewall.get('iptables_error') or firewall.get('detail') or 'no output'}",
        )
        require(
            case_id,
            firewall["node_allow_sources"],
            "the Worker allows no source to reach the control port, so there is no allowed "
            "management path for the trusted half of this pair",
        )

        self.denial_facts_cache = {
            "master_address": master_address,
            "worker_address": worker_address,
            "untrusted_address": untrusted_address,
            "trusted_mtls": positive,
            "trusted_ssh": trusted,
            "untrusted": probe,
            "observed_source": untrusted_address if observed else "",
            "observed_lines": observed,
            "journal_tail": journal_tail,
            "firewall": firewall,
            "worker_name": host.worker_name,
            "untrusted_name": host.untrusted_name,
        }
        return self.denial_facts_cache

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

    # ------------------------------------------------- outage and restart
    def worker_record(self, case_id: str) -> Dict[str, Any]:
        """The Panel's registry record for the Worker, refused by name when absent."""
        self.require_worker()
        return panel_node(self.cluster_facts(case_id), topology.WORKER_NODE_NAME, case_id)

    def worker_tuple(self) -> Tuple[Dict[str, Any], str]:
        """The one Worker tuple the lifecycle cases drive, in matrix order.

        The fault cases need a real inbound to carry a payload before the fault
        and after it, so the tuple comes from the matrix the product is serving
        rather than from a port the harness picked.
        """
        inbounds = matrix_data.inbounds(self.matrix, vision=self.worker_vision)
        if not inbounds:
            raise CaseBlocked(
                f"{OUTAGE_CASE_ID}: the matrix declares no inbound for the Worker, so no "
                "payload could traverse it"
            )
        return inbounds[0], LIFECYCLE_CLIENT

    def master_tuple(self) -> Tuple[Dict[str, Any], str]:
        """The Master tuple the outage case keeps delivering through.

        It is the control that separates "the Worker is down" from "the cluster is
        down": the same Panel, the same subscription, one node still serving.
        """
        inbounds = matrix_data.inbounds(self.matrix, vision=self.vision)
        if not inbounds:
            raise CaseBlocked(
                f"{OUTAGE_CASE_ID}: the matrix declares no inbound for the Master, so the "
                "degraded half of the outage would have no control"
            )
        return inbounds[0], LIFECYCLE_CLIENT

    def node_transfer(
        self, case_id: str, node: str, inbound: Dict[str, Any], client: str,
        expect_refusal: bool = False,
    ) -> Dict[str, Any]:
        """One transfer through one node's tuple, refusal-tolerant when asked.

        ``expect_refusal`` is what makes a stopped node measurable: the probe
        returns the refusal instead of exiting, so the case can tell the product's
        degraded state from a probe that could not run at all.
        """
        return self.master.transfer_facts(
            case_id, str(inbound["id"]), client, node=node,
            expect_refusal=expect_refusal,
        )

    def wait_for_worker_connection(
        self, case_id: str, expected: bool, timeout_seconds: int,
    ) -> Dict[str, Any]:
        """Wait until the Panel reports the Worker connected (or not) and return its record.

        The Panel learns a connection state from the node's own traffic, so both
        directions lag the unit's state: a stopped node keeps its flag until the
        heartbeat window expires, and a started one is only connected once it
        answers. The deadline is what turns that lag into a poll.
        """
        observed: Dict[str, Any] = {}

        def matches() -> bool:
            record = self.worker_record(case_id)
            observed.clear()
            observed.update(record)
            return record.get("connected") is expected

        ready = wait_until(
            matches, timeout_seconds, f"{case_id} Worker connection",
            interval_seconds=RECOVERY_INTERVAL_SECONDS,
        )
        require(
            case_id,
            ready,
            f"the Panel still reports {topology.WORKER_NODE_NAME!r} as "
            f"{observed.get('connected')!r} after {timeout_seconds}s, expected "
            f"{'connected' if expected else 'offline'}",
        )
        return observed

    def wait_for_worker_peer(
        self, case_id: str, timeout_seconds: int = RESTART_TIMEOUT_SECONDS,
    ) -> Dict[str, Any]:
        """Wait until the Master's own dial to the Worker is live again.

        The Panel's connected flag is not that evidence. A short restart can
        complete inside one heartbeat, so the flag stays set while the Master's
        mTLS connection is still down; only the sockets on the Worker itself say
        when the control plane is back. Run 20261112T230625-a64b2235 measured
        exactly that gap: MN-OUTAGE had 10.89.0.10 among its peers after a 17.4 s
        recovery, while MN-RESTART read the peer set 1.2 s after the restart and
        found none — the node had re-registered, the Master had not re-dialled.
        """
        host = self.require_installed()
        master_address = host.plan.target_ip
        started_at = time.monotonic()
        seen: Dict[str, Any] = {}

        def dialled() -> bool:
            seen.clear()
            seen.update(self.worker_control_facts(case_id))
            return master_address in (seen.get("peers") or [])

        ready = wait_until(
            dialled, timeout_seconds, f"{case_id} Master control connection",
            interval_seconds=RECOVERY_INTERVAL_SECONDS,
        )
        require(
            case_id,
            ready,
            f"the Master's control connection to the Worker did not come back within "
            f"{timeout_seconds}s of the unit coming up again; the Worker observed "
            f"peers {seen.get('peers') or 'none'} from {master_address}",
        )
        facts = self.worker_address_facts(case_id)
        facts["peer_wait_seconds"] = round(time.monotonic() - started_at, 1)
        return facts

    def worker_service(self, action: str, case_id: str) -> Dict[str, Any]:
        """Run the operator's own systemctl action on the Worker's supervising unit.

        The action's exit code travels back with the state it left, because a
        shell that carried on after a failed stop would otherwise look like a
        completed outage. The caller decides what the state means: the outage case
        has to restore the unit even when its body fails, so it cannot assert here.
        """
        host = self.require_worker()
        script = (
            f"systemctl {action} {WORKER_UNIT} </dev/null; rc=$?\n"
            "echo '==returncode'\n"
            'printf \'%s\\n\' "$rc"\n'
            "echo '==active'\n"
            f"systemctl is-active {WORKER_UNIT} || true\n"
            "echo '==mainpid'\n"
            f"systemctl show {WORKER_UNIT} -p MainPID --value || true\n"
        )
        result = self.podman.exec_bash(
            host.worker_name, script, check=False, timeout=WORKER_SERVICE_TIMEOUT_SECONDS,
        )
        sections = aio.inventory_sections(result.stdout or "")
        raw = (sections.get("returncode") or [""])[0]
        returncode = int(raw) if raw.lstrip("-").isdigit() else None
        return {
            "action": action,
            "returncode": returncode,
            "state": (sections.get("active") or [""])[0],
            "main_pid": (sections.get("mainpid") or [""])[0],
            "detail": (result.stderr or "").strip()[-400:] if returncode != 0 else "",
        }

    def worker_main_pid(self, case_id: str) -> str:
        """The supervising unit's main PID, read on the Worker itself.

        A Panel that never noticed the blip would otherwise let a "restart" pass
        without one, so the process identity is observed where the process runs.
        """
        host = self.require_worker()
        result = self.podman.exec_bash(
            host.worker_name,
            f"systemctl show {WORKER_UNIT} -p MainPID --value || true",
            check=False, timeout=60,
        )
        require(
            case_id,
            result.returncode == 0,
            f"reading {WORKER_UNIT}'s main PID on the Worker exited {result.returncode}: "
            f"{(result.stderr or result.stdout or '').strip()[-400:]}",
        )
        return (result.stdout or "").strip()


def case_ssh_host_key(product: MultiNodeProduct) -> Dict[str, Any]:
    """MN-SSHKEY: a wrong or rotated Worker host key stops the controller before it acts.

    The controller sends nothing to the Worker except over OpenSSH with
    ``StrictHostKeyChecking=yes`` against the operator's pinned ``known_hosts``,
    so the trust has to hold in both directions: a key that is not the Worker's
    must abort the operation before its remote effect, and a real rotation must
    be adoptable only by re-pinning the new key.

    Both are proven through the product's own remote-finalize operation, whose
    effect — deleting a leftover ACME recovery snapshot — is observable on the
    Worker afterwards. The case plants that snapshot, so a refused connection and
    an executed command leave different evidence, and it re-pins before asserting
    so a failure cannot leave the product path unusable for the rest of the run.
    """
    host = product.require_installed()
    worker_ip = host.plan.worker_ip
    transaction = f"/var/lib/gowave-auto-nginx/recovery/{SSH_ROTATION_TX_ID}"
    sentinel = f"{transaction}/sentinel"
    known_hosts = "/root/.ssh/known_hosts"
    wrong_pin = "/root/.ssh/known_hosts-wrong-key"
    finalized = "Worker ACME recovery snapshot finalized."

    def snapshot_present() -> bool:
        return product.podman.exec(
            host.worker_name, ["test", "-f", sentinel], check=False,
        ).returncode == 0

    def pin(path: str, public_key: str) -> None:
        result = product.podman.exec(
            host.target_name,
            ["bash", "-c", f"umask 077; cat > {shlex.quote(path)}"],
            input_text=f"{worker_ip} {public_key}\n",
            timeout=120,
        )
        require(
            SSH_KEY_CASE_ID,
            result.returncode == 0,
            f"pinning a host key in {path} on the Master exited {result.returncode}: "
            f"{(result.stderr or '').strip()[-500:]}",
        )

    prepared = product.podman.exec_bash(host.worker_name, f"""
set -eu
umask 077
install -d -m 0700 {shlex.quote(transaction)}
: > {shlex.quote(sentinel)}
test -f {shlex.quote(sentinel)}
""", check=False, timeout=120)
    require(
        SSH_KEY_CASE_ID,
        prepared.returncode == 0,
        f"planting the Worker's leftover ACME snapshot exited {prepared.returncode}: "
        f"{(prepared.stderr or '').strip()[-500:]}",
    )
    require(
        SSH_KEY_CASE_ID,
        snapshot_present(),
        f"the planted snapshot {sentinel} is not readable on the Worker",
    )

    decoy = product.podman.exec_bash(host.target_name, """
set -eu
umask 077
test -f /root/.ssh/mn-sshkey-decoy || ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/mn-sshkey-decoy
cat /root/.ssh/mn-sshkey-decoy.pub
""", check=False, timeout=120)
    decoy_key = (decoy.stdout or "").strip()
    require(
        SSH_KEY_CASE_ID,
        decoy.returncode == 0 and decoy_key.startswith("ssh-ed25519 "),
        f"the Master did not produce an unrelated ed25519 key to pin instead: "
        f"{(decoy.stderr or decoy.stdout or '').strip()[-500:]}",
    )

    pin(wrong_pin, decoy_key)
    wrong = product.remote_finalize(wrong_pin, SSH_ROTATION_TX_ID)
    wrong_output = (wrong.stdout or "") + (wrong.stderr or "")
    wrong_survived = snapshot_present()

    before_key = product.podman.exec(
        host.worker_name, ["cat", "/etc/ssh/ssh_host_ed25519_key.pub"], check=False,
    ).stdout.strip()
    rotation = product.podman.exec_bash(host.worker_name, """
set -eu
rm -f /etc/ssh/ssh_host_*
ssh-keygen -A >/dev/null
systemctl restart ssh.service
""", check=False, timeout=180)
    after_key = product.podman.exec(
        host.worker_name, ["cat", "/etc/ssh/ssh_host_ed25519_key.pub"], check=False,
    ).stdout.strip()

    stale = product.remote_finalize(known_hosts, SSH_ROTATION_TX_ID)
    stale_output = (stale.stdout or "") + (stale.stderr or "")
    stale_survived = snapshot_present()

    # Pin the new key before any assertion, so a failed expectation cannot leave
    # the controller unable to reach the Worker it is still managing.
    re_pinned = after_key.startswith("ssh-ed25519 ")
    if re_pinned:
        pin(known_hosts, after_key)
    accepted = product.remote_finalize(known_hosts, SSH_ROTATION_TX_ID)
    accepted_output = (accepted.stdout or "") + (accepted.stderr or "")
    accepted_survived = snapshot_present()

    require(
        SSH_KEY_CASE_ID,
        wrong.returncode != 0,
        f"the controller connected while a different key was pinned for {worker_ip!r}: "
        f"{wrong_output.strip()[-800:]}",
    )
    require(
        SSH_KEY_CASE_ID,
        "Host key verification failed" in wrong_output,
        f"the wrong pin was refused without OpenSSH naming the verification failure: "
        f"{wrong_output.strip()[-800:]!r}",
    )
    require(
        SSH_KEY_CASE_ID,
        finalized not in wrong_output and wrong_survived,
        f"the remote script ran although the pinned host key was not the Worker's: "
        f"{wrong_output.strip()[-800:]!r}",
    )
    require(
        SSH_KEY_CASE_ID,
        rotation.returncode == 0,
        f"rotating the Worker's host keys exited {rotation.returncode}: "
        f"{(rotation.stderr or '').strip()[-500:]}",
    )
    require(
        SSH_KEY_CASE_ID,
        re_pinned and after_key != before_key,
        f"the Worker's ed25519 host key did not change, so the rotation was not "
        f"exercised: before {before_key.split()[:2]!r}, after {after_key.split()[:2]!r}",
    )
    require(
        SSH_KEY_CASE_ID,
        stale.returncode != 0,
        f"the stale pin was accepted after the Worker rotated its host key: "
        f"{stale_output.strip()[-800:]}",
    )
    require(
        SSH_KEY_CASE_ID,
        "Host key verification failed" in stale_output,
        f"the stale pin was refused without OpenSSH naming the verification failure: "
        f"{stale_output.strip()[-800:]!r}",
    )
    require(
        SSH_KEY_CASE_ID,
        finalized not in stale_output and stale_survived,
        f"the remote script ran under the stale pin after rotation: "
        f"{stale_output.strip()[-800:]!r}",
    )
    require(
        SSH_KEY_CASE_ID,
        accepted.returncode == 0,
        f"the re-pinned rotated key was rejected: "
        f"{(accepted.stderr or accepted.stdout or '').strip()[-800:]}",
    )
    require(
        SSH_KEY_CASE_ID,
        finalized in accepted_output,
        f"the re-pinned key did not reach the remote script: "
        f"{accepted_output.strip()[-800:]!r}",
    )
    require(
        SSH_KEY_CASE_ID,
        not accepted_survived,
        f"the remote script reported success but the planted snapshot {sentinel} is "
        f"still on the Worker",
    )

    def fingerprint(key: str) -> str:
        # The head of an ed25519 blob is the same for every key, so the tail is
        # what tells one host key from another in the evidence.
        fields = key.split()
        return f"{fields[0]} …{fields[1][-12:]}" if len(fields) > 1 else "none"

    return {
        "worker_ip": worker_ip,
        "known_hosts_entry": known_hosts,
        "wrong_key_refused": wrong.returncode != 0,
        "wrong_key_executed_remotely": not wrong_survived,
        "old_key_rejected": stale.returncode != 0,
        "old_key_executed_remotely": not stale_survived,
        "new_key_accepted": accepted.returncode == 0,
        "new_key_executed_remotely": not accepted_survived,
        "worker_host_key_before": fingerprint(before_key),
        "worker_host_key_after": fingerprint(after_key),
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


def case_management_denial(product: MultiNodeProduct) -> Dict[str, Any]:
    """FW-01: an untrusted source cannot reach the Worker's management plane.

    The Worker's control port is allowed from the Master's address and nowhere
    else, and the node demands a client certificate on top of that. Both halves
    are asserted here, because one without the other is not a policy: a refusal
    that would also happen for the Master is a broken control plane, and an
    allow rule naming the Master proves nothing if the port is open to everyone
    with a certificate. The SSH attempt is the same question at the other
    boundary — the port is open to every source, so the denial has to be
    authentication, and the Worker's own log has to name the address it refused.
    """
    facts = product.denial_facts(MANAGEMENT_DENIAL_CASE_ID)
    firewall = facts["firewall"]
    master = facts["master_address"]
    untrusted = facts["untrusted_address"]

    require(
        MANAGEMENT_DENIAL_CASE_ID,
        firewall["active"],
        "the Worker's UFW is not active, so the control port is not being filtered at all",
    )
    require(
        MANAGEMENT_DENIAL_CASE_ID,
        firewall["input_policy"] == "DROP",
        f"the Worker's INPUT policy is {firewall['input_policy'] or 'unset'!r} instead of DROP",
    )
    require(
        MANAGEMENT_DENIAL_CASE_ID,
        not firewall["unscoped_allows"],
        f"the Worker allows the control port from every source: "
        f"{[entry['line'] for entry in firewall['unscoped_allows']]}",
    )
    require(
        MANAGEMENT_DENIAL_CASE_ID,
        firewall["node_allow_sources"] == [master],
        f"the Worker allows {firewall['node_allow_sources'] or 'nobody'} to reach the "
        f"control port instead of only the Master's run address {master}",
    )
    require(
        MANAGEMENT_DENIAL_CASE_ID,
        firewall["ssh_anywhere"],
        "the Worker's SSH port is not open to every source, so a refused login would "
        "prove a closed port rather than a rejected identity",
    )

    # The allowed management client, using the trust material the operator set up:
    # a payload-backed TLS 1.3 handshake with a 200 over it, and a root login over
    # the pinned host key.
    trusted_mtls = facts["trusted_mtls"]
    require(
        MANAGEMENT_DENIAL_CASE_ID,
        trusted_mtls.get("handshake_pass") is True,
        f"the Master's mTLS handshake with the Worker failed, so the trusted management "
        f"path is not working: {trusted_mtls.get('tail') or 'no output'}",
    )
    require(
        MANAGEMENT_DENIAL_CASE_ID,
        trusted_mtls.get("response") == "health",
        f"the Master's authenticated call answered {trusted_mtls.get('status_line')!r} "
        f"instead of the Node health response",
    )
    trusted_ssh = facts["trusted_ssh"]
    require(
        MANAGEMENT_DENIAL_CASE_ID,
        trusted_ssh.get("returncode") == 0 and trusted_ssh.get("marker"),
        f"the operator's pinned-key SSH command to the Worker exited "
        f"{trusted_ssh.get('returncode')} without its marker; the allowed management "
        f"client cannot reach the Worker: {trusted_ssh.get('stderr') or 'no output'}",
    )

    management = (facts["untrusted"].get("management") or {})
    outcome = str(management.get("outcome") or "")
    require(
        MANAGEMENT_DENIAL_CASE_ID,
        outcome != "CONNECTED",
        f"the untrusted source at {untrusted} completed a TCP connection to the Worker's "
        f"control port {denial.NODE_PORT}, so the source allowlist is not in force",
    )
    require(
        MANAGEMENT_DENIAL_CASE_ID,
        outcome in ("REFUSED", "TIMEOUT"),
        f"the untrusted control-plane attempt ended {outcome or 'without a verdict'} "
        f"({management.get('detail') or 'no detail'}), which is "
        f"neither a refusal nor a dropped connection",
    )

    ssh = facts["untrusted"].get("ssh_login") or {}
    require(
        MANAGEMENT_DENIAL_CASE_ID,
        ssh.get("outcome") == "REJECTED",
        f"the untrusted identity's SSH login ended {ssh.get('outcome') or 'without a verdict'}"
        f" ({ssh.get('detail') or ssh.get('stderr') or 'no detail'}) instead of being "
        f"refused during authentication",
    )
    require(
        MANAGEMENT_DENIAL_CASE_ID,
        ssh.get("command_output") is False,
        "the untrusted identity executed a remote command on the Worker",
    )
    require(
        MANAGEMENT_DENIAL_CASE_ID,
        "permission denied" in str(ssh.get("stderr") or "").lower(),
        f"the refused login did not report a permission denial, so it was not "
        f"authentication that stopped it: {ssh.get('stderr') or 'no output'}",
    )

    require(
        MANAGEMENT_DENIAL_CASE_ID,
        untrusted != master,
        f"the untrusted role and the Master report the same address {master}, so this "
        f"denial cannot be attributed to the vantage",
    )
    if not facts["observed_source"]:
        # The refusal itself was measured and the rules are scoped, but the
        # Worker never named the address it refused: the catalog calls that
        # INCOMPLETE, because a missing observation is absent evidence rather
        # than a product failure the run can point at.
        raise CaseIncomplete(
            f"{MANAGEMENT_DENIAL_CASE_ID}: the Worker never logged the untrusted source "
            f"{untrusted} on its SSH port, so the address that was refused is unproven: "
            f"{facts['observed_lines'] or 'no matching line'}; sshd's last lines were "
            f"{facts.get('journal_tail') or 'none'}"
        )
    return {
        "input_policy": firewall["input_policy"],
        "node_allow_sources": ",".join(firewall["node_allow_sources"]),
        "ssh_port_open_to_any_source": firewall["ssh_anywhere"],
        "node_allow_packets": sum(
            int(entry.get("packets") or 0) for entry in firewall["counters"]
        ),
        "master_address": master,
        "worker_address": facts["worker_address"],
        "untrusted_address": untrusted,
        "trusted_mtls_response": trusted_mtls.get("status_line"),
        "trusted_ssh": "pinned host key, authorized identity",
        "untrusted_management": outcome,
        "untrusted_ssh": ssh.get("outcome"),
        "untrusted_ssh_returncode": ssh.get("returncode"),
        "worker_observed_source": facts["observed_source"],
        "worker_observation": (facts["observed_lines"] or [""])[-1][:300],
    }


def case_denial_classification(product: MultiNodeProduct) -> Dict[str, Any]:
    """FW-02: a refusal alone is not a firewall verdict.

    Connection refused, a timeout, a route failure, or a missing Worker all look
    identical from the vantage that was denied. The classification therefore
    requires the working control beside the refusal and the Worker's own rule and
    log evidence; anything less is INCOMPLETE rather than a pass, and an accepted
    connection is a finding of its own.
    """
    facts = product.denial_facts(DENIAL_CLASSIFICATION_CASE_ID)
    firewall = facts["firewall"]
    verdict, reason = denial.classify_denial(
        management_outcome=str(
            (facts["untrusted"].get("management") or {}).get("outcome") or ""
        ),
        positive_control=(
            facts["trusted_mtls"].get("handshake_pass") is True
            and facts["trusted_mtls"].get("response") == "health"
            and facts["trusted_ssh"].get("returncode") == 0
            and bool(facts["trusted_ssh"].get("marker"))
        ),
        worker_rule_scoped=(
            firewall["node_allow_sources"] == [facts["master_address"]]
            and not firewall["unscoped_allows"]
        ),
        observed_source=facts["observed_source"],
        allowed_source=facts["master_address"],
    )
    require(
        DENIAL_CLASSIFICATION_CASE_ID,
        verdict != denial.ACCEPTED,
        f"{DENIAL_CLASSIFICATION_CASE_ID}: {reason}",
    )
    if verdict == denial.AMBIGUOUS:
        raise CaseIncomplete(f"{DENIAL_CLASSIFICATION_CASE_ID}: {reason}")
    return {
        "verdict": verdict,
        "reason": reason,
        "allowed_source": facts["master_address"],
        "denied_source": facts["observed_source"],
        "classification_requires": "allowed control + Worker rule + observed source",
    }


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
        "api_inbound_tag": api[0].get("tag") if api else "",
        "api_inbound_type": api[0].get("type") if api else "",
        "api_inbound_listen": api[0].get("listen") if api else "",
        "api_services": ",".join(api_config.get("services") or []),
        "inbound_ports": ",".join(sorted({str(entry.get("port")) for entry in serving})),
        "inbound_tags": ",".join(sorted(str(entry.get("tag") or "") for entry in serving)),
        "outbound_count": applied.get("outbound_count"),
        "node_port": options.get("NODE_PORT"),
        "runtime_mode": runtime_mode,
        "config_mode": config_mode,
        "env_mode": env_mode,
    }


def case_vision_independence(product: MultiNodeProduct) -> Dict[str, Any]:
    """MN-VISION: each node provisions — and lacks — the Vision endpoint on its own.

    The four combinations are launched and counted elsewhere, but a count cannot
    tell one node's configuration from the other's: swapping the two nodes'
    Vision domains leaves every total unchanged. So each node is checked against
    its *own* Vision name — the Panel declaration and host bound to it, the
    certificate lineage, the NGINX stream route and vhost, and the config the
    node applied. The absent configuration is asserted as exactly as the present
    one, so a node that received its neighbour's endpoint fails.
    """
    product.require_worker()
    identity = vision_identity(product.matrix)
    port = identity["port"]
    target = "127.0.0.1:{};".format(port)
    cluster = product.cluster_facts(VISION_CASE_ID)

    nodes: Dict[str, Dict[str, Any]] = {}
    for record in (cluster.get("nodes") or {}).get("records") or []:
        if isinstance(record, dict):
            nodes[str(record.get("name") or "")] = record
    hosts = [
        record for record in (cluster.get("hosts") or {}).get("records") or []
        if isinstance(record, dict)
    ]

    planned = (
        ("master", LOCAL_NODE_NAME, topology.VISION_DOMAIN, bool(product.vision)),
        (
            "worker", topology.WORKER_NODE_NAME, topology.WORKER_VISION_DOMAIN,
            bool(product.worker_vision),
        ),
    )
    evidence: Dict[str, Any] = {
        "combination": product.combination,
        "vision_type": identity["type"],
        "vision_internal_port": port,
    }
    for node, name, domain, enabled in planned:
        record = nodes.get(name)
        require(
            VISION_CASE_ID,
            isinstance(record, dict),
            f"the Panel reports no node {name!r}; observed {sorted(nodes)}",
        )
        specs = [spec for spec in record.get("inbound_specs") or [] if isinstance(spec, dict)]
        declared = [spec for spec in specs if vision_matches(spec, identity)]
        digests = [
            digest
            for digest, spec in zip(record.get("inbounds") or [], specs)
            if vision_matches(spec, identity) and digest
        ]
        # Hosts reference their node by the digest the node record carries, not
        # by name, so the relation is proven the way the Panel stores it.
        uuid = str(record.get("uuid") or "")
        vision_hosts = [
            host for host in hosts
            if uuid and uuid in (host.get("nodes") or [])
            and domain in (host.get("address"), host.get("sni"))
        ]

        facts = product.node_vision_facts(VISION_CASE_ID, node, domain, port)
        certificate = facts.get("certificate") or {}
        routing = facts.get("nginx") or {}
        applied = facts.get("applied") or {}
        require(
            VISION_CASE_ID,
            applied.get("parsed") is True,
            f"the {node} node has no parseable applied config at "
            f"/run/gowave-node/xray.json, so the inbounds it serves cannot be observed",
        )
        loaded = [entry for entry in applied.get("inbounds") or [] if isinstance(entry, dict)]
        loaded_vision = [entry for entry in loaded if vision_matches(entry, identity)]
        routes = [route for route in routing.get("stream_routes") or [] if isinstance(route, dict)]
        targets = list(routing.get("stream_vision_targets") or [])
        vhosts = list(routing.get("vhost_files") or [])
        named = list(routing.get("vision_named_files") or [])

        evidence[f"{node}_domain"] = domain
        evidence[f"{node}_vision_enabled"] = enabled
        evidence[f"{node}_declared_vision_inbounds"] = len(declared)
        evidence[f"{node}_vision_hosts"] = len(vision_hosts)
        evidence[f"{node}_certificate"] = bool(certificate.get("present"))
        evidence[f"{node}_renewal_server"] = str(certificate.get("renewal_server") or "")
        evidence[f"{node}_stream_routes"] = ",".join(
            str(route.get("file") or "") for route in routes
        )
        evidence[f"{node}_vhosts"] = ",".join(vhosts)
        evidence[f"{node}_applied_inbounds"] = len(loaded)
        evidence[f"{node}_applied_vision_inbounds"] = len(loaded_vision)

        if enabled:
            require(
                VISION_CASE_ID,
                len(declared) == 1,
                f"the Panel declares {len(declared)} Vision inbounds for {name!r}, "
                f"expected exactly one: {describe_inbounds(specs)}",
            )
            require(
                VISION_CASE_ID,
                len(vision_hosts) == 1,
                f"{name!r} owns {len(vision_hosts)} Panel hosts under the Vision domain "
                f"{domain!r}, expected exactly one",
            )
            host = vision_hosts[0]
            require(
                VISION_CASE_ID,
                len(digests) == 1 and host.get("inbound") == digests[0],
                f"the Panel host under {domain!r} is bound to inbound "
                f"{host.get('inbound')!r} instead of the node's own Vision inbound "
                f"{digests[0] if digests else 'none'!r}",
            )
            observed = (
                host.get("address"), host.get("sni"), str(host.get("port")),
                host.get("security_layer"),
            )
            require(
                VISION_CASE_ID,
                observed == (domain, domain, "443", "TLS"),
                f"the Panel host under {domain!r} publishes {observed} instead of "
                f"{(domain, domain, '443', 'TLS')}",
            )
            require(
                VISION_CASE_ID,
                host.get("disabled") is False,
                f"the Vision host of {name!r} is disabled, so {domain!r} is published "
                f"but unusable",
            )
            require(
                VISION_CASE_ID,
                certificate.get("present") is True,
                f"{node} provisioned no certificate for {domain!r}: {certificate}",
            )
            require(
                VISION_CASE_ID,
                certificate.get("host_ok") is True,
                f"the {node} certificate for {domain!r} does not cover the name: "
                f"{certificate}",
            )
            require(
                VISION_CASE_ID,
                certificate.get("valid") is True,
                f"the {node} certificate for {domain!r} expires within a day: {certificate}",
            )
            require(
                VISION_CASE_ID,
                certificate.get("renewal_server") == acme_fixture.ACME_DIRECTORY_URL,
                f"the {node} renewal config asks {certificate.get('renewal_server')!r} "
                f"instead of this run's ACME directory "
                f"{acme_fixture.ACME_DIRECTORY_URL!r}",
            )
            require(
                VISION_CASE_ID,
                len(routes) == 1 and routes[0].get("target") == target,
                f"{node} routes {domain!r} to "
                f"{[route.get('target') for route in routes]} instead of exactly one "
                f"{target} route",
            )
            require(
                VISION_CASE_ID,
                bool(vhosts),
                f"{node} has no vhost naming {domain!r}, so nothing terminates TLS for "
                f"the domain on that node",
            )
            require(
                VISION_CASE_ID,
                len(loaded_vision) == 1,
                f"the {node} applied config carries {len(loaded_vision)} Vision inbounds "
                f"instead of one: {describe_inbounds(loaded)}",
            )
            continue

        require(
            VISION_CASE_ID,
            not declared,
            f"the Panel declares a Vision inbound for {name!r} although the run did not "
            f"configure one there: {describe_inbounds(declared)}",
        )
        require(
            VISION_CASE_ID,
            not vision_hosts,
            f"the Panel publishes {len(vision_hosts)} hosts under {domain!r} for {name!r} "
            f"although the run did not configure Vision there",
        )
        require(
            VISION_CASE_ID,
            certificate.get("present") is False,
            f"{node} holds a certificate for {domain!r} although the run did not "
            f"configure Vision there: {certificate}",
        )
        require(
            VISION_CASE_ID,
            not routes and not targets,
            f"{node} routes Vision traffic although the run did not configure it: "
            f"domain routes {routes}, {target} routes {targets}",
        )
        require(
            VISION_CASE_ID,
            not vhosts and not named,
            f"{node} keeps Vision vhosts although the run did not configure Vision: "
            f"naming {domain!r} {vhosts}, vision-named files {named}",
        )
        require(
            VISION_CASE_ID,
            not loaded_vision,
            f"the {node} applied config carries a Vision inbound although the run did "
            f"not configure one: {describe_inbounds(loaded_vision)}",
        )

    return evidence


def case_matrix(product: MultiNodeProduct) -> Dict[str, Any]:
    """MN-MATRIX: the positive cases are exactly the matrix tuples of both nodes.

    The count is an acceptance invariant, not an estimate: each node owes one
    case per inbound it was configured with times every client, so this run owes
    16 tuples with Vision on neither node, 18 with it on one, and 20 on both.
    Four ways the count can drift are each a failure here — the matrix declaring
    a number its own per-node inbounds and clients do not produce, a node that
    ran fewer clients than the matrix names (so one client never traversed it),
    a declared tuple that produced no result or did not pass, and a result
    outside the declared matrix being counted as green.
    """
    product.require_worker()
    data = product.matrix
    clients = matrix_data.clients(data)
    expected_ids: List[str] = []
    per_node: Dict[str, Dict[str, Any]] = {}
    for node, node_vision in (("master", product.vision), ("worker", product.worker_vision)):
        tuples = matrix_data.tuples(data, node_vision)
        node_ids = [
            matrix_data.case_id(
                data, matrix_data.MULTI_NODE, str(inbound["id"]), client, node=node,
            )
            for inbound, client in tuples
        ]
        node_clients = sorted({client for _inbound, client in tuples})
        require(
            MATRIX_CASE_ID,
            node_clients == sorted(clients),
            f"the {node} node ran {node_clients} instead of every matrix client "
            f"{sorted(clients)}, so a client never had to traverse that node",
        )
        per_node[node] = {
            "inbounds": len({str(inbound["id"]) for inbound, _client in tuples}),
            "clients": node_clients,
            "cases": len(node_ids),
        }
        expected_ids.extend(node_ids)

    declared = product.declared_data_plane
    executed = product.data_plane_results
    declared_count = product.positive_case_count
    require(
        MATRIX_CASE_ID,
        declared_count == len(expected_ids),
        f"the matrix declares {declared_count} positive case(s) for the "
        f"{product.combination} Vision configuration but its own per-node inbounds and "
        f"clients enumerate {len(expected_ids)} tuple(s), so one of the two is unexplained",
    )
    missing = [case_id for case_id in expected_ids if case_id not in declared]
    extra = [case_id for case_id in declared if case_id not in expected_ids]
    require(
        MATRIX_CASE_ID,
        not missing and not extra,
        f"the suite declares {len(declared)} data-plane case(s) that are not the matrix's "
        f"{len(expected_ids)}: missing {missing}, unexplained {extra}",
    )
    not_run = [case_id for case_id in expected_ids if case_id not in executed]
    require(
        MATRIX_CASE_ID,
        not not_run,
        f"{len(not_run)} matrix case(s) produced no result: {', '.join(not_run)}",
    )
    failed = sorted(case_id for case_id, status in executed.items() if status != "PASS")
    require(
        MATRIX_CASE_ID,
        not failed,
        f"{len(failed)} matrix case(s) did not pass: {', '.join(failed)}",
    )
    require(
        MATRIX_CASE_ID,
        len(executed) == declared_count,
        f"{len(executed)} data-plane case(s) ran, but the matrix declares {declared_count} for "
        f"the {product.combination} Vision configuration",
    )
    return {
        "vision": product.combination,
        "inbounds": product.expected_inbound_total,
        "clients": len(clients),
        "per_node": per_node,
        "expected_positive_cases": declared_count,
        "declared_cases": len(declared),
        "executed_cases": len(executed),
        "passed_cases": sum(1 for status in executed.values() if status == "PASS"),
    }


def case_egress(product: MultiNodeProduct) -> Dict[str, Any]:
    """MN-EGRESS: every payload is attributable to the node that carried it.

    The source address the endpoint records is the one fact a client cannot
    supply, so a cluster has to prove three things about it: the two nodes have
    distinct egress identities, every matrix payload left from the identity of
    the node its case names, and a direct attempt from either client role is
    refused and recorded as a denial under that role's own address. The last
    check is what gives the first two meaning — a fixture that accepted any
    source would let a client manufacture the evidence the matrix rests on.
    """
    host = product.require_worker()
    master_ip = str(host.plan.data_target_ip)
    worker_ip = str(host.plan.data_worker_ip)
    node_ids = sorted({master_ip, worker_ip})
    require(
        EGRESS_CASE_ID,
        len(node_ids) == 2,
        f"the Master and the Worker share the egress identity {master_ip!r}, so the address "
        "the endpoint records cannot attribute a payload to the node that carried it",
    )

    cases = data_plane_cases(product)
    sources = product.data_plane_sources
    unattributed = [case_id for case_id, _inbound, _client, _node in cases
                    if not sources.get(case_id)]
    require(
        EGRESS_CASE_ID,
        not unattributed,
        f"{len(unattributed)} matrix case(s) left no egress evidence: "
        f"{', '.join(unattributed)}",
    )
    per_node: Dict[str, Dict[str, Any]] = {}
    wrong: List[str] = []
    for case_id, _inbound, _client, node in cases:
        expected = str(host.node_data_ip(node))
        observed = sources.get(case_id, "")
        if observed != expected:
            wrong.append(
                f"{case_id} left from {observed or 'nowhere'} instead of the {node} node "
                f"{expected}"
            )
            continue
        tally = per_node.setdefault(node, {"identity": expected, "cases": 0})
        tally["cases"] += 1
    require(
        EGRESS_CASE_ID,
        not wrong,
        "the matrix payloads were attributed to the wrong node: " + "; ".join(wrong),
    )
    observed_ids = sorted({sources[case_id] for case_id, _inbound, _client, _node in cases})
    require(
        EGRESS_CASE_ID,
        observed_ids == node_ids,
        f"the matrix payloads left from {observed_ids} instead of exactly the two node "
        f"identities {node_ids}",
    )

    vantages = {
        "control": str(host.plan.client_ip),
        "engine": str(host.plan.engine_client_ip),
    }
    denials: Dict[str, Dict[str, Any]] = {}
    payload_sources: set = set()
    denied_sources: set = set()
    for vantage, identity in vantages.items():
        facts = product.direct_egress_facts(vantage)
        require(
            EGRESS_CASE_ID,
            not facts.get("accepted"),
            f"the {vantage} delivered a payload straight at the endpoint, so a client can "
            "manufacture the source evidence the matrix cases rest on",
        )
        require(
            EGRESS_CASE_ID,
            facts.get("status") == 403,
            f"the endpoint answered the {vantage} payload with {facts.get('status')!r} instead "
            f"of refusing it: {facts.get('reason', '')}",
        )
        require(
            EGRESS_CASE_ID,
            not facts.get("recorded"),
            f"the endpoint recorded the {vantage} payload although it refused it",
        )
        require(
            EGRESS_CASE_ID,
            facts.get("denied_recorded"),
            f"the endpoint refused the {vantage} payload without recording the denial, so the "
            "refusal exists only in the response",
        )
        denied_source = str(facts.get("denied_source_ip") or "")
        require(
            EGRESS_CASE_ID,
            denied_source == identity,
            f"the endpoint attributed the refused {vantage} payload to "
            f"{denied_source or 'no source'} instead of the {vantage} vantage {identity}",
        )
        require(
            EGRESS_CASE_ID,
            denied_source not in node_ids,
            f"the endpoint attributed the refused {vantage} payload to the node identity "
            f"{denied_source!r}, so a client attempt is indistinguishable from product traffic",
        )
        allowed = sorted(str(address) for address in facts.get("allowed_sources") or [])
        require(
            EGRESS_CASE_ID,
            allowed == node_ids,
            f"the endpoint accepts payloads from {allowed} instead of exactly the two node "
            f"identities {node_ids}",
        )
        payload_sources.update(str(item) for item in facts.get("payload_sources") or [])
        denied_sources.update(str(item) for item in facts.get("denied_sources") or [])
        denials[vantage] = {
            "identity": identity,
            "status": facts.get("status"),
            "source_ip": denied_source,
            "reason": facts.get("reason", ""),
        }

    require(
        EGRESS_CASE_ID,
        sorted(payload_sources) == node_ids,
        f"the endpoint's own record shows payloads from {sorted(payload_sources)} instead of "
        f"exactly the two node identities {node_ids}",
    )
    require(
        EGRESS_CASE_ID,
        set(vantages.values()) <= denied_sources,
        f"the endpoint recorded denials from {sorted(denied_sources)} instead of the two "
        f"client vantages {sorted(vantages.values())}",
    )
    require(
        EGRESS_CASE_ID,
        not (denied_sources & set(node_ids)),
        f"a node identity {sorted(denied_sources & set(node_ids))} appears among the "
        "endpoint's refusals, so the source allowlist is not the product's own",
    )

    return {
        "master_identity": master_ip,
        "worker_identity": worker_ip,
        "attributed_cases": len(cases),
        "per_node": per_node,
        "payload_sources": sorted(payload_sources),
        "denied_sources": sorted(denied_sources),
        "denials": denials,
    }


def case_worker_outage(product: MultiNodeProduct) -> Dict[str, Any]:
    """MN-OUTAGE: stopping the Worker degrades the cluster, and removing the fault restores it.

    One subscription is seen three times. It has to carry a payload *before* the
    fault, or a refusal afterwards says nothing about the fault. It has to be
    refused while the Worker's own unit is stopped and the Panel has noticed,
    while the Master keeps delivering — a cluster-wide silence would be an outage
    of the test rather than the degradation this case claims. And after the unit
    is started again the same captured payload has to transfer through the Worker
    once more, with no client re-import and no reseeding.

    The fault is the case's own to remove: the unit is restored even when a
    check fails, so a defect here cannot turn every later case into evidence
    about a cluster left broken.
    """
    host = product.require_worker()
    # Nothing is re-fetched after the fault: the client's payload is the one the
    # Panel issued while the cluster was still healthy.
    product.master.subscription_payloads(OUTAGE_CASE_ID)
    inbound, client = product.worker_tuple()

    baseline = product.node_transfer(
        OUTAGE_CASE_ID, "worker", inbound, client, expect_refusal=True,
    )
    require(
        OUTAGE_CASE_ID,
        baseline.get("delivered"),
        f"the Worker never carried a payload before the fault, so a refusal afterwards "
        f"would not be the outage's: {baseline.get('reason', '')}",
    )
    require(
        OUTAGE_CASE_ID,
        baseline.get("status") == 200
        and baseline.get("request_id_match")
        and baseline.get("body_match"),
        f"the Worker's baseline transfer returned {baseline.get('status')!r} without the "
        "endpoint echoing the payload",
    )
    require(
        OUTAGE_CASE_ID,
        baseline.get("source_ip") == host.plan.data_worker_ip,
        f"the baseline payload left from {baseline.get('source_ip')!r} instead of the "
        f"Worker's own data address {host.plan.data_worker_ip}, so it did not traverse it",
    )

    stopped = product.worker_service("stop", OUTAGE_CASE_ID)
    require(
        OUTAGE_CASE_ID,
        stopped.get("returncode") == 0,
        f"`systemctl stop {WORKER_UNIT}` on the Worker exited {stopped.get('returncode')!r}: "
        f"{stopped.get('detail') or 'no output'}",
    )
    require(
        OUTAGE_CASE_ID,
        stopped.get("state") != "active",
        f"{WORKER_UNIT} still reports {stopped.get('state')!r} after `systemctl stop`, so "
        "the Worker was never taken down",
    )

    offline_at = time.monotonic()
    try:
        product.wait_for_worker_connection(OUTAGE_CASE_ID, False, OUTAGE_TIMEOUT_SECONDS)
        degraded = product.cluster_facts(OUTAGE_CASE_ID)
        offline = panel_node(degraded, topology.WORKER_NODE_NAME, OUTAGE_CASE_ID)
        master_record = panel_node(degraded, LOCAL_NODE_NAME, OUTAGE_CASE_ID)
        require(
            OUTAGE_CASE_ID,
            master_record.get("connected") is True,
            "the Master's own node is reported offline too, so this is a cluster outage "
            "rather than the Worker's",
        )
        offline_seconds = round(time.monotonic() - offline_at, 1)

        refused = product.node_transfer(
            OUTAGE_CASE_ID, "worker", inbound, client, expect_refusal=True,
        )
        require(
            OUTAGE_CASE_ID,
            refused.get("delivered") is False,
            f"the stopped Worker still carried a payload through {inbound['id']} "
            f"(status {refused.get('status')!r}), so its unit was not what served it",
        )

        master_inbound, master_client = product.master_tuple()
        control = product.node_transfer(
            OUTAGE_CASE_ID, "master", master_inbound, master_client, expect_refusal=True,
        )
        require(
            OUTAGE_CASE_ID,
            control.get("delivered")
            and control.get("status") == 200
            and control.get("request_id_match")
            and control.get("body_match"),
            f"the Master stopped delivering at the same time as the Worker, so the "
            f"refusal cannot be attributed to the Worker: {control.get('reason', '')}",
        )
    finally:
        restored = product.worker_service("start", OUTAGE_CASE_ID)

    require(
        OUTAGE_CASE_ID,
        restored.get("returncode") == 0 and restored.get("state") == "active",
        f"`systemctl start {WORKER_UNIT}` left the Worker at {restored.get('state')!r} "
        f"(exit {restored.get('returncode')!r}): {restored.get('detail') or 'no output'}",
    )

    recovered_at = time.monotonic()
    product.wait_for_worker_connection(OUTAGE_CASE_ID, True, RESTART_TIMEOUT_SECONDS)
    # A connected node is not yet a serving one: the Master's own control dial has
    # to come back before the Panel can re-apply the Worker's users.
    healthy = product.wait_for_worker_peer(OUTAGE_CASE_ID, RESTART_TIMEOUT_SECONDS)

    attempt: Dict[str, Any] = {}

    def delivers() -> bool:
        facts = product.node_transfer(
            OUTAGE_CASE_ID, "worker", inbound, client, expect_refusal=True,
        )
        attempt.clear()
        attempt.update(facts)
        return (
            bool(facts.get("delivered"))
            and facts.get("status") == 200
            and bool(facts.get("request_id_match"))
            and bool(facts.get("body_match"))
        )

    delivered = wait_until(
        delivers, RESTART_TIMEOUT_SECONDS,
        f"{OUTAGE_CASE_ID} Worker data plane after recovery",
        interval_seconds=RECOVERY_INTERVAL_SECONDS,
    )
    require(
        OUTAGE_CASE_ID,
        delivered,
        f"the Worker never carried the same subscription again within "
        f"{RESTART_TIMEOUT_SECONDS}s of its unit coming back: "
        f"{attempt.get('reason') or attempt.get('status') or 'no transfer completed'}",
    )
    require(
        OUTAGE_CASE_ID,
        attempt.get("source_ip") == host.plan.data_worker_ip,
        f"the recovered payload left from {attempt.get('source_ip')!r} instead of the "
        f"Worker's data address {host.plan.data_worker_ip}",
    )
    return {
        "worker_inbound": inbound["id"],
        "worker_client": client,
        "baseline_status": baseline.get("status"),
        "baseline_source_ip": baseline.get("source_ip"),
        "worker_unit_after_stop": stopped.get("state"),
        "worker_unit_after_start": restored.get("state"),
        "panel_worker_offline": offline.get("connected") is False,
        "panel_master_connected": master_record.get("connected") is True,
        "offline_seconds": offline_seconds,
        "refused_status": refused.get("status"),
        "refused_reason": (refused.get("reason") or "")[:160],
        "master_control_status": control.get("status"),
        "master_control_source_ip": control.get("source_ip"),
        "control_peers": ",".join(healthy.get("peers") or []),
        "control_plane_seconds": healthy.get("peer_wait_seconds"),
        "recovered_source_ip": attempt.get("source_ip"),
        "recovery_seconds": round(time.monotonic() - recovered_at, 1),
    }


def case_worker_restart(product: MultiNodeProduct) -> Dict[str, Any]:
    """MN-RESTART: restarting the Worker's unit is maintenance, not a re-registration.

    The restart is bounded the way an operator would bound it, and the Panel's
    own record is what proves the node stayed the node: the same registry uuid,
    endpoint, assigned inbounds and version, connected again. The main PID is read
    on the Worker itself, because a Panel that never noticed the blip would let
    the whole case pass without a restart ever happening. The subscription
    captured before the restart then has to carry a payload through the Worker
    again — no client re-import, no new credentials, no reseeding.
    """
    host = product.require_worker()
    product.master.subscription_payloads(RESTART_CASE_ID)
    inbound, client = product.worker_tuple()
    before = product.wait_for_worker_report(RESTART_CASE_ID)
    before_pid = product.worker_main_pid(RESTART_CASE_ID)
    require(
        RESTART_CASE_ID,
        before_pid not in ("", "0"),
        f"the Worker's unit reported no main PID before the restart ({before_pid!r}), so the "
        "restart could not be told from a unit that was never running",
    )

    restarted = product.worker_service("restart", RESTART_CASE_ID)
    require(
        RESTART_CASE_ID,
        restarted.get("returncode") == 0,
        f"`systemctl restart {WORKER_UNIT}` on the Worker exited {restarted.get('returncode')!r}: "
        f"{restarted.get('detail') or 'no output'}",
    )
    require(
        RESTART_CASE_ID,
        restarted.get("state") == "active",
        f"{WORKER_UNIT} reports {restarted.get('state')!r} right after the restart",
    )
    require(
        RESTART_CASE_ID,
        restarted.get("main_pid") not in ("", "0", before_pid),
        f"{WORKER_UNIT} kept main PID {before_pid!r} across the restart, so no new node "
        "process was started",
    )

    after = product.wait_for_worker_connection(RESTART_CASE_ID, True, RESTART_TIMEOUT_SECONDS)
    changed = [
        f"{field}: {before.get(field)!r} -> {after.get(field)!r}"
        for field in ("uuid", "address", "port", "profile")
        if before.get(field) != after.get(field)
    ]
    require(
        RESTART_CASE_ID,
        not changed,
        "the restart re-registered the Worker instead of restarting it: " + "; ".join(changed),
    )
    require(
        RESTART_CASE_ID,
        (after.get("inbounds") or []) == (before.get("inbounds") or []),
        f"the Panel now assigns the Worker {after.get('inbounds')} instead of the "
        f"{before.get('inbounds')} it was serving",
    )
    require(
        RESTART_CASE_ID,
        (after.get("versions") or {}).get("node") == (before.get("versions") or {}).get("node"),
        f"the Panel records the Worker's node version as "
        f"{(after.get('versions') or {}).get('node')!r} after the restart, was "
        f"{(before.get('versions') or {}).get('node')!r}",
    )
    require(
        RESTART_CASE_ID,
        not (after.get("state") or {}).get("status_message"),
        f"the Panel records a node status message after the restart: "
        f"{(after.get('state') or {}).get('status_message')!r}",
    )
    # The Panel's flag survives a restart this short, so the dial has to be seen on
    # the Worker itself before the case may call the control plane recovered.
    healthy = product.wait_for_worker_peer(RESTART_CASE_ID, RESTART_TIMEOUT_SECONDS)

    recovered_at = time.monotonic()
    attempt: Dict[str, Any] = {}

    def delivers() -> bool:
        facts = product.node_transfer(
            RESTART_CASE_ID, "worker", inbound, client, expect_refusal=True,
        )
        attempt.clear()
        attempt.update(facts)
        return (
            bool(facts.get("delivered"))
            and facts.get("status") == 200
            and bool(facts.get("request_id_match"))
            and bool(facts.get("body_match"))
        )

    delivered = wait_until(
        delivers, RESTART_TIMEOUT_SECONDS,
        f"{RESTART_CASE_ID} Worker data plane after the restart",
        interval_seconds=RECOVERY_INTERVAL_SECONDS,
    )
    require(
        RESTART_CASE_ID,
        delivered,
        f"the Worker never carried the subscription captured before the restart within "
        f"{RESTART_TIMEOUT_SECONDS}s: "
        f"{attempt.get('reason') or attempt.get('status') or 'no transfer completed'}",
    )
    require(
        RESTART_CASE_ID,
        attempt.get("source_ip") == host.plan.data_worker_ip,
        f"the recovered payload left from {attempt.get('source_ip')!r} instead of the "
        f"Worker's data address {host.plan.data_worker_ip}",
    )
    return {
        "worker_inbound": inbound["id"],
        "worker_client": client,
        "unit_after_restart": restarted.get("state"),
        "main_pid_before": before_pid,
        "main_pid_after": restarted.get("main_pid"),
        "panel_node_uuid": str(after.get("uuid") or ""),
        "panel_node_endpoint": f"{after.get('address')}:{after.get('port')}",
        "panel_inbound_count": len(after.get("inbounds") or []),
        "panel_node_version": (after.get("versions") or {}).get("node"),
        "control_peers": ",".join(healthy.get("peers") or []),
        "control_plane_seconds": healthy.get("peer_wait_seconds"),
        "recovered_status": attempt.get("status"),
        "recovered_source_ip": attempt.get("source_ip"),
        "recovery_seconds": round(time.monotonic() - recovered_at, 1),
    }


def data_plane_case(
    product: MultiNodeProduct, inbound: Dict[str, Any], client: str, node: str,
) -> Dict[str, Any]:
    """Run one matrix tuple and keep the address its payload actually left from.

    The shared body already records the tuple's verdict for the count case; the
    source address is the separate fact the egress case needs, so a Worker tuple
    that left from the Master's address is caught by name instead of passing on
    the strength of a 200.
    """
    evidence = aio._data_plane_case(product.master, inbound, client, node=node)
    case_id = matrix_data.case_id(
        product.matrix, matrix_data.MULTI_NODE, str(inbound["id"]), client, node=node,
    )
    product.record_data_plane_source(case_id, str(evidence.get("source_ip") or ""))
    return evidence


def data_plane_cases(product: MultiNodeProduct) -> List[Tuple[str, Dict[str, Any], str, str]]:
    """Every matrix tuple this cluster owes: each node's inbounds, both clients.

    The node is part of the tuple, not of the payload: both nodes serve the same
    transport/security pairs, so a case that named only the pair would run
    whichever outbound matched first. Each node contributes the inbounds its own
    Vision configuration gave it, which is what makes the count 16, 18 or 20.
    """
    cases = []
    for node, node_vision in (("master", product.vision), ("worker", product.worker_vision)):
        for inbound, client in matrix_data.tuples(product.matrix, node_vision):
            case_id = matrix_data.case_id(
                product.matrix, matrix_data.MULTI_NODE, str(inbound["id"]), client, node=node,
            )
            cases.append((case_id, inbound, client, node))
    return cases


def cases(
    podman: Any, distribution: str = "ubuntu-24.04",
    vision: bool = False, worker_vision: bool = False,
) -> List[Case]:
    """The Multi-Node suite: install, Worker provisioning, then observation."""
    product = MultiNodeProduct(
        podman, distribution, vision=vision, worker_vision=worker_vision,
    )
    data_plane = data_plane_cases(product)
    product.declare_data_plane([case_id for case_id, _inbound, _client, _node in data_plane])
    suite = [
        Case(INSTALL_CASE_ID, "multi-node", lambda context: product.install(),
             timeout_seconds=aio.INSTALL_TIMEOUT_SECONDS),
        # The trust the provisioning path depends on is proven before that path
        # runs: a wrong pin and a rotated host key must both stop the controller.
        Case(SSH_KEY_CASE_ID, "multi-node", lambda context: case_ssh_host_key(product),
             timeout_seconds=SSH_TRUST_TIMEOUT_SECONDS),
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
        Case(MANAGEMENT_DENIAL_CASE_ID, "multi-node",
             lambda context: case_management_denial(product),
             timeout_seconds=DENIAL_TIMEOUT_SECONDS),
        Case(DENIAL_CLASSIFICATION_CASE_ID, "multi-node",
             lambda context: case_denial_classification(product),
             timeout_seconds=DENIAL_TIMEOUT_SECONDS),
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
        Case(VISION_CASE_ID, "multi-node", lambda context: case_vision_independence(product),
             timeout_seconds=CLUSTER_TIMEOUT_SECONDS),
    ]
    for case_id, inbound, client, node in data_plane:
        suite.append(Case(
            case_id, "multi-node",
            lambda context, inbound=inbound, client=client, node=node: data_plane_case(
                product, inbound, client, node),
            timeout_seconds=aio.DATA_PLANE_TIMEOUT_SECONDS,
        ))
    # The count case closes the matrix: it reads the verdicts the tuples above
    # recorded, so it runs once every one of them had its chance to report.
    suite.append(Case(
        MATRIX_CASE_ID, "multi-node", lambda context: case_matrix(product),
        timeout_seconds=MATRIX_TIMEOUT_SECONDS,
    ))
    # Attribution reads what the tuples left behind, so it belongs immediately
    # after the count and before any lifecycle case revokes a client.
    suite.append(Case(
        EGRESS_CASE_ID, "multi-node", lambda context: case_egress(product),
        timeout_seconds=EGRESS_TIMEOUT_SECONDS,
    ))
    suite.extend([
        Case("SUB-SERVED", "multi-node", lambda context: aio.case_subscriptions(product.master),
             timeout_seconds=SUB_SERVED_TIMEOUT_SECONDS),
        Case("SUB-B64", "multi-node", lambda context: aio.case_share_links(product.master),
             timeout_seconds=SUB_SHARE_LINK_TIMEOUT_SECONDS),
        # The lifecycle cases run last: they revoke a client and fault the
        # Worker's own unit, so nothing that observes a healthy cluster may run
        # after them and no earlier case may be blamed for their state.
        Case(REVOCATION_CASE_ID, "multi-node",
             lambda context: aio.case_revocation(
                 product.master, REVOCATION_CASE_ID,
                 expected_sources=product.expected_egress_sources(),
             ),
             timeout_seconds=aio.TUNNEL_READY_TIMEOUT_SECONDS + 2 * aio.TRAFFIC_TIMEOUT_SECONDS),
        Case(OUTAGE_CASE_ID, "multi-node", lambda context: case_worker_outage(product),
             timeout_seconds=OUTAGE_CASE_TIMEOUT_SECONDS),
        Case(RESTART_CASE_ID, "multi-node", lambda context: case_worker_restart(product),
             timeout_seconds=RESTART_CASE_TIMEOUT_SECONDS),
    ])
    return suite
