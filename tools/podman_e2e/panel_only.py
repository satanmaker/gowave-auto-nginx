"""The Panel-only product E2E.

``gowave-auto.sh install --panel-only`` deploys the Panel and the static
camouflage site and leaves the host without a traffic plane: no GoWave Node, no
Xray, and no inbound listener. This module owns the cases that prove that shape
from inside the disposable host, the Panel API and ``state.json`` an install
leaves behind, and the squad the first ``node add`` has to create.

The vantage rule is the All-in-One one. Host-side facts (units, sockets,
binaries, ``state.json``) are read on the host under test; anything a client can
observe (the Panel and the decoy over 443) is read from the Control Machine,
which has no product code on it. The registration runs through the operator's
own ``node add`` against a second clean host, because a Panel-only deployment
has no local node and a registration no host could receive proves nothing.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from tools.live_vps.versions import output_matches_expected_version, version_token

from . import aio, ingress_matrix, topology
from . import matrix as matrix_data
from .runner import Case, CaseBlocked, require

INSTALL_CASE_ID = "PO-INSTALL"
HOST_CASE_ID = "PO-HOST"
API_CASE_ID = "PO-API"
SQUAD_CASE_ID = "PO-SQUAD"
SQUAD_REFUSED_CASE_ID = "PO-SQUAD-REFUSED"
ADD_NODE_REFUSED_CASE_ID = "MN-ADD-NODE-REFUSED"

# The install downloads releases, resolves packages and issues two certificates.
INSTALL_TIMEOUT_SECONDS = aio.INSTALL_TIMEOUT_SECONDS
# The registration deploys a whole Worker over SSH; the ceiling is a hang guard.
REGISTRATION_TIMEOUT_SECONDS = topology.NODE_ADD_TIMEOUT_SECONDS
PROBE_TIMEOUT_SECONDS = 300

STATE_FILE = "/var/lib/gowave-auto-nginx/state.json"
WORKER_BINARIES = (
    "/opt/gowave-node/gowave-node",
    "/usr/local/bin/gowave-node",
    "/opt/gowave-node/rw-core",
)
# The two ports a traffic plane listens on. A Panel-only host has no backend to
# bind them, and a listener on either one is the deployment, not a script, that
# says otherwise.
TRAFFIC_PORTS = ("8443", "8444")

# Read on the host: the units, the sockets, the binaries that should not exist,
# the rendered configuration. Nothing here writes, so the case runs before the
# registration adds API state to the same host.
HOST_SHAPE_SCRIPT = (
    "systemctl is-active gowave.service nginx.service fail2ban.service || true\n"
    "echo '==unit'\n"
    "systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null"
    " | awk '{print $1}' | grep -x 'gowave-node.service' | wc -l\n"
    "echo '==listeners'\n"
    "ss -H -ltn 2>/dev/null | awk '{print $4}' | sort -u || true\n"
    "echo '==processes'\n"
    "ps -eo comm= 2>/dev/null | grep -x -E 'rw-core|xray' | wc -l || true\n"
    "echo '==binaries'\n"
    + "".join(f"test -e {path} && echo {path}\n" for path in WORKER_BINARIES)
    + "echo '==credentials'\n"
    "stat -c '%a %U %G' /root/gowave-credentials.txt 2>/dev/null || echo 'absent'\n"
    "grep -cE '^(ADMIN_USERNAME|ADMIN_PASSWORD|SCOPED_API_TOKEN)=' "
    "/root/gowave-credentials.txt 2>/dev/null || echo 0\n"
    "echo '==lineages'\n"
    "certbot certificates 2>/dev/null | sed -n 's/.*Certificate Name: //p' | sort\n"
    "echo '==nginx'\n"
    "nginx -t 2>&1; echo \"nginx_t=$?\"\n"
)

# Read on the host: what a Panel-only install leaves in ``state.json``. The file
# is the product's own record, so a key it must not hold is as load-bearing as
# the mode it must name.
STATE_SHAPE_SCRIPT = r"""
python3 - <<'PY'
import json
from pathlib import Path

state = json.loads(Path("__STATE__").read_text(encoding="utf-8"))
nodes = state.get("nodes")
print(json.dumps({
    "schema_version": state.get("schemaVersion"),
    "installation_mode": str(state.get("installationMode") or ""),
    "nodes_is_list": isinstance(nodes, list),
    "node_count": len(nodes) if isinstance(nodes, list) else -1,
    "local_node_keys": sorted(
        key for key in ("localNodeUuid", "nodePort", "profileUuid", "inboundUuid")
        if key in state
    ),
    "state_keys": sorted(str(key) for key in state),
}, sort_keys=True))
PY
""".replace("__STATE__", STATE_FILE)

# Read on the host after the registration: the squad the Panel holds, the host
# records that name it, and what ``state.json`` stored. Identifiers are reduced
# to a length and a comparison, never printed.
SQUAD_FACTS_SCRIPT = r"""
python3 - <<'PY'
import json
import sys
from pathlib import Path

sys.path.insert(0, "/repo/tools/podman_e2e")
from panel_surface import Panel, items, login, read_credentials

STATE = Path("__STATE__")
CREDENTIALS = Path("/root/gowave-credentials.txt")
MVP_SQUAD = "Default MVP Squad"

state = json.loads(STATE.read_text(encoding="utf-8"))
squad = str(state.get("squadUuid") or "")
username, password = read_credentials(CREDENTIALS)
panel = Panel("http://127.0.0.1:3000")
login(panel, username, password)

hosts_status, hosts_body = panel.call("GET", "/api/hosts")
hosts = [host for host in items(hosts_body, "hosts") if isinstance(host, dict)]
entries = []
modes = set()
nulls = 0
without = 0
naming = 0
for host in hosts:
    policy = host.get("internalSquads") if isinstance(host.get("internalSquads"), dict) else {}
    squads = policy.get("squads") if isinstance(policy.get("squads"), list) else []
    entries.append(len(squads))
    modes.add(str(policy.get("mode") or ""))
    nulls += sum(1 for entry in squads if not entry)
    if not squads:
        without += 1
    if squad and squads == [squad]:
        naming += 1

squads_status, squads_body = panel.call("GET", "/api/internal-squads")
squads_list = [item for item in items(squads_body, "internalSquads") if isinstance(item, dict)]
mvp = next((item for item in squads_list if item.get("name") == MVP_SQUAD), None)
mvp_inbounds = mvp.get("inbounds") if isinstance(mvp, dict) else None

nodes_status, nodes_body = panel.call("GET", "/api/nodes")
nodes = [node for node in items(nodes_body, "nodes") if isinstance(node, dict)]

print(json.dumps({
    "state_squad_present": bool(squad),
    "state_squad_length": len(squad),
    "nodes_in_state": len(state.get("nodes") or []),
    "hosts_status": hosts_status,
    "host_count": len(hosts),
    "host_squad_entries": entries,
    "host_squad_modes": sorted(mode for mode in modes if mode),
    "hosts_with_null_squad": nulls,
    "hosts_without_squad": without,
    "hosts_naming_state_squad": naming,
    "squads_status": squads_status,
    "squad_count": len(squads_list),
    "mvp_squad_present": mvp is not None,
    "mvp_squad_inbound_count": len(mvp_inbounds) if isinstance(mvp_inbounds, list) else -1,
    "nodes_status": nodes_status,
    "panel_node_count": len(nodes),
    "panel_node_names": sorted(str(node.get("name") or "") for node in nodes),
}, sort_keys=True))
PY
""".replace("__STATE__", STATE_FILE)

# The negative half, with its control. The same host payload is posted twice: once
# with the squad the Panel holds, which has to be accepted, and once with a null
# entry in that squad list, which must not be. The control is what makes the
# refusal attributable — a Panel that refused both would be refusing the payload
# shape, not the defect.
REFUSED_PAYLOAD_SCRIPT = r"""
python3 - <<'PY'
import json
import sys
import uuid
from pathlib import Path

sys.path.insert(0, "/repo/tools/podman_e2e")
from panel_surface import Panel, items, login, payload, read_credentials

STATE = Path("__STATE__")
CREDENTIALS = Path("/root/gowave-credentials.txt")

state = json.loads(STATE.read_text(encoding="utf-8"))
squad = str(state.get("squadUuid") or "")
username, password = read_credentials(CREDENTIALS)
panel = Panel("http://127.0.0.1:3000")
login(panel, username, password)

def host_count() -> int:
    status, body = panel.call("GET", "/api/hosts")
    return len([host for host in items(body, "hosts") if isinstance(host, dict)])

before = host_count()
status, body = panel.call("GET", "/api/hosts")
hosts = [host for host in items(body, "hosts") if isinstance(host, dict)]
source = hosts[0] if hosts else {}
inbound = source.get("inbound") if isinstance(source.get("inbound"), dict) else {}
nodes = source.get("nodes") if isinstance(source.get("nodes"), list) else []
node_ids = [entry.get("uuid") if isinstance(entry, dict) else entry for entry in nodes]
remark = "REFUSED-PROBE@" + uuid.uuid4().hex[:8]

base = {
    "inbound": {
        "configProfileUuid": inbound.get("configProfileUuid"),
        "configProfileInboundUuid": inbound.get("configProfileInboundUuid"),
    },
    "nodes": [node for node in node_ids if node],
    "remark": remark,
    "address": source.get("address"),
    "port": int(source.get("port") or 443),
    "sni": source.get("sni"),
    "path": source.get("path"),
    "host": source.get("host"),
    "alpn": source.get("alpn"),
    "fingerprint": source.get("fingerprint"),
    "securityLayer": source.get("securityLayer"),
    "isDisabled": False,
}

control_status, control = panel.call(
    "POST", "/api/hosts", dict(base, internalSquads={"mode": "ALLOW_ONLY", "squads": [squad]})
)
created = payload(control)
control_uuid = created.get("uuid") if isinstance(created, dict) else None
after_control = host_count()
delete_status = None
if control_uuid:
    delete_status, _ = panel.call("DELETE", "/api/hosts/" + str(control_uuid))
after_delete = host_count()

refused_status, refused = panel.call(
    "POST", "/api/hosts", dict(base, internalSquads={"mode": "ALLOW_ONLY", "squads": [None]})
)
created_refused = payload(refused)
refused_uuid = created_refused.get("uuid") if isinstance(created_refused, dict) else None
after_refused = host_count()

# What the Panel did with the null entry, if it took the record at all: the
# question a refused payload must answer is whether it still handed the operator
# the squad, and only the stored record can say.
accepted_entries = 0
accepted_nulls = 0
accepted_naming = 0
refused_cleanup_status = None
if refused_uuid:
    status, body = panel.call("GET", "/api/hosts")
    record = next(
        (host for host in items(body, "hosts")
         if isinstance(host, dict) and host.get("uuid") == refused_uuid),
        {},
    )
    policy = record.get("internalSquads") if isinstance(record.get("internalSquads"), dict) else {}
    squads = policy.get("squads") if isinstance(policy.get("squads"), list) else []
    accepted_entries = len(squads)
    accepted_nulls = sum(1 for entry in squads if not entry)
    accepted_naming = 1 if squad and squads == [squad] else 0
    refused_cleanup_status, _ = panel.call("DELETE", "/api/hosts/" + str(refused_uuid))
after_refused_cleanup = host_count()

print(json.dumps({
    "squad_present": bool(squad),
    "hosts_before": before,
    "control_status": control_status,
    "control_created": bool(control_uuid),
    "hosts_after_control": after_control,
    "delete_status": delete_status,
    "hosts_after_delete": after_delete,
    "refused_status": refused_status,
    "refused_created": bool(refused_uuid),
    "refused_body_keys": sorted(str(key) for key in refused) if isinstance(refused, dict) else [],
    "hosts_after_refused": after_refused,
    "accepted_squad_entries": accepted_entries,
    "accepted_squad_nulls": accepted_nulls,
    "accepted_naming_state_squad": accepted_naming,
    "refused_cleanup_status": refused_cleanup_status,
    "hosts_after_refused_cleanup": after_refused_cleanup,
}, sort_keys=True))
PY
""".replace("__STATE__", STATE_FILE)


class PanelOnlyProduct(aio.AioProduct):
    """One disposable Panel-only host, installed once, plus the Worker it is given."""

    # The matrix topology this install's case ids are named after.
    case_topology = "panel-only"

    def __init__(self, podman: Any, distribution: str = "ubuntu-24.04") -> None:
        super().__init__(
            podman, distribution, vision=False, install_case_id=INSTALL_CASE_ID,
        )
        self.node_add_outcome: Optional[topology.InstallOutcome] = None
        self.trust: Dict[str, Any] = {}

    # ------------------------------------------------------------------ install
    def install(self) -> Dict[str, Any]:
        """Create the roles and run the operator's Panel-only install exactly once.

        The Worker is created before the install because the run declares it: a
        role a later case needs must exist before the install is asked to
        succeed, and a missing vantage would turn the registration's own evidence
        into a probe of nothing.
        """
        if self.host is not None:
            raise AssertionError(
                f"{self.install_case_id}: the host is installed once per run and reused by later cases"
            )
        host = topology.PanelOnlyTopology(self.podman, distribution=self.distribution)
        host.create()
        host.require_roles()
        self.host = host
        self.outcome = host.install()
        require(
            self.install_case_id,
            self.outcome.ok,
            f"the operator Panel-only install failed with exit {self.outcome.returncode}:\n"
            f"{self.outcome.tail(6000)}",
        )
        record = host.evidence(self.outcome)
        record.update(self.require_panel_version())
        return record

    def require_panel_version(self) -> Dict[str, str]:
        """The Panel reports the version this deployment configured.

        The All-in-One install case asks the Node and the core the same question
        because it installs them. A Panel-only host installs neither, so their
        absence is asserted by the host case instead of being reported here as a
        probe that failed.
        """
        report = self.installed_versions()
        facts = report.get("panel") or {}
        output = f"{facts.get('stdout') or ''}\n{facts.get('stderr') or ''}"
        expected = matrix_data.product(self.matrix).get("panel_version", "")
        require(
            self.install_case_id,
            bool(facts.get("binary")),
            "the Panel binary is installed at no documented path, so its version cannot be recorded",
        )
        require(
            self.install_case_id,
            facts.get("returncode") == 0 and bool(version_token(output)),
            f"`{facts.get('argv') or 'panel'}` printed no version: {output.strip()[:300]!r}",
        )
        require(
            self.install_case_id,
            output_matches_expected_version(output, expected),
            f"the installed Panel reports {output.strip()[:200]!r} while this deployment "
            f"configured {expected!r}",
        )
        return {
            "panel_version": version_token(output),
            "panel_version_expected": expected,
            "panel_version_binary": str(facts.get("binary") or ""),
        }

    # --------------------------------------------------------------- node add
    def add_worker(self) -> Dict[str, Any]:
        """Pin the Worker's trust and register it through the operator's own command."""
        host = self.require_installed()
        self.trust = host.pin_worker_trust()
        outcome = host.node_add()
        self.node_add_outcome = outcome
        require(
            SQUAD_CASE_ID,
            outcome.ok,
            f"the operator node add failed with exit {outcome.returncode}:\n"
            f"{outcome.tail(6000)}",
        )
        return {
            "node_add_command": outcome.command,
            "node_add_duration_seconds": round(outcome.duration, 1),
            "worker_trust": self.trust,
        }

    def squad_facts(self, case_id: str) -> Dict[str, Any]:
        host = self.require_installed()
        result = self.podman.exec_bash(
            host.target_name, SQUAD_FACTS_SCRIPT, check=False, timeout=PROBE_TIMEOUT_SECONDS,
        )
        require(
            case_id,
            result.returncode == 0,
            f"the squad probe exited {result.returncode}: "
            f"{(result.stderr or result.stdout or '').strip()[-2000:]}",
        )
        try:
            facts = json.loads(result.stdout or "")
        except json.JSONDecodeError:
            facts = None
        require(
            case_id,
            isinstance(facts, dict),
            f"the squad probe printed no JSON object: {(result.stdout or '')[:400]}",
        )
        return facts or {}


# ---------------------------------------------------------------------- cases
def case_host_shape(product: PanelOnlyProduct) -> Dict[str, Any]:
    """PO-HOST: the Panel and the decoy are here, and the traffic plane is not.

    Read from the host twice over: the units and sockets the product manages,
    and the public surface a client reaches on 443. A missing Node unit is a
    fact this case asserts rather than tolerates, and ``nginx -t`` is the
    product's own verdict on the configuration it just wrote.
    """
    host = product.require_installed()
    result = product.host_script(HOST_SHAPE_SCRIPT)
    require(
        HOST_CASE_ID,
        result.returncode == 0,
        f"the host shape probe exited {result.returncode}: {(result.stderr or '').strip()[-2000:]}",
    )
    sections: Dict[str, str] = {}
    current = ""
    for line in (result.stdout or "").splitlines():
        if line.startswith("=="):
            current = line.strip("= ").strip()
            sections[current] = ""
            continue
        sections[current] = sections.get(current, "") + line + "\n"

    states = sections.get("", "").split()
    unit_names = ("gowave.service", "nginx.service", "fail2ban.service")
    units = dict(zip(unit_names, states))
    not_active = sorted(name for name, state in units.items() if state != "active")
    require(
        HOST_CASE_ID,
        len(states) == len(unit_names) and not not_active,
        "units are not active: " + ", ".join(f"{name}={units.get(name)}" for name in not_active),
    )

    node_units = sections.get("unit", "").strip()
    require(
        HOST_CASE_ID,
        node_units == "0",
        f"the host declares a gowave-node.service unit ({node_units!r} matching files), "
        "and a Panel-only install has no node to supervise",
    )

    addresses = [line.strip() for line in sections.get("listeners", "").splitlines() if line.strip()]
    traffic = sorted(
        addr for addr in addresses if any(addr.endswith(":" + port) for port in TRAFFIC_PORTS)
    )
    require(HOST_CASE_ID, not traffic, f"the host listens on a traffic-plane port: {traffic}")
    require(
        HOST_CASE_ID,
        any(addr.startswith("127.0.0.1:3000") for addr in addresses),
        f"the Panel is not listening on 127.0.0.1:3000: {addresses}",
    )
    require(
        HOST_CASE_ID,
        any(addr.endswith(":443") and not addr.startswith("127.0.0.1") for addr in addresses),
        f"NGINX is not listening publicly on 443: {addresses}",
    )

    processes = sections.get("processes", "").strip()
    require(
        HOST_CASE_ID,
        processes in ("", "0"),
        f"{processes} rw-core/xray process(es) are running on a Panel-only host",
    )
    binaries = [line.strip() for line in sections.get("binaries", "").splitlines() if line.strip()]
    require(
        HOST_CASE_ID,
        not binaries,
        f"the traffic plane's binaries are installed on a Panel-only host: {binaries}",
    )

    nginx = sections.get("nginx", "")
    require(
        HOST_CASE_ID,
        "nginx_t=0" in nginx and "test is successful" in nginx,
        f"`nginx -t` did not accept the rendered configuration: {nginx.strip()[-600:]!r}",
    )

    credentials = [line.strip() for line in sections.get("credentials", "").splitlines() if line.strip()]
    require(
        HOST_CASE_ID,
        len(credentials) == 2 and credentials[0] == "600 root root",
        f"the credentials file is {credentials[:1] or 'absent'} instead of 600 root root",
    )
    require(
        HOST_CASE_ID,
        credentials[-1].isdigit() and int(credentials[-1]) >= 3,
        f"the credentials file holds {credentials[-1:]!r} of the three documented keys",
    )

    lineages = [line.strip() for line in sections.get("lineages", "").splitlines() if line.strip()]
    expected_lineages = sorted([host.panel_domain, host.reality_domain])
    require(
        HOST_CASE_ID,
        lineages == expected_lineages,
        f"the host holds the lineages {lineages} instead of the Panel and camouflage pair "
        f"{expected_lineages}; a Panel-only deployment terminates no third name",
    )

    panel = aio.require_client_certificate(
        HOST_CASE_ID, "panel", host.panel_domain,
        host.client_http(
            f"https://{host.panel_domain}/", expect_status=200, expect_san=[host.panel_domain], timeout=30,
        ),
        200,
    )
    decoy_url = f"https://{host.reality_domain}/"
    decoy = host.client_http(
        decoy_url, expect_status=200, expect_body="<html",
        expect_san=[host.reality_domain], timeout=30,
    )
    require(
        HOST_CASE_ID,
        decoy["returncode"] == 0,
        f"the camouflage name {host.reality_domain} does not serve the static site: "
        f"{decoy['probe'].get('error') or decoy['stderr'][-400:]}",
    )
    snippet = str((decoy["probe"] or {}).get("body_snippet") or "").lower()
    require(
        HOST_CASE_ID,
        "/api/" not in snippet and "gowave" not in snippet,
        f"the camouflage name answered with product content: {snippet[:300]!r}",
    )
    return {
        "units": units,
        "node_unit_files": node_units,
        "listeners": sorted(addresses),
        "traffic_listeners": traffic,
        "traffic_processes": processes,
        "traffic_binaries": binaries,
        "credentials": credentials,
        "certificate_lineages": lineages,
        "nginx_test": nginx.strip().splitlines()[-2:],
        "public_panel": panel,
        "public_decoy_status": decoy["probe"].get("status"),
        "public_decoy_san": (decoy["probe"].get("peer") or {}).get("san"),
    }


def case_api_shape(product: PanelOnlyProduct) -> Dict[str, Any]:
    """PO-API: the install stopped after the Panel's own bootstrap.

    The API is asked, not the filesystem: hosts, nodes, profiles and squads are
    the four entities a traffic plane would own, and a Panel-only install owes
    none of them while it does owe the default user and its scoped token.
    """
    facts = aio.panel_probe(product, API_CASE_ID, "surface")
    login = facts.get("login") or {}
    surface = facts.get("surface") or {}
    require(
        API_CASE_ID,
        login.get("status") == 200,
        f"the documented admin login returned {login.get('status')!r}",
    )
    hosts = surface.get("hosts") or {}
    nodes = surface.get("nodes") or {}
    profiles = surface.get("profiles") or {}
    squads = surface.get("squads") or {}
    user = surface.get("default_user") or {}
    tokens = surface.get("tokens") or {}
    for label, entry in (
        ("hosts", hosts), ("nodes", nodes), ("profiles", profiles),
        ("squads", squads), ("tokens", tokens),
    ):
        require(
            API_CASE_ID,
            entry.get("status") == 200,
            f"the authenticated {label} read returned {entry.get('status')!r}",
        )
    require(
        API_CASE_ID, hosts.get("count") == 0,
        f"the Panel publishes {hosts.get('count')!r} host records",
    )
    require(API_CASE_ID, nodes.get("count") == 0, f"the Panel knows {nodes.get('count')!r} nodes")
    require(
        API_CASE_ID,
        profiles.get("count") == 0,
        f"the Panel holds {profiles.get('count')!r} config profiles; an install with no "
        "inbound owes none",
    )
    require(
        API_CASE_ID,
        squads.get("count") == 0,
        f"the Panel holds {squads.get('count')!r} internal squads; the first node add creates "
        "the squad",
    )
    require(
        API_CASE_ID,
        user.get("status") == 200 and int(user.get("short_uuid_length") or 0) > 0,
        f"the default user is not served with a shortUuid: {user}",
    )
    require(
        API_CASE_ID,
        int(tokens.get("count") or 0) >= 1,
        f"the install provisioned no scoped API token: {tokens}",
    )

    result = product.host_script(STATE_SHAPE_SCRIPT)
    require(
        API_CASE_ID,
        result.returncode == 0,
        f"the state probe exited {result.returncode}: {(result.stderr or '').strip()[-1000:]}",
    )
    try:
        state = json.loads(result.stdout or "")
    except json.JSONDecodeError:
        state = None
    require(
        API_CASE_ID,
        isinstance(state, dict),
        f"the state probe printed no JSON object: {(result.stdout or '')[:400]}",
    )
    state = state or {}
    require(
        API_CASE_ID,
        state.get("installation_mode") == "panel-only",
        f"state.json names the mode {state.get('installation_mode')!r}",
    )
    require(
        API_CASE_ID,
        state.get("schema_version") == 2,
        f"schemaVersion is {state.get('schema_version')!r}",
    )
    require(
        API_CASE_ID,
        state.get("nodes_is_list") is True,
        f"state.json nodes is not an array: {state.get('nodes_is_list')!r}",
    )
    require(
        API_CASE_ID,
        state.get("node_count") == 0,
        f"state.json lists {state.get('node_count')!r} nodes",
    )
    require(
        API_CASE_ID,
        state.get("local_node_keys") == [],
        "state.json carries local-node fields a Panel-only host has no node for: "
        f"{state.get('local_node_keys')}",
    )
    return {
        "login_status": login.get("status"),
        "hosts": hosts,
        "nodes": nodes,
        "profiles": profiles,
        "squads": squads,
        "default_user": user,
        "tokens": tokens,
        "state": state,
    }


def case_squad(product: PanelOnlyProduct) -> Dict[str, Any]:
    """PO-SQUAD: the first registration after a Panel-only install owns a real squad.

    The squad is read where it is spent: the host records the Panel stores, and
    the ``state.json`` the next registration reads. A run whose records carry an
    empty or null squad is the defect this case exists to refuse.
    """
    evidence = product.add_worker()
    facts = product.squad_facts(SQUAD_CASE_ID)
    require(
        SQUAD_CASE_ID,
        facts.get("state_squad_present") is True
        and int(facts.get("state_squad_length") or 0) >= 32,
        f"state.json stored no squad identifier: {facts}",
    )
    require(
        SQUAD_CASE_ID,
        int(facts.get("host_count") or 0) >= 1,
        f"the Panel publishes {facts.get('host_count')!r} host records after the registration",
    )
    require(
        SQUAD_CASE_ID,
        facts.get("hosts_with_null_squad") == 0,
        f"{facts.get('hosts_with_null_squad')} host record(s) carry a null squad entry",
    )
    require(
        SQUAD_CASE_ID,
        facts.get("hosts_without_squad") == 0,
        f"{facts.get('hosts_without_squad')} host record(s) carry no squad at all",
    )
    require(
        SQUAD_CASE_ID,
        facts.get("hosts_naming_state_squad") == facts.get("host_count"),
        f"only {facts.get('hosts_naming_state_squad')} of {facts.get('host_count')} host "
        "records name the identifier state.json stored",
    )
    require(
        SQUAD_CASE_ID,
        facts.get("host_squad_modes") == ["ALLOW_ONLY"],
        f"the host records use the squad mode {facts.get('host_squad_modes')!r}",
    )
    require(
        SQUAD_CASE_ID,
        facts.get("squad_count") == 1 and facts.get("mvp_squad_present") is True,
        f"the Panel holds {facts.get('squad_count')!r} squads instead of the one the "
        f"registration created: {facts.get('mvp_squad_present')!r} is the default squad",
    )
    require(
        SQUAD_CASE_ID,
        int(facts.get("mvp_squad_inbound_count") or 0) >= 1,
        "the internal squad allows no inbound, so a subscription from it would deliver nothing",
    )
    require(
        SQUAD_CASE_ID,
        facts.get("panel_node_count") == 1
        and topology.WORKER_NODE_NAME in (facts.get("panel_node_names") or []),
        f"the Panel reports nodes {facts.get('panel_node_names')!r} instead of the "
        f"registered {topology.WORKER_NODE_NAME!r}",
    )
    require(
        SQUAD_CASE_ID,
        facts.get("nodes_in_state") == 1,
        f"state.json lists {facts.get('nodes_in_state')!r} nodes after one registration",
    )
    evidence.update({"squad": facts})
    return evidence


def case_refused_payload(product: PanelOnlyProduct) -> Dict[str, Any]:
    """PO-SQUAD-REFUSED: a null squad is never turned into a usable grant.

    The registration's own guard is unit-proven; what a container adds is the
    Panel's side of the sentence. The same host payload is posted twice — once
    with the squad the Panel holds, which has to be accepted, and once with a null
    entry in that squad list — so the answer is attributable: a Panel that refused
    both would be refusing the shape, not the defect.

    The Panel decides which branch is real and the run says which one it took.
    Either it refuses the payload and the count has to stay put, or it takes the
    record and that record must not name the squad: a null entry that silently
    granted the operator's squad would be the failure this case exists to refuse,
    because nothing downstream would then notice the registration was broken.
    """
    if product.node_add_outcome is None:
        product.add_worker()
    elif not product.node_add_outcome.ok:
        raise CaseBlocked(
            f"{SQUAD_CASE_ID}: the registration failed, so it left no host record to replay"
        )
    host = product.require_installed()
    result = product.podman.exec_bash(
        host.target_name, REFUSED_PAYLOAD_SCRIPT, check=False, timeout=PROBE_TIMEOUT_SECONDS,
    )
    require(
        SQUAD_REFUSED_CASE_ID,
        result.returncode == 0,
        f"the refusal probe exited {result.returncode}: "
        f"{(result.stderr or result.stdout or '').strip()[-2000:]}",
    )
    try:
        facts = json.loads(result.stdout or "")
    except json.JSONDecodeError:
        facts = None
    require(
        SQUAD_REFUSED_CASE_ID,
        isinstance(facts, dict),
        f"the refusal probe printed no JSON object: {(result.stdout or '')[:400]}",
    )
    facts = facts or {}
    require(
        SQUAD_REFUSED_CASE_ID,
        facts.get("squad_present") is True,
        "the Panel holds no squad to compare against",
    )
    require(
        SQUAD_REFUSED_CASE_ID,
        200 <= int(facts.get("control_status") or 0) < 300 and facts.get("control_created") is True,
        f"the control host record was refused with {facts.get('control_status')!r}, so the "
        "result below cannot be attributed to the null squad",
    )
    require(
        SQUAD_REFUSED_CASE_ID,
        facts.get("hosts_after_control") == int(facts.get("hosts_before") or 0) + 1,
        f"the control post reported {facts.get('control_status')!r} but the host count went "
        f"{facts.get('hosts_before')!r} -> {facts.get('hosts_after_control')!r}",
    )
    require(
        SQUAD_REFUSED_CASE_ID,
        200 <= int(facts.get("delete_status") or 0) < 300,
        f"the control host record was not removed: DELETE returned {facts.get('delete_status')!r}",
    )
    require(
        SQUAD_REFUSED_CASE_ID,
        facts.get("hosts_after_delete") == facts.get("hosts_before"),
        f"the control host record survived its own delete: {facts.get('hosts_before')!r} -> "
        f"{facts.get('hosts_after_delete')!r}",
    )

    status = int(facts.get("refused_status") or 0)
    if status >= 400:
        facts["panel_refuses_null_squad"] = True
        require(
            SQUAD_REFUSED_CASE_ID,
            facts.get("hosts_after_refused") == facts.get("hosts_before"),
            f"the refused payload still changed the host count: {facts.get('hosts_before')!r} -> "
            f"{facts.get('hosts_after_refused')!r}",
        )
        return facts

    facts["panel_refuses_null_squad"] = False
    require(
        SQUAD_REFUSED_CASE_ID,
        200 <= status < 300 and facts.get("refused_created") is True,
        f"the null-squad post answered {status!r} without creating a host record, which is "
        "neither a refusal nor an acceptance",
    )
    require(
        SQUAD_REFUSED_CASE_ID,
        int(facts.get("accepted_naming_state_squad") or 0) == 0,
        "the Panel stored the null squad as the operator's own squad, so a broken registration "
        "would grant exactly what a correct one grants",
    )
    require(
        SQUAD_REFUSED_CASE_ID,
        200 <= int(facts.get("refused_cleanup_status") or 0) < 300,
        "the probe's own host record could not be removed: DELETE returned "
        f"{facts.get('refused_cleanup_status')!r}",
    )
    require(
        SQUAD_REFUSED_CASE_ID,
        facts.get("hosts_after_refused_cleanup") == facts.get("hosts_before"),
        "the probe left a host record behind: "
        f"{facts.get('hosts_before')!r} -> {facts.get('hosts_after_refused_cleanup')!r}",
    )
    return facts


def case_add_node_refused(product: PanelOnlyProduct) -> Dict[str, Any]:
    """``MN-ADD-NODE-REFUSED``: the wizard refuses an unverifiable Panel before mutating.

    The scenario is the operator's second and third mistake in one flow: a Panel
    address that does not answer a verified API, entered for a deployment that
    already exists. The attempt must stop at the verification step, so the case
    reads three independent facts — the verification message on the operator's
    stream, the absence of the mutation sentinel and of the credential prompt,
    and a Panel surface whose node list is byte-for-byte the one it had before.

    The Panel is named, not addressed: the wizard refuses a bare address before
    it probes anything, so the case names one no resolver can answer and the flow
    is refused at the API check itself.
    """
    host = product.require_installed()

    before = aio.panel_probe(product, ADD_NODE_REFUSED_CASE_ID, "surface")
    nodes_before = (before.get("surface") or {}).get("nodes") or {}

    resolution = aio.add_node_refused_resolution(
        product.podman, host.target_name, ADD_NODE_REFUSED_CASE_ID,
    )
    aio.require_add_node_refused_premise(ADD_NODE_REFUSED_CASE_ID, resolution)
    script = aio.add_node_refusal_script()
    started = time.monotonic()
    proc = product.podman.exec_bash(
        host.target_name, script, check=False, timeout=PROBE_TIMEOUT_SECONDS,
    )
    outcome = topology.InstallOutcome(
        returncode=proc.returncode,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
        duration=time.monotonic() - started,
        command=script,
    )
    output = f"{outcome.stdout}\n{outcome.stderr}"

    require(
        ADD_NODE_REFUSED_CASE_ID,
        not outcome.ok,
        f"the wizard accepted a Panel address that cannot be verified and exited "
        f"{outcome.returncode}:\n{output[-4000:]}",
    )
    reported = [marker for marker in aio.PANEL_VERIFICATION_FAILURES if marker in output]
    require(
        ADD_NODE_REFUSED_CASE_ID,
        bool(reported),
        "the refusal named no verification failure, so it stopped for some other reason "
        f"(expected one of {list(aio.PANEL_VERIFICATION_FAILURES)}):\n{output[-4000:]}",
    )
    require(
        ADD_NODE_REFUSED_CASE_ID,
        "GOWAVE_CMD_NODE_CALLED" not in output,
        "the refused attempt reached the Worker deployment boundary, so a mutation began "
        f"before the Panel was verified:\n{output[-4000:]}",
    )
    # `read -p` prints its prompt only when stdin is a terminal, so the absence of
    # a credential prompt would prove nothing here. The sentinel above is the real
    # reading: Worker credentials are collected before `cmd_node add` and handed to
    # it, so a boundary that was never crossed received none of them.
    require(
        ADD_NODE_REFUSED_CASE_ID,
        f"Verifying Panel API at {aio.ADD_NODE_REFUSED_PANEL}..." in output,
        "the flow never reached the verification step for the address it was given, so the "
        f"refusal below cannot be attributed to Panel verification:\n{output[-4000:]}",
    )

    after = aio.panel_probe(product, ADD_NODE_REFUSED_CASE_ID, "surface")
    nodes_after = (after.get("surface") or {}).get("nodes") or {}
    require(
        ADD_NODE_REFUSED_CASE_ID,
        (nodes_after.get("names") or []) == (nodes_before.get("names") or []),
        f"the refused attempt changed the Panel's node list: "
        f"{nodes_before.get('names')!r} -> {nodes_after.get('names')!r}",
    )

    return {
        "panel_address": aio.ADD_NODE_REFUSED_PANEL,
        "verification_failure_reported": reported,
        "wizard_returncode": outcome.returncode,
        "mutation_boundary_reached": "GOWAVE_CMD_NODE_CALLED" in output,
        "verification_step_reached": True,
        "panel_node_names_before": nodes_before.get("names"),
        "panel_node_names_after": nodes_after.get("names"),
        "output_tail": outcome.tail(2000),
    }


def cases(podman: Any, distribution: str = "ubuntu-24.04") -> List[Case]:
    """The Panel-only suite in run order.

    The install owns the host; every later case reuses it. The registration runs
    once, after the two read-only shapes, because it is what adds API state to
    the host the API shape case measures, and the negative reads the records the
    positive created rather than provisioning a second Worker.
    """
    product = PanelOnlyProduct(podman, distribution)
    return [
        Case(INSTALL_CASE_ID, "panel-only", lambda context: product.install(),
             timeout_seconds=INSTALL_TIMEOUT_SECONDS),
        Case(HOST_CASE_ID, "panel-only", lambda context: case_host_shape(product),
             timeout_seconds=PROBE_TIMEOUT_SECONDS),
        # The host shape's firewall half, read as an ingress decision: no Node
        # API rule and no listener on either the installed port or a port the
        # product never uses, the operator's SSH ports still public, and the
        # same answer after the unit a reboot runs re-applies the files.
        Case(ingress_matrix.PANEL_ONLY_CASE_ID, "panel-only",
             lambda context: ingress_matrix.case_panel_only_ingress(product, context),
             timeout_seconds=2 * ingress_matrix.POLICY_TIMEOUT_SECONDS
             + 2 * ingress_matrix.FACTS_TIMEOUT_SECONDS),
        Case(API_CASE_ID, "panel-only", lambda context: case_api_shape(product),
             timeout_seconds=PROBE_TIMEOUT_SECONDS),
        Case(SQUAD_CASE_ID, "panel-only", lambda context: case_squad(product),
             timeout_seconds=REGISTRATION_TIMEOUT_SECONDS),
        Case(SQUAD_REFUSED_CASE_ID, "panel-only",
             lambda context: case_refused_payload(product),
             timeout_seconds=PROBE_TIMEOUT_SECONDS),
        Case(ADD_NODE_REFUSED_CASE_ID, "panel-only",
             lambda context: case_add_node_refused(product),
             timeout_seconds=PROBE_TIMEOUT_SECONDS),
    ]
