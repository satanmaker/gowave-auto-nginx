"""All-in-One product acceptance cases.

Every case here runs against one real operator install in one disposable host.
The install is performed once, by the install case, and later cases reuse that
host: re-provisioning per case would hide whether repeated installs are safe,
so a single case owns the second install and measures it on purpose.

Two vantage points are kept apart on purpose. Host-side facts (units, sockets,
packages, certificate files, the loopback API) are read from the host under
test; anything a client can observe (HTTPS on 443, certificate chains, served
subscriptions) is read from a separate Control Machine container that has no
product code on it.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional, Sequence, Set

from . import matrix, panel_surface, topology
from .podman import wait_until
from .runner import Case, CaseBlocked, require

INSTALL_CASE_ID = "AIO-INSTALL"

# The real install downloads releases, resolves packages, and issues three
# certificates; the ceiling is a hang guard, not an expectation.
INSTALL_TIMEOUT_SECONDS = 5400

# Mirrors get_required_packages in modules/os.sh. The harness keeps its own copy
# so a case can never be satisfied by asking the product what it installed; a
# nonroot test fails if the two lists drift apart.
REQUIRED_PACKAGES: Sequence[str] = (
    "nginx-full",
    "libnginx-mod-stream",
    "certbot",
    "python3",
    "python3-systemd",
    "sqlite3",
    "curl",
    "tar",
    "gzip",
    "openssl",
    "ufw",
    "fail2ban",
    "systemd-resolved",
    "iproute2",
    "ca-certificates",
    "openssh-client",
)

UNITS: Sequence[str] = (
    "gowave.service",
    "gowave-node.service",
    "nginx.service",
    "fail2ban.service",
)

CREDENTIALS_FILE = "/root/gowave-credentials.txt"
LETSENCRYPT_ROOT = "/etc/letsencrypt/live"
LOOPBACK_PANEL = "http://127.0.0.1:3000"
PUBLIC_PANEL = f"https://{topology.PANEL_DOMAIN}"
PANEL_DOMAIN = topology.PANEL_DOMAIN
REALITY_DOMAIN = topology.REALITY_DOMAIN
PANEL_SURFACE_SCRIPT = "/repo/tools/podman_e2e/panel_surface.py"
SUBSCRIPTION_PROBE_SCRIPT = topology.SUBSCRIPTION_PROBE_SCRIPT

# What each YAML representation is expected to carry, per the shipped generators.
# GenerateMihomo skips only kcp, so Mihomo receives one proxy per inbound.
# GenerateClash skips vless, xhttp, kcp and hysteria outright, so Clash receives
# one proxy per trojan inbound — a strict subset of the Mihomo inventory, not a
# second copy of it. The count therefore follows the node inventory: one for an
# All-in-One install, one per node for a cluster.
MIHOMO_PROXY_TYPES: Sequence[str] = ("trojan", "vless")
CLASH_PROXY_TYPES: Sequence[str] = ("trojan",)

# Every served representation the Panel exposes, and the client family that
# consumes it. The order matches the documented representation inventory.
REPRESENTATIONS: Sequence[str] = ("base64", "xray-json", "mihomo", "clash", "singbox")
# Non-base64 representations are validated structurally; these two are loaded by
# the real engine that consumes them.
ENGINE_LOADED: Sequence[str] = ("base64", "xray-json", "mihomo", "clash")

# The product emits this uTLS fingerprint on REALITY and TLS transports, and the
# matrix pins the same value; a subscription that lost it is not importable.
EXPECTED_FINGERPRINT = "firefox"

UA_REFUSAL_STATUS = 403

# The pinned clients that have to traverse every inbound. The inbound set itself
# comes from the protocol/client matrix: four inbounds without the optional
# Vision domain, five with it, which is what makes the matrix 8 or 10 tuples
# rather than a fixed list.
TRAFFIC_ENGINES: Sequence[str] = ("mihomo", "xray")
# Two engines over the whole inbound set, run sequentially on one client
# container; lifecycle cases that exercise the matrix reuse the budget.
TRAFFIC_TIMEOUT_SECONDS = 900
# One matrix case starts one engine and sends one payload; it must not inherit
# the deadline of the whole matrix.
DATA_PLANE_TIMEOUT_SECONDS = 300

# A restart of the product's own units is bounded by the same kind of deadline as
# any other readiness wait; the interval is coarse because every poll is an exec.
RESTART_TIMEOUT_SECONDS = 900
RESTART_INTERVAL_SECONDS = 5

# A bound upstream listener is not a working tunnel: the Panel hands users to the
# node and the node applies them asynchronously, so the first transfer of a payload
# that was just issued can still be refused. Readiness is proven by one real
# payload through one served outbound, polled under this deadline.
TUNNEL_READY_TIMEOUT_SECONDS = 300
TUNNEL_READY_INTERVAL_SECONDS = 5
# One warm-up attempt starts an engine and sends one request; it must not inherit
# the deadline of the whole matrix.
TUNNEL_READY_ATTEMPT_TIMEOUT_SECONDS = 180

# The host resources a repeated install must neither duplicate nor rewrite. The
# Nginx section carries a digest per file, so a regenerated-but-different config
# is as visible as an added one.
INVENTORY_SCRIPT = (
    "echo '==units'\n"
    "systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null"
    " | awk '{print $1, $2}'"
    " | grep -E '^(gowave|gowave-node|nginx|fail2ban)\\.service ' | sort || true\n"
    "echo '==unit-files'\n"
    "find /etc/systemd/system -maxdepth 2 -type f"
    " \\( -name 'gowave*' -o -name 'nginx*' -o -name 'fail2ban*' \\) 2>/dev/null | sort || true\n"
    "echo '==nginx'\n"
    "(cd /etc/nginx 2>/dev/null && find nginx.conf conf.d sites-enabled stream-enabled"
    " modules-enabled -type f 2>/dev/null | sort | xargs -r sha256sum) || true\n"
    "echo '==credentials'\n"
    f"stat -c '%U %a' {CREDENTIALS_FILE} 2>/dev/null || echo missing\n"
)

# A unit that reports active is not a service that serves again; the returned
# dependency is followed to a deadline like every other readiness signal.
RECOVERY_TIMEOUT_SECONDS = 180
RECOVERY_INTERVAL_SECONDS = 5

# Preflight's port guard, exercised on the installed host. The port to hold is
# discovered instead of hardcoded: the topology's own configuration decides which
# declared ports are free, and a fixed choice would assert the container layout
# rather than the guard. 443 is the control: the product holds it, so it must not
# be reported as a conflict.
FOREIGN_LISTENER_SCRIPT = r"""
set -uo pipefail
source /repo/modules/preflight.sh
candidate=""
for port in "${PREFLIGHT_REQUIRED_PORTS[@]}"; do
    if ss -Hltn "sport = :$port" 2>/dev/null | grep -q .; then
        continue
    fi
    if python3 - "$port" <<'PY' 2>/dev/null
import socket, sys
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("127.0.0.1", int(sys.argv[1])))
sock.close()
PY
    then
        candidate="$port"
        break
    fi
done
if [[ -z "$candidate" ]]; then
    echo "error=no-free-declared-port"
    exit 2
fi
python3 - "$candidate" <<'PY' &
import socket, sys, time
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("127.0.0.1", int(sys.argv[1])))
sock.listen(4)
time.sleep(120)
PY
holder=$!
trap 'kill "$holder" 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do
    if ss -Hltn "sport = :$candidate" 2>/dev/null | grep -q .; then
        break
    fi
    sleep 0.1
done
if check_port_availability "$candidate" >/dev/null 2>&1; then
    echo "foreign=accepted"
else
    echo "foreign=refused"
fi
if check_port_availability 443 >/dev/null 2>&1; then
    echo "managed=accepted"
else
    echo "managed=refused"
fi
kill "$holder" 2>/dev/null || true
wait "$holder" 2>/dev/null || true
for _ in $(seq 1 50); do
    if ! ss -Hltn "sport = :$candidate" 2>/dev/null | grep -q .; then
        break
    fi
    sleep 0.1
done
if check_port_availability "$candidate" >/dev/null 2>&1; then
    echo "released=accepted"
else
    echo "released=refused"
fi
printf 'port=%s\n' "$candidate"
"""

# The ACME allowlist, asked directly instead of by running an install: the four
# answers together are the contract, and one of them alone would pass while the
# fixture became an arbitrary-URL option. The CA file is a real regular file with
# a digest that cannot match, so the refusal comes from the pin and not from a
# missing path.
ACME_FAIL_CLOSED_SCRIPT = r"""
set -uo pipefail
source /repo/modules/nginx.sh
endpoint="$GOWAVE_ACME_TEST_ENDPOINT"
ca_file=/etc/hostname
digest=$(printf '%064d' 0)
if GOWAVE_ACME_TEST_MODE=0 GOWAVE_ACME_SERVER="$endpoint" \
    validate_acme_server "$endpoint" >/dev/null 2>&1; then
    echo "fixture_without_optin=accepted"
else
    echo "fixture_without_optin=refused"
fi
if GOWAVE_ACME_TEST_MODE=1 \
    validate_acme_server https://acme.example.invalid/directory >/dev/null 2>&1; then
    echo "arbitrary_in_test_mode=accepted"
else
    echo "arbitrary_in_test_mode=refused"
fi
if GOWAVE_ACME_TEST_MODE=1 GOWAVE_ACME_TEST_CA_FILE="$ca_file" \
    GOWAVE_ACME_TEST_CA_SHA256="$digest" \
    validate_acme_server "$endpoint" >/dev/null 2>&1; then
    echo "unpinned_ca=accepted"
else
    echo "unpinned_ca=refused"
fi
if GOWAVE_ACME_TEST_MODE=0 \
    validate_acme_server https://acme-v02.api.letsencrypt.org/directory >/dev/null 2>&1; then
    echo "letsencrypt_production=accepted"
else
    echo "letsencrypt_production=refused"
fi
"""


class AioProduct:
    """One disposable AIO host, installed once by the real operator."""

    # The matrix topology this install's case ids are named after. A product that
    # installs more than one host overrides it, so the same data-plane body names
    # its cases after its own topology instead of borrowing the AIO ids.
    case_topology = "aio"

    def __init__(
        self, podman: Any, distribution: str = "ubuntu-24.04", vision: bool = False,
        install_case_id: str = INSTALL_CASE_ID,
    ) -> None:
        self.podman = podman
        self.context = podman.context
        self.distribution = distribution
        # A topology that installs more than one host names its own install case;
        # the block messages must then point at that case, not at the AIO one.
        self.install_case_id = install_case_id
        # The optional Vision domain is a product configuration, not a harness
        # option: it decides whether the operator provisions a fifth inbound and
        # therefore whether the matrix owes 8 or 10 positive cases.
        self.vision = vision
        self.matrix = matrix.load()
        self.declared_data_plane: List[str] = []
        self.data_plane_results: Dict[str, str] = {}
        self.host: Optional[topology.AioTopology] = None
        self.outcome: Optional[topology.InstallOutcome] = None
        self._subscriptions: Optional[Dict[str, Any]] = None
        self._subscription_error = ""
        self.subscription_inbounds_override: Optional[List[Dict[str, Any]]] = None

    @property
    def inbound_count(self) -> int:
        """How many inbounds this install carries, per the selected configuration."""
        return len(matrix.inbounds(self.matrix, self.vision))

    def subscription_inbounds(self) -> List[Dict[str, Any]]:
        """The inbounds a client of this Panel should be served.

        One install publishes its own node, so the answer is its own matrix
        inbounds. A Panel that also runs a Worker publishes the inbounds of every
        node in the client's squad, and says so by setting the override.
        """
        if self.subscription_inbounds_override is not None:
            return list(self.subscription_inbounds_override)
        return matrix.inbounds(self.matrix, self.vision)

    @property
    def subscription_inbound_count(self) -> int:
        """How many inbounds the served subscription must describe."""
        return len(self.subscription_inbounds())

    def declare_data_plane(self, case_ids: Sequence[str]) -> None:
        """Record the data-plane cases the suite declared, for the matrix count case."""
        self.declared_data_plane = list(case_ids)

    def record_data_plane(self, case_id: str, status: str) -> None:
        """Record one matrix case's own verdict; a case that never reports is missing."""
        self.data_plane_results[case_id] = status

    # ------------------------------------------------------------------ install
    def install(self, host: Optional[topology.AioTopology] = None) -> Dict[str, Any]:
        """Create the disposable host and run the operator install exactly once.

        ``host`` lets a topology that owns more than one node — the Multi-Node
        Master and its Worker — hand in the host it already prepared, so the
        install command and every probe after it run against the same instance.
        """
        if self.host is not None:
            raise AssertionError(
                f"{self.install_case_id}: the host is installed once per run and reused by later cases"
            )
        if host is None:
            host = topology.AioTopology(
                self.podman,
                distribution=self.distribution,
                vision_domain=topology.VISION_DOMAIN if self.vision else None,
            )
            host.create()
        self.host = host
        self.outcome = host.install()
        require(
            self.install_case_id,
            self.outcome.ok,
            f"the operator full install failed with exit {self.outcome.returncode}:\n"
            f"{self.outcome.tail(6000)}",
        )
        return host.evidence(self.outcome)

    def reinstall(self, case_id: str) -> Dict[str, Any]:
        """Run the operator's install command a second time against the same host.

        The first install's outcome is kept as the host's provenance: a repeated
        install that fails is a finding of the idempotency case, not a reason to
        forget that the host was installed correctly the first time.
        """
        host = self.require_installed()
        outcome = host.reinstall()
        require(
            case_id,
            outcome.ok,
            f"the repeated install failed with exit {outcome.returncode}:\n{outcome.tail(6000)}",
        )
        return {
            "reinstall_returncode": outcome.returncode,
            "reinstall_duration_seconds": round(outcome.duration, 1),
            "reinstall_command": outcome.command,
        }

    def require_installed(self) -> topology.AioTopology:
        """The successfully installed host, for cases that must not provision anything themselves."""
        if self.host is None or self.outcome is None:
            raise CaseBlocked(
                f"{self.install_case_id}: this case needs the install, and no install has run in this suite"
            )
        if not self.outcome.ok:
            # A half-installed host answers some probes and not others; running
            # them anyway would report the install failure six times over.
            raise CaseBlocked(
                f"{self.install_case_id}: the install failed with exit {self.outcome.returncode}, "
                "so this case had nothing to verify"
            )
        return self.host

    # ------------------------------------------------------------------ probes
    def host_script(self, script: str, timeout: int = 120) -> Any:
        host = self.require_installed()
        return self.podman.exec_bash(host.target_name, script, check=False, timeout=timeout)

    # ----------------------------------------------------------- subscriptions
    def collect_subscriptions(self, case_id: str) -> Dict[str, Any]:
        """Fetch every representation once; the payloads stay on the host, 0600.

        The subscription routes are loopback-only, so the host is the only place
        that can read them. What comes back is a status, a media type, and a byte
        count per representation — never the payload itself.
        """
        if self._subscriptions is not None:
            return self._subscriptions
        if self._subscription_error:
            raise CaseBlocked(f"SUB-SERVED: {self._subscription_error}")
        result = self.host_script(
            f"python3 {PANEL_SURFACE_SCRIPT} --scope subscriptions "
            f"--payload-dir {topology.PAYLOAD_MOUNT}"
        )
        detail = (result.stderr or result.stdout or "").strip()[-2000:]
        if result.returncode != 0:
            self._subscription_error = f"the subscription probe exited {result.returncode}: {detail}"
            require(case_id, False, self._subscription_error)
        try:
            facts = json.loads(result.stdout or "")
        except json.JSONDecodeError:
            self._subscription_error = f"the subscription probe did not print JSON: {(result.stdout or '')[:400]}"
            require(case_id, False, self._subscription_error)
            return {}
        self._subscriptions = facts.get("subscriptions") or {}
        return self._subscriptions

    def subscription_payloads(self, case_id: str) -> Dict[str, Any]:
        """The payloads another case fetched, or a block that names the owning case."""
        return self.collect_subscriptions(case_id)

    def engine_facts(self, case_id: str, scope: str) -> Dict[str, Any]:
        """Run the engine-side probe and return the facts it reports."""
        host = self.require_installed()
        return self._probe_json(case_id, "the client probe", host.subscription_facts(scope))

    def traffic_facts(self, case_id: str, scope: str, payload_dir: Optional[str] = None) -> Dict[str, Any]:
        """Run the engine-side traffic probe and return what the endpoint recorded."""
        host = self.require_installed()
        return self._probe_json(case_id, "the traffic probe", host.traffic_facts(
            scope, payload_dir=payload_dir,
        ))

    def transfer_facts(
        self, case_id: str, inbound_id: str, client: str, node: str = "",
    ) -> Dict[str, Any]:
        """Run exactly one matrix tuple: one client through one inbound.

        The matrix, not the case body, decides the transport and security layer,
        so a matrix edit that renames or re-transports an inbound changes what the
        case exercises instead of leaving the case asserting the old shape.

        ``node`` names the host the tuple belongs to. A cluster serves the same
        transport/security pairs on both nodes, so the probe is narrowed by the
        node's own dial name; otherwise it would run the first match and call it
        this one.
        """
        host = self.require_installed()
        inbound = matrix.inbound(self.matrix, inbound_id)
        return self._probe_json(case_id, "the transfer probe", host.transfer_facts(
            client, str(inbound["transport"]), str(inbound["security"]),
            host=matrix_expectations(self, inbound, node)["server"],
        ))

    def prohibited_facts(self, case_id: str) -> Dict[str, Any]:
        """Run the policy probe: one permitted control, one destination the product denies."""
        host = self.require_installed()
        return self._probe_json(case_id, "the policy probe", host.prohibited_facts())

    def _probe_json(self, case_id: str, label: str, result: Any) -> Dict[str, Any]:
        """A probe that exited non-zero or printed no JSON fails the case."""
        detail = (result.stderr or result.stdout or "").strip()[-2000:]
        require(case_id, result.returncode == 0, f"{label} exited {result.returncode}: {detail}")
        try:
            return json.loads(result.stdout or "")
        except json.JSONDecodeError:
            require(case_id, False, f"{label} did not print JSON: {(result.stdout or '')[:400]}")
            return {}

    def wait_tunnel_ready(self, case_id: str, payload_dir: Optional[str] = None) -> Dict[str, Any]:
        """Wait until one served outbound really carries a payload to the endpoint.

        A listener that is bound and a Panel that answers say nothing about the
        data plane: the Panel pushes users to the node and the node applies them
        asynchronously, so both a freshly issued client and a restarted node can
        have a tunnel that refuses the first transfer. One payload, confirmed by
        the endpoint's own log, is the smallest honest proof that the matrix that
        follows is measuring the product rather than its propagation lag.
        """
        host = self.require_installed()
        observed: Dict[str, Any] = {}

        def carried() -> bool:
            result = host.traffic_facts(
                "warmup",
                timeout=TUNNEL_READY_ATTEMPT_TIMEOUT_SECONDS,
                payload_dir=payload_dir,
            )
            if result.returncode != 0:
                observed.clear()
                observed["returncode"] = result.returncode
                observed["detail"] = (result.stderr or result.stdout or "").strip()[-400:]
                return False
            try:
                facts = json.loads(result.stdout or "")
            except json.JSONDecodeError:
                observed.clear()
                observed["detail"] = f"the readiness probe did not print JSON: {(result.stdout or '')[:200]}"
                return False
            observed.clear()
            observed.update(facts)
            return bool(facts.get("delivered"))

        ready = wait_until(
            carried, TUNNEL_READY_TIMEOUT_SECONDS, f"{case_id} data plane",
            interval_seconds=TUNNEL_READY_INTERVAL_SECONDS,
        )
        require(case_id, ready,
                f"no served outbound carried a payload to the endpoint within "
                f"{TUNNEL_READY_TIMEOUT_SECONDS}s: {observed}")
        return observed


def _login_preamble() -> str:
    """Shell that authenticates against the loopback Panel without leaking secrets.

    The credentials file is read by python into a 0600 temporary body posted with
    ``-d @file``, and the bearer token it comes back with is written into a curl
    config file used with ``-K``; neither value ever appears on a command line.
    The token lives at ``response.accessToken`` (the Panel wraps every payload in
    ``response``), so both shapes are accepted rather than assuming one.
    """
    return (
        "umask 077\n"
        f"creds={CREDENTIALS_FILE}\n"
        'body=$(mktemp)\nresp=$(mktemp)\ncfg=$(mktemp)\n'
        "trap 'rm -f \"$body\" \"$resp\" \"$cfg\"' EXIT\n"
        'python3 - "$creds" > "$body" <<\'PY\'\n'
        "import json, sys\n"
        "values = {}\n"
        "for line in open(sys.argv[1], encoding='utf-8'):\n"
        "    key, _, value = line.partition('=')\n"
        "    values[key.strip()] = value.strip()\n"
        "print(json.dumps({'username': values['ADMIN_USERNAME'], 'password': values['ADMIN_PASSWORD']}))\n"
        "PY\n"
        f'login=$(curl -sS -o "$resp" -w \'%{{http_code}}\' -X POST {LOOPBACK_PANEL}/api/auth/login '
        '-H \'Content-Type: application/json\' -d @"$body")\n'
        'token=$(python3 - "$resp" <<\'PY\'\n'
        "import json, sys\n"
        "data = json.load(open(sys.argv[1], encoding='utf-8'))\n"
        "nested = data.get('response')\n"
        "nested = nested if isinstance(nested, dict) else {}\n"
        "print(data.get('accessToken') or nested.get('accessToken') or data.get('token') or '')\n"
        "PY\n"
        ')\n'
        'printf \'header = "Authorization: Bearer %s"\\n\' "$token" > "$cfg"\n'
    )


def _parse_key_values(output: str) -> Dict[str, str]:
    """Parse ``key=value`` tokens from a probe's stdout.

    Probes print several pairs per line, so the split is on whitespace rather
    than on lines; every value is a single token (a number, a mode, an owner),
    so nothing is lost.
    """
    values: Dict[str, str] = {}
    for token in (output or "").split():
        key, separator, value = token.partition("=")
        if separator and key:
            values[key] = value
    return values


def panel_probe_script() -> str:
    """Log in over loopback, call ``/api/nodes`` with the token, report both codes."""
    return (
        _login_preamble()
        + 'api=$(curl -sS -K "$cfg" -o "$resp" -w \'%{http_code}\' '
        f'{LOOPBACK_PANEL}/api/nodes)\n'
        + 'printf \'login=%s api=%s token_length=%s\\n\' "$login" "$api" "${#token}"\n'
    )


def restart_readiness_script() -> str:
    """The Panel answers and the stream router's upstream listeners are bound.

    The Panel answering is not the product being up: port 443 hands the REALITY
    SNI to Xray on :8443 and the panel SNI to 127.0.0.1:7443. A tunnel dialled
    before Xray has bound its listener is refused by the client engine instead of
    travelling, so both listeners are part of the readiness deadline. The Xray
    inbound carries no ``listen`` field, so its port is matched on any address.
    """
    return (
        panel_probe_script()
        + "upstreams=$(ss -H -ltn 2>/dev/null | awk '{print $4}' "
          "| grep -cE ':(7443|8443)$' || true)\n"
        + 'printf \'upstreams=%s\\n\' "${upstreams:-0}"\n'
    )


def identity_probe_script() -> str:
    """Read the default user through the API so shortUuid cannot come from a file."""
    return (
        "set -euo pipefail\n"
        + _login_preamble()
        + f'curl -sS -K "$cfg" -o "$resp" {LOOPBACK_PANEL}/api/users/by-username/default-user\n'
        + "python3 - \"$resp\" <<'PY'\n"
        "import json, sys\n"
        "data = json.load(open(sys.argv[1], encoding='utf-8'))\n"
        "user = data.get('response', data) if isinstance(data, dict) else {}\n"
        "if isinstance(user, list) and user:\n"
        "    user = user[0]\n"
        "user = user if isinstance(user, dict) else {}\n"
        "short = user.get('shortUuid') or ''\n"
        "print(f'short_uuid_length={len(short)}')\n"
        "print(f'username_present={bool(user.get(\"username\"))}')\n"
        "PY\n"
    )


# ---------------------------------------------------------------------- cases
def required_subscription_hosts(product: AioProduct) -> Set[str]:
    """The names the served subscription must dial, from the topology's own nodes."""
    domains = product.require_installed().subscription_domains()
    return set(domains.get("required_hosts") or set())


def subscription_protocol_counts(product: AioProduct) -> Dict[str, int]:
    """How many share links each protocol owes, counted from the served inbounds."""
    counts: Dict[str, int] = {}
    for inbound in product.subscription_inbounds():
        protocol = str(inbound.get("subscription_protocol"))
        counts[protocol] = counts.get(protocol, 0) + 1
    return counts


def matrix_expectations(
    product: AioProduct, inbound: Dict[str, Any], node: str = "",
) -> Dict[str, str]:
    """The name, SNI and egress address one matrix tuple has to be served under.

    A tuple names an inbound by transport and security layer, and a cluster
    carries the same layers on both nodes, so the node decides every fact the
    case asserts: the name a share link dials (which also selects the outbound),
    the SNI the inbound presents, and the address the payload has to leave from.
    REALITY dials the node's TLS name and presents its own SNI; the Vision
    inbound is the one that carries the node's Vision name on both sides.
    """
    host = product.require_installed()
    names = host.node_names(node)
    if str(inbound.get("id")) == matrix.VISION_INBOUND:
        return {"server": names["vision"], "sni": names["vision"],
                "source_ip": host.node_data_ip(node)}
    if str(inbound.get("security")) == "reality":
        return {"server": names["dial"], "sni": names["reality"],
                "source_ip": host.node_data_ip(node)}
    return {"server": names["dial"], "sni": names["dial"], "source_ip": host.node_data_ip(node)}


def case_packages(product: AioProduct) -> Dict[str, Any]:
    """AIO-PACKAGES: the operator resolved its documented prerequisites itself."""
    packages = " ".join(REQUIRED_PACKAGES)
    script = (
        f'for pkg in {packages}; do '
        'if dpkg-query -W -f=\'${Status}\' "$pkg" 2>/dev/null | grep -q "install ok installed"; then '
        'printf "installed=%s\\n" "$pkg"; else printf "missing=%s\\n" "$pkg"; fi; done'
    )
    result = product.host_script(script)
    require("AIO-PACKAGES", result.returncode == 0, f"package probe failed: {result.stderr.strip()}")
    installed, missing = [], []
    for line in (result.stdout or "").splitlines():
        key, _, value = line.partition("=")
        if key == "installed":
            installed.append(value.strip())
        elif key == "missing":
            missing.append(value.strip())
    require("AIO-PACKAGES", not missing, f"the operator left prerequisites uninstalled: {', '.join(missing)}")
    return {"installed_packages": sorted(installed), "missing_packages": missing}


def case_services(product: AioProduct) -> Dict[str, Any]:
    """AIO-04: the declared units are active and the expected sockets are open."""
    units = " ".join(UNITS)
    script = (
        f"systemctl is-active {units} || true\n"
        "echo ---\n"
        "ss -H -ltn || true"
    )
    result = product.host_script(script)
    require("AIO-04", result.returncode == 0, f"service probe failed: {result.stderr.strip()}")
    active_part, _, sockets_part = (result.stdout or "").partition("---")
    states = dict(zip(UNITS, active_part.split()))
    not_active = sorted(name for name in UNITS if states.get(name) != "active")
    require("AIO-04", not not_active, f"units are not active: {', '.join(f'{n}={states.get(n)}' for n in not_active)}")

    listeners = [line.split() for line in sockets_part.strip().splitlines() if line.strip()]
    addresses = [fields[3] for fields in listeners if len(fields) >= 4]
    require("AIO-04", any(addr.startswith("127.0.0.1:3000") for addr in addresses),
            f"Panel is not listening on 127.0.0.1:3000: {addresses}")
    require("AIO-04", any(addr.endswith(":3002") for addr in addresses),
            f"the local Node is not listening on 3002: {addresses}")
    require("AIO-04", any(addr.endswith(":443") and not addr.startswith("127.0.0.1") for addr in addresses),
            f"NGINX is not listening publicly on 443: {addresses}")
    return {"units": states, "listeners": sorted(addresses)}


def case_panel_ready(product: AioProduct) -> Dict[str, Any]:
    """AIO-01: the Panel answers an authenticated call, and HTTPS serves it over 443."""
    loopback = product.host_script(panel_probe_script())
    require("AIO-01", loopback.returncode == 0, f"loopback API probe failed: {loopback.stderr.strip()}")
    values = _parse_key_values(loopback.stdout or "")
    require("AIO-01", values.get("login") == "200", f"login returned {values.get('login')!r}")
    require("AIO-01", values.get("api") == "200", f"authenticated /api/nodes returned {values.get('api')!r}")
    require("AIO-01", int(values.get("token_length") or 0) > 0, "login returned an empty access token")

    host = product.require_installed()
    probe = host.client_http(
        f"{PUBLIC_PANEL}/",
        expect_status=200,
        expect_san=[host.panel_domain],
        timeout=30,
    )
    require("AIO-01", probe["returncode"] == 0, f"HTTPS panel probe failed from the client: {probe['probe'].get('error')}")
    peer = probe["probe"].get("peer") or {}
    require("AIO-01", str(peer.get("tls_version", "")).startswith("TLSv1.3"),
            f"public HTTPS did not negotiate TLS 1.3: {peer.get('tls_version')!r}")
    return {
        "loopback_login": values.get("login"),
        "loopback_api": values.get("api"),
        "public_status": probe["probe"].get("status"),
        "public_tls": peer.get("tls_version"),
        "public_san": peer.get("san"),
    }


def case_credentials(product: AioProduct) -> Dict[str, Any]:
    """AIO-03: the credentials file is root-owned 0600 and holds the expected keys."""
    script = (
        f"test -f {CREDENTIALS_FILE} && stat -c '%U %a %s' {CREDENTIALS_FILE} || echo missing\n"
        f"grep -c '^ADMIN_USERNAME=' {CREDENTIALS_FILE} 2>/dev/null || true\n"
        f"grep -c '^ADMIN_PASSWORD=' {CREDENTIALS_FILE} 2>/dev/null || true\n"
        f"grep -c '^SCOPED_API_TOKEN=' {CREDENTIALS_FILE} 2>/dev/null || true\n"
        f"grep -c '^SHORT_UUID=' {CREDENTIALS_FILE} 2>/dev/null || true"
    )
    result = product.host_script(script)
    require("AIO-03", result.returncode == 0, f"credentials probe failed: {result.stderr.strip()}")
    lines = (result.stdout or "").splitlines()
    require("AIO-03", lines and lines[0].startswith("root"), f"credentials file stat: {lines[:1]}")
    owner, mode, _size = (lines[0].split() + ["", "", ""])[:3]
    require("AIO-03", owner == "root", f"credentials file owner is {owner!r}")
    require("AIO-03", mode == "600", f"credentials file mode is {mode!r}")
    counters = [int(value) for value in lines[1:5] if value.strip().isdigit()]
    require("AIO-03", len(counters) >= 4, "credentials file key probe produced no counts")
    require("AIO-03", all(count >= 1 for count in counters[:3]),
            "credentials file is missing ADMIN_USERNAME, ADMIN_PASSWORD, or SCOPED_API_TOKEN")
    return {
        "owner": owner,
        "mode": mode,
        "has_admin_username": counters[0] >= 1,
        "has_admin_password": counters[1] >= 1,
        "has_scoped_api_token": counters[2] >= 1,
        "has_short_uuid_key": counters[3] >= 1,
    }


def case_tls_and_identity(product: AioProduct) -> Dict[str, Any]:
    """AIO-05: both lineages are valid for their SANs, and shortUuid comes from the API."""
    host = product.require_installed()
    domains = [host.panel_domain, host.reality_domain]
    checks = []
    for domain in domains:
        live = f"{LETSENCRYPT_ROOT}/{domain}"
        # -checkhost is SAN-aware; verify against the run CA proves the chain is
        # the fixture directory's, not a self-signed or staged replacement.
        script = (
            f"openssl x509 -in {live}/cert.pem -noout -checkhost {domain}; "
            f"openssl x509 -in {live}/cert.pem -noout -checkend 86400; "
            f"openssl verify -CAfile {topology.CA_MOUNT}/{topology.ISSUED_ROOT_NAME} "
            f"-untrusted {live}/fullchain.pem {live}/cert.pem"
        )
        result = product.host_script(script)
        checks.append({"domain": domain, "returncode": result.returncode,
                       "stdout": (result.stdout or "").strip(), "stderr": (result.stderr or "").strip()})
        require("AIO-05", result.returncode == 0,
                f"certificate lineage for {domain} failed verification: {(result.stdout + result.stderr).strip()}")

    identity = product.host_script(identity_probe_script())
    require("AIO-05", identity.returncode == 0, f"identity probe failed: {identity.stderr.strip()}")
    values = _parse_key_values(identity.stdout or "")
    require("AIO-05", int(values.get("short_uuid_length") or 0) > 0,
            "the default user has no shortUuid from the Panel API")
    # The assertion forbids taking the identity from the credentials file, so the
    # absence of that key there is itself worth reporting.
    key_probe = product.host_script(
        f"grep -c '^SHORT_UUID=' {CREDENTIALS_FILE} 2>/dev/null || true"
    )
    key_count = (key_probe.stdout or "").strip()
    require("AIO-05", key_count in ("", "0"),
            f"the credentials file carries a SHORT_UUID key ({key_count}) and must not")
    return {
        "lineages": checks,
        "short_uuid_length": values.get("short_uuid_length"),
        "short_uuid_source": "api",
        "credentials_short_uuid_key": False,
    }


def _panel_facts(product: AioProduct, case_id: str, scope: str) -> Dict[str, Any]:
    """Run the host-side probe and return its facts; comparisons stay here."""
    return panel_probe(product, case_id, scope)


def panel_probe(product: AioProduct, case_id: str, scope: str, extra: str = "") -> Dict[str, Any]:
    """Run any panel_surface scope on the host, with optional trailing arguments."""
    arguments = f"--scope {scope}"
    if extra:
        arguments += f" {extra}"
    result = product.host_script(f"python3 {PANEL_SURFACE_SCRIPT} {arguments}")
    require(
        case_id,
        result.returncode == 0,
        f"the Panel probe exited {result.returncode}: "
        f"{(result.stderr or result.stdout or '').strip()[-2000:]}",
    )
    try:
        return json.loads(result.stdout or "")
    except json.JSONDecodeError:
        require(case_id, False, f"the Panel probe did not print JSON: {(result.stdout or '')[:400]}")
        return {}


def case_panel_auth(product: AioProduct) -> Dict[str, Any]:
    """AIO-AUTH: the documented admin login opens the real, consistent read surface.

    The inventory is read entirely through the API, so a case cannot be satisfied
    by a file the operator wrote next to it: the node's active inbounds, the
    profile that declares them, the squad that grants them, and the hosts that
    publish them must all describe the same set.
    """
    facts = _panel_facts(product, "AIO-AUTH", "surface")
    login = facts.get("login") or {}
    require("AIO-AUTH", login.get("status") == 200, f"admin login returned {login.get('status')!r}")
    require("AIO-AUTH", login.get("token_present"), "admin login returned no access token")

    surface = facts.get("surface") or {}
    # The read surface is only "authenticated" if the same call is refused
    # without the token.
    anonymous = surface.get("unauthenticated_nodes_status")
    require("AIO-AUTH", anonymous in (401, 403),
            f"an anonymous /api/nodes call returned {anonymous!r} instead of being refused")

    nodes = surface.get("nodes") or {}
    require("AIO-AUTH", nodes.get("status") == 200, f"/api/nodes returned {nodes.get('status')!r}")
    require("AIO-AUTH", nodes.get("count") == 1,
            f"the Panel reports {nodes.get('count')!r} nodes instead of the one local node")
    require("AIO-AUTH", nodes.get("inbound_count") == product.inbound_count,
            f"the local node exposes {nodes.get('inbound_count')!r} active inbounds, "
            f"expected {product.inbound_count}")
    require("AIO-AUTH", bool(nodes.get("inbound_digest")),
            "the local node reported no active inbound identifiers")

    profiles = surface.get("profiles") or {}
    require("AIO-AUTH", profiles.get("status") == 200,
            f"/api/config-profiles returned {profiles.get('status')!r}")
    require("AIO-AUTH", profiles.get("count") == 1,
            f"the Panel reports {profiles.get('count')!r} config profiles instead of one")
    require("AIO-AUTH", profiles.get("inbound_count") == product.inbound_count,
            f"the config profile declares {profiles.get('inbound_count')!r} inbounds, "
            f"expected {product.inbound_count}")
    require("AIO-AUTH", profiles.get("inbound_digest") == nodes.get("inbound_digest"),
            "the config profile and the node disagree on which inbounds are active")

    squads = surface.get("squads") or {}
    require("AIO-AUTH", squads.get("status") == 200,
            f"/api/internal-squads returned {squads.get('status')!r}")
    require("AIO-AUTH", squads.get("mvp_present"),
            "the Panel has no 'Default MVP Squad' to grant the profile's inbounds")
    require("AIO-AUTH", squads.get("mvp_inbound_digest") == profiles.get("inbound_digest"),
            "the default squad does not carry exactly the profile's inbounds")

    hosts = surface.get("hosts") or {}
    require("AIO-AUTH", hosts.get("status") == 200, f"/api/hosts returned {hosts.get('status')!r}")
    require("AIO-AUTH", hosts.get("count") == product.inbound_count,
            f"the Panel publishes {hosts.get('count')!r} hosts, expected one per inbound "
            f"({product.inbound_count})")
    require("AIO-AUTH", hosts.get("inbound_digest") == profiles.get("inbound_digest"),
            "the published hosts do not cover exactly the profile's inbounds")

    default_user = surface.get("default_user") or {}
    require("AIO-AUTH", default_user.get("status") == 200,
            f"/api/users/by-username/default-user returned {default_user.get('status')!r}")
    require("AIO-AUTH", int(default_user.get("short_uuid_length") or 0) > 0,
            "the default user has no shortUuid in the API")

    return {
        "login_status": login.get("status"),
        "token_length": login.get("token_length"),
        "unauthenticated_nodes_status": anonymous,
        "node_count": nodes.get("count"),
        "node_connected_count": nodes.get("connected_count"),
        "node_inbound_count": nodes.get("inbound_count"),
        "inbound_digest": nodes.get("inbound_digest"),
        "inbound_types": ",".join(nodes.get("inbound_types") or []),
        "inbound_ports": ",".join(nodes.get("inbound_ports") or []),
        "profile_count": profiles.get("count"),
        "profile_inbound_tags": ",".join(profiles.get("inbound_tags") or []),
        "squad_count": squads.get("count"),
        "squad_inbound_count": squads.get("mvp_inbound_count"),
        "host_count": hosts.get("count"),
        "host_fingerprints": ",".join(hosts.get("fingerprints") or []),
        "host_security_layers": ",".join(hosts.get("security_layers") or []),
        "default_user_short_uuid_length": default_user.get("short_uuid_length"),
    }


def case_client_lifecycle(product: AioProduct) -> Dict[str, Any]:
    """AIO-CLIENT: a client is created, read back, and deleted through the real API.

    The username is unique per invocation, and the deletion is part of the case
    rather than cleanup: leaving the client behind would make the next run's
    inventory assertions depend on the previous run.
    """
    facts = _panel_facts(product, "AIO-CLIENT", "lifecycle").get("lifecycle") or {}
    require("AIO-CLIENT", facts.get("squad_requested"),
            "no 'Default MVP Squad' exists, so the client could not be provisioned as documented")
    require("AIO-CLIENT", facts.get("create_status") == 201,
            f"POST /api/users returned {facts.get('create_status')!r} instead of 201")
    require("AIO-CLIENT", facts.get("created_id_present"), "the created client has no id")
    require("AIO-CLIENT", int(facts.get("created_short_uuid_length") or 0) > 0,
            "the created client has no shortUuid")
    require("AIO-CLIENT", facts.get("readback_status") == 200,
            f"reading the client back by username returned {facts.get('readback_status')!r}")
    require("AIO-CLIENT", facts.get("readback_username_matches"),
            "the client read back by username is not the one that was created")
    require("AIO-CLIENT", facts.get("readback_short_uuid_matches"),
            "the client read back by username has a different shortUuid")
    require("AIO-CLIENT", facts.get("readback_squad_count") == 1,
            f"the client was created with one squad but reports "
            f"{facts.get('readback_squad_count')!r}")
    require("AIO-CLIENT", facts.get("get_by_id_status") == 200,
            f"reading the client by id returned {facts.get('get_by_id_status')!r}")
    require("AIO-CLIENT", facts.get("delete_status") == 204,
            f"DELETE /api/users/{{id}} returned {facts.get('delete_status')!r} instead of 204")
    require("AIO-CLIENT", facts.get("after_delete_status") == 404,
            f"the deleted client is still served by username "
            f"(status {facts.get('after_delete_status')!r})")
    return facts


def case_revocation(product: AioProduct) -> Dict[str, Any]:
    """AIO-REVOKE: revoked access stops transferring, and the Panel says so.

    The client is created through the real API, its subscription is captured while
    it still works, and a payload travels through every transport with it — after
    one transfer has shown that the Panel's asynchronous user push has reached the
    node. The documented revoke action then rotates the credentials and the
    subscription path, and the payload the client already holds is replayed by
    freshly started engines.

    The verdict does not rest on an error message: a closed port would produce the
    same silence. It rests on the controlled endpoint's own log holding none of
    those requests, after the Panel has already reported the rotation.

    The client is deleted whether the case passes or not, so a failed run cannot
    leave inventory that changes the next run's assertions.
    """
    host = product.require_installed()
    # The Panel probe runs on the target, where the payload volume is mounted at
    # PAYLOAD_MOUNT; the engines run in the client, where the same volume is
    # mounted read-only at SECRETS_MOUNT.
    payload_dir = f"{topology.SECRETS_MOUNT}/{panel_surface.REVOKE_DIRECTORY}"
    issue = panel_probe(
        product, "AIO-REVOKE", "revoke", f"--step issue --payload-dir {topology.PAYLOAD_MOUNT}",
    ).get("revocation") or {}
    require("AIO-REVOKE", issue.get("squad_requested"),
            "no 'Default MVP Squad' exists, so the revocation client could not be granted an inbound")
    require("AIO-REVOKE", issue.get("create_status") == 201,
            f"POST /api/users returned {issue.get('create_status')!r} instead of 201")
    require("AIO-REVOKE", issue.get("patch_status") == 200,
            f"PATCH /api/users/{{id}} returned {issue.get('patch_status')!r} instead of 200")
    require("AIO-REVOKE", issue.get("patch_visible"),
            "the traffic limit written by PATCH /api/users/{id} is not visible on read back")
    representations = issue.get("representations") or {}
    unserved = sorted(name for name, facts in representations.items() if (facts or {}).get("status") != 200)
    require("AIO-REVOKE", not unserved, f"the created client was not served: {', '.join(unserved)}")
    require("AIO-REVOKE", bool(issue.get("credential_digest")),
            "the captured subscription carries no credential to compare against after revoking")

    try:
        tunnel = product.wait_tunnel_ready("AIO-REVOKE", payload_dir=payload_dir)
        positive = product.traffic_facts("AIO-REVOKE", "traffic", payload_dir=payload_dir)
        expected = product.inbound_count * len(TRAFFIC_ENGINES)
        require("AIO-REVOKE", int(positive.get("transfer_count") or 0) == expected,
                f"the issued client transferred through {positive.get('transfer_count')!r} "
                f"transports, expected {expected}")
        require("AIO-REVOKE", int(positive.get("missing_request_ids") or 0) == 0,
                f"the endpoint never saw {positive.get('missing_request_ids')!r} of the issued "
                "client's requests")
        unverified = [item["tag"] for item in positive.get("transfers") or []
                      if not (item.get("request_id_match") and item.get("body_match"))]
        require("AIO-REVOKE", not unverified,
                f"the endpoint did not echo the payload for: {', '.join(unverified)}")
        require("AIO-REVOKE", positive.get("source_ips") == [host.plan.data_target_ip],
                f"the issued client's payload left from {positive.get('source_ips')!r} "
                f"instead of the installed host {host.plan.data_target_ip}")

        applied = panel_probe(
            product, "AIO-REVOKE", "revoke", f"--step apply --payload-dir {topology.PAYLOAD_MOUNT}",
        ).get("revocation") or {}
        require("AIO-REVOKE", applied.get("revoke_status") == 200,
                f"POST /api/users/{{id}}/actions/revoke returned {applied.get('revoke_status')!r}")
        require("AIO-REVOKE", applied.get("revoked_at_present"),
                "the revoke action reported no subRevokedAt, so the Panel recorded no revocation")
        require("AIO-REVOKE", applied.get("short_uuid_rotated"),
                "the revoke action did not rotate the subscription path")
        require("AIO-REVOKE", applied.get("old_subscription_status") == 404,
                f"the revoked subscription path still answers with "
                f"{applied.get('old_subscription_status')!r} instead of 404")
        require("AIO-REVOKE", applied.get("new_subscription_status") == 200,
                f"the rotated subscription path answers {applied.get('new_subscription_status')!r}")
        require("AIO-REVOKE", applied.get("credential_digest_changed"),
                "the subscription served after revoking carries the same credentials as before")

        negative = product.traffic_facts("AIO-REVOKE", "revoked", payload_dir=payload_dir)
        require("AIO-REVOKE", int(negative.get("delivered") or 0) == 0,
                f"{negative.get('delivered')!r} transports still delivered a payload with revoked access")
        require("AIO-REVOKE", int(negative.get("refused") or 0) == int(negative.get("attempt_count") or -1),
                f"{negative.get('refused')!r} of {negative.get('attempt_count')!r} attempts were refused")
        require("AIO-REVOKE", int(negative.get("attempt_count") or 0) == expected,
                f"the revoked access exercised {negative.get('attempt_count')!r} transports, "
                f"expected {expected}")
        require("AIO-REVOKE", int(negative.get("recorded_request_ids") or 0) == 0,
                "the endpoint recorded a request sent with revoked access")
    finally:
        cleanup = panel_probe(
            product, "AIO-REVOKE", "revoke", f"--step cleanup --payload-dir {topology.PAYLOAD_MOUNT}",
        ).get("revocation") or {}
        require("AIO-REVOKE", cleanup.get("delete_status") == 204,
                f"deleting the revocation client returned {cleanup.get('delete_status')!r} "
                "instead of 204")
        require("AIO-REVOKE", cleanup.get("after_delete_status") == 404,
                f"the revocation client is still served after deletion "
                f"(status {cleanup.get('after_delete_status')!r})")

    return {
        "created_id_present": issue.get("created_id_present"),
        "created_short_uuid_length": issue.get("created_short_uuid_length"),
        "representations": ",".join(sorted(representations)),
        "patch_status": issue.get("patch_status"),
        "readiness_network": tunnel.get("network"),
        "positive_transfer_count": positive.get("transfer_count"),
        "positive_source_ips": ",".join(positive.get("source_ips") or []),
        "revoke_status": applied.get("revoke_status"),
        "revoked_at_present": applied.get("revoked_at_present"),
        "old_subscription_status": applied.get("old_subscription_status"),
        "new_subscription_status": applied.get("new_subscription_status"),
        "credential_digest_changed": applied.get("credential_digest_changed"),
        "revoked_attempt_count": negative.get("attempt_count"),
        "revoked_refused": negative.get("refused"),
        "revoked_delivered": negative.get("delivered"),
        "revoked_rounds": negative.get("rounds"),
        "revoked_networks": ",".join(negative.get("networks") or []),
        "recorded_request_ids": negative.get("recorded_request_ids"),
        "delete_status": cleanup.get("delete_status"),
    }


def inventory_sections(output: str) -> Dict[str, List[str]]:
    """Split the marked inventory output into one sorted list per resource area."""
    sections: Dict[str, List[str]] = {}
    current = ""
    for line in (output or "").splitlines():
        if line.startswith("=="):
            current = line[2:].strip()
            sections[current] = []
        elif line.strip() and current:
            sections[current].append(line.strip())
    return sections


def system_inventory(product: AioProduct, case_id: str) -> Dict[str, List[str]]:
    """The host resources a repeated install must neither duplicate nor rewrite."""
    result = product.host_script(INVENTORY_SCRIPT)
    require(case_id, result.returncode == 0,
            f"the host inventory probe exited {result.returncode}: "
            f"{(result.stderr or '').strip()[-800:]}")
    return inventory_sections(result.stdout or "")


def case_restart(product: AioProduct) -> Dict[str, Any]:
    """AIO-RESTART: the product's own units restart and the service recovers.

    Restarting the product's units is what an operator does after a configuration
    change or a package update, so the case stops them the way the product starts
    them and then waits, under one deadline, for the Panel and the tunnel's
    loopback upstream to come back. The data plane is exercised afterwards because
    a control plane that recovers while the tunnel stayed down would otherwise
    look healthy; one served outbound has to carry a payload first, because a node
    that has its listener back applies its users asynchronously.
    """
    host = product.require_installed()
    product.subscription_payloads("AIO-RESTART")

    started = time.monotonic()
    restart = product.host_script(f"systemctl restart {' '.join(UNITS)}", timeout=300)
    require("AIO-RESTART", restart.returncode == 0,
            f"systemctl restart of the product's units exited {restart.returncode}: "
            f"{(restart.stderr or restart.stdout or '').strip()[-800:]}")

    observed: Dict[str, str] = {}

    def answers() -> bool:
        probe = product.host_script(restart_readiness_script())
        observed["probe_returncode"] = str(probe.returncode)
        if probe.returncode != 0:
            return False
        values = _parse_key_values(probe.stdout or "")
        observed.update(values)
        return (
            values.get("login") == "200"
            and values.get("api") == "200"
            and values.get("upstreams") == "2"
        )

    recovered = wait_until(
        answers, RESTART_TIMEOUT_SECONDS, "the product after restarting its units",
        interval_seconds=RESTART_INTERVAL_SECONDS,
    )
    downtime = round(time.monotonic() - started, 1)
    require("AIO-RESTART", recovered,
            f"the product did not recover within {RESTART_TIMEOUT_SECONDS}s of restarting its "
            f"units: {observed}")

    active = product.host_script(f"systemctl is-active {' '.join(UNITS)} || true")
    states = dict(zip(UNITS, (active.stdout or "").split()))
    inactive = sorted(name for name in UNITS if states.get(name) != "active")
    require("AIO-RESTART", not inactive,
            "units are not active after the restart: "
            + ", ".join(f"{name}={states.get(name)}" for name in inactive))

    tunnel = product.wait_tunnel_ready("AIO-RESTART")

    facts = product.traffic_facts("AIO-RESTART", "traffic")
    expected = product.inbound_count * len(TRAFFIC_ENGINES)
    require("AIO-RESTART", int(facts.get("transfer_count") or 0) == expected,
            f"after the restart {facts.get('transfer_count')!r} transports carried a payload, "
            f"expected {expected}")
    require("AIO-RESTART", int(facts.get("missing_request_ids") or 0) == 0,
            f"the endpoint never saw {facts.get('missing_request_ids')!r} requests after the restart")
    unverified = [item["tag"] for item in facts.get("transfers") or []
                  if not (item.get("request_id_match") and item.get("body_match"))]
    require("AIO-RESTART", not unverified,
            f"the endpoint did not echo the payload after the restart for: {', '.join(unverified)}")
    require("AIO-RESTART", facts.get("source_ips") == [host.plan.data_target_ip],
            f"the recovered payload left from {facts.get('source_ips')!r} instead of the "
            f"installed host {host.plan.data_target_ip}")

    return {
        "restart_units": ",".join(UNITS),
        "recovery_seconds": downtime,
        "loopback_login": observed.get("login"),
        "loopback_api": observed.get("api"),
        "readiness_network": tunnel.get("network"),
        "unit_states": ",".join(f"{name}={states.get(name)}" for name in UNITS),
        "transfer_count": facts.get("transfer_count"),
        "source_ips": ",".join(facts.get("source_ips") or []),
    }


def case_idempotent(product: AioProduct) -> Dict[str, Any]:
    """AIO-IDEMPOTENT: the same install again adds nothing and breaks nothing.

    Two independent surfaces have to agree. The Panel inventory is read through
    the API before and after, so a duplicated node, profile, squad, host or token
    is a changed count rather than an opinion; the host inventory is read as file
    lists and digests, so a second NGINX config or a rewritten one is equally
    visible. The subscription the Panel already served must still carry the same
    credentials, and the clients that imported it must still transfer.
    """
    host = product.require_installed()
    product.subscription_payloads("AIO-IDEMPOTENT")

    before = _panel_facts(product, "AIO-IDEMPOTENT", "surface")
    require("AIO-IDEMPOTENT", (before.get("login") or {}).get("status") == 200,
            "the admin credentials did not work before the repeated install")
    baseline = before.get("surface") or {}
    baseline_host = system_inventory(product, "AIO-IDEMPOTENT")
    baseline_subscription = panel_probe(
        product, "AIO-IDEMPOTENT", "subscriptions", f"--payload-dir {topology.PAYLOAD_MOUNT}",
    ).get("subscriptions") or {}
    require("AIO-IDEMPOTENT", bool(baseline_subscription.get("credential_digest")),
            "the Panel served no subscription credentials to compare after the repeated install")

    repeat = product.reinstall("AIO-IDEMPOTENT")

    after = _panel_facts(product, "AIO-IDEMPOTENT", "surface")
    require("AIO-IDEMPOTENT", (after.get("login") or {}).get("status") == 200,
            "the credentials file no longer authenticates the admin after the repeated install")
    current = after.get("surface") or {}

    changed = []
    for area, field in (
        ("nodes", "count"), ("profiles", "count"), ("squads", "count"),
        ("hosts", "count"), ("tokens", "count"),
        ("nodes", "inbound_digest"), ("profiles", "inbound_digest"),
        ("squads", "mvp_inbound_digest"), ("hosts", "inbound_digest"),
        ("tokens", "name_digest"),
    ):
        was = (baseline.get(area) or {}).get(field)
        now = (current.get(area) or {}).get(field)
        if was != now:
            changed.append(f"{area}.{field}: {was!r} -> {now!r}")
    require("AIO-IDEMPOTENT", not changed,
            "the repeated install changed the Panel inventory: " + "; ".join(changed))

    current_host = system_inventory(product, "AIO-IDEMPOTENT")
    rewritten = [area for area in ("units", "unit-files", "nginx")
                 if baseline_host.get(area) != current_host.get(area)]
    require("AIO-IDEMPOTENT", not rewritten,
            "the repeated install changed host resources: " + ", ".join(rewritten))
    require("AIO-IDEMPOTENT", current_host.get("credentials") == ["root 600"],
            f"the credentials file is {current_host.get('credentials')!r} after the repeated "
            "install instead of root-owned mode 600")

    after_subscription = panel_probe(
        product, "AIO-IDEMPOTENT", "subscriptions", f"--payload-dir {topology.PAYLOAD_MOUNT}",
    ).get("subscriptions") or {}
    require("AIO-IDEMPOTENT",
            baseline_subscription.get("credential_digest") == after_subscription.get("credential_digest"),
            "the repeated install rotated the credentials the served subscription carries, so "
            "every client that already imported it would stop working")

    facts = product.traffic_facts("AIO-IDEMPOTENT", "traffic")
    expected = product.inbound_count * len(TRAFFIC_ENGINES)
    require("AIO-IDEMPOTENT", int(facts.get("transfer_count") or 0) == expected,
            f"after the repeated install {facts.get('transfer_count')!r} transports carried a "
            f"payload, expected {expected}")
    require("AIO-IDEMPOTENT", int(facts.get("missing_request_ids") or 0) == 0,
            f"the endpoint never saw {facts.get('missing_request_ids')!r} requests after the "
            "repeated install")
    unverified = [item["tag"] for item in facts.get("transfers") or []
                  if not (item.get("request_id_match") and item.get("body_match"))]
    require("AIO-IDEMPOTENT", not unverified,
            "the endpoint did not echo the payload after the repeated install for: "
            + ", ".join(unverified))
    require("AIO-IDEMPOTENT", facts.get("source_ips") == [host.plan.data_target_ip],
            f"the payload after the repeated install left from {facts.get('source_ips')!r} instead "
            f"of the installed host {host.plan.data_target_ip}")

    return {
        "reinstall_returncode": repeat.get("reinstall_returncode"),
        "reinstall_duration_seconds": repeat.get("reinstall_duration_seconds"),
        "panel_counts": ",".join(
            f"{area}={(current.get(area) or {}).get('count')}"
            for area in ("nodes", "profiles", "squads", "hosts", "tokens")
        ),
        "credentials": ",".join(current_host.get("credentials") or []),
        "nginx_files": len(current_host.get("nginx") or []),
        "unit_files": len(current_host.get("unit-files") or []),
        "credential_digest_changed": (
            baseline_subscription.get("credential_digest") != after_subscription.get("credential_digest")
        ),
        "transfer_count": facts.get("transfer_count"),
        "source_ips": ",".join(facts.get("source_ips") or []),
    }


def case_negative_destination(product: AioProduct) -> Dict[str, Any]:
    """AIO-NEG-DEST: a destination the product's egress policy excludes is denied.

    The product compiles one routing rule that sends private and loopback
    destinations to its block outbound, and the same subscription is used for
    both halves of this case. The permitted control must arrive first: a refusal
    that also happens on a working destination is a broken tunnel, not a policy.
    """
    product.subscription_payloads("AIO-NEG-DEST")
    facts = product.prohibited_facts("AIO-NEG-DEST")
    require("AIO-NEG-DEST", facts.get("control_delivered") is True,
            "the permitted control transfer did not reach the endpoint, so a refusal of the "
            "prohibited destination would prove nothing")
    require("AIO-NEG-DEST", facts.get("delivered") is False,
            "a payload addressed to a private destination the product's routing excludes was "
            f"delivered (status {facts.get('status')!r})")
    require("AIO-NEG-DEST", facts.get("recorded_request_ids") == 0,
            f"the endpoint recorded {facts.get('recorded_request_ids')!r} request(s) sent to a "
            "destination the product excludes")
    return {
        "engine": facts.get("engine"),
        "network": facts.get("network"),
        "control_delivered": facts.get("control_delivered"),
        "delivered": facts.get("delivered"),
        "status": facts.get("status"),
        "reason": facts.get("reason"),
        "endpoint_records": facts.get("endpoint_records"),
    }


def case_foreign_listener(product: AioProduct) -> Dict[str, Any]:
    """AIO-NEG-PORT: preflight refuses a foreign listener and keeps the product's own.

    A repeated install legitimately rediscovers the product on the ports it is
    about to check, so the port guard has exactly two jobs and both are asserted
    here on the installed host: a port this topology leaves free, held by a
    process outside the managed units, must be a conflict, and 443 — held by the
    product's own NGINX — must not be one.
    """
    result = product.host_script(FOREIGN_LISTENER_SCRIPT, timeout=240)
    require("AIO-NEG-PORT", result.returncode == 0,
            f"the port-conflict probe failed: {(result.stderr or result.stdout or '').strip()[-600:]}")
    values = _parse_key_values(result.stdout or "")
    require("AIO-NEG-PORT", values.get("port", "").isdigit(),
            f"the probe found no declared port to hold: {values}")
    require("AIO-NEG-PORT", values.get("foreign") == "refused",
            f"a foreign listener on port {values.get('port')} was accepted as no conflict")
    require("AIO-NEG-PORT", values.get("managed") == "accepted",
            "the product's own listener on 443 was reported as a port conflict")
    require("AIO-NEG-PORT", values.get("released") == "accepted",
            f"port {values.get('port')} stayed a conflict after the foreign listener exited")
    return {
        "port": int(values["port"]),
        "foreign_listener": values.get("foreign"),
        "managed_listener": values.get("managed"),
        "after_release": values.get("released"),
    }


def case_acme_fail_closed(product: AioProduct) -> Dict[str, Any]:
    """AIO-NEG-ACME: the local ACME fixture is reachable only through its pinned opt-in.

    Both directions are asserted, because only the pair is safe: enabling test
    mode must not turn the fixture into an arbitrary-URL option, and the fixture
    must stay unusable without it. The production directory has to remain
    accepted, which is what keeps the default path unchanged.
    """
    result = product.host_script(ACME_FAIL_CLOSED_SCRIPT)
    require("AIO-NEG-ACME", result.returncode == 0,
            f"the ACME validation probe failed: {(result.stderr or result.stdout or '').strip()[-600:]}")
    values = _parse_key_values(result.stdout or "")
    require("AIO-NEG-ACME", values.get("fixture_without_optin") == "refused",
            "the local ACME fixture endpoint was accepted without GOWAVE_ACME_TEST_MODE=1")
    require("AIO-NEG-ACME", values.get("arbitrary_in_test_mode") == "refused",
            "an arbitrary ACME URL was accepted inside test mode")
    require("AIO-NEG-ACME", values.get("unpinned_ca") == "refused",
            "test mode accepted a CA file whose digest does not match the pinned one")
    require("AIO-NEG-ACME", values.get("letsencrypt_production") == "accepted",
            "the production ACME directory was rejected, so the default path changed")
    return {
        "fixture_without_optin": values.get("fixture_without_optin"),
        "arbitrary_in_test_mode": values.get("arbitrary_in_test_mode"),
        "unpinned_ca": values.get("unpinned_ca"),
        "letsencrypt_production": values.get("letsencrypt_production"),
    }


def case_public_dependency(product: AioProduct) -> Dict[str, Any]:
    """AIO-NEG-DEP: the public surface fails with its NGINX dependency and recovers.

    NGINX is what terminates 443 and hands the SNI to the Panel and to Xray, so
    taking it down must remove the public surface while the Panel's loopback API
    keeps answering. The restart is then followed to a deadline rather than
    assumed: a unit that reports active before its listeners are bound would
    otherwise pass, and the recovered public call has to be the same request the
    stopped dependency broke.
    """
    host = product.require_installed()
    before = host.client_http(f"{PUBLIC_PANEL}/", expect_status=200, timeout=30)
    require("AIO-NEG-DEP", before["returncode"] == 0,
            f"the public surface did not answer before the dependency was removed: "
            f"{before['probe'].get('error')}")

    stopped = product.host_script("systemctl stop nginx; systemctl is-active nginx || true")
    require("AIO-NEG-DEP", stopped.returncode == 0,
            f"NGINX did not stop: {(stopped.stderr or '').strip()[-400:]}")
    down = host.client_http(f"{PUBLIC_PANEL}/", expect_status=200, timeout=20)
    require("AIO-NEG-DEP", down["returncode"] != 0,
            "the public surface still answered with NGINX stopped, so 443 does not depend on it")

    loopback = product.host_script(panel_probe_script())
    values = _parse_key_values(loopback.stdout or "")
    require("AIO-NEG-DEP", values.get("login") == "200",
            f"the Panel itself stopped answering when NGINX stopped: login {values.get('login')!r}")

    started = product.host_script("systemctl start nginx; systemctl is-active nginx || true")
    require("AIO-NEG-DEP", (started.stdout or "").strip() == "active",
            f"NGINX did not come back active: {(started.stdout or '').strip()!r}")

    def recovered() -> bool:
        probe = host.client_http(f"{PUBLIC_PANEL}/", expect_status=200, timeout=20)
        return probe["returncode"] == 0

    ready = wait_until(recovered, RECOVERY_TIMEOUT_SECONDS, "the public surface after NGINX returned",
                       interval_seconds=RECOVERY_INTERVAL_SECONDS)
    require("AIO-NEG-DEP", ready,
            f"the public surface did not recover within {RECOVERY_TIMEOUT_SECONDS}s of NGINX restarting")
    return {
        "public_before": before["probe"].get("status"),
        "public_without_dependency": "failed",
        "panel_loopback_login": values.get("login"),
        "public_after_recovery": 200,
    }


def case_subscriptions(product: AioProduct) -> Dict[str, Any]:
    """SUB-SERVED: every served representation is fetched and loaded by its real client.

    The Panel serves five representations and none of them substitutes for
    another: the base64 list is what an Xray-family mobile client imports, the
    Xray JSON is a config object or a list of complete per-profile configs, and
    the Mihomo YAML is loaded by Mihomo itself. The Clash YAML is loaded by the
    same engine but carries only the trojan subset the shipped Clash generator
    keeps. Only the representations a pinned engine consumes are executed,
    because the sing-box client is not part of the pinned matrix.
    """
    facts = product.collect_subscriptions("SUB-SERVED")
    require("SUB-SERVED", int(facts.get("short_uuid_length") or 0) > 0,
            "the default client has no shortUuid, so no subscription could be fetched")

    served = facts.get("representations") or {}
    for name in REPRESENTATIONS:
        record = served.get(name) or {}
        require("SUB-SERVED", record.get("status") == 200,
                f"GET /api/sub/<shortUuid>/{name} returned {record.get('status')!r} instead of 200")
        require("SUB-SERVED", int(record.get("bytes") or 0) > 0,
                f"the {name} representation is empty")
        require("SUB-SERVED", bool(record.get("content_type")),
                f"the {name} representation came back without a media type")

    loaded = product.engine_facts("SUB-SERVED", "representations")

    base64 = loaded.get("base64") or {}
    require("SUB-SERVED", base64.get("decoded"), "the base64 subscription did not decode")
    require("SUB-SERVED", base64.get("link_count") == product.subscription_inbound_count,
            f"the base64 list carries {base64.get('link_count')!r} links, expected one per inbound "
            f"({product.subscription_inbound_count})")

    xray_json = loaded.get("xray_json") or {}
    shape = xray_json.get("shape")
    require("SUB-SERVED", shape in ("list", "object"),
            f"the Xray JSON is neither a config object nor a profile list (shape {shape!r})")
    expected_entries = product.subscription_inbound_count if shape == "list" else 1
    require("SUB-SERVED", xray_json.get("entries") == expected_entries,
            f"the Xray JSON {shape} carries {xray_json.get('entries')!r} profile(s), "
            f"expected {expected_entries}")
    require("SUB-SERVED", sorted(xray_json.get("protocols") or []) == ["trojan", "vless"],
            f"the Xray profiles carry outbound protocols {xray_json.get('protocols')!r} instead of "
            "the core vless and trojan set")
    # Every served profile is a complete config and is validated as one; the
    # runtime wrapper exists for a bare outbound object, which is not what the
    # Panel serves.
    require("SUB-SERVED", xray_json.get("wrapped") == 0,
            f"a served Xray {shape} profile needed {xray_json.get('wrapped')!r} runtime wrapper(s) "
            "before Xray accepted it, so it is not a runnable config")

    # Clash keeps only the trojan subset, and each node issues one, so a cluster
    # serves one Clash proxy per node rather than the single one an All-in-One
    # install serves.
    trojan_inbounds = subscription_protocol_counts(product).get("trojan", 0)
    for name, proxies, expected_types, reason in (
        ("mihomo", product.subscription_inbound_count, MIHOMO_PROXY_TYPES, "one per inbound"),
        ("clash", trojan_inbounds, CLASH_PROXY_TYPES,
         "one per trojan inbound, so the trojan subset GenerateClash keeps"),
    ):
        record = loaded.get(name) or {}
        require("SUB-SERVED", record.get("exit") == 0,
                f"{name} did not load the Panel YAML (exit {record.get('exit')!r})")
        require("SUB-SERVED", record.get("proxies") == proxies,
                f"the {name} YAML declares {record.get('proxies')!r} proxies, expected {proxies} "
                f"({reason})")
        require("SUB-SERVED", sorted(record.get("proxy_types") or []) == list(expected_types),
                f"the {name} YAML declares proxy types {record.get('proxy_types')!r}, expected "
                f"{list(expected_types)!r}")
        require("SUB-SERVED", record.get("match_rule"),
                f"the {name} YAML has no MATCH rule, so a client would route nothing through it")

    # A subscription that loads is not yet a subscription for this cluster: the
    # YAML has to address the Worker too, or the client would only ever reach the
    # Master. Every name the run configured for its nodes must appear as a server.
    mihomo_servers = {
        str(entry.get("server") or "")
        for entry in (loaded.get("mihomo") or {}).get("proxy_details") or []
    }
    missing_servers = sorted(required_subscription_hosts(product) - mihomo_servers)
    require("SUB-SERVED", not missing_servers,
            f"the Mihomo YAML addresses {sorted(mihomo_servers)} but never "
            f"{', '.join(missing_servers)}, so the client it configures cannot reach that node")

    singbox = loaded.get("singbox") or {}
    require("SUB-SERVED", singbox.get("parsed"), "the sing-box JSON did not parse")
    require("SUB-SERVED", int(singbox.get("outbounds") or 0) > 0,
            "the sing-box JSON carries no outbounds")

    evidence: Dict[str, Any] = {"short_uuid_length": facts.get("short_uuid_length")}
    for name in REPRESENTATIONS:
        record = served.get(name) or {}
        evidence[f"{name}_status"] = record.get("status")
        evidence[f"{name}_content_type"] = record.get("content_type")
        evidence[f"{name}_bytes"] = record.get("bytes")
    evidence["base64_link_count"] = base64.get("link_count")
    evidence["base64_schemes"] = ",".join(base64.get("schemes") or [])
    evidence["xray_json_shape"] = shape
    evidence["xray_json_entries"] = xray_json.get("entries")
    evidence["xray_json_wrapped"] = xray_json.get("wrapped")
    evidence["xray_json_protocols"] = ",".join(xray_json.get("protocols") or [])
    for name in ("mihomo", "clash"):
        record = loaded.get(name) or {}
        evidence[f"{name}_proxies"] = record.get("proxies")
        evidence[f"{name}_proxy_types"] = ",".join(record.get("proxy_types") or [])
        evidence[f"{name}_groups"] = record.get("groups")
        evidence[f"{name}_match_rule"] = record.get("match_rule")
    evidence["mihomo_servers"] = ",".join(sorted(mihomo_servers))
    evidence["singbox_outbounds"] = singbox.get("outbounds")
    return evidence


def _user_agent_case(product: AioProduct, case_id: str, scope: str, policy: str) -> Dict[str, Any]:
    """Assert the pinned policy: no header and a blank header are both refused."""
    facts = _panel_facts(product, case_id, scope).get("policy") or {}
    require(case_id, facts.get("policy") == policy,
            f"the probe reported policy {facts.get('policy')!r} instead of {policy!r}")
    statuses = facts.get("representations") or {}
    require(case_id, set(statuses) == set(REPRESENTATIONS),
            f"the probe asked {sorted(statuses)} instead of every served representation")
    served = sorted(name for name, status in statuses.items() if status != UA_REFUSAL_STATUS)
    require(case_id, not served,
            f"the Panel served {', '.join(served)} with a {policy} User-Agent instead of "
            f"refusing it with {UA_REFUSAL_STATUS}")
    return {
        "policy": policy,
        "representation_count": len(statuses),
        "statuses": ",".join(f"{name}={statuses[name]}" for name in REPRESENTATIONS),
    }


def case_user_agent_absent(product: AioProduct) -> Dict[str, Any]:
    """SUB-UA-ABSENT: a subscription request without a User-Agent header is refused."""
    return _user_agent_case(product, "SUB-UA-ABSENT", "ua-absent", "absent")


def case_user_agent_blank(product: AioProduct) -> Dict[str, Any]:
    """SUB-UA-BLANK: a subscription request with an explicitly blank header is refused."""
    return _user_agent_case(product, "SUB-UA-BLANK", "ua-blank", "blank")


def case_share_links(product: AioProduct) -> Dict[str, Any]:
    """SUB-B64: the base64 list describes exactly the served proxy inventory.

    The link list is decoded and every entry is compared with the outbound the
    Panel publishes in its Xray JSON, so the two representations cannot drift
    apart unnoticed. Xray imports the decoded list; the raw JSON body, offered to
    the same importer, yields nothing.
    """
    product.subscription_payloads("SUB-B64")
    host = product.require_installed()
    facts = product.engine_facts("SUB-B64", "share-links")

    expected_protocols = subscription_protocol_counts(product)
    require("SUB-B64", facts.get("link_count") == product.subscription_inbound_count,
            f"the base64 list carries {facts.get('link_count')!r} links, expected one per inbound "
            f"({product.subscription_inbound_count})")
    require("SUB-B64", facts.get("protocols") == expected_protocols,
            f"the link list carries protocols {facts.get('protocols')!r} instead of the inbound "
            f"set's own {expected_protocols!r}")
    require("SUB-B64", facts.get("ports") == ["443"],
            f"the links point at ports {facts.get('ports')!r} instead of the public 443 listener")
    require("SUB-B64", facts.get("sni_missing") == 0,
            f"{facts.get('sni_missing')!r} links carry no SNI")
    require("SUB-B64", facts.get("fingerprint_missing") == 0,
            f"{facts.get('fingerprint_missing')!r} links carry no uTLS fingerprint")
    require("SUB-B64", facts.get("fingerprints") == [EXPECTED_FINGERPRINT],
            f"the links carry fingerprints {facts.get('fingerprints')!r} instead of "
            f"{EXPECTED_FINGERPRINT!r}")
    require("SUB-B64", facts.get("credential_present"),
            "at least one link carries no client credential, so it could not be imported")
    domains = host.subscription_domains()
    allowed_hosts = set(domains.get("allowed") or set())
    unknown_hosts = sorted(set(facts.get("hosts") or []) - allowed_hosts)
    require("SUB-B64", not unknown_hosts,
            f"the links point at hosts this run never configured: {', '.join(unknown_hosts)}")
    unknown_snis = sorted(set(facts.get("snis") or []) - allowed_hosts)
    require("SUB-B64", not unknown_snis,
            f"the links name SNIs this run never configured: {', '.join(unknown_snis)}")
    # Importing the list proves it is well formed; it does not prove the list is
    # this cluster's. Every node the run configured has to be dialled by name,
    # and has to present the SNI its own inbound was issued for.
    required_hosts = set(domains.get("required_hosts") or set())
    unserved = sorted(required_hosts - set(facts.get("hosts") or []))
    require("SUB-B64", not unserved,
            f"no link dials {', '.join(unserved)}, so the served list omits a node the run "
            "provisioned")
    required_snis = set(domains.get("required_snis") or set())
    unsnid = sorted(required_snis - set(facts.get("snis") or []))
    require("SUB-B64", not unsnid,
            f"no link carries the SNI {', '.join(unsnid)}, so the inbound it was issued for is "
            "unreachable through the list")

    require("SUB-B64", facts.get("xray_outbounds") == product.subscription_inbound_count,
            f"Xray imported {facts.get('xray_outbounds')!r} outbounds from the link list")
    require("SUB-B64", facts.get("cross_representation_issued") == product.subscription_inbound_count,
            f"the Xray JSON publishes {facts.get('cross_representation_issued')!r} proxy outbounds")
    require(
        "SUB-B64",
        facts.get("cross_representation_matches") == facts.get("cross_representation_issued"),
        f"only {facts.get('cross_representation_matches')!r} of "
        f"{facts.get('cross_representation_issued')!r} link entries match the Panel's own JSON "
        "outbounds",
    )
    require("SUB-B64", facts.get("json_body_links") == 0,
            f"the raw Xray JSON body yielded {facts.get('json_body_links')!r} share links, so the "
            "two representations cannot be told apart by an importer")

    return {
        "link_count": facts.get("link_count"),
        "protocols": ",".join(f"{name}={count}" for name, count in sorted((facts.get("protocols") or {}).items())),
        "hosts": ",".join(facts.get("hosts") or []),
        "snis": ",".join(facts.get("snis") or []),
        "fingerprints": ",".join(facts.get("fingerprints") or []),
        "ports": ",".join(facts.get("ports") or []),
        "networks": ",".join(facts.get("networks") or []),
        "xray_outbounds": facts.get("xray_outbounds"),
        "cross_representation_matches": facts.get("cross_representation_matches"),
        "json_body_links": facts.get("json_body_links"),
    }


def case_data_plane(
    product: AioProduct, inbound: Dict[str, Any], client: str, node: str = "",
) -> Dict[str, Any]:
    """One matrix tuple carries a payload through the product it belongs to.

    The case id comes from the matrix topology the product names (``AIO-DP-…``
    for one host, ``MN-DP-<node>-…`` for a cluster).

    The engines run from the Control Machine, so a transfer that shows up at the
    endpoint with the installed host as its source address traversed the product.
    A 200 alone is not proof: the endpoint has to echo the request id and the
    digest of the body it received, and the SNI has to be the domain the inbound
    was issued for, because a served outbound that addresses another host would
    still answer while proving the wrong tuple.

    Exactly one served outbound may match the tuple: the matrix names one inbound
    per transport and security layer, so a second match is a representation the
    matrix does not explain and must not be counted as this case. In a cluster
    the node is part of the tuple for the same reason: both nodes serve the same
    layers, so the outbound, the SNI and the egress address all have to be that
    node's.
    """
    case_id = matrix.case_id(product.matrix, product.case_topology, str(inbound["id"]), client,
                             node=node)
    product.subscription_payloads(case_id)
    expectations = matrix_expectations(product, inbound, node)
    facts = product.transfer_facts(case_id, str(inbound["id"]), client, node=node)

    transport = f"{inbound['transport']}/{inbound['security']}"
    require(case_id, int(facts.get("outbounds") or 0) == 1,
            f"the served {client} representation declares {facts.get('outbounds')!r} {transport} "
            f"outbound(s) for {inbound['id']}, expected exactly one")
    require(case_id, facts.get("delivered"),
            f"the {inbound['id']} payload never reached the controlled endpoint: "
            f"{facts.get('reason', '')}")
    require(case_id, facts.get("status") == 200,
            f"the {inbound['id']} transfer returned {facts.get('status')!r} instead of 200")
    require(case_id, facts.get("request_id_match"),
            f"the endpoint did not echo the {inbound['id']} request id")
    require(case_id, facts.get("body_match"),
            f"the endpoint did not receive the exact {inbound['id']} payload")
    require(case_id, facts.get("server") == expectations["server"],
            f"the served {client} outbound dials {facts.get('server')!r} instead of "
            f"{expectations['server']!r}, so it is not the {inbound['id']} inbound of this node")
    require(case_id, facts.get("source_ip") == expectations["source_ip"],
            f"the {inbound['id']} payload left from {facts.get('source_ip')!r} instead of "
            f"{expectations['source_ip']!r}, so it did not traverse the product")
    require(case_id, facts.get("sni") == expectations["sni"],
            f"the served {client} outbound carries SNI {facts.get('sni')!r} instead of the "
            f"{expectations['sni']!r} the {inbound['id']} inbound was issued for")

    evidence = {
        "inbound": inbound["id"],
        "client": client,
        "transport": transport,
        "tag": facts.get("tag"),
        "server": facts.get("server"),
        "sni": facts.get("sni"),
        "status": facts.get("status"),
        "source_ip": facts.get("source_ip"),
        "outbounds": facts.get("outbounds"),
    }
    if node:
        evidence["node"] = node
    return evidence


def _data_plane_case(
    product: AioProduct, inbound: Dict[str, Any], client: str, node: str = "",
) -> Dict[str, Any]:
    """Run one matrix tuple and record its own verdict for the count case."""
    case_id = matrix.case_id(product.matrix, product.case_topology, str(inbound["id"]), client,
                             node=node)
    try:
        evidence = case_data_plane(product, inbound, client, node=node)
    except AssertionError:
        product.record_data_plane(case_id, "FAIL")
        raise
    product.record_data_plane(case_id, "PASS")
    return evidence


def case_matrix(product: AioProduct) -> Dict[str, Any]:
    """AIO-MATRIX: the positive data-plane cases are exactly the matrix tuples.

    The count is an acceptance invariant, not an estimate: the selected Vision
    configuration owes 8 tuples without the optional inbound and 10 with it, and
    every one of them is one inbound through one client. The three ways a count
    can drift are each a failure here — the matrix declaring a number its own
    inbound/client list does not produce, the suite declaring cases the matrix
    does not enumerate, and a declared case that produced no result or did not
    pass.
    """
    product.require_installed()
    data = product.matrix
    expected_ids = [
        matrix.case_id(data, "aio", str(inbound["id"]), client)
        for inbound, client in matrix.tuples(data, product.vision)
    ]
    declared = product.declared_data_plane
    executed = product.data_plane_results
    declared_count = matrix.positive_count(data, "aio", product.vision)

    require("AIO-MATRIX", declared_count == len(expected_ids),
            f"the matrix declares {declared_count} positive case(s) for the "
            f"{matrix.combination('aio', product.vision)} Vision configuration but enumerates "
            f"{len(expected_ids)} inbound/client tuple(s), so one of the two is unexplained")
    missing = [case_id for case_id in expected_ids if case_id not in declared]
    extra = [case_id for case_id in declared if case_id not in expected_ids]
    require("AIO-MATRIX", not missing and not extra,
            f"the suite declares {len(declared)} data-plane case(s) that are not the matrix's "
            f"{len(expected_ids)}: missing {missing}, unexplained {extra}")
    not_run = [case_id for case_id in expected_ids if case_id not in executed]
    require("AIO-MATRIX", not not_run,
            f"{len(not_run)} matrix case(s) produced no result: {', '.join(not_run)}")
    failed = sorted(case_id for case_id, status in executed.items() if status != "PASS")
    require("AIO-MATRIX", not failed,
            f"{len(failed)} matrix case(s) did not pass: {', '.join(failed)}")
    require("AIO-MATRIX", len(executed) == declared_count,
            f"{len(executed)} data-plane case(s) ran, but the matrix declares {declared_count} for "
            f"the {matrix.combination('aio', product.vision)} Vision configuration")

    return {
        "vision": matrix.combination("aio", product.vision),
        "inbounds": product.inbound_count,
        "clients": len(matrix.clients(data)),
        "expected_positive_cases": declared_count,
        "declared_cases": len(declared),
        "executed_cases": len(executed),
        "passed_cases": sum(1 for status in executed.values() if status == "PASS"),
    }


def case_json_shapes(product: AioProduct) -> Dict[str, Any]:
    """SUB-JSON-SHAPES: the served and the alternate `/v2ray-json` shape both load.

    Only one shape is served per request, so the other is formed from the Panel's
    own outbound — the outbound, not all of them: a config object is one host and
    the Panel tags every host outbound ``proxy``, so merging profiles into a
    single object would collide on the tag instead of testing a shape. The
    wrapper count is the assertion that matters: whatever the Panel serves is a
    complete config and is never wrapped, while the bare outbound object that is
    not a core config needs exactly one listener added.
    """
    product.subscription_payloads("SUB-JSON-SHAPES")
    facts = product.engine_facts("SUB-JSON-SHAPES", "json-shapes")

    served = facts.get("served_shape")
    require("SUB-JSON-SHAPES", served in ("list", "object"),
            f"the Panel served a {served!r} shape, which is neither documented shape")
    require("SUB-JSON-SHAPES", int(facts.get("served_entries") or 0) > 0,
            "the served Xray JSON carries no profile")
    require("SUB-JSON-SHAPES", facts.get("served_wrapped") == 0,
            f"a served {served} profile was wrapped {facts.get('served_wrapped')!r} time(s) before "
            "Xray accepted it; a served profile is a complete config and needs no wrapper")

    alternate = facts.get("alternate_shape")
    require("SUB-JSON-SHAPES", alternate == ("object" if served == "list" else "list"),
            f"the alternate shape is {alternate!r} instead of the one the served {served} shape omits")
    expected_alternate_wrapped = 1 if alternate == "object" else 0
    require("SUB-JSON-SHAPES", facts.get("alternate_wrapped") == expected_alternate_wrapped,
            f"the alternate {alternate} shape needed {facts.get('alternate_wrapped')!r} wrapper(s), "
            f"expected {expected_alternate_wrapped}")
    require("SUB-JSON-SHAPES", facts.get("alternate_outbounds") == 1,
            f"the alternate shape carries {facts.get('alternate_outbounds')!r} Panel outbounds; a "
            "config object is one host, and the Panel tags every host outbound 'proxy', so it "
            "carries exactly one")
    return {
        "served_shape": served,
        "served_entries": facts.get("served_entries"),
        "served_wrapped": facts.get("served_wrapped"),
        "alternate_shape": alternate,
        "alternate_outbounds": facts.get("alternate_outbounds"),
        "alternate_wrapped": facts.get("alternate_wrapped"),
    }


def cases(podman: Any, distribution: str = "ubuntu-24.04", vision: bool = False) -> List[Case]:
    """The AIO suite: the install case plus every case that reuses its host.

    The data-plane cases are generated from the protocol/client matrix, so the
    selected Vision configuration decides their number (8 without the optional
    inbound, 10 with it) and no case id is written by hand.
    """
    product = AioProduct(podman, distribution, vision=vision)
    data_plane = [
        (matrix.case_id(product.matrix, "aio", str(inbound["id"]), client), inbound, client)
        for inbound, client in matrix.tuples(product.matrix, vision)
    ]
    product.declare_data_plane([case_id for case_id, _inbound, _client in data_plane])
    suite = [
        Case(INSTALL_CASE_ID, "aio", lambda context: product.install(),
             timeout_seconds=INSTALL_TIMEOUT_SECONDS),
        Case("AIO-PACKAGES", "aio", lambda context: case_packages(product), timeout_seconds=300),
        Case("AIO-04", "aio", lambda context: case_services(product), timeout_seconds=300),
        Case("AIO-01", "aio", lambda context: case_panel_ready(product), timeout_seconds=300),
        Case("AIO-03", "aio", lambda context: case_credentials(product), timeout_seconds=300),
        Case("AIO-05", "aio", lambda context: case_tls_and_identity(product), timeout_seconds=300),
        Case("AIO-AUTH", "aio", lambda context: case_panel_auth(product), timeout_seconds=300),
        Case("AIO-CLIENT", "aio", lambda context: case_client_lifecycle(product), timeout_seconds=300),
        Case("SUB-SERVED", "aio", lambda context: case_subscriptions(product), timeout_seconds=600),
        Case("SUB-UA-ABSENT", "aio", lambda context: case_user_agent_absent(product), timeout_seconds=300),
        Case("SUB-UA-BLANK", "aio", lambda context: case_user_agent_blank(product), timeout_seconds=300),
        Case("SUB-B64", "aio", lambda context: case_share_links(product), timeout_seconds=300),
        Case("SUB-JSON-SHAPES", "aio", lambda context: case_json_shapes(product), timeout_seconds=300),
    ]
    for case_id, inbound, client in data_plane:
        suite.append(Case(
            case_id, "aio",
            lambda context, inbound=inbound, client=client: _data_plane_case(product, inbound, client),
            timeout_seconds=DATA_PLANE_TIMEOUT_SECONDS,
        ))
    suite.append(Case(
        "AIO-MATRIX", "aio", lambda context: case_matrix(product), timeout_seconds=120,
    ))
    suite.extend([
        Case("AIO-REVOKE", "aio", lambda context: case_revocation(product),
             timeout_seconds=TUNNEL_READY_TIMEOUT_SECONDS + 2 * TRAFFIC_TIMEOUT_SECONDS),
        Case("AIO-RESTART", "aio", lambda context: case_restart(product),
             timeout_seconds=RESTART_TIMEOUT_SECONDS + TUNNEL_READY_TIMEOUT_SECONDS
             + TRAFFIC_TIMEOUT_SECONDS),
        Case("AIO-IDEMPOTENT", "aio", lambda context: case_idempotent(product),
             timeout_seconds=INSTALL_TIMEOUT_SECONDS + TRAFFIC_TIMEOUT_SECONDS),
        Case("AIO-NEG-DEST", "aio", lambda context: case_negative_destination(product),
             timeout_seconds=TRAFFIC_TIMEOUT_SECONDS),
        Case("AIO-NEG-PORT", "aio", lambda context: case_foreign_listener(product), timeout_seconds=300),
        Case("AIO-NEG-ACME", "aio", lambda context: case_acme_fail_closed(product), timeout_seconds=300),
        Case("AIO-NEG-DEP", "aio", lambda context: case_public_dependency(product),
             timeout_seconds=RECOVERY_TIMEOUT_SECONDS + 300),
    ])
    return suite
