"""All-in-One product acceptance cases.

Every case here runs against one real operator install in one disposable host.
The install is performed once, by the install case, and later cases reuse that
host: a second install would prove something the product never promises, and
re-provisioning per case would hide whether repeated installs are safe.

Two vantage points are kept apart on purpose. Host-side facts (units, sockets,
packages, certificate files, the loopback API) are read from the host under
test; anything a client can observe (HTTPS on 443, certificate chains, served
subscriptions) is read from a separate Control Machine container that has no
product code on it.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Sequence

from . import topology
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

# The MVP profile carries four inbounds without a Vision domain; the fifth
# appears only when the optional Vision domain is configured, which this
# topology does not configure.
CORE_INBOUNDS = 4

# What each YAML representation is expected to carry, per the shipped generators.
# GenerateMihomo skips only kcp, so Mihomo receives one proxy per inbound.
# GenerateClash skips vless, xhttp, kcp and hysteria outright, and the core set
# has exactly one trojan entry, so Clash receives that single proxy — a strict
# subset of the Mihomo inventory, not a second copy of it.
MIHOMO_PROXIES = CORE_INBOUNDS
CLASH_PROXIES = 1
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


class AioProduct:
    """One disposable AIO host, installed once by the real operator."""

    def __init__(self, podman: Any, distribution: str = "ubuntu-24.04") -> None:
        self.podman = podman
        self.context = podman.context
        self.distribution = distribution
        self.host: Optional[topology.AioTopology] = None
        self.outcome: Optional[topology.InstallOutcome] = None
        self._subscriptions: Optional[Dict[str, Any]] = None
        self._subscription_error = ""

    # ------------------------------------------------------------------ install
    def install(self) -> Dict[str, Any]:
        """Create the disposable host and run the operator install exactly once."""
        if self.host is not None:
            raise AssertionError(
                f"{INSTALL_CASE_ID}: the AIO host is installed once per run and reused by later cases"
            )
        host = topology.AioTopology(self.podman, distribution=self.distribution)
        host.create()
        self.host = host
        self.outcome = host.install()
        require(
            INSTALL_CASE_ID,
            self.outcome.ok,
            f"the operator full install failed with exit {self.outcome.returncode}:\n"
            f"{self.outcome.tail(6000)}",
        )
        return host.evidence(self.outcome)

    def require_installed(self) -> topology.AioTopology:
        """The successfully installed host, for cases that must not provision anything themselves."""
        if self.host is None or self.outcome is None:
            raise CaseBlocked(
                f"{INSTALL_CASE_ID}: this case needs the AIO install, and no install has run in this suite"
            )
        if not self.outcome.ok:
            # A half-installed host answers some probes and not others; running
            # them anyway would report the install failure six times over.
            raise CaseBlocked(
                f"{INSTALL_CASE_ID}: the install failed with exit {self.outcome.returncode}, "
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
        result = host.subscription_facts(scope)
        detail = (result.stderr or result.stdout or "").strip()[-2000:]
        require(
            case_id,
            result.returncode == 0,
            f"the client probe exited {result.returncode}: {detail}",
        )
        try:
            return json.loads(result.stdout or "")
        except json.JSONDecodeError:
            require(case_id, False, f"the client probe did not print JSON: {(result.stdout or '')[:400]}")
            return {}


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
    result = product.host_script(f"python3 {PANEL_SURFACE_SCRIPT} --scope {scope}")
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
    require("AIO-AUTH", nodes.get("inbound_count") == CORE_INBOUNDS,
            f"the local node exposes {nodes.get('inbound_count')!r} active inbounds, "
            f"expected {CORE_INBOUNDS}")
    require("AIO-AUTH", bool(nodes.get("inbound_digest")),
            "the local node reported no active inbound identifiers")

    profiles = surface.get("profiles") or {}
    require("AIO-AUTH", profiles.get("status") == 200,
            f"/api/config-profiles returned {profiles.get('status')!r}")
    require("AIO-AUTH", profiles.get("count") == 1,
            f"the Panel reports {profiles.get('count')!r} config profiles instead of one")
    require("AIO-AUTH", profiles.get("inbound_count") == CORE_INBOUNDS,
            f"the config profile declares {profiles.get('inbound_count')!r} inbounds, "
            f"expected {CORE_INBOUNDS}")
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
    require("AIO-AUTH", hosts.get("count") == CORE_INBOUNDS,
            f"the Panel publishes {hosts.get('count')!r} hosts, expected one per inbound "
            f"({CORE_INBOUNDS})")
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
    require("SUB-SERVED", base64.get("link_count") == CORE_INBOUNDS,
            f"the base64 list carries {base64.get('link_count')!r} links, expected one per inbound "
            f"({CORE_INBOUNDS})")

    xray_json = loaded.get("xray_json") or {}
    shape = xray_json.get("shape")
    require("SUB-SERVED", shape in ("list", "object"),
            f"the Xray JSON is neither a config object nor a profile list (shape {shape!r})")
    expected_entries = CORE_INBOUNDS if shape == "list" else 1
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

    for name, proxies, expected_types, reason in (
        ("mihomo", MIHOMO_PROXIES, MIHOMO_PROXY_TYPES, "one per inbound"),
        ("clash", CLASH_PROXIES, CLASH_PROXY_TYPES, "the trojan subset GenerateClash keeps"),
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

    require("SUB-B64", facts.get("link_count") == CORE_INBOUNDS,
            f"the base64 list carries {facts.get('link_count')!r} links, expected one per inbound "
            f"({CORE_INBOUNDS})")
    require("SUB-B64", facts.get("protocols") == {"vless": 3, "trojan": 1},
            f"the link list carries protocols {facts.get('protocols')!r} instead of the core "
            "three vless and one trojan entries")
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
    allowed_hosts = {host.panel_domain, host.reality_domain}
    if host.vision_domain:
        allowed_hosts.add(host.vision_domain)
    unknown_hosts = sorted(set(facts.get("hosts") or []) - allowed_hosts)
    require("SUB-B64", not unknown_hosts,
            f"the links point at hosts this run never configured: {', '.join(unknown_hosts)}")
    unknown_snis = sorted(set(facts.get("snis") or []) - allowed_hosts)
    require("SUB-B64", not unknown_snis,
            f"the links name SNIs this run never configured: {', '.join(unknown_snis)}")

    require("SUB-B64", facts.get("xray_outbounds") == CORE_INBOUNDS,
            f"Xray imported {facts.get('xray_outbounds')!r} outbounds from the link list")
    require("SUB-B64", facts.get("cross_representation_issued") == CORE_INBOUNDS,
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


def cases(podman: Any, distribution: str = "ubuntu-24.04") -> List[Case]:
    """The AIO suite: the install case plus every case that reuses its host."""
    product = AioProduct(podman, distribution)
    return [
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
