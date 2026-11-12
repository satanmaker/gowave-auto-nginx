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


class AioProduct:
    """One disposable AIO host, installed once by the real operator."""

    def __init__(self, podman: Any, distribution: str = "ubuntu-24.04") -> None:
        self.podman = podman
        self.context = podman.context
        self.distribution = distribution
        self.host: Optional[topology.AioTopology] = None
        self.outcome: Optional[topology.InstallOutcome] = None

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
    ]
