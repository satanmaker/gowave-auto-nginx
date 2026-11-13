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
import shlex
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional, Sequence, Set

from . import client_trust, matrix, panel_surface, topology
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
# payload through every served outbound of both engines, polled under this
# deadline: a case that then asserts the whole matrix has to wait for the whole
# matrix, or it reports propagation lag as a transport failure.
TUNNEL_READY_TIMEOUT_SECONDS = 300
TUNNEL_READY_INTERVAL_SECONDS = 5
# One warm-up attempt starts an engine per profile and sends one request through
# each; it must not inherit the deadline of the whole matrix.
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

NGX_CONFIG_CASE_ID = "NGX-05"
# A snippet the generated tree can never contain: NGINX reads /etc/nginx/conf.d
# on both roles, so an unknown directive there makes `nginx -t` fail while the
# configuration that is already loaded keeps serving.
NGX_CONFIG_SNIPPET = "/etc/nginx/conf.d/zz-gowave-e2e-broken.conf"
NGX_CONFIG_DIRECTIVE = "gowave_e2e_broken_probe"
# The managed Certbot deploy hook is the only unattended path that reloads
# NGINX, and its `nginx -t` gate is the same one the operator's strict reload
# uses before it touches the running master.
NGX_CONFIG_HOOK = "/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh"
# One phase pays for a full `nginx -T` dump and, on restore, for the master to
# replace its workers; the ceiling is a hang guard, not an expectation.
NGX_CONFIG_PROBE_TIMEOUT_SECONDS = 180
NGX_CONFIG_RELOAD_WAIT_SECONDS = 30
# The AIO suite runs the contract on one host; a cluster runs it on both roles.
NGX_CONFIG_TIMEOUT_SECONDS = 300

NGX_CONFIG_SCRIPT = r"""python3 - MODE_PLACEHOLDER PRIMARY_DOMAIN_PLACEHOLDER <<'PY'
import hashlib
import json
import os
import subprocess
import sys
import time

MODE = sys.argv[1]
PRIMARY_DOMAIN = sys.argv[2]
SNIPPET = "SNIPPET_PLACEHOLDER"
DIRECTIVE = "DIRECTIVE_PLACEHOLDER"
HOOK = "HOOK_PLACEHOLDER"
CONFIG_DIRS = ("/etc/nginx/conf.d", "/etc/nginx/stream-enabled", "/etc/nginx/sites-enabled")
RELOAD_WAIT_SECONDS = RELOAD_WAIT_PLACEHOLDER


def run(argv, timeout=90):
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as error:
        return {
            "returncode": 127,
            "stdout": "",
            "stderr": "%s: %s" % (type(error).__name__, error),
        }
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout or "",
        "stderr": completed.stderr or "",
    }


def tail(result, limit=1500):
    text = (result["stderr"] or result["stdout"] or "").strip()
    return text[-limit:]


def configuration_test():
    result = run(("nginx", "-t"))
    return {"returncode": result["returncode"], "tail": tail(result)}


def configuration_dump():
    result = run(("nginx", "-T"))
    text = result["stdout"] or ""
    return {
        "returncode": result["returncode"],
        "bytes": len(text.encode("utf-8")),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "server_name_lines": len([
            line for line in text.splitlines() if line.strip().startswith("server_name")
        ]),
        "ssl_preread": "ssl_preread on;" in text,
        "primary_server_name": PRIMARY_DOMAIN in text,
        "tail": tail(result, 600),
    }


def child_pids(pid):
    # Direct children of the master, read from procfs so no tool can be missing.
    try:
        with open("/proc/%s/task/%s/children" % (pid, pid), encoding="utf-8") as handle:
            return sorted(entry for entry in handle.read().split() if entry.isdigit())
    except OSError:
        return []


def service():
    active = run(("systemctl", "is-active", "nginx"))
    show = run(("systemctl", "show", "-p", "MainPID", "--value", "nginx"))
    main = (show["stdout"] or "").strip()
    workers = []
    if main.isdigit() and int(main) > 0:
        workers = child_pids(main)
        if not workers:
            children = run(("pgrep", "-P", main))
            workers = sorted(pid for pid in (children["stdout"] or "").split() if pid.isdigit())
    return {
        "active": (active["stdout"] or "").strip(),
        "main_pid": main,
        "worker_pids": workers,
        "listeners_443": len([
            line for line in (run(("ss", "-H", "-ltn", "sport = :443"))["stdout"] or "").splitlines()
            if line.strip()
        ]),
    }


def config_files():
    paths = []
    for directory in CONFIG_DIRS:
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            continue
        paths.extend(os.path.join(directory, name) for name in names if name.endswith(".conf"))
    return paths


def mutate():
    if MODE == "break":
        with open(SNIPPET, "w", encoding="utf-8") as handle:
            handle.write("%s on;\n" % DIRECTIVE)
            handle.flush()
            os.fsync(handle.fileno())
    elif MODE == "restore":
        try:
            os.unlink(SNIPPET)
        except FileNotFoundError:
            pass


def drive_hook():
    # Run the product's own reload guard and report what it did.
    present = os.path.isfile(HOOK)
    facts = {
        "present": present,
        "executable": os.access(HOOK, os.X_OK),
        "executed": MODE != "before",
        "returncode": None,
        "stdout": "",
        "stderr": "",
    }
    # The baseline phase only reports the guard: driving it there would reload the
    # master with the untouched tree, and every worker the reload creates would
    # then look like a worker the break phase gained.
    if not present or MODE == "before":
        return facts
    result = run((HOOK,), timeout=120)
    facts.update({
        "returncode": result["returncode"],
        "stdout": (result["stdout"] or "").strip()[-600:],
        "stderr": (result["stderr"] or "").strip()[-600:],
    })
    return facts


def wait_for_new_workers(before_pids):
    # Poll until the master replaced a worker, or the deadline expires.
    started = time.monotonic()
    deadline = started + RELOAD_WAIT_SECONDS
    state = service()
    while set(state["worker_pids"]) <= set(before_pids) and time.monotonic() < deadline:
        time.sleep(0.5)
        state = service()
    return state, round(time.monotonic() - started, 2)


snippet_before = os.path.isfile(SNIPPET)
mutate()
before_hook = service()
hook = drive_hook()
if MODE == "break":
    # A guard that refused to reload leaves the running master untouched; give a
    # wrong implementation a moment to show its new workers before reading them.
    time.sleep(2.0)
    after_hook = service()
    waited = 2.0
elif MODE == "restore":
    after_hook, waited = wait_for_new_workers(before_hook["worker_pids"])
else:
    after_hook = service()
    waited = 0.0

print(json.dumps({
    "mode": MODE,
    "primary_domain": PRIMARY_DOMAIN,
    "directive": DIRECTIVE,
    "snippet": {
        "path": SNIPPET,
        "present_before": snippet_before,
        "present": os.path.isfile(SNIPPET),
    },
    "config_files": config_files(),
    "test": configuration_test(),
    "dump": configuration_dump(),
    "hook": hook,
    "before_hook": before_hook,
    "after_hook": after_hook,
    "reload_waited_seconds": waited,
}, sort_keys=True))
PY
"""


def ngx_config_script(mode: str, primary_domain: str) -> str:
    """The NGINX configuration probe for one phase of the case on one role."""
    return (
        NGX_CONFIG_SCRIPT
        .replace("MODE_PLACEHOLDER", shlex.quote(mode))
        .replace("PRIMARY_DOMAIN_PLACEHOLDER", shlex.quote(primary_domain))
        .replace("SNIPPET_PLACEHOLDER", NGX_CONFIG_SNIPPET)
        .replace("DIRECTIVE_PLACEHOLDER", NGX_CONFIG_DIRECTIVE)
        .replace("HOOK_PLACEHOLDER", NGX_CONFIG_HOOK)
        .replace("RELOAD_WAIT_PLACEHOLDER", str(int(NGX_CONFIG_RELOAD_WAIT_SECONDS)))
    )


TLS_CASE_ID = "TLS-01"
# One role costs four independent handshakes from the client plus one host-side
# configuration read; the ceiling is a hang guard, not an expectation.
TLS_PROBE_TIMEOUT_SECONDS = 60
TLS_TIMEOUT_SECONDS = 300
# The versions the product documents for its HTTPS vhosts. A role that inherits
# a platform default instead would accept whatever the distribution shipped,
# which is exactly the difference an independent client cannot see on its own.
TLS_POLICY_PROTOCOLS = ("TLSv1.2", "TLSv1.3")
# A certificate with less headroom than this has no time left for the renewal
# that is supposed to replace it.
TLS_MINIMUM_REMAINING_SECONDS = 86400

TLS_POLICY_SCRIPT = r"""python3 - DOMAIN_PLACEHOLDER <<'PY'
import glob
import json
import re
import sys

DOMAIN = sys.argv[1]
CONFIG_GLOBS = ("/etc/nginx/conf.d/*.conf", "/etc/nginx/sites-enabled/*")


# Every top-level server block, by brace depth. A server_name token is not a
# block, so a candidate whose first semicolon comes before its opening brace is
# skipped instead of swallowing the rest of the file.
def server_blocks(text):
    blocks = []
    index = 0
    while True:
        start = text.find("server", index)
        if start == -1:
            return blocks
        brace = text.find("{", start + len("server"))
        semicolon = text.find(";", start + len("server"))
        if brace == -1:
            return blocks
        if semicolon != -1 and semicolon < brace:
            index = start + len("server")
            continue
        depth = 0
        end = None
        for position in range(brace, len(text)):
            char = text[position]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    end = position + 1
                    break
        if end is None:
            return blocks
        blocks.append(text[start:end])
        index = end


def directives(block, name):
    return [match.strip() for match in re.findall(r"^\s*" + name + r"\s+([^;]+);", block, re.M)]


def main():
    matched = []
    paths = sorted({path for pattern in CONFIG_GLOBS for path in glob.glob(pattern)})
    for path in paths:
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                text = handle.read()
        except OSError:
            continue
        for block in server_blocks(text):
            names = [token for line in directives(block, "server_name") for token in line.split()]
            listens = directives(block, "listen")
            if DOMAIN not in names:
                continue
            # The port 80 ACME vhost carries the same server name without
            # terminating TLS, so only an `ssl` listener describes the HTTPS face.
            if not any("ssl" in listen.split() for listen in listens):
                continue
            matched.append({
                "file": path,
                "server_names": names,
                "listen": listens,
                "ssl_protocols": directives(block, "ssl_protocols"),
                "ssl_certificate": directives(block, "ssl_certificate"),
            })
    print(json.dumps({"domain": DOMAIN, "blocks": matched}, sort_keys=True))


main()
PY
"""


def tls_policy_facts(
    podman: Any, container: str, case_id: str, domain: str,
    timeout: int = TLS_PROBE_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """Read the HTTPS vhost one role generated for its own name."""
    result = podman.exec_bash(
        container,
        TLS_POLICY_SCRIPT.replace("DOMAIN_PLACEHOLDER", shlex.quote(domain)),
        check=False,
        timeout=timeout,
    )
    return probe_json(case_id, f"the NGINX TLS policy probe on {container}", result)


def require_role_tls_policy(case_id: str, role: str, domain: str, facts: Dict[str, Any]) -> Dict[str, Any]:
    """The role serves its own lineage and pins its protocol list itself.

    Inheriting `ssl_protocols` from the platform is the defect this assertion
    exists for: the same product would then accept legacy protocols on one
    supported distribution and refuse them on another, and nothing in the served
    certificate would say so.
    """
    require(case_id, facts.get("domain") == domain,
            f"{role}: the policy probe answered for {facts.get('domain')!r} instead of {domain!r}")
    blocks = facts.get("blocks") or []
    require(case_id, len(blocks) == 1,
            f"{role}: {len(blocks)} HTTPS server blocks claim {domain!r} "
            f"({[block.get('file') for block in blocks]}), so the vhost that terminates TLS "
            "for this role cannot be read unambiguously")
    block = blocks[0]
    protocol_lines = block.get("ssl_protocols") or []
    require(case_id, protocol_lines,
            f"{role}: the HTTPS vhost in {block.get('file')} inherits its TLS protocol policy "
            "instead of pinning one, so the accepted versions follow the platform default")
    protocols = [token for line in protocol_lines for token in line.split()]
    require(case_id, set(protocols) == set(TLS_POLICY_PROTOCOLS),
            f"{role}: the HTTPS vhost in {block.get('file')} allows {protocols} instead of "
            f"{list(TLS_POLICY_PROTOCOLS)}")
    certificates = block.get("ssl_certificate") or []
    require(case_id, len(certificates) == 1,
            f"{role}: the HTTPS vhost in {block.get('file')} names {len(certificates)} certificates "
            f"({certificates}) instead of the one lineage issued for {domain!r}")
    lineage = f"{LETSENCRYPT_ROOT}/{domain}/"
    require(case_id, certificates[0].startswith(lineage),
            f"{role}: the HTTPS vhost serves {certificates[0]!r} instead of the lineage the "
            f"operator issued for this name ({lineage}...)")
    return {
        "file": block.get("file"),
        "listen": block.get("listen"),
        "ssl_protocols": protocols,
        "ssl_certificate": certificates[0],
    }


def _certificate_time(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def require_certificate_window(
    case_id: str, role: str, peer: Dict[str, Any], now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """The certificate the client validated is inside its own validity window."""
    not_before = _certificate_time(str(peer.get("not_before") or ""))
    not_after = _certificate_time(str(peer.get("not_after") or ""))
    require(case_id, not_before is not None and not_after is not None,
            f"{role}: the served certificate exposes no validity window "
            f"({peer.get('not_before')!r} .. {peer.get('not_after')!r})")
    require(case_id, not_before < not_after,
            f"{role}: the served certificate expires before it becomes valid "
            f"({not_before.isoformat()} .. {not_after.isoformat()})")
    moment = now or datetime.now(timezone.utc)
    require(case_id, not_before <= moment,
            f"{role}: the served certificate is not valid yet "
            f"({not_before.isoformat()} > {moment.isoformat()})")
    require(case_id, moment < not_after,
            f"{role}: the served certificate has expired "
            f"({not_after.isoformat()} <= {moment.isoformat()})")
    remaining = int((not_after - moment).total_seconds())
    require(case_id, remaining >= TLS_MINIMUM_REMAINING_SECONDS,
            f"{role}: the served certificate expires in {remaining}s, less than the "
            f"{TLS_MINIMUM_REMAINING_SECONDS}s a renewal path needs to replace it")
    return {
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "remaining_seconds": remaining,
    }


def require_client_certificate(
    case_id: str, role: str, domain: str, report: Dict[str, Any], expected_status: int,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """An independent client validates the name, the chain, and the handshake.

    The probe trusts only the run CA, so a successful call proves the served
    chain is the one the fixture directory issued; the SAN set is then compared
    exactly, because a certificate that also covers another name would let the
    client validate something this role was never issued.
    """
    probe = report.get("probe") or {}
    require(case_id, report.get("returncode") == 0,
            f"{role}: the independent client could not verify https://{domain}/ through the "
            f"fixture CA: {probe.get('error') or report.get('stderr')}")
    require(case_id, probe.get("status") == expected_status,
            f"{role}: https://{domain}/ answered {probe.get('status')!r} instead of "
            f"{expected_status}")
    peer = probe.get("peer") or {}
    san = sorted(str(name) for name in peer.get("san") or [])
    require(case_id, san == [domain],
            f"{role}: the certificate served for {domain} covers {san}, so the name an "
            "independent client validated is not the lineage this role was issued")
    version = str(peer.get("tls_version", ""))
    require(case_id, version.startswith("TLSv1.3"),
            f"{role}: the public handshake negotiated {version!r} instead of TLSv1.3")
    require(case_id, peer.get("issuer"),
            f"{role}: the served certificate reports no issuer, so its chain is not described "
            "by the handshake at all")
    window = require_certificate_window(case_id, role, peer, now=now)
    return {
        "status": probe.get("status"),
        "san": san,
        "tls_version": version,
        "cipher": peer.get("cipher"),
        "issuer": peer.get("issuer"),
        **window,
    }


def require_tls12_accepted(case_id: str, role: str, domain: str, report: Dict[str, Any]) -> Dict[str, Any]:
    """The version the generated vhost lists is really offered to a client."""
    probe = report.get("probe") or {}
    require(case_id, report.get("returncode") == 0,
            f"{role}: a client limited to TLS 1.2 could not complete the handshake on "
            f"https://{domain}/ although the generated vhost allows it: "
            f"{probe.get('error') or report.get('stderr')}")
    version = str((probe.get("peer") or {}).get("tls_version", ""))
    require(case_id, version.startswith("TLSv1.2"),
            f"{role}: a client limited to TLS 1.2 negotiated {version!r}")
    return {"tls_version": version}


def require_legacy_protocol_refused(case_id: str, role: str, domain: str, report: Dict[str, Any]) -> Dict[str, Any]:
    """A legacy protocol has to fail the handshake, not reach the vhost."""
    probe = report.get("probe") or {}
    version = str((probe.get("peer") or {}).get("tls_version", ""))
    require(case_id, report.get("returncode") != 0,
            f"{role}: https://{domain}/ completed a session pinned to TLS 1.1 "
            f"({version!r}), so the generated vhost accepts a protocol the product does "
            "not document")
    require(case_id, not version,
            f"{role}: the TLS 1.1 probe failed after negotiating {version!r}, so the refusal is "
            "not the protocol policy's")
    return {
        "refused": True,
        "error": str(probe.get("error") or report.get("stderr") or "").strip()[:300],
    }


def require_untrusted_chain_refused(case_id: str, role: str, domain: str, report: Dict[str, Any]) -> Dict[str, Any]:
    """Without the fixture anchor the same call has to fail as a chain error.

    This is what keeps the positive handshake honest: a certificate that also
    verified against the client's system store would pass either way, and the
    fixture CA would then be a global trust change nobody asked for.
    """
    probe = report.get("probe") or {}
    require(case_id, report.get("returncode") != 0,
            f"{role}: https://{domain}/ verified without the fixture CA, so either the served "
            "chain is not the fixture directory's or the fixture CA reached the client's system "
            "trust store")
    error = str(probe.get("error") or report.get("stderr") or "").strip()
    try:
        client_trust.verify_chain_failure(error)
    except client_trust.ClientTrustError as failure:
        require(case_id, False,
                f"{role}: the unanchored client failed without a certificate-chain error: {failure}")
    return {"refused": True, "error": error[:300]}


def tls_surface_contract(
    product: AioProduct, case_id: str, role: str, domain: str, expected_status: int,
    container: str = "",
) -> Dict[str, Any]:
    """Prove one role's HTTPS certificate and protocol policy from outside it.

    ``container`` names the host the vhost was generated on; it defaults to the
    install's own host. The client-side probes always run from the Control
    Machine role, which resolves the name through the fixture zone, so the
    handshake is what a real client would get rather than what the host believes
    about itself.
    """
    host = product.require_installed()
    target = container or host.target_name
    policy = require_role_tls_policy(
        case_id, role, domain, tls_policy_facts(product.podman, target, case_id, domain),
    )
    url = f"https://{domain}/"
    verified = require_client_certificate(
        case_id, role, domain,
        host.client_http(url, expect_status=expected_status, expect_san=[domain], timeout=30),
        expected_status,
    )
    tls12 = require_tls12_accepted(
        case_id, role, domain, host.client_http(url, timeout=30, max_tls="TLSv1.2"),
    )
    # No pin succeeds here for a documented reason: the vhost lists its versions.
    legacy = require_legacy_protocol_refused(
        case_id, role, domain, host.client_http(url, timeout=30, max_tls="TLSv1.1"),
    )
    untrusted = require_untrusted_chain_refused(
        case_id, role, domain, host.client_http(url, timeout=30, anchor=False),
    )
    return {
        "role": role,
        "domain": domain,
        "policy": policy,
        "verified": verified,
        "tls12_pinned": tls12,
        "legacy_refused": legacy,
        "untrusted_refused": untrusted,
    }


def probe_json(case_id: str, label: str, result: Any) -> Dict[str, Any]:
    """A probe that exited non-zero or printed no JSON fails the case."""
    detail = (result.stderr or result.stdout or "").strip()[-2000:]
    require(case_id, result.returncode == 0, f"{label} exited {result.returncode}: {detail}")
    try:
        return json.loads(result.stdout or "")
    except json.JSONDecodeError:
        require(case_id, False, f"{label} did not print JSON: {(result.stdout or '')[:400]}")
        return {}


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
        expect_refusal: bool = False,
    ) -> Dict[str, Any]:
        """Run exactly one matrix tuple: one client through one inbound.

        The matrix, not the case body, decides the transport and security layer,
        so a matrix edit that renames or re-transports an inbound changes what the
        case exercises instead of leaving the case asserting the old shape.

        ``node`` names the host the tuple belongs to. A cluster serves the same
        transport/security pairs on both nodes, so the probe is narrowed by the
        node's own dial name; otherwise it would run the first match and call it
        this one.

        ``expect_refusal`` keeps a refused connection in the result instead of
        failing the probe, which is how a case measures a node that was stopped.
        """
        host = self.require_installed()
        inbound = matrix.inbound(self.matrix, inbound_id)
        return self._probe_json(case_id, "the transfer probe", host.transfer_facts(
            client, str(inbound["transport"]), str(inbound["security"]),
            host=matrix_expectations(self, inbound, node)["server"],
            expect_refusal=expect_refusal,
        ))

    def prohibited_facts(self, case_id: str) -> Dict[str, Any]:
        """Run the policy probe: one permitted control, one destination the product denies."""
        host = self.require_installed()
        return self._probe_json(case_id, "the policy probe", host.prohibited_facts())

    def _probe_json(self, case_id: str, label: str, result: Any) -> Dict[str, Any]:
        """A probe that exited non-zero or printed no JSON fails the case."""
        return probe_json(case_id, label, result)

    def wait_tunnel_ready(self, case_id: str, payload_dir: Optional[str] = None) -> Dict[str, Any]:
        """Wait until every served outbound really carries a payload to the endpoint.

        A listener that is bound and a Panel that answers say nothing about the
        data plane: the Panel pushes users to the node and the node applies them
        asynchronously, so both a freshly issued client and a restarted node can
        have a tunnel that refuses the first transfer. A payload per outbound,
        confirmed by the endpoint's own log, is what tells the matrix that follows
        it is measuring the product rather than its propagation lag — one warm
        transport would let the deadline expire on a case that still asserts the
        rest.
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
                f"not every served outbound carried a payload to the endpoint within "
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


def case_tls_surface(product: AioProduct) -> Dict[str, Any]:
    """TLS-01: an independent client validates the certificate the host serves.

    AIO-05 reads the lineage on disk; this case asks the client, which is the
    only vantage point that can tell what the public handshake actually presents. The
    certificate has to cover exactly the name it is served for, sit inside its
    validity window, chain to the run CA, and negotiate TLS 1.3 — while a client
    pinned to TLS 1.1 is refused and the same call without the run CA fails as a
    chain error.
    """
    return tls_surface_contract(
        product, TLS_CASE_ID, "the All-in-One host", PANEL_DOMAIN, 200,
    )


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


def case_revocation(
    product: AioProduct, case_id: str = "AIO-REVOKE",
    expected_sources: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """AIO-REVOKE/MN-REVOKE: revoked access stops transferring, and the Panel says so.

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

    A cluster runs the same body: the client's subscription carries both nodes'
    inbounds, so the transfer count comes from what the Panel served rather than
    from the one install's own inbound list, and the egress addresses have to be
    exactly the nodes that subscription names — an egress set that lost a node
    would otherwise pass while the revocation was only proven on the other one.
    """
    host = product.require_installed()
    sources = list(expected_sources or [host.plan.data_target_ip])
    # The Panel probe runs on the target, where the payload volume is mounted at
    # PAYLOAD_MOUNT; the engines run in the client, where the same volume is
    # mounted read-only at SECRETS_MOUNT.
    payload_dir = f"{topology.SECRETS_MOUNT}/{panel_surface.REVOKE_DIRECTORY}"
    issue = panel_probe(
        product, case_id, "revoke", f"--step issue --payload-dir {topology.PAYLOAD_MOUNT}",
    ).get("revocation") or {}
    require(case_id, issue.get("squad_requested"),
            "no 'Default MVP Squad' exists, so the revocation client could not be granted an inbound")
    require(case_id, issue.get("create_status") == 201,
            f"POST /api/users returned {issue.get('create_status')!r} instead of 201")
    require(case_id, issue.get("patch_status") == 200,
            f"PATCH /api/users/{{id}} returned {issue.get('patch_status')!r} instead of 200")
    require(case_id, issue.get("patch_visible"),
            "the traffic limit written by PATCH /api/users/{id} is not visible on read back")
    representations = issue.get("representations") or {}
    unserved = sorted(name for name, facts in representations.items() if (facts or {}).get("status") != 200)
    require(case_id, not unserved, f"the created client was not served: {', '.join(unserved)}")
    require(case_id, bool(issue.get("credential_digest")),
            "the captured subscription carries no credential to compare against after revoking")

    try:
        tunnel = product.wait_tunnel_ready(case_id, payload_dir=payload_dir)
        positive = product.traffic_facts(case_id, "traffic", payload_dir=payload_dir)
        expected = product.subscription_inbound_count * len(TRAFFIC_ENGINES)
        require(case_id, int(positive.get("transfer_count") or 0) == expected,
                f"the issued client transferred through {positive.get('transfer_count')!r} "
                f"transports, expected {expected}")
        require(case_id, int(positive.get("missing_request_ids") or 0) == 0,
                f"the endpoint never saw {positive.get('missing_request_ids')!r} of the issued "
                "client's requests")
        unverified = [item["tag"] for item in positive.get("transfers") or []
                      if not (item.get("request_id_match") and item.get("body_match"))]
        require(case_id, not unverified,
                f"the endpoint did not echo the payload for: {', '.join(unverified)}")
        require(case_id, sorted(positive.get("source_ips") or []) == sorted(sources),
                f"the issued client's payload left from {positive.get('source_ips')!r} "
                f"instead of the node egress addresses {sorted(sources)}")

        applied = panel_probe(
            product, case_id, "revoke", f"--step apply --payload-dir {topology.PAYLOAD_MOUNT}",
        ).get("revocation") or {}
        require(case_id, applied.get("revoke_status") == 200,
                f"POST /api/users/{{id}}/actions/revoke returned {applied.get('revoke_status')!r}")
        require(case_id, applied.get("revoked_at_present"),
                "the revoke action reported no subRevokedAt, so the Panel recorded no revocation")
        require(case_id, applied.get("short_uuid_rotated"),
                "the revoke action did not rotate the subscription path")
        require(case_id, applied.get("old_subscription_status") == 404,
                f"the revoked subscription path still answers with "
                f"{applied.get('old_subscription_status')!r} instead of 404")
        require(case_id, applied.get("new_subscription_status") == 200,
                f"the rotated subscription path answers {applied.get('new_subscription_status')!r}")
        require(case_id, applied.get("credential_digest_changed"),
                "the subscription served after revoking carries the same credentials as before")

        negative = product.traffic_facts(case_id, "revoked", payload_dir=payload_dir)
        require(case_id, int(negative.get("delivered") or 0) == 0,
                f"{negative.get('delivered')!r} transports still delivered a payload with revoked access")
        require(case_id, int(negative.get("refused") or 0) == int(negative.get("attempt_count") or -1),
                f"{negative.get('refused')!r} of {negative.get('attempt_count')!r} attempts were refused")
        require(case_id, int(negative.get("attempt_count") or 0) == expected,
                f"the revoked access exercised {negative.get('attempt_count')!r} transports, "
                f"expected {expected}")
        require(case_id, int(negative.get("recorded_request_ids") or 0) == 0,
                "the endpoint recorded a request sent with revoked access")
    finally:
        cleanup = panel_probe(
            product, case_id, "revoke", f"--step cleanup --payload-dir {topology.PAYLOAD_MOUNT}",
        ).get("revocation") or {}
        require(case_id, cleanup.get("delete_status") == 204,
                f"deleting the revocation client returned {cleanup.get('delete_status')!r} "
                "instead of 204")
        require(case_id, cleanup.get("after_delete_status") == 404,
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
        "expected_source_ips": ",".join(sorted(sources)),
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
    look healthy; every served outbound has to carry a payload first, because a
    node that has its listener back applies its users asynchronously and a
    transport that is still warming up would otherwise be read as broken.
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


def nginx_config_facts(
    podman: Any, container: str, case_id: str, mode: str, primary_domain: str,
    timeout: int = NGX_CONFIG_PROBE_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """One phase of the configuration contract, measured on one role.

    ``mode`` is the phase name the probe reports back: ``before`` plants nothing,
    ``break`` writes an invalid snippet and drives the product's reload guard,
    and ``restore`` removes it and drives the same guard again.
    """
    result = podman.exec_bash(
        container, ngx_config_script(mode, primary_domain), check=False, timeout=timeout,
    )
    return probe_json(case_id, f"the NGINX {mode} probe on {container}", result)


def require_generated_nginx_config(case_id: str, role: str, facts: Dict[str, Any]) -> None:
    """The generated tree is valid, complete, and behind the guard the product ships.

    ``nginx -t`` alone would pass on an empty configuration, so the dump is read
    too: the tree has to carry the deployment's own server name and the stream
    SNI routing both roles are built around.
    """
    service = facts.get("before_hook") or {}
    require(case_id, facts.get("mode") == "before",
            f"{role}: the baseline probe answered for {facts.get('mode')!r}, not for the untouched tree")
    require(case_id, service.get("active") == "active",
            f"{role}: NGINX reports {service.get('active')!r} before the case touched its configuration")
    test = facts.get("test") or {}
    require(case_id, test.get("returncode") == 0,
            f"{role}: the generated NGINX configuration does not pass `nginx -t`:\n{test.get('tail', '')}")
    dump = facts.get("dump") or {}
    require(case_id, dump.get("returncode") == 0 and int(dump.get("bytes") or 0) > 0,
            f"{role}: `nginx -T` produced no configuration dump: {dump.get('tail', '')}")
    require(case_id, dump.get("ssl_preread"),
            f"{role}: the generated configuration carries no ssl_preread SNI routing")
    require(case_id, dump.get("primary_server_name"),
            f"{role}: the generated configuration carries no server_name for "
            f"{facts.get('primary_domain')!r}")
    require(case_id, facts.get("config_files"),
            f"{role}: the product generated no NGINX configuration file")
    require(case_id, not (facts.get("snippet") or {}).get("present_before"),
            f"{role}: {NGX_CONFIG_SNIPPET} existed before the case planted it")
    hook = facts.get("hook") or {}
    require(case_id, hook.get("present"),
            f"{role}: the managed ACME deploy hook {NGX_CONFIG_HOOK} is missing, so a renewal "
            "would never reload NGINX")
    require(case_id, hook.get("executable"),
            f"{role}: the managed ACME deploy hook {NGX_CONFIG_HOOK} is not executable")
    require(case_id, str(service.get("main_pid") or "").isdigit(),
            f"{role}: NGINX reported no master PID ({service.get('main_pid')!r})")
    require(case_id, service.get("worker_pids"),
            f"{role}: NGINX reported no worker process, so a reload could not be observed")
    require(case_id, int(service.get("listeners_443") or 0) >= 1,
            f"{role}: nothing listens on 443 while the generated configuration is loaded")


def require_refused_reload(
    case_id: str, role: str, before: Dict[str, Any], broken: Dict[str, Any],
) -> None:
    """An invalid configuration must fail `nginx -t` and must not reach the master.

    The three facts are one conclusion: the guard saw the broken tree, refused,
    and left the running master, its workers and its listener exactly as they
    were. Requiring the whole trio is what tells "the reload was suppressed" from
    "the hook crashed before it could matter".

    The worker baseline is the break phase's own reading, taken after the snippet
    was planted and before the guard ran: comparing against the earlier baseline
    phase would count any reload that happened between the two probes as a reload
    the guard caused, which is what the phase itself is here to measure.
    """
    require(case_id, broken.get("mode") == "break",
            f"{role}: the failing probe answered for {broken.get('mode')!r}")
    require(case_id, (broken.get("snippet") or {}).get("present"),
            f"{role}: the invalid snippet {NGX_CONFIG_SNIPPET} was not written")
    test = broken.get("test") or {}
    require(case_id, test.get("returncode") != 0,
            f"{role}: the invalid snippet in {NGX_CONFIG_SNIPPET} left `nginx -t` succeeding, so the "
            "tree NGINX validates is not the tree the product generates")
    tail = test.get("tail") or ""
    require(case_id, NGX_CONFIG_DIRECTIVE in tail and "zz-gowave-e2e-broken.conf" in tail,
            f"{role}: `nginx -t` failed without naming the planted snippet:\n{tail}")
    hook = broken.get("hook") or {}
    require(case_id, hook.get("returncode") == 0,
            f"{role}: the managed deploy hook exited {hook.get('returncode')!r} on an invalid "
            f"configuration instead of leaving NGINX alone: {hook.get('stderr') or hook.get('stdout')}")
    baseline = before.get("before_hook") or {}
    same_phase = broken.get("before_hook") or {}
    after = broken.get("after_hook") or {}
    require(case_id, same_phase.get("worker_pids"),
            f"{role}: the break probe read no worker before driving the guard "
            f"({same_phase.get('worker_pids')!r}), so no reload could be observed")
    require(case_id, after.get("active") == "active",
            f"{role}: NGINX stopped after the deploy hook ran against an invalid configuration")
    require(case_id, after.get("main_pid") == baseline.get("main_pid"),
            f"{role}: the deploy hook replaced the NGINX master on an invalid configuration "
            f"({baseline.get('main_pid')} -> {after.get('main_pid')})")
    appeared = sorted(set(after.get("worker_pids") or []) - set(same_phase.get("worker_pids") or []))
    require(case_id, not appeared,
            f"{role}: the deploy hook reloaded NGINX with an invalid configuration "
            f"({same_phase.get('worker_pids')} -> {after.get('worker_pids')})")
    require(case_id, int(after.get("listeners_443") or 0) >= 1,
            f"{role}: the 443 listener disappeared while the loaded configuration was untouched")


def require_reload_after_restore(
    case_id: str, role: str, before: Dict[str, Any], restored: Dict[str, Any],
) -> None:
    """A valid tree must be reloaded — and reloaded, not restarted."""
    require(case_id, restored.get("mode") == "restore",
            f"{role}: the restoring probe produced no report ({restored.get('error') or restored})")
    require(case_id, not (restored.get("snippet") or {}).get("present"),
            f"{role}: the invalid snippet {NGX_CONFIG_SNIPPET} survived the restore")
    test = restored.get("test") or {}
    require(case_id, test.get("returncode") == 0,
            f"{role}: the restored configuration still fails `nginx -t`:\n{test.get('tail', '')}")
    hook = restored.get("hook") or {}
    require(case_id, hook.get("returncode") == 0,
            f"{role}: the managed deploy hook exited {hook.get('returncode')!r} on a valid "
            f"configuration: {hook.get('stderr') or hook.get('stdout')}")
    baseline = before.get("before_hook") or {}
    after = restored.get("after_hook") or {}
    appeared = sorted(set(after.get("worker_pids") or []) - set(baseline.get("worker_pids") or []))
    require(case_id, appeared,
            f"{role}: the deploy hook did not reload NGINX once the configuration was valid again "
            f"(workers stayed {baseline.get('worker_pids')} after "
            f"{restored.get('reload_waited_seconds')}s)")
    require(case_id, after.get("main_pid") == baseline.get("main_pid"),
            f"{role}: the configuration change replaced the NGINX master instead of reloading it "
            f"({baseline.get('main_pid')} -> {after.get('main_pid')})")
    require(case_id, after.get("active") == "active",
            f"{role}: NGINX is {after.get('active')!r} after the reload")
    require(case_id, int(after.get("listeners_443") or 0) >= 1,
            f"{role}: nothing listens on 443 after the reload")


def _restore_nginx_configuration(
    podman: Any, container: str, primary_domain: str,
) -> Dict[str, Any]:
    """Remove the planted snippet and drive a real reload, never masking a finding.

    This runs from a ``finally`` block, so it reports its own failure instead of
    raising: the case's primary assertion is what the operator needs to read.
    """
    try:
        result = podman.exec_bash(
            container, ngx_config_script("restore", primary_domain), check=False,
            timeout=NGX_CONFIG_PROBE_TIMEOUT_SECONDS,
        )
    except Exception as error:  # noqa: BLE001 - cleanup must not hide the primary finding
        return {"error": f"{type(error).__name__}: {error}"}
    detail = (result.stderr or result.stdout or "").strip()[-600:]
    if result.returncode != 0:
        return {"error": f"the restore probe exited {result.returncode}: {detail}"}
    try:
        return json.loads(result.stdout or "")
    except json.JSONDecodeError:
        return {"error": f"the restore probe did not print JSON: {(result.stdout or '')[:300]}"}


def nginx_config_reload_contract(
    podman: Any, container: str, case_id: str, role: str, primary_domain: str,
) -> Dict[str, Any]:
    """Prove the generated configuration is valid and a broken one is never loaded.

    The snippet is planted and removed either way, so the host is left with the
    configuration the product generated even when an assertion fails.
    """
    before = nginx_config_facts(podman, container, case_id, "before", primary_domain)
    require_generated_nginx_config(case_id, role, before)
    broken: Dict[str, Any] = {}
    try:
        broken = nginx_config_facts(podman, container, case_id, "break", primary_domain)
        require_refused_reload(case_id, role, before, broken)
    finally:
        restored = _restore_nginx_configuration(podman, container, primary_domain)
    require_reload_after_restore(case_id, role, before, restored)
    return {
        "role": role,
        "primary_domain": primary_domain,
        "generated_config_files": len(before.get("config_files") or []),
        "generated_config_dump_bytes": (before.get("dump") or {}).get("bytes"),
        "generated_config_sha256": (before.get("dump") or {}).get("sha256"),
        "generated_config_server_names": (before.get("dump") or {}).get("server_name_lines"),
        "invalid_configuration": {
            "nginx_test_returncode": (broken.get("test") or {}).get("returncode"),
            "nginx_test_tail": (broken.get("test") or {}).get("tail"),
            "hook_returncode": (broken.get("hook") or {}).get("returncode"),
            "hook_stdout": (broken.get("hook") or {}).get("stdout"),
            "hook_stderr": (broken.get("hook") or {}).get("stderr"),
            "master_pid": (broken.get("after_hook") or {}).get("main_pid"),
            "worker_pids_before_hook": (broken.get("before_hook") or {}).get("worker_pids"),
            "worker_pids": (broken.get("after_hook") or {}).get("worker_pids"),
            "listener_443": (broken.get("after_hook") or {}).get("listeners_443"),
        },
        "restored_configuration": {
            "nginx_test_returncode": (restored.get("test") or {}).get("returncode"),
            "hook_returncode": (restored.get("hook") or {}).get("returncode"),
            "master_pid": (restored.get("after_hook") or {}).get("main_pid"),
            "worker_pids_before": (before.get("before_hook") or {}).get("worker_pids"),
            "worker_pids_after": (restored.get("after_hook") or {}).get("worker_pids"),
            "reload_waited_seconds": restored.get("reload_waited_seconds"),
        },
    }


def case_nginx_config(product: AioProduct) -> Dict[str, Any]:
    """NGX-05: the generated configuration validates and a broken one never reloads.

    The product generates the NGINX tree and then relies on one guard everywhere
    it touches the running master: `nginx -t` first, reload only if it passes.
    The case drives that guard through the file the product itself installs —
    the Certbot deploy hook that fires on every renewal — because an unattended
    renewal is exactly when an invalid tree would otherwise reach NGINX.

    Nothing is reimplemented: the snippet is a file the generated tree cannot
    contain, and the guard is the product's own script. What the case asserts is
    the pair of behaviours that file has to have — refuse a broken tree, reload a
    valid one — and that the refusal left the running master serving.
    """
    host = product.require_installed()
    return nginx_config_reload_contract(
        product.podman, host.target_name, NGX_CONFIG_CASE_ID, "the All-in-One host", PANEL_DOMAIN,
    )


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
        # The public certificate is read before the tree is reloaded, so a later
        # case's reload cannot be mistaken for a defect in what this one measured.
        Case(TLS_CASE_ID, "aio", lambda context: case_tls_surface(product),
             timeout_seconds=TLS_TIMEOUT_SECONDS),
        # The configuration case only observes and reloads: it runs before any
        # traffic so a reload it caused can never be read as a data-plane fault.
        Case(NGX_CONFIG_CASE_ID, "aio", lambda context: case_nginx_config(product),
             timeout_seconds=NGX_CONFIG_TIMEOUT_SECONDS),
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
