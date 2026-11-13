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
import uuid
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional, Sequence, Set

from . import acme_fixture, client_trust, matrix, panel_surface, topology
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


ACME_CASE_ID = "ACME-01"
# The directory the product hands Certbot on every role it provisions; the port
# 80 vhost serves exactly this path, so a token written here is what an HTTP-01
# validator has to fetch over the network.
ACME_WEBROOT = "/var/www/gowave-acme"
ACME_RENEWAL_DIR = "/etc/letsencrypt/renewal"
ACME_ARCHIVE_DIR = "/etc/letsencrypt/archive"
ACME_LINEAGE_DIR = "/etc/letsencrypt/live"
# Certbot appends every invocation to one log per directory, so each renewal gets
# a directory of its own beneath this one: the challenge type it chose and the
# certificate it received are then that invocation's own words instead of a line
# the install or an earlier phase left behind.
ACME_RENEWAL_LOG_DIR = "/tmp/gowave-e2e-acme-logs"
# One phase costs a full Certbot renewal against the local directory plus the
# master replacing its workers; the ceilings are hang guards, not expectations.
ACME_PROBE_TIMEOUT_SECONDS = 180
ACME_RENEWAL_TIMEOUT_SECONDS = 300
ACME_RENEWAL_WAIT_SECONDS = 30
ACME_ROUTE_TIMEOUT_SECONDS = 30
ACME_TIMEOUT_SECONDS = 600
# A lineage older than this predates the run that claims to have obtained it,
# which is what a pre-seeded certificate looks like from the outside. The window
# is wide because a slow install still has to fit inside it.
ACME_ISSUANCE_WINDOW_SECONDS = 7200

ACME_OUTAGE_CASE_ID = "ACME-02"
# Four Certbot runs plus three reloads and the client calls around them; the
# unreachable-directory attempt alone spends its own retry budget before it fails.
ACME_OUTAGE_TIMEOUT_SECONDS = 1200
# A failed attempt is waited for with no reload budget: the renewal must leave the
# running master alone, so waiting for new workers would only slow the failure down.
ACME_OUTAGE_RELOAD_WAIT_SECONDS = 0
# The line that puts the pinned directory behind a loopback address on the target,
# and the marker that removes it again without touching the host's own entries.
ACME_BLACKHOLE_MARKER = "gowave-e2e-acme-blackhole"
# The file the target's own resolver reads for the pinned directory's name.
ACME_HOSTS_FILE = "/etc/hosts"

ACME_RENEWAL_SCRIPT = r"""python3 - MODE_PLACEHOLDER DOMAIN_PLACEHOLDER CA_PLACEHOLDER <<'PY'
import calendar
import json
import os
import subprocess
import sys
import time

MODE = sys.argv[1]
DOMAIN = sys.argv[2]
CA_FILE = sys.argv[3]
WEBROOT = "WEBROOT_PLACEHOLDER"
LOG_ROOT = "LOG_DIR_PLACEHOLDER"
# Certbot appends to one log per directory, so each invocation gets its own: the
# challenge type and the certificate it received are then this run's own words
# instead of a line an earlier phase left behind.
LOG_DIR = os.path.join(LOG_ROOT, "%s-%d" % (MODE, time.time_ns()))
RENEWAL_DIR = "RENEWAL_DIR_PLACEHOLDER"
ARCHIVE_DIR = "ARCHIVE_DIR_PLACEHOLDER"
LINEAGE_DIR = "LINEAGE_DIR_PLACEHOLDER"
RELOAD_WAIT_SECONDS = RELOAD_WAIT_PLACEHOLDER
RENEWAL_TIMEOUT_SECONDS = RENEWAL_TIMEOUT_PLACEHOLDER


def run(argv, timeout=90, env=None):
    try:
        completed = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, env=env,
        )
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


def stamp(value):
    # OpenSSL and the TLS client print the same UTC second; an epoch is what lets
    # a certificate file on the host be compared with a certificate a client
    # received over the wire as the one certificate they are.
    try:
        return calendar.timegm(time.strptime(value, "%b %d %H:%M:%S %Y %Z"))
    except (TypeError, ValueError):
        return None


def certificate(path):
    if not os.path.isfile(path):
        return {"path": path, "present": False}
    result = run((
        "openssl", "x509", "-in", path, "-noout", "-serial", "-subject",
        "-issuer", "-dates", "-ext", "subjectAltName",
    ))
    facts = {"path": path, "present": True, "returncode": result["returncode"]}
    if result["returncode"] != 0:
        facts["error"] = tail(result)
        return facts
    san = []
    collecting = False
    for raw in (result["stdout"] or "").splitlines():
        stripped = raw.strip()
        if stripped.startswith("X509v3 Subject Alternative Name"):
            collecting = True
            continue
        if collecting:
            if not stripped:
                collecting = False
                continue
            for token in stripped.split(","):
                token = token.strip()
                if token.startswith("DNS:"):
                    san.append(token[len("DNS:"):])
                elif token.startswith("IP Address:"):
                    san.append(token[len("IP Address:"):].strip())
            continue
        key, separator, value = stripped.partition("=")
        if not separator:
            continue
        key = key.replace(" ", "").lower()
        value = value.strip()
        if key == "serial":
            facts["serial"] = value
        elif key == "subject":
            facts["subject"] = value
        elif key == "issuer":
            facts["issuer"] = value
        elif key == "notbefore":
            facts["not_before"] = value
            facts["not_before_epoch"] = stamp(value)
        elif key == "notafter":
            facts["not_after"] = value
            facts["not_after_epoch"] = stamp(value)
    if san:
        facts["san"] = san
    return facts


def certbot_list(value):
    # Certbot keeps the webroot as a list and serialises it comma-separated, so a
    # lineage with one webroot reads '/var/www/gowave-acme,' — the same path the
    # install passed with -w, plus the separator configobj appends.
    return [item.strip() for item in value.split(",") if item.strip()]


def lineage():
    path = os.path.join(RENEWAL_DIR, DOMAIN + ".conf")
    facts = {"path": path, "present": os.path.isfile(path), "values": {}}
    if not facts["present"]:
        return facts
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError as error:
        facts["error"] = "%s: %s" % (type(error).__name__, error)
        return facts
    for line in lines:
        key, separator, value = line.partition("=")
        if not separator:
            continue
        key = key.strip()
        facts["values"][key] = value.strip()
        if key == "webroot_path":
            facts["values"]["webroot_paths"] = certbot_list(value)
    return facts


def sequence(name):
    digits = "".join(character for character in name if character.isdigit())
    return int(digits or 0)


def archive():
    directory = os.path.join(ARCHIVE_DIR, DOMAIN)
    try:
        names = sorted(
            (name for name in os.listdir(directory)
             if name.startswith("cert") and name.endswith(".pem")),
            key=sequence,
        )
    except OSError:
        return []
    return [certificate(os.path.join(directory, name)) for name in names]


def live():
    return certificate(os.path.join(LINEAGE_DIR, DOMAIN, "fullchain.pem"))


def child_pids(pid):
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


def configuration_test():
    result = run(("nginx", "-t"))
    return {"returncode": result["returncode"], "tail": tail(result, 600)}


def wait_for_new_workers(before_pids):
    # Poll until the master replaced a worker, or the deadline expires.
    started = time.monotonic()
    deadline = started + RELOAD_WAIT_SECONDS
    state = service()
    while set(state["worker_pids"]) <= set(before_pids) and time.monotonic() < deadline:
        time.sleep(0.5)
        state = service()
    return state, round(time.monotonic() - started, 2)


def renewal_log():
    try:
        with open(os.path.join(LOG_DIR, "letsencrypt.log"), encoding="utf-8",
                  errors="replace") as handle:
            return handle.read()[-20000:]
    except OSError:
        return ""


report = {
    "mode": MODE,
    "domain": DOMAIN,
    "webroot": WEBROOT,
    "challenge_dir": os.path.join(WEBROOT, ".well-known", "acme-challenge"),
    "lineage": lineage(),
    "live": live(),
    "archive": archive(),
    "service": service(),
    "test": configuration_test(),
}
if MODE == "renew":
    environment = dict(os.environ)
    if CA_FILE:
        # The same scoped anchor run_certbot uses in test mode: the fixture CA
        # signs the ACME endpoint and nothing installs it system-wide, so the
        # renewal has to be handed the anchor the install was handed.
        environment["REQUESTS_CA_BUNDLE"] = CA_FILE
        environment["SSL_CERT_FILE"] = CA_FILE
    started = time.monotonic()
    renewal = run(
        ("certbot", "renew", "--cert-name", DOMAIN, "--force-renewal",
         "--non-interactive", "--no-random-sleep-on-renew", "--logs-dir", LOG_DIR),
        timeout=RENEWAL_TIMEOUT_SECONDS, env=environment,
    )
    elapsed = round(time.monotonic() - started, 2)
    after_hook, waited = wait_for_new_workers(report["service"]["worker_pids"])
    report.update({
        "renewal": {
            "returncode": renewal["returncode"],
            "stdout": (renewal["stdout"] or "").strip()[-3000:],
            "stderr": (renewal["stderr"] or "").strip()[-3000:],
            "tail": tail(renewal, 3000),
            "duration_seconds": elapsed,
        },
        "certbot_log": renewal_log(),
        "live_after": live(),
        "archive_after": archive(),
        "service_after": after_hook,
        "test_after": configuration_test(),
        "reload_waited_seconds": waited,
    })
print(json.dumps(report, sort_keys=True))
PY
"""


def acme_renewal_script(
    mode: str, domain: str, ca_file: str, reload_wait: int = ACME_RENEWAL_WAIT_SECONDS,
) -> str:
    """The ACME probe for one phase: read the lineage, or renew and read it again."""
    return (
        ACME_RENEWAL_SCRIPT
        .replace("MODE_PLACEHOLDER", shlex.quote(mode))
        .replace("DOMAIN_PLACEHOLDER", shlex.quote(domain))
        .replace("CA_PLACEHOLDER", shlex.quote(ca_file))
        .replace("WEBROOT_PLACEHOLDER", ACME_WEBROOT)
        .replace("LOG_DIR_PLACEHOLDER", ACME_RENEWAL_LOG_DIR)
        .replace("RENEWAL_DIR_PLACEHOLDER", ACME_RENEWAL_DIR)
        .replace("ARCHIVE_DIR_PLACEHOLDER", ACME_ARCHIVE_DIR)
        .replace("LINEAGE_DIR_PLACEHOLDER", ACME_LINEAGE_DIR)
        .replace("RELOAD_WAIT_PLACEHOLDER", str(int(reload_wait)))
        .replace("RENEWAL_TIMEOUT_PLACEHOLDER", str(int(ACME_RENEWAL_TIMEOUT_SECONDS)))
    )


ACME_OUTAGE_SCRIPT = r"""python3 - MODE_PLACEHOLDER WEBROOT_PLACEHOLDER ORIGINAL_MODE_PLACEHOLDER HOST_PLACEHOLDER MARKER_PLACEHOLDER HOSTS_PLACEHOLDER <<'PY'
import json
import os
import subprocess
import sys

MODE, WEBROOT, ORIGINAL_MODE, HOST, MARKER, HOSTS = sys.argv[1:7]


def run(argv, timeout=60):
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as error:
        return {"returncode": 127, "stdout": "", "stderr": "%s: %s" % (type(error).__name__, error)}
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout or "",
        "stderr": completed.stderr or "",
    }


def webroot_mode():
    try:
        return oct(os.stat(WEBROOT).st_mode & 0o777)[2:].rjust(4, "0")
    except OSError:
        return ""


def resolution():
    return (run(("getent", "hosts", HOST))["stdout"] or "").strip()


def hosts_lines():
    try:
        with open(HOSTS, encoding="utf-8") as handle:
            return handle.read().splitlines()
    except OSError:
        return []


def write_hosts(lines):
    # /etc/hosts is a bind mount inside the container, so it is rewritten in
    # place: renaming a file over it would leave the mount pointing at a deleted
    # inode and the next process reading the host's view instead of this one's.
    with open(HOSTS, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def blackhole():
    write_hosts([line for line in hosts_lines() if MARKER not in line]
                + ["127.0.0.1 %s  # %s" % (HOST, MARKER)])
    return resolution()


def unblackhole():
    write_hosts([line for line in hosts_lines() if MARKER not in line])
    return resolution()


report = {
    "mode": MODE,
    "webroot": WEBROOT,
    "webroot_mode": webroot_mode(),
    "resolution": resolution(),
}
if MODE == "challenge-block":
    os.chmod(WEBROOT, 0o700)
    report["webroot_mode_after"] = webroot_mode()
elif MODE == "challenge-restore":
    os.chmod(WEBROOT, int(ORIGINAL_MODE, 8))
    report["webroot_mode_after"] = webroot_mode()
elif MODE == "directory-block":
    report["resolution_after"] = blackhole()
elif MODE == "directory-restore":
    report["resolution_after"] = unblackhole()
print(json.dumps(report, sort_keys=True))
PY
"""


def acme_outage_script(
    mode: str, webroot_mode: str = "", hosts_file: str = ACME_HOSTS_FILE,
) -> str:
    """Install or remove one outage: the webroot the validator reads, or the directory."""
    return (
        ACME_OUTAGE_SCRIPT
        .replace("MODE_PLACEHOLDER", shlex.quote(mode))
        .replace("WEBROOT_PLACEHOLDER", ACME_WEBROOT)
        .replace("ORIGINAL_MODE_PLACEHOLDER", shlex.quote(webroot_mode))
        .replace("HOST_PLACEHOLDER", acme_fixture.FIXTURE_HOST)
        .replace("MARKER_PLACEHOLDER", ACME_BLACKHOLE_MARKER)
        .replace("HOSTS_PLACEHOLDER", shlex.quote(hosts_file))
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


def acme_renewal_facts(
    podman: Any, container: str, case_id: str, mode: str, domain: str, ca_file: str,
    timeout: int = ACME_PROBE_TIMEOUT_SECONDS, reload_wait: int = ACME_RENEWAL_WAIT_SECONDS,
) -> Dict[str, Any]:
    """One phase of the ACME contract: the lineage as it is, or renewed and read again."""
    result = podman.exec_bash(
        container, acme_renewal_script(mode, domain, ca_file, reload_wait),
        check=False, timeout=timeout,
    )
    return probe_json(case_id, f"the ACME {mode} probe on {container}", result)


def require_webroot_lineage(case_id: str, role: str, domain: str, facts: Dict[str, Any]) -> None:
    """Certbot's own renewal record describes the webroot lineage the install used.

    The record is what an unattended renewal reads, so an ``authenticator`` or
    ``webroot_path`` that differs from the install's would make the renewal
    validate through a route this case never observes — or fail outright.
    """
    lineage = facts.get("lineage") or {}
    values = lineage.get("values") or {}
    require(case_id, lineage.get("present"),
            f"{role}: Certbot keeps no renewal lineage at {lineage.get('path')!r} for {domain}, "
            "so the installed certificate would never be renewed")
    require(case_id, values.get("authenticator") == "webroot",
            f"{role}: the renewal lineage for {domain} authenticates as "
            f"{values.get('authenticator')!r} instead of the webroot method the install used")
    webroots = values.get("webroot_paths") or []
    require(case_id, webroots == [ACME_WEBROOT],
            f"{role}: the renewal lineage for {domain} writes its challenge under "
            f"{webroots!r} (certbot recorded {values.get('webroot_path')!r}) instead of "
            f"[{ACME_WEBROOT!r}], which is the path the port 80 vhost serves")
    require(case_id, values.get("server") == acme_fixture.ACME_DIRECTORY_URL,
            f"{role}: the renewal lineage for {domain} points at {values.get('server')!r} "
            f"instead of this run's ACME directory {acme_fixture.ACME_DIRECTORY_URL!r}")


def require_certificate_was_issued_in_this_run(
    case_id: str, role: str, domain: str, facts: Dict[str, Any], now: float,
) -> Dict[str, Any]:
    """The installed leaf is fresh, so it came from this run and not from an image.

    A certificate baked into an image or copied in by the harness would still be
    served, still chain to the fixture CA, and still pass a TLS case — its
    ``notBefore`` is the one fact that puts its issuance inside this run.

    Readability is the reader's exit status, not a ``subject`` field: Certbot
    builds a SAN-only CSR with no subject at all, so the certificate this product
    legitimately obtains has an empty subject and only the SAN carries the name.
    """
    live = facts.get("live") or {}
    require(case_id, live.get("present"),
            f"{role}: no certificate is installed at {live.get('path')!r} for {domain}")
    require(case_id, live.get("returncode") == 0,
            f"{role}: the installed certificate for {domain} could not be read: "
            f"{live.get('path')!r} (`openssl x509` exited {live.get('returncode')!r}: "
            f"{live.get('error') or 'no diagnostics'})")
    issued = live.get("not_before_epoch")
    require(case_id, isinstance(issued, int),
            f"{role}: the installed certificate reports no parseable notBefore "
            f"({live.get('not_before')!r})")
    require(case_id, issued >= int(now) - ACME_ISSUANCE_WINDOW_SECONDS,
            f"{role}: the certificate installed for {domain} was issued at "
            f"{live.get('not_before')!r}, more than {ACME_ISSUANCE_WINDOW_SECONDS}s before this "
            "case ran, so it was seeded rather than obtained through the operator's ACME path")
    return {
        "serial": live.get("serial"),
        "not_before": live.get("not_before"),
        "not_after": live.get("not_after"),
        "san": live.get("san"),
        "issuer": live.get("issuer"),
        "installed_certificates": len(facts.get("archive") or []),
    }


def require_webroot_route(case_id: str, role: str, domain: str, probe: Dict[str, Any]) -> Dict[str, Any]:
    """The product's own port 80 vhost serves the token a validator has to fetch.

    The token is fetched from the Control Machine, not from the host: what an ACME
    validator sees is a request over the network to the challenge URL, so a file
    read from the host would prove the wrong thing.
    """
    report = probe.get("probe") or {}
    require(case_id, probe.get("returncode") == 0,
            f"{role}: an independent client could not fetch "
            f"http://{domain}/.well-known/acme-challenge/ through the product's port 80 vhost: "
            f"{report.get('error') or (probe.get('stderr') or '').strip()[-600:]}")
    require(case_id, report.get("status") == 200,
            f"{role}: the product's port 80 vhost answered {report.get('status')!r} for "
            f"http://{domain}/.well-known/acme-challenge/ instead of serving the token")
    return {
        "url": report.get("url"),
        "status": report.get("status"),
        "body_length": report.get("body_length"),
        "body_sha256": report.get("body_sha256"),
    }


def require_renewal_issued(case_id: str, role: str, domain: str, facts: Dict[str, Any]) -> Dict[str, Any]:
    """A forced renewal performs a real HTTP-01 challenge and yields a new certificate.

    Issuance is the validator's own verdict: the fixture directory is not
    configured to accept challenges without fetching them, so a new certificate
    with a new serial and a later ``notBefore`` can only exist after a successful
    HTTP-01 fetch from the challenge URL. The challenge type is read from
    Certbot's log for this invocation, which is what rules out a DNS-01 or
    TLS-ALPN-01 path that the route probe could never have observed.
    """
    renewal = facts.get("renewal") or {}
    require(case_id, facts.get("mode") == "renew",
            f"{role}: the renewal probe answered for {facts.get('mode')!r}")
    require(case_id, renewal.get("returncode") == 0,
            f"{role}: `certbot renew --force-renewal` for {domain} exited "
            f"{renewal.get('returncode')!r}: {renewal.get('tail')}")
    transcript = "\n".join([
        str(facts.get("certbot_log") or ""),
        str(renewal.get("stdout") or ""),
        str(renewal.get("stderr") or ""),
    ])
    require(case_id, f"http-01 challenge for {domain}" in transcript,
            f"{role}: the renewal for {domain} did not perform an HTTP-01 challenge, so the "
            f"challenge route this case validates is not the one that was used: "
            f"{renewal.get('tail')}")
    require(case_id, "Successfully received certificate" in transcript,
            f"{role}: Certbot never reported receiving a renewed certificate for {domain}: "
            f"{renewal.get('tail')}")
    before = facts.get("archive") or []
    after = facts.get("archive_after") or []
    require(case_id, len(after) > len(before),
            f"{role}: the archive for {domain} holds {len(after)} certificate(s) after a forced "
            f"renewal, the same count it held before it ({[item.get('path') for item in after]})")
    old = facts.get("live") or {}
    new = facts.get("live_after") or {}
    require(case_id, old.get("serial") and new.get("serial") and old.get("serial") != new.get("serial"),
            f"{role}: the renewed lineage for {domain} still reports certificate serial "
            f"{new.get('serial')!r}")
    issued, renewed = old.get("not_before_epoch"), new.get("not_before_epoch")
    require(case_id, isinstance(renewed, int) and isinstance(issued, int) and renewed > issued,
            f"{role}: the renewed certificate for {domain} is not newer than the one it replaced "
            f"({old.get('not_before')!r} -> {new.get('not_before')!r})")
    return {
        "returncode": renewal.get("returncode"),
        "duration_seconds": renewal.get("duration_seconds"),
        "challenge": f"http-01 for {domain}",
        "installed_certificates_before": len(before),
        "installed_certificates_after": len(after),
        "serial_before": old.get("serial"),
        "serial_after": new.get("serial"),
        "not_before_before": old.get("not_before"),
        "not_before_after": new.get("not_before"),
        "certbot_tail": str(renewal.get("tail") or "")[-600:],
    }


def require_renewed_certificate_is_served(
    case_id: str, role: str, domain: str, facts: Dict[str, Any], report: Dict[str, Any],
    expected_status: int,
) -> Dict[str, Any]:
    """The handshake a client gets now carries the certificate the renewal issued.

    Reloading NGINX onto a new lineage is the only way the served leaf can change,
    so matching the client's ``notBefore`` to the renewed file is what proves the
    renewal reached the public surface rather than only the disk.
    """
    verified = require_client_certificate(case_id, role, domain, report, expected_status)
    renewed = (facts.get("live_after") or {}).get("not_before_epoch")
    require(case_id, isinstance(renewed, int),
            f"{role}: the renewed certificate for {domain} reports no parseable notBefore")
    served = verified.get("not_before")
    expected = datetime.fromtimestamp(renewed, timezone.utc).isoformat()
    require(case_id, served == expected,
            f"{role}: the certificate served for {domain} starts at {served!r}, not at the "
            f"{expected!r} the renewal issued, so NGINX is still serving the replaced lineage")
    return verified


def require_renewal_reloaded_nginx(
    case_id: str, role: str, facts: Dict[str, Any],
) -> Dict[str, Any]:
    """The product's deploy hook reloaded the master onto the renewed lineage.

    A renewal that never reloads leaves NGINX serving the expired certificate
    until the next restart, which is the exact failure the managed hook exists to
    prevent; replacing the master instead of reloading it would drop the
    listeners the hook is supposed to leave alone.
    """
    baseline = facts.get("service") or {}
    refreshed = facts.get("service_after") or {}
    require(case_id, baseline.get("worker_pids"),
            f"{role}: the renewal probe read no worker before the renewal "
            f"({baseline.get('worker_pids')!r}), so no reload could be observed")
    require(case_id, refreshed.get("active") == "active",
            f"{role}: NGINX is {refreshed.get('active')!r} after the renewal")
    require(case_id, refreshed.get("main_pid") == baseline.get("main_pid"),
            f"{role}: the renewal replaced the NGINX master "
            f"({baseline.get('main_pid')} -> {refreshed.get('main_pid')}) instead of reloading it")
    appeared = sorted(set(refreshed.get("worker_pids") or []) - set(baseline.get("worker_pids") or []))
    require(case_id, appeared,
            f"{role}: the product's deploy hook did not reload NGINX after the renewal "
            f"(workers stayed {baseline.get('worker_pids')} for "
            f"{facts.get('reload_waited_seconds')}s)")
    require(case_id, int(refreshed.get("listeners_443") or 0) >= 1,
            f"{role}: nothing listens on 443 after the renewal reloaded NGINX")
    test = facts.get("test_after") or {}
    require(case_id, test.get("returncode") == 0,
            f"{role}: the configuration fails `nginx -t` after the renewal:\n{test.get('tail', '')}")
    return {
        "master_pid": refreshed.get("main_pid"),
        "worker_pids_before": baseline.get("worker_pids"),
        "worker_pids_after": refreshed.get("worker_pids"),
        "listener_443": refreshed.get("listeners_443"),
        "nginx_test_returncode": test.get("returncode"),
        "reload_waited_seconds": facts.get("reload_waited_seconds"),
    }


def _acme_route_probe(
    product: AioProduct, case_id: str, role: str, domain: str,
) -> Dict[str, Any]:
    """Place a token in the product's webroot and fetch it as a validator would.

    The token is removed in a ``finally`` block: a case that fails must not leave
    a challenge file behind for the next renewal or for a later case to read.
    """
    token = uuid.uuid4().hex
    body = f"gowave-e2e-acme-{token}"
    directory = f"{ACME_WEBROOT}/.well-known/acme-challenge"
    challenge = f"{directory}/{token}"
    write = product.host_script(
        f"install -d -m 0755 {shlex.quote(directory)} && "
        f"printf '%s' {shlex.quote(body)} > {shlex.quote(challenge)}",
        timeout=60,
    )
    try:
        require(case_id, write.returncode == 0,
                f"{role}: the case could not write a challenge token into the product's ACME "
                f"webroot: {(write.stderr or write.stdout or '').strip()[-600:]}")
        return product.host.client_http(
            f"http://{domain}/.well-known/acme-challenge/{token}",
            expect_status=200, expect_body=body, timeout=ACME_ROUTE_TIMEOUT_SECONDS,
        )
    finally:
        product.host_script(f"rm -f {shlex.quote(challenge)}", timeout=60)


def acme_renewal_contract(
    product: AioProduct, case_id: str, role: str, domain: str,
    container: str = "", expected_status: int = 200,
) -> Dict[str, Any]:
    """Prove issuance and renewal run through the target's own webroot route.

    Four observations make one conclusion, and none of them substitutes for
    another: Certbot's renewal record names the webroot method, the product's
    port 80 vhost serves a token written into that webroot to an independent
    client, a forced renewal performs an HTTP-01 challenge and yields a new
    serial, and the certificate the client now receives is that renewed leaf
    behind a reloaded — not restarted — NGINX.
    """
    host = product.require_installed()
    target = container or host.target_name
    ca_file = str(host.install_environment().get("GOWAVE_ACME_TEST_CA_FILE", ""))
    now = time.time()
    before = acme_renewal_facts(product.podman, target, case_id, "before", domain, ca_file)
    require_webroot_lineage(case_id, role, domain, before)
    installed = require_certificate_was_issued_in_this_run(case_id, role, domain, before, now)
    route = require_webroot_route(
        case_id, role, domain, _acme_route_probe(product, case_id, role, domain),
    )
    renewed = acme_renewal_facts(product.podman, target, case_id, "renew", domain, ca_file)
    issuance = require_renewal_issued(case_id, role, domain, renewed)
    served = require_renewed_certificate_is_served(
        case_id, role, domain, renewed,
        host.client_http(f"https://{domain}/", expect_status=expected_status,
                         expect_san=[domain], timeout=30),
        expected_status,
    )
    reload_facts = require_renewal_reloaded_nginx(case_id, role, renewed)
    return {
        "role": role,
        "domain": domain,
        "webroot": ACME_WEBROOT,
        "lineage": (before.get("lineage") or {}).get("values"),
        "installed_certificate": installed,
        "challenge_route": route,
        "renewal": issuance,
        "served_after_renewal": served,
        "reload": reload_facts,
    }


def case_acme_renewal(product: AioProduct) -> Dict[str, Any]:
    """ACME-01: the certificate serving the Panel is issued and renewed for real.

    The product does not ship a certificate: it asks the pinned ACME directory
    for one through Certbot's webroot method, and the port 80 vhost it generated
    is what the validator fetches. The case never writes a certificate and never
    answers a challenge itself — it plants one token to prove the route, then lets
    Certbot renew the lineage and checks that the leaf a client receives changed.
    """
    return acme_renewal_contract(product, ACME_CASE_ID, "the All-in-One host", PANEL_DOMAIN)


def acme_outage_facts(
    podman: Any, container: str, case_id: str, mode: str, webroot_mode: str = "",
    timeout: int = ACME_PROBE_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """One outage phase: install the failure, remove it, or report what it left behind."""
    result = podman.exec_bash(
        container, acme_outage_script(mode, webroot_mode), check=False, timeout=timeout,
    )
    return probe_json(case_id, f"the ACME outage {mode} probe on {container}", result)


def acme_renewal_attempt(
    podman: Any, container: str, case_id: str, domain: str, ca_file: str,
) -> Dict[str, Any]:
    """A forced renewal that is expected to fail, with no reload budget to spend."""
    return acme_renewal_facts(
        podman, container, case_id, "renew", domain, ca_file,
        reload_wait=ACME_OUTAGE_RELOAD_WAIT_SECONDS,
    )


def require_challenge_route_is_down(
    case_id: str, role: str, domain: str, probe: Dict[str, Any],
) -> Dict[str, Any]:
    """Positive control: the token route really stopped answering before Certbot is blamed.

    A renewal that fails while the route still serves tokens would mean the case
    broke something else, and the failure it then reported would name the wrong
    cause; the control is what keeps the assertion attributable.
    """
    report = probe.get("probe") or {}
    served = probe.get("returncode") == 0 and report.get("status") == 200
    require(case_id, not served,
            f"{role}: the product's port 80 vhost still served a challenge token for {domain} "
            "after the webroot was closed, so the challenge outage this phase measures never "
            "happened")
    return {
        "url": report.get("url"),
        "status": report.get("status"),
        "returncode": probe.get("returncode"),
        "error": (report.get("error") or (probe.get("stderr") or "").strip()[-300:]),
    }


def require_directory_is_unreachable(
    case_id: str, role: str, facts: Dict[str, Any], reachable: bool,
) -> Dict[str, Any]:
    """Positive control for the directory phase: the name now answers loopback.

    Certbot resolves the pinned directory per invocation, so pointing that name
    at the target itself is an outage it has to notice; reading the resolution
    back proves the outage was in place instead of assuming it.
    """
    resolution = str(facts.get("resolution_after") or facts.get("resolution") or "")
    loopback = "127.0.0.1" in resolution
    require(case_id, loopback is not reachable,
            f"{role}: the target resolved {acme_fixture.FIXTURE_HOST} to {resolution!r} when the "
            f"directory was supposed to be {'reachable' if reachable else 'unreachable'}")
    return {"resolution": resolution, "loopback": loopback}


FAILED_RENEWAL_MARKERS = {
    "challenge": ("Some challenges have failed", "Challenge failed", "unauthorized"),
    "directory": ("Connection refused", "ConnectionError", "Max retries exceeded",
                  "Failed to establish a new connection"),
}


def require_renewal_failed(
    case_id: str, role: str, domain: str, facts: Dict[str, Any], kind: str,
) -> Dict[str, Any]:
    """A forced renewal reports the failure this phase installed, and no certificate.

    Certbot exits non-zero and quotes the validator's own verdict, so the failure
    is attributable to the outage rather than to a client that could not reach the
    host: the same transcript has to carry the HTTP-01 attempt for this domain, or
    the directory's own connection error.
    """
    renewal = facts.get("renewal") or {}
    require(case_id, facts.get("mode") == "renew",
            f"{role}: the failed-attempt probe answered for {facts.get('mode')!r}")
    require(case_id, renewal.get("returncode") not in (0, None),
            f"{role}: `certbot renew --force-renewal` for {domain} exited "
            f"{renewal.get('returncode')!r} although the {kind} was down, so the outage never "
            f"reached the renewal this case is about: {renewal.get('tail')}")
    transcript = "\n".join([
        str(facts.get("certbot_log") or ""),
        str(renewal.get("stdout") or ""),
        str(renewal.get("stderr") or ""),
    ])
    if kind == "challenge":
        require(case_id, f"http-01 challenge for {domain}" in transcript,
                f"{role}: the renewal for {domain} never attempted an HTTP-01 challenge, so the "
                f"challenge route that failed is not the one it used: {renewal.get('tail')}")
    markers = FAILED_RENEWAL_MARKERS[kind]
    matched = [marker for marker in markers if marker in transcript]
    require(case_id, matched,
            f"{role}: the renewal for {domain} failed without naming the {kind} it was denied: "
            f"{renewal.get('tail')}")
    require(case_id, "Successfully received certificate" not in transcript,
            f"{role}: the renewal for {domain} reported receiving a certificate while the "
            f"{kind} was down: {renewal.get('tail')}")
    return {
        "returncode": renewal.get("returncode"),
        "reported": matched,
        "duration_seconds": renewal.get("duration_seconds"),
        "tail": str(renewal.get("tail") or "")[-600:],
    }


def require_failure_left_the_lineage_alone(
    case_id: str, role: str, domain: str, facts: Dict[str, Any],
) -> Dict[str, Any]:
    """A failed renewal neither replaced nor extended the lineage on disk.

    Certbot only saves on success, so the archive growing without a new leaf — or
    the leaf changing without a served reload — would mean the certificate the
    host depends on was mutated by an attempt that never succeeded.
    """
    before = facts.get("live") or {}
    after = facts.get("live_after") or {}
    require(case_id, before.get("present") and after.get("present"),
            f"{role}: the lineage for {domain} disappeared after a failed renewal "
            f"({before.get('path')!r})")
    require(case_id, before.get("serial") == after.get("serial")
            and before.get("not_before_epoch") == after.get("not_before_epoch"),
            f"{role}: a failed renewal for {domain} changed the installed certificate "
            f"({before.get('serial')!r}/{before.get('not_before')!r} -> "
            f"{after.get('serial')!r}/{after.get('not_before')!r})")
    archive_before = len(facts.get("archive") or [])
    archive_after = len(facts.get("archive_after") or [])
    require(case_id, archive_before == archive_after,
            f"{role}: a failed renewal for {domain} added a certificate to the archive "
            f"({archive_before} -> {archive_after})")
    return {
        "serial": after.get("serial"),
        "not_before": after.get("not_before"),
        "archive": archive_after,
    }


def require_failure_left_the_certificate_serving(
    case_id: str, role: str, domain: str, facts: Dict[str, Any], report: Dict[str, Any],
    expected_status: int,
) -> Dict[str, Any]:
    """The client still receives the working leaf, so the outage never reached 443.

    This is the half of the contract that protects the users during a failed
    renewal: the validator failing must not take the served certificate with it.
    """
    verified = require_client_certificate(case_id, role, domain, report, expected_status)
    unchanged = (facts.get("live") or {}).get("not_before_epoch")
    require(case_id, isinstance(unchanged, int),
            f"{role}: the installed certificate for {domain} reports no parseable notBefore")
    served = verified.get("not_before")
    expected = datetime.fromtimestamp(unchanged, timezone.utc).isoformat()
    require(case_id, served == expected,
            f"{role}: after a failed renewal for {domain} a client is served a certificate "
            f"starting at {served!r} instead of the {expected!r} the lineage already held, so the "
            "failed attempt disturbed the certificate the host was serving")
    return verified


def require_recovery_issued(
    case_id: str, role: str, domain: str, facts: Dict[str, Any], previous: Dict[str, Any],
) -> Dict[str, Any]:
    """With the outage gone, the same forced renewal succeeds and replaces the leaf."""
    issuance = require_renewal_issued(case_id, role, domain, facts)
    require(case_id, issuance.get("serial_after") != previous.get("serial"),
            f"{role}: the renewal after recovery for {domain} reports the serial the failed "
            f"attempt left behind ({issuance.get('serial_after')!r}), so nothing was reissued")
    return issuance


def _release_acme_outage(
    product: AioProduct, target: str, case_id: str, mode: str, argument: str = "",
) -> Dict[str, Any]:
    """Remove an outage; a cleanup that fails must not replace the reason the case did.

    The host is left as the outage phase found it either way, so the report is
    returned for the success path and swallowed when an assertion is already on
    its way out of the case.
    """
    try:
        return acme_outage_facts(product.podman, target, case_id, mode, argument)
    except AssertionError:
        return {}


def acme_outage_contract(
    product: AioProduct, case_id: str, role: str, domain: str,
    container: str = "", expected_status: int = 200,
) -> Dict[str, Any]:
    """Prove both ACME failures fail closed, and that the lineage survives them.

    Two outages are installed one after the other, each with a positive control
    that shows the outage is real before Certbot is asked about it: the webroot
    the validator reads stops answering, and the pinned directory becomes
    unreachable from the target. In both, the renewal must fail, name its own
    cause, and leave the installed lineage and the certificate on 443 exactly as
    they were; after the outage is removed, the same forced renewal must succeed.
    Nothing is answered or reissued by the harness.
    """
    host = product.require_installed()
    target = container or host.target_name
    ca_file = str(host.install_environment().get("GOWAVE_ACME_TEST_CA_FILE", ""))
    now = time.time()
    before = acme_renewal_facts(product.podman, target, case_id, "before", domain, ca_file)
    require_webroot_lineage(case_id, role, domain, before)
    installed = require_certificate_was_issued_in_this_run(case_id, role, domain, before, now)

    blocked = acme_outage_facts(product.podman, target, case_id, "challenge-block")
    original_mode = str(blocked.get("webroot_mode") or "")
    challenge: Dict[str, Any] = {}
    directory: Dict[str, Any] = {}
    try:
        require(case_id, blocked.get("webroot_mode_after") == "0700",
                f"{role}: the product's ACME webroot is {blocked.get('webroot_mode_after')!r} "
                "after the outage, so the validator's path was never closed")
        challenge["control"] = require_challenge_route_is_down(
            case_id, role, domain, _acme_route_probe(product, case_id, role, domain),
        )
        attempt = acme_renewal_attempt(product.podman, target, case_id, domain, ca_file)
        challenge["failure"] = require_renewal_failed(case_id, role, domain, attempt, "challenge")
        challenge["lineage"] = require_failure_left_the_lineage_alone(
            case_id, role, domain, attempt,
        )
        challenge["served"] = require_failure_left_the_certificate_serving(
            case_id, role, domain, attempt,
            host.client_http(f"https://{domain}/", expect_status=expected_status,
                             expect_san=[domain], timeout=30),
            expected_status,
        )
    except BaseException:
        _release_acme_outage(product, target, case_id, "challenge-restore", original_mode)
        raise
    restored = acme_outage_facts(
        product.podman, target, case_id, "challenge-restore", original_mode,
    )
    require(case_id, restored.get("webroot_mode_after") == original_mode,
            f"{role}: the ACME webroot was left at {restored.get('webroot_mode_after')!r} instead "
            f"of {original_mode!r} after the outage was removed")
    challenge["restored_mode"] = restored.get("webroot_mode_after")
    challenge["route_after_restore"] = require_webroot_route(
        case_id, role, domain, _acme_route_probe(product, case_id, role, domain),
    )
    recovered = acme_renewal_facts(product.podman, target, case_id, "renew", domain, ca_file)
    challenge["recovery"] = require_recovery_issued(
        case_id, role, domain, recovered, {"serial": (before.get("live") or {}).get("serial")},
    )
    require_renewed_certificate_is_served(
        case_id, role, domain, recovered,
        host.client_http(f"https://{domain}/", expect_status=expected_status,
                         expect_san=[domain], timeout=30),
        expected_status,
    )

    blackholed = acme_outage_facts(product.podman, target, case_id, "directory-block")
    try:
        directory["control"] = require_directory_is_unreachable(
            case_id, role, blackholed, reachable=False,
        )
        attempt = acme_renewal_attempt(product.podman, target, case_id, domain, ca_file)
        directory["failure"] = require_renewal_failed(case_id, role, domain, attempt, "directory")
        directory["lineage"] = require_failure_left_the_lineage_alone(
            case_id, role, domain, attempt,
        )
        directory["served"] = require_failure_left_the_certificate_serving(
            case_id, role, domain, attempt,
            host.client_http(f"https://{domain}/", expect_status=expected_status,
                             expect_san=[domain], timeout=30),
            expected_status,
        )
    except BaseException:
        _release_acme_outage(product, target, case_id, "directory-restore")
        raise
    released = acme_outage_facts(product.podman, target, case_id, "directory-restore")
    directory["resolution_after_release"] = require_directory_is_unreachable(
        case_id, role, released, reachable=True,
    )["resolution"]
    renewed = acme_renewal_facts(product.podman, target, case_id, "renew", domain, ca_file)
    directory["recovery"] = require_recovery_issued(
        case_id, role, domain, renewed,
        {"serial": (recovered.get("live_after") or {}).get("serial")},
    )
    require_renewed_certificate_is_served(
        case_id, role, domain, renewed,
        host.client_http(f"https://{domain}/", expect_status=expected_status,
                         expect_san=[domain], timeout=30),
        expected_status,
    )

    return {
        "role": role,
        "domain": domain,
        "webroot": ACME_WEBROOT,
        "installed_certificate": installed,
        "challenge_outage": challenge,
        "directory_outage": directory,
    }


def case_acme_outage(product: AioProduct) -> Dict[str, Any]:
    """ACME-02: both ACME failures fail closed, and the lineage survives them.

    A renewal is the one operation a host performs unattended, so the two ways it
    can be denied — the validator cannot read the challenge, the directory cannot
    be reached — are exactly the cases where a wrong reaction would either drop
    the working certificate or silently keep serving an expired one. The case
    installs each outage, proves Certbot reports it, proves the lineage and the
    served certificate are untouched, then removes the outage and proves the same
    renewal now succeeds.
    """
    return acme_outage_contract(product, ACME_OUTAGE_CASE_ID, "the All-in-One host", PANEL_DOMAIN)


DNS_CASE_ID = "DNS-01"
DNS_SUFFIX = topology.DNS_ZONE_SUFFIX
DNS_A_NAME = f"dns-a.{DNS_SUFFIX}"
DNS_AAAA_NAME = f"dns-aaaa.{DNS_SUFFIX}"
DNS_BOTH_NAME = f"dns-both.{DNS_SUFFIX}"
DNS_TTL_NAME = f"dns-ttl.{DNS_SUFFIX}"
DNS_ABSENT_NAME = f"dns-absent.{DNS_SUFFIX}"
DNS_WRONG_NAME = f"dns-wrong.{DNS_SUFFIX}"
DNS_STALE_NAME = f"dns-stale.{DNS_SUFFIX}"
# An address in a family the run does not otherwise carry, so a published AAAA
# can be told from an A answer by value alone.
DNS_AAAA_ANSWER = "2001:db8::53"
# The record lifetime the case publishes: long enough that a resolver which
# caches at all will cache it, short enough that one which ignores expiry is
# caught by the deadline instead of being believed for the rest of the run.
DNS_CASE_TTL = 5
DNS_EXPIRY_DEADLINE_SECONDS = 60
DNS_EXPIRY_INTERVAL_SECONDS = 3
DNS_CASE_TIMEOUT_SECONDS = 600
RCODE_NOERROR = 0
RCODE_NXDOMAIN = 3


def dns_vantages(host: topology.AioTopology) -> List[Dict[str, str]]:
    """The two places answers are read from: the host under test and a client.

    The host's own resolution path is what a product step gets; the Control
    Machine shares nothing with the product, so an answer it receives can only
    have come from the resolver both of them were given.
    """
    return [
        {"role": "target", "container": host.target_name, "source": str(host.plan.target_ip)},
        {"role": "client", "container": host.client_name, "source": str(host.plan.client_ip)},
    ]


def dns_case_zone(
    host: topology.AioTopology, ttl_address: str = "",
    behavior: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """The install's own zone plus the names this case steers.

    The probe names are added to the base zone rather than replacing it, so a
    rewrite cannot make a later case resolve differently. The zone's TTL is
    shortened for the expiry half, and restored with the zone at the end.
    """
    data = json.loads(json.dumps(host.zone()))
    data["ttl"] = DNS_CASE_TTL
    records = data["records"]
    records[DNS_A_NAME] = {"A": [str(host.plan.target_ip)]}
    records[DNS_AAAA_NAME] = {"AAAA": [DNS_AAAA_ANSWER]}
    records[DNS_BOTH_NAME] = {
        "A": [str(host.plan.target_ip)], "AAAA": [DNS_AAAA_ANSWER],
    }
    records[DNS_TTL_NAME] = {"A": [ttl_address or str(host.plan.target_ip)]}
    data["behavior"] = behavior or {"mode": "answer", "delay_ms": 0}
    return data


def _dns_report(
    product: AioProduct, case_id: str, vantage: Dict[str, str], scope: str,
    queries: Sequence[str] = (), names: Sequence[str] = (),
) -> Dict[str, Any]:
    host = product.require_installed()
    result = host.dns_probe(vantage["container"], scope, queries=queries, names=names)
    return probe_json(case_id, f"the DNS {scope} probe on {vantage['role']}", result)


def _direct_entry(report: Dict[str, Any], name: str, qtype: str) -> Dict[str, Any]:
    for entry in report.get("queries") or []:
        if entry.get("name") == name and entry.get("type") == qtype:
            return entry
    return {}


def _system_entry(report: Dict[str, Any], name: str) -> Dict[str, Any]:
    for entry in report.get("names") or []:
        if entry.get("name") == name:
            return entry
    return {}


def require_direct_answer(
    case_id: str, role: str, report: Dict[str, Any], name: str, qtype: str,
    expected: Sequence[str], rcode: int = RCODE_NOERROR,
) -> Dict[str, Any]:
    """One authoritative answer, read without a resolver library in between."""
    entry = _direct_entry(report, name, qtype)
    require(case_id, entry,
            f"{role}: the direct probe reported no {qtype} query for {name!r} "
            f"({[(item.get('name'), item.get('type')) for item in report.get('queries') or []]})")
    require(case_id, not entry.get("error"),
            f"{role}: a direct {qtype} query for {name} never reached the resolver: {entry.get('error')}")
    require(case_id, entry.get("rcode") == rcode,
            f"{role}: a direct {qtype} query for {name} answered "
            f"{entry.get('rcode')} ({entry.get('rcode_name')}) instead of {rcode} from "
            f"{report.get('server')}")
    answers = list(entry.get("answers") or [])
    require(case_id, answers == list(expected),
            f"{role}: a direct {qtype} query for {name} answered {answers} instead of "
            f"{list(expected)}, so the resolver published a different record set than the zone")
    return entry


def require_system_family(
    case_id: str, role: str, report: Dict[str, Any], name: str, family: str,
    expected: Sequence[str],
) -> Dict[str, Any]:
    """One family's addresses, resolved through the role's own path."""
    entry = _system_entry(report, name)
    require(case_id, entry,
            f"{role}: the system probe reported no resolution for {name!r} "
            f"({[item.get('name') for item in report.get('names') or []]})")
    addresses = list(entry.get(family) or [])
    require(case_id, addresses == list(expected),
            f"{role}: {name} resolved to {addresses} for {family} instead of {list(expected)}, "
            f"through the resolver configuration {report.get('resolver')}")
    return entry


def require_fixture_attribution(
    case_id: str, role: str, source: str, events: Sequence[Dict[str, Any]], name: str,
    qtype: str, expected: Sequence[str], rcode: int = RCODE_NOERROR,
    mode: str = "answer",
) -> Dict[str, Any]:
    """The resolver's own log names this vantage and this answer.

    A name that resolves says nothing about where the answer came from: a hosts
    entry or a cache left by an earlier phase would look identical. Only the
    fixture recording this source address asking this question lets the answer be
    attributed to the zone the case published.
    """
    matches = [
        event for event in events
        if event.get("qname") == name and event.get("qtype") == qtype
        and str(event.get("client", "")).startswith(f"{source}:")
    ]
    require(case_id, matches,
            f"{role}: the resolver recorded no {qtype} query for {name!r} from {source}, "
            "so the answer did not come from the fixture zone")
    event = matches[-1]
    require(case_id, event.get("rcode") == rcode,
            f"{role}: the resolver recorded rcode {event.get('rcode')} for the {qtype} query "
            f"for {name} from {source} instead of {rcode}")
    require(case_id, event.get("mode") == mode,
            f"{role}: the resolver recorded mode {event.get('mode')!r} for {name!r} instead of "
            f"{mode!r}, so the answer was not the one this phase published")
    if rcode == RCODE_NOERROR:
        answers = list(event.get("answers") or [])
        require(case_id, answers == list(expected),
                f"{role}: the resolver recorded {answers} for {name} from {source} instead of "
                f"{list(expected)}")
    return event


def require_address_selection(
    case_id: str, role: str, direct: Dict[str, Any], system: Dict[str, Any], target_address: str,
) -> Dict[str, Any]:
    """Each family answers with its own records and never with the other's.

    A resolver that substituted one family for the other would still resolve
    every name here, so the empty side is as much an assertion as the filled one.
    """
    a_only = require_direct_answer(case_id, role, direct, DNS_A_NAME, "A", [target_address])
    a_empty = require_direct_answer(case_id, role, direct, DNS_A_NAME, "AAAA", [])
    aaaa_only = require_direct_answer(case_id, role, direct, DNS_AAAA_NAME, "AAAA", [DNS_AAAA_ANSWER])
    aaaa_empty = require_direct_answer(case_id, role, direct, DNS_AAAA_NAME, "A", [])
    both_a = require_direct_answer(case_id, role, direct, DNS_BOTH_NAME, "A", [target_address])
    both_aaaa = require_direct_answer(case_id, role, direct, DNS_BOTH_NAME, "AAAA", [DNS_AAAA_ANSWER])

    system_a = require_system_family(case_id, role, system, DNS_A_NAME, "inet", [target_address])
    require(case_id, not system_a.get("inet6"),
            f"{role}: {DNS_A_NAME} carries only an A record, yet the system path resolved "
            f"{system_a.get('inet6')} for inet6")
    system_aaaa = require_system_family(case_id, role, system, DNS_AAAA_NAME, "inet6", [DNS_AAAA_ANSWER])
    require(case_id, not system_aaaa.get("inet"),
            f"{role}: {DNS_AAAA_NAME} carries only an AAAA record, yet the system path resolved "
            f"{system_aaaa.get('inet')} for inet")
    system_both = require_system_family(case_id, role, system, DNS_BOTH_NAME, "inet", [target_address])
    require(case_id, list(system_both.get("inet6") or []) == [DNS_AAAA_ANSWER],
            f"{role}: {DNS_BOTH_NAME} resolved to {system_both.get('inet6')} for inet6 instead of "
            f"[{DNS_AAAA_ANSWER!r}]")

    require(case_id, a_only.get("ttl") == DNS_CASE_TTL and aaaa_only.get("ttl") == DNS_CASE_TTL,
            f"{role}: the fixture published TTL {a_only.get('ttl')}/{aaaa_only.get('ttl')} for the "
            f"A/AAAA records instead of the zone's {DNS_CASE_TTL}s, so a downstream cache would keep "
            "an answer past the change this case makes")
    require(case_id, a_empty.get("answers") == [] and aaaa_empty.get("answers") == [],
            f"{role}: the fixture answered the empty family instead of publishing no record for it")
    return {
        "a": {"answers": a_only.get("answers"), "ttl": a_only.get("ttl")},
        "a_aaaa": {"rcode": a_empty.get("rcode")},
        "aaaa": {"answers": aaaa_only.get("answers"), "ttl": aaaa_only.get("ttl")},
        "aaaa_a": {"rcode": aaaa_empty.get("rcode")},
        "both": {"a": both_a.get("answers"), "aaaa": both_aaaa.get("answers")},
        "system": {
            "a": {"inet": system_a.get("inet"), "inet6": system_a.get("inet6")},
            "aaaa": {"inet": system_aaaa.get("inet"), "inet6": system_aaaa.get("inet6")},
            "both": {"inet": system_both.get("inet"), "inet6": system_both.get("inet6")},
        },
    }


def require_nxdomain(
    case_id: str, role: str, direct: Dict[str, Any], system: Dict[str, Any],
) -> Dict[str, Any]:
    """A name the zone does not carry is refused by the zone, not by a fallback."""
    entry = require_direct_answer(
        case_id, role, direct, DNS_ABSENT_NAME, "A", [], rcode=RCODE_NXDOMAIN,
    )
    missing = require_system_family(case_id, role, system, DNS_ABSENT_NAME, "inet", [])
    require(case_id, not missing.get("inet6"),
            f"{role}: {DNS_ABSENT_NAME} does not exist in the zone, yet the system path resolved "
            f"{missing.get('inet6')} for inet6")
    return {"rcode": entry.get("rcode"), "answers": entry.get("answers"),
            "system_error": missing.get("inet_error")}


def require_ttl_expiry(
    case_id: str, role: str, earlier: Dict[str, Any], later: Dict[str, Any],
    previous: Sequence[str], expected: Sequence[str], polls: int,
) -> Dict[str, Any]:
    """The answer a record changes to is visible by the time its TTL has passed.

    Both ends are asserted: the old answer really was what the role resolved
    before the zone changed, and the new one replaced it inside the deadline. A
    resolver that never caches passes the second half immediately, which is the
    correct outcome for it — what must not happen is an old answer surviving
    beyond the TTL the record published.
    """
    observed = list(earlier.get("inet") or [])
    require(case_id, observed == list(previous),
            f"{role}: {DNS_TTL_NAME} resolved to {observed} instead of {list(previous)} before the "
            "zone changed, so the change had nothing observable to replace")
    addresses = list(later.get("inet") or [])
    require(case_id, addresses == list(expected),
            f"{role}: {DNS_TTL_NAME} still resolved to {addresses} instead of {list(expected)} "
            f"after {polls} polls inside {DNS_EXPIRY_DEADLINE_SECONDS}s, so the answer the previous "
            f"zone published ({list(previous)}) outlived the {DNS_CASE_TTL}s record TTL")
    return {"before": observed, "after": addresses, "polls": polls}


def require_wrong_answer(
    case_id: str, role: str, direct: Dict[str, Any], wrong_address: str,
) -> Dict[str, Any]:
    """A steered wrong answer is served as published instead of being repaired.

    Making the resolver lie is the precondition for proving the product refuses a
    wrong address later, so the wrong address has to arrive intact.
    """
    entry = require_direct_answer(case_id, role, direct, DNS_WRONG_NAME, "A", [wrong_address])
    require(case_id, entry.get("ttl") == DNS_CASE_TTL,
            f"{role}: the wrong answer for {DNS_WRONG_NAME} carried TTL {entry.get('ttl')} instead "
            f"of {DNS_CASE_TTL}s")
    return {"answers": entry.get("answers"), "ttl": entry.get("ttl")}


def require_stale_answer(
    case_id: str, role: str, direct: Dict[str, Any], stale_address: str,
) -> Dict[str, Any]:
    """An answer about to expire is served with the short TTL that says so."""
    entry = require_direct_answer(case_id, role, direct, DNS_STALE_NAME, "A", [stale_address])
    require(case_id, entry.get("ttl") == DNS_CASE_TTL,
            f"{role}: the stale answer for {DNS_STALE_NAME} carried TTL {entry.get('ttl')} instead "
            f"of {DNS_CASE_TTL}s, so it was not published as an answer about to expire")
    return {"answers": entry.get("answers"), "ttl": entry.get("ttl")}


def _restore_dns_zone(host: topology.AioTopology, data: Dict[str, Any]) -> None:
    """Put the install's own zone back; a cleanup failure must not replace the real error."""
    try:
        host.write_dns_zone(data)
    except OSError:
        pass


def case_dns(product: AioProduct) -> Dict[str, Any]:
    """DNS-01: the fixture's answers are measured from both vantages, twice.

    The product trusts this resolver at install time and at renewal time, so the
    resolver's behaviour is part of what an acceptance run rests on: a name that
    answers the wrong family, an expired record that keeps being served, a
    missing name that resolves anyway, or an injected wrong address that is
    silently repaired would each make a later case pass or fail for a reason
    nobody attributed. Every answer is read twice — through the host's own
    resolution path and from the Control Machine — and matched against the
    resolver's own query log, which is the only thing that can say the answer
    came from the zone rather than from a cache or a hosts file.
    """
    host = product.require_installed()
    case_id = DNS_CASE_ID
    target_address = str(host.plan.target_ip)
    changed_address = str(host.plan.client_ip)
    wrong_address = str(host.plan.echo_ip)
    base_zone = host.zone()
    resolution = str(host.plan.dns_ip)

    host.write_dns_zone(dns_case_zone(host))
    answers: Dict[str, Dict[str, Any]] = {}
    attribution: Dict[str, Any] = {}
    selection: Dict[str, Any] = {}
    expiry: Dict[str, Any] = {}
    steered: Dict[str, Any] = {}
    try:
        for vantage in dns_vantages(host):
            role = vantage["role"]
            direct = _dns_report(product, case_id, vantage, "direct", queries=[
                f"{DNS_A_NAME}:A", f"{DNS_A_NAME}:AAAA",
                f"{DNS_AAAA_NAME}:AAAA", f"{DNS_AAAA_NAME}:A",
                f"{DNS_BOTH_NAME}:A", f"{DNS_BOTH_NAME}:AAAA",
                f"{DNS_ABSENT_NAME}:A", f"{DNS_TTL_NAME}:A",
            ])
            system = _dns_report(product, case_id, vantage, "system", names=[
                DNS_A_NAME, DNS_AAAA_NAME, DNS_BOTH_NAME, DNS_ABSENT_NAME, DNS_TTL_NAME,
            ])
            selection[role] = require_address_selection(
                case_id, role, direct, system, target_address,
            )
            selection[role]["nxdomain"] = require_nxdomain(case_id, role, direct, system)
            # The expiry half compares this resolution with the same name's later
            # one, so what is kept is the name's own entry, not the whole report.
            answers[role] = require_system_family(
                case_id, role, system, DNS_TTL_NAME, "inet", [target_address],
            )
            events = host.dns_queries()
            attribution[role] = {
                "source": vantage["source"],
                "resolver": resolution,
                "resolv_conf": (system.get("resolver") or {}).get("nameservers"),
                "a": require_fixture_attribution(
                    case_id, role, vantage["source"], events, DNS_A_NAME, "A", [target_address],
                ),
                "absent": require_fixture_attribution(
                    case_id, role, vantage["source"], events, DNS_ABSENT_NAME, "A", [],
                    rcode=RCODE_NXDOMAIN,
                ),
            }

        host.write_dns_zone(dns_case_zone(host, ttl_address=changed_address))
        for vantage in dns_vantages(host):
            role = vantage["role"]
            published = require_direct_answer(
                case_id, role,
                _dns_report(product, case_id, vantage, "direct", queries=[f"{DNS_TTL_NAME}:A"]),
                DNS_TTL_NAME, "A", [changed_address],
            )
            observed: Dict[str, Any] = {}

            def expired() -> bool:
                observed.clear()
                observed.update(_dns_report(
                    product, case_id, vantage, "system", names=[DNS_TTL_NAME],
                ))
                return list(_system_entry(observed, DNS_TTL_NAME).get("inet") or []) == [changed_address]

            expired_in_time = wait_until(
                expired, DNS_EXPIRY_DEADLINE_SECONDS,
                f"{case_id} {role} resolution of {DNS_TTL_NAME}",
                interval_seconds=DNS_EXPIRY_INTERVAL_SECONDS,
            )
            require(case_id, expired_in_time,
                    f"{role}: {DNS_TTL_NAME} never resolved to {changed_address} within "
                    f"{DNS_EXPIRY_DEADLINE_SECONDS}s after the zone changed")
            require(case_id, published.get("answers") == [changed_address],
                    f"{role}: the resolver published {published.get('answers')} for {DNS_TTL_NAME} "
                    f"instead of the changed record {[changed_address]}")
            expiry[role] = require_ttl_expiry(
                case_id, role, answers[role], _system_entry(observed, DNS_TTL_NAME),
                [target_address], [changed_address],
                DNS_EXPIRY_DEADLINE_SECONDS // DNS_EXPIRY_INTERVAL_SECONDS,
            )
            attribution[role]["ttl_after_change"] = require_fixture_attribution(
                case_id, role, vantage["source"], host.dns_queries(), DNS_TTL_NAME, "A",
                [changed_address],
            )

        host.write_dns_zone(dns_case_zone(
            host,
            behavior={"mode": "wrong", "overrides": {DNS_WRONG_NAME: {"A": [wrong_address]}}},
        ))
        for vantage in dns_vantages(host):
            role = vantage["role"]
            direct = _dns_report(
                product, case_id, vantage, "direct", queries=[f"{DNS_WRONG_NAME}:A"],
            )
            steered[role] = {"wrong": require_wrong_answer(case_id, role, direct, wrong_address)}
            steered[role]["wrong"]["attribution"] = require_fixture_attribution(
                case_id, role, vantage["source"], host.dns_queries(), DNS_WRONG_NAME, "A",
                [wrong_address], mode="wrong",
            )

        host.write_dns_zone(dns_case_zone(
            host,
            behavior={
                "mode": "stale", "ttl": DNS_CASE_TTL,
                "overrides": {DNS_STALE_NAME: {"A": [wrong_address]}},
            },
        ))
        for vantage in dns_vantages(host):
            role = vantage["role"]
            direct = _dns_report(
                product, case_id, vantage, "direct", queries=[f"{DNS_STALE_NAME}:A"],
            )
            steered[role]["stale"] = require_stale_answer(case_id, role, direct, wrong_address)
            steered[role]["stale"]["attribution"] = require_fixture_attribution(
                case_id, role, vantage["source"], host.dns_queries(), DNS_STALE_NAME, "A",
                [wrong_address], mode="stale",
            )
    except BaseException:
        _restore_dns_zone(host, base_zone)
        raise

    host.write_dns_zone(base_zone)
    restored: Dict[str, Any] = {}
    for vantage in dns_vantages(host):
        role = vantage["role"]
        direct = _dns_report(
            product, case_id, vantage, "direct",
            queries=[f"{topology.PANEL_DOMAIN}:A", f"{DNS_A_NAME}:A"],
        )
        restored[role] = {
            "panel_domain": require_direct_answer(
                case_id, role, direct, topology.PANEL_DOMAIN, "A", [target_address],
            ).get("answers"),
            "probe_name": require_direct_answer(
                case_id, role, direct, DNS_A_NAME, "A", [], rcode=RCODE_NXDOMAIN,
            ).get("rcode"),
        }

    return {
        "case": case_id,
        "zone": {"ttl": DNS_CASE_TTL, "suffix": DNS_SUFFIX, "resolver": resolution},
        "selection": selection,
        "expiry": expiry,
        "steered": steered,
        "restored": restored,
        "attribution": attribution,
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
        # The public certificate is read before the tree is reloaded, so a later
        # case's reload cannot be mistaken for a defect in what this one measured.
        Case(TLS_CASE_ID, "aio", lambda context: case_tls_surface(product),
             timeout_seconds=TLS_TIMEOUT_SECONDS),
        # The fixture resolver answers for every name the install and the renewal
        # trust, so what it publishes is measured before anything is asked to
        # rely on it; the case puts the installed zone back before it returns.
        Case(DNS_CASE_ID, "aio", lambda context: case_dns(product),
             timeout_seconds=DNS_CASE_TIMEOUT_SECONDS),
        # The configuration case only observes and reloads: it runs before any
        # traffic so a reload it caused can never be read as a data-plane fault.
        Case(NGX_CONFIG_CASE_ID, "aio", lambda context: case_nginx_config(product),
             timeout_seconds=NGX_CONFIG_TIMEOUT_SECONDS),
        # The renewal runs before any traffic for the same reason: it reloads
        # NGINX onto a fresh lineage, and a data-plane case must not be measured
        # across a reload this one caused.
        Case(ACME_CASE_ID, "aio", lambda context: case_acme_renewal(product),
             timeout_seconds=ACME_TIMEOUT_SECONDS),
        # The outage case renews twice more, so it also runs before any traffic:
        # each recovery reloads NGINX onto a fresh lineage.
        Case(ACME_OUTAGE_CASE_ID, "aio", lambda context: case_acme_outage(product),
             timeout_seconds=ACME_OUTAGE_TIMEOUT_SECONDS),
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
