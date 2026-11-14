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

import base64
import copy
import hashlib
import io
import ipaddress
import json
import os
import re
import shlex
import stat
import tarfile
import time
from pathlib import Path
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
# FW-03 asks the same question of the Master's own rule set that FW-01 asks of
# the Worker's: which origin reaches which port, proven by real connections.
MASTER_ACCESS_CASE_ID = "FW-03"
REVOCATION_CASE_ID = "MN-REVOKE"
OUTAGE_CASE_ID = "MN-OUTAGE"
RESTART_CASE_ID = "MN-RESTART"
VISION_CASE_ID = "MN-VISION"
SSH_KEY_CASE_ID = "MN-SSHKEY"
MATRIX_CASE_ID = "MN-MATRIX"
EGRESS_CASE_ID = "MN-EGRESS"
# One requirement, one case id: the AIO suite runs the same contract on its own
# host, and a cluster runs it on both roles.
NGINX_CONFIG_CASE_ID = aio.NGX_CONFIG_CASE_ID
# A cluster renders two decoys from two scripts, so the derivation that names
# them is asserted on both roles instead of on whichever one is cheaper to read.
COVER_DERIVE_CASE_ID = "NGX-COVER-DERIVE"
MTLS_TIMEOUT_SECONDS = 300
MATRIX_TIMEOUT_SECONDS = 120
EGRESS_TIMEOUT_SECONDS = 300
DENIAL_TIMEOUT_SECONDS = 300
# Every port the Master install's own rule set names, plus the panel vhost it
# never publishes: the operator's SSH port, the ACME/web pair, the local node
# port the All-in-One install isolates, and the loopback-only panel API.
FIREWALL_PORTS: Sequence[int] = (
    denial.SSH_PORT,
    denial.HTTP_PORT,
    denial.HTTPS_PORT,
    denial.NODE_PORT,
    denial.PANEL_API_PORT,
)
# A dropped packet has to be waited out and a refused one answers at once, so
# the attempt ceiling is what separates the two; the case ceiling covers every
# origin plus both readings of the rule set.
FIREWALL_ATTEMPT_TIMEOUT_SECONDS = 5
FIREWALL_TIMEOUT_SECONDS = 300
# FW-04 asks the same question through the other address family. The product
# decides from the kernel whether to publish IPv6 listeners and to mirror its
# rules onto ip6tables, so the run keeps one dual-stack role (the Master) and one
# IPv4-only role (the Worker) and reads both branches in a single run.
IPV6_CASE_ID = "FW-04"
IPV6_PUBLISHED_PORTS: Sequence[int] = (denial.SSH_PORT, denial.HTTP_PORT, denial.HTTPS_PORT)
IPV6_ATTEMPT_TIMEOUT_SECONDS = 5
IPV6_TIMEOUT_SECONDS = 300
# The cover case runs one function table and reads one vhost per role; the ceiling
# is a hang guard for those four `podman exec` calls, not a budget.
COVER_DERIVE_TIMEOUT_SECONDS = 180
# The camouflage apex is the last two labels of the deployment domain, so these
# are the answers the deployed decision has to produce. A domain with fewer than
# three labels has no subdomain to strip: the decoy has no apex of its own and
# the refusal is part of the contract instead of an empty render.
COVER_APEX_TABLE: Sequence[str] = (
    topology.PANEL_DOMAIN,
    "panel.sub.example.org",
    "example.com",
    "localhost",
    "",
)
COVER_APEX_ANSWERS = {
    topology.PANEL_DOMAIN: "testbed.internal",
    "panel.sub.example.org": "example.org",
    "example.com": "",
    "localhost": "",
    "": "",
}
# Both roles ship their own copy of one decision: the Master sources it from
# modules/nginx.sh, while the Worker's copy travels inside the payload streamed
# from gowave-node-auto.sh and is never written to its disk, so the file the
# payload was cut from is where that role's deployed text can be read.
COVER_DECISION_FUNCTIONS: Sequence[str] = (
    "derive_cover_domain", "cover_domains_not_resolving", "cover_domains_resolve_here",
    "cover_domain_for",
)
# One requirement, one case id: a cluster that refuses the apex has to leave no
# certificate, vhost or site claiming it, on either role.
COVER_UNRESOLVED_CASE_ID = "NGX-COVER-UNRESOLVED"
# The refusal case rewrites the fixture zone and runs the steered matrix on both
# roles, so its ceiling is a hang guard for those calls rather than a budget.
COVER_UNRESOLVED_TIMEOUT_SECONDS = 300
# Every probe steers the installed apex pair itself: the derived apex is fixed by
# the zone's own name, so a probe domain cannot carry an apex of its own.
COVER_FLUSH_SCRIPT = (
    "resolvectl flush-caches >/dev/null 2>&1 || "
    "systemd-resolve --flush-caches >/dev/null 2>&1 || true\n"
)
# The fixture reloads its zone on a poll and the resolver caches what it already
# answered, so a probe waits for the steered answers to be live before it reads.
COVER_PROBE_SETTLE_ATTEMPTS = 50
COVER_PROBE_SETTLE_SECONDS = "0.2"
COVER_SITE_INDEX = "/var/www/gowave-auto-nginx/cover-reality/index.html"
# The site the apex serves is measured as one tree: these are the documents the
# template ships, and the paths NGINX resolves each one from.
COVER_SITE_CASE_ID = "NGX-COVER-SITE"
# The site case reads one rendered tree and fetches each page and asset once, so
# its budget covers those fetches; a single fetch is only bounded against a hang.
COVER_SITE_TIMEOUT_SECONDS = 300
COVER_SITE_PROBE_TIMEOUT_SECONDS = 30
COVER_SITE_ROOT = "/var/www/gowave-auto-nginx/cover-reality"
COVER_SITE_DOCUMENTS: Sequence[str] = (
    "index.html", "404.html", "product/index.html", "demo/index.html",
    "guides/index.html", "principles/index.html",
)
COVER_SITE_PAGES: Sequence[str] = (
    "/", "/index.html", "/product/", "/demo/", "/guides/", "/principles/", "/404.html",
)
# What NGINX's own mime table answers for each asset kind the template ships.
COVER_SITE_ASSET_TYPES: Dict[str, str] = {
    ".html": "text/html",
    ".css": "text/css",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".js": "application/javascript",
}
# A camouflage page may say the word "API" in prose, but it must never carry the
# panel's routes or the management addresses a scanner tries next.
COVER_SITE_LEAKS: Sequence[str] = (
    "/api", "127.0.0.1", "9443", "9444", "panel", "gowave", "xhttp", "trojan",
    "server-status", "/metrics",
)
COVER_VHOST_DIRS: Sequence[str] = ("/etc/nginx/sites-enabled", "/etc/nginx/conf.d")
# The decoy is only reachable through a loopback listener, so the route case
# reads the stream map and that socket's bindings instead of the public surface.
DECOY_ROUTE_CASE_ID = "NGX-DECOY-ROUTE"
DECOY_ROUTE_TIMEOUT_SECONDS = 300
DECOY_LISTENER_PORT = 9443
# The product's own local ports, in the stream map's own numbering: the panel
# vhost, the REALITY and Vision inbounds, and the camouflage decoy.
DECOY_ROUTE_BACKENDS: Dict[str, int] = {"panel": 7443, "reality": 8443, "vision": 8444}
# A refused connection answers at once and a filtered one has to be waited out,
# so each attempt from a client network is bounded by its own short timeout.
DECOY_ROUTE_PATH_TIMEOUT_SECONDS = 5
# The ACME vhost on port 80 is what certbot's HTTP-01 renewal revalidates
# through, so it has to outlive a Worker re-provision and a domain change.
ACME80_CASE_ID = "NGX-WORKER-ACME80"
ACME80_TIMEOUT_SECONDS = 900
# A Worker re-provision re-streams the whole payload, and the domain change
# re-issues two lineages, so each half is bounded on its own.
ACME80_REAPPLY_TIMEOUT_SECONDS = 540
ACME80_DOMAIN_CHANGE_TIMEOUT_SECONDS = 420
ACME_WEBROOT = "/var/www/gowave-acme"
ACME_MASTER_VHOST = "/etc/nginx/conf.d/gowave-http.conf"
ACME_WORKER_VHOST = "/etc/nginx/conf.d/00-worker-acme-challenge.conf"
ACME_CHALLENGE_DIR = "/.well-known/acme-challenge"
# The token is the whole file: a 404, the redirect, or the decoy page all hash
# differently, so a served challenge cannot be mistaken for any of them.
ACME_CHALLENGE_TOKEN = "gowave-e2e-http01-token"
# The names the domain change installs, inside the fixture's own zone so the
# product's resolution precondition and certbot's HTTP-01 both still hold.
ACME_NEW_PANEL_DOMAIN = "panel2.testbed.internal"
ACME_NEW_REALITY_DOMAIN = "reality2.testbed.internal"
# Both archive types are separate contracts and both are unencrypted and
# secret-bearing, so this case records what each archive carries -- member paths,
# declared checksums, environment key names and where private keys sit -- and
# never reads out a value the archive protects.
BACKUP_CASE_ID = "MN-BACKUP"
BACKUP_TIMEOUT_SECONDS = 600
BACKUP_READ_TIMEOUT_SECONDS = 180
# One archive type per role, because that is the role each one restores.
BACKUP_TYPES: Dict[str, str] = {"master": "panel", "worker": "node"}
# A Panel archive is the Panel, not the host: the database, the environment, the
# installation state, the managed NGINX tree and the lineages it renews.
BACKUP_PANEL_REQUIRED_PATHS = (
    "opt/gowave/gowave.db",
    "opt/gowave/.env",
    "var/lib/gowave-auto-nginx/state.json",
)
BACKUP_PANEL_REQUIRED_PREFIXES = (
    "etc/nginx/conf.d/gowave-",
    "etc/nginx/stream-enabled/gowave-",
    "etc/letsencrypt/live/",
    "etc/letsencrypt/archive/",
    "etc/letsencrypt/renewal/",
)
# The Worker archive is its `.env` credentials only; it is not a system image and
# it does not carry the Panel's database.
BACKUP_NODE_PATHS = ("opt/gowave-node/.env",)
# The key whose presence makes each archive secret-bearing. Only the name is read.
BACKUP_SECRET_KEYS: Dict[str, str] = {"panel": "APP_SECRET", "node": "SECRET_KEY"}
# A restore is only proven by what it undoes: this case creates a client and a
# Worker environment edit, backs the role up, destroys both, and asks the
# product's own restore to bring them back byte for byte.
RESTORE_CASE_ID = "MN-RESTORE"
RESTORE_CASE_TIMEOUT_SECONDS = 1800
RESTORE_STEP_TIMEOUT_SECONDS = 240
RESTORE_COMMAND_TIMEOUT_SECONDS = 300
# The marker an injected Worker environment edit leaves behind. It names nothing
# the node reads, so the running node is undisturbed until the restore replaces
# the file.
RESTORE_SENTINEL_KEY = "GOWAVE_E2E_RESTORE_SENTINEL"
RESTORE_NODE_ENV = "/opt/gowave-node/.env"
# The archives are unencrypted, so they live on a run-owned volume: the case
# proves the directory is that volume and that no archive reaches an artifact.
BACKUP_VOLUME_CASE_ID = "MN-BACKUP-VOL"
BACKUP_VOLUME_TIMEOUT_SECONDS = 600
# An archive keeps the product's own 0600 file mode; the volume around it is
# root-only, because the payloads inside are readable by whoever reads the file.
BACKUP_VOLUME_DIRECTORY_MODE = "700"
# Nothing an artifact may contain: an archive is gzip, a private key announces
# itself, and a secret-bearing variable is written as a name plus a value.
ARTIFACT_FORBIDDEN_MARKERS = ("BEGIN PRIVATE KEY", "SECRET_KEY=", "APP_SECRET=")
ARTIFACT_ARCHIVE_SUFFIXES = (".tar", ".tar.gz", ".tgz")
# A restore refuses an archive it cannot honour -- and refuses it before it stops
# a service, takes a snapshot or writes a single live file.
REJECT_CASE_ID = "MN-BACKUP-BAD"
REJECT_CASE_TIMEOUT_SECONDS = 1800
REJECT_COMMAND_TIMEOUT_SECONDS = 300
# Each variant breaks exactly one promise of the format, so the case can name
# the promise that was broken rather than "some error happened".
REJECT_VARIANTS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("truncated", ("not a readable Format v1 tar.gz", "could not be read back")),
    ("garbage", ("not a readable Format v1 tar.gz",)),
    ("checksum", ("Checksum mismatch for member opt/gowave/.env",)),
    ("incomplete", ("Missing archive member declared in meta.json: opt/gowave/.env",)),
    ("no-database", ("missing its required member: opt/gowave/gowave.db",)),
    ("wrong-type", ("Backup type mismatch",)),
)
CLUSTER_TIMEOUT_SECONDS = 300
WORKER_STATE_TIMEOUT_SECONDS = 300
VISION_PROBE_TIMEOUT_SECONDS = 120
SSH_TRUST_TIMEOUT_SECONDS = 240
# The transaction id only has to satisfy the product's own format; it names a
# leftover snapshot the case plants on the Worker to observe a remote effect.
SSH_ROTATION_TX_ID = "worker_install_sshkey_rotation"
# The Worker's SSH daemon is what the controller speaks to; the node itself is a
# unit and a control port, so the two can be faulted separately.
SSH_DOWN_CASE_ID = "MN-SSH-DOWN"
SSH_UNIT = "ssh.service"
# Ubuntu 24.04 ships socket activation alongside the daemon: `ssh.socket` owns
# port 22 and starts an `ssh@…service` instance per connection, so stopping the
# service alone leaves the port answering and prints that its triggering unit is
# still active. Both units are the fault; neither is the node.
SSH_SOCKET_UNIT = "ssh.socket"
SSH_DOWN_TX_ID = "worker_install_sshdown"
SSH_DOWN_TIMEOUT_SECONDS = 900
# OpenSSH names the reason it never reached a listener; each of these is a
# transport failure rather than the host-key verification SSHKEY measures.
SSH_CONNECT_FAILURES: Tuple[str, ...] = (
    "ssh: connect to host",
    "Connection refused",
    "Connection timed out",
    "No route to host",
    "Network is unreachable",
)
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
# The configuration contract runs three probes per role and, on restore, waits
# for that role's master to replace its workers.
NGX_CONFIG_CASE_TIMEOUT_SECONDS = 2 * aio.NGX_CONFIG_TIMEOUT_SECONDS
# The public certificate contract costs four client handshakes per role, and a
# cluster has two roles with two independent lineages.
TLS_CASE_TIMEOUT_SECONDS = 2 * aio.TLS_TIMEOUT_SECONDS

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


def case_ssh_service_down(product: MultiNodeProduct) -> Dict[str, Any]:
    """MN-SSH-DOWN: a Worker whose sshd is down is still a node, and comes back.

    Everything the operator does to a Worker travels over OpenSSH, so losing the
    daemon must stop those operations before they act — and it must stop nothing
    else: the node keeps its unit and keeps carrying payload, because the control
    plane and the data plane never used that port. The fault is both units that
    can answer on 22, ``ssh.socket`` and ``ssh.service``: stopping the service
    alone leaves the socket activating a daemon on the next connection.

    The observation is the same one SSHKEY uses: the controller's remote-finalize
    operation deletes a leftover ACME snapshot on the Worker, so a refused
    connection and an executed command leave different evidence. The case restores
    the unit in a ``finally`` and then repeats the very operation that was
    refused, which is what separates "the daemon came back" from "the host is
    still unreachable".
    """
    host = product.require_installed()
    worker_ip = host.plan.worker_ip
    transaction = f"/var/lib/gowave-auto-nginx/recovery/{SSH_DOWN_TX_ID}"
    sentinel = f"{transaction}/sentinel"
    known_hosts = "/root/.ssh/known_hosts"
    finalized = "Worker ACME recovery snapshot finalized."

    def snapshot_present() -> bool:
        return product.podman.exec(
            host.worker_name, ["test", "-f", sentinel], check=False,
        ).returncode == 0

    def ssh_state(action: str) -> Dict[str, Any]:
        # The socket goes first on the way down: while it is active it would
        # start a fresh per-connection daemon, and on the way back up it is the
        # listener a client actually reaches.
        result = product.podman.exec_bash(
            host.worker_name,
            f"systemctl {action} {SSH_SOCKET_UNIT} </dev/null >/dev/null 2>&1 || true\n"
            f"systemctl {action} {SSH_UNIT} </dev/null >/dev/null 2>&1 || true\n"
            f"echo \"service=$(systemctl is-active {SSH_UNIT} 2>/dev/null || true)\"\n"
            f"echo \"socket=$(systemctl is-active {SSH_SOCKET_UNIT} 2>/dev/null || true)\"\n",
            check=False, timeout=120,
        )
        fields: Dict[str, str] = {}
        for line in (result.stdout or "").splitlines():
            key, separator, value = line.strip().partition("=")
            if separator:
                fields[key.strip()] = value.strip()
        return {
            "action": action,
            "service": fields.get("service", ""),
            "socket": fields.get("socket", ""),
            "detail": (result.stderr or "").strip()[-400:],
        }

    prepared = product.podman.exec_bash(host.worker_name, f"""
set -eu
umask 077
install -d -m 0700 {shlex.quote(transaction)}
: > {shlex.quote(sentinel)}
test -f {shlex.quote(sentinel)}
""", check=False, timeout=120)
    require(
        SSH_DOWN_CASE_ID,
        prepared.returncode == 0 and snapshot_present(),
        f"planting the Worker's leftover ACME snapshot exited {prepared.returncode}: "
        f"{(prepared.stderr or '').strip()[-500:]}",
    )

    product.master.subscription_payloads(SSH_DOWN_CASE_ID)
    inbound, client = product.worker_tuple()
    baseline = product.node_transfer(
        SSH_DOWN_CASE_ID, "worker", inbound, client, expect_refusal=True,
    )
    require(
        SSH_DOWN_CASE_ID,
        baseline.get("delivered")
        and baseline.get("status") == 200
        and baseline.get("request_id_match")
        and baseline.get("body_match"),
        f"the Worker never carried a payload before its sshd was stopped, so the "
        f"degraded state would not be attributable to the fault: "
        f"{baseline.get('reason', '')}",
    )
    require(
        SSH_DOWN_CASE_ID,
        baseline.get("source_ip") == host.plan.data_worker_ip,
        f"the baseline payload left from {baseline.get('source_ip')!r} instead of the "
        f"Worker's own data address {host.plan.data_worker_ip}",
    )

    stopped = ssh_state("stop")
    require(
        SSH_DOWN_CASE_ID,
        stopped.get("service") != "active" and stopped.get("socket") != "active",
        f"the Worker still answers for SSH after `systemctl stop {SSH_SOCKET_UNIT} {SSH_UNIT}`: "
        f"{SSH_UNIT}={stopped.get('service')!r} {SSH_SOCKET_UNIT}={stopped.get('socket')!r} "
        f"({stopped.get('detail') or 'no output'})",
    )

    refused: Dict[str, Any] = {}
    during: Dict[str, Any] = {}
    unit_during = ""
    refused_survived = True
    started: Dict[str, Any] = {}
    try:
        refused = product.remote_finalize(known_hosts, SSH_DOWN_TX_ID)
        refused_output = (refused.stdout or "") + (refused.stderr or "")
        refused_survived = snapshot_present()
        unit_during = (product.podman.exec_bash(
            host.worker_name, f"systemctl is-active {WORKER_UNIT} || true",
            check=False, timeout=60,
        ).stdout or "").strip()
        during = product.node_transfer(
            SSH_DOWN_CASE_ID, "worker", inbound, client, expect_refusal=True,
        )

        require(
            SSH_DOWN_CASE_ID,
            refused.returncode != 0,
            f"the controller's remote operation exited 0 while the Worker's "
            f"{SSH_SOCKET_UNIT} and {SSH_UNIT} were stopped: "
            f"{refused_output.strip()[-800:]}",
        )
        require(
            SSH_DOWN_CASE_ID,
            any(marker in refused_output for marker in SSH_CONNECT_FAILURES),
            f"the refused operation did not name a connection failure: "
            f"{refused_output.strip()[-800:]!r}",
        )
        # A host-key failure here would mean sshd answered after all, so the
        # refusal would be about the pin rather than about the daemon.
        require(
            SSH_DOWN_CASE_ID,
            "Host key verification failed" not in refused_output,
            f"the operation was refused by host-key verification, so a daemon was still "
            f"answering on 22: {refused_output.strip()[-800:]!r}",
        )
        require(
            SSH_DOWN_CASE_ID,
            finalized not in refused_output and refused_survived,
            f"the remote script ran although the Worker's sshd was stopped: "
            f"{refused_output.strip()[-800:]!r}",
        )
        require(
            SSH_DOWN_CASE_ID,
            unit_during == "active",
            f"{WORKER_UNIT} is {unit_during!r} on the Worker whose SSH was stopped, "
            "so losing SSH took the node with it",
        )
        require(
            SSH_DOWN_CASE_ID,
            during.get("delivered") is True
            and during.get("status") == 200
            and during.get("request_id_match")
            and during.get("body_match"),
            f"the Worker stopped carrying payload while only its sshd was down "
            f"(status {during.get('status')!r}): {during.get('reason', '')}",
        )
        require(
            SSH_DOWN_CASE_ID,
            during.get("source_ip") == host.plan.data_worker_ip,
            f"the payload during the fault left from {during.get('source_ip')!r} instead of "
            f"the Worker's data address {host.plan.data_worker_ip}",
        )
    finally:
        # The controller needs this daemon back whatever the checks above decided.
        started = ssh_state("start")

    require(
        SSH_DOWN_CASE_ID,
        started.get("service") == "active",
        f"`systemctl start {SSH_SOCKET_UNIT} {SSH_UNIT}` left the Worker's daemon "
        f"{started.get('service')!r} with its socket {started.get('socket')!r}: "
        f"{started.get('detail') or 'no output'}",
    )

    recovered = product.remote_finalize(known_hosts, SSH_DOWN_TX_ID)
    recovered_output = (recovered.stdout or "") + (recovered.stderr or "")
    recovered_survived = snapshot_present()
    require(
        SSH_DOWN_CASE_ID,
        recovered.returncode == 0,
        f"the same operation was still refused after {SSH_UNIT} was started: "
        f"{recovered_output.strip()[-800:]}",
    )
    require(
        SSH_DOWN_CASE_ID,
        finalized in recovered_output and not recovered_survived,
        f"the operation reported success without removing the planted snapshot {sentinel}: "
        f"{recovered_output.strip()[-800:]!r}",
    )

    return {
        "worker_ip": worker_ip,
        "ssh_unit_after_stop": stopped.get("service"),
        "ssh_socket_after_stop": stopped.get("socket"),
        "ssh_unit_after_start": started.get("service"),
        "ssh_socket_after_start": started.get("socket"),
        "refused_returncode": refused.returncode,
        "refusal_names_transport": str(
            any(marker in ((refused.stdout or "") + (refused.stderr or ""))
                for marker in SSH_CONNECT_FAILURES)
        ).lower(),
        "remote_effect_during_fault": str(not refused_survived).lower(),
        "worker_unit_with_sshd_down": unit_during,
        "worker_status_with_sshd_down": during.get("status"),
        "worker_source_ip_with_sshd_down": during.get("source_ip"),
        "recovered_returncode": recovered.returncode,
        "remote_effect_after_restore": str(not recovered_survived).lower(),
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


# The three vantages the Master can be reached from, named once because the
# contract, the failure messages and the evidence all quote them.
ORIGIN_CONTROL_MACHINE = "the Control Machine"
ORIGIN_PUBLISHED = "the published address"
ORIGIN_LOCAL = "the host itself"


def firewall_origins(plan: Any) -> List[Dict[str, Any]]:
    """Every origin the Master can be reached from, and what each one tries.

    Three vantages, none of them invented: the Control Machine on the run
    network (what the operator's own machine sees), the published address block
    the data plane leaves from (an address the product publishes, which must not
    widen its rule set), and the host itself, whose loopback is the only place
    the management ports listen.

    The external vantages try the isolated node port as well as the published
    ones, because that port is the one the install decides about. The denial
    suite's untrusted role is not one of them: it runs the clean target image,
    which has no Python, so it cannot report a multi-path probe — its vantage is
    the Worker's control plane, which FW-01 and FW-02 measure.
    """
    return [
        {
            "name": ORIGIN_CONTROL_MACHINE,
            "container": "client",
            "address": plan.target_ip,
            "attempts": (
                {"label": "operator-ssh", "port": denial.SSH_PORT, "banner": True},
                {"label": "node", "port": denial.NODE_PORT},
                {"label": "panel-api", "port": denial.PANEL_API_PORT},
            ),
        },
        {
            "name": ORIGIN_PUBLISHED,
            "container": "echo",
            "address": plan.data_target_ip,
            "attempts": (
                {"label": "https", "port": denial.HTTPS_PORT},
                {"label": "node", "port": denial.NODE_PORT},
            ),
        },
        {
            "name": ORIGIN_LOCAL,
            "container": "target",
            "address": "127.0.0.1",
            "attempts": (
                {"label": "https", "port": denial.HTTPS_PORT},
                {"label": "node", "port": denial.NODE_PORT},
                {"label": "panel-api", "port": denial.PANEL_API_PORT},
            ),
        },
    ]


def master_access_facts(product: MultiNodeProduct, case_id: str) -> Dict[str, Any]:
    """The Master's rule set read twice around real connections from every origin."""
    host = product.require_installed()
    containers = {
        "client": host.client_name,
        "echo": host.echo_name,
        "target": host.target_name,
    }
    origins = firewall_origins(host.plan)
    before = denial.host_firewall(product.podman, host.target_name, FIREWALL_PORTS)
    require(
        case_id,
        before.get("chain_returncode") == 0,
        f"the Master's rules could not be read (exit {before.get('chain_returncode')}): "
        f"{before.get('error') or before.get('detail') or 'no output'}",
    )

    observed: Dict[str, Any] = {}
    for origin in origins:
        attempts = [
            dict(
                attempt,
                address=origin["address"],
                timeout=FIREWALL_ATTEMPT_TIMEOUT_SECONDS,
            )
            for attempt in origin["attempts"]
        ]
        report = denial.tcp_paths(product.podman, containers[origin["container"]], attempts)
        require(
            case_id,
            any(key not in ("returncode", "detail") for key in report),
            f"the probe from {origin['name']} produced no report (exit "
            f"{report.get('returncode')}): {report.get('detail') or 'no output'}",
        )
        observed[origin["name"]] = report

    cover = topology.COVER_APEX
    https = host.client_http(
        f"https://{cover}/", expect_status=200,
        timeout=FIREWALL_ATTEMPT_TIMEOUT_SECONDS + 10,
    )
    http = host.client_http(
        f"http://{cover}/", expect_status=301,
        timeout=FIREWALL_ATTEMPT_TIMEOUT_SECONDS + 10,
    )
    after = denial.host_firewall(product.podman, host.target_name, FIREWALL_PORTS)
    return {
        "before": before,
        "after": after,
        "origins": observed,
        "https": https,
        "http": http,
        "cover": cover,
        "addresses": {origin["name"]: origin["address"] for origin in origins},
    }


def _master_access_path(
    origin: str, label: str, report: Dict[str, Any], case_id: str,
) -> Dict[str, Any]:
    """One origin's attempt, named when the probe never reported it."""
    entry = report.get(label)
    require(
        case_id,
        isinstance(entry, dict),
        f"the {origin} probe reported nothing for {label!r}; it observed "
        f"{sorted(key for key in report if key not in ('returncode', 'detail'))}",
    )
    return entry


def master_access_contract(facts: Dict[str, Any], case_id: str) -> Dict[str, Any]:
    """The Master's rule set, its counters, and what each origin actually got.

    The refusals are never read alone. A refused connection says the packet was
    answered with a reset, a silent one says it was dropped, and only the rule
    that counted the packet says the host's own policy did it — so every denial
    is paired with the loopback path to the same port (the service is up), the
    rule the install wrote for it, and the packet counter that moved while this
    case ran. Nothing here reads the Worker: its rules say nothing about the
    Master's.
    """
    before, after = facts["before"], facts["after"]
    require(
        case_id,
        before["active"],
        "the Master's UFW is not active, so nothing filters the ports the install publishes",
    )
    require(
        case_id,
        before["default_incoming"] == "deny",
        f"the Master's UFW default incoming policy is "
        f"{before['default_incoming'] or 'unset'!r} instead of deny",
    )
    require(
        case_id,
        before["input_policy"] == "DROP",
        f"the Master's INPUT policy is {before['input_policy'] or 'unset'!r} instead of DROP",
    )

    for port in (denial.SSH_PORT, denial.HTTP_PORT, denial.HTTPS_PORT):
        require(
            case_id,
            denial.open_to_every_source(before, port),
            f"port {port} is not open to every source, so the Master does not serve the internet "
            f"on it: {[entry['line'] for entry in before['allows'][port]]}",
        )
    require(
        case_id,
        not before["allows"][denial.NODE_PORT],
        f"the local node port {denial.NODE_PORT} carries an ACCEPT rule, so it is published: "
        f"{[entry['line'] for entry in before['allows'][denial.NODE_PORT]]}",
    )
    require(
        case_id,
        before["blocks"][denial.NODE_PORT],
        f"the local node port {denial.NODE_PORT} carves out no block rule, so its isolation is "
        "the default policy alone rather than a decision about that port",
    )
    require(
        case_id,
        not before["allows"][denial.PANEL_API_PORT],
        f"the panel API port {denial.PANEL_API_PORT} carries an ACCEPT rule, so it is published: "
        f"{[entry['line'] for entry in before['allows'][denial.PANEL_API_PORT]]}",
    )
    require(
        case_id,
        not before["blocks"][denial.PANEL_API_PORT],
        f"the panel API port {denial.PANEL_API_PORT} is blocked by its own rule, which would hide "
        "whether the default policy reaches it: "
        f"{[entry['line'] for entry in before['blocks'][denial.PANEL_API_PORT]]}",
    )
    panel_listeners = before["listeners"][denial.PANEL_API_PORT]
    require(
        case_id,
        panel_listeners,
        f"nothing listens on {denial.PANEL_API_PORT} on the Master, so the loopback control below "
        "has no socket behind it",
    )
    require(
        case_id,
        not [address for address in panel_listeners if address in denial.WILDCARD_ADDRESSES],
        f"the panel API listens on {panel_listeners}, which is not loopback only",
    )

    control = facts["origins"][ORIGIN_CONTROL_MACHINE]
    ssh = _master_access_path("Control Machine", "operator-ssh", control, case_id)
    require(
        case_id,
        ssh["outcome"] == "CONNECTED",
        f"SSH from the Control Machine ended {ssh['outcome'] or 'without a verdict'} "
        f"({ssh['detail'] or 'no detail'}), so the Master is not administrable from outside",
    )
    require(
        case_id,
        str(ssh.get("banner") or "").startswith("SSH-2.0-"),
        f"the SSH port answered {ssh.get('banner')!r} instead of an SSH identification",
    )

    https = facts["https"]
    https_probe = https.get("probe") or {}
    require(
        case_id,
        https.get("returncode") == 0,
        f"https://{facts['cover']}/ from the Control Machine did not answer 200: "
        f"{https_probe.get('error') or https.get('stderr') or 'the probe printed no report'}",
    )
    require(
        case_id,
        str((https_probe.get("peer") or {}).get("tls_version", "")).startswith("TLSv1.3"),
        f"https://{facts['cover']}/ negotiated "
        f"{(https_probe.get('peer') or {}).get('tls_version')!r} instead of TLSv1.3",
    )

    http = facts["http"]
    http_probe = http.get("probe") or {}
    require(
        case_id,
        http.get("returncode") == 0,
        f"http://{facts['cover']}/ from the Control Machine did not answer 301: "
        f"{http_probe.get('error') or http.get('stderr') or 'the probe printed no report'}",
    )
    location = str((http_probe.get("headers") or {}).get("location") or "")
    require(
        case_id,
        location.startswith("https://"),
        f"the plaintext vhost answered 301 without an https Location: {location!r}",
    )

    node = _master_access_path("Control Machine", "node", control, case_id)
    require(
        case_id,
        node["outcome"] != "CONNECTED",
        f"the Control Machine reached the local node port {denial.NODE_PORT} at "
        f"{node['address']}, so the port the All-in-One install isolates is published",
    )
    require(
        case_id,
        node["outcome"] in ("REFUSED", "TIMEOUT"),
        f"the Control Machine's attempt on the node port ended "
        f"{node['outcome'] or 'without a verdict'} ({node['detail'] or 'no detail'}), which is "
        "neither a rule nor a dropped packet",
    )

    panel = _master_access_path("Control Machine", "panel-api", control, case_id)
    require(
        case_id,
        panel["outcome"] == "TIMEOUT",
        f"the Control Machine's attempt on the panel API port {denial.PANEL_API_PORT} ended "
        f"{panel['outcome'] or 'without a verdict'}: an answered port publishes the management "
        "interface, and a refusal would mean the port has no socket on that address rather than "
        "the default policy dropping the packet",
    )

    published = facts["origins"][ORIGIN_PUBLISHED]
    served = _master_access_path("the published address", "https", published, case_id)
    require(
        case_id,
        served["outcome"] == "CONNECTED",
        f"the published address {served['address']} could not reach the HTTPS port "
        f"({served['outcome'] or 'without a verdict'}): {served['detail'] or 'no detail'}",
    )
    withheld = _master_access_path("the published address", "node", published, case_id)
    require(
        case_id,
        withheld["outcome"] != "CONNECTED",
        f"the published address {withheld['address']} reached the local node port "
        f"{denial.NODE_PORT}, so publishing the address widened the rule set",
    )

    local = facts["origins"][ORIGIN_LOCAL]
    for label, port in (
        ("https", denial.HTTPS_PORT),
        ("node", denial.NODE_PORT),
        ("panel-api", denial.PANEL_API_PORT),
    ):
        entry = _master_access_path("host", label, local, case_id)
        require(
            case_id,
            entry["outcome"] == "CONNECTED",
            f"the Master could not reach {label} on {port} over loopback "
            f"({entry['outcome'] or 'without a verdict'}): {entry['detail'] or 'no detail'}; the "
            "refusals above would then say the service is down, not that the source was denied",
        )

    moved: Dict[int, int] = {}
    for port in (denial.SSH_PORT, denial.HTTP_PORT, denial.HTTPS_PORT, denial.NODE_PORT):
        before_packets = denial.packets_for(before, port)
        after_packets = denial.packets_for(after, port)
        moved[port] = after_packets - before_packets
        require(
            case_id,
            after_packets > before_packets,
            f"the Master's rule for port {port} counted no packet while this case ran "
            f"({before_packets} -> {after_packets}), so the attempts above did not traverse the "
            "rule set the install wrote",
        )
    policy_moved: Optional[int] = None
    before_policy = before.get("input_policy_packets")
    after_policy = after.get("input_policy_packets")
    if isinstance(before_policy, int) and isinstance(after_policy, int):
        policy_moved = after_policy - before_policy
        require(
            case_id,
            after_policy > before_policy,
            f"the INPUT policy counted no dropped packet while the panel API port was probed from "
            f"the Control Machine ({before_policy} -> {after_policy})",
        )

    return {
        "input_policy": before["input_policy"],
        "default_incoming": before["default_incoming"],
        "allows": {
            str(port): [entry["line"] for entry in before["allows"][port]]
            for port in FIREWALL_PORTS
        },
        "blocks": {
            str(port): [entry["line"] for entry in before["blocks"][port]]
            for port in FIREWALL_PORTS
        },
        "listeners": {str(port): before["listeners"][port] for port in FIREWALL_PORTS},
        "addresses": facts["addresses"],
        "origins": {
            name: {
                label: {
                    "address": entry.get("address"),
                    "port": entry.get("port"),
                    "outcome": entry.get("outcome"),
                    "elapsed_ms": entry.get("elapsed_ms"),
                    "banner": entry.get("banner"),
                }
                for label, entry in report.items()
                if isinstance(entry, dict)
            }
            for name, report in facts["origins"].items()
        },
        "https_status": https_probe.get("status"),
        "https_tls_version": (https_probe.get("peer") or {}).get("tls_version"),
        "http_status": http_probe.get("status"),
        "http_location": location,
        "packets_moved": {str(port): count for port, count in moved.items()},
        "input_policy_packets_moved": policy_moved,
    }


def case_master_access(product: MultiNodeProduct) -> Dict[str, Any]:
    """FW-03: the Master allows and denies the declared paths, from every origin.

    The Master's own install writes one rule set for the whole host: the
    operator's SSH port, the ACME and HTTPS pair and the default incoming
    policy, plus a block rule for the local node port, which only the Panel
    reaches over loopback. A refusal seen from one place proves nothing about
    that policy — a stopped service, a port that was never bound, and a dropped
    packet all look refused from far away — so the case attempts every path with
    a real TCP connection from the Control Machine, from the run's published
    address, and from the host itself, and requires the Master's rule counters
    to have counted those attempts.
    """
    return master_access_contract(
        master_access_facts(product, MASTER_ACCESS_CASE_ID), MASTER_ACCESS_CASE_ID,
    )


def ipv6_facts(product: MultiNodeProduct, case_id: str) -> Dict[str, Any]:
    """Both roles' IPv6 declarations, and what the Master's v6 sockets answer.

    The Master runs with its IPv6 stack switched on, the Worker without one, and
    the product was installed on both after that was settled — so each role's own
    surfaces say which branch its install took. The Master's v6 sockets are then
    dialled for real from the host itself: an internal port that answers there is
    published, and one that is refused has no v6 socket at all, which is a
    different observation from a packet the v6 rules dropped.
    """
    host = product.require_worker()
    ports = FIREWALL_PORTS
    master = denial.host_firewall(product.podman, host.target_name, ports)
    require(
        case_id,
        master.get("chain_returncode") == 0,
        f"the Master's IPv4 rules could not be read (exit {master.get('chain_returncode')}): "
        f"{master.get('error') or master.get('detail') or 'no output'}",
    )
    worker = denial.host_firewall(product.podman, host.worker_name, ports)
    require(
        case_id,
        worker.get("chain_returncode") == 0,
        f"the Worker's IPv4 rules could not be read (exit {worker.get('chain_returncode')}): "
        f"{worker.get('error') or worker.get('detail') or 'no output'}",
    )

    address = host.ipv6_address
    require(
        case_id,
        bool(address),
        "the Master never received an IPv6 address, so this run cannot exercise the product's "
        "enabled branch and would pass by inspecting the disabled one twice",
    )
    attempts = [
        {
            "label": label,
            "address": address,
            "port": port,
            "timeout": IPV6_ATTEMPT_TIMEOUT_SECONDS,
        }
        for label, port in (
            ("https", denial.HTTPS_PORT),
            ("http", denial.HTTP_PORT),
            ("node", denial.NODE_PORT),
            ("panel-api", denial.PANEL_API_PORT),
        )
    ]
    master_paths = denial.tcp_paths(product.podman, host.target_name, attempts)
    require(
        case_id,
        any(key not in ("returncode", "detail") for key in master_paths),
        f"the Master's IPv6 probe produced no report (exit {master_paths.get('returncode')}): "
        f"{master_paths.get('detail') or 'no output'}",
    )
    worker_paths = denial.tcp_paths(
        product.podman,
        host.worker_name,
        [{
            "label": "ssh-port",
            "address": "::1",
            "port": denial.SSH_PORT,
            "timeout": IPV6_ATTEMPT_TIMEOUT_SECONDS,
        }],
    )
    require(
        case_id,
        any(key not in ("returncode", "detail") for key in worker_paths),
        f"the Worker's IPv6 probe produced no report (exit {worker_paths.get('returncode')}): "
        f"{worker_paths.get('detail') or 'no output'}",
    )
    return {
        "master": master,
        "worker": worker,
        "address": address,
        "master_paths": master_paths,
        "worker_paths": worker_paths,
        # Whatever the case proves, it cannot prove this: the run network is
        # IPv4-only, so there is no IPv6 origin to probe from and no AAAA record
        # to route. Saying so in the evidence is cheaper than letting a reader
        # assume the Control Machine half was measured.
        "limitation": {
            "status": "NOT_APPLICABLE",
            "reason": (
                "the run network carries IPv4 only, so no IPv6 origin and no AAAA routing exist "
                "for the Control Machine probe; a real external IPv6 source is live-only. The "
                "remaining v6 attempts are self-connects from the Master itself, which "
                "ufw-before-input accepts on `-i lo` before any user rule runs: they can show "
                "that a socket exists, never that other peers could reach it"
            ),
        },
    }


def ipv6_contract(facts: Dict[str, Any], case_id: str) -> Dict[str, Any]:
    """Each role's branch, read back from the surfaces the product writes.

    The Master is the dual-stack host: its kernel has an address, so the install
    must declare ``IPV6=yes``, mirror the same allow/deny decisions onto the v6
    chain, and publish ``[::]`` listeners for exactly the ports it publishes on
    IPv4. The Worker is the IPv4-only host: no address, ``IPV6=no``, no v6 chain,
    no ``[::]`` listener — and its IPv4 rule set is unchanged, which is what makes
    the branch a decision rather than a side effect.
    """
    master, worker = facts["master"], facts["worker"]
    master_v6, worker_v6 = master["ipv6"], worker["ipv6"]
    ports = FIREWALL_PORTS

    require(
        case_id,
        master_v6["kernel_addresses"],
        "the Master reports no address in /proc/net/if_inet6, which is the input the product's "
        "own check reads: the enabled branch was never reachable in this run",
    )
    require(
        case_id,
        not master_v6["kernel_disabled"],
        "the Master's kernel disables IPv6, so its install could not take the enabled branch",
    )
    require(
        case_id,
        master_v6["declared"] == "yes",
        f"the Master has IPv6 but /etc/default/ufw declares "
        f"IPV6={master_v6['declared'] or 'nothing'}: the firewall would not filter v6 traffic at all",
    )
    require(
        case_id,
        master_v6["active"],
        "the Master has no ufw6-user-input chain, so enabling IPv6 left the v6 stack unfiltered "
        "instead of mirroring the rule set onto it",
    )
    for port in IPV6_PUBLISHED_PORTS:
        require(
            case_id,
            denial.open_to_every_source(master_v6, port),
            f"the Master's v6 rules do not open port {port} to every source, so enabling IPv6 "
            f"closed a port its IPv4 rules publish: "
            f"{[entry['line'] for entry in master_v6['allows'][port]]}",
        )
    require(
        case_id,
        not master_v6["allows"][denial.NODE_PORT],
        f"the Master's v6 rules accept the local node port {denial.NODE_PORT}, so the isolation "
        f"the IPv4 rules apply is missing on the v6 stack: "
        f"{[entry['line'] for entry in master_v6['allows'][denial.NODE_PORT]]}",
    )
    require(
        case_id,
        master_v6["blocks"][denial.NODE_PORT],
        f"the Master's v6 rules carry no block for the local node port {denial.NODE_PORT}, so v6 "
        "traffic to it would be answered by the default policy alone rather than by a decision "
        "about that port",
    )
    require(
        case_id,
        not master_v6["allows"][denial.PANEL_API_PORT],
        f"the Master's v6 rules accept the panel API port {denial.PANEL_API_PORT}, so the "
        "management interface is reachable over IPv6",
    )
    for port in (denial.HTTPS_PORT, denial.HTTP_PORT):
        require(
            case_id,
            denial.ipv6_listens_for(master, port),
            f"the Master renders no `listen [::]` for port {port} although the host has IPv6, so "
            "the services it publishes on IPv4 are silently IPv4-only",
        )
    for port in (denial.NODE_PORT, denial.PANEL_API_PORT):
        require(
            case_id,
            not denial.ipv6_listens_for(master, port),
            f"the Master renders a `listen [::]` for the internal port {port}: "
            f"{denial.ipv6_listens_for(master, port)}",
        )
    for port in (denial.HTTPS_PORT, denial.HTTP_PORT):
        addresses = master["listeners"][port]
        require(
            case_id,
            "[::]" in addresses,
            f"the Master binds no wildcard IPv6 socket on port {port} (`ss` reports {addresses}), "
            "so the rendered listener never became a socket an IPv6 peer could reach",
        )
    # Enabling the v6 stack must not have displaced the v4 one: FW-03 measures
    # the same decisions in detail, so this only pins coexistence.
    require(
        case_id,
        denial.open_to_every_source(master, denial.HTTPS_PORT),
        "the Master stopped publishing port 443 on IPv4 once IPv6 was enabled",
    )

    https = _master_access_path("Master", "https", facts["master_paths"], case_id)
    require(
        case_id,
        https["outcome"] == "CONNECTED",
        f"[{facts['address']}]:{denial.HTTPS_PORT} ended "
        f"{https['outcome'] or 'without a verdict'} ({https['detail'] or 'no detail'}), so the "
        "port the case says is published on IPv6 has no v6 socket",
    )
    http = _master_access_path("Master", "http", facts["master_paths"], case_id)
    require(
        case_id,
        http["outcome"] == "CONNECTED",
        f"[{facts['address']}]:{denial.HTTP_PORT} ended "
        f"{http['outcome'] or 'without a verdict'} ({http['detail'] or 'no detail'}), so the ACME "
        "path the product publishes on IPv4 is unreachable over IPv6",
    )
    # The panel API is bound to loopback on IPv4 and must not gain a v6 socket:
    # nothing else on the host answers that port, so a refused attempt is a real
    # absence rather than a filtered packet, and a timeout is not the same
    # observation.
    panel_api = _master_access_path("Master", "panel-api", facts["master_paths"], case_id)
    require(
        case_id,
        panel_api["outcome"] in ("REFUSED", "UNREACHABLE"),
        f"the panel API port {denial.PANEL_API_PORT} over IPv6 ended "
        f"{panel_api['outcome'] or 'without a verdict'} ({panel_api['detail'] or 'no detail'}): a "
        "timeout would mean the v6 rule set dropped a packet, while the port simply having no v6 "
        "socket is what keeps it unpublished",
    )
    # The node port is a local service and stays one on both families: on IPv4 it
    # listens on a wildcard address too and only UFW keeps it private. The v6
    # half therefore has to be proven by the rule set, never by a self-connect —
    # ufw-before-input accepts `-i lo` before any user rule runs, so dialling
    # ::1 from the host itself always succeeds whenever a socket exists.
    _master_access_path("Master", "node", facts["master_paths"], case_id)
    require(
        case_id,
        any(entry["source"] == "" for entry in master_v6["blocks"][denial.NODE_PORT]),
        f"the Master's v6 block for the node port {denial.NODE_PORT} only covers a named source, "
        "so it does not keep the port off the network: "
        f"{[entry['line'] for entry in master_v6['blocks'][denial.NODE_PORT]]}",
    )
    require(
        case_id,
        worker_v6["kernel_disabled"],
        "the Worker's kernel does not disable IPv6, so this run has no IPv4-only host and the "
        "product's disabled branch was never exercised",
    )
    require(
        case_id,
        not worker_v6["kernel_addresses"],
        f"the Worker reports IPv6 addresses {worker_v6['kernel_addresses']}, so it is not the "
        "IPv4-only host this case measures",
    )
    require(
        case_id,
        worker_v6["declared"] == "no",
        f"the Worker has no IPv6 but /etc/default/ufw declares "
        f"IPV6={worker_v6['declared'] or 'nothing'}, so the install misread the host",
    )
    require(
        case_id,
        not worker_v6["active"],
        "the Worker carries a ufw6-user-input chain although its host has no IPv6",
    )
    for port in ports:
        require(
            case_id,
            not worker_v6["allows"][port] and not worker_v6["blocks"][port],
            f"the Worker's v6 rules name port {port} although the host has no IPv6: "
            f"{[entry['line'] for entry in worker_v6['allows'][port] + worker_v6['blocks'][port]]}",
        )
    require(
        case_id,
        not worker_v6["listens"],
        f"the Worker renders `listen [::]` entries although its host has no IPv6: "
        f"{worker_v6['listens']}",
    )
    for port in IPV6_PUBLISHED_PORTS:
        require(
            case_id,
            denial.open_to_every_source(worker, port),
            f"the Worker stopped publishing port {port} on IPv4 in its IPv4-only branch: "
            f"{[entry['line'] for entry in worker['allows'][port]]}",
        )
    require(
        case_id,
        worker["allows"][denial.NODE_PORT],
        f"the Worker's IPv4 rules carry no allow for the control port {denial.NODE_PORT} from the "
        "Master, so the IPv4-only branch is not the shape FW-01 measures",
    )
    require(
        case_id,
        not denial.open_to_every_source(worker, denial.NODE_PORT),
        f"the Worker's IPv4 rules open the control port {denial.NODE_PORT} to every source",
    )
    ssh = _master_access_path("Worker", "ssh-port", facts["worker_paths"], case_id)
    require(
        case_id,
        ssh["outcome"] == "UNREACHABLE",
        f"the Worker's attempt on its own SSH port over IPv6 ended "
        f"{ssh['outcome'] or 'without a verdict'} ({ssh['detail'] or 'no detail'}): on a host "
        "where the stack is absent the attempt has to fail before it can be filtered, which is "
        "how a reader tells 'no IPv6' from 'IPv6 blocked'",
    )

    def paths(report: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        return {
            label: {
                "address": entry.get("address"),
                "port": entry.get("port"),
                "outcome": entry.get("outcome"),
                "elapsed_ms": entry.get("elapsed_ms"),
                "detail": entry.get("detail"),
            }
            for label, entry in report.items()
            if isinstance(entry, dict)
        }

    def rules(facts_one: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "allows": {
                str(port): [entry["line"] for entry in facts_one["allows"][port]]
                for port in ports
            },
            "blocks": {
                str(port): [entry["line"] for entry in facts_one["blocks"][port]]
                for port in ports
            },
        }

    return {
        "address": facts["address"],
        "master": {
            "kernel_addresses": master_v6["kernel_addresses"],
            "kernel_disabled": master_v6["kernel_disabled"],
            "declared": master_v6["declared"],
            "v6_chain": master_v6["active"],
            "v6_rules": rules(master_v6),
            "v6_listens": master_v6["listens"],
            "v4_rules": rules(master),
            "v4_listeners": {str(port): master["listeners"][port] for port in ports},
            "paths": paths(facts["master_paths"]),
        },
        "worker": {
            "kernel_addresses": worker_v6["kernel_addresses"],
            "kernel_disabled": worker_v6["kernel_disabled"],
            "declared": worker_v6["declared"],
            "v6_chain": worker_v6["active"],
            "v6_rules": rules(worker_v6),
            "v6_listens": worker_v6["listens"],
            "v4_rules": rules(worker),
            "paths": paths(facts["worker_paths"]),
        },
        "limitation": facts["limitation"],
    }


def case_ipv6_policy(product: MultiNodeProduct) -> Dict[str, Any]:
    """FW-04: both IPv6 branches the product can take, on hosts that force each one.

    The product never asks whether IPv6 should be filtered; it reads the kernel
    and either publishes ``[::]`` listeners and mirrors its rules onto ip6tables,
    or leaves the v6 stack alone. A run that only ever installs on an IPv4 host
    proves the second branch and calls it IPv6 support. So the Master's IPv6
    stack is switched on before the install, the Worker is pinned to an IPv4-only
    host, and the case reads each role's decision back from where the product
    wrote it: ``/etc/default/ufw``, the v6 chain, the rendered listeners and the
    wildcard sockets they became, and a real connection to each port.
    """
    return ipv6_contract(ipv6_facts(product, IPV6_CASE_ID), IPV6_CASE_ID)


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


def case_nginx_config(product: MultiNodeProduct) -> Dict[str, Any]:
    """NGX-05: both roles validate their own generated NGINX tree and reload safely.

    A cluster generates two independent configurations — the Master's and the
    Worker's, written by two different scripts — so proving one says nothing about
    the other. Each role runs the full contract against its own server name: the
    tree it generated passes `nginx -t`, a broken snippet in the tree it reads
    makes the product's own deploy hook refuse to reload, and removing the
    snippet makes the same hook reload without replacing the master.
    """
    host = product.require_worker()
    roles = (
        ("master", "the Master", host.target_name, topology.PANEL_DOMAIN),
        ("worker", "the Worker", host.worker_name, host.worker_domain),
    )
    evidence: Dict[str, Any] = {}
    for key, label, container, domain in roles:
        evidence[key] = aio.nginx_config_reload_contract(
            product.podman, container, NGINX_CONFIG_CASE_ID, label, domain,
        )
    return evidence


def case_tls_surface(product: MultiNodeProduct) -> Dict[str, Any]:
    """TLS-01: each role's own certificate is validated by the independent client.

    The Master and the Worker are issued separate lineages by separate scripts
    and terminate TLS for different names, so a certificate read on one says
    nothing about the other. Each role's HTTPS vhost is read on the host that
    generated it, and the handshake is driven from the Control Machine, which
    resolves each name through the fixture zone to the node that serves it.

    The Worker serves no Panel page, so its own vhost answers 404 on `/`: that
    is the documented edge behaviour and still proves which vhost terminated
    the connection.
    """
    host = product.require_worker()
    return {
        "master": aio.tls_surface_contract(
            product.master, aio.TLS_CASE_ID, "the Master", topology.PANEL_DOMAIN, 200,
        ),
        "worker": aio.tls_surface_contract(
            product.master, aio.TLS_CASE_ID, "the Worker", host.worker_domain, 404,
            container=host.worker_name,
        ),
    }


def cover_decision_loader(role: str) -> str:
    """The lines that put this role's own copy of the decision in scope."""
    if role == "master":
        return f"source {topology.REPO_IN_CONTAINER}/modules/nginx.sh"
    if role != "worker":
        raise ValueError(f"unknown cover-domain role: {role!r}")
    # The Worker keeps no copy of its payload, so the functions are read back out
    # of the file the payload was cut from instead of a file it never wrote.
    return "\n".join(
        f"eval \"$(sed -n '/^{name}() {{/,/^}}$/p' "
        f"{topology.REPO_IN_CONTAINER}/gowave-node-auto.sh)\""
        for name in COVER_DECISION_FUNCTIONS
    )


def cover_decision_script(role: str, domain: str) -> str:
    """The apex table run through the copy of the decision the role ships.

    The same run also reports what the role's own resolver says about its derived
    apex and which addresses the role holds, because the product only binds the
    decoy to names that resolve here: a role whose apex points at another host is
    supposed to keep a nameless decoy instead of a certificate that cannot issue.
    """
    domains = " ".join(shlex.quote(candidate) for candidate in COVER_APEX_TABLE)
    refusals = " ".join(shlex.quote(candidate) for candidate in ("example.com", "localhost"))
    return f"""set -eu
{cover_decision_loader(role)}
apex=$(derive_cover_domain {shlex.quote(domain)})
printf 'apex\\t%s\\n' "$(getent ahostsv4 "$apex" 2>/dev/null | awk 'NR==1 {{print $1}}' || true)"
hostname -I 2>/dev/null | tr ' ' '\\n' | sed '/^$/d; s/^/self\\t/' || true
for domain in {domains}; do
    printf 'derived\\t%s\\t%s\\n' "$domain" "$(derive_cover_domain "$domain")"
done
for domain in {refusals}; do
    printf 'refusals\\t%s\\t%s\\n' "$domain" "$(cover_domain_for "$domain" "" 2>&1 >/dev/null)"
done
"""


def parse_cover_decision(output: str) -> Dict[str, Any]:
    facts: Dict[str, Any] = {"derived": {}, "refusals": {}, "apex": "", "self": []}
    for line in output.splitlines():
        fields = line.split("\t")
        kind = fields[0] if fields else ""
        if kind in ("derived", "refusals") and len(fields) == 3:
            facts[kind][fields[1]] = fields[2]
        elif kind == "apex" and len(fields) >= 2:
            facts["apex"] = fields[1]
        elif kind == "self" and len(fields) >= 2:
            facts["self"].append(fields[1])
    return facts


def require_cover_decision(case_id: str, role: str, facts: Dict[str, Any]) -> None:
    derived = facts["derived"]
    require(
        case_id,
        derived == COVER_APEX_ANSWERS,
        f"{role} derives the camouflage apex differently: {derived!r} instead of "
        f"{COVER_APEX_ANSWERS!r}",
    )
    for domain in ("example.com", "localhost"):
        message = facts["refusals"].get(domain, "")
        require(
            case_id,
            "has no subdomain" in message,
            f"{role} renders no cover lineage for {domain!r} without saying why: "
            f"{message!r}",
        )


def cover_vhost_names(case_id: str, role: str, path: str, text: str) -> List[str]:
    match = re.search(r"^[ \t]*server_name[ \t]+([^;]+);", text, re.MULTILINE)
    require(case_id, match, f"{role}'s cover vhost {path} declares no server_name")
    return match.group(1).split()


def require_cover_binding(case_id: str, role: str, names: Sequence[str],
                          apex: str, domain: str, resolved: str,
                          own_addresses: Sequence[str]) -> None:
    """The decoy names the apex exactly when this role's own resolver points there."""
    # A first-two-label derivation would name the deployment's own subdomain, so
    # it is checked first: its presence explains the wrong apex better than a
    # missing one does.
    first_two = ".".join(domain.rstrip(".").split(".")[:2])
    for wrong in (first_two, f"www.{first_two}"):
        require(
            case_id,
            wrong not in names,
            f"{role}'s cover vhost carries {wrong!r}, the first-two-label derivation, "
            f"instead of the apex {apex!r}: {list(names)}",
        )
    binds_here = bool(resolved) and resolved in own_addresses
    if binds_here:
        require(
            case_id,
            apex in names and f"www.{apex}" in names,
            f"{role} resolves {apex} to its own {resolved}, so its decoy has to carry "
            f"{apex} and www.{apex}: {list(names)}",
        )
    else:
        require(
            case_id,
            apex not in names and f"www.{apex}" not in names,
            f"{role} does not resolve {apex} to itself ({resolved!r} against "
            f"{list(own_addresses)}), so its decoy must not name names it cannot "
            f"validate over HTTP-01: {list(names)}",
        )


def case_cover_derive(product: MultiNodeProduct) -> Dict[str, Any]:
    """NGX-COVER-DERIVE: both roles derive the camouflage apex from their own domain.

    The Master and the Worker render their decoys from two scripts, so the
    derivation is proven on each role's own copy of the decision. The table is run
    in the container because the refusal for a domain without a subdomain cannot
    be observed on an install whose domain has one. Each role's real decoy vhost
    then has to follow that role's own resolution of the derived apex: the names
    are bound where the apex points here, and withheld where it points at another
    host, because ACME validates the lineage over port 80 on this machine. Neither
    role may carry the first-two-label derivation a wrong implementation produces.
    """
    host = product.require_worker()
    roles = (
        ("master", "the Master", host.target_name, topology.PANEL_DOMAIN,
         "/etc/nginx/conf.d/gowave-decoy.conf"),
        ("worker", "the Worker", host.worker_name, host.worker_domain,
         "/etc/nginx/conf.d/gowave-worker-decoy.conf"),
    )
    evidence: Dict[str, Any] = {}
    for key, label, container, domain, path in roles:
        labels = domain.rstrip(".").split(".")
        require(
            COVER_DERIVE_CASE_ID,
            len(labels) >= 3,
            f"{label}'s deployment domain {domain!r} has no subdomain, so this run "
            "cannot show a decoy bound to a derived apex",
        )
        apex = ".".join(labels[-2:])

        decided = product.podman.exec_bash(
            container, cover_decision_script(key, domain), check=False, timeout=120,
        )
        require(
            COVER_DERIVE_CASE_ID,
            decided.returncode == 0,
            f"{label} could not run its own cover-domain decision: "
            f"{(decided.stderr or '').strip()[-500:]}",
        )
        facts = parse_cover_decision(decided.stdout or "")
        require_cover_decision(COVER_DERIVE_CASE_ID, label, facts)

        rendered = product.podman.exec(container, ["cat", path], check=False)
        require(
            COVER_DERIVE_CASE_ID,
            rendered.returncode == 0,
            f"{label} has no decoy vhost at {path}: "
            f"{(rendered.stderr or '').strip()[-500:]}",
        )
        names = cover_vhost_names(COVER_DERIVE_CASE_ID, label, path, rendered.stdout)
        require_cover_binding(COVER_DERIVE_CASE_ID, label, names, apex, domain,
                              facts["apex"], facts["self"])
        evidence[key] = {
            "deployment_domain": domain,
            "cover_domain": apex,
            "apex_resolved_to": facts["apex"],
            "own_addresses": facts["self"],
            "derived": facts["derived"],
            "refusals": facts["refusals"],
            "vhost": path,
            "server_names": names,
            "cover_names_bound": apex in names,
        }
    return evidence


def cover_site_script(apex: str) -> str:
    """The Master's own rendering: the brand it derives and every file it ships.

    The public listener is measured separately, from the Control Machine; this
    reads the deployable tree that listener is configured with, so a page served
    from anywhere else cannot be mistaken for the site the product rendered.
    """
    documents = " ".join(shlex.quote(name) for name in COVER_SITE_DOCUMENTS)
    return f"""set -u
{cover_decision_loader("master")}
root={shlex.quote(COVER_SITE_ROOT)}
printf 'brand\\t%s\\t%s\\n' {shlex.quote(apex)} "$(cover_brand_from_domain {shlex.quote(apex)})"
cd "$root" || exit 1
find . -type f | LC_ALL=C sort | while IFS= read -r file; do
    printf 'file\\t%s\\t%s\\t%s\\n' "${{file#./}}" "$(sha256sum "$file" | cut -d' ' -f1)" "$(stat -c '%s' "$file")"
done
for doc in {documents}; do
    [ -f "$doc" ] || continue
    printf 'body\\t%s\\t%s\\n' "$doc" "$(base64 -w0 "$doc")"
done
"""


def parse_cover_site(output: str) -> Dict[str, Any]:
    """The rendered tree one line at a time: brand, files, and document text."""
    facts: Dict[str, Any] = {"brand": "", "files": {}, "bodies": {}}
    for line in output.splitlines():
        fields = line.split("\t")
        kind = fields[0] if fields else ""
        if kind == "brand" and len(fields) == 3:
            facts["brand"] = fields[2]
        elif kind == "file" and len(fields) == 4:
            facts["files"][fields[1]] = {"sha256": fields[2], "size": int(fields[3] or 0)}
        elif kind == "body" and len(fields) == 3:
            facts["bodies"][fields[1]] = base64.b64decode(fields[2]).decode("utf-8", "replace")
    return facts


def cover_brand_from_apex(apex: str) -> str:
    """The brand the site must carry: the apex's second-to-last label, title-cased.

    Read from the apex rather than from the deployment domain, because the apex
    is the name a visitor sees; a label with hyphens becomes separate words.
    """
    labels = [label for label in apex.rstrip(".").split(".") if label]
    if not labels:
        return ""
    label = labels[-2] if len(labels) >= 3 else labels[0]
    return " ".join(
        word[:1].upper() + word[1:] for word in label.replace("-", " ").split()
    )


def cover_site_path(path: str) -> str:
    """The file NGINX serves for one path under the cover root."""
    rel = path.lstrip("/").split("#", 1)[0].split("?", 1)[0]
    if rel == "" or path.endswith("/"):
        return f"{rel}index.html"
    if "." not in rel.rsplit("/", 1)[-1]:
        return f"{rel}/index.html"
    return rel


def cover_site_links(text: str) -> List[str]:
    """Every same-site path one HTML document points at, in first-seen order."""
    links: List[str] = []
    for match in re.finditer(r'(?:href|src)="([^"]+)"', text):
        target = match.group(1).split("#", 1)[0].split("?", 1)[0]
        if not target.startswith("/") or target == "/" or target in links:
            continue
        links.append(target)
    return links


def cover_site_fetch(case_id: str, host: topology.MultiNodeTopology, apex: str,
                     path: str) -> Dict[str, Any]:
    """One fetch of the apex from the independent client, or a failure naming it."""
    report = host.client_http(f"https://{apex}{path}", timeout=COVER_SITE_PROBE_TIMEOUT_SECONDS)
    probe = report.get("probe") or {}
    require(
        case_id,
        report.get("returncode") == 0 and probe,
        f"GET https://{apex}{path} produced no report (exit {report.get('returncode')}): "
        f"{report.get('stderr') or probe.get('error') or 'the probe printed nothing'}",
    )
    return probe


def require_cover_site_served(case_id: str, host: topology.MultiNodeTopology, apex: str,
                              path: str, document: str, files: Dict[str, Any],
                              expect_type: str = "") -> Dict[str, Any]:
    """One path serves exactly the file the Master rendered, with its own type."""
    require(
        case_id,
        document in files,
        f"{path} resolves to {document}, which the rendered site does not ship: "
        f"{sorted(files)}",
    )
    probe = cover_site_fetch(case_id, host, apex, path)
    require(
        case_id,
        probe.get("status") == 200,
        f"GET {path} on {apex} answered {probe.get('status')} instead of serving {document}",
    )
    require(
        case_id,
        probe.get("body_sha256") == files[document]["sha256"],
        f"GET {path} served a document the Master's {COVER_SITE_ROOT}/{document} does not "
        f"hold ({probe.get('body_sha256')} vs {files[document]['sha256']}), so the public "
        "listener is not serving the site the product rendered",
    )
    content_type = (probe.get("headers") or {}).get("content-type", "")
    if expect_type:
        require(
            case_id,
            content_type.startswith(expect_type),
            f"GET {path} was served as {content_type!r} instead of {expect_type!r}, so it "
            "would not be loaded as the page asks for it",
        )
    return {
        "path": path,
        "document": document,
        "status": probe.get("status"),
        "content_type": content_type,
        "body_sha256": probe.get("body_sha256"),
    }


def case_cover_site(product: MultiNodeProduct) -> Dict[str, Any]:
    """NGX-COVER-SITE: the apex serves one complete, plausibly branded site.

    A REALITY deployment is looked at before it is talked to, so the page the
    fallback hands out is part of the product surface: it has to be a whole site
    — documents, stylesheet, icons and artwork — branded for the apex rather than
    for whatever the installation happens to be called, with no unsubstituted
    template left in it and nothing that names the panel, its routes or the
    loopback listeners.

    Two halves make that one claim. The Master's own rendered tree is read where
    it sits, and the apex is fetched from the Control Machine over the real
    listener; every served document must be byte for byte the file the Master
    rendered, and every asset the pages point at must be served with the type
    NGINX's mime table gives it. The content is then judged against the rule the
    task states — the brand comes from the apex's second-to-last label — and
    against the shipped derivation, so a page branded by anything else fails.
    """
    case_id = COVER_SITE_CASE_ID
    host = product.require_worker()
    apex = topology.COVER_APEX
    rendered = product.podman.exec_bash(
        host.target_name, cover_site_script(apex), check=False, timeout=120,
    )
    require(
        case_id,
        rendered.returncode == 0,
        "the Master could not read its rendered cover site: "
        f"{(rendered.stderr or '').strip()[-500:]}",
    )
    facts = parse_cover_site(rendered.stdout or "")
    files, bodies = facts["files"], facts["bodies"]

    brand = cover_brand_from_apex(apex)
    require(
        case_id,
        facts["brand"] == brand,
        f"the Master's own derivation for {apex} is {facts['brand']!r} instead of {brand!r}, "
        "so the site is branded from something other than the apex's second-to-last label",
    )
    for suffix in (".html", ".css", ".svg"):
        require(
            case_id,
            any(name.endswith(suffix) for name in files),
            f"the rendered site ships no {suffix} asset: {sorted(files)}",
        )
    absent = [name for name in COVER_SITE_DOCUMENTS if name not in bodies]
    require(
        case_id,
        not absent,
        f"the rendered site is missing {absent} of the template's documents: {sorted(files)}",
    )

    placeholders = sorted(name for name, text in bodies.items() if "{{" in text)
    require(
        case_id,
        not placeholders,
        f"these rendered documents still carry a template placeholder: {placeholders}",
    )
    leaks = {
        name: sorted(token for token in COVER_SITE_LEAKS if token in text.lower())
        for name, text in bodies.items()
    }
    leaks = {name: tokens for name, tokens in leaks.items() if tokens}
    require(
        case_id,
        not leaks,
        f"the cover site names the deployment's own management surface: {leaks}",
    )

    index = bodies["index.html"]
    require(
        case_id,
        f"| {brand}</title>" in index,
        f"the front page is not titled with the brand {brand!r}: "
        f"{index[index.find('<title>'):index.find('</title>') + 8]}",
    )
    require(
        case_id,
        index.count(brand) >= 2,
        f"the brand {brand!r} appears {index.count(brand)} time(s) on the front page, so "
        "the header or footer was not branded",
    )

    served: Dict[str, Any] = {}
    for path in COVER_SITE_PAGES:
        served[path] = require_cover_site_served(
            case_id, host, apex, path, cover_site_path(path), files,
            expect_type="text/html",
        )

    assets: Dict[str, Any] = {}
    links: List[str] = []
    for text in bodies.values():
        links.extend(link for link in cover_site_links(text) if link not in links)
    for link in links:
        document = cover_site_path(link)
        if document in bodies:
            # A page the site ships was already measured with the pages above.
            continue
        assets[link] = require_cover_site_served(
            case_id, host, apex, link, document, files,
            expect_type=COVER_SITE_ASSET_TYPES.get(
                os.path.splitext(document)[1].lower(), "",
            ),
        )
    require(
        case_id,
        any(asset.get("content_type", "").startswith("text/css") for asset in assets.values()),
        f"the site's stylesheet is not served as CSS: {sorted(assets)}",
    )
    require(
        case_id,
        any(asset.get("content_type", "").startswith("image/svg") for asset in assets.values()),
        f"the site's artwork is not served as SVG: {sorted(assets)}",
    )
    return {
        "apex": apex,
        "brand": brand,
        "files": len(files),
        "documents": sorted(bodies),
        "pages": served,
        "assets": assets,
        "placeholders": placeholders,
        "leaks": leaks,
    }


def decoy_cover_decision_script(role: str, domain: str, server_ip: str) -> str:
    """The role's own cover decision for its deployment domain, and nothing else.

    The route case only needs to know whether this role owes a cover route, so it
    asks the shipped decision instead of assuming both roles render an apex.
    """
    return f"""set -u
{cover_decision_loader(role)}
apex=$(cover_domain_for {shlex.quote(domain)} {shlex.quote(server_ip)} 2>/dev/null || true)
reason=$(cover_domain_for {shlex.quote(domain)} {shlex.quote(server_ip)} 2>&1 >/dev/null || true)
printf 'decision\\t%s\\t%s\\t%s\\n' {shlex.quote(domain)} "$apex" "$reason"
"""


def decoy_route_script(vhost: str) -> str:
    """The stream map, the decoy vhost's listens, the sockets, and the SANs.

    ``nginx -T`` prints the configuration verbatim, so the map block is read from
    the running tree rather than from the file the product would have written;
    ``ss`` reports where the decoy is actually bound, which is what decides
    whether a client network can reach it.
    """
    return f"""set -u
nginx -T 2>/dev/null | sed -n '/^map \\$ssl_preread_server_name /,/^}}/p' | sed 's/^/mapraw\\t/'
grep -nE '^[[:space:]]*listen[[:space:]]' {shlex.quote(vhost)} 2>/dev/null | sed 's/^/decoy\\t/' || true
ss -ltnH 'sport = :443' 2>/dev/null | awk '{{print "bound\\t443\\t" $4}}' || true
ss -ltnH 'sport = :{DECOY_LISTENER_PORT}' 2>/dev/null | awk '{{print "bound\\t{DECOY_LISTENER_PORT}\\t" $4}}' || true
for cert in /etc/letsencrypt/live/*/cert.pem; do
    [ -f "$cert" ] || continue
    printf 'lineage\\t%s\\t%s\\n' "$cert" "$(openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null | tr '\\n' ' ' || true)"
done
"""


def parse_decoy_route(output: str) -> Dict[str, Any]:
    """The map, the decoy's listens, the bound sockets, and every lineage's SANs."""
    facts: Dict[str, Any] = {"map": {}, "decoy": [], "bound": {}, "lineages": {}}
    for line in output.splitlines():
        fields = line.split("\t")
        kind = fields[0] if fields else ""
        if kind == "mapraw" and len(fields) == 2:
            # The dump keeps the directive's semicolon; the map block's own
            # braces are not entries.
            entry = re.match(
                r"^([A-Za-z0-9_.*-]+)\s+([0-9.]+:[0-9]+)$",
                fields[1].strip().rstrip(";").strip(),
            )
            if entry:
                facts["map"][entry.group(1)] = entry.group(2)
        elif kind == "decoy" and len(fields) == 2:
            facts["decoy"].append(fields[1])
        elif kind == "bound" and len(fields) == 3:
            address, _, port = fields[2].rpartition(":")
            facts["bound"].setdefault(port, []).append(address)
        elif kind == "lineage" and len(fields) == 3:
            facts["lineages"][fields[1]] = cover_lineage_sans(fields[2])
    return facts


def require_decoy_loopback(case_id: str, label: str, facts: Dict[str, Any]) -> Dict[str, Any]:
    """The decoy listens on 127.0.0.1 only, and 443 is the public listener."""
    bound = facts["bound"]
    listeners = bound.get(str(DECOY_LISTENER_PORT)) or []
    require(
        case_id,
        listeners,
        f"{label} has no {DECOY_LISTENER_PORT} listener at all, so the camouflage page "
        "would have to be served by the public 443 vhost",
    )
    foreign = sorted(address for address in listeners if address != "127.0.0.1")
    require(
        case_id,
        not foreign,
        f"{label} binds its decoy to {foreign} as well as 127.0.0.1, so the camouflage "
        "listener is reachable from the network instead of only through NGINX's own "
        "loopback proxy",
    )
    public = bound.get("443") or []
    require(
        case_id,
        any(address in denial.WILDCARD_ADDRESSES for address in public),
        f"{label} does not accept 443 on a wildcard address: {public}",
    )
    require(
        case_id,
        facts["decoy"],
        f"{label}'s decoy vhost declares no listen directive",
    )
    stray = [line for line in facts["decoy"] if f"127.0.0.1:{DECOY_LISTENER_PORT}" not in line]
    require(
        case_id,
        not stray,
        f"{label}'s decoy vhost listens outside the loopback listener: {stray}",
    )
    return {"bound_9443": listeners, "bound_443": public, "decoy_listen": facts["decoy"]}


def require_decoy_routes(case_id: str, label: str, facts: Dict[str, Any],
                         cover_names: Sequence[str], names: Dict[str, str]) -> Dict[str, str]:
    """Only the camouflage names reach the decoy, and every VPN name keeps its port."""
    routes = facts["map"]
    require(
        case_id,
        routes,
        f"{label}'s running configuration carries no ssl_preread server-name map, so no "
        "SNI has a route of its own",
    )
    decoy = f"127.0.0.1:{DECOY_LISTENER_PORT}"
    for name in cover_names:
        require(
            case_id,
            routes.get(name) == decoy,
            f"{label} routes {name} to {routes.get(name)!r} instead of the loopback decoy "
            f"{decoy}, so that name does not terminate on {decoy}",
        )
    stray = sorted(
        name for name, backend in routes.items()
        if backend == decoy and name not in set(cover_names) and name != "default"
    )
    require(
        case_id,
        not stray,
        f"{label} sends {stray} to the camouflage listener, so a name that is not a cover "
        "name would land on the decoy instead of keeping its own route",
    )
    reality = f"127.0.0.1:{DECOY_ROUTE_BACKENDS['reality']}"
    require(
        case_id,
        routes.get("default") == reality,
        f"{label}'s stream map defaults to {routes.get('default')!r} instead of its own "
        f"REALITY listener {reality}, so an unmatched SNI would not fall back to the node",
    )
    for kind, name in names.items():
        if not name:
            continue
        expected = f"127.0.0.1:{DECOY_ROUTE_BACKENDS[kind]}"
        require(
            case_id,
            routes.get(name) == expected,
            f"{label} routes {name} to {routes.get(name)!r} instead of {expected}, so that "
            f"name does not keep its own route (observed: {sorted(routes.items())})",
        )
    return dict(routes)


def require_cover_lineage(case_id: str, label: str, facts: Dict[str, Any],
                          wanted: Sequence[str]) -> Dict[str, List[str]]:
    """The installed lineage that names every cover name, or a failure naming it."""
    covering = {
        path: sans for path, sans in facts["lineages"].items()
        if all(name in sans for name in wanted)
    }
    require(
        case_id,
        covering,
        f"{label} holds no certificate lineage naming {list(wanted)}, so the decoy would "
        f"serve a lineage that does not cover the camouflage names: {facts['lineages']}",
    )
    return covering


def require_decoy_page(case_id: str, host: topology.MultiNodeTopology, name: str,
                       index_sha256: str, wanted: Sequence[str]) -> Dict[str, Any]:
    """One name answers with the rendered cover page over a lineage naming the pair."""
    probe = cover_site_fetch(case_id, host, name, "/")
    require(
        case_id,
        probe.get("status") == 200,
        f"https://{name}/ answered {probe.get('status')} instead of the camouflage page, so "
        "that name does not terminate on the decoy",
    )
    require(
        case_id,
        probe.get("body_sha256") == index_sha256,
        f"https://{name}/ served {probe.get('body_sha256')} instead of the rendered cover "
        f"page {index_sha256}, so the decoy it reached is not the site the product rendered",
    )
    sans = list((probe.get("peer") or {}).get("san") or [])
    for cover_name in wanted:
        require(
            case_id,
            cover_name in sans,
            f"the certificate https://{name}/ presented does not name {cover_name}: {sans}",
        )
    return {
        "status": probe.get("status"),
        "body_sha256": probe.get("body_sha256"),
        "san": sans,
        "tls_version": (probe.get("peer") or {}).get("tls_version", ""),
    }


def decoy_route_paths(case_id: str, podman: Any, container: str, origin: str,
                      addresses: Dict[str, str]) -> Dict[str, Any]:
    """Real TCP attempts from one client network: 443 answers, the decoy does not."""
    attempts = []
    for key, address in addresses.items():
        attempts.append({
            "label": f"{origin}-{key}-{DECOY_LISTENER_PORT}",
            "address": address,
            "port": DECOY_LISTENER_PORT,
            "timeout": DECOY_ROUTE_PATH_TIMEOUT_SECONDS,
        })
        attempts.append({
            "label": f"{origin}-{key}-443",
            "address": address,
            "port": 443,
            "timeout": DECOY_ROUTE_PATH_TIMEOUT_SECONDS,
        })
    observed = denial.tcp_paths_shell(podman, container, attempts)
    require(
        case_id,
        observed.get("returncode") == 0,
        f"the {origin} role could not attempt a connection: {observed.get('detail') or ''}",
    )
    for key in addresses:
        opened = observed.get(f"{origin}-{key}-443", {})
        require(
            case_id,
            opened.get("outcome") == "CONNECTED",
            f"{origin} could not reach {addresses[key]}:443 ({opened.get('outcome')}, "
            f"{opened.get('detail') or 'no detail'}), so a refused decoy port would prove "
            "nothing about that network",
        )
        closed = observed.get(f"{origin}-{key}-{DECOY_LISTENER_PORT}", {})
        require(
            case_id,
            closed.get("outcome") in ("REFUSED", "TIMEOUT", "UNREACHABLE"),
            f"{origin} reached {addresses[key]}:{DECOY_LISTENER_PORT} "
            f"({closed.get('outcome')}), so the camouflage listener is exposed to a client "
            "network instead of staying on the node's own loopback",
        )
    return observed


def case_decoy_route(product: MultiNodeProduct) -> Dict[str, Any]:
    """NGX-DECOY-ROUTE: the decoy is a loopback target, never a public surface.

    Three claims make the camouflage listener an internal detail. The running
    stream map sends the cover pair to `127.0.0.1:9443` and every other name to
    its own local port; the socket itself is bound to the loopback address and
    refuses connections from both client networks while 443 answers them; and
    the certificate a client receives for the apex, its www and the REALITY name
    is the installed lineage that names the pair, so the camouflage is what a
    scanning client sees rather than an Xray fingerprint.

    The role that decides no apex (its own resolution puts the pair elsewhere)
    owes no cover route at all, so the case reads each role's own decision
    instead of assuming both render one.
    """
    case_id = DECOY_ROUTE_CASE_ID
    host = product.require_worker()
    apex = topology.COVER_APEX
    roles = (
        ("master", "the Master", host.target_name, host.panel_domain,
         host.reality_domain, getattr(host, "vision_domain", "") or "",
         "/etc/nginx/conf.d/gowave-decoy.conf", host.plan.target_ip),
        ("worker", "the Worker", host.worker_name, host.worker_domain,
         host.worker_reality_domain, host.worker_vision_domain,
         "/etc/nginx/conf.d/gowave-worker-decoy.conf", host.plan.worker_ip),
    )
    evidence: Dict[str, Any] = {"apex": apex, "roles": {}}
    for key, label, container, domain, reality, vision, vhost, address in roles:
        decided = product.podman.exec_bash(
            container, decoy_cover_decision_script(key, domain, address),
            check=False, timeout=120,
        )
        require(
            case_id,
            decided.returncode == 0,
            f"{label} could not run its own cover-domain decision: "
            f"{(decided.stderr or '').strip()[-500:]}",
        )
        rendered_apex = cover_decision_for(
            case_id, label, domain, parse_cover_state(decided.stdout or ""),
        ).get("apex", "")
        cover_names = [rendered_apex, f"www.{rendered_apex}"] if rendered_apex else []

        read = product.podman.exec_bash(
            container, decoy_route_script(vhost), check=False, timeout=120,
        )
        require(
            case_id,
            read.returncode == 0,
            f"{label} could not read its stream map and decoy listener: "
            f"{(read.stderr or '').strip()[-500:]}",
        )
        facts = parse_decoy_route(read.stdout or "")
        evidence["roles"][key] = {
            "cover_names": cover_names,
            "bindings": require_decoy_loopback(case_id, label, facts),
            "routes": require_decoy_routes(
                case_id, label, facts, cover_names,
                {"panel": domain, "reality": reality, "vision": vision},
            ),
            "lineage": require_cover_lineage(
                case_id, label, facts, cover_names or [reality],
            ),
            "address": address,
        }

    # The page and the lineage are observed from the client, which trusts only
    # the fixture CA: a name that does not terminate on the decoy cannot answer
    # with the rendered page and the camouflage lineage.
    rendered = product.podman.exec_bash(
        host.target_name, cover_site_script(apex), check=False, timeout=120,
    )
    require(
        case_id,
        rendered.returncode == 0,
        "the Master could not read its rendered cover site: "
        f"{(rendered.stderr or '').strip()[-500:]}",
    )
    index_sha256 = (parse_cover_site(rendered.stdout or "")["files"].get("index.html") or {}).get(
        "sha256", "")
    require(
        case_id,
        index_sha256,
        f"the Master rendered no index.html for {apex}, so there is no page the decoy "
        "could be serving",
    )
    wanted = [apex, f"www.{apex}"]
    evidence["client"] = {
        "apex": require_decoy_page(case_id, host, apex, index_sha256, wanted),
        "www": require_decoy_page(case_id, host, f"www.{apex}", index_sha256, wanted),
        "reality": require_decoy_page(
            case_id, host, host.reality_domain, index_sha256, wanted,
        ),
    }
    panel = cover_site_fetch(case_id, host, host.panel_domain, "/")
    require(
        case_id,
        panel.get("body_sha256") != index_sha256,
        f"https://{host.panel_domain}/ served the camouflage page, so the panel name "
        "does not keep its own route",
    )
    evidence["client"]["panel"] = {
        "status": panel.get("status"),
        "body_sha256": panel.get("body_sha256"),
    }

    # Both client networks attempt the real TCP path: 443 has to answer from each
    # of them, because a decoy that is unreachable only where nothing is
    # reachable would prove nothing.
    addresses = {"master": host.plan.target_ip, "worker": host.plan.worker_ip}
    evidence["paths"] = {
        origin: decoy_route_paths(case_id, product.podman, container, origin, addresses)
        for origin, container in (
            ("client", host.client_name), ("untrusted", host.untrusted_name),
        )
    }
    return evidence


def acme_challenge_script(token: str) -> str:
    """Put a token in the role's own ACME webroot, where HTTP-01 reads it."""
    return f"""set -u
root={ACME_WEBROOT}
mkdir -p "$root{ACME_CHALLENGE_DIR}" || exit 1
printf '%s' {shlex.quote(token)} > "$root{ACME_CHALLENGE_DIR}/{shlex.quote(token)}" || exit 1
chmod 0644 "$root{ACME_CHALLENGE_DIR}/{shlex.quote(token)}"
printf 'challenge\\t%s\\t%s\\n' "$root" "$(sha256sum "$root{ACME_CHALLENGE_DIR}/{shlex.quote(token)}" | cut -d' ' -f1)"
"""


def acme_vhost_script(vhost: str, old_domain: str) -> str:
    """One role's port 80 vhost, its enabled sites, and any entry naming the old name."""
    return f"""set -u
vhost={shlex.quote(vhost)}
if [ -f "$vhost" ]; then
    printf 'present\\t1\\n'
    grep -nE '^[[:space:]]*(listen|server_name|root|ssl_certificate)[[:space:]]' "$vhost" | sed 's/^/line\\t/'
else
    printf 'present\\t0\\n'
fi
if [ -d {ACME_WEBROOT} ]; then printf 'webroot\\t1\\n'; else printf 'webroot\\t0\\n'; fi
ls -1 /etc/nginx/sites-enabled 2>/dev/null | sed 's/^/enabled\\t/' || true
grep -rlF -- {shlex.quote(old_domain)} /etc/nginx/sites-enabled /etc/nginx/sites-available 2>/dev/null | sed 's/^/stale\\t/' || true
"""


def parse_acme_vhost(output: str) -> Dict[str, Any]:
    """The vhost's directives, the enabled sites, and the stale entries."""
    facts: Dict[str, Any] = {
        "present": False, "lines": [], "listen": [], "server_name": [],
        "root": "", "certificate": "", "webroot": False, "enabled": [], "stale": [],
    }
    for line in (output or "").splitlines():
        fields = line.split("\t")
        kind = fields[0] if fields else ""
        if kind == "present" and len(fields) == 2:
            facts["present"] = fields[1].strip() == "1"
        elif kind == "line" and len(fields) == 2:
            facts["lines"].append(fields[1])
            directive = fields[1].split(":", 1)[-1].strip().rstrip(";").strip()
            name, _, value = directive.partition(" ")
            value = value.strip()
            if name == "listen":
                facts["listen"].append(value)
            elif name == "server_name":
                facts["server_name"].extend(value.split())
            elif name == "root":
                facts["root"] = value
            elif name == "ssl_certificate":
                facts["certificate"] = value
        elif kind == "webroot" and len(fields) == 2:
            facts["webroot"] = fields[1].strip() == "1"
        elif kind == "enabled" and len(fields) == 2:
            facts["enabled"].append(fields[1])
        elif kind == "stale" and len(fields) == 2:
            facts["stale"].append(fields[1])
    return facts


def require_acme_vhost(case_id: str, label: str, facts: Dict[str, Any],
                       names: Sequence[str], default_server: bool) -> Dict[str, Any]:
    """The port 80 vhost is there, answers 80, and serves the challenge root."""
    require(
        case_id,
        facts["present"],
        f"{label} has no port 80 ACME vhost, so certbot's HTTP-01 renewal would have "
        "nothing to revalidate through",
    )
    listening = [line for line in facts["listen"] if line.split()[0:1] == ["80"]]
    require(
        case_id,
        listening,
        f"{label}'s port 80 vhost does not listen on 80: {facts['listen']}",
    )
    require(
        case_id,
        any("default_server" in line for line in listening) == default_server,
        f"{label}'s port 80 vhost declares {listening}, so its default-server role is "
        f"{'missing' if default_server else 'unexpected'}",
    )
    missing = [name for name in names if name and name not in facts["server_name"]]
    require(
        case_id,
        not missing,
        f"{label}'s port 80 vhost does not answer for {missing}: {facts['server_name']}",
    )
    require(
        case_id,
        facts["root"] == ACME_WEBROOT,
        f"{label}'s port 80 vhost serves challenges from {facts['root']!r} instead of "
        f"{ACME_WEBROOT}",
    )
    require(
        case_id,
        facts["webroot"],
        f"{label} holds no {ACME_WEBROOT} directory, so the vhost's challenge root is empty",
    )
    return facts


def acme_challenge_fetch(case_id: str, host: topology.MultiNodeTopology, name: str,
                         token: str) -> Dict[str, Any]:
    """The challenge answers over plain HTTP on the name's own vhost."""
    url = f"http://{name}{ACME_CHALLENGE_DIR}/{token}"
    report = host.client_http(url, timeout=COVER_SITE_PROBE_TIMEOUT_SECONDS)
    probe = report.get("probe") or {}
    require(
        case_id,
        report.get("returncode") == 0 and probe,
        f"GET {url} produced no report (exit {report.get('returncode')}): "
        f"{report.get('stderr') or 'the probe printed nothing'}",
    )
    require(
        case_id,
        probe.get("status") == 200,
        f"GET {url} answered {probe.get('status')} (location "
        f"{(probe.get('headers') or {}).get('location', '')!r}) instead of serving the "
        "challenge, so a renewal would fail",
    )
    expected = hashlib.sha256(token.encode("utf-8")).hexdigest()
    require(
        case_id,
        probe.get("body_sha256") == expected,
        f"GET {url} served {probe.get('body_sha256')} instead of the token written into "
        f"{ACME_WEBROOT}, so the vhost answers from somewhere else",
    )
    return {
        "url": url,
        "status": probe.get("status"),
        "body_sha256": probe.get("body_sha256"),
    }


def node_reapply_script(name: str) -> str:
    """The operator's own Worker re-apply, unmodified and without a TTY."""
    return f"bash {topology.REPO_IN_CONTAINER}/gowave-auto.sh node reapply {shlex.quote(name)}\n"


def domain_change_script(panel_domain: str, reality_domain: str) -> str:
    """The operator's own domain change, unmodified and without a TTY."""
    return (
        f"bash {topology.REPO_IN_CONTAINER}/gowave-auto.sh domain-change "
        f"{shlex.quote(panel_domain)} {shlex.quote(reality_domain)}\n"
    )


def case_acme80(product: MultiNodeProduct) -> Dict[str, Any]:
    """NGX-WORKER-ACME80: port 80 keeps revalidating across a re-provision.

    Certificate renewal revalidates through the port 80 vhost, so a Worker
    re-provision must not remove it and a domain change must re-render it for
    the new names. The case writes a token into each role's own ACME webroot
    and fetches it from the independent client, which is exactly what certbot
    asks an HTTP-01 challenge to do; it repeats that after re-applying the
    Worker payload with the operator's `node reapply`, and after a real
    `domain-change` on the Master, where the decoy, the lineage and the enabled
    sites are read again for the new names.
    """
    case_id = ACME80_CASE_ID
    host = product.require_worker()
    token = ACME_CHALLENGE_TOKEN
    old_panel = host.panel_domain
    roles = (
        ("master", "the Master", host.target_name, host.panel_domain, ACME_MASTER_VHOST, True),
        ("worker", "the Worker", host.worker_name, host.worker_domain, ACME_WORKER_VHOST, False),
    )
    evidence: Dict[str, Any] = {"token": token, "roles": {}}

    def read_role(key: str, label: str, container: str, name: str, vhost: str,
                  default_server: bool, names: Sequence[str]) -> Dict[str, Any]:
        written = product.podman.exec_bash(
            container, acme_challenge_script(token), check=False, timeout=120,
        )
        require(
            case_id,
            written.returncode == 0,
            f"{label} could not write its own challenge token: "
            f"{(written.stderr or '').strip()[-400:]}",
        )
        read = product.podman.exec_bash(
            container, acme_vhost_script(vhost, old_panel), check=False, timeout=120,
        )
        require(
            case_id,
            read.returncode == 0,
            f"{label} could not read its port 80 tree: {(read.stderr or '').strip()[-400:]}",
        )
        facts = require_acme_vhost(
            case_id, label, parse_acme_vhost(read.stdout or ""), names, default_server,
        )
        return {
            "vhost": vhost,
            "server_name": facts["server_name"],
            "listen": facts["listen"],
            "root": facts["root"],
            "certificate": facts["certificate"],
            "enabled": facts["enabled"],
            "stale": facts["stale"],
            "challenge": acme_challenge_fetch(case_id, host, name, token),
        }

    masters = [role for role in roles if role[0] == "master"][0]
    workers = [role for role in roles if role[0] == "worker"][0]
    evidence["roles"]["master"] = read_role(
        *masters, names=[host.panel_domain, host.reality_domain],
    )
    evidence["roles"]["worker"] = read_role(
        *workers, names=[host.worker_domain, host.worker_reality_domain],
    )
    require(
        case_id,
        "default" not in evidence["roles"]["master"]["enabled"],
        f"the Master still enables the distribution's default site "
        f"({evidence['roles']['master']['enabled']}), which competes for port 80",
    )

    # The Worker's route is install-time state too: a re-provision may re-render
    # it, but it may not move the decoy or the SNI routes when nothing changed.
    def worker_route() -> Dict[str, Any]:
        read = product.podman.exec_bash(
            host.worker_name, decoy_route_script(ACME_WORKER_VHOST), check=False, timeout=120,
        )
        require(
            case_id,
            read.returncode == 0,
            f"the Worker could not read its stream map: {(read.stderr or '').strip()[-400:]}",
        )
        facts = parse_decoy_route(read.stdout or "")
        return {"map": facts["map"], "bound_9443": facts["bound"].get(str(DECOY_LISTENER_PORT), [])}

    before = worker_route()
    changed = product.podman.exec_bash(
        host.target_name, node_reapply_script(host.worker_node_name),
        check=False, timeout=ACME80_REAPPLY_TIMEOUT_SECONDS,
    )
    require(
        case_id,
        changed.returncode == 0,
        f"re-applying the Worker payload with `node reapply` exited {changed.returncode}: "
        f"{(changed.stderr or changed.stdout or '').strip()[-600:]}",
    )
    evidence["reapply"] = {
        "command": node_reapply_script(host.worker_node_name).strip(),
        "returncode": changed.returncode,
    }
    after = worker_route()
    require(
        case_id,
        before == after,
        f"re-provisioning the Worker moved its routes: {before} became {after}, so a "
        "reconfiguration changed a tree that had no domain change to apply",
    )
    evidence["roles"]["worker"]["routes_unchanged"] = after == before
    evidence["roles"]["worker"]["routes"] = after
    evidence["roles"]["master"]["after_reconfigure"] = read_role(
        *masters, names=[host.panel_domain, host.reality_domain],
    )
    evidence["roles"]["worker"]["after_reconfigure"] = read_role(
        *workers, names=[host.worker_domain, host.worker_reality_domain],
    )

    # A domain change is the one flow that has to move the decoy and the
    # lineage; the new names are added to the fixture zone first, so the
    # product's own resolution precondition and certbot's HTTP-01 both hold.
    zone = host.zone()
    zone["records"][ACME_NEW_PANEL_DOMAIN] = {"A": [host.plan.target_ip]}
    zone["records"][ACME_NEW_REALITY_DOMAIN] = {"A": [host.plan.target_ip]}
    host.write_dns_zone(zone)
    renamed = product.podman.exec_bash(
        host.target_name, domain_change_script(ACME_NEW_PANEL_DOMAIN, ACME_NEW_REALITY_DOMAIN),
        check=False, timeout=ACME80_DOMAIN_CHANGE_TIMEOUT_SECONDS,
    )
    require(
        case_id,
        renamed.returncode == 0,
        f"`gowave-auto.sh domain-change` exited {renamed.returncode}: "
        f"{(renamed.stderr or renamed.stdout or '').strip()[-800:]}",
    )
    evidence["domain_change"] = {
        "panel": ACME_NEW_PANEL_DOMAIN,
        "reality": ACME_NEW_REALITY_DOMAIN,
        "returncode": renamed.returncode,
    }

    post = product.podman.exec_bash(
        host.target_name, acme_vhost_script(ACME_MASTER_VHOST, old_panel),
        check=False, timeout=120,
    )
    facts = require_acme_vhost(
        case_id, "the Master after the domain change", parse_acme_vhost(post.stdout or ""),
        [ACME_NEW_PANEL_DOMAIN, ACME_NEW_REALITY_DOMAIN], True,
    )
    require(
        case_id,
        not facts["stale"],
        f"the Master's enabled and available sites still name {old_panel}: "
        f"{facts['stale']}, so the old name kept a stale entry",
    )
    require(
        case_id,
        "default" not in facts["enabled"],
        f"the domain change reinstated the distribution's default site: {facts['enabled']}",
    )
    evidence["after_domain_change"] = {
        "server_name": facts["server_name"],
        "listen": facts["listen"],
        "root": facts["root"],
        "enabled": facts["enabled"],
        "stale": facts["stale"],
        "challenge": acme_challenge_fetch(case_id, host, ACME_NEW_PANEL_DOMAIN, token),
    }

    route = product.podman.exec_bash(
        host.target_name, decoy_route_script("/etc/nginx/conf.d/gowave-decoy.conf"),
        check=False, timeout=120,
    )
    require(
        case_id,
        route.returncode == 0,
        f"the Master could not read its re-rendered decoy: "
        f"{(route.stderr or '').strip()[-400:]}",
    )
    rendered = parse_decoy_route(route.stdout or "")
    apex = topology.COVER_APEX
    require_decoy_routes(
        case_id, "the Master after the domain change", rendered, [apex, f"www.{apex}"],
        {"panel": ACME_NEW_PANEL_DOMAIN, "reality": ACME_NEW_REALITY_DOMAIN},
    )
    lineage = require_cover_lineage(
        case_id, "the Master after the domain change", rendered, [apex, f"www.{apex}"],
    )
    certificate = (
        f"/etc/letsencrypt/live/{ACME_NEW_REALITY_DOMAIN}/fullchain.pem"
    )
    decoy = product.podman.exec_bash(
        host.target_name,
        "set -u\ngrep -nE '^[[:space:]]*(server_name|ssl_certificate)[[:space:]]' "
        "/etc/nginx/conf.d/gowave-decoy.conf\n",
        check=False, timeout=120,
    )
    require(
        case_id,
        certificate in (decoy.stdout or ""),
        f"the re-rendered decoy does not name {certificate}: {(decoy.stdout or '').strip()}",
    )
    require(
        case_id,
        ACME_NEW_REALITY_DOMAIN in (decoy.stdout or "")
        and apex in (decoy.stdout or ""),
        f"the re-rendered decoy does not name the new pair: {(decoy.stdout or '').strip()}",
    )
    evidence["decoy"] = {
        "routes": dict(rendered["map"]),
        "lineage": lineage,
        "server_lines": (decoy.stdout or "").splitlines(),
        "certificate": certificate,
    }
    return evidence


def backup_script(type_name: str) -> str:
    """The operator's own backup command for one archive type."""
    return (
        f"bash {topology.REPO_IN_CONTAINER}/gowave-auto.sh backup "
        f"--type {shlex.quote(type_name)}\n"
    )


def backup_verify_script(archive: str, type_name: str) -> str:
    """The product's own validator, run against the archive it just wrote."""
    return (
        f"bash {topology.REPO_IN_CONTAINER}/assets/backup/gowave-backup.sh verify "
        f"{shlex.quote(archive)} {shlex.quote(type_name)}\n"
    )


def backup_volume_probe_script() -> str:
    """Inside one role: what the archive directory is, and whether it is a volume.

    The root filesystem is read beside it, because a directory that is merely part
    of the container layer would report the same filesystem type and would vanish
    with the container — the archive store has to be a mount of its own.
    """
    store = topology.BACKUP_STORE
    return (
        "set -u\n"
        f"target=$(stat -f -c '%T' {store} 2>/dev/null || echo missing)\n"
        "root=$(stat -f -c '%T' / 2>/dev/null || echo missing)\n"
        f"owner=$(stat -c '%U' {store} 2>/dev/null || echo missing)\n"
        f"mode=$(stat -c '%a' {store} 2>/dev/null || echo missing)\n"
        f"mounts=$(grep -c ' {store} ' /proc/self/mounts 2>/dev/null || true)\n"
        "printf 'target_type=%s root_type=%s owner=%s mode=%s mounts=%s\\n' "
        '"${target}" "${root}" "${owner}" "${mode}" "${mounts:-0}"\n'
    )


def require_backup_volume(
    case_id: str, label: str, facts: Dict[str, str],
) -> None:
    """The archive store is a root-only mount of its own, not part of the image."""
    require(
        case_id,
        facts.get("target_type") not in ("", "missing", None)
        and facts.get("target_type") != facts.get("root_type"),
        f"{label}: the archive store reports filesystem {facts.get('target_type')!r} "
        f"while the root is {facts.get('root_type')!r}, so the archives sit in the "
        "container layer rather than on a volume of their own",
    )
    require(
        case_id,
        facts.get("owner") == "root",
        f"{label}: the archive store is owned by {facts.get('owner')!r}, so an "
        "unencrypted archive would be readable by another user",
    )
    require(
        case_id,
        facts.get("mode") == BACKUP_VOLUME_DIRECTORY_MODE,
        f"{label}: the archive store is mode {facts.get('mode')!r} instead of "
        f"{BACKUP_VOLUME_DIRECTORY_MODE}, so an unencrypted archive would be "
        "readable by another user",
    )
    require(
        case_id,
        facts.get("mounts") == "1",
        f"{label}: the archive store has {facts.get('mounts')!r} mount entries "
        "instead of exactly one, so it is not the single run-owned volume",
    )


def artifact_leaks(directory: Path, archive_names: Sequence[str]) -> Dict[str, Any]:
    """What an artifact tree holds, scanned by shape rather than by name.

    The archives are secret-bearing, so the check is on what they *are*: a gzip
    stream, a file named after an archive, or a line a probe would only write if it
    printed a value. Everything here is a fact about the tree, never content.
    """
    files = [path for path in directory.rglob("*") if path.is_file()]
    gzip_files: List[str] = []
    named: List[str] = []
    markers: List[str] = []
    suffixes: List[str] = []
    for path in files:
        relative = str(path.relative_to(directory))
        if any(name and name in path.name for name in archive_names):
            named.append(relative)
        if path.name.endswith(ARTIFACT_ARCHIVE_SUFFIXES):
            suffixes.append(relative)
        try:
            content = path.read_bytes()
        except OSError:
            continue
        if content[:2] == b"\x1f\x8b":
            gzip_files.append(relative)
        for marker in ARTIFACT_FORBIDDEN_MARKERS:
            if marker.encode("utf-8") in content:
                markers.append(f"{relative}:{marker}")
    return {
        "files": len(files),
        "gzip_files": sorted(gzip_files),
        "archive_names": sorted(named),
        "archive_suffixes": sorted(suffixes),
        "secret_markers": sorted(markers),
    }


def case_backup_volume(product: MultiNodeProduct) -> Dict[str, Any]:
    """MN-BACKUP-VOL: the archives live on a run-owned volume no artifact can reach.

    Both archives are unencrypted copies of a role's credentials and lineage, so
    where they are written is part of the format's contract: the store is a mount
    of its own, root-only, named after this run, removed by the same label the
    cleanup uses — and nothing in the artifact tree is an archive, a gzip stream,
    or a line carrying a value the archive protects.
    """
    case_id = BACKUP_VOLUME_CASE_ID
    host = product.require_worker()
    volumes = getattr(host, "backup_volumes", None) or {}
    require(
        case_id,
        {"master", "worker"} <= set(volumes),
        f"the roles do not each carry an archive volume: {sorted(volumes)}",
    )
    run_suffix = str(product.podman.context.run_id).rsplit("-", 1)[-1]
    owned = product.podman.labelled_volumes()
    artifacts = Path(product.podman.context.artifact_dir)
    evidence: Dict[str, Any] = {"roles": {}}
    archive_names: List[str] = []

    for role, container, label, type_name in (
        ("master", host.target_name, "the Master", "panel"),
        ("worker", host.worker_name, "the Worker", "node"),
    ):
        name = str(volumes[role].get("name") or "")
        mountpoint = Path(str(volumes[role].get("mountpoint") or ""))
        require(
            case_id,
            name and run_suffix in name,
            f"{label}'s archive volume is named {name!r}, so it is not scoped to this run",
        )
        require(
            case_id,
            name in owned,
            f"{label}'s archive volume {name!r} does not carry this run's cleanup "
            f"label, so cleanup would leave it behind ({sorted(owned)})",
        )
        require(
            case_id,
            mountpoint.is_dir(),
            f"{label}'s archive volume {name!r} has no directory at {mountpoint}",
        )
        require(
            case_id,
            stat.S_IMODE(mountpoint.stat().st_mode) == 0o700,
            f"{label}'s archive volume {name!r} is mode "
            f"{oct(stat.S_IMODE(mountpoint.stat().st_mode))} on the host, so it is "
            "not root-only",
        )

        probed = product.podman.exec_bash(
            container, backup_volume_probe_script(), check=False,
            timeout=BACKUP_READ_TIMEOUT_SECONDS,
        )
        require(
            case_id,
            probed.returncode == 0,
            f"{label} could not describe its archive store: "
            f"{(probed.stderr or probed.stdout or '').strip()[-400:]}",
        )
        facts = parse_key_value_fields(probed.stdout or "")
        require_backup_volume(case_id, label, facts)

        created = product.podman.exec_bash(
            container, backup_script(type_name), check=False,
            timeout=BACKUP_TIMEOUT_SECONDS,
        )
        require(
            case_id,
            created.returncode == 0,
            f"{label} could not write a {type_name} archive into its volume: "
            f"{(created.stderr or created.stdout or '').strip()[-400:]}",
        )
        archive = parse_backup_archive(created.stdout or "")
        require(
            case_id,
            archive.startswith(topology.BACKUP_STORE.rstrip("/") + "/"),
            f"{label}'s {type_name} archive is at {archive!r}, which is not inside "
            f"the archive store {topology.BACKUP_STORE}",
        )
        stored = mountpoint / Path(archive).name
        require(
            case_id,
            stored.is_file(),
            f"{label}'s {type_name} archive {Path(archive).name} is not on the host "
            f"volume at {stored}",
        )
        require(
            case_id,
            stat.S_IMODE(stored.stat().st_mode) == 0o600,
            f"{label}'s {type_name} archive is mode "
            f"{oct(stat.S_IMODE(stored.stat().st_mode))} instead of 0o600",
        )
        archive_names.append(Path(archive).name)
        evidence["roles"][role] = {
            "volume": name,
            "volume_mode": "0o700",
            "filesystem": facts.get("target_type"),
            "root_filesystem": facts.get("root_type"),
            "owner": facts.get("owner"),
            "directory_mode": facts.get("mode"),
            "archive": archive,
            "archive_mode": "0o600",
            "archive_on_volume": True,
        }

    leaks = artifact_leaks(artifacts, archive_names)
    require(
        case_id,
        not leaks["gzip_files"],
        f"the artifact tree holds gzip files, so an archive reached it: {leaks['gzip_files']}",
    )
    require(
        case_id,
        not leaks["archive_names"] and not leaks["archive_suffixes"],
        f"the artifact tree holds an archive by name: {leaks['archive_names'] + leaks['archive_suffixes']}",
    )
    require(
        case_id,
        not leaks["secret_markers"],
        "the artifact tree holds a line a probe would only write by printing a "
        f"protected value: {leaks['secret_markers']}",
    )
    evidence["artifacts"] = leaks
    evidence["cleanup"] = {"labelled_volumes": sorted(owned)}
    return evidence


def master_state_probe_script() -> str:
    """What a refused restore must leave exactly as it found it.

    The service, its NGINX in front of it, the two files a panel archive replaces
    and the count of recovery snapshots: a restore that rejects its input before
    preflight changes none of them, and one that half-applies an archive changes
    at least one.
    """
    return (
        "set -u\n"
        "unit=$(systemctl is-active gowave.service 2>/dev/null || true)\n"
        "nginx=$(systemctl is-active nginx 2>/dev/null || true)\n"
        "env=$(sha256sum /opt/gowave/.env 2>/dev/null | cut -d' ' -f1 || true)\n"
        "db=$(sha256sum /opt/gowave/gowave.db 2>/dev/null | cut -d' ' -f1 || true)\n"
        "snapshots=$(find /var/lib/gowave-auto-nginx/recovery -maxdepth 1 -name 'restore-*' "
        "2>/dev/null | wc -l)\n"
        "printf 'unit=%s nginx=%s env=%s db=%s snapshots=%s\\n' "
        '"${unit}" "${nginx}" "${env}" "${db}" "${snapshots}"\n'
    )


def restore_command(archive: str, type_name: str) -> str:
    """The operator's own restore verb, on an archive the case chose."""
    return (
        f"bash {topology.REPO_IN_CONTAINER}/gowave-auto.sh restore "
        f"{shlex.quote(archive)} --type {shlex.quote(type_name)}\n"
    )


def rewrite_archive(
    source: Path,
    target: Path,
    drop: Sequence[str] = (),
    replace: Optional[Dict[str, bytes]] = None,
    manifest_drop: Sequence[str] = (),
) -> Path:
    """Copy a real archive while breaking exactly one thing about it.

    Members keep their type, mode and link target, so the only difference the
    validator can see is the one the case asked for: a removed member, a rewritten
    payload under an unchanged checksum, or a manifest that no longer declares it.
    """
    replaced = dict(replace or {})
    dropped = set(drop)
    with tarfile.open(source, "r:gz") as src:
        members = src.getmembers()
        payloads = {
            member.name: (src.extractfile(member).read() if member.isreg() else None)
            for member in members
        }
    manifest_name = next(
        (name for name in payloads if name in ("meta.json", "./meta.json")), "",
    )
    if not manifest_name:
        raise AssertionError(f"{source} carries no manifest to rewrite")
    manifest = json.loads((payloads[manifest_name] or b"{}").decode("utf-8"))
    if manifest_drop:
        manifest["files"] = [
            entry for entry in manifest.get("files") or []
            if entry.get("path") not in set(manifest_drop)
        ]
    with tarfile.open(target, "w:gz") as dst:
        for member in members:
            clean = member.name[2:] if member.name.startswith("./") else member.name
            if clean in dropped or clean == "meta.json":
                continue
            data = payloads[member.name]
            if member.isreg() and clean in replaced:
                data = replaced[clean]
            info = copy.copy(member)
            if data is not None:
                info.size = len(data)
            dst.addfile(info, io.BytesIO(data) if data is not None else None)
        blob = json.dumps(manifest).encode("utf-8")
        info = tarfile.TarInfo(manifest_name)
        info.size = len(blob)
        info.mode = 0o600
        dst.addfile(info, io.BytesIO(blob))
    target.chmod(0o600)
    return target


def rejected_archives(
    store: Path, panel: str, worker_store: Path, node: str,
) -> Dict[str, Path]:
    """One broken archive per promise of the format, all written beside the real one."""
    panel_source = store / Path(panel).name
    node_source = worker_store / Path(node).name
    created: Dict[str, Path] = {}

    truncated = store / "rejected-truncated.tar.gz"
    content = panel_source.read_bytes()
    truncated.write_bytes(content[: max(1, len(content) // 3)])
    truncated.chmod(0o600)
    created["truncated"] = truncated

    garbage = store / "rejected-garbage.tar.gz"
    garbage.write_bytes(b"not a Format v1 archive\n")
    garbage.chmod(0o600)
    created["garbage"] = garbage

    created["checksum"] = rewrite_archive(
        panel_source, store / "rejected-checksum.tar.gz",
        replace={"files/opt/gowave/.env": b"APP_SECRET=replaced-by-the-case\n"},
    )
    created["incomplete"] = rewrite_archive(
        panel_source, store / "rejected-incomplete.tar.gz",
        drop=("files/opt/gowave/.env",),
    )
    created["no-database"] = rewrite_archive(
        panel_source, store / "rejected-no-database.tar.gz",
        drop=("files/opt/gowave/gowave.db",),
        manifest_drop=("opt/gowave/gowave.db",),
    )
    wrong_type = store / "rejected-wrong-type.tar.gz"
    wrong_type.write_bytes(node_source.read_bytes())
    wrong_type.chmod(0o600)
    created["wrong-type"] = wrong_type
    return created


def case_backup_rejected(product: MultiNodeProduct) -> Dict[str, Any]:
    """MN-BACKUP-BAD: an archive that cannot deliver its contract is refused, untouched.

    A restore of a corrupt archive must not be a partial restore. Each variant below
    breaks exactly one promise the format makes — the stream reads, the manifest
    names every member, the manifest's checksums hold, the mandatory member is
    there, the archive is the type it is applied as — and each attempt has to be
    refused with a message naming that promise while the Master's service, its
    NGINX, its database, its environment and the recovery snapshot count stay
    exactly as they were.
    """
    case_id = REJECT_CASE_ID
    host = product.require_worker()
    volumes = getattr(host, "backup_volumes", None) or {}
    require(
        case_id,
        {"master", "worker"} <= set(volumes),
        f"the roles do not each carry an archive volume: {sorted(volumes)}",
    )
    stores = {role: Path(str(volumes[role].get("mountpoint") or "")) for role in ("master", "worker")}

    archives: Dict[str, str] = {}
    for role, container, type_name in (
        ("master", host.target_name, "panel"),
        ("worker", host.worker_name, "node"),
    ):
        created = product.podman.exec_bash(
            container, backup_script(type_name), check=False,
            timeout=BACKUP_TIMEOUT_SECONDS,
        )
        require(
            case_id,
            created.returncode == 0,
            f"{container} could not write the {type_name} archive this case corrupts: "
            f"{(created.stderr or created.stdout or '').strip()[-400:]}",
        )
        archive = parse_backup_archive(created.stdout or "")
        require(
            case_id,
            archive.startswith(topology.BACKUP_STORE.rstrip("/") + "/"),
            f"{container} wrote its {type_name} archive to {archive!r}, which is not "
            f"inside {topology.BACKUP_STORE}",
        )
        archives[role] = archive

    # The control: the archives the variants come from are accepted by the same
    # validator, so a rejection below is the corruption and not a broken fixture.
    for role, container, type_name in (
        ("master", host.target_name, "panel"),
        ("worker", host.worker_name, "node"),
    ):
        verified = product.podman.exec_bash(
            container, backup_verify_script(archives[role], type_name), check=False,
            timeout=BACKUP_READ_TIMEOUT_SECONDS,
        )
        require(
            case_id,
            verified.returncode == 0
            and "15-point preflight archive validation PASSED" in (verified.stdout or ""),
            f"the product's own validator refuses the untouched {type_name} archive, so "
            f"a rejection below would prove nothing: {(verified.stderr or '').strip()[-400:]}",
        )

    before = product.podman.exec_bash(
        host.target_name, master_state_probe_script(), check=False,
        timeout=REJECT_COMMAND_TIMEOUT_SECONDS,
    )
    require(
        case_id,
        before.returncode == 0,
        f"the Master state probe exited {before.returncode}: {(before.stderr or '').strip()[-400:]}",
    )
    before_facts = parse_key_value_fields(before.stdout or "")
    require(
        case_id,
        before_facts.get("unit") == "active",
        f"gowave.service is {before_facts.get('unit')!r} before the first rejection, so a "
        "service that stays up afterwards would prove nothing",
    )

    variants = rejected_archives(stores["master"], archives["master"],
                                 stores["worker"], archives["worker"])
    evidence: Dict[str, Any] = {"refused": []}
    for name, fragments in REJECT_VARIANTS:
        path = variants[name]
        inside = f"{topology.BACKUP_STORE}/{path.name}"
        result = product.podman.exec_bash(
            host.target_name, restore_command(inside, "panel"), check=False,
            timeout=REJECT_COMMAND_TIMEOUT_SECONDS,
        )
        output = (result.stdout or "") + (result.stderr or "")
        require(
            case_id,
            result.returncode != 0,
            f"the {name} archive was not refused: restore exited 0 with "
            f"{output.strip()[-400:]}",
        )
        require(
            case_id,
            "Restore completed and verified successfully." not in output,
            f"the {name} archive was refused and still reported success: "
            f"{output.strip()[-400:]}",
        )
        require(
            case_id,
            any(fragment in output for fragment in fragments),
            f"the {name} archive was refused for another reason than {fragments}: "
            f"{output.strip()[-400:]}",
        )
        require(
            case_id,
            "Traceback" not in output,
            f"the {name} archive crashed the validator instead of being refused: "
            f"{output.strip()[-400:]}",
        )
        after = product.podman.exec_bash(
            host.target_name, master_state_probe_script(), check=False,
            timeout=REJECT_COMMAND_TIMEOUT_SECONDS,
        )
        after_facts = parse_key_value_fields(after.stdout or "")
        require(
            case_id,
            after_facts == before_facts,
            f"the refused {name} archive changed the Master: it was {before_facts} and "
            f"is now {after_facts}",
        )
        message = next(
            (line.strip() for line in output.splitlines()
             if "Validation Error:" in line or line.startswith("[FAIL]")),
            output.strip().splitlines()[-1] if output.strip() else "",
        )
        evidence["refused"].append({
            "variant": name,
            "archive": inside,
            "returncode": result.returncode,
            "message": message,
            "state": after_facts,
        })

    # The Worker path is refused the same way, before its own unit is touched.
    node_before = product.podman.exec_bash(
        host.worker_name, node_env_probe_script(), check=False,
        timeout=REJECT_COMMAND_TIMEOUT_SECONDS,
    )
    node_before_facts = parse_node_env_probe(node_before.stdout or "")
    require(
        case_id,
        node_before_facts.get("active") == "active" and bool(node_before_facts.get("digest")),
        f"the Worker is not healthy enough for a refusal to mean anything: {node_before_facts}",
    )
    node_variant = stores["worker"] / "rejected-node-truncated.tar.gz"
    node_content = (stores["worker"] / Path(archives["worker"]).name).read_bytes()
    node_variant.write_bytes(node_content[: max(1, len(node_content) // 3)])
    node_variant.chmod(0o600)
    refused_node = product.podman.exec_bash(
        host.worker_name,
        restore_command(f"{topology.BACKUP_STORE}/{node_variant.name}", "node"),
        check=False, timeout=REJECT_COMMAND_TIMEOUT_SECONDS,
    )
    node_output = (refused_node.stdout or "") + (refused_node.stderr or "")
    require(
        case_id,
        refused_node.returncode != 0,
        f"the truncated Worker archive was not refused: {node_output.strip()[-400:]}",
    )
    require(
        case_id,
        "not a readable Format v1 tar.gz" in node_output
        or "could not be read back" in node_output,
        f"the truncated Worker archive was refused for another reason: {node_output.strip()[-400:]}",
    )
    node_after = product.podman.exec_bash(
        host.worker_name, node_env_probe_script(), check=False,
        timeout=REJECT_COMMAND_TIMEOUT_SECONDS,
    )
    require_node_env(case_id, "after a refused Worker restore",
                     parse_node_env_probe(node_after.stdout or ""),
                     node_before_facts.get("digest", ""))

    evidence["node_refused"] = {
        "archive": f"{topology.BACKUP_STORE}/{node_variant.name}",
        "returncode": refused_node.returncode,
        "unit": parse_node_env_probe(node_after.stdout or "").get("active"),
        "environment_unchanged": True,
    }
    evidence["control"] = {
        "panel": archives["master"],
        "node": archives["worker"],
        "validation": "15-point preflight archive validation PASSED.",
    }
    evidence["master_state"] = before_facts
    return evidence


def backup_probe_script(archive: str) -> str:
    """Read an archive back without printing a single value it protects."""
    return (
        "set -u\n"
        f"python3 - {shlex.quote(archive)} <<'PY'\n"
        "import hashlib\n"
        "import json\n"
        "import os\n"
        "import tarfile\n"
        "import sys\n"
        "\n"
        "archive = sys.argv[1]\n"
        "facts = {'path': archive}\n"
        "stat = os.stat(archive)\n"
        "facts['mode'] = oct(stat.st_mode & 0o777)\n"
        "facts['size'] = stat.st_size\n"
        "digest = hashlib.sha256()\n"
        "with open(archive, 'rb') as handle:\n"
        "    for block in iter(lambda: handle.read(65536), b''):\n"
        "        digest.update(block)\n"
        "facts['sha256'] = digest.hexdigest()\n"
        "facts['paths'] = []\n"
        "facts['declared'] = []\n"
        "facts['env_keys'] = {}\n"
        "facts['private_key_members'] = []\n"
        "facts['sqlite_header'] = False\n"
        "with tarfile.open(archive, 'r:gz') as tar:\n"
        "    members = tar.getmembers()\n"
        "    meta_name = next(\n"
        "        m.name for m in members if m.name in ('meta.json', './meta.json')\n"
        "    )\n"
        "    meta = json.load(tar.extractfile(meta_name))\n"
        "    facts['format_version'] = meta.get('format_version')\n"
        "    facts['type'] = meta.get('backup_type')\n"
        "    facts['declared'] = sorted(\n"
        "        entry.get('path', '') for entry in meta.get('files', []) if isinstance(entry, dict)\n"
        "    )\n"
        "    for member in members:\n"
        "        name = member.name\n"
        "        if member.isdir() or name in ('meta.json', './meta.json'):\n"
        "            continue\n"
        "        rel = name[6:] if name.startswith('files/') else name\n"
        "        facts['paths'].append(rel)\n"
        "        # The live/ members are symlinks into archive/; a link is counted\n"
        "        # where it sits and is never resolved, so a dangling one cannot\n"
        "        # turn a readable archive into a probe failure.\n"
        "        if member.issym() or member.islnk():\n"
        "            continue\n"
        "        payload = tar.extractfile(member)\n"
        "        if payload is None:\n"
        "            continue\n"
        "        if rel.endswith('/.env'):\n"
        "            text = payload.read().decode('utf-8', 'replace')\n"
        "            facts['env_keys'][rel] = sorted(\n"
        "                line.split('=', 1)[0].strip() for line in text.splitlines()\n"
        "                if '=' in line and not line.lstrip().startswith('#')\n"
        "            )\n"
        "        elif rel.endswith('gowave.db'):\n"
        "            facts['sqlite_header'] = payload.read(16).startswith(b'SQLite format 3')\n"
        "        elif rel.startswith('etc/letsencrypt/archive/') and rel.endswith('.pem'):\n"
        "            if b'PRIVATE KEY' in payload.read():\n"
        "                facts['private_key_members'].append(rel)\n"
        "facts['paths'] = sorted(facts['paths'])\n"
        "print(json.dumps(facts))\n"
        "PY\n"
    )


def parse_backup_archive(stdout: str) -> str:
    """The path the product reports for the archive it just wrote.

    Both archive types end with `... backup created successfully: <path>
    (mode 0600).`, and nothing else on stdout carries an absolute path, so the
    last such line names the archive that has to be read back.
    """
    for line in reversed(stdout.splitlines()):
        if "created successfully:" not in line:
            continue
        _, _, rest = line.partition("created successfully:")
        candidate = rest.strip().split(" ")[0]
        return candidate if candidate.startswith("/") else ""
    return ""


def require_backup_archive(case_id: str, role: str, facts: Dict[str, Any],
                           type_name: str) -> None:
    """One archive type carries exactly what its restore contract promises."""
    require(
        case_id,
        facts.get("format_version") == 1,
        f"{role}'s archive declares format version {facts.get('format_version')!r}, "
        "so it is not the Backup & Restore Format v1 the product documents",
    )
    require(
        case_id,
        facts.get("type") == type_name,
        f"{role}'s archive declares backup_type {facts.get('type')!r} instead of "
        f"{type_name!r}, so a restore would apply the wrong contract",
    )
    require(
        case_id,
        facts.get("mode") == "0o600",
        f"{role}'s archive is mode {facts.get('mode')} instead of 0600, so the "
        "credentials it carries are not root-only",
    )
    paths = set(facts.get("paths") or ())
    declared = set(facts.get("declared") or ())
    require(
        case_id,
        paths and declared,
        f"{role}'s archive lists its members as {sorted(paths)} and declares "
        f"{sorted(declared)}, so there is nothing to compare",
    )
    require(
        case_id,
        declared <= paths,
        f"{role}'s meta.json declares checksums for members the archive does not "
        f"carry: {sorted(declared - paths)}",
    )
    if type_name == "panel":
        missing = [path for path in BACKUP_PANEL_REQUIRED_PATHS if path not in paths]
        require(
            case_id,
            not missing,
            f"{role}'s Panel archive is missing {missing}, so a restore would not "
            "bring back that part of the installation",
        )
        for prefix in BACKUP_PANEL_REQUIRED_PREFIXES:
            require(
                case_id,
                any(path.startswith(prefix) for path in paths),
                f"{role}'s Panel archive carries no {prefix}* member, so a restore "
                "would lose that part of the installation",
            )
        require(
            case_id,
            facts.get("sqlite_header") is True,
            f"{role}'s opt/gowave/gowave.db is not a SQLite database, so the Panel "
            "archive holds no usable database",
        )
        require(
            case_id,
            facts.get("private_key_members"),
            f"{role}'s Panel archive carries no TLS private key, so it could not "
            "restore a lineage",
        )
        require(
            case_id,
            "opt/gowave/gowave-server" not in paths,
            "the Panel archive carries the Panel binary, which the archive format "
            "forbids and a restore would overwrite",
        )
        require(
            case_id,
            not any(path.startswith("opt/gowave-node/") for path in paths),
            "the Panel archive carries the Worker's credentials, so the two role "
            "archives are mixed",
        )
    else:
        require(
            case_id,
            paths == set(BACKUP_NODE_PATHS),
            f"{role}'s Worker archive carries {sorted(paths)} instead of exactly "
            f"{list(BACKUP_NODE_PATHS)}, so it is not the documented "
            "credentials-only archive",
        )
    secret_keys = facts.get("env_keys") or {}
    required_key = BACKUP_SECRET_KEYS[type_name]
    require(
        case_id,
        any(required_key in names for names in secret_keys.values()),
        f"{role}'s archive carries no {required_key} in any environment file "
        f"({sorted(secret_keys)}), so it does not hold the credential its own "
        "restore contract promises",
    )


def case_backup_types(product: MultiNodeProduct) -> Dict[str, Any]:
    """MN-BACKUP: both archive types come out of the operator's own interface.

    The archives are unencrypted and secret-bearing, so the evidence keeps the
    inventory -- member paths, declared checksums, environment key names, where
    private keys sit -- and the archive's own digest, and never a value.
    """
    case_id = BACKUP_CASE_ID
    host = product.require_worker()
    evidence: Dict[str, Any] = {"roles": {}}
    for role, container, label in (
        ("master", host.target_name, "the Master"),
        ("worker", host.worker_name, "the Worker"),
    ):
        type_name = BACKUP_TYPES[role]
        created = product.podman.exec_bash(
            container, backup_script(type_name), check=False, timeout=BACKUP_TIMEOUT_SECONDS,
        )
        require(
            case_id,
            created.returncode == 0,
            f"{label} could not create a {type_name} archive: "
            f"{(created.stderr or created.stdout or '').strip()[-400:]}",
        )
        archive = parse_backup_archive(created.stdout or "")
        require(
            case_id,
            bool(archive),
            f"{label}'s {type_name} backup did not name the archive it wrote: "
            f"{(created.stdout or '').strip()[-400:]}",
        )
        read = product.podman.exec_bash(
            container, backup_probe_script(archive), check=False,
            timeout=BACKUP_READ_TIMEOUT_SECONDS,
        )
        require(
            case_id,
            read.returncode == 0,
            f"{label} could not read its own {type_name} archive {archive}: "
            f"{(read.stderr or '').strip()[-400:]}",
        )
        try:
            facts = json.loads(read.stdout or "")
        except json.JSONDecodeError:
            raise AssertionError(
                f"{case_id}: {label} did not describe its {type_name} archive: "
                f"{(read.stdout or '').strip()[-400:]}"
            )
        require_backup_archive(case_id, label, facts, type_name)
        verified = product.podman.exec_bash(
            container, backup_verify_script(archive, type_name), check=False,
            timeout=BACKUP_READ_TIMEOUT_SECONDS,
        )
        require(
            case_id,
            verified.returncode == 0 and "PASSED" in (verified.stdout or ""),
            f"{label}'s own validator refused its {type_name} archive "
            f"{(verified.stderr or verified.stdout or '').strip()[-400:]}",
        )
        evidence["roles"][role] = {
            "type": type_name,
            "path": archive,
            "mode": facts["mode"],
            "size": facts["size"],
            "sha256": facts["sha256"],
            "members": facts["paths"],
            "declared": facts["declared"],
            "secret_keys": facts["env_keys"],
            "private_key_members": facts["private_key_members"],
            "validation": (verified.stdout or "").strip().splitlines()[-1:],
        }
    return evidence


def restore_step_script(step: str) -> str:
    """One Panel-side restore step, run where the loopback API lives."""
    return (
        f"python3 {aio.PANEL_SURFACE_SCRIPT} --scope restore --step {step} "
        f"--payload-dir {topology.PAYLOAD_MOUNT}\n"
    )


def node_env_probe_script() -> str:
    """The Worker environment's fingerprint, and nothing out of the file itself."""
    return (
        "set -u\n"
        f"digest=$(sha256sum {RESTORE_NODE_ENV} 2>/dev/null | awk '{{print $1}}')\n"
        f"sentinel=$(grep -c '^{RESTORE_SENTINEL_KEY}=' {RESTORE_NODE_ENV} 2>/dev/null || true)\n"
        "active=$(systemctl is-active gowave-node.service 2>/dev/null || true)\n"
        'printf \'digest=%s sentinel=%s active=%s\\n\' '
        '"${digest:-}" "${sentinel:-0}" "${active:-unknown}"\n'
    )


def parse_key_value_fields(output: str) -> Dict[str, str]:
    """The key=value fields a role-side probe prints, however it lays them out.

    Role probes print their facts as ``key=value`` tokens, either one per line or
    all on one line, so the report is read as a token stream; a token without a
    value carries no fact and is dropped.
    """
    values: Dict[str, str] = {}
    for token in (output or "").split():
        key, separator, value = token.partition("=")
        if separator:
            values[key.strip()] = value.strip()
    return values


def parse_node_env_probe(output: str) -> Dict[str, str]:
    return parse_key_value_fields(output)


def require_node_env(
    case_id: str, label: str, facts: Dict[str, str], digest: str,
) -> None:
    """The Worker environment is back to the exact bytes the archive captured."""
    require(
        case_id,
        facts.get("digest") == digest and bool(digest),
        f"{label}: the Worker environment hashes to {facts.get('digest')!r} instead of "
        f"the captured {digest!r}, so the restore did not restore its credentials",
    )
    require(
        case_id,
        facts.get("sentinel", "0") == "0",
        f"{label}: the Worker environment still carries the injected "
        f"{RESTORE_SENTINEL_KEY} marker, so the restore did not replace the file",
    )
    require(
        case_id,
        facts.get("active") == "active",
        f"{label}: gowave-node.service is {facts.get('active')!r} after the restore",
    )


def case_backup_restore(product: MultiNodeProduct) -> Dict[str, Any]:
    """MN-RESTORE: the product restores what a backup captured, on both roles.

    The targets are the ones this run provisioned through the operator, so a
    restore is asked to put back state those very commands created. What the
    restore has to undo is chosen to be observable without reading a secret: a
    client created through the Panel API and then deleted, and a Worker
    environment file with one marker appended. Each archive is written by the
    product, each restore is the product's own command, and the verdict comes
    from the Panel's API, the Worker's own unit, and every served outbound
    carrying a payload again.
    """
    case_id = RESTORE_CASE_ID
    host = product.require_worker()
    evidence: Dict[str, Any] = {"roles": {}}

    # ---------------------------------------------------------------- capture
    captured = product.podman.exec_bash(
        host.target_name, restore_step_script("capture"), check=False,
        timeout=RESTORE_STEP_TIMEOUT_SECONDS,
    )
    require(
        case_id,
        captured.returncode == 0,
        f"the Panel probe could not capture a client before the backup: "
        f"{(captured.stderr or captured.stdout or '').strip()[-400:]}",
    )
    try:
        capture_facts = (json.loads(captured.stdout or "") or {}).get("restore") or {}
    except json.JSONDecodeError:
        raise AssertionError(
            f"{case_id}: the capture step did not print a JSON object: "
            f"{(captured.stdout or '')[:400]}"
        )
    require(
        case_id,
        capture_facts.get("create_status") == 201,
        f"POST /api/users returned {capture_facts.get('create_status')!r} instead of 201, "
        "so there is no client for the restore to bring back",
    )
    require(
        case_id,
        capture_facts.get("readback_username_matches") is True,
        "the Panel did not read back the client it had just created",
    )
    served = {
        name: entry
        for name, entry in (capture_facts.get("representations") or {}).items()
        if isinstance(entry, dict)
    }
    require(
        case_id,
        served and all(entry.get("status") == 200 for entry in served.values()),
        f"the captured client was not served every representation: {served}",
    )
    evidence["roles"]["master"] = {
        "users_in_archive": capture_facts.get("users_in_archive"),
        "create_status": capture_facts.get("create_status"),
        "representations": served,
    }

    # ------------------------------------------------------------- the Worker
    before = product.podman.exec_bash(
        host.worker_name, node_env_probe_script(), check=False,
        timeout=RESTORE_STEP_TIMEOUT_SECONDS,
    )
    require(
        case_id,
        before.returncode == 0,
        f"the Worker environment probe exited {before.returncode}: "
        f"{(before.stderr or '').strip()[-400:]}",
    )
    env_before = parse_node_env_probe(before.stdout or "")
    require(
        case_id,
        bool(env_before.get("digest")),
        f"the Worker environment probe reported no digest: {(before.stdout or '').strip()[:200]}",
    )
    require(
        case_id,
        env_before.get("sentinel", "0") == "0",
        "the Worker environment already carries the restore marker, so the case cannot "
        "tell whether the restore replaced the file",
    )

    # ---------------------------------------------------------------- backups
    archives: Dict[str, str] = {}
    for role, container, type_name in (
        ("master", host.target_name, "panel"),
        ("worker", host.worker_name, "node"),
    ):
        created = product.podman.exec_bash(
            container, backup_script(type_name), check=False,
            timeout=BACKUP_TIMEOUT_SECONDS,
        )
        require(
            case_id,
            created.returncode == 0,
            f"the {type_name} backup this restore needs exited {created.returncode}: "
            f"{(created.stderr or created.stdout or '').strip()[-400:]}",
        )
        archive = parse_backup_archive(created.stdout or "")
        require(
            case_id,
            bool(archive),
            f"the {type_name} backup did not name the archive it wrote: "
            f"{(created.stdout or '').strip()[-400:]}",
        )
        archives[role] = archive

    # ----------------------------------------------------------- destroy state
    mutated = product.podman.exec_bash(
        host.target_name, restore_step_script("mutate"), check=False,
        timeout=RESTORE_STEP_TIMEOUT_SECONDS,
    )
    require(
        case_id,
        mutated.returncode == 0,
        f"the Panel probe could not delete the captured client: "
        f"{(mutated.stderr or mutated.stdout or '').strip()[-400:]}",
    )
    try:
        mutate_facts = (json.loads(mutated.stdout or "") or {}).get("restore") or {}
    except json.JSONDecodeError:
        raise AssertionError(
            f"{case_id}: the mutate step did not print a JSON object: "
            f"{(mutated.stdout or '')[:400]}"
        )
    require(
        case_id,
        mutate_facts.get("delete_status") == 204,
        f"DELETE /api/users/{{id}} returned {mutate_facts.get('delete_status')!r} instead of 204",
    )
    require(
        case_id,
        mutate_facts.get("user_present_after_delete") is False,
        "the Panel still lists the client after deleting it, so the restore has "
        "nothing to prove",
    )
    require(
        case_id,
        mutate_facts.get("subscription_after_delete_status") != 200,
        "the deleted client's subscription route still answered 200, so the Panel's "
        "own change never reached it",
    )

    marked = product.podman.exec_bash(
        host.worker_name,
        f"printf '%s\\n' '{RESTORE_SENTINEL_KEY}=1' >> {RESTORE_NODE_ENV}\n",
        check=False, timeout=RESTORE_STEP_TIMEOUT_SECONDS,
    )
    require(
        case_id,
        marked.returncode == 0,
        f"the case could not mark the Worker environment: {(marked.stderr or '').strip()[-400:]}",
    )
    edited = product.podman.exec_bash(
        host.worker_name, node_env_probe_script(), check=False,
        timeout=RESTORE_STEP_TIMEOUT_SECONDS,
    )
    env_edited = parse_node_env_probe(edited.stdout or "")
    require(
        case_id,
        env_edited.get("sentinel") == "1" and env_edited.get("digest") != env_before["digest"],
        f"the Worker environment did not change after the injected marker: {env_edited}",
    )

    # --------------------------------------------------------------- restores
    restored: Dict[str, Any] = {}
    for role, container, type_name in (
        ("master", host.target_name, "panel"),
        ("worker", host.worker_name, "node"),
    ):
        result = product.podman.exec_bash(
            container,
            f"bash {topology.REPO_IN_CONTAINER}/gowave-auto.sh restore "
            f"{shlex.quote(archives[role])} --type {type_name}\n",
            check=False, timeout=RESTORE_COMMAND_TIMEOUT_SECONDS,
        )
        output = (result.stdout or "") + (result.stderr or "")
        require(
            case_id,
            result.returncode == 0,
            f"the {type_name} restore exited {result.returncode}: {output.strip()[-800:]}",
        )
        require(
            case_id,
            "Restore completed and verified successfully." in output,
            f"the {type_name} restore did not report its own success: {output.strip()[-800:]}",
        )
        restored[role] = {
            "type": type_name,
            "archive": archives[role],
            "returncode": result.returncode,
            "tail": output.strip().splitlines()[-3:],
        }

    # ---------------------------------------------------------------- verify
    verify = product.podman.exec_bash(
        host.target_name, restore_step_script("verify"), check=False,
        timeout=RESTORE_STEP_TIMEOUT_SECONDS,
    )
    require(
        case_id,
        verify.returncode == 0,
        f"the Panel probe could not verify the restored state: "
        f"{(verify.stderr or verify.stdout or '').strip()[-400:]}",
    )
    try:
        verify_facts = (json.loads(verify.stdout or "") or {}).get("restore") or {}
    except json.JSONDecodeError:
        raise AssertionError(
            f"{case_id}: the verify step did not print a JSON object: "
            f"{(verify.stdout or '')[:400]}"
        )
    require(
        case_id,
        verify_facts.get("readback_status") == 200,
        f"GET /api/users/{{id}} returned {verify_facts.get('readback_status')!r} after the "
        "restore, so the deleted client did not come back",
    )
    require(
        case_id,
        verify_facts.get("username_restored") is True
        and verify_facts.get("short_uuid_restored") is True,
        f"the restored client is {verify_facts.get('username_restored')!r}/"
        f"{verify_facts.get('short_uuid_restored')!r} rather than the captured identity",
    )
    require(
        case_id,
        verify_facts.get("inventory_restored") is True,
        f"the Panel lists {verify_facts.get('users_restored')!r} clients after the "
        "restore instead of the inventory the archive captured",
    )
    identical = verify_facts.get("representations_identical") or {}
    require(
        case_id,
        identical and all(identical.values()),
        f"the restored client is not served the bytes it was served before the restore: {identical}",
    )

    after = product.podman.exec_bash(
        host.worker_name, node_env_probe_script(), check=False,
        timeout=RESTORE_STEP_TIMEOUT_SECONDS,
    )
    require_node_env(case_id, "after the restore", parse_node_env_probe(after.stdout or ""),
                     env_before["digest"])

    # The engines are only ready when a payload really leaves: the client's
    # payloads are fetched here so the readiness wait has something to send.
    product.master.subscription_payloads(case_id)
    nodes = product.wait_for_nodes(case_id, expected=2)
    traffic = product.master.wait_tunnel_ready(case_id)

    after_facts = parse_node_env_probe(after.stdout or "")
    evidence["roles"]["worker"] = {
        "environment_sha256": env_before["digest"],
        "environment_restored": after_facts.get("digest") == env_before["digest"],
        "unit": after_facts.get("active"),
    }
    evidence.update({
        "restore": restored,
        "panel": {
            "users_in_archive": capture_facts.get("users_in_archive"),
            "users_restored": verify_facts.get("users_restored"),
            "identity_restored": verify_facts.get("readback_status") == 200
            and verify_facts.get("username_restored") is True
            and verify_facts.get("short_uuid_restored") is True,
            "representations_identical": identical,
        },
        "nodes": nodes,
        "data_plane": traffic.get("delivered"),
    })
    return evidence


def cover_probe_matrix(server_ip: str, other_ip: str) -> Sequence[Dict[str, Any]]:
    """Every way the installed apex pair can fail to resolve to one role.

    One probe withholds `www.<apex>`, one withholds the apex itself, and one
    answers both with a foreign address. Each is relative to the role running
    it, so the pair is steered towards that role's own address and the refusal
    has to name exactly the half the zone failed to answer.
    """
    apex = topology.COVER_APEX
    return (
        {
            "label": "www_missing",
            "domain": topology.PANEL_DOMAIN,
            "server_ip": server_ip,
            "zone": {apex: [server_ip]},
            "answers": {apex: server_ip, f"www.{apex}": ""},
        },
        {
            "label": "apex_missing",
            "domain": topology.PANEL_DOMAIN,
            "server_ip": server_ip,
            "zone": {f"www.{apex}": [server_ip]},
            "answers": {apex: "", f"www.{apex}": server_ip},
        },
        {
            "label": "both_elsewhere",
            "domain": topology.PANEL_DOMAIN,
            "server_ip": server_ip,
            "zone": {apex: [other_ip], f"www.{apex}": [other_ip]},
            "answers": {apex: other_ip, f"www.{apex}": other_ip},
        },
    )


def cover_probe_zone(host: topology.MultiNodeTopology,
                     records: Dict[str, Sequence[str]]) -> Dict[str, Any]:
    """The installed zone with both halves of the apex answered from a probe.

    Only the two apex records are replaced: every other name keeps the answer the
    install published, so steering a probe cannot change what a later case
    resolves.
    """
    data = json.loads(json.dumps(host.zone()))
    published = data["records"]
    apex = topology.COVER_APEX
    for name in (apex, f"www.{apex}"):
        published.pop(name, None)
    for name, values in records.items():
        published[name] = {"A": list(values)}
    return data


def cover_published_answers(zone: Dict[str, Any]) -> Dict[str, str]:
    """The zone's own A answers for the apex pair, as the resolver reports them."""
    records = zone.get("records") or {}
    answers: Dict[str, str] = {}
    for name in (topology.COVER_APEX, f"www.{topology.COVER_APEX}"):
        addresses = (records.get(name) or {}).get("A") or [""]
        answers[name] = str(addresses[0])
    return answers


def cover_probe_script(role: str, probe: Dict[str, Any],
                       attempts: int = COVER_PROBE_SETTLE_ATTEMPTS,
                       settle: str = COVER_PROBE_SETTLE_SECONDS) -> str:
    """One steered pair run through this role's own copy of the decision.

    The probe waits for the steered answers to be live before it reads: the
    fixture reloads its zone on a poll and the resolver has already cached what
    the install asked it, so every attempt flushes and only a settled pair is
    handed to the decision. What the resolver finally answered is printed either
    way, so a pair that never settled is still reported rather than hidden.
    """
    apex = topology.COVER_APEX
    www = f"www.{apex}"
    answers = probe["answers"]
    return f"""set -eu
{cover_decision_loader(role)}
want_apex={shlex.quote(answers[apex])}
want_www={shlex.quote(answers[www])}
read_half() {{
    getent ahostsv4 "$1" 2>/dev/null | awk 'NR==1 {{print $1}}' || true
}}
for _ in {{1..{attempts}}}; do
    {COVER_FLUSH_SCRIPT.rstrip()}
    apex_ip=$(read_half {shlex.quote(apex)})
    www_ip=$(read_half {shlex.quote(www)})
    if [ "$apex_ip" = "$want_apex" ] && [ "$www_ip" = "$want_www" ]; then
        break
    fi
    sleep {settle}
done
printf 'resolved\\t%s\\t%s\\n' {shlex.quote(apex)} "$apex_ip"
printf 'resolved\\t%s\\t%s\\n' {shlex.quote(www)} "$www_ip"
apex=$(cover_domain_for {shlex.quote(probe['domain'])} {shlex.quote(probe['server_ip'])} 2>/dev/null || true)
reason=$(cover_domain_for {shlex.quote(probe['domain'])} {shlex.quote(probe['server_ip'])} 2>&1 >/dev/null || true)
printf 'decision\\t%s\\t%s\\t%s\\n' {shlex.quote(probe['domain'])} "$apex" "$reason"
"""


def cover_state_script(role: str, domain: str, server_ip: str,
                       answers: Dict[str, str]) -> str:
    """This role's real decision plus every file a rendered apex would leave.

    The case steered the zone and then restored it, so the pair is read the same
    way a probe reads it: flushed and retried until the restored answers are live.
    The vhost claims are read from both directories NGINX loads, and the lineage
    is read from the certificate files themselves, so "no partial decoy" and "no
    lineage issued" are facts about the deployable state rather than about the
    decision's wording.
    """
    apex = ".".join(domain.rstrip(".").split(".")[-2:])
    dirs = " ".join(shlex.quote(path) for path in COVER_VHOST_DIRS)
    return f"""set -u
{cover_decision_loader(role)}
server_ip={shlex.quote(server_ip)}
apex={shlex.quote(apex)}
want_apex={shlex.quote(answers.get(apex, ""))}
want_www={shlex.quote(answers.get(f"www.{apex}", ""))}
read_half() {{
    getent ahostsv4 "$1" 2>/dev/null | awk 'NR==1 {{print $1}}' || true
}}
for _ in {{1..{COVER_PROBE_SETTLE_ATTEMPTS}}}; do
    {COVER_FLUSH_SCRIPT.rstrip()}
    apex_ip=$(read_half "$apex")
    www_ip=$(read_half "www.$apex")
    if [ "$apex_ip" = "$want_apex" ] && [ "$www_ip" = "$want_www" ]; then
        break
    fi
    sleep {COVER_PROBE_SETTLE_SECONDS}
done
printf 'resolved\\t%s\\t%s\\n' "$apex" "$apex_ip"
printf 'resolved\\t%s\\t%s\\n' "www.$apex" "$www_ip"
hostname -I 2>/dev/null | tr ' ' '\\n' | sed '/^$/d; s/^/self\\t/' || true
decision_apex=$(cover_domain_for {shlex.quote(domain)} "$server_ip" 2>/dev/null || true)
decision_reason=$(cover_domain_for {shlex.quote(domain)} "$server_ip" 2>&1 >/dev/null || true)
printf 'decision\\t%s\\t%s\\t%s\\n' {shlex.quote(domain)} "$decision_apex" "$decision_reason"
printf 'site\\t%s\\t%s\\n' {shlex.quote(COVER_SITE_INDEX)} "$(stat -c '%s' {shlex.quote(COVER_SITE_INDEX)} 2>/dev/null || true)"
for dir in {dirs}; do
    [ -d "$dir" ] || continue
    grep -rHnE '^[[:space:]]*server_name[[:space:]]' "$dir" 2>/dev/null | sed 's/^/claim\\t/' || true
done
for cert in /etc/letsencrypt/live/*/cert.pem; do
    [ -f "$cert" ] || continue
    printf 'lineage\\t%s\\t%s\\n' "$cert" "$(openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null | tr '\\n' ' ' || true)"
done
"""


def parse_cover_state(output: str) -> Dict[str, Any]:
    """Every line the probe and state scripts print, keyed by what it measures.

    A probe script reports one decision per steered domain and the state script
    reports one for the installed domain, so decisions are keyed by the domain
    they were asked about instead of by the order they arrived in.
    """
    facts: Dict[str, Any] = {
        "resolved": {}, "self": [], "decisions": {}, "site_size": "",
        "claims": [], "lineages": {},
    }
    for line in output.splitlines():
        fields = line.split("\t")
        kind = fields[0] if fields else ""
        if kind == "resolved" and len(fields) == 3:
            facts["resolved"][fields[1]] = fields[2]
        elif kind == "decision" and len(fields) == 4:
            facts["decisions"][fields[1]] = {"apex": fields[2], "reason": fields[3]}
        elif kind == "self" and len(fields) == 2:
            facts["self"].append(fields[1])
        elif kind == "site" and len(fields) == 3:
            facts["site_size"] = fields[2]
        elif kind == "claim" and len(fields) == 2:
            facts["claims"].append(fields[1])
        elif kind == "lineage" and len(fields) == 3:
            facts["lineages"][fields[1]] = fields[2]
    return facts


def cover_decision_for(case_id: str, role: str, domain: str, facts: Dict[str, Any]) -> Dict[str, Any]:
    """The decision a role printed for one domain, or a failure naming the gap."""
    decision = facts["decisions"].get(domain)
    require(
        case_id,
        decision is not None,
        f"{role} printed no cover decision for {domain}: {sorted(facts['decisions'])}",
    )
    return decision or {}


def cover_refusal_message(names: Sequence[str], server_ip: str) -> str:
    """The operator-facing refusal, worded the way the product words it."""
    verb = "do not resolve" if len(names) > 1 else "does not resolve"
    return (
        f"Camouflage apex disabled — {' / '.join(names)} {verb} to {server_ip}, "
        "so HTTP-01 would fail."
    )


def cover_claim_names(claim: str) -> List[str]:
    """The names one `server_name` line claims, read as NGINX reads them."""
    match = re.search(r"server_name[ \t]+([^;]+);", claim)
    return match.group(1).split() if match else []


def cover_lineage_sans(text: str) -> List[str]:
    """The DNS entries of one certificate's subjectAltName extension."""
    return [token for token in re.findall(r"DNS:([^,\s]+)", text)]


def require_cover_probe(case_id: str, role: str, probe: Dict[str, Any],
                        facts: Dict[str, Any]) -> Dict[str, Any]:
    """A steered probe: the records the fixture withheld are the records named."""
    server_ip = probe["server_ip"]
    for name, expected in probe["answers"].items():
        require(
            case_id,
            facts["resolved"].get(name, "") == expected,
            f"{role}: the fixture answered {name} with "
            f"{facts['resolved'].get(name, '')!r} instead of {expected!r}, so the "
            f"{probe['label']} probe cannot stand for the pair it was steered to withhold",
        )
    failing = [name for name, expected in probe["answers"].items() if expected != server_ip]
    require(
        case_id,
        failing,
        f"{role}: the {probe['label']} probe resolves every record to {server_ip}, so it "
        "shows no refusal at all",
    )
    decision = cover_decision_for(case_id, role, probe["domain"], facts)
    require(
        case_id,
        decision.get("apex") == "",
        f"{role} rendered the apex {decision.get('apex')!r} for {probe['domain']} on the "
        f"{probe['label']} probe although only {failing} resolve to {server_ip}, so a "
        "lineage ACME cannot validate would be requested",
    )
    expected = cover_refusal_message(failing, server_ip)
    require(
        case_id,
        decision.get("reason") == expected,
        f"{role} refuses {probe['domain']} on the {probe['label']} probe with "
        f"{decision.get('reason')!r} instead of naming the records that did not resolve, "
        f"{expected!r}",
    )
    return {
        "domain": probe["domain"],
        "steered": probe["answers"],
        "apex_rendered": decision.get("apex", ""),
        "refusal": decision.get("reason", ""),
    }


def require_cover_rendered(case_id: str, role: str, domain: str, apex: str,
                           server_ip: str, facts: Dict[str, Any]) -> Dict[str, Any]:
    """Both halves resolve here, so the decoy, the page and the lineage exist."""
    require(
        case_id,
        server_ip in facts["self"],
        f"{role} does not hold {server_ip} among its own addresses {facts['self']}, so the "
        "apex cannot resolve to it",
    )
    for name in (apex, f"www.{apex}"):
        require(
            case_id,
            facts["resolved"].get(name) == server_ip,
            f"{role}: {name} resolves to {facts['resolved'].get(name)!r} instead of the "
            f"host's own {server_ip}, so this run cannot show the rendering precondition",
        )
    decision = cover_decision_for(case_id, role, domain, facts)
    require(
        case_id,
        decision.get("apex") == apex and decision.get("reason") == "",
        f"{role} decided {decision.get('apex')!r} with {decision.get('reason')!r} although "
        f"{apex} and www.{apex} both resolve to {server_ip}",
    )
    require(
        case_id,
        facts["site_size"].isdigit() and int(facts["site_size"]) > 0,
        f"{role} accepted the apex but left no rendered cover page at {COVER_SITE_INDEX}",
    )
    claimed = [name for claim in facts["claims"] for name in cover_claim_names(claim)]
    for name in (apex, f"www.{apex}"):
        require(
            case_id,
            name in claimed,
            f"{role} rendered no vhost claiming {name}: {claimed}",
        )
    sans = {path: cover_lineage_sans(text) for path, text in facts["lineages"].items()}
    covering = [
        path for path, names in sans.items()
        if apex in names and f"www.{apex}" in names
    ]
    require(
        case_id,
        covering,
        f"{role} holds no certificate covering both {apex} and www.{apex}, so the decoy "
        f"would serve a lineage ACME cannot validate: {sans}",
    )
    return {
        "server_ip": server_ip,
        "own_addresses": facts["self"],
        "apex_rendered": decision.get("apex", ""),
        "cover_page_bytes": int(facts["site_size"]),
        "covered_by": covering,
    }


def require_cover_withheld(case_id: str, role: str, domain: str, apex: str,
                           server_ip: str, answers: Dict[str, str],
                           facts: Dict[str, Any]) -> Dict[str, Any]:
    """The apex resolves elsewhere, so nothing may claim it and nothing may be issued."""
    for name, expected in answers.items():
        require(
            case_id,
            facts["resolved"].get(name, "") == expected,
            f"{role}: {name} resolves to {facts['resolved'].get(name, '')!r} instead of "
            f"{expected!r}, so this run cannot show the refusal it claims",
        )
    failing = [name for name, expected in answers.items() if expected != server_ip]
    decision = cover_decision_for(case_id, role, domain, facts)
    require(
        case_id,
        decision.get("apex") == "",
        f"{role} rendered the apex {decision.get('apex')!r} although {failing} do not "
        f"resolve to its own {server_ip}",
    )
    expected_reason = cover_refusal_message(failing, server_ip)
    require(
        case_id,
        decision.get("reason") == expected_reason,
        f"{role} refuses its apex with {decision.get('reason')!r} instead of "
        f"{expected_reason!r}",
    )
    claimed = [name for claim in facts["claims"] for name in cover_claim_names(claim)]
    for name in (apex, f"www.{apex}"):
        require(
            case_id,
            name not in claimed,
            f"{role} refused the apex but a vhost still claims {name}, leaving a partial "
            f"decoy or a stale sites-enabled entry: {claimed}",
        )
    sans = {path: cover_lineage_sans(text) for path, text in facts["lineages"].items()}
    covering = [path for path, names in sans.items() if apex in names]
    require(
        case_id,
        not covering,
        f"{role} refused the apex but already holds a lineage naming it ({covering}), so "
        f"the refusal came after issuance: {sans}",
    )
    return {
        "server_ip": server_ip,
        "apex_rendered": decision.get("apex", ""),
        "refusal": decision.get("reason", ""),
        "claimed_names": claimed,
        "lineages": sans,
    }


def case_cover_unresolved(product: MultiNodeProduct) -> Dict[str, Any]:
    """NGX-COVER-UNRESOLVED: resolution, not intent, decides whether the apex is rendered.

    The install publishes one apex for the Master, so a single run cannot show
    what a half-missing pair refuses unless the fixture zone is steered. The
    derived apex is the last two labels of the deployment domain, so a probe
    domain cannot carry an apex of its own: the probes steer the installed pair
    itself instead. Each role is asked three times — once with `www.<apex>`
    withheld, once with the apex withheld, once with both answered elsewhere —
    and every probe must refuse, name exactly the records that did not resolve,
    and render nothing.

    The installed apex is then read on both roles against the restored zone: the
    role that holds the address gets a rendered page, a claiming vhost and a
    lineage covering the pair, and the role that does not gets a refusal with no
    claim and no lineage. The zone is restored before the case returns, because
    the cases after it resolve the installed names.
    """
    case_id = COVER_UNRESOLVED_CASE_ID
    host = product.require_worker()
    master_ip = str(host.plan.target_ip)
    worker_ip = str(host.plan.worker_ip)
    other_ip = str(host.plan.echo_ip)
    base_zone = host.zone()
    evidence: Dict[str, Any] = {"installed_cover_domain": topology.COVER_APEX}
    try:
        probe_evidence: Dict[str, Any] = {}
        for key, label, container, server_ip in (
            ("master", "the Master", host.target_name, master_ip),
            ("worker", "the Worker", host.worker_name, worker_ip),
        ):
            seen: Dict[str, Any] = {}
            for probe in cover_probe_matrix(server_ip, other_ip):
                host.write_dns_zone(cover_probe_zone(host, probe["zone"]))
                steered = product.podman.exec_bash(
                    container, cover_probe_script(key, probe), check=False, timeout=120,
                )
                require(
                    case_id,
                    steered.returncode == 0,
                    f"{label} could not run the {probe['label']} cover probe: "
                    f"{(steered.stderr or '').strip()[-500:]}",
                )
                facts = parse_cover_state(steered.stdout or "")
                seen[probe["label"]] = require_cover_probe(case_id, label, probe, facts)
            probe_evidence[key] = seen
        evidence["probes"] = probe_evidence

        host.write_dns_zone(base_zone)
        restored = cover_published_answers(base_zone)
        for key, label, container, domain, server_ip, answers, rendered in (
            ("master", "the Master", host.target_name, topology.PANEL_DOMAIN, master_ip,
             {topology.COVER_APEX: master_ip,
              f"www.{topology.COVER_APEX}": master_ip}, True),
            ("worker", "the Worker", host.worker_name, host.worker_domain, worker_ip,
             {topology.COVER_APEX: master_ip,
              f"www.{topology.COVER_APEX}": master_ip}, False),
        ):
            state = product.podman.exec_bash(
                container, cover_state_script(key, domain, server_ip, restored),
                check=False, timeout=120,
            )
            require(
                case_id,
                state.returncode == 0,
                f"{label} could not report its cover state: "
                f"{(state.stderr or '').strip()[-500:]}",
            )
            facts = parse_cover_state(state.stdout or "")
            if rendered:
                evidence[key] = require_cover_rendered(
                    case_id, label, domain, topology.COVER_APEX, server_ip, facts,
                )
            else:
                evidence[key] = require_cover_withheld(
                    case_id, label, domain, topology.COVER_APEX, server_ip, answers, facts,
                )
    finally:
        # A restore failure must not replace the error the case is reporting, and
        # the zone is the fixture's own state: later cases resolve the installed
        # names, so it is put back even when a check above failed.
        try:
            host.write_dns_zone(base_zone)
        except OSError:
            pass
    evidence["zone_restored"] = True
    return evidence


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
        # The Master's rule set is read twice around this case's own connections,
        # so it runs while nothing else is dialling the host and its counters only
        # move for the attempts below.
        Case(MASTER_ACCESS_CASE_ID, "multi-node",
             lambda context: case_master_access(product),
             timeout_seconds=FIREWALL_TIMEOUT_SECONDS),
        # Both IPv6 branches in one case: the Master was installed on a host with
        # an address and the Worker on one without, so each role's own surfaces
        # say which branch its install took.
        Case(IPV6_CASE_ID, "multi-node",
             lambda context: case_ipv6_policy(product),
             timeout_seconds=IPV6_TIMEOUT_SECONDS),
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
    # Losing the Worker's daemon is the same trust question as SSHKEY asked from
    # the other side. It cannot run before the Worker is registered: its baseline
    # payload has to traverse the Worker, which only the provisioned cluster
    # carries. It runs here because the matrix above has warmed both nodes' data
    # planes, and it restores the unit itself before returning.
    suite.append(Case(
        SSH_DOWN_CASE_ID, "multi-node", lambda context: case_ssh_service_down(product),
        timeout_seconds=SSH_DOWN_TIMEOUT_SECONDS,
    ))
    suite.extend([
        Case("SUB-SERVED", "multi-node", lambda context: aio.case_subscriptions(product.master),
             timeout_seconds=SUB_SERVED_TIMEOUT_SECONDS),
        Case("SUB-B64", "multi-node", lambda context: aio.case_share_links(product.master),
             timeout_seconds=SUB_SHARE_LINK_TIMEOUT_SECONDS),
        # Both roles' trees are validated and reloaded before the lifecycle cases:
        # revocation and the Worker's own outage must not be read through a
        # configuration change this case made.
        Case(NGINX_CONFIG_CASE_ID, "multi-node", lambda context: case_nginx_config(product),
             timeout_seconds=NGX_CONFIG_CASE_TIMEOUT_SECONDS),
        # Both roles' public certificates are measured before the lifecycle cases
        # for the same reason: a Worker outage or restart must not be read
        # through a handshake this case would otherwise have taken first.
        Case(aio.TLS_CASE_ID, "multi-node", lambda context: case_tls_surface(product),
             timeout_seconds=TLS_CASE_TIMEOUT_SECONDS),
        # Both decoys are read while the cluster is healthy: the apex a vhost is
        # bound to is install-time state, so a later outage cannot change it.
        Case(COVER_DERIVE_CASE_ID, "multi-node",
             lambda context: case_cover_derive(product),
             timeout_seconds=COVER_DERIVE_TIMEOUT_SECONDS),
        # The site the apex serves is read in the same healthy window: it is the
        # page the fallback hands out, so it is measured before any case can
        # change the tree or the listener it is served from.
        Case(COVER_SITE_CASE_ID, "multi-node",
             lambda context: case_cover_site(product),
             timeout_seconds=COVER_SITE_TIMEOUT_SECONDS),
        # The decoy's route is install-time state on both roles, so it is read in
        # the same healthy window: the socket bindings, the stream map and the
        # lineage cannot change behind a case that faulted a role later.
        Case(DECOY_ROUTE_CASE_ID, "multi-node",
             lambda context: case_decoy_route(product),
             timeout_seconds=DECOY_ROUTE_TIMEOUT_SECONDS),
        # The refusal case steers the fixture zone and puts it back before it
        # returns, so it runs beside the other reads of a healthy cluster.
        Case(COVER_UNRESOLVED_CASE_ID, "multi-node",
             lambda context: case_cover_unresolved(product),
             timeout_seconds=COVER_UNRESOLVED_TIMEOUT_SECONDS),
        # Both archive types are read while the cluster is healthy and before the
        # lifecycle cases revoke a client or fault a role: the credentials and the
        # lineages they carry are install-time state of exactly those roles.
        Case(BACKUP_CASE_ID, "multi-node", lambda context: case_backup_types(product),
             timeout_seconds=BACKUP_TIMEOUT_SECONDS),
        # The volume case writes one archive per role into the store, so it runs
        # immediately after the archive contracts and while both roles are whole.
        Case(BACKUP_VOLUME_CASE_ID, "multi-node", lambda context: case_backup_volume(product),
             timeout_seconds=BACKUP_VOLUME_TIMEOUT_SECONDS),
        # Every refusal below is proven against the same live Master, so it runs
        # before the restore changes what that state is, and after the archive
        # formats it corrupts have been read.
        Case(REJECT_CASE_ID, "multi-node", lambda context: case_backup_rejected(product),
             timeout_seconds=REJECT_CASE_TIMEOUT_SECONDS),
        # The restore runs beside the backup it depends on being possible, and
        # before the lifecycle cases: it puts the cluster back the way the
        # operator built it instead of reading what a fault left behind.
        Case(RESTORE_CASE_ID, "multi-node", lambda context: case_backup_restore(product),
             timeout_seconds=RESTORE_CASE_TIMEOUT_SECONDS),
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
        # This case re-provisions the Worker and then changes the Master's own
        # names, so it runs after every case that reads the installed cluster:
        # nothing after it may be blamed for the domains it installs.
        Case(ACME80_CASE_ID, "multi-node", lambda context: case_acme80(product),
             timeout_seconds=ACME80_TIMEOUT_SECONDS),
    ])
    return suite
