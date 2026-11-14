"""Failure diagnostics: what the machine looked like when a case failed.

An assertion message names a contradiction, not a cause. When a case fails the
run therefore captures, from every container it still owns, the state an
operator asks for first. The areas follow the change ledger's list — operator,
service, systemd, network, TLS, DNS, client, endpoint — and each one is a single
shell probe whose output is written through ``RunContext.evidence_text``, so it
is redacted, made 0600, handed to the invoking operator, and named in the case's
``evidence_files``.

Three rules keep the bundle from becoming a second, quieter test:

* Collection never decides anything. The probes read state and assert nothing,
  and a probe that fails, times out, or meets a container that has already
  exited reports that instead of changing the verdict.
* The bundle is time-bounded end to end. A wedged host cannot turn a one-minute
  failure into a stalled run, and every file says whether it is complete or was
  truncated.
* Nothing secret is printed. Environment files are listed by key only, keys and
  passwords travel through ``redact()`` like any other evidence, and private key
  material is never read.

The containers are discovered from the run label rather than from the products,
because a case can fail before the object that would have named its roles
exists.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from .runner import CaseResult, RunAborted, RunContext

# One probe reads a small amount of local state; the cap is what a hung
# ``systemctl`` or ``journalctl`` needs, not what a healthy host costs.
PROBE_TIMEOUT_SECONDS = 25
# The whole bundle stays inside a minute and a half even on a wedged host.
BUNDLE_BUDGET_SECONDS = 90
# journal tails and rule dumps are the only outputs that can grow; the marker
# below is what makes a truncated file distinguishable from a short one.
OUTPUT_LIMIT_BYTES = 64 * 1024
# A case message can carry a traceback; the header repeats it in every area file.
MESSAGE_LIMIT_BYTES = 4 * 1024

# The names the installed vhosts answer for. The product writes them into nginx,
# so they are its own statement of what it serves, and they are the names the
# TLS and DNS probes use instead of a harness-side list that could drift.
_VHOST_NAMES = r'''
gowave_vhost_names() {
    sed -n 's/.*server_name[[:space:]]*\([^;{}]*\);.*/\1/p' \
        /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* 2>/dev/null |
        tr ' ' '\n' | grep -v '^$' | grep -v '^_' | sort -u
}
'''

_OPERATOR = r'''
echo "== operator identity =="
id 2>&1
echo "== root home =="
ls -la /root 2>&1 | head -40
echo "== credential file =="
stat -c '%a %U:%G %s %y %n' /root/gowave-credentials.txt 2>&1
echo "== panel installation =="
ls -la /opt/gowave 2>&1 | head -30
echo "== panel environment keys (values withheld) =="
sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p' /opt/gowave/.env 2>&1 | sort
echo "== node installation =="
ls -la /opt/gowave-node 2>&1 | head -30
echo "== node environment keys (values withheld) =="
sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p' /opt/gowave-node/.env 2>&1 | sort
echo "== mutation lock =="
stat -c '%a %U:%G %s %y %n' /run/lock/gowave-managed-mutation.lock 2>&1
echo "== state directories =="
ls -la /etc/gowave* /var/lib/gowave* 2>&1 | head -30
echo "== installed operator command =="
ls -l /usr/local/bin/gowave* 2>&1
'''

_SERVICE = r'''
for unit in gowave gowave-node nginx fail2ban; do
    echo "== $unit =="
    printf 'is-active: '; systemctl is-active "$unit" 2>&1
    printf 'is-enabled: '; systemctl is-enabled "$unit" 2>&1
    systemctl show -p ActiveState -p SubState -p MainPID -p ExecMainStatus -p NRestarts "$unit" 2>&1
done
echo "== running services =="
systemctl list-units --type=service --state=running --no-pager 2>&1 | head -40
'''

_SYSTEMD = r'''
echo "== system state =="
systemctl is-system-running 2>&1
echo "== failed units =="
systemctl --failed --no-pager 2>&1
for unit in gowave gowave-node nginx fail2ban; do
    echo "== journal: $unit (last 40) =="
    journalctl -q -u "$unit" -n 40 --no-pager -o short-iso 2>&1
done
echo "== journal errors (last 20) =="
journalctl -q -p err -n 20 --no-pager -o short-iso 2>&1
echo "== uptime =="
uptime 2>&1
'''

_NETWORK = r'''
echo "== interfaces =="
ip -br addr 2>&1
echo "== routes =="
ip route 2>&1
ip -6 route 2>&1
echo "== listeners =="
ss -ltnup 2>&1
echo "== resolvers =="
cat /etc/resolv.conf 2>&1
echo "== ufw =="
ufw status verbose 2>&1
echo "== iptables =="
iptables -S 2>&1 | head -100
echo "== ip6tables =="
ip6tables -S 2>&1 | head -60
'''

_TLS = r'''
echo "== certificate directory =="
ls -la /etc/letsencrypt/live 2>&1
for fullchain in /etc/letsencrypt/live/*/fullchain.pem; do
    [ -f "$fullchain" ] || continue
    echo "== $fullchain =="
    openssl x509 -in "$fullchain" -noout -subject -issuer -dates -serial -fingerprint -sha256 2>&1
    printf 'certificates in chain: '
    grep -c 'BEGIN CERTIFICATE' "$fullchain" 2>&1
done
echo "== renewal configuration =="
ls -la /etc/letsencrypt/renewal 2>&1
echo "== certbot inventory =="
certbot certificates 2>&1 | head -40
echo "== certificate served on 443 =="
name=$(gowave_vhost_names | head -1)
printf 'probe SNI: %s\n' "${name:-none}"
if [ -n "${name:-}" ]; then
    echo | timeout 10 openssl s_client -connect 127.0.0.1:443 -servername "$name" 2>&1 |
        openssl x509 -noout -subject -issuer -dates 2>&1
fi
'''

_DNS = r'''
echo "== resolver configuration =="
cat /etc/resolv.conf 2>&1
echo "== resolved status =="
resolvectl status 2>&1 | head -40
echo "== names the product serves =="
names=$(gowave_vhost_names | head -10)
printf '%s\n' $names
for name in $names; do
    echo "== $name =="
    getent ahosts "$name" 2>&1
    if command -v dig >/dev/null 2>&1; then
        dig +short "$name" 2>&1
    fi
done
'''

_CLIENT = r'''
echo "== client engines =="
for binary in xray mihomo sing-box; do
    if command -v "$binary" >/dev/null 2>&1; then
        echo "== $binary =="
        "$binary" version 2>&1 | head -3
    fi
done
echo "== client home =="
ls -la /root 2>&1 | head -25
echo "== client listeners =="
ss -ltnup 2>&1
echo "== client journal (last 30) =="
journalctl -q -n 30 --no-pager -o short-iso 2>&1
'''

_ENDPOINT = r'''
echo "== panel API on loopback =="
curl -sS -o /dev/null -w 'HTTP %{http_code} from http://127.0.0.1:7443/\n' --max-time 5 \
    http://127.0.0.1:7443/ 2>&1
echo "== node control port =="
curl -skS -o /dev/null -w 'HTTP %{http_code} from https://127.0.0.1:3002/\n' --max-time 5 \
    https://127.0.0.1:3002/ 2>&1
echo "== nginx configuration test =="
nginx -t 2>&1 | head -20
'''


@dataclass(frozen=True)
class Area:
    name: str
    purpose: str
    script: str


# One probe per area, in the ledger's order. Each runs inside every container the
# run owns, so a role that never received the product answers "no such unit"
# instead of being silently skipped.
AREAS: Tuple[Area, ...] = (
    Area("operator", "what the operator's install left behind, with values withheld", _OPERATOR),
    Area("service", "unit state of the managed services", _SERVICE),
    Area("systemd", "system state, failed units, and service journals", _SYSTEMD),
    Area("network", "interfaces, routes, listeners, resolvers, and firewall rules", _NETWORK),
    Area("tls", "issued certificates and the one served on 443", _VHOST_NAMES + _TLS),
    Area("dns", "resolver configuration and the product's names as resolved here", _VHOST_NAMES + _DNS),
    Area("client", "client engines, their listeners, and their last journal lines", _CLIENT),
    Area("endpoint", "the product's own endpoints as this host sees them", _ENDPOINT),
)


def _safe(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._-")
    return cleaned or "case"


def _clip(text: str, limit: int = OUTPUT_LIMIT_BYTES) -> str:
    if len(text) <= limit:
        return text
    return f"{text[:limit]}\n[output clipped at {limit} bytes of {len(text)}]"


def _probe(podman: Any, container: str, area: Area) -> str:
    """Run one area probe in one container and describe whatever came back."""
    try:
        proc = podman.exec_bash(container, area.script, check=False, timeout=PROBE_TIMEOUT_SECONDS)
    except RunAborted:
        # Best-effort collection stops here: the operator asked the run to end,
        # and an interrupt swallowed as "probe could not run" would keep it alive.
        raise
    except Exception as exc:  # a wedged or removed container is a fact, not a failure
        return f"[probe could not run: {type(exc).__name__}: {exc}]"
    stdout = (getattr(proc, "stdout", "") or "").rstrip()
    stderr = (getattr(proc, "stderr", "") or "").rstrip()
    returncode = getattr(proc, "returncode", "")
    parts = [stdout if stdout else "[no output]"]
    if stderr:
        parts.append(f"[stderr]\n{stderr}")
    parts.append(f"[exit {returncode}]")
    return _clip("\n".join(parts))


def collect(
    context: RunContext,
    podman: Any,
    result: CaseResult,
    budget_seconds: float = BUNDLE_BUDGET_SECONDS,
) -> List[str]:
    """Write the failure bundle for ``result`` and name the files it produced."""
    started = time.monotonic()
    deadline = started + budget_seconds

    listing_error = ""
    try:
        containers: List[Dict[str, str]] = list(podman.run_containers())
    except RunAborted:
        raise
    except Exception as exc:
        containers = []
        listing_error = f"{type(exc).__name__}: {exc}"

    directory = f"diagnostics/{_safe(result.id)}"
    written: List[str] = []
    skipped = 0
    probed = 0
    failures: List[str] = []

    for area in AREAS:
        header = [
            f"case: {result.id}",
            f"status: {result.status}",
            f"message: {_clip(result.message, MESSAGE_LIMIT_BYTES)}",
            f"area: {area.name} — {area.purpose}",
            f"containers: {len(containers)}",
        ]
        if listing_error:
            header.append(f"[container listing failed: {listing_error}]")
        chunks = ["\n".join(header), ""]
        truncated_here = 0
        for container in containers:
            name = str(container.get("name") or "")
            state = str(container.get("state") or container.get("status") or "unknown")
            chunks.append(f"==== {name} ({state}) ====")
            if not name:
                chunks.append("[skipped: the container has no name]")
                truncated_here += 1
                continue
            if time.monotonic() > deadline:
                chunks.append("[skipped: the diagnostic bundle ran out of time]")
                truncated_here += 1
                continue
            chunks.append(_probe(podman, name, area))
            probed += 1
            chunks.append("")
        if truncated_here:
            skipped += truncated_here
            failures.append(f"{area.name}: {truncated_here} probe(s) not run")
            chunks.append(f"[bundle truncated: {truncated_here} probe(s) not run]")
        else:
            chunks.append(f"[bundle complete: {len(containers)} container(s) probed]")
        path = context.evidence_text(f"{directory}/{area.name}.txt", "\n".join(chunks))
        written.append(str(path.relative_to(context.artifact_dir)))

    index = [
        f"case: {result.id}",
        f"status: {result.status}",
        f"message: {_clip(result.message, MESSAGE_LIMIT_BYTES)}",
        "collector: tools/podman_e2e/diagnostics.py",
        f"bundle budget: {budget_seconds}s, probe timeout: {PROBE_TIMEOUT_SECONDS}s",
        f"duration: {time.monotonic() - started:.2f}s",
        f"probes run: {probed}, not run: {skipped}",
        "containers:",
    ]
    if listing_error:
        index.append(f"  [container listing failed: {listing_error}]")
    if not containers:
        index.append("  [none: the run owned no container when this case failed]")
    for container in containers:
        index.append(
            f"  {container.get('name')} {container.get('state') or container.get('status') or 'unknown'}"
        )
    index.append("areas:")
    for area, path in zip(AREAS, written):
        index.append(f"  {area.name}: {path}")
    if failures:
        index.append("incomplete:")
        index.extend(f"  {line}" for line in failures)
    path = context.evidence_text(f"{directory}/index.txt", "\n".join(index))
    written.insert(0, str(path.relative_to(context.artifact_dir)))
    return written
