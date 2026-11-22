"""Reusable /etc/hosts block helper for the pinned Xray core acceptance proof.

This module provides a container-agnostic way to block a hostname by pointing it
at an address nothing serves (127.0.0.2), and to verify the block is in force
from inside the container. It is used by both the AIO and Multi-Node topologies
to prove that node installation places the pinned core before the upstream
installer runs, and that an installation with the pin opted out fails when the
release API is unreachable.
"""
from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any, Dict, Optional

from .podman import Podman as PodmanContext
from .runner import Case, require

# The release API host that the pin replaces. Blocking it proves the installer
# does not reach GitHub when the pin is in force.
PINNED_CORE_BLOCKED_HOST = "api.github.com"
# 127.0.0.2 is used instead of 127.0.0.1 because the product's own NGINX
# listens on 127.0.0.1:443; a TLS error from it is a weaker observation than a
# refused connection from an address nothing binds.
PINNED_CORE_BLOCK_ADDRESS = "127.0.0.2"
# The marker identifies this harness's entry in /etc/hosts so it can be removed
# cleanly even if the file is rewritten between the install and a later case.
PINNED_CORE_BLOCK_MARKER = "gowave-e2e-pinned-core-block"
# The hosts file the product manages; the ACME installer rewrites it, so the
# block must be re-applied after any product operation that touches it.
ACME_HOSTS_FILE = "/etc/hosts"

# The shell script template. It is pure shell + getent + /dev/tcp so it runs on
# a pristine target image before the product installs python3.
_HOSTS_BLOCK_SCRIPT = r"""MODE=MODE_PLACEHOLDER
HOST=HOST_PLACEHOLDER
ADDRESS=ADDRESS_PLACEHOLDER
MARKER=MARKER_PLACEHOLDER
HOSTS=HOSTS_PLACEHOLDER
PORT=PORT_PLACEHOLDER

# The probe runs before the product installs anything, so it may not assume a
# single package the operator is responsible for: on a pristine target image
# there is no python3 yet, and the observation has to be made anyway. Everything
# below is shell, getent and /dev/tcp, which the base image does ship.
set_host_entry() {
    # Install one entry, or drop this marker's own line when the address is empty.
    # ``/etc/hosts`` is a bind mount, so the new bytes go into the same inode: a
    # rename over it would replace the mount point instead of the file.
    local host="$1" address="$2" marker="$3" staged="" rc=0
    staged="$(mktemp </dev/null)" || { printf 'mktemp failed\n' >&2; exit 9; }
    if [ -e "$HOSTS" ]; then
        grep -v -F -- "$marker" "$HOSTS" > "$staged" </dev/null
        rc=$?
        if [ "$rc" -gt 1 ]; then
            rm -f "$staged"
            printf 'cannot read %s\n' "$HOSTS" >&2
            exit 9
        fi
    fi
    if [ -n "$address" ]; then
        printf '%s %s  # %s\n' "$address" "$host" "$marker" >> "$staged"
    fi
    cat "$staged" > "$HOSTS" || { rm -f "$staged"; exit 9; }
    sync
    rm -f "$staged"
}

json_string() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g'
}

address="$ADDRESS"
[ "$MODE" = "install" ] || address=""
set_host_entry "$HOST" "$address" "$MARKER"

resolution=""
if command -v getent >/dev/null 2>&1; then
    resolution="$(getent hosts "$HOST" 2>/dev/null </dev/null | tr '\n' ' ' | sed -e 's/[[:space:]]*$//')"
fi
marker_count="$(grep -c -F -- "$MARKER" "$HOSTS" 2>/dev/null </dev/null)"
[ -n "$marker_count" ] || marker_count=0

# A restored name resolves to the real service, and this harness does not contact
# it: the request is measured only while the entry is in place. One connect, made
# in a subshell so its refusal is a status instead of the end of the probe, with
# its own stdin so it cannot consume the script this shell is still reading.
request="null"
if [ -n "$address" ]; then
    request_error="$( ( exec 3<>"/dev/tcp/$HOST/$PORT" ) 2>&1 </dev/null)"
    request_status=$?
    # bash answers a refusal in two lines; the report is one line, so the message
    # is flattened rather than escaped, and the status is read before the pipe.
    request_error="$(printf '%s' "$request_error" | tr '\n' ' ' | sed -e 's/[[:space:]]*$//')"
    request="$(printf '{"returncode": %d, "stdout": "%s", "stderr": ""}' \
        "$request_status" "$(json_string "$request_error")")"
fi

printf '{"mode": "%s", "host": "%s", "address": "%s", "resolution": "%s", "marker_count": %s, "request": %s}\n' \
    "$MODE" "$(json_string "$HOST")" "$address" "$(json_string "$resolution")" \
    "$marker_count" "$request"
"""


def hosts_block_script(
    mode: str,
    host: str,
    address: str = PINNED_CORE_BLOCK_ADDRESS,
    marker: str = PINNED_CORE_BLOCK_MARKER,
    hosts_file: str = ACME_HOSTS_FILE,
    port: int = 443,
) -> str:
    """Return the shell script that installs or removes one /etc/hosts entry.

    ``install`` rewrites the file rather than appending, so re-applying the block
    after anything else has rewritten ``/etc/hosts`` is the same call.
    """
    return (
        _HOSTS_BLOCK_SCRIPT
        .replace("MODE_PLACEHOLDER", shlex.quote(mode))
        .replace("ADDRESS_PLACEHOLDER", shlex.quote(address))
        .replace("MARKER_PLACEHOLDER", shlex.quote(marker))
        .replace("HOSTS_PLACEHOLDER", shlex.quote(hosts_file))
        .replace("PORT_PLACEHOLDER", str(int(port)))
        .replace("HOST_PLACEHOLDER", shlex.quote(host))
    )


def probe_json(case_id: str, label: str, result: Any) -> Dict[str, Any]:
    """Parse the probe's JSON output, raising CaseBlocked on failure."""
    stdout = (result.stdout or "").strip()
    if result.returncode != 0:
        raise CaseBlocked(
            f"{case_id}: {label} probe exited {result.returncode}: {stdout[:500]}"
        )
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise CaseBlocked(
            f"{case_id}: {label} probe produced invalid JSON: {exc} — {stdout[:500]}"
        )


def hosts_block_facts(
    podman: PodmanContext,
    container: str,
    case_id: str,
    mode: str = "install",
    role: str = "",
    host: str = PINNED_CORE_BLOCKED_HOST,
    address: str = PINNED_CORE_BLOCK_ADDRESS,
    timeout: int = 120,
) -> Dict[str, Any]:
    """Apply or remove the block in one container and report what the name answers.

    The report comes from inside the container, so it describes the resolution and
    the request that this host makes rather than the ones the harness can make.
    """
    script = hosts_block_script(mode, host, address, marker=PINNED_CORE_BLOCK_MARKER)
    result = podman.exec_bash(container, script, check=False, timeout=timeout)
    return probe_json(
        case_id, f"the {role or container} hosts entry for {host} ({mode})", result,
    )


def require_host_blocked(case_id: str, role: str, facts: Dict[str, Any]) -> Dict[str, Any]:
    """Verify the name answers the block address and a request to it is refused.

    Two readings, because neither alone is the claim: the resolution proves the
    entry is the one in force, and the refused connection proves nothing answers
    the address the name now names.
    """
    blocked_host = str(facts.get("host") or PINNED_CORE_BLOCKED_HOST)
    address = PINNED_CORE_BLOCK_ADDRESS
    resolution = str(facts.get("resolution") or "")
    request = facts.get("request") or {}
    require(
        case_id,
        facts.get("mode") == "install" and facts.get("address") == address,
        f"{role}: the block on {blocked_host} is not in force; the probe reports "
        f"{facts.get('mode')!r} for {facts.get('address')!r}",
    )
    require(
        case_id,
        address in resolution,
        f"{role}: {blocked_host} resolves to {resolution!r} instead of the block address {address}, "
        "so the install could reach the release API the pin is supposed to replace",
    )
    require(
        case_id,
        request.get("returncode") not in (0, None),
        f"{role}: a request to {blocked_host} answered (exit {request.get('returncode')!r}) although "
        f"nothing serves {address}, so the block did not take effect",
    )
    return {
        "host": blocked_host,
        "address": address,
        "resolution": resolution,
        "marker_count": facts.get("marker_count"),
        "request_returncode": request.get("returncode"),
        "request_error": (request.get("stdout") or request.get("stderr") or "").strip()[-300:],
    }


def pinned_core_digests() -> tuple:
    """The archive digests this checkout pins, read from the shipped table.

    Reading the module keeps one table: the install prints the digest it verified,
    and the case compares that line with the file the release ships rather than
    with a copy of the value kept here.
    """
    import re
    text = (Path(__file__).resolve().parents[2] / "modules" / "xray_core.sh").read_text(encoding="utf-8")
    return tuple(
        re.findall(r'^GOWAVE_PINNED_XRAY_(?:AMD64|ARM64)_SHA256="([0-9a-f]{64})"$', text, re.M)
    )