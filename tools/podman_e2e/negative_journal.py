"""A Worker install the transport never accepted leaves no committed journal.

``openspec/changes/podman-full-e2e/specs/podman-e2e/spec.md`` §Negative Scenario
and Fault Injection Tests: when the SSH connection to a Worker is interrupted
mid-installation, the recovery journal on the Master is not ``COMMITTED`` — it is
in a failure or recovery-required state that needs an operator before the Worker
counts as registered — the recorded rollback removes the partial Panel entities
and the Worker entry from ``state.json``, and the host mutation lock is released.

The operator's own ``node add`` runs on the installed Master against an address
whose sshd never answers. The host key is pinned, as an operator pins it after
verifying the fingerprint out of band, so the product gets as far as every
operator flow does before the transport does: it registers the node with the
Panel, writes the transaction journal, appends the node to ``state.json`` and
only then dials. What the case reads afterwards is the Master's own recovery —
the journal, the state file, the Panel inventory and the mutation lock.

The remote payload therefore never starts, and the case says exactly that: the
Worker side of the compensation is ``INCOMPLETE`` because nothing on the far end
answered, which is the same verdict a drop in the middle of the payload leaves
behind on the Master. The Worker's own rollback is HOOK-03's and TXN-01's
subject; this case owns what the Master records when the far end says nothing.

A finished journal left by an earlier transaction stays in the same file: the
All-in-One contour ends its channel cases with a rolled-back update record, and
the Multi-Node contour keeps the committed record of the Worker it added. The
case sets that journal aside before the command runs and puts its own bytes back
afterwards, so the record it reads is the one this invocation wrote — it proves
that by the journal naming this transaction, not by the file having been empty.

The host is put back as it was found — the journal as found, ``state.json``
restored from the snapshot the case took, host key pin withdrawn — so a later
case is not reading this one's half-finished transaction.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tools.podman_e2e import topology
from tools.podman_e2e.runner import CaseBlocked, require

CASE_ID = "NEG-03"

#: The Worker the case registers. It is never reached: the address has no sshd
#: on the port the command is told to dial — the All-in-One host runs one on 22,
#: and its loopback answers there — and the domains are in the fixture zone, so
#: nothing has to resolve them.
WORKER_NAME = "neg03-unreachable"
WORKER_ADDRESS = "127.0.0.2"
#: A port with no listener, so the ssh client is refused at connect and the
#: payload never starts. The case checks the silence before it dials.
WORKER_SSH_PORT = "2222"
WORKER_DOMAIN = "neg03.testbed.internal"
WORKER_REALITY_DOMAIN = "neg03-reality.testbed.internal"

AUTO = f"{topology.REPO_IN_CONTAINER}/gowave-auto.sh"
PANEL_SURFACE = f"{topology.REPO_IN_CONTAINER}/tools/podman_e2e/panel_surface.py"

STATE = "/var/lib/gowave-auto-nginx/state.json"
JOURNAL = "/var/lib/gowave-auto-nginx/recovery/journal.json"
LOCK = "/run/lock/gowave-managed-mutation.lock"
KNOWN_HOSTS = "/root/.ssh/known_hosts"
CREDENTIALS = "/root/gowave-credentials.txt"

#: The transport refusals that end the dispatch without a remote side. Every one
#: of them is the ssh client's own sentence, so the case can name which happened
#: instead of assuming the connection was refused.
_REFUSAL_TOKENS = (
    "Connection refused",
    "Permission denied",
    "ssh: connect",
    "ssh: Could not resolve",
    "No route to host",
    "Connection timed out",
)

_SENTENCES = {
    "port_silent":
        "a listener answers on the Worker's SSH port, so the failure cannot be "
        "attributed to a transport that never reached a Worker",
    "pin_reaches_the_product":
        "the pinned host key does not answer ssh-keygen -F, so the product refused "
        "the address before it registered anything",
    "panel_readable_before":
        "the Panel inventory could not be read before the attempt",
    "panel_readable_after":
        "the Panel inventory could not be read after the attempt",
    "reached_the_registration":
        "the product never recorded a Worker transaction, so the interruption the case "
        "injects did not happen where it claims",
    "transport_refused":
        "no transport refusal appears in the product's own output, so the remote side "
        "may have answered and the outcome cannot be attributed to a severed transport",
    "payload_not_deployed":
        "the product printed its success line, so the Worker it could not reach is "
        "reported as deployed",
    "journal_never_committed":
        "the journal is committed for a Worker whose transport never answered",
    "journal_is_this_transaction":
        "the journal the case read is not the transaction this command wrote, so its "
        "state describes an earlier operation",
    "journal_requires_recovery":
        "the journal is not left in a state that requires an operator",
    "journal_keeps_the_action_ledger":
        "the journal kept no action ledger, so the operator cannot finish or verify "
        "the rollback it refuses to call complete",
    "both_sides_recorded":
        "the journal does not record both compensation sides, or records the Worker "
        "side as verified when nothing on it answered",
    "operator_reads_incomplete":
        "the product did not print the INCOMPLETE sentence an operator acts on",
    "panel_entities_removed":
        "the recorded rollback did not remove the partial Panel entities",
    "state_matches_snapshot":
        "state.json does not match the pre-dispatch snapshot apart from the update "
        "timestamp",
    "node_absent_from_state":
        "the Worker is still an entry in state.json after the rollback",
    "state_mode_is_private":
        "state.json is not left mode 0600",
    "mutation_lock_free":
        "the host mutation lock is still held after the command returned",
    "host_left_as_found":
        "the case did not put the Master back the way it found it",
}

_SCRIPT = r"""
set -u

STATE=__STATE__
JOURNAL=__JOURNAL__
LOCK=__LOCK__
KNOWN_HOSTS=__KNOWN_HOSTS__
CREDENTIALS=__CREDENTIALS__
AUTO=__AUTO__
SURFACE=__SURFACE__
NAME=__NAME__
ADDRESS=__ADDRESS__
PORT=__PORT__
WORKER_DOMAIN=__WORKER_DOMAIN__
REALITY_DOMAIN=__REALITY_DOMAIN__

# The host key name is the one the product computes for this port.
HOST_KEY="$ADDRESS"
[[ "$PORT" != "22" ]] && HOST_KEY="[$ADDRESS]:$PORT"

work=$(mktemp -d)
known_hosts_existed=0
[[ -e "$KNOWN_HOSTS" ]] && known_hosts_existed=1

report() { printf '%s=%s\n' "$1" "$2"; }

# Idempotent: run once at the end and once more from the trap, so a script that
# dies half way through still leaves the Master as it found it.
restore_host() {
    if [[ -f "$work/state-before.json" ]]; then
        cp -a "$work/state-before.json" "$STATE" 2>/dev/null || true
        chmod 0600 "$STATE" 2>/dev/null || true
    fi
    rm -f "$JOURNAL" "$JOURNAL.tmp" 2>/dev/null || true
    if [[ -f "$work/journal-before.json" ]]; then
        cp -a "$work/journal-before.json" "$JOURNAL" 2>/dev/null || true
    fi
    if [[ "$known_hosts_existed" == "1" && -f "$work/known_hosts-before" ]]; then
        cp -a "$work/known_hosts-before" "$KNOWN_HOSTS" 2>/dev/null || true
    else
        rm -f "$KNOWN_HOSTS" 2>/dev/null || true
    fi
    rm -f "$KNOWN_HOSTS.old" 2>/dev/null || true
}
trap 'restore_host; rm -rf "$work"' EXIT

surface_facts() {  # <file> <prefix>
python3 - "$1" "$2" "$NAME" <<'PY'
import json
import sys

path, prefix, name = sys.argv[1:4]
try:
    with open(path, "r", encoding="utf-8") as stream:
        data = json.load(stream)
except Exception:
    data = {}
surface = data.get("surface") if isinstance(data, dict) else None
surface = surface if isinstance(surface, dict) else {}
nodes = surface.get("nodes") or {}
profiles = surface.get("profiles") or {}
hosts = surface.get("hosts") or {}
names = nodes.get("names") if isinstance(nodes.get("names"), list) else []
print(f"{prefix}_nodes={nodes.get('count', -1)}")
print(f"{prefix}_profiles={profiles.get('count', -1)}")
print(f"{prefix}_hosts={hosts.get('count', -1)}")
print(f"{prefix}_worker_listed={1 if any(str(entry) == name for entry in names) else 0}")
PY
}

# 0. The host must be the one the install left: its state file and credentials
#    in place. A journal already in the file is an earlier transaction's
#    outcome, not this case's subject, so it is set aside and put back — the
#    record this case reads has to be the one the command below writes. The
#    Worker's port must have no listener, or the refusal cannot be attributed
#    to a transport that never reached it.
report journal_preexisting "$([[ -e "$JOURNAL" ]] && echo 1 || echo 0)"
report state_present "$([[ -f "$STATE" ]] && echo 1 || echo 0)"
report credentials_present "$([[ -f "$CREDENTIALS" ]] && echo 1 || echo 0)"
listeners=$(ss -ltn 2>/dev/null | awk 'NR > 1 {print $4}' | grep -cE "[:.]$PORT$" || true)
report port_silent "$([[ "${listeners:-0}" == "0" ]] && echo 1 || echo 0)"
set_aside=0
if [[ -e "$JOURNAL" ]]; then
    if [[ -f "$JOURNAL" ]] && cp -a "$JOURNAL" "$work/journal-before.json" 2>/dev/null; then
        rm -f "$JOURNAL" "$JOURNAL.tmp" 2>/dev/null || true
        set_aside=1
    fi
fi
report journal_set_aside "$set_aside"
if [[ -e "$JOURNAL" || ! -f "$STATE" || ! -f "$CREDENTIALS" || "${listeners:-0}" != "0" ]]; then
    report bailed 1
    exit 0
fi

# 1. The pre-dispatch snapshot the assertion compares against.
cp -a "$STATE" "$work/state-before.json"

python3 "$SURFACE" --scope surface > "$work/surface-before.json" 2> "$work/surface-before.err"
report panel_readable_before "$([[ -s "$work/surface-before.json" ]] && echo 1 || echo 0)"
surface_facts "$work/surface-before.json" before

# 2. Pin the host key, as an operator does after verifying the fingerprint out
#    of band: without the pin the product refuses the address before it writes
#    anything, which is a different case. The pin is a known_hosts entry —
#    address, type, key — because a bare public key line is not one, and the
#    product's own gate is `ssh-keygen -F`.
ssh_dir=$(dirname "$KNOWN_HOSTS")
mkdir -p "$ssh_dir"
chmod 0700 "$ssh_dir"
[[ -f "$KNOWN_HOSTS" ]] && cp -a "$KNOWN_HOSTS" "$work/known_hosts-before"
: >> "$KNOWN_HOSTS"
chmod 0600 "$KNOWN_HOSTS"
ssh-keygen -q -t ed25519 -N '' -f "$work/pin" >/dev/null 2>&1 || true
printf '%s %s %s\n' "$HOST_KEY" \
    "$(cut -d' ' -f1 "$work/pin.pub")" "$(cut -d' ' -f2 "$work/pin.pub")" >> "$KNOWN_HOSTS"
report pin_reaches_the_product "$(ssh-keygen -F "$HOST_KEY" -f "$KNOWN_HOSTS" >/dev/null 2>&1 && echo 1 || echo 0)"

# 3. The operator's own command, against a port whose sshd never answers. The
#    user is spelled out because the port is the argument after it.
bash "$AUTO" node add "$NAME" "$ADDRESS" "$WORKER_DOMAIN" "$REALITY_DOMAIN" root "$PORT" \
    > "$work/add.out" 2> "$work/add.err"
report add_returncode "$?"

# 4. What the Master recorded, read from the files the product wrote.
python3 - "$STATE" "$work/state-before.json" "$JOURNAL" "$work/add.out" "$work/add.err" "$NAME" <<'PY'
import json
import sys

state_path, before_path, journal_path, out_path, err_path, name = sys.argv[1:7]
refusal_tokens = __REFUSALS__


def load(path):
    try:
        with open(path, "r", encoding="utf-8") as stream:
            return json.load(stream)
    except Exception:
        return None


def read(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as stream:
            return stream.read()
    except Exception:
        return ""


def report(key, value):
    print(f"{key}={value}")


journal = load(journal_path)
report("journal_present", 1 if isinstance(journal, dict) else 0)
journal = journal if isinstance(journal, dict) else {}
entries = journal.get("entities")
entries = entries if isinstance(entries, list) else []
sides = journal.get("rollback_sides")
sides = sides if isinstance(sides, dict) else {}
report("journal_state", journal.get("state", "absent"))
report("journal_is_this_transaction",
       1 if journal.get("op") == "node_add" and journal.get("node_name") == name else 0)
report("journal_entries", len(entries))
report("journal_worker_side", sides.get("worker", "none"))
report("journal_api_side", sides.get("api", "none"))

stderr = read(err_path)
combined = read(out_path) + stderr
report("operator_reads_incomplete", 1 if "is INCOMPLETE:" in stderr else 0)
report("no_success_line", 0 if "successfully added and deployed" in combined else 1)
refusal = ""
for line in stderr.splitlines():
    if any(token in line for token in refusal_tokens):
        refusal = line.strip().replace("\n", " ")
        break
report("refusal_line", refusal or "none")

now = load(state_path)
before = load(before_path)


def scrub(data):
    if not isinstance(data, dict):
        return data
    copy = dict(data)
    copy.pop("lastUpdated", None)
    return copy


report("state_snapshot_usable", 1 if isinstance(before, dict) and before else 0)
report("state_matches_snapshot", 1 if scrub(now) == scrub(before) else 0)
nodes_now = now.get("nodes") if isinstance(now, dict) else None
nodes_before = before.get("nodes") if isinstance(before, dict) else None
report("state_nodes_before", len(nodes_before) if isinstance(nodes_before, list) else -1)
report("state_nodes_after", len(nodes_now) if isinstance(nodes_now, list) else -1)
listed = any(isinstance(node, dict) and node.get("name") == name for node in (nodes_now or []))
report("node_absent_from_state", 0 if listed else 1)
PY
report state_mode "$(stat -c '%a' "$STATE" 2>/dev/null || echo missing)"

# 5. The lock the command took: a released lock is one nothing else holds.
lock_rc=0
flock -n "$LOCK" true 2>/dev/null || lock_rc=1
report mutation_lock_free "$([[ "$lock_rc" == "0" ]] && echo 1 || echo 0)"

python3 "$SURFACE" --scope surface > "$work/surface-after.json" 2> "$work/surface-after.err"
report panel_readable_after "$([[ -s "$work/surface-after.json" ]] && echo 1 || echo 0)"
surface_facts "$work/surface-after.json" after

# 6. Put the Master back, then prove it: the journal is the one that was there
#    (byte for byte, or still absent), the state file is byte-identical to the
#    snapshot, the pin is withdrawn and the lock is free.
restore_host
state_restored=0
cmp -s "$STATE" "$work/state-before.json" && state_restored=1
journal_as_found=0
if [[ -f "$work/journal-before.json" ]]; then
    cmp -s "$JOURNAL" "$work/journal-before.json" && journal_as_found=1
elif [[ ! -e "$JOURNAL" ]]; then
    journal_as_found=1
fi
pin_gone=0
! ssh-keygen -F "$ADDRESS" -f "$KNOWN_HOSTS" >/dev/null 2>&1 && pin_gone=1
lock_free_after=0
flock -n "$LOCK" true 2>/dev/null || lock_free_after=1
report host_left_as_found \
    "$([[ "$state_restored$journal_as_found$pin_gone" == "111" && "$lock_free_after" == "0" ]] && echo 1 || echo 0)"

exit 0
"""


def driver_script() -> str:
    """The operator's command and the reads that decide what it left behind."""
    replacements = {
        "__STATE__": STATE,
        "__JOURNAL__": JOURNAL,
        "__LOCK__": LOCK,
        "__KNOWN_HOSTS__": KNOWN_HOSTS,
        "__CREDENTIALS__": CREDENTIALS,
        "__AUTO__": AUTO,
        "__SURFACE__": PANEL_SURFACE,
        "__NAME__": WORKER_NAME,
        "__ADDRESS__": WORKER_ADDRESS,
        "__PORT__": WORKER_SSH_PORT,
        "__WORKER_DOMAIN__": WORKER_DOMAIN,
        "__REALITY_DOMAIN__": WORKER_REALITY_DOMAIN,
        "__REFUSALS__": repr(_REFUSAL_TOKENS),
    }
    script = _SCRIPT
    for placeholder, value in replacements.items():
        script = script.replace(placeholder, value)
    return script


def _parse(result: Any) -> Dict[str, str]:
    """The probe's ``key=value`` lines, read back as the values the case asserts."""
    require(CASE_ID, result.returncode == 0,
            f"the interrupted node add probe exited {result.returncode}: "
            f"{(result.stderr or '').strip()[-800:]}")
    values: Dict[str, str] = {}
    for line in (result.stdout or "").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip()] = value.strip()
    return values


def _flag(values: Dict[str, str], key: str) -> bool:
    return values.get(key) == "1"


def _number(values: Dict[str, str], key: str) -> int:
    try:
        return int(values.get(key, ""))
    except ValueError:
        return -1


_REPORTED: List[str] = [
    "journal_preexisting",
    "journal_set_aside",
    "state_present",
    "credentials_present",
    "port_silent",
    "panel_readable_before",
    "before_nodes",
    "before_profiles",
    "before_hosts",
    "before_worker_listed",
    "pin_reaches_the_product",
    "add_returncode",
    "journal_present",
    "journal_state",
    "journal_is_this_transaction",
    "journal_entries",
    "journal_worker_side",
    "journal_api_side",
    "operator_reads_incomplete",
    "no_success_line",
    "refusal_line",
    "state_snapshot_usable",
    "state_matches_snapshot",
    "state_nodes_before",
    "state_nodes_after",
    "node_absent_from_state",
    "state_mode",
    "mutation_lock_free",
    "panel_readable_after",
    "after_nodes",
    "after_profiles",
    "after_hosts",
    "after_worker_listed",
    "host_left_as_found",
]


def _master_script(product: Any, script: str, timeout: int) -> Any:
    """Run the script on the Master, whichever contour the run installed.

    The All-in-One product reaches its one container through ``host_script``; the
    Multi-Node product names the Master through the topology it prepared. Both
    refuse a host that was never installed, so a failed install is reported once
    instead of as a defect of this case.
    """
    host_script = getattr(product, "host_script", None)
    if host_script is not None:
        return host_script(script, timeout=timeout)
    host = product.require_installed()
    return product.podman.exec_bash(host.target_name, script, check=False, timeout=timeout)


def case_partial_worker_install_leaves_no_committed_journal(
    product: Any, run: Any
) -> Dict[str, Any]:
    """NEG-03: a Worker whose transport never answered is not a registered Worker."""
    values = _parse(_master_script(product, driver_script(), timeout=900))

    # A journal this case cannot set aside, or a host that lost its state file
    # or its credentials, cannot answer this question: the case would be reading
    # another transaction's outcome beside its own, or inventing a defect out of
    # a broken host.
    if _flag(values, "bailed"):
        raise CaseBlocked(
            f"{CASE_ID}: the Master could not be prepared for the attempt — a recovery "
            "journal that could not be set aside, no state.json or admin credentials left "
            f"by the install, or a listener answering on {WORKER_ADDRESS}:{WORKER_SSH_PORT} "
            "— so nothing could be registered against a transport that never answers"
        )
    require(CASE_ID,
            _flag(values, "journal_preexisting") == _flag(values, "journal_set_aside"),
            "the interrupted node add probe reports a journal it neither set aside nor "
            "found absent")
    if not _flag(values, "state_present") or not _flag(values, "credentials_present"):
        raise CaseBlocked(
            f"{CASE_ID}: the Master has no state.json or no admin credentials left by "
            "the install, so nothing could be registered"
        )
    missing = [key for key in _REPORTED if key not in values]
    require(CASE_ID, not missing,
            f"the interrupted node add probe reported nothing for {', '.join(missing)}")

    before_inventory = (
        _number(values, "before_nodes"),
        _number(values, "before_profiles"),
        _number(values, "before_hosts"),
    )
    after_inventory = (
        _number(values, "after_nodes"),
        _number(values, "after_profiles"),
        _number(values, "after_hosts"),
    )
    journal_state = values.get("journal_state", "")
    evidence = {
        "journal_preexisting": _flag(values, "journal_preexisting"),
        "port_silent": _flag(values, "port_silent"),
        "pin_reaches_the_product": _flag(values, "pin_reaches_the_product"),
        "panel_readable_before": _flag(values, "panel_readable_before"),
        "panel_readable_after": _flag(values, "panel_readable_after"),
        "reached_the_registration": _flag(values, "journal_present")
        and _flag(values, "journal_is_this_transaction")
        and journal_state.startswith("NODE_ADD_"),
        "journal_is_this_transaction": _flag(values, "journal_is_this_transaction"),
        "transport_refused": values.get("refusal_line", "none") != "none",
        "payload_not_deployed": _flag(values, "no_success_line"),
        "journal_never_committed": journal_state != "NODE_ADD_COMMITTED",
        "journal_requires_recovery": journal_state == "NODE_ADD_ROLLBACK_REQUIRED",
        "journal_keeps_the_action_ledger": _number(values, "journal_entries") > 0,
        "both_sides_recorded": (
            values.get("journal_worker_side") == "INCOMPLETE"
            and values.get("journal_api_side") == "ROLLED_BACK"
        ),
        "operator_reads_incomplete": _flag(values, "operator_reads_incomplete"),
        "panel_entities_removed": (
            not _flag(values, "after_worker_listed")
            and before_inventory == after_inventory
        ),
        "state_matches_snapshot": (
            _flag(values, "state_snapshot_usable")
            and _flag(values, "state_matches_snapshot")
        ),
        "node_absent_from_state": _flag(values, "node_absent_from_state"),
        "state_mode_is_private": values.get("state_mode") == "600",
        "mutation_lock_free": _flag(values, "mutation_lock_free"),
        "host_left_as_found": _flag(values, "host_left_as_found"),
        "add_returncode": _number(values, "add_returncode"),
        "journal_state": journal_state,
        "journal_entries": _number(values, "journal_entries"),
        "journal_worker_side": values.get("journal_worker_side", ""),
        "journal_api_side": values.get("journal_api_side", ""),
        "refusal_line": values.get("refusal_line", "none"),
        "panel_inventory_before": "/".join(str(item) for item in before_inventory),
        "panel_inventory_after": "/".join(str(item) for item in after_inventory),
    }
    refused = [_SENTENCES[key] for key in _SENTENCES if not evidence[key]]
    if refused:
        raise AssertionError(
            f"{CASE_ID}: " + "; ".join(refused)
            + f" (journal {evidence['journal_state']!r} with Worker "
              f"{evidence['journal_worker_side']!r} and API "
              f"{evidence['journal_api_side']!r}, panel "
              f"{evidence['panel_inventory_before']} -> "
              f"{evidence['panel_inventory_after']}, exit {evidence['add_returncode']})"
        )
    return evidence
