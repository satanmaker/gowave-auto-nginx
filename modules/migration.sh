#!/usr/bin/env bash
# modules/migration.sh - read-only inspection of an installed deployment and the
# confirmation gate that lets a rerun adopt the identity the host already serves.
#
# Nothing here writes: an inspection that reported a change it had already made
# could not be declined, and the point of the gate is that a host which predates
# the explicit ownership record keeps serving what it serves until its operator
# says otherwise.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# migration_state_facts STATE_FILE
#
# The identity a deployment recorded for itself, one key=value per line. A
# missing file is a host with no deployment (`state=absent`), which is a normal
# first install rather than an error. A path this product cannot read as its own
# state is refused: reading it as an empty state would silently replace the
# record an operator depends on.
migration_state_facts() {
    local state_file="$1"
    # A fresh host has no state file, and this inspection runs before
    # `bootstrap_early_tools` has put python3 on the host. Reading the absence in
    # shell keeps a first install from needing the interpreter it is about to
    # install; a state file that exists is only ever on a host an earlier install
    # already prepared, so the JSON parse below still has python3. `! -e && ! -L`
    # is the shell form of `os.path.lexists`: a dangling symlink is still present
    # and must be refused, not read as a first install.
    if [[ ! -e "$state_file" && ! -L "$state_file" ]]; then
        printf 'state=absent\n'
        return 0
    fi
    PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 - "$state_file" <<'PY'
import json
import os
import sys

path = sys.argv[1]
if not os.path.lexists(path):
    print("state=absent")
    raise SystemExit(0)
if os.path.islink(path) or not os.path.isfile(path):
    sys.stderr.write("Error: %s is not a regular file; refusing to read it as deployment state.\n" % path)
    raise SystemExit(1)
try:
    with open(path, encoding="utf-8") as handle:
        state = json.load(handle)
except (OSError, ValueError) as exc:
    sys.stderr.write("Error: cannot read %s: %s.\n" % (path, exc.__class__.__name__))
    raise SystemExit(1)
if not isinstance(state, dict):
    sys.stderr.write("Error: %s does not hold a state object.\n" % path)
    raise SystemExit(1)


def text(value):
    return value if isinstance(value, str) and value else "-"


schema = state.get("schemaVersion")
print("state=present")
print("schema=%d" % schema if type(schema) is int else "schema=missing")
print("installation_mode=%s" % text(state.get("installationMode")))

ownership = state.get("domainOwnership")
names = ownership.get("names") if isinstance(ownership, dict) else None
if not isinstance(names, dict):
    names = {}
role = ownership.get("role") if isinstance(ownership, dict) else None
print("ownership=%s" % ("explicit" if names else "legacy"))
print("recorded.role=%s" % (text(role) if role in ("master", "worker") else "-"))
for field in ("panel", "reality", "vision", "cover", "coverAlias"):
    print("recorded.%s=%s" % (field, text(names.get(field))))

# The transport names an older installer recorded beside the ownership record.
# They are what this host already serves, so they are subtracted from the names
# its decoy vhost carries just like the explicit ones.
for field, key in (("panel", "panelDomain"), ("reality", "realityDomain"), ("vision", "visionDomain")):
    print("legacy.%s=%s" % (field, text(state.get(key))))

lineages = state.get("certificateLineages")
if not isinstance(lineages, dict):
    lineages = {}
for role_name in ("panel", "reality", "vision"):
    print("recorded.lineage.%s=%s" % (role_name, text(lineages.get(role_name))))

nodes = state.get("nodes") if isinstance(state.get("nodes"), list) else []
registered = [node for node in nodes if isinstance(node, dict)]
print("recorded.nodes=%d" % len(registered))
print("recorded.node_uuids=%d" % sum(1 for node in registered if text(node.get("uuid")) != "-"))
print("recorded.host_uuids=%d" % sum(
    1 for node in registered
    if isinstance(node.get("hostUuids"), list) and node["hostUuids"]
))
PY
}

# migration_rendered_facts CONF_DIRECTORY
#
# What the managed NGINX configuration serves right now: the names on the decoy
# vhost and the certificate directory each listener references. Only files this
# product renders are read, and a managed path that is a symlink or not a
# regular file is refused rather than followed -- the same rule the install
# applies before it writes one.
migration_rendered_facts() {
    local conf_dir="$1"
    python3 - "$conf_dir" <<'PY'
import os
import re
import sys

directory = sys.argv[1]


def managed(path):
    """Read one managed file, refusing anything that is not the regular file we wrote."""
    if not os.path.lexists(path):
        return ""
    if os.path.islink(path) or not os.path.isfile(path):
        sys.stderr.write("Error: %s is not a regular file; refusing to read a managed vhost through it.\n" % path)
        raise SystemExit(1)
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except OSError as exc:
        sys.stderr.write("Error: cannot read %s: %s.\n" % (path, exc.__class__.__name__))
        raise SystemExit(1)


def first_match(pattern, body):
    match = re.search(pattern, body, re.MULTILINE)
    return match.group(1).strip() if match else ""


def certificate_directory(body):
    """The live directory a listener serves, from its ssl_certificate path."""
    path = first_match(r"^\s*ssl_certificate\s+([^;]+);", body)
    if path.endswith("/fullchain.pem"):
        return os.path.dirname(path)
    return ""


decoy = managed(os.path.join(directory, "gowave-decoy.conf"))
print("rendered.decoy_names=%s" % (first_match(r"^\s*server_name\s+([^;]+);", decoy) or "-"))
print("rendered.certificate.panel=%s" % (
    certificate_directory(managed(os.path.join(directory, "gowave-panel.conf"))) or "-"))
print("rendered.certificate.reality=%s" % (certificate_directory(decoy) or "-"))
print("rendered.certificate.vision=%s" % (
    certificate_directory(managed(os.path.join(directory, "gowave-vision-fallback.conf"))) or "-"))
PY
}

# migration_inspect_state STATE_FILE [CONF_DIRECTORY]
#
# Print the deployment's recorded identity beside the one its managed files
# serve, classify the run, and return what a caller has to do about it:
#
#   0  nothing to confirm: a fresh host, or an explicit ownership record
#   2  a legacy host whose identity has to be confirmed before any change
#   1  a state this installer will not act on (unreadable, unsafe, newer schema)
#
# The cover apex is never guessed from a transport name. It is a candidate only
# when the rendered decoy vhost actually names it, and two candidates are an
# ambiguity that is reported instead of resolved.
migration_inspect_state() {
    local state_file="$1"
    local conf_dir="${2:-/etc/nginx/conf.d}"
    local facts rendered=""

    facts=$(migration_state_facts "$state_file") || return 1

    local state="" schema="" mode="" ownership="" role="" panel="" reality="" vision=""
    local cover="" cover_alias="" lineage_panel="" lineage_reality="" lineage_vision=""
    local legacy_panel="" legacy_reality="" legacy_vision=""
    local nodes="0" node_uuids="0" host_uuids="0"
    local key value
    while IFS='=' read -r key value; do
        case "$key" in
            state) state="$value" ;;
            schema) schema="$value" ;;
            installation_mode) mode="$value" ;;
            ownership) ownership="$value" ;;
            recorded.role) role="$value" ;;
            recorded.panel) panel="$value" ;;
            recorded.reality) reality="$value" ;;
            recorded.vision) vision="$value" ;;
            recorded.cover) cover="$value" ;;
            recorded.coverAlias) cover_alias="$value" ;;
            recorded.lineage.panel) lineage_panel="$value" ;;
            recorded.lineage.reality) lineage_reality="$value" ;;
            recorded.lineage.vision) lineage_vision="$value" ;;
            legacy.panel) legacy_panel="$value" ;;
            legacy.reality) legacy_reality="$value" ;;
            legacy.vision) legacy_vision="$value" ;;
            recorded.nodes) nodes="$value" ;;
            recorded.node_uuids) node_uuids="$value" ;;
            recorded.host_uuids) host_uuids="$value" ;;
        esac
    done <<< "$facts"

    printf '%s\n' "$facts"

    if [[ "$state" == "absent" ]]; then
        echo "rendered.decoy_names=-"
        echo "rendered.certificate.panel=-"
        echo "rendered.certificate.reality=-"
        echo "rendered.certificate.vision=-"
        echo "candidate_cover="
        echo "candidate_alias="
        echo "ambiguity="
        echo "rendered.conflict="
        echo "action=none"
        echo "reason=no deployment state on this host"
        return 0
    fi

    # A state this installer is older than cannot be migrated by guessing what
    # its extra fields mean; the operator has to run the version that wrote it.
    if [[ "$schema" != "missing" ]] && (( schema > 2 )); then
        echo "candidate_cover="
        echo "candidate_alias="
        echo "ambiguity="
        echo "rendered.conflict="
        echo "action=block"
        echo "reason=state schema $schema is newer than this installer understands"
        return 1
    fi

    rendered=$(migration_rendered_facts "$conf_dir") || return 1
    printf '%s\n' "$rendered"

    local decoy_names="" rendered_panel="" rendered_reality="" rendered_vision=""
    while IFS='=' read -r key value; do
        case "$key" in
            rendered.decoy_names) decoy_names="$value" ;;
            rendered.certificate.panel) rendered_panel="$value" ;;
            rendered.certificate.reality) rendered_reality="$value" ;;
            rendered.certificate.vision) rendered_vision="$value" ;;
        esac
    done <<< "$rendered"

    local candidate="" alias="" ambiguity=""
    local -a apexes=() leftovers=()
    local token
    for token in $decoy_names; do
        [[ -n "$token" && "$token" != "-" && "$token" != "_" ]] || continue
        [[ "$token" == "$panel" || "$token" == "$reality" || "$token" == "$vision" ]] && continue
        [[ "$token" == "$legacy_panel" || "$token" == "$legacy_reality" || "$token" == "$legacy_vision" ]] && continue
        leftovers+=("$token")
    done
    for token in "${leftovers[@]}"; do
        [[ "$token" == www.* ]] || apexes+=("$token")
    done
    if (( ${#apexes[@]} == 1 )); then
        candidate="${apexes[0]}"
        if [[ " ${leftovers[*]} " == *" www.${candidate} "* ]]; then
            alias="www.${candidate}"
        fi
        if [[ ! "$candidate" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]]; then
            ambiguity="the rendered decoy names $candidate, which is not a DNS name this installer can own"
            candidate=""
            alias=""
        fi
    elif (( ${#apexes[@]} > 1 )); then
        ambiguity="the rendered decoy names more than one cover apex (${apexes[*]}); GOWAVE_COVER_DOMAIN selects one"
    elif (( ${#leftovers[@]} > 0 )); then
        ambiguity="the rendered decoy names only an alias (${leftovers[*]}) and no apex"
    else
        ambiguity="the rendered decoy names no cover apex of its own"
    fi

    local action="none" reason="the recorded ownership is explicit"
    if [[ "$ownership" != "explicit" ]]; then
        action="confirm"
        reason="legacy state records no explicit cover ownership"
    fi

    # The listener is what a client reaches, so a recorded path the vhosts do
    # not serve is drift worth naming even when the ownership record is intact.
    local conflict=""
    if [[ "$rendered_panel" != "-" && "$lineage_panel" != "-" && "$rendered_panel" != "$lineage_panel" ]]; then
        conflict="the Panel listener serves $rendered_panel but state records $lineage_panel"
    elif [[ "$rendered_reality" != "-" && "$lineage_reality" != "-" && "$rendered_reality" != "$lineage_reality" ]]; then
        conflict="the REALITY listener serves $rendered_reality but state records $lineage_reality"
    fi

    echo "candidate_cover=${candidate}"
    echo "candidate_alias=${alias}"
    echo "ambiguity=${ambiguity}"
    echo "rendered.conflict=${conflict}"
    echo "action=${action}"
    echo "reason=${reason}"

    if [[ "$action" == "confirm" ]]; then
        return 2
    fi
    return 0
}

# migration_confirm_existing STATE_FILE [CONF_DIRECTORY]
#
# Show what an existing host serves and what a migration would adopt, then wait
# for the operator's own word. Nothing is written either way:
#
#   0  nothing to migrate, or the migration was confirmed
#   3  the operator declined; the deployment is unchanged
#   1  the inspection failed, or no terminal can confirm it
#
# A non-interactive run confirms with GOWAVE_MIGRATE_EXISTING=yes, because a
# prompt with no terminal is a `read` under `set -e` and nothing on either
# stream. Silence is not consent: without either answer the run stops before
# the first mutation.
migration_confirm_existing() {
    local state_file="$1"
    local conf_dir="${2:-/etc/nginx/conf.d}"
    local report="" rc=0
    report=$(migration_inspect_state "$state_file" "$conf_dir") || rc=$?
    if (( rc == 1 )); then
        return 1
    fi
    if (( rc == 0 )); then
        return 0
    fi

    local key value action="" reason="" candidate="" alias="" ambiguity="" conflict=""
    local panel="" reality="" vision="" role="" nodes="0" node_uuids="0" host_uuids="0"
    local legacy_panel="" legacy_reality="" legacy_vision=""
    local rendered_panel="" rendered_reality="" rendered_vision=""
    while IFS='=' read -r key value; do
        case "$key" in
            action) action="$value" ;;
            reason) reason="$value" ;;
            candidate_cover) candidate="$value" ;;
            candidate_alias) alias="$value" ;;
            ambiguity) ambiguity="$value" ;;
            rendered.conflict) conflict="$value" ;;
            recorded.role) role="$value" ;;
            recorded.panel) panel="$value" ;;
            recorded.reality) reality="$value" ;;
            recorded.vision) vision="$value" ;;
            legacy.panel) legacy_panel="$value" ;;
            legacy.reality) legacy_reality="$value" ;;
            legacy.vision) legacy_vision="$value" ;;
            recorded.nodes) nodes="$value" ;;
            recorded.node_uuids) node_uuids="$value" ;;
            recorded.host_uuids) host_uuids="$value" ;;
            rendered.certificate.panel) rendered_panel="$value" ;;
            rendered.certificate.reality) rendered_reality="$value" ;;
            rendered.certificate.vision) rendered_vision="$value" ;;
        esac
    done <<< "$report"

    # A legacy record keeps its transport names outside the ownership block; the
    # preview names what this host actually serves, from whichever field holds it.
    [[ "$panel" != "-" ]] || panel="$legacy_panel"
    [[ "$reality" != "-" ]] || reality="$legacy_reality"
    [[ "$vision" != "-" ]] || vision="$legacy_vision"

    printf 'An existing deployment is already installed at %s.\n' "$state_file"
    printf '  %s.\n' "$reason"
    printf '  Recorded panel name:   %s\n' "$panel"
    printf '  Recorded REALITY name: %s\n' "$reality"
    if [[ "$vision" != "-" ]]; then
        printf '  Recorded Vision name:  %s\n' "$vision"
    fi
    if [[ -n "$candidate" ]]; then
        printf '  Cover apex to adopt:   %s (named by the rendered decoy vhost)\n' "$candidate"
        if [[ -n "$alias" ]]; then
            printf '  Cover alias to adopt:  %s\n' "$alias"
        fi
    else
        printf '  Cover apex to adopt:   none proven on this host\n'
    fi
    if [[ "$rendered_panel" != "-" ]]; then
        printf '  Panel certificate:     %s\n' "$rendered_panel"
    fi
    if [[ "$rendered_reality" != "-" ]]; then
        printf '  REALITY certificate:   %s\n' "$rendered_reality"
    fi
    if [[ "$rendered_vision" != "-" ]]; then
        printf '  Vision certificate:    %s\n' "$rendered_vision"
    fi
    if [[ "$nodes" != "0" ]]; then
        printf '  Registered identity:   %s node(s), %s with a UUID, %s with Host records — kept, not recreated\n' \
            "$nodes" "$node_uuids" "$host_uuids"
    fi
    if [[ -n "$ambiguity" ]]; then
        printf '  Ambiguity: %s.\n' "$ambiguity"
        printf '  No cover apex is adopted while the evidence is ambiguous; this run serves the cover site only if GOWAVE_COVER_DOMAIN selects one.\n'
    fi
    if [[ -n "$conflict" ]]; then
        printf '  Drift: %s.\n' "$conflict"
    fi
    printf 'Migration records this identity and re-renders the owned configuration from it; the names, certificates and registered identities above are reused, not replaced.\n'

    if [[ "${GOWAVE_MIGRATE_EXISTING:-}" == "yes" ]]; then
        printf 'Migration confirmed by GOWAVE_MIGRATE_EXISTING=yes.\n'
        return 0
    fi
    if [[ -t 0 ]]; then
        local answer=""
        read -r -p "Adopt this identity and continue? [y/N]: " answer
        case "$answer" in
            [Yy]|yes|YES)
                printf 'Migration confirmed.\n'
                return 0
                ;;
            *)
                printf 'Migration declined. The existing deployment is unchanged.\n'
                return 3
                ;;
        esac
    fi
    printf 'Error: this existing deployment needs an explicit migration confirmation, and there is no terminal to ask on.\n' >&2
    printf 'Rerun with GOWAVE_MIGRATE_EXISTING=yes to adopt the identity shown above, or take no action to leave the host unchanged.\n' >&2
    return 1
}

# migration_adopted_cover STATE_FILE [CONF_DIRECTORY]
#
# The cover apex a confirmed legacy migration adopts: the one the host's own
# decoy vhost names. Prints nothing when the host records its ownership already,
# when no apex is proven, or when the evidence is ambiguous — a run that selects
# a cover itself is never overridden by this.
migration_adopted_cover() {
    local state_file="$1"
    local conf_dir="${2:-/etc/nginx/conf.d}"
    local report="" rc=0
    report=$(migration_inspect_state "$state_file" "$conf_dir") || rc=$?
    if (( rc == 1 )); then
        return 1
    fi
    (( rc == 2 )) || return 0

    local key value candidate="" alias=""
    while IFS='=' read -r key value; do
        case "$key" in
            candidate_cover) candidate="$value" ;;
            candidate_alias) alias="$value" ;;
        esac
    done <<< "$report"
    [[ -n "$candidate" ]] || return 0
    printf '%s\n' "$candidate"
}

# node_confirm_edge_migration WORKER_NAME WORKER_DOMAIN REALITY_DOMAIN VISION_DOMAIN NODE_PORT
#
# `node reapply` streams the payload again, which rewrites the Worker's edge
# routes and certificate references. The Panel registration, the node UUID, its
# profile and its Host records are reused as they are; what changes is the
# traffic plane on that one host. That change needs the operator's own word:
#
#   0  confirmed (interactively or by GOWAVE_MIGRATE_EXISTING=yes)
#   3  declined; nothing is streamed and the Worker is untouched
#   1  no terminal and no confirmation
node_confirm_edge_migration() {
    local name="$1"
    local worker_domain="$2"
    local reality_domain="$3"
    local vision_domain="${4:-}"
    local node_port="$5"

    printf 'Edge migration preview for Worker %s:\n' "$name"
    printf '  Primary name (XHTTP/WS/gRPC + static cover): %s -> 127.0.0.1:7443\n' "$worker_domain"
    printf '  Camouflage name (REALITY SNI):              %s -> 127.0.0.1:8443\n' "$reality_domain"
    if [[ -n "$vision_domain" ]]; then
        printf '  Optional Vision name:                       %s -> 127.0.0.1:8444\n' "$vision_domain"
    fi
    printf '  Management and subscription paths are refused; Node API stays on %s.\n' "$node_port"
    printf 'The Panel registration, node UUID, profile and Host records are reused; only this host'"'"'s edge configuration is rewritten.\n'

    if [[ "${GOWAVE_MIGRATE_EXISTING:-}" == "yes" ]]; then
        printf 'Migration confirmed by GOWAVE_MIGRATE_EXISTING=yes.\n'
        return 0
    fi
    if [[ -t 0 ]]; then
        local answer=""
        read -r -p "Rewrite this Worker's edge configuration? [y/N]: " answer
        case "$answer" in
            [Yy]|yes|YES)
                printf 'Migration confirmed.\n'
                return 0
                ;;
            *)
                printf 'Migration declined. The Worker is unchanged.\n'
                return 3
                ;;
        esac
    fi
    printf 'Error: re-applying a Worker rewrites its edge configuration, and there is no terminal to confirm it on.\n' >&2
    printf 'Rerun `gowave-auto.sh node reapply <name>` from a terminal, or pass GOWAVE_MIGRATE_EXISTING=yes to confirm; either way the Worker is left unchanged until then.\n' >&2
    return 1
}
