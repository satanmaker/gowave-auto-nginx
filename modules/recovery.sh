#!/usr/bin/env bash
# modules/recovery.sh - Transaction-safe updates, channel switching, and crash recovery
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${SCRIPT_DIR}/modules/lock.sh"
RECOVERY_PY="${SCRIPT_DIR}/modules/recovery.py"
RECOVERY_DIR="${RECOVERY_DIR:-/var/lib/gowave-auto-nginx/recovery}"
JOURNAL_FILE="${JOURNAL_FILE:-${RECOVERY_DIR}/journal.json}"
STATE_FILE="${STATE_FILE:-/var/lib/gowave-auto-nginx/state.json}"
CREDENTIALS_FILE="${CREDENTIALS_FILE:-/root/gowave-credentials.txt}"
GOWAVE_DIR="${GOWAVE_DIR:-/opt/gowave}"

ensure_private_recovery_directory() {
    local dir="$1"
    local current="" component metadata owner mode
    local -a components=()

    if [[ "$dir" != /* || "$dir" == "/" || "$dir" == *"//"* ]]; then
        echo "CRITICAL: recovery directory path must be normalized and absolute, not filesystem root." >&2
        return 1
    fi

    # Reject symlinks in every existing path component, not only the leaf.
    IFS='/' read -r -a components <<< "$dir"
    for component in "${components[@]}"; do
        [[ -z "$component" ]] && continue
        if [[ "$component" == "." || "$component" == ".." ]]; then
            echo "CRITICAL: recovery directory path must not contain dot segments." >&2
            return 1
        fi
        current+="/$component"
        if [[ -L "$current" ]]; then
            echo "CRITICAL: recovery directory path contains a symlink: $current" >&2
            return 1
        fi
    done

    mkdir -p -- "$dir" || {
        echo "CRITICAL: cannot create recovery directory." >&2
        return 1
    }

    # Recheck after creation to catch a replaced path before changing permissions.
    current=""
    for component in "${components[@]}"; do
        [[ -z "$component" ]] && continue
        if [[ "$component" == "." || "$component" == ".." ]]; then
            echo "CRITICAL: recovery directory path must not contain dot segments." >&2
            return 1
        fi
        current+="/$component"
        if [[ -L "$current" ]]; then
            echo "CRITICAL: recovery directory path was replaced by a symlink: $current" >&2
            return 1
        fi
    done
    if [[ "$dir" == "/" || ! -d "$dir" || -L "$dir" ]]; then
        echo "CRITICAL: recovery path must be a dedicated real directory, not a filesystem root." >&2
        return 1
    fi

    metadata=$(stat -c '%u:%a' -- "$dir") || {
        echo "CRITICAL: cannot verify recovery directory ownership and permissions." >&2
        return 1
    }
    owner="${metadata%%:*}"
    if [[ "$owner" != "$(id -u)" ]]; then
        echo "CRITICAL: recovery directory must be owned by the current user." >&2
        return 1
    fi

    chmod 0700 -- "$dir" || {
        echo "CRITICAL: cannot enforce private recovery directory permissions." >&2
        return 1
    }
    metadata=$(stat -c '%u:%a' -- "$dir") || {
        echo "CRITICAL: cannot verify recovery directory ownership and permissions." >&2
        return 1
    }
    owner="${metadata%%:*}"
    mode="${metadata#*:}"
    if [[ "$owner" != "$(id -u)" || "$mode" != "700" ]]; then
        echo "CRITICAL: recovery directory must be owned by the current user and have mode 0700." >&2
        return 1
    fi
}

ensure_recovery_dir() {
    case "$RECOVERY_DIR" in
        */recovery) ;;
        *)
            echo "CRITICAL: RECOVERY_DIR must name a dedicated 'recovery' directory." >&2
            return 1
            ;;
    esac
    ensure_private_recovery_directory "$RECOVERY_DIR"
}

take_preflight_db_snapshot() {
    local target_snapshot_dir="$1"
    local db_path="${2:-$GOWAVE_DIR/gowave.db}"

    ensure_recovery_dir
    ensure_private_recovery_directory "$target_snapshot_dir"

    echo "Executing transactional SQLite Online Backup..." >&2
    PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
import sys
for p in ['$SCRIPT_DIR', '/opt/gowave-auto-nginx']:
    if p not in sys.path:
        sys.path.insert(0, p)
from modules.recovery import sqlite_online_backup
sqlite_online_backup('$db_path', '$target_snapshot_dir/gowave.db')
"
    echo "Database snapshot saved to $target_snapshot_dir/gowave.db." >&2
}

prepare_update_snapshot() {
    local target_version="$1"
    local ts
    ts=$(date +%s)
    local snap_dir="${RECOVERY_DIR}/update-${ts}"

    ensure_recovery_dir
    ensure_private_recovery_directory "$snap_dir"

    echo "Capturing pre-update persistent recovery snapshot in $snap_dir..." >&2

    # 1. Database snapshot
    take_preflight_db_snapshot "$snap_dir" "$GOWAVE_DIR/gowave.db" >&2

    # 2. Copy current binaries and configuration
    if [[ -f "$GOWAVE_DIR/.env" ]]; then
        cp "$GOWAVE_DIR/.env" "$snap_dir/.env"
    fi
    if [[ -f "$GOWAVE_DIR/gowave-server" ]]; then
        cp "$GOWAVE_DIR/gowave-server" "$snap_dir/gowave-server"
    fi
    if [[ -d "$GOWAVE_DIR/frontend" ]]; then
        cp -a "$GOWAVE_DIR/frontend" "$snap_dir/frontend"
    fi

    # Domain/channel operations also mutate NGINX and ACME state.
    if [[ "$(id -u)" -eq 0 ]]; then
        if [[ -d /etc/nginx ]]; then
            mkdir -p "$snap_dir/etc"
            cp -a /etc/nginx "$snap_dir/etc/nginx"
        fi
        if [[ -d /etc/letsencrypt ]]; then
            mkdir -p "$snap_dir/etc"
            cp -a /etc/letsencrypt "$snap_dir/etc/letsencrypt"
        fi
    fi
    if [[ -f "$STATE_FILE" ]]; then
        cp -p "$STATE_FILE" "$snap_dir/state.json"
    fi

    # 3. Write durable state journal
    python3 -c "
import sys, time
for p in ['$SCRIPT_DIR', '/opt/gowave-auto-nginx']:
    if p not in sys.path:
        sys.path.insert(0, p)
from modules.recovery import write_journal_atomically
data = {
    'transaction_id': 'update-$ts',
    'op': 'update',
    'state': 'PREPARED',
    'target_version': '$target_version',
    'snapshot_dir': '$snap_dir',
    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
}
write_journal_atomically('$JOURNAL_FILE', data)
"
    echo "Recovery snapshot and PREPARED journal written." >&2
    echo "$snap_dir"
}

update_journal_state() {
    local state="$1"
    PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 - "$JOURNAL_FILE" "$state" <<'PY'
import sys, time
from modules.recovery import load_journal_file, write_journal_atomically
path, state = sys.argv[1], sys.argv[2]
data = load_journal_file(path)
data["state"] = state
data["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
write_journal_atomically(path, data)
PY
}

execute_file_rollback() {
    local snap_dir="$1"
    echo "Rolling back GoWave files from snapshot $snap_dir..." >&2
    [[ -d "$snap_dir" ]] || { echo "Recovery snapshot does not exist: $snap_dir" >&2; return 1; }

    # Each step is checked here rather than left to `set -e`. Every caller has to
    # test this function's result — a boot recovery decides whether to report
    # ROLLED_BACK, a channel switch decides whether to roll back at all — and a
    # function invoked in a condition runs with errexit switched off, which would
    # turn a failed copy into a rollback that reports success.
    if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        if ! systemctl stop --no-ask-password gowave.service; then
            echo "Rollback could not stop gowave.service." >&2
            return 1
        fi
    fi

    if [[ -f "$snap_dir/gowave.db" ]]; then
        local db_tmp="$GOWAVE_DIR/.gowave.db.rollback"
        if ! cp -p "$snap_dir/gowave.db" "$db_tmp" \
           || ! chmod 0640 "$db_tmp" \
           || ! rm -f "$GOWAVE_DIR/gowave.db-wal" "$GOWAVE_DIR/gowave.db-shm" \
           || ! mv -f "$db_tmp" "$GOWAVE_DIR/gowave.db"; then
            echo "Rollback could not restore the database snapshot." >&2
            return 1
        fi
        if id -u gowave >/dev/null 2>&1; then
            if ! chown gowave:gowave "$GOWAVE_DIR/gowave.db"; then
                echo "Rollback could not hand the restored database to the gowave user." >&2
                return 1
            fi
        fi
    fi
    if [[ -f "$snap_dir/.env" ]]; then
        if ! install -m 0640 "$snap_dir/.env" "$GOWAVE_DIR/.env"; then
            echo "Rollback could not restore the environment file." >&2
            return 1
        fi
        if id -u gowave >/dev/null 2>&1; then
            if ! chown root:gowave "$GOWAVE_DIR/.env"; then
                echo "Rollback could not hand the restored environment to the gowave group." >&2
                return 1
            fi
        fi
    fi
    if [[ -f "$snap_dir/gowave-server" ]]; then
        if ! install -m 0755 "$snap_dir/gowave-server" "$GOWAVE_DIR/gowave-server"; then
            echo "Rollback could not restore the Panel binary." >&2
            return 1
        fi
    fi
    if [[ -d "$snap_dir/frontend" ]]; then
        if ! rm -rf "$GOWAVE_DIR/frontend" \
           || ! cp -a "$snap_dir/frontend" "$GOWAVE_DIR/frontend"; then
            echo "Rollback could not restore the frontend tree." >&2
            return 1
        fi
    fi
    if [[ -f "$snap_dir/state.json" ]]; then
        if ! install -m 0600 "$snap_dir/state.json" "$STATE_FILE"; then
            echo "Rollback could not restore state.json." >&2
            return 1
        fi
    fi

    # The ACME state has to be in place before anything validates the NGINX tree:
    # every generated server block points ssl_certificate at /etc/letsencrypt/live,
    # so `nginx -t` reads the lineage this step restores. Validating first would
    # make a corrupted lineage abort the rollback of everything else.
    if [[ -d "$snap_dir/etc/letsencrypt" ]]; then
        [[ "$(id -u)" -eq 0 ]] || { echo "Root is required to restore ACME certificates." >&2; return 1; }
        if ! mkdir -p /etc/letsencrypt \
           || ! cp -a "$snap_dir/etc/letsencrypt/." /etc/letsencrypt/; then
            echo "Rollback could not restore the ACME state." >&2
            return 1
        fi
    fi
    if [[ -d "$snap_dir/etc/nginx" ]]; then
        [[ "$(id -u)" -eq 0 ]] || { echo "Root is required to restore NGINX configuration." >&2; return 1; }
        if ! cp -a "$snap_dir/etc/nginx/." /etc/nginx/; then
            echo "Rollback could not restore the NGINX tree." >&2
            return 1
        fi
        if ! nginx -t; then
            echo "Rollback restored an NGINX tree its own test rejects." >&2
            return 1
        fi
    fi

    if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        # A release that failed to start burns the unit's start burst; without
        # clearing it the compensating restart is refused as "start request
        # repeated too quickly" and a restored tree would look unstartable.
        systemctl reset-failed --no-ask-password gowave.service >/dev/null 2>&1 || true
        if ! systemctl restart --no-ask-password gowave.service \
           || ! systemctl is-active --quiet gowave.service; then
            echo "Rollback restored the tree but gowave.service is not active." >&2
            return 1
        fi
        if command -v nginx >/dev/null 2>&1 && [[ -d "$snap_dir/etc/nginx" ]]; then
            if ! nginx -t \
               || ! systemctl reload nginx \
               || ! systemctl is-active --quiet nginx; then
                echo "Rollback could not return NGINX to service." >&2
                return 1
            fi
        fi
    fi
    echo "File rollback completed and services verified." >&2
}

rollback_channel_switch() {
    local snap_dir="$1"
    local reason="$2"
    echo "Channel switch failed: $reason" >&2
    echo "Restoring the pre-switch state from $snap_dir..." >&2
    if ! execute_file_rollback "$snap_dir"; then
        echo "CRITICAL: the rollback did not complete; the journal stays ROLLBACK_REQUIRED for recovery on the next boot." >&2
        update_journal_state "ROLLBACK_REQUIRED" || true
        return 1
    fi
    update_journal_state "ROLLED_BACK"
    echo "Channel switch rolled back to the pre-switch state." >&2
}

recovery_require_settled_journal() {
    PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 - "$JOURNAL_FILE" <<'PY'
import sys

from modules.recovery import JournalValidationError, load_journal_file, validate_journal

try:
    journal = load_journal_file(sys.argv[1])
    validate_journal(journal)
except FileNotFoundError:
    sys.exit(0)
except (JournalValidationError, OSError, ValueError):
    sys.exit(1)

if not journal["state"].endswith(("COMMITTED", "ROLLED_BACK")):
    sys.exit(1)
sides = journal.get("rollback_sides", {})
if not isinstance(sides, dict) or any(value != "ROLLED_BACK" for value in sides.values()):
    sys.exit(1)
PY
}

recover_boot_files() {
    acquire_mutation_lock || return 1
    if [[ ! -e "$JOURNAL_FILE" && ! -L "$JOURNAL_FILE" ]]; then
        return 0
    fi
    if [[ -L "$JOURNAL_FILE" || ! -f "$JOURNAL_FILE" ]]; then
        echo "CRITICAL: recovery journal is a symlink or non-regular file; refusing automatic recovery." >&2
        return 1
    fi

    echo "Inspecting journal for interrupted file transactions on boot..."
    # Validate journal schema first
    if ! python3 "$RECOVERY_PY" --validate-journal "$JOURNAL_FILE" 2>/dev/null; then
        echo "CRITICAL: journal.json validation failed; aborting automated rollback" >&2
        echo "Manual operator confirmation (--force-reconcile) required." >&2
        return 1
    fi

    local state snap_dir
    state=$(PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -c "from modules.recovery import load_journal_file; print(load_journal_file('$JOURNAL_FILE').get('state', ''))")
    snap_dir=$(PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -c "from modules.recovery import load_journal_file; print(load_journal_file('$JOURNAL_FILE').get('snapshot_dir', ''))")

    if [[ "$state" == "APPLYING" || "$state" == "VERIFYING" || "$state" == "ROLLBACK_REQUIRED" ]]; then
        echo "Detected interrupted update/restore in state $state. Performing file rollback..."
        if ! python3 - "$snap_dir" "$RECOVERY_DIR" <<'PY'
import sys
from pathlib import Path
snapshot = Path(sys.argv[1]).resolve()
root = Path(sys.argv[2]).resolve()
if snapshot == root or root not in snapshot.parents:
    raise SystemExit("snapshot path is not a child of RECOVERY_DIR")
PY
        then
            echo "CRITICAL: snapshot path is outside RECOVERY_DIR; refusing rollback." >&2
            return 1
        fi
        if [[ -z "$snap_dir" || ! -d "$snap_dir" ]]; then
            echo "CRITICAL: recovery snapshot is missing; refusing to report successful recovery." >&2
            return 1
        fi
        execute_file_rollback "$snap_dir"
        PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
import json, sys, time
from modules.recovery import write_journal_atomically
from modules.recovery import load_journal_file
data = load_journal_file('$JOURNAL_FILE')
data['state'] = 'ROLLED_BACK'
data['timestamp'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
write_journal_atomically('$JOURNAL_FILE', data)
"
        echo "Interrupted transaction rolled back successfully."
    fi
}

recover_boot_provision() {
    acquire_mutation_lock || return 1
    if [[ ! -e "$JOURNAL_FILE" && ! -L "$JOURNAL_FILE" ]]; then
        return 0
    fi
    if [[ -L "$JOURNAL_FILE" || ! -f "$JOURNAL_FILE" ]]; then
        echo "CRITICAL: recovery journal is a symlink or non-regular file; refusing automatic recovery." >&2
        return 1
    fi

    if ! python3 "$RECOVERY_PY" --validate-journal "$JOURNAL_FILE"; then
        echo "CRITICAL: provisioning journal is invalid; refusing API rollback." >&2
        return 1
    fi

    local state
    state=$(PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -c "from modules.recovery import load_journal_file; print(load_journal_file('$JOURNAL_FILE').get('state', ''))")

    if [[ "$state" =~ ^PROVISION_ || "$state" =~ ^NODE_ADD_ ]]; then
        if [[ "$state" != "PROVISION_COMMITTED" && "$state" != "NODE_ADD_COMMITTED" && "$state" != "PROVISION_ROLLED_BACK" && "$state" != "NODE_ADD_ROLLED_BACK" ]]; then
            echo "Detected uncommitted provisioning state $state. Waiting for panel health before API rollback..."
            # Wait for panel to respond
            for i in {1..30}; do
                if curl -fsSL -o /dev/null http://127.0.0.1:3000/api/system/health 2>/dev/null; then
                    break
                fi
                sleep 1
            done

            echo "Cleaning up partial API entities in reverse order..."
            if ! PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from modules.api_client import rollback_provisioning
import sys
ok = rollback_provisioning('$JOURNAL_FILE', '$STATE_FILE', '$CREDENTIALS_FILE')
sys.exit(0 if ok else 1)
"; then
                echo "CRITICAL: API rollback incomplete; journal remains in ROLLBACK_REQUIRED state." >&2
                return 1
            fi
            echo "API cleanup completed."
        fi
    fi
}

switch_channel() {
    acquire_mutation_lock || return 1
    local target_channel="$1"
    local force="${2:-false}"
    local env_file="$GOWAVE_DIR/.env"

    if [[ ! -f "$env_file" ]]; then
        echo "Error: $env_file not found" >&2
        return 1
    fi

    local current_channel
    current_channel=$(grep '^GOWAVE_CHANNEL=' "$env_file" | cut -d= -f2 || echo "stable")

    if [[ "$current_channel" == "$target_channel" ]]; then
        echo "GoWave is already on channel '$target_channel'."
        return 0
    fi

    if [[ "$current_channel" == "dev" && "$target_channel" == "stable" ]]; then
        if [[ "$force" != "true" ]]; then
            echo "WARNING: Switching from Dev to Stable may involve irreversible database migrations." >&2
            echo "Newer Dev schema migrations cannot be downgraded automatically." >&2
            echo "Use --force to confirm channel switch." >&2
            return 1
        fi
    fi

    local snap_dir
    snap_dir=$(prepare_update_snapshot "$target_channel")

    update_journal_state "APPLYING"
    echo "Updating channel to $target_channel in $env_file..."
    sed -i "s/^GOWAVE_CHANNEL=.*/GOWAVE_CHANNEL=$target_channel/" "$env_file"

    # A release that cannot start is exactly what the snapshot exists for, so the
    # restart and its liveness check are a decision point rather than a hard exit:
    # left to `set -e` the script would die here with the journal still APPLYING
    # and the panel down, and nothing would put the previous tree back.
    if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        if ! systemctl restart --no-ask-password gowave.service \
           || ! systemctl is-active --quiet gowave.service; then
            rollback_channel_switch "$snap_dir" \
                "gowave.service did not become active after the restart" || return 1
            return 1
        fi
    fi

    update_journal_state "VERIFYING"

    local healthy=false
    for i in {1..15}; do
        if curl -fsSL -o /dev/null http://127.0.0.1:3000/api/system/health 2>/dev/null || \
           curl -fsSL -o /dev/null http://127.0.0.1:3000 2>/dev/null; then
            healthy=true
            break
        fi
        sleep 2
    done

    if [[ "$healthy" != "true" ]]; then
        echo "Healthcheck failed after channel switch! Initiating rollback..." >&2
        rollback_channel_switch "$snap_dir" \
            "the Panel did not answer its health route within 30s of the restart" || return 1
        return 1
    fi

    update_journal_state "COMMITTED"
    PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from modules.recovery import prune_snapshots
prune_snapshots('$RECOVERY_DIR')
"
    echo "Switched to channel '$target_channel' successfully."
}

# ---------------------------------------------------------------------------
# Resume reconciliation
#
# A checkpoint is a verdict about a moment. A resume reads the same records
# again before it continues, and `modules/resume_reconcile.py` is the single
# place that decides whether what the Panel and the host answer is still what
# the draft recorded. The functions below hand it the draft's expectation and
# the live answer and translate one verdict into a checkpoint write and an
# operator sentence:
#
#   match                        keep the completed checkpoint
#   missing / drift             re-create or re-apply only that component
#   incompatible / ambiguous    stop only that component, name why
#   unreachable                  write nothing; the draft stays resumable
#
# The expectation comes from the draft and from state.json — both records this
# deployment wrote. Nothing is filled in from the Panel answer, because an
# expectation copied from the answer would agree with itself.
# ---------------------------------------------------------------------------

# Node checkpoints a resume stopped, will re-create or re-applied, by identity.
RESUME_STOPPED_NODES=()
RESUME_RECREATED_NODES=()
RESUME_REAPPLIED_NODES=()

recovery_resume_root() {
    cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd
}

# One field of a JSON document, as text. Args: document, dotted path.
recovery_json_field() {
    python3 -c '
import json
import sys

value = json.load(sys.stdin)
for part in sys.argv[1].split("."):
    if not isinstance(value, dict):
        value = None
        break
    value = value.get(part)
if value is None:
    print("", end="")
elif isinstance(value, str):
    print(value, end="")
else:
    print(json.dumps(value), end="")
' "$2" <<< "$1"
}

# The Panel answer a resume reconciles, or {"reachable": false} when it cannot
# be read. Never fails: an unread Panel is a classification, not a crash.
#
# Args: credentials file, state file, running installer revision, profile UUIDs
recovery_panel_live_state() {
    local credentials="$1" state_file="${2:-}" revision="${3:-}"
    local profile
    local -a profile_args=() profiles=("${@:4}")
    for profile in "${profiles[@]}"; do
        if [[ -n "$profile" ]]; then
            profile_args+=(--profile "$profile")
        fi
    done
    local root
    root=$(recovery_resume_root)
    PYTHONPATH="$root${PYTHONPATH:+:$PYTHONPATH}" \
        python3 -m modules.resume_reconcile --probe \
            --credentials "$credentials" \
            --state "$state_file" \
            --installer-revision "$revision" \
            "${profile_args[@]}"
}

# What one checkpoint recorded, from the draft alone.
recovery_draft_expectation() {
    local identity="$1" root
    declare -F draft_load >/dev/null 2>&1 || return 1
    root=$(recovery_resume_root)
    PYTHONPATH="$root${PYTHONPATH:+:$PYTHONPATH}" \
        python3 -m modules.deployment_state \
            --path "${GOWAVE_DRAFT_PATH:-/var/lib/gowave-auto-nginx/deployment/active.json}" \
            --expectation "$identity"
}

# Fill the identities a checkpoint written before they were recorded took from
# the state file the same deployment wrote. Nothing here reads the Panel.
#
# Args: expectation JSON, state file
recovery_expectation_with_state() {
    local expectation="$1" state_file="${2:-}"
    RECOVERY_EXPECTATION="$expectation" RECOVERY_STATE="$state_file" python3 - <<'PY'
import json
import os
import stat
import sys
from pathlib import Path

expectation = json.loads(os.environ['RECOVERY_EXPECTATION'])
recorded = expectation.setdefault('recorded', {})
state_path = Path(os.environ.get('RECOVERY_STATE') or '')
if state_path and os.path.lexists(state_path) and not os.path.islink(state_path) \
        and stat.S_ISREG(os.stat(state_path).st_mode):
    try:
        state = json.loads(state_path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        state = None
    if isinstance(state, dict):
        nodes = [node for node in state.get('nodes') or [] if isinstance(node, dict)]
        node_uuid = str(recorded.get('node_uuid') or '')
        name = str(recorded.get('node_name') or '').lower()
        entry = None
        for candidate in nodes:
            if node_uuid and str(candidate.get('uuid') or '') == node_uuid:
                entry = candidate
                break
        if entry is None and name:
            for candidate in nodes:
                if str(candidate.get('name') or '').lower() == name:
                    entry = candidate
                    break
        if entry is not None:
            if not recorded.get('node_uuid') and entry.get('uuid'):
                recorded['node_uuid'] = str(entry['uuid'])
            if not recorded.get('profile_uuid'):
                profile = entry.get('profileUuid') or state.get('profileUuid')
                if profile:
                    recorded['profile_uuid'] = str(profile)
            if not recorded.get('host_uuids'):
                hosts = entry.get('hostUuids')
                if isinstance(hosts, list) and hosts:
                    recorded['host_uuids'] = [str(uuid) for uuid in hosts if uuid]
            if not recorded.get('address') and entry.get('address'):
                recorded['address'] = str(entry['address'])
            if recorded.get('port') is None and type(entry.get('port')) is int:
                recorded['port'] = entry['port']
json.dump(expectation, sys.stdout)
PY
}

# One classified verdict, as a tab-separated line:
#   class  action  reason  detail  node_uuid
#
# Args: expectation JSON, live JSON, [security JSON]
recovery_classify_component() {
    local expectation="$1" live="$2" security="${3:-}" root document
    root=$(recovery_resume_root)
    document=$(RECOVERY_EXPECTATION="$expectation" RECOVERY_LIVE="$live" \
        RECOVERY_SECURITY="$security" python3 - <<'PY'
import json
import os
import sys

document = {
    'expectation': json.loads(os.environ['RECOVERY_EXPECTATION']),
    'live': json.loads(os.environ['RECOVERY_LIVE']),
}
security = os.environ.get('RECOVERY_SECURITY') or ''
if security:
    try:
        document['security'] = json.loads(security)
    except ValueError:
        pass
json.dump(document, sys.stdout)
PY
    ) || return 1
    printf '%s' "$document" \
        | PYTHONPATH="$root${PYTHONPATH:+:$PYTHONPATH}" \
            python3 -m modules.resume_reconcile --classify \
        | python3 -c '
import json
import sys

verdict = json.load(sys.stdin)
print("\t".join([
    verdict["class"],
    verdict["action"],
    verdict["reason"],
    verdict["detail"],
    verdict.get("node_uuid") or "",
]))
'
}

# Write one checkpoint through the draft store. Args: identity, JSON update
recovery_draft_checkpoint_record() {
    local identity="$1" payload="$2" root
    [[ -n "${GOWAVE_DRAFT_PATH:-}" ]] || return 1
    root=$(recovery_resume_root)
    printf '%s' "$payload" \
        | PYTHONPATH="$root${PYTHONPATH:+:$PYTHONPATH}" \
            python3 -m modules.deployment_state \
                --path "$GOWAVE_DRAFT_PATH" --checkpoint "$identity" >/dev/null
}

# Record that one component was stopped, keeping its identity for the operator.
# Args: identity, reason code, attempt
recovery_checkpoint_stop() {
    local identity="$1" reason="$2" attempt="${3:-0}" payload
    [[ "$attempt" =~ ^[0-9]+$ ]] || attempt=0
    payload=$(printf \
        '{"state":"indeterminate","stage":"verification","attempt":%d,"reason_code":"%s","recovery":"unknown"}' \
        "$((attempt + 1))" "${reason^^}")
    recovery_draft_checkpoint_record "$identity" "$payload"
}

# Record a component whose recorded association was just re-applied.
# Args: identity, attempt, node UUID, [profile UUID], [space-separated Host UUIDs]
recovery_checkpoint_verified() {
    local identity="$1" attempt="$2" node_uuid="$3" profile_uuid="${4:-}" hosts="${5:-}" payload
    payload=$(RECOVERY_ATTEMPT="$attempt" RECOVERY_NODE_UUID="$node_uuid" \
        RECOVERY_PROFILE_UUID="$profile_uuid" RECOVERY_HOST_UUIDS="$hosts" python3 - <<'PY'
import json
import os

attempt = os.environ.get('RECOVERY_ATTEMPT') or '1'
payload = {
    'state': 'verified',
    'stage': 'complete',
    'attempt': int(attempt) if attempt.isdigit() else 1,
}
for key, variable in (('node_uuid', 'RECOVERY_NODE_UUID'),
                      ('profile_uuid', 'RECOVERY_PROFILE_UUID')):
    value = os.environ.get(variable) or ''
    if value:
        payload[key] = value
hosts = [uuid for uuid in (os.environ.get('RECOVERY_HOST_UUIDS') or '').split() if uuid]
if hosts:
    payload['host_uuids'] = hosts
print(json.dumps(payload))
PY
    )
    recovery_draft_checkpoint_record "$identity" "$payload"
}

# Re-apply a drifted node's recorded Panel association. The API client writes
# through the recorded UUIDs, so this cannot register a second node.
# Args: node UUID, [profile UUID]
recovery_reapply_node() {
    local node_uuid="$1" profile_uuid="${2:-}" root
    [[ -n "$node_uuid" ]] || return 1
    root=$(recovery_resume_root)
    PYTHONPATH="$root${PYTHONPATH:+:$PYTHONPATH}" \
        python3 - "$CREDENTIALS_FILE" "$STATE_FILE" "$node_uuid" "$profile_uuid" "$JOURNAL_FILE" <<'PY'
import json
import sys

from modules.api_client import reapply_node_identity

credentials, state, node_uuid, profile_uuid, journal = sys.argv[1:6]
result = reapply_node_identity(
    credentials, state, node_uuid, profile_uuid or None,
    journal_path=journal or None,
)
print(json.dumps(result))
PY
}

# Reconcile every node checkpoint a resumed draft calls done, before the batch
# is handed the plan. Only the affected component is rewritten:
#
#   drift        re-applied through its recorded UUID, then verified again
#   missing      marked pending, so the batch re-creates just that node
#   incompatible
#   ambiguous    recorded as indeterminate, held out of the batch
#   unreachable  nothing is written; the draft is left for a later retry
#
# 0 — every checkpoint was classified; 3 — the Panel did not answer; 1 — the
# classifier itself could not run.
recovery_reconcile_resume_nodes() {
    RESUME_STOPPED_NODES=()
    RESUME_RECREATED_NODES=()
    RESUME_REAPPLIED_NODES=()
    (( ${GOWAVE_DRAFT_RESUMED:-0} == 1 )) || return 0
    declare -F draft_load >/dev/null 2>&1 || return 0
    local document identities revision live verdict
    local identity expectation profile attempt node_uuid
    local klass action reason detail
    local -a identities_all=() expectations=() profiles=()
    document=$(draft_load 2>/dev/null) || return 0
    identities=$(printf '%s' "$document" | python3 -c '
import json
import sys

document = json.load(sys.stdin)
for identity, checkpoint in sorted(document["checkpoints"].items()):
    # Only a component the draft calls done is reconciled here. Pending,
    # failed and skipped checkpoints belong to the batch: classifying them
    # would either re-create them twice or stop work that never completed.
    if identity.startswith("node-") and checkpoint.get("state") in {"verified", "indeterminate"}:
        print(identity)
' 2>/dev/null) || return 1
    [[ -n "$identities" ]] || return 0
    revision=$(declare -F draft_installer_revision >/dev/null 2>&1 && draft_installer_revision || true)
    while IFS= read -r identity; do
        [[ -n "$identity" ]] || continue
        expectation=$(recovery_draft_expectation "$identity") || return 1
        expectation=$(recovery_expectation_with_state "$expectation" "$STATE_FILE") || return 1
        identities_all+=("$identity")
        expectations+=("$expectation")
        profile=$(recovery_json_field "$expectation" recorded.profile_uuid)
        if [[ -n "$profile" ]]; then
            profiles+=("$profile")
        fi
    done <<< "$identities"

    live=$(recovery_panel_live_state "$CREDENTIALS_FILE" "$STATE_FILE" "$revision" "${profiles[@]}") \
        || live='{"reachable": false, "error": "unreadable"}'
    if [[ "$(recovery_json_field "$live" reachable)" != "true" ]]; then
        printf '%s\n' \
            'Resume: the Panel did not answer the reconciliation readback; no component checkpoint was changed and this run can be retried.' >&2
        return 3
    fi

    for index in "${!identities_all[@]}"; do
        identity="${identities_all[$index]}"
        expectation="${expectations[$index]}"
        attempt=$(recovery_json_field "$expectation" recorded.attempt)
        verdict=$(recovery_classify_component "$expectation" "$live" "") || return 1
        IFS=$'\t' read -r klass action reason detail node_uuid <<< "$verdict"
        case "$klass" in
            match)
                ;;
            drift)
                profile=$(recovery_json_field "$expectation" recorded.profile_uuid)
                if recovery_reapply_node "$node_uuid" "$profile"; then
                    live=$(recovery_panel_live_state "$CREDENTIALS_FILE" "$STATE_FILE" "$revision" "${profiles[@]}") \
                        || live='{"reachable": false, "error": "unreadable"}'
                    if [[ "$(recovery_json_field "$live" reachable)" != "true" ]]; then
                        printf '%s\n' \
                            "Resume: the Panel did not answer after re-applying $identity; no component checkpoint was changed and this run can be retried." >&2
                        return 3
                    fi
                    verdict=$(recovery_classify_component "$expectation" "$live" "") || return 1
                    IFS=$'\t' read -r klass action reason detail node_uuid <<< "$verdict"
                else
                    klass="ambiguous"
                    reason="reapply_failed"
                    detail="the recorded association could not be re-applied; inspect the Panel and the recovery journal, then retry."
                fi
                if [[ "$klass" == "match" ]]; then
                    recovery_checkpoint_verified "$identity" "$attempt" "$node_uuid" "$profile" || true
                    RESUME_REAPPLIED_NODES+=("$identity")
                    printf 'Resume: re-applied the recorded Panel association for %s.\n' "$identity" >&2
                else
                    recovery_checkpoint_stop "$identity" "$reason" "$attempt" || true
                    RESUME_STOPPED_NODES+=("$identity")
                    printf 'Resume: %s stopped; %s\n' "$identity" "$detail" >&2
                fi
                ;;
            missing)
                recovery_draft_checkpoint_record "$identity" \
                    "$(printf '{"state":"pending","stage":"registration","attempt":%d}' "$attempt")" || true
                RESUME_RECREATED_NODES+=("$identity")
                printf 'Resume: %s will be re-created; %s\n' "$identity" "$detail" >&2
                ;;
            incompatible | ambiguous)
                # Only this component stops: every sibling keeps the checkpoint
                # it already holds.
                recovery_checkpoint_stop "$identity" "$reason" "$attempt" || true
                RESUME_STOPPED_NODES+=("$identity")
                printf 'Resume: %s stopped; %s\n' "$identity" "$detail" >&2
                ;;
            unreachable)
                printf '%s\n' "Resume: $detail" >&2
                return 3
                ;;
            *)
                recovery_checkpoint_stop "$identity" "classifier_unknown" "$attempt" || true
                RESUME_STOPPED_NODES+=("$identity")
                printf 'Resume: %s stopped; the classifier answered %s.\n' "$identity" "$klass" >&2
                ;;
        esac
    done
    return 0
}

# Hold the stopped components out of the batch, keeping every planned sibling.
# The arrays are the plan's; the caller has already recorded the stop.
recovery_exclude_stopped_nodes() {
    (( ${#RESUME_STOPPED_NODES[@]} > 0 )) || return 0
    [[ -n "${GOWAVE_PLAN_NODE_NAMES+x}" ]] || return 0
    local -a names=() camouflage=() vision=() labels=()
    local index identity stopped skipped
    for index in "${!GOWAVE_PLAN_NODE_NAMES[@]}"; do
        identity="node-$((index + 1))"
        skipped=0
        for stopped in "${RESUME_STOPPED_NODES[@]}"; do
            if [[ "$identity" == "$stopped" ]]; then
                skipped=1
                break
            fi
        done
        if (( skipped == 1 )); then
            continue
        fi
        names+=("${GOWAVE_PLAN_NODE_NAMES[$index]}")
        camouflage+=("${GOWAVE_PLAN_NODE_CAMOUFLAGE[$index]}")
        vision+=("${GOWAVE_PLAN_NODE_VISION[$index]:-}")
        labels+=("${GOWAVE_PLAN_NODE_LABELS[$index]:-}")
    done
    GOWAVE_PLAN_NODE_NAMES=("${names[@]}")
    GOWAVE_PLAN_NODE_CAMOUFLAGE=("${camouflage[@]}")
    GOWAVE_PLAN_NODE_VISION=("${vision[@]}")
    GOWAVE_PLAN_NODE_LABELS=("${labels[@]}")
}

# The security report this host wrote, as text. Empty when there is none or the
# path is not a regular file this product owns: a report that cannot be read is
# not a report, and reading through a symlink would adopt whatever it names.
recovery_read_security_report() {
    local path="${GOWAVE_SECURITY_REPORT:-/var/lib/gowave-auto-nginx/security-report.json}"
    if [[ ! -f "$path" || -L "$path" ]]; then
        return 0
    fi
    cat -- "$path" 2>/dev/null || true
}

# The recorded and live security answers as one reconciliation document.
# Empty when neither side is a report object, which is how a caller that does
# not produce structured security evidence opts out instead of stopping.
#
# Args: recorded report text, live report text
recovery_security_document() {
    local recorded="$1" live="$2"
    RECOVERY_SECURITY_RECORDED="$recorded" RECOVERY_SECURITY_LIVE="$live" python3 - <<'PY'
import json
import os
import sys


def report(text):
    if not text:
        return None
    try:
        value = json.loads(text)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


recorded = report(os.environ.get('RECOVERY_SECURITY_RECORDED'))
live = report(os.environ.get('RECOVERY_SECURITY_LIVE'))
if recorded is None and live is None:
    sys.exit(0)
document = {'recorded': recorded, 'live': live}
if live is None and recorded is not None:
    document['error'] = 'unreadable'
print(json.dumps(document))
PY
}

# Put the recorded report back after a stopped component. The readback writes a
# fresh report over it; a component this run refused to adopt must not leave
# the stranger's evidence where the next resume reads "recorded".
recovery_restore_security_report() {
    local content="$1"
    local path="${GOWAVE_SECURITY_REPORT:-/var/lib/gowave-auto-nginx/security-report.json}"
    [[ -n "$content" ]] || return 0
    local directory temporary
    directory=$(dirname "$path")
    [[ -d "$directory" ]] || return 0
    temporary=$(mktemp "$directory/.security-report.XXXXXX" 2>/dev/null) || return 0
    if printf '%s\n' "$content" > "$temporary" \
        && chmod 0600 "$temporary" \
        && sync "$temporary" 2>/dev/null; then
        mv -f -- "$temporary" "$path" || true
        sync "$directory" 2>/dev/null || true
    else
        rm -f -- "$temporary"
    fi
    return 0
}
