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
