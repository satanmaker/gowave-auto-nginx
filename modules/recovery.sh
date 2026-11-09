#!/usr/bin/env bash
# modules/recovery.sh - Transaction-safe updates, channel switching, and crash recovery
set -euo pipefail

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

    if [[ "$dir" != /* ]]; then
        echo "CRITICAL: recovery directory path must be absolute." >&2
        return 1
    fi

    # Reject symlinks in every existing path component, not only the leaf.
    IFS='/' read -r -a components <<< "$dir"
    for component in "${components[@]}"; do
        [[ -z "$component" || "$component" == "." ]] && continue
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
        [[ -z "$component" || "$component" == "." ]] && continue
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

execute_file_rollback() {
    local snap_dir="$1"
    echo "Rolling back GoWave files from snapshot $snap_dir..." >&2
    [[ -d "$snap_dir" ]] || { echo "Recovery snapshot does not exist: $snap_dir" >&2; return 1; }

    if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        systemctl stop --no-ask-password gowave.service
    fi

    if [[ -f "$snap_dir/gowave.db" ]]; then
        local db_tmp="$GOWAVE_DIR/.gowave.db.rollback"
        cp -p "$snap_dir/gowave.db" "$db_tmp"
        chmod 0640 "$db_tmp"
        if id -u gowave >/dev/null 2>&1; then
            chown gowave:gowave "$db_tmp"
        fi
        rm -f "$GOWAVE_DIR/gowave.db-wal" "$GOWAVE_DIR/gowave.db-shm"
        mv -f "$db_tmp" "$GOWAVE_DIR/gowave.db"
    fi
    if [[ -f "$snap_dir/.env" ]]; then
        install -m 0640 "$snap_dir/.env" "$GOWAVE_DIR/.env"
        if id -u gowave >/dev/null 2>&1; then chown root:gowave "$GOWAVE_DIR/.env"; fi
    fi
    if [[ -f "$snap_dir/gowave-server" ]]; then
        install -m 0755 "$snap_dir/gowave-server" "$GOWAVE_DIR/gowave-server"
    fi
    if [[ -d "$snap_dir/frontend" ]]; then
        rm -rf "$GOWAVE_DIR/frontend"
        cp -a "$snap_dir/frontend" "$GOWAVE_DIR/frontend"
    fi
    if [[ -f "$snap_dir/state.json" ]]; then
        install -m 0600 "$snap_dir/state.json" "$STATE_FILE"
    fi

    if [[ -d "$snap_dir/etc/nginx" ]]; then
        [[ "$(id -u)" -eq 0 ]] || { echo "Root is required to restore NGINX configuration." >&2; return 1; }
        cp -a "$snap_dir/etc/nginx/." /etc/nginx/
        nginx -t
    fi
    if [[ -d "$snap_dir/etc/letsencrypt" ]]; then
        [[ "$(id -u)" -eq 0 ]] || { echo "Root is required to restore ACME certificates." >&2; return 1; }
        mkdir -p /etc/letsencrypt
        cp -a "$snap_dir/etc/letsencrypt/." /etc/letsencrypt/
    fi

    if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        systemctl restart --no-ask-password gowave.service
        systemctl is-active --quiet gowave.service
        if command -v nginx >/dev/null 2>&1 && [[ -d "$snap_dir/etc/nginx" ]]; then
            nginx -t
            systemctl reload nginx
            systemctl is-active --quiet nginx
        fi
    fi
    echo "File rollback completed and services verified." >&2
}

recover_boot_files() {
    acquire_mutation_lock || return 1
    if [[ ! -f "$JOURNAL_FILE" ]]; then
        return 0
    fi

    echo "Inspecting journal for interrupted file transactions on boot..."
    # Validate journal schema first
    if ! python3 "$RECOVERY_PY" --validate-journal "$JOURNAL_FILE" 2>/dev/null; then
        echo "CRITICAL: journal.json validation failed; aborting automated rollback" >&2
        echo "Manual operator confirmation (--force-reconcile) required." >&2
        return 1
    fi

    local state snap_dir
    state=$(python3 -c "import json; print(json.load(open('$JOURNAL_FILE')).get('state', ''))")
    snap_dir=$(python3 -c "import json; print(json.load(open('$JOURNAL_FILE')).get('snapshot_dir', ''))")

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
data = json.load(open('$JOURNAL_FILE'))
data['state'] = 'ROLLED_BACK'
data['timestamp'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
write_journal_atomically('$JOURNAL_FILE', data)
"
        echo "Interrupted transaction rolled back successfully."
    fi
}

recover_boot_provision() {
    acquire_mutation_lock || return 1
    if [[ ! -f "$JOURNAL_FILE" ]]; then
        return 0
    fi

    if ! python3 "$RECOVERY_PY" --validate-journal "$JOURNAL_FILE"; then
        echo "CRITICAL: provisioning journal is invalid; refusing API rollback." >&2
        return 1
    fi

    local state
    state=$(python3 -c "import json; print(json.load(open('$JOURNAL_FILE')).get('state', ''))")

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

    PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 - "$JOURNAL_FILE" "APPLYING" <<'PY'
import json, sys, time
from modules.recovery import write_journal_atomically
p=sys.argv[1]; d=json.load(open(p)); d["state"]=sys.argv[2]
d["timestamp"]=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
write_journal_atomically(p,d)
PY
    echo "Updating channel to $target_channel in $env_file..."
    sed -i "s/^GOWAVE_CHANNEL=.*/GOWAVE_CHANNEL=$target_channel/" "$env_file"

    # Restart and verify health
    if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        systemctl restart --no-ask-password gowave.service
        systemctl is-active --quiet gowave.service
    fi

    PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 - "$JOURNAL_FILE" "VERIFYING" <<'PY'
import json, sys, time
from modules.recovery import write_journal_atomically
p=sys.argv[1]; d=json.load(open(p)); d["state"]=sys.argv[2]
d["timestamp"]=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
write_journal_atomically(p,d)
PY

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
        execute_file_rollback "$snap_dir"
        PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 - "$JOURNAL_FILE" <<'PY'
import json, sys, time
from modules.recovery import write_journal_atomically
p=sys.argv[1]; d=json.load(open(p)); d["state"]="ROLLED_BACK"
d["timestamp"]=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
write_journal_atomically(p,d)
PY
        return 1
    fi

    PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
import json, sys, time
from modules.recovery import write_journal_atomically, prune_snapshots
data = json.load(open('$JOURNAL_FILE'))
data['state'] = 'COMMITTED'
data['timestamp'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
write_journal_atomically('$JOURNAL_FILE', data)
prune_snapshots('$RECOVERY_DIR')
"
    echo "Switched to channel '$target_channel' successfully."
}
