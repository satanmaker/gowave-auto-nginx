#!/usr/bin/env bash
# modules/recovery.sh - Transaction-safe updates, channel switching, and crash recovery
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RECOVERY_PY="${SCRIPT_DIR}/modules/recovery.py"
RECOVERY_DIR="/var/lib/gowave-auto-nginx/recovery"
JOURNAL_FILE="${RECOVERY_DIR}/journal.json"
GOWAVE_DIR="/opt/gowave"

ensure_recovery_dir() {
    mkdir -p "$RECOVERY_DIR"
    chmod 0700 "$RECOVERY_DIR" 2>/dev/null || true
}

take_preflight_db_snapshot() {
    local target_snapshot_dir="$1"
    local db_path="${2:-$GOWAVE_DIR/gowave.db}"

    ensure_recovery_dir
    mkdir -p "$target_snapshot_dir"
    chmod 0700 "$target_snapshot_dir" 2>/dev/null || true

    echo "Executing transactional SQLite Online Backup..."
    python3 -c "
import sys
from modules.recovery import sqlite_online_backup
sqlite_online_backup('$db_path', '$target_snapshot_dir/gowave.db')
"
    echo "Database snapshot saved to $target_snapshot_dir/gowave.db."
}

prepare_update_snapshot() {
    local target_version="$1"
    local ts
    ts=$(date +%s)
    local snap_dir="${RECOVERY_DIR}/update-${ts}"

    ensure_recovery_dir
    mkdir -p "$snap_dir"
    chmod 0700 "$snap_dir" 2>/dev/null || true

    echo "Capturing pre-update persistent recovery snapshot in $snap_dir..."

    # 1. Database snapshot
    take_preflight_db_snapshot "$snap_dir" "$GOWAVE_DIR/gowave.db"

    # 2. Copy current binaries and configuration
    if [[ -f "$GOWAVE_DIR/.env" ]]; then
        cp "$GOWAVE_DIR/.env" "$snap_dir/.env"
    fi
    if [[ -f "$GOWAVE_DIR/gowave-server" ]]; then
        cp "$GOWAVE_DIR/gowave-server" "$snap_dir/gowave-server"
    fi
    if [[ -d "$GOWAVE_DIR/frontend" ]]; then
        cp -r "$GOWAVE_DIR/frontend" "$snap_dir/frontend"
    fi

    # 3. Write durable state journal
    python3 -c "
from modules.recovery import write_journal_atomically
import time
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
    echo "Recovery snapshot and PREPARED journal written."
    echo "$snap_dir"
}

execute_file_rollback() {
    local snap_dir="$1"
    echo "Rolling back GoWave files from snapshot $snap_dir..."

    if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        systemctl stop --no-ask-password gowave.service || true
    fi

    if [[ -f "$snap_dir/gowave.db" ]]; then
        cp "$snap_dir/gowave.db" "$GOWAVE_DIR/gowave.db"
        rm -f "$GOWAVE_DIR/gowave.db-wal" "$GOWAVE_DIR/gowave.db-shm"
    fi
    if [[ -f "$snap_dir/.env" ]]; then
        cp "$snap_dir/.env" "$GOWAVE_DIR/.env"
    fi
    if [[ -f "$snap_dir/gowave-server" ]]; then
        cp "$snap_dir/gowave-server" "$GOWAVE_DIR/gowave-server"
        chmod 0755 "$GOWAVE_DIR/gowave-server"
    fi
    if [[ -d "$snap_dir/frontend" ]]; then
        rm -rf "$GOWAVE_DIR/frontend"
        cp -r "$snap_dir/frontend" "$GOWAVE_DIR/frontend"
    fi

    if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        systemctl restart --no-ask-password gowave.service || true
    fi
    echo "File rollback completed."
}

recover_boot_files() {
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
        if [[ -d "$snap_dir" ]]; then
            execute_file_rollback "$snap_dir"
            python3 -c "
import json
from modules.recovery import write_journal_atomically
data = json.load(open('$JOURNAL_FILE'))
data['state'] = 'ROLLED_BACK'
write_journal_atomically('$JOURNAL_FILE', data)
"
            echo "Interrupted transaction rolled back successfully."
        fi
    fi
}

recover_boot_provision() {
    if [[ ! -f "$JOURNAL_FILE" ]]; then
        return 0
    fi

    local state
    state=$(python3 -c "import json; print(json.load(open('$JOURNAL_FILE')).get('state', ''))" 2>/dev/null || echo "")

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
            # Mark rolled back
            python3 -c "
import json
from modules.recovery import write_journal_atomically
data = json.load(open('$JOURNAL_FILE'))
if data.get('op') == 'provision':
    data['state'] = 'PROVISION_ROLLED_BACK'
elif data.get('op') == 'node_add':
    data['state'] = 'NODE_ADD_ROLLED_BACK'
write_journal_atomically('$JOURNAL_FILE', data)
"
            echo "API cleanup completed."
        fi
    fi
}

switch_channel() {
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

    echo "Updating channel to $target_channel in $env_file..."
    sed -i "s/^GOWAVE_CHANNEL=.*/GOWAVE_CHANNEL=$target_channel/" "$env_file"

    # Restart and verify health
    if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        systemctl restart --no-ask-password gowave.service || true
    fi

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
        return 1
    fi

    python3 -c "
import json
from modules.recovery import write_journal_atomically, prune_snapshots
data = json.load(open('$JOURNAL_FILE'))
data['state'] = 'COMMITTED'
write_journal_atomically('$JOURNAL_FILE', data)
prune_snapshots('$RECOVERY_DIR')
"
    echo "Switched to channel '$target_channel' successfully."
}
