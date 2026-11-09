#!/usr/bin/env bash
# ==============================================================================
# GoWave Auto NGINX: Host-Wide Mutation Lock and Re-entrant Lease Helper
# Implements D18 canonical mutation lock contract.
# ==============================================================================
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    MUTATION_LOCK_FILE="${MUTATION_LOCK_FILE:-/tmp/gowave-managed-mutation-$(id -u).lock}"
    MUTATION_LEASE_FILE="${MUTATION_LEASE_FILE:-/tmp/gowave-mutation-lease-$(id -u).json}"
else
    MUTATION_LOCK_FILE="${MUTATION_LOCK_FILE:-/run/lock/gowave-managed-mutation.lock}"
    MUTATION_LEASE_FILE="${MUTATION_LEASE_FILE:-/run/lock/gowave-mutation-lease.json}"
fi

validate_lock_path() {
    local lock_file="${1:-$MUTATION_LOCK_FILE}"
    local lock_dir
    lock_dir="$(dirname "$lock_file")"

    if [[ ! -d "$lock_dir" ]]; then
        mkdir -p "$lock_dir"
        chmod 0755 "$lock_dir" 2>/dev/null || true
    fi

    if [[ -L "$lock_dir" ]]; then
        echo "Error: Lock directory $lock_dir is a symlink; unsafe." >&2
        return 1
    fi

    if [[ -L "$lock_file" ]]; then
        echo "Error: Lock file $lock_file is a symlink; refusing path substitution." >&2
        return 1
    fi

    if [[ -e "$lock_file" && ! -f "$lock_file" ]]; then
        echo "Error: Lock file $lock_file exists and is not a regular file." >&2
        return 1
    fi

    return 0
}

validate_mutation_lease() {
    local candidate_token="$1"
    local lease_file="${2:-$MUTATION_LEASE_FILE}"
    local lock_file="${3:-$MUTATION_LOCK_FILE}"

    python3 - "$candidate_token" "$lease_file" "$lock_file" <<'PY'
import json
import os
import sys

token, lease_path, lock_path = sys.argv[1:4]

if not os.path.exists(lease_path):
    sys.exit(1)

if os.path.islink(lease_path):
    sys.exit(1)

st = os.stat(lease_path)
if os.geteuid() == 0 and st.st_uid != 0:
    sys.exit(1)

try:
    with open(lease_path, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception:
    sys.exit(1)

expected_token = data.get("lease_token", "")
holder_pid = data.get("holder_pid")

if not expected_token or expected_token != token:
    sys.exit(1)

if type(holder_pid) is not int or holder_pid <= 0:
    sys.exit(1)

try:
    os.kill(holder_pid, 0)
except OSError:
    sys.exit(1)

fd_dir = f"/proc/{holder_pid}/fd"
if os.path.exists(fd_dir):
    try:
        real_lock = os.path.realpath(lock_path)
        has_fd = False
        for fd in os.listdir(fd_dir):
            try:
                target = os.path.realpath(os.path.join(fd_dir, fd))
                if target == real_lock:
                    has_fd = True
                    break
            except Exception:
                continue
        if not has_fd:
            sys.exit(1)
    except Exception:
        pass

sys.exit(0)
PY
}

acquire_mutation_lock() {
    if [[ "${_MUTATION_LOCK_HELD:-0}" -eq 1 || "${_MUTATION_LEASE_VALIDATED:-0}" -eq 1 ]]; then
        return 0
    fi

    validate_lock_path "$MUTATION_LOCK_FILE" || return 1

    if [[ ! -f "$MUTATION_LOCK_FILE" ]]; then
        (
            umask 0177
            touch "$MUTATION_LOCK_FILE"
        ) 2>/dev/null || true
        chmod 0600 "$MUTATION_LOCK_FILE" 2>/dev/null || true
    fi

    exec 9>>"$MUTATION_LOCK_FILE"
    if flock -n 9; then
        _MUTATION_LOCK_HELD=1
        return 0
    fi

    local candidate_token=""
    if [[ -n "${GOWAVE_LEASE_TOKEN:-}" ]]; then
        candidate_token="$GOWAVE_LEASE_TOKEN"
    elif [[ ! -t 0 ]]; then
        local first_line=""
        if IFS= read -r -t 1 first_line; then
            if [[ "$first_line" =~ ^GOWAVE_LEASE:\ *(.*)$ ]]; then
                candidate_token="${BASH_REMATCH[1]}"
            fi
        fi
    fi

    if [[ -n "$candidate_token" ]]; then
        if validate_mutation_lease "$candidate_token" "$MUTATION_LEASE_FILE" "$MUTATION_LOCK_FILE"; then
            _MUTATION_LEASE_VALIDATED=1
            return 0
        fi
        echo "Error: Invalid or stale mutation lock lease provided." >&2
        return 1
    fi

    echo "Error: Another process currently holds the mutation lock ($MUTATION_LOCK_FILE)." >&2
    echo "Refusing concurrent mutation without an authorized re-entrant lease." >&2
    return 1
}
