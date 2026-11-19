#!/usr/bin/env bash
# modules/tempdir.sh - Scratch-directory bookkeeping for scripts that must not
# leave a temporary tree behind when a command fails deep inside a function.
#
# A `trap ... RETURN` handler is not enough: under `errexit` a failing command
# abandons the function without unwinding it, so the RETURN trap never runs and
# the directory survives the failed run. Every tracked directory is therefore
# removed from an EXIT trap, which does run on that path.
set -Eeuo pipefail

# Sourcing is idempotent: a module that needs the helpers may source this file
# itself, and the entrypoint may have sourced it first.
if [[ -z "${GOWAVE_TEMP_DIRS+set}" ]]; then
    GOWAVE_TEMP_DIRS=()
fi

cleanup_temp_dirs() {
    local dir
    if (( ${#GOWAVE_TEMP_DIRS[@]} )); then
        for dir in "${GOWAVE_TEMP_DIRS[@]}"; do
            [[ -n "$dir" ]] || continue
            rm -rf -- "$dir" || true
        done
    fi
    GOWAVE_TEMP_DIRS=()
    return 0
}

# track_temp_dir DIR - remember DIR and install the cleanup trap. Call it right
# after mktemp, before anything else can fail.
track_temp_dir() {
    local dir="$1"
    [[ -n "$dir" ]] || {
        echo "Error: track_temp_dir requires a directory path." >&2
        return 1
    }
    GOWAVE_TEMP_DIRS+=("$dir")
    trap 'cleanup_temp_dirs' EXIT
}

# release_temp_dir DIR - remove DIR now and stop tracking it, for the paths
# where the caller is done with it before the script exits.
release_temp_dir() {
    local dir="$1"
    local kept=()
    local candidate
    [[ -n "$dir" ]] || return 1
    rm -rf -- "$dir" || return 1
    if (( ${#GOWAVE_TEMP_DIRS[@]} )); then
        for candidate in "${GOWAVE_TEMP_DIRS[@]}"; do
            [[ "$candidate" == "$dir" ]] || kept+=("$candidate")
        done
    fi
    GOWAVE_TEMP_DIRS=("${kept[@]+"${kept[@]}"}")
}
