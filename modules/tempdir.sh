#!/usr/bin/env bash
# modules/tempdir.sh - Scratch-directory bookkeeping for scripts that must not
# leave a temporary tree behind when a command fails deep inside a function.
#
# A `trap ... RETURN` handler is not enough: under `errexit` a failing command
# abandons the function without unwinding it, so the RETURN trap never runs and
# the directory survives the failed run. Every tracked directory is therefore
# removed from an EXIT trap, which does run on that path.
#
# The trap is not scoped to the shell that installed it. A command substitution
# inherits the tracked array, and a callee that tracks a directory of its own
# installs a fresh EXIT trap in that child: without a level the child's exit
# runs a cleanup over the parent's entries and deletes a directory the parent
# is still reading. That is how `wizard_onboard_nodes` lost the Worker's stderr
# and reported "phase: unknown". Every entry therefore records the
# BASH_SUBSHELL it was tracked in, and a cleanup removes only its own level.
set -Eeuo pipefail

# Sourcing is idempotent: a module that needs the helpers may source this file
# itself, and the entrypoint may have sourced it first.
if [[ -z "${GOWAVE_TEMP_DIRS+set}" ]]; then
    GOWAVE_TEMP_DIRS=()
fi
if [[ -z "${GOWAVE_TEMP_DIR_LEVELS+set}" ]]; then
    GOWAVE_TEMP_DIR_LEVELS=()
fi

cleanup_temp_dirs() {
    local level="${BASH_SUBSHELL:-0}"
    local dir
    local kept=()
    local kept_levels=()
    local index
    if (( ${#GOWAVE_TEMP_DIRS[@]} )); then
        for index in "${!GOWAVE_TEMP_DIRS[@]}"; do
            dir="${GOWAVE_TEMP_DIRS[$index]}"
            [[ -n "$dir" ]] || continue
            if [[ "${GOWAVE_TEMP_DIR_LEVELS[$index]:-0}" != "$level" ]]; then
                kept+=("$dir")
                kept_levels+=("${GOWAVE_TEMP_DIR_LEVELS[$index]:-0}")
                continue
            fi
            rm -rf -- "$dir" || true
        done
    fi
    GOWAVE_TEMP_DIRS=("${kept[@]+"${kept[@]}"}")
    GOWAVE_TEMP_DIR_LEVELS=("${kept_levels[@]+"${kept_levels[@]}"}")
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
    GOWAVE_TEMP_DIR_LEVELS+=("${BASH_SUBSHELL:-0}")
    trap 'cleanup_temp_dirs' EXIT
}

# release_temp_dir DIR - remove DIR now and stop tracking it, for the paths
# where the caller is done with it before the script exits.
release_temp_dir() {
    local dir="$1"
    local kept=()
    local kept_levels=()
    local candidate
    local index
    [[ -n "$dir" ]] || return 1
    rm -rf -- "$dir" || return 1
    if (( ${#GOWAVE_TEMP_DIRS[@]} )); then
        for index in "${!GOWAVE_TEMP_DIRS[@]}"; do
            candidate="${GOWAVE_TEMP_DIRS[$index]}"
            [[ "$candidate" == "$dir" ]] && continue
            kept+=("$candidate")
            kept_levels+=("${GOWAVE_TEMP_DIR_LEVELS[$index]:-0}")
        done
    fi
    GOWAVE_TEMP_DIRS=("${kept[@]+"${kept[@]}"}")
    GOWAVE_TEMP_DIR_LEVELS=("${kept_levels[@]+"${kept_levels[@]}"}")
}
