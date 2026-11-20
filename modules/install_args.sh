#!/usr/bin/env bash
# modules/install_args.sh - install argument contract shared by the CLI and the wizard
set -Eeuo pipefail

GOWAVE_INSTALL_USAGE="Usage: gowave-auto.sh install [--panel-only|--mode all-in-one|panel-only] <panel-or-worker-name> <camouflage-name> <email> [vision]"
GOWAVE_INSTALL_MODE="all-in-one"
GOWAVE_INSTALL_POSITIONAL=()

# Parse an `install` invocation without touching the host. The three positional
# arguments keep their meaning; the mode is only ever a flag. Results are left
# in GOWAVE_INSTALL_MODE and GOWAVE_INSTALL_POSITIONAL so the caller can run the
# mutation under its own lock.
parse_install_arguments() {
    GOWAVE_INSTALL_MODE="all-in-one"
    GOWAVE_INSTALL_POSITIONAL=()

    while (( $# > 0 )); do
        case "$1" in
            --panel-only)
                GOWAVE_INSTALL_MODE="panel-only"
                shift
                ;;
            --mode)
                if (( $# < 2 )); then
                    echo "Error: --mode requires all-in-one or panel-only." >&2
                    return 2
                fi
                case "$2" in
                    all-in-one|panel-only)
                        GOWAVE_INSTALL_MODE="$2"
                        ;;
                    *)
                        echo "Error: unsupported installation mode: $2 (expected all-in-one or panel-only)." >&2
                        return 2
                        ;;
                esac
                shift 2
                ;;
            --mode=*)
                case "${1#*=}" in
                    all-in-one|panel-only)
                        GOWAVE_INSTALL_MODE="${1#*=}"
                        ;;
                    *)
                        echo "Error: unsupported installation mode: ${1#*=} (expected all-in-one or panel-only)." >&2
                        return 2
                        ;;
                esac
                shift
                ;;
            --)
                shift
                while (( $# > 0 )); do
                    GOWAVE_INSTALL_POSITIONAL+=("$1")
                    shift
                done
                ;;
            -*)
                echo "Error: unknown install option: $1" >&2
                echo "$GOWAVE_INSTALL_USAGE" >&2
                return 2
                ;;
            *)
                GOWAVE_INSTALL_POSITIONAL+=("$1")
                shift
                ;;
        esac
    done

    if [[ "$GOWAVE_INSTALL_MODE" == "panel-only" && ${#GOWAVE_INSTALL_POSITIONAL[@]} -ge 4 ]]; then
        echo "Error: --panel-only deploys no traffic plane, so it accepts no Vision domain." >&2
        return 2
    fi

    return 0
}

installation_mode_from_state() {
    local state_file="${1:-${STATE_FILE:-/var/lib/gowave-auto-nginx/state.json}}"
    if [[ ! -f "$state_file" ]]; then
        echo "all-in-one"
        return 0
    fi
    python3 - "$state_file" <<'PY' 2>/dev/null || echo "all-in-one"
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        mode = json.load(handle).get("installationMode", "all-in-one")
except Exception:
    mode = "all-in-one"
print(mode if mode in ("all-in-one", "panel-only") else "all-in-one")
PY
}
