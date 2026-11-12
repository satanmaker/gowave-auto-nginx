#!/usr/bin/env bash
# modules/preflight.sh - Preflight port availability and NGINX conflict verification
set -euo pipefail

PREFLIGHT_REQUIRED_PORTS=(80 443 3000 3001 3002 7443 8443 8444 9443 9444 10001 10002 10003)

# A repeated install legitimately rediscovers the product already bound to the ports
# it is about to re-check. Only listeners owned by anything else are a conflict.
PREFLIGHT_MANAGED_UNITS=(gowave.service gowave-node.service nginx.service)
PREFLIGHT_PROC_ROOT="${PREFLIGHT_PROC_ROOT:-/proc}"

preflight_pid_is_managed() {
    local pid="$1"
    local cgroup=""
    if [[ -z "$pid" ]]; then
        return 1
    fi
    cgroup=$(cat "${PREFLIGHT_PROC_ROOT}/${pid}/cgroup" 2>/dev/null || true)
    if [[ -z "$cgroup" ]]; then
        return 1
    fi
    local unit
    for unit in "${PREFLIGHT_MANAGED_UNITS[@]}"; do
        # Matches both cgroup v2 ("0::/system.slice/<unit>") and the cgroup v1
        # hierarchy ("1:name=systemd:/system.slice/<unit>").
        if [[ "$cgroup" == *"/${unit}"* ]]; then
            return 0
        fi
    done
    return 1
}

preflight_describe_socket() {
    local line="$1"
    local info
    info=$(printf '%s\n' "$line" | grep -o 'users:(.*)' || true)
    if [[ -n "$info" ]]; then
        printf '%s\n' "$info"
        return 0
    fi
    printf '%s\n' "$line"
}

check_port_availability() {
    local ports=("${@:-${PREFLIGHT_REQUIRED_PORTS[@]}}")
    local conflicts=()

    if ! command -v ss >/dev/null 2>&1; then
        return 0
    fi

    for port in "${ports[@]}"; do
        local line=""
        line=$(ss -Hltnp "sport = :$port" 2>/dev/null || true)
        if [[ -z "$line" ]]; then
            continue
        fi

        local owners=""
        owners=$(printf '%s\n' "$line" | grep -o 'pid=[0-9][0-9]*' | cut -d= -f2 | sort -u || true)
        if [[ -z "$owners" ]]; then
            # An owner we cannot attribute is never silently forgiven.
            conflicts+=("Port $port is in use: $(preflight_describe_socket "$line")")
            continue
        fi

        local foreign=0
        local owner
        while IFS= read -r owner; do
            if [[ -z "$owner" ]]; then
                continue
            fi
            if ! preflight_pid_is_managed "$owner"; then
                foreign=1
            fi
        done <<< "$owners"
        if [[ "$foreign" -eq 0 ]]; then
            continue
        fi
        conflicts+=("Port $port is in use: $(preflight_describe_socket "$line")")
    done

    if [[ ${#conflicts[@]} -gt 0 ]]; then
        echo "Error: Conflicting listening ports detected:" >&2
        for c in "${conflicts[@]}"; do
            echo "  - $c" >&2
        done
        return 1
    fi
    return 0
}

check_nginx_443_conflicts() {
    local nginx_dir="${1:-/etc/nginx}"
    if [[ ! -d "$nginx_dir" ]]; then
        return 0
    fi

    # Scan for unmanaged listen 443 directives
    local matches=()
    mapfile -t matches < <(grep -rsE \
        --exclude="gowave-*.conf" \
        --exclude="gowave-stream.conf" \
        --exclude="default" \
        --exclude="*.bak" \
        '^[[:space:]]*listen[[:space:]]+([^;]*:)?443[^0-9]' "$nginx_dir" 2>/dev/null || true)

    # Filter out comments and disabled sites
    local real_conflicts=()
    for m in "${matches[@]}"; do
        local file="${m%%:*}"
        local line="${m#*:}"
        # Skip commented lines
        if [[ "$line" =~ ^[[:space:]]*# ]]; then
            continue
        fi
        # Skip if file path contains sites-available without being in sites-enabled
        if [[ "$file" == *"/sites-available/"* ]]; then
            local base
            base=$(basename "$file")
            if [[ ! -e "${nginx_dir}/sites-enabled/${base}" ]]; then
                continue
            fi
        fi
        real_conflicts+=("$file: $line")
    done

    if [[ ${#real_conflicts[@]} -gt 0 ]]; then
        echo "Error: Unmanaged NGINX port 443 configuration detected:" >&2
        for c in "${real_conflicts[@]}"; do
            echo "  - $c" >&2
        done
        echo "Port 443 is exclusively dedicated to GoWave Auto NGINX Stream SNI multiplexing." >&2
        echo "Please disable or relocate conflicting HTTP SSL server blocks before installation." >&2
        return 1
    fi
    return 0
}

run_preflight_panel() {
    local nginx_dir="${1:-/etc/nginx}"
    echo "Running preflight environment and port inspection..."
    check_port_availability
    check_nginx_443_conflicts "$nginx_dir"
    echo "Preflight port and NGINX conflict checks passed successfully."
}
