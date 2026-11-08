#!/usr/bin/env bash
# modules/preflight.sh - Preflight port availability and NGINX conflict verification
set -euo pipefail

PREFLIGHT_REQUIRED_PORTS=(80 443 3000 3001 3002 7443 8443 9443 10001 10002 10003)

check_port_availability() {
    local ports=("${@:-${PREFLIGHT_REQUIRED_PORTS[@]}}")
    local conflicts=()

    for port in "${ports[@]}"; do
        local line
        # Check ss -Hltnp for listening sockets on the specified port
        if command -v ss >/dev/null 2>&1; then
            line=$(ss -Hltnp "sport = :$port" 2>/dev/null || true)
            if [[ -n "$line" ]]; then
                # Extract pid/process name if available
                local proc_info
                proc_info=$(echo "$line" | grep -o 'users:(.*)' || echo "$line")
                conflicts+=("Port $port is in use: $proc_info")
            fi
        fi
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
