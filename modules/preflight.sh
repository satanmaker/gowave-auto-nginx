#!/usr/bin/env bash
# modules/preflight.sh - Preflight port availability and NGINX conflict verification
set -Eeuo pipefail

PREFLIGHT_REQUIRED_PORTS=(80 443 3000 3001 3002 7443 8443 8444 9443 9444 10001 10002 10003)

# ---------------------------------------------------------------------------
# Required-input contract
#
# One table per lifecycle component. A command validates every input its
# component needs before it stops a service, installs a package, writes a
# managed path or contacts the Panel. The first failure names the component and
# the field. The wizard and the positional path call the same validators, so a
# value is refused identically on both entry paths.
# ---------------------------------------------------------------------------
PREFLIGHT_INSTALL_FIELDS=(panel_domain reality_domain acme_email vision_domain)
PREFLIGHT_INSTALL_KINDS=(hostname hostname email optional_hostname)
PREFLIGHT_INSTALL_LABELS=(
    "the panel domain"
    "the camouflage (REALITY) domain"
    "the ACME contact email"
    "the Vision domain"
)
PREFLIGHT_NODE_FIELDS=(name address worker_domain reality_domain ssh_user ssh_port vision_domain)
PREFLIGHT_NODE_KINDS=(node_name address hostname hostname ssh_user port optional_hostname)
PREFLIGHT_NODE_LABELS=(
    "the Worker name"
    "the Worker address"
    "the Worker domain"
    "the camouflage (REALITY) domain"
    "the SSH user"
    "the SSH port"
    "the Vision domain"
)
# The Worker payload has no Worker name or address: those stay on the
# controller. It refuses the values it has to act on, from the same module.
PREFLIGHT_WORKER_FIELDS=(worker_domain reality_domain vision_domain node_port)
PREFLIGHT_WORKER_KINDS=(hostname hostname optional_hostname port)
PREFLIGHT_WORKER_LABELS=(
    "the Worker domain"
    "the camouflage (REALITY) domain"
    "the Vision domain"
    "the Worker port"
)

preflight_validate_hostname() {
    local value="$1"
    local label
    local -a labels
    [[ ${#value} -ge 3 && ${#value} -le 253 ]] || return 1
    [[ "$value" != .* && "$value" != *. && "$value" != *..* ]] || return 1
    [[ "$value" == *.* ]] || return 1
    IFS='.' read -r -a labels <<< "$value"
    for label in "${labels[@]}"; do
        [[ ${#label} -le 63 ]] || return 1
        [[ "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
    done
    return 0
}

preflight_validate_email() {
    [[ "$1" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]
}

preflight_validate_node_name() {
    [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]
}

preflight_validate_ssh_user() {
    [[ "$1" =~ ^[A-Za-z_][A-Za-z0-9._-]{0,31}$ ]]
}

preflight_validate_port() {
    [[ "$1" =~ ^[0-9]+$ ]] || return 1
    (( 10#$1 >= 1 && 10#$1 <= 65535 ))
}

preflight_validate_address() {
    local value="$1"
    local octet
    local -a octets
    if [[ "$value" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        IFS='.' read -r -a octets <<< "$value"
        for octet in "${octets[@]}"; do
            (( 10#$octet <= 255 )) || return 1
        done
        return 0
    fi
    # A syntactic screen only: the address parser used by the API client stays
    # the authority, so an abbreviated IPv6 form this pattern accepts is still
    # rejected there before any mutation.
    [[ ${#value} -le 39 ]] || return 1
    [[ "$value" =~ ^([0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}$ ]] || return 1
    [[ "$value" != *::*::* && "$value" != *:::* ]] || return 1
    return 0
}

preflight_validate_optional_hostname() {
    [[ -z "$1" ]] && return 0
    preflight_validate_hostname "$1"
}

preflight_require_inputs() {
    local component="$1"
    shift
    local -a values=("$@")
    local -a fields kinds labels
    case "$component" in
        install)
            fields=("${PREFLIGHT_INSTALL_FIELDS[@]}")
            kinds=("${PREFLIGHT_INSTALL_KINDS[@]}")
            labels=("${PREFLIGHT_INSTALL_LABELS[@]}")
            ;;
        node)
            fields=("${PREFLIGHT_NODE_FIELDS[@]}")
            kinds=("${PREFLIGHT_NODE_KINDS[@]}")
            labels=("${PREFLIGHT_NODE_LABELS[@]}")
            ;;
        worker)
            fields=("${PREFLIGHT_WORKER_FIELDS[@]}")
            kinds=("${PREFLIGHT_WORKER_KINDS[@]}")
            labels=("${PREFLIGHT_WORKER_LABELS[@]}")
            ;;
        *)
            printf 'Error: unknown preflight component: %s\n' "$component" >&2
            return 2
            ;;
    esac

    local index value validator
    for index in "${!fields[@]}"; do
        value="${values[$index]:-}"
        if [[ -z "$value" ]]; then
            # An optional field is absent by design; the positional and the
            # environment path both leave it empty rather than inventing one.
            if [[ "${kinds[$index]}" == optional_* ]]; then
                continue
            fi
            printf 'Error: %s requires %s, which was not provided.\n' "$component" "${labels[$index]}" >&2
            return 2
        fi
        validator="preflight_validate_${kinds[$index]}"
        if ! "$validator" "$value"; then
            printf 'Error: %s requires %s; %q is not valid.\n' \
                "$component" "${labels[$index]}" "$value" >&2
            return 2
        fi
    done

    local panel reality vision
    case "$component" in
        install)
            panel="${values[0],,}"
            reality="${values[1],,}"
            vision="${values[3]:-}"
            vision="${vision,,}"
            if [[ "$panel" == "$reality" ]]; then
                printf 'Error: install requires the panel domain and %s to differ.\n' \
                    "${PREFLIGHT_INSTALL_LABELS[1]}" >&2
                return 2
            fi
            if [[ -n "$vision" && ( "$vision" == "$panel" || "$vision" == "$reality" ) ]]; then
                printf 'Error: install requires %s to differ from the panel and camouflage domains.\n' \
                    "${PREFLIGHT_INSTALL_LABELS[3]}" >&2
                return 2
            fi
            ;;
        node)
            if [[ "${values[2],,}" == "${values[3],,}" ]]; then
                printf 'Error: node requires the Worker domain and %s to differ.\n' \
                    "${PREFLIGHT_NODE_LABELS[3]}" >&2
                return 2
            fi
            vision="${values[6]:-}"
            vision="${vision,,}"
            if [[ -n "$vision" && ( "$vision" == "${values[2],,}" || "$vision" == "${values[3],,}" ) ]]; then
                printf 'Error: node requires %s to differ from the Worker and camouflage domains.\n' \
                    "${PREFLIGHT_NODE_LABELS[6]}" >&2
                return 2
            fi
            ;;
        worker)
            if [[ "${values[0],,}" == "${values[1],,}" ]]; then
                printf 'Error: worker requires the Worker domain and %s to differ.\n' \
                    "${PREFLIGHT_WORKER_LABELS[1]}" >&2
                return 2
            fi
            vision="${values[2]:-}"
            vision="${vision,,}"
            if [[ -n "$vision" && ( "$vision" == "${values[0],,}" || "$vision" == "${values[1],,}" ) ]]; then
                printf 'Error: worker requires %s to differ from the Worker and camouflage domains.\n' \
                    "${PREFLIGHT_WORKER_LABELS[2]}" >&2
                return 2
            fi
            ;;
    esac
    return 0
}

# ---------------------------------------------------------------------------
# Cloudflare proxy refusal
#
# HTTP-01 cannot complete when the name answers from a Cloudflare proxy range,
# so an install that would fail at issuance is refused before the first
# certificate request. The list is a dated snapshot: fetching it at preflight
# would add a network dependency and a trust decision to the step that must
# fail fast. An operator whose provider blocks these ranges replaces the
# snapshot with GOWAVE_PREFLIGHT_PROXY_CIDRS, and
# GOWAVE_PREFLIGHT_ALLOW_PROXIED=1 records a decision to continue anyway.
# ---------------------------------------------------------------------------
PREFLIGHT_PROXY_CIDRS_SNAPSHOT="2026-11-20"
PREFLIGHT_PROXY_CIDRS=(
    173.245.48.0/20
    103.21.244.0/22
    103.22.200.0/22
    103.31.4.0/22
    141.101.64.0/18
    108.162.192.0/18
    190.93.240.0/20
    188.114.96.0/20
    197.234.240.0/22
    198.41.128.0/17
    162.158.0.0/15
    104.16.0.0/13
    104.24.0.0/14
    172.64.0.0/13
    131.0.72.0/22
    2400:cb00::/32
    2606:4700::/32
    2803:f800::/32
    2405:b500::/32
    2405:8100::/32
    2a06:98c0::/29
    2c0f:f248::/32
)

preflight_expand_ipv6() {
    local value="${1,,}"
    local head tail group
    # ``set -u`` reads the length of an empty array as unbound unless it was
    # initialised, and the ``::`` form leaves one half empty by definition.
    local -a left=() right=() groups=()
    [[ -n "$value" && "$value" != *:::* ]] || return 1
    if [[ "$value" == *::* ]]; then
        head="${value%%::*}"
        tail="${value#*::}"
        if [[ -n "$head" ]]; then
            IFS=':' read -r -a left <<< "$head"
        fi
        if [[ -n "$tail" ]]; then
            IFS=':' read -r -a right <<< "$tail"
        fi
        local missing=$(( 8 - ${#left[@]} - ${#right[@]} ))
        (( missing >= 1 )) || return 1
        groups=("${left[@]}")
        local index
        for (( index = 0; index < missing; index++ )); do
            groups+=("0")
        done
        groups+=("${right[@]}")
    else
        IFS=':' read -r -a groups <<< "$value"
    fi
    [[ ${#groups[@]} -eq 8 ]] || return 1
    for group in "${groups[@]}"; do
        [[ ${#group} -le 4 && "$group" =~ ^[0-9A-Fa-f]+$ ]] || return 1
        printf '%04x\n' "0x${group}"
    done
}

preflight_ipv6_in_cidr() {
    local address="$1" network="$2" prefix="$3"
    local -a a=() n=()
    mapfile -t a < <(preflight_expand_ipv6 "$address") || return 1
    mapfile -t n < <(preflight_expand_ipv6 "$network") || return 1
    [[ ${#a[@]} -eq 8 && ${#n[@]} -eq 8 ]] || return 1
    local index=$(( prefix / 16 ))
    local remainder=$(( prefix % 16 ))
    local position
    for (( position = 0; position < index; position++ )); do
        [[ "${a[$position]}" == "${n[$position]}" ]] || return 1
    done
    if (( remainder > 0 )); then
        local mask=$(( (0xFFFF << (16 - remainder)) & 0xFFFF ))
        (( (0x${a[$index]} & mask) == (0x${n[$index]} & mask) )) || return 1
    fi
    return 0
}

preflight_ipv4_in_cidr() {
    local address="$1" network="$2" prefix="$3"
    local -a a=() n=()
    IFS='.' read -r -a a <<< "$address"
    IFS='.' read -r -a n <<< "$network"
    [[ ${#a[@]} -eq 4 && ${#n[@]} -eq 4 ]] || return 1
    local address_value=0 network_value=0 index
    for index in 0 1 2 3; do
        address_value=$(( address_value * 256 + a[index] ))
        network_value=$(( network_value * 256 + n[index] ))
    done
    (( prefix == 0 )) && return 0
    local shift=$(( 32 - prefix ))
    (( (address_value >> shift) == (network_value >> shift) ))
}

preflight_cidr_match() {
    local address="$1" cidr="$2" prefix
    [[ "$cidr" == */* ]] || return 1
    prefix="${cidr#*/}"
    [[ "$prefix" =~ ^[0-9]+$ ]] || return 1
    if [[ "$address" == *:* ]]; then
        [[ "$cidr" == *:* ]] || return 1
        (( prefix <= 128 )) || return 1
        preflight_ipv6_in_cidr "$address" "${cidr%/*}" "$prefix"
    else
        [[ "$cidr" != *:* ]] || return 1
        (( prefix <= 32 )) || return 1
        preflight_ipv4_in_cidr "$address" "${cidr%/*}" "$prefix"
    fi
}

preflight_require_direct_dns() {
    local name address cidr
    local -a cidrs=()
    if [[ -n "${GOWAVE_PREFLIGHT_PROXY_CIDRS:-}" ]]; then
        local list="${GOWAVE_PREFLIGHT_PROXY_CIDRS// /}"
        IFS=',' read -r -a cidrs <<< "$list"
    else
        cidrs=("${PREFLIGHT_PROXY_CIDRS[@]}")
    fi

    local -a proxied=()
    for name in "$@"; do
        [[ -z "$name" ]] && continue
        local -a resolved=()
        while read -r address _; do
            [[ -n "$address" ]] && resolved+=("$address")
        done < <(getent ahosts "$name" 2>/dev/null || true)
        if [[ ${#resolved[@]} -eq 0 ]]; then
            printf 'Error: preflight could not resolve %s; HTTP-01 needs a name that answers here.\n' \
                "$name" >&2
            return 1
        fi
        for address in "${resolved[@]}"; do
            for cidr in "${cidrs[@]}"; do
                [[ -z "$cidr" ]] && continue
                if preflight_cidr_match "$address" "$cidr"; then
                    proxied+=("$name resolves to $address, inside $cidr")
                    break
                fi
            done
        done
    done

    if [[ ${#proxied[@]} -gt 0 ]]; then
        if [[ "${GOWAVE_PREFLIGHT_ALLOW_PROXIED:-0}" == "1" ]]; then
            printf 'Warning: a requested name answers from a proxy range; continuing because GOWAVE_PREFLIGHT_ALLOW_PROXIED=1:\n' >&2
            printf '  - %s\n' "${proxied[@]}" >&2
            return 0
        fi
        printf 'Error: a requested name is fronted by the Cloudflare proxy (snapshot %s):\n' \
            "$PREFLIGHT_PROXY_CIDRS_SNAPSHOT" >&2
        printf '  - %s\n' "${proxied[@]}" >&2
        printf 'HTTP-01 cannot complete behind the proxy. Make the DNS record DNS-only (grey cloud) and retry.\n' >&2
        printf 'Set GOWAVE_PREFLIGHT_ALLOW_PROXIED=1 to record a decision to continue anyway.\n' >&2
        return 1
    fi
    return 0
}

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
