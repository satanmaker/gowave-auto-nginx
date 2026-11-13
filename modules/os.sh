#!/usr/bin/env bash
# modules/os.sh - Base OS, package inventory, and environment detection
set -euo pipefail

detect_os() {
    local os_release="${1:-/etc/os-release}"
    local key value

    OS_ID=""
    OS_VERSION_ID=""
    OS_CODENAME=""

    if [[ ! -f "$os_release" ]]; then
        return 1
    fi

    while IFS='=' read -r key value || [[ -n "$key" ]]; do
        case "$value" in \"*\"|\'*\') value=${value:1:-1} ;; esac
        case "$key" in
            ID) OS_ID=$value ;;
            VERSION_ID) OS_VERSION_ID=$value ;;
            VERSION_CODENAME) OS_CODENAME=$value ;;
        esac
    done < "$os_release"

    # Fallback codename if not in os-release
    if [[ -z "$OS_CODENAME" ]]; then
        case "${OS_ID}-${OS_VERSION_ID}" in
            ubuntu-24.04) OS_CODENAME="noble" ;;
            ubuntu-26.04) OS_CODENAME="resolute" ;;
            debian-12) OS_CODENAME="bookworm" ;;
            debian-13) OS_CODENAME="trixie" ;;
        esac
    fi
    return 0
}

check_os() {
    local os_release="${1:-/etc/os-release}"
    local os_id='' os_version='' key value

    if [[ ! -f "$os_release" ]]; then
        echo "Error: $os_release not found" >&2
        return 1
    fi

    while IFS='=' read -r key value || [[ -n "$key" ]]; do
        case "$value" in \"*\"|\'*\') value=${value:1:-1} ;; esac
        case "$key" in
            ID) os_id=$value ;;
            VERSION_ID) os_version=$value ;;
        esac
    done < "$os_release"

    case "${os_id}" in
        ubuntu)
            if [[ "$os_version" == "24.04" || "$os_version" == "26.04" ]]; then
                return 0
            fi
            ;;
        debian)
            if [[ "$os_version" == "12" || "$os_version" == "13" ]]; then
                return 0
            fi
            ;;
    esac

    echo "Error: Unsupported OS: ${os_id:-unknown} ${os_version:-unknown}" >&2
    echo "Supported operating systems: Ubuntu 24.04, Ubuntu 26.04, Debian 12, Debian 13" >&2
    return 1
}

check_kernel_ipv6() {
    local if_inet6="${1:-/proc/net/if_inet6}"
    # The address table has to be read, not measured: procfs reports a zero
    # inode size for /proc/net/if_inet6 however many addresses it prints, so
    # ``[[ -s ]]`` answers "empty" even on a dual-stack host.
    if [[ ! -f "$if_inet6" ]] || ! grep -q '[^[:space:]]' "$if_inet6" 2>/dev/null; then
        return 1
    fi
    # Check sysctl disable_ipv6 if sysctl is available
    if command -v sysctl >/dev/null 2>&1; then
        local disabled
        disabled=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 0)
        if [[ "$disabled" == "1" ]]; then
            return 1
        fi
    fi
    return 0
}

detect_nginx_version() {
    local nginx_bin="${1:-nginx}"
    local ver_str=""

    if [[ -n "${OVERRIDE_NGINX_VERSION:-}" ]]; then
        echo "$OVERRIDE_NGINX_VERSION"
        return 0
    fi

    if command -v "$nginx_bin" >/dev/null 2>&1; then
        ver_str=$("$nginx_bin" -v 2>&1 || true)
    elif [[ -x "$nginx_bin" ]]; then
        ver_str=$("$nginx_bin" -v 2>&1 || true)
    else
        echo "unknown"
        return 1
    fi

    # Format: nginx version: nginx/1.24.0
    if [[ "$ver_str" =~ nginx/([0-9]+\.[0-9]+\.[0-9]+) ]]; then
        echo "${BASH_REMATCH[1]}"
        return 0
    fi
    echo "unknown"
    return 1
}

is_version_ge() {
    local v1="$1"
    local v2="$2"
    # Returns 0 if v1 >= v2
    if [[ "$v1" == "$v2" ]]; then
        return 0
    fi
    local lowest
    lowest=$(printf '%s\n%s\n' "$v1" "$v2" | sort -V | head -n1)
    [[ "$lowest" == "$v2" ]]
}

render_nginx_listen_ssl_http2() {
    local bind_addr="$1"
    local extra_opts="${2:-}"
    local nginx_bin="${3:-nginx}"
    local version=""
    local space_extra=""

    if [[ -n "$extra_opts" ]]; then
        space_extra=" $extra_opts"
    fi

    version=$(detect_nginx_version "$nginx_bin" 2>/dev/null || echo "1.24.0")
    if [[ "$version" == "unknown" ]]; then
        version="1.24.0"
    fi

    if is_version_ge "$version" "1.25.1"; then
        # Modern syntax: listen ... ssl <extra>; http2 on;
        printf 'listen %s ssl%s;\n    http2 on;' "$bind_addr" "$space_extra"
    else
        # Legacy syntax: listen ... ssl http2 <extra>;
        printf 'listen %s ssl http2%s;' "$bind_addr" "$space_extra"
    fi
}

configure_debian_security_apt() {
    local apt_conf_dir="${1:-/etc/apt/apt.conf.d}"
    local os_release="${2:-/etc/os-release}"

    detect_os "$os_release" || true

    if [[ "$OS_ID" == "debian" ]]; then
        local codename="${OS_CODENAME:-bookworm}"
        mkdir -p "$apt_conf_dir"
        local conf_file="${apt_conf_dir}/99zz-gowave-auto-nginx"
        cat > "$conf_file" <<EOF
// Managed by GoWave Auto NGINX
Unattended-Upgrade::Allowed-Origins {
    "origin=Debian,label=Debian-Security,codename=${codename}-security";
};
Unattended-Upgrade::Automatic-Reboot "false";
EOF
        chmod 0644 "$conf_file"
    elif [[ "$OS_ID" == "ubuntu" ]]; then
        mkdir -p "$apt_conf_dir"
        local conf_file="${apt_conf_dir}/99zz-gowave-auto-nginx"
        cat > "$conf_file" <<EOF
// Managed by GoWave Auto NGINX
Unattended-Upgrade::Automatic-Reboot "false";
EOF
        chmod 0644 "$conf_file"
    fi
}

ensure_systemd_resolved() {
    local os_release="${1:-/etc/os-release}"
    detect_os "$os_release" || true

    if [[ "$OS_ID" == "debian" && ( "$OS_VERSION_ID" == "12" || "$OS_VERSION_ID" == "13" ) ]]; then
        mkdir -p /etc/systemd/resolved.conf.d
        if [[ ! -f /etc/systemd/resolved.conf.d/90-gowave-auto-nginx.conf ]]; then
            cat > /etc/systemd/resolved.conf.d/90-gowave-auto-nginx.conf << 'EOF'
# Managed by GoWave Auto NGINX: VPS Security
[Resolve]
DNS=
DNS=1.1.1.1#one.one.one.one 1.0.0.1#one.one.one.one 8.8.8.8#dns.google 8.8.4.4#dns.google
FallbackDNS=
Domains=
Domains=~.
DNSOverTLS=yes
DNSSEC=no
LLMNR=no
MulticastDNS=no
Cache=yes
DNSStubListener=yes
EOF
        fi
        if ! command -v resolvectl >/dev/null 2>&1; then
            echo "Installing systemd-resolved on Debian ${OS_VERSION_ID}..."
            DEBIAN_FRONTEND=noninteractive apt-get update -qq && \
            DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd-resolved
            systemctl enable --now systemd-resolved || true
        fi
        systemctl restart systemd-resolved 2>/dev/null || true
    fi
}

get_required_packages() {
    cat <<'EOF'
nginx-full
libnginx-mod-stream
certbot
python3
python3-systemd
sqlite3
curl
tar
gzip
openssl
ufw
fail2ban
systemd-resolved
iproute2
ca-certificates
openssh-client
EOF
}

# Packages the arguments-validation and address-resolution steps need before
# install_prerequisites runs. Every one of them ships with a stock supported
# image; the list exists so a minimal container is not failed blind.
get_bootstrap_packages() {
    cat <<'EOF'
python3
iproute2
curl
ca-certificates
openssl
EOF
}

missing_packages() {
    local pkg
    for pkg in "$@"; do
        [[ -z "$pkg" || "$pkg" =~ ^# ]] && continue
        if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
            printf '%s\n' "$pkg"
        fi
    done
}

check_prerequisites() {
    local packages=() missing=()
    mapfile -t packages < <(get_required_packages)
    mapfile -t missing < <(missing_packages "${packages[@]}")

    if [[ ${#missing[@]} -gt 0 ]]; then
        printf '%s\n' "${missing[@]}"
        return 1
    fi
    return 0
}

bootstrap_early_tools() {
    local packages=() missing=()
    mapfile -t packages < <(get_bootstrap_packages)
    mapfile -t missing < <(missing_packages "${packages[@]}")

    if [[ ${#missing[@]} -eq 0 ]]; then
        return 0
    fi
    echo "Bootstrapping early tools required before prerequisites: ${missing[*]}..."
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"
}

install_prerequisites() {
    local missing=()
    mapfile -t missing < <(check_prerequisites || true)

    if [[ ${#missing[@]} -eq 0 ]]; then
        echo "All prerequisites are satisfied."
        return 0
    fi

    echo "Installing missing prerequisites: ${missing[*]}..."
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"
    ensure_systemd_resolved
    return 0
}
