#!/usr/bin/env bash
# modules/panel.sh - GoWave Panel native deployment, environment, and service lifecycle
set -euo pipefail

GOWAVE_INSTALL_DIR="/opt/gowave"
GOWAVE_DEFAULT_VERSION="latest"
GOWAVE_REPO="aaaSaZaN/gowave"

detect_arch() {
    local m
    m=$(uname -m)
    case "$m" in
        x86_64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *)
            echo "Unsupported architecture: $m" >&2
            return 1
            ;;
    esac
}

ensure_gowave_user() {
    if ! id -u gowave >/dev/null 2>&1; then
        if [[ "$(id -u)" -eq 0 ]]; then
            echo "Creating gowave system user and group..."
            useradd --system --no-create-home --shell /usr/sbin/nologin gowave
        fi
    fi
}

download_panel_release() {
    local target_dir="${1:-$GOWAVE_INSTALL_DIR}"
    local version="${2:-$GOWAVE_DEFAULT_VERSION}"
    local arch
    arch=$(detect_arch)

    mkdir -p "$target_dir"
    local tmp_dir
    tmp_dir=$(mktemp -d "/tmp/gowave-download-XXXXXX")
    trap '[[ -n "${tmp_dir:-}" ]] && rm -rf "$tmp_dir"' RETURN

    local base_url="https://github.com/${GOWAVE_REPO}/releases"
    local tag_url="$base_url/latest/download"
    if [[ "$version" != "latest" ]]; then
        tag_url="$base_url/download/$version"
    fi

    echo "Downloading GoWave Panel release ($version, $arch)..."

    # Support offline local artifacts via env if provided
    local bin_source="${GOWAVE_PANEL_BINARY:-}"
    local frontend_source="${GOWAVE_FRONTEND_ARCHIVE:-}"
    local sums_source="${GOWAVE_SHA256SUMS:-}"

    fetch_panel_asset() {
        local name="$1"
        local target="$2"
        if ! curl -fsSL --connect-timeout 15 "$tag_url/$name" -o "$target" 2>/dev/null; then
            echo "Direct download failed for $name; attempting GitHub API fallback..."
            local api_url
            api_url=$(curl -s "https://api.github.com/repos/${GOWAVE_REPO}/releases" | python3 -c "
import sys, json
try:
    releases = json.load(sys.stdin)
    for r in releases:
        if '$version' == 'latest' or r.get('tag_name') == '$version':
            for a in r.get('assets', []):
                if a.get('name') == '$name':
                    print(a.get('url'))
                    sys.exit(0)
except Exception:
    pass
" 2>/dev/null || true)
            if [[ -n "$api_url" ]]; then
                curl -fsSL -H "Accept: application/octet-stream" "$api_url" -o "$target"
            fi
        fi
    }

    if [[ -z "$bin_source" ]]; then
        fetch_panel_asset "gowave-linux-$arch" "$tmp_dir/gowave-server"
        fetch_panel_asset "gowave-frontend.tar.gz" "$tmp_dir/gowave-frontend.tar.gz"
        fetch_panel_asset "SHA256SUMS" "$tmp_dir/SHA256SUMS" || true
    else
        cp "$bin_source" "$tmp_dir/gowave-server"
        cp "$frontend_source" "$tmp_dir/gowave-frontend.tar.gz"
        [[ -n "$sums_source" ]] && cp "$sums_source" "$tmp_dir/SHA256SUMS"
    fi

    # Verify SHA256 if SHA256SUMS exists
    if [[ -f "$tmp_dir/SHA256SUMS" ]]; then
        echo "Verifying SHA256 checksums..."
        (
            cd "$tmp_dir"
            # Extract expected hashes for our files
            local expected_bin expected_front
            expected_bin=$(grep "gowave-linux-$arch" SHA256SUMS | awk '{print $1}' || true)
            expected_front=$(grep "gowave-frontend.tar.gz" SHA256SUMS | awk '{print $1}' || true)

            if [[ -n "$expected_bin" ]]; then
                local actual_bin
                actual_bin=$(sha256sum gowave-server | awk '{print $1}')
                if [[ "$actual_bin" != "$expected_bin" ]]; then
                    echo "Error: Checksum mismatch for gowave-server: expected $expected_bin, got $actual_bin" >&2
                    return 1
                fi
            fi

            if [[ -n "$expected_front" ]]; then
                local actual_front
                actual_front=$(sha256sum gowave-frontend.tar.gz | awk '{print $1}')
                if [[ "$actual_front" != "$expected_front" ]]; then
                    echo "Error: Checksum mismatch for gowave-frontend.tar.gz: expected $expected_front, got $actual_front" >&2
                    return 1
                fi
            fi
        )
    fi

    # Install files
    cp "$tmp_dir/gowave-server" "$target_dir/gowave-server"
    chmod 0755 "$target_dir/gowave-server"

    mkdir -p "$target_dir/frontend"
    tar -xzf "$tmp_dir/gowave-frontend.tar.gz" -C "$target_dir/frontend"

    # Set ownership if root
    ensure_gowave_user
    if [[ "$(id -u)" -eq 0 ]]; then
        chown -R root:gowave "$target_dir"
    fi
    chmod 1770 "$target_dir" 2>/dev/null || chmod 0770 "$target_dir" || true
    echo "GoWave Panel binaries installed successfully in $target_dir."
    rm -rf "$tmp_dir"
}

generate_panel_env() {
    local target_dir="${1:-$GOWAVE_INSTALL_DIR}"
    local panel_domain="$2"
    local sub_domain="${3:-$panel_domain/api/sub}"
    local app_port="${4:-3000}"
    local metrics_port="${5:-3001}"
    local channel="${6:-stable}"

    local env_file="$target_dir/.env"
    local app_secret
    app_secret=$(openssl rand -hex 32)

    mkdir -p "$target_dir"
    ensure_gowave_user

    # Generate mode 0640 .env with root:gowave ownership
    (
        umask 027
        cat > "$env_file" <<EOF
# Managed by GoWave Auto NGINX
APP_HOST=127.0.0.1
APP_PORT=$app_port
METRICS_ENABLED=false
METRICS_PORT=$metrics_port
DB_DRIVER=sqlite
DATABASE_URL=gowave.db
APP_SECRET=$app_secret
GOWAVE_PROXY=external
GOWAVE_CHANNEL=$channel
PANEL_DOMAIN=$panel_domain
SUB_PUBLIC_DOMAIN=$sub_domain
EOF
    )

    if [[ "$(id -u)" -eq 0 ]]; then
        chown root:gowave "$env_file"
    fi
    chmod 0640 "$env_file"
    echo "Generated $env_file with mode 0640."
}

configure_panel_systemd() {
    local target_dir="${1:-$GOWAVE_INSTALL_DIR}"
    local unit_file="/etc/systemd/system/gowave.service"
    local recover_unit="/etc/systemd/system/gowave-recover.service"
    local recover_prov_unit="/etc/systemd/system/gowave-recover-provision.service"

    ensure_gowave_user

    # 1. Base unit /etc/systemd/system/gowave.service
    cat > "$unit_file" <<EOF
[Unit]
Description=GoWave Panel Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=gowave
Group=gowave
WorkingDirectory=$target_dir
ExecStart=$target_dir/gowave-server
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    # 2. Early-boot file recovery unit
    cat > "$recover_unit" <<'EOF'
[Unit]
Description=GoWave Auto NGINX early boot file/DB recovery
ConditionPathExists=/var/lib/gowave-auto-nginx/recovery/journal.json
Before=gowave.service gowave-node.service
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/gowave-auto.sh recover --boot-files

[Install]
WantedBy=multi-user.target
EOF

    # 3. Post-boot API recovery unit
    cat > "$recover_prov_unit" <<'EOF'
[Unit]
Description=GoWave Auto NGINX post-boot API provision cleanup
ConditionPathExists=/var/lib/gowave-auto-nginx/recovery/journal.json
After=gowave.service
Wants=gowave.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/gowave-auto.sh recover --boot-provision

[Install]
WantedBy=multi-user.target
EOF

    if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload --no-ask-password
        systemctl enable --no-ask-password gowave.service gowave-recover.service gowave-recover-provision.service
    fi

    # 4. Invoke native gowave-server service install if binary exists and is executable
    if [[ -x "$target_dir/gowave-server" ]]; then
        echo "Executing upstream service installation..."
        "$target_dir/gowave-server" service install "$target_dir" || true
    fi
    echo "Panel systemd units registered successfully."
}

verify_panel_startup() {
    local host="${1:-127.0.0.1}"
    local port="${2:-3000}"
    local timeout="${3:-30}"
    local interval=1
    local elapsed=0

    echo "Waiting for GoWave Panel listener at http://$host:$port..."
    while [[ $elapsed -lt $timeout ]]; do
        if curl -fsSL -o /dev/null "http://$host:$port/api/system/health" 2>/dev/null || \
           curl -fsSL -o /dev/null "http://$host:$port" 2>/dev/null; then
            echo "GoWave Panel is healthy and listening on http://$host:$port."
            return 0
        fi
        sleep "$interval"
        elapsed=$((elapsed + interval))
    done

    echo "Error: Timed out after ${timeout}s waiting for GoWave Panel at http://$host:$port" >&2
    if [[ "$(id -u)" -eq 0 ]] && command -v journalctl >/dev/null 2>&1; then
        journalctl -u gowave -n 25 --no-pager >&2 || true
    fi
    return 1
}
