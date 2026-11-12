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

save_credentials() {
    local username="$1"
    local password="$2"
    local panel_url="$3"
    local token="${4:-}"
    local creds_file="${5:-${CREDENTIALS_FILE:-/root/gowave-credentials.txt}}"

    local creds_dir
    creds_dir="$(dirname "$creds_file")"
    mkdir -p "$creds_dir"
    local tmp_file="${creds_file}.tmp"

    (
        umask 077
        cat > "$tmp_file" <<EOF
# GoWave Auto NGINX Administrative Credentials
# Generated at $(date -u +"%Y-%m-%dT%H:%M:%SZ")
PANEL_URL=$panel_url
ADMIN_USERNAME=$username
ADMIN_PASSWORD=$password
EOF
        if [[ -n "$token" ]]; then
            echo "SCOPED_API_TOKEN=$token" >> "$tmp_file"
        fi
    )
    chmod 0600 "$tmp_file"
    sync "$tmp_file" 2>/dev/null || true
    mv -f "$tmp_file" "$creds_file"
    sync "$creds_dir" 2>/dev/null || true
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
        local candidate_urls=()
        if [[ "$version" == "latest" ]]; then
            candidate_urls+=("$base_url/latest/download/$name")
        else
            candidate_urls+=("$base_url/download/$version/$name")
            if [[ "$version" == v* ]]; then
                candidate_urls+=("$base_url/download/${version#v}/$name")
            else
                candidate_urls+=("$base_url/download/v${version}/$name")
            fi
        fi

        local downloaded=0
        for u in "${candidate_urls[@]}"; do
            if curl -fsSL --retry 2 --connect-timeout 15 "$u" -o "$target" 2>/dev/null; then
                if [[ -s "$target" ]]; then
                    downloaded=1
                    break
                fi
            fi
        done

        if [[ "$downloaded" -eq 0 ]]; then
            echo "Direct download failed for $name; attempting GitHub API fallback..."
            local api_url
            api_url=$(curl -fsSL "https://api.github.com/repos/${GOWAVE_REPO}/releases" 2>/dev/null | python3 -c "
import sys, json
try:
    releases = json.load(sys.stdin)
    v_target = '$version'
    v_clean = v_target.lstrip('v')
    for r in releases:
        tag = r.get('tag_name', '')
        tag_clean = tag.lstrip('v')
        if v_target == 'latest' or tag == v_target or tag_clean == v_clean:
            for a in r.get('assets', []):
                if a.get('name') == '$name':
                    print(a.get('url'))
                    sys.exit(0)
except Exception:
    pass
" 2>/dev/null || true)
            if [[ -n "$api_url" ]]; then
                curl -fsSL --retry 2 -H "Accept: application/octet-stream" "$api_url" -o "$target"
            fi
        fi
        [[ -s "$target" ]] || return 1
    }

    if [[ -z "$bin_source" ]]; then
        fetch_panel_asset "gowave-linux-$arch" "$tmp_dir/gowave-server" || {
            echo "Error: failed to download GoWave Panel binary." >&2
            return 1
        }
        fetch_panel_asset "gowave-frontend.tar.gz" "$tmp_dir/gowave-frontend.tar.gz" || {
            echo "Error: failed to download GoWave frontend archive." >&2
            return 1
        }
        fetch_panel_asset "SHA256SUMS" "$tmp_dir/SHA256SUMS" || {
            echo "Error: release SHA256SUMS is required; refusing unverified artifacts." >&2
            return 1
        }
    else
        cp "$bin_source" "$tmp_dir/gowave-server"
        cp "$frontend_source" "$tmp_dir/gowave-frontend.tar.gz"
        [[ -n "$sums_source" ]] && cp "$sums_source" "$tmp_dir/SHA256SUMS"
    fi

    # Checksums are mandatory for downloaded and explicitly supplied artifacts.
    [[ -s "$tmp_dir/SHA256SUMS" ]] || {
        echo "Error: SHA256SUMS is missing or empty; refusing unverified artifacts." >&2
        return 1
    }
    echo "Verifying mandatory SHA256 checksums..."
    (
        cd "$tmp_dir"
        local expected_bin expected_front actual_bin actual_front
        expected_bin=$(awk -v name="gowave-linux-$arch" '$2 == name || $2 == "*" name {print $1}' SHA256SUMS)
        expected_front=$(awk '$2 == "gowave-frontend.tar.gz" || $2 == "*gowave-frontend.tar.gz" {print $1}' SHA256SUMS)
        [[ "$expected_bin" =~ ^[[:xdigit:]]{64}$ ]] || {
            echo "Error: SHA256SUMS must contain exactly one valid checksum for gowave-linux-$arch." >&2
            exit 1
        }
        [[ "$expected_front" =~ ^[[:xdigit:]]{64}$ ]] || {
            echo "Error: SHA256SUMS must contain exactly one valid checksum for gowave-frontend.tar.gz." >&2
            exit 1
        }
        actual_bin=$(sha256sum gowave-server | awk '{print $1}')
        actual_front=$(sha256sum gowave-frontend.tar.gz | awk '{print $1}')
        if [[ "$actual_bin" != "$expected_bin" ]]; then
            echo "Error: Checksum mismatch for gowave-server: expected $expected_bin, got $actual_bin" >&2
            exit 1
        fi
        if [[ "$actual_front" != "$expected_front" ]]; then
            echo "Error: Checksum mismatch for gowave-frontend.tar.gz: expected $expected_front, got $actual_front" >&2
            exit 1
        fi
    )

    # Install files. A repeated install replaces the binary the Panel is already
    # running from this path, and writing through that inode fails with ETXTBSY.
    # Staging beside the target and renaming only swaps the directory entry.
    local staged_server="$target_dir/.gowave-server.new"
    cp "$tmp_dir/gowave-server" "$staged_server"
    chmod 0755 "$staged_server"
    sync "$staged_server" 2>/dev/null || true
    mv -f "$staged_server" "$target_dir/gowave-server"
    sync "$target_dir" 2>/dev/null || true

    mkdir -p "$target_dir/frontend"
    tar -xzf "$tmp_dir/gowave-frontend.tar.gz" -C "$target_dir/frontend"
    ln -sfn "$target_dir/frontend" "$target_dir/dist"

    # Set ownership if root
    ensure_gowave_user
    if [[ "$(id -u)" -eq 0 ]]; then
        chown -R root:gowave "$target_dir"
        retain_panel_data_ownership "$target_dir"
    fi
    chmod 1770 "$target_dir" 2>/dev/null || chmod 0770 "$target_dir" || true
    echo "GoWave Panel binaries installed successfully in $target_dir."
    rm -rf "$tmp_dir"
}

retain_panel_data_ownership() {
    # The Panel writes its own database, and a binary refresh hands every file in
    # the install directory to root. Leaving the database root-owned turns the
    # running Panel's next write into "attempt to write a readonly database".
    local target_dir="${1:-$GOWAVE_INSTALL_DIR}"
    local data_file
    for data_file in "$target_dir/gowave.db" "$target_dir/gowave.db-wal" "$target_dir/gowave.db-shm"; do
        [[ -e "$data_file" ]] || continue
        chown gowave:gowave "$data_file"
        chmod 0600 "$data_file"
    done
}

generate_panel_env() {
    local target_dir="${1:-$GOWAVE_INSTALL_DIR}"
    local panel_domain="$2"
    local sub_domain="${3:-$panel_domain/api/sub}"
    local app_port="${4:-3000}"
    local metrics_port="${5:-3001}"
    local channel="${6:-stable}"

    local env_file="$target_dir/.env"
    # A repeated install keeps the running Panel's APP_SECRET: it is the key the
    # Panel encrypts stored credentials with, so a new one would make every row
    # it already wrote unreadable.
    local app_secret=""
    if [[ -r "$env_file" ]]; then
        app_secret=$(grep -s '^APP_SECRET=' "$env_file" | cut -d= -f2- || true)
    fi
    if [[ -z "$app_secret" ]]; then
        app_secret=$(openssl rand -hex 32)
    fi

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

    # The managed gowave.service unit above is authoritative. Do not invoke the
    # upstream "service install" command here: it may rewrite the hardened unit.
    echo "Managed Panel and recovery systemd units registered successfully."
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
