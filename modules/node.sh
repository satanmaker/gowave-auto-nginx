#!/usr/bin/env bash
# modules/node.sh - GoWave Node installation, configuration, and mTLS verification
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GOWAVE_NODE_INSTALL_DIR="/opt/gowave-node"
DEFAULT_NODE_PORT=3002

extract_secret_key() {
    local gowave_dir="${1:-/opt/gowave}"
    local gowave_bin="$gowave_dir/gowave-server"

    if [[ ! -x "$gowave_bin" ]]; then
        echo "Error: GoWave binary $gowave_bin not found or not executable" >&2
        return 1
    fi

    local secret
    secret=$(cd "$gowave_dir" && "$gowave_bin" rescue --print-secret-key-raw </dev/null 2>/dev/null || true)
    secret="${secret//[[:space:]]/}"

    if [[ -z "$secret" ]]; then
        echo "Error: Failed to extract SECRET_KEY via rescue --print-secret-key-raw" >&2
        return 1
    fi

    # Print strictly the secret key to stdout
    printf '%s' "$secret"
}

configure_node_env() {
    local target_dir="${1:-$GOWAVE_NODE_INSTALL_DIR}"
    local secret_key="$2"
    local node_port="${3:-$DEFAULT_NODE_PORT}"
    local env_file="$target_dir/.env"

    mkdir -p "$target_dir"
    (
        umask 077
        cat > "$env_file" <<EOF
# Managed by GoWave Auto NGINX
SECRET_KEY=$secret_key
NODE_PORT=$node_port
SNI_VERIFICATION=true
EOF
    )
    chmod 0600 "$env_file"
    echo "Configured $env_file with mode 0600."
}

deploy_node_systemd_dropins() {
    local node_port="${1:-$DEFAULT_NODE_PORT}"
    local dropin_dir="${2:-/etc/systemd/system/gowave-node.service.d}"

    mkdir -p "$dropin_dir"
    cat > "$dropin_dir/10-port.conf" <<EOF
[Service]
Environment="NODE_PORT=$node_port"
ExecStartPost=/usr/bin/env bash -c 'for i in {1..30}; do if ss -Hltn "sport = :$node_port" 2>/dev/null | grep -q "$node_port" || (: < /dev/tcp/127.0.0.1/$node_port) 2>/dev/null; then exit 0; fi; sleep 0.5; done; exit 1'
EOF

    if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload --no-ask-password
    fi
    echo "Deployed $dropin_dir/10-port.conf."
}

install_local_node() {
    local secret_key="$1"
    local node_port="${2:-$DEFAULT_NODE_PORT}"
    local upstream_installer="${3:-}"

    echo "Orchestrating local GoWave Node installation (port $node_port)..."

    # Use bundled upstream installer if available
    if [[ -z "$upstream_installer" ]]; then
        if [[ -f "$SCRIPT_DIR/sources/gowave-node/install.sh" ]]; then
            upstream_installer="$SCRIPT_DIR/sources/gowave-node/install.sh"
        fi
    fi

    # E2E Gate: require bundled installer and verified SHA256 when configured
    if [[ "${GOWAVE_NODE_REQUIRE_BUNDLED_INSTALLER:-0}" == "1" ]]; then
        if [[ -z "$upstream_installer" || ! -f "$upstream_installer" ]]; then
            echo "Error: GOWAVE_NODE_REQUIRE_BUNDLED_INSTALLER=1 but bundled installer is absent ($upstream_installer)." >&2
            return 1
        fi
        if [[ -z "${GOWAVE_NODE_INSTALLER_SHA256:-}" ]]; then
            echo "Error: GOWAVE_NODE_REQUIRE_BUNDLED_INSTALLER=1 but GOWAVE_NODE_INSTALLER_SHA256 is not set." >&2
            return 1
        fi
        local actual_sha256
        actual_sha256=$(sha256sum "$upstream_installer" | awk '{print $1}')
        if [[ "$actual_sha256" != "$GOWAVE_NODE_INSTALLER_SHA256" ]]; then
            echo "Error: Bundled installer SHA256 mismatch: expected $GOWAVE_NODE_INSTALLER_SHA256, got $actual_sha256." >&2
            return 1
        fi
    fi

    # Pass SECRET_KEY and NODE_PORT strictly via environment to installer execution
    if [[ -n "$upstream_installer" && -f "$upstream_installer" ]]; then
        if [[ -n "${GOWAVE_NODE_INSTALLER_SHA256:-}" ]]; then
            local actual_sha256
            actual_sha256=$(sha256sum "$upstream_installer" | awk '{print $1}')
            if [[ "$actual_sha256" != "$GOWAVE_NODE_INSTALLER_SHA256" ]]; then
                echo "Error: Bundled installer SHA256 mismatch: expected $GOWAVE_NODE_INSTALLER_SHA256, got $actual_sha256." >&2
                return 1
            fi
        fi
        (
            export SECRET_KEY="$secret_key"
            export NODE_PORT="$node_port"
            export GOWAVE_NODE_VERSION="${GOWAVE_NODE_VERSION:-latest}"
            bash "$upstream_installer" </dev/null
        )
    elif [[ "${GOWAVE_NODE_REQUIRE_BUNDLED_INSTALLER:-0}" == "1" ]]; then
        echo "Error: GOWAVE_NODE_REQUIRE_BUNDLED_INSTALLER=1 prohibits remote download or floating fallback." >&2
        return 1
    else
        echo "Fetching upstream gowave-node installer..."
        (
            export SECRET_KEY="$secret_key"
            export NODE_PORT="$node_port"
            export GOWAVE_NODE_VERSION="${GOWAVE_NODE_VERSION:-latest}"
            local tmp_inst
            tmp_inst=$(mktemp "/tmp/gowave-node-install-XXXXXX.sh")
            curl -fsSL https://raw.githubusercontent.com/aaaSaZaN/gowave-node/main/install.sh -o "$tmp_inst"
            chmod 0700 "$tmp_inst"
            bash "$tmp_inst" </dev/null
            rm -f "$tmp_inst"
        )
    fi

    # Ensure hardening and port configuration in .env and drop-in
    configure_node_env "$GOWAVE_NODE_INSTALL_DIR" "$secret_key" "$node_port"
    deploy_node_systemd_dropins "$node_port"

    # Install pinned Xray core version if explicitly configured and mismatched
    if [[ -n "${XRAY_SERVER_VERSION:-}" && -x "$GOWAVE_NODE_INSTALL_DIR/gowave-node" ]]; then
        local cur_core
        cur_core=$("$GOWAVE_NODE_INSTALL_DIR/rw-core" version 2>/dev/null || true)
        if ! echo "$cur_core" | grep -q "${XRAY_SERVER_VERSION#v}"; then
            echo "Installing explicit Xray server version $XRAY_SERVER_VERSION..."
            "$GOWAVE_NODE_INSTALL_DIR/gowave-node" core install --version "v${XRAY_SERVER_VERSION#v}" -y 2>/dev/null || \
            "$GOWAVE_NODE_INSTALL_DIR/gowave-node" core install --version "${XRAY_SERVER_VERSION#v}" -y 2>/dev/null || true
        fi
    fi

    # Isolate local node from external network access
    if command -v ufw >/dev/null 2>&1; then
        echo "UFW: Enforcing external isolation on port $node_port/tcp..."
        ufw deny "${node_port}/tcp" comment "Isolate local GoWave Node from external access" || true
    fi

    if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        systemctl restart --no-ask-password gowave-node.service || true
    fi
    echo "Local GoWave Node installed and hardened on port $node_port."
}

verify_node_mtls_health() {
    local secret_b64="$1"
    local node_port="${2:-$DEFAULT_NODE_PORT}"
    local host="${3:-127.0.0.1}"
    local mode="${4:-full}"

    echo "Verifying mTLS 1.3 handshake with HKDF-derived SNI on $host:$node_port..."
    local verifier_py="$SCRIPT_DIR/modules/verify_node_mtls.py"
    if [[ ! -f "$verifier_py" ]]; then
        verifier_py="$(dirname "${BASH_SOURCE[0]}")/verify_node_mtls.py"
    fi

    # Pass secret key strictly over standard input (zero-leak argv compliance)
    printf '%s' "$secret_b64" | python3 "$verifier_py" \
        --host "$host" \
        --port "$node_port" \
        --mode "$mode"
}
