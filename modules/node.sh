#!/usr/bin/env bash
# modules/node.sh - GoWave Node installation, configuration, and mTLS verification
set -Eeuo pipefail

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

core_version_matches() {
    local reported="${1:-}"
    local expected="${2:-}"
    [[ -n "$expected" ]] || return 1
    local token
    for token in $reported; do
        if [[ "$token" == "$expected" ]]; then
            return 0
        fi
    done
    return 1
}

ensure_pinned_xray_core() {
    local node_bin="${1:-$GOWAVE_NODE_INSTALL_DIR/gowave-node}"
    local core_bin="${2:-$GOWAVE_NODE_INSTALL_DIR/rw-core}"

    # "latest" is the shipped default: it means the core the node installation
    # already brought is the one to keep, not a version to reinstall.
    local requested="${XRAY_SERVER_VERSION:-}"
    if [[ -z "$requested" || "${requested,,}" == "latest" || "${requested,,}" == "vlatest" || ! -x "$node_bin" ]]; then
        return 0
    fi

    local expected_core cur_core
    expected_core="${requested#v}"
    cur_core=$("$core_bin" version 2>/dev/null || true)
    if core_version_matches "$cur_core" "$expected_core"; then
        return 0
    fi

    echo "Installing explicit Xray server version $XRAY_SERVER_VERSION..."
    if ! "$node_bin" core install --version "v$expected_core" -y 2>/dev/null && \
       ! "$node_bin" core install --version "$expected_core" -y 2>/dev/null; then
        echo "Error: Failed to install requested Xray server version $XRAY_SERVER_VERSION." >&2
        return 1
    fi
    cur_core=$("$core_bin" version 2>/dev/null || true)
    if core_version_matches "$cur_core" "$expected_core"; then
        return 0
    fi
    echo "Error: Xray server version mismatch after installation: expected $expected_core, got ${cur_core:-unknown}." >&2
    return 1
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

node_binary_version() {
    local node_bin="${1:-$GOWAVE_NODE_INSTALL_DIR/gowave-node}"
    "$node_bin" version 2>/dev/null | awk 'NR == 1 {print $2}'
}

local_node_is_serving() {
    local node_port="${1:-$DEFAULT_NODE_PORT}"
    local expected="${2:-latest}"
    local node_bin="$GOWAVE_NODE_INSTALL_DIR/gowave-node"

    [[ "$(id -u)" -eq 0 ]] || return 1
    command -v systemctl >/dev/null 2>&1 || return 1
    command -v timeout >/dev/null 2>&1 || return 1
    [[ -x "$node_bin" ]] || return 1
    systemctl is-active --quiet gowave-node.service || return 1
    # A different port means the running service is not the one this install
    # would configure, so it has to go through the installer.
    grep -qx "NODE_PORT=$node_port" "$GOWAVE_NODE_INSTALL_DIR/.env" 2>/dev/null || return 1
    if [[ "$expected" != "latest" ]]; then
        local installed
        installed=$(node_binary_version "$node_bin")
        [[ "v${installed#v}" == "v${expected#v}" ]] || return 1
    fi
    # Only a node whose Xray core is serving counts as already installed: a
    # restarted node has to wait for the Panel to push a configuration again.
    timeout 20 "$node_bin" status --wait-ready >/dev/null 2>&1
}

pinned_node_installer_url() {
    printf '%s\n' "https://raw.githubusercontent.com/aaaSaZaN/gowave-node/${GOWAVE_NODE_INSTALLER_COMMIT}/install.sh"
}

validate_node_installer_pin() {
    if [[ ! "${GOWAVE_NODE_INSTALLER_COMMIT:-}" =~ ^[0-9a-fA-F]{40}$ ]]; then
        echo "Error: GOWAVE_NODE_INSTALLER_COMMIT must be a 40-character hex commit SHA." >&2
        return 1
    fi
    if [[ ! "${GOWAVE_NODE_INSTALLER_SHA256:-}" =~ ^[0-9a-fA-F]{64}$ ]]; then
        echo "Error: GOWAVE_NODE_INSTALLER_SHA256 must be a 64-character hex SHA-256 digest." >&2
        return 1
    fi
}

verify_node_installer_digest() {
    local installer="$1"
    if [[ -z "${GOWAVE_NODE_INSTALLER_SHA256:-}" ]]; then
        return 0
    fi
    local actual_sha256
    actual_sha256=$(sha256sum "$installer" | awk '{print $1}')
    if [[ "$actual_sha256" != "$GOWAVE_NODE_INSTALLER_SHA256" ]]; then
        echo "Error: Node installer SHA256 mismatch: expected $GOWAVE_NODE_INSTALLER_SHA256, got $actual_sha256." >&2
        return 1
    fi
}

# The repository no longer vendors upstream install.sh: the pinned commit is the
# authority, and the fetched bytes must match its digest before any execution.
fetch_pinned_node_installer() {
    local dest="$1"
    validate_node_installer_pin || return 1
    if ! curl -fsSL --retry 2 --connect-timeout 15 --max-time 60 "$(pinned_node_installer_url)" -o "$dest"; then
        rm -f "$dest"
        echo "Error: failed to fetch the pinned GoWave Node installer for commit $GOWAVE_NODE_INSTALLER_COMMIT." >&2
        return 1
    fi
    if ! verify_node_installer_digest "$dest"; then
        rm -f "$dest"
        return 1
    fi
    chmod 0700 "$dest"
}

install_local_node() {
    local secret_key="$1"
    local node_port="${2:-$DEFAULT_NODE_PORT}"
    local upstream_installer="${3:-}"
    local bundled_installer="$SCRIPT_DIR/sources/gowave-node/install.sh"
    local fetched_installer=""
    # E2E runs require a pinned, digest-verified installer and never the floating
    # `main` download; GOWAVE_NODE_REQUIRE_BUNDLED_INSTALLER is its legacy name.
    local require_pinned_installer="${GOWAVE_NODE_REQUIRE_PINNED_INSTALLER:-${GOWAVE_NODE_REQUIRE_BUNDLED_INSTALLER:-0}}"

    echo "Orchestrating local GoWave Node installation (port $node_port)..."

    if [[ -n "$upstream_installer" && ! -f "$upstream_installer" ]]; then
        echo "Error: GoWave Node installer not found: $upstream_installer" >&2
        return 1
    fi

    # A developer checkout may still carry the pinned installer as a local bundle.
    if [[ -z "$upstream_installer" && -f "$bundled_installer" ]]; then
        upstream_installer="$bundled_installer"
    fi

    if [[ -n "$upstream_installer" ]]; then
        verify_node_installer_digest "$upstream_installer" || return 1
    elif [[ "$require_pinned_installer" == "1" ]]; then
        validate_node_installer_pin || return 1
    fi

    local normalized_node_ver="${GOWAVE_NODE_VERSION:-latest}"
    if [[ "$normalized_node_ver" != "latest" && "$normalized_node_ver" != v* ]]; then
        normalized_node_ver="v$normalized_node_ver"
    fi

    # A repeated install finds the node its predecessor left running. Running the
    # upstream installer again restarts that node, which drops the Xray
    # configuration the Panel pushed, and the Panel only pushes it again when the
    # node answers as offline. Keeping a serving node untouched is what makes a
    # repeated install a no-op for the traffic plane.
    local node_restart_required=1
    if local_node_is_serving "$node_port" "$normalized_node_ver"; then
        node_restart_required=0
        echo "Local GoWave Node already serves $normalized_node_ver on port $node_port; keeping the running service."
    fi

    if (( node_restart_required == 1 )); then
        # Resolve the pinned installer only when the node actually has to restart,
        # so a serving node never triggers a pointless download.
        if [[ -z "$upstream_installer" && "$require_pinned_installer" == "1" ]]; then
            if ! fetched_installer=$(mktemp "/tmp/gowave-node-install-XXXXXX.sh"); then
                echo "Error: cannot create a temporary file for the pinned installer." >&2
                return 1
            fi
            if ! fetch_pinned_node_installer "$fetched_installer"; then
                rm -f "$fetched_installer"
                return 1
            fi
            upstream_installer="$fetched_installer"
        fi

        if [[ -n "$upstream_installer" ]]; then
            # Pass SECRET_KEY and NODE_PORT strictly via environment to installer execution
            local installer_rc=0
            (
                export SECRET_KEY="$secret_key"
                export NODE_PORT="$node_port"
                export GOWAVE_NODE_VERSION="$normalized_node_ver"
                bash "$upstream_installer" </dev/null
            ) || installer_rc=$?
            if [[ -n "$fetched_installer" ]]; then
                rm -f "$fetched_installer"
            fi
            (( installer_rc == 0 )) || return "$installer_rc"
        else
            echo "Fetching upstream gowave-node installer..."
            (
                export SECRET_KEY="$secret_key"
                export NODE_PORT="$node_port"
                export GOWAVE_NODE_VERSION="$normalized_node_ver"
                local tmp_inst
                tmp_inst=$(mktemp "/tmp/gowave-node-install-XXXXXX.sh")
                curl -fsSL https://raw.githubusercontent.com/aaaSaZaN/gowave-node/main/install.sh -o "$tmp_inst"
                chmod 0700 "$tmp_inst"
                bash "$tmp_inst" </dev/null
                rm -f "$tmp_inst"
            )
        fi
    fi

    # Ensure hardening and port configuration in .env and drop-in
    configure_node_env "$GOWAVE_NODE_INSTALL_DIR" "$secret_key" "$node_port"
    deploy_node_systemd_dropins "$node_port"

    # Install pinned Xray core version if explicitly configured and mismatched
    ensure_pinned_xray_core "$GOWAVE_NODE_INSTALL_DIR/gowave-node" "$GOWAVE_NODE_INSTALL_DIR/rw-core" || return 1

    # Isolate local node from external network access
    if command -v ufw >/dev/null 2>&1; then
        echo "UFW: Enforcing external isolation on port $node_port/tcp..."
        ufw deny "${node_port}/tcp" comment "Isolate local GoWave Node from external access" || true
    fi

    if (( node_restart_required == 1 )) && [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
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
