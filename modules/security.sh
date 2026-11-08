#!/usr/bin/env bash
# modules/security.sh - Host security, firewall, swap, BBR, and log rotation
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANAGED_SECURITY_PY="${SCRIPT_DIR}/assets/security/managed.py"

configure_ssh_and_fail2ban() {
    echo "Configuring non-destructive SSH inspection and Fail2ban..."
    python3 "$MANAGED_SECURITY_PY" --configure-fail2ban
}

configure_dot() {
    echo "Configuring strict DNS-over-TLS via systemd-resolved..."
    python3 "$MANAGED_SECURITY_PY" --prepare-dns
}

configure_unattended_upgrades() {
    echo "Configuring unattended-upgrades with automatic reboot disabled..."
    python3 "$MANAGED_SECURITY_PY" --configure-apt
}

configure_ufw() {
    local is_worker="${1:-false}"
    local panel_ip="${2:-}"
    local node_port="${3:-3002}"
    local if_inet6="${4:-/proc/net/if_inet6}"
    local ufw_default="${5:-/etc/default/ufw}"

    echo "Configuring UFW firewall rules..."

    # Extract detected SSH ports
    local ports_json
    ports_json=$(python3 "$MANAGED_SECURITY_PY" --ssh-ports 2>/dev/null || echo '{"ports": [22]}')
    local ports
    mapfile -t ports < <(echo "$ports_json" | python3 -c 'import sys, json; print("\n".join(str(p) for p in json.load(sys.stdin).get("ports", [22])))')

    if [[ ${#ports[@]} -eq 0 ]]; then
        ports=(22)
    fi

    # 1. Whitelist detected SSH ports
    for port in "${ports[@]}"; do
        echo "UFW: Allowing SSH port $port/tcp..."
        ufw allow "${port}/tcp" comment "SSH port" || true
    done

    # 2. Allow public web ports 80/443
    echo "UFW: Allowing public ports 80/tcp and 443/tcp..."
    ufw allow 80/tcp comment "HTTP ACME challenge" || true
    ufw allow 443/tcp comment "HTTPS and Xray Stream" || true

    # 3. Handle Node port
    if [[ "$is_worker" == "true" ]]; then
        if [[ -n "$panel_ip" ]]; then
            echo "UFW: Whitelisting Central Panel IP $panel_ip for Node port $node_port/tcp..."
            ufw allow from "$panel_ip" to any port "$node_port" proto tcp comment "GoWave Panel control plane" || true
        else
            echo "Warning: Panel IP not provided for worker UFW configuration." >&2
        fi
    else
        # All-in-One: strictly deny external access to local Node port 3002
        echo "UFW: Blocking external access to local Node port $node_port/tcp..."
        ufw deny "$node_port/tcp" comment "Isolate local GoWave Node from external access" || true
    fi

    # 4. Handle IPv6 configuration in /etc/default/ufw
    if [[ -f "$ufw_default" ]]; then
        if [[ ! -f "$if_inet6" ]] || [[ ! -s "$if_inet6" ]]; then
            echo "UFW: IPv6 disabled in kernel; setting IPV6=no in $ufw_default..."
            sed -i 's/^IPV6=.*/IPV6=no/' "$ufw_default" || true
        else
            sed -i 's/^IPV6=.*/IPV6=yes/' "$ufw_default" || true
        fi
    fi

    # 5. Enable UFW
    ufw --force enable || true
    echo "UFW configuration complete."
}

configure_swap() {
    local meminfo="${1:-/proc/meminfo}"
    local swapfile="${2:-/swapfile}"
    local fstab="${3:-/etc/fstab}"

    # Skip in containerized environments
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        if systemd-detect-virt --container >/dev/null 2>&1; then
            echo "Container environment detected; skipping swap allocation."
            return 0
        fi
    fi
    if [[ -f /.dockerenv || -f /run/.containerenv ]]; then
        echo "Container environment detected; skipping swap allocation."
        return 0
    fi

    local mem_total_kb=0
    if [[ -f "$meminfo" ]]; then
        mem_total_kb=$(awk '/MemTotal/ {print $2}' "$meminfo")
    fi

    # Check <= 1GB RAM (1048576 KiB)
    if [[ "$mem_total_kb" -le 1048576 ]] && [[ "$mem_total_kb" -gt 0 ]]; then
        if swapon --show 2>/dev/null | grep -q .; then
            echo "Swap is already active."
        else
            echo "Low memory detected (${mem_total_kb} KiB <= 1GB); allocating 1 GiB swap..."
            local fs_type="ext4"
            if command -v df >/dev/null 2>&1; then
                fs_type=$(df -T / 2>/dev/null | awk 'NR==2 {print $2}' || echo "ext4")
            fi

            if [[ "$fs_type" == "btrfs" ]] && command -v btrfs >/dev/null 2>&1; then
                btrfs filesystem mkswapfile --size 1G "$swapfile" 2>/dev/null || {
                    truncate -s 0 "$swapfile" && chattr +C "$swapfile" 2>/dev/null || true
                    dd if=/dev/zero of="$swapfile" bs=1M count=1024 status=none
                }
            else
                dd if=/dev/zero of="$swapfile" bs=1M count=1024 status=none
            fi

            chmod 0600 "$swapfile"
            mkswap "$swapfile" >/dev/null 2>&1 || true
            swapon "$swapfile" >/dev/null 2>&1 || true

            if [[ -f "$fstab" ]] && ! grep -q "$swapfile" "$fstab"; then
                echo "$swapfile none swap sw 0 0" >> "$fstab"
            fi
            echo "Swap successfully configured."
        fi
    fi

    # Configure GOMEMLIMIT=250MiB systemd drop-in
    mkdir -p /etc/systemd/system/gowave.service.d /etc/systemd/system/gowave-node.service.d
    cat > /etc/systemd/system/gowave.service.d/20-gomemlimit.conf <<'EOF'
[Service]
Environment="GOMEMLIMIT=250MiB"
EOF
    cat > /etc/systemd/system/gowave-node.service.d/20-gomemlimit.conf <<'EOF'
[Service]
Environment="GOMEMLIMIT=250MiB"
EOF
    if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload --no-ask-password 2>/dev/null || true
    fi
}

configure_bbr_and_mtu() {
    local state_file="${1:-/var/lib/gowave-auto-nginx/state.json}"
    local sysctl_conf="${2:-/etc/sysctl.d/99-gowave.conf}"
    local bbr_unit="${3:-/etc/systemd/system/bbr-load.service}"

    echo "Configuring MTU probing and BBR congestion control..."
    mkdir -p "$(dirname "$sysctl_conf")" "$(dirname "$bbr_unit")"

    # 1. Configure MTU probing
    cat > "$sysctl_conf" <<'EOF'
# Managed by GoWave Auto NGINX
net.ipv4.tcp_mtu_probing = 1
EOF

    # 2. Deploy bbr-load.service
    cat > "$bbr_unit" <<'EOF'
[Unit]
Description=Load tcp_bbr and set congestion control
Before=systemd-sysctl.service
DefaultDependencies=no
ConditionVirtualization=!container

[Service]
Type=oneshot
ExecStart=-/sbin/modprobe tcp_bbr
ExecStart=-/sbin/sysctl -w net.ipv4.tcp_congestion_control=bbr
RemainAfterExit=yes

[Install]
WantedBy=sysinit.target
EOF

    local selected_cc="cubic"
    # Test BBR availability
    if modprobe tcp_bbr 2>/dev/null; then
        local avail
        avail=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "")
        if [[ "$avail" =~ bbr ]]; then
            sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null || true
            echo "net.ipv4.tcp_congestion_control = bbr" >> "$sysctl_conf"
            selected_cc="bbr"
            echo "BBR congestion control enabled."
        else
            echo "Warning: BBR unavailable, falling back to CUBIC" >&2
        fi
    else
        echo "Warning: BBR unavailable, falling back to CUBIC" >&2
    fi

    if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload --no-ask-password 2>/dev/null || true
        systemctl enable --no-ask-password bbr-load.service 2>/dev/null || true
    fi

    # Record congestionControl in state_file if directory exists
    if [[ -d "$(dirname "$state_file")" ]]; then
        python3 -c "
import json, os
path = '$state_file'
data = {'schemaVersion': 2}
if os.path.exists(path):
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception:
        pass
data['schemaVersion'] = 2
data['congestionControl'] = '$selected_cc'
tmp_path = path + '.tmp'
with open(tmp_path, 'w') as f:
    json.dump(data, f, indent=2)
    f.flush()
    os.fsync(f.fileno())
os.chmod(tmp_path, 0o600)
os.replace(tmp_path, path)
dir_fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_DIRECTORY)
try:
    os.fsync(dir_fd)
finally:
    os.close(dir_fd)
" 2>/dev/null || true
    fi
}

configure_log_rotation() {
    local logrotate_file="${1:-/etc/logrotate.d/gowave-nginx}"
    local journal_conf="${2:-/etc/systemd/journald.conf.d/99-gowave.conf}"

    echo "Configuring log rotation and journal caps..."
    mkdir -p "$(dirname "$logrotate_file")" "$(dirname "$journal_conf")"

    # Daily rotation, 7 days retention, gzip
    cat > "$logrotate_file" <<'EOF'
# Managed by GoWave Auto NGINX
/var/log/nginx/gowave-*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        if [ -f /var/run/nginx.pid ]; then
            kill -USR1 $(cat /var/run/nginx.pid)
        fi
    endscript
}
EOF

    # Cap journal to 100M
    cat > "$journal_conf" <<'EOF'
# Managed by GoWave Auto NGINX
[Journal]
SystemMaxUse=100M
EOF

    if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        systemctl restart --no-ask-password systemd-journald 2>/dev/null || true
    fi
}
