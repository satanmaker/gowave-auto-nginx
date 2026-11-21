#!/usr/bin/env bash
# gowave-cleanup.sh — Aggressive full cleanup of GoWave Auto NGINX installation
# Run as root on Master and each Worker node.
# WARNING: This DELETES all data, configs, certs, backups, and state irreversibly.

set -Eeuo pipefail

# ===================== CONFIG =====================
GOWAVE_DIR="${GOWAVE_DIR:-/opt/gowave}"
NODE_DIR="${NODE_DIR:-/opt/gowave-node}"
STATE_DIR="${STATE_DIR:-/var/lib/gowave-auto-nginx}"
WWW_GOWAVE="${WWW_GOWAVE:-/var/www/gowave-auto-nginx}"
WWW_ACME="${WWW_ACME:-/var/www/gowave-acme}"
CREDENTIALS_FILE="${CREDENTIALS_FILE:-/root/gowave-credentials.txt}"
# ==================================================

msg() { echo -e "\033[1;32m[CLEANUP]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*" >&2; }
die() { echo -e "\033[1;31m[FATAL]\033[0m $*" >&2; exit 1; }

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        die "Must run as root. Use: sudo $0"
    fi
}

stop_and_disable_services() {
    msg "Stopping and disabling systemd services..."
    local services=(
        gowave-update.path
        gowave-update.service
        gowave.service
        gowave-node.service
        gowave-recover.service
        gowave-recover-provision.service
        bbr-load.service
    )
    for svc in "${services[@]}"; do
        systemctl stop --no-ask-password "$svc" 2>/dev/null || true
        systemctl disable --no-ask-password "$svc" 2>/dev/null || true
    done

    # Remove unit files
    local unit_dirs=(
        /etc/systemd/system
        /etc/systemd/system/multi-user.target.wants
        /etc/systemd/system/sockets.target.wants
        /etc/systemd/system/paths.target.wants
        /usr/lib/systemd/system
        /lib/systemd/system
    )
    for dir in "${unit_dirs[@]}"; do
        [[ -d "$dir" ]] || continue
        rm -f "$dir"/gowave*.service "$dir"/gowave*.path "$dir"/bbr-load.service 2>/dev/null || true
    done

    systemctl daemon-reload --no-ask-password 2>/dev/null || true
    msg "Systemd cleanup done."
}

cleanup_nginx() {
    msg "Cleaning NGINX configurations..."
    rm -f /etc/nginx/conf.d/gowave-*.conf /etc/nginx/stream-enabled/gowave-*.conf 2>/dev/null || true

    # Remove managed stream block from nginx.conf
    if [[ -f /etc/nginx/nginx.conf ]]; then
        python3 -c "
import sys
with open('/etc/nginx/nginx.conf') as f:
    lines = f.readlines()
new_lines = []
skip = False
for line in lines:
    if '# Managed by GoWave Auto NGINX: Stream SNI Multiplexer' in line:
        skip = True
    if not skip:
        new_lines.append(line)
    if skip and '}' in line and line.strip() == '}':
        skip = False
with open('/etc/nginx/nginx.conf', 'w') as f:
    f.writelines(new_lines)
" 2>/dev/null || true
        systemctl reload --no-ask-password nginx 2>/dev/null || true
    fi
    msg "NGINX cleanup done."
}

cleanup_directories() {
    msg "Removing application directories..."

    local dirs=(
        "$GOWAVE_DIR"
        "$NODE_DIR"
        "$STATE_DIR"
        "$WWW_GOWAVE"
        "$WWW_ACME"
    )

    for d in "${dirs[@]}"; do
        if [[ -d "$d" ]]; then
            msg "  Removing $d"
            rm -rf -- "$d"
        elif [[ -L "$d" ]]; then
            msg "  Removing symlink $d"
            rm -f -- "$d"
        fi
    done

    # Remove parent empty dirs if they exist and are empty
    rmdir /var/www/gowave-auto-nginx 2>/dev/null || true
    rmdir /var/www/gowave-acme 2>/dev/null || true
    rmdir /var/lib/gowave-auto-nginx 2>/dev/null || true
    rmdir /opt/gowave 2>/dev/null || true
    rmdir /opt/gowave-node 2>/dev/null || true

    msg "Directory cleanup done."
}

cleanup_credentials() {
    msg "Removing credentials file..."
    if [[ -f "$CREDENTIALS_FILE" ]]; then
        shred -u "$CREDENTIALS_FILE" 2>/dev/null || rm -f "$CREDENTIALS_FILE"
    fi
    msg "Credentials removed."
}

cleanup_ufw_rules() {
    msg "Cleaning UFW rules added by GoWave (best effort)..."
    # Remove rules referencing GoWave ports (443, 7443, 8443, 9443, 8080, 8317)
    # We can't safely auto-delete without knowing exact rules, so just warn.
    warn "UFW rules NOT auto-removed — review with: ufw status numbered"
    warn "Delete GoWave-related rules manually if needed: ufw delete <num>"
}

cleanup_fail2ban() {
    msg "Cleaning Fail2ban GoWave jails (best effort)..."
    if command -v fail2ban-client >/dev/null 2>&1; then
        fail2ban-client status 2>/dev/null | grep -i gowave || true
    fi
    warn "Fail2ban jails NOT auto-removed — check: fail2ban-client status"
}

cleanup_sysctl() {
    msg "Cleaning sysctl BBR config (best effort)..."
    rm -f /etc/sysctl.d/99-gowave-bbr.conf 2>/dev/null || true
    sysctl --system 2>/dev/null || true
    warn "Sysctl config removed. Verify with: sysctl net.ipv4.tcp_congestion_control"
}

cleanup_ssh_keys() {
    msg "Cleaning temporary SSH keys from authorized_keys (best effort)..."
    # The wizard uses temporary keys with expiry; they auto-expire.
    # Manual cleanup if needed:
    warn "Check ~/.ssh/authorized_keys for keys with 'gowave-node-' prefix"
}

cleanup_cron() {
    msg "Cleaning cron jobs (best effort)..."
    crontab -l 2>/dev/null | grep -i gowave || true
    warn "Cron jobs NOT auto-removed — review with: crontab -l"
}

main() {
    require_root

    echo "================================================================="
    echo "  GoWave Auto NGINX — AGGRESSIVE FULL CLEANUP"
    echo "  This will DELETE ALL DATA, CONFIGS, CERTS, STATE, BACKUPS."
    echo "  Run on MASTER and each WORKER node."
    echo "================================================================="
    echo ""
    read -r -p "Type YES to confirm TOTAL DESTRUCTION: " confirm
    if [[ "$confirm" != "YES" ]]; then
        echo "Aborted."
        exit 0
    fi

    stop_and_disable_services
    cleanup_nginx
    cleanup_directories
    cleanup_credentials
    cleanup_ufw_rules
    cleanup_fail2ban
    cleanup_sysctl
    cleanup_ssh_keys
    cleanup_cron

    echo ""
    echo "================================================================="
    echo "  CLEANUP COMPLETE"
    echo "  Remaining manual checks:"
    echo "    - ufw status numbered"
    echo "    - fail2ban-client status"
    echo "    - crontab -l"
    echo "    - ~/.ssh/authorized_keys (gowave-node-* keys)"
    echo "    - sysctl net.ipv4.tcp_congestion_control"
    echo "================================================================="
}

main "$@"