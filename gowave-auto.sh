#!/usr/bin/env bash
# gowave-auto.sh - Main GoWave Auto NGINX Lifecycle Manager and CLI Entrypoint
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCK_FILE="/run/lock/gowave-auto.lock"
STATE_FILE="/var/lib/gowave-auto-nginx/state.json"
JOURNAL_FILE="/var/lib/gowave-auto-nginx/recovery/journal.json"
CREDENTIALS_FILE="/root/gowave-credentials.txt"

# Source submodules
source "$SCRIPT_DIR/modules/os.sh"
source "$SCRIPT_DIR/modules/preflight.sh"
source "$SCRIPT_DIR/modules/security.sh"
source "$SCRIPT_DIR/modules/panel.sh"
source "$SCRIPT_DIR/modules/node.sh"
source "$SCRIPT_DIR/modules/nginx.sh"
source "$SCRIPT_DIR/modules/recovery.sh"

acquire_lock() {
    mkdir -p "$(dirname "$LOCK_FILE")"
    exec 9>>"$LOCK_FILE"
    if ! flock -n 9; then
        echo "Error: Another instance of GoWave Auto NGINX is currently executing." >&2
        echo "Lock held on $LOCK_FILE. Please wait for it to finish." >&2
        exit 1
    fi
}

cmd_status() {
    echo "================================================================================"
    echo "                      GoWave Auto NGINX Service Status                          "
    echo "================================================================================"

    echo "--- Systemd Services ---"
    for svc in gowave.service gowave-node.service nginx.service fail2ban.service; do
        if command -v systemctl >/dev/null 2>&1; then
            local state
            state=$(systemctl is-active "$svc" 2>/dev/null || echo "not-found")
            printf "%-25s : %s\n" "$svc" "$state"
        fi
    done

    echo ""
    echo "--- Port Listeners ---"
    for port in 80 443 3000 3001 3002 7443 8443 9443; do
        local line
        line=$(ss -Hltnp "sport = :$port" 2>/dev/null || true)
        if [[ -n "$line" ]]; then
            printf "Port %-5s : %s\n" "$port" "LISTEN ($line)"
        else
            printf "Port %-5s : %s\n" "$port" "FREE"
        fi
    done

    echo ""
    echo "--- Certificate Lineages ---"
    if [[ -d /etc/letsencrypt/live ]]; then
        for cert in /etc/letsencrypt/live/*; do
            if [[ -d "$cert" && -f "$cert/cert.pem" ]]; then
                local domain expiry
                domain=$(basename "$cert")
                expiry=$(openssl x509 -enddate -noout -in "$cert/cert.pem" 2>/dev/null | cut -d= -f2 || echo "unknown")
                printf "%-30s : Expiry %s\n" "$domain" "$expiry"
            fi
        done
    else
        echo "No Let's Encrypt certificates found."
    fi
    echo "================================================================================"
}

cmd_health() {
    echo "Checking GoWave system health..."
    local ok=true

    if ! curl -fsSL -o /dev/null "http://127.0.0.1:3000/api/system/health" 2>/dev/null && \
       ! curl -fsSL -o /dev/null "http://127.0.0.1:3000" 2>/dev/null; then
        echo "[FAIL] GoWave Panel listener (127.0.0.1:3000) is unresponsive." >&2
        ok=false
    else
        echo "[PASS] GoWave Panel listener (127.0.0.1:3000) is healthy."
    fi

    if ! ss -Hltn "sport = :3002" 2>/dev/null | grep -q "3002" && \
       ! (: < /dev/tcp/127.0.0.1/3002) 2>/dev/null; then
        echo "[WARN] GoWave Node listener (127.0.0.1:3002) is not listening." >&2
    else
        echo "[PASS] GoWave Node listener (127.0.0.1:3002) is active."
    fi

    if [[ "$ok" == "true" ]]; then
        echo "Overall health status: HEALTHY"
        return 0
    else
        echo "Overall health status: UNHEALTHY" >&2
        return 1
    fi
}

cmd_install() {
    acquire_lock
    local panel_domain="${1:-}"
    local reality_domain="${2:-}"
    local admin_email="${3:-}"

    if [[ -z "$panel_domain" || -z "$reality_domain" ]]; then
        read -r -p "Enter GoWave Panel domain (e.g. vpn.example.com): " panel_domain
        read -r -p "Enter REALITY camouflage domain (e.g. cdn.example.com): " reality_domain
        read -r -p "Enter Let's Encrypt admin email: " admin_email
    fi

    echo "==> Starting GoWave Auto NGINX All-in-One Deployment..."
    echo "Panel Domain:   $panel_domain"
    echo "Reality Domain: $reality_domain"

    # Step 1: Preflight Environment Inspection
    check_os
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop nginx 2>/dev/null || true
    fi
    run_preflight_panel

    # Step 2: System Prerequisites
    install_prerequisites

    # Step 3: Host Security Hardening
    configure_ssh_and_fail2ban
    configure_swap
    configure_bbr_and_mtu "$STATE_FILE"
    configure_log_rotation

    # Step 4: Webroot ACME TLS Acquisition
    generate_bootstrap_acme_vhost "$panel_domain" "$reality_domain"
    if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        systemctl reload nginx 2>/dev/null || systemctl restart nginx 2>/dev/null || true
    fi

    if command -v certbot >/dev/null 2>&1; then
        certbot certonly --webroot -w "$ACME_WEBROOT" \
            -d "$panel_domain" --cert-name "$panel_domain" \
            --non-interactive --agree-tos -m "$admin_email" --keep-until-expiring || true

        certbot certonly --webroot -w "$ACME_WEBROOT" \
            -d "$reality_domain" --cert-name "$reality_domain" \
            --non-interactive --agree-tos -m "$admin_email" --keep-until-expiring || true
    fi
    rm -f /etc/nginx/conf.d/00-bootstrap-acme.conf
    ensure_tls_cert "$panel_domain"
    ensure_tls_cert "$reality_domain"

    # Step 5: NGINX Configuration
    ensure_nginx_stream_block
    generate_stream_config "$panel_domain" "$reality_domain"
    generate_production_http_vhost "$panel_domain" "$reality_domain"
    generate_panel_https_vhost "$panel_domain"
    generate_decoy_vhost "$reality_domain"
    configure_certbot_deploy_hook

    if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        systemctl reload --no-ask-password nginx || systemctl restart --no-ask-password nginx || true
    fi

    # Step 6: GoWave Panel Native Installation
    download_panel_release "$GOWAVE_DIR"
    generate_panel_env "$GOWAVE_DIR" "$panel_domain" "$panel_domain/api/sub"
    configure_panel_systemd "$GOWAVE_DIR"
    if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        systemctl restart --no-ask-password gowave.service || true
    fi
    verify_panel_startup 127.0.0.1 3000 30

    # Step 7: Local Node Installation
    local secret_key
    secret_key=$(extract_secret_key "$GOWAVE_DIR")
    install_local_node "$secret_key" 3002
    verify_node_mtls_health "$secret_key" 3002

    # Step 8: Safe UFW Activation
    configure_ufw false "" 3002

    # Step 9: REST API Provisioning
    echo "Executing REST API bootstrapping and MVP profile provisioning..."
    local admin_user="admin"
    local admin_pass
    admin_pass=$(openssl rand -hex 16)
    save_credentials "$admin_user" "$admin_pass" "https://$panel_domain" "" "$CREDENTIALS_FILE"

    python3 -c "
import sys, os, json, time
for p in ['$SCRIPT_DIR', '/opt/gowave-auto-nginx']:
    if p not in sys.path:
        sys.path.insert(0, p)
from modules.api_client import GoWaveClient, atomic_write_state, save_credentials
from modules.recovery import write_journal_atomically

# 1. Initialize provisioning in journal
jdata = {
    'transaction_id': f'provision_{int(time.time())}',
    'op': 'provision',
    'state': 'PROVISION_PREPARED',
    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'entities': {}
}
write_journal_atomically('$JOURNAL_FILE', jdata)

client = GoWaveClient('http://127.0.0.1:3000')
client.register_initial_admin('$admin_user', '$admin_pass')
client.login('$admin_user', '$admin_pass')

jdata['state'] = 'PROVISION_APPLYING'
write_journal_atomically('$JOURNAL_FILE', jdata)

x25519 = client.generate_x25519()
raw_cfg = client.compile_config_profile('local-node', '$reality_domain', x25519['privateKey'])
prof_info = client.provision_config_profile('GoWave MVP Unified Profile - local-node', raw_cfg)
prof_uuid = prof_info['profile_uuid']
inbounds = prof_info['inbounds']
inb_uuids = [inb['uuid'] for inb in inbounds]
jdata['entities']['profile_uuid'] = prof_uuid
write_journal_atomically('$JOURNAL_FILE', jdata)

node_uuid = client.associate_node('local-node', '127.0.0.1', 3002, prof_uuid, inb_uuids)
jdata['entities']['node_uuid'] = node_uuid
write_journal_atomically('$JOURNAL_FILE', jdata)

squad_uuid = client.provision_internal_squad('Default MVP Squad', inb_uuids)
jdata['entities']['squad_uuid'] = squad_uuid
write_journal_atomically('$JOURNAL_FILE', jdata)

hosts = client.provision_hosts(prof_uuid, inbounds, node_uuid, squad_uuid, '$panel_domain', '$reality_domain')
jdata['entities']['host_uuids'] = hosts
write_journal_atomically('$JOURNAL_FILE', jdata)

short_uuid = client.provision_user('default-user', squad_uuid)

token_info = client.issue_api_token()
jdata['entities']['token_id'] = token_info.get('id')
write_journal_atomically('$JOURNAL_FILE', jdata)

save_credentials('$admin_user', '$admin_pass', 'https://$panel_domain', token_info['token'], '$CREDENTIALS_FILE')

existing_cc = 'bbr'
if os.path.exists('$STATE_FILE'):
    try:
        existing_cc = json.load(open('$STATE_FILE')).get('congestionControl', 'bbr')
    except Exception:
        pass

state = {
    'schemaVersion': 2,
    'installationMode': 'all-in-one',
    'panelDomain': '$panel_domain',
    'realityDomain': '$reality_domain',
    'congestionControl': existing_cc,
    'nodePort': 3002,
    'localNodeUuid': node_uuid,
    'profileUuid': prof_uuid,
    'squadUuid': squad_uuid,
    'defaultUserShortUuid': short_uuid,
    'nodes': [{
        'name': 'local-node',
        'address': '127.0.0.1',
        'port': 3002,
        'uuid': node_uuid
    }]
}
atomic_write_state(state, '$STATE_FILE')

# Commit provisioning transaction
jdata['state'] = 'PROVISION_COMMITTED'
jdata['timestamp'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
write_journal_atomically('$JOURNAL_FILE', jdata)
"
    # Read shortUuid
    local user_short_uuid
    user_short_uuid=$(python3 -c "import json; print(json.load(open('$STATE_FILE')).get('defaultUserShortUuid', ''))" 2>/dev/null || echo "default-user")

    echo "================================================================================"
    echo "                   GoWave Auto NGINX Installation Complete                      "
    echo "================================================================================"
    echo "Panel Web UI:        https://$panel_domain"
    echo "Admin Username:      $admin_user"
    echo "Saved Credentials:   $CREDENTIALS_FILE (mode 0600)"
    echo ""
    echo "--- Client Subscription Links for 'default-user' ---"
    echo "Xray JSON:           https://$panel_domain/api/sub/$user_short_uuid/v2ray-json"
    echo "Mihomo YAML:         https://$panel_domain/api/sub/$user_short_uuid/mihomo"
    echo ""
    echo "MANDATORY REQUIREMENT: Clients MUST send a non-empty User-Agent header!"
    echo "Example verification commands:"
    echo "  curl -fsSL -H 'User-Agent: v2rayN/6.0' 'https://$panel_domain/api/sub/$user_short_uuid/v2ray-json'"
    echo "  curl -fsSL -H 'User-Agent: ClashMeta/1.19' 'https://$panel_domain/api/sub/$user_short_uuid/mihomo'"
    echo "================================================================================"
}

cmd_node() {
    local subcmd="${1:-}"
    shift || true

    case "$subcmd" in
        add)
            acquire_lock
            local name="${1:-}"
            local ip="${2:-}"
            local worker_domain="${3:-}"
            local reality_domain="${4:-}"
            local ssh_user="${5:-root}"
            local ssh_port="${6:-22}"

            if [[ -z "$name" || -z "$ip" || -z "$worker_domain" || -z "$reality_domain" ]]; then
                echo "Usage: gowave-auto.sh node add <worker-name> <worker-ip> <worker-domain> <reality-domain> [ssh-user] [ssh-port]" >&2
                return 1
            fi

            local panel_ip
            panel_ip=$(curl -s4 --connect-timeout 5 --max-time 10 https://ifconfig.me || curl -s4 --connect-timeout 5 --max-time 10 https://api.ipify.org || echo "127.0.0.1")
            local node_port=3002

            if [[ "$ip" == "$panel_ip" || "$ip" == "127.0.0.1" ]]; then
                log_warn "Worker IP matches PANEL_IP or 127.0.0.1; enforcing NODE_PORT=3002 to avoid collision with Panel on 3000."
                node_port=3002
            fi

            echo "Provisioning Distributed Worker '$name' ($ip)..."

            # 1. Read admin credentials
            local admin_user="admin" admin_pass=""
            if [[ -f "$CREDENTIALS_FILE" ]]; then
                admin_pass=$(grep '^ADMIN_PASSWORD=' "$CREDENTIALS_FILE" | cut -d= -f2- || true)
            fi

            # 2. Authenticate and register node via API
            python3 -c "
import sys, json, time
for p in ['$SCRIPT_DIR', '/opt/gowave-auto-nginx']:
    if p not in sys.path:
        sys.path.insert(0, p)
from modules.api_client import GoWaveClient, atomic_write_state
from modules.recovery import write_journal_atomically

client = GoWaveClient('http://127.0.0.1:3000')
client.login('$admin_user', '$admin_pass')

# Track in journal
jdata = {
    'transaction_id': 'node_add_$name',
    'op': 'node_add',
    'state': 'NODE_ADD_PREPARED',
    'node_name': '$name',
    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'entities': {}
}
write_journal_atomically('$JOURNAL_FILE', jdata)

x25519 = client.generate_x25519()
raw_cfg = client.compile_config_profile('$name', '$reality_domain', x25519['privateKey'])
prof_info = client.provision_config_profile('GoWave Worker $name Profile', raw_cfg)
prof_uuid = prof_info['profile_uuid']
inbounds = prof_info['inbounds']
inb_uuids = [inb['uuid'] for inb in inbounds]
jdata['state'] = 'NODE_ADD_APPLYING'
jdata['entities']['profile_uuid'] = prof_uuid
jdata['entities']['inbound_uuids'] = inb_uuids
write_journal_atomically('$JOURNAL_FILE', jdata)

node_uuid = client.associate_node('$name', '$ip', $node_port, prof_uuid, inb_uuids)
jdata['entities']['node_uuid'] = node_uuid
write_journal_atomically('$JOURNAL_FILE', jdata)

state_data = json.load(open('$STATE_FILE'))
squad_uuid = state_data.get('squadUuid')
client.provision_internal_squad('Default MVP Squad', inb_uuids)
hosts = client.provision_hosts(prof_uuid, inbounds, node_uuid, squad_uuid, '$worker_domain', '$reality_domain', '$name')
jdata['entities']['host_uuids'] = hosts
write_journal_atomically('$JOURNAL_FILE', jdata)

state_data.setdefault('nodes', []).append({
    'name': '$name',
    'address': '$ip',
    'port': $node_port,
    'workerDomain': '$worker_domain',
    'realityDomain': '$reality_domain',
    'uuid': node_uuid
})
atomic_write_state(state_data, '$STATE_FILE')
"

            # 3. Dispatch remote deployment strictly via SSH stdin
            local secret_key
            secret_key=$(extract_secret_key "$GOWAVE_DIR")
            PANEL_IP="$panel_ip" NODE_PORT="$node_port" SECRET_KEY="$secret_key" GOWAVE_NODE_VERSION="${GOWAVE_NODE_VERSION:-latest}" \
                "$SCRIPT_DIR/gowave-node-auto.sh" remote_payload "$ip" "$ssh_port" "$worker_domain" "$reality_domain" "$ssh_user"

            # 4. Commit transaction
            python3 -c "
import sys, json, time
for p in ['$SCRIPT_DIR', '/opt/gowave-auto-nginx']:
    if p not in sys.path:
        sys.path.insert(0, p)
from modules.recovery import write_journal_atomically
jdata = json.load(open('$JOURNAL_FILE'))
jdata['state'] = 'NODE_ADD_COMMITTED'
jdata['timestamp'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
write_journal_atomically('$JOURNAL_FILE', jdata)
"
            echo "Worker '$name' successfully added and deployed."
            ;;
        list)
            if [[ -f "$STATE_FILE" ]]; then
                python3 -c "
import json
data = json.load(open('$STATE_FILE'))
print(f'Total configured nodes: {len(data.get(\"nodes\", []))}')
for n in data.get('nodes', []):
    print(f'  - {n.get(\"name\")}: {n.get(\"address\")}:{n.get(\"port\")} (UUID: {n.get(\"uuid\")})')
"
            else
                echo "No state file found."
            fi
            ;;
        *)
            echo "Usage: gowave-auto.sh node {add|list}"
            ;;
    esac
}

cmd_domain_change() {
    acquire_lock
    local new_panel_domain="$1"
    local new_reality_domain="$2"

    echo "Changing domains to: $new_panel_domain / $new_reality_domain..."

    # Preflight DNS validation
    local srv_ip
    srv_ip=$(curl -s4 --connect-timeout 5 --max-time 10 https://ifconfig.me || curl -s4 --connect-timeout 5 --max-time 10 https://api.ipify.org || echo "")
    if [[ -n "$srv_ip" ]] && command -v getent >/dev/null 2>&1; then
        local resolved_ip
        resolved_ip=$(getent ahosts "$new_panel_domain" 2>/dev/null | awk '{print $1}' | head -n1 || true)
        if [[ -n "$resolved_ip" && "$resolved_ip" != "$srv_ip" ]]; then
            echo "Error: DNS resolution for $new_panel_domain ($resolved_ip) does not match server IP ($srv_ip)." >&2
            echo "Please update your DNS records before changing domains." >&2
            return 1
        fi
    fi

    # Snapshot current NGINX and .env
    local snap_dir
    snap_dir=$(prepare_update_snapshot "domain-change")

    # Generate bootstrap ACME config and request certificates
    generate_bootstrap_acme_vhost "$new_panel_domain" "$new_reality_domain"
    if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        systemctl reload nginx 2>/dev/null || true
    fi

    local acme_ok=false
    if certbot certonly --webroot -w "$ACME_WEBROOT" -d "$new_panel_domain" --non-interactive --agree-tos --register-unsafely-without-email --keep-until-expiring && \
       certbot certonly --webroot -w "$ACME_WEBROOT" -d "$new_reality_domain" --non-interactive --agree-tos --register-unsafely-without-email --keep-until-expiring; then
        acme_ok=true
    fi
    rm -f /etc/nginx/conf.d/00-bootstrap-acme.conf
    ensure_tls_cert "$panel_domain"
    ensure_tls_cert "$reality_domain"

    if [[ "$acme_ok" != "true" ]]; then
        echo "ACME certificate acquisition failed! Rolling back to previous domain configuration..." >&2
        execute_file_rollback "$snap_dir"
        return 1
    fi

    # Deploy new NGINX vhosts
    generate_stream_config "$new_panel_domain" "$new_reality_domain"
    generate_production_http_vhost "$new_panel_domain" "$new_reality_domain"
    generate_panel_https_vhost "$new_panel_domain"
    generate_decoy_vhost "$new_reality_domain"

    # Update .env
    sed -i "s/^PANEL_DOMAIN=.*/PANEL_DOMAIN=$new_panel_domain/" "$GOWAVE_DIR/.env"
    sed -i "s|^SUB_PUBLIC_DOMAIN=.*|SUB_PUBLIC_DOMAIN=$new_panel_domain/api/sub|" "$GOWAVE_DIR/.env"

    if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        systemctl restart --no-ask-password gowave.service nginx.service || true
    fi

    echo "Domain change completed successfully."
}

cmd_uninstall() {
    acquire_lock
    local confirm="${1:-}"

    if [[ "$confirm" != "--yes" && "$confirm" != "-y" ]]; then
        echo "WARNING: This will remove GoWave Auto NGINX managed components." >&2
        read -r -p "Type YES to confirm uninstallation: " reply
        if [[ "$reply" != "YES" ]]; then
            echo "Uninstallation aborted."
            return 0
        fi
    fi

    echo "==> Uninstalling GoWave Auto NGINX managed components..."

    # 1. Stop and disable systemd services
    if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        systemctl stop --no-ask-password gowave.service gowave-node.service 2>/dev/null || true
        systemctl disable --no-ask-password gowave.service gowave-node.service gowave-recover.service gowave-recover-provision.service 2>/dev/null || true
        rm -f /etc/systemd/system/gowave.service \
              /etc/systemd/system/gowave-node.service \
              /etc/systemd/system/gowave-recover.service \
              /etc/systemd/system/gowave-recover-provision.service \
              /etc/systemd/system/bbr-load.service
        systemctl daemon-reload --no-ask-password 2>/dev/null || true
    fi

    # 2. Remove managed NGINX configurations
    rm -f /etc/nginx/conf.d/gowave-*.conf /etc/nginx/stream-enabled/gowave-*.conf

    # 3. Clean stream block in nginx.conf
    if [[ -f /etc/nginx/nginx.conf ]]; then
        python3 -c "
with open('/etc/nginx/nginx.conf') as f:
    lines = f.readlines()
new_lines = []
skip = False
for line in lines:
    if '# Managed by GoWave Auto NGINX: Stream SNI Multiplexer' in line:
        skip = True
    if not skip:
        new_lines.append(line)
    if skip and '}' in line:
        skip = False
with open('/etc/nginx/nginx.conf', 'w') as f:
    f.writelines(new_lines)
" 2>/dev/null || true
        if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
            systemctl reload --no-ask-password nginx 2>/dev/null || true
        fi
    fi

    # 4. Remove directories
    rm -rf /opt/gowave /opt/gowave-node /var/lib/gowave-auto-nginx /var/www/gowave-auto-nginx /var/www/gowave-acme
    echo "Uninstallation complete. System packages (nginx, certbot, etc.) were preserved."
}

cmd_user_links() {
    local identifier="${1:-default-user}"
    local short_uuid=""

    if [[ -f "$STATE_FILE" ]]; then
        short_uuid=$(python3 -c "import json; print(json.load(open('$STATE_FILE')).get('defaultUserShortUuid', ''))" 2>/dev/null || true)
        panel_domain=$(python3 -c "import json; print(json.load(open('$STATE_FILE')).get('panelDomain', 'localhost'))" 2>/dev/null || true)
    fi
    if [[ -z "$short_uuid" ]]; then
        short_uuid="$identifier"
    fi
    panel_domain="${panel_domain:-localhost}"

    echo "================================================================================"
    echo "GoWave Subscription Links for user: $identifier"
    echo "================================================================================"
    echo "Xray Subscription URL (JSON):"
    echo "  https://$panel_domain/api/sub/$short_uuid/v2ray-json"
    echo ""
    echo "Mihomo Subscription URL (YAML):"
    echo "  https://$panel_domain/api/sub/$short_uuid/mihomo"
    echo ""
    echo "NOTE: Upstream GoWave strictly enforces a non-empty User-Agent header!"
    echo "Verification curl examples:"
    echo "  curl -fsSL -H 'User-Agent: v2rayN/6.0' 'https://$panel_domain/api/sub/$short_uuid/v2ray-json'"
    echo "  curl -fsSL -H 'User-Agent: ClashMeta/1.19' 'https://$panel_domain/api/sub/$short_uuid/mihomo'"
    echo "================================================================================"
}

main_menu() {
    clear
    echo "================================================================================"
    echo "                      GoWave Auto NGINX Manager                                 "
    echo "================================================================================"
    echo " 1) Show status & health"
    echo " 2) Install All-in-One GoWave stack"
    echo " 3) Add Distributed Edge Worker Node"
    echo " 4) Change domains"
    echo " 5) Switch channel (stable <-> dev)"
    echo " 6) Create Backup"
    echo " 7) Restore Backup"
    echo " 8) Show User Subscription Links"
    echo " 9) Uninstall"
    echo " 0) Exit"
    echo "================================================================================"
    read -r -p "Select option [0-9]: " choice
    case "$choice" in
        1) cmd_status ;;
        2) cmd_install ;;
        3)
            read -r -p "Worker Name: " wname
            read -r -p "Worker IP: " wip
            read -r -p "Worker Domain: " wdom
            read -r -p "Camouflage Domain: " rdom
            cmd_node add "$wname" "$wip" "$wdom" "$rdom"
            ;;
        4)
            read -r -p "New Panel Domain: " np
            read -r -p "New Camouflage Domain: " nr
            cmd_domain_change "$np" "$nr"
            ;;
        5)
            read -r -p "Target Channel (stable|dev): " tch
            switch_channel "$tch"
            ;;
        6) "$SCRIPT_DIR/assets/backup/gowave-backup.sh" backup ;;
        7)
            read -r -p "Path to archive.tar.gz: " arch_path
            "$SCRIPT_DIR/assets/backup/gowave-backup.sh" restore "$arch_path"
            ;;
        8)
            read -r -p "Username or ShortUUID [default-user]: " uid
            cmd_user_links "${uid:-default-user}"
            ;;
        9) cmd_uninstall ;;
        0) exit 0 ;;
        *) echo "Invalid option." ;;
    esac
}

# CLI Entrypoint Router
if [[ $# -eq 0 ]]; then
    main_menu
else
    case "${1:-}" in
        status) cmd_status ;;
        health) cmd_health ;;
        install) shift; cmd_install "$@" ;;
        node) shift; cmd_node "$@" ;;
        channel) shift; switch_channel "$@" ;;
        domain-change) shift; cmd_domain_change "$@" ;;
        backup) shift; "$SCRIPT_DIR/assets/backup/gowave-backup.sh" backup "$@" ;;
        restore) shift; "$SCRIPT_DIR/assets/backup/gowave-backup.sh" restore "$@" ;;
        uninstall) shift; cmd_uninstall "$@" ;;
        user)
            if [[ "${2:-}" == "links" ]]; then
                cmd_user_links "${3:-default-user}"
            fi
            ;;
        recover)
            if [[ "${2:-}" == "--boot-files" ]]; then
                recover_boot_files
            elif [[ "${2:-}" == "--boot-provision" ]]; then
                recover_boot_provision
            fi
            ;;
        *)
            echo "Usage: gowave-auto.sh {status|health|install|node|channel|domain-change|backup|restore|uninstall|user links <id>|recover}"
            exit 1
            ;;
    esac
fi
