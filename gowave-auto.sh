#!/usr/bin/env bash
# gowave-auto.sh - Main GoWave Auto NGINX Lifecycle Manager and CLI Entrypoint
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCK_FILE="/run/lock/gowave-auto.lock"
STATE_FILE="/var/lib/gowave-auto-nginx/state.json"
JOURNAL_FILE="/var/lib/gowave-auto-nginx/recovery/journal.json"
CREDENTIALS_FILE="/root/gowave-credentials.txt"

# Source submodules
source "$SCRIPT_DIR/modules/lock.sh"
source "$SCRIPT_DIR/modules/os.sh"
source "$SCRIPT_DIR/modules/preflight.sh"
source "$SCRIPT_DIR/modules/security.sh"
source "$SCRIPT_DIR/modules/panel.sh"
source "$SCRIPT_DIR/modules/node.sh"
source "$SCRIPT_DIR/modules/nginx.sh"
source "$SCRIPT_DIR/modules/recovery.sh"

reload_nginx_strict() {
    command -v nginx >/dev/null 2>&1 || { echo "Fatal: NGINX binary is unavailable." >&2; return 1; }
    nginx -t
    if command -v systemctl >/dev/null 2>&1; then
        systemctl reload nginx || systemctl restart nginx
        systemctl is-active --quiet nginx
    fi
}

verify_public_tls_sni() {
    local domain="$1"
    command -v timeout >/dev/null 2>&1 || { echo "Fatal: timeout is required for TLS verification." >&2; return 1; }
    local ca_opts=(-CApath /etc/ssl/certs)
    if [[ -n "${GOWAVE_TLS_CA_FILE:-}" ]]; then
        if [[ ! -f "$GOWAVE_TLS_CA_FILE" || -L "$GOWAVE_TLS_CA_FILE" ]]; then
            echo "Fatal: GOWAVE_TLS_CA_FILE must be a readable regular file, not a symlink." >&2
            return 1
        fi
        ca_opts=(-CAfile "$GOWAVE_TLS_CA_FILE")
    fi
    timeout 10 openssl s_client -connect 127.0.0.1:443 -servername "$domain" \
        -verify_return_error -verify_hostname "$domain" "${ca_opts[@]}" -brief </dev/null
}

acquire_lock() {
    acquire_mutation_lock "$@"
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
    local vision_domain="${4:-${VISION_DOMAIN:-}}"

    if [[ -z "$panel_domain" ]]; then
        read -r -p "Enter GoWave Panel domain (e.g. vpn.example.com): " panel_domain
    fi
    if [[ -z "$reality_domain" ]]; then
        read -r -p "Enter REALITY camouflage domain (e.g. cdn.example.com): " reality_domain
    fi
    if [[ -z "$admin_email" ]]; then
        read -r -p "Enter Let's Encrypt admin email: " admin_email
    fi
    if [[ -z "$vision_domain" ]] && [[ -t 0 ]] && [[ -z "${1:-}" ]]; then
        local enable_vision="n"
        read -r -p "Configure optional VLESS + XTLS Vision? (requires a dedicated 3rd domain/subdomain) [y/N]: " enable_vision
        if [[ "$enable_vision" =~ ^[Yy]$ ]]; then
            read -r -p "Enter Vision domain (e.g. vision.example.com): " vision_domain
        fi
    fi
    python3 - "$panel_domain" "$reality_domain" "$vision_domain" <<'PY'
import re, sys
panel, reality, *extra = sys.argv[1:]
vision = extra[0] if extra and extra[0] else None
def validate_domain(domain):
    if len(domain) > 253:
        raise SystemExit(f"Invalid DNS hostname (too long): {domain}")
    labels = domain.rstrip(".").split(".")
    if len(labels) < 2 or any(
        not label or len(label) > 63 or
        not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in labels
    ):
        raise SystemExit(f"Invalid DNS hostname: {domain}")
validate_domain(panel)
validate_domain(reality)
if panel.lower().rstrip(".") == reality.lower().rstrip("."):
    raise SystemExit("Panel and REALITY domains must be different.")
if vision:
    validate_domain(vision)
    if vision.lower().rstrip(".") in (panel.lower().rstrip("."), reality.lower().rstrip(".")):
        raise SystemExit("Vision domain must differ from Panel and REALITY domains.")
PY
    if [[ ! "$admin_email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        echo "Error: a valid Let's Encrypt email address is required." >&2
        return 2
    fi

    validate_acme_server "${GOWAVE_ACME_SERVER:-}" || return 1
    local effective_acme_server="${GOWAVE_ACME_SERVER:-https://acme-v02.api.letsencrypt.org/directory}"
    check_acme_lineage "$panel_domain" "$effective_acme_server" || return 1
    check_acme_lineage "$reality_domain" "$effective_acme_server" || return 1
    if [[ -n "$vision_domain" ]]; then
        check_acme_lineage "$vision_domain" "$effective_acme_server" || return 1
    fi

    echo "==> Starting GoWave Auto NGINX All-in-One Deployment..."
    echo "Panel Domain:   $panel_domain"
    echo "Reality Domain: $reality_domain"
    if [[ -n "$vision_domain" ]]; then
        echo "Vision Domain:  $vision_domain (Optional VLESS + XTLS Vision enabled)"
    else
        echo "Vision Domain:  Disabled (default 4-inbound configuration)"
    fi

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
    local acme_tx_id="install_$(date +%s)"
    verify_deploy_hook_preflight "/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh" "$acme_tx_id" || return 1
    snapshot_acme_lineage "$acme_tx_id" "$panel_domain"
    snapshot_acme_lineage "$acme_tx_id" "$reality_domain"
    if [[ -n "$vision_domain" ]]; then
        snapshot_acme_lineage "$acme_tx_id" "$vision_domain"
    fi

    rollback_acme_lineages() {
        echo "ACME acquisition or verification failed. Rolling back certificate lineages..." >&2
        rollback_managed_deploy_hook "$acme_tx_id" 2>/dev/null || true
        restore_acme_lineage "$acme_tx_id" "$panel_domain" 2>/dev/null || true
        restore_acme_lineage "$acme_tx_id" "$reality_domain" 2>/dev/null || true
        if [[ -n "$vision_domain" ]]; then
            restore_acme_lineage "$acme_tx_id" "$vision_domain" 2>/dev/null || true
        fi
        rm -f /etc/nginx/conf.d/00-bootstrap-acme.conf
    }

    generate_bootstrap_acme_vhost "$panel_domain" "$reality_domain" "/etc/nginx/conf.d/00-bootstrap-acme.conf" "/proc/net/if_inet6" "$vision_domain"
    reload_nginx_strict

    if ! command -v certbot >/dev/null 2>&1; then
        echo "Error: certbot is required for production TLS certificate acquisition but not installed." >&2
        rollback_acme_lineages
        return 1
    fi

    local certbot_extra_args=()
    if [[ -n "${GOWAVE_ACME_SERVER:-}" ]]; then
        certbot_extra_args+=(--server "$GOWAVE_ACME_SERVER")
    fi

    echo "Acquiring Let's Encrypt TLS certificate for Panel ($panel_domain)..."
    if ! certbot certonly --webroot -w "$ACME_WEBROOT" \
        -d "$panel_domain" --cert-name "$panel_domain" \
        --non-interactive --agree-tos -m "$admin_email" --keep-until-expiring \
        "${certbot_extra_args[@]}"; then
        rollback_acme_lineages
        return 1
    fi

    echo "Acquiring Let's Encrypt TLS certificate for REALITY decoy ($reality_domain)..."
    if ! certbot certonly --webroot -w "$ACME_WEBROOT" \
        -d "$reality_domain" --cert-name "$reality_domain" \
        --non-interactive --agree-tos -m "$admin_email" --keep-until-expiring \
        "${certbot_extra_args[@]}"; then
        rollback_acme_lineages
        return 1
    fi

    if [[ -n "$vision_domain" ]]; then
        echo "Acquiring Let's Encrypt TLS certificate for VLESS Vision ($vision_domain)..."
        if ! certbot certonly --webroot -w "$ACME_WEBROOT" \
            -d "$vision_domain" --cert-name "$vision_domain" \
            --non-interactive --agree-tos -m "$admin_email" --keep-until-expiring \
            "${certbot_extra_args[@]}"; then
            rollback_acme_lineages
            return 1
        fi
    fi

    rm -f /etc/nginx/conf.d/00-bootstrap-acme.conf

    # Verify certificates cryptographically (refuse to proceed with invalid or missing certificates)
    if ! verify_acme_certificate "$panel_domain" || \
       ! verify_acme_certificate "$reality_domain" || \
       { [[ -n "$vision_domain" ]] && ! verify_acme_certificate "$vision_domain"; }; then
        rollback_acme_lineages
        return 1
    fi

    # Step 5: NGINX Configuration
    ensure_nginx_stream_block
    generate_stream_config "$panel_domain" "$reality_domain" "/etc/nginx/stream-enabled/gowave-stream.conf" "/proc/net/if_inet6" "$vision_domain"
    generate_production_http_vhost "$panel_domain" "$reality_domain" "/etc/nginx/conf.d/gowave-http.conf" "/proc/net/if_inet6" "$vision_domain"
    generate_panel_https_vhost "$panel_domain"
    generate_decoy_vhost "$reality_domain"
    if [[ -n "$vision_domain" ]]; then
        generate_vision_fallback_vhost "$vision_domain"
    fi
    configure_certbot_deploy_hook "$acme_tx_id"

    reload_nginx_strict

    # Step 6: GoWave Panel Native Installation
    download_panel_release "$GOWAVE_DIR" "${GOWAVE_PANEL_VERSION:-$GOWAVE_DEFAULT_VERSION}"
    generate_panel_env "$GOWAVE_DIR" "$panel_domain" "$panel_domain/api/sub"
    configure_panel_systemd "$GOWAVE_DIR"
    if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        systemctl restart --no-ask-password gowave.service
        systemctl is-active --quiet gowave.service
    fi
    verify_panel_startup 127.0.0.1 3000 30
    verify_public_tls_sni "$panel_domain"

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

    if ! PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
        XRAY_SERVER_VERSION="${XRAY_SERVER_VERSION:-}" \
        GOWAVE_MIHOMO_X25519="${GOWAVE_MIHOMO_X25519:-}" \
        GOWAVE_REALITY_FINGERPRINT="${GOWAVE_REALITY_FINGERPRINT:-}" \
        python3 - \
        "$SCRIPT_DIR" "$panel_domain" "$reality_domain" "$admin_user" \
        "$JOURNAL_FILE" "$STATE_FILE" "$CREDENTIALS_FILE" "$vision_domain" 3<<< "$admin_pass" <<'PY'
import json
import os
import sys
import time

(script_dir, panel_domain, reality_domain, admin_user,
 journal_path, state_path, credentials_path, *extra) = sys.argv[1:]
vision_domain = extra[0] if extra and extra[0] else None
admin_password = os.fdopen(3, "r", encoding="utf-8").read().rstrip("\n")

sys.path.insert(0, script_dir)
from modules.api_client import GoWaveClient, atomic_write_state, save_credentials
from modules.recovery import write_journal_atomically

journal = {
    "transaction_id": f"provision_{int(time.time())}",
    "op": "provision",
    "state": "PROVISION_PREPARED",
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "entities": {},
}
write_journal_atomically(journal_path, journal)

client = GoWaveClient("http://127.0.0.1:3000")
client.register_initial_admin(admin_user, admin_password)
client.login(admin_user, admin_password)

journal["state"] = "PROVISION_APPLYING"
write_journal_atomically(journal_path, journal)

def persist_transaction_entities(entities):
    journal["entities"] = list(entities)
    write_journal_atomically(journal_path, journal)

client.transaction_callback = persist_transaction_entities
x25519 = client.generate_x25519()
raw_config = client.compile_config_profile(
    "local-node", reality_domain, x25519["privateKey"],
    public_key=x25519.get("publicKey"), vision_domain=vision_domain, panel_domain=panel_domain
)
profile = client.provision_config_profile("GoWave MVP Unified Profile - local-node", raw_config)
profile_uuid = profile["profile_uuid"]
inbounds = profile["inbounds"]
inbound_uuids = [item["uuid"] for item in inbounds]
journal["entities"] = client.transaction_entities
write_journal_atomically(journal_path, journal)

node_uuid = client.associate_node("local-node", "127.0.0.1", 3002, profile_uuid, inbound_uuids)
journal["entities"] = client.transaction_entities
write_journal_atomically(journal_path, journal)

squad_uuid = client.provision_internal_squad("Default MVP Squad", inbound_uuids)
journal["entities"] = client.transaction_entities
write_journal_atomically(journal_path, journal)

client.provision_hosts(
    profile_uuid, inbounds, node_uuid, squad_uuid,
    panel_domain, reality_domain, vision_domain=vision_domain
)
journal["entities"] = client.transaction_entities
write_journal_atomically(journal_path, journal)

short_uuid = client.provision_user("default-user", squad_uuid)
token_info = client.issue_api_token()
journal["entities"] = client.transaction_entities
write_journal_atomically(journal_path, journal)

save_credentials(admin_user, admin_password, f"https://{panel_domain}",
                 token_info["token"], credentials_path)

existing_cc = "bbr"
if os.path.exists(state_path):
    try:
        with open(state_path, encoding="utf-8") as state_file:
            existing_cc = json.load(state_file).get("congestionControl", "bbr")
    except Exception:
        pass

state = {
    "schemaVersion": 2,
    "installationMode": "all-in-one",
    "panelDomain": panel_domain,
    "realityDomain": reality_domain,
    "congestionControl": existing_cc,
    "nodePort": 3002,
    "localNodeUuid": node_uuid,
    "profileUuid": profile_uuid,
    "squadUuid": squad_uuid,
    "defaultUserShortUuid": short_uuid,
    "nodes": [{
        "name": "local-node",
        "address": "127.0.0.1",
        "port": 3002,
        "uuid": node_uuid,
    }],
}
atomic_write_state(state, state_path)

journal["state"] = "PROVISION_COMMITTED"
journal["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
write_journal_atomically(journal_path, journal)
PY
    then
        echo "Initial API provisioning failed; attempting action-aware rollback." >&2
        rollback_acme_lineages
        if [[ -f "$JOURNAL_FILE" ]] && ! PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from modules.api_client import rollback_provisioning
import sys
sys.exit(0 if rollback_provisioning('$JOURNAL_FILE', '$STATE_FILE', '$CREDENTIALS_FILE') else 1)
"; then
            echo "CRITICAL: API rollback incomplete; recovery journal requires operator attention." >&2
        fi
        return 1
    fi

    cleanup_acme_snapshot "$acme_tx_id" "$panel_domain"
    cleanup_acme_snapshot "$acme_tx_id" "$reality_domain"
    if [[ -n "$vision_domain" ]]; then
        cleanup_acme_snapshot "$acme_tx_id" "$vision_domain"
    fi
    cleanup_deploy_hook_manifest "$acme_tx_id"
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
            local vision_domain="${VISION_DOMAIN:-}"
            local positional_args=()
            while (( $# > 0 )); do
                case "$1" in
                    --vision-domain)
                        if (( $# < 2 )); then
                            echo "Error: --vision-domain requires an argument." >&2
                            return 1
                        fi
                        vision_domain="$2"
                        shift 2
                        ;;
                    --vision-domain=*)
                        vision_domain="${1#*=}"
                        shift
                        ;;
                    *)
                        positional_args+=("$1")
                        shift
                        ;;
                esac
            done

            local name="${positional_args[0]:-}"
            local ip="${positional_args[1]:-}"
            local worker_domain="${positional_args[2]:-}"
            local reality_domain="${positional_args[3]:-}"
            local ssh_user="${positional_args[4]:-root}"
            local ssh_port="${positional_args[5]:-22}"

            if [[ -z "$name" || -z "$ip" || -z "$worker_domain" || -z "$reality_domain" ]]; then
                echo "Usage: gowave-auto.sh node add [--vision-domain <domain>] <worker-name> <worker-ip> <worker-domain> <reality-domain> [ssh-user] [ssh-port]" >&2
                return 1
            fi

            validate_acme_server "${GOWAVE_ACME_SERVER:-}" || return 1

            local panel_ip panel_ipv6
            panel_ip=$(curl -s4 --connect-timeout 5 --max-time 10 https://ifconfig.me || curl -s4 --connect-timeout 5 --max-time 10 https://api.ipify.org || true)
            panel_ipv6=$(curl -s6 --connect-timeout 5 --max-time 10 https://ifconfig.me || curl -s6 --connect-timeout 5 --max-time 10 https://api64.ipify.org || true)
            if [[ -z "$panel_ip" && -z "$panel_ipv6" ]]; then
                echo "Error: unable to determine a public Panel IP address; refusing an untrusted firewall fallback." >&2
                return 1
            fi
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
            # Validate SSH target and pin before mutating the GoWave API.
            if [[ ! "$ssh_port" =~ ^[0-9]+$ ]] || (( ssh_port < 1 || ssh_port > 65535 )); then
                echo "Error: SSH port must be between 1 and 65535." >&2
                return 2
            fi
            if [[ ! "$ssh_user" =~ ^[A-Za-z_][A-Za-z0-9._-]{0,31}$ ]]; then
                echo "Error: invalid SSH username." >&2
                return 2
            fi
            python3 - "$ip" <<'PY'
import ipaddress, sys
try:
    ipaddress.ip_address(sys.argv[1])
except ValueError as exc:
    raise SystemExit(f"Invalid Worker IP address: {exc}")
PY
            local known_hosts="${SSH_KNOWN_HOSTS:-/root/.ssh/known_hosts}"
            local host_key="$ip"
            if [[ "$ssh_port" != "22" ]]; then
                host_key="[$ip]:$ssh_port"
            fi
            if [[ ! -s "$known_hosts" ]] || ! ssh-keygen -F "$host_key" -f "$known_hosts" >/dev/null 2>&1; then
                echo "Error: SSH host key for $host_key is not pre-pinned in $known_hosts." >&2
                echo "Verify the fingerprint out of band and add the host key before retrying." >&2
                return 1
            fi

            # 2. Register the node using argv for data and FD 3 for the password.
            # User-controlled values are never interpolated into Python source.
            if ! PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
                XRAY_SERVER_VERSION="${XRAY_SERVER_VERSION:-}" \
                GOWAVE_MIHOMO_X25519="${GOWAVE_MIHOMO_X25519:-}" \
                GOWAVE_REALITY_FINGERPRINT="${GOWAVE_REALITY_FINGERPRINT:-}" \
                python3 - \
                "$SCRIPT_DIR" "$name" "$ip" "$worker_domain" "$reality_domain" \
                "$node_port" "$admin_user" "$JOURNAL_FILE" "$STATE_FILE" "$vision_domain" 3<<< "$admin_pass" <<'PY'
import ipaddress
import json
import os
import re
import sys
import time

(script_dir, name, address, worker_domain, reality_domain, port, admin_user,
 journal_path, state_path, vision_domain) = sys.argv[1:]
admin_password = os.fdopen(3, "r", encoding="utf-8").read().rstrip("\n")

if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", name):
    raise SystemExit("Invalid node name; use 1-64 ASCII letters, digits, dot, underscore or hyphen.")
try:
    ipaddress.ip_address(address)
except ValueError as exc:
    raise SystemExit(f"Invalid worker IP address: {exc}") from exc

def validate_domain(value):
    if len(value) > 253:
        raise SystemExit(f"Invalid DNS hostname (too long): {value}")
    labels = value.rstrip(".").split(".")
    if len(labels) < 2 or any(
        not label or len(label) > 63 or
        not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in labels
    ):
        raise SystemExit(f"Invalid DNS hostname: {value}")

validate_domain(worker_domain)
validate_domain(reality_domain)
if worker_domain.lower().rstrip(".") == reality_domain.lower().rstrip("."):
    raise SystemExit("Worker and REALITY domains must be different.")
if vision_domain:
    validate_domain(vision_domain)
    if vision_domain.lower().rstrip(".") in (worker_domain.lower().rstrip("."), reality_domain.lower().rstrip(".")):
        raise SystemExit("Vision domain must be distinct from Worker and REALITY domains.")
if not port.isdigit() or not 1 <= int(port) <= 65535:
    raise SystemExit("Invalid Node API port.")
if not admin_password:
    raise SystemExit("Panel admin password is missing; refusing node registration.")

sys.path.insert(0, script_dir)
from modules.api_client import GoWaveClient, atomic_write_state
from modules.recovery import write_journal_atomically

state_data = json.loads(open(state_path, encoding="utf-8").read())
nodes = state_data.get("nodes", [])
if not isinstance(nodes, list):
    raise SystemExit("state.json nodes must be an array.")
if any(isinstance(item, dict) and item.get("name") == name for item in nodes):
    raise SystemExit(f"Worker name is already registered in state.json: {name}")

client = GoWaveClient("http://127.0.0.1:3000")
client.login(admin_user, admin_password)

journal = {
    "transaction_id": f"node_add_{name}",
    "op": "node_add",
    "state": "NODE_ADD_PREPARED",
    "node_name": name,
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "entities": {},
}
write_journal_atomically(journal_path, journal)

def persist_transaction_entities(entities):
    journal["entities"] = list(entities)
    write_journal_atomically(journal_path, journal)

client.transaction_callback = persist_transaction_entities
x25519 = client.generate_x25519()
raw_config = client.compile_config_profile(
    f"GoWave Worker {name} Profile",
    reality_domain,
    x25519["privateKey"],
    vision_domain=vision_domain or None
)
profile = client.provision_config_profile(f"GoWave Worker {name} Profile", raw_config)
profile_uuid = profile["profile_uuid"]
inbounds = profile["inbounds"]
inbound_uuids = [item["uuid"] for item in inbounds]
journal["state"] = "NODE_ADD_APPLYING"
journal["entities"] = client.transaction_entities
write_journal_atomically(journal_path, journal)

node_uuid = client.associate_node(name, address, int(port), profile_uuid, inbound_uuids)
journal["entities"] = client.transaction_entities
write_journal_atomically(journal_path, journal)

squad_uuid = state_data.get("squadUuid")
client.provision_internal_squad("Default MVP Squad", inbound_uuids)
client.provision_hosts(
    profile_uuid, inbounds, node_uuid, squad_uuid,
    worker_domain, reality_domain, name,
    vision_domain=vision_domain or None
)
journal["entities"] = client.transaction_entities
write_journal_atomically(journal_path, journal)

node_entry = {
    "name": name,
    "address": address,
    "port": int(port),
    "workerDomain": worker_domain,
    "realityDomain": reality_domain,
    "uuid": node_uuid,
}
if vision_domain:
    node_entry["visionDomain"] = vision_domain
nodes.append(node_entry)
state_data["nodes"] = nodes
atomic_write_state(state_data, state_path)
PY
            then
                echo "Worker API registration failed; attempting action-aware API rollback." >&2
                if [[ -f "$JOURNAL_FILE" ]] && ! PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from modules.api_client import rollback_provisioning
import sys
sys.exit(0 if rollback_provisioning('$JOURNAL_FILE', '$STATE_FILE', '$CREDENTIALS_FILE') else 1)
"; then
                    echo "CRITICAL: API rollback incomplete; recovery journal requires operator attention." >&2
                fi
                return 1
            fi


            # Mark remote side effects as in-flight before dispatch.
            python3 -c "
import sys, json, time
for p in ['$SCRIPT_DIR', '/opt/gowave-auto-nginx']:
    if p not in sys.path:
        sys.path.insert(0, p)
from modules.recovery import write_journal_atomically
jdata = json.load(open('$JOURNAL_FILE'))
jdata['state'] = 'NODE_ADD_VERIFYING'
jdata['timestamp'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
write_journal_atomically('$JOURNAL_FILE', jdata)
"
            # 4. Dispatch remote deployment strictly via SSH stdin
            local secret_key
            secret_key=$(extract_secret_key "$GOWAVE_DIR")
            if ! PANEL_IP="$panel_ip" PANEL_IPV6="$panel_ipv6" NODE_PORT="$node_port" SECRET_KEY="$secret_key" GOWAVE_NODE_VERSION="${GOWAVE_NODE_VERSION:-latest}" \
                XRAY_SERVER_VERSION="${XRAY_SERVER_VERSION:-}" \
                GOWAVE_ACME_SERVER="${GOWAVE_ACME_SERVER:-}" \
                GOWAVE_NODE_INSTALLER_COMMIT="${GOWAVE_NODE_INSTALLER_COMMIT:-}" \
                GOWAVE_NODE_INSTALLER_SHA256="${GOWAVE_NODE_INSTALLER_SHA256:-}" \
                VISION_DOMAIN="$vision_domain" \
                SSH_KNOWN_HOSTS="$known_hosts" "$SCRIPT_DIR/gowave-node-auto.sh" remote_payload "$ip" "$ssh_port" "$worker_domain" "$reality_domain" "$ssh_user"; then
                echo "Remote Worker deployment failed; rolling back Worker host configuration and Panel API entities." >&2
                local rollback_failed=0
                if ! PANEL_IP="$panel_ip" PANEL_IPV6="$panel_ipv6" NODE_PORT="$node_port" SSH_KNOWN_HOSTS="$known_hosts" \
                    VISION_DOMAIN="$vision_domain" \
                    "$SCRIPT_DIR/gowave-node-auto.sh" remote_rollback "$ip" "$ssh_port" "$worker_domain" "$reality_domain" "$ssh_user"; then
                    echo "CRITICAL: Remote Worker host rollback failed; manual inspection required." >&2
                    rollback_failed=1
                fi
                if ! PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from modules.api_client import rollback_provisioning
import sys
sys.exit(0 if rollback_provisioning('$JOURNAL_FILE', '$STATE_FILE', '$CREDENTIALS_FILE') else 1)
"; then
                    echo "CRITICAL: API rollback incomplete; recovery journal requires operator attention." >&2
                    rollback_failed=1
                fi
                if (( rollback_failed != 0 )); then
                    echo "CRITICAL: Rollback failed for Worker '$name'; recovery journal retained." >&2
                fi
                return 1
            fi

            # 5. Commit transaction
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
        rollback|remove)
            acquire_lock
            local vision_domain="${VISION_DOMAIN:-}"
            local positional_args=()
            while (( $# > 0 )); do
                case "$1" in
                    --vision-domain)
                        if (( $# < 2 )); then
                            echo "Error: --vision-domain requires an argument." >&2
                            return 1
                        fi
                        vision_domain="$2"
                        shift 2
                        ;;
                    --vision-domain=*)
                        vision_domain="${1#*=}"
                        shift
                        ;;
                    *)
                        positional_args+=("$1")
                        shift
                        ;;
                esac
            done

            local ip="${positional_args[0]:-}"
            local worker_domain="${positional_args[1]:-}"
            local reality_domain="${positional_args[2]:-}"
            local ssh_user="${positional_args[3]:-root}"
            local ssh_port="${positional_args[4]:-22}"

            if [[ -z "$ip" || -z "$worker_domain" || -z "$reality_domain" ]]; then
                echo "Usage: gowave-auto.sh node rollback [--vision-domain <domain>] <worker-ip> <worker-domain> <reality-domain> [ssh-user] [ssh-port]" >&2
                return 1
            fi
            local known_hosts="${SSH_KNOWN_HOSTS:-/root/.ssh/known_hosts}"
            local panel_ip panel_ipv6
            panel_ip=$(curl -s4 --connect-timeout 5 --max-time 10 https://ifconfig.me || curl -s4 --connect-timeout 5 --max-time 10 https://api.ipify.org || true)
            panel_ipv6=$(curl -s6 --connect-timeout 5 --max-time 10 https://ifconfig.me || curl -s6 --connect-timeout 5 --max-time 10 https://api64.ipify.org || true)
            local node_port=3002
            PANEL_IP="$panel_ip" PANEL_IPV6="$panel_ipv6" NODE_PORT="$node_port" SSH_KNOWN_HOSTS="$known_hosts" \
                VISION_DOMAIN="$vision_domain" \
                "$SCRIPT_DIR/gowave-node-auto.sh" remote_rollback "$ip" "$ssh_port" "$worker_domain" "$reality_domain" "$ssh_user"
            ;;
        *)
            echo "Usage: gowave-auto.sh node {add|list|rollback}"
            ;;
    esac
}

cmd_domain_change() {
    acquire_lock
    local new_panel_domain="${1:-}"
    local new_reality_domain="${2:-}"
    if [[ -z "$new_panel_domain" || -z "$new_reality_domain" ]]; then
        echo "Usage: gowave-auto.sh domain-change <panel-domain> <reality-domain>" >&2
        return 2
    fi

    if [[ "$new_panel_domain" == "$new_reality_domain" ]]; then
        echo "Error: panel and REALITY domains must be different." >&2
        return 2
    fi
    python3 - "$new_panel_domain" "$new_reality_domain" <<'PY'
import re, sys
for domain in sys.argv[1:]:
    if len(domain) > 253:
        raise SystemExit(f"Invalid domain name (too long): {domain}")
    labels = domain.rstrip(".").split(".")
    if len(labels) < 2 or any(
        not label or len(label) > 63 or
        not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in labels
    ):
        raise SystemExit(f"Invalid DNS hostname: {domain}")
PY

    echo "Changing domains to: $new_panel_domain / $new_reality_domain..."

    local srv_ip
    srv_ip=$(curl -s4 --connect-timeout 5 --max-time 10 https://ifconfig.me || curl -s4 --connect-timeout 5 --max-time 10 https://api.ipify.org || echo "")
    if [[ -n "$srv_ip" ]] && command -v getent >/dev/null 2>&1; then
        local resolved_ip
        resolved_ip=$(getent ahostsv4 "$new_panel_domain" 2>/dev/null | awk 'NR==1 {print $1}' || true)
        if [[ -n "$resolved_ip" && "$resolved_ip" != "$srv_ip" ]]; then
            echo "Error: DNS resolution for $new_panel_domain ($resolved_ip) does not match server IP ($srv_ip)." >&2
            return 1
        fi
    fi

    validate_acme_server "${GOWAVE_ACME_SERVER:-}" || return 1
    local effective_acme_server="${GOWAVE_ACME_SERVER:-https://acme-v02.api.letsencrypt.org/directory}"
    check_acme_lineage "$new_panel_domain" "$effective_acme_server" || return 1
    check_acme_lineage "$new_reality_domain" "$effective_acme_server" || return 1

    local snap_dir
    snap_dir=$(prepare_update_snapshot "domain-change")
    rollback_domain_change() {
        local reason="$1"
        echo "Domain change failed: $reason. Restoring previous files, NGINX and certificates..." >&2
        if execute_file_rollback "$snap_dir"; then
            PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 - "$JOURNAL_FILE" "$reason" <<'PY'
import json, sys, time
from pathlib import Path
p = Path(sys.argv[1])
data = json.loads(p.read_text())
data["state"] = "ROLLED_BACK"
data["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
data["error"] = sys.argv[2]
from modules.recovery import write_journal_atomically
write_journal_atomically(str(p), data)
PY
        else
            echo "CRITICAL: rollback did not complete; journal remains recoverable." >&2
        fi
        return 1
    }

    PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 - "$JOURNAL_FILE" <<'PY'
import json, sys, time
from pathlib import Path
p=Path(sys.argv[1]); data=json.loads(p.read_text())
data["state"]="APPLYING"
data["timestamp"]=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
from modules.recovery import write_journal_atomically
write_journal_atomically(str(p), data)
PY

    generate_bootstrap_acme_vhost "$new_panel_domain" "$new_reality_domain"
    reload_nginx_strict || { rollback_domain_change "bootstrap NGINX activation failed"; return 1; }

    local certbot_extra_args=()
    if [[ -n "${GOWAVE_ACME_SERVER:-}" ]]; then
        certbot_extra_args+=(--server "$GOWAVE_ACME_SERVER")
    fi

    if ! certbot certonly --webroot -w "$ACME_WEBROOT" -d "$new_panel_domain" --cert-name "$new_panel_domain" --non-interactive --agree-tos --register-unsafely-without-email --keep-until-expiring "${certbot_extra_args[@]}"; then
        rollback_domain_change "ACME issuance failed for panel domain"; return 1
    fi
    if ! certbot certonly --webroot -w "$ACME_WEBROOT" -d "$new_reality_domain" --cert-name "$new_reality_domain" --non-interactive --agree-tos --register-unsafely-without-email --keep-until-expiring "${certbot_extra_args[@]}"; then
        rollback_domain_change "ACME issuance failed for REALITY domain"; return 1
    fi
    verify_acme_certificate "$new_panel_domain" || { rollback_domain_change "invalid panel certificate"; return 1; }
    verify_acme_certificate "$new_reality_domain" || { rollback_domain_change "invalid REALITY certificate"; return 1; }

    rm -f /etc/nginx/conf.d/00-bootstrap-acme.conf
    generate_stream_config "$new_panel_domain" "$new_reality_domain"
    generate_production_http_vhost "$new_panel_domain" "$new_reality_domain"
    generate_panel_https_vhost "$new_panel_domain"
    generate_decoy_vhost "$new_reality_domain"
    sed -i "s/^PANEL_DOMAIN=.*/PANEL_DOMAIN=$new_panel_domain/" "$GOWAVE_DIR/.env"
    sed -i "s|^SUB_PUBLIC_DOMAIN=.*|SUB_PUBLIC_DOMAIN=$new_panel_domain/api/sub|" "$GOWAVE_DIR/.env"

    python3 - "$JOURNAL_FILE" <<'PY'
import json, sys, time
from pathlib import Path
p=Path(sys.argv[1]); data=json.loads(p.read_text())
data["state"]="VERIFYING"
data["timestamp"]=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
from modules.recovery import write_journal_atomically
write_journal_atomically(str(p), data)
PY
    reload_nginx_strict || { rollback_domain_change "production NGINX configuration failed"; return 1; }
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart --no-ask-password gowave.service || { rollback_domain_change "Panel restart failed"; return 1; }
        systemctl is-active --quiet gowave.service || { rollback_domain_change "Panel service is not active"; return 1; }
    fi
    verify_panel_startup 127.0.0.1 3000 30 || { rollback_domain_change "Panel healthcheck failed"; return 1; }
    verify_public_tls_sni "$new_panel_domain" || { rollback_domain_change "Panel TLS/SNI verification failed"; return 1; }

    PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 - "$JOURNAL_FILE" "$RECOVERY_DIR" <<'PY'
import json, sys, time
from pathlib import Path
p=Path(sys.argv[1]); data=json.loads(p.read_text())
data["state"]="COMMITTED"
data["timestamp"]=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
from modules.recovery import write_journal_atomically, prune_snapshots
write_journal_atomically(str(p), data)
prune_snapshots(sys.argv[2])
PY
    echo "Domain change completed and verified successfully."
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

    # Preserve application data and recovery state by default. Without a
    # verified installer ownership marker, recursive deletion is unsafe.
    echo "Managed service/config removal completed. Application data, node binaries, backups, and state were preserved:"
    echo "  $GOWAVE_DIR"
    echo "  /opt/gowave-node"
    echo "  /var/lib/gowave-auto-nginx"
    echo "  /var/www/gowave-auto-nginx"
    echo "  /var/www/gowave-acme"
    echo "Review and remove these paths manually only after checking their contents."
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
