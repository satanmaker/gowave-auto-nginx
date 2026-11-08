#!/usr/bin/env bash
# gowave-node-auto.sh - Distributed Edge Worker Deployment and Hardening Orchestrator
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECOMMENDED_NODE_PORT=3002

log_info() { printf '[INFO] %s\n' "$*"; }
log_warn() { printf '[WARN] %s\n' "$*" >&2; }
log_err()  { printf '[ERROR] %s\n' "$*" >&2; }

# Modules source if local
if [[ -f "$SCRIPT_DIR/modules/os.sh" ]]; then
    source "$SCRIPT_DIR/modules/os.sh"
fi
if [[ -f "$SCRIPT_DIR/modules/security.sh" ]]; then
    source "$SCRIPT_DIR/modules/security.sh"
fi

# Function to pack cover-reality into base64 string
pack_cover_reality() {
    local cover_dir="${1:-$SCRIPT_DIR/assets/cover-sites/cover-reality}"
    if [[ ! -d "$cover_dir" ]]; then
        echo "Error: Cover directory $cover_dir not found" >&2
        return 1
    fi
    tar -czf - -C "$cover_dir" . | base64 -w 0
}

# The remote orchestration payload streaming over SSH stdin
remote_payload() {
    local host="$1"
    local port="${2:-22}"
    local worker_domain="$3"
    local reality_domain="$4"
    local ssh_user="${5:-root}"

    local node_port="${NODE_PORT:-$RECOMMENDED_NODE_PORT}"
    local panel_ip="${PANEL_IP:-}"
    local panel_ipv6="${PANEL_IPV6:-}"
    local admin_email="${ADMIN_EMAIL:-admin@${worker_domain}}"
    local known_hosts="${SSH_KNOWN_HOSTS:-/root/.ssh/known_hosts}"
    local host_key="$host"
    if [[ "$port" != "22" ]]; then
        host_key="[$host]:$port"
    fi
    if [[ ! -s "$known_hosts" ]] || ! ssh-keygen -F "$host_key" -f "$known_hosts" >/dev/null 2>&1; then
        log_err "SSH host key for $host_key is not pre-pinned in $known_hosts."
        log_err "Obtain the host key over a trusted channel, compare its fingerprint out-of-band, then add it to known_hosts."
        return 1
    fi
    local installer_commit="7b3514d1ab8c674050597820d52d55525d4bece7"
    local verifier_b64=""
    if [[ -f "$SCRIPT_DIR/modules/verify_node_mtls.py" ]]; then
        verifier_b64=$(base64 -w 0 "$SCRIPT_DIR/modules/verify_node_mtls.py")
    else
        echo "Error: mTLS verifier is required for remote worker acceptance." >&2
        return 1
    fi

    # Validate node port and warn on host collisions if worker host matches panel IP
    if [[ "$host" == "127.0.0.1" || "$host" == "localhost" || "$host" == "$panel_ip" ]]; then
        if [[ "$node_port" != "$RECOMMENDED_NODE_PORT" ]]; then
            log_warn "Worker IP matches PANEL_IP or loopback; enforcing NODE_PORT=$RECOMMENDED_NODE_PORT to prevent port collision with Panel (3000)."
            node_port="$RECOMMENDED_NODE_PORT"
        fi
    fi

    # Pack cover-reality assets
    local cover_b64 cover_sha256
    cover_b64=$(pack_cover_reality)
    cover_sha256=$(echo -n "$cover_b64" | base64 -d | sha256sum | awk '{print $1}')

    log_info "Deploying GoWave Edge Worker to ${ssh_user}@${host}:${port} (Worker Domain: $worker_domain, Reality Domain: $reality_domain, Port: $node_port)..."

    {
        # 1. Environment variables strictly over stdin (NEVER in ssh argv)
        printf 'export PANEL_IP=%q\n' "$panel_ip"
        printf 'export PANEL_IPV6=%q\n' "$panel_ipv6"
        printf 'export NODE_PORT=%q\n' "$node_port"
        printf 'export GOWAVE_NODE_VERSION=%q\n' "${GOWAVE_NODE_VERSION:-latest}"
        printf 'export GOWAVE_NODE_INSTALLER_COMMIT=%q\n' "$installer_commit"
        printf 'export SSH_PORT=%q\n' "$port"
        printf 'export VERIFY_NODE_MTLS_B64=%q\n' "$verifier_b64"
        printf 'export WORKER_DOMAIN=%q\n' "$worker_domain"
        printf 'export REALITY_DOMAIN=%q\n' "$reality_domain"
        printf 'export ADMIN_EMAIL=%q\n' "$admin_email"
        printf 'COVER_REALITY_B64=%q\n' "$cover_b64"
        printf 'COVER_REALITY_SHA256=%q\n' "$cover_sha256"
        # Secret strictly scoped, not exported globally
        printf '_NODE_SECRET_KEY=%q\n' "$SECRET_KEY"

        # 2. Remote helper functions
        cat <<'RUNNER_FUNCS'
setup_system_prereqs() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        nginx-full libnginx-mod-stream certbot python3 python3-systemd \
        curl tar gzip openssl ufw fail2ban iproute2 ca-certificates
}

configure_host_security() {
    # Keep MTU/file-limit tuning independent from optional BBR support.
    mkdir -p /etc/sysctl.d
    modprobe tcp_bbr 2>/dev/null || true
    {
        echo "# Managed by GoWave Auto NGINX"
        echo "net.ipv4.tcp_mtu_probing = 1"
        echo "fs.file-max = 1048576"
        if grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
            echo "net.core.default_qdisc = fq"
            echo "net.ipv4.tcp_congestion_control = bbr"
        else
            echo "Warning: BBR is unavailable in this kernel; retaining the system congestion-control default." >&2
        fi
    } > /etc/sysctl.d/99-gowave-node.conf
    sysctl -p /etc/sysctl.d/99-gowave-node.conf

    # Allocate swap only on small-memory hosts. Do not persist a failed swapon.
    local mem_kb fs_type swap_tmp
    mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
    if [[ "$mem_kb" -le 1048576 && "$mem_kb" -gt 0 ]] && ! swapon --show --noheadings | grep -q .; then
        if [[ -e /swapfile ]]; then
            log_warn "/swapfile already exists; refusing to overwrite an unmanaged file."
        else
            fs_type=$(findmnt -n -o FSTYPE /)
            if [[ "$fs_type" == "btrfs" ]]; then
                if ! command -v btrfs >/dev/null 2>&1 || ! btrfs filesystem mkswapfile --size 1G /swapfile; then
                    log_warn "Could not create a Btrfs-compatible swapfile; continuing without swap."
                    rm -f /swapfile
                fi
            elif fallocate -l 1G /swapfile 2>/dev/null; then
                chmod 0600 /swapfile
                mkswap /swapfile >/dev/null
            else
                rm -f /swapfile
                dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none
                chmod 0600 /swapfile
                mkswap /swapfile >/dev/null
            fi
            if [[ -f /swapfile ]] && swapon /swapfile; then
                if ! grep -qE '^[[:space:]]*/swapfile[[:space:]]' /etc/fstab; then
                    swap_tmp=$(mktemp /etc/fstab.gowave.XXXXXX)
                    cat /etc/fstab > "$swap_tmp"
                    printf '/swapfile none swap sw 0 0\n' >> "$swap_tmp"
                    chmod --reference=/etc/fstab "$swap_tmp"
                    chown --reference=/etc/fstab "$swap_tmp"
                    mv -f "$swap_tmp" /etc/fstab
                fi
            else
                log_warn "Swap activation failed; no /etc/fstab entry was written."
                swapoff /swapfile 2>/dev/null || true
                rm -f /swapfile
            fi
        fi
    fi
}

configure_firewall() {
    local panel_ip="${PANEL_IP:-}" panel_ipv6="${PANEL_IPV6:-}" ssh_port="${SSH_PORT:-22}"
    if [[ -z "$panel_ip" && -z "$panel_ipv6" ]]; then
        echo "Fatal: PANEL_IP or PANEL_IPV6 is required; refusing an unscoped Node API firewall rule." >&2
        return 1
    fi
    python3 - "$panel_ip" "$panel_ipv6" "$ssh_port" "$NODE_PORT" <<'PY'
import ipaddress, sys
v4, v6, ssh_port, node_port = sys.argv[1:]
if v4 and ipaddress.ip_address(v4).version != 4:
    raise SystemExit("PANEL_IP must be an IPv4 address")
if v6 and ipaddress.ip_address(v6).version != 6:
    raise SystemExit("PANEL_IPV6 must be an IPv6 address")
for name, value in (("SSH_PORT", ssh_port), ("NODE_PORT", node_port)):
    if not value.isdigit() or not 1 <= int(value) <= 65535:
        raise SystemExit(f"{name} must be a valid TCP port")
PY

    # Detect an existing unrestricted API-port exception rather than claiming
    # the new source-specific rule makes an already-open port private.
    if ufw status | awk -v p="$NODE_PORT/tcp" 'index($0, p) == 1 && $0 ~ /ALLOW[[:space:]]+IN/ && $0 ~ /Anywhere/ {found=1} END {exit !found}'; then
        echo "Fatal: UFW already contains an unrestricted allow rule for NODE_PORT=$NODE_PORT; remove it manually before retrying." >&2
        return 1
    fi

    ufw default deny incoming
    ufw default allow outgoing
    ufw allow "$ssh_port/tcp" comment "SSH administration"
    ufw allow 80/tcp comment "HTTP ACME challenge"
    ufw allow 443/tcp comment "HTTPS and Xray Stream"
    if [[ -n "$panel_ip" ]]; then
        ufw allow proto tcp from "$panel_ip" to any port "$NODE_PORT" comment "GoWave Control Plane IPv4"
    fi
    if [[ -n "$panel_ipv6" ]]; then
        ufw allow proto tcp from "$panel_ipv6" to any port "$NODE_PORT" comment "GoWave Control Plane IPv6"
    fi
    ufw --force enable
    ufw status | grep -q '^Status: active$' || {
        echo "Fatal: UFW did not enter the active state." >&2
        return 1
    }
}

unpack_cover_reality() {
    mkdir -p /var/www/gowave-auto-nginx/cover-reality
    local actual_sha
    actual_sha=$(echo -n "$COVER_REALITY_B64" | base64 -d | sha256sum | awk '{print $1}')
    if [ "$actual_sha" != "$COVER_REALITY_SHA256" ]; then
        echo "Error: Cover reality archive SHA-256 verification failed!" >&2
        echo "Expected: $COVER_REALITY_SHA256, got: $actual_sha" >&2
        exit 1
    fi
    echo -n "$COVER_REALITY_B64" | base64 -d | tar -xzf - -C /var/www/gowave-auto-nginx/cover-reality
    chmod -R 0755 /var/www/gowave-auto-nginx/cover-reality
}

configure_edge_nginx() {
    mkdir -p /etc/nginx/stream-enabled /etc/nginx/conf.d /var/www/gowave-acme
    chmod 0755 /var/www/gowave-acme

    # Certbot issuance via webroot
    cat > /etc/nginx/conf.d/00-bootstrap-worker-acme.conf <<EOF
server {
    listen 80;
    server_name $WORKER_DOMAIN $REALITY_DOMAIN;
    location /.well-known/acme-challenge/ {
        root /var/www/gowave-acme;
    }
    location / {
        return 444;
    }
}
EOF
    nginx -t
    systemctl reload nginx || systemctl restart nginx
    systemctl is-active --quiet nginx || { echo "Fatal: NGINX failed to activate bootstrap ACME config" >&2; return 1; }

    echo "Acquiring Let's Encrypt TLS certificate for Worker ($WORKER_DOMAIN)..."
    certbot certonly --webroot -w /var/www/gowave-acme \
        -d "$WORKER_DOMAIN" --cert-name "$WORKER_DOMAIN" \
        --non-interactive --agree-tos -m "$ADMIN_EMAIL" --keep-until-expiring

    echo "Acquiring Let's Encrypt TLS certificate for REALITY decoy ($REALITY_DOMAIN)..."
    certbot certonly --webroot -w /var/www/gowave-acme \
        -d "$REALITY_DOMAIN" --cert-name "$REALITY_DOMAIN" \
        --non-interactive --agree-tos -m "$ADMIN_EMAIL" --keep-until-expiring

    rm -f /etc/nginx/conf.d/00-bootstrap-worker-acme.conf

    verify_worker_certificate() {
        local domain="$1" cert="/etc/letsencrypt/live/$1/fullchain.pem" key="/etc/letsencrypt/live/$1/privkey.pem"
        [[ -s "$cert" && -s "$key" ]] || { echo "Fatal: certificate/key missing for $domain" >&2; return 1; }
        openssl x509 -in "$cert" -noout -checkhost "$domain" >/dev/null
        openssl x509 -in "$cert" -noout -checkend 86400 >/dev/null
        local cert_pub key_pub
        cert_pub=$(openssl x509 -in "$cert" -noout -pubkey)
        key_pub=$(openssl pkey -in "$key" -pubout)
        [[ -n "$cert_pub" && "$cert_pub" == "$key_pub" ]] || {
            echo "Fatal: certificate/private-key mismatch for $domain" >&2
            return 1
        }
    }
    verify_worker_certificate "$WORKER_DOMAIN"
    verify_worker_certificate "$REALITY_DOMAIN"

    # Configure automated ACME reload hook for Worker
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    cat > /etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh <<'EOF'
#!/bin/sh
set -eu
nginx -t -q
systemctl reload nginx
EOF
    chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh

    # Hook top-level stream if missing
    if ! grep -q 'stream-enabled' /etc/nginx/nginx.conf; then
        sed -i '/events {/i stream { include /etc/nginx/stream-enabled/*.conf; }' /etc/nginx/nginx.conf || \
        echo "stream { include /etc/nginx/stream-enabled/*.conf; }" >> /etc/nginx/nginx.conf
    fi

    local listen_v6=""
    if [[ -f /proc/net/if_inet6 ]] && [[ -s /proc/net/if_inet6 ]]; then
        listen_v6="listen [::]:443 so_keepalive=on;"
    fi

    # Stream SNI Preread on 443
    cat > /etc/nginx/stream-enabled/gowave-worker-stream.conf <<EOF
# Managed by GoWave Auto NGINX: Worker Edge Stream
map \$ssl_preread_server_name \$worker_dest {
    $WORKER_DOMAIN 127.0.0.1:7443;
    $REALITY_DOMAIN 127.0.0.1:8443;
    default 127.0.0.1:8443;
}

server {
    listen 443 so_keepalive=on;
    $listen_v6
    ssl_preread on;
    proxy_protocol on;
    proxy_timeout 1h;
    proxy_connect_timeout 5s;
    proxy_pass \$worker_dest;
}
EOF

    # Detect NGINX version for HTTP/2 syntax compatibility (< 1.25.1 vs >= 1.25.1)
    local listen_7443="listen 127.0.0.1:7443 ssl http2 proxy_protocol;"
    local listen_9443="listen 127.0.0.1:9443 ssl http2 proxy_protocol;"
    local ngx_ver=""
    ngx_ver=$(nginx -v 2>&1 | grep -oP 'nginx/\K[0-9.]+' || echo "1.24.0")
    if [[ "$(printf '%s\n1.25.1\n' "$ngx_ver" | sort -V | head -n1)" == "1.25.1" ]]; then
        listen_7443="listen 127.0.0.1:7443 ssl proxy_protocol;
    http2 on;"
        listen_9443="listen 127.0.0.1:9443 ssl proxy_protocol;
    http2 on;"
    fi

    # Edge HTTPS listener on 7443
    cat > /etc/nginx/conf.d/gowave-worker-https.conf <<EOF
# Managed by GoWave Auto NGINX: Worker Edge HTTPS
server {
    $listen_7443
    server_name $WORKER_DOMAIN;
    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

    ssl_certificate /etc/letsencrypt/live/$WORKER_DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$WORKER_DOMAIN/privkey.pem;

    location ^~ /xhttp-down/ {
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_request_buffering off;
        client_max_body_size 0;
        client_body_timeout 1h;
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location = /ws {
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location /trojan-grpc {
        grpc_pass grpc://127.0.0.1:10003;
        grpc_read_timeout 1h;
        grpc_send_timeout 1h;
        client_body_timeout 1h;
    }

    location / {
        return 404;
    }
}
EOF

    # Decoy on 9443
    cat > /etc/nginx/conf.d/gowave-worker-decoy.conf <<EOF
# Managed by GoWave Auto NGINX: Worker Edge Decoy
server {
    $listen_9443
    server_name $REALITY_DOMAIN;
    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;
    ssl_protocols TLSv1.3;

    ssl_certificate /etc/letsencrypt/live/$REALITY_DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$REALITY_DOMAIN/privkey.pem;

    root /var/www/gowave-auto-nginx/cover-reality;
    index index.html;
    access_log /var/log/nginx/gowave-decoy-access.log;
}
EOF

    nginx -t
    systemctl reload nginx || systemctl restart nginx
    systemctl is-active --quiet nginx || { echo "Fatal: NGINX failed to activate production configuration" >&2; return 1; }
}

run_upstream_node_installer() {
    local tmp_inst
    : "${GOWAVE_NODE_INSTALLER_COMMIT:?Pinned upstream installer commit is required}"
    [[ "$GOWAVE_NODE_INSTALLER_COMMIT" =~ ^[0-9a-f]{40}$ ]] || {
        echo "Fatal: invalid pinned upstream installer commit." >&2
        return 1
    }
    tmp_inst=$(mktemp "/tmp/gowave-node-install-XXXXXX.sh")
    if ! curl -fsSL --retry 2 --connect-timeout 15 --max-time 60 \
        "https://raw.githubusercontent.com/aaaSaZaN/gowave-node/$GOWAVE_NODE_INSTALLER_COMMIT/install.sh" -o "$tmp_inst"; then
        rm -f "$tmp_inst"
        echo "Fatal: failed to fetch the pinned GoWave Node installer." >&2
        return 1
    fi
    chmod 0700 "$tmp_inst"
    if bash "$tmp_inst" </dev/null; then
        rm -f "$tmp_inst"
    else
        local installer_rc=$?
        rm -f "$tmp_inst"
        return "$installer_rc"
    fi

    # Configure drop-in for NODE_PORT
    mkdir -p /etc/systemd/system/gowave-node.service.d
    cat > /etc/systemd/system/gowave-node.service.d/10-port.conf <<EOF
[Service]
Environment="NODE_PORT=$NODE_PORT"
EOF
    systemctl daemon-reload
    systemctl restart gowave-node.service
    systemctl is-active --quiet gowave-node.service || {
        echo "Fatal: gowave-node.service is not active after upstream installation." >&2
        return 1
    }
}
RUNNER_FUNCS

        # 3. Main entrypoint executed remotely
        cat <<'REMOTE_EOF'
set -euo pipefail
main() {
    umask 077
    trap 'unset _NODE_SECRET_KEY SECRET_KEY VERIFY_NODE_MTLS_B64; rm -f /tmp/gowave-verify-node-mtls.py' EXIT HUP INT TERM
    setup_system_prereqs </dev/null
    configure_host_security </dev/null
    configure_firewall </dev/null
    umask 022
    unpack_cover_reality </dev/null
    configure_edge_nginx </dev/null
    umask 077
    printf '%s' "$VERIFY_NODE_MTLS_B64" | base64 -d > /tmp/gowave-verify-node-mtls.py
    chmod 0700 /tmp/gowave-verify-node-mtls.py
    # Pass secret strictly scoped to upstream installer execution only.
    SECRET_KEY="$_NODE_SECRET_KEY" run_upstream_node_installer </dev/null
    unset SECRET_KEY
    systemctl is-active --quiet gowave-node.service
    printf '%s' "$_NODE_SECRET_KEY" | python3 /tmp/gowave-verify-node-mtls.py --host 127.0.0.1 --port "$NODE_PORT"
    nginx -t
    systemctl is-active --quiet nginx
    unset _NODE_SECRET_KEY VERIFY_NODE_MTLS_B64
    echo "GoWave Edge Worker deployment complete (service, NGINX, TLS and mTLS health verified)."
}
main "$@" </dev/null
REMOTE_EOF
    } | ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts" -o ServerAliveInterval=15 -p "$port" "${ssh_user}@${host}" 'bash -s'
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ "${1:-}" == "pack-cover" ]]; then
        pack_cover_reality
    else
        echo "Usage: gowave-node-auto.sh <command> [args]"
    fi
fi

