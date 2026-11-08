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
    # 1. TCP MTU Probing and kernel BBR / FQ tuning
    mkdir -p /etc/sysctl.d
    cat > /etc/sysctl.d/99-gowave-node.conf <<'EOF'
# Managed by GoWave Auto NGINX
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_mtu_probing = 1
fs.file-max = 1048576
EOF
    sysctl -p /etc/sysctl.d/99-gowave-node.conf 2>/dev/null || true

    # 2. Swap allocation if <= 1GB RAM on KVM
    local mem_kb
    mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
    if [ "$mem_kb" -le 1048576 ] && [ "$mem_kb" -gt 0 ] && ! swapon --show 2>/dev/null | grep -q .; then
        dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none
        chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile || true
        grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi
}

configure_firewall() {
    # Enforce UFW rules: whitelist PANEL_IP for NODE_PORT, open 80/443
    ufw allow 80/tcp comment "HTTP ACME challenge" || true
    ufw allow 443/tcp comment "HTTPS and Xray Stream" || true
    if [ -n "${PANEL_IP:-}" ]; then
        ufw allow proto tcp from "$PANEL_IP" to any port "$NODE_PORT" comment "GoWave Control Plane IPv4" || true
    fi
    if [ -n "${PANEL_IPV6:-}" ]; then
        ufw allow proto tcp from "$PANEL_IPV6" to any port "$NODE_PORT" comment "GoWave Control Plane IPv6" || true
    fi
    ufw --force enable || true
}

unpack_cover_reality() {
    mkdir -p /var/www/gowave-auto-nginx/cover-reality
    echo "$COVER_REALITY_B64" | base64 -d | tar -xzf - -C /var/www/gowave-auto-nginx/cover-reality
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
    nginx -t -q && systemctl reload nginx || systemctl restart nginx || true

    certbot certonly --webroot -w /var/www/gowave-acme \
        -d "$WORKER_DOMAIN" --cert-name "$WORKER_DOMAIN" \
        --non-interactive --agree-tos -m "$ADMIN_EMAIL" --keep-until-expiring || true

    certbot certonly --webroot -w /var/www/gowave-acme \
        -d "$REALITY_DOMAIN" --cert-name "$REALITY_DOMAIN" \
        --non-interactive --agree-tos -m "$ADMIN_EMAIL" --keep-until-expiring || true

    rm -f /etc/nginx/conf.d/00-bootstrap-worker-acme.conf

    # Hook top-level stream if missing
    if ! grep -q 'stream-enabled' /etc/nginx/nginx.conf; then
        sed -i '/events {/i stream { include /etc/nginx/stream-enabled/*.conf; }' /etc/nginx/nginx.conf || \
        echo "stream { include /etc/nginx/stream-enabled/*.conf; }" >> /etc/nginx/nginx.conf
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

    nginx -t -q && systemctl reload nginx || systemctl restart nginx || true
}

run_upstream_node_installer() {
    local tmp_inst
    tmp_inst=$(mktemp "/tmp/gowave-node-install-XXXXXX.sh")
    curl -fsSL https://raw.githubusercontent.com/aaaSaZaN/gowave-node/main/install.sh -o "$tmp_inst"
    chmod 0700 "$tmp_inst"
    bash "$tmp_inst" </dev/null
    rm -f "$tmp_inst"

    # Configure drop-in for NODE_PORT
    mkdir -p /etc/systemd/system/gowave-node.service.d
    cat > /etc/systemd/system/gowave-node.service.d/10-port.conf <<EOF
[Service]
Environment="NODE_PORT=$NODE_PORT"
EOF
    systemctl daemon-reload
    systemctl restart gowave-node.service
}
RUNNER_FUNCS

        # 3. Main entrypoint executed remotely
        cat <<'REMOTE_EOF'
set -euo pipefail
main() {
    umask 077
    trap 'unset _NODE_SECRET_KEY SECRET_KEY' EXIT HUP INT TERM
    setup_system_prereqs </dev/null
    configure_host_security </dev/null
    configure_firewall </dev/null
    umask 022
    unpack_cover_reality </dev/null
    configure_edge_nginx </dev/null
    umask 077
    # Pass secret strictly scoped to upstream installer execution only
    SECRET_KEY="$_NODE_SECRET_KEY" run_upstream_node_installer </dev/null
    unset _NODE_SECRET_KEY SECRET_KEY
    echo "GoWave Edge Worker deployment complete."
}
main "$@" </dev/null
REMOTE_EOF
    } | ssh -T -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=15 -p "$port" "${ssh_user}@${host}" 'bash -s'
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ "${1:-}" == "pack-cover" ]]; then
        pack_cover_reality
    else
        echo "Usage: gowave-node-auto.sh <command> [args]"
    fi
fi
