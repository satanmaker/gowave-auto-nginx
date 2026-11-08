#!/usr/bin/env bash
# modules/nginx.sh - NGINX Stream SNI demultiplexing, TLS termination, and camouflage fallback
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -f "$SCRIPT_DIR/modules/os.sh" ]]; then
    source "$SCRIPT_DIR/modules/os.sh"
fi

ACME_WEBROOT="/var/www/gowave-acme"
COVER_REALITY_ROOT="/var/www/gowave-auto-nginx/cover-reality"
DECOY_ACCESS_LOG="/var/log/nginx/gowave-decoy-access.log"

ensure_nginx_stream_block() {
    local nginx_conf="${1:-/etc/nginx/nginx.conf}"
    if [[ ! -f "$nginx_conf" ]]; then
        return 0
    fi

    # Remove default site if present to avoid port 80 default_server conflicts
    if [[ -e /etc/nginx/sites-enabled/default ]]; then
        rm -f /etc/nginx/sites-enabled/default
    fi

    if [[ "$(id -u)" -eq 0 ]] || [[ -w "/etc/nginx" ]]; then
        mkdir -p /etc/nginx/stream-enabled
    fi

    if ! grep -q 'stream-enabled' "$nginx_conf"; then
        echo "Injecting top-level stream block into $nginx_conf..."
        # Wrap outside http {}
        cat >> "$nginx_conf" <<'EOF'

# Managed by GoWave Auto NGINX: Stream SNI Multiplexer
stream {
    include /etc/nginx/stream-enabled/*.conf;
}
EOF
    fi

    # Ensure libnginx-mod-stream is loaded if dynamic modules are used
    if [[ -d /etc/nginx/modules-enabled ]] && [[ ! -f /etc/nginx/modules-enabled/50-mod-stream.conf ]]; then
        if [[ -f /usr/lib/nginx/modules/ngx_stream_module.so ]]; then
            echo "load_module modules/ngx_stream_module.so;" > /etc/nginx/modules-enabled/50-mod-stream.conf
        fi
    fi
}

generate_stream_config() {
    local panel_domain="$1"
    local reality_domain="$2"
    local out_file="${3:-/etc/nginx/stream-enabled/gowave-stream.conf}"
    local if_inet6="${4:-/proc/net/if_inet6}"

    mkdir -p "$(dirname "$out_file")"

    local listen_v6=""
    if check_kernel_ipv6 "$if_inet6" 2>/dev/null; then
        listen_v6="listen [::]:443 so_keepalive=on;"
    fi

    cat > "$out_file" <<EOF
# Managed by GoWave Auto NGINX: Port 443 Stream SNI Router
map \$ssl_preread_server_name \$sni_backend {
    $panel_domain 127.0.0.1:7443;
    $reality_domain 127.0.0.1:8443;
    default 127.0.0.1:8443;
}

server {
    listen 443 so_keepalive=on;
    $listen_v6
    ssl_preread on;
    proxy_protocol on;
    proxy_timeout 1h;
    proxy_connect_timeout 5s;
    proxy_pass \$sni_backend;
}
EOF
    echo "Generated $out_file."
}

generate_bootstrap_acme_vhost() {
    local panel_domain="$1"
    local reality_domain="$2"
    local out_file="${3:-/etc/nginx/conf.d/00-bootstrap-acme.conf}"
    local if_inet6="${4:-/proc/net/if_inet6}"

    mkdir -p "$(dirname "$out_file")"
    if [[ "$(id -u)" -eq 0 ]] || [[ -w "/var/www" ]]; then
        mkdir -p "$ACME_WEBROOT"
        chmod 0755 "$ACME_WEBROOT" 2>/dev/null || true
    fi

    local listen_v6=""
    if check_kernel_ipv6 "$if_inet6" 2>/dev/null; then
        listen_v6="listen [::]:80;"
    fi

    cat > "$out_file" <<EOF
# Managed by GoWave Auto NGINX: Bootstrap ACME
server {
    listen 80;
    $listen_v6
    server_name $panel_domain $reality_domain;

    location /.well-known/acme-challenge/ {
        root $ACME_WEBROOT;
    }

    location / {
        return 444;
    }
}
EOF
}

generate_production_http_vhost() {
    local panel_domain="$1"
    local reality_domain="$2"
    local out_file="${3:-/etc/nginx/conf.d/gowave-http.conf}"
    local if_inet6="${4:-/proc/net/if_inet6}"

    mkdir -p "$(dirname "$out_file")"
    if [[ "$(id -u)" -eq 0 ]] || [[ -w "/var/www" ]]; then
        mkdir -p "$ACME_WEBROOT"
        chmod 0755 "$ACME_WEBROOT" 2>/dev/null || true
    fi

    local listen_v6=""
    if check_kernel_ipv6 "$if_inet6" 2>/dev/null; then
        listen_v6="listen [::]:80;"
    fi

    cat > "$out_file" <<EOF
# Managed by GoWave Auto NGINX: Port 80 ACME Challenge & Redirects
server {
    listen 80 default_server;
    $listen_v6
    server_name $panel_domain $reality_domain;

    location /.well-known/acme-challenge/ {
        root $ACME_WEBROOT;
    }

    location / {
        if (\$host ~* ^(${panel_domain}|${reality_domain})\$) {
            return 301 https://\$host\$request_uri;
        }
        return 444;
    }
}
EOF
    echo "Generated $out_file."
}

ensure_tls_cert() {
    local domain="$1"
    local live_dir="/etc/letsencrypt/live/$domain"
    if [[ ! -f "$live_dir/fullchain.pem" || ! -f "$live_dir/privkey.pem" ]]; then
        echo "Creating self-signed fallback TLS certificate for $domain..."
        mkdir -p "$live_dir"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$live_dir/privkey.pem" \
            -out "$live_dir/fullchain.pem" \
            -subj "/CN=$domain" 2>/dev/null || true
    fi
}

generate_panel_https_vhost() {
    local panel_domain="$1"
    local out_file="${2:-/etc/nginx/conf.d/gowave-panel.conf}"
    local nginx_bin="${3:-nginx}"

    mkdir -p "$(dirname "$out_file")"
    local listen_directive
    listen_directive=$(render_nginx_listen_ssl_http2 "127.0.0.1:7443" "proxy_protocol" "$nginx_bin")

    cat > "$out_file" <<EOF
# Managed by GoWave Auto NGINX: Panel HTTPS Listener & Transports
server {
    $listen_directive
    server_name $panel_domain;

    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

    ssl_certificate /etc/letsencrypt/live/$panel_domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$panel_domain/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Subscriptions: headers preserved, User-Agent preserved, cache disabled
    location ^~ /api/sub/ {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header User-Agent \$http_user_agent;
        add_header Cache-Control "no-store, no-cache, must-revalidate, max-age=0";
    }

    # GoWave REST API
    location ^~ /api/ {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    # GoWave Web UI Frontend
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    # Inbound: VLESS XHTTP TLS
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
        access_log off;
    }

    # Inbound: VLESS WebSocket TLS
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
        access_log off;
    }

    # Inbound: Trojan gRPC TLS
    location /trojan-grpc {
        grpc_pass grpc://127.0.0.1:10003;
        grpc_read_timeout 1h;
        grpc_send_timeout 1h;
        client_body_timeout 1h;
    }
}
EOF
    echo "Generated $out_file."
}

generate_decoy_vhost() {
    local reality_domain="$1"
    local out_file="${2:-/etc/nginx/conf.d/gowave-decoy.conf}"
    local nginx_bin="${3:-nginx}"

    mkdir -p "$(dirname "$out_file")"
    if [[ "$(id -u)" -eq 0 ]] || [[ -w "/var/www" ]]; then
        mkdir -p "$COVER_REALITY_ROOT"
    fi
    local listen_directive
    listen_directive=$(render_nginx_listen_ssl_http2 "127.0.0.1:9443" "proxy_protocol" "$nginx_bin")

    cat > "$out_file" <<EOF
# Managed by GoWave Auto NGINX: REALITY Fallback Camouflage Decoy
server {
    $listen_directive
    server_name $reality_domain;

    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

    ssl_protocols TLSv1.3;
    ssl_certificate /etc/letsencrypt/live/$reality_domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$reality_domain/privkey.pem;

    root $COVER_REALITY_ROOT;
    index index.html;

    # Dedicated probe security audit log recording PROXY-restored remote_addr
    access_log $DECOY_ACCESS_LOG combined;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF
    echo "Generated $out_file."
}

configure_certbot_deploy_hook() {
    local hook_dir="/etc/letsencrypt/renewal-hooks/deploy"
    local hook_file="$hook_dir/gowave-nginx.sh"

    mkdir -p "$hook_dir"
    cat > "$hook_file" <<'EOF'
#!/bin/sh
# Managed by GoWave Auto NGINX: Automated ACME Reload Hook
if nginx -t -q; then
    systemctl reload nginx
fi
EOF
    chmod 0755 "$hook_file"
    echo "Configured ACME renewal hook in $hook_file."
}
