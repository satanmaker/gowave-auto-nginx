#!/usr/bin/env bash
# modules/nginx.sh - NGINX Stream SNI demultiplexing, TLS termination, and camouflage fallback
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -f "$SCRIPT_DIR/modules/os.sh" ]]; then
    source "$SCRIPT_DIR/modules/os.sh"
fi

ACME_WEBROOT="${ACME_WEBROOT:-/var/www/gowave-acme}"
COVER_REALITY_ROOT="${COVER_REALITY_ROOT:-/var/www/gowave-auto-nginx/cover-reality}"
DECOY_ACCESS_LOG="${DECOY_ACCESS_LOG:-/var/log/nginx/gowave-decoy-access.log}"

ensure_nginx_stream_block() {
    local nginx_conf="${1:-/etc/nginx/nginx.conf}"
    if [[ ! -f "$nginx_conf" ]]; then
        return 0
    fi

    # Remove default site if present to avoid port 80 default_server conflicts
    if [[ "$(id -u)" -eq 0 ]] || [[ -w "/etc/nginx/sites-enabled" ]]; then
        if [[ -e /etc/nginx/sites-enabled/default ]]; then
            rm -f /etc/nginx/sites-enabled/default
        fi
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
    if [[ "$(id -u)" -eq 0 ]] || [[ -w "/etc/nginx/modules-enabled" ]]; then
        if [[ -d /etc/nginx/modules-enabled ]] && [[ ! -f /etc/nginx/modules-enabled/50-mod-stream.conf ]]; then
            if [[ -f /usr/lib/nginx/modules/ngx_stream_module.so ]]; then
                echo "load_module modules/ngx_stream_module.so;" > /etc/nginx/modules-enabled/50-mod-stream.conf
            fi
        fi
    fi
}

generate_stream_config() {
    local panel_domain="$1"
    local reality_domain="$2"
    local out_file="${3:-/etc/nginx/stream-enabled/gowave-stream.conf}"
    local if_inet6="${4:-/proc/net/if_inet6}"
    local vision_domain="${5:-${VISION_DOMAIN:-}}"

    mkdir -p "$(dirname "$out_file")"

    local listen_v6=""
    if check_kernel_ipv6 "$if_inet6" 2>/dev/null; then
        listen_v6="listen [::]:443 so_keepalive=on;"
    fi

    local vision_entry=""
    if [[ -n "$vision_domain" ]]; then
        vision_entry="    $vision_domain 127.0.0.1:8444;"
    fi

    cat > "$out_file" <<EOF
# Managed by GoWave Auto NGINX: Port 443 Stream SNI Router
map \$ssl_preread_server_name \$sni_backend {
    $panel_domain 127.0.0.1:7443;
    $reality_domain 127.0.0.1:8443;
$vision_entry
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
    local vision_domain="${5:-}"

    mkdir -p "$(dirname "$out_file")"
    if [[ "$(id -u)" -eq 0 ]] || [[ -w "/var/www" ]]; then
        mkdir -p "$ACME_WEBROOT"
        chmod 0755 "$ACME_WEBROOT" 2>/dev/null || true
    fi

    local listen_v6=""
    if check_kernel_ipv6 "$if_inet6" 2>/dev/null; then
        listen_v6="listen [::]:80;"
    fi

    local server_names="$panel_domain $reality_domain"
    if [[ -n "$vision_domain" ]]; then
        server_names="$server_names $vision_domain"
    fi

    cat > "$out_file" <<EOF
# Managed by GoWave Auto NGINX: Bootstrap ACME
server {
    listen 80;
    $listen_v6
    server_name $server_names;

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
    local vision_domain="${5:-}"

    mkdir -p "$(dirname "$out_file")"
    if [[ "$(id -u)" -eq 0 ]] || [[ -w "/var/www" ]]; then
        mkdir -p "$ACME_WEBROOT"
        chmod 0755 "$ACME_WEBROOT" 2>/dev/null || true
    fi

    local listen_v6=""
    if check_kernel_ipv6 "$if_inet6" 2>/dev/null; then
        listen_v6="listen [::]:80;"
    fi

    local server_names="$panel_domain $reality_domain"
    local redirect_regex="${panel_domain}|${reality_domain}"
    if [[ -n "$vision_domain" ]]; then
        server_names="$server_names $vision_domain"
        redirect_regex="${redirect_regex}|${vision_domain}"
    fi

    cat > "$out_file" <<EOF
# Managed by GoWave Auto NGINX: Port 80 ACME Challenge & Redirects
server {
    listen 80 default_server;
    $listen_v6
    server_name $server_names;

    location /.well-known/acme-challenge/ {
        root $ACME_WEBROOT;
    }

    location / {
        if (\$host ~* ^(${redirect_regex})\$) {
            return 301 https://\$host\$request_uri;
        }
        return 444;
    }
}
EOF
    echo "Generated $out_file."
}

verify_acme_certificate() {
    local domain="$1"
    local live_dir="${2:-/etc/letsencrypt/live/$domain}"

    local fullchain="$live_dir/fullchain.pem"
    local privkey="$live_dir/privkey.pem"

    if [[ ! -s "$fullchain" ]]; then
        echo "Error: Certificate fullchain missing or empty: $fullchain" >&2
        return 1
    fi
    if [[ ! -s "$privkey" ]]; then
        echo "Error: Private key missing or empty: $privkey" >&2
        return 1
    fi

    # Check certificate validity, hostname/SAN and remaining lifetime.
    if ! openssl x509 -checkend 86400 -noout -in "$fullchain" >/dev/null 2>&1; then
        echo "Error: Certificate $fullchain is expired or not valid within 24 hours" >&2
        return 1
    fi
    # OpenSSL builds differ in whether -checkhost reports a mismatch via
    # the exit status. Inspect the explicit result text as well, and fail
    # closed unless the requested hostname is positively confirmed.
    local host_check
    if ! host_check=$(openssl x509 -checkhost "$domain" -noout -in "$fullchain" 2>&1); then
        echo "Error: Certificate SAN/CN does not cover $domain." >&2
        return 1
    fi
    if [[ "$host_check" != "Hostname $domain does match certificate" ]]; then
        echo "Error: Certificate SAN/CN does not cover $domain." >&2
        return 1
    fi

    # Check certificate cryptographically matches private key
    local cert_pk
    local key_pk
    cert_pk=$(openssl x509 -noout -pubkey -in "$fullchain" 2>/dev/null || true)
    key_pk=$(openssl pkey -pubout -in "$privkey" 2>/dev/null || true)
    if [[ -z "$cert_pk" || "$cert_pk" != "$key_pk" ]]; then
        echo "Error: Certificate and private key do not cryptographically match for $domain" >&2
        return 1
    fi

    echo "ACME certificate verification PASSED for $domain."
    return 0
}

# Retained strictly for mock / offline testing harness environments
ensure_tls_cert() {
    local domain="$1"
    local live_dir="${2:-/etc/letsencrypt/live/$domain}"
    if [[ ! -f "$live_dir/fullchain.pem" || ! -f "$live_dir/privkey.pem" ]]; then
        echo "Creating self-signed test TLS certificate for mock environment: $domain..."
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
    local cover_root="${4:-$COVER_REALITY_ROOT}"

    mkdir -p "$(dirname "$out_file")"
    if [[ "$(id -u)" -eq 0 ]] || [[ -w "/var/www" ]] || [[ -w "$(dirname "$cover_root")" ]] || [[ -d "$cover_root" && -w "$cover_root" ]]; then
        mkdir -p "$cover_root" 2>/dev/null || true
        if [[ -d "$cover_root" && -w "$cover_root" && -d "$SCRIPT_DIR/assets/cover-sites/cover-reality" ]]; then
            cp -r "$SCRIPT_DIR/assets/cover-sites/cover-reality/." "$cover_root/"
            chmod -R 0755 "$cover_root" 2>/dev/null || true
        fi
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

    root $cover_root;
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

generate_vision_fallback_vhost() {
    local vision_domain="$1"
    local out_file="${2:-/etc/nginx/conf.d/gowave-vision-fallback.conf}"
    local cover_root="${3:-$COVER_REALITY_ROOT}"

    mkdir -p "$(dirname "$out_file")"
    if [[ "$(id -u)" -eq 0 ]] || [[ -w "/var/www" ]] || [[ -w "$(dirname "$cover_root")" ]] || [[ -d "$cover_root" && -w "$cover_root" ]]; then
        mkdir -p "$cover_root" 2>/dev/null || true
        if [[ -d "$cover_root" && -w "$cover_root" && -d "$SCRIPT_DIR/assets/cover-sites/cover-reality" ]]; then
            cp -r "$SCRIPT_DIR/assets/cover-sites/cover-reality/." "$cover_root/"
            chmod -R 0755 "$cover_root" 2>/dev/null || true
        fi
    fi

    cat > "$out_file" <<EOF
# Managed by GoWave Auto NGINX: VLESS XTLS Vision Fallback Cover Site
server {
    listen 127.0.0.1:9444 proxy_protocol;
    server_name $vision_domain;
    server_tokens off;

    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

    root $cover_root;
    index index.html;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF
    echo "Generated $out_file."
}

verify_deploy_hook_preflight() {
    local hook_file="${1:-/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh}"
    local transaction_id="${2:-}"
    local recovery_root="${3:-/var/lib/gowave-auto-nginx/recovery}"

    if [[ -e "$hook_file" ]] || [[ -L "$hook_file" ]]; then
        if [[ -n "$transaction_id" ]]; then
            local manifest="${recovery_root}/${transaction_id}/deploy-hook-manifest.json"
            if [[ -f "$manifest" ]]; then
                local owned
                owned=$(python3 -c "import json; print('1' if json.load(open('$manifest')).get('created_by_tx') else '0')" 2>/dev/null || echo "0")
                if [[ "$owned" == "1" ]]; then
                    return 0
                fi
            fi
        fi
        echo "Error: Pre-existing unowned Certbot deploy hook found at $hook_file. Refusing to overwrite unmanaged host resource." >&2
        return 1
    fi

    local hook_dir
    hook_dir=$(dirname "$hook_file")
    if [[ -e "$hook_dir" && -L "$hook_dir" ]]; then
        echo "Error: Certbot renewal hook directory $hook_dir is an unsafe symlink." >&2
        return 1
    fi
    return 0
}

install_managed_deploy_hook() {
    local transaction_id="$1"
    local hook_file="${2:-/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh}"
    local recovery_root="${3:-/var/lib/gowave-auto-nginx/recovery}"

    verify_deploy_hook_preflight "$hook_file" "$transaction_id" "$recovery_root" || return 1

    local hook_dir
    hook_dir=$(dirname "$hook_file")
    mkdir -p "$hook_dir"
    chmod 0755 "$hook_dir" 2>/dev/null || true

    local snap_dir="${recovery_root}/${transaction_id}"
    mkdir -p "$snap_dir"
    chmod 0700 "$snap_dir" 2>/dev/null || true
    local manifest="${snap_dir}/deploy-hook-manifest.json"

    local tmp_file="${hook_file}.tmp.$$"
    cat > "$tmp_file" <<'EOF'
#!/bin/sh
# Managed by GoWave Auto NGINX: Automated ACME Reload Hook
if nginx -t -q; then
    systemctl reload nginx
fi
EOF
    chmod 0755 "$tmp_file"
    sync "$tmp_file"
    mv -f "$tmp_file" "$hook_file"
    sync "$hook_dir"

    local digest
    digest=$(sha256sum "$hook_file" | awk '{print $1}')
    python3 - "$manifest" "$transaction_id" "$hook_file" "$digest" <<'PY'
import json, sys
manifest_path, tx_id, path, digest = sys.argv[1:5]
data = {
    "transaction_id": tx_id,
    "path": path,
    "created_by_tx": True,
    "sha256": digest
}
with open(manifest_path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
PY
    chmod 0600 "$manifest" 2>/dev/null || true
    echo "Configured managed ACME renewal hook in $hook_file."
}

rollback_managed_deploy_hook() {
    local transaction_id="$1"
    local hook_file="${2:-/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh}"
    local recovery_root="${3:-/var/lib/gowave-auto-nginx/recovery}"

    local manifest="${recovery_root}/${transaction_id}/deploy-hook-manifest.json"
    if [[ ! -f "$manifest" ]]; then
        return 0
    fi

    local created_by_tx recorded_sha
    created_by_tx=$(python3 -c "import json; print('1' if json.load(open('$manifest')).get('created_by_tx') else '0')" 2>/dev/null || echo "0")
    recorded_sha=$(python3 -c "import json; print(json.load(open('$manifest')).get('sha256', ''))" 2>/dev/null || echo "")

    if [[ "$created_by_tx" != "1" ]]; then
        return 0
    fi

    if [[ ! -e "$hook_file" && ! -L "$hook_file" ]]; then
        return 0
    fi

    if [[ -L "$hook_file" ]]; then
        echo "Warning: Deploy hook $hook_file is now a symlink; preserving modified object and reporting incomplete recovery." >&2
        return 1
    fi

    if [[ ! -f "$hook_file" ]]; then
        echo "Warning: Deploy hook $hook_file is not a regular file; preserving modified object and reporting incomplete recovery." >&2
        return 1
    fi

    local current_sha
    current_sha=$(sha256sum "$hook_file" | awk '{print $1}')
    if [[ "$current_sha" != "$recorded_sha" ]]; then
        echo "Warning: Deploy hook $hook_file was modified after installation (digest mismatch); preserving modified object and reporting incomplete recovery." >&2
        return 1
    fi

    rm -f "$hook_file"
    sync "$(dirname "$hook_file")"
    return 0
}

cleanup_deploy_hook_manifest() {
    local transaction_id="$1"
    local recovery_root="${2:-/var/lib/gowave-auto-nginx/recovery}"
    rm -f "${recovery_root}/${transaction_id}/deploy-hook-manifest.json"
}

configure_certbot_deploy_hook() {
    local tx_id="${1:-master_install}"
    local hook_dir="/etc/letsencrypt/renewal-hooks/deploy"
    local hook_file="$hook_dir/gowave-nginx.sh"

    install_managed_deploy_hook "$tx_id" "$hook_file"
}

validate_acme_server() {
    local server="${1:-}"
    if [[ -z "$server" ]]; then
        return 0
    fi
    if [[ "$server" != "https://acme-staging-v02.api.letsencrypt.org/directory" && \
          "$server" != "https://acme-v02.api.letsencrypt.org/directory" ]]; then
        echo "Error: Invalid GOWAVE_ACME_SERVER: '$server'. Only 'https://acme-staging-v02.api.letsencrypt.org/directory' or 'https://acme-v02.api.letsencrypt.org/directory' are supported." >&2
        return 1
    fi
    return 0
}

check_acme_lineage() {
    local domain="$1"
    local target_server="${2:-https://acme-v02.api.letsencrypt.org/directory}"
    local renewal_conf="${3:-/etc/letsencrypt/renewal/${domain}.conf}"
    local live_dir="${4:-/etc/letsencrypt/live/${domain}}"

    if [[ -f "$renewal_conf" ]]; then
        local existing_server=""
        while IFS='=' read -r key val || [[ -n "$key" ]]; do
            key=$(echo "$key" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
            if [[ "$key" == "server" ]]; then
                existing_server=$(echo "$val" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
                break
            fi
        done < "$renewal_conf"

        if [[ -z "$existing_server" ]]; then
            echo "Error: Existing renewal lineage for $domain has no readable 'server' field in $renewal_conf; failing closed to prevent cross-lineage staging/production reuse." >&2
            return 1
        fi

        if [[ "$existing_server" != "https://acme-staging-v02.api.letsencrypt.org/directory" && \
              "$existing_server" != "https://acme-v02.api.letsencrypt.org/directory" ]]; then
            echo "Error: Existing renewal lineage for $domain uses unrecognized ACME directory: '$existing_server'." >&2
            return 1
        fi

        if [[ "$existing_server" != "$target_server" ]]; then
            echo "Error: ACME directory mismatch for $domain: existing lineage in $renewal_conf was issued by '$existing_server', but requested server is '$target_server'. Staging and production lineages cannot be mixed." >&2
            return 1
        fi
    fi

    local fullchain="$live_dir/fullchain.pem"
    if [[ -s "$fullchain" ]]; then
        local issuer
        issuer=$(openssl x509 -in "$fullchain" -noout -issuer 2>/dev/null || true)
        local is_staging_cert=0
        if [[ "$issuer" =~ \(STAGING\) ]]; then
            is_staging_cert=1
        fi
        if [[ "$target_server" == "https://acme-staging-v02.api.letsencrypt.org/directory" && "$is_staging_cert" -eq 0 ]]; then
            echo "Error: Existing certificate for $domain was issued by production ($issuer), but requested ACME server is staging ($target_server)." >&2
            return 1
        elif [[ "$target_server" == "https://acme-v02.api.letsencrypt.org/directory" && "$is_staging_cert" -eq 1 ]]; then
            echo "Error: Existing certificate for $domain was issued by staging ($issuer), but requested ACME server is production ($target_server)." >&2
            return 1
        fi
    fi

    return 0
}

snapshot_acme_lineage() {
    local transaction_id="$1"
    local domain="$2"
    local recovery_root="${3:-/var/lib/gowave-auto-nginx/recovery}"
    local letsencrypt_root="${4:-/etc/letsencrypt}"

    local snap_dir="${recovery_root}/${transaction_id}/acme/${domain}"
    mkdir -p "$snap_dir"
    chmod 0700 "$snap_dir" 2>/dev/null || true

    local renewal_conf="${letsencrypt_root}/renewal/${domain}.conf"
    local live_dir="${letsencrypt_root}/live/${domain}"
    local meta_file="${snap_dir}/lineage-manifest.json"

    if [[ -f "$renewal_conf" || -d "$live_dir" ]]; then
        mkdir -p "$snap_dir/archive" "$snap_dir/live"
        chmod 0700 "$snap_dir/archive" "$snap_dir/live" 2>/dev/null || true

        if [[ -f "$renewal_conf" ]]; then
            cp -p "$renewal_conf" "$snap_dir/renewal.conf"
        fi

        local cert_serial=""
        local cert_fingerprint=""
        if [[ -d "$live_dir" ]]; then
            local f
            for f in cert.pem chain.pem fullchain.pem privkey.pem; do
                local link_path="${live_dir}/${f}"
                if [[ -L "$link_path" ]]; then
                    local target
                    target=$(readlink "$link_path")
                    echo "$target" > "$snap_dir/live/${f}.target"
                    local real_file
                    real_file=$(realpath -q "$link_path" || true)
                    if [[ -n "$real_file" && -f "$real_file" ]]; then
                        local bn
                        bn=$(basename "$real_file")
                        cp -p "$real_file" "$snap_dir/archive/$bn"
                        if [[ "$f" == "privkey.pem" || "$bn" =~ ^privkey ]]; then
                            chmod 0600 "$snap_dir/archive/$bn" 2>/dev/null || true
                        fi
                    fi
                elif [[ -f "$link_path" ]]; then
                    cp -p "$link_path" "$snap_dir/live/$f"
                    if [[ "$f" == "privkey.pem" ]]; then
                        chmod 0600 "$snap_dir/live/$f" 2>/dev/null || true
                    fi
                fi
            done

            local fc="${live_dir}/fullchain.pem"
            if [[ -s "$fc" ]]; then
                cert_serial=$(openssl x509 -in "$fc" -noout -serial 2>/dev/null || true)
                cert_fingerprint=$(openssl x509 -in "$fc" -noout -fingerprint -sha256 2>/dev/null || true)
            fi
        fi

        python3 - "$meta_file" "$domain" "$cert_serial" "$cert_fingerprint" <<'PY'
import json, sys
meta_file, domain, serial, fingerprint = sys.argv[1:5]
data = {
    "domain": domain,
    "existed_before": True,
    "serial": serial,
    "fingerprint": fingerprint
}
with open(meta_file, "w") as f:
    json.dump(data, f, indent=2)
PY
    else
        python3 - "$meta_file" "$domain" <<'PY'
import json, sys
meta_file, domain = sys.argv[1:3]
data = {
    "domain": domain,
    "existed_before": False
}
with open(meta_file, "w") as f:
    json.dump(data, f, indent=2)
PY
    fi
}

restore_acme_lineage() {
    local transaction_id="$1"
    local domain="$2"
    local recovery_root="${3:-/var/lib/gowave-auto-nginx/recovery}"
    local letsencrypt_root="${4:-/etc/letsencrypt}"

    local snap_dir="${recovery_root}/${transaction_id}/acme/${domain}"
    local meta_file="${snap_dir}/lineage-manifest.json"

    if [[ ! -f "$meta_file" ]]; then
        echo "Error: ACME lineage manifest not found for $domain in $snap_dir" >&2
        return 1
    fi

    local existed
    existed=$(python3 - "$meta_file" "$domain" <<'PY'
import json, sys
path, domain = sys.argv[1:3]
with open(path, encoding="utf-8") as stream:
    data = json.load(stream)
if not isinstance(data, dict) or data.get("domain") != domain or type(data.get("existed_before")) is not bool:
    raise SystemExit(1)
print("1" if data["existed_before"] else "0")
PY
) || { echo "Error: Invalid ACME lineage manifest for $domain" >&2; return 1; }
if [[ "$existed" != "0" && "$existed" != "1" ]]; then
    echo "Error: Invalid existed_before marker for $domain" >&2
    return 1
fi

    local renewal_conf="${letsencrypt_root}/renewal/${domain}.conf"
    local live_dir="${letsencrypt_root}/live/${domain}"
    local archive_dir="${letsencrypt_root}/archive/${domain}"

    if [[ "$existed" == "0" ]]; then
        echo "Removing transaction-created ACME lineage for $domain..." >&2
        rm -f "$renewal_conf" || { echo "Error: Could not remove transaction-created renewal config for $domain" >&2; return 1; }
        rm -rf "$live_dir" "$archive_dir" || { echo "Error: Could not remove transaction-created lineage for $domain" >&2; return 1; }
        return 0
    fi

    echo "Restoring pre-existing ACME lineage for $domain from snapshot..." >&2
    mkdir -p "${letsencrypt_root}/renewal" "$live_dir" "$archive_dir" || { echo "Error: Could not create ACME restore directories for $domain" >&2; return 1; }
    chmod 0755 "${letsencrypt_root}/renewal" "$live_dir" "$archive_dir" 2>/dev/null || { echo "Error: Could not set ACME directory permissions for $domain" >&2; return 1; }

    if [[ -f "$snap_dir/renewal.conf" ]]; then
        cp -p "$snap_dir/renewal.conf" "$renewal_conf" || { echo "Error: Could not restore renewal config for $domain" >&2; return 1; }
        chmod 0644 "$renewal_conf" 2>/dev/null || { echo "Error: Could not set renewal config permissions for $domain" >&2; return 1; }
    fi

    if [[ -d "$snap_dir/archive" ]]; then
        local arc
        for arc in "$snap_dir/archive"/*; do
            [[ -f "$arc" ]] || continue
            local bn
            bn=$(basename "$arc")
            cp -p "$arc" "$archive_dir/$bn" || { echo "Error: Could not restore ACME archive file $bn for $domain" >&2; return 1; }
            if [[ "$bn" =~ ^privkey ]]; then
                chmod 0600 "$archive_dir/$bn" 2>/dev/null || { echo "Error: Could not secure restored private key $bn for $domain" >&2; return 1; }
            else
                chmod 0644 "$archive_dir/$bn" 2>/dev/null || { echo "Error: Could not set restored certificate permissions for $bn ($domain)" >&2; return 1; }
            fi
        done
    fi

    if [[ -d "$snap_dir/live" ]]; then
        local f
        for f in cert.pem chain.pem fullchain.pem privkey.pem; do
            if [[ -f "$snap_dir/live/${f}.target" ]]; then
                local tgt
                tgt=$(cat "$snap_dir/live/${f}.target") || { echo "Error: Could not read ACME symlink target for $f ($domain)" >&2; return 1; }
                ln -sf "$tgt" "$live_dir/$f" || { echo "Error: Could not restore ACME symlink $f for $domain" >&2; return 1; }
            elif [[ -f "$snap_dir/live/$f" ]]; then
                cp -p "$snap_dir/live/$f" "$live_dir/$f" || { echo "Error: Could not restore ACME live file $f for $domain" >&2; return 1; }
                if [[ "$f" == "privkey.pem" ]]; then
                    chmod 0600 "$live_dir/$f" 2>/dev/null || { echo "Error: Could not secure restored live private key for $domain" >&2; return 1; }
                else
                    chmod 0644 "$live_dir/$f" 2>/dev/null || { echo "Error: Could not set restored live certificate permissions for $domain" >&2; return 1; }
                fi
            fi
        done
    fi

    local fullchain="$live_dir/fullchain.pem"
    local privkey="$live_dir/privkey.pem"
    if [[ ! -s "$fullchain" || ! -s "$privkey" ]]; then
        echo "Error: Restored certificate or private key missing for $domain" >&2
        return 1
    fi

    if ! openssl x509 -in "$fullchain" -noout 2>/dev/null; then
        echo "Error: Restored certificate for $domain is corrupted" >&2
        return 1
    fi

    local pub_from_cert pub_from_key
    pub_from_cert=$(openssl x509 -in "$fullchain" -noout -pubkey 2>/dev/null || true)
    pub_from_key=$(openssl pkey -in "$privkey" -pubout 2>/dev/null || true)
    if [[ -z "$pub_from_cert" || "$pub_from_cert" != "$pub_from_key" ]]; then
        echo "Error: Restored certificate and private key public key mismatch for $domain" >&2
        return 1
    fi

    local exp_serial exp_fingerprint cur_serial cur_fingerprint
    exp_serial=$(python3 -c "import json; print(json.load(open('$meta_file', encoding='utf-8')).get('serial', ''))") || { echo "Error: Could not read snapshot certificate serial for $domain" >&2; return 1; }
    exp_fingerprint=$(python3 -c "import json; print(json.load(open('$meta_file', encoding='utf-8')).get('fingerprint', ''))") || { echo "Error: Could not read snapshot certificate fingerprint for $domain" >&2; return 1; }
    if [[ -z "$exp_serial" || -z "$exp_fingerprint" ]]; then
        echo "Error: ACME snapshot is missing certificate identity metadata for $domain" >&2
        return 1
    fi
    if [[ -n "$exp_serial" ]]; then
        cur_serial=$(openssl x509 -in "$fullchain" -noout -serial 2>/dev/null) || { echo "Error: Could not read restored certificate serial for $domain" >&2; return 1; }
        if [[ "$cur_serial" != "$exp_serial" ]]; then
            echo "Error: Restored certificate serial ($cur_serial) does not match snapshot ($exp_serial)" >&2
            return 1
        fi
    fi
    if [[ -n "$exp_fingerprint" ]]; then
        cur_fingerprint=$(openssl x509 -in "$fullchain" -noout -fingerprint -sha256 2>/dev/null) || { echo "Error: Could not read restored certificate fingerprint for $domain" >&2; return 1; }
        if [[ "$cur_fingerprint" != "$exp_fingerprint" ]]; then
            echo "Error: Restored certificate fingerprint ($cur_fingerprint) does not match snapshot ($exp_fingerprint)" >&2
            return 1
        fi
    fi

    echo "ACME lineage for $domain successfully restored and verified." >&2
    return 0
}

cleanup_acme_snapshot() {
    local transaction_id="$1"
    local domain="$2"
    local recovery_root="${3:-/var/lib/gowave-auto-nginx/recovery}"

    local snap_dir="${recovery_root}/${transaction_id}/acme/${domain}"
    if [[ -d "$snap_dir" ]]; then
        rm -rf "$snap_dir"
    fi
}
