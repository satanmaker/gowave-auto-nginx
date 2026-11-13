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
COVER_ACCENT="${GOWAVE_COVER_ACCENT:-#0f6b5c}"
COVER_ACCENT2="${GOWAVE_COVER_ACCENT2:-#14876f}"
COVER_SOFT="${GOWAVE_COVER_SOFT:-#e7f3ee}"
COVER_HEADLINE="${GOWAVE_COVER_HEADLINE:-Plan the work, keep the context, move on.}"
COVER_LEDE="${GOWAVE_COVER_LEDE:-Projects, notes and next steps in one calm place, with just enough structure to keep everyone oriented.}"

# The cover site is served on the registrable apex of the deployment domain, so
# a browser that reaches for the bare domain lands on a plausible static site
# instead of a certificate error. Only domains with a subdomain part qualify:
# for a two-label deployment domain the apex *is* the public entry point.
derive_cover_domain() {
    local panel_domain="${1:-}"
    local labels
    [[ -n "$panel_domain" ]] || return 0
    IFS='.' read -r -a labels <<< "${panel_domain%.}"
    local count="${#labels[@]}"
    if [[ "$count" -lt 3 ]]; then
        return 0
    fi
    printf '%s.%s\n' "${labels[count - 2]}" "${labels[count - 1]}"
}

# Cover-site brand is the site label of the deployment domain, so the decoy
# names itself after its own domain instead of shipping a placeholder.
cover_brand_from_domain() {
    local domain="${1:-}"
    local labels label word out=""
    [[ -n "$domain" ]] || return 0
    IFS='.' read -r -a labels <<< "${domain%.}"
    local count="${#labels[@]}"
    if [[ "$count" -ge 3 ]]; then
        label="${labels[count - 2]}"
    else
        label="${labels[0]}"
    fi
    label="${label//-/ }"
    for word in $label; do
        out+="${word^} "
    done
    printf '%s\n' "${out% }"
}

# ACME validates the cover domains over port 80 on this host, so they are only
# usable when both records already resolve to its public IPv4 address. Each name
# that does not is printed, one per line, so the refusal can point at the record
# an operator has to fix instead of blaming the pair.
cover_domains_not_resolving() {
    local cover_domain="${1:-}"
    local server_ip="${2:-}"
    local name resolved
    [[ -n "$cover_domain" ]] || return 0
    for name in "$cover_domain" "www.$cover_domain"; do
        resolved=$(getent ahostsv4 "$name" 2>/dev/null | awk 'NR==1 {print $1}')
        if [[ -z "$server_ip" || "$resolved" != "$server_ip" ]]; then
            printf '%s\n' "$name"
        fi
    done
}

cover_domains_resolve_here() {
    local cover_domain="${1:-}"
    local server_ip="${2:-}"
    [[ -n "$cover_domain" && -n "$server_ip" ]] || return 1
    [[ -z "$(cover_domains_not_resolving "$cover_domain" "$server_ip")" ]]
}

# The single cover-site decision: the apex to use on stdout, nothing when the
# decoy stays off, and a reason on stderr either way. A deployment domain
# without a subdomain has no registrable apex to camouflage, so saying so is
# the refusal -- an empty render would leave the operator guessing.
cover_domain_for() {
    local panel_domain="${1:-}"
    local server_ip="${2:-}"
    local cover_domain unresolved
    cover_domain=$(derive_cover_domain "$panel_domain")
    if [[ -z "$cover_domain" ]]; then
        if [[ -n "$panel_domain" ]]; then
            echo "Camouflage apex disabled — $panel_domain has no subdomain, so no cover apex exists." >&2
        fi
        return 0
    fi
    unresolved=$(cover_domains_not_resolving "$cover_domain" "$server_ip")
    if [[ -n "$unresolved" ]]; then
        if [[ "$unresolved" == *$'\n'* ]]; then
            echo "Camouflage apex disabled — ${unresolved//$'\n'/ / } do not resolve to ${server_ip:-this host}, so HTTP-01 would fail." >&2
        else
            echo "Camouflage apex disabled — $unresolved does not resolve to ${server_ip:-this host}, so HTTP-01 would fail." >&2
        fi
        return 0
    fi
    printf '%s\n' "$cover_domain"
}

# Copy the camouflage template into the webroot and substitute its placeholders.
# Files are rewritten through temporary siblings so a reader never sees a
# half-rendered page.
render_cover_site() {
    local cover_root="$1"
    local domain="${2:-}"
    local source_dir="$SCRIPT_DIR/assets/cover-sites/cover-reality"

    [[ -d "$cover_root" ]] || mkdir -p "$cover_root" || return 1
    # The Worker receives the template in its payload instead of a checkout, so
    # a missing source directory means "render what is already in the webroot".
    if [[ -d "$source_dir" ]]; then
        cp -r "$source_dir/." "$cover_root/" || return 1
    fi
    chmod -R 0755 "$cover_root" 2>/dev/null || true

    local brand="${GOWAVE_COVER_BRAND:-}"
    if [[ -z "$brand" ]]; then
        brand=$(cover_brand_from_domain "$domain")
    fi
    brand="${brand//&/}"
    brand="${brand//|/}"

    local file tmp
    while IFS= read -r file; do
        tmp="$file.tmp.$$"
        if ! sed -e "s|{{BRAND}}|$brand|g" \
                 -e "s|{{ACCENT2}}|$COVER_ACCENT2|g" \
                 -e "s|{{ACCENT}}|$COVER_ACCENT|g" \
                 -e "s|{{SOFT}}|$COVER_SOFT|g" \
                 -e "s|{{HOME_HEADLINE}}|$COVER_HEADLINE|g" \
                 -e "s|{{HOME_LEDE}}|$COVER_LEDE|g" \
                 "$file" > "$tmp"; then
            rm -f "$tmp"
            echo "Error: failed to render $file" >&2
            return 1
        fi
        chmod 0644 "$tmp" && mv "$tmp" "$file" || { rm -f "$tmp"; return 1; }
    done < <(find "$cover_root" -type f \( -name '*.html' -o -name '*.css' -o -name '*.svg' \) -print)

    if grep -rq '{{' "$cover_root" --include='*.html' --include='*.css' --include='*.svg'; then
        echo "Error: camouflage site still contains unrendered placeholders under $cover_root" >&2
        return 1
    fi
    echo "Rendered camouflage site for ${domain:-unknown domain} into $cover_root."
}

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
    local cover_domain="${6:-}"

    mkdir -p "$(dirname "$out_file")"

    local listen_v6=""
    if check_kernel_ipv6 "$if_inet6" 2>/dev/null; then
        listen_v6="listen [::]:443 so_keepalive=on;"
    fi

    local vision_entry=""
    if [[ -n "$vision_domain" ]]; then
        vision_entry="    $vision_domain 127.0.0.1:8444;"
    fi

    # The camouflage apex terminates on the decoy listener directly: no reason
    # to expose an Xray fingerprint on a name that is meant to look like a
    # plain static website.
    local cover_entry=""
    if [[ -n "$cover_domain" ]]; then
        cover_entry="    $cover_domain 127.0.0.1:9443;
    www.$cover_domain 127.0.0.1:9443;"
    fi

    cat > "$out_file" <<EOF
# Managed by GoWave Auto NGINX: Port 443 Stream SNI Router
map \$ssl_preread_server_name \$sni_backend {
    $panel_domain 127.0.0.1:7443;
    $reality_domain 127.0.0.1:8443;
$vision_entry
$cover_entry
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
    local cover_domain="${6:-}"

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
    if [[ -n "$cover_domain" ]]; then
        server_names="$server_names $cover_domain www.$cover_domain"
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
    local cover_domain="${6:-}"

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
    if [[ -n "$cover_domain" ]]; then
        local cover_regex="${cover_domain//./\\.}"
        server_names="$server_names $cover_domain www.$cover_domain"
        redirect_regex="${redirect_regex}|${cover_regex}|www\\.${cover_regex}"
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
    local cover_domain="${5:-}"

    mkdir -p "$(dirname "$out_file")"
    if [[ "$(id -u)" -eq 0 ]] || [[ -w "/var/www" ]] || [[ -w "$(dirname "$cover_root")" ]] || [[ -d "$cover_root" && -w "$cover_root" ]]; then
        # The decoy is the visible face of the deployment, so it is always
        # rendered: an unsubstituted template is an obvious tell.
        render_cover_site "$cover_root" "${cover_domain:-$reality_domain}" || return 1
    fi
    local cover_names=""
    if [[ -n "$cover_domain" ]]; then
        cover_names=" $cover_domain www.$cover_domain"
    fi
    local listen_directive
    listen_directive=$(render_nginx_listen_ssl_http2 "127.0.0.1:9443" "proxy_protocol" "$nginx_bin")

    cat > "$out_file" <<EOF
# Managed by GoWave Auto NGINX: REALITY Fallback Camouflage Decoy
server {
    $listen_directive
    server_name $reality_domain$cover_names;

    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

    ssl_protocols TLSv1.3;
    ssl_certificate /etc/letsencrypt/live/$reality_domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$reality_domain/privkey.pem;

    root $cover_root;
    index index.html;
    error_page 404 /404.html;

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
        render_cover_site "$cover_root" "$vision_domain" || return 1
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

deploy_hook_owned_by_prior_transaction() {
    local hook_file="$1"
    local recovery_root="$2"

    if [[ ! -f "$hook_file" || -L "$hook_file" ]]; then
        return 1
    fi
    if [[ ! -d "$recovery_root" || -L "$recovery_root" ]]; then
        return 1
    fi
    local digest
    digest=$(sha256sum -- "$hook_file" 2>/dev/null | awk '{print $1}' || true)
    if [[ -z "$digest" ]]; then
        return 1
    fi
    local manifest
    for manifest in "${recovery_root}"/*/deploy-hook-manifest.json; do
        if [[ ! -f "$manifest" || -L "$manifest" ]]; then
            continue
        fi
        if python3 - "$manifest" "$hook_file" "$digest" <<'PY'
import json
import sys

manifest_path, hook_path, digest = sys.argv[1:4]
try:
    with open(manifest_path, "r", encoding="utf-8") as stream:
        data = json.load(stream)
except Exception:
    raise SystemExit(1)
raise SystemExit(0 if (
    isinstance(data, dict)
    and data.get("created_by_tx") is True
    and data.get("path") == hook_path
    and data.get("sha256") == digest
) else 1)
PY
        then
            return 0
        fi
    done
    return 1
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
        # A repeated install finds the hook an earlier transaction installed. It is
        # only recognised as ours when that transaction recorded this exact path and
        # the file still hashes to what was recorded, so a hook written or edited by
        # someone else stays a refusal rather than a file this product overwrites.
        if deploy_hook_owned_by_prior_transaction "$hook_file" "$recovery_root"; then
            return 0
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

    local hook_dir resolved_hook_dir metadata owner mode
    hook_dir=$(dirname "$hook_file") || return 1
    resolved_hook_dir=$(realpath -m -- "$hook_dir") || {
        echo "Error: Could not resolve Certbot deploy-hook directory." >&2
        return 1
    }
    if [[ "$resolved_hook_dir" != "$hook_dir" ]]; then
        echo "Error: Certbot deploy-hook directory contains a symlink or non-normalized path." >&2
        return 1
    fi
    mkdir -p -- "$hook_dir" || {
        echo "Error: Could not create Certbot deploy-hook directory." >&2
        return 1
    }
    if [[ ! -d "$hook_dir" || -L "$hook_dir" ]]; then
        echo "Error: Certbot deploy-hook directory is not a real directory." >&2
        return 1
    fi
    metadata=$(stat -c '%u:%a' -- "$hook_dir") || {
        echo "Error: Could not verify Certbot deploy-hook directory." >&2
        return 1
    }
    owner="${metadata%%:*}"
    if [[ "$owner" != "$(id -u)" ]]; then
        echo "Error: Certbot deploy-hook directory is not owned by the current user." >&2
        return 1
    fi
    chmod 0755 -- "$hook_dir" || {
        echo "Error: Could not enforce Certbot deploy-hook directory permissions." >&2
        return 1
    }
    metadata=$(stat -c '%u:%a' -- "$hook_dir") || return 1
    owner="${metadata%%:*}"
    mode="${metadata#*:}"
    if [[ "$owner" != "$(id -u)" || "$mode" != "755" ]]; then
        echo "Error: Certbot deploy-hook directory owner or mode verification failed." >&2
        return 1
    fi

    local snap_dir="${recovery_root}/${transaction_id}" resolved_snap_dir
    resolved_snap_dir=$(realpath -m -- "$snap_dir") || {
        echo "Error: Could not resolve deploy-hook recovery directory." >&2
        return 1
    }
    if [[ "$snap_dir" != /* || "$snap_dir" == "/" || "$resolved_snap_dir" != "$snap_dir" ]]; then
        echo "Error: Deploy-hook recovery path is not a normalized absolute path without symlinks." >&2
        return 1
    fi
    mkdir -p -- "$snap_dir" || {
        echo "Error: Could not create deploy-hook recovery directory." >&2
        return 1
    }
    if [[ ! -d "$snap_dir" || -L "$snap_dir" ]]; then
        echo "Error: Deploy-hook recovery path is not a real directory." >&2
        return 1
    fi
    metadata=$(stat -c '%u:%a' -- "$snap_dir") || {
        echo "Error: Could not verify deploy-hook recovery directory." >&2
        return 1
    }
    owner="${metadata%%:*}"
    if [[ "$owner" != "$(id -u)" ]]; then
        echo "Error: Deploy-hook recovery directory is not owned by the current user." >&2
        return 1
    fi
    chmod 0700 -- "$snap_dir" || {
        echo "Error: Could not secure deploy-hook recovery directory." >&2
        return 1
    }
    metadata=$(stat -c '%u:%a' -- "$snap_dir") || return 1
    owner="${metadata%%:*}"
    mode="${metadata#*:}"
    if [[ "$owner" != "$(id -u)" || "$mode" != "700" ]]; then
        echo "Error: Deploy-hook recovery directory owner or mode verification failed." >&2
        return 1
    fi

    local manifest="${snap_dir}/deploy-hook-manifest.json"
    local tmp_file="${hook_file}.tmp.$$"
    if ! cat > "$tmp_file" <<'EOF'
#!/bin/sh
# Managed by GoWave Auto NGINX: Automated ACME Reload Hook
if nginx -t -q; then
    systemctl reload nginx
fi
EOF
    then
        echo "Error: Could not write temporary Certbot deploy hook." >&2
        return 1
    fi
    if ! chmod 0755 -- "$tmp_file" || ! sync "$tmp_file"; then
        rm -f -- "$tmp_file" || true
        echo "Error: Could not secure and sync temporary Certbot deploy hook." >&2
        return 1
    fi

    local digest
    digest=$(sha256sum "$tmp_file" | awk '{print $1}') || {
        rm -f -- "$tmp_file" || true
        echo "Error: Could not calculate Certbot deploy-hook digest." >&2
        return 1
    }
    python3 -c 'import json, os, sys; manifest_path, tx_id, path, digest = sys.argv[1:5]; flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0); fd = os.open(manifest_path, flags, 0o600); stream = os.fdopen(fd, "w", encoding="utf-8"); json.dump({"transaction_id": tx_id, "path": path, "created_by_tx": True, "sha256": digest}, stream, indent=2); stream.flush(); os.fsync(stream.fileno()); stream.close()' "$manifest" "$transaction_id" "$hook_file" "$digest" || {
        rm -f -- "$tmp_file" || true
        echo "Error: Could not create deploy-hook ownership manifest safely." >&2
        return 1
    }
    if ! chmod 0600 -- "$manifest"; then
        rm -f -- "$tmp_file" || true
        echo "Error: Could not enforce private deploy-hook manifest permissions." >&2
        return 1
    fi
    metadata=$(stat -c '%u:%a' -- "$manifest") || {
        rm -f -- "$tmp_file" || true
        echo "Error: Could not verify deploy-hook ownership manifest." >&2
        return 1
    }
    owner="${metadata%%:*}"
    mode="${metadata#*:}"
    if [[ "$owner" != "$(id -u)" || "$mode" != "600" ]]; then
        rm -f -- "$tmp_file" || true
        echo "Error: Deploy-hook manifest owner or mode verification failed." >&2
        return 1
    fi
    sync "$manifest" && sync "$snap_dir" || {
        rm -f -- "$tmp_file" || true
        echo "Error: Could not sync deploy-hook ownership manifest." >&2
        return 1
    }

    mv -f -- "$tmp_file" "$hook_file" || {
        rm -f -- "$tmp_file" || true
        echo "Error: Could not install managed Certbot deploy hook." >&2
        return 1
    }
    sync "$hook_dir" || {
        echo "Error: Could not sync Certbot deploy-hook directory after installation." >&2
        return 1
    }
    echo "Configured managed ACME renewal hook in $hook_file."
}
rollback_managed_deploy_hook() {
    local transaction_id="$1"
    local hook_file="${2:-/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh}"
    local recovery_root="${3:-/var/lib/gowave-auto-nginx/recovery}"

    local manifest="${recovery_root}/${transaction_id}/deploy-hook-manifest.json"
    if [[ ! -e "$manifest" && ! -L "$manifest" ]]; then
        if [[ -e "$hook_file" || -L "$hook_file" ]]; then
            echo "Error: Deploy hook exists without an ownership manifest; refusing to claim rollback succeeded." >&2
            return 1
        fi
        return 0
    fi
    if [[ ! -f "$manifest" || -L "$manifest" ]]; then
        echo "Error: Deploy-hook rollback manifest is missing, non-regular, or a symlink." >&2
        return 1
    fi

    local manifest_data
    manifest_data=$(python3 - "$manifest" "$transaction_id" "$hook_file" <<'PY'
import json
import re
import sys

path, expected_tx, expected_hook = sys.argv[1:4]
try:
    with open(path, "r", encoding="utf-8") as stream:
        data = json.load(stream)
    if not isinstance(data, dict):
        raise ValueError("manifest root must be an object")
    if data.get("transaction_id") != expected_tx or data.get("path") != expected_hook:
        raise ValueError("manifest transaction/path mismatch")
    created = data.get("created_by_tx")
    if type(created) is not bool:
        raise ValueError("created_by_tx must be a boolean")
    digest = data.get("sha256", "")
    if not isinstance(digest, str):
        raise ValueError("sha256 must be a string")
    if created and not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("created hook digest is invalid")
    print("1" if created else "0")
    print(digest)
except Exception as exc:
    print(f"Invalid deploy-hook rollback manifest: {type(exc).__name__}", file=sys.stderr)
    sys.exit(1)
PY
    ) || {
        echo "Error: Refusing deploy-hook rollback because its ownership manifest is invalid." >&2
        return 1
    }

    local -a manifest_fields=()
    mapfile -t manifest_fields <<< "$manifest_data"
    if [[ "${#manifest_fields[@]}" -ne 2 ]]; then
        echo "Error: Deploy-hook rollback manifest has an invalid field count." >&2
        return 1
    fi
    local created_by_tx="${manifest_fields[0]}"
    local recorded_sha="${manifest_fields[1]}"
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
    current_sha=$(sha256sum "$hook_file" | awk '{print $1}') || {
        echo "Error: Could not verify managed deploy-hook digest." >&2
        return 1
    }
    if [[ "$current_sha" != "$recorded_sha" ]]; then
        echo "Warning: Deploy hook $hook_file was modified after installation (digest mismatch); preserving modified object and reporting incomplete recovery." >&2
        return 1
    fi

    rm -f "$hook_file" || {
        echo "Error: Could not remove transaction-owned deploy hook $hook_file." >&2
        return 1
    }
    sync "$(dirname "$hook_file")" || {
        echo "Error: Could not sync deploy-hook directory after rollback." >&2
        return 1
    }
    return 0
}

configure_certbot_deploy_hook() {
    local tx_id="${1:-master_install}"
    local hook_dir="/etc/letsencrypt/renewal-hooks/deploy"
    local hook_file="$hook_dir/gowave-nginx.sh"

    install_managed_deploy_hook "$tx_id" "$hook_file"
}

# The local ACME fixture is a test-only trust anchor. Its endpoint is pinned so
# enabling test mode never turns GOWAVE_ACME_SERVER into an arbitrary-URL option.
GOWAVE_ACME_TEST_ENDPOINT="https://pebble.testbed.internal:14000/dir"

acme_test_mode_enabled() {
    [[ "${GOWAVE_ACME_TEST_MODE:-0}" == "1" ]]
}

validate_acme_test_ca() {
    local ca_file="${GOWAVE_ACME_TEST_CA_FILE:-}"
    local expected_sha256="${GOWAVE_ACME_TEST_CA_SHA256:-}"
    if [[ -z "$ca_file" || -z "$expected_sha256" ]]; then
        echo "Error: test-only ACME mode requires GOWAVE_ACME_TEST_CA_FILE and GOWAVE_ACME_TEST_CA_SHA256." >&2
        return 1
    fi
    if [[ -L "$ca_file" || ! -f "$ca_file" ]]; then
        echo "Error: GOWAVE_ACME_TEST_CA_FILE must be a regular file, not a symlink." >&2
        return 1
    fi
    if [[ ! "$expected_sha256" =~ ^[0-9a-fA-F]{64}$ ]]; then
        echo "Error: GOWAVE_ACME_TEST_CA_SHA256 must be a 64-character hex digest." >&2
        return 1
    fi
    local actual_sha256
    actual_sha256=$(sha256sum -- "$ca_file" 2>/dev/null | awk '{print $1}')
    if [[ "$actual_sha256" != "$expected_sha256" ]]; then
        echo "Error: ACME test CA digest mismatch; refusing an unpinned trust anchor." >&2
        return 1
    fi
    return 0
}

run_certbot() {
    if acme_test_mode_enabled && [[ "${GOWAVE_ACME_SERVER:-}" == "$GOWAVE_ACME_TEST_ENDPOINT" ]]; then
        REQUESTS_CA_BUNDLE="$GOWAVE_ACME_TEST_CA_FILE" \
            SSL_CERT_FILE="$GOWAVE_ACME_TEST_CA_FILE" \
            certbot "$@"
        return
    fi
    certbot "$@"
}

validate_acme_server() {
    local server="${1:-}"
    if [[ -z "$server" ]]; then
        return 0
    fi
    if [[ "$server" == "$GOWAVE_ACME_TEST_ENDPOINT" ]]; then
        if ! acme_test_mode_enabled; then
            echo "Error: Invalid GOWAVE_ACME_SERVER: the local ACME fixture endpoint is accepted only with GOWAVE_ACME_TEST_MODE=1." >&2
            return 1
        fi
        validate_acme_test_ca || return 1
        return 0
    fi
    if [[ "$server" != "https://acme-staging-v02.api.letsencrypt.org/directory" && \
          "$server" != "https://acme-v02.api.letsencrypt.org/directory" ]]; then
        if acme_test_mode_enabled; then
            echo "Error: test-only ACME mode accepts only the pinned fixture endpoint '$GOWAVE_ACME_TEST_ENDPOINT' or a Let's Encrypt Staging/Production directory; refusing '$server'." >&2
        else
            echo "Error: Invalid GOWAVE_ACME_SERVER: '$server'. Only 'https://acme-staging-v02.api.letsencrypt.org/directory' or 'https://acme-v02.api.letsencrypt.org/directory' are supported." >&2
        fi
        return 1
    fi
    return 0
}

check_acme_lineage() {
    local domain="$1"
    local target_server="${2:-https://acme-v02.api.letsencrypt.org/directory}"
    local renewal_conf="${3:-/etc/letsencrypt/renewal/${domain}.conf}"
    local live_dir="${4:-/etc/letsencrypt/live/${domain}}"
    local fixture_target=0

    if [[ "$target_server" == "$GOWAVE_ACME_TEST_ENDPOINT" ]]; then
        if ! acme_test_mode_enabled; then
            echo "Error: ACME lineage for $domain targets the local fixture endpoint without GOWAVE_ACME_TEST_MODE=1." >&2
            return 1
        fi
        validate_acme_test_ca || return 1
        fixture_target=1
    fi

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

        local recognized=0
        if [[ "$existing_server" == "https://acme-staging-v02.api.letsencrypt.org/directory" || \
              "$existing_server" == "https://acme-v02.api.letsencrypt.org/directory" ]]; then
            recognized=1
        elif [[ "$existing_server" == "$GOWAVE_ACME_TEST_ENDPOINT" ]] && acme_test_mode_enabled; then
            validate_acme_test_ca || return 1
            recognized=1
        fi
        if [[ "$recognized" -ne 1 ]]; then
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
        if [[ "$fixture_target" -eq 1 ]]; then
            if ! openssl verify -CAfile "$GOWAVE_ACME_TEST_CA_FILE" -untrusted "$fullchain" "$fullchain" >/dev/null 2>&1; then
                echo "Error: Existing certificate for $domain does not chain to the pinned local ACME test CA; refusing to reuse a cross-lineage certificate." >&2
                return 1
            fi
        else
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
    fi

    return 0
}

snapshot_acme_lineage() {
    local transaction_id="$1"
    local domain="$2"
    local recovery_root="${3:-/var/lib/gowave-auto-nginx/recovery}"
    local letsencrypt_root="${4:-/etc/letsencrypt}"

    if [[ ! "$transaction_id" =~ ^[A-Za-z0-9._-]+$ || ! "$domain" =~ ^[A-Za-z0-9.-]+$ ]]; then
        echo "Error: Invalid transaction ID or domain for ACME snapshot." >&2
        return 1
    fi

    local snap_dir="${recovery_root}/${transaction_id}/acme/${domain}"
    mkdir -p "$snap_dir" || { echo "Error: Could not create ACME snapshot directory for $domain." >&2; return 1; }
    if [[ -L "$snap_dir" ]]; then
        echo "Error: ACME snapshot directory is an unsafe symlink for $domain." >&2
        return 1
    fi
    chmod 0700 "$snap_dir" 2>/dev/null || { echo "Error: Could not secure ACME snapshot directory for $domain." >&2; return 1; }

    local renewal_conf="${letsencrypt_root}/renewal/${domain}.conf"
    local live_dir="${letsencrypt_root}/live/${domain}"
    local archive_dir="${letsencrypt_root}/archive/${domain}"
    local meta_file="${snap_dir}/lineage-manifest.json"
    local existed_before=false cert_serial="" cert_fingerprint=""

    if [[ -e "$renewal_conf" || -L "$renewal_conf" || -e "$live_dir" || -L "$live_dir" ]]; then
        if [[ ! -f "$renewal_conf" || -L "$renewal_conf" || ! -d "$live_dir" || -L "$live_dir" ]]; then
            echo "Error: Existing ACME lineage for $domain is incomplete or unsafe; refusing to snapshot it." >&2
            return 1
        fi
        mkdir -p "$snap_dir/archive" "$snap_dir/live" || { echo "Error: Could not create ACME snapshot subdirectories for $domain." >&2; return 1; }
        chmod 0700 "$snap_dir/archive" "$snap_dir/live" 2>/dev/null || { echo "Error: Could not secure ACME snapshot subdirectories for $domain." >&2; return 1; }
        cp -p "$renewal_conf" "$snap_dir/renewal.conf" || { echo "Error: Could not snapshot ACME renewal config for $domain." >&2; return 1; }

        local archive_real
        archive_real=$(realpath -e -- "$archive_dir") || { echo "Error: ACME archive directory is missing for existing lineage $domain." >&2; return 1; }
        local f link_path target real_file bn
        for f in cert.pem chain.pem fullchain.pem privkey.pem; do
            link_path="${live_dir}/${f}"
            if [[ -L "$link_path" ]]; then
                target=$(readlink "$link_path") || { echo "Error: Could not read ACME symlink $f for $domain." >&2; return 1; }
                if [[ -z "$target" || "$target" == /* ]]; then
                    echo "Error: Unsafe ACME symlink target for $domain/$f." >&2
                    return 1
                fi
                printf '%s\n' "$target" > "$snap_dir/live/${f}.target" || { echo "Error: Could not snapshot ACME symlink target for $domain/$f." >&2; return 1; }
                chmod 0600 "$snap_dir/live/${f}.target" 2>/dev/null || { echo "Error: Could not secure ACME symlink metadata for $domain/$f." >&2; return 1; }
                real_file=$(realpath -e -- "$link_path") || { echo "Error: ACME symlink $domain/$f is broken." >&2; return 1; }
                case "$real_file" in
                    "$archive_real"/*) ;;
                    *)
                        echo "Error: ACME symlink $domain/$f escapes its archive directory." >&2
                        return 1
                        ;;
                esac
                bn=$(basename "$real_file")
                cp -p "$real_file" "$snap_dir/archive/$bn" || { echo "Error: Could not snapshot ACME archive file $bn for $domain." >&2; return 1; }
                if [[ "$bn" =~ ^privkey ]]; then
                    chmod 0600 "$snap_dir/archive/$bn" 2>/dev/null || { echo "Error: Could not secure snapshotted ACME private key for $domain." >&2; return 1; }
                else
                    chmod 0644 "$snap_dir/archive/$bn" 2>/dev/null || { echo "Error: Could not set snapshotted ACME certificate permissions for $domain." >&2; return 1; }
                fi
            elif [[ -f "$link_path" ]]; then
                cp -p "$link_path" "$snap_dir/live/$f" || { echo "Error: Could not snapshot ACME live file $f for $domain." >&2; return 1; }
                if [[ "$f" == "privkey.pem" ]]; then
                    chmod 0600 "$snap_dir/live/$f" 2>/dev/null || { echo "Error: Could not secure snapshotted ACME private key for $domain." >&2; return 1; }
                fi
            else
                if [[ "$f" == "fullchain.pem" || "$f" == "privkey.pem" ]]; then
                    echo "Error: Existing ACME lineage is missing required file $domain/$f." >&2
                    return 1
                fi
                continue
            fi
        done

        local fullchain="${live_dir}/fullchain.pem" privkey="${live_dir}/privkey.pem"
        openssl x509 -in "$fullchain" -noout >/dev/null 2>&1 || { echo "Error: Existing ACME certificate is invalid for $domain." >&2; return 1; }
        local pub_from_cert pub_from_key
        pub_from_cert=$(openssl x509 -in "$fullchain" -noout -pubkey 2>/dev/null) || { echo "Error: Could not read existing ACME certificate key for $domain." >&2; return 1; }
        pub_from_key=$(openssl pkey -in "$privkey" -pubout 2>/dev/null) || { echo "Error: Could not read existing ACME private key for $domain." >&2; return 1; }
        if [[ -z "$pub_from_cert" || "$pub_from_cert" != "$pub_from_key" ]]; then
            echo "Error: Existing ACME certificate and private key do not match for $domain." >&2
            return 1
        fi
        cert_serial=$(openssl x509 -in "$fullchain" -noout -serial 2>/dev/null) || { echo "Error: Could not read existing ACME certificate serial for $domain." >&2; return 1; }
        cert_fingerprint=$(openssl x509 -in "$fullchain" -noout -fingerprint -sha256 2>/dev/null) || { echo "Error: Could not read existing ACME certificate fingerprint for $domain." >&2; return 1; }
        if [[ -z "$cert_serial" || -z "$cert_fingerprint" ]]; then
            echo "Error: Existing ACME certificate identity metadata is empty for $domain." >&2
            return 1
        fi
        existed_before=true
    fi

    python3 - "$meta_file" "$domain" "$existed_before" "$cert_serial" "$cert_fingerprint" <<'PY'
import json
import os
import sys

meta_file, domain, existed, serial, fingerprint = sys.argv[1:6]
data = {
    "domain": domain,
    "existed_before": existed == "true",
    "serial": serial,
    "fingerprint": fingerprint,
}
tmp_path = meta_file + ".tmp"
fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(data, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp_path, meta_file)
    dir_fd = os.open(os.path.dirname(meta_file), os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
except Exception as exc:
    try:
        os.unlink(tmp_path)
    except OSError:
        pass
    print(f"Failed to persist ACME snapshot manifest: {type(exc).__name__}", file=sys.stderr)
    raise SystemExit(1)
PY
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
