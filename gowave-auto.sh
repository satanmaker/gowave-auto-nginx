#!/usr/bin/env bash
# gowave-auto.sh - Main GoWave Auto NGINX Lifecycle Manager and CLI Entrypoint
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCK_FILE="/run/lock/gowave-auto.lock"
STATE_FILE="${GOWAVE_STATE_FILE:-/var/lib/gowave-auto-nginx/state.json}"
JOURNAL_FILE="/var/lib/gowave-auto-nginx/recovery/journal.json"
CREDENTIALS_FILE="/root/gowave-credentials.txt"

# The failure report names the phase, the command and the status, so a failed
# run says where it stopped instead of exiting on a bare status. The handler
# only reports: every compensation in this tree is explicit and already runs
# inside the failing step, so rolling back here would double-compensate a
# transaction that step had partially removed.
CURRENT_STEP="initialization"
on_error() {
    local code=$?
    trap - ERR
    # `set -E` hands this trap to command substitutions and pipeline elements.
    # They keep the code and stay quiet; the parent knows the phase and speaks
    # once.
    if [[ "${BASHPID:-$$}" != "$$" ]]; then
        exit "$code"
    fi
    printf 'Error: step "%s" failed running "%s" (exit %s).\n' \
        "${CURRENT_STEP:-unassigned}" "$BASH_COMMAND" "$code" >&2
    exit "$code"
}
trap 'on_error' ERR

# Source submodules
source "$SCRIPT_DIR/modules/lock.sh"
source "$SCRIPT_DIR/modules/tempdir.sh"
source "$SCRIPT_DIR/modules/address.sh"
source "$SCRIPT_DIR/modules/os.sh"
source "$SCRIPT_DIR/modules/preflight.sh"
source "$SCRIPT_DIR/modules/install_args.sh"
source "$SCRIPT_DIR/modules/i18n.sh"
source "$SCRIPT_DIR/modules/wizard.sh"
source "$SCRIPT_DIR/modules/ssh_bootstrap.sh"
source "$SCRIPT_DIR/modules/security.sh"
source "$SCRIPT_DIR/modules/firewall.sh"
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
    local connect="${2:-127.0.0.1:443}"
    local attempts="${3:-10}"
    command -v timeout >/dev/null 2>&1 || { echo "Fatal: timeout is required for TLS verification." >&2; return 1; }
    local ca_opts=(-CApath /etc/ssl/certs)
    if [[ -n "${GOWAVE_TLS_CA_FILE:-}" ]]; then
        if [[ ! -f "$GOWAVE_TLS_CA_FILE" || -L "$GOWAVE_TLS_CA_FILE" ]]; then
            echo "Fatal: GOWAVE_TLS_CA_FILE must be a readable regular file, not a symlink." >&2
            return 1
        fi
        ca_opts=(-CAfile "$GOWAVE_TLS_CA_FILE")
    fi
    local workdir
    workdir=$(mktemp -d "${TMPDIR:-/tmp}/gowave-tls-sni.XXXXXX") || {
        echo "Fatal: Could not create a temporary directory for TLS verification." >&2
        return 1
    }
    track_temp_dir "$workdir"
    # `systemctl reload nginx` only hands the new configuration to the master:
    # the previous worker generation keeps its own certificates until it drains,
    # so the first handshake after a reload can still be answered with what the
    # change just replaced. Wait for the listener to settle, but judge every
    # attempt strictly -- a name the served certificate does not cover, or a
    # chain the trust store does not anchor, still fails closed.
    local attempt name_check trust_check served
    for ((attempt = 1; attempt <= attempts; attempt++)); do
        rm -f -- "$workdir/chain.pem" "$workdir/leaf.pem" "$workdir/untrusted.pem"
        timeout 10 openssl s_client -connect "$connect" -servername "$domain" -showcerts \
            "${ca_opts[@]}" </dev/null >"$workdir/chain.pem" 2>"$workdir/handshake.log" || true
        # s_client interleaves its banner with the PEM chain, so split the
        # certificates out instead of trusting the raw stream.
        awk -v leaf="$workdir/leaf.pem" -v rest="$workdir/untrusted.pem" '
            /^-----BEGIN CERTIFICATE-----$/ {
                seen += 1
                inside = 1
                target = (seen == 1) ? leaf : rest
                print > target
                next
            }
            /^-----END CERTIFICATE-----$/ {
                if (inside) {
                    print > target
                    inside = 0
                }
                next
            }
            inside { print > target }
        ' "$workdir/chain.pem" 2>/dev/null || true
        if [[ -s "$workdir/leaf.pem" ]]; then
            name_check=$(openssl x509 -noout -checkhost "$domain" -in "$workdir/leaf.pem" 2>&1 || true)
            if [[ "$name_check" == "Hostname $domain does match certificate" ]]; then
                if [[ -s "$workdir/untrusted.pem" ]]; then
                    trust_check=$(openssl verify "${ca_opts[@]}" -untrusted "$workdir/untrusted.pem" \
                        "$workdir/leaf.pem" 2>&1 || true)
                else
                    trust_check=$(openssl verify "${ca_opts[@]}" "$workdir/leaf.pem" 2>&1 || true)
                fi
                if [[ "$trust_check" == *": OK" ]]; then
                    release_temp_dir "$workdir"
                    return 0
                fi
                served=$(printf '%s' "$trust_check" | tr -s '[:space:]' ' ' | cut -c1-300)
            else
                served=$(openssl x509 -noout -ext subjectAltName -in "$workdir/leaf.pem" 2>/dev/null \
                    | tr -s '[:space:]' ' ' || true)
                served="wrong certificate: ${served:-no subjectAltName}"
            fi
        else
            served="no certificate was served"
        fi
        if ((attempt < attempts)); then
            # Give the previous worker generation time to finish draining.
            sleep 1
        fi
    done
    # The bare error leaves an operator guessing whether the wrong certificate
    # or the wrong SNI route answered, so name everything on failure.
    local routed certificate
    routed=$(grep -F "$domain " /etc/nginx/stream-enabled/gowave-stream.conf 2>/dev/null \
        | head -n 1 || true)
    certificate=$(grep -E '^[[:space:]]*ssl_certificate[[:space:]]' /etc/nginx/conf.d/gowave-panel.conf 2>/dev/null \
        | head -n 1 || true)
    echo "Error: The port 443 listener did not prove TLS for $domain." >&2
    echo "  SNI map entry: ${routed:-none}" >&2
    echo "  Panel listener certificate: ${certificate:-none}" >&2
    echo "  Last attempt answered with: ${served:-unreadable}" >&2
    if [[ -s "$workdir/handshake.log" ]]; then
        echo "  Handshake log:" >&2
        tail -n 5 "$workdir/handshake.log" >&2 || true
    fi
    release_temp_dir "$workdir"
    return 1
}

acquire_lock() {
    acquire_mutation_lock "$@"
}

cmd_status() {
    local install_mode
    install_mode=$(installation_mode_from_state)
    echo "================================================================================"
    echo "                      GoWave Auto NGINX Service Status                          "
    echo "================================================================================"

    echo "--- Systemd Services ---"
    for svc in gowave.service gowave-node.service nginx.service fail2ban.service; do
        if command -v systemctl >/dev/null 2>&1; then
            local state
            state=$(systemctl is-active "$svc" 2>/dev/null | head -n 1 || true)
            [[ -n "$state" ]] || state="not-found"
            if [[ "$svc" == "gowave-node.service" && "$install_mode" == "panel-only" && "$state" != "active" ]]; then
                state="not present (panel-only installation)"
            fi
            printf "%-25s : %s\n" "$svc" "$state"
        fi
    done

    echo ""
    echo "--- Port Listeners ---"
    for port in 80 443 3000 3001 3002 7443 8443 8444 9443; do
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
    local install_mode
    install_mode=$(installation_mode_from_state)
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
        if [[ "$install_mode" == "panel-only" ]]; then
            echo "[WARN] GoWave Node listener (127.0.0.1:3002) is intentionally absent in Panel-only mode." >&2
        else
            echo "[WARN] GoWave Node listener (127.0.0.1:3002) is not listening." >&2
        fi
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
    local install_mode plan_rc=0
    if wizard_should_run "$@"; then
        # A cancelled plan is not a failure: no server was changed, so the
        # interactive session returns to its menu and a positional caller exits
        # 0. Every other code keeps the failure the step reported.
        wizard_collect_plan || plan_rc=$?
        if (( plan_rc == 3 )); then
            return 0
        elif (( plan_rc != 0 )); then
            return "$plan_rc"
        fi
        wizard_review_plan || plan_rc=$?
        if (( plan_rc == 3 )); then
            return 0
        elif (( plan_rc != 0 )); then
            return "$plan_rc"
        fi
        wizard_check_ssh_reachable || return $?
        wizard_apply_plan || return $?
        install_mode="$GOWAVE_INSTALL_MODE"
        # Only this branch asks a traffic node where it exits. The lookup is a
        # request to a third party that sees the node's address, so a positional
        # install — which has nobody to confirm the answer — makes none.
        GOWAVE_COUNTRY_ASK="yes"
    else
        if [[ $# -eq 0 ]]; then
            wizard_missing_terminal || return $?
        fi
        parse_install_arguments "$@" || return $?
        install_mode="$GOWAVE_INSTALL_MODE"
    fi
    # A partial list is completed by prompting, and a prompt with no terminal is a
    # `read` under `set -e`: it exits 1 with nothing on either stream.
    if [[ ! -t 0 ]]; then
        local missing="" index
        local -a argument_names=("the panel or worker name" "the camouflage name" "the acme email")
        for index in 0 1 2; do
            if [[ -z "${GOWAVE_INSTALL_POSITIONAL[$index]:-}" ]]; then
                missing+="${missing:+, }${argument_names[$index]}"
            fi
        done
        if [[ -n "$missing" ]]; then
            printf 'Error: no terminal to prompt on, so install needs %s.\n' "$missing" >&2
            printf '%s\n' "$GOWAVE_INSTALL_USAGE" >&2
            return 2
        fi
    fi
    # The local node keeps the operator's own word for this server on a wizard
    # run; an installation that never collected a plan keeps the historical
    # name so its state, tags and remarks stay what earlier versions produced.
    local local_node_name="${GOWAVE_PLAN_LOCAL_LABEL:-local-node}"
    acquire_lock
    local panel_domain="${GOWAVE_INSTALL_POSITIONAL[0]:-}"
    local reality_domain="${GOWAVE_INSTALL_POSITIONAL[1]:-}"
    local admin_email="${GOWAVE_INSTALL_POSITIONAL[2]:-}"
    local vision_domain="${GOWAVE_INSTALL_POSITIONAL[3]:-${VISION_DOMAIN:-}}"
    if [[ "$install_mode" == "panel-only" ]]; then
        vision_domain=""
    fi

    if [[ -z "$panel_domain" ]]; then
        read -r -p "Enter GoWave Panel domain (e.g. vpn.example.com): " panel_domain
    fi
    if [[ -z "$reality_domain" ]]; then
        read -r -p "Enter REALITY camouflage domain (e.g. cdn.example.com): " reality_domain
    fi
    if [[ -z "$admin_email" ]]; then
        read -r -p "Enter Let's Encrypt admin email: " admin_email
    fi
    if [[ -z "$vision_domain" ]] && [[ -t 0 ]] && [[ ${#GOWAVE_INSTALL_POSITIONAL[@]} -eq 0 ]] && [[ "$install_mode" == "all-in-one" ]]; then
        local enable_vision="n"
        read -r -p "Configure optional VLESS + XTLS Vision? (requires a dedicated 3rd domain/subdomain) [y/N]: " enable_vision
        if [[ "$enable_vision" =~ ^[Yy]$ ]]; then
            read -r -p "Enter Vision domain (e.g. vision.example.com): " vision_domain
        fi
    fi
    # The required-input contract is pure shell, so it runs before any tool is
    # installed, before NGINX is stopped and before any managed path is written.
    # The camouflage probe that follows does need a handful of tools that
    # install_prerequisites would install later; get them first so a bare host
    # fails for a product reason rather than a missing interpreter.
    CURRENT_STEP="install: input contract"
    preflight_require_inputs install "$panel_domain" "$reality_domain" "$admin_email" "$vision_domain" || return $?
    preflight_require_direct_dns "$panel_domain" "$reality_domain" "$vision_domain" || return 1
    bootstrap_early_tools || return 1

    validate_acme_server "${GOWAVE_ACME_SERVER:-}" || return 1
    local effective_acme_server="${GOWAVE_ACME_SERVER:-https://acme-v02.api.letsencrypt.org/directory}"
    # A lineage that already covers a name is adopted instead of issuing a second
    # one beside it: certbot names a lineage after --cert-name, so a host that
    # already serves `example.com-0001` would otherwise gain `example.com` and the
    # vhost would have to guess which one to point at. Selection only ever returns
    # a directory whose renewal config names this ACME directory, so the staging /
    # production isolation below still applies to the lineage actually picked.
    local panel_live reality_live vision_live="" panel_lineage reality_lineage vision_lineage=""
    panel_live=$(select_acme_lineage "$panel_domain" "$effective_acme_server") || return 1
    reality_live=$(select_acme_lineage "$reality_domain" "$effective_acme_server") || return 1
    if [[ -n "$vision_domain" ]]; then
        vision_live=$(select_acme_lineage "$vision_domain" "$effective_acme_server") || return 1
    fi
    panel_live="${panel_live:-/etc/letsencrypt/live/$panel_domain}"
    reality_live="${reality_live:-/etc/letsencrypt/live/$reality_domain}"
    if [[ -n "$vision_domain" ]]; then
        vision_live="${vision_live:-/etc/letsencrypt/live/$vision_domain}"
    fi
    panel_lineage=$(basename -- "$panel_live")
    reality_lineage=$(basename -- "$reality_live")
    if [[ -n "$vision_domain" ]]; then
        vision_lineage=$(basename -- "$vision_live")
    fi
    check_acme_lineage "$panel_domain" "$effective_acme_server" \
        "/etc/letsencrypt/renewal/$panel_lineage.conf" "$panel_live" || return 1
    check_acme_lineage "$reality_domain" "$effective_acme_server" \
        "/etc/letsencrypt/renewal/$reality_lineage.conf" "$reality_live" || return 1
    if [[ -n "$vision_domain" ]]; then
        check_acme_lineage "$vision_domain" "$effective_acme_server" \
            "/etc/letsencrypt/renewal/$vision_lineage.conf" "$vision_live" || return 1
    fi
    record_certificate_lineages "$STATE_FILE" "$panel_live" "$reality_live" "$vision_live" || return 1

    # The camouflage site lives on the registrable apex of the panel domain so
    # that a browser reaching for the bare domain lands on a plausible static
    # site. ACME validates it over port 80 on this host, so it is only enabled
    # when both the apex and www already resolve here; the decision names its
    # own refusal, including a panel domain that has no apex to derive.
    local cover_domain="" cover_server_ip=""
    if [[ -n "$(derive_cover_domain "$panel_domain")" ]]; then
        cover_server_ip=$(resolve_panel_ipv4) || return 1
    fi
    cover_domain=$(cover_domain_for "$panel_domain" "$cover_server_ip")

    if [[ "$install_mode" == "panel-only" ]]; then
        echo "==> Starting GoWave Auto NGINX Panel-only Deployment..."
        echo "Installation Mode: Panel-only (no traffic plane, no local node)"
    else
        echo "==> Starting GoWave Auto NGINX All-in-One Deployment..."
        echo "Installation Mode: All-in-One"
    fi
    echo "Panel Domain:   $panel_domain"
    echo "Reality Domain: $reality_domain"
    if [[ "$install_mode" == "panel-only" ]]; then
        echo "Traffic Plane:  Disabled (Panel and static decoy only)"
    elif [[ -n "$vision_domain" ]]; then
        echo "Vision Domain:  $vision_domain (Optional VLESS + XTLS Vision enabled)"
    else
        echo "Vision Domain:  Disabled (default 4-inbound configuration)"
    fi
    if [[ -n "$cover_domain" ]]; then
        echo "Cover Site:     $cover_domain (+ www) — camouflage website on the apex"
    else
        echo "Cover Site:     Disabled"
    fi

    # Step 1: Preflight Environment Inspection
    CURRENT_STEP="install: preflight"
    check_os
    # A repeat install finds NGINX already serving the managed stream config.
    # Taking it down there is downtime for a live target, and the ACME stage
    # relies on that running vhost to answer challenges from the same webroot.
    local managed_nginx_in_place=0
    if [[ -f /etc/nginx/stream-enabled/gowave-stream.conf && -f /etc/nginx/conf.d/gowave-http.conf ]]; then
        managed_nginx_in_place=1
    fi
    if (( managed_nginx_in_place == 0 )) && command -v systemctl >/dev/null 2>&1; then
        systemctl stop nginx 2>/dev/null || true
    fi
    run_preflight_panel

    # Step 2: System Prerequisites
    CURRENT_STEP="install: prerequisites"
    install_prerequisites

    # Step 3: Host Security Hardening
    CURRENT_STEP="install: host security"
    configure_ssh_and_fail2ban
    configure_swap
    configure_bbr_and_mtu "$STATE_FILE"
    configure_log_rotation

    # The baseline and the conflict verdict belong here, before the first step
    # that can change ingress: the local Node denies its API port before the
    # policy is applied, and a baseline taken after that would record this
    # install's own rule as the state to return to.
    CURRENT_STEP="install: firewall baseline"
    firewall_prepare_install "$install_mode" 3002 || return 1
    firewall_begin_transaction || return 1

    # Step 4: Webroot ACME TLS Acquisition
    CURRENT_STEP="install: certificates"
    local acme_tx_id="install_$(date +%s)"
    verify_deploy_hook_preflight "/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh" "$acme_tx_id" || return 1
    # Snapshot under the lineage name, not the requested one: an adopted lineage
    # is thereby recorded as pre-existing, which is what stops
    # rollback_acme_lineages from deleting a certificate this run did not create.
    snapshot_acme_lineage "$acme_tx_id" "$panel_lineage"
    snapshot_acme_lineage "$acme_tx_id" "$reality_lineage"
    if [[ -n "$vision_domain" ]]; then
        snapshot_acme_lineage "$acme_tx_id" "$vision_lineage"
    fi

    rollback_acme_lineages() {
        local rollback_failed=0
        echo "ACME acquisition or verification failed. Rolling back certificate lineages..." >&2
        rollback_managed_deploy_hook "$acme_tx_id" 2>/dev/null || rollback_failed=1
        restore_acme_lineage "$acme_tx_id" "$panel_lineage" 2>/dev/null || rollback_failed=1
        restore_acme_lineage "$acme_tx_id" "$reality_lineage" 2>/dev/null || rollback_failed=1
        if [[ -n "$vision_domain" ]]; then
            restore_acme_lineage "$acme_tx_id" "$vision_lineage" 2>/dev/null || rollback_failed=1
        fi
        rm -f /etc/nginx/conf.d/00-bootstrap-acme.conf || rollback_failed=1
        if [[ "$rollback_failed" -ne 0 ]]; then
            echo "CRITICAL: ACME rollback incomplete; certificate lineage or deploy-hook restoration failed. Recovery snapshot retained for operator intervention." >&2
        else
            echo "ACME certificate lineage rollback completed successfully." >&2
        fi
        # Preserve the caller's original deployment failure status; the explicit
        # diagnostic above distinguishes a complete rollback from partial recovery.
        return 0
    }

    if (( managed_nginx_in_place == 1 )); then
        # The managed :80 vhost already answers ACME challenges for these names
        # from the same webroot, so a bootstrap vhost would only duplicate every
        # server name NGINX is serving.
        true
    else
        if ! generate_bootstrap_acme_vhost "$panel_domain" "$reality_domain" "/etc/nginx/conf.d/00-bootstrap-acme.conf" "/proc/net/if_inet6" "$vision_domain" "$cover_domain"; then
            echo "Error: Failed to generate bootstrap ACME NGINX configuration; rolling back certificate lineages." >&2
            rollback_acme_lineages
            return 1
        fi
        if ! reload_nginx_strict; then
            echo "Error: Failed to activate bootstrap ACME NGINX configuration; rolling back certificate lineages." >&2
            rollback_acme_lineages
            return 1
        fi
    fi

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
    if ! run_certbot certonly --webroot -w "$ACME_WEBROOT" \
        -d "$panel_domain" --cert-name "$panel_lineage" \
        --non-interactive --agree-tos -m "$admin_email" --keep-until-expiring \
        "${certbot_extra_args[@]}"; then
        rollback_acme_lineages
        return 1
    fi

    echo "Acquiring Let's Encrypt TLS certificate for REALITY decoy ($reality_domain)..."
    # The camouflage certificate also covers the apex website, so one lineage
    # serves both the probe fallback and the plain-domain landing page.
    local reality_cert_args=(-d "$reality_domain")
    local reality_cert_flags=()
    if [[ -n "$cover_domain" ]]; then
        reality_cert_args+=(-d "$cover_domain" -d "www.$cover_domain")
        reality_cert_flags+=(--expand)
    fi
    if ! run_certbot certonly --webroot -w "$ACME_WEBROOT" \
        "${reality_cert_args[@]}" "${reality_cert_flags[@]}" --cert-name "$reality_lineage" \
        --non-interactive --agree-tos -m "$admin_email" --keep-until-expiring \
        "${certbot_extra_args[@]}"; then
        rollback_acme_lineages
        return 1
    fi

    if [[ -n "$vision_domain" ]]; then
        echo "Acquiring Let's Encrypt TLS certificate for VLESS Vision ($vision_domain)..."
        if ! run_certbot certonly --webroot -w "$ACME_WEBROOT" \
            -d "$vision_domain" --cert-name "$vision_lineage" \
            --non-interactive --agree-tos -m "$admin_email" --keep-until-expiring \
            "${certbot_extra_args[@]}"; then
            rollback_acme_lineages
            return 1
        fi
    fi

    rm -f /etc/nginx/conf.d/00-bootstrap-acme.conf

    # Verify certificates cryptographically (refuse to proceed with invalid or missing certificates)
    if ! verify_acme_certificate "$panel_domain" "$panel_live" || \
       ! verify_acme_certificate "$reality_domain" "$reality_live" || \
       { [[ -n "$cover_domain" ]] && ! verify_acme_certificate "$cover_domain" "$reality_live"; } || \
       { [[ -n "$vision_domain" ]] && ! verify_acme_certificate "$vision_domain" "$vision_live"; }; then
        rollback_acme_lineages
        return 1
    fi

    # Step 5: NGINX Configuration
    CURRENT_STEP="install: nginx"
    ensure_nginx_stream_block
    generate_stream_config "$panel_domain" "$reality_domain" "/etc/nginx/stream-enabled/gowave-stream.conf" "/proc/net/if_inet6" "$vision_domain" "$cover_domain" "$install_mode"
    generate_production_http_vhost "$panel_domain" "$reality_domain" "/etc/nginx/conf.d/gowave-http.conf" "/proc/net/if_inet6" "$vision_domain" "$cover_domain"
    generate_panel_https_vhost "$panel_domain" "/etc/nginx/conf.d/gowave-panel.conf" nginx "$panel_live"
    generate_decoy_vhost "$reality_domain" "/etc/nginx/conf.d/gowave-decoy.conf" nginx "$COVER_REALITY_ROOT" "$cover_domain" "$reality_live"
    if [[ "$install_mode" == "all-in-one" && -n "$vision_domain" ]]; then
        generate_vision_fallback_vhost "$vision_domain"
    fi
    configure_certbot_deploy_hook "$acme_tx_id"

    reload_nginx_strict

    # Step 6: GoWave Panel Native Installation
    CURRENT_STEP="install: panel"
    download_panel_release "$GOWAVE_DIR" "${GOWAVE_PANEL_VERSION:-$GOWAVE_DEFAULT_VERSION}"
    generate_panel_env "$GOWAVE_DIR" "$panel_domain" "$panel_domain/api/sub"
    configure_panel_systemd "$GOWAVE_DIR"
    if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        systemctl restart --no-ask-password gowave.service
        systemctl is-active --quiet gowave.service
        # The path unit is armed only now, once the restart has created
        # /run/gowave, so the watch never starts against a missing directory.
        systemctl start --no-ask-password gowave-update.path
    fi
    verify_panel_startup 127.0.0.1 3000 30
    verify_public_tls_sni "$panel_domain"

    # Step 7: Local Node Installation (the traffic plane is absent in Panel-only)
    CURRENT_STEP="install: local node"
    local local_country=""
    if [[ "$install_mode" == "all-in-one" ]]; then
        local secret_key
        secret_key=$(extract_secret_key "$GOWAVE_DIR")
        install_local_node "$secret_key" 3002
        verify_node_mtls_health "$secret_key" 3002
        # Asked only once this node serves: the answer is about the route its
        # traffic leaves from, and a node that never came up has no such route.
        local_country=$(wizard_local_exit_country "$local_node_name") || local_country=""
        configure_ufw false "" 3002
    else
        configure_ufw false ""
    fi

    # Step 9: REST API Provisioning
    CURRENT_STEP="install: provisioning"
    echo "Executing REST API bootstrapping and MVP profile provisioning..."
    # A repeated install must keep the credentials the running Panel accepts: a
    # freshly generated password would be refused by the existing admin, and the
    # credentials file would no longer hold the password the operator needs.
    local admin_user="admin"
    local admin_pass=""
    if [[ -r "$CREDENTIALS_FILE" ]]; then
        local stored_user
        stored_user=$(grep -s '^ADMIN_USERNAME=' "$CREDENTIALS_FILE" | cut -d= -f2- || true)
        admin_pass=$(grep -s '^ADMIN_PASSWORD=' "$CREDENTIALS_FILE" | cut -d= -f2- || true)
        if [[ -n "$stored_user" ]]; then
            admin_user="$stored_user"
        fi
    fi
    if [[ -z "$admin_pass" ]]; then
        admin_pass=$(openssl rand -hex 16)
        save_credentials "$admin_user" "$admin_pass" "https://$panel_domain" "" "$CREDENTIALS_FILE"
    fi

    if ! PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
        XRAY_SERVER_VERSION="${XRAY_SERVER_VERSION:-}" \
        GOWAVE_MIHOMO_X25519="${GOWAVE_MIHOMO_X25519:-}" \
        GOWAVE_REALITY_FINGERPRINT="${GOWAVE_REALITY_FINGERPRINT:-}" \
        GOWAVE_VISION_CERT_DIR="${vision_live}" \
        GOWAVE_LOCAL_NODE_NAME="$local_node_name" \
        GOWAVE_LOCAL_COUNTRY="$local_country" \
        python3 - \
        "$SCRIPT_DIR" "$panel_domain" "$reality_domain" "$admin_user" \
        "$JOURNAL_FILE" "$STATE_FILE" "$CREDENTIALS_FILE" "$vision_domain" "$install_mode" 3<<< "$admin_pass" <<'PY'
import json
import os
import sys
import time

(script_dir, panel_domain, reality_domain, admin_user,
 journal_path, state_path, credentials_path, *extra) = sys.argv[1:]
vision_domain = extra[0] if extra and extra[0] else None
mode = extra[1] if len(extra) > 1 and extra[1] else "all-in-one"
# The name the operator chose for this server. It reaches profile tags and Host
# remarks, which is why the wizard validates it as an identifier before it gets
# here; an installation without a plan keeps the name earlier versions wrote.
local_node_name = (os.environ.get("GOWAVE_LOCAL_NODE_NAME") or "").strip() or "local-node"
admin_password = os.fdopen(3, "r", encoding="utf-8").read().rstrip("\n")

sys.path.insert(0, script_dir)
from modules.api_client import GoWaveClient, atomic_write_state, confirmed_country, save_credentials
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

def persist_transaction_entities(entities):
    journal["state"] = "PROVISION_APPLYING"
    journal["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    journal["entities"] = list(entities)
    write_journal_atomically(journal_path, journal)

client.transaction_callback = persist_transaction_entities


def stored_credentials(path):
    values = {}
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                key, separator, value = line.partition("=")
                if separator:
                    values[key.strip()] = value.strip()
    except FileNotFoundError:
        pass
    return values


PROFILE_NAME = f"GoWave MVP Unified Profile - {local_node_name}"

existing_cc = "bbr"
existing_state = {}
if os.path.exists(state_path):
    try:
        with open(state_path, encoding="utf-8") as state_file:
            existing_state = json.load(state_file)
    except Exception:
        existing_state = {}
if not isinstance(existing_state, dict):
    existing_state = {}
existing_cc = existing_state.get("congestionControl", "bbr")

# The exit country the operator confirmed for this server. A run that asked
# nothing keeps the answer an earlier run stored, so a positional rerun cannot
# erase a label the operator already confirmed.
previous_local_country = ""
previous_local_hosts = []
for known in existing_state.get("nodes") or []:
    if isinstance(known, dict) and known.get("name") == local_node_name:
        previous_local_country = str(known.get("country") or "")
        recorded_hosts = known.get("hostUuids")
        if isinstance(recorded_hosts, list):
            previous_local_hosts = [str(u) for u in recorded_hosts if u]
local_country = confirmed_country(
    os.environ.get("GOWAVE_LOCAL_COUNTRY"), previous_local_country
)

if mode == "panel-only":
    # Nothing exists that an inbound could reference, so the install stops at
    # the credentials the operator needs to reach the Panel. The first node add
    # creates the profile, the inbounds, the squad, and the host records.
    short_uuid = client.provision_user("default-user", None)
    token_info = client.ensure_api_token(
        existing_token=stored_credentials(credentials_path).get("SCOPED_API_TOKEN", "")
    )
    journal["entities"] = client.transaction_entities
    write_journal_atomically(journal_path, journal)

    save_credentials(admin_user, admin_password, f"https://{panel_domain}",
                     token_info["token"], credentials_path)

    state = {
        "schemaVersion": 2,
        "installationMode": "panel-only",
        "panelDomain": panel_domain,
        "realityDomain": reality_domain,
        "congestionControl": existing_cc,
        "defaultUserShortUuid": short_uuid,
        "nodes": [],
    }
    atomic_write_state(state, state_path)

    journal["state"] = "PROVISION_COMMITTED"
    journal["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    write_journal_atomically(journal_path, journal)
    sys.exit(0)

# A repeated install reuses the REALITY material and the API token the installed
# Panel already publishes: new keys would invalidate every subscription already
# served, and a new token would leave a duplicate behind.
installed_material = client.existing_reality_material(PROFILE_NAME, reality_domain)
if installed_material:
    x25519 = {
        "privateKey": installed_material["privateKey"],
        "publicKey": installed_material["publicKey"],
    }
    short_ids = installed_material["shortIds"]
else:
    x25519 = client.generate_x25519()
    short_ids = None
raw_config = client.compile_config_profile(
    local_node_name, reality_domain, x25519["privateKey"], short_ids=short_ids,
    public_key=x25519.get("publicKey"), vision_domain=vision_domain, panel_domain=panel_domain,
    vision_cert_dir=os.environ.get("GOWAVE_VISION_CERT_DIR") or None,
)
profile = client.provision_config_profile(PROFILE_NAME, raw_config)
profile_uuid = profile["profile_uuid"]
inbounds = profile["inbounds"]
inbound_uuids = [item["uuid"] for item in inbounds]
journal["entities"] = client.transaction_entities
write_journal_atomically(journal_path, journal)

node_uuid = client.associate_node(local_node_name, "127.0.0.1", 3002, profile_uuid, inbound_uuids)
journal["entities"] = client.transaction_entities
write_journal_atomically(journal_path, journal)

squad_uuid = client.provision_internal_squad("Default MVP Squad", inbound_uuids)
journal["entities"] = client.transaction_entities
write_journal_atomically(journal_path, journal)

host_uuids = client.provision_hosts(
    profile_uuid, inbounds, node_uuid, squad_uuid,
    panel_domain, reality_domain, node_name=local_node_name, vision_domain=vision_domain,
    known_host_uuids=previous_local_hosts, country=local_country,
)
journal["entities"] = client.transaction_entities
write_journal_atomically(journal_path, journal)

short_uuid = client.provision_user("default-user", squad_uuid)
token_info = client.ensure_api_token(
    existing_token=stored_credentials(credentials_path).get("SCOPED_API_TOKEN", "")
)
journal["entities"] = client.transaction_entities
write_journal_atomically(journal_path, journal)

save_credentials(admin_user, admin_password, f"https://{panel_domain}",
                 token_info["token"], credentials_path)

local_node_entry = {
    "name": local_node_name,
    "address": "127.0.0.1",
    "port": 3002,
    "uuid": node_uuid,
}
if local_country:
    local_node_entry["country"] = local_country
if host_uuids:
    # The records this run owns. The next run reconciles by these identities
    # first, so a label that moved does not turn into a second set of Hosts.
    local_node_entry["hostUuids"] = list(host_uuids)

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
    "nodes": [local_node_entry],
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

    # The deploy-hook ownership manifest stays behind after commit: it is the
    # host-local record that lets a later install recognise the hook it wrote.
    cleanup_acme_snapshot "$acme_tx_id" "$panel_domain"
    cleanup_acme_snapshot "$acme_tx_id" "$reality_domain"
    if [[ -n "$vision_domain" ]]; then
        cleanup_acme_snapshot "$acme_tx_id" "$vision_domain"
    fi
    # A verified install keeps no firewall baseline behind; a failed one keeps
    # the image its compensation restored from.
    firewall_commit_transaction

    # A plan that still has nodes to onboard has not finished installing: the
    # Panel reaches a serving state first, and "Installation Complete" over it
    # was the banner an operator read while the run was still waiting on SSH.
    # The Panel therefore gets its own line, and the completion banner below is
    # reached only when nothing remains.
    local nodes_planned=0
    case "${GOWAVE_PLAN_VARIANT:-}" in
        multi-node | panel-only) nodes_planned=1 ;;
    esac

    if (( nodes_planned == 1 )); then
        wizard_panel_installed_notice "https://$panel_domain"
        echo "Panel Web UI:        https://$panel_domain"
        echo "Admin Username:      $admin_user"
        echo "Saved Credentials:   $CREDENTIALS_FILE (mode 0600)"
        echo ""
        cmd_user_links default-user
        echo ""
        echo "Onboarding the planned remote nodes..."
        local onboard_rc=0
        wizard_onboard_nodes "https://$panel_domain" "127.0.0.1" "yes" || onboard_rc=$?
        # Return code 2 means partial success (some nodes succeeded, some failed).
        # The Panel deployment and the successful nodes are kept: this is not a
        # rollback. The command still exits with that code so an operator, and
        # anything driving the install, can tell it apart from a clean install
        # (0) and from a failed Panel deployment (1). The summary above already
        # names the failed stages and what to do next.
        if (( onboard_rc != 0 )); then
            return "$onboard_rc"
        fi
        echo ""
    fi

    echo "================================================================================"
    echo "                   GoWave Auto NGINX Installation Complete                      "
    echo "================================================================================"
    if (( nodes_planned == 0 )); then
        echo "Panel Web UI:        https://$panel_domain"
        echo "Admin Username:      $admin_user"
        echo "Saved Credentials:   $CREDENTIALS_FILE (mode 0600)"
        echo ""
        cmd_user_links default-user
    fi
}

# Compensate a failed `node add` on both sides and record what each one reached.
#
# The Panel API rollback is the writer that finalizes the journal as
# NODE_ADD_ROLLED_BACK, and it runs on the Master while the Worker restore runs
# on another host: a Worker failure discovered after the API side succeeded would
# otherwise leave a transaction recorded as rolled back over a host that was
# never put back. Both sides are attempted, both verdicts are written into the
# journal by modules.recovery, and the operation is reported INCOMPLETE unless
# both sides verified. The caller's panel_ip, panel_ipv6, node_port,
# vision_domain and known_hosts are read from the enclosing scope.
finalize_failed_node_add() {
    local name="$1"
    local ip="$2"
    local ssh_port="$3"
    local worker_domain="$4"
    local reality_domain="$5"
    local ssh_user="$6"
    local acme_tx_id="$7"
    local worker_status="INCOMPLETE"
    local api_status="INCOMPLETE"

    if ACME_TX_ID="$acme_tx_id" PANEL_IP="$panel_ip" PANEL_IPV6="$panel_ipv6" NODE_PORT="$node_port" SSH_KNOWN_HOSTS="$known_hosts" \
        VISION_DOMAIN="$vision_domain" \
        GOWAVE_WORKER_LEASE_TOKEN="${GOWAVE_WORKER_LEASE_TOKEN:-}" \
        "$SCRIPT_DIR/gowave-node-auto.sh" remote_rollback "$ip" "$ssh_port" "$worker_domain" "$reality_domain" "$ssh_user"; then
        worker_status="ROLLED_BACK"
    else
        echo "CRITICAL: Remote Worker host rollback failed; manual inspection required." >&2
    fi

    if PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from modules.api_client import rollback_provisioning
import sys
sys.exit(0 if rollback_provisioning('$JOURNAL_FILE', '$STATE_FILE', '$CREDENTIALS_FILE') else 1)
"; then
        api_status="ROLLED_BACK"
    else
        echo "CRITICAL: API rollback incomplete; recovery journal requires operator attention." >&2
    fi

    if ! PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 - "$JOURNAL_FILE" "$worker_status" "$api_status" <<'PY'
from modules.recovery import record_rollback_sides
import sys

journal_path, worker_status, api_status = sys.argv[1:]
record_rollback_sides(journal_path, worker_status, api_status)
PY
    then
        echo "CRITICAL: the rollback outcome for Worker '$name' could not be recorded; the recovery journal was not rewritten." >&2
        return 1
    fi

    if [[ "$worker_status" != "ROLLED_BACK" || "$api_status" != "ROLLED_BACK" ]]; then
        echo "CRITICAL: Node add '$name' is INCOMPLETE: Worker $worker_status, Panel API $api_status; both sides recorded in $JOURNAL_FILE." >&2
        echo "CRITICAL: Rollback failed for Worker '$name'; recovery journal retained." >&2
        return 1
    fi
    echo "Node add '$name' rolled back: Worker and Panel API both verified." >&2
    return 0
}

# Resolves `node add` inputs: each field starts from its GOWAVE_* variable, a
# non-empty positional overwrites it, and the result is validated by the same
# contract the positional path uses. An empty variable is the same as unset.
# The Worker secret is not an input of this command — it is read from the
# Panel's .env and handed to the remote side over stdin — so this contract
# cannot introduce it into argv or the environment.
resolve_node_inputs() {
    NODE_INPUT_NAME="${GOWAVE_NODE_NAME:-}"
    NODE_INPUT_ADDRESS="${GOWAVE_NODE_IP:-}"
    NODE_INPUT_WORKER_DOMAIN="${GOWAVE_WORKER_DOMAIN:-}"
    NODE_INPUT_REALITY_DOMAIN="${GOWAVE_REALITY_DOMAIN:-}"
    NODE_INPUT_SSH_USER="${GOWAVE_SSH_USER:-root}"
    NODE_INPUT_SSH_PORT="${GOWAVE_SSH_PORT:-22}"
    NODE_INPUT_VISION_DOMAIN="${GOWAVE_VISION_DOMAIN:-${VISION_DOMAIN:-}}"

    if [[ -n "${1:-}" ]]; then NODE_INPUT_NAME="$1"; fi
    if [[ -n "${2:-}" ]]; then NODE_INPUT_ADDRESS="$2"; fi
    if [[ -n "${3:-}" ]]; then NODE_INPUT_WORKER_DOMAIN="$3"; fi
    if [[ -n "${4:-}" ]]; then NODE_INPUT_REALITY_DOMAIN="$4"; fi
    if [[ -n "${5:-}" ]]; then NODE_INPUT_SSH_USER="$5"; fi
    if [[ -n "${6:-}" ]]; then NODE_INPUT_SSH_PORT="$6"; fi
    if [[ -n "${7:-}" ]]; then NODE_INPUT_VISION_DOMAIN="$7"; fi

    preflight_require_inputs node \
        "$NODE_INPUT_NAME" "$NODE_INPUT_ADDRESS" "$NODE_INPUT_WORKER_DOMAIN" \
        "$NODE_INPUT_REALITY_DOMAIN" "$NODE_INPUT_SSH_USER" "$NODE_INPUT_SSH_PORT" \
        "$NODE_INPUT_VISION_DOMAIN"
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

            # A zero-argument invocation keeps its usage hint; when inputs were
            # supplied, the contract below is what names a missing field.
            if (( ${#positional_args[@]} == 0 )) && [[ -z "${GOWAVE_NODE_NAME:-}${GOWAVE_NODE_IP:-}${GOWAVE_WORKER_DOMAIN:-}${GOWAVE_REALITY_DOMAIN:-}" ]]; then
                echo "Usage: gowave-auto.sh node add [--vision-domain <domain>] <worker-name> <worker-ip> <worker-domain> <reality-domain> [ssh-user] [ssh-port]" >&2
                echo "Every input may also come from GOWAVE_NODE_NAME, GOWAVE_NODE_IP, GOWAVE_WORKER_DOMAIN, GOWAVE_REALITY_DOMAIN, GOWAVE_SSH_USER, GOWAVE_SSH_PORT and GOWAVE_VISION_DOMAIN." >&2
                return 1
            fi
            resolve_node_inputs \
                "${positional_args[0]:-}" "${positional_args[1]:-}" "${positional_args[2]:-}" \
                "${positional_args[3]:-}" "${positional_args[4]:-}" "${positional_args[5]:-}" \
                "$vision_domain" || return $?
            local name="$NODE_INPUT_NAME"
            local ip="$NODE_INPUT_ADDRESS"
            local worker_domain="$NODE_INPUT_WORKER_DOMAIN"
            local reality_domain="$NODE_INPUT_REALITY_DOMAIN"
            local ssh_user="$NODE_INPUT_SSH_USER"
            local ssh_port="$NODE_INPUT_SSH_PORT"
            vision_domain="$NODE_INPUT_VISION_DOMAIN"

            validate_acme_server "${GOWAVE_ACME_SERVER:-}" || return 1

            local panel_ip panel_ipv6
            panel_ip=$(resolve_panel_ipv4) || return 1
            panel_ipv6=$(resolve_panel_ipv6) || return 1
            if [[ -z "$panel_ip" && -z "$panel_ipv6" ]]; then
                echo "Error: unable to determine a public Panel IP address; refusing an untrusted firewall fallback." >&2
                return 1
            fi
            local node_port=3002
            local acme_tx_id="worker_install_${name}_$(date +%s)_${BASHPID}"

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

            # Resolve the local Worker secret before creating any API-side effects.
            # A local config/read failure must not strand a partially registered node.
            local secret_key
            if ! secret_key=$(extract_secret_key "$GOWAVE_DIR"); then
                echo "Error: unable to extract the Worker secret; no API changes were made." >&2
                return 1
            fi

            # 2. Register the node using argv for data and FD 3 for the password.
            # User-controlled values are never interpolated into Python source.
            local register_rc=0
            PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
                XRAY_SERVER_VERSION="${XRAY_SERVER_VERSION:-}" \
                GOWAVE_MIHOMO_X25519="${GOWAVE_MIHOMO_X25519:-}" \
                GOWAVE_REALITY_FINGERPRINT="${GOWAVE_REALITY_FINGERPRINT:-}" \
                python3 - \
                "$SCRIPT_DIR" "$name" "$ip" "$worker_domain" "$reality_domain" \
                "$node_port" "$admin_user" "$JOURNAL_FILE" "$STATE_FILE" "$vision_domain" 3<<< "$admin_pass" <<'PY' || register_rc=$?
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
from modules.api_client import GoWaveClient, GoWaveNodeNameTaken, atomic_write_state, confirmed_country
from modules.recovery import write_journal_atomically

state_data = json.loads(open(state_path, encoding="utf-8").read())
nodes = state_data.get("nodes", [])
if not isinstance(nodes, list):
    raise SystemExit("state.json nodes must be an array.")
# The country this node's entry already holds. A registration that asked nobody
# — a positional `node add`, a retry with no terminal — keeps that answer rather
# than dropping the operator's confirmed label from the managed identity.
previous_country = ""
previous_hosts = []
existing_index = None
for index, known in enumerate(nodes):
    if not isinstance(known, dict) or known.get("name") != name:
        continue
    # The same node answering again: the retry keeps its uuid and its address.
    if str(known.get("address") or "") == address:
        previous_country = str(known.get("country") or "")
        recorded_hosts = known.get("hostUuids")
        if isinstance(recorded_hosts, list):
            previous_hosts = [str(u) for u in recorded_hosts if u]
        existing_index = index
        break
    raise SystemExit(
        f"state.json already registers the name {name} for the node at "
        f"{known.get('address')}; choose another name or remove that entry first."
    )
node_country = confirmed_country(os.environ.get("GOWAVE_NODE_COUNTRY"), previous_country)

client = GoWaveClient("http://127.0.0.1:3000")
client.login(admin_user, admin_password)

# The Panel is the authority on names, and a name it already holds belongs to
# that node: adopting it would rewrite another server's address and move its
# traffic endpoint. The refusal is therefore printed here, before the profile,
# the inbounds and the Host records exist, so there is nothing to roll back.
for held in client.list_nodes():
    if not isinstance(held, dict) or str(held.get("name", "")).lower() != name.lower():
        continue
    if str(held.get("address") or "") == address and str(held.get("port")) == port:
        continue  # this node, at this address: the retry of a known identity
    sys.stderr.write(
        f"Error: the Panel already has a node named {held.get('name')} at "
        f"{held.get('address')}:{held.get('port')}; choose another name or delete that node first.\n"
    )
    raise SystemExit(3)

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
    journal["state"] = "NODE_ADD_APPLYING"
    journal["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
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

# The pre-check above ran before the profile existed; a collision that appears
# between the two is still the client's refusal, and the nonzero exit is what
# makes the shell roll the profile back instead of leaving it behind.
try:
    node_uuid = client.associate_node(name, address, int(port), profile_uuid, inbound_uuids)
except GoWaveNodeNameTaken as error:
    raise SystemExit(f"Error: {error}. Choose another name or delete that node first.")
journal["entities"] = client.transaction_entities
write_journal_atomically(journal_path, journal)

squad_uuid = client.provision_internal_squad("Default MVP Squad", inbound_uuids)
journal["entities"] = client.transaction_entities
write_journal_atomically(journal_path, journal)
if not squad_uuid:
    raise SystemExit(
        "The Panel returned no internal squad identifier; refusing to submit a host record with a null squad."
    )
state_data["squadUuid"] = squad_uuid
# The Panel-only install created default-user before any inbound existed, so that
# user holds no squad and its subscription would answer "No Hosts Available".
# Attaching it here is what makes a Panel-only plan deliver the node's endpoints;
# a user that already holds a squad is left exactly as the operator set it.
client.attach_squad_to_user("default-user", squad_uuid)
journal["entities"] = client.transaction_entities
write_journal_atomically(journal_path, journal)
host_uuids = client.provision_hosts(
    profile_uuid, inbounds, node_uuid, squad_uuid,
    worker_domain, reality_domain, name,
    vision_domain=vision_domain or None,
    known_host_uuids=previous_hosts,
    country=node_country,
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
if node_country:
    node_entry["country"] = node_country
if host_uuids:
    node_entry["hostUuids"] = list(host_uuids)
# A retry of a node this file already registers updates that record. Appending a
# second entry for one identity would make every later read of `nodes` ambiguous
# about which record is the node, and would lose whatever the retry did not
# restate.
if existing_index is not None:
    merged = {**nodes[existing_index], **node_entry}
    if "visionDomain" not in node_entry:
        merged.pop("visionDomain", None)
    nodes[existing_index] = merged
else:
    nodes.append(node_entry)
state_data["nodes"] = nodes
atomic_write_state(state_data, state_path)

# Record that the local state and API entities are committed before remote dispatch.
journal["state"] = "NODE_ADD_VERIFYING"
journal["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
write_journal_atomically(journal_path, journal)
PY
            if (( register_rc == 3 )); then
                # Nothing was written, so there is nothing to roll back.
                echo "Worker name refused; the Panel and this host were not changed." >&2
                return 1
            fi
            if (( register_rc != 0 )); then
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


            # 4. Dispatch remote deployment strictly via SSH stdin
            local acme_test_ca_b64=""
            if [[ "${GOWAVE_ACME_TEST_MODE:-0}" == "1" && "${GOWAVE_ACME_SERVER:-}" == "$GOWAVE_ACME_TEST_ENDPOINT" ]]; then
                validate_acme_test_ca || return 1
                acme_test_ca_b64=$(base64 -w 0 "$GOWAVE_ACME_TEST_CA_FILE")
            fi
            if ! ACME_TX_ID="$acme_tx_id" PANEL_IP="$panel_ip" PANEL_IPV6="$panel_ipv6" NODE_PORT="$node_port" SECRET_KEY="$secret_key" GOWAVE_NODE_VERSION="${GOWAVE_NODE_VERSION:-latest}" \
                XRAY_SERVER_VERSION="${XRAY_SERVER_VERSION:-}" \
                GOWAVE_ACME_SERVER="${GOWAVE_ACME_SERVER:-}" \
                GOWAVE_ACME_TEST_MODE="${GOWAVE_ACME_TEST_MODE:-0}" \
                GOWAVE_ACME_TEST_CA_FILE="${GOWAVE_ACME_TEST_CA_FILE:-}" \
                GOWAVE_ACME_TEST_CA_SHA256="${GOWAVE_ACME_TEST_CA_SHA256:-}" \
                GOWAVE_ACME_TEST_CA_B64="$acme_test_ca_b64" \
                GOWAVE_PODMAN_TEST_MODE="${GOWAVE_PODMAN_TEST_MODE:-0}" \
                GOWAVE_NODE_INSTALLER_COMMIT="${GOWAVE_NODE_INSTALLER_COMMIT:-}" \
                GOWAVE_NODE_INSTALLER_SHA256="${GOWAVE_NODE_INSTALLER_SHA256:-}" \
                VISION_DOMAIN="$vision_domain" \
                GOWAVE_WORKER_LEASE_TOKEN="${GOWAVE_WORKER_LEASE_TOKEN:-}" \
                SSH_KNOWN_HOSTS="$known_hosts" "$SCRIPT_DIR/gowave-node-auto.sh" remote_payload "$ip" "$ssh_port" "$worker_domain" "$reality_domain" "$ssh_user"; then
                echo "Remote Worker deployment failed; rolling back Worker host configuration and Panel API entities." >&2
                finalize_failed_node_add "$name" "$ip" "$ssh_port" \
                    "$worker_domain" "$reality_domain" "$ssh_user" "$acme_tx_id" || true
                return 1
            fi

            # 5. Commit transaction. If the durable commit record fails after
            # remote deployment succeeded, compensate both remote and API state.
            if ! python3 -c "
import sys, json, time
for p in ['$SCRIPT_DIR', '/opt/gowave-auto-nginx']:
    if p not in sys.path:
        sys.path.insert(0, p)
from modules.recovery import write_journal_atomically
jdata = json.load(open('$JOURNAL_FILE'))
jdata['state'] = 'NODE_ADD_COMMITTED'
jdata['timestamp'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
write_journal_atomically('$JOURNAL_FILE', jdata)
"; then
                echo "CRITICAL: Worker deployment succeeded but the commit journal could not be persisted; compensating both sides." >&2
                finalize_failed_node_add "$name" "$ip" "$ssh_port" \
                    "$worker_domain" "$reality_domain" "$ssh_user" "$acme_tx_id" || true
                return 1
            fi
            if ! ACME_TX_ID="$acme_tx_id" SSH_KNOWN_HOSTS="$known_hosts" \
                GOWAVE_WORKER_LEASE_TOKEN="${GOWAVE_WORKER_LEASE_TOKEN:-}" \
                "$SCRIPT_DIR/gowave-node-auto.sh" remote_finalize "$ip" "$ssh_port" "$ssh_user"; then
                echo "WARNING: Worker '$name' is committed and deployed, but its ACME recovery snapshot could not be finalized; snapshot retained for manual cleanup." >&2
            fi
            echo "Worker '$name' successfully added and deployed."
            ;;
        list)
            if [[ -f "$STATE_FILE" ]]; then
                python3 -c "
import json
data = json.load(open('$STATE_FILE'))
nodes = data.get('nodes', [])
if not nodes:
    print('No nodes are registered.')
else:
    print(f'Total configured nodes: {len(nodes)}')
    for n in nodes:
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
            panel_ip=$(resolve_panel_ipv4) || return 1
            panel_ipv6=$(resolve_panel_ipv6) || return 1
            local node_port=3002
            PANEL_IP="$panel_ip" PANEL_IPV6="$panel_ipv6" NODE_PORT="$node_port" SSH_KNOWN_HOSTS="$known_hosts" \
                VISION_DOMAIN="$vision_domain" \
                GOWAVE_WORKER_LEASE_TOKEN="${GOWAVE_WORKER_LEASE_TOKEN:-}" \
                "$SCRIPT_DIR/gowave-node-auto.sh" remote_rollback "$ip" "$ssh_port" "$worker_domain" "$reality_domain" "$ssh_user"
            ;;
        reapply)
            acquire_lock
            local name="${1:-}"
            local ssh_user="${2:-root}"
            local ssh_port="${3:-22}"

            if [[ -z "$name" ]]; then
                echo "Usage: gowave-auto.sh node reapply <worker-name> [ssh-user] [ssh-port]" >&2
                return 1
            fi
            if [[ ! -f "$STATE_FILE" ]]; then
                echo "Error: no state.json found; no Worker is registered to re-apply." >&2
                return 1
            fi
            if [[ ! "$ssh_port" =~ ^[0-9]+$ ]] || (( ssh_port < 1 || ssh_port > 65535 )); then
                echo "Error: SSH port must be between 1 and 65535." >&2
                return 2
            fi
            if [[ ! "$ssh_user" =~ ^[A-Za-z_][A-Za-z0-9._-]{0,31}$ ]]; then
                echo "Error: invalid SSH username." >&2
                return 2
            fi

            # The host is already registered with the Panel, so a re-apply
            # converges it with the identity the operator added instead of
            # registering a second node: every argument is read back from
            # state.json and the Panel side is left untouched.
            local identity_text=""
            if ! identity_text=$(PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 - "$STATE_FILE" "$name" <<'PY'
import json
import sys

state_path, name = sys.argv[1:]
nodes = json.load(open(state_path, encoding="utf-8")).get("nodes", [])
matches = [item for item in nodes if isinstance(item, dict) and item.get("name") == name]
if not matches:
    raise SystemExit(f"Worker name is not registered in state.json: {name}")
node = matches[0]
for field in ("address", "port", "workerDomain", "realityDomain"):
    if not node.get(field):
        raise SystemExit(f"state.json node '{name}' is missing {field}.")
print(f"address={node['address']}")
print(f"port={node['port']}")
print(f"worker_domain={node['workerDomain']}")
print(f"reality_domain={node['realityDomain']}")
print(f"vision_domain={node.get('visionDomain') or ''}")
PY
            ); then
                echo "Error: cannot re-apply Worker '$name': $identity_text" >&2
                return 1
            fi
            # Read by label: a name may legitimately be empty (a Worker without
            # Vision), and command substitution drops trailing empty lines.
            local ip="" node_port="" worker_domain="" reality_domain="" vision_domain=""
            while IFS='=' read -r key value; do
                case "$key" in
                    address) ip="$value" ;;
                    port) node_port="$value" ;;
                    worker_domain) worker_domain="$value" ;;
                    reality_domain) reality_domain="$value" ;;
                    vision_domain) vision_domain="$value" ;;
                esac
            done <<< "$identity_text"
            if [[ -z "$ip" || -z "$node_port" || -z "$worker_domain" || -z "$reality_domain" ]]; then
                echo "Error: state.json node '$name' did not yield its identity." >&2
                return 1
            fi
            if [[ ! "$node_port" =~ ^[0-9]+$ ]] || (( node_port < 1 || node_port > 65535 )); then
                echo "Error: state.json node '$name' carries an invalid port: $node_port" >&2
                return 1
            fi

            local known_hosts="${SSH_KNOWN_HOSTS:-/root/.ssh/known_hosts}"
            local host_key="$ip"
            if [[ "$ssh_port" != "22" ]]; then
                host_key="[$ip]:$ssh_port"
            fi
            if [[ ! -s "$known_hosts" ]] || ! ssh-keygen -F "$host_key" -f "$known_hosts" >/dev/null 2>&1; then
                echo "Error: SSH host key for $host_key is not pre-pinned in $known_hosts." >&2
                echo "Verify the fingerprint out of band before re-applying." >&2
                return 1
            fi

            local secret_key
            if ! secret_key=$(extract_secret_key "$GOWAVE_DIR"); then
                echo "Error: unable to extract the Worker secret; the host was not touched." >&2
                return 1
            fi
            validate_acme_server "${GOWAVE_ACME_SERVER:-}" || return 1
            local panel_ip panel_ipv6
            panel_ip=$(resolve_panel_ipv4) || return 1
            panel_ipv6=$(resolve_panel_ipv6) || return 1
            if [[ -z "$panel_ip" && -z "$panel_ipv6" ]]; then
                echo "Error: unable to determine a public Panel IP address; refusing an untrusted firewall fallback." >&2
                return 1
            fi
            local acme_test_ca_b64=""
            if [[ "${GOWAVE_ACME_TEST_MODE:-0}" == "1" && "${GOWAVE_ACME_SERVER:-}" == "$GOWAVE_ACME_TEST_ENDPOINT" ]]; then
                validate_acme_test_ca || return 1
                acme_test_ca_b64=$(base64 -w 0 "$GOWAVE_ACME_TEST_CA_FILE")
            fi

            # The payload is streamed again instead of rebuilt: the Worker keeps
            # no copy of it, so this is the only path that reconverges a host
            # that is already installed.
            local acme_tx_id="worker_install_reapply_$(date +%s)_${BASHPID}"
            echo "Re-applying the Worker payload to '$name' ($ip:$ssh_port)..."
            if ! ACME_TX_ID="$acme_tx_id" PANEL_IP="$panel_ip" PANEL_IPV6="$panel_ipv6" NODE_PORT="$node_port" SECRET_KEY="$secret_key" GOWAVE_NODE_VERSION="${GOWAVE_NODE_VERSION:-latest}" \
                XRAY_SERVER_VERSION="${XRAY_SERVER_VERSION:-}" \
                GOWAVE_ACME_SERVER="${GOWAVE_ACME_SERVER:-}" \
                GOWAVE_ACME_TEST_MODE="${GOWAVE_ACME_TEST_MODE:-0}" \
                GOWAVE_ACME_TEST_CA_FILE="${GOWAVE_ACME_TEST_CA_FILE:-}" \
                GOWAVE_ACME_TEST_CA_SHA256="${GOWAVE_ACME_TEST_CA_SHA256:-}" \
                GOWAVE_ACME_TEST_CA_B64="$acme_test_ca_b64" \
                GOWAVE_PODMAN_TEST_MODE="${GOWAVE_PODMAN_TEST_MODE:-0}" \
                GOWAVE_NODE_INSTALLER_COMMIT="${GOWAVE_NODE_INSTALLER_COMMIT:-}" \
                GOWAVE_NODE_INSTALLER_SHA256="${GOWAVE_NODE_INSTALLER_SHA256:-}" \
                VISION_DOMAIN="$vision_domain" \
                GOWAVE_WORKER_LEASE_TOKEN="${GOWAVE_WORKER_LEASE_TOKEN:-}" \
                SSH_KNOWN_HOSTS="$known_hosts" "$SCRIPT_DIR/gowave-node-auto.sh" remote_payload "$ip" "$ssh_port" "$worker_domain" "$reality_domain" "$ssh_user"; then
                echo "Error: re-applying Worker '$name' failed; its Panel registration is unchanged." >&2
                return 1
            fi
            if ! ACME_TX_ID="$acme_tx_id" SSH_KNOWN_HOSTS="$known_hosts" \
                GOWAVE_WORKER_LEASE_TOKEN="${GOWAVE_WORKER_LEASE_TOKEN:-}" \
                "$SCRIPT_DIR/gowave-node-auto.sh" remote_finalize "$ip" "$ssh_port" "$ssh_user"; then
                echo "WARNING: Worker '$name' was re-applied, but its ACME recovery snapshot could not be finalized." >&2
            fi
            echo "Worker '$name' re-applied."
            ;;
        *)
            echo "Usage: gowave-auto.sh node {add|list|reapply|rollback}"
            ;;
    esac
}

cmd_domain_change() {
    acquire_lock
    local install_mode
    install_mode=$(installation_mode_from_state)
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
    srv_ip=$(resolve_panel_ipv4) || return 1
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

    local cover_domain=""
    cover_domain=$(cover_domain_for "$new_panel_domain" "$srv_ip")

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

    generate_bootstrap_acme_vhost "$new_panel_domain" "$new_reality_domain" "/etc/nginx/conf.d/00-bootstrap-acme.conf" "/proc/net/if_inet6" "" "$cover_domain"
    reload_nginx_strict || { rollback_domain_change "bootstrap NGINX activation failed"; return 1; }

    local certbot_extra_args=()
    if [[ -n "${GOWAVE_ACME_SERVER:-}" ]]; then
        certbot_extra_args+=(--server "$GOWAVE_ACME_SERVER")
    fi

    if ! run_certbot certonly --webroot -w "$ACME_WEBROOT" -d "$new_panel_domain" --cert-name "$new_panel_domain" --non-interactive --agree-tos --register-unsafely-without-email --keep-until-expiring "${certbot_extra_args[@]}"; then
        rollback_domain_change "ACME issuance failed for panel domain"; return 1
    fi
    local new_reality_cert_args=(-d "$new_reality_domain")
    local new_reality_cert_flags=()
    if [[ -n "$cover_domain" ]]; then
        new_reality_cert_args+=(-d "$cover_domain" -d "www.$cover_domain")
        new_reality_cert_flags+=(--expand)
    fi
    if ! run_certbot certonly --webroot -w "$ACME_WEBROOT" "${new_reality_cert_args[@]}" "${new_reality_cert_flags[@]}" --cert-name "$new_reality_domain" --non-interactive --agree-tos --register-unsafely-without-email --keep-until-expiring "${certbot_extra_args[@]}"; then
        rollback_domain_change "ACME issuance failed for REALITY domain"; return 1
    fi
    verify_acme_certificate "$new_panel_domain" || { rollback_domain_change "invalid panel certificate"; return 1; }
    verify_acme_certificate "$new_reality_domain" || { rollback_domain_change "invalid REALITY certificate"; return 1; }
    if [[ -n "$cover_domain" ]] && ! verify_acme_certificate "$cover_domain" "/etc/letsencrypt/live/$new_reality_domain"; then
        rollback_domain_change "REALITY certificate does not cover the camouflage apex"; return 1
    fi

    rm -f /etc/nginx/conf.d/00-bootstrap-acme.conf
    generate_stream_config "$new_panel_domain" "$new_reality_domain" "/etc/nginx/stream-enabled/gowave-stream.conf" "/proc/net/if_inet6" "" "$cover_domain" "$install_mode"
    generate_production_http_vhost "$new_panel_domain" "$new_reality_domain" "/etc/nginx/conf.d/gowave-http.conf" "/proc/net/if_inet6" "" "$cover_domain"
    generate_panel_https_vhost "$new_panel_domain"
    generate_decoy_vhost "$new_reality_domain" "/etc/nginx/conf.d/gowave-decoy.conf" nginx "$COVER_REALITY_ROOT" "$cover_domain"
    sed -i "s/^PANEL_DOMAIN=.*/PANEL_DOMAIN=$new_panel_domain/" "$GOWAVE_DIR/.env"
    sed -i "s|^SUB_PUBLIC_DOMAIN=.*|SUB_PUBLIC_DOMAIN=$new_panel_domain/api/sub|" "$GOWAVE_DIR/.env"

    PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 - "$JOURNAL_FILE" <<'PY'
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
        systemctl stop --no-ask-password gowave-update.path gowave-update.service gowave.service gowave-node.service 2>/dev/null || true
        systemctl disable --no-ask-password gowave-update.path gowave-update.service gowave.service gowave-node.service gowave-recover.service gowave-recover-provision.service 2>/dev/null || true
        rm -f /etc/systemd/system/gowave-update.path \
              /etc/systemd/system/gowave-update.service \
              /etc/systemd/system/gowave.service \
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
    # v2rayNG and NekoBox parse a subscription body as base64 share links only; the
    # /v2ray-json array of full configs is rejected by their subscription updater.
    echo "v2rayNG / NekoBox / Hiddify / v2rayN 6+ (base64 share links):"
    echo "  https://$panel_domain/api/sub/$short_uuid"
    echo ""
    echo "Xray JSON config array (file or JSON import, not a v2rayNG subscription):"
    echo "  https://$panel_domain/api/sub/$short_uuid/v2ray-json"
    echo ""
    echo "Mihomo / Clash Verge Rev / FlClash (Meta YAML):"
    echo "  https://$panel_domain/api/sub/$short_uuid/mihomo"
    echo ""
    echo "Clash / Clash Meta for Android (compact YAML):"
    echo "  https://$panel_domain/api/sub/$short_uuid/clash"
    echo ""
    echo "NOTE: Upstream GoWave strictly enforces a non-empty User-Agent header!"
    echo "Verification curl examples:"
    echo "  curl -fsSL -H 'User-Agent: v2rayNG/1.8.5' 'https://$panel_domain/api/sub/$short_uuid'"
    echo "  curl -fsSL -H 'User-Agent: ClashMeta/1.19' 'https://$panel_domain/api/sub/$short_uuid/mihomo'"
    echo "================================================================================"
}

# Detect local Panel installation and return its domain if found.
# Returns 0 and prints the Panel domain if exactly one local Panel is found.
# Returns 1 if no local Panel or ambiguous (multiple).
# Returns 2 if Panel service is not active.
detect_local_panel() {
    # Check if Panel service is active
    if ! systemctl is-active --quiet gowave.service 2>/dev/null; then
        return 2
    fi

    # Try to get Panel domain from NGINX config
    local panel_domain=""
    if [[ -f /etc/nginx/conf.d/gowave-panel.conf ]]; then
        panel_domain=$(grep -E '^[[:space:]]*server_name[[:space:]]' /etc/nginx/conf.d/gowave-panel.conf 2>/dev/null | head -1 | awk '{print $2}' | sed 's/;//')
    fi

    # Fallback: try to get from state.json
    if [[ -z "$panel_domain" && -f /opt/gowave/state.json ]]; then
        panel_domain=$(python3 -c "
import json, sys
try:
    data = json.load(open('/opt/gowave/state.json'))
    panel = data.get('panel', {})
    if isinstance(panel, dict):
        print(panel.get('domain', ''))
except Exception:
    pass
" 2>/dev/null)
    fi

    # Fallback: try to get from Panel's .env
    if [[ -z "$panel_domain" && -f /opt/gowave/.env ]]; then
        panel_domain=$(grep '^PANEL_DOMAIN=' /opt/gowave/.env 2>/dev/null | cut -d= -f2-)
    fi

    if [[ -n "$panel_domain" ]]; then
        printf '%s\n' "$panel_domain"
        return 0
    fi

    return 1
}

# Interactive add-node flow with local Panel detection and verification.
wizard_add_node_to_panel() {
    local panel_domain="" panel_is_local="no" confirm=""
    local detected_rc=0
    local wname="" wip="" wdom="" rdom=""

    # This flow has an operator in front of it, so the Worker is asked where it
    # exits: the request leaves through the Worker's own outbound route, which is
    # the route its traffic takes and not the Panel's.
    local GOWAVE_COUNTRY_ASK="yes"

    # Try to detect local Panel. The helper reports "no local Panel" through
    # its status, so a bare assignment would end the menu under errexit.
    detected_rc=0
    panel_domain=$(detect_local_panel) || detected_rc=$?

    case $detected_rc in
        0)
            # Exactly one local Panel found
            panel_is_local="yes"
            printf '%s\n' "$(tf wizard.add_node.local_detected "$panel_domain")"
            read -r -p "$(t wizard.add_node.confirm_local)" confirm
            if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
                printf '%s\n' "$(t wizard.add_node.cancelled)"
                return 1
            fi
            ;;
        2)
            # Panel service not active
            printf '%s\n' "$(t wizard.add_node.no_local_service)"
            ;;
        1|*)
            # No local Panel or ambiguous
            printf '%s\n' "$(t wizard.add_node.no_local)"
            ;;
    esac

    # If we didn't confirm a local Panel, ask for Panel address
    if [[ "$panel_is_local" != "yes" ]]; then
        printf '%s\n' "$(t wizard.add_node.enter_panel)"
        read -r -p "$(t wizard.add_node.panel_address)" panel_domain
    fi

    # Verify Panel API identity and reachability before collecting SSH credentials
    # or mutating the Worker.
    if ! wizard_verify_panel_api "$panel_domain" "$panel_is_local"; then
        return 1
    fi

    # Now prompt for worker details. The name goes through the reader that holds
    # the Panel's own inventory when the Panel is local, so it is trimmed,
    # refused when blank, held to the rule the Panel enforces on registration,
    # and refused when the Panel already has a node by that name — `node add`
    # would otherwise reject it only after the SSH session and the temporary key
    # were already set up.
    wname=$(wizard_read_panel_worker_name "$panel_domain" "$panel_is_local") || return 1
    read -r -p "$(t menu.prompt.worker_ip)" wip
    read -r -p "$(t menu.prompt.worker_domain)" wdom
    read -r -p "$(t menu.prompt.camouflage_domain)" rdom

    # The same temporary-access onboarding the install runs: the operator types
    # the Worker's host-key fingerprint, the key is authorised with the password
    # and revoked when the registration ends. `node add` on its own cannot do
    # that — it requires the host key already pinned and key-only authentication.
    #
    # The outcome is this node's, not the Panel's: the Panel was installed
    # before this action and its state is untouched here. A registration the
    # Panel will not confirm is reported as what it is, never as a success.
    local record="" state="" first="" second="" add_rc=0
    _wizard_onboard_record record "$wdom" "$rdom" "" "$wname" "$wip" \
        "$panel_domain" "$panel_is_local" || add_rc=$?
    state=""
    IFS=$'\t' read -r _ state first second <<< "$record"
    case "$state" in
        VERIFIED)
            printf '%s\n' "$(tf wizard.add_node.result_verified "$wname" "$first" "$second")"
            ;;
        UNVERIFIED)
            printf '%s\n' "$(tf wizard.add_node.result_unverified "$wname")"
            ;;
        *)
            printf '%s\n' "$(tf wizard.add_node.result_failed "$wname" \
                "${first:-unknown}" "$(_wizard_failure_reason "${first:-unknown}" "$second")")" >&2
            ;;
    esac
    return "$add_rc"
}

# An interactive screen stays on screen until the operator acknowledges it: the
# menu starts with `clear`, so a status or a result that ended the branch was
# erased before anyone could read it. A run with no terminal returns at once —
# a positional `status` from a script or a CI case has nobody to press Enter.
menu_pause() {
    [[ -t 0 ]] || return 0
    printf '%s' "$(t menu.prompt.return)" >&2
    IFS= read -r _ || return 0
    return 0
}

# One menu action. A failure is named and the session continues: dying on a
# cancelled plan or a refused step would take the language choice and every
# answer with it, which is the dead end this menu exists to avoid. The positional
# CLI is untouched and still exits with the step's own code.
menu_action() {
    local code=0
    "$@" || code=$?
    if (( code != 0 )); then
        printf '%s\n' "$(tf menu.action.failed "$code")" >&2
    fi
    menu_pause
    return 0
}

main_menu() {
    local lang
    lang=$(wizard_language)
    # A terminal without TERM is still a terminal: `clear` failing must not take
    # the menu down with it, and the redraw is what hides the screen just read.
    clear 2>/dev/null || true
    tf menu.title
    echo ""
    printf ' 1) %s\n' "$(t menu.option.status)"
    printf ' 2) %s\n' "$(t menu.option.install)"
    printf ' 3) %s\n' "$(t menu.option.add_node)"
    printf ' 4) %s\n' "$(t menu.option.change_domains)"
    printf ' 5) %s\n' "$(t menu.option.switch_channel)"
    printf ' 6) %s\n' "$(t menu.option.backup)"
    printf ' 7) %s\n' "$(t menu.option.restore)"
    printf ' 8) %s\n' "$(t menu.option.user_links)"
    printf ' 9) %s\n' "$(t menu.option.uninstall)"
    printf ' 0) %s\n' "$(t menu.option.exit)"
    echo ""
    local choice
    if ! read -r -p "$(t menu.prompt)" choice; then
        # End of input leaves the loop the way option 0 does, with a newline of
        # our own so the shell prompt is not glued to the menu text.
        printf '\n'
        exit 0
    fi
    case "$choice" in
        1) menu_action cmd_status ;;
        2) menu_action cmd_install ;;
        3) menu_action wizard_add_node_to_panel ;;
        4)
            read -r -p "$(t menu.prompt.new_panel_domain)" np
            read -r -p "$(t menu.prompt.new_camouflage_domain)" nr
            menu_action cmd_domain_change "$np" "$nr"
            ;;
        5)
            read -r -p "$(t menu.prompt.target_channel)" tch
            menu_action switch_channel "$tch"
            ;;
        6) menu_action "$SCRIPT_DIR/assets/backup/gowave-backup.sh" backup ;;
        7)
            read -r -p "$(t menu.prompt.archive_path)" arch_path
            menu_action "$SCRIPT_DIR/assets/backup/gowave-backup.sh" restore "$arch_path"
            ;;
        8)
            read -r -p "$(t menu.prompt.username)" uid
            menu_action cmd_user_links "${uid:-default-user}"
            ;;
        9) menu_action cmd_uninstall ;;
        0) exit 0 ;;
        *) echo "Invalid option." ;;
    esac
}

# Interactive entrypoint: select language first, then show menu
cmd_interactive() {
    # If language is not pre-configured and no terminal, print usage and exit non-zero
    local configured="${GOWAVE_WIZARD_LANG:-}"
    if [[ -z "$configured" || ! $(wizard_language_for "$configured" >/dev/null 2>&1; echo $?) -eq 0 ]]; then
        if [[ ! -t 0 ]]; then
            printf 'Usage: gowave-auto.sh {status|health|install|node|channel|domain-change|backup|restore|uninstall|user links <id>|recover}\n' >&2
            return 2
        fi
    fi
    # Select language before any menu
    wizard_select_language || return 1
    # Loop the menu until the operator exits
    while true; do
        main_menu
    done
}

# Sourced by a fixture: the functions above are the subject, and the router below
# belongs to an execution. `return` leaves a sourced file; an executed one never
# reaches this branch, so the CLI is unchanged.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    return 0
fi

# CLI Entrypoint Router
if [[ $# -eq 0 ]]; then
    CURRENT_STEP="menu"
    cmd_interactive
else
    CURRENT_STEP="${1:-unknown command}"
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
