#!/usr/bin/env bash
# modules/wizard.sh - the interactive setup wizard
#
# Collects an installation plan from the operator, validates it, and hands the
# panel host back to cmd_install in the same shape the positional arguments
# produce. Nothing here mutates the host: the plan is data until cmd_install
# acts on it.
set -Eeuo pipefail

_wizard_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=modules/i18n.sh
source "$_wizard_dir/i18n.sh"
# The wizard validates a field through the same contract the positional path
# uses, so the same answer is refused on both.
# shellcheck source=modules/preflight.sh
source "$_wizard_dir/preflight.sh"
# SSH bootstrap for unauthenticated reachability check
# shellcheck source=modules/ssh_bootstrap.sh
source "$_wizard_dir/ssh_bootstrap.sh"

GOWAVE_PLAN_VARIANT=""
GOWAVE_PLAN_SHARED_DOMAIN="no"
GOWAVE_PLAN_PANEL_VISION="no"
GOWAVE_PLAN_PANEL_NAME=""
GOWAVE_PLAN_CAMOUFLAGE_NAME=""
GOWAVE_PLAN_VISION_NAME=""
GOWAVE_PLAN_EMAIL=""
GOWAVE_PLAN_NODE_COUNT=0
GOWAVE_PLAN_NODE_NAMES=()
GOWAVE_PLAN_NODE_CAMOUFLAGE=()
GOWAVE_PLAN_NODE_VISION=()

wizard_reset_plan() {
    GOWAVE_PLAN_VARIANT=""
    GOWAVE_PLAN_SHARED_DOMAIN="no"
    GOWAVE_PLAN_PANEL_VISION="no"
    GOWAVE_PLAN_PANEL_NAME=""
    GOWAVE_PLAN_CAMOUFLAGE_NAME=""
    GOWAVE_PLAN_VISION_NAME=""
    GOWAVE_PLAN_EMAIL=""
    GOWAVE_PLAN_NODE_COUNT=0
    GOWAVE_PLAN_NODE_NAMES=()
    GOWAVE_PLAN_NODE_CAMOUFLAGE=()
    GOWAVE_PLAN_NODE_VISION=()
}

# The wizard is the only entrypoint that reads answers, and only when the
# operator gave it nothing to work with.
wizard_should_run() {
    (( $# == 0 )) && [[ -t 0 ]]
}

wizard_normalize_name() {
    local name="${1,,}"
    printf '%s' "${name%.}"
}

wizard_validate_hostname() {
    preflight_validate_hostname "$1"
}

wizard_validate_email() {
    preflight_validate_email "$1"
}

# Every name the plan already holds, as "owner<TAB>name".
_wizard_plan_pairs() {
    local i
    if [[ -n "$GOWAVE_PLAN_PANEL_NAME" ]]; then
        printf 'Panel host\t%s\n' "$GOWAVE_PLAN_PANEL_NAME"
    fi
    if [[ -n "$GOWAVE_PLAN_CAMOUFLAGE_NAME" ]]; then
        printf 'Panel camouflage\t%s\n' "$GOWAVE_PLAN_CAMOUFLAGE_NAME"
    fi
    if [[ -n "$GOWAVE_PLAN_VISION_NAME" ]]; then
        printf 'Panel Vision\t%s\n' "$GOWAVE_PLAN_VISION_NAME"
    fi
    for i in "${!GOWAVE_PLAN_NODE_NAMES[@]}"; do
        printf 'node %s\t%s\n' "$((i + 1))" "${GOWAVE_PLAN_NODE_NAMES[$i]}"
        if [[ -n "${GOWAVE_PLAN_NODE_CAMOUFLAGE[$i]}" ]]; then
            printf 'node %s camouflage\t%s\n' "$((i + 1))" "${GOWAVE_PLAN_NODE_CAMOUFLAGE[$i]}"
        fi
        if [[ -n "${GOWAVE_PLAN_NODE_VISION[$i]}" ]]; then
            printf 'node %s Vision\t%s\n' "$((i + 1))" "${GOWAVE_PLAN_NODE_VISION[$i]}"
        fi
    done
}

# Prints the owner of an already-used name and returns 1; returns 0 when free.
wizard_plan_name_owner() {
    local candidate owner name
    candidate=$(wizard_normalize_name "$1")
    while IFS=$'\t' read -r owner name; do
        [[ -n "$name" ]] || continue
        if [[ "$(wizard_normalize_name "$name")" == "$candidate" ]]; then
            printf '%s' "$owner"
            return 1
        fi
    done < <(_wizard_plan_pairs)
    return 0
}

_wizard_prompt_read() {
    local prompt="$1" answer=""
    printf '%s' "$prompt" >&2
    if ! IFS= read -r answer; then
        printf '\n' >&2
        return 1
    fi
    printf '%s' "$answer"
}

wizard_read_yes_no() {
    local prompt="$1" default="${2:-no}" answer
    while true; do
        answer=$(_wizard_prompt_read "$prompt") || return 1
        case "${answer,,}" in
            y|yes|д|да) return 0 ;;
            n|no|н|нет) return 1 ;;
            "") if [[ "$default" == "yes" ]]; then return 0; else return 1; fi ;;
            *) printf '%s\n' "$(t wizard.yes_no.invalid)" >&2 ;;
        esac
    done
}

wizard_read_hostname() {
    local prompt="$1" allow_empty="${2:-no}" answer
    while true; do
        answer=$(_wizard_prompt_read "$prompt") || return 1
        answer=$(wizard_normalize_name "$answer")
        if [[ -z "$answer" ]]; then
            if [[ "$allow_empty" == "yes" ]]; then
                return 0
            fi
            printf '%s\n' "$(t wizard.name.empty)" >&2
            continue
        fi
        if wizard_validate_hostname "$answer"; then
            printf '%s' "$answer"
            return 0
        fi
        printf '%s\n' "$(tf wizard.name.invalid "$answer")" >&2
    done
}

wizard_read_email() {
    local answer
    while true; do
        answer=$(_wizard_prompt_read "$(t wizard.name.email)") || return 1
        if wizard_validate_email "$answer"; then
            printf '%s' "$answer"
            return 0
        fi
        printf '%s\n' "$(t wizard.email.invalid)" >&2
    done
}

wizard_select_language() {
    local configured="${GOWAVE_WIZARD_LANG:-}" answer
    if [[ -n "$configured" ]] && wizard_language_for "$configured" >/dev/null 2>&1; then
        set_wizard_language "$configured"
        return 0
    fi
    while true; do
        answer=$(_wizard_prompt_read "$(t wizard.language.prompt)") || return 1
        if set_wizard_language "$answer"; then
            return 0
        fi
        printf '%s\n' "$(t wizard.language.invalid)" >&2
    done
}

wizard_select_variant() {
    local answer
    while true; do
        printf '%s\n' "$(t wizard.variant.prompt)" >&2
        printf '%s\n' "$(t wizard.variant.option.all_in_one)" >&2
        printf '%s\n' "$(t wizard.variant.option.panel_only)" >&2
        printf '%s\n' "$(t wizard.variant.option.multi_node)" >&2
        printf '%s\n' "$(t wizard.variant.trial_note)" >&2
        answer=$(_wizard_prompt_read "> ") || return 1
        case "${answer,,}" in
            1|all-in-one|all_in_one|aio)
                GOWAVE_PLAN_VARIANT="all-in-one"
                return 0
                ;;
            2|panel-only|panel_only|panel)
                GOWAVE_PLAN_VARIANT="panel-only"
                return 0
                ;;
            3|multi-node|multi_node|multi)
                GOWAVE_PLAN_VARIANT="multi-node"
                return 0
                ;;
            *)
                printf '%s\n' "$(t wizard.variant.invalid)" >&2
                ;;
        esac
    done
}

wizard_read_node_count() {
    local answer
    while true; do
        answer=$(_wizard_prompt_read "$(t wizard.nodes.prompt)") || return 1
        if [[ "$answer" =~ ^[0-9]+$ ]] && (( 10#$answer >= 1 )); then
            printf '%s' "$((10#$answer))"
            return 0
        fi
        printf '%s\n' "$(t wizard.nodes.invalid)" >&2
    done
}

# Registers one host. Validates the whole set before assigning anything, so a
# rejected camouflage name leaves the plan exactly as it was.
wizard_register_host() {
    local role="$1" panel_name="$2" camouflage="$3" vision="${4:-}"
    local -a names=() owners=()
    local i j taken

    names+=("$panel_name")
    owners+=("$(_wizard_owner_label "$role" "host")")
    names+=("$camouflage")
    owners+=("$(_wizard_owner_label "$role" "camouflage")")
    if [[ -n "$vision" ]]; then
        names+=("$vision")
        owners+=("$(_wizard_owner_label "$role" "Vision")")
    fi

    for i in "${!names[@]}"; do
        if ! wizard_validate_hostname "${names[$i]}"; then
            printf '%s\n' "$(tf wizard.name.invalid "${names[$i]}")" >&2
            return 1
        fi
        if taken=$(wizard_plan_name_owner "${names[$i]}"); then
            :
        else
            printf '%s\n' "$(tf wizard.name.duplicate "${names[$i]}" "$taken")" >&2
            return 1
        fi
        for j in "${!names[@]}"; do
            if (( j >= i )); then
                continue
            fi
            if [[ "$(wizard_normalize_name "${names[$j]}")" == "$(wizard_normalize_name "${names[$i]}")" ]]; then
                printf '%s\n' "$(tf wizard.name.duplicate "${names[$i]}" "${owners[$j]}")" >&2
                return 1
            fi
        done
    done

    if [[ "$role" == "panel" ]]; then
        GOWAVE_PLAN_PANEL_NAME="${names[0]}"
        GOWAVE_PLAN_CAMOUFLAGE_NAME="${names[1]}"
        GOWAVE_PLAN_VISION_NAME="${names[2]:-}"
        if [[ -n "$GOWAVE_PLAN_VISION_NAME" ]]; then
            GOWAVE_PLAN_PANEL_VISION="yes"
        else
            GOWAVE_PLAN_PANEL_VISION="no"
        fi
    else
        GOWAVE_PLAN_NODE_NAMES+=("${names[0]}")
        GOWAVE_PLAN_NODE_CAMOUFLAGE+=("${names[1]}")
        GOWAVE_PLAN_NODE_VISION+=("${names[2]:-}")
    fi
    return 0
}

_wizard_owner_label() {
    local role="$1" kind="$2"
    local index=$(( ${#GOWAVE_PLAN_NODE_NAMES[@]} + 1 ))
    if [[ "$role" == "panel" ]]; then
        case "$kind" in
            host) printf 'the Panel host' ;;
            camouflage) printf 'the Panel camouflage' ;;
            *) printf 'the Panel Vision' ;;
        esac
    else
        case "$kind" in
            host) printf 'node %s' "$index" ;;
            camouflage) printf 'node %s camouflage' "$index" ;;
            *) printf 'node %s Vision' "$index" ;;
        esac
    fi
}

# C = 2 + v_panel + 2N + k.
wizard_certificate_count() {
    local panel_vision="$1" nodes="$2" vision_nodes="$3"
    local count=2
    if [[ "$panel_vision" == "yes" ]]; then
        count=$((count + 1))
    fi
    count=$((count + 2 * nodes + vision_nodes))
    printf '%s' "$count"
}

# Largest node count that still fits the 50-per-7-days ceiling.
# vision_mode: none (k=0), all (k=N), or fixed (k=$3).
wizard_certificate_ceiling() {
    local panel_vision="$1" vision_mode="${2:-none}" fixed_k="${3:-0}"
    local nodes=0 k=0
    while true; do
        case "$vision_mode" in
            none) k=0 ;;
            all) k=$nodes ;;
            *) k=$fixed_k ;;
        esac
        if (( $(wizard_certificate_count "$panel_vision" "$nodes" "$k") > 50 )); then
            printf '%s' "$((nodes - 1))"
            return 0
        fi
        nodes=$((nodes + 1))
    done
}

wizard_plan_vision_count() {
    local count=0 vision
    for vision in "${GOWAVE_PLAN_NODE_VISION[@]}"; do
        if [[ -n "$vision" ]]; then
            count=$((count + 1))
        fi
    done
    printf '%s' "$count"
}

wizard_plan_certificate_count() {
    wizard_certificate_count "$GOWAVE_PLAN_PANEL_VISION" "$GOWAVE_PLAN_NODE_COUNT" "$(wizard_plan_vision_count)"
}

wizard_plan_certificate_ceiling() {
    local vision_count
    vision_count=$(wizard_plan_vision_count)
    if (( vision_count == 0 )); then
        wizard_certificate_ceiling "$GOWAVE_PLAN_PANEL_VISION" none
    elif (( vision_count == GOWAVE_PLAN_NODE_COUNT )); then
        wizard_certificate_ceiling "$GOWAVE_PLAN_PANEL_VISION" all
    else
        wizard_certificate_ceiling "$GOWAVE_PLAN_PANEL_VISION" fixed "$vision_count"
    fi
}

# Separate registered domains spend separate budgets; a shared one has to fit
# the whole cluster inside the 50-per-7-days limit, and even then it needs an
# explicit confirmation because the rest of that domain competes for the same
# budget.
wizard_certificate_preflight() {
    local count ceiling message
    count=$(wizard_plan_certificate_count)
    if [[ "$GOWAVE_PLAN_SHARED_DOMAIN" != "yes" ]]; then
        printf '%s\n' "$(t wizard.cert.separate)"
        return 0
    fi
    printf '%s\n' "$(t wizard.cert.remaining_unknown)"
    ceiling=$(wizard_plan_certificate_ceiling)
    if (( count > 50 )); then
        printf '%s\n' "$(tf wizard.cert.shared_refused "$count")" >&2
        printf '%s\n' "$(tf wizard.cert.ceiling "$ceiling")" >&2
        return 1
    fi
    message=$(tf wizard.cert.shared_within "$count" "$ceiling")
    wizard_read_yes_no "$message" no
}

wizard_resolve_name() {
    local name="$1"
    local resolver="${GOWAVE_WIZARD_RESOLVER:-getent}"
    "$resolver" ahostsv4 "$name" >/dev/null 2>&1
}

wizard_resolve_ipv4() {
    local name="$1" address=""
    local resolver="${GOWAVE_WIZARD_RESOLVER:-getent}"
    address=$("$resolver" ahostsv4 "$name" 2>/dev/null | awk 'NR == 1 { print $1 }')
    if [[ -z "$address" ]]; then
        return 1
    fi
    printf '%s' "$address"
}

# Every planned name must answer before the first ACME order exists.
wizard_check_plan_names() {
    local -a names=() failed=()
    local name
    names+=("$GOWAVE_PLAN_PANEL_NAME")
    names+=("$GOWAVE_PLAN_CAMOUFLAGE_NAME")
    if [[ -n "$GOWAVE_PLAN_VISION_NAME" ]]; then
        names+=("$GOWAVE_PLAN_VISION_NAME")
    fi
    names+=("${GOWAVE_PLAN_NODE_NAMES[@]}")
    names+=("${GOWAVE_PLAN_NODE_CAMOUFLAGE[@]}")
    for name in "${GOWAVE_PLAN_NODE_VISION[@]}"; do
        if [[ -n "$name" ]]; then
            names+=("$name")
        fi
    done
    for name in "${names[@]}"; do
        if ! wizard_resolve_name "$name"; then
            failed+=("$name")
        fi
    done
    if (( ${#failed[@]} > 0 )); then
        printf '%s\n' "$(tf wizard.dns.failed "${failed[*]}")" >&2
        return 1
    fi
    return 0
}

# Checks SSH reachability for all worker nodes in the plan using ssh-keyscan.
# Returns 0 if all reachable, 1 if any unreachable. Prints status for each.
# Only runs during interactive wizard flow; the positional path never calls this.
wizard_check_ssh_reachable() {
    local i host port scanned expected
    local -a failed=()

    for i in "${!GOWAVE_PLAN_NODE_NAMES[@]}"; do
        host="${GOWAVE_PLAN_NODE_NAMES[$i]}"
        port="${GOWAVE_SSH_PORT:-22}"

        printf '%s\n' "$(tf ssh_reach.prompt "$host")"
        if ! scanned=$(ssh_bootstrap_scan "$host" "$port" 2>&1); then
            # Distinguish timeout/refused from other errors
            case "$scanned" in
                *"timed out"*|*"Timeout"*)
                    printf '%s\n' "$(tf ssh_reach.timeout "$host")" >&2
                    ;;
                *"refused"*|*"Connection refused"*)
                    printf '%s\n' "$(tf ssh_reach.refused "$host")" >&2
                    ;;
                *"banner"*)
                    printf '%s\n' "$(t ssh_reach.banner)" >&2
                    ;;
                *)
                    printf '%s\n' "$(tf ssh_reach.fail "$host")" >&2
                    ;;
            esac
            failed+=("$host")
            continue
        fi

        expected=$(printf '%s\n' "$scanned" | ssh_bootstrap_fingerprint)
        if [[ -z "$expected" ]]; then
            printf '%s\n' "$(t ssh_reach.banner)" >&2
            failed+=("$host")
            continue
        fi

        # If the plan carries a fingerprint, verify it matches
        if [[ -n "${GOWAVE_SSH_FINGERPRINT:-}" ]]; then
            if ! ssh_bootstrap_fingerprint_matches "$GOWAVE_SSH_FINGERPRINT" "$expected"; then
                printf '%s\n' "$(tf ssh_reach.mismatch "$GOWAVE_SSH_FINGERPRINT" "$host")" >&2
                failed+=("$host")
                continue
            fi
        fi

        printf '%s\n' "$(tf ssh_reach.ok "$host")"
    done

    if (( ${#failed[@]} > 0 )); then
        return 1
    fi
    return 0
}

# A name is the only thing a certificate can be checked against. A bare
# address is refused rather than probed: the Panel's certificate names its
# domain, and the stream demultiplexer answers a connection with no SNI from
# the decoy, so there is nothing on 443 an address could be verified with.
wizard_panel_address_is_bare() {
    local address="$1"
    [[ -n "$address" ]] || return 1
    case "$address" in
        *:*) return 0 ;;        # IPv6 literal, with or without a port
        *[!0-9.]*) return 1 ;;  # any other character makes it a name
        *[0-9]*) return 0 ;;    # digits and dots only: an IPv4 literal
        *) return 1 ;;
    esac
}

# The SHA-256 fingerprint of the certificate the host serves on 443. Empty when
# the handshake produces no certificate at all.
wizard_panel_certificate_fingerprint() {
    local address="$1"
    openssl s_client -connect "$address:443" -servername "$address" </dev/null 2>/dev/null \
        | openssl x509 -noout -fingerprint -sha256 2>/dev/null \
        | cut -d= -f2
}

# Verify Panel API identity and reachability.
#
# The Panel answers plaintext HTTP on 3000 and NGINX terminates TLS on 443 in
# front of it, so TLS has to be checked on 443 and the probe has to name the
# Panel's own health route. Speaking TLS to 3000 could never succeed, and
# /api/health is not a route the Panel answers, so an existing Panel could not
# be verified at all.
# Args: panel_address (domain or IP), panel_is_local (`yes` when the Panel
# service runs on this host, in which case the loopback answers without TLS)
# Returns 0 if verified, 1 otherwise.
wizard_verify_panel_api() {
    local panel_address="$1" panel_is_local="${2:-no}"
    local panel_url="" verify_mode="" fingerprint="" confirm="" rc=0
    local health="/api/system/health"

    if [[ -z "$panel_address" ]]; then
        printf '%s\n' "$(t wizard.add_node.enter_panel)" >&2
        return 1
    fi

    if [[ "$panel_is_local" == "yes" || "$panel_address" == "127.0.0.1" || "$panel_address" == "localhost" ]]; then
        panel_url="http://127.0.0.1:3000"
        verify_mode="local"
    elif wizard_panel_address_is_bare "$panel_address"; then
        printf '%s\n' "$(tf wizard.panel_verify.needs_domain "$panel_address")" >&2
        return 1
    else
        panel_url="https://$panel_address"
        verify_mode="remote"
    fi

    printf '%s\n' "$(tf wizard.panel_verify.checking "$panel_address")"

    if [[ "$verify_mode" == "local" ]]; then
        if ! curl -fsS --max-time 10 -o /dev/null "$panel_url$health" 2>/dev/null; then
            printf '%s\n' "$(t wizard.panel_verify.api_unreachable)" >&2
            return 1
        fi
        printf '%s\n' "$(tf wizard.panel_verify.success "$panel_address")"
        return 0
    fi

    # curl's own answer separates a certificate the trust store rejects (60, 51)
    # from an API that does not answer at all; the first is the case the
    # operator can settle by comparing a fingerprint.
    curl -fsS --max-time 10 -o /dev/null "$panel_url$health" 2>/dev/null || rc=$?
    if (( rc == 0 )); then
        printf '%s\n' "$(t wizard.panel_verify.tls_ok)"
        printf '%s\n' "$(tf wizard.panel_verify.success "$panel_address")"
        return 0
    fi
    if (( rc != 60 && rc != 51 )); then
        printf '%s\n' "$(t wizard.panel_verify.api_unreachable)" >&2
        return 1
    fi

    printf '%s\n' "$(t wizard.panel_verify.tls_failed)"
    fingerprint=$(wizard_panel_certificate_fingerprint "$panel_address")
    if [[ -z "$fingerprint" ]]; then
        printf '%s\n' "$(t wizard.panel_verify.no_cert)" >&2
        return 1
    fi

    printf '%s\n' "$(tf wizard.panel_verify.fingerprint "$fingerprint")"
    if ! read -r -p "$(t wizard.panel_verify.confirm_fingerprint)" confirm; then
        printf '\n'
        return 1
    fi
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        printf '%s\n' "$(t wizard.panel_verify.cancelled)" >&2
        return 1
    fi
    # Read the certificate again after the answer: confirming one value must
    # not authorise a request to whatever answers next.
    if [[ "$(wizard_panel_certificate_fingerprint "$panel_address")" != "$fingerprint" ]]; then
        printf '%s\n' "$(tf wizard.panel_verify.certificate_changed "$panel_address")" >&2
        return 1
    fi
    if ! curl -fsSk --max-time 10 -o /dev/null "$panel_url$health" 2>/dev/null; then
        printf '%s\n' "$(t wizard.panel_verify.api_unreachable)" >&2
        return 1
    fi

    printf '%s\n' "$(tf wizard.panel_verify.success "$panel_address")"
    return 0
}

wizard_plan_summary() {
    local i vision
    printf '%s\n' "$(t wizard.plan.summary)"
    printf '%s\n' "$(tf wizard.plan.host "Panel" "$GOWAVE_PLAN_PANEL_NAME" "$GOWAVE_PLAN_CAMOUFLAGE_NAME" "${GOWAVE_PLAN_VISION_NAME:-none}")"
    for i in "${!GOWAVE_PLAN_NODE_NAMES[@]}"; do
        vision="${GOWAVE_PLAN_NODE_VISION[$i]:-}"
        printf '%s\n' "$(tf wizard.plan.host "node $((i + 1))" "${GOWAVE_PLAN_NODE_NAMES[$i]}" "${GOWAVE_PLAN_NODE_CAMOUFLAGE[$i]}" "${vision:-none}")"
    done
    printf '%s\n' "$(tf wizard.plan.certificates "$(wizard_plan_certificate_count)")"
    if [[ "$GOWAVE_PLAN_SHARED_DOMAIN" == "yes" ]]; then
        printf '%s\n' "$(t wizard.plan.shared)"
    else
        printf '%s\n' "$(t wizard.plan.separate)"
    fi
}

wizard_collect_plan() {
    local panel camouflage vision i

    wizard_reset_plan
    wizard_select_language || return 1
    wizard_select_variant || return 1

    panel=$(wizard_read_hostname "$(t wizard.name.panel)") || return 1
    camouflage=$(wizard_read_hostname "$(t wizard.name.camouflage)") || return 1
    vision=""
    if [[ "$GOWAVE_PLAN_VARIANT" != "panel-only" ]]; then
        if wizard_read_yes_no "$(tf wizard.vision.prompt "$panel")" no; then
            vision=$(wizard_read_hostname "$(t wizard.name.vision)" yes) || return 1
        fi
    fi
    wizard_register_host panel "$panel" "$camouflage" "$vision" || return 1

    GOWAVE_PLAN_EMAIL=$(wizard_read_email) || return 1

    # A Panel-only host has no local node, so its workers are the whole traffic
    # plane; only the All-in-One variant ends at the local host.
    if [[ "$GOWAVE_PLAN_VARIANT" != "all-in-one" ]]; then
        GOWAVE_PLAN_NODE_COUNT=$(wizard_read_node_count) || return 1
        for ((i = 1; i <= GOWAVE_PLAN_NODE_COUNT; i++)); do
            local node_name node_camouflage node_vision=""
            node_name=$(wizard_read_hostname "$(tf wizard.name.worker "$i")") || return 1
            node_camouflage=$(wizard_read_hostname "$(tf wizard.name.worker_camouflage "$i")") || return 1
            if wizard_read_yes_no "$(tf wizard.vision.prompt "$node_name")" no; then
                node_vision=$(wizard_read_hostname "$(t wizard.name.vision)" yes) || return 1
            fi
            if ! wizard_register_host worker "$node_name" "$node_camouflage" "$node_vision"; then
                return 1
            fi
        done
    fi

    if wizard_read_yes_no "$(t wizard.shared_domain.prompt)" no; then
        GOWAVE_PLAN_SHARED_DOMAIN="yes"
    else
        GOWAVE_PLAN_SHARED_DOMAIN="no"
    fi

    wizard_plan_summary
    wizard_certificate_preflight || return 1
    wizard_check_plan_names || return 1
    if ! wizard_read_yes_no "$(t wizard.confirm)" no; then
        printf '%s\n' "$(t wizard.aborted)" >&2
        return 1
    fi
    return 0
}

# Plan review screen: displays the collected plan, allows editing any field,
# re-runs dependent validations, and returns only when the operator confirms.
wizard_review_plan() {
    local choice field new_value node_idx

    while true; do
        printf '\n%s\n' "$(t plan_review.title)"
        wizard_plan_summary
        printf '\n'

        # Build the list of editable fields - fixed order for predictability
        local -a field_keys=() field_labels=()
        field_keys+=("variant")
        field_labels+=("$(t plan_review.field.variant)")
        field_keys+=("panel_domain")
        field_labels+=("$(t plan_review.field.panel_domain)")
        field_keys+=("camouflage_domain")
        field_labels+=("$(t plan_review.field.camouflage_domain)")
        field_keys+=("vision_domain")
        field_labels+=("$(t plan_review.field.vision_domain)")
        field_keys+=("email")
        field_labels+=("$(t plan_review.field.email)")
        field_keys+=("shared_domain")
        field_labels+=("$(t plan_review.field.shared_domain)")

        if (( GOWAVE_PLAN_NODE_COUNT > 0 )); then
            field_keys+=("node_count")
            field_labels+=("$(t plan_review.field.node_count)")
            for ((node_idx = 0; node_idx < GOWAVE_PLAN_NODE_COUNT; node_idx++)); do
                field_keys+=("node_name_$node_idx")
                field_labels+=("$(tf plan_review.field.node_name "$((node_idx + 1))")")
                field_keys+=("node_camouflage_$node_idx")
                field_labels+=("$(tf plan_review.field.node_camouflage "$((node_idx + 1))")")
                field_keys+=("node_vision_$node_idx")
                field_labels+=("$(tf plan_review.field.node_vision "$((node_idx + 1))")")
            done
        fi

        # Display menu
        for ((choice = 0; choice < ${#field_keys[@]}; choice++)); do
            local current=""
            case "${field_keys[$choice]}" in
                variant) current="$GOWAVE_PLAN_VARIANT" ;;
                panel_domain) current="$GOWAVE_PLAN_PANEL_NAME" ;;
                camouflage_domain) current="$GOWAVE_PLAN_CAMOUFLAGE_NAME" ;;
                vision_domain) current="${GOWAVE_PLAN_VISION_NAME:-}" ;;
                email) current="$GOWAVE_PLAN_EMAIL" ;;
                shared_domain) current="$GOWAVE_PLAN_SHARED_DOMAIN" ;;
                node_count) current="$GOWAVE_PLAN_NODE_COUNT" ;;
                node_name_*) current="${GOWAVE_PLAN_NODE_NAMES[${field_keys[$choice]#node_name_}]}" ;;
                node_camouflage_*) current="${GOWAVE_PLAN_NODE_CAMOUFLAGE[${field_keys[$choice]#node_camouflage_}]}" ;;
                node_vision_*) current="${GOWAVE_PLAN_NODE_VISION[${field_keys[$choice]#node_vision_}]:-}" ;;
            esac
            printf '  %d) %s [%s]\n' "$((choice + 1))" "${field_labels[$choice]}" "$current"
        done
        printf '  0) %s\n' "$(t plan_review.confirm)"

        # Read choice
        choice=$(_wizard_prompt_read "$(t plan_review.edit_field)") || return 1
        if [[ "$choice" == "0" ]]; then
            return 0
        fi
        if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#field_keys[@]} )); then
            printf '%s\n' "$(t plan_review.invalid_choice)" >&2
            continue
        fi

        local idx=$((choice - 1))
        field="${field_keys[$idx]}"
        local current_value=""
        case "$field" in
            variant) current_value="$GOWAVE_PLAN_VARIANT" ;;
            panel_domain) current_value="$GOWAVE_PLAN_PANEL_NAME" ;;
            camouflage_domain) current_value="$GOWAVE_PLAN_CAMOUFLAGE_NAME" ;;
            vision_domain) current_value="${GOWAVE_PLAN_VISION_NAME:-}" ;;
            email) current_value="$GOWAVE_PLAN_EMAIL" ;;
            shared_domain) current_value="$GOWAVE_PLAN_SHARED_DOMAIN" ;;
            node_count) current_value="$GOWAVE_PLAN_NODE_COUNT" ;;
            node_name_*) current_value="${GOWAVE_PLAN_NODE_NAMES[${field#node_name_}]}" ;;
            node_camouflage_*) current_value="${GOWAVE_PLAN_NODE_CAMOUFLAGE[${field#node_camouflage_}]}" ;;
            node_vision_*) current_value="${GOWAVE_PLAN_NODE_VISION[${field#node_vision_}]:-}" ;;
        esac

        printf '%s\n' "$(tf plan_review.current_value "$current_value")"
        new_value=$(_wizard_prompt_read "$(t plan_review.enter_new)") || return 1

        # Empty input means "keep current" for most fields, but for vision fields
        # it means "remove vision". Handle this in the field-specific logic.
        if [[ -z "$new_value" && "$field" != "vision_domain" && "$field" != node_vision_* ]]; then
            continue
        fi

        # Apply the change and re-run validations
        case "$field" in
            variant)
                case "${new_value,,}" in
                    1|all-in-one|all_in_one|aio) new_value="all-in-one" ;;
                    2|panel-only|panel_only|panel) new_value="panel-only" ;;
                    3|multi-node|multi_node|multi) new_value="multi-node" ;;
                    *) printf '%s\n' "$(t wizard.variant.invalid)" >&2; continue ;;
                esac
                GOWAVE_PLAN_VARIANT="$new_value"
                ;;
            panel_domain)
                if ! wizard_validate_hostname "$new_value"; then
                    printf '%s\n' "$(tf wizard.name.invalid "$new_value")" >&2
                    continue
                fi
                # Skip duplicate check if value unchanged (avoids self-detection)
                if [[ "$new_value" != "$GOWAVE_PLAN_PANEL_NAME" ]]; then
                    if taken=$(wizard_plan_name_owner "$new_value"); then
                        :
                    else
                        printf '%s\n' "$(tf wizard.name.duplicate "$new_value" "$taken")" >&2
                        continue
                    fi
                fi
                GOWAVE_PLAN_PANEL_NAME="$new_value"
                ;;
            camouflage_domain)
                if ! wizard_validate_hostname "$new_value"; then
                    printf '%s\n' "$(tf wizard.name.invalid "$new_value")" >&2
                    continue
                fi
                if [[ "$new_value" != "$GOWAVE_PLAN_CAMOUFLAGE_NAME" ]]; then
                    if taken=$(wizard_plan_name_owner "$new_value"); then
                        :
                    else
                        printf '%s\n' "$(tf wizard.name.duplicate "$new_value" "$taken")" >&2
                        continue
                    fi
                fi
                GOWAVE_PLAN_CAMOUFLAGE_NAME="$new_value"
                ;;
            vision_domain)
                if [[ -n "$new_value" ]] && ! wizard_validate_hostname "$new_value"; then
                    printf '%s\n' "$(tf wizard.name.invalid "$new_value")" >&2
                    continue
                fi
                if [[ -n "$new_value" && "$new_value" != "$GOWAVE_PLAN_VISION_NAME" ]]; then
                    if taken=$(wizard_plan_name_owner "$new_value"); then
                        :
                    else
                        printf '%s\n' "$(tf wizard.name.duplicate "$new_value" "$taken")" >&2
                        continue
                    fi
                fi
                GOWAVE_PLAN_VISION_NAME="$new_value"
                if [[ -n "$new_value" ]]; then
                    GOWAVE_PLAN_PANEL_VISION="yes"
                else
                    GOWAVE_PLAN_PANEL_VISION="no"
                fi
                ;;
            email)
                if ! wizard_validate_email "$new_value"; then
                    printf '%s\n' "$(t wizard.email.invalid)" >&2
                    continue
                fi
                GOWAVE_PLAN_EMAIL="$new_value"
                ;;
            shared_domain)
                case "${new_value,,}" in
                    y|yes|д|да) new_value="yes" ;;
                    n|no|н|нет) new_value="no" ;;
                    *) printf '%s\n' "$(t wizard.yes_no.invalid)" >&2; continue ;;
                esac
                GOWAVE_PLAN_SHARED_DOMAIN="$new_value"
                ;;
            node_count)
                if ! [[ "$new_value" =~ ^[0-9]+$ ]] || (( 10#$new_value < 1 )); then
                    printf '%s\n' "$(t wizard.nodes.invalid)" >&2
                    continue
                fi
                new_value=$((10#$new_value))
                # Adjust node arrays if count changed
                if (( new_value > GOWAVE_PLAN_NODE_COUNT )); then
                    for ((node_idx = GOWAVE_PLAN_NODE_COUNT + 1; node_idx <= new_value; node_idx++)); do
                        local node_name node_camouflage node_vision=""
                        node_name=$(wizard_read_hostname "$(tf wizard.name.worker "$node_idx")") || return 1
                        node_camouflage=$(wizard_read_hostname "$(tf wizard.name.worker_camouflage "$node_idx")") || return 1
                        if wizard_read_yes_no "$(tf wizard.vision.prompt "$node_name")" no; then
                            node_vision=$(wizard_read_hostname "$(t wizard.name.vision)" yes) || return 1
                        fi
                        if ! wizard_register_host worker "$node_name" "$node_camouflage" "$node_vision"; then
                            return 1
                        fi
                    done
                elif (( new_value < GOWAVE_PLAN_NODE_COUNT )); then
                    # Truncate arrays
                    GOWAVE_PLAN_NODE_NAMES=("${GOWAVE_PLAN_NODE_NAMES[@]:0:new_value}")
                    GOWAVE_PLAN_NODE_CAMOUFLAGE=("${GOWAVE_PLAN_NODE_CAMOUFLAGE[@]:0:new_value}")
                    GOWAVE_PLAN_NODE_VISION=("${GOWAVE_PLAN_NODE_VISION[@]:0:new_value}")
                fi
                GOWAVE_PLAN_NODE_COUNT="$new_value"
                ;;
            node_name_*)
                node_idx="${field#node_name_}"
                if ! wizard_validate_hostname "$new_value"; then
                    printf '%s\n' "$(tf wizard.name.invalid "$new_value")" >&2
                    continue
                fi
                if [[ "$new_value" != "${GOWAVE_PLAN_NODE_NAMES[$node_idx]}" ]]; then
                    if taken=$(wizard_plan_name_owner "$new_value"); then
                        :
                    else
                        printf '%s\n' "$(tf wizard.name.duplicate "$new_value" "$taken")" >&2
                        continue
                    fi
                fi
                GOWAVE_PLAN_NODE_NAMES[$node_idx]="$new_value"
                ;;
            node_camouflage_*)
                node_idx="${field#node_camouflage_}"
                if ! wizard_validate_hostname "$new_value"; then
                    printf '%s\n' "$(tf wizard.name.invalid "$new_value")" >&2
                    continue
                fi
                if [[ "$new_value" != "${GOWAVE_PLAN_NODE_CAMOUFLAGE[$node_idx]}" ]]; then
                    if taken=$(wizard_plan_name_owner "$new_value"); then
                        :
                    else
                        printf '%s\n' "$(tf wizard.name.duplicate "$new_value" "$taken")" >&2
                        continue
                    fi
                fi
                GOWAVE_PLAN_NODE_CAMOUFLAGE[$node_idx]="$new_value"
                ;;
            node_vision_*)
                node_idx="${field#node_vision_}"
                if [[ -n "$new_value" ]] && ! wizard_validate_hostname "$new_value"; then
                    printf '%s\n' "$(tf wizard.name.invalid "$new_value")" >&2
                    continue
                fi
                if [[ -n "$new_value" && "$new_value" != "${GOWAVE_PLAN_NODE_VISION[$node_idx]}" ]]; then
                    if taken=$(wizard_plan_name_owner "$new_value"); then
                        :
                    else
                        printf '%s\n' "$(tf wizard.name.duplicate "$new_value" "$taken")" >&2
                        continue
                    fi
                fi
                GOWAVE_PLAN_NODE_VISION[$node_idx]="$new_value"
                ;;
        esac

        # Re-run dependent validations
        wizard_certificate_preflight || continue
        wizard_check_plan_names || continue

        printf '%s\n' "$(t plan_review.updated)"
    done
}

# Hands the panel host to cmd_install exactly as the positional path would.
wizard_apply_plan() {
    GOWAVE_INSTALL_POSITIONAL=()
    case "$GOWAVE_PLAN_VARIANT" in
        panel-only)
            GOWAVE_INSTALL_MODE="panel-only"
            GOWAVE_INSTALL_POSITIONAL=("$GOWAVE_PLAN_PANEL_NAME" "$GOWAVE_PLAN_CAMOUFLAGE_NAME" "$GOWAVE_PLAN_EMAIL")
            ;;
        all-in-one|multi-node)
            GOWAVE_INSTALL_MODE="all-in-one"
            GOWAVE_INSTALL_POSITIONAL=("$GOWAVE_PLAN_PANEL_NAME" "$GOWAVE_PLAN_CAMOUFLAGE_NAME" "$GOWAVE_PLAN_EMAIL" "$GOWAVE_PLAN_VISION_NAME")
            ;;
        *)
            return 1
            ;;
    esac
    return 0
}

wizard_missing_terminal() {
    printf '%s\n' "$(t wizard.missing_tty)" >&2
    if [[ -n "${GOWAVE_INSTALL_USAGE:-}" ]]; then
        printf '%s\n' "$GOWAVE_INSTALL_USAGE" >&2
    fi
    return 2
}

# One worker at a time: the Panel host holds the mutation lock and the
# temporary-access lifecycle is per host.
# Returns 0 if all nodes succeeded, 1 if all nodes failed, 2 if partial success.
# Prints a per-node summary to stdout.
wizard_onboard_nodes() {
    local i host camouflage vision
    local -a node_results=()
    local any_succeeded=0 any_failed=0
    local scratch stderr_file

    # A tracked scratch directory, not a bare file: the cleanup helper removes
    # the directory it is given, so handing it `dirname` of a /tmp file would
    # delete /tmp itself when the onboarding finishes.
    scratch=$(mktemp -d "${TMPDIR:-/tmp}/wizard_onboard.XXXXXX")
    stderr_file="$scratch/stderr"
    : > "$stderr_file"
    if declare -F track_temp_dir >/dev/null 2>&1; then
        track_temp_dir "$scratch"
    fi

    for i in "${!GOWAVE_PLAN_NODE_NAMES[@]}"; do
        host="${GOWAVE_PLAN_NODE_NAMES[$i]}"
        camouflage="${GOWAVE_PLAN_NODE_CAMOUFLAGE[$i]}"
        vision="${GOWAVE_PLAN_NODE_VISION[$i]:-}"

        # Capture stdout and stderr separately to extract phase info
        local stdout_output stderr_output
        stdout_output=$(ssh_bootstrap_onboard_one "$host" "$camouflage" "$vision" 2>"$stderr_file")
        local result=$?
        stderr_output=$(cat "$stderr_file" 2>/dev/null || true)
        : > "$stderr_file"

        # Extract the last phase from stderr (PHASE: markers)
        local failed_phase=""
        if (( result != 0 )); then
            failed_phase=$(printf '%s\n' "$stderr_output" | grep '^PHASE:' | tail -1 | cut -d: -f2)
            [[ -n "$failed_phase" ]] || failed_phase="unknown"
        fi

        # Combine output for operator display
        local output
        output=$(printf '%s\n%s' "$stdout_output" "$stderr_output" | sed '/^PHASE:/d')

        if (( result == 0 )); then
            node_results+=("$host:SUCCESS")
            any_succeeded=1
        else
            any_failed=1
            # Extract a safe diagnostic from the output (last non-empty non-PHASE line)
            local diagnostic
            diagnostic=$(printf '%s\n' "$output" | grep -v '^==' | grep -v '^PHASE:' | tail -1)
            [[ -n "$diagnostic" ]] || diagnostic="onboarding failed"
            # Redact any potential secrets from diagnostic
            diagnostic=$(_redact_secrets "$diagnostic")
            node_results+=("$host:FAILED:phase=$failed_phase:$diagnostic")
        fi

        # Print the output so operator sees progress (redacted)
        printf '%s\n' "$(_redact_secrets "$output")"
    done

    if declare -F release_temp_dir >/dev/null 2>&1; then
        release_temp_dir "$scratch"
    else
        rm -rf -- "$scratch"
    fi

    # Print detailed summary
    _print_onboarding_summary node_results

    # Store node results for potential retry
    _store_node_results node_results

    # Offer the retry only for the partial case: with every node failed there is
    # nothing a per-node retry can add over running the installation again.
    if (( any_succeeded > 0 && any_failed > 0 )); then
        _offer_selective_retry node_results
    fi

    if (( any_succeeded == 0 )); then
        return 1  # all failed
    elif (( any_failed == 0 )); then
        return 0  # all succeeded
    else
        return 2  # partial success
    fi
}

# Redact secrets from output.
# Args: text
_redact_secrets() {
    local text="$1"
    # Redact SSH passwords (common patterns)
    text=$(printf '%s\n' "$text" | sed -E 's/(password|secret|token|key)=[^[:space:]]+/\1=***REDACTED***/gi')
    # Redact private key content
    text=$(printf '%s\n' "$text" | sed -E 's/-----BEGIN [A-Z ]+PRIVATE KEY-----[^-]*-----END [A-Z ]+PRIVATE KEY-----/***PRIVATE KEY REDACTED***/g')
    # Redact SSH private key files
    text=$(printf '%s\n' "$text" | sed -E 's/ssh-ed25519 [A-Za-z0-9+/=]+/ssh-ed25519 ***REDACTED***/g')
    printf '%s' "$text"
}

# Print a detailed onboarding summary.
# Args: array_name (reference to array of results)
_print_onboarding_summary() {
    local -n results="$1"
    printf '\n=== Node Onboarding Summary ===\n'
    local result
    for result in "${results[@]}"; do
        if [[ "$result" == *:SUCCESS ]]; then
            printf '  %s: %s\n' "${result%%:*}" "$(t wizard.summary.success)"
        else
            local host="${result%%:*}"
            local rest="${result#*:}"
            local phase="${rest#*phase=}"
            phase="${phase%%:*}"
            local diagnostic="${rest#*:}"
            diagnostic="${diagnostic#*:}"
            printf '  %s: %s (phase: %s, reason: %s)\n' "$host" "$(t wizard.summary.failed)" "$phase" "$diagnostic"
        fi
    done
}

# Store node results for potential retry.
# Args: array_name (reference to array of results)
_store_node_results() {
    local -n results="$1"
    local state_file="${GOWAVE_STATE_DIR:-/opt/gowave}/wizard_node_results"
    printf '%s\n' "${results[@]}" > "$state_file"
    chmod 600 "$state_file"
}

# Retry a single failed node.
# Args: host
_retry_single_node() {
    local host="$1"
    local i
    for i in "${!GOWAVE_PLAN_NODE_NAMES[@]}"; do
        if [[ "${GOWAVE_PLAN_NODE_NAMES[$i]}" == "$host" ]]; then
            local camouflage="${GOWAVE_PLAN_NODE_CAMOUFLAGE[$i]}"
            local vision="${GOWAVE_PLAN_NODE_VISION[$i]:-}"
            local stdout_output stderr_output
            local stderr_file
            stderr_file=$(mktemp "${TMPDIR:-/tmp}/wizard_onboard_stderr.XXXXXX")
            stdout_output=$(ssh_bootstrap_onboard_one "$host" "$camouflage" "$vision" 2>"$stderr_file")
            local result=$?
            stderr_output=$(cat "$stderr_file" 2>/dev/null || true)
            rm -f "$stderr_file"

            local output
            output=$(printf '%s\n%s' "$stdout_output" "$stderr_output" | sed '/^PHASE:/d')
            printf '%s\n' "$output"

            if (( result == 0 )); then
                printf '%s\n' "$(tf wizard.retry.succeeded "$host")"
            else
                printf '%s\n' "$(tf wizard.retry.failed "$host")" >&2
            fi
            return "$result"
        fi
    done
    printf '%s\n' "$(tf wizard.retry.not_found "$host")" >&2
    return 1
}

# Read-only retry diagnostics for a failed node.
# Reads the recovery journal through modules/recovery.py and checks VPS reachability.
# Args: host
_retry_diagnostics() {
    local host="$1"
    local journal_file="${GOWAVE_JOURNAL_FILE:-/opt/gowave/recovery/journal.json}"
    local state_file="${GOWAVE_STATE_FILE:-/opt/gowave/state.json}"
    local credentials_file="${GOWAVE_CREDENTIALS_FILE:-/root/gowave-credentials.txt}"

    printf '\n%s\n' "$(tf wizard.diagnostics.header "$host")"

    # 1. Check Panel registration state via recovery journal
    if [[ -f "$journal_file" ]]; then
        printf '%s\n' "$(t wizard.diagnostics.journal_found)"
        local journal_output
        if journal_output=$(PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
import sys
sys.path.insert(0, '$SCRIPT_DIR')
from modules.recovery import load_journal_file, validate_journal
try:
    data = load_journal_file('$journal_file')
    validate_journal(data)
    print('STATE=' + data.get('state', 'UNKNOWN'))
    print('OP=' + data.get('op', 'UNKNOWN'))
    if 'entities' in data:
        for entity in data['entities']:
            if entity.get('type') == 'node' and entity.get('uuid') == '$host':
                print('NODE_STATE=' + entity.get('action', 'UNKNOWN'))
                break
except Exception as e:
    print('ERROR=' + str(e))
" 2>&1); then
            local state=$(printf '%s\n' "$journal_output" | grep '^STATE=' | cut -d= -f2)
            local op=$(printf '%s\n' "$journal_output" | grep '^OP=' | cut -d= -f2)
            local node_state=$(printf '%s\n' "$journal_output" | grep '^NODE_STATE=' | cut -d= -f2)
            local error=$(printf '%s\n' "$journal_output" | grep '^ERROR=' | cut -d= -f2-)

            if [[ -n "$error" ]]; then
                printf '%s\n' "$(tf wizard.diagnostics.journal_error "$error")"
            else
                printf '%s\n' "$(tf wizard.diagnostics.journal_state "$op" "$state")"
                if [[ -n "$node_state" ]]; then
                    printf '%s\n' "$(tf wizard.diagnostics.node_state "$node_state")"
                fi
            fi
        else
            printf '%s\n' "$(t wizard.diagnostics.journal_unreadable)"
        fi
    else
        printf '%s\n' "$(t wizard.diagnostics.journal_missing)"
    fi

    # 2. Check VPS SSH reachability (unauthenticated scan)
    printf '%s\n' "$(t wizard.diagnostics.ssh_check)"
    local port="${GOWAVE_SSH_PORT:-22}"
    local scanned
    if scanned=$(ssh_bootstrap_scan "$host" "$port" 2>/dev/null); then
        local fingerprint
        fingerprint=$(printf '%s\n' "$scanned" | ssh_bootstrap_fingerprint)
        if [[ -n "$fingerprint" ]]; then
            printf '%s\n' "$(tf wizard.diagnostics.ssh_ok "$host" "$fingerprint")"
        else
            printf '%s\n' "$(t wizard.diagnostics.ssh_banner)"
        fi
    else
        printf '%s\n' "$(tf wizard.diagnostics.ssh_unreachable "$host")"
    fi

    # 3. Check if VPS has managed state (basic connectivity)
    printf '%s\n' "$(t wizard.diagnostics.vps_check)"
    if ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -p "$port" "root@$host" 'true' 2>/dev/null; then
        printf '%s\n' "$(t wizard.diagnostics.vps_managed)"
    else
        printf '%s\n' "$(t wizard.diagnostics.vps_unmanaged)"
    fi

    printf '%s\n' "$(t wizard.diagnostics.footer)"
}

# Offer selective retry of failed nodes.
# Args: array_name (reference to array of results)
_offer_selective_retry() {
    local -n results="$1"
    local -a failed_nodes=()
    local result host

    for result in "${results[@]}"; do
        if [[ "$result" != *:SUCCESS ]]; then
            host="${result%%:*}"
            failed_nodes+=("$host")
        fi
    done

    if (( ${#failed_nodes[@]} == 0 )); then
        return 0
    fi

    # Show diagnostics for each failed node
    for host in "${failed_nodes[@]}"; do
        _retry_diagnostics "$host"
    done

    printf '\n%s\n' "$(t wizard.retry.offer)"
    local i=1
    for host in "${failed_nodes[@]}"; do
        printf '  %d) %s\n' "$i" "$host"
        ((i++))
    done
    printf '  %d) %s\n' "$i" "$(t wizard.retry.skip)"

    local choice
    while true; do
        printf '%s' "$(t wizard.retry.prompt)"
        if ! IFS= read -r choice; then
            printf '\n'
            return 1
        fi
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#failed_nodes[@]} )); then
            local retry_host="${failed_nodes[choice-1]}"
            printf '%s\n' "$(tf wizard.retry.retrying "$retry_host")"
            _retry_single_node "$retry_host"
        elif (( choice == ${#failed_nodes[@]} + 1 )); then
            printf '%s\n' "$(t wizard.retry.skipped)"
            return 0
        else
            printf '%s\n' "$(t wizard.retry.invalid)"
        fi
    done
}
