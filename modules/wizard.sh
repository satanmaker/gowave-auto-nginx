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
# The exit country asked of a traffic node after it serves.
# shellcheck source=modules/geoip.sh
source "$_wizard_dir/geoip.sh"

GOWAVE_PLAN_VARIANT=""
GOWAVE_PLAN_SHARED_DOMAIN="no"
# The certificate count whose shared-domain consent the operator already gave,
# so re-running the checks at review does not ask the same question twice.
GOWAVE_PLAN_SHARED_CONFIRMED_COUNT=""
GOWAVE_PLAN_PANEL_VISION="no"
GOWAVE_PLAN_PANEL_NAME=""
GOWAVE_PLAN_CAMOUFLAGE_NAME=""
GOWAVE_PLAN_VISION_NAME=""
GOWAVE_PLAN_EMAIL=""
GOWAVE_PLAN_NODE_COUNT=0
GOWAVE_PLAN_NODE_NAMES=()
GOWAVE_PLAN_NODE_CAMOUFLAGE=()
GOWAVE_PLAN_NODE_VISION=()
# Display names for the Panel and the subscriptions, independent of DNS: the
# local node's name and one per remote node. Empty means "the product default".
GOWAVE_PLAN_LOCAL_LABEL=""
GOWAVE_PLAN_NODE_LABELS=()

wizard_reset_plan() {
    GOWAVE_PLAN_VARIANT=""
    GOWAVE_PLAN_SHARED_DOMAIN="no"
    GOWAVE_PLAN_SHARED_CONFIRMED_COUNT=""
    GOWAVE_PLAN_PANEL_VISION="no"
    GOWAVE_PLAN_PANEL_NAME=""
    GOWAVE_PLAN_CAMOUFLAGE_NAME=""
    GOWAVE_PLAN_VISION_NAME=""
    GOWAVE_PLAN_EMAIL=""
    GOWAVE_PLAN_NODE_COUNT=0
    GOWAVE_PLAN_NODE_NAMES=()
    GOWAVE_PLAN_NODE_CAMOUFLAGE=()
    GOWAVE_PLAN_NODE_VISION=()
    GOWAVE_PLAN_LOCAL_LABEL=""
    GOWAVE_PLAN_NODE_LABELS=()
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

# Every name the plan already holds, as "owner<TAB>name". The owner label comes
# from the catalog because it is printed inside the duplicate refusal.
_wizard_plan_pairs() {
    local i
    if [[ -n "$GOWAVE_PLAN_PANEL_NAME" ]]; then
        printf '%s\t%s\n' "$(t wizard.owner.panel_host)" "$GOWAVE_PLAN_PANEL_NAME"
    fi
    if [[ -n "$GOWAVE_PLAN_CAMOUFLAGE_NAME" ]]; then
        printf '%s\t%s\n' "$(t wizard.owner.panel_camouflage)" "$GOWAVE_PLAN_CAMOUFLAGE_NAME"
    fi
    if [[ -n "$GOWAVE_PLAN_VISION_NAME" ]]; then
        printf '%s\t%s\n' "$(t wizard.owner.panel_vision)" "$GOWAVE_PLAN_VISION_NAME"
    fi
    for i in "${!GOWAVE_PLAN_NODE_NAMES[@]}"; do
        printf '%s\t%s\n' "$(tf wizard.owner.node "$((i + 1))")" "${GOWAVE_PLAN_NODE_NAMES[$i]}"
        if [[ -n "${GOWAVE_PLAN_NODE_CAMOUFLAGE[$i]}" ]]; then
            printf '%s\t%s\n' "$(tf wizard.owner.node_camouflage "$((i + 1))")" \
                "${GOWAVE_PLAN_NODE_CAMOUFLAGE[$i]}"
        fi
        if [[ -n "${GOWAVE_PLAN_NODE_VISION[$i]}" ]]; then
            printf '%s\t%s\n' "$(tf wizard.owner.node_vision "$((i + 1))")" \
                "${GOWAVE_PLAN_NODE_VISION[$i]}"
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

# A hostname the plan does not hold yet. A duplicate is refused at the field, so
# the operator corrects that one answer and keeps every earlier one: losing the
# card to a name the plan already has would discard the Panel and the previous
# node. `pending` lists the names this card has already read (space separated).
wizard_read_plan_hostname() {
    local prompt="$1" allow_empty="${2:-no}" pending="${3:-}"
    local answer owner name
    while true; do
        answer=$(wizard_read_hostname "$prompt" "$allow_empty") || return 1
        if [[ -z "$answer" ]]; then
            return 0
        fi
        if ! owner=$(wizard_plan_name_owner "$answer"); then
            printf '%s\n' "$(tf wizard.name.duplicate "$answer" "$owner")" >&2
            continue
        fi
        for name in $pending; do
            if [[ "$(wizard_normalize_name "$name")" == "$answer" ]]; then
                printf '%s\n' "$(tf wizard.name.duplicate "$answer" "$(t wizard.owner.same_card)")" >&2
                continue 2
            fi
        done
        printf '%s' "$answer"
        return 0
    done
}

# Display names for the Panel and the subscriptions, independent of DNS. Trimming
# happens here rather than at the caller: " ams-01" and "ams-01 " are one name to
# the product, and two names that differ only by case read as one in a list.
wizard_normalize_label() {
    local label="$1"
    label="${label#"${label%%[![:space:]]*}"}"
    label="${label%"${label##*[![:space:]]}"}"
    printf '%s' "$label"
}

_wizard_label_pairs() {
    local i
    if [[ -n "$GOWAVE_PLAN_LOCAL_LABEL" ]]; then
        printf '%s\t%s\n' "$(t wizard.owner.local_node)" "$GOWAVE_PLAN_LOCAL_LABEL"
    fi
    for i in "${!GOWAVE_PLAN_NODE_LABELS[@]}"; do
        printf '%s\t%s\n' "$(tf wizard.owner.node_label "$((i + 1))")" "${GOWAVE_PLAN_NODE_LABELS[$i]}"
    done
}

# Prints the owner of a label the plan already holds and returns 1; 0 when free.
wizard_plan_label_owner() {
    local candidate owner label
    candidate=$(wizard_normalize_label "$1")
    while IFS=$'\t' read -r owner label; do
        [[ -n "$label" ]] || continue
        if [[ "${label,,}" == "${candidate,,}" ]]; then
            printf '%s' "$owner"
            return 1
        fi
    done < <(_wizard_label_pairs)
    return 0
}

# The name reaches profile tags, Host remarks and the `node add` positional, and
# the Panel refuses a worker name it cannot register. This is that same rule
# (see the node-registration guard in cmd_install), so a name the wizard accepts
# is a name the Panel accepts, and the refusal states it instead of the operator
# discovering it after the SSH session opened.
wizard_validate_label() {
    [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]
}

# A display name: trimmed, non-blank, unique in the plan. A refusal names the
# owner and repeats only this question.
wizard_read_label() {
    local prompt="$1" answer owner
    while true; do
        answer=$(_wizard_prompt_read "$prompt") || return 1
        answer=$(wizard_normalize_label "$answer")
        if [[ -z "$answer" ]]; then
            printf '%s\n' "$(t wizard.name.label_empty)" >&2
            continue
        fi
        if ! wizard_validate_label "$answer"; then
            printf '%s\n' "$(t wizard.name.label_charset)" >&2
            continue
        fi
        if ! owner=$(wizard_plan_label_owner "$answer"); then
            printf '%s\n' "$(tf wizard.name.label_duplicate "$answer" "$owner")" >&2
            continue
        fi
        printf '%s' "$answer"
        return 0
    done
}

# Records a display name next to the host it belongs to.
wizard_register_label() {
    local role="$1" label="$2"
    if [[ "$role" == "panel" ]]; then
        GOWAVE_PLAN_LOCAL_LABEL="$label"
    else
        GOWAVE_PLAN_NODE_LABELS+=("$label")
    fi
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
            host) t wizard.owner.panel_host ;;
            camouflage) t wizard.owner.panel_camouflage ;;
            *) t wizard.owner.panel_vision ;;
        esac
    else
        case "$kind" in
            host) tf wizard.owner.node "$index" ;;
            camouflage) tf wizard.owner.node_camouflage "$index" ;;
            *) tf wizard.owner.node_vision "$index" ;;
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
# budget. The consent belongs to the plan it was given for, so it is recorded
# against the certificate count: review re-runs this check, and a yes for twelve
# certificates must not be read as a yes for twenty.
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
        GOWAVE_PLAN_SHARED_CONFIRMED_COUNT=""
        return 1
    fi
    if [[ "$GOWAVE_PLAN_SHARED_CONFIRMED_COUNT" == "$count" ]]; then
        return 0
    fi
    message=$(tf wizard.cert.shared_within "$count" "$ceiling")
    if wizard_read_yes_no "$message" no; then
        GOWAVE_PLAN_SHARED_CONFIRMED_COUNT="$count"
        return 0
    fi
    return 1
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

# The display name is the operator's own word for the server, so it is shown
# beside the role rather than inside the catalog sentence: a translated
# sentence cannot decide where the name reads best, and the name is data.
_wizard_plan_role_label() {
    local role="$1" name="${2:-}"
    if [[ -n "$name" ]]; then
        printf '%s (%s)' "$role" "$name"
    else
        printf '%s' "$role"
    fi
}

wizard_plan_summary() {
    local i vision
    printf '%s\n' "$(t wizard.plan.summary)"
    printf '%s\n' "$(tf wizard.plan.host "$(_wizard_plan_role_label "Panel" "$GOWAVE_PLAN_LOCAL_LABEL")" "$GOWAVE_PLAN_PANEL_NAME" "$GOWAVE_PLAN_CAMOUFLAGE_NAME" "${GOWAVE_PLAN_VISION_NAME:-none}")"
    for i in "${!GOWAVE_PLAN_NODE_NAMES[@]}"; do
        vision="${GOWAVE_PLAN_NODE_VISION[$i]:-}"
        printf '%s\n' "$(tf wizard.plan.host "$(_wizard_plan_role_label "node $((i + 1))" "${GOWAVE_PLAN_NODE_LABELS[$i]:-}")" "${GOWAVE_PLAN_NODE_NAMES[$i]}" "${GOWAVE_PLAN_NODE_CAMOUFLAGE[$i]}" "${vision:-none}")"
    done
    printf '%s\n' "$(tf wizard.plan.certificates "$(wizard_plan_certificate_count)")"
    # The exit country is a fact about a node's own outbound route, and that
    # route only exists once the node does. Review therefore marks it as still to
    # come instead of opening SSH to a server the operator has not agreed to yet.
    printf '%s\n' "$(t wizard.plan.country_pending)"
    if [[ "$GOWAVE_PLAN_SHARED_DOMAIN" == "yes" ]]; then
        printf '%s\n' "$(t wizard.plan.shared)"
    else
        printf '%s\n' "$(t wizard.plan.separate)"
    fi
}

wizard_collect_plan() {
    local panel camouflage vision local_label i

    wizard_reset_plan
    wizard_select_language || return 1
    wizard_select_variant || return 1

    panel=$(wizard_read_plan_hostname "$(t wizard.name.panel)") || return 1
    camouflage=$(wizard_read_plan_hostname "$(t wizard.name.camouflage)" no "$panel") || return 1
    vision=""
    if [[ "$GOWAVE_PLAN_VARIANT" != "panel-only" ]]; then
        if wizard_read_yes_no "$(tf wizard.vision.prompt "$panel")" no; then
            vision=$(wizard_read_plan_hostname "$(t wizard.name.vision)" yes "$panel $camouflage") || return 1
        fi
    fi
    wizard_register_host panel "$panel" "$camouflage" "$vision" || return 1
    # A Panel-only host runs no local node, so there is no local node to name.
    if [[ "$GOWAVE_PLAN_VARIANT" != "panel-only" ]]; then
        local_label=$(wizard_read_label "$(t wizard.name.local_node_label)") || return 1
        wizard_register_label panel "$local_label"
    fi

    GOWAVE_PLAN_EMAIL=$(wizard_read_email) || return 1

    # A Panel-only host has no local node, so its workers are the whole traffic
    # plane; only the All-in-One variant ends at the local host.
    if [[ "$GOWAVE_PLAN_VARIANT" != "all-in-one" ]]; then
        GOWAVE_PLAN_NODE_COUNT=$(wizard_read_node_count) || return 1
        for ((i = 1; i <= GOWAVE_PLAN_NODE_COUNT; i++)); do
            local node_name node_camouflage node_vision=""
            node_name=$(wizard_read_plan_hostname "$(tf wizard.name.worker "$i")") || return 1
            node_camouflage=$(wizard_read_plan_hostname \
                "$(tf wizard.name.worker_camouflage "$i")" no "$node_name") || return 1
            if wizard_read_yes_no "$(tf wizard.vision.prompt "$node_name")" no; then
                node_vision=$(wizard_read_plan_hostname \
                    "$(t wizard.name.vision)" yes "$node_name $node_camouflage") || return 1
            fi
            if ! wizard_register_host worker "$node_name" "$node_camouflage" "$node_vision"; then
                return 1
            fi
            local node_label
            node_label=$(wizard_read_label "$(tf wizard.name.node_label "$i")") || return 1
            wizard_register_label worker "$node_label"
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
    # The review that follows is the confirmation: it shows the same plan again
    # and its start action re-runs these checks, so a [y/N] here would ask the
    # operator to approve one plan twice.
    return 0
}

# Current value of one review field. The action list and the field editor both
# read it, and two copies of this case would drift.
_wizard_review_value() {
    local field="$1"
    case "$field" in
        variant) printf '%s' "$GOWAVE_PLAN_VARIANT" ;;
        panel_domain) printf '%s' "$GOWAVE_PLAN_PANEL_NAME" ;;
        camouflage_domain) printf '%s' "$GOWAVE_PLAN_CAMOUFLAGE_NAME" ;;
        vision_domain) printf '%s' "${GOWAVE_PLAN_VISION_NAME:-}" ;;
        email) printf '%s' "$GOWAVE_PLAN_EMAIL" ;;
        shared_domain) printf '%s' "$GOWAVE_PLAN_SHARED_DOMAIN" ;;
        node_count) printf '%s' "$GOWAVE_PLAN_NODE_COUNT" ;;
        node_name_*) printf '%s' "${GOWAVE_PLAN_NODE_NAMES[${field#node_name_}]}" ;;
        node_camouflage_*) printf '%s' "${GOWAVE_PLAN_NODE_CAMOUFLAGE[${field#node_camouflage_}]}" ;;
        node_vision_*) printf '%s' "${GOWAVE_PLAN_NODE_VISION[${field#node_vision_}]:-}" ;;
        local_node_label) printf '%s' "$GOWAVE_PLAN_LOCAL_LABEL" ;;
        node_label_*) printf '%s' "${GOWAVE_PLAN_NODE_LABELS[${field#node_label_}]:-}" ;;
    esac
}

# Localized label of one review field; a node field carries its ordinal.
_wizard_review_label() {
    local field="$1" index=0
    case "$field" in
        node_name_*|node_camouflage_*|node_vision_*|node_label_*)
            index=$(( ${field##*_} + 1 ))
            ;;
    esac
    case "$field" in
        variant) t plan_review.field.variant ;;
        panel_domain) t plan_review.field.panel_domain ;;
        camouflage_domain) t plan_review.field.camouflage_domain ;;
        vision_domain) t plan_review.field.vision_domain ;;
        email) t plan_review.field.email ;;
        shared_domain) t plan_review.field.shared_domain ;;
        node_count) t plan_review.field.node_count ;;
        node_name_*) tf plan_review.field.node_name "$index" ;;
        node_camouflage_*) tf plan_review.field.node_camouflage "$index" ;;
        node_vision_*) tf plan_review.field.node_vision "$index" ;;
        local_node_label) t plan_review.field.local_node_label ;;
        node_label_*) tf plan_review.field.node_label "$index" ;;
    esac
}

# Applies one reviewed answer: 0 changed, 1 refused with the reason printed, 2
# nothing to change. An empty answer keeps the current value everywhere except a
# Vision domain, where it removes Vision — the one field where empty is a value.
_wizard_review_apply() {
    local field="$1" new_value="$2" node_idx taken owner
    if [[ -z "$new_value" ]]; then
        case "$field" in
            vision_domain|node_vision_*) ;;
            *) return 2 ;;
        esac
    fi
    case "$field" in
        variant)
            case "${new_value,,}" in
                1|all-in-one|all_in_one|aio) new_value="all-in-one" ;;
                2|panel-only|panel_only|panel) new_value="panel-only" ;;
                3|multi-node|multi_node|multi) new_value="multi-node" ;;
                *) printf '%s\n' "$(t wizard.variant.invalid)" >&2; return 1 ;;
            esac
            GOWAVE_PLAN_VARIANT="$new_value"
            ;;
        panel_domain)
            if ! wizard_validate_hostname "$new_value"; then
                printf '%s\n' "$(tf wizard.name.invalid "$new_value")" >&2
                return 1
            fi
            if [[ "$new_value" != "$GOWAVE_PLAN_PANEL_NAME" ]] \
                && ! taken=$(wizard_plan_name_owner "$new_value"); then
                printf '%s\n' "$(tf wizard.name.duplicate "$new_value" "$taken")" >&2
                return 1
            fi
            GOWAVE_PLAN_PANEL_NAME="$new_value"
            ;;
        camouflage_domain)
            if ! wizard_validate_hostname "$new_value"; then
                printf '%s\n' "$(tf wizard.name.invalid "$new_value")" >&2
                return 1
            fi
            if [[ "$new_value" != "$GOWAVE_PLAN_CAMOUFLAGE_NAME" ]] \
                && ! taken=$(wizard_plan_name_owner "$new_value"); then
                printf '%s\n' "$(tf wizard.name.duplicate "$new_value" "$taken")" >&2
                return 1
            fi
            GOWAVE_PLAN_CAMOUFLAGE_NAME="$new_value"
            ;;
        vision_domain)
            if [[ -n "$new_value" ]] && ! wizard_validate_hostname "$new_value"; then
                printf '%s\n' "$(tf wizard.name.invalid "$new_value")" >&2
                return 1
            fi
            if [[ -n "$new_value" && "$new_value" != "$GOWAVE_PLAN_VISION_NAME" ]] \
                && ! taken=$(wizard_plan_name_owner "$new_value"); then
                printf '%s\n' "$(tf wizard.name.duplicate "$new_value" "$taken")" >&2
                return 1
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
                return 1
            fi
            GOWAVE_PLAN_EMAIL="$new_value"
            ;;
        shared_domain)
            case "${new_value,,}" in
                y|yes|д|да) new_value="yes" ;;
                n|no|н|нет) new_value="no" ;;
                *) printf '%s\n' "$(t wizard.yes_no.invalid)" >&2; return 1 ;;
            esac
            GOWAVE_PLAN_SHARED_DOMAIN="$new_value"
            ;;
        node_count)
            if ! [[ "$new_value" =~ ^[0-9]+$ ]] || (( 10#$new_value < 1 )); then
                printf '%s\n' "$(t wizard.nodes.invalid)" >&2
                return 1
            fi
            new_value=$((10#$new_value))
            if (( new_value > GOWAVE_PLAN_NODE_COUNT )); then
                for ((node_idx = GOWAVE_PLAN_NODE_COUNT + 1; node_idx <= new_value; node_idx++)); do
                    local node_name node_camouflage node_vision=""
                    node_name=$(wizard_read_plan_hostname "$(tf wizard.name.worker "$node_idx")") || return 1
                    node_camouflage=$(wizard_read_plan_hostname \
                        "$(tf wizard.name.worker_camouflage "$node_idx")" no "$node_name") || return 1
                    if wizard_read_yes_no "$(tf wizard.vision.prompt "$node_name")" no; then
                        node_vision=$(wizard_read_plan_hostname \
                            "$(t wizard.name.vision)" yes "$node_name $node_camouflage") || return 1
                    fi
                    if ! wizard_register_host worker "$node_name" "$node_camouflage" "$node_vision"; then
                        return 1
                    fi
                    local node_label
                    node_label=$(wizard_read_label "$(tf wizard.name.node_label "$node_idx")") || return 1
                    wizard_register_label worker "$node_label"
                done
            elif (( new_value < GOWAVE_PLAN_NODE_COUNT )); then
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
                return 1
            fi
            if [[ "$new_value" != "${GOWAVE_PLAN_NODE_NAMES[$node_idx]}" ]] \
                && ! taken=$(wizard_plan_name_owner "$new_value"); then
                printf '%s\n' "$(tf wizard.name.duplicate "$new_value" "$taken")" >&2
                return 1
            fi
            GOWAVE_PLAN_NODE_NAMES[$node_idx]="$new_value"
            ;;
        node_camouflage_*)
            node_idx="${field#node_camouflage_}"
            if ! wizard_validate_hostname "$new_value"; then
                printf '%s\n' "$(tf wizard.name.invalid "$new_value")" >&2
                return 1
            fi
            if [[ "$new_value" != "${GOWAVE_PLAN_NODE_CAMOUFLAGE[$node_idx]}" ]] \
                && ! taken=$(wizard_plan_name_owner "$new_value"); then
                printf '%s\n' "$(tf wizard.name.duplicate "$new_value" "$taken")" >&2
                return 1
            fi
            GOWAVE_PLAN_NODE_CAMOUFLAGE[$node_idx]="$new_value"
            ;;
        node_vision_*)
            node_idx="${field#node_vision_}"
            if [[ -n "$new_value" ]] && ! wizard_validate_hostname "$new_value"; then
                printf '%s\n' "$(tf wizard.name.invalid "$new_value")" >&2
                return 1
            fi
            if [[ -n "$new_value" && "$new_value" != "${GOWAVE_PLAN_NODE_VISION[$node_idx]}" ]] \
                && ! taken=$(wizard_plan_name_owner "$new_value"); then
                printf '%s\n' "$(tf wizard.name.duplicate "$new_value" "$taken")" >&2
                return 1
            fi
            GOWAVE_PLAN_NODE_VISION[$node_idx]="$new_value"
            ;;
        local_node_label|node_label_*)
            new_value=$(wizard_normalize_label "$new_value")
            if [[ -z "$new_value" ]]; then
                printf '%s
' "$(t wizard.name.label_empty)" >&2
                return 1
            fi
            if [[ "$new_value" != "$(_wizard_review_value "$field")" ]] \
                && ! owner=$(wizard_plan_label_owner "$new_value"); then
                printf '%s\n' "$(tf wizard.name.label_duplicate "$new_value" "$owner")" >&2
                return 1
            fi
            if [[ "$field" == "local_node_label" ]]; then
                GOWAVE_PLAN_LOCAL_LABEL="$new_value"
            else
                node_idx="${field#node_label_}"
                GOWAVE_PLAN_NODE_LABELS[$node_idx]="$new_value"
            fi
            ;;
    esac
    return 0
}

# One field: show the current value, read one answer, apply it. A refused answer
# leaves the plan as it was and the editor open, so the operator fixes the field
# instead of retyping the card that answered it.
_wizard_review_edit_field() {
    local field="$1" label new_value rc=0
    label=$(_wizard_review_label "$field")
    printf '%s\n' "$(tf plan_review.current_value "$(_wizard_review_value "$field")")"
    if [[ "$field" == vision_domain || "$field" == node_vision_* ]]; then
        new_value=$(_wizard_prompt_read "$(tf plan_review.enter_new_vision "$label")") || return 1
    else
        new_value=$(_wizard_prompt_read "$(tf plan_review.enter_new "$label")") || return 1
    fi
    _wizard_review_apply "$field" "$new_value" || rc=$?
    if (( rc == 0 )) && wizard_certificate_preflight && wizard_check_plan_names; then
        printf '%s\n' "$(t plan_review.updated)"
    fi
    return 0
}

# Numbered editor for one group of fields. Returns 1 only when the terminal stops
# answering: a refused value keeps the editor open on the same group.
_wizard_review_edit_group() {
    local title="$1"
    shift
    local -a keys=("$@")
    local choice index key
    while true; do
        printf '\n%s\n' "$title"
        for ((index = 0; index < ${#keys[@]}; index++)); do
            key="${keys[$index]}"
            printf '  %d) %s [%s]\n' "$((index + 1))" \
                "$(_wizard_review_label "$key")" "$(_wizard_review_value "$key")"
        done
        printf '  0) %s\n' "$(t plan_review.back)"
        choice=$(_wizard_prompt_read "$(t plan_review.choose_field)") || return 1
        if [[ "$choice" == "0" ]]; then
            return 0
        fi
        if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#keys[@]} )); then
            printf '%s\n' "$(t plan_review.invalid_choice)" >&2
            continue
        fi
        _wizard_review_edit_field "${keys[$((choice - 1))]}" || return 1
    done
}

# Plan review: start, edit the Panel and plan settings, edit one node, or cancel.
# Nothing here touches a server; start re-runs the dependent checks, so a plan
# refused during editing cannot be started without passing them. Returns 0 to
# deploy, 3 when the operator cancels, and 1 when the terminal stops answering.
wizard_review_plan() {
    local choice index
    local -a panel_keys=(variant panel_domain camouflage_domain vision_domain)
    if [[ "$GOWAVE_PLAN_VARIANT" != "panel-only" ]]; then
        panel_keys+=(local_node_label)
    fi
    panel_keys+=(email shared_domain node_count)
    while true; do
        printf '\n%s\n' "$(t plan_review.title)"
        wizard_plan_summary
        printf '\n  1) %s\n' "$(t plan_review.confirm)"
        printf '  2) %s\n' "$(t plan_review.edit_panel)"
        for ((index = 0; index < GOWAVE_PLAN_NODE_COUNT; index++)); do
            printf '  %d) %s\n' "$((index + 3))" "$(tf plan_review.edit_node "$((index + 1))")"
        done
        printf '  0) %s\n\n' "$(t plan_review.cancel)"
        choice=$(_wizard_prompt_read "$(t plan_review.edit_field)") || return 1
        case "$choice" in
            1)
                if wizard_certificate_preflight && wizard_check_plan_names; then
                    return 0
                fi
                ;;
            2)
                _wizard_review_edit_group "$(t plan_review.panel_title)" \
                    "${panel_keys[@]}" || return 1
                ;;
            0)
                printf '%s\n' "$(t plan_review.cancelled)"
                return 3
                ;;
            *)
                if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 3 && choice - 3 < GOWAVE_PLAN_NODE_COUNT )); then
                    index=$((choice - 3))
                    _wizard_review_edit_group "$(tf plan_review.node_title "$((index + 1))")" \
                        "node_name_$index" "node_camouflage_$index" "node_vision_$index" \
                        "node_label_$index" || return 1
                else
                    printf '%s\n' "$(t plan_review.invalid_choice)" >&2
                fi
                ;;
        esac
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

# The nodes the Panel already holds, one "name<TAB>address<TAB>port<TAB>uuid"
# per line.
#
# Only a Panel on this host can be read: the administrative credentials that
# read it live in this host's credentials file, and a remote Panel's are not
# this installer's to hold. The read authenticates the way the registration
# does, with `ADMIN_USERNAME`/`ADMIN_PASSWORD`, because the scoped API token in
# the same file is issued for external subscription consumers and carries no
# `nodes:read`: a readback behind that token answers 403 and would report every
# registered node as unconfirmed.
# 0 is a read inventory, 1 a local Panel that did not answer, 2 a remote Panel
# whose inventory is unverifiable here — never a "the name is free" answer.
wizard_panel_inventory_names() {
    local panel_address="$1" panel_is_local="${2:-no}"
    local root
    if [[ "$panel_is_local" != "yes" && "$panel_address" != "127.0.0.1" && "$panel_address" != "localhost" ]]; then
        return 2
    fi
    root=$(cd "$_wizard_dir/.." && pwd)
    PYTHONPATH="$root${PYTHONPATH:+:$PYTHONPATH}" python3 - \
        "${CREDENTIALS_FILE:-/root/gowave-credentials.txt}" <<'PY'
import sys

from modules.api_client import GoWaveAPIError, GoWaveClient

values = {}
try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        for line in handle:
            key, sep, value = line.partition("=")
            if sep and not key.lstrip().startswith("#"):
                values[key.strip()] = value.strip()
except OSError:
    raise SystemExit(1)
username = values.get("ADMIN_USERNAME", "")
password = values.get("ADMIN_PASSWORD", "")
if not username or not password:
    raise SystemExit(1)
client = GoWaveClient("http://127.0.0.1:3000")
try:
    client.login(username, password)
    nodes = client.list_nodes()
except (GoWaveAPIError, OSError):
    raise SystemExit(1)
for node in nodes:
    if isinstance(node, dict) and node.get("name"):
        print("%s\t%s\t%s\t%s" % (
            node["name"],
            node.get("address") or "-",
            node.get("port") or "-",
            node.get("uuid") or "-",
        ))
PY
}

# Read one node back from the Panel that was just told about it.
#
# 0 — the Panel lists the name with a uuid, at the address and port the
#     registration used; prints that uuid.
# 1 — the Panel answered and the node is not there as registered; prints
#     `missing`, or `moved<TAB>address<TAB>port` for the identity it holds.
# 2 — no readable inventory here (a remote Panel, or a local one that did not
#     answer), so nothing about this node was disproved.
#
# The Panel is the authority on what it registered: `node add` exiting 0 is a
# claim about a command, and only this read makes it a claim about the Panel.
wizard_verify_node_registration() {
    local name="$1" address="${2:-}" port="${3:-}"
    local panel_address="$4" panel_is_local="${5:-no}"
    local inventory="" rc=0 line held_address held_port held_uuid reason

    inventory=$(wizard_panel_inventory_names "$panel_address" "$panel_is_local") || rc=$?
    if (( rc != 0 )); then
        return 2
    fi
    if [[ -z "$name" ]]; then
        printf 'missing'
        return 1
    fi
    line=$(printf '%s\n' "$inventory" | awk -F'\t' -v want="$name" \
        'tolower($1) == tolower(want) { print; exit }')
    if [[ -z "$line" ]]; then
        printf 'missing'
        return 1
    fi
    IFS=$'\t' read -r _ held_address held_port held_uuid <<< "$line"
    reason=""
    if [[ -n "$address" && "$held_address" != "-" && "$held_address" != "$address" ]]; then
        reason="moved"
    fi
    if [[ -n "$port" && "$held_port" != "-" && "$held_port" != "$port" ]]; then
        reason="moved"
    fi
    if [[ -n "$reason" ]]; then
        printf 'moved\t%s\t%s' "$held_address" "$held_port"
        return 1
    fi
    if [[ -z "$held_uuid" || "$held_uuid" == "-" ]]; then
        printf 'missing'
        return 1
    fi
    printf '%s' "$held_uuid"
    return 0
}

# Asks for the Worker name with the Panel's own inventory in hand.
#
# A collision is refused here, before the SSH session and before the remote
# server is touched; an unreadable inventory is reported as unverified, so the
# operator never hears that a name is free when nobody checked.
wizard_read_panel_worker_name() {
    local panel_address="$1" panel_is_local="${2:-no}"
    local inventory="" count="" name taken rc=0

    inventory=$(wizard_panel_inventory_names "$panel_address" "$panel_is_local") || rc=$?
    if (( rc == 2 )); then
        printf '%s\n' "$(t wizard.add_node.inventory_unverified)" >&2
    else
        while (( rc != 0 )); do
            printf '%s\n' "$(tf wizard.add_node.inventory_unavailable "$panel_address")" >&2
            if ! wizard_read_yes_no "$(t wizard.add_node.inventory_retry)" no; then
                printf '%s\n' "$(t wizard.add_node.cancelled)" >&2
                return 1
            fi
            rc=0
            inventory=$(wizard_panel_inventory_names "$panel_address" "$panel_is_local") || rc=$?
        done
        count=0
        [[ -n "$inventory" ]] && count=$(printf '%s\n' "$inventory" | wc -l)
        printf '%s\n' "$(tf wizard.add_node.inventory_checked "$count")" >&2
    fi

    while true; do
        name=$(wizard_read_label "$(t menu.prompt.worker_name)") || return 1
        if (( rc == 0 )); then
            taken=$(printf '%s\n' "$inventory" | awk -F'\t' -v want="$name" \
                'tolower($1) == tolower(want) { print $2; exit }')
            if [[ -n "$taken" ]]; then
                printf '%s\n' "$(tf wizard.add_node.name_taken "$name" "$taken")" >&2
                continue
            fi
        fi
        printf '%s' "$name"
        return 0
    done
}

wizard_missing_terminal() {
    printf '%s\n' "$(t wizard.missing_tty)" >&2
    if [[ -n "${GOWAVE_INSTALL_USAGE:-}" ]]; then
        printf '%s\n' "$GOWAVE_INSTALL_USAGE" >&2
    fi
    return 2
}

# The exit country of this server, asked once its node is serving.
#
# The request is made here, not on the Panel's behalf: it leaves through the same
# outbound route the traffic does, which for the local node is this host. Nothing
# is asked when no wizard is running, so a positional install neither prompts the
# operator nor contacts a lookup service for them.
#
# Args: node label. Prints the confirmed code, or nothing.
wizard_local_exit_country() {
    local label="$1" suggestion=""
    country_asking || return 0
    suggestion=$(country_lookup_here)
    country_confirm "$label" "$suggestion"
}

# One worker at a time: the Panel host holds the mutation lock and the
# temporary-access lifecycle is per host.
#
# Args: [panel display] [panel address] [panel is local]
# Returns 0 if every node registered, 1 if none did, 2 if some did.
# Prints a per-node summary to stdout.
wizard_onboard_nodes() {
    local panel_display="${1:-}"
    local panel_address="${2:-127.0.0.1}"
    local panel_is_local="${3:-yes}"
    local i host camouflage vision label state
    local -a node_results=()
    local any_succeeded=0 any_failed=0
    local record=""

    for i in "${!GOWAVE_PLAN_NODE_NAMES[@]}"; do
        host="${GOWAVE_PLAN_NODE_NAMES[$i]}"
        camouflage="${GOWAVE_PLAN_NODE_CAMOUFLAGE[$i]}"
        vision="${GOWAVE_PLAN_NODE_VISION[$i]:-}"
        label="${GOWAVE_PLAN_NODE_LABELS[$i]:-}"

        record=""
        if ! _wizard_onboard_record record "$host" "$camouflage" "$vision" "$label" "" \
            "$panel_address" "$panel_is_local"; then
            : # the record carries the outcome; the failing status is not needed here
        fi
        state=""
        IFS=$'\t' read -r _ state _ _ <<< "$record"
        node_results+=("$record")
        if [[ "$state" == "FAILED" ]]; then
            any_failed=1
        else
            any_succeeded=1
        fi
    done

    # Print detailed summary
    _print_onboarding_summary node_results "$panel_display"

    # Store node results for potential retry
    _store_node_results node_results

    # Offer the retry only for the partial case: with every node failed there is
    # nothing a per-node retry can add over running the installation again.
    if (( any_succeeded > 0 && any_failed > 0 )); then
        _offer_selective_retry node_results "$panel_address" "$panel_is_local" "$panel_display"
    fi

    if (( any_succeeded == 0 )); then
        return 1  # all failed
    elif (( any_failed == 0 )); then
        return 0  # all succeeded
    else
        return 2  # partial success
    fi
}

# Run one Worker's onboarding and read the registration back from the Panel.
#
# The Worker's own output is printed for the operator (redacted); the outcome
# travels in `result_var` as one tab-separated record:
#
#   <node>  VERIFIED    <uuid>          <address>:<port>
#   <node>  UNVERIFIED  unreadable      <address>:<port>
#   <node>  FAILED      <phase>         <reason>
#
# VERIFIED means the Panel's own node list answered with this name, address,
# port and uuid. UNVERIFIED means the Panel could not be read from this host,
# so nothing about the node was disproved — a remote Panel's token is not this
# host's to hold. FAILED with phase `verify` means the Panel was read and does
# not hold what `node add` just claimed, so the claim lost.
#
# The record is data because the summary localizes it; the display keeps the
# Worker's lines, with the machine markers that carried the identity stripped.
#
# Args: result variable, node, camouflage, vision, label, address, panel
# address, panel is local
# Returns 0 for VERIFIED and UNVERIFIED, 1 for FAILED.
_wizard_onboard_record() {
    local -n record_out="$1"
    local host="$2" camouflage="$3" vision="${4:-}" label="${5:-}" node_ip="${6:-}"
    local panel_address="${7:-127.0.0.1}" panel_is_local="${8:-yes}"
    local scratch stderr_file stdout_output stderr_output output result identity
    local node_name node_address node_port phase detail readback readback_rc

    # A tracked scratch directory, not a bare file: the cleanup helper removes
    # the directory it is given, so handing it `dirname` of a /tmp file would
    # delete /tmp itself when the onboarding finishes.
    scratch=$(mktemp -d "${TMPDIR:-/tmp}/wizard_onboard.XXXXXX")
    stderr_file="$scratch/stderr"
    : > "$stderr_file"
    if declare -F track_temp_dir >/dev/null 2>&1; then
        track_temp_dir "$scratch"
    fi

    # The assignment is guarded rather than followed by `$?`: a bare failing
    # assignment ends the run under `set -e` as soon as no caller happens to
    # hold this function in a `||` list.
    result=0
    stdout_output=$(ssh_bootstrap_onboard_one "$host" "$camouflage" "$vision" "$label" "$node_ip" \
        2>"$stderr_file") || result=$?
    stderr_output=$(cat "$stderr_file" 2>/dev/null || true)
    : > "$stderr_file"
    if declare -F release_temp_dir >/dev/null 2>&1; then
        release_temp_dir "$scratch"
    else
        rm -rf -- "$scratch"
    fi

    identity=$(printf '%s\n' "$stderr_output" | sed -n 's/^NODE-IDENTITY://p' | tail -1)
    output=$(printf '%s\n%s' "$stdout_output" "$stderr_output" \
        | sed -e '/^PHASE:/d' -e '/^NODE-IDENTITY:/d')
    printf '%s\n' "$(_redact_secrets "$output")"

    if (( result != 0 )); then
        phase=$(printf '%s\n' "$stderr_output" | grep '^PHASE:' | tail -1 | cut -d: -f2)
        [[ -n "$phase" ]] || phase="unknown"
        detail=$(printf '%s\n' "$output" | grep -v '^==' | grep -v '^PHASE:' | tail -1)
        [[ -n "$detail" ]] || detail="onboarding failed"
        record_out=$(printf '%s\t%s\t%s\t%s' "$host" "FAILED" "$phase" "$(_redact_secrets "$detail")")
        return 1
    fi

    node_name="${label:-$host}"
    node_address=""
    node_port=""
    if [[ -n "$identity" ]]; then
        IFS=$'\t' read -r node_name node_address node_port <<< "$identity"
    fi
    readback=""
    readback_rc=0
    readback=$(wizard_verify_node_registration "$node_name" "$node_address" "$node_port" \
        "$panel_address" "$panel_is_local") || readback_rc=$?
    case "$readback_rc" in
        0)
            record_out=$(printf '%s\t%s\t%s\t%s' "$host" "VERIFIED" "$readback" \
                "${node_address}:${node_port}")
            return 0
            ;;
        2)
            record_out=$(printf '%s\t%s\t%s\t%s' "$host" "UNVERIFIED" "unreadable" \
                "${node_address}:${node_port}")
            return 0
            ;;
        *)
            : # the Panel answered and contradicts the registration
            ;;
    esac
    if [[ "$readback" == moved* ]]; then
        detail="moved ${readback#moved$'\t'}"
        detail="${detail//$'\t'/:}"
    else
        detail="missing"
    fi
    record_out=$(printf '%s\t%s\t%s\t%s' "$host" "FAILED" "verify" "$detail")
    return 1
}

# The operator-facing reason for a FAILED record: a localized sentence when the
# Panel contradicted the registration, the Worker's own redacted line otherwise.
_wizard_failure_reason() {
    local phase="$1" detail="$2"
    if [[ "$phase" == "verify" ]]; then
        if [[ "$detail" == moved* ]]; then
            printf '%s' "$(tf wizard.summary.moved "${detail#moved }")"
        else
            printf '%s' "$(t wizard.summary.not_listed)"
        fi
        return 0
    fi
    printf '%s' "$detail"
}

# The Panel step is done and the nodes are not: said in its own words, because
# an "installation complete" banner over a node that still has to be onboarded
# is the screen that made a running install look finished.
wizard_panel_installed_notice() {
    printf '%s\n' "$(tf wizard.summary.panel "$1")"
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
#
# Each node is one line: the verified ones with the uuid the Panel answered
# with, the unconfirmed ones as such, and the failed ones with the stage and a
# reason the operator can act on. The count is what the install's completion
# line depends on, and the last line says what to do next, because the summary
# is the final screen of a run that stopped at a node.
#
# Args: array_name (reference to array of results), panel display
_print_onboarding_summary() {
    local -n results="$1"
    local panel_display="${2:-}"
    local result host state first second reason
    local verified=0 failed=0 total=0

    printf '\n%s\n' "$(t wizard.summary.header)"
    if [[ -n "$panel_display" ]]; then
        printf '  %s\n' "$(tf wizard.summary.panel "$panel_display")"
    fi
    for result in "${results[@]}"; do
        total=$((total + 1))
        IFS=$'\t' read -r host state first second <<< "$result"
        case "$state" in
            VERIFIED)
                verified=$((verified + 1))
                printf '  %s: %s\n' "$host" "$(tf wizard.summary.success "$first")"
                ;;
            UNVERIFIED)
                printf '  %s: %s\n' "$host" "$(t wizard.summary.unverified)"
                ;;
            *)
                failed=$((failed + 1))
                reason=$(_wizard_failure_reason "$first" "$second")
                printf '  %s: %s (phase: %s, reason: %s)\n' \
                    "$host" "$(t wizard.summary.failed)" "$first" "$reason"
                ;;
        esac
    done
    printf '  %s\n' "$(tf wizard.summary.count "$verified" "$total")"
    if (( failed > 0 )); then
        if (( verified > 0 )); then
            printf '%s\n' "$(t wizard.summary.next_partial)"
        else
            printf '%s\n' "$(t wizard.summary.next_all_failed)"
        fi
    fi
}

# Store node results for potential retry.
# Args: array_name (reference to array of results)
_store_node_results() {
    local -n results="$1"
    local state_file="${GOWAVE_STATE_DIR:-/opt/gowave}/wizard_node_results"
    printf '%s\n' "${results[@]}" > "$state_file"
    chmod 600 "$state_file"
}

# Retry a single failed node and put its new record back in the result list.
#
# Only the chosen node is onboarded again: the sibling's record, the Panel step
# and everything the first pass completed are left where they are, and the row
# that is replaced is this node's own.
#
# Args: results array, host, panel address, panel is local
_retry_single_node() {
    local -n retry_results="$1"
    local host="$2" panel_address="${3:-127.0.0.1}" panel_is_local="${4:-yes}"
    local i j state record
    for i in "${!GOWAVE_PLAN_NODE_NAMES[@]}"; do
        if [[ "${GOWAVE_PLAN_NODE_NAMES[$i]}" == "$host" ]]; then
            record=""
            _wizard_onboard_record record "$host" "${GOWAVE_PLAN_NODE_CAMOUFLAGE[$i]}" \
                "${GOWAVE_PLAN_NODE_VISION[$i]:-}" "${GOWAVE_PLAN_NODE_LABELS[$i]:-}" "" \
                "$panel_address" "$panel_is_local" || true
            state=""
            IFS=$'\t' read -r _ state _ _ <<< "$record"
            for j in "${!retry_results[@]}"; do
                if [[ "${retry_results[$j]%%$'\t'*}" == "$host" ]]; then
                    retry_results[$j]="$record"
                fi
            done
            case "$state" in
                VERIFIED | UNVERIFIED)
                    printf '%s\n' "$(tf wizard.retry.succeeded "$host")"
                    return 0
                    ;;
                *)
                    printf '%s\n' "$(tf wizard.retry.failed "$host")" >&2
                    return 1
                    ;;
            esac
        fi
    done
    printf '%s\n' "$(tf wizard.retry.not_found "$host")" >&2
    return 1
}

# Read-only retry diagnostics for a failed node.
# Reads the recovery journal through modules/recovery.py and checks VPS reachability.
#
# Returns 0 when the node's partial state answered at least one of the two
# independent records — a journal it is named in, or an SSH server that answers —
# and 1 when neither did. A retry is a mutation of a host whose state is then
# unknown: it may be half-provisioned from the failed attempt, and rerunning the
# onboarding over that is the one thing this check exists to avoid.
#
# Args: host
_retry_diagnostics() {
    local host="$1"
    local journal_file="${GOWAVE_JOURNAL_FILE:-/opt/gowave/recovery/journal.json}"
    local state_file="${GOWAVE_STATE_FILE:-/opt/gowave/state.json}"
    local credentials_file="${GOWAVE_CREDENTIALS_FILE:-/root/gowave-credentials.txt}"
    local journal_read=0 ssh_answered=0

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
                journal_read=1
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
            ssh_answered=1
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
    (( journal_read == 1 || ssh_answered == 1 ))
}

# Offer selective retry of failed nodes.
#
# The list is the failure record, so every failed node is offered; the choice is
# where the run is refused. A node neither record answered for cannot be retried
# safely, and a retry that the operator has not confirmed does not start. The
# other results are read, not rewritten: the sibling's row and the Panel stay as
# the first pass left them, and only the retried node's row is replaced. The menu
# is printed again after each attempt so the numbers below a reprinted summary
# still name the nodes that are still failed.
#
# Args: array_name (reference to array of results), panel address, panel is
# local, panel display
_offer_selective_retry() {
    local -n results="$1"
    local panel_address="${2:-127.0.0.1}" panel_is_local="${3:-yes}" panel_display="${4:-}"
    local -a failed_nodes=()
    local -a retryable=()
    local -a still_retryable=()
    local result host state i
    # The helpers take an array by name. Passing them this function's own
    # nameref name would make their `local -n` a reference to itself, which
    # reads empty, so the caller's name travels instead.
    local results_name="$1"

    for result in "${results[@]}"; do
        state=""
        IFS=$'\t' read -r host state _ _ <<< "$result"
        if [[ "$state" == "FAILED" ]]; then
            failed_nodes+=("$host")
        fi
    done

    if (( ${#failed_nodes[@]} == 0 )); then
        return 0
    fi

    # Show diagnostics for each failed node and keep which ones answered.
    for host in "${failed_nodes[@]}"; do
        if _retry_diagnostics "$host"; then
            retryable+=("$host")
        fi
    done

    local choice retry_host confirmed
    while true; do
        printf '\n%s\n' "$(t wizard.retry.offer)"
        i=1
        for host in "${failed_nodes[@]}"; do
            printf '  %d) %s\n' "$i" "$host"
            ((i++))
        done
        printf '  %d) %s\n' "$i" "$(t wizard.retry.skip)"
        printf '%s' "$(t wizard.retry.prompt)"
        if ! IFS= read -r choice; then
            printf '\n'
            return 1
        fi
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#failed_nodes[@]} )); then
            retry_host="${failed_nodes[choice-1]}"
            confirmed=0
            for host in "${retryable[@]}"; do
                [[ "$host" == "$retry_host" ]] && confirmed=1
            done
            if (( confirmed == 0 )); then
                printf '%s\n' "$(tf wizard.retry.unverifiable "$retry_host")"
                continue
            fi
            if ! wizard_read_yes_no "$(tf wizard.retry.confirm "$retry_host")" no; then
                printf '%s\n' "$(tf wizard.retry.declined "$retry_host")"
                continue
            fi
            printf '%s\n' "$(tf wizard.retry.retrying "$retry_host")"
            _retry_single_node "$results_name" "$retry_host" "$panel_address" "$panel_is_local" || true
            _store_node_results "$results_name"
            _print_onboarding_summary "$results_name" "$panel_display"

            # The list and the screen would otherwise disagree: the menu is
            # rebuilt from the records the retry just wrote, so a node that now
            # verified is no longer offered, and it is printed again under the
            # summary so the numbers still name the nodes they are asked about.
            failed_nodes=()
            for result in "${results[@]}"; do
                state=""
                IFS=$'\t' read -r host state _ _ <<< "$result"
                if [[ "$state" == "FAILED" ]]; then
                    failed_nodes+=("$host")
                fi
            done
            if (( ${#failed_nodes[@]} == 0 )); then
                return 0
            fi
            still_retryable=()
            for host in "${retryable[@]}"; do
                for result in "${failed_nodes[@]}"; do
                    if [[ "$result" == "$host" ]]; then
                        still_retryable+=("$host")
                    fi
                done
            done
            retryable=("${still_retryable[@]}")
        elif (( choice == ${#failed_nodes[@]} + 1 )); then
            printf '%s\n' "$(t wizard.retry.skipped)"
            return 0
        else
            printf '%s\n' "$(t wizard.retry.invalid)"
        fi
    done
}
