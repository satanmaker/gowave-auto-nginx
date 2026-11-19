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
    local name="$1"
    local label
    local IFS='.'
    [[ ${#name} -ge 3 && ${#name} -le 253 ]] || return 1
    [[ "$name" != .* && "$name" != *. && "$name" != *..* ]] || return 1
    [[ "$name" == *.* ]] || return 1
    for label in $name; do
        [[ ${#label} -le 63 ]] || return 1
        [[ "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
    done
    return 0
}

wizard_validate_email() {
    [[ "$1" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]
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

    if [[ "$GOWAVE_PLAN_VARIANT" == "multi-node" ]]; then
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
wizard_onboard_nodes() {
    local i host camouflage vision rc=0
    for i in "${!GOWAVE_PLAN_NODE_NAMES[@]}"; do
        host="${GOWAVE_PLAN_NODE_NAMES[$i]}"
        camouflage="${GOWAVE_PLAN_NODE_CAMOUFLAGE[$i]}"
        vision="${GOWAVE_PLAN_NODE_VISION[$i]:-}"
        if ! ssh_bootstrap_onboard_one "$host" "$camouflage" "$vision"; then
            rc=1
        fi
    done
    return "$rc"
}
