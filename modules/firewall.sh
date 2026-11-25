#!/usr/bin/env bash
# modules/firewall.sh - Transactional firewall baseline and role policy
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIREWALL_IMAGE_PY="${FIREWALL_IMAGE_PY:-${SCRIPT_DIR}/assets/security/firewall_image.py}"
MANAGED_SECURITY_PY="${MANAGED_SECURITY_PY:-${SCRIPT_DIR}/assets/security/managed.py}"
FIREWALL_COMMENT="${FIREWALL_COMMENT:-GoWave Auto NGINX}"

firewall_policy_json() {
    local role="${1:?}" node_port="${2:-3002}" master_ipv4="${3:-}" master_ipv6="${4:-}" ipv6="${5:-false}"
    python3 - "$role" "$node_port" "$master_ipv4" "$master_ipv6" "$ipv6" <<'PY' | python3 "$MANAGED_SECURITY_PY" --firewall-policy
import json, sys
role, port, v4, v6, ipv6 = sys.argv[1:]
if ipv6 not in ('true', 'false'):
    raise SystemExit('Invalid IPv6 policy')
json.dump({'role': role, 'node_port': int(port), 'master_sources': [value for value in (v4, v6) if value], 'ipv6': ipv6 == 'true'}, sys.stdout)
PY
}

firewall_before_image() {
    # Per transaction, beside the ACME snapshot: a successful install removes
    # the image it captured, a failed one keeps exactly the image its
    # compensation restored from.
    local recovery="${RECOVERY_DIR:-/var/lib/gowave-auto-nginx/recovery}"
    local transaction="${_FIREWALL_TX_ID:-}"
    if [[ -z "$transaction" ]]; then
        printf '%s\n' "$recovery/firewall-before-image"
        return 0
    fi
    printf '%s\n' "$recovery/$transaction/firewall-before-image"
}

firewall_image() {
    local action="${1:-}"
    local root="${2:-/}"
    local image="${3:-$(firewall_before_image)}"
    case "$action" in
        capture|restore) ;;
        *)
            echo "Error: firewall_image needs capture or restore, not '$action'." >&2
            return 2
            ;;
    esac
    if [[ ! -f "$FIREWALL_IMAGE_PY" ]]; then
        echo "Fatal: the firewall before-image helper is missing at $FIREWALL_IMAGE_PY." >&2
        return 1
    fi
    python3 "$FIREWALL_IMAGE_PY" "$root" "$image" "$action"
}

record_firewall_before_image() {
    firewall_image capture "${1:-/}" "${2:-$(firewall_before_image)}"
}

restore_firewall_before_image() {
    firewall_image restore "${1:-/}" "${2:-$(firewall_before_image)}"
}

firewall_policy_error() {
    # The helper answers a refusal on stdout as JSON; the operator reads the
    # reason, not a bare exit status.
    local payload="${1:-}"
    if [[ -n "$payload" ]]; then
        printf '%s' "$payload" | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("error", "firewall preflight failed"))
except Exception:
    print("firewall preflight failed")' 2>/dev/null && return 0
    fi
    printf '%s\n' "firewall preflight failed"
}

firewall_prepare() {
    # Derive the role policy once and refuse conflicting existing policy before
    # anything is mutated. Every later step reads the same document, so the
    # rules that were inspected are the rules that are applied.
    local role="${1:?}" node_port="${2:-3002}" master_ipv4="${3:-}" master_ipv6="${4:-}"
    local if_inet6="${5:-/proc/net/if_inet6}" root="${6:-/}"
    local ipv6=false
    if declare -F check_kernel_ipv6 >/dev/null 2>&1 && check_kernel_ipv6 "$if_inet6" 2>/dev/null; then
        ipv6=true
    fi
    local policy_json
    if ! policy_json=$(firewall_policy_json "$role" "$node_port" "$master_ipv4" "$master_ipv6" "$ipv6"); then
        echo "Fatal: cannot derive the $role firewall policy." >&2
        return 1
    fi
    local preflight
    if ! preflight=$(printf '%s' "$policy_json" | python3 -c 'import json,sys
json.dump(json.load(sys.stdin)["policy"], sys.stdout)' | python3 "$MANAGED_SECURITY_PY" --firewall-preflight "$root"); then
        printf 'Fatal: %s\n' "$(firewall_policy_error "$preflight")" >&2
        echo "Fatal: the managed ingress for this host conflicts with existing firewall policy; resolve it before retrying." >&2
        return 1
    fi
    local preserved
    preserved=$(printf '%s' "$preflight" | python3 -c 'import json,sys
try:
    print(len(json.load(sys.stdin).get("preserved_exceptions", [])))
except Exception:
    print(0)' 2>/dev/null || echo 0)
    if [[ "$preserved" != "0" ]]; then
        echo "Firewall preflight preserved $preserved unrelated administrator allow rule(s)." >&2
    fi
    _FIREWALL_POLICY_JSON="$policy_json"
    _FIREWALL_POLICY_ROLE="$role"
    _FIREWALL_POLICY_PORT="$node_port"
    _FIREWALL_POLICY_IPV6="$ipv6"
}

firewall_prepare_install() {
    # Runs before the first firewall mutation of the run. A Panel-only host has
    # no Node listener, so it carries no Node exception; the All-in-One host
    # carries the default Node API port.
    local mode="${1:-all-in-one}"
    local node_port="${2:-3002}"
    local if_inet6="${3:-/proc/net/if_inet6}"
    local root="${4:-/}"
    local role=aio
    if [[ "$mode" != "all-in-one" ]]; then
        role=panel-only
    fi
    firewall_prepare "$role" "$node_port" "" "" "$if_inet6" "$root"
}

firewall_begin_transaction() {
    # The baseline is captured once per run and only after the policy that will
    # change it is known to be applicable. Without a baseline the run stops
    # here rather than mutating a firewall it could not put back.
    local root="${1:-/}"
    if [[ "${_FIREWALL_IMAGE_CAPTURED:-0}" -eq 1 ]]; then
        return 0
    fi
    if [[ -z "${_FIREWALL_TX_ID:-}" ]]; then
        _FIREWALL_TX_ID="firewall_$(date +%s)_${BASHPID}"
    fi
    if ! record_firewall_before_image "$root"; then
        echo "Fatal: the firewall baseline could not be captured; refusing to change a firewall this install cannot restore." >&2
        return 1
    fi
    # Restoration writes through the same root the capture read, so a run
    # against a displaced tree restores that tree and nothing else.
    _FIREWALL_ROOT="$root"
    _FIREWALL_IMAGE_CAPTURED=1
    return 0
}

firewall_restore_once() {
    # Exactly one attempt per run: a second failure must not re-run restoration
    # over a state the first attempt already rewrote.
    local reason="${1:-the firewall change failed}"
    if [[ "${_FIREWALL_IMAGE_CAPTURED:-0}" -ne 1 ]]; then
        return 0
    fi
    if [[ "${_FIREWALL_RESTORED:-0}" -eq 1 ]]; then
        echo "Firewall recovery was already attempted; not repeating it." >&2
        return 0
    fi
    _FIREWALL_RESTORED=1
    echo "Restoring the firewall baseline captured before this transaction..." >&2
    if restore_firewall_before_image "${_FIREWALL_ROOT:-/}"; then
        echo "Firewall baseline restored and read back as captured." >&2
        _FIREWALL_RECOVERY="verified"
        return 0
    fi
    _FIREWALL_RECOVERY="failed"
    echo "CRITICAL: firewall restoration failed after: $reason. The before-image is retained for operator intervention." >&2
    return 1
}

firewall_failed() {
    local reason="${1:?}"
    echo "Error: $reason" >&2
    firewall_restore_once "$reason" || true
    return 1
}

firewall_apply_policy() {
    # Applies the prepared policy verbatim, so the rules the preflight approved
    # are the rules the host receives.
    if [[ -z "${_FIREWALL_POLICY_JSON:-}" ]]; then
        echo "Fatal: no firewall policy was prepared; refusing to guess the managed ingress." >&2
        return 1
    fi
    local rules
    if ! rules=$(printf '%s' "$_FIREWALL_POLICY_JSON" | python3 -c 'import json,sys
policy = json.load(sys.stdin).get("policy")
if not isinstance(policy, dict):
    raise SystemExit("no policy")
for command in policy.get("commands", []):
    print("\x1f".join(str(token) for token in command))'); then
        firewall_failed "the prepared firewall policy is not readable"
        return 1
    fi
    local -a rule
    while IFS=$'\x1f' read -r -a rule; do
        [[ "${#rule[@]}" -gt 0 ]] || continue
        # The applied rule is echoed before it runs: an operator reading a
        # failed install sees the last rule UFW accepted, not only the error.
        printf 'UFW: %s\n' "${rule[*]}"
        if [[ "${rule[0]}" == "default" ]]; then
            ufw "${rule[@]}" </dev/null || {
                firewall_failed "ufw ${rule[*]} failed"
                return 1
            }
        else
            ufw "${rule[@]}" comment "$FIREWALL_COMMENT" </dev/null || {
                firewall_failed "ufw ${rule[*]} failed"
                return 1
            }
        fi
    done <<< "$rules"
}

firewall_verify() {
    local root="${1:-/}"
    local verified
    if ! verified=$(printf '%s' "$_FIREWALL_POLICY_JSON" | python3 -c 'import json,sys
policy = json.load(sys.stdin).get("policy")
json.dump(policy, sys.stdout)' | python3 "$MANAGED_SECURITY_PY" --firewall-verify "$root"); then
        printf 'Error: %s\n' "$(firewall_policy_error "$verified")" >&2
        return 1
    fi
    return 0
}

firewall_commit_transaction() {
    # A verified install keeps no baseline behind: the image is what a failure
    # would have restored, and its removal is the record that nothing is
    # pending. A failed or repaired run keeps it.
    if [[ "${_FIREWALL_IMAGE_CAPTURED:-0}" -ne 1 ]]; then
        return 0
    fi
    if [[ "${_FIREWALL_RESTORED:-0}" -eq 1 ]]; then
        return 0
    fi
    local image directory base resolved
    image=$(firewall_before_image)
    directory=$(dirname -- "$image")
    base="${RECOVERY_DIR:-/var/lib/gowave-auto-nginx/recovery}"
    base=$(realpath -m -- "$base") || return 0
    resolved=$(realpath -m -- "$directory") || return 0
    case "$resolved" in
        "$base"/*) ;;
        *)
            echo "Warning: refusing to remove a firewall before-image outside the recovery root: $resolved" >&2
            return 0
            ;;
    esac
    rm -rf -- "$resolved" || echo "Warning: could not remove the firewall before-image at $resolved." >&2
    return 0
}
