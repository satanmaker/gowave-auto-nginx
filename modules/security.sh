#!/usr/bin/env bash
# modules/security.sh - Host security, firewall, swap, BBR, and log rotation
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANAGED_SECURITY_PY="${SCRIPT_DIR}/assets/security/managed.py"
source "${SCRIPT_DIR}/modules/firewall.sh"

configure_ssh_and_fail2ban() {
    echo "Configuring non-destructive SSH inspection and Fail2ban..."
    python3 "$MANAGED_SECURITY_PY" --configure-fail2ban
}

configure_dot() {
    local policy="${GOWAVE_DOT_POLICY:-best-effort}"
    local output status
    _DOT_RECOVERY=unknown
    case "$policy" in
        off|best-effort|required) ;;
        *)
            echo "Error: unsupported DNS-over-TLS policy '$policy'; expected off, best-effort or required." >&2
            return 1
            ;;
    esac
    echo "Configuring DNS-over-TLS policy: $policy..."
    if output=$(GOWAVE_DOT_POLICY="$policy" python3 "$MANAGED_SECURITY_PY" --prepare-dns); then
        printf '%s\n' "$output"
        _DOT_RECOVERY=not-needed
        return 0
    fi
    printf '%s\n' "$output"
    status=$(printf '%s' "$output" | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("status", ""))
except Exception:
    print("")' 2>/dev/null || true)
    # Only a verified rollback may be tolerated, and only when the operator did
    # not ask for DoT as a hard requirement: the host then keeps working
    # resolution without it, and the run reports the control as failed.
    if [[ "$policy" != "required" && "$status" == "failed_rolled_back" ]]; then
        _DOT_RECOVERY=verified
        echo "Warning: DNS-over-TLS was not applied; the original resolver state was restored and verified, so the deployment continues without it." >&2
        return 0
    fi
    echo "Fatal: DNS-over-TLS policy '$policy' was not applied and the resolver rollback was not verified." >&2
    return 1
}

write_security_report() {
    # One report per host, produced from effective state rather than from the
    # steps that configured it: the helper reads the firewall, the jail, the
    # update schedule and the resolver back before it writes anything, so a
    # control that drifted since it was configured is reported failed.
    local role="${1:-}"
    local node_port="${2-}"
    local master_sources="${3:-}"
    local ipv6="${4:-false}"
    local dot_recovery="${5:-unknown}"
    local request output rc=0
    if [[ -z "$role" ]]; then
        echo "Error: a security report needs the host role." >&2
        return 1
    fi
    request=$(python3 -c 'import json,sys
role, port, sources, ipv6, recovery = sys.argv[1:6]
json.dump({"role": role,
           "node_port": int(port) if port else None,
           "master_sources": [item for item in sources.split(",") if item],
           "ipv6": ipv6 == "true",
           "dot_recovery": recovery}, sys.stdout)' \
        "$role" "$node_port" "$master_sources" "$ipv6" "$dot_recovery") || return 1
    if ! output=$(printf '%s' "$request" | python3 "$MANAGED_SECURITY_PY" --security-report); then
        rc=1
    fi
    printf '%s\n' "$output"
    if [[ "$rc" -ne 0 ]]; then
        echo "Error: this host is not ready for deployment; the security report names the control that failed." >&2
        return 1
    fi
    return 0
}

verify_worker_security_readback() {
    local host="$1" ipv4 ipv6 policy report
    ipv4=$(resolve_panel_ipv4) || return 1
    ipv6=$(resolve_panel_ipv6) || return 1
    policy="${GOWAVE_DOT_POLICY:-best-effort}"
    local remote_command
    remote_command=$(python3 -c 'import ipaddress, shlex, sys
port, v4, v6, policy = sys.argv[1:]
if (not v4 or ipaddress.ip_address(v4).version != 4
        or (v6 and ipaddress.ip_address(v6).version != 6)
        or policy not in {"off", "best-effort", "required"}):
    sys.exit(1)
print(shlex.join(["python3", "-", "--worker-security-readback", port, v4, v6, policy]))' \
        "$GOWAVE_SSH_NODE_PORT" "$ipv4" "$ipv6" "$policy" 2>/dev/null) || return 1
    report=$(timeout 45 ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes \
        -o ConnectTimeout=5 -o ClearAllForwardings=yes -o ForwardAgent=no -o UpdateHostKeys=no \
        -p "${GOWAVE_SSH_PORT:-22}" -- "root@$host" "$remote_command" \
        < "$MANAGED_SECURITY_PY" 2>/dev/null) || return 1
    PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -c '
import json
import sys
from modules.security_report import StateError, readiness

try:
    report = json.load(sys.stdin)
    status = readiness(report)
    if report["role"] != "worker" or report["controls"]["dot"]["policy"] != sys.argv[1]:
        sys.exit(1)
except (StateError, ValueError, TypeError):
    sys.exit(1)
sys.exit(status != "ready")
' "$policy" <<< "$report"
}

configure_unattended_upgrades() {
    echo "Configuring unattended-upgrades with automatic reboot disabled..."
    python3 "$MANAGED_SECURITY_PY" --configure-apt
}

configure_ufw() {
    local is_worker="${1:-false}"
    local panel_ip="${2:-}"
    # `-` not `:-`: an absent port means the caller has no Node listener to
    # isolate, while an explicit 3002 names the one this host does have.
    local node_port="${3-3002}"
    local if_inet6="${4:-/proc/net/if_inet6}"
    local ufw_default="${5:-/etc/default/ufw}"
    local root="${6:-/}"

    echo "Configuring UFW firewall rules..."

    # A Panel-only host has no Node listener, so its policy carries no Node
    # exception; the role decides which ports are internal, not the caller.
    local role=aio
    local policy_port="${node_port:-3002}"
    if [[ "$is_worker" == "true" ]]; then
        role=worker
    elif [[ -z "$node_port" ]]; then
        role=panel-only
    fi
    if [[ "$role" == "worker" && -z "$panel_ip" ]]; then
        echo "Warning: Panel IP not provided for worker UFW configuration." >&2
    fi

    # One policy document serves the run: the rules the preflight approved are
    # the rules applied below. A different role or port rebuilds and rechecks it
    # rather than applying a verdict about a policy this step no longer uses.
    if [[ -z "${_FIREWALL_POLICY_JSON:-}" ||
          "${_FIREWALL_POLICY_ROLE:-}" != "$role" ||
          "${_FIREWALL_POLICY_PORT:-}" != "$policy_port" ]]; then
        firewall_prepare "$role" "$policy_port" "$panel_ip" "${PANEL_IPV6:-}" "$if_inet6" "$root" || return 1
    fi
    firewall_begin_transaction "$root" || return 1

    # The family declaration comes first: `ufw allow` only maintains
    # user6.rules while the declaration says yes, so a host told yes after its
    # rules were written keeps the package's v6 table instead of this policy's.
    if [[ -f "$ufw_default" ]]; then
        if [[ "${_FIREWALL_POLICY_IPV6:-false}" == "true" ]]; then
            echo "UFW: IPv6 active in kernel; setting IPV6=yes in $ufw_default..."
            sed -i 's/^IPV6=.*/IPV6=yes/' "$ufw_default" || {
                firewall_failed "writing IPV6=yes to $ufw_default failed"
                return 1
            }
        else
            echo "UFW: IPv6 disabled in kernel; setting IPV6=no in $ufw_default..."
            sed -i 's/^IPV6=.*/IPV6=no/' "$ufw_default" || {
                firewall_failed "writing IPV6=no to $ufw_default failed"
                return 1
            }
        fi
    fi

    firewall_apply_policy || return 1

    ufw --force enable </dev/null || {
        firewall_failed "ufw --force enable failed"
        return 1
    }
    firewall_verify "$root" || {
        firewall_failed "the applied firewall policy does not read back from the running ruleset"
        return 1
    }
    echo "UFW configuration complete."
}

configure_swap() {
    local meminfo="${1:-/proc/meminfo}"
    local swapfile="${2:-/swapfile}"
    local fstab="${3:-/etc/fstab}"

    # Skip in containerized environments.
    if command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt --container >/dev/null 2>&1; then
        echo "Container environment detected; skipping swap allocation."
        return 0
    fi
    if [[ -f /.dockerenv || -f /run/.containerenv ]]; then
        echo "Container environment detected; skipping swap allocation."
        return 0
    fi

    local mem_total_kb=0
    [[ -f "$meminfo" ]] && mem_total_kb=$(awk '/MemTotal/ {print $2}' "$meminfo")
    [[ "$mem_total_kb" =~ ^[0-9]+$ ]] || mem_total_kb=0

    if [[ "$mem_total_kb" -le 1048576 && "$mem_total_kb" -gt 0 ]]; then
        if swapon --show --noheadings | grep -q .; then
            echo "Swap is already active."
        elif [[ -e "$swapfile" ]]; then
            echo "Warning: $swapfile already exists and is not active; refusing to overwrite an unmanaged file." >&2
        else
            echo "Low memory detected (${mem_total_kb} KiB <= 1GB); creating a 1 GiB swapfile..."
            local fs_type tmp_fstab swap_created=false
            fs_type=$(findmnt -n -o FSTYPE / 2>/dev/null || echo "unknown")
            if [[ "$fs_type" == "btrfs" ]]; then
                if command -v btrfs >/dev/null 2>&1 && btrfs filesystem mkswapfile --size 1G "$swapfile"; then
                    swap_created=true
                else
                    echo "Warning: failed to create a Btrfs-compatible swapfile; continuing without additional swap." >&2
                    rm -f "$swapfile"
                fi
            else
                if fallocate -l 1G "$swapfile" 2>/dev/null || {
                    rm -f "$swapfile"
                    dd if=/dev/zero of="$swapfile" bs=1M count=1024 status=none
                }; then
                    chmod 0600 "$swapfile"
                    if mkswap "$swapfile" >/dev/null; then
                        swap_created=true
                    else
                        echo "Warning: mkswap failed; removing the unactivated swapfile." >&2
                        rm -f "$swapfile"
                    fi
                else
                    echo "Warning: could not allocate swapfile; continuing without additional swap." >&2
                    rm -f "$swapfile"
                fi
            fi

            if [[ "$swap_created" == "true" ]]; then
                chmod 0600 "$swapfile"
                if swapon "$swapfile"; then
                    # Persist only an actually active swapfile. Replace fstab atomically.
                    if [[ -f "$fstab" ]] && grep -Fq "$swapfile" "$fstab"; then
                        echo "Swap successfully activated; fstab entry already exists."
                    else
                        tmp_fstab=$(mktemp "$(dirname "$fstab")/.fstab.gowave.XXXXXX")
                        if { [[ ! -f "$fstab" ]] || cat "$fstab" > "$tmp_fstab"; } &&
                           printf '%s none swap sw 0 0\n' "$swapfile" >> "$tmp_fstab" &&
                           { [[ ! -f "$fstab" ]] || { chmod --reference="$fstab" "$tmp_fstab" && chown --reference="$fstab" "$tmp_fstab"; }; } &&
                           mv -f "$tmp_fstab" "$fstab"; then
                            echo "Swap successfully activated and persisted."
                        else
                            rm -f "$tmp_fstab"
                            if swapoff "$swapfile"; then
                                rm -f "$swapfile"
                                echo "Warning: could not persist swap configuration; swapfile was deactivated and removed." >&2
                            else
                                echo "Warning: swap is active but could not be persisted in fstab; preserving the active swapfile." >&2
                            fi
                        fi
                    fi
                else
                    echo "Warning: swapon failed; removing the unactivated swapfile." >&2
                    rm -f "$swapfile"
                fi
            fi
        fi
    fi

    # Configure GOMEMLIMIT=250MiB systemd drop-ins.
    mkdir -p /etc/systemd/system/gowave.service.d /etc/systemd/system/gowave-node.service.d
    cat > /etc/systemd/system/gowave.service.d/20-gomemlimit.conf <<'EOF'
[Service]
Environment="GOMEMLIMIT=250MiB"
EOF
    cat > /etc/systemd/system/gowave-node.service.d/20-gomemlimit.conf <<'EOF'
[Service]
Environment="GOMEMLIMIT=250MiB"
EOF
    if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload --no-ask-password
    fi
}

configure_bbr_and_mtu() {
    local state_file="${1:-/var/lib/gowave-auto-nginx/state.json}"
    local sysctl_conf="${2:-/etc/sysctl.d/99-gowave.conf}"
    local bbr_unit="${3:-/etc/systemd/system/bbr-load.service}"

    echo "Configuring MTU probing and BBR congestion control..."
    mkdir -p "$(dirname "$sysctl_conf")" "$(dirname "$bbr_unit")"

    # A file this install did not write is not its to truncate. Only a regular
    # file carrying our marker and nothing but our own lines is adopted, so an
    # operator's policy file, an empty file and a symlink are each refused.
    if [[ -e "$sysctl_conf" || -L "$sysctl_conf" ]]; then
        if [[ -L "$sysctl_conf" ]] ||
            ! grep -qxF '# Managed by GoWave Auto NGINX' "$sysctl_conf" ||
            grep -qvxF -e '# Managed by GoWave Auto NGINX' \
                -e 'net.ipv4.tcp_mtu_probing = 1' \
                -e 'net.ipv4.tcp_congestion_control = bbr' "$sysctl_conf"; then
            echo "Error: Pre-existing unmanaged sysctl configuration at $sysctl_conf. Refusing to overwrite unmanaged host resource." >&2
            return 1
        fi
    fi

    # 1. Deploy bbr-load.service
    cat > "$bbr_unit" <<'EOF'
[Unit]
Description=Load tcp_bbr and set congestion control
Before=systemd-sysctl.service
DefaultDependencies=no
ConditionVirtualization=!container

[Service]
Type=oneshot
ExecStart=-/sbin/modprobe tcp_bbr
ExecStart=-/sbin/sysctl -w net.ipv4.tcp_congestion_control=bbr
RemainAfterExit=yes

[Install]
WantedBy=sysinit.target
EOF

    local selected_cc="cubic"
    # Test BBR availability
    if modprobe tcp_bbr 2>/dev/null; then
        local avail
        avail=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "")
        if [[ "$avail" =~ bbr ]]; then
            if sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null; then
                selected_cc="bbr"
                echo "BBR congestion control enabled."
            else
                echo "Warning: BBR sysctl activation failed; retaining CUBIC." >&2
            fi
        else
            echo "Warning: BBR unavailable, falling back to CUBIC" >&2
        fi
    else
        echo "Warning: BBR unavailable, falling back to CUBIC" >&2
    fi

    # 2. Write the sysctl drop-in once, from a temporary sibling, so an
    # interrupted run never leaves a half-written policy file behind.
    local sysctl_tmp
    sysctl_tmp=$(mktemp "${sysctl_conf}.gowave.XXXXXX") || return 1
    {
        echo "# Managed by GoWave Auto NGINX"
        echo "net.ipv4.tcp_mtu_probing = 1"
        if [[ "$selected_cc" == "bbr" ]]; then
            echo "net.ipv4.tcp_congestion_control = bbr"
        fi
    } > "$sysctl_tmp" || { rm -f "$sysctl_tmp"; return 1; }
    chmod 0644 "$sysctl_tmp" || { rm -f "$sysctl_tmp"; return 1; }
    sync "$sysctl_tmp" 2>/dev/null || true
    mv -f "$sysctl_tmp" "$sysctl_conf" || { rm -f "$sysctl_tmp"; return 1; }
    sync "$(dirname "$sysctl_conf")" 2>/dev/null || true

    if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload --no-ask-password
        if [[ "$selected_cc" == "bbr" ]]; then
            systemctl enable --no-ask-password bbr-load.service
        fi
    fi

    # Record congestionControl in state_file if directory exists
    if [[ -d "$(dirname "$state_file")" ]]; then
        local module_root
        module_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)" || return 1
        python3 - "$state_file" "$selected_cc" "$module_root" <<'PY' || return 1
import json
import os
import sys

path, selected_cc, module_root = sys.argv[1:4]
sys.path.insert(0, module_root)
from modules.api_client import atomic_write_state

if os.path.exists(path):
    with open(path, "r", encoding="utf-8") as stream:
        data = json.load(stream)
    if not isinstance(data, dict):
        raise ValueError("state.json root must be a JSON object")
else:
    data = {}

data["congestionControl"] = selected_cc
atomic_write_state(data, path)
PY
    fi
}

configure_log_rotation() {
    local logrotate_file="${1:-/etc/logrotate.d/gowave-nginx}"
    local journal_conf="${2:-/etc/systemd/journald.conf.d/99-gowave.conf}"

    echo "Configuring log rotation and journal caps..."
    mkdir -p "$(dirname "$logrotate_file")" "$(dirname "$journal_conf")"

    # Daily rotation, 7 days retention, gzip
    cat > "$logrotate_file" <<'EOF'
# Managed by GoWave Auto NGINX
/var/log/nginx/gowave-*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        if [ -f /var/run/nginx.pid ]; then
            kill -USR1 $(cat /var/run/nginx.pid)
        fi
    endscript
}
EOF

    # Cap journal to 100M
    cat > "$journal_conf" <<'EOF'
# Managed by GoWave Auto NGINX
[Journal]
SystemMaxUse=100M
EOF

    if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        systemctl restart --no-ask-password systemd-journald 2>/dev/null || true
    fi
}

# Aggregate Worker security reports onto the Master.
#
# After all Workers are onboarded and verified, this function fetches each
# Worker's effective-state security report via trusted SSH, validates it, and
# writes a combined aggregate report on the Master. The aggregate includes the
# Master's own report plus one entry per Worker, keyed by the Worker's
# planned host name. A Worker whose report cannot be fetched or is stale/
# invalid is recorded with a failed status so the operator sees the gap.
#
# Args: none (reads GOWAVE_PLAN_* arrays, GOWAVE_SSH_* vars, MANAGED_SECURITY_PY,
#       GOWAVE_STATE_DIR for the state directory)
# Returns 0 on success, 1 if any required Worker report is missing or invalid.
aggregate_worker_security_reports() {
    local i host report rc=0
    local state_dir="${GOWAVE_STATE_DIR:-/var/lib/gowave-auto-nginx}"
    local master_report_path="${state_dir}/security-report.json"
    local aggregate_report=""

    # First, load the Master's own report
    if [[ ! -f "$master_report_path" ]]; then
        echo "Error: Master security report not found at $master_report_path" >&2
        return 1
    fi
    local master_report
    master_report=$(cat "$master_report_path") || return 1

    # Build the aggregate structure
    aggregate_report=$(python3 -c 'import json, sys
master = json.load(sys.stdin)
print(json.dumps({"schema_version": 1,
                  "master": master,
                  "workers": {},
                  "observed_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()}))' <<< "$master_report") || return 1

    # No Workers to aggregate? Still write the aggregate with empty workers.
    if [[ "${#GOWAVE_PLAN_NODE_NAMES[@]}" -eq 0 ]]; then
        local agg_path="${state_dir}/security-report-aggregate.json"
        local agg_dir
        agg_dir=$(dirname "$agg_path")
        mkdir -p "$agg_dir" && chmod 0700 "$agg_dir"
        printf '%s\n' "$aggregate_report" > "$agg_path.tmp" && mv "$agg_path.tmp" "$agg_path" && chmod 0600 "$agg_path"
        echo "Security report aggregate written (no Workers planned)."
        return 0
    fi

    local ipv4 ipv6 policy
    ipv4=$(resolve_panel_ipv4) || return 1
    ipv6=$(resolve_panel_ipv6) || return 1
    policy="${GOWAVE_DOT_POLICY:-best-effort}"

    for i in "${!GOWAVE_PLAN_NODE_NAMES[@]}"; do
        host="${GOWAVE_PLAN_NODE_NAMES[$i]}"
        local remote_command worker_report worker_rc=0

        remote_command=$(python3 -c 'import ipaddress, shlex, sys
port, v4, v6, policy = sys.argv[1:]
if (not v4 or ipaddress.ip_address(v4).version != 4
        or (v6 and ipaddress.ip_address(v6).version != 6)
        or policy not in {"off", "best-effort", "required"}):
    sys.exit(1)
print(shlex.join(["python3", "-", "--worker-security-readback", port, v4, v6, policy]))' \
            "$GOWAVE_SSH_NODE_PORT" "$ipv4" "$ipv6" "$policy" 2>/dev/null) || { rc=1; continue; }

        worker_report=$(timeout 45 ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes \
            -o ConnectTimeout=5 -o ClearAllForwardings=yes -o ForwardAgent=no -o UpdateHostKeys=no \
            -p "${GOWAVE_SSH_PORT:-22}" -- "root@$host" "$remote_command" \
            < "$MANAGED_SECURITY_PY" 2>/dev/null) || worker_rc=$?

        if [[ "$worker_rc" -ne 0 ]]; then
            echo "Warning: failed to fetch security report from Worker $host" >&2
            aggregate_report=$(python3 -c 'import json, sys
agg = json.load(sys.stdin)
agg["workers"][sys.argv[1]] = {"status": "fetch_failed", "error": "SSH or helper execution failed"}
print(json.dumps(agg))' "$host" <<< "$aggregate_report") || rc=1
            rc=1
            continue
        fi

        # Validate the Worker report and add to aggregate
        local validated
        validated=$(PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -c '
import json
import sys
from modules.security_report import StateError, validate

try:
    report = json.load(sys.stdin)
    validate(report)
    if report["role"] != "worker":
        raise StateError("Worker report has non-worker role")
    print(json.dumps({"status": "ok", "report": report}))
except (StateError, ValueError, TypeError) as exc:
    print(json.dumps({"status": "invalid", "error": str(exc)}))
    sys.exit(1)
' <<< "$worker_report") || { rc=1; continue; }

        aggregate_report=$(python3 -c 'import json, sys
agg = json.load(sys.stdin)
worker_data = json.load(sys.stdin)
agg["workers"][sys.argv[1]] = worker_data
print(json.dumps(agg))' "$host" <<< "$aggregate_report" <<< "$validated") || rc=1
    done

    # Write the aggregate report atomically
    local agg_path="${state_dir}/security-report-aggregate.json"
    local agg_dir
    agg_dir=$(dirname "$agg_path")
    mkdir -p "$agg_dir" && chmod 0700 "$agg_dir"
    local agg_tmp
    agg_tmp=$(mktemp "${agg_path}.gowave.XXXXXX") || return 1
    printf '%s\n' "$aggregate_report" > "$agg_tmp" || { rm -f "$agg_tmp"; return 1; }
    chmod 0600 "$agg_tmp" || { rm -f "$agg_tmp"; return 1; }
    sync "$agg_tmp" 2>/dev/null || true
    mv -f "$agg_tmp" "$agg_path" || { rm -f "$agg_tmp"; return 1; }
    sync "$agg_dir" 2>/dev/null || true

    echo "Security report aggregate written to $agg_path"
    return "$rc"
}
