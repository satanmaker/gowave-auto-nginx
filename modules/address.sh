#!/usr/bin/env bash
# modules/address.sh - Panel address resolution with an explicit Podman test-only override.

# Podman E2E uses private container addresses that public IP echo services do
# not report. This override is test-only: it requires an explicit opt-in, the
# address must be private, and it must be assigned to this host on the
# run-scoped management network. The public-IP path is untouched otherwise.
resolve_panel_ipv4() {
    local mode="${GOWAVE_PODMAN_TEST_MODE:-0}"
    local override="${GOWAVE_PODMAN_MASTER_ADDRESS:-}"
    if [[ -n "$override" && "$mode" != "1" ]]; then
        echo "Error: GOWAVE_PODMAN_MASTER_ADDRESS is a test-only override and requires GOWAVE_PODMAN_TEST_MODE=1." >&2
        return 1
    fi
    if [[ "$mode" == "1" ]]; then
        if [[ -z "$override" ]]; then
            echo "Error: Podman test mode requires GOWAVE_PODMAN_MASTER_ADDRESS." >&2
            return 1
        fi
        if ! python3 - "$override" <<'PY'
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError as exc:
    raise SystemExit(f"Invalid Podman Master address: {exc}")
if not address.is_private:
    raise SystemExit("Podman Master address must be a private address on the run-scoped network.")
PY
        then
            return 1
        fi
        if ! command -v ip >/dev/null 2>&1; then
            echo "Error: iproute2 is required to validate the Podman Master address." >&2
            return 1
        fi
        local assignment
        assignment=$(ip -o -4 addr show 2>/dev/null | grep -F " ${override}/" || true)
        if [[ -z "$assignment" ]]; then
            echo "Error: Podman Master address $override is not assigned to this host on the run-scoped management network." >&2
            return 1
        fi
        local interface="${GOWAVE_PODMAN_NETWORK_INTERFACE:-}"
        if [[ -n "$interface" ]] && ! grep -Fq " ${interface} " <<<" $assignment "; then
            echo "Error: Podman Master address $override is not assigned to the run-scoped interface $interface." >&2
            return 1
        fi
        local cidr="${GOWAVE_PODMAN_NETWORK_CIDR:-}"
        if [[ -n "$cidr" ]] && ! python3 - "$override" "$cidr" <<'PY'
import ipaddress
import sys

address = ipaddress.ip_address(sys.argv[1])
network = ipaddress.ip_network(sys.argv[2], strict=False)
if address not in network:
    raise SystemExit(
        f"Podman Master address {address} is outside the run-scoped network {network}."
    )
PY
        then
            return 1
        fi
        printf '%s\n' "$override"
        return 0
    fi
    curl -s4 --connect-timeout 5 --max-time 10 https://ifconfig.me 2>/dev/null || \
        curl -s4 --connect-timeout 5 --max-time 10 https://api.ipify.org 2>/dev/null || true
}

resolve_panel_ipv6() {
    local mode="${GOWAVE_PODMAN_TEST_MODE:-0}"
    if [[ "$mode" == "1" ]]; then
        return 0
    fi
    curl -s6 --connect-timeout 5 --max-time 10 https://ifconfig.me 2>/dev/null || \
        curl -s6 --connect-timeout 5 --max-time 10 https://api64.ipify.org 2>/dev/null || true
}
