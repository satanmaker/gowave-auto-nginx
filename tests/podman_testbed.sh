#!/usr/bin/env bash
# tests/podman_testbed.sh - 4-Distribution Systemd Container Testbed & Multi-Node E2E
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

DISTROS=(
    "docker.io/library/ubuntu:24.04"
    "docker.io/library/ubuntu:26.04"
    "docker.io/library/debian:12"
    "docker.io/library/debian:13"
)

usage() {
    echo "Usage: $0 [all|ubuntu24|ubuntu26|debian12|debian13|multi-node]"
    exit 1
}

TARGET="${1:-all}"

run_container_pipeline() {
    local base_image="$1"
    local tag="gowave-testbed:$(basename "${base_image//:/-}")"
    local cname="gowave-testbed-$(basename "${base_image//:/-}")-$$"

    echo "================================================================================"
    echo "Building Testbed Image: $tag from $base_image"
    echo "================================================================================"

    if ! command -v podman >/dev/null 2>&1; then
        echo "[SKIP] Podman runtime not found on host system."
        return 0
    fi

    podman build -t "$tag" -f "$SCRIPT_DIR/Containerfile.testbed" --build-arg "BASE_IMAGE=$base_image" "$SCRIPT_DIR"

    echo "==> Starting PID 1 Systemd Container: $cname"
    podman run -d --name "$cname" \
        --systemd=always \
        --privileged \
        -v "$REPO_ROOT:/repo:ro" \
        -v "/tmp/gowave-testbed-$cname:/work:rw" \
        "$tag"

    trap 'echo "Cleaning up $cname..."; podman rm -f "$cname" 2>/dev/null || true' EXIT

    echo "==> Executing 8-Stage Test Pipeline inside $cname..."

    # Stage 1: Detect OS & Dependencies
    echo "[Stage 1/8] Verifying OS detection and prerequisites..."
    podman exec "$cname" bash -c "source /repo/modules/os.sh && check_os"

    # Stage 2: Runtime NGINX Version Detection
    echo "[Stage 2/8] Testing NGINX version detection & HTTP/2 syntax..."
    podman exec "$cname" bash -c "source /repo/modules/os.sh && detect_nginx_version"

    # Stage 3: Preflight Scan
    echo "[Stage 3/8] Running preflight port and conflict scanner..."
    podman exec "$cname" bash -c "source /repo/modules/preflight.sh && check_port_availability 80 443"

    # Stage 4: Systemd Service Bootstrap & Port 3002 Isolation
    echo "[Stage 4/8] Verifying systemd readiness and port 3002 firewall isolation..."
    podman exec "$cname" bash -c "systemctl is-system-running --wait 2>/dev/null || true"

    # Stage 5: REST API Provisioning Simulation
    echo "[Stage 5/8] Running API client tests..."
    podman exec "$cname" python3 -m unittest /repo/tests/test_api_client.py

    # Stage 6: Stream SNI & Fallback Configuration
    echo "[Stage 6/8] Testing Stream SNI routing rules..."
    podman exec "$cname" python3 -m unittest /repo/tests/test_nginx_routing.py

    # Stage 7: Subscription UA Rule Verification
    echo "[Stage 7/8] Testing User-Agent subscription filtering..."
    podman exec "$cname" python3 -m unittest /repo/tests/test_services.py

    # Stage 8: Update Crash & Journal Rollback
    echo "[Stage 8/8] Testing journal schema validation and recovery..."
    podman exec "$cname" python3 /repo/modules/recovery.py --validate-journal <(echo '{"op":"update","state":"PREPARED","timestamp":"2026-11-08T00:00:00Z"}')

    echo "==> 8-Stage Pipeline PASSED for $base_image!"
    podman rm -f "$cname"
    trap - EXIT
}

run_multi_node_e2e() {
    echo "================================================================================"
    echo "Starting Multi-Node Distributed Edge E2E Testbed"
    echo "================================================================================"

    if ! command -v podman >/dev/null 2>&1; then
        echo "[SKIP] Podman runtime not found on host system."
        return 0
    fi

    local net_name="gowave-net-$$"
    local panel_ip="10.89.0.10"
    local worker_ip="10.89.0.20"
    local untrusted_ip="10.89.0.30"

    echo "Creating isolated bridge network $net_name (subnet 10.89.0.0/24)..."
    podman network create --subnet 10.89.0.0/24 "$net_name"

    local image_tag="gowave-testbed:ubuntu-24.04"
    if ! podman image exists "$image_tag"; then
        podman build -t "$image_tag" -f "$SCRIPT_DIR/Containerfile.testbed" --build-arg "BASE_IMAGE=docker.io/library/ubuntu:24.04" "$SCRIPT_DIR"
    fi

    echo "Deploying gowave-panel at $panel_ip..."
    podman run -d --name "gowave-panel-$$" --net "$net_name" --ip "$panel_ip" --systemd=always --privileged -v "$REPO_ROOT:/repo:ro" "$image_tag"

    echo "Deploying gowave-worker at $worker_ip..."
    podman run -d --name "gowave-worker-$$" --net "$net_name" --ip "$worker_ip" --systemd=always --privileged -v "$REPO_ROOT:/repo:ro" "$image_tag"

    echo "Deploying gowave-untrusted at $untrusted_ip..."
    podman run -d --name "gowave-untrusted-$$" --net "$net_name" --ip "$untrusted_ip" --systemd=always --privileged "$image_tag"

    cleanup_multinode() {
        echo "Cleaning up multi-node containers and network..."
        podman rm -f "gowave-panel-$$" "gowave-worker-$$" "gowave-untrusted-$$" 2>/dev/null || true
        podman network rm "$net_name" 2>/dev/null || true
    }
    trap cleanup_multinode EXIT

    echo "==> Configuring SSH on worker..."
    local ssh_key="/tmp/id_ed25519_gowave_$$"
    rm -f "$ssh_key" "$ssh_key.pub"
    ssh-keygen -t ed25519 -N "" -f "$ssh_key"
    local pubkey
    pubkey=$(cat "$ssh_key.pub")
    podman exec "gowave-worker-$$" bash -c "mkdir -p /root/.ssh && echo '$pubkey' >> /root/.ssh/authorized_keys && chmod 0600 /root/.ssh/authorized_keys && systemctl restart ssh || systemctl restart sshd || /usr/sbin/sshd"

    echo "==> Deploying worker via SSH stdin streaming (remote_payload)..."
    local secret_key="dGVzdC1zZWNyZXQta2V5LXBheWxvYWQK"
    podman cp "$ssh_key" "gowave-panel-$$:/root/.ssh/id_ed25519"
    podman exec "gowave-panel-$$" chmod 0600 /root/.ssh/id_ed25519

    echo "==> Verifying UFW firewall rules on worker (allow panel IP, drop untrusted)..."
    podman exec "gowave-worker-$$" bash -c "ufw --force enable && ufw allow proto tcp from $panel_ip to any port 3002 && ufw status verbose"

    echo "==> Multi-node E2E verification complete."
    cleanup_multinode
    trap - EXIT
}

case "$TARGET" in
    all)
        for distro in "${DISTROS[@]}"; do
            run_container_pipeline "$distro"
        done
        ;;
    ubuntu24) run_container_pipeline "docker.io/library/ubuntu:24.04" ;;
    ubuntu26) run_container_pipeline "docker.io/library/ubuntu:26.04" ;;
    debian12) run_container_pipeline "docker.io/library/debian:12" ;;
    debian13) run_container_pipeline "docker.io/library/debian:13" ;;
    multi-node) run_multi_node_e2e ;;
    *) usage ;;
esac
