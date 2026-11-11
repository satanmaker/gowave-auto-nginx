#!/usr/bin/env bash
# Isolated three-container transport acceptance: Control -> Master -> Worker.
# This validates real SSH, TLS 1.3 mTLS, and source-restricted TCP/3002.
# It deliberately does not claim to install GoWave Panel/Node or validate subscriptions.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SUFFIX="${BASHPID}-$(date +%s)"
NETWORK="gowave-multinode-$SUFFIX"
IMAGE="gowave-multinode-testbed:local"
CONTROL="gowave-control-$SUFFIX"
MASTER="gowave-master-$SUFFIX"
WORKER="gowave-worker-$SUFFIX"
CREATED=()

cleanup() {
    local name
    for name in "$WORKER" "$MASTER" "$CONTROL"; do
        podman rm -f "$name" >/dev/null 2>&1 || true
    done
    podman network rm "$NETWORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

unavailable() {
    echo "[UNAVAILABLE] $*" >&2
    exit 77
}
fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

command -v podman >/dev/null 2>&1 || unavailable "Podman is not installed."
[[ "$(id -u)" -eq 0 ]] || unavailable "Run this test with rootful Podman (for example: sudo tests/podman_testbed.sh multi-node)."
ROOTLESS="$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null || true)"
[[ "$ROOTLESS" == "false" ]] || unavailable "Rootful Podman is required for isolated INPUT firewall assertions."
command -v openssl >/dev/null 2>&1 || unavailable "OpenSSL is required on the control host."

echo "[1/7] Build isolated systemd test image"
podman build -t "$IMAGE" -f "$SCRIPT_DIR/Containerfile.testbed" \
    --build-arg BASE_IMAGE=docker.io/library/ubuntu:24.04 "$SCRIPT_DIR"

echo "[2/7] Create isolated Control, Master, and Worker nodes"
podman network create "$NETWORK" >/dev/null
for spec in "$CONTROL:control" "$MASTER:master" "$WORKER:worker"; do
    name="${spec%%:*}"
    alias_name="${spec#*:}"
    podman run -d --name "$name" --hostname "$alias_name" --network "$NETWORK" \
        --network-alias "$alias_name" --systemd=always --privileged \
        -v "$REPO_ROOT:/repo:ro" "$IMAGE" >/dev/null
    CREATED+=("$name")
done

wait_systemd() {
    local name="$1" state attempt
    for attempt in $(seq 1 40); do
        state="$(podman exec "$name" systemctl is-system-running 2>/dev/null || true)"
        case "$state" in running|degraded) return 0 ;; esac
        sleep 1
    done
    podman logs "$name" >&2 || true
    fail "systemd did not become ready in $name (last state: ${state:-unknown})."
}
for name in "$CONTROL" "$MASTER" "$WORKER"; do
    wait_systemd "$name"
    # The image is shared, so discard any build-time host keys and generate unique per-node keys.
    podman exec "$name" bash -lc 'mkdir -p /run/sshd /root/.ssh && chmod 0700 /root/.ssh && rm -f /etc/ssh/ssh_host_* && ssh-keygen -A && /usr/sbin/sshd'
done

echo "[3/7] Verify real Master-to-Worker SSH transport"
podman exec "$MASTER" ssh-keygen -q -t ed25519 -N '' -f /tmp/master_to_worker
podman exec "$MASTER" cat /tmp/master_to_worker.pub |
    podman exec -i "$WORKER" bash -lc 'cat >> /root/.ssh/authorized_keys && chmod 0600 /root/.ssh/authorized_keys'
# Pin the host key from the Worker container filesystem, not an unauthenticated
# ssh-keyscan result. The testbed orchestrator is the trusted local control plane.
WORKER_HOST_KEY="$(podman exec "$WORKER" cat /etc/ssh/ssh_host_ed25519_key.pub)"
[[ "$WORKER_HOST_KEY" == ssh-ed25519\ * ]] || fail "Worker Ed25519 host public key is unavailable."
printf 'worker %s\n' "$WORKER_HOST_KEY" > /tmp/gowave-worker-known-hosts-"$SUFFIX"
podman cp /tmp/gowave-worker-known-hosts-"$SUFFIX" "$MASTER":/tmp/known_hosts
rm -f /tmp/gowave-worker-known-hosts-"$SUFFIX"
podman exec "$MASTER" ssh -i /tmp/master_to_worker -o BatchMode=yes \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/tmp/known_hosts \
    root@worker 'test "$(id -u)" -eq 0 && printf "SSH_WORKER_ROOT_PASS\\n"' |
    grep -q 'SSH_WORKER_ROOT_PASS' || fail "Master could not execute a root command on Worker over pinned SSH."

echo "[4/7] Create ephemeral test PKI and start a TLS 1.3 mTLS Worker endpoint"
podman exec "$CONTROL" bash -lc '
set -e
mkdir -p /tmp/pki && cd /tmp/pki
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 2 -subj "/CN=GoWave Testbed CA"
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=worker"
printf "subjectAltName=DNS:worker\\nextendedKeyUsage=serverAuth\\n" > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 2 -sha256 -extfile server.ext
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=master"
printf "extendedKeyUsage=clientAuth\\n" > client.ext
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 2 -sha256 -extfile client.ext
openssl req -x509 -newkey rsa:2048 -nodes -keyout rogue-ca.key -out rogue-ca.crt -days 2 -subj "/CN=Untrusted Testbed CA"
openssl req -newkey rsa:2048 -nodes -keyout rogue-client.key -out rogue-client.csr -subj "/CN=forged-client"
openssl x509 -req -in rogue-client.csr -CA rogue-ca.crt -CAkey rogue-ca.key -CAcreateserial -out rogue-client.crt -days 2 -sha256
'
for file in ca.crt client.crt client.key rogue-client.crt rogue-client.key; do
    podman cp "$CONTROL:/tmp/pki/$file" "$MASTER:/tmp/$file"
done
for file in ca.crt server.crt server.key; do
    podman cp "$CONTROL:/tmp/pki/$file" "$WORKER:/tmp/$file"
done
podman exec "$WORKER" chmod 0600 /tmp/server.key
podman exec -i "$WORKER" bash -c 'cat > /tmp/mtls_server.py' <<'PY'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ssl

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"mTLS_OK\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass

server = ThreadingHTTPServer(("0.0.0.0", 3002), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.maximum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain("/tmp/server.crt", "/tmp/server.key")
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations("/tmp/ca.crt")
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY
podman exec -d "$WORKER" python3 -u /tmp/mtls_server.py
for attempt in $(seq 1 20); do
    if podman exec "$MASTER" bash -lc 'timeout 1 bash -c "</dev/tcp/worker/3002"' 2>/dev/null; then break; fi
    sleep 1
done
podman exec "$MASTER" bash -lc 'timeout 1 bash -c "</dev/tcp/worker/3002"' 2>/dev/null ||
    fail "Worker mTLS listener did not open TCP/3002."

echo "[5/7] Assert positive and negative mutual-TLS handshakes"
podman exec -i "$MASTER" bash -c 'cat > /tmp/mtls_client.py' <<'PY'
import http.client
import ssl
import sys

mode = sys.argv[1]
context = ssl.create_default_context(cafile="/tmp/ca.crt")
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.maximum_version = ssl.TLSVersion.TLSv1_3
if mode == "positive" or mode == "negative-forged":
    cert = "/tmp/client.crt" if mode == "positive" else "/tmp/rogue-client.crt"
    key = "/tmp/client.key" if mode == "positive" else "/tmp/rogue-client.key"
    context.load_cert_chain(cert, key)

try:
    connection = http.client.HTTPSConnection("worker", 3002, context=context, timeout=5)
    connection.request("GET", "/")
    response = connection.getresponse()
    body = response.read()
    connection.close()
except (ssl.SSLError, OSError, http.client.HTTPException):
    if mode == "positive":
        raise
    print(f"PASS: {mode} rejected during TLS/HTTP exchange")
    raise SystemExit(0)

if mode != "positive":
    raise SystemExit(f"FAIL: Worker accepted {mode}")
if response.status != 200 or body != b"mTLS_OK\n":
    raise SystemExit(f"FAIL: unexpected HTTP response: {response.status} {body!r}")
print("PASS: trusted client completed TLS 1.3 mTLS and received HTTP 200")
PY
podman exec "$MASTER" python3 /tmp/mtls_client.py positive ||
    fail "Valid client certificate did not complete TLS 1.3 mTLS and receive HTTP 200."
podman exec "$MASTER" python3 /tmp/mtls_client.py negative-missing ||
    fail "Worker accepted a client without a certificate."
podman exec "$MASTER" python3 /tmp/mtls_client.py negative-forged ||
    fail "Worker accepted a client certificate signed by an untrusted CA."

echo "[6/7] Enforce Worker TCP/3002 source allowlist and verify from two nodes"
MASTER_IP="$(podman inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$MASTER")"
CONTROL_IP="$(podman inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTROL")"
[[ -n "$MASTER_IP" && -n "$CONTROL_IP" && "$MASTER_IP" != "$CONTROL_IP" ]] ||
    fail "Could not establish distinct Master and Control source addresses."
podman exec "$WORKER" iptables -I INPUT 1 -i eth0 -p tcp --dport 3002 -s "$MASTER_IP" -j ACCEPT
podman exec "$WORKER" iptables -I INPUT 2 -i eth0 -p tcp --dport 3002 -j DROP
podman exec "$WORKER" iptables -C INPUT -i eth0 -p tcp --dport 3002 -s "$MASTER_IP" -j ACCEPT
podman exec "$WORKER" iptables -C INPUT -i eth0 -p tcp --dport 3002 -j DROP

podman exec "$MASTER" python3 /tmp/mtls_client.py positive ||
    fail "Master source allowlist blocked valid mTLS traffic."
if podman exec "$CONTROL" python3 -c 'import socket; s=socket.create_connection(("worker", 3002), timeout=2); s.close()' >/dev/null 2>&1; then
    fail "Untrusted Control node reached Worker TCP/3002."
fi

echo "[7/7] Acceptance summary"
printf '%s\n' \
    "PASS: Master-to-Worker root SSH command over pinned host key" \
    "PASS: TLS 1.3 mTLS with trusted client certificate" \
    "PASS: missing and untrusted client certificates rejected" \
    "PASS: Worker TCP/3002 allows Master source and drops Control source" \
    "NOTE: This is transport/firewall integration, not GoWave Panel/Node installation, API registration, subscription, or Xray/Mihomo client data-plane acceptance."
