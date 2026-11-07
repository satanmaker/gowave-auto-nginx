# Testing Strategy & CI Architecture: GoWave Auto NGINX

**Document Status**: Authoritative Specification  
**Source Baseline**: `community-baseline/tests/run_ci.py` (`community-baseline`) and `gowave-node/tests/`  
**Purpose**: Define the 5-suite testing architecture, runner contract, EUID privilege separation, test matrix, and acceptance gates for GoWave Auto NGINX.

---

## 1. Test Runner Contract & Privilege Separation

GoWave Auto NGINX adopts the exact test runner architecture of `community-baseline/tests/run_ci.py`. The runner verifies test completeness dynamically and enforces strict process EUID privileges before running any suite:

```bash
# Verify test inventory and completeness (zero unassigned or stale TestCase classes)
python3 tests/run_ci.py --check-completeness

# Run specific suite
python3 tests/run_ci.py --suite <name>

# Official OpenSpec strict validation (version 1.16.1)
openspec validate --all --strict
# or target specific change:
openspec validate gowave-auto-nginx --strict
```

### Privilege Context Enforcement

| Suite Name | Permitted EUID | Required Execution Environment | Forbidden Operations |
|---|---|---|---|
| **`nonroot`** | `os.geteuid() != 0` (Unprivileged) | Bare host or unprivileged container (`--user 1001:1001`) | Any `sudo`, filesystem mutation outside `/tmp`, network binds < 1024 |
| **`integration`**| `os.geteuid() != 0` (Unprivileged) | Bare host or unprivileged container (`--user 1001:1001`) | Systemd modifications, real firewall/iptables changes |
| **`services`** | `os.geteuid() != 0` (Unprivileged) | Mock container / local unprivileged environment (`--user 1001:1001`) | Host network manager changes, host DNS changes |
| **`root`** | `os.geteuid() == 0` (Root) | **Disposable throwaway container ONLY** | Bare host execution; changes to developer's host OS |
| **`systemd`** | `os.geteuid() == 0` (Root inside VM) | **QEMU TCG Virtual Machine with genuine PID 1 systemd** | Direct container execution lacking genuine systemd |

If `run_ci.py` is invoked with an incorrect EUID, it immediately terminates with code 1 and outputs:
```text
PRIVILEGE: FAIL — <suite> requires EUID 0 (or EUID != 0)
```

---

## 2. Test Suites & Verification Contracts

```mermaid
flowchart TD
    systemd["systemd (EUID 0 in QEMU VM): Genuine PID 1, Cold Boot, Crash Recovery"]
    root["root (EUID 0 in Container): Users, File Permissions, Fail2ban Syntax, UFW Rules"]
    services["services (EUID != 0): Live Mock Daemon Handshakes, Client TLS Simulations"]
    integration["integration (EUID != 0): GoWave API Provisioning, SQLite WAL Online Backup"]
    nonroot["nonroot (EUID != 0): ShellCheck, Python Linting, Config Generators, Malicious Tarballs"]
    
    nonroot --> integration --> services --> root --> systemd
```

### Suite 1: `nonroot` (L1 Static Linting & Unit Logic)
- **Privilege**: Strictly non-root (`id -u != 0`).
- **Tests Covered**:
  - `test_shellcheck`: ShellCheck on all bash scripts (`SC1090`, `SC1091` ignored where appropriate).
  - `test_python_lint`: `flake8` and `mypy` on management Python utilities.
  - `test_scripts_py`: Execution of `python3 tests/test_scripts.py` verifying CLI script arguments and basic handlers.
  - `test_openspec`: OpenSpec CLI validation (`openspec validate --all --strict` / `openspec validate gowave-auto-nginx --strict`).
  - `test_nginx_generator`: NGINX Stream and HTTP configuration generator tests evaluating runtime version detection (`nginx -v`): validates `listen ... ssl http2;` for NGINX < 1.25.1 (Ubuntu 24.04 with 1.24.0, Debian 12 with 1.22.1) and `listen ...; http2 on;` for NGINX >= 1.25.1 (Debian 13 with 1.26.3, Ubuntu 26.04), verifying syntax with `nginx -t`.
  - `test_archive_security`: Malicious tarball injection tests verifying rejection of `../` path traversals, leading `/`, symlinks escaping managed roots, device nodes, and FIFOs.
  - `test_node_secret_parser`: Unit tests verifying base64 `SECRET_KEY` parsing and HKDF-SHA256 SNI derivation (`rw-v1`).
  - `test_nginx_conflict_scanner`: Unit tests scanning test `/etc/nginx/` trees with mock virtual hosts; asserts correct detection and reporting of unmanaged `listen ... 443` directives.
  - `test_remote_payload_generator`: Unit tests verifying SSH stdin payload generation (packing variables via `declare -p` and modular shell functions via `declare -f`) for remote worker deployment without file transfer dependencies.

### Suite 2: `integration` (L3 Inter-Process Contracts & Online Backup)
- **Privilege**: Non-root (`id -u != 0`).
- **Execution Harness & Fixture Strategy (AUD-11)**:
  - Runs in a disposable container under unprivileged UID (`--user 1001:1001`).
  - Spawns a real, native `gowave-server` instance backed by tmpfs-isolated SQLite (`DATABASE_URL=/tmp/test-gowave-$$.db`).
  - Bootstraps admin credentials dynamically via `POST /api/auth/register` (`username: "admin"`, `password: "testPassword123!"`).
  - Request/response validation utilizes static JSON fixtures in `tests/fixtures/api/` representing canonical DTO schemas.
- **Tests Covered**:
  - `test_sqlite_online_backup`: Continuous write transactions executed concurrently while `sqlite3 <db> ".backup <dest>"` executes; verify destination database passes `PRAGMA integrity_check;` with 100% data consistency.
  - `test_gowave_api_auth`: GoWave API admin bootstrap: query `/api/auth/status`, register initial admin via `POST /api/auth/register`, login via `POST /api/auth/login`, and verify JWT token issuance.
  - `test_profile_provisioning`: Authenticated creation of single unified Config Profile via `POST /api/config-profiles` containing all 4 inbounds, retrieving the 4 generated inbound UUIDs via `GET /api/config-profiles/{uuid}/inbounds`, and verifying `GET /api/config-profiles/{uuid}/computed-config`.
  - `test_computed_config_validation`: Queries `GET /api/config-profiles/{uuid}/computed-config` and verifies explicit validation checklist (AUD-09): HTTP status is 200, `response.config` is valid JSON, no top-level `error` or `message` fields, `inbounds` array contains exactly 4 elements, `streamSettings.security` is populated for all inbounds, and REALITY settings with valid keys exist on port 8443.
  - `test_node_association`: Verification of linking single unified profile and all 4 inbounds to node via `POST /api/nodes` or `PATCH /api/nodes/{uuid}` with `{"configProfile": {"activeConfigProfileUuid": "<uuid>", "activeInbounds": [...]}}`.
  - `test_profile_cross_membership_negative`: Deliberately attempts to associate an inbound UUID belonging to a different Config Profile into `configProfile.activeInbounds`; asserts GoWave rejects the transaction with error `inbound X does not belong to config profile Y` without mutating the Node.
  - `test_internal_squad_and_user_sync`: Automated creation of managed Internal Squad via `POST /api/internal-squads` with 4 inbounds, creation of user via `POST /api/users` with squad assignment, and assertion that `syncUserToSingleNode` dispatches credentials to the Node for all 4 inbounds.
  - `test_host_provisioning`: Automated creation of Host records via `POST /api/hosts` for each MVP protocol with `"nodes": ["<node-uuid>"]`, `"internalSquads"`, and verified `securityLayer` (`DEFAULT` for REALITY, `TLS` for XHTTP, WS, and Trojan gRPC), followed by read-back verification via `GET /api/hosts` confirming node and squad relations.
  - `test_subscription_user_agent`: Verification that requests with valid client User-Agents (`v2rayN`, `ClashMeta`) return HTTP 200, while requests with missing or empty User-Agent return HTTP 403 Forbidden.
  - `test_response_rules_and_templates`: Verification that `DisableSubscriptionAccessByPath=false` in GoWave database and default templates (`MIHOMO` and `XRAY_JSON`) are seeded and intact.
  - `test_x25519_api_generation`: Integration test verifying Curve25519 keypair generation via `GET /api/system/tools/x25519/generate` returning valid base64 `privateKey` and `publicKey`.
  - `test_api_token_generation`: Integration test verifying long-lived token creation via `POST /api/tokens` with granular scopes (`subscription-page-configs:*`, `subscriptions:subpage-config`, `users:by-username`) and secure credential file creation at `/root/gowave-credentials.txt` with mode `0600`.
  - `test_mtls_handshake`: Go test vectors validating Node mTLS 1.3 handshake with derived HKDF SNI and RS256 JWT bearer token against mock TLS server.

### Suite 3: `services` (L4 Live Services & Protocol Simulation)
- **Privilege**: Non-root (`id -u != 0`).
- **Tests Covered**:
  - `test_stream_sni_routing`: NGINX Stream routing port 443 into `panel_domain` (7443) and `reality_domain` (8443).
  - `test_reality_fallback`: Legitimate REALITY client handshake vs scanner probe; verify fallback sends PROXY protocol v1 to port 9443 where decoy static site is served.
  - `test_xhttp_streaming`: Bidirectional HTTP/1.1 and HTTP/2 POST stream sent to `https://panel_domain/<xhttp_path>/`; verify NGINX reverse proxies to loopback port without chunk buffering or request body truncation.
  - `test_websocket_upgrade`: Verification of WebSocket handshake and protocol upgrade headers.
  - `test_trojan_grpc`: Live client test connecting to Trojan gRPC over HTTP/2 with password authentication, `grpc_pass` proxying to 10003, and bidirectional data transfer.
  - `test_worker_edge_traffic`: Live client test connecting directly to remote Worker node on port 443 across all 4 protocols, validating Worker NGINX Stream, TLS termination, and direct data tunneling without traversing Central Panel.
  - `test_xray_subscription`: Fetch `GET /api/sub/{shortUuid}/v2ray-json` with Xray UA; verify explicit assertion checklist (AUD-08): `status_code == 200`, `len(body.strip()) > 0`, body parses as valid JSON with `len(inbounds) >= 4`, all 4 inbounds present on port 443, and zero loopback/internal leaks (`127.0.0.1`, internal ports, unix sockets).
  - `test_mihomo_subscription`: Fetch `GET /api/sub/{shortUuid}/mihomo` with Mihomo UA; verify explicit assertion checklist (AUD-08): `status_code == 200`, `Content-Type: text/yaml`, `len(body.strip()) > 0`, body parses as valid YAML matching `assets/mihomo/expected.yaml` structure with `len(proxies) >= 4`, and zero internal leaks.
  - `test_client_import_validators`: Pass fetched Xray JSON to official Xray core (`v1.8.24`+ / `v24.9.30`+ via `xray run -test -c`) and Mihomo YAML to official Mihomo core (`v1.18.10`+ / `v1.19.0`+ via `mihomo -t -f`), asserting exit code 0 and verifying all proxy fields (type, server, port, cipher, password, uuid, flow, tls, sni, alpn, reality-opts, grpc-opts, ws-opts, xhttp-opts).
  - `test_node_firewall_isolation`: Verify that external IPv4 (`<public-ipv4>:3002`) and IPv6 (`[<public-ipv6>]:3002`) probes are dropped or refused by UFW firewall rules, while local loopback connections (`127.0.0.1:3002`, `[::1]:3002`) succeed, and verify rule persistence after UFW reload.

### Suite 4: `root` (L2 Filesystem Permissions & Isolated System Drop-Ins)
- **Privilege**: Root (`id -u == 0`) inside disposable Docker container.
- **Tests Covered**:
  - `test_user_permissions`: Creation of user `gowave:gowave`, verify directory permissions `1770 root:gowave` on `/opt/gowave`, and verify executable is owned by `root:root`.
  - `test_service_install`: Execution of `gowave-server service install /opt/gowave` and verification of generated `90-unprivileged.conf` and `gowave-update.path`.
  - `test_secret_delivery`: Delivery of `SECRET_KEY` via stdin or temporary `0600` file; verify process inspection via `/proc/<pid>/cmdline` reveals zero credentials.
  - `test_fail2ban_syntax`: Validation of `/etc/fail2ban/jail.d/90-gowave-auto-nginx.local` via `fail2ban-client --test`.
  - `test_backup_format_v1`: Generation of `GoWave Auto NGINX Backup Format v1` archive; verify mode `0600` and validation of `meta.json` manifest.

### Suite 5: `systemd` (L5 Genuine PID 1 Systemd in QEMU TCG Guest)
- **Privilege**: Root (`id -u == 0`) inside QEMU virtual machine.
- **Target OS Matrix**: Ubuntu 24.04 LTS, Ubuntu 26.04 LTS, Debian 12, Debian 13.
- **Tests Covered**:
  - `test_qemu_clean_install`: Clean installation in fresh OS image; verify all services (`gowave`, `gowave-node`, `nginx`, `fail2ban`) start and reach `active (running)`.
  - `test_qemu_port_conflict`: Preflight port conflict test: simulate busy port 3000, 3001, or 3002; verify installer detects conflicting process and aborts without altering system state.
  - `test_qemu_cold_reboot`: Execute `systemctl reboot`; verify all services, firewall rules, and DoT configurations persist and resume automatically.
  - `test_qemu_channel_switching`: Switch from Stable to Dev via `gowave-auto.sh channel dev`, verify health, then switch back from Dev to Stable via `gowave-auto.sh channel stable --force`, verifying pre-switch snapshot creation and health.
  - `test_qemu_update_rollback`: Trigger `gowave-auto.sh update` with simulated post-update migration crash; verify automatic rollback from `/var/lib/gowave-auto-nginx/recovery/` restores original operational state.
  - `test_qemu_power_loss_recovery`: Simulate hard power cut / SIGKILL during update transaction; verify journal state machine initiates recovery on subsequent boot.

---

## 3. GitHub Actions CI Pipeline Architecture

> [!NOTE]
> **Implementation Status (AUD-12)**: The GitHub Actions workflows listed below (`.github/workflows/*.yml`) and linter configuration files (`.shellcheckrc`) represent authoritative architectural specifications and are scheduled deliverables of Tasks 1.1, 1.3, and 13.1–13.3 (`[IMPLEMENTATION_PLANNED]`).

| Workflow File | Trigger Events | Required Suites & Tasks | Status Check Name | Permissions |
|---|---|---|---|---|
| `lint-and-nonroot.yml` | Push, Pull Request | Suite `nonroot`, ShellCheck, actionlint, completeness check | `lint-and-nonroot` | `contents: read` |
| `root-integration.yml` | Push, Pull Request | Suite `root` (EUID 0) & Suite `integration` (container `--user 1001:1001`, EUID != 0) | `root-integration` | `contents: read` |
| `systemd-acceptance.yml` | Schedule (daily), Manual dispatch | Suite `services` & Suite `systemd` across Ubuntu 24/26 & Debian 12/13 | `systemd-acceptance` | `contents: read`, `actions: write` |

---

## 4. Local Multi-Distribution Podman Testbed (Pre-Deployment VPS Gate)

To guarantee that deployment scripts and automation execute cleanly before deploying to a physical or cloud VPS, the repository provides an automated local testbed runner script: `tests/podman_testbed.sh`.

Podman provides containerized execution with genuine PID 1 `systemd` support (`--systemd=always --privileged`), eliminating the need to launch heavy QEMU virtual machines for fast, multi-distribution pre-flight checks.

### Target Distribution Matrix & Container Images

| Distribution Identifier | Target Operating System | Container Image | Container Init & Flags | Specific Adaptations Verified |
|---|---|---|---|---|
| `ubuntu24` | Ubuntu 24.04 LTS (Noble) | `docker.io/library/ubuntu:24.04` | PID 1 systemd 255.4 (`--systemd=always --privileged`) | NGINX 1.24.0 legacy HTTP/2 syntax (`listen ... ssl http2;`), UFW firewall loopback rules, native Panel/Node units |
| `ubuntu26` | Ubuntu 26.04 LTS (Resolute) | `docker.io/library/ubuntu:devel` | PID 1 systemd 256+ (`--systemd=always --privileged`) | Modern NGINX HTTP/2 syntax (`http2 on;`), Stream multiplexing, UFW isolation |
| `debian12` | Debian 12 (Bookworm) | `docker.io/library/debian:12` | PID 1 systemd 252.30 (`--systemd=always --privileged`) | Auto-installation of `systemd-resolved`, NGINX 1.22.1 legacy syntax (`listen ... ssl http2;`), Debian security origins |
| `debian13` | Debian 13 (Trixie) | `docker.io/library/debian:testing` | PID 1 systemd 256+ (`--systemd=always --privileged`) | Modern NGINX HTTP/2 syntax (`http2 on;`), systemd-resolved integration, Stream multiplexing |

### CLI Invocation Interface

```bash
# Run all 4 distributions sequentially and verify zero failures
./tests/podman_testbed.sh all

# Or run individual distribution testbeds
./tests/podman_testbed.sh ubuntu24
./tests/podman_testbed.sh ubuntu26
./tests/podman_testbed.sh debian12
./tests/podman_testbed.sh debian13
```

### Container Launch Contract & Cgroups Configuration

`podman_testbed.sh` invokes Podman with specific volume mounts and systemd integration flags:
```bash
podman run --rm -d \
  --name "gowave-testbed-${DISTRO}" \
  --systemd=always \
  --privileged \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  -v "${WORKSPACE_ROOT}:/workspace:ro" \
  "${IMAGE_NAME}"
```

### 8-Stage In-Container Verification Pipeline

Once the container reaches PID 1 `systemd` readiness, `podman_testbed.sh` executes the following 8 stages via `podman exec`:

1. **Stage 1: Base OS Detection & Prerequisite Provisioning**:
   - Detects OS release via `/etc/os-release`.
   - On Debian 12: explicitly verifies and executes automatic installation of `systemd-resolved`.
   - Installs base prerequisites (`curl`, `tar`, `sqlite3`, `socat`, `jq`, `openssl`, `ufw`, `fail2ban`, `nginx`).
2. **Stage 2: Runtime NGINX HTTP/2 Syntax Adaptation**:
   - Inspects `nginx -v` version string.
   - For NGINX < 1.25.1 (Ubuntu 24.04, Debian 12): verifies compiled configuration uses `listen 7443 ssl http2;`.
   - For NGINX >= 1.25.1 (Ubuntu 26.04, Debian 13): verifies compiled configuration uses `listen 7443 ssl;` and `http2 on;`.
   - Validates configuration integrity with `nginx -t`.
3. **Stage 3: Preflight Conflict Scanner Verification**:
   - Scans port availability for 3000, 3001, 3002, 7443, 8443, 9443, 443.
   - Simulates unmanaged NGINX virtual hosts listening on 443 and verifies installer detection and clean diagnostic abort.
4. **Stage 4: Systemd Service Bootstrap & Port Isolation**:
   - Boots `gowave.service` on loopback port 3000 (`APP_PORT=3000`).
   - Provisions `gowave-node.service` with drop-in `/etc/systemd/system/gowave-node.service.d/10-port.conf` enforcing port 3002.
   - Applies UFW firewall rules denying public ingress to 3002 while permitting loopback `127.0.0.1:3002` and `[::1]:3002`.
5. **Stage 5: GoWave REST API Provisioning & Native x25519 Keys**:
   - Bootstraps admin account via `POST /api/auth/register` and verifies JWT session.
   - Generates Curve25519 keypair via `GET /api/system/tools/x25519/generate`.
   - Creates single unified Config Profile with all 4 inbounds via `POST /api/config-profiles`.
   - Configures managed Internal Squad, associates user, and creates Host records (`POST /api/hosts`).
   - Generates scoped API tokens and records credentials to `/root/gowave-credentials.txt` with mode `0600`.
6. **Stage 6: NGINX Stream & Reverse Proxy Verification**:
   - Tests SNI dispatch on port 443 (`panel_domain` -> 7443, `reality_domain` -> 8443).
   - Validates XHTTP buffering disabled (`proxy_buffering off; proxy_request_buffering off;`).
   - Validates WebSocket connection upgrade headers and Trojan gRPC proxying.
   - Sends scanner probes to port 8443 and verifies PROXY protocol v1 fallback to decoy website on 9443.
7. **Stage 7: Deterministic Subscription Delivery & Core Parser Validation**:
   - Fetches Xray JSON (`GET /api/sub/{shortUuid}/v2ray-json`) and validates schema using `xray run -test -c`.
   - Fetches Mihomo YAML (`GET /api/sub/{shortUuid}/mihomo`) and validates schema using `mihomo -t -f`.
   - Confirms zero loopback leaks (`127.0.0.1`, `localhost`, internal ports) across all delivered client profiles.
8. **Stage 8: Disaster Recovery & Rollback Simulation**:
   - Creates `GoWave Auto NGINX Backup Format v1` archive and verifies `0600` permissions.
   - Injects simulated process failure into update transaction and asserts automatic rollback from `/var/lib/gowave-auto-nginx/recovery/` via `journal.json`.

### Pre-Deployment VPS Gate Rule

> [!IMPORTANT]
> **VPS Deployment Gate Requirement**: No changes to `gowave-auto.sh`, `gowave-node-auto.sh`, templates, or systemd configurations may be pushed to production branches or executed on physical/cloud VPS environments without passing `./tests/podman_testbed.sh all` across all 4 operating systems.
