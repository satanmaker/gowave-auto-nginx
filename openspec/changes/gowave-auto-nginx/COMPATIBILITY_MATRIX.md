# OS & Architecture Compatibility Matrix: GoWave Auto NGINX

**Document Status**: Authoritative Baseline  
**Date**: November 7, 2026  
**Change Target**: `openspec/changes/gowave-auto-nginx/`

---

## 1. Compatibility Status Definitions

- **UPSTREAM_SUPPORTED**: Explicitly stated by upstream documentation/build scripts and confirmed by source code analysis and existing test workflows.
- **SOURCE_COMPATIBLE**: Source code and dependencies do not exclude the OS or architecture, but dedicated upstream CI tests for this specific distribution are absent or minimal.
- **ADAPTED**: Requires GoWave Auto NGINX compatibility layers or workarounds to function reliably.
- **PROJECT_CI_PLANNED**: Automated containerized or unit tests designed and scheduled in the project CI pipeline; executes during implementation phase.
- **PROJECT_CI_TESTED**: Automated containerized or unit tests actually executed and passed on the exact commit with preserved test artifacts.
- **PROJECT_E2E_PLANNED**: End-to-end clean installation, reboot survival, and protocol handshake verification designed and scheduled in full systemd environment (QEMU); executes during implementation phase.
- **PROJECT_E2E_VERIFIED**: Real system tests actually executed and passed on the target OS with preserved test run logs.
- **NOT_SUPPORTED**: Incompatible, broken, or explicitly excluded from support scope.
- **UNKNOWN**: Insufficient evidence to determine compatibility without further testing.

### Minimum Hardware & Resource Requirements

| Deployment Topology | Minimum vCPU | Minimum RAM | Recommended Swap | Minimum Storage | Notes & Degradation Strategy |
|---|---|---|---|---|---|
| **All-in-One (Panel + Node + Xray + NGINX)** | 1 vCPU | 1 GB RAM | 1 GB swapfile | 10 GB NVMe/SSD | 512 MB RAM is insufficient for full stack with Vite/Go migrations; 1 GB is hard minimum. GOMEMLIMIT=250MiB. |
| **Distributed Edge Worker (Node + Xray + NGINX)** | 1 vCPU | 512 MB RAM | 1 GB swapfile | 5 GB SSD | 512 MB RAM is fully supported for Worker edge gateways running without the React/Panel backend. |

*Kernel Congestion Fallback*: Full BBR is deployed on kernels supporting `tcp_bbr`. On restricted virtualization environments (e.g. OpenVZ, LXC, custom cloud kernels lacking `tcp_bbr`), the installer gracefully falls back to `cubic`, logs `BBR unavailable, falling back to CUBIC`, records `"congestionControl": "cubic"` in `state.json`, and completes deployment successfully.

---

## 2. Component Compatibility Matrix by Operating System

### Ubuntu 24.04 LTS (Noble Numbat) & Ubuntu 26.04 LTS (Resolute Raccoon)

| Component | Target Version | Ubuntu 24.04 Status | Ubuntu 26.04 Status | Required Adaptations | Evidence & Code Source |
|---|---|---|---|---|---|
| **GoWave Panel** | `v1.2.4` (`6d2c357`) | `UPSTREAM_SUPPORTED` | `SOURCE_COMPATIBLE` | `GOWAVE_PROXY=external` in `.env`; `service install` drop-in. | `gowave/install.sh:48-66` (amd64/arm64 detection) |
| **GoWave Node** | `v1.1.3` (`7b3514d`) | `UPSTREAM_SUPPORTED` | `SOURCE_COMPATIBLE` | Installed via upstream `gowave-node/install.sh`; wildcard `:3002` isolated by UFW. | `gowave-node/install.sh:82-97` (systemd detection) |
| **Xray-Core (`rw-core`)** | `v25.x` | `UPSTREAM_SUPPORTED` | `SOURCE_COMPATIBLE` | Supervised directly by GoWave Node ProcessManager. | `gowave-node/internal/xray/process.go:51-94` |
| **NGINX + Stream** | 1.24.0 (Noble) / 1.26+ (Resolute) | `ADAPTED` | `UPSTREAM_SUPPORTED` | **Ubuntu 24.04 adaptation**: Ubuntu 24.04 ships NGINX 1.24.0 (< 1.25.1), requiring legacy `listen ... ssl http2;` across both HTTPS (7443) and Decoy (9443) listeners. Directive `http2 on;` causes fatal syntax error on 1.24.0. Runtime `nginx -v` evaluation determines syntax. | Ubuntu 24.04 `nginx` package (1.24.0-2ubuntu7); `nginx.org/en/docs/http/ngx_http_v2_module.html` |
| **Certbot** | 2.x+ | `UPSTREAM_SUPPORTED` | `UPSTREAM_SUPPORTED` | Webroot mode with deployment reload hook. | Certbot deb package in Ubuntu main repo |
| **Fail2ban** | 1.0+ | `UPSTREAM_SUPPORTED` | `UPSTREAM_SUPPORTED` | Inspect both `sshd.service` and `ssh.socket` bindings. | `community-baseline/assets/security/managed.py:51-62` |
| **UFW Firewall** | 0.36+ | `UPSTREAM_SUPPORTED` | `UPSTREAM_SUPPORTED` | Whitelist active SSH port before enabling; deny external 3002. | Ubuntu standard UFW package |
| **systemd-resolved / DoT** | Systemd 255+ | `UPSTREAM_SUPPORTED` | `UPSTREAM_SUPPORTED` | Global DoT drop-in (`DNSOverTLS=yes`). | `community-baseline/assets/security/managed.py:17-34` |
| **unattended-upgrades** | Distro package | `UPSTREAM_SUPPORTED` | `UPSTREAM_SUPPORTED` | Set origin to `origin=Ubuntu,archive=${distro_codename}-security`. Set `Automatic-Reboot "false"`. | `community-baseline/assets/security/managed.py:84-86` |
| **Backup Tooling** | Format v1 | `UPSTREAM_SUPPORTED` | `UPSTREAM_SUPPORTED` | Python 3 + tar + gzip + sqlite3 CLI. | `community-baseline/assets/backup/x-ui-backup.sh:13-14` |
| **Test Runner / QEMU** | Python 3.12+ / QEMU 8+ | `PROJECT_CI_PLANNED` | `PROJECT_CI_PLANNED` | Full systemd QEMU TCG guest testing. | `community-baseline/tests/systemd/boot.sh` |

---

### Debian 12 (Bookworm) & Debian 13 (Trixie)

| Component | Target Version | Debian 12 Status | Debian 13 Status | Required Adaptations | Evidence & Code Source |
|---|---|---|---|---|---|
| **GoWave Panel** | `v1.2.4` (`6d2c357`) | `SOURCE_COMPATIBLE` | `SOURCE_COMPATIBLE` | Static Linux binary; `GOWAVE_PROXY=external` in `.env`. | `gowave/install.sh:48-66` |
| **GoWave Node** | `v1.1.3` (`7b3514d`) | `SOURCE_COMPATIBLE` | `SOURCE_COMPATIBLE` | Installed via upstream `gowave-node/install.sh`; wildcard `:3002` isolated by UFW. | `gowave-node/install.sh:82-97` |
| **Xray-Core (`rw-core`)** | `v25.x` | `SOURCE_COMPATIBLE` | `SOURCE_COMPATIBLE` | Supervised directly by GoWave Node ProcessManager. | `gowave-node/internal/xray/process.go:51-94` |
| **NGINX + Stream** | 1.22.1 (Bookworm) / 1.26.3 (Trixie) | `ADAPTED` | `UPSTREAM_SUPPORTED` | **Debian 12 adaptation**: NGINX 1.22.1 (< 1.25.1) requires `listen ... ssl http2;` across both HTTPS (7443) and Decoy (9443) listeners. Using `http2 on;` causes fatal syntax error. Debian 13 ships NGINX 1.26.3 (>= 1.25.1) which uses `http2 on;`. | Debian 12 `nginx-full` package (1.22.1-9); Debian 13 package (1.26.3-1); `community-baseline/x-ui-latest.sh:790-795` |
| **Certbot** | 2.1+ | `UPSTREAM_SUPPORTED` | `UPSTREAM_SUPPORTED` | Webroot mode with deployment hook. | Debian official repository |
| **Fail2ban** | 1.0+ | `UPSTREAM_SUPPORTED` | `UPSTREAM_SUPPORTED` | Monitor auth journal or `/var/log/auth.log`. | `/etc/fail2ban/jail.conf` in Debian |
| **UFW Firewall** | 0.36+ | `UPSTREAM_SUPPORTED` | `UPSTREAM_SUPPORTED` | Whitelist SSH before enabling; deny external 3002. | Debian official repository |
| **systemd-resolved / DoT** | Systemd 252+ | `ADAPTED` | `UPSTREAM_SUPPORTED` | **Debian 12 adaptation**: `systemd-resolved` is NOT installed by default. Must run `apt-get install -y systemd-resolved` when DoT is requested. | Debian 12 package inventory; `community-baseline/assets/security/managed.py:111-120` |
| **unattended-upgrades** | Distro package | `ADAPTED` | `UPSTREAM_SUPPORTED` | **Debian adaptation**: Set origin to `origin=Debian,label=Debian-Security,codename=${distro_codename}-security`. Set `Automatic-Reboot "false"`. | `community-baseline/assets/security/managed.py:87-88` |
| **Backup Tooling** | Format v1 | `UPSTREAM_SUPPORTED` | `UPSTREAM_SUPPORTED` | Python 3 + tar + gzip + sqlite3 CLI. | Standard POSIX tools in Debian base |
| **Test Runner / QEMU** | Python 3.11+ / QEMU 8+ | `PROJECT_CI_PLANNED` | `PROJECT_CI_PLANNED` | Full systemd QEMU TCG guest testing. | `community-baseline/tests/systemd/boot.sh` |

---

## 3. CPU Architecture Support Matrix

| Architecture | Scope Role | Status | Availability of Binaries | Required Adaptations & Limitations |
|---|---|---|---|---|
| **amd64 (x86_64)** | **Primary MVP Target** | `UPSTREAM_SUPPORTED` / `PROJECT_E2E_PLANNED` | Full: `gowave-linux-amd64`, `gowave-node-linux-amd64`, `rw-core` | None. Full automated CI and QEMU test coverage. |
| **arm64 (aarch64)** | **Secondary / Conditional**| `SOURCE_COMPATIBLE` | Available: `gowave-linux-arm64`, `gowave-node-linux-arm64`, `xray-linux-arm64` | Requires 64-bit kernel and 4KB standard memory page size. E2E verification is deferred until physical/emulated ARM64 CI runners are integrated. |

---

## 4. Port Conflict Avoidance Matrix (All-in-One Topology)

| Service Component | Default Port | Binding Scope | Purpose | Conflicting Defaults & Resolution |
|---|---|---|---|---|
| **GoWave Panel** | `3000` | Loopback (`127.0.0.1`) | Web UI & REST API | Kept at default `APP_PORT=3000`. |
| **GoWave Metrics** | `3001` | Loopback (`127.0.0.1`) | Prometheus Metrics | Kept at default `METRICS_PORT=3001`. |
| **Local GoWave Node**| `3002` | Wildcard (`:3002`), UFW loopback-only | Node mTLS Control Plane | **Resolved conflict & security**: Changed to `NODE_PORT=3002`. UFW denies external traffic; only loopback (`127.0.0.1`, `::1`) permitted. |
| **NGINX Panel Listener**| `7443` | Loopback (`127.0.0.1`) | Terminated TLS HTTPS | Receives PROXY protocol v1 from Stream 443. |
| **Xray REALITY Inbound**| `8443` | Loopback (`127.0.0.1`) | VLESS REALITY Vision | Receives PROXY protocol v1 from Stream 443. |
| **NGINX Decoy Listener**| `9443` | Loopback (`127.0.0.1`) | REALITY Fallback Camouflage | Receives PROXY protocol v1 from Xray 8443. |
| **Xray Inbounds** | `10001-10003`| Loopback (`127.0.0.1`) | XHTTP, WS, gRPC | Internal cleartext inbounds behind NGINX TLS. |
| **NGINX HTTP** | `80` | Public (`0.0.0.0/0`, `[::]`) | ACME HTTP-01 & Redirect | Standard web port. |
| **NGINX Stream** | `443` | Public (`0.0.0.0/0`, `[::]`) | SNI Multiplexer | Public TLS edge port. |
| **OpenSSH** | Dynamic | Public (`0.0.0.0/0`) | Administration | Detected dynamically via `sshd -T` / `ssh.socket`; never overwritten. |

---

## 5. Client Validators & Schema Compatibility Matrix

To prevent acceptance of corrupt or pseudo-valid subscription files, verification uses genuine client core validators and parsers pinned to exact minimum versions:

| Client Format | Target Minimum Version | Tested Baseline Version | Validation Command & Tool | Verified Transport Profiles | Evidence & Upstream Reference |
|---|---|---|---|---|---|
| **Xray JSON (`v2ray-json`)** | `v24.11.30+` / `v25.x` | `v25.x` | `xray run -test -c <config.json>` | All 4 MVP transports: VLESS-REALITY-Vision, VLESS-XHTTP, VLESS-WS, Trojan-gRPC | `XTLS/Xray-core` releases; exit code 0 indicates 100% schema and outbound validity (XHTTP transport requires v24.11.30+) |
| **Mihomo YAML (`mihomo`)** | `v1.19.22` | `v1.20.0` | `mihomo -t -f <config.yaml>` | All client-compatible MVP transports: VLESS-REALITY, VLESS-WS, Trojan-gRPC, VLESS-XHTTP | `MetaCubeX/mihomo` releases; v1.19.22+ required for native XHTTP transport (`network: xhttp`) |

---

## 6. Local Podman Multi-Distribution Testbed Matrix

Before deploying to physical or virtual cloud servers, the automated test harness (`tests/podman_testbed.sh`) executes containerized pre-flight tests across all 4 supported operating systems using Podman's native systemd integration (`--systemd=always --privileged`).

> [!NOTE]
> Because official Docker Hub base images (`ubuntu:24.04`, `debian:12`, etc.) strip systemd and `/sbin/init` to minimize footprint, `tests/podman_testbed.sh` compiles local testbed images (`gowave-testbed-${DISTRO}:latest`) using `tests/Containerfile.testbed` to install `systemd`, `systemd-sysv`, `dbus`, `python3-systemd`, `openssh-server`, `openssh-client`, and core utilities before container execution.

| Operating System | Distribution Codename | Official Base Image | Testbed Container Target | Container Init System | NGINX Version | Testbed Validation Status | Verified Adaptations in Testbed |
|---|---|---|---|---|---|---|---|
| **Ubuntu 24.04 LTS** | Noble Numbat | `docker.io/library/ubuntu:24.04` | `gowave-testbed-ubuntu24:latest` | `systemd` 255.4 (PID 1) | 1.24.0 (`< 1.25.1`) | `PODMAN_TESTBED_PLANNED` | Legacy HTTP/2 syntax (`listen ... ssl http2;`), UFW bridge rules, native Panel/Node systemd units |
| **Ubuntu 26.04 LTS** | Resolute Raccoon | `docker.io/library/ubuntu:26.04` | `gowave-testbed-ubuntu26:latest` | `systemd` 256+ (PID 1) | 1.26+ (`>= 1.25.1`) | `PODMAN_TESTBED_PLANNED` | Modern HTTP/2 syntax (`http2 on;`), Stream multiplexing, UFW isolation |
| **Debian 12** | Bookworm | `docker.io/library/debian:12` | `gowave-testbed-debian12:latest` | `systemd` 252.30 (PID 1) | 1.22.1 (`< 1.25.1`) | `PODMAN_TESTBED_PLANNED` | Legacy HTTP/2 syntax (`listen ... ssl http2;`), auto-installation of `systemd-resolved`, Debian security origins |
| **Debian 13** | Trixie | `docker.io/library/debian:13` | `gowave-testbed-debian13:latest` | `systemd` 256+ (PID 1) | 1.26.3 (`>= 1.25.1`) | `PODMAN_TESTBED_PLANNED` | Modern HTTP/2 syntax (`http2 on;`), systemd-resolved integration, Stream multiplexing |

### Multi-Node Distributed Edge Testbed Matrix

In addition to All-in-One single-container tests, the testbed executes an automated Distributed Edge test (`./tests/podman_testbed.sh multi-node`) across an isolated Podman bridge network (`gowave-net`) with an untrusted client peer to verify firewall isolation:

| Node Role | Target Container Image | Assigned IP / Port | Verified Services & Components | Verification Scope in Testbed |
|---|---|---|---|---|
| **Control Plane (Panel)** | `docker.io/library/ubuntu:24.04` (or Debian 12) | `10.89.0.10` / `:3000`, `:7443` | GoWave Panel, SQLite, NGINX reverse proxy, Certbot | REST API onboarding, mTLS CA issuance, Worker node registration (`POST /api/nodes`), user sync |
| **Worker Node (Edge)** | `docker.io/library/debian:12` (or Ubuntu 24.04) | `10.89.0.20` / `:3002` (mTLS), `:443`, `:8443` | `gowave-node`, Xray core, NGINX Stream, UFW | SSH stdin deployment via `gowave-node-auto.sh`, UFW whitelist (`10.89.0.10` only), mTLS 1.3 handshake (`rw-v1`), direct client VPN data plane |
| **Untrusted Client Peer** | `docker.io/library/debian:12` | `10.89.0.30` | Client utilities, curl, nmap/nc | Verifies firewall drops connections to `10.89.0.20:3002` from unauthorized IPs outside allowlist |


