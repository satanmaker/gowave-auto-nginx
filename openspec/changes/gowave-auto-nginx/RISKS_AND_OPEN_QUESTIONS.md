# Risks & Open Decisions Register: GoWave Auto NGINX

**Document Status**: Authoritative Scope & Risk Baseline  
**Date**: November 7, 2026  
**Change Target**: `openspec/changes/gowave-auto-nginx/`

---

## 1. Resolved Decisions from Audits & Remediation

| Decision ID | Issue Title | Resolution Summary | Reference Artifact |
|---|---|---|---|
| **RES-01** | Panel & Node Port Collision | **RESOLVED**: In All-in-One topology, Panel binds to `127.0.0.1:3000`, local Node binds to `127.0.0.1:3002` (`NODE_PORT=3002`), metrics use `3001`. Preflight checks verify all ports and abort before mutating system. | `design.md`, `COMPATIBILITY_MATRIX.md` |
| **RES-02** | Multi-Node Network Architecture | **RESOLVED**: Primary MVP is All-in-One (Topology A). Multi-Node is defined as Distributed Edge (Topology B): each worker has its own public IP and Stream/Xray; subscriptions point directly to worker nodes. Central Edge proxying is rejected. | `design.md`, `specs/traffic-routing/spec.md` |
| **RES-03** | Inbound Configuration Mechanism | **RESOLVED**: Inbounds are managed strictly through GoWave's native API: bootstrap admin, call `POST /api/config-profiles`, link profile to Node, verify computed config. Zero direct editing of Xray files. | `specs/protocol-profiles/spec.md`, `design.md` |
| **RES-04** | Vision Terminology & Inbound Scope | **RESOLVED**: MVP covers VLESS + REALITY + Vision (`xtls-rprx-vision`). Direct VLESS + TLS + Vision without REALITY requires cross-boundary Let's Encrypt certificate renewal into Xray and is deferred to post-MVP. | `specs/protocol-profiles/spec.md`, `proposal.md` |
| **RES-05** | Test Runner Contract | **RESOLVED**: Synchronized with upstream `tests/run_ci.py`: uses `--suite <name>` and `--check-completeness`. EUID privileges enforced: nonroot/integration/services require `EUID != 0`; root/systemd require `EUID == 0`. | `TESTING_STRATEGY.md` |
| **RES-06** | SQLite Backup Consistency | **RESOLVED**: Replaced file copy with SQLite Online Backup API (`sqlite3 <db> ".backup <dest>"`), providing transactional consistency even under concurrent client write operations. | `specs/backup-recovery/spec.md`, `design.md` |
| **RES-07** | Backup Identity & Encryption | **RESOLVED**: Format designated as `GoWave Auto NGINX Backup Format v1`. Explicitly declared as UNENCRYPTED gzip archive protected by POSIX `0600` root-only permissions. | `specs/backup-recovery/spec.md`, `proposal.md` |
| **RES-08** | Crash Recovery Persistence | **RESOLVED**: Snapshot storage moved from `/run` (tmpfs) to `/var/lib/gowave-auto-nginx/recovery/` with atomic `journal.json` tracking states (`PREPARED` -> `COMMITTED`), surviving reboots. | `specs/lifecycle-management/spec.md`, `design.md` |
| **RES-09** | Xray Core Supervision | **RESOLVED**: Relies exclusively on GoWave Node's native `ProcessManager` to supervise Xray. Independent systemd watchdog timer eliminated to prevent race conditions during config apply. | `specs/panel-node-integration/spec.md`, `design.md` |
| **RES-10** | Deterministic Subscription Links | **RESOLVED**: Every user receives two explicit, deterministic URLs: `/api/sub/{shortUuid}/v2ray-json` (Xray JSON) and `/api/sub/{shortUuid}/mihomo` (Mihomo YAML), with validated templates, Response Rules, and UI output. | `specs/protocol-profiles/spec.md`, `design.md` |
| **RES-11** | Automatic Host Record Provisioning | **RESOLVED**: Automatically provision GoWave Host records via `POST /api/hosts` for each MVP protocol, mapping public domain, port 443, SNI, path, and security layers to inbounds and nodes. | `specs/protocol-profiles/spec.md`, `design.md` |
| **RES-12** | Node Wildcard Bind & Firewall Isolation | **RESOLVED**: Source code binds wildcard `:3002` (`addr := fmt.Sprintf(":%d")`). The security model enforces UFW firewall rules denying external inbound traffic on 3002 in All-in-One setups, permitting only loopback. | `specs/vps-security/spec.md`, `design.md` |
| **RES-13** | Upstream GoWave Node Installer | **RESOLVED**: Use official `gowave-node/install.sh` as the primary installation mechanism, orchestrating parameters and secrets via environment variables instead of manual binary downloads. | `specs/panel-node-integration/spec.md`, `design.md` |
| **RES-14** | Avoid Duplicate Service Hardening | **RESOLVED**: Panel service is managed via `gowave-server service install`, which automatically creates unprivileged `gowave:gowave` and `90-unprivileged.conf`. Manual duplicate drop-in is eliminated. | `specs/lifecycle-management/spec.md`, `design.md` |
| **RES-15** | External Proxy Mode Configuration | **RESOLVED**: Explicitly set `GOWAVE_PROXY=external` in `/opt/gowave/.env`, ensuring GoWave delegates reverse proxy management entirely to project-owned NGINX configurations. | `specs/lifecycle-management/spec.md`, `design.md` |
| **RES-16** | Safe Channel Switching Contract | **RESOLVED**: Implement `gowave-auto.sh channel [stable|dev]` with automated pre-switch SQLite snapshot, schema downgrade warning with `--force`, asset update, and auto-rollback on failure. | `specs/lifecycle-management/spec.md`, `design.md` |
| **RES-17** | Integration Suite Non-Root Container User | **RESOLVED**: Containerized integration suite runs under unprivileged UID/GID (`--user 1001:1001`), satisfying the upstream runner contract (`os.geteuid() != 0`) while root suite runs as root. | `TESTING_STRATEGY.md`, `tasks.md` |

---

## 2. Formal Scope Boundary: MVP Scope vs. Deferred Non-Goals

| Feature / Subsystem | Scope Status | Engineering Rationale | Future Roadmap / Prerequisites |
|---|---|---|---|
| **VLESS + REALITY + Vision** | **MVP Scope** | Natively supported in Xray-core and GoWave `subtpl`; standard Stream SNI routing; zero cert renewal overhead. | Core protocol profile. |
| **VLESS + XHTTP + TLS** | **MVP Scope** | Verified native support; reverse proxied through NGINX port 7443 with buffering disabled. | Core protocol profile. |
| **VLESS + WebSocket + TLS** | **MVP Scope** | Verified native support; NGINX terminates TLS on 7443 and passes HTTP Upgrade to Xray loopback port. | Core protocol profile. |
| **Trojan + gRPC + TLS** | **MVP Scope** | Supported natively in GoWave and NGINX `grpc_pass` behind port 7443. | Core protocol profile. |
| **Direct VLESS + TLS + Vision** | **Deferred (Post-MVP)** | Requires Xray to terminate TLS directly with Let's Encrypt certificates, necessitating automated cert reload hooks across process boundaries. | Post-MVP: add dedicated reload hook into Node API once upstream supports cert rotation without core restart. |
| **Hysteria 2 Protocol** | **Deferred (Post-MVP)** | Requires standalone external daemon or non-standard core; lacks native GoWave user traffic accounting. | Await native GoWave core support or design dedicated sidecar accounting daemon. |
| **AmneziaWG 3.1** | **Deferred (Post-MVP)** | Requires kernel module and separate wireguard daemon; GoWave has no native sync for AWG credentials. | Provide standalone manual deployment guide; integrate when GoWave adds native AWG support. |
| **CDN Integration (Cloudflare/Yandex)**| **Deferred (Post-MVP)** | Requires specialized user-owned DNS routing and CDN proxy header configurations. | Provide optional post-install snippet in documentation. |
| **PostgreSQL Database Mode** | **Deferred (Post-MVP)** | Requires Docker or external PostgreSQL management, increasing deployment complexity. SQLite is default and sufficient for 95%+ deployments. | Can be added in a future minor release with Docker compose lifecycle. |
| **Automated 3X-UI Migration Runner** | **Deferred (Post-MVP)** | Full migration automation across live databases carries data loss risks. GoWave already includes manual CLI rescue migration commands (`gowave rescue --import-3x-ui`). | Retain native GoWave CLI commands; do not write automated wrapper in MVP. |
| **GPG / Age Backup Encryption** | **Deferred (Post-MVP)** | Adding encryption requires key management and passphrase escrow, creating operator lockout risks if keys are lost. | Introduce as opt-in flag in Backup Format v2 once key management is standardized. |

---

## 3. Genuine Technical Risks & Mitigation Strategies

### Risk 1: Upstream GoWave Release Asset Naming Changes
- **Description**: If GoWave modifies asset names in future GitHub releases (e.g. changing `gowave-linux-amd64` to `gowave-server-linux-amd64`), automated downloads will fail.
- **Likelihood**: Low | **Impact**: High (Installer or update fails).
- **Mitigation**:
  1. Pin exact release versions in production installer manifests (`v1.2.4`).
  2. Implement asset name fallback matching in `install_release()` similar to `community-baseline/internal/updater/artifacts.go`.

### Risk 2: Let's Encrypt Rate Limits on Domain Reconfiguration
- **Description**: Rapid domain changes or test runs may hit Let's Encrypt duplicate certificate rate limits (5 certs per week for exact domain set).
- **Likelihood**: Low | **Impact**: High (Blocked TLS issuance, panel inaccessible).
- **Mitigation**:
  1. Strict DNS preflight: Verify A/AAAA records resolve to public IP before contacting Let's Encrypt.
  2. In CI and testing environments, always pass `--test-cert` (staging ACME server) or utilize local self-signed CA fixtures.
  3. Domain change command preserves previous certificates until the new certificate is successfully verified and active.

### Risk 3: SSH Port Lockout During UFW Firewall Activation
- **Description**: If the installer enables UFW without accurately identifying custom SSH ports (e.g. non-standard port or `ssh.socket`), the administrator may be permanently locked out.
- **Likelihood**: Low | **Impact**: Critical (Server lockout).
- **Mitigation**:
  1. Use non-destructive detection: inspect `sshd -T` AND `systemctl show ssh.socket -p Listen` to detect effective listening ports.
  2. Whitelist detected SSH ports BEFORE calling `ufw enable`.
  3. Pre-flight check: If SSH port cannot be determined with 100% confidence, halt installation and require manual port confirmation.

### Risk 4: In-Panel Update vs. CLI Installer Coordination
- **Description**: GoWave allows admins to trigger updates directly from the web interface via `gowave-update.path`. If an admin updates via UI, the CLI installer's pre-update database snapshot might be bypassed.
- **Likelihood**: Medium | **Impact**: Medium (Failed in-panel update has no automated snapshot rollback).
- **Mitigation**:
  1. Hook into `gowave-update.service`: Wrap the update execution so that `gowave-update.service` also performs the pre-update SQLite snapshot to `/var/lib/gowave-auto-nginx/recovery/` before invoking `gowave update apply`.
  2. Document both update workflows as supported and safe.
