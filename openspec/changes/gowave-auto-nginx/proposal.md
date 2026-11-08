# Proposal: GoWave Auto NGINX

## Why

GoWave is a modern high-performance VPN panel and node ecosystem (Go + React + Xray), offering native user accounting, subscription rendering, and node orchestration. In stock deployments, GoWave includes basic NGINX or Caddy reverse proxy setups, but intentionally leaves advanced edge routing, multi-domain SNI multiplexing, REALITY camouflage fallbacks, host security (Fail2ban, strict DoT, UFW whitelisting), and disaster recovery (Backup/Restore) to external infrastructure automation.

Meanwhile, the `community-baseline` project has established battle-tested infrastructure patterns: NGINX Stream SNI multiplexing on port 443, loopback REALITY fallbacks, transactional security hardening, and resilient backup mechanisms with rollback protection.

There is a clear engineering requirement for a dedicated, independent deployment and lifecycle manager that brings these infrastructure patterns to GoWave. This system must provide single-command All-in-One deployment (Panel + local Node) as its primary MVP target, deliver deterministic, client-ready Xray and Mihomo subscription links, and support Distributed Edge worker nodes across Ubuntu 24.04/26.04 and Debian 12/13, providing zero-touch security hardening, safe GoWave updates and channel switching with database rollback protection, and multi-suite automated CI verification without modifying GoWave source code.

## What Changes

- **Autonomous Installer & Lifecycle Manager**: Create `gowave-auto.sh` providing initial setup, health inspection, diagnostics, domain switching, component uninstallation, channel switching (`stable` vs `dev`), and transaction-safe GoWave updates.
- **Port Conflict Elimination in All-in-One Setup**: Bind GoWave Panel to `127.0.0.1:3000` (`APP_PORT=3000`), GoWave Metrics to `127.0.0.1:3001` (`METRICS_PORT=3001`), and local GoWave Node to `NODE_PORT=3002`, using UFW firewall rules to deny external network access to the Node's wildcard listener and permit only local loopback traffic (`127.0.0.1`, `::1`).
- **Deterministic Per-User Xray and Mihomo Subscriptions**: Deliver two client-ready, deterministic URLs for every user (`GET /api/sub/{shortUuid}/v2ray-json` returning Xray JSON and `GET /api/sub/{shortUuid}/mihomo` returning Mihomo YAML), ensuring GoWave Response Rules, managed Internal Squads, and subscription templates (`DefaultTemplateXrayJson` and `DefaultTemplateMihomo`) are fully configured and verified, with direct links output in the installer summary and accessible via CLI helper commands without forking the upstream Web UI.
- **Automated Host Record Provisioning**: Automatically create and verify GoWave Host entities (`POST /api/hosts`) for each MVP profile, linking public domain/IP, port 443, SNI, path, `"nodes": ["<node-uuid>"]`, `"internalSquads"` policy, and verified security layers (`DEFAULT` for REALITY, `TLS` for NGINX-terminated inbounds) to inbounds and nodes so that client connections are fully resolved.
- **External Reverse Proxy Mode & Native Service Integration**: Set `GOWAVE_PROXY=external` in `/opt/gowave/.env` establishing that NGINX is owned and managed by GoWave Auto NGINX, and manage the Panel service cleanly via `gowave-server service install` without duplicate systemd drop-ins.
- **Upstream GoWave Node Installer Orchestration**: Leverage upstream `gowave-node/install.sh` as the primary installation mechanism for worker nodes, passing `SECRET_KEY`, `NODE_PORT`, and version parameters securely via environment variables and stdin without redundant binary downloads.
- **Dedicated Remote Node Automation & Hardening**: Create `gowave-node-auto.sh` for deploying and hardening remote GoWave worker nodes in a Distributed Edge topology, featuring UFW whitelisting of the Control Plane IP for `NODE_PORT` (recommended 3002 for All-in-One and default for distributed workers to prevent host-level collisions; 3000 supported only for isolated worker containers) across IPv4 and IPv6, kernel BBR sysctl tuning, and systemd sandboxing.
- **NGINX Stream SNI Routing & Multiplexing**: Route public TCP :443 via `ssl_preread` separating the Panel domain (`www` upstream `127.0.0.1:7443`) from the REALITY domain (`xray` upstream `127.0.0.1:8443`) with automatic fallback to static camouflage website (`127.0.0.1:9443`).
- **Native Protocol Profiles Support**: Provide verified configuration templates and client simulation tests for 4 native MVP protocol profiles: VLESS-REALITY-Vision, VLESS-XHTTP-TLS, VLESS-WS-TLS, and Trojan-gRPC-TLS.
- **Automated API Profile Provisioning**: Implement automated onboarding via GoWave's native REST API (`POST /api/auth/register`, `POST /api/config-profiles` with a single unified profile containing all 4 inbounds, `POST /api/internal-squads`, and `POST /api/nodes` or `PATCH /api/nodes/{uuid}` with `activeConfigProfileUuid` and `activeInbounds`) without direct manual editing of Xray runtime files.
- **Safe Channel Switching with Rollback**: Provide `gowave-auto.sh channel [stable|dev]` with automated pre-switch SQLite Online Backup snapshotting, irreversible migration downgrade warning with `--force` confirmation, asset update with SHA256 checksums, and automatic rollback on failure.
- **Transaction-Safe GoWave Updates**: Implement pre-update SQLite WAL checkpoints, persistent recovery snapshots in `/var/lib/gowave-auto-nginx/recovery/`, durable transaction journaling, and post-restart health probes with automatic rollback upon migration failures.
- **VPS Security Hardening**: Port transactional security drop-ins from `community-baseline`: Fail2ban for detected SSH ports and sockets, strict DNS-over-TLS via `systemd-resolved` (with Debian 12 compatibility), UFW firewall management, optional swap, and automated security updates with `Automatic-Reboot "false"` by default.
- **Hardened Backup & Restore (Format v1)**: Implement `GoWave Auto NGINX Backup Format v1` packaging GoWave SQLite database, `.env`, Node credentials, and NGINX configurations into an unencrypted gzip archive (`meta.json` + `files/`) with root-only file permissions (`0600`), SQLite Online Backup API consistency, strict Python preflight path-traversal prevention, and persistent recovery snapshots.
- **Debian 12 Compatibility Layer**: Provide explicit adaptations for Debian 12 (NGINX 1.22 `listen ... http2;` syntax, `systemd-resolved` auto-installation, and Debian-specific APT origins).
- **5-Suite Automated Testing & CI/CD**: Implement a 5-suite test architecture (`nonroot`, `root`, `integration`, `services`, `systemd` in QEMU TCG guest) with strict EUID privilege separation and automated CI workflows.
- **Local Multi-Distribution Podman Pre-Flight Gate**: Provide `tests/podman_testbed.sh` automating local containerized execution with PID 1 systemd across all 4 supported operating systems (Ubuntu 24.04, Ubuntu 26.04, Debian 12, and Debian 13) in both All-in-One and Multi-Node Distributed Edge topologies (`multi-node`), establishing an authoritative pre-flight gate that must pass before deploying changes to physical or cloud VPS environments.

## Capabilities

### New Capabilities
- `panel-node-integration`: Deployment and lifecycle automation for GoWave Panel (Control Plane) and GoWave Node (Worker) in All-in-One and Distributed Edge topologies, utilizing native base64 `SECRET_KEY`, derived HKDF SNI, mTLS 1.3 / RS256 JWT authentication, and conflict-free port assignment (`3000` / `3002` with UFW isolation).
- `traffic-routing`: NGINX Stream SNI routing on port 443 with REALITY loopback fallback, TLS termination on 7443, proxying of `/api/sub/`, and inbound transport handling (XHTTP, WebSocket, gRPC).
- `protocol-profiles`: Standardized definitions, routing parameters, Host record provisioning, and deterministic per-user Xray JSON and Mihomo YAML subscription delivery for the 4 native VPN transport profiles supported in the MVP release.
- `vps-security`: Operating system hardening across Ubuntu 24.04/26.04 and Debian 12/13, including non-destructive SSH protection (services and sockets), Fail2ban, strict DoT, UFW with Panel IP restriction and Node wildcard isolation, Swap, unattended-upgrades without auto-reboot, and BBR sysctl tuning.
- `backup-recovery`: Backup & Restore Format v1 mechanism with `meta.json` manifest, SQLite Online Backup API consistency checkpoints, persistent pre-restore recovery snapshots, durable crash recovery journals, and path-traversal defenses.
- `lifecycle-management`: Interactive CLI manager for installation, domain changes, health diagnostics, channel switching (`stable` vs `dev`), and transaction-safe GoWave updates with automatic rollback.

### Modified Capabilities
*(None - this is a new project)*

## Impact

- **Target Platforms**: Ubuntu 24.04 LTS, Ubuntu 26.04 LTS, Debian 12 (with compatibility adaptations), Debian 13.
- **CPU Architectures**: amd64 as primary verified MVP target; arm64 supported as source-compatible (E2E verification deferred).
- **Installed Components**: GoWave Panel, GoWave Node, Xray-core (`rw-core`), NGINX (with `ngx_stream_module`), Certbot, systemd-resolved, Fail2ban, UFW.
- **Deferred / Non-Goals**: Direct VLESS-TLS-Vision (without REALITY), Hysteria 2, AmneziaWG 3.1, CDN integration, PostgreSQL mode, automated cross-panel migration runner, and GPG/age backup encryption are explicitly deferred to post-MVP releases.
- **Licensing**: Released under GNU GPL-3.0, interacting with upstream components (GoWave and GoWave Node, licensed under AGPL-3.0) exclusively as independent processes over documented REST and system network APIs. Original third-party copyright notices and upstream licenses from `community-baseline`, `mozaroc`, `MHSanaei`, and `LibreSpeed` are preserved in `THIRD_PARTY_NOTICES.md`.
