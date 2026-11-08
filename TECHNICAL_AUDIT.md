# Technical Audit & Architectural Blueprints

## Pinned Upstream Repositories & Commit SHAs

The implementation of `gowave-auto-nginx` is anchored to verified upstream and community baseline repository states. All specifications, integration contracts, and test scenarios are directly validated against the following commit SHAs:

| Project | Role | Pinned Commit SHA | Full Commit SHA | Pinned Repository / Tree |
|---|---|---|---|---|
| **GoWave** | Panel Backend, Frontend & Database | `6d2c357` | `6d2c35788b3b038627b5e86e6c6486caff0851c8` | `sources/gowave` (`aaaSaZaN/gowave`) |
| **GoWave Node** | Node Daemon & Xray Process Manager | `7b3514d` | `7b3514d1ab8c674050597820d52d55525d4bece7` | `sources/gowave-node` (`aaaSaZaN/gowave-node`) |
| **community-baseline** | community baseline & Security Hardening | `community-baseline` | `community-baseline` | `sources/community-baseline` (`community-baseline/community-baseline`) |

---

## Direct Blueprint Links to `design.md`

To prevent specification duplication, all implementation tasks are mapped directly to authoritative architectural blueprints in [`design.md`](file:///home/dmitry/IdeaProjects/govawe-auto-nginx/openspec/changes/gowave-auto-nginx/design.md):

### 1. Stages 1–5: Network, TLS & Deployment Pipeline

- **Stage 1: Webroot Port 80 ACME Bootstrap Vhost**
  - *Location*: [`design.md` Section: 3-Stage Dual-Lineage Let's Encrypt TLS Bootstrapping](file:///home/dmitry/IdeaProjects/govawe-auto-nginx/openspec/changes/gowave-auto-nginx/design.md#L257-L284)
  - *Tasks*: 7.3, 7.5
  - *Contract*: Temporary `/var/www/gowave-acme` webroot with dynamic IPv6 detection, `certbot certonly --webroot`, and unconditional `authenticator = webroot` storage in `/etc/letsencrypt/renewal/<domain>.conf`.

- **Stage 2: Production NGINX Configuration & Port 80 Redirects**
  - *Location*: [`design.md` Section: Production Configuration & Non-Conflicting Port 80 Redirects](file:///home/dmitry/IdeaProjects/govawe-auto-nginx/openspec/changes/gowave-auto-nginx/design.md#L285-L290)
  - *Tasks*: 7.2, 7.3
  - *Contract*: Port 443 Stream multiplexing with conditional IPv6 `listen [::]:443`, HTTP 80 selective 301 redirect preserving ACME challenges, and reverse proxying on 7443.

- **Stage 3: Validation, Reload & Renewal Dry-Run**
  - *Location*: [`design.md` Section: Validation, Reload & Renewal Dry-Run](file:///home/dmitry/IdeaProjects/govawe-auto-nginx/openspec/changes/gowave-auto-nginx/design.md#L290-L294)
  - *Tasks*: 7.3, 7.5
  - *Contract*: Verification with `nginx -t -q`, deployment reload hook in `/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh`, and `certbot renew --dry-run`.

- **Stage 4: REALITY Loopback Fallback Vhost on 9443**
  - *Location*: [`design.md` Section: NGINX REALITY fallback vhost on 127.0.0.1:9443](file:///home/dmitry/IdeaProjects/govawe-auto-nginx/openspec/changes/gowave-auto-nginx/design.md#L289-L310)
  - *Tasks*: 7.4
  - *Contract*: PROXY v1 termination on loopback 9443, TLS 1.3 authentic certificate presentation, runtime HTTP/2 detection, static `cover-reality` site, and logging to `/var/log/nginx/gowave-decoy-access.log`.

- **Stage 5: Service Lifecycle & Dual Recovery System**
  - *Location*: [`design.md` Section: Reboot & Power Loss Recovery Architecture](file:///home/dmitry/IdeaProjects/govawe-auto-nginx/openspec/changes/gowave-auto-nginx/design.md#L710-L750)
  - *Tasks*: 4.4, 9.7
  - *Contract*: Pre-boot file recovery via `gowave-recover.service` (`Before=gowave.service`) and post-boot API recovery via `gowave-recover-provision.service` (`After=gowave.service`).

---

### 2. Sections 2–4: Protocols, API Provisioning & Lifecycle Management

- **Section 2: Traffic Routing & Native Protocol Profiles**
  - *Location*: [`design.md` Section: Decision 1: Traffic Routing & Native Protocol Profiles](file:///home/dmitry/IdeaProjects/govawe-auto-nginx/openspec/changes/gowave-auto-nginx/design.md#L145-L318)
  - *Tasks*: 7.1–7.4, 8.2, 8.6, 8.8, 8.9
  - *Contract*: 4 native MVP protocol profiles (VLESS-REALITY-Vision, VLESS-XHTTP-TLS, VLESS-WS-TLS, Trojan-gRPC-TLS), strict PROXY protocol boundary (443 -> 8443 -> 9443), client IP headers on 7443 -> 10001/10002, deterministic per-user Xray JSON and Mihomo YAML subscriptions with mandatory User-Agent requirement.

- **Section 3: Upstream Installers, Hardening & Service Management**
  - *Location*: [`design.md` Section: Decision 3: Upstream Installers, Hardening & Service Management](file:///home/dmitry/IdeaProjects/govawe-auto-nginx/openspec/changes/gowave-auto-nginx/design.md#L495-L644)
  - *Tasks*: 4.2–4.5, 5.1–5.5, 6.1–6.9
  - *Contract*: Native Panel service installation (`GOWAVE_PROXY=external`), base systemd unit `/etc/systemd/system/gowave.service`, upstream Node installer orchestration with `NODE_PORT=3002`, UFW loopback isolation, and remote worker SSH stdin streaming pipeline (`remote_payload`).

- **Section 4: Safe Channel Switching & Transaction-Safe Updates**
  - *Location*: [`design.md` Section: Decision 4 & Decision 5](file:///home/dmitry/IdeaProjects/govawe-auto-nginx/openspec/changes/gowave-auto-nginx/design.md#L646-L785)
  - *Tasks*: 9.1–9.9
  - *Contract*: Preflight SQLite checks and WAL checkpoints, staged SQLite Online Backup under `gowave` user (`install -o gowave -g gowave -m 0640 /dev/null ...`), durable transaction journaling in `journal.json`, and automatic rollback on healthcheck failure.
