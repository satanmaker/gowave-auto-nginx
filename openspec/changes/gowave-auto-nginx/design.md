# Design: GoWave Auto NGINX

## Context

See `proposal.md` for background and motivation. GoWave is an AGPL-3.0 licensed system consisting of a Go backend, React frontend, SQLite storage, and Go-based worker nodes (`gowave-node`). The infrastructure community baseline project, `community-baseline` (GPL-3.0), provides battle-tested implementations of NGINX Stream multiplexing, transactional security hardening, and Backup/Restore mechanisms.

This design specifies the modular implementation of a standalone installer and lifecycle manager for GoWave, detailing the network architecture, deterministic subscription delivery, host provisioning, update lifecycle, edge node hardening, backup system, and testing pipeline.

Refer to `TECHNICAL_AUDIT.md` for verified upstream commit SHAs and technical facts, `COMPATIBILITY_MATRIX.md` for OS-level support, `TESTING_STRATEGY.md` for test suite specifications, and `RISKS_AND_OPEN_QUESTIONS.md` for scope boundaries.

---

## Component Ownership Matrix

```
+-------------------+----------------------------+-----------------------------------+---------------------------------------------------+
| Subsystem         | Supervising Process        | Primary Configuration / State     | Ownership Policy                                  |
+===================+============================+===================================+===================================================+
| GoWave Panel      | systemd: gowave.service    | /opt/gowave/.env, gowave.db       | Managed via gowave-server service install;        |
|                   |                            | (GOWAVE_PROXY=external)           | unprivileged gowave user; sticky bit 1770;        |
|                   |                            |                                   | orchestrated initially & updated by gowave-auto.sh|
+-------------------+----------------------------+-----------------------------------+---------------------------------------------------+
| GoWave Node       | systemd: gowave-node.service| /opt/gowave-node/.env, /run/...  | Installed via upstream gowave-node/install.sh;    |
|                   |                            |                                   | runs as root; orchestrated by gowave-node-auto.sh |
+-------------------+----------------------------+-----------------------------------+---------------------------------------------------+
| Xray-Core         | Child process of           | /run/gowave-node/xray.json,       | Supervised strictly by gowave-node ProcessManager.|
|                   | gowave-node daemon         | /run/gowave-node/xray.sock        | **No independent watchdog or external timer.**    |
+-------------------+----------------------------+-----------------------------------+---------------------------------------------------+
| NGINX Stream (443)| systemd: nginx.service     | /etc/nginx/stream-enabled/        | Installer owns Stream SNI map and public listener.|
+-------------------+----------------------------+-----------------------------------+---------------------------------------------------+
| NGINX Web (80/7443| systemd: nginx.service     | /etc/nginx/conf.d/gowave-*.conf   | Installer owns reverse proxy rules & ACME webroot.|
| / 9443)           |                            |                                   | (GOWAVE_PROXY=external ensures GoWave doesn't alter)|
+-------------------+----------------------------+-----------------------------------+---------------------------------------------------+
| TLS Certificates  | systemd: certbot.timer     | /etc/letsencrypt/live/            | Managed by Certbot; renewal reloads NGINX.        |
+-------------------+----------------------------+-----------------------------------+---------------------------------------------------+
| Firewall (UFW)    | systemd: ufw.service       | /etc/ufw/user.rules               | Installer configures rules, isolates Node port    |
|                   |                            |                                   | 3002 to loopback, and whitelists Panel IP.        |
+-------------------+----------------------------+-----------------------------------+---------------------------------------------------+
| Host Security     | fail2ban, systemd-resolved | /etc/fail2ban/, /etc/systemd/     | Project drop-in files with marker comments.       |
+-------------------+----------------------------+-----------------------------------+---------------------------------------------------+
| Updates           | gowave-auto.sh &           | /var/lib/gowave-auto-nginx/       | Preflight SQLite backup, persistent snapshot,     |
|                   | gowave-update.path         | recovery/                         | health verification, and auto-rollback on failure.|
+-------------------+----------------------------+-----------------------------------+---------------------------------------------------+
```

---

## Network Topologies: All-in-One vs. Distributed Edge

### Topology A: All-in-One Deployment (Primary MVP Target)
In Topology A, all services run on a single host. To prevent port collision:
- GoWave Panel API: `127.0.0.1:3000` (`APP_PORT=3000`)
- GoWave Metrics: `127.0.0.1:3001` (`METRICS_PORT=3001`)
- Local GoWave Node: binds wildcard `:3002` (`NODE_PORT=3002`), but is strictly isolated from external networks via UFW firewall rules (`ufw deny 3002/tcp`), permitting only loopback connections (`127.0.0.1`, `::1`).
- NGINX Stream (Port 443) inspects SNI: forwards `panel_domain` to local NGINX HTTPS (`127.0.0.1:7443`), and `reality_domain` or scanners to local Xray (`127.0.0.1:8443`).

```mermaid
graph TD
    Client["Client / Web Browser / Scanner"] -->|TCP 443| Stream["NGINX Stream (:443)"]
    Stream -->|SNI panel_domain (PROXY v1)| HTTPS["NGINX HTTPS (:7443)"]
    Stream -->|SNI reality_domain / default (PROXY v1)| XrayReality["Xray REALITY (:8443)"]
    
    HTTPS -->|Path / or /api/*| Panel["GoWave Panel (:3000)"]
    HTTPS -->|Path /<xhttp>/| XrayXHTTP["Xray XHTTP (:10001)"]
    HTTPS -->|Path /<ws>/| XrayWS["Xray WS (:10002)"]
    HTTPS -->|Path /<grpc>/| XrayGRPC["Xray gRPC (:10003)"]
    
    XrayReality -->|Scanner Fallback (PROXY v1)| Decoy["NGINX Decoy (:9443)"]
    Panel -->|mTLS 1.3 / JWT (Loopback only)| Node["GoWave Node (:3002, Firewalled)"]
    Node -->|Supervises / gRPC| XrayCore["Xray Core Process"]
```

### Topology B: Distributed Edge Deployment (Multi-Node Architecture)
In Topology B, the Central Server acts as the Control Plane, while one or more remote Worker Servers act as VPN edge gateways:
1. **Central Server (Control Plane)**:
   - Hosts GoWave Panel (`127.0.0.1:3000`), NGINX reverse proxy (`panel_domain:443`), and SQLite database.
   - Publishes user subscriptions containing the public addresses/ports of Worker Nodes.
   - Connects to remote Worker Nodes over mTLS 1.3 on `NODE_PORT` (default 3002) using derived HKDF SNI (`rw-v1`).
2. **Worker Server (Edge Gateway & Complete Traffic Plane)**:
   - Has its own public IPv4/IPv6 address and dedicated worker FQDN (`worker_domain`).
   - Runs `gowave-node` (installed via upstream `install.sh`) and Xray core, orchestrated via `gowave-node-auto.sh`.
   - Runs **full NGINX edge traffic plane**:
     - NGINX Stream on public port 443 (`ssl_preread on; proxy_protocol on;`) demultiplexing incoming connections: `worker_domain` SNI to local NGINX HTTPS listener (`127.0.0.1:7443`), camouflage SNI to local Xray REALITY inbound (`127.0.0.1:8443`), and unrecognized/scanner probes to 8443 (which fall back to local decoy vhost on 9443).
     - NGINX HTTPS listener on `127.0.0.1:7443` terminating Let's Encrypt TLS for `worker_domain`, with reverse proxy locations for XHTTP (`127.0.0.1:10001` with `proxy_buffering off;`), WebSocket upgrade (`127.0.0.1:10002`), and Trojan gRPC (`127.0.0.1:10003` via `grpc_pass`).
     - Certbot automated ACME HTTP-01 challenge on port 80 with deployment reload hook for NGINX.
   - UFW firewall permits public ports 80 and 443, and strictly whitelists `PANEL_IP` for `NODE_PORT` (recommended 3002 for All-in-One and default for distributed workers to prevent host-level collisions; 3000 supported only for isolated worker containers) across both IPv4 and IPv6.
   - Clients connect **directly to the Worker Server** on port 443 for all 4 MVP VPN transports. Client VPN data does NOT pass through the Central Panel.
3. **Central Edge Proxying (Topology C) is Formally Rejected**:
   - Proxying all client VPN data through the central panel introduces a fatal latency bottleneck, doubles bandwidth costs, and creates a single point of failure.

```mermaid
sequenceDiagram
    autonumber
    actor Client as VPN Client
    participant Panel as GoWave Panel (Central Host)
    participant Worker as Worker Gateway (Remote VPS)
    participant NodeDaemon as GoWave Node (:3002)
    participant WorkerXray as Worker Xray (:8443)

    Note over Panel,Worker: 1. Control Plane Orchestration
    Panel->>NodeDaemon: Connect via mTLS 1.3 (Derived HKDF SNI rw-v1)
    Panel->>NodeDaemon: Link Profile & Push Inbounds -> Supervise Xray
    NodeDaemon->>WorkerXray: Supervise Xray & Apply Inbounds

    Note over Client,Panel: 2. Subscription Fetch
    Client->>Panel: GET https://panel_domain/api/sub/{id}/v2ray-json (or /mihomo)
    Panel-->>Client: Returns Config pointing to Worker Public IP:443

    Note over Client,Worker: 3. Direct Client VPN Tunnel
    Client->>Worker: Connect directly to Worker IP:443 (VLESS REALITY / XHTTP)
    Worker-->>Client: Established VPN Session (Zero load on Panel server)
```

---

## Conflict-Free Port & Protocol Matrix (All-in-One Topology)

| Port | Protocol / Transport | Network Scope | Listener Process | PROXY Protocol In / Out | Purpose |
|---|---|---|---|---|---|
| **443** | TCP (TLS / Stream) | Public (`0.0.0.0/0`, conditional `[::]` if IPv6 enabled) | NGINX Stream | In: None / Out: **PROXY v1** | Public edge port; inspects SNI via `ssl_preread` |
| **80** | TCP (HTTP) | Public (`0.0.0.0/0`, conditional `[::]` if IPv6 enabled) | NGINX HTTP | In: None / Out: None | ACME HTTP-01 challenge (`/var/www/gowave-acme`) & 301 redirect to HTTPS |
| **7443** | TCP (TLS + HTTP/1.1, H2) | Loopback (`127.0.0.1`) | NGINX HTTPS | In: **PROXY v1** / Out: None | Terminates Let's Encrypt TLS for `panel_domain`; proxies web UI and inbounds |
| **8443** | TCP (REALITY / TLS RAW) | Loopback (`127.0.0.1`) | Xray REALITY Inbound | In: **PROXY v1** / Out: **PROXY v1** (on fallback) | Terminated by Xray REALITY; valid clients tunnel VPN; scanners fallback to 9443 |
| **8444** | TCP (TLS / XTLS-Vision) | Loopback (`127.0.0.1`) | Xray Vision Inbound (Optional) | In: **PROXY v1** / Out: None | Optional VLESS+XTLS Vision inbound (when 3rd domain configured); fallback to 9444 |
| **9443** | TCP (TLS 1.3 + HTTP/2, HTTP/1.1) | Loopback (`127.0.0.1`) | NGINX Decoy Vhost | In: **PROXY v1** / Out: None | Terminates TLS 1.3/H2 for `reality_domain`; serves static camouflage website (`cover-reality`) |
| **9444** | TCP (Cleartext HTTP) | Loopback (`127.0.0.1`) | NGINX Vision Decoy Vhost (Optional) | In: **PROXY v1** / Out: None | Fallback vhost for non-VLESS HTTP probes on Vision domain; serves decoy website |
| **3000** | TCP (Cleartext HTTP) | Loopback (`127.0.0.1`) | GoWave Panel Backend | In: None / Out: None | Panel REST API and static frontend assets (`APP_PORT=3000`) |
| **3001** | TCP (Cleartext HTTP) | Loopback (`127.0.0.1`) | GoWave Panel Metrics | In: None / Out: None | Prometheus metrics endpoint (optional, loopback only) |
| **3002** | TCP (mTLS 1.3) | Wildcard (`:3002`) isolated via UFW (fail-closed) | GoWave Node (Local / Worker) | In: None / Out: None | Node control plane (`NODE_PORT=3002` recommended for both Local and Worker); UFW whitelists Panel IP / loopback; verified fail-closed |
| **10001**| TCP (Cleartext HTTP/1.1)| Loopback (`127.0.0.1`) | Xray XHTTP Inbound | In: None / Out: None | Internal backend inbound for VLESS-XHTTP |
| **10002**| TCP (Cleartext HTTP/WS) | Loopback (`127.0.0.1`) | Xray WS Inbound | In: None / Out: None | Internal backend inbound for VLESS-WS |
| **10003**| TCP (Cleartext gRPC) | Loopback (`127.0.0.1`) | Xray gRPC Inbound | In: None / Out: None | Internal backend inbound for Trojan-gRPC |

#### Preflight Port & NGINX Configuration Conflict Inspection
To guarantee collision-free deployment:
1. **Socket Inspection**: The preflight module verifies active TCP listeners on ports 80, 443, 3000, 3001, 3002, 7443, 8443, 8444, 9443, 9444, 10001, 10002, and 10003 via `ss -Hltnp "sport = :<port>"`. If occupied by non-project processes, installation halts with conflicting process name and PID before mutating any system state.
2. **NGINX Configuration Inspection**: Port 443 is exclusively dedicated to the top-level NGINX `stream` block. The preflight module scans `/etc/nginx/` (excluding project-managed files) for conflicting `listen ... 443` directives:
   ```bash
   grep -rqsE --exclude="gowave-*.conf" --exclude="gowave-stream.conf" '^[[:space:]]*listen[[:space:]]+([^;]*:)?443[^0-9]' /etc/nginx/
   ```
   If unmanaged web server blocks listening on 443 are found, the installer detects the conflict and informs the operator to relocate existing HTTP SSL sites before applying the Stream configuration.

---

## Architectural Decisions

### Decision 1: Traffic Routing & Native Protocol Profiles

#### 4 Native MVP Protocol Profiles
The system provides verified templates and testing for exactly 4 native protocol profiles:
1. **VLESS + REALITY + Vision**:
   - `protocol: "vless"`, `security: "reality"`, `flow: "xtls-rprx-vision"`.
   - Incoming on port 443 Stream -> forwarded with PROXY v1 to Xray at `127.0.0.1:8443`.
   - Handshake authenticated via REALITY keys. The installer generates cryptographic x25519 keypairs natively via GoWave Panel REST API `GET /api/system/tools/x25519/generate`, obtaining verified `privateKey` and `publicKey` without external binary dependencies.
   - Scanners forward with PROXY v1 (`dest: "127.0.0.1:9443", xver: 1`) to NGINX decoy vhost.
2. **VLESS + XHTTP + TLS**:
   - `protocol: "vless"`, `security: "none"`, `network: "xhttp"`.
   - Incoming on port 443 Stream (`panel_domain`) -> NGINX HTTPS listener at 7443 terminates TLS.
   - Inbound at `127.0.0.1:10001` does NOT accept PROXY protocol (`acceptProxyProtocol` MUST be omitted or `false`); client IP is passed via standard HTTP headers (`X-Forwarded-For`).
   - Location `^~ /xhttp-down/` reverse proxies to `http://127.0.0.1:10001` using `mode: packet-up` with complete streaming directives and body limits:
     ```nginx
     location ^~ /xhttp-down/ {
         proxy_pass http://127.0.0.1:10001;
         proxy_http_version 1.1;
         proxy_buffering off;
         proxy_request_buffering off;
         client_max_body_size 0;
         client_body_timeout 1h;
         proxy_read_timeout 1h;
         proxy_send_timeout 1h;
         proxy_set_header Host $host;
         proxy_set_header X-Real-IP $remote_addr;
         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
     }
     ```
   - Canonical Xray template: `assets/xray/vless-xhttp.json`.
3. **VLESS + WebSocket + TLS**:
   - `protocol: "vless"`, `security: "none"`, `network: "ws"`.
   - Incoming on port 443 Stream (`panel_domain`) -> NGINX HTTPS listener at 7443 terminates TLS.
   - Inbound at `127.0.0.1:10002` does NOT accept PROXY protocol (`acceptProxyProtocol` MUST be omitted or `false`).
   - Location `= /ws` proxies to `http://127.0.0.1:10002` preserving `Upgrade: websocket` headers with 1-hour timeouts preventing premature idle disconnections:
     ```nginx
     location = /ws {
         proxy_pass http://127.0.0.1:10002;
         proxy_http_version 1.1;
         proxy_set_header Upgrade $http_upgrade;
         proxy_set_header Connection "upgrade";
         proxy_read_timeout 1h;
         proxy_send_timeout 1h;
         proxy_set_header Host $host;
         proxy_set_header X-Real-IP $remote_addr;
         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
     }
     ```
   - Canonical Xray template: `assets/xray/vless-ws.json`.
4. **Trojan + gRPC + TLS**:
   - `protocol: "trojan"`, `security: "none"`, `network: "grpc"`.
   - Incoming on port 443 Stream (`panel_domain`) -> NGINX HTTPS listener at 7443 terminates TLS.
   - Inbound at `127.0.0.1:10003` does NOT accept PROXY protocol (`acceptProxyProtocol` MUST be omitted or `false`).
   - Location `/trojan-grpc` passes HTTP/2 frames via `grpc_pass grpc://127.0.0.1:10003;` with `grpc_read_timeout 1h; grpc_send_timeout 1h; client_body_timeout 1h;`.
   - Canonical Xray template: `assets/xray/trojan-grpc.json`.
5. **Optional VLESS + XTLS Vision**:
   - `protocol: "vless"`, `security: "tls"`, `flow: "xtls-rprx-vision"`.
   - Enabled only when the operator provides a dedicated 3rd domain/subdomain (`vision_domain`).
   - Incoming on port 443 Stream (`vision_domain`) -> NGINX Stream routes to `127.0.0.1:8444` with PROXY protocol v1.
   - Inbound at `127.0.0.1:8444` accepts PROXY protocol (`acceptProxyProtocol: true`), terminates Let's Encrypt TLS for `vision_domain`, and routes unauthenticated non-VLESS HTTP fallback probes to `127.0.0.1:9444`.
   - NGINX on `127.0.0.1:9444` serves the static decoy website (`cover-reality`).
   - Canonical Xray template: `assets/xray/vless-vision.json`.
6. **Panel API, Subscriptions & Web UI Reverse Proxying (Port 7443)**:
   - For all non-transport HTTP traffic destined to `panel_domain`, NGINX on 7443 terminates TLS and proxies to GoWave's internal loopback listener at `127.0.0.1:3000`:
     ```nginx
     # Subscriptions caching disabled, headers preserved, User-Agent preserved
     location ^~ /api/sub/ {
         proxy_pass http://127.0.0.1:3000;
         proxy_http_version 1.1;
         proxy_set_header Host $host;
         proxy_set_header X-Real-IP $remote_addr;
         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
         proxy_set_header X-Forwarded-Proto $scheme;
         proxy_set_header User-Agent $http_user_agent;
         add_header Cache-Control "no-store, no-cache, must-revalidate, max-age=0";
     }

     # Panel REST API and Deterministic Client Subscriptions
     location ^~ /api/ {
         proxy_pass http://127.0.0.1:3000;
         proxy_http_version 1.1;
         proxy_set_header Host $host;
         proxy_set_header X-Real-IP $remote_addr;
         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
         proxy_set_header X-Forwarded-Proto https;
     }

     # GoWave Single Page Application Frontend Web UI
     location / {
         proxy_pass http://127.0.0.1:3000;
         proxy_http_version 1.1;
         proxy_set_header Host $host;
         proxy_set_header X-Real-IP $remote_addr;
         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
         proxy_set_header X-Forwarded-Proto https;
     }
     ```
   - Transport paths (`^~ /xhttp-down/`, `= /ws`, `/trojan-grpc`) use high-priority prefix/exact matches and route directly to Xray loopback ports (10001-10003), while `/api/` (including `/api/sub/...`) and root `/` route to GoWave on 3000.
   - NGINX proxy module preserves and forwards custom subscription response headers (`Subscription-Userinfo`, `profile-update-interval`) transparently to clients without header suppression.

#### Explicit SNI Roles and Camouflage Architectures
To prevent conflation between camouflage sites, management panels, and public VPN connection endpoints, exactly 5 distinct domain and SNI roles and a verified camouflage architecture are established:
1. **Host Address (`address`)**: The public IPv4/IPv6 address or resolvable FQDN of the edge server (`vpn.example.com` or Worker IP). Clients send TCP SYN packets to this address on port 443.
2. **REALITY Camouflage SNI (`reality_camouflage_sni` / `serverNames`)**: Domain configured in Xray `realitySettings.serverNames` and sent by the client in the TLS ClientHello SNI extension during REALITY handshakes.
3. **NGINX `ssl_preread` SNI Router**: NGINX Stream on port 443 evaluates `$ssl_preread_server_name` using dynamic IPv6 environment detection:
   ```nginx
   listen 443 so_keepalive=on;
   # Included ONLY when IPv6 is confirmed active ([ -f /proc/net/if_inet6 ]):
   # listen [::]:443 so_keepalive=on;
   ```
   - Matches `reality_camouflage_sni` -> forwards via PROXY v1 to Xray REALITY inbound (`127.0.0.1:8443`).
   - Matches `vision_domain` (if configured) -> forwards via PROXY v1 to Xray Vision inbound (`127.0.0.1:8444`).
   - Matches `panel_domain` (or `worker_domain`) -> forwards via PROXY v1 to NGINX HTTPS listener (`127.0.0.1:7443`).
   - Missing SNI or unrecognized scanner probe -> forwards to `127.0.0.1:8443`, triggering REALITY fallback.
   - Loopback listeners (7443, 8443, 8444, 9443, 9444, 10001-10003) bind strictly to `127.0.0.1`, avoiding wildcard socket collisions and IPv6 socket failures.
4. **Camouflage Architecture (Scope Constraint)**:
   - **Mode A: Owned Camouflage Domain with Local Decoy (Exclusive MVP Scope)**: Operator configures an owned secondary domain (`reality_domain`, e.g. `cdn.example.com`). Certbot issues an authentic Let's Encrypt certificate for it. NGINX on loopback port 9443 terminates TLS presenting this authentic certificate and serves `cover-reality`. Xray REALITY uses `serverNames: ["cdn.example.com"]` and `dest: "127.0.0.1:9443", xver: 1`. Active probes receive valid certificates matching the SNI.
   - **Mode B: Third-Party SNI Stealing (Deferred Post-MVP Non-Goal)**: Third-party SNI proxying (`dest: external:443`, `xver: 0`) requires dynamic upstream SNI matching, external network reachability without loopback proxy protocol, and external certificate dependency. To ensure deterministic local validation and eliminate external blocking risks, Mode B is formally deferred to post-MVP Non-Goals.
5. **Decoy Web Site (`cover-reality`)**: An authentic multi-asset website (retained from `community-baseline` `cover-reality` under `/var/www/gowave-auto-nginx/cover-reality` including complete HTML, stylesheets, scripts, and media assets) served on loopback port `9443` by NGINX. Minimal single-file HTML stubs are explicitly rejected to provide realistic camouflage against active probing and DPI scanners. During `generate_decoy_vhost`, static assets from `assets/cover-sites/cover-reality/` are automatically deployed to `/var/www/gowave-auto-nginx/cover-reality` with permissions `0755`, preventing 403 Forbidden responses caused by empty webroot directories.

#### 3-Stage Dual-Lineage Let's Encrypt TLS Bootstrapping
To resolve the classic chicken-and-egg bootstrap deadlock while guaranteeing permanent, non-deadlocking automated renewals via `certbot.timer`:
1. **Stage 1 (Webroot Port 80 Bootstrap Vhost)**: The installer creates `/var/www/gowave-acme` (`chmod 755`), unlinks default distribution vhosts (`/etc/nginx/sites-enabled/default`), and writes temporary bootstrap vhost `/etc/nginx/conf.d/00-bootstrap-acme.conf` listening on HTTP port 80 (with dynamic IPv6 detection: `listen [::]:80;` is included ONLY when IPv6 is active on the host, omitting it if IPv6 is disabled in the kernel to prevent fatal `Address family not supported` socket errors):
   ```nginx
   server {
       listen 80;
       # Included conditionally only if IPv6 is supported ([ -f /proc/net/if_inet6 ])
       # listen [::]:80;
       server_name _;
       location /.well-known/acme-challenge/ {
           root /var/www/gowave-acme;
       }
       location / {
           return 444; # Drop scanner probes during initial issuance
       }
   }
   ```
   The installer verifies syntax via `nginx -t`, starts or reloads NGINX, and executes webroot acquisition for both domain lineages (`PANEL_DOMAIN` and `REALITY_DOMAIN`):
   ```bash
   certbot certonly --webroot -w /var/www/gowave-acme \
     -d "$PANEL_DOMAIN" --cert-name "$PANEL_DOMAIN" \
     --non-interactive --agree-tos -m "$ADMIN_EMAIL" --keep-until-expiring

   certbot certonly --webroot -w /var/www/gowave-acme \
     -d "$REALITY_DOMAIN" --cert-name "$REALITY_DOMAIN" \
     --non-interactive --agree-tos -m "$ADMIN_EMAIL" --keep-until-expiring
   ```
   Both certificate lineages (`/etc/letsencrypt/live/$PANEL_DOMAIN/` and `/etc/letsencrypt/live/$REALITY_DOMAIN/`) are validated with `verify_acme_certificate` ensuring `fullchain.pem` and `privkey.pem` exist, match cryptographically, and have >24h validity. Self-signed fallback generation is strictly prohibited in the production path: any ACME issuance failure results in an immediate fail-fast termination before production vhosts are deployed. Crucially, this ensures Certbot unconditionally stores `authenticator = webroot` in `/etc/letsencrypt/renewal/<domain>.conf`, preventing the renewal deadlocks inherent in standalone mode.
2. **Stage 2 (Production Configuration & Non-Conflicting Port 80 Redirects)**: Once both certificates exist on disk, the installer deploys production configurations:
   - NGINX Stream 443 with `proxy_timeout 1h; proxy_connect_timeout 5s; listen 443 so_keepalive=on;` (with conditional `listen [::]:443 so_keepalive=on;` included ONLY when `/proc/net/if_inet6` is present and active, omitting `[::]` if IPv6 is disabled in the kernel to prevent fatal `Address family not supported` socket errors) demultiplexing to `127.0.0.1:7443` and `127.0.0.1:8443`. Global NGINX tuning sets `worker_rlimit_nofile 65535; worker_connections 8192;`.
   - NGINX HTTP port 80 with selective redirect: preserves `location /.well-known/acme-challenge/ { root /var/www/gowave-acme; }`, redirects known domains to HTTPS (`return 301 https://$host$request_uri;`), and returns 444 for unmanaged hostnames/IP scanners.
   - NGINX HTTPS listener at `127.0.0.1:7443` with `ssl_certificate /etc/letsencrypt/live/$PANEL_DOMAIN/fullchain.pem`.
   - NGINX Decoy listener at `127.0.0.1:9443` with `ssl_protocols TLSv1.3;`, runtime version-detected HTTP/2 syntax (`listen 127.0.0.1:9443 ssl http2 proxy_protocol;` on NGINX < 1.25.1; `listen 127.0.0.1:9443 ssl proxy_protocol; http2 on;` on NGINX >= 1.25.1), `ssl_certificate /etc/letsencrypt/live/$REALITY_DOMAIN/fullchain.pem`, and a dedicated security audit log `access_log /var/log/nginx/gowave-decoy-access.log;` recording PROXY-restored `$remote_addr`, `$ssl_server_name` / `$host`, and timestamp with daily logrotate rotation, without logging VPN payload content.
3. **Stage 3 (Validation, Reload & Renewal Dry-Run)**: The installer removes the temporary bootstrap config `00-bootstrap-acme.conf`, tests syntax via `nginx -t -q`, reloads NGINX (`systemctl reload nginx`), establishes automated renewal hooks in `/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh` (`nginx -t -q && systemctl reload nginx`), and immediately verifies renewal safety via:
   ```bash
   certbot renew --dry-run
   ```

#### Optional Direct VLESS + TLS + Vision Architecture
When an operator configures an optional 3rd domain (`vision_domain`), VLESS + XTLS Vision is provisioned on port 8444 with direct TLS termination in Xray:
- **Certificates**: Let's Encrypt certificates for `vision_domain` are acquired during ACME bootstrap and read by Xray (`/etc/letsencrypt/live/<vision_domain>/fullchain.pem` and `privkey.pem`).
- **Fallback**: Fallback for non-VLESS HTTP traffic on port 8444 is routed to loopback port 9444 (`gowave-vision-fallback`), where NGINX receives requests with PROXY protocol v1 and serves the decoy website (`cover-reality`).

#### Strict PROXY Protocol Boundaries (443 -> 8443/8444 -> 9443/9444)
- **Sender (NGINX Stream 443)**: NGINX Stream on port 443 sends PROXY protocol v1 (`proxy_protocol on;`) to `127.0.0.1:7443`, `127.0.0.1:8443`, and conditionally to `127.0.0.1:8444` (when optional Vision is enabled).
- **Receiver (Xray 8443 & 8444)**: Inbounds at `127.0.0.1:8443` and `127.0.0.1:8444` strictly specify `"tcpSettings": {"acceptProxyProtocol": true}`. When NGINX prepends the PROXY v1 header, Xray consumes it, restores the genuine client IP, and passes it to REALITY/TLS handshakes and fallback destinations.
- **Authoritative Fallback Sender (Xray -> NGINX 9443 & 9444)**: `realitySettings.dest: "127.0.0.1:9443"` with `xver: 1` (for REALITY) and `fallbacks` to `"127.0.0.1:9444"` with `xver: 1` (for Vision) guarantee that Xray preserves and forwards the genuine client IP via PROXY protocol v1 to loopback decoy ports when unauthorized scanners probe ports 8443 or 8444.
- **Receiver (NGINX Decoy 9443/9444 & HTTPS 7443)**: All loopback listeners configure `proxy_protocol` and restrict trust strictly to `127.0.0.1`:
  ```nginx
  listen 127.0.0.1:9443 ssl proxy_protocol;
  set_real_ip_from 127.0.0.1;
  real_ip_header proxy_protocol;
  ```
  This ensures real client IPs are preserved across the entire 443 -> 8443/8444 -> 9443/9444 chain, logged in access logs, rate-limited accurately, and made available to Fail2ban.
- Any external attempt to inject fake PROXY protocol headers from non-loopback addresses is discarded.

#### Client IP Preservation for HTTP & WebSocket Transports (7443 -> 10001/10002)
Because NGINX HTTPS listener on 7443 receives PROXY protocol v1 from Stream 443 and restores the authentic client IP into `$remote_addr` via `real_ip_header proxy_protocol;`, reverse proxy locations for XHTTP (`^~ /xhttp-down/`) and WebSocket (`= /ws`) explicitly pass this authentic IP to Xray's loopback HTTP inbounds:
```nginx
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```
Internal Xray inbounds (10001 XHTTP, 10002 WS, 10003 Trojan gRPC) strictly omit `acceptProxyProtocol`, avoiding framing and parsing crashes while guaranteeing that genuine client IPs are preserved across the entire edge chain for audit logging and Fail2ban integration.

---

### Decision 2: GoWave Subscriptions, Response Rules, Internal Squads & Host Provisioning

#### Unified Config Profile & Per-Node Profile Architecture
In upstream GoWave (`backend-go/internal/nodes/service.go`), `updateNodeWithProfile()` delegates to `createNodeInboundLinks()`, which enforces:
```go
if inbound.ProfileUUID != profileID {
    return fmt.Errorf("inbound %s does not belong to config profile %s", inbound.UUID, profileID)
}
```
A GoWave Node can have exactly ONE `activeConfigProfileUuid`, and **all active inbounds assigned to the node must belong to this single active profile**. Furthermore, Xray REALITY strictly validates that the client TLS ClientHello SNI matches an entry in `realitySettings.serverNames`. Because each distributed node (the Central Panel and remote edge workers) uses its own distinct camouflage domain (`reality_domain`), **each node receives its own dedicated Config Profile**:
1. **Central Panel Profile**: Named `"GoWave MVP Unified Profile - local-node"` via `POST /api/config-profiles`, with `realitySettings.serverNames: ["$LOCAL_REALITY_DOMAIN"]`, native x25519 keypair, and randomly generated 8-byte shortIds (`openssl rand -hex 8`).
2. **Worker Node Profiles**: Created during `gowave-auto.sh node add` as `"GoWave Worker <name> Profile"`, embedding the worker's unique `REALITY_DOMAIN` in `serverNames`, its own distinct x25519 keypair, and unique shortIds.
3. **Global Inbound Tag Uniqueness**:
   Upstream GoWave database schema enforces a global UNIQUE constraint across all profiles via index `idx_config_profile_inbounds_tag` on table `config_profile_inbounds(tag)`. Attempting to register multiple profiles with identical tags (e.g. static `vless-reality`) causes a fatal database collision. Therefore, all inbound tags are deterministically node-scoped:
   - Central Panel local node: `vless-reality-local-node`, `vless-xhttp-local-node`, `vless-ws-local-node`, `trojan-grpc-local-node`.
   - Worker nodes: `vless-reality-<node-name>`, `vless-xhttp-<node-name>`, `vless-ws-<node-name>`, `trojan-grpc-<node-name>`.
4. **Mandatory Outbound Routing Rules & Node API Precedence**:
   In `gowave-node/internal/xray/config.go:GenerateApiConfig()`, the node daemon prepends the node management API routing rule (`{"inboundTag": ["GOWAVE_NODE_API_INBOUND"], "outboundTag": "GOWAVE_NODE_API"}`) before user profile rules. Because Xray processes routing rules on a first-match-wins basis, internal node management over loopback is routed to the API handler before evaluating our outbound SSRF block rule (`127.0.0.0/8`), ensuring loopback node management is never impaired by the SSRF security policy.
   Every generated Config Profile raw Xray JSON contains an authoritative `"routing"` block:
   ```json
   "routing": {
     "domainStrategy": "IPIfNonMatch",
     "rules": [
       {
         "type": "field",
         "outboundTag": "BLOCK",
         "ip": [
           "127.0.0.0/8",
           "10.0.0.0/8",
           "172.16.0.0/12",
           "192.168.0.0/16",
           "169.254.0.0/16",
           "100.64.0.0/10",
           "::1/128",
           "fc00::/7",
           "fe80::/10"
         ]
       },
       {
         "type": "field",
         "outboundTag": "BLOCK",
         "protocol": ["bittorrent"]
       }
     ]
   }
   ```
   This strictly prevents VPN users from tunneling connections into local panel management listeners (`127.0.0.1:3000`, `3001`, `3002`), cloud provider instance metadata endpoints (`169.254.169.254`), or private cloud networks.
4. **Inbound Retrieval & Node Linking**: The installer retrieves the 4 generated inbounds via `GET /api/config-profiles/{uuid}/inbounds` and associates them to the node via `POST /api/nodes` or `PATCH /api/nodes/{uuid}`.
5. **Idempotency**: Existing profiles are reconciled by name and updated via `PATCH /api/config-profiles/{uuid}`.

#### Internal Squad and User Lifecycle Provisioning
In upstream GoWave (`backend-go/internal/nodes/service.go`), `GetUserResolvedInbounds(userID)` constructs user inbounds strictly via relational joins:
`internal_squad_members` -> `internal_squads` -> `internal_squad_inbounds` -> `config_profile_inbounds`.
Subsequently, `syncUserToSingleNode()` sends user credentials to the Node only for inbounds linked through the squads of which the user is an active member. If a user is not in an Internal Squad or the squad has no inbound links, the Node receives ZERO user credentials for those inbounds.

To provision a unified user experience:
1. **Managed Internal Squad Provisioning**: The installer creates a managed Internal Squad (`POST /api/internal-squads`) named `"Default MVP Squad"`. It links all 4 inbound UUIDs from the local node profile, and whenever a worker node is added, links the worker's 4 inbound UUIDs into this same squad via `PATCH /api/internal-squads` with `{"uuid": squad_uuid, "name": squad_name, "inbounds": all_inbounds}` (calling GoWave's `UpdateInternalSquadCommand`, avoiding 405 Method Not Allowed on path-based PATCH).
2. **Initial User Provisioning**: The installer provisions an initial active user via `POST /api/users` adhering to GoWave's strict schema (`username` and `expireAt` are mandatory):
   ```json
   {
     "username": "default-user",
     "status": "ACTIVE",
     "trafficLimitStrategy": "NO_RESET",
     "expireAt": "2099-01-01T00:00:00.000Z",
     "activeInternalSquads": ["<squad-uuid>"]
   }
   ```
3. **Automated Credential Dispatch**: GoWave automatically executes `syncUserToSingleNode()`, transmitting user credentials (UUID, Trojan password) for all linked inbounds across all nodes in the squad.
4. **Subscription Short UUID**: The created user response contains `shortUuid`, which forms the deterministic subscription links.

#### Deterministic Per-User Subscription Links & Response Rules Contract
GoWave supports route `GET /api/sub/{shortUuid}/{clientType}`. To eliminate dependency on ambiguous client sniffing, every user is provided two distinct, deterministic URLs:
1. **Xray Subscription URL**:
   - Route: `https://<public-domain>/api/sub/<shortUuid>/v2ray-json`
   - Maps to GoWave response type `XRAY_JSON`.
   - Header: `Content-Type: application/json`.
   - Contains all 4 MVP protocols in full Xray configuration JSON format.
2. **Mihomo Subscription URL**:
   - Route: `https://<public-domain>/api/sub/<shortUuid>/mihomo`
   - Maps to GoWave response type `MIHOMO`.
   - Header: `Content-Type: text/yaml` (or `text/yaml; charset=utf-8`).
   - Contains all client-compatible MVP protocols formatted as Mihomo/Clash-Meta proxies in YAML format.

#### Response Rules and User-Agent Enforcement (Option A)
- **Pinned Upstream Fact**: On pinned GoWave commit `6d2c35788b3b038627b5e86e6c6486caff0851c8`, `responseRules()` in `backend-go/internal/subscription/serve.go` executes for **both** `/api/sub/{shortUuid}` and `/api/sub/{shortUuid}/{clientType}`. If the `User-Agent` header is missing or empty, it returns `HTTP 403 Forbidden`:
  ```go
  if err != nil || settings.ResponseRules == nil || userAgent == nil || *userAgent == "" {
      nestError(w, r, http.StatusForbidden, "Forbidden")
      return nil
  }
  ```
- **Adopted Contract (Option A)**:
  - Clients requesting subscriptions must provide a non-empty, valid client User-Agent header (e.g. `v2rayN/6.23`, `Xray/1.8.4`, `ClashMeta/v1.18.0`, `Mihomo/1.18.0`).
  - In `subscription_settings`, `DisableSubscriptionAccessByPath` is verified as `false`.
  - The `subscription_templates` database table contains `DefaultTemplateMihomo` and `DefaultTemplateXrayJson`.
  - Tests verify that valid client User-Agents return HTTP 200, while missing or empty User-Agent returns HTTP 403 Forbidden (negative security test).

#### Automatic GoWave Host Record Provisioning & Canonical Remark Taxonomy
Client subscription links are generated from `Host` entities in GoWave. For each provisioned profile, the installer creates Host records via `POST /api/hosts` using canonical remark taxonomy `<PROTO>@<node-name>`:
```json
{
  "inbound": {
    "configProfileUuid": "<profile-uuid>",
    "configProfileInboundUuid": "<inbound-uuid>"
  },
  "nodes": ["<node-uuid>"],
  "remark": "VLESS-REALITY-Vision@local-node",
  "address": "vpn.example.com",
  "port": 443,
  "sni": "cdn.example.com",
  "path": null,
  "host": null,
  "alpn": "h2,http/1.1",
  "fingerprint": "firefox",
  "securityLayer": "DEFAULT",
  "internalSquads": {
    "mode": "ALLOW_ONLY",
    "squads": ["<squad-uuid>"]
  },
  "isDisabled": false
}
```

##### Upstream Host.securityLayer Resolution Contract
In `backend-go/internal/configprofiles/handler.go`, `formatHostResponse()` normalizes `securityLayer` to exactly 3 values: `DEFAULT`, `TLS`, `NONE`. Any other string (including `"REALITY"`) is converted to `"DEFAULT"`.

In `backend-go/internal/subtpl/resolve.go`, `resolveSecurity()` resolves client security:
- If `securityLayer == "TLS"`: forces client `security = "tls"`.
- If `securityLayer == "NONE"`: forces client `security = "none"`.
- If `securityLayer == "DEFAULT"`: inherits security from the inbound's stream settings.

| MVP Protocol Host | Inbound `streamSettings.security` | Host `securityLayer` | Resolved Client Security | Rationale |
|---|---|---|---|---|
| **VLESS REALITY Vision** | `reality` | `DEFAULT` | `reality` | Inherits `reality` from Xray inbound. `"REALITY"` is invalid enum; must be `"DEFAULT"`. |
| **VLESS XTLS Vision** | `tls` | `TLS` | `tls` | Directly terminates TLS in Xray with Let's Encrypt certificates; uses flow `xtls-rprx-vision`. |
| **VLESS XHTTP TLS** | `none` | `TLS` | `tls` | NGINX terminates TLS on 443/7443; Xray listens with `none`. Host must force `"TLS"` so client connects with TLS. |
| **VLESS WebSocket TLS** | `none` | `TLS` | `tls` | NGINX terminates TLS; Host must force `"TLS"`. |
| **Trojan gRPC TLS** | `none` | `TLS` | `tls` | NGINX terminates TLS; Host must force `"TLS"`. |

#### GoWave Response Rules Contract & Mandatory User-Agent
Upstream GoWave (`backend-go/internal/server/response_rules.go`) strictly requires a non-empty `User-Agent` header for client subscription requests, responding with HTTP 403 Forbidden if absent.
- The installer completion summary and CLI helper command `gowave-auto-nginx user links` explicitly document this requirement and provide copy-paste `curl` verification commands with client headers:
  ```bash
  curl -fsSL -H "User-Agent: v2rayN/6.0" "https://$PANEL_DOMAIN/api/sub/<shortUuid>/v2ray-json"
  curl -fsSL -H "User-Agent: ClashMeta/1.19" "https://$PANEL_DOMAIN/api/sub/<shortUuid>/mihomo"
  ```
- NGINX on 7443 preserves client User-Agent headers transparently to GoWave Panel via `proxy_set_header User-Agent $http_user_agent;`.

#### Web Panel UI vs. CLI Subscription Delivery (Scope Boundary)
- Upstream GoWave React frontend natively displays `user.subscriptionUrl` (the base subscription URL `https://<subPublicDomain>/<shortUuid>`).
- GoWave Auto NGINX explicitly **does NOT fork, rebuild, or patch the upstream React frontend bundle** in the MVP, avoiding frontend compilation fragility and maintenance divergence.
- The installer completion summary outputs both direct typed URLs (`/v2ray-json` and `/mihomo`).
- A CLI helper command `gowave-auto-nginx user links <username-or-shortUuid>` is provided to retrieve both typed URLs at any time.
- Subscriptions are validated to contain strictly public domain/IP and port 443; loopback addresses (`127.0.0.1`, `::1`), internal ports (`3000`, `3001`, `3002`, `7443`, `8443`, `9443`, `10001-10003`), node secrets, and private keys never appear in subscription output.

#### Scoped API Token Provisioning for External Web Frontends and Integrations
To enable seamless integration with external web subscription portals (such as `remnawave/subscription-page`) or Telegram management bots without exposing administrative passwords or granting raw database access, the installer automates token generation via `POST /api/tokens`:
```json
{
  "name": "gowave-auto-nginx subscription-page token",
  "description": "Generated by gowave-auto-nginx for external web subscription interfaces and integrations",
  "scopes": [
    "subscription-page-configs:list",
    "subscription-page-configs:get",
    "subscriptions:subpage-config",
    "system:metadata",
    "users:by-username"
  ],
  "expiresAt": null
}
```
To guarantee recovery resilience, administrative credentials (username, strong 24+ character password meeting complexity requirements, panel URL) are generated and persisted to `/root/gowave-credentials.txt` (mode `0600`, with directory fsync) **prior** to invoking `POST /api/auth/register`. When the scoped Bearer token is subsequently issued, it is appended atomically to `/root/gowave-credentials.txt`. This ensures that if a crash or network interruption occurs during subsequent provisioning steps, the recovery subsystem can always re-authenticate to roll back or inspect created entities.

---

### Decision 3: Upstream Installers, Hardening & Service Management

#### GoWave Panel Native Service Installation
- The installer downloads Panel binaries and frontend assets with SHA256 checksum verification.
- Generates `/opt/gowave/.env` containing `GOWAVE_PROXY=external`.
- Pre-creates system user and group `gowave:gowave` (`id -u gowave &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin gowave`).
- Explicitly deploys the complete base systemd unit `/etc/systemd/system/gowave.service`:
  ```ini
  [Unit]
  Description=GoWave Panel Server
  After=network-online.target
  Wants=network-online.target

  [Service]
  Type=simple
  User=gowave
  Group=gowave
  WorkingDirectory=/opt/gowave
  ExecStart=/opt/gowave/gowave-server
  Restart=always
  RestartSec=5
  LimitNOFILE=65535

  [Install]
  WantedBy=multi-user.target
  ```
- Executes `systemctl daemon-reload && systemctl enable gowave.service` to register the base unit.
- The installer registers the project-managed unit using the explicit `User=gowave`, `Group=gowave`, `WorkingDirectory=/opt/gowave`, and `ExecStart=/opt/gowave/gowave-server` contract above.
- It deliberately does **not** invoke `gowave-server service install`: that upstream helper can rewrite the managed unit and drop-ins outside the installer ownership/recovery contract. Required hardening is applied explicitly by this project and validated against its own service-unit template.
- This avoids silently replacing the managed service definition with a second unit-generation path.

#### GoWave Node Upstream Installer Orchestration
- `gowave-node-auto.sh` utilizes the official upstream `gowave-node/install.sh` installer as its foundation.
- The orchestrator sets environment variables:
  ```bash
  export NODE_PORT=3002 # (recommended default for both local node and remote workers)
  export GOWAVE_NODE_VERSION=latest
  export SECRET_KEY="<base64-payload>"
  ```
- Invokes upstream installer, which verifies checksums, creates `/etc/systemd/system/gowave-node.service`, manages runtime directories, and validates startup.
- Orchestrator configures UFW firewall rules:
  - On All-in-One: `ufw deny 3002/tcp` blocks external access to the wildcard listener; only loopback is permitted.
  - On Worker: `ufw allow from <PANEL_IP> to any port <NODE_PORT> proto tcp` whitelists the Control Plane IP (both IPv4 and IPv6), dropping all other external traffic.

##### Upstream NODE_PORT Support Verification & Fallback Contract (AUD-04)
- **Source Verification**: In pinned commit `gowave-node` `7b3514d`:
  - `gowave-node/install.sh#L340-L351`: Checks `port=$(env_get NODE_PORT); [ -n "$port" ] || port=${NODE_PORT:-}; port=$(unquote "${port:-3000}" NODE_PORT)`. Validates numeric range (`1-65535`), checks listener collision, and writes `NODE_PORT="$port"` into `/opt/gowave-node/.env`.
  - `gowave-node/internal/config/config.go#L102-L105`: Reads `portStr := os.Getenv("NODE_PORT")` and falls back to 3000 only when unset.
- **Hardening Fallback Drop-In**: To guarantee collision-free operation even if `/opt/gowave-node/.env` is modified manually or overwritten, the orchestrator deploys a persistent systemd drop-in `/etc/systemd/system/gowave-node.service.d/10-port.conf`:
  ```ini
  [Service]
  Environment="NODE_PORT=3002"
  ExecStartPost=/usr/bin/env bash -c 'for i in {1..30}; do if ss -Hltn "sport = :$node_port" 2>/dev/null | grep -q "$node_port" || (: < /dev/tcp/127.0.0.1/$node_port) 2>/dev/null; then exit 0; fi; sleep 0.5; done; exit 1'
  ```
  This guarantees that the node daemon unconditionally binds to port 3002 on All-in-One deployments, and systemd fails closed if the TCP listener does not come online within 15 seconds. Note that systemd drop-in reachability is verified via kernel socket / TCP connect (`ss` and `/dev/tcp`) rather than unauthenticated HTTP/TLS requests (`curl -k`), because `gowave-node` runs with `SNI_VERIFICATION=true` and rejects any TLS handshake lacking dynamic HKDF-derived SNI with `http: TLS handshake error: unknown sni`. Furthermore, comprehensive mutual TLS 1.3 health verification is executed via `modules/verify_node_mtls.py` (`verify_node_mtls_health`), validating the X.509 client certificate and EC private key match, deriving upstream HKDF-SHA256 SNI (`rw-v1`), performing a full client mTLS 1.3 handshake, and querying `/node/xray/healthcheck`.

#### Remote Worker SSH Stdin Pipeline Orchestration (`remote_payload`)
To deploy remote worker nodes over SSH without depending on `scp`, creating messy file transfers, or leaving orphaned scripts or credentials on target machines:
1. `gowave-node-auto.sh` implements a single, unified SSH stdin streaming mechanism:
   ```bash
   remote_payload() {
       local host="$1"
       local port="${2:-22}"
       local worker_domain="$3"
       local reality_domain="$4"
       local ssh_user="${5:-root}"
       {
           # Safely serialize environment variables strictly over stdin with export (NEVER in ssh argv)
           printf 'export PANEL_IP=%q\n' "$PANEL_IP"
           printf 'export PANEL_IPV6=%q\n' "${PANEL_IPV6:-}"
           printf 'export NODE_PORT=%q\n' "${NODE_PORT:-3002}"
           printf 'export GOWAVE_NODE_VERSION=%q\n' "${GOWAVE_NODE_VERSION:-latest}"
           printf 'export WORKER_DOMAIN=%q\n' "$worker_domain"
           printf 'export REALITY_DOMAIN=%q\n' "$reality_domain"
           printf 'export ADMIN_EMAIL=%q\n' "$ADMIN_EMAIL"
           # Stream base64 cover-reality tarball and expected checksum
           printf 'COVER_REALITY_B64=%q\n' "$cover_reality_b64"
           printf 'COVER_REALITY_SHA256=%q\n' "$cover_reality_sha256"
           # Scoped node secret variable (NOT exported to environment)
           printf '_NODE_SECRET_KEY=%q\n' "$SECRET_KEY"
           # Safely serialize modular installer and hardening functions
           declare -f log_info log_warn log_err setup_system_prereqs configure_host_security configure_firewall configure_edge_nginx run_upstream_node_installer unpack_cover_reality
           # Stream inline remote runner entrypoint wrapped in main function to prevent stdin hijacking
           cat <<'REMOTE_EOF'
   set -euo pipefail
   main() {
       umask 077
       trap 'unset _NODE_SECRET_KEY SECRET_KEY' EXIT HUP INT TERM
       setup_system_prereqs </dev/null
       configure_host_security </dev/null
       configure_firewall </dev/null
       umask 022
       unpack_cover_reality </dev/null
       configure_edge_nginx </dev/null
       umask 077
       # Pass secret strictly scoped to upstream installer execution only
       SECRET_KEY="$_NODE_SECRET_KEY" run_upstream_node_installer </dev/null
       unset _NODE_SECRET_KEY SECRET_KEY
   }
   main "$@" </dev/null
   REMOTE_EOF
       } | ssh -T -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=15 -p "$port" "${ssh_user}@${host}" 'bash -s'
   }
   ```
2. The remote execution runs directly through `bash -s` from stdin without creating unmanaged temporary disk files, applies host hardening (`configure_host_security` with swap, MTU probing `net.ipv4.tcp_mtu_probing = 1`, and fail2ban), resets `umask 022` for public web directories (`/var/www/gowave-auto-nginx/cover-reality` and `/var/www/gowave-acme`), securely unsets `SECRET_KEY` on completion or signal trap, keeps `SECRET_KEY` strictly out of process `argv` on both local and remote hosts, and transparently propagates the remote return code back to the orchestrator.

#### Config Profile to Node Association API
The installer associates Config Profiles and active inbounds to nodes using GoWave's exact API contract:
```json
POST /api/nodes
or
PATCH /api/nodes/{uuid}
{
  "name": "worker-1",
  "address": "127.0.0.1",
  "port": 3002,
  "configProfile": {
    "activeConfigProfileUuid": "<profile-uuid>",
    "activeInbounds": [
      "<inbound-uuid-1>",
      "<inbound-uuid-2>",
      "<inbound-uuid-3>",
      "<inbound-uuid-4>"
    ]
  }
}
```
- GoWave automatically compiles the Xray config and dispatches it to `gowave-node`.

#### Distributed Worker Registration Workflow (`gowave-auto.sh node add`)
To eliminate manual REST API calls and provide a complete all-in-one UX for registering distributed edge workers:
1. **Command Syntax**:
   ```bash
   gowave-auto.sh node add <node-name> <node-ip> <worker-domain> <reality-domain> [ssh-user] [ssh-port]
   ```
2. **Automated Provisioning Sequence**:
   - Authenticates against local Panel REST API (`POST /api/auth/login`) retrieving JWT bearer token.
   - Issues `POST /api/nodes` with `name`, `address: <node-ip>`, `port: 3000`, and links `activeConfigProfileUuid` and `activeInbounds` from the unified profile. Note that GoWave enforces a database UNIQUE constraint on `nodes.address` (`UNIQUE(address)`); each registered node must possess a distinct network address. Furthermore, `gowave-node` binds runtime socket `/run/gowave-node/xray.sock` and is strictly scoped to one daemon instance per host OS.
   - Extracts assigned `node-uuid` and retrieves node `SECRET_KEY` payload (`caCertPem`, `jwtPublicKey`, `nodeCertPem`, `nodeKeyPem`).
   - Creates corresponding worker Host records via `POST /api/hosts` (`address: <worker-domain>`, `port: 443`, linked to `node-uuid` and Internal Squad).
   - If `ssh-user` is supplied (or configured), initiates remote worker deployment using the canonical `remote_payload` function (zero secrets in `ssh` argv):
     ```bash
     PANEL_IP="$PANEL_IP" NODE_PORT=3002 SECRET_KEY="$SECRET_KEY" GOWAVE_NODE_VERSION=latest \
       remote_payload "$node_ip" "${ssh_port:-22}" "$worker_domain" "$reality_domain"
     ```
   - Records the provisioned worker node metadata into `/var/lib/gowave-auto-nginx/state.json` via atomic write with parent directory fsync.

---

### Decision 4: Safe Channel Switching (Stable vs. Dev)

GoWave Auto NGINX implements a dedicated subcommand `gowave-auto.sh channel [stable|dev]`:
1. **Pre-switch Inspection**: Reads `GOWAVE_CHANNEL` in `/opt/gowave/.env`. If already on the requested channel, exits with status 0.
2. **Mandatory Persistent Snapshot**: Executes SQLite Online Backup (`sqlite3 /opt/gowave/gowave.db ".backup /var/lib/gowave-auto-nginx/recovery/pre-channel-switch-<ts>.db"`) and archives current binaries.
3. **Migration Warning Guard**: When switching from Dev to Stable, the manager displays an explicit warning that newer Dev database migrations cannot be reversed, requiring interactive confirmation or the `--force` flag.
4. **Asset Update & Checksum Verification**: Downloads release assets for the target channel from official GitHub releases (`aaaSaZaN/gowave`), validates SHA256 checksums, and updates `/opt/gowave/.env` (`GOWAVE_CHANNEL=<channel>`).
5. **Restart & Health Verification**: Restarts `gowave.service` and polls `http://127.0.0.1:3000/api/system/health` for 30 seconds.
6. **Automatic Rollback**: If health verification fails, the manager halts the service, restores the previous binary, database, and `.env` from the snapshot, restarts the service, and exits with code 1.

---

### Decision 5: Transaction-Safe Updates with Crash Recovery Journal

#### Update Execution Flow
1. **Preflight Check & SQLite Online Backup**:
   - Verify panel health via `GET http://127.0.0.1:3000/api/system/health`.
   - Execute `PRAGMA integrity_check;` on live database.
   - Execute `PRAGMA wal_checkpoint(TRUNCATE);` with a 5-second busy timeout.
   - Capture a consistent database snapshot using staged SQLite Online Backup executing under service user privileges:
     ```bash
     # 1. Root pre-creates empty destination file with service user ownership and explicit mode 0640 (bypassing any strict system umask such as 077)
     install -o gowave -g gowave -m 0640 /dev/null "/opt/gowave/.backup-<ts>.db"
     # 2. Service user executes online SQLite backup into the pre-created file
     runuser -u gowave -- sqlite3 /opt/gowave/gowave.db ".backup /opt/gowave/.backup-<ts>.db"
     # 3. Root moves backup into root-only (0700) recovery storage and restores database permissions
     mv /opt/gowave/.backup-<ts>.db /var/lib/gowave-auto-nginx/recovery/update-<ts>/gowave.db
     chmod 0600 /var/lib/gowave-auto-nginx/recovery/update-<ts>/gowave.db
     chown gowave:gowave /opt/gowave/gowave.db /opt/gowave/gowave.db-wal /opt/gowave/gowave.db-shm 2>/dev/null || true
     chmod 0640 /opt/gowave/gowave.db /opt/gowave/gowave.db-wal /opt/gowave/gowave.db-shm 2>/dev/null || true
     ```
   - Verify `PRAGMA integrity_check;` on the backup copy.
2. **Persistent Snapshot & Durable State Journal**:
   - Create directory `/var/lib/gowave-auto-nginx/recovery/update-<ts>/` (mode 0700).
   - Copy `/opt/gowave/.env`, binary `gowave-server`, and `frontend/dist/`.
   - Write state to journal file `/var/lib/gowave-auto-nginx/recovery/journal.json` using atomic write (`.tmp` + `fsync` + `rename`):
     ```json
     {"transaction_id": "update-<ts>", "state": "PREPARED", "target_version": "v1.2.4"}
     ```
3. **Staged Release Application**:
   - Update journal state to `"APPLYING"`.
   - Download release binary and frontend bundle to temporary directory.
   - Verify SHA256 checksums against official `SHA256SUMS`.
   - Atomically replace files in `/opt/gowave/`.
4. **Service Restart & Health Verification**:
   - Update journal state to `"VERIFYING"`.
   - Run `systemctl restart gowave`.
   - Poll healthcheck endpoint for 30 seconds (15 attempts, 2-second interval).
5. **Automatic Rollback on Failure**:
   - If healthcheck fails, update journal state to `"ROLLBACK_REQUIRED"`.
   - Stop `gowave.service`.
   - Restore database, `.env`, binary, and frontend from recovery snapshot.
   - Restart `gowave.service`, verify original service health, and update journal state to `"ROLLED_BACK"`.
6. **Commit & Snapshot Pruning**:
   - Upon successful healthcheck, update journal state to `"COMMITTED"`.
   - Retain the last 3 recovery snapshots (enforcing a 5 GB maximum storage ceiling), pruning older snapshots safely.

#### Journal Schema Validation & Integrity Guard
Prior to executing any recovery action, `gowave-auto.sh recover` performs strict schema and structural validation of `/var/lib/gowave-auto-nginx/recovery/journal.json` (verifying required fields: `op`, `state`, `timestamp`, mapping `state` strictly to `OP_ALLOWED_STATES[op]`, and validating timestamp format).
- If `journal.json` is corrupted, truncated, or structurally invalid:
  1. The recovery unit immediately aborts without executing destructive rollbacks, logging a critical alert: `CRITICAL: journal.json validation failed; aborting automated rollback`.
  2. It performs a non-destructive read-only consistency audit via Panel API (`GET /api/nodes`, `GET /api/config-profiles`, `GET /api/hosts`) against `/var/lib/gowave-auto-nginx/state.json`.
  3. It requires manual operator confirmation (`gowave-auto.sh recover --force-reconcile`) to proceed, preventing cascading corruption from malformed journal state.

#### Reboot & Power Loss Recovery Architecture (Split Recovery Units)
If the server suffers a sudden power loss or kernel panic during an active update, restore, or provisioning transaction, rollback requires two distinct execution stages:
1. **File/DB Early Recovery (`gowave-recover.service`)**:
   Runs BEFORE `gowave.service` to prevent GoWave from booting with half-migrated SQLite databases, mismatched binaries, or corrupted configuration files:
   ```ini
   [Unit]
   Description=GoWave Auto NGINX early boot file/DB recovery
   ConditionPathExists=/var/lib/gowave-auto-nginx/recovery/journal.json
   Before=gowave.service gowave-node.service
   After=local-fs.target

   [Service]
   Type=oneshot
   ExecStart=/usr/local/sbin/gowave-auto.sh recover --boot-files

   [Install]
   WantedBy=multi-user.target
   ```
   On boot, `recover --boot-files` acquires `/run/lock/gowave-auto.lock` and checks `journal.json`:
   - If the journal state is `APPLYING`, `VERIFYING`, or `ROLLBACK_REQUIRED` (update or restore), it restores the pre-transaction database, `.env`, and binaries from the snapshot, transitions journal state to `ROLLED_BACK`, and unblocks service startup.
2. **API Entity Cleanup Recovery (`gowave-recover-provision.service`)**:
   API-driven entity rollbacks (such as deleting half-provisioned users, hosts, or nodes) require `gowave.service` to be actively running and serving HTTP REST API requests. An early unit ordered `Before=gowave.service` cannot perform HTTP API rollbacks. Therefore, API rollback is delegated to a post-startup unit:
   ```ini
   [Unit]
   Description=GoWave Auto NGINX post-boot API provision cleanup
   ConditionPathExists=/var/lib/gowave-auto-nginx/recovery/journal.json
   After=gowave.service
   Wants=gowave.service

   [Service]
   Type=oneshot
   ExecStart=/usr/local/sbin/gowave-auto.sh recover --boot-provision

   [Install]
   WantedBy=multi-user.target
   ```
   On boot, `recover --boot-provision` waits for `GET http://127.0.0.1:3000/api/system/health` to return HTTP 200:
   - If journal state is `PROVISION_*` (uncommitted initial setup), it executes API deletion of tracked partial entities in reverse order, cleans up `state.json.tmp`, and marks journal `PROVISION_ROLLED_BACK`.
   - If journal state is `NODE_ADD_*` (uncommitted worker addition), it executes worker-specific isolated API cleanup, and marks journal `NODE_ADD_ROLLED_BACK`.

#### Initial Provisioning Transaction Lifecycle & Rollback (AUD-05)
To eliminate dirty partial setups and guarantee complete atomicity during initial installation, the initial provisioning phase (Config Profile, Node, Squad, Hosts, User, API Token) is tracked inside `/var/lib/gowave-auto-nginx/recovery/journal.json`:
1. **Provisioning State Transitions**:
   - `PROVISION_PREPARED`: Initial admin authenticated, parameters validated.
   - `PROVISION_APPLYING`: Entities are created and their UUIDs recorded sequentially into `/var/lib/gowave-auto-nginx/state.json.tmp`.
   - `PROVISION_VERIFYING`: `GET /api/config-profiles/{uuid}/computed-config` and subscription test queries executed.
   - `PROVISION_COMMITTED`: Atomic rename of `state.json.tmp` -> `state.json` with parent directory fsync. Journal marked `COMMITTED`.
   - `PROVISION_ROLLBACK_REQUIRED`: Any step failed or verification timed out.
   - `PROVISION_ROLLED_BACK`: Cleanup completed, system reverted to clean state.
2. **Deterministic Initial Provisioning Rollback Actions on Failure**:
   If an error occurs or verification fails during initial panel provisioning, the orchestrator parses the recorded entities from `journal.json` and distinguishes resource action:
   - For `created`: deletes only the resources created in this transaction by UUID (`DELETE /api/tokens/{id}`, `DELETE /api/users/{uuid}`, `DELETE /api/hosts/{uuid}`, `DELETE /api/internal-squads/{uuid}`, `DELETE /api/nodes/{uuid}`, `DELETE /api/config-profiles/{uuid}`).
   - For `updated`: restores pre-transaction state (`before`).
   - For `adopted`: preserves existing entities untouched.
   - Destructive global scans by name are strictly eliminated.
   - Remove temporary files, update journal state to `PROVISION_ROLLED_BACK`, and halt with exit code 1.

#### Dedicated Worker Node Addition Transaction & Isolated Rollback
Worker node addition (`gowave-auto.sh node add`) operates under an independent transaction lifecycle to ensure failures during worker deployment NEVER delete existing central panel users, tokens, or squad entities:
1. **Worker Addition Journal States**:
   - `{"op": "node_add", "name": "<worker-name>", "state": "NODE_ADD_PREPARED"}`
   - `NODE_ADD_APPLYING`: Worker profile, node registration, squad association, and worker hosts recorded in `state.json.tmp`.
   - `NODE_ADD_VERIFYING`: Worker edge connectivity and computed config validated.
   - `NODE_ADD_COMMITTED`: Atomic commit merging worker into `state.json`.
   - `NODE_ADD_ROLLBACK_REQUIRED` / `NODE_ADD_ROLLED_BACK`: Automated cleanup on failure.
2. **Isolated Worker Rollback Actions**:
   If worker deployment or verification fails, the orchestrator compensates the **Panel API transaction** using its action ledger:
   - Delete only Worker hosts/node/profile entries recorded as `created`.
   - Restore a pre-existing resource from its `before` image when recorded as `updated`.
   - Preserve entries recorded as `adopted`, including shared internal squads.
   - Strictly FORBIDS deleting unrelated panel users or API tokens.

   **Compensating Worker Rollback**:
   If worker deployment or verification fails, the orchestrator executes automated compensating rollback on the Worker (`compensate_remote_worker` via in-process `ERR` trap and `gowave-node-auto.sh remote_rollback` via SSH stdin):
   - Stops and disables `gowave-node.service` and `xray.service`, removes systemd drop-ins (`/etc/systemd/system/gowave-node.service.d/10-port.conf`), reloads daemon, and purges `/opt/gowave-node` and `/run/gowave-node`.
   - Removes NGINX virtual hosts (`gowave-worker-https.conf`, `gowave-worker-decoy.conf`, `gowave-worker-stream.conf`, `00-bootstrap-worker-acme.conf`), reverts `stream` include if added, and reloads NGINX.
   - Revokes and deletes ACME certificates via Certbot for `$WORKER_DOMAIN` and `$REALITY_DOMAIN`.
   - Reverts UFW firewall changes (disabling UFW if originally inactive, or deleting source-scoped Control Plane rules).
   - Deactivates and deletes `/swapfile` (and removes `/etc/fstab` entry) if created during the session.
   - Removes `/etc/sysctl.d/99-gowave-node.conf` and reloads sysctl.
   - Securely wipes secrets and `/tmp/gowave-*` scratch files.

---

### Decision 6: Zero-Leak Secret Delivery

- `SECRET_KEY` is extracted via `./gowave-server rescue --print-secret-key-raw`.
- When configuring `gowave-node`, the secret is delivered strictly via standard input (`stdin`) or written to a private temporary file with mode `0600` that is unlinked immediately after ingestion.
- The secret key is **never passed in CLI arguments** (`argv`), preventing credential exposure via `/proc/<pid>/cmdline` or `ps aux`.
- `SNI_VERIFICATION=true` is explicitly set in `/opt/gowave-node/.env`.
- Initial administrative credentials are saved via `save_credentials` (implemented natively in both Bash and Python with `umask 077`, mode `0600`, and immediate directory sync) into `/root/gowave-credentials.txt` prior to calling registration APIs.

---

### Decision 7: Multi-Distribution Compatibility Layer (Debian & Ubuntu)

Multi-distribution compatibility across target systems is achieved via three targeted runtime adaptations, adhering strictly to the taxonomy defined in `COMPATIBILITY_MATRIX.md`:
1. **`systemd-resolved` Provisioning (Debian 12 Bookworm `[SOURCE_COMPATIBLE]` & Debian 13 Trixie `[PROJECT_E2E_PLANNED]`)**:
   - Detected via `command -v resolvectl`. If missing and DoT is selected, runs `apt-get install -y systemd-resolved` and enables the unit.
2. **NGINX Runtime HTTP/2 Syntax Detection**:
   - Evaluates `nginx -v` dynamically rather than relying solely on OS release names.
   - For NGINX versions < 1.25.1 (which includes Debian 12 Bookworm `[SOURCE_COMPATIBLE]` with 1.22.1 AND Ubuntu 24.04 Noble `[UPSTREAM_SUPPORTED]` with 1.24.0), renders:
     ```nginx
     listen 127.0.0.1:7443 ssl http2 proxy_protocol;
     ```
   - For NGINX versions >= 1.25.1 (Debian 13 Trixie `[PROJECT_E2E_PLANNED]` with 1.26.3, Ubuntu 26.04 Resolute `[PROJECT_E2E_PLANNED]`, or official nginx.org repos), renders:
     ```nginx
     listen 127.0.0.1:7443 ssl proxy_protocol;
     http2 on;
     ```
3. **APT Security Origins**:
   - Configures `/etc/apt/apt.conf.d/99zz-gowave-auto-nginx` with `origin=Debian,label=Debian-Security,codename=${distro_codename}-security` for Debian hosts.
   - Disables automatic reboots (`Unattended-Upgrade::Automatic-Reboot "false";`) by default.
4. **Kernel Congestion Control (BBR) & MTU Probing (PLPMTUD)**:
   - To eliminate the asynchronous race condition between `systemd-modules-load.service` and `systemd-sysctl.service` (which causes `net.ipv4.tcp_congestion_control = bbr` to silently fall back to `cubic` on boot), the installer deploys a dedicated oneshot systemd unit `/etc/systemd/system/bbr-load.service`:
     ```ini
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
     ```
   - Enabled via `systemctl enable bbr-load.service`. The `-` prefix ensures graceful fallback on kernels or virtualized environments without `tcp_bbr` (e.g. OpenVZ, LXC), preserving system startup, logging `BBR unavailable, falling back to CUBIC`, persisting `"congestionControl": "cubic"` in `state.json`, and defaulting to `cubic` without service failure.
   - Runtime drop-in verification: installer confirms `GOMEMLIMIT=250MiB` is active in service runtime:
     `systemctl show gowave.service -p Environment | grep -q "GOMEMLIMIT=250MiB"`.
   - Enables Packetization Layer Path MTU Discovery (`net.ipv4.tcp_mtu_probing = 1`) in `/etc/sysctl.d/99-gowave.conf` to significantly reduce the risk of PMTU blackholing across non-1500 MTU cloud networks (e.g. Hetzner vSwitch 1450, GCP 1460, PPPoE).
5. **Fail2ban Modern Systemd Journal & Socket Activation**:
   - Installs `python3-systemd` prerequisite, configures `backend = systemd` in `/etc/fail2ban/jail.d/90-gowave-auto-nginx.local`:
     ```ini
     [sshd]
     enabled = true
     backend = systemd
     banaction = ufw
     ignoreip = 127.0.0.1/8 ::1
     journalmatch = _SYSTEMD_UNIT=ssh.service + _COMM=sshd
                 + _COMM=sshd-session
     ```
   - Monitors standalone `ssh.service` (Debian 12), socket-activated `ssh.socket` (Ubuntu 24.04), and modern OpenSSH 9.8+ session workers (`sshd-session`), eliminating brute-force detection blind spots.
6. **Low-Memory (512MB-1GB RAM) Protection & Filesystem-Aware Swap**:
   - Pre-flight memory check evaluates `/proc/meminfo` for systems with <= 1 GiB RAM (`MemTotal <= 1048576 KiB`):
     ```bash
     if [[ $(awk '/MemTotal/ {print $2}' /proc/meminfo) -le 1048576 ]] && ! swapon --show | grep -q .; then
       # Filesystem-aware swap allocation (strictly avoiding fallocate sparse extents)
       FS_TYPE=$(df -T / | awk 'NR==2 {print $2}')
       if [[ "$FS_TYPE" == "btrfs" ]] && command -v btrfs >/dev/null; then
         btrfs filesystem mkswapfile --size 1G /swapfile 2>/dev/null || {
           truncate -s 0 /swapfile && chattr +C /swapfile && dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none
         }
       else
         dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none
       fi
       chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
       echo '/swapfile none swap sw 0 0' >> /etc/fstab
     fi
     ```
   - Injects `Environment="GOMEMLIMIT=250MiB"` into systemd service drop-ins for `gowave` and `gowave-node`, tuning Go runtime garbage collection cadence to reduce heap spikes (acknowledged as a runtime GC tuning parameter rather than a hard cgroup ceiling).
7. **Conditional IPv6 Firewall & Listener Adaptation**:
   - Detects `sysctl -n net.ipv6.conf.all.disable_ipv6`. If `1` or if no valid IPv6 route exists:
     - Sets `IPV6=no` in `/etc/default/ufw` to prevent UFW startup errors during `ip6tables` rule evaluation.
     - Omits `listen [::]:443` and `listen [::]:80` in NGINX configurations, preventing fatal `bind() to [::] failed (97: Address family not supported by protocol)`.
   - When IPv6 is enabled, provisions dual-stack listeners and firewall rules.
8. **Log Rotation & Disk Space Depletion Prevention**:
   - Disables access logging on high-volume streaming endpoints (`access_log off;` in locations `/xhttp-down/` and `/ws`).
   - Deploys `/etc/logrotate.d/gowave-nginx` with daily rotation, 7-day retention, and gzip compression.
   - Caps persistent systemd journal storage at `SystemMaxUse=100M` in `/etc/systemd/journald.conf.d/99-gowave.conf`.

---

### Decision 8: Backup Format v1 & Hardened Archive Validation

#### Format Identity & Structure
The archive format is formally designated as **GoWave Auto NGINX Backup Format v1**:
- Type: **UNENCRYPTED gzip archive (`.tar.gz`)**, protected by POSIX mode `0600` root-only permissions.
- Manifest `meta.json`:
  ```json
  {
    "format_version": 1,
    "created_at": "2026-11-07T12:00:00Z",
    "backup_type": "panel",
    "source_os": {"id": "ubuntu", "version_id": "24.04", "arch": "amd64"},
    "component_versions": {
      "gowave": "v1.2.4",
      "gowave_node": "v1.1.3",
      "xray": "v25.x",
      "nginx": "1.24.0"
    },
    "files": [
      {"path": "opt/gowave/gowave.db", "sha256": "...", "mode": "0640", "owner": "gowave", "group": "gowave"},
      {"path": "opt/gowave/.env", "sha256": "...", "mode": "0640", "owner": "root", "group": "gowave"}
    ]
  }
  ```

#### 15-Point Archive Preflight Security Validation
Before extracting any archive, a dedicated Python validator inspects all tar members:
1. Rejects member names containing directory traversal sequences (`..`).
2. Rejects absolute path member names (leading `/`).
3. Rejects member paths outside strict file-level allowlists:
   - Panel (`--type panel`): strictly restricted to explicit safe configuration and database files: `opt/gowave/gowave.db`, `opt/gowave/.env`, `etc/nginx/conf.d/gowave-*.conf`, `etc/nginx/stream-enabled/gowave-*.conf`, `etc/letsencrypt/{archive,live,renewal}/<domains-from-meta>/**`, and `var/lib/gowave-auto-nginx/state.json`.
   - Node (`--type node`): strictly restricted to `opt/gowave-node/.env`.
   - Explicitly rejects: `etc/letsencrypt/renewal-hooks/`, `etc/nginx/modules-enabled/`, `etc/systemd/system/gowave-node.service.d/`, any shell scripts (`*.sh`), shared objects (`*.so`), and executable binaries (`opt/gowave/gowave-server`, `opt/gowave-node/*`). Binaries are NEVER restored from archives (they are freshly downloaded and verified via upstream `SHA256SUMS`). Unmanaged locations (`etc/cron.d/`, `etc/systemd/system/*.service`, `root/.ssh/`, `bin/`) are rejected with fatal error.
4. Clears SUID, SGID, and executable sticky bits (`04000`, `02000`, `01000`) on all extracted files; ignores tar header owner/group attributes and applies target restore permission policy.
5. Validates symbolic links: permits relative symbolic links whose normalized path resolves within the archive root hierarchy (`files/etc/letsencrypt`) and matches the allowlist (such as Certbot `../../archive/<domain>/fullchain1.pem`); strictly rejects absolute symlinks or relative symlinks escaping `files/`.
6. Rejects hard links pointing to non-regular files.
7. Rejects FIFO, socket, block, or character device nodes.
8. Rejects archives with member counts exceeding 5,000 files.
9. Rejects archives whose unpacked size exceeds 1 GB (decompression bomb protection).
10. Rejects `meta.json` exceeding 16 KB.
11. Validates file SHA256 checksums against `meta.json`.
12. Validates OS and architecture compatibility against target host.
13. Restricts extraction strictly to a private staging directory (`mode 0700`).
14. Restores files atomically using temporary siblings and renames.
15. Displays prominent security warning: archives contain unencrypted master CA, JWT signing keys, and TLS certificates.

#### Transactional Restore Execution Lifecycle
The restore process in `gowave-backup.sh restore` executes an 8-stage transactional lifecycle with automated crash recovery:
1. **Pre-extraction 15-Point Preflight**: Extract to private temporary staging directory (`mode 0700`).
2. **Preflight Staged Database Integrity Check**: Verifies `PRAGMA integrity_check` on staged `gowave.db` before stopping any running services or touching live files. Corrupted archives are rejected immediately.
3. **Pre-Restore Snapshot & Service Suspension**: Stops `gowave.service` to prevent active SQLite WAL transactions, captures consistent pre-restore snapshot via `sqlite_online_backup`, and snapshots `.env` and `state.json`.
4. **Journal Initialized to PREPARED**: Recovery journal records `{"op": "restore", "state": "PREPARED", "snapshot_dir": "..."}`.
5. **Atomic File Replacement (APPLYING)**: Restores `gowave.db`, `.env`, and `state.json` via `.restoring` temporary files with `fsync`, clears obsolete WAL/SHM, restores NGINX configs and Let's Encrypt certificates, and enforces ownership `gowave:gowave` and mode `0640`.
6. **Service Start & Verification (VERIFYING)**: Starts `gowave.service` and executes HTTP health probe against `/api/system/health`.
7. **Automated Rollback on Failure**: If service fails to start or healthcheck fails, journal transitions to `ROLLBACK_REQUIRED`, previous snapshot files are restored, `gowave.service` is restarted, journal is marked `ROLLED_BACK`, and restore exits non-zero.
8. **Commit (COMMITTED)**: Upon verified health, journal is marked `COMMITTED` and old snapshots are pruned.

### Decision 9: Local Multi-Distribution Podman Testbed (Pre-Deployment VPS Gate)

#### Motivation & Operational Context
Deploying infrastructure code directly to remote VPS instances introduces high risk of mid-flight failures due to distribution discrepancies, systemd version differences, or package availability issues. To eliminate VPS deployment risks and provide instant developer feedback without the latency of launching full QEMU virtual machines, GoWave Auto NGINX establishes a local containerized pre-flight gate powered by Podman.

#### PID 1 Systemd in Containerized Environments
Unlike standard container runtimes, Podman natively supports systemd as PID 1 when invoked with `--systemd=always --privileged`. Podman automatically manages tmpfs on `/run` and `/tmp` and sets up cgroup hierarchy namespaces, enabling complete lifecycle testing of systemd services (`gowave.service`, `gowave-node.service`, `nginx.service`, `fail2ban.service`), UFW firewall initialization, and socket-based activation across all target distributions without hazardous direct host `/sys/fs/cgroup` volume mounts.

#### 4-Distribution Testbed Matrix
The automated testbed runner (`tests/podman_testbed.sh`) executes against the official base images:
- **Ubuntu 24.04 LTS**: `docker.io/library/ubuntu:24.04` (systemd 255.4, NGINX 1.24.0 legacy HTTP/2 syntax)
- **Ubuntu 26.04 LTS**: `docker.io/library/ubuntu:26.04` (systemd 256+, NGINX 1.26+ modern HTTP/2 syntax)
- **Debian 12 Bookworm**: `docker.io/library/debian:12` (systemd 252.30, `systemd-resolved` installation adaptation)
- **Debian 13 Trixie**: `docker.io/library/debian:13` (systemd 256+, modern HTTP/2 syntax)

#### 8-Stage In-Container Test Execution
The testbed script executes an 8-stage verification pipeline inside each containerized distribution:
1. Detects OS and provisions distribution-specific dependencies (including `systemd-resolved` on Debian 12).
2. Verifies runtime NGINX version detection and configuration syntax (`listen ... ssl http2;` vs `http2 on;`).
3. Executes preflight port and unmanaged NGINX port 443 conflict scanning.
4. Bootstraps systemd services with port 3002 isolation and UFW loopback-only rules.
5. Executes REST API provisioning (unified Config Profile, Host records, native x25519 key generation).
6. Verifies NGINX Stream SNI multiplexing, XHTTP unbuffered streaming, and 9443 cover fallback.
7. Retrieves deterministic Xray JSON and Mihomo YAML subscriptions and validates them with official core binaries.
8. Simulates update transaction crash and asserts automatic state rollback via `journal.json`.

Passing all 8 stages across all 4 distributions is enforced as a mandatory requirement prior to any VPS deployment.

#### Multi-Node Distributed Edge E2E Testbed (Panel + Remote Worker)
**Current status (2026-11-08):** `tests/podman_testbed.sh multi-node` is deliberately marked unavailable (exit 77). The previous script was only a three-container/SSH scaffold; it did not call `remote_payload`, register the Worker through the real GoWave API, complete mTLS, or send client data-plane traffic. It must not be described as an E2E test or a passed release gate.

The following remain required before multi-node E2E can be claimed:
- Deploy a real Panel and Worker through the same orchestration path used in production.
- Verify source-scoped UFW rules from an authorized Panel and an unauthorized peer.
- Complete a protocol-level TLS 1.3 mTLS handshake using the HKDF-derived SNI (`rw-v1`).
- Verify API resource synchronization and direct client traffic to the Worker across supported transports.
- Verify the Worker REALITY fallback/decoy path.
