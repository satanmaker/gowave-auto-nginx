# Technical Audit & Decision Register: GoWave Auto NGINX

**Document Status**: Authoritative Engineering Baseline  
**Audit Date**: November 7, 2026  
**Auditor**: Senior DevOps / Linux Infrastructure Engineer / Security Architect  
**Scope**: Codebases of `gowave`, `gowave-node`, and `community-baseline`

---

## 1. Upstream Repositories, Pinned Commits & Audit Scope

| Repository | Upstream URL | Pinned Tag / Ref | Pinned Commit SHA | Commit Date | Exact Examined Scope |
|---|---|---|---|---|---|
| **GoWave** | `https://github.com/aaaSaZaN/gowave` | `v1.2.4` (tag `dev`, `main`) | `6d2c35788b3b038627b5e86e6c6486caff0851c8` | 2026-11-07 04:42:31 +0700 | `backend-go/config/`, `cmd/server/`, `internal/server/`, `internal/subscription/`, `internal/subtpl/`, `internal/configprofiles/`, `internal/nodes/`, `internal/serviceunit/`, `internal/database/`, `install.sh` |
| **GoWave Node** | `https://github.com/aaaSaZaN/gowave-node` | `v1.1.3-3-g7b3514d` | `7b3514d1ab8c674050597820d52d55525d4bece7` | 2026-11-07 04:18:09 +0700 | `cmd/gowave-node/`, `internal/config/`, `internal/tlsutil/`, `internal/auth/`, `internal/xray/`, `internal/handler/`, `internal/stats/`, `internal/updater/`, `install.sh`, `AGENTS.md` |
| **community-baseline** | `https://github.com/community-baseline/community-baseline` | `v2.4.0-1-gcommunity-baseline` | `community-baseline` | 2026-11-07 13:21:15 +0300 | `tests/run_ci.py`, `tests/systemd/`, `assets/security/`, `assets/xhttp-cdn/`, `assets/vision/`, `assets/backup/`, `x-ui-latest.sh`, `THIRD_PARTY_NOTICES.md`, `LICENSE` |

---

## 2. Line-Level Source Evidence

### 2.1 GoWave Panel (`gowave`)
1. **Environment Variables & Configuration**:
   - `gowave/backend-go/config/config.go#L88-L96`: `APP_HOST` defaults to `"127.0.0.1"`, `APP_PORT` defaults to `"3000"`.
   - `gowave/backend-go/config/config.go#L105-L122`: `DB_DRIVER` defaults to `"sqlite"`, `DATABASE_URL` defaults to `"gowave.db"`.
   - `gowave/backend-go/config/config.go#L147-L164`: Loads `APP_SECRET`, `PANEL_DOMAIN`, `SUB_PUBLIC_DOMAIN`, `METRICS_PORT` (3001), `METRICS_ENABLED`.
   - `gowave/install.sh#L1365-L1373`: `configured_proxy()` explicitly tests `[ "$(env_get "$ENV_FILE" GOWAVE_PROXY)" = external ]`. Setting `GOWAVE_PROXY=external` instructs GoWave to leave reverse proxy ownership entirely to external automation.
2. **Subscription Routing, Client Types & Templates**:
   - `gowave/backend-go/internal/server/server.go#L522-L524`: Chi router registers `/api/sub/{shortUuid}`, `/api/sub/{shortUuid}/info`, and `/api/sub/{shortUuid}/{clientType}`.
   - `gowave/backend-go/internal/subscription/srr.go#L77-L83`: `Match()` inspects `overrideClientType`. If `DisableSubscriptionAccessByPath` is true, returns `BLOCK`.
   - `gowave/backend-go/internal/subscription/srr.go#L164-L180`: `handleOverrideClientType()` maps `"v2ray-json"` and `"json"` to `"XRAY_JSON"`, and `"mihomo"` to `"MIHOMO"`.
   - `gowave/backend-go/internal/subtpl/render.go#L54-L76`: `Render()` queries template by type. If template is nil/missing, returns empty string `""`.
   - `gowave/backend-go/internal/database/default_data.go#L10-L60,L238-L270`: `EnsureDefaultTemplates()` seeds `DefaultTemplateMihomo` and `DefaultTemplateXrayJson`. `EnsureSubscriptionSetting()` seeds `DefaultSRRConfig` with `DisableSubscriptionAccessByPath: false`.
3. **Hosts Management API**:
   - `gowave/backend-go/internal/server/server.go#L611-L623`: Registers `/api/hosts` endpoints (`POST`, `GET`, `PATCH`, `DELETE`).
   - `gowave/backend-go/internal/configprofiles/service.go#L55-L95,L97-L160`: `CreateHostInput` struct maps `inbound.configProfileUuid`, `inbound.configProfileInboundUuid`, `remark`, `address`, `port`, `sni`, `path`, `host`, `alpn`, `fingerprint`, `securityLayer`, and `nodes`.
4. **Nodes Config Profile & Inbounds DTO**:
   - `gowave/backend-go/internal/nodes/service.go#L218-L221`: `ConfigProfile` struct defines `ActiveConfigProfileUUID string` and `ActiveInbounds []string`.
   - `gowave/backend-go/internal/nodes/handler.go#L494-L515`: `UpdateWithConfigProfile()` updates active profile and inbounds, automatically triggering `StartNode()` and Xray configuration compilation.
5. **Privilege Boundary & Native Service Installation**:
   - `gowave/backend-go/internal/serviceunit/install.sh#L36-L102`: `service install` creates system user and group `gowave:gowave`, sets mode `1770 root:gowave` on `/opt/gowave`, and generates `/etc/systemd/system/gowave.service.d/90-unprivileged.conf` with `ProtectSystem=strict`, `NoNewPrivileges=true`, `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`.
   - `gowave/backend-go/internal/serviceunit/install.sh#L109-L133`: Configures `gowave-update.path` and `gowave-update.service`.

### 2.2 GoWave Node (`gowave-node`)
1. **Wildcard Network Bind & Port**:
   - `gowave-node/cmd/gowave-node/main.go#L177`: `addr := fmt.Sprintf(":%d", cfg.NodePort)` binds to wildcard interfaces (`0.0.0.0` and `[::]`), confirming that loopback restriction must be enforced at the host firewall (UFW) layer.
2. **Upstream Installer**:
   - `gowave-node/install.sh#L1-L220`: Accepts `SECRET_KEY`, `NODE_PORT`, `GOWAVE_NODE_VERSION`, checks SHA256 checksums from GitHub releases, detects init systems, and installs `/etc/systemd/system/gowave-node.service`.
3. **Node Payload & HKDF SNI**:
   - `gowave-node/internal/config/payload.go#L33-L38`: Defines `NodePayload` struct containing `caCertPem`, `jwtPublicKey`, `nodeCertPem`, `nodeKeyPem`.
   - `gowave-node/internal/config/payload.go#L59-L85`: `DeriveSni(caCertPem, jwtPublicKey)` computes SNI via HKDF-SHA256 with info `"rw-v1"`.
4. **Mutual TLS 1.3 & JWT**:
   - `gowave-node/internal/tlsutil/tls.go#L13-L42`: `SetupServerTLS` configures `MinVersion = tls.VersionTLS13`, `ClientAuth = tls.RequireAndVerifyClientCert`, and adds `caCertPem` to `ClientCAs`. If `cfg.SniVerification` is true, verifies `hello.ServerName`.
   - `gowave-node/internal/config/config.go#L101-L152`: `NODE_PORT` defaults to `3000`. `SNI_VERIFICATION` defaults to `false` (overridden to `true` by GoWave Auto NGINX).
5. **Xray-Core Supervision & Process Lifecycle**:
   - `gowave-node/internal/xray/process.go#L51-L132`: Supervised execution with ring buffer logging. Direct process management handles auto-restart on unexpected exit. **No external watchdog timer.**

### 2.3 community-baseline (community baseline)
1. **NGINX Stream SNI Demultiplexing**:
   - `community-baseline/x-ui-latest.sh#L797-L825`: Public port 443 bound by NGINX Stream (`ssl_preread on; proxy_protocol on;`). SNI map routes `reality_domain` to 8443, `panel_domain` to 7443, and default/unknown to 8443.
2. **REALITY Fallback & Decoy Site**:
   - `community-baseline/assets/vision/managed.py#L73-L100`: Xray fallback sends PROXY protocol v1 (`dest: 127.0.0.1:9443, xver: 1`) to NGINX listener at 9443 (`listen 127.0.0.1:9443 ssl proxy_protocol;`) serving static camouflage HTML.
3. **Backup Preflight Validation & Security Checks**:
   - `community-baseline/assets/backup/x-ui-backup.sh#L400-L452`: Python validator inspects tar members, rejects `..`, leading `/`, symlinks pointing outside managed roots, hardlinks to non-files, device nodes, and FIFOs.
4. **CI Runner & Privilege Separation**:
   - `community-baseline/tests/run_ci.py#L12-L41,L94-L116`: Uses `--suite` with choices `nonroot`, `root`, `integration`, `services`, `systemd`, or `--check-completeness`. Enforces EUID checks before execution.

---

## 3. Decision Register

```
+--------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Question & Context     | Previous Assumption     | Upstream Verified Fact     | Adopted Decision         | Alternatives Rejected    | Consequence & Verification   |
+========================+=========================+============================+==========================+==========================+==============================+
| 1. Subscription Links  | Generic endpoint        | GoWave supports            | Provide two deterministic| Relying only on generic  | User receives client-ready   |
|    (P0-1)              | /api/sub/{shortUuid}    | /api/sub/{id}/{clientType};| URLs: /v2ray-json (Xray  | endpoint with User-Agent | links immediately; tested via|
|                        | without client format   | missing templates yield    | JSON) and /mihomo        | sniffing; returning      | HTTP status 200, Content-Type|
|                        | specification.          | empty body.                | (Mihomo YAML); seed tpls.| raw links without format.| and client config parsers.   |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 2. Host Provisioning   | Config Profiles alone   | GoWave requires Host       | Automatically provision  | Leaving Host creation to | All 4 MVP protocols resolve  |
|    (P0-2)              | create client-ready     | records (POST /api/hosts)  | Host entities linking    | manual user entry in     | to functional client configs;|
|                        | subscriptions.          | to define public endpoints.| public IP, port 443, SNI.| panel UI.                | verified in subscriptions.   |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 3. Node Bind Address   | Node binds strictly to  | Source does                | Document wildcard bind;  | Claiming Node listens    | Secure network model; local  |
|    (P1-1)              | loopback 127.0.0.1:3002.| addr := fmt.Sprintf(":%d") | isolate via UFW firewall | only on 127.0.0.1;       | node inaccessible from       |
|                        |                         | (wildcard on all ifaces).  | rule denying external in.| leaving port 3002 open.  | outside; verified by L4 test.|
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 4. Node Installer      | Orchestrator downloads  | Upstream gowave-node has   | Use gowave-node/install. | Reimplementing binary    | Avoids maintenance drift;    |
|    (P1-2)              | binary and writes       | install.sh with checksums, | sh as primary installer  | download and systemd unit| leverages upstream updates   |
|                        | systemd unit manually.  | systemd, and rollback.     | orchestrating parameters.| generation.              | and rollback logic.          |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 5. Service Hardening   | Installer writes manual | gowave-server service      | Manage service via       | Writing redundant drop-in| Clean systemd unit hierarchy;|
|    (P1-3)              | 90-unprivileged.conf    | install creates identical  | native service install;  | that may conflict or     | zero race conditions during  |
|                        | drop-in file.           | 90-unprivileged.conf.      | remove manual duplicate. | break on update.         | upgrades.                    |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 6. External Proxy Mode | NGINX managed externally| GoWave install.sh checks   | Set GOWAVE_PROXY=external| Allowing GoWave to try to| NGINX configs owned 100% by  |
|    (P1-4)              | without informing       | GOWAVE_PROXY == external   | in /opt/gowave/.env      | configure Caddy or Nginx | GoWave Auto NGINX; zero      |
|                        | GoWave panel.           | in configured_proxy().     | explicitly.              | in background.           | config overwrite conflicts.  |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 7. Node Profile DTO    | Generic profile linking | Node DTO requires          | Send exact DTO:          | Sending arbitrary JSON   | Reliable API association;    |
|    (P1-5)              | description.            | activeConfigProfileUuid &  | configProfile with UUID  | payloads; manual DB      | GoWave immediately compiles  |
|                        |                         | activeInbounds ([]string). | and array of inbounds.   | injection.               | and dispatches Xray config.  |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 8. Channel Switching   | Claimed in proposal     | Dev builds have higher     | Implement explicit       | Dropping channel command;| Full lifecycle support for   |
|    (P1-6)              | without full contract   | migrations; downgrade      | gowave-auto.sh channel   | uncontrolled switching   | operators wanting bleeding-  |
|                        | in tasks/specs.         | cannot auto-reverse.       | with snapshot & guard.   | without backup.          | edge or stable releases.     |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 9. Compatibility Status| Debian 12 marked as     | Upstream GoWave/community baseline lack | Refine matrix taxonomy;  | Overstating official     | Rigorous engineering claims; |
|    (P1-7)              | UPSTREAM_SUPPORTED.     | dedicated Debian 12 CI     | classify Panel/Node on   | upstream verification.   | adaptations verified via L5  |
|                        |                         | test workflows.            | Debian 12 as SOURCE_COMP.|                          | QEMU tests.                  |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 10. Container User     | Integration tests ran   | tests/run_ci.py rejects    | Run integration container| Running integration as   | Strict compliance with community baseline |
|     (P1-9)             | as root in container.   | EUID 0 for integration     | with --user 1001:1001    | root; disabling EUID     | runner privilege separation  |
|                        |                         | and services suites.       | enforcing EUID != 0.     | checks in runner.        | contract.                    |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
```
