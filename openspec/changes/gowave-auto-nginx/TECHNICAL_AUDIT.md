# Technical Audit & Decision Register: GoWave Auto NGINX

**Document Status**: Authoritative Engineering Baseline  
**Audit Date**: November 7, 2026  
**Auditor**: Senior DevOps / Linux Infrastructure Engineer / Security Architect  
**Scope**: Codebases of `gowave` and `gowave-node`

---

## 1. Upstream Repositories, Pinned Commits & Audit Scope

| Repository | Upstream URL | Pinned Tag / Ref | Pinned Commit SHA | Commit Date | Exact Examined Scope |
|---|---|---|---|---|---|
| **GoWave** | `https://github.com/aaaSaZaN/gowave` | `v1.2.4` (tag `dev`, `main`) | `6d2c35788b3b038627b5e86e6c6486caff0851c8` | 2026-11-07 04:42:31 +0700 | `backend-go/config/`, `cmd/server/`, `internal/server/`, `internal/subscription/`, `internal/subtpl/`, `internal/configprofiles/`, `internal/nodes/`, `internal/serviceunit/`, `internal/database/`, `install.sh` |
| **GoWave Node** | `https://github.com/aaaSaZaN/gowave-node` | `v1.1.3-3-g7b3514d` | `7b3514d1ab8c674050597820d52d55525d4bece7` | 2026-11-07 04:18:09 +0700 | `cmd/gowave-node/`, `internal/config/`, `internal/tlsutil/`, `internal/auth/`, `internal/xray/`, `internal/handler/`, `internal/stats/`, `internal/updater/`, `install.sh`, `AGENTS.md` |

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
3. **Hosts Management API, Node Links & Security Layer**:
   - `gowave/backend-go/internal/server/server.go#L611-L623`: Registers `/api/hosts` endpoints (`POST`, `GET`, `PATCH`, `DELETE`).
   - `gowave/backend-go/internal/configprofiles/service.go#L38-L95`: `CreateHostInput` struct defines `Nodes []string json:"nodes"` and `InternalSquads *struct { Mode string json:"mode"; Squads []string json:"squads" } json:"internalSquads"`.
   - `gowave/backend-go/internal/configprofiles/service.go#L245-L260`: `replaceHostRelations()` records relations in `hosts_to_nodes` and `internal_squad_host_links`.
   - `gowave/backend-go/internal/configprofiles/handler.go#L458-L463`: `formatHostResponse()` normalizes `securityLayer` via switch statement: only `DEFAULT`, `TLS`, and `NONE` are valid; any other string (such as `"REALITY"`) falls back to `DEFAULT`.
   - `gowave/backend-go/internal/subtpl/resolve.go#L468-L531`: `resolveSecurity()` evaluates `host.SecurityLayer`: if `"TLS"`, forces client `security: "tls"`; if `"DEFAULT"`, inherits inbound's streamSettings security. For inbounds behind NGINX TLS termination (`security: "none"`), Host must set `"TLS"` so clients use TLS.
4. **Nodes Config Profile & Inbounds DTO Constraints**:
   - `gowave/backend-go/internal/nodes/service.go#L218-L221`: `ConfigProfile` struct defines `ActiveConfigProfileUUID string` and `ActiveInbounds []string`.
   - `gowave/backend-go/internal/nodes/service.go#L900-L971,L1020-L1025`: `createNodeInboundLinks()` checks: `if inbound.ProfileUUID != profileID { return fmt.Errorf("inbound %s does not belong to config profile %s", inbound.UUID, profileID) }`. Exactly one active Config Profile per Node; all active inbounds must belong to that profile.
   - `gowave/backend-go/internal/nodes/handler.go#L494-L515`: `UpdateWithConfigProfile()` updates active profile and inbounds, automatically triggering `StartNode()` and Xray configuration compilation.
5. **Internal Squad Membership & Inbound Credential Resolution**:
   - `gowave/backend-go/internal/nodes/service.go#L1090-L1117`: `GetUserResolvedInbounds(userID)` performs SQL join: `internal_squad_members` -> `internal_squads` -> `internal_squad_inbounds` -> `config_profile_inbounds`. Node only receives user credentials for inbounds associated with squads of which the user is a member.
   - `gowave/backend-go/internal/squads/handler.go#L139-L208`: `CreateInternalSquad` creates squad with `inbounds: []string`.
   - `gowave/backend-go/internal/users/service.go#L142-L232`: `CreateUser` accepts `ActiveInternalSquads: []string` and dispatches `syncUserToSingleNode()`.
6. **Subscription Serving & User-Agent Enforcement**:
   - `gowave/backend-go/internal/subscription/serve.go#L105-L125`: `responseRules()` enforces: `if err != nil || settings.ResponseRules == nil || userAgent == nil || *userAgent == "" { nestError(w, r, http.StatusForbidden, "Forbidden"); return nil }`. Both generic and typed clientType subscription routes invoke `responseRules()`, returning HTTP 403 when User-Agent is empty or missing.
7. **Privilege Boundary & Native Service Installation**:
   - `gowave/backend-go/internal/serviceunit/install.sh#L36-L102`: `service install` creates system user and group `gowave:gowave`, sets mode `1770 root:gowave` on `/opt/gowave`, and generates `/etc/systemd/system/gowave.service.d/90-unprivileged.conf` with `ProtectSystem=strict`, `NoNewPrivileges=true`, `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`.
   - `gowave/backend-go/internal/serviceunit/install.sh#L109-L133`: Configures `gowave-update.path` and `gowave-update.service`.
8. **Native x25519 Key Generation Endpoint**:
   - `gowave/backend-go/internal/tokens/scopes.json#L44-L48`, `internal/system/handler.go#L60-L95`: route `GET /api/system/tools/x25519/generate` requires scope `system:generate-x25519` and returns `{keypairs: [{privateKey: "...", publicKey: "..."}]}` in base64 Curve25519 format, eliminating any external `xray x25519` CLI dependency during REALITY provisioning.
9. **Granular Scoped API Tokens Endpoint**:
   - `gowave/backend-go/internal/tokens/handler.go#L35-L95`: route `POST /api/tokens` accepts `CreateTokenInput{Name, Description, Scopes, ExpiresAt}` and issues long-lived Bearer tokens for external frontends (such as `remnawave/subscription-page`) and Telegram bots without leaking administrator password.
10. **Authentication, Tokens & Session Security**:
    - `gowave/backend-go/internal/auth/handler.go#L95-L327`: Defines bootstrap registration `POST /api/auth/register`, login `POST /api/auth/login`, and status `GET /api/auth/status`.
    - `gowave/backend-go/internal/middleware/auth.go#L34-L94`: Authenticates requests via `Authorization: Bearer <accessToken>`. Validates HS256 JWT signed with `APP_SECRET`. Default TTL is 12 hours (`config/config.go#L139`). Re-login on 401 and error taxonomy documented in `API_CONTRACTS.md`.
11. **Config Profiles Service & Inbound Synchronization**:
    - `gowave/backend-go/internal/configprofiles/service.go#L419-L456,L514-L600`: `CreateProfile` and `syncInbounds` parse raw Xray config JSON, validate uniqueness of inbound tags, extract port, protocol, and stream settings, and generate relational inbound records.
    - `gowave/backend-go/internal/configprofiles/handler.go#L388-L409`: `GetComputedConfig` expands config via `configrender.Expand` and returns compiled Xray config.

### 2.2 GoWave Node (`gowave-node`)
1. **Wildcard Network Bind & Port**:
   - `gowave-node/cmd/gowave-node/main.go#L177`: `addr := fmt.Sprintf(":%d", cfg.NodePort)` binds to wildcard interfaces (`0.0.0.0` and `[::]`), confirming that loopback restriction must be enforced at the host firewall (UFW) layer.
2. **Upstream Installer & Native NODE_PORT Override**:
   - `gowave-node/install.sh#L1-L220`: Accepts `SECRET_KEY`, `NODE_PORT`, `GOWAVE_NODE_VERSION`, checks SHA256 checksums from GitHub releases, detects init systems, and installs `/etc/systemd/system/gowave-node.service`.
   - `gowave-node/install.sh#L340-L351`: Natively checks `NODE_PORT` environment variable (`[ -n "$port" ] || port=${NODE_PORT:-}`), validates numeric range (`1-65535`), checks listener collision, and writes `NODE_PORT="$port"` into `/opt/gowave-node/.env`.
   - `gowave-node/internal/config/config.go#L102-L105`: Directly reads `portStr := os.Getenv("NODE_PORT")` at startup. Hardening fallback drop-in `/etc/systemd/system/gowave-node.service.d/10-port.conf` provides additional guarantee.
3. **Node Payload & HKDF SNI**:
   - `gowave-node/internal/config/payload.go#L33-L38`: Defines `NodePayload` struct containing `caCertPem`, `jwtPublicKey`, `nodeCertPem`, `nodeKeyPem`.
   - `gowave-node/internal/config/payload.go#L59-L85`: `DeriveSni(caCertPem, jwtPublicKey)` computes SNI via HKDF-SHA256 with info `"rw-v1"`.
4. **Mutual TLS 1.3 & JWT**:
   - `gowave-node/internal/tlsutil/tls.go#L13-L42`: `SetupServerTLS` configures `MinVersion = tls.VersionTLS13`, `ClientAuth = tls.RequireAndVerifyClientCert`, and adds `caCertPem` to `ClientCAs`. If `cfg.SniVerification` is true, verifies `hello.ServerName`.
   - `gowave-node/internal/config/config.go#L101-L152`: `NODE_PORT` defaults to `3000`. `SNI_VERIFICATION` defaults to `false` (overridden to `true` by GoWave Auto NGINX).
5. **Xray-Core Supervision & Process Lifecycle**:
   - `gowave-node/internal/xray/process.go#L51-L132`: Supervised execution with ring buffer logging. Direct process management handles auto-restart on unexpected exit. **No external watchdog timer.**

### 2.3 Baseline community installer patterns
1. **NGINX Stream SNI Demultiplexing**:
   - `community-baseline/x-ui-latest.sh#L797-L825`: Public port 443 bound by NGINX Stream (`ssl_preread on; proxy_protocol on;`). SNI map routes `reality_domain` to 8443, `panel_domain` to 7443, and default/unknown to 8443.
2. **REALITY Fallback & Decoy Site**:
   - `community-baseline/assets/vision/managed.py#L73-L100`: Xray fallback sends PROXY protocol v1 (`dest: 127.0.0.1:9443, xver: 1`) to NGINX listener at 9443 (`listen 127.0.0.1:9443 ssl proxy_protocol;`) serving static camouflage HTML.
3. **Backup Preflight Validation & Security Checks**:
   - `community-baseline/assets/backup/x-ui-backup.sh#L400-L452`: Python validator inspects tar members, rejects `..`, leading `/`, symlinks pointing outside managed roots, hardlinks to non-files, device nodes, and FIFOs.
4. **CI Runner & Privilege Separation**:
   - `community-baseline/tests/run_ci.py#L12-L41,L94-L116`: Uses `--suite` with choices `nonroot`, `root`, `integration`, `services`, `systemd`, or `--check-completeness`. Enforces EUID checks before execution.
5. **Authentic Multi-Asset Decoy Camouflage**:
   - `community-baseline/assets/vision/managed.py#L73-L100`: Retains authentic multi-asset static website (`cover-reality` under `/var/www/gowave-auto-nginx/cover-reality`), providing realistic HTML, CSS, JavaScript, and image assets on loopback port 9443 rather than minimal single-file HTML stubs.

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
| 9. Compatibility Status| Debian 12 marked as     | Upstream GoWave lacks a | Refine matrix taxonomy;  | Overstating official     | Rigorous engineering claims; |
|    (P1-7)              | UPSTREAM_SUPPORTED.     | dedicated Debian 12 CI     | classify Panel/Node on   | upstream verification.   | adaptations verified via L5  |
|                        |                         | test workflows.            | Debian 12 as SOURCE_COMP.|                          | QEMU tests.                  |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 10. Container User     | Integration tests ran   | tests/run_ci.py rejects    | Run integration container| Running integration as   | Strict compliance with runner |
|     (P1-9)             | as root in container.   | EUID 0 for integration     | with --user 1001:1001    | root; disabling EUID     | runner privilege separation  |
|                        |                         | and services suites.       | enforcing EUID != 0.     | checks in runner.        | contract.                    |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 11. Unified Profile    | Create 4 separate       | updateNodeWithProfile()    | Provision ONE unified    | Linking inbounds from    | Prevents "inbound does not   |
|     (4-P0-1)           | Config Profiles for     | requires all inbounds to   | Config Profile with all 4| multiple profiles to one | belong to config profile"    |
|                        | MVP protocols.          | belong to active profile.  | inbounds in raw Xray JSON| node.                    | transaction error.           |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 12. Host Node Links    | Host payload omitted    | CreateHostInput has        | Include nodes: [uuid] in | Leaving Host unbound to  | Subscriptions correctly map  |
|     (4-P0-2)           | "nodes" array.          | Nodes []string and links   | all Host API payloads and| edge nodes.              | to worker edge endpoints.    |
|                        |                         | hosts_to_nodes table.      | verify read-back.        |                          |                              |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 13. Host Security Layer| REALITY enum used;      | formatHostResponse() allows| Use DEFAULT for REALITY; | Using invalid "REALITY"  | Correct client security:     |
|     (4-P0-3)           | DEFAULT used for TLS.   | DEFAULT, TLS, NONE; resolve| TLS for XHTTP, WS, and   | enum; using DEFAULT for  | REALITY resolves to reality; |
|                        |                         | Security() needs TLS for   | Trojan gRPC.             | NGINX TLS inbounds.      | XHTTP/WS/gRPC use TLS.       |
|                        |                         | inbounds behind NGINX.     |                          |                          |                              |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 14. Subscription UA    | UA claimed optional on  | responseRules() rejects    | Adopt Option A: require  | Assuming typed route     | Deterministic subscription   |
|     (4-P0-4)           | /api/sub/:id/:type.     | missing/empty UA with 403  | valid client UA; test    | bypasses rules; claiming | tests on pinned commit SHA;  |
|                        |                         | on pinned commit.          | missing UA as 403 test.  | unproven behavior.       | zero discrepancy.            |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 15. Squad & User Sync  | User provisioning and   | Node receives credentials  | Create managed squad with| Omitting squad creation; | User credentials sync to     |
|     (4-P0-5)           | squad lifecycle omitted.| only via internal squad    | 4 inbounds; create user  | relying on manual UI     | node for all 4 inbounds;     |
|                        |                         | membership.                | assigned to squad.       | creation without squad.  | tests pass end-to-end.       |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 16. Worker Traffic Plane| Worker script only ran  | Clients connect directly   | Implement full NGINX     | Routing client VPN data  | True edge multi-node         |
|     (4-P1-1)           | node installer.         | to Worker port 443; Worker | Stream, TLS, and routes  | through central panel;   | architecture with direct     |
|                        |                         | is the traffic plane edge. | on Worker host.          | worker without NGINX.    | client tunneling.            |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 17. NGINX HTTP/2 Syntax| Claimed Ubuntu 24.04    | Ubuntu 24.04 has NGINX     | Runtime detection:       | Hardcoding http2 on;     | Prevents fatal NGINX syntax  |
|     (4-P1-2)           | uses http2 on; syntax.  | 1.24.0 (< 1.25.1), which   | < 1.25.1 uses listen...  | on Ubuntu 24.04.         | error during configuration   |
|                        |                         | requires listen ... http2; | http2;, >= 1.25.1 http2 on|                          | compilation and reload.      |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 18. Native x25519 Keys | External xray x25519 CLI| GoWave provides GET        | Call native GET /api/    | Spawning external xray   | Eliminates external binary   |
|     (Item 1)           | binary required.        | /api/system/tools/x25519/  | system/tools/x25519/     | binary or installing     | dependency; verified in      |
|                        |                         | generate endpoint.         | generate for keys.       | separate crypto tool.    | integration test suite.      |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 19. Remote SSH Deploy  | Multi-step scp copy     | Shell functions & env can  | Use remote_payload       | scp script upload;       | Clean atomic deployment;     |
|     (Item 3)           | of script files.        | stream via SSH stdin.      | packing declare -p & -f  | leaving temporary files  | automatic cleanup; code      |
|                        |                         |                            | directly into bash stdin.| on remote worker.        | propagation verified.        |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 20. NGINX 443 Precheck | Only port socket check  | Preexisting /etc/nginx/    | Scan /etc/nginx/ for     | Allowing nginx -t to fail| Halts gracefully with clear  |
|     (Item 4)           | via ss -Hltnp.          | vhosts can listen on 443.  | unmanaged listen 443     | after modifying Stream   | warning before modifying     |
|                        |                         |                            | before Stream binding.   | configuration.           | system configuration.        |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 21. Scoped API Tokens  | External apps need panel| GoWave provides POST       | Issue scoped API token   | Sharing admin login or   | Secure external frontend and |
|     (Item 5)           | admin username/password.| /api/tokens with scopes.   | for external sub pages   | direct DB credentials    | bot integration; credentials |
|                        |                         |                            | and bots; save to 0600.  | with third-party tools.  | saved with mode 0600.        |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 22. Decoy Camouflage   | Minimal single-file HTML| Scanners easily detect     | Retain multi-asset       | Adopting minimal 1-line  | High-fidelity camouflage     |
|     (Item 2)           | stub used as decoy.     | simplistic static stubs.   | cover-reality template   | HTML stub from third-    | against DPI and scanners;    |
|                        |                         |                            | from community baseline.   | party scripts.           | verified in test suite.      |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 23. Contractual Auth   | Implicit auth flow      | GoWave requires POST       | Codify exact auth DTO,   | Uncontracted API calls;  | Deterministic login and      |
|     (AUD-01)           | without path/headers.   | /api/auth/login, Bearer    | 12h TTL, and 401 re-login| hardcoded tokens.        | token lifecycle handling;    |
|                        |                         | token, HS256 algorithm.    | policy in API_CONTRACTS. |                          | verified in test suite.      |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 24. Explicit API DTOs  | Assumed API paths       | server.go registers exact  | Document all 22 panel    | Ad-hoc payload guess;    | Clean REST integration with  |
|     (AUD-02)           | without full schemas.   | endpoints and DTO schemas. | endpoints with citations | unvalidated API calls.   | zero runtime 400 errors;     |
|                        |                         |                            | in API_CONTRACTS.md.     |                          | documented in contract.      |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 25. Reference Inbounds | Raw Xray JSON claimed   | Xray core requires valid   | Codify 4 canonical inbounds| Reconstructing JSON by  | Valid streamSettings and     |
|     (AUD-03)           | without templates.      | streamSettings/reality.    | in assets/xray/*.json +  | memory; untested config  | realitySettings guaranteed;  |
|                        |                         |                            | unified-profile.json.    | syntax.                  | verified via computed-config.|
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 26. NODE_PORT Override | Assumed unsupported or  | install.sh#L340 reads      | Use export NODE_PORT=3002| Hardcoding port 3000;    | Clean conflict-free All-in-  |
|     (AUD-04)           | unverified in node repo.| NODE_PORT; writes to .env. | + systemd drop-in        | manually modifying       | One deployment on port 3002; |
|                        |                         |                            | 10-port.conf hardening.  | upstream source files.   | zero listener collisions.    |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 27. Provision Journal  | Journal covered only    | Partial install failures   | Add PROVISIONING states  | Leaving partial state on | Safe rollback on failed      |
|     (AUD-05)           | update phase.           | leave dirty DB artifacts.  | to journal.json with     | install; unhandled setup | setup; clean re-runnable     |
|                        |                         |                            | reverse-order rollback.  | crash.                   | state machine.               |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 28. Idempotency State  | Declarative claim       | Repeat installs risk       | Codify state.json schema | Relying only on random   | Deterministic idempotency;   |
|     (AUD-06)           | without algorithm.      | duplicate entities.        | and 5-step reconciliation| names; recreating all    | adopted resources preserved; |
|                        |                         |                            | algorithm with adoption. | resources on retry.      | zero duplicate entities.     |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 29. Error Taxonomy     | No error classification | Different status codes     | Codify error matrix in   | Generic catch-all failure| Proper backoff and retry     |
|     (AUD-07)           | or retry rules.         | require distinct actions.  | API_CONTRACTS (401 reauth| ignoring rate limits and | on transient errors; fast    |
|                        |                         |                            | 429 backoff, 400 abort). | auth expiration.         | abort on payload errors.     |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 30. Subscription Assert| Empty body could pass   | Render() on nil template   | Explicit assert checklist| Status code 200 alone as | Prevents silent failure on   |
|     (AUD-08)           | test with code 200.     | returns empty string "".   | (200, len>0, proxies>=4, | test passing criterion.  | unseeded templates; verifies |
|                        |                         |                            | zero loopback leaks).    |                          | genuine subscription payload.|
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 31. Computed Config    | GET computed-config     | Expand() can produce       | Explicit 5-point checklist| curl && echo OK without  | Guarantees valid compiled    |
|     (AUD-09)           | called without asserts. | 400 error or empty config. | (4 inbounds, security,   | inspecting JSON response | Xray configuration before    |
|                        |                         |                            | reality keys, no errors).| structure.               | node binding.                |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
| 32. XHTTP Directives   | Generic description     | XHTTP requires specific    | Codify complete NGINX    | Relying on default proxy | Complete streaming without   |
|     (AUD-10)           | without directives.     | buffering & timeout rules. | location block with all  | buffering; missing       | chunk truncation or stream   |
|                        |                         |                            | 9 streaming directives.  | streaming timeouts.      | disconnects.                 |
+------------------------+-------------------------+----------------------------+--------------------------+--------------------------+------------------------------+
```
