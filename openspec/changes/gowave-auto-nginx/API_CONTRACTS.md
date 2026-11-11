# API Contracts & Integration Specification: GoWave Panel

**Document Status**: Authoritative Engineering Specification  
**Pinned Upstream Commit**: `gowave` `6d2c35788b3b038627b5e86e6c6486caff0851c8`  
**Base URL**: `http://127.0.0.1:3000` (Local Panel Loopback) / `https://<panel_domain>` (External via NGINX)  

---

## 1. Authentication & Session Lifecycle

### 1.1 Auth Status Inspection
- **Method & Path**: `GET /api/auth/status` (or `HEAD /api/auth/status`)
- **Source Reference**: `gowave/backend-go/internal/server/server.go#L511`, `internal/auth/handler.go#L95-L167`
- **Authentication**: None required.
- **Response 200 OK**:
  ```json
  {
    "response": {
      "isLoginAllowed": true,
      "isRegisterAllowed": false,
      "authentication": {
        "password": { "enabled": true },
        "passkey": { "enabled": false },
        "oauth2": { "providers": { "github": false, "generic": false } }
      },
      "branding": {
        "title": "GoWave",
        "logoUrl": null
      }
    }
  }
  ```
- **Operational Logic**:
  - If `adminCount == 0`: `isRegisterAllowed = true`, `isLoginAllowed = false`. The installer MUST invoke `POST /api/auth/register`.
  - If `adminCount > 0`: `isRegisterAllowed = false`, `isLoginAllowed = true`. The installer MUST invoke `POST /api/auth/login`.

### 1.2 Initial Administrator Registration (Bootstrap)
- **Method & Path**: `POST /api/auth/register`
- **Source Reference**: `gowave/backend-go/internal/server/server.go#L514`, `internal/auth/handler.go#L171-L242`
- **Authentication**: None required (available ONLY when database table `admin` is empty; atomic database lock prevents race conditions).
- **Request Headers**: `Content-Type: application/json`
- **Request Body DTO**:
  ```json
  {
    "username": "admin",
    "password": "<min-8-chars-password>"
  }
  ```
- **Response 200 OK**:
  ```json
  {
    "response": {
      "accessToken": "<jwt-hs256-bearer-token>"
    }
  }
  ```
- **Response 400 Bad Request**: `{"message":"Username is required and password must be at least 8 characters"}`
- **Response 403 Forbidden**: `{"message":"Registration is disabled because an admin already exists"}` (triggers fallback to `POST /api/auth/login`).
- **Response 500 Internal Server Error**: `{"message":"Failed to create admin"}`

### 1.3 Administrator Login
- **Method & Path**: `POST /api/auth/login`
- **Source Reference**: `gowave/backend-go/internal/server/server.go#L513`, `internal/auth/handler.go#L278-L327`
- **Authentication**: None required.
- **Request Headers**: `Content-Type: application/json`
- **Request Body DTO**:
  ```json
  {
    "username": "admin",
    "password": "<admin-password>"
  }
  ```
- **Response 200 OK**:
  ```json
  {
    "response": {
      "accessToken": "<jwt-hs256-bearer-token>"
    }
  }
  ```
- **Response 400 Bad Request**: `{"code":"E000","message":"username and password are required"}`
- **Response 403 Forbidden**: `{"code":"A068","message":"Forbidden"}` (invalid password or password auth disabled).
- **Response 500 Internal Server Error**: `{"code":"A067","message":"Get auth status error"}`

### 1.4 Token Format, Header & TTL
- **Header Format**: `Authorization: Bearer <accessToken>`
- **Source Reference**: `gowave/backend-go/internal/middleware/auth.go#L34-L47`
- **Signature Algorithm**: HMAC-SHA256 (`HS256`), signed with `APP_SECRET` from `/opt/gowave/.env`.
- **Token Claims**: `{"uuid": "<admin-uuid>", "username": "admin", "role": "ADMIN", "exp": <unix-timestamp>}`.
- **Token TTL**: 12 hours (default `jwtLifetime := 12` from `gowave/backend-go/config/config.go#L139`).
- **401 Unauthorized Handling Protocol**:
  1. If any protected API call returns HTTP 401 Unauthorized (`{"error":"Unauthorized"}`), the client library captures the 401.
  2. The client invokes `POST /api/auth/login` exactly once using the stored administrative credentials.
  3. If login succeeds, the new `accessToken` replaces the expired token in memory and the failed request is retried once.
  4. If the re-login fails or the retried request returns 401 again, execution terminates immediately with exit code 1.

---

## 2. Protected Provisioning Endpoints Matrix

All endpoints below require header `Authorization: Bearer <accessToken>` unless specified otherwise.

| Operation | Method & Path | Source Citation (6d2c357) | Request Body DTO | Response 2xx DTO | Response Error Codes | Idempotency & Reconciliation Policy |
|---|---|---|---|---|---|---|
| **Generate x25519 Keys** | `GET /api/system/tools/x25519/generate` | `server.go#L690`, `system/handler.go#L60-L95`, `tokens/scopes.json#L44` | *None* | `200 OK`:<br>`{"response": {"keypairs": [{"privateKey": "<b64>", "publicKey": "<b64>"}]}}` | `401 Unauthorized`<br>`403 Forbidden` | Read-only tool. Can be invoked repeatedly; generates unique keypair on each call. |
| **List Config Profiles** | `GET /api/config-profiles` | `server.go#L628`, `configprofiles/handler.go#L200-L218` | *None* | `200 OK`:<br>`{"response": {"configProfiles": [{"uuid": "...", "name": "...", "viewPosition": 1, ...}]}}` | `401 Unauthorized` | Read-only. Used by installer to detect existing managed profile by `name == "GoWave MVP Unified Profile"`. |
| **Create Config Profile** | `POST /api/config-profiles` | `server.go#L629`, `configprofiles/handler.go#L220-L257`, `service.go#L419-L456` | `{"name": "GoWave MVP Unified Profile", "config": { ... raw Xray JSON ... }}` | `201 Created`:<br>`{"response": {"uuid": "<profile-uuid>", "name": "...", "inbounds": [...]}}` | `400 Bad Request`<br>`409 Conflict` (name exists) | If 409 Conflict or profile exists, adopt existing profile UUID via `GET /api/config-profiles` and update via `PATCH`. |
| **Get Profile Inbounds** | `GET /api/config-profiles/{uuid}/inbounds` | `server.go#L635`, `configprofiles/handler.go#L351-L368` | *None* | `200 OK`:<br>`{"response": {"total": 4, "inbounds": [{"uuid": "<ib-uuid>", "tag": "vless-reality-local-node", "protocol": "vless", "port": 8443, ...}]}}` | `401 Unauthorized`<br>`404 Not Found` | Deterministically returns the 4 parsed inbound UUIDs generated by GoWave's `syncInbounds()`. |
| **Get Computed Config** | `GET /api/config-profiles/{uuid}/computed-config` | `server.go#L636`, `configprofiles/handler.go#L388-L409` | *None* | `200 OK`:<br>`{"response": {"uuid": "...", "name": "...", "config": "<expanded-xray-json-string>"}}` | `400 Bad Request` (expansion error)<br>`404 Not Found` | Validation gate. Installer parses `response.config` JSON and verifies all 4 inbounds compile without error before node binding. |
| **Update Config Profile** | `PATCH /api/config-profiles/{uuid}` | `server.go#L632`, `configprofiles/handler.go#L280-L330`, `service.go#L458-L503` | `{"name": "...", "config": { ... raw Xray JSON ... }}` | `200 OK`:<br>`{"response": {"uuid": "...", ...}}` | `400 Bad Request`<br>`404 Not Found` | Replaces Xray config and resyncs inbounds idempotently via `syncInbounds(tx, uuid, bytes, false)`. |
| **Delete Config Profile** | `DELETE /api/config-profiles/{uuid}` | `server.go#L633`, `configprofiles/service.go#L505-L512` | *None* | `200 OK` / `204 No Content` | `404 Not Found` | Used strictly during automated rollback if subsequent provisioning steps fail. |
| **Create Node** | `POST /api/nodes` | `server.go#L593`, `nodes/handler.go#L359-L375`, `nodes/service.go#L215-L260` | `{"name": "node-1", "address": "127.0.0.1", "port": 3002, "configProfile": {"activeConfigProfileUuid": "<p-uuid>", "activeInbounds": ["<ib1>", "<ib2>", "<ib3>", "<ib4>"]}}` | `201 Created`:<br>`{"response": {"uuid": "<node-uuid>", "name": "...", ...}}` | `400 Bad Request` (inbound cross-profile error)<br>`409 Conflict` | Links single active profile and all 4 inbound UUIDs. All inbounds MUST belong to the active profile. Inbound tags are deterministically node-scoped (`*-<node-name>`) due to GoWave's global UNIQUE index `idx_config_profile_inbounds_tag`. Enforces database UNIQUE constraint on `nodes.address` (`UNIQUE(address)`); each registered node must have a unique host address. |
| **Update / Bind Node** | `PATCH /api/nodes/{uuid}` | `server.go#L599`, `nodes/handler.go#L402-L525` | `{"configProfile": {"activeConfigProfileUuid": "<p-uuid>", "activeInbounds": ["<ib1>", "<ib2>", "<ib3>", "<ib4>"]}}` | `200 OK`:<br>`{"response": {"uuid": "...", ...}}` | `400 Bad Request`<br>`404 Not Found` | Updates active profile and inbounds, automatically triggering node reconfiguration and Xray restart. |
| **List Internal Squads** | `GET /api/internal-squads` | `server.go#L638`, `squads/handler.go#L100-L135` | *None* | `200 OK`:<br>`{"response": {"internalSquads": [{"uuid": "...", "name": "Default MVP Squad", "inbounds": [...]}]}}` | `401 Unauthorized` | Used to detect existing squad by `name == "Default MVP Squad"`. |
| **Create Internal Squad** | `POST /api/internal-squads` | `server.go#L639`, `squads/handler.go#L139-L160` | `{"name": "Default MVP Squad", "inbounds": ["<ib1>", "<ib2>", "<ib3>", "<ib4>"]}` | `201 Created`:<br>`{"response": {"uuid": "<squad-uuid>", "name": "Default MVP Squad", "inbounds": [...]}}` | `400 Bad Request`<br>`409 Conflict` | Links all 4 MVP inbounds to squad. If already exists, adopt UUID and update via PATCH. |
| **Update Internal Squad** | `PATCH /api/internal-squads` | `server.go#L640`, `squads/handler.go#L162-L188` | `{"uuid": "<squad-uuid>", "name": "Default MVP Squad", "inbounds": ["<ib1>", "<ib2>", ...]}` | `200 OK`:<br>`{"response": {"uuid": "<squad-uuid>", "name": "...", "inbounds": [...]}}` | `400 Bad Request`<br>`404 Not Found` | Updates squad inbounds and name (`UpdateInternalSquadCommand`). Note that UUID is passed in payload body, not URL path (path-based PATCH returns 405 Method Not Allowed). |
| **Delete Internal Squad** | `DELETE /api/internal-squads/{uuid}` | `server.go#L642`, `squads/handler.go#L190-L210` | *None* | `200 OK` / `204 No Content` | `404 Not Found` | Used strictly during automated rollback if subsequent provisioning steps fail. |
| **List Hosts** | `GET /api/hosts` | `server.go#L611`, `configprofiles/handler.go#L560-L588` | *None* | `200 OK`:<br>`{"response": {"hosts": [{"uuid": "...", "remark": "VLESS-REALITY-Vision@local-node", "address": "...", ...}]}}` | `401 Unauthorized` | Queries existing Host entities, matching by `remark` to adopt UUIDs. |
| **Create Host** | `POST /api/hosts` | `server.go#L612`, `configprofiles/handler.go#L590-L614`, `service.go#L38-L95` | Full Host DTO (see Section 2.1) | `201 Created`:<br>`{"response": {"uuid": "<host-uuid>", "remark": "...", "nodes": ["<node-uuid>"], ...}}` | `400 Bad Request`<br>`500 Server Error` | Creates Host record. One Host entity created per MVP protocol (4 total). |
| **Update Host** | `PATCH /api/hosts` | `server.go#L613`, `configprofiles/handler.go#L633-L670` | `{"uuid": "<host-uuid>", ...}` (subset of Host DTO fields) | `200 OK`:<br>`{"response": { ... updated host ... }}` | `400 Bad Request`<br>`404 Not Found` | Updates existing Host record in place (`UpdateHostCommand`). Note that UUID is passed in payload body, not URL path (path-based PATCH returns 405 Method Not Allowed). |
| **Delete Host** | `DELETE /api/hosts/{uuid}` | `server.go#L614`, `configprofiles/handler.go#L680-L700` | *None* | `200 OK` / `204 No Content` | `404 Not Found` | Used strictly during automated rollback if provisioning fails. |
| **Create User** | `POST /api/users` | `server.go#L554`, `users/handler.go#L120-L170`, `users/service.go#L142-L232` | `{"username": "default-user", "status": "ACTIVE", "trafficLimitStrategy": "NO_RESET", "expireAt": "2099-01-01T00:00:00.000Z", "activeInternalSquads": ["<squad-uuid>"]}` | `201 Created`:<br>`{"response": {"uuid": "<user-uuid>", "username": "default-user", "shortUuid": "<nanoid>", "status": "ACTIVE", ...}}` | `400 Bad Request`<br>`409 Conflict` (username exists) | Automatically triggers `syncUserToSingleNode()` for all squad inbounds. `expireAt` is mandatory per OpenAPI schema. |
| **Get User by Username** | `GET /api/users/by-username/{username}` | `server.go#L581`, `users/handler.go#L450-L480` | *None* | `200 OK`:<br>`{"response": {"uuid": "...", "username": "...", "shortUuid": "<nanoid>", ...}}` | `404 Not Found` | Retrieves existing user and extracts `shortUuid` if user was already provisioned. |
| **Create Scoped API Token** | `POST /api/tokens` | `server.go#L673`, `tokens/handler.go#L35-L95` | `{"name": "gowave-auto-nginx token", "scopes": ["subscription-page-configs:list", "subscription-page-configs:get", "subscriptions:subpage-config", "system:metadata", "users:by-username"], "expiresAt": null}` | `201 Created`:<br>`{"response": {"uuid": "<token-uuid>", "token": "<bearer-token>", ...}}` | `400 Bad Request` | Issues long-lived token for external web subscription pages and Telegram bots. |

---

### 2.1 Complete Host Entity Request DTO

The request payload for `POST /api/hosts` MUST strictly follow this exact structure:

```json
{
  "inbound": {
    "configProfileUuid": "<single-profile-uuid>",
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
  "fingerprint": "chrome",
  "securityLayer": "DEFAULT",
  "internalSquads": {
    "mode": "ALLOW_ONLY",
    "squads": ["<squad-uuid>"]
  },
  "isDisabled": false,
  "isHidden": false,
  "overrideSniFromAddress": false,
  "keepSniBlank": false
}
```

#### Protocol-Specific Field Matrix for `POST /api/hosts`

| Field | VLESS REALITY Vision | VLESS XTLS Vision | VLESS XHTTP TLS | VLESS WebSocket TLS | Trojan gRPC TLS |
|---|---|---|---|---|---|
| `remark` | `"VLESS-REALITY-Vision@<node-name>"` | `"VLESS-Vision-TLS@<node-name>"` | `"VLESS-XHTTP-TLS@<node-name>"` | `"VLESS-WS-TLS@<node-name>"` | `"Trojan-gRPC-TLS@<node-name>"` |
| `address` | `<public_fqdn_or_ip>` | `<vision_domain_or_panel_fqdn>` | `<public_fqdn_or_ip>` | `<public_fqdn_or_ip>` | `<public_fqdn_or_ip>` |
| `port` | `443` | `443` | `443` | `443` | `443` |
| `sni` | `<reality_camouflage_sni>` (Mode A: `cdn.example.com`; Mode B: `gateway.icloud.com`) | `<vision_domain_or_panel_domain>` | `<panel_or_worker_domain>` | `<panel_or_worker_domain>` | `<panel_or_worker_domain>` |
| `path` | `null` | `null` | `"/xhttp-down/"` | `"/ws"` | `"trojan-grpc"` |
| `host` | `null` | `null` | `"<panel_or_worker_domain>"` | `"<panel_or_worker_domain>"` | `null` |
| `alpn` | `"h2,http/1.1"` | `"http/1.1"` | `"h2,http/1.1"` | `"http/1.1"` | `"h2"` |
| `fingerprint`| `"chrome"` | `"firefox"` | `"firefox"` | `"firefox"` | `"firefox"` |
| `securityLayer` | `"DEFAULT"` | `"TLS"` | `"TLS"` | `"TLS"` | `"TLS"` |
| `nodes` | `["<node-uuid>"]` | `["<node-uuid>"]` | `["<node-uuid>"]` | `["<node-uuid>"]` | `["<node-uuid>"]` |
| `internalSquads` | `{"mode": "ALLOW_ONLY", "squads": ["<squad-uuid>"]}` | `{"mode": "ALLOW_ONLY", "squads": ["<squad-uuid>"]}` | `{"mode": "ALLOW_ONLY", "squads": ["<squad-uuid>"]}` | `{"mode": "ALLOW_ONLY", "squads": ["<squad-uuid>"]}` | `{"mode": "ALLOW_ONLY", "squads": ["<squad-uuid>"]}` |

---

## 3. Error Handling Taxonomy & Retry Policy

| HTTP Status Code | Classification | Action | Retry Strategy | Rollback Trigger |
|---|---|---|---|---|
| **`400 Bad Request`** / **`422 Unprocessable`** | Client Payload Error | Abort immediately. Log request payload and response error message. | Non-retryable (fail fast). | Immediate trigger of `PROVISION_ROLLBACK`. |
| **`401 Unauthorized`** | Authentication Expired | Capture 401; invoke `POST /api/auth/login` with stored admin credentials to obtain fresh token; retry original call. | Re-login exactly once. If 401 recurs, abort. | If re-login fails, trigger `PROVISION_ROLLBACK`. |
| **`403 Forbidden`** | Scope / Permission Error | Log error description (`A068` / scope missing). Abort execution. | Non-retryable. | Immediate trigger of `PROVISION_ROLLBACK`. |
| **`404 Not Found`** | Resource Missing | On `GET`: indicates resource absent (proceed to create). On `PATCH`/`DELETE`: resource gone. | Non-retryable. | If unexpected during update, trigger rollback. |
| **`409 Conflict`** | Resource Exists | Extract existing resource identifier or query resource via `GET` to adopt its UUID; switch from `POST` to `PATCH`. | Non-retryable. Adopt existing resource rather than failing. | None (successful adoption). |
| **`429 Too Many Requests`** | Rate Limiting | Pause execution with exponential backoff and retry. | Max 3 attempts: wait 2s, 4s, 8s. | If 3 attempts exhausted, trigger rollback. |
| **`500 Internal Error`** / **`502 Bad Gateway`** / **`503 Service Unavailable`** / **`504 Gateway Timeout`** / **Connection Reset** | Transient Daemon Failure | Verify daemon health via systemd; pause and retry request. | Exponential backoff: initial 1s, factor 2, max 3 attempts (1s, 2s, 4s). | If 3 attempts exhausted, enter `PROVISION_FAILED` and trigger rollback. |

---

## 4. Algorithmic Idempotency & State Reconciliation

### 4.1 Schema of `/var/lib/gowave-auto-nginx/state.json`

The file is written with mode `0600` owned by `root:root`:

```json
{
  "schemaVersion": 2,
  "panelDomain": "panel.example.com",
  "localRealityDomain": "cdn.example.com",
  "nodes": [
    {
      "name": "local-node",
      "uuid": "018d9f12-3456-7890-abcd-ef012345678e",
      "port": 3002,
      "realityDomain": "cdn.example.com",
      "profile": {
        "name": "GoWave MVP Unified Profile - local-node",
        "uuid": "018d9f12-3456-7890-abcd-ef0123456789",
        "inbounds": {
          "vless-reality": "018d9f12-3456-7890-abcd-ef012345678a",
          "vless-xhttp": "018d9f12-3456-7890-abcd-ef012345678b",
          "vless-ws": "018d9f12-3456-7890-abcd-ef012345678c",
          "trojan-grpc": "018d9f12-3456-7890-abcd-ef012345678d"
        }
      },
      "hosts": {
        "vless-reality": "018d9f12-3456-7890-abcd-ef0123456790",
        "vless-xhttp": "018d9f12-3456-7890-abcd-ef0123456791",
        "vless-ws": "018d9f12-3456-7890-abcd-ef0123456792",
        "trojan-grpc": "018d9f12-3456-7890-abcd-ef0123456793"
      }
    }
  ],
  "managedSquad": {
    "name": "Default MVP Squad",
    "uuid": "018d9f12-3456-7890-abcd-ef012345678f"
  },
  "defaultUser": {
    "username": "default-user",
    "uuid": "018d9f12-3456-7890-abcd-ef0123456794",
    "shortUuid": "ab12cd34"
  },
  "apiToken": {
    "name": "gowave-auto-nginx subscription-page token",
    "uuid": "018d9f12-3456-7890-abcd-ef0123456795",
    "issuedAt": "2026-11-07T21:00:00Z"
  },
  "congestionControl": "bbr",
  "lastReconciledAt": "2026-11-07T21:00:00Z"
}
```

#### Mandatory Field Constraints in `state.json`:
- `nodes[].port` (integer, mandatory): the mTLS control plane listener port for the node. Defaults to `3002` for both local node and worker edge nodes. On any single host, `port` must be unique to prevent socket collisions.
- `congestionControl` (string, mandatory): either `"bbr"` or `"cubic"` (fallback when `tcp_bbr` kernel module is unavailable).

### 4.2 Schema and Integrity Verification of `journal.json`
Before executing crash recovery via `gowave-recover.service` or `gowave-recover-provision.service`, the orchestrator validates `/var/lib/gowave-auto-nginx/recovery/journal.json`:
- Must be valid JSON containing mandatory fields: `op` (one of `"provision"`, `"update"`, `"node_add"`), `state` (string matching transaction taxonomy), `timestamp` (ISO-8601).
- If `journal.json` is corrupted, truncated, or invalid, automated recovery halts with a fatal alert, initiates a read-only audit against GoWave Panel API (`GET /api/nodes`, `GET /api/config-profiles`, `GET /api/hosts`), and prompts the operator for manual confirmation (`gowave-auto.sh recover --force-reconcile`).

### 4.3 Reconciliation & Adoption Algorithm

```mermaid
flowchart TD
    start[Start Provisioning / Reconciliation] --> loadState[Load /var/lib/gowave-auto-nginx/state.json]
    loadState --> stateCheck{File Exists & Valid JSON?}
    stateCheck -- No / Corrupt --> backupCorrupt[Backup to state.json.corrupt.<ts> & Init Empty Cache]
    stateCheck -- Yes --> cacheLoaded[Cache Loaded]
    backupCorrupt --> cacheLoaded
    
    cacheLoaded --> authAdmin[Authenticate Admin Session via POST /api/auth/login]
    authAdmin --> syncProfile[Reconcile Config Profile]
    
    syncProfile --> queryProfiles[GET /api/config-profiles: Match name 'GoWave MVP Unified Profile']
    queryProfiles --> profileExists{Profile Found?}
    profileExists -- Yes --> adoptProfile[Adopt UUID & Inbound UUIDs; PATCH if config changed]
    profileExists -- No --> createProfile[POST /api/config-profiles with unified Xray config]
    adoptProfile --> verifyComputed[Validate GET /api/config-profiles/{uuid}/computed-config]
    createProfile --> verifyComputed
    
    verifyComputed --> syncNode[Reconcile Node: Bind activeConfigProfileUuid & activeInbounds]
    syncNode --> syncSquad[Reconcile Squad: GET /api/internal-squads -> POST / PATCH]
    syncSquad --> syncHosts[Reconcile Hosts: GET /api/hosts -> Match remarks -> POST / PATCH]
    syncHosts --> syncUser[Reconcile User: GET /api/users/by-username/default-user -> POST if absent]
    syncUser --> syncToken[Reconcile API Token: POST /api/tokens if not in state.json]
    syncToken --> atomicWrite[Atomically Write state.json: .tmp + fsync + rename]
    atomicWrite --> complete[Reconciliation Succeeded]
```

#### Safe Atomic State Persistence Contract
```bash
atomic_write_state() {
    local target="/var/lib/gowave-auto-nginx/state.json"
    local dir="/var/lib/gowave-auto-nginx"
    local temp="${dir}/state.json.tmp.$$"
    mkdir -p "$dir"
    printf '%s\n' "$STATE_JSON" > "$temp"
    chmod 0600 "$temp"
    sync -d "$temp" 2>/dev/null || sync "$temp"
    mv -f "$temp" "$target"
    # Fsync containing directory so directory entries survive unexpected power cuts
    python3 -c "import os; d=os.open('$dir', os.O_RDONLY|os.O_DIRECTORY); os.fsync(d); os.close(d)" 2>/dev/null || sync -d "$dir" 2>/dev/null || sync
}
```
If interrupted at any point, `state.json` is never left truncated or corrupt.

---

## 5. Worker Node Provisioning Contract & CLI Interface (`gowave-auto.sh node add`)

### 5.1 CLI Command Specification
```bash
gowave-auto.sh node add <node-name> <node-ip> <worker-domain> <reality-domain> [ssh-user] [ssh-port]
```

### 5.2 Registration Protocol Flow
1. **Admin Authentication**:
   - `POST /api/auth/login` with stored admin credentials to obtain an active JWT bearer token.
2. **Dedicated Worker Config Profile Creation**:
   - `POST /api/config-profiles` creates `"GoWave Worker <node-name> Profile"` with `realitySettings.serverNames: ["<reality-domain>"]`, native x25519 keypair, random 8-byte shortIds, and loopback SSRF blocking rules in `routing`.
   - Fetches inbound UUIDs via `GET /api/config-profiles/{uuid}/inbounds`.
3. **Node Creation in Panel**:
   - `POST /api/nodes` with payload linking the worker profile and its 4 active inbounds:
     ```json
     {
       "name": "<node-name>",
       "address": "<node-ip>",
       "port": 3002,
       "configProfile": {
         "activeConfigProfileUuid": "<worker-profile-uuid>",
         "activeInbounds": [
           "<worker-inbound-1>",
           "<worker-inbound-2>",
           "<worker-inbound-3>",
           "<worker-inbound-4>"
         ]
       }
     }
     ```
   - Receives `response.uuid` identifying the newly registered worker node.
4. **Squad Inbound Association**:
   - `PATCH /api/internal-squads` with `{"uuid": "<squad-uuid>", "name": "Default MVP Squad", "inbounds": [...]}` appends the 4 worker inbound UUIDs to `inbounds` array, ensuring users in the squad receive credentials on the worker node.
5. **Secret Key Extraction**:
   - Executes `./gowave-server rescue --print-secret-key-raw` or fetches credentials payload to extract `SECRET_KEY` (`caCertPem`, `jwtPublicKey`, `nodeCertPem`, `nodeKeyPem`).
6. **Host Entity Creation**:
   - Issues `POST /api/hosts` for each of the 4 transport profiles using canonical remarks `<PROTO>@<node-name>`:
     - REALITY: `remark: "VLESS-REALITY-Vision@<node-name>"`, `address: "<worker-domain>"`, `sni: "<reality-domain>"`, `port: 443`, `securityLayer: "DEFAULT"`, `"nodes": ["<node-uuid>"]`, `"internalSquads"` policy.
     - XHTTP, WS, Trojan gRPC: `remark: "<PROTO>@<node-name>"`, `address: "<worker-domain>"`, `port: 443`, `securityLayer: "TLS"`, `"nodes": ["<node-uuid>"]`, `"internalSquads"` policy.
7. **Zero-Leak Remote Worker Deployment via Canonical `remote_payload`**:
   - Dispatches configuration over SSH stdin (zero secrets in `argv`):
     ```bash
     PANEL_IP="$PANEL_IP" PANEL_IPV6="${PANEL_IPV6:-}" NODE_PORT="${NODE_PORT:-3002}" SECRET_KEY="$SECRET_KEY" \
     GOWAVE_NODE_VERSION=latest ADMIN_EMAIL="$ADMIN_EMAIL" \
       remote_payload "$node_ip" "${ssh_port:-22}" "$worker_domain" "$reality_domain" "${ssh_user:-root}"
     ```
   - Worker node validation: If `$node_ip` matches `$PANEL_IP` or `127.0.0.1`, `gowave-auto.sh node add` enforces `NODE_PORT=3002` (and logs a warning if port 3000 was requested) to eliminate port collisions with the Central Panel API.
   - The remote runner executes via `bash -s` from stdin, runs `main() </dev/null` preventing stdin theft, applies UFW rule (`ufw allow from $PANEL_IP to any port ${NODE_PORT:-3002} proto tcp`), sets up NGINX Stream 443, obtains Let's Encrypt certificates for both `$WORKER_DOMAIN` and `$REALITY_DOMAIN`, installs `gowave-node`, unsets `SECRET_KEY`, and initiates daemon supervision.
8. **State Persistence**:
   - Appends node entry into `/var/lib/gowave-auto-nginx/state.json` via `atomic_write_state()`.

### 5.3 Provisioning Rollback & Resource Deletion Contracts

#### 5.3.1 Initial Panel Provisioning Rollback Contract (`PROVISION_*`)
Every API mutation is written to the transaction journal immediately after the API response using an action ledger entry:

```json
{"type":"profile","uuid":"<uuid>","action":"created"}
{"type":"node","uuid":"<uuid>","action":"updated","before":{"name":"...","address":"...","port":3002,"configProfile":{}}}
{"type":"user","uuid":"<uuid>","action":"adopted"}
```

Rollback traverses the ledger in reverse order:
- `created`: delete only that UUID using the corresponding resource endpoint.
- `updated`: PATCH the stored `before` image to restore pre-transaction state.
- `adopted`: preserve the pre-existing resource; do not delete or modify it during rollback.

The journal is validated before rollback. A missing or incomplete `before` image, unknown action/type, missing UUID, or legacy UUID-only journal causes a non-destructive `PROVISION_ROLLBACK_REQUIRED` result. The implementation MUST NOT perform global name scans or delete shared resources based only on names. An empty PREPARED ledger is safe to close as rolled back because no API mutations were recorded.

#### 5.3.2 Worker Node Addition Rollback Contract (`NODE_ADD_*`)
The Panel-side API transaction uses the same action-aware ledger. It may delete newly created Worker hosts/node/profile, restore a pre-existing resource that was updated, and preserve adopted shared resources (including the default squad). Failure of remote SSH deployment triggers Panel API rollback and records whether that rollback completed.

**Compensating Remote Worker Rollback:** if a Worker deployment fails during or after host-level mutations have begun (packages, UFW, NGINX, certificates, swap, or systemd), automated compensation is triggered both in-process on the remote host via `ERR` trap (`compensate_remote_worker`) and from the Panel orchestrator via SSH stdin streaming (`gowave-node-auto.sh remote_rollback`). The compensating workflow stops and disables `gowave-node` and `xray` units, removes `/etc/systemd/system/gowave-node.service.d`, purges `/opt/gowave-node` and `/run/gowave-node`, deletes Worker NGINX vhosts and stream blocks, reloads NGINX, deletes Certbot ACME certificates, reverts UFW rules or disables UFW if inactive prior to deployment, deactivates and unmounts `/swapfile`, and removes sysctl configuration. Panel API entity rollback runs concurrently according to the action-aware ledger.

`NODE_ADD_ROLLBACK_REQUIRED` is retained when any API compensation step fails; the command returns non-zero and leaves the journal for operator reconciliation.
