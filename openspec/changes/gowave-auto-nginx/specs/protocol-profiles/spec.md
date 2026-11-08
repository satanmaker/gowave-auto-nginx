# Spec Delta: Protocol Profiles

## Purpose

Defines the configuration standards, GoWave API provisioning lifecycle, transport parameters, Host record entities, deterministic per-user subscription links (Xray and Mihomo), and verification scenarios for the 4 native VPN transport profiles supported in the MVP release.

## ADDED Requirements

### Requirement: Native VLESS REALITY Vision Profile
The system SHALL support VLESS with REALITY security and XTLS-Vision flow (`xtls-rprx-vision`) routed through NGINX Stream port 443 into Xray port 8443.

#### Scenario: VLESS REALITY Vision tunnel establishment
- **GIVEN** a client configured with VLESS REALITY Vision parameters
- **WHEN** the client initiates a connection to port 443 with `reality_domain` SNI and valid REALITY public key
- **THEN** Xray authenticates the handshake and establishes an encrypted VPN tunnel with Vision flow without requiring Let's Encrypt certificates.

#### Scenario: Native cryptographic x25519 keypair generation via GoWave REST API
- **GIVEN** an active GoWave Panel REST API instance with valid admin authorization
- **WHEN** the installer requests key generation via `GET /api/system/tools/x25519/generate`
- **THEN** GoWave returns HTTP 200 with a valid Curve25519 keypair containing `privateKey` and `publicKey` in base64 format, which are directly embedded into the REALITY inbound configuration without external binary execution.

### Requirement: Native VLESS XHTTP TLS Profile
The system SHALL support VLESS over XHTTP (splitHTTP) transport multiplexed behind the main panel domain TLS termination on port 7443.

#### Scenario: VLESS XHTTP TLS data transfer
- **GIVEN** a client configured with VLESS XHTTP parameters matching `panel_domain` and `<xhttp_path>`
- **WHEN** the client sends uplink packets via HTTP POST
- **THEN** NGINX terminates TLS on 7443 and streams the data to Xray port 10001 without chunk buffering or request body truncation, backed by kernel PLPMTUD (`net.ipv4.tcp_mtu_probing = 1`) preventing packet drops on non-standard MTU networks.

### Requirement: Native VLESS WebSocket TLS Profile
The system SHALL support VLESS over WebSocket transport with TLS encryption for maximum CDN and proxy compatibility.

#### Scenario: VLESS WebSocket TLS connection
- **GIVEN** a client configured with VLESS WebSocket parameters matching `panel_domain` and `<ws_path>`
- **WHEN** the client negotiates a WebSocket connection via port 443
- **THEN** NGINX terminates TLS on 7443 and upgrades the TCP connection to Xray port 10002.

### Requirement: Native Trojan gRPC TLS Profile
The system SHALL support Trojan protocol over gRPC transport with TLS multiplexed behind `panel_domain`.

#### Scenario: Trojan gRPC TLS handshake
- **GIVEN** a client configured with Trojan gRPC parameters and valid user password
- **WHEN** the client sends gRPC calls over HTTP/2 to the Trojan service path
- **THEN** NGINX routes gRPC frames to Xray port 10003 and authenticates user traffic.

### Requirement: Optional Native VLESS XTLS Vision Profile
The system SHALL support an optional VLESS with direct XTLS-Vision flow (`xtls-rprx-vision`) routed through NGINX Stream port 443 into Xray port 8444 when a dedicated 3rd domain/subdomain (`vision_domain`) is provided.

#### Scenario: Optional VLESS XTLS Vision provisioning with 3rd domain
- **GIVEN** a deployment invocation with a valid `vision_domain`
- **WHEN** provisioning executes
- **THEN** Let's Encrypt issues certificates for `vision_domain`, Xray terminates TLS on port 8444 with `acceptProxyProtocol: true`, NGINX stream multiplexes `vision_domain` to 8444, non-VLESS HTTP fallback routes to loopback 9444, and a 5th inbound and Host record are provisioned.

#### Scenario: Default provisioning without optional Vision
- **GIVEN** a deployment invocation without `vision_domain`
- **WHEN** provisioning executes
- **THEN** exactly 4 core inbounds (`vless-reality`, `vless-xhttp`, `vless-ws`, `trojan-grpc`) and 4 Host records are provisioned, skipping Vision certificate acquisition, stream route, and fallback vhost.

### Requirement: Automated Profile Provisioning via GoWave API
The installer SHALL provision the protocol profiles (4 core profiles by default; 5 profiles when optional Vision is enabled with a dedicated 3rd domain) by creating a single unified Config Profile via `POST /api/config-profiles`, associating the profile and its inbounds to active nodes, and verifying `GET /api/config-profiles/{uuid}/computed-config`.

#### Scenario: Single unified Config Profile provisioning with 5 inbounds
- **GIVEN** a newly installed GoWave Panel and registered Node
- **WHEN** the provisioning script executes
- **THEN** it creates one managed Config Profile embedding all 5 inbounds with unique node-scoped tags (`*-<node-name>`), `acceptProxyProtocol: true` strictly on REALITY 8443 and Vision 8444, outbound routing rules blocking loopback and cloud metadata, and random shortIds, retrieves the 5 generated inbound UUIDs, links them to the Node, and verifies the compiled Xray config via `GET /api/config-profiles/{uuid}/computed-config`.

#### Scenario: Cross-profile inbound association rejection (negative test)
- **GIVEN** an active GoWave Node associated with a primary Config Profile
- **WHEN** an API request attempts to link an inbound UUID belonging to a different Config Profile into `configProfile.activeInbounds`
- **THEN** GoWave rejects the transaction with an error indicating the inbound does not belong to the active config profile, and leaves the Node's active profile and inbounds unmutated.

### Requirement: Managed Internal Squad and User Lifecycle Provisioning
The system SHALL manage user inbound access and credential propagation through GoWave Internal Squads, linking all 5 MVP inbound UUIDs to a managed squad and provisioning an active user assigned to this squad.

#### Scenario: Automated Internal Squad creation linking all MVP inbounds
- **GIVEN** a provisioned unified Config Profile with 5 inbound UUIDs
- **WHEN** Internal Squad provisioning executes
- **THEN** `POST /api/internal-squads` creates a managed squad containing all 5 inbound UUIDs, and read-back via `GET /api/internal-squads/{uuid}` confirms the squad and its inbound associations.

#### Scenario: Initial active user provisioning and squad assignment
- **GIVEN** an active GoWave Panel with a managed Internal Squad
- **WHEN** user provisioning executes via `POST /api/users` with mandatory `expireAt` timestamp and `activeInternalSquads` containing the managed squad UUID
- **THEN** GoWave creates the user with status `ACTIVE`, assigns a random nanoid `shortUuid`, and emits `user.created`.

#### Scenario: User credential sync to Node for all active inbounds
- **GIVEN** a newly created active user assigned to the managed Internal Squad
- **WHEN** GoWave's user synchronization worker executes `syncUserToSingleNode()`
- **THEN** GoWave resolves all 5 inbounds for the user via squad membership and dispatches the user's VLESS UUID and Trojan password to `gowave-node`, enabling client authentication across all 5 inbounds.

### Requirement: Automatic GoWave Host Record Provisioning
For each provisioned MVP protocol profile, the provisioning system SHALL automatically create and verify a corresponding Host entity via GoWave API (`POST /api/hosts`) with public endpoints, node associations, squad permissions, and `fingerprint: "firefox"`.

#### Scenario: Automated creation of Host entities with Node and Squad links
- **GIVEN** an active GoWave Panel with provisioned Config Profiles, Inbounds, and Node
- **WHEN** Host provisioning executes for each of the 5 MVP protocols
- **THEN** `POST /api/hosts` is invoked with `inbound.configProfileUuid`, `inbound.configProfileInboundUuid`, canonical `remark` (`<PROTO>@<node-name>`), `address` set to the public hostname, `port` set to 443, `sni`, `path`, `"fingerprint": "firefox"`, `"nodes": ["<node-uuid>"]`, `"internalSquads"` policy, and appropriate `securityLayer` (`DEFAULT` for REALITY, `TLS` for Vision, XHTTP, WS, and Trojan gRPC), and the created hosts are confirmed via `GET /api/hosts`.

#### Scenario: Host securityLayer resolution verification
- **GIVEN** provisioned Host records in GoWave
- **WHEN** Host records are retrieved via `GET /api/hosts` and subscription configurations are rendered
- **THEN** the REALITY Host record has `securityLayer: "DEFAULT"` resolving to client `security: reality`, while Vision, XHTTP, WS, and Trojan gRPC Host records have `securityLayer: "TLS"` resolving to client `security: tls`, with all hosts configured with `fingerprint: "firefox"`.

#### Scenario: Host record presence in subscription output
- **GIVEN** provisioned Host records for VLESS-REALITY, VLESS-Vision, VLESS-XHTTP, VLESS-WS, and Trojan-gRPC
- **WHEN** subscription endpoints are queried for an active user belonging to the managed squad
- **THEN** all 5 configured Host endpoints appear in the generated client configurations with correct public hostnames, port 443, paths, and `client-fingerprint: "firefox"`.

#### Scenario: Idempotent Host provisioning and atomic rollback
- **GIVEN** a provisioning operation that experiences an interruption or failure while creating Host records
- **WHEN** the provisioning script detects a failure or is re-executed
- **THEN** partially created Host records are cleanly deleted or existing matching records are updated in place without leaving orphan or duplicate host entries.

### Requirement: Automatic Per-User Xray and Mihomo Subscription Links
The system SHALL provide two deterministic, per-user subscription URLs for every user: an Xray subscription URL (`GET /api/sub/{shortUuid}/v2ray-json`) and a Mihomo subscription URL (`GET /api/sub/{shortUuid}/mihomo`), ensuring Response Rules, templates, and User-Agent policies are properly configured, and displaying both links in the installer summary and CLI management commands.

#### Scenario: Deterministic retrieval of Xray subscription
- **GIVEN** an active user with short UUID `<shortUuid>` and a client sending a valid Xray User-Agent
- **WHEN** an HTTP GET request is made to `https://<public-domain>/api/sub/<shortUuid>/v2ray-json`
- **THEN** GoWave responds with HTTP 200, `Content-Type: application/json`, non-empty body (`body.strip() != ""`), valid Xray JSON containing at least 4 inbounds and zero internal loopback endpoints, and forwards `profile-update-interval: 24` and `Subscription-Userinfo` headers.

#### Scenario: Deterministic retrieval of Mihomo subscription
- **GIVEN** an active user with short UUID `<shortUuid>` and a client sending a valid Mihomo User-Agent
- **WHEN** an HTTP GET request is made to `https://<public-domain>/api/sub/<shortUuid>/mihomo`
- **THEN** GoWave responds with HTTP 200, `Content-Type: text/yaml` (or `text/yaml; charset=utf-8`), non-empty body (`body.strip() != ""`), valid Mihomo YAML containing at least 4 proxies matching `assets/mihomo/expected.yaml` with `GEOIP,private,DIRECT,no-resolve` private network bypass, and forwards `profile-update-interval: 24` and `Subscription-Userinfo` headers.

#### Scenario: Verification of GoWave Response Rules and Subscription Templates
- **GIVEN** a fresh or updated GoWave deployment
- **WHEN** subscription settings, templates, and User-Agent evaluation are tested
- **THEN** `DisableSubscriptionAccessByPath` is verified as false in `subscription_settings`, default subscription templates for `MIHOMO` (`DefaultTemplateMihomo`) and `XRAY_JSON` (`DefaultTemplateXrayJson`) exist in `subscription_templates`, requests with valid client User-Agents return HTTP 200, and requests with missing or empty User-Agent headers return HTTP 403 Forbidden.

#### Scenario: Live Trojan gRPC handshake and data transfer verification
- **GIVEN** a running All-in-One deployment and active Trojan gRPC inbound
- **WHEN** a client initiates an HTTP/2 gRPC handshake to port 443 with valid Trojan password and service path
- **THEN** NGINX terminates TLS, proxies gRPC frames via `grpc_pass` to port 10003, and Xray establishes an authenticated bidirectional VPN data session.

#### Scenario: Client parser and import validation
- **GIVEN** fetched Xray JSON and Mihomo YAML subscription payloads
- **WHEN** the Xray JSON payload is validated using official Xray core (`v24.11.30`+ / `v25.x` via `xray run -test -c`) and the Mihomo YAML payload is validated using Mihomo (`v1.19.22`+ / `v1.20.0`+ via `mihomo -t -f`)
- **THEN** both tools complete validation with exit code 0, verifying proxy outbounds contain valid public server addresses, port 443, and zero internal loopback or socket references.

#### Scenario: Protocol update reflection in subscriptions
- **GIVEN** an active user with working Xray and Mihomo subscriptions
- **WHEN** an administrator adds, updates, or disables an MVP protocol profile or Host record in GoWave
- **THEN** subsequent requests to both `/api/sub/<shortUuid>/v2ray-json` and `/api/sub/<shortUuid>/mihomo` immediately reflect the updated protocol configuration.

### Requirement: Validated Public Subscription Link Generation
The subscription engine SHALL publish client configuration links containing valid public addresses, port 443, and correct paths, never leaking internal loopback endpoints.

#### Scenario: Subscription format and endpoint verification
- **GIVEN** an active user requesting a subscription from `/api/sub/{shortUuid}`
- **WHEN** the subscription response is parsed in Xray JSON, Clash/Mihomo, or sing-box format
- **THEN** the server address points to the public domain or worker IP, port is 443, and loopback addresses (`127.0.0.1`, `::1`) or internal ports (`3000`, `3001`, `3002`, `7443`, `8443`, `9443`, `10001-10003`) are completely absent.

### Requirement: Scoped API Token Generation for External Frontends
The system SHALL support issuing long-lived API tokens via `POST /api/tokens` with granular scopes for external web subscription interfaces and bot integrations.

#### Scenario: Provisioning long-lived API token with defined scopes
- **GIVEN** an authenticated GoWave administrative session
- **WHEN** the installer requests a new API token via `POST /api/tokens` with scopes for subscription page configurations and user lookups
- **THEN** GoWave generates a persistent API token, returns the bearer token, and the installer records the token and panel endpoint into `/root/gowave-credentials.txt` with mode `0600`.

### Requirement: Formal Scope Boundaries for Auxiliary Protocols
The installer SHALL NOT configure Hysteria 2 or AmneziaWG in the MVP release.

#### Scenario: Rejection of deferred non-MVP protocol options
- **GIVEN** an MVP deployment
- **WHEN** protocol profile configuration is evaluated
- **THEN** only the 4 core profiles (and optional 5th VLESS-Vision profile if a 3rd domain is provided) are provisioned, and Hysteria 2 and AmneziaWG are documented as deferred non-goals.
