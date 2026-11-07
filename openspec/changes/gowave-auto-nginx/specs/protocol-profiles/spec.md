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

### Requirement: Native VLESS XHTTP TLS Profile
The system SHALL support VLESS over XHTTP (splitHTTP) transport multiplexed behind the main panel domain TLS termination on port 7443.

#### Scenario: VLESS XHTTP TLS data transfer
- **GIVEN** a client configured with VLESS XHTTP parameters matching `panel_domain` and `<xhttp_path>`
- **WHEN** the client sends uplink packets via HTTP POST
- **THEN** NGINX terminates TLS on 7443 and streams the data to Xray port 10001 without chunk buffering or request body truncation.

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

### Requirement: Automated Profile Provisioning via GoWave API
The installer SHALL provision the 4 MVP protocol profiles by authenticating against GoWave Panel REST API, calling `POST /api/config-profiles` with raw Xray JSON, linking the profile to nodes using explicit `activeConfigProfileUuid` and `activeInbounds` DTO, and verifying `GET /api/config-profiles/{uuid}/computed-config`.

#### Scenario: Idempotent API profile creation
- **GIVEN** a newly installed GoWave Panel
- **WHEN** the provisioning script executes
- **THEN** it checks for existing managed profiles, creates missing Config Profiles via `POST /api/config-profiles`, links them to active nodes via `POST /api/nodes` or `PATCH /api/nodes/{uuid}` with `{"configProfile": {"activeConfigProfileUuid": "<uuid>", "activeInbounds": [...]}}`, and verifies the compiled Xray config without creating duplicate profiles on subsequent runs.

### Requirement: Automatic GoWave Host Record Provisioning
For each provisioned MVP protocol profile, the provisioning system SHALL automatically create and verify a corresponding Host entity via GoWave API (`POST /api/hosts`) specifying public address, port 443, SNI, path, Host header, fingerprint, security layer, and inbound association.

#### Scenario: Automated creation of Host entities for MVP protocols
- **GIVEN** an active GoWave Panel with provisioned Config Profiles and Inbounds
- **WHEN** Host provisioning executes for each of the 4 MVP protocols
- **THEN** `POST /api/hosts` is invoked with `inbound.configProfileUuid`, `inbound.configProfileInboundUuid`, `remark`, `address` set to the public hostname, `port` set to 443, `sni`, `path`, and appropriate `securityLayer` (`REALITY` or `DEFAULT`), and the created hosts are confirmed via `GET /api/hosts`.

#### Scenario: Host record presence in subscription output
- **GIVEN** provisioned Host records for VLESS-REALITY, VLESS-XHTTP, VLESS-WS, and Trojan-gRPC
- **WHEN** subscription endpoints are queried for an active user
- **THEN** all 4 configured Host endpoints appear in the generated client configurations with correct public hostnames and paths.

#### Scenario: Idempotent Host provisioning and atomic rollback
- **GIVEN** a provisioning operation that experiences an interruption or failure while creating Host records
- **WHEN** the provisioning script detects a failure or is re-executed
- **THEN** partially created Host records are cleanly deleted or existing matching records are updated in place without leaving orphan or duplicate host entries.

### Requirement: Automatic Per-User Xray and Mihomo Subscription Links
The system SHALL provide two deterministic, per-user subscription URLs for every user: an Xray subscription URL (`GET /api/sub/{shortUuid}/v2ray-json`) and a Mihomo subscription URL (`GET /api/sub/{shortUuid}/mihomo`), ensuring Response Rules and templates are properly configured, and displaying both links in the web panel and installer summary.

#### Scenario: Deterministic retrieval of Xray subscription
- **GIVEN** an active user with short UUID `<shortUuid>`
- **WHEN** an HTTP GET request is made to `https://<public-domain>/api/sub/<shortUuid>/v2ray-json`
- **THEN** GoWave responds with HTTP 200, `Content-Type: application/json`, and a non-empty, valid Xray JSON configuration containing all 4 MVP protocols.

#### Scenario: Deterministic retrieval of Mihomo subscription
- **GIVEN** an active user with short UUID `<shortUuid>`
- **WHEN** an HTTP GET request is made to `https://<public-domain>/api/sub/<shortUuid>/mihomo`
- **THEN** GoWave responds with HTTP 200, `Content-Type: text/yaml`, and a non-empty, valid Mihomo YAML configuration containing all client-compatible MVP protocols.

#### Scenario: Verification of GoWave Response Rules and Subscription Templates
- **GIVEN** a fresh or updated GoWave deployment
- **WHEN** subscription settings and templates are evaluated
- **THEN** `DisableSubscriptionAccessByPath` is verified as false in `subscription_settings`, default subscription templates for `MIHOMO` (`DefaultTemplateMihomo`) and `XRAY_JSON` (`DefaultTemplateXrayJson`) exist in `subscription_templates`, and requests with or without client User-Agent resolve to valid non-empty configurations.

#### Scenario: Client parser and import validation
- **GIVEN** fetched Xray JSON and Mihomo YAML subscription payloads
- **WHEN** the Xray JSON payload is loaded by an Xray configuration parser and the Mihomo YAML payload is parsed by a YAML/Mihomo schema validator
- **THEN** both configurations parse with zero syntax errors, and all proxy outbounds contain valid public server addresses, port 443, and zero internal loopback or socket references.

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

### Requirement: Formal Scope Boundaries for Auxiliary Protocols
The installer SHALL NOT configure direct VLESS-TLS-Vision (without REALITY), Hysteria 2, or AmneziaWG in the MVP release.

#### Scenario: Rejection of non-MVP protocol options
- **GIVEN** an MVP deployment
- **WHEN** protocol profile configuration is evaluated
- **THEN** only the 4 native profiles are provisioned, and direct TLS Vision, Hysteria 2, and AmneziaWG are documented as deferred non-goals.
