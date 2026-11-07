# Spec Delta: Panel Node Integration

## Purpose

Automates the deployment, mutual TLS communication, upstream installer usage, and lifecycle integration of GoWave Panel (Control Plane) and GoWave Node (Worker) across All-in-One and Distributed Edge topologies without port collisions.

## ADDED Requirements

### Requirement: Conflict-Free All-in-One Provisioning
The installer SHALL deploy GoWave Panel, local GoWave Node, and Xray core on a single host with distinct port bindings, assigning port 3000 to the Panel API, port 3001 to Panel Metrics, and port 3002 to the local Node, with the local Node's wildcard listener isolated from external networks via firewall rules.

#### Scenario: Clean All-in-One installation without port collision
- **GIVEN** a supported clean Linux host
- **WHEN** the installer is executed in All-in-One standalone mode
- **THEN** GoWave Panel binds to `127.0.0.1:3000`, Panel Metrics bind to `127.0.0.1:3001`, GoWave Node binds to port 3002 (`addr := ":3002"`), UFW denies external incoming connections to port 3002, and both services run concurrently without listener conflicts.

#### Scenario: Abort before mutation on occupied port
- **GIVEN** a host where port 3000, 3001, or 3002 is already occupied by another service
- **WHEN** installer preflight port checks are executed
- **THEN** the installer outputs the conflicting process name and port number, and halts before creating users or writing configuration files.

#### Scenario: Abort on unmanaged NGINX port 443 conflict
- **GIVEN** a host where `/etc/nginx/` contains existing unmanaged virtual hosts listening on port 443
- **WHEN** installer preflight checks scan `/etc/nginx/` for conflicting `listen ... 443` directives
- **THEN** the installer detects the conflicting files, outputs the file paths and line numbers, and halts before applying the NGINX Stream configuration.

### Requirement: Upstream Installer Orchestration for GoWave Node
The orchestration system SHALL utilize the upstream `gowave-node/install.sh` installer as its primary mechanism for installing, updating, and initializing `gowave-node`, preparing parameters (`SECRET_KEY`, `NODE_PORT`, `GOWAVE_NODE_VERSION`) via environment variables rather than duplicating binary downloads and unit definitions.

#### Scenario: Node deployment using upstream installer
- **GIVEN** a target host for local or remote GoWave Node deployment
- **WHEN** the orchestration script initiates node installation
- **THEN** it sets `NODE_PORT=3002` (or remote port), passes `SECRET_KEY` via stdin or temporary mode 0600 file, runs `gowave-node/install.sh`, verifies checksums and systemd unit creation, and confirms active service status.

#### Scenario: Node port configuration override and systemd drop-in verification
- **GIVEN** an All-in-One deployment where `NODE_PORT=3002` is exported
- **WHEN** `gowave-node/install.sh` executes
- **THEN** the upstream installer validates the numeric port, writes `NODE_PORT=3002` to `/opt/gowave-node/.env`, the orchestrator writes systemd drop-in `10-port.conf` with `Environment="NODE_PORT=3002"`, and `gowave-node` binds to port 3002.

### Requirement: Remote Worker Node Deployment with Firewall Whitelisting
The installer SHALL provide an independent automated worker script (`gowave-node-auto.sh`) that provisions `gowave-node` on remote edge servers using upstream installer routines, configures `NODE_PORT` (default 3000), and whitelists access strictly from the Control Plane IP (both IPv4 and IPv6).

#### Scenario: Remote worker installation and firewall lockdown
- **GIVEN** an edge server designated as a remote worker and a Control Plane `PANEL_IP`
- **WHEN** `gowave-node-auto.sh` is executed
- **THEN** `gowave-node` is installed under user `root`, UFW allows `NODE_PORT` strictly from `PANEL_IP`, all other external access to `NODE_PORT` is dropped, and the daemon starts supervising Xray core.

#### Scenario: External inaccessibility verification of local node port
- **GIVEN** a running All-in-One installation where `gowave-node` listens on wildcard `:3002`
- **WHEN** external probes attempt to connect to `<public-ipv4>:3002` or `[<public-ipv6>]:3002`
- **THEN** connections are dropped or refused by UFW firewall rules across both IPv4 and IPv6, while local connections from `127.0.0.1:3000` and `[::1]:3000` succeed.

#### Scenario: Worker node complete edge traffic plane deployment
- **GIVEN** a remote worker server running `gowave-node-auto.sh`
- **WHEN** edge traffic plane configuration is applied
- **THEN** NGINX Stream on port 443 routes camouflage SNI to local Xray REALITY (`127.0.0.1:8443`) and worker domain SNI to local NGINX HTTPS (`127.0.0.1:7443`) terminating Let's Encrypt TLS, proxying XHTTP, WebSocket, and Trojan gRPC to local Xray loopback inbounds, enabling direct client VPN connections without traversing the Central Panel.

#### Scenario: Remote worker orchestration via SSH stdin streaming
- **GIVEN** an operator running `gowave-node-auto.sh` targeting a remote edge server over SSH
- **WHEN** the deployment begins
- **THEN** environment variables and deployment functions are packed and piped directly over SSH stdin via `remote_payload`, executing inside a temporary remote script without copying files via `scp`, and cleaning up temporary files upon completion.

#### Scenario: Automated worker registration via CLI node add command
- **GIVEN** an active GoWave Panel and an accessible remote worker host
- **WHEN** `gowave-auto.sh node add <name> <ip> <worker-domain> <reality-domain> [user] [port]` is executed
- **THEN** it registers the node via `POST /api/nodes` linking unified profile inbounds, provisions worker Host records (`POST /api/hosts`), streams deployment payload via `remote_payload` strictly over SSH stdin with zero secrets in `argv`, and stores node state in `state.json`.

### Requirement: Mutual TLS 1.3 Control Plane Protocol with Strict SNI Verification
All panel-to-node management communication SHALL use TLS 1.3 with mutual certificate verification, derived HKDF SNI (`rw-v1`), RS256 JWT bearer token authentication, and strict SNI enforcement.

#### Scenario: Verified node health check
- **GIVEN** a running GoWave Node with active Xray core and `SNI_VERIFICATION=true`
- **WHEN** the GoWave Panel issues an authenticated GET request to `/node/xray/node-health-check` using HKDF-derived SNI and a valid client certificate signed by the panel CA
- **THEN** the node accepts the connection and returns HTTP 200 with Xray core status and inbound statistics.

#### Scenario: Reject mismatched SNI or unauthorized client certificate
- **GIVEN** a running GoWave Node with `SNI_VERIFICATION=true`
- **WHEN** a client connects with an invalid certificate or an SNI hostname differing from the HKDF derivation
- **THEN** the node terminates the TLS handshake before any HTTP request processing occurs.

### Requirement: Zero-Leak Node Secret Provisioning
The installer SHALL provision `SECRET_KEY` to `gowave-node` strictly via standard input or a temporary mode `0600` file, never passing sensitive cryptographic material in command-line arguments.

#### Scenario: Secret key delivery without command-line exposure
- **GIVEN** a newly generated base64 256-bit secret key for node provisioning
- **WHEN** `gowave-node` is configured by the automated installer
- **THEN** the base64 payload is piped via stdin or read from a mode `0600` file that is immediately unlinked, and process inspection of both local `ssh` processes and remote runners via `/proc/<pid>/cmdline` or `ps aux` reveals zero credentials.

### Requirement: Exact Node Config Profile and Inbound Association Payload
The system SHALL link Config Profiles and active inbounds to GoWave nodes using the exact API structure required by GoWave backend (`activeConfigProfileUuid` and `activeInbounds`), enforcing that all active inbounds assigned to the Node belong to that single active Config Profile.

#### Scenario: Successful node profile association
- **GIVEN** an active GoWave Node and a provisioned unified Config Profile containing all 4 MVP inbounds
- **WHEN** `POST /api/nodes` or `PATCH /api/nodes/{uuid}` is sent with `configProfile.activeConfigProfileUuid` and array `configProfile.activeInbounds` containing the 4 UUIDs belonging to that profile
- **THEN** GoWave responds with HTTP 200/201 confirming `activeConfigProfileUuid` and `activeInbounds` are bound to the node, and the node receives the compiled Xray config.

#### Scenario: Rejection of inbounds from differing config profiles (negative test)
- **GIVEN** an active GoWave Node with an assigned active Config Profile
- **WHEN** an update is dispatched attempting to add an inbound UUID that belongs to a different Config Profile
- **THEN** GoWave rejects the transaction with an error indicating the inbound does not belong to the active config profile, and leaves the Node's active profile and inbounds unmutated.

#### Scenario: Algorithmic idempotency and state reconciliation via state.json
- **GIVEN** an existing deployment where resources have previously been provisioned
- **WHEN** the installer runs subsequent provisioning or reconciliation cycles
- **THEN** it reads `/var/lib/gowave-auto-nginx/state.json`, queries GoWave API to verify resource existence by name and remark, adopts existing UUIDs without creating duplicate entries, and atomically updates `state.json`.

#### Scenario: Verification checklist for compiled Xray config
- **GIVEN** a provisioned unified Config Profile in GoWave Panel
- **WHEN** the installer queries `GET /api/config-profiles/{uuid}/computed-config`
- **THEN** GoWave responds with HTTP 200, `response.config` is valid parseable JSON containing exactly 4 inbounds with populated `streamSettings.security` fields, REALITY settings with valid keys on port 8443, and zero top-level error fields.

### Requirement: Native Xray Core Supervision
The `gowave-node` daemon SHALL directly supervise the Xray core child process without external systemd watchdog timers or parallel process managers.

#### Scenario: Xray child process auto-restart
- **GIVEN** a running `gowave-node` daemon supervising Xray core
- **WHEN** the Xray core process terminates unexpectedly
- **THEN** `gowave-node` detects process exit and automatically respawns Xray core.

### Requirement: Multi-Node Distributed Edge Podman Verification Gate
The verification harness SHALL provide an automated dual-container Podman testbed (`./tests/podman_testbed.sh multi-node`) verifying end-to-end deployment of `gowave-node-auto.sh`, panel-to-node mTLS 1.3 handshake, firewall panel IP restriction, and direct edge client VPN data tunneling.

#### Scenario: Automated multi-node deployment and mTLS connection in Podman testbed
- **GIVEN** an isolated Podman bridge network connecting `gowave-panel` and `gowave-worker` containers
- **WHEN** `./tests/podman_testbed.sh multi-node` is executed
- **THEN** it deploys GoWave Panel on the first container, deploys `gowave-node-auto.sh` on the second container via SSH stdin streaming, verifies successful mTLS 1.3 handshake with HKDF SNI (`rw-v1`), registers the worker node in the panel, and syncs users.

#### Scenario: Worker node firewall panel IP restriction and edge traffic routing in Podman testbed
- **GIVEN** a running multi-node Podman testbed
- **WHEN** client VPN connections are initiated to the worker container port 443
- **THEN** client traffic is routed directly by the worker's NGINX Stream and Xray inbounds without passing through the panel container, while the worker's UFW denies external access to `NODE_PORT=3000` from IPs other than the panel.
