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

### Requirement: Upstream Installer Orchestration for GoWave Node
The orchestration system SHALL utilize the upstream `gowave-node/install.sh` installer as its primary mechanism for installing, updating, and initializing `gowave-node`, preparing parameters (`SECRET_KEY`, `NODE_PORT`, `GOWAVE_NODE_VERSION`) via environment variables rather than duplicating binary downloads and unit definitions.

#### Scenario: Node deployment using upstream installer
- **GIVEN** a target host for local or remote GoWave Node deployment
- **WHEN** the orchestration script initiates node installation
- **THEN** it sets `NODE_PORT=3002` (or remote port), passes `SECRET_KEY` via stdin or temporary mode 0600 file, runs `gowave-node/install.sh`, verifies checksums and systemd unit creation, and confirms active service status.

### Requirement: Remote Worker Node Deployment with Firewall Whitelisting
The installer SHALL provide an independent automated worker script (`gowave-node-auto.sh`) that provisions `gowave-node` on remote edge servers using upstream installer routines, configures `NODE_PORT` (default 3000), and whitelists access strictly from the Control Plane IP (both IPv4 and IPv6).

#### Scenario: Remote worker installation and firewall lockdown
- **GIVEN** an edge server designated as a remote worker and a Control Plane `PANEL_IP`
- **WHEN** `gowave-node-auto.sh` is executed
- **THEN** `gowave-node` is installed under user `root`, UFW allows `NODE_PORT` strictly from `PANEL_IP`, all other external access to `NODE_PORT` is dropped, and the daemon starts supervising Xray core.

#### Scenario: External inaccessibility verification of local node port
- **GIVEN** a running All-in-One installation where `gowave-node` listens on port 3002
- **WHEN** an external probe attempts to connect to `<public-ip>:3002`
- **THEN** the connection is blocked or dropped by UFW firewall rules, while local connections from `127.0.0.1:3000` succeed.

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
- **THEN** the base64 payload is piped via stdin or read from a mode `0600` file that is immediately unlinked, and process inspection via `/proc/<pid>/cmdline` or `ps aux` reveals zero credentials.

### Requirement: Exact Node Config Profile and Inbound Association Payload
The system SHALL link Config Profiles and active inbounds to GoWave nodes using the exact API structure required by GoWave backend (`activeConfigProfileUuid` and `activeInbounds`).

#### Scenario: Successful node profile association
- **GIVEN** an active GoWave Node and a provisioned Config Profile containing 4 inbounds
- **WHEN** `POST /api/nodes` or `PATCH /api/nodes/{uuid}` is sent with `configProfile.activeConfigProfileUuid` and array `configProfile.activeInbounds`
- **THEN** GoWave responds with HTTP 200/201 confirming `activeConfigProfileUuid` and `activeInbounds` are bound to the node, and the node receives the compiled Xray config.

### Requirement: Native Xray Core Supervision
The `gowave-node` daemon SHALL directly supervise the Xray core child process without external systemd watchdog timers or parallel process managers.

#### Scenario: Xray child process auto-restart
- **GIVEN** a running `gowave-node` daemon supervising Xray core
- **WHEN** the Xray core process terminates unexpectedly
- **THEN** `gowave-node` detects process exit and automatically respawns Xray core.
