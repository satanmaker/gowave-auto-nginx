# panel-node-integration Specification

## Purpose

Automates the deployment, mutual TLS communication, upstream installer usage, and lifecycle integration of GoWave Panel (Control Plane) and GoWave Node (Worker) across All-in-One and Distributed Edge topologies without port collisions.

## Requirements

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
- **THEN** the upstream installer validates the numeric port, writes `NODE_PORT=3002` to `/opt/gowave-node/.env`, the orchestrator writes systemd drop-in `10-port.conf` with `Environment="NODE_PORT=3002"` and fail-closed loopback TCP listener check (`ss -Hltn` and `/dev/tcp`), and `gowave-node` binds to port 3002 without triggering mTLS SNI handshake errors.

### Requirement: Remote Worker Node Deployment with Firewall Whitelisting
The installer SHALL provide an independent automated worker script (`gowave-node-auto.sh`) that provisions `gowave-node` on remote edge servers using upstream installer routines, configures `NODE_PORT` (recommended default 3002), and whitelists access strictly from the Control Plane IP (both IPv4 and IPv6).

#### Scenario: Remote worker installation and firewall lockdown
- **GIVEN** an edge server designated as a remote worker and a Control Plane `PANEL_IP`
- **WHEN** `gowave-node-auto.sh` is executed
- **THEN** `gowave-node` is installed under user `root`, UFW allows `NODE_PORT` strictly from `PANEL_IP`, all other external access to `NODE_PORT` is dropped, and the daemon starts supervising Xray core.

#### Scenario: External inaccessibility verification of local node port
- **GIVEN** a running All-in-One installation where `gowave-node` listens on wildcard `:3002`
- **WHEN** external probes attempt to connect to public IPv4 or IPv6 port 3002
- **THEN** connections are dropped or refused by UFW across both enabled families while local loopback connections succeed.

#### Scenario: Worker node complete edge traffic plane deployment
- **GIVEN** a remote worker server running `gowave-node-auto.sh`
- **WHEN** edge traffic plane configuration is applied
- **THEN** NGINX Stream routes REALITY SNI to local 8443, primary Worker SNI to local HTTPS 7443 for XHTTP/WS/gRPC and generated static cover, and enabled Vision to local 8444 with cover-only fallback; management/subscription paths are denied, all fallback listeners are loopback-only, and Worker does not adopt Master apex/www routes or SANs. Port 80 serves owned HTTP-01 challenges, redirects other owned requests to HTTPS and refuses unmanaged hosts, enabling direct VPN traffic without traversing Panel.

#### Scenario: Remote worker orchestration via SSH stdin streaming
- **GIVEN** an operator targeting a remote edge server over SSH
- **WHEN** deployment begins
- **THEN** variables, functions and the checksummed base64 cover payload are streamed over SSH stdin to `bash -s` without scp or unmanaged remote staging files, and SECRET_KEY is scoped to upstream installer execution.

#### Scenario: Automated worker registration via CLI node add command
- **GIVEN** an active Panel and accessible remote worker
- **WHEN** `gowave-auto.sh node add <name> <ip> <worker-domain> <reality-domain> [user] [port]` runs
- **THEN** same-host nodes enforce port 3002, a dedicated profile and unique tags are associated with the node and squad, Worker Host records are provisioned, payload is streamed over SSH stdin and versioned state preserves UUID and edge-identity associations.

#### Scenario: Remote worker deployment failure compensating rollback
- **GIVEN** a remote worker deployment transaction
- **WHEN** firewall, NGINX, ACME, upstream installation or mTLS verification fails
- **THEN** remote and Panel compensation restore the pre-install baseline for owned changes, remove only newly created owned services/configuration/certificates and entities, restore firewall state and managed swap/sysctl changes, unset secrets and verify recovery; adopted or unrelated resources and completed sibling nodes remain untouched.

#### Scenario: Failed re-apply leaves a serving Worker serving
- **GIVEN** a Worker that is already installed and serving, whose Panel registration this run does not change
- **WHEN** the re-apply fails after it stopped the managed service
- **THEN** compensation restores the run's before-image and starts that service again with its enablement intact, so the host is not left registered and silent; only a run that found the service inactive disables it, and a restoration that could not put every owned path back reports the recovery as failed instead of starting a half-restored host.
### Requirement: Mutual TLS 1.3 Control Plane Protocol with Strict SNI Verification
All panel-to-node management communication SHALL use TLS 1.3 with mutual certificate verification, derived HKDF SNI (`rw-v1`), RS256 JWT bearer token authentication, and strict SNI enforcement.

#### Scenario: Verified node health check
- **GIVEN** a running GoWave Node with active Xray core and `SNI_VERIFICATION=true`
- **WHEN** the GoWave Panel issues an authenticated GET request to `/node/xray/node-health-check` using HKDF-derived SNI and a valid client certificate signed by the panel CA
- **THEN** the node accepts the connection and returns HTTP 200 with Xray core status and inbound statistics.

#### Scenario: Cryptographic verification of node mTLS payload and health check handshake
- **GIVEN** a base64-encoded mTLS payload (`SECRET_KEY`) streamed via standard input containing `caCertPem`, `jwtPublicKey`, `nodeCertPem`, and `nodeKeyPem`
- **WHEN** node health verification executes via `verify_node_mtls_health`
- **THEN** it validates JSON structure, confirms the client certificate matches the EC private key, validates X.509 CA certificate, verifies RSA public key format, computes the exact upstream HKDF-SHA256 SNI (`rw-v1`, salt=32 zeros, okm 22 bytes), performs a mutual TLS 1.3 client handshake against the node daemon, queries `/node/xray/healthcheck`, and halts with a non-zero exit code on any cryptographic, handshake, or HTTP failure.

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
- **GIVEN** an active GoWave Node and a provisioned unified Config Profile containing all 5 MVP inbounds
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

#### Scenario: Internal squad inbound union update via PATCH /api/internal-squads
- **GIVEN** an existing Internal Squad (`Default MVP Squad`)
- **WHEN** additional worker inbounds are associated during worker node onboarding
- **THEN** the orchestrator dispatches `PATCH /api/internal-squads` with `uuid`, `name`, and the full union array of master and worker inbound UUIDs in the request body (calling `UpdateInternalSquadCommand`), avoiding 405 Method Not Allowed errors on `/api/internal-squads/{uuid}`, and GoWave updates the squad membership.

### Requirement: Native Xray Core Supervision
The `gowave-node` daemon SHALL directly supervise the Xray core child process without external systemd watchdog timers or parallel process managers.

#### Scenario: Xray child process auto-restart
- **GIVEN** a running `gowave-node` daemon supervising Xray core
- **WHEN** the Xray core process terminates unexpectedly
- **THEN** `gowave-node` detects process exit and automatically respawns Xray core.

### Requirement: Multi-Node Distributed Edge Podman Verification Gate
The verification harness SHALL provide an automated dual-container Podman testbed (`./tests/podman_testbed.sh multi-node`) verifying deployment scaffolds, returning exit code 77 (unavailable/skipped) until full multi-node client tunneling is executed.

#### Scenario: Multi-node Podman testbed scaffold status
- **GIVEN** the isolated Podman bridge network scaffold in `tests/podman_testbed.sh`
- **WHEN** `./tests/podman_testbed.sh multi-node` is executed
- **THEN** it explicitly returns exit code 77 (unavailable/skipped), documenting that full multi-node E2E client data tunneling is deferred to dedicated live multi-node VPS testing, preventing false positive verification claims.

#### Scenario: Multi-node discovery and node address uniqueness
- **GIVEN** a panel managing `local-node` on address `127.0.0.1`
- **WHEN** an operator provisions an additional worker node
- **THEN** GoWave enforces address uniqueness (`UNIQUE(address)`), requiring distinct network addressing for the worker, and subsequent queries to `GET /api/nodes` return both `local-node` and the worker node with their respective profiles and inbounds.

### Requirement: Persisted node edge identity
The deployment state SHALL record each host's role, node identity, explicit domain roles, certificate SAN ownership and selected lineage paths with a schema version. State SHALL remain secret-free for draft and report use, preserve existing UUID associations and be reconciled with Panel and host readback before adoption or resume.

#### Scenario: Resume does not duplicate resources
- **WHEN** a resumed deployment finds the expected node, profile and host records already registered
- **THEN** it verifies their identity and readiness, retains their UUIDs and runs only confirmed incomplete work rather than creating replacements.

#### Scenario: Legacy identity needs confirmation
- **WHEN** legacy state lacks explicit cover ownership or certificate paths
- **THEN** the installer derives a read-only candidate from actual configuration, shows ambiguities and waits for migration confirmation rather than inferring a new apex from the transport name.

### Requirement: Explicit Worker edge migration
Existing Worker routes and certificate ownership SHALL change only after an explicit migration preview and confirmation. Migration SHALL preserve Node supervision, profile associations, valid transport sessions' configuration and immutable upstream interfaces. Failure SHALL restore prior owned configuration with verified recovery and report unresolved state without claiming readiness.

#### Scenario: Existing Worker adopts static primary cover
- **WHEN** the operator confirms migration from generic primary-host refusal to static cover
- **THEN** primary root and assets serve the generated site, management paths remain denied, XHTTP/WS/gRPC and optional Vision keep their selected identities and no Panel is installed on Worker.

#### Scenario: Shared-zone migration fails
- **WHEN** a Worker migration fails after changing owned NGINX or certificate references
- **THEN** previous owned routes and references are restored and verified, Master apex and certificates remain unchanged, and the report distinguishes deployment failure from recovery failure.

### Requirement: Pinned Xray Core Delivery Before the Upstream Installer

On an installation that restarts the node, the orchestrator SHALL install the pinned Xray core at `<install_dir>/rw-core` before the upstream installer runs, from an artifact whose SHA-256 matches the pin for the host architecture. An executable `rw-core` makes the upstream installer skip its own core installation, so a node installation on the default version SHALL complete without any request to `api.github.com`. `XRAY_SERVER_VERSION=latest` is the specified exception.

#### Scenario: Node installation completes while the GitHub API is unreachable

- **GIVEN** a host where `api.github.com` is unreachable and no Xray core is installed
- **WHEN** node installation runs with `XRAY_SERVER_VERSION` unset or naming the pin
- **THEN** installation succeeds, `<install_dir>/rw-core` reports the pinned version, and no `core install` request is made

#### Scenario: The upstream installer finds a runnable core and does not fetch one

- **GIVEN** the pinned core is already installed at `<install_dir>/rw-core` and executable
- **WHEN** the upstream installer runs
- **THEN** it skips its own core installation step and starts the node with that core

#### Scenario: A core that fails verification is never installed

- **GIVEN** a release artifact whose bytes do not match the pinned SHA-256
- **WHEN** the pinned core step fetches it
- **THEN** no `rw-core` is created and the installation stops with the mismatch named

### Requirement: Single Meaning for Each XRAY_SERVER_VERSION Value

`XRAY_SERVER_VERSION` SHALL have exactly one meaning per value: unset, or naming the pin itself, installs the pinned core; `latest` delegates the core to the upstream installer as an explicit opt-out; any other version is left to the upstream installer and the existing explicit-version path. The pin SHALL be Xray 26.11.9, the release verified against mihomo 1.19.34 for REALITY.

#### Scenario: An unset version installs the pin

- **GIVEN** `XRAY_SERVER_VERSION` is unset or empty
- **WHEN** node installation runs
- **THEN** the installed core is 26.11.9 and the upstream core installation is skipped

#### Scenario: An explicit value naming the pin installs the pin

- **GIVEN** `XRAY_SERVER_VERSION` is `26.11.9` or `v26.11.9`
- **WHEN** node installation runs
- **THEN** the pinned step installs 26.11.9 and no upstream core installation is attempted

#### Scenario: latest opts out of the pin

- **GIVEN** `XRAY_SERVER_VERSION` is `latest`
- **WHEN** node installation runs
- **THEN** the pinned step does not install a core and the upstream installer selects the core itself

#### Scenario: An explicit foreign version is not overridden

- **GIVEN** `XRAY_SERVER_VERSION` names a version other than the pin
- **WHEN** node installation runs
- **THEN** the pinned step does not act and the requested version is handled by the explicit-version path

### Requirement: Version-Based Idempotency of the Pinned Core Step

On an installation that restarts the node, the pinned core step SHALL treat an installed core as satisfied only when its reported version names the pinned version as a version token, not as a substring. A core whose version differs SHALL be replaced, and a repeat installation that already finds the pinned version SHALL not download the artifact again.

#### Scenario: A repeat installation does not download the core again

- **GIVEN** a host whose `rw-core` already reports the pinned version
- **WHEN** node installation restarts the node
- **THEN** no artifact is downloaded and the running core is left untouched

#### Scenario: A foreign core is replaced instead of accepted

- **GIVEN** a host whose `rw-core` reports a different version than the pin
- **WHEN** node installation runs with the default version
- **THEN** the pinned core is installed in its place before the upstream installer runs

### Requirement: Fail-Closed Delivery on the Pinned Path

When the pinned artifact cannot be delivered or fails verification, node installation SHALL fail with a message naming the artifact and the pinned version, and SHALL name `XRAY_SERVER_VERSION=latest` as the opt-out. The step SHALL NOT hand the installation to the upstream core installation path, because that path is the API dependency this change removes.

#### Scenario: An unavailable artifact stops the installation

- **GIVEN** no artifact host can deliver the pinned core
- **WHEN** node installation runs with the default version
- **THEN** installation fails, the failure names the pinned version and `XRAY_SERVER_VERSION=latest`, and no upstream core installation is attempted

#### Scenario: The failure is reported once and located

- **GIVEN** the pinned artifact cannot be delivered
- **WHEN** node installation fails
- **THEN** the installation log carries one message naming the pinned version and `XRAY_SERVER_VERSION=latest`, the run exits non-zero, and no upstream `core install` attempt follows

### Requirement: One Authoritative Core Pin Table

The product SHALL keep one table mapping a supported (version, architecture) pair to an artifact URL and SHA-256 digest — for each architecture the acceptance matrix also names, the same digest that matrix pins. An unknown version or architecture SHALL make the pinned step abstain rather than select a near-matching artifact.

#### Scenario: The product pin and the acceptance matrix name the same bytes

- **GIVEN** the product pin table and `tests/cases/matrix.yaml`
- **WHEN** both are read for the supported version and architecture
- **THEN** they state the same URL and the same SHA-256 digest

#### Scenario: An unsupported architecture is not guessed

- **GIVEN** a host whose architecture the pin table does not describe
- **WHEN** node installation runs with the default version
- **THEN** the pinned step does not install a core and the reason is reported
