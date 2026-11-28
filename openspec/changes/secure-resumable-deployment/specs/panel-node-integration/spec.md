# Spec Delta

## MODIFIED Requirements

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

## ADDED Requirements

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
