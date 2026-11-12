# Capability: Product-Level Podman E2E

## ADDED Requirements

### Requirement: Independent All-in-One acceptance topology

The test framework MUST provide an isolated All-in-One topology that starts from a clean supported Linux image and invokes the repository's real `gowave-auto.sh install` command in the target host context. It MUST NOT manually perform product provisioning steps that the operator is expected to perform.

#### Scenario: All-in-One clean installation

- **WHEN** the All-in-One acceptance suite is executed against a clean disposable target
- **THEN** it invokes the real operator in the supported full-install mode
- **AND** verifies the installed services, Panel/API readiness, TLS endpoint, and configured data-plane endpoint independently
- **AND** records a machine-readable result and sanitized diagnostics

#### Scenario: All-in-One repeated provisioning

- **WHEN** the same provisioning operation is executed again against the installed target
- **THEN** the suite verifies idempotency and absence of duplicate or conflicting resources
- **AND** verifies that previously working API and client traffic remain functional

### Requirement: Independent Multi-Node acceptance topology

The test framework MUST provide distinct Control, Master/Panel, and Worker roles. Control is the test orchestrator; the product's real `gowave-auto.sh install` command MUST run in the Master host context and the real `gowave-auto.sh node add` command MUST provision Worker from Master. Worker MUST be registered and reconciled through the real GoWave Panel API.

#### Scenario: Multi-Node clean installation and registration

- **WHEN** the Multi-Node acceptance suite runs against clean disposable nodes
- **THEN** the real operator provisions Master and Worker according to the supported deployment flow
- **AND** the Worker is registered through the real Panel API
- **AND** the suite verifies the Worker's externally observable healthy/online state
- **AND** no test-only API mock substitutes for the Panel or Worker

#### Scenario: Master and Worker optional domain configuration

- **WHEN** the suite runs all supported Multi-Node Vision combinations
- **THEN** it covers neither Vision domain configured, Master only, Worker only, and both configured
- **AND** only the host with a configured Vision domain provisions its Vision certificate, inbound, Panel host, and NGINX route
- **AND** the other host remains installable and its core protocol cases continue to pass

### Requirement: Real Panel subscription lifecycle

The framework MUST use the actual GoWave Panel endpoint and the version-pinned contract to create, retrieve, update where supported, and revoke test client access. It MUST exercise the real User-Agent policy: a non-empty header is accepted, while absent and blank headers are rejected. If the pinned API exposes no client-update operation, that case is NOT_APPLICABLE only with a cited contract and a separate check of the closest supported mutation; the harness MUST NOT invent endpoints.

#### Scenario: Subscription User-Agent policy is enforced

- **WHEN** the suite requests every served subscription representation from the real Panel
- **THEN** a request carrying a non-empty client-identifying User-Agent returns HTTP 200 with parseable content
- **AND** a request with no User-Agent header is rejected with HTTP 403
- **AND** a request with an explicitly blank User-Agent header is rejected with HTTP 403
- **AND** the absent and blank rejection cases are recorded as separate results

#### Scenario: Subscription is issued, updated where supported, and revoked

- **WHEN** the suite creates a test client, obtains its real subscription, and performs a documented client/configuration update when the pinned API supports one
- **THEN** the changed state is independently visible through the Panel API and the newly fetched subscription reflects the supported change
- **AND** after revocation a fresh connection using the revoked access cannot transfer a payload
- **AND** existing-session termination is asserted only if the pinned product contract promises immediate termination

### Requirement: Panel subscription representations

The framework MUST consume every representation the Panel serves and MUST NOT treat one as a substitute for another. Base64 share links at `/api/sub/<shortUuid>` are what Xray-family clients import; `/v2ray-json` is served as one config object or as a list of complete per-profile configs; `/mihomo` and `/clash` serve the Mihomo YAML.

#### Scenario: Base64 share-link list matches the profile inventory

- **GIVEN** a test client with subscriptions issued by the real Panel
- **WHEN** the suite fetches `/api/sub/<shortUuid>` with a client-identifying User-Agent and decodes the base64 payload
- **THEN** it contains one share link per proxy entry with the expected protocol, host, SNI, and fingerprint
- **AND** an Xray-family mobile client imports that list, and the JSON body is never substituted for it as the client's subscription

#### Scenario: Xray JSON is validated in both served shapes

- **GIVEN** the Panel returns either a single config object or a list of complete per-profile configs
- **WHEN** the suite validates the payload with the pinned Xray binary
- **THEN** each list entry is validated as the complete config it is
- **AND** only a bare outbound object is wrapped with a minimal runtime wrapper
- **AND** no Panel-issued outbound field is replaced with a hand-built equivalent

### Requirement: Versioned protocol and client coverage matrix

The framework MUST maintain a versioned, machine-readable protocol/client matrix derived from the authoritative product inventory and pinned generated configuration. Every applicable inbound on every installed node MUST be tested with both Xray and Mihomo using the corresponding Panel-issued representation.

#### Scenario: Complete client and inbound matrix is executed

- **WHEN** the suite executes against a pinned product version and selected Vision configuration
- **THEN** the matrix includes VLESS REALITY, VLESS XHTTP/TLS, VLESS WebSocket/TLS, and Trojan gRPC/TLS on each node, plus VLESS Vision/TLS when enabled on that node
- **AND** it validates actual Panel-issued Xray JSON and Mihomo YAML subscriptions against generated inbound/host configuration
- **AND** Xray JSON is consumed as served: a list entry is validated as the complete per-profile config it is, a bare outbound object is wrapped with only the minimal runtime wrapper the pinned Xray binary needs (for example, local SOCKS inbound and routing), and the Panel-issued outbound is never replaced with a hand-built equivalent
- **AND** runs every applicable inbound with both Xray and Mihomo
- **AND** reports exactly 8 or 10 positive cases for All-in-One and 16, 18, or 20 for Multi-Node according to independently enabled Vision inbounds
- **AND** fails on any unexplained count mismatch, missing client, missing node/inbound tuple, or silently skipped case

### Requirement: Real client data-plane verification

The framework MUST use both actual supported client engines (Xray and Mihomo) and MUST verify payload delivery through the intended proxy path for every applicable node/inbound/client tuple in the authoritative support inventory.

#### Scenario: Supported protocol transfers payload

- **WHEN** the harness consumes the Panel-issued Xray JSON subscription to build a runnable Xray client configuration, or Mihomo loads the Panel-issued Mihomo YAML subscription, and the client connects using a supported inbound
- **THEN** it transfers a unique payload through the intended inbound
- **AND** the controlled external endpoint records the exact request ID and payload
- **AND** the evidence proves that traffic egressed from the intended Master or Worker node
- **AND** client exit status alone is not accepted as proof of successful traffic

#### Scenario: Prohibited destination remains inaccessible

- **WHEN** a client attempts to reach a destination excluded by the configured policy
- **THEN** the connection or request is denied according to the documented policy
- **AND** the external fixture confirms that no prohibited payload was received

### Requirement: Deterministic DNS and ACME fixtures

The framework MUST provide controlled DNS and ACME fixtures. Certificate issuance MUST use the operator's actual Certbot webroot HTTP-01 flow against a local ACME fixture; pre-seeded certificates and mocked challenge success are prohibited.

#### Scenario: Certificate issuance and renewal

- **WHEN** the operator performs certificate issuance or renewal in the local E2E topology
- **THEN** Certbot invoked by the real operator obtains the certificate from the local ACME test server using the explicit test-only mode
- **AND** the fixture DNS and Pebble challenge validator reach the target's real NGINX/webroot HTTP-01 challenge path
- **AND** an independent client verifies the resulting certificate chain, SAN, validity, and required TLS version
- **AND** the fixture CA is not added to global system trust

#### Scenario: DNS A/AAAA and TTL behavior

- **WHEN** the fixture changes A/AAAA answers and TTL values for a test name
- **THEN** the suite observes the expected address family, answer, and cache-expiry behavior from the target and the independent client
- **AND** IPv6 assertions are limited to configurations the product declares supported

#### Scenario: NXDOMAIN and stale-answer handling

- **WHEN** the fixture returns NXDOMAIN or deliberately stale/wrong A/AAAA answers
- **THEN** the operator's bounded retry/failure behavior is observed and recorded
- **AND** stale or incorrect resolution cannot produce a false successful ACME issuance or data-plane assertion

#### Scenario: ACME challenge and service failure

- **WHEN** the suite injects HTTP-01 challenge failure or makes the local ACME directory unavailable
- **THEN** the operator follows its documented failure/rollback contract
- **AND** the previous working service state is independently verified where rollback is promised
- **AND** the result is not classified as PASS unless the expected state is independently verified

### Requirement: Camouflage decoy and certificate lineage

Every installed host MUST serve the product's camouflage decoy. The cover apex is the last two labels of `panel_domain`; the apex and `www.<apex>` MUST resolve to the host, terminate on the loopback decoy listener, serve the rendered cover site, and be covered by the REALITY certificate lineage. The port 80 ACME vhost MUST stay reachable on Master and Worker so renewal keeps a working HTTP-01 path.

#### Scenario: Decoy renders for the derived apex

- **GIVEN** a `panel_domain` with at least three labels, and apex plus `www.<apex>` resolving to the host's IPv4 address
- **WHEN** the operator completes installation or a domain change
- **THEN** the cover site contains the expected `*.html`, `*.css`, and `*.svg` assets with the derived brand and no surviving `{{` placeholder
- **AND** apex and `www` SNI terminate on the loopback listener while every VPN SNI keeps its own route
- **AND** the decoy listener is unreachable from client networks and exposes no Panel, API, or management path

#### Scenario: Unresolvable cover names block rendering

- **GIVEN** either the apex or `www.<apex>` does not resolve to the host's IPv4 address
- **WHEN** the operator attempts to install or re-render the decoy
- **THEN** it refuses before issuing the lineage and reports the resolution failure
- **AND** no partial decoy configuration or stale `sites-enabled` entry remains

#### Scenario: Worker keeps its decoy and ACME route

- **GIVEN** a provisioned Worker host
- **WHEN** the Worker is installed, restarted, or reconfigured
- **THEN** its port 80 ACME vhost remains reachable for renewal
- **AND** its decoy listener and SNI routes are unchanged unless the domain actually changed

### Requirement: Private test CA trust for both client engines

Certificates issued by the local ACME fixture MUST be trusted by both client engines without changing global system trust. The Xray client MUST receive the fixture CA through explicit `tlsSettings.certificates` entries with `usage: verify`, because Xray ignores `SSL_CERT_FILE`; Mihomo, curl, and the Python clients MUST use the scoped bundle. A missing anchor MUST fail the case with a chain error rather than pass silently.

#### Scenario: Fixture chain is trusted by Xray and Mihomo

- **WHEN** both clients run against every TLS transport provisioned with a fixture-issued certificate
- **THEN** each TLS session completes and the payload is transferred
- **AND** the fixture CA is absent from system trust stores
- **AND** removing the verify anchors turns the same case into a chain-verification failure

### Requirement: Non-bypassable node egress attribution

The framework MUST isolate client ingress, management, and node-egress networks. Trusted/untrusted clients and Control MUST NOT share the external fixture's node-egress network. Master and Worker MUST have distinct observable egress identities, and the external fixture MUST accept product traffic only from that network.

#### Scenario: Worker data-plane traffic cannot bypass Worker

- **WHEN** a client sends a payload through a Worker-issued inbound
- **THEN** the external fixture receives the exact payload with the expected Worker source identity
- **AND** direct client-to-fixture and Control-to-fixture connections are denied
- **AND** Master-originated egress for a Worker-targeted case is rejected as incorrect attribution
- **AND** a client-supplied path marker without matching network-source evidence is insufficient for PASS

### Requirement: Podman-only Master address selection for Worker provisioning

The Podman adapter MUST invoke the real `gowave-auto.sh node add` command and use a validated Master address from the run-scoped management network. The override MUST require explicit Podman test-mode opt-in and MUST be rejected outside that mode. Live VPS target checks and the real SSH, firewall, Panel API, and Worker installation paths MUST remain unchanged.

#### Scenario: Worker provisioning uses the actual private Master address

- **GIVEN** Master and Worker are attached to a run-scoped Podman management network
- **WHEN** the suite invokes the real `gowave-auto.sh node add` from Master with the Podman-only address override
- **THEN** the operator uses the verified Master address reachable by Worker for its firewall allow rule
- **AND** the Worker observes that same source address on the real mTLS connection
- **AND** public IP echo services are not required for this Podman case
- **AND** the override is rejected when the Podman test-mode opt-in is absent or the address is not assigned to Master on that network

### Requirement: Fail-closed local ACME test mode

Both Master and Worker scripts MUST accept a local ACME fixture only under an explicit test-only opt-in. The fixture endpoint and CA MUST be pinned; the production/Staging allowlist and default MUST remain unchanged, and arbitrary ACME URLs MUST remain rejected.

#### Scenario: Pebble endpoint is rejected outside test mode

- **GIVEN** the test-only ACME opt-in is absent or disabled
- **WHEN** the operator is configured with the Pebble directory URL or any arbitrary ACME URL
- **THEN** both Master and Worker validation reject the URL before certificate issuance
- **AND** the existing Let's Encrypt Staging/Production allowlist and default behavior remain unchanged

#### Scenario: Arbitrary ACME URL is rejected inside test mode

- **GIVEN** the test-only ACME opt-in is enabled
- **WHEN** the operator is configured with a directory URL other than the exact pinned fixture endpoint
- **THEN** Master and Worker reject the URL before any ACME request

### Requirement: Security and network isolation verification

The framework MUST test SSH trust, mTLS authentication, and network policy from independent trusted and untrusted origins.

#### Scenario: Unauthorized management access

- **WHEN** an untrusted client attempts SSH or management-plane access to the Worker
- **THEN** the connection is denied
- **AND** an allowed management client continues to connect using the configured trust material

#### Scenario: SSH host-key pinning rejects mismatch and supports rotation

- **GIVEN** the Control-to-Master or Master-to-Worker SSH connection uses a pinned host key
- **WHEN** the peer presents a different key without an authorized rotation procedure
- **THEN** the SSH operation fails before executing a remote command
- **AND** after the expected key is rotated through an explicit trust-update step, the new key is accepted and the old key is rejected

#### Scenario: mTLS rejects invalid client certificates

- **WHEN** the caller presents a missing, untrusted, or expired client certificate
- **THEN** the Worker rejects the TLS handshake before the application handler
- **AND** a valid replacement certificate restores the authorized path
- **AND** certificate revocation is tested only when the deployed trust mechanism actually enforces CRL/OCSP or an equivalent denylist; otherwise the revocation case is NOT_APPLICABLE with the mechanism limitation recorded

### Requirement: Lifecycle recovery acceptance

The framework MUST exercise Panel and Worker backup/restore through the product's supported interfaces and the currently exposed stable-to-dev channel update (`gowave-auto.sh channel dev`) with its real snapshot rollback. It MUST NOT invent a general version-upgrade or downgrade interface that the product does not expose. The current dev-to-stable transition is NOT_APPLICABLE unless a separately documented migration/downgrade contract establishes that it is safe.

#### Scenario: Restore Panel and Worker backups

- **WHEN** a valid Panel archive and a valid Worker Node archive are restored to their respective compatible targets after real operator provisioning
- **THEN** the Panel database, environment, state, managed NGINX/ACME data, and Worker environment are restored according to the archive type contract
- **AND** the Worker returns to the expected registered/healthy state
- **AND** a real Xray client and a real Mihomo client can use the restored subscriptions and transfer payloads

#### Scenario: Failed channel update rolls back

- **WHEN** the supported stable-to-dev channel update is deliberately failed after its snapshot has been captured
- **THEN** the operator's actual snapshot rollback restores the previous database, binaries, frontend, environment, NGINX/ACME state, and installation state
- **AND** the previous API state and real Xray/Mihomo client data-plane behavior are verified after rollback

### Requirement: Backup archive confidentiality

The framework MUST treat Panel and Worker backup archives as secret-bearing files. The current archive formats are unencrypted and contain credentials and/or private material. Archives MUST remain in a run-private ephemeral volume with restrictive permissions and MUST NOT be uploaded to CI artifacts, attached to reports, or printed to logs. Only sanitized metadata, checksums, and independent restore assertions may be exported.

#### Scenario: Backup archives are excluded from exported evidence

- **WHEN** Panel and Worker backup archives are created during a test run
- **THEN** they remain mode-restricted in run-private storage
- **AND** no archive bytes or embedded credentials/private keys appear in CI artifacts, reports, or logs
- **AND** cleanup removes the run-private archive storage

### Requirement: Failure injection and recovery

The framework MUST support deterministic injection of dependency, network, service, filesystem, and process failures.

#### Scenario: Recovery after Worker outage

- **WHEN** the Worker is stopped or isolated during an established test
- **THEN** the expected degraded behavior is observed
- **AND** after the fault is removed, the Worker returns to the expected healthy state and client traffic succeeds again

#### Scenario: Interrupted operator execution

- **WHEN** the operator is terminated during a supported lifecycle phase
- **THEN** the system is left in a documented recoverable or safely failed state
- **AND** a subsequent supported retry or rollback restores the expected state

### Requirement: Independent topology CI gates

The framework MUST publish separate required CI jobs and reports for All-in-One and Multi-Node acceptance. Missing, skipped, or incomplete topology jobs MUST prevent an overall PASS. Lifecycle CI MUST gate changes to backup, restore, channel update, and rollback.

#### Scenario: One topology job is absent or incomplete

- **WHEN** CI evaluates a change requiring product-level Podman acceptance
- **THEN** both All-in-One and Multi-Node jobs execute as separate required checks
- **AND** a missing, skipped, blocked, or incomplete job prevents an overall acceptance PASS

### Requirement: Pre-push and pull-request acceptance gate

The full All-in-One and Multi-Node suites MUST run automatically before every push and as separate required pull-request checks, without live credentials and within the runtime budget declared in the protocol/client matrix. A run that exceeds the budget or omits cases MUST report INCOMPLETE and MUST NOT pass.

#### Scenario: Pre-push run blocks a regressed change

- **GIVEN** a contributor has installed the documented pre-push entrypoint
- **WHEN** a change breaks a covered behavior
- **THEN** the affected topology reports FAIL with its case IDs
- **AND** the push is blocked until the suite passes or the run is explicitly bypassed outside the gate

#### Scenario: Budget overrun is not a truncated pass

- **WHEN** the declared runtime budget is exhausted before every case ran
- **THEN** the suite reports INCOMPLETE naming the unexecuted cases
- **AND** no aggregate job may convert that run into PASS

### Requirement: Coverage completeness and error paths

The framework MUST keep a checked-in inventory mapping every in-scope behavior to at least one case, and each behavior's error paths MUST be exercised. The inventory MUST cover installation, provisioning, subscription representations, data plane, decoy, TLS/DNS/ACME, network policy, lifecycle, and failure injection. The audit MUST fail when a behavior has no case or a case maps to no behavior, and shared contracts with the live acceptance capability MUST be asserted identically.

#### Scenario: Unmapped behavior or orphan case fails the audit

- **WHEN** the coverage audit runs against the inventory
- **THEN** a behavior with no case, a behavior covered only on its happy path, and a case mapped to no behavior each produce a failure naming the item

#### Scenario: Shared contract diverges from live acceptance

- **WHEN** this capability and the live acceptance capability assert the same product contract
- **THEN** their observable outcomes and expected counts agree
- **AND** a divergence is reported as a defect in this capability, not accepted as a container-only variant

### Requirement: Case incubation and promotion path

Both acceptance suites MUST share one case catalog. A new case MUST be implemented in the Podman suite first and promoted to the live suite only after its Podman runs are stable and reviewed; after promotion it MUST assert the same observable outcome in both environments. A case that cannot run in containers MUST be tagged live-only with a written reason. The suites MUST NOT keep independent definitions of the same behavior.

#### Scenario: New case starts in Podman

- **GIVEN** a product behavior needs new acceptance coverage
- **WHEN** the case is added to the catalog
- **THEN** it enters with an incubating state and a Podman driver
- **AND** no live driver is created before the promotion criteria are met

#### Scenario: Promotion keeps one definition

- **WHEN** an incubating case is promoted
- **THEN** the same case ID and assertion text run against the live environment
- **AND** the Podman suite keeps running that case as a regression
- **AND** divergent assertion text for the same ID fails the catalog audit

#### Scenario: Live-only case states its reason

- **WHEN** a live scenario cannot be reproduced in containers
- **THEN** it carries the live-only state with the specific environment limitation
- **AND** its absence from the Podman run is reported as a justified exclusion, not as an unexpected skip

### Requirement: Live scenario parity

The Podman suite MUST provide a case for every live acceptance scenario whose behavior is reproducible in containers. Of the current 125 live scenarios, 115 are container-reproducible, 8 are partially reproducible, and 2 are live-only. Partial cases MUST state which part the container proves and which part only the live run proves. The parity inventory MUST be checked in and MUST fail when a live scenario has neither a Podman case nor a justified classification.

#### Scenario: Parity inventory matches both suites

- **WHEN** the audit compares live scenario IDs against catalog entries
- **THEN** every scenario is classified as container, partial, or live-only
- **AND** an unclassified scenario fails the audit

#### Scenario: Partial case splits the proof

- **GIVEN** a partial case such as real Let's Encrypt issuance
- **WHEN** the Podman suite runs it
- **THEN** the container asserts the operator and lineage mechanics against the fixture CA
- **AND** the live run remains the only source of truth for public issuance

#### Scenario: Podman-first case has a promotion target

- **WHEN** a Podman case asserts a contract the live suite does not cover yet
- **THEN** the catalog records its promotion target and owning live requirement
- **AND** the case is still executed in the pre-push gate

### Requirement: Trustworthy result and diagnostics

Every case MUST produce structured evidence and sanitized diagnostics. Unexpected skips, blocked cases, or partial execution MUST NOT be reported as a successful acceptance run.

#### Scenario: Secret redaction

- **WHEN** diagnostics contain known sentinel credentials or private material
- **THEN** exported reports and artifacts contain no occurrence of those sentinels

#### Scenario: Unexpected skip

- **WHEN** a required case is skipped or blocked without an approved NOT_APPLICABLE rationale
- **THEN** the acceptance suite fails or reports INCOMPLETE, never PASS

### Requirement: Safe isolation and cleanup

Every run MUST use uniquely labelled disposable resources and cleanup MUST be scoped to resources created by that run.

#### Scenario: Cleanup after failure

- **WHEN** a suite fails, times out, or receives a termination signal
- **THEN** cleanup removes only resources carrying the current run identity
- **AND** no unrelated host/container resources or firewall configuration are modified
- **AND** any preserved debugging environment is explicit and reported
