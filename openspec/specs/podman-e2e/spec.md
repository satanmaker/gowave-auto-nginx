# Podman E2E Specification

## Purpose

Prove each released installer against observable product behaviour on both acceptance topologies, by running the real commands in rootful Podman on a pinned image instead of asserting what the documentation says they do.

## Requirements

### Requirement: Independent All-in-One acceptance topology

The test framework MUST provide an isolated All-in-One topology that starts from a clean supported Linux image and invokes the repository's real `gowave-auto.sh install` command in the target host context. It MUST NOT manually perform product provisioning steps that the operator is expected to perform.

#### Scenario: All-in-One clean installation

- **WHEN** the All-in-One acceptance suite is executed against a clean disposable target
- **THEN** it invokes the real operator in the supported full-install mode
- **AND** verifies the installed services — including the in-panel update trigger the installer arms, its
  runtime directory, both `gowave-update.*` units and the enabled path unit — Panel/API readiness, TLS
  endpoint, and configured data-plane endpoint independently
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

#### Scenario: Worker dispatch is observed without the secret

- **WHEN** the Master runs the real `gowave-auto.sh node add` that provisions the Worker
- **THEN** the Master traces its own descendant exec calls with
  `strace -f -v -s 32*PAGE_SIZE -e trace=execve,execveat`, and before reading that trace the
  observer proves on the same host that a sentinel after byte 32 survives in both an `execve`
  and an `execveat` record and that a 128-element argv arrives in order with its sentinel last
- **AND** only a complete trace passes: every argv vector whole, the SSH client's own exec record
  present, and no `SECRET_KEY` in raw or encoded form in any argv
- **AND** the trace is removed on the Master, so the `envp` strace printed never enters a report or a log
- **AND** the observation covers the Master-side process tree only, not the remote Worker beyond the
  SSH boundary

#### Scenario: Multi-Node deployment with one failed node and partial success

- **GIVEN** a Multi-Node deployment with multiple Workers planned
- **WHEN** one Worker fails onboarding while the Panel installation and another Worker succeed
- **THEN** the Panel deployment and the successful Worker onboarding continue
- **AND** the failed Worker is recorded with its target, phase and diagnostic reason
- **AND** the command exits with the partial-success code distinct from a failed Panel installation
- **AND** the per-node summary distinguishes successful and failed nodes

#### Scenario: The composed wizard corrects a duplicate cover domain and retries one Worker

- **GIVEN** a Multi-Node deployment whose Worker is registered and connected in the Panel
- **WHEN** the interactive wizard reads a plan whose second Worker enters a cover domain the
  plan already holds, onboards a batch in which that Worker fails and the registered one
  succeeds, and offers the selective retry
- **THEN** only the repeated cover-domain prompt is asked again and every earlier answer survives
- **AND** the successful Worker is printed as registered and verified only with the uuid the
  Panel's own node list answered for it
- **AND** the failed Worker is recorded with its phase and diagnostic and the batch exits with
  the partial-success code
- **AND** the retry list names the failed Worker alone, only that node is onboarded again, and
  the operator is returned to the menu
- **AND** the Panel's node list is unchanged, because the plan was entered but never applied

#### Scenario: Add-node refused by Panel API verification failure

- **GIVEN** an existing Panel whose API identity or reachability verification fails
- **WHEN** an add-node attempt is made against that Panel
- **THEN** the attempt reports the failed verification and does not begin any remote node mutation
- **AND** no Worker-side deployment is attempted and no credentials are transmitted

### Requirement: Independent Panel-only acceptance topology

The test framework MUST provide an isolated Panel-only topology that installs the Panel and the static camouflage site on one clean supported image through the repository's real `gowave-auto.sh install --panel-only` command, provisioning no traffic plane — no local node, no backend listener, no Vision inbound — and MUST verify the resulting host and Panel state through the real API.

#### Scenario: Panel-only clean installation

- **WHEN** the Panel-only acceptance suite executes the documented `install --panel-only` command against a clean disposable target
- **THEN** the host runs the Panel, NGINX and the static decoy while declaring no node unit, running no traffic-engine process and listening on neither of the two backend ports
- **AND** the credentials file is root-owned with mode `0600`, exactly the Panel and camouflage lineages are issued, and the camouflage name answers with the static site instead of any product content
- **AND** the Panel API reports the mode's own end state — no host, node, config profile or internal squad — with the default user and a scoped API token present, while `state.json` names the mode, holds an empty node array and carries no local-node fields
- **AND** the run records a machine-readable result and sanitized diagnostics

#### Scenario: Panel-only Worker registration

- **WHEN** the Panel-only Master registers a Worker through the real `gowave-auto.sh node add`
- **THEN** the Panel holds one internal squad that allows an inbound, one host record per matching inbound whose `ALLOW_ONLY` squad list names the identifier `state.json` stored, and the registered Worker as its only node
- **AND** a host record carrying a null squad entry either is refused by the Panel with the host count unchanged, or is stored without naming that identifier, and the probe removes whatever it created

#### Scenario: Add-node refused by Panel API verification failure

- **GIVEN** an existing Panel whose API identity or reachability verification fails
- **WHEN** an add-node attempt is made against that Panel
- **THEN** the attempt reports the failed verification and does not begin any remote node mutation
- **AND** no Worker-side deployment is attempted and no credentials are transmitted

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

Every installed host MUST serve the camouflage decoy. The Master's cover apex MUST be the selected name, never a suffix guess, and a deployment that selects none MUST infer none. A Worker MUST own no apex: it serves its camouflage site under its own camouflage name, which is also its REALITY SNI. Each name used MUST resolve to its host, reach that host's camouflage listener, serve the rendered site and be covered by its REALITY lineage.

#### Scenario: Decoy renders for the apex each role owns

- **GIVEN** the Master's selected cover apex and its optional `www` alias resolving to the Master's IPv4 address, and a Worker whose own camouflage and REALITY names resolve to it
- **WHEN** the operator completes installation or a domain change
- **THEN** the case reports the name each role decided — the Master's selection, and for the Worker only its own camouflage name — and never a first-two-label guess or an apex the role does not own
- **AND** the cover site contains the expected `*.html`, `*.css`, and `*.svg` assets with that name's brand and no surviving `{{` placeholder
- **AND** the Master's apex and `www` SNI terminate on the loopback decoy listener while every VPN SNI keeps its own route, and the Worker's camouflage name terminates on its own decoy
- **AND** the decoy listener is unreachable from client networks and exposes no Panel, API, or management path

#### Scenario: Unresolvable cover names block rendering

- **GIVEN** a selected apex that is not a fully qualified domain name, a selected apex equal to the Panel's own name, or either the apex or `www.<apex>` not resolving to the Master's IPv4 address
- **WHEN** the operator attempts to install or re-render the decoy
- **THEN** it refuses before issuing the lineage and reports the reason, naming the records that did not resolve
- **AND** no partial decoy configuration or stale `sites-enabled` entry remains
- **AND** a Worker claims neither half of that apex and holds no lineage naming either, so the refusal cannot be answered by issuing the Master's names on the Worker

#### Scenario: Worker keeps its decoy and ACME route

- **GIVEN** a provisioned Worker host
- **WHEN** the Worker is installed, restarted, or reconfigured
- **THEN** its port 80 ACME vhost remains reachable for renewal, redirects its own primary, camouflage and Vision names to HTTPS, and refuses every other host
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

### Requirement: Harness ceilings never decide a product verdict

A container command ceiling MUST be sized to the work it bounds and MUST be capped by the run's remaining budget, so it can fire inside the run. A ceiling or budget that fires MUST be published as INCOMPLETE naming the command and the limit that fired, never as a product FAIL — the command-level counterpart of *Budget overrun is not a truncated pass* — and a case whose evidence a timeout cut short MUST NOT assert about that evidence.

#### Scenario: A slow legitimate step keeps its ceiling

- **GIVEN** a deployment step whose work — an image pull, or a package install inside an image build — legitimately outlasts the default container command ceiling
- **WHEN** the harness runs that step
- **THEN** the command carries a ceiling sized for that work and no larger than the run's remaining budget
- **AND** a step that completes inside its ceiling produces no verdict about the product from the harness clock

#### Scenario: A budget kill inside a cleanup probe stays INCOMPLETE

- **GIVEN** a run whose remaining budget expires while a case is restoring a configuration it changed
- **WHEN** the case is finished
- **THEN** the case reports INCOMPLETE naming the exhausted budget
- **AND** the restore is still attempted
- **AND** the deadline is not converted into a failed assertion about the restored configuration

#### Scenario: A ceiling that fires names its own limit

- **GIVEN** a command that outlasts even the ceiling sized for it
- **WHEN** the case ends
- **THEN** the verdict names the command and the ceiling that fired
- **AND** it does not present the timeout as a defect in the product

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

Every case MUST produce structured evidence and sanitized diagnostics. Unexpected skips, blocked cases, or partial execution MUST NOT be reported as a successful acceptance run. A case that needs a successful installation MUST gate on it and MUST report BLOCKED when no installation succeeded, instead of asserting about a host that was never installed.

#### Scenario: Secret redaction

- **WHEN** diagnostics contain known sentinel credentials or private material
- **THEN** exported reports and artifacts contain no occurrence of those sentinels

#### Scenario: Unexpected skip

- **WHEN** a required case is skipped or blocked without an approved NOT_APPLICABLE rationale
- **THEN** the acceptance suite fails or reports INCOMPLETE, never PASS

#### Scenario: Install-dependent case without a successful installation

- **GIVEN** a run in which the installation failed or never executed
- **WHEN** a case that needs the installed host runs
- **THEN** that case reports BLOCKED naming the install case it depends on
- **AND** the installation failure is reported once, by the install case, rather than again as a defect in whatever the dependent case would have inspected

### Requirement: Safe isolation and cleanup

Every run MUST use uniquely labelled disposable resources and cleanup MUST be scoped to resources created by that run.

#### Scenario: Cleanup after failure

- **WHEN** a suite fails, times out, or receives a termination signal
- **THEN** cleanup removes only resources carrying the current run identity
- **AND** no unrelated host/container resources or firewall configuration are modified
- **AND** any preserved debugging environment is explicit and reported

### Requirement: Parallel distribution acceptance with isolated evidence
The acceptance harness SHALL cover Debian 12, Debian 13, Ubuntu 24.04 and Ubuntu 26.04 in parallel locally and in GitHub Actions. Each run SHALL have independent artifacts and resource ownership. Existing required GitHub status check names and event applicability SHALL remain stable.

#### Scenario: GitHub Actions runs the distribution matrix
- **WHEN** an event enables an acceptance job type
- **THEN** its four distribution cells can execute concurrently on separate runners, publish uniquely named artifacts even on failure, and its stable required check passes only if all four cells pass.

#### Scenario: Four local runs start together
- **WHEN** the operator launches one acceptance suite for all four distributions on the same Podman host
- **THEN** the harness reserves non-overlapping control and data networks without a discovery-to-creation race, runs the suites concurrently, and returns independent results plus a non-zero aggregate status if any required result is unsuccessful or missing.
- **AND** cleanup of one run does not remove another run's resources.

#### Scenario: NGINX package policy is verified
- **WHEN** the pinned-package acceptance coverage runs
- **THEN** it reads back the actual installed NGINX package revision, source and Stream capability in the applicable roles and checks the official path, permitted fallback and refusal without activation.

#### Scenario: Data-plane evidence is read from the edge's own log
- **WHEN** a data-plane case proves that a request reached the intended host
- **THEN** it reads the new lines of that host's stream access log and requires a line naming the request's SNI and client address.
- **AND** a missing line fails the case, while a request that the edge never logged is never reported as a pass.
- **AND** the raw packet capture is not the witness: it is a laboratory instrument that observes nothing in an unprivileged container namespace, so an empty capture can no longer decide a verdict.

### Requirement: Operable harness evidence and selected runs
Every finished run SHALL leave a compact, world-readable summary beside its full
result, and the suite SHALL be runnable for a named subset of cases against an
already provisioned cell. A status command SHALL report each running cell's
topology, distribution, elapsed time and current step without requiring root,
and no declared number SHALL have a second source.

#### Scenario: A finished run leaves a compact summary
- **WHEN** a run finishes, green or not
- **THEN** `summary.json` sits beside `result.json` in mode 0644 with the run id, topology, distribution, overall status, per-status counts and one bounded entry per non-PASS case.
- **AND** reading the verdict needs neither root nor the full result.

#### Scenario: The phase of a running cell is one command away
- **WHEN** the operator asks what is running
- **THEN** the status command prints one line per cell with its topology, distribution, elapsed time, the step its child command names, the diagnostic-bundle count and whether a verdict exists.
- **AND** it reads the process tree and the artifact directory rather than an unprivileged container list, because a rootful run is invisible there.

#### Scenario: Selected cases run without reinstalling the cell
- **WHEN** a fix has to be checked by a named subset of cases
- **THEN** `--only` runs exactly those cases in the suite's declared order, an unknown id exits 2 before a container exists, and `--keep` leaves the run's hosts and its run directory in place and prints how to reuse them.
- **AND** `--reuse <run_id>` adopts a kept run only when the setup that run needs still exists; a kept cell it cannot adopt is refused with the missing part named, never reinstalled under the name of reuse.
- **AND** a run records the cases it executed and its own run directory, so a selected run is never presented as a full suite.

#### Scenario: A re-provisioning step cannot run on the default timeout
- **WHEN** a harness step re-provisions a host
- **THEN** it passes an explicit budget, and a test refuses such a step that would fall back to the default exec timeout.
- **AND** declared deadlines, budgets and tier totals are read from the matrix manifest by the tests and the documentation rather than repeated as literals.

### Requirement: Node installation is proven without the GitHub API

An acceptance run SHALL be able to prove that node installation needs no request to `api.github.com` by making that host unreachable on the deployment contour, and SHALL distinguish that proof from a run that merely happened to have quota left.

#### Scenario: A blocked API contour still installs the node

- **GIVEN** an acceptance topology whose containers resolve `api.github.com` to an address nothing answers on
- **WHEN** node installation runs with `XRAY_SERVER_VERSION` unset or naming the pin
- **THEN** the installation succeeds, the core interrogated inside the node's container reports the pinned version, and the step's own record names the pinned archive digest

#### Scenario: The opt-out control fails on the same contour

- **GIVEN** the same blocked contour and a host with no installed core, so the upstream installer would have to fetch one
- **WHEN** node installation runs with `XRAY_SERVER_VERSION=latest`
- **THEN** the installation fails naming the blocked host, no `rw-core` is created, and the passing run is shown to have exercised the pinned path rather than an unreachable one

#### Scenario: Evidence is read from the installed side

- **GIVEN** a passing blocked-API run
- **WHEN** its evidence is written
- **THEN** it records the version read from the installed core inside the node's container, the archive digest the step verified, and the run's commit — three separate facts, because the pin names the release archive and the installed binary has no digest of its own
