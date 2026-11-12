# Design: Full Product-Level Podman E2E

## Context and current boundary

The current `tests/podman_testbed.sh multi-node` target creates isolated Control, Master, and Worker systemd containers. It validates pinned Master-to-Worker SSH, TLS 1.3 mTLS positive/negative cases, and source filtering for Worker TCP/3002. The mTLS endpoints are synthetic listeners created inside the testbed image; no product control-plane service is involved. This is valuable transport coverage, but it does not run the GoWave product lifecycle.

The new framework must close that gap without conflating container-level acceptance with public VPS acceptance.

## Design principles

1. **Production path, test infrastructure only.** The test harness may create networks, fixtures, credentials, and disposable nodes. It must not implement product provisioning steps itself. Installation, registration, configuration, backup, restore, supported channel updates, and rollback must be invoked through the repository's real operator or the product's documented interfaces.
2. **Black-box first.** Assertions must observe externally visible behavior: API responses, TLS handshakes, systemd state, socket availability, client import results, and payloads received by a controlled endpoint.
3. **No self-attestation.** An operator success message, generated summary, or file-exists check is not sufficient evidence for a product acceptance claim.
4. **Real product components.** GoWave Panel/Node, Xray, NGINX, and both supported client engines (Xray and Mihomo) must be used. Mocks are allowed only for external dependencies that are explicitly outside the product boundary.
5. **Deterministic and isolated.** Every run gets a unique Podman network, volumes, credentials, domain namespace, and run ID. No shared host service or production endpoint may be modified.
6. **Explicit evidence.** Every case has a stable ID, preconditions, action, independent assertion, expected failure semantics, and evidence record.
7. **No false green.** PASS, FAIL, BLOCKED, NOT_APPLICABLE, SKIP, and INCOMPLETE are distinct. An unexpected SKIP/BLOCKED or incomplete phase fails the acceptance suite.

## Topologies

### All-in-One

A disposable systemd-enabled Linux container represents the target host. The real operator installs the complete supported All-in-One product topology. The test harness provides only external fixtures and client containers.

Logical roles:
- Control/runner: creates and owns the disposable topology, invokes the operator command on the target, runs API assertions, and coordinates clients; it is not a substitute for the product operator.
- All-in-One target: runs the real `gowave-auto.sh install` path and hosts Panel, local GoWave Node, NGINX, and Xray.
- DNS/ACME fixture: controlled DNS plus Pebble, reachable from the target and Pebble challenge validator.
- External test service: HTTP/HTTPS echo endpoint on a node-only egress network; it records request ID, exact payload, and source identity.
- Trusted Xray and Mihomo client containers: execute the real pinned client binaries against the two Panel-issued subscription formats.
- Untrusted client: negative network and authentication checks.

### Multi-Node

Use distinct disposable Linux systemd containers and isolated Podman networks:
- Control/runner: owns orchestration and evidence collection only.
- Master: runs the real `gowave-auto.sh install` path, Panel, local GoWave Node, NGINX, and Xray.
- Worker: provisioned from Master through the real `gowave-auto.sh node add` path and managed through the real Panel API.
- Trusted Xray and Mihomo clients: import the actual Master-issued subscriptions and send traffic to the intended Master or Worker inbound.
- Untrusted client: attempts prohibited management, direct-egress, and data-plane access.
- DNS/ACME fixture: controlled names and ACME test CA.
- External test service: records end-to-end payloads and node-specific source identity.

The Control container is a test orchestrator, not a new product provisioning implementation. Execute `gowave-auto.sh install` on the All-in-One target or Master, then `gowave-auto.sh node add` on Master for Worker provisioning. The harness may transport and invoke these commands, but MUST NOT reproduce their installation/API side effects. Do not point the existing Live VPS controller at private Podman addresses or weaken its public-target safety checks. A Podman-specific adapter is required because the current `node add` implementation discovers Master's address through public IP echo services; that public egress address is not necessarily the address Worker sees on the private Podman network. The operator implementation delivered by this change must expose a Podman-only, explicitly opted-in Master-address override, validate that the address is assigned to Master on the run-scoped management network, and reject the override outside Podman test mode. The adapter must still invoke the real `node add` path, SSH transport, firewall configuration, and Panel API registration.

## Container and OS fidelity

- Use systemd-enabled images based on the supported OS versions already declared by the repository compatibility matrix (`openspec/changes/gowave-auto-nginx/COMPATIBILITY_MATRIX.md` until that change is archived and its capability specs become authoritative).
- Run the operator against clean images with the same package manager and service manager assumptions as the target OS.
- Use rootful Podman for tests requiring namespace-local firewall administration, kernel networking controls, or privileged service installation. Rootless Podman may run only a clearly identified portable subset.
- Keep QEMU cold-boot coverage for actual boot behavior, kernel/systemd interactions, and cases that cannot be represented reliably in containers.
- Pin base images by immutable digest and record the resolved digest in test evidence.
- Do not assume privileged containers fully emulate a VPS host kernel or provider networking.

## Fixture services

### DNS

Provide a controllable authoritative DNS fixture for the test namespace. It must support A and AAAA records, TTL changes, missing records, NXDOMAIN, and deliberately stale/wrong answers. Cases must separately verify address-family selection, TTL/cache expiry, NXDOMAIN, and stale-answer handling from the target and an independent client. IPv6 behavior is asserted only when enabled/supported by the tested product configuration. The harness must record which resolver path was used and prevent a stale/wrong answer from being mistaken for successful ACME or data-plane behavior.

### ACME

**Current operator constraint:** the current Master-side `validate_acme_server()` in `modules/nginx.sh` and the duplicated Worker-side validation/lineage checks in `gowave-node-auto.sh` accept only the exact Let's Encrypt Staging and Production directory URLs. `check_acme_lineage()` also rejects an unrecognized renewal `server` value. Therefore Pebble is NOT usable through the current operator path as-is; simply starting a Pebble container does not make this scenario executable.

The implementation must add a narrowly scoped, explicit test-only ACME mode to both Master and Worker paths. The mode may accept only the exact fixture endpoint and its pinned test CA; it MUST NOT turn the ordinary `GOWAVE_ACME_SERVER` interface into an arbitrary-URL option. With test mode disabled, the existing exact Staging/Production allowlist and production default remain unchanged. With test mode enabled, only the configured fixture endpoint on the isolated Podman network is accepted, and arbitrary ACME URLs remain rejected. The test mode and endpoint must be propagated to Worker through the validated SSH stdin stream that `gowave-node-auto.sh` already uses to run the remote `bash -s` payload, not through argv or logs. Lineage reuse checks must recognize the fixture directory only in test mode and verify the certificate chain against the fixture CA rather than relying on the Let's Encrypt `(STAGING)` issuer marker. Certbot's TLS trust for the ACME directory and client-side trust for issued certificates must use a scoped CA bundle; the fixture CA must never be installed into global system trust. Xray builds its certificate pool from hardcoded system paths and ignores `SSL_CERT_FILE`, so the Xray client used by the suite must carry explicit `tlsSettings.certificates` entries with `usage: verify` pointing at the fixture CA in every TLS outbound; curl and the Python clients use the scoped bundle path instead. Without this, a correct fixture chain is reported as `certificate signed by unknown authority` and the TLS matrix fails for the wrong reason.

Use Pebble or an equivalent local ACME test server for issuance, renewal, challenge failure, and unavailable-server scenarios. Exercise the product's actual Certbot webroot HTTP-01 flow: fixture DNS must resolve the test FQDN to the target, Pebble's challenge validator must reach the target's real NGINX/webroot challenge path, and Certbot must obtain the certificate from the configured Pebble directory through the explicit test-only mode. Do not pre-seed certificates, call Certbot outside the operator path, or synthesize successful challenge responses. Use a test CA trusted only inside the fixture network. Public Let's Encrypt staging/production remains a separate live acceptance concern.

### External HTTP/HTTPS service

Provide a deterministic endpoint that:
- accepts unique request IDs and payloads;
- records the observed request and source identity;
- returns a verifiable response body/hash;
- supports controlled latency, errors, and unavailability;
- can distinguish direct host access from traffic that traversed the intended proxy/Worker path.

The test must prove data-plane traversal by inspecting the external endpoint's observed request and expected network path, not by trusting client exit status alone. In Multi-Node, clients and Control MUST NOT share the node-egress network with the external endpoint. Master and Worker receive distinct, observable egress identities; the endpoint accepts test traffic only on that egress network and records the source identity. Direct client-to-endpoint, Control-to-endpoint, and wrong-node egress attempts MUST be denied or produce a source identity that fails the case. A Worker-targeted inbound case passes only when the endpoint receipt identifies Worker as the egress source; a Master/Control source or missing attribution is FAIL/INCOMPLETE, never PASS.

### Client implementations

Use both actual supported client engines and every Panel subscription representation the product serves:

- base64 share-link list at `/api/sub/<shortUuid>` — the representation Xray-family clients actually import; the suite decodes it and asserts one link per proxy entry;
- Xray JSON at `/api/sub/<shortUuid>/v2ray-json` — served either as one config object with `outbounds` or as a list of complete per-profile configs; a list entry is a runnable config and is validated as such, while a bare object needs the minimal runtime wrapper required by the pinned Xray binary (for example, a local SOCKS inbound and routing);
- Mihomo YAML at `/api/sub/<shortUuid>/mihomo` and the compact `/clash` form.

The Panel User-Agent rule on the pinned version is "non-empty header required": absent and blank headers are rejected with 403, and any non-empty value is served. Send a client-identifying header for each representation, and assert both rejection cases separately rather than assuming a per-format allowlist. Do not replace the returned outbound with a hand-built shortcut, and do not pass a bare outbound object to `xray run` as though it were a complete core config. Neither client may replace protocol handshakes with synthetic TCP checks. Preserve product-generated per-host TLS/SNI/ALPN/path settings, and assert the `firefox` uTLS fingerprint that the product now emits for REALITY and TLS transports.

Maintain a versioned protocol/client matrix sourced from the repository's authoritative compatibility/protocol documentation and generated host/profile configuration. The current baseline is four core inbounds per node — VLESS REALITY, VLESS XHTTP/TLS, VLESS WebSocket/TLS, and Trojan gRPC/TLS — plus optional VLESS Vision/TLS. Every applicable inbound on every installed node must pass through both clients; one client or one node cannot stand in for the other.

## Protocol/client acceptance matrix

The implementation must publish a machine-readable matrix (for example, a checked-in YAML manifest) that maps each topology/node/inbound to both client engines, subscription representation, expected host/SNI/port/path/ALPN/fingerprint (`firefox` for REALITY and TLS transports), stable case ID, and the runtime budget the gate must respect. The matrix is generated or validated against the pinned product version and the real Panel response; it must not become a second hand-maintained source of truth.

| Topology | Node coverage | Vision enabled | Positive cases |
|---|---|---|---:|
| All-in-One | local node | no | 8 |
| All-in-One | local node | yes | 10 |
| Multi-Node | Master + Worker | neither | 16 |
| Multi-Node | Master + Worker | one node only | 18 |
| Multi-Node | Master + Worker | both | 20 |

Each inbound is tested once with Xray and once with Mihomo. Multi-Node counts include both Master and Worker endpoints. The optional Vision domain is independently configurable per node. A case count mismatch, missing client, missing endpoint, or unapproved NOT_APPLICABLE entry fails acceptance. These counts cover positive import/connect/payload-transfer cases only; negative and lifecycle cases are additive.

## Lifecycle and scenario model

Each scenario follows a common lifecycle:

1. Create isolated resources and record run identity.
2. Verify prerequisites and fixture health.
3. Start clean target nodes.
4. Invoke the real operator with explicit test configuration.
5. Wait for services using bounded readiness checks.
6. Verify product state independently through APIs and host/service interfaces.
7. Perform client-visible operations and verify payload delivery.
8. Execute negative/failure/recovery steps where applicable.
9. Capture sanitized evidence.
10. Clean up resources, or preserve them only when explicitly requested for debugging.

The framework must support cleanup on normal completion, assertion failure, timeout, SIGINT, SIGTERM, and abrupt runner termination where the host can recover stale resources by run ID/labels.

## Scenario groups and required assertions

### A. Provisioning and installation

- AIO-01: clean All-in-One install completes; expected services are active; API and inbound checks succeed.
- AIO-02: rerun installation/provisioning; no duplicate resources or drift; externally observed behavior remains correct.
- MN-01: clean Multi-Node install; Master and Worker are independently provisioned.
- MN-02: Worker is registered through the real Panel API and reaches the expected healthy/online state.
- CFG-01: test all four Multi-Node Vision combinations (neither, Master-only, Worker-only, both); only the configured node receives the Vision certificate/inbound/Panel host/NGINX route, and core traffic remains functional on both nodes.
- CFG-02: invalid/missing required settings fail before destructive changes.
- CFG-03: secrets are absent from logs, reports, command traces, and CI artifacts.

### B. Panel/API lifecycle

- API-01: authenticate using the supported admin flow.
- API-02: create/manage a Node through real API contracts.
- API-03: create a user/client and fetch both real subscriptions with the required User-Agent headers; assert the no-User-Agent response against the pinned Panel policy.
- API-04: perform a documented client/configuration update where the pinned API supports it; verify changed Panel state and newly fetched subscription/Worker state. If no supported update operation exists, record NOT_APPLICABLE with the exact API-contract evidence rather than inventing an endpoint.
- API-05: revoke user/client access and prove old credentials no longer provide data-plane access.
- API-06: Panel/Worker state remains consistent after restart and transient API failure.

Do not invent API paths or payloads in the harness. Derive requests from the product's current API contract or supported client library and pin contract fixtures to the tested product version.

### C. SSH, mTLS, and trust

Retain current transport tests and extend them with a wrong pinned SSH host key (must fail before remote command execution), authorized host-key rotation (new key accepted, old key rejected), missing/untrusted/expired mTLS client certificates, and recovery after legitimate certificate rotation. Assert caller outcome and receiver-side evidence. Test certificate revocation only if the deployed TLS trust mechanism actually enforces CRL/OCSP or an equivalent denylist; otherwise record NOT_APPLICABLE with the limitation.

### D. NGINX, TLS, and ACME

- Validate rendered NGINX configuration with the actual binary before reload.
- Verify TLS handshake, certificate SAN, validity, chain, and required protocol versions from an independent client.
- Exercise Pebble issuance and renewal through the product's actual ACME path.
- Exercise challenge failure, resolver failure, expired/invalid certificate, unavailable ACME, and failed reload.
- Verify the previously working configuration remains active after failed validation/reload.

Camouflage decoy surface, as shipped in `modules/nginx.sh`:

- The cover domain is derived from the last two labels of `panel_domain`; a `panel_domain` with fewer than three labels produces no cover lineage, and that branch is asserted separately.
- Before rendering, both the apex and `www.<apex>` must resolve to the host's IPv4 address; the suite must prove the failure path when either name does not resolve, because the operator refuses to render in that case.
- The rendered cover site must contain the expected assets (`*.html`, `*.css`, `*.svg`), carry no surviving `{{` placeholder, and use the brand derived from the apex's second-to-last label.
- The decoy terminates on the loopback listener `127.0.0.1:9443`, is never reachable from outside the host, and never exposes Panel/API or management paths.
- The REALITY certificate lineage covers the apex and `www.<apex>` in addition to the routing domain; SNI routing for both names lands on the decoy while every VPN SNI keeps its own route.
- The port 80 ACME vhost stays reachable on Master and on Worker so renewals keep working; a Worker install or reconfiguration must not delete it.
- A domain change re-renders the decoy and reissues the lineage without leaving stale `sites-enabled` entries.

### E. Subscription and data plane

For every applicable node/inbound/client tuple in the versioned matrix:
1. Obtain every served representation from the real Panel endpoint with a client-identifying User-Agent: the base64 share-link list, the Xray JSON config object or profile list, and the Mihomo YAML. Separately assert the absent-header and blank-header responses, which the pinned Panel rejects with 403.
2. Validate the returned content against the expected format and the Panel-issued host fields.
3. Load it into the corresponding real Xray or Mihomo binary without replacing the generated outbound with a hand-built shortcut.
4. Establish the actual protocol session to the intended Master or Worker inbound.
5. Send unique TCP and HTTP/HTTPS payloads through the proxy where supported.
6. Verify the external fixture received the exact request ID and payload and that its observed source identity is the intended node.
7. Verify the client and Control cannot reach the egress fixture directly and prohibited destinations remain unreachable.
8. Revoke access through the real Panel lifecycle; prove a fresh connection cannot transfer data and define separately whether existing sessions are terminated or merely expire according to the pinned product contract.
9. Restart the relevant service and verify expected recovery.

For Multi-Node, prove each endpoint's actual node path. Worker-targeted traffic must egress from Worker; Master-targeted traffic must egress from Master. The network topology must make direct client/Control access impossible, and the endpoint's observed source identity must distinguish Master from Worker. A client-provided path marker alone is not sufficient evidence because the client can assert it without traversing that node.

### F. Firewall and network isolation

Run probes from trusted client, untrusted client, Control, Master, and Worker contexts as appropriate. Validate both allowed and denied paths using actual connection attempts and service-level evidence. Include IPv4 and IPv6 only where the product claims support; otherwise assert IPv6 is disabled/closed according to the selected configuration.

Do not infer firewall correctness solely from nftables/iptables text output. Inspect rules for diagnostics, but make reachability assertions authoritative.

### G. Backup, restore, channel update, rollback

- Exercise the real backup interface and its two distinct archive types: Panel (`gowave-auto.sh backup --type panel`) and Worker Node (`gowave-backup.sh backup --type node`, invoked on Worker). The current Panel archive contains the Panel SQLite database, `.env`, `state.json`, managed NGINX configuration, and Let's Encrypt lineages. The current Worker archive contains its `.env` credentials only; it does not contain the Worker binary or OS image.
- Restore the Panel archive to a compatible target that has first been provisioned through the real operator; restore the Worker Node archive on its separately provisioned Worker. Do not imply that either archive is a bare-metal/system-image backup or that the Panel archive alone restores the remote Worker filesystem.
- Verify restored Panel API state, Worker registration/health, and actual Xray/Mihomo client traffic after both restores.
- Test corrupt/incomplete archive rejection without damaging the current installation.
- Exercise the currently exposed update operation, `gowave-auto.sh channel dev`, as a stable-to-dev channel transition. Verify service/API health and client data-plane behavior after the update. Do not describe this as a general arbitrary-version upgrade API.
- Inject a controlled post-update health failure and verify the operator's real snapshot rollback restores the prior database, binaries, frontend, environment, NGINX/ACME state, and `state.json`; verify the restored API and client data plane independently.
- Do not use dev-to-stable as an automatic rollback scenario: the current operator warns that newer Dev schema migrations may be irreversible and requires `--force`. Treat it as NOT_APPLICABLE unless a separately documented migration/downgrade contract is introduced.
- Verify repeated same-channel invocation is idempotent and repeated backup/restore operations preserve the documented state.
- Panel and Worker backup archives are currently unencrypted and contain credentials, database data, and/or TLS private keys. Keep them in a run-private mode-0600 ephemeral volume, never upload them as CI artifacts, and publish only sanitized metadata/checksums and post-restore assertions.

### H. Failure injection and recovery

Inject controlled failures: SSH unavailable, Panel unavailable, Worker unavailable, DNS failure/wrong answer, ACME unavailable, blocked port, packet loss/latency, invalid certificate, invalid NGINX config, full test filesystem, stopped Xray, interrupted operator process, and interrupted stable-to-dev channel update.

For each case define one expected contract: safe failure before mutation, bounded retry, rollback, or explicitly documented degraded state. Verify recovery after removing the fault. Never leave ambiguous partial state classified as PASS.

### I. Cleanup and diagnostics

- All created resources carry a unique run label.
- Cleanup removes only resources belonging to the current run.
- Cleanup never removes user-managed containers, networks, volumes, or host firewall rules.
- Preserve-on-failure is opt-in and must print the exact resource identifiers.
- Artifacts include JSON/JUnit summary, phase timeline, operator stdout/stderr, service logs, systemd status, socket/port inventory, firewall snapshot, DNS/TLS evidence, client logs, and external endpoint receipts.
- Redact passwords, tokens, private keys, subscription secrets, cookies, and sensitive URLs before artifact upload.
- A redaction test must use sentinel secrets and prove they do not appear in any exported artifact.

## CI tiers

- L0: unit, static analysis, shell lint, and API/schema contract tests.
- L1: focused component integration and existing transport acceptance.
- L2: full All-in-One Podman E2E.
- L3: full Multi-Node Podman E2E including real subscription and client traffic.
- L4: Panel/Worker backup and restore, supported channel update/rollback, failure injection, and recovery.
- L5: QEMU cold boot across the supported OS matrix.
- L6: separately authorized Live VPS acceptance for public DNS, public ingress, public ACME, provider firewall, and external network reachability.

L2 and L3 are also the local gate: a pre-push entrypoint runs both topologies with the pinned fixtures and no live credentials, and the same targets back the required pull-request jobs. The declared runtime budget in the matrix manifest is the ceiling for that gate; exceeding it reports INCOMPLETE instead of silently truncating cases, and the suite must never trade a case away to fit the budget.

L2 and L3 MUST be separate required CI status checks before the framework or this OpenSpec change can be declared complete and archived. A topology job that is missing, skipped, blocked, or not executed cannot be hidden by an aggregate green job. L4 MUST be a required check for changes affecting backup, restore, supported channel updates, rollback, or the corresponding recovery paths. L5 follows the existing compatibility triggers. L6 is never an implicit PR side effect and requires explicit disposable-host authorization. Until both L2 and L3 are implemented and required, the repository must describe product-level Podman E2E as planned/incomplete, not as an existing acceptance capability.

The workflow must publish distinct jobs and reports per topology/scenario group. A single aggregate green status must not hide a missing topology.

## Resource and runtime controls

- Define per-container CPU, memory, PID, and disk limits with headroom based on measured peak use.
- Use explicit timeouts for provisioning, API readiness, client connection, transfer, and cleanup.
- Avoid fixed sleeps; poll observable readiness with bounded deadlines.
- Limit parallel full topologies to prevent resource contention and flaky timeouts.
- Capture Podman version, kernel, cgroup mode, network backend, image digests, and host architecture in every report.
- Make host prerequisites explicit and fail fast if required rootful Podman/network features are unavailable.

## Evidence and result semantics

Each case reports:
- stable case ID and suite/topology;
- product/operator/image versions and immutable image digests;
- run ID and sanitized environment fingerprint;
- preconditions and actions;
- expected and observed results;
- evidence references (API response, endpoint receipt, TLS transcript, client output, service state);
- status: PASS, FAIL, BLOCKED, SKIP, NOT_APPLICABLE, or INCOMPLETE;
- reason and cleanup result.

Unexpected SKIP/BLOCKED is a suite failure. NOT_APPLICABLE requires a checked-in rationale and must be consistent with the product support matrix. Partial execution is INCOMPLETE and cannot be reported as PASS.

## Decisions requiring confirmation during implementation

- Exact Panel API authentication and CRUD contracts must be read from the current GoWave version and repository integration points.
- Exact supported protocol/client matrix must be reconciled with current product docs and generated subscription formats; the current expected baseline is 8/10 All-in-One and 16/18/20 Multi-Node positive cases for Xray plus Mihomo.
- The subscription representation and User-Agent contract are settled and asserted, not re-litigated: base64 share links at the root path, Xray JSON in both served shapes, Mihomo YAML at `/mihomo` and `/clash`, non-empty header accepted, absent and blank rejected with 403, `firefox` fingerprint on REALITY and TLS transports.
- The supported OS matrix and existing QEMU workflows remain authoritative; no additional OS support is implied.
- The default PR tier may need resource-aware partitioning, but both topologies must remain required acceptance gates. A declared resource-based split is acceptable; silently omitting either topology or either client is not.
- Some system/kernel behaviors may require QEMU or host-level tests rather than privileged containers; such cases must be explicitly assigned to those tiers.

## Relationship to the live-vps-e2e capability

The `live-vps-e2e` capability owns the product-truth contracts that both suites share: subscription delivery and User-Agent policy, the per-endpoint data-plane inventory and its counts, Vision independence, firewall evidence rules, redaction, and result semantics. This change is the container-side projection of those contracts. Where both describe the same behavior, the assertions must agree word for word on the observable outcome; a divergence is a defect in this change, not a new variant. Anything that only a public VPS can prove stays in the live capability.

## Case catalog, incubation, and promotion

Both suites are driven from one checked-in case catalog (for example `tests/cases/catalog.yaml`). A case is defined once — ID, owning requirement, topology, fixtures, assertion, evidence schema, gate tier, and environment classifications — and each suite supplies a driver, never a second copy of the assertion.

Case entry fields:

- `id` — neutral and stable (`NEG-01`, `DP-03`, `SUB-02`), emitted unchanged in `result.json` and JUnit by both suites;
- `requirement` — the owning requirement in this capability or in `live-vps-e2e`;
- `runs_in` — `podman`, `live`, or both;
- `state` — `incubating` (Podman only, not yet stable), `podman-stable` (green repeatedly, awaiting live implementation), `live-parity` (asserted in both), or `live-only`;
- `environment` — `container`, `partial`, or `live-only`, with a required `live_only_reason` or `partial_split` note;
- `gate` — `pre-push`, `pr`, or `nightly`, so the declared runtime budget covers a defined subset while unexecuted cases still report SKIP/INCOMPLETE rather than PASS.

Promotion is one-directional. A new case lands in the Podman suite as `incubating`, becomes `podman-stable` after its configured green-run count and review, and only then gets a live driver that asserts the identical outcome. After promotion the Podman case keeps running as the regression net and the live run becomes authoritative for anything the container cannot prove. Adding a case directly to the live suite is rejected unless it is classified `live-only`.

Direction of truth stays with `openspec/specs/live-vps-e2e/spec.md` for shared product contracts. The catalog decides where a case runs, not what the product must do; a contract change is made once in the owning requirement and both suites follow.

### Parity baseline

Of the 125 live scenarios, 115 are container-reproducible, 8 are partial, and 2 are live-only. The table is regenerated whenever the live spec changes, and the divergence guard fails when a new live scenario arrives without a classification, so the counts are an enforced invariant rather than a snapshot.

| Live requirement group | Scenarios | Container | Partial | Live-only |
|---|---:|---:|---:|---:|
| Disposable Environment Gate | 2 | 2 | 0 | 0 |
| Mutation-Target Baseline and Resource Ownership | 4 | 4 | 0 | 0 |
| Preflight SSH Trust and DNS Verification | 6 | 5 | 1 | 0 |
| Target Address, Domain, and SSH Identity Safety | 3 | 3 | 0 | 0 |
| Independent Optional Vision Domains | 8 | 8 | 0 | 0 |
| Pinned Version Fidelity | 3 | 3 | 0 | 0 |
| All-in-One Master VPS Installation Verification | 5 | 5 | 0 | 0 |
| Distributed Worker VPS Deployment Verification | 5 | 5 | 0 | 0 |
| Public mTLS Control Plane Verification | 8 | 8 | 0 | 0 |
| TLS-aware Bounded Panel API Client | 1 | 1 | 0 | 0 |
| Panel API Cluster Structure Audit | 3 | 3 | 0 | 0 |
| Real Subscription Delivery and User-Agent Policy | 4 | 4 | 0 | 0 |
| UFW Firewall Isolation Verification | 4 | 3 | 1 | 0 |
| NGINX SNI Routing and REALITY Decoy Verification | 4 | 4 | 0 | 0 |
| Data Plane E2E Traffic Through All VPN Endpoints | 15 | 12 | 3 | 0 |
| Negative Scenario and Fault Injection Tests | 8 | 8 | 0 | 0 |
| Global Certbot Deploy Hook Ownership | 4 | 4 | 0 | 0 |
| Signal-Safe and Verifiable Transaction Compensation | 3 | 3 | 0 | 0 |
| Teardown Policy Enforcement | 8 | 6 | 1 | 1 |
| Pair-Wide Run Locking | 2 | 2 | 0 | 0 |
| Shared Mutation Lock Across All Management Entry Points | 3 | 3 | 0 | 0 |
| Durable Run State for Partial CLI Modes | 2 | 2 | 0 | 0 |
| Redacted Diagnostic Artifact Collection | 2 | 2 | 0 | 0 |
| Result Status Semantics | 3 | 3 | 0 | 0 |
| Local Operator Credential Bootstrap and Cleanup | 2 | 0 | 2 | 0 |
| Per-Case Data-Plane Packet Evidence | 3 | 3 | 0 | 0 |
| Local interactive operator entrypoint | 2 | 2 | 0 | 0 |
| Out-of-band SSH host identity verification | 2 | 2 | 0 | 0 |
| Temporary SSH access with remote expiry | 2 | 2 | 0 | 0 |
| Immediate credential revocation gates overall status | 2 | 2 | 0 | 0 |
| Local-only live VPS credential handling | 2 | 1 | 0 | 1 |

Partial cases and their split:

- preflight private/reserved-address rejection — the container proves the rule, but Podman addresses are themselves private, so the suite uses an explicitly scoped, fail-closed Podman exemption and the live run remains authoritative for real public addresses;
- UFW "external" origin — the container proves isolation between distinct source addresses, not provider-level reachability;
- the three data-plane CA scenarios — the container proves explicit verify anchors and no global trust change against the fixture CA, not real Let's Encrypt Staging/Production issuance;
- snapshot-restore hook with pair lock reacquisition — the container proves the protocol and lock ordering, not a provider snapshot;
- the two operator bootstrap scenarios — the container proves host-identity-before-password and bounded key lifetime, not the live controller's public-target path.

Live-only cases, which must stay in the live suite and are reported as justified exclusions in every Podman run: single-host snapshot restore after reboot without self-deadlock, and the local operator starting a real live run.

Podman-first cases with no live counterpart today (base64 share-link list, blank versus absent User-Agent, both `/v2ray-json` shapes, cover-domain derivation and unresolvable-name refusal, Worker port 80 ACME retention, private CA verify anchors, Podman-only Master address, arbitrary ACME URL rejection, runtime-budget overrun, coverage audit, pre-push gate, shared-contract divergence) are registered with a promotion target so they can move into the live suite instead of living only here.

### Divergence guard

A required check compares the catalog, the scenarios declared by both suites, and the executed case IDs from each run. It fails when a live scenario has no catalog entry, when a catalog entry claims `live-parity` but only one suite executed it, when the same ID asserts different text, or when the topology counts diverge from the 8/10 and 16/18/20 invariants. The guard reads the same catalog the runners read, so it cannot be satisfied by editing a report.

## Coverage completeness

Passing the gates means every in-scope behavior has at least one case and every behavior's error paths are tested, not just its happy path. The implementation must keep a checked-in inventory that maps behavior → case ID → topology → gate, and fail the audit when a behavior has no case or a case has no behavior. The inventory must cover at least:

- installation and prerequisites: OS detection, package set, service units, ports, NGINX validation, preflight conflicts;
- provisioning: Master install, Worker `node add`, API registration, repeat runs, interrupted runs, mutation lock;
- subscriptions: base64 links, Xray JSON in both shapes, Mihomo YAML, absent and blank User-Agent, wrong token, revoked user, `Cache-Control` and content type;
- data plane: the positive matrix, per-node egress attribution, direct-access denial, revoked-credential denial, client restart;
- decoy: cover-domain derivation, apex and `www` resolution success and failure, asset rendering, placeholder leakage, loopback isolation, certificate lineage, port 80 ACME retention, domain change;
- TLS/DNS/ACME: chain, SAN, protocol version, fingerprint, TTL and stale answers, NXDOMAIN, challenge failure, ACME outage, renewal;
- network policy: SSH trust and rotation, mTLS positives and negatives, TCP/3002 allow/deny from distinct origins, IPv4 and declared IPv6 behavior;
- lifecycle: Panel and Worker backup types, restore, corrupt archive rejection, stable-to-dev update, forced dev-to-stable gate, snapshot rollback, idempotency, cleanup;
- failure injection: every fault switch, expected safe-failure or degraded state, and recovery afterwards.

## Scope boundary

This change implements the test harness, the pre-push and pull-request gates, and the narrow operator capabilities those gates require: the Podman-only Master address override and the fail-closed test-only ACME endpoint. It does not redesign install, routing, subscription, or backup contracts, and it does not move any Live VPS responsibility into containers.
