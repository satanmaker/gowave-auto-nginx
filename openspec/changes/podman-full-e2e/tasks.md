# Tasks: Full Product-Level Podman E2E

## 1. Repository and contract discovery

- [ ] 1.1 Inventory current operator entrypoints, install modes, and supported deployment topologies.
- [ ] 1.2 Map the real GoWave Panel API authentication, Node registration, client lifecycle, supported update operations, and subscription contracts; cite the source/version for each and mark unsupported operations NOT_APPLICABLE rather than inventing endpoints.
- [ ] 1.2a Pin the Panel's actual User-Agent policy per subscription path: a non-empty header is accepted, an absent header and a blank header are rejected with 403. Assert the absent and blank cases separately; do not encode a per-format client-family allowlist that the Panel does not enforce.
- [ ] 1.2b Inventory every subscription representation the Panel serves and record which client family consumes each: base64 share links at `/api/sub/<shortUuid>`, Xray JSON at `/v2ray-json`, Mihomo YAML at `/mihomo` and `/clash`, and sing-box JSON at `/singbox`. Prove that an Xray-family mobile client imports the base64 list and not the JSON body.
- [ ] 1.2c Record both served shapes of `/v2ray-json`: a single config object with `outbounds` and a list of complete per-profile configs. A list entry is validated as the complete config it is; only a bare object is wrapped before `xray run -test`.
- [ ] 1.3 Reconcile supported protocols, subscription formats, and real client implementations with the authoritative repository documentation and the `live-vps-e2e` capability contracts.
- [ ] 1.4 Reconcile the OS matrix with the repository compatibility matrix (`openspec/changes/gowave-auto-nginx/COMPATIBILITY_MATRIX.md` until that change is archived) and the existing QEMU workflows.
- [ ] 1.5 Inventory existing Podman testbed scripts, systemd images, transport acceptance, and CI workflows; identify reusable fixtures without duplicating product behavior.
- [ ] 1.6 Define the boundary between Podman, QEMU, and Live VPS acceptance, including cases that cannot be faithfully tested in containers.
- [ ] 1.7 Add a versioned machine-readable protocol/client test matrix derived from the real generated profile/host data: core inbounds, optional per-node Vision, base64/Xray JSON/Mihomo representations, client binary versions, host/SNI/ALPN/path, pinned `firefox` fingerprint on REALITY and TLS transports, stable case IDs, expected case counts (AIO 8/10; Multi-Node 16/18/20), and the runtime budget for the pre-push gate.
- [ ] 1.8 Record the relationship to `openspec/specs/live-vps-e2e/spec.md`: shared product contracts are asserted identically, and any divergence is fixed here rather than introduced as a container-only variant.

## 2. Framework architecture

- [x] 2.1 Define a run-scoped Podman resource model with unique labels, network, volumes, credentials, and cleanup ownership.
- [x] 2.2 Define a shared test runner contract, stable case IDs, timeouts, result states, and JSON/JUnit report schema.
- [x] 2.3 Define rootful Podman prerequisites and a separately scoped rootless-compatible subset.
- [x] 2.4 Pin base image references by immutable digest and record runtime/kernel/cgroup/network metadata.
- [x] 2.5 Implement failure-safe cleanup for success, assertion failure, timeout, SIGINT, SIGTERM, and stale-run recovery.
- [x] 2.6 Define bounded readiness polling; prohibit unbounded waits and fixed sleeps as readiness assertions.
- [x] 2.7 Define the Podman-only Master-address override contract for the real `node add` path: explicit opt-in, address/interface/network membership validation, rejection outside Podman mode, and no change to Live VPS safety checks.

## 3. Deterministic external fixtures

- [ ] 3.1 Add a controllable authoritative DNS fixture supporting A/AAAA, TTL, NXDOMAIN, stale/wrong answers, and resolver diagnostics.
- [ ] 3.2 Add Pebble or equivalent local ACME fixture and trusted test CA.
- [ ] 3.3 Add external HTTP/HTTPS echo/egress service with unique request IDs, payload verification, and source/path evidence.
- [ ] 3.4 Add controlled fault switches for fixture unavailability, latency, and error responses.
- [ ] 3.5 Verify fixtures are isolated from public DNS, production ACME, and external VPS targets.
- [ ] 3.6 Implement and test the narrow test-only ACME opt-in in both Master and Worker validation/lineage paths: exact Pebble endpoint plus pinned CA only; SSH-stdin propagation; scoped Certbot/client CA trust; no global trust changes; production/Staging defaults unchanged; arbitrary URLs rejected even when test mode is enabled.
- [ ] 3.7 Make the fixture CA usable by both client engines without global trust: inject `tlsSettings.certificates` entries with `usage: verify` into every Xray TLS outbound, because Xray ignores `SSL_CERT_FILE`, and pass the scoped bundle to Mihomo, curl, and the Python clients. Assert that a missing anchor fails the case with a chain error rather than passing silently.

## 4. All-in-One product E2E

- [ ] 4.1 Create a clean supported systemd-enabled target image.
- [ ] 4.2 Execute the real operator full-install path without test-side product provisioning.
- [ ] 4.3 Verify installed packages, systemd units, active services, listening sockets, Panel/API, NGINX, and TLS independently.
- [ ] 4.4 Exercise Panel authentication and required API lifecycle operations.
- [ ] 4.5 Obtain every served representation from the real Panel with a client-identifying User-Agent: the base64 share-link list, the Xray JSON config object or profile list (validated in both shapes), and the Mihomo YAML. Load the Mihomo YAML in Mihomo and consume the Xray representations without replacing the Panel-issued outbound.
- [ ] 4.5a Test absent-header and blank-header behavior against the pinned Panel policy, which rejects both with 403; do not collapse the two cases into one probe.
- [ ] 4.5b Decode the base64 share-link list and assert one link per proxy entry with the expected protocol, host, SNI, and fingerprint, and prove an Xray-family client imports it while the raw JSON body imports nothing.
- [ ] 4.6 Transfer verifiable payloads through every applicable supported protocol/configuration.
- [ ] 4.7 Verify revocation, restart recovery, and repeated provisioning/idempotency.
- [ ] 4.8 Add negative configuration and dependency-failure scenarios.
- [ ] 4.9 Execute and assert the complete All-in-One matrix with both Xray and Mihomo: exactly 8 positive transfer cases without Vision and 10 with Vision; fail on missing or unexplained extra cases.

## 5. Multi-Node product E2E

- [ ] 5.1 Create clean Control, Master/Panel, Worker, trusted client, and untrusted client roles.
- [ ] 5.2 Run the real operator's supported Master and Worker provisioning flow.
- [ ] 5.2a Implement the narrowly scoped Podman-only Master private-address override and prove the real Worker observes that address on its Master-to-Worker connection; do not mock `node add` or use the host's public egress address.
- [ ] 5.3 Verify pinned SSH trust and mTLS using actual deployed services.
- [ ] 5.4 Register and manage Worker through the real GoWave Panel API.
- [ ] 5.5 Verify Node health/state and configuration consistency across Panel and Worker.
- [ ] 5.6 Obtain the real Panel representations for a Worker-issued profile — base64 links, Xray JSON, and Mihomo YAML — and import each into the client that consumes it.
- [ ] 5.7 Prove payload traversal through Worker for every applicable supported protocol/configuration.
- [ ] 5.8 Verify untrusted management access is denied and trusted access remains functional.
- [ ] 5.9 Verify subscription revocation, Worker outage, restart, and recovery behavior.
- [ ] 5.10 Verify all four independent Vision combinations: neither, Master-only, Worker-only, and both.
- [ ] 5.10a Verify SSH wrong-host-key rejection before command execution and authorized host-key rotation (new key accepted, old key rejected).
- [ ] 5.11 Execute and assert the complete Multi-Node matrix with both Xray and Mihomo: exactly 16 positive transfer cases with Vision disabled, 18 with Vision enabled on one node, and 20 with Vision enabled on both nodes.
- [ ] 5.12 Prove Worker and Master egress attribution using distinct node-only egress identities; deny direct client/Control access to the external fixture and reject wrong-node source attribution.

## 6. TLS, DNS, ACME, and network policy

- [ ] 6.1 Validate generated NGINX configuration and safe reload behavior.
- [ ] 6.2 Verify TLS version, certificate SAN, validity, and chain from independent clients.
- [ ] 6.3 Exercise ACME issuance and renewal through Pebble using the real Certbot webroot HTTP-01 path and the target's actual NGINX challenge route; do not pre-seed certificates or mock successful challenges.
- [ ] 6.4 Exercise challenge and ACME outage failures and recovery.
- [ ] 6.4a Separately verify A/AAAA selection, TTL/cache expiry, NXDOMAIN, and stale/wrong DNS answers from target and independent-client vantage points.
- [ ] 6.5 Verify decoy/fallback does not expose internal management interfaces.
- [ ] 6.6 Verify firewall allow/deny paths from each relevant network origin using real connection attempts.
- [ ] 6.7 Cover IPv4/IPv6 behavior according to the declared product support/configuration.
- [ ] 6.8 Assert cover-domain derivation from `panel_domain`: the last two labels form the apex, and a domain with fewer than three labels produces no cover lineage and must be handled explicitly instead of silently rendering nothing.
- [ ] 6.9 Prove the apex and `www.<apex>` resolution precondition from the target's own resolver: successful rendering when both resolve to the host IPv4, and the operator's documented refusal when either name does not.
- [ ] 6.10 Verify the rendered cover site: expected `*.html`/`*.css`/`*.svg` assets present, brand derived from the apex's second-to-last label, no surviving `{{` placeholder, and a served page whose content does not expose Panel/API or management paths.
- [ ] 6.11 Verify decoy routing and isolation: apex and `www` SNI terminate on the loopback listener `127.0.0.1:9443`, the listener is unreachable from client networks, every VPN SNI keeps its own route, and the REALITY certificate lineage covers the apex and `www.<apex>`.
- [ ] 6.12 Verify the port 80 ACME vhost survives a Worker install and reconfiguration on both roles, so renewal keeps a reachable HTTP-01 path, and that a domain change re-renders the decoy and lineage without stale `sites-enabled` entries.

## 7. Lifecycle and failure recovery

- [ ] 7.1 Exercise both supported archive types through the real interface: Panel backup (`--type panel`) and Worker Node backup (`--type node`); record their actual included files and secret-bearing content.
- [ ] 7.2 Provision compatible clean targets through the real operator, restore the Panel archive on Master and Worker Node archive on Worker, then verify API state, Worker health, and Xray/Mihomo data-plane traffic.
- [ ] 7.2a Keep unencrypted backup archives in a run-private mode-0600 ephemeral volume; prove they are excluded from CI artifacts/logs/reports and delete the volume during cleanup.
- [ ] 7.3 Exercise corrupt/incomplete backup rejection.
- [ ] 7.4 Exercise the currently supported stable-to-dev channel transition through `gowave-auto.sh channel dev`; do not invent arbitrary-version upgrade coverage.
- [ ] 7.5 Inject a controlled failure after the channel update snapshot is captured; verify real snapshot rollback restores database, binaries, frontend, environment, NGINX/ACME state, and `state.json`, then verify API and Xray/Mihomo traffic.
- [ ] 7.5a Treat dev-to-stable as NOT_APPLICABLE unless a documented safe migration/downgrade contract is introduced; test same-channel invocation as an idempotent no-op.
- [ ] 7.6 Inject SSH, Panel, Worker, DNS, ACME, firewall, NGINX, Xray, disk, latency, and process failures.
- [ ] 7.7 Verify documented safe-failure/retry/rollback/degraded-state behavior for each injected fault.
- [ ] 7.8 Verify subsequent recovery and rerun/idempotency.

## 8. Evidence, security, and CI

- [ ] 8.1 Produce structured per-case JSON and JUnit output with stable IDs and evidence references.
- [ ] 8.2 Collect operator/service/systemd/network/TLS/DNS/client/endpoint diagnostics on failure.
- [ ] 8.3 Implement secret redaction and sentinel-based redaction tests.
- [ ] 8.4 Distinguish PASS, FAIL, BLOCKED, SKIP, NOT_APPLICABLE, and INCOMPLETE; fail unexpected skips/blocks.
- [ ] 8.5 Add distinct CI jobs for full All-in-One and full Multi-Node acceptance.
- [ ] 8.6 Add lifecycle/failure-recovery CI coverage with explicit required status checks.
- [ ] 8.7 Preserve existing transport acceptance and QEMU cold-boot workflows as independent checks.
- [ ] 8.8 Document local invocation, prerequisites, resource limits, debugging, artifact retention, and cleanup.
- [ ] 8.9 Verify normal CI never contacts or mutates public VPS targets and requires no live credentials.
- [ ] 8.10 Perform a final acceptance audit proving every requirement maps to an implemented test and CI job.
- [ ] 8.11 Publish the requirement → scenario ID → protocol/client matrix row → CI job traceability report; verify expected positive-case counts independently from aggregate suite status.
- [ ] 8.12 Configure and verify distinct required status checks for All-in-One and Multi-Node; require lifecycle/recovery jobs for affected code paths and prove an omitted/skipped topology cannot yield aggregate PASS.
- [ ] 8.13 Publish traceability for User-Agent accepted/absent/blank cases, base64 and Xray JSON handling, private Master-address selection, all four Vision combinations, SSH host-key mismatch/rotation, decoy derivation/resolution/rendering, and each DNS behavior.
- [ ] 8.14 Add a pre-push entrypoint that runs the full All-in-One and Multi-Node suites with the pinned fixtures and no live credentials, and document installing it as a git hook.
- [ ] 8.15 Back the pull-request required checks with the same targets, enforce the runtime budget declared in the matrix manifest, and report INCOMPLETE when the budget is exceeded instead of dropping cases.
- [ ] 8.16 Keep a checked-in behavior inventory (behavior → case ID → topology → gate) covering installation, provisioning, subscription representations, data plane, decoy, TLS/DNS/ACME, network policy, lifecycle, and failure injection, including each behavior's error paths; fail the audit on an unmapped behavior or an orphan case.
- [ ] 8.17 Audit this capability against `openspec/specs/live-vps-e2e/spec.md` for shared contracts (subscription policy, case counts, Vision independence, firewall evidence, redaction, result semantics) and record the mapping in the traceability report.

## 9. Live parity and case promotion

- [ ] 9.1 Create the shared case catalog with stable IDs, owning requirement, topology, fixtures, assertion, evidence schema, gate tier, and `runs_in`/`state`/`environment` fields; both suites read it and neither keeps a private copy of an assertion.
- [ ] 9.2 Import every container-reproducible live scenario (115 of 125) as a catalog entry with a Podman driver, grouped by the owning `live-vps-e2e` requirement.
- [ ] 9.3 Classify the 8 partial scenarios with an explicit split of what the container proves and what only the live run proves; implement the container half.
- [ ] 9.4 Register the 2 live-only scenarios with a written environment limitation and report them as justified exclusions in every Podman run.
- [ ] 9.5 Register the Podman-first cases that have no live counterpart yet, each with a promotion target and owning live requirement.
- [ ] 9.6 Implement the one-directional promotion path: `incubating` → `podman-stable` after the configured green-run count and review → `live-parity` with a live driver asserting the same outcome; reject a live-only addition without classification.
- [ ] 9.7 Add the divergence guard as a required check: live scenario without a catalog entry, `live-parity` executed by only one suite, identical ID with different assertion text, or counts departing from 8/10 and 16/18/20 all fail.
- [ ] 9.8 Implement the `pre-push` / `pr` / `nightly` gate tiers from the catalog, and prove that an unexecuted lower-tier case reports SKIP/INCOMPLETE rather than letting the aggregate pass.
- [ ] 9.9 Publish the checked-in parity inventory (live scenario → catalog case → environment classification → gate) and wire it into the coverage audit.
