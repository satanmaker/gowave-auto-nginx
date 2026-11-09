# Tasks: Full Product-Level Podman E2E

## 1. Repository and contract discovery

- [ ] 1.1 Inventory current operator entrypoints, install modes, and supported deployment topologies.
- [ ] 1.2 Map the real GoWave Panel API authentication, Node registration, client lifecycle, supported update operations, and subscription contracts; cite the source/version for each and mark unsupported operations NOT_APPLICABLE rather than inventing endpoints.
- [ ] 1.2a Verify the Panel's actual User-Agent policy for both Xray JSON and Mihomo YAML subscriptions, including the response to missing User-Agent; pin the expected behavior to the tested Panel version.
- [ ] 1.3 Reconcile supported protocols, subscription formats, and real client implementations with the authoritative repository documentation.
- [ ] 1.4 Reconcile the OS matrix with compatibility documentation and existing QEMU workflows.
- [ ] 1.5 Inventory existing Podman testbed scripts, systemd images, transport acceptance, and CI workflows; identify reusable fixtures without duplicating product behavior.
- [ ] 1.6 Define the boundary between Podman, QEMU, and Live VPS acceptance, including cases that cannot be faithfully tested in containers.
- [ ] 1.7 Add a versioned machine-readable protocol/client test matrix derived from the real generated profile/host data: core inbounds, optional per-node Vision, Xray JSON and Mihomo YAML subscriptions, client binary versions, host/SNI/ALPN/path/fingerprint, stable case IDs, and expected case counts (AIO 8/10; Multi-Node 16/18/20).

## 2. Framework architecture

- [ ] 2.1 Define a run-scoped Podman resource model with unique labels, network, volumes, credentials, and cleanup ownership.
- [ ] 2.2 Define a shared test runner contract, stable case IDs, timeouts, result states, and JSON/JUnit report schema.
- [ ] 2.3 Define rootful Podman prerequisites and a separately scoped rootless-compatible subset.
- [ ] 2.4 Pin base image references by immutable digest and record runtime/kernel/cgroup/network metadata.
- [ ] 2.5 Implement failure-safe cleanup for success, assertion failure, timeout, SIGINT, SIGTERM, and stale-run recovery.
- [ ] 2.6 Define bounded readiness polling; prohibit unbounded waits and fixed sleeps as readiness assertions.
- [ ] 2.7 Define the Podman-only Master-address override contract for the real `node add` path: explicit opt-in, address/interface/network membership validation, rejection outside Podman mode, and no change to Live VPS safety checks.

## 3. Deterministic external fixtures

- [ ] 3.1 Add a controllable authoritative DNS fixture supporting A/AAAA, TTL, NXDOMAIN, stale/wrong answers, and resolver diagnostics.
- [ ] 3.2 Add Pebble or equivalent local ACME fixture and trusted test CA.
- [ ] 3.3 Add external HTTP/HTTPS echo/egress service with unique request IDs, payload verification, and source/path evidence.
- [ ] 3.4 Add controlled fault switches for fixture unavailability, latency, and error responses.
- [ ] 3.5 Verify fixtures are isolated from public DNS, production ACME, and external VPS targets.
- [ ] 3.6 Implement and test the narrow test-only ACME opt-in in both Master and Worker validation/lineage paths: exact Pebble endpoint plus pinned CA only; SSH-stdin propagation; scoped Certbot/client CA trust; no global trust changes; production/Staging defaults unchanged; arbitrary URLs rejected even when test mode is enabled.

## 4. All-in-One product E2E

- [ ] 4.1 Create a clean supported systemd-enabled target image.
- [ ] 4.2 Execute the real operator full-install path without test-side product provisioning.
- [ ] 4.3 Verify installed packages, systemd units, active services, listening sockets, Panel/API, NGINX, and TLS independently.
- [ ] 4.4 Exercise Panel authentication and required API lifecycle operations.
- [ ] 4.5 Obtain both real Panel subscriptions with their required User-Agent headers; load Mihomo YAML in Mihomo and consume Xray JSON by extracting the Panel-issued outbound into the minimal runtime wrapper required by the pinned Xray binary.
- [ ] 4.5a Test missing-User-Agent behavior against the actual pinned Panel policy; do not assume a hardcoded HTTP status.
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
- [ ] 5.6 Obtain a real Panel-issued subscription and import it into actual clients.
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
- [ ] 8.13 Publish traceability for User-Agent positive/negative cases, Xray subscription-to-runtime-config handling, private Master-address selection, all four Vision combinations, SSH host-key mismatch/rotation, and each DNS behavior.
