# Proposal: Full Product-Level Podman E2E

## Why

The current `multi-node` Podman test is a transport acceptance test. It proves a pinned SSH command path, TLS 1.3 mutual TLS, certificate rejection, and Worker TCP/3002 source filtering. It does not install or exercise the GoWave Panel/Node product, register a Worker through the Panel API, issue subscriptions, or carry client proxy traffic.

A green transport test must therefore not be interpreted as full GoWave E2E acceptance. The project needs a repeatable local acceptance environment that executes the real operator against disposable Linux nodes and verifies the product from external client perspectives.

## What changes

Introduce a **Podman E2E framework** with two independent product topologies:

1. **All-in-One** — a clean single-node installation using the real operator and real GoWave/Xray/NGINX components.
2. **Multi-Node** — separate Control, Master/Panel, Worker, trusted client, untrusted client, and controlled external test-service roles. The real operator provisions the nodes and the real Panel API manages the Worker and client configuration.

The framework will provide:

- deterministic fixture services for DNS and ACME (Pebble), plus an external HTTP/HTTPS echo/egress endpoint; a narrowly scoped test-only ACME opt-in is required because the current Master and Worker scripts reject non-Let's-Encrypt directory URLs;
- both real supported client engines — Xray and Mihomo — consuming their respective Panel-issued subscription formats and carrying data-plane traffic;
- black-box assertions for API state, TLS, SSH, firewall behavior, service health, configuration, and actual payload delivery;
- failure injection and recovery checks;
- Panel/Worker backup and restore, the currently supported stable-to-dev channel update and its snapshot rollback, idempotency, and cleanup acceptance;
- sanitized diagnostics and machine-readable test reports;
- CI tiers that distinguish fast component checks, full All-in-One, full Multi-Node, recovery, and QEMU/live-host acceptance.

The existing transport acceptance remains as a focused lower-level test and is not renamed or promoted to full E2E.

## Goals

- Exercise the real installation and lifecycle paths shipped by this repository.
- Prove the full path from operator invocation through Panel/Worker provisioning to client subscription import and successful data transfer.
- Keep ordinary CI independent of public VPS credentials, public DNS, and production ACME.
- Cover All-in-One and Multi-Node as separate first-class topologies.
- Verify negative behavior and recovery, not only happy paths.
- Make skipped, unsupported, or incomplete cases visible and impossible to count as PASS.
- Preserve the existing Live VPS acceptance as a separate validation of public networking and provider-specific behavior.

## Non-goals

- Replacing QEMU cold-boot coverage with containers.
- Claiming Podman proves public IP reachability, provider firewall behavior, or Internet routing from arbitrary networks.
- Replacing GoWave, Xray, NGINX, or the operator with mocks in product acceptance tests.
- Making production Let's Encrypt, real public DNS, or disposable VPS instances mandatory for every PR.
- Changing product implementation or CI workflows in this documentation-only change.
- Defining new product features solely to make the test harness easier.

## Scope and compatibility

The framework must test the repository's supported OS/runtime matrix and protocol inventory as defined by the existing compatibility and protocol documentation. The implementation must discover and reference those authoritative inventories rather than inventing a second list. Any protocol or OS not supported by the product is explicitly marked NOT APPLICABLE with a documented reason; it must not be silently skipped.

The existing `tests/podman_testbed.sh multi-node` transport acceptance remains intact. The new full product acceptance is introduced under distinct targets and report identities.

## Required protocol/client matrix

The current repository implementation is the starting baseline to be reconciled with the version-pinned support inventory during implementation:

- Core inbounds per node: VLESS REALITY, VLESS XHTTP over TLS, VLESS WebSocket over TLS, and Trojan gRPC over TLS.
- Optional inbound: VLESS Vision over TLS, independently enabled per applicable node.
- Panel subscription formats: Xray JSON (/api/sub/<shortUuid>/v2ray-json) and Mihomo YAML (/api/sub/<shortUuid>/mihomo).
- Every applicable inbound on every installed node MUST be exercised by both the real Xray client and the real Mihomo client using the corresponding Panel-issued subscription. Xray JSON is subscription data: the harness must extract the actual Panel-issued outbound and add only the minimal runtime wrapper required by the pinned Xray binary; Mihomo loads the returned YAML. Both requests must use the client-family User-Agent required by the pinned Panel version, and the no-User-Agent response must be checked against the real policy. A single client passing is not sufficient.

Expected positive data-plane case counts, before negative/recovery cases:

| Topology | Vision configuration | Expected cases |
|---|---|---:|
| All-in-One | Disabled | 4 inbounds × 2 clients = 8 |
| All-in-One | Enabled | 5 inbounds × 2 clients = 10 |
| Multi-Node | Disabled on both nodes | 8 inbounds × 2 clients = 16 |
| Multi-Node | Enabled on Master only | 9 inbounds × 2 clients = 18 |
| Multi-Node | Enabled on Worker only | 9 inbounds × 2 clients = 18 |
| Multi-Node | Enabled on both nodes | 10 inbounds × 2 clients = 20 |

These counts are acceptance invariants, not estimates. The implementation must reconcile them with the authoritative protocol inventory for the pinned product version and fail closed on unexplained count drift. Negative cases, such as revoked credentials, are additional cases and MUST NOT replace a missing positive matrix entry.

## Acceptance summary

This change is ready for implementation only when the design and scenario inventory have been reviewed. It does not itself implement the framework or claim any new test has passed.

The implementation is accepted when:

1. All-In-One and Multi-Node run from clean disposable environments using the real operator.
2. Multi-Node registers and manages a real Worker through GoWave's actual API.
3. Both real client engines (Xray and Mihomo) consume their respective actual Panel-issued subscription formats and transfer a verifiable payload through every applicable inbound on every installed node; the topology-specific positive-case counts above are met exactly.
4. Negative security and firewall cases are proven from independent network origins.
5. Panel and Worker backup/restore, the supported stable-to-dev channel update and snapshot rollback, idempotency, and defined recovery scenarios have observable state-based assertions.
6. CI reports each topology and scenario group separately and fails on unexpected skips or incomplete execution.
7. Diagnostics are sanitized and retained on failure without exposing credentials or private keys.
8. Existing transport acceptance and QEMU cold-boot checks continue to run independently.
