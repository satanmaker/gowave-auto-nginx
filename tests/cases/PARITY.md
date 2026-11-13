# Podman / Live parity inventory

Generated from `tests/cases/catalog.yaml`; do not edit by hand.

Live scenarios: 125 — container 115, partial 8, live-only 2.

| Live requirement group | Scenarios | Container | Partial | Live-only |
|---|---:|---:|---:|---:|
| Disposable Environment Gate | 2 | 2 | 0 | 0 |
| Complete Mutation-Target Baseline and Resource Ownership | 4 | 4 | 0 | 0 |
| Preflight SSH Trust and DNS Verification | 6 | 5 | 1 | 0 |
| Target Address, Domain, and SSH Identity Safety | 3 | 3 | 0 | 0 |
| Independent Optional Vision Domains | 8 | 8 | 0 | 0 |
| Pinned Version Fidelity | 3 | 3 | 0 | 0 |
| All-in-One Master VPS Installation Verification | 5 | 5 | 0 | 0 |
| Distributed Worker VPS Deployment Verification | 5 | 5 | 0 | 0 |
| Public mTLS Control Plane Verification (Master → Worker) | 8 | 8 | 0 | 0 |
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

## Partial splits

- **PRE-04** — Container proves the private/reserved rule against Podman addresses with an explicitly scoped, fail-closed exemption; the live run is authoritative for real public addresses.
- **FW-03** — Container proves isolation between distinct source addresses; provider-level external reachability is live-only.
- **DP-09** — Container proves explicit verify anchors and no global trust change; public Let's Encrypt issuance is live-only.
- **DP-10** — Container proves the injected verify anchor is required; real Staging material is live-only.
- **DP-11** — Container proves fixture CA pinning by digest; real Staging CA distribution is live-only.
- **TD-05** — Container proves lock ordering and hook protocol; provider snapshots are live-only.
- **BOOT-01** — Container proves host identity precedes the password; the live controller's public-target path is live-only.
- **BOOT-02** — Container proves bounded key lifetime and revocation; live account behaviour is live-only.

## Live-only exclusions

- **TD-06** — Requires a provider snapshot and a real reboot; a container cannot reproduce the host lifecycle.
- **LOCAL-02** — Starts the interactive operator against real disposable VPS instances; live infrastructure only.

## Podman-first cases awaiting live promotion

- **AIO-INSTALL** — promotion target: All-in-One Master VPS Installation Verification
- **MN-INSTALL** — promotion target: Distributed Worker VPS Deployment Verification
- **AIO-PACKAGES** — promotion target: All-in-One Master VPS Installation Verification
- **AIO-AUTH** — promotion target: All-in-One Master VPS Installation Verification
- **AIO-CLIENT** — promotion target: Real Subscription Delivery and User-Agent Policy
- **SUB-SERVED** — promotion target: Real Subscription Delivery and User-Agent Policy
- **SUB-B64** — promotion target: Real Subscription Delivery and User-Agent Policy
- **SUB-UA-ABSENT** — promotion target: Real Subscription Delivery and User-Agent Policy
- **SUB-UA-BLANK** — promotion target: Real Subscription Delivery and User-Agent Policy
- **SUB-JSON-SHAPES** — promotion target: Real Subscription Delivery and User-Agent Policy
- **AIO-REVOKE** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **AIO-RESTART** — promotion target: All-in-One Master VPS Installation Verification
- **AIO-IDEMPOTENT** — promotion target: All-in-One Master VPS Installation Verification
- **AIO-NEG-DEST** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **AIO-NEG-PORT** — promotion target: All-in-One Master VPS Installation Verification
- **AIO-NEG-ACME** — promotion target: Independent All-in-One Acceptance Topology
- **AIO-NEG-DEP** — promotion target: All-in-One Master VPS Installation Verification
- **NGX-05** — promotion target: NGINX SNI Routing and REALITY Decoy Verification
- **TLS-01** — promotion target: NGINX SNI Routing and REALITY Decoy Verification
- **DECOY-01** — promotion target: NGINX SNI Routing and REALITY Decoy Verification
- **ACME-01** — promotion target: Global Certbot Deploy Hook Ownership
- **ACME-02** — promotion target: Global Certbot Deploy Hook Ownership
- **DNS-01** — promotion target: Preflight SSH Trust and DNS Verification
- **NGX-COVER-DERIVE** — promotion target: NGINX SNI Routing and REALITY Decoy Verification
- **NGX-COVER-SITE** — promotion target: NGINX SNI Routing and REALITY Decoy Verification
- **NGX-DECOY-ROUTE** — promotion target: NGINX SNI Routing and REALITY Decoy Verification
- **NGX-COVER-UNRESOLVED** — promotion target: NGINX SNI Routing and REALITY Decoy Verification
- **NGX-WORKER-ACME80** — promotion target: Distributed Worker VPS Deployment Verification
- **TLS-VERIFY-ANCHORS** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **MN-BACKUP** — promotion target: Signal-Safe and Verifiable Transaction Compensation
- **MN-BACKUP-VOL** — promotion target: Signal-Safe and Verifiable Transaction Compensation
- **MN-BACKUP-BAD** — promotion target: Signal-Safe and Verifiable Transaction Compensation
- **MN-RESTORE** — promotion target: Signal-Safe and Verifiable Transaction Compensation
- **PODNET-MASTER-ADDR** — promotion target: Distributed Worker VPS Deployment Verification
- **WRK-06** — promotion target: Distributed Worker VPS Deployment Verification
- **ACME-REJECT-ARB** — promotion target: Global Certbot Deploy Hook Ownership
- **GATE-BUDGET** — promotion target: Result Status Semantics
- **GATE-COVERAGE** — promotion target: Result Status Semantics
- **GATE-PREPUSH** — promotion target: Result Status Semantics
- **GATE-DIVERGENCE** — promotion target: Result Status Semantics
- **MN-REVOKE** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **MN-OUTAGE** — promotion target: Negative Scenario and Fault Injection Tests
- **MN-RESTART** — promotion target: Negative Scenario and Fault Injection Tests
- **MN-SSHKEY** — promotion target: Preflight SSH Trust and DNS Verification
- **MN-VISION** — promotion target: Independent Optional Vision Domains
- **AIO-DP-REALITY-xray** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **AIO-DP-REALITY-mihomo** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **AIO-DP-XHTTP-xray** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **AIO-DP-XHTTP-mihomo** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **AIO-DP-WS-xray** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **AIO-DP-WS-mihomo** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **AIO-DP-TROJAN-GRPC-xray** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **AIO-DP-TROJAN-GRPC-mihomo** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **AIO-DP-VISION-xray** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **AIO-DP-VISION-mihomo** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **AIO-MATRIX** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **MN-DP-master-REALITY-xray** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **MN-DP-master-REALITY-mihomo** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **MN-DP-master-XHTTP-xray** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **MN-DP-master-XHTTP-mihomo** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **MN-DP-master-WS-xray** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **MN-DP-master-WS-mihomo** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **MN-DP-master-TROJAN-GRPC-xray** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **MN-DP-master-TROJAN-GRPC-mihomo** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **MN-DP-master-VISION-xray** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **MN-DP-master-VISION-mihomo** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **MN-DP-worker-REALITY-xray** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **MN-DP-worker-REALITY-mihomo** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **MN-DP-worker-XHTTP-xray** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **MN-DP-worker-XHTTP-mihomo** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **MN-DP-worker-WS-xray** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **MN-DP-worker-WS-mihomo** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **MN-DP-worker-TROJAN-GRPC-xray** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **MN-DP-worker-TROJAN-GRPC-mihomo** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **MN-DP-worker-VISION-xray** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **MN-DP-worker-VISION-mihomo** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **MN-MATRIX** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **MN-EGRESS** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
