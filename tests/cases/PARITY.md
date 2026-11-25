# Podman / Live parity inventory

Generated from `tests/cases/catalog.yaml`; do not edit by hand.

Live scenarios: 125 — container 111, partial 12, live-only 2.

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
| Negative Scenario and Fault Injection Tests | 8 | 4 | 4 | 0 |
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

## Scenario inventory

One row per live scenario: the catalog case that covers it, the environment
classification `tests/cases/scenarios.yaml` states, and the gate tier that
blocks on the case. A scenario missing from this table has no case, and
`python3 -m tools.podman_e2e.catalog check` refuses that before the table can
be published.

| Case | Environment | Gate | Live scenario | Requirement |
|---|---|---|---|---|
| ENV-01 | container | pre-push | Clean VPS passes baseline gate | Disposable Environment Gate |
| ENV-02 | container | pre-push | Contaminated VPS blocked before modification | Disposable Environment Gate |
| OWN-01 | container | pre-push | Existing Worker system configuration is not overwritten | Complete Mutation-Target Baseline and Resource Ownership |
| OWN-02 | container | pre-push | Existing Worker service or binary paths are not removed | Complete Mutation-Target Baseline and Resource Ownership |
| OWN-03 | container | pre-push | Existing firewall policy is preserved | Complete Mutation-Target Baseline and Resource Ownership |
| OWN-04 | container | pre-push | Failure restores every transaction-owned resource | Complete Mutation-Target Baseline and Resource Ownership |
| PRE-01 | container | pre-push | SSH host key not pre-pinned | Preflight SSH Trust and DNS Verification |
| PRE-02 | container | pre-push | DNS A-record points to wrong IP | Preflight SSH Trust and DNS Verification |
| PRE-03 | container | pre-push | Published AAAA is rejected when IPv6 testing is disabled | Preflight SSH Trust and DNS Verification |
| PRE-04 | partial | pre-push | Private or reserved IP rejected | Preflight SSH Trust and DNS Verification |
| PRE-05 | container | pre-push | IPv6 AAAA records verified when enabled | Preflight SSH Trust and DNS Verification |
| PRE-06 | container | pre-push | Published AAAA records cannot bypass IPv6 verification | Preflight SSH Trust and DNS Verification |
| ADDR-01 | container | pre-push | Master and Worker target addresses must differ | Target Address, Domain, and SSH Identity Safety |
| ADDR-02 | container | pre-push | Mandatory domains are pairwise unique | Target Address, Domain, and SSH Identity Safety |
| ADDR-03 | container | pre-push | Non-root SSH account is rejected in v1 | Target Address, Domain, and SSH Identity Safety |
| VIS-01 | container | pre-push | Master-only Vision configuration | Independent Optional Vision Domains |
| VIS-02 | container | pre-push | Worker-only Vision configuration | Independent Optional Vision Domains |
| VIS-03 | container | pre-push | Both Vision domains are configured | Independent Optional Vision Domains |
| VIS-04 | container | pre-push | Vision domains are unique | Independent Optional Vision Domains |
| VIS-05 | container | pre-push | Vision certificate failure aborts the relevant host installation | Independent Optional Vision Domains |
| VIS-06 | container | pre-push | Incomplete Vision compensation is reported, not hidden | Independent Optional Vision Domains |
| VIS-07 | container | pre-push | Vision disabled preserves the four-inbound topology | Independent Optional Vision Domains |
| VIS-08 | container | pre-push | Vision port gate applies only to the Vision-enabled host | Independent Optional Vision Domains |
| VER-01 | container | pre-push | Version mismatch detected post-installation | Pinned Version Fidelity |
| VER-02 | container | pre-push | Floating installer branch or installer digest mismatch rejected | Pinned Version Fidelity |
| VER-03 | container | pre-push | Server and client Xray versions are independently pinned | Pinned Version Fidelity |
| AIO-01 | container | pre-push | Panel service active and API ready | All-in-One Master VPS Installation Verification |
| AIO-02 | container | pre-push | Installer TLS/SNI probe trusts only the per-run CA bundle | All-in-One Master VPS Installation Verification |
| AIO-03 | container | pre-push | Credentials file has correct permissions and content | All-in-One Master VPS Installation Verification |
| AIO-04 | container | pre-push | Master services active and listeners correct | All-in-One Master VPS Installation Verification |
| AIO-05 | container | pre-push | TLS certificate valid and shortUuid retrievable | All-in-One Master VPS Installation Verification |
| WRK-01 | container | pre-push | SECRET_KEY is absent from a complete process argv trace | Distributed Worker VPS Deployment Verification |
| WRK-02 | container | pre-push | Long argv string is not truncated | Distributed Worker VPS Deployment Verification |
| WRK-03 | container | pre-push | Later argv elements are not abbreviated | Distributed Worker VPS Deployment Verification |
| WRK-04 | container | pre-push | Worker node registered and connected in Panel | Distributed Worker VPS Deployment Verification |
| WRK-05 | container | pre-push | Worker deployment details verified | Distributed Worker VPS Deployment Verification |
| MTLS-01 | container | pre-push | Existing verifier succeeds with valid credentials | Public mTLS Control Plane Verification (Master → Worker) |
| MTLS-02 | container | pre-push | HTTP 200 is distinguished from HTTP 401 | Public mTLS Control Plane Verification (Master → Worker) |
| MTLS-03 | container | pre-push | Panel-to-Worker authenticated connectivity is independently verified | Public mTLS Control Plane Verification (Master → Worker) |
| MTLS-04 | container | pre-push | Untrusted client certificate rejected by Worker | Public mTLS Control Plane Verification (Master → Worker) |
| MTLS-05 | container | pre-push | Absent client certificate rejected by Worker | Public mTLS Control Plane Verification (Master → Worker) |
| MTLS-06 | container | pre-push | Mismatched client certificate and private key is classified as local failure | Public mTLS Control Plane Verification (Master → Worker) |
| MTLS-07 | container | pre-push | Untrusted Worker CA is classified as client-side server verification failure | Public mTLS Control Plane Verification (Master → Worker) |
| MTLS-08 | container | pre-push | Wrong SNI routing is measured without assuming a TLS alert | Public mTLS Control Plane Verification (Master → Worker) |
| APIC-01 | container | pre-push | Panel API client uses scoped trust and configured timeout | TLS-aware Bounded Panel API Client |
| CLUS-01 | container | pre-push | Hosts present with correct node and inbound associations | Panel API Cluster Structure Audit |
| CLUS-02 | container | pre-push | Internal Squad contains all provisioned inbound UUIDs | Panel API Cluster Structure Audit |
| CLUS-03 | container | pre-push | Two nodes and two config profiles with correct structure | Panel API Cluster Structure Audit |
| SUB-01 | container | pre-push | Subscription rejected with absent User-Agent | Real Subscription Delivery and User-Agent Policy |
| SUB-02 | container | pre-push | Proxy-capable outbounds in Xray JSON | Real Subscription Delivery and User-Agent Policy |
| SUB-03 | container | pre-push | Xray JSON subscription headers and content verified | Real Subscription Delivery and User-Agent Policy |
| SUB-04 | container | pre-push | Mihomo YAML subscription verified | Real Subscription Delivery and User-Agent Policy |
| FW-01 | container | pre-push | Worker allows Master and blocks Control Machine | UFW Firewall Isolation Verification |
| FW-02 | container | pre-push | Negative probe is not misclassified | UFW Firewall Isolation Verification |
| FW-03 | partial | pre-push | Master local and external access are distinguished | UFW Firewall Isolation Verification |
| FW-04 | container | pre-push | IPv6 firewall isolation checked when enabled | UFW Firewall Isolation Verification |
| NGX-01 | container | pre-push | Panel HTTPS accessible with correct SNI | NGINX SNI Routing and REALITY Decoy Verification |
| NGX-02 | container | pre-push | REALITY decoy does not leak GoWave API content | NGINX SNI Routing and REALITY Decoy Verification |
| NGX-03 | container | pre-push | REALITY fallback and cover-reality assets present | NGINX SNI Routing and REALITY Decoy Verification |
| NGX-04 | container | pre-push | Optional Vision SNI routing and decoy fallback | NGINX SNI Routing and REALITY Decoy Verification |
| DP-01 | container | pre-push | All active logical endpoints are exercised by both clients | Data Plane E2E Traffic Through All VPN Endpoints |
| DP-02 | container | pre-push | Tunnel setup tolerates one cold resolver stall | Data Plane E2E Traffic Through All VPN Endpoints |
| DP-03 | container | pre-push | Clients are the cores deployed by Panel and Node | Data Plane E2E Traffic Through All VPN Endpoints |
| DP-04 | container | pre-push | Xray runtime request traverses the selected Master endpoint | Data Plane E2E Traffic Through All VPN Endpoints |
| DP-05 | container | pre-push | Mihomo runtime configuration is isolated on Control Machine | Data Plane E2E Traffic Through All VPN Endpoints |
| DP-06 | container | pre-push | Mihomo runtime request traverses the selected Master endpoint | Data Plane E2E Traffic Through All VPN Endpoints |
| DP-07 | container | pre-push | Xray runtime request traverses the selected Worker endpoint | Data Plane E2E Traffic Through All VPN Endpoints |
| DP-08 | container | pre-push | Mihomo runtime request traverses the selected Worker endpoint | Data Plane E2E Traffic Through All VPN Endpoints |
| DP-09 | partial | pre-push | Staging and public CA chains are both trusted without bypass | Data Plane E2E Traffic Through All VPN Endpoints |
| DP-10 | partial | pre-push | Xray TLS outbounds carry explicit Staging trust anchors | Data Plane E2E Traffic Through All VPN Endpoints |
| DP-11 | partial | pre-push | Staging CA material is pinned and reproducible | Data Plane E2E Traffic Through All VPN Endpoints |
| DP-12 | container | pre-push | Production mode does not add Staging roots to trust | Data Plane E2E Traffic Through All VPN Endpoints |
| DP-13 | container | pre-push | Ingress evidence is ambiguous | Data Plane E2E Traffic Through All VPN Endpoints |
| DP-14 | container | pre-push | Data Plane is explicitly disabled | Data Plane E2E Traffic Through All VPN Endpoints |
| DP-15 | container | pre-push | One or more mandatory runtime cases fail | Data Plane E2E Traffic Through All VPN Endpoints |
| NEG-01 | partial | pre-push | Matrix of fifteen fault scenarios verified (NEG-01..NEG-15) | Negative Scenario and Fault Injection Tests |
| NEG-02 | container | pre-push | A registered Worker name claimed for another address is rejected without mutation (NEG-14) | Negative Scenario and Fault Injection Tests |
| NEG-03 | container | pre-push | Partial SSH deployment leaves no false COMMITTED journal state (NEG-13) | Negative Scenario and Fault Injection Tests |
| NEG-04 | partial | pre-push | Preflight, lifecycle, and protocol scenarios verified (NEG-01..NEG-10) | Negative Scenario and Fault Injection Tests |
| NEG-05 | container | pre-push | Backup and restore negative scenarios verified (NEG-11, NEG-12) | Negative Scenario and Fault Injection Tests |
| NEG-06 | container | pre-push | Forged or expired Panel JWT is rejected (NEG-15) | Negative Scenario and Fault Injection Tests |
| NEG-07 | partial | pre-push | Negative suite PASS requires all fifteen scenarios to pass | Negative Scenario and Fault Injection Tests |
| NEG-08 | partial | pre-push | Negative suite cannot be silently skipped for a passing run | Negative Scenario and Fault Injection Tests |
| HOOK-01 | container | pre-push | Pre-existing global deploy hook blocks installation safely | Global Certbot Deploy Hook Ownership |
| HOOK-02 | container | pre-push | Transaction-created hook is cleaned up only while still owned | Global Certbot Deploy Hook Ownership |
| HOOK-03 | container | pre-push | Uncatchable Worker termination is recovered before the next mutation | Global Certbot Deploy Hook Ownership |
| HOOK-04 | container | pre-push | PRESERVE reports package-manager residuals without claiming OS baseline restoration | Global Certbot Deploy Hook Ownership |
| TXN-01 | container | pre-push | Worker deployment is interrupted by a signal | Signal-Safe and Verifiable Transaction Compensation |
| TXN-02 | container | pre-push | Remote rollback cannot claim success after a failed cleanup step | Signal-Safe and Verifiable Transaction Compensation |
| TXN-03 | container | pre-push | Worker and Panel API rollback results are both required | Signal-Safe and Verifiable Transaction Compensation |
| TD-01 | container | pre-push | Destroy policy rejected before the run starts | Teardown Policy Enforcement |
| TD-02 | container | pre-push | Preserve policy after success or failure | Teardown Policy Enforcement |
| TD-03 | container | pre-push | Snapshot restore hook configuration and protocol are validated | Teardown Policy Enforcement |
| TD-04 | container | pre-push | Restore hook receives a versioned request and returns both restored resources | Teardown Policy Enforcement |
| TD-05 | partial | pre-push | Snapshot restore reacquires the remote lock pair before baseline verification | Teardown Policy Enforcement |
| TD-06 | live-only | pre-push | Single-host snapshot reboot does not self-deadlock lock reacquisition | Teardown Policy Enforcement |
| TD-07 | container | pre-push | Snapshot restore hook success requires baseline verification | Teardown Policy Enforcement |
| TD-08 | container | pre-push | Snapshot restore hook does not restore both hosts | Teardown Policy Enforcement |
| LOCK-01 | container | pre-push | A second Control Machine cannot acquire an occupied VPS | Pair-Wide Run Locking |
| LOCK-02 | container | pre-push | Loss of a remote lock-holder session fails closed | Pair-Wide Run Locking |
| MLOCK-01 | container | pre-push | Existing management command is blocked while the E2E run owns the host | Shared Mutation Lock Across All Management Entry Points |
| MLOCK-02 | container | pre-push | Runner-owned nested command does not release exclusivity | Shared Mutation Lock Across All Management Entry Points |
| MLOCK-03 | container | pre-push | Unsafe remote lock path is rejected | Shared Mutation Lock Across All Management Entry Points |
| STATE-01 | container | pre-push | Run ID cannot escape the artifact root | Durable Run State for Partial CLI Modes |
| STATE-02 | container | pre-push | Partial mode cannot resume a different run or repeat completed installation | Durable Run State for Partial CLI Modes |
| RED-01 | container | pre-push | Redacted copy of credentials file | Redacted Diagnostic Artifact Collection |
| RED-02 | container | pre-push | Diagnostic files contain required safe fields | Redacted Diagnostic Artifact Collection |
| RES-01 | container | pre-push | PASS requires all active Data Plane runtime cases | Result Status Semantics |
| RES-02 | container | pre-push | Vision-enabled PASS requires all active runtime cases | Result Status Semantics |
| RES-03 | container | pre-push | result.json schema fields present | Result Status Semantics |
| BOOT-01 | partial | pre-push | Host identity is verified before password authentication | Local Operator Credential Bootstrap and Cleanup |
| BOOT-02 | partial | pre-push | Temporary access is bounded and revoked | Local Operator Credential Bootstrap and Cleanup |
| PKT-01 | container | pre-push | Selected VPS receives the proxy request | Per-Case Data-Plane Packet Evidence |
| PKT-02 | container | pre-push | Packet evidence is unavailable or ambiguous | Per-Case Data-Plane Packet Evidence |
| PKT-03 | container | pre-push | Traffic reaches the wrong VPS | Per-Case Data-Plane Packet Evidence |
| OP-01 | container | pre-push | Five-domain input is validated before network access | Local interactive operator entrypoint |
| OP-02 | container | pre-push | Password is hidden and not persisted | Local interactive operator entrypoint |
| SSHID-01 | container | pre-push | Host key is confirmed | Out-of-band SSH host identity verification |
| SSHID-02 | container | pre-push | Host key is not confirmed | Out-of-band SSH host identity verification |
| TSSH-01 | container | pre-push | Temporary key is installed | Temporary SSH access with remote expiry |
| TSSH-02 | container | pre-push | Bootstrap fails after expiry is armed | Temporary SSH access with remote expiry |
| REV-01 | container | pre-push | Immediate revocation succeeds | Immediate credential revocation gates overall status |
| REV-02 | container | pre-push | Immediate revocation cannot be verified | Immediate credential revocation gates overall status |
| LOCAL-01 | container | pre-push | GitHub CI runs without target credentials | Local-only live VPS credential handling |
| LOCAL-02 | live-only | pre-push | Local operator starts a live run | Local-only live VPS credential handling |

## Partial splits

- **PRE-04** — Container proves the private/reserved rule against Podman addresses with an explicitly scoped, fail-closed exemption; the live run is authoritative for real public addresses.
- **FW-03** — Container proves isolation between distinct source addresses; provider-level external reachability is live-only.
- **DP-09** — Container proves explicit verify anchors and no global trust change; public Let's Encrypt issuance is live-only.
- **DP-10** — Container proves the injected verify anchor is required; real Staging material is live-only.
- **DP-11** — Container proves fixture CA pinning by digest; real Staging CA distribution is live-only.
- **NEG-01** — Container witnesses the matrix one case per row, each at its own boundary; 'all 15 scenarios terminate at their designated boundaries' is a property of the suite's case list rather than a verdict one run can produce, and `catalog gaps` with the divergence table is what audits it.
- **NEG-04** — Container witnesses the ten rows one case per sentence, including the timeout bounds `MN-OUTAGE` records as offline and control-plane seconds; the conjunction over the ten is a suite property, not a verdict a single case can read.
- **NEG-07** — Container proves the aggregate refuses a run that recorded any non-PASS among its declared cases; the live `negative_tests` field, the `NOT_RUN` and `PARTIAL` states and a skip verdict of INCOMPLETE do not exist in this contour, whose aggregate turns a skipped declared case into FAIL.
- **NEG-08** — Container proves a run cannot report PASS while a declared case is SKIP; the negative phase the sentence names, and its INCOMPLETE verdict, are live-only because this suite has no switch that disables a phase and aggregates a skip to FAIL.
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
- **SUB-EDGE** — promotion target: Real Subscription Delivery and User-Agent Policy
- **SUB-EDGE-BAD** — promotion target: Real Subscription Delivery and User-Agent Policy
- **NGX-HYGIENE** — promotion target: All-in-One Master VPS Installation Verification
- **NGX-SCANNER** — promotion target: All-in-One Master VPS Installation Verification
- **PRE-INPUTS** — promotion target: All-in-One Master VPS Installation Verification
- **PRE-INPUTS-BAD** — promotion target: All-in-One Master VPS Installation Verification
- **SUB-JSON-SHAPES** — promotion target: Real Subscription Delivery and User-Agent Policy
- **AIO-REVOKE** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **AIO-RESTART** — promotion target: All-in-One Master VPS Installation Verification
- **AIO-IDEMPOTENT** — promotion target: All-in-One Master VPS Installation Verification
- **AIO-NEG-DEST** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **AIO-NEG-PORT** — promotion target: All-in-One Master VPS Installation Verification
- **AIO-NEG-ACME** — promotion target: Independent All-in-One acceptance topology
- **AIO-NEG-DEP** — promotion target: All-in-One Master VPS Installation Verification
- **AIO-NEG-PIN** — promotion target: Pinned Version Fidelity
- **AIO-CHANNEL-NOOP** — promotion target: All-in-One Master VPS Installation Verification
- **AIO-CHANNEL-ROLLBACK** — promotion target: Signal-Safe and Verifiable Transaction Compensation
- **AIO-INTERRUPT** — promotion target: Signal-Safe and Verifiable Transaction Compensation
- **AIO-CHANNEL-DEV** — promotion target: All-in-One Master VPS Installation Verification
- **AIO-FAULT-DISK** — promotion target: Lifecycle recovery acceptance
- **AIO-FAULT-PANEL** — promotion target: All-in-One Master VPS Installation Verification
- **AIO-FAULT-XRAY** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **AIO-FAULT-LATENCY** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
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
- **MN-LOCK** — promotion target: Pair-Wide Run Locking
- **MN-LOCK-LOSS** — promotion target: Pair-Wide Run Locking
- **MN-LOCK-PATH** — promotion target: Shared Mutation Lock Across All Management Entry Points
- **MN-LOCK-CLI** — promotion target: Shared Mutation Lock Across All Management Entry Points
- **MN-LOCK-NESTED** — promotion target: Shared Mutation Lock Across All Management Entry Points
- **RUNID-01** — promotion target: Durable Run State for Partial CLI Modes
- **RESUME-01** — promotion target: Durable Run State for Partial CLI Modes
- **PODNET-MASTER-ADDR** — promotion target: Distributed Worker VPS Deployment Verification
- **WRK-06** — promotion target: Distributed Worker VPS Deployment Verification
- **ACME-REJECT-ARB** — promotion target: Global Certbot Deploy Hook Ownership
- **GATE-BUDGET** — promotion target: Result Status Semantics
- **GATE-STATUS** — promotion target: Result Status Semantics
- **GATE-TEARDOWN** — promotion target: Teardown Policy Enforcement
- **GATE-COVERAGE** — promotion target: Result Status Semantics
- **GATE-PREPUSH** — promotion target: Result Status Semantics
- **GATE-DIVERGENCE** — promotion target: Result Status Semantics
- **MN-REVOKE** — promotion target: Data Plane E2E Traffic Through All VPN Endpoints
- **MN-OUTAGE** — promotion target: Negative Scenario and Fault Injection Tests
- **MN-RESTART** — promotion target: Negative Scenario and Fault Injection Tests
- **MN-SSHKEY** — promotion target: Preflight SSH Trust and DNS Verification
- **MN-SSH-DOWN** — promotion target: Negative Scenario and Fault Injection Tests
- **MN-VISION** — promotion target: Independent Optional Vision Domains
- **VIS-CONFIG** — promotion target: Independent Optional Vision Domains
- **VIS-GATE** — promotion target: Independent Optional Vision Domains
- **MN-ARGV-OBSERVER** — promotion target: Distributed Worker VPS Deployment Verification
- **AIO-AUTH-NEG** — promotion target: Negative Scenario and Fault Injection Tests
- **MN-DUP-ADD** — promotion target: Negative Scenario and Fault Injection Tests
- **MN-ENV-CONTRACT** — promotion target: Distributed Worker VPS Deployment Verification
- **PO-INSTALL** — promotion target: Independent Panel-only acceptance topology
- **PO-HOST** — promotion target: Independent Panel-only acceptance topology
- **PO-API** — promotion target: Independent Panel-only acceptance topology
- **PO-SQUAD** — promotion target: Independent Panel-only acceptance topology
- **PO-SQUAD-REFUSED** — promotion target: Independent Panel-only acceptance topology
- **PRE-PROXY-CIDR** — promotion target: All-in-One Master VPS Installation Verification
- **PRE-PROXY-CIDR-OVERRIDE** — promotion target: All-in-One Master VPS Installation Verification
- **TLS-LINEAGE** — promotion target: All-in-One Master VPS Installation Verification
- **TLS-LINEAGE-BAD** — promotion target: All-in-One Master VPS Installation Verification
- **FAIL-STEP** — promotion target: All-in-One Master VPS Installation Verification
- **PANEL-ASSET-VERIFICATION** — promotion target: All-in-One Master VPS Installation Verification
- **PINNED-INSTALLER-HOSTS** — promotion target: All-in-One Master VPS Installation Verification
- **VERIFIED-ARTIFACT-FETCH** — promotion target: All-in-One Master VPS Installation Verification
- **MN-PARTIAL-SUCCESS** — promotion target: Distributed Worker VPS Deployment Verification
- **MN-ADD-NODE-REFUSED** — promotion target: Distributed Worker VPS Deployment Verification
- **MN-WIZARD-FLOW** — promotion target: Distributed Worker VPS Deployment Verification
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
- **AIO-PKT-02** — promotion target: Per-Case Data-Plane Packet Evidence
- **MN-PKT-03** — promotion target: Per-Case Data-Plane Packet Evidence
