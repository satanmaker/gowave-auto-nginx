# Design

## Context

See `proposal.md` for motivation. Research baseline is `origin/develop` at `3b3536c`, isolated on `research/issue-2-security`; runtime failures on the operator's host have not been reproduced. This design separates confirmed source defects from a plausible explanation of the reported silence.

Observed integration points:

| Area | Current evidence | Consequence |
| --- | --- | --- |
| Master firewall | `modules/security.sh:23–86` lacks explicit default policy and suppresses UFW errors | Existing permissive policy can survive an apparently successful install |
| Worker firewall | `gowave-node-auto.sh:4432–4478` snapshots and applies default deny but detects only one broad-rule shape | Reuse its rollback guarantees, extend conflict checks rather than reset the firewall |
| Host helpers | `assets/security/managed.py` already has transactional DNS, jail and APT verification | Wire and strengthen existing code instead of inventing another hardening subsystem |
| Alternate DNS path | `modules/os.sh:302–315` runs legacy Debian resolver preparation only when prerequisites were missing | Package installation is an unreliable gate for selected security controls |
| Wizard state | `modules/wizard.sh:739–796`, `1333–1353`, `1539–1544` | Plan resets; all-failed remote batch lacks retry; successful retry can retain an old exit; stored results are not resume input |
| Stage output | `modules/ssh_bootstrap.sh:490–531`, `modules/wizard.sh:1408–1445` | Country precedes a long buffered operation; a final silent exit is not yet proven |
| Menu errors | `gowave-auto.sh:1928–1936` invokes operations in an OR-list | Bash can suppress nested errexit/ERR semantics; mandatory boundaries need explicit isolation and propagation |
| Domain model | `modules/nginx.sh:23–34`, `modules/i18n.sh:281–284,308` | Last-two-label apex inference and Worker `panel=` terminology obscure ownership |
| Certificate reuse | Master selects actual lineage paths; Worker payload assumes hostname-based paths | Suffix lineages and shared-zone ownership need one contract |

Several shell helpers have sibling definitions inside streamed heredocs. Symbol graphs do not establish payload call graphs; source searches and rendered-payload tests must include these copies.

## Goals / Non-Goals

**Goals:** Preserve completed independent work, verify effective security rather than file presence, and give domain/certificate identity one explicit owner per host. Use existing module boundaries and upstream network/API contracts.

**Non-Goals:** Universal resume at arbitrary shell instructions, automatic destructive cleanup, DNS provider integration, shared wildcard certificates, relocating the apex between hosts, or changing upstream GoWave/Xray binaries. Registration readback is not a claim that every client data path was tested.

## Decisions

### 1. One declarative role and ingress matrix

Use the same policy inputs on Master and Worker. No generic firewall reset or deletion of administrator rules.

| Port / listener | Panel-only | All-in-One | Worker |
| --- | --- | --- | --- |
| Discovered SSH TCP ports | Public administration, preserved before activation | Same | Same, including daemon/socket discovery |
| TCP 80 | Public local HTTP-01; managed HTTP redirects | Same | Same for its own names |
| TCP 443 | Public Stream to Panel/cover | Public Stream to Panel/transports/cover | Public Stream to transports/cover, never Panel |
| 3000 / 3001 | Loopback Panel/metrics | Loopback Panel/metrics | Absent |
| Configured Node API, default 3002 | Absent | Loopback use; wildcard externally denied | Master IPv4/IPv6 sources and loopback only |
| 7443 / 9443 | Loopback HTTPS/decoy | Loopback HTTPS/decoy | Loopback HTTPS/decoy |
| 8443, optional 8444 / 9444 | Absent | Loopback REALITY, optional Vision/fallback | Same |
| 10001–10003 | Absent | Loopback transport inbounds | Same |

Policy defaults: deny incoming, allow outgoing. Capture UFW persisted files, effective family rules and enabled/disabled state before mutation. Refuse unreadable or unrestorable baselines. Classify conflicts against protected ports/source restrictions, including general and range rules, not just a string match in `ufw status`. Preserve unrelated administrator allows, disclose them as exceptions in the report and never imply the entire host has only three open ports. Refuse managed isolation conflicts and unsupported competing firewall managers before mutation; do not flush their rules.

Allow all discovered SSH ports before enabling/reloading. Bind-family detection and UFW declarations must agree. After apply verify default policy, managed rules and effective tables; acceptance tests additionally probe allowed/denied sources from independent clients. Restore prior files, active state and effective policy on failure, comparing semantic rules rather than unstable counter-bearing dumps.

Alternative rejected: enforcing a pristine rule list by resetting UFW. It can lock out administrators and destroy unrelated services.

### 2. Shared verified host controls and honest status

Keep orchestration in `modules/security.sh` and host logic in `assets/security/managed.py`; deliver the same helper to Worker over the existing SSH stream. Eliminate normal-flow reliance on the legacy package-gated DNS writer, without deleting unrelated OS initialization.

- Firewall, Fail2ban SSH protection and unattended security updates are required for baseline readiness. A failed required control blocks that host's ready status, not independent completed nodes.
- Fail2ban verification includes active `sshd` jail, effective ports/settings, systemd backend and journal matching for standalone and socket-activated SSH. Do not modify sshd configuration or root keys.
- APT ensures `unattended-upgrades` is installed, adds the distro security origin, disables auto-reboot, and verifies periodic policy and persistent active timers. Preserve existing origins; if broader origins remain, explicitly say that policy is not security-only. Never silently tighten the operator's unrelated update policy.
- DoT policy values are `off`, `best-effort` (default) and `required`; surface the choice before deployment and provide the same documented non-interactive configuration without positional argument changes. Verify strict effective resolver state and uncached resolution. Best-effort failure permits continuation only after verified restoration of working DNS. Required-mode failure, or unverified recovery in either mode, blocks host readiness. This intentionally refines the existing warning-only DoT scenarios, not a retroactive claim that the previous spec required fail-fast.
- System-resolver DoT is not proof of encryption for application-bypassed DNS and is not DNSSEC.

Write `/var/lib/gowave-auto-nginx/security-report.json` atomically on each host (root-owned 0600). Preserve the existing shared parent directory's permissions when root-owned and not group/world-writable (0755 is acceptable); never chmod the shared state/recovery directory merely to add a report. Newly created directories use 0700. Unlike the shared report parent, the dedicated deployment draft directory must always remain 0700. Both paths reject symlink ancestors and unsafe ownership; a sticky bit does not permit a writable immediate report parent. This avoids changing access for existing consumers while keeping report contents private. Schema version 1 includes host identity/role, installer revision, observation time, each control's requested policy, status (`verified`, `failed`, `skipped`, `unsupported`), safe evidence/reason and recovery (`not-needed`, `verified`, `failed`, `unknown`). Master aggregates remote reports through protected orchestration, not public endpoints. A required unsupported control is not ready. A stale report is history, never a fresh verification.

Alternative rejected: treating successful configuration writes or `systemctl is-active` as sufficient evidence.

### 3. Durable drafts separate from mutation journals

Use a small standard-library Python persistence module under `modules/`, called by the Bash wizard. Do not serialize shell source or use `eval` to reload state. Keep deployment UI state separate from existing resource/transaction journals so abandoning an interview cannot trigger compensation.

Store a single active draft/checkpoint document under `/var/lib/gowave-auto-nginx/deployment/active.json` in a root-owned 0700 directory, file 0600, atomic sibling write, fsync and rename. Include schema version, installer revision, operation id, operation kind, topology, selected language, non-secret accepted answers, reviewed plan revision/digest, explicit domain ownership and per-operation checkpoints. Persist accepted answers after each field; unreviewed drafts are not authorization to execute. Serialize writes under the existing mutation-lock discipline for execution; reject concurrent writers instead of merging unrelated sessions.

Never include passwords, API/JWT tokens, SECRET_KEY, private keys, saved temporary access, or raw command logs. Existing protected runtime configuration may contain secrets; resume references verified resource identities, not copies of those secrets. Validate schema/permissions/ownership and refuse symlinks before loading. Re-prompt transient credentials and host fingerprint for each access attempt.

```text
DRAFT --> REVIEWED --> RUNNING --> VERIFIED
  ^                       |           |
  |                       v           v
correct field           FAILED      recheck on resume
                          |
                          v
                    RECONCILE --> confirm pending work
                          |
                          v
                    INDETERMINATE --> manual recovery
```

Checkpoints are per Panel, local Node and each remote Node, not arbitrary shell line. They record phase, safe reason, attempt and verification scope, plus cleanup/recovery state. Resume first handles any existing transaction recovery, then reads Panel UUID/profile/host associations and host/service/listener/security state; it skips mutation only for reverified components. If version/schema or identity cannot be reconciled safely, stop that operation and show recovery steps. Other completed components remain untouched. Editing pending work invalidates its dependent validations and review authorization only; completed identities are immutable within resume.

Alternative rejected: restarting every command or treating the old TSV result file as a trusted execution cursor.

### 4. Explicit failure boundaries and final-state reduction

Run menu-started mutations behind an isolated execution boundary that retains `set -Eeuo pipefail` and inherited ERR traps; the menu captures the resulting process status, not an OR-list encompassing all nested functions. Keep UI pause/navigation separate from mutations. Every mandatory call and remote payload must have a testable failure propagation path; intentional best-effort controls use explicit policy/result handling, not broad error suppression.

Offer retry for every failed remote operation, including an all-failed batch and a single remote node. Preserve the existing read-only partial-state inspection, fresh temporary-access and explicit continuation/compensation choice. Recompute outcomes after each retry from final state, not initial counters.

Exit contract: `0` all planned components and required controls/cleanup verified; `1` Panel/core operation not ready; `2` Panel ready but at least one planned node or required node cleanup/control is failed or indeterminate. Existing standalone command argument contracts remain; document status semantics in both manuals. A node can be registered while cleanup failed: report these as separate facts and never duplicate registration on retry.

### 5. Safe live progress, including after country entry

Use structured allowlisted stage events, separate from credential-bearing output. Parent UI prints node identity plus registration, remote prerequisites/security, ACME, service/config deployment, verification and temporary-access cleanup. No raw captured payload becomes progress. When no controlling terminal exists, send safe events to the documented stderr/event sink rather than `/dev/null`.

Reuse documented phase timeouts where present; set finite named budgets for remaining waits, state the budget at entry and emit bounded heartbeat notices during otherwise silent phases. A timeout identifies the active node/phase and starts the existing safe recovery path; it is not evidence the remote process stopped or rolled back. Persist the outcome before repainting the menu; hold the final summary until explicit return. Positional invocations have no new prompts or pause.

Exact report: Panel state; each local/remote identity; registration/readiness/cleanup/security states; evidence timestamp; safe reason; retry/recovery next action. Never label registration verification as data-plane verification.

### 6. Explicit domain roles and static cover

The operator confirmed three Worker names with Vision, primary serving transports and static cover. Without Vision use two names and retain all four mandatory profiles.

| Host | Name example | HTTPS ordinary client | Authenticated transport |
| --- | --- | --- | --- |
| Master | `example.com`, optional `www.example.com` | Generated cover | Not a published transport identity |
| Master | `panel.example.com` | Panel UI/API/subscriptions | Existing XHTTP/WS/gRPC on configured paths |
| Master | `reality.example.com` | Cover fallback | REALITY |
| Master | `xtls.example.com` | Cover fallback | Optional Vision |
| Worker | `node-1.example.com` | Generated cover; management paths denied | XHTTP/WS/gRPC |
| Worker | `reality-node-1.example.com` | Cover fallback | REALITY |
| Worker | `xtls-node-1.example.com` | Cover fallback | Optional Vision |

Make Master cover apex explicit, with a separately selected www alias; no public-suffix dependency and no last-two-label guessing. Validate exact FQDNs and DNS-to-owning-host addresses before HTTP-01. Same-zone Worker never adds Master apex/www routes or SANs. A different-zone Worker also uses its primary hostname for direct static cover; it does not implicitly claim its own zone apex. A future extra Worker cover hostname is out of scope.

REALITY `address` and SNI currently differ in generated Host records. Preserve that compatible representation unless a specific corrected mapping is necessary; show both fields rather than silently rewriting subscriptions. Preserve original client addresses and PROXY trust boundaries. Deny management paths on Worker before static handling and ensure mismatched SNI/Host cannot select Panel unexpectedly. HTTP method/rate limiting beyond this routing isolation remains out of scope.

Master cover lineages can include explicit apex/www plus REALITY SAN; Worker REALITY lineage contains only its Worker identity. Vision has a separate optional lineage; primary uses its own. Each selected certificate must match all names it serves. Port 80 consistently serves local challenges, redirects other owned names to HTTPS, and refuses unmanaged hosts. This resolves the existing Worker implementation/spec disagreement over non-challenge redirects.

Alternative rejected: two Worker names without a redesign of the three HTTP transports, or moving/round-robining the Master apex to satisfy Worker HTTP-01.

### 7. Consistent lineage adoption and migration

Reuse Master lineage-selection logic on Worker through shared code or synchronized rendered payload logic, not a second weaker implementation. Record intended SANs, host ownership, ACME issuer mode and selected live paths. Validate key match, SAN coverage, lifetime and safe ownership; reject unsuitable candidates with a correction route. Certbot suffix names are valid when the identity matches. Check IPv4 and advertised IPv6 DNS destinations, not the first IPv4 alone.

Do not share private keys across hosts or issue wildcard certificates. Test renewal ownership and verify the certificate actually served at each SNI after activation. Snapshot only resources owned/adopted with explicit consent. On failure restore previous owned references/routes and validate service plus served identity; preserve unrelated certificates and Master apex resources.

State migration adds explicit edge identity with versioning while retaining UUIDs and existing associations. Legacy inference is read-only evidence for a preview, not permission to alter DNS/routes. Display old/new hostnames, routing, SANs and certificate paths; require confirmation for changed existing deployments. New positional installs preserve old argument count, default explicit-cover behavior to disabled unless provided by documented configuration, and never guess an apex. Interactive new Master plans collect the cover name explicitly. No implementation phase may silently migrate installed hosts.

### 8. Evidence ladder and coverage

Start with focused unit/rendered-payload tests, then composed PTY flows and disposable rootful Podman cases. Every changed/new case updates all affected catalog, driver, behaviour, traceability and suite-registry artifacts together; do not create orphan declarations or weaken assertions.

Required samples include all three topologies; all four supported distributions for host-control policy; custom/socket SSH; fresh, rerun, conflicting existing rules, IPv4-only and dual-stack; reboot/persistence and injected rollback failure; DoT 853 refusal with both policies; effective APT/jail settings; single/all-failed retry and repaired exit; interruption/new-process resume; no-TTY progress; country-to-final mixed deployment; shared-zone different-IP ownership; `example.co.uk`; suffixed lineages, wrong SAN/key/issuer, renewal and failed migration. Existing valid-client transport tests run alongside unknown/no-SNI, malformed TLS and Host-mismatch probes. Malformed TLS may close; it need not produce a website.

Source guards and stubs do not prove effective host state. Read firewall and listener state on the relevant host, certificates and HTTP responses from actual clients, and Node identity from Panel. State the topology/distribution/options/commit and evidence files; no green verdict from incomplete/skipped required cases. Live-host reproduction remains separately consented and is not required to author this plan.

## Risks / Trade-offs

- Existing permissive firewall environments can now fail preflight -> show exact conflict and preserve their rules; never reset them automatically.
- A stricter baseline can reveal unavailable packages or services -> mark unsupported/failed accurately and refuse only the affected required readiness claim.
- Persistent drafts contain infrastructure metadata -> root-only permissions, schema validation, no secrets and explicit abandon behavior.
- Resume after drift can misidentify resources -> compare stable UUIDs, host keys and readback; stop rather than guess.
- Menu isolation changes trap behavior -> test mandatory failure and exactly-once compensation through the real menu, including payload functions.
- Primary Worker cover changes browser behavior -> explicit existing-host migration and management-path negative tests.
- DoT verification does not prove application-wide DNS encryption -> document scope; separate control result from working-DNS recovery.
- Broader administrator APT origins conflict with a security-only claim -> preserve and disclose rather than silently override.
- Shared-zone HTTP-01 and advertised AAAA can challenge the wrong host -> verify ownership across advertised addresses and never transfer apex ownership to Worker.

## Migration Plan

1. Land persistence/report schemas and regression tests without applying host migrations.
2. Wire shared host controls, verified firewall policy and failure boundaries; exercise rollback in disposable environments.
3. Introduce explicit domain inputs, lineage paths and resume/readback with compatible non-interactive defaults.
4. Provide existing-state inspection and an explicit routing/certificate migration preview; run only after operator confirmation.
5. Prove the focused matrix, then existing acceptance suites; update both manuals and record limitations.
6. If apply fails, keep the draft and safe diagnostics, compensate only the active owned transaction, verify recovery and offer a fresh readback before continuation. Never undo successful siblings automatically.
