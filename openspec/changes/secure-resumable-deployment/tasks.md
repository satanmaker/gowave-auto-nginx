# Tasks

Each implementation group lands its own regression tests and operator documentation. No box is satisfied by a configuration file alone when the corresponding spec requires effective-state evidence. Run privileged tests only in disposable containers/VMs; live VPS actions need separate authorization.

## 1. Durable draft and report foundations

- [ ] 1.1 Add versioned secret-free deployment draft/checkpoint persistence under `modules/` with atomic fsync/rename, root-only ownership, schema checks, symlink refusal and concurrent-writer protection; verify unit tests for interrupted writes, invalid input, unsafe paths, stale revisions and exclusion of secrets, and register new TestCase classes in `tests/run_ci.py`.
- [ ] 1.2 Define per-host security-report serialization and final operation-state reduction with separate registration, readiness, cleanup and recovery states; verify schema/status/exit tests, timestamps, stale-report rejection and redaction tests.
- [ ] 1.3 Document draft/report locations, permissions, retention/abandon behavior and schemas in the operator/wizard guides in RU and EN; verify examples match the serialization tests and contain no credentials.

## 2. Transactional role firewall policy

- [ ] 2.1 Implement shared role-policy inputs and complete daemon/socket SSH discovery for Master and Worker; verify focused security/node-integration tests render the design's port matrix for Panel-only, AIO and Worker, custom Node ports, IPv4-only and dual-stack, including streamed payload copies.
- [ ] 2.2 Extend preflight to detect protected-port/source conflicts from broad, range and single-port rules and unsupported competing managers while preserving unrelated administrator rules; verify tests reject each conflict before mutation and retain unrelated allows with reported exceptions.
- [ ] 2.3 Bring Master onto verified before-image/apply/restore semantics, remove suppression of required UFW failures and preserve Worker's existing rollback guarantees; verify fault injection at snapshot, each mutation, activation and restoration, semantic before/after rule comparison and exactly-once recovery.
- [ ] 2.4 Add disposable acceptance cases for allowed/denied clients, Master-only Worker API sources, SSH preservation and reload/reboot persistence; update case catalog, drivers, behaviour mapping, traceability and relevant suite declarations, and verify effective IPv4/IPv6 rules plus external probes rather than service status alone.
- [ ] 2.5 Document the ingress matrix, conflict remediation, preserved exceptions and firewall recovery route in RU/EN manuals; verify doc guards and case registrations agree with policy inputs.

## 3. Equivalent host hardening and effective reports

- [ ] 3.1 Wire managed Fail2ban configuration and verification into normal Master and Worker paths, including journal backend/matches and discovered ports; verify unit/rendered-payload tests and disposable active-jail tests for standalone and socket SSH, plus an active-service/missing-jail negative case.
- [ ] 3.2 Wire unattended-upgrades package preparation, distro security-origin policy, no-auto-reboot and effective periodic/timer checks into both roles; verify four-distribution policy tests, preserved broader origins, disabled-timer negatives and managed rollback behavior.
- [ ] 3.3 Consolidate selected DoT through the transactional helper independently of missing prerequisites; expose `off`, default `best-effort` and `required` without changing positional argument count, and verify policy parsing, existing-package rerun, effective strict mode and system-query tests.
- [ ] 3.4 Add disposable blocked-853 and failed-DNS-restoration cases for both policies; verify optional failure continues only with working-DNS recovery, required failure blocks readiness and control/recovery statuses are never conflated; update all affected acceptance registrations.
- [ ] 3.5 Produce and aggregate fresh per-host reports with required-control readiness gating; verify readback/rerun and redaction tests, and document policy choices, unsupported controls, preserved APT origins, DoT bypass limits and DNSSEC distinction in RU/EN guides.

## 4. Explicit domain ownership and wizard review

- [ ] 4.1 Replace implicit apex derivation for new plans with explicit Master cover apex and optional www, persist target/role/SAN ownership and compatible non-interactive configuration; verify exact-name tests including `example.co.uk`, shared-zone distinct hosts, conflicting names and advertised A/AAAA ownership.
- [ ] 4.2 Update RU/EN questions and review tables to distinguish Panel, Worker transport/static cover, REALITY, optional Vision, certificate contact, address versus SNI and host ownership; verify PTY/golden-output tests show three Worker names with Vision and two without, no Worker `panel=` label and all mandatory transports retained.
- [ ] 4.3 Route correctable name/domain/DNS/certificate-budget errors back to the offending saved field without resetting the plan; verify multi-node PTY tests preserve previous nodes, language, names and accepted answers and invalidate only dependent review authorization.
- [ ] 4.4 Update setup and deployment manuals with the confirmed domain tables and DNS-to-host examples; verify doc tests and examples do not instruct moving Master apex to Worker or imply an installed Worker Panel.

## 5. Routing, certificates and existing-host migration

- [ ] 5.1 Implement Worker primary static cover and branded unknown-path responses with explicit management/subscription denial before static handling; verify NGINX compilation/rendered payload tests and real-client success for XHTTP, WS and gRPC plus REALITY/optional Vision.
- [ ] 5.2 Remove implicit Worker apex routes/SANs and align owned-name HTTP-01/non-challenge redirects with the updated contract; verify shared-zone Master/Worker different-IP cases, absent Vision inverse assertions and unmanaged-host refusal without altering Master resources.
- [ ] 5.3 Apply consistent owned-lineage selection and explicit live paths on Master and Worker, including suffixed lineages; verify SAN/key/lifetime/issuer/ownership negative tests, selected-path rendering and certificates actually served for every configured SNI.
- [ ] 5.4 Add explicit existing-state inspection and confirmed migration preview while retaining UUID/profile/Host associations; verify legacy-state migration, declined preview/no mutation, idempotent rerun, certificate/route failure rollback and preservation of unrelated/adopted resources.
- [ ] 5.5 Extend acceptance coverage for cover content, management denial, unknown/no-SNI, SNI/Host mismatch, malformed ClientHello, fallback loopback isolation, renewal and failed migration; update all case/behaviour/traceability/driver registrations and verify client-observed responses/certificates, allowing malformed TLS closure rather than demanding HTTP success.
- [ ] 5.6 Document browser fallback behavior, lineage ownership, explicit migration, renewal and rollback in RU/EN guides; verify examples preserve four mandatory profiles and do not promise DPI invisibility or wildcard/DNS-01 support.

## 6. Failure boundaries, retry and process restart

- [ ] 6.1 Isolate menu-started mutations so nested mandatory failures retain strict ERR/errexit semantics while menu navigation survives; verify the real `menu_action` path with failed local install, firewall and payload function calls, no dependent mutations and exactly-once compensation.
- [ ] 6.2 Offer retry for a single/all-failed remote batch and recompute final exits after retries; verify focused wizard tests for ready Panel plus zero successful remote nodes, mixed outcomes, all repaired, declined retry and registered-node/failed-cleanup without duplicate creation.
- [ ] 6.3 Integrate draft reload, review authorization and per-Panel/local/remote checkpoints with existing transaction recovery and fresh remote access; verify new-process interruption/resume tests recheck successful components without reinstalling them and preserve temporary-access revocation guarantees.
- [ ] 6.4 Reconcile actual Panel UUID/profile/Host and host readiness/security identity before resume; verify unreachable hosts, drift, incompatible schema/revision and ambiguous legacy state stop only affected work with recovery guidance and preserve completed siblings.
- [ ] 6.5 Document continue/new-plan/abandon actions, immutable completed identities, retry inspection and exit codes 0/1/2 in RU/EN operator help; verify documentation and menu tests distinguish Panel failure, partial completion and complete readiness.

## 7. Progress and composed installation evidence

- [ ] 7.1 Add allowlisted safe stage events through registration, remote hardening, ACME, deployment, verification and cleanup after country entry; define finite named budgets and bounded heartbeat notices and verify PTY/no-controlling-TTY tests, timeout attribution and secret-free stderr/event output.
- [ ] 7.2 Persist final results before redraw and keep summary readable until explicit return, with no positional-command pause; verify success, degraded security, indeterminate verification and cleanup-failure displays in both languages.
- [ ] 7.3 Add a composed menu-to-final mixed-topology test covering Panel + local Node + one remote Node, country entry, real orchestration boundaries, failure, retry, interruption and restart; verify final Panel readback and preserved successful identities rather than only source guards or stubbed helper outcomes, and register its acceptance artifacts completely.
- [ ] 7.4 Update RU/EN progress/help and troubleshooting examples with stages, budgets, report evidence and recovery actions; verify documented outcomes correspond to the composed tests and do not equate registration with data-plane verification.

## 8. Cross-cutting acceptance and delivery evidence

- [ ] 8.1 Run changed-shell syntax checks, error-severity ShellCheck, focused Python/PTY/rendered-payload tests, `python3 tests/run_ci.py --check-completeness` and affected documented suites in cheapest-first order; record actual commands/results and explicitly name unavailable checks without bypassing failures.
- [ ] 8.2 Run disposable rootful Podman acceptance across AIO, multi-node and Panel-only, with a named coverage matrix for Ubuntu 24.04/26.04, Debian 12/13, IPv4/dual-stack, SSH variants, rerun, reboot and injected rollback; verify each required scenario has effective-state/client evidence and no skipped/incomplete required result is called a pass.
- [ ] 8.3 Run existing transport/client and lifecycle/recovery regressions alongside changed security/domain cases; inspect final result artifacts and record commit ancestry, topology/options, evidence paths, failures versus retries and any untested live-host behavior.
- [ ] 8.4 Reconcile final implementation with all five deltas and operator manuals, run strict OpenSpec validation and document migration/compatibility limits; verify no orphan case, TestCase, behaviour or traceability entry remains and no out-of-scope feature was introduced.

## Workflow follow-up

- Review the planning artifacts before starting the apply workflow.
- Archive and sync only after implementation and the recorded acceptance requirements are satisfied; review overlapping main-spec updates from other branches before integration.
- Live-host reproduction or migration requires separate operator authorization; do not infer it from acceptance on disposable fixtures.
