# Tasks

## 1. Menu and review
- [ ] 1.1 Update RU/EN action labels, topology explanations, contextual headers and field prompts in the catalog and guide. Verify all three layouts, no default topology on Enter, Panel-only omits local Vision, and catalog/documentation parity in `tests/test_wizard.py`.
- [ ] 1.2 Hold interactive status/results until explicit return without rerunning operations. Drive the actual menu using a pseudo-terminal: assert no redraw before Enter, one redraw after Enter, degraded status remains readable, EOF exits safely, and positional status never waits.
- [ ] 1.3 Provide start/edit Panel/edit node/cancel actions at review. Test editing the second node and cancelling leaves siblings unchanged and starts no local or remote mutation; document the review screen.

## 2. Correct fields and name nodes
- [ ] 2.1 Validate primary/cover/Vision domains during collection and review. Add a regression transcript for the second worker's duplicate cover domain: correct it in place before Vision without repeating language or discarding any earlier answers.
- [ ] 2.2 Carry an explicit trimmed display name independently of DNS through local, batch and single add workflows, including summary, bootstrap and API provisioning. Test blank, padded, case-only collision and two distinct same-country nodes; retain positional default behavior.
- [ ] 2.3 Check verified Panel inventory before mutating the worker; recheck name ownership at registration and distinguish create from retry of the same UUID. Test unavailable inventory, concurrent collision, retry of a known identity and no accidental adoption. Document the naming rules and role-specific prompts.

## 3. Onboarding and results
- [ ] 3.1 Emit localized, allowlisted live phase and input prompts on the terminal independently of captured logs. PTY-test a deliberately blocked SSH step: phase and question visible before release, hidden input not echoed, no password or key material in logs or argv.
- [ ] 3.2 Replace premature completion with separate Panel progress and per-node outcomes. Require verified Panel identity/readback for registration; exercise all-success, mixed, all-workers-failed, Panel failure and single add refusal/success, preserving rollback and existing noninteractive codes.
- [ ] 3.3 Wire failed-only retry through partial-state inspection and confirmation, retaining other results. Test no rerun of the successful sibling or Panel, refusal on unverifiable state, and a final screen that remains readable; document action names and limits of registration evidence.

## 4. Exit country and subscription presentation
- [ ] 4.1 Add bounded node-origin country detection, confirmation and strict manual fallback in both node paths. Test distinct local/remote suggestions, lowercase correction, invalid code, provider timeout, no Panel-only lookup, and legacy noninteractive execution without a provider. Document the source-IP disclosure and override.
- [ ] 4.2 Persist confirmed country with managed identity; reconcile existing Hosts by UUID or proven unique ownership before changing remarks. Test two reconciliations preserve UUID/count, unrelated records and confirmed metadata, fail safely on ambiguity, and restore prior labels on rollback.
- [ ] 4.3 Render the five documented label forms for enabled profiles. Update all affected subscription fixtures, consumers, assertion parsers and docs; test Vision on/off, UTF-8 round-trip, two nodes in one country and consistent Mihomo group references without changing endpoint settings.

## 5. Integrated acceptance
- [ ] 5.1 Register affected tests/cases in the existing suite and traceability catalogs; run syntax, ShellCheck, targeted tests, completeness and all affected project suites, recording failures, skips and unrun contours explicitly.
- [ ] 5.2 Drive the composed wizard in a disposable environment: correct worker 2's duplicate domain, observe registration of worker 1, fail worker 2, retry only worker 2, then return to the menu. Capture sanitized phase order, actual Panel node identities and final count, not just process exit.
- [ ] 5.3 Run affected Podman AIO, Panel-only and mixed-topology paths including add to an existing Panel. Import the served Xray JSON and Mihomo YAML with real clients; retain sanitized proof of labels, working references and stable Host UUIDs/count on reconciliation. Keep live credentials and raw subscriptions out of git.
