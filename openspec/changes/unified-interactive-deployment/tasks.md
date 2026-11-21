# Tasks

## 1. Unified language-first entrypoint

- [ ] 1.1 Add a single interactive entry route that selects `ru`/`en` before rendering any menu and routes to existing lifecycle operations; verify with wizard unit tests that no menu text precedes language selection and that explicit commands remain prompt-free.
- [ ] 1.2 Add menu flows for new deployment and adding nodes to an existing Panel while retaining module boundaries; verify menu routing and non-interactive positional compatibility with targeted CLI tests.
- [ ] 1.3 Add translated prompts, menu labels, and validation messages for new routes; verify Russian/English catalog key parity and run the wizard localization tests.

## 2. Editable plan and preflight boundary

- [ ] 2.1 Add a plan review screen that can edit any collected field and re-run dependent validation before mutation; verify changing one field preserves unrelated values and issues no server-side commands.
- [ ] 2.2 Add local controller-to-VPS SSH reachability checks using each planned node's configured address, user, and port; verify reachable/unreachable outcomes with mocked SSH and prove checks occur before install mutations.
- [ ] 2.3 Implement the Globalping feasibility spike for DNS and TCP/443, country selection, bounded polling, rate/terms review, and observed RU/CN/IR probe availability; record evidence in the design/task ledger and enable the optional provider only if all criteria pass, otherwise verify the build leaves external probing disabled and installation independent.
- [ ] 2.4 If the Globalping spike passes, add the optional external check, target/result disclosure and consent, and pass/fail/insufficient/unavailable classification; verify request and response behavior with mocked API tests and an opt-in live smoke test against an approved public fixture.
- [ ] 2.5 Present failed external checks with continue-or-edit choices and insufficient data as inconclusive; verify neither outcome is reported as a confirmed block and that declining to continue returns to plan editing.

## 3. Failure-isolated multi-node deployment

- [ ] 3.1 Refactor batch onboarding to capture each node's target, phase, exit result, and safe diagnostic text while continuing independent nodes and the Panel deployment; verify injected failure on one node does not skip successful siblings or convert their status to failure.
- [ ] 3.2 Add final per-node success/failure summary and selective retry selection; verify successful nodes are not invoked again when failed nodes are selected.
- [ ] 3.3 Add read-only retry diagnostics for Panel registration, recovery journal, and reachable VPS managed state, followed by explicit continuation/compensation confirmation; verify no cleanup or retry command runs before confirmation and ambiguous state is preserved for manual recovery.
- [ ] 3.4 Ensure summaries and captured diagnostics redact credentials and do not expose SSH passwords, private keys, API tokens, or other secrets; verify with sentinel-secret tests across success and failure paths.

## 4. Add nodes to an existing Panel

- [ ] 4.1 Detect and display a uniquely identified local Panel for confirmation; verify local Panel detection, absent Panel, and ambiguous-target behaviors with unit tests.
- [ ] 4.2 Add explicit Panel address entry and API identity/reachability verification when local discovery is absent or ambiguous; verify a wrong/unavailable target is rejected before any Worker access or mutation.
- [ ] 4.3 Document the unified entrypoint, language-first menu, plan editing boundary, external probe privacy/limitations, and partial-node recovery; verify documented invocations match the tested CLI.

## 5. Integration and acceptance

- [ ] 5.1 Add deterministic Podman acceptance coverage for a multi-node deployment with one failed node, a successful sibling, final partial-success report, and selective retry; verify the resulting host and Panel state rather than relying only on command exit status.
- [ ] 5.2 Add acceptance coverage for adding a node to an existing Panel and for a pre-mutation refusal when Panel/API verification fails; verify no Worker-side mutation occurred on refusal.
- [ ] 5.3 Run targeted Python unittest/shell syntax and ShellCheck gates, then the relevant Podman topology suite; record exact commands and outcomes, and identify any external Globalping smoke check not run.
