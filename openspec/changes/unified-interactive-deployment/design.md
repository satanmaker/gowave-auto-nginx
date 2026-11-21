# Design

## Context

See `proposal.md` — Why. The completed `interactive-setup-wizard` change already supplies a language catalog, plan collection, certificate budget, temporary SSH access, and a wizard over the existing `install` command. The `inspiration-backlog` change already owns required-input validation, DNS/Cloudflare preflight, shared failure reporting, and artifact-fetch reliability. This change extends those surfaces rather than replacing them.

The current top-level `gowave-auto.sh` menu is English and precedes the language prompt inside the install wizard. `wizard_onboard_nodes` processes nodes in sequence and returns failure when the onboarding batch contains a failure, which can make a completed Panel deployment appear as a failed overall command. The existing `node add` path has transaction journals and action-aware compensation; retries must respect that state rather than blindly replaying or deleting it.

## Goals / Non-Goals

**Goals:**
- Keep one user-facing shell entrypoint and preserve internal module boundaries and positional automation contracts.
- Make plan edits and decisions visible before the first server mutation.
- Distinguish local controller-to-VPS SSH reachability from optional geographically distributed user-reachability diagnostics.
- Preserve transaction safety while reporting independent node outcomes and supporting selective retries.

**Non-Goals:**
- Replace or duplicate existing input, certificate-budget, Cloudflare, port-conflict, journal, or compensation checks.
- Scan arbitrary ports or build a general-purpose censorship/uptime scanner.
- Make Globalping a hard dependency, install a resident probe, or require a user API key.
- Automatically undo successful deployment phases after the operator chooses to deploy.
- Change the non-interactive positional CLI contract or translate non-interactive output.

## Decisions

### D1 — One entrypoint, retain modular Bash implementation

Keep `gowave-auto.sh` as the single operator entrypoint. It selects the wizard language before rendering its menu, then routes to the existing lifecycle operations and the guided deployment/add-node flows. Keep plan/i18n/SSH/preflight behavior in their existing modules; do not concatenate the node installer into the panel script. The positional `install` and `node add` routes remain prompt-free when fully specified. This reuses existing locks and transaction paths; a separate frontend executable or physical monolithic script would create another entrypoint or weaken module boundaries.

### D2 — Plan is editable until an explicit mutation boundary

Represent collected values as the current plan and render a review screen with field selection. Editing a field re-runs its dependent syntactic, uniqueness, certificate-budget, and DNS validations. The only boundary that ends arbitrary plan editing is explicit confirmation immediately before the first server mutation. After that point, expose progress, remaining work, and safe retry choices, not a fictional rollback of completed steps. This avoids gathering the same data again while respecting externally visible side effects.

### D3 — Separate local install readiness from external reachability

Run SSH connectivity checks from the operator host to each remote VPS using the exact configured address, port, and user; this tests the path needed by the installer. Keep existing per-host input and install preflights authoritative. Offer external DNS and TCP/443 diagnostics as a separate optional action, since those probes answer whether public endpoints appear reachable from selected geographies, not whether the operator can SSH to a VPS. Do not probe unrelated ports. External failure or no probe result is informational and requires an explicit continue-or-edit choice; it does not silently skip a failed VPS or assert a country-wide block.

### D4 — Globalping is an optional provider behind a narrow diagnostic contract

Prototype Globalping REST API for country-scoped DNS and TCP ping using port 443. Before enabling it in the interactive flow, verify supported query forms, actual country probe availability (especially RU/CN/IR), bounded result polling, provider limits, and its terms. A provider error, no matching probes, or ambiguous result is `unavailable/insufficient`, not a reachability verdict. Requests disclose the target IP/FQDN and Globalping measurement IDs/results are publicly retrievable; show that notice and obtain consent before submitting. If these conditions cannot be met, retain the optional diagnostic seam and manual/local checks without blocking install. Rejected alternative: hard-code an unverified provider assumption into core installation or run a broad scan.

### D5 — Continue independent node jobs and preserve per-node outcomes

Treat Panel/local installation and each remote onboarding as separately recorded phases. A remote-node failure is captured with its target, phase, and bounded diagnostic output; continue other independent nodes and produce a final success/failure summary. Avoid leaking secrets in captured output. Do not mark a failed node successful merely because its siblings succeeded. This changes batch orchestration only; the individual `node add` transaction remains responsible for its existing compensation and journal semantics.

### D6 — Selective retry starts with read-only diagnosis

A retry begins with read-only inspection of the existing transaction journal/Panel registration and the remote node's reachable managed state. Present what could be established and what could not. Ask the operator to choose a supported continuation or action-aware compensation; do not run destructive cleanup automatically. If diagnostics cannot safely establish state, stop that retry and show the manual recovery route rather than guessing. Retrying a node must not re-run successful sibling operations.

### D7 — Resolve existing Panel explicitly before add-node mutation

For the add-node menu action, inspect whether the current host has a usable local Panel. If exactly one target is identified, display it for confirmation. If not found or ambiguous, ask for a Panel address and verify API reachability/identity before collecting SSH access or mutating a Worker. Reuse the existing authenticated API client and mutation lock; do not create a second API implementation.

### D8 — Keep acceptance deterministic and provider-independent

Unit tests mock the diagnostic provider and assert request construction, country selection, DNS/TCP result classification, no-probe handling, and disclosure/consent behavior. Podman cases inject failures at individual remote-node boundaries and assert that successful siblings and Panel remain successful while failures are summarized. The core acceptance suite must not depend on public Globalping probe availability; a live provider smoke check is optional, rate-limited, and uses an approved public fixture.

## Risks / Trade-offs

- [Globalping has no probe in a requested country or changes API behavior] → classify the check as unavailable, validate through mocked unit tests, and keep deployment independent of the provider.
- [A user mistakes a few external probes for a guarantee across a country] → report selected country/probe and timestamp, avoid country-wide claims, and preserve the continue/edit decision.
- [The target becomes publicly visible through measurement metadata] → disclose target/result visibility before submission, require consent, and avoid logging secrets or unrelated plan data.
- [Continuing after one node failure obscures an incomplete cluster] → provide per-node final states and an overall partial-success status distinct from full success.
- [Retry encounters an incomplete journal or unreachable VPS] → do not infer cleanup success; preserve the journal, explain the limit, and require manual recovery.
- [Changing menu entry could affect scripted callers] → leave all explicit subcommands and complete positional invocations on their existing prompt-free route; test both paths.

## Migration Plan

1. Add and test the unified interactive menu and language-first selection while retaining existing command routes.
2. Add plan review/edit navigation and the pre-mutation confirmation boundary.
3. Add local SSH readiness checks and provider-neutral optional DNS/TCP diagnostic behavior; integrate Globalping only after its documented API and target-country coverage are verified.
4. Refactor multi-node orchestration to record isolated outcomes and report partial success without changing per-node transaction compensation.
5. Add read-only retry diagnosis and explicit action choice, then exercise it with injected failures in deterministic acceptance tests.
6. Rollback is a code revert. Existing host state and transaction journals are not deleted by the UI change; users with a partial deployment retain existing recovery procedures.

## Open Questions

- Exact Globalping probe availability for RU, CN, and IR and whether the service permits the proposed low-volume preflight pattern must be confirmed during the provider spike before its integration is enabled.
