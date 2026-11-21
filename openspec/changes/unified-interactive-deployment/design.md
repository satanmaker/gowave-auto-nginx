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

Check each remote VPS from the operator host using the exact configured address and SSH port, but keep the check unauthenticated: the existing pre-mutation mechanism is `ssh_bootstrap_scan` (`ssh-keyscan` plus the banner filter), while the password is read only inside onboarding and the authenticated session runs under `StrictHostKeyChecking=yes`. An authenticated check cannot live in preflight — it would demand a password before the mutation boundary, in a batch, for every node, and it would put a network round trip inside `preflight_require_inputs`, which the positional unattended path shares. So the local check proves the SSH service answers on that port, and a plan that already carries a fingerprint also refuses a host key that changed. Keep existing per-host input and install preflights authoritative.

Offer external diagnostics as a separate, consented action. They probe what is actually served at the time of the check: DNS answers from the selected country before the first mutation, plus TCP on the SSH port, because port 443 belongs to the installer — `modules/preflight.sh` requires 443 to be free before installation and `modules/nginx.sh` starts the stream listener on 443 afterwards. Port 443 is therefore probed only where a listener exists: the add-nodes path against a running Panel, and the post-install verification of a fresh deployment. A not-yet-served port is never reported as blocked. External failure or insufficient coverage is informational and requires an explicit continue-or-edit choice; it does not silently skip a failed VPS or assert a country-wide block.

### D4 — Globalping is an optional provider behind a narrow diagnostic contract

Prototype Globalping REST API for country-scoped DNS and TCP probes. Before enabling it in the interactive flow, verify supported query forms, actual country probe availability (especially RU/CN/IR), bounded result polling, provider limits, and its terms. Keep two distinct non-verdicts: `unavailable` when the service answers with an error or refuses the request, and `insufficient` when the service works but has no matching probe or returns no usable measurement. Both are reported as "could not be determined" and neither is a reachability verdict. Requests disclose the target IP/FQDN and Globalping measurement IDs/results are publicly retrievable; show that notice and obtain consent before submitting anything, and send no request when consent is declined. If these conditions cannot be met, retain the optional diagnostic seam and manual/local checks without blocking install — a build with the provider disabled makes no third-party request at all. Rejected alternative: hard-code an unverified provider assumption into core installation or run a broad scan.

### D5 — Continue independent node jobs and preserve per-node outcomes

Treat Panel/local installation and each remote onboarding as separately recorded phases. A remote-node failure is captured with its target, phase, and bounded diagnostic output; continue other independent nodes and produce a final success/failure summary. Avoid leaking secrets in captured output. Do not mark a failed node successful merely because its siblings succeeded. This changes batch orchestration only; the individual `node add` transaction remains responsible for its existing compensation and journal semantics.

### D6 — Selective retry starts with read-only diagnosis

A retry begins with read-only inspection of the existing transaction journal/Panel registration and the remote node's reachable managed state. Inspecting the VPS re-enters the onboarding access contract instead of improvising one: the host-key fingerprint is typed in full, the password is read without echo, and the temporary key is removed by the host timer. Reusing a password from the earlier attempt, or falling back to `StrictHostKeyChecking=accept-new`, would move the password onto an unconfirmed host key and leave a key behind on an interrupted retry. Present what could be established and what could not. Ask the operator to choose a supported continuation or action-aware compensation; do not run destructive cleanup automatically. If diagnostics cannot safely establish state, stop that retry and show the manual recovery route rather than guessing. Retrying a node must not re-run successful sibling operations.

### D7 — Resolve existing Panel explicitly before add-node mutation

For the add-node menu action, inspect whether the current host has a usable local Panel. If exactly one target is identified, display it for confirmation. If not found or ambiguous, ask for a Panel address and verify API reachability/identity before collecting SSH access or mutating a Worker. A remote Panel must be reached over HTTPS with certificate validation, or with a certificate fingerprint the operator confirms explicitly; plaintext HTTP is accepted only for the local loopback address. Credentials are sent only after that channel check passes, because the existing `GoWaveClient` login POST carries the administrator password and the client today has no caller-supplied verification policy. Reuse the existing authenticated API client and mutation lock; do not create a second API implementation.

### D8 — Keep acceptance deterministic and provider-independent

Unit tests mock the diagnostic provider and assert request construction, country selection, DNS/TCP result classification, no-probe handling, and disclosure/consent behavior, including that a declined consent sends nothing. Podman cases inject failures at individual remote-node boundaries and assert that successful siblings and Panel remain successful while failures are summarized. The core acceptance suite must not depend on public Globalping probe availability; a live provider smoke check is optional, rate-limited, and uses an approved public fixture.

### D9 — Archive order is a prerequisite, not an afterthought

`setup-wizard` and `install-preflight` exist only as unarchived change deltas (`interactive-setup-wizard`, `inspiration-backlog`); `openspec/specs/` holds neither capability. A `MODIFIED` delta against a capability with no archived spec is refused at archive time, and `openspec validate --all --strict` — what CI runs — reports it only as an INFO line and still exits zero. This change therefore records the order: archive `interactive-setup-wizard` and `inspiration-backlog` first, then this change, then recompute the requirement and scenario counts. Because `install-preflight` has no archived spec yet, its delta carries a `## Purpose` so a first archive cannot leave a `TBD` placeholder behind.

## Risks / Trade-offs

- [Globalping has no probe in a requested country or changes API behavior] → classify the check as `insufficient` or `unavailable`, validate through mocked unit tests, and keep deployment independent of the provider.
- [A user mistakes a few external probes for a guarantee across a country] → report selected country/probe and timestamp, avoid country-wide claims, and preserve the continue/edit decision.
- [The target becomes publicly visible through measurement metadata] → disclose target/result visibility before submission, require consent, and avoid logging secrets or unrelated plan data.
- [Continuing after one node failure obscures an incomplete cluster] → provide per-node final states, a printed per-node summary, and a partial-success exit code distinct from both full success and a failed Panel installation, so automation cannot read an incomplete cluster as complete.
- [Retry encounters an incomplete journal or unreachable VPS] → do not infer cleanup success; preserve the journal, explain the limit, and require manual recovery.
- [Changing menu entry could affect scripted callers] → leave all explicit subcommands and complete positional invocations on their existing prompt-free route; test both paths.
- [The menu and the alias for translated strings drift apart] → the current catalog guard accepts `t`/`tf` calls only for `wizard.` keys and only in two modules; adding menu labels must extend that guard deliberately, with a negative test that still fails for any other shipped script.

## Migration Plan

0. Archive the prerequisite changes `interactive-setup-wizard` and `inspiration-backlog`, so `setup-wizard` and `install-preflight` exist in `openspec/specs/` before this delta is archived; verify with a trial archive on a scratch copy.
1. Add and test the unified interactive menu and language-first selection while retaining existing command routes.
2. Add plan review/edit navigation and the pre-mutation confirmation boundary.
3. Add local SSH readiness checks and provider-neutral optional DNS/TCP diagnostic behavior; integrate Globalping only after its documented API and target-country coverage are verified.
4. Refactor multi-node orchestration to record isolated outcomes and report partial success without changing per-node transaction compensation.
5. Add read-only retry diagnosis and explicit action choice, then exercise it with injected failures in deterministic acceptance tests.
6. Recompute the requirement and scenario totals after archive and update `README.md` with the count its own guard checks.
7. Rollback is a code revert. Existing host state and transaction journals are not deleted by the UI change; users with a partial deployment retain existing recovery procedures.

## Open Questions

- Exact Globalping probe availability for RU, CN, and IR and whether the service permits the proposed low-volume preflight pattern must be confirmed during the provider spike before its integration is enabled.
