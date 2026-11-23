# Design

## Context

Three timeout layers exist in `tools/podman_e2e` and each is mis-scaled in a different direction: one container command (300 s, shared by a short probe and by a `podman build` that runs `apt-get`), one case (300 s by default, 6000–11400 s where a case declares its own), one run (2700/4500/4500 s). The runner already reports a case the run budget capped as INCOMPLETE, and the suite already has one vocabulary for "the subject was not there" (`CaseBlocked`) and one for "what was seen cannot decide the question" (`CaseIncomplete`). This change moves two measurements into that vocabulary and sizes the third layer to its work; it does not touch the product or the live contour.

## Decisions

### 1. Per-operation ceilings, bounded by the run's remaining budget

`ensure_image` and `build` get their own ceilings instead of inheriting `DEFAULT_COMMAND_TIMEOUT`. Each is `max(PULL_CEILING_SECONDS, ...)`-free and simple: a declared floor for the operation, capped by `self.context.remaining()` so the command cannot outlive the run.

Alternatives considered:

- Raise `DEFAULT_COMMAND_TIMEOUT` to 1800 s. Rejected: it also becomes the ceiling of every short probe, so a wedged `exec` wastes half an All-in-One budget before anything notices, and the mis-scaling moves rather than disappears.
- Move the ceiling into the Containerfile. Rejected: the ceiling is the harness's statement about how long its own work takes; a build file cannot express it, and CI would have no number to report.
- Only fix the build and leave the pull. Rejected: both were measured under the same constant, and a cold pull of the pinned base is the same kind of work.

The declared floors start at the measured cost of the failing runs (311.2 s and 306.8 s, both still climbing when the ceiling fired) with room for a slower runner, and task 4.2 replaces them with the durations of the measured run this change produces. The cap by `remaining()` is what keeps a ceiling from becoming a limit that cannot fire inside the run — the error the per-case caps already make.

### 2. `CaseTimeout` passes through the cleanup probe

`_restore_nginx_configuration` re-raises `CaseTimeout` before its broad handler; nothing else changes. `nginx_config_reload_contract` needs no report-presence guard, because the code after its `finally` is unreachable when the `finally` raises — that is exactly how the deadline leaves, so the restore is still attempted and no assertion about the restored configuration is reached. Every other restore failure still reaches `require_reload_after_restore`, because the helper returns a dictionary for a bad exit code, non-JSON output and any other exception.

Alternatives considered:

- Narrow `except Exception` to transport errors. Rejected: the probe's own gate failures surface as `RuntimeError`, so a narrowed handler would let a real cleanup crash escape the `finally` and replace the case's primary message with a traceback. The broad handler earns its keep for everything except the runner's own deadline.
- Clear the alarm before entering the cleanup. Rejected: it makes the last seconds of a case unbounded, and the budget that fired is exactly the thing the operator needs named in the verdict.
- Skip the restore on a timeout. Rejected: the host stays with the planted invalid snippet, and the next case inherits a broken configuration.
- Initialise the restore report to `None` and assert only when a report exists. Rejected: dead code — a `None` report cannot be observed after the `finally`, and the guard would suppress the very FAIL that a genuine restore failure must produce.

A genuine cleanup failure still fails the case: only `CaseTimeout` is passed through, and `require_reload_after_restore`'s own assertions are unchanged.

### 3. A failed installation reports BLOCKED, not FAIL and not SKIP

`require_installed()` raises `CaseBlocked`, which is what `RED-02` starts calling. `SKIP` means the case was not executed, `NOT_APPLICABLE` means the environment has no subject to judge; here the subject exists and a prerequisite failed, which is BLOCKED in this suite's existing vocabulary and what the aggregate gate already renders (`GATE-STATUS` fails on a blocked required case).

Alternative considered: a new exception type for "prerequisite failed". Rejected: it would duplicate `CaseBlocked` and force every aggregate report to learn a second name for the same outcome.

### 4. Rescale the caps and budgets only after the measured run

The per-case declared caps and the per-topology budgets are not touched here. The study's sample (37 local runs, 20 CI runs) measured the failures, not the post-fix cost, so any new number would be a second guess. The same applies to the 20-minute `Lint, Completeness, and Suite` job cap: it is a decision for after the measured run, and it may need no change at all if the run fits.

### 5. A ceiling that fires is a harness limit, not an unexpected error

`_run` raises a dedicated exception carrying the command and the ceiling instead of a bare `RuntimeError`, and `Runner.execute` maps it to INCOMPLETE before its final `except Exception`. Without that branch a ceiling that fires with budget still left reaches the broad handler and is published as FAIL with a traceback — the shape the measured runs already have — so sizing the ceilings without naming the verdict would leave the requirement true only for the cases where nothing fires.

Alternative considered: add a new verdict state alongside `PASS/FAIL/SKIP/BLOCKED/INCOMPLETE/NOT_APPLICABLE`. Rejected: INCOMPLETE already means "what was seen cannot decide the question", the aggregate gate already treats it as not-green, and a seventh state would have to be taught to every report, matcher and dashboard. What the requirement adds is not a new state but a named reason inside the existing one.

A declared per-case cap is out of scope: `CaseTimeout` with `capped_by_budget` false is the case's own statement about how long its own work may take, and the change leaves that branch as it is.

## Risks

- **A generous ceiling hides a genuine hang.** The verdict names the command and its ceiling, the ceiling is capped by the run's remaining budget, and a hang therefore ends as INCOMPLETE inside the budget rather than as a truncated pass.
- **The passthrough skips the restore assertion.** Only the assertion about the restore is skipped, and only because the deadline leaves the function before it; the restore itself still runs and the run's teardown removes the container. A restore that fails on its own still reaches `require_reload_after_restore`.
- **A case that used to fail now blocks.** That is the intent, and a blocked required case still fails the aggregate gate, so nothing becomes greener than the evidence allows.

## Migration

No product change, no data migration. The gate keeps its entrypoints and case IDs; only the verdicts of harness-caused reds change.
