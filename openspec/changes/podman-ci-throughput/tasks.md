# Tasks

## 1. Ceilings sized to their work (`tools/podman_e2e/podman.py`)

- [x] 1.1 Add two named ceilings beside `DEFAULT_COMMAND_TIMEOUT` (`podman.py:49`): `PULL_CEILING_SECONDS` and
  `BUILD_CEILING_SECONDS`, each with a comment naming the runs it is sized from (`podman-acceptance.yml`
  `45161440198`: pull-plus-build died at 311.2 s on `AIO-INSTALL` and 306.8 s on `PO-INSTALL`). `DEFAULT_COMMAND_TIMEOUT`
  keeps its value and its role as the ceiling of short probes.
  Verify: `grep -c 'DEFAULT_COMMAND_TIMEOUT = 300' tools/podman_e2e/podman.py` returns 1.
- [x] 1.2 Pass the ceilings at the two call sites, each capped by the run's remaining budget so the ceiling cannot
  outlive the run: the `pull` inside `ensure_image` (`podman.py:239`) and the build argv inside `build`
  (`podman.py:263`). Take the cap from the run context the class already holds (`self.context.remaining()`,
  `runner.py:246`). When nothing is left, raise the suite's existing budget exception instead of starting a command
  that cannot finish.
  Verify: the unit test in 1.4, and a read of `ensure_image`/`build` showing an explicit `timeout=` on both `_run`
  calls.
- [x] 1.3 Do not widen `exec`/`exec_bash`. A probe that legitimately needs longer already passes its own timeout
  (`NGX_CONFIG_PROBE_TIMEOUT_SECONDS` and its siblings), and a wider default would turn a wedged probe into a
  silently expensive one.
  Verify: `grep -c 'timeout: int = DEFAULT_COMMAND_TIMEOUT' tools/podman_e2e/podman.py` still prints 3.
- [x] 1.4 Add `TestOperationCeilings` beside `TestDeclaredBudget` in `tests/test_podman_budget.py`: the pull and the
  build are given a timeout no smaller than the measured cost and no larger than the remaining budget; a context with
  10 s left yields 10 s, not the declared floor; a spent budget refuses before the command starts; every other caller
  still gets 300 s. Register the class in `tests/run_ci.py`'s `SUITES` in the same commit — `collect()` refuses an
  unassigned class before suite selection (`run_ci.py:410-413`), so an unregistered class turns
  `--check-completeness` and every suite run red.
  Verify: `python3 -m unittest -v tests.test_podman_budget` and `python3 tests/run_ci.py --check-completeness`.
- [x] 1.5 Make a fired ceiling a harness limit instead of an unexpected error: replace the bare `RuntimeError` in
  `_run` (`podman.py:105-108`) with a dedicated exception carrying the command and the ceiling that fired, and map it
  in `Runner.execute` to INCOMPLETE ahead of the final `except Exception` (`runner.py:363-369`), which today publishes
  it as FAIL with a bare traceback. Import it through runner's existing exception block, next to `BudgetExhausted`.
  The message names the command and the limit, and a declared per-case cap is out of scope: that branch keeps its
  current FAIL/INCOMPLETE split.
  Verify: `TestHarnessLimitVerdict` in `tests/test_podman_runner.py` — a `HarnessLimit` raised inside a case ends as
  INCOMPLETE, and the published reason names both the command and the ceiling — registered in `run_ci.py` with the
  rest of section 1; `python3 -m unittest -v tests.test_podman_runner`.

## 2. A deadline is not a defect (`tools/podman_e2e/aio.py`)

- [x] 2.1 Re-raise `CaseTimeout` in `_restore_nginx_configuration` (`aio.py:4871`) ahead of its broad handler, importing
  it through the module's existing `.runner` import block rather than adding a second one.
  Verify: a restore probe that raises `CaseTimeout` no longer returns a `{"error": …}` dictionary (test in 2.3).
- [x] 2.2 Change nothing downstream in `nginx_config_reload_contract`: no `None` initialisation of the restore report
  and no report-presence guard around `require_reload_after_restore`. Neither is reachable — when the `try` body or the
  `finally` raises, the code after the `finally` does not run, and `_restore_nginx_configuration` returns a dictionary
  on every non-deadline path, so the existing "the restoring probe produced no report" assertion is already the one
  that fails for a bad exit code, non-JSON output or another exception. A guard here would only make the deadline path
  quieter while breaking the FAIL path the same task requires.
  Verify: the 2.3 negative test — a `RuntimeError` from the restore probe still ends as FAIL.
- [x] 2.3 Prove both directions at the cheapest layer: in `tests/test_podman_runner.py` beside `TestResultSemantics`,
  a `CaseTimeout` raised during a case capped by the budget ends as INCOMPLETE; in `tests/test_podman_aio.py`,
  `TestRestoreDeadlineCase` shows a deadline inside the restore probe leaving `nginx_config_reload_contract` by
  exception with no assertion about the restored configuration, while a `RuntimeError` from the same probe still ends
  as FAIL carrying the case's primary message. Register both classes in `tests/run_ci.py`'s `SUITES`.
  Verify: `python3 -m unittest -v tests.test_podman_runner tests.test_podman_aio` and
  `python3 tests/run_ci.py --check-completeness`.
- [x] 2.4 Pin the handler order with a source-level test that anchors on the call site, not on a character window: the
  deadline is named before the broad handler inside `_restore_nginx_configuration`. Nothing else is pinned — 2.2 keeps
  that function's guard structure unchanged, so a test asserting a report-presence guard would pass on dead code.
  Verify: the new test fails when 2.1 is reverted.

## 3. An install-dependent case gates on the install (`tools/podman_e2e/aio.py`)

- [x] 3.1 `case_diagnostic_artifacts` (`aio.py:2973`, `RED-02`) begins with `product.require_installed()`, so a failed or
  absent install yields BLOCKED naming `AIO-INSTALL` instead of an assertion about a host that was never installed.
- [x] 3.2 Audit the rest of the suite for the same omission: enumerate the public `case_*` functions that read the host
  or call `diagnostics.collect` without reaching `require_installed()`/`require_worker()` first, and record the list in
  this task. The expected result is `RED-02` alone; any other name is a second instance of this defect and gets its own
  gate.
  Result: `case_diagnostic_artifacts` alone. It was the only public `case_*` in `aio.py`, `multi_node.py` and
  `panel_only.py` that reached `diagnostics.collect` or `product.podman` without a gate; the 47 cases whose bodies name
  neither reach the host through `AioProduct.host_script()`, which calls `require_installed()` itself, and the
  `multi_node` ones through `require_worker()`. Re-checked after 3.1: no such function is left.
  Verify: the recorded enumeration, plus 3.3.
- [x] 3.3 Extend `TestDiagnosticArtifactsCase` (`tests/test_podman_aio.py:6513`): a product whose install outcome is not
  ok raises `CaseBlocked` naming the install case and `diagnostics.collect` is never called; a healthy product still
  produces the bundle.
  Verify: `python3 -m unittest -v tests.test_podman_aio`.

## 4. Measure, then set the numbers

- [x] 4.1 Run one full local acceptance run on this change's commit over the three topologies that carry the measured
  paths, and record the run directory and its per-case durations in this task: `aio` (`AIO-INSTALL` builds and pulls,
  `NGX-05` owns the restore, `RED-02` owns the install gate), `panel-only` (`PO-INSTALL` is the second measured build
  kill), and `multi-node` (`NGX-05` and `ENV-02` are where the budget was spent and reported as a defect). Record the
  pull and build durations separately from the case durations — 4.2 needs the former, 4.3 the latter.
  Result: three runs on `05e23ee`, `tree: dirty` only by this file and the untracked `artifacts/`:
  - `artifacts/podman-e2e/podman-aio-20261123T193952-2d80cddc` — FAIL, 985.1 s of 2700 (36 %): 107 PASS,
    8 INCOMPLETE, 2 FAIL. `AIO-INSTALL` PASS 83.0 s, `RED-02` 34.4 s, `NGX-05` 2.9 s.
  - `artifacts/podman-e2e/podman-panel-only-20261123T195617-1664ab7e` — PASS, 6 of 6, 158.7 s of 4500 (3.5 %).
    `PO-INSTALL` 72.1 s, `PO-SQUAD` 58.3 s, `MN-ADD-NODE-REFUSED` 0.8 s.
  - `artifacts/podman-e2e/podman-multi-node-20261123T195857-3adaabde` — FAIL, 1826.9 s of 4500 (41 %): 117 PASS,
    8 INCOMPLETE, 2 FAIL. `MN-INSTALL` 82.5 s, `WRK-04` 124.4 s, `MN-ENV-CONTRACT` 94.3 s, `ENV-02` 20.2 s,
    `NGX-05` 6.1 s; the slowest PASS is `NGX-COVER-UNRESOLVED` at 202.1 s.

  Every non-PASS verdict is one signature this change does not touch: the eight `AIO-DP-*` and `MN-DP-master-*`
  data-plane cases report INCOMPLETE with «the local host captured nothing on port 443» while their request facts
  hold, and `AIO-MATRIX`, `AIO-PKT-02`, `MN-MATRIX`, `MN-EGRESS` fail on that same capture. No `HarnessLimit` fired
  and no case reported a budget exhaustion in any topology, and the two cases that used to hold 4165 s of the
  multi-node run now take 218.7 s together.
  The pull and the build are measured apart from the cases, cold, on this workstation: the acceptance runs reused the
  pre-existing rootful store `/home/podman-rootful` (dated Jul 11) and so neither pulled nor built the base. After
  removing `localhost/gowave-e2e-target:ubuntu-24.04`, `localhost/probe-target:latest` and the pinned digest, the
  digest pull took 1 s and `podman build --no-cache` 14 s, with all ten Containerfile steps run and zero
  `Using cache` lines. `AIO-INSTALL` 83.0 s, `PO-INSTALL` 72.1 s and `MN-INSTALL` 82.5 s are warm-store numbers and
  say nothing about the pull or the build.
- [x] 4.2 Replace the initial `PULL_CEILING_SECONDS` and `BUILD_CEILING_SECONDS` with values derived from 4.1, keeping
  the rule "declared floor sized to the work, capped by the remaining budget", and record the measured pull and build
  durations beside the constants.
  Verify: the 1.4 test still passes with the new numbers, and the recorded durations are shorter than the floors.
  Result: `PULL_CEILING_SECONDS = 300` (from 600) and `BUILD_CEILING_SECONDS = 1800` (unchanged), each with its
  measured duration in the comment above it. Only the pull moved, because the measurement divides what one 311.2 s
  kill had charged to both commands: the pull is at most 11.2 s and 1 s cold, it was never the command that ran long,
  and 600 s was 53x that — headroom charged for the build's overrun. The probe default the pull already had is 27x
  the observation and the honest floor, so the pull keeps `DEFAULT_COMMAND_TIMEOUT` instead of a number of its own.
  The build keeps 1800 s: 14 s cold here, but the same ten steps outlasted 300 s on the runner and were still
  climbing, so the floor stays 6x that lower bound; a build that wedges is stopped by the run's remaining budget
  either way. `tests.test_podman_budget.TestOperationCeilings.test_the_pull_gets_its_own_ceiling` now pins the pull to
  `DEFAULT_COMMAND_TIMEOUT` and keeps the assertion that the floor outlasts the 11.2 s observation.
  Verify: `python3 -m unittest -v tests.test_podman_budget` — `Ran 23 tests`, OK; 1 s < 300 s and 14 s < 1800 s, so
  both recorded durations are shorter than their floors.
- [x] 4.3 Decide with the user whether the per-case declared caps (6000–11400 s) and the per-topology run budgets
  (2700/4500/4500 s) move. If they do, that is its own change with 4.1 as evidence: the post-fix cost is what decides
  them, and this change does not measure it before 4.1.
  Result: both stay, decided by the operator on the 4.1 numbers. Measured cost is 985.1 s of 2700 (36 %), 158.7 s of
  4500 (3.5 %) and 1826.9 s of 4500 (41 %), and one full pass is 2971 s against the 9000 s the pull-request tier
  declares for two passes (66 %); the 59 % left on Multi-Node is the margin a slower runner spends, since the same
  build takes 14 s here and outlasted 300 s there. `pre_push_total_seconds = 7200` is the All-in-One and Multi-Node
  budgets summed and does not move either. The per-case caps stay inert — larger than the budget that caps them, so
  they cannot fire, the defect `design.md` names — and correcting them is its own change with 4.1 as its evidence, as
  this task requires.
- [x] 4.4 Decide the same for the 20-minute `Lint, Completeness, and Suite` job cap after 4.3, and record either the new
  value or the measured margin that makes the current value sufficient.
  Result: the cap stays at 90 minutes, and the task's 20 minutes is stale — `.github/workflows/lint-and-nonroot.yml:25`
  already declares `timeout-minutes: 90`, raised in `podman-full-e2e` after the 20-minute cap ended every run as
  `cancelled`. 4.5 measured the suite at 3128.777 s, 52.1 minutes, so the job carries 37.9 minutes (42 %) for checkout,
  dependencies and the completeness pass: the same headroom the Multi-Node acceptance job carries. No workflow change,
  and the job is not in `tests/cases/gates.yaml`, so `gate --check` has no statement about it to reconcile.
  Verify: `sed -n '18,26p' .github/workflows/lint-and-nonroot.yml` shows the 90 and the comment that explains it.
- [x] 4.5 Run the non-root suite — `python3 tests/run_ci.py --suite nonroot` — and record the verdict read from the
  run, not from the log tail, which does not carry it.
  Result: `Ran 3077 tests in 3128.777s` — `OK (skipped=1)`, exit 0, zero `ERROR:`/`FAIL:` lines. Read from the
  runner's own summary line on commit `05e23ee`, not from the size of the log. The one skip is the local sample's
  normal count (CI skips 24 where the workstation lacks a container-only capability).
  Verify: `grep -nE '^(Ran [0-9]+ tests|OK|FAILED)' /tmp/nonroot-suite-4.5.log` and the shell's exit status.

## 5. Traceability and the pages that state verdicts

- [x] 5.1 Add one traceability row per scenario of the delta at archive time — the three ADDED ones and
  `Install-dependent case without a successful installation` — using full ids that exist by then, never a
  two-segment module id: `tests.test_podman_budget.TestOperationCeilings` (a slow legitimate step keeps its ceiling),
  `tests.test_podman_runner.TestHarnessLimitVerdict` (a ceiling that fires names its own limit),
  `tests.test_podman_aio.TestRestoreDeadlineCase` (a budget kill inside a cleanup probe stays INCOMPLETE) and
  `tests.test_podman_aio.TestDiagnosticArtifactsCase` (the install gate). Each row names the job that runs its proof:
  `Lint, Completeness, and Suite Nonroot` for the unit tests, `All-in-One Podman Acceptance` and
  `Panel-only Podman Acceptance` for the two measured ceiling sites, `Multi-Node Podman Acceptance` for the budget and
  install paths. Use no `gap`: `trace.py` reads the ledger of `podman-full-e2e` (`trace.py:61`) and refuses a gap
  naming a task of another change, and by archive time every row has a passing test.
  Verify: `python3 -m tools.podman_e2e.trace --strict` lists the four new rows and reports no problem.
  Result: four rows, 55 scenarios against 55 rows, 0 gaps. The delta had to reach
  `openspec/specs/podman-e2e/spec.md` first — `trace.py` compares the table with the capability spec, not with the
  delta — so the archive's sync step ran before the rows: the ADDED requirement is inserted after *Pre-push and
  pull-request acceptance gate*, whose *Budget overrun is not a truncated pass* scenario it names as its sibling, and
  `Trustworthy result and diagnostics` takes the delta's description and its third scenario verbatim. Two rows carry
  tests and no cases: `NGX-05` and `RED-02` already serve scenario-less requirements in the `unstated:` block, and the
  audit refuses a case mapped to two places, so a case column there would have had to steal the redaction and decoy
  mappings. That is the same shape the table already uses for *Secret redaction* and *Cleanup after failure*, and
  `TestOperationCeilings` and `TestHarnessLimitVerdict` rows do name cases — `AIO-INSTALL` with `PO-INSTALL`, and
  `AIO-INSTALL` with `MN-INSTALL` — because the measured ceiling sites are install cases. The count the table states
  moved with it, so `tests/test_podman_traceability.py` now pins 55 in both places, with a comment naming the 51 plus
  the delta's four.
- [x] 5.2 If `docs/PODMAN_E2E_DISCOVERY.md` or `tests/cases/behaviors.yaml` states that a timed-out case is a product
  FAIL, bring the sentence in line with the new verdict.
  Result: nothing to align. Neither page calls a timed-out case a product FAIL, and neither states a ceiling for the
  pull or the build. The sentences that do touch a lost case already sit on the new side — `behaviors.yaml` «FAIL or
  INCOMPLETE naming the case instead of PASS» and «an exhausted budget reports INCOMPLETE» — while the discovery
  page's verdict vocabulary section describes the live reporter's statuses, not this harness's.
  Verify: `python3 -m unittest -v tests.test_podman_docs tests.test_podman_behaviors` — 122 tests OK.
- [x] 5.3 Validate the change and the tree: `openspec validate podman-ci-throughput --strict`, then
  `openspec validate --all --strict`.
  Result: `Change 'podman-ci-throughput' is valid`; the tree-wide run passed 10, failed 0.
- [ ] 5.4 Regenerate the traceability report after 5.1 — `python3 -m tools.podman_e2e.trace --markdown` — and commit
  `docs/PODMAN_E2E_TRACEABILITY.md`: `trace.py:1203-1206` refuses a report that differs from the table's own render.
  Verify: `python3 -m tools.podman_e2e.trace --strict` passes twice in a row.
  Result: `traceability: wrote docs/PODMAN_E2E_TRACEABILITY.md`, then `--strict` passed twice on the same tree with
  `55 scenarios, 55 rows, 0 gaps` each time. The report carries the four new rows and the two new requirements.

## 6. Close

- [x] 6.1 Re-read one red Podman run produced before this change and one after 4.1, and account for every verdict
  difference: each must be either the same product finding or one of the harness paths this change names. A
  difference that is neither is a finding this change did not intend.
  Result: two pairs, and each pair carries an identical case set (117 for `aio`, 127 for `multi-node`), so every
  difference is a status change on the same id rather than a case that appeared or vanished.
  - `podman-aio-20261122T204058-30530910` (FAIL, 3 FAIL / 64 BLOCKED / 50 PASS, 306.9 s) against
    `podman-aio-20261123T193952-2d80cddc` (FAIL, 2 FAIL / 8 INCOMPLETE / 107 PASS, 985.1 s). `AIO-INSTALL` failed in
    25.5 s on «the hosts entry for api.github.com (install) did not print JSON», so the 64 BLOCKED cases were the
    install gate naming `AIO-INSTALL` — and `RED-02` was the case that did not: it FAILed on «the operator file does
    not carry the package version» about a host no install had touched, which is the defect 3.1 closed. After the
    run, the install succeeds and `RED-02` passes; `ENV-01`'s FAIL, on the install case not having succeeded, goes the
    same way. The ten cases left non-PASS are the eight `AIO-DP-*` INCOMPLETE and their two dependants `AIO-MATRIX`
    and `AIO-PKT-02`, and no case moved from PASS to anything else.
  - `podman-multi-node-20261122T144401-ab045897` (FAIL, 5 FAIL / 8 INCOMPLETE / 114 PASS, 2037.2 s) against
    `podman-multi-node-20261123T195857-3adaabde` (FAIL, 2 FAIL / 8 INCOMPLETE / 117 PASS, 1826.9 s): 19 status changes.
    The eight empty-capture INCOMPLETE changed host — they were the eight `MN-DP-worker-*` cases and are now the eight
    `MN-DP-master-*` ones — so the count of that signature is unchanged and the sixteen are one finding observed on
    either side of the pair. `MN-DUP-ADD` (recovery journal left at `NODE_ADD_ROLLBACK_REQUIRED`), `MN-ENV-CONTRACT`
    (node add exited 1) and `MN-PKT-03` (a request the master did not carry) pass after the commits that fixed them
    landed between the two runs, not because of anything here.
  - Neither side carries a verdict from this change: no `HarnessLimit` and no budget-exhaustion INCOMPLETE appears in
    any of the four runs, and their 306.9 / 985.1 / 2037.2 / 1826.9 s sit far inside 2700 / 4500 / 4500. The only
    PASS-to-non-PASS movement is those eight master captures, and the same signature is in the before side itself and
    a day earlier in `podman-aio-20261121T141243-9d32338c`, so it is not something this change introduced.
- [ ] 6.2 Archive the change only after 6.1, and only with 4.3/4.4 decided or explicitly carried forward as their own
  change.
