# Tasks

## 1. Ceilings sized to their work (`tools/podman_e2e/podman.py`)

- [ ] 1.1 Add two named ceilings beside `DEFAULT_COMMAND_TIMEOUT` (`podman.py:49`): `PULL_CEILING_SECONDS` and
  `BUILD_CEILING_SECONDS`, each with a comment naming the runs it is sized from (`podman-acceptance.yml`
  `45161440198`: pull-plus-build died at 311.2 s on `AIO-INSTALL` and 306.8 s on `PO-INSTALL`). `DEFAULT_COMMAND_TIMEOUT`
  keeps its value and its role as the ceiling of short probes.
  Verify: `grep -c 'DEFAULT_COMMAND_TIMEOUT = 300' tools/podman_e2e/podman.py` returns 1.
- [ ] 1.2 Pass the ceilings at the two call sites, each capped by the run's remaining budget so the ceiling cannot
  outlive the run: `ensure_image`'s `pull` (`podman.py:242`) and `build`'s `build` (`podman.py:268`). Take the cap from
  the run context the class already holds (`self.context.remaining()`, `runner.py:246`). When nothing is left, raise
  the suite's existing budget exception instead of starting a command that cannot finish.
  Verify: the unit test in 1.4, and a read of `ensure_image`/`build` showing an explicit `timeout=` on both `_run`
  calls.
- [ ] 1.3 Do not widen `exec`/`exec_bash`. A probe that legitimately needs longer already passes its own timeout
  (`NGX_CONFIG_PROBE_TIMEOUT_SECONDS` and its siblings), and a wider default would turn a wedged probe into a
  silently expensive one.
  Verify: `grep -c 'timeout: int = DEFAULT_COMMAND_TIMEOUT' tools/podman_e2e/podman.py` is unchanged.
- [ ] 1.4 Add a test class beside `TestDeclaredBudget` in `tests/test_podman_budget.py`: the pull and the build are
  given a timeout no smaller than the measured cost and no larger than the remaining budget; a context with 10 s left
  yields 10 s, not the declared floor; a spent budget refuses before the command starts; every other caller still gets
  300 s.
  Verify: `python3 -m unittest -v tests.test_podman_budget`.

## 2. A deadline is not a defect (`tools/podman_e2e/aio.py`)

- [ ] 2.1 Re-raise `CaseTimeout` in `_restore_nginx_configuration` (`aio.py:4871`) ahead of its broad handler, importing
  it through the module's existing `.runner` import block rather than adding a second one.
  Verify: a restore probe that raises `CaseTimeout` no longer returns a `{"error": …}` dictionary (test in 2.3).
- [ ] 2.2 In `nginx_config_reload_contract`, initialise the restore report to `None`, keep the restore in the `finally`,
  and call `require_reload_after_restore` only when a report exists. A restore that fails on its own — bad exit code,
  non-JSON output, an exception other than the deadline — still reaches the assertion and still FAILs.
- [ ] 2.3 Prove both directions at the cheapest layer: in `tests/test_podman_runner.py` beside `TestResultSemantics`,
  a `CaseTimeout` raised during a case capped by the budget ends as INCOMPLETE; in `tests/test_podman_aio.py` beside
  `TestNginxConfigCase`, a deadline inside the restore probe leaves the restore attempted, evaluates no assertion about
  the restored configuration, and a `RuntimeError` from the same probe still ends as FAIL carrying the case's primary
  message.
  Verify: `python3 -m unittest -v tests.test_podman_runner tests.test_podman_aio`.
- [ ] 2.4 Pin the handler order with a source-level test that anchors on the call site, not on a character window: the
  deadline is named before the broad handler inside `_restore_nginx_configuration`, and `require_reload_after_restore`
  is guarded by the report's presence.
  Verify: the new test fails when 2.1 is reverted.

## 3. An install-dependent case gates on the install (`tools/podman_e2e/aio.py`)

- [ ] 3.1 `case_diagnostic_artifacts` (`aio.py:2973`, `RED-02`) begins with `product.require_installed()`, so a failed or
  absent install yields BLOCKED naming `AIO-INSTALL` instead of an assertion about a host that was never installed.
- [ ] 3.2 Audit the rest of the suite for the same omission: enumerate the public `case_*` functions that read the host
  or call `diagnostics.collect` without reaching `require_installed()`/`require_worker()` first, and record the list in
  this task. The expected result is `RED-02` alone; any other name is a second instance of this defect and gets its own
  gate.
  Verify: the recorded enumeration, plus 3.3.
- [ ] 3.3 Extend `TestDiagnosticArtifactsCase` (`tests/test_podman_aio.py:6513`): a product whose install outcome is not
  ok raises `CaseBlocked` naming the install case and `diagnostics.collect` is never called; a healthy product still
  produces the bundle.
  Verify: `python3 -m unittest -v tests.test_podman_aio`.

## 4. Measure, then set the numbers

- [ ] 4.1 Run one full local acceptance run on this change's commit over the affected topologies and record the run
  directory and its per-case durations in this task.
- [ ] 4.2 Replace the initial `PULL_CEILING_SECONDS` and `BUILD_CEILING_SECONDS` with values derived from 4.1, keeping
  the rule "declared floor sized to the work, capped by the remaining budget", and record the measured pull and build
  durations beside the constants.
  Verify: the 1.4 test still passes with the new numbers, and the recorded durations are shorter than the floors.
- [ ] 4.3 Decide with the user whether the per-case declared caps (6000–11400 s) and the per-topology run budgets
  (2700/4500/4500 s) move. If they do, that is its own change with 4.1 as evidence: the post-fix cost is what decides
  them, and this change does not measure it before 4.1.
- [ ] 4.4 Decide the same for the 20-minute `Lint, Completeness, and Suite` job cap after 4.3, and record either the new
  value or the measured margin that makes the current value sufficient.
- [ ] 4.5 Run the non-root suite — `python3 -m tests.run_ci.py --suite nonroot` — and record the verdict read from the
  run, not from the log tail, which does not carry it.

## 5. Traceability and the pages that state verdicts

- [ ] 5.1 Add the traceability rows for the delta's scenarios at archive time: the two ceiling scenarios cite
  `tests.test_podman_budget` and `tests.test_podman_runner`, the install-gate scenario cites `tests.test_podman_aio`, and
  all three cite the job that runs them. A scenario with no row is an audit gap, and the gap must name the task whose
  box is still open.
  Verify: `python3 -m tools.podman_e2e.trace --strict` reports 0 gaps and `tests/test_podman_traceability.py` passes.
- [ ] 5.2 If `docs/PODMAN_E2E_DISCOVERY.md` or `tests/cases/behaviors.yaml` states that a timed-out case is a product
  FAIL, bring the sentence in line with the new verdict.
  Verify: `python3 -m unittest -v tests.test_podman_docs tests.test_podman_behaviors`.
- [ ] 5.3 Validate the change and the tree: `openspec validate podman-ci-throughput --strict`, then
  `openspec validate --all --strict`.

## 6. Close

- [ ] 6.1 Re-read one red Podman run produced before this change and one after 4.1, and account for every verdict
  difference: each must be either the same product finding or one of the three harness paths this change names. A
  difference that is neither is a finding this change did not intend.
- [ ] 6.2 Archive the change only after 6.1, and only with 4.3/4.4 decided or explicitly carried forward as their own
  change.
