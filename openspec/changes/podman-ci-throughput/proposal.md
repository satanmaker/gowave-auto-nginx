# Proposal

## Why

The Podman acceptance contour reports red findings the product did not produce. Three of them are measured, each in a different layer:

- **One command, 300 seconds.** `DEFAULT_COMMAND_TIMEOUT` (`tools/podman_e2e/podman.py:49`) is the default of `_run`, `exec` and `exec_bash`, and neither `ensure_image` nor `build` overrides it. The digest-pinned base `podman pull` and the `podman build -f tests/Containerfile.target`, whose `RUN` performs `apt-get update && apt-get install`, therefore share a ceiling sized for a probe. On `93c24df` (`podman-acceptance.yml` run `45161440198`) `AIO-INSTALL` failed at 311.2 s and `PO-INSTALL` at 306.8 s with `RuntimeError: podman build ... did not finish within 300s`, before any case had run.
- **A budget kill published as a defect.** `_raise_case_timeout` raises `CaseTimeout`; when the deadline fires while a case is inside its `finally` block, `_restore_nginx_configuration` (`tools/podman_e2e/aio.py:4871`) catches it with `except Exception` and returns `{"error": "CaseTimeout: ..."}`, and `require_reload_after_restore` then fails on "the restoring probe produced no report". The runner's own `except CaseTimeout` branch — the one that reports INCOMPLETE when a run budget capped the case — never runs. Multi-Node `282f638` published `NGX-05 FAIL 57.2 s` for a case that had already done its work and then lost the run's remaining budget.
- **A phantom second defect.** `case_diagnostic_artifacts` (`tools/podman_e2e/aio.py:2973`, case `RED-02`) never calls `require_installed()`, unlike the rest of the suite, so on a build that died before the installation it probes a host that was never installed and fails its own assertions. The same run reports `NGX-05` and `ENV-02` as BLOCKED, correctly, and adds `RED-02 FAIL: the operator file does not carry the package version ('nginx=' is absent)` on top.

While these hold, the gate's colour says nothing about the diff: an operator has to read every red run by hand to separate harness mis-sizing from a product defect, and the required PR checks stay red for reasons no diff can fix.

## What Changes

- Size each container ceiling to the work it bounds: the image pull and the image build get their own ceilings, and each ceiling is capped by the run's remaining budget so it can actually fire inside the run. The 300-second default stays for short probes.
- A ceiling kill is a verdict about the harness, not the product: `CaseTimeout` passes through the cleanup probe untouched, the restore is still attempted, and the case is finished by the runner's budget branch as INCOMPLETE.
- Every case that depends on a successful installation gates on it and reports BLOCKED when no installation succeeded; `RED-02` is the measured instance, and the rest of the suite is audited for the same omission.
- Prove all three falsifiably at the cheapest layer: runner unit tests for the timeout passthrough, a unit test for the install gate, and one measured acceptance run whose durations replace the initial ceiling numbers.
- Deliberately out of scope: rescaling the per-case declared caps (6000–11400 s) and the per-topology run budgets (2700/4500/4500 s), and the 20-minute `Lint, Completeness, and Suite` job cap. Those numbers are only meaningful after the run this change measures; moving them now would replace one guess with another.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `podman-e2e`: gains a requirement that the harness's own ceilings and budgets never produce a product verdict, and the diagnostics requirement gains the install-dependency clause that the rest of the suite already follows.

## Impact

- `tools/podman_e2e/podman.py`: per-operation ceilings for the pull and the build, each bounded by the run's remaining budget.
- `tools/podman_e2e/aio.py`: `_restore_nginx_configuration` re-raises `CaseTimeout`; `nginx_config_reload_contract` skips the restore assertion when the helper produced no report; `case_diagnostic_artifacts` gates on `require_installed()`.
- `tests/test_podman_runner.py`, `tests/test_podman_budget.py`, `tests/test_podman_aio.py`: the three proofs.
- `tests/cases/traceability.yaml` and the pages that record verdict semantics: updated when the delta is archived, since the new scenarios are harness-level and cite unit tests rather than new cases.
- Out of scope: product code, the live-VPS contour (not part of this change), the per-case and per-run budgets, the CI job time cap, and any change to what the suite asserts about the product.

## Evidence

The study behind this change is a read-only sample: 37 local runs plus the 20 most recent `podman-acceptance.yml` runs, 6 green, 13 red, one in flight. The three findings above were each read out of a specific run and then re-verified against the current tree before this proposal was written. The live-VPS work already shipped on `research/podman-ci-throughput` (`3652dce`) is context: it shows a harness defect being fixed at the harness and proven by a rerun, which is the shape this change follows.
