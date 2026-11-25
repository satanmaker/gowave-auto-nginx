---
name: acceptance-case
description: Add or change one Podman acceptance case across all five artifacts it lives in. Use when a spec scenario, a product behaviour, or an error path has to become a case in tests/cases, when the user says "add an acceptance case", "cover this scenario", or when a catalog, behaviour, traceability, or completeness audit reports a case that is missing, orphaned, or unassigned.
---

One acceptance case is written in five files, and each audit fails on the one that was skipped.

## When to use

- A spec scenario, a product behaviour, or an error path needs a case of its own.
- `catalog check`, `trace --strict`, or `--check-completeness` reports a missing case, an orphan, an open gap, or an unassigned `TestCase` class.
- An existing case changes its id, topology, gate, or the test that proves it.

Not for running the suites: that is a separate, root-only action (see Reporting).

## The chain

| # | Artifact | What it asserts | Validated by |
|---|---|---|---|
| 1 | `tests/cases/catalog.yaml` (generated) | the case exists: id, requirement, assertion, topology | `catalog check` |
| 2 | `tests/cases/behaviors.yaml` | the case belongs to exactly one behaviour, and that behaviour has an error path | `catalog check` |
| 3 | `tests/cases/traceability.yaml` | the case answers a spec scenario, and a test and CI job prove it | `trace --strict` |
| 4 | `tests/cases/matrix.yaml` | the case's topology, gate tier, and runtime budget | `catalog check` |
| 5 | `SUITES` in `tests/run_ci.py` | the `unittest` class that pins the case is run by a suite | `--check-completeness` |

`tests/cases/PARITY.md`, `docs/PODMAN_E2E_BEHAVIORS.md`, and `docs/PODMAN_E2E_TRACEABILITY.md` are generated. Never edit them by hand.

The message names the artifact that is missing:

- `Case is mapped to no behavior` / `no suite declares the case` → 2 or 6.
- `Behavior has no error-path case` → 2, and the case proves only the happy path.
- `orphan case: … is mapped to no scenario` / `no row for the scenario` → 3.
- `Unassigned TestCase classes` → 5.

## Procedure

1. **Decide where the case is born.** A case with a spec scenario starts as a scenario in `openspec/specs/live-vps-e2e/spec.md`. A Podman-first case (including every `AIO-DP-*` / `MN-DP-*`) is an entry in `PODMAN_FIRST_CASES` or `data_plane_cases()` in `tools/podman_e2e/catalog.py`. Then regenerate: this rewrites `catalog.yaml` and `PARITY.md`, so a hand edit to either is lost.
2. **Partition it into exactly one behaviour** in `behaviors.yaml`: `cases:` for what establishes the behaviour, `error_paths:` for what exercises its failure. A behaviour whose only cases are its happy path is refused, so name the case that proves the refusal, the boundary, or the rollback. The entry's `gate` must equal the case's gate and its `topology` list must cover every topology its cases run in.
3. **Add the traceability row** in `traceability.yaml`, one row per spec scenario, naming `cases`, `topologies`, `tests` (`tests.<module>.<Class>[.<method>]`), and `jobs`. A case serving a requirement with no scenario goes under `cases_by_requirement` with a `reason`.
4. **Touch the matrix only when the case is a new data-plane combination**: the id pattern and `positive_case_counts` are declared per topology, and `gate: [pre-push, …]` plus `runtime_budget` are read from here.
5. **Register the test class** in `SUITES` in `tests/run_ci.py`. A class nobody assigns, or an entry naming a class that is gone, fails the completeness check.
6. **Declare the case in the suite**, in `tools/podman_e2e/aio.py` or `tools/podman_e2e/multi_node.py`: the traceability audit resolves ids from those declarations, so an id that exists only in YAML is reported as one no suite declares.
7. **Regenerate both rendered pages** after every YAML edit — the audit re-renders and compares, so an edited table without a regenerated page fails the same check.
8. **Run the cheap gates** in the order below, cheapest first, before claiming anything.

## Commands

```bash
python3 -m tools.podman_e2e.catalog generate            # after spec / PODMAN_FIRST_CASES edits
python3 -m tools.podman_e2e.catalog check               # catalog + behaviour partition + rendered page
python3 -m tools.podman_e2e.catalog behaviors --write   # rewrite docs/PODMAN_E2E_BEHAVIORS.md
python3 -m tools.podman_e2e.trace --strict              # rows, ids, tests, jobs, no open gaps
python3 -m tools.podman_e2e.trace --markdown            # rewrite docs/PODMAN_E2E_TRACEABILITY.md
python3 tests/run_ci.py --check-completeness
python3 -m unittest -v tests.test_podman_traceability
python3 -m unittest -v tests.test_podman_behaviors
```

All of the above run as a normal user. Container proof is root-only and expensive:
`sudo python3 -m tools.run_podman_e2e --topology aio` or `--topology multi-node`. Do not launch a suite "to see if it works"; read the failure first.

## Reporting

- Name each artifact touched and the gate that accepted it, in the order above. A green exit status is not evidence that the behaviour is proven.
- State the sample: which run directory, which case ids inside it, how many cases the run reported.
- If no suite ran, say the new case has no execution evidence yet, and that `catalog check` and `trace --strict` prove only that the case is declared and mapped.
- If an audit fails twice for the same reason, report the cause instead of trying another edit.
