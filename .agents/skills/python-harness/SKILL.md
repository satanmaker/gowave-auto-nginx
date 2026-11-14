---
name: python-harness
description: Change the Python unittest harness of GoWave Auto NGINX - tests/, tools/, tools/podman_e2e/ and modules/*.py - by finding the affected tests, keeping the run_ci.py suite registry complete, and running the cheapest check that proves the change. Use for a правка tests/, to fix a failing unittest, a change in tools/podman_e2e, a new helper under modules/, or a new TestCase class that must be registered.
---

Change Python harness code so the suite registry stays complete and the smallest sufficient check proves it.

## When to use

- A test under `tests/` fails, or must follow a shape change in the Bash installer.
- Behaviour changes in `tools/`, `tools/podman_e2e/`, `modules/*.py` or `assets/**/*.py` and tests must cover it.
- A new `unittest.TestCase` class was added and completeness complains.

## Finding callers

`grep -rn 'ClassName' tests tools` is the trustworthy answer here: the tree is small and every import and registry entry is a literal string, so the search sees all of them. A symbol graph or LSP index is not: the product path is Bash inside SSH heredocs in `gowave-node-auto.sh`, which no Python index parses, so "no callers" from a symbol tool says nothing about what a Python helper really affects. Grep the class name, its file stem, and the function name before deleting anything.

## Procedure

1. Identify the touched module and grep for its importers and for its `SUITES` entry, so you know which suite already owns it.
2. Decide whether a registry line is needed. Every `unittest.TestCase` class must appear exactly once in the `SUITES` dict of `tests/run_ci.py`. A new class needs a line under `nonroot`, `root`, `integration`, `services` or `systemd`; a renamed or deleted class needs its stale line removed. A class with zero test methods also fails `collect()`.
3. Write the test next to the behaviour it proves - the module that already owns that subject, never a new catch-all file. Assert on what the product side actually reads (the rendered command, the emitted payload, the probe output), not on the presence of a source string.
4. Run the completeness check. It imports every `tests/test_*.py`, so it also catches import errors and duplicates before any suite runs.
5. Run the targeted module, or the single test when only one method is in question, and iterate until green.
6. Run the full suite once the change crosses modules, and `tools/tests` for anything under `tools/`. The nonroot suite's `py_compile` coverage spans `modules/*.py`, `assets/**/*.py` and `tests/*.py`; `tools/` is compiled only by `tools/tests`, so a syntax break there survives the nonroot suite.

Suite privilege: `nonroot`, `integration` and `services` refuse `EUID == 0`; `root` and `systemd` require it. The runner prints `PRIVILEGE: FAIL` rather than running on the wrong side.

The working tree is shared and usually holds unrelated uncommitted edits: `collect()` reads the tree, not a commit. When a red `COMPLETENESS: FAIL` names classes you did not write, check whether they exist in the commit under review before repairing anything.

Python floor is 3.10+; prefer the standard library, and treat PyYAML as available (CI installs it, and the catalog/matrix code imports it).

## Commands

```bash
# registry: every TestCase assigned once, none stale, none empty - fast, no root
python3 tests/run_ci.py --check-completeness

# targeted module
python3 -m unittest -v tests.test_podman_traceability

# single test
python3 -m unittest -v tests.test_podman_traceability.TestTraceabilityRules.test_the_checked_in_table_agrees_with_what_it_cites

# full unprivileged suite (needs EUID != 0)
python3 tests/run_ci.py --suite nonroot

# tools-side tests - exactly what tools/check_acceptance_gate.py runs
python3 -m unittest discover -s tools/tests
```

## Reporting

Name the tests that ran, verbatim as they appear in the output, and the ones that did not - an unrun suite is not a pass. `--check-completeness` proves the registry (assignment, staleness, method presence), never behaviour; a green completeness run with no suite executed is evidence of nothing beyond collection. State the EUID side you ran on, and when only a module was run, say the full suite was skipped.
