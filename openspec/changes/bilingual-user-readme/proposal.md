# Proposal

## Why

The English-only README describes implementation mechanisms but does not guide an operator from choosing servers and preparing DNS to a working client connection and safe maintenance. Its topology advice, testing explanation and linked contribution guidance have drifted from the shipped wizard and CI, making a complete, equally detailed English/Russian replacement necessary.

## What Changes

- Replace `README.md` with the primary English operator guide and add a complete Russian counterpart, `README.ru.md`, with reciprocal language links and equivalent sections, commands, defaults and warnings.
- Explain the project's purpose, its relationship to upstream GoWave, native systemd deployment, topology tradeoffs, supported profiles, subscription formats and explicit non-goals.
- Provide a prerequisite checklist, host/domain/DNS and port tables, architecture sketches, interactive-first installation, prompt-free examples, first login and subscription import, expected outcomes and troubleshooting.
- Cover remote onboarding, partial success and selective retry, status/health, updates versus channel switching, domain changes, backup/restore, recovery boundaries and destructive operations.
- Explain the five test suites separately from Podman and live-VPS acceptance, real-client checks, evidence limitations and safe reproduction environments; do not present specification counts as passed tests.
- Correct confirmed contradictions and broken links in directly referenced repository guides, especially `CONTRIBUTING.md`, without translating or rewriting the whole `docs/` tree.
- Extend documentation checks for both languages, local links/anchors, important CLI contracts and maintained quantitative claims. Preserve existing meaningful assertions rather than deleting them to accommodate the rewrite.

## Capabilities

### New Capabilities

None. This change improves documentation and its regression checks, not runtime behavior. `.openspec.yaml` explicitly sets `skip_specs: true`.

### Modified Capabilities

None. Existing deployment, lifecycle, protocol and acceptance contracts remain unchanged. Any discovered conflict that requires changing runtime behavior or an existing requirement is reported separately, not silently resolved by expanding this change.

## Impact

- Primary deliverables: `README.md` and `README.ru.md`.
- Supporting changes: narrowly scoped corrections in directly referenced `CONTRIBUTING.md` and `docs/*.md` when verified against current code/configuration.
- Verification: existing documentation tests in `tests/test_wizard.py`, `tests/test_preflight.py`, `tests/test_podman_docs.py`, and focused README checks as needed; register any new TestCase in `tests/run_ci.py`.
- No installer, upstream binary, API, deployment dependency, CI trigger, release policy or infrastructure behavior changes. No new production dependency, full documentation translation, live deployment or destructive test run is required by this documentation change.
