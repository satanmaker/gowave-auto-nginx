# Design

## Context

See `proposal.md` for motivation and scope. Discovery already read the current README, `docs/SETUP_WIZARD.md`, `docs/PODMAN_E2E.md`, `CONTRIBUTING.md`, the CLI router/menu in `gowave-auto.sh`, `modules/os.sh`, the suite registry in `tests/run_ci.py`, documentation guards and `.github/workflows/podman-acceptance.yml`.

Observed constraints:

- The terminal entrypoint selects a language and opens a lifecycle menu. Complete positional invocations remain a separate automation contract.
- The current wizard guide recommends a Panel-only control host with separate traffic nodes; the README's production advice is less precise. No topology promises automatic failover.
- The CLI exposes status, health, install, node, channel, domain-change, backup, restore, uninstall, user links and specific internal recovery forms. A router word alone is not evidence that a bare invocation is useful; document valid arguments and audience.
- `tests/test_preflight.py` checks the README's node environment contract; `tests/test_wizard.py` checks certificate-policy warnings and SSH bootstrap inputs. `tests/test_podman_docs.py` already reads documentation against implementation and specification counts.
- Five privilege-separated suites and rootful Podman acceptance are different test layers. Production deployment does not require a container runtime merely because acceptance uses one.
- `CONTRIBUTING.md` still describes `main` as the primary branch and omits `-E` from its shell strict-mode guidance. The actual acceptance workflow includes PRs into `develop`, push to `develop` and manual dispatch; do not generalize that event set to every workflow.

The design is included because bilingual parity, existing source-reading guards and safety-sensitive operating instructions need explicit decisions before rewriting.

## Goals / Non-Goals

**Goals:**

- Make both README versions independently sufficient for the supported installation-to-client journey, with a navigable reference for later maintenance.
- Use current source/configuration as the authority for commands and defaults; explain limitations where observed behavior and broader specification claims differ.
- Keep regression checks deterministic and offline, and preserve meaningful existing documentation contracts.

**Non-Goals:**

- No runtime fixes, added CLI flags, CI/release policy changes, upstream changes or automatic translation service.
- No full translation of linked guides, screenshots requiring live credentials, new benchmark campaign or unrequested live/privileged deployments.
- No universal client-application tutorial or guarantee against detection, blocking, outages or data loss.

## Decisions

### 1. Two manually maintained, equally complete guides

Use English `README.md` and Russian `README.ru.md`. Put reciprocal relative language links and a linked contents list near the top. Keep matching section order and stable explicit ASCII section anchors so automated checks can compare semantic sections without requiring translated headings to match byte-for-byte. Technical identifiers, commands, paths and version values remain unchanged.

Alternative: one combined bilingual file makes navigation too long; translating all of `docs/` expands maintenance beyond the agreed scope. A short Russian summary is not equivalent documentation and is rejected.

### 2. Organize by operator journey, then reference

Both files use this section contract:

1. Purpose, intended audience, relation to GoWave and what gets installed.
2. Features, supported transports/clients and non-goals.
3. Architecture and topology choices, including failure isolation and no automatic failover.
4. Requirements and preparation: supported OS/architectures, verified resource guidance, root/SSH, outbound downloads, clean-host assumptions, DNS and external firewall.
5. Domain/DNS plan and public/internal port tables, including optional Vision and certificate policy.
6. Interactive-first installation: obtain the full repository, run on the Panel VPS, review the plan, confirm, interpret the final result.
7. First login and first client connection: protected credentials location, initial user behavior, subscription retrieval/import and actual traffic verification.
8. Remote nodes: where to run onboarding, fingerprint verification, temporary wizard access versus positional SSH access, registration readback, partial success and selective retry.
9. Operations: status/health, subscription links, domain changes, Panel update versus channel switching, backups, restores, recovery and uninstall.
10. CLI and environment reference: valid syntax, defaults, precedence, sensitive-data handling and special-purpose/internal commands.
11. Files/services and security model: owned state, hardening side effects, trust boundaries and rollback limits.
12. Troubleshooting: symptom, safe check, interpretation and next action.
13. Testing and evidence: five suites, Podman and live VPS, real clients, artifacts, reproducible commands and limitations.
14. Repository/developer links, contribution route, license and external upstream references.

Use small ASCII topology/traffic diagrams. Each main procedure states execution host, prerequisites, operation, expected result, what it does not prove and the failure/recovery route. Long linked references supplement the route; they must not hide a mandatory first-install step.

Alternative: a feature-first catalogue followed by commands preserves the existing onboarding gap. A tiny landing README would not meet the requested detail.

### 3. Ground technical instructions before translating

Build the English guide and Russian counterpart from one verified fact inventory. Validate installation/bootstrap commands against the repository layout and entrypoints, not an assumed standalone download. Distinguish Panel assets, Node installer and Xray core sources; explain pinned defaults and opt-outs without promising that every download or lifecycle operation avoids the GitHub API.

Use reserved example domains and documentation IP ranges. Never put actual hosts, local workstation paths, passwords, tokens or subscription secrets into tracked examples. Do not copy another project's secret-in-argv patterns. Do not recommend running destructive root suites on an installed production host.

Explain credential retrieval without printing sample real credentials. Explain that valid client User-Agent/format and core compatibility matter; do not infer support for all GUI clients from tests of the underlying cores. Verify any version floor against the actual client lock and behavior before publishing it.

State hardening changes and deletion/restore consequences beside the relevant actions. Avoid invented universal RAM/disk minima, unmeasured memory claims, unconditional rollback claims and guarantees of invisibility.

### 4. Adopt documentation patterns, not foreign behavior

Read on 2026-11-25 as editorial references, not dependencies or independent correctness evidence:

- https://github.com/hwdsl2/setup-ipsec-vpn — lifecycle ordering, separate translations and explicit next steps/client setup.
- https://github.com/DigneZzZ/remnawave-scripts — component command tables, paths and update/backup distinctions.
- https://github.com/acmesh-official/acme.sh — list of system mutations and warnings adjacent to commands.
- https://github.com/nodenv/nodenv — separate practical instructions, mechanism and command/environment reference.

Do not reproduce their text, marketing claims, commands, deployment architecture or licensing notices as our own. Their scripts and translations were not validated in this research.

### 5. Regression checks protect semantics, not prose layout

Prefer extending existing relevant test modules; add a focused `tests/test_readme.py` only if bilingual/link checks do not fit them cleanly. Register every new TestCase in the nonroot suite.

Check both files for reciprocal language links, the agreed semantic section anchors, resolvable repository-relative files/fragments, and selected command/environment/default contracts sourced from actual code or existing authoritative manifests. Compare executable examples with allowances for localized comments; compare exact identifiers and maintained values, not translated sentences. Reject removed warnings or one-language-only contract changes.

Keep checks offline. Restrict Markdown handling to the supported README constructs; do not introduce a generic documentation framework or network availability checks. Add negative fixtures or in-memory damaged-document tests proving detection of a broken link, missing language section and changed command/default. Preserve current assertions by extending them to both guides or making them structurally aware while retaining the same behavior requirement.

If counts of requirements, scenarios or cases remain, derive expected values from the owning files and test both guides. Prefer explaining coverage with links over quoting volatile totals. Historical PASS claims require a named commit/run and scope; a badge or scenario declaration is not a current result.

### 6. Repair linked contradictions narrowly

Audit links originating from both README files. Correct verified stale branch, command, strict-mode, topology or testing statements in directly linked guides, retaining the rest of their content and language. Keep a concrete list of touched supporting documents in the implementation report. If a correction needs behavior or policy changes, stop and report it outside this documentation change.

## Risks / Trade-offs

- Two full guides can diverge -> same section contract, shared executable examples and paired offline assertions; manual review still checks translation meaning.
- A source-reading guard can overfit wording -> assert identifiers, values and warning semantics, not paragraph order or arbitrary English phrases.
- A rewrite can silently remove an existing contract -> carry the node environment, SSH and certificate guards forward before removing old prose.
- Supported-platform declarations can look like measured acceptance -> separate supported targets, configured CI coverage and named historical run evidence.
- Rich command examples can accidentally imply safe production testing -> label execution host, privilege level, destructive effects and disposable-only test commands.
- Linked docs remain largely English -> disclose link language where useful; both README versions still contain the complete essential route.

## Migration Plan

Ship the paired README changes, narrowly scoped linked corrections and tests together. Do not change production configuration or deployment state. Verify focused documentation tests, suite completeness and the nonroot suite; inspect the rendered Markdown for both languages. Rollback, if requested, is a normal documentation-only follow-up; no runtime migration is needed.
