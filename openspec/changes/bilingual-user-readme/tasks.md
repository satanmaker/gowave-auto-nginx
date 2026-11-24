# Tasks

## 1. Paired foundation and preparation

- [ ] 1.1 Establish matching English/Russian README structure, reciprocal language links, contents and explicit ASCII section anchors for all 14 design sections; add paired structure/link tests and register any new TestCase in `tests/run_ci.py`. Verify focused tests and `python3 tests/run_ci.py --check-completeness`.
- [ ] 1.2 Write purpose, upstream relationship, native deployment, four default profiles/optional Vision, subscription families and non-goals in both guides; verify technical identifiers against profile templates and provisioning code and run the paired content tests.
- [ ] 1.3 Write topology diagrams, recommendations, OS/architecture prerequisites, justified resource guidance and domain/DNS/public-internal port tables in both guides; verify against `modules/os.sh`, preflight, NGINX/UFW configuration and current wizard guidance, and add/run source-backed assertions for key supported values.
- [ ] 1.4 Carry the existing node environment, certificate budget and SSH-bootstrap warnings into both guides, including precedence/defaults and pin opt-out consequences; extend `TestPreflightDocumentation` and `TestWizardDocumentation` without dropping their behavioral coverage and run those focused classes.

## 2. Installation through first working client

- [ ] 2.1 Document repository acquisition and interactive-first installation on the correct host, plan review, DNS/certificate checks and final outcomes in both languages; add/run checks for valid entrypoints and equivalent executable examples, and manually trace the steps against the wizard without installing anything.
- [ ] 2.2 Document first Panel login, protected credentials handling, initial user behavior, subscription retrieval/import, User-Agent/core compatibility and real-traffic verification in both languages; verify against credential/user-link/provisioning code and client locks, and add/run checks for subscription paths and consistent technical values without embedding secrets.
- [ ] 2.3 Document remote onboarding with temporary wizard access versus positional SSH access, fingerprint trust, registration readback, partial success and selective retry; verify both language procedures against onboarding implementation and run the relevant paired documentation and existing wizard guards.

## 3. Operations and safety reference

- [ ] 3.1 Complete both command/environment references for valid install modes, node subcommands, status/health, user links, channels and domains; mark recovery forms by audience and purpose. Add/run source-backed command/default tests that refuse a changed documented command or value.
- [ ] 3.2 Explain Panel update versus channel switching, backup/restore scope, secret-bearing archives, recovery limits and uninstall consequences beside their examples in both guides; verify against lifecycle/update/backup implementations and add/run paired warning/reference tests.
- [ ] 3.3 Add the files/services map, hardening side effects and symptom/check/next-action troubleshooting in both languages; verify named paths/services and key diagnostics against shipped configuration and run local-link and relevant content tests. Do not add unconditional rollback, failover or anti-detection guarantees.

## 4. Testing explanation and linked consistency

- [ ] 4.1 Explain all five privilege-separated suites, Podman topologies/distributions, live-VPS acceptance, real-client checks, artifacts and evidence boundaries in both guides; verify against `tests/run_ci.py`, matrix/locks, runner interfaces and workflows, and run source-backed documentation checks. Clearly label disposable-only privileged tests and avoid presenting declarations as current PASS evidence.
- [ ] 4.2 Audit repository-relative links and referenced guidance; make only verified corrections in directly linked `CONTRIBUTING.md`/`docs/*.md`, including branch and strict-mode contradictions. Verify every changed statement against its owning code/config and run existing affected documentation guards plus the link checks.
- [ ] 4.3 Prove documentation guards detect an invalid local file/fragment, a missing language section and an altered CLI/default using negative fixtures or in-memory mutations; run those tests. Remove unnecessary volatile totals or verify every retained requirement/scenario/case total from its owning files in both languages.

## 5. Integrated acceptance of the documentation change

- [ ] 5.1 Run all touched documentation test classes, `python3 tests/run_ci.py --check-completeness` and `python3 tests/run_ci.py --suite nonroot`; record actual results and any unrun/failed checks without launching unrequested live or destructive suites.
- [ ] 5.2 Review rendered English/Russian Markdown for navigable contents, readable diagrams/tables, working anchors and equivalent complete procedures; verify all 14 design sections, matching executable examples and warnings, and ensure no placeholders, real credentials, personal paths or unsupported claims remain.
- [ ] 5.3 Review the final diff for documentation/test-only scope, run `git diff --check` and `openspec validate bilingual-user-readme --strict`, and report the supporting documents touched and the checks that do and do not establish runtime acceptance.

## Workflow follow-up

- Review the implementation and archive this documentation-only change once all tracked work has evidence. No runtime delta is expected because `skip_specs: true` is intentional.
