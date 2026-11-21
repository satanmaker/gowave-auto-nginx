# Proposal

## Why

The installer exposes interactive setup only inside selected commands, asks for inputs as a long one-way sequence, and can leave the operator without a clear recovery path when one remote node fails. Operators need to choose the interface language before any menu, review and correct a deployment plan before server mutations begin, and distinguish basic connectivity problems from installation failures.

## What Changes

- Provide one user-facing entrypoint and top-level menu for fresh deployment, adding nodes to an existing Panel, and existing lifecycle operations; keep the implementation internally modular.
- Select Russian or English before displaying any menu, while preserving existing prompt-free positional/non-interactive command contracts.
- Allow navigation back and editing any collected plan field before the operator confirms deployment. Do not promise rollback of already successful phases after deployment begins.
- Add optional, minimal preflight diagnostics: an unauthenticated local SSH reachability check per target VPS, and consented external DNS plus TCP checks from a user-selected country on ports that are served at the time of the check. A failed probe is explained and the operator may continue or return to editing; missing, insufficient, or unavailable probe results are not classified as a block and never decide the deployment.
- Treat Globalping as a candidate integration, not a fixed dependency: verify country/probe availability and TCP/DNS behavior; do not scan arbitrary ports. Public probe requests and results may disclose the tested public IP/FQDN.
- Continue the panel deployment and other independent node deployments when an individual remote node fails. Summarize each failed node with address, failed phase, and reason, then offer a selective retry.
- Before retrying a partially completed node operation, inspect Panel and VPS state, show detected leftovers, and obtain confirmation before continuation or compensation. Never silently delete partial state.
- For “add nodes”, detect a local Panel when possible; if it is absent or ambiguous, ask for the Panel address and verify Panel/API reachability.

## Capabilities

### New Capabilities
- `interactive-deployment`: One interactive entrypoint and menu, plan review and editing before the first mutation, per-node failure isolation, partial-success reporting, and diagnosable selective retry.

### Modified Capabilities
- `setup-wizard`: Extend the completed wizard contract so the language question precedes the menu, every command outside that menu stays English, and the temporary-access invariants are scoped per node.
- `install-preflight`: Add an unauthenticated local SSH reachability check and consented, country-scoped external DNS/TCP diagnostics on ports that are actually served. The existing validation and Cloudflare/ACME checks remain authoritative and are not duplicated.
- `lifecycle-management`: Add the unified menu operation for adding nodes to a discovered or explicitly selected existing Panel, with a verified HTTPS channel before credentials are sent, without changing positional CLI behavior.

## Impact

- Likely code areas: `gowave-auto.sh`, `modules/wizard.sh`, `modules/i18n.sh`, `modules/ssh_bootstrap.sh`, `modules/preflight.sh`, and the node orchestration path.
- Tests and acceptance coverage: wizard and preflight unit tests, shell lint guards, and Podman acceptance cases for per-node failure isolation, summary, and selective retry; external Globalping tests must use public test targets or controlled fixtures, not production VPS by default.
- Potential external integration: Globalping REST API, only if basic country-scoped DNS and TCP probes are verified. No resident agent, daemon, or mandatory API credential is intended.
- Documentation and ledgers: `docs/SETUP_WIZARD.md` and the `README.md` requirement/scenario count, which a guard in `tests/test_podman_docs.py` re-derives from `openspec/specs/`.
- Archive ordering: `setup-wizard` and `install-preflight` exist only as unarchived deltas, so `interactive-setup-wizard` and `inspiration-backlog` must be archived before this change.
- Existing positional installation and node commands remain available and non-interactive; this change is limited to the interactive surface and explicit optional diagnostics.
