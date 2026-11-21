# Proposal

## Why

The installer exposes interactive setup only inside selected commands, asks for inputs as a long one-way sequence, and can leave the operator without a clear recovery path when one remote node fails. Operators need to choose the interface language before any menu, review and correct a deployment plan before server mutations begin, and distinguish basic connectivity problems from installation failures.

## What Changes

- Provide one user-facing entrypoint and top-level menu for fresh deployment, adding nodes to an existing Panel, and existing lifecycle operations; keep the implementation internally modular.
- Select Russian or English before displaying any menu, while preserving existing prompt-free positional/non-interactive command contracts.
- Allow navigation back and editing any collected plan field before the operator confirms deployment. Do not promise rollback of already successful phases after deployment begins.
- Add optional, minimal preflight diagnostics: local SSH connectivity to target VPS and external DNS plus TCP/443 checks from a user-selected country, when an appropriate external probe is available. A failed probe is explained and the operator may continue or return to editing; missing/insufficient probe results are not classified as a block.
- Treat Globalping as a candidate integration, not a fixed dependency: verify country/probe availability and TCP/DNS behavior; do not scan arbitrary ports. Public probe requests and results may disclose the tested public IP/FQDN.
- Continue the panel deployment and other independent node deployments when an individual remote node fails. Summarize each failed node with address, failed phase, and reason, then offer a selective retry.
- Before retrying a partially completed node operation, inspect Panel and VPS state, show detected leftovers, and obtain confirmation before continuation or compensation. Never silently delete partial state.
- For “add nodes”, detect a local Panel when possible; if it is absent or ambiguous, ask for the Panel address and verify Panel/API reachability.

## Capabilities

### New Capabilities
- `interactive-deployment`: Unified interactive entrypoint, pre-deployment plan navigation, optional connectivity diagnostics, and recoverable multi-node onboarding.

### Modified Capabilities
- `setup-wizard`: Extend the completed wizard contract with language-before-menu, plan-wide backward navigation, and recovery behavior for independent remote-node failures.
- `install-preflight`: Extend existing input/domain preflight with minimal local SSH and optional external DNS/TCP reachability diagnostics. The existing validation and Cloudflare/ACME checks remain authoritative and are not duplicated.
- `lifecycle-management`: Add the unified menu operation for adding nodes to a discovered or explicitly selected existing Panel, without changing positional CLI behavior.

## Impact

- Likely code areas: `gowave-auto.sh`, `modules/wizard.sh`, `modules/i18n.sh`, `modules/ssh_bootstrap.sh`, `modules/preflight.sh`, and the node orchestration path.
- Tests and acceptance coverage: wizard and preflight unit tests, shell lint guards, and Podman acceptance cases for per-node failure isolation, summary, and selective retry; external Globalping tests must use public test targets or controlled fixtures, not production VPS by default.
- Potential external integration: Globalping REST API, only if basic country-scoped DNS and TCP/443 probes are verified. No resident agent, daemon, or mandatory API credential is intended.
- Existing positional installation and node commands remain available and non-interactive; this change is limited to the interactive surface and explicit optional diagnostics.
