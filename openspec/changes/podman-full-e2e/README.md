# Full Product-Level Podman E2E

This OpenSpec change defines the target for local product-level E2E testing. It is a documentation/specification change only; no test harness, application code, or workflow is implemented here.

## Documents

- [Proposal](proposal.md) — motivation, goals, scope, and acceptance summary.
- [Design](design.md) — topology, fixtures, scenario contracts, CI tiers, evidence, and boundaries.
- [Tasks](tasks.md) — implementation plan with traceable work items.
- [Capability specification](specs/podman-e2e/spec.md) — normative requirements and scenarios.

## Important boundary

The existing `multi-node` Podman test remains transport acceptance (SSH/mTLS/firewall). It is not full GoWave product E2E. The planned product-level suite must invoke the real `gowave-auto.sh install` and `gowave-auto.sh node add` paths, use the real Panel API, and test both Xray JSON and Mihomo YAML subscriptions. Positive transfer coverage is 8/10 cases for All-in-One and 16/18/20 for Multi-Node. Multi-Node explicitly tests neither Vision domain, Master-only, Worker-only, and both domains; either one-sided configuration has 18 cases. Multi-Node egress must be independently attributable to the intended Master or Worker; direct client/Control bypass is prohibited. Pebble requires a future fail-closed test-only ACME opt-in because the current Master and Worker scripts accept only Let's Encrypt Staging/Production endpoints. Panel and Worker backup archives are unencrypted and secret-bearing; they must never be published as CI artifacts.

Public DNS, provider networking, public ACME, and external Internet reachability remain separate Live VPS acceptance responsibilities. QEMU remains responsible for cold-boot and OS/kernel behaviors that containers cannot faithfully prove.
