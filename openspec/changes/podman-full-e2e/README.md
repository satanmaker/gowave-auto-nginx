# Full Product-Level Podman E2E

This OpenSpec change defines and implements product-level E2E testing on Podman. It covers the test harness, the CI/pre-push gates, and the narrowly scoped operator capabilities those gates require: a Podman-only Master address override for Worker provisioning and a fail-closed test-only ACME endpoint.

## Documents

- [Proposal](proposal.md) — motivation, goals, scope, and acceptance summary.
- [Design](design.md) — topology, fixtures, scenario contracts, CI tiers, evidence, and boundaries.
- [Tasks](tasks.md) — implementation plan with traceable work items.
- [Capability specification](specs/podman-e2e/spec.md) — normative requirements and scenarios.

## Important boundary

The existing `multi-node` Podman test remains transport acceptance: it drives SSH, a synthetic mTLS listener, and TCP/3002 source filtering. It is not full GoWave product E2E. The product-level suite must invoke the real `gowave-auto.sh install` and `gowave-auto.sh node add` paths, use the real Panel API, and consume the Panel's real subscription representations.

Subscription representations are not interchangeable:

- `/api/sub/<shortUuid>` returns base64 share links and is the only representation Xray-family mobile clients import;
- `/v2ray-json` returns either one config object or a list of complete per-profile configs;
- `/mihomo` and `/clash` return the full and the compact Mihomo YAML.

The Panel's User-Agent rule is "non-empty header required": absent and blank headers are rejected with 403, while any non-empty value is served. A per-format client-family header is a client-identification convention, not a server-side requirement.

Positive transfer coverage is 8/10 cases for All-in-One and 16/18/20 for Multi-Node. Multi-Node explicitly tests neither Vision domain, Master-only, Worker-only, and both domains; either one-sided configuration has 18 cases. Multi-Node egress must be independently attributable to the intended Master or Worker; direct client/Control bypass is prohibited. REALITY hosts and the TLS transports use the `firefox` uTLS preset by default and the suite asserts it.

The camouflage decoy is part of the acceptance surface: the apex of `panel_domain` and its `www` host must resolve to the host, terminate on the loopback decoy listener, serve the rendered cover site, and be covered by the REALITY certificate lineage, with the port 80 ACME vhost preserved on both Master and Worker.

Pebble requires the fail-closed test-only ACME opt-in this change adds, because the current Master and Worker scripts accept only Let's Encrypt Staging/Production endpoints. Panel and Worker backup archives are unencrypted and secret-bearing; they must never be published as CI artifacts.

The full All-in-One and Multi-Node suites are the pre-push and pull-request gates. They run without live credentials and must stay within the declared runtime budget recorded in the protocol/client matrix manifest.

Both suites are driven from one checked-in case catalog, so a case is defined once and run in the environment that can prove it. Of the 125 live acceptance scenarios, 115 are container-reproducible, 8 are partial (the container proves the mechanism, the live run proves the environment), and 2 are live-only and reported as justified exclusions. New cases are incubated here first: `incubating` → `podman-stable` → `live-parity`, one direction only, with the same case ID and assertion text on both sides. A divergence guard fails the build when a live scenario has no catalog entry, when a `live-parity` case runs in only one suite, or when an ID asserts different things in the two catalogs.

Public DNS, provider networking, public ACME, and external Internet reachability remain separate Live VPS acceptance responsibilities. QEMU remains responsible for cold-boot and OS/kernel behaviors that containers cannot faithfully prove.
