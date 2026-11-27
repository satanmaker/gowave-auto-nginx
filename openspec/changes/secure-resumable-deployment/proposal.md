# Proposal

## Why

Issue #2 exposes inconsistent host-security integration across Panel, All-in-One and Worker roles. Operator reports also reveal lost deployment answers, incomplete retry semantics, opaque remote-node outcomes and ambiguous domain/certificate ownership; together these prevent a deployment from being reliably operated or called hardened.

## What Changes

- Establish a role-specific listener and ingress matrix, verified firewall snapshots/restoration, SSH preservation and conflict detection without silently deleting administrator rules.
- Apply and verify Fail2ban and unattended security updates on both host roles; unify strict DoT preparation and expose its best-effort versus required policy and verified rollback outcome.
- Persist a secret-free editable deployment draft and per-operation checkpoints; reconcile actual state before resume and retry failed work without replaying verified siblings.
- Preserve mandatory failure semantics through the interactive menu, display bounded live stages after country entry, recompute retry outcomes and retain a readable final report.
- Make cover, Panel, transport, REALITY and optional Vision names explicit. Master cover is an explicitly selected zone apex; a same-zone Worker does not acquire that apex. With Vision enabled, Worker uses three names: transport/static cover, REALITY and Vision; neither fallback exposes Panel/API.
- Record hostname-to-host-to-certificate ownership, adopt valid existing certificate lineages consistently and verify renewal/rollback and certificates actually served.
- **BREAKING** for new Worker deployments: ordinary requests to the primary transport hostname serve the generated static cover instead of a generic refusal; management/subscription paths remain denied. Existing deployments require an explicit migration preview, not silent routing or certificate changes.

- Pin NGINX stable 1.30.8 from the signed official NGINX APT repository as the primary source on every supported OS. Fall back only to a distribution package with explicitly verified equivalent security fixes; refuse if neither source qualifies.
- Run all four supported distributions concurrently in GitHub Actions and local Podman acceptance, keeping independent results and stable required check names.

## Capabilities

### New Capabilities

None. Extend the existing security, wizard, routing and integration boundaries.

### Modified Capabilities

- `vps-security`: per-role ingress and effective security reporting; shared verified hardening, explicit DoT policy and pinned NGINX package selection.
- `podman-e2e`: parallel distribution coverage and independent evidence in GitHub Actions and locally.
- `interactive-deployment`: durable draft/checkpoints, reconciled resume, all-failed retry, strict failure propagation and truthful final outcomes.
- `setup-wizard`: role-specific domain explanations, ownership review and correction without losing answers.
- `traffic-routing`: explicit cover ownership, Worker static cover, isolated fallbacks and certificate/SNI routing consistency.
- `panel-node-integration`: persist role/domain/certificate identity and migrate existing Worker edge configurations safely.

## Impact

Affected implementation areas: `gowave-auto.sh`, streamed payloads and sibling copies in `gowave-node-auto.sh`, `modules/wizard.sh`, `modules/i18n.sh`, `modules/ssh_bootstrap.sh`, `modules/security.sh`, `modules/os.sh`, `modules/nginx.sh`, `modules/recovery.*`, `modules/api_client.py`, and `assets/security/managed.py`. Extend existing unittest/PTY and Podman acceptance coverage, its case/behaviour/traceability registrations, and RU/EN operator documentation. Preserve positional commands, zero-leak credentials, immutable upstream binaries, external NGINX ownership and native Node supervision of Xray.

Out of scope: WAF, GeoIP, generic HTTP rate limiting, CDN deployment, mTLS rotation/revocation, new VPN protocols, DNS-01/wildcards and provider-level DDoS automation. Active probes are included only to verify the changed routing and listener isolation. No upstream source changes or automatic destructive live-host migration are authorized.
