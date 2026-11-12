# Tasks: Local Live VPS Operator Controller

## 1. OpenSpec and operator contract

- [x] 1.1 Define local execution, credential boundary, host-key verification, temporary access lifecycle, reporting gate, and non-goals.
- [x] 1.2 Define the five-domain operator mapping and independent Master/Worker Vision semantics.
- [x] 1.3 Document root-only bootstrap, pre-enabled root password authentication, local Xray/Mihomo prerequisites, ACME staging default, and non-destructive PRESERVE behavior.

## 2. Independent Vision topology

- [x] 2.1 Remove the config parser's pair-wide Vision requirement while preserving global domain uniqueness.
- [x] 2.2 Make Master and Worker disposable port gates depend on their own Vision setting.
- [x] 2.3 Calculate subscription endpoint expectations as eight core endpoints plus one per configured Vision endpoint.
- [x] 2.4 Add parser and preflight regression coverage for Master-only and Worker-only Vision.

## 3. Local operator and secure bootstrap

- [x] 3.1 Add a local interactive entrypoint that collects the five domains, two target IPs, SSH ports/logins, hidden passwords, and ACME email.
- [x] 3.2 Validate all inputs with the existing strict config parser before contacting either VPS.
- [x] 3.3 Verify SSH host-key fingerprint before password authentication; require an exact operator confirmation against the provider console.
- [x] 3.4 Generate a per-host Ed25519 keypair and install only the public key with a unique marker.
- [x] 3.5 Install and enable persistent remote expiry before appending the temporary key; remove only the matching marker.
- [x] 3.6 Run the existing E2E runner with ephemeral key paths and strict known_hosts pins.
- [x] 3.7 Revoke temporary keys immediately and downgrade the report to INCOMPLETE if cleanup is not independently verified.
- [x] 3.8 Remove all temporary local key/config material on exit.
- [x] 3.9 Add pinned Paramiko/PyYAML requirements and operator command wrapper.

## 4. CI and tests

- [x] 4.1 Remove the GitHub Actions live VPS workflow that consumed target credentials as repository/environment secrets.
- [x] 4.2 Keep unit-test CI and install pinned Python dependencies there.
- [x] 4.3 Add unit tests for fingerprint formatting, remote expiry cleanup, and generated config permissions/topology.
- [x] 4.4 Update CLI regression tests to assert local password prompting and no credential-bearing live VPS workflow.
- [x] 4.5 Run the full unittest suite and all repository CI checks on the PR head; resolve every regression.
- [x] 4.6 Replace aggregate `/proc/net/dev` traffic heuristics with per-case packet capture on both VPS instances, filtered by control-machine source IPv4 and the exact proxy destination port; require target ingress, zero offload ingress, and matching egress for every Xray/Mihomo case.
- [x] 4.7 Add regression tests for capture lifecycle, SSH-port exclusion, missing evidence, and offload detection.
- [x] 4.8 Perform a complete live ACME staging run against two freshly provisioned disposable VPS instances and verify remote expiry/cleanup before marking the overall feature accepted.
