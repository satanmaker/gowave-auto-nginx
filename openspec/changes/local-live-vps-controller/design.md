# Design: Local Live VPS Operator Controller

## Context and goals

The existing E2E suite already implements the deployment and acceptance lifecycle. This change adds an operator-facing local authentication/bootstrap layer rather than rewriting deployment logic.

The controller must:
- Run locally on Linux and invoke the existing runner in the same checked-out, clean repository.
- Accept the five-domain topology: Master Panel, Master REALITY, Master Vision; Worker NGINX and Worker REALITY.
- Never put passwords in process arguments, environment variables, persistent config, logs, or artifacts.
- Authenticate the host identity before sending a password.
- Convert password authentication into a temporary key-based session for the existing OpenSSH runner.
- Guarantee remote key expiry independently of the local process, including local crash and VPS reboot.
- Never claim overall PASS unless temporary SSH access removal is verified.

## Decisions

### D1 — Local execution, not a target-credential GitHub workflow

The operator launches `tools/test_live_vps.py` as a local subprocess. GitHub Actions continues to run repository CI and unit tests only. The old `workflow_dispatch` workflow that consumed `LIVE_VPS_CONFIG`, private-key, and known_hosts secrets is removed.

### D2 — Hidden password prompt and Paramiko bootstrap

Passwords are read with Python `getpass` and passed directly to Paramiko's in-memory `Transport.auth_password` call. They are never serialized. Paramiko is pinned in `tools/requirements-live-vps.txt`.

The controller first starts SSH key exchange without authenticating, obtains the server host key, and prints its SHA-256 fingerprint. The operator must type the exact fingerprint obtained independently from the VPS provider's trusted console. A mismatch aborts before password entry/authentication. No `ssh-keyscan` trust-on-first-use shortcut is allowed.

### D3 — Temporary Ed25519 key bootstrap

After password authentication, the controller verifies `id -u == 0`, generates a fresh Ed25519 keypair per host, and writes the private key into a mode-0700 temporary directory. Only the public key is appended to `/root/.ssh/authorized_keys`, with a unique per-run comment marker. Existing authorized_keys content is preserved and replaced atomically.

The current installer and rollback commands require root; v1 rejects non-root SSH users rather than implying that sudo support exists.

### D4 — Remote expiry before key installation

The controller creates a root-owned cleanup script, a systemd oneshot service, and a persistent absolute-time systemd timer on each VPS. The timer is enabled before the temporary public key is appended. This ordering closes the failure window in which a process/network failure could leave a privileged key without an expiry mechanism.

The expiry script removes only the exact unique marker from `authorized_keys`, disables the timer, removes its own service/timer/script files, and reloads systemd. The timer uses `OnCalendar` plus `Persistent=true` so a reboot does not silently discard the expiry deadline. Default lifetime is two hours.

### D5 — Immediate revocation and PASS gate

After the E2E subprocess exits, the controller connects using the ephemeral key, runs the exact remote cleanup script, and independently verifies:
- The marker is absent from `authorized_keys`.
- The expiry timer is no longer active.

If the immediate cleanup cannot be verified, the controller leaves the remote timer armed and records `operator_access_cleanup=INCOMPLETE`. It updates the run-state, JSON, JUnit, and text summary. An otherwise PASS E2E result becomes overall INCOMPLETE.

### D6 — Ephemeral local files

Private keys, known_hosts files, and generated configuration live in a temporary directory with mode 0700. Key files and known_hosts files are mode 0600. The generated config contains paths and non-secret target metadata only; it never contains passwords. Temporary local material is removed on exit.

### D7 — Input validation and five-domain mapping

All target inputs are validated by the existing whitelist config parser before opening SSH connections. Master Vision and Worker Vision are independent optional config fields. The interactive flow requires the Master Vision field and leaves Worker Vision unset, producing the requested 3+2 mapping. DNS validation already includes each configured domain independently. Expected subscription endpoint count is eight core endpoints plus one for each configured Vision endpoint.

### D8 — ACME defaults and production guard

ACME staging is the default. Production mode is available only through an explicit command-line choice and a second typed confirmation. No production credentials are collected.

## Security boundaries and limitations

- Root password authentication must already be enabled by the operator. The controller does not modify sshd policy.
- Existing root password authentication remains enabled after the run; if it was enabled only for bootstrap, the operator must disable it through the provider console or their normal secure process.
- Root login only; non-root sudo support is not implemented.
- Remote expiry is a bounded fallback, not a substitute for immediate cleanup. If immediate cleanup fails, the report remains INCOMPLETE until expiry is independently confirmed.
- The controller does not create or destroy VPS instances. The existing preflight gate and teardown policy remain authoritative.
- The default existing teardown policy is PRESERVE; the operator must understand that this does not destroy VPS instances or restore provider snapshots.
- Xray and Mihomo client binaries must already be installed locally at the configured pinned versions.

## Validation strategy

Unit tests cover fingerprint formatting, expiry script contents, mode-0600 config generation, absence of password fields, independent Vision parsing, and workflow removal. Existing runner tests remain in place. Each Xray/Mihomo request is now bracketed by simultaneous inbound tcpdump captures on both target VPSs, filtered to the control machine's IPv4 as each target reports it on the runner's SSH session, the exact proxy service destination port, and excluding the respective SSH port. Per-case PASS requires a positive packet count on the intended VPS, zero packets on the other VPS, and the expected egress IP; an empty capture on both hosts while the tunnel carried the request is INCOMPLETE. Capture summaries are persisted; payloads and PCAPs are not. Both VPSs must have tcpdump installed. CI runs the full `tools/tests` unittest suite. Live acceptance still requires a fresh disposable VPS pair and a complete ACME staging run with verified temporary-key revocation; CI green alone is not live VPS acceptance.
