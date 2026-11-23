# Setup wizard and deployment variants

`gowave-auto.sh` has a unified interactive entrypoint and prompt-free positional forms. The interactive
entrypoint selects the language first, then presents a menu that routes to all lifecycle operations.
The positional forms remain English-only and prompt-free.

```bash
# Unified interactive entrypoint: selects language, shows menu, routes to operations
sudo ./gowave-auto.sh

# Interactive install (legacy, still works):
sudo ./gowave-auto.sh install

# Non-interactive install (prompt-free):
sudo ./gowave-auto.sh install [--panel-only | --mode panel-only] \
    <panel-domain> <camouflage-domain> <acme-email> [vision-domain]
```

`--panel-only` and `--mode panel-only` are the same flag. Panel-only accepts no Vision domain: it deploys
no traffic plane, so the fourth positional argument is refused.

## Interactive menu

Running `gowave-auto.sh` without arguments (and with a terminal) enters the interactive mode:

1. **Language selection** — `ru` or `en`, before any menu text is rendered
2. **Menu** — numbered options for all lifecycle operations:
   - Show status & health
   - Install All-in-One GoWave stack
   - Add Distributed Edge Worker Node
   - Change domains
   - Switch channel (stable ↔ dev)
   - Create Backup
   - Restore Backup
   - Show User Subscription Links
   - Uninstall
   - Exit

## The three deployment variants

| Variant | What runs on this host | Production use |
| --- | --- | --- |
| Panel-only | Panel and a static camouflage site; stream `default` goes to the decoy at `:9443` | Yes, as the control plane |
| All-in-One | Panel and a local Node, with Xray/REALITY/Vision on `:8443`/`:8444` | Trial and evaluation only |
| All-in-One plus remote nodes | The All-in-One host, then each Worker onboarded over SSH | Yes, with Workers as the traffic plane |

All-in-One is not a production topology: one host would be both the control plane and the traffic plane.

## Adding nodes to an existing Panel (menu option 3)

The "Add Distributed Edge Worker Node" menu option onboards a new Worker to a Panel that is already
deployed. The flow is:

1. **Local Panel detection** — If a `gowave.service` is active on this host, its domain is read from
   NGINX config, `state.json`, or `.env` and offered for confirmation.
2. **Panel address entry** — If no local Panel is found or the operator declines it, the Panel
   address (domain or IP) is prompted.
3. **Panel API verification** — Before any SSH credentials are collected or the Worker is mutated,
   the Panel API is verified:
   - For `127.0.0.1`/`localhost`: HTTP to `:3000/api/health`
   - For remote addresses: HTTPS to `:3000/api/health` with TLS certificate validation against the
     system CA bundle; if validation fails, the certificate fingerprint (SHA-256) is displayed and
     the operator must explicitly confirm it.
   - A wrong target, an unverified certificate without confirmation, or a plaintext remote address
     are all rejected before any Worker access or credential transmission.
4. **Worker details** — Worker name, IP, domain, and camouflage domain are prompted.
5. **Onboarding** — The Worker is registered via the Panel API and provisioned over SSH with
   temporary key authorisation (same process as initial deployment).

## Temporary SSH access for remote nodes

The wizard authorises an Ed25519 key on a Worker only after the operator types the Worker's host-key
fingerprint in full. The flow prints the fingerprint the Worker presents, then asks for it, so the operator
confirms that value against the one the provider's console shows; the question and the password prompt are
written to the terminal, not to the captured diagnostic stream. Two variables provide the non-interactive
inputs:

- `GOWAVE_SSH_FINGERPRINT` — the SHA-256 fingerprint the operator read from the Worker. It must equal the
  key the Worker presents; a mismatch refuses the onboarding before `authorized_keys` is touched.
- `GOWAVE_SSH_PASSWORD_FILE` — a file containing the SSH password, mode `0600`. A file with any other mode
  is refused. The password is read once, written into the private key directory, and never placed in a
  command line: `ssh` reads it through an `SSH_ASKPASS` helper.

```bash
sudo GOWAVE_SSH_FINGERPRINT='SHA256:...' \
     GOWAVE_SSH_PASSWORD_FILE=/root/worker-password.txt \
     ./gowave-auto.sh install
```

The plan questions still come from the terminal; the two variables replace only the SSH prompts of the
onboarding step. The wizard reads them around the `node add` it runs, so the operator is asked once per
Worker.

A systemd timer on the Worker removes the temporary entry within two hours, and the entry is also revoked
at the end of `node add` on success and on failure.

## Non-interactive answers

`GOWAVE_WIZARD_LANG=ru` or `en` selects the wizard's message catalog. It is read per invocation and is
never written to `state.json`, because the language is not installation state. Unknown values fall back
to English.

## Temporary SSH access for remote nodes

The wizard authorises an Ed25519 key on a Worker only after the operator types the Worker's host-key
fingerprint in full. The flow prints the fingerprint the Worker presents, then asks for it, so the operator
confirms that value against the one the provider's console shows; the question and the password prompt are
written to the terminal, not to the captured diagnostic stream. Two variables provide the non-interactive
inputs:

- `GOWAVE_SSH_FINGERPRINT` — the SHA-256 fingerprint the operator read from the Worker. It must equal the
  key the Worker presents; a mismatch refuses the onboarding before `authorized_keys` is touched.
- `GOWAVE_SSH_PASSWORD_FILE` — a file containing the SSH password, mode `0600`. A file with any other mode
  is refused. The password is read once, written into the private key directory, and never placed in a
  command line: `ssh` reads it through an `SSH_ASKPASS` helper.

```bash
sudo GOWAVE_SSH_FINGERPRINT='SHA256:...' \
     GOWAVE_SSH_PASSWORD_FILE=/root/worker-password.txt \
     ./gowave-auto.sh install
```

The plan questions still come from the terminal; the two variables replace only the SSH prompts of the
onboarding step. The wizard reads them around the `node add` it runs, so the operator is asked once per
Worker.

A systemd timer on the Worker removes the temporary entry within two hours, and the entry is also revoked
at the end of `node add` on success and on failure.

## Domain and certificate policy

The preflight counts `C = 2 + v_panel + 2N + k` certificates, where `v_panel` is 1 when the Panel host has
Vision, `N` is the number of Workers, and `k` is the number of Workers with Vision. The 50-per-7-days
Let's Encrypt limit for a registered domain yields four node ceilings:

| Vision placement | Ceiling under one registered domain |
| --- | --- |
| None | 24 nodes |
| Panel host only | 23 nodes |
| Everywhere, Panel-only Panel | 16 nodes |
| Everywhere, All-in-One Panel | 15 nodes |

Separate registered domains proceed without a question because each host spends its own budget. A shared
domain within the ceiling proceeds only after an explicit confirmation that names the count and the
ceiling; above the ceiling the plan is refused and one registered domain per host is recommended.

Three limits are stated rather than worked around:

1. **The remaining budget cannot be queried.** Let's Encrypt exposes no endpoint for it, so the preflight
   counts only the plan in front of it.
2. **The apex and `www` camouflage certificate belongs to a single host.** A second host on the same apex
   cannot serve that website; it can only run a decoy at its own subdomain.
3. **Wildcard is not a remedy for a shared domain.** Every host would order the identical
   `[domain, *.domain]` set, and the five-per-exact-set limit caps a shared-domain cluster at about five
   hosts per week.

## DNS preflight

Every planned name must resolve before the first ACME order. The check runs before any host is modified
and names the names that do not resolve. `GOWAVE_WIZARD_RESOLVER` overrides the resolver command (default
`getent`) for test harnesses.
