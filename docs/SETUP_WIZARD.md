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
   - Show installation status
   - Deploy a new Panel (and optional nodes)
   - Connect a remote server as a node to the existing Panel
   - Change domains
   - Switch channel (stable ↔ dev)
   - Create Backup
   - Restore Backup
   - Show User Subscription Links
   - Uninstall
   - Exit

Every action stays on screen until Enter is pressed, and only then does the menu redraw: the menu starts
with a clear, so a status report or a result that ended the branch would otherwise be erased before it
could be read. End of input (Ctrl-D) leaves the menu the way Exit does. The positional `status` command
never waits, because a script or a CI case has nobody to press Enter.

## The three deployment variants

| Variant | What runs on this host | Production use |
| --- | --- | --- |
| Panel only | Panel and a static camouflage site; stream `default` goes to the decoy at `:9443` | Recommended: control plane only, no client traffic |
| Panel and one node | Panel and a local Node, with Xray/REALITY/Vision on `:8443`/`:8444` | Evaluation and personal use only |
| Panel and one node plus remote nodes | The same host, then each Worker onboarded over SSH | Not recommended: one host is both control plane and one of the traffic endpoints |

The recommended shape is Panel-only on this host with every node on a separate server: losing the
Panel host then costs the control plane but no client endpoint. Every variant that runs a node here
puts one traffic endpoint on the same host as the control plane, and no scheme moves clients between
nodes automatically when one fails — failover is a property of the client configuration and the node
inventory, not of this installer.

## Naming servers

Every server in the plan is given a name of the operator's own choosing, asked separately from its
domain: the local node right after the Panel card, each remote node right after its own card. A
Panel-only host runs no local node, so it asks for no local name and no Vision. The name is what the
Panel, the subscriptions and the Host records call the server, so it is not derived from DNS and does
not have to look like one — `ams-01` is a fine name for a host whose domain is `node1.example.com`.

The same rules apply wherever a name is asked — during collection, in the review editor, and when
adding a node to an existing Panel:

- surrounding spaces are removed, so a pasted name is accepted as typed;
- a blank name is refused and only that question is repeated;
- letters, digits, dot, underscore and hyphen are allowed, and the first character is a letter or a
  digit. This is the rule the Panel enforces on registration, so a name the wizard accepts is a name
  `node add` accepts instead of failing after the SSH session opened;
- two servers cannot share a name, and a difference in case alone is a shared name. The refusal names
  the server that already holds it.

The accepted name reaches everything the server is registered with: profile tags, Host remarks, the
`node add` argument and `state.json`. An installation that collects no plan — a positional
`gowave-auto.sh install …` run — keeps the historical `local-node` name, so a repeated non-interactive
install does not register a second local node under a new name.

## Reviewing the plan

Collecting the answers builds a plan; nothing on a server changes until the review is started. A name
the plan already holds — the Panel host, the Panel camouflage, a node's own two other names, or the
name another server was given — is refused at the field that typed it and asked again, so a second
node's cover domain cannot cost the Panel and the first node. The review prints the summary and four
kinds of action:

```
  1) Start deployment with this plan
  2) Edit the Panel and plan settings
  3) Edit node 1
  0) Cancel and return to the menu
```

Adding remote nodes puts one `Edit node N` line per node, so node 2 is always action 4 and cannot
reach node 1's fields. Each editor lists that group's fields with their current values and a number
for each, and `0` returns to the action list. An empty answer keeps the current value, except a
Vision domain, where empty removes Vision; a refused value prints its reason and leaves the editor
open, so the operator fixes that one field instead of retyping the whole card.

Start re-runs the DNS check and the certificate-budget check, so a plan refused during editing cannot
be started anyway. The shared-domain consent is remembered for the certificate count it was given
for, and asked again only when the count changes. Cancel prints `Deployment cancelled. No server was
changed.` and returns to the menu with the plan discarded: no lock is taken, and no install step
runs.

## Adding nodes to an existing Panel (menu option 3)

The "Connect a remote server as a node to the existing Panel" menu option onboards a new Worker to a
Panel that is already deployed. The flow is:

1. **Local Panel detection** — If a `gowave.service` is active on this host, its domain is read from
   NGINX config, `state.json`, or `.env` and offered for confirmation.
2. **Panel address entry** — If no local Panel is found or the operator declines it, the Panel
   domain is prompted. An address is not accepted: the certificate the Panel serves names its
   domain, so a bare IP offers nothing to verify.
3. **Panel API verification** — Before any SSH credentials are collected or the Worker is mutated,
   the Panel API is verified:
   - For a Panel running on this host, and for `127.0.0.1`/`localhost`: plaintext HTTP to
     `127.0.0.1:3000/api/system/health`. The Panel itself speaks plaintext on 3000; TLS is
     terminated by the NGINX in front of it.
   - For a remote domain: HTTPS to `https://<domain>/api/system/health` on 443, validated against
     the system CA bundle. If validation fails, the certificate fingerprint (SHA-256) is displayed
     and the operator must confirm it; the certificate is read again after the answer, and a
     changed one refuses the request.
   - A bare IP address is refused: the certificate names the Panel's domain, and the stream
     demultiplexer answers a connection carrying no name from the decoy, so an address has no
     identity to verify.
   - A wrong target, an unverified certificate without confirmation, a bare address, and an
     unreachable API are all rejected before any Worker access or credential transmission.
4. **Worker details** — Worker name, IP, domain, and camouflage domain are prompted. The name is
   read with the same rules as in a deployment plan: trimmed, never blank, and only the characters
   the Panel accepts, so a rejected name costs one question instead of a finished SSH session. The
   question also holds the Panel's own node list: a name the Panel already lists is refused there
   and answered with the address of the node that holds it, because registering it again would
   rewrite that server's address and move its traffic. Only a Panel on this host is read — its API
   token is in this host's credentials file, and a remote Panel's token is not this installer's to
   hold. A remote Panel therefore prints that the name is checked when the node registers, and a
   local Panel whose list cannot be read says so and offers to read it again before the question,
   never treating an unread list as a free name.
5. **Onboarding** — The Worker is registered via the Panel API and provisioned over SSH with
   temporary key authorisation (same process as initial deployment). The registration repeats the
   name check against the live Panel, and a name held by a different address or port is refused
   before any profile, inbound or Host record exists, so a collision that appeared since the
   question costs no rollback.

## The result screen

The install does not announce completion because the Panel started. The Panel step is reported in its
own words (`Panel installed: …`), then every planned Worker is onboarded and the run ends with a
summary that states what the Panel itself holds:

```
=== Node Onboarding Summary ===
  Panel installed: https://panel.example.com
  ams-01: registered and verified in the Panel (uuid 3d5c9a71-6f24-4b8e-9c07-2a1f5e8d4b63)
  fra-01: failed (phase: scan, reason: Could not read the SSH host key of fra-01.)
  Registered and verified in the Panel: 1 of 2.
The Panel and the verified nodes stay as they are. The wizard then offers the failed nodes for a
retry, and one can also be added from the menu (option 3).
```

Each node is one of three states:

- **registered and verified in the Panel** — `node add` succeeded *and* the Panel's own `/api/nodes`
  list, read from this host with this host's token, answered with the same name, address and port, and
  its own uuid. The uuid on the screen is that answer, not a value the installer chose.
- **registered; a Panel on another host cannot confirm it from here** — `node add` succeeded but the
  Panel is remote, so no read-back is possible: its token is not this host's to hold. Nothing was
  disproved, so the node is not a failure and the run keeps its exit status.
- **failed, with the stage and a reason** — the Worker's own failing stage (`prepare_key`, `scan`,
  `fingerprint`, `confirm_fingerprint`, `resolve_ip`, `pin_host_key`, `prepare_password`,
  `authorise`, `start_agent`, `add_node`, `revoke`, `stop_agent`), or the stage `verify` when the Panel
  answered and does not hold what `node add` claimed — either the name is absent
  (`the Panel's node list does not hold this node`) or it is held at another address
  (`the Panel lists it at <address>:<port>`).

The `Registered and verified in the Panel: N of M.` line counts only the first state. The install
exits `0` when every node is verified or unconfirmed, `2` when some nodes were registered and some
failed, and `1` when none was registered; the completion banner is printed only for `0`. The exit codes
are the same as before this screen, so a script that branches on them keeps working.

A `verify` failure is a real failure: the Panel is the authority on what it registered, and a read-back
that contradicts `node add` means the traffic path the operator expects does not exist. A node reported
this way may still need a manual `node rollback` before it is retried.

Registration evidence has a stated limit: it proves the Panel lists the node at that name, address,
port and uuid. It does not prove that a client's traffic crossed that node — `node add` connects the
node's control plane, and the data path is proved by a client request, which the summary does not
attempt.

After a partial failure the wizard offers a retry that names only the failed nodes; a successful
sibling is not offered, and the Panel step is not repeated:

```
Some nodes failed. Select a node to retry, or skip:
  1) fra-01
  2) Skip retry for all failed nodes
Choice: 1
```

Choosing a node prints that node's read-only diagnostics — whether the recovery journal names it,
whether its SSH server answers, and whether the host already holds a managed install — and then asks
`Retry onboarding for fra-01 now? [y/N]: `. Nothing is mutated before that `y`. A confirmed retry
prints `Retrying fra-01...` and reruns the onboarding for that node alone: the Panel step and the
sibling that succeeded are not touched, and the retried node's row in the summary and in the saved
results file is the one that is replaced. The reply is `Retry succeeded: fra-01` followed by a
reprinted summary of the Panel and every node with its state, or `Retry failed: fra-01` with the stage
and reason of the new attempt. Declining answers `Retry declined, fra-01 was not touched.` and returns
to the same list. The list is printed again under the summary after every attempt and holds only the
nodes that still failed, so the numbers always name the node the next answer is about.

A node that neither record answered for is refused before the question is asked: `Refusing to retry
fra-01: neither its recovery journal nor its SSH server answered, so its state cannot be verified
from here.` Its failed attempt may have left the host half-provisioned, and rerunning the onboarding
over that is exactly what the inspection exists to prevent — finish a `node rollback` on it first.
`Skip retry for all failed nodes` prints `Retry skipped.` and leaves everything as it was.

The retry is offered only after a partial run. When every node failed, there is nothing a per-node
retry adds over running the installation again.

Menu option 3 prints its own outcome in the same vocabulary — a node addition that the Panel confirmed,
one it could not confirm, or one that failed at a named stage — and never a Panel installation
statement.

## The exit country of a node

Each traffic node is asked once, after it serves, which country its traffic leaves from:

```
Exit country check: one request from the node itself to https://ipinfo.io/country, which sees the node's address and nothing else.
Exit country of ams-01: 🇳🇱 Netherlands (NL)
Press Enter to confirm, or type a two-letter country code:
```

The request is made by the node, not by the Panel on its behalf: on the local node it leaves through
this host's own outbound route, and on a Worker it runs over the SSH session the temporary key was
already authorised for. That is why the two nodes of one deployment can be offered different
countries even when the Panel is somewhere else entirely. No name, domain, token or password is sent;
the service necessarily sees the node's source address, and that disclosure is the sentence printed
above the question. `GOWAVE_COUNTRY_LOOKUP_URL` moves the request to another service,
`GOWAVE_COUNTRY_LOOKUP_TIMEOUT` (default 5 seconds) bounds it.

Enter accepts the suggestion. A typed ISO 3166-1 alpha-2 code overrides it, in any case: `de` on a
node offered `NL` is accepted as `DE` and shown as `🇩🇪 Germany (DE)`. Only assigned codes are
countries, so `UK`, `EU` or a fragment of prose is refused with `That is not an assigned two-letter
country code; try again.` and the same question is repeated — the answer is never replaced by a
guess. The country is a label for the subscription and nothing else: no routing, firewall rule or
inbound is changed by it.

A lookup that does not answer asks for the code directly (`The country lookup did not answer for
ams-01. Enter the two-letter code of its exit country: `) instead of ending the installation. The
confirmed code is stored in the node entry of `state.json` and carried forward by a later run, so an
install that asks nothing keeps the label the operator already confirmed.

Only the interactive wizard and the add-node menu ask. A positional install — `gowave-auto.sh
install …`, a scripted run, a CI case — neither prompts nor contacts the service, and a Panel-only
host asks nothing because it runs no traffic node of its own; its Workers are asked when they are
onboarded. The plan review names the country as still to come rather than opening SSH to a server
before the operator starts the deployment.

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

## Domain and certificate policy

The preflight counts `C = 2 + v_panel + 2N + k` certificates, where `v_panel` is 1 when the Panel host has
Vision, `N` is the number of Workers, and `k` is the number of Workers with Vision. The 50-per-7-days
Let's Encrypt limit for a registered domain yields four node ceilings:

| Vision placement | Ceiling under one registered domain |
| --- | --- |
| None | 24 nodes |
| Panel host only | 23 nodes |
| Everywhere, Panel-only Panel | 16 nodes |
| Everywhere, Panel and one node on this host | 15 nodes |

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
