# Design

## Context

`gowave-auto.sh install` takes `<panel> <reality> <email> [vision]`, prompts only for arguments it was not
given (`gowave-auto.sh:202-226`), and unconditionally installs a local node at `:446`. The certificate step
issues one lineage per host role (`:372`, `:389`, `:399`; worker equivalent at
`gowave-node-auto.sh:2456-2481`), so a host spends two or three certificates, never one. The `:443` stream map is
a fixed literal (`modules/nginx.sh:192-250`): panel → 7443, reality → 8443, vision → 8444, cover → 9443, and
`default` → 8443. The decoy vhost terminates on 9443 with the camouflage lineage
(`modules/nginx.sh:501-541`). `modules/api_client.py:651` returns the internal squad identifier, `:697` puts it
into every host record, and `gowave-auto.sh:846` ignores that return and reads `squadUuid` from `state.json`.

Two SSH layers exist and must not be conflated: the product onboards a worker with a pre-pinned host key and
`BatchMode=yes` (`gowave-auto.sh:726-734`, `gowave-node-auto.sh:3086`), while password bootstrap lives only in the
live operator (`tools/live_vps/operator.py:129-380`). The container suite drives the product positionally with no
TTY (`tools/podman_e2e/topology.py:1026-1031`) and pins one distribution for both hosts
(`tools/podman_e2e/multi_node.py:857-869`).

See `proposal.md` for motivation and `specs/` for the required behaviour.

## Goals / Non-Goals

**Goals:**

- One guided entry point that ends by running the same commands the product already runs, so a wizard install and
  a positional install produce the same host.
- A Panel-only host that is a supported product mode rather than a hand-edited configuration, with no listener
  pointing at an absent traffic plane.
- A certificate plan the operator can see before the first ACME order, with the domain policy stated as arithmetic.
- Worker onboarding that works from the Panel host alone, keeps the product stdlib-only, and is drivable by an
  acceptance run without a terminal.

**Non-Goals:**

- Translating anything except the wizard. `status`, `health`, `node`, `update`, and all error text stay English.
- Creating DNS records. The wizard validates that names resolve; it never calls a registrar or a DNS API.
- DNS-01 and wildcard certificates. They are analysed below and rejected for this change, not deferred silently.
- Cross-OS Panel/worker combinations. The OS gate stays as it is (`modules/os.sh:46-78`); combinations are recorded
  as unverified.
- Converting an existing All-in-One host into a Panel-only one. Mode is chosen at install time.

## Decisions

### D1 — The wizard is a surface over the existing commands, in two new modules

`modules/wizard.sh` holds the conversation and the plan; `modules/i18n.sh` holds the message catalog and a `t`
lookup. `cmd_install` keeps its argument contract, gains an explicit mode, and calls the wizard only when it has
no arguments and a terminal. Alternatives rejected: a separate `setup.sh` (a second entry point that must
re-acquire the mutation lock and re-implement journaling) and a Python TUI (a dependency and a second language
runtime for a script whose whole value is being auditable bash).

### D2 — Mode is a flag, not a subcommand

The non-interactive contract becomes `install [--panel-only] <panel-or-worker-name> <camouflage-name> <email>`,
with the positional meaning of the second argument unchanged (it has always been the camouflage name; the code
calls it `reality_domain`). `--mode all-in-one|panel-only` is accepted as the explicit spelling. The wizard sets
the same flag. Alternatives rejected: `install-panel` (a second install path to keep in step with every future
change) and overloading the email position (an argument whose meaning depends on another argument is how the
current positional contract already confuses operators).

### D3 — Panel-only routing sends the default to the decoy, not to a dead port

`generate_stream_config` takes the mode: in Panel-only it emits the panel entry and the cover entries and sets
`default 127.0.0.1:9443`; no 8443 or 8444 entry and no listener on those ports exists. Alternatives rejected:
keeping `default` at 8443 (a client with an unknown SNI would open TCP to a closed port and hang instead of
seeing the website the camouflage story promises) and mapping the camouflage name only (unknown names would leak
the difference between "domain we own" and "domain we do not"). Trade-off accepted: a typo'd client domain gets a
website rather than a failure, which is exactly what a REALITY decoy is for.

### D4 — Panel-only install order and what it does not provision

Bootstrap ACME vhost → two lineages (panel, camouflage; no Vision lineage exists without Xray) → stream and decoy
configuration → Panel install and health → credentials → API: admin, token, default user. The install stops
there: no config profile, no inbound, no host record, no internal squad, because none of them can reference an
inbound that does not exist yet. The first `node add` creates the profile, the inbounds, the squad, and the host
records for that node. Alternatives rejected: creating an empty profile at install (the Panel UI shows a profile
with no inbounds and the operator cannot tell whether that is intended) and creating the squad with an empty
inbound list (an allow-only squad that allows nothing, which silently drops subscription delivery instead of
failing).

### D5 — The squad identifier comes from the call that provisions it

`node add` becomes `squad_uuid = client.provision_internal_squad(...)`, persists the result into `state.json`,
and passes it to `provision_hosts`. If the value is empty, the command aborts before `provision_hosts` and runs
its compensating rollback, so a null squad is a failure rather than a silently accepted host record.
Alternatives rejected: `state_data.get("squadUuid") or provisioned` (two sources of truth that disagree exactly
when the state is stale, which is the panel-only case that produced the defect).

### D6 — Temporary access is ported into the product, driven by files and env, never argv

`modules/ssh_bootstrap.sh` mirrors `tools/live_vps/operator.py`: exact SHA-256 string comparison of the presented
fingerprint against what the operator typed in full, `read -rsp` for the password, an Ed25519 key in a `0700`
directory, a `authorized_keys` entry installed atomically, a systemd timer that removes it within two hours,
`node add` while the access exists, then removal of the entry, the timer, and the key on both success and failure.
Systemd is a hard requirement for that step: if the timer cannot be installed, onboarding aborts before the key
is authorised. Alternatives rejected: paramiko (a dependency the project excludes), `sshpass` (leaks the password
through argv and needs a package), an unguarded key (a credential with no expiry is exactly what the live
operator's design exists to avoid).

Acceptance runs cannot type a fingerprint, so the same module reads two optional inputs: `GOWAVE_SSH_FINGERPRINT`
(the exact expected string) and `GOWAVE_SSH_PASSWORD_FILE` (mode `0600`, read once, unset after use). Both are
environment variables; neither is ever an argument. Without them the module prompts. This is the only new
non-interactive secret surface in the change and it is documented in `README.md` and `docs/`.

### D7 — Language is per invocation and never persisted

`GOWAVE_WIZARD_LANG=ru|en` selects the catalog; the wizard asks when unset and a terminal exists, and defaults to
English otherwise. The choice is not written to `state.json`: a language is not installation state, and persisting
it would make the next operator's session silently Russian. Both catalogs must have identical key sets, enforced
by a unit test rather than by discipline.

### D8 — The certificate preflight is arithmetic plus a DNS check, and nothing else

`C = 2 + v_panel + 2N + k` follows from one lineage per role per host; the ceiling comes from Let's Encrypt's
"50 certificates per registered domain every 7 days", which is global across accounts and refills one certificate
every 202 minutes. Ceilings are 24 (no Vision), 23 (Vision on the Panel host only), 16 (Vision on every node of a
Panel-only plan), 15 (Vision on the Panel host and every node). The preflight also enforces cluster-wide name
uniqueness, which the product does not have today, and resolves every name before the first ACME order.

Recommendation is one registered domain per host, because that gives each host its own 50-per-7-days budget. A
shared domain is allowed within the ceiling with an explicit warning that the budget is shared with anything else
on that domain (mail, a website, other tooling).

Whole-cluster-on-one-domain is technically sound — every host owns its own `:443`, its own certificate, and its
own SNI map, and client links carry names rather than addresses — but three caveats belong in the design record:

1. The apex and `www` camouflage certificate can only belong to one host. `cover_domain_for`
   (`modules/nginx.sh:83-107`) disables the cover silently on every other host, so the rest of the cluster has a
   decoy at its own subdomain and no apex website.
2. The budget is shared globally, as above.
3. Wildcard certificates are not the escape hatch. Every host would order the identical identifier set
   `[domain, *.domain]`, and the "5 certificates per exact set of identifiers every 7 days" limit has no override,
   so wildcard on a shared domain would cap a cluster at about five hosts per week instead of 24. Wildcard also
   requires DNS-01, which needs a DNS plugin and an API token on every host. It is only rational when each node
   already has its own registered domain.

### D9 — Acceptance drives the flag, not the wizard

The Podman suite gains `--topology panel-only` as a third value alongside `aio` and `multi-node`; its install
script emits the same command an operator would, with the flag and no TTY. Multi-node stays the 2.3 drive and
gains a squad assertion. The live runner gains `INSTALL_MODE` so a disposable Master can prove the Panel-only
mode. Sequencing is deliberate: the container contour proves the mode and the squad fix first, and the live
contour follows in the same change only after that evidence exists. The four-distribution invariant
(`tests/test_podman_docs.py:979`) and the one-distribution-per-run rule are unchanged.

## Risks / Trade-offs

- **Shared-domain budget is unreadable** → the preflight can only count its own plan; it states the limit and
  refuses above the ceiling, and the operator is told the remaining budget cannot be queried. Never claim a
  remaining budget.
- **A failed install after issuance consumes budget, and rollback deletes the lineage** → re-installation is
  free while the certificate is alive (`--keep-until-expiring`), so the cost is limited to genuinely failed runs;
  the five-per-identifier-set limit still caps retries per host at five per week.
- **Cross-OS combinations unverified** → recorded as unverified in `tasks.md` and never claimed as working. The
  OS gate stays as is; Ubuntu 22.04 remains rejected (`tests/test_os_detection.py:39-47`).
- **`update`/`uninstall` on a Panel-only host** → both must tolerate a missing local node; `state.json` gains an
  optional mode field and a `schemaVersion` that does not change, so an older state is read as All-in-One.
- **Temporary-access onboarding needs systemd on the node** → abort before authorising the key when the timer
  cannot be installed, rather than leaving a key without an expiry.
- **i18n drift** → a test asserts identical key sets and that no wizard message is a bare literal.
- **A wizard prompt reaching a container run hangs the suite** → `install` with no arguments and no terminal exits
  non-zero with usage; a readiness test refuses TTY-dependent code in the acceptance path
  (`tests/test_podman_readiness.py:71-74` already refuses `input()` in tests).

## Migration Plan

1. Land the mode flag and Panel-only routing with the squad fix; All-in-One behaviour is unchanged and existing
   installations read as All-in-One because the mode field is optional.
2. Land the wizard over the same code path; positional and container drives keep working.
3. Land the container topology and cases; then the live `INSTALL_MODE` drive.
4. Rollback is a code revert: Panel-only hosts keep valid certificates and a serving Panel, and only the absent
   traffic plane distinguishes them. No data migration, no state rewrite, no ACME lineage deletion.

## Open Questions

None that change the specs. The Russian catalog wording can be refined during implementation without touching a
requirement, and the exact `GOWAVE_SSH_*` variable names can be renamed as long as they stay environment
variables and the zero-leak rule holds.
