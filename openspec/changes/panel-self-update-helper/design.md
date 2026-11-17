# Design

## Context

- The Panel is registered by this project's own `gowave.service` (`modules/panel.sh:281-342`); the upstream
  `gowave-server service install` is deliberately not invoked (`modules/panel.sh:345-347`).
- The Panel's update endpoint refuses unless `/etc/systemd/system/gowave-update.path` exists
  (`updates.go:226-236`) and writes its request into `$RUNTIME_DIRECTORY` or `/run/gowave`
  (`updates.go:279-289`), a directory our base unit never declares.
- The upstream helper contract is two units (`serviceunit/install.sh:107-133`): a root oneshot
  `<install-dir>/gowave-server update apply <install-dir>` and a `PathExists=/run/gowave/update-request` trigger.
- `update apply` re-verifies the install layout (`selfupdate.go:183-201`), installs a checksum-verified release
  and runs `systemctl restart gowave.service` (`selfupdate.go:129`); it touches no NGINX, Certbot or `.env`.
- Our install already restarts `gowave.service` immediately after `configure_panel_systemd`
  (`gowave-auto.sh:435-439`), and `uninstall` removes managed units in one list (`gowave-auto.sh:1327-1333`).
- Static unit contracts live in `tests/test_systemd_runner.py::TestSystemdRunner`.

## Goals / Non-Goals

**Goals:**

- The Panel's standard update endpoint works on a host installed by this project, without running any upstream
  script.
- The helper units are authored, enabled, documented and removed by this project, and their content is pinned by
  a test.
- Enabling the helper changes nothing about NGINX, certificates, `.env`, or the Panel's unit beyond the new
  runtime-directory declaration.

**Non-Goals:**

- A `gowave-auto.sh update` subcommand or a project-side journal/snapshot around in-panel updates.
- Executing the upstream `install.sh` at any point.
- The upstream `90-unprivileged.conf` sandbox drop-in or any other unit-hardening parity.
- Changing the upstream `update apply` implementation.

## Decisions

### D1. Author the two helper units in `configure_panel_systemd`

The installer writes `/etc/systemd/system/gowave-update.service` and `gowave-update.path` from its own templates
and enables the path unit; it does not call `gowave-server service install`.

*Alternatives:* (a) call `service install` and accept its output — rejected: it rewrites the managed unit's
drop-in set (`90-unprivileged.conf`), a second unit-generation path the project already refuses
(`modules/panel.sh:345-347`); (b) run the upstream `install.sh --update` once — rejected: floating `main`
script, and its only added value is exactly these units.

### D2. `RuntimeDirectory=gowave` in the base unit

`RuntimeDirectory=gowave`, `RuntimeDirectoryMode=0700`, `RuntimeDirectoryPreserve=yes` are added to our unit
template so systemd creates the directory with the service account's ownership at every start and keeps it
across restarts.

*Alternatives:* (a) `tmpfiles.d` — adds a file outside the unit lifecycle that would survive the unit's removal
and would need its own uninstall entry; (b) `install -d` in `ExecStartPre` — an extra root command to keep
correct after reboot, while systemd already owns this mechanism.

### D3. The path unit is started after the Panel restart

`configure_panel_systemd` only *enables* `gowave-update.path`; the install step starts it right after the
existing `systemctl restart gowave.service`, i.e. after `/run/gowave` exists. This avoids depending on how a
`PathExists` watch behaves while the watched directory is still missing.

*Alternatives:* `enable --now` inside `configure_panel_systemd` — arms the watch before the directory exists on a
fresh install; correct order beats relying on watch re-evaluation.

### D4. The helper runs as root without a sandbox of its own

`gowave-update.service` has no `User=` and no `ProtectSystem=`; it must write the root-owned install directory and
restart a system unit. The request it accepts names only a channel, and the installed release must pass
`SHA256SUMS`, so the escalation is "replace Panel code with a verified release", not "run an arbitrary command".

*Alternatives:* wrapping the helper in a hardened unit — plausible later, but it would need write access to the
install directory and the unit manager, and it belongs to the separate hardening-parity decision.

### D5. Uninstall owns the helper like the other managed units

Both units join the existing stop/disable/remove lists (`gowave-auto.sh:1327-1333`), still with a single
`daemon-reload`. Nothing else changes on uninstall: `/opt/gowave` and the database stay, as today.

### D6. Tests pin the contract statically

`TestSystemdRunner` gains assertions on the emitted unit fragments (`RuntimeDirectory=gowave`,
`ExecStart=<install-dir>/gowave-server update apply`, `PathExists=/run/gowave/update-request`), on the path unit
being enabled, on the uninstall removal list, and on the absence of a `gowave-server service install` invocation.
Adding methods to an existing class keeps the suite registry unchanged.

## Risks / Trade-offs

- **The unprivileged Panel can trigger a root code replacement** → the request carries only a channel, the release
  must match `SHA256SUMS`, and `trustedExecutable` refuses a non-root-owned binary or a non-sticky install
  directory.
- **An in-panel update is not journaled by this project** → the operation is confined to Panel code and restarts
  one unit; the project's snapshots remain the mechanism for `channel`, `domain-change`, `backup` and `restore`.
  Design states this explicitly so nobody later reads a UI update as transaction-protected.
- **Existing hosts gain the helper only on reinstall** → until then the endpoint keeps answering 409; there is no
  half-configured state where the helper exists without the runtime directory.
- **Name collision if the operator ever runs the upstream installer on this host** → upstream writes the same two
  unit names with the same contract; our uninstall still removes them, so ownership does not silently move.
- **Restarting the panel to pick up `RuntimeDirectory`** → the install already restarts it in the same step, so no
  extra interruption is introduced.

## Migration Plan

1. Re-run `gowave-auto.sh install` on an installed host: the unit gains the runtime-directory directives, the two
   helper units appear and the path unit is started after the panel restart.
2. Verify: `systemctl status gowave-update.path`, `ls -ld /run/gowave`, and `POST /api/system/system/update`
   no longer returns the "helper is not installed" refusal.
3. Rollback: remove the two unit files, drop the three `RuntimeDirectory*` lines, `daemon-reload`, restart
   `gowave.service`. The Panel returns to the current 409 behaviour with no data change.
