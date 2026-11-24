# Design

## Context

- The Panel is registered by this project's own `gowave.service` (`modules/panel.sh:279-342`); the upstream
  `gowave-server service install` is deliberately not invoked (`modules/panel.sh:345-347`).
- The Panel's update endpoint refuses unless `/etc/systemd/system/gowave-update.path` exists
  (`updates.go:225-236,261-263`) and writes its request into `$RUNTIME_DIRECTORY` or `/run/gowave`
  (`updates.go:279-289`), a directory our base unit never declares.
- The upstream helper contract is two units (`serviceunit/install.sh:109-133`): a root oneshot
  `<install-dir>/gowave-server update apply <install-dir>` and a `PathExists=/run/gowave/update-request` trigger.
- `update apply` re-verifies the install layout (`selfupdate.go:183-201`), installs a checksum-verified release,
  runs `gowave-server service install` (`selfupdate.go:124-127`) and restarts `gowave.service`
  (`selfupdate.go:129-131`); it touches no NGINX, Certbot or `.env` content.
- Our install already restarts `gowave.service` immediately after `configure_panel_systemd`
  (`gowave-auto.sh:437-438`), and `uninstall` removes managed units in one list (`cmd_uninstall`,
  `gowave-auto.sh:1336`, lists at `1353-1358`).
- The published dashboard archive is packed with `tar -czf gowave-frontend.tar.gz -C dist .`
  (`sources/gowave/.github/workflows/release.yml:45`), so its root holds the files; upstream installs them into
  `frontend/dist` (`sources/gowave/install.sh:565-575`) and the Panel resolves `./frontend/dist` before `./dist`
  (`server.go:419`).
- `download_panel_release` instead extracts into `frontend/` and creates `dist -> frontend`
  (`modules/panel.sh:203-204`). The upstream service policy refuses any symlink among
  `gowave-server`, `gowave-server.bak`, `frontend`, `dist`, `static` (`serviceunit/install.sh:57-67`), and both
  `install.sh --update` and `update apply` run that policy (`install.sh:680`, `selfupdate.go:124-127`). Measured
  2026-11-17 on a host installed by this project: `install.sh --update --stable` aborted with
  `Refusing a symlinked /opt/gowave/dist` after replacing the binary, before the restart.
- Static unit contracts live in `tests/test_systemd_runner.py::TestSystemdRunner`.

## Goals / Non-Goals

**Goals:**

- The Panel's standard update endpoint works on a host installed by this project, without running any upstream
  script.
- The helper units are authored, enabled, documented and removed by this project (the vendored helper rewrites
  the same two units on each update), and their content is pinned by a test against the upstream template.
- Enabling the helper at installation changes nothing about NGINX, certificates, `.env`, or the Panel's unit
  beyond the new runtime-directory declaration; the first in-panel update later reapplies the upstream sandbox
  drop-in.

**Non-Goals:**

- A `gowave-auto.sh update` subcommand or a project-side journal/snapshot around in-panel updates.
- Invoking the upstream `install.sh` from any script or product path; a manual layout verification on a
  disposable host is allowed.
- Installing the upstream `90-unprivileged.conf` sandbox drop-in ourselves or seeking any other unit-hardening
  parity; the vendored helper still reapplies that drop-in on each in-panel update.
- Changing the upstream `update apply` implementation.

## Decisions

### D0. Install the dashboard into `frontend/dist` and drop the `dist` symlink

`download_panel_release` extracts the archive into a staging directory and renames it to
`<install-dir>/frontend/dist`, replacing any previous `frontend/dist`; it no longer creates `<install-dir>/dist`,
and on a reinstall it removes that path if it is a symlink. The Panel already prefers `./frontend/dist`
(`server.go:419`), so the served dashboard is unchanged while the install layout becomes the one the upstream
policy accepts. Upstream performs the same swap through `frontend/dist.new` (`sources/gowave/install.sh:565-575`).

The existing test fixture packs the dashboard as `dist/` inside the tar
(`tests/test_panel_deployment.py:323-329`), so its current `frontend/dist/index.html` assertion also passes under
the old symlinked layout; the fixture must be repacked at the archive root before that assertion can discriminate.

*Alternatives:* (a) keep the symlink and stop calling the upstream helper — rejected: it makes the native
`--update` path abort mid-update on every host this project installs, and that path is a product requirement;
(b) point `dist` at a real directory copy — rejected: duplicates the dashboard and leaves two roots to keep in
sync; (c) extract into `frontend/` and move the files into `frontend/dist` — rejected: the staging rename is the
same operation with one failure window instead of two.

### D1. Author the two helper units in `configure_panel_systemd`

The installer writes `/etc/systemd/system/gowave-update.service` and `gowave-update.path` from its own templates
and enables and starts the path unit; it does not call `gowave-server service install`. The templates mirror
`sources/gowave/backend-go/internal/serviceunit/install.sh:109-133` (`After=network-online.target`,
`Wants=network-online.target`, `TimeoutStartSec=15min`, `WantedBy=multi-user.target`), so the `service install`
that `update apply` runs rewrites them with identical content.

*Alternatives:* (a) call `service install` at installation time and accept its output — rejected: it reintroduces
the second unit-generation path the project already refuses (`modules/panel.sh:345-347`) and would hand the
Panel's drop-in set to upstream at install; the in-panel helper still runs that command on every update, which D4
records as an upstream property rather than a project decision; (b) run the upstream `install.sh --update` once —
rejected: floating `main` script, and its only added value is exactly these units.

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

The helper is the upstream `update apply`, which also runs `gowave-server service install` before the restart
(`selfupdate.go:124-127`): the first in-panel update creates `gowave.service.d/90-unprivileged.conf` and rewrites
both helper units. This change accepts that as the upstream contract; it does not install the drop-in itself and
does not pin post-update unit content beyond keeping `RuntimeDirectory=gowave`.

*Alternatives:* wrapping the helper in a hardened unit — plausible later, but it would need write access to the
install directory and the unit manager, and it belongs to the separate hardening-parity decision.

### D5. Uninstall owns the helper like the other managed units

Both units join the existing stop/disable/remove lists (`gowave-auto.sh:1353-1358`), still with a single
`daemon-reload`. Nothing else changes on uninstall: `/opt/gowave` and the database stay, as today.

### D6. Tests pin the contract statically

`TestSystemdRunner` gains assertions on the emitted unit fragments (`RuntimeDirectory=gowave`,
`ExecStart=<install-dir>/gowave-server update apply`, `PathExists=/run/gowave/update-request`), on the path unit
being enabled, on the start line following the Panel restart in `cmd_install`, on the uninstall stop/disable/
removal lists, and on the absence of a `gowave-server service install` invocation.
Adding methods to an existing class keeps the suite registry unchanged.

## Risks / Trade-offs

- **The unprivileged Panel can trigger a root code replacement** → the request carries only a channel, the release
  must match `SHA256SUMS`, and `trustedExecutable` refuses a binary that is not root-owned or is
  group/other-writable, and an install directory that is not root-owned or is group/other-writable without the
  sticky bit.
- **An in-panel update is not journaled by this project** → the operation is confined to Panel code, the upstream
  service policy and the helper units, and restarts one service; the project's snapshots remain the mechanism for
  `channel`, `domain-change`, `backup` and `restore`. Design states this explicitly so nobody later reads a UI
  update as transaction-protected.
- **Existing hosts gain the helper only on reinstall** → until then the endpoint keeps answering 409; there is no
  half-configured state where the helper exists without the runtime directory.
- **The layout fix also runs on reinstall** → the same reinstall removes the legacy `dist` symlink, so a host that
  was left mid-update by the upstream command (new binary and `frontend/dist` in place, process still old, symlink
  still present) becomes consistent without a second operation.
- **The helper rewrites the unit names on the first update** → `update apply` runs `service install`, which writes
  the same two units with the same contract (D1 mirrors them); our uninstall still removes them, so ownership does
  not silently move, and the vendor's drop-in keeps `RuntimeDirectory=gowave`.
- **Restarting the panel to pick up `RuntimeDirectory`** → the install already restarts it in the same step, so no
  extra interruption is introduced.

## Migration Plan

1. Re-run `gowave-auto.sh install` on an installed host: the dashboard moves to `frontend/dist`, the legacy
   `dist` symlink is removed, the unit gains the runtime-directory directives, the two helper units appear and the
   path unit is started after the panel restart.
2. Verify: `ls -l /opt/gowave/dist` reports "No such file or directory", `ls /opt/gowave/frontend/dist/index.html`
   exists, `systemctl status gowave-update.path`, `ls -ld /run/gowave`, and `POST /api/system/updates/apply` no
   longer returns the "helper is not installed" refusal.
3. Rollback: remove the two unit files, drop the three `RuntimeDirectory*` lines, `daemon-reload`, restart
   `gowave.service`. The Panel returns to the current 409 behaviour with no data change; the layout change is not
   rolled back, because the previous symlinked layout is what the upstream policy rejects.
