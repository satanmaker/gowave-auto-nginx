# Spec Delta

## ADDED Requirements

### Requirement: Installation layout accepted by the Panel updater

The installer SHALL place the Panel dashboard at `<install-dir>/frontend/dist` and MUST NOT leave a symlink at
`<install-dir>/dist`, so that the layout check performed by either update path accepts the installation.

#### Scenario: Fresh installation uses the updater's layout

- **GIVEN** a clean supported host
- **WHEN** `gowave-auto.sh install` completes
- **THEN** `<install-dir>/frontend/dist/index.html` exists, `<install-dir>/dist` does not exist, and neither
  `<install-dir>/frontend` nor `<install-dir>/dist` is a symlink

#### Scenario: Reinstall removes the legacy dashboard symlink

- **GIVEN** a host installed by an earlier version where `<install-dir>/dist` is a symlink to `frontend`
- **WHEN** `gowave-auto.sh install` runs again
- **THEN** the symlink is removed, the dashboard is served from `frontend/dist`, and no file outside
  `frontend/dist` and the legacy `dist` symlink is removed

#### Scenario: An updater's layout check accepts the installation

- **GIVEN** an installed host
- **WHEN** a Panel updater validates the install layout before replacing code, whether that is the upstream
  service policy or `update apply`
- **THEN** the check passes instead of refusing a symlinked install entry

### Requirement: Project-owned in-panel update helper

The installer SHALL provision the Panel's root-side update helper itself at installation time instead of calling
the upstream `gowave-server service install`: the base unit SHALL declare `RuntimeDirectory=gowave` (mode `0700`,
preserved), and the installer SHALL write and own `gowave-update.service` and `gowave-update.path` and enable and
start the path unit.

#### Scenario: Fresh installation enables the Panel update endpoint

- **GIVEN** a clean supported host and a completed `gowave-auto.sh install`
- **WHEN** the Panel calls `POST /api/system/updates/apply`
- **THEN** `gowave.service` carries `RuntimeDirectory=gowave`, `/run/gowave` exists with mode `0700` owned by the
  service account, `/etc/systemd/system/gowave-update.path` and `/etc/systemd/system/gowave-update.service` exist,
  `gowave-update.path` is enabled and active, and the request is accepted instead of answered with the "update
  helper is not installed" refusal

#### Scenario: Helper units are authored by this project, not by the upstream service command

- **GIVEN** a completed installation
- **WHEN** the emitted units and the installer source are inspected
- **THEN** both helper unit files are written from this project's templates, no `gowave-server service install`
  invocation exists in `modules/panel.sh`, and no `gowave.service.d/90-unprivileged.conf` is created by the
  installation

#### Scenario: Uninstallation removes the helper with the other managed units

- **GIVEN** an installed host whose update helper was provisioned by this project
- **WHEN** `gowave-auto.sh uninstall` runs
- **THEN** `gowave-update.path` and `gowave-update.service` are stopped if active, disabled and removed together
  with the managed Panel and recovery units, followed by a single `systemctl daemon-reload`

#### Scenario: Repeated installation is idempotent for the helper

- **GIVEN** a host whose Panel is already running and whose helper units exist
- **WHEN** `gowave-auto.sh install` runs again
- **THEN** both unit files are rewritten to the same content, `gowave-update.path` stays enabled and active, and
  the already-provisioned `/run/gowave` state does not cause a failure

### Requirement: In-panel update is confined to Panel code

The helper SHALL install a checksum-verified release of the requested channel: it replaces the Panel binary and
`frontend/dist`, reapplies the upstream service policy and restarts `gowave.service`. It MUST NOT change
`/opt/gowave/.env` content, NGINX, Certbot material, the Panel database or other managed services. This pins the
vendored upstream `gowave-server update apply`.

#### Scenario: Update request replaces Panel code only

- **GIVEN** the Panel writes `/run/gowave/update-request` naming a channel
- **WHEN** `gowave-update.path` starts `gowave-update.service`
- **THEN** the helper verifies `SHA256SUMS` before installing, replaces the binary and `frontend/dist`, reapplies
  the upstream service policy (`90-unprivileged.conf` and both helper units), restarts only `gowave.service`, and
  leaves the content of `/opt/gowave/.env`, `/etc/nginx`, the managed Certbot deploy hook and the recovery journal
  unchanged; `gowave.service` keeps `RuntimeDirectory=gowave` after the policy is reapplied

#### Scenario: Untrusted install layout is refused

- **GIVEN** the running binary is not `<install-dir>/gowave-server`, or the binary is not root-owned or is
  group/other-writable, or the install directory is not root-owned or is group/other-writable without the sticky
  bit
- **WHEN** the helper starts
- **THEN** it refuses to update and reports the refusal through `/run/gowave/update-status.json` instead of
  replacing code

#### Scenario: Failed download leaves the running Panel untouched

- **GIVEN** the release download fails or the checksums do not match
- **WHEN** the helper runs
- **THEN** the installed binary and frontend remain unchanged, `gowave.service` keeps serving the running code,
  and the failure is reported to the Panel rather than recorded as a successful update
