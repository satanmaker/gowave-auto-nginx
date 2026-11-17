# Spec Delta

## ADDED Requirements

### Requirement: Project-owned in-panel update helper

The installer SHALL provision the Panel's root-side update helper itself instead of relying on the upstream
`gowave-server service install`: the base unit SHALL declare `RuntimeDirectory=gowave` (mode `0700`, preserved),
and the installer SHALL write, enable and own `gowave-update.service` and `gowave-update.path`.

#### Scenario: Fresh installation enables the Panel update endpoint

- **GIVEN** a clean supported host and a completed `gowave-auto.sh install`
- **WHEN** the Panel calls `POST /api/system/update`
- **THEN** `gowave.service` carries `RuntimeDirectory=gowave`, `/run/gowave` exists with mode `0700` owned by the
  service account, `/etc/systemd/system/gowave-update.path` and `/etc/systemd/system/gowave-update.service` exist,
  `gowave-update.path` is enabled, and the request is accepted instead of answered with the "update helper is not
  installed" refusal

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
- **THEN** both unit files are rewritten to the same content, `gowave-update.path` stays enabled, and the
  already-provisioned `/run/gowave` state does not cause a failure

### Requirement: In-panel update is confined to Panel code

The helper SHALL run as a root oneshot that replaces only the Panel binary and frontend from a
checksum-verified release and restarts `gowave.service`; it MUST NOT change the managed unit, `.env`, NGINX,
Certbot material or other managed services.

#### Scenario: Update request replaces Panel code only

- **GIVEN** the Panel writes `/run/gowave/update-request` naming a channel
- **WHEN** `gowave-update.path` starts `gowave-update.service`
- **THEN** the helper verifies `SHA256SUMS` before installing, replaces the binary and frontend, restarts only
  `gowave.service`, and leaves `/etc/nginx`, the managed Certbot deploy hook, `/opt/gowave/.env` and the unit
  files byte-identical

#### Scenario: Untrusted install layout is refused

- **GIVEN** the running binary is not `<install-dir>/gowave-server`, or the binary is writable by a non-root user,
  or the install directory is not root-owned without the sticky bit
- **WHEN** the helper starts
- **THEN** it refuses to update and reports the refusal through the update status file instead of replacing code

#### Scenario: Failed download leaves the running Panel untouched

- **GIVEN** the release download fails or the checksums do not match
- **WHEN** the helper runs
- **THEN** the installed binary and frontend remain unchanged, `gowave.service` keeps serving the running code,
  and the failure is reported to the Panel rather than recorded as a successful update
