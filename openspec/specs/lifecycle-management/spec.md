# Lifecycle Management Specification

## Purpose

Defines how the GoWave Auto NGINX lifecycle manager behaves for operators: its CLI and interactive surface, exclusive mutation locking, external proxy ownership, channel switching, transaction-safe updates with crash recovery, atomic reconfiguration, targeted uninstallation, and ACME endpoint selection with certificate lineage isolation.

## Requirements

### Requirement: Explicit ACME Endpoint Selection and Certificate Lineage Isolation

The installer and distributed orchestrator SHALL accept `GOWAVE_ACME_SERVER` (defaulting to Let's Encrypt
production when unset) restricted to official Let's Encrypt staging and production directory URLs. The runner
SHALL map `ACME_MODE` to the matching URL, propagate it over SSH stdin to Worker, and prevent cross-lineage
staging and production reuse.

#### Scenario: Runner maps ACME mode to the official staging directory

- **GIVEN** E2E config has `ACME_MODE=staging`
- **WHEN** the runner invokes Master installation and subsequent `node add`
- **THEN** it passes exactly `https://acme-staging-v02.api.letsencrypt.org/directory` as `GOWAVE_ACME_SERVER`; for `ACME_MODE=production` it passes exactly `https://acme-v02.api.letsencrypt.org/directory`; no arbitrary URL is accepted

#### Scenario: Staging certificate issued on a clean disposable Master

- **GIVEN** `GOWAVE_ACME_SERVER=https://acme-staging-v02.api.letsencrypt.org/directory` and a clean disposable Master
- **WHEN** `gowave-auto.sh install` provisions the Panel and REALITY certificates
- **THEN** every Certbot issuance call uses the staging directory; the resulting certificate chain is staging-issued; no production ACME endpoint is contacted

#### Scenario: Master installer TLS probe uses scoped staging trust

- **GIVEN** the Master receives a staging-issued Panel certificate and the runner has built the D9 mode-specific CA bundle
- **WHEN** `gowave-auto.sh install` invokes `verify_public_tls_sni`
- **THEN** the runner supplies the bundle through `GOWAVE_TLS_CA_FILE`, the probe uses `-CAfile` with hostname and chain verification, and the staging certificate passes without installing Staging roots into system trust; an untrusted test certificate still fails. The same optional override applies to `domain-change`; with no override, legacy `-CApath` behavior is unchanged.

#### Scenario: Staging parameter propagated to Worker

- **GIVEN** the Master installation uses the staging directory
- **WHEN** `gowave-auto.sh node add` invokes the remote Worker deployment
- **THEN** the exact ACME directory URL is serialized through SSH stdin and every Worker Certbot issuance call uses that URL

#### Scenario: Vision certificates use the selected ACME directory on both hosts

- **GIVEN** both `MASTER_VISION_DOMAIN` and `WORKER_VISION_DOMAIN` are configured
- **WHEN** Master and Worker certificates are issued
- **THEN** Master and Worker each issue and verify a third Vision certificate using the same selected ACME directory as their two mandatory certificates; before Worker issuance, its HTTP-01 bootstrap vhost includes `WORKER_VISION_DOMAIN` in `server_name`; each Vision renewal lineage MUST match that directory

#### Scenario: Vision certificate failure is not silently ignored

- **GIVEN** the paired Vision domains are configured but Certbot issuance or certificate validation fails on either VPS
- **WHEN** the corresponding installation phase runs
- **THEN** that host's installation fails and rolls back; on Worker, the HTTP-01 bootstrap vhost must have included the Vision name before issuance, and rollback must remove any transaction-created Vision certificate/renewal lineage, stream-map entry, 9444 fallback vhost and generated profile/host state. It MUST preserve pre-existing/unowned lineages and unrelated resources. Deployment MUST NOT proceed with a profile or NGINX route advertising an unusable Vision inbound

#### Scenario: Master and Worker Vision domains are independently optional

- **GIVEN** either, both, or neither of `MASTER_VISION_DOMAIN` and `WORKER_VISION_DOMAIN` is configured
- **WHEN** the runner validates its configuration and invokes the corresponding Master/Worker install paths
- **THEN** preflight accepts each valid independently configured domain
- **AND** only the host with a configured Vision domain provisions its Vision certificate, inbound, Panel host, NGINX route, and fallback
- **AND** an unset Vision domain does not block installation on the other host
- **AND** no Vision artifacts are created on a host whose Vision domain is unset

#### Scenario: Missing or unknown renewal directory fails closed

- **GIVEN** an existing Certbot lineage has no readable `server` field or an unrecognized ACME directory URL
- **WHEN** installation checks whether that lineage can be reused
- **THEN** the installer MUST NOT infer the directory from the generic Let's Encrypt issuer; it fails closed or
  provisions a separately named lineage with all consumers and renewal hooks migrated atomically

#### Scenario: Existing certificate is reused only for the same ACME directory

- **GIVEN** a valid certificate lineage exists for the requested domain
- **WHEN** installation is repeated with the same ACME directory URL
- **THEN** Certbot may reuse the lineage without unnecessary issuance, after validating its renewal configuration and certificate SAN/expiry

#### Scenario: Failed transaction preserves pre-existing certificate lineages

- **GIVEN** a requested-domain certificate lineage existed before installation and is valid for the selected ACME directory
- **WHEN** a later Master or Worker provisioning step fails and compensation runs
- **THEN** rollback MUST NOT delete the pre-existing lineage; if Certbot changed it, restore and verify its certificate, private key, renewal configuration, live symlink targets, ownership and modes from the same-host snapshot under `/var/lib/gowave-auto-nginx/recovery/<transaction-id>/acme/<domain>/` (root-owned `0700` directories, root-owned `0600` private-key files). Snapshots MUST NOT be copied to runner/CI artifacts or logs. Only lineages proven to have been absent before the failed transaction may be deleted. Remove snapshots only after verified commit/rollback; retain them and report incomplete recovery if restoration fails. If safe restoration cannot be guaranteed, the install MUST fail before issuance or report cleanup incomplete rather than claim rollback success.

#### Scenario: ACME directory changes between staging and production

- **GIVEN** the domain has a certificate lineage issued by the other ACME directory
- **WHEN** the operator changes `GOWAVE_ACME_SERVER`
- **THEN** the installer MUST NOT treat the old lineage as a valid reusable certificate; it MUST require a fresh disposable baseline or create a separately named lineage and atomically update all consumers; it MUST never mix staging and production certificates

#### Scenario: Existing NGINX certificate path contract is preserved

- **GIVEN** Master or Worker has NGINX consumers referencing `/etc/letsencrypt/live/<domain>/`
- **WHEN** a staging or production lineage is issued or migrated
- **THEN** every consumer continues to resolve the expected certificate and private-key paths; any isolated
  lineage migration updates all consumers and renewal hooks atomically before reload, or fails without
  replacing the active certificate

#### Scenario: Existing global deploy hook is not overwritten or removed

- **GIVEN** Master or Worker already contains
  `/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh` from another workflow
- **WHEN** GoWave installation checks its ACME hook prerequisites or rollback executes
- **THEN** installation fails before replacing the existing hook; rollback never deletes it, including when it is a symlink or non-regular object. A hook created by the current transaction is recorded with host-local ownership metadata and may be removed only if its current identity and digest still match that transaction

#### Scenario: ACME parameter is unset

- **GIVEN** `GOWAVE_ACME_SERVER` is unset
- **WHEN** the existing installer is run
- **THEN** the production endpoint and existing certificate behavior remain backward-compatible

### Requirement: The unified menu can add nodes to an existing Panel

The interactive entrypoint SHALL offer adding remote nodes to an existing Panel without requiring a new Panel installation, and SHALL verify the selected Panel/API before collecting or applying node changes. For a Panel that is not on the local host, it SHALL use HTTPS with certificate validation or an explicitly confirmed certificate fingerprint, and SHALL send credentials only after that identity check has passed.

#### Scenario: A local Panel is detected

- **GIVEN** a local GoWave Panel is installed and its API is available
- **WHEN** the operator chooses to add nodes
- **THEN** the flow identifies the local Panel, confirms the target, and proceeds to node planning

#### Scenario: No local Panel or multiple candidates are found

- **GIVEN** no usable local Panel is detected or the target is ambiguous
- **WHEN** the operator chooses to add nodes
- **THEN** the flow asks for the Panel address, verifies connectivity and API identity over the verified channel, and proceeds only after the target is confirmed

#### Scenario: The selected Panel cannot be verified

- **GIVEN** the entered Panel address does not answer the expected API check
- **WHEN** target validation runs
- **THEN** the flow reports the failed verification and does not begin remote node mutations

#### Scenario: An unverified certificate or a plaintext address is refused

- **GIVEN** a remote Panel presents a certificate that does not match the expected name and is not an explicitly confirmed fingerprint, or answers only over plaintext HTTP
- **WHEN** the operator tries to target it
- **THEN** the flow refuses the target before any credential is sent and reports why the channel was rejected

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
