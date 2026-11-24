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

### Requirement: Granular CLI & Interactive Management Interface
The management script (`gowave-auto.sh`) SHALL provide explicit subcommands and an interactive menu for: `install`, `update`, `channel`, `node`, `status`, `health`, `domain-change`, `backup`, `restore`, and `uninstall`.

#### Scenario: Status and diagnostics inspection
- **GIVEN** an active GoWave installation
- **WHEN** `gowave-auto.sh status` is executed
- **THEN** it checks and displays the systemd status and port bindings of GoWave Panel (:3000), GoWave Node (:3002 with UFW firewall loopback isolation), Xray core, NGINX, and Let's Encrypt certificate expiry dates.

### Requirement: Exclusive Process Locking
The management utility SHALL enforce mutually exclusive execution using file locks (`flock`) on `/run/lock/gowave-auto.lock` to prevent race conditions during concurrent modifications.

#### Scenario: Block concurrent manager invocations
- **GIVEN** an active `gowave-auto.sh update` running in the background
- **WHEN** a second instance of `gowave-auto.sh` is started
- **THEN** the second instance detects the active lock, reports that another operation is in progress, and exits with code 1 without modifying system state.

### Requirement: External Proxy Mode and Service Ownership
The installation module SHALL configure `GOWAVE_PROXY=external` in `/opt/gowave/.env`, write the base unit `/etc/systemd/system/gowave.service` itself, and write and enable the in-panel update helper units `gowave-update.service` and `gowave-update.path` from its own templates. It MUST NOT invoke `gowave-server service install`.

#### Scenario: GoWave external proxy mode verification
- **GIVEN** a newly provisioned GoWave Panel
- **WHEN** `/opt/gowave/.env` is generated and the managed units are written and enabled
- **THEN** `GOWAVE_PROXY=external` is present in `/opt/gowave/.env`, the base unit and both helper units are registered with systemd, no `gowave-server service install` invocation exists in the installation path, and no `gowave.service.d/90-unprivileged.conf` is created by the installation; the vendored helper reapplies that drop-in on each in-panel update

### Requirement: Safe Channel Switching Between Stable and Dev Releases
The manager SHALL provide a dedicated command `gowave-auto.sh channel [stable|dev]` supporting transitions between Stable and Dev release channels with automated pre-switch snapshotting, schema migration guardrails, health checks, and rollback on failure. The command SHALL NOT fetch or replace release assets: it records the channel the Panel reads at startup and restarts it, and installing a different release remains the job of `gowave-auto.sh update`.

#### Scenario: Switch from Stable to Dev channel
- **GIVEN** an active GoWave installation currently tracking the `stable` channel
- **WHEN** `gowave-auto.sh channel dev` is executed
- **THEN** the manager captures a recovery snapshot in `/var/lib/gowave-auto-nginx/recovery/update-<timestamp>/` (SQLite Online Backup of the database plus the Panel binary, the frontend tree, `.env`, `state.json`, and the `/etc/nginx` and `/etc/letsencrypt` trees), writes the `APPLYING` journal, updates `GOWAVE_CHANNEL=dev` in `/opt/gowave/.env`, restarts `gowave.service`, confirms health via `GET http://127.0.0.1:3000/api/system/health` within 30 seconds, marks the journal `COMMITTED`, prunes old snapshots, and exits with code 0.

#### Scenario: Repeating the command for the current channel is a no-op
- **GIVEN** an active GoWave installation already tracking the requested channel
- **WHEN** `gowave-auto.sh channel <current channel>` is executed
- **THEN** the manager reports `GoWave is already on channel '<channel>'.` and exits with code 0 without taking a snapshot, rewriting `.env`, or restarting the service.

#### Scenario: Switch from Dev to Stable channel with snapshot and confirmation
- **GIVEN** an active GoWave installation currently tracking the `dev` channel
- **WHEN** `gowave-auto.sh channel stable` is executed without `--force`
- **THEN** the manager displays an explicit warning that Dev database migrations cannot be automatically rolled back to an older Stable release, exits with code 1 without snapshotting, rewriting `.env`, or restarting the service, and only a repeated invocation with `--force` captures the recovery snapshot, applies the stable channel label, restarts the service, and verifies service health.

#### Scenario: Channel switch failure and automatic rollback
- **GIVEN** a channel switch operation where the restarted Panel does not become active or its healthcheck fails
- **WHEN** `systemctl restart gowave.service` fails or the healthcheck times out after 30 seconds
- **THEN** the manager restores the previous binary, SQLite database, frontend tree, `.env`, `state.json`, and the NGINX and ACME state from the pre-switch snapshot, restarts the service, marks the journal `ROLLED_BACK`, and exits with code 1, leaving the journal `ROLLBACK_REQUIRED` when the rollback itself cannot complete so that the boot recovery unit retries it.

### Requirement: Transaction-Safe Updates with Crash Recovery Journal
The update module SHALL execute SQLite Online Backup, capture a persistent snapshot in `/var/lib/gowave-auto-nginx/recovery/update-<timestamp>/`, maintain atomic state in `journal.json`, and roll back automatically upon healthcheck failure or power loss.

#### Scenario: Successful release upgrade
- **GIVEN** a running GoWave Panel
- **WHEN** `gowave-auto.sh update` is executed
- **THEN** preflight checks pass, WAL is truncated, database and binaries are snapshotted to persistent storage, `journal.json` transitions from `PREPARED` to `COMMITTED`, and healthcheck confirms HTTP 200 within 30 seconds.

#### Scenario: Interrupted update recovery after reboot
- **GIVEN** a host that rebooted or lost power while `journal.json` was in `APPLYING` or `VERIFYING` state
- **WHEN** the host boots and systemd executes early oneshot `gowave-recover.service` before `gowave.service`
- **THEN** `gowave-auto.sh recover --boot-files` acquires the exclusive lock `/run/lock/gowave-auto.lock`, detects uncommitted update or restore files, restores the pre-transaction snapshot, transitions state to `ROLLED_BACK`, and unblocks service startup.

#### Scenario: Interrupted provisioning recovery after reboot
- **GIVEN** a host that lost power while `journal.json` was in `PROVISION_*` or `NODE_ADD_*` state
- **WHEN** systemd starts `gowave.service` and executes `gowave-recover-provision.service`
- **THEN** `gowave-auto.sh recover --boot-provision` confirms panel health, executes reverse-order API cleanup of partial entities (`Tokens` -> `Users` -> `Hosts` -> `Squads` -> `Nodes` -> `Profiles`), and transitions journal state to `PROVISION_ROLLED_BACK` (or `NODE_ADD_ROLLED_BACK`).

#### Scenario: Initial provisioning failure rollback
- **GIVEN** an initial installation where provisioning fails midway while creating Host records or binding nodes
- **WHEN** the orchestrator detects an unhandled error or verification failure
- **THEN** it reads the partial entity records from `journal.json`, deletes ONLY resources created in this transaction (`"action": "created"`), restores prior states for updated resources (`"action": "updated"`), preserves existing resources adopted during idempotent reconciliation (`"action": "adopted"`), avoids global name-based deletions, marks `journal.json` state as `PROVISION_ROLLED_BACK`, and leaves the system in a clean, re-runnable state.

#### Scenario: Worker node addition failure rollback
- **GIVEN** an active panel where `gowave-auto.sh node add` fails during edge deployment or verification
- **WHEN** the orchestrator triggers worker rollback
- **THEN** it deletes worker hosts (`DELETE /api/hosts/{uuid}`), disassociates worker inbounds via `PATCH /api/internal-squads` with the remaining inbound union array, deletes worker node and worker config profile by explicit UUID, prunes the worker entry from `state.json`, and strictly preserves central panel users, tokens, and squads.

#### Scenario: Corrupted journal validation before recovery
- **GIVEN** an uncommitted transaction where `journal.json` is truncated, corrupted, or violates schema
- **WHEN** `gowave-auto.sh recover` executes
- **THEN** it validates that `op` is supported, `state` belongs strictly to `OP_ALLOWED_STATES[op]`, and timestamps are valid; if validation fails, it aborts without deleting entities, logs a fatal schema error, and requires manual operator confirmation before modifying state.

### Requirement: Recovery Snapshot Retention Ceiling
The lifecycle manager SHALL enforce a retention policy keeping the last 3 recovery snapshots and capping total snapshot storage at 5 GB, forbidding deletion of snapshots for active in-flight transactions.

#### Scenario: Prune older snapshots after transaction commit
- **GIVEN** 3 existing snapshots in `/var/lib/gowave-auto-nginx/recovery/`
- **WHEN** a new update transaction commits successfully
- **THEN** the oldest snapshot is safely removed, keeping exactly 3 snapshots, and free disk space is verified.

### Requirement: Atomic Domain Reconfiguration with Rollback
The manager SHALL support changing the panel domain or REALITY domain with DNS preflight validation, proper variable scoping (`new_panel_domain` and `new_reality_domain`), recomputing the camouflage apex from the new panel domain, reissuing the REALITY lineage with `--expand` so it also carries the apex and `www.<apex>`, verifying that SAN before deploying production vhosts, and rolling back cleanly if certificate issuance or SAN validation fails.

#### Scenario: Failed domain change rollback
- **GIVEN** an operator requesting a domain change to `new.example.com`
- **WHEN** ACME challenge verification fails due to misconfigured DNS
- **THEN** NGINX configurations and `.env` are restored to the previous domain, NGINX is reloaded, and active traffic to the old domain continues uninterrupted.

#### Scenario: Domain change carries the camouflage apex along
- **GIVEN** an operator changing the panel domain from `dns.old.example` to `panel.new.example`, with the new camouflage apex `new.example` resolving to this host
- **WHEN** the manager provisions certificates for the new names
- **THEN** it derives the new camouflage apex `new.example`, issues the panel lineage for `panel.new.example`, issues the REALITY lineage for the REALITY domain together with `new.example` and `www.new.example` using `--expand`, verifies the REALITY certificate covers that apex SAN, deploys stream, port 80, and decoy vhosts naming the new apex and `www.<apex>`, and rolls the whole change back if issuance or SAN verification fails.

### Requirement: Safe and Targeted Component Uninstallation
The uninstall command SHALL remove only project-managed systemd units, NGINX vhosts, and the managed stream include block, SHALL stop and disable the managed services, and SHALL preserve application data, Worker binaries, certificates, backups, and recovery state without purging system packages or modifying user home directories.

#### Scenario: Clean component removal
- **GIVEN** an installed GoWave Auto NGINX instance
- **WHEN** `gowave-auto.sh uninstall --yes` is executed
- **THEN** `gowave.service` and `gowave-node.service` are stopped and disabled, the managed unit files (`gowave`, `gowave-node`, both recovery units, and `bbr-load.service`) are removed, NGINX project vhosts and `# Managed by GoWave Auto NGINX` stream blocks in `/etc/nginx/nginx.conf` are cleanly removed, and system-wide packages (Python, systemd, SSH, base NGINX, Certbot) remain installed and intact.

#### Scenario: Application data survives uninstallation
- **GIVEN** an installed GoWave Auto NGINX instance with an active database, certificates, and recovery snapshots
- **WHEN** `gowave-auto.sh uninstall --yes` completes
- **THEN** `/opt/gowave`, `/opt/gowave-node`, `/var/lib/gowave-auto-nginx`, `/var/www/gowave-auto-nginx`, and `/var/www/gowave-acme` remain on disk, are reported to the operator for manual review, and are not recursively deleted, because no verified installer ownership marker exists for them.

### Requirement: Local Multi-Distribution Podman Testbed Gate
The verification harness SHALL provide `tests/podman_testbed.sh` executing containerized pre-flight tests with PID 1 systemd across all 4 supported operating systems (Ubuntu 24.04, Ubuntu 26.04, Debian 12, Debian 13), requiring 100% pass rate across the 8-stage verification pipeline prior to VPS deployment.

#### Scenario: Automated local Podman validation across all 4 supported distributions
- **GIVEN** a local development or CI environment with Podman installed
- **WHEN** `./tests/podman_testbed.sh all` is executed
- **THEN** it sequentially launches official container images for Ubuntu 24.04, Ubuntu 26.04, Debian 12, and Debian 13 using `--systemd=always --privileged`, runs the 8-stage verification pipeline inside each container, collects structured logs, and confirms all 4 environments pass with zero errors.

#### Scenario: Runtime distribution adaptation verification in Podman containers
- **GIVEN** container testbeds running Debian 12, Debian 13, Ubuntu 24.04, and Ubuntu 26.04
- **WHEN** the testbed executes stage 1 (prerequisites) and stage 2 (NGINX syntax)
- **THEN** it verifies that `systemd-resolved` is auto-installed on Debian 12, that NGINX legacy syntax (`listen ... ssl http2;`) is configured on Ubuntu 24.04 and Debian 12, and modern syntax (`http2 on;`) is configured on Ubuntu 26.04 and Debian 13.
