# Spec Delta: Lifecycle Management

## Purpose

Provides interactive menu and CLI operations for installation, status diagnostics, domain changes, safe uninstallation, channel switching between Stable and Dev releases, and transaction-safe GoWave updates with automatic rollback and reboot recovery.

## ADDED Requirements

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
The installation module SHALL configure `GOWAVE_PROXY=external` in `/opt/gowave/.env`, write complete base unit `/etc/systemd/system/gowave.service`, enable it via `systemctl enable`, and invoke `gowave-server service install` for drop-in sandboxing `90-unprivileged.conf`.

#### Scenario: GoWave external proxy mode verification
- **GIVEN** a newly provisioned GoWave Panel
- **WHEN** `/opt/gowave/.env` is generated, base unit `/etc/systemd/system/gowave.service` is written and enabled, and `gowave-server service install` is executed
- **THEN** `GOWAVE_PROXY=external` is present in `/opt/gowave/.env`, base unit `/etc/systemd/system/gowave.service` is registered with systemd, and the native service unit drop-in `90-unprivileged.conf` applies unprivileged user sandboxing without missing unit errors.

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
