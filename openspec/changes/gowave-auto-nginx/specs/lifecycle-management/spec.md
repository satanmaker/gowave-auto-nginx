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
The manager SHALL provide a dedicated command `gowave-auto.sh channel [stable|dev]` supporting transitions between Stable and Dev release channels with automated pre-switch snapshotting, schema migration guardrails, health checks, and rollback on failure.

#### Scenario: Switch from Stable to Dev channel
- **GIVEN** an active GoWave installation currently tracking the `stable` channel
- **WHEN** `gowave-auto.sh channel dev` is executed
- **THEN** the manager creates an automated SQLite Online Backup snapshot in `/var/lib/gowave-auto-nginx/recovery/`, updates `GOWAVE_CHANNEL=dev` in `/opt/gowave/.env`, fetches and verifies the latest dev release assets, restarts `gowave.service`, and confirms health via `GET http://127.0.0.1:3000/api/system/health`.

#### Scenario: Switch from Dev to Stable channel with snapshot and confirmation
- **GIVEN** an active GoWave installation currently tracking the `dev` channel
- **WHEN** `gowave-auto.sh channel stable` is executed
- **THEN** the manager displays an explicit warning that Dev database migrations cannot be automatically rolled back to an older Stable release, requires explicit confirmation or `--force` flag, creates an automated SQLite Online Backup snapshot, applies the stable release, and verifies service health.

#### Scenario: Channel switch failure and automatic rollback
- **GIVEN** a channel switch operation where the new release binary fails to start or healthcheck fails
- **WHEN** healthcheck times out after 30 seconds
- **THEN** the manager immediately stops the failed binary, restores the previous binary and SQLite database from the pre-switch snapshot, restores the previous `GOWAVE_CHANNEL` in `.env`, restarts the service, and exits with code 1.

### Requirement: Transaction-Safe Updates with Crash Recovery Journal
The update module SHALL execute SQLite Online Backup, capture a persistent snapshot in `/var/lib/gowave-auto-nginx/recovery/update-<timestamp>/`, maintain atomic state in `journal.json`, and roll back automatically upon healthcheck failure or power loss.

#### Scenario: Successful release upgrade
- **GIVEN** a running GoWave Panel
- **WHEN** `gowave-auto.sh update` is executed
- **THEN** preflight checks pass, WAL is truncated, database and binaries are snapshotted to persistent storage, `journal.json` transitions from `PREPARED` to `COMMITTED`, and healthcheck confirms HTTP 200 within 30 seconds.

#### Scenario: Interrupted update recovery after reboot
- **GIVEN** a host that rebooted or lost power while `journal.json` was in `APPLYING` or `VERIFYING` state
- **WHEN** the host finishes booting or `gowave-auto.sh` is invoked
- **THEN** the manager detects the uncommitted transaction, executes automated rollback to the persistent snapshot, restores service operation, and transitions journal state to `ROLLED_BACK`.

#### Scenario: Initial provisioning failure rollback
- **GIVEN** an initial installation where provisioning fails midway while creating Host records or binding nodes
- **WHEN** the orchestrator detects an unhandled error or verification failure
- **THEN** it reads the partial entity UUIDs recorded in `state.json.tmp`, invokes deletion APIs in strict reverse order (`DELETE /api/tokens`, `DELETE /api/users`, `DELETE /api/hosts`, `DELETE /api/internal-squads`, `DELETE /api/nodes`, `DELETE /api/config-profiles`), marks `journal.json` state as `PROVISION_ROLLED_BACK`, and leaves the system in a clean, re-runnable state.

### Requirement: Recovery Snapshot Retention Ceiling
The lifecycle manager SHALL enforce a retention policy keeping the last 3 recovery snapshots and capping total snapshot storage at 5 GB, forbidding deletion of snapshots for active in-flight transactions.

#### Scenario: Prune older snapshots after transaction commit
- **GIVEN** 3 existing snapshots in `/var/lib/gowave-auto-nginx/recovery/`
- **WHEN** a new update transaction commits successfully
- **THEN** the oldest snapshot is safely removed, keeping exactly 3 snapshots, and free disk space is verified.

### Requirement: Atomic Domain Reconfiguration with Rollback
The manager SHALL support changing the panel domain or REALITY domain with DNS preflight validation, rolling back cleanly if certificate issuance fails.

#### Scenario: Failed domain change rollback
- **GIVEN** an operator requesting a domain change to `new.example.com`
- **WHEN** ACME challenge verification fails due to misconfigured DNS
- **THEN** NGINX configurations and `.env` are restored to the previous domain, NGINX is reloaded, and active traffic to the old domain continues uninterrupted.

### Requirement: Safe and Targeted Component Uninstallation
The uninstall command SHALL inspect `# Managed by GoWave Auto NGINX` ownership markers and remove only project-managed units, configurations, and data directories without purging system packages or modifying user home directories.

#### Scenario: Clean component removal
- **GIVEN** an installed GoWave Auto NGINX instance
- **WHEN** `gowave-auto.sh uninstall --confirm` is executed
- **THEN** `gowave` and `gowave-node` systemd units are stopped and disabled, NGINX project vhosts and `# Managed by GoWave Auto NGINX` stream blocks in `/etc/nginx/nginx.conf` are cleanly removed, `/opt/gowave` and `/opt/gowave-node` are deleted, and system-wide packages (Python, systemd, SSH, base NGINX) remain intact.

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
