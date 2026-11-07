# Spec Delta: Backup and Recovery

## Purpose

Provides verified, portable Backup and Restore operations for GoWave databases, certificates, configurations, and state with Online Backup API consistency, path-traversal defenses, and persistent recovery storage.

## ADDED Requirements

### Requirement: GoWave Auto NGINX Backup Format v1
The backup subsystem SHALL generate a private gzip-compressed tar archive designated as Format Version 1 containing application databases, configurations, certificates, and manifest `meta.json`, protected by root-only permissions (`0600`).

#### Scenario: Unencrypted archive creation with explicit status
- **GIVEN** a running GoWave Panel or Node
- **WHEN** a backup operation is executed
- **THEN** an archive is generated with `meta.json` (format version 1) and `files/` directory, file permissions are set to `0600`, and the CLI explicitly outputs that the archive is unencrypted.

### Requirement: Transactional SQLite Consistency via Online Backup API
The backup subsystem SHALL capture SQLite database snapshots using staged SQLite Online Backup executing under the unprivileged service user (`runuser -u gowave -- sqlite3 <db> ...`), guaranteeing transactional consistency under concurrent writes and preserving database permissions (`0640 gowave:gowave`).

#### Scenario: Database backup during active write transactions
- **GIVEN** an active GoWave Panel with continuous read and write queries
- **WHEN** backup creation executes
- **THEN** SQLite integrity check and WAL checkpoint are run under `gowave` user privileges, root pre-creates `/opt/gowave/.backup-<ts>.db` with mode `0640` and ownership `gowave:gowave`, the database is staged via `sqlite3 <db> ".backup /opt/gowave/.backup-<ts>.db"`, moved to the recovery snapshot directory with mode `0600`, database file permissions (`0640 gowave:gowave`) are preserved, and the destination file passes integrity verification before archive compression.

### Requirement: Independent Panel and Node Backup Scopes
The backup tool SHALL support separate backup scopes for Central Panel servers and Edge Worker nodes.

#### Scenario: Panel backup creation
- **GIVEN** a running Central Panel deployment with active SQLite database and TLS certificates
- **WHEN** `gowave-backup.sh backup --type panel` is executed
- **THEN** the archive captures the SQLite database (including master CA and JWT keys), `.env`, NGINX configurations, and Let's Encrypt certificates.

#### Scenario: Worker node backup creation
- **GIVEN** an active Edge Worker node deployment with local node configuration and environment state
- **WHEN** `gowave-backup.sh backup --type node` is executed on an edge server
- **THEN** the archive captures `/opt/gowave-node/.env` containing its specific assigned `SECRET_KEY`, local service configuration, and node metadata.

### Requirement: 15-Point Archive Preflight Security Validation
The restore subsystem SHALL inspect tarball headers using a dedicated Python preflight validator before extraction, rejecting malicious archives containing traversal attacks, paths outside managed roots, SUID binaries, or resource exhaustion vectors.

#### Scenario: Rejection of path traversal and unmanaged root paths
- **GIVEN** a malformed archive containing path members with `..`, leading `/`, or paths outside managed roots (`etc/cron.d/`, `root/.ssh/`)
- **WHEN** restore preflight validation is performed
- **THEN** the archive is rejected before extraction, and no host filesystem state is modified.

#### Scenario: Rejection of symlinks escaping managed roots
- **GIVEN** a crafted archive containing a symlink pointing outside designated managed roots
- **WHEN** restore preflight validation is performed
- **THEN** the validator flags the unsafe symlink target and halts extraction.

#### Scenario: Decompression bomb and device node protection
- **GIVEN** an archive containing character/block devices, FIFOs, more than 5,000 files, or an unpacked size exceeding 1 GB
- **WHEN** restore preflight validation is performed
- **THEN** the validator aborts restore with an informative error.

#### Scenario: SUID and SGID stripping on restoration
- **GIVEN** an archive containing files with SUID or SGID permission bits
- **WHEN** restore extraction proceeds
- **THEN** the validator clears SUID/SGID bits (`04000`, `02000`) and enforces managed permissions on destination paths.

### Requirement: Persistent Pre-Restore Recovery Snapshotting
The restore subsystem SHALL create a persistent recovery snapshot of current host state in `/var/lib/gowave-auto-nginx/recovery/restore-<timestamp>/` before modifying any files, tracking operations in `journal.json`.

#### Scenario: Persistent recovery snapshot and automatic rollback
- **GIVEN** a restore operation where archive extraction succeeds but GoWave Panel fails post-restore healthcheck
- **WHEN** health verification times out after 30 seconds
- **THEN** the restore subsystem automatically halts the failed services, restores files and service configurations from `/var/lib/gowave-auto-nginx/recovery/restore-<timestamp>/`, restarts original services, and reports the failure.
