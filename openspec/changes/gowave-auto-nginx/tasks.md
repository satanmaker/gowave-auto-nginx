# Tasks: GoWave Auto NGINX

## 1. Repository Scaffolding, Audits, and Licensing Compliance

- [ ] 1.1 Document pinned upstream commit SHAs (`gowave` `6d2c357`, `gowave-node` `7b3514d`, `community-baseline` `community-baseline`) and create project directory structure (`assets/`, `modules/`, `config/`, `tests/`, `tools/`, `.github/workflows/`)
- [ ] 1.2 Add `LICENSE` (GNU GPL-3.0) with AGPLv3 Section 13 compatibility notices and complete `THIRD_PARTY_NOTICES.md` retaining upstream copyright attribution for `community-baseline`, `mozaroc`, `MHSanaei`, and `LibreSpeed`
- [ ] 1.3 Implement `AGENTS.md` and `CONTRIBUTING.md` establishing modular code standards, shell formatting rules, and zero-leak credential requirements

## 2. Base OS, Package Inventory, and Environment Detection

- [ ] 2.1 Implement `check_os()` supporting Ubuntu 24.04, Ubuntu 26.04, Debian 12, and Debian 13, verified with unit tests against `/etc/os-release` fixtures
- [ ] 2.2 Implement Debian 12 compatibility layer: auto-install `systemd-resolved` when DoT is requested, detect NGINX version < 1.25.1 to use `listen ... http2;` instead of `http2 on;`, and configure Debian security APT origins
- [ ] 2.3 Implement system prerequisites checks installing only necessary packages: `nginx-full`, `libnginx-mod-stream`, `certbot`, `python3`, `sqlite3`, `curl`, `tar`, `gzip`, `openssl`, `ufw`, `fail2ban`, `systemd-resolved`, `iproute2`

## 3. Host Security and Hardening Modules

- [ ] 3.1 Port and adapt `assets/security/managed.py` for non-destructive SSH inspection via both `sshd -T` and `systemctl show ssh.socket -p Listen` without modifying user configuration files
- [ ] 3.2 Implement transactional Fail2ban jail installation (`/etc/fail2ban/jail.d/90-gowave-auto-nginx.local`) protecting SSH and NGINX, verified via `fail2ban-client status`
- [ ] 3.3 Implement strict DNS-over-TLS via `systemd-resolved` with Cloudflare and Google upstream servers, preserving link DNS search routes and rolling back on network failure
- [ ] 3.4 Implement safe UFW firewall configuration: whitelist detected SSH ports before enabling UFW, open public web ports 80/443, deny external access to local Node port 3002, and isolate internal loopback listeners
- [ ] 3.5 Implement optional swap allocation (2 GiB) with filesystem space checks (>= 2 GiB free), mode `0600`, and graceful skipping in containerized environments (OpenVZ/LXC)
- [ ] 3.6 Implement `unattended-upgrades` configuration with distro-specific security origins and `Unattended-Upgrade::Automatic-Reboot "false"` by default to prevent unexpected VPN downtime
- [ ] 3.7 Implement conditional BBR congestion control tuning in `/etc/sysctl.d/99-gowave.conf`, active only after verifying `modprobe tcp_bbr` kernel availability

## 4. GoWave Panel Native Deployment (All-in-One)

- [ ] 4.1 Implement preflight port availability verification: check ports 80, 443, 3000, 3001, 3002, 7443, 8443, 9443, 10001-10003; abort with conflicting process name if occupied
- [ ] 4.2 Implement GoWave Panel native installation module downloading `gowave-linux-$ARCH` and `gowave-frontend.tar.gz` with SHA256 verification against `SHA256SUMS`
- [ ] 4.3 Generate secure `/opt/gowave/.env` configuration (`APP_HOST=127.0.0.1`, `APP_PORT=3000`, `METRICS_PORT=3001`, `DB_DRIVER=sqlite`, `DATABASE_URL=gowave.db`, `APP_SECRET=<random-64-hex>`, `GOWAVE_PROXY=external`, `GOWAVE_CHANNEL=stable`, `PANEL_DOMAIN`, `SUB_PUBLIC_DOMAIN`) with mode `0640`
- [ ] 4.4 Configure systemd unprivileged unit `gowave.service` using native `gowave-server service install /opt/gowave` (user `gowave`, directory mode `1770 root:gowave`, generating native `90-unprivileged.conf`) without duplicate drop-ins
- [ ] 4.5 Verify panel startup and loopback listener availability at `http://127.0.0.1:3000`

## 5. Panel & Local Node Integration (Conflict-Free All-in-One)

- [ ] 5.1 Implement local GoWave Node orchestration using upstream `gowave-node/install.sh`, preparing environment (`NODE_PORT=3002`, `SECRET_KEY`, `GOWAVE_NODE_VERSION`), and validating checksums and systemd unit creation
- [ ] 5.2 Extract base64 `SECRET_KEY` payload (`caCertPem`, `jwtPublicKey`, `nodeCertPem`, `nodeKeyPem`) via `./gowave-server rescue --print-secret-key-raw` without leaking credentials into command-line arguments
- [ ] 5.3 Configure `/opt/gowave-node/.env` with `NODE_PORT=3002`, `SNI_VERIFICATION=true`, deliver `SECRET_KEY` via stdin or temporary mode `0600` file, and configure UFW rule (`ufw deny 3002/tcp`) blocking external network access to the wildcard listener
- [ ] 5.4 Verify native systemd service `gowave-node.service` (user `root`, `RuntimeDirectory=gowave-node`) and verify native Xray child supervision without external watchdog timers
- [ ] 5.5 Verify mTLS 1.3 handshake with HKDF-derived SNI (`rw-v1`) and RS256 JWT authentication via `GET https://127.0.0.1:3002/node/xray/node-health-check`, and verify that external connections to `<public-ip>:3002` are dropped by the firewall

## 6. Remote Worker Node Deployment Script (Distributed Edge)

- [ ] 6.1 Implement standalone `gowave-node-auto.sh` for deploying remote worker nodes, orchestrating upstream `gowave-node/install.sh` with `NODE_PORT` (default 3000), `GOWAVE_NODE_VERSION`, and `SECRET_KEY` via stdin or temporary mode 0600 file
- [ ] 6.2 Enforce UFW firewall rule restricting `NODE_PORT` strictly to `PANEL_IP` (`ufw allow proto tcp from $PANEL_IP to any port $NODE_PORT`) for both IPv4 and IPv6, and verify dropped packets from unauthorized IPs
- [ ] 6.3 Apply Linux kernel TCP tuning (`bbr`, `fq`, `LimitNOFILE=1048576`) in `/etc/sysctl.d/99-gowave-node.conf`
- [ ] 6.4 Verify `gowave-node status --wait-ready` confirms healthy node and Xray core status on the remote worker

## 7. NGINX Stream SNI Routing and Camouflage Fallback

- [ ] 7.1 Hook top-level Stream configuration in `/etc/nginx/nginx.conf` (`stream { include /etc/nginx/stream-enabled/*.conf; }`) outside `http {}`, and verify `libnginx-mod-stream` loading
- [ ] 7.2 Implement NGINX Stream configuration on port 443 (`ssl_preread on; proxy_protocol on;`) routing `reality_domain` to 127.0.0.1:8443, `panel_domain` to 127.0.0.1:7443, and default/scanners to 127.0.0.1:8443
- [ ] 7.3 Implement NGINX panel vhost on 127.0.0.1:7443 (`listen 127.0.0.1:7443 ssl proxy_protocol; set_real_ip_from 127.0.0.1; real_ip_header proxy_protocol;`) with Let's Encrypt TLS termination and reverse proxying to GoWave at 127.0.0.1:3000
- [ ] 7.4 Implement NGINX REALITY fallback vhost on 127.0.0.1:9443 (`listen 127.0.0.1:9443 ssl proxy_protocol; set_real_ip_from 127.0.0.1; real_ip_header proxy_protocol;`) with REALITY domain TLS certificate and static camouflage site (`cover-reality`)
- [ ] 7.5 Configure Certbot webroot ACME challenge on port 80 and automated renewal hook in `/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh` reloading NGINX

## 8. Protocol Transport Profiles & API Provisioning

- [ ] 8.1 Implement automated GoWave REST API provisioning module: bootstrap initial admin via `POST /api/auth/register`, login via `POST /api/auth/login`, and obtain JWT access token
- [ ] 8.2 Provision VLESS + REALITY + Vision profile via `POST /api/config-profiles` (inbound on `127.0.0.1:8443` with `acceptProxyProtocol: true` and fallback to `127.0.0.1:9443` with PROXY v1)
- [ ] 8.3 Provision VLESS + XHTTP + TLS profile via API and configure NGINX location `^~ /<xhttp_path>/` reverse proxying to `http://127.0.0.1:10001` with buffering disabled
- [ ] 8.4 Provision VLESS + WebSocket + TLS profile (port 10002) and Trojan + gRPC + TLS profile (port 10003) via API and NGINX reverse proxy
- [ ] 8.5 Link profiles to active nodes using the exact GoWave DTO via `POST /api/nodes` or `PATCH /api/nodes/{uuid}` (`{"configProfile": {"activeConfigProfileUuid": "<uuid>", "activeInbounds": [...]}}`) and verify compiled configuration via `GET /api/config-profiles/{uuid}/computed-config`
- [ ] 8.6 Implement automated GoWave Host record provisioning via `POST /api/hosts` for each of the 4 MVP protocols, mapping public hostname, port 443, SNI, path, and security layers to inbounds and nodes, and verify read-back via `GET /api/hosts`
- [ ] 8.7 Verify and configure GoWave Response Rules (`DisableSubscriptionAccessByPath=false`) and confirm presence of default subscription templates (`MIHOMO` and `XRAY_JSON`) in `subscription_templates` table
- [ ] 8.8 Generate, verify, and display both deterministic per-user subscription links (`GET /api/sub/{shortUuid}/v2ray-json` for Xray JSON and `GET /api/sub/{shortUuid}/mihomo` for Mihomo YAML), confirming HTTP 200, valid Content-Type, non-empty parseable bodies, zero loopback/internal leaks, and outputting both links in installer completion summary

## 9. Transaction-Safe Updates and Crash Recovery Journal

- [ ] 9.1 Implement preflight SQLite check (`PRAGMA integrity_check;`) and WAL checkpoint (`PRAGMA wal_checkpoint(TRUNCATE);`) with 5s busy timeout
- [ ] 9.2 Execute transactional database backup using SQLite Online Backup API (`sqlite3 /opt/gowave/gowave.db ".backup /var/lib/.../gowave.db"`) and verify destination integrity
- [ ] 9.3 Maintain durable state journal at `/var/lib/gowave-auto-nginx/recovery/journal.json` using atomic write (`.tmp` + `fsync` + `rename`) tracking states (`PREPARED`, `APPLYING`, `VERIFYING`, `COMMITTED`, `ROLLBACK_REQUIRED`, `ROLLED_BACK`)
- [ ] 9.4 Implement channel switching command `gowave-auto.sh channel [stable|dev]` with automated pre-switch SQLite snapshot, migration irreversible downgrade warning with `--force` confirmation, asset update with SHA256 checksums, and rollback on failure
- [ ] 9.5 Implement staged release download, SHA256 checksum verification, atomic file swap, and service restart
- [ ] 9.6 Implement post-update health probe with automated rollback: restore DB and binary from `/var/lib/.../recovery/` upon healthcheck timeout or failure
- [ ] 9.7 Implement boot-time crash recovery: check `journal.json` on script startup, automatically completing rollback if an update was interrupted by power loss
- [ ] 9.8 Hook into systemd unit `gowave-update.service` so that in-panel web UI update triggers automatically execute the pre-update snapshot
- [ ] 9.9 Enforce snapshot retention policy: retain the last 3 snapshots, enforce a 5 GB storage ceiling, and prune older snapshots after transaction commit

## 10. Hardened Backup and Restore Format v1 Implementation

- [ ] 10.1 Implement `assets/backup/gowave-backup.sh` creating `GoWave Auto NGINX Backup Format v1` unencrypted gzip archives containing databases, `.env`, node credentials, NGINX configurations, and `meta.json` with permissions `0600`
- [ ] 10.2 Implement separate backup commands for Central Panel (`--type panel`) and Edge Worker nodes (`--type node`)
- [ ] 10.3 Implement 12-point Python preflight validator rejecting archives with path traversal (`..`, leading `/`), symlink escapes outside managed roots, hardlinks to non-files, device nodes, decompression bombs (> 5,000 files, > 1 GB), or oversized metadata
- [ ] 10.4 Implement pre-restore persistent snapshotting in `/var/lib/gowave-auto-nginx/recovery/restore-<timestamp>/` with transaction state tracking persisting across system reboots
- [ ] 10.5 Implement automated restore rollback reverting files and restarting services if post-restore health verification fails

## 11. Interactive Management Interface

- [ ] 11.1 Implement interactive CLI menu in `gowave-auto.sh` providing `status`, `health`, `install`, `update`, `channel`, `domain-change`, `backup`, `restore`, and `uninstall`
- [ ] 11.2 Implement non-interactive CLI flags for all commands enabling headless execution and Ansible integration
- [ ] 11.3 Implement exclusive file locking (`/run/lock/gowave-auto.lock`) preventing concurrent conflicting operations
- [ ] 11.4 Implement installation progress checkpoints allowing resumed execution or safe rollback on interrupted initial setups
- [ ] 11.5 Implement atomic domain change with DNS preflight validation and rollback to old domain if ACME challenge fails
- [ ] 11.6 Implement safe uninstall inspecting `# Managed by GoWave Auto NGINX` ownership markers and removing only project-managed assets without purging system packages

## 12. 5-Suite Testing Architecture & Verification

- [ ] 12.1 Implement `tests/run_ci.py` with explicit `SUITES` registry (`nonroot`, `root`, `integration`, `services`, `systemd`) and `--check-completeness` enforcement
- [ ] 12.2 Enforce EUID privilege separation: require `os.geteuid() != 0` for `nonroot`, `integration`, and `services`; require `os.geteuid() == 0` for `root` (container) and `systemd` (QEMU)
- [ ] 12.3 Implement Suite `nonroot`: ShellCheck, Python linting, OpenSpec validation (`openspec validate --all --strict`), NGINX config compilation for Debian 12 (1.22) and Ubuntu (1.24+), and malicious tarball rejection
- [ ] 12.4 Implement Suite `integration`: concurrent SQLite writes during `.backup`, GoWave API admin bootstrap, profile provisioning, Host entity creation (`POST /api/hosts`), node association payload verification, and mTLS 1.3 handshake verification
- [ ] 12.5 Implement Suite `services`: live daemon execution, client REALITY handshake, scanner fallback to 9443 cover site, XHTTP bidirectional streaming, separate retrieval and client parsing/import validation of Xray JSON (`/api/sub/{shortUuid}/v2ray-json`) and Mihomo YAML (`/api/sub/{shortUuid}/mihomo`), and local Node external inaccessibility check
- [ ] 12.6 Implement Suite `root`: user/group creation (`gowave:gowave`), sticky bit permissions (1770), service install verification, zero-leak secret delivery verification, and Fail2ban syntax check
- [ ] 12.7 Integrate GoWave Node upstream test suite: run `go test ./...`, `go vet`, ShellCheck, `python3 tests/test_scripts.py`, and `gowave-node status --wait-ready` CLI verification
- [ ] 12.8 Implement Suite `systemd` QEMU TCG runner (`tests/systemd/boot.sh`): verify PID 1 systemd cold boot, All-in-One port bindings, service persistence across reboot, power cut journal recovery, and backup/restore across Ubuntu 24.04, 26.04, Debian 12, and Debian 13

## 13. CI/CD Workflows and Acceptance

- [ ] 13.1 Implement GitHub Actions workflow `lint-and-nonroot.yml` running ShellCheck, actionlint, completeness check, and Suite `nonroot`
- [ ] 13.2 Implement GitHub Actions workflow `root-integration.yml` running Suite `root` (as EUID 0) and Suite `integration` (under unprivileged container user `--user 1001:1001` with EUID != 0)
- [ ] 13.3 Implement GitHub Actions workflow `systemd-acceptance.yml` executing Suite `services` and Suite `systemd` QEMU tests across all 4 target OSs
- [ ] 13.4 Implement `tools/prepare_release.py` generating reproducible release archives with pinned commit SHAs and SHA256 checksum sidecars
- [ ] 13.5 Execute full end-to-end acceptance install, domain change, update with simulated crash, and backup/restore verification on a clean VM
