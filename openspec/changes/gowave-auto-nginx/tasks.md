# Tasks: GoWave Auto NGINX

## 1. Repository Scaffolding, Audits, and Licensing Compliance

- [ ] 1.1 Document pinned upstream commit SHAs (`gowave` `6d2c357`, `gowave-node` `7b3514d`, `community-baseline` `community-baseline`) and create project directory structure (`assets/`, `modules/`, `config/`, `tests/`, `tools/`, `.github/workflows/`)
- [ ] 1.2 Add `LICENSE` (GNU GPL-3.0) with upstream compatibility notices and complete `THIRD_PARTY_NOTICES.md` retaining upstream copyright attribution for `community-baseline`, `mozaroc`, `MHSanaei`, and `LibreSpeed`
- [ ] 1.3 Implement `AGENTS.md` and `CONTRIBUTING.md` establishing modular code standards, shell formatting rules, and zero-leak credential requirements

## 2. Base OS, Package Inventory, and Environment Detection

- [ ] 2.1 Implement `check_os()` supporting Ubuntu 24.04, Ubuntu 26.04, Debian 12, and Debian 13, verified with unit tests against `/etc/os-release` fixtures
- [ ] 2.2 Implement runtime NGINX version detection (`nginx -v`): generate `listen ... ssl http2;` for NGINX < 1.25.1 (Ubuntu 24.04 with 1.24.0 and Debian 12 with 1.22.1) and `listen ...; http2 on;` for NGINX >= 1.25.1 (Debian 13 with 1.26.3 and Ubuntu 26.04); auto-install `systemd-resolved` on Debian 12 when DoT is requested; configure Debian security APT origins
- [ ] 2.3 Implement system prerequisites checks installing only necessary packages: `nginx-full`, `libnginx-mod-stream`, `certbot`, `python3`, `sqlite3`, `curl`, `tar`, `gzip`, `openssl`, `ufw`, `fail2ban`, `systemd-resolved`, `iproute2`

## 3. Host Security and Hardening Modules

- [ ] 3.1 Port and adapt `assets/security/managed.py` for non-destructive SSH inspection via both `sshd -T` and `systemctl show ssh.socket -p Listen` without modifying user configuration files
- [ ] 3.2 Implement transactional Fail2ban jail installation (`/etc/fail2ban/jail.d/90-gowave-auto-nginx.local`) with `python3-systemd` prerequisite, configuring `backend = systemd` and journalmatch monitoring both `ssh.service` and `ssh.socket` (`ssh@*.service`), verified via `fail2ban-client status`
- [ ] 3.3 Implement strict DNS-over-TLS via `systemd-resolved` with Cloudflare and Google upstream servers, preserving link DNS search routes and rolling back on network failure
- [ ] 3.4 Implement safe UFW firewall configuration: whitelist detected SSH ports before enabling UFW, open public web ports 80/443, deny external access to local Node port 3002, isolate internal loopback listeners, and conditionally configure `IPV6=no` in `/etc/default/ufw` when IPv6 is disabled in kernel to prevent ip6tables failures
- [ ] 3.5 Implement automatic filesystem-aware swap allocation (1 GiB) on KVM VPS with <= 1GB RAM using `dd if=/dev/zero` or `btrfs filesystem mkswapfile` (avoiding fallocate holes on XFS/Btrfs), mode `0600`, graceful skipping in containerized environments, and set `GOMEMLIMIT=250MiB` systemd drop-in
- [ ] 3.6 Implement `unattended-upgrades` configuration with distro-specific security origins and `Unattended-Upgrade::Automatic-Reboot "false"` by default to prevent unexpected VPN downtime
- [ ] 3.7 Implement conditional BBR congestion control and MTU probing (`net.ipv4.tcp_mtu_probing = 1`) in `/etc/sysctl.d/99-gowave.conf`, persisting kernel module loading via dedicated oneshot systemd unit `/etc/systemd/system/bbr-load.service` ordered `Before=systemd-sysctl.service` with graceful fallback on kernels lacking `tcp_bbr`
- [ ] 3.8 Implement NGINX and systemd log rotation policies: deploy `/etc/logrotate.d/gowave-nginx` with daily rotation and gzip compression, and cap systemd journal size to 100MB via `SystemMaxUse=100M`

## 4. GoWave Panel Native Deployment (All-in-One)

- [ ] 4.1 Implement preflight port availability verification (check ports 80, 443, 3000, 3001, 3002, 7443, 8443, 9443, 10001-10003) and NGINX 443 conflict scan across /etc/nginx/ for unmanaged listen 443 directives; abort with conflicting process name or config location before mutating system state
- [ ] 4.2 Implement GoWave Panel native installation module downloading `gowave-linux-$ARCH` and `gowave-frontend.tar.gz` with SHA256 verification against `SHA256SUMS`
- [ ] 4.3 Generate secure `/opt/gowave/.env` configuration (`APP_HOST=127.0.0.1`, `APP_PORT=3000`, `METRICS_PORT=3001`, `DB_DRIVER=sqlite`, `DATABASE_URL=gowave.db`, `APP_SECRET=<random-64-hex>`, `GOWAVE_PROXY=external`, `GOWAVE_CHANNEL=stable`, `PANEL_DOMAIN`, `SUB_PUBLIC_DOMAIN`) with mode `0640`
- [ ] 4.4 Configure systemd unit `gowave.service`: pre-create `gowave` system user, write complete base unit `/etc/systemd/system/gowave.service` (`Type=simple`, `ExecStart=/opt/gowave/gowave-server`, `WorkingDirectory=/opt/gowave`, `After=network-online.target`, `LimitNOFILE=65535`), run `systemctl daemon-reload && systemctl enable gowave.service`, and execute native `/opt/gowave/gowave-server service install /opt/gowave` generating directory mode `1770 root:gowave`, drop-in `90-unprivileged.conf`, and `gowave-update.path`
- [ ] 4.5 Verify panel startup and loopback listener availability at `http://127.0.0.1:3000`

## 5. Panel & Local Node Integration (Conflict-Free All-in-One)

- [ ] 5.1 Implement local GoWave Node orchestration using upstream `gowave-node/install.sh`, preparing environment (`NODE_PORT=3002`, `SECRET_KEY`, `GOWAVE_NODE_VERSION`), and validating checksums and systemd unit creation
- [ ] 5.2 Extract base64 `SECRET_KEY` payload (`caCertPem`, `jwtPublicKey`, `nodeCertPem`, `nodeKeyPem`) via `./gowave-server rescue --print-secret-key-raw` without leaking credentials into command-line arguments
- [ ] 5.3 Configure `/opt/gowave-node/.env` with `NODE_PORT=3002`, `SNI_VERIFICATION=true`, deploy systemd hardening drop-in `/etc/systemd/system/gowave-node.service.d/10-port.conf` (`Environment="NODE_PORT=3002"`), deliver `SECRET_KEY` via stdin or temporary mode `0600` file, and configure UFW rule (`ufw deny 3002/tcp`) blocking external network access to the wildcard listener
- [ ] 5.4 Verify native systemd service `gowave-node.service` (user `root`, `RuntimeDirectory=gowave-node`) and verify native Xray child supervision without external watchdog timers
- [ ] 5.5 Verify mTLS 1.3 handshake with HKDF-derived SNI (`rw-v1`) and RS256 JWT authentication via `GET https://127.0.0.1:3002/node/xray/node-health-check`, and verify that external connections to `<public-ip>:3002` are dropped by the firewall

## 6. Remote Worker Node Deployment Script (Distributed Edge)

- [ ] 6.1 Implement standalone `gowave-node-auto.sh` with SSH stdin streaming orchestration pattern (`remote_payload` packing `PANEL_IP`, `NODE_PORT`, `SECRET_KEY`, `GOWAVE_NODE_VERSION`, `WORKER_DOMAIN`, `REALITY_DOMAIN` strictly over SSH stdin with `umask 077` and zero secrets in process `argv`) for remote worker deployment without temporary `scp` file copies or `/proc/<pid>/cmdline` exposure
- [ ] 6.2 Enforce UFW firewall rule restricting `NODE_PORT` strictly to `PANEL_IP` (`ufw allow proto tcp from $PANEL_IP to any port $NODE_PORT`) for both IPv4 and IPv6, and verify dropped packets from unauthorized IPs
- [ ] 6.3 Apply Linux kernel TCP tuning (`bbr`, `fq`, `LimitNOFILE=1048576`) in `/etc/sysctl.d/99-gowave-node.conf`
- [ ] 6.4 Verify `gowave-node status --wait-ready` confirms healthy node and Xray core status on the remote worker
- [ ] 6.5 Implement NGINX Stream and HTTPS edge configuration on Worker: configure Stream port 443 with SNI preread routing Worker domain to local NGINX HTTPS listener (7443) and camouflage SNI to local Xray REALITY (8443) with fallback to local decoy site (9443)
- [ ] 6.6 Implement Certbot ACME HTTP-01 challenge on port 80 and automated renewal hook for Worker domain on Worker host
- [ ] 6.7 Configure Worker NGINX HTTPS reverse proxy rules on 7443 for XHTTP (`proxy_buffering off`), WebSocket (`Upgrade`), and Trojan gRPC (`grpc_pass`) matching local Xray inbounds
- [ ] 6.8 Verify end-to-end edge traffic routing on Worker: test direct client connections to Worker public IP/domain on port 443 across all 4 protocols without routing through the Central Panel
- [ ] 6.9 Implement automated worker registration command in `gowave-auto.sh` (`gowave-auto.sh node add <worker-name> <worker-ip> <worker-domain> <reality-domain>`): dispatches deployment payload strictly via SSH stdin without secret CLI parameters, issues `POST /api/nodes` linking unified profile and inbounds, creates worker Host entities (`POST /api/hosts`), and records worker in `state.json`

## 7. NGINX Stream SNI Routing and Camouflage Fallback

- [ ] 7.1 Hook top-level Stream configuration in `/etc/nginx/nginx.conf` (`stream { include /etc/nginx/stream-enabled/*.conf; }`) wrapped in `# Managed by GoWave Auto NGINX` markers outside `http {}`, and verify `libnginx-mod-stream` loading
- [ ] 7.2 Implement NGINX Stream configuration on port 443 (`ssl_preread on; proxy_protocol on;`) routing `reality_domain` to 127.0.0.1:8443, `panel_domain` to 127.0.0.1:7443, and default/scanners to 127.0.0.1:8443
- [ ] 7.3 Implement Let's Encrypt TLS bootstrap sequence: execute dual-lineage standalone ACME acquisition (`certbot certonly --standalone`) for both `PANEL_DOMAIN` and `REALITY_DOMAIN` prior to starting NGINX, deploy NGINX panel vhost on 127.0.0.1:7443 (`listen 127.0.0.1:7443 ssl proxy_protocol; set_real_ip_from 127.0.0.1; real_ip_header proxy_protocol;`) with explicit `location ^~ /api/` and `location /` proxying to `http://127.0.0.1:3000` with `access_log off;` on streaming paths (`/xhttp-down/`, `/ws`, `/trojan-grpc`), and configure port 80 with selective redirect preserving `/.well-known/acme-challenge/` for renewals
- [ ] 7.4 Implement NGINX REALITY fallback vhost on 127.0.0.1:9443 (`listen 127.0.0.1:9443 ssl proxy_protocol; set_real_ip_from 127.0.0.1; real_ip_header proxy_protocol;`) receiving PROXY protocol v1 from Xray fallback (`dest: "127.0.0.1:9443", xver: 1`), terminating TLS with REALITY domain TLS certificate, and serving static camouflage site (`cover-reality`)
- [ ] 7.5 Configure Certbot webroot ACME challenge on port 80 and automated renewal hook in `/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh` reloading NGINX after verifying `nginx -t -q`

## 8. Protocol Transport Profiles & API Provisioning

- [ ] 8.1 Implement automated GoWave REST API provisioning client adhering to `API_CONTRACTS.md`: bootstrap initial admin via `POST /api/auth/register`, login via `POST /api/auth/login`, handle 12-hour HS256 JWT lifecycle, and implement automated 401 re-login and error taxonomy retry policy
- [ ] 8.2 Generate x25519 keypair natively via GoWave REST API `GET /api/system/tools/x25519/generate` and provision a single unified Config Profile ("GoWave MVP Unified Profile") via `POST /api/config-profiles` embedding reference templates from `assets/xray/` (including `tcpSettings.acceptProxyProtocol: true` on REALITY 8443, XHTTP 10001, WS 10002, Trojan gRPC 10003)
- [ ] 8.3 Validate compiled config via `GET /api/config-profiles/{uuid}/computed-config` against 5-point verification checklist (valid JSON, 4 inbounds, `streamSettings.security` populated, `realitySettings` present on 8443, zero errors), retrieve inbound UUIDs via `GET /api/config-profiles/{uuid}/inbounds`, and associate profile and inbounds to the Node via `POST /api/nodes` or `PATCH /api/nodes/{uuid}`
- [ ] 8.4 Implement algorithmic idempotency and state reconciliation via `/var/lib/gowave-auto-nginx/state.json` adhering to `API_CONTRACTS.md`: match existing resources by canonical name/remark, adopt UUIDs, update via `PATCH`/`PUT`, and persist state atomically (`.tmp` + file `fsync` + `rename` + directory `fsync`)
- [ ] 8.5 Provision managed Internal Squad via `POST /api/internal-squads` with `name: "Default MVP Squad"` linking all 4 inbound UUIDs, verify read-back via `GET /api/internal-squads/{uuid}`, and implement idempotent sync
- [ ] 8.6 Implement automated GoWave Host record provisioning via `POST /api/hosts` for each of the 4 MVP protocols, mapping public hostname, port 443, SNI, path, `"nodes": ["<node-uuid>"]`, `"internalSquads": {"mode": "ALLOW_ONLY", "squads": ["<squad-uuid>"]}`, and verified `securityLayer` values (`DEFAULT` for REALITY, `TLS` for XHTTP, WS, and Trojan gRPC), and verify read-back via `GET /api/hosts`
- [ ] 8.7 Implement initial user lifecycle provisioning: create an active user via `POST /api/users` assigned to the managed Internal Squad (`activeInternalSquads: ["<squad-uuid>"]`), wait for node user-sync (`syncUserToSingleNode`), and extract the user's `shortUuid`
- [ ] 8.8 Verify and configure GoWave Response Rules (`DisableSubscriptionAccessByPath=false`), verify default templates (`MIHOMO` with `GEOIP,private,DIRECT,no-resolve` private network bypass and `XRAY_JSON`), and configure UA rules requiring non-empty User-Agent headers
- [ ] 8.9 Generate, verify, and display both deterministic per-user subscription links (`GET /api/sub/{shortUuid}/v2ray-json` with Xray UA and `GET /api/sub/{shortUuid}/mihomo` with Mihomo UA), verifying HTTP 200, valid Content-Type, non-empty parseable bodies, zero loopback/internal leaks, outputting both links in installer completion summary, and providing CLI helper command `gowave-auto-nginx user links <id>`
- [ ] 8.10 Issue scoped long-lived API token via `POST /api/tokens` with subscription-page and user scopes for external web subscription frontends (`remnawave/subscription-page`) and bots, saving API credentials to `/root/gowave-credentials.txt` with mode `0600`

## 9. Transaction-Safe Updates and Crash Recovery Journal

- [ ] 9.1 Implement preflight SQLite check (`PRAGMA integrity_check;`) and WAL checkpoint (`PRAGMA wal_checkpoint(TRUNCATE);`) with 5s busy timeout
- [ ] 9.2 Execute transactional database backup using staged SQLite Online Backup under service user privileges: root pre-creates empty file `/opt/gowave/.backup-<ts>.db` with mode `0640` and ownership `gowave:gowave` (`install -o gowave -g gowave -m 0640 /dev/null ...`), gowave runs `sqlite3 .backup` into the pre-created file, root moves backup copy to recovery snapshot directory with mode `0600`, restores database file permissions (`chown gowave:gowave`, mode `0640`), and verifies destination integrity
- [ ] 9.3 Maintain durable state journal at `/var/lib/gowave-auto-nginx/recovery/journal.json` using atomic write (`.tmp` + file `fsync` + `rename` + directory `fsync`) tracking both initial provisioning (`PROVISION_PREPARED`, `PROVISION_APPLYING`, `PROVISION_VERIFYING`, `PROVISION_COMMITTED` with 6-stage reverse-order rollback) and updates (`PREPARED`, `APPLYING`, `VERIFYING`, `COMMITTED`, `ROLLBACK_REQUIRED`, `ROLLED_BACK`)
- [ ] 9.4 Implement channel switching command `gowave-auto.sh channel [stable|dev]` with automated pre-switch SQLite snapshot, migration irreversible downgrade warning with `--force` confirmation, asset update with SHA256 checksums, and rollback on failure
- [ ] 9.5 Implement staged release download, SHA256 checksum verification, atomic file swap, and service restart
- [ ] 9.6 Implement post-update health probe with automated rollback: restore DB and binary from `/var/lib/.../recovery/` upon healthcheck timeout or failure
- [ ] 9.7 Implement boot-time crash recovery: check `journal.json` on script startup, automatically completing rollback if an update was interrupted by power loss (`APPLYING` or `VERIFYING`), or executing 6-stage reverse rollback for interrupted initial setups (`PROVISION_APPLYING` or `PROVISION_VERIFYING`) via entity deletion (Token, User, Hosts, Squad, Node, Profile) from `state.json.tmp`
- [ ] 9.8 Hook into systemd unit `gowave-update.service` so that in-panel web UI update triggers automatically execute the pre-update snapshot
- [ ] 9.9 Enforce snapshot retention policy: retain the last 3 snapshots, enforce a 5 GB storage ceiling, and prune older snapshots after transaction commit

## 10. Hardened Backup and Restore Format v1 Implementation

- [ ] 10.1 Implement `assets/backup/gowave-backup.sh` creating `GoWave Auto NGINX Backup Format v1` unencrypted gzip archives containing databases, `.env`, node credentials, NGINX configurations, and `meta.json` with permissions `0600`
- [ ] 10.2 Implement separate backup commands for Central Panel (`--type panel`) and Edge Worker nodes (`--type node`)
- [ ] 10.3 Implement 12-point Python preflight validator rejecting archives with path traversal (`..`, leading `/`), symlink escapes outside managed roots, hardlinks to non-files, device nodes, decompression bombs (> 5,000 files, > 1 GB), or oversized metadata
- [ ] 10.4 Implement pre-restore persistent snapshotting in `/var/lib/gowave-auto-nginx/recovery/restore-<timestamp>/` with transaction state tracking persisting across system reboots
- [ ] 10.5 Implement automated restore rollback reverting files and restarting services if post-restore health verification fails

## 11. Interactive Management Interface

- [ ] 11.1 Implement interactive CLI menu in `gowave-auto.sh` providing `status`, `health`, `install`, `update`, `channel`, `node` (`node add/list/remove`), `domain-change`, `backup`, `restore`, and `uninstall`
- [ ] 11.2 Implement non-interactive CLI flags for all commands enabling headless execution and Ansible integration
- [ ] 11.3 Implement exclusive file locking (`/run/lock/gowave-auto.lock`) preventing concurrent conflicting operations
- [ ] 11.4 Implement installation progress checkpoints allowing resumed execution or safe rollback on interrupted initial setups
- [ ] 11.5 Implement atomic domain change with DNS preflight validation and rollback to old domain if ACME challenge fails
- [ ] 11.6 Implement safe uninstall inspecting `# Managed by GoWave Auto NGINX` ownership markers, cleanly removing project vhosts, `/opt/gowave`, `/opt/gowave-node`, and the stream block in `/etc/nginx/nginx.conf` without purging system packages

## 12. 5-Suite Testing Architecture & Verification

- [ ] 12.1 Implement `tests/run_ci.py` with explicit `SUITES` registry (`nonroot`, `root`, `integration`, `services`, `systemd`) and `--check-completeness` enforcement
- [ ] 12.2 Enforce EUID privilege separation: require `os.geteuid() != 0` for `nonroot`, `integration`, and `services`; require `os.geteuid() == 0` for `root` (container) and `systemd` (QEMU)
- [ ] 12.3 Implement Suite `nonroot`: ShellCheck, Python linting, OpenSpec validation (`openspec validate --all --strict`), NGINX config compilation with runtime version detection for Debian 12 (1.22.1) and Ubuntu 24.04 (1.24.0) using `listen ... ssl http2;` and Ubuntu 26/Debian 13 using `http2 on;`, and malicious tarball rejection
- [ ] 12.4 Implement Suite `integration`: concurrent SQLite writes during `.backup`, GoWave API admin bootstrap, single unified profile provisioning, profile cross-membership negative test, Internal Squad creation, user provisioning with squad assignment, Host entity creation (`POST /api/hosts`) with `nodes` and `internalSquads` read-back verification, and mTLS 1.3 handshake verification
- [ ] 12.5 Implement Suite `services`: live daemon execution, client REALITY handshake, scanner fallback to 9443 cover site, XHTTP bidirectional streaming, WebSocket upgrade, live Trojan gRPC handshake over HTTP/2 with password authentication, Worker direct edge client tunneling, separate retrieval of Xray JSON and Mihomo YAML with User-Agent positive and negative tests, client parser validation via official Xray (`v1.8.24`+) and Mihomo (`v1.19.22`+) binaries, and dual-stack IPv4/IPv6 external port 3002 isolation check
- [ ] 12.6 Implement Suite `root`: user/group creation (`gowave:gowave`), sticky bit permissions (1770), service install verification, zero-leak secret delivery verification, and Fail2ban syntax check
- [ ] 12.7 Integrate GoWave Node upstream test suite: run `go test ./...`, `go vet`, ShellCheck, `python3 tests/test_scripts.py`, and `gowave-node status --wait-ready` CLI verification
- [ ] 12.8 Implement Suite `systemd` QEMU TCG runner (`tests/systemd/boot.sh`): verify PID 1 systemd cold boot, All-in-One port bindings, service persistence across reboot, power cut journal recovery, and backup/restore across Ubuntu 24.04, 26.04, Debian 12, and Debian 13
- [ ] 12.9 Implement `tests/podman_testbed.sh` compiling systemd-enabled testbed images via `tests/Containerfile.testbed` (installing systemd, systemd-sysv, dbus, python3-systemd, openssh-server, openssh-client), automating container lifecycle (`--systemd=always --privileged`), workspace mounting, 8-stage test execution, and cleanup across Ubuntu 24.04, Ubuntu 26.04, Debian 12, and Debian 13
- [ ] 12.10 Enforce mandatory local Podman pre-flight validation gate: require passing testbed runs across all 4 target operating systems prior to production VPS deployment
- [ ] 12.11 Implement multi-node E2E test target in `tests/podman_testbed.sh` (`multi-node`): provision 3-container Podman bridge network (`gowave-panel` at `10.89.0.10`, `gowave-worker` at `10.89.0.20`, and `gowave-untrusted` at `10.89.0.30`), deploy remote worker via `gowave-node-auto.sh` over SSH stdin, verify UFW drops traffic from untrusted peer while allowing panel IP, validate mTLS 1.3 handshake, push inbounds/users, and verify direct edge VPN client traffic

## 13. CI/CD Workflows and Acceptance

- [ ] 13.1 Implement GitHub Actions workflow `lint-and-nonroot.yml` running ShellCheck, actionlint, completeness check, and Suite `nonroot`
- [ ] 13.2 Implement GitHub Actions workflow `root-integration.yml` running Suite `root` (as EUID 0) and Suite `integration` (under unprivileged container user `--user 1001:1001` with EUID != 0)
- [ ] 13.3 Implement GitHub Actions workflow `systemd-acceptance.yml` executing Suite `services` and Suite `systemd` QEMU tests across all 4 target OSs
- [ ] 13.4 Implement `tools/prepare_release.py` generating reproducible release archives with pinned commit SHAs and SHA256 checksum sidecars
- [ ] 13.5 Execute full end-to-end acceptance install, domain change, update with simulated crash, and backup/restore verification on a clean VM
