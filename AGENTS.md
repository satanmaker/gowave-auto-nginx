# GoWave Auto NGINX: Agent and Developer Guidelines

## 1. Project Purpose & Scope

GoWave Auto NGINX is a standalone, modular infrastructure installer and lifecycle manager for the [GoWave](https://github.com/aaaSaZaN/gowave) ecosystem. It delivers:
- Single-command All-in-One deployment (GoWave Panel + local GoWave Node) without port conflicts.
- High-performance NGINX Stream SNI demultiplexing on port 443 with REALITY loopback fallback to static camouflage decoy sites.
- Deterministic per-user Xray JSON and Mihomo YAML subscription delivery with mandatory User-Agent compliance.
- Automated Host record provisioning linking public domain/IP to nodes and managed Internal Squads.
- Transaction-safe updates and channel switching (`stable` vs `dev`) with pre-update SQLite Online Backup and crash recovery journaling.
- Distributed Edge worker deployment (`gowave-node-auto.sh`) via SSH stdin pipelines with complete traffic-plane offloading.
- VPS host hardening (non-destructive SSH inspection, Fail2ban with systemd backend, strict DoT, UFW, swap, and BBR sysctl tuning).
- Hardened Backup & Restore Format v1 with 15-point preflight validation.

Supported platforms: Ubuntu 24.04 LTS, Ubuntu 26.04 LTS, Debian 12 (Bookworm), and Debian 13 (Trixie).

---

## 2. Modular Architecture & Code Standards

The codebase adheres strictly to modular separation of concerns:

```
├── gowave-auto.sh             # Central lifecycle manager and CLI entrypoint
├── gowave-node-auto.sh        # Distributed Edge worker installer & orchestrator
├── assets/
│   ├── backup/                # Backup & Restore Format v1 (gowave-backup.sh)
│   ├── cover-sites/           # Static multi-asset camouflage sites (cover-reality)
│   ├── security/              # Host hardening & non-destructive SSH (managed.py)
│   └── xray/                  # Canonical raw inbound templates for MVP profiles
├── modules/                   # Reusable Bash submodules (os, preflight, nginx, systemd, api, ufw)
├── config/                    # Systemd units, logrotate, and NGINX templates
├── tests/                     # 5-suite CI test architecture, runners, and fixtures
└── tools/                     # Release automation and helper scripts (prepare_release.py)
```

### Module Boundaries
- **No Monolithic Bloat**: Keep shell scripts modular. Common logic is encapsulated in `modules/` and sourced cleanly.
- **External Proxy Contract**: Always set `GOWAVE_PROXY=external` in `/opt/gowave/.env` so GoWave never tampers with NGINX.
- **No Upstream Source Modifications**: GoWave and GoWave Node are treated as immutable upstream binaries. All integration occurs via documented network ports, REST APIs, and systemd interfaces.
- **Process Supervision Policy**: Xray-core is supervised strictly by `gowave-node`. Do not create separate watchdog timers or systemd units for Xray.

---

## 3. Shell Formatting & Scripting Standards

All Bash scripts (`*.sh`) must follow these strict requirements:
1. **Strict Error Handling**: Every script begins with:
   ```bash
   #!/usr/bin/env bash
   set -euo pipefail
   ```
2. **Linting & Validation**:
   - Must pass `bash -n <script>` syntax check.
   - Must pass `shellcheck --severity=error <script>` without errors.
3. **Variable Expansion & Quoting**:
   - Double-quote all variable references: `"$var"`, `"${array[@]}"`.
   - Never use unquoted `$*` or `$@`.
4. **Subshell & Pipe Safety**:
   - Wrap commands in functions with local variable scoping (`local var=...`).
   - Guard against stdin stealing when looping over lines or streaming over SSH by redirecting from `/dev/null` (`command </dev/null`).
5. **Atomic File Mutations**:
   - Write files via temporary siblings followed by `fsync` and `rename`:
     `write to file.tmp -> sync -> mv file.tmp file -> sync directory`.

---

## 4. Zero-Leak Credential Requirements

Protecting sensitive credentials is a non-negotiable security requirement:
1. **No Secrets in CLI Arguments (`argv`)**:
   - Secrets (`SECRET_KEY`, admin passwords, JWT tokens, private keys) must **NEVER** be passed as command-line arguments.
   - Passing secrets in `argv` leaks them via `/proc/<pid>/cmdline`, `ps aux`, and system audit logs.
2. **Standard Input & Secure File Delivery**:
   - Pass secret keys and tokens via standard input (`stdin`) or temporary files with POSIX mode `0600`.
   - Temporary files must be created in `mode 0600` and cleaned up immediately in signal traps (`trap 'rm -f "$tmp"' EXIT HUP INT TERM`).
3. **Remote SSH Streaming (`remote_payload`)**:
   - When orchestrating remote worker nodes, serialize variables strictly over the SSH stdin stream (`ssh -T ... 'bash -s'`).
   - Unset secret variables immediately after ingestion:
     `trap 'unset _NODE_SECRET_KEY SECRET_KEY' EXIT HUP INT TERM`.
4. **Credential File Security**:
   - Initial administrative credentials are saved to `/root/gowave-credentials.txt` with mode `0600` and immediate directory sync before calling registration APIs.
5. **Clean Logs**:
   - Never echo or log passwords, session tokens, or private keys to stdout, stderr, or journal logs.
