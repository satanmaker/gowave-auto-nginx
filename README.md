# GoWave Auto NGINX

**One-command, rollback-safe NGINX + REALITY deployment for the [GoWave](https://github.com/aaaSaZaN/gowave) ecosystem.**

GoWave Auto NGINX is a standalone, modular installer and lifecycle manager. It deploys a GoWave Panel
and a local GoWave Node on one host without port conflicts, demultiplexes public TLS traffic on port 443,
delivers per-user VPN-client subscriptions, provisions additional edge workers over SSH, and keeps the
whole stack updatable with transaction safety, crash recovery and rollback on every mutating path.

## What it delivers

- **All-in-One deployment** — GoWave Panel + local GoWave Node on a single host, no port conflicts.
- **NGINX Stream SNI demultiplexing on :443** with **REALITY loopback fallback** to static camouflage
  decoy sites: unrecognised traffic is dropped to the decoy, never proxied.
- **Deterministic subscriptions** — per-user Xray JSON and Mihomo YAML with mandatory `User-Agent`
  compliance, so each client family always gets the format it can import.
- **Distributed edge workers** — `gowave-node-auto.sh` provisions extra hosts over an SSH stdin pipeline
  with full traffic-plane offload, mTLS control plane and rollback.
- **Transaction-safe lifecycle** — updates and `stable`/`dev` channel switching with pre-update SQLite
  online backup and crash-recovery journaling; every mutation runs under an exclusive lock.
- **Host hardening** — non-destructive SSH inspection, Fail2ban (systemd backend), strict DNS-over-TLS,
  UFW, swap and BBR sysctl tuning.
- **Backup & Restore v1** with a 15-point preflight validation.

Supported platforms: **Ubuntu 24.04 / 26.04 LTS, Debian 12 / 13**, bash + root on a fresh host.

## Quick start

This default branch carries the specification baseline and the audit trail. The complete modular
product — lifecycle modules, hardened NGINX/Xray assets, cover-site generation and the E2E runners —
rides on the `feature/podman-full-e2e` integration branch and lands here at acceptance close. To run:

```bash
git clone -b feature/podman-full-e2e https://github.com/satanmaker/gowave-auto-nginx.git
cd gowave-auto-nginx
sudo ./gowave-auto.sh install vpn.example.com cdn.example.com acme@example.com
sudo ./gowave-auto.sh node add worker-1 203.0.113.10 worker-1.example.com cdn.example.com
```

Omitting arguments drops into interactive prompts. Administrative credentials are written to
`/root/gowave-credentials.txt` (mode `0600`). See `./gowave-auto.sh help` for the full command surface.

## Safety model

- Exclusive **mutation lock** — one mutating operation at a time, never concurrent installs.
- **Atomic file mutations** — temp sibling → `fsync` → `rename` → directory sync.
- **Rollback everywhere** — certificate issuance, UFW declarations, domain changes, worker joins and
  recovery journals all roll back on failure instead of leaving a half-configured host.
- **Zero-leak credentials** — secrets travel via stdin or `0600` temp files with signal traps; never
  command-line arguments, never logs. GoWave and Xray credentials are unlinked immediately after use.

## Specification-driven acceptance

The behaviour is pinned by an OpenSpec change under `openspec/changes/gowave-auto-nginx/`: six
capability specifications (lifecycle management, traffic routing, protocol profiles, panel-node
integration, VPS security, backup/recovery) carry **48 requirements / 95 GIVEN-WHEN-THEN acceptance
scenarios**. Scenarios are executed by two runners — **Podman E2E** (a rootful 4-distribution container
testbed) and **Live VPS E2E** (the same catalog against real clean-room servers) — rather than only
eyeballed in code review; both runners ship on the integration branch.

## Repository layout

```
gowave-auto.sh            lifecycle manager CLI entrypoint (install, update, node, domain-change, backup, uninstall)
gowave-node-auto.sh       distributed edge worker orchestrator
modules/                  panel API client and transactional recovery tooling (Python + shell)
openspec/                 pinned change: proposal, design, tasks, capability specs, decision register
tests/                    security, panel-API and node-integration suites
tools/                    test tooling
```

## Provenance

GoWave (`6d2c357`) and GoWave Node (`7b3514d`) are pinned by upstream commit and treated as immutable:
neither binary nor source tree is modified or vendored, and all integration happens through documented
ports, REST endpoints and systemd units only.

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md). In short: `feature/<topic>` branches, `set -euo pipefail` +
`shellcheck` for all shell code, PEP-8 with standard-library-only Python, and the same zero-leak
credential policy everywhere.

## License

[GPL-3.0](LICENSE). GoWave and GoWave Node are external projects used unmodified and remain under
their own licenses.
