# GoWave Auto NGINX

**One-command, rollback-safe NGINX + REALITY deployment for the [GoWave](https://github.com/aaaSaZaN/gowave) ecosystem.**

GoWave Auto NGINX is a standalone, modular installer and lifecycle manager. It deploys a GoWave Panel
and a local GoWave Node on one host without port conflicts, demultiplexes public TLS traffic on port 443,
delivers per-user VPN-client subscriptions, provisions additional edge workers over SSH, and keeps the
whole stack updatable with transaction safety, crash recovery and rollback on every mutating path.

## What it delivers

- **Three deployment variants** — Panel-only (Panel and a static camouflage site, no traffic plane),
  All-in-One (Panel + local GoWave Node on a single host, for trial and evaluation), and All-in-One plus
  remote nodes onboarded over SSH.
- **Interactive setup wizard** — an argument-less `install` on a terminal asks language (EN/RU), variant,
  node count and every host name, validates the plan as DNS names, prints the certificate count, and only
  then runs the same commands the positional path runs.
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

```bash
git clone https://github.com/satanmaker/gowave-auto-nginx.git
cd gowave-auto-nginx
sudo ./gowave-auto.sh install vpn.example.com cdn.example.com acme@example.com
sudo ./gowave-auto.sh node add worker-1 203.0.113.10 worker-1.example.com cdn.example.com
```

An argument-less `install` opens the setup wizard, which needs a terminal; without one it exits with the
usage message that names the arguments. Administrative credentials are written to
`/root/gowave-credentials.txt` (mode `0600`). Running `./gowave-auto.sh` with no arguments opens the menu
and the command usage; `./gowave-auto.sh` with an unknown command prints the full command surface.

## Deployment variants

The three positional arguments are `<panel-domain> <camouflage-domain> <acme-email>`, with an optional
fourth Vision domain:

```bash
# Panel-only: Panel and a static camouflage site; no local node, no traffic plane.
sudo ./gowave-auto.sh install --panel-only vpn.example.com cdn.example.com acme@example.com

# All-in-One: Panel plus a local GoWave Node on this host (trial and evaluation only).
sudo ./gowave-auto.sh install vpn.example.com cdn.example.com acme@example.com

# All-in-One with the optional Vision inbound on this host.
sudo ./gowave-auto.sh install vpn.example.com cdn.example.com acme@example.com vision.example.com
```

All-in-One is recommended only for testing and familiarising yourself with the UI: a single host is both
the control plane and the traffic plane, so it is not a production topology. A production deployment is
Panel-only or All-in-One on the Panel host plus remote Workers, each onboarded with `node add`.

## Remote node onboarding over temporary access

`node add` takes the same inputs from the environment as from positionals, so a scripted onboarding does
not have to build an argument list:

| Variable | Positional | Default |
| --- | --- | --- |
| `GOWAVE_NODE_NAME` | `<worker-name>` | required |
| `GOWAVE_NODE_IP` | `<worker-ip>` | required |
| `GOWAVE_WORKER_DOMAIN` | `<worker-domain>` | required |
| `GOWAVE_REALITY_DOMAIN` | `<reality-domain>` | required |
| `GOWAVE_SSH_USER` | `[ssh-user]` | `root` |
| `GOWAVE_SSH_PORT` | `[ssh-port]` | `22` |
| `GOWAVE_VISION_DOMAIN` | `--vision-domain <domain>` | none |
| `XRAY_SERVER_VERSION` | — | `26.11.9` (unset installs the pin; `latest` opts out) |

A non-empty positional (or `--vision-domain`) wins over its variable, an empty variable counts as unset,
and both paths validate the same fields through the same contract, so an invalid value is refused on the
field it belongs to. No secret is accepted here: the Worker secret is read from the Panel's `.env` and
passed to the remote side over stdin, never as an argument or an exported variable.

```bash
sudo GOWAVE_NODE_NAME=worker-1 GOWAVE_NODE_IP=203.0.113.10 \
  GOWAVE_WORKER_DOMAIN=worker-1.example.com GOWAVE_REALITY_DOMAIN=cdn.example.com \
  ./gowave-auto.sh node add
```

The wizard onboards each Worker without leaving a standing key behind:

- The Worker's Ed25519 host-key SHA-256 fingerprint is shown and must be typed in full; a mismatch refuses
  the onboarding before any key is written.
- Non-interactive inputs are `GOWAVE_SSH_FINGERPRINT` (the value the operator read from the Worker) and
  `GOWAVE_SSH_PASSWORD_FILE` (a file with mode `0600`; a `0644` file is refused). The password is read
  once and is never placed in a command line.
- A systemd timer on the Worker removes the temporary `authorized_keys` entry within two hours. The same
  entry is revoked at the end of `node add`, on success and on failure, and the timer is disabled and
  deleted with it.

### The pinned Xray core

A node installation places the pinned Xray core (`<install_dir>/rw-core`) before the upstream installer
runs, so a default installation makes no `api.github.com` request and the version the node runs is the one
this repository pins. Three consequences are worth knowing before an install:

- An undeliverable or unverifiable pinned archive stops the installation, naming the artifact and the
  pinned version, instead of falling back to the upstream download. `XRAY_SERVER_VERSION=latest` is the
  way out: it restores the previous behaviour and lets the installer fetch its own core.
- On a host that never had a managed core installation, `gowave-node core reset` answers
  `no managed stock core is available`; the file this installer places has no `.stock` backup behind it.
- The release archive and the geodata files still come from `github.com`. That path costs no API quota,
  and this installer does not remove it.

## Domain and certificate policy

Every host spends `2 + v_panel + 2N + k` certificates: the Panel name, the camouflage apex and `www`,
each worker's panel and camouflage names, and each Vision domain. Let's Encrypt allows **50 certificates
per registered domain per 7 days**, and that budget is shared by the whole cluster and by anything else
on the registered domain. The preflight's node ceiling follows from that limit: **24** nodes with no
Vision, **23** with Vision on the Panel host only, **16** with Vision everywhere under a Panel-only
Panel, and **15** with Vision everywhere under an All-in-One Panel.

Three limits are part of the policy, not implementation details:

- **The remaining budget cannot be queried.** Let's Encrypt exposes no endpoint for it, so the preflight
  counts only the plan in front of it and never claims a remaining figure.
- **The apex and `www` camouflage certificate belongs to a single host.** A second host on the same
  registered apex cannot serve that website; it can only run a decoy at its own subdomain.
- **Wildcard is not a remedy for a shared domain.** Every host would order the identical
  `[domain, *.domain]` identifier set, and the five-per-exact-set limit would cap a shared-domain cluster
  at about five hosts per week — worse than the ceilings above.

## Safety model

- Exclusive **mutation lock** — one mutating operation at a time, never concurrent installs.
- **Atomic file mutations** — temp sibling → `fsync` → `rename` → directory sync.
- **Rollback everywhere** — certificate issuance, UFW declarations, domain changes, worker joins and
  recovery journals all roll back on failure instead of leaving a half-configured host.
- **Zero-leak credentials** — secrets travel via stdin or `0600` temp files with signal traps; never
  command-line arguments, never logs. GoWave and Xray credentials are unlinked immediately after use.

## Specification-driven with real acceptance runs

The behaviour is pinned by OpenSpec specifications in `openspec/specs/`: the specs carry
**70 requirements / 237 GIVEN-WHEN-THEN acceptance scenarios**. Each scenario is executed by one of two
runners rather than only eyeballed in code review:

- **Podman E2E** (`tools/run_podman_e2e.py`) — a rootful 4-distribution container testbed that
  incubates every new scenario in minutes. Local invocation, prerequisites, budgets, the failure
  bundle, artifact retention and cleanup are documented in [`docs/PODMAN_E2E.md`](docs/PODMAN_E2E.md),
  and every scenario is tied to its cases, matrix rows, tests and CI job in
  [`docs/PODMAN_E2E_TRACEABILITY.md`](docs/PODMAN_E2E_TRACEABILITY.md).
- **Live VPS E2E** (`tools/run_live_vps.py`) — the same acceptance catalog driven against real clean-room
  virtual servers; scenarios graduate here from the container suite.

## Repository layout

```
gowave-auto.sh            lifecycle manager (install, channel, node, domain-change, backup, restore, uninstall)
gowave-node-auto.sh       distributed edge worker orchestrator
modules/                  lock, os detection, preflight, security, panel API, node, nginx, recovery
config/ assets/           systemd units, logrotate, NGINX templates, SNI decoy sites
openspec/                 specs + active changes (proposal → design → tasks, strict validation)
tools/                    E2E runners (podman, live VPS), acceptance gate, release prep
tests/                    podman multi-node, security, recovery, panel API suites
docs/                     live-VPS testing guide, E2E scenario catalog
```

Panel releases are upgraded from the Panel's own interface: the installer provisions the `gowave-update.path`
trigger and the root oneshot it starts, so `gowave-auto.sh` stays on server-side operations — `install`,
`channel`, `node`, `domain-change`, `backup`, `restore`, `uninstall` and `recover`.

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
