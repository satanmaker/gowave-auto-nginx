# Live VPS End-to-End Testing Guide & Acceptance Gate

This document serves as the operational guide for executing the GoWave Auto NGINX Live VPS End-to-End Test Runner (`tools/test_live_vps.py`) on disposable real VPS instances over the public internet.

---

## 1. Overview & Architecture

The Live VPS Test Runner executes end-to-end infrastructure lifecycle, deployment, protocol routing, subscription delivery, client Data Plane traffic, fault injection, and teardown across a distributed pair of disposable VPS:
- **Master VPS**: Runs GoWave Panel, local GoWave Node, NGINX Stream SNI demultiplexer, ACME certificates, and web camouflage.
- **Worker VPS**: Runs distributed edge GoWave Node, NGINX Stream SNI router, ACME certificates, and camouflage fallback.
- **Control Machine**: Orchestrator host executing `tools/test_live_vps.py` with pinned client binaries (`xray`, `mihomo`, `ssh`, `openssl`, `dig`).

---

## 2. VPS Prerequisites & Disposable Gate

The test runner operates exclusively on disposable test servers that pass the read-only Disposable Gate in Phase 0:
1. **Operating System**: Clean installation of Ubuntu 24.04 LTS, Ubuntu 26.04 LTS, Debian 12 (Bookworm), or Debian 13 (Trixie).
2. **Access**: Direct root SSH access (`MASTER_SSH_USER=root`, `WORKER_SSH_USER=root`).
3. **Clean Baseline**:
   - No existing GoWave directories (`/opt/gowave`, `/opt/gowave-node`, `/var/lib/gowave-auto-nginx`).
   - No port conflicts on required listening ports (80, 443, 8080, 8443, 8444, 9443, 9444, 3000, 3001).
   - Unmodified standard firewall state.
   - Pinned system utilities present (`python3`, `tar`, `curl`, `systemd`).

---

## 3. DNS Configuration

All required domains must resolve authoritatively to the public IPv4 (and optionally IPv6) addresses of the corresponding VPS before execution:

| VPS | Mandatory FQDN Role | Example Config Key |
|---|---|---|
| **Master** | Panel HTTPS Web UI & API | `MASTER_PANEL_DOMAIN` |
| **Master** | Camouflage Decoy / REALITY SNI | `MASTER_REALITY_DOMAIN` |
| **Master** | *(Optional)* VLESS XTLS Vision SNI | `MASTER_VISION_DOMAIN` |
| **Worker** | Worker HTTPS / Subscription | `WORKER_DOMAIN` |
| **Worker** | Camouflage Decoy / REALITY SNI | `WORKER_REALITY_DOMAIN` |
| **Worker** | *(Optional)* VLESS XTLS Vision SNI | `WORKER_VISION_DOMAIN` |

### IPv6 & DNS Consistency Rules
- If `ENABLE_IPV6=false`, **no** domain may publish an `AAAA` record. Any published `AAAA` record fails preflight before any SSH connection.
- If `ENABLE_IPV6=true`, all domains must publish matching `AAAA` records resolving strictly to the target VPS IPv6 address.
- At least two independent public resolvers (e.g. 1.1.1.1, 8.8.8.8) are queried; resolver disagreement or CDN proxying (e.g. Cloudflare proxy orange cloud) fails preflight immediately.

---

## 4. SSH Authentication & Host Key Pinning

SSH security requires strict key isolation and host key verification:
1. **Private Keys**: Mode `0600`, regular non-symlink file owned by runner user.
2. **Known Hosts**: Pre-pinned host keys for both Master and Worker in `SSH_KNOWN_HOSTS` (or per-host `MASTER_KNOWN_HOSTS_PATH` / `WORKER_KNOWN_HOSTS_PATH`).
3. **Zero Secrets in Argv**: All secrets, environment variables, and tokens are delivered strictly over SSH `stdin` pipelines or secured temporary files (`0600`), never via CLI arguments.

---

## 5. Configuration Setup

Copy the template and configure your test environment:
```bash
cp tools/live_vps_config.env.example tools/live_vps_config.env
chmod 0600 tools/live_vps_config.env
```
Populate `tools/live_vps_config.env` with your real VPS IP addresses, FQDNs, SSH key paths, and pinned software versions. Note that `tools/live_vps_config.env` is ignored by git and must never be committed.

### REALITY Fingerprint and Client Compatibility

| Key | Default | Purpose |
|---|---|---|
| `REALITY_FINGERPRINT` | `chrome` | uTLS preset written to REALITY Host records and asserted by subscription validation |
| `ALT_MIHOMO_CORE` | unset | Absolute path to a mihomo-compatible core (for example Prizrak-Core) run as a second traffic client |

`chrome` is the default because of a client-side limitation, not a server one: `metacubex/utls` maps `HelloFirefox_Auto` to the Firefox 120 preset, and the X25519MLKEM768 key share exists only in the Chrome 131/133 presets. Upstream mihomo therefore fails REALITY authentication while the subscription advertises `client-fingerprint: firefox`, even with `support-x25519mlkem768: true`. Xray clients accept either preset, and Vision/XHTTP/WS/Trojan-gRPC hosts keep `firefox`.

Set `REALITY_FINGERPRINT=firefox` only for client fleets that ship a post-quantum Firefox ClientHello (Prizrak-Core does). The installer prints a warning for any non-chrome value, and the traffic phase will report FAIL for upstream mihomo in that mode.

`ALT_MIHOMO_CORE` keeps the upstream `mihomo` binary as the mandatory client and adds a second, optional suite against the same fetched subscription. Failures of the alternative client are gated the same way once it runs; leaving the key unset skips it entirely.

---

## 6. ACME Modes: Staging vs Production

- **`ACME_MODE=staging` (Default)**:
  Uses the Let's Encrypt Staging ACME v2 endpoint (`https://acme-staging-v02.api.letsencrypt.org/directory`).
  Prevents hitting production rate limits (5 certs per week per domain set). The runner automatically verifies and stages the pinned Let's Encrypt Staging CA bundle (`tools/certs/letsencrypt-staging/`) on the Control Machine and Master VPS.
- **`ACME_MODE=production`**:
  Uses the Let's Encrypt Production ACME v2 endpoint.
  Reserved for final acceptance verification prior to production rollout.

---

## 7. Execution Modes & CLI Usage

The CLI `tools/test_live_vps.py` supports atomic execution and progressive phase resume:

```bash
# Full execution across all phases (preflight -> install -> verify -> traffic -> negative -> teardown)
python3 tools/test_live_vps.py --config tools/live_vps_config.env --mode full

# Phase 0 only: Read-only preflight and baseline capture (outputs generated TEST_RUN_ID)
python3 tools/test_live_vps.py --config tools/live_vps_config.env --mode preflight

# Resume subsequent phases using the authenticated run ID:
python3 tools/test_live_vps.py --config tools/live_vps_config.env --mode install --run-id <RUN_ID>
python3 tools/test_live_vps.py --config tools/live_vps_config.env --mode verify --run-id <RUN_ID>
python3 tools/test_live_vps.py --config tools/live_vps_config.env --mode traffic --run-id <RUN_ID>
python3 tools/test_live_vps.py --config tools/live_vps_config.env --mode negative --run-id <RUN_ID>
python3 tools/test_live_vps.py --config tools/live_vps_config.env --mode teardown --run-id <RUN_ID>
```

---

## 8. Test Artifacts & Diagnostics

Every run generates an isolated artifact bundle under `artifacts/live-vps/<TEST_RUN_ID>/`:
- `result.json`: Comprehensive structured machine-readable result of all test phases.
- `junit.xml`: JUnit-format test suite report for CI integration.
- `summary.txt`: Human-readable test report.
- `run-state.json`: State file recording prerequisites, baseline hashes, and phase statuses (mode `0600`).
- `diagnostics/`: Sanitized logs and system telemetry with all credentials redacted.

---

## 9. Pre-Deployment Acceptance Gate Rule

> [!IMPORTANT]
> **Pre-Deployment Acceptance Gate Requirement (Task 10.11)**
>
> No release or PR merging `feature/live-vps-e2e-testing` into production/main branches may proceed without satisfying the complete 5-point Pre-Deployment Acceptance Gate:
>
> 1. **Codebase Implementation Complete**: All tasks across Sections 1 through 10 of OpenSpec change `live-vps-e2e-testing` are implemented and verified in the reviewed commit.
> 2. **CI Suite Completeness & Pass**: All standard CI suites (`tests/run_ci.py --check-completeness` and `python3 tests/run_ci.py --suite nonroot`) pass with zero errors.
> 3. **Runner Unit & Integration Tests**: All runner test suites under `tools/tests/` (`python3 -m unittest discover -s tools/tests`) pass with zero errors.
> 4. **OpenSpec Strict Validation**: Strict validation across all changes and specs (`openspec validate --all --strict`) passes with zero warnings or errors.
> 5. **Live VPS Staging Run**: A complete ACME staging execution (`--mode full` with `ACME_MODE=staging`) executed on freshly provisioned, disposable VPS instances must achieve an overall verdict of `PASS` with verified teardown.
>
> *A green mock CI run, documentation-only PR, or simulated unit test run is NOT evidence that the runner is ready for two-VPS rollout.*
