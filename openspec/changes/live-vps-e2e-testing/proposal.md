# Proposal

## Why

GoWave Auto NGINX has a comprehensive mock-and-static CI suite (5 suites, QEMU cold-boot matrix, ShellCheck, unit
tests), but `tests/podman_testbed.sh multi-node` explicitly returns exit code `77` — there is no implemented
distributed E2E on real VPS hardware. Successful CI green does not prove that user VPN traffic traverses all
expected protocol endpoints (eight core endpoints by default across four protocols, or ten endpoints when both Master and Worker
VLESS XTLS Vision domains are configured) on real Master and Worker VPS over the public internet.

A dedicated Live VPS E2E Test Runner is needed to close this gap and provide a production-grade acceptance gate
that validates the complete infrastructure lifecycle — from bare OS through deployment, mTLS control plane,
subscription delivery, and actual Data Plane tunnel traffic — on disposable real servers.

## What Changes

- **New tool** `tools/test_live_vps.py` — Python 3.10+ E2E Test Runner with structured submodule package
  `tools/live_vps/`.
- **New configuration** `tools/live_vps_config.env.example` — whitelist-parsed env configuration with complete
  parameter documentation. `tools/live_vps_config.env` added to `.gitignore`.
- **New workflows** `.github/workflows/live-vps-e2e.yml` (`workflow_dispatch`-only CI acceptance job using
  GitHub Environment secrets) and `.github/workflows/live-vps-unit.yml` (automated unit test CI executing
  the runner submodule test suite under `tools/tests/`).
- **New documentation** `docs/LIVE_VPS_TESTING.md` — operator guide covering VPS prerequisites, DNS setup, SSH
  host key pinning, ACME staging vs production, run modes, and artifact handling.
- **New artifact directory structure** `artifacts/live-vps/<TEST_RUN_ID>/` — structured reports with redacted
  diagnostics and no plaintext secrets.
- **Delta: install scripts** — `gowave-auto.sh install`, `gowave-auto.sh node add`, and `gowave-node-auto.sh`
  require ACME staging/production mode switch support (`certbot --server` override propagated over SSH stdin)
  to allow repeatable E2E runs without hitting Let's Encrypt production rate limits. The runner manages
  Let's Encrypt Staging CA trust for client HTTPS and Data Plane tunnel handshakes.
- **Delta: `modules/node.sh`** — bundled upstream installer path must be verifiable by commit SHA at E2E
  acceptance time; fallback to floating `main` is prohibited in a pinned E2E run.
- **Final safety delta** — all Master/Worker mutation entrypoints participate in one host-wide lock; the disposable gate covers every rollback target; interrupted Worker deployment and remote/API compensation produce independently verified transaction results; IPv6 DNS answers cannot be ignored when IPv6 traffic tests are disabled.

## Capabilities

### New Capabilities

- `live-vps-e2e`: Live VPS E2E Test Runner — validates the complete GoWave Auto NGINX infrastructure lifecycle
  on real disposable servers: preflight safety, All-in-One Master installation, Distributed Worker deployment,
  public mTLS control plane, Panel API cluster structure, subscription delivery policy, UFW firewall isolation,
  NGINX SNI routing and REALITY decoy, and Data Plane traffic through eight logical VPN endpoints by default (four core
  protocols on each VPS), or ten when both Vision domains are configured; each endpoint is exercised by both real
  Xray and Mihomo client processes using the configured REALITY fingerprint (`chrome` by default) (sixteen or twenty runtime cases), plus an optional second mihomo-compatible client via `ALT_MIHOMO_CORE`.

### Modified Capabilities

- `lifecycle-management`: ACME staging/production mode becomes a configurable parameter for install and
  `node add` flows to allow E2E certification issuance without hitting Let's Encrypt production rate limits on
  repeated test runs.

## Impact

- **New files**: `tools/test_live_vps.py`, `tools/live_vps/` package, `tools/tests/` unit test package,
  `tools/live_vps_config.env.example`, `.github/workflows/live-vps-e2e.yml`, `.github/workflows/live-vps-unit.yml`,
  `docs/LIVE_VPS_TESTING.md`.
- **Modified files**: `gowave-auto.sh` (ACME mode mapping, Master/Worker Vision domain-pair validation and
  propagation), `gowave-node-auto.sh` (ACME propagation, optional Worker Vision certificate/inbound and NGINX
  routing support, plus configurable commit/SHA256 verification of the remote installer),
  `modules/node.sh` (SHA-verified bundled installer gate), `modules/api_client.py` (backward-compatible
  SSLContext/timeout injection), `.gitignore`.
- **Vendored input**: `sources/gowave-node/install.sh` at the configured immutable commit with a verified
  `GOWAVE_NODE_INSTALLER_SHA256`.
- **Dependencies introduced**: Xray client binary, Mihomo binary (pinned versions on Control Machine).
- **No upstream source changes**: GoWave Panel and GoWave Node treated as immutable upstream binaries.
- **No production installation impact**: runner operates only on declared disposable test VPS confirmed by
  baseline gate.
- **Existing test suites**: unchanged; Live VPS E2E is an entirely separate acceptance tier.
