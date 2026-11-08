# Design: Live VPS E2E Testing

## Context

See `proposal.md — Why` for motivation. Key implementation constraints derived from codebase audit:

- `modules/verify_node_mtls.py` already implements HKDF-SHA256 SNI derivation and mTLS socket handshake;
  the E2E runner reuses this logic via subprocess call, not by copying crypto code.
- `modules/api_client.py` implements `GoWaveClient` with Bearer token auth (`/api/auth/login` → `accessToken`);
  the runner uses the same auth pattern against the real Panel.
- `shortUuid` is stored in `state.json` as `defaultUserShortUuid`, not in `/root/gowave-credentials.txt`;
  the runner reads it from `state.json` via SSH and cross-validates via `GET /api/users/by-username/default-user`.
- `gowave-auto.sh node add` reads Master egress IP via `curl -s4 https://ifconfig.me` and uses it for Worker
  UFW allowlist; this IP may differ from `MASTER_IP` under NAT/multi-homed setups.
- `gowave-auto.sh install` calls `certbot certonly --webroot` with no server parameter override; staging
  support requires a delta to this call.
- `gowave-node-auto.sh` calls `certbot certonly --webroot` with no server override; same delta needed.
- `modules/node.sh` falls back to `curl -fsSL https://raw.githubusercontent.com/aaaSaZaN/gowave-node/main/install.sh`
  when no bundled installer is present; E2E runs must gate on bundled installer with verified SHA256.
- `tests/podman_testbed.sh multi-node` returns exit `77` — real distributed E2E is not implemented.
- Existing 5-suite CI continues unchanged; Live VPS E2E is a separate acceptance tier.

---

## Goals / Non-Goals

**Goals (design-level):**
- Zero-secret-in-argv architecture throughout the runner.
- Single-process Python runner with structured submodule package; each phase has bounded timeout and explicit
  status.
- Reuse existing crypto/mTLS logic via subprocess, not reimplementation.
- SSH transport uses system OpenSSH CLI with `StrictHostKeyChecking=yes` and pre-pinned `known_hosts`.
- All log output passes through a redaction filter before writing.
- Teardown is policy-driven and idempotent; it never destroys a VPS not created by this runner.
- Run-level lock prevents concurrent tests on the same Master/Worker pair.

**Non-Goals (design-level):**
- Cloud provider VPS provisioning API (Provider Adapter interface reserved for future, not implemented).
- Modifying GoWave Panel or GoWave Node upstream behavior.
- Replacing or merging with the existing 5-suite unit/integration CI.
- Running on Windows or macOS (Linux Control Machine only, v1).
- Supporting concurrent tests on the same VPS pair (explicitly locked out).

---

## Decisions

### D1: SSH Transport — System OpenSSH CLI via subprocess, not Paramiko

**Chosen:** `subprocess` with system `ssh` / `scp`, `shell=False`, args as array, timeout mandatory.

**Rationale:** System OpenSSH respects host OS `~/.ssh/known_hosts` format, supports `StrictHostKeyChecking=yes`
natively, and delegates all host key verification logic to the battle-tested OpenSSH binary. No Python-layer
re-implementation of SSH crypto. Paramiko requires maintaining its own host key store and has historically
lagged behind OpenSSH security releases.

**Alternatives considered:** Paramiko — rejected because it requires duplicating host key pinning logic and
introduces an additional crypto dependency. Fabric — rejected as it wraps Paramiko with the same drawback.

**Security consequence:** Secrets are never placed in argv. Remote commands that require secrets (reading
credentials, extracting SECRET_KEY) pipe data via stdin or use isolated SSH `cat` commands followed by
in-memory processing, then immediate unset.

---

### D2: Config Parser — Whitelist-only env parser, no `eval`, no `source`

**Chosen:** A custom Python parser that reads the `.env` file line-by-line, strips comments, splits on the
first `=`, and validates each key against a strict whitelist with type/range/value rules.

**Rationale:** `eval` and Python `os.environ` source-execute arbitrary shell; a `.env` file from an untrusted
path could inject shell commands. The whitelist parser fails on unknown keys, duplicate keys, and values that
fail type validation. File must have mode `0600` before parsing; parser enforces this.

**Alternatives considered:** `python-dotenv` — rejected because it supports interpolation and exec features
that expand the attack surface. Shell `source` — rejected per AGENTS.md zero-leak credential requirement.

---

### D3: mTLS Verification — Reuse `modules/verify_node_mtls.py` via subprocess for Positive Acceptance; Direct Python Socket for Negative TLS Tests

**Chosen:**
1. **Positive Verification**: Call `python3 modules/verify_node_mtls.py` via subprocess from the runner,
   feeding the base64 `SECRET_KEY` payload over stdin, with `--host WORKER_IP --port 3002 --mode full`.
2. **Negative TLS Handshake Tests**: The five negative live socket scenarios (wrong client certificate,
   mismatched private key, wrong SNI, untrusted CA, and absent client certificate) are executed directly
   by `tools/live_vps/mtls.py` opening a TCP connection to `WORKER_IP:3002` with specifically configured
   `ssl.SSLContext` objects. This asserts that the TLS handshake is rejected by GoWave Node on the wire before
   the HTTP layer executes, without relying on `verify_node_mtls.py`'s pre-socket crypto validation.

**Rationale:** `verify_node_mtls.py` already implements the exact HKDF-SHA256 SNI derivation matching the
upstream GoWave Node implementation. Duplicating this logic in the runner would create two authoritative
sources of truth for the crypto. However, `verify_node_mtls.py` terminates locally during preflight crypto checks
when a key and certificate mismatch; direct socket tests are required to prove remote server-side rejection.

**Consequence for separate sub-checks:** The runner parses `verify_node_mtls.py` stdout to extract individual
signals (`MTLS_HANDSHAKE_PASS`, `MTLS_CERTIFICATE_VALIDATION_PASS`, `WORKER_HTTP_HEALTH_PASS`).
`PANEL_WORKER_AUTH_PASS` requires a separate authenticated Panel API call (Panel→Worker health from Panel's
perspective), which the runner performs via the Panel REST API.

---

### D4: Xray Client Config Construction

**Chosen:** The runner constructs a minimal temporary Xray client config file per endpoint: one outbound
(extracted from the real subscription), one SOCKS5 inbound with a unique local port, and mandatory `log`
and `routing` sections. The config is written to a `tempfile.NamedTemporaryFile` with mode `0600`, the Xray
process is started, the runner waits for the SOCKS5 port to become connectable (bounded poll), traffic test
runs, then Xray is terminated and the temp file is deleted. When `ACME_MODE=staging`, the client outbound
`tlsSettings` includes the Let's Encrypt Staging CA certificate (or `allowInsecure: true` in test configuration)
to allow valid TLS negotiation without modifying host root stores.

**Rationale:** The subscription endpoint returns a JSON structure that may be an outbound-only fragment, not
a standalone `xray run`-compatible config. Building the wrapper config ensures `xray run -test` and `xray run`
both work correctly regardless of the subscription format.

**Alternatives considered:** Direct `xray run -c <subscription.json>` — rejected because subscription format
is not guaranteed to be a complete standalone config.

---

### D5: Server-Side Ingress Evidence and Egress IP Verification

**Chosen:** Two-source verification:
1. **Client-side Egress Verification**: Control Machine sends HTTPS request via tunnel and reads egress IP
   from the response (e.g., `https://cloudflare.com/cdn-cgi/trace` with fallback to `https://api.ipify.org`).
   If `EXPECTED_WORKER_EGRESS_IP` is set, the egress IP must match it. If not set, the runner first queries
   the Worker's actual egress IP via SSH, then compares against the client-side observation.
2. **Server-side Ingress Evidence**: As GoWave Panel does not enable the Xray gRPC Stats API in default
   profile templates, server-side proof of traffic traversal uses iptables/nftables byte/packet accounting
   on the inbound port (e.g. `iptables -I INPUT -p tcp --dport <port>`), or a temporary non-blocking `tcpdump`
   capture during the test request on Worker. Server-side packets must increment during Worker tunnel requests,
   and must NOT increment on Master for Worker-directed traffic (proving zero Master relay).

**Rationale:** A client-only egress check can be fooled if Master relays traffic. Server-side packet evidence
combined with egress IP matching confirms the traffic genuinely traversed Worker, not Master.

---

### D6: Redaction Architecture

**Chosen:** A `redaction.py` module maintains a runtime set of sensitive string patterns (populated from
config values: secrets, tokens, shortUuid, subscription endpoint URLs). All log writes, SSH stdout/stderr,
and subprocess output pass through `redact(text)` before being written to any file or emitted to console.
Artifact files that could contain mixed content (e.g., API summaries) are written via a redact-on-write
wrapper.

**Pattern sources:** `ADMIN_PASSWORD`, `SCOPED_API_TOKEN`, `SECRET_KEY` (read from Master), `shortUuid`,
raw subscription URLs, JWT tokens (detected by pattern), private key PEM blocks.

---

### D7: Parallel vs Sequential Phase Execution

**Chosen:** Sequential execution with explicit phase checkpoints. Each phase is recorded with start time,
end time, and status before the next begins.

**Rationale:** Phases have hard dependencies (Worker must be deployed before mTLS can be verified; mTLS must
pass before Panel API audit makes sense). Parallel execution would complicate error attribution and teardown
ordering. The total run time is dominated by installation and certificate issuance, not Python computation.

---

### D8: Run-Level Locking

**Chosen:** A per-(MASTER_IP, WORKER_IP) lock file at `/tmp/gowave-e2e-<hash>.lock` using `fcntl.flock`
with `LOCK_EX | LOCK_NB`. Failure to acquire → immediate exit with clear message.

**Rationale:** Concurrent tests on the same VPS pair would corrupt state, duplicate API objects, and produce
unreliable results. The lock is released on process exit (normal or signal).

---

### D9: ACME Staging CA Trust Management on Control Machine

**Chosen:** When `ACME_MODE=staging`, the runner manages trust for Let's Encrypt Staging CA chains without
mutating system-wide `/etc/ssl/certs` on the Control Machine:
1. `tools/live_vps/tls.py` bundles or downloads the Let's Encrypt Staging Root/Intermediate certificates
   (`(STAGING) Pretend Pear X1` / `Artificial Strawberry Root X1`).
2. For Python Panel API calls (`panel_api.py`), the staging CA is loaded into a dedicated `ssl.create_default_context(cafile=...)`.
3. For curl calls, `--cacert <staging-ca-path>` is passed.
4. For Xray and Mihomo temporary client configs, the staging CA certificate is referenced in `tlsSettings`
   (or `allowInsecure: true` is configured in the ephemeral test client config).

**Rationale:** In staging mode, standard HTTPS requests to the Panel and TLS proxy tunnels fail with
`certificate verify failed` if the staging CA is not explicitly trusted by the client. This scoped approach
allows strict verification without polluting the host machine's root store.

---

### D10: Process argv Observation via Local Background Auditor on Master

**Chosen:** During `gowave-auto.sh node add`, the runner starts a background auditor script on Master via SSH
immediately before invoking deployment. The script monitors process creation locally (via `/proc/*/cmdline`
sampling or bash debug trap output) and logs all executed command lines to a private temporary file (`mode 0600`).
After deployment finishes, the runner inspects this log to confirm `SECRET_KEY` was never passed in `argv`,
then deletes the log.

**Rationale:** Polling `/proc/*/cmdline` over SSH network connections from the Control Machine introduces high
latency and race conditions, missing short-lived helper processes. A local auditor on Master captures all
executions reliably.

---

### D11: Operational Lifecycle and Disposable Baseline Policy in v1

**Chosen:** In v1 (without cloud provider API adapters), disposable test VPS instances must be provisioned or
re-imaged out-of-band by the operator before the test run.
1. The Disposable Environment Gate (Phase 0.7) strictly rejects any VPS with existing GoWave directories,
   running services, or listening ports.
2. For a clean test run, `TEST_DESTROY_VPS_ON_SUCCESS` and `TEST_RESTORE_SNAPSHOT` will record `NOT_RUN` /
   `TEARDOWN_UNAVAILABLE` on pre-existing VPS.
3. To execute subsequent test runs, the operator must re-image the VPS via cloud hosting tools to restore
   a clean OS baseline.

**Rationale:** Attempting in-place uninstallation leaves residual files, modified kernel sysctl, and firewall
state that invalidate clean-room acceptance testing. Clear documentation of this operational cycle prevents
unexpected Phase 0.7 failures.

---

## Runner Module Structure

```
tools/
  test_live_vps.py          # CLI entrypoint, phase orchestration
  live_vps/
    __init__.py
    config.py               # Whitelist env parser, validation, type coercion
    redaction.py            # Runtime redaction registry and filter
    ssh.py                  # SSH/SCP subprocess wrapper (no secrets in argv)
    dns.py                  # DNS A/AAAA/CNAME verification via dig/getent
    preflight.py            # Control Machine tools, baseline, disposable gate
    deployment.py           # Master install, Worker node add, version capture
    mtls.py                 # mTLS verification wrapper (calls verify_node_mtls.py)
    panel_api.py            # GoWaveClient wrapper for E2E (real Panel, no mock)
    subscriptions.py        # shortUuid retrieval, Xray JSON, Mihomo YAML fetch+verify
    firewall.py             # UFW isolation checks, DROP confirmation, egress IP
    nginx.py                # SNI routing, decoy, PROXY protocol, nginx -t
    traffic.py              # Xray/Mihomo client process management, SOCKS5, egress
    negative.py             # Negative scenario orchestration (NEG-01..NEG-15)
    teardown.py             # Preserve / snapshot restore / destroy policy
    reporting.py            # result.json, JUnit XML, summary.txt writers
```

---

## Phase Execution Flow

```
Phase 0: Preflight
  0.1  Config load + validate (whitelist parser, reserved IP rejection)
  0.2  Run-level lock acquire
  0.3  Control Machine tool check (python3, ssh, openssl, curl, dig, xray, mihomo)
  0.4  SSH trust check (both VPS, StrictHostKeyChecking=yes)
  0.5  DNS verification (4 domains, A/AAAA, 2+ resolvers)
  0.6  Baseline snapshot (systemd, listeners, firewall, GoWave dirs)
  0.7  Disposable gate (reject if GoWave present or ports occupied)
  0.8  Port hygiene (11+ required ports checked as free)

Phase 1: Master Installation
  1.1  Copy pinned repo commit to Master /opt/gowave-auto-nginx
  1.2  Run gowave-auto.sh install (with ACME_MODE parameter)
  1.3  Verify service states, listeners, TLS certs
  1.4  Verify credentials file (mode, owner, keys present — values not logged)
  1.5  Retrieve shortUuid (state.json + API cross-check)
  1.6  Verify Panel locally and from Control Machine
  1.7  Record versions (Panel, Node, Xray, NGINX, OpenSSL, OS)

Phase 2: Worker Deployment
  2.1  Run gowave-auto.sh node add worker-1 (from Master via SSH)
  2.2  Verify exit code, state.json, process argv observation (SECRET_KEY not in argv)
  2.3  Verify Worker services, listeners, certs, deploy hook, cover-reality SHA256
  2.4  Poll Panel API isConnected until true (bounded NODE_READY_TIMEOUT)

Phase 3: Public mTLS Verification
  3.1  Extract SECRET_KEY payload from Master state (via SSH, in-memory)
  3.2  Run verify_node_mtls.py --host WORKER_IP --port 3002 (subprocess from Master)
  3.3  Parse outputs → MTLS_HANDSHAKE_PASS, MTLS_CERTIFICATE_VALIDATION_PASS
  3.4  Verify WORKER_HTTP_HEALTH_PASS (200 OK from health endpoint)
  3.5  Verify PANEL_WORKER_AUTH_PASS (Panel REST API perspective)
  3.6  Run 5 negative mTLS sub-tests (wrong cert, wrong key, wrong SNI, wrong CA, no cert)

Phase 4: Panel API Audit
  4.1  GET /api/nodes — 2 nodes, correct addresses, 4 inbounds each, isConnected
  4.2  GET /api/config-profiles — 2 profiles, 4 inbounds each, computed-config valid JSON
  4.3  GET /api/internal-squads — Default MVP Squad, 8 inbound UUIDs, set equality
  4.4  GET /api/hosts — 8 hosts, all fields verified, correct node/inbound associations

Phase 5: Subscriptions
  5.1  GET /api/users/by-username/default-user → shortUuid
  5.2  User-Agent policy (empty, absent, Xray UA, Mihomo UA → check actual Panel response)
  5.3  Fetch Xray JSON (Xray UA), verify 8 proxy outbounds, headers, no server secrets
  5.4  Validate with xray run -test (temporary wrapper config)
  5.5  Fetch Mihomo YAML (Mihomo UA), verify 8 proxies, GEOIP rule, headers
  5.6  Validate with mihomo -t

Phase 6: Firewall
  6.1  Master: local 127.0.0.1:3002 reachable; external MASTER_IP:3002 blocked (DROP)
  6.2  Worker: Master egress IP determined; mTLS from Master allowed; Control Machine blocked (DROP)
  6.3  IPv6 checks if ENABLE_IPV6=true

Phase 7: NGINX SNI + REALITY Decoy
  7.1  Panel HTTPS with correct SNI (TLS cert valid, Panel API responds)
  7.2  Worker HTTPS with correct SNI
  7.3  REALITY fallback with REALITY SNI + invalid REALITY params (decoy content, not GoWave API)
  7.4  Unknown SNI routing (matches NGINX + Xray REALITY fallback behavior)
  7.5  nginx -t on both VPS configs
  7.6  cover-reality unique marker file accessible
  7.7  PROXY protocol integrity (inferred from correct Panel and Worker HTTPS responses)

Phase 8: Data Plane E2E (8 × Xray + 8 × Mihomo)
  8.1  For each of 8 endpoints:
       - Extract outbound from real subscription
       - Build temp Xray client config (unique SOCKS5 port, mode 0600)
       - Start Xray subprocess, await SOCKS5 readiness
       - curl socks5h://127.0.0.1:<port> https://cloudflare.com/cdn-cgi/trace
       - Verify egress IP vs EXPECTED_*_EGRESS_IP
       - Verify server-side inbound counter (SSH to target VPS)
       - Stop Xray, delete temp config
  8.2  Repeat 8 checks with Mihomo (if TEST_MIHOMO_TRAFFIC=true)

Phase 9: Negative Tests (NEG-01 .. NEG-15)
  Executed on disposable VPS; fault states cleaned up before next test where possible

Phase 10: Diagnostics Collection
  SSH dump: OS, packages, systemd, listeners, firewall, nginx -t, cert metadata, API summaries
  All written via redact-on-write; no plaintext secrets in any file

Phase 11: Teardown
  Apply configured policy (Preserve / Snapshot Restore / Destroy)
  Write final result.json, junit.xml, summary.txt
  Release run-level lock
```

---

## Trust Boundaries

```
+------------------+       SSH (StrictHostKeyChecking=yes)        +-------------+
| Control Machine  | ------------------------------------------> | Master VPS  |
|                  |       pre-pinned known_hosts                 |             |
|  Runner process  |                                              |  Panel API  |
|  Xray client     | <--- HTTPS /api/* (Bearer, real Panel) ----> |  :3000      |
|  Mihomo client   |                                              |             |
|  ssh subprocess  | <--- HTTPS :443 (subscription, SNI) -------> |  NGINX :443 |
+------------------+                                              +------+------+
                                                                         |
                                        SSH stdin pipeline (from Master) |
                                        mTLS 1.3 rw-v1 (from Master)     v
                                                                  +-------------+
                                                                  | Worker VPS  |
                                                                  |             |
                                                                  |  Node :3002 |
                                                                  |  NGINX :443 |
                                                                  +-------------+

Secrets never cross trust boundaries via argv or log files.
shortUuid and subscription content redacted in all CI artifacts.
```

---

## ACME Staging/Production Delta

**Problem:** `gowave-auto.sh` calls `certbot certonly --webroot` with no `--server` override; repeated E2E
runs against production ACME hit rate limits. Furthermore, when deploying worker nodes via `gowave-auto.sh node add`,
the ACME server selection must be propagated across the network to Worker.

**Solution:**
1. Support optional environment variable `GOWAVE_ACME_SERVER` in `gowave-auto.sh install`, `gowave-auto.sh domain-change`,
   and `gowave-node-auto.sh`.
2. When set to the staging URL, all `certbot certonly` invocations append `--server "$GOWAVE_ACME_SERVER"`.
3. In `gowave-auto.sh node add`, forward `GOWAVE_ACME_SERVER="${GOWAVE_ACME_SERVER:-}"` into `gowave-node-auto.sh remote_payload`.
4. In `gowave-node-auto.sh remote_payload()`, serialize `GOWAVE_ACME_SERVER` into the SSH stdin payload stream
   (`printf 'export GOWAVE_ACME_SERVER=%q\n' "${GOWAVE_ACME_SERVER:-}"`) so Worker certbot runs execute with the same
   staging endpoint.

---

## Negative Scenario Matrix (NEG-01 — NEG-15)

The runner executes 15 negative scenarios in Phase 9 (and during isolated test phases) to assert error handling boundaries:

| Scenario ID | Component / Area | Fault Injection Mechanism | Expected Outcome & Assertion Boundary |
|-------------|------------------|---------------------------|---------------------------------------|
| **NEG-01**  | Preflight SSH    | Host key absent or corrupted in `known_hosts` | Preflight terminates before any remote command |
| **NEG-02**  | Preflight SSH    | Target SSH port closed / unreachable | Preflight terminates with connection timeout |
| **NEG-03**  | Preflight DNS    | Domain resolves to IP other than target VPS | Preflight terminates before SSH connection |
| **NEG-04**  | Preflight DNS    | Missing AAAA record when `ENABLE_IPV6=true` | Preflight terminates before remote execution |
| **NEG-05**  | ACME Install     | Certbot challenge failure (NXDOMAIN / blocked port 80) | Installation aborts; services not marked healthy |
| **NEG-06**  | NGINX Config     | Syntax error in `/etc/nginx/conf.d/*.conf` | `nginx -t` fails; runner blocks config activation |
| **NEG-07**  | Worker Node      | `systemctl stop gowave-node` on Worker | Panel detects offline; `isConnected` becomes `false` |
| **NEG-08**  | Worker Node      | `systemctl start gowave-node` on Worker | Panel recovers; `isConnected` returns `true` |
| **NEG-09**  | Subscription     | Request without User-Agent header | Real Panel rejects with upstream policy code (e.g. 403) |
| **NEG-10**  | mTLS Control     | Forged / self-signed client certificate | Worker TLS 1.3 rejects handshake before HTTP handler |
| **NEG-11**  | Backup Restore   | Corrupted archive header / invalid tar format | Preflight check rejects before mutating live files |
| **NEG-12**  | Backup Restore   | SQLite DB file in archive corrupted | SQLite integrity check fails before replacing live DB |
| **NEG-13**  | Worker Deploy    | SSH pipeline interrupted mid-execution | Master recovery journal does NOT enter `COMMITTED` |
| **NEG-14**  | Worker Deploy    | Duplicate `node add` invocation for same node | Idempotent; no duplicate DB entities or hosts created |
| **NEG-15**  | Panel API Auth   | API request with expired or forged JWT | Panel returns 401 Unauthorized |

---

## Whitelist Configuration Schema (`tools/live_vps_config.env`)

The whitelist parser in `tools/live_vps/config.py` enforces POSIX permissions `0600` and validates every key against
the following strict schema:

| Variable Name | Type / Format | Mandatory | Default | Description |
|---------------|---------------|-----------|---------|-------------|
| `MASTER_IP` | IPv4 address | Yes | — | Public IPv4 of Master VPS (disallowed: RFC-1918, loopback, docs) |
| `MASTER_PANEL_DOMAIN` | FQDN | Yes | — | Domain pointing to Master Panel NGINX HTTPS |
| `MASTER_REALITY_DOMAIN` | FQDN | Yes | — | Camouflage decoy domain pointing to Master REALITY SNI |
| `MASTER_SSH_PORT` | Integer 1–65535 | No | `22` | Master SSH management port |
| `MASTER_SSH_USER` | String | No | `root` | Master SSH login user |
| `WORKER_IP` | IPv4 address | Yes | — | Public IPv4 of Worker VPS |
| `WORKER_DOMAIN` | FQDN | Yes | — | Domain pointing to Worker NGINX HTTPS |
| `WORKER_REALITY_DOMAIN` | FQDN | Yes | — | Camouflage decoy domain pointing to Worker REALITY SNI |
| `WORKER_SSH_PORT` | Integer 1–65535 | No | `22` | Worker SSH management port |
| `WORKER_SSH_USER` | String | No | `root` | Worker SSH login user |
| `SSH_KEY_PATH` | File path | Yes | — | Path to private SSH key for authentication |
| `SSH_KNOWN_HOSTS` | File path | Yes | — | Pre-pinned `known_hosts` file with both VPS host keys |
| `ACME_MODE` | `staging` \| `production` | No | `staging` | Let's Encrypt endpoint mode |
| `GOWAVE_PANEL_VERSION` | SemVer / commit | Yes | — | Target GoWave Panel version to pin and verify |
| `GOWAVE_NODE_VERSION` | SemVer / commit | Yes | — | Target GoWave Node version to pin and verify |
| `GOWAVE_NODE_INSTALLER_COMMIT` | 40-hex SHA | Yes | — | Pinned commit of upstream `install.sh` |
| `XRAY_CLIENT_VERSION` | Version string | Yes | — | Pinned Xray client version on Control Machine |
| `MIHOMO_CLIENT_VERSION` | Version string | Yes | — | Pinned Mihomo client version on Control Machine |
| `ENABLE_IPV6` | Boolean | No | `false` | Enable IPv6 DNS, UFW, and listener verifications |
| `MASTER_IPV6` | IPv6 address | Conditional | — | Required if `ENABLE_IPV6=true` |
| `WORKER_IPV6` | IPv6 address | Conditional | — | Required if `ENABLE_IPV6=true` |
| `EXPECTED_MASTER_EGRESS_IP` | IPv4 address | No | — | Expected outbound IP when routing through Master |
| `EXPECTED_WORKER_EGRESS_IP` | IPv4 address | No | — | Expected outbound IP when routing through Worker |
| `NODE_READY_TIMEOUT` | Integer seconds | No | `120` | Bounded timeout for Worker `isConnected: true` |
| `API_TIMEOUT` | Integer seconds | No | `15` | Panel REST API call timeout |
| `TRAFFIC_TIMEOUT` | Integer seconds | No | `30` | SOCKS5 tunnel request timeout |
| `TEST_TRAFFIC_VERIFICATION` | Boolean | No | `true` | Verify Data Plane traffic (`false` yields `INCOMPLETE`) |
| `TEST_MIHOMO_TRAFFIC` | Boolean | No | `true` | Verify traffic with real Mihomo client process |
| `TEST_NEGATIVE_SUITE` | Boolean | No | `true` | Execute NEG-01 through NEG-15 |
| `TEST_KEEP_VPS_ON_FAILURE` | Boolean | No | `true` | Teardown policy: preserve VPS on failure |
| `TEST_RESTORE_SNAPSHOT` | Boolean | No | `false` | Teardown policy: restore snapshot if supported |
| `TEST_DESTROY_VPS_ON_SUCCESS` | Boolean | No | `false` | Teardown policy: destroy VPS on success (gated) |
| `ADMIN_EMAIL` | Email address | No | `admin@example.com` | Email for ACME certificate registration |

---

## Installer Pinning Gate

**Problem:** `modules/node.sh` falls back to `curl .../main/install.sh` when no bundled installer is present.

**Solution:** E2E preflight verifies `sources/gowave-node/install.sh` exists in the pinned repository commit
and that its SHA256 matches a computed value from the `GOWAVE_NODE_INSTALLER_COMMIT`. If the bundled file is
absent or SHA256 mismatches, preflight terminates before installation.

---

## Risks / Trade-offs

**[RISK] Real ACME certificates required for production mode runs**
→ Mitigation: Default to `ACME_MODE=staging`; document that production acceptance runs must be explicitly
configured and rate-limit-aware.

**[RISK] GoWave Panel API contracts may change between upstream versions**
→ Mitigation: All API field access is gated on the `GOWAVE_PANEL_VERSION` pin; spec requires verifying actual
API response structure before asserting field names. Runner fails fast with descriptive error on unexpected
API schema.

**[RISK] egress IP verification via `cloudflare.com/cdn-cgi/trace` depends on external service availability**
→ Mitigation: Configure at least two independent external IP check endpoints; fall back to the second if the
first times out.

**[RISK] Server-side inbound counter may not be available if Xray stats API is not enabled in GoWave config**
→ Mitigation: Runner checks whether stats API is enabled post-installation. If not, falls back to SSH-based
packet capture (tcpdump on the specific port for the duration of the test request) as server-side evidence.
Documents this fallback explicitly in the diagnostic report.

**[RISK] Xray and Mihomo binary versions on Control Machine may not match pinned config versions**
→ Mitigation: Preflight checks binary version strings against `XRAY_CLIENT_VERSION` and
`MIHOMO_CLIENT_VERSION`; mismatches terminate preflight.

**[RISK] Partial Worker SSH deployment leaves Worker in unknown state**
→ Mitigation: Runner invokes `gowave-auto.sh node rollback` on failure (which calls `remote_rollback`); result
is recorded independently of the rollback success. NEG-13 tests this path explicitly.

---

## Migration / Deployment Plan

1. Create `feature/live-vps-e2e-testing` branch (done).
2. Apply ACME staging delta to `gowave-auto.sh` and `gowave-node-auto.sh` (small isolated change).
3. Apply installer pinning gate to `modules/node.sh` preflight path.
4. Add `tools/live_vps_config.env.example` to repo; add `tools/live_vps_config.env` to `.gitignore`.
5. Implement `tools/test_live_vps.py` and `tools/live_vps/` package per tasks.md.
6. Add `docs/LIVE_VPS_TESTING.md`.
7. Add `.github/workflows/live-vps-e2e.yml` (`workflow_dispatch` only, no auto-trigger on PR).
8. First run against staging ACME on manually provisioned VPS; validate all phases.
9. Second run with `ACME_MODE=production` for acceptance certificate.

**Rollback:** Live VPS E2E is entirely additive. Removing `feature/live-vps-e2e-testing` branch leaves the
existing codebase unchanged. The ACME staging delta is a backward-compatible default-off env var.

---

## Open Questions & Findings

- **[RESOLVED] Xray stats API availability:** Codebase audit confirms that GoWave Panel profile templates
  in `assets/xray/` do not configure the Xray Stats gRPC API (`"stats": {}`, `"StatsService"`). Upstream binaries
  are treated as immutable per AGENTS.md. Therefore, server-side traffic evidence uses iptables/nftables packet
  counters and temporary SSH packet capture on the target port.
- **Worker `isConnected` polling behavior:** What is the typical observed time between SSH deployment
  completion and Panel marking `isConnected: true` in the pinned GoWave version? Default `NODE_READY_TIMEOUT`
  is set to 120s with 5s fixed-interval polling, which is sufficient based on mock integration benchmarks.
