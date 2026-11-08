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

### D3: mTLS Verification — Reuse Existing Verifier, Separate Client- and Server-Side Negative Cases

**Chosen:**
1. **Positive verification** runs `modules/verify_node_mtls.py` on Master (the allowed source address),
   with the base64 `SECRET_KEY` payload supplied over stdin. The runner records the verifier exit code,
   negotiated TLS version and HTTP status as separate observations. It MUST NOT parse synthetic markers that
   the current verifier does not emit. The existing verifier prints `Handshake SUCCESS`, `Node response`,
   and `mTLS 1.3 control plane verification PASSED`; it treats both `200 OK` and `401 Unauthorized` as
   successful TLS/SNI handshake evidence.
2. **Certificate/key consistency negative case** is local: pair a valid client certificate with a different
   private key and assert that the client TLS library refuses to load the chain. This is not a remote
   Worker-handshake test and MUST be reported separately.
3. **Server-side client-auth negative cases** use a TCP/TLS client from Master: an untrusted client certificate
   and an absent client certificate must be rejected by Worker during handshake. Wrong-SNI behavior is tested
   independently against the documented SNI router and must assert the observed route/handshake outcome rather
   than assume every wrong SNI produces a TLS alert.
4. **Server-certificate trust negative case** runs from a client that does not trust the GoWave CA and asserts
   that client-side certificate verification fails. It MUST NOT be described as Worker rejecting the client.

**Rationale:** The current verifier performs local cryptographic validation before opening a socket and only
then performs TLS 1.3 mTLS. A mismatched key fails locally before a network handshake. A wrong server CA is
validated by the client, not by the Worker. Treating these as server-side handshake rejection would produce
false security evidence.

**Output contract:** The runner derives `MTLS_CRYPTO_VALIDATION_PASS` from successful verifier completion
before socket creation only when that stage is independently exposed; otherwise it records the verifier as a
single `MTLS_VERIFIER_PASS` observation. It derives `MTLS_HANDSHAKE_PASS` from the explicit handshake-success
output plus negotiated `TLSv1.3`, and records the HTTP status separately. `200 OK` is application health
success; `401 Unauthorized` proves TLS/SNI reached the HTTP layer but is NOT an authenticated health pass.
`PANEL_WORKER_AUTH_PASS` requires independent evidence of an authenticated Panel-to-Worker exchange and
MUST NOT be inferred from the local verifier's HTTP response.

---

### D4: Xray Client Config Construction

**Chosen:** The runner constructs a minimal temporary Xray client config file per endpoint: one outbound
(extracted from the real subscription), one SOCKS5 inbound with a unique local port, and mandatory `log`
and `routing` sections. The config is written to a `tempfile.NamedTemporaryFile` with mode `0600`, the Xray
process is started, the runner waits for the SOCKS5 port to become connectable (bounded poll), traffic test
runs, then Xray is terminated and the temp file is deleted. When `ACME_MODE=staging`, the client trusts the
specific Let's Encrypt Staging CA chain through a scoped CA bundle. `allowInsecure: true` is prohibited even
for disposable tests because it disables server identity verification and can conceal SNI/certificate errors.

**Rationale:** The subscription endpoint returns a JSON structure that may be an outbound-only fragment, not
a standalone `xray run`-compatible config. Building the wrapper config ensures `xray run -test` and `xray run`
both work correctly regardless of the subscription format.

**Alternatives considered:** Direct `xray run -c <subscription.json>` — rejected because subscription format
is not guaranteed to be a complete standalone config.

---

### D5: Server-Side Ingress Evidence and Egress IP Verification

**Chosen:** Each endpoint test is executed sequentially with a bounded observation window:
1. Record baseline packet/byte counters (or start a bounded `tcpdump` capture) on the target VPS public
   transport listener. In the current NGINX stream topology this is TCP/443; do not assume the four logical
   protocols have four distinct public TCP ports. Use the exact configured listener and record the capture
   filter and interface.
2. Execute one tunnel request through the selected endpoint and record the client-observed egress IP.
   Compare it with `EXPECTED_MASTER_EGRESS_IP` or `EXPECTED_WORKER_EGRESS_IP` when configured. If no expected
   value is configured, query that VPS's direct egress independently and compare, while documenting that
   this verifies shared egress identity rather than a predeclared address.
3. Compare post-test ingress evidence with the baseline on the target VPS. For Worker endpoints, verify
   Worker ingress increases and Master ingress does not increase for the same controlled request. For Master
   endpoints, verify Master ingress increases. Counter deltas MUST be isolated per test window; unrelated
   background traffic invalidates ambiguous evidence and produces `INCOMPLETE`, not `PASS`.
4. If packet capture is used, capture metadata and packet counts only; do not persist payloads or credentials.

**Rationale:** Default GoWave Xray templates do not enable the Xray Stats API. The public NGINX stream listener
is shared by SNI-routed transports, so packet evidence proves traversal to the intended VPS but not by itself
which protocol was selected. Protocol identity is established by the client runtime and successful request;
server-side ingress is an independent host-traversal check.

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

**Chosen:** When `ACME_MODE=staging`, the runner creates one per-run CA bundle without
mutating system-wide `/etc/ssl/certs` on the Control Machine:
1. `tools/live_vps/tls.py` starts from the Control Machine's complete default public CA bundle, appends the
   applicable Let's Encrypt Staging Root/Intermediate certificates, and verifies pinned SHA256 fingerprints
   for every staging certificate before use. Certificate names alone are not accepted as trust anchors. If the
   complete public-root bundle cannot be located or read, preflight fails; a staging-only bundle is forbidden.
2. Python Panel API calls use `ssl.create_default_context(cafile=<combined-bundle>)`.
3. Every curl call that performs TLS verification (including the HTTPS egress probe to a public site) passes
   `--cacert <combined-bundle>`; this preserves trust in ordinary public CAs as well as the staging chain.
4. Xray and Mihomo child processes receive `SSL_CERT_FILE=<combined-bundle>` in their process environment.
   Verify this behavior against the exact pinned client binaries before use; never set `allowInsecure`,
   `skip-cert-verify`, or any equivalent verification bypass.
5. The bundle is private to the run directory, mode `0600`, and removed during local cleanup. It contains
   public certificates only and does not modify the host trust store.

**Rationale:** In staging mode, standard HTTPS requests to the Panel and TLS proxy tunnels fail with
`certificate verify failed` if the staging CA is not explicitly trusted by the client. This scoped approach
allows strict verification without polluting the host machine's root store.

---

### D10: Process argv Observation During Worker Registration

**Chosen:** Do not use periodic `/proc/*/cmdline` sampling or a Bash DEBUG trap as proof: both can miss
short-lived processes, and shell tracing can itself disclose expanded secrets. On Master, derive a positive
string-print limit as `STRACE_STRING_LIMIT = 32 * os.sysconf("SC_PAGE_SIZE")`. Linux limits each individual
`execve` argument/environment string to 32 pages, including its terminating NUL; a positive strace limit at
that bound is therefore sufficient to print every legal individual argv string. Do not use `-s 0`: strace
interprets zero as a zero-character limit, not unlimited output. Run the exact `gowave-auto.sh node add`
process tree under `strace -f -s "$STRACE_STRING_LIMIT" -e trace=execve,execveat` (or an equivalent
kernel-level observer that captures both syscall forms with the same completeness guarantee). If page size
cannot be determined, the computed limit is invalid, or the installed strace cannot accept it, record
`INCOMPLETE` and do not run a weaker observer as a fallback. Write raw output to a mode-0600 file inside a private `/run` tmpfs directory (mode `0700`), never persist it
or stream it to the Control Machine, parse the strace-quoted argv including escaped bytes, scan locally for
the exact `SECRET_KEY` and known encoded forms, then securely remove the raw trace. The observer must exit
successfully, follow all descendants, and contain no truncated or unfinished exec records or observer errors.
The acceptance test MUST place a sentinel secret after byte 32 in arguments passed through both `execve` and
`execveat`, then prove both complete values are present in the trace. The report stores only `PASS`/`FAIL`,
observer version, effective string limit, coverage limitations and timestamps.

**Rationale:** Process polling is inherently racy. A kernel-level exec observer gives a bounded observation
of process creation. The raw trace contains sensitive argv and therefore must never become a normal diagnostic
artifact. This verifies argv only; it does not prove absence from process environment, stdin, memory or files.

---

### D11: Operational Lifecycle and Disposable Baseline Policy in v1

**Chosen:** v1 accepts only operator-provisioned disposable VPS instances and has no built-in cloud
provider adapter. The runner accepts one mutually exclusive `TEST_TEARDOWN_POLICY` value: `PRESERVE`
(default) or `RESTORE_SNAPSHOT`; `DESTROY` is rejected during preflight before any remote modification.
`PRESERVE` leaves both VPS running and retains diagnostics after both successful and failed runs; no uninstall
is implied.

`RESTORE_SNAPSHOT` is supported only through an explicit operator-supplied restore hook on the Control Machine.
It requires `MASTER_SNAPSHOT_ID`, `WORKER_SNAPSHOT_ID`, an absolute `SNAPSHOT_RESTORE_HOOK` path, and a
matching `SNAPSHOT_RESTORE_HOOK_SHA256`. Preflight verifies that the hook is a regular executable file owned
by the runner user or root, is not group/world-writable, and matches the pinned SHA256; the digest is checked
again immediately before execution. The runner invokes it directly with `shell=False`, sends a versioned JSON
request containing `TEST_RUN_ID`, VPS addresses and snapshot IDs on stdin, and enforces `RESTORE_TIMEOUT`.
The hook must exit zero and return valid JSON with `status=RESTORED` and matching snapshot IDs for both hosts.
The runner then reconnects to both VPS, recollects the Phase 0 baseline manifest, and verifies the required
clean-baseline invariants before recording teardown `PASS`. Missing/invalid hook configuration is a preflight
`FAIL`; hook timeout, nonzero exit, invalid/mismatched response, failed reconnection or baseline mismatch
produces `TEARDOWN_FAILED`, never a simulated restore success. The hook may use operator-managed provider
credentials but must not print them.

Boolean policy combinations are not accepted. The runner does not claim that `gowave-auto.sh uninstall`
restores OS packages, UFW, sysctl, swap/fstab, certificates or unrelated host state. A clean baseline gate is
mandatory before installation. After `PRESERVE`, the next run requires operator re-image or this verified
external restore procedure.

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

Phase 3: Public mTLS Verification (execute allowed-source probes from Master)
  3.1  Extract SECRET_KEY payload from Master state (via SSH, in-memory)
  3.2  Run verify_node_mtls.py on Master against Worker:3002; retain raw output only in memory
  3.3  Record verifier exit code, explicit TLSv1.3 handshake line, and HTTP status as separate observations
  3.4  Treat 200 as HTTP health success; 401 as TLS/SNI reached HTTP layer but not authenticated health
  3.5  Verify Panel↔Worker authenticated connectivity independently through Panel API state
  3.6  Run client-cert rejected / no-client-cert server-side probes from Master
  3.7  Run wrong-key local client-load test and wrong-server-CA client-verification test separately
  3.8  Test wrong-SNI routing against observed NGINX/Xray behavior; do not assume a fixed TLS alert

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
  6.1  Master: loopback 127.0.0.1:3002 reachable; Control Machine public probe blocked
  6.2  Worker: establish positive mTLS probe from Master first; record actual Master source IP seen by Worker
  6.3  Compare observed source IP with the effective UFW allow rule; do not trust a separately queried egress IP alone
  6.4  Control Machine negative probe must be paired with listener-positive and Master-positive controls
  6.5  Confirm DROP evidence on the target host: Master evidence for Master external probes; Worker evidence for Control Machine → Worker probes
  6.6  Repeat equivalent checks over IPv6 when ENABLE_IPV6=true

Phase 7: NGINX SNI + REALITY Decoy
  7.1  Panel HTTPS with correct SNI (TLS cert valid, Panel API responds)
  7.2  Worker HTTPS with correct SNI
  7.3  REALITY fallback with REALITY SNI + invalid REALITY params (decoy content, not GoWave API)
  7.4  Unknown SNI routing (matches NGINX + Xray REALITY fallback behavior)
  7.5  nginx -t on both VPS configs
  7.6  cover-reality unique marker file accessible
  7.7  PROXY protocol integrity (inferred from correct Panel and Worker HTTPS responses)

Phase 8: Data Plane E2E (8 logical endpoints × 2 client runtimes = 16 required cases)
  8.1  Logical endpoint matrix: Master × {VLESS REALITY, VLESS XHTTP, VLESS WS, Trojan gRPC}
       and Worker × the same four protocols
  8.2  For each logical endpoint, run a real Xray client case and a real Mihomo client case:
       - Extract the corresponding proxy from the real subscription
       - Build/validate a temporary Xray wrapper config or load the real Mihomo subscription
       - Start the actual client process and wait for its local proxy listener
       - Send HTTPS request through the selected proxy; verify HTTP response and observed egress IP
       - Verify target VPS ingress evidence in an isolated observation window
       - Stop client and remove temporary configuration
  8.3  All 16 cases are mandatory for overall PASS. If a client runtime is intentionally disabled, mark its
       eight cases SKIP and overall status INCOMPLETE. A syntax-only validation is not a runtime traffic pass.

Phase 9: Negative Tests (NEG-01 .. NEG-15)
  Executed on disposable VPS; fault states cleaned up before next test where possible

Phase 10: Diagnostics Collection
  SSH dump: OS, packages, systemd, listeners, firewall, nginx -t, cert metadata, API summaries
  All written via redact-on-write; no plaintext secrets in any file

Phase 11: Teardown
  Apply configured policy (PRESERVE / RESTORE_SNAPSHOT via the verified external restore hook; DESTROY rejected in v1)
  v1: RESTORE_SNAPSHOT requires both per-host snapshot IDs and a SHA256-pinned external restore hook; post-restore baseline verification is mandatory
  Record test outcome separately from teardown outcome; uninstall is not OS baseline restoration
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
| `TEST_MIHOMO_TRAFFIC` | Boolean | No | `true` | Verify traffic with real Mihomo client process; false skips eight mandatory cases and makes overall status INCOMPLETE |
| `TEST_NEGATIVE_SUITE` | Boolean | No | `true` | Execute NEG-01 through NEG-15 |
| `TEST_TEARDOWN_POLICY` | Enum: `PRESERVE`, `RESTORE_SNAPSHOT` | No | `PRESERVE` | Mutually exclusive teardown policy; `DESTROY` is rejected in v1 |
| `MASTER_SNAPSHOT_ID` | String | Conditional | — | Required for RESTORE_SNAPSHOT; operator-managed Master snapshot identifier |
| `WORKER_SNAPSHOT_ID` | String | Conditional | — | Required for RESTORE_SNAPSHOT; operator-managed Worker snapshot identifier |
| `SNAPSHOT_RESTORE_HOOK` | Absolute file path | Conditional | — | Required for RESTORE_SNAPSHOT; external Control Machine restore executable |
| `SNAPSHOT_RESTORE_HOOK_SHA256` | 64-hex SHA256 | Conditional | — | Required digest pin for the external restore hook |
| `RESTORE_TIMEOUT` | Integer seconds | No | `900` | Maximum runtime for external restore hook and post-restore readiness checks |
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
