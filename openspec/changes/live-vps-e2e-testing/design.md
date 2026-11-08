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
- E2E v1 connects to both VPS as `root`; the current deployment scripts have no `sudo` execution adapter. Preflight verifies `id -u == 0` on both hosts before acquiring remote locks or mutating either host; non-root SSH accounts fail closed.
- `SSH_KNOWN_HOSTS` is one configured, pre-pinned file containing both target host keys. Each SSH invocation selects the exact target entry (including `[host]:port` for non-default ports); a second independent file is not required by this contract.
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
   with the already-Base64-encoded `SECRET_KEY` value returned by `modules/node.sh:extract_secret_key`
   supplied unchanged over stdin. The existing extractor returns the encoded value consumed by the verifier;
   `verify_node_mtls.py` performs exactly one `base64.b64decode()` before parsing the JSON payload. The runner
   MUST NOT Base64-encode this value a second time. The runner records the verifier exit code,
   negotiated TLS version and HTTP status as separate observations. It MUST NOT parse synthetic markers that
   the current verifier does not emit. The existing verifier prints `Handshake SUCCESS`, `Node response`,
   and `mTLS 1.3 control plane verification PASSED`; it treats both `200 OK` and `401 Unauthorized` as
   successful TLS/SNI handshake evidence.
2. **Certificate/key consistency negative case** is local: pair a valid client certificate with a different
   private key and call the existing verifier's `validate_payload_crypto()` path. It compares the certificate
   public key with the private key's derived public key through OpenSSL before any socket is opened; the
   mismatch MUST fail this local validation. The test MUST assert that no TCP connection was attempted. This
   is not a remote Worker-handshake test and MUST be reported separately.
3. **Server-side client-auth negative cases** use a TCP/TLS client from Master: an untrusted client certificate
   and an absent client certificate must be rejected by Worker during handshake. Wrong-SNI behavior is tested
   independently against the documented SNI router and must assert the observed route/handshake outcome rather
   than assume every wrong SNI produces a TLS alert.
4. **Server-certificate trust negative case** uses a dedicated TLS probe with the valid HKDF-derived SNI and
   valid client certificate/key unchanged, but replaces only the client's server-trust store with one that
   does not contain the GoWave CA. The test MUST assert a server-certificate trust failure and MUST prove that
   SNI routing and client identity were held constant. Do not derive a new SNI from the deliberately untrusted
   trust bundle. This is client-side certificate verification failure, not Worker rejecting the client.

**Rationale:** The current verifier performs local cryptographic validation before opening a socket and only
then performs TLS 1.3 mTLS. A mismatched key is rejected by `validate_payload_crypto()` through an OpenSSL
public-key comparison before the socket function is called; it is not a TLS-library handshake failure. A wrong
server CA is validated by the client, not by the Worker. To isolate that negative case, preserve the valid
SNI and valid client certificate/key and change only the client's server trust anchors. Treating these as
server-side handshake rejection would produce false security evidence.

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
   transport listener. In the current NGINX stream topology this is TCP/443; do not assume the four or five
   logical protocols have distinct public TCP ports. Use the exact configured listener and record the capture
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

**Chosen:** Use both a local process lock and authoritative remote locks; a local-only lock is not sufficient
to protect a shared VPS pair from two different Control Machines.

1. The Control Machine acquires a per-target local `fcntl.flock(LOCK_EX | LOCK_NB)` in a private runtime
   directory owned by the runner user (directory mode `0700`, lock file mode `0600`, opened without following
   symlinks). This prevents duplicate runner processes on one Control Machine.
2. Before any deployment or fault-injection mutation, acquire an authoritative kernel `flock` on both
   target VPS hosts at `/run/lock/gowave-live-vps.lock`. Acquire the two host locks in deterministic
   address order; if either acquisition fails, release the first and abort before remote modification.
   Hold each lock through a dedicated non-PTY SSH session for the complete run/partial operation. The
   remote SSH session is the lock holder; use bounded SSH keepalives and treat loss of either lock-holder
   session as loss of exclusivity.
3. The remote lock file may remain after release: lock ownership is determined by the kernel `flock`, not
   file existence. Never remove a lock file to force acquisition. A contender that cannot acquire either
   lock fails closed. The lock owner metadata (run ID, Control Machine identity, start time) is informational
   only and MUST NOT override a held kernel lock.
4. If either remote lock-holder session is lost during a run, stop starting new mutating phases and do not
   silently reconnect and continue without reacquiring both locks and validating the saved run state. Outside
   an already executing `RESTORE_SNAPSHOT` teardown, this is a terminal `INCOMPLETE` condition. During that
   declared teardown only, loss caused by snapshot reboot is an expected interruption: keep teardown
   non-passing, wait for the restore hook to confirm both resources, reacquire both locks in deterministic
   order, and validate the saved run identity plus clean baseline before finalizing teardown. Failed
   reacquisition or validation remains `TEARDOWN_FAILED`; no other phase may resume.

**Rationale:** A lock under `/tmp` on the Control Machine only serializes processes on that one machine.
Two operators or CI runners on different hosts could otherwise mutate the same Master or Worker at once.
Authoritative locks on both VPS hosts coordinate all controllers that use the target machines; deterministic
acquisition order prevents lock-order deadlocks. The local lock remains a cheap first-line guard.

---

### D9: Reproducible ACME Staging CA Trust on Control Machine

**Chosen:** When `ACME_MODE=staging`, the runner builds a per-run CA bundle from the Control Machine's
complete default public CA bundle plus a version-controlled set of Let's Encrypt Staging self-signed root
certificates. Staging roots are test-only trust anchors: they MUST NOT be installed in or appended to the
Control Machine's system-wide trust store, a browser trust store, or any non-E2E client.

1. The repository MUST vendor exactly the four active Staging root certificates listed by the official
   Let's Encrypt Staging Environment documentation
   (`https://letsencrypt.org/docs/staging-environment/`, page last updated 2026-04-10), under
   `tools/certs/letsencrypt-staging/`:

   | File | Official source URL | Expected subject CN |
   |---|---|---|
   | `pretend-pear-x1.pem` | `https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x1.pem` | `(STAGING) Pretend Pear X1` |
   | `bogus-broccoli-x2.pem` | `https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x2.pem` | `(STAGING) Bogus Broccoli X2` |
   | `yearning-yucca-root-ye.pem` | `https://letsencrypt.org/certs/staging/gen-y/root-ye.pem` | `(STAGING) Yearning Yucca Root YE` |
   | `yonder-yam-root-yr.pem` | `https://letsencrypt.org/certs/staging/gen-y/root-yr.pem` | `(STAGING) Yonder Yam Root YR` |

2. `tools/certs/letsencrypt-staging/pins.json` MUST contain a versioned entry for each file: exact
   official source URL, expected subject, and a 64-hex SHA-256 fingerprint calculated over the DER-encoded
   X.509 certificate (not the PEM text and not the SPKI). No placeholder, dynamically learned, or
   trust-on-first-use fingerprint is permitted. A runtime load MUST reject a missing, extra, duplicate,
   malformed, expired, not-yet-valid, non-CA, non-self-signed, wrong-subject, or fingerprint-mismatched
   certificate and MUST fail preflight before remote modification.

3. Only the four self-signed Staging roots are vendored as trust anchors. Staging intermediates MUST NOT be
   pinned or added as trust anchors: Let's Encrypt documents that the intermediate set changes and must not
   be pinned or trusted as a system root. The TLS peer must present the required intermediate chain; a missing
   or invalid chain fails normal certificate verification. Root updates are never downloaded automatically
   during a test run.

4. The update procedure is review-gated: compare the official Let's Encrypt Staging Environment page with the
   current four-root manifest; retrieve changed material only from the exact official URLs above or their
   replacement links on that official page; verify subject, CA constraints, self-signature and validity;
   calculate the DER SHA-256 with OpenSSL; update the vendored PEM and `pins.json` together in a PR; and run
   positive staging-chain plus negative untrusted-CA tests. Retired roots are removed only after the official
   page no longer lists them as active. A changed source URL or root set requires an explicit design/manifest
   review, never an automatic fallback.

5. `tools/live_vps/tls.py` MUST always resolve the Control Machine's complete default public CA bundle and
   fail preflight if it cannot be read in full. Bundle composition is conditional on `ACME_MODE`:
   - `staging`: verify exactly the four vendored roots against `pins.json` and append those roots to the
     complete public bundle to create the private per-run combined bundle. A staging-only bundle is forbidden.
   - `production`: use the complete public CA bundle without adding any Staging roots. Staging roots MUST NOT
     become trust anchors in production-mode runs, even in the private per-run bundle.
   Record the source public bundle path and SHA-256; for staging also record the Staging pin-manifest SHA-256
   and selected certificate subjects in redacted result metadata.

6. Python Panel API calls use `ssl.create_default_context(cafile=<mode-specific-bundle>)`. Every curl request
   that performs TLS verification, including the HTTPS public egress probe, passes
   `--cacert <mode-specific-bundle>`. Xray and Mihomo child processes receive
   `SSL_CERT_FILE=<mode-specific-bundle>` only in their process environment. In staging mode, the exact pinned
   binaries MUST pass a staging endpoint, an ordinary public-CA endpoint, and an untrusted-CA rejection test;
   in production mode they MUST pass an ordinary public-CA endpoint and reject an untrusted test CA, without
   trusting a Staging-only root. `allowInsecure`, `skip-cert-verify`, and equivalent verification bypasses
   are prohibited.

7. The mode-specific per-run bundle (whether production or staging) is mode `0600`, private to the current
   run, contains public certificates only, and is removed during local cleanup. In production it contains the
   complete public CA roots only; in staging it additionally contains only the four verified Staging roots.
   It MUST NOT be installed in a host-wide trust directory or reused by unrelated processes.

**Rationale:** Let's Encrypt explicitly warns that Staging roots are not audited for ordinary trust and must
only be added to test-only trust stores. Vendoring the documented roots and pinning their DER fingerprints
makes the test trust reproducible, reviewable, and independent of a mutable network download while preserving
ordinary public trust for the E2E clients.

---

### D10: Complete Process argv Observation During Worker Registration

**Chosen:** Do not use periodic `/proc/*/cmdline` sampling or a Bash DEBUG trap as proof: both can miss
short-lived processes, and shell tracing can itself disclose expanded secrets. On Master, derive a positive
string-print limit as `STRACE_STRING_LIMIT = 32 * os.sysconf("SC_PAGE_SIZE")`. Linux limits each individual
`execve` argument/environment string to 32 pages, including its terminating NUL; a positive strace limit
at that bound is sufficient to print every legal individual string. Do not use `-s 0`: strace interprets
zero as a zero-character limit, not unlimited output.

Run the exact `gowave-auto.sh node add` process tree on the Master VPS with both string and array abbreviation
disabled:
`strace -f -v -s "$STRACE_STRING_LIMIT" -e trace=execve,execveat -o "$RAW_TRACE" -- ...`.
The `-v` / `--no-abbrev` option is mandatory: it is equivalent to `-e abbrev=none` and prevents
strace's default structure/array abbreviation from replacing later `argv` elements with an omission marker.
The positive `-s` limit independently prevents individual argument strings from being truncated. The observer
MUST capture both `execve` and `execveat` for all descendants of the local `gowave-auto.sh node add`
process on Master, including the local SSH client process. This is a Master-side observation only:
it does not trace the remote Worker shell/process tree after the SSH boundary and MUST NOT be represented as
proof about Worker-side argv. If page size cannot be determined, the computed limit is invalid, the installed
strace does not support either option, or the complete output cannot be parsed, record `INCOMPLETE`; do not
use a weaker observer as fallback.

Because `-v` also expands the `envp` vector, the raw trace MUST be treated as containing arbitrary
environment secrets as well as argv values. The `strace` process, parser, and raw file MUST all execute/remain
on the Master VPS: store the trace only in a mode-`0600` file inside a private `/run` tmpfs directory (mode
`0700`), never stream or copy it to the Control Machine, console, logs, or artifacts. Parse the `argv` and
`envp` fields on Master separately; inspect `argv` for the exact `SECRET_KEY` and known encoded forms, and
discard `envp` without publishing or logging it. Return to the Control Machine only a sanitized structured
verdict (status, observer version/options, effective string limit, coverage metadata and timestamps). If the parser cannot unambiguously separate both
vectors or establish that every `argv` element was decoded, record `INCOMPLETE`. Unlink the raw trace and
remove the private directory in a guaranteed cleanup path; do not claim secure overwrite on SSD or
journaled storage. The observer must exit successfully, follow all descendants, and contain no truncated,
abbreviated, unfinished or unparseable exec records, nor observer errors.

The acceptance tests MUST cover both independent completeness dimensions for both syscall forms:
(a) a sentinel after byte 32 of a long argument, and (b) a sentinel in the final element of an argv vector
containing at least 128 arguments. The parsed trace MUST contain the complete sentinel and every argv
element, with no strace omission marker. A trace that only passes the long-string test but omits later array
elements MUST fail acceptance and can never produce a live `PASS`. The report stores only `PASS`/`FAIL`,
observer version, effective string limit, selected options, coverage limitations and timestamps.

**Rationale:** `-s` controls the maximum printed size of each string, while `-v` disables strace's
default abbreviation of structured syscall arguments. Both are required for a complete `argv` observation.
The expanded raw trace can contain environment secrets, so it is strictly ephemeral. This verifies argv only;
it does not prove absence from process environment, stdin, memory or files.

---

### D11: Operational Lifecycle and Disposable Baseline Policy in v1

**Chosen:** v1 accepts only operator-provisioned disposable VPS instances and has no built-in cloud
provider adapter. The runner accepts one mutually exclusive `TEST_TEARDOWN_POLICY` value: `PRESERVE`
(default) or `RESTORE_SNAPSHOT`; `DESTROY` is rejected during preflight before any remote modification.
`PRESERVE` leaves both VPS running and retains diagnostics after both successful and failed runs; no uninstall
is implied.

`RESTORE_SNAPSHOT` is supported only through an explicit operator-supplied restore hook on the Control Machine.
It requires `MASTER_SNAPSHOT_ID`, `WORKER_SNAPSHOT_ID`, an absolute `SNAPSHOT_RESTORE_HOOK` path, and a
matching `SNAPSHOT_RESTORE_HOOK_SHA256`. Preflight verifies that the absolute hook path is not a
symlink, resolves to a regular executable owned by the runner user or root, is not group/world-writable, and
matches the pinned SHA256; the digest is checked again immediately before execution. The runner invokes it
directly with `shell=False` and sends this versioned JSON request
on stdin:
```json
{"schema_version":1,"action":"restore","test_run_id":"...","master":{"address":"...","snapshot_id":"..."},"worker":{"address":"...","snapshot_id":"..."}}
```
The hook must exit zero and return valid JSON:
```json
{"schema_version":1,"status":"RESTORED","master":{"snapshot_id":"...","restored":true},"worker":{"snapshot_id":"...","restored":true}}
```
Both returned snapshot IDs must exactly match the request. Hook stdout/stderr are captured in memory and MUST
NOT be published verbatim; the operation is bounded by `RESTORE_TIMEOUT`.
The runner then reconnects to both VPS and reacquires both authoritative remote `flock` sessions in the same
deterministic address order used by preflight. It verifies the saved run identity and recollects the Phase 0
baseline while both locks are held; only then may teardown be recorded `PASS`. Snapshot restoration may reboot
either VPS and terminate the original lock-holder sessions, so the runner MUST NOT treat the hook's
`RESTORED` response alone as teardown success or continue baseline verification without reacquiring both locks.
If either lock cannot be reacquired, the saved run identity differs, or the baseline differs, teardown is
`TEARDOWN_FAILED`; no further mutating phase may start. Keep both replacement locks through final reporting
and release them only after the final result is durably written. Missing/invalid hook configuration is a
preflight `FAIL`; hook timeout, nonzero exit, invalid/mismatched response or failed reconnection also produces
`TEARDOWN_FAILED`, never a simulated restore success. The hook may use operator-managed provider credentials
but must not print them.

Boolean policy combinations are not accepted. The runner does not claim that `gowave-auto.sh uninstall`
restores OS packages, UFW, sysctl, swap/fstab, certificates or unrelated host state. A clean baseline gate is
mandatory before installation. After `PRESERVE`, the next run requires operator re-image or this verified
external restore procedure.

**Rationale:** Attempting in-place uninstallation leaves residual files, modified kernel sysctl, and firewall
state that invalidate clean-room acceptance testing. Clear documentation of this operational cycle prevents
unexpected Phase 0.7 failures.

---

### D12: Panel API TLS Context and Request Timeout Injection

**Chosen:** Extend `modules/api_client.py`'s `GoWaveClient` constructor compatibly with optional `ssl_context`
and `timeout` parameters (defaults preserve existing callers). Its `urlopen` call passes the configured timeout
and SSL context; `panel_api.py` constructs a client for `https://MASTER_PANEL_DOMAIN` with an SSL context built
from the per-run mode-specific CA bundle (public roots only in production, public plus verified Staging roots
in staging). Do not use `allowInsecure`, disable hostname verification, or silently fall back to system roots if
the mode-specific bundle cannot be built. API timeout applies
to each HTTP attempt; `NODE_READY_TIMEOUT` remains the separate overall polling deadline.

**Rationale:** The current `GoWaveClient` hard-codes `urlopen(..., timeout=15)` and exposes no SSL-context
injection. The E2E contract requires both a staging-aware trust context and configured `API_TIMEOUT`; those
cannot be claimed by simply instantiating the current class unchanged.

---

### D13: Partial Run State and Optional Negative Suite Semantics

**Chosen:** A fresh `--mode preflight` without `--run-id` generates a new `TEST_RUN_ID`; it may also accept
an explicitly supplied unused ID. Preflight performs read-only SSH inspection, stores the baseline manifest,
and atomically creates a mode-`0600` `run-state.json` under
`artifacts/live-vps/<TEST_RUN_ID>/run-state.json`. It prints the generated ID for the subsequent command.
`--mode full` also generates a new ID and executes all phases in one run; it MUST reject an already existing
run directory rather than overwrite it. The state records only non-secret target/config identity, repository
commit, baseline-manifest reference, phase statuses and timestamps. It MUST NOT contain passwords, tokens,
`SECRET_KEY`, `shortUuid`, subscription contents, or hashes of secret values.

Every later partial mode (`install`, `verify`, `traffic`, `negative`, `teardown`) requires `--run-id` and an
existing matching run-state record. It verifies target addresses, pinned repository commit and non-secret
configuration identity before proceeding. `install` requires a successful preflight record; `verify` requires
successful install records; `traffic` requires verification PASS; `negative` requires an installed disposable
environment; `teardown` requires an existing run and diagnostics/baseline record. A completed phase is not
repeated implicitly. A mismatch or missing state record fails closed before remote modification.

`TEST_RUN_ID` is a path component, not an arbitrary path. Accept only `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`;
explicitly reject `.` and `..`, path separators, NUL and any value whose resolved artifact path escapes
`artifacts/live-vps/`. Reject a pre-existing run directory, symlinked run directory, or symlinked parent path;
create the directory atomically with restrictive permissions. The same validation applies to generated IDs.

`install` requires a successful preflight record and, after reacquiring both remote locks, MUST re-collect the
baseline/disposable-gate invariants and compare them with the saved preflight manifest before its first remote
mutation. A stale run-state record or any baseline drift fails closed; it is not enough that the original
preflight phase once passed.

`TEST_NEGATIVE_SUITE` defaults to `true`. When explicitly false, all 15 negative scenarios are `SKIP` and the
overall result is at least `INCOMPLETE`; disabling the suite can never yield overall `PASS`.

**Rationale:** The CLI currently lists partial modes but has no durable contract for which run they resume or
how it prevents a second install from mutating an already provisioned VPS. The config already exposes a
negative-suite switch, so its effect on the acceptance gate must be normative.

---

### D14: Optional Vision Is a Paired, Fail-Closed Capability

**Chosen:** VLESS XTLS Vision is optional at the deployment level, but when enabled it is a required
capability on both VPS. `MASTER_VISION_DOMAIN` and `WORKER_VISION_DOMAIN` MUST either both be configured
or both be absent. A one-sided configuration is invalid and is rejected by the local config parser before
SSH or any remote modification. This keeps the topology and runtime matrix unambiguous: four inbounds per
node and sixteen client/runtime cases when disabled; five inbounds per node and twenty cases when enabled.

When the pair is configured:

1. Master installation MUST issue and cryptographically verify the Vision certificate in addition to the
   Panel and REALITY certificates before compiling/provisioning the Master profile. The current best-effort
   suppression of Vision Certbot/certificate-verification failures (`|| true`) MUST be removed for this E2E
   path. A missing, wrong-ACME-lineage, expired, or hostname-invalid Vision certificate fails Master
   installation; implementation MUST record which requested-domain lineages existed before the transaction.
   Cleanup may remove only lineages created by the failed transaction. If Certbot changes a pre-existing
   lineage, the implementation MUST restore its pre-install certificate, key, and renewal configuration from
   a securely permissioned transaction snapshot; if safe restoration cannot be guaranteed, fail before
   issuance. The rollback test MUST prove that no pre-existing lineage or unrelated certificate is lost and
   no partial Vision profile, certificate consumer, or NGINX route remains active. The runner MUST NOT report
   a partial four-inbound Master as successful Vision-enabled installation.
2. `gowave-auto.sh node add` MUST receive the Worker Vision domain through an explicit named
   `--vision-domain` option (not by shifting the existing optional SSH-user/SSH-port positional arguments).
   It validates the domain, includes it in the Worker API profile via `compile_config_profile(...,
   vision_domain=...)` and `provision_hosts(..., vision_domain=...)`, and records it in `state.json`.
3. `gowave-node-auto.sh remote_payload` MUST serialize the Worker Vision domain over SSH stdin. Before
   issuing the third certificate, the Worker HTTP-01 bootstrap server's `server_name` MUST include
   `WORKER_VISION_DOMAIN` as well as the mandatory Worker and REALITY domains; the challenge path MUST resolve
   to the same webroot for all three names. Worker installation MUST issue and verify its Vision certificate
   using the same selected `GOWAVE_ACME_SERVER` as its Panel/REALITY certificates and validate the matching
   renewal lineage. The NGINX stream map routes Vision SNI to `127.0.0.1:8444`; the Xray Vision fallback
   template sends non-VLESS HTTP traffic to `127.0.0.1:9444` with PROXY protocol (`xver: 1`). Worker MUST
   create a loopback-only cleartext HTTP decoy vhost on `127.0.0.1:9444` with `proxy_protocol` enabled,
   serving the managed cover-reality content and never the GoWave Panel/API. `nginx -t` MUST pass before
   activation/reload. Any requested Vision prerequisite failure fails the Worker phase.
4. Worker failure compensation MUST account for all Worker certificate and Vision artifacts: record the
   pre-transaction presence/identity of the Worker, REALITY and optional Vision lineages; remove only lineages
   created by this transaction, and restore any pre-existing lineage changed by Certbot from a secure snapshot.
   The same ownership rule applies to bootstrap names, renewal metadata, stream-map entries, the 9444 vhost,
   generated inbound/profile/host state and deploy-hook effects. Rollback MUST restore a valid NGINX
   configuration before reload and MUST NOT delete unrelated resources. If ownership or restoration cannot
   be proven, fail closed and report cleanup incomplete. The Master orchestrator MUST check and record both
   remote Worker rollback and Panel API rollback results; it MUST NOT suppress a failed `remote_rollback` with
   `|| true`. If either compensation fails, preserve the recovery journal, mark rollback incomplete and force
   the E2E run to `INCOMPLETE`; only verified success of both sides is rollback PASS.
5. Panel API acceptance MUST verify five inbounds and five corresponding hosts per node, including each
   Vision inbound/host association. The subscription MUST expose one Vision proxy per VPS, and Xray and
   Mihomo MUST each execute the two Vision endpoints as independent runtime cases.
6. When both Vision domains are absent, the default four-inbound topology remains unchanged: no Vision
   certificate issuance, no Vision SNI route/fallback, and no Vision subscription endpoint.

**Rationale:** The current Master installer suppresses Vision certificate issuance/verification errors, while
the current Worker dispatch does not propagate the Vision domain into Worker API provisioning or Worker
certificate issuance. Treating Vision as active after either partial path can create mismatched Master/Worker
profiles, missing TLS material, or an advertised proxy that cannot accept traffic. Pair validation and
fail-closed activation make the sixteen-versus-twenty test matrix deterministic.

---

### D15: ACME Lineage Snapshot Ownership and Recovery

**Chosen:** Before any Certbot command may reuse, renew, replace, or delete a requested-domain lineage, the
installer records whether that lineage existed before the transaction. For an existing lineage, it snapshots
the complete recoverable state on the same VPS under
`/var/lib/gowave-auto-nginx/recovery/<transaction-id>/acme/<domain>/`: the renewal configuration, live symlink
targets, archive certificate and private-key bytes, ownership, and file modes. Snapshot directories MUST be
owned by root with mode `0700`; regular snapshot files containing private keys MUST be root-owned mode `0600`.
The snapshot MUST NOT be copied to the Control Machine, runner artifacts, CI artifacts, logs, or reports.

On successful installation, the snapshot is removed only after the transaction is committed and all certificate
consumers, renewal configuration, and NGINX health checks have passed. On failure, rollback restores the complete
pre-transaction state and verifies the restored bytes, symlink targets, ownership, and modes; only lineages
recorded as absent before the transaction may be removed as transaction-created. If restoration cannot be
verified, the snapshot is retained for operator recovery and the transaction/teardown is reported incomplete.
The same ownership and recovery protocol applies to Master and Worker and to Panel, REALITY, and optional Vision
domains.

**Rationale:** Certbot can reuse an existing same-directory lineage, and a later failure must not cause broad
rollback code to delete a certificate and private key that pre-dated the current deployment transaction.

---

### D16: Scoped CA Trust for Master Installer TLS/SNI Verification

**Chosen:** `gowave-auto.sh:verify_public_tls_sni` currently invokes OpenSSL with the system
`/etc/ssl/certs` CA path. That check is incompatible with `ACME_MODE=staging`: Let's Encrypt Staging roots are
not part of ordinary system trust and MUST NOT be installed there. For E2E invocations, the runner MUST stage
the exact mode-specific CA bundle built by D9 on Master in a root-owned mode-`0700` directory under `/run`,
with a root-owned mode-`0600` bundle file, and pass its path as `GOWAVE_TLS_CA_FILE`. When that variable is set,
`verify_public_tls_sni` MUST use OpenSSL `-CAfile "$GOWAVE_TLS_CA_FILE"` while retaining
`-verify_return_error` and `-verify_hostname`; it MUST NOT fall back to the system CA path on an error. The
same optional override applies to `domain-change`. When unset, legacy callers retain the existing system
`-CApath` behavior. The runner removes the remote bundle on both success and failure; it is never copied to
system trust stores, kept in persistent state, or included in artifacts. Production mode uses the complete
public-CA bundle; staging mode uses the same bundle plus the four validated Staging roots.

**Rationale:** Master installation calls `verify_public_tls_sni` after certificate issuance, and domain change
calls it after certificate replacement. Without a scoped trust override, a valid staging certificate fails
that local OpenSSL probe because the staging roots are intentionally absent from system trust.

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
  0.2  Acquire the local per-target `fcntl.flock` in the private runtime directory
  0.3  Control Machine tool check (python3, ssh, openssl, curl, dig, xray, mihomo)
  0.4  SSH trust check (both VPS, StrictHostKeyChecking=yes, exact pinned entries from the single SSH_KNOWN_HOSTS file); verify `id -u == 0` on both hosts using read-only commands and fail before lock acquisition/mutation for non-root identities
  0.5  Reject identical MASTER_IP/WORKER_IP and duplicate mandatory Panel/REALITY FQDNs; when Vision is enabled require all six FQDNs pairwise unique. Verify DNS (4 mandatory domains plus optional Vision pair, A/AAAA, 2+ resolvers)
  0.6  Baseline snapshot (systemd, listeners, firewall, GoWave dirs)
  0.7  Disposable gate (reject if GoWave present or ports occupied)
  0.8  Port hygiene (11+ required ports checked as free: 80, 443, 3000, 3001, 3002, 7443, 8443, 9443, 10001, 10002, 10003; plus 8444 and 9444 when the Vision domain pair is enabled)
  0.9  Acquire and hold authoritative `flock` sessions on both VPS hosts in deterministic address order;
       preflight-only runs release them on exit; all mutating phases require both locks
  0.10 Re-collect the read-only baseline/disposable gate on both hosts while both locks are held; if any
       invariant differs from the snapshot taken in 0.6, fail before remote modification

Phase 1: Master Installation
  1.1  After acquiring both remote locks (including in partial `install` mode), re-collect and compare the
       stored preflight baseline before the first remote mutation; stale or changed baseline → fail closed
  1.2  Copy pinned repo commit to Master /opt/gowave-auto-nginx; stage the exact D9 mode-specific CA bundle
       in a root-owned mode-0700 `/run` directory with a mode-0600 file
  1.3  Run gowave-auto.sh install with `GOWAVE_ACME_SERVER` derived from `ACME_MODE` and
       `GOWAVE_TLS_CA_FILE` pointing to the staged bundle; set `GOWAVE_NODE_REQUIRE_BUNDLED_INSTALLER=1`
       and provide the pinned Node installer commit + SHA256;
       when the validated Vision pair is enabled, pass `VISION_DOMAIN=MASTER_VISION_DOMAIN` in the
       controlled environment and require Master Vision certificate issuance/verification to succeed
  1.4  Verify service states, listeners, TLS certs
  1.5  Verify credentials file (mode, owner, keys present — values not logged)
  1.6  Retrieve shortUuid (state.json + API cross-check)
  1.7  Verify Panel locally and from Control Machine
  1.8  Install/verify the distribution `strace` package on Master, record `strace -V`, and prove the
       installed build supports `-f`, `-v`, `-s` and `execveat`; fail before Worker dispatch if unavailable
  1.9  Record and compare versions (Panel, Node, Node installer commit/hash, Xray server and client,
       Mihomo, NGINX, OpenSSL, OS/kernel); an unpinned/mismatched component cannot PASS

Phase 2: Worker Deployment
  2.1  Run `gowave-auto.sh node add worker-1` on Master with the same validated ACME directory and the
       same Node-installer commit + SHA256 explicitly supplied again for the Worker dispatch; when the
       validated Vision pair is enabled, pass `--vision-domain WORKER_VISION_DOMAIN` as a named option
  2.2  Verify exit code, state.json, process argv observation (SECRET_KEY not in Master-side argv)
  2.3  Verify Worker services, listeners, certs, deploy hook, cover-reality SHA256
  2.4  Poll Panel API isConnected until true (bounded NODE_READY_TIMEOUT)

Phase 3: Public mTLS Verification (execute allowed-source probes from Master)
  3.1  On Master, run `/opt/gowave/gowave-server rescue --print-secret-key-raw` via the existing
       `modules/node.sh:extract_secret_key` contract; capture stdout in memory only (not state.json or credentials)
  3.2  Feed the already-Base64-encoded extractor output unchanged to verifier stdin (do NOT encode it again);
       the verifier performs one base64 decode. Run it on Master against Worker:3002 and retain raw output only in memory
  3.3  Parse only actual verifier output: `Payload cryptographic verification PASSED`,
       `Handshake SUCCESS: TLSv1.3 negotiated`, `Node response: <status line>`, and exit code;
       never persist derived SNI or payload
  3.4  Treat 200 as HTTP health success; 401 as TLS/SNI reached HTTP layer but not authenticated health
  3.5  Verify Panel↔Worker authenticated connectivity independently through Panel API state
  3.6  Run client-cert rejected / no-client-cert server-side probes from Master
  3.7  Run wrong-key local client-load test and wrong-server-CA client-verification test separately

Phase 4: Panel API Audit
  4.1  GET /api/nodes — 2 nodes, correct addresses, 4 inbounds each (or 5 with the validated Vision pair), isConnected
  4.2  GET /api/config-profiles — 2 profiles, 4 inbounds each (or 5 with the validated Vision pair), computed-config valid JSON
  4.3  GET /api/internal-squads — Default MVP Squad, 8 inbound UUIDs (or 10 with the validated Vision pair), set equality
  4.4  GET /api/hosts — 8 hosts (or 10 with the validated Vision pair), all fields verified, fingerprint="firefox", correct node/inbound associations

Phase 5: Subscriptions
  5.1  GET /api/users/by-username/default-user → shortUuid
  5.2  User-Agent policy (empty, absent, Xray UA, Mihomo UA → check actual Panel response)
  5.3  Fetch Xray JSON (Xray UA), verify 8 proxy outbounds (or 10 when the paired Vision domains are configured), fingerprint="firefox", headers, no server secrets
  5.4  Validate with xray run -test (temporary wrapper config)
  5.5  Fetch Mihomo YAML (Mihomo UA), verify 8 proxies (or 10 when the paired Vision domains are configured), client-fingerprint="firefox", GEOIP rule, headers
  5.6  Validate with mihomo -t
  5.7  Verify Mihomo runtime copy binds all local listeners to 127.0.0.1 on collision-free per-run ports;
       preserve proxy/rule semantics and reject externally exposed or non-loopback controllers

Phase 6: Firewall
  6.1  Master: loopback 127.0.0.1:3002 reachable; Control Machine public probe blocked
  6.2  Worker: establish positive mTLS probe from Master first; record actual Master source IP seen by Worker
  6.3  Compare observed source IP with the effective UFW allow rule; do not trust a separately queried egress IP alone
  6.4  Observe the actual Control Machine probe source address on the target VPS and compare it with the
       Master source address allowed by UFW; if they are equal, the Worker negative probe cannot prove
       isolation and MUST be `INCOMPLETE` (use a distinct external probe vantage for PASS)
  6.5  Confirm DROP evidence on the target host: Master evidence for Master external probes; Worker evidence for Control Machine → Worker probes
  6.6  Repeat equivalent checks over IPv6 when ENABLE_IPV6=true

Phase 7: NGINX SNI + REALITY Decoy (+ Optional Vision)
  7.1  Panel HTTPS with correct SNI (TLS cert valid, Panel API responds)
  7.2  Worker HTTPS with correct SNI
  7.3  REALITY fallback with REALITY SNI + invalid REALITY params (decoy content on 9443, not GoWave API)
  7.4  Unknown SNI routing (matches NGINX + Xray REALITY fallback behavior)
  7.5  Optional paired-Vision SNI routing to 8444 and non-VLESS HTTP fallback to decoy on 9444 when configured
  7.6  nginx -t on both VPS configs
  7.7  cover-reality unique marker file accessible
  7.8  PROXY protocol integrity (inferred from correct Panel, Worker, REALITY, and Vision responses)

Phase 8: Data Plane E2E (8 or 10 logical endpoints × 2 client runtimes = 16 or 20 required cases)
  8.1  Logical endpoint matrix: Master × {VLESS REALITY, VLESS XHTTP, VLESS WS, Trojan gRPC, and optional VLESS XTLS-Vision when the Vision domain pair is configured}
       and Worker × the same protocols (8 endpoints by default; 10 when both Vision domains are configured)
  8.2  For each logical endpoint, run a real Xray client case and a real Mihomo client case (with firefox fingerprint):
       - Extract the corresponding proxy from the real subscription
       - Build/validate a temporary Xray wrapper config; for Mihomo, create a per-run sanitized copy of
         the real YAML preserving proxy definitions/rules but assigning free loopback-only mixed/SOCKS/
         redir/controller ports and verifying `allow-lan: false` plus loopback controller binding
       - Start the actual client process and wait for its selected local proxy listener
       - Send HTTPS request through the selected proxy; verify HTTP response and observed egress IP
       - Verify target VPS ingress evidence in an isolated observation window
       - Stop client and remove temporary configuration
  8.3  All 16 (or 20) cases are mandatory for overall PASS. If a client runtime is intentionally disabled, mark its
       cases SKIP and overall status INCOMPLETE. A syntax-only validation is not a runtime traffic pass.

Phase 9: Negative Tests (NEG-01 .. NEG-15)
  NEG-01..NEG-04 are isolated preflight contract tests using temporary known_hosts/config fixtures and
  mocked SSH/DNS responses; never mutate the operator's real known_hosts file, public DNS, or SSH firewall.
  NEG-05 uses an isolated Certbot failure fixture/failpoint (or an explicitly isolated staging test domain)
  with guaranteed cleanup; it MUST NOT damage the active control domains or production lineages.
  NEG-06..NEG-15 run only against confirmed disposable VPS state, with per-case cleanup and baseline checks;
  any case that cannot restore its required preconditions is INCOMPLETE and stops dependent cases.
  If TEST_NEGATIVE_SUITE=false, record all 15 as SKIP and force overall INCOMPLETE (never PASS)

Phase 10: Diagnostics Collection
  SSH dump: OS, packages, systemd, listeners, firewall, nginx -t, cert metadata, API summaries, and the
  full version/digest inventory required by the result.json schema (Control Machine, Master, Worker).
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

**Problem:** The production installer currently invokes Certbot without `--server`; the runner's public
configuration exposes `ACME_MODE`, while the installer contract uses `GOWAVE_ACME_SERVER`. These are two
interfaces and MUST have one explicit mapping. The same selected directory must reach both Worker certificate
issuance calls through the `node add` SSH-stdin payload.

**Canonical mapping in the runner:**

| `ACME_MODE` | Exact `GOWAVE_ACME_SERVER` value |
|---|---|
| `staging` | `https://acme-staging-v02.api.letsencrypt.org/directory` |
| `production` | `https://acme-v02.api.letsencrypt.org/directory` |

The runner accepts only the `ACME_MODE` enum and derives the URL itself; arbitrary ACME directory URLs are not
accepted from the E2E config. The install scripts accept only those two exact URLs when `GOWAVE_ACME_SERVER`
is set. When the variable is unset outside the runner, existing production-default behavior remains unchanged.

**Propagation contract:**
1. The runner derives the exact URL once and passes it to `gowave-auto.sh install` and `gowave-auto.sh node add`.
2. `gowave-auto.sh install` and `domain-change` append `--server "$GOWAVE_ACME_SERVER"` to every Certbot issuance
   call when set. `install` issues two mandatory lineages (Panel and REALITY) and a third Vision lineage only
   when the validated Vision pair is enabled; `domain-change` applies the selected server to every lineage it
   issues for the domains being changed.
3. `gowave-auto.sh node add` forwards the same value to `gowave-node-auto.sh remote_payload`.
4. `remote_payload()` serializes the validated ACME URL and optional Worker Vision domain into the SSH stdin
   script. Worker issues the two mandatory Worker/REALITY lineages and, when Vision is enabled, a third Vision
   lineage; every requested Certbot call uses that exact URL. A configured Vision certificate is mandatory,
   not best-effort.
5. Before any certificate reuse, Master and Worker validate the renewal lineage's `server` directory URL
   for every requested domain (including Vision when enabled) against the selected mode. Missing, unknown,
   or opposite-mode lineage metadata fails closed; do not infer
   the ACME directory from a generic Let's Encrypt issuer string alone. A switch between modes requires a
   verified isolated lineage plus atomic consumer/renewal-hook path migration, or a fresh disposable baseline;
   never silently reuse or overwrite a cross-mode lineage.
6. Tests cover both mandatory Master issuance calls, both mandatory Worker issuance calls, optional Vision
   issuance on each host, `domain-change`, SSH propagation, lineage isolation for every configured domain,
   and unset-variable backward compatibility.
7. For E2E Master `install` and `domain-change`, the runner stages the D9 mode-specific CA bundle on Master
   and supplies `GOWAVE_TLS_CA_FILE` to the installer. `verify_public_tls_sni` uses that file for chain and
   hostname verification without changing `/etc/ssl/certs`; the remote bundle is removed after success or
   failure. A staging certificate must pass this local probe, while an untrusted test CA must still fail.

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
| **NEG-14**  | Worker Deploy    | Duplicate `node add` invocation when the name is already in `state.json` | Explicit fail-fast rejection before API client creation; no state/DB mutation or duplicate entities |
| **NEG-15**  | Panel API Auth   | API request with expired or forged JWT | Panel returns 401 Unauthorized |

---

## Whitelist Configuration Schema (`tools/live_vps_config.env`)

The whitelist parser in `tools/live_vps/config.py` enforces POSIX permissions `0600` and validates every key against
the following strict schema:

| Variable Name | Type / Format | Mandatory | Default | Description |
|---------------|---------------|-----------|---------|-------------|
| `MASTER_IP` | IPv4 address | Yes | — | Public IPv4 of Master VPS (disallowed: RFC-1918, loopback, docs); MUST differ from `WORKER_IP` |
| `MASTER_PANEL_DOMAIN` | FQDN | Yes | — | Domain pointing to Master Panel NGINX HTTPS |
| `MASTER_REALITY_DOMAIN` | FQDN | Yes | — | Camouflage decoy domain pointing to Master REALITY SNI |
| `MASTER_VISION_DOMAIN` | FQDN | Conditional pair | — | Master Vision domain; must be set together with `WORKER_VISION_DOMAIN` |
| `MASTER_SSH_PORT` | Integer 1–65535 | No | `22` | Master SSH management port |
| `MASTER_SSH_USER` | Literal `root` | No | `root` | Master SSH login identity; non-root is unsupported in E2E v1 |
| `WORKER_IP` | IPv4 address | Yes | — | Public IPv4 of Worker VPS; MUST differ from `MASTER_IP` |
| `WORKER_DOMAIN` | FQDN | Yes | — | Domain pointing to Worker NGINX HTTPS |
| `WORKER_REALITY_DOMAIN` | FQDN | Yes | — | Camouflage decoy domain pointing to Worker REALITY SNI |
| `WORKER_VISION_DOMAIN` | FQDN | Conditional pair | — | Worker Vision domain; must be set together with `MASTER_VISION_DOMAIN` |
| `WORKER_SSH_PORT` | Integer 1–65535 | No | `22` | Worker SSH management port |
| `WORKER_SSH_USER` | Literal `root` | No | `root` | Worker SSH login identity; non-root is unsupported in E2E v1 |
| `SSH_KEY_PATH` | File path | Yes | — | Path to private SSH key for authentication |
| `SSH_KNOWN_HOSTS` | File path | Yes | — | One pre-pinned `known_hosts` file containing both VPS host keys; each connection selects its exact host/port entry |
| `ACME_MODE` | `staging` \| `production` | No | `staging` | Let's Encrypt endpoint mode |
| `GOWAVE_PANEL_VERSION` | SemVer / commit | Yes | — | Target GoWave Panel version to pin and verify |
| `GOWAVE_NODE_VERSION` | SemVer / commit | Yes | — | Target GoWave Node version to pin and verify |
| `GOWAVE_NODE_INSTALLER_COMMIT` | 40-hex SHA | Yes | — | Pinned upstream `install.sh` commit; same value is used by Master-local and remote Worker paths |
| `GOWAVE_NODE_INSTALLER_SHA256` | 64-hex SHA256 | Yes | — | SHA256 of exact upstream `install.sh` bytes at the pinned commit; verified before either execution path |
| `XRAY_SERVER_VERSION` | Version string | Yes | — | Expected GoWave Node-managed Xray/rw-core version on both VPS; record and compare independently of Node version |
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
| `TEST_MIHOMO_TRAFFIC` | Boolean | No | `true` | Verify traffic with real Mihomo client process; false skips mandatory Mihomo cases and makes overall status INCOMPLETE |
| `TEST_NEGATIVE_SUITE` | Boolean | No | `true` | Execute NEG-01 through NEG-15; false marks all 15 SKIP and overall INCOMPLETE (never PASS) |
| `TEST_TEARDOWN_POLICY` | Enum: `PRESERVE`, `RESTORE_SNAPSHOT` | No | `PRESERVE` | Mutually exclusive teardown policy; `DESTROY` is rejected in v1 |
| `MASTER_SNAPSHOT_ID` | String | Conditional | — | Required for RESTORE_SNAPSHOT; operator-managed Master snapshot identifier |
| `WORKER_SNAPSHOT_ID` | String | Conditional | — | Required for RESTORE_SNAPSHOT; operator-managed Worker snapshot identifier |
| `SNAPSHOT_RESTORE_HOOK` | Absolute file path | Conditional | — | Required for RESTORE_SNAPSHOT; external Control Machine restore executable |
| `SNAPSHOT_RESTORE_HOOK_SHA256` | 64-hex SHA256 | Conditional | — | Required digest pin for the external restore hook |
| `RESTORE_TIMEOUT` | Integer seconds | No | `900` | Maximum runtime for external restore hook and post-restore readiness checks |
| `ADMIN_EMAIL` | Email address | No | `admin@example.com` | Email for ACME certificate registration |

---

## Installer Pinning Gate

**Problem:** `modules/node.sh` falls back to `curl .../main/install.sh` when no bundled installer is present;
`gowave-node-auto.sh` separately hard-codes the remote installer commit and downloads `install.sh` without a
content-digest check. The config's `GOWAVE_NODE_INSTALLER_COMMIT` therefore does not currently control both
installation paths, and a commit pin alone is not the documented commit-plus-content-integrity contract.

**Solution:** Vendor `sources/gowave-node/install.sh` from the exact configured 40-hex commit and record its
real SHA256 in `GOWAVE_NODE_INSTALLER_SHA256`. The Master-local installer path MUST verify the bundled file against the configured SHA256; the commit
provenance is established by fetching the upstream file at the configured immutable commit during vendoring
and recording that source commit alongside the vendored artifact. The remote Worker path MUST use the same
configured commit and digest, fetch only the immutable commit URL, verify the downloaded file's SHA256 before
execution, and fail closed on any mismatch. `GOWAVE_NODE_REQUIRE_BUNDLED_INSTALLER=1` disables the local
floating-`main` fallback for E2E. The remote script MUST NOT keep an independent hard-coded commit that can
drift from runner configuration. The actual digest is computed from the vendored upstream file during
implementation; no guessed or placeholder digest is allowed.

**Required propagation chain:** the runner supplies `GOWAVE_NODE_INSTALLER_COMMIT` and
`GOWAVE_NODE_INSTALLER_SHA256` to the Master for both `gowave-auto.sh install` and the later
`gowave-auto.sh node add` invocation. `gowave-auto.sh node add` MUST pass both values to
`gowave-node-auto.sh remote_payload`; that function MUST serialize both into the SSH-stdin Worker script.
The Worker MUST validate the commit format and digest, fetch the exact commit URL, verify the bytes, and only
then execute the installer. Supplying the variables only to the initial Master install is insufficient.

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
→ Mitigation: Preflight checks client versions against `XRAY_CLIENT_VERSION` and `MIHOMO_CLIENT_VERSION`,
and checks the Node-managed server core independently against `XRAY_SERVER_VERSION`; mismatches terminate preflight.

**[RISK] API TLS behavior differs between system trust and the Staging CA bundle**
→ Mitigation: `GoWaveClient` accepts an injected SSL context and timeout; staging and public-CA positive
requests plus an untrusted-CA negative test validate the actual pinned Python client path.

**[RISK] Mihomo's subscription listener/controller ports collide with Control Machine services**
→ Mitigation: Runtime config is isolated to loopback and free per-run ports; proxy definitions and rules are
preserved and the controller is local only.

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
- **Worker `isConnected` polling behavior:** The 120s `NODE_READY_TIMEOUT` with 5s polling interval is a provisional
  initial bound, not a measured real-VPS guarantee. Mock integration benchmarks do not establish the latency
  distribution of the pinned Panel/Node pair; staging acceptance MUST record observed registration latency and
  adjust the default or document the evidence before production acceptance.
