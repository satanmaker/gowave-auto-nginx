# Tasks: Live VPS E2E Testing

> **Findings from codebase audit & design.md:**
> - GoWave Panel profile templates in `assets/xray/` do NOT configure the Xray Stats gRPC API. Upstream binaries are immutable per AGENTS.md. Server-side traffic evidence uses per-case packet counters or bounded packet capture on the actual public transport listener (currently TCP/443 behind NGINX stream); protocol identity is established by the selected client outbound and successful request, not by a shared port counter alone.
> - When `ACME_MODE=staging`, one mode-0600 scoped CA bundle combines the Control Machine's complete default public roots with the pinned Let's Encrypt Staging chain. Python, curl, Xray and Mihomo all use this same bundle; staging-only trust stores are forbidden because public egress targets must remain trusted.
> - Worker `NODE_READY_TIMEOUT` default is 120s with 5s fixed-interval polling.

---

## 1. Install Script Delta: ACME Staging Support

- [ ] 1.1 Add `GOWAVE_ACME_SERVER` env var support to `gowave-auto.sh install` and `gowave-auto.sh domain-change`: when set, append `--server "$GOWAVE_ACME_SERVER"` to all `certbot certonly` calls; validate the existing renewal lineage's ACME directory and prevent staging/production lineage reuse; verify with `bash -n` and `shellcheck --severity=error`
- [ ] 1.2 Forward `GOWAVE_ACME_SERVER` in `gowave-auto.sh node add`: pass `GOWAVE_ACME_SERVER="${GOWAVE_ACME_SERVER:-}"` when invoking `gowave-node-auto.sh remote_payload`
- [ ] 1.3 Add `GOWAVE_ACME_SERVER` env var support to `gowave-node-auto.sh`: serialize variable over SSH stdin in `remote_payload()`, and append `--server "$GOWAVE_ACME_SERVER"` to Worker `certbot certonly` calls; validate lineage directory and preserve the NGINX certificate path contract; verify with `bash -n` and `shellcheck --severity=error`
- [ ] 1.4 Verify ACME staging delta backward-compat: when `GOWAVE_ACME_SERVER` is unset, certbot behavior is identical to current; confirm by grepping generated certbot commands in test output or unit test for the env var branch
- [ ] 1.5 Add a pre-install ACME lineage guard: inspect `/etc/letsencrypt/renewal/*.conf` and certificate issuer/chain for every requested domain; if the existing lineage belongs to a different ACME directory, fail before changing NGINX or replacing certificates unless an explicit isolated lineage migration is implemented and all NGINX consumers are updated atomically; test staging→production and production→staging rejection

---

## 2. Installer Pinning Gate in `modules/node.sh` and `gowave-node-auto.sh`

- [ ] 2.1 Vendor `sources/gowave-node/install.sh` from the exact `GOWAVE_NODE_INSTALLER_COMMIT` upstream commit and record its real SHA256 in the mandatory `GOWAVE_NODE_INSTALLER_SHA256` config field. Verify the fetched source commit and digest independently; do not use a placeholder digest.
- [ ] 2.2 Add the E2E gate in `modules/node.sh`: when `GOWAVE_NODE_REQUIRE_BUNDLED_INSTALLER=1`, require the bundled installer, verify its SHA256 before execution, and fail closed if absent or mismatched; retain the current floating-`main` fallback only for non-E2E legacy invocations.
- [ ] 2.3 Remove the independent hard-coded installer commit from `gowave-node-auto.sh`: consume the configured commit and digest passed by the runner, fetch only `https://raw.githubusercontent.com/aaaSaZaN/gowave-node/<40-hex-commit>/install.sh`, verify its SHA256 before `bash`, and serialize both values via SSH stdin. A missing or mismatched digest MUST prevent execution on Worker.
- [ ] 2.4 Verify both Master-local and remote Worker paths use the same commit/hash, `GOWAVE_NODE_VERSION` is pinned, no E2E path can reach floating `main`, and run `bash -n`, ShellCheck, and negative tests for missing file, invalid commit, missing digest and tampered installer

---

## 3. Project Scaffolding and Config Parser

- [ ] 3.1 Create `tools/live_vps/` package skeleton: `__init__.py`, `config.py`, `tls.py`, `redaction.py`, `ssh.py`, `dns.py`, `preflight.py`, `deployment.py`, `mtls.py`, `panel_api.py`, `subscriptions.py`, `firewall.py`, `nginx.py`, `traffic.py`, `negative.py`, `teardown.py`, `reporting.py`; create `tools/test_live_vps.py` entrypoint stub; verify `python3 -c "from live_vps import config"` succeeds from `tools/`
- [ ] 3.2 Implement `config.py`: whitelist-only env parser (no `eval`, no `source`), `0600` file mode check, type/range/value validation for all keys in `live_vps_config.env.example`, fail on unknown or duplicate keys; write `tools/live_vps_config.env.example` with all params documented per design schema; add `tools/live_vps_config.env` to `.gitignore`; verify parser rejects unknown key, duplicate key, private IP, missing required field
- [ ] 3.3 Implement `tls.py` & `redaction.py`: validate all vendored Staging roots against the DER SHA-256 `pins.json` manifest, then build a mode-0600 per-run CA bundle from the complete Control Machine public CA roots plus those four roots; fail closed if either source is incomplete. Python uses `ssl.create_default_context(cafile=bundle)`, curl uses `--cacert bundle`, Xray/Mihomo receive `SSL_CERT_FILE=bundle`. Test that all four clients trust a staging-issued endpoint and an ordinary public-CA endpoint, while rejecting an untrusted test CA. Never use `allowInsecure` or `skip-cert-verify`. `redaction.py` maintains runtime redaction registry; verify unit tests
- [ ] 3.4 Vendor the four current self-signed Let's Encrypt Staging roots under `tools/certs/letsencrypt-staging/` from the exact official URLs in design D9; add `pins.json` entries with source URL, exact subject and SHA-256 of DER bytes for each PEM. Validate exactly four unique files, CA constraints, self-signature, validity window, subject and digest; do not vendor/pin intermediates or download roots at runtime. Add tests for missing/extra/duplicate roots, tampered PEM, wrong subject, expired/not-yet-valid cert, bad digest and manifest/source mismatch; make the update procedure review-gated.

---

## 4. SSH, DNS, and Preflight Modules

- [ ] 4.1 Implement `ssh.py`: subprocess wrapper for `ssh` and `scp` with `shell=False`, args as array, mandatory timeout, `StrictHostKeyChecking=yes`, `BatchMode=yes`, separate `known_hosts` per host, stdout/stderr captured separately and redacted before logging; no secrets in argv; verify unit test: command that would put a secret in argv raises `ValueError` before subprocess is called
- [ ] 4.2 Implement `dns.py`: A/AAAA/CNAME resolution via `dig` subprocess for all four required domains, minimum two independent resolvers, verification that resolved IP equals expected VPS IP, AAAA gated on `ENABLE_IPV6`, detection of unexpected CDN proxies; verify test: mock `dig` returning wrong IP triggers DNS preflight failure
- [ ] 4.3 Implement `preflight.py`: Control Machine tool inventory (python3 version, ssh, ssh-keygen, openssl, curl, dig, getent, timeout, xray version vs `XRAY_CLIENT_VERSION`, mihomo version vs `MIHOMO_CLIENT_VERSION`); SSH trust check for both VPS via `ssh-keygen -F <host> -f <known_hosts>`; reserved/private/documentation IP rejection (`ipaddress` module); baseline snapshot collection via SSH (systemd services, listeners, firewall, GoWave dirs, packages, sysctl, swap, fs); disposable gate (reject if GoWave dirs or port conflicts found); port hygiene check for 11+ required ports; run-level lock acquisition (`fcntl.flock`); verify: disposable gate rejects VPS with existing GoWave dirs

---

## 5. Deployment and Panel API Modules

- [ ] 5.1 Implement `deployment.py`: copy the pinned repository commit to Master via `git archive` + `scp`; derive `GOWAVE_ACME_SERVER` from the exact `ACME_MODE` mapping in design (never accept an arbitrary URL); inject that value plus `GOWAVE_NODE_REQUIRE_BUNDLED_INSTALLER=1`, `GOWAVE_NODE_INSTALLER_COMMIT`, and `GOWAVE_NODE_INSTALLER_SHA256` via SSH stdin. Verify services, listeners, certificates, credentials file mode/owner, `gowave-auto.sh health`, Panel/Node/Xray/Mihomo/NGINX/OpenSSL versions and binary digests. Missing service or any version/digest mismatch → `master_install` FAIL
- [ ] 5.2 Implement the Master-side Worker-dispatch observer in `deployment.py`: derive `STRACE_STRING_LIMIT = 32 * os.sysconf("SC_PAGE_SIZE")` on Master; run the local `gowave-auto.sh node add` process tree (including the local SSH client) under `strace -f -v -s "$STRACE_STRING_LIMIT" -e trace=execve,execveat`. This observer does NOT trace the remote Worker shell/process tree after SSH. `-v` / `--no-abbrev` prevents argv-vector abbreviation and `-s` prevents per-string truncation. Never use `-s 0` or `/proc` sampling. Write raw output only to a mode-0600 file in a private `/run` tmpfs directory (0700); because `-v` expands envp too, treat the trace as containing secrets, parse argv/envp separately, inspect argv only, discard envp and never persist/stream/publish raw trace. Require successful observer exit, local descendant coverage, all argv elements and strings parsed, and no truncated/abbreviated/unfinished exec records or observer errors; otherwise mark `INCOMPLETE`. Secret observed → FAIL; complete Master-side argv trace with no match → PASS
- [ ] 5.3 Extend `modules/api_client.py` compatibly: add optional `ssl_context` and `timeout` constructor parameters to `GoWaveClient`, pass them to `urllib.request.urlopen`, and preserve current defaults for all existing callers. Implement `panel_api.py` against the public Panel HTTPS URL with Bearer auth from `/api/auth/login` and the combined CA SSLContext; all requests use `API_TIMEOUT` per attempt, while `NODE_READY_TIMEOUT` bounds the complete `isConnected` polling loop. Add tests for Staging trust, ordinary public-CA trust, untrusted-CA rejection, hostname verification and timeout propagation
- [ ] 5.4 Add argv observer acceptance fixtures for both `execve` and `execveat`: (a) pass a sentinel after byte 32 of a long argument and prove complete string capture with computed positive `-s`; (b) pass at least 128 argv elements and put the sentinel only in the final element, proving `-v` / `--no-abbrev` captures every element in order without an omission marker. Verify the parser separates argv from envp and never publishes envp; default 32-character truncation, `-s 0`, abbreviated arrays, malformed records or incomplete output must never produce observer PASS

---

## 6. mTLS, Subscriptions, Firewall, and NGINX Modules

- [ ] 6.1 Implement `mtls.py`: on Master, obtain the secret using the existing `/opt/gowave/gowave-server rescue --print-secret-key-raw` path (`modules/node.sh:extract_secret_key`); do not read it from `state.json` or credentials file. Base64-encode as the verifier expects and feed stdin. Parse only actual verifier output (`Payload cryptographic verification PASSED`, `Handshake SUCCESS: TLSv1.3 negotiated`, `Node response`, exit code); retain payload and derived SNI only in memory and never log them. HTTP 401 is handshake evidence only, not HTTP health; use `200 OK` for `WORKER_HTTP_HEALTH_PASS`; verify `PANEL_WORKER_AUTH_PASS` through Panel's `GET /api/nodes` Worker `isConnected` state; execute server-side rejection tests from Master for untrusted and absent client certificates; classify mismatched cert/key as local client validation and untrusted server CA as client-side server-certificate validation; record wrong-SNI routing outcome without assuming a TLS alert
- [ ] 6.2 Implement `subscriptions.py`: retrieve `shortUuid` via `GET /api/users/by-username/default-user`; User-Agent policy tests (empty, absent, Xray UA, Mihomo UA) against real Panel; fetch and validate Xray JSON (8 proxy-capable outbounds, headers, no server secrets, `xray run -test` with wrapper config); fetch and validate Mihomo YAML (8 proxies, `GEOIP,private,DIRECT,no-resolve`, `mihomo -t`); verify: parser counts only proxy outbounds, not `direct`/`block`; shortUuid value never written to any log or report
- [ ] 6.3 Implement `firewall.py`: Master TCP/3002 — prove loopback reachability from Master; probe public TCP/3002 from Control Machine; confirm DROP using effective UFW rule/counter or packet trace collected on Master itself (never Worker evidence). Worker TCP/3002 — first complete a successful mTLS positive control from Master and record the source IP observed by Worker; then probe from Control Machine and confirm DROP using Worker-side UFW rule/counter or packet trace. For either host, timeout alone, connection refusal, route failure, or DNS failure is not DROP evidence; ambiguous results are INCOMPLETE. Repeat on IPv6 when enabled; verify evidence is collected on the target host
- [ ] 6.4 Implement `nginx.py`: verify Panel HTTPS (correct SNI, TLS cert valid, Panel API responds); Worker HTTPS (correct SNI); REALITY fallback (REALITY SNI + invalid REALITY params → decoy content, not GoWave API); unknown SNI routing (matches NGINX + Xray REALITY fallback behavior); `nginx -t` on both VPS; cover-reality unique marker file; verify PROXY protocol integrity (Panel and Worker HTTPS responses received correctly); verify: decoy check fails if GoWave API content is returned

---

## 7. Traffic Module: Xray and Mihomo Data Plane

- [ ] 7.1 Implement server-side traffic evidence collector in `traffic.py`: capture baseline and per-case packet evidence on the actual public transport listener (currently TCP/443 behind NGINX stream); run endpoint cases sequentially, record interface/filter/counter deltas, and confirm target VPS ingress; for Worker endpoint tests Master ingress must not increase in the same controlled window; ambiguous background traffic yields INCOMPLETE
- [ ] 7.2 Implement `traffic.py` Xray runner: for each of 8 proxy outbounds, build a mode-0600 temporary Xray wrapper config with a unique SOCKS5 port; pass the combined CA bundle through `SSL_CERT_FILE` to the Xray child process and pass the same bundle via `curl --cacert` for the HTTPS egress request; verify HTTP 200, egress IP and target-VPS ingress evidence; stop Xray and delete temporary config. Missing egress match or server evidence → endpoint FAIL
- [ ] 7.3 Implement `traffic.py` Mihomo runner (mandatory; if explicitly disabled, all eight Mihomo cases are SKIP and overall status is INCOMPLETE): write a mode-0600 per-run copy of the real subscription YAML; preserve proxy definitions and rules, but assign collision-free per-run ports to mixed/SOCKS/redir listeners and the external controller, bind all of them to `127.0.0.1`, enforce `allow-lan: false`, and reject a non-loopback controller. Pass the combined CA bundle through `SSL_CERT_FILE` to Mihomo and via `curl --cacert` to the HTTPS egress request; start Mihomo, select each of the eight proxies through the local controller API, and execute an HTTPS request per proxy. Verify egress and target-VPS ingress; stop Mihomo and delete temporary files. `TEST_MIHOMO_TRAFFIC=false` → eight SKIP and overall INCOMPLETE
- [ ] 7.4 Verify `TEST_TRAFFIC_VERIFICATION=false` produces overall `INCOMPLETE` not `PASS`; write unit test for the status gate logic

---

## 8. Negative Tests Module

- [ ] 8.1 Implement `negative.py` for preflight & install failures (NEG-01..NEG-05): simulate by mutating known_hosts, closing SSH port, returning wrong DNS IP, missing AAAA record, and inducing Certbot challenge failure; verify execution terminates before remote modification or marks installation unready
- [ ] 8.2 Implement `negative.py` for config & service recovery (NEG-06..NEG-08): inject invalid NGINX syntax, verify `nginx -t` failure blocks activation; stop `gowave-node.service` on Worker via SSH, verify Panel detects unavailability (`isConnected: false`); restart service, poll for `isConnected: true` within bounded timeout
- [ ] 8.3 Implement `negative.py` for protocol & security enforcement (NEG-09..NEG-10): request subscription without User-Agent against real Panel (verify 403); attempt mTLS to Worker with forged self-signed certificate, verify TLS 1.3 handshake rejected
- [ ] 8.4 Implement `negative.py` for backup & restore hardening (NEG-11..NEG-12): invoke `gowave-backup.sh restore` with corrupted tar header (NEG-11) and corrupted SQLite DB (NEG-12); verify preflight rejection before mutating live data or stopping services
- [ ] 8.5 Implement `negative.py` for state integrity & auth (NEG-13..NEG-15): interrupt SSH deployment mid-stream, verify Master recovery journal is not `COMMITTED`; execute duplicate `node add` for same worker, verify no duplicate DB entities; invoke Panel API with forged/expired JWT, verify 401
- [ ] 8.6 Write integration check: with `TEST_NEGATIVE_SUITE=true`, all 15 negative scenarios (NEG-01 through NEG-15) execute in sequence per normative matrix; at least NEG-07/NEG-08 (stop/restart) and NEG-14 (re-registration) execute on the live disposable VPS; `negative_tests` phase aggregates all 15. With the flag false, all 15 are explicitly SKIP and overall status is INCOMPLETE, never PASS

---

## 9. Teardown, Reporting, and CI

- [ ] 9.1 Implement `teardown.py`: accept only `TEST_TEARDOWN_POLICY=PRESERVE` (default) or `RESTORE_SNAPSHOT`; reject `DESTROY` and unknown values during preflight. For RESTORE_SNAPSHOT require both snapshot IDs, an absolute operator-supplied non-symlink restore hook and SHA256 pin; verify hook ownership, executable type, non-group/world-writable permissions and digest before the run and immediately before invocation. Invoke directly with `shell=False`, pass versioned JSON (run ID, both VPS addresses and snapshot IDs) via stdin, enforce `RESTORE_TIMEOUT`, and require exit 0 plus valid JSON `status=RESTORED` with matching IDs. Reconnect to both VPS and verify clean-baseline invariants against the pre-install manifest; any hook error or baseline mismatch → `TEARDOWN_FAILED`, never PASS. PRESERVE retains both VPS and diagnostics after success or failure and records teardown separately. Never treat project uninstall as OS baseline restoration
- [ ] 9.2 Implement `reporting.py`: `write_result_json()` producing `result.json` with all required schema fields (`test_run_id`, `repository_commit`, `started_at`, `finished_at`, `master`, `worker`, `results`, `traffic`, `overall`); `write_junit_report()` producing `junit.xml` with one `testcase` per required check, including sixteen separate Data Plane runtime cases (timing, failure message, no `shortUuid` in classname/message); `write_summary_txt()`; all output via redact-on-write; verify: unit test asserts `shortUuid` value does not appear in any output file; `PASS` gate verifier (all 16 runtime cases PASS: 8 logical endpoints × Xray and Mihomo)
- [ ] 9.3 Implement `diagnostics` collection in `reporting.py`: SSH dump per VPS (OS/kernel, packages, systemd status, journal snippets, listeners, `nginx -t`, firewall rules, cert metadata without private keys, API summaries, timing); write to `artifacts/live-vps/<TEST_RUN_ID>/diagnostics/master/` and `.../worker/`; verify: redacted copy written when mixed-content file detected; private key PEM blocks replaced with `[REDACTED]`
- [ ] 9.4 Implement `test_live_vps.py` CLI: `--config`, `--mode` (`preflight|install|verify|traffic|negative|teardown|full`), `--run-id`; `full` creates a new run and atomic mode-0600 `artifacts/live-vps/<run-id>/run-state.json` (or generates a unique ID). Partial modes require an existing run ID/state, compare repository commit, target addresses and non-secret config identity, and enforce prerequisites: `install` requires preflight PASS; `verify` requires install PASS; `traffic` requires verification PASS; `negative` requires an installed disposable environment; `teardown` requires baseline + diagnostic state. Never rerun a completed destructive phase implicitly. Verify mismatch/missing state fails before remote modification; `preflight` itself makes no remote changes
- [ ] 9.5 Write `.github/workflows/live-vps-e2e.yml`: `workflow_dispatch` only trigger, no auto-trigger on push/PR; uses named GitHub Environment with required reviewer for secret access; includes explicit pre-steps to download and install pinned `xray` and `mihomo` binaries onto runner; SSH keys and config delivered via GitHub Environment secrets (never printed to log); publishes JUnit XML as artifact; saves redacted diagnostics as artifact; `concurrency` block prevents parallel runs for the same environment; verify: `act -l` or dry-run shows no trigger on `push` or `pull_request` event
- [ ] 9.6 Add restore-hook tests: missing IDs/hook, non-executable or writable hook, SHA256 mismatch, timeout, nonzero exit, malformed JSON, mismatched snapshot IDs, unreachable VPS and baseline drift must fail closed; a valid hook response plus matching baseline on both VPS is the only RESTORE_SNAPSHOT PASS path

---

## 10. Integration Validation

- [ ] 10.1 Run `openspec validate live-vps-e2e-testing --strict` with zero errors; fix any schema violations before merging
- [ ] 10.2 Run `openspec validate --all --strict` to confirm existing `gowave-auto-nginx` change and all specs remain valid after the new change is added
- [ ] 10.3 Run `git diff --stat feature/gowave-auto-nginx` and verify: no existing test files modified except `modules/node.sh` and `gowave-auto.sh`/`gowave-node-auto.sh` ACME delta; no secrets or `.env` files committed; `tools/live_vps_config.env` absent from diff (in `.gitignore`)
- [ ] 10.4 Run `python3 tests/run_ci.py --check-completeness` and confirm existing 5-suite inventory is unaffected by new files
- [ ] 10.5 Run `shellcheck --severity=error gowave-auto.sh gowave-node-auto.sh modules/node.sh` after ACME and installer deltas to confirm zero new errors
- [ ] 10.6 Add regression tests for `ACME_MODE` → exact official directory mapping, propagation to both Worker Certbot calls, cross-mode lineage rejection, and production-default backward compatibility
- [ ] 10.7 Add tests proving both local and remote Node installer paths consume the same configured commit + SHA256 and reject tampered/missing installers
- [ ] 10.8 Add tests for partial-run resume identity/prerequisite checks and for `TEST_NEGATIVE_SUITE=false` forcing overall INCOMPLETE

---

## Workflow follow-up

- Once tasks are complete and all phases PASS on a staging ACME run, run a production acceptance run:
  `python3 tools/test_live_vps.py --config tools/live_vps_config.env --mode full` with `ACME_MODE=production`
  on freshly provisioned disposable VPS.
- After production acceptance and implementation completion, open a separate PR from the implementation branch to `feature/gowave-auto-nginx`. The OpenSpec-only change is reviewed independently and is not merged implicitly.
- After merge, archive this change with `openspec archive live-vps-e2e-testing`.





