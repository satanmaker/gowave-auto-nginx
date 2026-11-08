# Tasks: Live VPS E2E Testing

> **Findings from codebase audit & design.md:**
> - GoWave Panel profile templates in `assets/xray/` do NOT configure the Xray Stats gRPC API. Upstream binaries are immutable per AGENTS.md. Server-side traffic evidence uses iptables/nftables packet counters or temporary SSH packet capture on the destination port.
> - When `ACME_MODE=staging`, client wrappers (`panel_api.py`, `nginx.py`, `traffic.py`) configure trust for Let's Encrypt Staging CA (or `allowInsecure: true` in test client configs) to prevent `certificate verify failed` on TLS endpoints.
> - Worker `NODE_READY_TIMEOUT` default is 120s with 5s fixed-interval polling.

---

## 1. Install Script Delta: ACME Staging Support

- [ ] 1.1 Add `GOWAVE_ACME_SERVER` env var support to `gowave-auto.sh install` and `gowave-auto.sh domain-change`: when set, append `--server "$GOWAVE_ACME_SERVER"` to all `certbot certonly` calls; verify with `bash -n` and `shellcheck --severity=error`
- [ ] 1.2 Forward `GOWAVE_ACME_SERVER` in `gowave-auto.sh node add`: pass `GOWAVE_ACME_SERVER="${GOWAVE_ACME_SERVER:-}"` when invoking `gowave-node-auto.sh remote_payload`
- [ ] 1.3 Add `GOWAVE_ACME_SERVER` env var support to `gowave-node-auto.sh`: serialize variable over SSH stdin in `remote_payload()`, and append `--server "$GOWAVE_ACME_SERVER"` to Worker `certbot certonly` calls; verify with `bash -n` and `shellcheck --severity=error`
- [ ] 1.4 Verify ACME staging delta backward-compat: when `GOWAVE_ACME_SERVER` is unset, certbot behavior is identical to current; confirm by grepping generated certbot commands in test output or unit test for the env var branch

---

## 2. Installer Pinning Gate in `modules/node.sh`

- [ ] 2.1 Add preflight check in `modules/node.sh`: when no bundled installer exists at `sources/gowave-node/install.sh`, fail with an explicit error requiring `GOWAVE_NODE_INSTALLER_COMMIT` to be provided and the installer to be bundled; remove silent fallback to floating `main` for E2E-designated runs (gate on presence of a new env var `GOWAVE_NODE_REQUIRE_BUNDLED_INSTALLER=1`)
- [ ] 2.2 Write `bash -n` and `shellcheck --severity=error` clean; verify that existing tests for `modules/node.sh` still pass and that the new gate triggers correctly when bundled installer is absent under the env var

---

## 3. Project Scaffolding and Config Parser

- [ ] 3.1 Create `tools/live_vps/` package skeleton: `__init__.py`, `config.py`, `tls.py`, `redaction.py`, `ssh.py`, `dns.py`, `preflight.py`, `deployment.py`, `mtls.py`, `panel_api.py`, `subscriptions.py`, `firewall.py`, `nginx.py`, `traffic.py`, `negative.py`, `teardown.py`, `reporting.py`; create `tools/test_live_vps.py` entrypoint stub; verify `python3 -c "from live_vps import config"` succeeds from `tools/`
- [ ] 3.2 Implement `config.py`: whitelist-only env parser (no `eval`, no `source`), `0600` file mode check, type/range/value validation for all keys in `live_vps_config.env.example`, fail on unknown or duplicate keys; write `tools/live_vps_config.env.example` with all params documented per design schema; add `tools/live_vps_config.env` to `.gitignore`; verify parser rejects unknown key, duplicate key, private IP, missing required field
- [ ] 3.3 Implement `tls.py` & `redaction.py`: `tls.py` provides scoped Let's Encrypt Staging CA bundle and creates custom `SSLContext` for staging verification; `redaction.py` maintains runtime redaction registry populated from loaded config; `redact(text)` replaces sensitive values with `[REDACTED]`; verify unit tests

---

## 4. SSH, DNS, and Preflight Modules

- [ ] 4.1 Implement `ssh.py`: subprocess wrapper for `ssh` and `scp` with `shell=False`, args as array, mandatory timeout, `StrictHostKeyChecking=yes`, `BatchMode=yes`, separate `known_hosts` per host, stdout/stderr captured separately and redacted before logging; no secrets in argv; verify unit test: command that would put a secret in argv raises `ValueError` before subprocess is called
- [ ] 4.2 Implement `dns.py`: A/AAAA/CNAME resolution via `dig` subprocess for all four required domains, minimum two independent resolvers, verification that resolved IP equals expected VPS IP, AAAA gated on `ENABLE_IPV6`, detection of unexpected CDN proxies; verify test: mock `dig` returning wrong IP triggers DNS preflight failure
- [ ] 4.3 Implement `preflight.py`: Control Machine tool inventory (python3 version, ssh, ssh-keygen, openssl, curl, dig, getent, timeout, xray version vs `XRAY_CLIENT_VERSION`, mihomo version vs `MIHOMO_CLIENT_VERSION`); SSH trust check for both VPS via `ssh-keygen -F <host> -f <known_hosts>`; reserved/private/documentation IP rejection (`ipaddress` module); baseline snapshot collection via SSH (systemd services, listeners, firewall, GoWave dirs, packages, sysctl, swap, fs); disposable gate (reject if GoWave dirs or port conflicts found); port hygiene check for 11+ required ports; run-level lock acquisition (`fcntl.flock`); verify: disposable gate rejects VPS with existing GoWave dirs

---

## 5. Deployment and Panel API Modules

- [ ] 5.1 Implement `deployment.py`: copy pinned repo commit to Master via `scp` (using `git archive` locally then `scp`), run `gowave-auto.sh install` with `GOWAVE_ACME_SERVER` injection via SSH stdin env prepend, verify all post-install checks (service states, listeners, TLS certs, credentials file mode/owner, `gowave-auto.sh health`); version capture (Panel, Node, Xray, NGINX, OpenSSL, OS via SSH commands); verify: missing service triggers `master_install` FAIL
- [ ] 5.2 Implement Worker deployment in `deployment.py`: start a local background cmdline auditor script on Master via SSH immediately before running `gowave-auto.sh node add worker-1 ...`; audit observed process list for `SECRET_KEY` in argv (confirming stdin injection); verify Worker services, certs, deploy hook, cover-reality SHA256, `nginx -t`; verify: SECRET_KEY absent from observed argv → PASS, present → FAIL
- [ ] 5.3 Implement `panel_api.py`: thin `GoWaveClient` wrapper using Bearer token auth (`/api/auth/login`), targeting real Panel via HTTPS (using `tls.py` SSLContext for Staging CA when `ACME_MODE=staging`); methods for `get_nodes`, `get_config_profiles`, `get_computed_config`, `get_internal_squads`, `get_hosts`, `get_user_by_username`, polling `is_connected` with bounded timeout; all requests use `API_TIMEOUT`; verify: polling stops after `NODE_READY_TIMEOUT` with FAIL if `isConnected` never becomes `true`

---

## 6. mTLS, Subscriptions, Firewall, and NGINX Modules

- [ ] 6.1 Implement `mtls.py`: extract SECRET_KEY payload from Master `state.json` via SSH (pipe to Python base64 decode, never log value); invoke `python3 modules/verify_node_mtls.py --host WORKER_IP --port 3002 --mode full` via SSH from Master (feeding payload over stdin); parse stdout for `MTLS_HANDSHAKE_PASS`, `MTLS_CERTIFICATE_VALIDATION_PASS`, `WORKER_HTTP_HEALTH_PASS`; verify `PANEL_WORKER_AUTH_PASS` via Panel API call to panel→node health; execute 5 negative live TLS socket sub-tests directly via `ssl.SSLContext` (NEG-10 & variants: wrong cert, wrong key, wrong SNI, wrong CA, no cert) and assert handshake rejection before HTTP handler
- [ ] 6.2 Implement `subscriptions.py`: retrieve `shortUuid` via `GET /api/users/by-username/default-user`; User-Agent policy tests (empty, absent, Xray UA, Mihomo UA) against real Panel; fetch and validate Xray JSON (8 proxy-capable outbounds, headers, no server secrets, `xray run -test` with wrapper config); fetch and validate Mihomo YAML (8 proxies, `GEOIP,private,DIRECT,no-resolve`, `mihomo -t`); verify: parser counts only proxy outbounds, not `direct`/`block`; shortUuid value never written to any log or report
- [ ] 6.3 Implement `firewall.py`: Master port 3002 — local loopback reachable, external blocked (TCP timeout confirmation); Worker port 3002 — determine actual Master egress IP via SSH (`curl -s4 https://ifconfig.me` on Master, compare to UFW rule), mTLS from Master succeeds, Control Machine blocked (DROP); `ENABLE_IPV6=true` extends all checks; verify: `Connection refused` without timeout does not satisfy DROP criterion
- [ ] 6.4 Implement `nginx.py`: verify Panel HTTPS (correct SNI, TLS cert valid, Panel API responds); Worker HTTPS (correct SNI); REALITY fallback (REALITY SNI + invalid REALITY params → decoy content, not GoWave API); unknown SNI routing (matches NGINX + Xray REALITY fallback behavior); `nginx -t` on both VPS; cover-reality unique marker file; verify PROXY protocol integrity (Panel and Worker HTTPS responses received correctly); verify: decoy check fails if GoWave API content is returned

---

## 7. Traffic Module: Xray and Mihomo Data Plane

- [ ] 7.1 Implement server-side traffic evidence collector in `traffic.py`: setup temporary iptables/nftables packet counters (or temporary background `tcpdump`) on the target inbound port on Worker via SSH; confirm packets increment only on Worker during Worker tunnel requests, and do not increment on Master
- [ ] 7.2 Implement `traffic.py` Xray runner: for each of 8 proxy outbounds (extracted from real subscription), build temp Xray client config (unique SOCKS5 port 10800–10815, mode `0600`, written to `tempfile.NamedTemporaryFile`), inject Let's Encrypt Staging CA in `tlsSettings` when `ACME_MODE=staging`, start Xray subprocess with bounded startup timeout (poll SOCKS5 port until connectable), execute `curl socks5h://127.0.0.1:<port> https://cloudflare.com/cdn-cgi/trace` with `TRAFFIC_TIMEOUT`, verify HTTP 200, parse egress IP from response, compare to `EXPECTED_*_EGRESS_IP`, verify server-side inbound evidence via SSH; stop Xray; delete temp config; verify: missing egress IP match → endpoint FAIL; server-side evidence absent → endpoint FAIL
- [ ] 7.3 Implement `traffic.py` Mihomo runner (gated on `TEST_MIHOMO_TRAFFIC=true`): load full subscription YAML into temp file (mode `0600`), inject staging CA configuration when `ACME_MODE=staging`, start Mihomo subprocess, await SOCKS5/HTTP listener readiness, iterate all 8 proxies via Mihomo proxy selection API or config override, execute HTTPS request per proxy, verify egress IP and server-side evidence; stop Mihomo; delete temp config; verify: `TEST_MIHOMO_TRAFFIC=false` → all Mihomo cases set to SKIP
- [ ] 7.4 Verify `TEST_TRAFFIC_VERIFICATION=false` produces overall `INCOMPLETE` not `PASS`; write unit test for the status gate logic

---

## 8. Negative Tests Module

- [ ] 8.1 Implement `negative.py` for preflight & install failures (NEG-01..NEG-05): simulate by mutating known_hosts, closing SSH port, returning wrong DNS IP, missing AAAA record, and inducing Certbot challenge failure; verify execution terminates before remote modification or marks installation unready
- [ ] 8.2 Implement `negative.py` for config & service recovery (NEG-06..NEG-08): inject invalid NGINX syntax, verify `nginx -t` failure blocks activation; stop `gowave-node.service` on Worker via SSH, verify Panel detects unavailability (`isConnected: false`); restart service, poll for `isConnected: true` within bounded timeout
- [ ] 8.3 Implement `negative.py` for protocol & security enforcement (NEG-09..NEG-10): request subscription without User-Agent against real Panel (verify 403); attempt mTLS to Worker with forged self-signed certificate, verify TLS 1.3 handshake rejected
- [ ] 8.4 Implement `negative.py` for backup & restore hardening (NEG-11..NEG-12): invoke `gowave-backup.sh restore` with corrupted tar header (NEG-11) and corrupted SQLite DB (NEG-12); verify preflight rejection before mutating live data or stopping services
- [ ] 8.5 Implement `negative.py` for state integrity & auth (NEG-13..NEG-15): interrupt SSH deployment mid-stream, verify Master recovery journal is not `COMMITTED`; execute duplicate `node add` for same worker, verify no duplicate DB entities; invoke Panel API with forged/expired JWT, verify 401
- [ ] 8.6 Write integration check: all 15 negative scenarios (NEG-01 through NEG-15) execute in sequence per normative matrix; at least NEG-07/NEG-08 (stop/restart) and NEG-14 (re-registration) execute on the live disposable VPS; `negative_tests` phase aggregates all 15

---

## 9. Teardown, Reporting, and CI

- [ ] 9.1 Implement `teardown.py`: Preserve policy (collect diagnostics, write `result.json` with `FAILED_PRESERVED`, do not destroy VPS); Snapshot Restore policy (call provider snapshot API if available, verify baseline manifest after restore, set `TEARDOWN_UNAVAILABLE` if snapshot absent or API unsupported); Destroy policy (gate: VPS must have been created by Provider Adapter in this `TEST_RUN_ID`; in v1 this gate always rejects pre-existing VPS); all cleanup steps idempotent with per-step timeout; verify: Destroy on pre-existing VPS → `NOT_RUN` or prohibition recorded
- [ ] 9.2 Implement `reporting.py`: `write_result_json()` producing `result.json` with all required schema fields (`test_run_id`, `repository_commit`, `started_at`, `finished_at`, `master`, `worker`, `results`, `traffic`, `overall`); `write_junit_report()` producing `junit.xml` with one `testcase` per required check (timing, failure message, no `shortUuid` in classname/message); `write_summary_txt()`; all output via redact-on-write; verify: unit test asserts `shortUuid` value does not appear in any output file; `PASS` gate verifier (all 8 Data Plane PASS required)
- [ ] 9.3 Implement `diagnostics` collection in `reporting.py`: SSH dump per VPS (OS/kernel, packages, systemd status, journal snippets, listeners, `nginx -t`, firewall rules, cert metadata without private keys, API summaries, timing); write to `artifacts/live-vps/<TEST_RUN_ID>/diagnostics/master/` and `.../worker/`; verify: redacted copy written when mixed-content file detected; private key PEM blocks replaced with `[REDACTED]`
- [ ] 9.4 Implement `test_live_vps.py` CLI: `--config`, `--mode` (`preflight|install|verify|traffic|negative|teardown|full`), `--run-id`; `--mode full` executes all phases; partial modes verify `TEST_RUN_ID` consistency before proceeding; verify: `python3 tools/test_live_vps.py --help` prints mode list; `--mode preflight` exits before any remote modification
- [ ] 9.5 Write `.github/workflows/live-vps-e2e.yml`: `workflow_dispatch` only trigger, no auto-trigger on push/PR; uses named GitHub Environment with required reviewer for secret access; includes explicit pre-steps to download and install pinned `xray` and `mihomo` binaries onto runner; SSH keys and config delivered via GitHub Environment secrets (never printed to log); publishes JUnit XML as artifact; saves redacted diagnostics as artifact; `concurrency` block prevents parallel runs for the same environment; verify: `act -l` or dry-run shows no trigger on `push` or `pull_request` event

---

## 10. Integration Validation

- [ ] 10.1 Run `openspec validate live-vps-e2e-testing --strict` with zero errors; fix any schema violations before merging
- [ ] 10.2 Run `openspec validate --all --strict` to confirm existing `gowave-auto-nginx` change and all specs remain valid after the new change is added
- [ ] 10.3 Run `git diff --stat feature/gowave-auto-nginx` and verify: no existing test files modified except `modules/node.sh` and `gowave-auto.sh`/`gowave-node-auto.sh` ACME delta; no secrets or `.env` files committed; `tools/live_vps_config.env` absent from diff (in `.gitignore`)
- [ ] 10.4 Run `python3 tests/run_ci.py --check-completeness` and confirm existing 5-suite inventory is unaffected by new files
- [ ] 10.5 Run `shellcheck --severity=error gowave-auto.sh gowave-node-auto.sh modules/node.sh` after ACME and installer deltas to confirm zero new errors

---

## Workflow follow-up

- Once tasks are complete and all phases PASS on a staging ACME run, run a production acceptance run:
  `python3 tools/test_live_vps.py --config tools/live_vps_config.env --mode full` with `ACME_MODE=production`
  on freshly provisioned disposable VPS.
- After production acceptance, open PR from `feature/live-vps-e2e-testing` to `feature/gowave-auto-nginx`.
- After merge, archive this change with `openspec archive live-vps-e2e-testing`.





