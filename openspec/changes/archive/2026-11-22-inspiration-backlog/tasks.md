# Tasks

## 1. Subscription edge

- [x] 1.1 In `generate_panel_https_vhost` (`modules/nginx.sh:414-509`) add `Cache-Control: no-store, private`
      and `X-Robots-Tag: noindex, nofollow, noarchive, nosnippet` with `always` inside `location ^~ /api/sub/`,
      and add static assertions to `tests/test_nginx_routing.TestNginxRouting` proving both directives are
      rendered with `always`; verify with `python3 tests/run_ci.py --suite nonroot`.
- [x] 1.2 Add `access_log off;` to the same location and a test asserting the rendered block contains it and
      that the XHTTP and WebSocket blocks keep theirs; verify with `python3 tests/run_ci.py --suite nonroot`.
- [x] 1.3 Declare `map $http_user_agent $gowave_sub_ua_class` above the server block with the bot patterns from
      `design.md` D1 and answer `204` for the preview class; add a test that renders the vhost, extracts the map
      and the `if`, and asserts the class of every client, crawler and empty header used by the suites; verify
      with `python3 tests/run_ci.py --suite nonroot`.
- [x] 1.4 Declare `map $request_uri $gowave_sub_path_bad` with the three ordered patterns from `design.md` D4 and
      a server-level `if` answering `444`; add a static test asserting the map is keyed on `$request_uri` (not
      `$uri`), the patterns are in the documented order, and the guard sits at server level; confirm the rendered
      file passes `nginx -t` inside the container image, because the counted pattern must stay quoted. Verify with
      `bash -n modules/nginx.sh` and `python3 tests/run_ci.py --suite nonroot`. The runtime proof that a raw
      `..` or `%2F` is refused belongs to 1.5, because it needs a live listener.
- [x] 1.5 Add the acceptance cases that read the subscription contract from a running container through the
      project's acceptance-case skill (all five artifacts: catalog, behaviour entry, traceability row, scenario
      and the case class), and a row in `docs/PODMAN_E2E_DISCOVERY.md` and
      `docs/PODMAN_E2E_TRACEABILITY.md`. `SUB-EDGE` serves the payload to a client through the edge and compares
      it with the loopback bytes, answers the twelve real preview headers with `204`, an empty body and both
      transport directives, reads the Panel's own refusal for an absent header, and brackets the sweep with the
      Panel's router counters (`GET /api/system/stats/http`) plus a loopback control that has to move them;
      `SUB-EDGE-BAD` sends `/api/sub/<id>/../x` and `/api/sub/<id>%2Fy` verbatim and reads the closed connection
      and the access-log pair. Three departures from the earlier wording, each because the replacement proves
      more: the `502` half is asserted by the existing `AIO-FAULT-PANEL` fault case on its own outage, since a
      served answer cannot be observed by stopping `gowave.service` a second time; "no matching line in the
      Panel's log" became the router's counters, because the Panel's request log is off by default
      (`internal/server/server.go:501`) and a quiet log would have proven nothing; and the cases are mapped with
      `cases_by_requirement` and a written reason rather than a new spec scenario, because the requirement
      states the served bytes and no scenario states the edge that stands in front of them. Verify with
      `python3 -m tools.podman_e2e.catalog check` and `python3 tests/run_ci.py --check-completeness`.

      **Verified 2026-11-21:** `modules/nginx.sh` renders all four contracts — the two `add_header … always`
      lines and `access_log off;` inside `^~ /api/sub/`, with the XHTTP and WebSocket blocks keeping theirs, both
      `map`s above the `server` block they serve, and the server-level `if` keyed on `$request_uri`.
      `tests.test_nginx_routing.TestNginxRouting` proves each one by rendering the vhost:
      `test_panel_vhost_subscription_headers_are_status_independent`,
      `test_panel_vhost_subscription_access_log_is_off`, `test_panel_vhost_user_agent_classification`,
      `test_panel_vhost_path_guard_is_keyed_on_the_raw_target`. The runtime half of 1.4 is `SUB-EDGE-BAD`. The
      `nginx -t` check on the rendered file was not re-run in this session, so it is not claimed here.

## 2. Panel vhost hygiene

- [x] 2.1 Add `server_tokens off` to the panel vhost beside `ssl_protocols` and a test that the rendered block
      carries it; verify with `python3 tests/run_ci.py --suite nonroot`.
- [x] 2.2 Replace `$proxy_add_x_forwarded_for` with `$remote_addr` in all five proxied locations
      (`^~ /api/sub/`, `^~ /api/`, `/`, `^~ /xhttp-down/`, `= /ws`), empty the eight other address headers
      `httpx.ClientIP` reads before those two (`X-Remnawave-Real-IP`, `X-Client-IP`, `CF-Connecting-IP`,
      `Fastly-Client-Ip`, `True-Client-Ip`, `X-Cluster-Client-IP`, `X-Forwarded`, `Forwarded-For`), and add a test
      that compares every header the Panel prefers with the rendered block and counts exactly five occurrences of
      the `$remote_addr` form — count the matches before the rewrite, as the bulk-edit rule requires — then run
      `python3 tests/run_ci.py --suite nonroot`. The eight headers are the ones `httpx.ClientIP` prefers *over*
      `X-Forwarded-For`, so a vhost that rewrote only the conventional two still let a client choose the address
      the Panel records for rate limits, login attempts and notifications.
- [x] 2.3 Add the anchored scanner-path location from `design.md` D5 and a test that asserts each named path is
      answered by that location while every path the Panel and dashboard serve is not matched; verify with
      `python3 tests/run_ci.py --suite nonroot`.
- [x] 2.4 Add the acceptance case that reads the panel-vhost hygiene contract from a running container, with its
      behaviour entry and traceability row. The case observes, at minimum: `Server` without a version on a `200`
      and on a `404`, and no version fragment in an error body; the Panel's own record of the client address after
      a request carrying a forged `X-Forwarded-For` and `X-Real-IP`, repeated on each of the five proxied
      locations; `444` for `/.env`, `/.git/config`, `/wp-login.php`, `/server-status` and `/actuator/health`, with
      nothing in the Panel's log; and every product route still proxied — `/api/`, `/api/sub/`, `/api/nodes`,
      `/api/auth/login`, `/xhttp-down/`, `/ws`, `/trojan-grpc` and a dashboard asset. Verify with
      `python3 -m tools.podman_e2e.catalog check`.

      Shipped as `NGX-HYGIENE` and `NGX-SCANNER`, reading one `--scope vhost-hygiene` probe block, with four
      departures from the wording above, each because the host answers more honestly than the sketch assumed:
      the probe forges each of the ten headers `httpx.ClientIP` prefers, one at a time, and reads the address back
      from `GET /api/users/{userId}/subscription-request-history` — the Panel's own record of the request — rather
      than sweeping all five locations, because the five share one header loop and the rendered-block guard covers
      all five; the error page read is NGINX's own `414` for a request line past its header buffer, the only page
      the listener writes itself, since a proxied `404` is the Panel's page; a refused scanner path is a dropped
      connection with no bytes rather than a `444` reply, which is what `return 444` produces and what the case
      asserts; and "nothing in the Panel's log" is read as the recorded address, because the Panel's request log is
      off by default (`internal/server/server.go:501`) and an absent log line would be satisfied by a listener that
      logged nothing at all.

      **Verified 2026-11-21:** the eight header names are one loop in `generate_panel_https_vhost` (lines 432–438
      of `modules/nginx.sh`) and `$remote_addr` is written in all five proxied locations, with no
      `proxy_add_x_forwarded_for` left in the rendered file. `tests.test_nginx_routing.TestNginxRouting` proves it
      by rendering: `test_generate_panel_https_vhost` (server tokens off, exactly five
      `X-Forwarded-For $remote_addr`, no `$proxy_add_x_forwarded_for`),
      `test_panel_vhost_hands_the_panel_only_the_peer_address` (every header `httpx.ClientIP` prefers, with
      `$remote_addr` for the two forwarded ones and `""` for the eight it reads first) and
      `test_panel_vhost_scanner_set_is_anchored_and_cannot_shadow_product_routes`. The acceptance pair passed
      `python3 -m tools.podman_e2e.catalog check` and `python3 -m tools.podman_e2e.trace --strict` (48 scenarios,
      48 rows, 0 gaps), and `tests.test_podman_aio.TestHygieneCase` + `TestVhostHygieneProbe` ran 22 tests with
      `OK`. Neither case has container execution evidence yet; that is 9.2.

## 3. Preflight input contract

- [x] 3.1 Add `preflight_require_inputs <component>` to `modules/preflight.sh` with one validation table per
      component (install, node add) and the first-failure report naming the component and the input; add a new
      `TestCase` for it and register it in `tests/run_ci.py`; verify with
      `python3 tests/run_ci.py --suite nonroot` and `python3 tests/run_ci.py --check-completeness`.
- [x] 3.2 Call it in `cmd_install` before `check_os`, the NGINX stop and `install_prerequisites`
      (`gowave-auto.sh:346-360`), and in the Worker payload before its first mutation in every copy of that
      function — count the copies with `grep -c` first and require the expected number; verify with `bash -n`,
      `python3 tests/run_ci.py --suite nonroot`.
- [x] 3.3 Delegate the wizard's existing field validation to the same contract so both entry paths reject the
      same value identically, and extend `tests/test_wizard` with the parity case; verify with
      `python3 tests/run_ci.py --suite nonroot`.
- [x] 3.4 Add the acceptance case that a missing input leaves NGINX running and the filesystem untouched, with
      its behaviour entry and traceability row in the `installation` area; verify with
      `python3 -m tools.podman_e2e.catalog check`.

      **Verified 2026-11-21:** `modules/preflight.sh:preflight_require_inputs` rejects partial lists and
      malformed ACME contacts with exit 2, naming the component and the field — the message for the missing
      email reads "install requires the ACME contact email, which was not provided." and the malformed one
      "install requires the ACME contact email; not-an-email is not valid." `tests.test_preflight.TestPreflightInputs`
      (8 tests incl. `test_the_wizard_and_the_positional_path_refuse_the_same_value`) proves the contract parity.
      The acceptance pair `PRE-INPUTS` / `PRE-INPUTS-BAD` (aio topology, declared in `aio.py`, registered in
      `catalog.py` `PODMAN_FIRST_CASES`, behaviour entry with `error_paths: [PRE-INPUTS-BAD]`,
      `traceability.yaml` row with the named unit tests and `TestPreflightInputCase` methods) passed
      `python3 -m tools.podman_e2e.catalog check` and `python3 -m tools.podman_e2e.trace --strict` (48 scenarios,
      48 rows, 0 gaps). `tests.test_podman_aio.TestPreflightInputCase` 13 tests OK. No container execution
      evidence yet for either case; that is 9.2.

## 4. Cloudflare-proxied name refusal

- [x] 4.1 Add the dated Cloudflare CIDR snapshot, `GOWAVE_PREFLIGHT_PROXY_CIDRS` and
      `GOWAVE_PREFLIGHT_ALLOW_PROXIED` to `modules/preflight.sh`, resolving with `getent ahosts` and refusing a
      proxied or unresolvable name before issuance. The check covers every name the run will validate —
      the panel name, the camouflage/decoy name, and each configured Vision name — and a proxy-range or
      no-answer result from any one of them stops the run before the first certificate request. Add tests with a
      stubbed resolver covering proxied panel, proxied decoy, proxied Vision, direct, unresolvable and
      overridden outcomes; verify with `python3 tests/run_ci.py --suite nonroot`.

      **Verified 2026-11-21:** `modules/preflight.sh` embeds the dated Cloudflare CIDR snapshot, exposes
      `GOWAVE_PREFLIGHT_PROXY_CIDRS` / `GOWAVE_PREFLIGHT_ALLOW_PROXIED`, resolves names with `getent ahosts`
      and refuses a proxied or unresolvable name before any certificate request — the check covers the panel
      name, the camouflage/decoy name, and every configured Vision name. `tests.test_preflight.TestPreflightProxyRefusal`
      (10 tests incl. `test_a_proxied_panel_name_stops_the_run`, `test_a_proxied_camouflage_name_stops_the_run`,
      `test_a_proxied_vision_name_stops_the_run`, `test_an_unresolvable_name_is_reported_not_guessed`,
      `test_an_explicit_override_is_honoured`) proves every outcome with a stubbed resolver. `PRE-PROXY-CIDR`
      acceptance case is not yet implemented (task 4.2).

- [x] 4.2 Add the acceptance case that a name answered with a proxy-range address is refused before any
      certificate exists, using the harness DNS fixture, with its behaviour entry and traceability row; verify
      with `python3 -m tools.podman_e2e.catalog check`.

      **Verified 2026-11-21:** `PRE-PROXY-CIDR` and `PRE-PROXY-CIDR-OVERRIDE` cases implemented in
      `preflight_cases.py`, registered in `aio.py`, with catalog entries in `catalog.yaml`, behaviour entry
      (cases: `[PRE-PROXY-CIDR]`, error_paths: `[PRE-PROXY-CIDR-OVERRIDE]`), traceability rows under
      "Independent All-in-One acceptance topology", and PARITY.md updated. `catalog check` and `trace check` PASS.

## 5. Lineage selection by coverage

- [x] 5.1 Add `select_acme_lineage` (coverage via `openssl x509 -checkhost`, ACME-directory match, expiry check,
      deterministic order) and record its choice in `state.json`; add tests with a temporary `live/` tree and
      self-signed certificates covering the adopted, mismatched-directory, multiple-covering, not-covering and
      expired cases — the expired one both beside a valid candidate and as the only candidate, asserting it is
      never selected; verify with `python3 tests/run_ci.py --suite nonroot`.
- [x] 5.2 Pass the chosen directory into `generate_panel_https_vhost`, `generate_decoy_vhost` and the Vision
      generator instead of deriving it from the domain, and mark an adopted lineage as pre-existing before any
      issuance step so `rollback_acme_lineages` cannot delete it; extend the rollback test to prove the adopted
      lineage survives a failed transaction. Add a render test per named generator, each with a suffixed chosen
      directory, asserting both `ssl_certificate` and `ssl_certificate_key` point into that directory and that no
      path is derived from the domain; verify with `python3 tests/run_ci.py --suite nonroot`.

      **Verified 2026-11-21:** `modules/nginx.sh:select_acme_lineage` implements coverage check via
      `openssl x509 -checkhost`, ACME-directory match, expiry check, and deterministic order (exact name first,
      then shortest suffix), recording the choice in `state.json`. `tests.test_nginx_routing.TestNginxRouting`
      proves the selection logic (6 tests: `test_select_acme_lineage_adopts_a_suffixed_covering_lineage`,
      `test_select_acme_lineage_does_not_mix_acme_directories`, `test_select_acme_lineage_prefers_the_exact_name_and_repeats`,
      `test_select_acme_lineage_ignores_a_name_the_certificate_does_not_cover`, `test_select_acme_lineage_never_selects_an_expired_lineage`,
      `test_select_acme_lineage_skips_a_symlinked_live_entry`). The chosen directory is passed into
      `generate_panel_https_vhost`, `generate_decoy_vhost`, and the Vision generator — 5 render tests
      (`test_generate_panel_https_vhost`, `test_generate_decoy_vhost`, `test_cover_domain_reaches_the_decoy_and_redirects_http`,
      `test_generate_vision_fallback_vhost`, `test_decoy_vhost_serves_from_the_given_lineage_directory`,
      `test_the_vision_vhost_renders_no_certificate_of_its_own`) assert both `ssl_certificate` and
      `ssl_certificate_key` point into the suffixed directory with no domain-derived path. Rollback tests
      (`test_acme_lineage_snapshot_and_rollback_preexisting`, `test_acme_lineage_snapshot_and_rollback_new_domain`)
      prove the adopted lineage survives a failed transaction. `TLS-LINEAGE` acceptance case is not yet
      implemented (task 5.3).

- [x] 5.3 Add the acceptance case that issues a lineage under a suffixed certificate name with the ACME fixture
      and asserts a repeated install serves that lineage without creating a second one, with its behaviour entry
      and traceability row; verify with `python3 -m tools.podman_e2e.catalog check`.

      **Verified 2026-11-21:** `TLS-LINEAGE` and `TLS-LINEAGE-BAD` cases implemented in
      `preflight_cases.py`, registered in `aio.py`, with catalog entries in `catalog.yaml`, behaviour entry
      (cases: `[TLS-LINEAGE]`, error_paths: `[TLS-LINEAGE-BAD]`), traceability rows under
      "Explicit ACME Endpoint Selection and Certificate Lineage Isolation", and PARITY.md updated.
      `catalog check` and `trace check` PASS.

## 6. `node add` environment contract

- [x] 6.1 Add `resolve_node_inputs` to `cmd_node`: environment first, non-empty positional overrides, then
      `preflight_require_inputs node`; add tests that an environment-only invocation, a mixed invocation and an
      invalid environment value behave as specified, and that no secret appears in `argv` or the environment;
      verify with `python3 tests/run_ci.py --suite nonroot`.
- [x] 6.2 Document the seven variables beside the positional usage in `README.md` and in the command's
      `--help`/usage text, and add a documentation test that every documented variable is accepted; verify with
      `python3 tests/run_ci.py --suite nonroot`.

      **Verified 2026-11-21:** `cmd_node` in `gowave-auto.sh` now resolves inputs from the environment first,
      then non-empty positional overrides, then `preflight_require_inputs node` — the seven variables
      (`GOWAVE_NODE_HOST`, `GOWAVE_NODE_SECRET_KEY`, `GOWAVE_NODE_PANEL_URL`, `GOWAVE_NODE_PANEL_TOKEN`,
      `GOWAVE_NODE_VISION_DOMAIN`, `GOWAVE_NODE_VISION_CERT_PATH`, `GOWAVE_NODE_VISION_KEY_PATH`) are
      documented in `README.md` and the command's `--help`/usage text. `tests.test_preflight.TestNodeEnvironmentContract`
      (6 tests incl. `test_an_environment_only_invocation_resolves_every_field`, `test_a_positional_overrides_its_variable`,
      `test_an_invalid_environment_value_is_refused_on_its_field`, `test_the_secret_is_not_an_input_of_this_contract`)
      and `TestPreflightDocumentation` (2 tests: `test_every_documented_variable_is_read_by_the_contract`,
      `test_the_usage_text_names_the_environment_contract`) prove the contract and documentation parity.
      `MN-ENV-CONTRACT` acceptance case is not yet implemented (task 6.3).

- [x] 6.3 Add the acceptance case that onboards a Worker through the environment contract and reads back the
      same host record, with its behaviour entry and traceability row; verify with
      `python3 -m tools.podman_e2e.catalog check`.

      **Verified 2026-11-21:** `MN-ENV-CONTRACT` case implemented in `multi_node.py:case_env_contract`,
      registered in `multi_node.py:cases()`, with catalog entry in `catalog.yaml`, behaviour entry added to
      "duplicate registration, partial deployment and forged credentials are refused without mutation"
      (cases list), traceability row under "Independent Multi-Node acceptance topology", and PARITY.md updated.
      `catalog check` and `trace check` PASS.

## 7. Verified download chain

- [x] 7.1 Add `fetch_verified_artifact` to a shared `modules/artifact.sh` sourced by `modules/node.sh` and
      `modules/panel.sh` (ordered hosts, digest before use, mismatch terminal) and route the pinned Worker
      installer through it with `raw.githubusercontent.com` first and the jsDelivr `gh/...@<commit>` form second;
      add tests in `tests/test_artifact_fetch.py` with a local HTTP fixture for fall-through, mismatch and
      no-host cases; verify with `python3 tests/run_ci.py --suite nonroot`.
- [x] 7.2 Route the panel asset transfer in `modules/panel.sh` through the same helper while keeping
      `SHA256SUMS` mandatory and fetched from the release host; add a test that a mismatch aborts without
      falling through; verify with `python3 tests/run_ci.py --suite nonroot`.
- [x] 7.3 Add the acceptance cases `VERIFIED-ARTIFACT-FETCH`, `PINNED-INSTALLER-HOSTS`,
      `PANEL-ASSET-VERIFICATION` with their behaviour entry and traceability rows; verify with
      `python3 -m tools.podman_e2e.catalog check`.

      **Verified 2026-11-21:** `modules/artifact.sh:fetch_verified_artifact` implements ordered hosts, digest
      verification before atomic rename, and terminal mismatch — the Worker installer is routed through it with
      `raw.githubusercontent.com` first and `jsDelivr gh/...@<commit>` second. `tests.test_artifact_fetch.TestVerifiedArtifactFetch`
      (6 tests: fall-through, terminal mismatch, no-host, unusable digest, atomic replace, missing host list),
      `TestPinnedInstallerHosts` (1 test: GitHub-then-jsDelivr order), and `TestPanelAssetVerification` (1 test:
      `test_a_mismatched_asset_aborts_without_falling_through` with mandatory `SHA256SUMS` from the release host)
      prove the chain. `VERIFIED-ARTIFACT-FETCH`, `PINNED-INSTALLER-HOSTS`, `PANEL-ASSET-VERIFICATION`
      acceptance cases implemented in `aio.py`, registered in `aio.py:cases()`, with catalog entries in
      `catalog.yaml`, behaviour entry "The pinned artifact chain fetches with digest verification and stops on mismatch"
      (cases: `[VERIFIED-ARTIFACT-FETCH, PINNED-INSTALLER-HOSTS, PANEL-ASSET-VERIFICATION]`,
      error_paths: `[FAIL-STEP]`), traceability rows under "Independent All-in-One acceptance topology",
      and PARITY.md updated. `catalog check` and `trace check` PASS.

## 8. Failure diagnostics

- [x] 8.1 Add the `ERR` trap and `CURRENT_STEP` to `gowave-auto.sh` per `design.md` D13, assigning the step at
      each phase boundary; add a test that forces a step failure and asserts the report names the step, the
      command and the status, and that the command exits non-zero; verify with
      `python3 tests/run_ci.py --suite nonroot`.
- [x] 8.2 Add a test proving the trap does not run compensation a second time when the failing step already
      rolled back, and that a successful run prints no report; verify with
      `python3 tests/run_ci.py --suite nonroot`.
- [x] 8.3 Add the acceptance case `FAIL-STEP` that a failed install prints a located failure, in the
      `failure-injection` area, with its behaviour entry and traceability row; verify with
      `python3 -m tools.podman_e2e.catalog check`.

      **Verified 2026-11-21:** `gowave-auto.sh` installs an `ERR` trap with `CURRENT_STEP` assigned at each
      phase boundary per `design.md` D13. `tests.test_failure_report.TestFailureReport` (8 tests:
      `test_a_failed_step_names_the_step_the_command_and_the_status`, `test_every_install_phase_is_labelled`,
      `test_the_command_name_labels_the_run_before_the_first_phase`, `test_the_command_substitution_stays_silent_and_keeps_its_status`,
      `test_the_handler_reports_and_does_not_compensate`, `test_the_report_is_printed_once`,
      `test_a_step_that_already_rolled_back_is_not_compensated_twice`, `test_a_successful_run_prints_no_report`)
      proves the trap reports the step, command, and status on failure, does not double-compensate a
      pre-rolled-back step, and is silent on success. `FAIL-STEP` acceptance case implemented in
      `aio.py:case_fail_step`, registered in `aio.py:cases()`, with catalog entry in `catalog.yaml`,
      behaviour entry "The pinned artifact chain fetches with digest verification and stops on mismatch"
      (error_paths: `[FAIL-STEP]`), traceability row under "Trustworthy result and diagnostics",
      and PARITY.md updated. `catalog check` and `trace check` PASS.

## 9. Integration

- [x] 9.1 Run `python3 tests/run_ci.py --check-completeness` and all five suites, and record the outcome of each
      in the change's task notes; a suite that cannot run here is reported as not run, never as a pass.

      **Verified 2026-11-21:** The gate `bg_b0a688a1` (background shell `ff2c5711-d9f1-494b-8df8-4807b86a6e1b`, log `shell-bg_b0a688a1.output`) reported a nonroot run that completed at ~03:54 UTC (3039.133s, 2969 tests) with status **FAILED: 7 failures, 5 errors, 1 skipped**.

      **What this run covers:** the whole nonroot contour on that tree — all 2969 tests the `nonroot` suite then held (the completeness gate printed `PASS` before it), i.e. the same surface the third run below describes: the unit and render guards this change adds plus the pre-existing suite around them. It runs no Podman acceptance case and none of the `root`, `systemd`, `integration` or `services` suites. Its verdict is a fail, so it is recorded as one.

      **Failure breakdown — all twelve `FAIL:`/`ERROR:` blocks read out of the whole log, not its tail**
      (a suite log does not end with its verdict: the `Ran …`/`FAILED …` pair sits above the tail and the
      justified-exclusion and SSH-key lines keep arriving below it):

      Failures (7):
      1. `test_harness_binds_only_private_or_loopback_addresses` (`test_podman_fixture_isolation.TestPodmanFixtureIsolation`) — `- ['2.23.20.0'] + [] : panel_surface.py`. The address is a User-Agent version string, not a bind; the fixture now lists it with its reason (see the third run below).
      2. `test_every_case_is_named_by_exactly_one_behavior` (`test_podman_lock_cases.TestLockRegistration`) — `'Behavior A Cloudflare-proxied name is refused before any certificate request names case PRE-PROXY-CIDR more than once'` and `'… declares topology aio that none of its cases runs in'`.
      3. `test_no_while_true_loops` (`test_podman_readiness.TestNoUnboundedWaits`) — **AssertionError**: `panel_surface.py: unbounded 'while True' loop`
      4. `test_sleeps_live_inside_bounded_wait_helpers` (`test_podman_readiness.TestNoUnboundedWaits`) — **AssertionError**: `panel_surface.py:955 fixed sleep outside a bounded wait helper (_new_history_row)`
      5. `test_the_checked_in_behaviours_agree_with_what_they_quote` (`test_podman_traceability.TestNamedBehaviours`) — **AssertionError**: `"behaviour 'A Cloudflare-proxied name is refused before any certificate request': no suite declares the case 'PRE-PROXY-CIDR'"`
      6. `test_the_audit_entrypoint_reads_the_checked_in_table` (`test_podman_traceability.TestTraceabilityRules`) — **AssertionError**: `trace.main(["--check"])` returned `1`
      7. `test_the_checked_in_table_agrees_with_what_it_cites` (`test_podman_traceability.TestTraceabilityRules`) — **AssertionError**: `"Independent All-in-One acceptance topology: no suite declares the case 'PRE-PROXY-CIDR'"` and `"no suite declares the case 'PRE-PROXY-CIDR-OVERRIDE'"` (2 missing entries)

      Errors (5), one cause: `tools.podman_e2e.catalog.CatalogError: the code runs cases the catalog does not
      define: PRE-PROXY-CIDR`, raised from `apply_implementations` — `test_the_catalog_carries_the_count_case_that_judges_the_run`,
      `test_the_catalog_lists_one_data_plane_entry_per_tuple_for_every_client`,
      `test_the_catalog_names_the_configuration_dependent_counts`,
      `test_the_static_aggregate_traffic_case_is_not_advertised_any_more` (all `test_podman_matrix.TestMatrixCatalog`)
      and `test_the_suite_is_built_from_the_case_ids_the_catalog_knows` (`test_podman_multi_node.TestMultiNodeSuite`).
      `PRE-PROXY-CIDR` existed in `aio.py` but in neither the catalog nor the behaviour/one-name-per-case guards —
      the same gap the three traceability failures report, seen from the catalog side.

      **Traceability note:** failures 5–7 were traceability gaps — the cases `PRE-PROXY-CIDR` and `PRE-PROXY-CIDR-OVERRIDE` ARE declared in the AIO suite (111 cases), but were missing from `tests/cases/traceability.yaml`'s `cases_by_requirement`. This has been fixed by adding entries under "Independent All-in-One acceptance topology" with reason "serve the proxy CIDR preflight parity sentence". Regenerated `docs/PODMAN_E2E_TRACEABILITY.md`. **Post-fix traceability check: PASS (48 scenarios, 48 rows, 0 gaps). Catalog check: PASS. Completeness check: PASS (354 TestCase classes).**

      **Crucial:** failures 3 and 4 are real unit failures in `panel_surface.py` and `test_podman_readiness`, not traceability issues. A fresh nonroot run is required to triage whether they persist. **This run does NOT count as a pass; task 9.2 must wait for a clean nonroot run.**

**Verified 2026-11-21 (second run):** Background shell `bg_c11f4791` (log `shell-bg_c11f4791.output`) completed a fresh nonroot run at ~04:54 UTC (3354.549s, 2969 tests) with status **FAILED: 5 failures, 0 errors, 1 skipped**.

**Failure breakdown (the five `FAIL:` blocks in the log, not its tail):**

1. `test_every_podman_first_case_names_an_owner_and_a_target_the_specs_state` (`TestPodmanFirstPromotion`) — **AssertionError**: `124 != 115` (catalog Podman-first count changed)
2. `test_the_environment_table_counts_are_the_catalog_counts` (`TestContourBoundary`) — **AssertionError**: `249 != 240` (catalog total size changed; `docs/PODMAN_E2E_DISCOVERY.md` quotes stale total)
3. `test_the_live_split_is_the_one_parity_reports` (`TestContourBoundary`) — **AssertionError**: "the page's live split drifted from the catalog" (live scenario counts in `docs/PODMAN_E2E_DISCOVERY.md` out of sync with catalog)
4. `test_harness_binds_only_private_or_loopback_addresses` (`TestPodmanFixtureIsolation`) — **AssertionError**: found `'2.23.20.0'` in `panel_surface.py` (public address bound in fixture)
5. `test_every_subprocess_call_has_a_timeout` (`TestNoUnboundedWaits`) — **AssertionError**: `preflight_cases.py:1149 subprocess.run without timeout`

**Key changes from first run (bg_b0a688a1):**
- ✅ **Traceability failures GONE** — `PRE-PROXY-CIDR` / `PRE-PROXY-CIDR-OVERRIDE` entries were added to `traceability.yaml`; traceability check now passes
- ✅ **`panel_surface.py` unbounded-loop failures GONE** — `test_no_while_true_loops` and `test_sleeps_live_inside_bounded_wait_helpers` now pass
- ❌ **New catalog/documentation drift failures** — catalog grew from 240→249 entries, Podman-first from 115→124; `docs/PODMAN_E2E_DISCOVERY.md` not regenerated
- ❌ **New fixture isolation failure** — `panel_surface.py` binds public address `2.23.20.0`
- ❌ **New readiness failure** — `preflight_cases.py:1149` missing `timeout` on `subprocess.run`

**Traceability, catalog, completeness checks:** All PASS (48/48, 354 classes).

**This run does NOT count as a pass; task 9.2 must wait for a clean nonroot run.**

**Verified 2026-11-21 (third run — the clean one):** Background shell `bg_af4e1717`, log `/tmp/nonroot-full.log`, started 08:36:46 UTC and ended 09:35:12 UTC (3503.273 s). The completeness gate ran first and printed `COMPLETENESS: PASS` (86 modules, 354 TestCase classes, 3067 unique tests; nonroot 2969), then the suite itself: **`Ran 2969 tests in 3503.273s` → `OK (skipped=1)`**, `EXIT=0`, zero `FAIL:` and zero `ERROR:` blocks.

**The one skip is stated, not hidden:** `test_podman_lock_cases.TestLockHolderProgram.test_a_file_owned_by_another_user_is_refused` — `skipped 'handing a file to another user needs CAP_CHOWN'`. That class is registered in the nonroot suite only, so the case is skipped wherever it runs; it predates this change, is not counted as a pass, and nothing in this change depends on it.

**What this run covers:** the whole nonroot contour on the current tree — every unit and render guard this change added (artifact chain `test_artifact_fetch`, failure report `test_failure_report`, preflight `test_preflight`, subscription `test_podman_subscriptions`, NGINX routing `test_nginx_routing`, the catalog/behaviour/traceability/matrix parity guards `test_podman_catalog` / `test_podman_docs` / `test_podman_traceability` / `test_podman_matrix`, fixture isolation, readiness, lock cases, and the remaining harness self-checks) plus the pre-existing suite around them. It does **not** run the `root`, `systemd`, `integration` or `services` suites (recorded separately below), and it runs no Podman acceptance case — that is 9.2.

**What it proves about the five run-2 failures:** each one is green in the same suite that reported it — `TestPodmanFirstPromotion` (124 Podman-first entries), `TestContourBoundary` (249 total and the live split), `TestPodmanFixtureIsolation` (`2.23.20.0` is a User-Agent version string, listed with its reason), `TestNoUnboundedWaits` (the four `openssl` calls in `preflight_cases.py` now carry `timeout=120`). Immediately before this run a targeted triage of the six heaviest modules printed `Ran 309 tests in 1354.518s — OK (skipped=1)`, so the repair was confirmed before the whole suite was spent on it.

**The other four suites, same tree, same day:** `integration` — `Ran 69 tests in 3.410s` → `OK` (`/tmp/suite-integration.log`); `services` — `Ran 5 tests in 0.515s` → `OK` (`/tmp/suite-services.log`); `root` under EUID 0 — `Ran 16 tests in 0.703s` → `OK` (`/tmp/suite-root.log`); `systemd` under EUID 0 — `Ran 8 tests in 0.007s` → `OK` (`/tmp/suite-systemd.log`). The `systemd` suite is the single class `test_systemd_runner.TestSystemdRunner`, which inspects the unit text `configure_panel_systemd()` emits — its 0.007 s says exactly that: a unit-render check, not a booted-unit exercise, and nothing more is claimed from it. All four exited 0 with no `FAIL:`/`ERROR:` block.

- [x] 9.2 Run the All-in-One Podman acceptance on a clean image and confirm the new subscription, panel-hygiene,
      preflight, lineage and failure cases pass together with the existing subscription and install cases; a red
      case is triaged before anything is declared complete.

      **Verified 2026-11-21:** Four AIO runs, each started as
      `sudo -b -S python3 -m tools.run_podman_e2e --topology aio`, each on containers created fresh from the
      digest-pinned images the run records in `environment.images_resolved`
      (`ubuntu-24.04` `sha256:2198e4c…`, `acme-pebble` `sha256:0c81f05…`, `fixture-echo` and `client-base`
      `sha256:5e2bdb1…`), budget 2700 s, 117 cases. Every run records
      `repository: {commit: 6a32f71f07a9e103a4952465224e2fa3e3f4b5c5, tree: dirty}` — the change is uncommitted,
      so these runs read the working tree and answer for this tree, not for a commit. Run directories live under
      `artifacts/podman-e2e/podman-aio-20261121T…/` and are owned by the operator, not root.

      **Run A `podman-aio-20261121T124056-fc29a0e0` — 84 PASS / 17 FAIL / 16 BLOCKED, 1929.783 s, `overall: FAIL`.**
      Six causes, each traced from the case message:
      1. `SUB-SERVED`, `SUB-EDGE`, `SUB-EDGE-BAD`, `NGX-HYGIENE`, `NGX-SCANNER` — the Panel probe exited 1 with
         `http.client.RemoteDisconnected: Remote end closed connection without response` on its first edge fetch.
         The cause was mine: the D4 path guard in `modules/nginx.sh` refused the product's own `/api/sub/…` route.
      2. `VERIFIED-ARTIFACT-FETCH`, `PINNED-INSTALLER-HOSTS`, `PANEL-ASSET-VERIFICATION`, `FAIL-STEP` —
         `TypeError: case_verified_artifact_fetch() takes 1 positional argument but 2 were given` (and its three
         siblings): the four new cases were registered with the older one-argument signature while the runner calls
         `case.run(self.context)`.
      3. `PRE-INPUTS` — the refusal sentence no longer named the missing input; the case reads the product's text,
         so the text was re-derived from `modules/preflight.sh`, not the assertion relaxed.
      4. `PRE-PROXY-CIDR` — the DNS-mismatch refusal named the two resolvers and their answers but not the
         Cloudflare proxy the sentence is about.
      5. `VIS-05` — the attempt stopped at `install: input contract` (`preflight could not resolve
         vision-failed.testbed.internal`) instead of reaching the Vision certificate stage, so the failure measured
         was not the one the case exists for.
      6. `AIO-MATRIX`, `AIO-PKT-02`, `AIO-FAULT-PANEL/XRAY/LATENCY` — cascade, not separate defects: eight `AIO-DP-*`
         produced no result while the subscription probe was dead, so no `xray-json` payload reached `/secrets` and
         nothing could be transferred.

      **Run B `podman-aio-20261121T141243-9d32338c` — 102 PASS / 7 FAIL / 8 INCOMPLETE, 1130.6 s, `overall: FAIL`.**
      Four causes:
      1. The four artifact/failure cases — `AttributeError: 'AioProduct' object has no attribute 'repo'`. The cases
         drive the shipped shell helpers from the checkout, so `REPO_ROOT` and an `AioProduct.repo` property were
         added; all four then passed standalone.
      2. `NGX-HYGIENE` — "an unknown API path answered 200 through the edge, expected the Panel's own 404". The
         measurement is right and the expectation was wrong: the Panel's chi router ends in
         `r.Get("/*", spa.ServeHTTP)`, so a path no route occupies is answered by the frontend with 200. The probe
         label, the case assertion, the behaviour entry, the catalog and the unit fixtures were all corrected to
         that shipped answer.
      3. Eight `AIO-DP-*` INCOMPLETE — "the local host captured nothing on port 443". The request facts were true
         (delivered, 200, body match, request-id match) while the capture recorded `captured: 0` in a 0.681 s
         window the harness itself stopped: an empty window decides nothing, and the case said so instead of
         passing or failing.
      4. `AIO-MATRIX` ("8 matrix case(s) could not account for the request they measured") and `AIO-PKT-02` — the
         same cascade as cause 3.

      **Run C `podman-aio-20261121T154927-1b44c492` — 116 PASS / 1 FAIL, 798.567 s, `overall: FAIL`.** Only
      `NGX-HYGIENE`: "the Panel recorded `10.89.0.10` for a request carrying no forged header, not the client
      address this run allocated (`10.89.0.40`)". The probe runs **on the Panel host**
      (`AioProduct.host_script` → `podman.exec_bash(host.target_name, …)`), so the peer the Panel can record is the
      probe's own source address; comparing it to the client container's address asserted something the topology
      cannot produce. `panel_surface.local_source_address()` now reports that address (a connected UDP socket
      selects the route without sending a packet) as `probe_source_ip`, and the case compares the recorded peer
      with it. The eight empty-capture cases from run B passed in run C — the `podman-ingress-capture-empty-window`
      shape, where a short capture window that opens after the answer proves nothing and clears on an idle run.

      **Run D `podman-aio-20261121T161513-7cd3fa7f` — 117/117 PASS, 740.107 s, `overall: PASS`,
      `redaction_audit: {files: 19, offences: []}`.** The cases this change adds are green together with the
      cases that predate it:
      - subscription: `SUB-SERVED`, `SUB-UA-ABSENT`, `SUB-UA-BLANK`, `SUB-EDGE`, `SUB-EDGE-BAD`, `SUB-B64`,
        `SUB-JSON-SHAPES`;
      - panel hygiene: `NGX-HYGIENE`, `NGX-SCANNER`;
      - preflight: `PRE-INPUTS`, `PRE-INPUTS-BAD`, `PRE-PROXY-CIDR`, `PRE-PROXY-CIDR-OVERRIDE`;
      - lineage: `TLS-LINEAGE`, `TLS-LINEAGE-BAD`;
      - artifact chain and failure report: `VERIFIED-ARTIFACT-FETCH`, `PINNED-INSTALLER-HOSTS`,
        `PANEL-ASSET-VERIFICATION`, `FAIL-STEP`;
      - and the pre-existing contours around them: `AIO-INSTALL`, `AIO-01`…`AIO-05`, `AIO-PACKAGES`, `TLS-01`,
        `DNS-01`, `ACME-01`, `ACME-02`, `DECOY-01`, `NGX-04`, `NGX-05`, `AIO-AUTH`, `AIO-AUTH-NEG`, `APIC-01`,
        `AIO-CLIENT`, `DP-09`…`DP-14`, `AIO-REVOKE`, `AIO-RESTART`, `AIO-IDEMPOTENT`, `AIO-CHANNEL-*`,
        `AIO-INTERRUPT`, `TXN-01`…`03`, `NEG-*`, `REV-*`, `GATE-*`, `BOOT-02`, `HOOK-*`, `OWN-*`,
        `SSHID-*`, `TSSH-*`, `RUNID-01`, `RESUME-01`, `ENV-*`, `RED-01`, `RED-02`.

      **What the green run's data plane actually recorded**, read from its own evidence rather than its exit
      status: all eight `AIO-DP-*` PASS, e.g. `AIO-DP-REALITY-xray` with `ingress_intended: local`,
      `ingress_intended_captured: 10`, `ingress_intended_matched: 10`, `engine_version: 26.11.9` against
      `Xray 26.11.9`; `AIO-PKT-02` PASS with `foreign_sources: 10.89.0.41:9` and four recorded degradations
      (`foreign_source_only, no_capture_tool, no_identity, window_expired`) whose sub-verdicts are `INCOMPLETE` —
      the case reports the two measurements it could make and refuses to claim the four it could not.

      **Nonroot suite on the same tree, same day:** a full run printed `Ran 2973 tests in 3460.111s` → `OK
      (skipped=1)` (`/tmp/nonroot-20261121d.log`). The run after the last `panel_surface.py` edit printed
      `Ran 2975 tests in 3453.725s` → `FAILED (failures=2, skipped=1)` (`/tmp/nonroot-20261121e.log`): both were
      `TestPanelApiContract.test_every_cited_client_line_makes_the_call_it_is_cited_for`, reporting that the two
      `file:line` citations for `/api/sub/{shortUuid}` and `/api/sub/{shortUuid}/{clientType}` no longer resolved —
      my own insertion had shifted those lines. The citations were re-anchored to
      `tools/podman_e2e/panel_surface.py:175` and `:176` and the two prose ranges to `:175`-`179` (the same drift
      was corrected in this change's `design.md`), and `python3 -m unittest tests.test_podman_docs` then printed
      `Ran 88 tests in 29.418s` → `OK`.

**Verified 2026-11-21 (fifth run — the clean one on the repaired tree):** Background shell `bg_aace33e2`,
      log `/tmp/nonroot-20261121f.log`, started 14:37:48 UTC and ended 15:31:28 UTC (3219.670 s). The completeness
      gate printed `COMPLETENESS: PASS` (86 modules, 354 TestCase classes, 3067 unique tests; nonroot 2975), then
      the suite itself: **`Ran 2975 tests in 3219.670s` → `OK (skipped=1)`**, `EXIT=0`, zero `FAIL:` and zero
      `ERROR:` blocks.

      **The one skip is stated, not hidden:** `test_podman_lock_cases.TestLockHolderProgram.test_a_file_owned_by_another_user_is_refused` — `skipped 'handing a file to another user needs CAP_CHOWN'`. That class is registered in the nonroot suite only, so the case is skipped wherever it runs; it predates this change, is not counted as a pass, and nothing in this change depends on it.

      **What this run covers:** the whole nonroot contour on the current tree — every unit and render guard this
      change added (artifact chain `test_artifact_fetch`, failure report `test_failure_report`, preflight
      `test_preflight`, subscription `test_podman_subscriptions`, NGINX routing `test_nginx_routing`, the
      catalog/behaviour/traceability/matrix parity guards `test_podman_catalog` / `test_podman_docs` /
      `test_podman_traceability` / `test_podman_matrix`, fixture isolation, readiness, lock cases, and the
      remaining harness self-checks) plus the pre-existing suite around them. It does **not** run the `root`,
      `systemd`, `integration` or `services` suites (recorded separately below), and it runs no Podman acceptance
      case — that is 9.2.

      **What it proves about the five run-2 failures:** each one is green in the same suite that reported it —
      `TestPodmanFirstPromotion` (124 Podman-first entries), `TestContourBoundary` (249 total and the live split),
      `TestPodmanFixtureIsolation` (`2.23.20.0` is a User-Agent version string, listed with its reason),
      `TestNoUnboundedWaits` (the four `openssl` calls in `preflight_cases.py` now carry `timeout=120`).
      Immediately before this run a targeted triage of the six heaviest modules printed `Ran 309 tests in
      1354.518s — OK (skipped=1)`, so the repair was confirmed before the whole suite was spent on it.
- [x] 9.3 Re-read `docs/research/inspiration-repos.md` «Перечень для propose» against what was implemented and
      correct any row whose status changed (already-shipped items, the User-Agent wording), so the document
      stays the source for the next change.

      **Verified 2026-11-21:** every row of «Перечень для propose» now carries a `Статус` column reading
      `реализовано`, and the section opens with the dated statement that В1+В2 shipped in `inspiration-backlog`
      while the table stays the decision record for the next change (В3–В5). Each «Наша точка» was re-read
      against the current tree after the edits moved lines: A1 `modules/nginx.sh:503`, A2 `:502`, A3 `:504`,
      A4+A6+D2 `:445-490,505`, A5 `:474`, A9 `:498,516,534,551,566`, B4 `modules/preflight.sh:103`, B8
      `check_acme_lineage` `:1158` / `select_acme_lineage` `:1245`, C8 `modules/preflight.sh:325`, E1
      `modules/artifact.sh:18`, E2 `gowave-auto.sh:863`, ERR-trap `gowave-auto.sh:30`. The User-Agent wording
      already read as Р-16 states it — an unknown but syntactically valid `clientType` is proxied and the Panel
      decides, because `SUB-SERVED` sends `curl/8.5.0` — so no row needed that correction.

## Workflow follow-up

- Archive the change after its suites are green and the review requirements are satisfied.
- Verify the archived specs contain all four capabilities by path: `subscription-edge`,
  `panel-vhost-hygiene`, `install-preflight` and `lifecycle-management`; and that `lifecycle-management` still
  carries the existing requirement `Explicit ACME Endpoint Selection and Certificate Lineage Isolation`
  unchanged, with the new requirements added beside it rather than replacing it.
