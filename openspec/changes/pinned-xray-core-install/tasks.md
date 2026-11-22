# Tasks

## 1. The pin table and the verified core installer (`modules/xray_core.sh`)

- [ ] 1.1 Create `modules/xray_core.sh` with the `#!/usr/bin/env bash` + `set -Eeuo pipefail` preamble and one
  table of `(version, arch)` rows: `GOWAVE_PINNED_XRAY_VERSION="26.11.9"`, amd64
  `https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-linux-64.zip` with
  `b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82`, arm64
  `…/Xray-linux-arm64-v8a.zip` with `64ed6858982a7f5eb85d88b811089063bd4f17561f4c8f44e0f1dc8e6f6430be`
  (`artifacts/tz-pinned-xray-core.txt:63-66`, confirmed against the release's `.dgst` files). Expose each row as a
  plain variable read by one lookup function, never from the environment, so a unit test can substitute a fixture
  digest for the archive it builds itself.
  Verify: `bash -n modules/xray_core.sh`, `shellcheck --severity=error modules/xray_core.sh`, and
  `grep -c 'Xray-linux-' modules/xray_core.sh` returns exactly 2 (one per architecture; a third copy means a row
  was duplicated).
- [ ] 1.2 Do not map the architecture a second time. `detect_arch` already answers `amd64`/`arm64` and refuses
  anything else (`modules/panel.sh:14-23`), but it sits in the Panel module and its three callers source
  `panel.sh` to reach it (`tests/test_panel_deployment.py:87`, `tests/test_artifact_fetch.py:212`,
  `tools/podman_e2e/aio.py:9682`). Move it, unchanged in behaviour, to `modules/os.sh` — the module whose own
  header is "Base OS, package inventory, and environment detection" — have `panel.sh` source `os.sh`, and have
  `modules/xray_core.sh` source `os.sh` by its own directory, so the new module is self-contained and the three
  existing callers keep working through `panel.sh`. `pinned_xray_arch` then calls `detect_arch`; the payload copy
  still carries the two-line `case`, because the payload cannot source `modules/`.
  Verify: `grep -c '^detect_arch() {' modules/*.sh` returns 1 (`modules/os.sh`), `grep -c 'uname -m'
  modules/xray_core.sh` returns 0, the three existing callers still answer (`python3 -m unittest -v
  tests.test_panel_deployment tests.test_artifact_fetch`), and the unit test in 4.4 substitutes `uname` on `PATH`
  to assert `riscv64` is refused with the architecture named.
- [ ] 1.3 Carry the version-token comparison in this module as the single definition for `modules/`
  (`core_version_matches`, moved from `modules/node.sh:35-46`), then delete that copy from `modules/node.sh` so the
  function is not defined twice in sourced code. The payload keeps its own copy: a payload-slicing test anchors on
  the literal `core_version_matches() {` (`tests/test_node_integration.py:435`). Token comparison, not a substring
  test, so `26.11.90` does not satisfy `26.11.9`.
  Verify: `grep -c '^core_version_matches() {' modules/*.sh` returns 1, `bash -n` on both files, and the unit test
  in 4.4 asserting a matching fake is satisfied, a `26.11.90` fake is not, and a core that exits non-zero is not.
- [ ] 1.4 Add `install_pinned_xray_core INSTALL_DIR`, the only entry point, with the value dispatch of design D1:
  unset or empty ⇒ deliver the pin; a value naming the pin itself — `26.11.9` **or** `v26.11.9` ⇒ deliver the same
  pin, because that is what the acceptance matrix injects (`tests/cases/matrix.yaml:26` →
  `tools/podman_e2e/topology.py:1068`) and what the documentation tells an operator to write; `latest` or `vlatest`
  ⇒ return 0 without touching the host; any other value ⇒ return 0, leaving the explicit-version path
  (`ensure_pinned_xray_core`) to act.
  Verify: unit tests for all four values, asserting the stub `curl` was never invoked for `latest` and for a foreign
  version, and was invoked exactly once for `26.11.9` and for `v26.11.9`.
- [ ] 1.5 Implement the delivery inside that entry point: one `track_temp_dir` scratch directory
  (`modules/tempdir.sh`), `fetch_verified_artifact "$scratch/Xray.zip" … "$digest"` (`modules/artifact.sh:18`,
  digest last, so a digest mismatch is terminal), extraction of the `xray` member with `python3 -c
  'import zipfile,sys; …'`, then `chmod 0755` and `"$scratch/xray" version` as a self-check before the file is
  installed at `<install_dir>/rw-core` through a same-directory rename plus `sync` of both the file and its
  directory.
  Verify: `bash -n` and `shellcheck --severity=error`; unit test in 4.3 asserting the installed file is the member
  from the archive and mode `0755`.
- [ ] 1.6 Make every failure on this path closed and located through one reporting helper, so each of the four
  conditions prints exactly one step-level message after whatever diagnostic the helper produced: no host delivered,
  digest mismatch, a member that does not report the pinned version, and an unsupported architecture. The message
  names the pinned version, the artifact that was attempted and `XRAY_SERVER_VERSION=latest`; the
  unsupported-architecture message names the architecture and the opt-out but no URL, because no artifact for that
  architecture exists in the table. The module must not call `core install`, `core reset`, `ensure_pinned_xray_core`
  or the upstream installer — the handover is the API request this change removes (design D5).
  Verify: `grep -c 'XRAY_SERVER_VERSION=latest' modules/xray_core.sh` returns 1 (the literal lives once, in the
  helper), `grep -cE 'core (install|reset)' modules/xray_core.sh` returns 0, and the unit test asserts that each of
  the four conditions reaches the helper.
- [ ] 1.7 Print one line on success naming the pinned version, the archive SHA-256 and the artifact URL, so the
  acceptance run can quote what the step verified instead of inferring it (AGENTS.md §5.2). The line carries no
  secret.
  Verify: unit test asserts the line contains both the version and the fixture digest.

## 2. Master-local installation path (`modules/node.sh`)

- [ ] 2.1 Source the new module beside `modules/artifact.sh` (`modules/node.sh:8-9`). Count the sourcing block
  before editing (`grep -c '^source "\$SCRIPT_DIR/modules/' modules/node.sh` currently returns 2) and require the
  count to grow by exactly one (AGENTS.md §3.7).
  Verify: `bash -n modules/node.sh`; `grep -c 'modules/xray_core.sh' modules/node.sh` returns 1.
- [ ] 2.2 Call `install_pinned_xray_core "$GOWAVE_NODE_INSTALL_DIR"` inside
  `if (( node_restart_required == 1 ))` (`modules/node.sh:294`), before the pinned-installer resolution and
  before both installer invocations — the pinned one (`:312`) and the floating `main` branch the Podman contour
  takes (`:318-331`) — rather than after the branch, so the acceptance proof reaches the changed code and a
  serving node's core is never replaced under it (design D3).
  Verify: source-order test in 4.5 comparing the anchor indices inside the `install_local_node` slice, and
  `grep -c 'install_pinned_xray_core' modules/node.sh` returns 1.
- [ ] 2.3 Leave `ensure_pinned_xray_core` (`modules/node.sh:48-78`) in place and un-widened: after the change it is
  reached with the pinned version already installed, so it is a no-op on the default path, and it keeps serving
  the explicit foreign-version path (design D9). Its only edit is the deleted duplicate of `core_version_matches`
  from task 1.3.
  Verify: `python3 -m unittest -v tests.test_node_integration.TestNodeIntegration
  tests.test_node_integration.TestLocalNodeIdempotency` passes unchanged.

## 3. Worker payload copy (`gowave-node-auto.sh`)

- [ ] 3.1 Duplicate the table and the functions into the payload immediately after the payload's
  `ensure_pinned_xray_core()` (`gowave-node-auto.sh:4889`), because the payload is one file streamed over SSH and
  cannot source `modules/` (design D6). Adapt only the output calls to the payload's own `log_info`/`log_err`, and
  keep the payload's own `core_version_matches` and the two-line architecture `case`. Before writing, count the
  anchors this edit can reach: `grep -c '^ensure_pinned_xray_core() {' gowave-node-auto.sh` must be 1 inside the
  payload for this edit to be the one you mean.
  Verify: `bash -n gowave-node-auto.sh`, `grep -c 'GOWAVE_PINNED_XRAY_VERSION=' gowave-node-auto.sh` returns 1, and
  the parity test in 4.2 compares this copy with `modules/xray_core.sh`.
- [ ] 3.2 Call the step in `run_upstream_node_installer` (`:4976`) before `run_node_installer_with_retry`
  (`:5007`). Place it after the `GOWAVE_NODE_INSTALLER_COMMIT`/`_SHA256` validation and before `tmp_inst` is
  created, so a failed pin leaves no installer temp file behind.
  Verify: source-order test in 4.5; `grep -c 'install_pinned_xray_core' gowave-node-auto.sh` equals the expected
  count (one definition site plus one call site).
- [ ] 3.3 Keep the payload ordering that supplies the step's dependencies: the call is reached only through
  `run_upstream_node_installer`, which the payload invokes after `setup_system_prereqs` (`:5337`, the python3
  install) at `:5347`.
  Verify: unit test asserting the payload sequence's index of `setup_system_prereqs` is smaller than the index of
  the `run_upstream_node_installer` invocation.

## 4. Unit tests (`tests/test_node_integration.py`)

- [ ] 4.1 Add `TestPinnedXrayCore` next to `TestPinnedNodeInstaller` and register it in the `nonroot` suite list
  (`tests/run_ci.py:31`, immediately after `test_node_integration.TestPinnedNodeInstaller`). The runner imports
  every name in the list, so an unregistered class is not silently skipped: it makes every run fail with a
  `ValueError` on the missing attribute.
  Verify: `python3 tests/run_ci.py --check-completeness` and
  `python3 -m unittest -v tests.test_node_integration.TestPinnedXrayCore` (imported as a package from the repo
  root).
- [ ] 4.2 Add the parity guard: read the table in `modules/xray_core.sh`, the copy in `gowave-node-auto.sh` and
  `tests/cases/matrix.yaml` (`clients[id=xray].artifact`), and require the same version, URL and SHA-256 for amd64.
  For arm64 the matrix has no row, so the guard checks that the product copies agree with each other, that the
  digest is 64 hex, and that the URL names `arm64` — the digest's only source is the published `.dgst`, and the
  test states that rather than pretending to a second in-tree witness. Add the mapping guard from task 1.2:
  `detect_arch` lives in `modules/os.sh` and still answers both architectures the table names, and
  `modules/panel.sh` still provides it to its own callers by sourcing `os.sh`. Prove the guard fails on its own
  damage: run the comparison over doctored text with one character changed in each input and require a failure for
  each.
  Verify: `python3 -m unittest -v tests.test_node_integration.TestPinnedXrayCore`.
- [ ] 4.3 Add the delivery tests, reusing the `_stub_curl` pattern from `TestPinnedNodeInstaller`
  (`tests/test_node_integration.py:1712`) and a zip built by `zipfile` whose `xray` member is a script printing
  `Xray 26.11.9 (Xray, Penetration)`, with the row variables reassigned to that fixture's URL and digest:
  a matching version already installed ⇒ no `curl` invocation at all; a foreign version installed ⇒ replaced; a
  digest mismatch ⇒ non-zero exit, no `rw-core`, and the stub's URL log shows exactly one host tried; no host
  delivers ⇒ non-zero exit; a member that reports another version ⇒ non-zero exit and no `rw-core`; `latest` and
  an explicit foreign version ⇒ nothing downloaded and no file written.
  Verify: the same command as 4.2; each case asserts the stub's URL log, the file's presence and its content, so
  the assertion cannot pass on a host where the step did nothing at all.
- [ ] 4.4 Add the abstention and dispatch tests: `uname` stubbed to `riscv64` ⇒ the step writes nothing and names
  both the architecture and `XRAY_SERVER_VERSION=latest`; `XRAY_SERVER_VERSION=26.11.9` and `v26.11.9` ⇒ the archive
  is fetched once and installed (the case the acceptance contour depends on); the four failure messages of task 1.6
  are each produced by its own condition.
  Verify: same command.
- [ ] 4.5 Add the source-order guards, each anchored on a call site inside a function slice rather than on a
  position in the file (`tests/test_node_integration.py` has no shared helper for this yet; add one beside the
  class): the `install_pinned_xray_core` call precedes both `run_node_installer_with_retry` and the
  `raw.githubusercontent.com/…/main/install.sh` fetch inside `install_local_node`; the payload call precedes
  `run_node_installer_with_retry` inside `run_upstream_node_installer`; the payload call appears exactly once.
  Verify: same command; then break each anchor deliberately and require the guard to fail before reverting.

## 5. Documentation, the environment example, and the guards that read them

- [ ] 5.1 Pin the three version variables in `tools/live_vps_config.env.example` (`:95,98,101`):
  `XRAY_SERVER_VERSION=26.11.9`, `XRAY_CLIENT_VERSION=26.11.9`, `MIHOMO_CLIENT_VERSION=1.19.34`, with a comment
  stating the unset/pin/`latest` meaning of `XRAY_SERVER_VERSION`. The validator in `tools/live_vps/config.py`
  accepts explicit versions, and `tools/live_vps/versions.py::output_matches_expected_version` compares by token,
  so `26.11.9` matches `Xray 26.11.9 …` and `1.19.34` matches `v1.19.34` (requirements §5.1).
  Verify: `grep -n 'XRAY_SERVER_VERSION\|XRAY_CLIENT_VERSION\|MIHOMO_CLIENT_VERSION' tools/live_vps_config.env.example`
  shows the three pinned values and no `=latest` on those keys.
- [ ] 5.2 Flip the guard that the pinning invalidates:
  `tests/test_podman_docs.py::TestLiveContractReconciliation::test_the_engine_pinning_difference_is_recorded`
  (`:686-700`) reads the same file (`LIVE_CONFIG`, `:596`) and asserts `XRAY_CLIENT_VERSION=latest` and
  `MIHOMO_CLIENT_VERSION=latest` verbatim, so it fails the moment 5.1 lands. Rewrite it to assert the pinned values,
  keep its comparison against `tests/cases/matrix.yaml` (`product.xray_client_version`/`mihomo_client_version`), and
  rename it for what it now records: the two sides name the same build instead of diverging.
  Verify: `python3 -m unittest -v tests.test_podman_docs.TestLiveContractReconciliation`.
- [ ] 5.3 Rewrite the three places that describe the divergence as permanent: `docs/PODMAN_E2E_DISCOVERY.md:524-538`
  ("The engines are the same binaries, pinned differently … which reads `latest`"), `:968-975` ("The engine pinning
  is the divergence that stays recorded"), and the matrix header (`tests/cases/matrix.yaml:4-6`, "The live runner
  follows the release instead"). Each must say that both sides now name the same client builds, without weakening
  the rule that the container suite is where a specific build is named.
  Verify: `grep -c 'pinned differently\|divergence that stays recorded' docs/PODMAN_E2E_DISCOVERY.md` returns 0,
  `python3 -m unittest -v tests.test_podman_docs` passes, and `grep -n 'latest' tests/cases/matrix.yaml` shows only
  the panel/node channel.
- [ ] 5.4 Correct the claims that every component floats to `latest`: `docs/LIVE_VPS_TESTING.md:10` and `:41`. The
  pin's consequence for a run — an unset value installs 26.11.9, `latest` is the opt-out, and an explicit client
  version makes preflight require exactly that build on the control machine — belongs in the same paragraph, and the
  file must still say which components do follow the channel.
  Verify: `grep -n 'latest' docs/LIVE_VPS_TESTING.md` shows the surviving floating defaults and the pinned Xray
  server, with no sentence left claiming the server core floats.
- [ ] 5.5 Add the variable to the `node add` environment table in `README.md` (`:69-81`) with its default (the
  pinned version) and the `latest` opt-out.
  Verify: the table row is present and the default column states `26.11.9`, not `latest`.
- [ ] 5.6 Document the operator-facing consequences next to the node installation instructions: an undeliverable
  pinned artifact stops the installation, the message names the artifact and `XRAY_SERVER_VERSION=latest`;
  `gowave-node core reset` answers "no managed stock core is available" on a host that never had a managed install
  (design D8); and the remaining network dependencies are named — the release zip and the geodata files still come
  from `github.com`, which costs no API quota but is not removed here (requirements §5.3, §7.2).
  Verify: `python3 tests/run_ci.py --suite nonroot` passes, including the documentation guards that read these
  files.

## 6. Acceptance proof on the Podman contour

- [ ] 6.1 Make the block reusable on any container, not only the AIO host. The hosts-steering code lives in
  `tools/podman_e2e/aio.py:1078-1128` as a script driven by `HOSTS`/`HOST` arguments, and it is currently used for
  the ACME directory. Lift it into one helper that takes the container name and the blocked host, and point the
  entry at an address nothing answers on — `127.0.0.2`, not `127.0.0.1`, because the product's own NGINX listens on
  `127.0.0.1:443` and a TLS error from it is a weaker observation than a refused connection. Re-apply the entry
  after any rewrite of `/etc/hosts` (the ACME fixture replaces the whole file) and record, from inside each
  container, the name's resolution and the exit status of a request to it.
  Verify: each container's evidence carries the resolved address and the refused request;
  `grep -c 'api.github.com' tools/podman_e2e/aio.py` equals the expected count for the helper plus the probes.
- [ ] 6.2 Prove the Master-local path: `AIO-INSTALL` stays green with the block applied before its install, and its
  evidence carries the step's success line (pinned version and archive digest) and `rw-core version` read inside
  the container — reuse `INSTALLED_VERSION_SCRIPT` (`aio.py:199-243`) and `require_configured_versions`, which
  already read the core, rather than adding a second reader.
  Verify: `sudo python3 -m tools.run_podman_e2e --topology aio` from the repository root, then read
  `artifacts/podman-e2e/<run>/evidence/` for the case and its `result.json` commit field.
- [ ] 6.3 Prove the Worker path, in the case that actually installs a Worker: `MN-INSTALL` installs the Master only
  and its evidence says the Worker "stays unprovisioned"; the Worker is registered by `WRK-04`
  (`tools/podman_e2e/multi_node.py:56,2115`). Apply the block to the Worker before `WRK-04` runs and read the
  core there: `worker_core_version` (`multi_node.py:1192`) reports what the node says, and one
  `/opt/gowave-node/rw-core version` exec inside the Worker container reports what the file is.
  Verify: `sudo python3 -m tools.run_podman_e2e --topology multi-node`, then the same two readings in the run's
  evidence for `WRK-04`; `AIO-INSTALL`/`MN-INSTALL` alone are not evidence for this path.
- [ ] 6.4 Prove the control inside `WRK-04`, on a host neither installed role needs. Create a disposable second
  Worker with `MultiNodeTopology.start_secondary_worker` + `pin_secondary_trust`
  (`tools/podman_e2e/topology.py:1565-1650`; the method is on the Multi-Node class, not on `AioTopology`), block
  the same name inside it, and run the product's `node add` against it with `XRAY_SERVER_VERSION=latest` set on the
  **Master's** command for that invocation — the value reaches the Worker over SSH stdin from the Master's
  environment (`gowave-auto.sh:1156` → `gowave-node-auto.sh:2147`), so a variable set in the container's creation
  environment changes nothing. Add the optional environment prefix to `node_add_script`/`node_add`
  (`topology.py:1678-1713`) and assert it is in the recorded command. Require a non-zero exit whose output names
  the blocked host and no `rw-core` on the control host. Tear down: remove the container, reset the argv observer's
  trace so `MN-ARGV-OBSERVER` reads only the positive deployment, and restore the DNS zone, `/root/.ssh/known_hosts`
  and the node-add journal/state from the bytes read before the attempt, mirroring `MN-ENV-CONTRACT`
  (`multi_node.py:2270-2360`). Then require the Panel to report exactly the two installed nodes.
  Verify: the case's evidence carries the control's return code, its matched failure text, the teardown result and
  the post-teardown node list; removing the block from the control container makes the control succeed, which is
  how the probe's own reach is confirmed before the green run is quoted.
- [ ] 6.5 Update the scripted fixtures the new probes reach: `tests/test_podman_aio.py` and
  `tests/test_podman_multi_node.py` answer per `exec`/`curl` call (a `results.pop(0)` queue), so an extra probe or
  an extra `exec` makes them fail or answer out of order. Add the block probe, the core version read and the
  control's command to the scripted transcripts.
  Verify: `python3 -m unittest -v tests.test_podman_aio tests.test_podman_multi_node`.
- [ ] 6.6 Keep the case inventory unchanged: no new case id, so the positive counts in `tests/cases/matrix.yaml`
  and `tests/cases/behaviors.yaml` stay as they are. If a case's own assertion sentence had to change, update its
  `assertion` in `tests/cases/catalog.yaml` and let the divergence guard recompute the digest; regenerate the
  published views afterwards.
  Verify: `python3 -m tools.podman_e2e.catalog check`, `python3 -m tools.podman_e2e.trace --strict`,
  `python3 -m tools.podman_e2e.catalog behaviors --write` followed by `python3 -m tools.podman_e2e.trace --markdown`,
  and `sudo python3 -m tools.podman_e2e.trace --verify-run artifacts/podman-e2e` on the run from 6.2/6.3.

## 7. Verification

- [ ] 7.1 `bash -n gowave-auto.sh gowave-node-auto.sh assets/backup/gowave-backup.sh modules/*.sh tests/*.sh`.
- [ ] 7.2 `shellcheck --severity=error gowave-auto.sh gowave-node-auto.sh assets/backup/gowave-backup.sh
  modules/*.sh tests/*.sh` — the binary is absent on this workstation, so run it through the Podman image and
  report "not run" rather than claiming it.
- [ ] 7.3 `python3 tests/run_ci.py --check-completeness`.
- [ ] 7.4 `python3 tests/run_ci.py --suite nonroot` (full log; the verdict is not in the log tail, so read the
  summary line).
- [ ] 7.5 `openspec validate pinned-xray-core-install --strict`.
- [ ] 7.6 State what was not run in the change's own report: no live VPS run (requirements §6.4), no executed arm64
  install, and no check of `github.com` reachability — the container contour is the only executed proof.
