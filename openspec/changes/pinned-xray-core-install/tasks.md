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
- [ ] 1.2 Add `pinned_xray_arch`, mapping `uname -m` (`x86_64` → `amd64`, `aarch64`/`arm64` → `arm64`) and
  returning non-zero for anything else. An unknown architecture is not guessed: the caller reports it and the step
  abstains (design D5 keeps the abstention a located message, not a silent skip).
  Verify: unit test in 4.4 substituting `uname` on `PATH` for `riscv64` and asserting the reason names the
  architecture and `XRAY_SERVER_VERSION=latest`.
- [ ] 1.3 Add `pinned_xray_core_satisfied CORE_BIN`, true only when `"$CORE_BIN" version` contains
  `$GOWAVE_PINNED_XRAY_VERSION` as a token — reuse the token comparison `core_version_matches` already performs
  (`modules/node.sh:35`) rather than a substring test, so `26.11.90` does not satisfy `26.11.9`.
  Verify: unit test asserting a matching fake core is satisfied, a `26.11.90` fake is not, and a core that exits
  non-zero is not satisfied.
- [ ] 1.4 Add `install_pinned_xray_core INSTALL_DIR`, the only entry point, with the value dispatch of design D1:
  unset or empty ⇒ deliver the pin; `latest` or `vlatest` ⇒ return 0 without touching the host; any other value ⇒
  return 0, leaving the explicit-version path (`ensure_pinned_xray_core`) to act.
  Verify: unit tests for all three values, asserting the stub `curl` was never invoked for `latest` and for a
  foreign version.
- [ ] 1.5 Implement the delivery inside that entry point: one `track_temp_dir` scratch directory
  (`modules/tempdir.sh`), `fetch_verified_artifact "$scratch/Xray.zip" … "$digest"` (`modules/artifact.sh:18`,
  digest last, so a digest mismatch is terminal), extraction of the `xray` member with `python3 -c
  'import zipfile,sys; …'`, then `chmod 0755` and `"$scratch/xray" version` as a self-check before the file is
  installed at `<install_dir>/rw-core` through a same-directory rename plus `sync` of both the file and its
  directory.
  Verify: `bash -n` and `shellcheck --severity=error`; unit test in 4.4 asserting the installed file is the member
  from the archive and mode `0755`.
- [ ] 1.6 Make every failure on this path closed and located: no host delivered, digest mismatch, a member that
  does not report the pinned version, and an unknown architecture each print one message naming the pinned
  version, the artifact URL and `XRAY_SERVER_VERSION=latest`. The module must not call `core install`, `core
  reset`, `ensure_pinned_xray_core` or the upstream installer — the handover is the API request this change
  removes (design D5).
  Verify: `grep -c 'XRAY_SERVER_VERSION=latest' modules/xray_core.sh` equals the number of failure messages
  (asserted by the unit test's own expected count, not by eye), and `grep -cE 'core (install|reset)' modules/xray_core.sh`
  returns 0.
- [ ] 1.7 Print one line on success naming the pinned version, the archive SHA-256 and the artifact URL, so the
  acceptance run can quote what the step verified instead of inferring it (AGENTS.md §5.2). The line carries no
  secret.
  Verify: unit test asserts the line contains both the version and the fixture digest.

## 2. Master-local installation path (`modules/node.sh`)

- [ ] 2.1 Source the new module beside `modules/artifact.sh` (`modules/node.sh:19`). Count the sourcing block
  before editing (`grep -c '^source "\$SCRIPT_DIR/modules/' modules/node.sh`) and require the count to grow by
  exactly one (AGENTS.md §3.7).
  Verify: `bash -n modules/node.sh`; `grep -c 'modules/xray_core.sh' modules/node.sh` returns 1.
- [ ] 2.2 Call `install_pinned_xray_core "$GOWAVE_NODE_INSTALL_DIR"` inside
  `if (( node_restart_required == 1 ))` (`modules/node.sh:294`), before the pinned-installer resolution and
  before both installer invocations — the pinned one (`:312`) and the floating `main` branch the Podman contour
  takes (`:318-331`) — rather than after the branch, so the acceptance proof reaches the changed code and a
  serving node's core is never replaced under it (design D3).
  Verify: source-order test in 4.5 comparing the anchor indices inside the `install_local_node` slice, and
  `grep -c 'install_pinned_xray_core' modules/node.sh` returns 1.
- [ ] 2.3 Leave `ensure_pinned_xray_core` (`modules/node.sh:338`) in place and un-widened: after the change it is
  reached with the pinned version already installed, so it is a no-op on the default path, and it keeps serving
  the explicit foreign-version path (design D9).
  Verify: `python3 -m unittest -v tests.test_node_integration.TestNodeIntegration
  tests.test_node_integration.TestLocalNodeIdempotency` passes unchanged.

## 3. Worker payload copy (`gowave-node-auto.sh`)

- [ ] 3.1 Duplicate the table and the four functions into the payload immediately after the payload's
  `ensure_pinned_xray_core()` (`gowave-node-auto.sh:4889`), because the payload is one file streamed over SSH and
  cannot source `modules/` (design D6). Adapt only the output calls to the payload's own `log_info`/`log_err`.
  Before writing, count the anchors this edit can reach:
  `grep -c '^ensure_pinned_xray_core() {' gowave-node-auto.sh` must be 1 inside the payload for this edit to be
  the one you mean.
  Verify: `bash -n gowave-node-auto.sh`,
  `grep -c 'GOWAVE_PINNED_XRAY_VERSION=' gowave-node-auto.sh` returns 1, and the parity test in 4.2 compares this
  copy with `modules/xray_core.sh`.
- [ ] 3.2 Call the step in `run_upstream_node_installer` (`:4976`) before `run_node_installer_with_retry`
  (`:5007`). Place it after the `GOWAVE_NODE_INSTALLER_COMMIT`/`_SHA256` validation and before `tmp_inst` is
  created, so a failed pin leaves no installer temp file behind.
  Verify: source-order test in 4.5; `grep -c 'install_pinned_xray_core' gowave-node-auto.sh` equals the expected
  count (one definition site plus one call site).
- [ ] 3.3 Keep the payload ordering that supplies the step's dependencies: the call is reached only through
  `run_upstream_node_installer`, which the payload invokes after `setup_system_prereqs` (`:5337`, the python3
  install) at `:5347`.
  Verify: unit test asserting the payload sequence's index of `setup_system_prereqs` is smaller than the index of
  the `run_upstream_node_installer` invocation, and that `python3` is not used earlier in the payload's install
  sequence.

## 4. Unit tests (`tests/test_node_integration.py`)

- [ ] 4.1 Add `TestPinnedXrayCore` next to `TestPinnedNodeInstaller` and register it in the `nonroot` suite list
  (`tests/run_ci.py:32`, immediately after `test_node_integration.TestPinnedNodeInstaller`); the runner discovers
  classes by name, so an unregistered class runs nowhere.
  Verify: `python3 tests/run_ci.py --check-completeness` and
  `python3 -m unittest -v tests.test_node_integration.TestPinnedXrayCore` (imported as a package from the repo
  root).
- [ ] 4.2 Add the parity guard: read the table in `modules/xray_core.sh`, the copy in `gowave-node-auto.sh` and
  `tests/cases/matrix.yaml` (`clients[id=xray].artifact`), and require the same version, URL and SHA-256 for
  amd64, plus one 64-hex digest and one `Xray-linux-arm64-v8a.zip` URL in the product copies. Prove the guard
  fails on its own damage: run the same comparison over doctored text with one character changed in each of the
  three inputs and require a failure for each.
  Verify: `python3 -m unittest -v tests.test_node_integration.TestPinnedXrayCore`.
- [ ] 4.3 Add the delivery tests, driving the real function with a stub `curl` on `PATH` and a zip built by
  `zipfile` whose `xray` member is a script printing `Xray 26.11.9 (Xray, Penetration)`, with the row variables
  reassigned to that fixture's URL and digest:
  a matching version already installed ⇒ no `curl` invocation at all; a foreign version installed ⇒ replaced; a
  digest mismatch ⇒ non-zero exit, no `rw-core`, and the stub's URL log shows exactly one host tried; no host
  delivers ⇒ non-zero exit; a member that reports another version ⇒ non-zero exit and no `rw-core`; `latest` and
  an explicit foreign version ⇒ nothing downloaded and no file written.
  Verify: the same command as 4.2; each case asserts the stub's URL log, the file's presence and its content, so
  the assertion cannot pass on a host where the step did nothing at all.
- [ ] 4.4 Add the abstention tests: `uname` stubbed to `riscv64` ⇒ non-zero exit from `pinned_xray_arch`, and
  `install_pinned_xray_core` writes nothing and names both the architecture and `XRAY_SERVER_VERSION=latest`.
  Verify: same command.
- [ ] 4.5 Add the source-order guards, each anchored on a call site inside a function slice rather than on a
  position in the file (`tests/test_node_integration.py` has no shared helper for this yet; add one beside the
  class): the `install_pinned_xray_core` call precedes both `run_node_installer_with_retry` and the
  `raw.githubusercontent.com/…/main/install.sh` fetch inside `install_local_node`; the payload call precedes
  `run_node_installer_with_retry` inside `run_upstream_node_installer`; the payload call appears exactly once.
  Verify: same command; then break each anchor deliberately and require the guard to fail before reverting.

## 5. Documentation and the environment example

- [ ] 5.1 Pin the three version variables in `tools/live_vps_config.env.example` (`:95,98,101`):
  `XRAY_SERVER_VERSION=26.11.9`, `XRAY_CLIENT_VERSION=26.11.9`, `MIHOMO_CLIENT_VERSION=1.19.34`, with a comment
  stating the unset/`latest` meaning of `XRAY_SERVER_VERSION`.
  Verify: `grep -n 'XRAY_SERVER_VERSION\|XRAY_CLIENT_VERSION\|MIHOMO_CLIENT_VERSION' tools/live_vps_config.env.example`
  shows the three pinned values and no `=latest` on those keys.
- [ ] 5.2 Correct the claims that every component floats to `latest`: `docs/LIVE_VPS_TESTING.md:10` and `:41`.
  The pin's consequence for a run — an unset value installs 26.11.9 and `latest` is the opt-out — belongs in the
  same paragraph, and the file must still say which components do follow the channel.
  Verify: `grep -n 'latest' docs/LIVE_VPS_TESTING.md` shows the surviving floating defaults and the pinned Xray
  server, with no sentence left claiming the server core floats.
- [ ] 5.3 Add the variable to the `node add` environment table in `README.md` (`:69-81`) with its default (the
  pinned version) and the `latest` opt-out.
  Verify: the table row is present and the default column states `26.11.9`, not `latest`.
- [ ] 5.4 Document the failure and the escape in the operator-facing documentation next to the node installation
  instructions: an undeliverable pinned artifact stops the installation, the message names the artifact and
  `XRAY_SERVER_VERSION=latest`, and `gowave-node core reset` answers "no managed stock core is available" on a
  host that never had a managed install (design D8).
  Verify: `python3 tests/run_ci.py --suite nonroot` passes, including the documentation guards that read these
  files.

## 6. Acceptance proof on the Podman contour

- [ ] 6.1 Make `api.github.com` unreachable inside the disposable hosts of both install contours: add the name to
  the harness's hosts writer (`tools/podman_e2e/aio.py:1104-1112` `hosts_lines`/`write_hosts`) pointing at the
  loopback address, so a request is refused immediately instead of hanging, and re-apply the entry after any
  rewrite (the ACME fixture replaces the whole file). Record the block from inside each container: name
  resolution and the exit status of a request to the name.
  Verify: the evidence file for the install case carries both the resolved address and the refused request;
  `grep -c 'api.github.com' tools/podman_e2e/aio.py` equals the expected count for the writer plus the probe.
- [ ] 6.2 Prove the AIO path: `AIO-INSTALL` stays green with the block in place, and its evidence carries the step's
  success line (pinned version and archive digest) and `rw-core version` read inside the container, which must
  report `Xray 26.11.9`.
  Verify: `sudo python3 -m tools.run_podman_e2e --topology aio` from the repository root, then read
  `artifacts/podman-e2e/<run>/evidence/` for the case and its `result.json` commit field.
- [ ] 6.3 Prove the Worker path: `MN-INSTALL` stays green with the block in place on the Worker, and its evidence
  carries the same two readings from inside the Worker container.
  Verify: `sudo python3 -m tools.run_podman_e2e --topology multi-node`.
- [ ] 6.4 Prove the control, on a host the measured pair does not need: create a disposable second Worker
  (`AioTopology.start_secondary_worker` + `pin_secondary_trust`,
  `tools/podman_e2e/topology.py:1565`), created with `XRAY_SERVER_VERSION=latest` and the same block, run the
  product's `node add` against it, and require a non-zero exit whose output names the unreachable API or its
  status. Tear the container down in a `finally`, restore the Master's registration record files from the bytes
  read before the attempt, and require the Panel to report exactly the installed nodes afterwards — a control that
  leaves a third node behind has damaged the run it was measuring.
  Verify: the case's evidence file carries the control's return code, its matched failure text, the teardown result
  and the post-teardown node list; deleting the block from the control container makes the control succeed, which
  is how the probe's own reach is confirmed before the green run is quoted.
- [ ] 6.5 Keep the case inventory unchanged: no new case id, so the positive counts in `tests/cases/matrix.yaml`
  and `tests/cases/behaviors.yaml` stay as they are. If the case's own assertion sentence had to change, update
  its `assertion` in `tests/cases/catalog.yaml` and let the divergence guard recompute the digest; regenerate the
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
