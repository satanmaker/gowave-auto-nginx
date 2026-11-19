# Tasks

## 0. Upstream-compatible dashboard layout

- [x] 0.1 Extract the dashboard into `<install-dir>/frontend/dist` through a staging rename and stop creating
  `<install-dir>/dist` in `download_panel_release` (`modules/panel.sh`); the release archive holds the files at its
  root (`sources/gowave/.github/workflows/release.yml:45`), so the old extraction left them in `frontend/` and
  only the symlink made them reachable.
  Verify: `bash -n modules/panel.sh`, `grep -c 'ln -sfn' modules/panel.sh` returns 0.
- [x] 0.2 Remove a legacy `<install-dir>/dist` symlink on reinstall, and leave the path alone when it is a real
  directory or a regular file. Verify: a test in `tests/test_panel_deployment.py` covers the migration with a
  pre-created symlink and a pre-created directory.
- [x] 0.3 Repack the release fixture in `tests/test_panel_deployment.py` the way
  `sources/gowave/.github/workflows/release.yml:45` does (`tar -czf ... -C dist .`, files at the archive root),
  then assert `frontend/dist/index.html` and that `<install-dir>/dist` does not exist. The current fixture adds
  `dist/` inside the tar (`tests/test_panel_deployment.py:323-329`), so the existing assertion also passes under
  the old symlinked layout. Verify: after repacking, the same test against the pre-change `panel.sh` fails on the
  `frontend/dist` assertion; with the change it passes (`python3 tests/test_panel_deployment.py`).
- [x] 0.4 Prove the layout on a real host: reinstall on a disposable host, then run the upstream
  `install.sh --update` manually (no product script invokes it) and confirm it reaches the restart instead of
  `Refusing a symlinked /opt/gowave/dist`. Verify: the command's exit status, the absence of the refusal line and
  the panel's `wait_healthy` line in the log are recorded here.
  Closed 2026-11-19 on the live pair by the in-panel updater rather than by `install.sh --update`: the operator
  triggered the update from the Panel UI, `gowave-update.service` ran once (17:42:06 → 17:42:11 UTC) and its
  journal reads `Installing the frontend into /opt/gowave/frontend/dist` → `Reapplying the service policy` →
  `Restarting gowave.service` → `Finished`, exit state `done`. Upstream's own binary writes the dashboard to
  `frontend/dist` and reaches the restart; the refusal line appears nowhere, and `/opt/gowave/dist` does not
  exist on either host. The literal `install.sh --update` command was **not** run — record:
  `artifacts/live-vps/post-update-20261119/README.md`.

## 1. Unit templates and the runtime directory

- [x] 1.1 Add `RuntimeDirectory=gowave`, `RuntimeDirectoryMode=0700` and `RuntimeDirectoryPreserve=yes` to the
  base unit template in `configure_panel_systemd` (`modules/panel.sh`). Verify: `bash -n modules/panel.sh`, and
  `grep -c 'RuntimeDirectory=gowave' modules/panel.sh` returns exactly 1 (a second copy means the template was
  edited in the wrong place).
- [x] 1.2 Write `/etc/systemd/system/gowave-update.service`
  (`ExecStart=<install-dir>/gowave-server update apply <install-dir>`, `Type=oneshot`, `TimeoutStartSec=15min`,
  `After=network-online.target`, `Wants=network-online.target`, no `User=`) and
  `/etc/systemd/system/gowave-update.path`
  (`PathExists=/run/gowave/update-request`, `Unit=gowave-update.service`, `WantedBy=multi-user.target`) from
  templates inside `configure_panel_systemd`, mirroring
  `sources/gowave/backend-go/internal/serviceunit/install.sh:109-133` so the `service install` that
  `update apply` runs rewrites them with identical content, and add `gowave-update.path` to the enable list (task
  2.1 starts it). Verify: `bash -n modules/panel.sh`, `shellcheck --severity=error modules/panel.sh` (report "not
  run" if the binary is absent), and `grep -c 'gowave-update' modules/panel.sh` equals the expected count for the
  two templates plus the enable entry.
- [x] 1.3 Extend `tests/test_systemd_runner.py::TestSystemdRunner` with assertions that `modules/panel.sh`
  emits the three `RuntimeDirectory*` directives, both helper unit fragments, the `gowave-update.path` enable
  entry, and contains no `service install` invocation. Verify: `python3 -m unittest -v tests.test_systemd_runner`
  passes, and a temporary removal of one fragment turns the new test red.

## 2. Install ordering and uninstall ownership

- [x] 2.1 Start `gowave-update.path` immediately after the existing `systemctl restart gowave.service` in
  `cmd_install` (`gowave-auto.sh:437-438`), so `/run/gowave` exists before the watch is armed. Verify: read the
  edited block, `bash -n gowave-auto.sh`, and a static test asserting the start line follows the restart line in
  the file.
- [x] 2.2 Add `gowave-update.path` and `gowave-update.service` to the `cmd_uninstall` stop, disable and removal
  lists, keeping a single `daemon-reload`. Verify: `bash -n gowave-auto.sh` and a test asserting both names appear
  in all three lists.

## 3. Specification and operator documentation

- [x] 3.1 Correct the stale claim that `gowave-server service install` registers the Panel and produces
  `90-unprivileged.conf` in `openspec/changes/gowave-auto-nginx/specs/lifecycle-management/spec.md` (requirement
  "External Proxy Mode and Service Ownership"), `openspec/changes/gowave-auto-nginx/RISKS_AND_OPEN_QUESTIONS.md`
  RES-14 and `openspec/changes/gowave-auto-nginx/tasks.md` 4.4 (which also claims the native command generates
  `gowave-update.path`), so they describe the shipped behaviour: the project writes the base unit and both helper
  units, and the upstream helper reapplies the drop-in and the helper units on each in-panel update. Verify:
  `openspec validate gowave-auto-nginx --strict` passes and `grep -rn 'service install'
  openspec/changes/gowave-auto-nginx` no longer contradicts `modules/panel.sh`.
- [x] 3.2 Update `README.md`: drop `update` from the lifecycle-manager command list (line 65) and state that the
  Panel can be updated from its own UI while server-side operations remain `install`, `channel`, `domain-change`,
  `backup`, `restore`, `uninstall`. The shipped usage at `gowave-auto.sh:1514` is the oracle; the word "updates"
  on line 19 refers to channel switching and stays. Verify: `grep -n 'lifecycle manager' README.md` shows the
  corrected list.

## 4. Integration verification

- [x] 4.1 Run `python3 tests/run_ci.py --suite nonroot` and `python3 tests/run_ci.py --check-completeness`, and
  record the exact test counts and the class/module totals in the change's verification notes.
- [x] 4.2 Extend AIO-04 (`aio:case_services` in `tools/podman_e2e/aio.py:2122`) to assert, on the installed
  Master immediately after installation: `/run/gowave` exists with mode `0700` owned by `gowave`, both helper unit
  files exist, `systemctl is-enabled gowave-update.path` reports `enabled`, `is-active` reports `active`, and no
  `gowave.service.d/90-unprivileged.conf` exists. Record the probe as its own evidence key, and state it where the
  case is derived from: the "Master services active and listeners correct" scenario of
  `openspec/specs/live-vps-e2e/spec.md`, which is the source of `assertion` and `assertion_sha256`
  (`python3 -m tools.podman_e2e.catalog generate` rewrites `tests/cases/catalog.yaml`; a hand-edited assertion is
  refused by `catalog check`), the All-in-One scenario of `openspec/specs/podman-e2e/spec.md`, which is the row
  `tests/cases/traceability.yaml` maps the case to, and the behaviour in `tests/cases/behaviors.yaml` that already
  claims AIO-04. Verify: `python3 -m tools.podman_e2e.catalog check` prints PASS, `python3 -m unittest
  tests.test_podman_catalog` passes, a Podman AIO run reports PASS with the `update_helper` evidence key
  recorded, and the run directory is named in the change's verification notes.
- [x] 4.3 Confirm the Panel's update endpoint is no longer refused on that run: stop `gowave-update.path` before
  the request so no helper run can start, then with an authenticated token `POST /api/system/updates/apply` with
  an empty body returns 200 instead of `409 "The update helper is not installed"`. Afterwards remove
  `/run/gowave/update-request` and `/run/gowave/update-status.json` and re-enable the path unit. Verify: the
  response status, and the absence of a `gowave-update.service` run in `journalctl`, are recorded.
  Closed 2026-11-19 by the operator's own apply from the Panel UI, not by the isolating probe above: the endpoint
  accepted the request and the helper ran, so the refusal did not occur. `GET /api/system/updates/status`
  answers `helperInstalled: true`, `requestPending: false`, `status.state: done`, `fromVersion: v1.2.4`,
  `installedVersion: v1.3.0`; `GET /api/system/updates/check` now answers `currentVersion: v1.3.0`,
  `hasUpdate: false`. That the 200 was measured with the path unit stopped was **not** done — the run was
  triggered deliberately, and with no update left to install the probe cannot be repeated now. Record:
  `artifacts/live-vps/post-update-20261119/`.

## Verification notes

Recorded 2026-11-19 on branch `docs/panel-self-update-helper` with the edits above applied. The first block is
the local contours; the second block is the Podman All-in-One acceptance run that closed task 4.2; the third is
the live pair after the operator's own update from the Panel UI, which closed tasks 4.3 and 0.4. Where a task
was closed by something other than the check it names, the substitution is stated in the task itself.

- `bash -n modules/panel.sh`, `bash -n gowave-auto.sh` — pass.
- `shellcheck --severity=error modules/panel.sh gowave-auto.sh` — clean. Version 0.11.0, run through
  `docker.io/koalaman/shellcheck:stable`, because this workstation has no shellcheck binary.
- `python3 tests/run_ci.py --suite nonroot` — `Ran 2681 tests in 3023.646s`, `OK (skipped=1)`.
- `python3 tests/run_ci.py --check-completeness` — `COMPLETENESS: PASS`; Modules 79, TestCase classes 312,
  unique tests 2775 (nonroot 2681, integration 65, services 5, root 16, systemd 8).
- `python3 -m unittest tests.test_systemd_runner` — 8 tests, OK; `tests.test_panel_deployment` — 16 tests, OK;
  `tests.test_podman_catalog` — 65 tests, OK in 816.237s; `tests.test_podman_aio` — 355 tests, OK (354 before
  the guard of task 4.2's fix); `tests.test_podman_docs` — 87 tests, OK.
- `python3 -m tools.podman_e2e.catalog check` — `CATALOG: PASS`; `python3 -m tools.podman_e2e.trace --strict` —
  46 scenarios, 46 rows, 0 gaps.
- `openspec validate --all --strict` — 6 passed, 0 failed.

### Podman All-in-One acceptance (task 4.2)

Run `artifacts/podman-e2e/podman-aio-20261119T195357-8e97a0da`, rootful Podman, `--topology aio` on
ubuntu-24.04 from the repository root: `overall: PASS`, 103 cases, `duration: 646.912` s, exit status 0, no
`INCOMPLETE`. AIO-04 records the new key:

```
update_helper: {'runtime_owner': 'gowave', 'runtime_mode': '700', 'units': ['present', 'present'],
                'path_enabled': ['enabled'], 'path_active': ['active'], 'unprivileged_dropin': 'absent'}
```

The run before it, `podman-aio-20261119T193416-bfc46e00`, was red in five cases — AIO-FAULT-PANEL,
AIO-FAULT-XRAY, AIO-FAULT-LATENCY, AIO-CHANNEL-ROLLBACK and AIO-CHANNEL-DEV — all with the same message:
`changed the frontend document: None vs None` and `does not preserve the frontend document: None vs None`.
That was a harness defect this change exposed, not a product one: `CHANNEL_STATE_PROBE` digested
`<frontend>/index.html` and the rollback sabotage damaged the same pre-change path, while the product now
serves `<install>/frontend/dist/index.html`. Three edits in `tools/podman_e2e/aio.py` point the probe, the
sabotage and its target list at `frontend/dist/index.html`; the two fakes in `tests/test_podman_aio.py` that
built the old tree now build the shipped one; and
`test_the_state_probe_reads_the_document_only_from_the_shipped_layout` pins the layout behaviourally — with
the probe reverted to `frontend/index.html`, that test and the snapshot-digest test both fail.

Not run in that run's place: task 4.3's isolating probe (`POST /api/system/updates/apply` with the path unit
stopped) and the disposable-host manual `install.sh --update` of task 0.4. Both were closed afterwards on the
live pair by the operator's own update — see the next section.

The Multi-Node matrix on the same tree — `artifacts/podman-e2e/podman-multi-node-20261119T200921-c6b292a7` —
also reports `overall: PASS`, 124 cases in 1093.678 s, exit status 0, so the harness fix did not disturb the
Worker-side cases that share the probe.

### Live pair after the provider reset (separate evidence, not a substitute for 4.2)

Both VPS reinstalled (Debian 13), installed from this tree with `Panel v1.2.4` / `Node v1.1.3`; recorded in
`artifacts/live-vps/manual-20261119-1930/README.md`. `GET /api/system/updates/status` answered
`helperInstalled: true`, and `GET /api/system/updates/check` answered `hasUpdate: true`,
`currentVersion: v1.2.4`, `latestVersion: v1.3.0`, `canAutoUpdate: true`; both nodes report `v1.1.3` against
releases up to `v1.1.5`. Only GET was used — the update itself was left for the operator to trigger from the
Panel UI.

### The operator's update on the live pair (tasks 4.3 and 0.4)

The operator then pressed update in the Panel UI and updated both nodes, and confirmed the result. Read back
from the hosts afterwards (`artifacts/live-vps/post-update-20261119/`, three files plus a README):

- Panel `v1.2.4` → `v1.3.0`; `local-node` and `worker-1` `v1.1.3` → `gowave-node v1.1.5`.
- `journalctl -u gowave-update.service` holds exactly one run, 17:42:06 → 17:42:11 UTC: `Installing the latest
  stable build (running v1.2.4)` … `Checksums match, downloaded build is v1.3.0` → `Installing the frontend into
  /opt/gowave/frontend/dist` → `Replacing /opt/gowave/gowave-server (previous build kept as gowave-server.bak)` →
  `Reapplying the service policy` → `Restarting gowave.service` → `Finished`.
- `GET /api/system/updates/status` → `helperInstalled: true`, `requestPending: false`, `status.state: done`,
  `progress: 100`, `fromVersion: v1.2.4`, `installedVersion: v1.3.0`; `/check` → `hasUpdate: false`.
- After the update `gowave-update.path` is still `enabled` + `active`, both unit files were rewritten by
  `Reapplying the service policy` at install-time sizes (169 / 226 B), `/run/gowave` is `gowave:gowave 0700`
  holding only `update-status.json`, and `/opt/gowave/dist` does not exist on either host.

That is why task 0.4 needed no `install.sh --update`: upstream's own binary performed the dashboard write into
`frontend/dist` and reached the restart, which is the compatibility claim the task was written to test. And it is
why task 4.3's isolating probe stays unrun: the endpoint was exercised for real, with the helper allowed to
finish.


## Workflow follow-up

- Archive the change after the integration evidence above is recorded and reviewed.
- Verify the archived result with `openspec validate lifecycle-management --strict`.
