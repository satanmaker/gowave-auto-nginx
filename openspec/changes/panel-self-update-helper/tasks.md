# Tasks

## 0. Upstream-compatible dashboard layout

- [ ] 0.1 Extract the dashboard into `<install-dir>/frontend/dist` through a staging rename and stop creating
  `<install-dir>/dist` in `download_panel_release` (`modules/panel.sh`); the release archive holds the files at its
  root (`sources/gowave/.github/workflows/release.yml:45`), so the old extraction left them in `frontend/` and
  only the symlink made them reachable.
  Verify: `bash -n modules/panel.sh`, `grep -c 'ln -sfn' modules/panel.sh` returns 0.
- [ ] 0.2 Remove a legacy `<install-dir>/dist` symlink on reinstall, and leave the path alone when it is a real
  directory or a regular file. Verify: a test in `tests/test_panel_deployment.py` covers the migration with a
  pre-created symlink and a pre-created directory.
- [ ] 0.3 Repack the release fixture in `tests/test_panel_deployment.py` the way
  `sources/gowave/.github/workflows/release.yml:45` does (`tar -czf ... -C dist .`, files at the archive root),
  then assert `frontend/dist/index.html` and that `<install-dir>/dist` does not exist. The current fixture adds
  `dist/` inside the tar (`tests/test_panel_deployment.py:323-329`), so the existing assertion also passes under
  the old symlinked layout. Verify: after repacking, the same test against the pre-change `panel.sh` fails on the
  `frontend/dist` assertion; with the change it passes (`python3 tests/test_panel_deployment.py`).
- [ ] 0.4 Prove the layout on a real host: reinstall on a disposable host, then run the upstream
  `install.sh --update` manually (no product script invokes it) and confirm it reaches the restart instead of
  `Refusing a symlinked /opt/gowave/dist`. Verify: the command's exit status, the absence of the refusal line and
  the panel's `wait_healthy` line in the log are recorded here.

## 1. Unit templates and the runtime directory

- [ ] 1.1 Add `RuntimeDirectory=gowave`, `RuntimeDirectoryMode=0700` and `RuntimeDirectoryPreserve=yes` to the
  base unit template in `configure_panel_systemd` (`modules/panel.sh`). Verify: `bash -n modules/panel.sh`, and
  `grep -c 'RuntimeDirectory=gowave' modules/panel.sh` returns exactly 1 (a second copy means the template was
  edited in the wrong place).
- [ ] 1.2 Write `/etc/systemd/system/gowave-update.service`
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
- [ ] 1.3 Extend `tests/test_systemd_runner.py::TestSystemdRunner` with assertions that `modules/panel.sh`
  emits the three `RuntimeDirectory*` directives, both helper unit fragments, the `gowave-update.path` enable
  entry, and contains no `service install` invocation. Verify: `python3 -m unittest -v tests.test_systemd_runner`
  passes, and a temporary removal of one fragment turns the new test red.

## 2. Install ordering and uninstall ownership

- [ ] 2.1 Start `gowave-update.path` immediately after the existing `systemctl restart gowave.service` in
  `cmd_install` (`gowave-auto.sh:437-438`), so `/run/gowave` exists before the watch is armed. Verify: read the
  edited block, `bash -n gowave-auto.sh`, and a static test asserting the start line follows the restart line in
  the file.
- [ ] 2.2 Add `gowave-update.path` and `gowave-update.service` to the `cmd_uninstall` stop, disable and removal
  lists, keeping a single `daemon-reload`. Verify: `bash -n gowave-auto.sh` and a test asserting both names appear
  in all three lists.

## 3. Specification and operator documentation

- [ ] 3.1 Correct the stale claim that `gowave-server service install` registers the Panel and produces
  `90-unprivileged.conf` in `openspec/changes/gowave-auto-nginx/specs/lifecycle-management/spec.md` (requirement
  "External Proxy Mode and Service Ownership"), `openspec/changes/gowave-auto-nginx/RISKS_AND_OPEN_QUESTIONS.md`
  RES-14 and `openspec/changes/gowave-auto-nginx/tasks.md` 4.4 (which also claims the native command generates
  `gowave-update.path`), so they describe the shipped behaviour: the project writes the base unit and both helper
  units, and the upstream helper reapplies the drop-in and the helper units on each in-panel update. Verify:
  `openspec validate gowave-auto-nginx --strict` passes and `grep -rn 'service install'
  openspec/changes/gowave-auto-nginx` no longer contradicts `modules/panel.sh`.
- [ ] 3.2 Update `README.md`: drop `update` from the lifecycle-manager command list (line 65) and state that the
  Panel can be updated from its own UI while server-side operations remain `install`, `channel`, `domain-change`,
  `backup`, `restore`, `uninstall`. The shipped usage at `gowave-auto.sh:1514` is the oracle; the word "updates"
  on line 19 refers to channel switching and stays. Verify: `grep -n 'lifecycle manager' README.md` shows the
  corrected list.

## 4. Integration verification

- [ ] 4.1 Run `python3 tests/run_ci.py --suite nonroot` and `python3 tests/run_ci.py --check-completeness`, and
  record the exact test counts and the class/module totals in the change's verification notes.
- [ ] 4.2 Extend AIO-04 (`aio:case_services` in `tools/podman_e2e/aio.py:2122`) to assert, on the installed
  Master immediately after installation: `/run/gowave` exists with mode `0700` owned by `gowave`, both helper unit
  files exist, `systemctl is-enabled gowave-update.path` reports `enabled`, `is-active` reports `active`, and no
  `gowave.service.d/90-unprivileged.conf` exists. Record the probe as its own evidence key, and update the case's
  assertion text and `assertion_sha256` in `tests/cases/catalog.yaml`, together with `tests/cases/behaviors.yaml`
  and `tests/cases/traceability.yaml`. Verify: `python3 -m unittest tests.test_podman_catalog` passes, a Podman
  AIO run reports PASS with those evidence keys recorded, and the run directory is named in the change's
  verification notes.
- [ ] 4.3 Confirm the Panel's update endpoint is no longer refused on that run: stop `gowave-update.path` before
  the request so no helper run can start, then with an authenticated token `POST /api/system/updates/apply` with
  an empty body returns 200 instead of `409 "The update helper is not installed"`. Afterwards remove
  `/run/gowave/update-request` and `/run/gowave/update-status.json` and re-enable the path unit. Verify: the
  response status, and the absence of a `gowave-update.service` run in `journalctl`, are recorded.

## Workflow follow-up

- Archive the change after the integration evidence above is recorded and reviewed.
- Verify the archived result with `openspec validate lifecycle-management --strict`.
