# Tasks

## 0. Upstream-compatible dashboard layout

- [ ] 0.1 Extract the dashboard into `<install-dir>/frontend/dist` through a staging rename and stop creating
  `<install-dir>/dist` in `download_panel_release` (`modules/panel.sh`); the release archive holds the files at its
  root (`release.yml:45`), so the old extraction left them in `frontend/` and only the symlink made them reachable.
  Verify: `bash -n modules/panel.sh`, `grep -c 'ln -sfn' modules/panel.sh` returns 0.
- [ ] 0.2 Remove a legacy `<install-dir>/dist` symlink on reinstall, and leave the path alone when it is a real
  directory or a regular file. Verify: a test in `tests/test_panel_deployment.py` covers the migration with a
  pre-created symlink and a pre-created directory.
- [ ] 0.3 Make the release fixture in `tests/test_panel_deployment.py` pack the dashboard the way
  `.github/workflows/release.yml:45` does (`tar -czf ... -C dist .`), assert `frontend/dist/index.html`, and assert
  that `<install-dir>/dist` does not exist. Verify: `python3 tests/test_panel_deployment.py` passes, and the same
  test against the pre-change `panel.sh` fails on the `frontend/dist` assertion.
- [ ] 0.4 Prove the layout on a real host: reinstall on the disposable VM, then run the upstream
  `install.sh --update` and confirm it reaches the restart instead of `Refusing a symlinked /opt/gowave/dist`.
  Verify: the command's exit status and the panel's `wait_healthy` line in the log are recorded here.

## 1. Unit templates and the runtime directory

- [ ] 1.1 Add `RuntimeDirectory=gowave`, `RuntimeDirectoryMode=0700` and `RuntimeDirectoryPreserve=yes` to the
  base unit template in `configure_panel_systemd` (`modules/panel.sh`). Verify: `bash -n modules/panel.sh`, and
  `grep -c 'RuntimeDirectory=gowave' modules/panel.sh` returns exactly 1 (a second copy means the template was
  edited in the wrong place).
- [ ] 1.2 Write `/etc/systemd/system/gowave-update.service`
  (`ExecStart=<install-dir>/gowave-server update apply <install-dir>`, `Type=oneshot`, `TimeoutStartSec=15min`,
  no `User=`) and `/etc/systemd/system/gowave-update.path`
  (`PathExists=/run/gowave/update-request`, `Unit=gowave-update.service`, `WantedBy=multi-user.target`) from
  templates inside `configure_panel_systemd`, and add `gowave-update.path` to the enable list. Verify:
  `bash -n modules/panel.sh`, `shellcheck --severity=error modules/panel.sh` (report "not run" if the binary is
  absent), and `grep -c 'gowave-update' modules/panel.sh` equals the expected count for the two templates plus
  the enable entry.
- [ ] 1.3 Extend `tests/test_systemd_runner.py::TestSystemdRunner` with assertions that `modules/panel.sh`
  emits the three `RuntimeDirectory*` directives, both helper unit fragments, the `gowave-update.path` enable
  entry, and contains no `service install` invocation. Verify: `python3 -m unittest -v tests.test_systemd_runner`
  passes, and a temporary removal of one fragment turns the new test red.

## 2. Install ordering and uninstall ownership

- [ ] 2.1 Start `gowave-update.path` immediately after the existing `systemctl restart gowave.service` in
  `cmd_install` (`gowave-auto.sh:437-439`), so `/run/gowave` exists before the watch is armed. Verify: read the
  edited block, `bash -n gowave-auto.sh`, and a static test asserting the start line follows the restart line in
  the file.
- [ ] 2.2 Add `gowave-update.path` and `gowave-update.service` to the `cmd_uninstall` stop, disable and removal
  lists, keeping a single `daemon-reload`. Verify: `bash -n gowave-auto.sh` and a test asserting both names appear
  in all three lists.

## 3. Specification and operator documentation

- [ ] 3.1 Correct the stale claim that `gowave-server service install` registers the Panel and produces
  `90-unprivileged.conf` in `openspec/changes/gowave-auto-nginx/specs/lifecycle-management/spec.md` (requirement
  "External Proxy Mode and Service Ownership"), `RISKS_AND_OPEN_QUESTIONS.md` RES-14 and `tasks.md` 4.4, so they
  describe the shipped behaviour plus the new helper. Verify: `openspec validate gowave-auto-nginx --strict`
  passes and `grep -rn 'service install' openspec/changes/gowave-auto-nginx` no longer contradicts
  `modules/panel.sh`.
- [ ] 3.2 Update `README.md`: drop `update` from the lifecycle-manager command list and state that the Panel can
  be updated from its own UI while server-side operations remain `install`, `channel`, `domain-change`, `backup`,
  `restore`, `uninstall`. Verify: `grep -n 'lifecycle manager' README.md` shows the corrected list.

## 4. Integration verification

- [ ] 4.1 Run `python3 tests/run_ci.py --suite nonroot` and `python3 tests/run_ci.py --check-completeness`, and
  record the exact test counts and the class/module totals in the change's verification notes.
- [ ] 4.2 Extend the existing All-in-One service-verification case in the Podman E2E suite to assert, on the
  installed Master: `/run/gowave` exists with mode `0700` owned by `gowave`, both helper unit files exist,
  `systemctl is-enabled gowave-update.path` reports `enabled`, `is-active` reports `active`, and no
  `gowave.service.d/90-unprivileged.conf` exists. Verify: a Podman AIO run reports PASS with those evidence keys
  recorded, and the run directory is named in the change's verification notes.
- [ ] 4.3 Confirm the Panel's update endpoint is no longer refused on that run: with an authenticated token,
  `POST /api/system/system/update` with an empty body does not return `409 "The update helper is not installed"`.
  Do not let the helper complete a real release download in the run — stop `gowave-update.path` and remove
  `/run/gowave/update-request` after the status is observed.

## Workflow follow-up

- Archive the change after the integration evidence above is recorded and reviewed.
- Verify the archived result with `openspec validate lifecycle-management --strict`.
