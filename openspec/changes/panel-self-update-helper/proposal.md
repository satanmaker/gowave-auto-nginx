# Proposal

## Why

A host installed by `gowave-auto.sh` has no in-panel update: `/etc/systemd/system/gowave-update.path` and
`gowave-update.service` are written only by the upstream `gowave-server service install`, which this project
deliberately never calls, so the Panel's `POST /api/system/updates/apply` answers `409` and tells the operator to run
the upstream `install.sh --update` — a floating `main` script this project does not run and whose side effects
(its own `service install`, update units and sandbox drop-in) are outside the installer's ownership contract.
The operator therefore loses the standard way to update the Panel from the UI, and the only remedy the product
offers is one the project bans. Both units are small, root-only and independent of NGINX, certificates and the
Panel's unit: installing them ourselves restores the standard path without adopting anything else upstream.

The units alone are not enough. On 2026-11-17 the native `install.sh --update --stable` aborted on a host installed
by this project with `Refusing a symlinked /opt/gowave/dist`: `modules/panel.sh` extracts the dashboard into
`frontend/` and compensates with `dist -> frontend`, while the upstream service policy refuses a symlinked
`gowave-server`, `frontend`, `dist` or `static`. `update apply` runs the same policy check before restarting, so an
in-panel update would fail the same way even with both units installed. The dashboard must therefore be installed
in the upstream layout, `frontend/dist`, which also removes the need for the symlink.

## What Changes

- `download_panel_release` extracts the dashboard archive into `<install-dir>/frontend/dist` (the layout the
  release archive and the Panel's static lookup expect), stops creating the `dist -> frontend` symlink, and
  removes that symlink from a host installed by an earlier version.
- `gowave.service` gains `RuntimeDirectory=gowave`, `RuntimeDirectoryMode=0700` and
  `RuntimeDirectoryPreserve=yes`, so systemd creates `/run/gowave` for the unprivileged Panel and the Panel can
  write its `update-request` file there.
- The installer writes `gowave-update.service` (root oneshot running
  `<install-dir>/gowave-server update apply <install-dir>`) and `gowave-update.path`
  (`PathExists=/run/gowave/update-request`), and enables and starts the path unit, i.e. the same trigger contract
  the upstream helper uses, under this project's ownership. The helper itself is the upstream binary: every run
  reapplies the upstream service policy (`gowave.service.d/90-unprivileged.conf`) and rewrites both helper units,
  which this change accepts instead of reimplementing.
- `gowave-auto.sh uninstall` stops, disables and removes both units together with the other managed units.
- The stale claim that `gowave-server service install` registers the Panel is corrected in the unarchived
  `gowave-auto-nginx` change (`specs/lifecycle-management/spec.md`, `RISKS_AND_OPEN_QUESTIONS.md` RES-14 and
  `tasks.md` 4.4), not in the archived main spec, which never made it. The lifecycle-management delta states the
  shipped behaviour: the project writes the base unit itself and installs the update helper explicitly.
- Static systemd contract tests pin the runtime-directory directives, both helper unit fragments, the install
  ordering and the uninstall removal lists, and assert that `modules/panel.sh` still does not invoke
  `gowave-server service install`.

Out of scope: a `gowave-auto.sh update` subcommand; invoking the upstream `install.sh` from any script or product
path (a manual layout verification on a disposable host is allowed); pinning or extending the
`90-unprivileged.conf` sandbox beyond what the upstream helper itself reapplies on every in-panel update — the
installer does not write that drop-in; changes to the upstream `update apply` implementation.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `lifecycle-management`: three added requirements covering the dashboard layout the updater accepts, the
  project-owned helper units and runtime directory, and what an in-panel update is allowed to change. The stale
  claim that the upstream `service install` command registers the Panel is not in the archived main spec; it is
  corrected in the `gowave-auto-nginx` change, which has not been archived yet.

## Impact

- `modules/panel.sh` — `download_panel_release` (dashboard layout, legacy symlink removal) and
  `configure_panel_systemd` (base unit template plus two new unit files and their enable list).
- `gowave-auto.sh` — `cmd_install` (start the path unit after the Panel restart) and `cmd_uninstall` unit
  stop/disable/removal lists.
- `tests/test_systemd_runner.py` — static contract assertions on the emitted units, the install ordering and the
  uninstall lists.
- `tests/test_panel_deployment.py` — the release fixture now packs the dashboard the way
  `sources/gowave/.github/workflows/release.yml:45` does, and the install assertions pin `frontend/dist`, the
  legacy-symlink migration and the absence of a `dist` path.
- `openspec/changes/gowave-auto-nginx/specs/lifecycle-management/spec.md`, its `RISKS_AND_OPEN_QUESTIONS.md`
  (RES-14) and its `tasks.md` 4.4 — correction of the stale `service install` claim.
- `README.md` — the lifecycle-manager command list loses `update`, which the shipped usage
  (`gowave-auto.sh:1514`) does not offer.
- `tests/cases/catalog.yaml` (AIO-04 assertion and `assertion_sha256`), `tests/cases/behaviors.yaml`,
  `tests/cases/traceability.yaml` and `tools/podman_e2e/aio.py` — the extended Podman evidence for the helper.
- Operators: the Panel's own update endpoint starts working after a reinstall, and the upstream `--update` path
  stops aborting on the install layout; no new ports, no new packages, no NGINX or certificate changes.
