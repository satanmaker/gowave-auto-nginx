# Proposal

## Why

A host installed by `gowave-auto.sh` has no in-panel update: `/etc/systemd/system/gowave-update.path` and
`gowave-update.service` are written only by the upstream `gowave-server service install`, which this project
deliberately never calls, so the Panel's `POST /api/system/update` answers `409` and tells the operator to run
the upstream `install.sh --update` — a floating `main` script this project does not run and whose side effects
(its own `service install`, update units and sandbox drop-in) are outside the installer's ownership contract.
The operator therefore loses the standard way to update the Panel from the UI, and the only remedy the product
offers is one the project bans. Both units are small, root-only and independent of NGINX, certificates and the
Panel's unit: installing them ourselves restores the standard path without adopting anything else upstream.

## What Changes

- `gowave.service` gains `RuntimeDirectory=gowave`, `RuntimeDirectoryMode=0700` and
  `RuntimeDirectoryPreserve=yes`, so systemd creates `/run/gowave` for the unprivileged Panel and the Panel can
  write its `update-request` file there.
- The installer writes and enables `gowave-update.service` (root oneshot running
  `<install-dir>/gowave-server update apply <install-dir>`) and `gowave-update.path`
  (`PathExists=/run/gowave/update-request`), i.e. the same trigger contract the upstream helper uses, under
  this project's ownership.
- `gowave-auto.sh uninstall` stops, disables and removes both units together with the other managed units.
- The lifecycle-management spec stops claiming that `gowave-server service install` registers the Panel; it
  states that the project writes the base unit itself and installs the update helper explicitly.
- Static systemd contract tests pin the three unit fragments and the uninstall removal list, and assert that
  `modules/panel.sh` still does not invoke `gowave-server service install`.

Out of scope: a `gowave-auto.sh update` subcommand; executing the upstream `install.sh` at any point; the
upstream `90-unprivileged.conf` sandbox drop-in (a separate decision — this change neither adds nor claims it);
changes to the upstream `update apply` implementation.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `lifecycle-management`: the Panel's service ownership requirement now covers the in-panel self-update helper
  (runtime directory, the two update units, uninstall ownership) and no longer asserts that the upstream
  `service install` command registers the Panel.

## Impact

- `modules/panel.sh` — `configure_panel_systemd` (base unit template plus two new unit files and their enable
  list).
- `gowave-auto.sh` — `cmd_uninstall` unit stop/disable/removal lists.
- `tests/test_systemd_runner.py` — static contract assertions on the emitted units and the uninstall list.
- `openspec/specs/lifecycle-management/spec.md` — the modified requirement and its scenarios.
- Operators: the Panel's own update endpoint starts working after a reinstall; no new ports, no new packages,
  no NGINX or certificate changes.
