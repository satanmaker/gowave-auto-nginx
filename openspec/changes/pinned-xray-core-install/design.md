# Design

## Context

See `proposal.md` — Why. The constraints that shape the approach:

- Upstream `install.sh` owns the node: it writes the binary, the unit and `.env`, and installs the core only when neither `"$install_dir/rw-core"` nor `"$prefix/bin/rw-core"` is executable (`sources/gowave-node/install.sh:517-519`). It creates `install_dir` with `mkdir -p` (`:247`) and never wipes it, so a file placed there before the run survives.
- `gowave-node core install` spends a `api.github.com` request before it reads `--version`: `FetchReleases` runs first in `internal/cli/update.go:38`, and the release lookup itself is `api.github.com` (`internal/updater/releases.go:34`). The existing `ensure_pinned_xray_core` (`modules/node.sh:48-79`, `gowave-node-auto.sh:4889`) therefore cannot remove the dependency — it is a second caller of the same API path.
- The two installation paths differ: `install_local_node` runs the pinned installer or, when `GOWAVE_NODE_REQUIRE_PINNED_INSTALLER` is not `1`, the floating `main` installer (`modules/node.sh:318-331`); the Podman contour currently takes the floating branch. The Worker path is `run_upstream_node_installer` (`gowave-node-auto.sh:4976`), which then calls `run_node_installer_with_retry` (`:5007`).
- The Podman contour already passes the matrix pin as `XRAY_SERVER_VERSION` (`tools/podman_e2e/topology.py:1068`, `tests/cases/matrix.yaml:26`), so a mismatched post-install pin currently spends a second API request.
- `python3` is present on both contours before the installer runs: `setup_system_prereqs` installs it (`gowave-node-auto.sh:4224`) ahead of the install call (`:5347`), and `bootstrap_early_tools` runs earlier still.
- CI cannot inject a token: `tests/test_ci_isolation.py:64` forbids workflow secrets and every workflow is `contents: read`. Upstream source is not modified (AGENTS.md, "No Upstream Source Modifications").

## Goals / Non-Goals

**Goals:**

- Node installation performs no `api.github.com` request on the default path, on both the Master-local and Worker contours.
- The installed core is a named, digest-verified release, and the product and the acceptance matrix name the same bytes.
- A failing pin is reported as a located failure, not absorbed into a lottery.

**Non-Goals:**

- Making `github.com` itself reachable, or mirroring the release asset.
- Removing the Panel's own API fallback (`modules/panel.sh:137`) or the node's runtime update path (`update.go:230`).
- Executing the arm64 pin.
- Introducing a systemd unit or watchdog for Xray; `gowave-node` remains the only supervisor.

## Decisions

### D1. One meaning per `XRAY_SERVER_VERSION` value

Unset or empty installs the pin. `latest` delegates the core to upstream — the explicit opt-out. Any other value goes to upstream plus the existing explicit-version path.

Alternative: keep `latest`/unset as "keep what upstream brought" and only pin when the value equals the pin. Rejected: the default install would still spend the API request, so the operator the fix targets would still fail, and only CI would be repaired.

### D2. Place the file, do not ask for a version

The step installs `<install_dir>/rw-core` before the installer runs, which makes upstream skip its own core installation.

Alternatives: `core install --version` (still `FetchReleases` first, `update.go:38`); an upstream offline switch (does not exist); vendoring the binary in the repository (a 30 MB blob, and the release digest is already the authority).

### D3. Insertion points cover both branches

- `modules/node.sh`: inside `if (( node_restart_required == 1 ))` (`:294`), before both installer invocations. Placing it after the branch, or only before `run_node_installer_with_retry`, would miss the floating `main` branch that the Podman contour uses, so the acceptance proof would not exercise the change.
- `gowave-node-auto.sh::run_upstream_node_installer`: before `run_node_installer_with_retry` (`:5007`).

Inside the restart branch rather than unconditionally, because replacing the core under a serving node leaves the binary on disk ahead of the running process: today `ensure_pinned_xray_core` (`modules/node.sh:338`) runs even when `node_restart_required` is `0` and the restart at `:355` does not happen.

### D4. Idempotency on version, not on existence

The step is a no-op only when `rw-core version` contains the pinned version; otherwise it replaces the file. Upstream's own check is only `-x` (`install.sh:517`), so accepting a foreign core would let one stale file block both the pin and every upstream upgrade.

### D5. A hard failure on the pinned path

Undelivered or unverified artifact ⇒ installation stops with the artifact, the expected digest and the pinned version named, plus `XRAY_SERVER_VERSION=latest` as the way out. No handover to upstream's `core install`.

Alternative: the warn-and-delegate behaviour the requirements draft asked for. Rejected: the handover is precisely the API request being removed, so it re-creates the lottery while appearing to succeed, and it makes a green acceptance run ambiguous.

### D6. Two physical copies of the function and table

The Worker payload is a single file streamed over SSH and cannot source `modules/`. `ensure_pinned_xray_core` already exists twice for the same reason. The table therefore lives in `modules/xray_core.sh` and is duplicated in `gowave-node-auto.sh`, with a guard test that reads both copies and `tests/cases/matrix.yaml` and fails when the version or digest differs. Edits to either copy are counted (`grep -c`) before rewriting (AGENTS.md §3.7), because the payload contains sibling copies of surrounding functions.

### D7. Verification and extraction

`fetch_verified_artifact` (`modules/artifact.sh:18`) owns the download, the single-attempt-per-host digest rule and the `tmp` + `sync` + `mv` install; the step reuses it. The zip is unpacked with `python3 -m zipfile`-equivalent code (member `xray`), because `python3` is already guaranteed on both contours and no `zipfile` extraction exists in `modules/` yet. The extracted binary is executed as `version` from a temporary path before the rename, so a wrong architecture or a corrupt member fails before anything lands at `rw-core`.

### D8. No `rw-core.stock`

`IsCustomCore` (`internal/updater/artifacts.go:321-330`) compares against `.stock` only when it exists, so a placed core without one is not classified as custom; the only consequence is that `core reset` answers `no managed stock core is available` (`:302`) until a later managed install backs the file up. Writing `.stock` ourselves would claim a previous state this repository did not observe, so the refusal is the honest outcome and is documented.

### D9. `ensure_pinned_xray_core` stays, narrowed by the new semantics

It keeps serving the explicit non-pin version path, where an API request is the operator's deliberate choice. After this change it is a no-op on the default path, because the version already matches. Removing it would drop that path's only mechanism.

### D10. Evidence is a blocked-API run plus its own control

The acceptance probe blocks `api.github.com` inside the container (`/etc/hosts` rewriting already exists at `tools/podman_e2e/aio.py:754,1113`), requires a green installation, and reads the digest and `version` of `/opt/gowave-node/rw-core` from inside the node container. The control run sets `XRAY_SERVER_VERSION=latest` on the same blocked contour and must fail. Without the control, a green run proves only that the installer did not happen to need the API, not that it cannot need it. The probe is added to an existing install case, not a new case, so the scripted-Podman and suite-length guards stay satisfied.

## Risks / Trade-offs

- [Hard failure where the host cannot reach the release asset] → the message names `XRAY_SERVER_VERSION=latest`, the `--help` text and the node-installation docs describe the opt-out, and the opt-out restores today's behaviour exactly.
- [Two table copies drift] → a guard test compares both copies with `tests/cases/matrix.yaml`; a drift fails the nonroot suite rather than a CI run.
- [Replacing the core while the node serves] → the step only runs where the installer runs, and the service restart follows in the same branch.
- [arm64 pin never executed] → the digest is confirmed against the published `.dgst`, and the evidence states the arm64 claim as unverified rather than passing.
- [Pin ages against `GOWAVE_NODE_VERSION=latest`] → the pin lives in one table, is changed together with `matrix.yaml` and the env example, and the guard test makes a partial update impossible.
- [The step's failure happens after the Panel already serves] → it runs before the node's own installation, so the failing run leaves no half-configured node; the rollback path is the installer's existing one.

## Migration Plan

No data migration. Existing hosts keep their running core: the step is a no-op when the version matches and is only reached on an installation that restarts the node. Rollback is reverting the pre-placement; a host that already has the pinned core continues to work, and `XRAY_SERVER_VERSION=latest` avoids the step entirely while the change is in place.

## Open Questions

- Whether `gowave-node core reset` should ever become available on a host that has never had a managed install is left as it is; revisit only if an operator reports the refusal as a loss.
