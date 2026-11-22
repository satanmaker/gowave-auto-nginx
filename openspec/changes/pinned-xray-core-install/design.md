# Design

## Context

See `proposal.md` — Why. The constraints that shape the approach:

- Upstream `install.sh` owns the node: it writes the binary, the unit and `.env`, and installs the core only when neither `"$install_dir/rw-core"` nor `"$prefix/bin/rw-core"` is executable (`sources/gowave-node/install.sh:517-519`). It creates `install_dir` with `mkdir -p` (`:247`) and never wipes it, so a file placed there before the run survives.
- `gowave-node core install` spends a `api.github.com` request before it reads `--version`: `FetchReleases` runs first in `internal/cli/update.go:38`, and the release lookup itself is `api.github.com` (`internal/updater/releases.go:34`). The existing `ensure_pinned_xray_core` (`modules/node.sh:48-79`, `gowave-node-auto.sh:4889`) therefore cannot remove the dependency — it is a second caller of the same API path.
- The two installation paths differ: `install_local_node` runs the pinned installer or, when `GOWAVE_NODE_REQUIRE_PINNED_INSTALLER` is not `1`, the floating `main` installer (`modules/node.sh:318-331`); the Podman contour currently takes the floating branch. The Worker path is `run_upstream_node_installer` (`gowave-node-auto.sh:4976`), which then calls `run_node_installer_with_retry` (`:5007`).
- The Podman contour passes the matrix pin as `XRAY_SERVER_VERSION` (`tools/podman_e2e/topology.py:1068`, `tests/cases/matrix.yaml:26`), and the Worker receives that value from the Master's environment (`gowave-auto.sh:1156` → `gowave-node-auto.sh:2147`). The value the step sees on the acceptance contour is therefore the pin itself, not an empty string, which is why D1 has to classify it as "install the pin".
- `python3` is present on both contours before the installer runs: `setup_system_prereqs` installs it (`gowave-node-auto.sh:4224`) ahead of the install call (`:5347`), and `bootstrap_early_tools` runs earlier still.
- CI cannot inject a token: `tests/test_ci_isolation.py:64` forbids workflow secrets and every workflow is `contents: read`. Upstream source is not modified (AGENTS.md, "No Upstream Source Modifications").

## Goals / Non-Goals

**Goals:**

- Node installation performs no `api.github.com` request on the default path, on both the Master-local and Worker contours.
- The installed core is a named, digest-verified release, and the product and the acceptance matrix name the same bytes.
- A failing pin is reported as a located failure, not absorbed into a lottery.

**Non-Goals:**

- Making `github.com` itself reachable, or mirroring the release asset. The Xray zip and the geodata files still come from `github.com` release paths (`internal/updater/updater.go:407`), which costs no API quota but is a network dependency this change does not remove; it is named in the node-installation documentation rather than solved here.
- Pinning `GOWAVE_PANEL_VERSION` or `GOWAVE_NODE_VERSION`: those are the product's own releases, not a third-party engine, and they stay on their release channel (requirements §5.2). `XRAY_SERVER_VERSION` is the only component whose value this change redefines.
- Removing the Panel's own API fallback (`modules/panel.sh:137`) or the node's runtime update path (`update.go:230`).
- Executing the arm64 pin, or a live VPS run (requirements §6.4). Both are named as unrun in the evidence rather than claimed.
- Moving the Podman acceptance contour onto the pinned installer branch (`GOWAVE_NODE_REQUIRE_PINNED_INSTALLER`): requirements §7.4 leaves that as a separate decision, and this change covers the floating branch instead.
- Introducing a systemd unit or watchdog for Xray; `gowave-node` remains the only supervisor.

## Decisions

### D1. One meaning per `XRAY_SERVER_VERSION` value

Unset or empty installs the pin. A value naming the pin itself — `26.11.9` or `v26.11.9` — installs the same pin, because that is the value an operator copies from the documentation and the value the acceptance matrix injects (`tests/cases/matrix.yaml:26` → `tools/podman_e2e/topology.py:1068`). `latest` delegates the core to upstream — the explicit opt-out. Any other value goes to upstream plus the existing explicit-version path.

The equal-to-pin case is not a detail: with it classified as "any other value", the step would abstain on exactly the two contours the acceptance proof runs on, upstream would run `core install`, and the blocked-API run would fail on the change that was supposed to fix it. Requirements §4.6 draws the same line ("задан и не равен пину").

Alternative: keep `latest`/unset as "keep what upstream brought" and only pin when the value equals the pin. Rejected: the default install would still spend the API request, so the operator the fix targets would still fail, and only CI would be repaired.

### D2. Place the file, do not ask for a version

The step installs `<install_dir>/rw-core` before the installer runs, which makes upstream skip its own core installation.

Alternatives: `core install --version` (still `FetchReleases` first, `update.go:38`); an upstream offline switch (does not exist); vendoring the binary in the repository (a 30 MB blob, and the release digest is already the authority).

### D3. Insertion points cover both branches

- `modules/node.sh`: inside `if (( node_restart_required == 1 ))` (`:294`), before both installer invocations. Placing it after the branch, or only before `run_node_installer_with_retry`, would miss the floating `main` branch that the Podman contour uses, so the acceptance proof would not exercise the change.
- `gowave-node-auto.sh::run_upstream_node_installer`: before `run_node_installer_with_retry` (`:5007`).

Inside the restart branch rather than unconditionally, because replacing the core under a serving node leaves the binary on disk ahead of the running process: today `ensure_pinned_xray_core` (`modules/node.sh:338`) runs even when `node_restart_required` is `0` and the restart at `:346-347` does not happen.

### D4. Idempotency on version, not on existence

The step is a no-op only when `rw-core version` reports the pinned version as a token; otherwise it replaces the file. Upstream's own check is only `-x` (`install.sh:517`), so accepting a foreign core would let one stale file block both the pin and every upstream upgrade.

This knowingly narrows requirements §4.5, which makes an already executable `rw-core` a no-op: with that rule a host carrying any other core never receives the pin and never receives an upgrade through this path either, and the acceptance run cannot tell "the pin is installed" from "something executable was already there".

### D5. A hard failure on the pinned path

Undelivered or unverified artifact ⇒ installation stops with the artifact, the expected digest and the pinned version named, plus `XRAY_SERVER_VERSION=latest` as the way out. No handover to upstream's `core install`.

This overrides requirements §4.7, which forbids a hard failure and asks for a warning followed by the upstream handover. The operator chose the strict variant when the change was proposed on 2026-11-22, and the reason is the one the alternative hides: the handover is precisely the API request being removed, so it re-creates the lottery while appearing to succeed, and it makes a green acceptance run ambiguous. The opt-out keeps §4.7's intent reachable — `XRAY_SERVER_VERSION=latest` restores today's behaviour exactly.

### D6. Two physical copies of the function and table

The Worker payload is a single file streamed over SSH and cannot source `modules/`. `ensure_pinned_xray_core` already exists twice for the same reason. The table therefore lives in `modules/xray_core.sh` and is duplicated in `gowave-node-auto.sh`, with a guard test that reads both copies and `tests/cases/matrix.yaml` and fails when the version or digest differs. Edits to either copy are counted (`grep -c`) before rewriting (AGENTS.md §3.7), because the payload contains sibling copies of surrounding functions.

The version-token comparison follows the same split, but only once in `modules/`: `core_version_matches` currently lives in `modules/node.sh:35-46` and again in the payload. The new module carries it, `modules/node.sh` drops its copy and relies on the sourced one, and the payload keeps its own because a payload-slicing test anchors on the literal `core_version_matches() {` (`tests/test_node_integration.py:435`). A module that is sourced on its own cannot call a function that only exists in `modules/node.sh` — that is a `command not found` at the first call, which is what a standalone unit test would have hit.

### D7. Verification and extraction

`fetch_verified_artifact` (`modules/artifact.sh:18`) owns the download, the single-attempt-per-host digest rule and the `tmp` + `sync` + `mv` install; the step reuses it. The zip is unpacked with `python3 -m zipfile`-equivalent code (member `xray`), because `python3` is already guaranteed on both contours and no `zipfile` extraction exists in `modules/` yet. The extracted binary is executed as `version` from a temporary path before the rename, so a wrong architecture or a corrupt member fails before anything lands at `rw-core`.

The architecture is not mapped a second time: `detect_arch` (`modules/panel.sh:14-23`) already maps `uname -m` to `amd64`/`arm64` and refuses the rest. It moves, unchanged in behaviour, to `modules/os.sh` — the module whose header is "Base OS, package inventory, and environment detection" — because the new module has to be sourceable on its own and cannot reach into the Panel module for an architecture decision. `modules/panel.sh` sources `os.sh`, so the three call sites that reach `detect_arch` through `panel.sh` (`tests/test_panel_deployment.py:87`, `tests/test_artifact_fetch.py:212`, `tools/podman_e2e/aio.py:9682`) keep working, and `modules/xray_core.sh` sources `os.sh` by its own directory. The payload copy carries the two-line `case` itself, because the payload is a single file and cannot source `modules/` — the same reason its `ensure_pinned_xray_core` is a copy. A guard asserts that the mapping still names both architectures the pin table describes, so the table cannot outlive the mapping that selects it.

### D8. No `rw-core.stock`

`IsCustomCore` (`internal/updater/artifacts.go:321-330`) compares against `.stock` only when it exists, so a placed core without one is not classified as custom; the only consequence is that `core reset` answers `no managed stock core is available` (`:302`) until a later managed install backs the file up. Writing `.stock` ourselves would claim a previous state this repository did not observe, so the refusal is the honest outcome and is documented.

### D9. `ensure_pinned_xray_core` stays, narrowed by the new semantics

It keeps serving the explicit non-pin version path, where an API request is the operator's deliberate choice. After this change it is a no-op on the default path, because the version already matches. Removing it would drop that path's only mechanism.

### D10. Evidence is a blocked-API run plus its own control

The acceptance probe makes `api.github.com` unresolvable-or-refusing inside the disposable host: the harness already steers a name to a loopback address by rewriting `/etc/hosts` from inside the container (`tools/podman_e2e/aio.py:1078-1128`, driven by `HOSTS`/`HOST` arguments), and the pinned step is proven by a green installation on that contour. The address is one nothing listens on (`127.0.0.2`, not `127.0.0.1`), because the product's own NGINX answers `127.0.0.1:443` and an answer with a TLS error is a weaker observation than a refused connection.

What the evidence can honestly name: the pin is the digest of the **release archive**, while the installed `rw-core` is the `xray` member extracted from it, so the binary has no pin of its own. The evidence therefore records three separate facts — the archive digest the step verified (from its own success line), the version the installed core reports when asked inside the container (`/opt/gowave-node/rw-core version` → `Xray 26.11.9`), and the run's commit. The first two already exist as probes for other reasons (`INSTALLED_VERSION_SCRIPT` at `aio.py:199-243` and `worker_core_version` at `multi_node.py:1192`); the case reuses them instead of adding a parallel reader.

The control run is the same contour with `XRAY_SERVER_VERSION=latest`, and it must fail. It runs against a **disposable second Worker** — `start_secondary_worker` lives on `MultiNodeTopology` (`tools/podman_e2e/topology.py:1565`), not on the AIO class — because a host that already has an executable core and a serving node never reaches upstream's `core install` at all, so a same-host control would pass regardless of the block. The value under test reaches the Worker over SSH stdin from the **Master's** environment (`gowave-auto.sh:1156` → `gowave-node-auto.sh:2147`), so the control sets it on the Master's command for that one `node add`, not in the container's creation environment. Its teardown mirrors the `MN-ENV-CONTRACT` precedent (`multi_node.py:2270-2360`): remove the container, put the DNS zone, `/root/.ssh/known_hosts`, the node-add journal and state back from the bytes read before the attempt, and read the Panel's node inventory back afterwards.

Adding the block and the control to an existing install case keeps the case inventory and the declared positive counts unchanged, but not for free: the scripted fixtures (`tests/test_podman_aio.py`, `tests/test_podman_multi_node.py`) answer per exec call, so every extra probe or `exec` the case makes needs its scripted answer, and the case's own assertion sentence is subject to the divergence guard.

Without the control, a green run proves only that the installer did not happen to need the API, not that it cannot need it. Requirements §6.3 asks for the positive run only; the control is this design's addition, and §6.3's silence is why the falsifiability argument has to be written down here.

## Risks / Trade-offs

- [Hard failure where the host cannot reach the release asset] → the message names `XRAY_SERVER_VERSION=latest`, the `--help` text and the node-installation docs describe the opt-out, and the opt-out restores today's behaviour exactly.
- [Two table copies drift] → a guard test compares both copies with `tests/cases/matrix.yaml`; a drift fails the nonroot suite rather than a CI run.
- [Replacing the core while the node serves] → the step only runs where the installer runs, and the service restart follows in the same branch.
- [arm64 pin never executed] → the digest is confirmed against the published `.dgst`, and the evidence states the arm64 claim as unverified rather than passing.
- [Pin ages against `GOWAVE_NODE_VERSION=latest`] → the pin lives in one table, is changed together with `matrix.yaml` and the env example, and the guard test makes a partial update impossible.
- [The step's failure happens after the Panel already serves] → it runs before the node's own installation, so the failing run leaves no half-configured node; the rollback path is the installer's existing one.
- [The acceptance contour keeps answering from a scripted fixture] → every extra probe the case makes needs its scripted answer in `tests/test_podman_aio.py` / `tests/test_podman_multi_node.py`; an unstubbed call fails the unit suite rather than passing quietly, which is how the fixture stays honest.
- [The control's failure could be the rollback's, not the pin's] → the control asserts the failing output names the blocked host and that no `rw-core` was created, so a failure for another reason is not counted as the opt-out failing as predicted.
- [No live VPS run] → stated in the evidence as unrun; the container contour is the only executed proof, and the arm64 row is unexecuted on both.

## Migration Plan

No data migration. Existing hosts keep their running core: the step is a no-op when the version matches and is only reached on an installation that restarts the node. Rollback is reverting the pre-placement; a host that already has the pinned core continues to work, and `XRAY_SERVER_VERSION=latest` avoids the step entirely while the change is in place.

## Open Questions

- Whether `gowave-node core reset` should ever become available on a host that has never had a managed install is left as it is; revisit only if an operator reports the refusal as a loss.
