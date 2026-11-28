# Proposal

## Why

Installing a GoWave Node spends an anonymous GitHub API request: upstream `install.sh` runs `gowave-node core install -y` whenever no executable `rw-core` exists, and that command lists Xray releases through `api.github.com` before it can act. Anonymous quota is 60 requests per hour per IP, and a GitHub Actions runner shares its IP with unrelated builds, so the install fails with `github api returned status 403` — a red `MN-INSTALL`/`AIO-INSTALL` that reflects the runner's neighbours rather than the diff, and that drags the ~80 cases behind the required group into `BLOCKED`. The same refusal waits for the operator wherever `api.github.com` is blocked or exhausted, which is much of the product's target audience.

## What Changes

- Pre-place a verified, pinned Xray core at `<install_dir>/rw-core` **before** the upstream installer runs, on both installation paths (Master-local and Worker). The upstream installer then skips its own `core install`, and no request to `api.github.com` is made.
- Pin Xray 26.11.9 (the pair verified against mihomo 1.19.34 for REALITY) from the published release asset, verified by SHA-256 before extraction.
- Define one meaning per `XRAY_SERVER_VERSION` value: unset, or naming the pin itself, installs the pin — the acceptance matrix injects exactly that value, so classifying it as "foreign" would abstain on the contour the proof runs on; `latest` is an explicit opt-out that lets upstream fetch its own core; any other version is handled by upstream plus the existing explicit-version path.
- **BREAKING**: an undeliverable pin is a hard failure with the reason named, instead of a warning followed by the upstream fallback. The message names `XRAY_SERVER_VERSION=latest` as the way out. This knowingly overrides requirements §4.7 at the operator's choice; the design records the override and its reason.
- Make the step idempotent on the installed core's version, not on the file's existence, so a foreign `rw-core` cannot block both the pin and upstream's own upgrade path.
- Pin `XRAY_SERVER_VERSION`, `XRAY_CLIENT_VERSION` and `MIHOMO_CLIENT_VERSION` in `tools/live_vps_config.env.example` instead of `latest`, and bring the guard that records the engine-pinning divergence and the three pages that describe it into line with the new values.
- Prove the change falsifiably: an acceptance run that blocks `api.github.com` inside the container must still install the node with the pinned core, and the same blocked run with `XRAY_SERVER_VERSION=latest` on a host with no core must fail — otherwise the probe never reaches the changed branch.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `panel-node-integration`: node installation gains a pinned-core step that owns the Xray core delivery, so the upstream installer orchestration requirement no longer implies an API request, and the version/opt-out contract for `XRAY_SERVER_VERSION` becomes specified behaviour.
- `podman-e2e`: the acceptance contour gains a blocked-API proof of node installation, with an opt-out control that fails on the same contour so a passing run cannot be a run that merely had quota left.

## Impact

- `modules/xray_core.sh` (new): pin table keyed by `(version, arch)`, version detection, verified fetch, zip member extraction, atomic install.
- `modules/node.sh`: call the step inside the restart branch of `install_local_node`, before both installer invocations (pinned and floating `main`).
- `gowave-node-auto.sh`: the same step in `run_upstream_node_installer`, before `run_node_installer_with_retry`; the payload cannot source `modules/`, so the function and table are carried twice and a guard keeps both copies equal to `tests/cases/matrix.yaml`.
- `modules/artifact.sh`: reused unchanged (`fetch_verified_artifact`).
- `modules/os.sh` and `modules/panel.sh`: `detect_arch` moves to `os.sh`, whose job is environment detection, so the new module can be sourced on its own; `panel.sh` sources `os.sh` and keeps answering its existing callers.
- `tools/live_vps_config.env.example`, `docs/LIVE_VPS_TESTING.md`, `README.md`, the node-installation documentation: pinned versions, the `latest` opt-out and the residual network dependencies.
- `tests/test_podman_docs.py` and the three pages that record the engine-pinning divergence (`docs/PODMAN_E2E_DISCOVERY.md`, the matrix header): the live runner no longer reads `latest` for the pinned clients, so the recorded divergence becomes a shared pin.
- Tests: `tests/test_node_integration.py` (unit), `tools/podman_e2e` (acceptance probe added to existing install and `node add` cases, not a new case, with the scripted fixtures updated for the extra probes).
- Out of scope: mirroring `github.com` reachability (the core zip and the geodata files still come from there), the Panel's own API fallback in `modules/panel.sh`, runtime core updates driven by the Panel, an executed arm64 run, a live VPS run, and moving the acceptance contour onto the pinned installer branch.
