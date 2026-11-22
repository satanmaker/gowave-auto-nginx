# Proposal

## Why

Installing a GoWave Node spends an anonymous GitHub API request: upstream `install.sh` runs `gowave-node core install -y` whenever no executable `rw-core` exists, and that command lists Xray releases through `api.github.com` before it can act. Anonymous quota is 60 requests per hour per IP, and a GitHub Actions runner shares its IP with unrelated builds, so the install fails with `github api returned status 403` — a red `MN-INSTALL`/`AIO-INSTALL` that reflects the runner's neighbours rather than the diff, and that drags the ~80 cases behind the required group into `BLOCKED`. The same refusal waits for the operator wherever `api.github.com` is blocked or exhausted, which is much of the product's target audience.

## What Changes

- Pre-place a verified, pinned Xray core at `<install_dir>/rw-core` **before** the upstream installer runs, on both installation paths (Master-local and Worker). The upstream installer then skips its own `core install`, and no request to `api.github.com` is made.
- Pin Xray 26.11.9 (the pair verified against mihomo 1.19.34 for REALITY) from the published release asset, verified by SHA-256 before extraction.
- Define one meaning per `XRAY_SERVER_VERSION` value: unset installs the pin; `latest` is an explicit opt-out that lets upstream fetch its own core; any other version is handled by upstream plus the existing explicit-version path.
- **BREAKING**: an undeliverable pin is a hard failure with the reason named, instead of a warning followed by the upstream fallback. The message names `XRAY_SERVER_VERSION=latest` as the way out.
- Make the step idempotent on the installed core's version, not on the file's existence, so a foreign `rw-core` cannot block both the pin and upstream's own upgrade path.
- Pin `XRAY_SERVER_VERSION`, `XRAY_CLIENT_VERSION` and `MIHOMO_CLIENT_VERSION` in `tools/live_vps_config.env.example` instead of `latest`.
- Prove the change falsifiably: an acceptance run that blocks `api.github.com` inside the container must still install the node with `rw-core` at the pinned digest, and the same blocked run with `XRAY_SERVER_VERSION=latest` must fail — otherwise the probe never reaches the changed branch.

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
- `tools/live_vps_config.env.example`, node-installation docs: pinned versions and the `latest` opt-out.
- Tests: `tests/test_node_integration.py` (unit), `tools/podman_e2e` (acceptance probe added to an existing install case, not a new case).
- Out of scope: mirroring `github.com` reachability, the Panel's own API fallback in `modules/panel.sh`, runtime core updates driven by the Panel, and an executed arm64 run.
