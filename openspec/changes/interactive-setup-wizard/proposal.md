# Proposal

## Why

`gowave-auto.sh install` today is a positional-argument command whose prompts only fill arguments the operator
left out, and it always installs a local GoWave Node (`gowave-auto.sh:446`). There is therefore no way to deploy
the documented "Panel on one VPS plus N workers" layout: the Panel cannot be installed alone, and every worker is
onboarded by hand with `node add` and a pre-pinned SSH host key. Operators who want that layout must already know
the argument order, the subdomain split per host, and the fact that a cluster sharing one registered domain draws
from a single Let's Encrypt budget. None of that is guided, none of it is translated, and a mis-ordered install
fails after certificates have already been issued.

## What Changes

- Add an interactive setup wizard as the product's guided entry point: language (RU/EN), deployment variant,
  per-host subdomain collection, node onboarding, and a certificate-budget preflight. The wizard runs on the
  Panel host and installs the Panel locally.
- Support three deployment variants:
  - **2.1 All-in-One** — Panel, local node, Xray/REALITY/Vision on one host (today's behaviour).
  - **2.2 Panel-only** — Panel plus a camouflage domain only: no Xray, no REALITY inbound, no Vision, and no
    local node. The SNI map serves the Panel and sends everything else to the static decoy. Like 2.3, this
    variant also onboards N remote nodes from the Panel host, one at a time with `node add`.
  - **2.3 All-in-One plus N remote nodes** — 2.1 on the Panel host, then N workers onboarded from it.
- Collect per host: Panel subdomain, decoy subdomain, and optionally a Vision subdomain. On worker nodes the
  real-VPN name and the camouflage name are separate subdomains, and Vision is optional per node.
- Onboard worker nodes over SSH the way the live operator already does it: out-of-band SHA-256 fingerprint
  confirmation, hidden password prompt, a temporary Ed25519 key guarded by a two-hour systemd timer, the existing
  `node add`, then immediate revocation. Behaviour is ported, not code: paramiko stays out, the product remains
  stdlib-only.
- State a domain policy with arithmetic instead of taste. Recommended: a separate registered domain for the
  Panel and a separate registered domain for each node, so each host keeps its own budget. Allowed with a
  guard: one registered domain for the whole cluster, where the wizard computes
  `C = 2 + v_panel + 2N + k` certificates and refuses above the ceiling (24 without Vision, 23 with Vision only
  on the Panel host, 16 with Vision everywhere under a panel-only install, 15 with Vision everywhere under 2.3).
- **BREAKING** for interactive callers: `gowave-auto.sh install` with no arguments starts the wizard rather than
  prompting three fields. The positional form `<panel> <reality> <email> [vision]` and `node add` keep their
  exact contract, so every non-interactive drive stays English and unchanged.
- Fix the panel-only squad defect in the same change: `node add` reads `squadUuid` from `state.json`
  (`gowave-auto.sh:846`) and discards what `provision_internal_squad` returns
  (`modules/api_client.py:651`), so the first worker of a panel-only cluster would send
  `"squads": [null]` (`modules/api_client.py:698`).
- Extend both acceptance contours for the new topology: the Podman suite gains a panel-only drive and catalog
  cases, and the live runner gains the matching panel-only verification.

## Capabilities

### New Capabilities

- `setup-wizard`: the guided installation surface — language selection, deployment-variant selection, host and
  subdomain collection, worker onboarding over temporary SSH access, certificate-budget preflight, and parity
  between the wizard and the non-interactive positional path.

### Modified Capabilities

- `lifecycle-management`: adds the installation-mode contract — what `install` writes and provisions in
  panel-only mode versus All-in-One, when the internal squad is created, and that `node add` consumes the squad
  it provisions instead of a possibly absent state field.
- `live-vps-e2e`: adds Panel-only Master verification — the traffic plane is absent by design, both names answer
  on 443, and the first worker registers with a real squad. Temporary-access onboarding is proven in the cheap
  contour first and is not claimed as live-proven by this change.

## Impact

- **Code**: `gowave-auto.sh` (`cmd_install`, `cmd_node add`, `main_menu`), `modules/nginx.sh`
  (`generate_stream_config`, decoy vhost selection for a panel-only host), `modules/api_client.py` (squad
  provisioning contract), new wizard and message-catalog modules, `modules/os.sh` unchanged.
- **Tests**: `tools/podman_e2e/` topology, case catalog, and docs; `tests/cases/*`; `tests/test_podman_*.py`
  guards; `tools/live_vps/` runner.
- **Docs**: `README.md` deployment variants, `docs/` catalogue of scenarios.
- **Dependencies**: none added. Bash and stdlib Python only; no paramiko, no new ACME plugin.
- **Known limits recorded rather than solved**: the remaining Let's Encrypt budget cannot be read from any API;
  cross-OS Panel/worker combinations are out of scope for this iteration; wildcard certificates are not a
  remedy for a shared domain because every host would submit the identical identifier set.
