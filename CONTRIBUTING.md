# Contributing to GoWave Auto NGINX

## Branching & Pull Request Workflow

- Target development pull requests at `develop`. `main` carries releases only; its release guard accepts pull requests only from this repository's `develop` branch.
- Feature branches should follow the naming scheme: `feature/<topic>`, `fix/<topic>`, or `docs/<topic>`.
- The Podman product-acceptance workflow runs on pull requests into `develop`, pushes to `develop`, and manual dispatch (recovery jobs exclude pushes). Lint/nonroot and root/integration workflows run on pull requests into `develop` and manual dispatch, not every feature-branch push.
- Keep pull requests focused on specific tasks or issues.
- All commits should have clear, descriptive commit messages referencing related tasks or specs.

---

## Code & Engineering Standards

### 1. Shell Script Standards
- Target environment: `bash` on Ubuntu 24.04, Ubuntu 26.04, Debian 12, and Debian 13.
- Always include `set -Eeuo pipefail`, including in payloads streamed over SSH. `-E` propagates `ERR` traps into functions so failure-path rollback runs there too.
- Validate syntax using `bash -n <script>`.
- All shell scripts must pass `shellcheck --severity=error`.
- Always use `local` variables inside functions.

### 2. Python Standards
- Python code must be compatible with Python 3.10+ (standard in Ubuntu 22.04/24.04 and Debian 12).
- Use standard library modules wherever possible; minimize third-party pip dependencies.
- Follow PEP 8 style conventions.

### 3. Zero-Leak Credential Policy
- **Never expose secrets in `argv`**: CLI options must never accept passwords, private keys, or tokens directly in command arguments.
- Use `stdin` streaming or temporary mode `0600` files with automated cleanup traps.
- Remote node orchestration must use SSH stdin streaming (`remote_payload`) without creating unmanaged temporary files on remote hosts.

---

## 5-Suite Testing & Verification

The test suite enforces strict EUID privilege separation:

| Suite | Description | EUID Requirement | Runner |
|---|---|---|---|
| `nonroot` | ShellCheck, Python linting, NGINX compilation, config validation | `EUID != 0` | Host or CI Container |
| `root` | System user creation, permissions, UFW rules, Fail2ban | `EUID == 0` | Privileged CI Container |
| `integration` | SQLite online backup concurrency, GoWave REST API provisioning | `EUID != 0` | Host or Container |
| `services` | Live daemons, Xray handshakes, proxy streaming, subscription validation | `EUID != 0` | Unprivileged CI User |
| `systemd` | PID 1 cold boot, service persistence, crash recovery, reboot acceptance | `EUID == 0` (VM) | QEMU TCG Guest or Podman |

### Running Local Validation

Run commands from the repository root. Run `root` and `systemd` suites only in a
disposable test container or VM, never on an installed production host: they
exercise privileged host configuration and service changes. Rootful Podman
acceptance also provisions privileged systemd containers; use a dedicated test
host with the prerequisites in [the Podman guide](docs/PODMAN_E2E.md#prerequisites).
Do not treat a privilege check or a container boundary as proof of safety on a
production host.

1. **Syntax & Completeness**:
   ```bash
   for s in *.sh modules/*.sh assets/**/*.sh; do [ -f "$s" ] && bash -n "$s"; done
   python3 tests/run_ci.py --check-completeness
   ```

2. **Unprivileged CI Suite**:
   ```bash
   python3 tests/run_ci.py --suite nonroot
   python3 tests/run_ci.py --suite integration
   ```

3. **Local Podman Product Acceptance** (dedicated test host only):
   ```bash
   sudo python3 -m tools.run_podman_e2e --topology aio
   sudo python3 -m tools.run_podman_e2e --topology multi-node
   sudo python3 -m tools.run_podman_e2e --topology panel-only
   ```
   These are the product-acceptance entrypoints used by CI; the older
   `tests/podman_testbed.sh` remains a separate transport testbed, not a substitute
   for them. The default distribution is `ubuntu-24.04`; use `--distribution`
   explicitly for the other targets. See [the invocation reference](docs/PODMAN_E2E.md#invocation)
   for the supported aliases, matrix-defined budget ceilings and artifact checks.
   A passing run proves only the selected topology, distribution and options,
   not all four supported operating systems or a live VPS deployment.

4. **Pre-Push Acceptance Gate**:
   Install the hook once per clone; from then on `git push` runs both full
   Podman suites (`aio`, then `multi-node`) against the pinned fixtures before
   anything leaves the machine, and blocks the push on the first failure:
   ```bash
   python3 -m tools.pre_push_e2e --install-hook
   ```
   The suites provision privileged systemd containers, so the hook runs the gate
   as root and `sudo` may prompt interactively. `git push --no-verify` bypasses
   the hook; the required pull-request checks then judge the change. The gate
   reads which topologies it covers from the `gate:` list in
   `tests/cases/matrix.yaml` — never edit the list to make a push pass.

---

## Licensing & Third-Party Notices

- Original code is licensed under **GNU GPL-3.0-only**.
- Interactions with upstream GoWave components (licensed under AGPL-3.0) occur exclusively across external network and REST APIs.
- Retain upstream attribution for `mozaroc`, `MHSanaei`, and `LibreSpeed` in `THIRD_PARTY_NOTICES.md`.
