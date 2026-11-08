# Contributing to GoWave Auto NGINX

## Branching & Pull Request Workflow

- `main` is the primary protected branch.
- Feature branches should follow the naming scheme: `feature/<topic>`, `fix/<topic>`, or `docs/<topic>`.
- Keep pull requests focused on specific tasks or issues.
- All commits should have clear, descriptive commit messages referencing related tasks or specs.

---

## Code & Engineering Standards

### 1. Shell Script Standards
- Target environment: `bash` on Ubuntu 24.04, Ubuntu 26.04, Debian 12, and Debian 13.
- Always include `set -euo pipefail`.
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

3. **Local Podman Pre-Flight Gate**:
   Before deploying to any physical or cloud VPS, run:
   ```bash
   ./tests/podman_testbed.sh
   ./tests/podman_testbed.sh multi-node
   ```
   All 8 stages must pass across all 4 target operating systems.

---

## Licensing & Third-Party Notices

- Original code is licensed under **GNU GPL-3.0-only**.
- Interactions with upstream GoWave components (licensed under AGPL-3.0) occur exclusively across external network and REST APIs.
- Retain upstream attribution for `community-baseline`, `mozaroc`, `MHSanaei`, and `LibreSpeed` in `THIRD_PARTY_NOTICES.md`.
