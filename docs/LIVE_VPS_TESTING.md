# Local Live VPS E2E Controller

The live two-VPS acceptance run is launched from the operator's Linux workstation. GitHub Actions remains responsible for repository CI and runner unit tests; it no longer receives target VPS passwords, private keys, or known-hosts secrets.

## Operator flow

1. Install Python dependencies in a virtual environment:
   ```bash
   python3 -m venv .venv
   . .venv/bin/activate
   python -m pip install -r tools/requirements-live-vps.txt
   ```
2. Ensure the pinned local Xray and Mihomo clients from `tools/live_vps_config.env.example` are installed, together with `ssh-keygen`, `dig`, `openssl`, and `curl`.
3. Run:
   ```bash
   python3 tools/run_live_vps.py
   ```
4. Enter the Master and Worker public IPv4 addresses, SSH ports and logins, three Master domains (Panel, REALITY, Vision), two Worker domains (NGINX and REALITY), and ACME email. The default ACME mode is Let's Encrypt staging. Production requires an additional explicit confirmation.
5. For each host, compare the displayed SSH host-key fingerprint with the value shown in the VPS provider's trusted console and type the exact fingerprint. Only then is the hidden SSH password requested.

## Authentication and cleanup contract

- Current deployment scripts require root privileges. The interactive controller therefore accepts only the `root` SSH account; it does not silently elevate through sudo.
- The SSH server must already permit root password authentication for the initial bootstrap. The controller does not edit sshd configuration or enable password authentication.
- Passwords are read using a hidden prompt and used only in the in-memory Paramiko authentication call. They are not written to argv, environment variables, config files, logs, reports, or GitHub Secrets.
- After host-key verification and password authentication, the controller creates a per-run Ed25519 keypair locally and installs only its public key in root's `authorized_keys`.
- Before adding that key, it installs and enables a persistent systemd expiry timer on each VPS. The timer removes only the exact run-specific authorized_keys entry after two hours, including after a reboot.
- The local private keys, known_hosts files, and generated config live in a mode-0700 temporary directory and are removed when the controller exits.
- Normal exit attempts immediate remote revocation and verifies that the marker is absent and the timer inactive. If revocation cannot be verified, the report is downgraded to INCOMPLETE; the remote expiry timer remains armed. A successful E2E suite alone is not sufficient for overall PASS.
- The controller does not disable an existing root-password authentication method. If password authentication was enabled solely for this run, disable it again using the provider console or your normal secure administration process.

## Target and test safety

- Use freshly provisioned disposable VPS instances only. The existing preflight rejects occupied GoWave directories, conflicting services, and required listeners before deployment.
- DNS for all five supplied domains must resolve exactly to the corresponding VPS addresses. Unexpected A/AAAA answers or resolver disagreement fail preflight.
- The existing runner requires pinned software versions, strict DNS, TLS trust, and a clean repository worktree. Local Xray and Mihomo binaries must match the pinned versions. Both target VPS instances must have `tcpdump` installed and executable by root; the runner does not install or remove it.
- The default teardown policy remains `PRESERVE`: the controller revokes temporary SSH access but does not destroy VPS instances or automatically restore provider snapshots. Review the report and remove disposable instances through the provider when appropriate. Snapshot restoration remains an explicitly configured option.
- The Master Vision domain is independent of Worker Vision. The interactive five-domain topology uses Master Panel + Master REALITY + Master Vision, and Worker NGINX + Worker REALITY.

## Results

The existing runner writes `artifacts/live-vps/<run-id>/` with JSON, JUnit, summary, and sanitized diagnostics. The controller adds an `operator_access_cleanup` phase. If remote key revocation is not verified, the report records INCOMPLETE even when all deployment and traffic phases passed. Each Xray and Mihomo request is bracketed by simultaneous inbound `tcpdump` captures on both VPS instances. Captures are filtered to the control machine's public IPv4 and the exact proxy service destination port, excluding each host's SSH destination port; only packet counts and the evidence method are persisted, never packet payloads or PCAP files. Each remote capture has a 45-second hard lifetime as a crash-safety fallback. A traffic case is PASS only when the expected VPS received packets, the other VPS received zero matching packets, and the observed egress IP matches the expected VPS egress.

## Limitations

The controller currently targets Linux and root SSH password authentication. It does not provision VPS instances, change SSH daemon policy, support non-root sudo accounts, or install the Xray/Mihomo client binaries or target-side `tcpdump` automatically. The packet-capture attribution assumes the control machine reaches both VPS instances from the same public IPv4 address; if NAT, provider filtering, or network topology prevents that, traffic evidence is INCOMPLETE rather than silently passing. Do not bypass host-key fingerprint confirmation or use production ACME for routine acceptance.
