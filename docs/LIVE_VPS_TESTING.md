# Local Live VPS E2E Controller

The live two-VPS acceptance run is launched from the operator's Linux workstation. GitHub Actions runs repository CI and automated tests only; it does not receive target VPS passwords, temporary private keys, or known-hosts secrets.

## Prerequisites

- Linux control machine and a clean checkout of the tested repository commit.
- Python 3 and a virtual environment.
- OpenSSH client tools (ssh, ssh-keygen), curl, dig, openssl, and timeout.
- Pinned Xray and Mihomo client binaries matching XRAY_CLIENT_VERSION and MIHOMO_CLIENT_VERSION in tools/live_vps_config.env.example.
- Both freshly provisioned disposable VPS instances must be reachable over SSH and have tcpdump and coreutils timeout installed and executable by root. The controller does not install these target-side tools.
- DNS records for the five required domains must resolve to the corresponding target IPv4 addresses. Optional Master and Worker Vision domains are independent.

## Install and launch

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r tools/requirements-live-vps.txt
python3 tools/run_live_vps.py
```

The interactive entrypoint collects Master and Worker public IPv4 addresses, SSH ports and root logins, the five required domain names (Master Panel, Master REALITY, Master Vision; Worker NGINX and Worker REALITY), and ACME registration email. Master Vision and Worker Vision are independently optional in the underlying configuration model; the interactive five-domain flow asks for Master Vision and does not require Worker Vision. The controller defaults to Let's Encrypt staging. Production requires an explicit mode selection and a second typed confirmation.

## Authentication and cleanup contract

- Existing deployment and rollback commands require root. The controller accepts only the root SSH account; it does not silently elevate through sudo.
- Root password authentication must already be enabled on both SSH servers for initial bootstrap. The controller does not edit sshd configuration or enable password authentication.
- For each VPS, the controller obtains the SSH host key before authentication, displays its SHA-256 fingerprint, and requires the operator to type the exact fingerprint independently obtained from the VPS provider's trusted console. A mismatch aborts before the password is requested.
- Passwords are read using a hidden prompt and passed only to the in-memory Paramiko authentication call. They are never written to argv, environment variables, config files, logs, reports, or GitHub Secrets.
- After host-key verification and password authentication, the controller creates a per-run Ed25519 keypair locally and installs only its public key in root's authorized_keys, using a unique run-specific marker.
- Before appending that key, it installs and enables a persistent two-hour systemd expiry timer on the VPS. The timer removes only the exact run-specific authorized_keys entry and survives reboot (Persistent=true).
- Normal exit attempts immediate remote revocation and verifies that the marker is absent and the timer inactive. If cleanup cannot be verified, the report is downgraded to INCOMPLETE; the remote expiry timer remains the bounded fallback.
- The local private keys, known_hosts files, and generated config live in a mode-0700 temporary directory and are removed when the controller exits.
- Root password authentication remains enabled after the run. If it was enabled solely for bootstrap, disable it through the provider console or the normal secure administration process.

## Test safety and traffic evidence

- Use freshly provisioned disposable VPS instances only. Preflight rejects occupied GoWave directories, conflicting services, and required listeners before deployment.
- DNS validation checks all configured domains and rejects unexpected A/AAAA answers or resolver disagreement.
- The runner requires pinned software versions, TLS trust, and a clean repository worktree. The local Xray and Mihomo binaries must match their configured versions.
- Every Xray and Mihomo proxy request is bracketed by simultaneous inbound tcpdump captures on Master and Worker. The filter includes the control machine's public IPv4 and the exact destination port of the tested proxy service, and excludes each host's SSH destination port.
- A traffic case is PASS only when the intended VPS receives at least one matching inbound packet, the other VPS receives zero matching packets, and the observed egress IPv4 matches the expected VPS egress. Missing or ambiguous evidence is INCOMPLETE; traffic observed on the wrong VPS is FAIL.
- Captures have a 45-second hard lifetime as a crash-safety bound. Only packet counts and evidence metadata are persisted; packet payloads and PCAP files are not.
- Attribution assumes the control machine reaches both VPS instances from the same public IPv4 address. If NAT, provider filtering, or network topology prevents that, evidence is INCOMPLETE, never a heuristic PASS.
- The default teardown policy is PRESERVE: temporary SSH access is revoked, but VPS instances are not destroyed and provider snapshots are not restored automatically. Review the report and remove disposable instances through the provider when appropriate.

## Results and acceptance boundary

The runner writes artifacts/live-vps/<run-id>/ with JSON, JUnit, summary, and sanitized diagnostics. The controller adds an operator_access_cleanup phase; unverified revocation makes the overall result INCOMPLETE, even if deployment and traffic tests passed.

A green repository CI run validates code and automated tests only. It does not constitute live acceptance. The feature remains pending its first complete ACME staging run on two freshly provisioned disposable VPS instances, including all enabled traffic/negative checks and verified teardown/temporary-key cleanup.

## Limitations

The controller targets Linux and root SSH password bootstrap. It does not provision or destroy VPS instances, change SSH daemon policy, support non-root sudo accounts, or install local Xray/Mihomo binaries or target-side tcpdump automatically. Do not bypass host-key fingerprint confirmation or use production ACME for routine acceptance.
