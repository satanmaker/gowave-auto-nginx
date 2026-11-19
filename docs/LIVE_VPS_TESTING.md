# Local Live VPS E2E Controller

The live two-VPS acceptance run is launched from the operator's Linux workstation. GitHub Actions runs repository CI and automated tests only; it does not receive target VPS passwords, temporary private keys, or known-hosts secrets.

## Prerequisites

- Linux control machine and a clean checkout of the tested repository commit.
- Python 3 and a virtual environment.
- OpenSSH client tools (ssh, ssh-keygen), curl, dig, openssl, and timeout.
- Xray and Mihomo client binaries on the Control Machine. `XRAY_CLIENT_VERSION` and `MIHOMO_CLIENT_VERSION` default to `latest`, so preflight accepts the installed builds; set an explicit tag there to require one.
- Both freshly provisioned disposable VPS instances must be reachable over SSH and have tcpdump and coreutils timeout installed and executable by root. The controller does not install these target-side tools; preflight rejects a target that lacks either one instead of failing later in the traffic phase.
- DNS records for the five required domains must resolve to the corresponding target IPv4 addresses. Optional Master and Worker Vision domains are independent.

## Install and launch

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r tools/requirements-live-vps.txt
python3 tools/run_live_vps.py
```

The interactive entrypoint collects Master and Worker public IPv4 addresses, SSH ports and root logins, the required Master Panel/REALITY and Worker NGINX/REALITY domains, and independent optional Master/Worker Vision domains. The controller defaults to Let's Encrypt staging. Production requires an explicit mode selection and a second typed confirmation.

Run a non-deploying eligibility check first with `python3 tools/run_live_vps.py --mode preflight`. This performs local tool/DNS checks, bootstraps temporary SSH access only after out-of-band host-key confirmation, executes the runner's read-only remote baseline checks, then revokes the temporary keys. It does not install GoWave or modify GoWave services. Use `--mode full` (the default) only after preflight passes and both targets are confirmed disposable.

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

## Component versions and REALITY fingerprint

Every component version defaults to `latest`, matching what the installers ship: `GOWAVE_PANEL_VERSION`, `GOWAVE_NODE_VERSION`, `XRAY_SERVER_VERSION`, `XRAY_CLIENT_VERSION` and `MIHOMO_CLIENT_VERSION`. With a floating channel the deployment step asserts that each component reports a version and records what it reported, instead of comparing it to a hardcoded tag; an explicit version/tag is still accepted when a run has to reproduce a specific release. Keep `tools/live_vps_config.env` in sync with `tools/live_vps_config.env.example` so the run does not start from a stale pin.

| Key | Default | Purpose |
|---|---|---|
| `REALITY_FINGERPRINT` | `firefox` | uTLS preset written to REALITY Host records and asserted by subscription validation |

`firefox` is the default: `metacubex/utls` maps `HelloFirefox_Auto` to Firefox 148, whose ClientHello carries the X25519MLKEM768 key share required by Xray REALITY servers. Xray and mihomo both authenticate against REALITY hosts with this preset, and Vision/XHTTP/WS/Trojan-gRPC hosts use `firefox` as well. `REALITY_FINGERPRINT` remains overridable for client fleets that need a different uTLS preset; when it is overridden, the Mihomo subscription validator rejects any REALITY proxy whose `client-fingerprint` does not match the configured preset.

## Test safety and traffic evidence

- Use freshly provisioned disposable VPS instances only. Preflight rejects occupied GoWave directories, conflicting services, and required listeners before deployment.
- DNS validation checks all configured domains and rejects unexpected A/AAAA answers or resolver disagreement.
- The runner requires pinned software versions, TLS trust, and a clean repository worktree. The local Xray and Mihomo binaries must match their configured versions.
- Every Xray and Mihomo proxy request is bracketed by simultaneous inbound tcpdump captures on Master and Worker. The capture filter names only the exact destination port of the tested proxy service (excluding each host's SSH destination port); it deliberately contains no source address. Attribution is decided after the capture from the source addresses tcpdump actually saw, compared against the control machine's IPv4 as each target reports it on its own SSH session (`SSH_CONNECTION`). This is what makes the check independent of VPN split tunnelling and carrier-grade NAT, where different destinations — and sometimes different flows — leave through different public addresses. A public echo service such as api.ipify.org is never consulted: it answers from an address that does not reach the VPS.
- A traffic case is PASS only when the intended VPS receives at least one matching inbound packet, the other VPS receives zero matching packets, and the observed egress IPv4 matches the expected VPS egress. Traffic observed on the wrong VPS is FAIL; an empty capture, or a capture whose packets all came from an address other than the reported control IPv4, is INCOMPLETE. Non-matching source addresses are recorded as `observed_other_sources`, so a rotated VPN exit shows up as an explicit address mismatch instead of a silent zero.
- Captures have a 45-second hard lifetime as a crash-safety bound. Only packet counts and evidence metadata are persisted; packet payloads and PCAP files are not.
- `TRAFFIC_TIMEOUT` bounds each Xray and Mihomo egress request and also derives the curl connect budget (half the timeout, never below 10 seconds). Xray and Go cache no resolver answers, so a single dropped UDP/53 query costs a full 5-second stall; both VPS receive strict DNS-over-TLS hardening so tunnel setup does not race the resolver.
- Attribution requires that both VPS instances report the same control-machine IPv4 address for the runner's SSH sessions. If NAT, provider filtering, or network topology presents a different address per target, every case is INCOMPLETE, never a heuristic PASS.
- The default teardown policy is PRESERVE: temporary SSH access is revoked, but VPS instances are not destroyed and provider snapshots are not restored automatically. Review the report and remove disposable instances through the provider when appropriate.

## Local Multi-Node Podman transport acceptance

Run `sudo tests/podman_testbed.sh multi-node` on a Linux host with rootful Podman. The target builds the systemd test image and creates an isolated three-container network (Control, Master, Worker). It verifies a pinned-key Master-to-Worker root SSH command, a real TLS 1.3 mTLS request, rejection of absent and untrusted client certificates, and Worker TCP/3002 source filtering (Master allowed, Control dropped). The workflow executes this test on GitHub Actions as a separate job.

This is a transport/firewall integration test, not a substitute for live GoWave acceptance: it does not install the GoWave Panel/Node binaries, register a Worker through the Panel API, validate subscription payloads, or exercise Xray/Mihomo client proxy traffic. Those assertions remain in the two-disposable-VPS Live E2E.

## Results and acceptance boundary

The runner writes artifacts/live-vps/<run-id>/ with JSON, JUnit, summary, and sanitized diagnostics. The controller adds an operator_access_cleanup phase; unverified revocation makes the overall result INCOMPLETE, even if deployment and traffic tests passed.

A green repository CI run validates code and automated tests only. It does not constitute live acceptance. The runner's six-phase matrix (preflight, install, verify, traffic, negative, teardown) has completed with overall PASS in ACME staging on two freshly provisioned disposable VPS instances, including all 20 traffic cases with packet evidence, all 15 negative scenarios, and verified teardown. The interactive `python3 tools/run_live_vps.py` bootstrap path — host-key fingerprint confirmation, per-run temporary key installation, immediate revocation, and the two-hour remote expiry fallback — still requires its own acceptance run before that path is considered proven.

## Limitations

The controller targets Linux and root SSH password bootstrap. It does not provision or destroy VPS instances, change SSH daemon policy, support non-root sudo accounts, or install local Xray/Mihomo binaries or target-side tcpdump automatically. Do not bypass host-key fingerprint confirmation or use production ACME for routine acceptance.
