# Proposal: Local Live VPS Operator Controller

## Why

The current live E2E workflow asks operators to maintain permanent GitHub Environment secrets for two VPS configurations, private SSH keys, and known-hosts files. That is a poor fit for a one-operator workflow where the target servers are supplied per run. GitHub Actions dispatch inputs are not a secure password-entry interface, and the existing workflow cannot safely accept arbitrary target credentials from the operator.

The desired workflow is direct: enter Master and Worker IPs, SSH logins/passwords, and five domain names, then receive a complete acceptance report. The test execution and credentials should remain on the operator's Linux workstation.

## What Changes

- Add an interactive local entrypoint: `python3 tools/run_live_vps.py`.
- Prompt for the two target addresses, SSH ports/logins, hidden passwords, Master Panel/REALITY/Vision domains, Worker NGINX/REALITY domains, and ACME email.
- Verify each SSH host key against a fingerprint the operator independently obtains from the VPS provider console before sending a password.
- Bootstrap a per-run Ed25519 keypair, install the public key with a persistent two-hour remote expiry timer, and run the existing E2E runner using strict OpenSSH host-key verification.
- Keep passwords out of argv, environment variables, files, logs, reports, and GitHub Secrets.
- Revoke temporary access immediately after the run; an unverified cleanup downgrades the report to INCOMPLETE. The remote expiry timer is the crash/reboot fallback.
- Allow Master Vision and Worker Vision to be configured independently. The interactive topology is three Master domains and two Worker domains.
- Remove the credential-bearing GitHub Actions live VPS dispatch workflow. Keep unit/integration CI in GitHub Actions.

## Non-Goals

- VPS provisioning or destruction through a cloud-provider API.
- Automatic modification of sshd password-authentication policy.
- Non-root sudo execution support; existing install and rollback scripts require root.
- Automatic installation of Xray/Mihomo client binaries.
- Replacing existing E2E lifecycle tests, teardown, or provider snapshot restoration.

## Impact

New local operator module, entrypoint, pinned Python requirements, tests, and operator documentation. Existing configuration validation and runner orchestration are updated for independent Vision domains. The legacy GitHub Actions live VPS workflow is removed; the Live VPS unit-test workflow installs the local controller's pinned Python dependencies.
