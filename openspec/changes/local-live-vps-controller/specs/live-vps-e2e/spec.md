# Delta: Local Live VPS Operator Controller

## ADDED Requirements

### Requirement: Local interactive operator entrypoint

The system MUST provide a Linux local operator entrypoint that collects Master and Worker public IPv4 addresses, SSH ports and logins, hidden SSH passwords, Master Panel/REALITY/Vision domains, Worker NGINX/REALITY domains, and ACME registration email. The interactive topology MUST support exactly three required Master domains and two required Worker domains without requiring a Worker Vision domain.

#### Scenario: Five-domain input is validated before network access

- **WHEN** the operator enters the two target addresses and five domain names
- **THEN** the controller validates all values with the strict configuration parser before opening either SSH connection
- **AND** invalid IPs, duplicate domains, invalid FQDNs, or unsupported SSH accounts abort without contacting either VPS

#### Scenario: Password is hidden and not persisted

- **WHEN** the operator enters an SSH password
- **THEN** the password is read through a hidden prompt and passed only to the in-memory SSH authentication call
- **AND** the password MUST NOT appear in argv, environment variables, config files, logs, reports, or CI secrets

### Requirement: Out-of-band SSH host identity verification

The controller MUST verify each target's SSH host key before sending its password. It MUST display the SHA-256 fingerprint and require the operator to confirm the exact fingerprint obtained independently from the VPS provider's trusted console. It MUST NOT silently trust a key obtained only from the network.

#### Scenario: Host key is confirmed

- **WHEN** the observed SSH host-key fingerprint exactly matches the operator-confirmed fingerprint
- **THEN** password authentication may proceed
- **AND** the exact host key is written to a private temporary known_hosts file for subsequent OpenSSH connections

#### Scenario: Host key is not confirmed

- **WHEN** the fingerprint does not match or the operator declines confirmation
- **THEN** the controller aborts before sending the password and before modifying the VPS

### Requirement: Temporary SSH access with remote expiry

After successful password authentication, the controller MUST generate a per-run Ed25519 keypair and install only the public key with a unique run marker. It MUST install and enable a persistent remote expiry timer before appending the key. The expiry action MUST remove only the exact key entry created by this run and MUST survive VPS reboot.

#### Scenario: Temporary key is installed

- **WHEN** password authentication and root identity verification succeed
- **THEN** a per-host temporary public key is added without replacing existing authorized_keys entries
- **AND** a persistent two-hour expiry timer is active before the key becomes usable

#### Scenario: Bootstrap fails after expiry is armed

- **WHEN** any bootstrap operation fails after timer installation
- **THEN** the controller attempts immediate cleanup
- **AND** the remote timer remains the bounded fallback if immediate cleanup cannot be verified

### Requirement: Immediate credential revocation gates overall status

The controller MUST attempt immediate removal of temporary SSH access after the E2E subprocess exits. It MUST independently verify that the run-specific marker is absent and the remote expiry timer is inactive. An unverified cleanup MUST downgrade an otherwise successful run to INCOMPLETE and update JSON, JUnit, and text reports.

#### Scenario: Immediate revocation succeeds

- **WHEN** the run-specific authorized_keys marker is absent and the expiry timer is inactive
- **THEN** the cleanup phase is PASS

#### Scenario: Immediate revocation cannot be verified

- **WHEN** SSH cleanup fails or the marker/timer state cannot be independently verified
- **THEN** the cleanup phase is INCOMPLETE
- **AND** an otherwise PASS overall result MUST become INCOMPLETE
- **AND** the persistent remote expiry timer MUST remain armed

### Requirement: Independent Master and Worker Vision domains

The configuration parser MUST allow Master Vision and Worker Vision domains to be configured independently. The E2E runner MUST count one additional endpoint for each configured Vision domain and apply the corresponding disposable-port gate only to the VPS that has Vision enabled.

#### Scenario: Master-only Vision topology

- **WHEN** MASTER_VISION_DOMAIN is configured and WORKER_VISION_DOMAIN is absent
- **THEN** configuration validation succeeds
- **AND** Master Vision is provisioned and verified without requiring a Worker Vision domain
- **AND** the expected subscription endpoint count is nine

#### Scenario: Worker-only Vision topology

- **WHEN** WORKER_VISION_DOMAIN is configured and MASTER_VISION_DOMAIN is absent
- **THEN** configuration validation succeeds
- **AND** Worker Vision is provisioned and verified independently
- **AND** the expected subscription endpoint count is nine

#### Scenario: Both Vision domains are configured

- **WHEN** both Vision domains are configured
- **THEN** both endpoints are provisioned and verified
- **AND** the expected subscription endpoint count is ten

## MODIFIED Requirements

### Requirement: Local-only live VPS credential handling

The live two-VPS E2E acceptance workflow MUST run from the operator's Linux control machine. GitHub Actions MUST NOT request or store target VPS passwords or permanent SSH private keys for this workflow. GitHub Actions remains responsible for repository CI and automated unit/integration tests.

#### Scenario: GitHub CI runs without target credentials

- **WHEN** repository CI executes
- **THEN** it runs the runner unit tests without requiring VPS target credentials or GitHub Environment secrets

#### Scenario: Local operator starts a live run

- **WHEN** the operator launches the local controller
- **THEN** target credentials remain on the local control machine and the existing E2E runner executes with temporary SSH keys and strict host-key verification


### Requirement: Per-case data-plane ingress evidence

Every Xray and Mihomo traffic case MUST use isolated server-side evidence for the individual request. Aggregate interface counters MUST NOT be accepted as proof of endpoint routing.

#### Scenario: Traffic is routed through the selected VPS

- **WHEN** one proxy request is executed with simultaneous packet capture active on Master and Worker, filtered to the exact destination service port used by that proxy
- **THEN** the intended VPS MUST capture at least one inbound TCP packet sourced from the control machine's IPv4 address as that target reports it on the runner's SSH session
- **AND** the other VPS MUST capture zero matching inbound TCP packets
- **AND** the observed egress IPv4 MUST equal the expected egress address of the intended VPS
- **AND** the individual case MAY be marked PASS only when all three conditions hold

#### Scenario: Packet capture is unavailable or incomplete

- **WHEN** tcpdump is unavailable, the targets do not report a common control-machine IPv4, or either capture lacks a valid packet summary
- **THEN** the individual case MUST be INCOMPLETE
- **AND** aggregate interface counters MUST NOT be used as a fallback to PASS

#### Scenario: Traffic reaches the wrong VPS

- **WHEN** the other VPS captures matching inbound packets during a proxy case
- **THEN** the individual case MUST be FAIL even if the egress IPv4 matches the expected value

