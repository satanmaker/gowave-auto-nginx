# Spec Delta

## MODIFIED Requirements

### Requirement: Strict DNS-over-TLS with Rollback
The security subsystem SHALL apply the same optional strict DoT control on Master and Worker, with best-effort as the default and an explicit required mode. It SHALL verify effective resolver settings and queries, restore prior DNS state on failure, and report the control and recovery outcomes separately. Required-mode failure or unverified DNS recovery SHALL prevent successful deployment completion.

#### Scenario: Successful DoT deployment on Debian 12
- **GIVEN** a clean Debian 12 host lacking `systemd-resolved`
- **WHEN** DNS-over-TLS is selected
- **THEN** the package is installed, the managed drop-in and resolver integration are applied, effective strict DoT and uncached system and resolver queries are verified, and the result is reported as verified.

#### Scenario: Atomic rollback on DoT network failure
- **GIVEN** upstream port 853 is blocked and best-effort DoT is selected
- **WHEN** strict DoT verification fails
- **THEN** original DNS settings and service state are restored and resolution is verified; deployment can continue with a visible failed-control warning only when recovery is verified, never reporting DoT enabled.

#### Scenario: Edge Worker applies the same strict DoT policy
- **GIVEN** an Edge Worker host being hardened
- **WHEN** selected DoT preparation runs
- **THEN** it uses the same verification and policy as Master; compensation and standalone rollback remove only project-owned configuration and preserve unrelated resolver settings.

#### Scenario: Required DoT or failed recovery blocks success
- **WHEN** required DoT fails or restoration of working DNS cannot be verified in either mode
- **THEN** the host is not reported ready, control failure and recovery failure are distinguished, and the operator receives a recovery route.

#### Scenario: Existing prerequisites do not bypass selected DoT
- **GIVEN** all installation prerequisites are already present on any supported distribution
- **WHEN** selected DoT preparation runs
- **THEN** verification is still performed and its result is included in the security report.

### Requirement: UFW Firewall Port Lockdown
The security subsystem SHALL apply a role-specific deny-by-default inbound policy transactionally, preserve discovered SSH access, restrict Worker control access to Master sources and isolate internal listeners on IPv4 and IPv6. It SHALL detect conflicting existing rules without silently deleting administrator policy and verify restoration on failure. Unverified enforcement or recovery SHALL block successful completion.

#### Scenario: Atomic UFW activation
- **GIVEN** a host with SSH access
- **WHEN** firewall policy is applied
- **THEN** a restorable baseline is captured before mutation, all discovered SSH ports are preserved before activation, public TCP 80/443 are allowed, effective incoming default is deny and outgoing default is allow, and external access to internal ports 3000, 3001, 7443, 8443, 8444, 9443, 9444 and 10001-10003 is denied for existing listeners. The configured Node API port (default 3002, including a non-default value) is explicitly denied externally on All-in-One, allowed only from configured Master sources on Worker, and has no listener or managed allow exception on Panel-only; these role-specific rules apply across enabled IPv4 and IPv6 families.

#### Scenario: Node control port whitelisting
- **GIVEN** a Worker with defined Master IPv4 and optional IPv6 control addresses
- **WHEN** firewall policy is applied
- **THEN** its configured Node API port is reachable only from those sources and loopback; other sources are denied across enabled families.

#### Scenario: Firewall persistence and dual-stack isolation across reboots
- **GIVEN** an All-in-One host whose Node binds wildcard port 3002
- **WHEN** UFW is reloaded or the host reboots
- **THEN** external IPv4 and IPv6 connections remain denied and local loopback connectivity is unaffected.

#### Scenario: Conditional UFW IPv6 handling when IPv6 is disabled in kernel
- **GIVEN** IPv6 is disabled or lacks a default route and no public IPv6 listeners are generated
- **WHEN** firewall policy is applied
- **THEN** the UFW family declaration follows the listener decision without claiming verified IPv6 protection for an untested family.

#### Scenario: Administrator allow conflicts with required isolation
- **GIVEN** existing single-port, port-range or general allow policy exposes an internal or source-restricted listener
- **WHEN** preflight evaluates effective ingress
- **THEN** it names the conflicting policy and refuses mutation until explicitly resolved, without resetting UFW or deleting unrelated rules.

#### Scenario: Snapshot or enforcement fails
- **WHEN** the baseline cannot be captured or a required firewall change fails
- **THEN** no mutation occurs without a baseline; after mutation the prior configuration and active state are restored and verified, with failed restoration reported separately and no success banner.

#### Scenario: Panel-only role
- **WHEN** a Panel-only host is configured
- **THEN** only discovered SSH and TCP 80/443 are publicly allowed by the managed policy; no local Node API exception is created and absent Node listeners are reported as not applicable.

### Requirement: Automated Security Updates Without Auto-Reboot
The security subsystem SHALL apply and verify unattended security updates during normal Master and Worker installation on supported Debian and Ubuntu releases. It SHALL ensure the required package, effective security origins, periodic execution and active persistent timers, with automatic reboot disabled. Existing administrator origins SHALL NOT be silently removed or reported as security-only.

#### Scenario: Distro-specific security updates configuration
- **GIVEN** a target host running Ubuntu or Debian
- **WHEN** automated updates are configured
- **THEN** the managed policy contains the correct distro security origin, effective automatic reboot is false, unattended-upgrades is installed and periodic policy and enabled active timers are verified.

#### Scenario: Existing wider update policy
- **GIVEN** administrator policy already permits non-security origins
- **WHEN** security updates are configured
- **THEN** existing origins are preserved and disclosed in the effective report; the installer does not claim that only security updates are enabled.

#### Scenario: Ineffective APT control
- **WHEN** required package, policy or timer verification fails
- **THEN** the host is not reported fully hardened, prior managed changes are restored where possible and the failure and recovery outcome remain visible.

## ADDED Requirements

### Requirement: Equivalent effective SSH protection on all roles
Master and Worker SHALL apply the managed Fail2ban SSH jail using discovered standalone and socket-activated SSH ports, a systemd journal backend and verified active jail settings. Package or service presence alone SHALL NOT count as verified SSH protection. Existing SSH configuration and administrator keys SHALL remain unchanged.

#### Scenario: Worker SSH jail is applied during normal install
- **WHEN** a Worker is installed with a custom SSH port or socket-activated SSH
- **THEN** the effective jail monitors the corresponding journal events and discovered ports, and its active status and settings are verified as on Master.

#### Scenario: Jail fails to activate
- **WHEN** the service is active but the required SSH jail or matching settings cannot be verified
- **THEN** the control is failed, not verified, and required baseline completion is blocked with a safe diagnostic.

### Requirement: Per-host effective security report
Each host SHALL produce an atomic machine-readable security report and a readable summary identifying role, control policy, evidence time, verified/failed/skipped/unsupported status, safe reason and recovery outcome. Required firewall, SSH protection or security-update failures SHALL block readiness. Optional failure SHALL remain explicit; no credentials SHALL enter either report.

#### Scenario: Best-effort degradation is visible
- **WHEN** optional DoT fails with verified DNS recovery while other required controls pass
- **THEN** deployment reports the host ready with warnings, identifies DoT as failed and recovery as verified, and does not call the host fully hardened.

#### Scenario: Readback after rerun
- **GIVEN** a prior report says controls passed
- **WHEN** installation is resumed or rerun
- **THEN** effective state is verified again before a fresh report is issued; stale success is not treated as current evidence.

#### Scenario: Scope of DNS protection
- **WHEN** the report explains verified system-resolver DoT
- **THEN** it states that bypassing applications are not covered, DNSSEC is separate, and neither DoT nor the firewall is a guarantee of DPI invisibility or upstream DDoS protection.

### Requirement: Pinned NGINX package provenance and security level
The installer SHALL enforce one NGINX package policy for Panel-only, All-in-One and Worker provisioning. The primary source SHALL be the official signed NGINX stable APT repository and its approved exact package revisions for upstream `1.30.8`. Trust SHALL be scoped to that repository, and package versions, provenance and Stream capability SHALL be verified before NGINX is used by the deployment. The installer SHALL NOT select a floating latest version or downgrade a newer existing installation.

#### Scenario: Approved official package is available
- **WHEN** the signed official repository offers the approved revision for the target OS and architecture
- **THEN** provisioning selects that exact revision and a compatible Stream-capable package set, and verifies the actual installation before using NGINX.

#### Scenario: Official package is unavailable
- **WHEN** the required official revision is unavailable without a repository authentication error
- **THEN** provisioning may use a package from the signed distribution archive only if an explicitly approved revision covers all required applicable fixes, including CVE-2026-132779 where affected, and its installed revision and Stream capability are verified.

#### Scenario: The vendor repository is briefly unreachable
- **GIVEN** a Worker that is already serving and is being re-applied
- **WHEN** a connection to the signed official repository drops during the index refresh, the package download or the install
- **THEN** that authenticated fetch is retried within a bounded budget before the repository is called unavailable, and exhausting the budget is still a refusal with the same diagnostic and no distribution fallback.

#### Scenario: Neither source can establish a verified install
- **WHEN** neither source qualifies, a repository authentication check fails, a downgrade would be required, or the installed package cannot be verified
- **THEN** provisioning fails with a safe diagnostic identifying the source and version check, does not activate the managed NGINX configuration, and does not stop or replace a pre-existing service merely to work around the refusal.
