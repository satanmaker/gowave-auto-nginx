# Spec Delta: VPS Security

## Purpose

Enforces non-destructive host security hardening, firewall controls, automated security updates without auto-reboot, strict DNS-over-TLS, and conditional kernel optimizations.

## ADDED Requirements

### Requirement: Non-Destructive SSH Port and Socket Inspection
The security subsystem SHALL discover active SSH ports and socket bindings using `sshd -T` and `systemctl show ssh.socket -p Listen` without modifying existing `sshd_config` or truncating root authorized keys.

#### Scenario: SSH port detection and firewall safeguard
- **GIVEN** a host with SSH running on a custom port or managed via `ssh.socket`
- **WHEN** security configuration evaluates SSH settings
- **THEN** effective listening ports are extracted from both daemon configuration and socket units, and whitelisted in UFW before the firewall is activated.

### Requirement: Fail2ban Intrusion Prevention
The security subsystem SHALL install an isolated project drop-in `/etc/fail2ban/jail.d/90-gowave-auto-nginx.local` protecting SSH and NGINX, and verify active jail status via `fail2ban-client status`.

#### Scenario: Fail2ban jail activation and verification
- **GIVEN** a host with `fail2ban` installed
- **WHEN** the security module is applied
- **THEN** the drop-in configuration is installed, `fail2ban` is reloaded, and `fail2ban-client status` confirms the jails are active and monitoring logs.

### Requirement: Strict DNS-over-TLS with Rollback
The security subsystem SHALL optionally configure `systemd-resolved` with encrypted Cloudflare and Google DoT resolvers, auto-installing the package on Debian 12 if absent, and atomically reverting on failure.

#### Scenario: Successful DoT deployment on Debian 12
- **GIVEN** a clean Debian 12 host lacking `systemd-resolved`
- **WHEN** DNS-over-TLS is selected
- **THEN** `systemd-resolved` is installed via APT, the drop-in configuration is written, DNS-over-TLS is verified via `resolvectl status`, and unencrypted link DNS is preserved if needed.

#### Scenario: Atomic rollback on DoT network failure
- **GIVEN** a VPS environment where upstream port 853 is blocked by the datacenter
- **WHEN** DNS-over-TLS query verification fails
- **THEN** the drop-in configuration is removed, original DNS settings are restored, and a warning is logged without aborting installation.

### Requirement: UFW Firewall Port Lockdown
The security subsystem SHALL manage UFW rules atomically, opening only necessary ports, whitelisting Control Plane IP for Node ports, and preventing administrator lockout. Because `gowave-node` binds wildcard addresses (`:3002`), UFW rules SHALL explicitly block external inbound traffic on node ports in All-in-One setups.

#### Scenario: Atomic UFW activation
- **GIVEN** a host with SSH access
- **WHEN** firewall rules are applied
- **THEN** SSH ports are allowed first, ports 80 and 443 are allowed publicly, internal ports (3000, 3001, 3002, 7443, 8443, 9443, 10001-10003) remain closed to external interfaces via explicit deny rules across both IPv4 and IPv6, and UFW is enabled.

#### Scenario: Node control port whitelisting
- **GIVEN** an edge node deployment with a defined `PANEL_IP`
- **WHEN** firewall rules are applied on the node
- **THEN** `NODE_PORT` is allowed strictly from `PANEL_IP` (for both IPv4 and IPv6 where enabled), and connections from all other external IPs are dropped.

#### Scenario: Firewall persistence and dual-stack isolation across reboots
- **GIVEN** an active UFW configuration with node port 3002 denied to external interfaces
- **WHEN** UFW is reloaded or the operating system reboots
- **THEN** effective iptables and ip6tables rules persist, node port 3002 remains strictly inaccessible from external IPv4 and IPv6 addresses, and loopback connectivity (`127.0.0.1`, `::1`) is unaffected.

### Requirement: Optional Swap Space Management
The security subsystem SHALL provide optional swap file allocation (2 GiB), safely detecting existing swap and container virtualization limitations.

#### Scenario: Swap creation on low-memory VPS
- **GIVEN** a KVM VPS with <= 1GB RAM and no active swap
- **WHEN** swap configuration is evaluated
- **THEN** a 2GB swap file is created with mode 0600, activated via `swapon`, and recorded in `/etc/fstab`.

#### Scenario: Skip swap on containerized environments
- **GIVEN** an LXC or OpenVZ container where `swapon` is restricted
- **WHEN** swap configuration is evaluated
- **THEN** swap creation is skipped gracefully without raising a fatal error.

### Requirement: Automated Security Updates Without Auto-Reboot
The security subsystem SHALL configure `unattended-upgrades` with OS-specific security repository origins and set `Automatic-Reboot "false"` by default to prevent unexpected VPN downtime.

#### Scenario: Distro-specific security updates configuration
- **GIVEN** a target host running Ubuntu or Debian
- **WHEN** automated updates are configured
- **THEN** `/etc/apt/apt.conf.d/99zz-gowave-auto-nginx` is written with the appropriate distro security origin pattern, and `Unattended-Upgrade::Automatic-Reboot` is set to `"false"`.

### Requirement: Conditional Kernel BBR Congestion Control
The security subsystem SHALL conditionally enable BBR congestion control only after verifying kernel module support and qdisc availability.

#### Scenario: BBR activation when module is available
- **GIVEN** a Linux kernel supporting `tcp_bbr`
- **WHEN** kernel performance tuning is requested
- **THEN** `/etc/sysctl.d/99-gowave.conf` is written with `net.core.default_qdisc = fq` and `net.ipv4.tcp_congestion_control = bbr`, and verified via `sysctl net.ipv4.tcp_congestion_control`.
