# Spec Delta

## ADDED Requirements

### Requirement: SSH reachability is checked from the operator host before deployment
The interactive deployment flow SHALL verify that each planned remote VPS accepts an SSH connection from the operator host using the configured address, port, and user before the first deployment mutation.

#### Scenario: SSH preflight passes for each remote VPS
- **GIVEN** all remote VPS addresses and SSH settings are valid and reachable
- **WHEN** the operator runs preflight
- **THEN** each remote target is reported reachable and deployment may proceed after plan confirmation

#### Scenario: SSH preflight failure blocks unattended deployment
- **GIVEN** a planned remote VPS cannot be reached over SSH from the operator host
- **WHEN** preflight runs
- **THEN** it identifies the target and connection failure before deployment mutations and offers plan editing or an explicit decision to continue without that node

### Requirement: Optional external preflight checks only deployment-relevant public reachability
The interactive flow SHALL optionally check DNS for configured public FQDNs and TCP reachability of the public HTTPS port from a selected country, without scanning unrelated ports or treating the result as proof for every ISP in that country.

#### Scenario: DNS and HTTPS checks pass from a selected country
- **GIVEN** a public FQDN resolves and its server accepts TCP connections on port 443 from an available probe in the selected country
- **WHEN** the operator requests external preflight
- **THEN** the flow reports the DNS and TCP/443 results, including the country/probe context where available

#### Scenario: External check fails and operator chooses to continue
- **GIVEN** an external DNS or TCP/443 check fails
- **WHEN** the result is shown
- **THEN** the flow explains the failed check and asks whether to continue or return to editing the deployment plan

#### Scenario: Probe coverage is unavailable or insufficient
- **GIVEN** the selected country has no available probe or the service returns no usable result
- **WHEN** the external check completes
- **THEN** the flow reports that reachability could not be determined and does not classify the VPS as blocked or reachable

#### Scenario: Public probe disclosure is explained
- **GIVEN** an external service will receive a public IP or FQDN for measurement
- **WHEN** the operator enables that check
- **THEN** the flow informs the operator that the target and measurement results may be visible to the external service or publicly retrievable before submitting the check

#### Scenario: External service is unavailable
- **GIVEN** the optional external probe API cannot be reached or rejects a request
- **WHEN** preflight handles the service error
- **THEN** it reports the diagnostic as unavailable and lets the operator continue or return without treating the service failure as a deployment failure
