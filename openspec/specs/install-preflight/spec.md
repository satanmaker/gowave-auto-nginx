# install-preflight Specification

## Purpose

Defines what the installer proves about a requested deployment before it changes the host: that the operator can reach each target for provisioning, and that the public names and served endpoints of the deployment appear reachable from where its users are.

## Requirements

### Requirement: SSH reachability is checked from the operator host before deployment

The interactive deployment flow SHALL verify, before the first deployment mutation, that each planned remote VPS answers with an SSH service on its configured address and port from the operator host. The check SHALL be unauthenticated and SHALL NOT request a password or authorise a key. An unreachable target SHALL be reported with an offer to edit the plan or continue without that node. Non-interactive invocations SHALL keep their current behaviour.

#### Scenario: SSH preflight passes for each remote VPS

- **GIVEN** all remote VPS addresses and SSH settings are valid and reachable
- **WHEN** the operator runs preflight
- **THEN** each remote target is reported reachable and deployment may proceed after plan confirmation

#### Scenario: SSH preflight failure does not silently drop a node

- **GIVEN** a planned remote VPS cannot be reached over SSH from the operator host
- **WHEN** preflight runs
- **THEN** it identifies the target and connection failure before deployment mutations and offers plan editing or an explicit decision to continue without that node

#### Scenario: A password-only host is not reported unreachable

- **GIVEN** a planned remote VPS accepts only password authentication and no key is authorised yet
- **WHEN** preflight contacts it
- **THEN** the target is reported reachable, and no password is requested and no key is written during the check

#### Scenario: A host key that differs from the plan is reported

- **GIVEN** the plan already carries a host-key fingerprint for a target
- **WHEN** the target presents a different host key during preflight
- **THEN** the flow reports the mismatch for that target and does not treat it as reachable

### Requirement: External checks require explicit consent and never decide the deployment

The flow SHALL submit a target to an external measurement provider only after the operator explicitly consents to that submission, SHALL make no third-party request when consent is declined or the provider is not enabled, and SHALL never treat an external result as a deployment failure or as proof of country-wide reachability.

#### Scenario: Disclosure comes before the first request

- **GIVEN** an external service would receive a public IP or FQDN for measurement
- **WHEN** the operator reaches the external check
- **THEN** the flow states that the target and measurement results may be visible to that service or publicly retrievable, and asks for consent before submitting anything

#### Scenario: Declining the check sends nothing

- **GIVEN** the operator is asked to consent to the external check
- **WHEN** they decline
- **THEN** no request is made to any external provider, the flow reports that no external check ran, and deployment continues

#### Scenario: A build without an enabled provider stays silent

- **GIVEN** the external provider was not enabled for this build
- **WHEN** the operator reaches the external check
- **THEN** the flow states that no external check is available, makes no third-party request, and leaves the deployment path unchanged

### Requirement: External checks cover DNS and served ports only, from a selected country

The flow SHALL resolve each configured public FQDN from a country the operator selects and SHALL probe TCP only on a port that is served when the check runs: the SSH port before installation, and port 443 only once a listener exists, as on an existing Panel or after installation. It SHALL report the country and probe context, SHALL NOT scan unrelated ports, and SHALL distinguish an unavailable provider from insufficient probe coverage.

#### Scenario: DNS and served-port checks pass from a selected country

- **GIVEN** a public FQDN resolves and its server accepts TCP connections on a served port from an available probe in the selected country
- **WHEN** the operator requests external preflight
- **THEN** the flow reports the DNS and TCP results, including the country and probe context where available

#### Scenario: External check fails and operator chooses to continue

- **GIVEN** an external DNS or TCP check fails
- **WHEN** the result is shown
- **THEN** the flow explains the failed check, does not classify the deployment as blocked, and asks whether to continue or return to editing the deployment plan

#### Scenario: Port 443 is not probed before it is served

- **GIVEN** a fresh deployment whose HTTPS listener does not exist yet because installation has not run
- **WHEN** the external check runs before the first mutation
- **THEN** the flow probes only the port served at that moment and does not report port 443 as blocked or unreachable

#### Scenario: Probe coverage is insufficient

- **GIVEN** the selected country has no available probe or the service returns no usable result
- **WHEN** the external check completes
- **THEN** the flow reports that reachability could not be determined, does not classify the VPS as blocked or reachable, and offers continuing or returning to editing

#### Scenario: External service is unavailable

- **GIVEN** the external probe API cannot be reached or rejects a request
- **WHEN** preflight handles the service error
- **THEN** it reports the diagnostic as unavailable, distinct from insufficient coverage, and lets the operator continue or return without treating the service failure as a deployment failure
