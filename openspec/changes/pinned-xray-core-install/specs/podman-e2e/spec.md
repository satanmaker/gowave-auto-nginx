# Spec Delta

## ADDED Requirements

### Requirement: Node installation is proven without the GitHub API

An acceptance run SHALL be able to prove that node installation needs no request to `api.github.com` by making that host unreachable on the deployment contour, and SHALL distinguish that proof from a run that merely happened to have quota left.

#### Scenario: A blocked API contour still installs the node

- **GIVEN** an acceptance topology whose containers resolve `api.github.com` to an address nothing answers on
- **WHEN** node installation runs with `XRAY_SERVER_VERSION` unset or naming the pin
- **THEN** the installation succeeds, the core interrogated inside the node's container reports the pinned version, and the step's own record names the pinned archive digest

#### Scenario: The opt-out control fails on the same contour

- **GIVEN** the same blocked contour and a host with no installed core, so the upstream installer would have to fetch one
- **WHEN** node installation runs with `XRAY_SERVER_VERSION=latest`
- **THEN** the installation fails naming the blocked host, no `rw-core` is created, and the passing run is shown to have exercised the pinned path rather than an unreachable one

#### Scenario: Evidence is read from the installed side

- **GIVEN** a passing blocked-API run
- **WHEN** its evidence is written
- **THEN** it records the version read from the installed core inside the node's container, the archive digest the step verified, and the run's commit — three separate facts, because the pin names the release archive and the installed binary has no digest of its own
