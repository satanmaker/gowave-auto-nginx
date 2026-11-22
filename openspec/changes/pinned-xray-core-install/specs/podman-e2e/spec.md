# Spec Delta

## ADDED Requirements

### Requirement: Node installation is proven without the GitHub API

An acceptance run SHALL be able to prove that node installation needs no request to `api.github.com` by making that host unreachable on the deployment contour, and SHALL distinguish that proof from a run that merely happened to have quota left.

#### Scenario: A blocked API contour still installs the node

- **GIVEN** an acceptance topology whose containers resolve `api.github.com` to an unreachable address
- **WHEN** node installation runs with `XRAY_SERVER_VERSION` unset
- **THEN** the installation succeeds and the core reported from inside the node's container matches the pinned digest

#### Scenario: The opt-out control fails on the same contour

- **GIVEN** the same blocked contour
- **WHEN** node installation runs with `XRAY_SERVER_VERSION=latest`
- **THEN** the installation fails, showing that the passing run exercised the pinned path rather than an unreachable one

#### Scenario: Evidence is read from the installed side

- **GIVEN** a passing blocked-API run
- **WHEN** its evidence is written
- **THEN** it records the digest and version of the installed core as read inside the node's container, and the run's commit, rather than a conclusion drawn from the installer's log alone
