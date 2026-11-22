# Spec Delta

## ADDED Requirements

### Requirement: Pinned Xray Core Delivery Before the Upstream Installer

Before the upstream GoWave Node installer runs, the orchestrator SHALL install the pinned Xray core at `<install_dir>/rw-core` from a release artifact whose SHA-256 matches the pin for the host architecture. Because an executable `rw-core` makes the upstream installer skip its own core installation, a node install SHALL complete without any request to `api.github.com`.

#### Scenario: Node installation completes while the GitHub API is unreachable

- **GIVEN** a host where `api.github.com` is unreachable and no Xray core is installed
- **WHEN** node installation runs with `XRAY_SERVER_VERSION` unset
- **THEN** installation succeeds, `<install_dir>/rw-core` reports the pinned version, and no `core install` request is made

#### Scenario: The upstream installer finds a runnable core and does not fetch one

- **GIVEN** the pinned core is already installed at `<install_dir>/rw-core` and executable
- **WHEN** the upstream installer runs
- **THEN** it skips its own core installation step and starts the node with that core

#### Scenario: A core that fails verification is never installed

- **GIVEN** a release artifact whose bytes do not match the pinned SHA-256
- **WHEN** the pinned core step fetches it
- **THEN** no `rw-core` is created and the installation stops with the mismatch named

### Requirement: Single Meaning for Each XRAY_SERVER_VERSION Value

`XRAY_SERVER_VERSION` SHALL have exactly one meaning per value: unset installs the pinned core; `latest` delegates the core to the upstream installer as an explicit opt-out; any other version is left to the upstream installer and the existing explicit-version path. The pin SHALL be Xray 26.11.9, the release verified against mihomo 1.19.34 for REALITY.

#### Scenario: An unset version installs the pin

- **GIVEN** `XRAY_SERVER_VERSION` is unset or empty
- **WHEN** node installation runs
- **THEN** the installed core is 26.11.9 and the upstream core installation is skipped

#### Scenario: latest opts out of the pin

- **GIVEN** `XRAY_SERVER_VERSION` is `latest`
- **WHEN** node installation runs
- **THEN** the pinned step does not install a core and the upstream installer selects the core itself

#### Scenario: An explicit foreign version is not overridden

- **GIVEN** `XRAY_SERVER_VERSION` names a version other than the pin
- **WHEN** node installation runs
- **THEN** the pinned step does not act and the requested version is handled by the explicit-version path

### Requirement: Version-Based Idempotency of the Pinned Core Step

The pinned core step SHALL treat an installed core as satisfied only when its reported version contains the pinned version. A core whose version differs SHALL be replaced, and a repeat installation that already finds the pinned version SHALL not download the artifact again.

#### Scenario: A repeat installation does not download the core again

- **GIVEN** a host whose `rw-core` already reports the pinned version
- **WHEN** node installation runs again
- **THEN** no artifact is downloaded and the running core is left untouched

#### Scenario: A foreign core is replaced instead of accepted

- **GIVEN** a host whose `rw-core` reports a different version than the pin
- **WHEN** node installation runs with the default version
- **THEN** the pinned core is installed in its place before the upstream installer runs

### Requirement: Fail-Closed Delivery on the Pinned Path

When the pinned artifact cannot be delivered or fails verification, node installation SHALL fail with a message naming the artifact and the pinned version, and SHALL name `XRAY_SERVER_VERSION=latest` as the opt-out. The step SHALL NOT hand the installation to the upstream core installation path, because that path is the API dependency this change removes.

#### Scenario: An unavailable artifact stops the installation

- **GIVEN** no artifact host can deliver the pinned core
- **WHEN** node installation runs with the default version
- **THEN** installation fails, the failure names the pinned version and `XRAY_SERVER_VERSION=latest`, and no upstream core installation is attempted

#### Scenario: The failure is reported once and located

- **GIVEN** the pinned artifact cannot be delivered
- **WHEN** node installation fails
- **THEN** the run reports the failing step and its exit status exactly once, as the installer's other failures do

### Requirement: One Authoritative Core Pin Table

The product SHALL keep one table mapping a supported (version, architecture) pair to an artifact URL and SHA-256 digest, the same digest the acceptance matrix pins for that client. An unknown version or architecture SHALL make the pinned step abstain rather than select a near-matching artifact.

#### Scenario: The product pin and the acceptance matrix name the same bytes

- **GIVEN** the product pin table and `tests/cases/matrix.yaml`
- **WHEN** both are read for the supported version and architecture
- **THEN** they state the same URL and the same SHA-256 digest

#### Scenario: An unsupported architecture is not guessed

- **GIVEN** a host whose architecture the pin table does not describe
- **WHEN** node installation runs with the default version
- **THEN** the pinned step does not install a core and the reason is reported
