# Spec Delta

## ADDED Requirements

### Requirement: The unified menu can add nodes to an existing Panel

The interactive entrypoint SHALL offer adding remote nodes to an existing Panel without requiring a new Panel installation, and SHALL verify the selected Panel/API before collecting or applying node changes. For a Panel that is not on the local host, it SHALL use HTTPS with certificate validation or an explicitly confirmed certificate fingerprint, and SHALL send credentials only after that identity check has passed.

#### Scenario: A local Panel is detected

- **GIVEN** a local GoWave Panel is installed and its API is available
- **WHEN** the operator chooses to add nodes
- **THEN** the flow identifies the local Panel, confirms the target, and proceeds to node planning

#### Scenario: No local Panel or multiple candidates are found

- **GIVEN** no usable local Panel is detected or the target is ambiguous
- **WHEN** the operator chooses to add nodes
- **THEN** the flow asks for the Panel address, verifies connectivity and API identity over the verified channel, and proceeds only after the target is confirmed

#### Scenario: The selected Panel cannot be verified

- **GIVEN** the entered Panel address does not answer the expected API check
- **WHEN** target validation runs
- **THEN** the flow reports the failed verification and does not begin remote node mutations

#### Scenario: An unverified certificate or a plaintext address is refused

- **GIVEN** a remote Panel presents a certificate that does not match the expected name and is not an explicitly confirmed fingerprint, or answers only over plaintext HTTP
- **WHEN** the operator tries to target it
- **THEN** the flow refuses the target before any credential is sent and reports why the channel was rejected
