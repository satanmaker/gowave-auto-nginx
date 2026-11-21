# Spec Delta

## ADDED Requirements

### Requirement: The unified menu can add nodes to an existing Panel
The interactive entrypoint SHALL offer adding remote nodes to an existing Panel without requiring a new Panel installation, and SHALL verify the selected Panel/API before collecting or applying node changes.

#### Scenario: A local Panel is detected
- **GIVEN** a local GoWave Panel is installed and its API is available
- **WHEN** the operator chooses to add nodes
- **THEN** the flow identifies the local Panel, confirms the target, and proceeds to node planning

#### Scenario: No local Panel or multiple candidates are found
- **GIVEN** no usable local Panel is detected or the target is ambiguous
- **WHEN** the operator chooses to add nodes
- **THEN** the flow asks for the Panel address, verifies connectivity and API identity, and proceeds only after the target is confirmed

#### Scenario: The selected Panel cannot be verified
- **GIVEN** the entered Panel address does not answer the expected API check
- **WHEN** target validation runs
- **THEN** the flow reports the failed verification and does not begin remote node mutations
