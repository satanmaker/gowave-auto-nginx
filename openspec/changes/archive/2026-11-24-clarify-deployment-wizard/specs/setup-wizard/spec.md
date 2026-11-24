# Spec Delta

## ADDED Requirements

### Requirement: Topology choices describe placement and failure isolation
The RU and EN menus SHALL distinguish deploying a Panel from connecting a remote server to an existing Panel. The topology menu SHALL require an explicit selection, describe what runs here versus on other servers, and provide a return action.

#### Scenario: Compare three schemes
- **WHEN** the operator opens new deployment
- **THEN** local Panel plus node is labelled for evaluation and personal use only; Panel here plus remote nodes is recommended for failure isolation; local Panel plus local and remote nodes is not recommended because a single host failure takes out the Panel and one node. No option promises automatic failover.

### Requirement: Questions reflect the role and preserve prior answers
The wizard SHALL identify the current server role, remote node ordinal and total, distinguish the certificate contact from Panel login and the display name from DNS, and ask traffic-profile questions only for traffic nodes. On invalid input it SHALL explain the constraint and reprompt the offending field before proceeding.

#### Scenario: Conflicting cover domain on the second worker
- **WHEN** the operator enters its primary domain again as its cover domain
- **THEN** the wizard names the conflicting role and repeats only the cover-domain prompt before asking about Vision; language, Panel, first worker and current worker answers remain intact.

#### Scenario: Panel-only local server
- **WHEN** the operator chooses a Panel here and nodes elsewhere
- **THEN** the wizard does not ask for local node name, country or local Vision and still offers optional Vision separately for each remote node, including a node added later.

### Requirement: Node names are operator-selected and unique
The wizard SHALL accept a separate name for each local and remote node, trim surrounding whitespace, reject blank or duplicate names, and show the accepted name on review. It SHALL check the entire pending plan and, when adding to an existing Panel, the verified Panel inventory before registration.

#### Scenario: Collision within a new plan
- **WHEN** a remote node is given the local node's name padded with spaces
- **THEN** the wizard identifies the owner and requests another name without discarding other answers.

#### Scenario: Adding to an existing Panel
- **WHEN** the requested name already exists or inventory cannot be verified
- **THEN** a collision requests a new name; failed verification offers retry or return, without claiming the name is free or changing the remote server.
