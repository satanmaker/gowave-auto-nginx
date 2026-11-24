# Spec Delta

## ADDED Requirements

### Requirement: Interactive navigation preserves readable screens
The menu SHALL keep status and terminal operation results visible until the operator explicitly returns. Plan review SHALL distinguish start, edit Panel, edit a selected node and cancel before mutation. Return after mutation SHALL NOT imply undo or retry. Positional commands SHALL NOT acquire a pause.

#### Scenario: Status remains readable
- **WHEN** status finishes from the menu, including a degraded health result
- **THEN** findings and a localized return prompt remain visible until input; Enter returns to the menu without asking for language again.

#### Scenario: Edit or abandon a reviewed plan
- **WHEN** the operator edits the second node and then cancels at review
- **THEN** unrelated answers remain, dependent checks rerun and no server has been changed.

### Requirement: Onboarding reports live stages and verified results
Both interactive install and add-node SHALL identify the node and current stage before waiting on SSH, input, installation or verification. Final results SHALL distinguish Panel state and each node's verified registration or failed stage, safe reason and next action. A completed Panel step SHALL NOT announce overall completion while nodes remain.

#### Scenario: Mixed batch result
- **WHEN** one of two workers fails after Panel installation
- **THEN** the wizard shows Panel installed, one of two registered, both node names and the failure reason; retry targets only failed nodes under the existing partial-state inspection contract, and returning leaves completed work alone.

#### Scenario: Adding a single node
- **WHEN** an existing Panel accepts or refuses a node
- **THEN** the wizard reports the result as a node addition, not a Panel installation; success requires matching Panel readback and does not claim a verified data path. Failure is not hidden by menu redraw or replaced by a generic shell trap.

#### Scenario: Interaction while a worker is running
- **WHEN** host-key confirmation or a hidden password is required
- **THEN** the operator sees the prompt before input is read, no password is echoed, and no raw credential-bearing subprocess output is used as progress.
