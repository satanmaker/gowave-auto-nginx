# interactive-deployment Specification

## Purpose

Gives the operator one interactive route to plan and run a GoWave deployment or an add-nodes operation, keeps the plan editable until the first mutation, and reports and retries each remote-node failure without cancelling the rest of the work.

## Requirements

### Requirement: One interactive entrypoint exposes deployment and lifecycle operations

The user-facing script SHALL provide one interactive entrypoint for new Panel, local-node, and remote-node deployments, for adding nodes to an existing Panel, and for the available lifecycle operations, while preserving modular internal implementation and the existing non-interactive command contracts.

#### Scenario: Operator opens the interactive entrypoint

- **GIVEN** the operator launches the script with a terminal and no explicit command
- **WHEN** the interface starts
- **THEN** it presents one menu containing new deployment, add nodes to an existing Panel, and the lifecycle operations, and prints no installation output before that menu

#### Scenario: Existing positional commands remain compatible

- **GIVEN** a complete existing positional invocation
- **WHEN** it is run without an interactive terminal
- **THEN** it performs no menu or language prompt and preserves the existing argument contract

### Requirement: Plan review precedes all deployment mutations

The interactive flow SHALL present a complete deployment plan and allow review and editing of any collected value before the operator confirms the first deployment mutation. After the first mutation it SHALL offer edits only for work that has not yet run and SHALL NOT claim to undo a completed phase.

#### Scenario: Operator confirms a reviewed plan

- **GIVEN** the plan is complete and validated
- **WHEN** the operator confirms deployment
- **THEN** deployment starts using the values shown in the final plan summary

#### Scenario: Operator edits a value before confirmation

- **GIVEN** the plan has been collected but not confirmed
- **WHEN** the operator selects any plan field for editing
- **THEN** only that field and dependent validations are recomputed, the updated plan is shown, and no server has yet been modified

#### Scenario: Going back after deployment started changes nothing already done

- **GIVEN** deployment has started and at least one phase has completed
- **WHEN** the operator asks to go back
- **THEN** no completed phase is re-run, no compensating action is executed, and the flow offers only edits or choices for work that has not yet run

### Requirement: A node failure does not cancel independent deployment work

The deployment flow SHALL treat each planned Panel or remote-node operation as independently reportable, SHALL continue unrelated planned work after an individual remote-node failure, and SHALL finish and report the Panel installation even when a node failed.

#### Scenario: One remote node fails during a multi-node deployment

- **GIVEN** the Panel deployment and several remote nodes are planned
- **WHEN** one remote node fails onboarding
- **THEN** Panel deployment and other independent node operations continue, and the failed node is recorded with its target, phase, and diagnostic reason

#### Scenario: All node attempts finish

- **GIVEN** one or more remote nodes failed
- **WHEN** the batch completes
- **THEN** the final report distinguishes successful and failed nodes and offers a selective retry of failed nodes only

### Requirement: Retry handles partial state explicitly

The retry flow SHALL inspect possible partial Panel and VPS state and require operator confirmation before continuing or compensating any failed node attempt. A retry SHALL NOT re-run sibling nodes that already succeeded.

#### Scenario: Retry finds partial state

- **GIVEN** a prior node attempt may have left state on the Panel or VPS
- **WHEN** the operator starts a retry
- **THEN** the flow reports discovered state on both sides and waits for an explicit choice before any cleanup or continuation

#### Scenario: Retry finds no partial state

- **GIVEN** diagnostics find no state from a previous attempt
- **WHEN** the retry flow presents its findings
- **THEN** it identifies that no relevant partial state was found and asks for confirmation before retrying

#### Scenario: Retry stops when state cannot be established

- **GIVEN** the transaction journal cannot be read or the node cannot be inspected
- **WHEN** the retry flow finishes its diagnosis
- **THEN** it stops that retry, preserves the discovered state unchanged, and presents the manual recovery route instead of retrying or cleaning up

### Requirement: Retry inspection uses the onboarding access contract

When a retry inspects a remote VPS, it SHALL establish access exactly as onboarding does — a host-key fingerprint the operator types in full, a password read without echo, and a temporary key the host timer removes — and SHALL NOT reuse or cache credentials from the earlier attempt.

#### Scenario: Retry asks for the fingerprint again

- **GIVEN** a retry needs to inspect a remote VPS whose earlier attempt used temporary access
- **WHEN** the inspection starts
- **THEN** the flow presents the host-key fingerprint for that attempt and requires it to be typed in full before any key or password reaches the host

#### Scenario: An interrupted retry leaves no temporary access

- **GIVEN** a retry inspection is interrupted after access was authorised
- **WHEN** the flow exits
- **THEN** the temporary key and its expiry timer are removed from the node and no password remains on the Panel host

### Requirement: Partial node success has its own reported status and exit code

The deployment flow SHALL record a final state for every planned node and SHALL exit zero only when every planned node was registered. When the Panel installation succeeded and at least one node failed, it SHALL exit with a code distinct from the code used for a failed Panel installation and SHALL print the per-node summary.

#### Scenario: Complete success exits zero

- **GIVEN** every planned node registered successfully
- **WHEN** the command ends
- **THEN** it exits zero and every node is reported as registered

#### Scenario: Partial success is distinguishable from both outcomes

- **GIVEN** the Panel installation succeeded and one of three planned nodes failed
- **WHEN** the command ends
- **THEN** it exits with the partial-success code, which differs from a failed Panel installation, and the summary reports one failed and two registered nodes

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
