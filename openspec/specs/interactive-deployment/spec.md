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
The flow SHALL record every planned node's final state and recompute the final exit after retries. Exit zero SHALL require verified readiness of all planned components and required cleanup/security controls. A ready Panel with any failed or indeterminate node SHALL use a distinct partial-success code, including when no remote node succeeded. Failed-node retry SHALL be offered regardless of successful sibling count.

#### Scenario: Complete success exits zero
- **GIVEN** every planned node has verified registration and required readiness and cleanup checks passed
- **WHEN** the command ends
- **THEN** it exits zero and reports each node's actual verified scope without claiming untested traffic compatibility.

#### Scenario: Partial success is distinguishable from both outcomes
- **GIVEN** the Panel installation succeeded and one of three planned nodes failed
- **WHEN** the command ends
- **THEN** it exits with the partial-success code, distinct from Panel failure, and reports one failed and two registered nodes.

#### Scenario: Only remote node fails
- **GIVEN** Panel and local Node succeeded but the single remote Node failed
- **WHEN** the first batch finishes
- **THEN** a selective retry is offered for that node and declining it returns partial success, not Panel failure.

#### Scenario: Retry repairs all failures
- **WHEN** confirmed retry makes every component ready and required cleanup succeeds
- **THEN** the report and exit are recomputed from final states and the earlier failed attempt does not force a nonzero exit.
### Requirement: Interactive navigation preserves readable screens

The menu SHALL keep status and terminal operation results visible until the operator explicitly returns. Plan review SHALL distinguish start, edit Panel, edit a selected node and cancel before mutation. Return after mutation SHALL NOT imply undo or retry. Positional commands SHALL NOT acquire a pause.

#### Scenario: Status remains readable

- **WHEN** status finishes from the menu, including a degraded health result
- **THEN** findings and a localized return prompt remain visible until input; Enter returns to the menu without asking for language again.

#### Scenario: Edit or abandon a reviewed plan

- **WHEN** the operator edits the second node and then cancels at review
- **THEN** unrelated answers remain, dependent checks rerun and no server has been changed.

### Requirement: Onboarding reports live stages and verified results
Interactive install and add-node SHALL display node identity and current stage before SSH, input, installation, verification and cleanup waits, including after country entry. Each wait SHALL have a documented finite budget and safe progress output. Final reports SHALL separate Panel and node outcomes, failed stage, reason and next action, remain readable until return and never expose raw credential-bearing output.

#### Scenario: Mixed batch result
- **WHEN** one of two workers fails after Panel installation
- **THEN** the wizard shows Panel installed, one of two registered, node names and failure reason; retry targets only failed work and returning preserves completed work.

#### Scenario: Adding a single node
- **WHEN** an existing Panel accepts or refuses a node
- **THEN** the result is described as a node addition, success requires matching Panel readback, no untested data-path success is claimed and menu redraw does not hide the report.

#### Scenario: Interaction while a worker is running
- **WHEN** host-key confirmation or a hidden password is required
- **THEN** the prompt is visible before reading input, passwords are not echoed and credential-bearing subprocess output is not used as progress.

#### Scenario: Country entry precedes slow remote installation
- **WHEN** country is accepted and remote setup is still running
- **THEN** visible safe stages identify registration, remote deployment, verification and access cleanup, with timeout reported against the correct node rather than silent termination.

#### Scenario: No controlling terminal
- **WHEN** operation progress cannot use a controlling terminal
- **THEN** safe stage events and the terminal result still reach the operation's documented output sink instead of being silently discarded; positional commands acquire no interactive pause.

### Requirement: Durable secret-free deployment draft
The interactive flow SHALL persist accepted non-secret answers and reviewed plan revisions atomically with restrictive permissions. Restart and correctable preflight errors SHALL offer continuation or targeted correction without recollecting unrelated answers. Passwords, tokens, private keys and temporary SSH access SHALL NOT be retained in the draft.

#### Scenario: Restart during collection
- **WHEN** the process stops after accepting the second remote node's domain
- **THEN** a new invocation offers the saved draft, restores accepted non-secret answers after operator selection and asks again for any needed credentials.

#### Scenario: Correctable plan failure
- **WHEN** domain, name, DNS or certificate-budget validation fails before execution
- **THEN** the offending field and reason are shown, correction preserves other answers and dependent checks rerun before review.

#### Scenario: Abandon draft
- **WHEN** the operator selects a new plan instead of continuing
- **THEN** abandoning the draft does not uninstall, compensate or rerun any completed deployment operation.

### Requirement: Resume reconciles durable operation checkpoints
The flow SHALL checkpoint each Panel, local-node and remote-node operation and reconcile its actual state before confirmed continuation. A saved success alone SHALL NOT justify skipping verification or replaying mutations. Unreachable, incompatible or ambiguous state SHALL stop that operation with a recovery route while preserving independent completed work.

#### Scenario: Resume mixed topology
- **GIVEN** Panel and local Node are verified and the remote attempt was interrupted
- **WHEN** a new invocation resumes the reviewed plan
- **THEN** existing successful components are checked without reinstalling them, remote partial state is inspected under the temporary-access contract and only confirmed pending work runs.

#### Scenario: Changed installer or actual state
- **WHEN** a checkpoint schema is incompatible or readback conflicts with saved identity
- **THEN** automatic continuation is refused with the specific mismatch and a safe recovery path, without deleting or adopting unrelated resources.

### Requirement: Mandatory failures survive interactive operation boundaries
Interactive execution SHALL preserve mandatory-step failure and compensation semantics. A failed prerequisite SHALL prevent dependent mutations even when the menu captures its exit status. Final status SHALL distinguish deployment readiness, verification uncertainty and cleanup failure; a generic menu handler SHALL NOT replace the operation diagnosis.

#### Scenario: Nested mandatory step fails under the menu
- **WHEN** a required local-node or firewall step fails inside a menu-started deployment
- **THEN** dependent phases do not run, required compensation executes once and a readable failed-stage report remains until return.

#### Scenario: Cleanup fails after registration
- **WHEN** Panel readback confirms registration but temporary-access removal cannot be verified
- **THEN** registration and cleanup are reported separately, overall completion is nonzero and retry does not blindly create a duplicate node.
