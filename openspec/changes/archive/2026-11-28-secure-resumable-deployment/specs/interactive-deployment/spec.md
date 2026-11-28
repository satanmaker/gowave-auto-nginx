# Spec Delta

## ADDED Requirements

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

## MODIFIED Requirements

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
