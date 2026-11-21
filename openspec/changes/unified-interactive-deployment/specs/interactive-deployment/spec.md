# Spec Delta

## Purpose

Provides a unified interactive surface for planning GoWave deployments and adding nodes, with basic connectivity diagnostics and clear recovery choices for independent remote-node failures.

## ADDED Requirements

### Requirement: One interactive entrypoint exposes deployment and lifecycle operations
The user-facing script SHALL provide one interactive entrypoint for new Panel/local-node/remote-node deployments, adding nodes to an existing Panel, and available lifecycle operations, while preserving modular internal implementation and existing non-interactive command contracts.

#### Scenario: Operator opens the interactive entrypoint
- **WHEN** the operator launches the script with a terminal and no explicit command
- **THEN** the script selects the interface language first and presents a menu containing new deployment, add nodes to an existing Panel, and lifecycle operations

#### Scenario: Existing positional commands remain compatible
- **GIVEN** a complete existing positional invocation
- **WHEN** it is run without an interactive terminal
- **THEN** it performs no menu or language prompt and preserves the existing argument contract

### Requirement: Plan review precedes all deployment mutations
The interactive flow SHALL present a complete deployment plan and allow review and editing of any collected value before the operator confirms the first deployment mutation.

#### Scenario: Operator confirms a reviewed plan
- **GIVEN** the plan is complete and validated
- **WHEN** the operator confirms deployment
- **THEN** deployment starts using the values shown in the final plan summary

#### Scenario: Operator edits a value before confirmation
- **GIVEN** the plan has been collected but not confirmed
- **WHEN** the operator selects any plan field for editing
- **THEN** only that field and dependent validations are recomputed, the updated plan is shown, and no server has yet been modified

### Requirement: A node failure does not cancel independent deployment work
The deployment flow SHALL treat each planned remote-node onboarding as an independently reportable operation and continue unrelated planned work after an individual node failure.

#### Scenario: One remote node fails during a multi-node deployment
- **GIVEN** the Panel deployment and several remote nodes are planned
- **WHEN** one remote node fails onboarding
- **THEN** Panel deployment and other independent node operations continue, and the failed node is recorded with its target, phase, and diagnostic reason

#### Scenario: All node attempts finish
- **GIVEN** one or more remote nodes failed
- **WHEN** the batch completes
- **THEN** the final report distinguishes successful and failed nodes and offers a selective retry of failed nodes only

### Requirement: Retry handles partial state explicitly
The retry flow SHALL inspect possible partial Panel and VPS state and require operator confirmation before continuing or compensating any failed node attempt.

#### Scenario: Retry finds partial state
- **GIVEN** a prior node attempt may have left state on the Panel or VPS
- **WHEN** the operator starts a retry
- **THEN** the flow reports discovered state on both sides and waits for an explicit choice before any cleanup or continuation

#### Scenario: Retry finds no partial state
- **GIVEN** diagnostics find no state from a previous attempt
- **WHEN** the retry flow presents its findings
- **THEN** it identifies that no relevant partial state was found and asks for confirmation before retrying
