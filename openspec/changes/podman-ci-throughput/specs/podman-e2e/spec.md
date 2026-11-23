# Spec Delta

## ADDED Requirements

### Requirement: Harness ceilings never decide a product verdict

A container command ceiling MUST be sized to the work it bounds and MUST be capped by the run's remaining budget, so it can fire inside the run. A ceiling or budget that fires MUST be published as INCOMPLETE or a named harness limit, never as a product FAIL, and a case whose evidence a timeout cut short MUST NOT assert about that evidence.

#### Scenario: A slow legitimate step keeps its ceiling

- **GIVEN** a deployment step whose work — an image pull, or a package install inside an image build — legitimately outlasts the default container command ceiling
- **WHEN** the harness runs that step
- **THEN** the command carries a ceiling sized for that work and no larger than the run's remaining budget
- **AND** a step that completes inside its ceiling produces no verdict about the product from the harness clock

#### Scenario: A budget kill inside a cleanup probe stays INCOMPLETE

- **GIVEN** a run whose remaining budget expires while a case is restoring a configuration it changed
- **WHEN** the case is finished
- **THEN** the case reports INCOMPLETE naming the exhausted budget
- **AND** the restore is still attempted
- **AND** the deadline is not converted into a failed assertion about the restored configuration

#### Scenario: A ceiling that fires names its own limit

- **GIVEN** a command that outlasts even the ceiling sized for it
- **WHEN** the case ends
- **THEN** the verdict names the command and the ceiling that fired
- **AND** it does not present the timeout as a defect in the product

## MODIFIED Requirements

### Requirement: Trustworthy result and diagnostics

Every case MUST produce structured evidence and sanitized diagnostics. Unexpected skips, blocked cases, or partial execution MUST NOT be reported as a successful acceptance run. A case that needs a successful installation MUST gate on it and MUST report BLOCKED when no installation succeeded, instead of asserting about a host that was never installed.

#### Scenario: Secret redaction

- **WHEN** diagnostics contain known sentinel credentials or private material
- **THEN** exported reports and artifacts contain no occurrence of those sentinels

#### Scenario: Unexpected skip

- **WHEN** a required case is skipped or blocked without an approved NOT_APPLICABLE rationale
- **THEN** the acceptance suite fails or reports INCOMPLETE, never PASS

#### Scenario: Install-dependent case without a successful installation

- **GIVEN** a run in which the installation failed or never executed
- **WHEN** a case that needs the installed host runs
- **THEN** that case reports BLOCKED naming the install case it depends on
- **AND** the installation failure is reported once, by the install case, rather than again as a defect in whatever the dependent case would have inspected
