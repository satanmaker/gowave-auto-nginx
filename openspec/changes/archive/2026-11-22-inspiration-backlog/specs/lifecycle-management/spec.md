# Spec Delta

## ADDED Requirements

### Requirement: Certificate lineage is selected by coverage

When an existing certificate lineage already covers a requested name, the installer SHALL use that lineage's
live directory for the vhost and for renewal, even when the lineage's certificate name differs from the
requested name. Reuse SHALL remain subject to the existing ACME-directory match.

#### Scenario: A suffixed lineage is adopted

- **GIVEN** a lineage whose certificate name carries a suffix but whose certificate covers the requested name
- **WHEN** the installer provisions that name
- **THEN** the vhost references that lineage's `live/` directory, no second lineage is created for the same
  name, and the served certificate covers the name

#### Scenario: A covering lineage from another ACME directory is not adopted

- **GIVEN** the only lineage covering the name was issued by the other ACME directory
- **WHEN** the installer runs with the selected directory
- **THEN** it does not reuse that lineage and does not mix the two, failing closed or provisioning a separately
  named lineage as the existing isolation requires

#### Scenario: Several covering lineages are resolved deterministically

- **GIVEN** more than one lineage covers the requested name
- **WHEN** the installer selects one
- **THEN** the choice is decided by a stated rule, recorded in the run output, and repeated identically on a
  second run with the same input

#### Scenario: A lineage that does not cover the name is not adopted

- **WHEN** an existing lineage's certificate names the requested name only as an unrelated suffix or not at all
- **THEN** it is not used for that name

### Requirement: Release artifacts are acquired through verified mirrors

Every artifact the installer downloads SHALL be fetched through an ordered list of hosts and verified against
its mandatory digest before it is executed or installed. A digest mismatch SHALL abort the run and SHALL NOT be
resolved by trying another host.

#### Scenario: A failed host falls through to the next

- **GIVEN** the first host in the list answers 404 or is unreachable
- **WHEN** the same artifact is requested
- **THEN** the next host is tried, the fetched bytes are verified, and the run continues

#### Scenario: A mismatched digest aborts

- **WHEN** a host returns bytes whose digest differs from the pinned or published value
- **THEN** the artifact is discarded, the run fails, and no further host is tried

#### Scenario: No host answers

- **WHEN** every host in the list fails
- **THEN** the run fails naming the artifact and the hosts that were tried

#### Scenario: A locally supplied artifact is verified the same way

- **GIVEN** an artifact supplied from disk instead of over the network
- **WHEN** it is used
- **THEN** the same mandatory digest check applies

### Requirement: Node onboarding accepts an environment contract

`node add` SHALL accept each of its inputs from a named environment variable as well as from a positional
argument, with an explicitly given positional taking precedence, identical validation on both paths, and no
secret added to the process arguments or to the environment.

#### Scenario: An environment-only invocation deploys the same node

- **GIVEN** every input supplied through its environment variable
- **WHEN** `node add` runs
- **THEN** the resulting Worker and Panel record are identical to the positional invocation

#### Scenario: A positional takes precedence

- **WHEN** an input is given both positionally and through its variable
- **THEN** the positional value is used and the variable is not applied

#### Scenario: An invalid environment value is rejected on its field

- **WHEN** an environment value is not a valid name, address, port or domain
- **THEN** the command fails naming that field, exactly as the positional path does

#### Scenario: The Worker secret never becomes an argument

- **WHEN** the command runs with either input style
- **THEN** the secret is delivered over a file descriptor or standard input and appears in neither `argv` nor
  the environment

### Requirement: A failing lifecycle command names the step

`install`, `node add`, `domain-change` and `uninstall` SHALL report the step in progress, the command that
failed and its exit status when an unexpected failure aborts the run. That report SHALL NOT repeat compensation
an explicit step already performed.

#### Scenario: A mid-install failure is located

- **GIVEN** a step of `install` fails unexpectedly
- **WHEN** the command aborts
- **THEN** the output names the step, the failing command and the exit status, and the command still exits
  non-zero

#### Scenario: Compensation still runs once

- **GIVEN** a failing step whose own handler already rolled back what it created
- **WHEN** the command aborts
- **THEN** the failure is reported and no second rollback is attempted

#### Scenario: A successful run reports no failure

- **WHEN** the command completes successfully
- **THEN** no failure report is printed and the exit status is zero
