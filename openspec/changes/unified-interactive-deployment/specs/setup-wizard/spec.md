# Spec Delta

## MODIFIED Requirements

### Requirement: Language selection precedes every other question
The wizard SHALL ask for the display language, Russian or English, before any other question unless `GOWAVE_WIZARD_LANG` already names one of the two, apply the choice to every message it prints afterwards, and accept only one of the two offered answers. Every other command and every non-interactive invocation SHALL remain in English.

#### Scenario: Russian wizard prints Russian prompts
- **GIVEN** the operator starts the wizard and chooses Russian
- **WHEN** the wizard asks for the deployment variant and then for host names
- **THEN** every question, validation error, warning, and summary is printed in Russian, and the English sentence that names a file path, a command, or an error echoed from a subprocess stays verbatim

#### Scenario: English wizard prints English prompts
- **GIVEN** the operator starts the wizard and chooses English
- **WHEN** the wizard runs to completion
- **THEN** every wizard message is English

#### Scenario: An unoffered answer is refused
- **GIVEN** the wizard is waiting for the language choice
- **WHEN** the operator answers anything other than one of the two offered choices
- **THEN** the wizard repeats the question and does not advance to the deployment variant

#### Scenario: Non-interactive invocation is never asked for a language
- **GIVEN** `gowave-auto.sh install` is invoked with complete positional arguments and no terminal on stdin
- **WHEN** the installer runs
- **THEN** no language question is asked and every line it prints is English

#### Scenario: Language is selected before the top-level menu
- **GIVEN** the user starts the unified interactive entrypoint without `GOWAVE_WIZARD_LANG`
- **WHEN** the interface starts
- **THEN** it requests Russian or English before displaying any operation menu or other prompt

### Requirement: Every collected name is validated in one plan
The wizard SHALL collect a Panel or worker name, a camouflage name, and an optional Vision name per host, SHALL reject a value that is not a valid DNS hostname, SHALL reject a name that another host in the same plan already uses, and SHALL finish collecting every name before the first mutation.

#### Scenario: A repeated name stops the plan
- **GIVEN** a plan in which the second node is given the camouflage name already used by the first node
- **WHEN** the wizard validates the plan
- **THEN** it reports which two hosts collide and stops before installing anything or issuing any certificate

#### Scenario: An invalid hostname is refused in place
- **GIVEN** the operator enters a name with an empty label, a label longer than 63 characters, or a character outside letters, digits, and hyphen
- **WHEN** the wizard validates that answer
- **THEN** it names the offending value, repeats the question for that field, and keeps the answers already given

#### Scenario: Vision stays optional per node
- **GIVEN** a multi-node plan
- **WHEN** the operator enables Vision for one node and declines it for another
- **THEN** the plan records Vision for exactly one node and the wizard continues without requiring it elsewhere

#### Scenario: Operator can return to a previous plan field
- **GIVEN** the operator has entered several plan values but has not confirmed deployment
- **WHEN** they choose to review or edit the plan
- **THEN** they can select any collected field, change it, and see the updated plan without recollecting unrelated values or mutating a server

#### Scenario: Back navigation does not undo server changes
- **GIVEN** deployment has started and at least one phase has completed
- **WHEN** the operator requests to go back
- **THEN** the wizard does not claim to roll back completed phases and only offers edits or actions for work that has not yet run

### Requirement: Remote node onboarding uses temporary access
The wizard SHALL onboard a remote node only after the operator confirms the presented host-key fingerprint by typing it in full, SHALL read the password without echo, SHALL authorise a temporary key that a host timer removes within two hours, SHALL run the existing node registration under that access, SHALL revoke the key and the timer when the registration ends, succeeds or not, and SHALL abort before any key is authorised when the timer cannot be installed or enabled.

#### Scenario: An incompletely typed fingerprint stops onboarding
- **GIVEN** the wizard presents the SHA-256 fingerprint of a node's host key
- **WHEN** the operator answers with a different value, a prefix, or an empty line
- **THEN** the wizard refuses that node, installs no key, runs no command on the node, and leaves the other hosts of the plan untouched

#### Scenario: A successful onboarding leaves no temporary access
- **GIVEN** the fingerprint was confirmed and the node registration succeeded
- **WHEN** the wizard finishes that node
- **THEN** the node appears in the Panel, the temporary key is absent from the node's `authorized_keys`, the expiry timer no longer exists, and the password is not retained anywhere on the Panel host

#### Scenario: A failed registration still revokes access
- **GIVEN** the temporary key was installed and the node registration exits non-zero
- **WHEN** the wizard handles that failure
- **THEN** it revokes the key and the timer before reporting the failure, and the failure message names the node

#### Scenario: The password never reaches a process argument list
- **GIVEN** the wizard is onboarding a node
- **WHEN** the Panel host's process arguments are inspected while the password is held
- **THEN** no argument of any spawned process contains the password, and the password is not written to a file that outlives the onboarding

#### Scenario: Onboarding aborts when the expiry timer cannot be installed
- **GIVEN** the wizard is onboarding a node whose expiry timer cannot be installed or enabled
- **WHEN** the wizard reaches the point where the temporary key would be authorised
- **THEN** it aborts that node before any key is written, leaves no temporary access or timer artefacts, and leaves the other hosts of the plan untouched

#### Scenario: One failed node does not stop independent nodes
- **GIVEN** a plan contains multiple remote nodes
- **WHEN** onboarding of one node fails
- **THEN** the wizard records that node's address, failed phase, and reason, continues onboarding the remaining independent nodes, and completes the Panel installation

#### Scenario: Failed nodes are summarized and can be selectively retried
- **GIVEN** one or more nodes failed while other planned work completed
- **WHEN** the onboarding batch finishes
- **THEN** the wizard lists each failed node with its address, phase, and reason and offers retry for selected failed nodes without rerunning successful nodes

#### Scenario: Partial node state is inspected before retry
- **GIVEN** retry is requested for a node whose prior attempt may have changed the Panel or remote VPS
- **WHEN** the retry flow begins
- **THEN** it diagnoses both sides, displays discovered residual state, and requires explicit operator confirmation before continuing or compensating; it performs no silent deletion
