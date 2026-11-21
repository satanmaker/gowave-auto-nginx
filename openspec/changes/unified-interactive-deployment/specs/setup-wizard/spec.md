# Spec Delta

## MODIFIED Requirements

### Requirement: Language selection precedes every other question
The interactive entrypoint SHALL ask for the display language, Russian or English, before any other question and before displaying any menu, unless `GOWAVE_WIZARD_LANG` already names one of the two, apply the choice to every message the interactive surface prints afterwards, and accept only one of the two offered answers. Every non-interactive invocation and every command reached without the interactive menu SHALL remain in English.

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

### Requirement: Remote node onboarding uses temporary access
The wizard SHALL onboard a remote node only after the operator confirms the presented host-key fingerprint by typing it in full, SHALL read the password without echo, SHALL authorise a temporary key that a host timer removes within two hours, SHALL run the existing node registration under that access, SHALL revoke the key and the timer when the registration ends, succeeds or not, and SHALL abort before any key is authorised when the timer cannot be installed or enabled.

#### Scenario: An incompletely typed fingerprint stops onboarding
- **GIVEN** the wizard presents the SHA-256 fingerprint of a node's host key
- **WHEN** the operator answers with a different value, a prefix, or an empty line
- **THEN** that attempt authorises no key and runs no command on any host of the plan

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
- **THEN** no argument of any spawned process contains the password, and the password is not written to a file that outlives that node's onboarding

#### Scenario: Onboarding aborts when the expiry timer cannot be installed
- **GIVEN** the wizard is onboarding a node whose expiry timer cannot be installed or enabled
- **WHEN** the wizard reaches the point where the temporary key would be authorised
- **THEN** it aborts that node before any key is written and leaves no temporary access or timer artefacts on any host

### Requirement: The wizard is the only interactive surface
The interactive menu and the wizard it reaches SHALL be the only surfaces that ask questions. The positional `install` and `node add` commands SHALL keep their existing argument contract and SHALL perform no prompt when their arguments are complete. An invocation with no arguments and no terminal SHALL print the usage text and exit non-zero instead of printing a menu, blocking on input, or starting an installation with empty values.

#### Scenario: A container drive never enters the wizard
- **GIVEN** an acceptance run invokes `gowave-auto.sh install <panel> <reality> <email>` with stdin that is not a terminal
- **WHEN** the install runs
- **THEN** no wizard question is asked, the command behaves as it did before this change, and its output is English

#### Scenario: Missing arguments without a terminal fail fast
- **GIVEN** `gowave-auto.sh install` is invoked with no arguments and stdin that is not a terminal
- **WHEN** the command runs
- **THEN** it exits non-zero with a usage message naming the expected arguments and modifies nothing on the host

#### Scenario: A bare invocation without a terminal prints usage instead of the menu
- **GIVEN** `gowave-auto.sh` is invoked with no arguments and stdin that is not a terminal
- **WHEN** the command runs
- **THEN** it prints the usage text, exits non-zero, and neither prints the menu nor blocks on input
