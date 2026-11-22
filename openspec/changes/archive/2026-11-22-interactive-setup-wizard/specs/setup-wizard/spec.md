# Spec Delta: Setup Wizard

## Purpose

Defines the guided installation surface of `gowave-auto.sh`: the choice of display language and deployment
variant, the names each host must answer to, the certificate budget a plan will spend, and how a remote node is
onboarded — while every non-interactive invocation keeps the existing English positional contract.

## ADDED Requirements

### Requirement: Language selection precedes every other question

The wizard SHALL ask for the display language, Russian or English, before any other question unless
`GOWAVE_WIZARD_LANG` already names one of the two, apply the choice to every message it prints afterwards, and
accept only one of the two offered answers. Every other command and every non-interactive invocation SHALL
remain in English.

#### Scenario: Russian wizard prints Russian prompts

- **GIVEN** the operator starts the wizard and chooses Russian
- **WHEN** the wizard asks for the deployment variant and then for host names
- **THEN** every question, validation error, warning, and summary is printed in Russian, and the English sentence
  that names a file path, a command, or an error echoed from a subprocess stays verbatim

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

### Requirement: Deployment variant selection describes its domain cost first

The wizard SHALL offer exactly three deployment variants — All-in-One, Panel-only, and All-in-One plus remote
nodes — SHALL present All-in-One as suitable for trial use and evaluation, and SHALL describe the names the
chosen variant requires before collecting any of them.

#### Scenario: All-in-One is presented as the trial variant

- **GIVEN** the wizard asks for the deployment variant
- **WHEN** the variant list is printed
- **THEN** All-in-One is described as recommended only for testing and familiarisation with the UI, and the other
  two variants are present with their own descriptions

#### Scenario: Panel-only asks for no REALITY or Vision name

- **GIVEN** the operator chooses Panel-only
- **WHEN** the wizard describes and collects the names for the Panel host
- **THEN** it asks for the Panel name and the camouflage name only, and no REALITY, Vision, or worker name is
  requested for that host

#### Scenario: Multi-node variants ask for a node count and one node at a time

- **GIVEN** the operator chooses Panel-only with nodes or All-in-One plus remote nodes
- **WHEN** the wizard continues
- **THEN** it asks how many remote nodes to onboard, refuses a count below one, and then collects the names of
  each node in turn before any host is modified

### Requirement: Every collected name is validated in one plan

The wizard SHALL collect a Panel or worker name, a camouflage name, and an optional Vision name per host,
SHALL reject a value that is not a valid DNS hostname, SHALL reject a name that another host in the same plan
already uses, and SHALL finish collecting every name before the first mutation.

#### Scenario: A repeated name stops the plan

- **GIVEN** a plan in which the second node is given the camouflage name already used by the first node
- **WHEN** the wizard validates the plan
- **THEN** it reports which two hosts collide and stops before installing anything or issuing any certificate

#### Scenario: An invalid hostname is refused in place

- **GIVEN** the operator enters a name with an empty label, a label longer than 63 characters, or a character
  outside letters, digits, and hyphen
- **WHEN** the wizard validates that answer
- **THEN** it names the offending value, repeats the question for that field, and keeps the answers already given

#### Scenario: Vision stays optional per node

- **GIVEN** a multi-node plan
- **WHEN** the operator enables Vision for one node and declines it for another
- **THEN** the plan records Vision for exactly one node and the wizard continues without requiring it elsewhere

### Requirement: Certificate budget is computed before the first certificate

The wizard SHALL compute the number of certificates a plan requires as `2 + v_panel + 2N + k`, where `N` is the
number of remote nodes, `v_panel` is one when the Panel host runs a local node with Vision, and `k` is the number
of remote nodes with Vision. It SHALL recommend a separate registered domain per host, SHALL state the
50-per-registered-domain-per-7-days limit whenever the plan shares one, and SHALL refuse a plan whose shared
domain exceeds that ceiling.

#### Scenario: A separate registered domain per host is not limited by the arithmetic

- **GIVEN** a plan where the Panel and every node use a different registered domain
- **WHEN** the wizard evaluates the plan
- **THEN** it reports that each host spends its own budget and proceeds without a certificate refusal

#### Scenario: A shared domain within the ceiling proceeds with an explicit warning

- **GIVEN** a Panel-only plan with 20 nodes and no Vision, all names under one registered domain
- **WHEN** the wizard evaluates the plan
- **THEN** it computes 42 certificates, states that the 50-per-7-days budget is shared by the whole cluster and by
  anything else using that domain, and proceeds only after the operator confirms

#### Scenario: A shared domain above the ceiling is refused

- **GIVEN** a Panel-only plan with 30 nodes and no Vision under one registered domain
- **WHEN** the wizard evaluates the plan
- **THEN** it computes 62 certificates, refuses to continue, names the ceiling for that combination, and offers
  a separate registered domain per host as the way forward

#### Scenario: Vision on the Panel host costs one more certificate

- **GIVEN** an All-in-One plus remote nodes plan with no Vision on any remote node and Vision on the Panel host
- **WHEN** the wizard evaluates the plan
- **THEN** the computed count is `3 + 2N`, and the reported ceiling is 23 nodes under one registered domain

### Requirement: Remote node onboarding uses temporary access

The wizard SHALL onboard a remote node only after the operator confirms the presented host-key fingerprint by
typing it in full, SHALL read the password without echo, SHALL authorise a temporary key that a host timer
removes within two hours, SHALL run the existing node registration under that access, SHALL revoke the key and
the timer when the registration ends, succeeds or not, and SHALL abort before any key is authorised when the
timer cannot be installed or enabled.

#### Scenario: An incompletely typed fingerprint stops onboarding

- **GIVEN** the wizard presents the SHA-256 fingerprint of a node's host key
- **WHEN** the operator answers with a different value, a prefix, or an empty line
- **THEN** the wizard refuses that node, installs no key, runs no command on the node, and leaves the other hosts
  of the plan untouched

#### Scenario: A successful onboarding leaves no temporary access

- **GIVEN** the fingerprint was confirmed and the node registration succeeded
- **WHEN** the wizard finishes that node
- **THEN** the node appears in the Panel, the temporary key is absent from the node's `authorized_keys`, the
  expiry timer no longer exists, and the password is not retained anywhere on the Panel host

#### Scenario: A failed registration still revokes access

- **GIVEN** the temporary key was installed and the node registration exits non-zero
- **WHEN** the wizard handles that failure
- **THEN** it revokes the key and the timer before reporting the failure, and the failure message names the node

#### Scenario: The password never reaches a process argument list

- **GIVEN** the wizard is onboarding a node
- **WHEN** the Panel host's process arguments are inspected while the password is held
- **THEN** no argument of any spawned process contains the password, and the password is not written to a file
  that outlives the onboarding

#### Scenario: Onboarding aborts when the expiry timer cannot be installed

- **GIVEN** the wizard is onboarding a node whose expiry timer cannot be installed or enabled
- **WHEN** the wizard reaches the point where the temporary key would be authorised
- **THEN** it aborts that node before any key is written, leaves no temporary access or timer artefacts, and
  leaves the other hosts of the plan untouched

### Requirement: The wizard is the only interactive surface

The positional `install` and `node add` commands SHALL keep their existing argument contract and SHALL perform
no prompt when their arguments are complete. An `install` invoked with no arguments and no terminal SHALL fail
with a usage message instead of blocking on input or starting an installation with empty values.

#### Scenario: A container drive never enters the wizard

- **GIVEN** an acceptance run invokes `gowave-auto.sh install <panel> <reality> <email>` with stdin that is not a
  terminal
- **WHEN** the install runs
- **THEN** no wizard question is asked, the command behaves as it did before this change, and its output is
  English

#### Scenario: Missing arguments without a terminal fail fast

- **GIVEN** `gowave-auto.sh install` is invoked with no arguments and stdin that is not a terminal
- **WHEN** the command runs
- **THEN** it exits non-zero with a usage message naming the expected arguments and modifies nothing on the host
