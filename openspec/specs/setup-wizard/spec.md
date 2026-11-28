# setup-wizard Specification

## Purpose

Defines the operator-facing setup wizard behind `docs/SETUP_WIZARD.md`: the language-first question order, the editable deployment plan and its preflight boundary, Panel discovery and API identity verification for adding nodes, and the Russian and English prompt catalog every interactive message renders through.

## Requirements

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

### Requirement: Topology choices describe placement and failure isolation
The RU and EN menus SHALL distinguish deploying a Panel from connecting a remote server to an existing Panel. The topology menu SHALL require an explicit selection, describe what runs here versus on other servers, and provide a return action.

#### Scenario: Compare three schemes
- **WHEN** the operator opens new deployment
- **THEN** local Panel plus node is labelled for evaluation and personal use only; Panel here plus remote nodes is recommended for failure isolation; local Panel plus local and remote nodes is not recommended because a single host failure takes out the Panel and one node. No option promises automatic failover.

### Requirement: Questions reflect the role and preserve prior answers
The wizard SHALL identify the current server role, remote node ordinal and total, distinguish the certificate contact from Panel login and the display name from DNS, and ask traffic-profile questions only for traffic nodes. On invalid input it SHALL explain the constraint and reprompt the offending field before proceeding.

#### Scenario: Conflicting cover domain on the second worker
- **WHEN** the operator enters its primary domain again as its cover domain
- **THEN** the wizard names the conflicting role and repeats only the cover-domain prompt before asking about Vision; language, Panel, first worker and current worker answers remain intact.

#### Scenario: Panel-only local server
- **WHEN** the operator chooses a Panel here and nodes elsewhere
- **THEN** the wizard does not ask for local node name, country or local Vision and still offers optional Vision separately for each remote node, including a node added later.

### Requirement: Node names are operator-selected and unique
The wizard SHALL accept a separate name for each local and remote node, trim surrounding whitespace, reject blank or duplicate names, and show the accepted name on review. It SHALL check the entire pending plan and, when adding to an existing Panel, the verified Panel inventory before registration.

#### Scenario: Collision within a new plan
- **WHEN** a remote node is given the local node's name padded with spaces
- **THEN** the wizard identifies the owner and requests another name without discarding other answers.

#### Scenario: Adding to an existing Panel
- **WHEN** the requested name already exists or inventory cannot be verified
- **THEN** a collision requests a new name; failed verification offers retry or return, without claiming the name is free or changing the remote server.

### Requirement: Domain questions explain role and observable routing
The wizard SHALL distinguish explicit Master cover apex, Panel UI hostname, Worker transport hostname, REALITY SNI and optional Vision hostname in RU and EN. It SHALL explain browser and protocol behavior before collection, never describe a Worker transport hostname as a Panel, and preserve the four mandatory profiles when Vision is disabled.

#### Scenario: Master domain explanation
- **WHEN** the operator plans `example.com`, `panel.example.com`, `reality.example.com` and optional `xtls.example.com`
- **THEN** the wizard identifies apex as static cover, panel as UI/API/subscriptions and shared TLS transports, and REALITY/Vision as protocol endpoints whose unauthenticated fallback exposes only cover content.

#### Scenario: Worker domain explanation
- **WHEN** a Worker with Vision is planned
- **THEN** the wizard asks for three distinct names, explains the primary name as XHTTP/WS/gRPC plus static cover, the second as REALITY and the third as Vision, and states that no Panel is installed there.

#### Scenario: Worker without Vision
- **WHEN** Vision is disabled for a Worker
- **THEN** only primary transport and REALITY names are required; XHTTP, WS, Trojan/gRPC and REALITY remain available and no Vision certificate or listener is planned.

### Requirement: Domain and certificate ownership review
Before mutation the plan SHALL show each hostname's target host, role, expected ordinary-client behavior, protocol address versus SNI, and certificate SAN ownership. Cover names SHALL be explicit rather than guessed from DNS suffix labels. A same-zone Worker SHALL NOT implicitly claim the Master's apex or www certificate names.

#### Scenario: Shared zone on distinct hosts
- **WHEN** Master owns `example.com` and a Worker on another IP uses `node-1.example.com`, `reality-node-1.example.com` and `xtls-node-1.example.com`
- **THEN** review assigns apex and optional www to Master only, shows three Worker certificate identities without apex SANs and does not ask to move apex DNS to Worker.

#### Scenario: Multi-label public suffix
- **WHEN** Master uses `panel.example.co.uk` with explicit cover `example.co.uk`
- **THEN** review retains that cover name, never substitutes `co.uk`, and validates each chosen name against its target host.

#### Scenario: Conflicting ownership or certificate validation
- **WHEN** a name conflicts with another role, target or unsuitable certificate lineage
- **THEN** the wizard explains the owner and conflict, returns to the affected field or certificate choice and preserves the remaining plan; no certificate is silently reassigned.

#### Scenario: Existing deployment preview
- **WHEN** existing domains or certificate paths differ from the proposed model
- **THEN** the wizard shows the existing-to-proposed routing and SAN changes and requires explicit migration confirmation before mutation.
