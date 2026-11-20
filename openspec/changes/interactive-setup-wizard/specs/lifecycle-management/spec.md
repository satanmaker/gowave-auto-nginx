# Spec Delta: Lifecycle Management

## ADDED Requirements

### Requirement: Panel-only installation mode

`install` SHALL accept a Panel-only mode that deploys the Panel and the static camouflage site only: no GoWave
Node unit, no Xray core, no REALITY or Vision inbound. In that mode `:443` SHALL route the Panel name to 7443
and every other name to the decoy on 9443, and no 8443 or 8444 listener SHALL exist.

#### Scenario: Panel-only install omits the traffic plane

- **GIVEN** a clean supported host and the operator selects the Panel-only mode
- **WHEN** the installation completes
- **THEN** `gowave.service` and `nginx.service` are active, `gowave-node.service` does not exist, no Xray process
  runs, and nothing listens on `127.0.0.1:8443` or `127.0.0.1:8444`

#### Scenario: Panel name and camouflage name terminate in different places

- **GIVEN** a Panel-only installation with a Panel name and a camouflage name
- **WHEN** a client opens TLS to each name on port 443
- **THEN** the Panel name is served by the Panel listener and the camouflage name, as well as any name the map
  does not know, is served by the static decoy site

#### Scenario: A later domain change keeps the panel-only map

- **GIVEN** a Panel-only installation
- **WHEN** `gowave-auto.sh domain-change <new-panel> <new-decoy>` completes
- **THEN** the regenerated `:443` map still contains no `8443` or `8444` backend and still sends the default entry
  to `9443`

### Requirement: Health and status distinguish an absent node from a broken one

In Panel-only mode `gowave-auto.sh health` SHALL report `HEALTHY` when the Panel answers, treating the
intentionally absent Node listener as informational. `gowave-auto.sh status` SHALL report the absent Node unit
and ports as absent without presenting them as a failure.

#### Scenario: Health is healthy without a local node

- **GIVEN** a Panel-only installation whose Panel answers on `127.0.0.1:3000`
- **WHEN** `gowave-auto.sh health` runs
- **THEN** it prints the absent Node listener as a warning, prints `Overall health status: HEALTHY`, and exits 0

#### Scenario: Status names the missing node without failing

- **GIVEN** a Panel-only installation
- **WHEN** `gowave-auto.sh status` runs
- **THEN** it reports `gowave-node.service` as not present and ports 3002, 8443, and 8444 as free, and exits 0

### Requirement: Installation state records the mode and no invented node

`state.json` SHALL record which installation mode was used, and in Panel-only mode SHALL hold an empty node list
and no local-node identifier, so later commands do not treat an absent local node as a broken one.

#### Scenario: State written by a panel-only install

- **GIVEN** a Panel-only installation
- **WHEN** `state.json` is read back
- **THEN** it names the Panel-only mode, the Panel and camouflage domains, an empty `nodes` list, and no
  `localNodeUuid`, `nodePort`, or `profileUuid` that would describe a local node

#### Scenario: Node listing works on a panel-only panel

- **GIVEN** a Panel-only installation with no nodes yet
- **WHEN** `gowave-auto.sh node list` runs
- **THEN** it reports that no nodes are registered and exits 0

### Requirement: The first worker assigns the panel-only default user

A Panel-only installation creates `default-user` before any inbound exists, so `node add` SHALL put that user into
the squad it provisions when, and only when, that user holds no squad. A user that already holds a squad SHALL be
left as the operator set it, and the assignment SHALL be journalled so a failed registration takes it back off.

#### Scenario: The squadless default user receives the new node's endpoints

- **GIVEN** a Panel-only installation whose `default-user` holds no internal squad
- **WHEN** `gowave-auto.sh node add` registers the first worker
- **THEN** the Panel is told to assign that user the squad just created, and the user's subscription answers the
  node's own endpoints rather than a placeholder

#### Scenario: A user that already holds a squad is left alone

- **GIVEN** a `default-user` already assigned to an operator-created squad
- **WHEN** `gowave-auto.sh node add` registers a new worker
- **THEN** the user's squad list is unchanged and the registration still completes

#### Scenario: A failed registration takes the assignment back off

- **GIVEN** a `node add` that assigned the squadless user and then failed
- **WHEN** the compensating rollback runs
- **THEN** the user's squad list is restored to the empty list the journal recorded, and the rollback reports its
  outcome rather than a partial success

### Requirement: Host records carry a provisioned squad identifier

Every host record SHALL carry the identifier of the internal squad provisioned for its inbounds, and the node
registration SHALL take that identifier from the provisioning call rather than from a previously stored value,
so a cluster whose first worker follows a Panel-only installation never submits an empty or null squad.

#### Scenario: First worker after a panel-only install gets a real squad

- **GIVEN** a Panel-only installation that has never provisioned an internal squad
- **WHEN** `gowave-auto.sh node add` registers the first worker
- **THEN** the internal squad is created, every host record for that node names its identifier, no request body
  contains a null squad entry, and the identifier is stored in `state.json`

#### Scenario: Later workers reuse the same squad

- **GIVEN** a cluster that already has one registered worker
- **WHEN** a second worker is added
- **THEN** the existing internal squad is extended with the new inbounds, no duplicate squad is created, and both
  nodes' host records name the same identifier

#### Scenario: A refused squad payload fails the registration instead of passing silently

- **GIVEN** the Panel refuses a host record whose squad list is empty or null
- **WHEN** `node add` submits it
- **THEN** the command exits non-zero, names the refusal, and runs its compensating rollback rather than reporting
  a successful registration
