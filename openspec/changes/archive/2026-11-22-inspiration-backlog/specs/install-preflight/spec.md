# Spec Delta

## Purpose

Defines what the installer proves about a requested deployment before it changes anything on the host: that every
input the selected component needs is present and well-formed, and that the names it will validate over HTTP-01
can actually be validated.

## ADDED Requirements

### Requirement: Mandatory inputs are proven before the first mutation

A lifecycle command SHALL validate every input its component requires before it stops a service, installs a
package, writes a managed path or contacts the Panel, and a rejected input SHALL name the input and the
component.

#### Scenario: A missing panel input changes nothing

- **GIVEN** a host with a running NGINX and no installed deployment
- **WHEN** `install` is invoked without the panel name, the camouflage name or the ACME contact
- **THEN** the command fails naming the missing input, and NGINX is still running, no package was installed and
  no managed path was created

#### Scenario: A missing Worker input is rejected before the remote side

- **WHEN** `node add` is invoked with a name, an address and a Worker domain but no camouflage domain
- **THEN** the command fails naming the camouflage domain, and no SSH channel is opened and no Panel API call is
  made

#### Scenario: A malformed input is rejected the same way as a missing one

- **WHEN** an input is present but is not a valid name, address, port or domain
- **THEN** the command fails naming that input and the component, before any mutation

#### Scenario: A complete invocation proceeds

- **WHEN** every required input of the selected component is present and valid
- **THEN** the preflight passes and the command continues into its normal steps

#### Scenario: The wizard and the positional path agree

- **GIVEN** the same invalid value
- **WHEN** it is supplied through the interactive wizard and through positional arguments
- **THEN** both paths reject it on the same field and with the same explanation

### Requirement: A proxied name is refused before certificate issuance

The installer SHALL resolve the names it will validate and SHALL refuse to continue when a name resolves into a
published Cloudflare proxy range, because the HTTP-01 challenge cannot complete behind that proxy.

#### Scenario: A proxied decoy name stops the install

- **GIVEN** the camouflage name resolves to an address inside a published Cloudflare proxy range
- **WHEN** `install` runs its preflight
- **THEN** it fails before any certificate is requested, names that name, and states that the record must be
  DNS-only for the challenge to succeed

#### Scenario: A Cloudflare-fronted panel name stops the install too

- **WHEN** the panel name, the camouflage name or a configured Vision name is proxied
- **THEN** the same refusal applies to that name

#### Scenario: An unproxied deployment is unaffected

- **WHEN** every name resolves to an address outside the proxy ranges
- **THEN** the preflight passes and installation continues

#### Scenario: An explicit override is honoured

- **GIVEN** an operator who has arranged for the challenge to be answered some other way
- **WHEN** the override is set for the run
- **THEN** the preflight records the decision and continues

#### Scenario: An unresolvable name is reported, not guessed

- **WHEN** a name cannot be resolved at all during preflight
- **THEN** the command fails naming the name and the resolver outcome, instead of assuming the deployment is
  direct
