# Spec Delta

## MODIFIED Requirements

### Requirement: Camouflage decoy and certificate lineage

Every installed host MUST serve the camouflage decoy. The Master's cover apex MUST be the selected name, never a suffix guess, and a deployment that selects none MUST infer none. A Worker MUST own no apex: it serves its camouflage site under its own camouflage name, which is also its REALITY SNI. Each name used MUST resolve to its host, reach that host's camouflage listener, serve the rendered site and be covered by its REALITY lineage.

#### Scenario: Decoy renders for the apex each role owns

- **GIVEN** the Master's selected cover apex and its optional `www` alias resolving to the Master's IPv4 address, and a Worker whose own camouflage and REALITY names resolve to it
- **WHEN** the operator completes installation or a domain change
- **THEN** the case reports the name each role decided — the Master's selection, and for the Worker only its own camouflage name — and never a first-two-label guess or an apex the role does not own
- **AND** the cover site contains the expected `*.html`, `*.css`, and `*.svg` assets with that name's brand and no surviving `{{` placeholder
- **AND** the Master's apex and `www` SNI terminate on the loopback decoy listener while every VPN SNI keeps its own route, and the Worker's camouflage name terminates on its own decoy
- **AND** the decoy listener is unreachable from client networks and exposes no Panel, API, or management path

#### Scenario: Unresolvable cover names block rendering

- **GIVEN** a selected apex that is not a fully qualified domain name, a selected apex equal to the Panel's own name, or either the apex or `www.<apex>` not resolving to the Master's IPv4 address
- **WHEN** the operator attempts to install or re-render the decoy
- **THEN** it refuses before issuing the lineage and reports the reason, naming the records that did not resolve
- **AND** no partial decoy configuration or stale `sites-enabled` entry remains
- **AND** a Worker claims neither half of that apex and holds no lineage naming either, so the refusal cannot be answered by issuing the Master's names on the Worker

#### Scenario: Worker keeps its decoy and ACME route

- **GIVEN** a provisioned Worker host
- **WHEN** the Worker is installed, restarted, or reconfigured
- **THEN** its port 80 ACME vhost remains reachable for renewal, redirects its own primary, camouflage and Vision names to HTTPS, and refuses every other host
- **AND** its decoy listener and SNI routes are unchanged unless the domain actually changed

## ADDED Requirements

### Requirement: Parallel distribution acceptance with isolated evidence
The acceptance harness SHALL cover Debian 12, Debian 13, Ubuntu 24.04 and Ubuntu 26.04 in parallel locally and in GitHub Actions. Each run SHALL have independent artifacts and resource ownership. Existing required GitHub status check names and event applicability SHALL remain stable.

#### Scenario: GitHub Actions runs the distribution matrix
- **WHEN** an event enables an acceptance job type
- **THEN** its four distribution cells can execute concurrently on separate runners, publish uniquely named artifacts even on failure, and its stable required check passes only if all four cells pass.

#### Scenario: Four local runs start together
- **WHEN** the operator launches one acceptance suite for all four distributions on the same Podman host
- **THEN** the harness reserves non-overlapping control and data networks without a discovery-to-creation race, runs the suites concurrently, and returns independent results plus a non-zero aggregate status if any required result is unsuccessful or missing.
- **AND** cleanup of one run does not remove another run's resources.

#### Scenario: NGINX package policy is verified
- **WHEN** the pinned-package acceptance coverage runs
- **THEN** it reads back the actual installed NGINX package revision, source and Stream capability in the applicable roles and checks the official path, permitted fallback and refusal without activation.

#### Scenario: Data-plane evidence is read from the edge's own log
- **WHEN** a data-plane case proves that a request reached the intended host
- **THEN** it reads the new lines of that host's stream access log and requires a line naming the request's SNI and client address.
- **AND** a missing line fails the case, while a request that the edge never logged is never reported as a pass.
- **AND** the raw packet capture is not the witness: it is a laboratory instrument that observes nothing in an unprivileged container namespace, so an empty capture can no longer decide a verdict.
