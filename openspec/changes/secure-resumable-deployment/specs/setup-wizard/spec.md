# Spec Delta

## ADDED Requirements

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
