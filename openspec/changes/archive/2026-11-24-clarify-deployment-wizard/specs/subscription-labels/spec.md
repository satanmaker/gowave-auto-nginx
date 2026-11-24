# Spec Delta

## Purpose

Identify a managed profile's protocol, node and operator-confirmed exit country without changing connection settings or duplicating subscription entries.

## ADDED Requirements

### Requirement: Country belongs to the traffic node
The wizard SHALL offer an exit country detected using the node's own outbound connection, not the Panel address, hostname or operator location. Enter confirms a displayed suggestion; an assigned ISO 3166-1 alpha-2 code overrides it case-insensitively. Failed detection SHALL fall back to manual input, not abort installation.

#### Scenario: Remote egress differs from Panel
- **WHEN** the Panel and worker exit in different countries and the operator presses Enter on the worker's suggestion
- **THEN** the worker's country is saved; a Panel-only host receives no country prompt.

#### Scenario: Manual correction on a local node
- **WHEN** a local AIO node suggests NL and the operator enters de
- **THEN** the wizard shows Germany, DE and 🇩🇪 and uses DE without changing network routing.

#### Scenario: No valid suggestion
- **WHEN** the lookup times out or returns an invalid code
- **THEN** the wizard asks for a valid code, repeats only that question for empty or invalid input and never silently substitutes a country.

### Requirement: Stable labels reach subscription clients
Managed profiles with confirmed country metadata SHALL display the flag, protocol and transport/security descriptors separated by ` · `, then ` — ` and the chosen node name. Relabelling SHALL preserve managed Host identity, connectivity settings and unrelated Hosts.

#### Scenario: Confirmed labels survive import
- **WHEN** Xray JSON and Mihomo YAML subscriptions for a named node are imported with Vision enabled
- **THEN** all five profiles expose the same country and node name, REALITY Vision is distinct from TLS Vision, and Mihomo group references resolve to the renamed entries.

#### Scenario: Reconcile an existing deployment twice
- **WHEN** a legacy managed Host is reconciled with confirmed country metadata and reconciliation is repeated
- **THEN** the old Host is updated in place, no duplicate appears, and a similarly named unmanaged Host remains untouched.

#### Scenario: No interactive metadata
- **WHEN** a positional operation runs without confirmed country metadata
- **THEN** it neither prompts nor requires a GeoIP service and does not invent a flag or erase a previously confirmed label.
