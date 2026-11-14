# Spec Delta: Live VPS E2E

## ADDED Requirements

### Requirement: Panel-only Master VPS installation verification

On a disposable Master VPS the runner SHALL install the Panel-only mode and verify from the host itself that the
traffic plane is absent by design: Panel active and serving over 443, no Node unit, no Xray process, no 8443 or
8444 listener, the camouflage name served by the static decoy, and `gowave-auto.sh health` reporting HEALTHY.

#### Scenario: Panel-only Master has no traffic plane

- **GIVEN** a clean disposable Master VPS and `gowave-auto.sh install` run in the Panel-only mode
- **WHEN** the runner inspects the host after the installer exits 0
- **THEN** `gowave.service`, `nginx.service`, and `fail2ban.service` are active; `gowave-node.service` does not
  exist; no Xray process runs; nothing listens on `127.0.0.1:8443` or `127.0.0.1:8444`; and `health` prints
  `Overall health status: HEALTHY`

#### Scenario: Both names answer on 443 and the decoy never exposes the Panel

- **GIVEN** the Panel-only Master installation completed
- **WHEN** the runner opens TLS to `MASTER_PANEL_DOMAIN` and to `MASTER_DECOY_DOMAIN` from the Control Machine
- **THEN** the Panel name returns the Panel UI over a certificate whose SANs are exactly the names the install was
  given, the camouflage name returns the static decoy page, and no response on either name reveals a Panel or
  Xray signature

#### Scenario: The first worker after a panel-only Master registers with a squad

- **GIVEN** a Panel-only Master with no nodes and no internal squad
- **WHEN** the runner executes `gowave-auto.sh node add worker-1`
- **THEN** `GET /api/nodes` shows `worker-1` connected, every host record created for it names a non-empty squad
  identifier, and no request body submitted during registration contained a null squad entry

#### Scenario: The runner reads the panel-only mode from state, not from assumptions

- **GIVEN** the Panel-only Master installation completed
- **WHEN** the runner reads `state.json` over SSH
- **THEN** it records the Panel-only mode, an empty node list, and no local-node identifiers, and the runner's
  certificate audit expects exactly the Panel and camouflage lineages rather than the All-in-One set
