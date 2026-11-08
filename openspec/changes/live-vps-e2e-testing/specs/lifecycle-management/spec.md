# Spec Delta: Lifecycle Management

## ADDED Requirements

### Requirement: ACME Staging/Production Mode Parameter

The installer and distributed orchestrator SHALL accept an ACME server mode parameter switching certbot between
Let's Encrypt staging and production endpoints. When active, certbot SHALL be invoked with `--server <staging-url>`.
The orchestrator SHALL propagate this parameter across Master and Worker via SSH stdin. Valid certificates SHALL be
reused without reissuing.

#### Scenario: Staging certificate issued during E2E test run on Master

- **GIVEN** `ACME_MODE=staging` is configured for the E2E run
- **WHEN** `gowave-auto.sh install` is called with the staging parameter
- **THEN** certbot is invoked with `--server https://acme-staging-v02.api.letsencrypt.org/directory`,
  a staging certificate is issued for the domain, and the installation proceeds to completion without
  contacting the Let's Encrypt production endpoint

#### Scenario: Staging parameter propagated to Worker during node add

- **GIVEN** `ACME_MODE=staging` is active on Master
- **WHEN** `gowave-auto.sh node add worker-1 ...` executes
- **THEN** `GOWAVE_ACME_SERVER` is transmitted over SSH stdin to Worker, and Worker certbot calls execute
  with `--server https://acme-staging-v02.api.letsencrypt.org/directory` without hitting production rate limits

#### Scenario: Existing valid production certificate reused

- **GIVEN** `ACME_MODE=production` and a valid certificate already exists for the domain
- **WHEN** `gowave-auto.sh install` or `node add` is invoked again for the same domain
- **THEN** certbot's `--keep-until-expiring` or equivalent flag causes the existing certificate to be
  reused without issuing a new one, respecting production rate limits
