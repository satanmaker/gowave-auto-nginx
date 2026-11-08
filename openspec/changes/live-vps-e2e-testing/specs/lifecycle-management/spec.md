# Spec Delta: Lifecycle Management

## ADDED Requirements

### Requirement: Explicit ACME Endpoint Selection and Certificate Lineage Isolation

The installer and distributed orchestrator SHALL accept an explicit ACME directory URL, defaulting to Let's Encrypt
production when unset. Only official Let's Encrypt production and staging URLs are allowed in v1. The URL SHALL be
propagated from Master to Worker over SSH stdin. A staging lineage MUST NOT be reused as production, nor production as staging.

#### Scenario: Staging certificate issued on a clean disposable Master

- **GIVEN** `GOWAVE_ACME_SERVER=https://acme-staging-v02.api.letsencrypt.org/directory` and a clean disposable Master
- **WHEN** `gowave-auto.sh install` provisions the Panel and REALITY certificates
- **THEN** every Certbot issuance call uses the staging directory; the resulting certificate chain is staging-issued; no production ACME endpoint is contacted

#### Scenario: Staging parameter propagated to Worker

- **GIVEN** the Master installation uses the staging directory
- **WHEN** `gowave-auto.sh node add` invokes the remote Worker deployment
- **THEN** the exact ACME directory URL is serialized through SSH stdin and every Worker Certbot issuance call uses that URL

#### Scenario: Existing certificate is reused only for the same ACME directory

- **GIVEN** a valid certificate lineage exists for the requested domain
- **WHEN** installation is repeated with the same ACME directory URL
- **THEN** Certbot may reuse the lineage without unnecessary issuance, after validating its renewal configuration and certificate SAN/expiry

#### Scenario: ACME directory changes between staging and production

- **GIVEN** the domain has a certificate lineage issued by the other ACME directory
- **WHEN** the operator changes `GOWAVE_ACME_SERVER`
- **THEN** the installer MUST NOT treat the old lineage as a valid reusable certificate; it MUST require a fresh disposable baseline or create a separately named lineage and atomically update all consumers; it MUST never mix staging and production certificates

#### Scenario: Existing NGINX certificate path contract is preserved

- **GIVEN** Master or Worker has NGINX consumers referencing `/etc/letsencrypt/live/<domain>/`
- **WHEN** a staging or production lineage is issued or migrated
- **THEN** every consumer continues to resolve the expected certificate and private-key paths; any isolated
  lineage migration updates all consumers and renewal hooks atomically before reload, or fails without
  replacing the active certificate

#### Scenario: ACME parameter is unset

- **GIVEN** `GOWAVE_ACME_SERVER` is unset
- **WHEN** the existing installer is run
- **THEN** the production endpoint and existing certificate behavior remain backward-compatible
