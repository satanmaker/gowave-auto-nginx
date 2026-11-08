# Spec Delta: Lifecycle Management

## ADDED Requirements

### Requirement: Explicit ACME Endpoint Selection and Certificate Lineage Isolation

The installer and distributed orchestrator SHALL accept `GOWAVE_ACME_SERVER` (defaulting to Let's Encrypt
production when unset) restricted to official Let's Encrypt staging and production directory URLs. The runner
SHALL map `ACME_MODE` to the matching URL, propagate it over SSH stdin to Worker, and prevent cross-lineage
staging and production reuse.

#### Scenario: Runner maps ACME mode to the official staging directory

- **GIVEN** E2E config has `ACME_MODE=staging`
- **WHEN** the runner invokes Master installation and subsequent `node add`
- **THEN** it passes exactly `https://acme-staging-v02.api.letsencrypt.org/directory` as `GOWAVE_ACME_SERVER`; for `ACME_MODE=production` it passes exactly `https://acme-v02.api.letsencrypt.org/directory`; no arbitrary URL is accepted

#### Scenario: Staging certificate issued on a clean disposable Master

- **GIVEN** `GOWAVE_ACME_SERVER=https://acme-staging-v02.api.letsencrypt.org/directory` and a clean disposable Master
- **WHEN** `gowave-auto.sh install` provisions the Panel and REALITY certificates
- **THEN** every Certbot issuance call uses the staging directory; the resulting certificate chain is staging-issued; no production ACME endpoint is contacted

#### Scenario: Staging parameter propagated to Worker

- **GIVEN** the Master installation uses the staging directory
- **WHEN** `gowave-auto.sh node add` invokes the remote Worker deployment
- **THEN** the exact ACME directory URL is serialized through SSH stdin and every Worker Certbot issuance call uses that URL

#### Scenario: Vision certificates use the selected ACME directory on both hosts

- **GIVEN** both `MASTER_VISION_DOMAIN` and `WORKER_VISION_DOMAIN` are configured
- **WHEN** Master and Worker certificates are issued
- **THEN** Master and Worker each issue and verify a third Vision certificate using the same selected ACME directory as their two mandatory certificates; before Worker issuance, its HTTP-01 bootstrap vhost includes `WORKER_VISION_DOMAIN` in `server_name`; each Vision renewal lineage MUST match that directory

#### Scenario: Vision certificate failure is not silently ignored

- **GIVEN** the paired Vision domains are configured but Certbot issuance or certificate validation fails on either VPS
- **WHEN** the corresponding installation phase runs
- **THEN** that host's installation fails and rolls back; on Worker, the HTTP-01 bootstrap vhost must have included the Vision name before issuance, and rollback must remove any transaction-created Vision certificate/renewal lineage, stream-map entry, 9444 fallback vhost and generated profile/host state. It MUST preserve pre-existing/unowned lineages and unrelated resources. Deployment MUST NOT proceed with a profile or NGINX route advertising an unusable Vision inbound

#### Scenario: One-sided Vision configuration is rejected before deployment

- **GIVEN** only one of `MASTER_VISION_DOMAIN` and `WORKER_VISION_DOMAIN` is configured
- **WHEN** the runner validates its configuration
- **THEN** preflight fails before SSH or any remote modification

#### Scenario: Missing or unknown renewal directory fails closed

- **GIVEN** an existing Certbot lineage has no readable `server` field or an unrecognized ACME directory URL
- **WHEN** installation checks whether that lineage can be reused
- **THEN** the installer MUST NOT infer the directory from the generic Let's Encrypt issuer; it fails closed or
  provisions a separately named lineage with all consumers and renewal hooks migrated atomically

#### Scenario: Existing certificate is reused only for the same ACME directory

- **GIVEN** a valid certificate lineage exists for the requested domain
- **WHEN** installation is repeated with the same ACME directory URL
- **THEN** Certbot may reuse the lineage without unnecessary issuance, after validating its renewal configuration and certificate SAN/expiry

#### Scenario: Failed transaction preserves pre-existing certificate lineages

- **GIVEN** a requested-domain certificate lineage existed before installation and is valid for the selected ACME directory
- **WHEN** a later Master or Worker provisioning step fails and compensation runs
- **THEN** rollback MUST NOT delete the pre-existing lineage; if Certbot changed it, restore and verify its certificate, private key, renewal configuration, live symlink targets, ownership and modes from the same-host snapshot under `/var/lib/gowave-auto-nginx/recovery/<transaction-id>/acme/<domain>/` (root-owned `0700` directories, root-owned `0600` private-key files). Snapshots MUST NOT be copied to runner/CI artifacts or logs. Only lineages proven to have been absent before the failed transaction may be deleted. Remove snapshots only after verified commit/rollback; retain them and report incomplete recovery if restoration fails. If safe restoration cannot be guaranteed, the install MUST fail before issuance or report cleanup incomplete rather than claim rollback success.

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
