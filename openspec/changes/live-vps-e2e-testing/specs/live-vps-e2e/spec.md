# Spec: Live VPS E2E

## Purpose

Defines the observable behavior contract for the Live VPS E2E Test Runner — an automated acceptance tool that
validates the complete GoWave Auto NGINX distributed infrastructure lifecycle on real disposable servers over the
public internet, from bare OS through deployment, mTLS control plane, subscription delivery, and Data Plane VPN
traffic through all eight protocol endpoints.

---

## ADDED Requirements

### Requirement: Disposable Environment Gate

The runner SHALL refuse to modify any VPS that does not satisfy a verifiable disposable baseline. It SHALL
collect a pre-install manifest (systemd services, listeners, firewall rules, GoWave directories, package
inventory, sysctl, swap, filesystem usage, certificate state) before any installation step. If existing GoWave
directories, running GoWave services, or port conflicts are detected, the runner SHALL terminate before the
first remote modification and report the disqualifying evidence.

#### Scenario: Clean VPS passes baseline gate

- **GIVEN** a VPS with fresh OS, no running GoWave services, and no listening processes on required ports
- **WHEN** the runner performs baseline inspection over SSH
- **THEN** the VPS passes the disposable gate, baseline manifest is recorded, and installation proceeds

#### Scenario: Contaminated VPS blocked before modification

- **GIVEN** a VPS with an existing GoWave installation or a listener on port 443
- **WHEN** the runner performs baseline inspection
- **THEN** the runner terminates before any remote command that modifies system state, records the rejection
  reason in `result.json`, and sets overall status to `FAIL`

---

### Requirement: Preflight SSH Trust and DNS Verification

The runner SHALL verify SSH connectivity and DNS correctness for all required domains before the first
installation command. SSH host keys MUST be pre-pinned in `known_hosts`; automatic trust of `ssh-keyscan`
output is prohibited. DNS SHALL use at least two independent resolvers and confirm A-record → VPS IP mapping
for every domain. An unresolvable domain or wrong A-record SHALL cause preflight failure before any remote
command.

#### Scenario: SSH host key not pre-pinned

- **GIVEN** a VPS whose SSH host key is absent from the configured `known_hosts` file
- **WHEN** the runner performs SSH preflight check
- **THEN** the runner terminates before any remote modification with a message identifying the missing key

#### Scenario: DNS A-record points to wrong IP

- **GIVEN** `MASTER_PANEL_DOMAIN` resolves to an IP other than `MASTER_IP`
- **WHEN** DNS preflight check is performed
- **THEN** the runner terminates before connecting to any VPS and records the DNS mismatch in the report

#### Scenario: Private or reserved IP rejected

- **GIVEN** `MASTER_IP` or `WORKER_IP` is set to a loopback, RFC-1918 private, link-local, multicast,
  or documentation range address (e.g., `203.0.113.0/24`)
- **WHEN** config validation runs
- **THEN** the runner terminates immediately with an error identifying the disallowed address

#### Scenario: IPv6 AAAA records verified when enabled

- **GIVEN** `ENABLE_IPV6=true` is configured and DNS preflight runs
- **WHEN** DNS verification checks AAAA records for each required domain
- **THEN** every domain has an AAAA record resolving to the expected VPS IPv6 address; any missing or wrong
  AAAA record causes preflight failure before any remote command

---

### Requirement: Pinned Version Fidelity

Every test run SHALL record and verify the exact version of each software component: repository commit,
GoWave Panel version, GoWave Node version, upstream Node installer commit, Xray (server and client), Mihomo,
NGINX, OpenSSL, OS and kernel, and SHA256 of installed binaries. If any required version cannot be
unambiguously pinned or verified, preflight SHALL terminate before installation.

#### Scenario: Version mismatch detected post-installation

- **GIVEN** `GOWAVE_PANEL_VERSION` is set to `1.2.3` in configuration
- **WHEN** the installed Panel binary is interrogated after installation
- **THEN** the runner records the installed version; if it does not match the configured version, the
  `master_install` result is set to `FAIL`

#### Scenario: Floating installer branch rejected

- **GIVEN** `GOWAVE_NODE_INSTALLER_COMMIT` is not set or resolves to a floating branch reference
- **WHEN** preflight validation runs
- **THEN** the runner terminates before installation with an error requiring an explicit 40-hex commit SHA

---

### Requirement: All-in-One Master VPS Installation Verification

After running `gowave-auto.sh install` on the Master VPS, the runner SHALL verify: exit code 0; Panel binary
version matches configuration; required systemd services are active; Panel and Node listeners are on correct
ports; NGINX listens on port 443; TLS certificates exist with correct SAN and valid chain; a local mTLS health
check succeeds; and `gowave-auto.sh health` returns `HEALTHY`.

#### Scenario: Panel service active and API ready

- **GIVEN** `gowave-auto.sh install` completed with exit code 0
- **WHEN** the runner verifies Master installation
- **THEN** `gowave.service` is active, Panel responds to an authenticated API call at `127.0.0.1:3000`,
  and the same HTTPS endpoint is reachable from the Control Machine through NGINX on port 443

#### Scenario: Credentials file has correct permissions and content

- **GIVEN** install completed successfully
- **WHEN** the runner checks `/root/gowave-credentials.txt` via SSH on Master
- **THEN** owner is root, mode is `0600`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, and `SCOPED_API_TOKEN` are
  present, and no credential values appear in runner logs or reports

#### Scenario: Master services active and listeners correct

- **GIVEN** `gowave-auto.sh install` completed with exit code 0
- **WHEN** the runner checks systemd service status and port listeners on Master
- **THEN** `gowave.service`, `gowave-node.service`, `nginx.service`, and `fail2ban.service` are all active;
  Panel listens on `127.0.0.1:3000`, Node on `3002`, and NGINX publicly on `443`

#### Scenario: TLS certificate valid and shortUuid retrievable

- **GIVEN** Master installation completed with exit code 0
- **WHEN** the runner verifies certificates and retrieves the default user identity
- **THEN** TLS certificates for `MASTER_PANEL_DOMAIN` and `MASTER_REALITY_DOMAIN` have correct SAN and valid
  chain; `shortUuid` is retrieved via `GET /api/users/by-username/default-user` or confirmed from `state.json`
  — it is NOT read from `/root/gowave-credentials.txt`

---

### Requirement: Distributed Worker VPS Deployment Verification

After running `gowave-auto.sh node add worker-1` from Master, the runner SHALL verify: exit code 0; Worker
recorded in `state.json`; Panel API entity created; SSH deployment used pre-pinned host key with
`StrictHostKeyChecking=yes`; `SECRET_KEY` was not passed via process argv; `gowave-node.service` and
`nginx.service` are active on Worker; certificates are valid; and NGINX config passes `nginx -t`.

#### Scenario: SECRET_KEY not in process argv at deployment time

- **GIVEN** `gowave-auto.sh node add` is executing the SSH remote deployment
- **WHEN** the runner observes running processes on Master during deployment
- **THEN** no process argv contains the literal `SECRET_KEY` value; delivery is confirmed via stdin or
  environment variable injection as implemented

#### Scenario: Worker node registered and connected in Panel

- **GIVEN** Worker deployment completed with exit code 0
- **WHEN** the runner polls `GET /api/nodes` with bounded timeout up to `NODE_READY_TIMEOUT`
- **THEN** a node named `worker-1` with address `WORKER_IP` and port `3002` appears with `isConnected: true`

#### Scenario: Worker deployment details verified

- **GIVEN** Worker deployment completed with exit code 0
- **WHEN** the runner audits the Worker node state
- **THEN** installer commit matches configuration; Node binary version matches `GOWAVE_NODE_VERSION`;
  deploy hook exists and is executable; cover-reality assets are present with SHA256 matching transmitted
  payload; `nginx -t` passes on Worker

---

### Requirement: Public mTLS Control Plane Verification (Master → Worker)

The runner SHALL initiate a live mTLS 1.3 connection from Master to `WORKER_IP:3002` using credentials
extracted from Master state. The HKDF-SHA256-derived SNI SHALL be computed as implemented in
`modules/verify_node_mtls.py`. The verification SHALL report four distinct outcomes and SHALL also verify
five negative mTLS scenarios — each MUST result in handshake failure before the HTTP handler executes.

#### Scenario: Successful public mTLS handshake Master to Worker

- **GIVEN** Worker is deployed and `gowave-node.service` is active
- **WHEN** the runner connects from Master's public IP to `WORKER_IP:3002` using correct mTLS credentials
- **THEN** TLS 1.3 is negotiated, server certificate is validated against the CA, client certificate is
  accepted, and the health endpoint returns a response — `MTLS_HANDSHAKE_PASS` and
  `MTLS_CERTIFICATE_VALIDATION_PASS` are set

#### Scenario: Authorized Panel-to-Worker control plane exchange

- **GIVEN** mTLS handshake succeeded
- **WHEN** Panel authenticates to the Worker Node health endpoint with a valid JWT
- **THEN** the Node returns `200 OK` and `PANEL_WORKER_AUTH_PASS` is set; a `401` response sets
  `MTLS_HANDSHAKE_PASS` but NOT `PANEL_WORKER_AUTH_PASS`

#### Scenario: Wrong client certificate rejected

- **GIVEN** a self-signed certificate not signed by the GoWave CA
- **WHEN** an mTLS connection to `WORKER_IP:3002` is attempted using the wrong certificate
- **THEN** the TLS handshake fails and no HTTP handler is reached

#### Scenario: Negative mTLS scenarios all fail before HTTP handler

- **GIVEN** Worker Node is active and accepting mTLS connections
- **WHEN** the runner attempts connections with: wrong client certificate, wrong private key, mismatched SNI,
  wrong CA, and absent client certificate — five separate attempts
- **THEN** each of the five attempts results in TLS handshake failure or connection rejection before the HTTP
  handler executes; `MTLS_HANDSHAKE_PASS` is NOT set for any negative case

---

### Requirement: Panel API Cluster Structure Audit

The runner SHALL verify the complete Panel API object graph against the real GoWave Panel using authenticated
REST API calls. On a clean test environment the runner SHALL confirm node count, inbound count, config profile
correctness, Internal Squad membership by set equality, and all Host record fields — with no duplicates.

#### Scenario: Eight Hosts present with correct node and inbound associations

- **GIVEN** Master installed and Worker deployed on a clean test environment
- **WHEN** runner queries `GET /api/hosts`
- **THEN** exactly eight Host records exist; four reference `local-node` UUID and four reference `worker-1`
  UUID; each Host's `inbound UUID` matches one of the four inbounds in the corresponding node's config profile

#### Scenario: Internal Squad contains all eight inbound UUIDs

- **GIVEN** both nodes are registered with four inbounds each
- **WHEN** runner queries `GET /api/internal-squads` for `Default MVP Squad`
- **THEN** the squad's inbound list contains exactly the eight UUIDs (four from Master profile, four from
  Worker profile) with no duplicates — verified by set equality

#### Scenario: Two nodes and two config profiles with correct structure

- **GIVEN** Master installed and Worker deployed on a clean test environment
- **WHEN** runner queries `GET /api/nodes` and `GET /api/config-profiles`
- **THEN** exactly two nodes exist (`local-node` at `127.0.0.1:3002` and `worker-1` at `WORKER_IP:3002`),
  each with four active inbounds and unique UUIDs; two config profiles each have four inbounds and valid
  computed JSON config; Node API address for Worker is `WORKER_IP` and VPN client address is `WORKER_DOMAIN`

---

### Requirement: Real Subscription Delivery and User-Agent Policy

The runner SHALL retrieve `shortUuid` via `GET /api/users/by-username/default-user` from the real Panel, then
fetch Xray JSON and Mihomo YAML subscriptions using the public HTTPS endpoint. No mock server responses are
permitted. Content SHALL be validated with real Xray and Mihomo binaries. User-Agent policy SHALL be verified
against the real Panel; actual HTTP response codes SHALL be used (not mock assumptions).

#### Scenario: Subscription rejected with absent User-Agent

- **GIVEN** a valid shortUuid for the default user
- **WHEN** `GET /api/sub/{shortUuid}/v2ray-json` is requested without a User-Agent header
- **THEN** the real Panel returns the HTTP status code mandated by the upstream User-Agent policy at the
  installed GoWave version; if that is 403, the runner records a pass; if the Panel behavior differs, the
  runner records the actual response and fails the assertion

#### Scenario: Eight proxy-capable outbounds in Xray JSON

- **GIVEN** subscription fetched with valid Xray User-Agent
- **WHEN** runner parses the JSON and counts proxy-capable outbounds
- **THEN** exactly eight outbounds are identified by protocol/transport tag (VLESS REALITY Vision, VLESS XHTTP
  TLS, VLESS WS TLS, Trojan gRPC TLS) for Master and Worker; `direct`, `block`, and routing-only entries
  are excluded from the count

#### Scenario: Xray JSON subscription headers and content verified

- **GIVEN** subscription fetched with valid Xray User-Agent
- **WHEN** runner validates HTTP response and parses JSON
- **THEN** HTTP 200 is returned with correct Content-Type, `Cache-Control: no-store` and all mandatory
  response headers; addresses and SNI match the corresponding Host API records; no server-side private secrets
  appear in the subscription content; real `xray run -test` validates the config

#### Scenario: Mihomo YAML subscription verified

- **GIVEN** subscription fetched with valid Mihomo User-Agent
- **WHEN** runner validates HTTP response and parses YAML
- **THEN** HTTP 200 is returned with correct Content-Type; eight proxy entries with correct protocol and
  transport parameters are present; `GEOIP,private,DIRECT,no-resolve` rule is present; no duplicates; real
  `mihomo -t` validates the config

---

### Requirement: UFW Firewall Isolation Verification

The runner SHALL verify port `3002` isolation on both VPS. For Master, loopback connections succeed and
external connections are rejected (DROP). For Worker, connections from Master's actual egress IP succeed and
connections from the Control Machine are rejected (DROP). `Connection refused` alone is insufficient — DROP
MUST be confirmed via TCP timeout and optionally UFW counter inspection.

#### Scenario: Control Machine blocked from Worker:3002

- **GIVEN** Worker Node is active and Master can successfully connect to `WORKER_IP:3002` via mTLS
- **WHEN** Control Machine attempts TCP connection to `WORKER_IP:3002`
- **THEN** the connection times out without TCP RST, confirming DROP rather than REJECT; UFW counters on
  Worker show the rule was hit

#### Scenario: Master egress IP confirmed against UFW allowlist

- **GIVEN** Worker UFW allows only the Master egress IP on port 3002
- **WHEN** runner determines the actual source IP of Master → Worker connections
- **THEN** that IP matches the UFW allow rule; if it does not, the firewall test is marked FAIL

#### Scenario: IPv6 firewall isolation checked when enabled

- **GIVEN** `ENABLE_IPV6=true` is configured
- **WHEN** runner performs port 3002 isolation checks on both Master and Worker
- **THEN** all isolation verifications (loopback, Master egress allow, Control Machine DROP) are repeated on
  IPv6 interfaces and must pass with the same DROP semantics as IPv4

---

### Requirement: NGINX SNI Routing and REALITY Decoy Verification

The runner SHALL verify NGINX Stream routing behavior on port 443 for both Master and Worker. Expected
routing: Panel/Worker SNI → `127.0.0.1:7443`; Reality SNI → `127.0.0.1:8443`; default (unknown SNI) →
`127.0.0.1:8443`. Generated NGINX config SHALL pass `nginx -t`. Cover-reality assets SHALL be present and
PROXY protocol SHALL be correctly forwarded.

#### Scenario: Panel HTTPS accessible with correct SNI

- **GIVEN** Master NGINX is active and TLS certificate for `MASTER_PANEL_DOMAIN` is installed
- **WHEN** HTTPS connection is made to `MASTER_IP:443` with SNI `MASTER_PANEL_DOMAIN`
- **THEN** TLS terminates correctly, certificate is for the expected domain, Panel API health endpoint responds

#### Scenario: REALITY decoy does not leak GoWave API content

- **GIVEN** REALITY decoy site is installed
- **WHEN** an HTTPS request is made to the decoy endpoint with the REALITY domain SNI
- **THEN** the response contains the cover-reality site content, not GoWave Panel API responses or admin routes

#### Scenario: REALITY fallback and cover-reality assets present

- **GIVEN** NGINX is active on Master or Worker with REALITY SNI configured
- **WHEN** runner connects with the REALITY SNI but invalid REALITY client parameters and checks asset presence
- **THEN** REALITY fallback returns a decoy site response; a unique cover-reality site marker file is accessible;
  unknown SNI routes per NGINX + Xray REALITY fallback logic without returning GoWave API content

---

### Requirement: Data Plane E2E Traffic Through All Eight VPN Endpoints

The runner SHALL verify that real user VPN traffic passes through each of the eight endpoints independently.
For each endpoint: select the outbound from the real subscription, build a minimal temporary Xray client
config, start Xray as a subprocess, execute an HTTPS request via SOCKS5, verify egress IP and server-side
traffic evidence, then stop Xray and delete the temporary config. `TEST_TRAFFIC_VERIFICATION=false` SHALL
produce status `INCOMPLETE`, never `PASS`.

#### Scenario: Worker VLESS REALITY Vision tunnel carries user traffic

- **GIVEN** Worker is deployed, subscription is retrieved, Worker VLESS REALITY endpoint config extracted
- **WHEN** Xray client is started with that outbound and an HTTPS request is sent via SOCKS5 proxy
- **THEN** the request succeeds, egress IP matches expected Worker egress, and server-side traffic evidence
  (verified via iptables/nftables packet counters or tcpdump packet capture on the target inbound listener port)
  confirms ingress on Worker; Master inbound traffic counters do NOT increase (no Master relay)

#### Scenario: ACME staging CA handled during TLS tunnel traffic

- **GIVEN** `ACME_MODE=staging` is active and Xray/Mihomo clients execute traffic checks for the six TLS endpoints
- **WHEN** client processes initiate TLS handshakes against Master and Worker HTTPS/Xray endpoints
- **THEN** the client configuration trusts the Let's Encrypt Staging CA chain (or configures `allowInsecure: true`
  for the disposable test client runtime) preventing `x509: certificate signed by unknown authority` failures

#### Scenario: Skipped Data Plane results in INCOMPLETE

- **GIVEN** `TEST_TRAFFIC_VERIFICATION=false` is set
- **WHEN** the full run completes all other phases
- **THEN** overall status is `INCOMPLETE`, not `PASS`; JUnit XML marks all Data Plane test cases as SKIP

#### Scenario: Mihomo data plane verifies all eight endpoints

- **GIVEN** `TEST_MIHOMO_TRAFFIC=true` is configured and all eight Xray endpoint checks have passed
- **WHEN** runner loads the actual Mihomo subscription and repeats the eight traffic checks using a real
  Mihomo process
- **THEN** each of the eight endpoints passes; egress IP matches expected VPS egress for each; overall `PASS`
  requires all eight endpoints verified by both Xray and Mihomo runtime

---

### Requirement: Negative Scenario and Fault Injection Tests

The runner SHALL execute 15 negative scenarios (NEG-01 through NEG-15) on the disposable test VPS and verify
each expected outcome. Fault injection that may disrupt server state is permitted only on confirmed disposable
VPS.

#### Scenario: Matrix of fifteen fault scenarios verified (NEG-01..NEG-15)

- **GIVEN** a confirmed disposable VPS testbed
- **WHEN** the runner executes the negative test suite
- **THEN** all 15 scenarios terminate at their designated boundaries per the following matrix:

| Scenario ID | Component / Area | Fault Injection Method | Expected Failure Boundary & Outcome |
|-------------|------------------|------------------------|--------------------------------------|
| **NEG-01**  | Preflight SSH    | Host key absent or mutated in `known_hosts` | Terminate before any remote modification |
| **NEG-02**  | Preflight SSH    | Target SSH port closed / unreachable | Terminate with connectivity timeout before execution |
| **NEG-03**  | Preflight DNS    | Domain resolves to wrong IP address | Terminate before remote modification |
| **NEG-04**  | Preflight DNS    | Missing AAAA record when `ENABLE_IPV6=true` | Preflight failure before execution |
| **NEG-05**  | ACME Install     | Certbot challenge failure (NXDOMAIN / blocked 80) | Installation aborts; services not marked healthy |
| **NEG-06**  | NGINX Config     | Syntax corruption in `/etc/nginx/conf.d/*.conf` | `nginx -t` fails; runner blocks activation |
| **NEG-07**  | Worker Node      | `systemctl stop gowave-node` on Worker | Panel detects offline; `isConnected` becomes `false` |
| **NEG-08**  | Worker Node      | `systemctl start gowave-node` on Worker | Panel recovers; `isConnected` returns `true` |
| **NEG-09**  | Subscription     | Request without User-Agent header | Real Panel rejects with upstream policy code (e.g. 403) |
| **NEG-10**  | mTLS Control     | Forged / self-signed client certificate | Worker TLS 1.3 rejects handshake before HTTP handler |
| **NEG-11**  | Backup Restore   | Corrupted archive header / invalid tar format | Preflight check rejects before mutating live files |
| **NEG-12**  | Backup Restore   | SQLite DB file in archive corrupted | SQLite integrity check fails before replacing live DB |
| **NEG-13**  | Worker Deploy    | SSH pipeline interrupted mid-execution | Master recovery journal does NOT enter `COMMITTED` |
| **NEG-14**  | Worker Deploy    | Duplicate `node add` invocation for same node | Idempotent; no duplicate DB entities or hosts created |
| **NEG-15**  | Panel API Auth   | API request with expired or forged JWT | Panel returns 401 Unauthorized |

#### Scenario: Duplicate Worker re-registration is idempotent (NEG-14)

- **GIVEN** `worker-1` is already registered and all associated API objects exist
- **WHEN** `gowave-auto.sh node add worker-1` is executed again with the same parameters
- **THEN** `GET /api/nodes` still shows exactly one node named `worker-1`; no duplicate config profiles,
  hosts, or inbounds appear

#### Scenario: Partial SSH deployment leaves no false COMMITTED journal state (NEG-13)

- **GIVEN** SSH connection to Worker is interrupted mid-installation
- **WHEN** the runner inspects the recovery journal on Master
- **THEN** journal state is NOT `COMMITTED`; it is in a failure or recovery-required state requiring operator
  action before the Worker is considered registered

#### Scenario: Negative preflight and credential scenarios verified (NEG-01..NEG-10)

- **GIVEN** disposable VPS confirmed and negative test suite enabled
- **WHEN** runner executes NEG-01 through NEG-10 per the normative matrix
- **THEN** each scenario terminates or fails at the expected boundary; NEG-07 and NEG-08 bound Panel
  detection of Worker unavailability and reconnection within configured timeouts; NEG-10 rejects forged
  client certificate at TLS handshake before HTTP handler executes

#### Scenario: Backup and restore negative scenarios verified (NEG-11, NEG-12, NEG-15)

- **GIVEN** disposable VPS confirmed and negative test suite enabled
- **WHEN** runner executes NEG-11 (corrupted archive), NEG-12 (corrupted SQLite DB in archive), and NEG-15 (invalid JWT)
- **THEN** NEG-11: restore rejects before modifying live data; NEG-12: restore fails before stopping or
  replacing the live DB; NEG-15: authorized operations are rejected with 401

---

### Requirement: Teardown Policy Enforcement

The runner SHALL support three teardown policies: Preserve (`TEST_KEEP_VPS_ON_FAILURE=true`), Snapshot
Restore (`TEST_RESTORE_SNAPSHOT=true`), and Destroy (`TEST_DESTROY_VPS_ON_SUCCESS=true`). Destruction is
permitted only for VPS resources created by this runner in the current `TEST_RUN_ID`. Any cleanup action
SHALL be idempotent and scoped to resources proven to belong to the current test run.

#### Scenario: Pre-existing VPS not destroyed

- **GIVEN** `TEST_DESTROY_VPS_ON_SUCCESS=true` and VPS were manually provisioned (not created by Provider Adapter)
- **WHEN** the test run completes successfully
- **THEN** the runner does NOT issue any destroy API call; it sets teardown status to `NOT_RUN` or logs that
  destruction of pre-existing VPS is prohibited

#### Scenario: Preserve policy on failure

- **GIVEN** `TEST_KEEP_VPS_ON_FAILURE=true` and the test run fails at any phase
- **WHEN** teardown executes
- **THEN** full diagnostics are collected, `result.json` is written with status `FAILED_PRESERVED`, and the
  VPS is not destroyed

#### Scenario: Snapshot restore policy when snapshot absent

- **GIVEN** `TEST_RESTORE_SNAPSHOT=true` and the provider does not support snapshot API or snapshot is absent
- **WHEN** teardown attempts to restore the VPS to its pre-modification snapshot
- **THEN** teardown status is set to `TEARDOWN_UNAVAILABLE` rather than simulating success

---

### Requirement: Redacted Diagnostic Artifact Collection

The runner SHALL write per-run artifacts to `artifacts/live-vps/<TEST_RUN_ID>/` including `result.json`,
`junit.xml`, `summary.txt`, and structured log files. The following data SHALL NOT appear in any artifact:
credentials file content, `.env` file content, `SECRET_KEY`, private keys, admin password, scoped API
token, raw `shortUuid`, or subscription content containing private parameters.

#### Scenario: Redacted copy of credentials file

- **GIVEN** diagnostics collection runs on Master
- **WHEN** runner reads `/root/gowave-credentials.txt` for diagnostic summary
- **THEN** only field names (e.g., `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `SCOPED_API_TOKEN`) are recorded as
  present/absent; actual values are replaced with `[REDACTED]`; no plaintext secret appears in any artifact

#### Scenario: Diagnostic files contain required safe fields

- **GIVEN** a completed test run (any outcome)
- **WHEN** runner writes diagnostic files to the artifacts directory
- **THEN** diagnostic files contain: OS/kernel/version, package versions, systemd unit statuses, journal
  snippets, listener inventory, `nginx -t` output, firewall status and relevant rules, certificate metadata
  (without private keys), API object summaries, traffic test results, and timing metrics

---

### Requirement: Result Status Semantics

The runner SHALL use exactly the status values: `PASS`, `FAIL`, `SKIP`, `NOT_RUN`, `PARTIAL`, `INCOMPLETE`,
`TEARDOWN_FAILED`. `SKIP` and `NOT_RUN` SHALL NOT be treated as passing states. Overall `PASS` requires all
mandatory phases completed, all eight Data Plane endpoints verified, and teardown matching the declared policy.
`shortUuid` SHALL NOT appear in JUnit XML or any CI-published artifact.

#### Scenario: PASS requires all eight Data Plane checks

- **GIVEN** all installation, API, subscription, firewall, and NGINX phases are `PASS`
- **WHEN** only six of eight Data Plane endpoints pass (two fail)
- **THEN** overall status is `FAIL`, not `PASS`; `xray_data_plane` and `mihomo_data_plane` results are `FAIL`
  in `result.json`

#### Scenario: result.json schema fields present

- **GIVEN** a completed test run (any outcome)
- **WHEN** `result.json` is written
- **THEN** it contains: `test_run_id`, `repository_commit`, `started_at`, `finished_at`, `master` object
  (os, panel_version, node_version, xray_version, egress_ip), `worker` object (os, node_version,
  xray_version, egress_ip), `results` object with all mandatory phase keys, `traffic` object with
  master/worker sub-objects for each of four protocols, and `overall` status string
