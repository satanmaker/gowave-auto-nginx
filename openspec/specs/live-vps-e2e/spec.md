# Live VPS E2E Specification

## Purpose

Defines the observable behavior contract for the Live VPS E2E Test Runner — an automated acceptance tool that
validates the complete GoWave Auto NGINX distributed infrastructure lifecycle on real disposable servers over the
public internet, from bare OS through deployment, mTLS control plane, subscription delivery, and Data Plane VPN
traffic through eight logical endpoints by default (four core protocols on each VPS), nine when Vision is enabled
on only one VPS, or ten when Vision is enabled on both. Master and Worker Vision domains are independent.

## Requirements

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


### Requirement: Complete Mutation-Target Baseline and Resource Ownership

The runner SHALL inventory every host resource that the exact pinned Master or Worker install, failure
compensation, manual rollback, or teardown path may write, replace, enable, disable or remove. Absence of
a running GoWave service or a listening port is not proof that a system path is unowned. Unknown, unreadable,
or non-restorable pre-existing state SHALL fail the disposable gate before the first remote mutation.

#### Scenario: Existing Worker system configuration is not overwritten

- **GIVEN** /etc/sysctl.d/99-gowave-node.conf exists with unrelated sentinel content, while no GoWave
  service is running and the required ports are free
- **WHEN** disposable-baseline validation runs
- **THEN** it rejects the target or captures a complete same-host restorable before-image before any write;
  Worker configuration MUST NOT truncate the file and later treat it as transaction-created

#### Scenario: Existing Worker service or binary paths are not removed

- **GIVEN** one or more of the Worker systemd unit/drop-in paths, /usr/local/bin/xray,
  /usr/local/bin/gowave-node, or managed NGINX/webroot paths exist but GoWave services are inactive
- **WHEN** the runner validates rollback targets
- **THEN** it rejects those paths unless a complete ownership record and tested restore operation proves
  they belong to this run; rollback MUST preserve the unrelated object

#### Scenario: Existing firewall policy is preserved

- **GIVEN** UFW is active or contains non-default IPv4/IPv6 rules or default policies
- **WHEN** preflight evaluates the supported disposable baseline
- **THEN** the runner either rejects the baseline or records a complete restorable firewall before-image;
  after an injected failure, all original rules, default policies and enabled state are restored, not merely
  a selected subset of rules deleted

#### Scenario: Failure restores every transaction-owned resource

- **GIVEN** the runner has modified one or more inventoried resources and a later deployment step fails
- **WHEN** compensation completes
- **THEN** every transaction-created object is removed only while its identity/digest still match, every
  supported pre-existing object is restored to its recorded content and metadata, and any externally
  modified or unverifiable object is preserved with cleanup reported as incomplete


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

#### Scenario: Published AAAA is rejected when IPv6 testing is disabled

- **GIVEN** any configured FQDN returns one or more AAAA records while ENABLE_IPV6=false
- **WHEN** DNS preflight validates the complete A/AAAA/CNAME answers
- **THEN** preflight rejects the configuration before remote mutation; the runner MUST NOT silently ignore IPv6 addresses because IPv6 traffic checks are disabled

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

#### Scenario: Published AAAA records cannot bypass IPv6 verification

- **GIVEN** any configured Panel, REALITY, or independently configured Vision FQDN publishes an AAAA record
- **WHEN** preflight validates DNS and the listener/firewall policy
- **THEN** with ENABLE_IPV6=false preflight fails before remote modification; with ENABLE_IPV6=true,
  every AAAA answer from each independent resolver matches only the configured VPS IPv6 address and the
  corresponding listener/firewall checks are mandatory. Extra or conflicting address answers fail preflight.

---

### Requirement: Target Address, Domain, and SSH Identity Safety

The runner SHALL target two distinct public VPS IPv4 addresses and SHALL reject duplicate mandatory Panel/REALITY FQDNs; every configured Vision FQDN SHALL also be globally unique against all mandatory and other configured Vision FQDNs. E2E v1 SHALL connect to both VPS as `root`, because the current installer/orchestrator scripts do not provide a supported non-root `sudo` execution path. These checks SHALL complete before remote locks or any remote modification.

#### Scenario: Master and Worker target addresses must differ

- **GIVEN** `MASTER_IP` and `WORKER_IP` contain the same IPv4 address
- **WHEN** configuration preflight validates target identity
- **THEN** preflight fails before SSH mutation or lock acquisition; the runner does not treat two ports on one public address as two independently verified VPS instances

#### Scenario: Mandatory domains are pairwise unique

- **GIVEN** the four mandatory Master/Worker Panel and REALITY domains are configured
- **WHEN** configuration preflight validates the FQDNs
- **THEN** all four names are distinct; duplicates fail preflight before SSH

#### Scenario: Non-root SSH account is rejected in v1

- **GIVEN** either `MASTER_SSH_USER` or `WORKER_SSH_USER` is not `root`
- **WHEN** configuration or read-only SSH preflight validates execution identity
- **THEN** preflight fails before remote lock acquisition or any mutation; no implicit `sudo` fallback is attempted

---

### Requirement: Independent Optional Vision Domains

The runner SHALL accept `MASTER_VISION_DOMAIN` and `WORKER_VISION_DOMAIN` independently. Each configured
domain SHALL be provisioned and verified only on its corresponding VPS, including certificate, inbound,
Panel host, NGINX route, and fallback. A Vision installation failure SHALL fail the relevant host install
phase. When a host's Vision domain is absent, its default four-inbound topology remains unchanged.

#### Scenario: Master-only Vision configuration

- **GIVEN** `MASTER_VISION_DOMAIN` is configured and `WORKER_VISION_DOMAIN` is absent
- **WHEN** the whitelist configuration parser validates the E2E config
- **THEN** validation succeeds and the Master Vision endpoint is provisioned independently; the total endpoint count is nine

#### Scenario: Worker-only Vision configuration

- **GIVEN** `WORKER_VISION_DOMAIN` is configured and `MASTER_VISION_DOMAIN` is absent
- **WHEN** the whitelist configuration parser validates the E2E config
- **THEN** validation succeeds and the Worker Vision endpoint is provisioned independently; the total endpoint count is nine

#### Scenario: Both Vision domains are configured

- **GIVEN** both Vision domains are configured and valid DNS records resolve to their respective VPS addresses
- **WHEN** Master and Worker installation and Panel provisioning complete
- **THEN** each VPS has a valid certificate for its Vision domain, each node has five inbounds, the Panel has five matching hosts per node with correct node/inbound associations, and NGINX routes Vision SNI to 8444; Xray's `xver: 1` non-VLESS HTTP fallback reaches a loopback-only cleartext HTTP vhost on `127.0.0.1:9444` that accepts PROXY protocol and serves decoy content, not Panel/API content; the total endpoint count is ten

#### Scenario: Vision domains are unique

- **GIVEN** any subset of Vision domains is configured
- **WHEN** the whitelist configuration parser validates the E2E config
- **THEN** every configured Vision domain MUST differ from every other configured Vision domain and all four mandatory Panel/REALITY domains; duplicates fail preflight before SSH or remote modification

#### Scenario: Vision certificate failure aborts the relevant host installation

- **GIVEN** Vision is enabled but issuance, ACME-lineage validation, certificate hostname validation, or
  certificate/key verification fails on Master or Worker
- **WHEN** that host's installation stage executes
- **THEN** the stage fails and rolls back; no profile, host, certificate lineage created by the failed transaction, bootstrap name, stream-map entry,
  9444 fallback vhost, or deploy-hook side effect may be left advertising or serving an unusable Vision endpoint;
  pre-existing certificate lineages and unrelated resources MUST NOT be deleted by rollback

#### Scenario: Incomplete Vision compensation is reported, not hidden

- **GIVEN** Worker remote rollback or Panel API rollback fails after a Vision provisioning failure
- **WHEN** the orchestrator performs compensation
- **THEN** it checks both rollback results, returns nonzero, retains the recovery journal and records rollback/run status as incomplete; it MUST NOT suppress the remote rollback error or report cleanup PASS

#### Scenario: Vision disabled preserves the four-inbound topology

- **GIVEN** both Vision domain fields are absent
- **WHEN** Master and Worker are installed
- **THEN** each node has exactly four inbounds and four hosts, no Vision certificate or route is created, and
  the mandatory Data Plane matrix contains sixteen runtime cases

#### Scenario: Vision port gate applies only to the Vision-enabled host

- **GIVEN** exactly one of `MASTER_VISION_DOMAIN` or `WORKER_VISION_DOMAIN` is configured
- **WHEN** the disposable baseline gate evaluates each VPS
- **THEN** only the VPS whose own Vision domain is configured is required to keep the Vision ports `8444` and `9444` free, while the other VPS is evaluated against the default port set alone

### Requirement: Pinned Version Fidelity

Every test run SHALL record and verify the exact version of each software component: repository commit,
GoWave Panel version, GoWave Node version, upstream Node installer commit and SHA256, Xray server/rw-core
and client versions, Mihomo, NGINX, OpenSSL, OS and kernel, and SHA256 of installed binaries. If any required version cannot be
unambiguously pinned or verified, preflight SHALL terminate before installation.

#### Scenario: Version mismatch detected post-installation

- **GIVEN** `GOWAVE_PANEL_VERSION` is set to `1.2.3` in configuration
- **WHEN** the installed Panel binary is interrogated after installation
- **THEN** the runner records the installed version; if it does not match the configured version, the
  `master_install` result is set to `FAIL`

#### Scenario: Floating installer branch or installer digest mismatch rejected

- **GIVEN** `GOWAVE_NODE_INSTALLER_COMMIT` is not an explicit 40-hex commit, or the installer artifact SHA256
  does not match mandatory `GOWAVE_NODE_INSTALLER_SHA256`
- **WHEN** preflight validates the bundled Master installer and immutable remote Worker installer source
- **THEN** the runner terminates before installation; neither path may fall back to floating `main` or execute
  an installer whose bytes do not match the configured digest

#### Scenario: Server and client Xray versions are independently pinned

- **GIVEN** `XRAY_SERVER_VERSION` and `XRAY_CLIENT_VERSION` are configured
- **WHEN** preflight and post-install checks inspect the Node-managed server core and Control Machine client
- **THEN** both exact versions are recorded and compared independently; Node version alone is not accepted as
  evidence of the installed Xray core version; inability to identify either version prevents overall PASS

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

#### Scenario: Installer TLS/SNI probe trusts only the per-run CA bundle

- **GIVEN** `ACME_MODE=staging` and the runner has validated the D9 mode-specific CA bundle
- **WHEN** `gowave-auto.sh install` runs `verify_public_tls_sni` on Master
- **THEN** the runner stages that bundle in a root-only `/run` file and supplies `GOWAVE_TLS_CA_FILE`; the probe uses `-CAfile`, `-verify_return_error`, and `-verify_hostname`, so the staging certificate succeeds without adding Staging roots to `/etc/ssl/certs`; an untrusted test CA fails; the temporary bundle is removed on success or failure

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

After `gowave-auto.sh node add worker-1`, the runner SHALL verify successful registration,
pinned SSH host identity, active Worker services, valid certificates, passing `nginx -t`, and absence of
`SECRET_KEY` from the complete Master-side descendant argv trace covering both `execve` and `execveat`.
This trace does not observe remote Worker processes beyond the SSH boundary.

#### Scenario: SECRET_KEY is absent from a complete process argv trace

- **GIVEN** `gowave-auto.sh node add` is executing the SSH remote deployment on Master
- **WHEN** the runner traces the local Master-side descendant process tree (including the local SSH client)
  with
  `strace -f -v -s N -e trace=execve,execveat`, where `N=32 * os.sysconf("SC_PAGE_SIZE")`
- **THEN** the observer exits successfully, every `argv` vector and string is complete, the scanner parses
  escaped argv bytes and finds no exact or known encoded `SECRET_KEY` value; only this complete observation
  can PASS. The raw `envp` emitted by `-v` is discarded and MUST NOT enter reports or logs.

#### Scenario: Long argv string is not truncated

- **GIVEN** a test helper performs both `execve` and `execveat` with a sentinel embedded after byte 32
  of an argument
- **WHEN** the argv observer acceptance test runs with the computed positive `-s` limit
- **THEN** the complete sentinel is present in each corresponding parsed argument; a missing or truncated
  sentinel makes observer acceptance FAIL and the live observation INCOMPLETE

#### Scenario: Later argv elements are not abbreviated

- **GIVEN** a test helper performs both `execve` and `execveat` with at least 128 argv elements and places
  a sentinel only in the final element
- **WHEN** the argv observer runs with `-v` / `--no-abbrev`
- **THEN** the parser receives all 128 or more argv elements in order, including the complete final sentinel,
  and no strace omission marker. Any omitted element or ambiguous parse makes acceptance FAIL and the live
  observation INCOMPLETE

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

The runner SHALL verify public mTLS 1.3 control-plane connectivity from Master to Worker:3002 using
credentials extracted via `modules/node.sh:extract_secret_key` on Master. All Worker:3002 probes MUST originate
from Master. The runner SHALL independently report cryptographic validation, TLS handshake, HTTP health, and
authenticated Panel connectivity using existing verifier markers.

#### Scenario: Existing verifier succeeds with valid credentials

- **GIVEN** Worker is deployed and `gowave-node.service` is active
- **WHEN** Master obtains the already-Base64-encoded value from `modules/node.sh:extract_secret_key` and runs
  `modules/verify_node_mtls.py --host WORKER_IP --port 3002 --mode full` with that value unchanged on stdin
- **THEN** the verifier performs exactly one Base64 decode and emits `Payload cryptographic verification PASSED` before the socket attempt, then (on a successful handshake) `Handshake SUCCESS: TLSv1.3 negotiated` and `Node response: <status line>`; the runner MUST NOT Base64-encode the extractor output again and records these exact observations without logging the payload or derived SNI

#### Scenario: HTTP 200 is distinguished from HTTP 401

- **GIVEN** TLS 1.3 and the HKDF-derived SNI handshake succeeded
- **WHEN** the Node health endpoint responds
- **THEN** HTTP 200 sets `WORKER_HTTP_HEALTH_PASS`; HTTP 401 records `MTLS_HANDSHAKE_PASS` but does NOT set HTTP health or authenticated control-plane success

#### Scenario: Panel-to-Worker authenticated connectivity is independently verified

- **GIVEN** the local mTLS verifier completed
- **WHEN** the runner checks the real Panel's node state and authenticated connectivity through the documented Panel API
- **THEN** `PANEL_WORKER_AUTH_PASS` is set only when the Panel reports the Worker connected; a local 401 response MUST NOT be treated as proof of Panel authentication

#### Scenario: Untrusted client certificate rejected by Worker

- **GIVEN** Worker Node is active and Master can reach Worker:3002
- **WHEN** Master attempts TLS 1.3 with a self-signed client certificate not issued by the GoWave CA
- **THEN** Worker rejects the client certificate during handshake and no HTTP handler is reached

#### Scenario: Absent client certificate rejected by Worker

- **GIVEN** Worker Node requires mTLS
- **WHEN** Master attempts TLS 1.3 without presenting a client certificate
- **THEN** Worker rejects the handshake before the HTTP handler

#### Scenario: Mismatched client certificate and private key is classified as local failure

- **GIVEN** the runner pairs a valid client certificate with a different private key
- **WHEN** the existing `validate_payload_crypto()` validation path compares the certificate public key with the private key's derived public key through OpenSSL
- **THEN** local cryptographic validation fails before any socket is opened; the runner records a client-side validation failure, not a remote Worker handshake rejection

#### Scenario: Untrusted Worker CA is classified as client-side server verification failure

- **GIVEN** the runner has already derived the valid HKDF SNI and has a valid client certificate/key
- **WHEN** Master connects with that same SNI and client identity but replaces only its server-trust store with one that does not contain the GoWave CA
- **THEN** Master rejects the Worker certificate during server-certificate validation; the test isolates trust failure without changing SNI or client identity and is not reported as Worker rejecting the client

#### Scenario: Wrong SNI routing is measured without assuming a TLS alert

- **GIVEN** the valid derived SNI and normal connection pass
- **WHEN** Master connects using a deliberately incorrect SNI
- **THEN** the runner records the actual NGINX/default-route and TLS outcome; it MUST NOT assume that every wrong SNI necessarily produces a TLS handshake failure

### Requirement: TLS-aware Bounded Panel API Client

The runner SHALL query Panel REST APIs over public HTTPS with strict hostname and certificate validation.
The client SHALL support an injected SSLContext and configurable `API_TIMEOUT` via backward-compatible
optional constructor parameters passed to `urllib.request.urlopen`, preserving existing defaults when omitted.

#### Scenario: Panel API client uses scoped trust and configured timeout

- **GIVEN** `ACME_MODE=staging` and a validated combined CA bundle
- **WHEN** `panel_api.py` logs in and requests the real Panel API over HTTPS
- **THEN** the request uses an SSL context loaded from that bundle, retains hostname verification, uses
  `API_TIMEOUT` per request attempt, and does not use `allowInsecure` or a trust bypass; normal production
  callers that omit the optional parameters retain their current behavior

---

### Requirement: Panel API Cluster Structure Audit

The runner SHALL verify the complete Panel API object graph against the real GoWave Panel using authenticated
REST API calls. On a clean test environment the runner SHALL confirm node count, inbound count, config profile
correctness, Internal Squad membership by set equality, and all Host record fields — with no duplicates.

#### Scenario: Hosts present with correct node and inbound associations

- **GIVEN** Master installed and Worker deployed on a clean test environment
- **WHEN** runner queries `GET /api/hosts`
- **THEN** exactly eight, nine, or ten according to the number of configured Vision domains Host records exist; four (or five) reference `local-node` UUID and four (or five) reference `worker-1`
  UUID; each Host's `inbound UUID` matches one of the inbounds in the corresponding node's config profile; REALITY hosts carry the configured REALITY fingerprint (`firefox` by
default, overridable via `REALITY_FINGERPRINT`) and every TLS host carries `fingerprint: firefox`

#### Scenario: Internal Squad contains all provisioned inbound UUIDs

- **GIVEN** both nodes are registered with four (or five) inbounds each
- **WHEN** runner queries `GET /api/internal-squads` for `Default MVP Squad`
- **THEN** the squad's inbound list contains exactly the eight (or ten) UUIDs (four or five from Master profile, four or five from
  Worker profile) with no duplicates — verified by set equality

#### Scenario: Two nodes and two config profiles with correct structure

- **GIVEN** Master installed and Worker deployed on a clean test environment
- **WHEN** runner queries `GET /api/nodes` and `GET /api/config-profiles`
- **THEN** exactly two nodes exist (`local-node` at `127.0.0.1:3002` and `worker-1` at `WORKER_IP:3002`),
  each with four (or five with vision) active inbounds and unique UUIDs; two config profiles each have four (or five) inbounds and valid
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

#### Scenario: Proxy-capable outbounds in Xray JSON

- **GIVEN** subscription fetched with valid Xray User-Agent
- **WHEN** runner parses the JSON and counts proxy-capable outbounds
- **THEN** exactly eight, nine, or ten according to the number of configured Vision domains outbounds are identified by protocol/transport tag (VLESS REALITY, VLESS XHTTP
  TLS, VLESS WS TLS, Trojan gRPC TLS, and optional VLESS XTLS Vision TLS) for Master and Worker; REALITY
  outbounds carry the configured REALITY fingerprint (`firefox` by default) and TLS outbounds carry
  `fingerprint: "firefox"`; `direct`, `block`, and routing-only entries
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
- **THEN** HTTP 200 is returned with correct Content-Type; eight, nine, or ten according to the number of configured Vision domains proxy entries with correct protocol and
  transport parameters are present; REALITY entries carry `client-fingerprint` equal to the configured REALITY
  fingerprint (`firefox` by default) and the TLS transports carry `client-fingerprint: "firefox"`;
  `GEOIP,private,DIRECT,no-resolve` rule is present; no duplicates; real
  `mihomo -t` validates the config

---

### Requirement: UFW Firewall Isolation Verification

The runner SHALL verify isolation of TCP/3002 on Master and Worker. A timeout alone is not sufficient evidence of UFW DROP. Each negative probe MUST be paired with a known-good positive probe to establish that the listener and route are functional. The runner SHALL inspect the effective UFW rules and, where available, rule counters or packet capture evidence on the target VPS.

#### Scenario: Worker allows Master and blocks Control Machine

- **GIVEN** Worker Node is active and a positive mTLS probe from Master succeeds
- **WHEN** the runner records the source address seen by Worker for that successful connection and then probes Worker:3002 from Control Machine
- **THEN** the observed Master source address matches the effective UFW allow rule; the Control Machine probe is blocked; and Worker-side UFW rule/counter or packet trace confirms the DROP path. The Worker MUST also observe the actual source address of the Control Machine probe and prove it differs from the allowed Master source. If the two source addresses are equal, this negative probe is `INCOMPLETE`, not a firewall PASS; a distinct external probe vantage is required

#### Scenario: Negative probe is not misclassified

- **GIVEN** a Control Machine connection to Worker:3002 fails
- **WHEN** the runner evaluates the result
- **THEN** `Connection refused`, route failure, DNS failure, or timeout without a successful Master control probe and Worker-side firewall evidence MUST NOT count as firewall PASS; ambiguous evidence is `INCOMPLETE`

#### Scenario: Master local and external access are distinguished

- **GIVEN** Master Node is listening on loopback port 3002 and external isolation is configured
- **WHEN** the runner probes loopback from Master and the public endpoint from Control Machine
- **THEN** loopback succeeds; the external probe is blocked; and the DROP rule/counter or packet trace is
  collected on Master itself. Worker-side evidence MUST NOT be used to prove Master firewall behavior.

#### Scenario: IPv6 firewall isolation checked when enabled

- **GIVEN** `ENABLE_IPV6=true` and valid AAAA routing are configured
- **WHEN** runner repeats the positive and negative probes over IPv6
- **THEN** the observed IPv6 source address matches the allowlist and the allowed Master probe succeeds;
  the Control Machine probe is blocked with DROP evidence collected on the VPS being tested (Master or Worker).

### Requirement: NGINX SNI Routing and REALITY Decoy Verification

The runner SHALL verify NGINX Stream routing behavior on port 443 for both Master and Worker. Expected
routing: Panel/Worker SNI → `127.0.0.1:7443`; Reality SNI → `127.0.0.1:8443`; optional Vision SNI →
`127.0.0.1:8444`; default (unknown SNI) → `127.0.0.1:8443`. Generated NGINX config SHALL pass `nginx -t`.
Cover-reality assets and fallbacks SHALL be present and PROXY protocol SHALL be correctly forwarded.

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

#### Scenario: Optional Vision SNI routing and decoy fallback

- **GIVEN** both Vision domains are configured and NGINX Stream is active
- **WHEN** runner connects with vision domain SNI using a non-VLESS HTTP probe
- **THEN** traffic routes to loopback port 8444 and falls back to loopback port 9444 returning decoy site content via PROXY protocol

---

### Requirement: Data Plane E2E Traffic Through All VPN Endpoints

The runner SHALL verify all logical endpoints (four core protocols on Master and Worker by default; plus optional
VLESS XTLS Vision when configured). Each active endpoint MUST be exercised independently by both a real Xray
client process and a real Mihomo client process, yielding sixteen, eighteen, or twenty mandatory runtime cases.
All tests SHALL use actual subscription data and verify client-observed egress plus target-VPS ingress evidence;
syntax checks do not count.

#### Scenario: All active logical endpoints are exercised by both clients

- **GIVEN** the real Xray JSON and Mihomo YAML subscriptions each contain four or five Master and four or five Worker proxy entries
- **WHEN** the runner executes the Data Plane phase
- **THEN** it runs Xray and Mihomo independently against each of the active logical endpoints (16, 18, or 20 cases total), both clients using the configured REALITY fingerprint (`firefox` by default); all cases must pass for overall `PASS`

#### Scenario: Tunnel setup tolerates one cold resolver stall

- **GIVEN** `TRAFFIC_TIMEOUT` bounds every Xray and Mihomo egress request
- **WHEN** a client must resolve the target hostname without a cached answer
- **THEN** the curl connect budget is at least half of `TRAFFIC_TIMEOUT` and never below 10 seconds, so a single 5-second resolver stall cannot fail an otherwise healthy endpoint

#### Scenario: Clients are the cores deployed by Panel and Node

- **GIVEN** the pinned `XRAY_CLIENT_VERSION` and `MIHOMO_CLIENT_VERSION` binaries on the Control Machine
- **WHEN** the runner executes the Data Plane phase
- **THEN** exactly those two pinned cores are exercised against the subscription (no alternative or
  replacement client binaries), matching the server cores that GoWave Panel and GoWave Node deploy

#### Scenario: Xray runtime request traverses the selected Master endpoint

- **GIVEN** a Master endpoint outbound has been extracted from the real Xray subscription
- **WHEN** a real Xray process exposes a local SOCKS5 listener and the runner sends an HTTPS request through that selected outbound
- **THEN** the request succeeds, egress matches the configured Master expectation (or documented direct-egress baseline), and isolated packet evidence increases on Master during the request window

#### Scenario: Mihomo runtime configuration is isolated on Control Machine

- **GIVEN** a real Mihomo subscription YAML fetched from the Panel
- **WHEN** the runner prepares the per-run Mihomo config
- **THEN** it preserves all proxy definitions and routing rules but assigns collision-free loopback-only
  mixed/SOCKS/redir/controller listeners, verifies `allow-lan: false` and controller binding to `127.0.0.1`,
  and refuses to launch if any control endpoint would bind to a non-loopback interface

#### Scenario: Mihomo runtime request traverses the selected Master endpoint

- **GIVEN** a Master proxy has been selected from the real Mihomo subscription
- **WHEN** a real Mihomo process is running and the runner selects that proxy through its supported controller/API or a dedicated generated config
- **THEN** the HTTPS request succeeds through the selected proxy, egress is verified, and Master ingress evidence increases during the isolated window

#### Scenario: Xray runtime request traverses the selected Worker endpoint

- **GIVEN** a Worker endpoint outbound has been extracted from the real Xray subscription
- **WHEN** a real Xray process sends an HTTPS request through the selected Worker outbound
- **THEN** the request succeeds, egress matches the configured Worker expectation (or documented direct-egress baseline), Worker ingress evidence increases, and Master ingress evidence does not increase for that controlled request

#### Scenario: Mihomo runtime request traverses the selected Worker endpoint

- **GIVEN** a Worker proxy has been selected from the real Mihomo subscription
- **WHEN** a real Mihomo process sends an HTTPS request through the selected Worker proxy
- **THEN** the request succeeds, egress is verified, Worker ingress evidence increases, and Master ingress evidence does not increase for that controlled request

#### Scenario: Staging and public CA chains are both trusted without bypass

- **GIVEN** `ACME_MODE=staging` and the runner has built its scoped combined CA bundle
- **WHEN** Python, curl, Xray and Mihomo perform their respective TLS requests
- **THEN** each client validates both a Let's Encrypt Staging endpoint and an ordinary public-CA endpoint
  (including the public HTTPS egress probe); an untrusted test CA is rejected; `allowInsecure` and
  `skip-cert-verify` are prohibited

#### Scenario: Xray TLS outbounds carry explicit Staging trust anchors

- **GIVEN** `ACME_MODE=staging` and the runner has built its scoped combined CA bundle
- **WHEN** the runner prepares an Xray outbound whose `streamSettings.security` is `tls`
- **THEN** it appends one `{"usage": "verify", "certificateFile": <staged bundle path>}` entry per pinned
  Staging root to `streamSettings.tlsSettings.certificates`, because Xray ignores `SSL_CERT_FILE` and reads
  only hardcoded system CA paths; REALITY outbounds are left unmodified since they trust the pinned key
  instead of a CA chain; `allowInsecure` stays absent, and in `ACME_MODE=production` no anchors are injected

#### Scenario: Staging CA material is pinned and reproducible

- **GIVEN** `ACME_MODE=staging`
- **WHEN** TLS preflight loads `tools/certs/letsencrypt-staging/`
- **THEN** exactly the four official self-signed Staging roots identified in design D9 are present and
  individually match the DER SHA-256 values in `pins.json`; no intermediate is treated as a trust anchor,
  no certificate is downloaded at runtime, and a missing or mismatched pin fails preflight before any
  remote modification


#### Scenario: Production mode does not add Staging roots to trust

- **GIVEN** `ACME_MODE=production`
- **WHEN** the runner constructs the mode-specific TLS bundle
- **THEN** the bundle contains the complete public CA roots and no Let's Encrypt Staging roots; a Staging-only
  chain remains untrusted, and ordinary public-CA endpoints continue to validate

#### Scenario: Ingress evidence is ambiguous

- **GIVEN** unrelated background traffic changes the same listener counters during the test window
- **WHEN** the runner cannot attribute ingress evidence to the controlled request
- **THEN** that case is `INCOMPLETE`, not `PASS`

#### Scenario: Data Plane is explicitly disabled

- **GIVEN** `TEST_TRAFFIC_VERIFICATION=false` or Mihomo runtime testing is disabled
- **WHEN** the full run completes the remaining phases
- **THEN** the skipped cases are recorded as `SKIP` and overall status is `INCOMPLETE`, never `PASS`

#### Scenario: One or more mandatory runtime cases fail

- **GIVEN** the sixteen-, eighteen-, or twenty-case runtime matrix is required
- **WHEN** any Xray or Mihomo case fails
- **THEN** the corresponding case is `FAIL` and overall status is `FAIL`

### Requirement: Negative Scenario and Fault Injection Tests

The runner SHALL execute fifteen negative scenarios (NEG-01 through NEG-15) and verify each designated failure
boundary. Preflight tests NEG-01..NEG-04 SHALL use isolated local fixtures without mutating live host state,
NEG-05 SHALL use an isolated Certbot failpoint or staging domain, and live VPS tests NEG-06..NEG-15 SHALL
execute guaranteed cleanup and post-case baseline verification.

#### Scenario: Matrix of fifteen fault scenarios verified (NEG-01..NEG-15)

- **GIVEN** a valid E2E config with isolated local preflight fixtures and a confirmed disposable VPS testbed for the live fault-injection cases
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
| **NEG-14**  | Worker Deploy    | Duplicate `node add` when the worker name is already in `state.json` | Explicit fail-fast rejection before API mutation; no duplicate DB entities or hosts |
| **NEG-15**  | Panel API Auth   | API request with expired or forged JWT | Panel returns 401 Unauthorized |

#### Scenario: Duplicate Worker registration is rejected without mutation (NEG-14)

- **GIVEN** `worker-1` is already present in Master `state.json` and all associated API objects exist
- **WHEN** `gowave-auto.sh node add worker-1` is invoked again with the same parameters
- **THEN** the command exits nonzero with the existing-name rejection before constructing `GoWaveClient` or issuing any Panel API request; `state.json` is unchanged and the existing single node, profile, hosts, and inbounds remain unchanged

#### Scenario: Partial SSH deployment leaves no false COMMITTED journal state (NEG-13)

- **GIVEN** SSH connection to Worker is interrupted mid-installation
- **WHEN** the runner inspects the recovery journal on Master
- **THEN** journal state is NOT `COMMITTED`; it is in a failure or recovery-required state requiring operator
  action before the Worker is considered registered
- **AND** the recorded rollback removes the partial Panel entities and the Worker entry from `state.json`, leaving
  its content equal to the pre-dispatch snapshot apart from the update timestamp, and releases the host mutation lock

#### Scenario: Preflight, lifecycle, and protocol scenarios verified (NEG-01..NEG-10)

- **GIVEN** isolated fixtures for NEG-01..NEG-04, an isolated ACME failure setup for NEG-05, and a confirmed disposable VPS for the live scenarios
- **WHEN** runner executes NEG-01 through NEG-10 per the normative matrix
- **THEN** each scenario terminates or fails at the expected boundary; NEG-07 and NEG-08 bound Panel
  detection of Worker unavailability and reconnection within configured timeouts; NEG-10 rejects forged
  client certificate at TLS handshake before HTTP handler executes

#### Scenario: Backup and restore negative scenarios verified (NEG-11, NEG-12)

- **GIVEN** disposable VPS confirmed and negative test suite enabled
- **WHEN** runner executes NEG-11 (corrupted archive) and NEG-12 (corrupted SQLite DB in archive)
- **THEN** NEG-11: restore rejects before modifying live data; NEG-12: restore fails before stopping or
  replacing the live DB

#### Scenario: Forged or expired Panel JWT is rejected (NEG-15)

- **GIVEN** the runner has an otherwise valid authenticated Panel API session
- **WHEN** it sends a protected Panel API request with a forged or expired JWT
- **THEN** the Panel returns HTTP 401 and the request is recorded as an authentication-negative PASS

---

#### Scenario: Negative suite PASS requires all fifteen scenarios to pass

- **GIVEN** `TEST_NEGATIVE_SUITE=true`
- **WHEN** the negative phase completes with any scenario `FAIL`, `SKIP`, `NOT_RUN`, `PARTIAL`, or `INCOMPLETE`
- **THEN** `negative_tests` is not `PASS` and overall status cannot be `PASS`; it is `FAIL` for a failed
  assertion and `INCOMPLETE` when required evidence or execution is missing

#### Scenario: Negative suite cannot be silently skipped for a passing run

- **GIVEN** `TEST_NEGATIVE_SUITE=false`
- **WHEN** the full run reaches the negative-test phase
- **THEN** all 15 negative scenarios are explicitly recorded as `SKIP` and overall status is `INCOMPLETE`;
  the run MUST NOT be reported as `PASS`

---

### Requirement: Global Certbot Deploy Hook Ownership

Installers SHALL protect the shared Certbot deploy hook through explicit transaction ownership.
A pre-existing unowned hook blocks mutation; a transaction-created hook is journaled and may be removed only
while its recorded identity and digest still match. Unverifiable ownership requires incomplete recovery.

#### Scenario: Pre-existing global deploy hook blocks installation safely

- **GIVEN** Master or Worker already has a deploy hook at the managed path, including a symlink or non-regular object
- **WHEN** the runner performs disposable-baseline and hook-ownership preflight
- **THEN** it fails before remote mutation and preserves the original path, target, bytes, owner, group, and mode

#### Scenario: Transaction-created hook is cleaned up only while still owned

- **GIVEN** the hook path was absent at preflight and the current transaction creates the managed hook
- **WHEN** a later installation failure triggers compensation
- **THEN** rollback removes the hook only if the journal proves transaction ownership and the current identity/digest still match; a modified/replaced path is preserved and cleanup is marked incomplete

#### Scenario: Uncatchable Worker termination is recovered before the next mutation

- **GIVEN** a previous Worker deployment was terminated by SIGKILL, kernel panic or power loss after writing an uncommitted transaction journal
- **WHEN** the next authenticated Worker management or recovery entrypoint is invoked
- **THEN** it discovers and reconciles the uncommitted journal before accepting any new mutation; if recovery cannot be fully verified, it rejects the new operation, retains the journal and reports INCOMPLETE

#### Scenario: PRESERVE reports package-manager residuals without claiming OS baseline restoration

- **GIVEN** the installation transaction has installed or upgraded OS packages and package post-install scripts have created service defaults
- **WHEN** compensation or teardown completes under TEST_TEARDOWN_POLICY=PRESERVE
- **THEN** the report records the package changes as retained residual state and distinguishes transaction compensation from restoration of the original OS baseline; the VPS is not eligible for another clean-baseline run until re-imaged or restored through the verified snapshot procedure


### Requirement: Signal-Safe and Verifiable Transaction Compensation

Worker deployment and Master orchestration SHALL provide crash/signal-safe, transaction-scoped compensation.
A cleanup attempt SHALL NOT be considered successful until each required resource has been verified against
the ownership journal and pre-install baseline.

#### Scenario: Worker deployment is interrupted by a signal

- **GIVEN** remote Worker deployment has mutated at least one resource and has not committed
- **WHEN** the remote shell receives HUP, INT or TERM
- **THEN** it stops starting new mutations, persists interruption state, executes compensation exactly once,
  verifies the result, and exits nonzero; secret/temp-file cleanup alone is not sufficient

#### Scenario: Remote rollback cannot claim success after a failed cleanup step

- **GIVEN** the Worker rollback encounters a Certbot, filesystem, NGINX, systemd, UFW or sysctl cleanup error
- **WHEN** the compensator reports its result to Master
- **THEN** it returns a versioned per-resource result with status INCOMPLETE, nonzero exit and retained
  recovery journal; exit zero and ROLLED_BACK are permitted only after all required final states are verified

#### Scenario: Worker and Panel API rollback results are both required

- **GIVEN** Worker compensation succeeds but Panel API rollback fails, or vice versa
- **WHEN** Master finalizes the failed node add transaction
- **THEN** it retains both recovery records, reports the overall operation as INCOMPLETE, and MUST NOT
  mark the transaction rolled back or committed until both sides are verified


### Requirement: Teardown Policy Enforcement

The runner SHALL accept one mutually exclusive `TEST_TEARDOWN_POLICY`: `PRESERVE` (default) or
`RESTORE_SNAPSHOT`. `DESTROY` and invalid restore configurations fail preflight before remote modification.
Teardown is reported separately from test outcome; overall `PASS` requires the selected policy to complete.

#### Scenario: Destroy policy rejected before the run starts

- **GIVEN** `TEST_TEARDOWN_POLICY=DESTROY`
- **WHEN** configuration preflight validates the teardown policy
- **THEN** preflight fails before any remote modification and records that destruction is unsupported in v1

#### Scenario: Preserve policy after success or failure

- **GIVEN** `TEST_TEARDOWN_POLICY=PRESERVE`
- **WHEN** the test run completes with any test outcome
- **THEN** diagnostics are collected, the actual test outcome is retained, and teardown is recorded separately as
  `PASS`; `PRESERVE` itself does not uninstall, restore, reimage, or destroy either VPS, so all mutations made by
  the test run remain in place and the next run requires operator re-image or verified snapshot restoration

#### Scenario: Snapshot restore hook configuration and protocol are validated

- **GIVEN** `TEST_TEARDOWN_POLICY=RESTORE_SNAPSHOT`
- **WHEN** configuration preflight validates the teardown policy
- **THEN** both `MASTER_SNAPSHOT_ID` and `WORKER_SNAPSHOT_ID`, an absolute `SNAPSHOT_RESTORE_HOOK` path,
  and `SNAPSHOT_RESTORE_HOOK_SHA256` MUST be supplied; the hook MUST be an absolute path to a non-symlink regular executable owned by the
  runner user or root, not group/world-writable, and its digest MUST match before the run and immediately before execution. Missing or invalid values fail
  preflight before remote modification.

#### Scenario: Restore hook receives a versioned request and returns both restored resources

- **GIVEN** preflight accepted both snapshot IDs and the SHA256-pinned external restore hook
- **WHEN** teardown invokes the hook directly without a shell, passing JSON on stdin
- **THEN** the request contains `schema_version: 1`, `action: "restore"`, `test_run_id`, and
  `master`/`worker` objects containing `address` and `snapshot_id`; the hook exits zero and returns valid
  JSON with `schema_version: 1`, `status: "RESTORED"`, and matching `snapshot_id` plus `restored: true`
  for both hosts. Hook execution is bounded by `RESTORE_TIMEOUT`.

#### Scenario: Snapshot restore reacquires the remote lock pair before baseline verification

- **GIVEN** snapshot restoration has rebooted one or both VPS; the original lock-holder session on a non-rebooted host may still be alive
- **WHEN** both restored VPS become reachable again
- **THEN** the runner explicitly closes/releases both original holder sessions (including any surviving session), confirms termination, then reacquires a fresh pair in deterministic address order before validating saved run identity and the clean baseline. It never acquires a replacement lock while its own previous holder may still own that host lock. If another controller acquires either lock during the release/reacquisition window, any lock already reacquired is released and teardown becomes `TEARDOWN_FAILED`; failure to reacquire, identity mismatch, or baseline mismatch also yields `TEARDOWN_FAILED`, never `PASS`

#### Scenario: Single-host snapshot reboot does not self-deadlock lock reacquisition

- **GIVEN** only Master (or only Worker) is rebooted by the restore hook and the other VPS remains online with its original SSH lock-holder session
- **WHEN** both hosts become reachable and the runner prepares the post-restore baseline check
- **THEN** it closes/releases the surviving old holder before acquiring the pair again; the test proves no self-deadlock, both locks are held during baseline verification, and a competing controller winning either lock causes safe `TEARDOWN_FAILED`

#### Scenario: Snapshot restore hook success requires baseline verification

- **GIVEN** the restore hook returns valid `RESTORED` JSON with matching IDs and the runner has reacquired both remote locks
- **WHEN** the runner recollects the Phase 0 baseline manifest while holding both locks
- **THEN** the required clean-baseline invariants match the pre-install manifest; only then may teardown be `PASS`

#### Scenario: Snapshot restore hook does not restore both hosts

- **GIVEN** preflight accepted the SHA256-pinned restore hook and both snapshot IDs
- **WHEN** the hook times out, exits nonzero, returns invalid/mismatched JSON, or restored VPS fail the baseline check
- **THEN** teardown is `TEARDOWN_FAILED`; neither test nor teardown status may be represented as overall `PASS`

---

### Requirement: Pair-Wide Run Locking

The runner SHALL prevent concurrent mutating runs against either target VPS, including runs started from
different Control Machines. It SHALL use a local process lock as a fast guard and authoritative kernel locks
on both Master and Worker, held for the complete mutating operation. Remote locks SHALL be acquired in
deterministic address order and MUST be held through dedicated SSH lock-holder sessions.

#### Scenario: A second Control Machine cannot acquire an occupied VPS

- **GIVEN** one runner holds the authoritative remote lock on either target VPS
- **WHEN** another runner attempts a run against the same Master or Worker from another Control Machine
- **THEN** it fails before remote modification; a lock-file's mere existence is not treated as ownership

#### Scenario: Loss of a remote lock-holder session fails closed

- **GIVEN** a mutating run holds both remote locks
- **WHEN** either SSH lock-holder session is lost
- **THEN** the runner stops starting mutating phases, records `INCOMPLETE`, and MUST NOT resume until it has
  reacquired both locks and revalidated the saved run state

---

### Requirement: Shared Mutation Lock Across All Management Entry Points

The runner SHALL coordinate with every supported GoWave mutation command on both VPS through the same
host-wide kernel lock protocol. A separate E2E-only lock does not provide exclusivity against ordinary
operator commands.

#### Scenario: Existing management command is blocked while the E2E run owns the host

- **GIVEN** the E2E runner holds the pair-wide lock on Master and Worker
- **WHEN** another session invokes gowave-auto.sh install, node add/rollback, domain-change,
  channel switch, uninstall, backup restore, or Worker remote_payload/remote_rollback without the
  active run's re-entrant lease
- **THEN** the command fails before its first mutation; it cannot bypass the E2E lock by using a separate
  lock file or by not acquiring a lock

#### Scenario: Runner-owned nested command does not release exclusivity

- **GIVEN** the E2E runner holds both remote locks and supplies a valid run-bound lease through stdin to a
  child deployment/rollback command
- **WHEN** that child performs its authorized mutations
- **THEN** it is accepted only while the original kernel lock holder and lease remain valid; another
  controller still fails to acquire either host lock, and a stale/replayed lease is rejected after holder loss

#### Scenario: Unsafe remote lock path is rejected

- **GIVEN** the remote lock file or any parent directory is a symlink, non-regular object, wrong-owner
  file, or has unsafe permissions
- **WHEN** the runner acquires the pair-wide lock
- **THEN** it fails closed before any remote modification and does not follow, replace or unlink the object


### Requirement: Durable Run State for Partial CLI Modes

The runner SHALL persist an atomic mode-`0600` `run-state.json` under `artifacts/live-vps/<TEST_RUN_ID>/`
containing non-secret execution metadata, phase statuses, and timestamps. Partial modes following `preflight`
SHALL require `--run-id` and a matching state record. The runner SHALL never overwrite existing run directories
or persist credentials, tokens, or secret keys.

#### Scenario: Run ID cannot escape the artifact root

- **GIVEN** an operator supplies a `--run-id` containing `..`, a path separator, NUL, or a symlinked path component
- **WHEN** the CLI validates the run ID and constructs its artifact directory
- **THEN** the CLI rejects it before creating files or contacting either VPS; accepted IDs match `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` and resolve strictly below `artifacts/live-vps/`

#### Scenario: Partial mode cannot resume a different run or repeat completed installation

- **GIVEN** preflight has created a stored run state for a specific repository commit, Master/Worker addresses
  and non-secret config identity
- **WHEN** `install`, `verify`, `traffic`, `negative`, or `teardown` is invoked with the printed run ID
- **THEN** the runner verifies the matching state and prerequisite phase statuses before remote modification;
  completed phases are not repeated implicitly; missing state, mismatched identity or unmet prerequisites fail
  closed. `install` requires preflight PASS, reacquires both remote locks, and re-collects the disposable
  baseline while holding those locks; any drift from the stored preflight snapshot fails before modification.
  `verify` requires install PASS, `traffic` requires verification PASS, `negative` requires an installed
  disposable environment, and `teardown` requires the original baseline and diagnostic state.

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
and `TEARDOWN_FAILED`. Overall `PASS` requires all mandatory phases completed, all sixteen, eighteen, or twenty Data Plane
runtime cases verified according to the configured Vision domains, verified temporary SSH-key cleanup, and
the declared teardown policy completed. `SKIP` and `NOT_RUN` are non-passing.
`shortUuid` SHALL NOT appear in JUnit XML or any CI-published artifact.

#### Scenario: PASS requires all active Data Plane runtime cases

- **GIVEN** Vision is disabled and all installation, API, subscription, firewall, and NGINX phases are `PASS`
- **WHEN** only fourteen of sixteen runtime cases pass (two fail)
- **THEN** overall status is `FAIL`, not `PASS`; the failing protocol/client cases are identified individually in `result.json`

#### Scenario: Vision-enabled PASS requires all active runtime cases

- **GIVEN** one or both Vision domains are configured and all installation, API, subscription, firewall, and NGINX phases are `PASS`
- **WHEN** any active runtime case fails
- **THEN** overall status is `FAIL`, not `PASS`; each failed Vision or core protocol/client case is identified individually in `result.json` and JUnit XML

#### Scenario: result.json schema fields present

- **GIVEN** a completed test run (any outcome)
- **WHEN** `result.json` is written
- **THEN** it contains: `test_run_id`, `repository_commit`, `started_at`, `finished_at`, `control_machine`, `master`,
  `worker`, `trust`, `results`, `traffic`, and `overall`. `control_machine` records OS/kernel, Python, OpenSSL,
  Xray client and Mihomo versions plus installed-binary SHA256 values. `master` records OS/kernel, Panel and Node
  versions, Node installer commit and SHA256, Node-managed Xray/rw-core version, NGINX/OpenSSL versions,
  egress IP and installed-binary SHA256 values. `worker` records OS/kernel, Node version, the same Node installer
  commit and SHA256, Node-managed Xray/rw-core version, NGINX/OpenSSL versions, egress IP and installed-binary
  SHA256 values. `trust` records ACME mode and, for staging, the public CA bundle SHA256, Staging pin-manifest
  SHA256 and validated root subjects. `results` contains all mandatory phase keys; `traffic` contains
  Master/Worker sub-objects for each of the provisioned protocols (four core protocols, plus optional VLESS Vision)
  and separate Xray/Mihomo case results per protocol;
  `overall` is the status string. All version and digest values are required to satisfy Pinned Version Fidelity;
  no secret, raw shortUuid, subscription content or private key is included.


### Requirement: Local Operator Credential Bootstrap and Cleanup

Live VPS acceptance SHALL use the local Linux operator controller. GitHub Actions MUST NOT store target VPS
passwords or permanent SSH private keys. The controller SHALL verify host identity before password auth and
revoke temporary keys after the run.

#### Scenario: Host identity is verified before password authentication

- **GIVEN** the controller has opened an unauthenticated SSH connection
- **WHEN** the operator does not confirm the provider-console SHA-256 fingerprint exactly
- **THEN** the controller aborts before requesting or sending the password

#### Scenario: Temporary access is bounded and revoked

- **GIVEN** the operator has authenticated and the controller is bootstrapping a VPS
- **WHEN** the temporary public key is installed
- **THEN** a persistent two-hour remote expiry timer is already enabled
- **AND** the controller attempts immediate revocation and independently verifies marker removal and timer inactivity
- **AND** unverified cleanup downgrades an otherwise successful run to INCOMPLETE

### Requirement: Per-Case Data-Plane Packet Evidence

Each Xray and Mihomo request SHALL use simultaneous inbound packet captures on both VPS. PASS requires intended
host ingress, zero matching ingress on the other host, and the expected egress IPv4. Missing evidence SHALL
be INCOMPLETE; aggregate counters MUST NOT be a PASS fallback. PCAP files and payloads MUST NOT be persisted.

#### Scenario: Selected VPS receives the proxy request

- **GIVEN** a single Xray or Mihomo proxy request is in progress
- **WHEN** both VPS packet captures are active, filtered only by the exact proxy destination port, and their observed source addresses are compared with the control-machine IPv4 each target reports on the runner's SSH session
- **THEN** the intended VPS records at least one matching packet and the other VPS records zero
- **AND** the observed egress IPv4 matches the expected egress of the intended VPS

#### Scenario: Packet evidence is unavailable or ambiguous

- **GIVEN** tcpdump, target-reported source-IP identity, endpoint port, or a valid capture summary is unavailable, or every captured packet came from an address other than the reported control IPv4
- **WHEN** the traffic case is evaluated
- **THEN** the case is INCOMPLETE, the non-matching source addresses are recorded, and aggregate interface counters MUST NOT be used to mark it PASS
- **AND** no PCAP or packet payload is persisted

#### Scenario: Traffic reaches the wrong VPS

- **WHEN** the other VPS captures matching inbound packets during a proxy case
- **THEN** the individual case MUST be FAIL even if the egress IPv4 matches the expected value

### Requirement: Local interactive operator entrypoint

The system MUST provide a Linux local operator entrypoint that collects Master and Worker public IPv4 addresses, SSH ports and logins, hidden SSH passwords, Master Panel/REALITY/Vision domains, Worker NGINX/REALITY domains, and ACME registration email. The interactive topology MUST support exactly three required Master domains and two required Worker domains without requiring a Worker Vision domain.

#### Scenario: Five-domain input is validated before network access

- **WHEN** the operator enters the two target addresses and five domain names
- **THEN** the controller validates all values with the strict configuration parser before opening either SSH connection
- **AND** invalid IPs, duplicate domains, invalid FQDNs, or unsupported SSH accounts abort without contacting either VPS

#### Scenario: Password is hidden and not persisted

- **WHEN** the operator enters an SSH password
- **THEN** the password is read through a hidden prompt and passed only to the in-memory SSH authentication call
- **AND** the password MUST NOT appear in argv, environment variables, config files, logs, reports, or CI secrets

### Requirement: Out-of-band SSH host identity verification

The controller MUST verify each target's SSH host key before sending its password. It MUST display the SHA-256 fingerprint and require the operator to confirm the exact fingerprint obtained independently from the VPS provider's trusted console. It MUST NOT silently trust a key obtained only from the network.

#### Scenario: Host key is confirmed

- **WHEN** the observed SSH host-key fingerprint exactly matches the operator-confirmed fingerprint
- **THEN** password authentication may proceed
- **AND** the exact host key is written to a private temporary known_hosts file for subsequent OpenSSH connections

#### Scenario: Host key is not confirmed

- **WHEN** the fingerprint does not match or the operator declines confirmation
- **THEN** the controller aborts before sending the password and before modifying the VPS

### Requirement: Temporary SSH access with remote expiry

After successful password authentication, the controller MUST generate a per-run Ed25519 keypair and install only the public key with a unique run marker. It MUST install and enable a persistent remote expiry timer before appending the key. The expiry action MUST remove only the exact key entry created by this run and MUST survive VPS reboot.

#### Scenario: Temporary key is installed

- **WHEN** password authentication and root identity verification succeed
- **THEN** a per-host temporary public key is added without replacing existing authorized_keys entries
- **AND** a persistent two-hour expiry timer is active before the key becomes usable

#### Scenario: Bootstrap fails after expiry is armed

- **WHEN** any bootstrap operation fails after timer installation
- **THEN** the controller attempts immediate cleanup
- **AND** the remote timer remains the bounded fallback if immediate cleanup cannot be verified

### Requirement: Immediate credential revocation gates overall status

The controller MUST attempt immediate removal of temporary SSH access after the E2E subprocess exits. It MUST independently verify that the run-specific marker is absent and the remote expiry timer is inactive. An unverified cleanup MUST downgrade an otherwise successful run to INCOMPLETE and update JSON, JUnit, and text reports.

#### Scenario: Immediate revocation succeeds

- **WHEN** the run-specific authorized_keys marker is absent and the expiry timer is inactive
- **THEN** the cleanup phase is PASS

#### Scenario: Immediate revocation cannot be verified

- **WHEN** SSH cleanup fails or the marker/timer state cannot be independently verified
- **THEN** the cleanup phase is INCOMPLETE
- **AND** an otherwise PASS overall result MUST become INCOMPLETE
- **AND** the persistent remote expiry timer MUST remain armed

### Requirement: Local-only live VPS credential handling

The live two-VPS E2E acceptance workflow MUST run from the operator's Linux control machine. GitHub Actions MUST NOT request or store target VPS passwords or permanent SSH private keys for this workflow. GitHub Actions remains responsible for repository CI and automated unit/integration tests.

#### Scenario: GitHub CI runs without target credentials

- **WHEN** repository CI executes
- **THEN** it runs the runner unit tests without requiring VPS target credentials or GitHub Environment secrets

#### Scenario: Local operator starts a live run

- **WHEN** the operator launches the local controller
- **THEN** target credentials remain on the local control machine and the existing E2E runner executes with temporary SSH keys and strict host-key verification
