# Spec Delta

## MODIFIED Requirements

### Requirement: NGINX Stream SNI Demultiplexing on Port 443
The routing subsystem SHALL bind public TCP 443 through NGINX Stream, route visible TLS SNI to role-specific loopback listeners and preserve PROXY protocol boundaries. Explicit Master cover names SHALL route directly to its decoy. Worker primary SNI SHALL reach its transport/static-cover listener without exposing Panel/API; REALITY and optional Vision SHALL retain authenticated traffic and cover-only fallback.

#### Scenario: Route traffic for panel domain
- **WHEN** public TLS SNI matches `panel_domain`
- **THEN** Stream forwards with PROXY protocol v1 to `127.0.0.1:7443` for Panel UI/API/subscriptions and configured TLS transports.

#### Scenario: Route traffic for REALITY domain
- **WHEN** SNI matches the host's REALITY name
- **THEN** traffic reaches local REALITY at `127.0.0.1:8443` with PROXY protocol v1, or directly reaches decoy on a Panel-only host with no local REALITY inbound.

#### Scenario: Route default or missing SNI to REALITY
- **WHEN** SNI is unknown or absent
- **THEN** a traffic host routes to local REALITY for cover fallback and a Panel-only host routes to decoy; neither route exposes Panel/API.

#### Scenario: Route traffic for optional Vision domain
- **WHEN** SNI matches enabled `vision_domain`
- **THEN** Stream forwards with PROXY protocol v1 to `127.0.0.1:8444`; disabled Vision creates no route.

#### Scenario: Xray Vision loopback PROXY protocol and HTTP fallback
- **WHEN** unauthenticated non-VLESS HTTP reaches Vision at 8444
- **THEN** Xray consumes PROXY protocol, terminates TLS and sends fallback with PROXY protocol to cleartext loopback decoy 9444, never Panel.

#### Scenario: Route camouflage apex website directly to the decoy
- **WHEN** Master receives SNI matching its explicitly selected cover apex or optional www alias
- **THEN** Stream routes directly to `127.0.0.1:9443`, serving generated cover with a certificate valid for that name.

#### Scenario: Worker edge NGINX Stream and HTTPS proxying
- **WHEN** public SNI matches a Worker's primary, REALITY or enabled Vision name
- **THEN** it reaches local 7443, 8443 or 8444 respectively; primary serves transport paths and static cover, its management and subscription paths are denied, and a same-zone Master's apex is not adopted by Worker.

#### Scenario: Xray REALITY loopback PROXY protocol acceptance
- **WHEN** Stream forwards a PROXY protocol v1 header to REALITY
- **THEN** Xray consumes it with `acceptProxyProtocol`, restores client source and proceeds without TLS framing errors.

### Requirement: REALITY Camouflage Decoy Fallback
The routing subsystem SHALL serve the generated static cover on loopback 9443 for unauthenticated REALITY fallback with PROXY protocol v1 and on the Worker's primary HTTPS static route. Master cover apex and optional www SHALL be explicit owned names. Decoy responses SHALL NOT expose Panel, API or subscription content and unknown ordinary paths SHALL use the branded 404 page.

#### Scenario: Scanner probe fallback to static cover
- **WHEN** an unauthenticated supported TLS probe reaches REALITY
- **THEN** Xray forwards to `127.0.0.1:9443` with `xver: 1`; NGINX terminates TLS 1.3, restores the source IP, serves cover only and retains the dedicated safe probe audit policy.

#### Scenario: Rendered camouflage decoy site deployment
- **GIVEN** explicitly selected Master cover `example.com` and optional `www.example.com`
- **WHEN** cover is deployed
- **THEN** the site is rendered from bundled assets with directory mode 0755, all placeholders are substituted and surviving placeholders fail deployment; only selected names resolving to the intended host are included in direct routes and certificate SANs, with no last-two-label inference.

#### Scenario: Worker primary static route and management denial
- **WHEN** a client requests the Worker primary root, a known static asset, an unknown ordinary path or a Panel/API/subscription path
- **THEN** root and assets return generated cover, unknown paths return branded 404, management paths are denied without control content, and valid XHTTP/WS/gRPC paths continue operating.

#### Scenario: Routing probes cannot reach management content
- **WHEN** unknown or absent SNI, mismatched HTTP Host or malformed ClientHello is probed on public 443
- **THEN** no unintended Panel/API/subscription content is returned; unsupported malformed handshakes may close without an HTTP response and public access to internal fallback listeners remains denied.

## ADDED Requirements

### Requirement: Explicit certificate identity and lineage ownership
Certificate provisioning SHALL map each role hostname to its owning host, intended SANs and selected live lineage. Master and Worker SHALL adopt existing valid matching lineages consistently, reject unsuitable or unowned material, and verify served identity after activation. Same-zone Workers SHALL NOT issue or renew the Master's cover apex or www names.

#### Scenario: Three Worker names share a Master zone
- **WHEN** Worker certificates are provisioned for primary, REALITY and enabled Vision
- **THEN** every lineage covers its intended Worker identity, none claims the Master apex and DNS ownership is checked before issuance.

#### Scenario: Existing suffixed lineage
- **GIVEN** a valid owned certificate under a suffixed lineage matches intended SANs and key
- **WHEN** either host role adopts it
- **THEN** generated listeners use its selected live path rather than an assumed basename, and the served certificate is verified from the client side.

#### Scenario: Invalid or cross-owned certificate
- **WHEN** a candidate has wrong SANs, an invalid lifetime, mismatched key, incompatible issuer mode or unsafe ownership
- **THEN** activation is refused without overwriting unrelated material and the operator receives a specific correction route.

#### Scenario: HTTP-01 ownership and renewal
- **WHEN** certificates are issued or renewal is exercised
- **THEN** TCP 80 serves ACME challenges locally for each owned managed name without redirect, non-challenge managed requests redirect to that name's HTTPS endpoint, unmanaged hosts are refused, and renewal reloads only a validated NGINX configuration.

#### Scenario: Failed certificate transition
- **WHEN** issuance, route activation, served-identity verification or renewal setup fails during a migration
- **THEN** previous owned routes and certificate references are restored and verified; unrelated lineages and the other host's apex ownership remain untouched.
