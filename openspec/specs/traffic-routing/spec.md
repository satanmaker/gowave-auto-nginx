# traffic-routing Specification

## Purpose

Provides high-performance SNI stream multiplexing on TCP port 443, TLS termination, REALITY fallback camouflage, and inbound transport proxying via NGINX with strict PROXY protocol boundaries.

## Requirements

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

#### Scenario: XHTTP stream-up over a loopback HTTP/2 upstream
- **WHEN** an Xray or Mihomo client uses its issued XHTTP `stream-up` profile on `/xhttp-down/` through the Master or Worker
- **THEN** NGINX retains HTTP/2 on the TLS listener and forwards this path over cleartext HTTP/2 to `127.0.0.1:10001` using `grpc_pass`, without changing the public port, client transport, or WebSocket and Trojan routes.
- **AND** acceptance requires the expected payload through each client on both roles; TLS negotiation or a response to an invalid XHTTP request is insufficient.

#### Scenario: Xray REALITY loopback PROXY protocol acceptance
- **WHEN** Stream forwards a PROXY protocol v1 header to REALITY
- **THEN** Xray consumes it with `acceptProxyProtocol`, restores client source and proceeds without TLS framing errors.
### Requirement: Strict PROXY Protocol Boundaries and Sender/Receiver Isolation
The routing subsystem SHALL enforce PROXY protocol reception strictly from loopback addresses, rejecting injected PROXY headers from untrusted external networks.

#### Scenario: Enforce loopback trust for PROXY protocol
- **GIVEN** NGINX HTTPS listener at 7443 and Decoy listener at 9443 configured with `proxy_protocol`
- **WHEN** traffic arrives with PROXY protocol v1 from `127.0.0.1`
- **THEN** NGINX extracts the real client IP via `real_ip_header proxy_protocol;` and `set_real_ip_from 127.0.0.1;`, refusing PROXY headers from non-loopback IPs.

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
### Requirement: XHTTP Inbound Reverse Proxy
The NGINX HTTPS listener at 7443 SHALL terminate TLS for `panel_domain` and reverse proxy configured XHTTP path prefixes to local Xray inbounds using HTTP/1.1 with buffering disabled, passing the PROXY-restored client IP via HTTP headers.

#### Scenario: Client XHTTP streaming session
- **GIVEN** an authenticated client sending HTTP POST or GET requests to `https://<panel_domain>/<xhttp_path>/`
- **WHEN** NGINX processes the request at 7443
- **THEN** NGINX forwards the request to `http://127.0.0.1:10001` with `proxy_buffering off; proxy_request_buffering off; proxy_http_version 1.1;`, `access_log off;`, `proxy_set_header X-Real-IP $remote_addr;`, and `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`.

### Requirement: WebSocket and gRPC Inbound Proxying
The NGINX HTTPS listener at 7443 SHALL proxy WebSocket and gRPC inbounds to designated loopback ports with protocol headers and PROXY-restored client IP headers intact.

#### Scenario: WebSocket inbound upgrade
- **GIVEN** an incoming request to `https://<panel_domain>/<ws_path>` with `Upgrade: websocket` and `Connection: Upgrade`
- **WHEN** NGINX evaluates the location block
- **THEN** NGINX proxies the connection to `http://127.0.0.1:10002` with upgrade headers, `proxy_set_header X-Real-IP $remote_addr;`, and `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` preserved.

#### Scenario: gRPC inbound pass-through
- **GIVEN** an incoming HTTP/2 gRPC connection to the designated gRPC service path
- **WHEN** NGINX evaluates the location block
- **THEN** NGINX passes the gRPC frames to `grpc://127.0.0.1:10003` using `grpc_pass`.

### Requirement: IPv4 and IPv6 Edge Listener Validation
The routing subsystem SHALL bind port 443 (Stream) and port 80 (HTTP) on IPv6 only after confirming an active global IPv6 address and default route on the host.

#### Scenario: Dual-stack binding on confirmed IPv6 host
- **GIVEN** a host (central panel or edge worker) with a global unicast IPv6 address and default IPv6 route (`ip -6 route show default`)
- **WHEN** NGINX configuration is generated
- **THEN** listeners include both `listen 443;` and `listen [::]:443;` in stream, and `listen 80;` and `listen [::]:80;` in HTTP block.

#### Scenario: Graceful omission of IPv6 listeners when IPv6 disabled
- **GIVEN** a host with IPv6 disabled in kernel (`net.ipv6.conf.all.disable_ipv6=1`) or lacking an IPv6 default route
- **WHEN** NGINX configuration is compiled
- **THEN** listeners bind strictly to IPv4 (`listen 443;` and `listen 80;`), omitting `[::]` directives to prevent fatal `Address family not supported` socket errors.

### Requirement: 3-Stage Dual-Lineage Let's Encrypt TLS Bootstrap Sequence
The installer SHALL bootstrap TLS by issuing certificates for the host's primary and REALITY names and optional Vision name via temporary HTTP-01 webroot, activating production Stream/HTTPS, then verifying renewal by dry-run. The REALITY lineage SHALL include cover apex and optional www only when explicitly selected and owned by that Master. Without explicit cover, no apex SHALL be inferred or added. Worker certificates SHALL NOT claim Master cover names.

#### Scenario: Bootstrap certificates on fresh host
- **GIVEN** a clean host without pre-existing Let's Encrypt certificates
- **WHEN** the installer initiates TLS provisioning
- **THEN** it deploys temporary port 80 webroot `/var/www/gowave-acme`, binds IPv6 only when host IPv6 is active, starts NGINX, issues primary and REALITY certificates and optional Vision certificate via `certbot certonly --webroot`, adds only explicitly selected and validated Master cover names to the REALITY lineage, deploys production Stream and HTTPS using the selected live paths, verifies `certbot renew --dry-run` with NGINX online and refuses unmanaged host traffic.

#### Scenario: Port 80 serves ACME for every managed name
- **GIVEN** an active production port 80 vhost
- **WHEN** a plain HTTP request arrives for the host's primary, REALITY, enabled Vision or explicitly selected owned cover name
- **THEN** `/.well-known/acme-challenge/` is served from `/var/www/gowave-acme` without redirection, other paths return `301 https://$host$request_uri`, and unmanaged hosts terminate with `444`.

#### Scenario: Prohibition of self-signed fallback certificates and fail-fast validation
- **GIVEN** an installer or domain-change process issuing certificates via Certbot ACME
- **WHEN** certificate issuance fails or produces an error
- **THEN** the affected provisioning operation halts with nonzero status without activating incomplete virtual hosts, no self-signed production fallback is generated, and certificate existence, validity exceeding 24 hours and private-public key consistency must be verified before production activation.

#### Scenario: Automated Certbot renewal deploy hook
- **GIVEN** an active installation with deployed Let's Encrypt certificates
- **WHEN** background ACME renewal succeeds via `certbot.timer`
- **THEN** `/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh` executes `nginx -t -q` and reloads NGINX with `nginx -s reload` only after successful validation, without manual intervention.

#### Scenario: Positional installation without explicit cover
- **GIVEN** a complete positional install invocation with no explicit cover configuration
- **WHEN** TLS bootstrap runs without interactive prompts
- **THEN** only the selected primary, REALITY and optional Vision identities receive certificates and routes; no apex/www is inferred, requested as a SAN or activated as a cover alias, and REALITY fallback still serves cover under its configured identity.

#### Scenario: Worker shares the Master's DNS zone
- **GIVEN** Master owns `example.com` and optional `www.example.com`, and Worker on another IP uses `node-1.example.com`, `reality-node-1.example.com` and optional `xtls-node-1.example.com`
- **WHEN** Worker bootstrap or renewal runs
- **THEN** only the Worker identities are issued or renewed, Master apex/www are absent from Worker SANs and ACME routes, and Master DNS, certificates and routes remain unchanged.

### Requirement: Stream edge keeps an operational access log
The port-443 stream router SHALL write one access-log line per connection to a managed name, in the same place an operator reads when diagnosing a deployment: the host's own NGINX log. The line SHALL carry the SNI the client sent, the negotiated transport protocol, the client address and the local port. The Panel and transport locations beneath the stream layer SHALL stay unlogged, so the log names edge connections rather than every proxied request.

#### Scenario: A connection on a managed name is logged at the edge
- **WHEN** a client completes a request through the Master's or the Worker's 443 under a managed domain
- **THEN** the stream access log on that host holds a line with that domain as the SNI, the client's address and the port, and the request's own result is unchanged.

#### Scenario: The edge log does not become a request log
- **WHEN** the Panel or a transport location proxies a request behind the stream router
- **THEN** no additional stream line is written for it, and the Panel's and transports' own logging stays as configured.

#### Scenario: The log is rotated and its retention is documented
- **WHEN** the edge log grows on a long-running host
- **THEN** a logrotate rule rotates and compresses it, and the operator documentation states that the file records client addresses.

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
