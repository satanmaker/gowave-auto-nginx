# Spec Delta: Traffic Routing

## Purpose

Provides high-performance SNI stream multiplexing on TCP port 443, TLS termination, REALITY fallback camouflage, and inbound transport proxying via NGINX with strict PROXY protocol boundaries.

## ADDED Requirements

### Requirement: NGINX Stream SNI Demultiplexing on Port 443
The routing subsystem SHALL bind TCP port 443 exclusively via top-level NGINX Stream (`stream { include /etc/nginx/stream-enabled/*.conf; }`), inspect incoming TLS handshakes using `ssl_preread`, and forward TCP traffic to loopback listeners with PROXY protocol v1.

#### Scenario: Route traffic for panel domain
- **GIVEN** an incoming TLS connection on public port 443 with SNI matching `panel_domain`
- **WHEN** NGINX Stream evaluates the preread SNI
- **THEN** NGINX forwards the stream with PROXY protocol v1 to `127.0.0.1:7443`.

#### Scenario: Route traffic for REALITY domain
- **GIVEN** an incoming TLS connection on public port 443 with SNI matching `reality_camouflage_sni`
- **WHEN** NGINX Stream evaluates the preread SNI
- **THEN** NGINX forwards the stream with PROXY protocol v1 to Xray at `127.0.0.1:8443`.

#### Scenario: Route default or missing SNI to REALITY
- **GIVEN** an incoming connection on public port 443 with unrecognized SNI, IP address scan, or absent SNI
- **WHEN** NGINX Stream evaluates the preread SNI
- **THEN** NGINX forwards the connection to `127.0.0.1:8443` where Xray handles it via REALITY fallback.

#### Scenario: Route traffic for optional Vision domain
- **GIVEN** an incoming TLS connection on public port 443 with SNI matching configured `vision_domain`
- **WHEN** NGINX Stream evaluates the preread SNI
- **THEN** NGINX forwards the stream with PROXY protocol v1 to Xray Vision inbound at `127.0.0.1:8444`.

#### Scenario: Xray Vision loopback PROXY protocol and HTTP fallback
- **GIVEN** NGINX Stream forwarding `vision_domain` traffic to `127.0.0.1:8444` with `proxy_protocol on;`
- **WHEN** Xray receives unauthenticated non-VLESS HTTP requests on port 8444
- **THEN** Xray consumes the PROXY protocol v1 header, terminates TLS, and forwards fallback requests to local NGINX Vision Decoy vhost at `127.0.0.1:9444`.

#### Scenario: Worker edge NGINX Stream and HTTPS proxying
- **GIVEN** an incoming connection to a remote Worker edge node on public port 443
- **WHEN** NGINX Stream evaluates the preread SNI on the Worker node
- **THEN** requests matching `worker_domain` are routed with PROXY protocol v1 to local NGINX HTTPS listener (7443) for XHTTP, WS, and Trojan gRPC termination, while camouflage SNI and scanner probes are routed to local Xray REALITY (8443).

#### Scenario: Xray REALITY loopback PROXY protocol acceptance
- **GIVEN** NGINX Stream forwarding port 443 to `127.0.0.1:8443` with `proxy_protocol on;`
- **WHEN** Xray REALITY inbound receives the initial PROXY protocol v1 header
- **THEN** Xray consumes the PROXY header via `tcpSettings.acceptProxyProtocol: true`, restores the client source IP, and proceeds with the REALITY handshake without TLS framing errors.

### Requirement: Strict PROXY Protocol Boundaries and Sender/Receiver Isolation
The routing subsystem SHALL enforce PROXY protocol reception strictly from loopback addresses, rejecting injected PROXY headers from untrusted external networks.

#### Scenario: Enforce loopback trust for PROXY protocol
- **GIVEN** NGINX HTTPS listener at 7443 and Decoy listener at 9443 configured with `proxy_protocol`
- **WHEN** traffic arrives with PROXY protocol v1 from `127.0.0.1`
- **THEN** NGINX extracts the real client IP via `real_ip_header proxy_protocol;` and `set_real_ip_from 127.0.0.1;`, refusing PROXY headers from non-loopback IPs.

### Requirement: REALITY Camouflage Decoy Fallback
The routing subsystem SHALL serve an authentic static camouflage website on loopback port 9443 for unauthenticated probes forwarded by Xray REALITY fallback with PROXY protocol v1 (`xver: 1`), preserving real client IPs via `real_ip_header proxy_protocol;`.

#### Scenario: Scanner probe fallback to static cover
- **GIVEN** an unauthenticated client or scanner connecting to `127.0.0.1:8443`
- **WHEN** Xray REALITY fails to authenticate the handshake
- **THEN** Xray forwards the connection with PROXY protocol v1 (`dest: "127.0.0.1:9443", xver: 1`) to `127.0.0.1:9443`, where NGINX terminates TLS 1.3 using runtime-adaptive HTTP/2 syntax (`listen ... ssl http2 proxy_protocol;` on < 1.25.1; `listen ... ssl proxy_protocol; http2 on;` on >= 1.25.1), restores the real client IP via `real_ip_header proxy_protocol;`, serves the multi-asset decoy website, and logs the probe to `/var/log/nginx/gowave-decoy-access.log` recording `remote_addr`, `ssl_server_name`, and timestamp.

#### Scenario: Automated camouflage decoy site assets deployment
- **GIVEN** the orchestrator configuring the REALITY fallback camouflage decoy vhost via `generate_decoy_vhost`
- **WHEN** the decoy vhost is generated
- **THEN** the orchestrator provisions directory `/var/www/gowave-auto-nginx/cover-reality`, copies the static multi-asset decoy files (HTML, CSS, JS, assets) from `assets/cover-sites/cover-reality/` with permissions `0755`, ensuring HTTP 200 OK responses for fallback probes without 403 Forbidden directory index errors.

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
The installer SHALL resolve the initial TLS bootstrap deadlock using a 3-stage sequence: issue initial certificates for PANEL_DOMAIN, REALITY_DOMAIN, and optional VISION_DOMAIN via temporary port 80 webroot vhost with webroot authenticator, deploy production Stream 443 and HTTPS 7443 configurations, verify automated renewal via dry-run, and maintain port 80 non-redirected ACME routes.

#### Scenario: Bootstrap certificates on fresh host
- **GIVEN** a clean host without pre-existing Let's Encrypt certificates
- **WHEN** the installer initiates TLS provisioning
- **THEN** it deploys temporary port 80 webroot vhost `/var/www/gowave-acme` (binding `[::]:80` conditionally only when host IPv6 is active), starts NGINX, issues certificates via `certbot certonly --webroot` for `PANEL_DOMAIN`, `REALITY_DOMAIN`, and optional `VISION_DOMAIN` (if configured), deploys production Stream and HTTPS configurations referencing the certificates, verifies `certbot renew --dry-run` succeeds with NGINX online, and drops scanner traffic on unmanaged domains.

#### Scenario: Prohibition of self-signed fallback certificates and fail-fast validation
- **GIVEN** an installer or domain-change process issuing certificates via Certbot ACME
- **WHEN** certificate issuance fails or produces an error
- **THEN** the process halts immediately with exit code 1 (fail-fast), strictly prohibiting self-signed fallback generation in production, and verifies certificate existence, validity exceeding 24 hours, and private-public key consistency via `verify_acme_certificate` before deploying production virtual hosts.

#### Scenario: Automated Certbot renewal deploy hook
- **GIVEN** an active installation with deployed Let's Encrypt certificates
- **WHEN** background ACME renewal succeeds via `certbot.timer`
- **THEN** deployment hook `/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh` executes `nginx -t -q` and reloads NGINX (`nginx -s reload`) without manual intervention.
