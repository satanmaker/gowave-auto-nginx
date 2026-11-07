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

#### Scenario: Worker edge NGINX Stream and HTTPS proxying
- **GIVEN** an incoming connection to a remote Worker edge node on public port 443
- **WHEN** NGINX Stream evaluates the preread SNI on the Worker node
- **THEN** requests matching `worker_domain` are routed with PROXY protocol v1 to local NGINX HTTPS listener (7443) for XHTTP, WS, and Trojan gRPC termination, while camouflage SNI and scanner probes are routed to local Xray REALITY (8443).

### Requirement: Strict PROXY Protocol Boundaries and Sender/Receiver Isolation
The routing subsystem SHALL enforce PROXY protocol reception strictly from loopback addresses, rejecting injected PROXY headers from untrusted external networks.

#### Scenario: Enforce loopback trust for PROXY protocol
- **GIVEN** NGINX HTTPS listener at 7443 and Decoy listener at 9443 configured with `proxy_protocol`
- **WHEN** traffic arrives with PROXY protocol v1 from `127.0.0.1`
- **THEN** NGINX extracts the real client IP via `real_ip_header proxy_protocol;` and `set_real_ip_from 127.0.0.1;`, refusing PROXY headers from non-loopback IPs.

### Requirement: REALITY Camouflage Decoy Fallback
The routing subsystem SHALL serve an authentic static camouflage website on loopback port 9443 for unauthenticated probes forwarded by Xray REALITY fallback with PROXY protocol v1.

#### Scenario: Scanner probe fallback to static cover
- **GIVEN** an unauthenticated client or scanner connecting to `127.0.0.1:8443`
- **WHEN** Xray REALITY fails to authenticate the handshake
- **THEN** Xray forwards the connection with PROXY protocol v1 (`dest: "127.0.0.1:9443", xver: 1`) to `127.0.0.1:9443`, where NGINX terminates TLS with `reality_domain` certificate and serves the authentic multi-asset decoy website (retained from `community-baseline` `cover-reality` under `/var/www/gowave-auto-nginx/cover-reality`), rejecting minimal single-file HTML stubs.

### Requirement: XHTTP Inbound Reverse Proxy
The NGINX HTTPS listener at 7443 SHALL terminate TLS for `panel_domain` and reverse proxy configured XHTTP path prefixes to local Xray inbounds using HTTP/1.1 with buffering disabled.

#### Scenario: Client XHTTP streaming session
- **GIVEN** an authenticated client sending HTTP POST or GET requests to `https://<panel_domain>/<xhttp_path>/`
- **WHEN** NGINX processes the request at 7443
- **THEN** NGINX forwards the request to `http://127.0.0.1:10001` with `proxy_buffering off; proxy_request_buffering off; proxy_http_version 1.1;` and `Cache-Control "no-store, no-transform"`.

### Requirement: WebSocket and gRPC Inbound Proxying
The NGINX HTTPS listener at 7443 SHALL proxy WebSocket and gRPC inbounds to designated loopback ports with protocol headers intact.

#### Scenario: WebSocket inbound upgrade
- **GIVEN** an incoming request to `https://<panel_domain>/<ws_path>` with `Upgrade: websocket` and `Connection: Upgrade`
- **WHEN** NGINX evaluates the location block
- **THEN** NGINX proxies the connection to `http://127.0.0.1:10002` with upgrade headers preserved.

#### Scenario: gRPC inbound pass-through
- **GIVEN** an incoming HTTP/2 gRPC connection to the designated gRPC service path
- **WHEN** NGINX evaluates the location block
- **THEN** NGINX passes the gRPC frames to `grpc://127.0.0.1:10003` using `grpc_pass`.

### Requirement: IPv4 and IPv6 Edge Listener Validation
The routing subsystem SHALL bind port 443 (Stream) and port 80 (HTTP) on IPv6 only after confirming an active global IPv6 address and default route on the host.

#### Scenario: Dual-stack binding on confirmed IPv6 host
- **GIVEN** a host with a global unicast IPv6 address and default IPv6 route (`ip -6 route show default`)
- **WHEN** NGINX configuration is generated
- **THEN** listeners include both `listen 443;` and `listen [::]:443;` in stream, and `listen 80;` and `listen [::]:80;` in HTTP block.
