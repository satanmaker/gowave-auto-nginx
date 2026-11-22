# Design

## Context

See `proposal.md` — Why. The constraints that shape the implementation:

- `generate_panel_https_vhost` (`modules/nginx.sh:414-509`) writes `/etc/nginx/conf.d/gowave-panel.conf` from
  one heredoc. `conf.d/*.conf` is included from `http {}`, so `map` is legal there; the file is regenerated
  whole on every install, which is where every NGINX item must land — not as a post-install edit.
- The vhost listens on `127.0.0.1:7443` behind the Stream SNI listener and restores the client address with
  `set_real_ip_from 127.0.0.1; real_ip_header proxy_protocol;` (`:429-430`). `$remote_addr` is therefore already
  the true client; the client's own headers are what must stop being copied.
- `location ^~ /api/sub/` (`:438`) is a prefix location, and `^~` stops regex evaluation, so a regex location
  cannot refine it. Path-level rules for that route have to live inside the block.
- `install` stops NGINX (`gowave-auto.sh:355`) and runs `run_preflight_panel` (`:357`) before
  `install_prerequisites` (`:360`). The preflight split below depends on that order.
- The Worker payload already runs `trap 'handle_error "$?"' ERR` with a `CURRENT_STEP`-style reporter
  (`gowave-node-auto.sh:5263-5267`); the master entrypoint has no trap at all.
- Acceptance is behavioural: `tools/podman_e2e` refuses a catalogued behaviour with no case, and the pinned
  Panel's subscription policy (any non-empty header is served) is asserted by `SUB-SERVED`.

## Goals / Non-Goals

**Goals:**

- Every edge behaviour in `subscription-edge` and `panel-vhost-hygiene` is produced by the existing generators
  and survives a regeneration — no hand-edited file, no `sed` over a rendered config.
- The three preflight/CLI items are single implementation points shared by the CLI, the wizard and the Worker
  payload, so a second entry path cannot skip a check.
- Each item is independently revertible: reverting one bullet of this change leaves the deployment valid.

**Non-Goals:**

- No change to the Stream SNI map, the REALITY fallback, the decoy block, the data plane or the Panel binary.
- No client allow-list on the subscription route (see `## Decisions` D1).
- No attempt to scrub the Panel's own logs: `access_log off` removes the edge's copy of the request line, and
  the Panel keeps its own logging contract.

## Decisions

### D1 — One `map` for the subscription User-Agent, three outcomes, no allow-list

A `map $http_user_agent $gowave_sub_ua_class` is declared above the `server` block in the panel vhost:

```
map $http_user_agent $gowave_sub_ua_class {
    default               client;
    ~*telegrambot         preview;
    ~*whatsapp            preview;
    ~*facebookexternalhit preview;
    ~*slackbot            preview;
    ~*discordbot          preview;
    ~*twitterbot          preview;
    ~*googlebot           preview;
    ~*bingbot             preview;
    ~*yandex(bot|images)  preview;
    ~*applebot            preview;
    ~*ahrefsbot           preview;
    ~*semrushbot          preview;
}
```

`client` means "unchanged behaviour". Inside `location ^~ /api/sub/`, `if ($gowave_sub_ua_class = preview) {
return 204; }` is the only conditional. Alternatives rejected: **a client allow-list** would turn every new
client release into an outage and contradicts the pinned Panel's contract that `SUB-SERVED` asserts with
`curl/8.5.0`; **`map` directly to a status** would answer every branch from the map, including the `client`
branch that must reach the proxy. `if` with `return` is the documented-safe form (no other directive in the
block). The map must not have an empty-string key: an absent header is the Panel's `403`, not a `204`.

### D2 — All subscription headers in the location, `always` where the status is not 2xx

`add_header` is inherited only when the child block declares none. The subscription location therefore declares
all of its own:

```
add_header Cache-Control "no-store, private" always;
add_header X-Robots-Tag  "noindex, nofollow, noarchive, nosnippet" always;
```

`always` is what makes both apply to a `4xx`/`5xx` proxied from the Panel — the defect the catalog found at
`:446`. Declaring them in the location (rather than the server) keeps the dashboard and API behaviour untouched
and keeps the header set from being dropped by an inherited `add_header` elsewhere. The `204` from D1 is
answered by the same block, so it carries both headers. A `444` closes the connection without sending a
response, so it carries no header at all and the two header requirements are scoped to answers that are sent;
the spec states that exclusion instead of promising a header on an answer that never exists.

### D3 — `access_log off` in the subscription location

The location gets `access_log off;`. A masked `log_format` was considered and rejected: it still writes a line
per subscription fetch (volume signal), and a mask that keeps the method and status is enough to fingerprint
polling. Request accounting moves to the Panel's own log and to the stream layer, which never sees the path.
The same directive is already used for the XHTTP and WebSocket transports (`:482`, `:496`), so this is the
existing pattern, not a new one.

### D4 — The path is validated on `$request_uri`, at server level

`^~ /api/sub/` suppresses regex locations, and `$uri` cannot carry this rule: it is normalised and
percent-decoded before any map sees it, so `/api/sub/x/../y` has already become `/api/sub/y` and `%2F` has
already become `/`. A check on `$uri` therefore cannot observe the traversal or the encoded separator the
requirement names — the refusal would be unobservable in the only place it matters.

The rule reads the raw request target instead, and runs in the server's rewrite phase so it also catches a
path that normalises out of the prefix:

```
map $request_uri $gowave_sub_path_bad {
    default                                            0;
    "~^/api/sub/[A-Za-z0-9_-]+/[a-z0-9-]{17,}"         1;
    ~^/api/sub/[A-Za-z0-9_-]*(/[a-z0-9-]+)?/?(\?.*)?$  0;
    ~^/api/sub/                                        1;
}

server {
    ...
    if ($gowave_sub_path_bad) { return 444; }
}
```

The counted pattern is quoted because `{` and `}` are block delimiters to the config parser; unquoted, the
file fails `nginx -t` instead of guarding anything. Map entries are evaluated in order and the first match wins:
a too-long `clientType` segment is bad, a path whose identifier is in the Panel's own alphabet and whose optional
`clientType` is spelled in lower case is good, and anything else under `/api/sub/` is bad. `.` and
`%` are outside both classes, so `..` and an encoded separator are refused without a separate traversal
pattern; an upper-case letter in the `clientType`, a space, a semicolon and a backslash are refused by the same
rule. The query string is exempt: the subscription path carries the identifier, and a client may append a query.

The identifier is not lower-case. GoWave issues the shortUuid from the base64url alphabet (`A–Z`, `a–z`, `0–9`,
`_`, `-`) — the install on the fixture host printed `k_2yr52aHyK4j4jg` — so a class of `[a-z0-9-]` would answer
`444` to every subscription link the product itself prints, which is the opposite of this requirement's purpose.
The measured alphabet is what the first segment admits; only the `clientType` segment, whose names the Panel
spells in lower case, keeps the narrow class. A case that drives the real identifier is what makes this
observable (`tests/test_nginx_routing.py`), and the AIO run that measured the served link is what caught it.

Server level is not a preference but the only place that works. A location-scoped check never runs for
`/api/sub/x/../../../etc/passwd`, because the normalised path leaves the prefix and the request is matched by
`location /`; a server-level `if` sees `$request_uri` first and closes the connection, so the promise "the Panel
receives nothing" holds for a traversal attempt as well. `if` with `return` is the documented-safe form, and
this is the same directive pair the subscription location uses for the preview bot.

The rule stays syntactical — there is no enumerated list of representations — because the Panel names them
(`internal/subscription/srr.go:165`) and an unknown but well-formed format is the Panel's decision (Р-16). The
suites send the identifier the Panel issued (`tools/podman_e2e/panel_surface.py:175-179`), which is mixed case,
and that is exactly what the first class admits; the narrow lower-case class is confined to the `clientType`
segment, where the product's own names live.

Rejected alternative: replacing `^~` with a plain prefix and adding a regex location. It changes precedence for
every other `/api/` path in the vhost for one rule, and it still cannot see a raw path that normalises away.

### D5 — Scanner paths are one anchored regex location, not a pattern

```
location ~* ^/(?:\.env|\.git|\.ds_store|wp-login\.php|wp-admin|phpmyadmin|server-status|actuator)(/|$) {
    return 444;
}
```

The set is closed and anchored at both ends, so every entry matches the literal path and nothing that merely
begins with it (`/server-statusx`, `/.envrc`, `/wp-login.php.bak` are proxied); every entry is a path no GoWave
route or dashboard asset occupies. It is placed before `location /` and cannot shadow `^~ /api/`,
`^~ /xhttp-down/`, `= /ws` or `/trojan-grpc`. A broad "dotfile" rule was rejected: it would answer
`/.well-known/` (ACME on port 80 only today, but a future HTTP-01-on-443 path) and any hashed asset whose name
begins with a dot. Extending the set to the decoy vhost belongs to the decoy wave, not here.

### D6 — `server_tokens off` at server level of the panel vhost

One line beside the existing `ssl_protocols` in the panel vhost, matching `:536` and `:575`. It removes the
version from the `Server` header and from NGINX-generated error bodies; it does not remove the product name,
which is what the spec states.

### D7 — Forwarded headers carry `$remote_addr` only

All five proxied locations — `^~ /api/sub/`, `^~ /api/`, `/`, `^~ /xhttp-down/` and `= /ws` — replace
`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` with `$remote_addr`. `X-Real-IP` already carries
`$remote_addr`. The same locations also empty the other eight address headers the Panel reads *before* those two
(`X-Remnawave-Real-IP`, `X-Client-IP`, `CF-Connecting-IP`, `Fastly-Client-Ip`, `True-Client-Ip`,
`X-Cluster-Client-IP`, `X-Forwarded`, `Forwarded-For`): `httpx.ClientIP` prefers them in that order, so a vhost
that rewrote only `X-Forwarded-For` still let a client choose the address the Panel records for rate limits,
login attempts and notifications. The list is one loop in `generate_panel_https_vhost`, and
`TestNginxRouting.test_panel_vhost_hands_the_panel_only_the_peer_address` renders the file and compares every
header against `panel_surface.PANEL_CLIENT_IP_HEADERS`. Alternatives: `$proxy_add_x_forwarded_for` with a `map`
that strips a client value is not expressible without a second variable per location; trusting the header
because the listener is loopback is wrong — the header is copied from the request, not from the peer. The cost is
that the Panel no longer sees an upstream chain, which does not exist here: NGINX is the only proxy in front of
it.

### D8 — Split the preflight: inputs first, ports and NGINX where they are

`modules/preflight.sh` gains `preflight_require_inputs <component>`, called immediately after argument parsing
and before `check_os`, the NGINX stop and `install_prerequisites`. It validates the same fields the command will
use — names, addresses, ports, domains, ACME contact — through one table per component, and returns the first
failure with the component and the input name. The wizard and the Worker payload call the same function; the
wizard keeps its prompt wording and only delegates validation.

`check_port_availability` and `check_nginx_443_conflicts` stay after the NGINX stop on purpose: on a fresh host
they must see the ports the installer has just freed, and a repeat install is already forgiven through
`PREFLIGHT_MANAGED_UNITS`. Moving them earlier would report the running installer's own NGINX as a conflict.
This keeps the spec's promise (no mutation before validation) without changing what the port check means.

### D9 — Cloudflare detection with `getent`, a vendored CIDR snapshot and an override

Preflight resolves each requested name with `getent ahosts` — glibc, present before `install_prerequisites` —
and compares every returned address with a vendored Cloudflare v4/v6 CIDR list in `modules/preflight.sh`. A
match refuses the run with the name, the address and the reason (HTTP-01 needs a direct answer; make the record
DNS-only). `dig` is deliberately not used: `dnsutils` is installed later, and the check must run before it.

The list is a dated snapshot, because fetching it at preflight would add a network dependency and a trust
decision to the very step that is supposed to fail fast. `GOWAVE_PREFLIGHT_PROXY_CIDRS` (a comma-separated list)
replaces the snapshot for an operator whose provider blocks those ranges; `GOWAVE_PREFLIGHT_ALLOW_PROXIED=1`
records the decision and continues. A name that does not resolve at all fails closed with the resolver outcome,
since the same name must answer an ACME challenge moments later.

### D10 — Lineage selection by certificate coverage, with ownership preserved

`select_acme_lineage <name> <target_server>` scans `/etc/letsencrypt/live/*/`, skips symlinked or non-directory
entries, and asks `openssl x509 -checkhost <name>` about each `cert.pem`. A covering lineage is usable only when
its renewal `server` equals the target directory (the existing isolation, unchanged) and its certificate is not
expired. Selection order is deterministic: the exact-name lineage first, then covering lineages by directory
name ascending. The chosen directory is returned to the caller.

The vhost generators take the lineage directory as an argument (`ssl_certificate <dir>/fullchain.pem`) instead
of deriving it from the domain, and `state.json` records the chosen directory so a re-render does not drift.
Rollback matters more than selection: a lineage that existed before the transaction is **adopted**, not created,
so `rollback_acme_lineages` must never delete it. The existing snapshot/ownership rule already distinguishes
pre-existing lineages; adoption has to mark the lineage as pre-existing before any later step can treat it as
transaction-created. `openssl x509 -checkhost` is available in the OpenSSL 3.x the supported distributions ship.

Two boundary facts are recorded here so the next reader does not take them for gaps:

- "The Vision generator" is `compile_config_profile` in `modules/api_client.py`, not an NGINX vhost:
  `generate_vision_fallback_vhost` renders no `ssl_certificate` at all, because Vision's TLS terminates in Xray.
  The adopted directory therefore reaches Vision as `vision_cert_dir`, which is what the certificate paths in
  the compiled profile use.
- `domain-change` keeps deriving `live/<domain>` because it pins the name with an explicit
  `certbot --cert-name`, so issuance and consumption agree there by construction; adopting a differently named
  lineage on that path is a separate decision and is not part of this change. `node add` compiles a Worker
  profile against the Worker's own domain, whose certificate that host's own certbot issues — the Master cannot
  know that host's lineage name, so it is not a generator this task can retarget.

### D11 — One verified-fetch helper, one extra host

A new `modules/artifact.sh` owns one `fetch_verified_artifact <dest> <name> <url>... <digest>`, sourced by both
`modules/node.sh` and `modules/panel.sh`; neither caller keeps its own copy, because two copies of a digest gate
drift apart exactly where the gate matters. The panel path keeps its candidate list and its mandatory
`SHA256SUMS` gate but calls the same helper for the byte transfer and the digest check. The digest check happens
before anything is executed or installed, and a mismatch is terminal — no
next host, because a second host returning different bytes for a pinned artifact is a supply-chain signal, not a
transport problem. The helper reports the reason through its exit status (1 = no host delivered, 2 = mismatch),
so the caller names the cause: a mismatch is reported as a checksum failure, a transport fault is not.

The new host covers only the pinned Worker installer, whose bytes are verified against `GOWAVE_NODE_INSTALLER_SHA256`
from this repository: `raw.githubusercontent.com` stays primary, and the jsDelivr `gh/<owner>/<repo>@<commit>`
form of the same file is the fallback. Panel release assets have no independent mirror that serves a release
archive, so their candidate list stays on GitHub; the contract is stated for both, the host count differs for a
reason that is recorded here rather than implied.

### D12 — Environment contract parsed before the positionals are read

`cmd_node` gains a `resolve_node_inputs` step: each field is initialised from its `GOWAVE_*` variable, then a
non-empty positional overwrites it, then `preflight_require_inputs node` validates the result. An empty variable
is the same as unset. `GOWAVE_SSH_USER`/`GOWAVE_SSH_PORT` keep their current defaults when neither source sets
them. The Worker secret is not an input of this command — it is read from the Panel's `.env` and passed to the
remote side over stdin — so the contract cannot introduce it into `argv` or the environment.

### D13 — The `ERR` trap reports, and compensation stays explicit

`gowave-auto.sh` gains:

```
CURRENT_STEP=""
on_error() { local code=$?; trap - ERR; printf 'Error: step "%s" failed running "%s" (exit %s).\n' \
    "$CURRENT_STEP" "$BASH_COMMAND" "$code" >&2; exit "$code"; }
trap 'on_error' ERR
```

`set -E` is already in force, so the trap fires inside functions. `CURRENT_STEP` is assigned at each phase
boundary. The trap does **not** call a rollback: the installer's compensations are explicit and already run
inside the failing step, and a trap that rolled back again would double-compensate a partially removed
transaction — the failure mode the Worker payload avoids with `compensate_once`. `trap - ERR` before `exit`
prevents the handler's own failure from re-entering itself.

## Risks / Trade-offs

- **A new client brand with a bot-like name is answered `204`** → the bot patterns are limited to names that are
  never VPN clients (chats, social previews, search crawlers), and the test matrix asserts `client` for every
  real representation's header. A false positive is fixed by editing one map, not by a release.
- **A crawler we did not list still indexes the link** → `X-Robots-Tag` is the primary defence and is
  status-independent; the map is the second layer.
- **`add_header` in the location drops a server-level header** → the panel vhost has none today; the generator
  declares every header the route needs, and a static test asserts the rendered block contains both directives
  with `always`.
- **The raw-path allow-list refuses a character the Panel would have accepted** → the class is lower-case
  letters, digits, `-` and `/` in the path plus any query, which covers every route and representation the
  product and the suites use (`tools/podman_e2e/panel_surface.py:175-179`). An upper-case or dotted path is not a
  GoWave route; if one ever appears, the map is one place to edit and a test fails first.
- **The scanner regex shadows a future Panel route** → the set is closed, anchored and tested against every
  path the Panel and dashboard serve today; a new route that collides is a deliberate edit of the set.
- **Dropping the forwarded chain breaks a component that expected it** → NGINX is the only proxy in front of the
  Panel; nothing else in the tree reads `X-Forwarded-For`. The Panel's rate limits and logs become correct
  instead.
- **Adopting a lineage while rollback still believes it is transaction-created** → the adoption is recorded
  before any issuance step, and the rollback test proves an adopted lineage survives a failed transaction.
- **A vendored Cloudflare snapshot ages** → documented as a fast-fail, not a boundary; the override exists and
  the snapshot date is in the comment. A missed range costs a failed ACME attempt, never a silent misinstall.
- **jsDelivr is a third party in the node installer path** → the bytes are pinned by digest in this repository;
  a mirror can only serve the exact file or be rejected.
- **Preflight before `check_os`** → the input contract is pure shell and does not depend on the detected OS, so
  running it first cannot mask a platform refusal; `check_os` still runs before any mutation.

## Migration Plan

- No data migration. A host installed by an earlier version keeps serving until the operator re-runs `install`
  (or `domain-change`), which regenerates the panel vhost through the same generator and reloads NGINX.
- Rollback of this change is a code revert plus a re-render; because every NGINX item is generated from the
  module, the previous vhost is restored by the previous generator. The adopted-lineage decision is per run and
  recorded in `state.json`, so reverting the selection logic leaves certificates where they are.
- The `ERR` trap and the environment contract are additive at the CLI level: an environment-only invocation
  works on the new version, and the positional form keeps working unchanged.

## Open Questions

- How often the vendored Cloudflare CIDR snapshot is refreshed. The check fails open on a missing range and the
  override exists, so this can be decided from operational experience without changing the spec or the tasks.
