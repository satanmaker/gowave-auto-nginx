# Proposal

## Why

`docs/research/inspiration-repos.md` surveyed eight third-party installers and reconciled their ideas against
this tree. Two classes of finding survived that reconciliation, and both are cheap to close where they live.
**Leakage around a subscription link:** the panel vhost answers `/api/sub/` without `X-Robots-Tag`, its
`Cache-Control` is written without `always` so a `502` from the Panel reaches the client with no cache directive
(`modules/nginx.sh:446`), the request line — which contains the `shortUuid` — goes to `access.log` (no
`access_log off` inside `modules/nginx.sh:438`), a link pasted into a messenger is fetched by that messenger's
preview bot, the vhost announces `nginx/<version>` because `server_tokens` is set only on the decoy and Vision
blocks (`:536`, `:575`), and the Panel is handed `$proxy_add_x_forwarded_for`, so a client-supplied header
survives into the Panel's own view of the address (`:443`, `:455`, `:465`, `:481`, `:495`). **Install-time
guarantees:** mandatory inputs are not validated before the first host mutation (NGINX is stopped at
`gowave-auto.sh:355` before `run_preflight_panel` at `:357`), a domain behind a Cloudflare proxy is accepted
and then fails at HTTP-01, an existing lineage that already covers the domain under another certificate name is
not adopted, `node add` has no environment contract beside its six positionals, downloads resolve through a
single host, and a failure anywhere in `gowave-auto.sh install` prints only an exit code — while the Worker
payload, which has done this since it was written, names the failing step
(`gowave-node-auto.sh:5263-5267`).

Everything below is additive to the shipped architecture: `443` stays NGINX Stream SNI, the Panel stays
unmodified upstream, and no item requires a new daemon, a new port or a change to the data plane. Each item
lands in the module that owns the behaviour — not as a `sed` over a generated file and not as a post-install
patch — carries a test that fails without it, and can be reverted on its own.

## What Changes

- **Subscription response hygiene.** The `/api/sub/` locations emit `X-Robots-Tag: noindex, nofollow, noarchive,
  nosnippet`, emit `Cache-Control: no-store, private` with `always` so Panel 4xx/5xx answers keep it, and stop
  writing the request line to the NGINX access log.
- **One User-Agent classification for the subscription route.** A single `map` classifies the header as
  *preview bot*, *client* or *other*. Preview bots and crawlers that a chat or a search engine sends to a pasted
  link receive `204` with an empty body; every other request keeps the Panel's own decision. The gate is
  deliberately not a client allowlist: the pinned Panel serves any non-empty header and the acceptance suites
  assert that (`docs/PODMAN_E2E_DISCOVERY.md:295-300`, `tools/podman_e2e/aio.py:178`), so a NGINX allowlist
  would replace a shipped contract with a maintenance burden.
- **Probe surface of the panel vhost.** The path under `/api/sub/` is validated on the raw request target —
  lower-case letters, digits and hyphens in a segment of at most sixteen characters — and answered `444` when it
  is not, so `../`, encoded separators and scanner probes never reach the Panel. Judging the raw target matters:
  a normalised path has already resolved `..` and decoded `%2F`, so the same rule read from it would be
  unobservable. A fixed, anchored set of known scanner paths is also answered `444` on the vhost. Semantics of a
  well-formed segment stay the Panel's, because the Panel already names the representations it serves
  (`internal/subscription/srr.go:165`).
- **Panel vhost fingerprint.** `server_tokens off` on the panel vhost, including error pages, matching the
  decoy and Vision blocks.
- **Real client address.** The Panel receives `X-Real-IP` and `X-Forwarded-For` built from `$remote_addr`
  only — the PROXY-protocol address restored by `real_ip_header proxy_protocol` — so a forged client header
  cannot reach the Panel's logs, rate limits or abuse checks.
- **Mandatory-input preflight before the first mutation.** A component-scoped required-input contract runs
  before NGINX is stopped, before packages are installed and before any managed path is written; a missing or
  malformed input names the input and the component and aborts. The wizard and the positional path validate the
  same fields through the same contract.
- **Cloudflare-proxied domain refusal.** Preflight resolves the panel, decoy and Vision names and refuses an
  install whose names land in a published Cloudflare proxy range, stating that HTTP-01 cannot complete behind
  the proxy and what to change. An operator-declared range or an explicit override is accepted.
- **Lineage resolution by coverage.** ACME lineage selection adopts an existing lineage whose certificate
  covers the requested name (SAN/CN) even when its certificate name carries a `-0001` suffix, and the vhost
  references that lineage's `live/` directory. A lineage that is reused must still match the selected ACME
  directory, so the existing staging/production isolation is unchanged; when several lineages cover the name,
  the choice is deterministic and recorded.
- **Environment contract for `node add`.** `gowave-auto.sh node add` accepts `GOWAVE_NODE_NAME`,
  `GOWAVE_NODE_IP`, `GOWAVE_WORKER_DOMAIN`, `GOWAVE_REALITY_DOMAIN`, `GOWAVE_SSH_USER`, `GOWAVE_SSH_PORT` and
  `GOWAVE_VISION_DOMAIN` beside the positionals, with positionals winning, identical validation on both paths,
  and no secret added to `argv` or to the environment.
- **Mirror chain for downloads.** The panel release already requires `SHA256SUMS` and already tries several
  candidate URLs on one host; the change keeps that gate, adds an independent second host for the pinned Worker
  installer, and states both as one contract: an ordered host list, and a digest that is verified before
  anything executes. A mismatch aborts the whole install rather than falling through to the next host.
- **Failure diagnostics in `gowave-auto.sh`.** `install`, `node add`, `domain-change` and `uninstall` install an
  `ERR` trap that reports the step, the failing command and the exit status, using the pattern the Worker
  payload already runs. Compensation stays where it is — the trap reports, it does not start a second rollback.

## Capabilities

### New Capabilities

- `subscription-edge`: what the NGINX panel vhost guarantees for `/api/sub/` — response headers on every status,
  access-log suppression, the User-Agent classification and its three outcomes, and the `clientType` segment
  contract.
- `panel-vhost-hygiene`: what the panel vhost does not reveal — the version banner, the client-supplied
  forwarding headers, and the scanner paths that are answered without reaching the Panel.
- `install-preflight`: what is proven about the requested deployment before the host is touched — mandatory
  inputs per component and the reachability/proxy facts that decide whether ACME can succeed.

### Modified Capabilities

- `lifecycle-management`: adds coverage-based certificate-lineage selection (the shipped check selects a lineage
  by exact certificate name only) and three operator-facing requirements — a verified download chain, the
  `node add` environment contract, and failure diagnostics.

## Impact

- `modules/nginx.sh` — `generate_panel_https_vhost` (headers, log, UA map, segment and scanner locations,
  `server_tokens`, forwarding headers); `check_acme_lineage` and the vhost's `ssl_certificate` paths for
  coverage-based lineage selection.
- `modules/preflight.sh` — the required-input contract and the Cloudflare proxy check, plus the call order in
  `gowave-auto.sh` and the Worker payload so that both run before the first mutation.
- `gowave-auto.sh` — preflight ordering, `cmd_node` environment contract, `ERR` trap installation.
- `modules/panel.sh`, `modules/node.sh` — ordered mirror hosts, reusing the existing mandatory-digest gate.
- Tests: static assertions in `tests/test_nginx_routing.py` and `tests/test_install_mode.py`, a new case class
  for the preflight contract, and Podman acceptance cases for every behaviour that a container can observe —
  the suite refuses a behaviour with no case (`docs/PODMAN_E2E_BEHAVIORS.md`).
- Documentation: `docs/PODMAN_E2E_DISCOVERY.md` (subscription contracts, User-Agent policy) and
  `docs/PODMAN_E2E_TRACEABILITY.md` gain the new rows; `README.md` documents the `node add` environment
  variables.
- No upstream source modification, no new listening port, no change to the Stream SNI map or to the data plane.
  `GOWAVE_PROXY=external` and the REALITY fallback contract are untouched.

## Out of Scope

- **В3–В5 of the research document** — the D-SNI fork, the decoy TLS block, a UDS fallback, the panel gate,
  render-if-changed, the maintenance window, Safe Migration, wildcard DNS-01. Each changes listener behaviour,
  locking or the backup schema and needs its own run and its own rollback.
- **C11 (external trusted SNI)** — incompatible with an own-domain REALITY and an own decoy; dropped in Р-3.
- **Items found already shipped while grounding this proposal**, which therefore carry no task here:
  `bittorrent → BLOCK` is emitted by the authoritative routing block (`modules/api_client.py:469-492`), so
  adding it to every `assets/xray/*.json` template would create a second source of truth; Worker and host names
  are validated before use (`gowave-auto.sh:925-945`, `modules/wizard.sh:51-63`); the panel release already
  requires `SHA256SUMS` and already tries several candidate URLs (`modules/panel.sh:93-181`), so the remaining
  work is the independent host, not the contract.
- **Denying unknown User-Agents on `/api/sub/`** — the research document's summary line says "unknown client →
  refuse", but the pinned Panel serves any non-empty header and `SUB-SERVED` asserts it with `curl/8.5.0`
  (`tools/podman_e2e/panel_surface.py:85`). Implementing that line would contradict a shipped acceptance
  contract, so the change keeps the Panel's decision and gates only preview bots and crawlers.
