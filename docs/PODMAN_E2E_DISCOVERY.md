# Podman E2E: the product surface under test

The acceptance suite accepts the product's own operator interface, so this page
records that interface as the suite found it: which commands exist, which of
them run inside a container, and which topologies they are accepted in. It is
written for the reader who has to decide whether a case is missing because the
product cannot do the thing or because no one wrote the case yet.

The page is read back by `tests/test_podman_docs.py` (`TestDiscoveryInventory`
for the command surface, `TestPanelApiContract` for the Panel API map), which
parses the usage lines out of `gowave-auto.sh`, the topologies and
representations out of `tests/cases/matrix.yaml`, the case ids out of
`tests/cases/catalog.yaml`, the endpoints the product calls out of
`modules/api_client.py` and the route declarations out of the vendored Panel.
A subcommand renamed in the product, a topology dropped from the manifest, a
case id this page invents or an endpoint no one declares fails the nonroot
suite rather than being discovered by a reader.

## Operator entrypoints

`gowave-auto.sh` takes exactly one command word, and `node` takes its own:

```
gowave-auto.sh {status|health|install|node|channel|domain-change|backup|restore|uninstall|user links <id>|recover}
gowave-auto.sh node {add|list|reapply|rollback}
```

Those two lines are the product's own `Usage:` text (`gowave-auto.sh:1553` and
`gowave-auto.sh:1223`), not a summary. Each entrypoint below names the cases
that invoke it; “none” is a fact about the suite, not a claim that the
entrypoint is unimportant.

| Entrypoint | What it does | Container cases that invoke it |
| --- | --- | --- |
| `status` | Prints what the operator installed and whether its units are up. | none — `AIO-04` asserts the underlying facts directly (unit states and the listening sockets) instead of trusting a summary |
| `health` | Checks the Panel's health endpoint. | none — `AIO-01` calls the same API from the client container |
| `install` | Installs the product on this host, with the domain, ACME contact and REALITY domain the operator passes. | `AIO-INSTALL`, `AIO-IDEMPOTENT` |
| `node add` | Registers a Worker from the Master and installs the Worker payload over SSH. | `MN-INSTALL` |
| `node list` | Lists the Workers the Master manages. | none |
| `node reapply` | Re-sends the Worker payload without re-registering the node. | `NGX-WORKER-ACME80` |
| `node rollback` | Rolls a Worker back to a previous payload. | none |
| `channel` | Switches between the `stable` and `dev` release channels, taking a snapshot first. | `AIO-CHANNEL-NOOP`, `AIO-CHANNEL-DEV`, `AIO-CHANNEL-ROLLBACK`, `AIO-INTERRUPT` |
| `domain-change` | Changes the Panel and REALITY domains and re-renders what depends on them. | `NGX-WORKER-ACME80` |
| `backup` | Writes a Panel or Node archive through the operator's own interface. | `MN-BACKUP`, `MN-BACKUP-VOL`, `MN-BACKUP-BAD` |
| `restore` | Restores an archive the operator produced. | `MN-RESTORE`, `MN-BACKUP-BAD` |
| `uninstall` | Removes the product's managed units from this host. | none |
| `user links <id>` | Prints a user's subscription links. | none — `AIO-CLIENT` fetches the same links through the Panel API |
| `recover` | Rolls a snapshot back with `--boot-files` after an interrupted run. | `AIO-CHANNEL-DEV`, `AIO-INTERRUPT` |

## Install modes

- **All-in-One** — `gowave-auto.sh install` on one host installs the Panel and
  a local GoWave Node together, with NGINX owning 443 and demultiplexing by SNI.
  `AIO-INSTALL` covers the clean path and `AIO-IDEMPOTENT` covers running it a
  second time on the same host.
- **Multi-Node** — the Master runs the All-in-One install and then registers
  each Worker with `node add`, which provisions the Worker over SSH over the
  private network the Master actually reaches (`MN-INSTALL`, `MN-EGRESS`).
- **Panel-only** — `gowave-auto.sh install --panel-only` on one host installs
  the Panel and the static camouflage site and stops there: no GoWave Node, no
  Xray and no inbound listener, so the stream map sends `default` to the decoy
  at `:9443`. The topology has no product case yet; until one lands the suite
  refuses a `--topology panel-only` run instead of reporting an empty green.
- **Channel switching** — a host installed on `stable` can move to `dev` and
  back; the product snapshots before it switches and rolls back a release that
  cannot start (`AIO-CHANNEL-DEV`, `AIO-CHANNEL-ROLLBACK`), and an operator
  killed mid-switch is recovered by `recover --boot-files` (`AIO-INTERRUPT`).
- **Uninstall** is a separate entrypoint and is not part of an install mode:
  no container case invokes it.

## Supported deployment topologies

`tests/cases/matrix.yaml` declares the topologies the suite builds, and
`openspec/changes/podman-full-e2e/design.md` (§Topologies) describes what each
one represents. The suite accepts:

- `aio` — one disposable systemd host running the complete All-in-One product,
  with the fixtures and the client containers outside it.
- `multi-node` — a Master and a Worker as two disposable systemd hosts, with the
  Worker provisioned through the Master's own `node add` path, plus per-node
  Vision: neither, master-only, worker-only, or both.
- `panel-only` — one disposable systemd host running the Panel and the static
  camouflage site, with no node, no Xray and no inbound listener, installed
  through `install --panel-only`. Its manifest entry declares no data-plane
  tuple and no Vision combination, because the mode has neither, and it names
  no gate tier: no workflow runs it yet.

All three topologies run on the same four pinned distributions; the next section
says which of them a workflow actually executes.

## The OS matrix, and which contour executes each row

The product decides which systems it supports in `modules/os.sh`, which turns
`${OS_ID}-${OS_VERSION_ID}` into a codename for exactly four of them:
`ubuntu-24.04` → `noble`, `ubuntu-26.04` → `resolute`, `debian-12` →
`bookworm`, `debian-13` → `trixie`. `tests/cases/images.lock.yaml` pins one
base image per row by registry digest, and `target_image.DISTRIBUTIONS` is the
`--distribution` vocabulary the suite accepts, so the four names are one set
rather than three opinions.

What differs between the rows is what executes, and that is the part a reader
has to be able to check rather than assume:

| Distribution | Pinned base | Product acceptance | QEMU cold boot | NGINX `listen` branch |
| --- | --- | --- | --- | --- |
| `ubuntu-24.04` | `docker.io/library/ubuntu:24.04` | executed by every `podman-acceptance.yml` job | `qemu-cold-boot` matrix | legacy, `1.24.0 < 1.25.1` |
| `ubuntu-26.04` | `docker.io/library/ubuntu:26.04` | selectable, not executed | `qemu-cold-boot` matrix | modern, `1.26+ >= 1.25.1` |
| `debian-12` | `docker.io/library/debian:12` | selectable, not executed | `qemu-cold-boot` matrix | legacy, `1.22.1 < 1.25.1` |
| `debian-13` | `docker.io/library/debian:13` | selectable, not executed | `qemu-cold-boot` matrix | modern, `1.26.3 >= 1.25.1` |

**Only one row is executed against the product.** `--distribution` defaults to
`ubuntu-24.04` and no workflow passes the flag, so all four acceptance jobs —
the two topologies and their two recovery runs — install on the same
distribution. The other three rows are pinned and runnable
(`sudo python3 -m tools.run_podman_e2e --topology aio --distribution debian-13`),
but no CI job has run them: that is a coverage gap of this suite, not a
compatibility claim. The compatibility matrix's component tables are what say a
row is supported, and this suite adds product-level evidence only where it
executed.

**The QEMU matrix is a different claim.** The `qemu-cold-boot` job in
`.github/workflows/systemd-acceptance.yml` boots all four images through
`tests/systemd/boot.sh`, but the unit that runs inside the guest is
`tests/run_ci.py --suite systemd`: it proves the systemd unit contracts under a
real systemd PID 1 on that distribution, not an operator install. Both facts
matter and neither replaces the other — a green QEMU job does not mean the
product installed there, and a green acceptance run does not mean the row's
systemd contracts hold.

**The two `listen` branches.** `render_nginx_listen_ssl_http2` in
`modules/os.sh` reads `nginx -v` and prints `listen … ssl http2 …;` below
1.25.1 and `listen … ssl …; http2 on;` from 1.25.1 up, which is the split the
compatibility matrix records per distribution. The version that lands is
whatever the distribution archive holds when the operator installs, so the
branch is decided at run time by the probe rather than recorded in a manifest,
and the numbers in the table are the expected values rather than assertions.
The executed row therefore proves the legacy branch; the modern branch has no
executed product run yet.

**The legacy scripts identify by tag, the suite by digest.**
`tests/podman_testbed.sh` and `tests/systemd/boot.sh` take
`docker.io/library/ubuntu:24.04` and build from it, while
`tests/cases/images.lock.yaml` pins the same four references by manifest digest
and `tools/podman_e2e/images.py` refuses an unpinned reference before it
invokes Podman. The divergence is recorded rather than fixed here: those two
scripts belong to the transport and cold-boot contours, and changing their
inputs belongs to the contour that owns them.

## The Panel API the suite is written to

The product does not configure the Panel by editing files: `gowave-auto.sh`
drives `modules/api_client.py` through the install, the provisioning and the
journal rollback, and the acceptance harness reads the same API from its client
containers. This section maps the endpoints both of them use, so that a case
that fails on a route can be read against the declaration it was written to
instead of against a guess about what the Panel serves.

The map was taken from the vendored tree at `sources/gowave/backend-go`,
revision `6800737` (`v1.2.4-4-g6800737`, 2026-11-12), which is the source of
every `file:line` below. That tree is a local checkout — `/sources/` is in
`.gitignore`, so the checkout is not part of this repository — and
`TestPanelApiContract` therefore reads the declarations back only where the tree
exists, naming the skip when it does not. The claims that need no tree run in
CI: every call `modules/api_client.py` makes is a row below, every `file:line`
in the `Client caller` column really makes the call it is cited for, every case
id named here exists in `tests/cases/catalog.yaml`, and every representation
`tests/cases/matrix.yaml` declares is served by a route below.

The installer installs `GOWAVE_DEFAULT_VERSION="latest"`
(`modules/panel.sh:10`), so this is the API the shipped client is written to
rather than a version the suite pins. A `latest` that dropped one of these
routes would fail a provisioning case, which is what the map is for: it says
where the call comes from, not that the release is frozen.

**Authentication.** `gowave-auto.sh install` registers the first administrator
with `POST /api/auth/register`, logs in, and mints a scoped API token that the
provisioning steps reuse; a repeat install reuses an existing token instead of
creating a second one.

| Area | Endpoint | Declared at | Client caller |
| --- | --- | --- | --- |
| authentication | `POST /api/auth/register` | `internal/server/server.go:514` | `modules/api_client.py:338` `register_initial_admin` |
| authentication | `POST /api/auth/login` | `internal/server/server.go:513` | `modules/api_client.py:350` `login` |
| authentication | `POST /api/tokens` | `internal/server/server.go:534` | `modules/api_client.py:817` `issue_api_token` |
| authentication | `GET /api/tokens` | `internal/server/server.go:533` | `modules/api_client.py:841` `ensure_api_token` |
| authentication | `DELETE /api/tokens/{uuid}` | `internal/server/server.go:535` | `modules/api_client.py:826` `delete_token` |

**Node registration.** The node record and its REALITY key material are made
through the Panel, which is why `AIO-INSTALL`, `AIO-IDEMPOTENT` and `MN-INSTALL`
are the cases that exercise this area: an AIO install registers its local node,
and a Multi-Node Master registers each Worker over the same route before it
provisions the Worker.

| Area | Endpoint | Declared at | Client caller |
| --- | --- | --- | --- |
| node registration | `GET /api/system/tools/x25519/generate` | `internal/stubs/stubs.go:218` | `modules/api_client.py:361` `generate_x25519` |
| node registration | `GET /api/nodes` | `internal/server/server.go:590` | `modules/api_client.py:584` `associate_node` |
| node registration | `POST /api/nodes` | `internal/server/server.go:593` | `modules/api_client.py:622` `associate_node` |
| node registration | `PATCH /api/nodes/{uuid}` | `internal/server/server.go:599` | `modules/api_client.py:592` `associate_node` |
| node registration | `DELETE /api/nodes/{uuid}` | `internal/server/server.go:600` | `modules/api_client.py:879` `delete_node` |

**Provisioning.** Hosts, internal squads and config profiles are the Panel
objects an install creates before a client can be served: the host record links
the public domain to the node, the squad decides which inbounds a user's
subscription carries, and the profile is what the node renders its Xray config
from. `AIO-INSTALL` and `MN-INSTALL` create them; the rollback cases
(`AIO-CHANNEL-ROLLBACK`, `AIO-INTERRUPT`) are what walk the same routes backwards
through `rollback_provisioning`.

| Area | Endpoint | Declared at | Client caller |
| --- | --- | --- | --- |
| provisioning | `GET /api/hosts` | `internal/server/server.go:612` | `modules/api_client.py:661` `provision_hosts` |
| provisioning | `POST /api/hosts` | `internal/server/server.go:613` | `modules/api_client.py:727` `provision_hosts` |
| provisioning | `PATCH /api/hosts` | `internal/server/server.go:615` | `modules/api_client.py:724` `provision_hosts` |
| provisioning | `DELETE /api/hosts/{uuid}` | `internal/server/server.go:616` | `modules/api_client.py:863` `delete_host` |
| provisioning | `GET /api/internal-squads` | `internal/server/server.go:638` | `modules/api_client.py:631` `provision_internal_squad` |
| provisioning | `POST /api/internal-squads` | `internal/server/server.go:639` | `modules/api_client.py:650` `provision_internal_squad` |
| provisioning | `PATCH /api/internal-squads` | `internal/server/server.go:641` | `modules/api_client.py:647` `provision_internal_squad` |
| provisioning | `DELETE /api/internal-squads/{uuid}` | `internal/server/server.go:642` | `modules/api_client.py:871` `delete_internal_squad` |
| provisioning | `GET /api/config-profiles` | `internal/server/server.go:628` | `modules/api_client.py:517` `provision_config_profile` |
| provisioning | `POST /api/config-profiles` | `internal/server/server.go:629` | `modules/api_client.py:539` `provision_config_profile` |
| provisioning | `PATCH /api/config-profiles/{uuid}` | `internal/server/server.go:632` | `modules/api_client.py:535` `provision_config_profile` |
| provisioning | `DELETE /api/config-profiles/{uuid}` | `internal/server/server.go:633` | `modules/api_client.py:887` `delete_config_profile` |
| provisioning | `GET /api/config-profiles/{uuid}/inbounds` | `internal/server/server.go:635` | `modules/api_client.py:562` `provision_config_profile` |
| provisioning | `GET /api/config-profiles/{uuid}/computed-config` | `internal/server/server.go:636` | `modules/api_client.py:545` `provision_config_profile` |

**Client lifecycle.** A client is a Panel user with a subscription: `AIO-CLIENT`
creates one and fetches its links, `AIO-REVOKE` and `MN-REVOKE` delete one and
assert that its links stop being served. The user is looked up by name before
creation so that a second install adopts the client it made rather than
duplicating it.

| Area | Endpoint | Declared at | Client caller |
| --- | --- | --- | --- |
| client lifecycle | `POST /api/users` | `internal/server/server.go:554` | `modules/api_client.py:760` `provision_user` |
| client lifecycle | `GET /api/users/by-username/{username}` | `internal/server/server.go:581` | `modules/api_client.py:739` `provision_user` |
| client lifecycle | `DELETE /api/users/{userId}` | `internal/server/server.go:579` | `modules/api_client.py:855` `delete_user` |

**Update operations.** The pinned Panel exposes an update for every object an
install creates, and the suite drives the configuration one: the journal writes
back the profile, node, squad and host it changed when it rolls a failed
provisioning step back (`modules/api_client.py:1145`-`1151`), and
`provision_config_profile` patches an existing profile instead of replacing it.
API-04's `configuration update` is that path.

| Area | Endpoint | Declared at | Client caller |
| --- | --- | --- | --- |
| update | `PATCH /api/config-profiles/{uuid}` | `internal/server/server.go:632` | `modules/api_client.py:1181` `rollback_provisioning` |
| update | `PATCH /api/nodes/{uuid}` | `internal/server/server.go:599` | `modules/api_client.py:1183` `rollback_provisioning` |
| update | `PATCH /api/internal-squads` | `internal/server/server.go:641` | `modules/api_client.py:1185` `rollback_provisioning` |
| update | `PATCH /api/hosts` | `internal/server/server.go:615` | `modules/api_client.py:1187` `rollback_provisioning` |
| update | `PATCH /api/users` | `internal/server/server.go:555` | none — coverage gap, not `NOT_APPLICABLE` |
| update | `PATCH /api/users/{userId}` | `internal/server/server.go:578` | `modules/api_client.py:799` `attach_squad_to_user`, `modules/api_client.py:1189` `rollback_provisioning` |

**Subscription contracts.** A subscription is fetched without a token, by short
UUID, so the route is the contract: one path per representation, the
non-base64 ones naming the representation as a path segment that the Panel maps
to a generator. The five representations are declared once, in
`tests/cases/matrix.yaml`: `base64` at `/api/sub/{shortUuid}`, `xray-json` at
`/v2ray-json`, `mihomo` at `/mihomo`, `clash` at `/clash` and `singbox` at
`/singbox`. The probe carries the client family and User-Agent for each
(`tools/podman_e2e/panel_surface.py:175`-`179`); `SUB-B64` is the case that checks
the base64 list an Xray-family client imports.

| Area | Endpoint | Declared at | Client caller |
| --- | --- | --- | --- |
| subscription | `GET /api/sub/{shortUuid}` | `internal/server/server.go:522` | `tools/podman_e2e/panel_surface.py:175` `base64` |
| subscription | `GET /api/sub/{shortUuid}/info` | `internal/server/server.go:523` | none — coverage gap |
| subscription | `GET /api/sub/{shortUuid}/{clientType}` | `internal/server/server.go:524` | `tools/podman_e2e/panel_surface.py:176` `xray-json` |

The path segment is not free-form: `handleOverrideClientType`
(`internal/subscription/srr.go:165`) switches on `stash`, `singbox`, `mihomo`,
`json`, `v2ray-json` and `clash`, and answers anything else with `BLOCK`. The
manifest's `xray-json` entry asks for `/v2ray-json`, which is the fourth arm of
that switch, and `TestPanelApiContract` refuses a representation whose segment
the switch does not name — otherwise a typo in the manifest would be answered by
`BLOCK` and would look like a Panel defect.

**The User-Agent policy, per path.** The two paths do not decide the same way.
On the client-type path the segment decides and the header only has to be
present: `Match` (`internal/subscription/srr.go:77`) returns
`handleOverrideClientType(...)` before it reads a single rule. On the bare path
the header decides, through the Panel's default rule set: `DefaultSRRConfig`
(`internal/database/default_data.go:10`) lists the Mihomo, Stash, sing-box,
Clash and browser rules and then an unconditional `Fallback Base64` rule, so any
other non-empty header is served the base64 list. In both cases an absent or a
blank header is refused with 403 before a rule is read
(`internal/subscription/serve.go:118`), which is the policy `user_agent` in
`tests/cases/matrix.yaml` states and `SUB-UA-ABSENT` and `SUB-UA-BLANK` assert
separately: two probes, two results, because a client that sends no header and a
client that sends an empty one are different requests.

That policy is why `SUB-SERVED` asks every representation a second time with
`curl/8.5.0`, a header that names no client family
(`tools/podman_e2e/panel_surface.py:85`). It has to be served, and with the same
bytes: a refusal would mean the Panel requires a format rather than a header,
and different bytes would mean the header selects the representation and the
family headers were carrying the assertion. Neither is true of the pinned Panel,
and the suite would be inventing an allowlist if it assumed either.

### The host record a tuple dials

`modules/api_client.py` posts one Host record per provisioned inbound, and
`host_projection` is that mapping: the address a client dials, the SNI it
presents, the ALPN it offers, the transport path and the `securityLayer` the
Panel stores. `tests/cases/matrix.yaml` restates it per inbound, so a case id
decodes to the record it exercises, and `TestHostProjection` compares the
matrix, the page and the shipped function — a record changed in the client
without the matrix, or the reverse, fails the nonroot suite.

| Tuple inbound | Address | SNI | ALPN | Path | `securityLayer` |
| --- | --- | --- | --- | --- | --- |
| `REALITY` | panel domain | REALITY domain | `h2,http/1.1` | — | `DEFAULT` |
| `XHTTP` | panel domain | panel domain | `h2,http/1.1` | `/xhttp-down/` | `TLS` |
| `WS` | panel domain | panel domain | `http/1.1` | `/ws` | `TLS` |
| `TROJAN-GRPC` | panel domain | panel domain | `h2` | `trojan-grpc` | `TLS` |
| `VISION` | Vision domain | Vision domain | `http/1.1` | — | `TLS` |

REALITY is the one row where the dialled name and the presented name differ:
clients connect to the panel's public address and present the REALITY domain as
SNI, which is what the loopback fallback in `modules/nginx.sh` demultiplexes. A
matrix that collapsed the two would name a tuple no client dials. Every row
pins the `firefox` uTLS fingerprint — `reality_fingerprint()` for REALITY and
the literal for the TLS transports — which is the value the subscription
importer carries into `tlsSettings` or `realitySettings`, and the `host` field
stays `null`, so the client's Host header follows the dialled address.

### Which client family consumes which representation

The manifest's `clients` block says which pinned binary imports which
representation; this table says what the case that fetches it actually does with
the body. The order is the order the probe fetches them in
(`tools/podman_e2e/panel_surface.py:175`-`179`), and
`TestSubscriptionFamilyInventory` reads every cell back against
`tests/cases/matrix.yaml`, that tuple and `tests/cases/catalog.yaml`, so a
representation added to the manifest without a row — or a row naming an engine
the manifest does not pin — fails the nonroot suite.

| Representation | Path | Header the probe sends | Consuming engine | Case | What consumption proves |
| --- | --- | --- | --- | --- | --- |
| `base64` | `/api/sub/{shortUuid}` | `v2rayNG/1.8.5` | `xray` 26.11.9 | `SUB-B64` | The body is decoded as a share-link list, every link becomes the outbound a client would build from it, and the result is validated with `xray run -test`. The same importer is then offered the `/v2ray-json` body and decodes nothing, so the two representations cannot be substituted for each other. |
| `xray-json` | `/api/sub/{shortUuid}/v2ray-json` | `Xray/26.11.9` | `xray` 26.11.9 | `SUB-SERVED` | Every served profile is already a complete config and is validated as one with `xray run -test`; a profile that needed the runtime wrapper would be a bare outbound, which the Panel does not serve. |
| `mihomo` | `/api/sub/{shortUuid}/mihomo` | `mihomo/1.19.34` | `mihomo` 1.19.34 | `SUB-SERVED` | The YAML is loaded by `mihomo -t -f`, and the proxies it declares are counted against the inbounds this cluster serves. |
| `clash` | `/api/sub/{shortUuid}/clash` | `clash.meta/1.19.34` | `mihomo` 1.19.34 | `SUB-SERVED` | The same engine loads it; the count is the trojan subset the shipped Clash generator keeps, which is why one node serves one Clash proxy rather than one per inbound. |
| `singbox` | `/api/sub/{shortUuid}/singbox` | `sing-box/1.10.0` | none pinned | `SUB-SERVED` | The body is parsed as JSON and its outbounds counted, and nothing executes it: no sing-box binary is pinned in the manifest, so this row records a representation the Panel serves without claiming that a client consumed it. |

Two rows share an engine because one binary really is the client: Mihomo loads
both the `mihomo` YAML and the `clash` YAML, and the Clash representation is
that engine fed the subset the Panel's Clash generator keeps. `singbox` is the
one representation in the manifest that no pinned client consumes, which is why
`tests/cases/matrix.yaml` lists exactly two clients — `xray`, consuming `base64`
and `xray-json`, and `mihomo`, consuming `mihomo` and `clash` — and the table
says "none pinned" instead of leaving a reader to infer that a parsed body was
an imported one.

### Both served shapes of `/v2ray-json`

The route has two documented shapes and the Panel serves one of them per
request: a single config object carrying `outbounds`, or a list of complete
per-profile configs. The suite does not assume which. `SUB-JSON-SHAPES` reads
the served shape first, then forms the other one from the Panel's own outbound,
so both shapes are exercised against the same account instead of one of them
being asserted from a fixture.

The half that decides the claim is the wrapper. A list entry is a complete
config — inbounds included — and is validated as such with `xray run -test`,
byte for byte; a run in which an entry needed the minimal listener added would
be a list of bare outbounds, which is not a shape the Panel serves. The bare
object is the one that gets wrapped, and exactly once: `prepare_config` in
`tools/podman_e2e/subscription_probe.py` adds a local SOCKS inbound only when
the config carries no `inbounds` at all, and reports whether it did. That object
carries one Panel outbound rather than one per host, because a config object is
one host and the Panel tags every host outbound `proxy`, so merging profiles
into a single object would collide on the tag instead of testing a shape.

A reader can therefore tell the two shapes apart from the counts alone:
`served_wrapped = 0` and `alternate_wrapped = 1` when the Panel served a list,
and the pair inverted when it served an object. `SUB-JSON-SHAPES` requires
exactly that, and `TestJsonShapeContract` holds this paragraph against
`case_json_shapes` and `prepare_config`, so the page cannot keep describing a
rule the probe stopped enforcing.

### The live contract, capability by capability

`openspec/specs/live-vps-e2e/spec.md` §Real Subscription Delivery and
User-Agent Policy accepts the same product surface on two real VPS instead of
one disposable host. The two suites have to assert the same product contract;
where their numbers differ the topology explains the number, and where the live
text names something the pinned Panel does not ship, this page says so instead
of quietly asserting the weaker half.

| Live scenario | Container case | Where the two differ |
| --- | --- | --- |
| `Subscription rejected with absent User-Agent` | `SUB-UA-ABSENT`, `SUB-UA-BLANK` | The live contract passes on whatever status the installed Panel returns and fails only if it differs from the upstream policy; the container suite pins `403` because the pinned Panel answers `403`, and asks every served path rather than `/v2ray-json` alone. |
| `Proxy-capable outbounds in Xray JSON` | `SUB-SERVED`, `SUB-B64` | The live contract counts 8, 9 or 10 outbounds because it always runs a Master and a Worker; an All-in-One subscription carries 4 (5 with Vision) and a Multi-Node one carries 8, 9 or 10. The count is per subscription, so the topology explains the smaller number and the product does not change. |
| `Xray JSON subscription headers and content verified` | `SUB-SERVED`, `SUB-B64` | `SUB-SERVED` requires HTTP 200, the media type each representation is served with, `Cache-Control: no-store`, every served outbound recorded by `GET /api/hosts` on address, SNI and path, no server-side secret in any representation and no private key field, and `xray run -test` over each served profile; `SUB-B64` decodes the link list and proves the Xray-family importer consumes it. The header is read through the public edge, because the Panel process itself sends none. The live text's "all mandatory response headers" is claimed only for the header it names itself; the rest are recorded, not asserted, because no container case reads one. |
| `Mihomo YAML subscription verified` | `SUB-SERVED` | Both require HTTP 200, a media type, one proxy per served inbound and `mihomo -t`. The live text also names the rule `GEOIP,private,DIRECT,no-resolve`; see below. |

**The one divergence that is prose, not behaviour.** The pinned Panel does not
emit `GEOIP,private,DIRECT,no-resolve`. Its Mihomo template carries
`GEOIP,LAN,DIRECT` followed by `MATCH,→ GoWave`
(`internal/database/default_data.go:108`), which is the same intent — keep
private destinations off the proxy — under the rule name that template uses.
The live runner accepts either family, a GEOIP rule or a MATCH rule
(`tools/live_vps/subscriptions.py:409`), and the container case asserts that a
`MATCH` rule exists so a client would route something at all, because a
representation the engine loads but never routes through is not a working
subscription. Restating the live sentence's literal line would fail against the
Panel this repository pins, so the divergence is recorded here rather than
turned into an assertion either suite would have to weaken later.

**The header is read where a client reads it.** `modules/nginx.sh` adds
`Cache-Control: no-store, no-cache, must-revalidate, max-age=0` inside
`location ^~ /api/sub/` of the Panel vhost, and the Panel's own handler adds
none: a probe that fetched `http://127.0.0.1:3000` would report an empty header
for a product that serves one. `SUB-SERVED` therefore reads every representation
twice — once on loopback, which is what the byte and User-Agent facts describe,
and once over `https://<panel_domain>/…` with the run's own CA bundle, which is
what a client receives — and requires the edge answer to carry `no-store` and to
be byte-identical to what the Panel issued. The first version of the case read
only the loopback answer and failed a real run
(`podman-aio-20261114T192016-4bb11a91`, `SUB-SERVED`, `Cache-Control ''`)
although the vhost sent the header: the case, not the product, was wrong, and
the two-vantage read is what closes that gap rather than a wider tolerance.

**The edge is read as the three audiences that share one URL.** A subscription
URL is kept on a phone and pasted into chats, so the shipped vhost answers three
callers differently: `map $http_user_agent $gowave_sub_ua_class` marks the
link-preview families, `location ^~ /api/sub/` returns `204` with no body to
them, and `add_header ... always` keeps `Cache-Control: no-store, private` and
`X-Robots-Tag: noindex, nofollow, noarchive, nosnippet` on every answer the
location sends, including the Panel's own `403`. `SUB-EDGE` reads a client, a
header naming no family (`curl/8.5.0`), an absent header and all twelve preview
families through `https://<panel_domain>` with the run's CA bundle, and requires
the client's bytes to be the ones the Panel issued while every preview answer is
empty and still carries both headers. The family list is compared with the map
itself in `TestDecoyCase`, so a pattern removed from `modules/nginx.sh` or a
header the probe stops sending fails the nonroot suite rather than silently
reading as a served preview.

**"The Panel never saw it" is read from the router, not from a log.** The Panel's
request logging is off unless `IS_HTTP_LOGGING_ENABLED` is set
(`server.go:501,546`), so an assertion about its journal would hold no matter
what the edge forwarded. The always-on instrument is the router's own counter,
`GET /api/system/stats/http`, keyed by chi patterns `GET /api/sub/{shortUuid}`
and `GET /api/sub/{shortUuid}/{clientType}`. `SUB-EDGE` reads it before and after
the twelve-family sweep and requires no movement, then fetches the same path on
loopback and requires the counter to move by exactly one: an instrument that
would not move for a request it served cannot prove quietness for the requests
it did not.

**A refused target is proven by the log that records it.** The dot-segment rule
reads `$request_uri`, because `$uri` is already normalised and decoded — the
dot segment and the encoded separator do not survive it. `SUB-EDGE-BAD` sends
`/api/sub/<shortUuid>/../x` and `/api/sub/<shortUuid>%2Fv2ray-json` verbatim with
`http.client`, so the bytes on the wire are the ones the rule sees, and requires
a closed connection with no status and no body. The access log is then read from
the same host and has to hold both refused targets with `444` while holding no
served `/api/sub/<shortUuid>` line: the refusals are the positive control that
distinguishes "nothing was logged" from "nothing was served", and the served
line is the credential a subscription URL is.

**The listener is also read for what it says about itself and whom it believes.**
Two audiences share the vhost with the subscription client: an operator's
scanner, which sorts hosts by the build they announce, and the Panel, which
believes whichever client address it is handed. `NGX-HYGIENE` asks
`/api/system/health` (a `200` the Panel answers) and an unknown `/api/` path (the
Panel's own `404`) and requires no version in either `Server`; it then sends a
request line past NGINX's header buffer, because the `414` it gets back is the
only error page the listener writes itself — a proxied `404` is the Panel's page
— and requires no version fragment in that header or body. The same case forges
each of the ten address headers `httpx.ClientIP` prefers over the socket, one at
a time, and reads the address back from
`GET /api/users/{userId}/subscription-request-history`: the record has to name
the peer this run allocated and must never name the forged value, so a listener
that cleared all but one header is reported by name. `NGX-SCANNER` sends the
shipped scanner set and requires a dropped connection with no bytes for each,
then sends `/api/nodes` from the same client and requires the Panel's own `401`:
without that control a listener that closed every connection would read as a
scan defence. The same set of headers is compared against the rendered vhost in
`TestNginxRouting`, and both cases are incubated in the container suite until a
promotion row names the live scenario that takes them.

**The subscription is compared with the records the Panel keeps, not with the
projection the installer posted.** Every served outbound is read back as the
tuple a client dials — address, port, SNI, and the path or gRPC service name —
and matched against `GET /api/hosts`, the document the Panel derives a client's
config from. Comparing it with `host_projection` instead would have agreed with
itself: the installer is what wrote both. Three of the five records share one
address and one SNI, so the path is the field that tells them apart, and the
require is "every dial is recorded" rather than set equality, because the Panel
keeps records no client dials. The probe reduces each record to the fields the
claim needs and reports a count, never a value.

**A representation is scanned for the values a client must never receive.**
`SUB-SERVED` reads the keys the product writes into its own environment files —
the Panel's `APP_SECRET` from `/opt/gowave/.env` and the Node's `SECRET_KEY` from
`/opt/gowave-node/.env`, both of which an All-in-One host carries — plus the
administrator's password from the credentials file the install wrote, and counts
each of them in every representation in four encodings — raw, base64, base64url
and URL-quoted — plus the decoded body of the base64 list, because a secret
inside a link is base64 twice. The count is per representation and the needles
are counted first: a scan with nothing to look for would report zero hits and
look like evidence. The private key is a separate question and a separate count,
because a Trojan `password` in a subscription is legitimate client material and a
name-based scan of key fields is what distinguishes the two.

**The database is read where the Panel writes it.** `AIO-FAULT-DISK` runs the
operator's `backup --type panel` against a store with no room left, and the claim
is that the failure publishes nothing and leaves the Panel's data alone. That
data is not a dump compared end to end: a running Panel writes its own rows — a
node heartbeat, a traffic sample, the rows a fresh process writes when it starts
— so the case reads every table and its row count before and after and requires
that no table and no row the database held is gone, then reads the client list
and the digest of all five representations through the Panel's API, which is the
same surface the channel cases use for their own database claim. The whole-dump
digest is reported as `database_dump_digest_changed` instead of asserted. The
first version compared the dump itself and failed run
`podman-aio-20261114T195129-29de0443` (`AIO-FAULT-DISK`, one table's rows moved
between the two reads, in a window that followed `AIO-RESTART`'s
`systemctl restart gowave.service`), although the failed backup had published
nothing: the case, not the product, was measuring the Panel's own writes.

**The engines are the same binaries, pinned differently.** Both suites validate
with the real Xray and Mihomo, and neither substitutes a parser for the engine:
`mihomo -t` and `xray run -test` are what accept a representation, and the
Python readers only count what the engines accepted. The container matrix pins
`xray` 26.11.9 and `mihomo` 1.19.34 with the artifact digest and sha256 of each
(`product.xray_client_version`, `product.mihomo_client_version`), because a
container image has to be reproducible from the tree; the live runner takes
`XRAY_CLIENT_VERSION` and `MIHOMO_CLIENT_VERSION` from
`tools/live_vps_config.env.example`, which reads `latest`, so the live side
follows the release. The shared contract is therefore "accepted by the real
engine", not "accepted by this exact build", and the container suite is the
place where a specific build is named.

### The version contract: a configured pin is read through its own binary

**A configured version is compared through the binary that reports it.** The
matrix declares all five versions a deployment configures —
`product.panel_version`, `product.node_version`, `product.xray_version`,
`product.xray_client_version` and `product.mihomo_client_version` — and the
install environment passes the first three to the product. Panel and Node read
`latest`, exactly as the live config's default does, and `latest` means "report
a version at all"; the Xray core is the exact pin, because the client core
below is the same build and a server core that drifted from it is the mismatch
this sentence names. The installed side is read through three distinct binaries
(`/opt/gowave/gowave-server` with `--version` or `version`, the node's own
`version`, and `/opt/gowave-node/rw-core version`) and the case refuses two
components interrogated through one binary, which is the sentence that a Node
version is not evidence of the core it supervises. A client core is read the
same way, through its own engine container's version argument. The rule that
turns an output into a version token is `tools/live_vps/versions.py`, imported
by both contours rather than restated: `26.11.90` does not satisfy a `26.11.9`
pin and `v1.19.34-linux` does satisfy a `1.19.34` one.

| Live scenario | Container case | Where the two differ |
| --- | --- | --- |
| `VER-01` a version mismatch detected after installation fails the install | `AIO-INSTALL`, `MN-INSTALL` | The live sentence pins `GOWAVE_PANEL_VERSION=1.2.3` and fails on the Panel's mismatch. The container can only make a component drift where the matrix pins it exactly, which is the Xray core; Panel and Node are held to "reports a version", because the matrix follows the channel for them the way the live config does. |
| `VER-02` a floating installer branch or an installer digest mismatch is rejected before installation | `AIO-NEG-PIN` | The live runner validates the pin in `tools/live_vps/config.py` before it opens an SSH session. The container asks the product's own `validate_node_installer_pin`, `pinned_node_installer_url` and `verify_node_installer_digest`, then calls `install_local_node` with a scratch `SCRIPT_DIR` so the pinned branch — not the bundled installer this workstation bind-mounts into `/repo` — is the branch refused, and requires the node binary and its unit to be byte-identical afterwards. |
| `VER-03` server and client Xray versions are independently pinned | the REALITY/xray tuple of each contour — the same tuple `DP-02` is observed through | The live runner records both versions in preflight and again after installation. The container compares them where they meet — the client engine's own version against the core the node reports it deployed — on every matrix tuple, and the install case carries the other half: the core is read through `rw-core` rather than through the node binary. |
| `DP-03` the clients are the cores Panel and Node deploy | the same REALITY/xray tuple of each contour | One engine container per run, read through its own version argument and required to carry the configured pin before it carries a payload; the deployed core is the Xray core the node supervises, so the equality is asserted on the Xray tuple only. Both sides of that equality are reduced by `tools/live_vps/versions.version_token`: a Worker reports its core as a whole sentence (`Xray 26.11.9 (Xray, Penetrates Everything.) 676eaf6 …`) while the install reads the Master's as the token alone, and comparing the two strings refused every Worker tuple until the shapes were normalised. |

### The data plane: the request budget and the Mihomo config

Two data-plane sentences are witnessable without a VPS, and both are read from
what the probe itself reports rather than from a stalled resolver or from a
second machine.

| Live scenario | Container case | Where the two differ |
| --- | --- | --- |
| `TRAFFIC_TIMEOUT` bounds every egress request | every matrix-driven data-plane case of both contours; `DP-02` is observed through the REALITY/xray tuple of each, and the catalog entry names that case | The live runner passes the budget to `curl --connect-timeout max(10, timeout // 2)` and `--max-time timeout` (`tools/live_vps/traffic.py:325`); the container probe carries the payload itself, so the same split is two facts per request — `connect_budget_seconds` and `transfer_budget_seconds` — read back from the transfer the case already made, and both are required on every tuple. |
| `Mihomo config preserves proxies and rules, assigns loopback listeners, refuses a non-loopback control endpoint` | every tuple the `mihomo` client runs; `DP-05` is observed through the REALITY/mihomo tuple of each contour, and the catalog entry names that case | The live runner rewrites the served YAML through `yaml.safe_load`; the client container has no PyYAML, so the probe edits top-level scalars textually and lets `scan_mihomo` remain the authority on what was preserved. Both assign collision-free loopback ports and pin the controller to `127.0.0.1` with `allow-lan: false`; the container probe invents no listener the Panel's document does not declare, so `socks-port`/`redir-port`/`tproxy-port` are rebound only where they are already present. |

### Packet evidence: a per-source account instead of an aggregate delta

The live capability's packet-evidence requirement is the one sentence in
`openspec/specs/live-vps-e2e/spec.md` that names the instrument: simultaneous
captures on both VPS, no matching ingress on the other host, the expected egress
address, missing evidence as INCOMPLETE, and an aggregate counter explicitly
refused as a PASS fallback. The live runner does it with `tcpdump -nn -i any -Q
in -l "tcp and dst port <port> and not dst port <ssh port>"` on each host
(`tools/live_vps/traffic.py`) and reads the client's address out of the target's
own `$SSH_CONNECTION`.

The container image is a deliberately clean VPS — no `tcpdump`, no `ss` — so the
instrument is the one thing this suite writes: `tools/podman_e2e/ingress_probe.py`,
started inside each host by `tools/podman_e2e/ingress.py`. It opens an
`AF_PACKET` socket per address family, filters on the proxy port the matrix
declares for the inbound, counts the segments per source address, and reports the
kernel's own drop counter (`PACKET_STATISTICS`) beside them. Nothing is written
to a file and no packet payload is kept: the summary is a JSON line on the pipe
the harness already holds, so a capture cannot leave a `.pcap` or a body behind
even if the case dies mid-transfer. `tests/test_podman_ingress.py` holds that as
a property of the source, not as a promise in this page.

The client's identity comes from the same shape the live runner reads: the target
reports the peer address of a TCP connection to port 22 as `/proc/net/tcp` holds
it, which is what `$SSH_CONNECTION` is on a real VPS. Port 22 is the product's own
sshd, allowed from any source, and — like the live filter's `not dst port <ssh
port>` — it cannot pollute a capture filtered on the proxy port.

| Live sentence | Where it is witnessed | How the container differs |
| --- | --- | --- |
| The intended host saw the request | `PKT-01`, observed through the Master's REALITY/xray tuple — the catalog entry names that case; `DP-04` in both contours | Same tuple, same port; the count is per source address rather than the live runner's delta of an aggregate counter across the request window. |
| No matching ingress on the other host | `PKT-01` (Multi-Node); `PKT-03` is the negative control — a Worker request whose payload, SNI and egress are all correct, judged as the Master's, which the Worker's own capture refuses | Only a cluster has an "other VPS". A single All-in-One host has no second place the traffic could have arrived, so `DP-07`/`DP-08` and `PKT-01`/`PKT-03` are witnessed on the Multi-Node contour and the All-in-One contour is absent by construction. |
| Missing evidence is INCOMPLETE, never a PASS | `PKT-02` (`AIO-PKT-02`) | Four degradations against a real request: no capture tool, no source-IP identity, a window that expired before the harness stopped it, and an identity channel that did not travel the request's path. The last is the container's NAT: the target reports the client's address from one vantage and captures the other, so a source that is counted is not the source the target named. Every one comes back INCOMPLETE with a reason. |
| Aggregate counters are not a fallback | `PKT-02`, plus the unit branch in `tests/test_podman_ingress.py` where a count exists and no attribution does | The tool-missing run is required to have counted nothing at all yet still be INCOMPLETE, which is the sentence in the only form a container can state it. |
| No PCAP or payload is persisted | the probe's source is audited for write-mode file opens, and `PKT-02` searches the hosts for a capture file after the four degradations | Same rule; the live runner keeps its captures in `/tmp` only for the length of the case, the container probe never creates one. |

The verdict is written as one record — `ingress_port`, `ingress_client`,
`ingress_intended`, the captured and matched counts for the intended and the
other host, the non-matching sources, and the reason whenever it is not PASS — so
a run that failed to arm a capture cannot be read as a run that saw nothing.

That record only reaches a reader when the tuple passed: the runner attaches
`evidence` to a PASS, and a case that fails keeps only the files it wrote. A
capture that did not decide in the product's favour is exactly that case, so the
measurement is also written as `evidence/<case id>-ingress.txt` whenever the
verdict is not PASS — each host's reported address, the summary its probe
printed, the identity report, and the request's own facts. The file is written by
the case, not by `ingress.py`: the probe still persists nothing, which is what
`tests/test_podman_ingress.py` holds.

### The report: what an overall PASS requires

`openspec/specs/live-vps-e2e/spec.md` §Result Status Semantics is the one
requirement whose subject is the report rather than a host: an overall `PASS`
requires every active Data Plane runtime case, a skip is non-passing, and each
failing case is identified individually in the machine-readable result. A report
is the one product surface this suite can produce with no VPS at all, so
`GATE-STATUS` (`tools/podman_e2e/status.py`) produces runs of the real `Runner`
over the case ids `tests/cases/matrix.yaml` declares — eight on one host, sixteen
to twenty on a cluster — with the outcomes chosen by raising the runner's own
exceptions, and reads the `result.json` and `junit.xml` back. The files it reads
are written by the same `write_result` and `write_junit` that write an acceptance
run's own report, which is what makes the case evidence rather than a second copy
of the aggregation.

| Live scenario | Container case | Where the two differ |
| --- | --- | --- |
| `Ingress evidence is ambiguous` | `AIO-PKT-02` | The live sentence is about a delta of listener counters that background traffic makes unattributable; the container refuses counters altogether and attributes each segment to the address the target itself reported, so the branch it exercises is the one that answers "every captured packet came from another address" — the NAT-like degradation — with `INCOMPLETE` and the non-matching sources recorded. The cluster contour asks the same question on every tuple rather than in a case of its own. |
| `Data Plane is explicitly disabled` | none yet — this scenario is left to 9.3 | The live runner has `TEST_TRAFFIC_VERIFICATION` to turn the Data Plane off; this suite has no switch that disables its subject. The aggregate it would read is asserted — a declared case recorded `SKIP` beside a passing one is not green — but the run the sentence describes cannot be produced here, so it is not claimed. |
| `One or more mandatory runtime cases fail` | `GATE-STATUS` | The case fails one tuple of the twenty a Vision-enabled cluster owes (eighteen on one host) and requires the aggregate to be `FAIL`, with that id named in `result.json`. |
| `PASS requires all active Data Plane runtime cases` | `GATE-STATUS` | Two of the runtime cases fail and the rest pass; the case requires overall `FAIL`, the two ids to be the only ones marked `FAIL`, and each message to name its own case. On a cluster that is the live sentence's fourteen of sixteen; on one host it is six of eight, and the topology explains the smaller number. |
| `Vision-enabled PASS requires all active runtime cases` | `GATE-STATUS` | One core and one Vision tuple fail; both are named in `result.json` and carried as a `<failure>` in `junit.xml`, which is all a CI reader sees. |
| `result.json schema fields present` | `GATE-STATUS` | The two reports answer the same questions under different names — see the mapping below. The case requires every field the container schema promises, and every field of every case in it. |

**One vocabulary, two spellings.** The live report names `test_run_id`,
`repository_commit`, `started_at`, `finished_at`, `control_machine`, `master`,
`worker`, `trust`, `results`, `traffic` and `overall`. This suite writes
`schema`, `run_id`, `topology`, `started`, `duration`, `budget_seconds`,
`environment`, `cases` and `overall`, and each case carries `id`, `topology`,
`status`, `duration`, `message`, `evidence` and `evidence_files`:

| Live field | Container field | Why it is not the same name |
| --- | --- | --- |
| `test_run_id` | `run_id`, `topology` | A run belongs to one topology here, so the topology travels beside the id instead of being implied. |
| `repository_commit` | `environment.repository.commit` and `.tree` | The tree state is recorded too: a run started on a dirty tree is evidence for the commit it started on, not for its contents. |
| `started_at`, `finished_at` | `started`, `duration` | The start and the window are recorded; the end is the sum, so a run that was killed before it wrote a finish time still has one. |
| `control_machine`, `master`, `worker`, `trust` | `environment` | The two hosts of a cluster run are containers this run started, and no ACME trust material is installed; the block carries what the run measured about its own environment instead. |
| `results` | `cases` | One entry per case, each with its own status and evidence. |
| `traffic` | the `*-DP-*` cases | Traffic is the Data Plane cases themselves rather than a second section about them. |
| `overall` | `overall` | The same string, computed by `overall_status`. |

**The vocabularies differ in two places.** The live runner's statuses are `PASS`,
`FAIL`, `SKIP`, `NOT_RUN`, `PARTIAL`, `INCOMPLETE` and `TEARDOWN_FAILED`; this
suite reports `BLOCKED` for a case whose prerequisite failed, `NOT_APPLICABLE`
for a case whose subject the environment does not contain, and has no partial or
teardown phase to name. `NOT_APPLICABLE` is not a skip: it says the subject was
absent, and a run that judged nothing with it is `INCOMPLETE` — but a pass beside
it stays green, which is the deliberate difference from the live runner's
treatment of `SKIP`. A `SKIP` in this suite means a declared case did not execute,
and the aggregate refuses it outright.

### The negative suite: the four sentences a container cannot own

`openspec/specs/live-vps-e2e/spec.md` §Negative Scenario and Fault Injection
Tests states a fifteen-row fault matrix and then two sentences about the suite
that runs it. The rows are witnessed one case per sentence — `PRE-01`, `PRE-02`,
`PRE-03`, `PRE-05`, `ADDR-01`, `AIO-NEG-ACME`, `NGX-05`, `MN-OUTAGE`,
`SUB-UA-ABSENT`, `MTLS-04` and `MN-BACKUP-BAD` among them, with the rows still
without a driver named by `python3 -m tools.podman_e2e.catalog gaps`. What no run
can own is the conjunction over the rows, and the live reporter's negative phase
and its `INCOMPLETE` verdict for a skip: those four entries are `partial`, and
this table states where the halves differ.

| Live scenario | Container case | Where the two differ |
| --- | --- | --- |
| `Matrix of fifteen fault scenarios verified (NEG-01..NEG-15)` | none — one case per row, as the rows land | The container witnesses each row where its fault happens and records the boundary it stopped at. "All 15 scenarios terminate at their designated boundaries" is a statement about the suite's case list, which `catalog gaps` and the divergence tables audit; no single case can read its siblings' verdicts. |
| `Preflight, lifecycle, and protocol scenarios verified (NEG-01..NEG-10)` | none — the ten rows' own cases | The ten rows are driven the same way, including the timeout bounds `MN-OUTAGE` records as `offline_seconds` and `control_plane_seconds`. The conjunction over them, and "within configured timeouts" as a whole-suite claim, are properties of the run rather than of one case. |
| `Negative suite PASS requires all fifteen scenarios to pass` | `GATE-STATUS` | The case drives the real `Runner` over declared ids and requires a non-PASS to keep the aggregate off `PASS`, naming each failing id. The live sentence names a `negative_tests` field, and the `NOT_RUN` and `PARTIAL` states, that this report does not have; and where it asks a skip to be `INCOMPLETE`, this aggregate turns a skipped declared case into `FAIL`. |
| `Negative suite cannot be silently skipped for a passing run` | `GATE-STATUS` | The case requires that a declared case recorded `SKIP` beside a passing one cannot be green, which is the load-bearing half. The negative phase the sentence names, and its `INCOMPLETE` verdict, are live-only: this suite has no switch that disables a phase, and its aggregate is deliberately stricter than the live reporter. |

### The pair-wide lock: one run, both hosts, and the lease that names them

`openspec/specs/live-vps-e2e/spec.md` §Pair-Wide Run Locking and §Shared Mutation
Lock Across All Management Entry Points state who may change a host: one run holds
both hosts for as long as it runs, a session that loses its holder stops mutating
instead of continuing unwatched, and a lock object that is not the regular file
the runner created — a symlink, a directory, a FIFO, a group-readable file,
another user's file — is refused before either host is modified rather than
followed, replaced or removed. None of that needs a VPS: a container runs the same
kernel that releases a `flock` when its holder dies, holds the same `/run/lock`
path and serves the same `/proc`, so `tools/podman_e2e/lock_cases.py` starts the
product's own lock-holder program (`LOCK_HOLDER_SCRIPT` in
`tools/live_vps/preflight.py`) inside each host of the pair and drives the
product's own `RemotePairLock` against it. What is real in these three cases is
the `flock`, the mode-0600 lease file carrying run id, host, holder pid and token,
the validator that reads it, and the `SIGTERM` that ends a holder the way a
dropped connection does; what is not is the transport — the SSH client is replaced
by one that runs the same command locally, and only the holder script's two
filesystem anchors are rewritten, so every refusal still names production's
`/run/lock`.

| Live scenario | Container case | Where the two differ |
| --- | --- | --- |
| `A second Control Machine cannot acquire an occupied VPS` | `MN-LOCK` | Two runners and two hosts are four local processes on one machine, so "another Control Machine" is an address and a lease rather than a second computer: the intruder is refused with the held path named, keeps no lease of its own, and the owner's two leases are compared byte for byte across the attempt. The sentence's own clause — that a lock file's mere existence is not ownership — is why the case then releases the pair and requires a fresh holder to take both hosts with different tokens, and the product's `validate_mutation_lease` to accept the new lease while refusing the released one. |
| `Loss of a remote lock-holder session fails closed` | `MN-LOCK-LOSS` | The loss is a `SIGTERM` to the holder's pid inside its container, which is what a dropped session leaves behind, and the pair is taken in address order so the surviving host is the second one: that is what makes the partial state observable. The case then reads the run's own gate — every mutating phase `INCOMPLETE` naming the phase and the lost lock, a read-only phase still reporting — and refuses to call a contender that wins the freed host and then releases it a resumed run. Reacquisition is proven by fresh tokens and the validator's refusal of the terminated holder's lease, not by a retry. |
| `Unsafe remote lock path is rejected` | `MN-LOCK-PATH` | Five object shapes are created on a real host filesystem — symlink, directory, FIFO, mode 0644, another owner's file — plus a symlinked lock directory, and each is refused by a sentence naming the host address and the object, with the object found unchanged afterwards and the pair-wide lock still free. The ownership shape needs `CAP_CHOWN` and the evidence says which of the two happened, so a runner that cannot create the file does not report the refusal it never read. Both hosts are cleared before every shape, because a leftover object on the other host would answer the sentence this iteration is about. |

**The entry-point half is not imported yet.** `MLOCK-01` (an ordinary
`gowave-auto.sh` command refused while the run owns the host) and `MLOCK-02` (a
run-bound lease on a nested command accepted while a second controller still
cannot take either host) name the management entrypoints rather than the lock
object, so they wait for the batch that drives those commands; the three cases
above prove the protocol they rest on, not those sentences.

### Teardown: the policy a run ends in

`openspec/specs/live-vps-e2e/spec.md` §Teardown Policy Enforcement is the one
requirement whose subject is the end of a run rather than its work: `PRESERVE`
records `PASS` without touching a host, `RESTORE_SNAPSHOT` hands a versioned
request to a digest-pinned external hook and may not be `PASS` until both hosts
are back on the manifest the run captured before it installed anything, and
`DESTROY` does not exist in v1. None of that needs a VPS — it is a configuration
file, a hook and a comparison — so `GATE-TEARDOWN`
(`tools/podman_e2e/teardown.py`) writes a real mode-0600 configuration, loads it
through the product's own `load_config` and drives `execute_teardown` with real
hook programs. The hook it pins is a Python program at a path a shell would split
into two commands, and it records the program name it was executed as, the
arguments it was given and the JSON it read from stdin: a hook that answers at
all is a hook that ran as a program, and the record is how the case knows.

| Live scenario | Container case | Where the two differ |
| --- | --- | --- |
| `Destroy policy rejected before the run starts` | `GATE-TEARDOWN` | The refusal happens while the configuration is being read, so no host object exists to reach: that is what "before any remote modification" means where there is no remote. The case also refuses an invented policy, and requires the message to name the value and the two policies v1 has. |
| `Preserve policy after success or failure` | `GATE-TEARDOWN` | The case hands in two SSH clients that raise on any attribute read, so a policy that reconnects to collect diagnostics cannot produce `PASS`. The record it returns is asserted to carry the teardown status alone — this contour keeps the test outcome in its own `result.json`, so a teardown record that restated it would be the coupling the sentence refuses. |
| `Snapshot restore hook configuration and protocol are validated` | `GATE-TEARDOWN` | Eleven refusals, each with its own message: four mandatory values, a relative path, a symlink, a directory, an absent file, a non-executable hook, a group-writable one and a malformed digest. The foreign-owned hook is probed only where the runner can create one, and the evidence says which of the two happened. The digest's second check is the tampering clause: the same configuration is accepted, the hook's bytes change, and execution refuses it. |
| `Restore hook receives a versioned request and returns both restored resources` | `GATE-TEARDOWN` | The request is read out of the hook's own record rather than from a mock, so `schema_version`, `action`, `test_run_id` and the per-host objects are what the hook was handed. The replies that are not a restored host — no version, a later version, no host object, a host unrestored, an id the run did not ask for — are refused beside it. `RESTORE_TIMEOUT` is the bound the configuration declares: a hook that outlives a one-second bound is refused at one second. |
| `Snapshot restore hook success requires baseline verification` | `GATE-TEARDOWN` | Two matching manifests report the comparison as `MATCHED` and the status as `INCOMPLETE`, never `PASS`, because the teardown phase does not reacquire the pair lock and the complete ownership comparison is still unimplemented; one differing field is `TEARDOWN_FAILED` and names the field. What the case cannot do is recollect the manifest from a restored host, so the two manifests are supplied to the product's own comparison rather than read over SSH. |
| `Snapshot restore hook does not restore both hosts` | `GATE-TEARDOWN` | A nonzero exit, a non-JSON answer, JSON that is not an object, a call that outlives the bound, and a host that came back with the install still on it are each `TEARDOWN_FAILED`. The last clause writes the live reporter's `junit.xml` — the contour that owns this status — and requires the failure to appear as a JUnit `<error>` beside a passing acceptance case, so no reader of the report can take the run for green. |
| `Snapshot restore reacquires the remote lock pair before baseline verification` | `MN-LOCK-LOSS` | The ordering is read on two real containers, one clause at a time: the pair is taken in the sorted address order rather than the order the caller passed it, a contender refused on the second host leaves the first free, a terminated holder session stops every mutating phase as `INCOMPLETE` while read-only phases still answer, the release is confirmed on both hosts before the replacement pair is taken, and the reacquired pair publishes a fresh token whose lost predecessor the product's own validator refuses. What the case cannot do is join that ordering to a snapshot restore: the hook's reboot has not happened, so the restore half stays the live run's. |

**One scenario of that requirement stays live-only.** `TD-05` is `partial`: the
ordering it asks for after a restore — release every original holder, including a
surviving one, then reacquire the pair in address order and refuse to hold half of
it — is what `MN-LOCK-LOSS` proves on two real hosts, while the case that would
join that ordering to a snapshot restore needs the hook's reboot to have happened,
which a container cannot produce, so the scenario stays partial and the live run
keeps the restore half. `TD-06` needs a provider snapshot and a real reboot for
the same reason, and is the one scenario of the requirement this suite does not
drive at all.
`TEARDOWN_FAILED` is not in this suite's vocabulary for the same reason the
report section gives: a container run has no teardown phase to name.

### Vision: two optional domains, and which host owes the gate

`openspec/specs/live-vps-e2e/spec.md` §Independent Optional Vision Domains is
eight scenarios over two optional fields, and most of what it states is already
witnessed here: per-node counts and hosts by `CLUS-01` and `CLUS-03`, each node's
certificate, route and absence by `MN-VISION`, and the stream route to
`127.0.0.1:8444` with its PROXY-only decoy on `127.0.0.1:9444` by `NGX-04`. What
those could not witness is the two sentences decided *before* a packet leaves the
control machine: that the two fields are configured independently and that every
configured name differs from every other name the run carries, and that only the
host whose own Vision domain is configured owes the Vision ports. Both are
decided by code this suite runs — the live runner's whitelist parser
(`tools/live_vps/config.py::load_config`) and its eligibility decision
(`tools/test_live_vps.py::evaluate_preflight_eligibility`) — so
`tools/podman_e2e/vision.py` writes real mode-0600 configuration files and hands
two real host manifests to those two functions. Neither case starts a container:
a refusal that needs a VPS to be observed is not the refusal the sentence
describes.

The counts those sentences imply are read back where they are declared. `NGX-04`
now asserts, beside its route on both contours, that each node's declared inbound
count is the combination's own arithmetic, that the Panel publishes exactly one
host per inbound for that node, that no published host names an inbound its node
does not run, and that the matrix owes its runtime cases as that total times the
clients it declares. `MN-VISION` closes the other end: the deployment's own names
and addresses are written as a configuration document and read back through the
parser, and the total the parsed answer produces has to equal the total the Panel
declares across its nodes — so a parser that dropped an optional field and a
Panel that declared the wrong count cannot both be true.

| Live scenario | Container case | Where the two differ |
| --- | --- | --- |
| `Master-only Vision configuration` | `MN-VISION` | One node's own configuration, read by the same case that asks it of the Worker: the Master declares exactly one Vision inbound and one host under its own name and the Worker has neither, in the combination where only the Master was configured. The requirement is a cluster requirement, so no single-container run carries this case. |
| `Worker-only Vision configuration` | `MN-VISION` | The same case in the combination where only the Worker was configured, which is the one that fails if the two nodes' fields are read from one switch. |
| `Both Vision domains are configured` | `NGX-04` | The route, the decoy and the fallback are read per host, and the endpoint arithmetic is asserted beside them: five inbounds and five published hosts per node, ten in all, and the matrix's runtime count as that total times its clients. |
| `Vision domains are unique` | `VIS-CONFIG` | Four accepted combinations — neither, Master only, Worker only, both — and eight duplicate classes refused, each naming what collided: the two Vision names equal, a Vision name repeating any of the four mandatory names, the two nodes' Vision names equal to each other's mandatory names, and the same name in two letter cases. The runner itself is run on the same duplicate and has to exit reporting a configuration error without creating a run directory, because that is what "before SSH or remote modification" means where there is no remote yet. |
| `Vision certificate failure aborts the relevant host installation` | `VIS-05` | The fault is a second install of the host the first one already provisioned, asking for a name the fixture resolver answers with `NXDOMAIN`: HTTP-01 cannot validate, so the Vision stage is the one that fails. The install exits nonzero and prints the lineage rollback line rather than a `CRITICAL` one, and the digests of the Panel and REALITY lineages, the deploy hook and its ownership record, the stream map, the HTTP vhost, the `9444` fallback vhost and the bootstrap vhost are identical before and after — so the rollback deleted nothing it did not create, and the failed name is mentioned nowhere under the NGINX tree. The install the later cases read is untouched because the fault runs on a host that is already installed. |
| `Vision disabled preserves the four-inbound topology` | `MN-VISION` | The absent branch of the same case: with both fields empty each node declares exactly four inbounds and four hosts, holds no certificate for the name, routes nothing and has no vhost, so a node that kept its neighbour's contour fails. |
| `Vision port gate applies only to the Vision-enabled host` | `VIS-GATE` | Which host is refused is read from the runner's own decision over two manifests. With both hosts holding `8444` and `9444` the configured one is refused naming the port and the unconfigured one is accepted, the reverse holds for the other combination, and a run in which only the unconfigured host holds them reports `PASS` — the clause a gate widened to the whole run would fail. The exempt host is still held to the default port set, so it is refused when it holds `443`. |
| `Incomplete Vision compensation is reported, not hidden` | `VIS-06` | Two faults at once, neither in the code under test. The first is a second `node add` of the Worker the earlier cases already provisioned, naming a Vision domain the fixture resolver answers with `NXDOMAIN`: the stage that runs last on the Worker — `Acquiring Let's Encrypt TLS certificate for Vision (...)` — fails after that node's own and REALITY lineages exist. The Panel holds one node per address, so that second record reaches the same host through an address the case adds to the Worker's interface and pins the Worker's existing host key under. The second fault is a detached watcher on the Master that empties the journal's `entities` once `state` reaches `NODE_ADD_VERIFYING`, so `rollback_provisioning` refuses to enumerate and returns `False`. The install then exits nonzero and prints the remote-failure line, the refusal text, the API-rollback `CRITICAL` line and the aggregate `CRITICAL: Rollback failed for Worker 'worker-2'; recovery journal retained.` — and neither the success line nor the remote-rollback `CRITICAL`, because the remote half is the one that succeeded. The journal survives with `state = NODE_ADD_ROLLBACK_REQUIRED` and its `rollback_error` holding the refusal, and the Panel still lists three nodes with the new one at the address the case gave it and the Worker's port: what the requirement forbids is reporting cleanup `PASS`, not leaving the journal behind. The case runs last but one because its compensation removes the Worker the earlier cases read. Not exercised: the branch where the *remote* rollback is the one that fails. |

### What is declared but not driven

`PATCH /api/users` and `PATCH /api/users/{userId}` update an existing client,
and no case calls them: the lifecycle cases create a client, read its
subscription and delete it, and never edit it. That is a **coverage gap** in this
suite, not a `NOT_APPLICABLE`: the pinned API does support the update, so
recording it as unsupported would be inventing an absence. `GET
/api/sub/{shortUuid}/info` is in the same position — declared by the Panel and
fetched by no case.

No operation this change names needed a `NOT_APPLICABLE` entry.
Authentication, node registration, client creation and deletion, the
configuration update and every subscription representation the manifest declares
are all present in the pinned API and mapped above, so every route the suite
depends on has a declaration to point at.

## What the suite reuses, and what it must not duplicate

The acceptance suite is assembled from contours and fixtures that were already
in this repository, and one rule separates them: a fixture may stand in for
something outside the product — a resolver, an ACME directory, an upstream site,
a client device — and may never stand in for the product itself. The contours
below therefore say what each one proves and, in the second column that matters
more, what it must not be quoted as proving.

| Contour | What it proves | What it must not claim |
| --- | --- | --- |
| `tests/podman_testbed.sh` | eight stages per base image from `tests/Containerfile.testbed`, all inside a `--systemd=always --privileged` container: `check_os`, `detect_nginx_version`, `check_port_availability 80 443`, systemd readiness, `test_api_client.py`, `test_nginx_routing.py`, `test_services.py`, and a `modules/recovery.py --validate-journal` round trip | a product install: it sources `modules/*.sh` and runs unit modules in an image that already carries systemd, SSH and python3, and the product is never invoked |
| `tests/multi_node_testbed.sh` | real SSH between three containers, TLS 1.3 mTLS on `rw-v1`, and TCP `:3002` reachable only from the source it allows | Panel or Node installation and subscription delivery — its own header says it "deliberately does not claim to install GoWave Panel/Node or validate subscriptions", and that sentence is the scope |
| `tests/systemd/boot.sh` | `tests/run_ci.py --suite systemd` inside the guest, under a real systemd PID 1 on all four base images, booted from a `Containerfile.testbed` rootfs | an operator install; `qemu-cold-boot` never runs `gowave-auto.sh install`, which is the split §The OS matrix describes |
| `.github/workflows/podman-acceptance.yml` | the product install, the traffic plane, the five representations and the recovery contract, as four jobs — two topologies × {plain, `--require-group recovery`} | the transport scaffold's claims, and any row other than `ubuntu-24.04` |
| `.github/workflows/systemd-acceptance.yml` | four jobs that are not an install: `services` and the static `systemd` unit contracts on the runner, `multi-node-podman` running the transport scaffold, and `qemu-cold-boot` booting all four images | a product install: none of the four invokes the installer, which is what `qemu-cold-boot` is checked against |
| `.github/workflows/lint-and-nonroot.yml` | `--check-completeness` then `--suite nonroot` on a runner that installs nothing | acceptance: no container is started |
| `.github/workflows/root-integration.yml` | `--suite root` with sudo, then `--suite integration` without | acceptance, for the same reason |
| `.github/workflows/live-vps-unit.yml` | the live runner's unit tests | the live suite: nothing in this job reaches a VPS |

The fixtures are pinned so that a case can never report "the resolver answered
wrongly" about a resolver that was swapped underneath it:

| Fixture | Stands in for | Pinned by | Consumed by |
| --- | --- | --- | --- |
| `ubuntu-24.04`, `ubuntu-26.04`, `debian-12`, `debian-13` | the operator's VPS | role `base`: one manifest digest per row in `tests/cases/images.lock.yaml`, resolved to `repository@sha256:…` before Podman runs | every case; `AIO-INSTALL` records the digest and the `assert_clean` fact set |
| `acme-pebble` (`ghcr.io/letsencrypt/pebble:2.10.3`) and `tests/fixtures/acme/pebble-config.json` | the Let's Encrypt directory | role `acme-fixture`: digest in the lock, config template copied into the run's own directory at mode `0600`, fixture CA mounted read-only | `ACME-01`, `ACME-02`, and the first certificate the install obtains |
| `fixture-echo` (`docker.io/library/python:3.12-slim`) running `tests/fixtures/echo_server.py` | an upstream site and an egress peer | role `egress-fixture`: digest in the lock plus a per-run source allowlist, so only the vantage under test is answered | the egress and decoy cases |
| `client-base` (`docker.io/library/python:3.12-slim`) built from `tests/Containerfile.client` through `tests/install_client_artifact.py` | the client devices | role `client-base`: digest for the base, SHA-256 for each release artifact, and the version the binary prints for itself (`Xray 26.11.9`, `v1.19.34`) | `SUB-SERVED`, `SUB-B64`, `SUB-JSON-SHAPES` and the data-plane cases that dial from the client |
| `tests/fixtures/dns_server.py` | authoritative DNS for `testbed.internal` | its own container from the `fixture-echo` alias at the run's `dns_ip`, with the zone in a writable volume; the script never forwards and never reads `/etc/resolv.conf` | `DNS-01` and every case that resolves a hostname |

**What the suite does not reimplement.** The target image
(`tests/Containerfile.target`) installs no package the product is responsible
for: `target_image.PRODUCT_PACKAGES` is that list, `assert_clean` reads
`dpkg-query` for every entry of it, and a case that finds one fails before the
install runs. The install itself is `bash /repo/gowave-auto.sh install '<panel
domain> …'`, rendered by `Topology.install_script`, so the suite drives the
same entrypoint an operator does. It writes none of the configuration the
product is supposed to generate, with one deliberate exception: `NGX-05` drops
`/etc/nginx/conf.d/zz-gowave-e2e-broken.conf`, a snippet carrying the unknown
directive `gowave_e2e_broken_probe`, because an invalid file in a directory
NGINX reads is how the case proves that the reload gate refuses what `nginx -t`
rejects. The file is the probe, not a second configuration. The legacy image is
kept for the legacy contours and not shared: `tests/Containerfile.testbed` bakes
systemd, SSH and python3 into the image, which is the opposite of what an
install test needs, so the acceptance suite builds `Containerfile.target` and
`Containerfile.client` and nothing under `tools/podman_e2e/` names the testbed
image.

## Where Podman stops, where QEMU starts, and what only a VPS can answer

`tests/cases/catalog.yaml` defines each scenario once and stamps it with an
`environment`, so the boundary between the contours is a checked field rather
than a sentence in a document. The catalog holds 251 entries:

| Environment | Entries | Which contour answers it |
| --- | ---: | --- |
| `container` | 237 | A rootful Podman run on a pinned image, because nothing in the case needs a provider, a reboot or a public address. The run executes the subset its gates select, and an entry whose driver is still planned appears in no `result.json` case list — `python3 -m tools.podman_e2e.catalog gaps` keeps that visible rather than letting it read as a pass. |
| `partial` | 12 | Both: the container half runs here against a fixture, and the live half stays in `live-vps-e2e`. The sentence that splits each one is generated from the catalog into `tests/cases/PARITY.md` (§Partial splits), not copied into this page. |
| `live-only` | 2 | Only the live suite. Every Podman run prints both as justified exclusions and records them in `result.json` as `environment.justified_exclusions`, each carrying the catalog's own limitation; `tools/podman_e2e/catalog.py` refuses a catalog that lets one run here, or that leaves one without a written reason. |

Of the 125 live scenarios projected into this catalog, 111 are container, 12 are
partial and 2 are live-only; the other 126 entries are Podman-first cases with a
promotion target, which `tests/cases/PARITY.md` lists separately. That file also
answers per scenario rather than per group: one row names the live scenario, the
catalog case that covers it, the environment classification and the gate that
blocks on it, and `catalog check` refuses the file when it is not the text the
catalog renders to, so a scenario added without a row cannot pass as published.

The fourteen entries that are not fully container-answerable are, by id:
`PRE-04`, `FW-03`, `DP-09`, `DP-10`, `DP-11`, `TD-05`, `BOOT-01`, `BOOT-02`,
`NEG-01`, `NEG-04`, `NEG-07`, `NEG-08` (partial) and `TD-06`, `LOCAL-02`
(live-only). Their reasons are not restated here: `tests/cases/PARITY.md` is
regenerated from the catalog, and the guard on this page compares both lists, so
an id that changes section in the catalog has to change here as well.

The QEMU contour answers a question none of those entries ask: whether the
units the product writes survive a real cold boot under a genuine systemd PID 1.
`tests/systemd/boot.sh` builds a rootfs from `tests/Containerfile.testbed` for
all four base images, boots it with QEMU (KVM when available, TCG otherwise),
and the guest's own `gowave-ci.service` runs `python3 tests/run_ci.py --suite
systemd`. That suite is eight tests and installs nothing: seven of them read
files — the unit templates in `modules/panel.sh` and `modules/security.sh`, the
install and uninstall blocks that arm and remove the Panel's update helper in
`gowave-auto.sh`, and `tests/systemd/boot.sh` itself for executability and the
four-image/KVM matrix — and `test_guest_genuine_pid1_when_in_vm` reads
`/proc/1/comm` and `systemctl is-system-running` from inside the guest. No
`gowave-auto.sh install` runs there, no traffic flows, no subscription is
fetched, and the contour carries no catalog case id at all: it is a check that
the units are accepted, not a scenario of the product. What it cannot answer is
therefore not a gap in the cases — a container with `--systemd=always` runs a
systemd as PID 1 that belongs to the container, and the cold boot is what
removes that difference.

What only a VPS can answer is the live half of the eight partial entries plus
the two live-only ones: provider-level reachability, real public addresses and
real Let's Encrypt issuance, a provider snapshot followed by a reboot, the live
controller's public-target bootstrap, and the operator starting a run against
real disposable hosts. `openspec/specs/live-vps-e2e/spec.md` owns those, and the
shared contracts — subscription delivery, User-Agent policy, Vision
independence, firewall evidence rules, redaction, result semantics — are
asserted in both suites from one text. A container run that reported a
live-only id as PASS, or presented a partial id's container half as the whole
scenario, would be claiming evidence it never produced; the catalog and
`python3 -m tools.podman_e2e.catalog check` make that unrepresentable.

## The contracts both contours assert, and the one owner each has

The two acceptance contours differ in environment, not in product. Where a
contract is shared, it has exactly one owner and both suites read it; a
container-only variant of a shared contract is a divergence, and this change
fixed the two such divergences it found rather than keeping them apart.

| Shared contract | Owner | Live assertion | Container assertion |
| --- | --- | --- | --- |
| Subscription path vocabulary | `tests/cases/matrix.yaml` `representations`, `internal/server/server.go` | `tools/live_vps/subscriptions.py` | `SUB-SERVED`, `SUB-B64` |
| User-Agent refusal code | `internal/subscription/serve.go` | `tools/live_vps/subscriptions.py` `SUBSCRIPTION_UA_REFUSAL_STATUS` | `tools/podman_e2e/aio.py` `UA_REFUSAL_STATUS`, `SUB-UA-ABSENT`, `SUB-UA-BLANK` |
| REALITY fingerprint vocabulary | `modules/api_client.py` `REALITY_FINGERPRINTS` | `tools/live_vps/config.py` | `SUB-SERVED`, `tests/cases/matrix.yaml` `host_record` |
| `Cache-Control: no-store` on `/api/sub/` | `modules/nginx.sh` | `openspec/specs/live-vps-e2e/spec.md` | `SUB-SERVED` |

**The refusal code was the divergence that mattered.** The live runner accepted
`400` or `403` for a missing and for an explicitly blank User-Agent, while the
container case requires exactly `403` (`UA_REFUSAL_STATUS`). The pinned Panel
answers `403` — `internal/subscription/serve.go` sends it when the header is
absent or empty, and the Panel's own test asserts that body — so the tolerance
did not describe a second product, it excused a Panel that had started
answering `400`. That is a weaker claim about one product made by one contour,
which is what this task forbids: the live runner now compares against
`SUBSCRIPTION_UA_REFUSAL_STATUS` in `verify_user_agent_policy` and in `NEG-09`.

**The fingerprint vocabulary had two copies.** `tools/live_vps/config.py`
restated the ten uTLS presets that `modules/api_client.py` already declares, and
both files spelled the `firefox` default. The live config now imports the tuple
and the default, so the live runner cannot accept a preset the Host record it
provisions cannot mint; the two `reality_fingerprint` defaults in
`tools/live_vps/subscriptions.py` read the same constant.

**Where the vocabulary is legitimately wider here.** The live runner dials three
representations (`/v2ray-json`, `/clash`, `/mihomo`); the container matrix
declares five, and `base64` and `singbox` are driven only by this contour —
`singbox` with no pinned client, as recorded above. That is a superset, not a
divergence: both name the same paths for the three they share, which is what
`tests/test_podman_docs.py` checks rather than comparing counts.

**The engine pinning is the divergence that stays recorded.** Both suites
validate with the real Xray and Mihomo and neither substitutes a parser, but
this contour pins `26.11.9`/`1.19.34` while the live runner reads `latest`; the
shared contract is "accepted by the real engine", and the pinned build is named
only where a run has to be reproducible. It is recorded in §The live contract,
capability by capability instead of being resolved by weakening either side.

## How the Master's own command line is observed

Three of those contracts assert a negative — that the Worker deployment never
puts `SECRET_KEY` in a process argument — and a container answers them by
tracing the command an operator runs rather than a reconstruction of it.
`WRK-01`, `WRK-02` and `WRK-03` are observed by `MN-ARGV-OBSERVER` in the
Multi-Node contour, and `tests/cases/catalog.yaml` records that as an observer on
those three entries rather than as a second driver: one deployment per run, one
trace, three assertions.

The trace is taken inside the Master container, wrapped around
`bash /repo/gowave-auto.sh node add '<worker>' …` — the same dispatch `WRK-04`
then judges — as `strace -f -v -s 131072 -e trace=execve,execveat -o
/run/gowave_e2e_strace/node_add.trace`, where `131072` is
`32 * os.sysconf("SC_PAGE_SIZE")` read from the Master, so the limit follows the
host's page size instead of a constant. `strace` is installed at run time in the
Master for the same reason it is installed on a VPS: the target image is built
clean, `target_image.PRODUCT_PACKAGES` refuses a package the product is
responsible for, and the observer must not become an installed part of the image
under test. A Master where `strace` cannot be installed is not a failed
deployment: `node add` runs untraced, the facts say so, `MN-ARGV-OBSERVER` fails
and `WRK-04` still judges what the deployment produced.

Dropping the trace of an earlier dispatch belongs to the dispatch, not to the
directory: the case delivers the probe into that same directory *after* the
deployment has written its trace, so a preparation step that also cleared "an
earlier trace" would delete the file the case reads. That is what the first live
run of this case reported — `the dispatch trace is INCOMPLETE: ['the trace file
is absent, so nothing was observed']` — while `WRK-04` passed on the same
deployment, whose dispatch therefore ran under the prefix and opened its trace;
the delivery that ran between them was the only step removing that path, which
is why the preparation and the reset are separate functions.

Before the trace is read, acceptance legs have to show that the observer can see
what it claims to see: a sentinel placed after byte 32 of an argument, once
through `execve` and once through `execveat` — the latter produced with ctypes,
because no shell builtin reaches it — and 128 arguments with a sentinel only in
the last one. A third leg is the control: the same argument under a deliberately
32-byte `-s` must come back cut, so an observation whose limit stopped working
cannot pass as complete. Only then is the trace scanned, and the scan reads argv
vectors alone: `-v` also prints `envp`, and the raw environment is discarded
rather than reported.

The scan rejoins records that `-f` split across `<unfinished ...>` and
`<... execve resumed>` lines, because dropping either half would hide an exec,
and it decodes strace's octal escapes before looking for the secret, because a
value containing a quote or a backslash is invisible to a text search. The
client whose exec record has to be present is the one `command -v` resolves on
the Master — `basename "$(command -v ssh)"` — so a host that names its client
differently is still observed rather than reported as a trace that missed the
deployment. The secret itself is read through the product's own
`modules/node.sh:extract_secret_key` on the Master and handed to the scanner on
`stdin`; the probe source is streamed over `stdin` as well, only counts come
back, and the trace file is removed inside the container before the verdict is
printed.

**What this does not observe.** The trace covers the Master-side descendant
process tree, including the local SSH client; the Worker's processes beyond the
SSH boundary are not traced, which the owning requirement states in the same
words (`openspec/specs/live-vps-e2e/spec.md`, §Distributed Worker VPS Deployment
Verification). It says nothing about `envp`, by design — the contract is about
arguments. And it observes the one deployment the run makes: the observer is
wrapped around the dispatch `WRK-04` depends on, so a second `node add` in the
same run would not be traced.

## What the suite does not drive, and why

Six entrypoints are not invoked by a container case, for two different reasons,
and keeping them apart is the point of this page. `status` and `health` report
facts the cases assert from their source — `AIO-04` reads the unit states, the
open sockets and the in-panel update helper's own files, `AIO-01` calls the
Panel API from the client — so invoking the summary would test the summary, and
`user links` prints links that `AIO-CLIENT` fetches over the authenticated API,
which is the path a real client uses.
`uninstall`, `node list` and `node rollback` have no container case at all;
their absence is recorded here so that a future parity review sees a gap rather
than a coverage claim.

Acceptance boundaries that are not container cases are divided in §Where
Podman stops, where QEMU starts, and what only a VPS can answer above, and
restated in `openspec/changes/podman-full-e2e/design.md` (§Scope boundary): the
QEMU cold-boot matrix and the live VPS capability answer questions a disposable
container cannot, and neither is a substitute for the other. The operator-facing
guide `docs/PODMAN_E2E.md` describes the invocations themselves.
