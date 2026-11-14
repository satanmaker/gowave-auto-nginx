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

Those two lines are the product's own `Usage:` text (`gowave-auto.sh:1482` and
`gowave-auto.sh:1154`), not a summary. Each entrypoint below names the cases
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

Both topologies run on the same four pinned distributions; the next section
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
| authentication | `POST /api/auth/register` | `internal/server/server.go:514` | `modules/api_client.py:273` `register_initial_admin` |
| authentication | `POST /api/auth/login` | `internal/server/server.go:513` | `modules/api_client.py:285` `login` |
| authentication | `POST /api/tokens` | `internal/server/server.go:534` | `modules/api_client.py:764` `issue_api_token` |
| authentication | `GET /api/tokens` | `internal/server/server.go:533` | `modules/api_client.py:788` `ensure_api_token` |
| authentication | `DELETE /api/tokens/{uuid}` | `internal/server/server.go:535` | `modules/api_client.py:773` `delete_token` |

**Node registration.** The node record and its REALITY key material are made
through the Panel, which is why `AIO-INSTALL`, `AIO-IDEMPOTENT` and `MN-INSTALL`
are the cases that exercise this area: an AIO install registers its local node,
and a Multi-Node Master registers each Worker over the same route before it
provisions the Worker.

| Area | Endpoint | Declared at | Client caller |
| --- | --- | --- | --- |
| node registration | `GET /api/system/tools/x25519/generate` | `internal/stubs/stubs.go:218` | `modules/api_client.py:296` `generate_x25519` |
| node registration | `GET /api/nodes` | `internal/server/server.go:590` | `modules/api_client.py:515` `associate_node` |
| node registration | `POST /api/nodes` | `internal/server/server.go:593` | `modules/api_client.py:553` `associate_node` |
| node registration | `PATCH /api/nodes/{uuid}` | `internal/server/server.go:599` | `modules/api_client.py:523` `associate_node` |
| node registration | `DELETE /api/nodes/{uuid}` | `internal/server/server.go:600` | `modules/api_client.py:826` `delete_node` |

**Provisioning.** Hosts, internal squads and config profiles are the Panel
objects an install creates before a client can be served: the host record links
the public domain to the node, the squad decides which inbounds a user's
subscription carries, and the profile is what the node renders its Xray config
from. `AIO-INSTALL` and `MN-INSTALL` create them; the rollback cases
(`AIO-CHANNEL-ROLLBACK`, `AIO-INTERRUPT`) are what walk the same routes backwards
through `rollback_provisioning`.

| Area | Endpoint | Declared at | Client caller |
| --- | --- | --- | --- |
| provisioning | `GET /api/hosts` | `internal/server/server.go:612` | `modules/api_client.py:646` `provision_hosts` |
| provisioning | `POST /api/hosts` | `internal/server/server.go:613` | `modules/api_client.py:712` `provision_hosts` |
| provisioning | `PATCH /api/hosts` | `internal/server/server.go:615` | `modules/api_client.py:709` `provision_hosts` |
| provisioning | `DELETE /api/hosts/{uuid}` | `internal/server/server.go:616` | `modules/api_client.py:810` `delete_host` |
| provisioning | `GET /api/internal-squads` | `internal/server/server.go:638` | `modules/api_client.py:562` `provision_internal_squad` |
| provisioning | `POST /api/internal-squads` | `internal/server/server.go:639` | `modules/api_client.py:581` `provision_internal_squad` |
| provisioning | `PATCH /api/internal-squads` | `internal/server/server.go:641` | `modules/api_client.py:578` `provision_internal_squad` |
| provisioning | `DELETE /api/internal-squads/{uuid}` | `internal/server/server.go:642` | `modules/api_client.py:818` `delete_internal_squad` |
| provisioning | `GET /api/config-profiles` | `internal/server/server.go:628` | `modules/api_client.py:448` `provision_config_profile` |
| provisioning | `POST /api/config-profiles` | `internal/server/server.go:629` | `modules/api_client.py:470` `provision_config_profile` |
| provisioning | `PATCH /api/config-profiles/{uuid}` | `internal/server/server.go:632` | `modules/api_client.py:466` `provision_config_profile` |
| provisioning | `DELETE /api/config-profiles/{uuid}` | `internal/server/server.go:633` | `modules/api_client.py:834` `delete_config_profile` |
| provisioning | `GET /api/config-profiles/{uuid}/inbounds` | `internal/server/server.go:635` | `modules/api_client.py:493` `provision_config_profile` |
| provisioning | `GET /api/config-profiles/{uuid}/computed-config` | `internal/server/server.go:636` | `modules/api_client.py:476` `provision_config_profile` |

**Client lifecycle.** A client is a Panel user with a subscription: `AIO-CLIENT`
creates one and fetches its links, `AIO-REVOKE` and `MN-REVOKE` delete one and
assert that its links stop being served. The user is looked up by name before
creation so that a second install adopts the client it made rather than
duplicating it.

| Area | Endpoint | Declared at | Client caller |
| --- | --- | --- | --- |
| client lifecycle | `POST /api/users` | `internal/server/server.go:554` | `modules/api_client.py:743` `provision_user` |
| client lifecycle | `GET /api/users/by-username/{username}` | `internal/server/server.go:581` | `modules/api_client.py:724` `provision_user` |
| client lifecycle | `DELETE /api/users/{userId}` | `internal/server/server.go:579` | `modules/api_client.py:802` `delete_user` |

**Update operations.** The pinned Panel exposes an update for every object an
install creates, and the suite drives the configuration one: the journal writes
back the profile, node, squad and host it changed when it rolls a failed
provisioning step back (`modules/api_client.py:1128`-`1134`), and
`provision_config_profile` patches an existing profile instead of replacing it.
API-04's `configuration update` is that path.

| Area | Endpoint | Declared at | Client caller |
| --- | --- | --- | --- |
| update | `PATCH /api/config-profiles/{uuid}` | `internal/server/server.go:632` | `modules/api_client.py:1128` `rollback_provisioning` |
| update | `PATCH /api/nodes/{uuid}` | `internal/server/server.go:599` | `modules/api_client.py:1130` `rollback_provisioning` |
| update | `PATCH /api/internal-squads` | `internal/server/server.go:641` | `modules/api_client.py:1132` `rollback_provisioning` |
| update | `PATCH /api/hosts` | `internal/server/server.go:615` | `modules/api_client.py:1134` `rollback_provisioning` |
| update | `PATCH /api/users` | `internal/server/server.go:555` | none — coverage gap, not `NOT_APPLICABLE` |
| update | `PATCH /api/users/{userId}` | `internal/server/server.go:578` | none — coverage gap, not `NOT_APPLICABLE` |

**Subscription contracts.** A subscription is fetched without a token, by short
UUID, so the route is the contract: one path per representation, the
non-base64 ones naming the representation as a path segment that the Panel maps
to a generator. The five representations are declared once, in
`tests/cases/matrix.yaml`: `base64` at `/api/sub/{shortUuid}`, `xray-json` at
`/v2ray-json`, `mihomo` at `/mihomo`, `clash` at `/clash` and `singbox` at
`/singbox`. The probe carries the client family and User-Agent for each
(`tools/podman_e2e/panel_surface.py:66`-`70`); `SUB-B64` is the case that checks
the base64 list an Xray-family client imports.

| Area | Endpoint | Declared at | Client caller |
| --- | --- | --- | --- |
| subscription | `GET /api/sub/{shortUuid}` | `internal/server/server.go:522` | `tools/podman_e2e/panel_surface.py:66` `base64` |
| subscription | `GET /api/sub/{shortUuid}/info` | `internal/server/server.go:523` | none — coverage gap |
| subscription | `GET /api/sub/{shortUuid}/{clientType}` | `internal/server/server.go:524` | `tools/podman_e2e/panel_surface.py:67` `xray-json` |

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
(`tools/podman_e2e/panel_surface.py:58`). It has to be served, and with the same
bytes: a refusal would mean the Panel requires a format rather than a header,
and different bytes would mean the header selects the representation and the
family headers were carrying the assertion. Neither is true of the pinned Panel,
and the suite would be inventing an allowlist if it assumed either.

### Which client family consumes which representation

The manifest's `clients` block says which pinned binary imports which
representation; this table says what the case that fetches it actually does with
the body. The order is the order the probe fetches them in
(`tools/podman_e2e/panel_surface.py:66`-`70`), and
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
| `Xray JSON subscription headers and content verified` | `SUB-SERVED`, `SUB-B64` | `SUB-SERVED` requires HTTP 200, the representation's media type and `Cache-Control: no-store`; `SUB-B64` decodes the link list and proves the Xray-family importer consumes it. The header is read through the public edge, because the Panel process itself sends none. |
| `Mihomo YAML subscription verified` | `SUB-SERVED` | Both require HTTP 200, a media type, one proxy per served inbound and `mihomo -t`. The live text also names the rule `GEOIP,private,DIRECT,no-resolve`; see below. |

**The one divergence that is prose, not behaviour.** The pinned Panel does not
emit `GEOIP,private,DIRECT,no-resolve`. Its Mihomo template carries
`GEOIP,LAN,DIRECT` followed by `MATCH,→ GoWave`
(`internal/database/default_data.go:108`), which is the same intent — keep
private destinations off the proxy — under the rule name that template uses.
The live runner accepts either family, a GEOIP rule or a MATCH rule
(`tools/live_vps/subscriptions.py:371`), and the container case asserts that a
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

## What the suite does not drive, and why

Six entrypoints are not invoked by a container case, for two different reasons,
and keeping them apart is the point of this page. `status` and `health` report
facts the cases assert from their source — `AIO-04` reads the unit states and
the open sockets, `AIO-01` calls the Panel API from the client — so invoking the
summary would test the summary, and `user links` prints links that `AIO-CLIENT`
fetches over the authenticated API, which is the path a real client uses.
`uninstall`, `node list` and `node rollback` have no container case at all;
their absence is recorded here so that a future parity review sees a gap rather
than a coverage claim.

Acceptance boundaries that are not container cases live in
`docs/PODMAN_E2E.md` and `openspec/changes/podman-full-e2e/design.md`
(§Scope boundary): the QEMU cold-boot matrix and the live VPS capability answer
questions a disposable container cannot, and neither is a substitute for the
other.
