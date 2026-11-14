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

Both topologies run on the same four pinned distributions, which is what makes
the OS matrix a property of the manifest rather than of a document.

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
(`tools/podman_e2e/panel_surface.py:63`-`67`); `SUB-B64` is the case that checks
the base64 list an Xray-family client imports.

| Area | Endpoint | Declared at | Client caller |
| --- | --- | --- | --- |
| subscription | `GET /api/sub/{shortUuid}` | `internal/server/server.go:522` | `tools/podman_e2e/panel_surface.py:63` `base64` |
| subscription | `GET /api/sub/{shortUuid}/info` | `internal/server/server.go:523` | none — coverage gap |
| subscription | `GET /api/sub/{shortUuid}/{clientType}` | `internal/server/server.go:524` | `tools/podman_e2e/panel_surface.py:64` `xray-json` |

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
(`tools/podman_e2e/panel_surface.py:63`-`67`), and
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
