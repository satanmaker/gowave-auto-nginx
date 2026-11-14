# Podman E2E: the product surface under test

The acceptance suite accepts the product's own operator interface, so this page
records that interface as the suite found it: which commands exist, which of
them run inside a container, and which topologies they are accepted in. It is
written for the reader who has to decide whether a case is missing because the
product cannot do the thing or because no one wrote the case yet.

The page is read back by `tests/test_podman_docs.py` (`TestDiscoveryInventory`),
which parses the usage lines out of `gowave-auto.sh`, the topologies out of
`tests/cases/matrix.yaml` and the case ids out of `tests/cases/catalog.yaml`.
A subcommand renamed in the product, a topology dropped from the manifest or a
case id this page invents fails the nonroot suite rather than being discovered
by a reader.

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
