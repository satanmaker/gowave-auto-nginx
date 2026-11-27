# Podman Product E2E

`tools/run_podman_e2e.py` runs the shipped installer and the shipped Node
orchestrator on disposable systemd hosts and reports every acceptance case as a
structured result. The hosts are containers on the workstation; the checkout is
mounted read-only at `/repo`, and each run owns its own networks, volumes and
containers. No live host, live credential or public DNS name is involved.

What the suite accepts — the product's operator entrypoints, its install modes,
the topologies and which of them a case actually invokes, and the Panel API the
product's own client and the probes are written to — is recorded in
`docs/PODMAN_E2E_DISCOVERY.md`, which is read back against `gowave-auto.sh`,
`modules/api_client.py`, the vendored Panel, `tests/cases/matrix.yaml` and
`tests/cases/catalog.yaml` by the nonroot suite.

## What a run builds

- One host (All-in-One) or two hosts (Master and Worker) booted as rootful
  Podman containers with systemd as PID 1.
- A private control network carrying a stub resolver, an ACME directory pinned
  to a fixture, the client containers and both probes.
- A second network whose addresses are read as public by the product, so egress
  and the public listener paths are exercised instead of short-circuited.
- A local ACME directory instead of Let's Encrypt, and a resolver that answers
  the run's own names from a fixture zone.

Both subnets are allocated at run time from a candidate range, because
`podman network create` fails when a candidate /24 overlaps a network the
workstation already has.

## Prerequisites

- Linux host with **rootful** Podman (`sudo`), cgroup v2, the netavark network
  backend, nftables and `iproute2`. Rootless Podman cannot bind 80/443 or read
  the host rule set back, so it cannot claim product acceptance.
- Python 3.12 and PyYAML (the catalog, the matrix and the image lock are YAML).
- `git` in the checkout: the run records the commit and tree state it measured,
  and a run started before a fix cannot contain it.
- Outbound network to the container registry and to GoWave's release endpoints:
  the operator install under test downloads its own release assets. A blocked
  or rate-limited GitHub makes `AIO-INSTALL` / `MN-INSTALL` red, and that is an
  external limit rather than a product defect.
- The command is a module, so run it from the repository root.

The host itself is checked with the fingerprint probe, which prints the facts a
run is only meaningful with and exits `1` when one of them is wrong (rootless
Podman, cgroup v1, an unpinned image lock):

```bash
sudo python3 -m tools.podman_e2e.environment
```

The product suite does not repeat that probe. It asserts nothing about the host
before spending the budget, so a rootless or cgroup-v1 machine shows up as a red
case rather than as a refusal; CI performs the same two assertions (`cgroup v2`,
`netavark`) as its own step before running the suite.

## Invocation

```bash
sudo python3 -m tools.run_podman_e2e --topology aio
sudo python3 -m tools.run_podman_e2e --topology multi-node
sudo python3 -m tools.run_podman_e2e --topology aio --distribution debian-13
sudo python3 -m tools.run_podman_e2e --topology multi-node --vision --worker-vision
sudo python3 -m tools.run_podman_e2e --topology aio --require-group recovery
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--topology` | `aio` | `aio` (one host), `multi-node` (Master and Worker) or `panel-only` (Panel and the static decoy, no traffic plane). |
| `--distribution` | `ubuntu-24.04` | Target alias from `tests/cases/images.lock.yaml`: `ubuntu-24.04`, `ubuntu-26.04`, `debian-12`, `debian-13`. |
| `--vision` | off | Install the optional VLESS Vision inbound. The positive-case count becomes 10 instead of 8 (AIO) or 18/20 instead of 16 (Multi-Node). Refused on `panel-only`, which has no traffic plane to terminate it. |
| `--worker-vision` | off | Configure the same optional inbound on the Multi-Node Worker. Refused on `aio`, which has no Worker, and on `panel-only`, which has no node. |
| `--artifact-root` | `artifacts/podman-e2e` | Directory the run's own run directory is created under. |
| `--budget-seconds` | the matrix's `runtime_budget_seconds`: `2700` (AIO), `6300` (Multi-Node), `4500` (Panel-only) | Wall-clock deadline for the whole suite. It may be lowered, never raised. On exhaustion the cases that did not run are reported `INCOMPLETE`, never dropped and never made green. |
| `--all-distributions` | off | Run the selected suite concurrently on all four pinned distributions, each in its own run directory; the exit status is `0` only if every cell passes and left a `PASS` result. |
| `--only CASE[,CASE...]` | every declared case | Run only the named cases, in the suite's declared order. An id the suite does not declare exits `2` before any container is created (also honoured by each cell of `--all-distributions`). |
| `--keep` | off | Leave the run's hosts, network, volumes and run directory in place and print the run id and how to reuse it. Nothing else about the verdict changes. |
| `--reuse RUN_ID` | — | Adopt a kept run instead of installing again. The per-run plan, fixture resolver and secrets live only in the memory of the process that made them, so a kept cell that no longer carries them is refused with the missing part named — never reinstalled under the name of reuse. A build that carries them records `reused: true` and the source run id in its own artifacts. |
| `--require-group` | — | Fail the run unless every case id of a declared group was present and passed. Today the only group is `recovery`. |

Exit status is `0` only when `result.json` says `overall: PASS`; every other
state exits `1`. Argument errors, including `--worker-vision` on the AIO
topology, `--vision` on Panel-only, an unknown group and a `--budget-seconds`
above the declared budget, exit `2` before any container is created.

`panel-only` drives the operator's own command — `gowave-auto.sh install
--panel-only <panel> <camouflage> <email>`, with no fourth positional argument
— and declares six cases against it: the install (`PO-INSTALL`), the shape of
the host it leaves (`PO-HOST`), the Panel's read surface and `state.json`
(`PO-API`), the squad the first registration creates (`PO-SQUAD`), the Panel's
answer to a null squad entry (`PO-SQUAD-REFUSED`), and the wizard's refusal to
add a node to an unverifiable Panel (`MN-ADD-NODE-REFUSED`, which the topology
runs beside the Multi-Node suite). The registration runs through the operator's
own `node add` against a second clean host, because a Panel-only deployment has
no local node whose squad could be read.

A data-plane case proves that a request reached the intended host by reading
that host's own stream access log — `/var/log/nginx/gowave-edge-access.log`, one
line per connection with the SNI, the protocol, the client address and the port
— and requiring a line naming the request's SNI. This is the file an operator
reads after a real deployment, and it is the product's own router that writes it.
A missing line fails the case instead of returning `INCOMPLETE`. The raw packet
capture remains only as a fallback for a host that predates the log: inside an
unprivileged container namespace it can observe nothing at all, so an empty
capture no longer decides a verdict.

The deadline is the `runtime_budget_seconds` the manifest declares for the
topology — 2700 s, 6300 s and 4500 s — and it is a ceiling rather than a
default: a run that asks for more wall clock than the matrix promises has left
the envelope the `pre-push` and `pr` tiers are defined by, so the entrypoint
refuses it (`--budget-seconds` may only tighten). Every run also executes `GATE-BUDGET`
first, which asserts that deadline is inside the declared one and then produces
an exhausted run of the real runner with no container at all, reading its report
back to prove the unexecuted case is named and `overall` is `INCOMPLETE` rather
than a shorter green.

The tier totals in the same manifest are enforced where the tier runs:
`runtime_budget.pre_push_total_seconds` (9600 s) is measured across both suites
by `tools/pre_push_e2e.py` and blocks the push when exceeded, and
`runtime_budget.pr_total_seconds` (12600 s) bounds one full wave plus one recovery
wave of the required checks; the Multi-Node deadline covers the four-distribution
concurrent mode, where the slowest cell finished at 62-70 minutes —
`python3 -m tools.podman_e2e.gate --check` refuses
a job timeout that does not leave those budgets room, because a job GitHub kills
at its timeout reports nothing at all.

## Pre-push gate

The pull request gate is not the first place a regression should be caught.
`tools/pre_push_e2e.py` runs the two full suites before a push leaves the
machine, and installs the hook that runs it:

```bash
python3 -m tools.pre_push_e2e --install-hook   # writes .git/hooks/pre-push
python3 -m tools.pre_push_e2e --list           # what the gate would run
sudo python3 -m tools.pre_push_e2e             # same thing, now
```

Which topologies it runs is read from the `gate:` list of
`tests/cases/matrix.yaml`, so a topology the manifest puts behind `pre-push` is
run without editing the gate, and one it does not gate is never silently skipped
into a shorter green. Each run is the same
`python3 -m tools.run_podman_e2e --topology <t>` the acceptance jobs invoke,
with the fixtures pinned by the matrix — no live host, no credential, no public
DNS name — and it prints the commit and tree it judges. Neither the gate nor the
required checks pass `--distribution`, `--vision`, `--worker-vision` or
`--budget-seconds`, so a pushed commit is judged against the same pinned target
image, client releases and deadline the pull request will be judged against.

A failing topology stops the gate and the remaining ones are printed as
`not run`: a later green suite would not change the verdict, and reporting it as
checked when it was not is the one thing a gate must not do. The suites
provision privileged systemd containers, so the gate runs as root, which is why
the installed hook is `exec sudo python3 -m tools.pre_push_e2e`; `sudo` may
prompt, and `git push --no-verify` bypasses the hook — the pull request gate
then judges the change, which is where the required checks live. The installer
owns only a hook carrying its own marker and refuses to replace a foreign one.

## Reading a result

Every run writes `artifacts/podman-e2e/<run_id>/` where the run id is
`podman-<topology>-<UTC timestamp>-<8 hex>`:

```
result.json                       the machine-readable report
junit.xml                         the same results for a CI viewer
evidence/<name>                   per-case logs written through the redactor
evidence/diagnostics/<CASE-ID>/   the failure bundle, when a case failed
```

`result.json` (schema `gowave-podman-e2e-result/v1`) carries `overall`, the
`cases[]` array with `id`, `assertion_sha256` — the digest of the catalog
sentence the case asserted, which is what the divergence guard compares with the
live suite's record of the same id — `status`, `duration`, `message` and the
`evidence_files` that case produced, and an `environment` block with the commit
and tree state the run measured, the image digests it resolved, the selected
Vision configuration, the `required_groups` audit and the `redaction_audit`.

`environment.vision` is the matrix's own combination key — `disabled`/`enabled`
on All-in-One, `neither`/`master-only`/`worker-only`/`both` on Multi-Node — so a
run can be matched to the positive-case count the matrix owes it (8/10 and
16/18/20). `overall: PASS` is an aggregate and says nothing about how many
data-plane cases contributed, so the count is read back from the artifact:

```bash
sudo python3 -m tools.podman_e2e.trace --verify-run artifacts/podman-e2e
```

It exits `1` naming the run, the count and the shortfall; CI runs it after every
acceptance suite. A topology with no data plane owes no count — the manifest
states none for Panel-only — so its run is read against the case list its suite
declares instead, and a case that did not run or did not pass is refused the
same way. The full requirement → scenario → matrix row → case → test →
CI job mapping, and the count itself, are published in
[`docs/PODMAN_E2E_TRACEABILITY.md`](PODMAN_E2E_TRACEABILITY.md). That page also
carries a `Named behaviours` table: one row per promise too narrow to be a
scenario — a subscription request with no User-Agent, one Vision combination,
one kind of DNS answer — with the `tests/cases/matrix.yaml` declaration each one
quotes. The audit refuses a behaviour that quotes a value the manifest does not
state, and refuses the table when a declaration the report is supposed to cover
is named by no behaviour, so the page cannot keep describing a policy the
matrix has moved away from.

Coverage is audited from the other side as well. `tests/cases/behaviors.yaml`
maps every catalog case to exactly one behaviour — installation, provisioning,
subscription representations, data plane, decoy, TLS/DNS/ACME, network policy,
lifecycle, failure injection — and names the cases that exercise each
behaviour's error paths, the topologies it is proven in and the gate tier that
blocks on it. The rendered view is
[`docs/PODMAN_E2E_BEHAVIORS.md`](PODMAN_E2E_BEHAVIORS.md):

```bash
python3 -m tools.podman_e2e.catalog behaviors --write   # regenerate the report
python3 -m tools.podman_e2e.catalog check               # audit the inventory
```

`check` fails on a behaviour with no case, a behaviour covered only on its happy
path, a case no behaviour names, a case two behaviours claim, an area the
requirement lists but no entry covers, a gate the named cases are not gated by,
and a topology none of the behaviour's cases reaches. The report is a fixed
point: editing the YAML without regenerating it fails the same check.

The same audit maps the contracts this suite shares with the live capability in
`openspec/specs/live-vps-e2e/spec.md` — subscription policy, case counts, Vision
independence, firewall evidence, redaction and result semantics — and publishes
them in the traceability report. Each contract quotes the live sentences it
rests on, names the `live-parity` catalog cases a container reproduces, and
resolves every count against `tests/cases/matrix.yaml` (`16/18/20` runtime cases
for Multi-Node, `8/9/10` outbounds per subscription, port `3002`). A live
sentence that was dropped or reworded, a case that is only partly reproducible,
and a count whose numbers disagree are refusals: a divergence is a defect here,
not a container-only variant.

States are never collapsed: `PASS`, `FAIL`, `BLOCKED`, `SKIP`,
`NOT_APPLICABLE`, `INCOMPLETE`. Any `SKIP` fails the run, `BLOCKED` and
`INCOMPLETE` never read as `PASS`, and a run in which nothing applied is
`INCOMPLETE`.

### Failure diagnostics

A failing case leaves `evidence/diagnostics/<CASE-ID>/` with one file per area
and an `index.txt` naming the case, the containers it probed and what was
skipped:

- `operator.txt` — what the install left behind, with values withheld
- `service.txt` — unit state of the managed services
- `systemd.txt` — system state, failed units and service journals
- `network.txt` — interfaces, routes, listeners, resolvers and firewall rules
- `tls.txt` — issued certificates and the one served on 443
- `dns.txt` — resolver configuration and the product's names as resolved there
- `client.txt` — client engines, their listeners and their last journal lines
- `endpoint.txt` — the product's own endpoints as that host sees them

The bundle is a reading, not a second test: probes assert nothing, a container
that already exited is reported as such, and each file ends with
`[bundle complete: N container(s) probed]` or an explicit truncation marker. It is
time-bounded end to end — 25 s per probe, 90 s for the whole bundle, 64 KiB per
output — so a wedged host cannot turn a one-minute failure into a stalled run.
Secrets are listed by key name only and every byte goes through the redactor.

Containers of a run in progress are labelled, so a case can be watched while it
is still running:

```bash
sudo podman ps -a --filter label=gowave.e2e.run=<run_id>
sudo podman logs <container>
```

The smallest unit a run can execute is a topology. There is no `--case`; narrow
with `--topology`, `--distribution` and the Vision flags, and use
`--require-group recovery` when the point of the run is that a named set of case
ids existed at all.

## Retention

- Locally the suite never deletes a run directory: the evidence of a red run is
  the reason the next commit exists. Run directories are ignored by
  `.gitignore` and are mode `0700`. A run started with `sudo` hands its tree
  back to the invoking operator (`SUDO_UID`/`SUDO_GID`), so the evidence is
  readable without root; a run started from a root shell leaves ownership alone.
- Each run directory is small — the three Multi-Node runs retained during this
  change total 536 KB — because evidence is logs and probe output, not images.
- Secrets never live under the artifact tree: they are materialized in a
  `mktemp -d` directory with mode `0700` outside it and removed when the run
  ends. Every artifact writer passes text through `redact()`, and a file that
  changes when redacted is scrubbed and fails the run.
- CI uploads `artifacts/podman-e2e/` on every outcome (`if: always()`) as
  `podman-aio-<run_id>`, `podman-multi-node-<run_id>`, `podman-panel-only-<run_id>`,
  `podman-aio-recovery-<run_id>` or `podman-multi-node-recovery-<run_id>`, retained
  for 14 days.

Prune local runs explicitly when their evidence is no longer needed:

```bash
ls artifacts/podman-e2e
rm -rf artifacts/podman-e2e/<run_id>
```

## Cleanup

The run removes what it created, by its own label, on every exit path:

- containers, volumes and networks labelled `gowave.e2e.run=<run_id>`;
- the testbed images it built, by tag;
- the secret directory outside the artifact tree.

`SIGINT`/`SIGTERM` are turned into an in-band abort: the case that was running
and every case after it are reported `INCOMPLETE`, cleanup still runs, and
`result.json` is still written. A cleanup that fails is itself reported as a
`CLEANUP` case with `FAIL`, so a leak cannot pass as a green run.

A run killed with `SIGKILL` cannot clean up after itself. The next invocation
reclaims the containers, volumes and networks of runs of this suite older than
6 hours before it starts its own, and prints what it reclaimed:

```
reclaimed from stale runs: container:..., volume:..., network:...
```

The filter is this suite's labels plus that age, so a young run, another tool's
container, or a container with no label is never touched. Images built by a
killed run are not reclaimed automatically; remove the residue of one run by
hand:

```bash
sudo podman ps -a --filter label=gowave.e2e.run
sudo podman volume ls --filter label=gowave.e2e.run
sudo podman network ls --filter label=gowave.e2e.run
sudo podman images --filter label=gowave.e2e.run
```

## CI

`.github/workflows/podman-acceptance.yml` runs five jobs, and these are the
required status checks of the repository ruleset:

| Job | Command |
| --- | --- |
| All-in-One Podman Acceptance | `sudo python3 -m tools.run_podman_e2e --topology aio` |
| Multi-Node Podman Acceptance | `sudo python3 -m tools.run_podman_e2e --topology multi-node` |
| Panel-only Podman Acceptance | `sudo python3 -m tools.run_podman_e2e --topology panel-only` |
| All-in-One Lifecycle and Recovery Acceptance | `sudo python3 -m tools.run_podman_e2e --topology aio --require-group recovery` |
| Multi-Node Lifecycle and Recovery Acceptance | `sudo python3 -m tools.run_podman_e2e --topology multi-node --require-group recovery` |

The recovery jobs run on `pull_request` and `workflow_dispatch` only, because a
push already spends the minutes on the two full suites. Panel-only has no
recovery group: it provisions no traffic plane whose restart or revocation could
be recovered, so a check requiring that group would pass by having nothing to
run. The transport testbed
(`tests/podman_testbed.sh`) and the QEMU cold-boot matrix stay in
`.github/workflows/systemd-acceptance.yml` as independent gates and are not
replaced by this workflow.

Those five names are also a contract that is checked in, because a required
check is written down in three places and a name that drifts in one of them
leaves the gate open: `tests/cases/gates.yaml` names each check, its topology,
its case group, its timeout and the prefix its report is uploaded under;
`podman-acceptance.yml` publishes them; and the repository ruleset decides what
GitHub requires. The audit reads all three:

```bash
python3 -m tools.podman_e2e.gate --check   # contract vs workflow, offline
python3 -m tools.podman_e2e.gate --live    # also reads ruleset 27258177 back
```

`--check` runs in the nonroot suite, so a renamed job, a job that runs the other
topology, a job that runs both, a raised timeout, a path filter on the
`pull_request` trigger or a suite-running job the ruleset does not require fails
a test rather than a review. `--live` additionally refuses a disabled ruleset, a
widened branch list or a changed bypass actor, and exits `2` when `gh` cannot
answer, because an unread ruleset is not a passing one.

An omitted topology cannot read as PASS because no job aggregates them: the
ruleset requires five names — the full suite of each topology, one of which is
Panel-only, and a recovery check for each traffic-plane topology. The same
question can be asked of a directory of finished runs, where `PASS` is a claim
about every topology a required check proves — the newest run of each must
exist, pass, carry the positive-case count the matrix owes it (Panel-only owes
the case list its suite declares), and measure one commit:

```bash
python3 -m tools.podman_e2e.gate --artifacts artifacts/podman-e2e
```

The harness itself is tested without root:

```bash
python3 tests/run_ci.py --suite nonroot
python3 tests/run_ci.py --check-completeness
```
