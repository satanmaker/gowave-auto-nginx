# Backlog

Deferred work with the measurement that justifies it. Each entry says what is
slow or missing, how it was measured, and what would count as done. A change
picked up from here gets its own OpenSpec change; this file is the queue, not a
second tracker.

---

## 1. Make `node reapply` re-render the edge instead of re-provisioning the host

**Measured on 2026-11-27.** `tools/podman_e2e/multi_node.py` runs **23** steps
whose command is `node add`, `node reapply` or `gowave-auto.sh install`. In the
mandatory four-distribution matrix those 23 steps execute **92 times**, and every
`node reapply` is a full Worker provision — apt, certificates, NGINX, Xray — which
takes 10–20 minutes on its own and rather longer when four cells share the apt
mirrors and network.

Consequence: a suite of 135 cases takes 62–70 minutes for one cell and 85–105
minutes for four, and the longest single case (`MN-COMPOSED-MIXED`) spends most of
its 1800 s ceiling inside two re-applies. The `multi-node` deadline had to be
raised to 6300 s to accommodate this.

**What the spec already says.** The migration requirement describes re-apply as
rewriting the edge: stream map, vhosts and cover site return to the digests the
product rendered. It does not promise a package install, a certificate reissue or
a service reinstall on a host that already serves the same identity.

**Done when**

- a confirmed `node reapply` on a Worker that is already provisioned changes only
  the edge files it owns, reloads NGINX and leaves package versions, certificates
  and the service PID untouched, and a case asserts each of those three;
- the same re-apply finishes in a couple of minutes rather than ten, so
  `WORKER_MIGRATION_TIMEOUT_ONE_RUN_SECONDS` can come back down;
- a first provision (no prior install) still does the full work, and the case
  that covers it still passes.

**Why it is deferred.** It changes the product's re-apply path, which the current
acceptance matrix is the evidence for; taking it means a new change, a spec
delta, and a full four-cell re-run afterwards.

---

## 2. One install pass in `case_env_contract`

**Measured on 2026-11-27.** `case_env_contract` runs four heavy steps by itself —
the largest single contributor to the 23 counted above — because each environment
variable it checks is exercised through a separate `install` invocation.

**Done when** the variables are checked against one install pass plus targeted
reads of the artifacts that pass wrote, with the same assertions per variable, and
the case's own tests still fail if any variable stops being honoured.

---

## 3. Keep the four-distribution matrix off the pre-push path

**Measured on 2026-11-27.** Four cells buy coverage, not latency: each cell runs the
whole suite, and in the set each is 20–35 % slower than alone. A pre-push run that
waits for all four therefore costs ~100 minutes to answer a question one
distribution answers in ~65.

**Done when** the pre-push tier runs one distribution (the one the change targets),
the four-cell matrix runs on the nightly tier and on demand through
`--all-distributions`, and `gates.yaml` still publishes the same required check
names with the same aggregate semantics.

---

## 4. `wizard.sh` Worker batch: read the live security report during resume

**Measured on 2026-11-27.** Task 6.4 added the identity classifier for the Panel and
the local node; the remote Worker batch was outside that change's scope, so it
still relies on its own TLS and SSH readback without comparing the recorded
security identity first.

**Done when** a Worker whose recorded security report belongs to another machine is
classified and stopped before the batch reads it as evidence, and the case that
covers a resumed Worker still passes.

---

## 5. Serve the pinned NGINX repository from the test bed

**Measured on 2026-11-28.** The four-cell multi-node matrix fetches
`https://nginx.org/packages/…` from the runner's own network on every install and
every re-apply. In `matrix-09d56bf449ed4f67ac998142bcb6b17c` one cell lost that
connection during the retry inside `MN-COMPOSED-MIXED`
(`E: Failed to fetch …/dists/trixie/InRelease  Unable to connect to nginx.org:https`)
and the case failed for the runner's network, not for the product. The bounded apt
retry added in the same change absorbs a single drop; it cannot absorb a real
outage, and the suite then reports a product failure it did not observe.

**Done when** the acceptance bed answers for `nginx.org` itself — a fixture that
serves the pinned `.deb` and its signed `InRelease` over the pinned fingerprint, the
way the ACME and DNS fixtures already answer for their services — and the matrix
passes with the runner's outbound access to the vendor blocked. The product keeps
verifying the vendor signature; only the transport the suite depends on changes.

**Why it is deferred.** It is test-bed infrastructure, not product behaviour, and it
needs its own change: a fixture container, a certificate the `signed-by` fingerprint
accepts, and a case proving the fixture is what the install actually read.

