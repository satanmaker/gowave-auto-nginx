---
name: podman-run
description: Launch and supervise the rootful Podman acceptance suites in this repository - aio, multi-node or panel-only on one or four distributions - and read their verdicts without mistaking a running cell, a hidden rootful store or a harness timeout for a product defect. Use when an acceptance run has to be started or restarted, when a fix needs a live cell, or when someone asks whether all four distributions are running.
---

Run the suites; do not hand the operator a command. This skill is the launch
side of the pair: `podman-triage` reads a finished run, this one starts one and
keeps it honest while it runs.

## When to use

- An acceptance run has to be started or restarted after a fix.
- A live cell is needed to prove one case (a pin, a transport, a log).
- Someone asks "are all four running?" or "what is it doing now?".
- A stale or half-dead run has to be stopped and its resources reclaimed.

## Standing rule: four distributions, not one

All four pinned distributions run **in parallel** — Debian 12, Debian 13,
Ubuntu 24.04, Ubuntu 26.04 — locally and in CI. A launch counts as parallel only
when all four cells are alive; a cell that died at start is a coverage gap to
report, not a pass. One cell at a time is acceptable only while bisecting a
single question, and that has to be said out loud.

## Procedure

1. **One privileged launch for all cells.** `sudo -n` is unavailable on this
   host, so feed the password to `sudo -S` on stdin exactly once per message and
   never through a GUI agent (`pkexec` opens a dialog and times out):

   ```bash
   printf '%s\n' "$PW" | sudo -S -p '' bash -c '
     for d in debian-12 debian-13 ubuntu-24.04 ubuntu-26.04; do
       PYTHONPATH=. /usr/bin/python3 -u -m tools.run_podman_e2e \
         --topology multi-node --distribution "$d" \
         --artifact-root "$PWD/artifacts/podman-e2e" > "/tmp/mn_$d.log" 2>&1 &
     done; wait'
   ```

   `--all-distributions` does the same in one process and adds a per-cell
   `result.json` check; use it unless you need per-cell logs on the host.

2. **Confirm liveness where root keeps it.** A rootful run lives in root's
   Podman store, so an unprivileged `podman ps` lists nothing and the run looks
   dead. Read the process tree instead:

   ```bash
   ps -eo pid,ppid,etime,args= | grep 'tools[.]run_podman_e2e' | grep -v grep
   tr '\0' ' ' < /proc/<pid>/cmdline   # the exact step inside the container
   ```

   Nine matching processes for four cells is normal: each run contributes
   `bash -c`, `sudo`, `python`, plus the transient `podman exec`.

3. **Read the phase from the child, not from the log.** A non-TTY run
   block-buffers stdout, so an empty `/tmp` log is normal. The child's command
   line names the step (`gowave-auto.sh install`, `node add`, `node reapply`, a
   case's command); `etime` says how long that step has been running.

4. **Find artifacts at the right depth.** A single run writes
   `artifacts/podman-e2e/podman-<topology>-<stamp>-<id>/result.json`; a matrix
   writes `artifacts/podman-e2e/matrix-<uuid>/<distribution>/podman-…/result.json`.
   `find -maxdepth 2` misses the matrix cells — use `-maxdepth 4`.

   ```bash
   python3 - <<'PY'
   import json, glob, collections
   for p in sorted(glob.glob("artifacts/podman-e2e/**/result.json", recursive=True)):
       d = json.load(open(p)); cs = d["cases"]
       print(p.split("/")[-3], d.get("overall"),
             dict(collections.Counter(c.get("status") for c in cs)))
   PY
   ```

   `result.json` is written once, at the end: no file means no verdict yet.

5. **Do not edit while cells run.** The repositories are mounted into the
   containers and the bash payloads are read step by step, so a product script
   edited mid-run mixes two versions into one verdict. Python harness modules
   are imported once and are safe; `tests/cases/*.yaml`, `catalog.yaml`,
   `behaviors.yaml`, `traceability.yaml` are **not** — the `GATE-*` cases inside
   the run audit them. Documentation is safe.

6. **Wait on a named timer, not on a poll loop.** Arm a background sleep, say
   when it fires, and read the run only then. A chained `sleep 90; tail ...` is
   refused by the harness; a standalone `sleep N` in the background is not.

7. **Judge before rerunning.** Absence of `evidence/diagnostics/<CASE-ID>/` means
   the case did not produce a bundle: `RED-01`/`RED-02` appear in green runs too.
   A FAIL whose message is `… did not finish within Ns` is the harness's own
   budget, not the product. One cause, one repair attempt.

8. **Clean up only what the run owns.** Stop a stale run by explicit PID from a
   clean `ps` listing, then remove its labelled leftovers:

   ```bash
   podman ps -a --filter label=gowave.e2e.run --format '{{.Names}}'
   podman volume ls --format '{{.Name}}' | grep '^backups-'
   podman network ls --format '{{.Name}}' | grep '^e2e-'
   ```

   Never `pgrep -f`/`pkill -f` a pattern that also appears in the command line
   running the kill: the loop matches its own wrapper and kills the caller.
   Never `chmod`/`chown` `/run/lock/gowave-podman-e2e-networks.lock`; isolate it
   in a fixture instead.

## Commands

```bash
# environment preflight (rootful podman, cgroup v2, images pinned)
printf '%s\n' "$PW" | sudo -S -p '' env PYTHONPATH=. python3 -m tools.podman_e2e.environment

# one topology, one distribution, foreground budget
printf '%s\n' "$PW" | sudo -S -p '' env PYTHONPATH=. python3 -u -m tools.run_podman_e2e \
  --topology aio --distribution debian-13 --artifact-root "$PWD/artifacts/podman-e2e"

# the same suite on all four, concurrently, one exit status
printf '%s\n' "$PW" | sudo -S -p '' env PYTHONPATH=. python3 -u -m tools.run_podman_e2e \
  --topology multi-node --all-distributions --artifact-root "$PWD/artifacts/podman-e2e"

# what is running now: one line per cell, no root, no podman
PYTHONPATH=. python3 -m tools.podman_e2e.live_status [--json]

# a named subset on one cell, and keeping the hosts for inspection
printf '%s\n' "$PW" | sudo -S -p '' env PYTHONPATH=. python3 -m tools.run_podman_e2e \
  --topology multi-node --distribution debian-13 \
  --only MN-DP-master-XHTTP-xray,MN-DP-worker-XHTTP-xray --keep
```

`live_status` is the cheapest look: it prints `topology distribution up=…
step=… diag=… verdict=…` and answers `diag=?` when a rootful cell's evidence
directory cannot be read. A finished run also leaves `summary.json` (0644) beside
`result.json` — counts, executed cases and one bounded entry per non-PASS case —
which is what to read instead of parsing the full result.

`--budget-seconds` may only tighten the deadline the matrix declares
(`tests/cases/matrix.yaml`); a larger value is refused before anything runs.

## Traps that cost a real rerun

- `podman ps` as an unprivileged user proves nothing about a rootful run.
- `find -maxdepth 2` finds no `result.json` under a matrix directory.
- `GATE-PREPUSH-PROBE aio FAIL` in the log is the gate's own self-test proving a
  red run is caught; it is not a case failure.
- `dpkg-query -W -f='${Version}'` nested through `sudo -S bash -c` and
  `podman exec … sh -c` loses the escapes and prints nothing; read the version as
  `dpkg-query -W nginx | tr '\t' '='`.
- A cell at `node add` with no `worker-*` nginx yet is progressing, not broken:
  the Worker is provisioned by that step.
- An empty `evidence/diagnostics/` is not a green verdict either; the verdict is
  `result.json`.

## Reporting

State per cell: distribution, elapsed, the step it is on, and — when the run is
finished — `overall`, the PASS/FAIL/INCOMPLETE counts, the distinct non-PASS case
ids and the run directory. Name what was not run (a distribution, a topology, a
group) instead of letting four cells imply the whole matrix.
