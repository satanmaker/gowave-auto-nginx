---
name: podman-triage
description: Read a Podman acceptance run directory as evidence and decide what it actually proves before proposing a fix. Use when a Podman E2E run is red, when a gate or a person points at a run directory, or when a run is about to be cited as proof for a commit.
---

Read a finished Podman acceptance run as evidence, not as a verdict: decide what the artifact proves, and refuse it when it proves nothing, before anyone proposes a fix.

## When to use

- A Podman E2E run finished red and the cause has to be named.
- A gate, a pre-push hook or a person points at `artifacts/podman-e2e/<run_id>/` and that directory is about to be cited as proof for a commit.
- A claim such as "the suite is green on this tree" needs checking against the artifact.

Not for starting a run: a rerun costs root and minutes, and this skill reads what a finished run already wrote. The run directories are gitignored and excluded from agent indexing, so they are read on disk, not searched for.

## Procedure

1. **Pick the run directory explicitly.** Name the absolute path you are reading and say why that one. Do not inherit it from a line in a reused log: the runner prints `artifacts: <dir>` when a run ends (`tools/run_podman_e2e.py`), so an old terminal line or a replayed log can point at a run that has already been consumed. Resolve the directory from its own `result.json`.
2. **Read the header and the environment block.** From `result.json` (`schema` is `gowave-podman-e2e-result/v1`) take `run_id`, `topology`, `started`, `duration`, `budget_seconds`, `overall`, and from `environment` take `vision`, `redaction_audit` and `repository` (its `commit` and `tree`). Those fields say what the run measured; nothing else in the file does. A non-empty `redaction_audit.offences` is a leaked-secret finding, not a flake: the run scrubbed the file and failed itself for it.
3. **Attribute or refuse the artifact.** Ask whether the recorded commit is an ancestor of the tree under review (`git merge-base --is-ancestor <commit> HEAD`). A `tree` of `dirty` means the artifact proves no commit at all. When the commit is not an ancestor, the run is a harness cursor, not evidence — say so and stop before reading cases.
4. **List the distinct non-PASS case ids.** Count ids, not log lines: one failure retried appears many times, and `SKIP` fails the run as a single decision rather than as many defects. Keep the status of each (`FAIL`, `BLOCKED`, `SKIP`, `NOT_APPLICABLE`, `INCOMPLETE`); never read `BLOCKED` or `INCOMPLETE` as `PASS`, and remember a run in which nothing applied is `INCOMPLETE`. An interrupted run (Ctrl-C) marks every case `INCOMPLETE`: an abort is not evidence of a failure.
5. **Open the failure bundle of the first id**, `evidence/diagnostics/<CASE-ID>/`. Read `index.txt` first — it names the case, the containers probed and what was skipped — then the area file the message points at (`network.txt`, `tls.txt`, `client.txt`, …). A bundle is a reading, not a second test: it asserts nothing, and its truncation markers and `[bundle complete: N container(s) probed]` line say how much of it is real.
6. **Decide the cause before proposing a fix**, and state it in one sentence the evidence supports. Then apply the rule: one cause, one repair attempt. If the same check fails for the same reason a second time, stop and report the cause instead of trying another variant.
7. **Check the budget.** `budget_seconds` is what the matrix declared for that topology; a `duration` above it is itself a finding, and cases that ran out of deadline are reported `INCOMPLETE`, never dropped.
8. **Only then consider a rerun**, and say what the rerun would add that the artifact cannot. Read back the count of positive cases the run owed before trusting any `overall: PASS` aggregate.

## Commands

The count check and the contract audit are the two readings that do not need a rerun:

```bash
sudo python3 -m tools.podman_e2e.trace --verify-run artifacts/podman-e2e/<run_id>
python3 -m tools.podman_e2e.gate --artifacts artifacts/podman-e2e   # --check is offline, --live reads the ruleset
```

`--verify-run` exits `1` naming the run, the count and the shortfall. `--artifacts` reads only the newest finished run of each topology, so it answers "is the pair green", not "is this run admissible". `jq` is not assumed; list the distinct ids with Python:

```bash
python3 - <<'PY'
import json
r = json.load(open("artifacts/podman-e2e/<run_id>/result.json"))
repo = r["environment"]["repository"]
print(r["schema"], r["run_id"], r["topology"], r["started"], r["duration"], "budget", r["budget_seconds"])
print("overall:", r["overall"], "| cases:", len(r["cases"]))
print("commit:", repo["commit"], "tree:", repo["tree"], "| vision:", r["environment"].get("vision"))
seen = {}
for c in r["cases"]:
    if c["status"] != "PASS":
        seen.setdefault((c["id"], c["status"]), c.get("message") or "")
for (cid, st), msg in sorted(seen.items()):
    print(st, cid, "::", msg[:300])
PY
```

Per-case logs live in `evidence/<name>` (written through the redactor) and the files a case produced are listed in its `evidence_files`.

## Reporting

Give the run id, the topology and the commit with its tree state (`clean` or `dirty`). State the sample: how many cases the artifact contains and how many you actually read. Name the distinct non-PASS ids with their status and message, the bundle files you opened, and what you did not read (`junit.xml`, the remaining bundles, per-case logs). End with admissibility: is this artifact evidence for the tree under review, a cursor to a harness run, or a run that proves nothing — and if a rerun is proposed, what it would settle that the artifact cannot.
