"""Hold the merge gate's three copies of a status-check name equal.

`tests/cases/gates.yaml` is the contract: which checks the repository ruleset
requires, which topology and case group each one proves, and which paths make
the lifecycle gate mandatory. `.github/workflows/podman-acceptance.yml` is the
only workflow that publishes those names, and the ruleset on github.com is the
copy GitHub evaluates when it decides whether a change may merge.

A name that drifts in one of the three leaves the other two green and the gate
open: a job deleted from the workflow still reads as an expected check in a
review, and a required check nothing publishes blocks everybody but the bypass
actor. `--check` judges the checked-in half offline, `--live` reads the ruleset
back and refuses a difference, and `--artifacts` answers the other question the
ruleset answers on GitHub — whether the pair of topologies passed at one commit,
because "the acceptance suite passed" is a claim about both.

The aggregate is deliberately not a job. A job that runs one topology cannot
hide the other, since the ruleset requires four names; a job that ran both would
be exactly the aggregate the design forbids, so the audit refuses one. The
proof that a skipped topology cannot read as PASS is therefore structural: the
required set covers both topologies at full width and at recovery width, and
that set is what `--check` and `--live` keep in place.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import yaml

from tools.podman_e2e import groups, trace

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CONTRACT_PATH = REPO_ROOT / "tests" / "cases" / "gates.yaml"
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
SCHEMA = "gowave-podman-gates/v1"

TOPOLOGIES = ("aio", "multi-node")
EVENTS = ("push", "pull_request", "workflow_dispatch")
BYPASS_MODES = ("always", "pull_request")
SUITE_MODULE = "tools.run_podman_e2e"


def load_contract(path: Path = CONTRACT_PATH) -> Dict[str, Any]:
    """The gate contract as written, without a second copy in Python."""
    return yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}


def load_workflow(
    contract: Dict[str, Any], directory: Path = WORKFLOWS,
) -> Dict[str, Any]:
    """The workflow document the contract points at."""
    return yaml.safe_load(
        (Path(directory) / contract["workflow"]).read_text(encoding="utf-8")
    ) or {}


def triggers(document: Dict[str, Any]) -> Dict[str, Any]:
    """The workflow's `on:` block, normalized.

    PyYAML resolves an unquoted `on:` key to the boolean ``True``, so both
    spellings are read; a trigger given as a bare string or a list is widened
    to an empty mapping so callers always see the same shape.
    """
    block = document.get("on")
    if block is None:
        block = document.get(True)
    if isinstance(block, str):
        return {block: {}}
    if isinstance(block, list):
        return {str(event): {} for event in block}
    return dict(block or {})


def run_text(job: Dict[str, Any]) -> str:
    """Everything a job's shell would execute, joined."""
    return "\n".join(
        str((step or {}).get("run") or "") for step in job.get("steps") or []
    )


def upload_name(job: Dict[str, Any]) -> str:
    """The name the job uploads its artifacts under, when it uploads any."""
    for step in job.get("steps") or []:
        when = (step or {}).get("with") or {}
        if str(step.get("uses") or "").startswith("actions/upload-artifact"):
            return str(when.get("name") or "")
    return ""


def job_events(job: Dict[str, Any]) -> Set[str]:
    """The trigger events a job's `if:` allows, read coarsely.

    A job without a condition runs for every event. One that names events runs
    only for the ones it names, because that is the only form in use here. The
    reading is coarse on purpose: the audit is looking for an event a check
    promises and its job cannot receive, not re-implementing GitHub's
    expression language.
    """
    condition = str(job.get("if") or "")
    if not condition:
        return set(EVENTS)
    named = {event for event in EVENTS if event in condition}
    return named or set(EVENTS)


def suite_jobs(document: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Every job of the workflow whose shell runs the acceptance entrypoint."""
    found: Dict[str, Dict[str, Any]] = {}
    for key, job in (document.get("jobs") or {}).items():
        job = job or {}
        if SUITE_MODULE in run_text(job):
            found[str(job.get("name") or key)] = job
    return found


def _topologies_of(text: str) -> Set[str]:
    """The `--topology` values a command line names, in any spelling."""
    values: Set[str] = set()
    words = text.split()
    for position, word in enumerate(words):
        if word == "--topology" and position + 1 < len(words):
            values.add(words[position + 1].strip("\"'"))
        elif word.startswith("--topology="):
            values.add(word.split("=", 1)[1].strip("\"'"))
    return values


def contract_problems(
    contract: Dict[str, Any], document: Dict[str, Any], root: Path = REPO_ROOT,
) -> List[str]:
    """Every way the contract and the workflow can disagree."""
    problems: List[str] = []
    if contract.get("schema") != SCHEMA:
        problems.append(f"the contract declares schema {contract.get('schema')!r}, not {SCHEMA!r}")
    checks = contract.get("checks") or []
    ruleset = contract.get("ruleset") or {}
    names = [str(check.get("name") or "") for check in checks]
    required = [str(name) for name in ruleset.get("required_status_checks") or []]

    for name in sorted({name for name in names if names.count(name) > 1}):
        problems.append(f"the contract requires {name!r} more than once")
    missing = set(names) ^ set(required)
    for name in sorted(missing):
        if name in set(names):
            problems.append(
                f"the contract lists {name!r} as a check but not as a required "
                "status check"
            )
        else:
            problems.append(f"the contract requires {name!r} but lists no check for it")

    available = suite_jobs(document)
    for name in sorted(set(available) - set(names)):
        problems.append(f"{document.get('name')}: the job {name!r} runs the acceptance suite "
                        "but the ruleset does not require it")
    for name in sorted(set(names) - set(available)):
        problems.append(f"{document.get('name')}: no job named {name!r} runs the acceptance suite")

    full = {check.get("topology") for check in checks if not check.get("group")}
    recovery = {check.get("topology") for check in checks if check.get("group")}
    for topology in TOPOLOGIES:
        if topology not in full:
            problems.append(f"no required check runs the full {topology} suite")
        if topology not in recovery:
            problems.append(f"no required check runs the {topology} recovery cases")
    for check in checks:
        group = check.get("group")
        if group and group not in groups.GROUPS:
            problems.append(f"{check.get('name')!r} requires the unknown case group {group!r}")

    for check in checks:
        name = check.get("name")
        job = available.get(str(name))
        if job is None:
            continue
        problems.extend(_check_problems(check, job, document))
    problems.extend(_trigger_problems(contract, document))
    problems.extend(_lifecycle_problems(contract, root))
    return problems


def _check_problems(
    check: Dict[str, Any], job: Dict[str, Any], document: Dict[str, Any],
) -> List[str]:
    """One required check against the job that is supposed to publish it."""
    problems: List[str] = []
    name = check["name"]
    text = run_text(job)
    named = _topologies_of(text)
    topology = check.get("topology")
    if not named:
        problems.append(f"{name!r} runs the suite without naming a --topology")
    elif named != {topology}:
        problems.append(f"{name!r} is required for {topology} but the job runs {sorted(named)}")
    group = check.get("group")
    declared = f"--require-group {group}" if group else None
    if declared and declared not in text:
        problems.append(
            f"{name!r} is required to prove the {group} cases but does not run {declared}"
        )
    if not declared and "--require-group" in text:
        problems.append(f"{name!r} requires a case group, so its verdict is not the full suite")
    if SUITE_MODULE not in text:
        problems.append(f"{name!r} does not run {SUITE_MODULE}")

    timeout = job.get("timeout-minutes")
    if not isinstance(timeout, int) or timeout <= 0:
        problems.append(f"{name!r} declares no bounded timeout-minutes")
    elif timeout != check.get("timeout_minutes"):
        problems.append(f"{name!r} declares {check.get('timeout_minutes')} minutes, the job "
                        f"allows {timeout}")

    prefix = str(check.get("artifact_prefix") or "")
    uploaded = upload_name(job)
    if not prefix:
        problems.append(f"{name!r} names no artifact prefix, so its report is unnamed")
    elif not uploaded.startswith(prefix):
        problems.append(f"{name!r} promises report {prefix}* but uploads {uploaded!r}")

    promised = set(check.get("events") or [])
    allowed = job_events(job)
    for event in sorted(promised - allowed):
        problems.append(f"{name!r} promises to run on {event} but its if: excludes it")
    for event in sorted(allowed - promised):
        problems.append(f"{name!r} runs on {event} although the contract does not promise it")

    triggers_ = triggers(document)
    for event in sorted(promised - set(triggers_)):
        problems.append(f"{document.get('workflow')}: {event} is not a trigger, so "
                        f"{name!r} cannot run for it")
    return problems


def _trigger_problems(
    contract: Dict[str, Any], document: Dict[str, Any],
) -> List[str]:
    """A path filter is the only way a required check silently stops running."""
    problems: List[str] = []
    block = triggers(document)
    for event in ("push", "pull_request"):
        options = block.get(event)
        if options is None:
            problems.append(f"{document.get('workflow')}: no {event} trigger, so the "
                            "required checks never run for it")
            continue
        if not isinstance(options, dict):
            continue
        for key in ("paths", "paths-ignore"):
            if key in options:
                problems.append(f"{document.get('workflow')}: the {event} trigger filters "
                                f"{key}, so a required check can silently stop running")
    promised = {event for check in contract.get("checks") or []
                for event in check.get("events") or []}
    for event in sorted(promised - set(block)):
        problems.append(f"{document.get('workflow')}: the contract promises {event} but the "
                        "workflow does not subscribe to it")
    return problems


def _lifecycle_problems(contract: Dict[str, Any], root: Path) -> List[str]:
    """The paths whose change must be judged by the recovery cases."""
    problems: List[str] = []
    paths = contract.get("lifecycle_paths") or []
    if not paths:
        problems.append("the contract names no lifecycle path, so the recovery gate covers nothing")
    for entry in paths:
        path = (Path(root) / str(entry)).resolve()
        try:
            path.relative_to(Path(root).resolve())
        except ValueError:
            problems.append(f"{entry}: escapes the repository")
            continue
        if not path.exists():
            problems.append(f"{entry}: no such path in the tree")
        elif path.is_dir() and not any(path.rglob("*")):
            problems.append(f"{entry}: the directory holds nothing")
    return problems


def live_problems(contract: Dict[str, Any], payload: Dict[str, Any]) -> List[str]:
    """The live ruleset against the contract, field by field."""
    problems: List[str] = []
    ruleset = contract.get("ruleset") or {}
    if payload.get("id") != ruleset.get("id"):
        problems.append(f"the live ruleset is {payload.get('id')!r}, the contract names "
                        f"{ruleset.get('id')!r}")
    for field in ("name", "enforcement"):
        if payload.get(field) != ruleset.get(field):
            problems.append(f"the live ruleset has {field} {payload.get(field)!r}, the contract "
                            f"records {ruleset.get(field)!r}")
    include = ((payload.get("conditions") or {}).get("ref_name") or {}).get("include") or []
    if set(include) != set(ruleset.get("include") or []):
        problems.append(f"the live ruleset applies to {sorted(include)}, the contract records "
                        f"{sorted(ruleset.get('include') or [])}")
    bypass = sorted(
        (int(actor.get("actor_id") or 0), str(actor.get("actor_type") or ""),
         str(actor.get("bypass_mode") or ""))
        for actor in payload.get("bypass_actors") or []
    )
    expected = sorted(
        (int(actor.get("actor_id") or 0), str(actor.get("actor_type") or ""),
         str(actor.get("bypass_mode") or ""))
        for actor in ruleset.get("bypass_actors") or []
    )
    if bypass != expected:
        problems.append(f"the live ruleset bypasses {bypass}, the contract records {expected}")
    for actor in payload.get("bypass_actors") or []:
        if str(actor.get("bypass_mode") or "") not in BYPASS_MODES:
            problems.append(f"the live ruleset bypasses with mode {actor.get('bypass_mode')!r}")
    parameters: Dict[str, Any] = {}
    for rule in payload.get("rules") or []:
        if rule.get("type") == "required_status_checks":
            parameters = rule.get("parameters") or {}
    if not parameters:
        problems.append("the live ruleset carries no required_status_checks rule")
    else:
        contexts = [
            str(entry.get("context") or "")
            for entry in parameters.get("required_status_checks") or []
        ]
        if set(contexts) != set(ruleset.get("required_status_checks") or []):
            problems.append(f"the live ruleset requires {sorted(contexts)}, the contract records "
                            f"{sorted(ruleset.get('required_status_checks') or [])}")
        if len(contexts) != len(set(contexts)):
            problems.append("the live ruleset requires the same check more than once")
        for field in ("do_not_enforce_on_create", "strict_required_status_checks_policy"):
            if parameters.get(field) != ruleset.get(field):
                problems.append(f"the live ruleset has {field} {parameters.get(field)!r}, the "
                                f"contract records {ruleset.get(field)!r}")
    return problems


def fetch_ruleset(contract: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], str]:
    """The live ruleset, or the reason it could not be read."""
    repository = contract.get("repository")
    ruleset_id = (contract.get("ruleset") or {}).get("id")
    command = ["gh", "api", f"/repos/{repository}/rulesets/{ruleset_id}"]
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=60, check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return None, f"{' '.join(command)} could not run: {error}"
    if completed.returncode != 0:
        tail = (completed.stderr or completed.stdout or "").strip().splitlines()
        last = tail[-1] if tail else ""
        return None, f"{' '.join(command)} exited {completed.returncode}: {last}"
    try:
        return json.loads(completed.stdout), ""
    except json.JSONDecodeError as error:
        return None, f"{' '.join(command)} did not answer JSON: {error}"


def _read_result(run: Path) -> Tuple[Optional[Dict[str, Any]], str]:
    path = run / "result.json"
    try:
        return json.loads(path.read_text(encoding="utf-8")), ""
    except (OSError, json.JSONDecodeError) as error:
        return None, f"{run}: result.json cannot be read back ({error})"


def aggregate_problems(directory: Path) -> List[str]:
    """Judge the pair of topologies, not one run of one topology.

    Only the newest finished run of each topology is read, because that is what
    a reviewer would look at: an older green run of the same topology does not
    make a newer red one disappear. A topology with no finished run is the
    central refusal — the aggregate is unproven, not PASS.
    """
    problems: List[str] = []
    runs = trace.run_directories(Path(directory))
    if not runs:
        return [
            f"{directory}: holds no finished run (no result.json), so the aggregate is unproven"
        ]
    latest: Dict[str, Tuple[Path, Dict[str, Any]]] = {}
    for run in runs:
        data, error = _read_result(run)
        if data is None:
            problems.append(error)
            continue
        topology = str(data.get("topology") or "")
        latest[topology] = (run, data)
    for topology in TOPOLOGIES:
        if topology not in latest:
            problems.append(
                f"{directory}: no {topology} run finished, so the aggregate is unproven"
            )
    commits: Set[str] = set()
    for topology in sorted(latest):
        run, data = latest[topology]
        if topology not in TOPOLOGIES:
            problems.append(f"{run}: records topology {topology!r}, which no gate requires")
        if data.get("overall") != "PASS":
            problems.append(f"{run}: overall is {data.get('overall')!r}")
        commit = str(((data.get("environment") or {}).get("repository") or {}).get("commit") or "")
        if commit:
            commits.add(commit)
        else:
            problems.append(f"{run}: records no commit, so it cannot be tied to the tree")
        problems.extend(trace.run_count_problems(run))
    if len(commits) > 1:
        problems.append(f"the runs measured different commits: {sorted(commits)}")
    return problems


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m tools.podman_e2e.gate",
        description="Hold the required status checks, the workflow and the ruleset equal.",
    )
    parser.add_argument("--check", action="store_true",
                        help="judge the contract against the workflow (offline)")
    parser.add_argument("--live", action="store_true",
                        help="also read the ruleset back through the GitHub API")
    parser.add_argument("--artifacts", metavar="DIRECTORY",
                        help="judge a root of finished runs as one aggregate")
    arguments = parser.parse_args(list(sys.argv[1:] if argv is None else argv))

    if arguments.artifacts:
        problems = aggregate_problems(Path(arguments.artifacts))
        if problems:
            print("gate: the aggregate is unproven or red")
            for problem in problems:
                print(f"  - {problem}")
            return 1
        print(f"gate: both topologies passed at one commit under {arguments.artifacts}")
        return 0
    if not arguments.check and not arguments.live:
        parser.error("nothing to do: pass --check, --live or --artifacts")

    contract = load_contract()
    document = load_workflow(contract)
    problems = contract_problems(contract, document)
    if arguments.live:
        payload, error = fetch_ruleset(contract)
        if payload is None:
            print(f"gate: the ruleset could not be read back ({error})")
            return 2
        problems.extend(live_problems(contract, payload))
    checks = contract.get("checks") or []
    if problems:
        print("gate: the required checks disagree with what publishes them")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    names = ", ".join(str(check.get("name")) for check in checks)
    source = "the workflow and the live ruleset" if arguments.live else "the workflow"
    print(f"gate: {len(checks)} required checks agree with {source}: {names}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
