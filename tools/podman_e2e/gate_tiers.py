"""``GATE-PREPUSH``, ``GATE-COVERAGE`` and ``GATE-DIVERGENCE``: each gate reads the tree it guards.

Three programs decide whether a change may land, and each of them reads the
checked-in manifests rather than a copy:

* ``tools/pre_push_e2e.py`` runs every topology ``tests/cases/matrix.yaml`` puts
  behind ``pre-push``, in the manifest's own order, with the full-suite module
  the acceptance jobs invoke;
* ``catalog.coverage_audit`` judges ``tests/cases/behaviors.yaml`` as a
  partition: a behaviour that names no case promises nothing, a behaviour with
  only its happy path has no measured failure behaviour, and a catalog case no
  behaviour names is a guarantee nobody wrote down;
* ``catalog.divergence_guard`` judges the catalog against the live spec, the
  matrix's positive-case counts, and the result files of both suites.

Each case drives its program twice: once over the tree as it ships, which must
be accepted, and once over a copy damaged in exactly the way the entry names,
which must be refused with the sentence that names the item. The two halves are
what separate a guard from a banner — a guard that is red on its own tree says
nothing about a change, and one that stays green on a damaged copy says nothing
either.

What is real: the entrypoints, the manifests, the sentences, and the exit status
``main`` returns. What is not: the pre-push case replaces ``suite_command`` with
a two-line child process, because a gate that ran the acceptance suites inside an
acceptance case would recurse, and the hook and the damaged copies live in a
temporary directory, so a run never edits the checked-in catalog or inventory.
"""
from __future__ import annotations

import contextlib
import copy
import io
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from unittest import mock

import yaml

from tools import pre_push_e2e as pre_push
from tools.podman_e2e import catalog as catalog_data
from tools.podman_e2e import matrix as matrix_data
from tools.podman_e2e.runner import require

PREPUSH_CASE_ID = "GATE-PREPUSH"
COVERAGE_CASE_ID = "GATE-COVERAGE"
DIVERGENCE_CASE_ID = "GATE-DIVERGENCE"

# The child stands in for a suite and says which case failed, so the gate's own
# refusal can be read next to the failure it is refusing.
PROBE_CASE_ID = "GATE-PREPUSH-PROBE"
PROBE_COMMIT = "0" * 40

# What must not appear in a suite invocation: a credential would make the gate
# prove a different combination than CI does, and a host would make it depend on
# a machine nobody provisioned for it.
CREDENTIAL_TOKENS = ("secret", "token", "password", "passwd", "credential", "ssh", "--host")
HOST_TOKENS = ("live", "vps", "https://", "http://")


# --- GATE-PREPUSH ------------------------------------------------------------


def _child(root: Path, topology: str, status: int) -> Tuple[List[str], Path]:
    """A two-line program standing in for the suite, and the file it leaves.

    Only a failing child speaks: the line it prints is the case id a real suite
    would print, and the gate must let it through to the operator instead of
    holding it in a buffer.
    """
    marker = root / f"ran-{topology}"
    script = root / f"child-{topology}.py"
    speech = f"print('{PROBE_CASE_ID} {topology} FAIL')\n" if status else ""
    script.write_text(
        "import sys\n"
        f"{speech}"
        f"open({str(marker)!r}, 'w', encoding='utf-8').write('ran')\n"
        f"sys.exit({status})\n",
        encoding="utf-8",
    )
    return [sys.executable, str(script)], marker


def _run_gate(
    commands: Dict[str, List[str]],
    *,
    euid: int = 0,
    clock: Optional[Sequence[float]] = None,
) -> Dict[str, str]:
    """Run the real entrypoint with the suite command replaced by a child process."""
    out, err = io.StringIO(), io.StringIO()
    patches: List[Any] = [
        mock.patch.object(pre_push, "repository_state", return_value=(PROBE_COMMIT, "clean")),
        mock.patch.object(pre_push, "suite_command", side_effect=lambda topology: commands[topology]),
        mock.patch.object(pre_push.os, "geteuid", return_value=euid),
    ]
    if clock is not None:
        values = list(clock)

        def fake_clock() -> float:
            # The gate asks twice; anything else that reads the clock while the
            # patch is in place gets the last value instead of a StopIteration.
            return values.pop(0) if len(values) > 1 else values[0]

        patches.append(mock.patch.object(pre_push.time, "monotonic", side_effect=fake_clock))
    with contextlib.ExitStack() as stack:
        for patch in patches:
            stack.enter_context(patch)
        stack.enter_context(contextlib.redirect_stdout(out))
        stack.enter_context(contextlib.redirect_stderr(err))
        status = pre_push.main([])
    return {"status": str(status), "out": out.getvalue(), "err": err.getvalue()}


def _recorded_call() -> Dict[str, Any]:
    """One gate run whose suites are answered for, so the call shape can be read."""
    recorded: List[Dict[str, Any]] = []

    def fake_run(command: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess:
        recorded.append({"command": list(command), "kwargs": kwargs})
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    with contextlib.ExitStack() as stack:
        stack.enter_context(
            mock.patch.object(pre_push, "repository_state", return_value=(PROBE_COMMIT, "clean"))
        )
        stack.enter_context(mock.patch.object(pre_push.os, "geteuid", return_value=0))
        stack.enter_context(mock.patch.object(pre_push.subprocess, "run", side_effect=fake_run))
        stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
        status = pre_push.main([])
    return {"status": status, "calls": recorded}


def case_pre_push_gate(product: Any, context: Any) -> Dict[str, Any]:
    """``GATE-PREPUSH``: the manifest decides what runs, and a failure blocks the push."""
    data = pre_push.load_matrix()
    topologies = pre_push.pre_push_topologies(data)
    require(
        PREPUSH_CASE_ID,
        topologies == ["aio", "multi-node"],
        f"the pre-push gate runs {topologies}, not both topologies in the manifest's order",
    )
    commands = {topology: pre_push.suite_command(topology) for topology in topologies}
    for topology, command in commands.items():
        require(
            PREPUSH_CASE_ID,
            command == [sys.executable, "-m", pre_push.SUITE_MODULE, "--topology", topology],
            f"{topology} runs {command}, which is not the full-suite module with its topology and "
            "nothing else: a version, a host or a credential here would make the gate prove a "
            "different combination than the acceptance jobs do",
        )
        arguments = " ".join(command[1:]).lower()
        for token in CREDENTIAL_TOKENS:
            require(
                PREPUSH_CASE_ID,
                token not in arguments,
                f"{topology}'s invocation carries {token!r} ({command}): the gate must run with the "
                "fixtures the matrix pins, not with a live credential",
            )
        for token in HOST_TOKENS:
            require(
                PREPUSH_CASE_ID,
                token not in arguments,
                f"{topology}'s invocation carries {token!r} ({command}): a live host or URL here "
                "would make the gate depend on a machine the container run never provisioned",
            )

    tier_budget = matrix_data.tier_budget_seconds(data, pre_push.TIER)
    topology_budgets = {
        topology: matrix_data.runtime_budget_seconds(data, topology) for topology in topologies
    }
    require(
        PREPUSH_CASE_ID,
        0 < tier_budget,
        f"the matrix declares no {pre_push.TIER} tier budget, so the gate has nothing to hold the "
        "pair of suites to",
    )

    # The topology list is read from the manifest, not written into the gate: a
    # copy that drops one topology must shorten the gate, or the manifest's
    # `gate:` list would be decoration.
    damaged = copy.deepcopy(data)
    damaged["topologies"]["multi-node"]["gate"] = [
        gate for gate in damaged["topologies"]["multi-node"]["gate"] if gate != pre_push.GATE
    ]
    require(
        PREPUSH_CASE_ID,
        pre_push.pre_push_topologies(damaged) == ["aio"],
        "a manifest that no longer gates multi-node still yields "
        f"{pre_push.pre_push_topologies(damaged)}: the gate does not read the manifest's own gate list",
    )

    with tempfile.TemporaryDirectory(prefix="gowave-prepush-") as directory:
        root = Path(directory)

        # A regressed change: the first gated topology fails, so the push is
        # blocked and the rest is named as not run instead of claimed green.
        children = {
            topology: _child(root, topology, 1 if topology == topologies[0] else 0)
            for topology in topologies
        }
        blocked = _run_gate({topology: command for topology, (command, _marker) in children.items()})
        require(
            PREPUSH_CASE_ID,
            blocked["status"] == "1",
            f"a failing {topologies[0]} left the gate at {blocked['status']}, so the push it exists "
            f"to block would continue ({blocked['out']}{blocked['err']})",
        )
        require(
            PREPUSH_CASE_ID,
            f"{topologies[0]} FAILED (exit 1); the push is blocked" in blocked["err"],
            f"the gate refused with {blocked['err']!r}, which does not name the topology that failed",
        )
        require(
            PREPUSH_CASE_ID,
            f"not run: {topologies[1]}" in blocked["err"],
            f"the gate refused with {blocked['err']!r}, which does not say that {topologies[1]} was "
            "not run: a gate must not leave the remainder looking green",
        )
        require(
            PREPUSH_CASE_ID,
            children[topologies[0]][1].is_file(),
            "the failing suite never started, so the refusal above came from somewhere other than "
            "a child process exit status",
        )
        require(
            PREPUSH_CASE_ID,
            not children[topologies[1]][1].is_file(),
            f"{topologies[1]} ran after {topologies[0]} failed: a later green suite would not change "
            "the verdict, and spending it is how a gate claims what it did not check",
        )

        # The same pair, green: the gate lets the push continue and says the
        # whole tier stayed inside the budget the matrix declares.
        green_children = {topology: _child(root, topology, 0) for topology in topologies}
        green = _run_gate(
            {topology: command for topology, (command, _marker) in green_children.items()}
        )
        require(
            PREPUSH_CASE_ID,
            green["status"] == "0",
            f"a green pair left the gate at {green['status']}: {green['err']!r}",
        )
        require(
            PREPUSH_CASE_ID,
            all(marker.is_file() for _command, marker in green_children.values()),
            "a green gate did not run every gated topology, so its verdict covers a subset",
        )
        require(
            PREPUSH_CASE_ID,
            "every gated suite passed; the push may continue" in green["out"],
            f"the green gate printed {green['out']!r}, which does not state the verdict",
        )
        require(
            PREPUSH_CASE_ID,
            f"of the {tier_budget}s tests/cases/matrix.yaml declares for the "
            f"{pre_push.GATE} tier" in green["out"],
            f"the green gate printed {green['out']!r}, which does not measure the pair against the "
            f"{tier_budget}s tier budget the matrix declares",
        )

        # The pair that outspends the tier: each suite stayed inside its own
        # deadline, so only the total can catch this, and it must block.
        overrun_children = {topology: _child(root, topology, 0) for topology in topologies}
        overrun = _run_gate(
            {topology: command for topology, (command, _marker) in overrun_children.items()},
            clock=(0.0, tier_budget + 1.0),
        )
        require(
            PREPUSH_CASE_ID,
            overrun["status"] == "1",
            f"a pair that spent more than the {tier_budget}s tier budget left the gate at "
            f"{overrun['status']}: {overrun['out']}{overrun['err']}",
        )
        require(
            PREPUSH_CASE_ID,
            f"past the {tier_budget}s the matrix declares" in overrun["err"],
            f"the overrun gate refused with {overrun['err']!r}, which does not name the budget it "
            "overran",
        )

        # Without root the gate refuses before it reads a host: the suites
        # provision privileged containers, so a run that cannot is not a green one.
        nonroot = _run_gate(
            {topology: command for topology, (command, _marker) in green_children.items()},
            euid=1000,
        )
        require(
            PREPUSH_CASE_ID,
            nonroot["status"] == "2",
            f"a non-root gate exited {nonroot['status']}, not the refusal its suites require",
        )
        require(
            PREPUSH_CASE_ID,
            "sudo python3 -m tools.pre_push_e2e" in nonroot["err"],
            f"the non-root gate said {nonroot['err']!r}, which does not tell the operator how to run it",
        )
        require(
            PREPUSH_CASE_ID,
            "aio passed" not in nonroot["out"],
            "the non-root gate ran a suite anyway, so the privilege check is not a precondition",
        )

        # What the gate hands the suite: the pinned invocation, from the
        # repository root, with the child's streams inherited so the case ids a
        # failing suite prints reach the operator rather than a buffer.
        recorded = _recorded_call()
        require(
            PREPUSH_CASE_ID,
            recorded["status"] == 0 and len(recorded["calls"]) == len(topologies),
            f"the recorded run made {len(recorded['calls'])} call(s) and exited {recorded['status']}",
        )
        for topology, call in zip(topologies, recorded["calls"]):
            require(
                PREPUSH_CASE_ID,
                call["command"] == commands[topology],
                f"{topology} was invoked as {call['command']}, not as {commands[topology]}",
            )
            require(
                PREPUSH_CASE_ID,
                call["kwargs"].get("cwd") == str(pre_push.REPO_ROOT),
                f"{topology} ran from {call['kwargs'].get('cwd')!r}, so a suite invoked outside the "
                "repository would read a different tree than the one the gate judged",
            )
            captured = {
                key for key in ("capture_output", "stdout", "stderr") if call["kwargs"].get(key)
            }
            require(
                PREPUSH_CASE_ID,
                not captured,
                f"{topology} was run with {sorted(captured)}: a captured stream hides the failing "
                "case ids the suite prints, which is the one thing a blocked push must show",
            )

        # The hook is the same gate, installed where git will find it.
        hooks = root / "hooks"
        hooks.mkdir()
        installed = pre_push.install_hook(hooks)
        hook_body = installed.read_text(encoding="utf-8")
        hook_mode = installed.stat().st_mode & 0o777
        require(
            PREPUSH_CASE_ID,
            installed.name == "pre-push" and pre_push.HOOK_MARKER in hook_body,
            f"the installer wrote {installed.name!r} without its own marker",
        )
        require(
            PREPUSH_CASE_ID,
            hook_mode == 0o755,
            f"the hook is mode {oct(hook_mode)}, so git would refuse to run it",
        )
        require(
            PREPUSH_CASE_ID,
            f"exec sudo python3 -m {pre_push.GATE_MODULE}" in hook_body,
            "the hook does not run the gate, so `git push` would not be judged by it",
        )
        foreign_hooks = root / "foreign-hooks"
        foreign_hooks.mkdir()
        foreign = foreign_hooks / "pre-push"
        foreign_body = "#!/bin/sh\necho somebody else's hook\n"
        foreign.write_text(foreign_body, encoding="utf-8")
        try:
            pre_push.install_hook(foreign_hooks)
        except FileExistsError as error:
            foreign_refusal = str(error)
        else:
            raise AssertionError(
                f"{PREPUSH_CASE_ID}: a hook this gate did not write was replaced, so whatever it did "
                "is now hidden"
            )
        require(
            PREPUSH_CASE_ID,
            foreign.read_text(encoding="utf-8") == foreign_body,
            "the refused install changed the foreign hook it refused to replace",
        )

    return {
        "blocked_exit": blocked["status"],
        "blocked_sentence": blocked["err"].strip().splitlines()[0],
        "credential_tokens": "0",
        "foreign_hook_refused": "True",
        "gated_topologies": ",".join(topologies),
        "green_exit": green["status"],
        "hook_marker_present": str(pre_push.HOOK_MARKER in hook_body),
        "hook_mode": oct(hook_mode),
        "host_tokens": "0",
        "manifest_damage_topologies": ",".join(pre_push.pre_push_topologies(damaged)),
        "nonroot_exit": nonroot["status"],
        "nonroot_sentence": nonroot["err"].strip().splitlines()[-1],
        "not_run_named": topologies[1],
        "overrun_exit": overrun["status"],
        "overrun_sentence": overrun["err"].strip().splitlines()[0],
        "suite_arguments": ";".join(" ".join(command[1:]) for command in commands.values()),
        "tier_budget_seconds": str(tier_budget),
        "topology_budgets": ",".join(
            f"{topology}={budget}" for topology, budget in sorted(topology_budgets.items())
        ),
        "unrun_topology_started": str(children[topologies[1]][1].is_file()),
        "suite_streams_captured": "False",
        "foreign_hook_refusal": foreign_refusal,
    }


# --- GATE-COVERAGE -----------------------------------------------------------


def _behavior(inventory: Dict[str, Any], name: str) -> Dict[str, Any]:
    for entry in inventory.get("behaviors") or []:
        if isinstance(entry, dict) and entry.get("name") == name:
            return entry
    raise AssertionError(f"the inventory no longer holds the behaviour {name!r}")


def case_coverage_audit(product: Any, context: Any) -> Dict[str, Any]:
    """``GATE-COVERAGE``: the inventory is a partition, and each way it can fail is named."""
    document = catalog_data.load_catalog()
    inventory = catalog_data.load_behaviors()
    behaviors = [entry for entry in inventory.get("behaviors") or [] if isinstance(entry, dict)]
    cases = document.get("cases") or []

    baseline = catalog_data.coverage_audit(document)
    require(
        COVERAGE_CASE_ID,
        baseline == [],
        f"the checked-in inventory fails its own audit ({baseline[:3]}), so every refusal below "
        "would be indistinguishable from the tree's own state",
    )
    require(
        COVERAGE_CASE_ID,
        len(behaviors) >= 2 and len(cases) >= len(behaviors),
        f"the inventory names {len(behaviors)} behaviour(s) over {len(cases)} case(s), so it is not "
        "the partition the audit exists to check",
    )

    no_case_target = next((entry for entry in behaviors if len(entry.get("cases") or []) > 1), None)
    happy_target = next(
        (
            entry
            for entry in behaviors
            if entry.get("error_paths") and entry is not no_case_target
        ),
        None,
    )
    require(
        COVERAGE_CASE_ID,
        no_case_target is not None and happy_target is not None,
        "the inventory holds no behaviour with more than one case or with an error path, so the "
        "damages below would have nothing to damage",
    )

    def audit(mutate: Callable[[Dict[str, Any]], None], path: Path) -> List[str]:
        damaged = copy.deepcopy(inventory)
        mutate(damaged)
        path.write_text(yaml.safe_dump(damaged, sort_keys=False), encoding="utf-8")
        return catalog_data.coverage_audit(document, behaviors_path=path)

    with tempfile.TemporaryDirectory(prefix="gowave-coverage-") as directory:
        root = Path(directory)

        no_case_name = str(no_case_target["name"])
        no_case = audit(
            lambda damaged: _behavior(damaged, no_case_name).__setitem__("cases", []),
            root / "no-case.yaml",
        )
        no_case_message = f"Behavior has no case: {no_case_name}"
        require(
            COVERAGE_CASE_ID,
            no_case_message in no_case,
            f"a behaviour that names no case was judged as {no_case[:3]}, which does not name it: "
            "an empty promise would pass the audit",
        )

        happy_name = str(happy_target["name"])
        happy_only = audit(
            lambda damaged: _behavior(damaged, happy_name).__setitem__("error_paths", []),
            root / "happy-only.yaml",
        )
        happy_message = f"Behavior has no error-path case: {happy_name}"
        require(
            COVERAGE_CASE_ID,
            happy_message in happy_only,
            f"a behaviour left with only its happy path was judged as {happy_only[:3]}, which does "
            "not name it: an unmeasured failure behaviour would pass the audit",
        )

        orphan = str(no_case_target["cases"][0])
        orphan_audit = audit(
            lambda damaged: _behavior(damaged, no_case_name)["cases"].remove(orphan),
            root / "orphan.yaml",
        )
        orphan_message = f"Case is mapped to no behavior: {orphan}"
        require(
            COVERAGE_CASE_ID,
            orphan_message in orphan_audit,
            f"a case no behaviour names was judged as {orphan_audit[:3]}, which does not name it: a "
            "guarantee nobody wrote down would pass the audit",
        )

    return {
        "baseline_errors": str(len(baseline)),
        "behaviors": str(len(behaviors)),
        "catalog_cases": str(len(cases)),
        "damaged_inventories": "happy_path_only,no_case,orphan",
        "happy_path_only_message": happy_message,
        "no_case_message": no_case_message,
        "orphan_message": orphan_message,
    }


# --- GATE-DIVERGENCE ---------------------------------------------------------


def _results(path: Path, case_id: str) -> Path:
    """A result file naming one executed case, in the shape the runner writes."""
    path.write_text(
        json.dumps(
            {
                "schema": "gowave-podman-e2e-result/v1",
                "cases": [{"id": case_id, "status": "PASS"}],
            }
        ),
        encoding="utf-8",
    )
    return path


def case_divergence_guard(product: Any, context: Any) -> Dict[str, Any]:
    """``GATE-DIVERGENCE``: a spec entry, a one-suite case and a shifted count are each named."""
    document = catalog_data.load_catalog()
    live_parity = next(
        (
            case
            for case in document.get("cases") or []
            if case.get("state") == "live-parity" and "podman" in (case.get("runs_in") or [])
        ),
        None,
    )
    require(
        DIVERGENCE_CASE_ID,
        live_parity is not None,
        "the catalog holds no live-parity case the Podman suite runs, so the one-suite damage below "
        "would have nothing to damage",
    )
    case_id = str(live_parity["id"])

    baseline = catalog_data.divergence_guard()
    require(
        DIVERGENCE_CASE_ID,
        baseline == [],
        f"the checked-in catalog diverges from the spec and the matrix ({baseline[:3]}), so every "
        "refusal below would be indistinguishable from the tree's own state",
    )

    with tempfile.TemporaryDirectory(prefix="gowave-divergence-") as directory:
        root = Path(directory)

        # A scenario the spec states and the catalog does not define.
        spec = root / "spec.md"
        spec.write_text(
            catalog_data.LIVE_SPEC.read_text(encoding="utf-8")
            + "\n### Requirement: Probe requirement\n\n"
            + "#### Scenario: A scenario the catalog does not hold\n\n"
            + "- **WHEN** the guard reads the spec\n"
            + "- **THEN** it names this scenario as one no catalog entry covers\n",
            encoding="utf-8",
        )
        unlisted = catalog_data.divergence_guard(spec_path=spec)
        unlisted_message = (
            "Live scenario has no catalog entry: Probe requirement / "
            "A scenario the catalog does not hold"
        )
        require(
            DIVERGENCE_CASE_ID,
            unlisted_message in unlisted,
            f"a live scenario with no catalog entry was judged as {unlisted[:3]}, which does not name "
            "it: a spec sentence nobody mapped would pass the guard",
        )

        # The same live-parity case executed by the live suite alone.
        live_only = _results(root / "live-only.json", case_id)
        both = _results(root / "both.json", case_id)
        one_suite = catalog_data.divergence_guard(live_results=[live_only])
        one_suite_message = f"live-parity case was not executed by the Podman suite: {case_id}"
        require(
            DIVERGENCE_CASE_ID,
            one_suite_message in one_suite,
            f"a live-parity case the Podman suite never ran was judged as {one_suite[:3]}, which does "
            "not name it: the container half could be deleted with the live half still green",
        )
        control = catalog_data.divergence_guard(
            podman_results=[both], live_results=[live_only]
        )
        require(
            DIVERGENCE_CASE_ID,
            control == [],
            f"the same case executed by both suites was still refused ({control[:3]}), so the "
            "one-suite refusal above does not depend on which suites ran",
        )

        # A topology whose positive-case count left the matrix.
        shifted = copy.deepcopy(document)
        counts = shifted["expected_positive_case_counts"]["aio"]
        field = sorted(counts)[0]
        counts[field] = counts[field] + 1
        shifted_path = root / "catalog.yaml"
        catalog_data.write_catalog(shifted, shifted_path)
        drift = catalog_data.divergence_guard(catalog_path=shifted_path)
        drift_message = "Positive case counts diverge between catalog and matrix for aio: "
        require(
            DIVERGENCE_CASE_ID,
            any(error.startswith(drift_message) for error in drift),
            f"a topology count that left the matrix was judged as {drift[:3]}, which does not name "
            "the topology: a case dropped from the suite would leave the counts to disagree silently",
        )
        drift_sentence = next(error for error in drift if error.startswith(drift_message))

    return {
        "baseline_errors": str(len(baseline)),
        "control_errors": str(len(control)),
        "count_divergence": drift_sentence,
        "damaged_inputs": "counts,one_suite,spec",
        "live_parity_case": case_id,
        "one_suite_message": one_suite_message,
        "unlisted_scenario": unlisted_message,
    }
