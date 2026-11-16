#!/usr/bin/env python3
"""Suite nonroot: the run id and the resume gate, and what each case watches refuse.

``STATE-01``/``STATE-02`` of ``openspec/specs/live-vps-e2e/spec.md`` make two
promises a container can witness without a VPS: a run id cannot name a directory
outside ``artifacts/live-vps/``, and a partial phase resumes only the run that
wrote the record it was handed. Both are the product's own functions —
``tools/live_vps/runstate.py`` reads them, and ``tools/test_live_vps.py`` calls
them before it creates a directory, opens an SSH client, or starts a phase.

What is real here is every clause the two cases state: the artifact root is a
real directory, the hostile ids are real strings handed to the real validator,
the record is written by the product's own ``save_run_state`` at mode 0600 and
read back by its own ``load_run_state``, and the baselines are the product's
manifest shape. What is not real is a pair of VPS — no case here opens a
connection, and the source-order guards are what say the CLI cannot have reached
one before the answer it got.

Then each clause is damaged on its own — a validator that rewrites the id it was
asked to accept, an artifact path that creates the directory it was only asked to
name, a gate that accepts or refuses everything, a drift comparison that never
moves, a record left world readable, a repository copied before the baseline is
re-checked, a statement moved in the runner — so every assertion is held by the
side it protects rather than by the case's own prose.
"""
import contextlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import yaml  # noqa: E402

from tools import test_live_vps  # noqa: E402
from tools.live_vps.runstate import ResumeVerdict  # noqa: E402
from tools.podman_e2e import aio, catalog, multi_node, runstate_cases  # noqa: E402

TOPOLOGIES = ("aio", "multi-node")

ALL_CASES = {
    runstate_cases.RUN_ID_CASE_ID: runstate_cases.case_run_id_root,
    runstate_cases.RESUME_CASE_ID: runstate_cases.case_resume_gate,
}

#: The statements the source-order guards read out of ``tools/test_live_vps.py``.
#: A damage moves one of them; the anchor text is the product's, not this file's.
VALIDATE_ANCHOR = "artifact_dir = artifact_path(artifact_root, run_id)"
MKDIR_ANCHOR = "artifact_dir.mkdir(parents=True, mode=0o700)"
SSH_ANCHOR = "master_ssh = SSHClient("
DRIFT_ANCHOR = "drift = baseline_drift("
PREP_ANCHOR = "prep_ok = prepare_master_repository(master_ssh, REPO_ROOT)"

#: What each damage is meant to make a case say. The parent asserts the case
#: refused *for that reason*, not merely that it failed: a case that goes red on
#: an unrelated assertion holds nothing.
EXPECTED_REFUSALS = {
    ("RUNID-01", "accepts-any-id"): "was accepted as a run id",
    ("RUNID-01", "rewrites-the-id"): "was refused although it matches the accepted shape",
    ("RUNID-01", "creates-the-directory"): "the caller creates the directory only after",
    ("RUNID-01", "mkdir-before-validation"): "creates the artifact directory before it validates",
    ("RUNID-01", "ssh-before-validation"): "opens an SSH client before it validates",
    ("RESUME-01", "gate-accepts"): "was accepted as a resumable phase",
    ("RESUME-01", "gate-refuses"): "was refused",
    ("RESUME-01", "drift-silent"): "was not reported as drift",
    ("RESUME-01", "drift-everything"): "was reported as drift",
    ("RESUME-01", "state-world-readable"): "permissions must not grant group or other access",
    ("RESUME-01", "state-mode-unchecked"): "is not world readable",
    ("RESUME-01", "repository-copied-first"): "copies the repository to the Master",
}


def _patched(module, **replacements):
    """One context manager that patches every named attribute of ``module``."""
    stack = contextlib.ExitStack()
    for name, value in replacements.items():
        stack.enter_context(mock.patch.object(module, name, value))
    return stack


def _artifact_path_that_accepts_any_id():
    """A path helper that names a directory without asking whether it may."""
    def path(artifact_root, run_id):
        return Path(artifact_root) / run_id
    return mock.patch.object(runstate_cases, "artifact_path", path)


def _validator_that_rewrites_the_id():
    """A validator that refuses what the real one refuses, and edits what it accepts."""
    original = runstate_cases.validate_run_id

    def validate(value):
        original(value)
        return f"{value}0"

    return mock.patch.object(runstate_cases, "validate_run_id", validate)


def _artifact_path_that_creates_the_directory():
    """A path helper that creates the directory it was only asked to name."""
    original = runstate_cases.artifact_path

    def path(artifact_root, run_id):
        candidate = original(artifact_root, run_id)
        candidate.mkdir(exist_ok=True)
        return candidate

    return mock.patch.object(runstate_cases, "artifact_path", path)


def _gate_that_accepts(*_args, **_kwargs):
    return ResumeVerdict(True, "")


def _gate_that_refuses(*_args, **_kwargs):
    return ResumeVerdict(False, "refused by the damaged gate")


def _drift_that_never_moves(*_args, **_kwargs):
    return ""


def _drift_that_always_moves(*_args, **_kwargs):
    return "master: existing_gowave_dirs moved"


def _state_written_world_readable():
    """A writer that leaves the record readable by everyone after it lands."""
    original = test_live_vps.save_run_state

    def save(artifact_dir, state):
        original(artifact_dir, state)
        (Path(artifact_dir) / "run-state.json").chmod(0o644)

    return mock.patch.object(test_live_vps, "save_run_state", save)


def _state_whose_mode_is_unchecked():
    """A writer and reader that both skip the mode the record is supposed to hold."""
    def save(artifact_dir, state):
        directory = Path(artifact_dir)
        directory.mkdir(parents=True, exist_ok=True)
        record = directory / "run-state.json"
        record.write_text(json.dumps(state, indent=2), encoding="utf-8")
        record.chmod(0o644)

    def load(artifact_dir):
        return json.loads(
            (Path(artifact_dir) / "run-state.json").read_text(encoding="utf-8"))

    return _patched(test_live_vps, save_run_state=save, load_run_state=load)


def _occurrences(lines, anchor):
    return [index for index, line in enumerate(lines) if anchor in line]


def _only(lines, anchor):
    hits = _occurrences(lines, anchor)
    if len(hits) != 1:
        raise AssertionError(
            f"the runner carries {len(hits)} lines with {anchor!r}, so a damage cannot "
            "move the one statement this probe is about"
        )
    return hits[0]


def _first(lines, anchor):
    hits = _occurrences(lines, anchor)
    if not hits:
        raise AssertionError(f"the runner carries no line with {anchor!r}")
    return hits[0]


def _statement(lines, start):
    """The whole statement that starts at ``start``, to its balanced close."""
    depth = 0
    for index in range(start, len(lines)):
        depth += lines[index].count("(") - lines[index].count(")")
        if depth <= 0:
            return lines[start:index + 1]
    raise AssertionError(f"the statement at {lines[start].strip()!r} never closes")


def _cut(lines, anchor):
    start = _only(lines, anchor)
    block = _statement(lines, start)
    return lines[:start] + lines[start + len(block):], block


def _mkdir_before_validation(lines):
    """The directory is created before the id that names it was validated."""
    rest, mkdir = _cut(lines, MKDIR_ANCHOR)
    validate = _first(rest, VALIDATE_ANCHOR)
    return rest[:validate] + mkdir + rest[validate:]


def _ssh_before_validation(lines):
    """The SSH client is opened before the id is validated; the mkdir stays after."""
    rest, ssh = _cut(lines, SSH_ANCHOR)
    rest, mkdir = _cut(rest, MKDIR_ANCHOR)
    validate = _first(rest, VALIDATE_ANCHOR)
    rest = rest[:validate + 1] + mkdir + rest[validate + 1:]
    return ssh + rest


def _repository_copied_first(lines):
    """The repository is copied to the Master before the baseline is re-checked."""
    rest, prep = _cut(lines, PREP_ANCHOR)
    drift = _only(rest, DRIFT_ANCHOR)
    return rest[:drift] + prep + rest[drift:]


@contextlib.contextmanager
def _runner_replaced(mutate):
    """Point the cases at a copy of the runner whose statements were moved.

    The guards read the file as text, so the copy is never imported: what the
    damage has to preserve is the anchor text and its order, not the file's
    ability to run.
    """
    lines = runstate_cases.RUNNER.read_text(encoding="utf-8").splitlines(keepends=True)
    with tempfile.TemporaryDirectory(prefix="gowave-runner-") as directory:
        copy = Path(directory) / runstate_cases.RUNNER.name
        copy.write_text("".join(mutate(list(lines))), encoding="utf-8")
        with mock.patch.object(runstate_cases, "RUNNER", copy):
            yield copy


DAMAGES = {
    "accepts-any-id": _artifact_path_that_accepts_any_id,
    "rewrites-the-id": _validator_that_rewrites_the_id,
    "creates-the-directory": _artifact_path_that_creates_the_directory,
    "mkdir-before-validation": lambda: _runner_replaced(_mkdir_before_validation),
    "ssh-before-validation": lambda: _runner_replaced(_ssh_before_validation),
    "gate-accepts": lambda: mock.patch.object(runstate_cases, "resume_gate", _gate_that_accepts),
    "gate-refuses": lambda: mock.patch.object(runstate_cases, "resume_gate", _gate_that_refuses),
    "drift-silent": lambda: mock.patch.object(
        runstate_cases, "baseline_drift", _drift_that_never_moves),
    "drift-everything": lambda: mock.patch.object(
        runstate_cases, "baseline_drift", _drift_that_always_moves),
    "state-world-readable": _state_written_world_readable,
    "state-mode-unchecked": _state_whose_mode_is_unchecked,
    "repository-copied-first": lambda: _runner_replaced(_repository_copied_first),
}


def run_case(case_id, topology="aio", damage=None):
    """Run one case, with one product behaviour damaged; return (facts, refusal)."""
    function = ALL_CASES[case_id]
    context = SimpleNamespace(topology=topology)
    try:
        if damage:
            with DAMAGES[damage]():
                return function(context), None
        return function(context), None
    except (AssertionError, PermissionError) as error:
        return None, str(error)


class TestRunStateCases(unittest.TestCase):
    """Both cases hold on both contours, and report only what the catalog records."""

    def test_the_cases_hold_on_both_contours(self):
        for topology in TOPOLOGIES:
            for case_id in ALL_CASES:
                with self.subTest(case_id=case_id, topology=topology):
                    facts, refusal = run_case(case_id, topology)
                    self.assertIsNone(refusal)
                    self.assertTrue(facts)

    def test_the_evidence_is_exactly_what_the_catalog_records(self):
        registry = catalog.driver_registry()
        for case_id in ALL_CASES:
            facts, _ = run_case(case_id, "aio")
            with self.subTest(case_id=case_id):
                self.assertEqual(sorted(facts), registry[case_id]["aio"]["evidence"])

    def test_an_artifact_path_that_accepts_any_id_is_refused(self):
        _, refusal = run_case("RUNID-01", damage="accepts-any-id")
        self.assertIn(EXPECTED_REFUSALS[("RUNID-01", "accepts-any-id")], refusal)

    def test_a_validator_that_rewrites_the_id_is_refused(self):
        _, refusal = run_case("RUNID-01", damage="rewrites-the-id")
        self.assertIn(EXPECTED_REFUSALS[("RUNID-01", "rewrites-the-id")], refusal)

    def test_an_artifact_path_that_creates_the_directory_is_refused(self):
        _, refusal = run_case("RUNID-01", damage="creates-the-directory")
        self.assertIn(EXPECTED_REFUSALS[("RUNID-01", "creates-the-directory")], refusal)

    def test_a_runner_that_creates_the_directory_before_validating_is_refused(self):
        _, refusal = run_case("RUNID-01", damage="mkdir-before-validation")
        self.assertIn(EXPECTED_REFUSALS[("RUNID-01", "mkdir-before-validation")], refusal)

    def test_a_runner_that_opens_a_client_before_validating_is_refused(self):
        _, refusal = run_case("RUNID-01", damage="ssh-before-validation")
        self.assertIn(EXPECTED_REFUSALS[("RUNID-01", "ssh-before-validation")], refusal)

    def test_a_gate_that_accepts_everything_is_refused(self):
        _, refusal = run_case("RESUME-01", damage="gate-accepts")
        self.assertIn(EXPECTED_REFUSALS[("RESUME-01", "gate-accepts")], refusal)

    def test_a_gate_that_refuses_everything_is_refused(self):
        _, refusal = run_case("RESUME-01", damage="gate-refuses")
        self.assertIn(EXPECTED_REFUSALS[("RESUME-01", "gate-refuses")], refusal)

    def test_a_drift_comparison_that_never_moves_is_refused(self):
        _, refusal = run_case("RESUME-01", damage="drift-silent")
        self.assertIn(EXPECTED_REFUSALS[("RESUME-01", "drift-silent")], refusal)

    def test_a_drift_comparison_that_always_moves_is_refused(self):
        _, refusal = run_case("RESUME-01", damage="drift-everything")
        self.assertIn(EXPECTED_REFUSALS[("RESUME-01", "drift-everything")], refusal)

    def test_a_world_readable_record_is_refused(self):
        _, refusal = run_case("RESUME-01", damage="state-world-readable")
        self.assertIn(EXPECTED_REFUSALS[("RESUME-01", "state-world-readable")], refusal)

    def test_a_record_whose_mode_is_unchecked_is_refused(self):
        _, refusal = run_case("RESUME-01", damage="state-mode-unchecked")
        self.assertIn(EXPECTED_REFUSALS[("RESUME-01", "state-mode-unchecked")], refusal)

    def test_a_runner_that_copies_the_repository_first_is_refused(self):
        _, refusal = run_case("RESUME-01", damage="repository-copied-first")
        self.assertIn(EXPECTED_REFUSALS[("RESUME-01", "repository-copied-first")], refusal)


class TestRunStateRegistration(unittest.TestCase):
    """The two ids are registered, catalogued, declared and mapped, from one source."""

    def test_every_id_is_registered_on_both_contours_with_its_own_callable(self):
        registry = catalog.driver_registry()
        for case_id, function in ALL_CASES.items():
            with self.subTest(case_id=case_id):
                self.assertIn(case_id, registry)
                self.assertEqual(set(registry[case_id]), set(TOPOLOGIES))
                for topology in TOPOLOGIES:
                    entry = registry[case_id][topology]
                    self.assertEqual(
                        entry["driver"], f"runstate_cases:{function.__name__}",
                        f"{case_id} / {topology} runs a different callable than the "
                        "module exports",
                    )

    def test_the_catalog_entry_is_what_the_registry_derives(self):
        registry = catalog.driver_registry()
        entries = {entry["id"]: entry for entry in catalog.load_catalog()["cases"]}
        for case_id in ALL_CASES:
            with self.subTest(case_id=case_id):
                entry = entries[case_id]
                self.assertEqual(entry["driver_status"], "implemented")
                self.assertEqual(entry["environment"], "container")
                self.assertEqual(entry["drivers"], registry[case_id])

    def test_both_suites_declare_the_cases(self):
        stub = SimpleNamespace(context=SimpleNamespace())
        for topology, suite in (("aio", aio.cases(stub)),
                                ("multi-node", multi_node.cases(stub))):
            declared = {(case.id, case.topology) for case in suite}
            for case_id in ALL_CASES:
                with self.subTest(case_id=case_id, topology=topology):
                    self.assertIn((case_id, topology), declared)

    def test_the_live_scenarios_are_observed_by_these_cases(self):
        self.assertEqual(
            catalog.LIVE_PARITY_OBSERVERS["STATE-01"],
            {"aio": runstate_cases.RUN_ID_CASE_ID,
             "multi-node": runstate_cases.RUN_ID_CASE_ID},
        )
        self.assertEqual(
            catalog.LIVE_PARITY_OBSERVERS["STATE-02"],
            {"aio": runstate_cases.RESUME_CASE_ID,
             "multi-node": runstate_cases.RESUME_CASE_ID},
        )

    def test_the_behaviour_inventory_covers_them(self):
        self.assertEqual(catalog.coverage_audit(catalog.load_catalog()), [])

    def test_every_id_is_mapped_to_a_requirement(self):
        table = yaml.safe_load(
            (REPO_ROOT / "tests" / "cases" / "traceability.yaml").read_text(encoding="utf-8"))
        mapped = set()
        for row in table["requirements"]:
            for scenario in row["scenarios"]:
                mapped.update(scenario.get("cases") or [])
        for entry in table.get("cases_by_requirement") or []:
            mapped.update(entry.get("cases") or [])
        self.assertEqual(sorted(set(ALL_CASES) - mapped), [])


if __name__ == "__main__":
    unittest.main()
