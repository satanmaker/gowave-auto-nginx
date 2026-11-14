#!/usr/bin/env python3
"""Suite nonroot: the required checks, the workflow and the ruleset are one name.

`tests/test_ci_workflows.py` already pins the four job names and their commands.
This suite holds the other two copies: the checked-in gate contract
(`tests/cases/gates.yaml`) and, through a stubbed API payload, the live ruleset.
Every refusal is driven by damaging a document the audit just read, so a rule
that stops being enforced fails here rather than in a review of a workflow diff.
The aggregate is judged the same way: one passing run of each topology at one
commit is PASS, and anything less is refused by name.
"""
import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import gate, trace  # noqa: E402


def live_payload(contract):
    """The ruleset 27258177 as the API returns it, built from the contract."""
    ruleset = contract["ruleset"]
    return {
        "id": ruleset["id"],
        "name": ruleset["name"],
        "target": "branch",
        "enforcement": ruleset["enforcement"],
        "conditions": {"ref_name": {"include": list(ruleset["include"]), "exclude": []}},
        "bypass_actors": [dict(actor) for actor in ruleset["bypass_actors"]],
        "rules": [
            {
                "type": "required_status_checks",
                "parameters": {
                    "do_not_enforce_on_create": ruleset["do_not_enforce_on_create"],
                    "strict_required_status_checks_policy": ruleset[
                        "strict_required_status_checks_policy"
                    ],
                    "required_status_checks": [
                        {"context": name} for name in ruleset["required_status_checks"]
                    ],
                },
            }
        ],
    }


class TestPodmanGateContract(unittest.TestCase):
    """The gate as three documents, judged against each other."""

    def setUp(self):
        self.contract = gate.load_contract()
        self.document = gate.load_workflow(self.contract)

    def problems(self, contract=None, document=None):
        return gate.contract_problems(
            contract if contract is not None else self.contract,
            document if document is not None else self.document,
        )

    def job(self, document, name):
        for job in (document.get("jobs") or {}).values():
            if (job or {}).get("name") == name:
                return job
        raise AssertionError(f"no job named {name!r}")

    def test_the_contract_agrees_with_the_workflow(self):
        self.assertEqual(
            self.problems(), [],
            "the gate that ships with the repository must hold on its own tree",
        )

    def test_the_contract_requires_both_topologies_at_full_and_recovery_width(self):
        pairs = {(check["topology"], check["group"]) for check in self.contract["checks"]}
        self.assertEqual(
            pairs,
            {("aio", None), ("multi-node", None), ("aio", "recovery"), ("multi-node", "recovery")},
            "an aggregate that omits one topology would read green from the other's run",
        )
        self.assertEqual(
            sorted(self.contract["ruleset"]["required_status_checks"]),
            sorted(check["name"] for check in self.contract["checks"]),
        )

    def test_a_required_check_no_job_publishes_is_refused(self):
        contract = copy.deepcopy(self.contract)
        contract["checks"][1]["name"] = "Multi-Node Podman Acceptance (renamed)"
        contract["ruleset"]["required_status_checks"][1] = "Multi-Node Podman Acceptance (renamed)"
        problems = self.problems(contract)
        self.assertTrue(
            any("(renamed)" in problem and "runs the acceptance suite" in problem
                for problem in problems),
            problems,
        )

    def test_a_job_that_runs_the_other_topology_is_refused(self):
        document = copy.deepcopy(self.document)
        job = self.job(document, "Multi-Node Podman Acceptance")
        for step in job["steps"]:
            if "--topology multi-node" in str(step.get("run") or ""):
                step["run"] = str(step["run"]).replace("--topology multi-node", "--topology aio")
        problems = self.problems(document=document)
        self.assertTrue(
            any("required for multi-node but the job runs ['aio']" in problem
                for problem in problems),
            problems,
        )

    def test_a_job_that_runs_both_topologies_is_refused(self):
        document = copy.deepcopy(self.document)
        job = self.job(document, "Multi-Node Podman Acceptance")
        job["steps"].append({"name": "And the other one", "run": (
            "sudo python3 -m tools.run_podman_e2e --topology aio"
        )})
        problems = self.problems(document=document)
        self.assertTrue(
            any("required for multi-node but the job runs" in problem for problem in problems),
            problems,
        )

    def test_a_recovery_job_that_also_runs_on_push_is_refused(self):
        document = copy.deepcopy(self.document)
        job = self.job(document, "All-in-One Lifecycle and Recovery Acceptance")
        job["if"] = f"{job['if']} || github.event_name == 'push'"
        problems = self.problems(document=document)
        self.assertTrue(
            any("runs on push although the contract does not promise it" in problem
                for problem in problems),
            problems,
        )

    def test_a_recovery_check_without_the_group_is_refused(self):
        contract = copy.deepcopy(self.contract)
        contract["checks"][2]["group"] = None
        problems = self.problems(contract)
        self.assertTrue(
            any("the job runs" in problem or "no required check runs the aio recovery" in problem
                for problem in problems),
            problems,
        )

    def test_a_raised_timeout_is_refused(self):
        document = copy.deepcopy(self.document)
        self.job(document, "Multi-Node Podman Acceptance")["timeout-minutes"] = 120
        problems = self.problems(document=document)
        self.assertTrue(
            any("declares 90 minutes, the job allows 120" in problem for problem in problems),
            problems,
        )

    def test_a_timeout_that_does_not_outlive_the_declared_budget_is_refused(self):
        # Both copies at 45 minutes agree with each other, so only the budget
        # rule can catch it: the suite would be allowed 2700 s inside a 2700 s
        # job, which leaves the setup and the artifact upload outside the ceiling.
        contract = copy.deepcopy(self.contract)
        document = copy.deepcopy(self.document)
        name = "All-in-One Podman Acceptance"
        for check in contract["checks"]:
            if check["name"] == name:
                check["timeout_minutes"] = 45
        self.job(document, name)["timeout-minutes"] = 45
        problems = self.problems(contract=contract, document=document)
        self.assertTrue(
            any(f"{name!r} allows 45 minutes" in problem and "declared budget is 2700s" in problem
                for problem in problems),
            problems,
        )

    def budget_problems(self, doctor):
        manifest = copy.deepcopy(gate.matrix.load())
        doctor(manifest)
        with unittest.mock.patch.object(gate.matrix, "load", return_value=manifest):
            return gate._budget_problems(self.contract)

    def test_a_topology_budget_that_breaks_the_pre_push_total_is_refused(self):
        problems = self.budget_problems(
            lambda manifest: manifest["topologies"]["aio"].__setitem__("runtime_budget_seconds", 3000)
        )
        self.assertTrue(
            any("declares 7500s of budget, past runtime_budget.pre_push_total_seconds = 7200s"
                in problem for problem in problems),
            problems,
        )

    def test_a_topology_budget_that_breaks_the_pull_request_wave_is_refused(self):
        problems = self.budget_problems(
            lambda manifest: manifest["topologies"]["multi-node"].__setitem__(
                "runtime_budget_seconds", 4600
            )
        )
        self.assertTrue(
            any("one full wave plus one recovery wave declares 9200s" in problem
                and "pr_total_seconds = 9000s" in problem
                for problem in problems),
            problems,
        )

    def test_a_manifest_without_a_declared_budget_is_refused(self):
        problems = self.budget_problems(
            lambda manifest: manifest["topologies"]["aio"].pop("runtime_budget_seconds")
        )
        self.assertTrue(
            any("no runtime_budget_seconds for 'aio'" in problem for problem in problems),
            problems,
        )

    def test_a_suite_job_the_ruleset_does_not_require_is_refused(self):
        document = copy.deepcopy(self.document)
        document["jobs"]["nightly-only"] = {
            "name": "Nightly Podman Acceptance",
            "runs-on": "ubuntu-24.04",
            "steps": [{"run": "sudo python3 -m tools.run_podman_e2e --topology aio"}],
        }
        problems = self.problems(document=document)
        self.assertTrue(
            any("Nightly Podman Acceptance" in problem and "does not require it" in problem
                for problem in problems),
            problems,
        )

    def test_a_report_uploaded_under_another_name_is_refused(self):
        document = copy.deepcopy(self.document)
        job = self.job(document, "All-in-One Podman Acceptance")
        for step in job["steps"]:
            if str(step.get("uses") or "").startswith("actions/upload-artifact"):
                step["with"]["name"] = "podman-run-${{ github.run_id }}"
        problems = self.problems(document=document)
        self.assertTrue(
            any("promises report podman-aio-*" in problem for problem in problems), problems
        )

    def test_a_path_filter_on_the_pull_request_trigger_is_refused(self):
        document = copy.deepcopy(self.document)
        block = gate.triggers(document)
        block["pull_request"] = {"branches": ["main"], "paths": ["gowave-auto.sh"]}
        document["on"] = block
        problems = self.problems(document=document)
        self.assertTrue(
            any("pull_request trigger filters paths" in problem for problem in problems),
            problems,
        )

    def test_a_lifecycle_path_the_tree_does_not_hold_is_refused(self):
        contract = copy.deepcopy(self.contract)
        contract["lifecycle_paths"].append("config/nonexistent.service")
        problems = self.problems(contract)
        self.assertTrue(
            any("config/nonexistent.service: no such path" in problem for problem in problems),
            problems,
        )

    def test_a_contract_without_lifecycle_paths_is_refused(self):
        contract = copy.deepcopy(self.contract)
        contract["lifecycle_paths"] = []
        problems = self.problems(contract)
        self.assertTrue(
            any("names no lifecycle path" in problem for problem in problems), problems
        )

    def test_the_live_ruleset_is_the_contract(self):
        self.assertEqual(gate.live_problems(self.contract, live_payload(self.contract)), [])

    def test_a_live_ruleset_missing_one_context_is_refused(self):
        payload = live_payload(self.contract)
        payload["rules"][0]["parameters"]["required_status_checks"].pop()
        problems = gate.live_problems(self.contract, payload)
        self.assertTrue(
            any("the live ruleset requires" in problem and "contract records" in problem
                for problem in problems),
            problems,
        )

    def test_a_disabled_live_ruleset_is_refused(self):
        payload = live_payload(self.contract)
        payload["enforcement"] = "evaluate"
        problems = gate.live_problems(self.contract, payload)
        self.assertTrue(
            any("enforcement 'evaluate'" in problem for problem in problems), problems
        )

    def test_a_live_ruleset_on_another_ref_is_refused(self):
        payload = live_payload(self.contract)
        payload["conditions"]["ref_name"]["include"].append("refs/heads/topic")
        problems = gate.live_problems(self.contract, payload)
        self.assertTrue(
            any("refs/heads/topic" in problem for problem in problems), problems
        )

    def test_a_changed_bypass_actor_is_refused(self):
        payload = live_payload(self.contract)
        payload["bypass_actors"][0]["bypass_mode"] = "pull_request"
        problems = gate.live_problems(self.contract, payload)
        self.assertTrue(
            any("the live ruleset bypasses" in problem for problem in problems), problems
        )

    def make_run(self, root, topology, count=None, status="PASS", overall="PASS",
                 commit="a" * 40):
        """A finished run of ``topology`` with the shape ``result.json`` has."""
        declared = trace.declared_cases()[topology]
        ids = [case for case in declared if "-DP-" in case]
        if count is not None:
            ids = ids[:count]
        vision = "disabled" if topology == "aio" else "neither"
        result = {
            "schema": "gowave-podman-e2e-result/v1",
            "run_id": f"podman-{topology}-stub",
            "topology": topology,
            "environment": {
                "vision": vision,
                "repository": {"commit": commit, "tree": "clean"},
            },
            "cases": [{"id": case_id, "status": status} for case_id in ids],
            "overall": overall,
        }
        run = Path(root) / f"podman-{topology}-stub"
        run.mkdir(parents=True, exist_ok=True)
        (run / "result.json").write_text(json.dumps(result), encoding="utf-8")
        return run

    def test_the_aggregate_accepts_one_passing_run_of_each_topology(self):
        with tempfile.TemporaryDirectory() as directory:
            for topology in gate.TOPOLOGIES:
                self.make_run(directory, topology)
            self.assertEqual(gate.aggregate_problems(Path(directory)), [])

    def test_the_aggregate_refuses_a_missing_topology(self):
        with tempfile.TemporaryDirectory() as directory:
            self.make_run(directory, "aio")
            problems = gate.aggregate_problems(Path(directory))
        self.assertTrue(
            any("no multi-node run finished" in problem for problem in problems), problems
        )

    def test_the_aggregate_refuses_a_topology_that_did_not_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            self.make_run(directory, "aio")
            self.make_run(directory, "multi-node", overall="FAIL")
            problems = gate.aggregate_problems(Path(directory))
        self.assertTrue(
            any("overall is 'FAIL'" in problem for problem in problems), problems
        )

    def test_the_aggregate_refuses_two_commits(self):
        with tempfile.TemporaryDirectory() as directory:
            self.make_run(directory, "aio", commit="a" * 40)
            self.make_run(directory, "multi-node", commit="b" * 40)
            problems = gate.aggregate_problems(Path(directory))
        self.assertTrue(
            any("measured different commits" in problem for problem in problems), problems
        )

    def test_the_aggregate_refuses_a_short_suite(self):
        with tempfile.TemporaryDirectory() as directory:
            self.make_run(directory, "aio", count=7)
            self.make_run(directory, "multi-node")
            problems = gate.aggregate_problems(Path(directory))
        self.assertTrue(
            any("owes 8 positive cases for aio/disabled" in problem for problem in problems),
            problems,
        )

    def test_a_root_with_no_finished_run_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            problems = gate.aggregate_problems(Path(directory))
        self.assertTrue(any("holds no finished run" in problem for problem in problems), problems)

    def test_the_entrypoint_judges_the_contract_and_needs_a_mode(self):
        with contextlib.redirect_stdout(io.StringIO()) as printed:
            self.assertEqual(gate.main(["--check"]), 0)
        self.assertIn("4 required checks agree with the workflow", printed.getvalue())
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                gate.main([])
        self.assertEqual(raised.exception.code, 2)

    def test_the_entrypoint_judges_an_artifact_root(self):
        with tempfile.TemporaryDirectory() as directory:
            for topology in gate.TOPOLOGIES:
                self.make_run(directory, topology)
            with contextlib.redirect_stdout(io.StringIO()) as printed:
                self.assertEqual(gate.main(["--artifacts", directory]), 0)
            self.assertIn("both topologies passed at one commit", printed.getvalue())
            self.make_run(directory, "multi-node", overall="FAIL")
            with contextlib.redirect_stdout(io.StringIO()) as printed:
                self.assertEqual(gate.main(["--artifacts", directory]), 1)
            self.assertIn("overall is 'FAIL'", printed.getvalue())


if __name__ == "__main__":
    unittest.main()
