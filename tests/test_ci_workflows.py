#!/usr/bin/env python3
"""Suite nonroot: the existing transport and QEMU gates stay independent.

The Podman product acceptance lives in its own workflow so a red case cannot
hide behind the fast lint contour. The reverse is just as important: the
transport testbed and the QEMU cold-boot matrix predate this suite and answer a
different question — a real boot and a real Master/Worker link, not a case in a
container. They must keep running on their own triggers and their own commands,
and the new workflow must not grow a copy that could drift from them.
"""
import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

# The four job names the repository ruleset requires. A rename here without the
# ruleset would leave a pull request waiting for a check that never reports.
REQUIRED_CHECK_JOBS = {
    "All-in-One Podman Acceptance",
    "Multi-Node Podman Acceptance",
    "All-in-One Lifecycle and Recovery Acceptance",
    "Multi-Node Lifecycle and Recovery Acceptance",
}


def load(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


class TestIndependentAcceptanceWorkflows(unittest.TestCase):
    def test_the_transport_and_qemu_jobs_keep_their_own_commands(self):
        workflow = load("systemd-acceptance.yml")
        jobs = workflow["jobs"]
        transport = jobs["multi-node-podman"]
        transport_runs = [
            step["run"] for step in transport["steps"] if "run" in step
        ]
        self.assertTrue(
            any("tests/podman_testbed.sh multi-node" in command for command in transport_runs),
            "the transport gate must keep running the testbed, not the product suite",
        )
        qemu = jobs["qemu-cold-boot"]
        qemu_runs = [step["run"] for step in qemu["steps"] if "run" in step]
        self.assertTrue(
            any("tests/systemd/boot.sh" in command for command in qemu_runs),
            "the cold-boot gate must keep booting a real image",
        )
        self.assertIn("qemu-system-x86", "\n".join(qemu_runs))
        matrix = qemu["strategy"]["matrix"]["include"]
        self.assertEqual(
            [entry["distro"] for entry in matrix],
            [
                "docker.io/library/ubuntu:24.04",
                "docker.io/library/ubuntu:26.04",
                "docker.io/library/debian:12",
                "docker.io/library/debian:13",
            ],
            "the cold-boot matrix must keep covering all four supported systems",
        )

    def test_the_transport_gate_still_runs_on_push_and_pull_request(self):
        workflow = load("systemd-acceptance.yml")
        triggers = workflow[True] if True in workflow else workflow["on"]
        for event in ("push", "pull_request", "workflow_dispatch"):
            self.assertIn(event, triggers, f"the independent gates must still run on {event}")

    def test_the_podman_workflow_does_not_copy_or_replace_the_old_gates(self):
        new = load("podman-acceptance.yml")
        old = load("systemd-acceptance.yml")
        new_names = {job["name"] for job in new["jobs"].values()}
        old_names = {job["name"] for job in old["jobs"].values()}
        self.assertEqual(new_names, REQUIRED_CHECK_JOBS)
        self.assertEqual(
            new_names & old_names, set(),
            "a job name shared with the old workflow would mask which gate reported",
        )
        self.assertNotIn("multi-node-podman", new["jobs"])
        self.assertNotIn("qemu-cold-boot", new["jobs"])

    def test_every_required_job_is_a_real_job_with_a_runner(self):
        workflow = load("podman-acceptance.yml")
        by_name = {job["name"]: job for job in workflow["jobs"].values()}
        self.assertEqual(set(by_name), REQUIRED_CHECK_JOBS)
        for name, job in by_name.items():
            with self.subTest(job=name):
                self.assertIn("runs-on", job)
                self.assertTrue(job.get("timeout-minutes"), "an unbounded job can hang a merge gate")

    def test_the_recovery_jobs_do_not_run_on_a_push(self):
        workflow = load("podman-acceptance.yml")
        for job_id in ("aio-lifecycle-recovery", "multi-node-lifecycle-recovery"):
            with self.subTest(job=job_id):
                condition = workflow["jobs"][job_id].get("if", "")
                self.assertIn("pull_request", condition)
                self.assertIn("workflow_dispatch", condition)

    def test_every_workflow_file_still_parses_and_declares_jobs(self):
        for path in sorted(WORKFLOWS.glob("*.yml")):
            with self.subTest(workflow=path.name):
                document = yaml.safe_load(path.read_text(encoding="utf-8"))
                self.assertIn("jobs", document)
                self.assertTrue(document["jobs"])


if __name__ == "__main__":
    unittest.main()
