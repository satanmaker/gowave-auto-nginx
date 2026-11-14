#!/usr/bin/env python3
"""Suite nonroot: normal CI cannot reach a live VPS and needs no live credential.

The live acceptance run is launched by the operator from their own workstation
(`docs/LIVE_VPS_TESTING.md`); repository CI runs unit tests and container gates
only. That is a property of the workflow files, not a habit: a step that shelled
out to `tools/run_live_vps.py`, or a `${{ secrets.* }}` that could carry a target
password, would make every push able to touch someone else's server. These tests
read the workflows back and refuse that shape.
"""
import ipaddress
import re
import subprocess
import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

# Programs that would let a job act on a machine outside the runner. The list is
# about the shell a step gets, not about the products: the podman gates drive
# containers through podman, and the QEMU gate drives a local image.
REMOTE_PROGRAMS = ("ssh", "scp", "sftp", "rsync", "ansible", "paramiko", "sshpass")
DOCUMENTATION_NETS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)


def documents():
    return {path.name: yaml.safe_load(path.read_text(encoding="utf-8")) for path in sorted(WORKFLOWS.glob("*.yml"))}


def run_commands(document):
    for job in document["jobs"].values():
        for step in job.get("steps", []):
            if "run" in step:
                yield step["run"]


class TestNormalCiIsolation(unittest.TestCase):
    def test_no_job_invokes_the_live_vps_controller(self):
        for name, document in documents().items():
            for command in run_commands(document):
                with self.subTest(workflow=name):
                    self.assertNotIn("run_live_vps", command)
                    self.assertNotIn("live_vps_config.env", command)

    def test_no_job_shells_out_to_a_remote_host(self):
        for name, document in documents().items():
            for command in run_commands(document):
                for program in REMOTE_PROGRAMS:
                    with self.subTest(workflow=name, program=program):
                        self.assertIsNone(
                            re.search(rf"(?<![\w-]){re.escape(program)}(?![\w-])", command),
                            f"{name} gives a step the {program} command",
                        )

    def test_no_workflow_reads_a_secret_or_a_repository_variable(self):
        for name, path in ((p.name, p) for p in sorted(WORKFLOWS.glob("*.yml"))):
            text = path.read_text(encoding="utf-8")
            with self.subTest(workflow=name):
                self.assertNotIn("secrets.", text)
                self.assertNotIn("secrets[", text)
                self.assertNotIn("vars.", text)
                self.assertNotIn("vars[", text)

    def test_every_workflow_asks_for_read_only_repository_access(self):
        for name, document in documents().items():
            with self.subTest(workflow=name):
                self.assertEqual(document.get("permissions"), {"contents": "read"})

    def test_the_live_runner_job_only_runs_unit_tests(self):
        document = documents()["live-vps-unit.yml"]
        allowed = (
            "python -m pip install --disable-pip-version-check -r tools/requirements-live-vps.txt",
            "python -m unittest discover -s tools/tests -p 'test_*.py' -v",
        )
        for command in run_commands(document):
            with self.subTest(command=command.strip()):
                self.assertIn(command.strip(), allowed)
        # The tests themselves are the only thing that runs; a mode flag or an
        # interpreter pointed at the controller would turn this into a live run.
        self.assertNotIn("--mode", "\n".join(run_commands(document)))

    def test_no_workflow_runs_on_a_schedule(self):
        # An unattended trigger would let a job act while nobody is watching;
        # today every gate answers a push, a pull request or an explicit dispatch.
        for name, document in documents().items():
            triggers = document[True] if True in document else document["on"]
            with self.subTest(workflow=name):
                self.assertLessEqual(set(triggers), {"push", "pull_request", "workflow_dispatch"})
                self.assertNotIn("schedule", triggers)

    def test_a_real_target_configuration_can_never_be_committed(self):
        ignored = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("tools/live_vps_config.env", ignored)
        tracked = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "ls-files", "tools/live_vps_config*"],
            capture_output=True, text=True, check=True, timeout=120,
        ).stdout.split()
        self.assertEqual(tracked, ["tools/live_vps_config.env.example"])

    def test_the_tracked_example_holds_no_real_target(self):
        example = (REPO_ROOT / "tools" / "live_vps_config.env.example").read_text(encoding="utf-8")
        addresses = re.findall(r"^(?:MASTER_IP|WORKER_IP)=(\S+)$", example, re.MULTILINE)
        self.assertEqual(len(addresses), 2, "the template must name both targets explicitly")
        for address in addresses:
            with self.subTest(address=address):
                parsed = ipaddress.ip_address(address)
                self.assertTrue(
                    any(parsed in network for network in DOCUMENTATION_NETS),
                    f"{address} is not a documentation address; the template must not point at a real host",
                )

    def test_the_guide_still_states_the_same_ci_contract(self):
        guide = (REPO_ROOT / "docs" / "LIVE_VPS_TESTING.md").read_text(encoding="utf-8")
        self.assertIn(
            "GitHub Actions runs repository CI and automated tests only; "
            "it does not receive target VPS passwords, temporary private keys, or known-hosts secrets.",
            guide,
        )


if __name__ == "__main__":
    unittest.main()
