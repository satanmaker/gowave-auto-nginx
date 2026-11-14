#!/usr/bin/env python3
"""Suite nonroot: the operator guide describes the suite that exists.

`docs/PODMAN_E2E.md` is the only place an operator learns how to run the gate,
what it spends, where its artifacts go and what it deletes. A guide that drifts
from the parser, from the diagnostics bundle or from the workflow is worse than
no guide: it sends the reader to a flag that was renamed and to a bundle that is
never written. These tests read the guide back against the code.
"""
import re
import shlex
import subprocess
import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools import run_podman_e2e  # noqa: E402
from tools.podman_e2e import diagnostics, target_image  # noqa: E402

DOC = REPO_ROOT / "docs" / "PODMAN_E2E.md"
ENTRYPOINT = "tools.run_podman_e2e"
FLAG = re.compile(r"--[a-z][a-z0-9-]*")


def documented() -> str:
    return DOC.read_text(encoding="utf-8")


def documented_invocations():
    """Every `sudo python3 -m tools.run_podman_e2e …` line, tokenized."""
    for line in documented().splitlines():
        stripped = line.strip()
        if not stripped.startswith(("python3 -m tools.run_podman_e2e", "sudo python3 -m tools.run_podman_e2e")):
            continue
        tokens = shlex.split(stripped)
        if tokens[:1] == ["sudo"]:
            tokens = tokens[1:]
        yield tokens[3:]


def documented_flags():
    return {
        token.split("=", 1)[0]
        for tokens in documented_invocations()
        for token in tokens
        if token.startswith("--")
    }


def documented_option_values(option: str):
    values = []
    for tokens in documented_invocations():
        for index, token in enumerate(tokens):
            if token == option and index + 1 < len(tokens):
                values.append(tokens[index + 1])
    return values


def parser_flags():
    completed = subprocess.run(
        [sys.executable, "-m", ENTRYPOINT, "--help"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=300, check=True,
    )
    return set(FLAG.findall(completed.stdout)) - {"--help"}


class TestPodmanE2EDocumentation(unittest.TestCase):
    def test_every_flag_in_a_documented_command_exists(self):
        unknown = sorted(documented_flags() - parser_flags())
        self.assertEqual(unknown, [], f"the guide invokes flags the parser does not declare: {unknown}")

    def test_every_parser_option_is_documented(self):
        undocumented = sorted(parser_flags() - set(FLAG.findall(documented())))
        self.assertEqual(undocumented, [], f"the parser declares options the guide never mentions: {undocumented}")

    def test_documented_topologies_and_distributions_are_the_real_choices(self):
        self.assertEqual(set(documented_option_values("--topology")) - set(run_podman_e2e.TOPOLOGIES), set())
        self.assertIn("aio", documented_option_values("--topology"))
        self.assertIn("multi-node", documented_option_values("--topology"))
        self.assertEqual(
            set(documented_option_values("--distribution")) - set(target_image.DISTRIBUTIONS), set()
        )
        for alias in target_image.DISTRIBUTIONS:
            with self.subTest(alias=alias):
                self.assertIn(alias, documented())

    def test_documented_budgets_are_the_defaults_and_the_matrix_values(self):
        for default in (run_podman_e2e.DEFAULT_BUDGET_SECONDS, run_podman_e2e.MULTI_NODE_BUDGET_SECONDS):
            with self.subTest(default=default):
                self.assertIn(str(default), documented())
        matrix = yaml.safe_load((REPO_ROOT / "tests" / "cases" / "matrix.yaml").read_text(encoding="utf-8"))
        for topology, entry in matrix["topologies"].items():
            with self.subTest(topology=topology):
                self.assertIn(str(entry["runtime_budget_seconds"]), documented())

    def test_the_guide_names_every_area_the_failure_bundle_writes(self):
        self.assertIn("index.txt", documented())
        for area in diagnostics.AREAS:
            with self.subTest(area=area.name):
                self.assertIn(f"`{area.name}.txt`", documented())

    def test_documented_retention_matches_the_workflow(self):
        workflow = yaml.safe_load(
            (REPO_ROOT / ".github" / "workflows" / "podman-acceptance.yml").read_text(encoding="utf-8")
        )
        retained = {
            step["with"]["retention-days"]
            for job in workflow["jobs"].values()
            for step in job["steps"]
            if step.get("uses", "").startswith("actions/upload-artifact")
        }
        self.assertEqual(retained, {14})
        self.assertIn(f"{14} days", documented())
        for job in workflow["jobs"].values():
            for step in job["steps"]:
                if not step.get("uses", "").startswith("actions/upload-artifact"):
                    continue
                self.assertIn(step["with"]["name"].split("-${{")[0], documented())

    def test_the_documented_run_directory_is_the_gitignored_artifact_root(self):
        self.assertIn("artifacts/podman-e2e", documented())
        ignored = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("artifacts/podman-e2e/", ignored, "a retained run directory must never be committable")

    def test_documented_stale_run_age_is_the_constant_the_code_uses(self):
        from tools.podman_e2e.podman import STALE_AFTER_SECONDS

        self.assertEqual(STALE_AFTER_SECONDS, 6 * 3600)
        self.assertIn("6 hours", documented())
        self.assertIn("reclaimed from stale runs", documented())

    def test_the_readme_points_at_the_guide(self):
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("docs/PODMAN_E2E.md", readme)


if __name__ == "__main__":
    unittest.main()
