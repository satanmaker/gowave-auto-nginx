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


DISCOVERY = REPO_ROOT / "docs" / "PODMAN_E2E_DISCOVERY.md"
OPERATOR = REPO_ROOT / "gowave-auto.sh"
CATALOG = REPO_ROOT / "tests" / "cases" / "catalog.yaml"
MATRIX = REPO_ROOT / "tests" / "cases" / "matrix.yaml"
CASE_ID = re.compile(r"\b(?:AIO|MN|NGX|SUB|ACME)-[A-Z0-9][A-Z0-9-]*")


def discovered() -> str:
    return DISCOVERY.read_text(encoding="utf-8")


def usage_words(pattern: str):
    """The command words a `Usage: gowave-auto.sh … {a|b|c}` line declares."""
    text = OPERATOR.read_text(encoding="utf-8")
    match = re.search(pattern, text)
    if match is None:
        raise AssertionError(f"no usage line matches {pattern!r}; the product's interface moved")
    words = []
    for word in match.group(1).split("|"):
        words.append(word.split("<", 1)[0].strip())
    return words


def manifest_topologies():
    return sorted(yaml.safe_load(MATRIX.read_text(encoding="utf-8"))["topologies"])


def catalog_ids():
    return {case["id"] for case in yaml.safe_load(CATALOG.read_text(encoding="utf-8"))["cases"]}


def entrypoint_rows():
    """The entrypoint a discovery table row is about, taking the first cell."""
    rows = []
    for line in discovered().splitlines():
        if line.startswith("| `"):
            rows.append(line.split("|")[1].strip().strip("`"))
    return rows


def row_for(word: str) -> bool:
    return any(row == word or row.startswith(f"{word} ") for row in entrypoint_rows())


class TestDiscoveryInventory(unittest.TestCase):
    """The product surface page says what the product and the manifest say.

    `docs/PODMAN_E2E_DISCOVERY.md` is where a reader checks whether a command
    the suite never runs is a deliberate gap. That answer is only worth reading
    while it matches the script, the manifest and the catalog, so each of those
    three is parsed here rather than quoted by hand.
    """

    def test_every_operator_subcommand_has_a_table_row(self):
        missing = [word for word in usage_words(r"Usage: gowave-auto\.sh \{([^}]+)\}") if not row_for(word)]
        self.assertEqual(missing, [], "a subcommand exists without its own row in the discovery table")

    def test_every_node_subcommand_has_a_table_row(self):
        words = usage_words(r"Usage: gowave-auto\.sh node \{([^}]+)\}")
        self.assertEqual(sorted(words), ["add", "list", "reapply", "rollback"])
        missing = [word for word in words if not row_for(f"node {word}")]
        self.assertEqual(missing, [], "a node subcommand exists without its own row in the discovery table")

    def test_every_declared_topology_appears_in_the_page(self):
        topologies = manifest_topologies()
        self.assertIn("multi-node", topologies)
        missing = [name for name in topologies if f"`{name}`" not in discovered()]
        self.assertEqual(missing, [], "the manifest declares a topology the discovery page does not name")

    def test_every_case_id_the_page_cites_exists_in_the_catalog(self):
        cited = set(CASE_ID.findall(discovered()))
        self.assertGreaterEqual(len(cited), 10, "the page cites almost no case ids, so it proves nothing")
        invented = sorted(cited - catalog_ids())
        self.assertEqual(invented, [], "the discovery page names a case id no suite declares")

    def test_the_guide_links_the_discovery_page(self):
        self.assertIn("docs/PODMAN_E2E_DISCOVERY.md", documented())


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

    def test_documented_budgets_are_the_matrix_values(self):
        matrix = yaml.safe_load((REPO_ROOT / "tests" / "cases" / "matrix.yaml").read_text(encoding="utf-8"))
        for topology, entry in matrix["topologies"].items():
            with self.subTest(topology=topology):
                self.assertIn(str(entry["runtime_budget_seconds"]), documented())
        for tier, key in (("pre-push", "pre_push_total_seconds"), ("9000", "pr_total_seconds")):
            with self.subTest(tier=tier):
                self.assertIn(tier, documented())
                self.assertIn(str(matrix["runtime_budget"][key]), documented())

    def test_the_guide_says_the_budget_is_a_ceiling(self):
        text = documented()
        self.assertIn("never raised", text)
        self.assertIn("may only tighten", text)
        self.assertIn("INCOMPLETE", text)

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
