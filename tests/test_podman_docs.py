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


BACKEND = REPO_ROOT / "sources" / "gowave" / "backend-go"
CLIENT = REPO_ROOT / "modules" / "api_client.py"
API_HEADING = "## The Panel API the suite is written to"
ENDPOINT = re.compile(r"`([A-Z]+) (/api/[^`]+)`")
DECLARATION = re.compile(r"`([\w./-]+\.go):(\d+)`")
CALL_SITE = re.compile(r"`((?:modules|tools)/[\w./-]+\.py):(\d+)`")
GO_VERB = {"get": "GET", "post": "POST", "patch": "PATCH", "put": "PUT", "delete": "DELETE"}
GO_ROUTE = re.compile(r'\.(Get|Post|Patch|Put|Delete)\("(/api/[^"]+)"')


def api_section() -> str:
    text = discovered()
    start = text.index(API_HEADING)
    return text[start : text.index("\n## ", start + len(API_HEADING))]


def normalised(path: str) -> str:
    """A route with its placeholder names erased, so `{uuid}` equals `{userId}`."""
    return re.sub(r"\{[^}]*\}", "{}", path)


def api_rows():
    """Each API table row as the four cells the page promises, whitespace removed."""
    rows = []
    for line in api_section().splitlines():
        if not line.startswith("| ") or line.startswith("| ---"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 4 or cells[1] == "Endpoint":
            continue
        rows.append({"area": cells[0], "endpoint": cells[1], "declaration": cells[2], "caller": cells[3]})
    return rows


def row_routes(row) -> set:
    return {(method, normalised(path)) for method, path in ENDPOINT.findall(row["endpoint"])}


def covers(mapped: str, called: str) -> bool:
    """Whether a mapped route answers a call: its placeholders stand for any segment."""
    mapped_parts = normalised(mapped).split("/")
    called_parts = normalised(called).split("/")
    if len(mapped_parts) != len(called_parts):
        return False
    return all(mapped_part in ("{}", called_part) for mapped_part, called_part in zip(mapped_parts, called_parts))


def page_routes() -> set:
    return {route for row in api_rows() for route in row_routes(row)}


def client_routes() -> set:
    """Every (method, path) `modules/api_client.py` asks the Panel to serve."""
    return {
        (method, normalised(path))
        for method, path in re.findall(r'"(GET|POST|PATCH|PUT|DELETE)",\s*f?"(/api/[^"]+)"', CLIENT.read_text(encoding="utf-8"))
    }


def backend_tree() -> bool:
    return (BACKEND / "internal" / "server" / "server.go").is_file()


def representation_paths():
    return yaml.safe_load(MATRIX.read_text(encoding="utf-8"))["representations"]


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


class TestPanelApiContract(unittest.TestCase):
    """The Panel API map on the discovery page is the map the code uses.

    A page that lists endpoints the product never calls, or omits one it does,
    reads as documentation and behaves as a trap: the reader checks the Panel
    against a route nothing uses, or debugs a call the page never mentions. The
    rows are therefore compared with `modules/api_client.py`, with the vendored
    Panel and with the representations the manifest declares, and each
    `file:line` is resolved rather than trusted.

    `sources/gowave` is a local checkout — `/sources/` is in `.gitignore` — so
    the two tests that read the Go declarations skip where the tree is absent,
    naming what did not run. Everything else runs in CI.
    """

    def test_the_page_maps_every_panel_call_the_product_makes(self):
        self.assertGreaterEqual(len(api_rows()), 25, "the API map has almost no rows, so it proves nothing")
        missing = sorted(client_routes() - page_routes())
        self.assertEqual(
            missing, [],
            "modules/api_client.py calls a route the discovery page does not map",
        )

    def test_every_row_cites_a_declaration_and_a_caller(self):
        areas = set()
        for row in api_rows():
            with self.subTest(endpoint=row["endpoint"]):
                self.assertEqual(len(ENDPOINT.findall(row["endpoint"])), 1, "a row must name exactly one endpoint")
                self.assertRegex(row["endpoint"], r"^`(GET|POST|PATCH|PUT|DELETE) /api/")
                self.assertTrue(DECLARATION.findall(row["declaration"]), "a row must cite the Go declaration")
                self.assertTrue(
                    CALL_SITE.findall(row["caller"]) or "none" in row["caller"],
                    "a row must cite its caller, or say none and why",
                )
                areas.add(row["area"])
        self.assertGreaterEqual(
            areas,
            {"authentication", "node registration", "provisioning", "client lifecycle", "update", "subscription"},
            "the map must keep the areas the product's flows are divided into",
        )

    def test_every_cited_client_line_makes_the_call_it_is_cited_for(self):
        for row in api_rows():
            expected = {path for _, path in row_routes(row)}
            for name, number in CALL_SITE.findall(row["caller"]):
                with self.subTest(caller=f"{name}:{number}"):
                    lines = (REPO_ROOT / name).read_text(encoding="utf-8").splitlines()
                    self.assertLessEqual(int(number), len(lines), f"{name}:{number} is past the end of the file")
                    cited = set(re.findall(r'"(/api/[^"]+)"', lines[int(number) - 1]))
                    self.assertTrue(
                        any(covers(mapped, call) for mapped in expected for call in cited),
                        f"{name}:{number} does not call {row['endpoint']}; it calls {sorted(cited)}",
                    )

    def test_the_cited_panel_tree_still_declares_every_route(self):
        if not backend_tree():
            self.skipTest(
                "sources/gowave is a local checkout (/sources/ is gitignored): "
                "the Go route declarations were not re-read in this run"
            )
        for row in api_rows():
            expected = row_routes(row)
            for name, number in DECLARATION.findall(row["declaration"]):
                with self.subTest(declaration=f"{name}:{number}"):
                    source = BACKEND / name
                    self.assertTrue(source.is_file(), f"{name} is not in the vendored Panel")
                    lines = source.read_text(encoding="utf-8").splitlines()
                    self.assertLessEqual(int(number), len(lines), f"{name}:{number} is past the end of the file")
                    declared = {(GO_VERB[verb.lower()], normalised(path)) for verb, path in GO_ROUTE.findall(lines[int(number) - 1])}
                    self.assertTrue(
                        declared & expected,
                        f"{name}:{number} declares {sorted(declared)} but the row promises {sorted(expected)}",
                    )

    def test_the_documented_panel_revision_is_the_one_in_the_tree(self):
        section = api_section()
        self.assertIn("sources/gowave/backend-go", section)
        revision = re.search(r"`v[\d.]+-\d+-g([0-9a-f]+)`", section)
        self.assertIsNotNone(revision, "the page does not pin the Panel revision its citations came from")
        if not (BACKEND.parent / ".git").exists():
            self.skipTest("sources/gowave carries no git metadata here: the documented revision was not compared")
        head = subprocess.run(
            ["git", "-C", str(BACKEND.parent), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=60, check=True,
        ).stdout.strip()
        self.assertEqual(
            revision.group(1), head,
            "the page was written against another revision of the vendored Panel; re-read it before trusting the map",
        )

    def test_every_manifest_representation_is_served_by_the_client_type_switch(self):
        representations = representation_paths()
        section = api_section()
        self.assertIn(("GET", normalised("/api/sub/{shortUuid}")), page_routes())
        self.assertIn(("GET", normalised("/api/sub/{shortUuid}/{clientType}")), page_routes())
        for name in representations:
            with self.subTest(representation=name):
                self.assertIn(f"`{name}`", section, "the map does not name a representation the manifest declares")
        if not backend_tree():
            self.skipTest(
                "sources/gowave is a local checkout (/sources/ is gitignored): "
                "the client-type switch was not re-read, so the suffix arms were not checked in this run"
            )
        switch = (BACKEND / "internal" / "subscription" / "srr.go").read_text(encoding="utf-8")
        arms = set(re.findall(r'case ((?:"[\w-]+"(?:, )?)+):', switch))
        served = {name.strip('"') for arm in arms for name in re.findall(r'"([\w-]+)"', arm)}
        self.assertIn("v2ray-json", served, "the handler's client-type switch moved; re-read the subscription route")
        for name, path in representations.items():
            with self.subTest(representation=name):
                segment = path.rstrip("/").rsplit("/", 1)[-1]
                if name == "base64":
                    self.assertEqual(segment, "{shortUuid}", "the base64 representation is not the bare route")
                    continue
                self.assertIn(
                    segment, served,
                    f"tests/cases/matrix.yaml asks for /{segment} but the Panel answers that arm with BLOCK",
                )

    def test_the_client_update_is_recorded_as_a_gap_not_as_not_applicable(self):
        rows = [row for row in api_rows() if "PATCH /api/users" in row["endpoint"]]
        self.assertEqual(len(rows), 2, "the map must record both client-update routes the pinned Panel serves")
        for row in rows:
            with self.subTest(endpoint=row["endpoint"]):
                self.assertIn("coverage gap", row["caller"], "a supported route with no caller is a gap, not a NOT_APPLICABLE")
        self.assertIn("not a `NOT_APPLICABLE`", api_section())


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
