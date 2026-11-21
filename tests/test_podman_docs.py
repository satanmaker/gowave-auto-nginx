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
from tools.podman_e2e import trace as trace_data  # noqa: E402

DOC = REPO_ROOT / "docs" / "PODMAN_E2E.md"
ENTRYPOINT = "tools.run_podman_e2e"
FLAG = re.compile(r"--[a-z][a-z0-9-]*")
REQUIREMENT = re.compile(r"^### Requirement:", re.MULTILINE)
SCENARIO = re.compile(r"^#### Scenario:", re.MULTILINE)


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
        rows = {row["endpoint"].strip("`"): row for row in api_rows() if "PATCH /api/users" in row["endpoint"]}
        self.assertEqual(len(rows), 2, "the map must record both client-update routes the pinned Panel serves")
        self.assertIn(
            "coverage gap", rows["PATCH /api/users"]["caller"],
            "a supported route with no caller is a gap, not a NOT_APPLICABLE",
        )
        self.assertIn(
            "attach_squad_to_user", rows["PATCH /api/users/{userId}"]["caller"],
            "the row a Panel-only plan reaches through the user it attaches must name that caller",
        )
        self.assertIn("not a `NOT_APPLICABLE`", api_section())

    def test_the_page_pins_the_user_agent_policy_per_path(self):
        section = api_section()
        for anchor in (
            "internal/subscription/serve.go:118",
            "internal/subscription/srr.go:77",
            "internal/database/default_data.go:10",
        ):
            with self.subTest(citation=anchor):
                self.assertIn(anchor, section, "the page no longer cites the rule that decides the policy")
        manifest = yaml.safe_load(MATRIX.read_text(encoding="utf-8"))["user_agent"]
        self.assertEqual(
            sorted(manifest), ["absent", "accepted", "blank"],
            "tests/cases/matrix.yaml must state the acceptance rule and the two refusals, never an allowlist",
        )
        self.assertEqual(manifest["accepted"], "non-empty header")
        from tools.podman_e2e import aio, panel_surface

        self.assertNotIn(panel_surface.FOREIGN_USER_AGENT, {agent for _n, _t, agent in panel_surface.REPRESENTATIONS})
        family = {name for name, _template, _agent in panel_surface.REPRESENTATIONS}
        self.assertEqual(family, set(aio.REPRESENTATIONS))

    def test_the_pinned_panel_enforces_the_policy_the_page_describes(self):
        if not backend_tree():
            self.skipTest(
                "sources/gowave is a local checkout (/sources/ is gitignored): "
                "the User-Agent policy was not re-read in this run"
            )
        serve = (BACKEND / "internal" / "subscription" / "serve.go").read_text(encoding="utf-8").splitlines()
        self.assertIn('userAgent == nil || *userAgent == ""', serve[117],
                      "the Panel no longer refuses an absent and a blank header at serve.go:118")
        matcher = (BACKEND / "internal" / "subscription" / "srr.go").read_text(encoding="utf-8")
        self.assertIn("func (config *SRRConfig) Match", matcher)
        self.assertLess(
            matcher.index("func (config *SRRConfig) Match"),
            matcher.index("handleOverrideClientType(overrideClientType)"),
            "the path override must be decided before any rule is read",
        )
        defaults = (BACKEND / "internal" / "database" / "default_data.go").read_text(encoding="utf-8")
        self.assertIn('"name":"Fallback Base64"', defaults)
        self.assertIn('"conditions":[],"responseType":"XRAY_BASE64"', defaults,
                      "the unconditional fallback rule is what serves a header that names no client family")


FAMILY_HEADING = "### Which client family consumes which representation"


def family_section() -> str:
    text = discovered()
    start = text.index(FAMILY_HEADING)
    end = text.find("\n### ", start + 1)
    return text[start:end if end != -1 else len(text)]


def family_rows() -> "list[dict]":
    """The representation inventory, one dict per row, in documented order."""
    rows = []
    for line in family_section().splitlines():
        if not line.startswith("| `"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        rows.append({
            "representation": cells[0].strip("`"),
            "path": cells[1].strip("`"),
            "header": cells[2].strip("`"),
            "engine": cells[3],
            "case": cells[4],
            "proves": cells[5],
        })
    return rows


class TestSubscriptionFamilyInventory(unittest.TestCase):
    """The representation inventory is read back against the manifest and the probe.

    The page says which client family consumes each representation; the manifest
    says which binary is pinned and which representations it consumes; the probe
    says which header it sends. None of the three may drift from the other two,
    because a row claiming a family the harness never sent would describe a
    client the run did not use.
    """

    def setUp(self):
        self.rows = family_rows()
        self.manifest = yaml.safe_load(MATRIX.read_text(encoding="utf-8"))
        self.by_name = {row["representation"]: row for row in self.rows}

    def test_every_manifest_representation_has_exactly_one_row(self):
        self.assertEqual(len(self.rows), len(self.by_name), "a representation is listed twice")
        self.assertEqual(sorted(self.by_name), sorted(self.manifest["representations"]))

    def test_the_inventory_lists_representations_in_the_order_the_probe_fetches_them(self):
        from tools.podman_e2e import panel_surface

        self.assertEqual(
            [row["representation"] for row in self.rows],
            [name for name, _template, _agent in panel_surface.REPRESENTATIONS],
            "the page and tools/podman_e2e/panel_surface.py disagree on the order the inventory is read in",
        )

    def test_each_row_declares_the_path_the_manifest_uses(self):
        for name, path in self.manifest["representations"].items():
            with self.subTest(representation=name):
                self.assertEqual(self.by_name[name]["path"], path,
                                 "the row names a path the manifest does not fetch")

    def test_each_row_names_the_header_the_probe_really_sends(self):
        from tools.podman_e2e import panel_surface

        for name, _template, agent in panel_surface.REPRESENTATIONS:
            with self.subTest(representation=name):
                self.assertEqual(
                    self.by_name[name]["header"], agent,
                    "the inventory must name the header the probe sends, not another member of the family",
                )

    def test_each_row_names_the_engine_the_manifest_pins(self):
        product = self.manifest["product"]
        consumers = {
            representation: client
            for client in self.manifest["clients"]
            for representation in client["consumes"]
        }
        for name, client in consumers.items():
            with self.subTest(representation=name):
                row = self.by_name[name]
                self.assertIn(f"`{client['binary']}`", row["engine"])
                self.assertIn(
                    str(product[client["version_key"]]), row["engine"],
                    f"the inventory names an engine version the manifest does not pin for {name}",
                )

    def test_a_representation_no_manifest_client_consumes_says_so(self):
        consumers = {
            representation
            for client in self.manifest["clients"]
            for representation in client["consumes"]
        }
        for name, row in self.by_name.items():
            with self.subTest(representation=name):
                if name in consumers:
                    self.assertNotIn("none pinned", row["engine"])
                else:
                    self.assertIn("none pinned", row["engine"])
                    self.assertIn("nothing executes", row["proves"],
                                  "a representation no pinned client consumes must not claim execution")

    def test_each_row_cites_a_case_the_catalogue_holds(self):
        ids = catalog_ids()
        for row in self.rows:
            with self.subTest(representation=row["representation"]):
                cited = set(CASE_ID.findall(row["case"]))
                self.assertTrue(cited, "the row cites no case, so nothing would notice it going stale")
                self.assertEqual(cited - ids, set())

    def test_the_link_importer_is_offered_the_json_body_too(self):
        probe = (REPO_ROOT / "tools" / "podman_e2e" / "subscription_probe.py").read_text(encoding="utf-8")
        start = probe.index("def share_link_facts")
        body = probe[start:probe.index("\ndef ", start + 1)]
        self.assertIn('read_payload(payload_dir, "xray-json")', body,
                      "the base64 case proves an import only if the JSON body is offered to the same importer")
        self.assertIn('"json_body_links"', body)
        aio_text = (REPO_ROOT / "tools" / "podman_e2e" / "aio.py").read_text(encoding="utf-8")
        start = aio_text.index("def case_share_links")
        body = aio_text[start:aio_text.index("\ndef ", start + 1)]
        self.assertIn('facts.get("json_body_links") == 0', body)
        self.assertIn('facts.get("xray_outbounds")', body,
                      "importing the list has to be executed by the Xray binary, not only parsed")
        self.assertEqual(self.by_name["base64"]["case"].strip("`"), "SUB-B64")


JSON_SHAPE_HEADING = "### Both served shapes of `/v2ray-json`"


def json_shape_section() -> str:
    text = discovered()
    start = text.index(JSON_SHAPE_HEADING)
    end = text.find("\n### ", start + 1)
    return text[start:end if end != -1 else len(text)]


def function_body(relative: str, name: str) -> str:
    """The source of one function, so a guard reads the code and not a copy of it."""
    text = (REPO_ROOT / relative).read_text(encoding="utf-8")
    start = text.index(f"def {name}(")
    end = text.find("\ndef ", start + 1)
    return text[start:end if end != -1 else len(text)]


class TestJsonShapeContract(unittest.TestCase):
    """The two `/v2ray-json` shapes are recorded as the probe enforces them.

    The distinction the page claims is the wrapper count: a served profile is a
    complete config and is never wrapped, while the bare object the case builds
    needs exactly one listener. Each test damages the claim it just read, so the
    paragraph cannot survive a probe that stopped enforcing it.
    """

    def setUp(self):
        self.section = json_shape_section()
        self.case = function_body("tools/podman_e2e/aio.py", "case_json_shapes")
        self.prepare = function_body("tools/podman_e2e/subscription_probe.py", "prepare_config")

    def test_the_page_records_both_shapes_and_names_the_case(self):
        prose = " ".join(self.section.split())
        self.assertIn("a single config object", prose)
        self.assertIn("a list of complete per-profile configs", prose)
        self.assertIn("`SUB-JSON-SHAPES`", prose)
        entries = {case["id"]: case for case in yaml.safe_load(CATALOG.read_text(encoding="utf-8"))["cases"]}
        entry = entries["SUB-JSON-SHAPES"]
        self.assertIn("both served shapes", entry["assertion"])
        self.assertEqual(sorted(entry["topology"]), ["aio", "multi-node"])

    def test_the_wrapper_counts_the_page_quotes_are_the_ones_the_case_asserts(self):
        self.assertIn("`served_wrapped = 0`", self.section)
        self.assertIn("`alternate_wrapped = 1`", self.section)
        self.assertIn('facts.get("served_wrapped") == 0', self.case,
                      "the page says a served profile is never wrapped; the case no longer asserts it")
        self.assertIn('expected_alternate_wrapped = 1 if alternate == "object" else 0', self.case)

    def test_a_served_profile_is_never_wrapped_but_a_bare_object_is(self):
        self.assertIn('if not result.get("inbounds")', self.prepare,
                      "the wrapper must key on a config with no inbounds, not on a served profile")
        self.assertIn("SOCKS_INBOUND", self.prepare)
        self.assertIn("wrapped = True", self.prepare)
        self.assertIn("return result, wrapped", self.prepare)
        self.assertNotIn('facts.get("served_wrapped") == 1', self.case,
                         "a served profile needing a wrapper is a defect the case must never accept")

    def test_the_alternate_object_carries_one_panel_outbound(self):
        self.assertIn('facts.get("alternate_outbounds") == 1', self.case,
                      "the alternate object is one host; a second outbound means profiles were merged")
        self.assertIn("collide on the tag", self.case,
                      "the case has to explain why profiles are not merged into one object")
        self.assertIn("one Panel outbound rather than one per host", self.section)

    def test_the_case_is_registered_in_the_all_in_one_suite(self):
        aio_text = (REPO_ROOT / "tools" / "podman_e2e" / "aio.py").read_text(encoding="utf-8")
        self.assertIn('Case("SUB-JSON-SHAPES", "aio"', aio_text,
                      "the shapes case is not in the suite that runs it, so the page describes a case nobody runs")


LIVE_HEADING = "### The live contract, capability by capability"
LIVE_SPEC = REPO_ROOT / "openspec" / "specs" / "live-vps-e2e" / "spec.md"
LIVE_REQUIREMENT = "### Requirement: Real Subscription Delivery and User-Agent Policy"
LIVE_CONFIG = REPO_ROOT / "tools" / "live_vps_config.env.example"
SCENARIO = re.compile(r"^#### Scenario: (.+)$", re.MULTILINE)


def live_section() -> str:
    text = discovered()
    start = text.index(LIVE_HEADING)
    end = text.find("\n### ", start + 1)
    return text[start:end if end != -1 else len(text)]


def live_requirement() -> str:
    text = LIVE_SPEC.read_text(encoding="utf-8")
    start = text.index(LIVE_REQUIREMENT)
    end = text.find("\n### Requirement: ", start + 1)
    return text[start:end if end != -1 else len(text)]


class TestLiveContractReconciliation(unittest.TestCase):
    """The container acceptance and the live acceptance accept one product.

    The page maps each scenario of the live subscription requirement onto the
    container case that asserts it, and names the places where the two differ.
    Each divergence is a claim about the pinned product or about the live
    runner's configuration, so it is read back from both rather than trusted.
    """

    def setUp(self):
        self.section = live_section()
        self.prose = " ".join(self.section.split())
        self.manifest = yaml.safe_load(MATRIX.read_text(encoding="utf-8"))

    def test_every_live_subscription_scenario_has_a_row(self):
        scenarios = set(SCENARIO.findall(live_requirement()))
        self.assertTrue(scenarios, "the live requirement declares no scenario; the page maps nothing")
        rows = set()
        for line in self.section.splitlines():
            if line.startswith("| `"):
                rows.add(line.strip().strip("|").split("|")[0].strip().strip("`"))
        self.assertEqual(scenarios - rows, set(), "a live scenario has no container row")
        self.assertEqual(rows - scenarios, set(), "a row maps a scenario the live spec does not state")

    def test_every_row_names_a_case_the_catalogue_holds(self):
        ids = catalog_ids()
        for line in self.section.splitlines():
            if not line.startswith("| `"):
                continue
            cited = set(CASE_ID.findall(line))
            self.assertTrue(cited, f"the row cites no case: {line[:60]}")
            self.assertEqual(cited - ids, set())

    def test_the_outbound_count_difference_is_explained_by_the_topology(self):
        self.assertIn("8, 9 or 10", self.prose)
        self.assertIn("carries 4 (5 with Vision)", self.prose)
        self.assertIn("Multi-Node one carries 8, 9 or 10", self.prose)
        self.assertEqual(sorted(self.manifest["topologies"]), ["aio", "multi-node", "panel-only"],
                         "the page names topologies the manifest does not declare")

    def test_the_geoip_divergence_names_the_pinned_template(self):
        self.assertIn("internal/database/default_data.go:108", self.prose)
        live = (REPO_ROOT / "tools" / "live_vps" / "subscriptions.py").read_text(encoding="utf-8")
        lines = live.splitlines()
        # Read the line the page cites rather than a remembered offset: the
        # citation is the claim, and an offset would keep passing after the
        # page started pointing somewhere else.
        cited = re.findall(r"tools/live_vps/subscriptions\.py:(\d+)", self.prose)
        self.assertTrue(cited, "the page stopped citing the rule the live runner accepts")
        for number in cited:
            with self.subTest(cited_line=number):
                rule_check = lines[int(number) - 1]
                self.assertIn('any("GEOIP" in rule', rule_check)
                self.assertIn('any("MATCH" in rule', rule_check)
        if not backend_tree():
            self.skipTest(
                "sources/gowave is a local checkout (/sources/ is gitignored): "
                "the pinned Mihomo template was not re-read in this run"
            )
        template = (BACKEND / "internal" / "database" / "default_data.go").read_text(encoding="utf-8")
        self.assertIn("GEOIP,LAN,DIRECT", template,
                      "the pinned Panel now ships the rule the live spec names; the divergence is gone")
        self.assertIn("MATCH,\u2192 GoWave", template)
        self.assertNotIn("GEOIP,private,DIRECT,no-resolve", template)

    def test_the_engine_pinning_difference_is_recorded(self):
        self.assertIn("pinned differently", self.prose)
        self.assertIn("reads `latest`", self.prose)
        product = self.manifest["product"]
        for name in ("xray_client_version", "mihomo_client_version"):
            with self.subTest(version=name):
                self.assertIn(str(product[name]), self.prose)
        live = LIVE_CONFIG.read_text(encoding="utf-8")
        self.assertIn("XRAY_CLIENT_VERSION=latest", live)
        self.assertIn("MIHOMO_CLIENT_VERSION=latest", live)
        header = MATRIX.read_text(encoding="utf-8").splitlines()
        self.assertFalse(
            any("pinned client" in line and "live_vps_config" in line for line in header[:10]),
            "the manifest still claims its pinned clients are the ones the live runner records",
        )

    def test_the_cache_control_contract_is_asserted_where_the_page_says(self):
        self.assertIn("`Cache-Control: no-store`", self.prose)
        self.assertIn("read where a client reads it", self.prose)
        nginx = (REPO_ROOT / "modules" / "nginx.sh").read_text(encoding="utf-8")
        location = nginx[nginx.index("location ^~ /api/sub/"):]
        self.assertIn('add_header Cache-Control "no-store', location.split("location ", 1)[-1],
                      "the vhost no longer disables caching on the subscription location")
        case = function_body("tools/podman_e2e/aio.py", "case_subscriptions")
        self.assertIn('edge_control = str(record.get("edge_cache_control") or "")', case,
                      "the case stopped judging the header the public edge returned")
        self.assertIn('require("SUB-SERVED", "no-store" in edge_control.lower()', case,
                      "the case records the edge header without requiring it to disable caching")
        self.assertIn('record.get("edge_identical") is True', case)
        collect = function_body("tools/podman_e2e/aio.py", "collect_subscriptions")
        self.assertIn("--edge-base https://{host.panel_domain}", collect,
                      "the probe is no longer pointed at the public edge")
        self.assertIn("topology.ACME_CA_BUNDLE_NAME", collect,
                      "the edge fetch is no longer given the run's CA bundle")
        self.assertIn("--ca {ca_file}", collect)
        # The request that is sent is the one whose headers are read, so the
        # guard follows the function that writes the request rather than the
        # name the callers use; a wrapper that stopped delegating would drop
        # the edge header read without touching this line.
        self.assertIn("return request(", function_body("tools/podman_e2e/panel_surface.py", "fetch"))
        self.assertIn('"cache_control": (response.getheader("Cache-Control") or "")',
                      function_body("tools/podman_e2e/panel_surface.py", "request"))

    def test_the_database_contract_is_read_where_the_page_says_the_panel_writes(self):
        self.assertIn("a running Panel writes its own rows", self.prose)
        self.assertIn("`database_dump_digest_changed`", self.prose)
        case = function_body("tools/podman_e2e/aio.py", "case_backup_store_full")
        self.assertIn("require_database_intact(", case,
                      "the case stopped asserting what a failed backup can destroy")
        self.assertIn("require_served_surface_unchanged(", case,
                      "the case stopped reading the database through the Panel's own surface")
        intact = function_body("tools/podman_e2e/aio.py", "require_database_intact")
        self.assertIn("lost rows the Panel stored", intact)
        self.assertNotIn("logical", intact,
                         "the row contract went back to comparing a whole dump, which the "
                         "Panel's own writes move")


REPORT_HEADING = "### The report: what an overall PASS requires"
RESULT_REQUIREMENT = "### Requirement: Result Status Semantics"
ANY_CASE_ID = re.compile(r"\b(?:AIO|MN|NGX|SUB|ACME|GATE)-[A-Z0-9][A-Z0-9-]*")


def report_section() -> str:
    text = discovered()
    start = text.index(REPORT_HEADING)
    end = text.find("\n### ", start + 1)
    return text[start:end if end != -1 else len(text)]


def result_status_scenarios():
    text = LIVE_SPEC.read_text(encoding="utf-8")
    start = text.index(RESULT_REQUIREMENT)
    end = text.find("\n### Requirement: ", start + 1)
    return set(SCENARIO.findall(text[start:end if end != -1 else len(text)]))


def all_live_scenarios():
    """Every scenario the live spec states, since one row can come from another requirement."""
    return set(SCENARIO.findall(LIVE_SPEC.read_text(encoding="utf-8")))


def row_cases(line: str) -> set:
    """The case ids a row cites, including the `GATE-` cases the suite declares."""
    return set(ANY_CASE_ID.findall(line))


class TestResultStatusContract(unittest.TestCase):
    """The report requirement is mapped onto the case that produces a report.

    The page's rows are held to the live spec and to the catalog from both
    sides: a scenario without a row fails, a row about a scenario the spec does
    not state fails, and a row that cites a case the catalog does not map to that
    scenario fails — so a driver that moves has to move the page with it.
    """

    def setUp(self):
        self.section = report_section()
        self.prose = " ".join(self.section.split())
        self.catalog = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))["cases"]

    def scenario_table(self) -> str:
        """The first table only: the second one maps fields, not scenarios."""
        return self.section.split("\n\n**", 1)[0]

    def rows(self):
        return [line for line in self.scenario_table().splitlines() if line.startswith("| `")]

    def test_every_result_status_scenario_has_a_row(self):
        scenarios = result_status_scenarios()
        self.assertTrue(scenarios, "the live requirement declares no scenario")
        rows = {line.strip().strip("|").split("|")[0].strip().strip("`") for line in self.rows()}
        self.assertEqual(scenarios - rows, set(), "a live scenario has no container row")
        self.assertEqual(rows - all_live_scenarios(), set(), "a row maps a scenario the live spec does not state")

    def test_every_row_names_a_case_the_catalogue_holds_or_says_it_is_unclaimed(self):
        ids = catalog_ids()
        by_scenario = {case.get("live_scenario"): case for case in self.catalog}
        for line in self.rows():
            scenario = line.strip().strip("|").split("|")[0].strip().strip("`")
            cited = row_cases(line)
            if not cited:
                self.assertIn("left to 9.3", line, f"a row claims nothing and does not say so: {line[:60]}")
                entry = by_scenario.get(scenario) or {}
                driven = {
                    str(facts.get("case"))
                    for facts in (entry.get("drivers") or {}).values()
                    if facts.get("case")
                }
                self.assertEqual(
                    driven, set(),
                    f"the page defers {scenario!r} and the catalog drives it with {sorted(driven)}",
                )
                continue
            self.assertEqual(cited - ids, set())

    def test_each_row_names_the_case_the_catalog_maps_to_that_scenario(self):
        by_scenario = {case.get("live_scenario"): case for case in self.catalog}
        for line in self.rows():
            scenario = line.strip().strip("|").split("|")[0].strip().strip("`")
            cited = row_cases(line)
            if not cited:
                continue
            entry = by_scenario.get(scenario)
            self.assertIsNotNone(entry, f"the catalog holds no entry for {scenario!r}")
            drivers = set()
            for facts in (entry.get("drivers") or {}).values():
                drivers.add(str(facts.get("case") or ""))
            self.assertEqual(
                cited - drivers, set(),
                f"the page cites {cited - drivers} for {scenario!r} and the catalog drives it elsewhere",
            )

    def test_the_field_mapping_names_every_live_field(self):
        text = LIVE_SPEC.read_text(encoding="utf-8")
        start = text.index(RESULT_REQUIREMENT)
        block = text[start : text.find("\n### Requirement: ", start + 1)]
        fields = set(re.findall(r"`(test_run_id|repository_commit|started_at|finished_at|control_machine|master|worker|trust|results|traffic|overall)`", block))
        for field in sorted(fields):
            self.assertIn(f"`{field}`", self.prose, f"the page does not map the live field {field!r}")


TEARDOWN_HEADING = "### Teardown: the policy a run ends in"
TEARDOWN_REQUIREMENT = "### Requirement: Teardown Policy Enforcement"
TEARDOWN_REQUIREMENT_NAME = "Teardown Policy Enforcement"
NUMBER_WORDS = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five"}


def teardown_section() -> str:
    text = discovered()
    start = text.index(TEARDOWN_HEADING)
    end = text.find("\n### ", start + 1)
    return text[start:end if end != -1 else len(text)]


def teardown_requirement_block() -> str:
    text = LIVE_SPEC.read_text(encoding="utf-8")
    start = text.index(TEARDOWN_REQUIREMENT)
    return text[start : text.find("\n### Requirement: ", start + 1)]


def teardown_entries() -> dict:
    """The live-scenario entries that own the requirement, keyed by scenario name."""
    return {
        case["live_scenario"]: case
        for case in yaml.safe_load(CATALOG.read_text(encoding="utf-8"))["cases"]
        if case.get("requirement") == TEARDOWN_REQUIREMENT_NAME and case.get("live_scenario")
    }


def teardown_product_cases() -> set:
    """The requirement's own cases: the ones the catalog declares with no scenario,
    because no live run states them and this suite is where they are decided."""
    return {
        case["id"]
        for case in yaml.safe_load(CATALOG.read_text(encoding="utf-8"))["cases"]
        if case.get("requirement") == TEARDOWN_REQUIREMENT_NAME and not case.get("live_scenario")
    }


def teardown_driver_cases(entry) -> set:
    return {
        str(facts.get("case"))
        for facts in (entry.get("drivers") or {}).values()
        if facts.get("case")
    }


def teardown_rows(section: str):
    return [line for line in section.splitlines() if line.startswith("| `")]


def teardown_row_scenario(line: str) -> str:
    return line.strip().strip("|").split("|")[0].strip().strip("`")


class TestTeardownPolicyContract(unittest.TestCase):
    """The policy a run ends in is mapped onto the case that reads it — and only partly.

    This is the one requirement where a stated scenario may be reproducible and
    not yet reproduced, so the page is held from three sides: a scenario the
    catalog drives has a row citing that case, a scenario it does not drive has
    no row and is named as left alone, and the number left alone is the number
    the page states — so a driver that starts or stops covering a scenario has
    to move the page with it, and a page that quietly promotes one is refused.
    """

    def setUp(self):
        self.section = teardown_section()
        self.rows = teardown_rows(self.section)
        self.prose = " ".join(self.section.split())
        self.entries = teardown_entries()

    def damaged(self, section: str) -> "TestTeardownPolicyContract":
        """A copy of this case reading a doctored page, so each guard can be
        shown to fail on the damage it exists for rather than on a fixture."""
        probe = TestTeardownPolicyContract(
            "test_every_driven_scenario_has_a_row_citing_the_case",
        )
        probe.section = section
        probe.prose = " ".join(section.split())
        probe.rows = teardown_rows(section)
        probe.entries = teardown_entries()
        return probe

    def test_the_spec_and_the_catalog_state_the_same_scenarios(self):
        self.assertEqual(
            set(self.entries), set(SCENARIO.findall(teardown_requirement_block())),
            "the catalog and the live requirement disagree about its scenarios",
        )

    def test_every_case_the_catalog_owns_for_the_requirement_is_cited(self):
        owned = teardown_product_cases()
        self.assertTrue(
            owned,
            "the requirement has no case of its own: the container contour holds none of it",
        )
        cited = set()
        for line in self.rows:
            cited |= row_cases(line)
        self.assertEqual(owned - cited, set(), "a case the catalog owns is cited by no row")

    def test_every_driven_scenario_has_a_row_citing_the_case(self):
        rows = {}
        for line in self.rows:
            rows.setdefault(teardown_row_scenario(line), []).append(line)
        for scenario, entry in self.entries.items():
            driven = teardown_driver_cases(entry)
            with self.subTest(scenario=scenario):
                if not driven:
                    self.assertNotIn(
                        scenario, rows,
                        "the page claims a row for a scenario nothing in the catalog drives",
                    )
                    continue
                self.assertIn(
                    scenario, rows,
                    "the catalog drives this scenario and the page has no row for it",
                )
                cited = set()
                for line in rows[scenario]:
                    cited |= row_cases(line)
                self.assertEqual(
                    driven - cited, set(),
                    f"the page's rows for {scenario!r} do not cite {sorted(driven - cited)}",
                )

    def test_every_row_names_a_scenario_the_requirement_states(self):
        stated = set(SCENARIO.findall(teardown_requirement_block()))
        for line in self.rows:
            self.assertIn(
                teardown_row_scenario(line), stated,
                "the page maps a scenario the teardown requirement does not state",
            )

    def test_each_row_cites_the_case_the_catalog_maps_to_that_scenario(self):
        for line in self.rows:
            scenario = teardown_row_scenario(line)
            cited = row_cases(line)
            with self.subTest(scenario=scenario):
                self.assertTrue(cited, f"a row claims no case: {line[:60]}")
                driven = teardown_driver_cases(self.entries[scenario])
                self.assertEqual(
                    cited - driven, set(),
                    f"the page cites {sorted(cited - driven)} for {scenario!r} "
                    "and the catalog drives it elsewhere",
                )

    def test_the_scenarios_left_to_the_live_runner_are_named_and_counted(self):
        undriven = sorted(
            entry["id"] for entry in self.entries.values() if not teardown_driver_cases(entry)
        )
        self.assertTrue(
            undriven,
            "every scenario of the requirement is now driven; the page still says otherwise",
        )
        stated = re.search(r"(\w+) scenarios? of that requirement stay(?:s)? live-only", self.prose)
        self.assertIsNotNone(
            stated, "the page does not say how much of the requirement stays live-only",
        )
        self.assertEqual(
            stated.group(1).lower(), NUMBER_WORDS.get(len(undriven), str(len(undriven))),
            f"the catalog leaves {len(undriven)} scenarios undriven and the page says "
            f"{stated.group(1)!r}",
        )
        for case_id in undriven:
            self.assertIn(
                f"`{case_id}`", self.prose,
                f"the page leaves {case_id} undriven without naming it",
            )

    def test_each_guard_fails_on_its_own_damage(self):
        section = teardown_section()
        driven = next(
            scenario for scenario in teardown_rows(section)
            if teardown_driver_cases(self.entries[teardown_row_scenario(scenario)])
        )
        driven = teardown_row_scenario(driven)
        undriven = next(
            entry["live_scenario"] for entry in self.entries.values()
            if not teardown_driver_cases(entry)
        )

        lost = "\n".join(
            line for line in section.splitlines() if not line.startswith(f"| `{driven}`")
        )
        with self.assertRaises(AssertionError):
            self.damaged(lost).test_every_driven_scenario_has_a_row_citing_the_case()

        claimed = f"{section}\n| `{undriven}` | `GATE-TEARDOWN` | invented |\n"
        with self.assertRaises(AssertionError):
            self.damaged(claimed).test_every_driven_scenario_has_a_row_citing_the_case()

        needle = f"| `{driven}` | `GATE-TEARDOWN`"
        self.assertEqual(
            section.count(needle), 1, "the row this probe damages is not identifiable",
        )
        retargeted = section.replace(needle, f"| `{driven}` | `GATE-BUDGET`", 1)
        with self.assertRaises(AssertionError):
            self.damaged(retargeted).test_each_row_cites_the_case_the_catalog_maps_to_that_scenario()

        miscounted = re.sub(
            r"\w+( scenarios? of that requirement stay(?:s)? live-only)",
            r"seven\1", section, count=1,
        )
        self.assertNotEqual(miscounted, section, "the sentence this probe damages is not there")
        with self.assertRaises(AssertionError):
            self.damaged(miscounted).test_the_scenarios_left_to_the_live_runner_are_named_and_counted()


VISION_HEADING = "### Vision: two optional domains, and which host owes the gate"
VISION_REQUIREMENT = "### Requirement: Independent Optional Vision Domains"
VISION_REQUIREMENT_NAME = "Independent Optional Vision Domains"
VISION_CASE = re.compile(r"\b(?:VIS|MN|NGX)-[A-Z0-9][A-Z0-9-]*")


def vision_section() -> str:
    text = discovered()
    start = text.index(VISION_HEADING)
    end = text.find("\n### ", start + 1)
    return text[start:end if end != -1 else len(text)]


def vision_requirement_block() -> str:
    text = LIVE_SPEC.read_text(encoding="utf-8")
    start = text.index(VISION_REQUIREMENT)
    return text[start : text.find("\n### Requirement: ", start + 1)]


def vision_entries() -> dict:
    """The live-scenario entries that own the requirement, keyed by scenario name."""
    return {
        case["live_scenario"]: case
        for case in yaml.safe_load(CATALOG.read_text(encoding="utf-8"))["cases"]
        if case.get("requirement") == VISION_REQUIREMENT_NAME and case.get("live_scenario")
    }


def vision_product_cases() -> set:
    """The requirement's own cases: the ones it declares with no live scenario."""
    return {
        case["id"]
        for case in yaml.safe_load(CATALOG.read_text(encoding="utf-8"))["cases"]
        if case.get("requirement") == VISION_REQUIREMENT_NAME and not case.get("live_scenario")
    }


def vision_driver_cases(entry) -> set:
    """The cases the catalog drives the scenario with, in either of its two shapes.

    A scenario witnessed by a different case names it in `case`; a scenario whose
    own id is the case names nothing, and reading the fact alone reported `VIS-05`
    as undriven while the catalog ran it — so the page could keep calling it
    live-only. `catalog.py` resolves the same fallback for the same reason.
    """
    return {
        str(facts.get("case") or entry["id"])
        for facts in (entry.get("drivers") or {}).values()
    }


def vision_rows(section: str):
    return [line for line in section.splitlines() if line.startswith("| `")]


def vision_row_scenario(line: str) -> str:
    return line.strip().strip("|").split("|")[0].strip().strip("`")


def vision_row_cases(line: str) -> set:
    return set(VISION_CASE.findall(line))


class TestVisionContract(unittest.TestCase):
    """Two optional domains are mapped onto the cases that decide them.

    Most of the requirement is already witnessed by cases that predate it, so
    the page is held from both sides: every scenario the catalog drives has a row
    citing that case, every row names a scenario the requirement states, and the
    two policy cases the requirement owns — the parser's matrix and the per-host
    gate — are cited too. Nothing of the requirement may be left to the live
    runner, so a driver that stops covering one has to add a row or fail here.
    """

    def setUp(self):
        self.section = vision_section()
        self.rows = vision_rows(self.section)
        self.prose = " ".join(self.section.split())
        self.entries = vision_entries()

    def damaged(self, section: str) -> "TestVisionContract":
        probe = TestVisionContract("test_every_driven_scenario_has_a_row_citing_the_case")
        probe.section = section
        probe.prose = " ".join(section.split())
        probe.rows = vision_rows(section)
        probe.entries = vision_entries()
        return probe

    def test_the_spec_and_the_catalog_state_the_same_scenarios(self):
        self.assertEqual(
            set(self.entries), set(SCENARIO.findall(vision_requirement_block())),
            "the catalog and the live requirement disagree about its scenarios",
        )

    def test_every_case_the_requirement_owns_is_cited(self):
        owned = vision_product_cases()
        self.assertEqual(
            owned, {"MN-VISION", "VIS-CONFIG", "VIS-GATE"},
            "the requirement's own cases are the per-node case and the two policy "
            "cases; the page maps them",
        )
        cited = set()
        for line in self.rows:
            cited |= vision_row_cases(line)
        self.assertEqual(owned - cited, set(), "a case the catalog owns is cited by no row")

    def test_every_driven_scenario_has_a_row_citing_the_case(self):
        rows = {}
        for line in self.rows:
            rows.setdefault(vision_row_scenario(line), []).append(line)
        for scenario, entry in self.entries.items():
            driven = vision_driver_cases(entry)
            with self.subTest(scenario=scenario):
                if not driven:
                    self.assertNotIn(
                        scenario, rows,
                        "the page claims a row for a scenario nothing in the catalog drives",
                    )
                    continue
                self.assertIn(
                    scenario, rows,
                    "the catalog drives this scenario and the page has no row for it",
                )
                cited = set()
                for line in rows[scenario]:
                    cited |= vision_row_cases(line)
                self.assertEqual(
                    driven - cited, set(),
                    f"the page's rows for {scenario!r} do not cite {sorted(driven - cited)}",
                )

    def test_every_row_names_a_scenario_the_requirement_states(self):
        stated = set(SCENARIO.findall(vision_requirement_block()))
        for line in self.rows:
            self.assertIn(
                vision_row_scenario(line), stated,
                "the page maps a scenario the Vision requirement does not state",
            )

    def test_each_row_cites_the_case_the_catalog_maps_to_that_scenario(self):
        for line in self.rows:
            scenario = vision_row_scenario(line)
            cited = vision_row_cases(line)
            with self.subTest(scenario=scenario):
                self.assertTrue(cited, f"a row claims no case: {line[:60]}")
                driven = vision_driver_cases(self.entries[scenario])
                self.assertEqual(
                    cited - driven, set(),
                    f"the page cites {sorted(cited - driven)} for {scenario!r} "
                    "and the catalog drives it elsewhere",
                )

    def test_the_policy_cases_run_in_both_contours(self):
        for case in yaml.safe_load(CATALOG.read_text(encoding="utf-8"))["cases"]:
            if case.get("id") not in {"VIS-CONFIG", "VIS-GATE"}:
                continue
            with self.subTest(case=case["id"]):
                self.assertEqual(
                    set(case.get("drivers") or {}), {"aio", "multi-node"},
                    "a policy case the page says both contours read is driven by fewer",
                )

    def test_no_scenario_of_the_requirement_is_left_to_the_live_runner(self):
        """VIS-06 closed the last one, so the page may not count any.

        The scenario that stayed live-only needed two faults at once — a Vision
        stage that fails and a compensation that cannot finish — and both seams
        are in the contour now. The claim the page has to carry is therefore the
        absence: no scenario of the requirement without a driver, and no sentence
        saying how many are left, because a count of zero is not a claim the page
        gets to keep.
        """
        undriven = sorted(
            entry["id"] for entry in self.entries.values() if not vision_driver_cases(entry)
        )
        self.assertEqual(
            undriven, [],
            f"the catalog leaves these scenarios of the requirement undriven: {undriven}",
        )
        self.assertIsNone(
            re.search(r"\w+ scenarios? of that requirement stay(?:s)? live-only", self.prose),
            "the page still says part of the requirement stays live-only",
        )

    def test_each_guard_fails_on_its_own_damage(self):
        section = vision_section()
        driven = next(
            row for row in vision_rows(section)
            if vision_driver_cases(self.entries[vision_row_scenario(row)])
        )
        driven = vision_row_scenario(driven)

        lost = "\n".join(
            line for line in section.splitlines() if not line.startswith(f"| `{driven}`")
        )
        with self.assertRaises(AssertionError):
            self.damaged(lost).test_every_driven_scenario_has_a_row_citing_the_case()

        needle = f"| `{driven}` | `{sorted(vision_driver_cases(self.entries[driven]))[0]}`"
        self.assertEqual(
            section.count(needle), 1, "the row this probe damages is not identifiable",
        )
        retargeted = section.replace(needle, f"| `{driven}` | `GATE-BUDGET`", 1)
        with self.assertRaises(AssertionError):
            self.damaged(retargeted).test_each_row_cites_the_case_the_catalog_maps_to_that_scenario()

        self.assertNotIn(
            "stays live-only", section,
            "the page already counts the undriven scenarios this probe adds back",
        )
        counted = f"{section}\n**One scenario of that requirement stays live-only.**\n"
        with self.assertRaises(AssertionError):
            self.damaged(counted).test_no_scenario_of_the_requirement_is_left_to_the_live_runner()


SHARED_CONTRACT_HEADING = "## The contracts both contours assert, and the one owner each has"
LIVE_SUBSCRIPTIONS = REPO_ROOT / "tools" / "live_vps" / "subscriptions.py"
LIVE_NEGATIVE = REPO_ROOT / "tools" / "live_vps" / "negative.py"
LIVE_CONFIG_MODULE = REPO_ROOT / "tools" / "live_vps" / "config.py"
SUBSCRIPTION_PATH = re.compile(r'/api/sub/[^\s"]+')
SHARED_OWNER_PATH = re.compile(r"`((?:tools|modules|tests|openspec|internal)/[^`]+)`")


def shared_contract_section() -> str:
    text = discovered()
    start = text.index(SHARED_CONTRACT_HEADING)
    end = text.find("\n### ", start + 1)
    return text[start:end if end != -1 else len(text)]


def shared_contract_rows():
    """contract -> [owner, live assertion, container assertion]."""
    rows = {}
    for line in shared_contract_section().splitlines():
        if not line.startswith("| ") or line.startswith("| Shared contract") or set(line) <= set("|- "):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        rows[cells[0]] = cells[1:]
    return rows


def normalised_subscription_path(path: str) -> str:
    """The matrix writes `{shortUuid}`; the live runner interpolates `{short_uuid}`."""
    return path.replace("{short_uuid}", "{shortUuid}")


def live_subscription_paths():
    """Every `/api/sub/…` literal the live contour names, normalised."""
    paths = set()
    for source in (LIVE_SUBSCRIPTIONS, LIVE_NEGATIVE):
        for line in source.read_text(encoding="utf-8").splitlines():
            for path in SUBSCRIPTION_PATH.findall(line):
                paths.add(normalised_subscription_path(path))
    return paths


class TestLiveContractParity(unittest.TestCase):
    """One product, two environments: a shared contract is one claim.

    `openspec/specs/live-vps-e2e/spec.md` owns the live contour, and the page
    tabulates the contracts both contours assert with the single owner of each.
    The risk this class closes is a divergence dressed as an environment
    difference: a live runner that accepts a wider User-Agent policy than the
    container, or a fingerprint vocabulary restated in two modules, is a second
    opinion about one product. Every claim is read from its owner rather than
    from the sentence that describes it.
    """

    def setUp(self):
        self.section = shared_contract_section()
        self.prose = " ".join(self.section.split())
        self.manifest = yaml.safe_load(MATRIX.read_text(encoding="utf-8"))

    def test_the_user_agent_refusal_is_one_code_in_both_contours(self):
        from tools.live_vps import subscriptions as live
        from tools.podman_e2e import aio

        self.assertEqual(
            aio.UA_REFUSAL_STATUS, live.SUBSCRIPTION_UA_REFUSAL_STATUS,
            "the two contours disagree on what refusing a subscription answers",
        )
        for policy in ("absent", "blank"):
            with self.subTest(policy=policy):
                self.assertEqual(self.manifest["user_agent"][policy], aio.UA_REFUSAL_STATUS,
                                 "the matrix disagrees with the case that reads it")
        negative = LIVE_NEGATIVE.read_text(encoding="utf-8")
        self.assertIn("code == SUBSCRIPTION_UA_REFUSAL_STATUS", negative,
                      "NEG-09 stopped using the contour's own refusal code")
        subscriptions = LIVE_SUBSCRIPTIONS.read_text(encoding="utf-8")
        self.assertEqual(
            subscriptions.count("== SUBSCRIPTION_UA_REFUSAL_STATUS"), 2,
            "the live runner stopped comparing the absent and blank answers against the "
            "contour's own refusal code; a literal here would pass the equality above and "
            "still be a second opinion about the product",
        )
        self.assertNotIn("400, 403", subscriptions + negative,
                         "a status range came back: the live contour accepts a weaker answer "
                         "than the container does for the same product")

    def test_every_subscription_path_the_live_runner_dials_is_a_representation(self):
        declared = {
            name: normalised_subscription_path(path)
            for name, path in self.manifest["representations"].items()
        }
        dialled = live_subscription_paths()
        self.assertTrue(dialled, "the live runner dials no subscription path; the probe is vacuous")
        self.assertEqual(
            dialled - set(declared.values()), set(),
            "the live runner dials a path the matrix does not declare, so the two contours "
            "name different products",
        )
        shared = set(declared.values()) - dialled
        self.assertEqual(
            shared,
            {declared["base64"], declared["singbox"]},
            "the representations only this contour drives changed; the page names base64 and single-box",
        )
        self.assertIn("`base64` and `singbox` are driven only by this contour", self.prose)

    def test_the_live_runner_takes_the_fingerprint_vocabulary_from_the_installer(self):
        from modules import api_client
        from tools.live_vps import config as live_config

        self.assertIs(
            live_config.REALITY_FINGERPRINTS, api_client.REALITY_FINGERPRINTS,
            "the live config restates the uTLS presets instead of importing the installer's",
        )
        self.assertEqual(live_config.REALITY_DEFAULT_FINGERPRINT, api_client.REALITY_DEFAULT_FINGERPRINT)
        self.assertEqual(self.manifest["product"]["reality_fingerprint"], api_client.REALITY_DEFAULT_FINGERPRINT)
        config_source = LIVE_CONFIG_MODULE.read_text(encoding="utf-8")
        self.assertNotIn('"chrome", "firefox"', config_source,
                         "a second copy of the preset tuple came back into the live config")
        subscriptions = LIVE_SUBSCRIPTIONS.read_text(encoding="utf-8")
        self.assertEqual(
            subscriptions.count("reality_fingerprint: str = REALITY_DEFAULT_FINGERPRINT,"), 2,
            "a subscription validator spells its own fingerprint default again",
        )
        self.assertNotIn('reality_fingerprint: str = "firefox"', subscriptions)

    def test_the_page_names_the_owner_of_each_shared_contract(self):
        rows = shared_contract_rows()
        self.assertEqual(
            set(rows),
            {
                "Subscription path vocabulary",
                "User-Agent refusal code",
                "REALITY fingerprint vocabulary",
                "`Cache-Control: no-store` on `/api/sub/`",
            },
            "a shared contract was dropped from the table or a new one was added unguarded",
        )
        ids = catalog_ids()
        for contract, (owner, live, container) in rows.items():
            with self.subTest(contract=contract):
                paths = SHARED_OWNER_PATH.findall(owner)
                self.assertTrue(paths, f"{contract} names no owner path")
                for relative in paths:
                    with self.subTest(path=relative):
                        if relative.startswith("internal/"):
                            if not backend_tree():
                                continue
                            self.assertTrue((BACKEND / relative).is_file(), f"{relative} is not in the vendored Panel")
                        else:
                            self.assertTrue((REPO_ROOT / relative).exists(), f"{relative} does not exist")
                self.assertTrue(SHARED_OWNER_PATH.search(live), f"{contract} names no live assertion site")
                cited = set(CASE_ID.findall(container))
                self.assertTrue(cited, f"{contract} names no container assertion")
                self.assertEqual(cited - ids, set(), f"{contract} cites a case the catalog does not hold")

    def test_the_design_records_the_same_relationship(self):
        design = " ".join(DESIGN.read_text(encoding="utf-8").split())
        self.assertIn("openspec/specs/live-vps-e2e/spec.md", design)
        self.assertIn(SHARED_CONTRACT_HEADING.lstrip("# "), design,
                      "the design no longer points at the table that owns this relationship")
        self.assertIn("TestLiveContractParity", design,
                      "the design claims a mechanism the tree does not name")
        self.assertIn("differ in environment rather than in product", design)
        self.assertTrue(LIVE_SPEC.is_file(), "the live spec this page defers to is gone")


OS_MATRIX_HEADING = "## The OS matrix, and which contour executes each row"
IMAGES_LOCK = REPO_ROOT / "tests" / "cases" / "images.lock.yaml"
OS_MODULE = REPO_ROOT / "modules" / "os.sh"
BOOT_SCRIPT = REPO_ROOT / "tests" / "systemd" / "boot.sh"
TESTBED_SCRIPT = REPO_ROOT / "tests" / "podman_testbed.sh"
ACCEPTANCE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "podman-acceptance.yml"
SYSTEMD_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "systemd-acceptance.yml"
COMPATIBILITY = REPO_ROOT / "openspec" / "changes" / "gowave-auto-nginx" / "COMPATIBILITY_MATRIX.md"
CODENAME_ARM = re.compile(r'^\s*([a-z]+-\d+(?:\.\d+)?)\)\s+OS_CODENAME="([a-z]+)"', re.MULTILINE)
ARRAY_ENTRY = re.compile(r'^\s*"(docker\.io/library/[^"]+)"', re.MULTILINE)
NGINX_VERSION = re.compile(r"(\d+\.\d+(?:\.\d+)?)\+?\s*(<|>=)\s*1\.25\.1")


def os_matrix_section() -> str:
    text = discovered()
    start = text.index(OS_MATRIX_HEADING)
    end = text.find("\n## ", start + 1)
    return text[start:end if end != -1 else len(text)]


def os_matrix_rows():
    """alias -> the four cells of its row, in the page's column order."""
    rows = {}
    for line in os_matrix_section().splitlines():
        if not line.startswith("| `"):
            continue
        cells = [cell.strip().strip("`") for cell in line.strip().strip("|").split("|")]
        rows[cells[0]] = cells[1:]
    return rows


def product_codenames():
    return dict(CODENAME_ARM.findall(OS_MODULE.read_text(encoding="utf-8")))


def pinned_base_images():
    lock = yaml.safe_load(IMAGES_LOCK.read_text(encoding="utf-8"))
    return {
        alias: entry["reference"]
        for alias, entry in lock["images"].items()
        if entry.get("role") == "base"
    }


def declared_base_images(path: Path, variable: str):
    text = path.read_text(encoding="utf-8")
    start = text.index(f"{variable}=(")
    body = text[start:text.index(")", start)]
    return set(ARRAY_ENTRY.findall(body))


def version_tuple(value: str):
    return tuple(int(part) for part in value.split("."))


def shell_function(relative: str, name: str) -> str:
    """One Bash function's body, found by its `name() {` header and closing brace."""
    text = (REPO_ROOT / relative).read_text(encoding="utf-8")
    start = text.index(f"\n{name}() {{") + 1
    end = text.index("\n}\n", start)
    return text[start:end]


class TestOsMatrixReconciliation(unittest.TestCase):
    """The supported distributions are one set, and each contour says what it ran.

    The product's supported list is `modules/os.sh`, the pins are
    `tests/cases/images.lock.yaml`, and three contours cite them: the product
    acceptance suite, the QEMU cold-boot matrix, and the legacy testbed
    scripts. A row that only one of them knows about is a distribution nobody
    installs on purpose; a status that claims more than the executed row
    supports is the drift the compatibility matrix exists to prevent.
    """

    def setUp(self):
        self.page = os_matrix_section()
        self.prose = " ".join(self.page.split())
        self.rows = os_matrix_rows()
        self.lock = pinned_base_images()

    def test_the_product_declares_the_four_distributions_the_lock_pins(self):
        declared = product_codenames()
        self.assertEqual(
            declared,
            {
                "ubuntu-24.04": "noble",
                "ubuntu-26.04": "resolute",
                "debian-12": "bookworm",
                "debian-13": "trixie",
            },
            "modules/os.sh no longer declares the four distributions the matrix supports",
        )
        self.assertEqual(set(self.lock), set(declared))
        self.assertEqual(set(self.lock), set(target_image.DISTRIBUTIONS))
        self.assertEqual(
            list(target_image.DISTRIBUTIONS.values()).count("ubuntu"), 2,
            "the suite accepts a distribution the product does not support",
        )

    def test_the_page_table_names_every_pinned_distribution_with_its_base_image(self):
        self.assertEqual(set(self.rows), set(self.lock), "a pinned distribution has no row")
        for alias, reference in self.lock.items():
            with self.subTest(alias=alias):
                self.assertEqual(self.rows[alias][0], reference)
                self.assertIn(alias, self.prose)

    def test_the_legacy_scripts_take_the_same_four_base_references(self):
        expected = set(self.lock.values())
        self.assertEqual(declared_base_images(BOOT_SCRIPT, "SUPPORTED_DISTROS"), expected,
                         "the QEMU boot script cites a base image the lock does not pin")
        self.assertEqual(declared_base_images(TESTBED_SCRIPT, "DISTROS"), expected,
                         "the legacy testbed cites a base image the lock does not pin")

    def test_the_qemu_matrix_covers_all_four_and_runs_the_systemd_suite(self):
        workflow = yaml.safe_load(SYSTEMD_WORKFLOW.read_text(encoding="utf-8"))
        job = workflow["jobs"]["qemu-cold-boot"]
        self.assertEqual(
            sorted(entry["distro"] for entry in job["strategy"]["matrix"]["include"]),
            sorted(self.lock.values()),
        )
        commands = "\n".join(step.get("run", "") for step in job["steps"])
        self.assertIn("tests/systemd/boot.sh", commands)
        self.assertIn("${{ matrix.distro }}", commands)
        guest = BOOT_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("tests/run_ci.py --suite systemd", guest,
                      "the QEMU guest no longer runs the suite the page says it does")
        self.assertNotIn("gowave-auto.sh install", guest,
                         "the QEMU job now installs the product; the page's split is stale")
        self.assertIn("not an operator install", self.prose)

    def test_the_product_acceptance_executes_only_the_default_distribution(self):
        workflow = yaml.safe_load(ACCEPTANCE_WORKFLOW.read_text(encoding="utf-8"))
        commands = "\n".join(
            step.get("run", "")
            for job in workflow["jobs"].values()
            for step in job["steps"]
        )
        self.assertNotIn("--distribution", commands,
                         "a workflow selects a distribution; the page says none does")
        default = run_podman_e2e.DEFAULT_DISTRIBUTION
        executed = [alias for alias, cells in self.rows.items() if cells[1].startswith("executed")]
        self.assertEqual(executed, ["ubuntu-24.04"])
        self.assertIn(default, executed)
        for alias, cells in self.rows.items():
            if alias == default:
                continue
            with self.subTest(alias=alias):
                self.assertEqual(cells[1], "selectable, not executed")
        self.assertIn("--distribution", self.prose)
        self.assertIn(default, self.prose)

    def test_the_compatibility_matrix_claim_matches_the_execution(self):
        text = COMPATIBILITY.read_text(encoding="utf-8")
        self.assertNotIn("PODMAN_TESTBED_PLANNED", text,
                         "the matrix still calls a suite that runs a plan")
        statuses = {}
        for line in text.splitlines():
            cells = [cell.strip().strip("`") for cell in line.strip().strip("|").split("|")]
            if len(cells) >= 7 and cells[2] in self.lock.values():
                statuses[next(alias for alias, ref in self.lock.items() if ref == cells[2])] = cells[6]
        self.assertEqual(statuses, {"ubuntu-24.04": "PROJECT_PODMAN_EXECUTED",
                                    "ubuntu-26.04": "PROJECT_PODMAN_SELECTABLE",
                                    "debian-12": "PROJECT_PODMAN_SELECTABLE",
                                    "debian-13": "PROJECT_PODMAN_SELECTABLE"})
        self.assertNotIn("NOT IMPLEMENTED / NOT EXECUTED", text,
                         "the matrix still says Multi-Node is unimplemented")
        self.assertIn("tools/run_podman_e2e.py --topology multi-node", text)
        self.assertIn("tests/multi_node_testbed.sh", text)

    def test_the_page_and_the_renderer_agree_on_the_two_listen_branches(self):
        renderer = shell_function("modules/os.sh", "render_nginx_listen_ssl_http2")
        self.assertIn('is_version_ge "$version" "1.25.1"', renderer)
        self.assertIn("http2 on;", renderer)
        self.assertIn("listen %s ssl http2%s;", renderer)
        for alias, cells in self.rows.items():
            with self.subTest(alias=alias):
                match = NGINX_VERSION.search(cells[3])
                self.assertIsNotNone(match, f"{alias} names no NGINX version and threshold")
                version, sign = match.group(1), match.group(2)
                above = version_tuple(version) >= (1, 25, 1)
                self.assertEqual(sign == ">=", above,
                                 f"{alias} states {version} {sign} 1.25.1, which is arithmetic")
                self.assertIn("modern" if above else "legacy", cells[3])


REUSABLE_HEADING = "## What the suite reuses, and what it must not duplicate"
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
WORKFLOW_REFERENCE = re.compile(r"\.github/workflows/([A-Za-z0-9_-]+\.yml)")


def reusable_section() -> str:
    text = discovered()
    start = text.index(REUSABLE_HEADING)
    end = text.find("\n## ", start + 1)
    return text[start:end if end != -1 else len(text)]


def fixture_row(alias: str):
    """The table row whose first cell names `alias`, as its raw cells."""
    needle = f"`{alias}`"
    for line in reusable_section().splitlines():
        if not line.startswith("| `"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if needle in cells[0]:
            return cells
    return None


class TestReusableFixtureInventory(unittest.TestCase):
    """Every contour and fixture the suite reuses says what it proves.

    The suite is assembled from scripts, images and fixture servers that already
    existed here, and each of them carries a scope in its own header. The risk
    this class covers is quotation: a green run of the transport scaffold read
    as an install, or a fixture described as if it were the product. So each
    test reads the claim back from the file that owns it — the workflow list,
    the image lock, the containerfile constants, the scripts the suite starts —
    rather than from a second copy of the page.
    """

    def test_every_workflow_has_a_row_and_every_row_is_a_workflow(self):
        existing = {path.name for path in WORKFLOW_DIR.glob("*.yml")}
        self.assertEqual(len(existing), 5, "a workflow was added or removed; the page lists five")
        cited = set(WORKFLOW_REFERENCE.findall(reusable_section()))
        self.assertEqual(sorted(cited), sorted(existing),
                         "a workflow runs without a row saying what it proves, "
                         "or the page cites a workflow that does not exist")

    def test_every_non_base_image_is_inventoried_with_its_role_and_pin(self):
        lock = yaml.safe_load(IMAGES_LOCK.read_text(encoding="utf-8"))["images"]
        self.assertEqual(sorted({entry["role"] for entry in lock.values()}),
                         ["acme-fixture", "base", "client-base", "egress-fixture"])
        for alias, entry in lock.items():
            with self.subTest(alias=alias):
                row = fixture_row(alias)
                self.assertIsNotNone(row, "a fixture the suite starts has no row")
                cells = " ".join(row)
                self.assertIn(f"role `{entry['role']}`", cells,
                              "the row does not say which lock role it is")
                if entry.get("role") == "base":
                    continue
                # Read inside the row that names the alias: two fixtures share
                # the python:3.12-slim base, so a section-wide search would let
                # one row's pin excuse the other's drift.
                self.assertIn(entry["reference"], cells, "the row does not name the pin")

    def test_the_containerfiles_are_the_ones_the_builders_build_from(self):
        from tools.podman_e2e import client_image
        from tools.podman_e2e import target_image as builder

        section = reusable_section()
        for module in (builder, client_image):
            relative = module.CONTAINERFILE.relative_to(REPO_ROOT).as_posix()
            self.assertTrue(module.CONTAINERFILE.is_file())
            self.assertIn(relative, section)
        legacy = "tests/Containerfile.testbed"
        self.assertTrue((REPO_ROOT / legacy).is_file())
        self.assertIn(legacy, section)
        for script in ("tests/podman_testbed.sh", "tests/multi_node_testbed.sh",
                       "tests/systemd/boot.sh"):
            with self.subTest(script=script):
                self.assertIn("Containerfile.testbed", (REPO_ROOT / script).read_text(encoding="utf-8"),
                              f"{script} stopped building the legacy image the page cites")
        shared = sorted(
            path.name
            for path in (REPO_ROOT / "tools" / "podman_e2e").glob("*.py")
            if "Containerfile.testbed" in path.read_text(encoding="utf-8")
        )
        self.assertEqual(shared, [], "the acceptance suite runs on the legacy image")

    def test_the_fixture_servers_are_the_scripts_the_suite_starts(self):
        from tools.podman_e2e import topology

        section = reusable_section()
        for started in (topology.DNS_FIXTURE_SCRIPT, topology.ECHO_FIXTURE_SCRIPT):
            with self.subTest(script=started):
                self.assertTrue(
                    started.startswith(f"{topology.REPO_IN_CONTAINER}/tests/fixtures/"),
                    "a fixture is started from outside the repository copy",
                )
                relative = started[len(topology.REPO_IN_CONTAINER) + 1:]
                self.assertTrue((REPO_ROOT / relative).is_file())
                self.assertIn(relative, section)
        pebble = "tests/fixtures/acme/pebble-config.json"
        self.assertIn(pebble, section)
        from tools.podman_e2e import acme_fixture

        self.assertEqual(acme_fixture.PEBBLE_CONFIG_TEMPLATE.relative_to(REPO_ROOT).as_posix(), pebble,
                         "the page cites a Pebble config the fixture does not read")

    def test_the_contour_scopes_match_what_the_scripts_say(self):
        section = " ".join(reusable_section().split())
        scope = "deliberately does not claim to install GoWave Panel/Node or validate subscriptions"
        self.assertIn(scope, (REPO_ROOT / "tests" / "multi_node_testbed.sh").read_text(encoding="utf-8"))
        self.assertIn(scope, section, "the page quotes a scope the scaffold no longer states")
        testbed = (REPO_ROOT / "tests" / "podman_testbed.sh").read_text(encoding="utf-8")
        stages = re.findall(r'echo "\[Stage \d/8\]', testbed)
        self.assertEqual(len(stages), 8,
                         "the legacy pipeline changed length; the page still says eight stages")
        self.assertIn("--systemd=always", testbed)
        self.assertIn("eight stages", section)
        guest = (REPO_ROOT / "tests" / "systemd" / "boot.sh").read_text(encoding="utf-8")
        self.assertIn("tests/run_ci.py --suite systemd", guest)
        self.assertIn("tests/run_ci.py --suite systemd", section,
                      "the page stopped naming the suite the QEMU guest runs")

    def test_the_install_is_the_operator_entrypoint_and_the_probe_is_named(self):
        from tools.podman_e2e import aio

        section = " ".join(reusable_section().split())
        install = function_body("tools/podman_e2e/topology.py", "install_script")
        self.assertIn("gowave-auto.sh install", install,
                      "the suite stopped driving the operator's installer")
        self.assertIn("gowave-auto.sh install", section)
        self.assertIn("may never stand in for the product itself", section)
        self.assertIn(aio.NGX_CONFIG_SNIPPET, section,
                      "the page no longer names the one file the suite writes into NGINX")
        self.assertIn(aio.NGX_CONFIG_DIRECTIVE, section)


BOUNDARY_HEADING = "## Where Podman stops, where QEMU starts, and what only a VPS can answer"
PARITY = REPO_ROOT / "tests" / "cases" / "PARITY.md"
SYSTEMD_SUITE = REPO_ROOT / "tests" / "test_systemd_runner.py"
DESIGN = trace_data.change_root() / "design.md"
LIVE_SPLIT = re.compile(r"Live scenarios: (\d+) — container (\d+), partial (\d+), live-only (\d+)\.")


def boundary_section() -> str:
    text = discovered()
    start = text.index(BOUNDARY_HEADING)
    end = text.find("\n## ", start + 1)
    return text[start:end if end != -1 else len(text)]


def environment_row(environment: str):
    """The boundary table row whose first cell is the quoted environment."""
    for line in boundary_section().splitlines():
        if not line.startswith("| `"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if cells[0] == f"`{environment}`":
            return cells
    return None


def parity_ids(heading: str) -> set:
    text = PARITY.read_text(encoding="utf-8")
    start = text.index(heading)
    end = text.find("\n## ", start + 1)
    return set(re.findall(r"^- \*\*([A-Z0-9-]+)\*\*", text[start:end], re.MULTILINE))


class TestContourBoundary(unittest.TestCase):
    """Podman, QEMU and Live VPS each answer a different question.

    Every catalog entry carries an `environment`, so the boundary is data, not
    prose. This class recomputes the counts and the fourteen non-container ids
    from the catalog and from the generated `tests/cases/PARITY.md`, and refuses
    a page or a design note that quotes a different set. The QEMU contour is read
    from its own script: if it ever gained an installer call or a catalog id,
    the claim that it checks the units without exercising the product would be
    false.
    """

    def test_the_environment_table_counts_are_the_catalog_counts(self):
        from tools.podman_e2e import catalog as case_catalog

        catalog = case_catalog.load_catalog()
        environments = {}
        for case in catalog["cases"]:
            environments[case["environment"]] = environments.get(case["environment"], 0) + 1
        self.assertEqual(len(catalog["cases"]), 249, "the catalog changed size; the page quotes its total")
        self.assertEqual(environments, {"container": 235, "partial": 12, "live-only": 2})
        self.assertIn(f"The catalog holds {len(catalog['cases'])} entries",
                      " ".join(boundary_section().split()),
                      "the page states a total the catalog does not have")
        rows = [line for line in boundary_section().splitlines() if line.startswith("| `")]
        self.assertEqual(len(rows), 3, "the environment table gained or lost a row")
        for environment, expected in environments.items():
            with self.subTest(environment=environment):
                row = environment_row(environment)
                self.assertIsNotNone(row, "the page states no count for this environment")
                self.assertEqual(row[1], str(expected),
                                 "the page counts a different number of cases than the catalog")

    def test_the_live_split_is_the_one_parity_reports(self):
        from tools.podman_e2e import catalog as case_catalog

        counts = case_catalog.load_catalog()["counts"]
        match = LIVE_SPLIT.search(PARITY.read_text(encoding="utf-8"))
        self.assertIsNotNone(match, "PARITY.md stopped stating the live split")
        self.assertEqual(
            tuple(int(value) for value in match.groups()),
            (counts["live_total"], counts["container"], counts["partial"], counts["live_only"]),
            "the generated parity header and the catalog counts disagree",
        )
        page = " ".join(boundary_section().split())
        self.assertIn(
            f"Of the {counts['live_total']} live scenarios projected into this catalog, "
            f"{counts['container']} are container, {counts['partial']} are partial and "
            f"{counts['live_only']} are live-only; the other {counts['podman_first']} entries "
            "are Podman-first",
            page,
            "the page's live split drifted from the catalog",
        )

    def test_the_ten_entries_that_are_not_fully_container_answerable_are_named(self):
        from tools.podman_e2e import catalog as case_catalog

        cases = case_catalog.load_catalog()["cases"]
        expected = {
            "partial": {case["id"] for case in cases if case["environment"] == "partial"},
            "live-only": {case["id"] for case in cases if case["environment"] == "live-only"},
        }
        self.assertEqual(expected["partial"], parity_ids("## Partial splits"),
                         "the generated partial split list moved away from the catalog")
        self.assertEqual(expected["live-only"], parity_ids("## Live-only exclusions"),
                         "the generated live-only exclusion list moved away from the catalog")
        page = boundary_section()
        named = set(re.findall(r"`([A-Z][A-Z0-9-]+)`", page))
        catalogued = {case["id"] for case in cases}
        self.assertEqual(named & catalogued, expected["partial"] | expected["live-only"],
                         "the page names a case id that is not on the boundary, or omits one that is")
        total = len(expected["partial"]) + len(expected["live-only"])
        self.assertEqual(total, 14)
        self.assertIn("The fourteen entries that are not fully container-answerable",
                      " ".join(page.split()),
                      "the page stopped counting the boundary entries")

    def test_the_qemu_contour_installs_nothing_and_carries_no_case_ids(self):
        from tools.podman_e2e import catalog as case_catalog

        boot = BOOT_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("python3 tests/run_ci.py --suite systemd", boot,
                      "the QEMU guest stopped running the systemd suite")
        self.assertNotIn("gowave-auto.sh", boot,
                         "the QEMU contour began invoking the product installer")
        catalogued = [case["id"] for case in case_catalog.load_catalog()["cases"]]
        for path in (BOOT_SCRIPT, SYSTEMD_SUITE):
            text = path.read_text(encoding="utf-8")
            found = sorted(
                case_id for case_id in catalogued
                if re.search(rf"\b{re.escape(case_id)}\b", text)
            )
            self.assertEqual(found, [], f"{path.name} names catalog cases the QEMU contour does not run")
        page = " ".join(boundary_section().split())
        for needle in ("python3 tests/run_ci.py --suite systemd", "/proc/1/comm", "no catalog case id"):
            self.assertIn(needle, page, "the page dropped a fact that keeps the QEMU claim honest")

    def test_the_systemd_suite_checks_the_units_the_page_names(self):
        page = " ".join(boundary_section().split())
        for relative in ("modules/panel.sh", "modules/security.sh"):
            with self.subTest(module=relative):
                self.assertTrue((REPO_ROOT / relative).is_file())
                self.assertIn(relative, page, "the page no longer names the unit template the suite reads")
        panel = (REPO_ROOT / "modules" / "panel.sh").read_text(encoding="utf-8")
        self.assertIn("Before=gowave.service gowave-node.service", panel)
        security = (REPO_ROOT / "modules" / "security.sh").read_text(encoding="utf-8")
        self.assertIn("Before=systemd-sysctl.service", security)
        suite = SYSTEMD_SUITE.read_text(encoding="utf-8")
        self.assertEqual(len(re.findall(r"^    def test_", suite, re.MULTILINE)), 8,
                         "the systemd suite changed length; the page still says eight tests")
        self.assertIn("eight tests", page)
        self.assertIn("`gowave-auto.sh`", page,
                      "the page no longer names the file the install and uninstall tests read")

    def test_the_design_scope_names_the_same_three_contours(self):
        text = DESIGN.read_text(encoding="utf-8")
        start = text.index("## Scope boundary")
        scope = " ".join(text[start:].split())
        for needle in (
            "docs/PODMAN_E2E_DISCOVERY.md",
            "tests/systemd/boot.sh",
            "tests/run_ci.py --suite systemd",
            "tests/cases/PARITY.md",
            "213 catalogued cases",
            "203 are `container`",
            "8 are `partial`",
            "2 are `live-only`",
        ):
            with self.subTest(needle=needle):
                self.assertIn(needle, scope, "the design's scope boundary stopped matching the page")


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

    def test_the_readme_cites_the_requirements_and_scenarios_the_specs_hold(self):
        # The quoted total is a copy of openspec/specs/, so it is read back from the
        # specs rather than trusted: an added requirement or scenario moves the count
        # and this test is where the README is told.
        readme = " ".join((REPO_ROOT / "README.md").read_text(encoding="utf-8").split())
        requirements = scenarios = 0
        for spec in sorted((REPO_ROOT / "openspec" / "specs").glob("*/spec.md")):
            text = spec.read_text(encoding="utf-8")
            requirements += len(REQUIREMENT.findall(text))
            scenarios += len(SCENARIO.findall(text))
        self.assertIn(
            f"**{requirements} requirements / {scenarios} GIVEN-WHEN-THEN acceptance scenarios**", readme
        )


if __name__ == "__main__":
    unittest.main()
