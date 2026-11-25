#!/usr/bin/env python3
"""Suite nonroot: the checked-in protocol/client matrix is the single source of tuples.

Every data-plane case id, every transport the probe runs, and the 8/10 count the
run owes come from ``tests/cases/matrix.yaml`` through this module. These tests
hold that contract: a matrix edit that removes an inbound, renames a client, or
declares a count its own tuples do not produce must fail here rather than
silently shrinking what the product acceptance claims to have covered.
"""
import os
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from modules.api_client import REALITY_DEFAULT_FINGERPRINT, host_projection  # noqa: E402
from tools.podman_e2e import catalog, matrix  # noqa: E402


class TestProtocolMatrix(unittest.TestCase):
    """The matrix file and the accessors the suite and the catalog share."""

    def setUp(self):
        self.data = matrix.load()

    def test_the_schema_is_the_versioned_one_the_gate_reads(self):
        self.assertEqual(self.data["version"], 1)
        self.assertEqual(self.data["schema"], "gowave-podman-matrix/v1")

    def test_the_non_optional_inbounds_are_the_four_the_product_always_installs(self):
        chosen = matrix.inbounds(self.data, vision=False)
        self.assertEqual(
            [inbound["id"] for inbound in chosen],
            ["REALITY", "XHTTP", "WS", "TROJAN-GRPC"],
        )
        self.assertEqual(len(matrix.tuples(self.data, vision=False)), 8)

    def test_the_optional_inbound_is_the_vision_tuple_that_makes_it_ten(self):
        chosen = matrix.inbounds(self.data, vision=True)
        self.assertEqual([inbound["id"] for inbound in chosen][-1], matrix.VISION_INBOUND)
        self.assertEqual(len(matrix.tuples(self.data, vision=True)), 10)
        self.assertEqual(
            [client for _inbound, client in matrix.tuples(self.data, vision=True)[-2:]],
            matrix.clients(self.data),
            "the optional inbound is exercised by every client, not just one",
        )

    def test_every_client_is_paired_with_every_selected_inbound(self):
        tuples = matrix.tuples(self.data, vision=False)
        self.assertEqual(len(tuples), 8)
        for inbound, client in tuples:
            self.assertIn(client, matrix.clients(self.data))
            self.assertFalse(inbound.get("optional"))

    def test_an_inbound_is_named_by_its_transport_and_security_pair(self):
        pairs = [
            (inbound["transport"], inbound["security"])
            for inbound in matrix.inbounds(self.data, vision=True)
        ]
        self.assertEqual(len(set(pairs)), len(pairs),
                         "two inbounds sharing a pair would make one tuple ambiguous")
        self.assertIn(("tcp", "reality"), pairs)
        self.assertIn(("tcp", "tls"), pairs, "Vision is the tcp/tls inbound")

    def test_the_case_id_comes_from_the_topology_pattern(self):
        self.assertEqual(
            matrix.case_id(self.data, "aio", "REALITY", "xray"), "AIO-DP-REALITY-xray",
        )
        self.assertEqual(
            matrix.case_id(self.data, "multi-node", "WS", "mihomo", node="worker"),
            "MN-DP-worker-WS-mihomo",
        )

    def test_a_topology_without_a_pattern_or_count_is_an_error_not_a_default(self):
        with self.assertRaises(KeyError):
            matrix.case_id(self.data, "edge", "REALITY", "xray")
        with self.assertRaises(KeyError):
            matrix.positive_count(self.data, "edge", vision=False)

    def test_the_declared_counts_are_the_ones_the_matrix_itself_produces(self):
        self.assertEqual(matrix.positive_count(self.data, "aio", vision=False), 8)
        self.assertEqual(matrix.positive_count(self.data, "aio", vision=True), 10)
        for vision in (False, True):
            self.assertEqual(
                matrix.positive_count(self.data, "aio", vision),
                len(matrix.tuples(self.data, vision)),
            )

    def test_the_vision_combination_names_the_selected_configuration(self):
        self.assertEqual(matrix.combination("aio", vision=False), "disabled")
        self.assertEqual(matrix.combination("aio", vision=True), "enabled")

    def test_the_panel_only_topology_declares_no_vision_and_no_data_plane(self):
        # Panel-only deploys no traffic plane, so there is nothing to configure
        # Vision on and no tuple to count: asking for either is a mistake, and a
        # silent 0 would read as a topology that ran its cases.
        self.assertEqual(matrix.combination(matrix.PANEL_ONLY), "none")
        for vision, worker_vision in ((True, False), (False, True)):
            with self.subTest(vision=vision, worker_vision=worker_vision):
                with self.assertRaises(KeyError):
                    matrix.combination(matrix.PANEL_ONLY, vision, worker_vision)
        self.assertEqual(matrix.runtime_budget_seconds(self.data, matrix.PANEL_ONLY), 4500)
        self.assertEqual(
            self.data["topologies"][matrix.PANEL_ONLY]["positive_case_counts"], {},
            "the mode owes no data-plane case, so it declares no count",
        )
        self.assertEqual(
            self.data["topologies"][matrix.PANEL_ONLY]["gate"], ["pr"],
            "the mode is judged by its own required check at the merge gate, and no push pays "
            "for it: 'pre-push' here would put a third suite behind every push",
        )
        with self.assertRaises(KeyError):
            matrix.positive_count(self.data, matrix.PANEL_ONLY)

    def test_an_unknown_inbound_is_reported_by_its_id(self):
        with self.assertRaises(KeyError) as caught:
            matrix.inbound(self.data, "HYSTERIA")
        self.assertIn("HYSTERIA", str(caught.exception))


class TestMatrixCatalog(unittest.TestCase):
    """The catalog advertises every matrix tuple the suite may run, and no other."""

    def setUp(self):
        self.catalog = catalog.build_catalog()
        self.data = matrix.load()

    def test_the_catalog_lists_one_data_plane_entry_per_tuple_for_every_client(self):
        entries = {case["id"] for case in self.catalog["cases"] if case["id"].startswith("AIO-DP-")}
        expected = {
            matrix.case_id(self.data, "aio", str(inbound["id"]), client)
            for inbound, client in matrix.tuples(self.data, vision=True)
        }
        self.assertEqual(entries, expected)
        self.assertEqual(len(entries), 10)

    def test_the_catalog_carries_the_count_case_that_judges_the_run(self):
        entries = {case["id"]: case for case in self.catalog["cases"]}
        self.assertIn("AIO-MATRIX", entries)
        self.assertEqual(entries["AIO-MATRIX"]["topology"], ["aio"])
        self.assertEqual(entries["AIO-MATRIX"]["state"], "incubating")

    def test_the_static_aggregate_traffic_case_is_not_advertised_any_more(self):
        entries = {case["id"] for case in self.catalog["cases"]}
        self.assertNotIn("AIO-TRAFFIC", entries)

    def test_the_catalog_names_the_configuration_dependent_counts(self):
        self.assertEqual(
            self.catalog["expected_positive_case_counts"]["aio"],
            {"vision_disabled": 8, "vision_enabled": 10},
        )


DOMAINS = {
    "panel": "panel.testbed.internal",
    "reality": "reality.testbed.internal",
    "vision": "vision.testbed.internal",
}
PAGE = REPO_ROOT / "docs" / "PODMAN_E2E_DISCOVERY.md"
HOST_TABLE_HEADING = "### The host record a tuple dials"
ROLE_WORDS = {"panel domain": "panel", "REALITY domain": "reality", "Vision domain": "vision"}
BACKTICK = re.compile(r"`([^`]+)`")


def projection():
    """The Host records the install posts, rendered with distinguishable domains."""
    return host_projection(
        DOMAINS["panel"], DOMAINS["reality"], "local-node", DOMAINS["vision"],
    )


def host_table_rows():
    text = PAGE.read_text(encoding="utf-8")
    start = text.index(HOST_TABLE_HEADING)
    end = text.find("\n### ", start + 1)
    rows = {}
    for line in text[start:end if end != -1 else len(text)].splitlines():
        if not line.startswith("| `"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        rows[cells[0].strip("`")] = cells[1:]
    return rows


class TestHostProjection(unittest.TestCase):
    """The tuple a case id names is the Host record the install really posts.

    `tests/cases/matrix.yaml` declares an address role, SNI role, port, path,
    ALPN and `securityLayer` per inbound. Those values live in
    `modules/api_client.host_projection`, which `provision_hosts` posts; this
    class compares the two and the page table, so a record that changes in the
    client cannot leave the matrix, a case id or the page describing the old
    one. REALITY is the row that matters most: clients dial the panel's public
    address but present the REALITY domain as SNI, and a matrix that collapsed
    the two would name a tuple no client dials.
    """

    def setUp(self):
        self.data = matrix.load()
        self.records = projection()

    def test_every_inbound_declares_the_host_record_the_install_posts(self):
        for inbound in self.data["inbounds"]:
            with self.subTest(inbound=inbound["id"]):
                record = inbound["host_record"]
                posted = self.records[inbound["tag"]]
                self.assertIn(record["address_role"], DOMAINS)
                self.assertIn(record["sni_role"], DOMAINS)
                self.assertEqual(posted["address"], DOMAINS[record["address_role"]],
                                 "the matrix names a different dialled address")
                self.assertEqual(posted["sni"], DOMAINS[record["sni_role"]],
                                 "the matrix names a different SNI")
                self.assertEqual(record["port"], posted["port"])
                self.assertEqual(posted["port"], 443,
                                 "every Host record is dialled through NGINX on 443")
                self.assertRegex(inbound["listener"], r"^\d+/tcp$",
                                 "the matrix listener no longer names a transport")
                if inbound["optional"]:
                    self.assertNotEqual(inbound["listener"], "443/tcp",
                                        "Vision terminates TLS on its own product-side listener")
                self.assertEqual(record["path"], posted["path"])
                self.assertEqual(record["alpn"], posted["alpn"])
                self.assertEqual(record["security_layer"], posted["securityLayer"])
                wire = "reality" if posted["securityLayer"] == "DEFAULT" else "tls"
                self.assertEqual(inbound["security"], wire,
                                 "the wire security and the stored securityLayer are one pair")

    def test_the_projection_and_the_matrix_name_the_same_five_tags(self):
        self.assertEqual(len(self.records), 5)
        self.assertEqual(
            sorted(self.records),
            sorted(inbound["tag"] for inbound in self.data["inbounds"]),
            "a provisioned Host record has no tuple, or a tuple has no Host record",
        )

    def test_the_fingerprint_pin_is_the_default_on_both_security_layers(self):
        with patch.dict(os.environ, {"GOWAVE_REALITY_FINGERPRINT": ""}, clear=False):
            recorded = projection()
        self.assertEqual(REALITY_DEFAULT_FINGERPRINT, "firefox")
        self.assertEqual(self.data["product"]["reality_fingerprint"], REALITY_DEFAULT_FINGERPRINT)
        for inbound in self.data["inbounds"]:
            with self.subTest(inbound=inbound["id"]):
                self.assertEqual(inbound["fingerprint"], recorded[inbound["tag"]]["fingerprint"])
                self.assertEqual(inbound["fingerprint"], REALITY_DEFAULT_FINGERPRINT,
                                 "a tuple pins a fingerprint the default does not mint")
                layer = inbound["host_record"]["security_layer"]
                self.assertIn(layer, ("DEFAULT", "TLS"))
        self.assertEqual(
            {inbound["host_record"]["security_layer"] for inbound in self.data["inbounds"]},
            {"DEFAULT", "TLS"},
            "both security layers must be represented, or one branch is unexercised",
        )

    def test_the_host_field_is_the_constant_the_payload_posts(self):
        source = (REPO_ROOT / "modules" / "api_client.py").read_text(encoding="utf-8")
        self.assertEqual(source.count('"host": None,'), 1,
                         "the Host payload no longer posts a constant host field")
        for inbound in self.data["inbounds"]:
            with self.subTest(inbound=inbound["id"]):
                self.assertIsNone(inbound["host_record"]["host"])

    def test_the_page_table_is_the_matrix_projection(self):
        rows = host_table_rows()
        self.assertEqual(sorted(rows), sorted(inbound["id"] for inbound in self.data["inbounds"]),
                         "the page table and the matrix name different inbounds")
        for inbound in self.data["inbounds"]:
            with self.subTest(inbound=inbound["id"]):
                address, sni, alpn, path, layer = rows[inbound["id"]]
                record = inbound["host_record"]
                self.assertEqual(ROLE_WORDS[address], record["address_role"])
                self.assertEqual(ROLE_WORDS[sni], record["sni_role"])
                self.assertEqual(BACKTICK.search(alpn).group(1), record["alpn"])
                if record["path"] is None:
                    self.assertEqual(path, "—")
                else:
                    self.assertEqual(BACKTICK.search(path).group(1), record["path"])
                self.assertEqual(layer.strip("`"), record["security_layer"])


if __name__ == "__main__":
    unittest.main()
