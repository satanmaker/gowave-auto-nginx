#!/usr/bin/env python3
"""Suite nonroot: the checked-in protocol/client matrix is the single source of tuples.

Every data-plane case id, every transport the probe runs, and the 8/10 count the
run owes come from ``tests/cases/matrix.yaml`` through this module. These tests
hold that contract: a matrix edit that removes an inbound, renames a client, or
declares a count its own tuples do not produce must fail here rather than
silently shrinking what the product acceptance claims to have covered.
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

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


if __name__ == "__main__":
    unittest.main()
