#!/usr/bin/env python3
"""Suite nonroot: the subscription a Multi-Node cluster hands its client.

5.6 is the first case that reads the Panel's *public* output for a cluster
rather than for a single node. What a case can get wrong here is not the YAML
Mihomo parses — the shared subscription cases already cover that — but the
wiring around it: which names the served list must dial, which SNI it must
present, whether the client engines can resolve the Worker at all, and whether
the inventory the Master publishes is really both nodes' rather than the
one-node default. Each of those turns a Working cluster into a subscription a
client cannot use, so each is held here.
"""
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tests.test_podman_subscriptions import (  # noqa: E402
    SHORT_UUID, StubEngineHost, engine_representations, engine_result,
    engine_share_links, installed_product, panel_result, served_facts,
)
from tests.test_podman_topology import FakePodman  # noqa: E402
from tools.podman_e2e import aio, matrix, multi_node, topology  # noqa: E402


class TestSubscriptionDomains(unittest.TestCase):
    """A subscription is complete only when every node appears on the right side."""

    def _aio(self, vision_domain=None):
        return topology.AioTopology(
            FakePodman(), egress_resolvers=["192.0.2.53"], vision_domain=vision_domain,
        )

    def _cluster(self, worker_vision_domain=None):
        return topology.MultiNodeTopology(
            FakePodman(), egress_resolvers=["192.0.2.53"],
            worker_vision_domain=worker_vision_domain,
        )

    def test_the_single_node_dials_its_own_name_and_presents_its_reality_sni(self):
        domains = self._aio().subscription_domains()
        self.assertEqual(domains["allowed"], {topology.PANEL_DOMAIN, topology.REALITY_DOMAIN})
        self.assertEqual(domains["required_hosts"], {topology.PANEL_DOMAIN})
        self.assertEqual(domains["required_snis"], {topology.REALITY_DOMAIN},
                         "a REALITY inbound is dialled by the node name and presents its own SNI")

    def test_the_single_node_vision_name_is_required_on_both_sides(self):
        domains = self._aio(topology.VISION_DOMAIN).subscription_domains()
        self.assertIn(topology.VISION_DOMAIN, domains["required_hosts"])
        self.assertIn(topology.VISION_DOMAIN, domains["required_snis"])

    def test_the_cluster_requires_the_worker_beside_the_master(self):
        domains = self._cluster().subscription_domains()
        self.assertEqual(domains["required_hosts"],
                         {topology.PANEL_DOMAIN, topology.WORKER_DOMAIN})
        self.assertEqual(domains["required_snis"],
                         {topology.REALITY_DOMAIN, topology.WORKER_REALITY_DOMAIN})
        self.assertEqual(domains["allowed"], {
            topology.PANEL_DOMAIN, topology.REALITY_DOMAIN,
            topology.WORKER_DOMAIN, topology.WORKER_REALITY_DOMAIN,
        })

    def test_the_worker_vision_name_is_required_on_both_sides(self):
        domains = self._cluster(topology.WORKER_VISION_DOMAIN).subscription_domains()
        self.assertIn(topology.WORKER_VISION_DOMAIN, domains["required_hosts"])
        self.assertIn(topology.WORKER_VISION_DOMAIN, domains["required_snis"])
        self.assertIn(topology.WORKER_VISION_DOMAIN, domains["allowed"])

    def test_every_name_a_subscription_may_dial_is_pinned_in_the_client_engines(self):
        for host in (self._aio(), self._aio(topology.VISION_DOMAIN),
                     self._cluster(), self._cluster(topology.WORKER_VISION_DOMAIN)):
            self.assertEqual(set(host.engine_hosts()), host.subscription_domains()["allowed"])

    def test_the_worker_names_resolve_to_the_worker_not_the_master(self):
        host = self._cluster(topology.WORKER_VISION_DOMAIN)
        hosts = host.engine_hosts()
        for name in host.worker_domains():
            self.assertEqual(hosts[name], str(host.plan.worker_ip),
                             f"{name} pinned to the Master would make the client dial the wrong node")
        for name in set(hosts) - host.worker_domains():
            self.assertEqual(hosts[name], str(host.plan.target_ip))
        self.assertNotEqual(host.plan.worker_ip, host.plan.target_ip)


class TestClusterSubscriptionInventory(unittest.TestCase):
    """The Master publishes the squad's inbounds, so both nodes' profiles are served."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _product(self, vision=False, worker_vision=False):
        return multi_node.MultiNodeProduct(
            FakePodman(), vision=vision, worker_vision=worker_vision,
        )

    def test_the_published_inventory_is_both_nodes_in_matrix_order(self):
        data = matrix.load()
        expected = [str(inbound["id"]) for inbound in matrix.inbounds(data, vision=False)] * 2
        product = self._product()
        self.assertEqual(
            [str(inbound["id"]) for inbound in product.master.subscription_inbounds()],
            expected,
        )

    def test_the_published_inventory_matches_the_cluster_inbound_total(self):
        for flags in ((False, False), (True, False), (False, True), (True, True)):
            product = self._product(*flags)
            self.assertEqual(product.master.subscription_inbound_count,
                             product.expected_inbound_total, flags)

    def test_the_protocol_split_follows_the_per_node_configuration(self):
        expected = {
            (False, False): {"vless": 6, "trojan": 2},
            (True, False): {"vless": 7, "trojan": 2},
            (False, True): {"vless": 7, "trojan": 2},
            (True, True): {"vless": 8, "trojan": 2},
        }
        for flags, counts in expected.items():
            product = self._product(*flags)
            self.assertEqual(aio.subscription_protocol_counts(product.master), counts, flags)

    def test_the_single_node_product_keeps_its_own_inventory(self):
        product = aio.AioProduct(FakePodman())
        self.assertIsNone(product.subscription_inbounds_override)
        self.assertEqual(product.subscription_inbound_count, 4)
        self.assertEqual(aio.subscription_protocol_counts(product), {"vless": 3, "trojan": 1})


class _ClusterHost(StubEngineHost):
    """The Multi-Node host interface a subscription case reads, without containers.

    The domains are written out rather than recomputed: what a cluster must
    publish is the topology's rule, and it is covered above. What this double
    answers is only "the case asked the host, and the host named the Worker".
    """

    def subscription_domains(self):
        return {
            "allowed": {
                topology.PANEL_DOMAIN, topology.REALITY_DOMAIN,
                topology.WORKER_DOMAIN, topology.WORKER_REALITY_DOMAIN,
            },
            "required_hosts": {topology.PANEL_DOMAIN, topology.WORKER_DOMAIN},
            "required_snis": {topology.REALITY_DOMAIN, topology.WORKER_REALITY_DOMAIN},
        }


class TestWorkerSubscriptionCases(unittest.TestCase):
    """SUB-SERVED and SUB-B64 refuse a subscription that leaves the Worker out."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.context = type("_Context", (), {"topology_name": "multi-node"})()

    def _product(self, engine):
        product, _ = installed_product(
            self.context,
            host_scripts=[panel_result({"subscriptions": served_facts()})],
        )
        product.host = _ClusterHost([engine_result(engine)])
        return product

    def test_the_share_link_list_must_dial_the_worker(self):
        product = self._product(engine_share_links())
        with self.assertRaises(AssertionError) as caught:
            aio.case_share_links(product)
        self.assertIn(topology.WORKER_DOMAIN, str(caught.exception))
        self.assertIn("no link dials", str(caught.exception))

    def test_the_share_link_list_must_present_the_worker_sni(self):
        product = self._product(engine_share_links({
            "hosts": [topology.PANEL_DOMAIN, topology.WORKER_DOMAIN],
        }))
        with self.assertRaises(AssertionError) as caught:
            aio.case_share_links(product)
        self.assertIn(topology.WORKER_REALITY_DOMAIN, str(caught.exception))
        self.assertIn("SNI", str(caught.exception))

    def test_a_list_dialling_both_nodes_is_accepted(self):
        product = self._product(engine_share_links({
            "hosts": [topology.PANEL_DOMAIN, topology.WORKER_DOMAIN],
            "snis": [topology.REALITY_DOMAIN, topology.WORKER_REALITY_DOMAIN],
        }))
        evidence = aio.case_share_links(product)
        self.assertIn(topology.WORKER_DOMAIN, evidence["hosts"])

    def test_the_mihomo_yaml_must_address_the_worker(self):
        product = self._product(engine_representations())
        with self.assertRaises(AssertionError) as caught:
            aio.case_subscriptions(product)
        self.assertIn(topology.WORKER_DOMAIN, str(caught.exception))
        self.assertIn("Mihomo", str(caught.exception))

    def test_a_yaml_addressing_both_nodes_is_accepted(self):
        engine = engine_representations()
        engine["mihomo"]["proxy_details"] = [
            {"name": "REALITY", "type": "vless", "server": topology.PANEL_DOMAIN},
            {"name": "XHTTP", "type": "vless", "server": topology.PANEL_DOMAIN},
            {"name": "WS", "type": "vless", "server": topology.WORKER_DOMAIN},
            {"name": "TROJAN", "type": "trojan", "server": topology.WORKER_DOMAIN},
        ]
        product = self._product(engine)
        evidence = aio.case_subscriptions(product)
        self.assertEqual(evidence["mihomo_servers"],
                         f"{topology.PANEL_DOMAIN},{topology.WORKER_DOMAIN}")
        self.assertEqual(evidence["short_uuid_length"], len(SHORT_UUID))

    def test_the_clash_subset_grows_with_the_cluster(self):
        # GenerateClash keeps only the trojan subset, and each node issues one, so
        # a two-node Panel serves two Clash proxies. A single-node expectation
        # here failed the live run podman-multi-node-20261112T205435-fb78f4c3 with
        # "the clash YAML declares 2 proxies, expected 1" while the Panel was right.
        data = matrix.load()
        cluster = (matrix.inbounds(data, vision=False) * 2)
        engine = engine_representations({
            "base64.link_count": 8,
            "xray_json.entries": 8,
            "mihomo.proxies": 8,
            "mihomo.proxy_details": [
                {"name": "REALITY", "type": "vless", "server": topology.PANEL_DOMAIN},
                {"name": "XHTTP", "type": "vless", "server": topology.PANEL_DOMAIN},
                {"name": "WS", "type": "vless", "server": topology.PANEL_DOMAIN},
                {"name": "TROJAN", "type": "trojan", "server": topology.PANEL_DOMAIN},
                {"name": "REALITY-worker", "type": "vless", "server": topology.WORKER_DOMAIN},
                {"name": "XHTTP-worker", "type": "vless", "server": topology.WORKER_DOMAIN},
                {"name": "WS-worker", "type": "vless", "server": topology.WORKER_DOMAIN},
                {"name": "TROJAN-worker", "type": "trojan", "server": topology.WORKER_DOMAIN},
            ],
            "clash.proxies": 2,
            "singbox.outbounds": 8,
        })
        product = self._product(engine)
        product.subscription_inbounds_override = cluster
        evidence = aio.case_subscriptions(product)
        self.assertEqual(evidence["clash_proxies"], 2)
        self.assertEqual(evidence["mihomo_proxies"], 8)


if __name__ == "__main__":
    unittest.main()
