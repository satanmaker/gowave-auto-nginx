#!/usr/bin/env python3
"""Suite nonroot: the Multi-Node topology, provisioning path, and its cases.

The Multi-Node suite runs two real installed hosts, so most of what can go
wrong there cannot be reproduced in a unit test. What *can* be held here is the
part the live run depends on being right: which roles the topology creates,
which addresses they own, what command provisions the Worker, and how the
Worker's own report is read. A mistake in any of them turns a real product
defect into a harness failure — or worse, a wrong node into a passing case.
"""
import base64
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(TESTS_DIR))

from tools.podman_e2e import aio, matrix, mtls, multi_node, topology  # noqa: E402
from tools.podman_e2e.runner import Case, CaseBlocked  # noqa: E402
from test_podman_aio import BROKEN_TAIL, nginx_probe  # noqa: E402


class _StubContext:
    topology_name = "multi-node"

    def __init__(self, root):
        self.run_id = "podman-multi-node-test-00000000"
        self.topology = "multi-node"
        self.secret_dir = root
        self.environment = {}

    def resource_name(self, prefix):
        return f"{prefix}-test"

    def add_cleanup(self, action):
        pass


class _StubPodman:
    def __init__(self, root):
        self.context = _StubContext(root)
        self.started = []

    def network_subnets(self):
        return []

    def run(self, **kwargs):
        self.started.append(kwargs["name"])
        return kwargs["name"]


class TestMultiNodePlan(unittest.TestCase):
    """The run plan must give every role its own address."""

    def test_every_role_gets_a_distinct_address_on_both_networks(self):
        plan = topology.allocate_plan([])
        control = {
            "dns": plan.dns_ip,
            "master": plan.target_ip,
            "pebble": plan.pebble_ip,
            "echo": plan.echo_ip,
            "client": plan.client_ip,
            "engine": plan.engine_client_ip,
            "worker": plan.worker_ip,
            "untrusted": plan.untrusted_ip,
        }
        self.assertEqual(len(set(control.values())), len(control),
                         "two roles sharing an address would make attribution impossible")
        data = {"master": plan.data_target_ip, "echo": plan.data_echo_ip,
                "worker": plan.data_worker_ip}
        self.assertEqual(len(set(data.values())), len(data))
        for address in data.values():
            self.assertTrue(address.startswith("203.") or address.startswith("198."),
                            f"{address} is outside the data plane's global ranges")

    def test_the_worker_is_not_the_master(self):
        plan = topology.allocate_plan([])
        self.assertNotEqual(plan.worker_ip, plan.target_ip)
        self.assertNotEqual(plan.data_worker_ip, plan.data_target_ip)


class TestMultiNodeRoles(unittest.TestCase):
    """5.1: the run's roles exist, own distinct addresses, and are the ones cases name."""

    PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

    def setUp(self):
        # The AIO suite already has a Podman stand-in that records every start,
        # so the role test uses it rather than a second, weaker imitation.
        from tests.test_podman_topology import FakePodman

        self.podman = FakePodman()
        self.addCleanup(self.podman.context.run_cleanup)
        self.host = topology.MultiNodeTopology(self.podman, egress_resolvers=["192.0.2.53"])

    def _create(self):
        from tools.podman_e2e import acme_fixture

        with unittest.mock.patch.object(acme_fixture.AcmeFixture, "issued_root",
                                        return_value=self.PEM), \
                unittest.mock.patch.object(acme_fixture.AcmeFixture, "wait_ready",
                                           return_value=None):
            self.host.create()
        return self.host

    def _runs(self):
        return {kwargs["name"]: kwargs for kwargs in self.podman.runs}

    def test_create_starts_every_declared_role_that_is_not_on_demand(self):
        host = self._create()
        started = [role["container"] for role in host.require_roles()]
        self.assertEqual(len(started), 6, "the change declares six roles")
        self.assertIn(host.client_name, started)
        self.assertIn(host.target_name, started)
        self.assertIn(host.worker_name, started)
        self.assertIn(host.untrusted_name, started)
        self.assertIn(host.echo_name, started)
        self.assertIn(host.engine_client_name, started)

    def test_every_role_owns_its_own_addresses(self):
        host = self._create()
        addresses = [
            address for role in host.roles() for address in role["addresses"]
        ]
        self.assertEqual(len(set(addresses)), len(addresses),
                         "two roles sharing an address would make attribution impossible")

    def test_only_the_two_nodes_are_product_installed(self):
        host = self._create()
        installed = {role["role"] for role in host.roles() if role["product_installed"]}
        self.assertEqual(installed, {"master", "worker"})

    def test_the_worker_and_the_master_start_before_the_denial_vantage_is_used(self):
        host = self._create()
        order = list(host.started)
        self.assertLess(order.index(host.target_name), order.index(host.worker_name),
                        "the Worker is provisioned from the Master, so the Master is first")
        self.assertLess(order.index(host.worker_name), order.index(host.untrusted_name),
                        "a denial runs after both nodes exist, or it proves nothing")

    def test_the_worker_is_a_privileged_systemd_host_and_the_denial_role_is_not(self):
        self._create()
        runs = self._runs()
        self.assertTrue(runs[self.host.worker_name]["privileged"])
        self.assertEqual(runs[self.host.worker_name]["systemd"], "always")
        self.assertFalse(runs[self.host.untrusted_name]["privileged"])
        self.assertEqual(runs[self.host.untrusted_name]["systemd"], "false")

    def test_the_denial_role_runs_the_clean_image_so_a_real_login_can_be_attempted(self):
        # The fixture image has no SSH client, so the refusal would be skipped
        # rather than measured. The clean target image carries one and still
        # holds no product package, credential, or node identity.
        from tools.podman_e2e import target_image

        self._create()
        runs = self._runs()
        self.assertEqual(
            runs[self.host.untrusted_name]["image_alias"],
            target_image.tag(self.host.distribution),
        )
        self.assertNotEqual(
            runs[self.host.untrusted_name]["image_alias"],
            topology.FIXTURE_IMAGE,
        )

    def test_a_role_that_never_started_is_refused_by_name(self):
        host = self._create()
        host.started.remove(host.worker_name)
        with self.assertRaises(topology.TopologyError) as caught:
            host.require_roles()
        self.assertIn(host.worker_name, str(caught.exception))

    def test_the_master_is_the_runs_dual_stack_host_and_the_worker_is_not(self):
        # 6.7: the product reads the kernel rather than a flag, so the two branches
        # only exist if both roles are given opposite answers before either install
        # runs. Swapping them would make the case inspect one branch twice.
        host = self._create()
        master = "".join(script for name, script in self.podman.scripts
                         if name == host.target_name)
        worker = "".join(script for name, script in self.podman.scripts
                         if name == host.worker_name)
        self.assertIn("echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6", master)
        self.assertIn("echo 0 > /proc/sys/net/ipv6/conf/lo/disable_ipv6", master)
        self.assertIn("readarray -t addresses < /proc/net/if_inet6", master)
        self.assertNotIn("echo 1 > /proc/sys/net/ipv6", master)
        self.assertIn("echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6", worker)
        self.assertIn("echo 1 > /proc/sys/net/ipv6/conf/lo/disable_ipv6", worker)
        self.assertNotIn("echo 0 > /proc/sys/net/ipv6", worker)
        self.assertEqual(host.ipv6_address, topology.IPV6_HOST_ADDRESS)
        self.assertIn(
            (host.target_name, ["cat", "/proc/net/if_inet6"]),
            [tuple(entry) for entry in self.podman.execs],
            "the address the product will read has to be confirmed, not assumed",
        )

    def test_the_on_demand_engine_role_is_not_required_before_a_case_needs_it(self):
        host = self._create()
        self.assertNotIn(host.engine_client_name, host.started)
        host.require_roles()


def _ssh_ed25519(seed, comment):
    """A well-formed ed25519 public key line, so the fingerprint helper is exercised for real."""
    blob = b"\x00\x00\x00\x0b" + b"ssh-ed25519" + b"\x00\x00\x00\x20" + seed
    return f"ssh-ed25519 {base64.b64encode(blob).decode('ascii')} {comment}"


MASTER_PUBLIC_KEY = _ssh_ed25519(b"m" * 32, "root@master")
WORKER_HOST_KEY = _ssh_ed25519(b"w" * 32, "root@worker")


def _append_targets(script):
    """The files a shell snippet appends to, read out of its own ``>>`` redirects."""
    targets = []
    for fragment in script.split(">>")[1:]:
        words = fragment.split()
        if words:
            targets.append(words[0].rstrip(";"))
    return targets


class _TrustPodman(_StubPodman):
    """A Podman stand-in whose only fidelity is whether stdin reaches the command.

    ``drop_stdin`` names the files whose append must be silently lost. That is
    precisely what ``podman exec`` without ``-i`` did: the command exited 0 and
    the file stayed empty, so the product's own preflight was the first thing to
    notice the missing key.
    """

    def __init__(self, root, drop_stdin=()):
        super().__init__(root)
        self.drop_stdin = tuple(drop_stdin)
        self.files = {}

    def exec_bash(self, name, script, check=True, input_text=None, timeout=300):
        if "ssh-keygen" in script:
            self.files[(name, "/root/.ssh/id_ed25519.pub")] = MASTER_PUBLIC_KEY + "\n"
            return subprocess.CompletedProcess(["bash"], 0, "", "")
        return self.exec(name, ["bash", "-c", script], check=check, input_text=input_text, timeout=timeout)

    def exec(self, name, argv, check=True, input_text=None, timeout=300):
        if argv[0] == "cat":
            content = self.files.get((name, argv[1]))
            if content is None:
                return subprocess.CompletedProcess(argv, 1, "", f"cat: {argv[1]}: No such file")
            return subprocess.CompletedProcess(argv, 0, content, "")
        if argv[0] == "bash":
            for target in _append_targets(argv[2]):
                if input_text is None or any(fragment in target for fragment in self.drop_stdin):
                    continue
                key = (name, target)
                self.files[key] = self.files.get(key, "") + input_text
            return subprocess.CompletedProcess(argv, 0, "", "")
        raise AssertionError(f"unexpected exec: {argv}")


class TestWorkerTrustPin(unittest.TestCase):
    """5.2: the trust the product preflight checks is proven, never assumed."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def host(self, **kwargs):
        podman = _TrustPodman(Path(self.tmp.name), **kwargs)
        host = topology.MultiNodeTopology(podman, egress_resolvers=["192.0.2.53"])
        podman.files[(host.worker_name, "/etc/ssh/ssh_host_ed25519_key.pub")] = WORKER_HOST_KEY + "\n"
        return host

    def test_the_pin_is_reported_and_present_on_both_sides(self):
        host = self.host()
        evidence = host.pin_worker_trust()
        files = host.podman.files
        self.assertIn(topology.MultiNodeTopology._key_blob(MASTER_PUBLIC_KEY),
                      files[(host.worker_name, "/root/.ssh/authorized_keys")])
        self.assertIn(topology.MultiNodeTopology._key_blob(WORKER_HOST_KEY),
                      files[(host.target_name, "/root/.ssh/known_hosts")])
        self.assertEqual(evidence["known_hosts_entry"], host.plan.worker_ip)
        self.assertTrue(evidence["master_key_fingerprint"].startswith("SHA256:"))

    def test_a_lost_authorized_key_write_is_refused_by_name(self):
        host = self.host(drop_stdin=("authorized_keys",))
        with self.assertRaises(topology.TopologyError) as caught:
            host.pin_worker_trust()
        self.assertIn("authorized_keys", str(caught.exception))
        self.assertIn(host.worker_name, str(caught.exception))

    def test_a_lost_known_hosts_write_is_refused_before_the_product_preflight(self):
        host = self.host(drop_stdin=("known_hosts",))
        with self.assertRaises(topology.TopologyError) as caught:
            host.pin_worker_trust()
        self.assertIn("known_hosts", str(caught.exception))
        self.assertIn(host.target_name, str(caught.exception))


class TestPodmanExecAttachesStdin(unittest.TestCase):
    """Delivery over stdin only happens when ``podman exec`` is handed ``-i``."""

    def podman(self):
        from tools.podman_e2e.podman import Podman
        from tools.podman_e2e.runner import RunContext

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with unittest.mock.patch("tools.podman_e2e.podman.podman_binary", return_value="/usr/bin/podman"):
            instance = Podman(RunContext(
                "multi-node", Path(tmp.name), budget_seconds=60,
                run_id="podman-multi-node-stdin-00000000",
            ))
        calls = []

        def record(args, check=True, input_text=None, timeout=300):
            calls.append((list(args), input_text))
            return subprocess.CompletedProcess(list(args), 0, "", "")

        instance._run = record
        return instance, calls

    def test_an_append_travels_over_attached_stdin(self):
        podman, calls = self.podman()
        podman.exec("worker", ["bash", "-c", "cat >> /root/.ssh/authorized_keys"],
                    input_text=MASTER_PUBLIC_KEY + "\n")
        argv, delivered = calls[0]
        self.assertEqual(argv[:5], ["exec", "-i", "worker", "bash", "-c"])
        self.assertEqual(delivered, MASTER_PUBLIC_KEY + "\n")

    def test_a_command_without_input_does_not_attach_stdin(self):
        podman, calls = self.podman()
        podman.exec("worker", ["cat", "/etc/ssh/ssh_host_ed25519_key.pub"])
        argv, delivered = calls[0]
        self.assertNotIn("-i", argv)
        self.assertIsNone(delivered)


class TestMultiNodeZone(unittest.TestCase):
    """The fixture zone has to answer for the Worker's names as well."""

    def setUp(self):
        import tempfile

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.podman = _StubPodman(Path(self.tmp.name))

    def test_the_zone_resolves_the_worker_names_to_the_worker(self):
        host = topology.MultiNodeTopology(self.podman, egress_resolvers=["192.0.2.53"])
        records = host.zone()["records"]
        self.assertEqual(records[topology.WORKER_DOMAIN]["A"], [host.plan.worker_ip])
        self.assertEqual(records[topology.WORKER_REALITY_DOMAIN]["A"], [host.plan.worker_ip])
        self.assertNotIn(topology.WORKER_VISION_DOMAIN, records,
                         "an unconfigured Vision domain must not resolve at all")

    def test_the_worker_vision_domain_appears_only_when_configured(self):
        host = topology.MultiNodeTopology(
            self.podman,
            egress_resolvers=["192.0.2.53"],
            worker_vision_domain=topology.WORKER_VISION_DOMAIN,
        )
        records = host.zone()["records"]
        self.assertEqual(records[topology.WORKER_VISION_DOMAIN]["A"], [host.plan.worker_ip])

    def test_the_master_names_keep_pointing_at_the_master(self):
        host = topology.MultiNodeTopology(self.podman, egress_resolvers=["192.0.2.53"])
        records = host.zone()["records"]
        self.assertEqual(records[topology.PANEL_DOMAIN]["A"], [host.plan.target_ip])
        self.assertEqual(records[topology.REALITY_DOMAIN]["A"], [host.plan.target_ip])

    def test_the_endpoint_accepts_payloads_only_from_both_node_identities(self):
        host = topology.MultiNodeTopology(self.podman, egress_resolvers=["192.0.2.53"])
        self.assertEqual(host.echo_allow_sources(),
                         [host.plan.data_target_ip, host.plan.data_worker_ip])
        for client_ip in (host.plan.client_ip, host.plan.engine_client_ip):
            self.assertNotIn(client_ip, host.echo_allow_sources(),
                             "a client vantage cannot own a node's egress identity")


class TestWorkerProvisioningCommand(unittest.TestCase):
    """The Worker is provisioned by the operator's own command, not by the harness."""

    def setUp(self):
        import tempfile

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.podman = _StubPodman(Path(self.tmp.name))

    def test_the_command_is_the_operator_entrypoint_with_positional_roles(self):
        host = topology.MultiNodeTopology(self.podman, egress_resolvers=["192.0.2.53"])
        script = host.node_add_script("worker-1")
        self.assertTrue(script.startswith(f"bash {topology.REPO_IN_CONTAINER}/gowave-auto.sh node add"))
        self.assertIn(f"'{host.plan.worker_ip}'", script)
        self.assertIn(f"'{host.worker_domain}'", script)
        self.assertIn(f"'{host.worker_reality_domain}'", script)
        self.assertNotIn("--vision-domain", script)

    def test_the_vision_flag_is_opt_in_per_node(self):
        host = topology.MultiNodeTopology(
            self.podman,
            egress_resolvers=["192.0.2.53"],
            worker_vision_domain=topology.WORKER_VISION_DOMAIN,
        )
        script = host.node_add_script()
        self.assertIn(f"--vision-domain '{topology.WORKER_VISION_DOMAIN}'", script)

    def test_the_command_carries_no_secret(self):
        host = topology.MultiNodeTopology(self.podman, egress_resolvers=["192.0.2.53"])
        script = host.node_add_script()
        for forbidden in ("SECRET_KEY", "ADMIN_PASSWORD", "accessToken"):
            self.assertNotIn(forbidden, script)


class TestWorkerControlReport(unittest.TestCase):
    """The Worker's own report is the evidence the Master address case asserts on."""

    REPORT = """\
== node service ==
active
== listeners ==
0.0.0.0:3002
== established peers ==
0      0      10.89.0.11:3002     10.89.0.10:54122
0      0      10.89.0.11:3002     10.89.0.10:54124
0      0      10.89.0.11:443      10.89.0.40:51000
== firewall ==
Status: active
3002                       ALLOW       10.89.0.10             # GoWave Control Plane IPv4
22/tcp                     ALLOW       Anywhere
"""

    def test_the_report_is_split_into_the_sections_the_cases_assert_on(self):
        facts = multi_node.parse_worker_control(self.REPORT)
        self.assertEqual(facts["node_service"], "active")
        self.assertEqual(facts["listeners"], ["0.0.0.0:3002"])

    def test_only_control_port_peers_are_reported(self):
        facts = multi_node.parse_worker_control(self.REPORT)
        self.assertEqual(facts["peers"], ["10.89.0.10"],
                         "a data-plane connection to :443 is not a control-plane peer")

    def test_duplicate_peers_are_collapsed(self):
        facts = multi_node.parse_worker_control(self.REPORT)
        self.assertEqual(len(facts["peers"]), 1)

    def test_a_dual_stack_socket_reports_the_master_as_plain_ipv4(self):
        # The node binds ``::``, so an IPv4 Master arrives on an IPv6 socket and
        # ``ss`` prints the peer as ``[::ffff:10.89.0.10]:port``. Comparing that
        # text with the plan's address would fail on notation, not on routing.
        report = self.REPORT.replace(
            "10.89.0.11:3002     10.89.0.10:54122",
            "[::ffff:10.89.0.11]:3002     [::ffff:10.89.0.10]:54122",
        ).replace(
            "10.89.0.11:3002     10.89.0.10:54124",
            "[::ffff:10.89.0.11]:3002     [::ffff:10.89.0.10]:54124",
        )
        facts = multi_node.parse_worker_control(report)
        self.assertEqual(facts["peers"], ["10.89.0.10"])

    def test_a_plain_ipv6_peer_keeps_its_own_notation(self):
        self.assertEqual(multi_node.normalize_peer_host("[fd00::1]"), "fd00::1")
        self.assertEqual(multi_node.normalize_peer_host("[::ffff:203.0.113.9]"), "203.0.113.9")
        self.assertEqual(multi_node.normalize_peer_host("[not-an-address]"), "[not-an-address]")

    def test_the_firewall_rule_names_the_master_address(self):
        facts = multi_node.parse_worker_control(self.REPORT)
        self.assertEqual(
            multi_node.firewall_master_sources(facts["firewall"]), ["10.89.0.10"],
        )

    def test_a_generic_rule_is_not_mistaken_for_a_control_plane_rule(self):
        rules = [
            "3002                       ALLOW       Anywhere",
            "3002/tcp                   ALLOW       Anywhere",
        ]
        self.assertEqual(multi_node.firewall_master_sources(rules), [])

    def test_an_empty_report_is_an_empty_report(self):
        facts = multi_node.parse_worker_control("")
        self.assertEqual(facts, {"node_service": "", "listeners": [], "peers": [], "firewall": []})


class _AddressProduct:
    """A product stub: it reports what the Worker said and what the plan expects."""

    def __init__(self, peers, sources, service="active", listeners=("0.0.0.0:3002",)):
        self.reported = {
            "node_service": service,
            "listeners": list(listeners),
            "peers": list(peers),
            "firewall": [
                f"{multi_node.NODE_PORT}  ALLOW  {source}  # GoWave Control Plane IPv4"
                for source in sources
            ],
        }
        self.topology = type("Host", (), {"plan": topology.allocate_plan([])})()

    def require_installed(self):
        return self.topology

    def worker_control_facts(self, case_id, timeout=120):
        return self.reported


class TestMasterAddressCase(unittest.TestCase):
    """PODNET-MASTER-ADDR fails closed on every way the Worker could talk to the wrong host."""

    def _run(self, product):
        return multi_node.MultiNodeProduct.worker_address_facts(
            product, multi_node.MASTER_ADDRESS_CASE_ID,
        )

    def _master(self, product):
        return product.topology.plan.target_ip

    def test_the_run_address_is_accepted_when_the_worker_uses_it(self):
        product = _AddressProduct([], [])
        product.reported["peers"] = [self._master(product)]
        product.reported["firewall"] = [
            f"3002  ALLOW  {self._master(product)}  # GoWave Control Plane IPv4"
        ]
        facts = self._run(product)
        self.assertEqual(facts["master_address"], self._master(product))
        self.assertEqual(facts["firewall_sources"], [self._master(product)])

    def test_a_public_source_is_rejected(self):
        product = _AddressProduct([], ["203.0.113.9"])
        product.reported["peers"] = [self._master(product)]
        with self.assertRaises(AssertionError) as caught:
            self._run(product)
        self.assertIn("instead of only the Master's run address", str(caught.exception))

    def test_no_live_connection_from_the_master_is_rejected(self):
        product = _AddressProduct(["10.89.0.99"], [])
        product.reported["firewall"] = [
            f"3002  ALLOW  {self._master(product)}  # GoWave Control Plane IPv4"
        ]
        with self.assertRaises(AssertionError) as caught:
            self._run(product)
        self.assertIn("no live Master-to-Worker connection", str(caught.exception))

    def test_a_peer_outside_the_run_network_is_rejected(self):
        product = _AddressProduct([], [])
        product.reported["peers"] = [self._master(product), "185.0.0.9"]
        product.reported["firewall"] = [
            f"3002  ALLOW  {self._master(product)}  # GoWave Control Plane IPv4"
        ]
        with self.assertRaises(AssertionError) as caught:
            self._run(product)
        self.assertIn("outside the run network", str(caught.exception))

    def test_an_inactive_node_service_is_rejected(self):
        product = _AddressProduct([], [])
        product.reported["node_service"] = "failed"
        product.reported["peers"] = [self._master(product)]
        with self.assertRaises(AssertionError) as caught:
            self._run(product)
        self.assertIn("instead of active", str(caught.exception))

    def test_a_missing_control_listener_is_rejected(self):
        product = _AddressProduct([], [])
        product.reported["listeners"] = []
        product.reported["peers"] = [self._master(product)]
        with self.assertRaises(AssertionError) as caught:
            self._run(product)
        self.assertIn("listens on no control port", str(caught.exception))


class _RegistrationProduct:
    """A product stub: it reports the Panel's node table and nothing else."""

    combination = "neither"
    expected_inbound_total = 8

    def __init__(self, hosts=2, name=None, connected=True, endpoint_port=3002,
                 inbound_count=8):
        plan = topology.allocate_plan([])
        self.topology = type("Host", (), {"plan": plan})()
        name = name or topology.WORKER_NODE_NAME
        self.surface = {
            "nodes": {
                "names": sorted(["local-node", name]),
                "endpoints": sorted([
                    "127.0.0.1:3002",
                    f"{plan.worker_ip}:{endpoint_port}",
                ]),
                "connected": {"local-node": True, name: connected},
                "count": 2,
                "connected_count": 2 if connected else 1,
                "inbound_count": inbound_count,
                "inbound_types": ["vless", "trojan"],
            },
            "hosts": {"count": hosts},
            "unauthenticated_nodes_status": 401,
        }

    def require_installed(self):
        return self.topology

    def add_worker(self):
        return {"node_add_returncode": 0}

    def wait_for_nodes(self, case_id, expected):
        return {"nodes": {"count": 2, "connected_count": 2}}

    def panel_surface(self, case_id):
        return {"surface": self.surface}


class TestWorkerRegistrationCase(unittest.TestCase):
    """WRK-04 names the registered Worker instead of counting nodes."""

    def _evidence(self, product):
        return multi_node.case_worker_registration(product)

    def test_the_registered_worker_is_named_with_its_endpoint_and_connection(self):
        product = _RegistrationProduct()
        evidence = self._evidence(product)
        self.assertEqual(evidence["worker_endpoint"],
                         f"{product.topology.plan.worker_ip}:3002")
        self.assertIn(topology.WORKER_NODE_NAME, evidence["panel_node_names"])
        self.assertIs(evidence["panel_node_connected"][topology.WORKER_NODE_NAME], True)

    def test_two_nodes_without_the_worker_name_are_rejected(self):
        with self.assertRaises(AssertionError) as caught:
            self._evidence(_RegistrationProduct(name="worker-2"))
        self.assertIn("none of them is the registered Worker", str(caught.exception))

    def test_a_worker_registered_on_the_wrong_port_is_rejected(self):
        with self.assertRaises(AssertionError) as caught:
            self._evidence(_RegistrationProduct(endpoint_port=3003))
        self.assertIn("instead of registering the Worker at", str(caught.exception))

    def test_a_registered_but_disconnected_worker_is_rejected(self):
        with self.assertRaises(AssertionError) as caught:
            self._evidence(_RegistrationProduct(connected=False))
        self.assertIn("rather than connected", str(caught.exception))

    def test_a_node_total_that_disagrees_with_the_configuration_is_rejected(self):
        with self.assertRaises(AssertionError) as caught:
            self._evidence(_RegistrationProduct(inbound_count=7))
        self.assertIn("active inbounds in total", str(caught.exception))


class TestRunnerEntrypoint(unittest.TestCase):
    """The CLI's flags must reach the suite; a dropped flag is a silent coverage gap."""

    def setUp(self):
        import tempfile

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _main(self, argv):
        from tools import run_podman_e2e

        captured = {}

        class _Podman:
            def __init__(self, context):
                self.context = context

            def register_cleanup(self):
                pass

        class _Runner:
            def __init__(self, context):
                pass

            def add(self, case):
                pass

            def execute(self):
                return 0

        def suite(podman, topology, distribution, vision=False, worker_vision=False):
            captured.update(
                topology=topology, distribution=distribution,
                vision=vision, worker_vision=worker_vision,
            )
            return []

        for name, value in (("Podman", _Podman), ("Runner", _Runner), ("build_suite", suite)):
            patcher = unittest.mock.patch.object(run_podman_e2e, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        argv = list(argv) + ["--artifact-root", str(self.tmp.name)]
        # The CLI reports its artifact directory and its usage errors on the
        # standard streams; a unit test is not the place for either.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            status = run_podman_e2e.main(argv)
        self.assertEqual(status, 0)
        return captured

    def test_both_vision_flags_reach_the_multi_node_suite(self):
        captured = self._main(["--topology", "multi-node", "--vision", "--worker-vision"])
        self.assertEqual(captured["topology"], "multi-node")
        self.assertTrue(captured["vision"])
        self.assertTrue(captured["worker_vision"])

    def test_an_unset_flag_reaches_the_suite_as_false(self):
        captured = self._main(["--topology", "multi-node"])
        self.assertFalse(captured["vision"])
        self.assertFalse(captured["worker_vision"])

    def test_the_aio_topology_rejects_the_worker_vision_flag(self):
        with self.assertRaises(SystemExit) as caught:
            self._main(["--topology", "aio", "--worker-vision"])
        self.assertEqual(caught.exception.code, 2)


class TestMultiNodeCounts(unittest.TestCase):
    """The suite owes the matrix's positive count for its own configuration."""

    def setUp(self):
        import tempfile

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.podman = _StubPodman(Path(self.tmp.name))

    def _product(self, vision=False, worker_vision=False):
        return multi_node.MultiNodeProduct(
            self.podman, vision=vision, worker_vision=worker_vision,
        )

    def test_the_four_vision_combinations_are_named_and_counted(self):
        expected = {
            (False, False): ("neither", 16),
            (True, False): ("master-only", 18),
            (False, True): ("worker-only", 18),
            (True, True): ("both", 20),
        }
        for flags, (name, count) in expected.items():
            product = self._product(*flags)
            self.assertEqual(product.combination, name)
            self.assertEqual(product.positive_case_count, count)

    def test_the_inbound_total_follows_the_per_node_configuration(self):
        self.assertEqual(self._product().expected_inbound_total, 8)
        self.assertEqual(self._product(vision=True).expected_inbound_total, 9)
        self.assertEqual(self._product(worker_vision=True).expected_inbound_total, 9)
        self.assertEqual(self._product(True, True).expected_inbound_total, 10)

    def test_the_count_comes_from_the_matrix_not_from_this_module(self):
        data = matrix.load()
        self.assertEqual(
            multi_node.MultiNodeProduct(self.podman).positive_case_count,
            matrix.positive_count(data, "multi-node", False, False),
        )
        with self.assertRaises(KeyError):
            matrix.combination("aio", vision=False, worker_vision=True)


class _MatrixProduct(multi_node.MultiNodeProduct):
    """The real product with the two readiness guards satisfied by a scripted run.

    Nothing else is replaced: the tuple enumeration, the declared/executed
    registries and every assertion stay the product's own, so a test drives the
    same count path the live suite does.
    """

    def __init__(self, vision=False, worker_vision=False):
        self._root = tempfile.TemporaryDirectory()
        super().__init__(_StubPodman(Path(self._root.name)),
                         vision=vision, worker_vision=worker_vision)
        self.topology = type("Host", (), {"plan": topology.allocate_plan([])})()

    def cleanup(self):
        self._root.cleanup()

    def require_installed(self):
        return self.topology

    def require_worker(self):
        return self.topology


class TestMatrixCase(unittest.TestCase):
    """MN-MATRIX: the positive cases are exactly the matrix tuples of both nodes."""

    def expected_ids(self, product):
        expected = []
        for node, node_vision in (("master", product.vision), ("worker", product.worker_vision)):
            for inbound, client in matrix.tuples(product.matrix, node_vision):
                expected.append(matrix.case_id(
                    product.matrix, multi_node.matrix_data.MULTI_NODE, str(inbound["id"]),
                    client, node=node,
                ))
        return expected

    def product(self, vision=False, worker_vision=False, declared=None, results=None):
        product = _MatrixProduct(vision=vision, worker_vision=worker_vision)
        self.addCleanup(product.cleanup)
        expected = self.expected_ids(product)
        product.declare_data_plane(expected if declared is None else declared)
        product.master.data_plane_results = dict(
            results if results is not None else {case_id: "PASS" for case_id in expected}
        )
        return product, expected

    def reject(self, expected_text, vision=False, worker_vision=False, declared=None,
               results=None):
        product, _expected = self.product(
            vision=vision, worker_vision=worker_vision, declared=declared, results=results,
        )
        with self.assertRaises(AssertionError) as caught:
            multi_node.case_matrix(product)
        self.assertIn(expected_text, str(caught.exception))

    def test_the_vision_less_run_owes_the_sixteen_tuples_on_both_clients(self):
        product, expected = self.product()
        evidence = multi_node.case_matrix(product)
        self.assertEqual(len(expected), 16)
        self.assertEqual(evidence["vision"], "neither")
        self.assertEqual(evidence["inbounds"], 8)
        self.assertEqual(evidence["clients"], 2)
        self.assertEqual(evidence["expected_positive_cases"], 16)
        self.assertEqual(evidence["declared_cases"], 16)
        self.assertEqual(evidence["executed_cases"], 16)
        self.assertEqual(evidence["passed_cases"], 16)
        self.assertEqual(evidence["per_node"]["master"],
                         {"inbounds": 4, "clients": ["mihomo", "xray"], "cases": 8})
        self.assertEqual(evidence["per_node"]["worker"],
                         {"inbounds": 4, "clients": ["mihomo", "xray"], "cases": 8})

    def test_each_vision_combination_owes_its_own_positive_count(self):
        expected = {
            (False, False): ("neither", 16, 4, 4),
            (True, False): ("master-only", 18, 5, 4),
            (False, True): ("worker-only", 18, 4, 5),
            (True, True): ("both", 20, 5, 5),
        }
        for flags, (name, count, master_inbounds, worker_inbounds) in expected.items():
            product, expected_ids = self.product(*flags)
            evidence = multi_node.case_matrix(product)
            self.assertEqual(len(expected_ids), count, flags)
            self.assertEqual(evidence["vision"], name)
            self.assertEqual(evidence["expected_positive_cases"], count)
            self.assertEqual(evidence["per_node"]["master"]["cases"], master_inbounds * 2)
            self.assertEqual(evidence["per_node"]["worker"]["cases"], worker_inbounds * 2)
            self.assertEqual(evidence["passed_cases"], count)

    def test_a_node_that_never_ran_one_client_fails_the_run(self):
        product, _expected = self.product()
        enumerated = multi_node.matrix_data.tuples

        def xray_only(data, vision):
            return [(inbound, client) for inbound, client in enumerated(data, vision)
                    if client == "xray"]

        with unittest.mock.patch.object(multi_node.matrix_data, "tuples", xray_only):
            with self.assertRaises(AssertionError) as caught:
                multi_node.case_matrix(product)
        self.assertIn("the master node ran ['xray'] instead of every matrix client "
                      "['mihomo', 'xray']", str(caught.exception))

    def test_a_declared_case_the_matrix_never_enumerates_fails_the_run(self):
        _, expected = self.product()
        self.reject("unexplained ['MN-DP-master-REALITY-singbox']",
                    declared=expected + ["MN-DP-master-REALITY-singbox"])

    def test_a_matrix_tuple_the_suite_never_declared_fails_the_run(self):
        _, expected = self.product()
        self.reject("missing ['MN-DP-worker-TROJAN-GRPC-mihomo']",
                    declared=[case_id for case_id in expected
                              if case_id != "MN-DP-worker-TROJAN-GRPC-mihomo"])

    def test_a_declared_case_that_produced_no_result_fails_the_run(self):
        _product, expected = self.product()
        results = {case_id: "PASS" for case_id in expected}
        del results["MN-DP-master-XHTTP-mihomo"]
        self.reject("produced no result: MN-DP-master-XHTTP-mihomo", results=results)

    def test_a_failed_tuple_fails_the_run_even_when_the_count_matches(self):
        _product, expected = self.product(worker_vision=True)
        results = {case_id: "PASS" for case_id in expected}
        results["MN-DP-worker-VISION-xray"] = "FAIL"
        self.reject("did not pass: MN-DP-worker-VISION-xray",
                    worker_vision=True, results=results)

    def test_a_case_outside_the_matrix_is_not_counted_as_a_green_one(self):
        _, expected = self.product()
        results = {case_id: "PASS" for case_id in expected}
        results["MN-DP-master-EXTRA-mihomo"] = "PASS"
        self.reject("but the matrix declares 16", results=results)

    def test_a_matrix_count_its_own_inbounds_do_not_produce_fails_the_run(self):
        product, _expected = self.product()
        product.matrix["topologies"]["multi-node"]["positive_case_counts"]["neither"] = 17
        with self.assertRaises(AssertionError) as caught:
            multi_node.case_matrix(product)
        self.assertIn("declares 17 positive case(s)", str(caught.exception))

    def test_the_case_is_blocked_when_no_install_has_run(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        product = multi_node.MultiNodeProduct(_StubPodman(Path(root.name)))
        with self.assertRaises(CaseBlocked) as caught:
            multi_node.case_matrix(product)
        self.assertIn(multi_node.INSTALL_CASE_ID, str(caught.exception))


class _Completed:
    """The shape a Podman exec returns, without a container behind it."""

    def __init__(self, payload=None, returncode=0, stdout=None, stderr=""):
        self.returncode = returncode
        self.stdout = json.dumps(payload) if stdout is None else stdout
        self.stderr = stderr


def _denial_facts(plan, vantage, **overrides):
    """What the endpoint should report for one refused direct attempt."""
    identity = plan.client_ip if vantage == "control" else plan.engine_client_ip
    node_ids = sorted({plan.data_target_ip, plan.data_worker_ip})
    facts = {
        "endpoint": f"{plan.echo_ip}:18080",
        "accepted": False,
        "status": 403,
        "reason": "HTTP 403 source-not-allowed",
        "source_ip": identity,
        "recorded": False,
        "denied_recorded": True,
        "denied_source_ip": identity,
        "denied_sources": [identity],
        "payload_sources": node_ids,
        "allowed_sources": node_ids,
    }
    facts.update(overrides)
    return facts


class _EgressHost:
    """Two node identities and the endpoint's answers to the direct probes."""

    def __init__(self, plan, facts_for=None):
        self.plan = plan
        self.facts_for = facts_for
        self.probes = []

    def node_data_ip(self, node=""):
        return str({
            "master": self.plan.data_target_ip,
            "worker": self.plan.data_worker_ip,
        }[node])

    def direct_egress_facts(self, vantage, timeout=300):
        self.probes.append(vantage)
        result = self.facts_for(self.plan, vantage) if self.facts_for else _denial_facts(
            self.plan, vantage)
        return result if isinstance(result, _Completed) else _Completed(result)


class _EgressProduct(_MatrixProduct):
    def __init__(self, facts_for=None, vision=False, worker_vision=False):
        super().__init__(vision=vision, worker_vision=worker_vision)
        self.topology = _EgressHost(self.topology.plan, facts_for)


class TestEgressCase(unittest.TestCase):
    """MN-EGRESS: the endpoint's observed source is the attribution evidence."""

    def product(self, vision=False, worker_vision=False, sources=None, facts_for=None):
        product = _EgressProduct(facts_for, vision=vision, worker_vision=worker_vision)
        self.addCleanup(product.cleanup)
        expected = {
            case_id: product.topology.node_data_ip(node)
            for case_id, _inbound, _client, node in multi_node.data_plane_cases(product)
        }
        product.declare_data_plane(list(expected))
        for case_id, source in (expected if sources is None else sources).items():
            product.record_data_plane_source(case_id, source)
        return product, expected

    def reject(self, expected_text, **kwargs):
        product, _expected = self.product(**kwargs)
        with self.assertRaises(AssertionError) as caught:
            multi_node.case_egress(product)
        self.assertIn(expected_text, str(caught.exception))

    def test_the_run_attributes_every_case_to_its_node_and_refuses_both_vantages(self):
        product, expected = self.product()
        plan = product.topology.plan
        evidence = multi_node.case_egress(product)
        self.assertEqual(len(expected), 16)
        self.assertEqual(evidence["master_identity"], plan.data_target_ip)
        self.assertEqual(evidence["worker_identity"], plan.data_worker_ip)
        self.assertEqual(evidence["attributed_cases"], 16)
        self.assertEqual(evidence["per_node"]["master"],
                         {"identity": plan.data_target_ip, "cases": 8})
        self.assertEqual(evidence["per_node"]["worker"],
                         {"identity": plan.data_worker_ip, "cases": 8})
        self.assertEqual(evidence["payload_sources"],
                         sorted({plan.data_target_ip, plan.data_worker_ip}))
        self.assertEqual(evidence["denied_sources"],
                         sorted({plan.client_ip, plan.engine_client_ip}))
        self.assertEqual(product.topology.probes, ["control", "engine"])
        self.assertEqual(evidence["denials"]["control"]["source_ip"], plan.client_ip)
        self.assertIn("source-not-allowed", evidence["denials"]["control"]["reason"])

    def test_the_vision_combination_does_not_change_the_attribution(self):
        product, expected = self.product(vision=True, worker_vision=True)
        plan = product.topology.plan
        evidence = multi_node.case_egress(product)
        self.assertEqual(len(expected), 20)
        self.assertEqual(evidence["attributed_cases"], 20)
        self.assertEqual(evidence["per_node"]["master"]["cases"], 10)
        self.assertEqual(evidence["per_node"]["worker"]["cases"], 10)

    def test_a_worker_tuple_that_left_from_the_master_fails_by_name(self):
        product, expected = self.product()
        plan = product.topology.plan
        sources = dict(expected)
        sources["MN-DP-worker-REALITY-xray"] = plan.data_target_ip
        self.reject(
            "MN-DP-worker-REALITY-xray left from "
            f"{plan.data_target_ip} instead of the worker node {plan.data_worker_ip}",
            sources=sources,
        )

    def test_a_matrix_case_without_egress_evidence_fails_the_run(self):
        product, expected = self.product()
        sources = dict(expected)
        del sources["MN-DP-master-REALITY-xray"]
        self.reject("left no egress evidence: MN-DP-master-REALITY-xray", sources=sources)

    def test_a_cluster_whose_nodes_share_an_identity_fails_the_run(self):
        with unittest.mock.patch.object(
            topology.NetworkPlan, "data_worker_ip",
            new=property(lambda self: self.data_target_ip),
        ):
            self.reject("the Master and the Worker share the egress identity")

    def test_a_direct_attempt_the_endpoint_accepted_fails_the_run(self):
        def accepted(plan, vantage):
            return _denial_facts(plan, vantage, accepted=True, status=200, recorded=True)

        self.reject("the control delivered a payload straight at the endpoint",
                    facts_for=accepted)

    def test_a_denial_attributed_to_a_node_fails_the_run(self):
        def misattributed(plan, vantage):
            return _denial_facts(plan, vantage, denied_source_ip=plan.data_worker_ip)

        self.reject("instead of the control vantage", facts_for=misattributed)

    def test_a_refusal_without_a_recorded_denial_fails_the_run(self):
        def silent(plan, vantage):
            return _denial_facts(plan, vantage, denied_recorded=False)

        self.reject("without recording the denial", facts_for=silent)

    def test_an_allowlist_wider_than_the_two_nodes_fails_the_run(self):
        def wide(plan, vantage):
            allowed = sorted({plan.data_target_ip, plan.data_worker_ip, plan.client_ip})
            return _denial_facts(plan, vantage, allowed_sources=allowed)

        self.reject("the endpoint accepts payloads from", facts_for=wide)

    def test_a_payload_the_fixture_recorded_from_a_client_fails_the_run(self):
        def leaked(plan, vantage):
            sources = sorted({plan.data_target_ip, plan.data_worker_ip, plan.client_ip})
            return _denial_facts(plan, vantage, payload_sources=sources)

        self.reject("the endpoint's own record shows payloads from", facts_for=leaked)

    def test_a_direct_probe_that_printed_no_json_blocks_the_case(self):
        def broken(_plan, _vantage):
            return _Completed(None, stdout="", returncode=0)

        self.reject("did not print JSON", facts_for=broken)

    def test_the_case_is_blocked_when_no_install_has_run(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        product = multi_node.MultiNodeProduct(_StubPodman(Path(root.name)))
        with self.assertRaises(CaseBlocked) as caught:
            multi_node.case_egress(product)
        self.assertIn(multi_node.INSTALL_CASE_ID, str(caught.exception))


class TestDataPlaneSourceEvidence(unittest.TestCase):
    """The tuple's own body is what supplies the egress attribution case's facts."""

    def product(self):
        product = _MatrixProduct()
        self.addCleanup(product.cleanup)
        return product

    def test_a_transfer_records_the_address_the_endpoint_observed(self):
        product = self.product()
        inbound, client = matrix.tuples(product.matrix, vision=False)[0]
        case_id = matrix.case_id(
            product.matrix, multi_node.matrix_data.MULTI_NODE, str(inbound["id"]), client,
            node="worker",
        )
        with unittest.mock.patch.object(
            multi_node.aio, "_data_plane_case",
            return_value={"source_ip": product.topology.plan.data_worker_ip},
        ):
            evidence = multi_node.data_plane_case(product, inbound, client, "worker")
        self.assertEqual(evidence["source_ip"], product.topology.plan.data_worker_ip)
        self.assertEqual(product.data_plane_sources[case_id],
                         product.topology.plan.data_worker_ip)

    def test_a_failed_tuple_records_no_attribution(self):
        product = self.product()
        inbound, client = matrix.tuples(product.matrix, vision=False)[0]
        with unittest.mock.patch.object(
            multi_node.aio, "_data_plane_case", side_effect=AssertionError("no delivery"),
        ):
            with self.assertRaises(AssertionError):
                multi_node.data_plane_case(product, inbound, client, "master")
        self.assertEqual(product.data_plane_sources, {})


class _SshCompleted:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class _SshTrustPodman:
    """A two-host stand-in for OpenSSH, the Worker's filesystem, and the remote script.

    It encodes the three rules the case depends on: a connection succeeds only
    when the pinned key equals the host's current key, the remote script deletes
    the planted snapshot, and each flag below can break exactly one of them so
    the case has to refuse it.
    """

    DECOY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDecoyDecoyDecoyDecoyDecoyDecoy"
    KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOriginalOriginalOriginalOriginal"
    ROTATED = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRotatedRotatedRotatedRotatedRotated"

    def __init__(
        self, *, rotate=True, wrong_pin_opens=False, stale_pin_opens=False,
        leaks_command=False, refusal="Host key verification failed.",
        delete_on_success=True,
    ):
        self.worker_ip = ""
        self.worker_key = self.KEY
        self.original_key = self.KEY
        self.rotated = False
        self.pins = {}
        self.sentinel = False
        self.rotate = rotate
        self.wrong_pin_opens = wrong_pin_opens
        self.stale_pin_opens = stale_pin_opens
        self.leaks_command = leaks_command
        self.refusal = refusal
        self.delete_on_success = delete_on_success

    # ------------------------------------------------------------ podman API
    def exec(self, name, argv, check=True, input_text=None, timeout=None):
        if name == "master" and argv[:2] == ["bash", "-c"] and "cat > " in argv[2]:
            self.pins[argv[2].split("cat > ", 1)[1]] = input_text or ""
            return _SshCompleted(0)
        if name == "worker" and argv[:2] == ["test", "-f"]:
            return _SshCompleted(0 if self.sentinel else 1)
        if name == "worker" and argv[:1] == ["cat"]:
            return _SshCompleted(0, self.worker_key + "\n")
        raise AssertionError(f"unexpected exec on {name}: {argv}")

    def exec_bash(self, name, script, check=True, input_text=None, timeout=None):
        if name == "worker" and "install -d" in script:
            self.sentinel = True
            return _SshCompleted(0)
        if name == "master" and "mn-sshkey-decoy.pub" in script:
            return _SshCompleted(0, self.DECOY + "\n")
        if name == "worker" and "ssh-keygen -A" in script:
            if self.rotate:
                self.worker_key = self.ROTATED
                self.rotated = True
            return _SshCompleted(0)
        if name == "master" and "remote_finalize" in script:
            return self._remote_finalize(script)
        raise AssertionError(f"unexpected bash script on {name}: {script[:200]!r}")

    # ------------------------------------------------------------- the rules
    def _remote_finalize(self, script):
        path = script.split("SSH_KNOWN_HOSTS=", 1)[1].split()[0].strip("'\"")
        if path in self.pins:
            pinned = self.pins[path]
        elif path == "/root/.ssh/known_hosts":
            # The harness pinned the Worker's original key before node add.
            pinned = f"{self.worker_ip} {self.original_key}\n"
        else:
            pinned = ""
        fields = pinned.split()
        # A known_hosts line is "<host> <type> <blob>", so the blob is third.
        key = fields[2] if len(fields) > 2 else ""
        accepted = key and key == self.worker_key.split()[1]
        if not accepted and path.endswith("wrong-key") and self.wrong_pin_opens:
            accepted = True
        if not accepted and self.rotated and self.stale_pin_opens and key == self.original_key.split()[1]:
            accepted = True
        if not accepted:
            if self.leaks_command:
                self.sentinel = False
                return _SshCompleted(
                    255, "Worker ACME recovery snapshot finalized.\n", self.refusal + "\n",
                )
            return _SshCompleted(255, "", self.refusal + "\n")
        if self.delete_on_success:
            self.sentinel = False
        return _SshCompleted(0, "Worker ACME recovery snapshot finalized.\n")


class _SshKeyProduct:
    """The case's product surface, with the real remote-finalize command builder."""

    def __init__(self, podman):
        self.podman = podman
        self.host = type("Host", (), {
            "plan": topology.allocate_plan([]),
            "target_name": "master",
            "worker_name": "worker",
        })()
        podman.worker_ip = self.host.plan.worker_ip

    def require_installed(self):
        return self.host

    def remote_finalize(self, known_hosts, transaction, timeout=0):
        return multi_node.MultiNodeProduct.remote_finalize(
            self, known_hosts, transaction, timeout,
        )


class TestSshHostKeyCase(unittest.TestCase):
    """MN-SSHKEY: the pin gates the command, and a rotation needs a new pin."""

    def _run(self, **flags):
        product = _SshKeyProduct(_SshTrustPodman(**flags))
        return multi_node.case_ssh_host_key(product), product

    def test_the_pinned_key_gates_every_operation_and_a_rotation_is_adopted(self):
        evidence, product = self._run()
        self.assertIs(evidence["wrong_key_refused"], True)
        self.assertIs(evidence["wrong_key_executed_remotely"], False)
        self.assertIs(evidence["old_key_rejected"], True)
        self.assertIs(evidence["old_key_executed_remotely"], False)
        self.assertIs(evidence["new_key_accepted"], True)
        self.assertIs(evidence["new_key_executed_remotely"], True)
        self.assertNotEqual(evidence["worker_host_key_before"],
                            evidence["worker_host_key_after"])
        self.assertIs(product.podman.sentinel, False)
        for path in ("/root/.ssh/known_hosts", "/root/.ssh/known_hosts-wrong-key"):
            self.assertTrue(product.podman.pins[path].startswith(evidence["worker_ip"]))

    def test_a_wrong_pin_that_still_connects_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self._run(wrong_pin_opens=True)
        self.assertIn("a different key was pinned", str(caught.exception))

    def test_a_refusal_that_still_runs_the_script_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self._run(leaks_command=True)
        self.assertIn("ran although the pinned host key was not the Worker's",
                      str(caught.exception))

    def test_a_refusal_without_the_ssh_verification_message_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self._run(refusal="Permission denied (publickey).")
        self.assertIn("without OpenSSH naming the verification failure",
                      str(caught.exception))

    def test_a_rotation_that_changes_nothing_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self._run(rotate=False)
        self.assertIn("did not change", str(caught.exception))

    def test_a_stale_pin_accepted_after_rotation_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self._run(stale_pin_opens=True)
        self.assertIn("stale pin was accepted", str(caught.exception))

    def test_a_re_pinned_key_that_never_reaches_the_worker_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self._run(delete_on_success=False)
        self.assertIn("still on the Worker", str(caught.exception))

    def test_the_suite_runs_the_trust_case_before_the_provisioning_path(self):
        ids = [case.id for case in multi_node.cases(_StubPodman(Path(tempfile.mkdtemp())))]
        self.assertLess(ids.index(multi_node.SSH_KEY_CASE_ID),
                        ids.index(multi_node.NODE_ADD_CASE_ID))


class TestMultiNodeSuite(unittest.TestCase):
    """The declared suite is what the runner executes, and its ids are stable."""

    def setUp(self):
        import tempfile

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.podman = _StubPodman(Path(self.tmp.name))

    def test_the_suite_starts_with_the_install_and_then_provisions_the_worker(self):
        suite = multi_node.cases(self.podman)
        self.assertIsInstance(suite[0], Case)
        self.assertEqual(
            [case.id for case in suite][:4],
            [multi_node.INSTALL_CASE_ID, multi_node.SSH_KEY_CASE_ID,
             multi_node.NODE_ADD_CASE_ID, multi_node.MASTER_ADDRESS_CASE_ID],
        )
        self.assertEqual({case.topology for case in suite}, {"multi-node"})

    def test_every_case_declares_a_positive_timeout(self):
        for case in multi_node.cases(self.podman):
            self.assertGreater(case.timeout_seconds, 0, case.id)

    def test_the_suite_is_built_from_the_case_ids_the_catalog_knows(self):
        from tools.podman_e2e import catalog

        known = {entry["id"] for entry in catalog.build_catalog()["cases"]}
        for case in multi_node.cases(self.podman):
            self.assertIn(case.id, known, f"{case.id} is not in the shared catalog")

    def test_the_mtls_cases_follow_the_verifier_then_the_negative_controls(self):
        ids = [case.id for case in multi_node.cases(self.podman)]
        self.assertEqual(ids[4:12], [f"MTLS-0{number}" for number in range(1, 9)])

    def test_the_management_denial_pair_follows_the_control_plane_proof(self):
        # 5.8: an untrusted vantage and the allowed one are measured after the
        # Master's mTLS path is proven, so a refusal can be told from an outage.
        ids = [case.id for case in multi_node.cases(self.podman)]
        self.assertEqual(ids[12:14], ["FW-01", "FW-02"])

    def test_the_master_access_case_follows_the_denial_pair(self):
        # 6.6: FW-03 asks the same question of the Master's own rules that the
        # pair above asked of the Worker's, so it reads them while the cluster
        # is healthy and before the cases that only observe the Panel.
        ids = [case.id for case in multi_node.cases(self.podman)]
        self.assertEqual(ids[14], multi_node.MASTER_ACCESS_CASE_ID)
        self.assertLess(ids.index(multi_node.MASTER_ACCESS_CASE_ID), ids.index("CLUS-01"))
        suite = {case.id: case for case in multi_node.cases(self.podman)}
        self.assertEqual(suite[multi_node.MASTER_ACCESS_CASE_ID].timeout_seconds,
                         multi_node.FIREWALL_TIMEOUT_SECONDS)
        self.assertEqual(suite[multi_node.MASTER_ACCESS_CASE_ID].topology, "multi-node")

    def test_the_ipv6_case_follows_the_firewall_pair(self):
        # 6.7: FW-04 re-reads the same decisions through the other address family
        # while both roles are healthy, so a later change to either install cannot
        # be read as an IPv6 effect.
        ids = [case.id for case in multi_node.cases(self.podman)]
        self.assertEqual(ids[15], multi_node.IPV6_CASE_ID)
        self.assertLess(ids.index(multi_node.MASTER_ACCESS_CASE_ID),
                        ids.index(multi_node.IPV6_CASE_ID))
        self.assertLess(ids.index(multi_node.IPV6_CASE_ID), ids.index("CLUS-01"))
        suite = {case.id: case for case in multi_node.cases(self.podman)}
        self.assertEqual(suite[multi_node.IPV6_CASE_ID].timeout_seconds,
                         multi_node.IPV6_TIMEOUT_SECONDS)
        self.assertEqual(suite[multi_node.IPV6_CASE_ID].topology, "multi-node")

    def test_the_cluster_audit_follows_the_control_plane_proof(self):
        ids = [case.id for case in multi_node.cases(self.podman)]
        self.assertEqual(ids[16:19], ["CLUS-01", "CLUS-02", "CLUS-03"])

    def test_the_worker_state_audit_follows_the_cluster_audit(self):
        ids = [case.id for case in multi_node.cases(self.podman)]
        self.assertEqual(ids[19:21], ["WRK-05", "WRK-06"])

    def test_the_vision_independence_case_follows_the_worker_config(self):
        # 5.10: the per-node Vision proof reads the config WRK-06 has just
        # compared, so it runs once that assignment is established and before any
        # data plane traffic.
        ids = [case.id for case in multi_node.cases(self.podman)]
        self.assertEqual(ids[19:22], ["WRK-05", "WRK-06", multi_node.VISION_CASE_ID])

    def test_the_data_plane_cases_follow_the_worker_audit(self):
        # 5.7: a payload has to traverse the Worker too, so the matrix tuples of
        # both nodes run once the Worker's own config is applied.
        ids = [case.id for case in multi_node.cases(self.podman)]
        self.assertEqual(ids[22], "MN-DP-master-REALITY-xray")
        self.assertEqual(ids[29], "MN-DP-master-TROJAN-GRPC-mihomo")
        self.assertEqual(ids[30], "MN-DP-worker-REALITY-xray")
        self.assertEqual(ids[37], "MN-DP-worker-TROJAN-GRPC-mihomo")

    def test_every_node_contributes_its_own_matrix_tuples(self):
        data = matrix.load()
        ids = {case.id for case in multi_node.cases(self.podman)}
        expected = {
            matrix.case_id(data, "multi-node", str(inbound["id"]), client, node=node)
            for node in (matrix.load()["topologies"]["multi-node"]["nodes"])
            for inbound, client in matrix.tuples(data, vision=False)
        }
        self.assertEqual(len(expected), 16)
        self.assertTrue(expected <= ids, f"missing: {sorted(expected - ids)}")

    def test_the_data_plane_count_is_the_matrix_positive_count(self):
        for vision, worker_vision, count in (
            (False, False, 16), (True, False, 18), (False, True, 18), (True, True, 20),
        ):
            suite = multi_node.cases(self.podman, vision=vision, worker_vision=worker_vision)
            data_plane = [case.id for case in suite if case.id.startswith("MN-DP-")]
            self.assertEqual(len(data_plane), count, (vision, worker_vision))
            self.assertEqual(len(set(data_plane)), count, "no tuple may be counted twice")

    def test_the_vision_tuples_are_only_on_the_node_that_was_configured(self):
        master_only = [case.id for case in multi_node.cases(self.podman, vision=True)]
        self.assertIn("MN-DP-master-VISION-xray", master_only)
        self.assertNotIn("MN-DP-worker-VISION-xray", master_only)
        worker_only = [case.id for case in multi_node.cases(self.podman, worker_vision=True)]
        self.assertIn("MN-DP-worker-VISION-xray", worker_only)
        self.assertNotIn("MN-DP-master-VISION-xray", worker_only)
        self.assertEqual(
            len([case_id for case_id in worker_only if case_id.startswith("MN-DP-")]), 18,
        )

    def test_the_suite_declares_exactly_the_data_plane_cases_it_runs(self):
        suite = multi_node.cases(self.podman)
        product = multi_node.MultiNodeProduct(self.podman)
        declared = {case_id for case_id, _inbound, _client, _node in
                    multi_node.data_plane_cases(product)}
        self.assertEqual(
            declared,
            {case.id for case in suite if case.id.startswith("MN-DP-")},
        )

    def test_the_declared_cases_live_in_one_registry_on_the_master(self):
        product = multi_node.MultiNodeProduct(self.podman)
        product.declare_data_plane(["MN-DP-master-REALITY-xray"])
        self.assertEqual(product.declared_data_plane, ["MN-DP-master-REALITY-xray"])
        self.assertEqual(product.master.declared_data_plane,
                         ["MN-DP-master-REALITY-xray"])
        product.record_data_plane("MN-DP-master-REALITY-xray", "PASS")
        self.assertEqual(product.data_plane_results,
                         {"MN-DP-master-REALITY-xray": "PASS"})

    def test_the_count_case_closes_the_matrix_before_the_subscriptions(self):
        # 5.11: the count case reads the verdicts the tuples recorded, so it runs
        # after every one of them and before the cases that only read the Panel.
        # 5.12: attribution reads the same run and the endpoint, so it follows the
        # count and still precedes revocation, which would revoke a client.
        ids = [case.id for case in multi_node.cases(self.podman)]
        self.assertEqual(ids[37], "MN-DP-worker-TROJAN-GRPC-mihomo")
        self.assertEqual(ids[38:42], [multi_node.MATRIX_CASE_ID, multi_node.EGRESS_CASE_ID,
                                      "SUB-SERVED", "SUB-B64"])
        suite = {case.id: case for case in multi_node.cases(self.podman)}
        self.assertEqual(suite[multi_node.MATRIX_CASE_ID].timeout_seconds,
                         multi_node.MATRIX_TIMEOUT_SECONDS)
        self.assertEqual(suite[multi_node.EGRESS_CASE_ID].timeout_seconds,
                         multi_node.EGRESS_TIMEOUT_SECONDS)

    def test_the_lifecycle_cases_run_last_because_they_fault_the_worker(self):
        # 5.9: revocation and the Worker's own stop/start/restart change the
        # cluster under the suite, so nothing that observes a healthy cluster may
        # run after them.
        ids = [case.id for case in multi_node.cases(self.podman)]
        self.assertEqual(
            ids[-3:],
            [multi_node.REVOCATION_CASE_ID, multi_node.OUTAGE_CASE_ID,
             multi_node.RESTART_CASE_ID],
        )

    def test_the_nginx_configuration_case_precedes_the_lifecycle_cases(self):
        # 6.1: both roles' trees are validated and reloaded while the cluster is
        # healthy, so a later revocation cannot be read as a reload effect.
        ids = [case.id for case in multi_node.cases(self.podman)]
        self.assertEqual(ids[42], multi_node.NGINX_CONFIG_CASE_ID)
        self.assertLess(ids.index(multi_node.NGINX_CONFIG_CASE_ID),
                        ids.index(multi_node.REVOCATION_CASE_ID))
        self.assertLess(ids.index("SUB-B64"), ids.index(multi_node.NGINX_CONFIG_CASE_ID))
        suite = {case.id: case for case in multi_node.cases(self.podman)}
        self.assertEqual(suite[multi_node.NGINX_CONFIG_CASE_ID].timeout_seconds,
                         multi_node.NGX_CONFIG_CASE_TIMEOUT_SECONDS)

    def test_the_tls_surface_case_precedes_the_lifecycle_cases(self):
        # 6.2: both roles' certificates are read from a healthy cluster, so a
        # later Worker shutdown cannot be blamed for what the client saw here.
        ids = [case.id for case in multi_node.cases(self.podman)]
        self.assertEqual(ids[43], aio.TLS_CASE_ID)
        self.assertEqual(ids[42], multi_node.NGINX_CONFIG_CASE_ID)
        self.assertLess(ids.index(aio.TLS_CASE_ID), ids.index(multi_node.REVOCATION_CASE_ID))
        suite = {case.id: case for case in multi_node.cases(self.podman)}
        self.assertEqual(suite[aio.TLS_CASE_ID].timeout_seconds,
                         multi_node.TLS_CASE_TIMEOUT_SECONDS)
        self.assertEqual(suite[aio.TLS_CASE_ID].topology, "multi-node")


class TestMtlsVerifierReport(unittest.TestCase):
    """MTLS-01/02: the verifier's own lines are the only evidence accepted."""

    VERIFIED = """\
Verifying mTLS 1.3 handshake with HKDF-derived SNI on 10.89.0.11:3002...
Derived HKDF SNI (rw-v1): 0f1e2d3c4b5a69788796a5b4c3d2e1f0.9a8b7.c0m
Payload cryptographic verification PASSED (CA signature, node EC keypair match, RSA JWT public key).
Initiating mutual TLS 1.3 handshake to https://10.89.0.11:3002 with SNI '0f1e...'
Handshake SUCCESS: TLSv1.3 negotiated.
Node response: HTTP/1.1 200 OK
mTLS 1.3 control plane verification PASSED.
"""

    def test_the_payload_proof_must_precede_the_socket_attempt(self):
        facts = mtls.parse_verifier_output(self.VERIFIED)
        self.assertTrue(facts["payload_crypto_pass"])
        self.assertTrue(facts["payload_verified_before_socket"])
        self.assertTrue(facts["handshake_pass"])

    def test_a_payload_proof_printed_after_the_handshake_is_not_an_ordered_proof(self):
        reordered = self.VERIFIED.replace(
            "Payload cryptographic verification PASSED", "DELAYED-MARKER",
        ).replace(
            "mTLS 1.3 control plane verification PASSED.",
            mtls.PAYLOAD_MARKER,
        )
        facts = mtls.parse_verifier_output(reordered)
        self.assertTrue(facts["payload_crypto_pass"])
        self.assertFalse(facts["payload_verified_before_socket"],
                         "the socket attempt preceded the payload proof")

    def test_a_missing_payload_proof_is_reported_as_missing(self):
        facts = mtls.parse_verifier_output(self.VERIFIED.replace(mtls.PAYLOAD_MARKER, ""))
        self.assertFalse(facts["payload_crypto_pass"])
        self.assertFalse(facts["payload_verified_before_socket"])

    def test_http_200_and_401_are_told_apart(self):
        self.assertEqual(mtls.parse_verifier_output(self.VERIFIED)["response"], "health")
        unauthenticated = self.VERIFIED.replace("HTTP/1.1 200 OK", "HTTP/1.1 401 Unauthorized")
        facts = mtls.parse_verifier_output(unauthenticated)
        self.assertEqual(facts["response"], "unauthenticated")
        self.assertEqual(facts["status_line"], "HTTP/1.1 401 Unauthorized")
        self.assertTrue(facts["handshake_pass"], "a 401 is still a completed handshake")

    def test_an_unrecognised_status_is_neither_health_nor_authentication(self):
        facts = mtls.parse_verifier_output(self.VERIFIED.replace("HTTP/1.1 200 OK", "HTTP/1.1 502 Bad Gateway"))
        self.assertEqual(facts["response"], "other")
        self.assertEqual(mtls.classify_response(""), "none")

    def test_the_derived_sni_is_never_recorded(self):
        self.assertEqual(mtls.sanitized_lines(self.VERIFIED.__str__()), [
            line for line in self.VERIFIED.splitlines() if not line.startswith(mtls.SNI_PREFIX)
        ])
        self.assertNotIn("0f1e2d3c4b5a69788796a5b4c3d2e1f0", mtls.safe_tail(
            type("Result", (), {"stdout": self.VERIFIED, "stderr": ""})(),
        ))

    def test_the_positive_check_is_the_operators_own_path(self):
        script = mtls.positive_script("10.89.0.11", 3002)
        self.assertIn('secret="$(extract_secret_key)"', script)
        self.assertIn('verify_node_mtls_health "$secret" 3002 10.89.0.11 full', script)
        self.assertNotIn("base64", script,
                         "the extractor output is already encoded and must not be re-encoded")


class TestMtlsNegativeReport(unittest.TestCase):
    """MTLS-04..08: each negative control is classified by who refused."""

    def test_the_report_is_the_last_json_line(self):
        stdout = 'warning: something\n{"untrusted_client": {"outcome": "TLS_REJECTED"}}\n'
        self.assertEqual(mtls.parse_negative_report(stdout),
                         {"untrusted_client": {"outcome": "TLS_REJECTED"}})

    def test_garbage_is_an_empty_report_rather_than_an_exception(self):
        self.assertEqual(mtls.parse_negative_report("Traceback (most recent call last):\n{"), {})
        self.assertEqual(mtls.parse_negative_report(""), {})

    def test_the_negative_script_targets_the_worker_and_keeps_the_payload_local(self):
        script = mtls.negative_script("10.89.0.11", 3002)
        self.assertIn('worker_ip = "10.89.0.11"', script)
        self.assertIn("port = 3002", script)
        self.assertIn("extract_secret_key", script,
                      "the Master's own extractor is the only accepted source")
        self.assertIn("SERVER_CERT_REJECTED", script,
                      "a server-trust failure must not be reported as a Worker rejection")


class _MtlsProduct:
    """A product stub: the verifier facts and the negative report, nothing else."""

    POSITIVE = {
        "returncode": 0,
        "payload_crypto_pass": True,
        "payload_verified_before_socket": True,
        "handshake_pass": True,
        "handshake_line": "Handshake SUCCESS: TLSv1.3 negotiated.",
        "status_line": "HTTP/1.1 200 OK",
        "response": "health",
        "tail": "",
    }
    REPORT = {
        "untrusted_client": {"outcome": "TLS_REJECTED", "error": "SSLError"},
        "absent_client": {"outcome": "TLS_REJECTED", "error": "SSLError"},
        "mismatched_crypto_failed": True,
        "mismatched_socket_calls": 0,
        "untrusted_ca": {"outcome": "SERVER_CERT_REJECTED",
                         "error": "SSLCertVerificationError"},
        "wrong_sni": {"outcome": "TLS_REJECTED", "error": "SSLError"},
    }

    def __init__(self, positive=None, report=None, connected=True, negative_exit=0):
        self.positive = dict(self.POSITIVE, **(positive or {}))
        self.facts = {
            "returncode": negative_exit,
            "report": dict(self.REPORT) if report is None else report,
            "tail": "",
        }
        self.connected = connected

    def require_worker(self):
        return None

    def mtls_positive(self):
        return self.positive

    def mtls_negatives(self):
        return self.facts

    def mtls_negative_report(self, case_id):
        return multi_node.MultiNodeProduct.mtls_negative_report(self, case_id)

    def mtls_negative_outcome(self, case_id, key):
        return multi_node.MultiNodeProduct.mtls_negative_outcome(self, case_id, key)

    def panel_surface(self, case_id):
        return {"surface": {
            "nodes": {"connected": {topology.WORKER_NODE_NAME: self.connected}},
            "unauthenticated_nodes_status": 401,
        }}


class TestMtlsCases(unittest.TestCase):
    """MTLS-01..08: every case fails closed on the outcome it must not accept."""

    def _run(self, case, product):
        return case(product)

    def test_the_verified_handshake_is_accepted(self):
        facts = self._run(multi_node.case_mtls_verifier, _MtlsProduct())
        self.assertTrue(facts["payload_verified_before_socket"])
        self.assertEqual(facts["node_response"], "HTTP/1.1 200 OK")

    def test_a_payload_proof_after_the_socket_is_refused(self):
        product = _MtlsProduct({"payload_verified_before_socket": False})
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_mtls_verifier, product)
        self.assertIn("after the socket attempt", str(caught.exception))

    def test_a_failed_verifier_is_refused_with_its_own_output(self):
        product = _MtlsProduct({"returncode": 1, "handshake_pass": False,
                                "tail": "Error: mTLS 1.3 handshake failed: timeout"})
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_mtls_verifier, product)
        self.assertIn("exited 1", str(caught.exception))
        self.assertIn("handshake failed", str(caught.exception))

    def test_http_200_sets_both_flags(self):
        facts = self._run(multi_node.case_mtls_http_classification, _MtlsProduct())
        self.assertTrue(facts["mtls_handshake_pass"])
        self.assertTrue(facts["worker_http_health_pass"])

    def test_http_401_is_a_handshake_without_health(self):
        product = _MtlsProduct({"response": "unauthenticated",
                                "status_line": "HTTP/1.1 401 Unauthorized"})
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_mtls_http_classification, product)
        message = str(caught.exception)
        self.assertIn("MTLS_HANDSHAKE_PASS", message)
        self.assertIn("WORKER_HTTP_HEALTH_PASS is not", message)

    def test_a_handshake_that_never_happened_says_nothing_about_http(self):
        product = _MtlsProduct({"handshake_pass": False})
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_mtls_http_classification, product)
        self.assertIn("never succeeded", str(caught.exception))

    def test_the_panel_registry_is_the_only_panel_authentication_proof(self):
        facts = self._run(multi_node.case_mtls_panel_auth, _MtlsProduct(connected=True))
        self.assertTrue(facts["panel_worker_auth_pass"])
        for state in (False, None):
            product = _MtlsProduct(connected=state)
            with self.assertRaises(AssertionError) as caught:
                self._run(multi_node.case_mtls_panel_auth, product)
            self.assertIn("cannot stand in", str(caught.exception))

    def test_an_untrusted_client_certificate_must_be_rejected_by_the_handshake(self):
        facts = self._run(multi_node.case_mtls_untrusted_client, _MtlsProduct())
        self.assertEqual(facts["untrusted_client"]["outcome"], "TLS_REJECTED")
        answered = _MtlsProduct(report=dict(
            _MtlsProduct.REPORT,
            untrusted_client={"outcome": "HTTP_RESPONSE", "status_line": "HTTP/1.1 200 OK"},
        ))
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_mtls_untrusted_client, answered)
        self.assertIn("HTTP_RESPONSE", str(caught.exception))

    def test_an_absent_client_certificate_must_be_rejected_by_the_handshake(self):
        facts = self._run(multi_node.case_mtls_absent_client, _MtlsProduct())
        self.assertEqual(facts["absent_client"]["outcome"], "TLS_REJECTED")
        silent = _MtlsProduct(report=dict(
            _MtlsProduct.REPORT, absent_client={"outcome": "NO_RESPONSE", "version": "TLSv1.3"},
        ))
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_mtls_absent_client, silent)
        self.assertIn("NO_RESPONSE", str(caught.exception))

    def test_a_mismatched_pair_must_fail_locally_without_a_socket(self):
        facts = self._run(multi_node.case_mtls_mismatched_pair, _MtlsProduct())
        self.assertEqual(facts["sockets_opened"], 0)
        remote = _MtlsProduct(report=dict(_MtlsProduct.REPORT, mismatched_socket_calls=1))
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_mtls_mismatched_pair, remote)
        self.assertIn("not local", str(caught.exception))
        accepted = _MtlsProduct(report=dict(_MtlsProduct.REPORT, mismatched_crypto_failed=False))
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_mtls_mismatched_pair, accepted)
        self.assertIn("does not match", str(caught.exception))

    def test_an_untrusted_ca_is_a_client_side_failure_not_a_worker_rejection(self):
        facts = self._run(multi_node.case_mtls_untrusted_ca, _MtlsProduct())
        self.assertEqual(facts["untrusted_ca"]["outcome"], "SERVER_CERT_REJECTED")
        misclassified = _MtlsProduct(report=dict(
            _MtlsProduct.REPORT, untrusted_ca={"outcome": "TLS_REJECTED", "error": "SSLError"},
        ))
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_mtls_untrusted_ca, misclassified)
        self.assertIn("client-side certificate verification failure", str(caught.exception))

    def test_a_wrong_sni_is_recorded_however_it_arrives(self):
        for outcome in ("TLS_REJECTED", "HTTP_RESPONSE"):
            report = dict(_MtlsProduct.REPORT, wrong_sni={"outcome": outcome})
            facts = self._run(multi_node.case_mtls_wrong_sni, _MtlsProduct(report=report))
            self.assertEqual(facts["wrong_sni"]["outcome"], outcome)
        unanswered = _MtlsProduct(report=dict(
            _MtlsProduct.REPORT, wrong_sni={"outcome": "NO_RESPONSE", "version": "TLSv1.3"},
        ))
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_mtls_wrong_sni, unanswered)
        self.assertIn("unanswered", str(caught.exception))

    def test_a_probe_that_produced_no_report_blocks_instead_of_inventing_failures(self):
        for case in (multi_node.case_mtls_untrusted_client,
                     multi_node.case_mtls_absent_client,
                     multi_node.case_mtls_mismatched_pair,
                     multi_node.case_mtls_untrusted_ca,
                     multi_node.case_mtls_wrong_sni):
            with self.assertRaises(CaseBlocked) as caught:
                case(_MtlsProduct(negative_exit=1, report={}))
            self.assertIn("produced no report", str(caught.exception))


class _RecordingPodman:
    """A Podman stand-in that records what the mTLS probes ask the Master to run."""

    def __init__(self):
        self.exec_bash_calls = []
        self.exec_calls = []

    def exec_bash(self, name, script, check=True, input_text=None, timeout=0):
        self.exec_bash_calls.append((name, script, input_text))
        return type("Result", (), {"returncode": 0, "stdout": TestMtlsVerifierReport.VERIFIED,
                                   "stderr": ""})()

    def exec(self, name, argv, check=True, input_text=None, timeout=0):
        self.exec_calls.append((name, list(argv), input_text))
        return type("Result", (), {"returncode": 0, "stderr": "",
                                   "stdout": '{"untrusted_client": {"outcome": "TLS_REJECTED"}}'})()


class TestMtlsProbeMemoization(unittest.TestCase):
    """The probes run once per run, on the Master, and never carry the payload."""

    def _product(self):
        import types

        podman = _RecordingPodman()
        product = multi_node.MultiNodeProduct.__new__(multi_node.MultiNodeProduct)
        product.podman = podman
        product.topology = types.SimpleNamespace(
            target_name="aio-test",
            plan=types.SimpleNamespace(worker_ip="10.89.0.11"),
        )
        product.node_add_outcome = types.SimpleNamespace(ok=True)
        product.mtls_positive_facts = None
        product.mtls_negative_facts = None
        product.master = types.SimpleNamespace(require_installed=lambda: None)
        return product, podman

    def test_the_positive_probe_runs_once_for_both_cases(self):
        product, podman = self._product()
        product.mtls_positive()
        product.mtls_positive()
        self.assertEqual(len(podman.exec_bash_calls), 1)
        name, script, input_text = podman.exec_bash_calls[0]
        self.assertEqual(name, "aio-test")
        self.assertIn("extract_secret_key", script)
        self.assertIn("10.89.0.11", script)
        self.assertIsNone(input_text, "the payload is extracted inside the Master")

    def test_the_negative_probe_runs_once_and_keeps_the_payload_out_of_argv(self):
        product, podman = self._product()
        product.mtls_negatives()
        product.mtls_negatives()
        self.assertEqual(len(podman.exec_calls), 1)
        name, argv, input_text = podman.exec_calls[0]
        self.assertEqual(name, "aio-test")
        self.assertEqual(argv[:2], ["python3", "-c"])
        self.assertIn("extract_secret_key", argv[2])
        self.assertIsNone(input_text)


def worker_record(name=None, connected=True, uuid="uuid-digest", inbounds=("in-1", "in-2"),
                  versions=None, status_message=""):
    """One Panel registry record, shaped like the cluster probe's own output."""
    return {
        "name": name or topology.WORKER_NODE_NAME,
        "address": topology.allocate_plan([]).worker_ip,
        "port": multi_node.NODE_PORT,
        "connected": connected,
        "uuid": uuid,
        "profile": "profile-digest",
        "inbounds": list(inbounds),
        "inbound_specs": [],
        "state": {"connecting": False, "disabled": False, "status_message": status_message},
        "versions": versions or {"node": "v1.2.3", "xray": "v26.11.9"},
    }


def delivered(source_ip):
    return {
        "delivered": True, "status": 200, "request_id_match": True, "body_match": True,
        "source_ip": source_ip, "reason": "",
    }


def refused():
    return {
        "delivered": False, "status": None,
        "reason": "ConnectionRefusedError: [Errno 111] Connection refused",
    }


class _LifecycleProduct(multi_node.MultiNodeProduct):
    """The real product with its probes and unit actions scripted.

    Only the network- and systemd-facing methods are replaced: the tuple
    selection, the Panel record reads and every assertion stay the product's own,
    so a test drives the same decision path the live run does and can script the
    states a real Worker takes seconds or minutes to reach.
    """

    def __init__(self, transfers=(), services=(), panel_connected=True, before=None,
                 main_pid="4242", healthy=None, peer_sets=None):
        self._root = tempfile.TemporaryDirectory()
        super().__init__(_StubPodman(Path(self._root.name)))
        self.topology = type("Host", (), {
            "plan": topology.allocate_plan([]),
            "worker_name": "worker-test",
            "target_name": "master-test",
        })()
        self.node_add_outcome = topology.InstallOutcome(0, "", "", 1.0, "node add")
        self.before_record = dict(before or worker_record())
        self.worker_template = dict(self.before_record)
        self.panel_connected = panel_connected
        self.main_pid = main_pid
        self.master_address = self.topology.plan.target_ip
        self.healthy = healthy or {"peers": [self.master_address], "node_service": "active"}
        # One entry per control-probe poll; the last entry repeats, so a test scripts
        # "down, then up" by giving two sets and a permanent state by giving one.
        self.peer_sets = [list(entry) for entry in (peer_sets or [[self.master_address]])]
        self.peer_calls = 0
        self._transfers = list(transfers)
        self._services = list(services)
        self.transfer_calls = []
        self.service_calls = []
        self.master.subscription_payloads = lambda case_id: {}

    def cleanup(self):
        self._root.cleanup()

    # ------------------------------------------------------------ scripted I/O
    def require_installed(self):
        return self.topology

    def require_worker(self):
        return self.topology

    def set_worker_connected(self, connected):
        self.panel_connected = connected

    def cluster_facts(self, case_id):
        worker = dict(self.worker_template)
        worker["connected"] = self.panel_connected
        master = dict(self.worker_template)
        master.update({"name": multi_node.LOCAL_NODE_NAME, "connected": True})
        return {"nodes": {"records": [worker, master]}}

    def wait_for_worker_report(self, case_id):
        return dict(self.before_record)

    def worker_main_pid(self, case_id):
        return self.main_pid

    def worker_control_facts(self, case_id, timeout=120):
        self.peer_calls += 1
        peers = self.peer_sets.pop(0) if len(self.peer_sets) > 1 else self.peer_sets[0]
        return {
            "peers": list(peers), "node_service": "active",
            "listeners": [str(multi_node.NODE_PORT)], "firewall": {},
        }

    def worker_address_facts(self, case_id):
        return dict(self.healthy)

    def node_transfer(self, case_id, node, inbound, client, expect_refusal=False):
        self.transfer_calls.append((case_id, node, inbound["id"], client, expect_refusal))
        if not self._transfers:
            raise AssertionError("the case made an unscripted transfer")
        return dict(self._transfers.pop(0))

    def worker_service(self, action, case_id):
        self.service_calls.append(action)
        if not self._services:
            raise AssertionError(f"the case ran an unscripted systemctl {action}")
        return dict(self._services.pop(0))


def stop_and_start(stop_state="inactive", start_state="active", start_returncode=0):
    return [
        {"action": "stop", "returncode": 0, "state": stop_state, "main_pid": "0", "detail": ""},
        {"action": "start", "returncode": start_returncode, "state": start_state,
         "main_pid": "5151" if start_state == "active" else "0", "detail": ""},
    ]


class TestWorkerOutageCase(unittest.TestCase):
    """MN-OUTAGE fails closed on every way the degradation could be misread."""

    def product(self, **kwargs):
        product = _LifecycleProduct(**kwargs)
        self.addCleanup(product.cleanup)
        return product

    def poll_once(self):
        return lambda predicate, *args, **kwargs: predicate()

    def transition(self, *actions):
        """Apply one scripted Panel state per poll, then evaluate the predicate."""
        pending = list(actions)

        def poll(predicate, *args, **kwargs):
            if pending:
                pending.pop(0)()
            return predicate()

        return poll

    def test_the_degradation_is_observed_and_the_same_subscription_recovers(self):
        product = self.product(
            transfers=[
                delivered(product_ip := topology.allocate_plan([]).data_worker_ip),
                refused(),
                delivered(topology.allocate_plan([]).data_target_ip),
                delivered(product_ip),
            ],
            services=stop_and_start(),
        )
        with unittest.mock.patch.object(
            multi_node, "wait_until",
            self.transition(lambda: product.set_worker_connected(False),
                            lambda: product.set_worker_connected(True)),
        ):
            evidence = multi_node.case_worker_outage(product)
        self.assertEqual([call[1] for call in product.transfer_calls],
                         ["worker", "worker", "master", "worker"])
        self.assertTrue(all(call[4] for call in product.transfer_calls),
                        "every fault-time transfer has to be refusal-tolerant")
        self.assertEqual(product.service_calls, ["stop", "start"])
        self.assertTrue(evidence["panel_worker_offline"])
        self.assertTrue(evidence["panel_master_connected"])
        self.assertIsNone(evidence["refused_status"])
        self.assertEqual(evidence["master_control_source_ip"],
                         topology.allocate_plan([]).data_target_ip)
        self.assertEqual(evidence["recovered_source_ip"],
                         topology.allocate_plan([]).data_worker_ip)

    def test_a_worker_that_keeps_delivering_after_stopping_fails_the_case(self):
        product = self.product(
            transfers=[delivered(topology.allocate_plan([]).data_worker_ip),
                       delivered(topology.allocate_plan([]).data_worker_ip)],
            services=stop_and_start(),
        )
        with unittest.mock.patch.object(
            multi_node, "wait_until",
            self.transition(lambda: product.set_worker_connected(False),
                            lambda: product.set_worker_connected(True)),
        ):
            with self.assertRaises(AssertionError) as caught:
                multi_node.case_worker_outage(product)
        self.assertIn("still carried a payload", str(caught.exception))

    def test_a_fault_the_master_cannot_survive_is_not_attributed_to_the_worker(self):
        product = self.product(
            transfers=[delivered(topology.allocate_plan([]).data_worker_ip),
                       refused(), refused()],
            services=stop_and_start(),
        )
        with unittest.mock.patch.object(
            multi_node, "wait_until",
            self.transition(lambda: product.set_worker_connected(False),
                            lambda: product.set_worker_connected(True)),
        ):
            with self.assertRaises(AssertionError) as caught:
                multi_node.case_worker_outage(product)
        self.assertIn("cannot be attributed to the Worker", str(caught.exception))

    def test_the_fault_is_removed_even_when_a_check_fails(self):
        product = self.product(
            transfers=[delivered(topology.allocate_plan([]).data_worker_ip),
                       delivered(topology.allocate_plan([]).data_worker_ip)],
            services=stop_and_start(),
        )
        with unittest.mock.patch.object(
            multi_node, "wait_until",
            self.transition(lambda: product.set_worker_connected(False),
                            lambda: product.set_worker_connected(True)),
        ):
            with self.assertRaises(AssertionError):
                multi_node.case_worker_outage(product)
        self.assertEqual(product.service_calls, ["stop", "start"],
                         "a failed case must still start the unit it stopped")

    def test_a_unit_that_does_not_come_back_fails_the_case(self):
        product = self.product(
            transfers=[delivered(topology.allocate_plan([]).data_worker_ip),
                       refused(),
                       delivered(topology.allocate_plan([]).data_target_ip)],
            services=stop_and_start(start_state="failed", start_returncode=1),
        )
        with unittest.mock.patch.object(
            multi_node, "wait_until",
            self.transition(lambda: product.set_worker_connected(False),
                            lambda: product.set_worker_connected(True)),
        ):
            with self.assertRaises(AssertionError) as caught:
                multi_node.case_worker_outage(product)
        self.assertIn("left the Worker at 'failed'", str(caught.exception))

    def panel_and_dead_data_plane(self, *actions):
        """Let the connection waits follow a scripted state, but never let the data plane return."""
        pending = list(actions)

        def poll(predicate, timeout_seconds, description, **kwargs):
            if "connection" in description:
                if pending:
                    pending.pop(0)()
                return predicate()
            return False

        return poll

    def test_a_worker_that_never_carries_the_subscription_again_fails_the_case(self):
        product = self.product(
            transfers=[delivered(topology.allocate_plan([]).data_worker_ip),
                       refused(),
                       delivered(topology.allocate_plan([]).data_target_ip)],
            services=stop_and_start(),
        )
        with unittest.mock.patch.object(
            multi_node, "wait_until",
            self.panel_and_dead_data_plane(
                lambda: product.set_worker_connected(False),
                lambda: product.set_worker_connected(True),
            ),
        ):
            with self.assertRaises(AssertionError) as caught:
                multi_node.case_worker_outage(product)
        self.assertIn("never carried the same subscription again", str(caught.exception))

    def test_a_panel_that_never_reports_the_worker_offline_fails_the_wait(self):
        product = self.product()
        with unittest.mock.patch.object(multi_node, "wait_until", lambda *args, **kwargs: False):
            with self.assertRaises(AssertionError) as caught:
                product.wait_for_worker_connection(multi_node.OUTAGE_CASE_ID, False, 1)
        self.assertIn("still reports", str(caught.exception))


class TestWorkerPeerWait(unittest.TestCase):
    """The control dial is waited for, never inferred from the Panel's flag."""

    def product(self, **kwargs):
        product = _LifecycleProduct(**kwargs)
        self.addCleanup(product.cleanup)
        return product

    def poll(self, attempts=8):
        def poll(predicate, timeout_seconds, description, **kwargs):
            for _ in range(attempts):
                if predicate():
                    return True
            return False

        return poll

    def test_the_dial_is_polled_until_the_masters_address_appears(self):
        master = topology.allocate_plan([]).target_ip
        product = self.product(peer_sets=[[], ["10.89.0.44"], [master]])
        with unittest.mock.patch.object(multi_node, "wait_until", self.poll()):
            facts = product.wait_for_worker_peer(multi_node.RESTART_CASE_ID, 30)
        self.assertEqual(product.peer_calls, 3, "a peer set without the Master is not the answer")
        self.assertEqual(facts["peers"], [master])
        self.assertIn("peer_wait_seconds", facts)

    def test_a_dial_that_never_returns_fails_with_the_peers_it_saw(self):
        product = self.product(peer_sets=[[]])
        with unittest.mock.patch.object(multi_node, "wait_until", self.poll()):
            with self.assertRaises(AssertionError) as caught:
                product.wait_for_worker_peer(multi_node.RESTART_CASE_ID, 30)
        message = str(caught.exception)
        self.assertIn("did not come back within 30s", message)
        self.assertIn("peers none", message)


class TestWorkerRestartCase(unittest.TestCase):
    """MN-RESTART proves a new process came up without a new registration."""

    def product(self, **kwargs):
        product = _LifecycleProduct(**kwargs)
        self.addCleanup(product.cleanup)
        return product

    def poll_once(self):
        return lambda predicate, *args, **kwargs: predicate()

    def restart(self, pid="5151", state="active", returncode=0):
        return {"action": "restart", "returncode": returncode, "state": state,
                "main_pid": pid, "detail": ""}

    def test_the_restart_keeps_the_node_and_the_subscription_transfers(self):
        plan = topology.allocate_plan([])
        product = self.product(
            transfers=[delivered(plan.data_worker_ip)],
            services=[self.restart()],
        )
        with unittest.mock.patch.object(multi_node, "wait_until", self.poll_once()):
            evidence = multi_node.case_worker_restart(product)
        self.assertEqual(product.service_calls, ["restart"])
        self.assertEqual(evidence["unit_after_restart"], "active")
        self.assertEqual(evidence["main_pid_before"], "4242")
        self.assertEqual(evidence["main_pid_after"], "5151")
        self.assertEqual(evidence["panel_node_endpoint"],
                         f"{plan.worker_ip}:{multi_node.NODE_PORT}")
        self.assertEqual(evidence["recovered_source_ip"], plan.data_worker_ip)

    def test_a_process_that_was_not_replaced_fails_the_case(self):
        product = self.product(services=[self.restart(pid="4242")])
        with unittest.mock.patch.object(multi_node, "wait_until", self.poll_once()):
            with self.assertRaises(AssertionError) as caught:
                multi_node.case_worker_restart(product)
        self.assertIn("kept main PID", str(caught.exception))

    def test_a_failed_restart_fails_the_case(self):
        product = self.product(services=[self.restart(state="failed", returncode=1)])
        with self.assertRaises(AssertionError) as caught:
            multi_node.case_worker_restart(product)
        self.assertIn("systemctl restart gowave-node.service", str(caught.exception))

    def test_a_unit_that_is_not_active_after_the_restart_fails_the_case(self):
        product = self.product(services=[self.restart(state="activating")])
        with self.assertRaises(AssertionError) as caught:
            multi_node.case_worker_restart(product)
        self.assertIn("right after the restart", str(caught.exception))

    def test_a_restart_that_re_registers_the_worker_fails_the_case(self):
        product = self.product(transfers=[], services=[self.restart()])
        product.worker_template["uuid"] = "another-uuid"
        with unittest.mock.patch.object(multi_node, "wait_until", self.poll_once()):
            with self.assertRaises(AssertionError) as caught:
                multi_node.case_worker_restart(product)
        self.assertIn("re-registered the Worker instead of restarting it",
                      str(caught.exception))

    def test_a_changed_inbound_assignment_fails_the_case(self):
        product = self.product(services=[self.restart()])
        product.worker_template["inbounds"] = ["in-1"]
        with unittest.mock.patch.object(multi_node, "wait_until", self.poll_once()):
            with self.assertRaises(AssertionError) as caught:
                multi_node.case_worker_restart(product)
        self.assertIn("now assigns the Worker", str(caught.exception))

    def test_a_rejected_config_after_the_restart_fails_the_case(self):
        product = self.product(services=[self.restart()])
        product.worker_template["state"] = {
            "connecting": False, "disabled": False, "status_message": "config rejected",
        }
        with unittest.mock.patch.object(multi_node, "wait_until", self.poll_once()):
            with self.assertRaises(AssertionError) as caught:
                multi_node.case_worker_restart(product)
        self.assertIn("node status message", str(caught.exception))

    def panel_and_dead_data_plane(self, *actions):
        """Let the connection waits follow a scripted state, but never let the data plane return."""
        pending = list(actions)

        def poll(predicate, timeout_seconds, description, **kwargs):
            if "connection" in description:
                if pending:
                    pending.pop(0)()
                return predicate()
            return False

        return poll

    def test_a_subscription_that_never_transfers_again_fails_the_case(self):
        product = self.product(
            transfers=[refused()], services=[self.restart()],
        )
        with unittest.mock.patch.object(
            multi_node, "wait_until", self.panel_and_dead_data_plane(),
        ):
            with self.assertRaises(AssertionError) as caught:
                multi_node.case_worker_restart(product)
        self.assertIn("never carried the subscription captured before the restart",
                      str(caught.exception))


class _ScriptedPodman:
    """A podman stub that answers the Worker's unit commands with a fixed script output."""

    def __init__(self, stdout, returncode=0, stderr=""):
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr
        self.scripts = []

    def exec_bash(self, name, script, check=True, input_text=None, timeout=0):
        self.scripts.append((name, script))
        return type("Result", (), {
            "returncode": self.returncode, "stdout": self.stdout, "stderr": self.stderr,
        })()


class TestWorkerUnitControl(unittest.TestCase):
    """The unit action is the operator's own and its exit code is never lost."""

    def product(self, stdout, returncode=0, stderr=""):
        product = multi_node.MultiNodeProduct.__new__(multi_node.MultiNodeProduct)
        product.podman = _ScriptedPodman(stdout, returncode, stderr)
        product.topology = type("Host", (), {
            "worker_name": "worker-test", "plan": topology.allocate_plan([]),
        })()
        product.node_add_outcome = topology.InstallOutcome(0, "", "", 1.0, "node add")
        product.master = type("Master", (), {"require_installed": lambda self: None})()
        return product, product.podman

    REPORT = (
        "==returncode\n0\n"
        "==active\ninactive\n"
        "==mainpid\n0\n"
    )

    def test_the_action_runs_against_the_workers_own_unit(self):
        product, podman = self.product(self.REPORT)
        facts = product.worker_service("stop", multi_node.OUTAGE_CASE_ID)
        name, script = podman.scripts[0]
        self.assertEqual(name, "worker-test")
        self.assertIn("systemctl stop gowave-node.service </dev/null", script)
        self.assertIn("rc=$?", script)
        self.assertEqual(facts["action"], "stop")
        self.assertEqual(facts["returncode"], 0)
        self.assertEqual(facts["state"], "inactive")
        self.assertEqual(facts["main_pid"], "0")

    def test_a_failed_action_reports_its_exit_code_and_output(self):
        product, _ = self.product(
            "==returncode\n1\n==active\nfailed\n==mainpid\n0\n",
            stderr="Job for gowave-node.service failed because the control process exited",
        )
        facts = product.worker_service("restart", multi_node.RESTART_CASE_ID)
        self.assertEqual(facts["returncode"], 1)
        self.assertEqual(facts["state"], "failed")
        self.assertIn("control process exited", facts["detail"])

    def test_an_output_without_a_return_code_is_not_a_success(self):
        product, _ = self.product("")
        facts = product.worker_service("start", multi_node.OUTAGE_CASE_ID)
        self.assertIsNone(facts["returncode"])
        self.assertEqual(facts["detail"], "")


class _NginxConfigProduct(multi_node.MultiNodeProduct):
    """The real product with both roles' host probes scripted, role by role."""

    def __init__(self, results):
        self._root = tempfile.TemporaryDirectory()
        super().__init__(_StubPodman(Path(self._root.name)))
        self.topology = type("Host", (), {
            "target_name": "master-test",
            "worker_name": "worker-test",
            "worker_domain": topology.WORKER_DOMAIN,
        })()
        self.node_add_outcome = topology.InstallOutcome(0, "", "", 1.0, "node add")
        self.master.host = type("Host", (), {"target_name": "master-test"})()
        self.master.outcome = topology.InstallOutcome(0, "", "", 1.0, "install")
        self.results = list(results)
        self.calls = []
        self.podman.exec_bash = self._exec_bash

    def _exec_bash(self, name, script, check=True, input_text=None, timeout=300):
        self.calls.append((name, script))
        stdout, returncode = self.results.pop(0)
        return subprocess.CompletedProcess(["bash", "-lc", script], returncode, stdout, "")

    def cleanup(self):
        self._root.cleanup()


class TestNginxConfigCase(unittest.TestCase):
    """NGX-05: both roles validate and reload their own generated NGINX tree."""

    def product(self, results):
        product = _NginxConfigProduct(results)
        self.addCleanup(product.cleanup)
        return product

    def phases(self, container_domain):
        return [
            (json.dumps(nginx_probe("before", domain=container_domain)), 0),
            (json.dumps(nginx_probe("break", test=1, tail=BROKEN_TAIL, present=True,
                                    domain=container_domain)), 0),
            (json.dumps(nginx_probe("restore", after_workers=("5100",),
                                    domain=container_domain)), 0),
        ]

    def test_the_case_runs_the_contract_on_the_master_and_on_the_worker(self):
        product = self.product(
            self.phases(topology.PANEL_DOMAIN) + self.phases(topology.WORKER_DOMAIN),
        )
        evidence = multi_node.case_nginx_config(product)
        self.assertEqual([call[0] for call in product.calls],
                         ["master-test"] * 3 + ["worker-test"] * 3)
        self.assertEqual(set(evidence), {"master", "worker"})
        self.assertEqual(evidence["master"]["primary_domain"], topology.PANEL_DOMAIN)
        self.assertEqual(evidence["worker"]["primary_domain"], topology.WORKER_DOMAIN)
        self.assertTrue(all(record["role"] for record in evidence.values()))

    def test_the_master_is_validated_before_the_worker_is_touched(self):
        product = self.product(
            self.phases(topology.PANEL_DOMAIN) + self.phases(topology.WORKER_DOMAIN),
        )
        multi_node.case_nginx_config(product)
        self.assertIn(topology.PANEL_DOMAIN, product.calls[0][1])
        self.assertIn(topology.WORKER_DOMAIN, product.calls[3][1])

    def test_a_worker_finding_names_the_worker_and_the_reason(self):
        broken_worker = nginx_probe("break", test=1, tail=BROKEN_TAIL, present=True,
                                    domain=topology.WORKER_DOMAIN)
        broken_worker["after_hook"]["worker_pids"] = ["4300"]
        product = self.product(
            self.phases(topology.PANEL_DOMAIN)
            + [(json.dumps(nginx_probe("before", domain=topology.WORKER_DOMAIN)), 0),
               (json.dumps(broken_worker), 0),
               (json.dumps(nginx_probe("restore", after_workers=("5100",),
                                       domain=topology.WORKER_DOMAIN)), 0)]
        )
        with self.assertRaises(AssertionError) as caught:
            multi_node.case_nginx_config(product)
        message = str(caught.exception)
        self.assertIn("the Worker", message)
        self.assertIn("reloaded NGINX with an invalid configuration", message)
        self.assertEqual(product.calls[-1][0], "worker-test",
                         "the Worker's own tree has to be restored")

    def test_a_case_without_a_provisioned_worker_is_blocked(self):
        product = self.product([])
        product.node_add_outcome = None
        with self.assertRaises(CaseBlocked) as caught:
            multi_node.case_nginx_config(product)
        self.assertIn(multi_node.NODE_ADD_CASE_ID, str(caught.exception))


class _TlsProduct(_NginxConfigProduct):
    """The real product with only the wiring TLS-01 reads left live."""


class TestTlsSurfaceCase(unittest.TestCase):
    """TLS-01: each role's own certificate is validated from the Control Machine."""

    def product(self):
        product = _TlsProduct([])
        self.addCleanup(product.cleanup)
        return product

    def contract(self, calls):
        def record(host, case_id, role, domain, expected_status, container=""):
            calls.append({
                "host": host, "case_id": case_id, "role": role, "domain": domain,
                "status": expected_status, "container": container,
            })
            return {"role": role, "domain": domain}
        return record

    def test_both_roles_are_validated_for_their_own_names(self):
        product = self.product()
        calls = []
        with unittest.mock.patch.object(aio, "tls_surface_contract", self.contract(calls)):
            evidence = multi_node.case_tls_surface(product)
        self.assertEqual([call["role"] for call in calls], ["the Master", "the Worker"])
        self.assertEqual([call["domain"] for call in calls],
                         [topology.PANEL_DOMAIN, topology.WORKER_DOMAIN])
        # The Master serves the Panel page; the Worker's own vhost answers 404,
        # which is what still proves which vhost terminated the connection.
        self.assertEqual([call["status"] for call in calls], [200, 404])
        self.assertEqual([call["container"] for call in calls], ["", "worker-test"])
        self.assertEqual(set(call["case_id"] for call in calls), {aio.TLS_CASE_ID})
        self.assertEqual(set(evidence), {"master", "worker"})

    def test_the_handshake_is_always_driven_from_the_control_machine(self):
        product = self.product()
        calls = []
        with unittest.mock.patch.object(aio, "tls_surface_contract", self.contract(calls)):
            multi_node.case_tls_surface(product)
        self.assertTrue(all(call["host"] is product.master for call in calls),
                        "no role may be probed from the host it runs on")

    def test_a_worker_finding_names_the_worker_and_the_reason(self):
        product = self.product()

        def refuse(host, case_id, role, domain, expected_status, container=""):
            if role == "the Worker":
                aio.require(case_id, False, f"{role}: the certificate names "
                            f"{domain!r} instead of {domain!r}")
            return {"role": role, "domain": domain}

        with unittest.mock.patch.object(aio, "tls_surface_contract", refuse):
            with self.assertRaises(AssertionError) as caught:
                multi_node.case_tls_surface(product)
        self.assertIn("the Worker", str(caught.exception))

    def test_a_case_without_a_provisioned_worker_is_blocked(self):
        product = self.product()
        product.node_add_outcome = None
        with self.assertRaises(CaseBlocked) as caught:
            multi_node.case_tls_surface(product)
        self.assertIn(multi_node.NODE_ADD_CASE_ID, str(caught.exception))


class TestMasterAccessCase(unittest.TestCase):
    """FW-03 is only a firewall verdict when the denials are attributable.

    The Master's rule set is read once here and the three origins report what
    they observed; every failure below is a way a green-looking case could in
    fact have proven nothing — a firewall that is off, a service that is down, a
    port nobody filtered, or a rule that never saw the packet.
    """

    PACKETS = {22: 5, 80: 3, 443: 9, 3002: 2, 7443: 0}

    def path(self, outcome, address="10.89.0.11", port=3002, **extra):
        observed = {
            "address": address,
            "port": port,
            "outcome": outcome,
            "elapsed_ms": 12,
            "banner": None,
            "detail": "",
        }
        observed.update(extra)
        return observed

    def rule_set(self, packets=None, policy_packets=7):
        counts = dict(self.PACKETS)
        counts.update(packets or {})

        def allow(port):
            return [{"target": "ACCEPT", "source": "",
                     "line": f"-A ufw-user-input -p tcp -m tcp --dport {port} -j ACCEPT"}]

        return {
            "active": True,
            "default_incoming": "deny",
            "input_policy": "DROP",
            "input_policy_packets": policy_packets,
            "input_policy_bytes": 420,
            "ports": list(multi_node.FIREWALL_PORTS),
            "allows": {22: allow(22), 80: allow(80), 443: allow(443), 3002: [], 7443: []},
            "blocks": {
                22: [], 80: [], 443: [],
                3002: [{"target": "DROP", "source": "",
                        "line": "-A ufw-user-input -p tcp -m tcp --dport 3002 -j DROP"}],
                7443: [],
            },
            "counters": {
                port: [{"packets": counts[port], "bytes": None,
                        "target": "ACCEPT", "source": ""}]
                for port in multi_node.FIREWALL_PORTS
            },
            # The local node is bound on loopback only, the panel API too; the
            # published ports answer on every address.
            "listeners": {
                22: ["0.0.0.0"], 80: ["0.0.0.0"], 443: ["0.0.0.0"],
                3002: ["127.0.0.1"], 7443: ["127.0.0.1"],
            },
            "ufw": ["Status: active"],
        }

    def facts(self):
        # The counters moved for every rule the case dialled, and the INPUT
        # policy dropped the silent panel API probe.
        after_packets = {
            port: count + 2 for port, count in self.PACKETS.items() if port != 7443
        }
        return {
            "before": self.rule_set(),
            "after": self.rule_set(packets=after_packets, policy_packets=9),
            "origins": {
                multi_node.ORIGIN_CONTROL_MACHINE: {
                    "operator-ssh": self.path("CONNECTED", port=22,
                                              banner="SSH-2.0-OpenSSH_9.6"),
                    "node": self.path("REFUSED"),
                    "panel-api": self.path("TIMEOUT", port=7443),
                },
                multi_node.ORIGIN_PUBLISHED: {
                    "https": self.path("CONNECTED", port=443, address="203.0.114.11"),
                    "node": self.path("TIMEOUT", address="203.0.114.11"),
                },
                multi_node.ORIGIN_LOCAL: {
                    "https": self.path("CONNECTED", port=443, address="127.0.0.1"),
                    "node": self.path("CONNECTED", address="127.0.0.1"),
                    "panel-api": self.path("CONNECTED", port=7443, address="127.0.0.1"),
                },
            },
            "https": {"returncode": 0, "probe": {
                "status": 200, "peer": {"tls_version": "TLSv1.3"},
            }},
            "http": {"returncode": 0, "probe": {
                "status": 301, "headers": {"location": f"https://{topology.COVER_APEX}/"},
            }},
            "cover": topology.COVER_APEX,
            "addresses": {
                multi_node.ORIGIN_CONTROL_MACHINE: "10.89.0.11",
                multi_node.ORIGIN_PUBLISHED: "203.0.114.11",
                multi_node.ORIGIN_LOCAL: "127.0.0.1",
            },
        }

    def contract(self, facts=None):
        return multi_node.master_access_contract(facts or self.facts(), "FW-03")

    def test_the_four_origins_and_their_counters_are_evidence(self):
        evidence = self.contract()
        self.assertEqual(sorted(evidence["origins"]), sorted([
            multi_node.ORIGIN_CONTROL_MACHINE, multi_node.ORIGIN_PUBLISHED,
            multi_node.ORIGIN_LOCAL,
        ]))
        self.assertEqual(evidence["input_policy"], "DROP")
        self.assertEqual(evidence["default_incoming"], "deny")
        self.assertEqual(evidence["packets_moved"], {"22": 2, "80": 2, "443": 2, "3002": 2})
        self.assertEqual(evidence["input_policy_packets_moved"], 2)
        self.assertEqual(evidence["https_tls_version"], "TLSv1.3")
        self.assertTrue(evidence["http_location"].startswith("https://"))
        self.assertEqual(
            evidence["origins"][multi_node.ORIGIN_LOCAL]["node"]["outcome"], "CONNECTED",
        )

    def test_an_inactive_firewall_is_not_a_pass(self):
        facts = self.facts()
        facts["before"]["active"] = False
        with self.assertRaises(AssertionError) as caught:
            self.contract(facts)
        self.assertIn("UFW is not active", str(caught.exception))

    def test_an_answered_panel_api_port_publishes_the_management_interface(self):
        facts = self.facts()
        facts["origins"][multi_node.ORIGIN_CONTROL_MACHINE]["panel-api"] = self.path(
            "CONNECTED", port=7443,
        )
        with self.assertRaises(AssertionError) as caught:
            self.contract(facts)
        self.assertIn("panel API", str(caught.exception))

    def test_a_reachable_node_port_from_the_published_address_is_a_finding(self):
        facts = self.facts()
        facts["origins"][multi_node.ORIGIN_PUBLISHED]["node"] = self.path(
            "CONNECTED", address="203.0.114.11",
        )
        with self.assertRaises(AssertionError) as caught:
            self.contract(facts)
        self.assertIn("widened the rule set", str(caught.exception))

    def test_a_rule_that_counted_nothing_proves_the_attempts_missed_it(self):
        facts = self.facts()
        facts["after"]["counters"][3002] = [{"packets": 2, "bytes": None,
                                             "target": "DROP", "source": ""}]
        with self.assertRaises(AssertionError) as caught:
            self.contract(facts)
        self.assertIn("counted no packet", str(caught.exception))

    def test_a_dead_loopback_service_invalidates_every_refusal(self):
        facts = self.facts()
        facts["origins"][multi_node.ORIGIN_LOCAL]["panel-api"] = self.path(
            "REFUSED", port=7443, address="127.0.0.1",
        )
        with self.assertRaises(AssertionError) as caught:
            self.contract(facts)
        self.assertIn("service is down", str(caught.exception))

    def test_a_wildcard_panel_listener_is_not_loopback_only(self):
        facts = self.facts()
        facts["before"]["listeners"][7443] = ["0.0.0.0"]
        with self.assertRaises(AssertionError) as caught:
            self.contract(facts)
        self.assertIn("not loopback only", str(caught.exception))

    def test_an_unblocked_node_port_is_a_decision_the_install_never_made(self):
        facts = self.facts()
        facts["before"]["blocks"][3002] = []
        with self.assertRaises(AssertionError) as caught:
            self.contract(facts)
        self.assertIn("carves out no block rule", str(caught.exception))

    def test_a_missing_attempt_names_what_the_probe_did_report(self):
        facts = self.facts()
        del facts["origins"][multi_node.ORIGIN_CONTROL_MACHINE]["panel-api"]
        with self.assertRaises(AssertionError) as caught:
            self.contract(facts)
        message = str(caught.exception)
        self.assertIn("reported nothing for 'panel-api'", message)
        self.assertIn("'operator-ssh'", message)


class TestIpv6PolicyCase(unittest.TestCase):
    """FW-04 only means something if both branches are forced, not inherited.

    A run whose host happens to have no IPv6 exercises the disabled branch twice
    and still reads green, so every failure below is a way that could happen: an
    enabled host whose install ignored the kernel, a v6 chain that mirrors
    nothing, an internal port published on the second stack, or an IPv4-only host
    that was in fact reachable over IPv6.
    """

    PORTS = multi_node.FIREWALL_PORTS

    def rules(self, chain, allows=(), blocks=(), scoped=None):
        """A rule dump in the shape the parser produces, with the given verdicts."""
        allow_map = {port: [] for port in self.PORTS}
        block_map = {port: [] for port in self.PORTS}
        for port in allows:
            allow_map[port] = [{"target": "ACCEPT", "source": "",
                                "line": f"-A {chain} -p tcp -m tcp --dport {port} -j ACCEPT"}]
        for port, source in (scoped or {}).items():
            allow_map[port] = [{"target": "ACCEPT", "source": source,
                                "line": f"-A {chain} -s {source} -p tcp -m tcp --dport {port} -j ACCEPT"}]
        for port in blocks:
            block_map[port] = [{"target": "DROP", "source": "",
                                "line": f"-A {chain} -p tcp -m tcp --dport {port} -j DROP"}]
        return {"allows": allow_map, "blocks": block_map}

    def master(self):
        """The dual-stack role: both families carry the same decisions."""
        v6 = self.rules("ufw6-user-input", allows=(22, 80, 443), blocks=(3002,))
        v4 = self.rules("ufw-user-input", allows=(22, 80, 443), blocks=(3002,))
        return {
            "active": True,
            "default_incoming": "deny",
            "input_policy": "DROP",
            "allows": v4["allows"],
            "blocks": v4["blocks"],
            "counters": {port: [] for port in self.PORTS},
            # A wildcard v6 socket is what `ss` reports for a `listen [::]`.
            "listeners": {22: ["0.0.0.0", "[::]"], 80: ["0.0.0.0", "[::]"],
                          443: ["0.0.0.0", "[::]"],
                          3002: ["127.0.0.1"], 7443: ["127.0.0.1"]},
            "ipv6": {
                "declared": "yes",
                "kernel_addresses": ["fd00000000000000000000000000000a"],
                "kernel_disabled": False,
                "active": True,
                "allows": v6["allows"],
                "blocks": v6["blocks"],
                "counters": {port: [] for port in self.PORTS},
                "listens": {"[::]:443": ["stream.conf"], "[::]:80": ["panel.conf"]},
                "rules_returncode": 0,
                "chain_returncode": 0,
                "error": "",
            },
        }

    def worker(self):
        """The IPv4-only role: no address, no v6 chain, unchanged v4 rules."""
        v6 = self.rules("ufw6-user-input")
        v4 = self.rules("ufw-user-input", allows=(22, 80, 443), scoped={3002: "10.89.0.10"})
        return {
            "active": True,
            "default_incoming": "deny",
            "input_policy": "DROP",
            "allows": v4["allows"],
            "blocks": v4["blocks"],
            "counters": {port: [] for port in self.PORTS},
            "listeners": {22: ["0.0.0.0"], 80: ["0.0.0.0"], 443: ["0.0.0.0"],
                          3002: ["0.0.0.0"], 7443: []},
            "ipv6": {
                "declared": "no",
                "kernel_addresses": [],
                "kernel_disabled": True,
                "active": False,
                "allows": v6["allows"],
                "blocks": v6["blocks"],
                "counters": {port: [] for port in self.PORTS},
                "listens": {},
                "rules_returncode": 0,
                "chain_returncode": 1,
                "error": "No chain/target/match by that name.",
            },
        }

    def path(self, outcome, address=None, port=443, **extra):
        observed = {
            "address": address or topology.IPV6_HOST_ADDRESS,
            "port": port,
            "outcome": outcome,
            "elapsed_ms": 4,
            "detail": "",
        }
        observed.update(extra)
        return observed

    def facts(self):
        return {
            "master": self.master(),
            "worker": self.worker(),
            "address": topology.IPV6_HOST_ADDRESS,
            "master_paths": {
                "https": self.path("CONNECTED", port=443),
                "http": self.path("CONNECTED", port=80),
                "node": self.path("REFUSED", port=3002),
                "panel-api": self.path("REFUSED", port=7443),
            },
            "worker_paths": {
                "ssh-port": self.path("UNREACHABLE", address="::1", port=22,
                                 detail="[Errno 99] Cannot assign requested address"),
            },
            "limitation": {"status": "NOT_APPLICABLE", "reason": "no IPv6 origin in this network"},
        }

    def contract(self, facts=None):
        return multi_node.ipv6_contract(facts or self.facts(), "FW-04")

    def test_the_two_branches_are_evidence(self):
        evidence = self.contract()
        self.assertTrue(evidence["master"]["v6_chain"])
        self.assertEqual(evidence["master"]["declared"], "yes")
        self.assertEqual(sorted(evidence["master"]["v6_listens"]),
                         ["[::]:443", "[::]:80"])
        self.assertEqual(evidence["master"]["paths"]["node"]["outcome"], "REFUSED")
        self.assertTrue(evidence["worker"]["kernel_disabled"])
        self.assertEqual(evidence["worker"]["declared"], "no")
        self.assertEqual(evidence["worker"]["v6_rules"]["allows"]["3002"], [])
        self.assertEqual(evidence["limitation"]["status"], "NOT_APPLICABLE")

    def test_a_host_with_ipv6_whose_firewall_declares_it_off_is_a_finding(self):
        facts = self.facts()
        facts["master"]["ipv6"]["declared"] = "no"
        with self.assertRaises(AssertionError) as caught:
            self.contract(facts)
        self.assertIn("IPV6=no", str(caught.exception))

    def test_an_enabled_host_without_a_v6_chain_is_unfiltered(self):
        facts = self.facts()
        facts["master"]["ipv6"]["active"] = False
        with self.assertRaises(AssertionError) as caught:
            self.contract(facts)
        self.assertIn("no ufw6-user-input chain", str(caught.exception))

    def test_the_node_port_may_not_be_accepted_on_the_v6_stack(self):
        facts = self.facts()
        facts["master"]["ipv6"]["allows"][3002] = self.rules(
            "ufw6-user-input", allows=(3002,),
        )["allows"][3002]
        with self.assertRaises(AssertionError) as caught:
            self.contract(facts)
        self.assertIn("accept the local node port", str(caught.exception))

    def test_a_v6_chain_without_the_node_block_is_not_a_mirror(self):
        facts = self.facts()
        facts["master"]["ipv6"]["blocks"][3002] = []
        with self.assertRaises(AssertionError) as caught:
            self.contract(facts)
        self.assertIn("no block for the local node port", str(caught.exception))

    def test_an_internal_port_published_on_v6_is_a_finding(self):
        facts = self.facts()
        facts["master"]["ipv6"]["listens"]["[::]:7443"] = ["panel.conf"]
        with self.assertRaises(AssertionError) as caught:
            self.contract(facts)
        self.assertIn("listen [::]` for the internal port 7443", str(caught.exception))

    def test_an_enabled_host_that_renders_no_v6_listener_did_not_read_the_kernel(self):
        facts = self.facts()
        del facts["master"]["ipv6"]["listens"]["[::]:443"]
        with self.assertRaises(AssertionError) as caught:
            self.contract(facts)
        self.assertIn("renders no `listen [::]` for port 443", str(caught.exception))

    def test_a_rendered_listener_without_a_wildcard_socket_is_not_a_publication(self):
        # A rendered ``listen [::]:443`` that never became a socket is a config
        # file, not a service: the case has to read the live socket table.
        facts = self.facts()
        facts["master"]["listeners"][443] = ["0.0.0.0"]
        with self.assertRaises(AssertionError) as caught:
            self.contract(facts)
        self.assertIn("binds no wildcard IPv6 socket", str(caught.exception))

    def test_a_node_port_answered_over_v6_is_published(self):
        facts = self.facts()
        facts["master_paths"]["node"] = self.path("CONNECTED", port=3002)
        with self.assertRaises(AssertionError) as caught:
            self.contract(facts)
        self.assertIn("answered over IPv6", str(caught.exception))

    def test_a_v6_timeout_is_not_the_same_observation_as_no_socket(self):
        facts = self.facts()
        facts["master_paths"]["panel-api"] = self.path("TIMEOUT", port=7443)
        with self.assertRaises(AssertionError) as caught:
            self.contract(facts)
        self.assertIn("timeout would mean the v6 rule set dropped a packet",
                      str(caught.exception))

    def test_a_master_without_an_address_never_exercised_the_enabled_branch(self):
        facts = self.facts()
        facts["master"]["ipv6"]["kernel_addresses"] = []
        with self.assertRaises(AssertionError) as caught:
            self.contract(facts)
        self.assertIn("enabled branch was never reachable", str(caught.exception))

    def test_an_ipv4_only_worker_declaring_v6_was_misread_by_the_install(self):
        facts = self.facts()
        facts["worker"]["ipv6"]["declared"] = "yes"
        with self.assertRaises(AssertionError) as caught:
            self.contract(facts)
        self.assertIn("misread the host", str(caught.exception))

    def test_a_worker_with_v6_listeners_is_not_an_ipv4_only_host(self):
        facts = self.facts()
        facts["worker"]["ipv6"]["listens"]["[::]:443"] = ["stream.conf"]
        with self.assertRaises(AssertionError) as caught:
            self.contract(facts)
        self.assertIn("renders `listen [::]` entries", str(caught.exception))

    def test_a_reachable_worker_over_v6_means_the_stack_was_never_absent(self):
        facts = self.facts()
        facts["worker_paths"]["ssh-port"] = self.path("CONNECTED", address="::1", port=22)
        with self.assertRaises(AssertionError) as caught:
            self.contract(facts)
        self.assertIn("no IPv6' from 'IPv6 blocked", str(caught.exception))

    def test_enabling_v6_may_not_close_the_ipv4_port(self):
        facts = self.facts()
        facts["master"]["allows"][443] = []
        with self.assertRaises(AssertionError) as caught:
            self.contract(facts)
        self.assertIn("stopped publishing port 443 on IPv4", str(caught.exception))

    def test_the_worker_keeps_its_scoped_control_port_allow(self):
        facts = self.facts()
        facts["worker"]["allows"][3002] = []
        with self.assertRaises(AssertionError) as caught:
            self.contract(facts)
        self.assertIn("control port 3002", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
