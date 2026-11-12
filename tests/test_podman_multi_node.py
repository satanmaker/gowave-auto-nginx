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
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import matrix, multi_node, topology  # noqa: E402
from tools.podman_e2e.runner import Case  # noqa: E402


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

    def test_a_role_that_never_started_is_refused_by_name(self):
        host = self._create()
        host.started.remove(host.worker_name)
        with self.assertRaises(topology.TopologyError) as caught:
            host.require_roles()
        self.assertIn(host.worker_name, str(caught.exception))

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
            [case.id for case in suite][:3],
            [multi_node.INSTALL_CASE_ID, multi_node.NODE_ADD_CASE_ID,
             multi_node.MASTER_ADDRESS_CASE_ID],
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


if __name__ == "__main__":
    unittest.main()
