#!/usr/bin/env python3
"""Suite nonroot: the AIO topology uses only run-scoped, pinned, two-network pieces."""
import contextlib
import io
import ipaddress
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools import run_podman_e2e  # noqa: E402
from tools.podman_e2e import acme_fixture, panel_only, target_image, topology  # noqa: E402
from tools.podman_e2e.runner import RunContext  # noqa: E402

PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"


class FakePodman:
    def __init__(self, install_output: str = "install ok", install_returncode: int = 0) -> None:
        self.artifacts = Path(tempfile.mkdtemp(prefix="gowave-topology-"))
        self.context = RunContext(topology="aio", artifact_root=self.artifacts, budget_seconds=3600)
        self.networks = []
        self.connects = []
        self.volumes = []
        self.used_subnets = ["10.89.0.0/24", "10.90.0.0/24", "10.88.0.0/16"]
        self.runs = []
        self.waits = []
        self.builds = []
        self.execs = []
        self.scripts = []
        self.install_script = ""
        self.install_output = install_output
        self.install_returncode = install_returncode

    def network_subnets(self):
        return list(self.used_subnets)

    def network_create(self, name, subnet=None, disable_dns=False, internal=False):
        self.networks.append((name, subnet, disable_dns, internal))
        return name

    def network_connect(self, name, network, ip=None):
        self.connects.append((name, network, ip))
        return name

    def volume_create(self, name):
        """The run's archive volume; a real one is a Podman volume, a directory here."""
        self.volumes.append(name)
        return name

    def volume_mountpoint(self, name):
        mountpoint = self.context.secret_dir / "volumes" / name
        mountpoint.mkdir(parents=True, exist_ok=True)
        return mountpoint

    def run(self, **kwargs):
        self.runs.append(kwargs)
        return kwargs["name"]

    def build(self, tag, base_alias, containerfile, context_dir):
        self.builds.append({"tag": tag, "base_alias": base_alias, "containerfile": Path(containerfile)})
        return tag

    def wait_tcp(self, name, host, port, timeout_seconds=60):
        self.waits.append(("tcp", name, host, port))

    def wait_systemd(self, name, timeout_seconds=90):
        self.waits.append(("systemd", name, "", 0))
        return "degraded"

    def exec(self, name, argv, check=True, input_text=None, timeout=300):
        self.execs.append((name, list(argv)))
        if len(argv) == 3 and argv[2] == target_image.cleanliness_probe():
            return subprocess.CompletedProcess(
                argv, 0, "init=systemd\nsystemd=systemd 255\nsshd=active\n", ""
            )
        if list(argv) == ["cat", "/proc/net/if_inet6"]:
            # ``/proc/net/if_inet6`` prints the address as 32 hex digits with no
            # separators, which is what the product's own check reads.
            address = ipaddress.ip_address(topology.IPV6_HOST_ADDRESS).exploded.replace(":", "")
            return subprocess.CompletedProcess(
                argv, 0, f"{address} 02 80 00 00 00     lo\n", ""
            )
        raise AssertionError(f"unexpected exec: {argv}")

    def exec_bash(self, name, script, check=True, input_text=None, timeout=300):
        self.scripts.append((name, script))
        self.install_script = script
        return subprocess.CompletedProcess(["bash", "-lc", script], self.install_returncode, self.install_output, "")


def run_for(kwargs_by_name, name):
    for kwargs in kwargs_by_name:
        if kwargs["name"] == name:
            return kwargs
    raise AssertionError(f"{name} was not started: {[k['name'] for k in kwargs_by_name]}")


class TestPodmanTopology(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        patcher = mock.patch.object(topology, "NETWORK_RESERVATION_LOCK", Path(directory.name) / "networks.lock")
        patcher.start()
        self.addCleanup(patcher.stop)

    def topology(self, **overrides):
        podman = FakePodman(**{key: overrides[key] for key in ("install_output", "install_returncode") if key in overrides})
        self.addCleanup(podman.context.run_cleanup)
        instance = topology.AioTopology(podman, **{k: v for k, v in overrides.items() if k not in ("install_output", "install_returncode")})
        return instance, podman

    def create(self, **overrides):
        # The disposable host must reach a resolver the fixtures do not answer for,
        # so the tests pin one instead of inheriting whatever /etc/resolv.conf holds
        # on the machine running them (CI runners only list loopback stubs).
        overrides.setdefault("egress_resolvers", ["192.0.2.53"])
        instance, podman = self.topology(**overrides)
        with mock.patch.object(acme_fixture.AcmeFixture, "issued_root", return_value=PEM), \
                mock.patch.object(acme_fixture.AcmeFixture, "wait_ready", return_value=None):
            instance.create()
        return instance, podman

    def test_four_concurrent_creates_reserve_distinct_networks(self):
        used = []
        start = Barrier(4)
        instances = []
        for distribution in target_image.DISTRIBUTIONS:
            instance, podman = self.topology(distribution=distribution, egress_resolvers=["192.0.2.53"])
            podman.used_subnets = used
            podman.network_create = lambda name, subnet, **kwargs: used.append(subnet)
            instances.append(instance)

        def create(instance):
            start.wait(timeout=5)
            return instance.create().plan

        with mock.patch.multiple(topology.AioTopology, _start_dns=mock.DEFAULT,
                                 _start_acme=mock.DEFAULT, _start_target=mock.DEFAULT,
                                 _start_echo=mock.DEFAULT, _start_client=mock.DEFAULT), \
                ThreadPoolExecutor(max_workers=4) as executor:
            plans = list(executor.map(create, instances))
        self.assertEqual(len(set(used)), 8)
        self.assertEqual({plan.subnet for plan in plans}, set(topology.CONTROL_PREFIX_CANDIDATES))
        self.assertEqual({plan.data_subnet for plan in plans}, set(topology.DATA_PREFIX_CANDIDATES))
        with self.assertRaisesRegex(topology.TopologyError, "no free /24"):
            topology.allocate_plan(used)

    def test_parallel_matrix_rejects_missing_evidence_and_failed_children(self):
        for failure in (None, "missing", "child"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                start = Barrier(4)
                observed = []

                def run(command, **kwargs):
                    start.wait(timeout=5)
                    distribution = command[command.index("--distribution") + 1]
                    artifact_root = Path(command[command.index("--artifact-root") + 1])
                    observed.append((distribution, artifact_root))
                    if distribution != "debian-13" or failure != "missing":
                        result = artifact_root / "run" / "result.json"
                        result.parent.mkdir(parents=True)
                        result.write_text('{"overall": "PASS"}', encoding="utf-8")
                    return subprocess.CompletedProcess(command, int(distribution == "debian-13" and failure == "child"))

                with mock.patch.object(run_podman_e2e.subprocess, "run", side_effect=run), \
                        contextlib.redirect_stdout(io.StringIO()):
                    status = run_podman_e2e.main(["--all-distributions", "--artifact-root", directory])
                self.assertEqual(status, int(failure is not None))
                self.assertEqual({name for name, _ in observed}, set(target_image.DISTRIBUTIONS))
                self.assertEqual(len({path for _, path in observed}), 4)

    def test_plan_skips_subnets_already_claimed_on_the_host(self):
        plan = topology.allocate_plan(["203.0.114.0/24"])
        self.assertEqual(plan.data_subnet, "198.51.101.0/24")
        self.assertEqual(plan.data_echo_ip, "198.51.101.30")
        self.assertEqual(topology.allocate_plan([]).data_subnet, "203.0.114.0/24")
        control = topology.allocate_plan(["10.89.0.0/24", "10.90.0.0/24"])
        self.assertEqual(control.subnet, "10.91.0.0/24")
        self.assertEqual(control.dns_ip, "10.91.0.53")
        self.assertEqual(control.target_ip, "10.91.0.10")
        self.assertEqual(control.pebble_ip, "10.91.0.20")
        self.assertEqual(control.echo_ip, "10.91.0.30")

    def test_the_control_network_is_private_and_the_data_network_is_public(self):
        # The product resolves its own address through a test-only override that
        # accepts a private address only, so the control network has to be private.
        for candidate in topology.CONTROL_PREFIX_CANDIDATES:
            self.assertTrue(
                ipaddress.ip_network(candidate).is_private,
                f"{candidate} is not private, so the installer would reject the override",
            )
        # A data-plane destination cannot be private or documented: the node blocks
        # private ranges, and the engine's freedom outbound blackholes everything the
        # IANA special-purpose registry lists while draining the stream until its
        # block duration expires, so a payload addressed there hangs instead of
        # recording an egress.
        documentation = {"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"}
        for candidate in topology.DATA_PREFIX_CANDIDATES:
            network = ipaddress.ip_network(candidate)
            self.assertTrue(
                network.is_global,
                f"{candidate} is not global unicast, so the engine would blackhole it",
            )
            self.assertNotIn(str(network), documentation)
        plan = topology.allocate_plan([])
        self.assertEqual(plan.subnet, "10.89.0.0/24")
        self.assertEqual(plan.data_subnet, "203.0.114.0/24")
        self.assertNotEqual(plan.data_target_ip, plan.target_ip)
        self.assertFalse(
            ipaddress.ip_network(plan.subnet).overlaps(ipaddress.ip_network(plan.data_subnet)),
            "the two networks must never share a block",
        )

    def test_zone_points_every_name_into_the_run(self):
        plan = topology.NetworkPlan(subnet="10.89.0.0/24")
        zone = topology.zone(plan)
        records = zone["records"]
        self.assertEqual(records[topology.PANEL_DOMAIN]["A"], [plan.target_ip])
        self.assertEqual(records[topology.REALITY_DOMAIN]["A"], [plan.target_ip])
        self.assertEqual(records[topology.VISION_DOMAIN]["A"], [plan.target_ip])
        self.assertEqual(records[acme_fixture.FIXTURE_HOST]["A"], [plan.pebble_ip])
        self.assertEqual(records[topology.ECHO_HOST]["A"], [plan.echo_ip])
        self.assertEqual(zone["behavior"]["mode"], "answer")

    def test_egress_resolvers_skip_stub_addresses(self):
        directory = Path(tempfile.mkdtemp(prefix="gowave-resolv-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(directory, True))
        resolv = directory / "resolv.conf"
        resolv.write_text(
            "nameserver 169.254.1.1\nnameserver 127.0.0.53\nnameserver 192.168.1.1\n"
            "nameserver 192.168.1.1\nnameserver 9.9.9.9\n",
            encoding="utf-8",
        )
        self.assertEqual(topology.egress_resolvers(resolv, upstreams=()), ["192.168.1.1", "9.9.9.9"])
        self.assertEqual(topology.egress_resolvers(directory / "absent", upstreams=()), [])

    def test_a_stub_only_resolv_conf_follows_the_upstream_list(self):
        # A host running systemd-resolved answers /etc/resolv.conf with its own
        # 127.0.0.53 listener, which does not exist inside the container. The
        # upstream file beside it is the only address the target can use.
        directory = Path(tempfile.mkdtemp(prefix="gowave-resolv-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(directory, True))
        stub = directory / "resolv.conf"
        stub.write_text("nameserver 127.0.0.53\nnameserver ::1\n", encoding="utf-8")
        upstream = directory / "upstream.conf"
        upstream.write_text(
            "nameserver 168.63.129.16\nnameserver 127.0.0.1\n",
            encoding="utf-8",
        )
        self.assertEqual(
            topology.egress_resolvers(stub, upstreams=(upstream,)),
            ["168.63.129.16"],
        )

    def test_a_real_address_in_the_host_file_is_not_replaced(self):
        directory = Path(tempfile.mkdtemp(prefix="gowave-resolv-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(directory, True))
        resolv = directory / "resolv.conf"
        resolv.write_text("nameserver 192.168.1.1\n", encoding="utf-8")
        upstream = directory / "upstream.conf"
        upstream.write_text("nameserver 9.9.9.9\n", encoding="utf-8")
        self.assertEqual(topology.egress_resolvers(resolv, upstreams=(upstream,)), ["192.168.1.1"])

    def test_a_stub_only_host_without_an_upstream_file_yields_nothing(self):
        directory = Path(tempfile.mkdtemp(prefix="gowave-resolv-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(directory, True))
        stub = directory / "resolv.conf"
        stub.write_text("nameserver 127.0.0.53\n", encoding="utf-8")
        self.assertEqual(
            topology.egress_resolvers(stub, upstreams=(directory / "absent.conf",)),
            [],
        )

    def test_a_run_without_an_egress_resolver_never_starts(self):
        instance, podman = self.topology(egress_resolvers=[])
        with self.assertRaises(topology.TopologyError):
            instance.create()
        self.assertEqual(podman.runs, [])
        self.assertEqual(podman.networks, [])

    def test_dns_fixture_command_serves_the_zone(self):
        command = topology.dns_command("/fixtures/dns/zone.json", "/fixtures/dns/queries.jsonl")
        self.assertEqual(command[0], "python3")
        self.assertIn(topology.DNS_FIXTURE_SCRIPT, command)
        self.assertEqual(command[command.index("--port") + 1], "53")
        self.assertEqual(command[command.index("--zone") + 1], "/fixtures/dns/zone.json")
        self.assertEqual(command[command.index("--out-of-zone") + 1], "refused")

    def test_create_builds_two_networks_and_three_containers(self):
        instance, podman = self.create()
        self.assertEqual(instance.plan.subnet, "10.91.0.0/24")
        self.assertEqual(len(podman.networks), 2)
        control, data = podman.networks
        self.assertEqual(control[1], "10.91.0.0/24")
        self.assertTrue(control[2], "the run network must not install its own resolver")
        self.assertFalse(control[3], "the control network keeps the gateway the host installs packages over")
        self.assertEqual(data[1], "203.0.114.0/24")
        self.assertTrue(data[2])
        self.assertTrue(data[3], "the data network must have no gateway, so nothing it carries can be routed")
        self.assertEqual(
            podman.connects,
            [
                (instance.target_name, instance.data_network, instance.plan.data_target_ip),
                (instance.echo_name, instance.data_network, instance.plan.data_echo_ip),
            ],
            "the host and the endpoint are the only roles the data plane needs before the engines start",
        )
        dns = run_for(podman.runs, instance.dns_name)
        self.assertEqual(dns["image_alias"], topology.FIXTURE_IMAGE)
        self.assertFalse(dns["privileged"])
        self.assertIn("--ip", dns["extra_args"])
        self.assertEqual(dns["extra_args"][dns["extra_args"].index("--ip") + 1], instance.plan.dns_ip)
        self.assertEqual(dns["volumes"][0].split(":/fixtures/dns")[0], str(podman.context.secret_dir / "dns"))

        target = run_for(podman.runs, instance.target_name)
        self.assertTrue(target["privileged"])
        self.assertEqual(target["systemd"], "always")
        self.assertEqual(target["aliases"], (topology.PANEL_DOMAIN,))
        extra = target["extra_args"]
        self.assertEqual(extra[extra.index("--ip") + 1], instance.plan.target_ip)
        self.assertEqual(extra[extra.index("--dns") + 1], instance.plan.dns_ip)
        self.assertEqual(
            [extra[i + 1] for i, value in enumerate(extra) if value == "--dns"],
            [instance.plan.dns_ip, *instance.egress_resolvers],
        )
        self.assertTrue(target["volumes"][0].startswith(str(podman.context.secret_dir / "client-ca")))
        self.assertIn(("systemd", instance.target_name, "", 0), podman.waits)

        pebble = run_for(podman.runs, instance.acme.name)
        self.assertEqual(pebble["image_alias"], "acme-pebble")
        self.assertFalse(pebble["privileged"])
        self.assertIn("--ip", pebble["extra_args"])
        self.assertIn(instance.acme.management_host_port, [int(v) for v in self._published_ports(pebble["extra_args"])])

    @staticmethod
    def _published_ports(extra_args):
        ports = []
        for index, value in enumerate(extra_args):
            if value == "-p":
                ports.append(extra_args[index + 1].rsplit(":", 2)[-2])
        return ports

    def test_target_image_is_built_from_the_pinned_alias(self):
        instance, podman = self.create(distribution="debian-13")
        self.assertEqual(podman.builds[0]["base_alias"], "debian-13")
        self.assertEqual(podman.builds[0]["tag"], "gowave-e2e-target:debian-13")

    def test_install_environment_carries_the_pinned_test_trust(self):
        instance, podman = self.create()
        environment = instance.install_environment()
        self.assertEqual(environment["GOWAVE_ACME_SERVER"], acme_fixture.ACME_DIRECTORY_URL)
        self.assertEqual(environment["GOWAVE_ACME_TEST_MODE"], "1")
        self.assertEqual(environment["GOWAVE_ACME_TEST_CA_FILE"], "/fixtures/ca/acme-trust.pem")
        self.assertRegex(environment["GOWAVE_ACME_TEST_CA_SHA256"], r"^[0-9a-f]{64}$")
        self.assertEqual(environment["GOWAVE_TLS_CA_FILE"], "/fixtures/ca/issued-root.pem")
        self.assertEqual(environment["GOWAVE_PODMAN_MASTER_ADDRESS"], instance.plan.target_ip)
        self.assertEqual(environment["GOWAVE_PODMAN_NETWORK_CIDR"], instance.plan.subnet)

        target = run_for(podman.runs, instance.target_name)
        self.assertEqual(target["environment"], environment)
        bundle = podman.context.secret_dir / "client-ca" / topology.ACME_CA_BUNDLE_NAME
        self.assertEqual(environment["GOWAVE_ACME_TEST_CA_SHA256"], acme_fixture.ca_file_sha256(bundle))
        # The pinned file has to trust Pebble's HTTPS endpoint and also carry the
        # root its issued certificates chain to; one root cannot do both.
        text = bundle.read_text(encoding="utf-8")
        fixture_root = podman.context.secret_dir / "client-ca" / topology.CA_FILE_NAME
        self.assertIn(fixture_root.read_text(encoding="utf-8"), text)
        self.assertIn(PEM, text)
        issued = podman.context.secret_dir / "client-ca" / topology.ISSUED_ROOT_NAME
        self.assertEqual(issued.read_text(encoding="utf-8"), PEM)

    def test_install_script_runs_the_real_operator_path(self):
        instance, _ = self.create()
        self.assertEqual(
            instance.install_script(),
            f"bash /repo/gowave-auto.sh install '{topology.PANEL_DOMAIN}' "
            f"'{topology.REALITY_DOMAIN}' '{instance.admin_email}'",
        )
        vision, _ = self.create(vision_domain="vision.testbed.internal")
        self.assertTrue(vision.install_script().endswith("'vision.testbed.internal'"))

    def test_install_writes_evidence_and_reports_failure(self):
        instance, podman = self.create(install_returncode=1, install_output="Error: ACME failed")
        outcome = instance.install()
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.returncode, 1)
        self.assertIn("bash /repo/gowave-auto.sh install", podman.install_script)
        self.assertTrue((podman.context.artifact_dir / "evidence" / "aio-install.stdout.log").is_file())
        self.assertTrue((podman.context.artifact_dir / "evidence" / "aio-install.stderr.log").is_file())
        with self.assertRaises(topology.TopologyError) as caught:
            instance.install_must_succeed()
        self.assertIn("ACME failed", str(caught.exception))

    def test_evidence_records_domains_fixtures_and_images(self):
        instance, podman = self.create()
        podman.context.environment["images_resolved"] = {"ubuntu-24.04": "docker.io/library/ubuntu@sha256:" + "a" * 64}
        record = instance.evidence(instance.install())
        self.assertEqual(record["panel_domain"], topology.PANEL_DOMAIN)
        self.assertEqual(record["target_ip"], instance.plan.target_ip)
        self.assertEqual(record["subnet"], instance.plan.subnet)
        self.assertEqual(record["pre_install"]["installed"], [])
        self.assertEqual(record["acme_fixture"]["endpoint"], acme_fixture.ACME_DIRECTORY_URL)
        self.assertIn("ubuntu-24.04", record["images_resolved"])
        self.assertEqual(record["install_command"], instance.install_script())

    def test_the_client_probe_carries_the_fixture_anchor_unless_it_is_withheld(self):
        instance, podman = self.create()

        def answer(name, argv, check=True, input_text=None, timeout=300):
            podman.execs.append((name, list(argv)))
            return subprocess.CompletedProcess(argv, 0, '{"url": "https://probe/"}', "")

        podman.exec = answer
        url = f"https://{topology.PANEL_DOMAIN}/"
        instance.client_http(url)
        argv = podman.execs[-1][1]
        self.assertEqual(argv[argv.index("--ca") + 1],
                         f"{topology.CA_MOUNT}/{topology.ISSUED_ROOT_NAME}")
        # Withholding the anchor is the only way an unanchored handshake can be
        # measured; switching verification off instead would prove nothing.
        instance.client_http(url, anchor=False)
        argv = podman.execs[-1][1]
        self.assertNotIn("--ca", argv)
        self.assertNotIn("--insecure", argv)
        instance.client_http(url, max_tls="TLSv1.1")
        argv = podman.execs[-1][1]
        self.assertEqual(argv[argv.index("--max-tls") + 1], "TLSv1.1")
        self.assertIn("--ca", argv)

    def test_the_aio_host_stays_ipv4_only_unless_the_run_asks_for_ipv6(self):
        # 6.7: the IPv6 branch belongs to the run that has to prove it, so an
        # ordinary All-in-One host keeps the address table a plain VPS has.
        instance, podman = self.create()
        self.assertFalse(instance.ipv6_host)
        self.assertEqual(instance.ipv6_address, "")
        self.assertNotIn("disable_ipv6=0", "".join(script for _name, script in podman.scripts))

    def test_unsupported_distribution_is_rejected_before_any_container(self):
        podman = FakePodman()
        self.addCleanup(podman.context.run_cleanup)
        with self.assertRaises(target_image.TargetImageError):
            topology.AioTopology(podman, distribution="centos-9")
        self.assertEqual(podman.runs, [])


class TestPanelOnlyTopology(unittest.TestCase):
    """The Panel-only drive: the operator's own flag, no Vision, and five declared cases.

    The mode is a product deployment the installer documents, so the harness has
    to invoke it through the command an operator would type rather than through a
    second entry point. These tests hold the rendered command, the refusal of the
    Vision arguments the mode cannot honour, and the suite the entrypoint builds.
    """

    def make(self, **overrides):
        podman = FakePodman(**{
            key: overrides[key]
            for key in ("install_output", "install_returncode") if key in overrides
        })
        self.addCleanup(podman.context.run_cleanup)
        overrides.setdefault("egress_resolvers", ["192.0.2.53"])
        instance = topology.PanelOnlyTopology(
            podman, **{
                key: value for key, value in overrides.items()
                if key not in ("install_output", "install_returncode")
            }
        )
        return instance, podman

    def test_the_rendered_command_is_the_documented_panel_only_flag(self):
        instance, _podman = self.make()
        self.assertEqual(
            instance.install_script(),
            f"bash /repo/gowave-auto.sh install --panel-only '{topology.PANEL_DOMAIN}' "
            f"'{topology.REALITY_DOMAIN}' '{instance.admin_email}'",
            "the harness must drive the flag the operator documentation names",
        )
        self.assertEqual(instance.install_script().count("'"), 6, "three positionals, no Vision")

    def test_the_mode_refuses_a_vision_domain_it_cannot_terminate(self):
        with self.assertRaises(ValueError) as caught:
            self.make(vision_domain="vision.testbed.internal")
        self.assertIn("no Vision domain", str(caught.exception))

    def test_install_and_reinstall_keep_their_own_evidence(self):
        instance, podman = self.make(install_output="panel-only ok")
        outcome = instance.install()
        self.assertTrue(outcome.ok)
        evidence = podman.context.artifact_dir / "evidence"
        self.assertTrue((evidence / "panel-only-install.stdout.log").is_file())
        self.assertTrue((evidence / "panel-only-install.stderr.log").is_file())
        self.assertIn("install --panel-only", podman.install_script)
        instance.reinstall()
        self.assertTrue((evidence / "panel-only-reinstall.stdout.log").is_file())
        self.assertIn("install --panel-only", podman.install_script)

    def test_the_host_and_its_record_are_named_by_the_mode(self):
        instance, _podman = self.make()
        self.assertEqual(instance.target_role, "panel-only")
        self.assertNotEqual(instance.target_name, instance.context.resource_name("aio"))
        record = instance.evidence(instance.install())
        self.assertEqual(record["installation_mode"], "panel-only")
        self.assertEqual(record["install_command"], instance.install_script())
        self.assertEqual(record["vision_domain"], "")

    def test_the_topology_declares_the_seven_panel_only_cases(self):
        suite = panel_only.cases(FakePodman())
        self.assertEqual(
            [case.id for case in suite],
            [
                "PO-INSTALL", "PO-HOST", "PO-FIREWALL", "PO-API", "PO-SQUAD",
                "PO-SQUAD-REFUSED",
                # The add-node refusal needs a Panel and no Worker, so both
                # topologies run it: Panel-only is where the mutation boundary it
                # asserts stays crossed by construction.
                "MN-ADD-NODE-REFUSED",
            ],
        )
        self.assertEqual({case.topology for case in suite}, {"panel-only"})

    def test_the_entrypoint_lists_the_third_topology(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as caught:
            run_podman_e2e.main(["--help"])
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("panel-only", out.getvalue())

    def _refused(self, arguments):
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as directory, \
                contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as caught:
            run_podman_e2e.main([*arguments, "--artifact-root", directory])
        return caught.exception.code, err.getvalue()

    def test_the_vision_flags_are_refused_before_any_container(self):
        for flag in ("--vision", "--worker-vision"):
            with self.subTest(flag=flag):
                code, err = self._refused(["--topology", "panel-only", flag])
                self.assertEqual(code, 2)
                self.assertIn("topology has none", err)

    def test_the_entrypoint_builds_the_declared_panel_only_suite(self):
        suite = run_podman_e2e.build_suite(
            FakePodman(), "panel-only", run_podman_e2e.DEFAULT_DISTRIBUTION,
        )
        self.assertEqual(
            [case.id for case in suite],
            [
                "PO-INSTALL", "PO-HOST", "PO-FIREWALL", "PO-API", "PO-SQUAD",
                "PO-SQUAD-REFUSED", "MN-ADD-NODE-REFUSED",
            ],
        )
        self.assertEqual(run_podman_e2e.TOPOLOGIES, ("aio", "multi-node", "panel-only"))


if __name__ == "__main__":
    unittest.main()
