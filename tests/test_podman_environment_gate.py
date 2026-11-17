#!/usr/bin/env python3
"""Suite nonroot: the disposable-environment gate, decided on a host.

``ENV-01``/``ENV-02`` start a throwaway container from the run's own pinned image
and read it over SSH, which a unit test cannot own. What it can own is everything
the live cases rely on being right:

* The container the cases start is asserted here against a recording Podman: the
  same image tag the install case built, the run's network and resolver, systemd
  as the entry point, the runner's own key installed into ``authorized_keys`` and
  the host key read from the host's filesystem rather than from a keyscan, and the
  container removed whatever the case did.
* The two cases are then driven whole against a modelled host. The product's own
  ``check_disposable_gate`` and ``evaluate_preflight_eligibility`` decide; only the
  read of the host is replaced, because that read is what needs SSH. The
  contaminations are real model mutations — a directory, a running unit, a real
  ``sshd`` on 443, a hidden ``tcpdump`` — so the four refusals are the gate's own
  sentences, cumulative as the case requires.
* Each clause is then damaged on its own, so every assertion is seen to fail for
  the reason it protects.

What is not covered here is the container itself: systemd, ``apt-get``, ``ss`` and
a network listener are proven by the live Podman run, not by this suite.
"""
import contextlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import catalog, environment_gate, target_image  # noqa: E402

TOPOLOGIES = ("aio", "multi-node")

CASES = {
    environment_gate.CLEAN_CASE_ID: environment_gate.case_clean_baseline_passes_gate,
    environment_gate.CONTAMINATED_CASE_ID: environment_gate.case_contaminated_host_is_refused,
}

DISTRIBUTION = "ubuntu-24.04"
ADDRESS = "10.89.0.2"
NETWORK = "gowave-e2e"
DNS_IP = "10.89.0.1"
EGRESS_RESOLVERS = ("1.1.1.1",)
HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGateProbeKey gate"

#: The product's own eligibility verdict, captured before a damage replaces it.
_REAL_ELIGIBILITY = environment_gate._eligibility

EXPECTED_REFUSALS = {
    ("ENV-01", "baseline-mutates"): "reading the baseline changed the host",
    ("ENV-01", "occupied-port"): "already listens on the required ports",
    ("ENV-01", "tools-missing"): "a host the case just gave both target tools reports",
    ("ENV-01", "no-listeners"): "the host reports no listening port at all",
    ("ENV-01", "manifest-short"): "the baseline manifest has no",
    ("ENV-01", "preflight-fails"): "preflight reported",
    ("ENV-01", "install-failed"): "the run's own install case has not succeeded",
    ("ENV-01", "services-running"): "a fresh container reports GoWave services",
    ("ENV-01", "image-has-directories"): "the container image already carries GoWave directories",
    ("ENV-01", "gate-refuses-clean"): "the gate refused a clean host:",
    ("ENV-01", "vision-gate-refuses"):
        "the gate refused a clean host once the Vision ports joined the list",
    ("ENV-01", "verdict-loses-the-manifest"):
        "the verdict does not carry the manifest it was read from",
    ("ENV-02", "gate-accepts"): "the gate accepted a host it has to refuse",
    ("ENV-02", "order-inverted"): "does not read the baseline, decide the gate, halt",
    ("ENV-02", "eligibility-passes"): "preflight reported",
    ("ENV-02", "refusal-repairs"): "the refused run changed the objects it refused for",
    ("ENV-02", "gate-errors-dropped"): "not the refusal the gate produced",
    ("ENV-02", "refusal-not-cumulative"):
        "does not name the service clause beside the directory it already found",
    ("ENV-02", "control-refused"): "the control read of an uncontaminated host was refused",
    ("ENV-02", "control-mutates"): "reading the control baseline changed the host",
    ("ENV-02", "verdict-loses-the-manifest"):
        "the rejected verdict does not carry the manifest it was read from",
}


class GateModel:
    """One container's state, as far as the gate can observe it."""

    def __init__(self):
        self.directories = []
        self.services = []
        self.listeners = [22]
        self.tools = {"tcpdump": "ok", "timeout": "ok"}
        #: Bumped by a baseline read that is not read-only; the sentinel is read
        #: through it, so a mutation is visible without modelling a filesystem.
        self.generation = 0

    def sentinel(self):
        return {
            "sha256": f"{self.generation:064d}",
            "mtime": str(1700000000 + self.generation),
            "packages": "12",
        }

    def manifest(self):
        return {
            "os_kernel": "6.8.0-51-generic",
            "running_services": list(self.services),
            "tcp_listeners_raw": "\n".join(
                f"LISTEN 0 4096 0.0.0.0:{port} 0.0.0.0:*" for port in self.listeners),
            "listening_ports": list(self.listeners),
            "existing_gowave_dirs": list(self.directories),
            "firewall_status": "inactive",
            "swap_info": "0B",
            "disk_usage": "8%",
            "key_packages": "1",
            "required_tools": dict(self.tools),
        }


class HostPodman:
    """The container, as far as these cases use it: a shell and three files."""

    def __init__(self, model):
        self.model = model
        self.commands = []

    @staticmethod
    def _result(stdout=""):
        return subprocess.CompletedProcess([], 0, stdout, "")

    def exec_bash(self, name, script, check=True, input_text=None, timeout=None):
        self.commands.append(("exec_bash", name, script))
        model = self.model
        if script.startswith("export DEBIAN_FRONTEND"):
            return self._result()
        if "gowave-gate-sentinel" in script:
            return self._result()
        if "mkdir -p /opt/gowave" in script:
            model.directories.append("/opt/gowave")
            return self._result()
        if "[Unit]" in script:
            model.services.append(environment_gate._PROBE_UNIT)
            return self._result()
        if "/usr/sbin/sshd -p" in script:
            model.listeners.append(environment_gate._PROBE_PORT)
            return self._result()
        if 'mv "$tool" "$tool.hidden"' in script:
            model.tools["tcpdump"] = "missing"
            return self._result("HIDDEN\n")
        if "test -d /opt/gowave" in script:
            return self._result(
                "present\n" if "/opt/gowave" in model.directories else "absent\n")
        if f"systemctl is-active --quiet {environment_gate._PROBE_UNIT}" in script:
            return self._result(
                "active\n" if environment_gate._PROBE_UNIT in model.services else "inactive\n")
        if "command -v tcpdump" in script:
            return self._result("hidden\n" if model.tools["tcpdump"] != "ok" else "present\n")
        raise AssertionError(f"unmodelled exec_bash: {script[:80]!r}")

    def exec(self, name, argv, check=True, input_text=None, timeout=None):
        self.commands.append(("exec", name, list(argv)))
        model = self.model
        if argv[0] == "sha256sum":
            return self._result(f"{model.sentinel()['sha256']}  {argv[1]}\n")
        if argv[0] == "stat":
            return self._result(model.sentinel()["mtime"] + "\n")
        if argv[0] == "cat":
            return self._result(HOST_KEY + "\n")
        script = argv[2] if len(argv) > 2 and argv[0] == "bash" else ""
        if "dpkg-query" in script:
            return self._result(model.sentinel()["packages"] + "\n")
        if "ss -tlnH" in script:
            port = environment_gate._PROBE_PORT
            return self._result(f"{str(port in model.listeners and 1 or 0)}\n")
        if "for t in" in script:
            return self._result("".join(f"{tool}=ok\n" for tool in environment_gate.GATE_TOOLS))
        raise AssertionError(f"unmodelled exec: {argv!r}")


def _fake_baseline(ssh):
    return ssh.model.manifest()


#: What a damage wants the container to start with, applied by the fake host.
_SEED = {}


class Seed:
    """A patcher that seeds the modelled container before the case reads it."""

    def __init__(self, **values):
        self.values = values

    def start(self):
        _SEED.update(self.values)

    def stop(self):
        _SEED.clear()


@contextlib.contextmanager
def _fake_gate_host(_product, _case_id, _label):
    model = GateModel()
    for attribute, value in _SEED.items():
        setattr(model, attribute, value)
    yield environment_gate._GateHost(
        name="gate-test", address=ADDRESS, ssh=SimpleNamespace(model=model),
        podman=HostPodman(model), distribution=DISTRIBUTION,
    )


def _product(ok=True):
    return SimpleNamespace(outcome=SimpleNamespace(ok=ok), topology=None, host=None)


def _damages(hosts):
    """The patches each damage installs, over the modelled host it is given."""

    def baseline(mutate=None, drop=None, ports=None, tools=None, cumulative=True):
        def read(ssh):
            if mutate is not None:
                mutate(ssh.model)
            manifest = ssh.model.manifest()
            if not cumulative and manifest["running_services"]:
                # A gate that reports only its newest reason: the directory it
                # already found is forgotten once a unit is running.
                manifest["existing_gowave_dirs"] = []
            if drop is not None:
                manifest.pop(drop, None)
            if ports is not None:
                manifest["listening_ports"] = ports
            if tools is not None:
                manifest["required_tools"] = tools
            return manifest

        return read

    def eligibility(**overrides):
        def evaluate(*_args, **_kwargs):
            status = {
                "status": "FAIL",
                "master_gate_errors": [],
                "worker_gate_errors": [],
                "master_baseline": {},
                "worker_baseline": {},
            }
            status.update(overrides)
            return status

        return evaluate

    def gate(cleared):
        return lambda *_args, **_kwargs: (cleared, [] if cleared else ["refused"])

    def gate_that_refuses_vision_only(_manifest, vision_enabled=False):
        return (False, ["vision"]) if vision_enabled else (True, [])

    def eligibility_that_loses_the_manifest(*args, **kwargs):
        status = _REAL_ELIGIBILITY(*args, **kwargs)
        status["master_baseline"] = dict(status["master_baseline"])
        status["worker_baseline"] = dict(status["worker_baseline"])
        return status

    def descending(_path, *anchors):
        return list(range(len(anchors)))[::-1]

    return {
        ("ENV-01", "baseline-mutates"): [
            mock.patch.object(
                environment_gate, "collect_remote_baseline",
                baseline(mutate=lambda model: setattr(model, "generation", 1))),
        ],
        ("ENV-01", "occupied-port"): [
            mock.patch.object(
                environment_gate, "collect_remote_baseline", baseline(ports=[22, 443])),
        ],
        ("ENV-01", "tools-missing"): [
            mock.patch.object(
                environment_gate, "collect_remote_baseline",
                baseline(tools={"tcpdump": "missing", "timeout": "ok"})),
        ],
        ("ENV-01", "no-listeners"): [
            mock.patch.object(
                environment_gate, "collect_remote_baseline", baseline(ports=[])),
        ],
        ("ENV-01", "manifest-short"): [
            mock.patch.object(
                environment_gate, "collect_remote_baseline", baseline(drop="swap_info")),
        ],
        ("ENV-01", "preflight-fails"): [
            mock.patch.object(environment_gate, "_eligibility", eligibility()),
        ],
        ("ENV-01", "install-failed"): [],
        ("ENV-01", "services-running"): [
            Seed(services=[environment_gate._PROBE_UNIT.replace("gate-probe", "node")]),
        ],
        ("ENV-01", "image-has-directories"): [
            Seed(directories=["/opt/gowave"]),
        ],
        ("ENV-01", "gate-refuses-clean"): [
            mock.patch.object(environment_gate, "check_disposable_gate", gate(False)),
        ],
        ("ENV-01", "vision-gate-refuses"): [
            mock.patch.object(
                environment_gate, "check_disposable_gate", gate_that_refuses_vision_only),
        ],
        ("ENV-01", "verdict-loses-the-manifest"): [
            mock.patch.object(
                environment_gate, "_eligibility", eligibility_that_loses_the_manifest),
        ],
        ("ENV-02", "gate-accepts"): [
            mock.patch.object(environment_gate, "check_disposable_gate", gate(True)),
        ],
        ("ENV-02", "order-inverted"): [
            mock.patch.object(environment_gate.preflight_cases, "_source_order", descending),
        ],
        ("ENV-02", "eligibility-passes"): [
            mock.patch.object(environment_gate, "_eligibility", eligibility(status="PASS")),
        ],
        ("ENV-02", "refusal-repairs"): [
            mock.patch.object(
                environment_gate, "_objects_after_refusal",
                lambda _host: {
                    "directory_present": False, "probe_service_active": True,
                    "probe_port_listening": True, "tcpdump_hidden": True,
                }),
        ],
        ("ENV-02", "gate-errors-dropped"): [
            mock.patch.object(environment_gate, "_eligibility", eligibility()),
        ],
        ("ENV-02", "refusal-not-cumulative"): [
            mock.patch.object(
                environment_gate, "collect_remote_baseline", baseline(cumulative=False)),
        ],
        ("ENV-02", "control-refused"): [
            mock.patch.object(
                environment_gate, "collect_remote_baseline",
                baseline(tools={"tcpdump": "missing", "timeout": "ok"})),
        ],
        ("ENV-02", "control-mutates"): [
            mock.patch.object(
                environment_gate, "collect_remote_baseline",
                baseline(mutate=lambda model: setattr(
                    model, "generation", model.generation + 1))),
        ],
        ("ENV-02", "verdict-loses-the-manifest"): [
            mock.patch.object(
                environment_gate, "_eligibility", eligibility_that_loses_the_manifest),
        ],
    }


def run_case(case_id, topology="aio", damage=None):
    """Run one case over the modelled host; return (facts, refusal)."""
    # The read of the host is the one thing that needs SSH, so it is replaced for
    # every run; a damage that changes what the host reports patches it again, and
    # the last patch started is the one the case reads.
    patchers = [mock.patch.object(environment_gate, "collect_remote_baseline", _fake_baseline)]
    patchers += _damages(None).get((case_id, damage), []) if damage else []
    product = _product(ok=(damage != "install-failed"))
    for patcher in patchers:
        patcher.start()
    try:
        with mock.patch.object(environment_gate, "_gate_host", _fake_gate_host), \
                mock.patch.object(environment_gate, "_install_gate_tools", lambda host, _id: {
                    tool: "ok" for tool in environment_gate.GATE_TOOLS
                }):
            return CASES[case_id](product, SimpleNamespace(topology=topology)), None
    except AssertionError as error:
        return None, str(error)
    finally:
        for patcher in reversed(patchers):
            patcher.stop()


class FakeTopology:
    """The run's own topology, as the container bootstrap reads it."""

    def __init__(self):
        self.distribution = DISTRIBUTION
        self.network = NETWORK
        self.plan = SimpleNamespace(dns_ip=DNS_IP)
        self.egress_resolvers = EGRESS_RESOLVERS
        self.podman = RecordingPodman()
        self.context = SimpleNamespace(resource_name=lambda label: f"gowave-{label}")


class RecordingPodman:
    """A Podman that records what the bootstrap asked for."""

    def __init__(self):
        self.runs = []
        self.waits = []
        self.commands = []

    def run(self, **kwargs):
        self.runs.append(kwargs)
        return kwargs["name"]

    def wait_systemd(self, name, timeout_seconds=180):
        self.waits.append((name, timeout_seconds))
        return True

    def address(self, _name, _network):
        return ADDRESS

    def exec_bash(self, name, script, check=True, input_text=None, timeout=None):
        self.commands.append((name, "exec_bash", script, input_text))
        return subprocess.CompletedProcess([], 0, "", "")

    def exec(self, name, argv, check=True, input_text=None, timeout=None):
        self.commands.append((name, "exec", list(argv), input_text))
        return subprocess.CompletedProcess([], 0, HOST_KEY + "\n", "")

    def _run(self, args, check=True, timeout=300):
        self.commands.append(("_run", list(args), None, None))
        return subprocess.CompletedProcess(args, 0, "", "")


class TestEnvironmentGateRegistration(unittest.TestCase):
    """Both ids are registered on both contours and mapped to their requirement."""

    def test_every_id_is_registered_on_both_contours_with_its_own_callable(self):
        registry = catalog.driver_registry()
        for case_id, function in CASES.items():
            with self.subTest(case_id=case_id):
                self.assertIn(case_id, registry)
                self.assertEqual(set(registry[case_id]), set(TOPOLOGIES))
                for topology in TOPOLOGIES:
                    self.assertEqual(
                        registry[case_id][topology]["driver"],
                        f"environment_gate:{function.__name__}",
                    )

    def test_the_catalog_entry_is_what_the_registry_derives(self):
        registry = catalog.driver_registry()
        entries = {entry["id"]: entry for entry in catalog.load_catalog()["cases"]}
        for case_id in CASES:
            with self.subTest(case_id=case_id):
                self.assertEqual(entries[case_id]["driver_status"], "implemented")
                self.assertEqual(entries[case_id]["drivers"], registry[case_id])


class TestGateHostBootstrap(unittest.TestCase):
    """The container the cases start: the run's own image, key and host key."""

    def setUp(self):
        self.topology = FakeTopology()
        self.product = SimpleNamespace(
            outcome=SimpleNamespace(ok=True), topology=self.topology, host=None)
        self.keys = Path(tempfile.mkdtemp(prefix="gowave-gate-keys-"))
        self.addCleanup(shutil.rmtree, self.keys, True)

    def test_the_container_is_the_run_s_own_image_network_and_resolver(self):
        with mock.patch.object(target_image, "build") as build, \
                mock.patch.object(environment_gate, "SSHClient") as client:
            with environment_gate._gate_host(
                    self.product, environment_gate.CLEAN_CASE_ID, "clean") as host:
                pass
        build.assert_called_once_with(self.topology.podman, DISTRIBUTION)
        run = self.topology.podman.runs[0]
        self.assertEqual(run["name"], "gowave-gate-clean")
        self.assertEqual(run["image_alias"], target_image.tag(DISTRIBUTION))
        self.assertEqual(run["network"], NETWORK)
        self.assertIs(run["privileged"], True)
        self.assertEqual(run["systemd"], "always")
        self.assertEqual(
            run["extra_args"], ("--dns", DNS_IP, "--dns", EGRESS_RESOLVERS[0]))
        self.assertEqual(self.topology.podman.waits[0][0], "gowave-gate-clean")
        self.assertEqual(host.address, ADDRESS)
        self.assertEqual(host.distribution, DISTRIBUTION)
        client.assert_called_once()
        self.assertEqual(client.call_args.kwargs["port"], 22)
        self.assertEqual(client.call_args.kwargs["user"], "root")
        self.assertIs(client.call_args.kwargs["multiplex"], False)

    def test_the_runner_key_reaches_authorized_keys_over_stdin(self):
        with mock.patch.object(target_image, "build"), \
                mock.patch.object(environment_gate, "SSHClient"):
            with environment_gate._gate_host(
                    self.product, environment_gate.CLEAN_CASE_ID, "clean"):
                pass
        installs = [
            command for command in self.topology.podman.commands
            if command[1] == "exec_bash" and "authorized_keys" in command[2]
        ]
        self.assertEqual(len(installs), 1)
        self.assertTrue(installs[0][3].startswith("ssh-ed25519 "))
        self.assertEqual(installs[0][3].count("\n"), 1)

    def test_the_host_key_is_read_from_the_host_filesystem_and_pinned(self):
        with mock.patch.object(target_image, "build"), \
                mock.patch.object(environment_gate, "SSHClient") as client:
            with environment_gate._gate_host(
                    self.product, environment_gate.CLEAN_CASE_ID, "clean"):
                known_hosts = client.call_args.kwargs["known_hosts"]
                pinned = known_hosts.read_text(encoding="utf-8")
                mode = known_hosts.stat().st_mode & 0o777
        reads = [
            command for command in self.topology.podman.commands
            if command[1] == "exec" and command[2][:2] == ["cat", "/etc/ssh/ssh_host_ed25519_key.pub"]
        ]
        self.assertEqual(len(reads), 1)
        self.assertEqual(pinned, f"{ADDRESS} {HOST_KEY}\n")
        self.assertEqual(mode, 0o600)

    def test_the_container_is_removed_even_when_the_case_raises(self):
        with mock.patch.object(target_image, "build"), \
                mock.patch.object(environment_gate, "SSHClient"):
            with self.assertRaises(RuntimeError):
                with environment_gate._gate_host(
                        self.product, environment_gate.CLEAN_CASE_ID, "clean"):
                    raise RuntimeError("case blew up")
        removal = [command for command in self.topology.podman.commands
                   if command[0] == "_run"]
        self.assertEqual(removal, [("_run", ["rm", "-f", "gowave-gate-clean"], None, None)])

    def test_a_host_without_a_host_key_is_refused(self):
        self.topology.podman.exec = lambda *args, **kwargs: subprocess.CompletedProcess(
            [], 0, "", "")
        with mock.patch.object(target_image, "build"), \
                mock.patch.object(environment_gate, "SSHClient"):
            with self.assertRaises(AssertionError) as caught:
                with environment_gate._gate_host(
                        self.product, environment_gate.CLEAN_CASE_ID, "clean"):
                    pass
        self.assertIn("published no ed25519 host key", str(caught.exception))


class TestEnvironmentGateCases(unittest.TestCase):
    """Both cases hold over the modelled host, and their evidence derives."""

    def test_the_cases_hold_on_both_contours(self):
        for topology in TOPOLOGIES:
            for case_id in CASES:
                with self.subTest(case_id=case_id, topology=topology):
                    facts, refusal = run_case(case_id, topology)
                    self.assertIsNone(refusal)
                    self.assertTrue(facts)

    def test_the_evidence_is_exactly_what_the_catalog_records(self):
        registry = catalog.driver_registry()
        for case_id in CASES:
            facts, _ = run_case(case_id)
            with self.subTest(case_id=case_id):
                self.assertEqual(sorted(facts), registry[case_id]["aio"]["evidence"])

    def test_the_clean_case_records_the_manifest_the_run_would_store(self):
        facts, _ = run_case(environment_gate.CLEAN_CASE_ID)
        self.assertEqual(facts["distribution"], DISTRIBUTION)
        self.assertEqual(facts["address"], ADDRESS)
        self.assertEqual(facts["manifest_keys"], ",".join(environment_gate.MANIFEST_KEYS))
        self.assertEqual(facts["gate_disqualifications"], 0)
        self.assertEqual(facts["vision_gate_disqualifications"], 0)
        self.assertEqual(facts["preflight_status"], "PASS")
        self.assertTrue(facts["installation_proceeded"])
        self.assertTrue(facts["baseline_read_is_read_only"])
        self.assertEqual(facts["listening_ports"], "22")
        self.assertEqual(facts["occupied_required_ports"], "")

    def test_the_contaminated_case_records_four_refusals_in_order(self):
        facts, _ = run_case(environment_gate.CONTAMINATED_CASE_ID)
        self.assertEqual(facts["refusal_count"], 4)
        self.assertIn(environment_gate._DIRECTORY_CLAUSE, facts["directory_refusal"])
        self.assertIn(environment_gate._SERVICE_CLAUSE, facts["service_refusal"])
        self.assertIn(environment_gate._PORT_CLAUSE, facts["port_refusal"])
        self.assertIn(environment_gate._TOOL_CLAUSE, facts["tool_refusal"])
        self.assertEqual(facts["recorded_gate_errors"], 4)
        self.assertEqual(facts["preflight_status"], "FAIL")
        self.assertTrue(facts["contamination_preserved"])
        self.assertTrue(facts["baseline_read_is_read_only"])
        self.assertTrue(facts["halts_before_first_write"])


class TestEnvironmentGateDamage(unittest.TestCase):
    """Each clause is damaged on its own and the case refuses for that reason."""

    def assert_refused(self, case_id, damage):
        _, refusal = run_case(case_id, damage=damage)
        self.assertIsNotNone(refusal, f"{case_id} / {damage} did not make the case refuse")
        self.assertIn(EXPECTED_REFUSALS[(case_id, damage)], refusal)

    def test_a_baseline_read_that_changes_the_host_is_refused(self):
        self.assert_refused("ENV-01", "baseline-mutates")

    def test_a_host_that_already_listens_on_a_required_port_is_refused(self):
        self.assert_refused("ENV-01", "occupied-port")

    def test_a_manifest_that_contradicts_the_tools_the_case_installed_is_refused(self):
        self.assert_refused("ENV-01", "tools-missing")

    def test_an_empty_listener_table_is_refused_rather_than_read_as_absent(self):
        self.assert_refused("ENV-01", "no-listeners")

    def test_a_manifest_missing_one_promised_key_is_refused(self):
        self.assert_refused("ENV-01", "manifest-short")

    def test_a_preflight_that_fails_a_clean_host_is_refused(self):
        self.assert_refused("ENV-01", "preflight-fails")

    def test_a_run_whose_install_did_not_succeed_is_refused(self):
        self.assert_refused("ENV-01", "install-failed")

    def test_an_image_that_already_runs_a_gowave_service_is_refused(self):
        self.assert_refused("ENV-01", "services-running")

    def test_an_image_that_already_carries_gowave_directories_is_refused(self):
        self.assert_refused("ENV-01", "image-has-directories")

    def test_a_gate_that_refuses_a_clean_host_is_refused(self):
        self.assert_refused("ENV-01", "gate-refuses-clean")

    def test_a_gate_that_refuses_a_clean_host_for_its_vision_ports_is_refused(self):
        self.assert_refused("ENV-01", "vision-gate-refuses")

    def test_a_verdict_that_does_not_carry_the_manifest_is_refused(self):
        self.assert_refused("ENV-01", "verdict-loses-the-manifest")

    def test_a_gate_that_accepts_a_contaminated_host_is_refused(self):
        self.assert_refused("ENV-02", "gate-accepts")

    def test_a_runner_that_writes_before_it_refuses_is_refused(self):
        self.assert_refused("ENV-02", "order-inverted")

    def test_a_preflight_that_passes_a_contaminated_host_is_refused(self):
        self.assert_refused("ENV-02", "eligibility-passes")

    def test_a_refused_run_that_changed_the_objects_it_refused_for_is_refused(self):
        self.assert_refused("ENV-02", "refusal-repairs")

    def test_a_verdict_that_records_a_reason_the_gate_did_not_produce_is_refused(self):
        self.assert_refused("ENV-02", "gate-errors-dropped")

    def test_a_gate_that_reports_only_its_newest_reason_is_refused(self):
        self.assert_refused("ENV-02", "refusal-not-cumulative")

    def test_a_control_read_that_is_refused_is_refused(self):
        self.assert_refused("ENV-02", "control-refused")

    def test_a_control_read_that_changes_the_host_is_refused(self):
        self.assert_refused("ENV-02", "control-mutates")

    def test_a_rejected_verdict_that_does_not_carry_the_manifest_is_refused(self):
        self.assert_refused("ENV-02", "verdict-loses-the-manifest")


if __name__ == "__main__":
    unittest.main()
