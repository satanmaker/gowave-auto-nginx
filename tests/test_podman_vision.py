"""Suite nonroot: Vision's two policy cases, and the endpoint arithmetic they feed.

`tools/podman_e2e/vision.py` decides two sentences before anything is contacted —
which Vision combinations the configuration accepts, and which host owes the
Vision ports — and reads the endpoint total a cluster declares beside them. Each
guard is proven here by damaging exactly what it reads: a parser that stops
refusing a duplicate, a runner that accepts one, a gate that pairs the ports with
the wrong host or drops them from the default set, and a cluster whose counts
disagree with its own nodes. A guard that cannot be shown to fail on its own
damage is not a guard.
"""
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools import test_live_vps  # noqa: E402
from tools.podman_e2e import vision  # noqa: E402
from tools.podman_e2e.runner import RunContext  # noqa: E402

VISION_PORTS = {8444, 9444}


def context(topology: str = "aio") -> RunContext:
    return RunContext(
        topology,
        REPO_ROOT / "artifacts" / "unit" / "vision",
        budget_seconds=120,
        run_id=f"podman-{topology}-vision-00000000",
    )


def ports(manifest) -> set:
    return set(manifest.get("listening_ports") or [])


def failure(callable_) -> str:
    """The message a damaged case fails with; a failure if it accepted the damage."""
    try:
        callable_()
    except AssertionError as error:
        return str(error)
    raise AssertionError("the case accepted the damage and reported nothing")


def assert_guard(message: str, fragment: str) -> None:
    """The damage has to trip the guard it was aimed at, not an earlier one."""
    if fragment not in message:
        raise AssertionError(
            f"the case failed on a different guard than the one this damage targets: {message}"
        )


class TestVisionConfigCase(unittest.TestCase):
    """`VIS-CONFIG` reads the whitelist parser, so the parser is what gets damaged."""

    def test_the_four_combinations_are_accepted_and_restated(self):
        evidence = vision.case_config_contract(context())
        self.assertEqual(evidence["combinations"], 4)
        self.assertEqual(evidence["master_only_vision"], vision.MASTER_VISION_DOMAIN)
        self.assertEqual(evidence["worker_only_vision"], vision.WORKER_VISION_DOMAIN)
        self.assertEqual(evidence["neither_master_vision"], "absent")
        self.assertEqual(evidence["duplicate_classes"], 8)
        self.assertEqual(evidence["runner_returncode"], 1)
        self.assertIn("Config parse error", evidence["runner_message"])

    def test_the_field_clause_fails_when_the_parser_drops_a_domain(self):
        dropped = SimpleNamespace(master_vision_domain=None, worker_vision_domain=None)
        with mock.patch.object(vision, "load_config", lambda path: dropped):
            message = failure(lambda: vision.case_config_contract(context()))
        assert_guard(message, "the master-only configuration parsed MASTER_VISION_DOMAIN")

    def test_the_duplicate_clause_fails_when_the_parser_accepts_a_duplicate(self):
        def permissive(path: Path):
            values = dict(
                line.split("=", 1)
                for line in Path(path).read_text(encoding="utf-8").splitlines()
                if "=" in line
            )
            return SimpleNamespace(
                master_vision_domain=values.get("MASTER_VISION_DOMAIN"),
                worker_vision_domain=values.get("WORKER_VISION_DOMAIN"),
            )

        with mock.patch.object(vision, "load_config", permissive):
            message = failure(lambda: vision.case_config_contract(context()))
        assert_guard(message, "was accepted by the whitelist parser")

    def test_the_runner_clause_fails_when_the_runner_exits_zero(self):
        accepted = SimpleNamespace(returncode=0, stdout="", stderr="")
        with mock.patch.object(vision.subprocess, "run", lambda *a, **k: accepted):
            message = failure(lambda: vision.case_config_contract(context()))
        assert_guard(message, "accepted a duplicate Vision domain and exited 0")

    def test_the_run_directory_clause_fails_when_a_run_directory_appears(self):
        run_id = vision.RUN_ID.format(topology="aio")
        directory = REPO_ROOT / "artifacts" / "live-vps" / run_id
        self.addCleanup(lambda: directory.is_dir() and directory.rmdir())

        def creates(path, *a, **k):
            directory.mkdir(parents=True, exist_ok=True)
            return SimpleNamespace(returncode=1, stdout="", stderr="Config parse error: duplicate")

        with mock.patch.object(vision.subprocess, "run", creates):
            message = failure(lambda: vision.case_config_contract(context()))
        assert_guard(message, "for a configuration it refused")


class TestVisionGateCase(unittest.TestCase):
    """`VIS-GATE` reads the runner's own eligibility decision, one manifest per host."""

    def run_with(self, transform) -> dict:
        real = test_live_vps.evaluate_preflight_eligibility

        def fake(config, **kwargs):
            return transform(real(config, **kwargs), config, kwargs)

        with mock.patch.object(test_live_vps, "evaluate_preflight_eligibility", fake):
            return vision.case_port_gate(context("multi-node"))

    def failure_with(self, transform) -> str:
        return failure(lambda: self.run_with(transform))

    def test_the_four_combinations_pair_the_gate_with_the_host(self):
        evidence = vision.case_port_gate(context())
        self.assertEqual(evidence["combinations"], 4)
        self.assertFalse(evidence["master_only_master_gate"])
        self.assertTrue(evidence["master_only_worker_gate"])
        self.assertTrue(evidence["worker_only_master_gate"])
        self.assertFalse(evidence["worker_only_worker_gate"])
        self.assertEqual(evidence["both_gates"], "False/False")
        self.assertEqual(evidence["neither_gates"], "True/True")
        self.assertEqual(evidence["master_only_status"], "FAIL")
        self.assertEqual(evidence["unowed_vision_ports_status"], "PASS")
        self.assertEqual(evidence["default_port_status"], "FAIL")

    def test_the_configured_host_clause_fails_when_the_ports_are_never_required(self):
        def accepts_everything(verdict, config, kwargs):
            verdict.update(
                master_gate_ok=True, worker_gate_ok=True, master_gate_errors=[],
                worker_gate_errors=[], status="PASS",
            )
            return verdict

        assert_guard(
            self.failure_with(accepts_everything),
            "while its own Vision domain is configured and the disposable gate accepted it",
        )

    def test_the_unconfigured_host_clause_fails_when_the_set_is_widened_to_the_run(self):
        def widened(verdict, config, kwargs):
            if ports(kwargs["worker_baseline"]) & VISION_PORTS and (
                config.master_vision_domain or config.worker_vision_domain
            ):
                verdict["worker_gate_ok"] = False
                verdict["worker_gate_errors"] = ["port 8444 is in use"]
                verdict["status"] = "FAIL"
            return verdict

        assert_guard(
            self.failure_with(widened),
            "the Worker owes no Vision ports, but the gate refused it",
        )

    def test_the_worker_clause_fails_when_only_the_master_is_consulted(self):
        def master_only(verdict, config, kwargs):
            verdict["worker_gate_ok"] = True
            verdict["worker_gate_errors"] = []
            verdict["status"] = "PASS" if verdict["master_gate_ok"] else "FAIL"
            return verdict

        assert_guard(
            self.failure_with(master_only),
            "the Worker holds 8444 and 9444 while its own Vision domain is configured",
        )

    def test_the_exempt_master_clause_fails_when_the_master_is_always_held(self):
        def always_held(verdict, config, kwargs):
            if ports(kwargs["master_baseline"]) & VISION_PORTS:
                verdict["master_gate_ok"] = False
                verdict["master_gate_errors"] = ["port 8444 is in use"]
                verdict["status"] = "FAIL"
            return verdict

        assert_guard(
            self.failure_with(always_held),
            "the Master owes no Vision ports, but the gate refused it",
        )

    def test_the_disabled_clause_fails_when_the_ports_are_demanded_while_off(self):
        def demands_when_off(verdict, config, kwargs):
            if not config.master_vision_domain and not config.worker_vision_domain:
                for host, key in (("master_baseline", "master"), ("worker_baseline", "worker")):
                    if ports(kwargs[host]) & VISION_PORTS:
                        verdict[f"{key}_gate_ok"] = False
                        verdict[f"{key}_gate_errors"] = ["port 8444 is in use"]
                        verdict["status"] = "FAIL"
            return verdict

        assert_guard(
            self.failure_with(demands_when_off),
            "no Vision domain is configured and the gate still demanded the Vision ports",
        )

    def test_the_port_naming_clause_fails_when_the_refusal_names_no_port(self):
        def unnamed(verdict, config, kwargs):
            for key in ("master", "worker"):
                if verdict[f"{key}_gate_ok"] is False:
                    verdict[f"{key}_gate_errors"] = ["a required port is in use"]
            return verdict

        assert_guard(
            self.failure_with(unnamed),
            "refusal does not name port 8444",
        )

    def test_the_status_clause_fails_when_a_refused_gate_reports_pass(self):
        def always_pass(verdict, config, kwargs):
            verdict["status"] = "PASS"
            return verdict

        assert_guard(
            self.failure_with(always_pass),
            "reported 'PASS' rather than FAIL",
        )

    def test_the_sharp_clause_fails_when_the_gate_reads_the_neighbours_manifest(self):
        def neighbour(verdict, config, kwargs):
            if config.master_vision_domain and not ports(kwargs["master_baseline"]) & VISION_PORTS:
                if ports(kwargs["worker_baseline"]) & VISION_PORTS:
                    verdict["worker_gate_ok"] = False
                    verdict["worker_gate_errors"] = ["port 8444 is in use"]
                    verdict["status"] = "FAIL"
            return verdict

        assert_guard(
            self.failure_with(neighbour),
            "the port set was widened to a host that owes nothing",
        )

    def test_the_default_set_clause_fails_when_the_exempt_host_is_exempt_from_all(self):
        def exempt(verdict, config, kwargs):
            if not config.worker_vision_domain:
                verdict["worker_gate_ok"] = True
                verdict["worker_gate_errors"] = []
            if not config.master_vision_domain:
                verdict["master_gate_ok"] = True
                verdict["master_gate_errors"] = []
            verdict["status"] = (
                "PASS" if verdict["master_gate_ok"] and verdict["worker_gate_ok"] else "FAIL"
            )
            return verdict

        assert_guard(
            self.failure_with(exempt),
            "the gate accepted it: a host exempt from the Vision ports is not exempt",
        )


def cluster(master: int, worker: int = 0, *, hosts_for_master=None, extra_hosts=()) -> dict:
    """A Panel cluster whose node and host records carry the counts asked for."""
    records = [{
        "name": "local-node", "uuid": "master-uuid",
        "inbounds": [f"master-{index}" for index in range(master)],
    }]
    hosts = [{"inbound": f"master-{index}", "nodes": ["master-uuid"]} for index in range(master)]
    if worker:
        records.append({
            "name": "worker-1", "uuid": "worker-uuid",
            "inbounds": [f"worker-{index}" for index in range(worker)],
        })
        hosts += [{"inbound": f"worker-{index}", "nodes": ["worker-uuid"]} for index in range(worker)]
    if hosts_for_master is not None:
        hosts = [host for host in hosts if host["nodes"] != ["master-uuid"]]
        hosts = list(hosts_for_master) + hosts
    hosts = list(hosts) + list(extra_hosts)
    return {
        "nodes": {"status": 200, "records": records},
        "hosts": {"status": 200, "records": hosts},
    }


MASTER = ("master", "local-node", 5)
WORKER = ("worker", "worker-1", 4)


class TestEndpointContract(unittest.TestCase):
    """The endpoint total a combination owes, read from the Panel's own records."""

    def test_the_envelope_clause_fails_when_the_probe_reports_no_cluster(self):
        # The probe prints its report under a `cluster` key beside the login it
        # used; a case that read node records from the envelope would find none
        # and call a cluster empty, so the envelope itself is refused by name.
        message = failure(
            lambda: vision.cluster_document("NGX-04", {"login": {"status": 200}})
        )
        assert_guard(message, "returned no cluster structure")

    def test_a_cluster_that_declares_the_combination_passes(self):
        evidence = vision.endpoint_contract(
            "NGX-04", cluster(5, 4), (MASTER, WORKER), 2, 18,
        )
        self.assertEqual(evidence["master_inbounds"], 5)
        self.assertEqual(evidence["master_hosts"], 5)
        self.assertEqual(evidence["worker_inbounds"], 4)
        self.assertEqual(evidence["worker_hosts"], 4)
        self.assertEqual(evidence["endpoints"], 9)
        self.assertEqual(evidence["runtime_cases"], 18)

    def test_a_single_node_cluster_is_read_without_a_name(self):
        evidence = vision.endpoint_contract(
            "NGX-04", cluster(5), (("master", None, 5),), 2, 10,
        )
        self.assertEqual(evidence["endpoints"], 5)

    def test_the_node_read_fails_when_the_api_refuses(self):
        broken = cluster(5)
        broken["nodes"]["status"] = 502
        message = failure(
            lambda: vision.endpoint_contract("NGX-04", broken, (("master", None, 5),), 2, 10)
        )
        assert_guard(message, "GET /api/nodes returned 502")

    def test_the_name_clause_fails_when_the_node_is_not_there(self):
        misnamed = cluster(5)
        misnamed["nodes"]["records"][0]["name"] = "some-other-node"
        message = failure(
            lambda: vision.endpoint_contract("NGX-04", misnamed, (MASTER,), 2, 10)
        )
        assert_guard(message, "the Panel reports no node 'local-node'")

    def test_the_inbound_count_fails_when_a_node_carries_the_wrong_number(self):
        message = failure(
            lambda: vision.endpoint_contract(
                "NGX-04", cluster(5, 5), (MASTER, WORKER), 2, 18,
            )
        )
        assert_guard(message, "worker runs 5 inbounds, expected 4")

    def test_the_host_count_fails_when_an_inbound_publishes_no_host(self):
        short = cluster(5, hosts_for_master=[
            {"inbound": f"master-{index}", "nodes": ["master-uuid"]} for index in range(4)
        ])
        message = failure(
            lambda: vision.endpoint_contract("NGX-04", short, (MASTER,), 2, 10)
        )
        assert_guard(message, "master publishes 4 hosts, expected one per inbound (5)")

    def test_the_stray_clause_fails_when_a_host_names_an_inbound_the_node_lacks(self):
        strayed = cluster(5, extra_hosts=(
            {"inbound": "someone-else", "nodes": ["master-uuid"]},
        ))
        strayed["hosts"]["records"] = [
            host for host in strayed["hosts"]["records"] if host["inbound"] != "master-4"
        ]
        message = failure(
            lambda: vision.endpoint_contract("NGX-04", strayed, (MASTER,), 2, 10)
        )
        assert_guard(message, "publish an inbound the node does not run")

    def test_the_total_clause_fails_when_the_two_nodes_disagree(self):
        message = failure(
            lambda: vision.endpoint_contract(
                "NGX-04", cluster(5, 4), (MASTER, WORKER), 2, 17,
            )
        )
        assert_guard(message, "which do not multiply to it")


if __name__ == "__main__":
    unittest.main()
