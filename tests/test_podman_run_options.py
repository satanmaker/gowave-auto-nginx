#!/usr/bin/env python3
"""Suite nonroot: the compact summary and the run's case-selection options.

Three things are held here, each read from the side the claim is about. The
summary is read out of the artifact directory a real ``Runner`` wrote, not from
the payload the writer was handed. ``--only`` is read from the ids that reached
the runner and from the exit status an unknown id produces, not from the parser's
help. ``--reuse`` is read from the setup record a real topology wrote, from the
refusal each missing resource produces, and from the artifact an adopted run
leaves: the flag exists to avoid an install, so a refusal that costs no container
and an adoption that records the run it borrowed are the two things asserted —
a fallback to a fresh install is the defect these tests keep out.
"""
import contextlib
import io
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools import run_podman_e2e  # noqa: E402
from tools.podman_e2e import (  # noqa: E402
    acme_fixture, run_setup, target_image, topology,
)
from tools.podman_e2e.runner import (  # noqa: E402
    BLOCKED,
    FAIL,
    INCOMPLETE,
    PASS,
    SUMMARY_MESSAGE_LIMIT,
    Case,
    CaseBlocked,
    RunContext,
    Runner,
    write_summary,
)

PASSWORD = "SuperSecretPassword12345"
PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class RecordingPodman:
    """A ``Podman`` stand-in that records the calls the entrypoint makes on it."""

    instances: list = []

    def __init__(self, context):
        self.context = context
        self.calls = []
        RecordingPodman.instances.append(self)

    def remove_stale_runs(self):
        self.calls.append("remove_stale_runs")
        return []

    def register_cleanup(self):
        self.calls.append("register_cleanup")


class RecordingRunner:
    """A ``Runner`` stand-in that records the cases handed to it."""

    instances: list = []

    def __init__(self, context):
        self.context = context
        self.added = []
        self.executed_any = False
        RecordingRunner.instances.append(self)

    def require_group(self, group):
        pass

    def add(self, case):
        self.added.append(case.id)

    def on_failure(self, hook):
        pass

    def execute(self):
        self.executed_any = True
        return 0


class RunPodman:
    """A Podman stand-in rich enough for ``AioTopology.create`` to run for real.

    The record a kept run writes is only worth testing against a creation that
    actually performed the steps, so this answers the same calls the real object
    does and invents nothing: every container, network and volume the topology
    asks for is recorded, and no address is made up by the double.
    """

    def __init__(self, context: RunContext) -> None:
        self.context = context
        self.networks = []
        self.runs = []
        self.connects = []
        self.builds = []
        self.execs = []

    def network_subnets(self):
        return []

    def network_create(self, name, subnet=None, disable_dns=False, internal=False):
        self.networks.append((name, subnet, disable_dns, internal))
        return name

    def network_connect(self, name, network, ip=None):
        self.connects.append((name, network, ip))
        return name

    def volume_create(self, name):
        return name

    def volume_mountpoint(self, name):
        mountpoint = self.context.secret_dir / "volumes" / name
        mountpoint.mkdir(parents=True, exist_ok=True)
        return mountpoint

    def run(self, **kwargs):
        self.runs.append(kwargs)
        return kwargs["name"]

    def build(self, tag, base_alias, containerfile, context_dir, build_args=None):
        self.builds.append(tag)
        return tag

    def wait_tcp(self, name, host, port, timeout_seconds=60):
        return None

    def wait_systemd(self, name, timeout_seconds=90):
        return "running"

    def exec(self, name, argv, check=True, input_text=None, timeout=300):
        import subprocess

        self.execs.append((name, list(argv)))
        if len(argv) == 3 and argv[2] == target_image.cleanliness_probe():
            return subprocess.CompletedProcess(
                argv, 0, "init=systemd\nsystemd=systemd 255\nsshd=active\n", ""
            )
        if list(argv) == ["cat", "/proc/net/if_inet6"]:
            import ipaddress

            address = ipaddress.ip_address(topology.IPV6_HOST_ADDRESS).exploded.replace(":", "")
            return subprocess.CompletedProcess(argv, 0, f"{address} 02 80 00 00 00     lo\n", "")
        raise AssertionError(f"unexpected exec: {argv}")

    def exec_bash(self, name, script, check=True, input_text=None, timeout=300):
        import subprocess

        self.execs.append((name, ["bash", "-lc", script]))
        return subprocess.CompletedProcess(["bash", "-lc", script], 0, "", "")

    def _run(self, args, check=True, input_text=None, timeout=300):
        """The private entry point ``AcmeFixture.stop`` reaches for during cleanup."""
        import subprocess

        return subprocess.CompletedProcess(list(args), 0, "", "")


class AdoptingPodman:
    """The minimum an adoption needs: a context, and a refusal if it provisions.

    Adoption rebuilds its topology from the record. Any call that would allocate,
    create or start is a failure, so the double raises instead of recording: a
    test that passes proves the path never made one.
    """

    def __init__(self, context: RunContext) -> None:
        self.context = context

    def network_subnets(self):
        raise AssertionError("adoption allocated a subnet")

    def network_create(self, *args, **kwargs):
        raise AssertionError("adoption created a network")

    def run(self, **kwargs):
        raise AssertionError("adoption started a container")


def create_kept_topology(
    root: Path,
    run_id: str,
    distribution: str = "debian-13",
    kind: str = "aio",
) -> tuple:
    """Create a real topology under ``root/<run_id>`` and return it with its Podman."""
    context = RunContext(kind, root, budget_seconds=60, run_id=run_id, distribution=distribution)
    podman = RunPodman(context)
    settings = dict(
        distribution=distribution,
        egress_resolvers=["192.0.2.53"],
        plan=topology.NetworkPlan("10.89.0.0/24", "203.0.114.0/24"),
    )
    if kind == "aio":
        host = topology.AioTopology(podman, **settings)
    else:
        host = topology.MultiNodeTopology(podman, **settings)
    with mock.patch.object(topology, "NETWORK_RESERVATION_LOCK", root / "networks.lock"), \
            mock.patch.object(acme_fixture.AcmeFixture, "issued_root", return_value=PEM), \
            mock.patch.object(acme_fixture.AcmeFixture, "wait_ready", return_value=None):
        host.create()
    return host, podman


def container_entries(host) -> list:
    """The containers the run started, each reported running, as Podman would list them.

    A role the run never started is deliberately absent: the engine client is
    started on demand, so a kept cell that never needed it has no such container
    and is still adoptable.
    """
    record = run_setup.read_setup(host.context.artifact_dir)
    started = set(record["started"])
    names = [record["containers"][role] for role in (
        "dns", "target", "echo", "client", "engine_client", "acme",
    )]
    return [
        {"name": name, "state": "running"} for name in names
        if name and name in started
    ]


class TestSummaryArtifact(unittest.TestCase):
    """``summary.json`` is the compact account a person or an agent reads first."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def context(self, **kwargs) -> RunContext:
        return RunContext(
            "aio", self.root, budget_seconds=60,
            run_id="podman-aio-options-abcdef12", **kwargs,
        )

    def summary(self, context: RunContext) -> dict:
        return read_json(context.artifact_dir / "summary.json")

    def test_it_sits_beside_the_result_and_is_world_readable(self):
        # The summary is what someone reads without root: a 0600 file would hide
        # the one artifact an unprivileged operator can use.
        context = self.context(distribution="debian-13")
        runner = Runner(context)
        runner.add(Case("AIO-ONE", "aio", lambda ctx: {"note": "ok"}))
        self.assertEqual(runner.execute(), 0)

        summary_path = context.artifact_dir / "summary.json"
        self.assertTrue((context.artifact_dir / "result.json").is_file())
        self.assertEqual(summary_path.stat().st_mode & 0o777, 0o644)
        self.assertEqual((context.artifact_dir / "result.json").stat().st_mode & 0o777, 0o600)

        summary = self.summary(context)
        self.assertEqual(summary["run_id"], context.run_id)
        self.assertEqual(summary["topology"], "aio")
        self.assertEqual(summary["distribution"], "debian-13")
        self.assertEqual(summary["overall"], PASS)
        self.assertEqual(summary["counts"], {PASS: 1})
        self.assertEqual(summary["executed"], ["AIO-ONE"])
        self.assertFalse(summary["reused"])
        self.assertEqual(summary["cases"], [])

    def test_it_lists_one_entry_per_non_pass_case_in_run_order(self):
        context = self.context()

        def failing(ctx):
            raise AssertionError("AIO-FAIL: the panel route answered 502")

        def blocked(ctx):
            raise CaseBlocked("AIO-BLOCKED: no certificate was issued")

        runner = Runner(context)
        runner.add(Case("AIO-PASS", "aio", lambda ctx: {}))
        runner.add(Case("AIO-FAIL", "aio", failing))
        runner.add(Case("AIO-BLOCKED", "aio", blocked))
        self.assertEqual(runner.execute(), 1)

        summary = self.summary(context)
        self.assertEqual(summary["overall"], FAIL)
        self.assertEqual(summary["counts"], {BLOCKED: 1, FAIL: 1, PASS: 1})
        self.assertEqual(
            [case["id"] for case in summary["cases"]], ["AIO-FAIL", "AIO-BLOCKED"],
        )
        self.assertEqual([case["status"] for case in summary["cases"]], [FAIL, BLOCKED])
        self.assertIn("answered 502", summary["cases"][0]["message"])
        self.assertIn("no certificate", summary["cases"][1]["message"])

    def test_a_long_message_is_bounded_while_the_result_keeps_it_whole(self):
        context = self.context()

        def failing(ctx):
            raise AssertionError("AIO-FAIL: " + "x" * (SUMMARY_MESSAGE_LIMIT * 2))

        runner = Runner(context)
        runner.add(Case("AIO-FAIL", "aio", failing))
        runner.execute()

        summary = self.summary(context)
        self.assertEqual(len(summary["cases"][0]["message"]), SUMMARY_MESSAGE_LIMIT)
        full = read_json(context.artifact_dir / "result.json")["cases"][0]["message"]
        self.assertEqual(len(full), len("AIO-FAIL: ") + SUMMARY_MESSAGE_LIMIT * 2)

    def test_a_case_the_deadline_left_unrun_is_not_reported_as_executed(self):
        # Both cases end up INCOMPLETE and only one of them ran. The summary has
        # to tell those apart, or a truncated run looks like a run that decided
        # nothing about every case.
        context = self.context()
        context.budget_seconds = 1
        runner = Runner(context)
        runner.add(Case("AIO-SLOW", "aio", lambda ctx: time.sleep(5), timeout_seconds=30))
        runner.add(Case("AIO-NEVER", "aio", lambda ctx: None))
        self.assertEqual(runner.execute(), 1)

        summary = self.summary(context)
        self.assertEqual(summary["executed"], ["AIO-SLOW"])
        self.assertEqual(summary["counts"], {INCOMPLETE: 2})
        self.assertEqual([case["id"] for case in summary["cases"]], ["AIO-SLOW", "AIO-NEVER"])
        self.assertIn("before the case ran", summary["cases"][1]["message"])

    def test_a_reused_run_says_which_run_it_borrowed_its_hosts_from(self):
        context = self.context(reused_from="podman-aio-earlier-12345678")
        runner = Runner(context)
        runner.add(Case("AIO-05", "aio", lambda ctx: {}))
        self.assertEqual(runner.execute(), 0)

        summary = self.summary(context)
        self.assertTrue(summary["reused"])
        self.assertEqual(summary["reused_from"], "podman-aio-earlier-12345678")
        result = read_json(context.artifact_dir / "result.json")
        self.assertTrue(result["reused"])
        self.assertEqual(result["reused_from"], "podman-aio-earlier-12345678")

    def test_an_ordinary_run_records_that_it_borrowed_nothing(self):
        # Both artifacts answer the same question the same way: a reader that
        # looks for ``reused`` must not have to treat an absent key as "no".
        context = self.context()
        runner = Runner(context)
        runner.add(Case("AIO-ONE", "aio", lambda ctx: {}))
        self.assertEqual(runner.execute(), 0)

        self.assertFalse(self.summary(context)["reused"])
        result = read_json(context.artifact_dir / "result.json")
        self.assertFalse(result["reused"])
        self.assertIsNone(result["reused_from"])

    def test_a_run_without_a_distribution_does_not_invent_one(self):
        context = self.context()
        runner = Runner(context)
        runner.add(Case("AIO-ONE", "aio", lambda ctx: {}))
        self.assertEqual(runner.execute(), 0)
        self.assertNotIn("distribution", self.summary(context))

    def test_the_summary_is_redacted_and_reads_back_as_json(self):
        context = self.context()
        context.write_secret("admin-password", PASSWORD)
        runner = Runner(context)
        runner.add(Case(
            "AIO-AUTH", "aio",
            lambda ctx: (_ for _ in ()).throw(AssertionError(f"login failed with {PASSWORD}")),
        ))
        self.assertEqual(runner.execute(), 1)

        text = (context.artifact_dir / "summary.json").read_text(encoding="utf-8")
        self.assertNotIn(PASSWORD, text)
        summary = json.loads(text)
        self.assertIn("[REDACTED]", summary["cases"][0]["message"])

    def test_a_red_verdict_reaches_the_summary_written_last(self):
        # The verdict is written twice: once before the redaction audit and once
        # after it. What an offence adds must land in the summary the operator
        # reads, not only in the full record.
        context = self.context()
        context.write_secret("admin-password", PASSWORD)

        def leaky(ctx):
            (ctx.artifact_dir / "leak.txt").write_text(f"password={PASSWORD}\n")
            return {}

        runner = Runner(context)
        runner.add(Case("AIO-LEAKY", "aio", leaky))
        self.assertEqual(runner.execute(), 1)

        summary = self.summary(context)
        self.assertEqual(summary["overall"], FAIL)
        self.assertIn("REDACTION", [case["id"] for case in summary["cases"]])

    def test_a_payload_without_the_run_keys_still_yields_a_summary(self):
        # A report a probe builds by hand carries neither ``executed`` nor
        # ``reused_from``; the writer must not invent a selection from that.
        data = {
            "run_id": "podman-aio-handmade-00000000",
            "topology": "aio",
            "overall": PASS,
            "cases": [{"id": "AIO-ONE", "status": PASS, "message": ""}],
        }
        path = write_summary(self.root, data)
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)
        summary = read_json(path)
        self.assertEqual(summary["executed"], [])
        self.assertFalse(summary["reused"])
        self.assertEqual(summary["counts"], {PASS: 1})


class TestOnlySelection(unittest.TestCase):
    """``--only`` is the suite's declared order, narrowed to the named ids."""

    def suite(self):
        return [
            Case("AIO-INSTALL", "aio", lambda ctx: {}),
            Case("AIO-05", "aio", lambda ctx: {}),
            Case("AIO-04", "aio", lambda ctx: {}),
        ]

    def test_the_declared_order_wins_over_the_typed_order(self):
        selected = run_podman_e2e.select_cases(self.suite(), ["AIO-04", "AIO-INSTALL"])
        self.assertEqual([case.id for case in selected], ["AIO-INSTALL", "AIO-04"])

    def test_no_selection_is_the_whole_declared_suite(self):
        selected = run_podman_e2e.select_cases(self.suite(), None)
        self.assertEqual([case.id for case in selected], ["AIO-INSTALL", "AIO-05", "AIO-04"])

    def test_a_repeated_id_selects_once(self):
        selected = run_podman_e2e.select_cases(self.suite(), ["AIO-05", "AIO-05"])
        self.assertEqual([case.id for case in selected], ["AIO-05"])

    def test_an_unknown_id_is_named_in_the_refusal(self):
        with self.assertRaises(run_podman_e2e.CaseSelectionError) as caught:
            run_podman_e2e.select_cases(self.suite(), ["AIO-05", "AIO-NOPE"])
        self.assertIn("AIO-NOPE", str(caught.exception))
        self.assertIn("does not declare", str(caught.exception))

    def test_an_empty_selection_is_refused_rather_than_widened(self):
        with self.assertRaises(run_podman_e2e.CaseSelectionError) as caught:
            run_podman_e2e.select_cases(self.suite(), [])
        self.assertIn("no case", str(caught.exception))


class EntrypointCase:
    """Drive ``main`` with the suite, Podman and the runner replaced by recorders.

    A mixin rather than a ``TestCase``: it has no test of its own, and a test
    class without test methods fails the repository's completeness check.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cases = [
            Case("AIO-INSTALL", "aio", lambda ctx: {}),
            Case("AIO-05", "aio", lambda ctx: {}),
            Case("AIO-04", "aio", lambda ctx: {}),
        ]
        self.podmen = []
        self.runners = []

    def patchers(self, suite=None, containers=None, runner=True):
        podmen, runners = self.podmen, self.runners
        suite_cases = list(self.cases if suite is None else suite)

        RecordingPodman.instances = podmen
        RecordingRunner.instances = runners

        patchers = [
            mock.patch.object(run_podman_e2e, "Podman", RecordingPodman),
            mock.patch.object(run_podman_e2e, "build_suite", lambda *a, **k: list(suite_cases)),
            # The catalog is a separate artifact and has no row for a synthetic
            # id; the disagreement it guards is not what these tests are about.
            mock.patch.object(run_podman_e2e.catalog, "require_executable", lambda cases: None),
        ]
        if runner:
            patchers.append(mock.patch.object(run_podman_e2e, "Runner", RecordingRunner))
        if containers is not None:
            patchers.append(mock.patch.object(
                run_podman_e2e, "kept_containers", lambda run_id, run=None: list(containers),
            ))
        return patchers

    def _invoke(self, argv, suite, containers):
        patchers = self.patchers(suite, containers)
        for patcher in patchers:
            patcher.start()
        try:
            return run_podman_e2e.main([*argv, "--artifact-root", str(self.root)])
        finally:
            for patcher in reversed(patchers):
                patcher.stop()

    def run_main(self, argv, suite=None, containers=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = self._invoke(argv, suite, containers)
        return status, stdout.getvalue(), stderr.getvalue()

    def run_main_expecting_exit_2(self, argv, suite=None, containers=None):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                self._invoke(argv, suite, containers)
        self.assertEqual(caught.exception.code, 2)
        return stderr.getvalue()


class TestOnlyFromTheCommandLine(EntrypointCase, unittest.TestCase):
    """An unknown id costs an argument error, never an install."""

    def test_an_unknown_id_exits_2_and_names_it(self):
        message = self.run_main_expecting_exit_2(["--only", "AIO-05,AIO-NOPE"])
        self.assertIn("AIO-NOPE", message)
        self.assertIn("AIO-INSTALL", message)
        # No case is handed to the runner and nothing is executed: the runner
        # object itself exists because the suite needs the context to be built.
        self.assertEqual([runner.added for runner in self.runners], [[]])
        self.assertFalse(any(runner.executed_any for runner in self.runners))
        for podman in self.podmen:
            self.assertEqual(podman.calls, [], "a refused selection may not touch the host")
        self.assertEqual(list(self.root.iterdir()), [], "an argument error leaves no run behind")

    def test_an_empty_selection_exits_2(self):
        message = self.run_main_expecting_exit_2(["--only", ","])
        self.assertIn("no case", message)
        self.assertFalse(any(runner.executed_any for runner in self.runners))

    def test_an_empty_selection_is_refused_before_a_matrix_starts_four_runs(self):
        message = self.run_main_expecting_exit_2(["--only", ",", "--all-distributions"])
        self.assertIn("no case", message)
        self.assertFalse(self.podmen, "the matrix must not be started to learn this")

    def test_the_selected_cases_reach_the_runner_in_the_declared_order(self):
        status, _out, _err = self.run_main(["--only", "AIO-04,AIO-INSTALL"])
        self.assertEqual(status, 0)
        self.assertEqual(len(self.runners), 1)
        runner = self.runners[0]
        self.assertEqual(runner.added, ["AIO-INSTALL", "AIO-04"])
        self.assertTrue(runner.executed_any)

    def test_without_the_flag_the_whole_suite_is_added(self):
        status, _out, _err = self.run_main([])
        self.assertEqual(status, 0)
        self.assertEqual(
            self.runners[0].added, ["AIO-INSTALL", "AIO-05", "AIO-04"],
        )

    def test_the_run_records_the_distribution_it_installs(self):
        status, _out, _err = self.run_main(["--distribution", "ubuntu-24.04"])
        self.assertEqual(status, 0)
        self.assertEqual(self.podmen[0].context.distribution, "ubuntu-24.04")


class TestKeepFromTheCommandLine(EntrypointCase, unittest.TestCase):
    """``--keep`` leaves the hosts and says which run id names them."""

    def test_keep_does_not_register_the_cleanup(self):
        status, _out, _err = self.run_main(["--keep"])
        self.assertEqual(status, 0)
        podman = self.podmen[0]
        self.assertIn("remove_stale_runs", podman.calls)
        self.assertNotIn("register_cleanup", podman.calls)

    def test_without_keep_the_cleanup_is_registered(self):
        status, _out, _err = self.run_main([])
        self.assertEqual(status, 0)
        self.assertIn("register_cleanup", self.podmen[0].calls)

    def test_keep_prints_the_run_id_and_how_to_reuse_it(self):
        status, out, _err = self.run_main(["--keep"])
        self.assertEqual(status, 0)
        run_id = self.podmen[0].context.run_id
        self.assertIn(f"run id: {run_id}", out)
        reuse_lines = [line for line in out.splitlines() if "--reuse" in line]
        self.assertTrue(reuse_lines, out)
        self.assertIn(run_id, reuse_lines[0])
        self.assertIn("gowave.e2e.run=", out)


class TestReuseFromTheCommandLine(EntrypointCase, unittest.TestCase):
    """``--reuse`` adopts a kept cell, or refuses; it never installs again."""

    SOURCE = "podman-aio-20260101T000000-abcdef12"

    def kept_run(self, run_id: str = SOURCE, result: bool = True) -> Path:
        directory = self.root / run_id
        directory.mkdir(parents=True)
        if result:
            (directory / "result.json").write_text(json.dumps({"overall": PASS}), encoding="utf-8")
        return directory

    def adopted_run(self, run_id: str = SOURCE, distribution: str = "debian-13") -> tuple:
        """A kept run with a real setup record and a result that installs passed.

        The topology is created for real, so the record under test is the one a
        ``--keep`` run actually writes rather than a hand-built approximation of
        it; only Podman's own answers are replaced.
        """
        host, _podman = create_kept_topology(self.root, run_id, distribution=distribution)
        self.addCleanup(host.context.run_cleanup)
        result = {
            "overall": PASS,
            "cases": [
                {"id": "AIO-INSTALL", "status": PASS},
                {"id": "AIO-05", "status": PASS},
            ],
        }
        (host.context.artifact_dir / "result.json").write_text(json.dumps(result), encoding="utf-8")
        return host, host.context.artifact_dir

    def networks_for(self, host) -> dict:
        """The two recorded networks, keyed by the name Podman would be asked for."""
        record = run_setup.read_setup(host.context.artifact_dir)
        return {
            record["network"][side]["name"]: {
                "name": record["network"][side]["name"],
                "subnets": [record["network"][side]["subnet"]],
            }
            for side in ("control", "data")
        }

    def resources(self, containers=None, networks=None) -> list:
        """The Podman answers an adoption reads, with one resource replaceable."""
        patches = [
            mock.patch.object(
                run_podman_e2e, "owned_containers",
                lambda run_id, run=None: [dict(entry) for entry in containers or []],
            ),
            mock.patch.object(
                run_podman_e2e, "network_facts",
                lambda name, run_id="", run=None: (networks or {}).get(name),
            ),
            mock.patch.object(
                run_podman_e2e, "image_present",
                lambda reference, run_id="", run=None: True,
            ),
        ]
        return patches

    def reuse_expecting_exit_2(self, argv, containers, networks, kept_containers=None):
        names = kept_containers if kept_containers is not None else [
            entry["name"] for entry in containers
        ]
        patches = self.patchers(None, names) + self.resources(containers, networks)
        stderr = io.StringIO()
        for patcher in patches:
            patcher.start()
        try:
            with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    run_podman_e2e.main([*argv, "--artifact-root", str(self.root)])
        finally:
            for patcher in reversed(patches):
                patcher.stop()
        self.assertEqual(caught.exception.code, 2)
        return stderr.getvalue()

    def test_a_run_without_a_setup_record_is_refused_not_reinstalled(self):
        # The record is what makes a cell adoptable. A run that predates it, or
        # whose record was pruned, is not adoptable — and the refusal is still a
        # refusal rather than an install under the name of reuse.
        directory = self.kept_run()
        message = self.run_main_expecting_exit_2(
            ["--reuse", self.SOURCE], containers=["aio-abcdef12", "dns-abcdef12"],
        )
        self.assertIn(self.SOURCE, message)
        self.assertIn(str(directory), message)
        self.assertIn(run_setup.SETUP_FILE_NAME, message)
        self.assertIn("missing", message)
        self.assertFalse(self.podmen, "a refused reuse may not start Podman")
        self.assertFalse(self.runners, "a refused reuse may not run a case")

    def test_a_recorded_container_that_is_gone_exits_2_naming_it(self):
        host, _directory = self.adopted_run()
        containers = container_entries(host)
        gone = containers[-1]["name"]
        message = self.reuse_expecting_exit_2(
            ["--reuse", self.SOURCE], containers[:-1], self.networks_for(host),
        )
        self.assertIn(gone, message)
        self.assertIn("container", message)
        self.assertIn("not adoptable", message)
        self.assertFalse(self.podmen, "a missing container is refused before Podman is used")
        self.assertFalse(self.runners)

    def test_a_recorded_network_that_is_gone_exits_2_naming_it(self):
        host, _directory = self.adopted_run()
        networks = self.networks_for(host)
        record = run_setup.read_setup(host.context.artifact_dir)
        gone = record["network"]["data"]["name"]
        networks.pop(gone)
        message = self.reuse_expecting_exit_2(
            ["--reuse", self.SOURCE], container_entries(host), networks,
        )
        self.assertIn(gone, message)
        self.assertIn("network", message)
        self.assertFalse(self.podmen)

    def test_a_missing_secret_directory_exits_2_naming_it(self):
        host, _directory = self.adopted_run()
        secret = host.context.secret_dir
        # The directory is removed after the record was written, which is what a
        # pruned scratch space looks like to an adopting run.
        secret.rename(secret.with_name(secret.name + "-gone"))
        self.addCleanup(
            lambda: secret.with_name(secret.name + "-gone").rename(secret)
            if secret.with_name(secret.name + "-gone").exists() else None
        )
        message = self.reuse_expecting_exit_2(
            ["--reuse", self.SOURCE], container_entries(host), self.networks_for(host),
        )
        self.assertIn("secret directory", message)
        self.assertIn(str(secret), message)
        self.assertFalse(self.podmen)

    def test_a_cell_whose_install_never_passed_is_refused(self):
        host, directory = self.adopted_run()
        (directory / "result.json").write_text(
            json.dumps({"overall": FAIL, "cases": [{"id": "AIO-INSTALL", "status": FAIL}]}),
            encoding="utf-8",
        )
        message = self.reuse_expecting_exit_2(
            ["--reuse", self.SOURCE], container_entries(host), self.networks_for(host),
        )
        self.assertIn("AIO-INSTALL", message)
        self.assertIn("FAIL", message)
        self.assertFalse(self.podmen)

    def test_the_install_case_cannot_be_selected_against_kept_hosts(self):
        host, _directory = self.adopted_run()
        message = self.reuse_expecting_exit_2(
            ["--reuse", self.SOURCE, "--only", "AIO-INSTALL"],
            container_entries(host), self.networks_for(host),
        )
        self.assertIn("AIO-INSTALL", message)
        self.assertIn("cannot run again", message)
        # The runner object exists because the suite is built before the selection
        # is judged, but no case reached it: a refused selection runs nothing.
        self.assertFalse(
            [runner for runner in self.runners if runner.added or runner.executed_any],
            "a refused selection may not run a case",
        )

    def test_a_cluster_record_that_never_named_its_worker_is_refused(self):
        # A create that stopped between the Master and the Worker leaves a record
        # that parses; adopting it would run cluster cases against half a cell.
        multi_id = "podman-multi-node-20260101T000000-abcdef12"
        host, _podman = create_kept_topology(self.root, multi_id, kind="multi-node")
        self.addCleanup(host.context.run_cleanup)
        (host.context.artifact_dir / "result.json").write_text(
            json.dumps({
                "overall": PASS,
                "cases": [{"id": "MN-INSTALL", "status": PASS}, {"id": "WRK-04", "status": PASS}],
            }),
            encoding="utf-8",
        )
        record = run_setup.read_setup(host.context.artifact_dir)
        record["containers"].pop("worker")
        record["containers"].pop("untrusted")
        (host.context.artifact_dir / run_setup.SETUP_FILE_NAME).write_text(
            json.dumps(record), encoding="utf-8",
        )
        containers = [
            {"name": record["containers"][role], "state": "running"}
            for role in ("dns", "target", "echo", "client", "acme")
        ]
        message = self.reuse_expecting_exit_2(
            ["--reuse", multi_id], containers, self.networks_for(host),
        )
        self.assertIn("worker", message)
        self.assertIn("never created whole", message)
        self.assertFalse(self.podmen)

    def test_an_adopted_run_borrows_the_kept_hosts_and_records_that_it_did(self):
        host, source_directory = self.adopted_run()
        # The engine client is started on demand by the first case that consumes a
        # payload, so this cell has none; the adoption below proves its absence is
        # not a missing resource.
        self.assertNotIn(host.engine_client_name, host.started)
        body = {}

        def adopted_case(context):
            body["reused_from"] = context.reused_from
            body["secret_dir"] = context.secret_dir
            return {"note": "ran against the kept host"}

        networks = self.networks_for(host)
        patches = self.patchers(
            [Case("AIO-05", "aio", adopted_case),
             Case("AIO-INSTALL", "aio", lambda ctx: {})],
            [entry["name"] for entry in container_entries(host)],
            runner=False,
        ) + self.resources(container_entries(host), networks)
        stdout, stderr = io.StringIO(), io.StringIO()
        for patcher in patches:
            patcher.start()
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = run_podman_e2e.main(["--reuse", self.SOURCE, "--artifact-root", str(self.root)])
        finally:
            for patcher in reversed(patches):
                patcher.stop()
        self.assertEqual(status, 0, stderr.getvalue())
        # The adopted run is a new run directory; the kept one is untouched.
        adopted = [
            path for path in self.root.iterdir()
            if path.is_dir() and path.name != self.SOURCE
        ]
        self.assertEqual(len(adopted), 1, [path.name for path in adopted])
        record = read_json(adopted[0] / "result.json")
        self.assertTrue(record["reused"])
        self.assertEqual(record["reused_from"], self.SOURCE)
        summary = read_json(adopted[0] / "summary.json")
        self.assertTrue(summary["reused"])
        self.assertEqual(summary["reused_from"], self.SOURCE)
        self.assertEqual(record["executed"], ["AIO-05"], "the install case is not run against kept hosts")
        self.assertEqual(body["reused_from"], self.SOURCE)
        self.assertEqual(body["secret_dir"], host.context.secret_dir)
        self.assertTrue(
            (source_directory / run_setup.SETUP_FILE_NAME).is_file(),
            "adoption may not consume or rewrite the kept run's record",
        )

    def test_adoption_takes_its_topology_from_the_record_not_the_default(self):
        multi_id = "podman-multi-node-20260101T000000-abcdef12"
        host, _podman = create_kept_topology(
            self.root, multi_id, kind="multi-node",
        )
        self.addCleanup(host.context.run_cleanup)
        (host.context.artifact_dir / "result.json").write_text(
            json.dumps({
                "overall": PASS,
                "cases": [{"id": "MN-INSTALL", "status": PASS}, {"id": "WRK-04", "status": PASS}],
            }),
            encoding="utf-8",
        )
        seen = {}

        def fake_build_suite(*args, **kwargs):
            seen.update(kwargs)
            seen["topology"] = args[1]
            seen["distribution"] = args[2]
            return []

        record = run_setup.read_setup(host.context.artifact_dir)
        containers = [
            {"name": record["containers"][role], "state": "running"}
            for role in ("dns", "target", "echo", "client", "engine_client", "acme", "worker", "untrusted")
        ]
        networks = self.networks_for(host)
        patches = self.patchers(None, [entry["name"] for entry in containers]) + self.resources(
            containers, networks,
        ) + [mock.patch.object(run_podman_e2e, "build_suite", fake_build_suite)]
        stdout, stderr = io.StringIO(), io.StringIO()
        for patcher in patches:
            patcher.start()
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = run_podman_e2e.main(
                    ["--reuse", multi_id, "--artifact-root", str(self.root)]
                )
        finally:
            for patcher in reversed(patches):
                patcher.stop()
        self.assertEqual(status, 0, stderr.getvalue())
        # The record decided the suite and the configuration it was built for; the
        # command line stated none of them, so the default topology played no part.
        self.assertEqual(seen["topology"], "multi-node")
        self.assertEqual(seen["distribution"], "debian-13")
        self.assertTrue(seen["worker_registered"])
        self.assertFalse(seen["vision"])
        self.assertFalse(seen["worker_vision"])

    def test_a_stated_topology_that_contradicts_the_record_is_refused(self):
        multi_id = "podman-multi-node-20260101T000000-abcdef12"
        host, _podman = create_kept_topology(self.root, multi_id, kind="multi-node")
        self.addCleanup(host.context.run_cleanup)
        (host.context.artifact_dir / "result.json").write_text(
            json.dumps({
                "overall": PASS,
                "cases": [{"id": "MN-INSTALL", "status": PASS}, {"id": "WRK-04", "status": PASS}],
            }),
            encoding="utf-8",
        )
        record = run_setup.read_setup(host.context.artifact_dir)
        containers = [
            {"name": record["containers"][role], "state": "running"}
            for role in ("dns", "target", "echo", "client", "engine_client", "acme", "worker", "untrusted")
        ]
        message = self.reuse_expecting_exit_2(
            ["--reuse", multi_id, "--topology", "aio"], containers, self.networks_for(host),
        )
        self.assertIn("multi-node", message)
        self.assertIn("--topology aio", message)
        self.assertFalse(self.podmen)

    def test_a_run_whose_containers_are_gone_is_refused(self):
        self.kept_run()
        message = self.run_main_expecting_exit_2(["--reuse", self.SOURCE], containers=[])
        self.assertIn("no container", message)
        self.assertIn(self.SOURCE, message)
        self.assertFalse(self.podmen)

    def test_a_missing_run_directory_is_refused_by_path(self):
        message = self.run_main_expecting_exit_2(["--reuse", self.SOURCE], containers=[])
        self.assertIn("no run directory", message)
        self.assertIn(str(self.root / self.SOURCE), message)

    def test_a_directory_that_is_not_a_run_is_refused(self):
        self.kept_run(result=False)
        message = self.run_main_expecting_exit_2(["--reuse", self.SOURCE], containers=[])
        self.assertIn("holds no result.json", message)

    def test_a_run_id_cannot_climb_out_of_the_artifact_root(self):
        message = self.run_main_expecting_exit_2(["--reuse", "../escape"], containers=[])
        self.assertIn("not a path", message)

    def test_reuse_and_the_four_distribution_matrix_are_refused(self):
        message = self.run_main_expecting_exit_2(
            ["--reuse", self.SOURCE, "--all-distributions"], containers=[],
        )
        self.assertIn("--all-distributions", message)

    def test_reuse_beside_keep_is_refused(self):
        self.kept_run()
        message = self.run_main_expecting_exit_2(
            ["--reuse", self.SOURCE, "--keep"], containers=["aio-abcdef12"],
        )
        self.assertIn("--keep", message)


class TestReuseResolution(unittest.TestCase):
    """The validation a later reuse will run, tested without a container."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.run_id = "podman-aio-20260101T000000-abcdef12"
        self.directory = self.root / self.run_id
        self.directory.mkdir()
        (self.directory / "result.json").write_text("{}", encoding="utf-8")

    def test_validation_reports_the_directory_and_the_live_containers(self):
        source = run_podman_e2e.validate_reuse(
            self.root, self.run_id, containers=["aio-abcdef12"],
        )
        self.assertEqual(source["run_id"], self.run_id)
        self.assertEqual(source["directory"], self.directory.resolve())
        self.assertEqual(source["containers"], ["aio-abcdef12"])

    def test_no_container_means_the_hosts_are_gone(self):
        with self.assertRaises(run_podman_e2e.ReuseRefused) as caught:
            run_podman_e2e.validate_reuse(self.root, self.run_id, containers=[])
        self.assertIn("no container", str(caught.exception))

    def test_the_container_list_is_read_through_the_runs_own_label(self):
        seen = {}

        def fake_podman(command, **kwargs):
            seen["command"] = list(command)
            seen["kwargs"] = kwargs
            listing = [
                {"Names": ["aio-abcdef12"], "State": "running"},
                {"Names": ["dns-abcdef12"], "State": "running"},
            ]
            return mock.Mock(returncode=0, stdout=json.dumps(listing), stderr="")

        with mock.patch.object(run_podman_e2e, "podman_binary", lambda: "/usr/bin/podman"):
            names = run_podman_e2e.kept_containers(self.run_id, run=fake_podman)
        self.assertEqual(names, ["aio-abcdef12", "dns-abcdef12"])
        self.assertEqual(seen["command"][:2], ["/usr/bin/podman", "ps"])
        self.assertIn(f"label=gowave.e2e.run={self.run_id}", seen["command"])
        self.assertIn("--format", seen["command"])
        self.assertEqual(seen["kwargs"], {
            "capture_output": True, "text": True, "check": False, "timeout": 60,
        })

    def test_a_single_name_and_an_empty_listing_are_both_understood(self):
        def listing(stdout):
            def run(command, **kwargs):
                return mock.Mock(returncode=0, stdout=stdout, stderr="")
            return run

        with mock.patch.object(run_podman_e2e, "podman_binary", lambda: "/usr/bin/podman"):
            single = run_podman_e2e.kept_containers(
                self.run_id, run=listing(json.dumps([{"Names": "aio-abcdef12"}])),
            )
            empty = run_podman_e2e.kept_containers(
                self.run_id, run=listing("[]"),
            )
        self.assertEqual(single, ["aio-abcdef12"])
        self.assertEqual(empty, [])

    def test_a_listing_that_is_not_json_is_a_refusal(self):
        def not_json(command, **kwargs):
            return mock.Mock(returncode=0, stdout="aio-abcdef12", stderr="")

        with mock.patch.object(run_podman_e2e, "podman_binary", lambda: "/usr/bin/podman"):
            with self.assertRaises(run_podman_e2e.ReuseRefused) as caught:
                run_podman_e2e.kept_containers(self.run_id, run=not_json)
        self.assertIn("did not answer JSON", str(caught.exception))

    def test_a_listing_that_fails_is_a_refusal_not_a_traceback(self):
        def failing_podman(command, **kwargs):
            return mock.Mock(returncode=125, stdout="", stderr="cannot connect to Podman")

        with mock.patch.object(run_podman_e2e, "podman_binary", lambda: "/usr/bin/podman"):
            with self.assertRaises(run_podman_e2e.ReuseRefused) as caught:
                run_podman_e2e.kept_containers(self.run_id, run=failing_podman)
        self.assertIn("exited 125", str(caught.exception))
        self.assertIn("cannot connect", str(caught.exception))

    def test_an_absent_podman_is_a_refusal(self):
        from tools.podman_e2e.podman import PodmanUnavailable

        def missing():
            raise PodmanUnavailable("Podman is not installed")

        with mock.patch.object(run_podman_e2e, "podman_binary", missing):
            with self.assertRaises(run_podman_e2e.ReuseRefused) as caught:
                run_podman_e2e.kept_containers(self.run_id)
        self.assertIn("Podman is not installed", str(caught.exception))

    # ------------------------------------------------------- the setup record
    # ``--reuse`` cannot rebuild a cell from the objects the creating process
    # held; it reads the record that process wrote. These methods read the record
    # a real creation produced and the topology adoption rebuilds from it.

    def host(self, kind: str = "aio", run_id: str = ""):
        host, _podman = create_kept_topology(
            self.root, run_id or self.run_id, kind=kind,
        )
        self.addCleanup(host.context.run_cleanup)
        return host

    def test_the_record_is_private_and_carries_every_key_adoption_reads(self):
        host = self.host()
        path = host.context.artifact_dir / run_setup.SETUP_FILE_NAME
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        record = read_json(path)
        self.assertEqual(run_setup.validate_setup(record), [])
        for key in run_setup.REQUIRED_KEYS:
            self.assertIn(key, record)
        self.assertEqual(record["schema"], run_setup.SETUP_SCHEMA)
        self.assertEqual(record["run_id"], self.run_id)
        self.assertEqual(record["topology"], "aio")
        self.assertEqual(record["distribution"], "debian-13")
        self.assertEqual(record["vision"], {
            "enabled": False, "worker_enabled": False, "combination": "disabled",
        })
        self.assertEqual(record["artifact_root"], str(self.root))
        self.assertEqual(record["secret_dir"], str(host.context.secret_dir))
        self.assertEqual(record["network"]["control"]["subnet"], host.plan.subnet)
        self.assertEqual(record["network"]["data"]["subnet"], host.plan.data_subnet)
        self.assertEqual(record["network"]["control"]["name"], host.network)
        self.assertEqual(record["addresses"]["target"], host.plan.target_ip)
        self.assertEqual(record["addresses"]["target_data"], host.plan.data_target_ip)
        self.assertEqual(record["containers"]["target"], host.target_name)
        self.assertEqual(record["containers"]["dns"], host.dns_name)
        self.assertEqual(record["started"], host.started)
        self.assertEqual(record["fixtures"]["dns"], str(host.dns_dir))
        self.assertEqual(record["fixtures"]["client_ca"], str(host._ca_dir))
        self.assertEqual(record["fixtures"]["payloads"], str(host.payload_dir))
        self.assertEqual(record["images"]["target"], target_image.tag("debian-13"))
        self.assertEqual(record["images"]["fixture"], topology.FIXTURE_IMAGE)
        self.assertEqual(record["egress_resolvers"], ["192.0.2.53"])
        self.assertEqual(record["domains"]["panel"], topology.PANEL_DOMAIN)
        self.assertTrue(path.read_text(encoding="utf-8").strip().startswith("{"))

    def test_a_cluster_records_the_roles_it_adds(self):
        host = self.host(kind="multi-node", run_id="podman-multi-node-20260101T000000-abcdef12")
        record = read_setup(host)
        self.assertEqual(record["topology"], "multi-node")
        self.assertEqual(record["containers"]["worker"], host.worker_name)
        self.assertEqual(record["containers"]["untrusted"], host.untrusted_name)
        self.assertEqual(record["domains"]["worker"], topology.WORKER_DOMAIN)
        self.assertEqual(record["addresses"]["worker"], host.plan.worker_ip)
        self.assertIn(host.worker_name, record["started"])

    def test_adoption_rebuilds_the_plan_and_names_without_allocating(self):
        host = self.host()
        record = read_setup(host)
        context = RunContext(
            "aio", self.root / "adopting", budget_seconds=60,
            run_id="podman-aio-20260102T000000-11112222",
            reused_from=self.run_id,
            secret_dir=host.context.secret_dir,
        )
        adopting = AdoptingPodman(context)
        adopted = topology.adopt_topology(adopting, record)
        self.assertEqual(adopted.plan.subnet, host.plan.subnet)
        self.assertEqual(adopted.plan.data_subnet, host.plan.data_subnet)
        self.assertEqual(adopted.plan.target_ip, host.plan.target_ip)
        self.assertEqual(adopted.plan.worker_ip, host.plan.worker_ip)
        self.assertEqual(adopted.network, host.network)
        self.assertEqual(adopted.data_network, host.data_network)
        self.assertEqual(adopted.target_name, host.target_name)
        self.assertEqual(adopted.dns_name, host.dns_name)
        self.assertEqual(adopted.started, host.started)
        self.assertEqual(adopted.dns_dir, host.dns_dir)
        self.assertEqual(adopted._ca_dir, host._ca_dir)
        self.assertEqual(adopted.acme.name, host.acme.name)
        self.assertEqual(adopted._issued_root, host._issued_root)
        self.assertEqual(adopted.adopted_from, self.run_id)
        # The engine client was never started in this cell, so adoption must leave
        # it to be started on demand instead of claiming it exists.
        self.assertEqual(adopted._engine_image, "")
        # The one call an adoption may never make is the one that provisions.
        with self.assertRaises(topology.TopologyError) as caught:
            adopted.create()
        self.assertIn(self.run_id, str(caught.exception))

    def test_adoption_addresses_the_cluster_roles_by_their_recorded_names(self):
        run_id = "podman-multi-node-20260101T000000-abcdef12"
        host = self.host(kind="multi-node", run_id=run_id)
        record = read_setup(host)
        context = RunContext(
            "multi-node", self.root / "adopting", budget_seconds=60,
            run_id="podman-multi-node-20260102T000000-99998888",
            reused_from=run_id,
            secret_dir=host.context.secret_dir,
        )
        adopted = topology.adopt_topology(AdoptingPodman(context), record)
        self.assertEqual(adopted.target_name, host.target_name)
        self.assertEqual(adopted.worker_name, host.worker_name)
        self.assertEqual(adopted.untrusted_name, host.untrusted_name)
        self.assertEqual(adopted.client_name, host.client_name)
        self.assertEqual(adopted.echo_name, host.echo_name)
        self.assertEqual(adopted.acme.name, host.acme.name)
        self.assertEqual(adopted.started, host.started)
        self.assertTrue(adopted.ipv6_host, "the Master's IPv6 branch is a fact the record carries")
        self.assertEqual(adopted._issued_root, host._issued_root)
        # The whole point of restoring the names is that the roles the record
        # declares can be found again without creating anything.
        self.assertEqual(
            [role["container"] for role in adopted.require_roles()],
            [role["container"] for role in host.require_roles()],
        )

    def test_an_engine_client_the_kept_run_started_is_not_started_again(self):
        host = self.host()
        record = read_setup(host)
        record["started"].append(record["containers"]["engine_client"])
        context = RunContext(
            "aio", self.root / "adopting", budget_seconds=60,
            run_id="podman-aio-20260102T000000-33334444",
            reused_from=self.run_id,
            secret_dir=host.context.secret_dir,
        )
        adopted = topology.adopt_topology(AdoptingPodman(context), record)
        self.assertEqual(adopted.engine_client(), record["containers"]["engine_client"])
        self.assertEqual(adopted._engine_image, record["images"]["client"])

    def test_a_record_missing_a_key_is_refused_by_name(self):
        host = self.host()
        record = read_setup(host)
        record.pop("network")
        path = host.context.artifact_dir / run_setup.SETUP_FILE_NAME
        path.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaises(run_setup.RunSetupError) as caught:
            run_setup.read_setup(host.context.artifact_dir)
        self.assertIn("network is missing", str(caught.exception))

    def test_a_record_naming_an_unknown_topology_is_refused(self):
        host = self.host()
        record = read_setup(host)
        record["topology"] = "podman-in-the-cloud"
        with self.assertRaises(topology.TopologyError) as caught:
            topology.adopt_topology(AdoptingPodman(host.context), record)
        self.assertIn("podman-in-the-cloud", str(caught.exception))


def read_setup(host) -> dict:
    return run_setup.read_setup(host.context.artifact_dir)


if __name__ == "__main__":
    unittest.main()
