#!/usr/bin/env python3
"""Suite nonroot: the pre-push gate is a contract, not a convenience.

`tools/pre_push_e2e.py` claims that the two full suites run before a push leaves
the machine, that a failing topology blocks the push and names what it did not
run, and that the hook it installs runs the gate. These tests hold those claims
by driving the entrypoint with the suites replaced: which topologies it runs
comes from the manifest's own `gate:` list, each run is the same full-suite
module the acceptance jobs invoke, the hook is written only where the gate owns
the file, and nothing in the path knows a live host or a credential.
"""
import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools import pre_push_e2e as gate  # noqa: E402

COMMIT = "6be5a9a0c9626933f068ceafe06d24d64cb0db10"


class TestPrePushGate(unittest.TestCase):
    """What the gate runs, what it refuses, and what it writes."""

    def run_gate(self, *arguments, codes=None, euid=0, tree="clean"):
        """Invoke ``main`` with the suites replaced by the exit codes given.

        Returns the status, both streams and the commands that were run, so a
        test can say which topology was invoked, in which order, and with what
        arguments rather than only that something exited non-zero.
        """
        calls = []

        def fake_run(command, **_kwargs):
            calls.append(list(command))
            topology = command[command.index("--topology") + 1]
            code = (codes or {}).get(topology, 0)
            return subprocess.CompletedProcess(command, code, stdout="", stderr="")

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(gate.os, "geteuid", return_value=euid))
            stack.enter_context(mock.patch.object(gate.subprocess, "run", side_effect=fake_run))
            stack.enter_context(
                mock.patch.object(gate, "repository_state", return_value=(COMMIT, tree))
            )
            out = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            err = stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            status = gate.main(arguments)
        return status, out.getvalue(), err.getvalue(), calls

    def test_the_gate_runs_the_topologies_the_manifest_gates(self):
        self.assertEqual(gate.pre_push_topologies(gate.load_matrix()), ["aio", "multi-node"])
        matrix = gate.load_matrix()
        matrix["topologies"]["multi-node"]["gate"] = ["pr"]
        self.assertEqual(gate.pre_push_topologies(matrix), ["aio"])
        matrix["topologies"]["edge"] = {"gate": ["pre-push"]}
        self.assertEqual(gate.pre_push_topologies(matrix), ["aio", "edge"])

    def test_each_run_is_the_full_suite_entrypoint(self):
        status, _out, _err, calls = self.run_gate()
        self.assertEqual(status, 0)
        self.assertEqual(
            [command[command.index("--topology") + 1] for command in calls],
            ["aio", "multi-node"],
            "All-in-One runs first, and both gated topologies run",
        )
        for command in calls:
            with self.subTest(command=command):
                self.assertEqual(command[1:3], ["-m", "tools.run_podman_e2e"])
                for forbidden in ("--require-group", "--vision", "--worker-vision",
                                  "--distribution", "--budget-seconds"):
                    self.assertNotIn(forbidden, command)
                joined = " ".join(command).lower()
                for token in ("live", "secret", "token", "password", "--host"):
                    self.assertNotIn(token, joined)

    def test_a_failing_topology_blocks_the_gate_and_names_the_rest_not_run(self):
        status, out, err, calls = self.run_gate(codes={"aio": 1})
        self.assertEqual(status, 1)
        self.assertEqual(len(calls), 1, "a failed topology stops the gate")
        self.assertIn("aio FAILED (exit 1); the push is blocked", err)
        self.assertIn("not run: multi-node", err)
        self.assertNotIn("every gated suite passed", out)

    def test_a_green_pair_lets_the_push_continue(self):
        status, out, _err, calls = self.run_gate()
        self.assertEqual(status, 0)
        self.assertEqual(len(calls), 2)
        self.assertIn("aio passed", out)
        self.assertIn("multi-node passed", out)
        self.assertIn("every gated suite passed; the push may continue", out)

    def test_the_gate_refuses_to_run_without_root(self):
        status, _out, err, calls = self.run_gate(euid=1000)
        self.assertEqual(status, 2)
        self.assertEqual(calls, [], "nothing runs before the privilege check")
        self.assertIn("runs as root", err)
        self.assertIn("sudo python3 -m tools.pre_push_e2e", err)

    def test_the_gate_names_the_commit_and_tree_it_judged(self):
        _status, out, _err, _calls = self.run_gate(tree="dirty")
        self.assertIn(f"judging {COMMIT} (tree: dirty)", out)
        self.assertIn("tree: dirty", out, "a dirty tree is how a suite passes on unpushed code")

    def test_the_gate_lists_what_it_would_run_without_running_it(self):
        status, out, _err, calls = self.run_gate("--list", euid=1000)
        self.assertEqual(status, 0)
        self.assertEqual(calls, [])
        self.assertIn("-m tools.run_podman_e2e --topology aio", out)
        self.assertIn("-m tools.run_podman_e2e --topology multi-node", out)

    def test_the_installer_writes_an_executable_hook(self):
        with tempfile.TemporaryDirectory() as directory:
            target = gate.install_hook(Path(directory))
            body = target.read_text(encoding="utf-8")
            mode = target.stat().st_mode & 0o777
        self.assertEqual(target.name, "pre-push")
        self.assertTrue(body.startswith("#!/usr/bin/env bash\n"), body)
        self.assertIn(gate.HOOK_MARKER, body)
        self.assertIn("set -Eeuo pipefail", body)
        self.assertIn("exec sudo python3 -m tools.pre_push_e2e", body)
        self.assertEqual(mode, 0o755, "git refuses to run a hook it cannot execute")

    def test_the_hook_runs_a_module_the_tree_holds(self):
        self.assertTrue(
            (REPO_ROOT / "tools" / "pre_push_e2e.py").exists(),
            "the hook names tools.pre_push_e2e, so that module is the gate",
        )
        self.assertIn(
            f"exec sudo python3 -m {gate.GATE_MODULE}",
            gate.HOOK_BODY,
            "the hook runs the gate as root, because the suites provision containers",
        )

    def test_the_installer_refuses_to_replace_a_foreign_hook(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "pre-push"
            foreign = "#!/bin/sh\necho somebody else's hook\n"
            target.write_text(foreign, encoding="utf-8")
            with self.assertRaises(FileExistsError):
                gate.install_hook(Path(directory))
            self.assertEqual(target.read_text(encoding="utf-8"), foreign)
            with mock.patch.object(gate, "hooks_directory", return_value=Path(directory)):
                with contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(io.StringIO()) as err:
                    status = gate.main(["--install-hook"])
        self.assertEqual(status, 2)
        self.assertIn("was not written by this gate", err.getvalue())

    def test_the_installer_is_idempotent_on_its_own_hook(self):
        with tempfile.TemporaryDirectory() as directory:
            first = gate.install_hook(Path(directory))
            body = first.read_text(encoding="utf-8")
            second = gate.install_hook(Path(directory))
            self.assertEqual(second.read_text(encoding="utf-8"), body)
            self.assertEqual(sorted(path.name for path in Path(directory).iterdir()),
                             ["pre-push"], "no temporary sibling survives the install")

    def test_the_gate_knows_no_live_target(self):
        source = (REPO_ROOT / "tools" / "pre_push_e2e.py").read_text(encoding="utf-8")
        for token in ("live_vps", "paramiko", "sshpass", "known_hosts", "--host"):
            with self.subTest(token=token):
                self.assertNotIn(token, source)


if __name__ == "__main__":
    unittest.main()
