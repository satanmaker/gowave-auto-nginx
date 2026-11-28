#!/usr/bin/env python3
"""Suite nonroot: the read-only status command of the Podman acceptance suite.

``python3 -m tools.podman_e2e.live_status`` has to answer for a rootful cell whose
containers no unprivileged ``podman ps`` can see, and it has to answer without
asking a container engine anything. The command therefore separates its decision
— :func:`tools.podman_e2e.live_status.report`, a function of a process list and an
artifact directory — from the two readers that produce them, and these tests
drive the decision with the same fixtures an operator meets on disk: a runner
command line, the ``podman exec`` it is blocked on, a run directory with a
diagnostics tree, and a ``result.json`` and ``summary.json`` left by a run that
finished.

Nothing here starts a process or opens a container, which is the property the
command itself has and the reason it can be checked on the same workstation that
runs the rest of the nonroot suite.
"""
import ast
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import live_status  # noqa: E402

#: A fixed clock. A run directory's age, its ``result.json``'s age and the cell's
#: elapsed time are all read against it, so the report is a function of the
#: fixtures and not of when the suite was run.
MOMENT = 1_800_000_000.0


class TestLiveStatus(unittest.TestCase):
    """The status command: one line per cell, and no line invented from nothing."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def runner_process(self, topology, distribution, root, elapsed, pid=4242, ppid=1):
        """A runner command line as ``/proc`` would show it."""
        return {
            "pid": pid,
            "ppid": ppid,
            "elapsed": elapsed,
            "cmdline": [
                "python3", "-m", "tools.run_podman_e2e", "--topology", topology,
                "--distribution", distribution, "--artifact-root", str(root),
            ],
        }

    def run_tree(self, root, topology, stamp="20260101T000000", run="00000000"):
        """An artifact root holding one run directory with an empty evidence tree."""
        directory = root / f"podman-{topology}-{stamp}-{run}"
        (directory / "evidence" / "diagnostics").mkdir(parents=True)
        return directory

    def record_result(self, run_dir, document, now=MOMENT, age=60):
        """``result.json`` aged by ``age`` seconds, so the window can be tested."""
        result = run_dir / "result.json"
        result.write_text(json.dumps(document), encoding="utf-8")
        os.utime(result, (now - age, now - age))
        return result

    def test_a_live_cell_is_one_line_naming_its_step_and_residue(self):
        root = Path(self.tmp.name)
        run = self.run_tree(root / f"matrix-{'a' * 32}" / "debian-13", "multi-node")
        os.utime(run, (MOMENT - 700, MOMENT - 700))
        (run / "evidence" / "diagnostics" / "MN-TLS-01").mkdir()
        processes = [
            self.runner_process("multi-node", "debian-13", run.parent, 754.0),
            {
                "pid": 4300, "ppid": 4242, "elapsed": 12.0,
                "cmdline": [
                    "podman", "exec", "gowave-e2e-mn-master", "bash", "-c",
                    "installer --case MN-TLS-01 --stage NODE_ADD",
                ],
            },
        ]
        entries = live_status.report(processes, root, now=MOMENT)
        self.assertEqual(len(entries), 1)
        self.assertEqual(
            live_status.line(entries[0]),
            "multi-node debian-13 up=12m34s "
            "step=podman exec gowave-e2e-mn-master bash -c installer --case... "
            "diag=1 verdict=none",
        )

    def test_a_live_cell_is_one_printed_line_and_exit_zero(self):
        """The command itself: the text branch, one line per cell, exit 0."""
        root = Path(self.tmp.name)
        run = self.run_tree(root, "multi-node", run="22222222")
        os.utime(run, (MOMENT - 130, MOMENT - 130))
        processes = [self.runner_process("multi-node", "debian-13", root, 120.0)]
        with mock.patch.object(live_status, "read_processes", lambda: processes), \
                mock.patch.object(live_status.time, "time", lambda: MOMENT):
            with contextlib.redirect_stdout(io.StringIO()) as printed:
                code = live_status.main(["--artifact-root", str(root)])
        self.assertEqual(code, 0)
        self.assertEqual(
            printed.getvalue().splitlines(),
            ["multi-node debian-13 up=2m00s step=- diag=0 verdict=none"],
        )

    def test_a_finished_run_reports_the_verdict_its_summary_recorded(self):
        root = Path(self.tmp.name)
        run = self.run_tree(root, "aio")
        (run / "evidence" / "diagnostics" / "AIO-01").mkdir()
        # The summary is the projection a reader is meant to use, so it decides
        # both the verdict and the distribution when it names them.
        (run / "summary.json").write_text(
            json.dumps({
                "overall": "PASS", "topology": "aio", "distribution": "ubuntu-24.04",
            }),
            encoding="utf-8",
        )
        self.record_result(run, {
            "topology": "aio",
            "overall": "FAIL",
            "environment": {"images_resolved": {"debian-12": "sha256:" + "0" * 64}},
        })
        entries = live_status.report([], root, now=MOMENT)
        self.assertEqual(
            live_status.line(entries[0]),
            "aio ubuntu-24.04 up=- step=- diag=1 verdict=PASS",
        )

    def test_a_finished_run_without_a_summary_reports_its_result(self):
        root = Path(self.tmp.name)
        run = self.run_tree(root, "panel-only", run="11111111")
        self.record_result(run, {
            "topology": "panel-only",
            "overall": "FAIL",
            "environment": {"images_resolved": {"debian-12": "sha256:" + "0" * 64}},
        })
        entries = live_status.report([], root, now=MOMENT)
        self.assertEqual(
            live_status.line(entries[0]),
            "panel-only debian-12 up=- step=- diag=0 verdict=FAIL",
        )

    def test_a_run_older_than_the_window_is_not_reported(self):
        root = Path(self.tmp.name)
        run = self.run_tree(root, "aio")
        self.record_result(
            run, {"topology": "aio", "overall": "PASS"},
            age=live_status.FINISHED_WINDOW_SECONDS + 60,
        )
        self.assertEqual(live_status.report([], root, now=MOMENT), [])

    def test_a_rootful_cell_is_reported_with_no_container_in_sight(self):
        """One runner process and nothing else: no container, no engine, one line."""
        root = Path(self.tmp.name)
        (root / "empty-artifacts").mkdir()
        processes = [self.runner_process("multi-node", "debian-13", root, 1320.0)]
        with mock.patch("subprocess.run", side_effect=AssertionError("no engine is asked")), \
                mock.patch("subprocess.Popen", side_effect=AssertionError("no engine is asked")), \
                mock.patch("subprocess.check_output",
                           side_effect=AssertionError("no engine is asked")):
            entries = live_status.report(processes, root, now=MOMENT)
        self.assertEqual(
            live_status.line(entries[0]),
            "multi-node debian-13 up=22m00s step=- diag=? verdict=none",
        )

    def test_a_wrapper_and_the_runner_it_started_are_one_cell(self):
        root = Path(self.tmp.name)
        processes = [
            self.runner_process("aio", "debian-12", root, 600.0, pid=500, ppid=1),
            self.runner_process("aio", "debian-12", root, 599.0, pid=501, ppid=500),
        ]
        entries = live_status.report(processes, root, now=MOMENT)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["up"], 600.0)

    def test_the_json_report_carries_the_same_fields(self):
        root = Path(self.tmp.name)
        run = self.run_tree(root, "aio")
        self.record_result(run, {
            "topology": "aio",
            "overall": "PASS",
            "environment": {"images_resolved": {"debian-13": "sha256:" + "1" * 64}},
        })
        with mock.patch.object(live_status, "read_processes", lambda: []):
            with contextlib.redirect_stdout(io.StringIO()) as printed:
                code = live_status.main(["--artifact-root", str(root), "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(printed.getvalue()), [{
            "topology": "aio",
            "distribution": "debian-13",
            "up": None,
            "step": None,
            "diag": 0,
            "verdict": "PASS",
        }])

    def test_nothing_to_report_exits_three(self):
        root = Path(self.tmp.name) / "no-runs-yet"
        root.mkdir()
        with mock.patch.object(live_status, "read_processes", lambda: []):
            with contextlib.redirect_stdout(io.StringIO()) as printed:
                code = live_status.main(["--artifact-root", str(root)])
        self.assertEqual(code, 3)
        self.assertEqual(printed.getvalue(), "")

    def test_the_default_distribution_is_the_one_the_entrypoint_declares(self):
        """The command cannot ask the entrypoint, so the value is read back here."""
        source = (REPO_ROOT / "tools" / "run_podman_e2e.py").read_text(encoding="utf-8")
        declared = [
            node.value.value
            for node in ast.parse(source).body
            if isinstance(node, ast.Assign)
            and any(getattr(target, "id", "") == "DEFAULT_DISTRIBUTION"
                    for target in node.targets)
            and isinstance(node.value, ast.Constant)
        ]
        self.assertEqual(declared, [live_status.DEFAULT_DISTRIBUTION])
        self.assertEqual(
            live_status.ARTIFACT_ROOT, REPO_ROOT / "artifacts" / "podman-e2e",
        )
        self.assertLessEqual(live_status.FINISHED_WINDOW_SECONDS, 24 * 3600)


if __name__ == "__main__":
    unittest.main()
