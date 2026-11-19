#!/usr/bin/env python3
"""Suite nonroot: bounded readiness polling contract for the Podman E2E harness."""
import ast
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e.podman import Podman, wait_until  # noqa: E402

PACKAGE_DIR = REPO_ROOT / "tools" / "podman_e2e"


def _python_sources():
    for path in sorted(PACKAGE_DIR.glob("*.py")):
        yield path, ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _enclosing_functions(tree):
    mapping = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for child in ast.walk(node):
                mapping.setdefault(id(child), node.name)
    return mapping


def _function_parameters(tree):
    """Function name -> the parameters its signature declares."""
    mapping = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            arguments = node.args
            names = {argument.arg for argument in arguments.args}
            names |= {argument.arg for argument in arguments.kwonlyargs}
            if arguments.vararg is not None:
                names.add(arguments.vararg.arg)
            if arguments.kwarg is not None:
                names.add(arguments.kwarg.arg)
            mapping[node.name] = names
    return mapping


class TestNoUnboundedWaits(unittest.TestCase):
    def test_no_while_true_loops(self):
        for path, tree in _python_sources():
            for node in ast.walk(tree):
                if isinstance(node, ast.While):
                    is_true = isinstance(node.test, ast.Constant) and node.test.value is True
                    self.assertFalse(is_true, f"{path.name}: unbounded 'while True' loop")

    def test_sleeps_live_inside_bounded_wait_helpers(self):
        for path, tree in _python_sources():
            functions = _enclosing_functions(tree)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if not isinstance(node.func, ast.Attribute) or node.func.attr != "sleep":
                    continue
                if not (isinstance(node.func.value, ast.Name) and node.func.value.id == "time"):
                    continue
                function = functions.get(id(node), "")
                self.assertTrue(
                    function.startswith("wait_"),
                    f"{path.name}:{node.lineno} fixed sleep outside a bounded wait helper ({function or 'module level'})",
                )

    def test_every_subprocess_call_has_a_timeout(self):
        for path, tree in _python_sources():
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                # ``Popen`` returns while the child is still running and takes no
                # ``timeout`` of its own, so it is held by its own test below.
                if name not in ("run", "check_output"):
                    continue
                if not isinstance(func, ast.Attribute) or not isinstance(func.value, ast.Name):
                    continue
                if func.value.id != "subprocess":
                    continue
                keywords = {keyword.arg for keyword in node.keywords}
                self.assertIn("timeout", keywords, f"{path.name}:{node.lineno} subprocess.{name} without timeout")

    def test_a_supervised_process_lives_in_a_spawn_helper_that_names_its_deadline(self):
        """``Popen`` is the one spawn that owes its bound to the caller.

        A streamed probe answers over the pipe for as long as the case needs it,
        which ``run`` cannot express, so the process is started by a ``spawn_``
        helper that has to declare the deadline it enforces — the convention the
        ``wait_`` rule applies to sleeps. Any ``Popen`` outside such a helper is
        a child nobody kills when the case stops answering.
        """
        for path, tree in _python_sources():
            functions = _enclosing_functions(tree)
            parameters = _function_parameters(tree)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                if name != "Popen":
                    continue
                if not isinstance(func, ast.Attribute) or not isinstance(func.value, ast.Name):
                    continue
                if func.value.id != "subprocess":
                    continue
                helper = functions.get(id(node), "")
                self.assertTrue(
                    helper.startswith("spawn_"),
                    f"{path.name}:{node.lineno} Popen outside a bounded spawn helper "
                    f"({helper or 'module level'})",
                )
                self.assertIn(
                    "timeout", parameters.get(helper, set()),
                    f"{path.name}:{node.lineno} the spawn helper {helper} names no deadline",
                )

    def test_no_interactive_input_calls(self):
        for path, tree in _python_sources():
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "input":
                    self.fail(f"{path.name}:{node.lineno} interactive input() in an automated suite")


class Clock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps = []

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class TestWaitUntil(unittest.TestCase):
    def test_success_needs_no_sleep(self):
        clock = Clock()
        self.assertTrue(wait_until(lambda: True, 5, "ready", clock=clock.clock, sleep=clock.sleep))
        self.assertEqual(clock.sleeps, [])

    def test_failure_is_bounded_by_the_deadline(self):
        clock = Clock()
        result = wait_until(lambda: False, 5, "never ready", interval_seconds=0.5, clock=clock.clock, sleep=clock.sleep)
        self.assertFalse(result)
        self.assertGreaterEqual(clock.now, 5)
        self.assertLessEqual(clock.now, 5.5)
        self.assertTrue(all(seconds > 0 for seconds in clock.sleeps))

    def test_zero_or_negative_timeout_is_a_programming_error(self):
        for timeout in (0, -1):
            with self.assertRaises(ValueError):
                wait_until(lambda: False, timeout, "bad", clock=lambda: 0.0, sleep=lambda seconds: None)


class StubPodman(Podman):
    def __init__(self, states, tcp_ready=True):
        self.states = list(states)
        self.tcp_ready = tcp_ready
        self.binary = "podman"

    def exec(self, name, argv, check=True, input_text=None):
        if argv[:2] == ["systemctl", "is-system-running"]:
            state = self.states.pop(0) if len(self.states) > 1 else self.states[0]
            return subprocess.CompletedProcess(argv, 1, state, "")
        return subprocess.CompletedProcess(argv, 0 if self.tcp_ready else 1, "", "")

    def exec_bash(self, name, script, check=True, input_text=None):
        return subprocess.CompletedProcess(["bash"], 0 if self.tcp_ready else 1, "", "")

    def _run(self, args, check=True, input_text=None, timeout=300):
        return subprocess.CompletedProcess(args, 0, "boot log", "")


class TestBoundedReadinessHelpers(unittest.TestCase):
    def test_wait_systemd_returns_the_observed_state(self):
        podman = StubPodman(["starting", "running"])
        self.assertEqual(podman.wait_systemd("panel", timeout_seconds=5), "running")

    def test_wait_systemd_failure_reports_last_state_and_logs(self):
        podman = StubPodman(["starting"])
        with self.assertRaises(RuntimeError) as raised:
            podman.wait_systemd("panel", timeout_seconds=1)
        self.assertIn("last state: starting", str(raised.exception))
        self.assertIn("boot log", str(raised.exception))

    def test_wait_tcp_success_and_failure(self):
        StubPodman([], tcp_ready=True).wait_tcp("panel", "127.0.0.1", 3000, timeout_seconds=1)
        with self.assertRaises(RuntimeError):
            StubPodman([], tcp_ready=False).wait_tcp("panel", "127.0.0.1", 3000, timeout_seconds=1)


if __name__ == "__main__":
    unittest.main()
