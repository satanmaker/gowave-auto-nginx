#!/usr/bin/env python3
"""Suite nonroot: a heavy harness step names its own wall-clock budget.

``tools/podman_e2e/multi_node.py`` runs every role step through
``podman.exec_bash(container, command, check=..., timeout=...)``. Omitted,
``timeout`` falls back to ``DEFAULT_COMMAND_TIMEOUT`` — the probe default, not a
budget. The composed-mixed case re-provisioned the Worker through ``node
reapply`` on that default, the payload was cut off mid-run, and the case
reported its own timeout as a product failure ("the retry did not die from
SIGTERM"). The budget such a step needs is the migration one
(``WORKER_MIGRATION_TIMEOUT_ONE_RUN_SECONDS``), not the probe default.

The rule these tests hold is mechanical: an ``exec_bash`` call that runs a
Worker registration, a Worker re-provision or an installer must name its own
``timeout=``, and one whose command names such a step may not name a budget
below ``FLOOR_SECONDS``. Call sites are found by parsing the harness with
``ast`` rather than by searching the text: the same commands are described in
docstrings and copied into payload heredocs, and a grep would report the prose
as a step.

The parse has to reach through the two shapes that hide a step from a naive
reader:

* a helper that builds the command (``node_reapply_script(...)``) and the local
  variable it was assigned to, including a closure that reads a variable of the
  function around it;
* a helper that receives its command as a parameter, where no text names the
  step. That cannot be resolved, so the enclosing helper is listed in
  ``OPAQUE_COMMAND_HELPERS`` with the budget it passes itself. A listed helper
  that disappears, or a new unlisted one, fails the count — nothing is skipped
  silently.

The analysis is exercised on synthetic sources too, because a lint that finds
nothing passes for the wrong reason: each shape above has a control that must be
reported and a control that must not.
"""
import ast
import re
import sys
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import multi_node, podman  # noqa: E402

HARNESS = REPO_ROOT / "tools" / "podman_e2e" / "multi_node.py"
HARNESS_LABEL = "tools/podman_e2e/multi_node.py"

# The steps that take minutes rather than seconds: a Worker registration, a
# Worker re-provision, and the installer that both of them run.
STEP_FRAGMENTS = (
    "node add",
    "node reapply",
    "gowave-auto.sh install",
    "install_prerequisites",
)
# The same steps reached through a name a `podman.exec_bash` argument can be
# read for: a builder in this file, or a method that returns the operator's own
# command. A name alone proves only that the call is about a step, so such a
# call has to name a budget but is not held to `FLOOR_SECONDS` — a duplicate
# `node add` is expected to be refused before it deploys anything and is
# deliberately capped at the probe default.
STEP_HELPER = re.compile(r"\b(?:node_add_script|node_reapply_script|install_script|"
                         r"install_prerequisites)\b")
# A step that cannot finish in ten minutes was never given a budget for the
# work it does; the shortest honest allowance for a re-provision is longer.
FLOOR_SECONDS = 600
# A step named only as a pattern a process-matching utility searches the process
# table for is not the step: `pkill -TERM -f 'gowave-auto.sh node reapply'`
# signals it and returns at once.
PROCESS_MATCH = re.compile(
    r"\b(?:pkill|pgrep)\b[^\n;|&]*?\s-f\s+(?P<quote>['\"])(?P<pattern>.*?)(?P=quote)"
)
# Helper functions whose command arrives as a parameter, so no text in this file
# names the step: the function itself has to name the budget. The number is how
# many `exec_bash` calls the helper owns, so a new call it grows is not covered
# by an entry written for an older shape.
OPAQUE_COMMAND_HELPERS = {
    "case_vision_route.<lambda>": (
        2,
        "the command is the script `aio.vision_route_contract` asks for, and the lambda "
        "itself passes aio.VISION_CONTOUR_TIMEOUT_SECONDS * 2 for the read it makes",
    ),
}


def _text(node):
    return ast.unparse(node)


def _without_process_match_patterns(text):
    """The command text with the pattern operand of `pkill`/`pgrep` blanked out."""
    return PROCESS_MATCH.sub(
        lambda match: match.group(0).replace(match.group("pattern"), ""), text
    )


def _is_exec_bash(node):
    if isinstance(node, ast.Attribute):
        return node.attr == "exec_bash"
    return isinstance(node, ast.Name) and node.id == "exec_bash"


def _keyword(call, name):
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _command_expression(call):
    if len(call.args) >= 2:
        return call.args[1]
    return _keyword(call, "script")


def _container_expression(call):
    if call.args:
        return call.args[0]
    return _keyword(call, "name")


def _timeout_expression(call):
    """The `timeout=` the call passes, keyword or the fifth position of
    ``exec_bash(name, script, check, input_text, timeout)``."""
    keyword = _keyword(call, "timeout")
    if keyword is not None:
        return keyword
    return call.args[4] if len(call.args) >= 5 else None


def _module_symbols(tree):
    """The module's own functions and its module-level bindings."""
    functions, constants = {}, {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions[node.name] = node
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    constants.setdefault(target.id, node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value:
            constants.setdefault(node.target.id, node.value)
    return functions, constants


def _bound_names(node):
    """What a function body binds, so a command held in a variable can be read."""
    bound = {}
    for child in ast.walk(node):
        if isinstance(child, ast.Assign) and len(child.targets) == 1 \
                and isinstance(child.targets[0], ast.Name):
            bound.setdefault(child.targets[0].id, child.value)
        elif isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name) \
                and child.value:
            bound.setdefault(child.target.id, child.value)
    return bound


def _lookup(name, scopes):
    for scope in scopes:
        if name in scope:
            return scope[name]
    return None


def _command_text(expression, scopes, functions, depth=0):
    """Every text the command may stand for: the expression, what its names are
    bound to, and the body of any helper in this file it calls."""
    parts = [_text(expression)]
    if depth >= 4:
        return "\n".join(parts)
    for node in ast.walk(expression):
        if isinstance(node, ast.Name):
            bound = _lookup(node.id, scopes)
            if bound is not None:
                parts.append(_command_text(bound, scopes, functions, depth + 1))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            helper = functions.get(node.func.id)
            if helper is not None:
                parts.append(_text(helper))
    return "\n".join(parts)


class CallSite:
    """One `exec_bash` call as the lint sees it."""

    def __init__(self, line, function, command, text, fragments, helper, timeout, opaque):
        self.line = line
        self.function = function
        self.command = command
        self.text = text
        self.fragments = fragments
        self.helper = helper
        self.timeout = timeout
        self.opaque = opaque

    @property
    def heavy(self):
        return bool(self.fragments or self.helper)

    def due(self):
        """Which step this call owes a budget for, as a fragment or a helper name."""
        if self.fragments:
            return self.fragments[0]
        return self.helper


class HarnessTimeoutLint:
    """The `exec_bash` calls of one harness source, and the budgets they name."""

    def __init__(self, source, path=HARNESS, label=HARNESS_LABEL, namespace=None):
        self.path = Path(path)
        self.label = label
        self.tree = ast.parse(source, filename=str(self.path))
        self.functions, self.constants = _module_symbols(self.tree)
        self.namespace = namespace if namespace is not None else {}
        self.sites = []
        self._walk(self.tree, [self.constants], [])

    # ------------------------------------------------------------ collection
    def _walk(self, node, scopes, stack):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.Lambda):
                inner = [*scopes, _bound_names(child)]
                self._walk(child, inner, [*stack, "<lambda>"])
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                inner = [*scopes, _bound_names(child)]
                self._walk(child, inner, [*stack, child.name])
            else:
                if isinstance(child, ast.Call):
                    self._record(child, scopes, stack)
                self._walk(child, scopes, stack)

    def _record(self, call, scopes, stack):
        if not _is_exec_bash(call.func):
            return
        container = _container_expression(call)
        command = _command_expression(call)
        if container is None or command is None:
            return
        if isinstance(container, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
            # An argv, not a container name: this call describes the call itself.
            return
        text = _command_text(command, scopes, self.functions)
        fragment_text = _without_process_match_patterns(text)
        fragments = tuple(step for step in STEP_FRAGMENTS if step in fragment_text)
        helper = STEP_HELPER.search(_text(command))
        opaque = isinstance(command, ast.Name) and _lookup(command.id, scopes) is None
        self.sites.append(CallSite(
            line=call.lineno,
            function=".".join(stack) or "<module>",
            command=_text(command),
            text=fragment_text,
            fragments=fragments,
            helper=helper.group(0) if helper else "",
            timeout=_timeout_expression(call),
            opaque=opaque,
        ))

    # ------------------------------------------------------------- findings
    def observed_fragments(self):
        return {step for site in self.sites for step in site.fragments}

    def opaque_sites(self):
        return [site for site in self.sites if site.opaque]

    def _excerpt(self, site, due):
        index = site.text.find(due)
        start = site.text.rfind("\n", 0, index) + 1
        end = site.text.find("\n", index)
        line = site.text[start:end if end != -1 else len(site.text)].strip()
        if len(line) <= 140:
            return line
        return "..." + line[max(index - start - 60, 0):][:140]

    def _where(self, site, due, complaint):
        return (
            f"{self.label}:{site.line}: in {site.function!r}, `exec_bash` runs {due!r} "
            f"{complaint}; the call passes {site.command!r}: {self._excerpt(site, due)!r}"
        )

    def missing_timeout(self):
        """Heavy calls that let the probe default stand in for a budget."""
        found = []
        for site in self.sites:
            absent = site.timeout is None or (
                isinstance(site.timeout, ast.Constant) and site.timeout.value is None
            )
            if site.heavy and absent:
                found.append(self._where(
                    site, site.due(),
                    f"without a `timeout=`, so it rides the "
                    f"{podman.DEFAULT_COMMAND_TIMEOUT} s probe default",
                ))
        return found

    def seconds(self, expression):
        """A timeout expression as seconds, or None when it cannot be read."""
        allowed = (
            ast.Expression, ast.Constant, ast.Name, ast.Attribute, ast.BinOp, ast.UnaryOp,
            ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.USub, ast.Load,
        )
        wrapped = ast.Expression(body=expression)
        for node in ast.walk(wrapped):
            if not isinstance(node, allowed):
                return None
        try:
            value = eval(  # noqa: S307 - this source's own numeric constants, nothing else
                compile(wrapped, "<timeout>", "eval"),
                {"__builtins__": {}},
                self.namespace,
            )
        except Exception:
            return None
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        return value

    def below_floor(self):
        """Step calls whose budget is shorter than the work can take.

        Only a call whose command names the step is held to the floor: a helper
        name says which step a call is *about*, not that the call runs it to
        completion. A duplicate `node add` is the difference — it is refused by a
        state read before it deploys anything and is capped at the probe default
        on purpose, so it owes a budget but not this one.
        """
        found = []
        for site in self.sites:
            if not site.fragments or site.timeout is None:
                continue
            seconds = self.seconds(site.timeout)
            if seconds is None:
                found.append(self._where(
                    site, site.due(),
                    f"with `timeout={_text(site.timeout)}`, which the lint cannot read as "
                    f"seconds to compare against the {FLOOR_SECONDS} s floor",
                ))
            elif seconds < FLOOR_SECONDS:
                found.append(self._where(
                    site, site.due(),
                    f"with `timeout={_text(site.timeout)}` ({seconds} s), below the "
                    f"{FLOOR_SECONDS} s floor",
                ))
        return found

    def unlisted_opaque_helpers(self):
        """`exec_bash` calls whose command is a parameter and whose helper is unlisted."""
        found = []
        for site in self.opaque_sites():
            if site.function not in OPAQUE_COMMAND_HELPERS:
                found.append(
                    f"{self.label}:{site.line}: `exec_bash` takes its command from "
                    f"{site.command!r}, a parameter of {site.function!r}, so the lint cannot "
                    f"see which step it runs and cannot check its budget; list {site.function!r} "
                    f"in OPAQUE_COMMAND_HELPERS with the `timeout=` it passes itself"
                )
        return found

    def stale_opaque_helpers(self):
        """Allowlist entries that no longer describe the calls they were written for."""
        found = []
        for function, (expected, _reason) in OPAQUE_COMMAND_HELPERS.items():
            count = sum(1 for site in self.opaque_sites() if site.function == function)
            if count != expected:
                found.append(
                    f"{function!r} is listed in OPAQUE_COMMAND_HELPERS for {expected} "
                    f"`exec_bash` call(s), but the harness has {count}: an entry that "
                    f"outlives or undercounts its helper would silently cover a new call"
                )
        return found


class TestHarnessTimeouts(unittest.TestCase):
    """Every heavy `exec_bash` in the harness names the budget it needs."""

    @classmethod
    def setUpClass(cls):
        cls.source = HARNESS.read_text(encoding="utf-8")
        cls.lint = HarnessTimeoutLint(
            cls.source, HARNESS, HARNESS_LABEL, namespace=vars(multi_node),
        )

    def test_the_analysis_reaches_the_steps_it_is_about(self):
        # A lint that resolves nothing finds nothing and passes, so the shapes
        # that hide a step are asserted here as findings rather than trusted.
        self.assertTrue(
            {"node add", "node reapply"} <= self.lint.observed_fragments(),
            "the parse lost a step the harness runs: it saw only "
            f"{sorted(self.lint.observed_fragments())}",
        )
        self.assertTrue(
            any(site.helper for site in self.lint.sites),
            "no call was read through a helper name, so a method that returns the "
            "operator's command would escape the check that the step names a budget",
        )

    def test_every_heavy_step_names_its_own_budget(self):
        self.assertEqual(
            self.lint.missing_timeout(), [],
            "a Worker registration, re-provision or install was left on the probe "
            "default; the harness then reports its own timeout as a product failure",
        )

    def test_no_heavy_step_is_budgeted_below_the_floor(self):
        self.assertEqual(self.lint.below_floor(), [])

    def test_a_helper_that_takes_its_command_as_a_parameter_is_listed(self):
        self.assertEqual(self.lint.unlisted_opaque_helpers(), [])
        self.assertEqual(self.lint.stale_opaque_helpers(), [])


SYNTHETIC_HEADER = """\
import subprocess

WORKER_MIGRATION_TIMEOUT_ONE_RUN_SECONDS = 1200
DUPLICATE_ADD_TIMEOUT_SECONDS = 300


class Podman:
    def exec_bash(self, name, script, check=True, input_text=None, timeout=300):
        return subprocess.run(["podman", "exec", name, "bash", "-lc", script], timeout=timeout)


def node_reapply_script(name):
    return f"bash /repo/gowave-auto.sh node reapply {name}\\n"


def node_add_script(name):
    return f"bash /repo/gowave-auto.sh node add {name}\\n"


def case(podman):
"""

# The synthetic sources name the same budgets the harness does, so a control can
# exercise the floor rule instead of tripping over an unresolvable constant.
SYNTHETIC_NAMES = {
    "WORKER_MIGRATION_TIMEOUT_ONE_RUN_SECONDS": 1200,
    "DUPLICATE_ADD_TIMEOUT_SECONDS": 300,
}


def lint_synthetic(body, namespace=None):
    source = textwrap.dedent(SYNTHETIC_HEADER + textwrap.indent(textwrap.dedent(body), "    "))
    return HarnessTimeoutLint(source, Path("synthetic.py"), "synthetic.py",
                             namespace=namespace if namespace is not None else SYNTHETIC_NAMES)


class TestTheLintIsNotFooled(unittest.TestCase):
    """Controls: the shapes that hide a step are reported, and the ones that do
    not are left alone."""

    def test_a_helper_that_supplies_the_budget_answers_for_its_callers(self):
        # The wrapper shape: the step runs inside a helper, and the helper — not
        # each of its call sites — is where the budget is named.
        lint = lint_synthetic("""
            def reapply(podman, container, name):
                return podman.exec_bash(container, node_reapply_script(name), check=False,
                                        timeout=WORKER_MIGRATION_TIMEOUT_ONE_RUN_SECONDS)

            return reapply
        """)
        self.assertEqual(lint.missing_timeout(), [])
        self.assertEqual(lint.below_floor(), [])

    def test_a_helper_that_wraps_the_step_without_a_budget_is_reported(self):
        lint = lint_synthetic("""
            def reapply(podman, container, name):
                return podman.exec_bash(container, node_reapply_script(name), check=False)
        """)
        problems = lint.missing_timeout()
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("'case.reapply'", problems[0])

    def test_a_step_named_in_the_command_is_reported(self):
        lint = lint_synthetic("""
            podman.exec_bash("master", "bash /repo/gowave-auto.sh node reapply w1", check=False)
        """)
        problems = lint.missing_timeout()
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("synthetic.py:", problems[0])
        self.assertIn("node reapply", problems[0])
        self.assertIn("gowave-auto.sh node reapply", problems[0])

    def test_a_step_behind_a_helper_is_reported(self):
        lint = lint_synthetic("""
            podman.exec_bash("master", node_reapply_script("w1"), check=False)
        """)
        self.assertEqual(len(lint.missing_timeout()), 1, lint.missing_timeout())

    def test_a_step_behind_a_closure_variable_is_reported(self):
        # The composed-mixed shape: the script is bound in the case and read by
        # the inner function that runs in a thread.
        lint = lint_synthetic("""
            script = node_reapply_script("w1")

            def run_retry():
                return podman.exec_bash("master", script, check=False)

            return run_retry
        """)
        self.assertEqual(len(lint.missing_timeout()), 1, lint.missing_timeout())

    def test_the_same_step_with_a_budget_is_left_alone(self):
        lint = lint_synthetic("""
            podman.exec_bash("master", node_reapply_script("w1"), check=False,
                             timeout=WORKER_MIGRATION_TIMEOUT_ONE_RUN_SECONDS)
        """)
        self.assertEqual(lint.missing_timeout(), [])
        self.assertEqual(lint.below_floor(), [])

    def test_a_budget_below_the_floor_is_reported(self):
        lint = lint_synthetic("""
            podman.exec_bash("master", "bash /repo/gowave-auto.sh node add w1", check=False,
                             timeout=300)
        """)
        problems = lint.below_floor()
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("below the 600 s floor", problems[0])

    def test_a_budget_the_lint_cannot_read_is_reported(self):
        lint = lint_synthetic("""
            podman.exec_bash("master", node_add_script("w1"), check=False,
                             timeout=budget_for("w1"))
        """)
        problems = lint.below_floor()
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("cannot read as seconds", problems[0])

    def test_an_explicit_none_is_a_missing_budget(self):
        lint = lint_synthetic("""
            podman.exec_bash("master", node_add_script("w1"), check=False, timeout=None)
        """)
        self.assertEqual(len(lint.missing_timeout()), 1, lint.missing_timeout())

    def test_a_step_reached_by_a_helper_name_owes_a_budget_but_not_the_floor(self):
        # The shipped shape: `host.node_add_script(...)` is a method in another
        # module, so only its name is readable here. The duplicate `node add`
        # that uses it is refused before it deploys anything and is capped at
        # the probe default on purpose.
        lint = lint_synthetic("""
            podman.exec_bash("master", podman.node_add_script("w1"), check=False,
                             timeout=DUPLICATE_ADD_TIMEOUT_SECONDS)
        """)
        self.assertEqual(lint.missing_timeout(), [])
        self.assertEqual(lint.below_floor(), [],
                         "a refused duplicate add is capped below the floor on purpose")
        unbudgeted = lint_synthetic("""
            podman.exec_bash("master", podman.node_add_script("w1"), check=False)
        """)
        self.assertEqual(len(unbudgeted.missing_timeout()), 1, unbudgeted.missing_timeout())

    def test_a_step_named_only_as_a_process_pattern_is_not_the_step(self):
        lint = lint_synthetic("""
            podman.exec_bash("master", "pkill -TERM -f 'gowave-auto.sh node reapply' || true",
                             check=False)
        """)
        self.assertEqual(lint.missing_timeout(), [])

    def test_the_pattern_exclusion_does_not_hide_a_step_in_the_same_command(self):
        lint = lint_synthetic("""
            podman.exec_bash(
                "master",
                "pkill -f 'gowave-auto.sh node reapply' ; "
                "bash /repo/gowave-auto.sh node reapply w1",
                check=False,
            )
        """)
        self.assertEqual(len(lint.missing_timeout()), 1, lint.missing_timeout())

    def test_a_command_argument_is_not_read_as_a_container_name(self):
        lint = lint_synthetic("""
            podman.exec_bash(["bash", "-lc", "true"],
                             "bash /repo/gowave-auto.sh node add w1", check=False)
        """)
        self.assertEqual(lint.sites, [],
                         "an argv is not a container name, so the call is not a step")

    def test_an_opaque_helper_must_be_listed(self):
        lint = lint_synthetic("""
            def read(script):
                return podman.exec_bash("master", script, check=False, timeout=1200)

            return read
        """)
        self.assertEqual(len(lint.opaque_sites()), 1)
        problems = lint.unlisted_opaque_helpers()
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("synthetic.py:", problems[0])
        self.assertIn("'case.read'", problems[0])


if __name__ == "__main__":
    unittest.main()
