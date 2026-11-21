"""Suite nonroot: the located failure report (`ERR` trap) of `gowave-auto.sh`.

The handler is driven from the shipped text rather than re-implemented, so a
change to its wording or to its disarm order is what the test reads back.
"""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GOWAVE_AUTO = REPO_ROOT / "gowave-auto.sh"


def bash(script):
    return subprocess.run(
        ["bash", "-c", script],
        text=True,
        capture_output=True,
        env=dict(os.environ),
        timeout=120,
    )


def handler_text():
    text = GOWAVE_AUTO.read_text(encoding="utf-8")
    start = text.index("on_error() {")
    return text[start:text.index("\n}\n", start) + 2]


def harness(body):
    """The shipped handler, armed, around a body written by the test."""
    return (
        'set -Eeuo pipefail\nCURRENT_STEP="unassigned"\n'
        + handler_text()
        + "\ntrap 'on_error' ERR\n"
        + body
    )


class TestFailureReport(unittest.TestCase):
    def test_a_failed_step_names_the_step_the_command_and_the_status(self):
        result = bash(
            harness('CURRENT_STEP="install: prerequisites"\nfalse\n')
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('step "install: prerequisites"', result.stderr)
        self.assertIn('failed running "false"', result.stderr)
        self.assertIn("(exit 1)", result.stderr)

    def test_the_report_is_printed_once(self):
        result = bash(
            harness(
                'CURRENT_STEP="install: nginx"\n'
                "install_nginx() {\n    false\n}\n"
                "install_nginx\n"
            )
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr.count("Error: step"), 1, result.stderr)

    def test_a_successful_run_prints_no_report(self):
        result = bash(harness('CURRENT_STEP="install: panel"\ntrue\necho done\n'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout.strip(), "done")

    def test_the_handler_reports_and_does_not_compensate(self):
        # Compensation belongs to the step that owns the transaction; a handler
        # that rolled back again would act on a host the step had already put
        # back. The handler is text, so the prohibition is read from it.
        body = handler_text()
        for forbidden in ("rollback", "restore", "compensate"):
            self.assertNotIn(forbidden, body.lower(), f"the handler must not call {forbidden}")
        self.assertLess(body.index("trap - ERR"), body.index("printf"),
                        "the handler must disarm before it reports")

    def test_a_step_that_already_rolled_back_is_not_compensated_twice(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "compensation"
            result = bash(
                harness(
                    'CURRENT_STEP="install: certificates"\n'
                    f'compensate() {{ echo done >> {marker}; }}\n'
                    "acquire_certificate() {\n"
                    "    compensate || true\n"
                    "    false\n"
                    "}\n"
                    "acquire_certificate\n"
                )
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(
                marker.read_text(encoding="utf-8").splitlines(),
                ["done"],
                "the compensation ran again",
            )
            self.assertEqual(result.stderr.count("Error: step"), 1, result.stderr)

    def test_the_command_substitution_stays_silent_and_keeps_its_status(self):
        result = bash(
            harness(
                'CURRENT_STEP="install: panel"\n'
                "if value=$(false); then echo unexpected; else echo refused; fi\n"
            )
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "refused")
        self.assertEqual(result.stderr, "", "a subshell must not report the phase itself")

    def test_every_install_phase_is_labelled(self):
        script = GOWAVE_AUTO.read_text(encoding="utf-8")
        start = script.index("cmd_install() {")
        body = script[start:script.index("\n}\n", start)]
        phases = body.split("# Step ")[1:]
        self.assertGreaterEqual(len(phases), 8, "the numbered phases disappeared")
        for phase in phases:
            label = phase.split("\n", 1)[0]
            self.assertIn('CURRENT_STEP="install: ', phase,
                          f"step {label} is not labelled")

    def test_the_command_name_labels_the_run_before_the_first_phase(self):
        script = GOWAVE_AUTO.read_text(encoding="utf-8")
        router = script[script.index("# CLI Entrypoint Router"):]
        self.assertIn('CURRENT_STEP="${1:-unknown command}"', router)
        self.assertLess(router.index('CURRENT_STEP="${1:-unknown command}"'),
                        router.index("cmd_install"))


if __name__ == "__main__":
    unittest.main()
