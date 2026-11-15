#!/usr/bin/env python3
"""Suite nonroot: the policy a run ends in, and what the case watches it refuse.

``GATE-TEARDOWN`` writes a real mode-0600 configuration, loads it through the
product's own ``load_config`` and hands it to the product's own
``execute_teardown`` with real hook programs. These tests drive the case on both
contours and then damage one product behaviour at a time — preflight that stops
refusing, a PRESERVE that reconnects, a digest check that stops comparing, a
request that moves into ``argv``, a reply that is accepted without its fields, a
baseline comparison that always matches, a restore reported as ``PASS`` — so each
clause is held by the side it protects rather than by the case's own prose.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.live_vps import reporting as live_reporting  # noqa: E402
from tools.live_vps import teardown as live_teardown  # noqa: E402
from tools.podman_e2e import teardown  # noqa: E402
from tools.podman_e2e.runner import RunContext  # noqa: E402

TOPOLOGIES = ("aio", "multi-node")
REAL_RUN = subprocess.run


class TestTeardownCase(unittest.TestCase):
    """``GATE-TEARDOWN``: what it demonstrates and what it refuses to demonstrate away."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def context(self, topology):
        return RunContext(
            topology, Path(self.tmp.name), budget_seconds=300,
            run_id=teardown.RUN_ID.format(topology=topology),
        )

    def refuse(self, damage, topology="aio"):
        """Run the case with one product behaviour damaged, and return the refusal."""
        with damage():
            with self.assertRaises(AssertionError) as caught:
                teardown.case_teardown_policy(self.context(topology))
        return str(caught.exception)

    def test_the_case_holds_on_both_contours(self):
        for topology in TOPOLOGIES:
            with self.subTest(topology=topology):
                evidence = teardown.case_teardown_policy(self.context(topology))
                self.assertIn("unsupported in v1", evidence["destroy_refusal"])
                self.assertEqual(evidence["preserve_status"], "PASS")
                self.assertEqual(evidence["preflight_refusals"], 11)
                self.assertIn("SHA-256 mismatch", evidence["digest_at_execution"])
                self.assertEqual(evidence["hook_arguments"], 0)
                self.assertEqual(evidence["request_schema_version"], 1)
                self.assertEqual(
                    evidence["request_keys"],
                    "action,master,schema_version,test_run_id,worker",
                )
                self.assertEqual(evidence["restored_status"], "INCOMPLETE")
                self.assertEqual(evidence["baseline_comparison"], "MATCHED")
                self.assertEqual(evidence["pair_lock_reacquisition"], "NOT_IMPLEMENTED")
                self.assertEqual(evidence["ownership_comparison"], "NOT_IMPLEMENTED")
                self.assertEqual(evidence["baseline_change_named"], "swap_info")
                self.assertEqual(evidence["hook_failures"], 5)
                self.assertEqual(evidence["teardown_result_status"], "TEARDOWN_FAILED")
                self.assertEqual(evidence["teardown_junit_errors"], "1")

    def test_the_ownership_probe_says_which_of_its_two_answers_it_gave(self):
        """A hook owned by another user can only be made by a process that can
        hand a file to one, so the case records which branch it took rather than
        claiming a refusal it did not watch."""
        evidence = teardown.case_teardown_policy(self.context("aio"))
        self.assertIn(
            evidence["foreign_owner_probe"],
            ("refused: uid 65534", "unrun: creating a foreign-owned hook needs root"),
        )

    def test_preflight_that_accepts_a_destroy_policy_is_refused(self):
        def accept_anything(_path):
            return mock.MagicMock(test_teardown_policy="PRESERVE")

        refusal = self.refuse(
            lambda: mock.patch.object(teardown, "load_config", accept_anything),
        )
        self.assertIn("was accepted by configuration preflight", refusal)

    def test_a_preserve_that_consults_a_host_is_refused(self):
        real = live_teardown.execute_teardown

        def contacts_the_host(config, run_id, **kwargs):
            result = real(config, run_id, **kwargs)
            if result.get("policy") == "PRESERVE":
                kwargs["master_ssh"].master_ip
            return result

        refusal = self.refuse(
            lambda: mock.patch.object(
                teardown.live_teardown, "execute_teardown", contacts_the_host,
            ),
        )
        self.assertIn("the PRESERVE policy used the host", refusal)

    def test_a_preserve_record_that_restates_the_outcome_is_refused(self):
        real = live_teardown.execute_teardown

        def restates_the_run(config, run_id, **kwargs):
            result = real(config, run_id, **kwargs)
            if result.get("policy") == "PRESERVE":
                result["overall"] = "PASS"
            return result

        refusal = self.refuse(
            lambda: mock.patch.object(
                teardown.live_teardown, "execute_teardown", restates_the_run,
            ),
        )
        self.assertIn("restates the test outcome", refusal)

    def test_a_digest_that_stops_being_compared_is_refused(self):
        refusal = self.refuse(
            lambda: mock.patch.object(
                teardown.live_teardown, "validate_restore_hook",
                lambda _path, _digest: (True, None),
            ),
        )
        self.assertIn("hook whose bytes changed after preflight reported", refusal)

    def test_a_request_that_moves_into_argv_is_refused(self):
        def in_argv(args, **kwargs):
            return REAL_RUN([*args, "leak"], **kwargs)

        refusal = self.refuse(
            lambda: mock.patch.object(teardown.live_teardown.subprocess, "run", in_argv),
        )
        self.assertIn("in argv", refusal)

    def test_a_request_that_names_another_run_is_refused(self):
        def another_run(args, **kwargs):
            payload = json.loads(kwargs["input"])
            payload["test_run_id"] = "someone-else"
            return REAL_RUN(args, **{**kwargs, "input": json.dumps(payload)})

        refusal = self.refuse(
            lambda: mock.patch.object(
                teardown.live_teardown.subprocess, "run", another_run,
            ),
        )
        self.assertIn("the request names the run", refusal)

    def test_a_reply_from_a_host_that_was_not_restored_is_refused(self):
        real = live_teardown.execute_teardown

        def accepts_an_unrestored_host(config, run_id, **kwargs):
            result = real(config, run_id, **kwargs)
            if "did not report the master as restored" in str(result.get("error") or ""):
                return {**result, "status": "INCOMPLETE", "error": ""}
            return result

        refusal = self.refuse(
            lambda: mock.patch.object(
                teardown.live_teardown, "execute_teardown", accepts_an_unrestored_host,
            ),
        )
        self.assertIn("the hook answer was accepted", refusal)

    def test_a_baseline_comparison_that_always_matches_is_refused(self):
        refusal = self.refuse(
            lambda: mock.patch.object(
                teardown.live_teardown, "compare_captured_baseline",
                lambda _before, _after: (True, [], []),
            ),
        )
        self.assertIn("came back with swap enabled reported", refusal)

    def test_a_conforming_restore_reported_as_pass_is_refused(self):
        real = live_teardown.execute_teardown

        def passes_the_restore(config, run_id, **kwargs):
            result = real(config, run_id, **kwargs)
            if result.get("captured_baseline_comparison") == "MATCHED":
                return {**result, "status": "PASS"}
            return result

        refusal = self.refuse(
            lambda: mock.patch.object(
                teardown.live_teardown, "execute_teardown", passes_the_restore,
            ),
        )
        self.assertIn("may not pass while a lock pair", refusal)

    def test_a_failed_teardown_written_as_a_junit_pass_is_refused(self):
        def green(artifact_dir, cases, *args, **kwargs):
            return live_reporting.write_junit_report(
                artifact_dir,
                [{**case, "status": "PASS"} for case in cases],
                *args, **kwargs,
            )

        refusal = self.refuse(
            lambda: mock.patch.object(teardown, "write_junit_report", green),
        )
        self.assertIn("a CI reader sees only what this file says", refusal)


if __name__ == "__main__":
    unittest.main()
