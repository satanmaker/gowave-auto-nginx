#!/usr/bin/env python3
"""Suite nonroot: a run that skipped the Data Plane never reports PASS.

``DP-14`` is decided by three product functions and one inline block, so all four
are driven here rather than quoted: the traffic suite's verdict, the JUnit
document a CI reader sees, ``result.json``'s own record, and the container
contour's aggregation. The runner's phase aggregation is the one piece with no
callable seam, so its shape is read from its own source — the quote is the
decision, not a comment beside it.

Each of those is then damaged on its own: a verdict that ignores the switch, a
runner whose quote moved, a container aggregate that rewards a skip, a runner
that never passes its own switch to the traffic gate, a JUnit document that hides
the skipped case.
"""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import catalog, preflight_cases, skip_policy  # noqa: E402

TOPOLOGIES = ("aio", "multi-node")

CASE = skip_policy.case_skipped_traffic_is_never_pass

DECISION = (
    'elif any(s in ("INCOMPLETE", "SKIP", "UNKNOWN", "RUNNING") for s in phase_statuses):\n'
    '            overall_status = "INCOMPLETE"\n'
    "        else:\n"
    '            overall_status = "PASS"'
)

EXPECTED_REFUSALS = {
    "switch-ignored": "so skipping the Data Plane could end in a verdict the sentence forbids",
    "decision-moved": "the runner no longer aggregates a SKIP phase into INCOMPLETE",
    "container-rewards-skip": "so the container contour would reward the skip the live sentence refuses",
    "runner-ignores-switch": "does not pass its own TEST_TRAFFIC_VERIFICATION to the traffic gate",
    "junit-hides-the-skip": "so a CI reader would not see the case the sentence names",
}


def _verdict_that_ignores_the_switch(**_kwargs):
    return "PASS"


def _container_aggregate_that_rewards_a_skip(_results):
    return skip_policy.PASS


def _descending(_path, *anchors):
    return list(range(len(anchors)))[::-1]


def _junit_without_the_skip(artifacts, _cases):
    path = Path(artifacts) / "junit.xml"
    path.write_text(
        '<testsuite tests="9" failures="0" errors="0" skipped="0"></testsuite>',
        encoding="utf-8",
    )
    return path


def _runner_without_the_skip_branch(workdir):
    text = skip_policy.RUNNER.read_text(encoding="utf-8")
    damaged = text.replace(DECISION, 'overall_status = "PASS"', 1)
    if damaged == text:
        raise AssertionError("the decision the case quotes is not in the runner verbatim")
    path = workdir / "test_live_vps.py"
    path.write_text(damaged, encoding="utf-8")
    return path


def _damages(workdir):
    return {
        "switch-ignored": [
            mock.patch.object(
                skip_policy, "evaluate_traffic_suite_status", _verdict_that_ignores_the_switch),
        ],
        "decision-moved": [
            mock.patch.object(
                skip_policy, "RUNNER", _runner_without_the_skip_branch(workdir)),
        ],
        "container-rewards-skip": [
            mock.patch.object(skip_policy, "overall_status", _container_aggregate_that_rewards_a_skip),
        ],
        "runner-ignores-switch": [
            mock.patch.object(preflight_cases, "_source_order", _descending),
        ],
        "junit-hides-the-skip": [
            mock.patch.object(skip_policy, "write_junit_report", _junit_without_the_skip),
        ],
    }


def run_case(topology="aio", damage=None, workdir=None):
    """Run the case, optionally with one damaged behaviour; return (facts, refusal)."""
    patchers = _damages(workdir)[damage] if damage else []
    for patcher in patchers:
        patcher.start()
    try:
        return CASE(object(), SimpleNamespace(topology=topology)), None
    except AssertionError as error:
        return None, str(error)
    finally:
        for patcher in reversed(patchers):
            patcher.stop()


class TestSkipPolicyRegistration(unittest.TestCase):
    """The case is registered on both contours, and its evidence derives."""

    def test_the_id_is_registered_on_both_contours_with_its_own_callable(self):
        registry = catalog.driver_registry()
        self.assertIn(skip_policy.DP14_CASE_ID, registry)
        self.assertEqual(set(registry[skip_policy.DP14_CASE_ID]), set(TOPOLOGIES))
        for topology in TOPOLOGIES:
            self.assertEqual(
                registry[skip_policy.DP14_CASE_ID][topology]["driver"],
                f"skip_policy:{CASE.__name__}",
            )

    def test_the_catalog_entry_is_what_the_registry_derives(self):
        registry = catalog.driver_registry()
        entries = {entry["id"]: entry for entry in catalog.load_catalog()["cases"]}
        entry = entries[skip_policy.DP14_CASE_ID]
        self.assertEqual(entry["driver_status"], "implemented")
        self.assertEqual(entry["drivers"], registry[skip_policy.DP14_CASE_ID])


class TestSkippedTrafficCase(unittest.TestCase):
    """The case holds here, and its facts are the verdict the sentence names."""

    def test_the_case_holds_on_both_contours(self):
        for topology in TOPOLOGIES:
            with self.subTest(topology=topology):
                facts, refusal = run_case(topology)
                self.assertIsNone(refusal)
                self.assertTrue(facts)

    def test_the_evidence_is_exactly_what_the_catalog_records(self):
        facts, _ = run_case()
        registry = catalog.driver_registry()
        self.assertEqual(
            sorted(facts), registry[skip_policy.DP14_CASE_ID]["aio"]["evidence"])

    def test_the_facts_separate_the_two_contours_and_both_counts(self):
        facts, _ = run_case()
        self.assertEqual(facts["switch_off_status"], "INCOMPLETE")
        self.assertEqual(facts["switch_on_status"], "PASS")
        self.assertEqual(facts["skip_case_status"], "INCOMPLETE")
        self.assertEqual(facts["case_counts"], "8,10")
        self.assertEqual(facts["junit_skipped"], "1")
        self.assertEqual(facts["junit_failures"], "0")
        self.assertEqual(facts["junit_case_child"], "skipped")
        self.assertEqual(facts["junit_phase_child"], "error")
        self.assertEqual(facts["result_overall"], "INCOMPLETE")
        # The container contour is stricter than the live one, and the case says so
        # rather than pretending the two vocabularies are one.
        self.assertEqual(facts["container_skip_aggregate"], "FAIL")
        self.assertTrue(facts["runner_skip_branch_quoted"])
        self.assertTrue(facts["runner_reads_its_own_switch"])


class TestSkipPolicyDamage(unittest.TestCase):
    """Each clause is damaged on its own and the case refuses for that reason."""

    def setUp(self):
        self.workdir = Path(tempfile.mkdtemp(prefix="gowave-dp14-test-"))
        self.addCleanup(shutil.rmtree, self.workdir, True)

    def assert_refused(self, damage):
        _, refusal = run_case(damage=damage, workdir=self.workdir)
        self.assertIsNotNone(refusal, f"{damage} did not make the case refuse")
        self.assertIn(EXPECTED_REFUSALS[damage], refusal)

    def test_a_verdict_that_ignores_the_switch_is_refused(self):
        self.assert_refused("switch-ignored")

    def test_a_runner_whose_skip_branch_moved_is_refused(self):
        self.assert_refused("decision-moved")

    def test_a_container_aggregate_that_rewards_a_skip_is_refused(self):
        self.assert_refused("container-rewards-skip")

    def test_a_runner_that_never_passes_its_switch_is_refused(self):
        self.assert_refused("runner-ignores-switch")

    def test_a_junit_document_that_hides_the_skip_is_refused(self):
        self.assert_refused("junit-hides-the-skip")


if __name__ == "__main__":
    unittest.main()
