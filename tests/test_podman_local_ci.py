#!/usr/bin/env python3
"""Suite nonroot: repository CI runs the runner unit tests with no credentials.

``LOCAL-01`` reads the workflow that claims it and then runs the command that
workflow runs, in an environment emptied of everything a credential could arrive
in. The suite takes seconds, so the case is driven here whole rather than quoted:
a green run of this module is a run of the same discovery CI performs.

Each half is then damaged on its own — a workflow that interpolates a secret, a
workflow that asks for write access, a discovery that fails, a dependency file
that names a credential — so the assertion behind each one is seen to hold.
"""
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import catalog, local_ci  # noqa: E402

TOPOLOGIES = ("multi-node",)

CASE = local_ci.case_ci_needs_no_credentials

EXPECTED_REFUSALS = {
    "workflow-interpolates-a-secret": "so the job it runs is not one that needs no secrets",
    "workflow-wants-write": "not read-only repository access",
    "discovery-fails": "the discovery the workflow runs exited",
    "requirements-name-a-token": "so the install step is not one a credential-free job could run",
    "two-jobs": "the workflow declares 2 jobs, not one",
    "environment-gated": "which is where an Environment secret would be supplied",
    "requirements-missing": "is missing, so the install step names a file that does not exist",
}

#: A workflow with the same job shape as the real one, so a damage is the one
#: thing it changes rather than a document that would be refused for another
#: reason first.
WORKFLOW_TEMPLATE = """\
name: live-vps-unit
on: [push, pull_request]
permissions:
  {permissions}
jobs:
  live-vps-unit-tests:
    runs-on: ubuntu-24.04
{job_extra}    steps:
      - uses: actions/checkout@v4
      - run: python3 -m pip install -r tools/requirements-live-vps.txt
      - run: python3 -m unittest discover -s tools/tests -p 'test_*.py'
{extra}"""


def _workflow(workdir, name, *, permissions="contents: read", extra="", job_extra=""):
    path = workdir / name
    path.write_text(
        WORKFLOW_TEMPLATE.format(
            permissions=permissions, extra=extra, job_extra=job_extra),
        encoding="utf-8")
    return path


def _two_job_workflow(workdir):
    path = workdir / "two-jobs.yml"
    path.write_text(
        "name: live-vps-unit\n"
        "on: [push]\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  first:\n"
        "    runs-on: ubuntu-24.04\n"
        "    steps:\n"
        "      - run: python3 -m unittest discover -s tools/tests -p 'test_*.py'\n"
        "  second:\n"
        "    runs-on: ubuntu-24.04\n"
        "    steps:\n"
        "      - run: true\n",
        encoding="utf-8")
    return path


def _failing_discovery():
    return [sys.executable, "-c", "raise SystemExit(3)"]


def _damages(workdir):
    requirements = REPO_ROOT / "tests" / "fixtures" / ".local-ci-damage-requirements.txt"
    requirements.write_text("requests==2.32.0\ngowave-token==1.0.0\n", encoding="utf-8")
    return {
        "workflow-interpolates-a-secret": [
            mock.patch.object(local_ci, "WORKFLOW", _workflow(
                workdir, "secrets.yml",
                extra="      - run: echo ${{ secrets.VPS_SSH_KEY }}\n",
            )),
        ],
        "workflow-wants-write": [
            mock.patch.object(local_ci, "WORKFLOW", _workflow(
                workdir, "write.yml", permissions="write-all")),
        ],
        "discovery-fails": [
            mock.patch.object(local_ci, "DISCOVERY", _failing_discovery()),
        ],
        "requirements-name-a-token": [
            mock.patch.object(local_ci, "REQUIREMENTS", requirements),
        ],
        "two-jobs": [
            mock.patch.object(local_ci, "WORKFLOW", _two_job_workflow(workdir)),
        ],
        "environment-gated": [
            mock.patch.object(local_ci, "WORKFLOW", _workflow(
                workdir, "environment.yml", job_extra="    environment: production\n")),
        ],
        "requirements-missing": [
            mock.patch.object(
                local_ci, "REQUIREMENTS",
                REPO_ROOT / "tests" / "fixtures" / ".absent-requirements.txt"),
        ],
    }, requirements


def run_case(topology="multi-node", damage=None, workdir=None):
    """Run the case, optionally with one damaged input; return (facts, refusal)."""
    patchers, requirements = _damages(workdir) if damage else ({}, None)
    installed = patchers.get(damage, []) if damage else []
    for patcher in installed:
        patcher.start()
    try:
        return CASE(object(), SimpleNamespace(topology=topology)), None
    except AssertionError as error:
        return None, str(error)
    finally:
        for patcher in reversed(installed):
            patcher.stop()
        if requirements is not None:
            requirements.unlink(missing_ok=True)


class TestLocalCiRegistration(unittest.TestCase):
    """The case is registered on the contour the catalog names for it."""

    def test_the_id_is_registered_with_its_own_callable(self):
        registry = catalog.driver_registry()
        self.assertIn(local_ci.LOCAL_CASE_ID, registry)
        # The claim is about repository CI, not about a contour, and the catalog
        # lists the requirement as multi-node; the case starts no container, so
        # a second registration would run the same discovery twice for one
        # sentence.
        self.assertEqual(set(registry[local_ci.LOCAL_CASE_ID]), set(TOPOLOGIES))
        for topology in TOPOLOGIES:
            self.assertEqual(
                registry[local_ci.LOCAL_CASE_ID][topology]["driver"],
                f"local_ci:{CASE.__name__}",
            )

    def test_the_catalog_entry_is_what_the_registry_derives(self):
        registry = catalog.driver_registry()
        entries = {entry["id"]: entry for entry in catalog.load_catalog()["cases"]}
        entry = entries[local_ci.LOCAL_CASE_ID]
        self.assertEqual(entry["driver_status"], "implemented")
        self.assertEqual(entry["drivers"], registry[local_ci.LOCAL_CASE_ID])


class TestLocalCiCase(unittest.TestCase):
    """The case holds here, and its facts are the claim the sentence makes."""

    def test_the_case_holds_on_its_contour(self):
        for topology in TOPOLOGIES:
            with self.subTest(topology=topology):
                facts, refusal = run_case(topology)
                self.assertIsNone(refusal)
                self.assertTrue(facts)

    def test_the_evidence_is_exactly_what_the_catalog_records(self):
        facts, _ = run_case()
        registry = catalog.driver_registry()
        self.assertEqual(
            sorted(facts), registry[local_ci.LOCAL_CASE_ID]["multi-node"]["evidence"])

    def test_the_workflow_claims_nothing_it_does_not_get(self):
        facts, _ = run_case()
        self.assertEqual(facts["workflow"], ".github/workflows/live-vps-unit.yml")
        self.assertEqual(facts["permissions"], "contents=read")
        self.assertEqual(facts["secrets_references"], 0)
        self.assertFalse(facts["environment_gated"])
        self.assertGreater(facts["requirements"], 0)

    def test_the_discovery_it_runs_passes_with_no_credential_in_the_environment(self):
        facts, _ = run_case()
        self.assertEqual(facts["suite_exit"], 0)
        self.assertTrue(facts["suite_ok"])
        self.assertRegex(facts["suite_summary"], r"^Ran \d+ tests")
        # The workstation may hold a forwarded agent socket; the run is asserted
        # to have been given none, and the evidence names what the parent had.
        self.assertEqual(
            facts["credential_variables_inherited"],
            ",".join(sorted(
                name for name in os.environ
                if name.startswith(local_ci.CREDENTIAL_PREFIXES))),
        )


class TestLocalCiDamage(unittest.TestCase):
    """Each half is damaged on its own and the case refuses for that reason."""

    def setUp(self):
        self.workdir = Path(tempfile.mkdtemp(prefix="gowave-local-01-test-"))
        self.addCleanup(shutil.rmtree, self.workdir, True)

    def assert_refused(self, damage):
        _, refusal = run_case(damage=damage, workdir=self.workdir)
        self.assertIsNotNone(refusal, f"{damage} did not make the case refuse")
        self.assertIn(EXPECTED_REFUSALS[damage], refusal)

    def test_a_workflow_that_interpolates_a_secret_is_refused(self):
        self.assert_refused("workflow-interpolates-a-secret")

    def test_a_workflow_that_asks_for_write_access_is_refused(self):
        self.assert_refused("workflow-wants-write")

    def test_a_discovery_that_fails_without_credentials_is_refused(self):
        self.assert_refused("discovery-fails")

    def test_a_dependency_file_that_names_a_credential_is_refused(self):
        self.assert_refused("requirements-name-a-token")

    def test_a_workflow_with_a_second_job_is_refused(self):
        self.assert_refused("two-jobs")

    def test_a_job_that_runs_in_a_github_environment_is_refused(self):
        self.assert_refused("environment-gated")

    def test_a_dependency_file_that_does_not_exist_is_refused(self):
        self.assert_refused("requirements-missing")


if __name__ == "__main__":
    unittest.main()
