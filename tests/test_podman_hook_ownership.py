#!/usr/bin/env python3
"""Suite nonroot: the deploy hook is removed only while the journal owns it.

``HOOK-02`` is decided by three shell functions in ``modules/nginx.sh`` and by
``tools/live_vps/teardown.py``, so the case drives them in a temporary tree and
reads back the manifest, the ownership record and the digests they wrote.

``HOOK-01`` drives the same preflight over what is already at the managed path —
a symlink whose bytes match the manifest, a symlink to a provider's file, a
directory, a FIFO, a file edited after its manifest, a file the manifest names
under another path, and a manifest that cannot be read at all — because a
manifest records that a transaction created a hook, not that what now sits there
is that hook.

Each clause is damaged on its own — a preflight that accepts an unowned hook, a
manifest that does not record the transaction as the creator, a rollback that
ignores the digest, a rollback that leaves the ownership record behind, a
``PRESERVE`` answer that claims a restored baseline, and a snapshot verdict that
says ``PASS`` — so every assertion is seen to fail for the reason it protects.
"""
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.live_vps import teardown  # noqa: E402
from tools.podman_e2e import catalog, hook_ownership  # noqa: E402

TOPOLOGIES = ("aio", "multi-node")

CASES = {
    hook_ownership.CASE_ID: hook_ownership.case_hook_is_removed_only_while_the_journal_owns_it,
    hook_ownership.HOOK_01: hook_ownership.case_preexisting_hook_is_never_adopted,
}

#: What each damage is meant to make the case say, so a probe that went red on an
#: unrelated assertion is not read as a held clause.
EXPECTED_REFUSALS = {
    "preflight-accepts-unowned": "an unowned hook was overwritten",
    "install-not-recorded": "the manifest does not record the transaction as the creator",
    "rollback-ignores-digest": "a hook edited after installation was not preserved",
    "record-outlives-the-hook": "the ownership record outlived the hook it named",
    "preserve-adds-a-foreign-field":
        "rather than the status, policy, message, residual state and two baseline denials it owns",
    "preserve-claims-a-restored-baseline": "PRESERVE claimed a baseline it never compared",
    "snapshot-claims-pass": "instead of INCOMPLETE",
}

EXPECTED_HOOK01_REFUSALS = {
    "manifest-adopts-a-symlink": "a symlink to the recorded bytes was adopted as the hook",
    "manifest-adopts-any-bytes": "a file edited after the manifest was adopted",
    "manifest-adopts-another-path": "a manifest naming another path adopted this hook",
    "manifest-failure-means-adopted": "an unreadable manifest was read as ownership",
    "preflight-accepts-any-existing-path": "an unmanaged hook was accepted",
    "preflight-accepts-a-symlinked-directory": "a symlinked hook directory was accepted",
}

_REAL_MODULE = hook_ownership.NGINX_MODULE
_REAL_TEARDOWN = teardown.execute_teardown


def _rewritten(workdir, old, new, expected):
    """A copy of the module with exactly ``expected`` occurrences rewritten."""
    body = _REAL_MODULE.read_text(encoding="utf-8")
    assert body.count(old) == expected, f"{old!r} occurs {body.count(old)} times, not {expected}"
    target = Path(workdir) / f"nginx-{len(list(Path(workdir).glob('nginx-*')))}.sh"
    target.write_text(body.replace(old, new), encoding="utf-8")
    return target


def _preflight_that_accepts_unowned(workdir):
    return _rewritten(
        workdir,
        '        echo "Error: Pre-existing unowned Certbot deploy hook found at $hook_file. '
        'Refusing to overwrite unmanaged host resource." >&2\n        return 1\n',
        '        echo "accepted an unowned hook" >&2\n        return 0\n',
        1,
    )


def _install_that_does_not_record(workdir):
    return _rewritten(workdir, '"created_by_tx": True', '"created_by_tx": False', 2)


def _rollback_that_ignores_the_digest(workdir):
    return _rewritten(workdir, 'if [[ "$current_sha" != "$recorded_sha" ]]; then',
                      "if false; then", 1)


def _rollback_that_keeps_the_record(workdir):
    return _rewritten(
        workdir,
        '    rm -f -- "$(deploy_hook_ownership_record "$recovery_root")" || {\n'
        '        echo "Error: Could not clear the deploy-hook ownership record after rollback." >&2\n'
        "        return 1\n"
        "    }\n",
        "    true\n",
        1,
    )


def _teardown_that(workdir, **overrides):
    """The product's teardown with one verdict edited, so the case must notice."""

    def patched(config, run_id, **kwargs):
        answer = _REAL_TEARDOWN(config, run_id, **kwargs)
        policy = getattr(config, "test_teardown_policy", "")
        if policy in overrides:
            answer = dict(answer)
            answer.update(overrides[policy])
        return answer

    return patched


def _hook_shape_damages(workdir):
    """One clause of the shape preflight edited per probe."""
    return {
        "manifest-adopts-a-symlink": [
            mock.patch.object(
                hook_ownership, "NGINX_MODULE",
                _rewritten(
                    workdir,
                    'if [[ -f "$manifest" && ! -L "$manifest" && -f "$hook_file" '
                    '&& ! -L "$hook_file" ]]; then',
                    'if [[ -f "$manifest" && ! -L "$manifest" && -f "$hook_file" ]]; then',
                    1,
                )),
        ],
        "manifest-adopts-any-bytes": [
            mock.patch.object(
                hook_ownership, "NGINX_MODULE",
                _rewritten(
                    workdir,
                    'd.get("sha256")==s else "0"',
                    'True else "0"',
                    1,
                )),
        ],
        "manifest-adopts-another-path": [
            mock.patch.object(
                hook_ownership, "NGINX_MODULE",
                _rewritten(
                    workdir,
                    'd.get("path")==h and d.get("sha256")==s',
                    'd.get("sha256")==s',
                    1,
                )),
        ],
        "manifest-failure-means-adopted": [
            mock.patch.object(
                hook_ownership, "NGINX_MODULE",
                _rewritten(
                    workdir,
                    '2>/dev/null || echo "0")',
                    '2>/dev/null || echo "1")',
                    1,
                )),
        ],
        "preflight-accepts-any-existing-path": [
            mock.patch.object(
                hook_ownership, "NGINX_MODULE",
                _rewritten(
                    workdir,
                    'if [[ -e "$hook_file" ]] || [[ -L "$hook_file" ]]; then',
                    "if false; then",
                    1,
                )),
        ],
        "preflight-accepts-a-symlinked-directory": [
            mock.patch.object(
                hook_ownership, "NGINX_MODULE",
                _rewritten(
                    workdir,
                    'if [[ -e "$hook_dir" && -L "$hook_dir" ]]; then',
                    "if false; then",
                    1,
                )),
        ],
    }


def _damages(workdir, case_id=hook_ownership.CASE_ID):
    if case_id == hook_ownership.HOOK_01:
        return _hook_shape_damages(workdir)
    return {
        "preflight-accepts-unowned": [
            mock.patch.object(hook_ownership, "NGINX_MODULE",
                              _preflight_that_accepts_unowned(workdir)),
        ],
        "install-not-recorded": [
            mock.patch.object(hook_ownership, "NGINX_MODULE",
                              _install_that_does_not_record(workdir)),
        ],
        "rollback-ignores-digest": [
            mock.patch.object(hook_ownership, "NGINX_MODULE",
                              _rollback_that_ignores_the_digest(workdir)),
        ],
        "record-outlives-the-hook": [
            mock.patch.object(hook_ownership, "NGINX_MODULE",
                              _rollback_that_keeps_the_record(workdir)),
        ],
        "preserve-adds-a-foreign-field": [
            mock.patch.object(teardown, "execute_teardown",
                              _teardown_that(workdir, PRESERVE={"packages_restored": True})),
        ],
        "preserve-claims-a-restored-baseline": [
            mock.patch.object(teardown, "execute_teardown",
                              _teardown_that(workdir, PRESERVE={"restored_baseline": True})),
        ],
        "snapshot-claims-pass": [
            mock.patch.object(teardown, "execute_teardown",
                              _teardown_that(workdir, RESTORE_SNAPSHOT={"status": "PASS"})),
        ],
    }


def run_case(case_id, damage=None, workdir=None):
    """Run the case, optionally with one damaged behaviour; return (facts, refusal)."""
    patchers = _damages(workdir, case_id)[damage] if damage else []
    for patcher in patchers:
        patcher.start()
    try:
        return CASES[case_id](object(), SimpleNamespace(topology="aio")), None
    except AssertionError as error:
        return None, str(error)
    finally:
        for patcher in reversed(patchers):
            patcher.stop()


class TestHookOwnershipRegistration(unittest.TestCase):
    """The id is registered on both contours with its own callable."""

    def test_the_id_is_registered_on_both_contours(self):
        registry = catalog.driver_registry()
        for case_id, function in CASES.items():
            with self.subTest(case=case_id):
                self.assertIn(case_id, registry)
                self.assertEqual(set(registry[case_id]), set(TOPOLOGIES))
                for topology in TOPOLOGIES:
                    self.assertEqual(
                        registry[case_id][topology]["driver"],
                        f"hook_ownership:{function.__name__}",
                    )

    def test_the_catalog_entry_is_what_the_registry_derives(self):
        registry = catalog.driver_registry()
        entries = {entry["id"]: entry for entry in catalog.load_catalog()["cases"]}
        for case_id in CASES:
            with self.subTest(case=case_id):
                entry = entries[case_id]
                self.assertEqual(entry["driver_status"], "implemented")
                self.assertEqual(entry["drivers"], registry[case_id])
                self.assertEqual(sorted(entry["topology"]), sorted(TOPOLOGIES))


class TestHookOwnershipCase(unittest.TestCase):
    """The case holds on both contours and its evidence is what the catalog records."""

    def test_every_case_holds_on_both_contours(self):
        for case_id in CASES:
            for topology in TOPOLOGIES:
                with self.subTest(case=case_id, topology=topology):
                    facts = CASES[case_id](object(), SimpleNamespace(topology=topology))
                    self.assertTrue(facts)

    def test_the_evidence_set_is_what_the_catalog_records(self):
        registry = catalog.driver_registry()
        for case_id in CASES:
            with self.subTest(case=case_id):
                facts, refusal = run_case(case_id)
                self.assertIsNone(refusal)
                self.assertEqual(sorted(facts), registry[case_id]["aio"]["evidence"])

    def test_the_unowned_hook_blocks_the_install_before_mutation(self):
        facts, refusal = run_case(hook_ownership.CASE_ID)
        self.assertIsNone(refusal)
        self.assertTrue(facts["unowned_hook_refused"])
        self.assertTrue(facts["refusal_names_the_unmanaged_resource"])
        self.assertTrue(facts["unowned_hook_unchanged"])
        self.assertEqual(facts["manifests_before_any_install"], 0)

    def test_the_installed_hook_is_owned_and_recognised_again(self):
        facts, refusal = run_case(hook_ownership.CASE_ID)
        self.assertIsNone(refusal)
        self.assertEqual(facts["install_exit"], 0)
        self.assertTrue(facts["manifest_created_by_tx"])
        self.assertTrue(facts["manifest_names_the_hook"])
        self.assertTrue(facts["manifest_digest_matches_the_hook"])
        self.assertTrue(facts["ownership_record_present"])
        self.assertEqual(facts["repeat_install_exit"], 0)

    def test_a_modified_hook_is_preserved_and_the_rollback_says_so(self):
        facts, refusal = run_case(hook_ownership.CASE_ID)
        self.assertIsNone(refusal)
        self.assertTrue(facts["edited_hook_preserved"])
        self.assertTrue(facts["rollback_of_edited_hook_refused"])

    def test_an_untouched_hook_and_its_record_are_both_removed(self):
        facts, refusal = run_case(hook_ownership.CASE_ID)
        self.assertIsNone(refusal)
        self.assertTrue(facts["owned_hook_removed"])
        self.assertTrue(facts["ownership_record_cleared"])

    def test_preserve_claims_no_baseline_and_the_snapshot_path_says_incomplete(self):
        facts, refusal = run_case(hook_ownership.CASE_ID)
        self.assertIsNone(refusal)
        self.assertEqual(facts["preserve_status"], "PASS")
        self.assertEqual(
            facts["preserve_fields"],
            "clean_baseline_eligible,message,policy,residual_state,restored_baseline,status")
        self.assertFalse(facts["preserve_claims_restored_baseline"])
        self.assertIn("not a restoration of the original OS baseline",
                      facts["preserve_message"])
        self.assertIn("not eligible for another clean-baseline run",
                      facts["preserve_message"])
        self.assertEqual(facts["snapshot_status"], "INCOMPLETE")
        self.assertEqual(facts["snapshot_baseline_comparison"], "MATCHED")
        self.assertEqual(facts["snapshot_pair_lock_reacquisition"], "NOT_IMPLEMENTED")
        self.assertEqual(facts["snapshot_ownership_comparison"], "NOT_IMPLEMENTED")


class TestHookOwnershipDamage(unittest.TestCase):
    """Each clause is damaged on its own and the case refuses for that reason."""

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory(prefix="gowave-hook-test-")
        self.addCleanup(self._directory.cleanup)
        self.workdir = Path(self._directory.name)

    def assert_refused(self, damage):
        _, refusal = run_case(hook_ownership.CASE_ID, damage=damage, workdir=self.workdir)
        self.assertIsNotNone(refusal, f"{damage} did not make HOOK-02 refuse")
        self.assertIn(EXPECTED_REFUSALS[damage], refusal)

    def test_a_preflight_that_accepts_an_unowned_hook_is_refused(self):
        self.assert_refused("preflight-accepts-unowned")

    def test_a_manifest_that_denies_creating_the_hook_is_refused(self):
        self.assert_refused("install-not-recorded")

    def test_a_rollback_that_ignores_the_digest_is_refused(self):
        self.assert_refused("rollback-ignores-digest")

    def test_a_record_that_outlives_the_hook_is_refused(self):
        self.assert_refused("record-outlives-the-hook")

    def test_a_preserve_answer_with_an_extra_field_is_refused(self):
        self.assert_refused("preserve-adds-a-foreign-field")

    def test_a_preserve_answer_that_claims_a_baseline_is_refused(self):
        self.assert_refused("preserve-claims-a-restored-baseline")

    def test_a_snapshot_verdict_of_pass_is_refused(self):
        self.assert_refused("snapshot-claims-pass")


class TestHookShapeCase(unittest.TestCase):
    """Every shape at the managed path is refused and left as it was found."""

    def test_no_shape_but_the_recorded_file_is_adopted(self):
        facts, refusal = run_case(hook_ownership.HOOK_01)
        self.assertIsNone(refusal)
        for clause in (
            "symlink_matching_refused",
            "symlink_foreign_refused",
            "directory_refused",
            "fifo_refused",
            "edited_file_refused",
            "manifest_for_another_path_refused",
            "unreadable_manifest_refused",
            "unmanaged_file_refused",
            "hook_directory_symlink_refused",
        ):
            with self.subTest(clause=clause):
                self.assertTrue(facts[clause], clause)
        self.assertTrue(facts["recorded_file_adopted"])

    def test_every_refused_shape_survives_with_its_bytes_and_metadata(self):
        facts, refusal = run_case(hook_ownership.HOOK_01)
        self.assertIsNone(refusal)
        for clause in (
            "symlink_target_intact",
            "symlink_foreign_target_intact",
            "directory_still_a_directory",
            "fifo_still_a_fifo",
            "edited_file_bytes_intact",
            "unmanaged_file_intact",
            "no_manifest_published_on_refusal",
        ):
            with self.subTest(clause=clause):
                self.assertTrue(facts[clause], clause)

    def test_the_refusal_names_the_unmanaged_resource(self):
        facts, refusal = run_case(hook_ownership.HOOK_01)
        self.assertIsNone(refusal)
        self.assertTrue(facts["refusal_names_the_unmanaged_resource"])


class TestHookShapeDamage(unittest.TestCase):
    """Each shape clause is damaged on its own and the case refuses for that reason."""

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory(prefix="gowave-hook-shape-")
        self.addCleanup(self._directory.cleanup)
        self.workdir = Path(self._directory.name)

    def assert_refused(self, damage):
        _, refusal = run_case(hook_ownership.HOOK_01, damage=damage, workdir=self.workdir)
        self.assertIsNotNone(refusal, f"{damage} did not make HOOK-01 refuse")
        self.assertIn(EXPECTED_HOOK01_REFUSALS[damage], refusal)

    def test_a_manifest_that_adopts_a_symlink_is_refused(self):
        self.assert_refused("manifest-adopts-a-symlink")

    def test_a_manifest_that_adopts_any_bytes_is_refused(self):
        self.assert_refused("manifest-adopts-any-bytes")

    def test_a_manifest_that_adopts_another_path_is_refused(self):
        self.assert_refused("manifest-adopts-another-path")

    def test_a_verification_whose_failure_adopts_is_refused(self):
        self.assert_refused("manifest-failure-means-adopted")

    def test_a_preflight_that_accepts_any_existing_path_is_refused(self):
        self.assert_refused("preflight-accepts-any-existing-path")

    def test_a_preflight_that_accepts_a_symlinked_directory_is_refused(self):
        self.assert_refused("preflight-accepts-a-symlinked-directory")


if __name__ == "__main__":
    unittest.main()
