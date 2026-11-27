import copy
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from modules import deployment_state as state


class TestDeploymentState(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / 'deployment' / 'active.json'
        self.store = state.DeploymentStore(self.path, owner_uid=os.getuid())
        self.document = {
            'schema_version': 1, 'revision': 1, 'installer_revision': 'test-1',
            'operation_id': 'operation-1', 'kind': 'install', 'topology': 'aio',
            'language': 'ru', 'answers': {'primary_domain': 'panel.example.com'},
            'nodes': {'worker-1': {'name': 'Worker 1', 'ssh_port': 2222}},
            'reviewed_digest': None, 'checkpoints': {},
        }

    def test_roundtrip_and_private_permissions(self):
        saved = self.store.save(self.document, expected_revision=0)
        self.assertEqual(saved, self.store.load())
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.path.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.document['revision'], 1)

    def test_stale_revision_and_other_operation_refused(self):
        self.store.save(self.document, expected_revision=0)
        with self.assertRaises(state.StateConflict):
            self.store.save(self.document, expected_revision=0)
        changed = copy.deepcopy(self.document)
        changed['operation_id'] = 'operation-2'
        with self.assertRaises(state.StateConflict):
            self.store.save(changed, expected_revision=1)

    def test_concurrent_lock_refused(self):
        self.store.save(self.document, expected_revision=0)
        with (self.path.parent / '.lock').open('r+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(state.StateConflict):
                self.store.save(self.document, expected_revision=1)

    def test_failed_replace_preserves_old_draft_and_removes_scratch(self):
        original = self.store.save(self.document, expected_revision=0)
        changed = copy.deepcopy(original)
        changed['answers']['name'] = 'Changed'
        with mock.patch.object(state.os, 'replace', side_effect=OSError('injected')):
            with self.assertRaises(OSError):
                self.store.save(changed, expected_revision=1)
        self.assertEqual(original, self.store.load())
        self.assertEqual(list(self.path.parent.glob('*.tmp')), [])

    def test_failed_file_sync_preserves_old_draft(self):
        original = self.store.save(self.document, expected_revision=0)
        with mock.patch.object(state.os, 'fsync', side_effect=OSError('injected')):
            with self.assertRaises(OSError):
                self.store.save(original, expected_revision=1)
        self.assertEqual(original, self.store.load())

    def test_secret_fields_rejected_at_every_schema_level(self):
        for field in ('password', 'token', 'SECRET_KEY', 'private_key', 'raw_log'):
            for location in ('root', 'answers', 'node', 'checkpoint'):
                with self.subTest(field=field, location=location):
                    document = copy.deepcopy(self.document)
                    target = document
                    if location == 'answers':
                        target = document['answers']
                    elif location == 'node':
                        target = document['nodes']['worker-1']
                    elif location == 'checkpoint':
                        target = {'state': 'pending', 'stage': 'pending', 'attempt': 0}
                        document['checkpoints']['worker-1'] = target
                    target[field] = 'sensitive-fixture'
                    with self.assertRaises(state.StateError) as raised:
                        self.store.save(document, expected_revision=0)
                    self.assertNotIn('sensitive-fixture', str(raised.exception))
                    self.assertFalse(self.path.exists())

    def test_invalid_schema_values_rejected(self):
        for field, value in (
            ('schema_version', True), ('schema_version', 2), ('revision', -1),
            ('topology', 'other'), ('language', 'xx'), ('kind', 'shell'),
        ):
            with self.subTest(field=field, value=value):
                document = copy.deepcopy(self.document)
                document[field] = value
                with self.assertRaises(state.StateError):
                    state.validate(document)
        self.document['answers']['ssh_port'] = True
        with self.assertRaises(state.StateError):
            state.validate(self.document)

    def test_review_digest_invalidated_by_edit_not_checkpoint(self):
        self.document['reviewed_digest'] = state.plan_digest(self.document)
        self.document['checkpoints']['worker-1'] = {
            'state': 'running', 'stage': 'registration', 'attempt': 1,
        }
        state.validate(self.document)
        self.document['nodes']['worker-1']['name'] = 'Different'
        with self.assertRaises(state.StateError):
            state.validate(self.document)

    def test_symlink_file_and_parent_refused(self):
        self.path.parent.mkdir(mode=0o700)
        outside = Path(self.temporary.name) / 'outside.json'
        outside.write_text('untouched')
        self.path.symlink_to(outside)
        with self.assertRaises(OSError):
            self.store.save(self.document, expected_revision=0)
        self.assertEqual(outside.read_text(), 'untouched')
        alias = Path(self.temporary.name) / 'alias'
        alias.symlink_to(self.path.parent, target_is_directory=True)
        store = state.DeploymentStore(alias / 'active.json', owner_uid=os.getuid())
        with self.assertRaises(OSError):
            store.load()

    def test_insecure_permissions_and_wrong_owner_refused(self):
        self.store.save(self.document, expected_revision=0)
        self.path.chmod(0o644)
        with self.assertRaises(state.StateError):
            self.store.load()
        self.path.chmod(0o600)
        wrong_owner = state.DeploymentStore(self.path, owner_uid=os.getuid() + 1)
        with self.assertRaises(state.StateError):
            wrong_owner.load()
        self.path.parent.chmod(0o755)
        with self.assertRaises(state.StateError):
            self.store.load()

    def test_special_file_and_hardlink_refused(self):
        self.path.parent.mkdir(mode=0o700)
        os.mkfifo(self.path, 0o600)
        with self.assertRaises(state.StateError):
            self.store.load()
        self.path.unlink()
        self.store.save(self.document, expected_revision=0)
        os.link(self.path, self.path.parent / 'alias.json')
        with self.assertRaises(state.StateError):
            self.store.load()

    def test_corrupt_or_oversized_document_refused(self):
        self.store.save(self.document, expected_revision=0)
        self.path.write_text('{')
        with self.assertRaises(json.JSONDecodeError):
            self.store.load()
        self.path.write_text('x' * (1024 * 1024 + 1))
        with self.assertRaises(state.StateError):
            self.store.load()

    def test_relative_and_traversal_paths_refused(self):
        for path in ('relative.json', '/tmp/../active.json'):
            with self.subTest(path=path), self.assertRaises(state.StateError):
                state.DeploymentStore(path)


class TestDeploymentDraftCli(unittest.TestCase):
    """The wizard drives the draft through this command line, so the contract
    under test is the process boundary: one JSON document in, one out."""

    ROOT = Path(__file__).resolve().parents[1]

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / 'deployment' / 'active.json'
        self.plan = {
            'kind': 'install', 'topology': 'aio', 'language': 'ru',
            'installer_revision': 'test-1',
            'answers': {'primary_domain': 'panel.example.com', 'node_port': 3002},
            'nodes': {'node-1': {'name': 'Worker 1', 'ssh_port': 2222}},
        }

    def run_cli(self, *arguments, stdin=''):
        environment = dict(os.environ, PYTHONPATH=str(self.ROOT))
        return subprocess.run(
            [sys.executable, '-m', 'modules.deployment_state', '--path', str(self.path), *arguments],
            input=stdin, text=True, capture_output=True, env=environment, check=False,
        )

    def plan_cli(self, plan, *arguments):
        return self.run_cli('--plan', *arguments, stdin=json.dumps(plan))

    def test_load_reports_an_absent_draft_without_a_traceback(self):
        result = self.run_cli('--load')
        self.assertEqual(result.returncode, state.EXIT_ABSENT)
        self.assertEqual(result.stdout, '')
        self.assertNotIn('Traceback', result.stderr)

    def test_plan_is_restored_with_its_review_and_checkpoints(self):
        created = self.plan_cli(self.plan, '--reviewed')
        self.assertEqual(created.returncode, state.EXIT_OK, created.stderr)
        document = json.loads(created.stdout)
        self.assertEqual(document['revision'], 1)
        self.assertEqual(document['reviewed_digest'], state.plan_digest(document))

        marked = self.run_cli('--checkpoint', 'node-1', stdin=json.dumps(
            {'state': 'verified', 'stage': 'complete', 'attempt': 1, 'node_uuid': '3d5c9a71-0000-4000-8000-000000000000'}))
        self.assertEqual(marked.returncode, state.EXIT_OK, marked.stderr)

        loaded = self.run_cli('--load')
        self.assertEqual(loaded.returncode, state.EXIT_OK, loaded.stderr)
        restored = json.loads(loaded.stdout)
        self.assertEqual(restored['revision'], 2)
        self.assertEqual(restored['checkpoints']['node-1']['state'], 'verified')
        self.assertEqual(restored['answers'], self.plan['answers'])

        corrected = dict(self.plan, answers=dict(self.plan['answers'], primary_domain='new.example.com'))
        rewritten = self.plan_cli(corrected)
        self.assertEqual(rewritten.returncode, state.EXIT_OK, rewritten.stderr)
        edited = json.loads(rewritten.stdout)
        self.assertIsNone(edited['reviewed_digest'])
        self.assertEqual(edited['checkpoints']['node-1']['state'], 'verified')
        self.assertEqual(edited['operation_id'], document['operation_id'])

        reviewed = self.plan_cli(corrected, '--reviewed')
        self.assertEqual(json.loads(reviewed.stdout)['reviewed_digest'], state.plan_digest(json.loads(reviewed.stdout)))

    def test_a_plan_from_another_installer_revision_is_refused(self):
        self.assertEqual(self.plan_cli(self.plan).returncode, state.EXIT_OK)
        result = self.plan_cli(dict(self.plan, installer_revision='test-2'))
        self.assertEqual(result.returncode, state.EXIT_CONFLICT)
        self.assertIn('installer revision', result.stderr)

    def test_checkpoint_without_a_draft_is_reported_as_absent(self):
        result = self.run_cli('--checkpoint', 'panel', stdin=json.dumps({'state': 'running', 'stage': 'preflight', 'attempt': 1}))
        self.assertEqual(result.returncode, state.EXIT_ABSENT)
        self.assertFalse(self.path.exists())

    def test_checkpoint_of_an_unplanned_identity_is_refused(self):
        self.assertEqual(self.plan_cli(self.plan).returncode, state.EXIT_OK)
        result = self.run_cli('--checkpoint', 'node-9', stdin=json.dumps({'state': 'running', 'stage': 'preflight', 'attempt': 1}))
        self.assertEqual(result.returncode, state.EXIT_INVALID)
        self.assertIn('unknown checkpoint identity', result.stderr)

    def test_discard_is_idempotent_and_leaves_no_scratch_files(self):
        self.assertEqual(self.plan_cli(self.plan).returncode, state.EXIT_OK)
        self.assertEqual(self.run_cli('--discard').returncode, state.EXIT_OK)
        self.assertEqual(self.run_cli('--discard').returncode, state.EXIT_OK)
        self.assertEqual(self.run_cli('--load').returncode, state.EXIT_ABSENT)
        self.assertEqual([entry.name for entry in self.path.parent.iterdir()], ['.lock'])

    def test_save_needs_the_revision_it_read(self):
        result = self.run_cli('--save', stdin=json.dumps({'schema_version': 1}))
        self.assertEqual(result.returncode, state.EXIT_INVALID)
        self.assertIn('--expected-revision', result.stderr)

    def test_a_credential_in_the_plan_is_rejected_before_it_is_stored(self):
        plan = copy.deepcopy(self.plan)
        plan['answers']['password'] = 'not-a-place-for-this'
        result = self.plan_cli(plan)
        self.assertEqual(result.returncode, state.EXIT_INVALID)
        self.assertEqual(result.stdout, '')
        self.assertFalse(self.path.exists())

    def test_an_owner_the_current_user_does_not_hold_is_refused(self):
        result = self.run_cli('--load', '--owner-uid', str(os.geteuid() + 1))
        self.assertEqual(result.returncode, state.EXIT_INVALID)
        self.assertIn('current user', result.stderr)
