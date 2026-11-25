import copy
import fcntl
import json
import os
from pathlib import Path
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
