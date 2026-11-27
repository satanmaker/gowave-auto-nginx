import copy
import fcntl
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from modules import deployment_state as state
from modules import resume_reconcile


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

    # -- The resume expectation ----------------------------------------------
    #
    # A resume may not replay a saved verdict, so it asks the store what the
    # checkpoint recorded and compares that with the Panel. These cases pin the
    # recorded half of that comparison: the identity, profile, Host UUIDs and
    # domains the draft owns, and nothing filled in from the live answer.

    def test_expectation_prints_the_identity_the_checkpoint_owns(self):
        self.assertEqual(self.plan_cli(self.plan).returncode, state.EXIT_OK)
        marked = self.run_cli('--checkpoint', 'node-1', stdin=json.dumps({
            'state': 'verified', 'stage': 'complete', 'attempt': 1,
            'node_uuid': '3d5c9a71-0000-4000-8000-000000000000',
            'profile_uuid': '3d5c9a71-0000-4000-8000-000000000001',
            'host_uuids': ['3d5c9a71-0000-4000-8000-000000000002'],
        }))
        self.assertEqual(marked.returncode, state.EXIT_OK, marked.stderr)
        result = self.run_cli('--expectation', 'node-1')
        self.assertEqual(result.returncode, state.EXIT_OK, result.stderr)
        expectation = json.loads(result.stdout)
        self.assertEqual(expectation['component'], 'node-1')
        self.assertEqual(expectation['kind'], 'node')
        recorded = expectation['recorded']
        self.assertEqual(recorded['node_uuid'], '3d5c9a71-0000-4000-8000-000000000000')
        self.assertEqual(recorded['profile_uuid'], '3d5c9a71-0000-4000-8000-000000000001')
        self.assertEqual(recorded['host_uuids'], ['3d5c9a71-0000-4000-8000-000000000002'])
        self.assertEqual(recorded['node_name'], 'Worker 1')
        self.assertEqual(recorded['installer_revision'], 'test-1')
        self.assertEqual(recorded['state'], 'verified')
        self.assertEqual(recorded['attempt'], 1)

    def test_expectation_names_the_domains_the_plan_answered(self):
        plan = dict(self.plan, answers={
            'primary_domain': 'panel.example.com',
            'reality_domain': 'cdn.example.com',
            'vision_domain': 'vision.example.com',
        })
        self.assertEqual(self.plan_cli(plan).returncode, state.EXIT_OK)
        self.assertEqual(self.run_cli('--checkpoint', 'panel', stdin=json.dumps({
            'state': 'verified', 'stage': 'complete', 'attempt': 1})).returncode, state.EXIT_OK)
        expectation = json.loads(self.run_cli('--expectation', 'panel').stdout)
        self.assertEqual(expectation['kind'], 'panel')
        self.assertEqual(expectation['recorded']['host_domains'],
                         ['panel.example.com', 'cdn.example.com', 'vision.example.com'])

    def test_expectation_of_an_unrecorded_component_is_refused(self):
        self.assertEqual(self.plan_cli(self.plan).returncode, state.EXIT_OK)
        result = self.run_cli('--expectation', 'node-1')
        self.assertEqual(result.returncode, state.EXIT_INVALID)
        self.assertIn('checkpoint is absent', result.stderr)
        self.assertEqual(self.run_cli('--expectation', 'node-9').returncode, state.EXIT_INVALID)

    # -- The resume classifier -----------------------------------------------
    #
    # `modules.resume_reconcile` is the single comparison a resumed component
    # goes through. These cases drive it with recorded and live answers for
    # every class it can answer, so a change in the vocabulary fails here.

    OK_NODE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
    OTHER_NODE = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
    OK_HOST = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'

    def expectation(self, **recorded):
        base = {
            'state': 'verified', 'stage': 'complete', 'attempt': 1,
            'node_uuid': self.OK_NODE, 'profile_uuid': 'profile-ok',
            'inbound_uuids': ['inb-ok'], 'host_uuids': [self.OK_HOST],
            'node_name': 'ok-01',
            'host_domains': ['ok.example.com', 'cam-ok.example.com'],
            'installer_revision': 'test-1',
        }
        base.update(recorded)
        return {'component': 'node-1', 'kind': 'node', 'recorded': base}

    def live(self, **overrides):
        document = {
            'reachable': True, 'schema_version': 2, 'installer_revision': 'test-1',
            'nodes': [{
                'uuid': self.OK_NODE, 'name': 'ok-01',
                'configProfile': {
                    'activeConfigProfileUuid': 'profile-ok',
                    'activeInbounds': [{'uuid': 'inb-ok'}],
                },
            }],
            'hosts': [{
                'uuid': self.OK_HOST,
                'address': 'ok.example.com', 'sni': 'cam-ok.example.com',
                'inbound': {
                    'configProfileUuid': 'profile-ok',
                    'configProfileInboundUuid': 'inb-ok',
                },
                'nodes': [{'uuid': self.OK_NODE}],
            }],
            'profiles': [{'uuid': 'profile-ok', 'inbounds': ['inb-ok']}],
        }
        document.update(overrides)
        return document

    def security_report(self, host_id='machine-a', role='worker', status='verified'):
        controls = {}
        for name in ('firewall', 'ssh_protection', 'security_updates', 'dot'):
            controls[name] = {
                'policy': 'required',
                'status': status,
                'reason_code': 'OK' if status == 'verified' else 'CONTROL_FAILED',
                'recovery': 'not-needed' if status == 'verified' else 'verified',
                'evidence_codes': ['PROBE'],
            }
        return {
            'schema_version': 1,
            'host_id': host_id,
            'role': role,
            'installer_revision': 'test-1',
            'observed_at': datetime.now(timezone.utc).isoformat(),
            'controls': controls,
        }

    def test_a_recorded_component_the_panel_still_holds_is_a_match(self):
        verdict = resume_reconcile.classify(self.expectation(), self.live())
        self.assertEqual(verdict.status, 'match')
        self.assertEqual(verdict.action, 'keep')
        self.assertEqual(verdict.node_uuid, self.OK_NODE)

    def test_a_component_the_panel_no_longer_holds_is_missing(self):
        verdict = resume_reconcile.classify(
            self.expectation(), self.live(nodes=[], hosts=[]))
        self.assertEqual(verdict.status, 'missing')
        self.assertEqual(verdict.action, 'recreate')
        self.assertEqual(verdict.reason, 'node_absent')

    def test_a_present_node_with_another_association_is_drift(self):
        live = self.live()
        live['nodes'][0]['configProfile']['activeConfigProfileUuid'] = 'profile-other'
        live['profiles'].append({'uuid': 'profile-other', 'inbounds': ['inb-other']})
        verdict = resume_reconcile.classify(self.expectation(), live)
        self.assertEqual(verdict.status, 'drift')
        self.assertEqual(verdict.action, 'reapply')
        self.assertEqual(verdict.reason, 'profile_association_changed')
        self.assertEqual(verdict.node_uuid, self.OK_NODE,
                         'the re-apply lost the UUID it must write through')

    def test_a_state_schema_this_installer_cannot_serve_is_incompatible(self):
        verdict = resume_reconcile.classify(self.expectation(), self.live(schema_version=3))
        self.assertEqual(verdict.status, 'incompatible')
        self.assertEqual(verdict.action, 'stop')
        self.assertEqual(verdict.reason, 'state_schema_unsupported')
        self.assertIn('schema 3', verdict.detail)

    def test_a_checkpoint_without_an_identity_is_ambiguous(self):
        verdict = resume_reconcile.classify(self.expectation(node_uuid=''), self.live())
        self.assertEqual(verdict.status, 'ambiguous')
        self.assertEqual(verdict.reason, 'node_identity_unrecorded')

    def test_an_unreadable_panel_is_unreachable_and_not_missing(self):
        for live in (None, {'reachable': False, 'error': 'connection refused'}):
            with self.subTest(live=live):
                verdict = resume_reconcile.classify(self.expectation(), live)
                self.assertEqual(verdict.status, 'unreachable')
                self.assertEqual(verdict.action, 'retry')
                self.assertEqual(verdict.reason, 'panel_unreachable')

    def test_a_name_held_by_another_uuid_is_never_adopted_or_duplicated(self):
        live = self.live()
        live['nodes'] = [{
            'uuid': self.OTHER_NODE, 'name': 'ok-01',
            'configProfile': {
                'activeConfigProfileUuid': 'profile-other',
                'activeInbounds': [{'uuid': 'inb-other'}],
            },
        }]
        live['hosts'] = []
        verdict = resume_reconcile.classify(self.expectation(), live)
        self.assertEqual(verdict.status, 'ambiguous')
        self.assertEqual(verdict.reason, 'node_name_held')
        self.assertIn(self.OTHER_NODE, verdict.detail)
        self.assertEqual(verdict.node_uuid, '',
                         'a name collision must not be reported as a proven identity')

    def test_a_domain_held_by_an_unrecorded_host_is_ambiguous(self):
        live = self.live(hosts=[{
            'uuid': 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
            'address': 'ok.example.com', 'sni': 'cam-ok.example.com',
            'inbound': {
                'configProfileUuid': 'profile-ok',
                'configProfileInboundUuid': 'inb-ok',
            },
            'nodes': [{'uuid': self.OK_NODE}],
        }])
        verdict = resume_reconcile.classify(self.expectation(), live)
        self.assertEqual(verdict.status, 'ambiguous')
        self.assertEqual(verdict.reason, 'host_domain_held_elsewhere')

    def test_drift_always_carries_the_recorded_uuid(self):
        # Every drift path re-applies through the UUID the Panel issued. A
        # verdict that named no UUID, or that said `recreate`, would be the
        # path that registers a second node.
        live = self.live()
        live['nodes'][0]['configProfile']['activeInbounds'] = [
            {'uuid': 'inb-ok'}, {'uuid': 'inb-new'}]
        live['profiles'][0]['inbounds'] = ['inb-ok', 'inb-new']
        verdict = resume_reconcile.classify(self.expectation(), live)
        self.assertEqual(verdict.status, 'drift')
        self.assertEqual(verdict.node_uuid, self.OK_NODE)
        self.assertNotEqual(verdict.action, 'recreate')

        live = self.live()
        live['hosts'][0]['inbound']['configProfileInboundUuid'] = 'inb-ok'
        live['hosts'][0]['nodes'] = [{'uuid': self.OK_NODE}, {'uuid': self.OTHER_NODE}]
        verdict = resume_reconcile.classify(self.expectation(), live)
        self.assertEqual(verdict.status, 'ambiguous',
                         'a Host shared with another node is not re-appliable')
        self.assertEqual(verdict.reason, 'host_claim_conflict')

    def test_a_recorded_endpoint_that_moved_is_drift_and_not_a_second_node(self):
        live = self.live()
        live['nodes'][0]['address'] = '198.51.100.9'
        live['nodes'][0]['port'] = 3002
        verdict = resume_reconcile.classify(
            self.expectation(address='203.0.113.7', port=3002), live)
        self.assertEqual(verdict.status, 'drift')
        self.assertEqual(verdict.reason, 'node_endpoint_changed')
        self.assertEqual(verdict.node_uuid, self.OK_NODE)

    def test_a_host_record_that_lost_a_planned_domain_is_drift(self):
        live = self.live()
        live['hosts'][0]['sni'] = 'other.example.com'
        verdict = resume_reconcile.classify(self.expectation(), live)
        self.assertEqual(verdict.status, 'drift')
        self.assertEqual(verdict.reason, 'host_domain_missing')
        self.assertEqual(verdict.node_uuid, self.OK_NODE)

    def test_a_security_report_from_another_machine_is_ambiguous(self):
        security = {
            'recorded': self.security_report(host_id='machine-a'),
            'live': self.security_report(host_id='machine-b'),
        }
        verdict = resume_reconcile.classify(self.expectation(), self.live(), security)
        self.assertEqual(verdict.status, 'ambiguous')
        self.assertEqual(verdict.reason, 'security_identity_changed')

    def test_a_failed_security_control_is_drift_not_a_stop(self):
        security = {
            'recorded': self.security_report(),
            'live': self.security_report(status='failed'),
        }
        verdict = resume_reconcile.classify(self.expectation(), self.live(), security)
        self.assertEqual(verdict.status, 'drift')
        self.assertEqual(verdict.reason, 'security_not_ready')

    def test_an_unreadable_host_identity_is_unreachable(self):
        security = {'recorded': self.security_report(), 'error': 'unreachable'}
        verdict = resume_reconcile.classify(self.expectation(), self.live(), security)
        self.assertEqual(verdict.status, 'unreachable')
        self.assertEqual(verdict.reason, 'host_unreachable')

    def test_the_cli_classifies_one_document_and_names_the_result(self):
        environment = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]))
        document = {'expectation': self.expectation(), 'live': self.live()}
        result = subprocess.run(
            [sys.executable, '-m', 'modules.resume_reconcile', '--classify'],
            input=json.dumps(document), text=True, capture_output=True,
            env=environment, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        verdict = json.loads(result.stdout)
        self.assertEqual(verdict['class'], 'match')
        self.assertEqual(verdict['action'], 'keep')
        self.assertEqual(verdict['component'], 'node-1')

    def test_the_probe_without_a_readable_panel_reports_it_as_unreachable(self):
        environment = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]))
        result = subprocess.run(
            [sys.executable, '-m', 'modules.resume_reconcile', '--probe',
             '--credentials', str(Path(self.temporary.name) / 'missing-credentials')],
            text=True, capture_output=True, env=environment, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['reachable'], False)
