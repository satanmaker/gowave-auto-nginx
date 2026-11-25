import copy
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import tempfile
import unittest

from modules import security_report as reports
from modules.deployment_state import StateError


class TestSecurityReport(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.report = {
            'schema_version': 1, 'host_id': 'worker-1', 'role': 'worker',
            'installer_revision': 'test-1', 'observed_at': self.now.isoformat(),
            'controls': {
                name: {'policy': 'required', 'status': 'verified',
                       'reason_code': 'VERIFIED', 'recovery': 'not-needed',
                       'evidence_codes': ['EFFECTIVE_STATE_READBACK']}
                for name in reports.CONTROLS
            },
        }
        self.component = {
            'registration': 'verified', 'readiness': 'verified',
            'cleanup': 'verified', 'recovery': 'not-needed',
        }

    def test_report_roundtrip_permissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'private' / 'security-report.json'
            store = reports.SecurityReportStore(path, owner_uid=os.getuid())
            store.save(self.report, now=self.now)
            self.assertEqual(store.load(now=self.now), self.report)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)

    def test_existing_shared_directory_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'shared'
            directory.mkdir(mode=0o755)
            directory.chmod(0o755)
            sibling = directory / 'state.json'
            sibling.write_text('existing state')
            path = directory / 'security-report.json'
            store = reports.SecurityReportStore(path, owner_uid=os.getuid())
            store.save(self.report, now=self.now)
            self.assertEqual(store.load(now=self.now), self.report)
            self.assertEqual(directory.stat().st_mode & 0o777, 0o755)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(sibling.read_text(), 'existing state')

    def test_writable_shared_directory_is_refused_even_with_sticky_bit(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'shared'
            directory.mkdir()
            path = directory / 'security-report.json'
            store = reports.SecurityReportStore(path, owner_uid=os.getuid())
            for mode in (0o775, 0o777, 0o1777):
                with self.subTest(mode=oct(mode)):
                    directory.chmod(mode)
                    with self.assertRaises(StateError):
                        store.save(self.report, now=self.now)
                    self.assertFalse(path.exists())
                    self.assertEqual(directory.stat().st_mode & 0o7777, mode)

    def test_stale_future_and_naive_timestamps_refused(self):
        for observed in (
            self.now - timedelta(seconds=301), self.now + timedelta(seconds=1),
            self.now.replace(tzinfo=None),
        ):
            with self.subTest(observed=observed):
                self.report['observed_at'] = observed.isoformat()
                with self.assertRaises(StateError):
                    reports.validate(self.report, now=self.now)

    def test_required_failure_and_optional_recovery(self):
        self.assertEqual(reports.readiness(self.report, now=self.now), 'ready')
        dot = self.report['controls']['dot']
        dot.update(status='failed', recovery='verified')
        self.assertEqual(reports.readiness(self.report, now=self.now), 'failed')
        dot['policy'] = 'best-effort'
        self.assertEqual(reports.readiness(self.report, now=self.now), 'ready-with-warnings')
        for recovery in ('failed', 'unknown', 'not-needed'):
            dot['recovery'] = recovery
            self.assertEqual(reports.readiness(self.report, now=self.now), 'failed')

    def test_skipped_required_control_blocks_ready(self):
        for status in ('failed', 'skipped', 'unsupported'):
            with self.subTest(status=status):
                self.report['controls']['firewall']['status'] = status
                self.assertEqual(reports.readiness(self.report, now=self.now), 'failed')

    def test_disabled_dot_is_not_reported_verified(self):
        self.report['controls']['dot']['policy'] = 'off'
        with self.assertRaises(StateError):
            reports.validate(self.report, now=self.now)
        self.report['controls']['dot']['status'] = 'skipped'
        self.assertEqual(reports.readiness(self.report, now=self.now), 'ready')

    def test_freeform_secrets_and_unknown_fields_refused(self):
        for key in ('password', 'token', 'SECRET_KEY', 'raw_output'):
            report = copy.deepcopy(self.report)
            report['controls']['dot'][key] = 'credential-fixture'
            with self.assertRaises(StateError) as raised:
                reports.validate(report, now=self.now)
            self.assertNotIn('credential-fixture', str(raised.exception))
        self.report['controls']['dot']['reason_code'] = 'password=credential-fixture'
        with self.assertRaises(StateError):
            reports.validate(self.report, now=self.now)

    def test_incomplete_controls_and_inconsistent_recovery_refused(self):
        del self.report['controls']['dot']
        with self.assertRaises(StateError):
            reports.validate(self.report, now=self.now)
        self.report['controls']['dot'] = copy.deepcopy(self.report['controls']['firewall'])
        self.report['controls']['dot']['recovery'] = 'verified'
        with self.assertRaises(StateError):
            reports.validate(self.report, now=self.now)

    def test_documented_schema_matches_validated_fixtures(self):
        guide = (Path(__file__).resolve().parents[1] / 'docs' / 'SETUP_WIZARD.md').read_text()
        from modules import deployment_state
        self.assertIn(str(deployment_state.DEFAULT_PATH), guide)
        self.assertIn(str(reports.DEFAULT_PATH), guide)
        for field in self.report:
            self.assertIn(f'`{field}`', guide)
        for field in self.report['controls']['dot']:
            self.assertIn(f'`{field}`', guide)
        for name in reports.CONTROLS:
            self.assertIn(f'`{name}`', guide)
        self.assertIn('not yet wired', guide)
        self.assertIn('пока не подключены', guide)
        self.assertIn('300 seconds', guide)
        self.assertIn('300 секунд', guide)
        self.assertIn('0755', guide)
        self.assertIn('0700', guide)
        self.assertIn('0600', guide)
        self.assertIn('no automatic expiry or deletion', guide)
        self.assertIn('сам не удаляет', guide)
        reports.validate(self.report, now=self.now)

    def test_exit_recomputed_after_retry(self):
        failed = dict(self.component, readiness='failed')
        self.assertEqual(reports.final_exit(self.component, [failed]), 2)
        self.assertEqual(reports.final_exit(self.component, [self.component]), 0)
        self.assertEqual(reports.final_exit(failed, []), 1)
        self.assertEqual(reports.final_exit(self.component, []), 0)

    def test_registered_node_with_failed_cleanup_is_partial(self):
        for key, value in (('cleanup', 'failed'), ('registration', 'indeterminate'),
                           ('recovery', 'unknown')):
            with self.subTest(key=key):
                component = dict(self.component, **{key: value})
                self.assertEqual(reports.final_exit(self.component, [component]), 2)
                self.assertEqual(component['registration'], value if key == 'registration' else 'verified')

    def test_warning_readiness_can_complete_and_unknown_states_refused(self):
        warning = dict(self.component, readiness='ready-with-warnings')
        self.assertEqual(reports.final_exit(warning, [warning]), 0)
        with self.assertRaises(StateError):
            reports.final_exit(self.component, [dict(self.component, cleanup='success')])
