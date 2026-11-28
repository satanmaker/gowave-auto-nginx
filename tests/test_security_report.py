import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from modules import security_report as reports
from modules.deployment_state import StateError

MANAGED_PY = Path(__file__).resolve().parents[1] / 'assets' / 'security' / 'managed.py'


def load_managed():
    spec = importlib.util.spec_from_file_location('managed_report', str(MANAGED_PY))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestHostReport(unittest.TestCase):
    """The host-side producer against the Panel-side schema and readiness.

    The helper re-verifies every control instead of trusting the step that
    configured it, so these cases break one verifier at a time and read what
    the report says: a control is never promoted to `verified`, an optional
    failure is a warning only with a proven recovery, and a required failure
    or an unknown recovery blocks. Readiness is compared with the Panel-side
    reduction, which is the copy that decides the overall exit.
    """

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / 'etc').mkdir()
        (self.root / 'etc/os-release').write_text('ID=debian\nVERSION_ID="12"\n', encoding='utf-8')
        (self.root / 'etc/machine-id').write_text('0123456789abcdef0123456789abcdef\n', encoding='utf-8')
        self.managed = load_managed()
        # The parent directory is created by this test's own user, standing in
        # for the root-owned state directory a host install has.
        self.managed.PROJECT_OWNER_UID = os.getuid()
        for name, value in (('inspect_ssh_ports', lambda: [22]),
                            ('verify_firewall', lambda *args, **kwargs: {'status': 'success'}),
                            ('verify_fail2ban', lambda *args, **kwargs: None),
                            ('verify_apt', lambda *args, **kwargs: None),
                            ('verify_dns', lambda *args, **kwargs: None)):
            patcher = mock.patch.object(self.managed, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def request(self, **overrides):
        request = {'role': 'aio', 'node_port': 3002, 'master_sources': [], 'ipv6': True,
                   'dot_policy': 'best-effort', 'dot_recovery': 'not-needed'}
        request.update(overrides)
        return request

    def build(self, **overrides):
        return self.managed.security_report(self.request(**overrides), root=self.root)

    def break_control(self, name, message):
        def failing(*args, **kwargs):
            raise ValueError(message)
        setattr(self.managed, name, failing)

    def test_a_healthy_host_writes_a_report_the_panel_accepts(self):
        report, warnings = self.build()
        self.assertEqual(warnings, [])
        self.assertEqual({name: control['status'] for name, control in report['controls'].items()},
                         {name: 'verified' for name in reports.CONTROLS})
        self.assertEqual(report['controls']['dot']['policy'], 'best-effort')
        self.assertEqual(self.managed.report_readiness(report), 'ready')

        path = self.managed.write_security_report(report, root=self.root)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        loaded = reports.SecurityReportStore(path, owner_uid=os.getuid()).load()
        self.assertEqual(loaded, json.loads(path.read_text(encoding='utf-8')))
        self.assertEqual(reports.readiness(loaded), 'ready')

    def test_optional_failure_with_a_proven_recovery_is_only_a_warning(self):
        self.break_control('verify_dns', 'Effective global DNSOverTLS is not best-effort')
        report, warnings = self.build(dot_recovery='verified')
        self.assertEqual(report['controls']['dot']['status'], 'failed')
        self.assertEqual(report['controls']['dot']['recovery'], 'verified')
        self.assertEqual(report['controls']['dot']['policy'], 'best-effort')
        self.assertTrue(any('Effective global DNSOverTLS' in warning for warning in warnings))
        self.assertEqual(self.managed.report_readiness(report), 'ready-with-warnings')
        path = self.managed.write_security_report(report, root=self.root)
        self.assertEqual(reports.readiness(reports.SecurityReportStore(path, owner_uid=os.getuid()).load()),
                         'ready-with-warnings')

    def test_required_failure_blocks_without_defacing_the_other_controls(self):
        self.break_control('verify_dns', 'Effective global DNSOverTLS is not required')
        report, _ = self.build(role='worker', node_port=3002, master_sources=['203.0.113.10'],
                               dot_policy='required', dot_recovery='verified')
        self.assertEqual(report['role'], 'worker')
        self.assertEqual(report['controls']['dot']['status'], 'failed')
        for name in ('firewall', 'ssh_protection', 'security_updates'):
            self.assertEqual(report['controls'][name]['status'], 'verified')
            self.assertEqual(report['controls'][name]['recovery'], 'not-needed')
        self.assertEqual(self.managed.report_readiness(report), 'failed')
        path = self.managed.write_security_report(report, root=self.root)
        self.assertEqual(reports.readiness(reports.SecurityReportStore(path, owner_uid=os.getuid()).load()), 'failed')

    def test_an_unproven_recovery_never_reads_as_a_warning(self):
        self.break_control('verify_dns', 'resolver did not answer')
        for recovery in ('unknown', 'failed'):
            with self.subTest(recovery=recovery):
                report, _ = self.build(dot_recovery=recovery)
                self.assertEqual(report['controls']['dot']['recovery'], recovery)
                self.assertEqual(self.managed.report_readiness(report), 'failed')

    def test_a_control_that_stops_being_effective_is_failed_on_the_next_read(self):
        first, _ = self.build()
        self.assertEqual(self.managed.report_readiness(first), 'ready')
        path = self.managed.write_security_report(first, root=self.root)
        self.break_control('verify_fail2ban', 'SSH jail ports not effective')
        second, warnings = self.build()
        self.assertEqual(second['controls']['ssh_protection']['status'], 'failed')
        self.assertEqual(second['controls']['ssh_protection']['recovery'], 'unknown')
        self.assertGreaterEqual(second['observed_at'], first['observed_at'])
        self.assertTrue(any('ssh_protection' in warning for warning in warnings))
        self.managed.write_security_report(second, root=self.root)
        loaded = reports.SecurityReportStore(path, owner_uid=os.getuid()).load()
        self.assertEqual(loaded, json.loads(path.read_text(encoding='utf-8')))
        self.assertEqual(loaded['controls']['ssh_protection']['status'], 'failed')
        self.assertEqual(self.managed.report_readiness(second), reports.readiness(loaded))

    def test_operator_facing_warnings_stay_out_of_the_report(self):
        self.break_control('verify_fail2ban', 'jail query failed: password=hunter2')
        report, warnings = self.build()
        path = self.managed.write_security_report(report, root=self.root)
        text = path.read_text(encoding='utf-8')
        self.assertNotIn('hunter2', text)
        self.assertTrue(any('hunter2' in warning for warning in warnings))

    def test_a_panel_only_host_has_no_node_port_and_no_worker_sources(self):
        report, _ = self.build(role='panel-only', node_port=None)
        self.assertEqual(report['role'], 'panel-only')
        self.assertEqual(report['controls']['firewall']['status'], 'verified')

    def test_an_invalid_request_is_refused_before_anything_is_read(self):
        for overrides in ({'role': 'edge'}, {'node_port': '3002'}, {'node_port': 0},
                          {'master_sources': '203.0.113.10'}, {'master_sources': [7]},
                          {'ipv6': 'yes'}, {'dot_policy': 'sometimes'}, {'dot_recovery': 'maybe'}):
            with self.subTest(overrides=overrides):
                with self.assertRaises(ValueError):
                    self.build(**overrides)

    def test_the_command_line_refuses_an_unknown_role_without_touching_the_host(self):
        result = subprocess.run(['python3', str(MANAGED_PY), '--security-report'],
                                input='{"role": "edge"}', text=True, capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('Unsupported host role', result.stdout)

    def test_an_unsafe_report_directory_is_refused(self):
        directory = self.root / 'var' / 'lib' / 'gowave-auto-nginx'
        directory.mkdir(parents=True)
        directory.chmod(0o775)
        report, _ = self.build()
        with self.assertRaisesRegex(ValueError, 'Unsafe security report directory'):
            self.managed.write_security_report(report, root=self.root)
        self.assertFalse((directory / 'security-report.json').exists())


REPORT_STUB = '''import os, sys
request = sys.stdin.read()
with open(os.environ["STUB_MARKER"], "w", encoding="utf-8") as stream:
    stream.write(request)
sys.stdout.write('{"status": "ready", "readiness": "ready", "report": "/tmp/report.json"}\\n')
sys.exit(int(os.environ["STUB_RC"]))
'''


class TestHostReportWiring(unittest.TestCase):
    """`write_security_report` turns host facts into one request for the helper."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.stub = self.root / 'report_stub.py'
        self.stub.write_text(REPORT_STUB, encoding='utf-8')
        self.marker = self.root / 'request.json'
        self.security_sh = Path(__file__).resolve().parents[1] / 'modules' / 'security.sh'

    def run_wrapper(self, *args, stub_rc='0'):
        quoted = ' '.join("'" + str(value).replace("'", "'\\''") + "'" for value in args)
        script = (f'source "{self.security_sh}"\n'
                  f'MANAGED_SECURITY_PY="{self.stub}"\n'
                  f'if write_security_report {quoted}; then echo "rc=0"; else echo "rc=$?"; fi\n')
        return subprocess.run(['bash', '-c', script], capture_output=True, text=True,
                              env={**os.environ, 'STUB_MARKER': str(self.marker), 'STUB_RC': stub_rc,
                                   'GOWAVE_DOT_POLICY': 'best-effort'})

    def request(self):
        return json.loads(self.marker.read_text(encoding='utf-8'))

    def test_the_request_carries_the_role_port_sources_family_and_recovery(self):
        result = self.run_wrapper('worker', '3002', '203.0.113.10,2001:db8::1', 'true', 'verified')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.request(), {'role': 'worker', 'node_port': 3002,
                                          'master_sources': ['203.0.113.10', '2001:db8::1'],
                                          'ipv6': True, 'dot_recovery': 'verified'})
        self.assertIn('"readiness": "ready"', result.stdout)

    def test_a_panel_only_host_sends_no_node_port_and_no_sources(self):
        result = self.run_wrapper('panel-only', '', '', 'false', 'unknown')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.request(), {'role': 'panel-only', 'node_port': None,
                                          'master_sources': [], 'ipv6': False,
                                          'dot_recovery': 'unknown'})

    def test_a_failed_verdict_stops_the_installation_and_says_so(self):
        result = self.run_wrapper('aio', '3002', '', 'false', 'unknown', stub_rc='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('rc=1', result.stdout)
        self.assertIn('not ready for deployment', result.stderr)

    def test_worker_readback_requires_a_fresh_healthy_report_over_trusted_ssh(self):
        report = {
            'schema_version': 1, 'host_id': 'worker-1', 'role': 'worker',
            'installer_revision': 'test', 'observed_at': datetime.now(timezone.utc).isoformat(),
            'controls': {
                name: {'policy': 'best-effort' if name == 'dot' else 'required',
                       'status': 'verified', 'reason_code': 'VERIFIED',
                       'recovery': 'not-needed', 'evidence_codes': []}
                for name in reports.CONTROLS
            },
        }
        script = '''source "$1"
resolve_panel_ipv4() { printf '203.0.113.10'; }
resolve_panel_ipv6() { :; }
timeout() {
    [[ "$1" == 45 && "$2" == ssh ]] || return 9
    shift 2
    [[ " $* " == *' BatchMode=yes '* && " $* " == *' StrictHostKeyChecking=yes '* &&
       " $* " == *' root@worker.example.com python3 - --worker-security-readback 3002 203.0.113.10 '* ]] || return 9
    IFS= read -r first_line && [[ "$first_line" == '\"\"\"Opt-in host security for GoWave Auto NGINX.' ]] || return 9
    printf '%s' "$REPORT"
}
GOWAVE_SSH_NODE_PORT=3002
GOWAVE_DOT_POLICY=best-effort
verify_worker_security_readback worker.example.com
'''
        stale = {**report, 'observed_at': '2000-01-01T00:00:00+00:00'}
        failed = copy.deepcopy(report)
        failed['controls']['firewall']['status'] = 'failed'
        for payload, code in ((report, 0), (stale, 1), (failed, 1), ({**report, 'role': 'aio'}, 1)):
            with self.subTest(role=payload['role'], observed=payload['observed_at'], code=code):
                result = subprocess.run(['bash', '-c', script, 'bash', str(self.security_sh)],
                                        capture_output=True, text=True,
                                        env={**os.environ, 'REPORT': json.dumps(payload)})
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertEqual(result.stdout, '')

    def test_a_missing_role_is_refused_before_the_helper_runs(self):
        result = self.run_wrapper('', '3002', '', 'false', 'unknown')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('rc=1', result.stdout)
        self.assertIn('needs the host role', result.stderr)
        self.assertFalse(self.marker.exists())


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
        self.assertIn('written by every role this installer hardens', guide)
        self.assertIn('a Worker writes it after its', guide)
        self.assertIn('каждая роль, которую этот установщик защищает', guide)
        self.assertIn('existing non-interactive root SSH access with a trusted host key', guide)
        self.assertIn('неинтерактивный SSH-доступ от root с доверенным ключом хоста', guide)
        self.assertIn('the Worker stays unconfirmed and is not rebuilt', guide)
        self.assertIn('Worker остаётся неподтверждённым', guide)
        self.assertIn('`ready-with-warnings`', guide)
        self.assertIn('`unsupported`', guide)
        self.assertIn('DNSSEC', guide)
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

    def host_report(self, host='worker-1', role='worker', **overrides):
        report = copy.deepcopy(self.report)
        report['host_id'] = host
        report['role'] = role
        report['observed_at'] = overrides.pop('observed_at', self.now.isoformat())
        for name, changes in overrides.items():
            report['controls'][name].update(changes)
        return report

    def document(self, master=None, workers=None):
        return reports.combine(master or self.host_report(host='master-1', role='panel-only'),
                               workers or {}, now=self.now)

    def test_reading_a_report_is_read_only_and_a_rerun_replaces_it_atomically(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'private' / 'security-report.json'
            store = reports.SecurityReportStore(path, owner_uid=os.getuid())
            store.save(self.report, now=self.now)
            before = path.stat()
            original = path.read_bytes()
            self.assertEqual(store.load(now=self.now), self.report)
            after = path.stat()
            self.assertEqual((after.st_ino, after.st_mtime_ns), (before.st_ino, before.st_mtime_ns))
            self.assertEqual(path.read_bytes(), original)

            drifted = self.host_report(firewall={'status': 'failed', 'recovery': 'unknown'})
            store.save(drifted, now=self.now)
            self.assertEqual(store.load(now=self.now), drifted)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.read_bytes(), json.dumps(drifted, sort_keys=True).encode() + b'\n')
            self.assertEqual([entry.name for entry in path.parent.iterdir()], ['security-report.json'])

    def test_the_store_reports_which_host_is_stale_and_how_old_it_is(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'private' / 'security-report.json'
            store = reports.SecurityReportStore(path, owner_uid=os.getuid())
            store.save(self.report, now=self.now)
            with self.assertRaises(reports.StaleReport) as raised:
                store.load(now=self.now + timedelta(seconds=901))
            self.assertEqual(raised.exception.host, 'worker-1')
            self.assertGreaterEqual(raised.exception.age_seconds, 901)
            self.assertIn('worker-1 is stale', str(raised.exception))
            self.assertIn('seconds old', str(raised.exception))
            self.assertEqual(path.read_bytes(), json.dumps(self.report, sort_keys=True).encode() + b'\n')

    def test_an_aggregate_refuses_a_stale_report_next_to_a_fresh_one(self):
        master = self.host_report(host='master-1', role='panel-only')
        fresh = self.host_report('worker-1')
        cases = (((self.now - timedelta(seconds=901)).isoformat(), 'seconds old'),
                 ((self.now + timedelta(seconds=5)).isoformat(), 'in the future'))
        for observed, wording in cases:
            with self.subTest(observed=observed):
                stale = self.host_report('worker-2', observed_at=observed)
                with self.assertRaises(reports.StaleReport) as raised:
                    reports.combine(master, {'worker-1': fresh, 'worker-2': stale}, now=self.now)
                self.assertEqual(raised.exception.host, 'worker-2')
                self.assertIn('worker-2 is stale', str(raised.exception))
                self.assertIn(wording, str(raised.exception))

    def test_an_aggregate_refuses_a_stale_master_too(self):
        master = self.host_report('master-1', role='panel-only',
                             observed_at=(self.now - timedelta(seconds=600)).isoformat())
        with self.assertRaises(reports.StaleReport) as raised:
            reports.combine(master, {'worker-1': self.host_report('worker-1')}, now=self.now)
        self.assertEqual(raised.exception.host, 'master-1')
        self.assertGreaterEqual(raised.exception.age_seconds, 600)

    def test_the_aggregate_is_the_weakest_host_and_names_the_control(self):
        master = self.host_report('master-1', role='panel-only')
        ready = self.host_report('worker-1')
        blocked = self.host_report('worker-2', firewall={'status': 'failed', 'recovery': 'unknown'})
        document = reports.combine(master, {'worker-1': ready, 'worker-2': blocked}, now=self.now)
        self.assertEqual(document['readiness'], 'failed')
        self.assertEqual(document['decided_by'],
                         {'host': 'worker-2', 'control': 'firewall', 'readiness': 'failed'})
        self.assertEqual(document['workers']['worker-2']['blocking'], ['firewall'])
        self.assertEqual(document['workers']['worker-1']['readiness'], 'ready')
        self.assertEqual(document['workers']['worker-1']['blocking'], [])
        reports.validate_aggregate(document)
        self.assertEqual(reports.aggregate_readiness(document), ('failed', document['decided_by']))

        failed_master = self.host_report('master-1', role='panel-only',
                                    ssh_protection={'status': 'failed', 'recovery': 'unknown'})
        document = reports.combine(failed_master, {'worker-1': ready}, now=self.now)
        self.assertEqual(document['readiness'], 'failed')
        self.assertEqual(document['decided_by']['host'], 'master')
        self.assertEqual(document['decided_by']['control'], 'ssh_protection')

    def test_required_and_best_effort_are_gated_differently(self):
        master = self.host_report('master-1', role='panel-only')
        warning = self.host_report('worker-1', dot={'policy': 'best-effort', 'status': 'failed',
                                              'recovery': 'verified'})
        document = reports.combine(master, {'worker-1': warning}, now=self.now)
        self.assertEqual(document['readiness'], 'ready-with-warnings')
        self.assertEqual(document['decided_by'],
                         {'host': 'worker-1', 'control': 'dot', 'readiness': 'ready-with-warnings'})
        self.assertEqual(document['workers']['worker-1']['warnings'], ['dot'])
        self.assertEqual(document['workers']['worker-1']['blocking'], [])

        blocked = self.host_report('worker-1', dot={'policy': 'required', 'status': 'failed',
                                               'recovery': 'verified'})
        document = reports.combine(master, {'worker-1': blocked}, now=self.now)
        self.assertEqual(document['readiness'], 'failed')
        self.assertEqual(document['decided_by']['control'], 'dot')
        self.assertEqual(document['workers']['worker-1']['blocking'], ['dot'])

        unproven = self.host_report('worker-1', dot={'policy': 'best-effort', 'status': 'failed',
                                                'recovery': 'unknown'})
        document = reports.combine(master, {'worker-1': unproven}, now=self.now)
        self.assertEqual(document['readiness'], 'failed')
        self.assertEqual(document['decided_by']['control'], 'dot')

    def test_a_missing_report_is_a_named_gap_not_a_pass(self):
        master = self.host_report('master-1', role='panel-only')
        document = reports.combine(master, {'worker-1': {'status': 'fetch_failed'},
                                            'worker-2': {'status': 'invalid'}}, now=self.now)
        self.assertEqual(document['readiness'], 'failed')
        self.assertEqual(document['decided_by'],
                         {'host': 'worker-1', 'control': 'security_report', 'readiness': 'failed'})
        self.assertEqual(document['workers']['worker-1']['reason_code'], 'WORKER_READBACK_FAILED')
        self.assertEqual(document['workers']['worker-2']['reason_code'], 'REPORT_INVALID')
        reports.validate_aggregate(document)

        tampered = copy.deepcopy(document)
        tampered['readiness'] = 'ready'
        with self.assertRaises(StateError):
            reports.validate_aggregate(tampered)
        tampered = copy.deepcopy(document)
        tampered['workers']['worker-1']['reason_code'] = 'password=hunter2'
        with self.assertRaises(StateError):
            reports.validate_aggregate(tampered)

    def test_an_aggregate_is_read_only_to_read_and_replaced_as_a_whole(self):
        master = self.host_report('master-1', role='panel-only')
        document = reports.combine(master, {'worker-1': self.host_report('worker-1')}, now=self.now)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'private' / 'security-report-aggregate.json'
            store = reports.AggregateStore(path, owner_uid=os.getuid())
            store.save(document)
            before = path.stat()
            original = path.read_bytes()
            self.assertEqual(store.load(), document)
            after = path.stat()
            self.assertEqual((after.st_ino, after.st_mtime_ns), (before.st_ino, before.st_mtime_ns))
            self.assertEqual(path.read_bytes(), original)

            rerun = reports.combine(master, {'worker-1': self.host_report(
                'worker-1', firewall={'status': 'failed', 'recovery': 'unknown'})}, now=self.now)
            store.save(rerun)
            self.assertEqual(store.load(), rerun)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual([entry.name for entry in path.parent.iterdir()],
                             ['security-report-aggregate.json'])

    def test_a_report_and_an_aggregate_refuse_secret_material(self):
        for payload in ({'value': '-----BEGIN OPENSSH PRIVATE KEY-----'},
                        {'value': '-----BEGIN CERTIFICATE-----'},
                        {'value': 'password=hunter2'},
                        {'value': 'token=abc'},
                        {'value': 'PRIVATE KEY'}):
            with self.subTest(payload=payload):
                self.assertFalse(reports.redacted(payload))
                with self.assertRaises(StateError):
                    reports.require_redacted(payload)

        master = self.host_report('master-1', role='panel-only')
        document = reports.combine(master, {'worker-1': self.host_report('worker-1')}, now=self.now)
        self.assertTrue(reports.redacted(document))
        tampered = copy.deepcopy(document)
        tampered['workers']['worker-1']['error'] = 'password=hunter2'
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'private' / 'security-report-aggregate.json'
            store = reports.AggregateStore(path, owner_uid=os.getuid())
            store.save(document)
            with self.assertRaises(StateError):
                store.save(tampered)
            self.assertEqual(store.load(), document)
            self.assertNotIn('hunter2', path.read_text(encoding='utf-8'))


class TestAggregateWorkerReports(unittest.TestCase):
    """Tests for the aggregate_worker_security_reports function in modules/security.sh."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.security_sh = Path(__file__).resolve().parents[1] / 'modules' / 'security.sh'
        self.managed_py = Path(__file__).resolve().parents[1] / 'assets' / 'security' / 'managed.py'
        # Create a mock state directory
        self.state_dir = self.root / 'var' / 'lib' / 'gowave-auto-nginx'
        self.state_dir.mkdir(parents=True)
        self.state_dir.chmod(0o700)
        # Create a valid master report
        self.master_report = {
            'schema_version': 1,
            'host_id': 'master-1',
            'role': 'aio',
            'installer_revision': 'test-1',
            'observed_at': datetime.now(timezone.utc).isoformat(),
            'controls': {
                name: {'policy': 'best-effort' if name == 'dot' else 'required',
                       'status': 'verified', 'reason_code': 'VERIFIED',
                       'recovery': 'not-needed', 'evidence_codes': ['EFFECTIVE_STATE_READBACK']}
                for name in reports.CONTROLS
            },
        }
        self.master_report_path = self.state_dir / 'security-report.json'
        self.master_report_path.write_text(json.dumps(self.master_report) + '\n')
        self.master_report_path.chmod(0o600)

    def worker_report(self, host='worker-1', role='worker', old_seconds=0, **controls):
        report = {
            'schema_version': 1, 'host_id': host, 'role': role, 'installer_revision': 'test-1',
            'observed_at': (datetime.now(timezone.utc) - timedelta(seconds=old_seconds)).isoformat(),
            'controls': {
                name: {'policy': 'best-effort' if name == 'dot' else 'required',
                       'status': 'verified', 'reason_code': 'VERIFIED',
                       'recovery': 'not-needed', 'evidence_codes': ['EFFECTIVE_STATE_READBACK']}
                for name in reports.CONTROLS
            },
        }
        for name, changes in controls.items():
            report['controls'][name].update(changes)
        return report

    def _run_aggregate(self, env=None, names=(), readbacks=None, extra=''):
        """Run aggregate_worker_security_reports against a disposable state tree.

        `readbacks` maps a planned host name to the JSON its readback returns; a
        name without an entry fails at the SSH step, which is how a hole in the
        fleet is simulated. `extra` is appended before the call so a test can
        replace the helper functions this module owns.
        """
        worker_dir = self.root / 'readbacks'
        worker_dir.mkdir(exist_ok=True)
        for host, report in (readbacks or {}).items():
            (worker_dir / f'{host}.json').write_text(
                report if isinstance(report, str) else json.dumps(report), encoding='utf-8')
        quoted_names = ' '.join(f"'{name}'" for name in names)
        script = f'''source "{self.security_sh}"
# Mock the required functions and variables
resolve_panel_ipv4() {{ printf '203.0.113.10'; }}
resolve_panel_ipv6() {{ :; }}
GOWAVE_SSH_NODE_PORT=3002
GOWAVE_SSH_PORT=22
GOWAVE_DOT_POLICY=best-effort
GOWAVE_PLAN_NODE_NAMES=({quoted_names})
MANAGED_SECURITY_PY="{self.managed_py}"
# Override state directory
export GOWAVE_STATE_DIR="{self.state_dir}"
WORKER_DIR="{worker_dir}"
# The readback travels over SSH in the product; here the fake answers from a
# file and consumes the helper stream the caller redirects into it.
timeout() {{ shift; "$@"; }}
ssh() {{
    local arg host=""
    for arg in "$@"; do
        if [[ "$arg" == root@* ]]; then
            host="${{arg#root@}}"
        fi
    done
    cat >/dev/null
    [[ -n "$host" ]] || return 1
    [[ -f "$WORKER_DIR/$host.json" ]] || return 1
    cat "$WORKER_DIR/$host.json"
}}
{extra}
aggregate_worker_security_reports
'''
        env_vars = {**os.environ}
        if env:
            env_vars.update(env)
        return subprocess.run(['bash', '-c', script], capture_output=True, text=True, env=env_vars)

    def aggregate(self):
        return json.loads((self.state_dir / 'security-report-aggregate.json').read_text())

    def test_aggregate_with_no_workers_writes_empty_aggregate(self):
        result = self._run_aggregate()
        self.assertEqual(result.returncode, 0, result.stderr)
        agg_path = self.state_dir / 'security-report-aggregate.json'
        self.assertTrue(agg_path.exists())
        agg = self.aggregate()
        self.assertEqual(agg['schema_version'], 1)
        self.assertEqual(agg['master'], self.master_report)
        self.assertEqual(agg['workers'], {})
        self.assertEqual(agg['readiness'], 'ready')
        self.assertIsNone(agg['decided_by'])
        self.assertEqual(agg_path.stat().st_mode & 0o777, 0o600)

    def test_aggregate_fails_when_master_report_missing(self):
        self.master_report_path.unlink()
        result = self._run_aggregate()
        self.assertEqual(result.returncode, 1)
        self.assertIn('Master security report not found', result.stderr)

    def test_aggregate_structure_has_expected_fields(self):
        result = self._run_aggregate()
        self.assertEqual(result.returncode, 0, result.stderr)
        agg = self.aggregate()
        self.assertIn('schema_version', agg)
        self.assertIn('master', agg)
        self.assertIn('workers', agg)
        self.assertIn('observed_at', agg)
        self.assertEqual(agg['schema_version'], 1)

    def test_a_fresh_worker_report_is_counted_and_named(self):
        worker = self.worker_report('worker-1')
        result = self._run_aggregate(names=('worker-1',), readbacks={'worker-1': worker})
        self.assertEqual(result.returncode, 0, result.stderr)
        agg = self.aggregate()
        self.assertEqual(agg['readiness'], 'ready')
        self.assertEqual(agg['workers']['worker-1']['status'], 'ok')
        self.assertEqual(agg['workers']['worker-1']['readiness'], 'ready')
        self.assertEqual(agg['workers']['worker-1']['report'], worker)
        self.assertEqual(agg['workers']['worker-1']['observed_at'], worker['observed_at'])
        self.assertIn('Security report aggregate written', result.stdout)

    def test_a_stale_worker_report_refuses_the_aggregate_and_names_the_host(self):
        stale = self.worker_report('worker-2', old_seconds=900)
        previous = self.state_dir / 'security-report-aggregate.json'
        previous.write_text('{"previous": true}\n')
        previous.chmod(0o600)
        result = self._run_aggregate(names=('worker-1', 'worker-2'),
                                     readbacks={'worker-1': self.worker_report('worker-1'),
                                                'worker-2': stale})
        self.assertEqual(result.returncode, 1)
        self.assertIn('worker-2 is stale', result.stderr)
        self.assertIn('seconds old', result.stderr)
        self.assertIn('"status": "refused"', result.stdout)
        # A refused rerun leaves the previous aggregate alone: no host list is
        # silently patched into a document that now claims a fresh verdict.
        self.assertEqual(previous.read_text(), '{"previous": true}\n')

    def test_a_stale_master_report_is_regenerated_before_aggregation(self):
        stub = '''write_security_report() {
    python3 - "$GOWAVE_STATE_DIR/security-report.json" <<'PY'
import json, sys
from datetime import datetime, timezone
path = sys.argv[1]
with open(path, encoding="utf-8") as stream:
    report = json.load(stream)
report["observed_at"] = datetime.now(timezone.utc).isoformat()
with open(path, "w", encoding="utf-8") as stream:
    json.dump(report, stream)
    stream.write("\\n")
PY
    printf '%s\\n' "$1:$2" >> "$GOWAVE_STATE_DIR/refresh.log"
}
'''
        # The multi-node Master is `panel-only`, so the branch that passes no
        # Node port is the production one, not the All-in-One branch.
        for role, expected in (('aio', 'aio:3002'), ('panel-only', 'panel-only:')):
            with self.subTest(role=role):
                self.master_report['role'] = role
                self.master_report['observed_at'] = (
                    datetime.now(timezone.utc) - timedelta(seconds=3600)).isoformat()
                self.master_report_path.write_text(json.dumps(self.master_report) + '\n')
                result = self._run_aggregate(extra=stub)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('Refreshing the Master security report', result.stdout)
                self.assertEqual((self.state_dir / 'refresh.log').read_text().splitlines()[-1], expected)
                agg = self.aggregate()
                self.assertGreater(agg['master']['observed_at'], self.master_report['observed_at'])
                self.assertEqual(agg['readiness'], 'ready')

    def test_a_master_report_that_cannot_be_refreshed_writes_no_aggregate(self):
        self.master_report['observed_at'] = (
            datetime.now(timezone.utc) - timedelta(seconds=3600)).isoformat()
        self.master_report_path.write_text(json.dumps(self.master_report) + '\n')
        result = self._run_aggregate(extra='write_security_report() { return 1; }')
        self.assertEqual(result.returncode, 1)
        self.assertIn('could not be refreshed', result.stderr)
        self.assertFalse((self.state_dir / 'security-report-aggregate.json').exists())

    def test_a_worker_that_cannot_be_read_is_a_named_gap(self):
        result = self._run_aggregate(names=('worker-1', 'worker-2'),
                                     readbacks={'worker-1': self.worker_report('worker-1')})
        self.assertEqual(result.returncode, 1)
        agg = self.aggregate()
        self.assertEqual(agg['readiness'], 'failed')
        self.assertEqual(agg['workers']['worker-2']['status'], 'fetch_failed')
        self.assertEqual(agg['workers']['worker-2']['reason_code'], 'WORKER_READBACK_FAILED')
        self.assertEqual(agg['decided_by'],
                         {'host': 'worker-2', 'control': 'security_report', 'readiness': 'failed'})
        self.assertIn('failed to fetch a security report from Worker worker-2', result.stderr)

    def test_a_worker_readback_with_a_secret_is_invalid_and_not_copied(self):
        poisoned = self.worker_report('worker-1')
        poisoned['password'] = 'hunter2'
        result = self._run_aggregate(names=('worker-1',), readbacks={'worker-1': poisoned})
        self.assertEqual(result.returncode, 1)
        agg_path = self.state_dir / 'security-report-aggregate.json'
        self.assertNotIn('hunter2', agg_path.read_text(encoding='utf-8'))
        agg = json.loads(agg_path.read_text())
        self.assertEqual(agg['workers']['worker-1']['status'], 'invalid')
        self.assertEqual(agg['workers']['worker-1']['reason_code'], 'REPORT_INVALID')
        self.assertNotIn('hunter2', result.stdout + result.stderr)
