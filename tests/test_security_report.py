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

    def _run_aggregate(self, env=None):
        """Run the aggregate_worker_security_reports function from security.sh."""
        script = f'''source "{self.security_sh}"
# Mock the required functions and variables
resolve_panel_ipv4() {{ printf '203.0.113.10'; }}
resolve_panel_ipv6() {{ :; }}
GOWAVE_SSH_NODE_PORT=3002
GOWAVE_SSH_PORT=22
GOWAVE_DOT_POLICY=best-effort
GOWAVE_PLAN_NODE_NAMES=()
MANAGED_SECURITY_PY="{self.managed_py}"
# Override state directory
export GOWAVE_STATE_DIR="{self.state_dir}"
# Mock ssh to fail (no Workers)
ssh() {{
    echo "ssh called unexpectedly" >&2
    return 1
}}
aggregate_worker_security_reports
'''
        env_vars = {**os.environ}
        if env:
            env_vars.update(env)
        return subprocess.run(['bash', '-c', script], capture_output=True, text=True, env=env_vars)

    def test_aggregate_with_no_workers_writes_empty_aggregate(self):
        result = self._run_aggregate()
        self.assertEqual(result.returncode, 0, result.stderr)
        agg_path = self.state_dir / 'security-report-aggregate.json'
        self.assertTrue(agg_path.exists())
        agg = json.loads(agg_path.read_text())
        self.assertEqual(agg['schema_version'], 1)
        self.assertEqual(agg['master'], self.master_report)
        self.assertEqual(agg['workers'], {})

    def test_aggregate_fails_when_master_report_missing(self):
        self.master_report_path.unlink()
        result = self._run_aggregate()
        self.assertEqual(result.returncode, 1)
        self.assertIn('Master security report not found', result.stderr)

    def test_aggregate_structure_has_expected_fields(self):
        result = self._run_aggregate()
        self.assertEqual(result.returncode, 0, result.stderr)
        agg_path = self.state_dir / 'security-report-aggregate.json'
        agg = json.loads(agg_path.read_text())
        self.assertIn('schema_version', agg)
        self.assertIn('master', agg)
        self.assertIn('workers', agg)
        self.assertIn('observed_at', agg)
        self.assertEqual(agg['schema_version'], 1)
